//! Middleware to handle `az://` URLs to pull artifacts from Azure Blob Storage.
use std::collections::HashMap;

use async_trait::async_trait;
use rattler_azure::{AzureChannelUrl, AzureEndpointOptions, AzureHost, AzureScheme, ContainerName};
use reqsign_azure_storage::{Credential, DefaultCredentialProvider, RequestSigner};
use reqsign_command_execute_tokio::TokioCommandExecute;
use reqsign_core::{Context, OsEnv, ProvideCredential, Signer};
use reqsign_file_read_tokio::TokioFileRead;
use reqsign_http_send_reqwest::ReqwestHttpSend;
use reqwest::{Client, Request, Response};
use reqwest_middleware::{Middleware, Next, Result as MiddlewareResult};
use url::Url;

/// The Azure Storage REST API version sent on every signed request.
const X_MS_VERSION: &str = "2021-12-02";

/// Middleware that rewrites `az://` URLs to their wire form and signs the ones
/// whose container is granted credentials.
///
/// The `az://` host is the full blob endpoint, so rewriting is a plain scheme
/// swap: `az://{host}/{path}` → `https://{host}/{path}`.
///
/// Requests are anonymous by default: with no `azure-options` entry for the host,
/// nothing is signed and no credential is resolved. A credential attaches only
/// because the user's config grants it to the *container* the request addresses:
///
/// ```toml
/// [azure-options."mycompany.blob.core.windows.net".auth]
/// releases = true
/// # an unlisted container is fetched anonymously
///
/// [azure-options."127.0.0.1:10000"]   # Azurite
/// scheme = "http"
/// path-style = true
///
/// [azure-options."127.0.0.1:10000".auth]
/// general = true
/// ```
///
/// Entries must stay user-scoped: a project-level manifest that could write one
/// would let a checked-out repository claim the user's credentials.
///
/// `az://user:pass@host/...` is refused. The host becomes the request target
/// verbatim, so userinfo is a host-spoofing vector.
///
/// Granted credentials come from reqsign's [`DefaultCredentialProvider`] chain;
/// rattler's [`crate::AuthenticationStorage`] has no Azure variant.
#[derive(Clone)]
pub struct AzureMiddleware {
    /// reqsign signer; caches the resolved credential internally.
    signer: Signer<Credential>,

    /// Whole `azure-options` entries, keyed by the same normalized authority the
    /// config table is keyed by. An absent host behaves as a defaulted entry, so a
    /// miss is never a separate code path.
    ///
    /// Entries and not the narrower [`rattler_azure::AzureFetchOptions`]: the host's addressing
    /// decides which path segment is the container, so the narrowing can only
    /// happen per request, in [`Self::resolve`].
    ///
    /// A plain `HashMap` rather than `rattler_config::AzureOptionsMap`, as in
    /// [`crate::S3Middleware`]: the config type would force a `rattler_config` edge
    /// on the `azure` feature.
    options: HashMap<AzureHost, AzureEndpointOptions>,
}

#[derive(Debug)]
struct Resolved {
    channel: AzureChannelUrl,
    grant: Grant,
    scheme: AzureScheme,
}

/// The container a request addresses, and whether it may be signed.
///
/// One value rather than an [`rattler_azure::Auth`] beside an `Option<ContainerName>`: a grant is
/// only ever read out of a container's entry, so a grant without a container has no
/// meaning and no representation here.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Grant {
    /// Send unsigned. Carries the container when the URL named one, for the 404
    /// hint.
    Ungranted(Option<ContainerName>),
    Granted(ContainerName),
}

impl AzureMiddleware {
    /// Create a new Azure middleware.
    ///
    /// `client` also carries reqsign's credential resolution (IMDS, managed
    /// identity, AAD token fetches), so its proxy, CA bundle and TLS settings apply
    /// there too.
    ///
    /// `options` is the `azure-options` table, as
    /// `rattler_config::AzureOptionsMap::endpoint_options` yields it. Empty means
    /// every `az://` request is anonymous.
    pub fn new(
        client: Client,
        options: impl IntoIterator<Item = (AzureHost, AzureEndpointOptions)>,
    ) -> Self {
        Self::with_credential_provider(client, DefaultCredentialProvider::new(), options)
    }

    /// Create a middleware that grants no host, so every `az://` request is sent
    /// unsigned.
    pub fn anonymous(client: Client) -> Self {
        Self::new(client, [])
    }

    fn with_credential_provider(
        client: Client,
        provider: impl ProvideCredential<Credential = Credential> + 'static,
        options: impl IntoIterator<Item = (AzureHost, AzureEndpointOptions)>,
    ) -> Self {
        let ctx = Context::new()
            .with_file_read(TokioFileRead)
            .with_http_send(ReqwestHttpSend::new(client))
            .with_command_execute(TokioCommandExecute)
            .with_env(OsEnv);
        let signer = Signer::new(ctx, provider, RequestSigner::new());
        Self {
            signer,
            options: options.into_iter().collect(),
        }
    }

    /// Resolve an `az://` request URL to the channel URL it names, the container it
    /// addresses, and the options that apply to it.
    ///
    /// [`AzureChannelUrl`] rejects userinfo and normalizes the authority to the
    /// spelling the options table is keyed by, so a grant cannot miss over case, a
    /// trailing dot or an IDNA name. The container comes from
    /// [`rattler_azure::container`], the derivation the write path also uses; two
    /// that disagreed would look a grant up for one container and send it to
    /// another.
    fn resolve(&self, url: &Url) -> MiddlewareResult<Resolved> {
        let channel = AzureChannelUrl::parse(url.as_str()).map_err(|e| {
            // The URL is not echoed back: the one rejection a user hits here is
            // userinfo, and quoting it would print their password.
            reqwest_middleware::Error::Middleware(anyhow::Error::from(e))
        })?;

        let unconfigured = AzureEndpointOptions::default();
        let entry = self.options.get(channel.host()).unwrap_or(&unconfigured);

        // A URL with no container segment resolves to no grant; a container segment
        // Azure could never accept is a malformed endpoint, and saying so beats an
        // anonymous request that comes back as an unexplained 401.
        let container = rattler_azure::container(&channel, entry.endpoint().addressing)
            .map_err(|e| reqwest_middleware::Error::Middleware(anyhow::Error::from(e)))?;

        let options = entry.fetch(container.as_ref());
        let grant = match container {
            Some(container) if options.auth.is_granted() => Grant::Granted(container),
            container => Grant::Ungranted(container),
        };

        Ok(Resolved {
            channel,
            grant,
            scheme: options.scheme,
        })
    }

    /// Whether the URL already carries an explicit SAS token (a `sig` query
    /// parameter). Such a URL is self-authenticating and must not be re-signed.
    fn has_sas_token(url: &Url) -> bool {
        url.query_pairs().any(|(key, _)| key == "sig")
    }

    /// Under [`Grant::Ungranted`] the credential is not *resolved* either. reqsign
    /// would otherwise probe the managed-identity / IMDS endpoint and block until it
    /// times out (~30s where there is no metadata service), and would pull an
    /// ambient credential into memory for a host the user never granted.
    async fn sign(&self, req: &mut Request, grant: &Grant) -> MiddlewareResult<()> {
        if Self::has_sas_token(req.url()) {
            return Ok(());
        }

        if !req.headers().contains_key("x-ms-version") {
            req.headers_mut()
                .insert("x-ms-version", http::HeaderValue::from_static(X_MS_VERSION));
        }

        let container = match grant {
            Grant::Ungranted(_) => {
                // The authority, not `host_str()`: a message naming a host the user
                // could act on must carry the port, or it names a host that is not
                // the one in their config.
                tracing::debug!(
                    "no `azure-options` auth grant for `{}`; sending `az://` request unsigned",
                    req.url().authority()
                );
                return Ok(());
            }
            Grant::Granted(container) => container,
        };

        let mut builder = http::Request::builder()
            .method(req.method().clone())
            .uri(req.url().as_str());
        for (name, value) in req.headers() {
            builder = builder.header(name, value);
        }
        let http_req = builder.body(()).map_err(|e| {
            reqwest_middleware::Error::Middleware(anyhow::anyhow!(
                "failed to build http request for signing: {e}"
            ))
        })?;
        let (mut parts, ()) = http_req.into_parts();

        // reqsign says only "failed to load signing credential": its chain walks
        // past a provider that errors exactly as it walks past one that finds
        // nothing, so an expired `az login` and an empty environment arrive here
        // indistinguishable, after however long the chain took to give up. The host
        // and the grant that asked for signing are both in scope here and nowhere
        // further up, so this is where they get attached.
        self.signer.sign(&mut parts, None).await.map_err(|e| {
            let authority = req.url().authority();
            reqwest_middleware::Error::Middleware(anyhow::anyhow!(
                "could not resolve an Azure credential for `{container}` on `{authority}`, which \
                 `[azure-options.\"{authority}\".auth]` `{container} = true` requires: {e}\n\
                 \n\
                 Try one of:\n\
                 \x20 - `az login`\n\
                 \x20 - `AZURE_STORAGE_ACCOUNT_NAME` and `AZURE_STORAGE_ACCOUNT_KEY` in the \
                 environment\n\
                 \x20 - set `{container} = false` to fetch this container anonymously\n\
                 \n\
                 Debug logging lists the credential providers that were tried."
            ))
        })?;

        *req.headers_mut() = parts.headers;
        let signed_url = Url::parse(&parts.uri.to_string()).map_err(|e| {
            reqwest_middleware::Error::Middleware(anyhow::anyhow!(
                "failed to parse signed azure URL '{}': {e}",
                parts.uri
            ))
        })?;
        *req.url_mut() = signed_url;
        Ok(())
    }
}

#[async_trait]
impl Middleware for AzureMiddleware {
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut http::Extensions,
        next: Next<'_>,
    ) -> MiddlewareResult<Response> {
        if req.url().scheme() != "az" {
            return next.run(req, extensions).await;
        }

        let Resolved {
            channel,
            grant,
            scheme,
        } = self.resolve(req.url())?;
        *req.url_mut() = channel.wire(scheme);
        self.sign(&mut req, &grant).await?;

        let response = next.run(req, extensions).await?;

        if let Grant::Ungranted(Some(container)) = &grant
            && response.status() == http::StatusCode::NOT_FOUND
            && first_404_for_container(channel.host(), container)
        {
            // One line, and spelled the way `AzureUrlError::InvalidHost` spells its
            // fix: a wrapped multi-line hint is harder to grep out of a log, and
            // the two guided messages should read as the same instruction.
            tracing::warn!(
                "`{}` returned 404 and container `{container}` has no `azure-options` auth grant. \
                 Azure answers an anonymous read of a *private* container with 404 rather than \
                 403, so a missing grant looks exactly like a missing file. If the container is \
                 private, grant it in your user configuration with \
                 `[azure-options.\"{}\".auth]` and `{container} = true`.",
                channel.canonical(),
                channel.host()
            );
        }

        Ok(response)
    }
}

/// Whether this container still owes the 404 hint, claiming it if so.
///
/// A 404 is the *normal* answer to plenty of requests a healthy public channel
/// makes: the repodata gateway probes for a shard index under every subdir, and a
/// non-sharded channel misses every time. Per container and not per host, because
/// the line to add differs per container.
fn first_404_for_container(host: &AzureHost, container: &ContainerName) -> bool {
    static HINTED: std::sync::LazyLock<
        std::sync::Mutex<std::collections::HashSet<(AzureHost, ContainerName)>>,
    > = std::sync::LazyLock::new(Default::default);
    HINTED
        .lock()
        .expect("the 404-hint set is never held across a panic")
        .insert((host.clone(), container.clone()))
}

#[cfg(test)]
mod tests {
    use rattler_azure::{Addressing, Auth, AzureEndpoint, AzureScheme};

    use super::*;

    fn container(name: &str) -> ContainerName {
        ContainerName::new(name).expect("test container name")
    }

    fn options(
        authority: &str,
        options: AzureEndpointOptions,
    ) -> HashMap<AzureHost, AzureEndpointOptions> {
        HashMap::from([(AzureHost::parse(authority).expect("test host"), options)])
    }

    fn granting(container_name: &str) -> AzureEndpointOptions {
        AzureEndpointOptions::new(
            [(container(container_name), Auth::DefaultChain)],
            AzureEndpoint::default(),
        )
    }

    fn middleware(options: HashMap<AzureHost, AzureEndpointOptions>) -> AzureMiddleware {
        AzureMiddleware::new(Client::new(), options)
    }

    fn wire_of(middleware: &AzureMiddleware, url: &str) -> String {
        let resolved = middleware
            .resolve(&Url::parse(url).expect("test url"))
            .expect("url should resolve");
        resolved.channel.wire(resolved.scheme).to_string()
    }

    fn resolve(middleware: &AzureMiddleware, url: &str) -> Resolved {
        middleware
            .resolve(&Url::parse(url).expect("test url"))
            .unwrap_or_else(|err| panic!("{url} should resolve: {err}"))
    }

    #[test]
    fn rewrites_to_https_without_an_entry() {
        let middleware = middleware(HashMap::new());
        assert_eq!(
            wire_of(
                &middleware,
                "az://myacct.blob.core.windows.net/mychannel/noarch/repodata.json"
            ),
            "https://myacct.blob.core.windows.net/mychannel/noarch/repodata.json"
        );
        assert_eq!(
            wire_of(
                &middleware,
                "az://acct.blob.core.windows.net/general/x.json?sv=2021&sig=abc#frag"
            ),
            "https://acct.blob.core.windows.net/general/x.json?sv=2021&sig=abc#frag"
        );
    }

    /// An emulator entry is the only thing that can send an `az://` URL in
    /// cleartext, and the port has to survive the rewrite under either scheme.
    #[test]
    fn rewrites_to_http_for_an_emulator_entry() {
        let emulator = middleware(options("127.0.0.1:10000", emulator_entry(["general"])));
        assert_eq!(
            wire_of(
                &emulator,
                "az://127.0.0.1:10000/devstoreaccount1/general/noarch/repodata.json"
            ),
            "http://127.0.0.1:10000/devstoreaccount1/general/noarch/repodata.json"
        );

        assert_eq!(
            wire_of(
                &middleware(HashMap::new()),
                "az://127.0.0.1:10000/devstoreaccount1/general/noarch/repodata.json"
            ),
            "https://127.0.0.1:10000/devstoreaccount1/general/noarch/repodata.json"
        );
    }

    #[test]
    fn a_grant_applies_regardless_of_how_the_host_is_spelled() {
        let middleware = middleware(options(
            "MyCompany.blob.core.windows.net.",
            granting("releases"),
        ));
        assert_eq!(
            resolve(
                &middleware,
                "az://mycompany.blob.core.windows.net/releases/x.json"
            )
            .grant,
            Grant::Granted(container("releases"))
        );
    }

    #[test]
    fn a_grant_stops_at_the_container_it_names() {
        let middleware = middleware(options(
            "mycompany.blob.core.windows.net",
            AzureEndpointOptions::new(
                [
                    (container("releases"), Auth::DefaultChain),
                    // Redundant with omission, and legal: it says "deliberately
                    // unsigned" rather than "forgotten".
                    (container("public"), Auth::Anonymous),
                ],
                AzureEndpoint::default(),
            ),
        ));

        for (url, expected) in [
            (
                "az://mycompany.blob.core.windows.net/releases/x.json",
                Grant::Granted(container("releases")),
            ),
            (
                "az://mycompany.blob.core.windows.net/public/x.json",
                Grant::Ungranted(Some(container("public"))),
            ),
            (
                "az://mycompany.blob.core.windows.net/staging/x.json",
                Grant::Ungranted(Some(container("staging"))),
            ),
        ] {
            assert_eq!(resolve(&middleware, url).grant, expected, "{url}");
        }
    }

    #[test]
    fn a_container_is_read_through_the_hosts_addressing() {
        let path_style = middleware(options("127.0.0.1:10000", emulator_entry(["general"])));
        let resolved = resolve(
            &path_style,
            "az://127.0.0.1:10000/devstoreaccount1/general/noarch/repodata.json",
        );
        assert_eq!(resolved.grant, Grant::Granted(container("general")));

        // Host-style on the same URL reads the account segment as the container, so
        // the grant does not apply — the addressing is what decides which name a
        // grant is even about.
        let host_style = middleware(options(
            "127.0.0.1:10000",
            AzureEndpointOptions::new(
                [(container("general"), Auth::DefaultChain)],
                AzureEndpoint {
                    scheme: AzureScheme::Http,
                    addressing: Addressing::HostStyle,
                },
            ),
        ));
        let resolved = resolve(
            &host_style,
            "az://127.0.0.1:10000/devstoreaccount1/general/noarch/repodata.json",
        );
        assert_eq!(
            resolved.grant,
            Grant::Ungranted(Some(container("devstoreaccount1")))
        );
    }

    #[test]
    fn a_url_without_a_container_is_anonymous() {
        let middleware = middleware(options(
            "mycompany.blob.core.windows.net",
            granting("releases"),
        ));

        for url in [
            "az://mycompany.blob.core.windows.net",
            "az://mycompany.blob.core.windows.net/",
            "az://mycompany.blob.core.windows.net/?comp=list",
        ] {
            assert_eq!(
                resolve(&middleware, url).grant,
                Grant::Ungranted(None),
                "{url}"
            );
        }
    }

    #[test]
    fn a_url_with_an_unusable_container_is_refused() {
        let middleware = middleware(options(
            "mycompany.blob.core.windows.net",
            granting("releases"),
        ));

        for url in [
            "az://mycompany.blob.core.windows.net/Releases/x.json",
            "az://mycompany.blob.core.windows.net/ab/x.json",
        ] {
            let err = middleware
                .resolve(&Url::parse(url).unwrap())
                .expect_err("an illegal container name must be refused");
            assert!(err.to_string().contains("container name"), "{url}: {err}");
        }
    }

    #[test]
    fn rejects_userinfo() {
        let middleware = middleware(HashMap::new());
        for url in [
            "az://user:pass@acct.blob.core.windows.net/general/x.json",
            "az://user@acct.blob.core.windows.net/general/x.json",
        ] {
            let err = middleware
                .resolve(&Url::parse(url).unwrap())
                .expect_err("userinfo must be refused");
            assert!(err.to_string().contains("userinfo"), "{err}");
        }
        assert!(
            middleware
                .resolve(&Url::parse("az://acct.blob.core.windows.net/general/x.json").unwrap())
                .is_ok()
        );
    }

    #[tokio::test]
    async fn passes_through_non_az_schemes_unchanged() {
        use reqwest_middleware::ClientBuilder;
        let client = ClientBuilder::new(Client::new())
            .with(middleware(HashMap::new()))
            .build();
        // A non-`az` request must not be rewritten; it should be attempted as-is
        // (and fail on DNS), proving the middleware left it untouched.
        let result = client
            .get("https://this-host-does-not-exist.invalid/x")
            .send()
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn an_ungranted_container_sends_unsigned_without_resolving_a_credential() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        #[derive(Debug)]
        struct RecordingProvider(Arc<AtomicBool>);
        impl ProvideCredential for RecordingProvider {
            type Credential = Credential;
            async fn provide_credential(
                &self,
                _ctx: &Context,
            ) -> reqsign_core::Result<Option<Credential>> {
                self.0.store(true, Ordering::SeqCst);
                Ok(None)
            }
        }

        let probed = Arc::new(AtomicBool::new(false));
        let middleware = AzureMiddleware::with_credential_provider(
            Client::new(),
            RecordingProvider(probed.clone()),
            HashMap::new(),
        );
        let mut req = Client::new()
            .get("https://acct.blob.core.windows.net/pub/noarch/repodata.json")
            .build()
            .unwrap();

        middleware
            .sign(&mut req, &Grant::Ungranted(None))
            .await
            .expect("an ungranted request must pass through unsigned");

        assert!(
            !probed.load(Ordering::SeqCst),
            "credential provider must not be probed without a grant"
        );
        assert!(
            req.headers().get(http::header::AUTHORIZATION).is_none(),
            "unsigned request must not carry an Authorization header"
        );
        assert!(
            !req.url().query_pairs().any(|(k, _)| k == "sig"),
            "unsigned request must not gain a SAS query parameter"
        );
    }

    #[tokio::test]
    async fn a_granted_container_is_signed() {
        use reqsign_azure_storage::StaticCredentialProvider;

        let middleware = AzureMiddleware::with_credential_provider(
            Client::new(),
            // A valid base64 account key, so the provider yields a usable
            // SharedKey credential.
            StaticCredentialProvider::new_shared_key("acct", "dGVzdF9rZXk="),
            options("acct.blob.core.windows.net", granting("releases")),
        );
        let mut req = Client::new()
            .get("https://acct.blob.core.windows.net/releases/noarch/repodata.json")
            .build()
            .unwrap();

        middleware
            .sign(&mut req, &Grant::Granted(container("releases")))
            .await
            .unwrap();

        let authorization = req
            .headers()
            .get(http::header::AUTHORIZATION)
            .expect("a granted container must be signed");
        assert!(
            authorization.to_str().unwrap().starts_with("SharedKey "),
            "{authorization:?}"
        );
    }

    #[tokio::test]
    async fn a_granted_container_with_broken_credentials_is_a_hard_error() {
        use reqsign_core::ProvideCredentialChain;

        let middleware = AzureMiddleware::with_credential_provider(
            Client::new(),
            ProvideCredentialChain::<Credential>::new(),
            options("acct.blob.core.windows.net", granting("releases")),
        );
        let mut req = Client::new()
            .get("https://acct.blob.core.windows.net/releases/noarch/repodata.json")
            .build()
            .unwrap();

        let result = middleware
            .sign(&mut req, &Grant::Granted(container("releases")))
            .await;

        assert!(
            result.is_err(),
            "a granted-but-failing credential must be a hard error, not unsigned"
        );
        assert!(
            req.headers().get(http::header::AUTHORIZATION).is_none(),
            "a failed signing attempt must not leave a partial Authorization header"
        );

        let message = result.unwrap_err().to_string();
        for expected in [
            "acct.blob.core.windows.net",
            "releases = true",
            "az login",
            "AZURE_STORAGE_ACCOUNT_KEY",
        ] {
            assert!(
                message.contains(expected),
                "the failure must name `{expected}`, got: {message}"
            );
        }
    }

    #[tokio::test]
    async fn a_sas_in_the_url_passes_through() {
        use reqsign_azure_storage::StaticCredentialProvider;

        let middleware = AzureMiddleware::with_credential_provider(
            Client::new(),
            StaticCredentialProvider::new_shared_key("acct", "dGVzdF9rZXk="),
            options("acct.blob.core.windows.net", granting("releases")),
        );
        let mut req = Client::new()
            .get("https://acct.blob.core.windows.net/releases/x.json?sv=2021&sig=abc")
            .build()
            .unwrap();

        middleware
            .sign(&mut req, &Grant::Granted(container("releases")))
            .await
            .unwrap();

        assert!(
            req.headers().get(http::header::AUTHORIZATION).is_none(),
            "a URL carrying an explicit SAS must not be re-signed"
        );
        assert!(
            !req.headers().contains_key("x-ms-version"),
            "a self-authenticating SAS URL is left untouched"
        );
        assert_eq!(
            req.url().as_str(),
            "https://acct.blob.core.windows.net/releases/x.json?sv=2021&sig=abc"
        );
    }

    async fn spawn_404_server() -> AzureHost {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = axum::Router::new().fallback(axum::http::StatusCode::NOT_FOUND);
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        AzureHost::parse(&addr.to_string()).unwrap()
    }

    fn emulator_entry<'a>(granted: impl IntoIterator<Item = &'a str>) -> AzureEndpointOptions {
        AzureEndpointOptions::new(
            granted
                .into_iter()
                .map(|name| (container(name), Auth::DefaultChain)),
            AzureEndpoint {
                scheme: AzureScheme::Http,
                addressing: Addressing::PathStyle,
            },
        )
    }

    async fn get_az(
        middleware: AzureMiddleware,
        host: &AzureHost,
        container: &str,
    ) -> reqwest::StatusCode {
        reqwest_middleware::ClientBuilder::new(Client::new())
            .with(middleware)
            .build()
            .get(format!(
                "az://{host}/devstoreaccount1/{container}/noarch/repodata.json"
            ))
            .send()
            .await
            .expect("request through azure middleware failed")
            .status()
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn the_404_hint_names_the_config_block_for_an_ungranted_container() {
        let host = spawn_404_server().await;
        let middleware = middleware(options(&host.to_string(), emulator_entry([])));

        assert_eq!(get_az(middleware, &host, "general").await, 404);

        assert!(logs_contain(&format!("[azure-options.\"{host}\".auth]")));
        assert!(logs_contain("general = true"));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn the_404_hint_is_emitted_once_per_container() {
        let host = spawn_404_server().await;
        let client = reqwest_middleware::ClientBuilder::new(Client::new())
            .with(middleware(options(&host.to_string(), emulator_entry([]))))
            .build();

        for container in ["general", "staging"] {
            for subdir in ["noarch", "linux-64", "osx-64"] {
                let status = client
                    .get(format!(
                        "az://{host}/devstoreaccount1/{container}/{subdir}/\
                         repodata_shards.msgpack.zst"
                    ))
                    .send()
                    .await
                    .expect("request through azure middleware failed")
                    .status();
                assert_eq!(status, 404);
            }
        }

        for container in ["general", "staging"] {
            logs_assert(move |lines: &[&str]| {
                let hints = lines
                    .iter()
                    .filter(|line| line.contains(&format!("{container} = true")))
                    .count();
                (hints == 1).then_some(()).ok_or_else(|| {
                    format!("expected exactly one hint for {container}, got {hints}")
                })
            });
        }
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn the_404_hint_is_silent_for_a_granted_container() {
        use reqsign_azure_storage::StaticCredentialProvider;

        let host = spawn_404_server().await;
        let middleware = AzureMiddleware::with_credential_provider(
            Client::new(),
            StaticCredentialProvider::new_shared_key("devstoreaccount1", "dGVzdF9rZXk="),
            options(&host.to_string(), emulator_entry(["general"])),
        );

        assert_eq!(get_az(middleware, &host, "general").await, 404);

        assert!(!logs_contain("azure-options"));
    }
}
