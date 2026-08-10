//! Middleware to handle `az://` URLs to pull artifacts from Azure Blob Storage.
use std::collections::HashMap;

use async_trait::async_trait;
use rattler_azure::{
    AzureChannelUrl, AzureCoordinates, AzureEndpointOptions, AzureHost, AzureScheme, AzureUrlError,
};
use reqsign_azure_storage::{
    Credential, DefaultCredentialProvider, EnvCredentialProvider, RequestSigner,
};
use reqsign_command_execute_tokio::TokioCommandExecute;
#[cfg(test)]
use reqsign_core::ProvideCredential;
use reqsign_core::{Context, OsEnv, Signer};
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
/// See [`rattler_azure::options`] for what an `azure-options` entry grants.
///
/// Granted credentials come from reqsign's [`DefaultCredentialProvider`] chain;
/// rattler's [`crate::AuthenticationStorage`] has no Azure variant.
#[derive(Clone)]
pub struct AzureMiddleware {
    /// The credential chains this middleware may sign from. Each signer caches
    /// its resolved credential internally.
    signers: Signers,

    /// Whole `azure-options` entries, keyed by the same normalized authority the
    /// config table is keyed by. An absent host behaves as a defaulted entry, so a
    /// miss is never a separate code path.
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

/// The credential chains a middleware signs from.
#[derive(Clone)]
enum Signers {
    /// The ambient chain, narrowed off Azure. `any` reaches everything reqsign
    /// can find — Azure CLI, IMDS, workload identity — and so is only reached for
    /// a host that is demonstrably Azure over TLS; `explicit` reads
    /// `AZURE_STORAGE_*` and nothing else, and covers every other granted host.
    /// See [`AzureMiddleware::signer_for`].
    Ambient {
        any: Signer<Credential>,
        explicit: Signer<Credential>,
    },

    /// A single caller-supplied chain, used for every host. Nothing here was
    /// discovered from the environment, so there is nothing ambient to narrow.
    #[cfg(test)]
    Given(Signer<Credential>),
}

/// The account and container a request addresses, and whether it may be signed.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Grant {
    /// Send unsigned.
    Ungranted,
    Granted(AzureCoordinates),
}

/// Whether the ambient credential chain may be reached for this request: a
/// public Azure blob endpoint, over TLS. See [`AzureMiddleware::signer_for`].
fn ambient_is_safe(channel: &AzureChannelUrl, scheme: AzureScheme) -> bool {
    scheme == AzureScheme::Https && channel.host().is_known_azure_blob_endpoint()
}

/// The reqsign context every signer shares. `client` also carries reqsign's
/// credential resolution (IMDS, managed identity, AAD token fetches), so its
/// proxy, CA bundle and TLS settings apply there too.
fn signing_context(client: Client) -> Context {
    Context::new()
        .with_file_read(TokioFileRead)
        .with_http_send(ReqwestHttpSend::new(client))
        .with_command_execute(TokioCommandExecute)
        .with_env(OsEnv)
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
        let ctx = signing_context(client);
        Self {
            signers: Signers::Ambient {
                any: Signer::new(
                    ctx.clone(),
                    DefaultCredentialProvider::new(),
                    RequestSigner::new(),
                ),
                explicit: Signer::new(ctx, EnvCredentialProvider::new(), RequestSigner::new()),
            },
            options: options.into_iter().collect(),
        }
    }

    /// Create a middleware that grants no host, so every `az://` request is sent
    /// unsigned.
    pub fn anonymous(client: Client) -> Self {
        Self::new(client, [])
    }

    /// A middleware signing from one named provider, whatever the host.
    #[cfg(test)]
    fn with_credential_provider(
        client: Client,
        provider: impl ProvideCredential<Credential = Credential> + 'static,
        options: impl IntoIterator<Item = (AzureHost, AzureEndpointOptions)>,
    ) -> Self {
        Self {
            signers: Signers::Given(Signer::new(
                signing_context(client),
                provider,
                RequestSigner::new(),
            )),
            options: options.into_iter().collect(),
        }
    }

    /// The signer whose credential sources are safe to reach for `host`.
    ///
    /// An AAD access token is audience-wide by construction — Azure issues it for
    /// `https://storage.azure.com/`, valid against every account the principal can
    /// reach — and a Shared Key signature names the account from the *credential*,
    /// not the request, so it replays verbatim against production. Neither can be
    /// scoped down at the point of use. So the ambient chain is only reached for a
    /// host that is demonstrably Azure over TLS; anywhere else — an emulator, a
    /// proxy, a private endpoint under its own name — the user must name a
    /// credential explicitly, which is a secret they chose to put on that host.
    ///
    /// This is what makes granting a non-Azure host safe, and it is why the config
    /// layer no longer refuses cleartext grants: the credential that a cleartext
    /// grant could have leaked can no longer be resolved for such a host at all.
    fn signer_for(&self, channel: &AzureChannelUrl, scheme: AzureScheme) -> &Signer<Credential> {
        match &self.signers {
            #[cfg(test)]
            Signers::Given(signer) => signer,
            Signers::Ambient { any, explicit } => {
                if ambient_is_safe(channel, scheme) {
                    any
                } else {
                    explicit
                }
            }
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
        // `account_and_container`, the derivation the write path also uses: a grant
        // is keyed by both, so deriving only the container here would look one up
        // for `accta/general` and spend it on `acctb/general` under path-style.
        //
        // A URL that simply does not carry the pair — no container segment, or a
        // host with no account label to read host-style — has nothing to attribute
        // a grant to, so it goes out anonymous. A name that is *present but
        // malformed* is a broken endpoint, and saying so beats an anonymous request
        // that comes back as an unexplained 404.
        let coordinates =
            match rattler_azure::account_and_container(&channel, entry.endpoint().addressing) {
                Ok(coordinates) => Some(coordinates),
                Err(
                    AzureUrlError::NoContainer
                    | AzureUrlError::NoAccount
                    | AzureUrlError::InvalidHost(_),
                ) => None,
                Err(e) => {
                    return Err(reqwest_middleware::Error::Middleware(anyhow::Error::from(
                        e,
                    )));
                }
            };

        let options = entry.fetch(coordinates.as_ref());
        let grant = match coordinates {
            Some(coordinates) if options.auth.is_granted() => Grant::Granted(coordinates),
            _ => Grant::Ungranted,
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
        // Case-insensitively: Azure matches query parameter names that way, so
        // `?SIG=…` is just as much a pre-signed URL, and re-signing one would
        // replace the caller's own credential.
        url.query_pairs()
            .any(|(key, _)| key.eq_ignore_ascii_case("sig"))
    }

    /// Under [`Grant::Ungranted`] the credential is not *resolved* either. reqsign
    /// would otherwise probe the managed-identity / IMDS endpoint and block until it
    /// times out, and would pull an ambient credential into memory for a host the user
    /// never granted.
    async fn sign(
        &self,
        req: &mut Request,
        grant: &Grant,
        channel: &AzureChannelUrl,
        scheme: AzureScheme,
    ) -> MiddlewareResult<()> {
        if Self::has_sas_token(req.url()) {
            return Ok(());
        }

        if !req.headers().contains_key("x-ms-version") {
            req.headers_mut()
                .insert("x-ms-version", http::HeaderValue::from_static(X_MS_VERSION));
        }

        let container = match grant {
            Grant::Ungranted => {
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

        let (mut parts, ()) = http::Request::new(()).into_parts();
        parts.method = req.method().clone();
        parts.uri = req.url().as_str().parse().map_err(|e| {
            reqwest_middleware::Error::Middleware(anyhow::anyhow!(
                "failed to build http request for signing: {e}"
            ))
        })?;
        parts.headers = req.headers().clone();

        // Shared Key signs `Content-Length`, so it has to be on the request
        // *before* signing and match what goes on the wire. reqwest sets it later,
        // from the body, and a signature computed without it is rejected with a
        // 403 that names nothing.
        match req.body().and_then(reqwest::Body::as_bytes) {
            Some(body) => {
                parts.headers.insert(
                    http::header::CONTENT_LENGTH,
                    http::HeaderValue::from(body.len()),
                );
            }
            // A streaming body has no length to sign, and reqwest will send it
            // chunked. Azure's Shared Key scheme has nothing to say about that, so
            // the signature would be wrong in a way only the server sees.
            None if req.body().is_some() => {
                return Err(reqwest_middleware::Error::Middleware(anyhow::anyhow!(
                    "cannot sign a streaming request body for `{}`: Shared Key signs                      `Content-Length`, which a body of unknown size does not have",
                    req.url().authority()
                )));
            }
            None => {}
        }

        // reqsign says only "failed to load signing credential": its chain walks
        // past a provider that errors exactly as it walks past one that finds
        // nothing, so an expired `az login` and an empty environment arrive here
        // indistinguishable, after however long the chain took to give up. The host
        // and the grant that asked for signing are both in scope here and nowhere
        // further up, so this is where they get attached.
        let signer = self.signer_for(channel, scheme);
        signer.sign(&mut parts, None).await.map_err(|e| {
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
            // The signed URI carries the signature reqsign just attached, so it is
            // reported masked — an error message is the one place a credential
            // reliably ends up in a log.
            reqwest_middleware::Error::Middleware(anyhow::anyhow!(
                "failed to parse signed azure URL '{}': {e}",
                rattler_redaction::redact_signatures_in_text(
                    &parts.uri.to_string(),
                    rattler_redaction::DEFAULT_REDACTION_STR,
                )
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
        self.sign(&mut req, &grant, &channel, scheme).await?;

        let response = next.run(req, extensions).await?;

        if let Grant::Ungranted = &grant
            && response.status() == http::StatusCode::NOT_FOUND
        {
            tracing::warn!(
                "404 from `{}`, which has no `azure-options` auth grant; Azure answers an \
                 unauthorized read of a private container with 404, so grant the container if it \
                 is private",
                channel.canonical()
            );
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use rattler_azure::{Addressing, Auth, AzureEndpoint, AzureScheme};

    use super::*;

    fn coords(account: &str, container: &str) -> AzureCoordinates {
        AzureCoordinates::parse(&format!("{account}/{container}")).expect("test coordinates")
    }

    /// The account every host-style test host carries.
    fn container(name: &str) -> AzureCoordinates {
        coords("mycompany", name)
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

    fn granting_on(account: &str, container_name: &str) -> AzureEndpointOptions {
        AzureEndpointOptions::new(
            [(coords(account, container_name), Auth::DefaultChain)],
            AzureEndpoint::default(),
        )
    }

    fn middleware(options: HashMap<AzureHost, AzureEndpointOptions>) -> AzureMiddleware {
        AzureMiddleware::new(Client::new(), options)
    }

    /// The channel URL a already-rewritten request came from, for the `sign`
    /// tests, which build the wire request directly rather than via `handle`.
    fn channel_of(req: &Request) -> AzureChannelUrl {
        let az = req.url().as_str().replacen("https://", "az://", 1);
        AzureChannelUrl::parse(&az).expect("test channel url")
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
                Grant::Ungranted,
            ),
            (
                "az://mycompany.blob.core.windows.net/staging/x.json",
                Grant::Ungranted,
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
        assert_eq!(
            resolved.grant,
            Grant::Granted(coords("devstoreaccount1", "general"))
        );

        // Host-style on the same URL has no account label to read — an IP literal
        // cannot carry one — so there are no coordinates to attribute a grant to.
        // The addressing is what decides whether a URL names a grant at all.
        let host_style = middleware(options(
            "127.0.0.1:10000",
            AzureEndpointOptions::new(
                [(coords("devstoreaccount1", "general"), Auth::DefaultChain)],
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
        assert_eq!(resolved.grant, Grant::Ungranted);
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
            assert_eq!(resolve(&middleware, url).grant, Grant::Ungranted, "{url}");
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

    #[test]
    fn the_ambient_chain_is_reached_only_for_azure_over_tls() {
        for (url, scheme, safe) in [
            (
                "az://acct.blob.core.windows.net/pub/x.json",
                AzureScheme::Https,
                true,
            ),
            // Azure by name, but the entry downgrades the wire to cleartext, where
            // the credential the ambient chain would resolve is on the wire.
            (
                "az://acct.blob.core.windows.net/pub/x.json",
                AzureScheme::Http,
                false,
            ),
            // A proxy or private endpoint under its own name: an AAD token minted
            // here is valid against every account the principal can reach.
            (
                "az://blobs.mycompany.com/acct/pub/x.json",
                AzureScheme::Https,
                false,
            ),
            (
                "az://127.0.0.1:10000/devstoreaccount1/pub/x.json",
                AzureScheme::Http,
                false,
            ),
        ] {
            let channel = AzureChannelUrl::parse(url).expect(url);
            assert_eq!(
                ambient_is_safe(&channel, scheme),
                safe,
                "{url} over {scheme:?}"
            );
        }
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
        let channel = channel_of(&req);

        middleware
            .sign(&mut req, &Grant::Ungranted, &channel, AzureScheme::Https)
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
            options(
                "acct.blob.core.windows.net",
                granting_on("acct", "releases"),
            ),
        );
        let mut req = Client::new()
            .get("https://acct.blob.core.windows.net/releases/noarch/repodata.json")
            .build()
            .unwrap();
        let channel = channel_of(&req);

        middleware
            .sign(
                &mut req,
                &Grant::Granted(coords("acct", "releases")),
                &channel,
                AzureScheme::Https,
            )
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

    /// Shared Key signs `Content-Length`, so a body whose length is only known
    /// once it has been streamed cannot be signed at all — better a message than
    /// a 403 from Azure that explains nothing.
    #[tokio::test]
    async fn a_streaming_body_is_refused_rather_than_signed_without_its_length() {
        use reqsign_azure_storage::StaticCredentialProvider;

        let middleware = AzureMiddleware::with_credential_provider(
            Client::new(),
            StaticCredentialProvider::new_shared_key("acct", "dGVzdF9rZXk="),
            options(
                "acct.blob.core.windows.net",
                granting_on("acct", "releases"),
            ),
        );
        let stream = futures::stream::once(async { Ok::<_, std::io::Error>("chunk") });
        let mut req = Client::new()
            .put("https://acct.blob.core.windows.net/releases/noarch/x.conda")
            .body(reqwest::Body::wrap_stream(stream))
            .build()
            .unwrap();
        let channel = channel_of(&req);

        let error = middleware
            .sign(
                &mut req,
                &Grant::Granted(coords("acct", "releases")),
                &channel,
                AzureScheme::Https,
            )
            .await
            .expect_err("a body of unknown size must not be signed");
        assert!(error.to_string().contains("Content-Length"), "{error}");
    }

    /// The signature covers `Content-Length`, so it has to be on the request
    /// before signing and match what reqwest puts on the wire.
    #[tokio::test]
    async fn a_sized_body_is_signed_with_its_content_length() {
        use reqsign_azure_storage::StaticCredentialProvider;

        let middleware = AzureMiddleware::with_credential_provider(
            Client::new(),
            StaticCredentialProvider::new_shared_key("acct", "dGVzdF9rZXk="),
            options(
                "acct.blob.core.windows.net",
                granting_on("acct", "releases"),
            ),
        );
        let mut req = Client::new()
            .put("https://acct.blob.core.windows.net/releases/noarch/x.conda")
            .body("body")
            .build()
            .unwrap();
        let channel = channel_of(&req);

        middleware
            .sign(
                &mut req,
                &Grant::Granted(coords("acct", "releases")),
                &channel,
                AzureScheme::Https,
            )
            .await
            .expect("a sized body must be signable");
        assert_eq!(
            req.headers().get(http::header::CONTENT_LENGTH),
            Some(&http::HeaderValue::from_static("4"))
        );
    }

    #[tokio::test]
    async fn a_granted_container_with_broken_credentials_is_a_hard_error() {
        use reqsign_core::ProvideCredentialChain;

        let middleware = AzureMiddleware::with_credential_provider(
            Client::new(),
            ProvideCredentialChain::<Credential>::new(),
            options(
                "acct.blob.core.windows.net",
                granting_on("acct", "releases"),
            ),
        );
        let mut req = Client::new()
            .get("https://acct.blob.core.windows.net/releases/noarch/repodata.json")
            .build()
            .unwrap();
        let channel = channel_of(&req);

        let result = middleware
            .sign(
                &mut req,
                &Grant::Granted(coords("acct", "releases")),
                &channel,
                AzureScheme::Https,
            )
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
            options(
                "acct.blob.core.windows.net",
                granting_on("acct", "releases"),
            ),
        );
        let mut req = Client::new()
            .get("https://acct.blob.core.windows.net/releases/x.json?sv=2021&sig=abc")
            .build()
            .unwrap();
        let channel = channel_of(&req);

        middleware
            .sign(
                &mut req,
                &Grant::Granted(coords("acct", "releases")),
                &channel,
                AzureScheme::Https,
            )
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

    /// A path-style emulator entry, whose grants sit under the emulator's
    /// well-known account name.
    fn emulator_entry<'a>(granted: impl IntoIterator<Item = &'a str>) -> AzureEndpointOptions {
        AzureEndpointOptions::new(
            granted
                .into_iter()
                .map(|name| (coords("devstoreaccount1", name), Auth::DefaultChain)),
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
    async fn a_404_for_an_ungranted_container_warns() {
        let host = spawn_404_server().await;
        let middleware = middleware(options(&host.to_string(), emulator_entry([])));

        assert_eq!(get_az(middleware, &host, "general").await, 404);

        assert!(logs_contain("azure-options"));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn a_404_for_a_granted_container_is_silent() {
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
