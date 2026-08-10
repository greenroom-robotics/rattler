//! Live fetch-path integration tests against a local Azurite emulator.
//!
//! Everything is driven through the single `azure-options` entry built by
//! `azurite_entry` below; there is no out-of-band account or endpoint
//! configuration on the fetch path.
//!
//! Run with:
//!
//! ```text
//! docker run --rm -p 10000:10000 mcr.microsoft.com/azure-storage/azurite \
//!     azurite-blob --blobHost 0.0.0.0
//! cargo nextest run -p rattler_networking --features azure --test azure_azurite_fetch \
//!     --run-ignored all
//! ```

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use rattler_azure::{
    Addressing, Auth, AzureCoordinates, AzureEndpoint, AzureEndpointOptions, AzureHost, AzureScheme,
};
use rattler_networking::AzureMiddleware;
use reqwest::{
    Request, Response,
    header::{AUTHORIZATION, HeaderMap},
};
use reqwest_middleware::{
    ClientBuilder, ClientWithMiddleware, Middleware, Next, Result as MiddlewareResult,
};
use url::Url;

/// Azurite's development account and its fixed key. Not a secret: both are
/// published constants of the emulator and only ever address a loopback port.
const ACCOUNT: &str = "devstoreaccount1";
const ACCOUNT_KEY: &str =
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

/// The authority, which is also the exact `azure-options` table key. Host-style
/// addressing cannot read an account out of an IP literal, so this needs
/// path-style.
const AUTHORITY: &str = "127.0.0.1:10000";

/// Azurite creates containers as private, which is what makes the ungranted case
/// below meaningful.
const CONTAINER: &str = "cli-channel";

const REPODATA: &str = r#"{
  "info": { "subdir": "noarch" },
  "packages": {},
  "packages.conda": {
    "empty-0.1.0-h4616a5c_0.conda": {
      "build": "h4616a5c_0",
      "build_number": 0,
      "depends": [],
      "md5": "d41d8cd98f00b204e9800998ecf8427e",
      "name": "empty",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "size": 1538,
      "subdir": "noarch",
      "version": "0.1.0"
    }
  }
}"#;

fn channel_url() -> String {
    format!("az://{AUTHORITY}/{ACCOUNT}/{CONTAINER}")
}

/// The one `azure-options` entry these tests run on, with the grant as the only
/// variable. It names `CONTAINER` specifically, so the ungranted case tests the
/// per-container lookup rather than an empty table: `Auth::Anonymous` is the
/// container named and *refused*.
fn azurite_entry(auth: Auth) -> HashMap<AzureHost, AzureEndpointOptions> {
    HashMap::from([(
        AzureHost::parse(AUTHORITY).expect("azurite authority is a valid host:port"),
        AzureEndpointOptions::new(
            [(
                AzureCoordinates::parse(&format!("{ACCOUNT}/{CONTAINER}"))
                    .expect("azurite account and container names"),
                auth,
            )],
            AzureEndpoint {
                scheme: AzureScheme::Http,
                addressing: Addressing::PathStyle,
            },
        ),
    )])
}

/// The last request to leave the stack, captured *after* `AzureMiddleware` ran.
///
/// Azurite answers 403 to any request it cannot authenticate, so a status cannot
/// tell an unsigned request from a signed one whose signature was rejected. The
/// claim under test is about what goes on the wire, so that is what is asserted.
#[derive(Clone, Default)]
struct SentRequest(Arc<Mutex<Option<(Url, HeaderMap)>>>);

impl SentRequest {
    fn recorded(&self) -> (Url, HeaderMap) {
        self.0
            .lock()
            .expect("recorder mutex")
            .clone()
            .expect("no request reached the recorder")
    }
}

#[async_trait]
impl Middleware for SentRequest {
    async fn handle(
        &self,
        req: Request,
        extensions: &mut http::Extensions,
        next: Next<'_>,
    ) -> MiddlewareResult<Response> {
        *self.0.lock().expect("recorder mutex") = Some((req.url().clone(), req.headers().clone()));
        next.run(req, extensions).await
    }
}

fn recording_client(auth: Auth) -> (ClientWithMiddleware, SentRequest) {
    let sent = SentRequest::default();
    let client = ClientBuilder::new(reqwest::Client::new())
        .with(AzureMiddleware::new(
            reqwest::Client::new(),
            azurite_entry(auth),
        ))
        .with(sent.clone())
        .build();
    (client, sent)
}

fn client(auth: Auth) -> ClientWithMiddleware {
    recording_client(auth).0
}

/// Create the container and put a `noarch/repodata.json` in it.
///
/// Seeding runs through the granted middleware rather than a separate SDK, which
/// also proves the signature works for a request carrying a query string:
/// `?restype=container` participates in the canonicalized signing resource.
async fn seed(client: &ClientWithMiddleware) {
    let created = client
        .put(format!("{}?restype=container", channel_url()))
        .send()
        .await
        .expect("container create request failed");
    assert!(
        // 409 is `ContainerAlreadyExists` — a re-run, not a failure.
        created.status().is_success() || created.status() == reqwest::StatusCode::CONFLICT,
        "could not create container {CONTAINER}: {}",
        created.status()
    );

    // `Content-Length` is set by hand because shared-key signing covers it, and
    // reqwest only materializes the header inside hyper at send time — after the
    // middleware has already signed. That gap is invisible to production, where the
    // middleware only ever carries bodyless `az://` reads, but a seeding PUT walks
    // straight into it and gets a 403 for a length mismatch.
    let put = client
        .put(format!("{}/noarch/repodata.json", channel_url()))
        .header("x-ms-blob-type", "BlockBlob")
        .header(reqwest::header::CONTENT_LENGTH, REPODATA.len())
        .body(REPODATA)
        .send()
        .await
        .expect("blob upload request failed");
    assert!(
        put.status().is_success(),
        "could not seed repodata.json: {}",
        put.status()
    );
}

#[tokio::test]
#[ignore = "requires a running Azurite emulator; see the module docs"]
async fn azurite_granted_entry_fetches_repodata() {
    // reqsign's env provider sits first in the default chain, so the shared key
    // is how a grant resolves against the emulator. Azurite rejects the AAD
    // bearer tokens the rest of the chain produces, so this is the only credential
    // shape that can work here — the chain itself is untouched.
    temp_env::async_with_vars(
        [
            ("AZURE_STORAGE_ACCOUNT_NAME", Some(ACCOUNT)),
            ("AZURE_STORAGE_ACCOUNT_KEY", Some(ACCOUNT_KEY)),
        ],
        async {
            let client = client(Auth::DefaultChain);
            seed(&client).await;

            let url = format!("{}/noarch/repodata.json", channel_url());
            let resp = client
                .get(&url)
                .send()
                .await
                .expect("request through azure middleware failed");
            let status = resp.status();
            let body = resp.bytes().await.expect("failed to read body");
            assert!(status.is_success(), "unexpected status {status} for {url}");

            let json: serde_json::Value =
                serde_json::from_slice(&body).expect("fetched repodata was not valid json");
            assert!(
                json["packages.conda"]
                    .as_object()
                    .is_some_and(|packages| packages.contains_key("empty-0.1.0-h4616a5c_0.conda")),
                "repodata fetched via az:// should list the seeded package: {json}"
            );
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires a running Azurite emulator; see the module docs"]
async fn azurite_ungranted_entry_is_refused_by_a_private_container() {
    temp_env::async_with_vars(
        [
            ("AZURE_STORAGE_ACCOUNT_NAME", Some(ACCOUNT)),
            ("AZURE_STORAGE_ACCOUNT_KEY", Some(ACCOUNT_KEY)),
        ],
        async {
            // Seed with a grant, then read without one. The credential is present in
            // the environment throughout, so a success below would mean the grant
            // check leaked it
            seed(&client(Auth::DefaultChain)).await;

            let url = format!("{}/noarch/repodata.json", channel_url());
            let (client, sent) = recording_client(Auth::Anonymous);
            let resp = client
                .get(&url)
                .send()
                .await
                .expect("request through azure middleware failed");

            let (sent_url, sent_headers) = sent.recorded();
            assert!(
                !sent_headers.contains_key(AUTHORIZATION),
                "an ungranted request must carry no credential, but it went out with an \
                 Authorization header: {:?}",
                sent_headers.get(AUTHORIZATION)
            );
            assert!(
                !sent_url.query_pairs().any(|(key, _)| key == "sig"),
                "an ungranted request must carry no credential, but its URL went out with a SAS \
                 signature: {sent_url}"
            );

            // 403 exactly, which is Azurite-specific: real Azure answers 404 to an
            // unsigned read of a private container so that a missing grant is
            // indistinguishable from a missing blob. This test only ever runs against
            // the emulator, and accepting 404 too would also admit a request sent to
            // the wrong URL — a wrong account segment or a dropped one both 404 here.
            assert_eq!(
                resp.status(),
                reqwest::StatusCode::FORBIDDEN,
                "Azurite refuses an unsigned read of a private container with 403; anything else \
                 means the request did not reach the blob this URL names: {url}"
            );
        },
    )
    .await;
}
