//! Live fetch-path integration tests against a local Azurite emulator.
//!
//! Run with:
//!
//! ```text
//! docker run --rm -p 10000:10000 mcr.microsoft.com/azure-storage/azurite \
//!     azurite-blob --blobHost 0.0.0.0
//! cargo nextest run -p rattler_networking --features azure --test azure_azurite_fetch \
//!     --run-ignored all
//! ```

use std::collections::HashMap;

use rattler_azure::{Auth, AzureEndpointKey, AzureEndpointOptions, AzureScheme, ContainerName};
use rattler_networking::AzureMiddleware;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};

/// Azurite's development account and its fixed key. Not a secret: both are
/// published constants of the emulator and only ever address a loopback port.
const ACCOUNT: &str = "devstoreaccount1";
const ACCOUNT_KEY: &str =
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

/// An IP literal carries no account label, so the table key below has to name the
/// account as a path segment.
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

/// Names `CONTAINER` specifically, so the ungranted case exercises the
/// per-container lookup, not an empty table.
fn azurite_entry(auth: Auth) -> HashMap<AzureEndpointKey, AzureEndpointOptions> {
    HashMap::from([(
        AzureEndpointKey::parse(&format!("{AUTHORITY}/{ACCOUNT}"))
            .expect("azurite authority and account name"),
        AzureEndpointOptions::new(
            [(
                ContainerName::new(CONTAINER).expect("azurite container name"),
                auth,
            )],
            AzureScheme::Http,
        ),
    )])
}

fn client(auth: Auth) -> ClientWithMiddleware {
    ClientBuilder::new(reqwest::Client::new())
        .with(AzureMiddleware::new(
            reqwest::Client::new(),
            azurite_entry(auth),
        ))
        .build()
}

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

    // `Content-Length` is set by hand: the middleware signs before reqwest
    // materializes the header.
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
            // The credential stays in the environment, so a success here would mean
            // the grant check leaked it.
            seed(&client(Auth::DefaultChain)).await;

            let url = format!("{}/noarch/repodata.json", channel_url());
            let resp = client(Auth::Anonymous)
                .get(&url)
                .send()
                .await
                .expect("request through azure middleware failed");

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
