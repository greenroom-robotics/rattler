use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

use futures::StreamExt;
use miette::IntoDiagnostic;
use opendal::{Configurator, ErrorKind};
use rattler_azure::{
    AccountName, AzureChannelUrl, AzureCredentials, AzureEndpointKey, AzureScheme, ContainerName,
};

use crate::upload::{
    object_store::{
        BlobStore, BlobStoreError, BlobUploadTarget, DESIRED_CHUNK_SIZE, PACKAGE_CONCURRENCY,
        UploadFailure, stream_package_to_object_store,
    },
    opt::ForceOverwrite,
    package::ExtractedPackage,
};

/// SAS permissions requested when minting a user-delegation SAS for uploads.
/// Creating and writing blobs needs `c` + `w`. `r` is needed on top because the
/// overwrite guard `stat`s each blob first, and a `stat` (HEAD Blob) is a read.
pub(crate) const AZURE_UPLOAD_SAS_PERMISSIONS: &str = "rcw";

/// Uploads packages to a channel in an Azure Blob Storage container.
///
/// The account name, endpoint, container and root prefix come from the channel
/// URL and `key` (see `azblob_config`). A path-style key is what makes an IP,
/// single-label or Azurite endpoint uploadable.
pub async fn upload_package_to_azure(
    channel: AzureChannelUrl,
    credentials: AzureCredentials,
    key: &AzureEndpointKey,
    scheme: AzureScheme,
    package_files: &[PathBuf],
    force: ForceOverwrite,
) -> miette::Result<()> {
    let config =
        rattler_azure::azblob_config(&credentials, &channel, key, scheme).into_diagnostic()?;

    // The container the requests below are aimed at. `azblob_config` has already
    // derived it, but it keeps it to itself, and an opendal error names neither it
    // nor the account.
    let container = key.container_in(&channel).into_diagnostic()?;

    let builder = config.into_builder();
    let op = BlobStore::new(builder).into_diagnostic()?;

    // Upload multiple packages concurrently. Each package is written to its own
    // key, so the individual uploads are independent. Every upload runs to
    // completion even once one has failed, matching the S3 path: a future dropped
    // mid-upload never reaches the code that discards its staged blocks, and Azure
    // bills for uncommitted blocks until they age out a week later.
    let outcomes: Vec<(PathBuf, miette::Result<()>)> = futures::stream::iter(package_files.iter())
        .map(|package_file| {
            let op = op.clone();
            let channel = &channel;
            let container = &container;
            async move {
                let result = upload_single_package(
                    &op,
                    channel,
                    key.account(),
                    container,
                    package_file,
                    force,
                )
                .await;
                (package_file.clone(), result)
            }
        })
        .buffer_unordered(PACKAGE_CONCURRENCY)
        .collect()
        .await;

    let summary = summarize(&outcomes);
    let mut failures = outcomes.into_iter().filter_map(|(_, result)| result.err());
    match failures.next() {
        None => {
            tracing::info!("{summary}");
            Ok(())
        }
        // Every package has an outcome in `summary`; the report carries the first
        // failure, since a `miette::Report` holds one error.
        Some(first) => {
            tracing::error!("{summary}");
            Err(first)
        }
    }
}

/// Renders the per-package outcomes of a run, which cover every package: no
/// upload is abandoned once another has failed.
fn summarize(outcomes: &[(PathBuf, miette::Result<()>)]) -> String {
    let failed: Vec<_> = outcomes
        .iter()
        .filter_map(|(path, result)| result.as_ref().err().map(|error| (path, error)))
        .collect();
    let uploaded = outcomes.len() - failed.len();

    let mut summary = format!(
        "Azure upload summary: uploaded {uploaded} / failed {}",
        failed.len()
    );
    for (path, error) in failed {
        let _ = write!(summary, "\n  failed: {}: {error}", path.display());
    }
    summary
}

/// Explains a store error in terms of the account and container the request was
/// aimed at, neither of which opendal's own error mentions.
fn explain(
    error: BlobStoreError,
    account: &AccountName,
    container: &ContainerName,
    blob_url: &str,
) -> miette::Report {
    let context = match error.kind() {
        // A container that is not there answers a blob request with the same
        // `NotFound` a missing blob does, so a wrong container — or a wrong
        // account — is otherwise indistinguishable from a first upload.
        ErrorKind::NotFound => format!(
            "could not reach {blob_url}: container `{container}` in account `{account}` may not \
             exist"
        ),
        // A SAS minted by `--azure-cli` is short-lived and is never renewed, so a
        // long run can outlive its own credential.
        ErrorKind::PermissionDenied => format!(
            "access to container `{container}` in account `{account}` was denied for {blob_url}; \
             a SAS minted by `--azure-cli` expires after `--azure-cli-sas-ttl-minutes` (30 by \
             default) and is not renewed mid-run, so a long upload can outlive it"
        ),
        _ => {
            format!("failed to upload {blob_url} to container `{container}` in account `{account}`")
        }
    };
    miette::Report::new(error).wrap_err(context)
}

async fn upload_single_package(
    op: &BlobStore,
    channel: &AzureChannelUrl,
    account: &AccountName,
    container: &ContainerName,
    package_file: &Path,
    force: ForceOverwrite,
) -> miette::Result<()> {
    let package = ExtractedPackage::from_package_file(package_file)?;
    let target = BlobUploadTarget::from_package(&package)?;

    // The blob's address as the user wrote the channel, used only for
    // diagnostics. The canonical spelling already carries `/<container>/<prefix>`,
    // so the key is appended to it; do not prepend the container again. Query and
    // fragment go first, or an inline SAS would land in the middle of the path.
    let blob_url = {
        let mut channel_url = channel.canonical();
        channel_url.set_query(None);
        channel_url.set_fragment(None);
        format!("{channel_url}/{}", target.key())
    };

    // Guard against overwriting an existing blob when `--force` was not passed.
    //
    // TODO(opendal#7990): the fix is merged upstream but unreleased. opendal 0.57
    // honours `if_not_exists` only on the single-shot Put Blob path, so a package
    // above `DESIRED_CHUNK_SIZE` commits through Put Block List unguarded. This
    // `stat` closes that for a blob that already exists, but not for two writers
    // racing to create one: both stat as absent and the second commit wins.
    //
    // On release, delete this guard and rattler_index's canary test
    // `azurite_if_not_exists_is_dropped_on_the_multi_block_path`, which fails
    // once it lands. Those two are the only places waiting on it.
    if !force.is_enabled() {
        match op.stat(target.key()).await {
            Ok(_) => {
                miette::bail!("Package {blob_url} already exists. Use --force to overwrite.");
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(explain(e, account, container, &blob_url)),
        }
    }

    // azblob attaches user metadata and content-disposition on the single-shot Put
    // Blob path only, never on the Put Block List commit a larger package takes,
    // and there is no set-metadata operation on the backend to repair it
    // afterwards. The blob therefore lands without `package-sha256`,
    // `package-md5` or its content-disposition. Say so, rather than letting the
    // schema of an uploaded blob depend silently on its size.
    let size = fs_err::metadata(package_file).into_diagnostic()?.len();
    if size > DESIRED_CHUNK_SIZE as u64 {
        tracing::warn!(
            "{blob_url} is larger than {DESIRED_CHUNK_SIZE} bytes, so it is uploaded through \
             Azure's multi-block path, which carries no blob metadata: package-sha256, \
             package-md5 and content-disposition will be missing on this blob."
        );
    }

    stream_package_to_object_store(op, &target, package_file, &blob_url, force)
        .await
        .map_err(|failure| match failure {
            UploadFailure::Store(e) => explain(e, account, container, &blob_url),
            failure => failure.into_report(&blob_url),
        })
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use opendal::services::Memory;
    use rattler_azure::AzureChannelUrl;

    use super::{BlobStore, summarize, upload_single_package};
    use crate::upload::opt::ForceOverwrite;
    use crate::upload::package::ExtractedPackage;
    use crate::upload::test_utils::test_package_path;

    fn memory_operator() -> BlobStore {
        BlobStore::new(Memory::default()).unwrap()
    }

    fn test_channel() -> AzureChannelUrl {
        AzureChannelUrl::parse("az://account.blob.core.windows.net/container/prefix").unwrap()
    }

    /// The key `test_channel` falls under, which carries the account the channel's
    /// host names.
    fn test_key() -> rattler_azure::AzureEndpointKey {
        rattler_azure::AzureEndpointKey::host_style(test_channel().host()).unwrap()
    }

    fn package_key() -> String {
        let path = test_package_path();
        let package = ExtractedPackage::from_package_file(&path).unwrap();
        format!(
            "{}/{}",
            package.subdir().unwrap(),
            package.filename().unwrap()
        )
    }

    /// Covers the small-blob path only: the fixture is a single block and the
    /// memory backend honours `if_not_exists` everywhere. Multi-block behaviour is
    /// in `rattler_index/tests/azure_azurite.rs`.
    #[tokio::test]
    async fn test_existing_blob_without_force_errors() {
        let op = memory_operator();
        let channel = test_channel();
        let package = test_package_path();

        upload_single_package(
            &op,
            &channel,
            test_key().account(),
            &test_key().container_in(&test_channel()).unwrap(),
            &package,
            ForceOverwrite(true),
        )
        .await
        .expect("initial force upload should succeed");

        let err = upload_single_package(
            &op,
            &channel,
            test_key().account(),
            &test_key().container_in(&test_channel()).unwrap(),
            &package,
            ForceOverwrite(false),
        )
        .await
        .expect_err("upload over an existing blob without --force must fail");
        assert!(
            err.to_string().contains("already exists"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_upload_into_empty_container_succeeds() {
        let op = memory_operator();
        upload_single_package(
            &op,
            &test_channel(),
            test_key().account(),
            &test_key().container_in(&test_channel()).unwrap(),
            &test_package_path(),
            ForceOverwrite(false),
        )
        .await
        .expect("upload into an empty container should succeed");

        let meta = op.stat(&package_key()).await.unwrap();
        let expected_size = std::fs::metadata(test_package_path()).unwrap().len();
        assert_eq!(meta.content_length(), expected_size);
    }

    /// Only the content disposition can be asserted here: the memory backend
    /// ignores user metadata, as azblob does above a single block.
    #[tokio::test]
    async fn test_upload_sets_content_disposition() {
        let op = memory_operator();
        upload_single_package(
            &op,
            &test_channel(),
            test_key().account(),
            &test_key().container_in(&test_channel()).unwrap(),
            &test_package_path(),
            ForceOverwrite(false),
        )
        .await
        .expect("upload should succeed");

        let path = test_package_path();
        let package = ExtractedPackage::from_package_file(&path).unwrap();
        let meta = op.stat(&package_key()).await.unwrap();
        assert_eq!(
            meta.content_disposition(),
            Some(format!("attachment; filename={}", package.filename().unwrap()).as_str())
        );
    }

    #[test]
    fn test_summary_counts_and_names_outcomes() {
        let outcomes = vec![
            (PathBuf::from("a.conda"), Ok(())),
            (
                PathBuf::from("b.conda"),
                Err(miette::miette!("Package b already exists")),
            ),
        ];

        let summary = summarize(&outcomes);
        assert!(
            summary.contains("uploaded 1 / failed 1"),
            "unexpected summary: {summary}"
        );
        assert!(summary.contains("failed: b.conda: Package b already exists"));
    }
}
