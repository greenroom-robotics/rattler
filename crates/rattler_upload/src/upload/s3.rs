use std::path::{Path, PathBuf};

use futures::StreamExt;
use miette::IntoDiagnostic;
use opendal::ErrorKind;
use rattler_digest::Sha256;
use rattler_s3::S3CredentialSource;
use url::Url;

use crate::upload::{
    object_store::{
        BlobStore, BlobUploadTarget, PACKAGE_CONCURRENCY, stream_package_to_object_store,
    },
    opt::ForceOverwrite,
    package::ExtractedPackage,
};

/// Uploads a package to a channel in an S3 bucket.
///
/// The credential source must already be determined by the caller (e.g. via
/// [`S3CredentialSource::resolve`] or [`S3CredentialSource::from_sdk`]).
pub async fn upload_package_to_s3(
    channel: Url,
    credentials: S3CredentialSource,
    package_files: &[PathBuf],
    force: impl Into<ForceOverwrite>,
) -> miette::Result<()> {
    upload_package_to_s3_with_attestation(channel, credentials, package_files, None, force).await
}

/// Uploads packages and an optional attestation sidecar to a channel in an S3
/// bucket.
///
/// The attestation must be the complete sidecar: a non-empty JSON array of
/// Sigstore bundles. It can only be supplied when uploading exactly one
/// package. The immutable content-addressed sidecar is published before the
/// mutable discovery sidecar.
pub async fn upload_package_to_s3_with_attestation(
    channel: Url,
    credentials: S3CredentialSource,
    package_files: &[PathBuf],
    attestation: Option<&Path>,
    force: impl Into<ForceOverwrite>,
) -> miette::Result<()> {
    let force = force.into();
    if attestation.is_some() && package_files.len() != 1 {
        miette::bail!("an attestation can only be uploaded with exactly one package");
    }

    // Validate and read the sidecar before changing any remote state.
    let attestation = match attestation {
        Some(path) => {
            let bytes = fs_err::tokio::read(path).await.into_diagnostic()?;
            validate_attestation_sidecar(&bytes)?;
            Some(bytes)
        }
        None => None,
    };

    let bucket = channel
        .host_str()
        .ok_or(miette::miette!("No bucket in S3 URL"))?;

    let builder = credentials.opendal_builder(bucket, channel.path());
    let op = BlobStore::new(builder).into_diagnostic()?;

    // Upload multiple packages concurrently. Each individual package upload also
    // streams its chunks concurrently (see `upload_single_package`).
    futures::stream::iter(package_files.iter())
        .map(|package_file| {
            let op = op.clone();
            let channel = &channel;
            async move { upload_single_package(&op, channel, bucket, package_file, force).await }
        })
        .buffer_unordered(PACKAGE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<miette::Result<Vec<_>>>()?;

    if let Some(attestation) = attestation {
        let package = ExtractedPackage::from_package_file(&package_files[0])?;
        let target = BlobUploadTarget::from_package(&package)?;
        let mutable_key = format!("{}.sigs", target.key());

        publish_attestation_sidecar(&op, &mutable_key, attestation).await?;
    }

    Ok(())
}

/// Checks the basic container format required for a conda attestation sidecar.
fn validate_attestation_sidecar(bytes: &[u8]) -> miette::Result<()> {
    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(serde_json::Value::Array(bundles)) if !bundles.is_empty() => Ok(()),
        Ok(_) => {
            miette::bail!("attestation sidecar must be a non-empty JSON array of Sigstore bundles")
        }
        Err(err) => Err(miette::miette!(
            "attestation sidecar is not valid JSON: {err}"
        )),
    }
}

/// Publishes the immutable sidecar before updating its mutable discovery path.
async fn publish_attestation_sidecar(
    op: &BlobStore,
    mutable_key: &str,
    bytes: Vec<u8>,
) -> miette::Result<()> {
    let sha256 = rattler_digest::compute_bytes_digest::<Sha256>(&bytes);
    let immutable_key = format!("{mutable_key}.{}", hex::encode(sha256));

    match op
        .write_new(&immutable_key, bytes.clone(), "application/json")
        .await
    {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::ConditionNotMatch => {
            let existing = op.read(&immutable_key).await.into_diagnostic()?;
            if existing.as_ref() != bytes.as_slice() {
                miette::bail!(
                    "content-addressed attestation sidecar {immutable_key} already exists with different contents"
                );
            }
        }
        Err(err) => return Err(err).into_diagnostic(),
    }

    // Copying from the immutable object guarantees that both published paths
    // contain exactly the same bytes.
    op.copy(&immutable_key, mutable_key)
        .await
        .into_diagnostic()?;

    tracing::info!("Uploaded attestation sidecar to {mutable_key}");
    Ok(())
}

/// Uploads a single package file to the S3 bucket via the given operator.
async fn upload_single_package(
    op: &BlobStore,
    channel: &Url,
    bucket: &str,
    package_file: &Path,
    force: ForceOverwrite,
) -> miette::Result<()> {
    let package = ExtractedPackage::from_package_file(package_file)?;
    let target = BlobUploadTarget::from_package(&package)?;
    let destination = format!("s3://{bucket}{}/{}", channel.path(), target.key());

    stream_package_to_object_store(op, &target, package_file, &destination, force)
        .await
        .map_err(|e| e.into_report(&destination))
}

#[cfg(test)]
mod tests {
    use opendal::services::Fs;

    use super::{BlobStore, publish_attestation_sidecar, validate_attestation_sidecar};

    #[test]
    fn validates_attestation_sidecar_container() {
        assert!(validate_attestation_sidecar(br#"[{"bundle":1}]"#).is_ok());
        assert!(validate_attestation_sidecar(br#"[]"#).is_err());
        assert!(validate_attestation_sidecar(br#"{"bundle":1}"#).is_err());
        assert!(validate_attestation_sidecar(b"not json").is_err());
    }

    #[tokio::test]
    async fn publishes_immutable_and_mutable_sidecars_with_identical_bytes() {
        let temp_dir = tempfile::tempdir().unwrap();
        let op = BlobStore::new(Fs::default().root(temp_dir.path().to_str().unwrap())).unwrap();
        let mutable_key = "noarch/test-1.0-0.conda.sigs";
        let bytes = br#"[{"bundle":1}]"#.to_vec();
        let hash =
            hex::encode(rattler_digest::compute_bytes_digest::<rattler_digest::Sha256>(&bytes));
        let immutable_key = format!("{mutable_key}.{hash}");

        publish_attestation_sidecar(&op, mutable_key, bytes.clone())
            .await
            .unwrap();

        assert_eq!(op.read(&immutable_key).await.unwrap(), bytes);
        assert_eq!(
            op.read(mutable_key).await.unwrap(),
            op.read(&immutable_key).await.unwrap()
        );

        // Publishing identical content is idempotent.
        publish_attestation_sidecar(&op, mutable_key, bytes)
            .await
            .unwrap();
    }
}
