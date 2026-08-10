use std::path::PathBuf;

#[cfg(feature = "s3")]
use anyhow::Context;
use clap::{Parser, Subcommand};
use clap_verbosity_flag::Verbosity;
#[cfg(feature = "azure")]
use rattler_azure::{AzureChannelUrl, AzureEndpointKey, AzureScheme};
use rattler_conda_types::Platform;
use rattler_config::config::{
    concurrency::default_max_concurrent_solves, index::IndexChannelConfig,
};
#[cfg(feature = "s3")]
use rattler_index::PreconditionChecks;
use rattler_index::{
    ChannelMetadata, IndexFsConfig, PackageRevisionAssignment, index_fs_with_channel_metadata,
};
#[cfg(feature = "azure")]
use rattler_index::{IndexAzureConfig, index_azure_with_channel_metadata};
#[cfg(feature = "s3")]
use rattler_index::{IndexS3Config, index_s3_with_channel_metadata};
#[cfg(feature = "s3")]
use rattler_networking::AuthenticationStorage;
#[cfg(feature = "s3")]
use rattler_s3::S3Credentials;
#[cfg(feature = "s3")]
use url::Url;

#[cfg(feature = "s3")]
fn parse_s3_url(value: &str) -> Result<Url, String> {
    let url: Url = Url::parse(value).map_err(|e| format!("`{value}` isn't a valid URL: {e}"))?;
    if url.scheme() == "s3" && url.host_str().is_some() {
        Ok(url)
    } else {
        Err(format!(
            "Only S3 URLs of format s3://bucket/... can be used, not `{value}`"
        ))
    }
}

/// SAS permissions requested when minting a user-delegation SAS for indexing.
/// Indexing read-modify-writes repodata and lists packages, so it needs read,
/// write, list and create.
#[cfg(feature = "azure")]
const AZURE_INDEX_SAS_PERMISSIONS: &str = "rwlc";

/// The `rattler-index` CLI.
#[derive(Parser)]
#[command(name = "rattler-index", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[command(flatten)]
    verbosity: Verbosity,

    /// Whether to force the re-indexing of all packages.
    /// Note that this will create a new repodata.json instead of updating the
    /// existing one.
    #[arg(short, long, default_value = "false", global = true)]
    force: bool,

    /// The maximum number of packages to process in-memory simultaneously.
    /// This is necessary to limit memory usage when indexing large channels.
    #[arg(long, global = true)]
    max_parallel: Option<usize>,

    /// A specific platform to index.
    /// Defaults to all platforms available in the channel.
    #[arg(long, global = true)]
    target_platform: Option<Platform>,

    /// The name of the conda package (expected to be in the `noarch` subdir)
    /// that should be used for repodata patching. For more information, see `https://prefix.dev/blog/repodata_patching`.
    #[arg(long, global = true)]
    repodata_patch: Option<String>,

    /// Disable precondition checks (`ETags`, timestamps) during file operations.
    /// Use this flag if your S3 backend doesn't fully support conditional requests,
    /// or if you're certain no concurrent indexing processes are running.
    /// Warning: Disabling this removes protection against concurrent modifications.
    #[cfg(feature = "s3")]
    #[arg(long, default_value = "false", global = true)]
    disable_precondition_checks: bool,

    /// The path to the config file to use to configure rattler-index.
    /// Uses the same configuration format as pixi, see `https://pixi.sh/latest/reference/pixi_configuration`.
    /// Per-channel index options are read from the `index-config` section.
    #[arg(long)]
    config: Option<PathBuf>,
}

/// The subcommands for the `rattler-index` CLI.
#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Index a channel stored on the filesystem.
    #[command(name = "fs")]
    FileSystem {
        /// The path to the channel directory.
        #[arg()]
        channel: std::path::PathBuf,
    },

    /// Index a channel stored in an S3 bucket.
    #[cfg(feature = "s3")]
    S3 {
        /// The S3 channel URL, e.g. `s3://my-bucket/my-channel`.
        #[arg(value_parser = parse_s3_url)]
        channel: Url,

        #[clap(flatten)]
        credentials: rattler_s3::clap::S3CredentialsOpts,
    },

    /// Index a channel stored in an Azure Blob container.
    #[cfg(feature = "azure")]
    #[command(name = "az")]
    Azblob {
        /// The Azure Blob channel URL, e.g.
        /// `az://<account>.blob.core.windows.net/<container>/<channel>`.
        // Not a wire `Url`: the wire scheme comes from the host's `azure-options`
        // entry, which is only read after clap has run.
        channel: AzureChannelUrl,

        #[clap(flatten)]
        credentials: rattler_azure::clap::AzureCredentialsOpts,
    },
}

/// The configuration type for rattler-index - just extends rattler config and
/// can load the same TOML files as pixi.
pub type Config = rattler_config::config::ConfigBase;

/// Entry point of the `rattler-index` cli.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse the command line arguments
    let cli = Cli::parse();

    tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(cli.verbosity)
        .init();

    let multi_progress = indicatif::MultiProgress::new();

    let config = if let Some(config_path) = cli.config {
        Some(Config::load_from_files(vec![config_path])?)
    } else {
        None
    };
    let max_parallel = cli
        .max_parallel
        .or(config.as_ref().map(|c| c.concurrency.downloads))
        .unwrap_or_else(default_max_concurrent_solves);

    #[cfg(feature = "s3")]
    let precondition_checks = if cli.disable_precondition_checks {
        PreconditionChecks::Disabled
    } else {
        PreconditionChecks::Enabled
    };

    match cli.command {
        Commands::FileSystem { channel } => {
            let resolved =
                resolve_index_channel_config(&config, &IndexConfigKey::for_path(&channel));
            let (write_zst, write_shards, repodata_revisions, package_revision_assignment) =
                effective_index_options(&resolved);
            let channel_metadata = ChannelMetadata::from_index_config(&resolved);

            index_fs_with_channel_metadata(
                IndexFsConfig {
                    channel,
                    target_platform: cli.target_platform,
                    repodata_patch: cli.repodata_patch,
                    write_zst,
                    write_shards,
                    repodata_revisions,
                    package_revision_assignment,
                    force: cli.force,
                    max_parallel,
                    multi_progress: Some(multi_progress),
                },
                channel_metadata,
            )
            .await
        }
        #[cfg(feature = "s3")]
        Commands::S3 {
            channel,
            mut credentials,
        } => {
            let resolved =
                resolve_index_channel_config(&config, &IndexConfigKey::for_url(&channel));
            let (write_zst, write_shards, repodata_revisions, package_revision_assignment) =
                effective_index_options(&resolved);
            let channel_metadata = ChannelMetadata::from_index_config(&resolved);

            let bucket = channel.host().context("Invalid S3 url")?.to_string();
            let s3_config = config
                .as_ref()
                .and_then(|config| config.s3_options.0.get(&bucket));

            // Fill in missing credentials from config file if not provided on command line
            credentials.region = credentials.region.or(s3_config.map(|c| c.region.clone()));
            credentials.endpoint_url = credentials
                .endpoint_url
                .or(s3_config.map(|c| c.endpoint_url.clone()));

            // Resolve the credentials
            let credentials = match Option::<S3Credentials>::from(credentials) {
                Some(credentials) => {
                    let auth_storage = AuthenticationStorage::from_env_and_defaults()?;
                    credentials.resolve(&channel, &auth_storage).ok_or_else(|| anyhow::anyhow!("Could not find S3 credentials in the authentication storage, and no credentials were provided via the command line."))?
                }
                None => rattler_s3::ResolvedS3Credentials::from_sdk().await?,
            };

            index_s3_with_channel_metadata(
                IndexS3Config {
                    channel,
                    credentials,
                    target_platform: cli.target_platform,
                    repodata_patch: cli.repodata_patch,
                    write_zst,
                    write_shards,
                    repodata_revisions,
                    package_revision_assignment,
                    force: cli.force,
                    max_parallel,
                    multi_progress: Some(multi_progress),
                    precondition_checks,
                },
                channel_metadata,
            )
            .await
        }
        #[cfg(feature = "azure")]
        Commands::Azblob {
            channel,
            credentials,
        } => {
            let resolved =
                resolve_index_channel_config(&config, &IndexConfigKey::for_azure(&channel));
            let (write_zst, write_shards, repodata_revisions, package_revision_assignment) =
                effective_index_options(&resolved);
            let channel_metadata = ChannelMetadata::from_index_config(&resolved);

            let (key, scheme) = azure_endpoint(&config, &channel)?;

            let credentials = credentials
                .resolve(AZURE_INDEX_SAS_PERMISSIONS, &channel, &key, scheme)
                .await?;

            index_azure_with_channel_metadata(
                IndexAzureConfig {
                    channel,
                    credentials,
                    key,
                    scheme,
                    target_platform: cli.target_platform,
                    repodata_patch: cli.repodata_patch,
                    write_zst,
                    write_shards,
                    repodata_revisions,
                    package_revision_assignment,
                    force: cli.force,
                    max_parallel,
                    multi_progress: Some(multi_progress),
                },
                channel_metadata,
            )
            .await
        }
    }?;
    println!("Finished indexing channel.");
    Ok(())
}

/// The `azure-options` entry a channel falls under: the key that says where its
/// account and container are, and the scheme to reach them over.
///
/// A missing entry and an empty entry behave identically, so this never reports
/// which it found. Grants are not part of the result: indexing signs with the
/// credential its caller supplied, so there is no ambient chain to gate. A URL
/// matching no entry is read host-style, which fails for a host that names no
/// account — indexing has to know the account.
#[cfg(feature = "azure")]
fn azure_endpoint(
    config: &Option<Config>,
    channel: &AzureChannelUrl,
) -> anyhow::Result<(AzureEndpointKey, AzureScheme)> {
    let located = rattler_azure::locate(channel, |key| {
        config
            .as_ref()
            .is_some_and(|config| config.azure_options.contains(key))
    })?;
    let key = match located.key() {
        Some(key) => key.clone(),
        // Re-derived only for the error, which names the key to add.
        None => AzureEndpointKey::host_style(channel.host())?,
    };
    let scheme = config
        .as_ref()
        .map(|config| config.azure_options.get(&key).scheme())
        .unwrap_or_default();
    Ok((key, scheme))
}

/// The `[index-config."…"]` key a channel is looked up under.
///
/// Each backend builds it one way only, so a channel cannot be looked up under a
/// spelling no user writes.
struct IndexConfigKey(String);

impl IndexConfigKey {
    fn for_path(path: &std::path::Path) -> Self {
        Self(
            path.canonicalize()
                .unwrap_or_else(|_| path.to_path_buf())
                .to_string_lossy()
                .into_owned(),
        )
    }

    #[cfg(feature = "s3")]
    fn for_url(url: &Url) -> Self {
        Self(url.to_string())
    }

    #[cfg(feature = "azure")]
    fn for_azure(channel: &AzureChannelUrl) -> Self {
        Self(channel.canonical().to_string())
    }
}

fn resolve_index_channel_config(
    config: &Option<Config>,
    key: &IndexConfigKey,
) -> IndexChannelConfig {
    config
        .as_ref()
        .map(|c| c.index_config.resolve(&key.0))
        .unwrap_or_default()
}

fn effective_index_options(
    cfg: &IndexChannelConfig,
) -> (
    bool,
    bool,
    Vec<rattler_index::RepodataRevisionInfo>,
    PackageRevisionAssignment,
) {
    let write_zst = cfg.write_zst.unwrap_or(true);
    let write_shards = cfg.write_shards.unwrap_or(true);
    let repodata_revisions = cfg.repodata_revisions.clone().unwrap_or_default();
    let package_revision_assignment = cfg.package_revision_assignment.unwrap_or_default();
    (
        write_zst,
        write_shards,
        repodata_revisions,
        package_revision_assignment,
    )
}

#[cfg(all(test, feature = "azure"))]
mod tests {
    use super::*;

    /// Load a config from TOML through a real file, the way `--config` does.
    fn config_from(toml: &str) -> Option<Config> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rattler-config.toml");
        std::fs::write(&path, toml).expect("write config");
        Some(Config::load_from_files(vec![path]).expect("config should load"))
    }

    #[test]
    fn index_config_is_keyed_by_the_canonical_az_url() {
        let config = config_from(
            r#"
            [index-config."az://acct.blob.core.windows.net/general"]
            write-shards = false
            "#,
        );
        let channel =
            AzureChannelUrl::parse("az://acct.blob.core.windows.net/general/mychannel").unwrap();

        let key = IndexConfigKey::for_azure(&channel);
        assert_eq!(
            resolve_index_channel_config(&config, &key).write_shards,
            Some(false)
        );
        assert_ne!(key.0, channel.wire(AzureScheme::Https).to_string());
    }

    /// The key is what tells the index the account is a path segment, and a wrong
    /// one fails silently.
    #[test]
    fn a_path_style_entry_drives_the_azurite_index_config() {
        let config = config_from(
            r#"
            [azure-options."127.0.0.1:10000/devstoreaccount1"]
            scheme = "http"

            [azure-options."127.0.0.1:10000/devstoreaccount1".auth]
            general = true
            "#,
        );
        let channel =
            AzureChannelUrl::parse("az://127.0.0.1:10000/devstoreaccount1/general/mychannel")
                .unwrap();

        let (key, scheme) = azure_endpoint(&config, &channel).unwrap();
        assert_eq!(scheme, AzureScheme::Http);
        assert_eq!(
            key,
            AzureEndpointKey::parse("127.0.0.1:10000/devstoreaccount1").unwrap()
        );
        assert_eq!(key.container_in(&channel).unwrap().as_str(), "general");
    }

    /// Without an entry the same channel is read host-style, and an IP literal
    /// names no account for the index to write to.
    #[test]
    fn an_unconfigured_ip_literal_channel_is_refused() {
        let channel =
            AzureChannelUrl::parse("az://127.0.0.1:10000/devstoreaccount1/general/mychannel")
                .unwrap();

        assert!(azure_endpoint(&None, &channel).is_err());
    }
}
