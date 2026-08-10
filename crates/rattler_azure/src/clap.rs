use std::time::Duration;

use clap::Parser;

use secrecy::{ExposeSecret, SecretString};

use crate::{
    AzureCliSasError, AzureCredentials, AzureLocation, AzureScheme, AzureUrlError,
    mint_user_delegation_sas,
};

/// A SAS cannot be individually revoked, so a short lifetime bounds the damage if
/// one leaks. Thirty minutes covers a typical index or upload run.
const DEFAULT_AZURE_CLI_SAS_TTL_MINUTES: u64 = 30;

/// Seven days, because Azure caps the lifetime of a user-delegation key there.
const MAX_AZURE_CLI_SAS_TTL_MINUTES: u64 = 7 * 24 * 60;

#[derive(Debug, thiserror::Error)]
pub enum AzureCredentialsError {
    #[error("no Azure credentials supplied: pass --account-key, --sas-token, or --azure-cli")]
    Missing,

    #[error(
        "`--azure-cli` mints its own SAS, so it cannot be combined with {flags}: the credential \
         you passed would never be used. Drop {flags}, or drop `--azure-cli`. Credentials read \
         from AZURE_STORAGE_KEY or AZURE_STORAGE_SAS_TOKEN are overridden by `--azure-cli` \
         instead of refused, so only values passed on the command line are an error"
    )]
    CliConflict { flags: String },

    #[error(transparent)]
    Url(#[from] AzureUrlError),

    #[error("failed to mint a user-delegation SAS from the Azure CLI")]
    Cli(#[from] AzureCliSasError),
}

/// [`AzureCredentialsOpts`] can express several inputs at once. This enum is the
/// single winner after precedence is applied, so downstream code never reasons
/// about combinations.
#[derive(Clone, Debug)]
pub enum AzureAuthSource {
    AccountKey(SecretString),

    SasToken(SecretString),

    AzureCli { ttl: Duration },
}

impl AzureAuthSource {
    /// Taking the location rather than a pre-derived account and container keeps the
    /// account the SAS is minted for and the container it is scoped to from coming
    /// from two different places.
    pub async fn resolve(
        self,
        permissions: &str,
        location: &AzureLocation,
        scheme: AzureScheme,
    ) -> Result<AzureCredentials, AzureCredentialsError> {
        match self {
            AzureAuthSource::AccountKey(account_key) => {
                Ok(AzureCredentials::AccountKey(account_key))
            }
            AzureAuthSource::SasToken(token) => Ok(AzureCredentials::SasToken(token)),
            AzureAuthSource::AzureCli { ttl } => {
                let (key, container) = location.addressed()?;
                let token =
                    mint_user_delegation_sas(key.account(), container, permissions, ttl, scheme)
                        .await?;
                Ok(AzureCredentials::SasToken(token))
            }
        }
    }
}

#[derive(Clone, Debug, Parser)]
pub struct AzureCredentialsOpts {
    /// The Azure Storage account key.
    ///
    /// Lowest precedence of the three: `--sas-token` wins over it, and
    /// `--azure-cli` over both.
    // The three are deliberately not `conflicts_with` each other, because clap
    // applies a conflict to a value it read from the environment too, and exporting
    // both `AZURE_STORAGE_KEY` and `AZURE_STORAGE_SAS_TOKEN` — what the `az`
    // documentation tells you to do — is not a usage error the user can undo from
    // the command line.
    #[arg(
        long,
        env = "AZURE_STORAGE_KEY",
        help_heading = "Azure Credentials",
        value_parser = secret
    )]
    pub account_key: Option<SecretString>,

    /// A shared access signature (SAS) token, with or without a leading `?`.
    ///
    /// Takes precedence over `--account-key`, and is itself overridden by
    /// `--azure-cli`.
    #[arg(
        long,
        env = "AZURE_STORAGE_SAS_TOKEN",
        help_heading = "Azure Credentials",
        value_parser = secret
    )]
    pub sas_token: Option<SecretString>,

    /// Mint a short-lived user-delegation SAS from the current `az login`
    /// session (requires the Azure CLI).
    ///
    /// Takes precedence over AZURE_STORAGE_KEY and AZURE_STORAGE_SAS_TOKEN, so it
    /// can override credentials picked up from the environment.
    #[allow(clippy::doc_markdown)]
    #[arg(long, help_heading = "Azure Credentials")]
    pub azure_cli: bool,

    /// Lifetime, in minutes, of the SAS minted for `--azure-cli`.
    ///
    /// Raise it for very large index or upload runs. If the SAS expires mid-run,
    /// later requests fail with a 403 and the run aborts, possibly leaving a
    /// partial index behind.
    #[arg(
        long,
        default_value_t = DEFAULT_AZURE_CLI_SAS_TTL_MINUTES,
        value_parser = clap::value_parser!(u64).range(1..=MAX_AZURE_CLI_SAS_TTL_MINUTES),
        help_heading = "Azure Credentials"
    )]
    pub azure_cli_sas_ttl_minutes: u64,
}

/// Take a command-line or environment value straight into a [`SecretString`], so
/// it is never a plain `String` a `{:?}` could reach.
fn secret(value: &str) -> Result<SecretString, std::convert::Infallible> {
    Ok(value.into())
}

impl PartialEq for AzureCredentialsOpts {
    /// Hand-written because [`SecretString`] withholds `PartialEq`: comparing
    /// secrets is not constant-time. The containing `UploadOpts` tree derives
    /// `PartialEq`, and comparing parsed command lines is not a secrets check.
    fn eq(&self, other: &Self) -> bool {
        fn same(left: Option<&SecretString>, right: Option<&SecretString>) -> bool {
            match (left, right) {
                (Some(left), Some(right)) => left.expose_secret() == right.expose_secret(),
                (None, None) => true,
                _ => false,
            }
        }

        same(self.account_key.as_ref(), other.account_key.as_ref())
            && same(self.sas_token.as_ref(), other.sas_token.as_ref())
            && self.azure_cli == other.azure_cli
            && self.azure_cli_sas_ttl_minutes == other.azure_cli_sas_ttl_minutes
    }
}

/// Whether `value` was typed on the command line rather than read from `var`.
///
/// clap does not carry a value's source into the derived struct, and reaching for
/// [`clap::ArgMatches`] here would mean hand-writing `FromArgMatches` for a
/// flattened struct. clap prefers the command line over the environment, so a
/// value that differs from the variable's cannot have come from it. A value typed
/// to be byte-identical to the variable reads as environment-sourced, which is the
/// harmless direction: both spellings ask for the same credential.
fn typed_on_command_line(var: &str, value: &SecretString) -> bool {
    !std::env::var(var).is_ok_and(|from_env| from_env == value.expose_secret())
}

impl AzureCredentialsOpts {
    fn explicit_credential_flags(&self) -> Vec<&'static str> {
        [
            (
                "`--account-key`",
                "AZURE_STORAGE_KEY",
                self.account_key.as_ref(),
            ),
            (
                "`--sas-token`",
                "AZURE_STORAGE_SAS_TOKEN",
                self.sas_token.as_ref(),
            ),
        ]
        .into_iter()
        .filter_map(|(flag, var, value)| {
            value
                .filter(|value| typed_on_command_line(var, value))
                .map(|_| flag)
        })
        .collect()
    }

    pub fn source(&self) -> Result<AzureAuthSource, AzureCredentialsError> {
        if self.azure_cli {
            let explicit = self.explicit_credential_flags();
            if !explicit.is_empty() {
                return Err(AzureCredentialsError::CliConflict {
                    flags: explicit.join(" and "),
                });
            }
            Ok(AzureAuthSource::AzureCli {
                ttl: Duration::from_secs(self.azure_cli_sas_ttl_minutes.saturating_mul(60)),
            })
        } else if let Some(sas_token) = &self.sas_token {
            Ok(AzureAuthSource::SasToken(sas_token.clone()))
        } else if let Some(account_key) = &self.account_key {
            Ok(AzureAuthSource::AccountKey(account_key.clone()))
        } else {
            Err(AzureCredentialsError::Missing)
        }
    }

    pub async fn resolve(
        self,
        permissions: &str,
        location: &AzureLocation,
        scheme: AzureScheme,
    ) -> Result<AzureCredentials, AzureCredentialsError> {
        self.source()?.resolve(permissions, location, scheme).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        creds: AzureCredentialsOpts,
    }

    fn opts(
        account_key: Option<&str>,
        sas_token: Option<&str>,
        azure_cli: bool,
    ) -> AzureCredentialsOpts {
        AzureCredentialsOpts {
            account_key: account_key.map(Into::into),
            sas_token: sas_token.map(Into::into),
            azure_cli,
            azure_cli_sas_ttl_minutes: DEFAULT_AZURE_CLI_SAS_TTL_MINUTES,
        }
    }

    fn unaddressable() -> AzureLocation {
        let channel = crate::AzureChannelUrl::parse("az://acct.blob.core.windows.net").unwrap();
        let location = crate::locate_as(&channel, crate::AzureAddressing::HostStyle).unwrap();
        assert!(location.addressed().is_err());
        location
    }

    #[tokio::test]
    async fn account_key_resolves() {
        assert!(matches!(
            opts(Some("key"), None, false).resolve("cw", &unaddressable(), AzureScheme::Https).await,
            Ok(AzureCredentials::AccountKey(k)) if k.expose_secret() == "key"
        ));
    }

    #[tokio::test]
    async fn sas_token_resolves() {
        assert!(matches!(
            opts(None, Some("sv=..."), false).resolve("cw", &unaddressable(), AzureScheme::Https).await,
            Ok(AzureCredentials::SasToken(t)) if t.expose_secret() == "sv=..."
        ));
    }

    #[tokio::test]
    async fn none_is_rejected() {
        assert!(matches!(
            opts(None, None, false)
                .resolve("cw", &unaddressable(), AzureScheme::Https)
                .await,
            Err(AzureCredentialsError::Missing)
        ));
    }

    #[test]
    fn sas_beats_account_key() {
        assert!(matches!(
            opts(Some("key"), Some("sv=..."), false).source(),
            Ok(AzureAuthSource::SasToken(t)) if t.expose_secret() == "sv=..."
        ));
        assert!(matches!(
            opts(Some("key"), None, false).source(),
            Ok(AzureAuthSource::AccountKey(k)) if k.expose_secret() == "key"
        ));
    }

    #[test]
    fn azure_cli_ttl_is_carried_through() {
        let mut opts = opts(None, None, true);
        opts.azure_cli_sas_ttl_minutes = 45;
        assert!(matches!(
            opts.source().unwrap(),
            AzureAuthSource::AzureCli { ttl } if ttl == Duration::from_secs(45 * 60)
        ));
    }

    // The `--azure-cli` resolve path shells out to `az`, which isn't available in
    // the test environment, so we only assert the flag and its TTL parse through
    // clap and that precedence selects the CLI source; the mint itself is not
    // exercised here.
    #[test]
    fn azure_cli_flag_and_ttl_parse() {
        let cli = Cli::try_parse_from(["test", "--azure-cli", "--azure-cli-sas-ttl-minutes", "90"])
            .expect("should parse");
        assert!(cli.creds.azure_cli);
        assert_eq!(cli.creds.azure_cli_sas_ttl_minutes, 90);

        let default = Cli::try_parse_from(["test", "--azure-cli"]).expect("should parse");
        assert_eq!(
            default.creds.azure_cli_sas_ttl_minutes,
            DEFAULT_AZURE_CLI_SAS_TTL_MINUTES
        );
    }

    /// Serialised env-var swap, since the vars below are process-global and the
    /// values under test are exactly the ones clap reads from the environment.
    fn with_env<R>(vars: &[(&str, Option<&str>)], body: impl FnOnce() -> R) -> R {
        use std::sync::Mutex;

        // SAFETY: the tests that touch these variables are serialised by LOCK.
        fn set(var: &str, value: Option<&str>) {
            match value {
                Some(value) => unsafe { std::env::set_var(var, value) },
                None => unsafe { std::env::remove_var(var) },
            }
        }

        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let previous: Vec<_> = vars
            .iter()
            .map(|(var, value)| {
                let previous = std::env::var(var).ok();
                set(var, *value);
                (*var, previous)
            })
            .collect();
        let out = body();
        for (var, value) in previous {
            set(var, value.as_deref());
        }
        out
    }

    fn parse(args: &[&str]) -> Result<AzureCredentialsOpts, clap::Error> {
        Cli::try_parse_from(std::iter::once("test").chain(args.iter().copied()))
            .map(|cli| cli.creds)
    }

    #[test]
    fn both_credential_env_vars_parse_and_resolve_by_precedence() {
        with_env(
            &[
                ("AZURE_STORAGE_KEY", Some("key")),
                ("AZURE_STORAGE_SAS_TOKEN", Some("sv=env")),
            ],
            || {
                let opts = parse(&[]).expect("both Azure env vars set must not be a usage error");
                assert!(matches!(
                    opts.source(),
                    Ok(AzureAuthSource::SasToken(t)) if t.expose_secret() == "sv=env"
                ));

                let opts = parse(&["--azure-cli"]).expect("--azure-cli must parse alongside them");
                assert!(matches!(
                    opts.source(),
                    Ok(AzureAuthSource::AzureCli { .. })
                ));

                // Precedence is by flag, not by source: the SAS token wins even
                // when it came from the environment and the account key was typed.
                let opts = parse(&["--account-key", "typed"]).expect("should parse");
                assert!(matches!(
                    opts.source(),
                    Ok(AzureAuthSource::SasToken(t)) if t.expose_secret() == "sv=env"
                ));
            },
        );
    }

    #[test]
    fn account_key_and_sas_token_together_are_resolved_by_precedence() {
        with_env(
            &[
                ("AZURE_STORAGE_KEY", None),
                ("AZURE_STORAGE_SAS_TOKEN", None),
            ],
            || {
                let opts = parse(&["--account-key", "k", "--sas-token", "sv=..."])
                    .expect("passing both credentials must not be a usage error");
                assert!(matches!(
                    opts.source(),
                    Ok(AzureAuthSource::SasToken(t)) if t.expose_secret() == "sv=..."
                ));
            },
        );
    }

    #[test]
    fn azure_cli_with_typed_credentials_is_an_error() {
        with_env(
            &[
                ("AZURE_STORAGE_KEY", None),
                ("AZURE_STORAGE_SAS_TOKEN", None),
            ],
            || {
                let opts = parse(&["--azure-cli", "--account-key", "k", "--sas-token", "sv=..."])
                    .expect("the combination is rejected by `source`, not by clap");
                let err = opts
                    .source()
                    .map(|_| ())
                    .expect_err("--azure-cli with typed credentials must be refused");
                let message = err.to_string();
                assert!(
                    message.contains("`--account-key` and `--sas-token`"),
                    "{message}"
                );
                assert!(matches!(err, AzureCredentialsError::CliConflict { .. }));
            },
        );
    }

    #[test]
    fn debug_never_prints_secrets() {
        let sources = [
            AzureAuthSource::AccountKey("supersecretkey".into()),
            AzureAuthSource::SasToken("sig=deadbeef".into()),
        ];
        for source in &sources {
            let out = format!("{source:?}");
            assert!(out.contains("REDACTED"), "not redacted: {out}");
            assert!(!out.contains("supersecret"), "leaked key: {out}");
            assert!(!out.contains("deadbeef"), "leaked token: {out}");
        }

        let out = format!("{:?}", opts(Some("supersecretkey"), None, false));
        assert!(out.contains("REDACTED"), "not redacted: {out}");
        assert!(!out.contains("supersecret"), "leaked key: {out}");

        let out = format!("{:?}", opts(None, Some("sig=deadbeef"), false));
        assert!(out.contains("REDACTED"), "not redacted: {out}");
        assert!(!out.contains("deadbeef"), "leaked token: {out}");
    }

    #[test]
    fn ttl_range_is_enforced() {
        assert!(
            Cli::try_parse_from(["test", "--azure-cli", "--azure-cli-sas-ttl-minutes", "0"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "test",
                "--azure-cli",
                "--azure-cli-sas-ttl-minutes",
                &(MAX_AZURE_CLI_SAS_TTL_MINUTES + 1).to_string(),
            ])
            .is_err()
        );
    }
}
