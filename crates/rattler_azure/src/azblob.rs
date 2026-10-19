use secrecy::ExposeSecret;

use crate::{AzureCredentials, AzureLocation, AzureScheme, AzureUrlError};

/// An opendal azblob config for the container a location addresses, rooted at
/// the channel path past the container.
///
/// The endpoint is the location's key, so a path-style account reaches the
/// request URI through it. `account_name` is always set, since opendal only
/// infers it for known Azure suffixes and shared-key signing silently never
/// engages without it.
pub fn azblob_config(
    credentials: &AzureCredentials,
    location: &AzureLocation,
    scheme: AzureScheme,
) -> Result<opendal::services::AzblobConfig, AzureUrlError> {
    let (key, container) = location.addressed()?;
    let endpoint = format!("{scheme}://{key}");

    let root = format!(
        "/{}",
        location
            .segments_past_container(key)
            .map(|segment| {
                percent_encoding::percent_decode_str(segment)
                    .decode_utf8()
                    .map_err(|source| AzureUrlError::NonUtf8Path {
                        segment: segment.to_string(),
                        source,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?
            .join("/")
    );

    let (account_key, sas_token) = match credentials {
        AzureCredentials::AccountKey(key) => (Some(key.expose_secret().to_string()), None),
        AzureCredentials::SasToken(token) => {
            let token = token.expose_secret();
            (
                None,
                Some(token.strip_prefix('?').unwrap_or(token).to_string()),
            )
        }
    };

    Ok(opendal::services::AzblobConfig {
        endpoint: Some(endpoint),
        account_name: Some(key.account().as_str().to_string()),
        container: container.as_str().to_string(),
        root: Some(root),
        account_key,
        sas_token,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{channel, located};
    use crate::{AzureAddressing, locate_as};

    fn path_style(url: &str) -> AzureLocation {
        locate_as(&channel(url), AzureAddressing::PathStyle)
            .unwrap_or_else(|err| panic!("{url} should locate path-style: {err}"))
    }

    #[test]
    fn azblob_config_under_path_style() {
        let config = azblob_config(
            &AzureCredentials::AccountKey("key".into()),
            &path_style("az://127.0.0.1:10000/devstoreaccount1/general/mychannel"),
            AzureScheme::Http,
        )
        .unwrap();

        assert_eq!(
            config.endpoint.as_deref(),
            Some("http://127.0.0.1:10000/devstoreaccount1")
        );
        assert_eq!(config.account_name.as_deref(), Some("devstoreaccount1"));
        assert_eq!(config.container, "general");
        assert_eq!(config.root.as_deref(), Some("/mychannel"));
        assert_eq!(config.account_key.as_deref(), Some("key"));
    }

    #[test]
    fn azblob_config_path_style_without_a_prefix() {
        let config = azblob_config(
            &AzureCredentials::SasToken("?sv=token".into()),
            &path_style("az://127.0.0.1:10000/devstoreaccount1/general"),
            AzureScheme::Http,
        )
        .unwrap();

        assert_eq!(config.root.as_deref(), Some("/"));
        assert_eq!(config.container, "general");
        assert_eq!(config.sas_token.as_deref(), Some("sv=token"));
    }

    #[test]
    fn azblob_config_under_host_style() {
        let config = azblob_config(
            &AzureCredentials::SasToken("sv=token".into()),
            &located(
                "az://stcondachannel.blob.core.windows.net/general/sub/dir",
                &[],
            ),
            AzureScheme::Https,
        )
        .unwrap();

        assert_eq!(
            config.endpoint.as_deref(),
            Some("https://stcondachannel.blob.core.windows.net")
        );
        assert_eq!(config.account_name.as_deref(), Some("stcondachannel"));
        assert_eq!(config.container, "general");
        assert_eq!(config.root.as_deref(), Some("/sub/dir"));
        assert_eq!(config.sas_token.as_deref(), Some("sv=token"));
        assert_eq!(config.account_key, None);
    }

    #[test]
    fn azblob_config_decodes_the_root() {
        let config = azblob_config(
            &AzureCredentials::AccountKey("key".into()),
            &located("az://acct.blob.core.windows.net/general/with%20space", &[]),
            AzureScheme::Https,
        )
        .unwrap();

        assert_eq!(config.root.as_deref(), Some("/with space"));
    }
}
