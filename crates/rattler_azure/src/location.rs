use crate::{AzureChannelUrl, AzureEndpointKey, AzureUrlError, ContainerName};

/// A channel together with the key and container read from it.
///
/// All three come from the one channel through [`locate`] or [`locate_as`], so the
/// key is a prefix of the channel and the container is the segment right after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AzureLocation {
    channel: AzureChannelUrl,
    key: Option<AzureEndpointKey>,
    container: Option<ContainerName>,
}

impl AzureLocation {
    pub fn channel(&self) -> &AzureChannelUrl {
        &self.channel
    }

    /// The key the URL matched, or the host-style key it falls back to.
    ///
    /// `None` when neither exists: an unconfigured IP literal names no account.
    pub fn key(&self) -> Option<&AzureEndpointKey> {
        self.key.as_ref()
    }

    pub fn container(&self) -> Option<&ContainerName> {
        self.container.as_ref()
    }

    /// The key and container a request has to name, or the reason the URL names
    /// neither.
    pub fn addressed(&self) -> Result<(&AzureEndpointKey, &ContainerName), AzureUrlError> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| AzureUrlError::InvalidHost(self.channel.host().to_string()))?;
        Ok((
            key,
            self.container.as_ref().ok_or(AzureUrlError::NoContainer)?,
        ))
    }

    /// The still-encoded path segments past the key and the container.
    pub(crate) fn segments_past_container<'a>(
        &'a self,
        key: &AzureEndpointKey,
    ) -> impl Iterator<Item = &'a str> {
        self.channel
            .path_segments()
            .skip(key.container_segment() + 1)
    }
}

/// Where the storage account sits in a URL that no configured key matches.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AzureAddressing {
    #[default]
    HostStyle,

    PathStyle,
}

impl From<bool> for AzureAddressing {
    fn from(path_style: bool) -> Self {
        if path_style {
            Self::PathStyle
        } else {
            Self::HostStyle
        }
    }
}

/// Match a channel URL against the configured entry keys.
///
/// Both candidates are tried, longest first, so `proxy.internal/accta` wins over
/// `proxy.internal` where both are configured. A URL matching neither is read
/// host-style.
pub fn locate(
    channel: &AzureChannelUrl,
    configured: impl Fn(&AzureEndpointKey) -> bool,
) -> Result<AzureLocation, AzureUrlError> {
    let host_style = AzureEndpointKey::host_style(channel.host()).ok();
    let path_style = segment(channel, 0)
        .and_then(|segment| AzureEndpointKey::path_style(channel.host().clone(), segment).ok());

    let key = [path_style, host_style.clone()]
        .into_iter()
        .flatten()
        .find(|key| configured(key))
        .or(host_style);

    located(channel, key)
}

/// Locate a channel under an explicitly stated addressing.
pub fn locate_as(
    channel: &AzureChannelUrl,
    addressing: AzureAddressing,
) -> Result<AzureLocation, AzureUrlError> {
    let key = match addressing {
        AzureAddressing::HostStyle => AzureEndpointKey::host_style(channel.host())?,
        AzureAddressing::PathStyle => AzureEndpointKey::path_style(
            channel.host().clone(),
            segment(channel, 0).unwrap_or_default(),
        )?,
    };
    located(channel, Some(key))
}

fn located(
    channel: &AzureChannelUrl,
    key: Option<AzureEndpointKey>,
) -> Result<AzureLocation, AzureUrlError> {
    let container = key
        .as_ref()
        .and_then(|key| segment(channel, key.container_segment()))
        .map(ContainerName::new)
        .transpose()?;
    Ok(AzureLocation {
        channel: channel.clone(),
        key,
        container,
    })
}

/// A non-empty path segment; [`AzureChannelUrl::parse`] only admits an empty
/// segment as a trailing slash.
fn segment(channel: &AzureChannelUrl, index: usize) -> Option<&str> {
    channel
        .path_segments()
        .nth(index)
        .filter(|segment| !segment.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{channel, container, key, located};

    fn path_style(url: &str) -> AzureLocation {
        locate_as(&channel(url), AzureAddressing::PathStyle)
            .unwrap_or_else(|err| panic!("{url} should locate path-style: {err}"))
    }

    #[test]
    fn the_container_follows_the_matched_key() {
        for (url, configured) in [
            ("az://acct.blob.core.windows.net/general/noarch", &[][..]),
            (
                "az://acct.blob.core.windows.net/general/noarch",
                &["acct.blob.core.windows.net"],
            ),
            (
                "az://proxy.internal/accta/general/noarch",
                &["proxy.internal/accta"],
            ),
            ("az://proxy.internal/accta/general", &["proxy.internal"]),
            (
                "az://127.0.0.1:10000/devstoreaccount1/general",
                &["127.0.0.1:10000/devstoreaccount1"],
            ),
        ] {
            let located = located(url, configured);
            let Some(container) = located.container() else {
                panic!("{url} names a container");
            };
            let prefix = match located.key() {
                Some(AzureEndpointKey::PathStyle(path)) => format!("/{}", path.account()),
                Some(AzureEndpointKey::HostStyle(_)) | None => String::new(),
            };
            assert!(
                channel(url)
                    .redacted()
                    .path()
                    .starts_with(&format!("{prefix}/{container}")),
                "{url}: `{container}` does not follow `{prefix}`"
            );
        }
    }

    #[test]
    fn the_longest_configured_key_wins() {
        let url = "az://proxy.internal/accta/general/noarch";

        let both = located(url, &["proxy.internal", "proxy.internal/accta"]);
        assert_eq!(both.key(), Some(&key("proxy.internal/accta")));
        assert_eq!(both.container(), Some(&container("general")));

        let host_only = located(url, &["proxy.internal"]);
        assert_eq!(host_only.key(), Some(&key("proxy.internal")));
        assert_eq!(host_only.container(), Some(&container("accta")));
    }

    #[test]
    fn an_unmatched_url_falls_back_to_host_style() {
        let anonymous = located("az://127.0.0.1:10000/devstoreaccount1/general", &[]);
        assert_eq!(anonymous.key(), None);
        assert_eq!(anonymous.container(), None);

        let azure = located("az://acct.blob.core.windows.net/general/noarch", &[]);
        assert_eq!(azure.key(), Some(&key("acct.blob.core.windows.net")));
        assert_eq!(azure.container(), Some(&container("general")));
    }

    #[test]
    fn a_url_without_a_container_names_none() {
        for (url, configured) in [
            ("az://acct.blob.core.windows.net", &[][..]),
            ("az://acct.blob.core.windows.net/", &[]),
            (
                "az://127.0.0.1:10000/devstoreaccount1",
                &["127.0.0.1:10000/devstoreaccount1"],
            ),
            ("az://127.0.0.1:10000/", &[]),
        ] {
            assert_eq!(located(url, configured).container(), None, "{url}");
        }
    }

    #[test]
    fn a_url_with_an_unusable_container_is_an_error() {
        for url in [
            "az://acct.blob.core.windows.net/General/noarch",
            "az://acct.blob.core.windows.net/ab/noarch",
            "az://acct.blob.core.windows.net/a--b/noarch",
            "az://acct.blob.core.windows.net/general;evil/noarch",
            "az://acct.blob.core.windows.net/-o/noarch",
        ] {
            let err = locate(&channel(url), |_| false)
                .expect_err("an illegal container name must be reported");
            assert!(
                matches!(err, AzureUrlError::InvalidContainerName(_)),
                "{url}: {err}"
            );
        }
    }

    #[test]
    fn an_unkeyed_url_reports_no_container_rather_than_a_bad_one() {
        for url in [
            "az://127.0.0.1:10000/Conda_Channel/noarch/repodata.json",
            "az://azurite/Conda_Channel/noarch/repodata.json",
            "az://mirror/ab/noarch/repodata.json",
            "az://localhost:8080/My_Repo/noarch/repodata.json",
        ] {
            let located = located(url, &[]);
            assert_eq!(located.key(), None, "{url}");
            assert_eq!(located.container(), None, "{url}");
        }
    }

    #[test]
    fn a_path_style_key_takes_the_account_off_any_host() {
        for host in [
            "127.0.0.1:10000",
            "[::1]:10000",
            "azurite:10000",
            "localhost:10000",
            "azurite",
            "localhost",
        ] {
            let key = key(&format!("{host}/devstoreaccount1"));
            assert_eq!(key.account().as_str(), "devstoreaccount1", "{host}");

            let located = path_style(&format!("az://{host}/devstoreaccount1/general/noarch"));
            assert_eq!(located.addressed().unwrap(), (&key, &container("general")));
        }
    }

    #[test]
    fn a_url_short_of_the_container_has_none_to_address() {
        for (url, addressing) in [
            (
                "az://127.0.0.1:10000/devstoreaccount1",
                AzureAddressing::PathStyle,
            ),
            (
                "az://acct.blob.core.windows.net",
                AzureAddressing::HostStyle,
            ),
        ] {
            let located =
                locate_as(&channel(url), addressing).unwrap_or_else(|err| panic!("{err}"));
            assert_eq!(located.container(), None, "{url}");
            assert!(
                matches!(located.addressed(), Err(AzureUrlError::NoContainer)),
                "{url}"
            );
        }

        assert!(matches!(
            locate_as(
                &channel("az://127.0.0.1:10000/"),
                AzureAddressing::PathStyle
            ),
            Err(AzureUrlError::InvalidAccountName(_))
        ));
    }
}
