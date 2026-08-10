//! Per-host endpoint options for Azure Blob channels.
//!
//! An entry in the `azure-options` config table is the only thing that grants a
//! host or one of its containers anything. Without one, a channel on that host is
//! fetched anonymously over https in host-style addressing. There is no hardcoded
//! list of "official" Azure suffixes, which is what lets custom endpoints and the
//! Azurite emulator work.

use crate::ContainerName;

/// Whether credentials may attach to requests for a container.
///
/// Defaults to [`Auth::Anonymous`], and serializes as the bool a container is
/// spelled with in an `azure-options` `auth` table.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(from = "bool", into = "bool")
)]
pub enum Auth {
    /// Send requests unsigned. No credential is resolved, so nothing ambient can
    /// leak to this host and nothing blocks on the managed-identity/IMDS probe.
    #[default]
    Anonymous,

    /// Run the standard Azure credential chain and sign with what it returns.
    /// Since this is an explicit grant, an unusable credential is a hard error
    /// rather than a silent downgrade to anonymous.
    DefaultChain,
}

impl From<bool> for Auth {
    fn from(value: bool) -> Self {
        if value {
            Auth::DefaultChain
        } else {
            Auth::Anonymous
        }
    }
}

impl From<Auth> for bool {
    fn from(value: Auth) -> Self {
        matches!(value, Auth::DefaultChain)
    }
}

impl Auth {
    pub fn is_granted(self) -> bool {
        matches!(self, Auth::DefaultChain)
    }
}

/// The wire scheme an `az://` channel URL is rewritten to when a request is sent.
///
/// Prefixed rather than spelled bare `Scheme`, because `opendal::Scheme` names a
/// storage service and is one import away.
///
/// Defaults to [`AzureScheme::Https`]. `Http` exists for local emulators such as
/// Azurite, and selecting it is an explicit per-host decision in config.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "lowercase")
)]
pub enum AzureScheme {
    #[default]
    Https,

    Http,
}

impl AzureScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            AzureScheme::Https => "https",
            AzureScheme::Http => "http",
        }
    }
}

impl std::fmt::Display for AzureScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where the storage account name is found in a blob URL.
///
/// Defaults to [`Addressing::HostStyle`], which is how real Azure addresses
/// accounts. Serializes as the bool `path-style` in `azure-options`.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(from = "bool", into = "bool")
)]
pub enum Addressing {
    /// `<account>.blob.core.windows.net/<container>`. Requires a domain with at
    /// least two labels, so IP literals and single-label hosts cannot be addressed
    /// this way.
    #[default]
    HostStyle,

    /// `<host>/<account>/<container>`. What Azurite and other emulators use, and
    /// the only form that works for an IP or single-label host.
    PathStyle,
}

impl Addressing {
    /// Which path segment holds the container name under this addressing.
    ///
    /// One number for both [`account_and_container`](crate::account_and_container)
    /// and [`container`](crate::container). If they disagreed, a grant looked up
    /// for one container would be applied to another.
    pub(crate) fn container_segment(self) -> usize {
        match self {
            // `<account>.host/<container>/…`
            Addressing::HostStyle => 0,
            // `host/<account>/<container>/…`
            Addressing::PathStyle => 1,
        }
    }

    /// How many leading path segments the account and container consume, and so
    /// where a channel's root prefix starts.
    #[cfg(feature = "opendal")]
    pub(crate) fn segments_before_root(self) -> usize {
        self.container_segment() + 1
    }
}

impl From<bool> for Addressing {
    fn from(value: bool) -> Self {
        if value {
            Addressing::PathStyle
        } else {
            Addressing::HostStyle
        }
    }
}

impl From<Addressing> for bool {
    fn from(value: Addressing) -> Self {
        matches!(value, Addressing::PathStyle)
    }
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct AzureEndpoint {
    pub scheme: AzureScheme,

    pub addressing: Addressing,
}

/// What the fetch middleware needs to send one request.
///
/// [`Addressing`] is absent because the grant is already resolved by the time this
/// exists: [`AzureEndpointOptions::fetch`] used the addressing to find the
/// container, and the fetch path never derives an account name.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct AzureFetchOptions {
    pub auth: Auth,

    pub scheme: AzureScheme,
}

/// One `azure-options` entry, as the config file spells it.
///
/// This is the serde surface. Each consumer takes the narrower view it can act
/// on, via [`Self::endpoint`] or [`Self::fetch`], and the fields are private so
/// that view is the only way in. The default value is the no-entry behaviour, so
/// callers can look an absent host up and fall back to `default()`.
///
/// # Why the grant is per container and the endpoint is per host
///
/// Azure assigns RBAC per *container*, so one storage account routinely holds a
/// mix of private and anonymous-read containers. A per-host grant cannot express
/// that: signing the anonymous-read container 403s, and not signing breaks the
/// private ones. `scheme` and `addressing` describe the endpoint, where two
/// containers disagreeing about where the account name lives is a contradiction.
///
/// There is therefore no host-level `auth` field at all. It is absent from the
/// type rather than defaulted to false, so the one setting whose blast radius
/// would be every container on the account is unrepresentable. The worst typo
/// here grants one container.
///
/// ```toml
/// [azure-options."mycompany.blob.core.windows.net"]
/// scheme = "https"
/// path-style = false
///
/// [azure-options."mycompany.blob.core.windows.net".auth]
/// releases = true
/// staging = true
/// # a container not listed here is fetched anonymously
/// ```
#[derive(Default, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(rename_all = "kebab-case", default)
)]
pub struct AzureEndpointOptions {
    scheme: AzureScheme,

    #[cfg_attr(feature = "serde", serde(rename = "path-style", alias = "path_style"))]
    addressing: Addressing,

    /// Which containers on this host may be sent credentials.
    ///
    /// An explicit `false` is legal and redundant with omission, which is what
    /// lets a higher-precedence config file revoke a grant a lower one made (see
    /// [`Self::layered_over`]).
    ///
    /// Declared last, because the TOML serializer must emit an entry's scalars
    /// before its tables.
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "indexmap::IndexMap::is_empty")
    )]
    auth: indexmap::IndexMap<ContainerName, Auth>,
}

impl AzureEndpointOptions {
    pub fn new(
        auth: impl IntoIterator<Item = (ContainerName, Auth)>,
        endpoint: AzureEndpoint,
    ) -> Self {
        Self {
            scheme: endpoint.scheme,
            addressing: endpoint.addressing,
            auth: auth.into_iter().collect(),
        }
    }

    pub fn endpoint(&self) -> AzureEndpoint {
        AzureEndpoint {
            scheme: self.scheme,
            addressing: self.addressing,
        }
    }

    /// The grant and wire scheme for one container, for the fetch path.
    ///
    /// `container` is an `Option` because a URL need not name one. That case is
    /// answered here rather than at the call site, and can only mean anonymous:
    /// there is no entry it could match.
    pub fn fetch(&self, container: Option<&ContainerName>) -> AzureFetchOptions {
        AzureFetchOptions {
            auth: container
                .and_then(|container| self.auth.get(container))
                .copied()
                .unwrap_or_default(),
            scheme: self.scheme,
        }
    }

    /// Every container this entry mentions, and what it grants it.
    ///
    /// Includes the explicit `false`s: a caller validating or listing the table
    /// needs what the file says, not what it effectively means.
    pub fn grants(&self) -> impl Iterator<Item = (&ContainerName, Auth)> {
        self.auth.iter().map(|(container, auth)| (container, *auth))
    }

    /// This entry layered over the one a lower-precedence config file wrote.
    ///
    /// `scheme` and `addressing` describe the endpoint as a whole, so this entry
    /// replaces them outright. Grants merge per container, so a file naming one
    /// container does not drop a grant on a container it never mentions. An
    /// explicit `false` still revokes, so the merge is not a one-way ratchet.
    pub fn layered_over(&self, lower: &Self) -> Self {
        let mut auth = lower.auth.clone();
        auth.extend(self.auth.iter().map(|(c, auth)| (c.clone(), *auth)));
        Self {
            scheme: self.scheme,
            addressing: self.addressing,
            auth,
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    fn container(name: &str) -> ContainerName {
        ContainerName::new(name).expect("test container name")
    }

    #[test]
    fn toml_bools_map_to_enums() {
        let opts: AzureEndpointOptions = toml::from_str(
            r#"
            scheme = "http"
            path-style = true

            [auth]
            releases = true
            "#,
        )
        .unwrap();
        assert_eq!(
            opts,
            AzureEndpointOptions::new(
                [(container("releases"), Auth::DefaultChain)],
                AzureEndpoint {
                    scheme: AzureScheme::Http,
                    addressing: Addressing::PathStyle,
                },
            )
        );

        let empty: AzureEndpointOptions = toml::from_str("").unwrap();
        assert_eq!(empty, AzureEndpointOptions::default());
        assert_eq!(
            empty.fetch(Some(&container("releases"))),
            AzureFetchOptions::default()
        );
        assert!(!empty.fetch(Some(&container("releases"))).auth.is_granted());
        assert_eq!(empty.endpoint(), AzureEndpoint::default());
    }

    #[test]
    fn a_grant_applies_to_one_container_only() {
        let opts: AzureEndpointOptions = toml::from_str(
            r#"
            [auth]
            releases = true
            public = false
            "#,
        )
        .unwrap();

        assert!(opts.fetch(Some(&container("releases"))).auth.is_granted());
        assert!(!opts.fetch(Some(&container("public"))).auth.is_granted());
        assert!(!opts.fetch(Some(&container("staging"))).auth.is_granted());

        assert!(!opts.fetch(None).auth.is_granted());

        // `grants` reports what the file says, explicit `false` included — in the
        // order the document's table iterated (`toml::Table` is a `BTreeMap`, so
        // that is byte order, not write order).
        assert_eq!(
            opts.grants().collect::<Vec<_>>(),
            vec![
                (&container("public"), Auth::Anonymous),
                (&container("releases"), Auth::DefaultChain),
            ]
        );
    }

    #[test]
    fn layering_replaces_the_endpoint_and_merges_the_grants() {
        let lower: AzureEndpointOptions = toml::from_str(
            r#"
            path-style = true

            [auth]
            releases = true
            staging = true
            "#,
        )
        .unwrap();
        let higher: AzureEndpointOptions = toml::from_str(
            r#"
            scheme = "http"

            [auth]
            staging = false
            internal = true
            "#,
        )
        .unwrap();

        let merged = higher.layered_over(&lower);

        assert_eq!(merged.endpoint(), higher.endpoint());
        assert!(
            merged.fetch(Some(&container("releases"))).auth.is_granted(),
            "a grant the higher file never mentions must survive"
        );
        assert!(
            !merged.fetch(Some(&container("staging"))).auth.is_granted(),
            "an explicit `false` in the higher file must revoke the lower grant"
        );
        assert!(merged.fetch(Some(&container("internal"))).auth.is_granted());
    }

    #[test]
    fn an_unusable_container_key_is_rejected() {
        let err = toml::from_str::<AzureEndpointOptions>("[auth]\nReleases = true\n")
            .expect_err("uppercase is not a legal container name");
        assert!(err.to_string().contains("Releases"), "{err}");
    }

    #[test]
    fn enums_serialize_back_to_bools() {
        let toml = toml::to_string(&AzureEndpointOptions::new(
            [
                (container("releases"), Auth::DefaultChain),
                (container("public"), Auth::Anonymous),
            ],
            AzureEndpoint {
                scheme: AzureScheme::Http,
                addressing: Addressing::PathStyle,
            },
        ))
        .unwrap();
        assert!(toml.contains("releases = true"), "{toml}");
        assert!(toml.contains("public = false"), "{toml}");
        assert!(toml.contains("path-style = true"), "{toml}");
        assert!(toml.contains(r#"scheme = "http""#), "{toml}");
        assert!(!toml.contains("DefaultChain"), "{toml}");

        let anonymous = toml::to_string(&AzureEndpointOptions::default()).unwrap();
        assert!(!anonymous.contains("auth"), "{anonymous}");
    }
}
