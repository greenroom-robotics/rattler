//! Per-endpoint options for Azure Blob channels.
//!
//! An entry in the `azure-options` config table is the only thing that grants an
//! endpoint or one of its containers anything. Without one, a channel is fetched
//! anonymously over https and read host-style. There is no hardcoded list of
//! "official" Azure suffixes, which is what lets custom endpoints and the Azurite
//! emulator work.

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
/// Azurite, and selecting it is an explicit per-endpoint decision in config.
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

/// What the fetch middleware needs to send one request.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct AzureFetchOptions {
    pub auth: Auth,

    pub scheme: AzureScheme,
}

/// One `azure-options` entry, as the config file spells it.
///
/// This is the serde surface. Each consumer takes the narrower view it can act
/// on, via [`Self::scheme`] or [`Self::fetch`], and the fields are private so
/// that view is the only way in. The default value is the no-entry behaviour, so
/// callers can look an absent key up and fall back to `default()`.
///
/// # Why the grant is per container
///
/// Azure assigns RBAC per *container*, so one storage account routinely holds a
/// mix of private and anonymous-read containers. A per-account grant cannot
/// express that: signing the anonymous-read container 403s, and not signing
/// breaks the private ones.
///
/// There is therefore no entry-level `auth` field at all. It is absent from the
/// type rather than defaulted to false, so a grant always names a container — a
/// container *under the key's reading of the URL*. A key whose shape does not
/// match the endpoint reads the account segment as the container: on a host that
/// really fronts its accounts path-style, a host-style key's `accta = true` grants
/// every URL whose first segment is `accta`, which is the whole account.
///
/// ```toml
/// [azure-options."mycompany.blob.core.windows.net"]
/// scheme = "https"
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
    // `deny_unknown_fields`, because a silently-missed grant is the worst failure
    // this table has: Azure answers an anonymous read of a private container with
    // 404, not 403, so a misspelled `[Auth]` surfaces as "channel not found" with
    // nothing pointing at the typo. Container names are already held to Azure's
    // rules for the same reason — a key that can never match is a config error.
    serde(rename_all = "kebab-case", default, deny_unknown_fields)
)]
pub struct AzureEndpointOptions {
    scheme: AzureScheme,

    /// Which containers under this key may be sent credentials.
    ///
    /// An explicit `false` is legal and redundant with omission, so a
    /// higher-precedence config file can revoke rather than only add.
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
    pub fn new(auth: impl IntoIterator<Item = (ContainerName, Auth)>, scheme: AzureScheme) -> Self {
        Self {
            scheme,
            auth: auth.into_iter().collect(),
        }
    }

    pub fn scheme(&self) -> AzureScheme {
        self.scheme
    }

    /// The grant and wire scheme for one container, for the fetch path.
    ///
    /// `container` is an `Option` because a URL need not name one. That case is
    /// answered here rather than at the call site, and can only mean anonymous.
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

            [auth]
            releases = true
            "#,
        )
        .unwrap();
        assert_eq!(
            opts,
            AzureEndpointOptions::new(
                [(container("releases"), Auth::DefaultChain)],
                AzureScheme::Http,
            )
        );

        let empty: AzureEndpointOptions = toml::from_str("").unwrap();
        assert_eq!(empty, AzureEndpointOptions::default());
        assert_eq!(
            empty.fetch(Some(&container("releases"))),
            AzureFetchOptions::default()
        );
        assert!(!empty.fetch(Some(&container("releases"))).auth.is_granted());
        assert_eq!(empty.scheme(), AzureScheme::default());
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
    fn an_unusable_container_key_is_rejected() {
        let err = toml::from_str::<AzureEndpointOptions>("[auth]\nReleases = true\n")
            .expect_err("uppercase is not a legal container name");
        assert!(err.to_string().contains("Releases"), "{err}");
    }

    /// A misspelled field is a grant that can never match, and Azure reports the
    /// resulting anonymous read of a private container as 404 rather than 403 — so
    /// without this it surfaces as "channel not found".
    #[test]
    fn an_unknown_field_is_rejected() {
        for document in [
            "[Auth]\nreleases = true\n",
            "[authz]\nreleases = true\n",
            "path-style = true\n",
        ] {
            assert!(
                toml::from_str::<AzureEndpointOptions>(document).is_err(),
                "silently ignored: {document}"
            );
        }
    }

    #[test]
    fn enums_serialize_back_to_bools() {
        let toml = toml::to_string(&AzureEndpointOptions::new(
            [
                (container("releases"), Auth::DefaultChain),
                (container("public"), Auth::Anonymous),
            ],
            AzureScheme::Http,
        ))
        .unwrap();
        assert!(toml.contains("releases = true"), "{toml}");
        assert!(toml.contains("public = false"), "{toml}");
        assert!(toml.contains(r#"scheme = "http""#), "{toml}");
        assert!(!toml.contains("DefaultChain"), "{toml}");

        let anonymous = toml::to_string(&AzureEndpointOptions::default()).unwrap();
        assert!(!anonymous.contains("auth"), "{anonymous}");
    }
}
