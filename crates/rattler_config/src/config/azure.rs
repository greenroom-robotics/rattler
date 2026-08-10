use indexmap::IndexMap;
use rattler_azure::{AzureEndpointOptions, AzureHost, AzureScheme};
use serde::{Deserialize, Serialize};

use crate::config::Config;

/// Whether a credential may cross this host's network unencrypted.
///
/// A single-label name (`localhost`, a compose service) has no public DNS
/// resolution, so it counts as local; anything with a dot does not.
fn is_local(host: &AzureHost) -> bool {
    match host.host() {
        url::Host::Domain(domain) => !domain.contains('.'),
        url::Host::Ipv4(ip) => {
            ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified()
        }
        url::Host::Ipv6(ip) => ip.is_loopback() || ip.is_unspecified(),
    }
}

/// Per-host options for Azure Blob channels, keyed by endpoint authority
/// (including a port where one is used, e.g. `127.0.0.1:10000`).
///
/// An entry is a *grant*: it is the only way a container gets credentials, or a
/// host a non-default scheme or path-style addressing. A host with no entry is
/// fetched anonymously over https in host-style addressing. Grants are keyed per
/// container inside the entry (see [`AzureEndpointOptions`]), because Azure
/// assigns RBAC per container.
///
/// The key is an [`AzureHost`] rather than a `String` because a missed grant
/// fails silently: Azure answers an unauthorized request for a private container
/// with a 404, so the user is told "not found". Every host normalization would be
/// such a miss (`MyCompany.blob…`, `host:443`, `[0:0:0:0:0:0:0:1]:10000`).
/// Deserializing the key through the parser that also produces the lookup value
/// removes the class. The inner map is private for the same reason.
///
/// Entries are **user-scoped by contract**. Read from a project manifest, a
/// checked-out repository could name a host and be sent ambient credentials.
#[derive(Default, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AzureOptionsMap(IndexMap<AzureHost, AzureEndpointOptions>);

impl AzureOptionsMap {
    pub fn get(&self, host: &AzureHost) -> AzureEndpointOptions {
        self.0.get(host).cloned().unwrap_or_default()
    }

    /// The configured hosts, in the order the document's table iterated them
    /// (`toml::Table` is a `BTreeMap`, so that is byte order, not write order).
    pub fn hosts(&self) -> impl Iterator<Item = &AzureHost> {
        self.0.keys()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn insert(
        &mut self,
        host: AzureHost,
        options: AzureEndpointOptions,
    ) -> Option<AzureEndpointOptions> {
        self.0.insert(host, options)
    }

    /// Revoke `host`'s grant, returning it if there was one. Shift-removes, so a
    /// serialized table does not reshuffle on an unrelated edit.
    pub fn remove(&mut self, host: &AzureHost) -> Option<AzureEndpointOptions> {
        self.0.shift_remove(host)
    }

    /// The entries as `AzureMiddleware::new` takes them.
    ///
    /// Whole entries, not the narrower `AzureFetchOptions`: the middleware needs a
    /// host's addressing to tell which path segment is the container.
    pub fn endpoint_options(&self) -> impl Iterator<Item = (AzureHost, AzureEndpointOptions)> {
        self.0
            .iter()
            .map(|(host, options)| (host.clone(), options.clone()))
    }
}

/// Reject a document that spells one host two ways.
///
/// Both spellings reach serde, which silently keeps whichever the table iterated
/// last. TOML's own duplicate-key check runs on the raw text, so it cannot see
/// the collision.
pub(crate) fn ensure_no_colliding_hosts(document: &toml::Table) -> Result<(), String> {
    let Some(table) = document
        .get("azure-options")
        .and_then(toml::Value::as_table)
    else {
        return Ok(());
    };

    let mut seen: IndexMap<AzureHost, &String> = IndexMap::new();
    for written in table.keys() {
        // An unparseable key is serde's error to report, not ours.
        let Ok(host) = AzureHost::parse(written) else {
            continue;
        };
        if let Some(first) = seen.insert(host.clone(), written) {
            return Err(format!(
                "`azure-options` names one host twice: \"{first}\" and \"{written}\" are both \
                 `{host}`"
            ));
        }
    }
    Ok(())
}

impl Config for AzureOptionsMap {
    fn is_default(&self) -> bool {
        self.0.is_empty()
    }

    fn merge_config(self, other: &Self) -> Result<Self, super::MergeError> {
        // Merge the two maps, with `other`'s entries layered over existing keys.
        // The host-scoped fields — `scheme`, `path-style` — replace wholesale, but
        // the grants merge per container: a higher-precedence file naming one
        // container must not discard a grant a lower file made on a different
        // container it never mentions. It can still revoke the container it does
        // name, because an explicit `false` is a legal grant.
        let mut merged = self.0;
        for (key, value) in &other.0 {
            let layered = match merged.get(key) {
                Some(lower) => value.layered_over(lower),
                None => value.clone(),
            };
            merged.insert(key.clone(), layered);
        }
        Ok(AzureOptionsMap(merged))
    }

    fn validate(&self) -> Result<(), super::ValidationError> {
        for (host, options) in &self.0 {
            if options.endpoint().scheme != AzureScheme::Http || is_local(host) {
                continue;
            }
            // One granted container is enough: the scheme is host-scoped, so its
            // requests all ride the same cleartext connection.
            if let Some((container, _)) = options.grants().find(|(_, auth)| auth.is_granted()) {
                return Err(super::ValidationError::Invalid(format!(
                    "`azure-options.\"{host}\".auth` grants credentials to `{container}` over \
                     cleartext http. A credential may only be sent unencrypted to a local \
                     endpoint: use an https scheme, or address the emulator by loopback address."
                )));
            }
        }
        Ok(())
    }

    fn keys(&self) -> Vec<String> {
        // Quoted, because every Azure authority contains dots and an unquoted key
        // is not the TOML path the user must pass to `config set`/`unset`. A
        // container name never needs quoting — Azure's rules leave nothing in one
        // that a bare TOML key cannot hold.
        //
        // The per-container grants are listed as their own keys so each is
        // separately unsettable. There is deliberately no `."<host>".auth` key: the
        // path exists only as a table of containers, so `config set
        // azure-options."<host>".auth true` has nowhere to land — which is the
        // point, since that is the one edit whose blast radius would be the whole
        // account.
        self.0
            .iter()
            .flat_map(|(host, options)| {
                let host = toml::Value::from(host.to_string()).to_string();
                let grants = options
                    .grants()
                    .map(|(container, _)| format!("{host}.auth.{container}"))
                    .collect::<Vec<_>>();
                std::iter::once(host).chain(grants)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use rattler_azure::{Addressing, Auth, AzureScheme, ContainerName};

    use super::*;

    fn host(authority: &str) -> AzureHost {
        AzureHost::parse(authority).expect("test host should parse")
    }

    fn container(name: &str) -> ContainerName {
        ContainerName::new(name).expect("test container name")
    }

    #[test]
    fn a_grant_can_be_written_and_revoked() {
        let key = host("mycompany.blob.core.windows.net");
        let granted = AzureEndpointOptions::new(
            [(container("releases"), Auth::DefaultChain)],
            rattler_azure::AzureEndpoint::default(),
        );

        let mut map = AzureOptionsMap::default();
        assert!(map.is_empty());
        assert_eq!(map.insert(key.clone(), granted.clone()), None);
        assert_eq!(map.get(&key), granted);
        assert!(!map.is_empty());

        assert_eq!(map.remove(&key), Some(granted));
        assert!(
            !map.get(&key)
                .fetch(Some(&container("releases")))
                .auth
                .is_granted()
        );
        assert!(map.is_empty());
        assert_eq!(map.remove(&key), None);
    }

    #[test]
    fn table_parses_and_absent_hosts_default() {
        let map: AzureOptionsMap = toml::from_str(
            r#"
            ["mycompany.blob.core.windows.net".auth]
            releases = true

            ["127.0.0.1:10000"]
            scheme = "http"
            path-style = true

            ["127.0.0.1:10000".auth]
            general = true
            "#,
        )
        .unwrap();

        let real = map.get(&host("mycompany.blob.core.windows.net"));
        assert_eq!(
            real.fetch(Some(&container("releases"))).auth,
            Auth::DefaultChain
        );
        assert_eq!(real.endpoint().scheme, AzureScheme::Https);
        assert_eq!(real.endpoint().addressing, Addressing::HostStyle);

        let azurite = map.get(&host("127.0.0.1:10000"));
        assert_eq!(
            azurite.fetch(Some(&container("general"))).auth,
            Auth::DefaultChain
        );
        assert_eq!(azurite.endpoint().scheme, AzureScheme::Http);
        assert_eq!(azurite.endpoint().addressing, Addressing::PathStyle);

        assert!(!real.fetch(Some(&container("public"))).auth.is_granted());
        let unlisted = map.get(&host("someoneelse.blob.core.windows.net"));
        assert!(
            !unlisted
                .fetch(Some(&container("releases")))
                .auth
                .is_granted()
        );
        assert_eq!(unlisted, AzureEndpointOptions::default());

        assert_eq!(
            map.endpoint_options().collect::<Vec<_>>(),
            vec![
                (host("127.0.0.1:10000"), azurite),
                (host("mycompany.blob.core.windows.net"), real),
            ]
        );
    }

    #[test]
    fn cleartext_grants_are_confined_to_local_endpoints() {
        for authority in ["127.0.0.1:10000", "[::1]:10000", "azurite:10000"] {
            let map: AzureOptionsMap = toml::from_str(&format!(
                "[\"{authority}\"]\nscheme = \"http\"\n[\"{authority}\".auth]\ngeneral = true\n"
            ))
            .unwrap();
            assert!(map.validate().is_ok(), "{authority} is local");
        }

        for authority in ["mycompany.blob.core.windows.net", "internal.example.com"] {
            let map: AzureOptionsMap = toml::from_str(&format!(
                "[\"{authority}\"]\nscheme = \"http\"\n[\"{authority}\".auth]\npublic = false\nreleases = true\n"
            ))
            .unwrap();
            let err = map.validate().expect_err("{authority} is routable");
            assert!(err.to_string().contains("releases"), "{err}");

            let https: AzureOptionsMap =
                toml::from_str(&format!("[\"{authority}\".auth]\nreleases = true\n")).unwrap();
            assert!(https.validate().is_ok());
            let anonymous: AzureOptionsMap = toml::from_str(&format!(
                "[\"{authority}\"]\nscheme = \"http\"\n[\"{authority}\".auth]\nreleases = false\n"
            ))
            .unwrap();
            assert!(anonymous.validate().is_ok());
        }
    }

    #[test]
    fn a_document_naming_one_host_twice_is_refused() {
        let document = r#"
[azure-options."acct.blob.example".auth]
releases = false

[azure-options."ACCT.blob.example.".auth]
releases = true
"#;
        let error = ensure_no_colliding_hosts(&document.parse().unwrap())
            .expect_err("a collision must be reported");
        assert!(error.contains("acct.blob.example"), "{error}");
    }

    #[test]
    fn merge_replaces_the_endpoint_wholesale() {
        let base: AzureOptionsMap =
            toml::from_str("[\"host.example\"]\npath-style = true\n").unwrap();
        let over: AzureOptionsMap =
            toml::from_str("[\"host.example\"]\nscheme = \"http\"\n").unwrap();

        let merged = base.merge_config(&over).unwrap();
        let entry = merged.get(&host("host.example"));
        assert_eq!(entry.endpoint().scheme, AzureScheme::Http);
        assert_eq!(entry.endpoint().addressing, Addressing::HostStyle);
    }

    #[test]
    fn merge_layers_grants_per_container() {
        let system: AzureOptionsMap =
            toml::from_str("[\"host.example\".auth]\nreleases = true\nstaging = true\n").unwrap();
        let user: AzureOptionsMap =
            toml::from_str("[\"host.example\".auth]\nstaging = false\ninternal = true\n").unwrap();

        let entry = system
            .merge_config(&user)
            .unwrap()
            .get(&host("host.example"));
        assert!(
            entry.fetch(Some(&container("releases"))).auth.is_granted(),
            "a grant the user file never mentions must survive the merge"
        );
        assert!(
            !entry.fetch(Some(&container("staging"))).auth.is_granted(),
            "an explicit `false` must revoke a lower-precedence grant"
        );
        assert!(entry.fetch(Some(&container("internal"))).auth.is_granted());
    }

    #[test]
    fn keys_are_normalized_the_same_way_lookups_are() {
        for (written, looked_up) in [
            (
                "MyCompany.blob.core.windows.net",
                "mycompany.blob.core.windows.net",
            ),
            (
                "mycompany.blob.core.windows.net:443",
                "mycompany.blob.core.windows.net:443",
            ),
            ("ünï.blob.example", "xn--n-nga1b.blob.example"),
            ("[0:0:0:0:0:0:0:1]:10000", "[::1]:10000"),
            ("0x7f.1", "127.0.0.1"),
            ("acct.blob.core.windows.net.", "acct.blob.core.windows.net"),
        ] {
            let map: AzureOptionsMap =
                toml::from_str(&format!("[\"{written}\".auth]\nreleases = true\n")).unwrap();

            assert!(
                map.get(&host(looked_up))
                    .fetch(Some(&container("releases")))
                    .auth
                    .is_granted(),
                "the grant written as `{written}` did not apply to `{looked_up}`"
            );
            assert_eq!(
                map.keys(),
                vec![
                    format!("\"{looked_up}\""),
                    format!("\"{looked_up}\".auth.releases"),
                ],
                "{written}"
            );
            let written_back = toml::to_string(&map).unwrap();
            assert!(
                written_back.contains(&format!("[\"{looked_up}\"")),
                "{written} was written back as {written_back}"
            );
        }
    }

    #[test]
    fn an_unparseable_key_is_rejected() {
        let err = toml::from_str::<AzureOptionsMap>(
            "[\"acct.blob.example/general\".auth]\nreleases = true\n",
        )
        .expect_err("a key carrying a path must be rejected");
        assert!(
            err.to_string().contains("acct.blob.example/general"),
            "{err}"
        );
    }

    #[test]
    fn an_unusable_container_key_is_rejected() {
        let err =
            toml::from_str::<AzureOptionsMap>("[\"acct.blob.example\".auth]\nReleases = true\n")
                .expect_err("an uppercase container name must be rejected");
        assert!(err.to_string().contains("Releases"), "{err}");
    }
}
