use indexmap::IndexMap;
use rattler_azure::{AzureEndpointOptions, AzureHost};
use serde::{Deserialize, Serialize};

use crate::config::Config;

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
        if let Some(options) = self.0.get(host) {
            return options.clone();
        }

        // `host` and `host:443` are the same https endpoint, and a user may write
        // either in the config and the other in a channel URL. `AzureHost` keeps
        // the written port because it has no scheme to judge it against; the entry
        // does, so the collapse happens here. Both directions, since either side
        // may be the one carrying the port.
        self.0
            .iter()
            .find(|(key, options)| {
                let scheme = options.endpoint().scheme;
                key.without_default_port(scheme).as_ref() == Some(host)
                    || host.without_default_port(scheme).as_ref() == Some(*key)
            })
            .map(|(_, options)| options.clone())
            .unwrap_or_default()
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
        // An entry replaces wholesale rather than merging field by field. Merging
        // let two individually-valid files produce a combination neither wrote: a
        // system file granting a container over https, plus a user file setting
        // only `scheme = "http"` on the same host, used to yield a cleartext grant.
        // An entry is one unit — its scheme, addressing and grants describe one
        // endpoint — so the layer that names a host owns it.
        let mut merged = self.0;
        merged.extend(
            other
                .0
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        Ok(AzureOptionsMap(merged))
    }

    fn keys(&self) -> Vec<String> {
        // Quoted, because every Azure authority contains dots and the grant keys
        // an `account/container` slash, and an unquoted key is not the TOML path
        // the user must pass to `config set`/`unset`.
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
                    .map(|(coordinates, _)| {
                        let coordinates = toml::Value::from(coordinates.to_string()).to_string();
                        format!("{host}.auth.{coordinates}")
                    })
                    .collect::<Vec<_>>();
                std::iter::once(host).chain(grants)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use rattler_azure::{Addressing, Auth, AzureCoordinates, AzureScheme};

    use super::*;

    fn host(authority: &str) -> AzureHost {
        AzureHost::parse(authority).expect("test host should parse")
    }

    fn coords(account: &str, container: &str) -> AzureCoordinates {
        AzureCoordinates::parse(&format!("{account}/{container}")).expect("test coordinates")
    }

    /// A container on the account every test host belongs to.
    fn container(name: &str) -> AzureCoordinates {
        coords("mycompany", name)
    }

    #[test]
    fn table_parses_and_absent_hosts_default() {
        let map: AzureOptionsMap = toml::from_str(
            r#"
            ["mycompany.blob.core.windows.net".auth]
            "mycompany/releases" = true

            ["127.0.0.1:10000"]
            scheme = "http"
            path-style = true

            ["127.0.0.1:10000".auth]
            "devstoreaccount1/general" = true
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
            azurite
                .fetch(Some(&coords("devstoreaccount1", "general")))
                .auth,
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
    fn merge_replaces_the_grant_table_wholesale() {
        let system: AzureOptionsMap = toml::from_str(
            "[\"host.example\".auth]\n\"mycompany/releases\" = true\n\"mycompany/staging\" = true\n",
        )
        .unwrap();
        let user: AzureOptionsMap =
            toml::from_str("[\"host.example\".auth]\n\"mycompany/internal\" = true\n").unwrap();

        let entry = system
            .merge_config(&user)
            .unwrap()
            .get(&host("host.example"));
        assert!(entry.fetch(Some(&container("internal"))).auth.is_granted());
        // The higher-precedence file states the whole grant table for the host, so
        // a grant it does not restate is revoked rather than inherited: a table
        // half-read from a file the user is not looking at is the worse surprise.
        assert!(
            !entry.fetch(Some(&container("releases"))).auth.is_granted(),
            "a grant the higher-precedence file omits must not survive the merge"
        );
    }

    #[test]
    fn keys_are_normalized_the_same_way_lookups_are() {
        for (written, looked_up) in [(
            "MyCompany.blob.core.windows.net",
            "mycompany.blob.core.windows.net",
        )] {
            let map: AzureOptionsMap = toml::from_str(&format!(
                "[\"{written}\".auth]\n\"mycompany/releases\" = true\n"
            ))
            .unwrap();

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
                    format!("\"{looked_up}\".auth.\"mycompany/releases\""),
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
            "[\"acct.blob.example/general\".auth]\n\"acct/releases\" = true\n",
        )
        .expect_err("a key carrying a path must be rejected");
        assert!(
            err.to_string().contains("acct.blob.example/general"),
            "{err}"
        );
    }
}
