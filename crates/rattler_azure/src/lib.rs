//! Helpers for deriving Azure Blob coordinates from channel URLs and for minting
//! short-lived credentials for them.
//!
//! # Host model
//!
//! The host a channel URL names is taken to be the storage endpoint it claims to
//! be. Credentials, wire scheme and addressing are declared in [`options`], never
//! inferred from the host name. Scheme and addressing are per host; credentials
//! are per *container*, the scope Azure's own RBAC has. The default grant is
//! [`Auth::Anonymous`], so naming a host in a URL by itself sends nothing to it.
//! Signing and sending live in `rattler_networking`, not here.
//!
//! Userinfo (`user:pass@host`) is rejected wherever a host is parsed:
//! `az://real.host@evil.example/…` reads as the real host while addressing the
//! attacker's.

#[cfg(feature = "clap")]
pub mod clap;

pub mod options;

pub use options::{
    Addressing, Auth, AzureEndpoint, AzureEndpointOptions, AzureFetchOptions, AzureScheme,
};

pub use secrecy::{ExposeSecret, SecretString};
use url::Url;

#[derive(Clone, Debug)]
pub enum AzureCredentials {
    AccountKey(SecretString),
    SasToken(SecretString),
}

/// Strip a single leading `?` from a SAS token.
///
/// `--sas-token` may be written with or without one; a SAS minted by
/// [`mint_user_delegation_sas`] never has one.
pub fn normalize_sas_token(token: &str) -> &str {
    token.strip_prefix('?').unwrap_or(token)
}

#[derive(Debug, thiserror::Error)]
pub enum AzureUrlError {
    #[error("no host in Azure blob URL")]
    NoHost,

    #[error(
        "Azure blob URL must not contain userinfo (`user:pass@host`): the `user@host` form is a \
         host-spoofing vector that can disguise the real target host, and userinfo is invalid in \
         blob URLs"
    )]
    UserInfoNotAllowed,

    #[error("`{authority}` is not a valid Azure host: {reason}; expected `host` or `host:port`")]
    InvalidHostAuthority { authority: String, reason: String },

    /// Host-style addressing was requested but the host has no account label: it
    /// is an IP literal, or a domain with only one label.
    ///
    /// The fix is a config line rather than a URL change, so the message names
    /// that line. The host is spelled the way [`AzureHost`] spells it, which is
    /// how the config table is keyed, so a key copied out of this message matches.
    #[error(
        "Azure blob URL host `{0}` is not a dotted domain of the form `<account>.blob.<suffix>`, \
         so its first label cannot be a storage account. Such a host needs path-style addressing, \
         where the storage account is the first path segment instead; that is not selectable from \
         configuration yet, and will be enabled by `[azure-options.\"{0}\"]` with \
         `path-style = true`"
    )]
    InvalidHost(String),

    #[error("could not derive account name from Azure blob URL")]
    NoAccount,

    #[error("no container in Azure blob URL")]
    NoContainer,

    #[error(
        "`{0}` is not a valid Azure storage account name: account names are 3-24 characters of \
         lowercase letters and digits only"
    )]
    InvalidAccountName(String),

    #[error(
        "`{0}` is not a valid Azure blob container name: container names are 3-63 characters of \
         lowercase letters, digits and hyphens, must start and end with a letter or digit, and \
         must not contain consecutive hyphens"
    )]
    InvalidContainerName(String),

    #[error("`{value}` is not a valid URL")]
    InvalidUrl {
        value: String,
        #[source]
        source: url::ParseError,
    },

    /// The path contains a `.` or `..` segment, in any spelling.
    ///
    /// The URL parser resolves these before anything here sees a segment, so
    /// `az://acct.blob.core.windows.net/general/a/../../evil/x` would arrive
    /// addressing container `evil` while reading as `general` — a credential
    /// granted for one container spent on another.
    #[error(
        "Azure blob channel URL segment `{0}` is a relative path segment; a channel URL must name \
         the container it addresses directly, so write the path without `.` or `..`"
    )]
    DotSegmentInPath(String),

    /// The path has an empty segment somewhere other than the end.
    ///
    /// `az://host//container/...` would otherwise read as having no container at
    /// all, which silently downgrades a granted fetch to an anonymous one.
    #[error(
        "Azure blob channel URL path `{path}` has an empty segment at position {index}; a doubled \
         `/` names nothing, so write the path with single separators"
    )]
    EmptyPathSegment { path: String, index: usize },

    /// A path segment contains a `%` that does not begin a percent-escape.
    ///
    /// Percent-decoding passes it through literally, so the fetch path would send
    /// it raw while the index path re-encodes it to `%25` and writes to a different
    /// blob than the one that gets read.
    #[error(
        "Azure blob channel URL segment `{segment}` contains `{escape}`, which is not a valid \
         percent-escape; write a literal `%` as `%25`"
    )]
    MalformedPercentEscape { segment: String, escape: String },

    /// A path segment percent-decodes to bytes that are not UTF-8.
    ///
    /// Blob names are UTF-8. Decoding lossily would substitute U+FFFD and silently
    /// address a different blob than the URL names.
    #[error(
        "Azure blob channel URL segment `{segment}` percent-decodes to bytes that are not UTF-8, \
         so it cannot name a blob"
    )]
    NonUtf8Path {
        segment: String,
        #[source]
        source: std::str::Utf8Error,
    },

    #[error(
        "Azure blob channel URL must use the `az://` scheme, e.g. \
         `az://<account>.blob.core.windows.net/<container>/...`: got `{0}`"
    )]
    InvalidScheme(String),
}

/// A storage account name that has passed Azure's naming rules: 3-24 characters
/// of lowercase letters and digits.
///
/// Those rules are the only thing keeping option-shaped text (`--as-user`, `-o`)
/// out of the `az` argv in [`mint_user_delegation_sas`], which is why the mint
/// takes this type rather than a `&str`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountName(String);

impl AccountName {
    pub fn new(name: &str) -> Result<Self, AzureUrlError> {
        let valid = (3..=24).contains(&name.len())
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        valid
            .then(|| Self(name.to_string()))
            .ok_or_else(|| AzureUrlError::InvalidAccountName(name.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AccountName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A blob container name that has passed Azure's naming rules: 3-63 characters of
/// lowercase letters, digits and hyphens, with no leading or trailing hyphen and
/// no consecutive hyphens.
///
/// Exists for the same reason as [`AccountName`].
///
/// It is also the key of an `auth` table in `azure-options`, hence the hash and
/// string serde bridge. Azure's rules make a container name lowercase by
/// construction, so unlike a host there is only one spelling of one container.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(try_from = "String", into = "String")
)]
pub struct ContainerName(String);

impl ContainerName {
    pub fn new(name: &str) -> Result<Self, AzureUrlError> {
        let valid = (3..=63).contains(&name.len())
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !name.starts_with('-')
            && !name.ends_with('-')
            && !name.contains("--");
        valid
            .then(|| Self(name.to_string()))
            .ok_or_else(|| AzureUrlError::InvalidContainerName(name.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ContainerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for ContainerName {
    type Err = AzureUrlError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// Routes a written `auth` key through [`ContainerName::new`], so a key Azure
/// would refuse is a config error at load rather than a grant that never matches.
impl TryFrom<String> for ContainerName {
    type Error = AzureUrlError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

impl From<ContainerName> for String {
    fn from(container: ContainerName) -> Self {
        container.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzureCoordinates {
    pub account: AccountName,
    pub container: ContainerName,
}

/// Derive the storage account name and container from an Azure Blob channel URL.
///
/// Which part of the URL holds the account is not guessable, since `host/a/b` is
/// a valid reading under both styles. `addressing` decides:
///
/// - [`Addressing::HostStyle`]: account is the first host label, container the
///   first path segment. The host must be a domain with at least two labels, so
///   IP literals and single-label hosts fail with
///   [`AzureUrlError::InvalidHost`].
/// - [`Addressing::PathStyle`]: account is the first path segment, container the
///   second. On a host under a known Azure Blob suffix this only warns, since the
///   suffix list cannot cover a proxy or a private endpoint.
///
/// Both derived names are held to Azure's naming rules under both styles, since
/// path-style takes the account from user-controlled path text.
pub fn account_and_container(
    channel: &AzureChannelUrl,
    addressing: Addressing,
) -> Result<AzureCoordinates, AzureUrlError> {
    let host = channel.host();
    let container_segment =
        || segment(channel, addressing.container_segment()).ok_or(AzureUrlError::NoContainer);

    let (account, container) = match addressing {
        Addressing::HostStyle => {
            let account = host
                .account_label()
                .ok_or_else(|| AzureUrlError::InvalidHost(host.to_string()))?;
            (account, container_segment()?)
        }
        Addressing::PathStyle => {
            if host.is_known_azure_blob_endpoint() {
                tracing::warn!(
                    "`path-style = true` is set for `{host}`, which is a real Azure Blob endpoint \
                     addressed host-style: its storage account is `{}`, not the first path \
                     segment. Requests still come out identical, but anything that needs the \
                     account on its own — minting a user-delegation SAS, for one — will use the \
                     path segment instead. Remove `path-style = true` from \
                     `[azure-options.\"{host}\"]` unless you meant it",
                    host.account_label().unwrap_or("<none>"),
                );
            }
            (
                segment(channel, 0).ok_or(AzureUrlError::NoAccount)?,
                container_segment()?,
            )
        }
    };

    Ok(AzureCoordinates {
        account: AccountName::new(account)?,
        container: ContainerName::new(container)?,
    })
}

/// The container an Azure Blob URL names, when it names one.
///
/// The fetch path's half of [`account_and_container`]. It derives no account, so
/// a host that cannot carry an account label (an IP literal read host-style) still
/// fetches.
///
/// `Ok(None)` means the URL has no container segment, so there is nothing to
/// attribute a grant to. `Err` means the segment is there but is not a name Azure
/// allows, which is a malformed endpoint rather than an ungranted one.
pub fn container(
    channel: &AzureChannelUrl,
    addressing: Addressing,
) -> Result<Option<ContainerName>, AzureUrlError> {
    segment(channel, addressing.container_segment())
        .map(ContainerName::new)
        .transpose()
}

fn segment(channel: &AzureChannelUrl, index: usize) -> Option<&str> {
    // The `is_empty` filter is only sound because `AzureChannelUrl::parse` rejects
    // an empty segment anywhere but the end: the sole one that can reach here is a
    // trailing slash, where "absent" is the right reading. Without that guarantee
    // `az://host//general` would read as having no container and silently fetch a
    // granted one anonymously.
    channel
        .path_segments()
        .nth(index)
        .filter(|segment| !segment.is_empty())
}

/// The first `%` in `segment` that does not begin a two-hex-digit escape, with
/// whatever follows it, for the error message.
fn malformed_percent_escape(segment: &str) -> Option<String> {
    let bytes = segment.as_bytes();
    bytes.iter().enumerate().find_map(|(index, byte)| {
        if *byte != b'%' {
            return None;
        }
        let escape = bytes
            .get(index..index + 3)
            .filter(|escape| escape[1..].iter().all(u8::is_ascii_hexdigit));
        escape
            .is_none()
            .then(|| segment[index..].chars().take(3).collect())
    })
}

#[derive(Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(try_from = "String", into = "String")
)]
pub struct AzureHost {
    host: url::Host,
    port: Option<u16>,
}

impl AzureHost {
    pub fn parse(authority: &str) -> Result<Self, AzureUrlError> {
        if authority.contains('@') {
            return Err(AzureUrlError::UserInfoNotAllowed);
        }
        if authority.contains(['/', '\\', '?', '#']) {
            return Err(AzureUrlError::InvalidHostAuthority {
                authority: authority.to_string(),
                reason: "it carries a path, query or fragment".to_string(),
            });
        }

        // Two parses, each for the one thing it is authoritative about, because no
        // single scheme gives both. `https` is a special scheme, so it runs the URL
        // Standard's host parser: lowercasing, IDNA, and IP literals as typed
        // `Ipv4`/`Ipv6` hosts — but it also drops `:443`. `az` is not special, so
        // it has no default port to drop, but its opaque-host parsing leaves the
        // host unnormalized (`MyCompany.X` stays mixed case, `127.0.0.1` arrives as
        // a `Domain`). Host from the first, port from the second.
        let normalized = Self::parse_as(authority, "https")?;
        let verbatim = Self::parse_as(authority, "az")?;

        // `url` reads a bare trailing colon as "no port at all", so `host:` would
        // otherwise be accepted as `host` — a different endpoint from the one whose
        // port the user was in the middle of writing. Port 0 it keeps, and `wire()`
        // then hands out `https://host:0/…`, which no connection can be made to.
        let port_reason = match (Self::written_port(authority), verbatim.port()) {
            (Some(""), _) => Some("its port is empty"),
            (_, Some(0)) => Some("port 0 cannot be connected to"),
            _ => None,
        };
        if let Some(reason) = port_reason {
            return Err(AzureUrlError::InvalidHostAuthority {
                authority: authority.to_string(),
                reason: reason.to_string(),
            });
        }

        let host = normalized.host().ok_or(AzureUrlError::NoHost)?.to_owned();
        Self::normalized(host, verbatim.port(), authority)
    }

    /// The port exactly as the authority spells it, when it spells one.
    ///
    /// An IPv6 literal is bracketed, so only a `]:port` suffix is a port.
    fn written_port(authority: &str) -> Option<&str> {
        let (_, port) = authority.rsplit_once(':')?;
        (!port.ends_with(']')).then_some(port)
    }

    fn parse_as(authority: &str, scheme: &str) -> Result<Url, AzureUrlError> {
        Url::parse(&format!("{scheme}://{authority}")).map_err(|err| {
            AzureUrlError::InvalidHostAuthority {
                authority: authority.to_string(),
                reason: err.to_string(),
            }
        })
    }

    fn normalized(
        host: url::Host,
        port: Option<u16>,
        authority: &str,
    ) -> Result<Self, AzureUrlError> {
        const DNS_NAME_LIMIT: usize = 253;

        let url::Host::Domain(domain) = &host else {
            return Ok(Self { host, port });
        };

        // Re-run the host parser on the trimmed name so there is exactly one
        // normalization path rather than a second, hand-rolled one.
        let host = url::Host::parse(domain.strip_suffix('.').unwrap_or(domain)).map_err(|err| {
            AzureUrlError::InvalidHostAuthority {
                authority: authority.to_string(),
                reason: err.to_string(),
            }
        })?;
        if let url::Host::Domain(domain) = &host {
            // Only one trailing dot is stripped, so `acct.example..` still has an
            // empty label here — as does `acct..example`. Rejecting both is what
            // lets `Display` round-trip, and what stops account derivation from
            // handing out an empty account name.
            if domain.split('.').any(str::is_empty) {
                return Err(AzureUrlError::InvalidHostAuthority {
                    authority: authority.to_string(),
                    reason: "one of its labels is empty".to_string(),
                });
            }
            // Measured after IDNA, since the punycode form is what is resolved.
            if domain.len() > DNS_NAME_LIMIT {
                return Err(AzureUrlError::InvalidHostAuthority {
                    authority: authority.to_string(),
                    reason: format!(
                        "it is {} characters long, over the {DNS_NAME_LIMIT}-character limit DNS \
                         puts on a name",
                        domain.len()
                    ),
                });
            }
        }
        Ok(Self { host, port })
    }

    pub fn host(&self) -> &url::Host {
        &self.host
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// The storage account label under host-style addressing.
    ///
    /// `None` whenever the host cannot carry an account name. The stored
    /// [`url::Host`] answers that by construction: an IP literal is never a
    /// domain, so `127.0.0.1` cannot yield an account named `127`, and a domain
    /// needs at least two labels, so `localhost` is rejected.
    ///
    /// [`parse`](Self::parse) has already rejected empty labels and a trailing
    /// dot, so those two labels are non-empty.
    fn account_label(&self) -> Option<&str> {
        match &self.host {
            url::Host::Domain(domain) => {
                let mut labels = domain.split('.');
                let first = labels.next()?;
                labels.next().is_some().then_some(first)
            }
            url::Host::Ipv4(_) | url::Host::Ipv6(_) => None,
        }
    }

    /// Whether this host sits under a suffix Microsoft operates, where the account
    /// is by definition the first label.
    ///
    /// Advisory only, never a security boundary: it exists to warn about a
    /// `path-style = true` that cannot be what the user meant. A proxy or private
    /// endpoint in front of real Azure answers `false`, so a `false` proves
    /// nothing.
    pub fn is_known_azure_blob_endpoint(&self) -> bool {
        const SUFFIXES: &[&str] = &[
            "blob.core.windows.net",
            "blob.core.usgovcloudapi.net",
            "blob.core.chinacloudapi.cn",
        ];

        let url::Host::Domain(domain) = &self.host else {
            return false;
        };
        SUFFIXES.iter().any(|suffix| {
            // The dot has to be part of the match, or `notblob.core.windows.net`
            // would pass as `blob.core.windows.net`.
            domain
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
        })
    }
}

impl std::fmt::Display for AzureHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `url::Host`'s own `Display` brackets an IPv6 literal, which is what an
        // authority needs.
        write!(f, "{}", self.host)?;
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for AzureHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AzureHost({:?})", self.to_string())
    }
}

impl std::str::FromStr for AzureHost {
    type Err = AzureUrlError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<String> for AzureHost {
    type Error = AzureUrlError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<AzureHost> for String {
    fn from(host: AzureHost) -> Self {
        host.to_string()
    }
}

/// A validated Azure Blob **channel** URL, which has two spellings: `az://…` as
/// the user writes it and in configuration, and `http(s)://…` on the wire.
///
/// The parts are stored rather than a `Url`, because a `Url`'s port is
/// scheme-relative: storing `az://host:443/…` as `https` drops the port, and
/// [`wire`](Self::wire) would then hand out `http://host/…`, a different endpoint.
/// [`AzureHost`] holds host and port explicitly and normalizes both without a
/// scheme. Every spelling is built from those same parts, so no two spellings can
/// disagree.
///
/// The wire scheme is an argument to [`wire`](Self::wire) rather than a field
/// because it comes from the host's `azure-options` entry, while
/// [`parse`](Self::parse) runs as a clap `value_parser`, before any config file is
/// read. `rattler-index` takes it from that entry; `rattler_upload` passes the
/// default, because it reads no config file at all.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AzureChannelUrl {
    host: AzureHost,

    /// The path as the URL Standard normalizes it: always a leading `/`, still
    /// percent-encoded.
    path: String,

    /// The query, when there is one — a SAS token may be written inline.
    query: Option<String>,

    /// The fragment, when there is one.
    ///
    /// Kept so [`canonical`](Self::canonical) spells the channel back the way the
    /// user wrote it. It reaches no server: an HTTP request carries only the path
    /// and query.
    fragment: Option<String>,
}

impl AzureChannelUrl {
    /// Parse and validate an `az://` channel URL.
    ///
    /// The only accepted spelling is `az://<host>/<…>`. A bare `http(s)://` URL is
    /// not accepted, so there is one canonical spelling for an Azure channel.
    ///
    /// Account and container derivation happens in [`account_and_container`], not
    /// here: it depends on the host's addressing style, which is config that does
    /// not exist yet at clap parse time.
    pub fn parse(value: &str) -> Result<Self, AzureUrlError> {
        // URL schemes are case-insensitive and `Url` lowercases them, so `AZ://…`
        // reaches every downstream `scheme() == "az"` comparison as `az`. Matching
        // case-insensitively here keeps this parser from rejecting what those
        // comparisons accept.
        let rest = strip_az_scheme(value)
            .ok_or_else(|| AzureUrlError::InvalidScheme(value.to_string()))?;

        // The authority runs to the first path, query or fragment delimiter. `\` is
        // in the set because the special-scheme parser used below treats it as `/`,
        // and splitting on it keeps the authority this type validates equal to the
        // authority that parser sees.
        let authority_end = rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(authority_end);
        let host = AzureHost::parse(authority)?;

        // Parse the whole thing as `https` for the path, query and fragment: the
        // special-scheme parser is what normalizes them, and `wire()` hands them
        // straight to an `http(s)` URL, so they have to be normalized its way.
        let url = Url::parse(&format!("https://{authority}{tail}")).map_err(|source| {
            AzureUrlError::InvalidUrl {
                value: value.to_string(),
                source,
            }
        })?;

        // Dot segments — `%2e%2e` as much as `..` — are resolved by that parser
        // before anything here has looked at a segment, so a path reading as one
        // container (path-style: one *account*) can address another. They are
        // checked against the text the user wrote, because by the time `url` exists
        // the evidence is gone. One anywhere is enough: `/general/a/../../evil/x`
        // eats backwards into the container from a segment that reads as harmless.
        //
        // Nothing else about the path is this parser's business. Which blob a
        // well-formed path names is the user's to get right; only the segments that
        // decide *which container gets a credential* are load-bearing here, and
        // those are guarded by `AccountName`/`ContainerName`, whose charsets admit
        // neither `/` nor `%`.
        let written = match tail.split(['?', '#']).next().unwrap_or_default() {
            "" => "/",
            path => path,
        };
        for segment in written.trim_start_matches('/').split('/') {
            let decoded = percent_encoding::percent_decode_str(segment)
                .decode_utf8()
                .map_err(|source| AzureUrlError::NonUtf8Path {
                    segment: segment.to_string(),
                    source,
                })?;
            if decoded == "." || decoded == ".." {
                return Err(AzureUrlError::DotSegmentInPath(segment.to_string()));
            }
        }

        // An empty segment is not a blob name and not a container name, but
        // `path_segments()` yields it, so without this `az://host//general` reads as
        // "no container" and downgrades a granted fetch to anonymous. A trailing one
        // is just a trailing slash.
        let segments = url
            .path_segments()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let last = segments.len().saturating_sub(1);
        if let Some(index) = segments
            .iter()
            .take(last)
            .position(|segment| segment.is_empty())
        {
            return Err(AzureUrlError::EmptyPathSegment {
                path: url.path().to_string(),
                index,
            });
        }

        // A `%` that does not start an escape is the one encoding defect the user
        // cannot be left to own: `percent_decode` passes it through literally, so
        // the fetch path sends `gen%eral` while opendal re-encodes the decoded form
        // to `gen%25eral` and indexes under a different blob.
        for segment in &segments {
            if let Some(escape) = malformed_percent_escape(segment) {
                return Err(AzureUrlError::MalformedPercentEscape {
                    segment: segment.to_string(),
                    escape,
                });
            }
            percent_encoding::percent_decode_str(segment)
                .decode_utf8()
                .map_err(|source| AzureUrlError::NonUtf8Path {
                    segment: segment.to_string(),
                    source,
                })?;
        }

        Ok(Self {
            host,
            path: url.path().to_string(),
            query: url.query().map(str::to_string),
            fragment: url.fragment().map(str::to_string),
        })
    }

    pub fn canonical(&self) -> Url {
        self.spelled("az", Sas::Masked)
    }

    pub fn wire(&self, scheme: AzureScheme) -> Url {
        self.spelled(scheme.as_str(), Sas::Exposed)
    }

    fn spelled(&self, scheme: &str, sas: Sas) -> Url {
        let mut text = format!("{scheme}://{}{}", self.host, self.path);
        if let Some(query) = &self.query {
            text.push('?');
            match sas {
                Sas::Exposed => text.push_str(query),
                Sas::Masked => text.push_str(&mask_sas_signature(query)),
            }
        }
        if let Some(fragment) = &self.fragment {
            text.push('#');
            // Masked on the same terms as the query: this spelling is the one that
            // reaches logs and error messages, and a `sig` is no less a signature
            // for having been written after a `#`.
            match sas {
                Sas::Exposed => text.push_str(fragment),
                Sas::Masked => text.push_str(&mask_sas_signature(fragment)),
            }
        }
        // Cannot fail: the authority re-serializes to the normalized form it was
        // parsed from, and the path, query and fragment are already-encoded output
        // of a `Url` parse. Every host shape `AzureHost` can hold (normalized
        // domain, IPv4 literal, bracketed IPv6) is valid both to the special-scheme
        // host parser and to the opaque-host parser `az://` gets.
        Url::parse(&text).expect("a normalized authority, path and query is a valid URL")
    }

    /// The host, with its port when the URL carries one.
    ///
    /// This is also the `azure-options` key for the channel.
    pub fn host(&self) -> &AzureHost {
        &self.host
    }

    /// The still-encoded path segments, exactly as [`Url::path_segments`] would
    /// yield them for the wire spelling.
    fn path_segments(&self) -> std::str::Split<'_, char> {
        self.path.strip_prefix('/').unwrap_or(&self.path).split('/')
    }
}

impl std::fmt::Display for AzureChannelUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.canonical())
    }
}

impl std::fmt::Debug for AzureChannelUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Derived, this would print the raw query and hand a `{:?}` on any struct
        // holding a channel the signature that `canonical()` exists to withhold.
        f.debug_tuple("AzureChannelUrl")
            .field(&self.canonical().as_str())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sas {
    Exposed,
    Masked,
}

/// Replace the value of a query's `sig` parameter, leaving the rest intact.
///
/// The other SAS parameters (`sv`, `se`, `sp`, …) only describe the grant; `sig`
/// is the secret that makes it usable.
fn mask_sas_signature(query: &str) -> String {
    query
        .split('&')
        .map(|parameter| match parameter.split_once('=') {
            Some((name, _)) if name.eq_ignore_ascii_case("sig") => format!("{name}=REDACTED"),
            _ => parameter.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

impl std::str::FromStr for AzureChannelUrl {
    type Err = AzureUrlError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

fn strip_az_scheme(value: &str) -> Option<&str> {
    const PREFIX: &str = "az://";
    value
        .get(..PREFIX.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(PREFIX))
        .map(|_| &value[PREFIX.len()..])
}

/// Build an opendal [`AzblobConfig`](opendal::services::AzblobConfig) from a
/// channel URL, the endpoint options of its host, and credentials.
///
/// Account name, endpoint, container and root prefix all come from the channel
/// URL, read the way `endpoint_options` says to read it. The credentials supply
/// only the account key or SAS token.
///
/// # The two addressing shapes
///
/// opendal's azblob core builds every request URI as `{endpoint}/{container}/{path}`
/// and carries no account field, so under path-style the account can only reach
/// the URL through `endpoint`:
///
/// - [`Addressing::HostStyle`]: `endpoint` is `{scheme}://{host}[:{port}]` and
///   `root` is the path after the container.
/// - [`Addressing::PathStyle`]: `endpoint` is
///   `{scheme}://{host}[:{port}]/{account}` and `root` is the path after *both*
///   the account and the container.
///
/// `account_name` is mandatory under both styles: opendal infers it only from
/// three known Azure suffixes and returns `None` rather than an error otherwise,
/// so omitting it makes shared-key signing quietly never engage and surfaces as a
/// 403.
///
/// Neither endpoint ends in a slash. `AzblobBuilder::endpoint` trims one, but this
/// builds the config struct literally, where nothing does.
#[cfg(feature = "opendal")]
pub fn azblob_config(
    credentials: &AzureCredentials,
    channel: &AzureChannelUrl,
    endpoint_options: AzureEndpoint,
) -> Result<opendal::services::AzblobConfig, AzureUrlError> {
    let AzureCoordinates { account, container } =
        account_and_container(channel, endpoint_options.addressing)?;

    let authority = channel.host();
    let endpoint = match endpoint_options.addressing {
        Addressing::HostStyle => format!("{}://{authority}", endpoint_options.scheme),
        Addressing::PathStyle => format!("{}://{authority}/{account}", endpoint_options.scheme),
    };

    // Percent-decode each segment: `path_segments()` yields still-encoded segments
    // and opendal percent-encodes `root + path` again, so passing them through
    // verbatim would double-encode a prefix containing a space or a `+`.
    // `account_and_container` has already confirmed the consumed segments exist.
    let root = format!(
        "/{}",
        channel
            .path_segments()
            .skip(endpoint_options.addressing.segments_before_root())
            // Infallible in practice: `AzureChannelUrl::parse` rejects a segment that
            // does not decode to UTF-8. Erroring rather than substituting U+FFFD is
            // what keeps that a guarantee instead of an assumption.
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
        AzureCredentials::SasToken(token) => (
            None,
            Some(normalize_sas_token(token.expose_secret()).to_string()),
        ),
    };

    Ok(opendal::services::AzblobConfig {
        endpoint: Some(endpoint),
        account_name: Some(account.as_str().to_string()),
        container: container.as_str().to_string(),
        root: Some(root),
        account_key,
        sas_token,
        ..Default::default()
    })
}

#[cfg(feature = "clap")]
#[derive(Debug, thiserror::Error)]
pub enum AzureCliSasError {
    #[error("failed to compute the SAS expiry timestamp: {0}")]
    Expiry(String),

    #[error("could not resolve the Azure CLI (`az`) on PATH; install it and run `az login`")]
    AzResolve(#[source] which::Error),

    #[error("failed to run the Azure CLI (`az`)")]
    Spawn(#[source] std::io::Error),

    #[error("the Azure CLI failed to generate a user-delegation SAS (is `az login` current?): {0}")]
    CommandFailed(String),

    #[error("the Azure CLI returned an empty SAS token")]
    EmptyOutput,
}

/// Mint a short-lived user-delegation SAS for a container by shelling out to the
/// Azure CLI.
///
/// opendal's azblob backend accepts a shared account key or a SAS token, not an
/// AAD bearer token, so an `az login` session has to be converted into a SAS:
///
/// ```text
/// az storage container generate-sas --account-name <account> --name <container>
///     --permissions <permissions> --expiry <expiry> --auth-mode login --as-user
///     [--https-only] -o tsv
/// ```
///
/// `permissions` is the Azure SAS permission string (e.g. `"cw"`). The returned
/// token has no leading `?`. Requires `az` on `PATH` and a prior `az login`.
/// `--https-only` is passed only when `scheme` is https, since it would otherwise
/// make the SAS unusable against the host.
///
/// # Container-scope limitation
///
/// The minted SAS is container-scoped, not prefix-scoped, so a SAS for one channel
/// also grants rights over sibling channels in the same container. Prefix-scoping
/// would need a stored access policy, which this path does not create.
#[cfg(feature = "clap")]
pub async fn mint_user_delegation_sas(
    account: &AccountName,
    container: &ContainerName,
    permissions: &str,
    valid_for: std::time::Duration,
    scheme: AzureScheme,
) -> Result<SecretString, AzureCliSasError> {
    /// Slack for a client clock running up to two minutes slow, since the expiry
    /// is computed here and evaluated by Azure.
    const CLOCK_SKEW_HEADROOM: std::time::Duration = std::time::Duration::from_secs(120);

    let signed = jiff::SignedDuration::try_from(valid_for.saturating_add(CLOCK_SKEW_HEADROOM))
        .map_err(|err| AzureCliSasError::Expiry(err.to_string()))?;
    let expiry = jiff::Timestamp::now()
        .checked_add(signed)
        .map_err(|err| AzureCliSasError::Expiry(err.to_string()))?;
    // `az` expects an ISO-8601 UTC timestamp; keep second precision so the window
    // is not floored down to the enclosing whole minute.
    let expiry = expiry.strftime("%Y-%m-%dT%H:%M:%SZ").to_string();

    let mut command = az_command()?;

    let output = command
        .args(generate_sas_args(
            account,
            container,
            permissions,
            &expiry,
            scheme,
        ))
        .output()
        .await
        .map_err(AzureCliSasError::Spawn)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(AzureCliSasError::CommandFailed(stderr));
    }

    let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if token.is_empty() {
        return Err(AzureCliSasError::EmptyOutput);
    }
    Ok(token.into())
}

#[cfg(feature = "clap")]
fn generate_sas_args<'a>(
    account: &'a AccountName,
    container: &'a ContainerName,
    permissions: &'a str,
    expiry: &'a str,
    scheme: AzureScheme,
) -> Vec<&'a str> {
    let mut args = vec![
        "storage",
        "container",
        "generate-sas",
        "--account-name",
        account.as_str(),
        "--name",
        container.as_str(),
        "--permissions",
        permissions,
        "--expiry",
        expiry,
        "--auth-mode",
        "login",
        "--as-user",
    ];
    if let AzureScheme::Https = scheme {
        args.push("--https-only");
    }
    args.extend(["-o", "tsv"]);
    args
}

/// Build the [`tokio::process::Command`] used to invoke the Azure CLI.
///
/// `which` resolves `az` up front, which matters on Windows: the CLI is an
/// `az.cmd` batch shim and the process spawner does not honor `PATHEXT`. The
/// resolved path is invoked directly rather than through `cmd /C`, which would be
/// an argument-injection vector.
#[cfg(feature = "clap")]
fn az_command() -> Result<tokio::process::Command, AzureCliSasError> {
    let path = which::which("az").map_err(AzureCliSasError::AzResolve)?;
    Ok(tokio::process::Command::new(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel(url: &str) -> AzureChannelUrl {
        AzureChannelUrl::parse(url).unwrap_or_else(|err| panic!("{url} should parse: {err}"))
    }

    fn coordinates(account: &str, container: &str) -> AzureCoordinates {
        AzureCoordinates {
            account: AccountName::new(account).expect("test account name"),
            container: ContainerName::new(container).expect("test container name"),
        }
    }

    #[test]
    fn normal_url_resolves() {
        assert_eq!(
            account_and_container(
                &channel("az://acct.blob.core.windows.net/general/noarch"),
                Addressing::HostStyle
            )
            .unwrap(),
            coordinates("acct", "general")
        );
    }

    /// The fetch path must find the same container `account_and_container` does
    /// under both styles, without inheriting its account rules: a host-style IP
    /// literal has no account label but still has a container.
    #[test]
    fn container_is_derived_from_the_addressing() {
        for (url, addressing, expected) in [
            (
                "az://acct.blob.core.windows.net/general/noarch",
                Addressing::HostStyle,
                "general",
            ),
            (
                "az://127.0.0.1:10000/devstoreaccount1/general/noarch",
                Addressing::PathStyle,
                "general",
            ),
            (
                "az://127.0.0.1:10000/general/noarch",
                Addressing::HostStyle,
                "general",
            ),
        ] {
            assert_eq!(
                container(&channel(url), addressing).unwrap(),
                Some(ContainerName::new(expected).unwrap()),
                "{url}"
            );
        }

        // Where both derivations answer, they must answer the same thing: a grant
        // looked up for one container and applied to another is a security bug.
        for (url, addressing) in [
            (
                "az://acct.blob.core.windows.net/general/noarch",
                Addressing::HostStyle,
            ),
            (
                "az://127.0.0.1:10000/devstoreaccount1/general",
                Addressing::PathStyle,
            ),
        ] {
            assert_eq!(
                container(&channel(url), addressing).unwrap(),
                Some(
                    account_and_container(&channel(url), addressing)
                        .unwrap()
                        .container
                ),
                "{url}"
            );
        }
    }

    #[test]
    fn a_url_without_a_container_names_none() {
        for (url, addressing) in [
            ("az://acct.blob.core.windows.net", Addressing::HostStyle),
            ("az://acct.blob.core.windows.net/", Addressing::HostStyle),
            (
                "az://127.0.0.1:10000/devstoreaccount1",
                Addressing::PathStyle,
            ),
            ("az://127.0.0.1:10000/", Addressing::PathStyle),
        ] {
            assert_eq!(container(&channel(url), addressing).unwrap(), None, "{url}");
        }
    }

    #[test]
    fn a_url_with_an_unusable_container_is_an_error() {
        for url in [
            "az://acct.blob.core.windows.net/General/noarch",
            "az://acct.blob.core.windows.net/ab/noarch",
            "az://acct.blob.core.windows.net/a--b/noarch",
        ] {
            let err = container(&channel(url), Addressing::HostStyle)
                .expect_err("an illegal container name must be reported");
            assert!(
                matches!(err, AzureUrlError::InvalidContainerName(_)),
                "{url}: {err}"
            );
        }
    }

    #[test]
    fn userinfo_is_rejected() {
        assert!(matches!(
            AzureChannelUrl::parse("az://acct.blob.core.windows.net@evil.example/general"),
            Err(AzureUrlError::UserInfoNotAllowed)
        ));
        assert!(matches!(
            AzureHost::parse("acct.blob.core.windows.net@evil.example"),
            Err(AzureUrlError::UserInfoNotAllowed)
        ));
    }

    /// Azure's naming rules keep injection-shaped values out of the `az`
    /// subprocess, so they must hold under path-style too, where the account comes
    /// from user-controlled path text.
    #[test]
    fn invalid_component_names_are_rejected_under_both_styles() {
        assert!(matches!(
            account_and_container(
                &channel("az://acct.blob.core.windows.net/general;evil/noarch"),
                Addressing::HostStyle
            ),
            Err(AzureUrlError::InvalidContainerName(_))
        ));

        for (path, account_at_fault) in [
            ("az://127.0.0.1:10000/devstore;evil/general", true),
            ("az://127.0.0.1:10000/DevStoreAccount1/general", true),
            // Azure allows no hyphen at all in an account name.
            ("az://127.0.0.1:10000/dev-store/general", true),
            // Too short for Azure, whatever the charset says.
            ("az://127.0.0.1:10000/ab/general", true),
            ("az://127.0.0.1:10000/devstoreaccount1/general;evil", false),
            ("az://127.0.0.1:10000/devstoreaccount1/ab", false),
            ("az://127.0.0.1:10000/devstoreaccount1/a--b", false),
            ("az://127.0.0.1:10000/devstoreaccount1/-general", false),
            ("az://127.0.0.1:10000/devstoreaccount1/general-", false),
        ] {
            let Err(err) = account_and_container(&channel(path), Addressing::PathStyle) else {
                panic!("expected a rejection for {path}");
            };
            let matched = if account_at_fault {
                matches!(err, AzureUrlError::InvalidAccountName(_))
            } else {
                matches!(err, AzureUrlError::InvalidContainerName(_))
            };
            assert!(matched, "unexpected error for {path}: {err}");
        }
    }

    /// A charset of `[a-z0-9-]` alone does not keep option-shaped values out of
    /// the `az` argv, because a leading `-` is inside it.
    #[test]
    fn option_shaped_components_are_rejected() {
        for (url, account_at_fault) in [
            ("az://--as-user.blob.core.windows.net/general", true),
            ("az://-o.blob.core.windows.net/general", true),
            ("az://acct.blob.core.windows.net/--https-only/noarch", false),
            ("az://acct.blob.core.windows.net/-o/noarch", false),
        ] {
            let Err(err) = account_and_container(&channel(url), Addressing::HostStyle) else {
                panic!("expected a rejection for {url}");
            };
            let matched = if account_at_fault {
                matches!(err, AzureUrlError::InvalidAccountName(_))
            } else {
                matches!(err, AzureUrlError::InvalidContainerName(_))
            };
            assert!(matched, "unexpected error for {url}: {err}");
        }
    }

    #[test]
    fn empty_components_are_rejected() {
        assert!(AccountName::new("").is_err());
        assert!(ContainerName::new("").is_err());
    }

    #[test]
    fn path_style_derives_account_from_first_segment() {
        for host in [
            "127.0.0.1:10000",
            "[::1]:10000",
            "azurite:10000",
            "localhost:10000",
            "azurite",
            "localhost",
        ] {
            assert_eq!(
                account_and_container(
                    &channel(&format!("az://{host}/devstoreaccount1/general/noarch")),
                    Addressing::PathStyle
                )
                .unwrap(),
                coordinates("devstoreaccount1", "general"),
                "path-style derivation failed for {host}"
            );
        }
    }

    #[test]
    fn path_style_needs_two_segments() {
        assert!(matches!(
            account_and_container(
                &channel("az://127.0.0.1:10000/devstoreaccount1"),
                Addressing::PathStyle
            ),
            Err(AzureUrlError::NoContainer)
        ));

        for empty in ["az://127.0.0.1:10000/", "az://127.0.0.1:10000"] {
            assert!(matches!(
                account_and_container(&channel(empty), Addressing::PathStyle),
                Err(AzureUrlError::NoAccount)
            ));
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn path_style_on_a_real_azure_host_warns_and_proceeds() {
        let coords = account_and_container(
            &channel("az://acct.blob.core.windows.net/general/mychannel"),
            Addressing::PathStyle,
        )
        .expect("addressing is the user's call, so this is a warning and not an error");
        assert_eq!(coords.account.as_str(), "general");

        assert!(logs_contain("path-style = true"));
        assert!(logs_contain("acct.blob.core.windows.net"));

        let coords = account_and_container(
            &channel("az://acct.blob.example.com/devstoreaccount1/general"),
            Addressing::PathStyle,
        )
        .unwrap();
        assert_eq!(coords.account.as_str(), "devstoreaccount1");
        assert!(!logs_contain("acct.blob.example.com"));
    }

    /// A sloppy suffix match would warn about hosts Microsoft does not operate and
    /// stay silent on ones it does.
    #[test]
    fn known_azure_endpoints_are_matched_on_a_label_boundary() {
        for host in [
            "acct.blob.core.windows.net",
            "acct.blob.core.usgovcloudapi.net",
            "acct.blob.core.chinacloudapi.cn",
        ] {
            assert!(
                AzureHost::parse(host)
                    .unwrap()
                    .is_known_azure_blob_endpoint(),
                "{host}"
            );
        }

        for host in [
            "notblob.core.windows.net",             // no label boundary
            "blob.core.windows.net",                // the suffix alone carries no account
            "acct.blob.core.windows.net.evil.test", // suffix in the middle
            "127.0.0.1:10000",
            "azurite",
        ] {
            assert!(
                !AzureHost::parse(host)
                    .unwrap()
                    .is_known_azure_blob_endpoint(),
                "{host}"
            );
        }
    }

    /// Host-style must reject hosts it cannot derive an account from, and the
    /// rejection must name a config key that would actually match: port included,
    /// host spelled the way [`AzureHost`] spells it.
    #[test]
    fn host_style_rejects_undottable_hosts_with_a_guided_error() {
        for (host, expected_key) in [
            ("127.0.0.1:10000", "127.0.0.1:10000"),
            ("azurite:10000", "azurite:10000"),
            ("localhost", "localhost"),
            ("[::1]:10000", "[::1]:10000"),
            // A trailing dot is the DNS root label, not a second label: this host
            // must not sneak past the dotted-domain gate.
            ("localhost.", "localhost"),
            ("LocalHost", "localhost"),
            // A port equal to a wire scheme's default: it is part of the key, and
            // only survives because the channel — not a `Url` — is what is read.
            ("azurite:443", "azurite:443"),
            ("azurite:80", "azurite:80"),
        ] {
            let channel = channel(&format!("az://{host}/devstoreaccount1/general"));
            let err = account_and_container(&channel, Addressing::HostStyle)
                .expect_err("host-style must not accept an undottable host");
            assert!(matches!(err, AzureUrlError::InvalidHost(_)), "{err}");

            let message = err.to_string();
            assert!(message.contains("path-style = true"), "{message}");
            let key = format!("[azure-options.\"{expected_key}\"]");
            assert!(message.contains(&key), "{message}");
            assert_eq!(expected_key, channel.host().to_string(), "{host}");
        }
    }

    #[test]
    fn empty_host_labels_are_rejected() {
        for host in [
            "acct..blob.core.windows.net",
            "acct.blob.example..",
            ".example",
        ] {
            assert!(
                matches!(
                    AzureHost::parse(host),
                    Err(AzureUrlError::InvalidHostAuthority { .. })
                ),
                "expected a rejection for {host}"
            );
            assert!(
                matches!(
                    AzureChannelUrl::parse(&format!("az://{host}/general/noarch")),
                    Err(AzureUrlError::InvalidHostAuthority { .. })
                ),
                "expected a rejection for {host}"
            );
        }
    }

    #[test]
    fn parse_requires_the_az_scheme() {
        for input in [
            "https://acct.blob.core.windows.net/general",
            "http://acct.blob.core.windows.net/general",
            "ftp://acct.blob.core.windows.net/general",
            "acct.blob.core.windows.net/general",
        ] {
            assert!(
                matches!(
                    AzureChannelUrl::parse(input),
                    Err(AzureUrlError::InvalidScheme(_))
                ),
                "expected InvalidScheme for {input}"
            );
        }
    }

    #[test]
    fn parse_accepts_a_scheme_in_any_case() {
        for input in [
            "AZ://acct.blob.core.windows.net/general",
            "Az://acct.blob.core.windows.net/general",
            "aZ://acct.blob.core.windows.net/general",
        ] {
            let channel = AzureChannelUrl::parse(input)
                .unwrap_or_else(|err| panic!("{input} should parse: {err}"));
            assert_eq!(
                channel.canonical().as_str(),
                "az://acct.blob.core.windows.net/general"
            );
        }
    }

    #[test]
    fn canonical_and_wire_round_trip() {
        let channel =
            AzureChannelUrl::parse("az://acct.blob.core.windows.net/general/noarch").unwrap();

        assert_eq!(
            channel.canonical().as_str(),
            "az://acct.blob.core.windows.net/general/noarch"
        );
        assert_eq!(
            channel.wire(AzureScheme::Https).as_str(),
            "https://acct.blob.core.windows.net/general/noarch"
        );
        assert_eq!(
            channel.wire(AzureScheme::Http).as_str(),
            "http://acct.blob.core.windows.net/general/noarch"
        );
        assert_eq!(channel.to_string(), channel.canonical().to_string());
        assert_eq!(
            channel,
            channel
                .canonical()
                .as_str()
                .parse::<AzureChannelUrl>()
                .unwrap()
        );
    }

    #[test]
    fn spellings_cannot_disagree() {
        for input in [
            "az://acct.blob.core.windows.net/general/noarch",
            "az://127.0.0.1:10000/devstoreaccount1/general",
            "az://acct.blob.core.windows.net/general/with%20space?sv=token",
            // An IPv6 literal is the host shape most likely to break the canonical
            // rebuild, since it has to survive being re-parsed as an opaque host.
            "az://[::1]:10000/devstoreaccount1/general",
            // The scheme-default ports: exactly the spellings a `Url` stored with a
            // fixed scheme silently drops.
            "az://azurite.local:443/devstoreaccount1/general",
            "az://azurite.local:80/devstoreaccount1/general",
        ] {
            let channel = AzureChannelUrl::parse(input).unwrap();
            let canonical = channel.canonical();
            for scheme in [AzureScheme::Https, AzureScheme::Http] {
                let wire = channel.wire(scheme);
                assert_eq!(wire.scheme(), scheme.as_str());
                assert_eq!(canonical.host_str(), wire.host_str(), "{input}");
                assert_eq!(canonical.path(), wire.path(), "{input}");
                assert_eq!(canonical.query(), wire.query(), "{input}");

                // Ports are compared semantically, not textually: `az` has no
                // default port so the canonical form always spells one out when the
                // URL has one, while a wire URL omits a port equal to its scheme's
                // default. An omitted port on `http` *is* 80, so those agree.
                let default = match scheme {
                    AzureScheme::Https => 443,
                    AzureScheme::Http => 80,
                };
                assert_eq!(
                    wire.port_or_known_default(),
                    Some(canonical.port().unwrap_or(default)),
                    "{input} over {scheme}"
                );
            }
        }
    }

    /// The `:443` regression: a wire URL stored with the `https` scheme drops this
    /// port, and `wire(Http)` then names a completely different endpoint.
    #[test]
    fn a_written_default_port_survives() {
        let channel =
            AzureChannelUrl::parse("az://azurite.local:443/devstoreaccount1/general").unwrap();

        assert_eq!(channel.host().to_string(), "azurite.local:443");
        assert_eq!(channel.host().port(), Some(443));
        assert_eq!(
            channel.canonical().as_str(),
            "az://azurite.local:443/devstoreaccount1/general"
        );
        assert_eq!(
            channel.wire(AzureScheme::Http).as_str(),
            "http://azurite.local:443/devstoreaccount1/general"
        );
        assert_eq!(
            channel.wire(AzureScheme::Https).as_str(),
            "https://azurite.local/devstoreaccount1/general"
        );

        // Identity must not be scheme-relative either: a host on 443 is not the
        // same endpoint as the same host with no port, because the scheme that
        // would make them equal is not known here.
        let no_port =
            AzureChannelUrl::parse("az://azurite.local/devstoreaccount1/general").unwrap();
        assert_ne!(channel, no_port);
        assert_ne!(channel.host(), no_port.host());
    }

    #[test]
    fn host_keeps_a_non_default_port() {
        let emulator =
            AzureChannelUrl::parse("az://127.0.0.1:10000/devstoreaccount1/general").unwrap();
        assert_eq!(emulator.host().to_string(), "127.0.0.1:10000");
        assert_eq!(
            emulator.wire(AzureScheme::Http).as_str(),
            "http://127.0.0.1:10000/devstoreaccount1/general"
        );
        assert_eq!(
            emulator.canonical().as_str(),
            "az://127.0.0.1:10000/devstoreaccount1/general"
        );

        // No port written, none invented.
        let azure = AzureChannelUrl::parse("az://acct.blob.core.windows.net/general").unwrap();
        assert_eq!(azure.host().to_string(), "acct.blob.core.windows.net");
        assert_eq!(azure.host().port(), None);
    }

    /// A written config key and a looked-up host disagree unless both go through
    /// this parser. These are the classes it has to collapse.
    #[test]
    fn host_normalization_collapses_equivalent_spellings() {
        for (written, canonical) in [
            (
                "MyCompany.blob.core.windows.net",
                "mycompany.blob.core.windows.net",
            ),
            (
                "mycompany.blob.core.windows.net:443",
                "mycompany.blob.core.windows.net:443",
            ),
            ("ünï.blob.example", "xn--n-nga1b.blob.example"),
            ("xn--n-nga1b.blob.example", "xn--n-nga1b.blob.example"),
            ("[0:0:0:0:0:0:0:1]:10000", "[::1]:10000"),
            ("[::1]:10000", "[::1]:10000"),
            ("0x7f.1", "127.0.0.1"),
            ("127.0.0.1", "127.0.0.1"),
            ("acct.blob.core.windows.net.", "acct.blob.core.windows.net"),
            ("acct.blob.core.windows.net", "acct.blob.core.windows.net"),
        ] {
            let host = AzureHost::parse(written)
                .unwrap_or_else(|err| panic!("{written} should parse: {err}"));
            assert_eq!(host.to_string(), canonical, "{written}");

            // Display and parse round-trip, so a key written out of an `AzureHost`
            // parses back to the same host…
            let reparsed = AzureHost::parse(canonical).unwrap();
            assert_eq!(reparsed, host, "{written}");
            // …and equal hosts hash equally, so they land on the same map entry.
            assert_eq!(hash_of(&host), hash_of(&reparsed), "{written}");
        }
    }

    #[test]
    fn host_equality_is_not_scheme_relative() {
        let with_port = AzureHost::parse("azurite.local:443").unwrap();
        let without = AzureHost::parse("azurite.local").unwrap();
        assert_ne!(with_port, without);
        assert_ne!(with_port, AzureHost::parse("azurite.local:80").unwrap());
        assert_eq!(with_port.to_string(), "azurite.local:443");
    }

    #[test]
    fn host_rejects_anything_that_is_not_a_bare_authority() {
        // A name DNS cannot resolve and a port nothing can connect to: `wire()`
        // would otherwise hand out `https://host:0/…`, and a bare `host:` would be
        // silently read as the portless host, a different endpoint entirely.
        // Labels of 60, so length is the only rule under test.
        let label = "a".repeat(60);
        let too_long = format!("{}.blob.example", [label.as_str(); 8].join("."));
        for authority in [
            "acct.blob.core.windows.net/general",
            "acct.blob.core.windows.net?sv=token",
            "acct.blob.core.windows.net#frag",
            "https://acct.blob.core.windows.net",
            "",
            "acct.blob.core.windows.net:notaport",
            "acct.blob.core.windows.net:",
            "acct.blob.core.windows.net:0",
            "[::1]:",
            "[::1]:0",
            &too_long,
        ] {
            assert!(
                AzureHost::parse(authority).is_err(),
                "expected a rejection for {authority:?}"
            );
        }

        // A name right at the limit still parses, so the check bounds the length
        // rather than the number of labels.
        let at_limit = format!(
            "{}.{}.blob.example",
            [label.as_str(); 3].join("."),
            "a".repeat(57)
        );
        assert_eq!(at_limit.len(), 253);
        assert!(AzureHost::parse(&at_limit).is_ok());
    }

    fn hash_of(host: &AzureHost) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        host.hash(&mut hasher);
        hasher.finish()
    }

    /// Asserted string by string, because every field but `container` differs from
    /// host-style and each fails silently when wrong: a missing `account_name` is a
    /// 403, a stray slash gives `//container/…`, a short `root` writes the channel
    /// one directory too deep.
    #[cfg(feature = "opendal")]
    #[test]
    fn azblob_config_under_path_style() {
        let channel =
            AzureChannelUrl::parse("az://127.0.0.1:10000/devstoreaccount1/general/mychannel")
                .unwrap();
        let config = azblob_config(
            &AzureCredentials::AccountKey("key".into()),
            &channel,
            AzureEndpoint {
                scheme: AzureScheme::Http,
                addressing: Addressing::PathStyle,
            },
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

        let endpoint = config.endpoint.unwrap();
        assert!(!endpoint.ends_with('/'), "{endpoint}");
        let root = config.root.unwrap();
        assert!(
            !root.contains("general"),
            "the container must not appear in the root: {root}"
        );
        assert!(
            !root.contains("devstoreaccount1"),
            "the account must not appear in the root: {root}"
        );
    }

    /// A bare `account/container` leaves nothing for the root, which must still be
    /// `/`, not the empty string opendal treats as a relative path.
    #[cfg(feature = "opendal")]
    #[test]
    fn azblob_config_path_style_without_a_prefix() {
        let channel =
            AzureChannelUrl::parse("az://127.0.0.1:10000/devstoreaccount1/general").unwrap();
        let config = azblob_config(
            &AzureCredentials::SasToken("?sv=token".into()),
            &channel,
            AzureEndpoint {
                scheme: AzureScheme::Http,
                addressing: Addressing::PathStyle,
            },
        )
        .unwrap();

        assert_eq!(config.root.as_deref(), Some("/"));
        assert_eq!(config.container, "general");
        assert_eq!(config.sas_token.as_deref(), Some("sv=token"));
    }

    #[cfg(feature = "opendal")]
    #[test]
    fn azblob_config_under_host_style_is_unchanged() {
        let channel =
            AzureChannelUrl::parse("az://stcondachannel.blob.core.windows.net/general/sub/dir")
                .unwrap();
        let config = azblob_config(
            &AzureCredentials::SasToken("sv=token".into()),
            &channel,
            AzureEndpoint::default(),
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

    #[cfg(feature = "opendal")]
    #[test]
    fn azblob_config_decodes_the_root() {
        let channel =
            AzureChannelUrl::parse("az://acct.blob.core.windows.net/general/with%20space").unwrap();
        let config = azblob_config(
            &AzureCredentials::AccountKey("key".into()),
            &channel,
            AzureEndpoint::default(),
        )
        .unwrap();

        assert_eq!(config.root.as_deref(), Some("/with space"));
    }

    #[test]
    fn parse_defers_account_derivation() {
        let channel = channel("az://127.0.0.1:10000/devstoreaccount1/general");

        assert!(account_and_container(&channel, Addressing::HostStyle).is_err());
        assert!(account_and_container(&channel, Addressing::PathStyle).is_ok());
    }

    /// Under path-style the rewrite moves the *account* too, so a channel URL that
    /// says `devstoreaccount1` mints a SAS for whatever the escaped `..` climbs
    /// out to.
    #[test]
    fn a_rewritten_path_is_rejected() {
        for input in [
            "az://acct.blob.core.windows.net/general/%2e%2e/%2e%2e/othercontainer/x",
            "az://127.0.0.1:10000/devstoreaccount1/general/%2e%2e/%2e%2e/otheraccount/othercontainer",
            "az://acct.blob.core.windows.net/general/../../othercontainer",
            "az://acct.blob.core.windows.net/general/./noarch",
            // A dot segment behind an encoded slash still climbs, because the
            // decode happens before the comparison.
            "az://acct.blob.core.windows.net/general/%2E%2E/othercontainer",
        ] {
            assert!(
                matches!(
                    AzureChannelUrl::parse(input),
                    Err(AzureUrlError::DotSegmentInPath(_))
                ),
                "expected a rejection for {input}"
            );
        }
    }

    /// The container is what a grant is spent on, so an empty leading segment must
    /// not read as "no container" — that fetches a private container anonymously
    /// and reports the 404 as a missing channel.
    #[test]
    fn an_empty_segment_is_rejected() {
        for input in [
            "az://acct.blob.core.windows.net//general/noarch",
            "az://acct.blob.core.windows.net/general//noarch",
            "az://127.0.0.1:10000//devstoreaccount1/general",
        ] {
            assert!(
                matches!(
                    AzureChannelUrl::parse(input),
                    Err(AzureUrlError::EmptyPathSegment { .. })
                ),
                "expected a rejection for {input}"
            );
        }

        // A trailing slash is a trailing slash, not an empty segment.
        assert_eq!(
            channel("az://acct.blob.core.windows.net/general/")
                .canonical()
                .path(),
            "/general/"
        );
    }

    /// A lone `%` decodes to itself, so the fetch path would send it raw while
    /// opendal re-encodes the decoded form to `%25` and indexes a different blob.
    #[test]
    fn a_malformed_percent_escape_is_rejected() {
        for input in [
            "az://acct.blob.core.windows.net/general/gen%eral",
            "az://acct.blob.core.windows.net/general/100%",
            "az://acct.blob.core.windows.net/general/%zz",
        ] {
            assert!(
                matches!(
                    AzureChannelUrl::parse(input),
                    Err(AzureUrlError::MalformedPercentEscape { .. })
                ),
                "expected a rejection for {input}"
            );
        }
    }

    /// Rejecting rewrites must not narrow what an ordinary channel URL can say.
    #[test]
    fn unrewritten_paths_still_parse() {
        for (input, path) in [
            (
                "az://acct.blob.core.windows.net/general/prefix",
                "/general/prefix",
            ),
            ("az://acct.blob.core.windows.net/general/", "/general/"),
            ("az://acct.blob.core.windows.net/", "/"),
            ("az://acct.blob.core.windows.net", "/"),
            (
                "az://acct.blob.core.windows.net/general/with%20space",
                "/general/with%20space",
            ),
            (
                "az://acct.blob.core.windows.net/general/p?sv=token#frag",
                "/general/p",
            ),
            // A dot inside a segment is not a dot segment.
            (
                "az://acct.blob.core.windows.net/general/..hidden/...",
                "/general/..hidden/...",
            ),
        ] {
            assert_eq!(channel(input).canonical().path(), path, "{input}");
        }
    }

    #[test]
    fn segments_that_cannot_name_a_blob_are_rejected() {
        assert!(matches!(
            AzureChannelUrl::parse("az://acct.blob.core.windows.net/general/%ff"),
            Err(AzureUrlError::NonUtf8Path { .. })
        ));

        // An encoded slash past the container is a blob name containing a slash,
        // which Azure supports. It cannot move the container: `container()` reads a
        // separate raw segment, and `ContainerName`'s charset admits neither `/`
        // nor `%`, so the boundary is held by the type rather than by banning the
        // escape everywhere.
        for input in [
            "az://acct.blob.core.windows.net/general/a%2Fb",
            "az://acct.blob.core.windows.net/general/a%2fb",
        ] {
            let parsed = channel(input);
            assert_eq!(
                container(&parsed, Addressing::HostStyle).unwrap(),
                Some(ContainerName::new("general").unwrap()),
                "{input}"
            );
        }

        // Unencoded UTF-8 and spaces are the user's to write; we encode them.
        for (input, path) in [
            (
                "az://acct.blob.core.windows.net/general/café",
                "/general/caf%C3%A9",
            ),
            (
                "az://acct.blob.core.windows.net/general/with space",
                "/general/with%20space",
            ),
        ] {
            assert_eq!(channel(input).canonical().path(), path, "{input}");
        }

        assert_eq!(
            channel("az://acct.blob.core.windows.net/general/caf%C3%A9")
                .canonical()
                .path(),
            "/general/caf%C3%A9"
        );
    }

    #[cfg(feature = "clap")]
    #[test]
    fn https_only_follows_the_configured_scheme() {
        let coordinates = coordinates("acct", "general");
        let args = |scheme| {
            generate_sas_args(
                &coordinates.account,
                &coordinates.container,
                "cw",
                "2030-01-01T00:00:00Z",
                scheme,
            )
        };

        assert!(args(AzureScheme::Https).contains(&"--https-only"));
        assert!(!args(AzureScheme::Http).contains(&"--https-only"));

        for scheme in [AzureScheme::Https, AzureScheme::Http] {
            let args = args(scheme);
            assert!(args.windows(2).any(|pair| pair == ["--permissions", "cw"]));
            assert!(
                args.windows(2)
                    .any(|pair| pair == ["--expiry", "2030-01-01T00:00:00Z"])
            );
            assert!(args.contains(&"--as-user"));
            assert!(args.windows(2).any(|pair| pair == ["--auth-mode", "login"]));
        }
    }
}

#[cfg(test)]
mod debug_redaction_tests {
    use super::*;

    #[test]
    fn debug_never_prints_secret() {
        for creds in [
            AzureCredentials::AccountKey("supersecretkey".into()),
            AzureCredentials::SasToken("sig=deadbeef".into()),
        ] {
            let out = format!("{creds:?}");
            assert!(out.contains("REDACTED"), "not redacted: {out}");
            assert!(!out.contains("supersecret"));
            assert!(!out.contains("deadbeef"));
        }
    }

    /// An inline SAS reaches the wire and nothing else. Every other spelling ends
    /// up in a log line or an error message.
    #[test]
    fn only_the_wire_spelling_carries_the_signature() {
        let channel = AzureChannelUrl::parse(
            "az://acct.blob.core.windows.net/general/p?sv=2024-11-04&sig=SECRETSIG&se=z",
        )
        .unwrap();

        for shown in [
            channel.canonical().to_string(),
            channel.to_string(),
            format!("{channel:?}"),
        ] {
            assert!(!shown.contains("SECRETSIG"), "signature leaked: {shown}");
            assert!(shown.contains("sv=2024-11-04"), "over-redacted: {shown}");
            assert!(shown.contains("se=z"), "over-redacted: {shown}");
        }

        // A `sig` is no less a signature for having been written after a `#`, and
        // the fragment reaches every printed spelling the query does.
        let fragmented =
            AzureChannelUrl::parse("az://acct.blob.core.windows.net/general/p?sv=1#sig=SECRETFRAG")
                .unwrap();
        for shown in [
            fragmented.canonical().to_string(),
            fragmented.to_string(),
            format!("{fragmented:?}"),
        ] {
            assert!(!shown.contains("SECRETFRAG"), "signature leaked: {shown}");
        }

        assert!(
            channel
                .wire(AzureScheme::Https)
                .to_string()
                .contains("sig=SECRETSIG"),
            "the wire spelling must keep the signature that authenticates the request"
        );
    }
}
