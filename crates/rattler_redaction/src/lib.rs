use std::borrow::Cow;

use url::Url;

/// A default string to use for redaction.
pub const DEFAULT_REDACTION_STR: &str = "********";

/// Query parameters holding the signature of a pre-signed URL, which is the
/// credential itself: `sig` for Azure SAS, `x-amz-signature` for S3/SigV4. The
/// rest of such a URL is inert without them and stays readable.
const SIGNATURE_PARAMS: &[&str] = &["sig", "x-amz-signature"];

/// Mask the signature of a pre-signed URL wherever one appears in `text`.
///
/// Takes text rather than a [`Url`] because that is the shape the leak has:
/// storage backends quote the request URL inside error messages.
pub fn redact_signatures_in_text<'a>(text: &'a str, redaction: &str) -> Cow<'a, str> {
    let mut out = String::new();
    let mut written = 0;

    for (separator, _) in text.char_indices().filter(|(_, c)| *c == '?' || *c == '&') {
        let pair = &text[separator + 1..];
        let Some(equals) = pair.find('=') else {
            continue;
        };
        if !SIGNATURE_PARAMS
            .iter()
            .any(|param| pair[..equals].eq_ignore_ascii_case(param))
        {
            continue;
        }

        let value = separator + 1 + equals + 1;
        let end = value
            + text[value..]
                .find(|c: char| c == '&' || c.is_whitespace() || "\"',)]}".contains(c))
                .unwrap_or(text.len() - value);
        if end == value || value < written {
            continue;
        }

        out.push_str(&text[written..value]);
        out.push_str(redaction);
        written = end;
    }

    if written == 0 {
        return Cow::Borrowed(text);
    }
    out.push_str(&text[written..]);
    Cow::Owned(out)
}

/// Anaconda channels are not always publicly available. This function checks if a URL contains a
/// secret by identifying whether it contains certain patterns. If it does, the function returns a
/// modified URL where any secret has been masked.
///
/// The `redaction` argument can be used to specify a custom string that should be used to replace
/// a secret. For consistency between application it is recommended to pass
/// [`DEFAULT_REDACTION_STR`].
///
/// # Example
///
/// ```rust
/// # use rattler_redaction::{redact_known_secrets_from_url, Redact, DEFAULT_REDACTION_STR};
/// # use url::Url;
///
/// let url = Url::parse("https://conda.anaconda.org/t/12345677/conda-forge/noarch/repodata.json").unwrap();
/// let redacted_url = redact_known_secrets_from_url(&url, DEFAULT_REDACTION_STR).unwrap_or(url.clone());
/// // or you can use the shorthand
/// let redacted_url = url.redact();
/// ```
pub fn redact_known_secrets_from_url(url: &Url, redaction: &str) -> Option<Url> {
    let mut url = url.clone();
    if url.password().is_some() {
        url.set_password(Some(redaction)).ok()?;
    }

    if let Some(query) = url.query()
        && let Cow::Owned(masked) = redact_signatures_in_text(&format!("?{query}"), redaction)
    {
        url.set_query(Some(&masked[1..]));
    }

    // A URL that cannot be a base has no path segments and so no `/t/<token>/`
    // to mask, but it may still have carried a signature above — returning `None`
    // here would throw that masking away, since callers fall back to the
    // unredacted URL.
    let token_prefixed = url.path_segments().is_some_and(|mut segments| {
        matches!((segments.next(), segments.next()), (Some("t"), Some(_)))
    });

    if token_prefixed {
        let remainder = url
            .path_segments()
            .into_iter()
            .flatten()
            .skip(2)
            .collect::<Vec<_>>();
        let mut redacted_path = format!(
            "t/{redaction}{separator}",
            separator = if remainder.is_empty() { "" } else { "/" },
        );

        for (idx, segment) in remainder.iter().enumerate() {
            redacted_path.push_str(segment);
            // if the original url ends with a slash, we need to add it to the redacted path
            if idx < remainder.len() - 1 {
                redacted_path.push('/');
            }
        }

        url.set_path(&redacted_path);
    }

    Some(url)
}

/// A trait to redact known secrets from a type.
pub trait Redact {
    /// Redacts any secrets from this instance.
    fn redact(self) -> Self;
}

#[cfg(feature = "reqwest-middleware")]
impl Redact for reqwest_middleware::Error {
    fn redact(self) -> Self {
        if let Some(url) = self.url() {
            let redacted_url = redact_known_secrets_from_url(url, DEFAULT_REDACTION_STR)
                .unwrap_or_else(|| url.clone());
            self.with_url(redacted_url)
        } else {
            self
        }
    }
}

#[cfg(feature = "reqwest")]
impl Redact for reqwest::Error {
    fn redact(self) -> Self {
        if let Some(url) = self.url() {
            let redacted_url = redact_known_secrets_from_url(url, DEFAULT_REDACTION_STR)
                .unwrap_or_else(|| url.clone());
            self.with_url(redacted_url)
        } else {
            self
        }
    }
}

impl Redact for Url {
    fn redact(self) -> Self {
        redact_known_secrets_from_url(&self, DEFAULT_REDACTION_STR).unwrap_or(self)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_redact_signatures_in_text() {
        let message = "unexpected status code 403, url=https://acct.blob.core.windows.net/c/p?sv=2025-01-05&se=2026-08-05T00%3A00Z&sig=aBcD%2Fefg%3D, op=stat";
        assert_eq!(
            redact_signatures_in_text(message, DEFAULT_REDACTION_STR),
            format!(
                "unexpected status code 403, url=https://acct.blob.core.windows.net/c/p?sv=2025-01-05&se=2026-08-05T00%3A00Z&sig={DEFAULT_REDACTION_STR}, op=stat"
            )
        );

        assert_eq!(
            redact_signatures_in_text(
                "https://b.s3.amazonaws.com/k?X-Amz-Credential=AK&X-Amz-Signature=deadbeef",
                "X"
            ),
            "https://b.s3.amazonaws.com/k?X-Amz-Credential=AK&X-Amz-Signature=X"
        );

        assert!(matches!(
            redact_signatures_in_text("https://prefix.dev/conda-forge?a=b", "X"),
            Cow::Borrowed(_)
        ));

        assert_eq!(
            redact_signatures_in_text("https://h/p?design=keep&sig=drop", "X"),
            "https://h/p?design=keep&sig=X"
        );

        assert_eq!(
            Url::from_str("https://acct.blob.core.windows.net/c/p?sv=2025-01-05&sig=secret")
                .unwrap()
                .redact()
                .to_string(),
            format!(
                "https://acct.blob.core.windows.net/c/p?sv=2025-01-05&sig={DEFAULT_REDACTION_STR}"
            )
        );
    }

    #[test]
    fn test_remove_known_secrets_from_url() {
        assert_eq!(
            redact_known_secrets_from_url(
                &Url::from_str(
                    "https://conda.anaconda.org/t/12345677/conda-forge/noarch/repodata.json"
                )
                .unwrap(),
                DEFAULT_REDACTION_STR
            ),
            Some(
                Url::from_str(
                    &format!("https://conda.anaconda.org/t/{DEFAULT_REDACTION_STR}/conda-forge/noarch/repodata.json")
                )
                .unwrap()
            )
        );

        // should stay as is
        assert_eq!(
            redact_known_secrets_from_url(
                &Url::from_str("https://conda.anaconda.org/conda-forge/noarch/repodata.json")
                    .unwrap(),
                "helloworld"
            )
            .unwrap(),
            Url::from_str("https://conda.anaconda.org/conda-forge/noarch/repodata.json").unwrap(),
        );

        let redacted = redact_known_secrets_from_url(
            &Url::from_str("https://user:secret@prefix.dev/conda-forge").unwrap(),
            DEFAULT_REDACTION_STR,
        )
        .unwrap();

        assert_eq!(
            redacted.to_string(),
            format!("https://user:{DEFAULT_REDACTION_STR}@prefix.dev/conda-forge")
        );

        let redacted = redact_known_secrets_from_url(
            &Url::from_str("https://user:secret@prefix.dev/conda-forge/").unwrap(),
            DEFAULT_REDACTION_STR,
        )
        .unwrap();

        assert_eq!(
            redacted.to_string(),
            format!("https://user:{DEFAULT_REDACTION_STR}@prefix.dev/conda-forge/")
        );
    }

    /// A URL with no path segments still has a signature worth masking, and
    /// callers fall back to the unredacted URL when this returns `None`.
    #[test]
    fn a_url_that_cannot_be_a_base_still_has_its_signature_masked() {
        let redacted = redact_known_secrets_from_url(
            &Url::from_str("az:container/repodata.json?sig=secret").unwrap(),
            DEFAULT_REDACTION_STR,
        )
        .expect("a signature must be masked even with no path segments to inspect");

        assert!(!redacted.to_string().contains("secret"), "{redacted}");
    }
}
