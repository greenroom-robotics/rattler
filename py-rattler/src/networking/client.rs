use crate::{
    error::PyRattlerError,
    networking::middleware::{AddHeadersMiddleware, PyMiddleware},
};
use pyo3::{PyResult, exceptions::PyValueError, pyclass, pymethods};
use rattler_networking::{
    AuthenticationMiddleware, AuthenticationStorage, AzureMiddleware, GCSMiddleware, LazyClient,
    MirrorMiddleware, OciMiddleware, S3Middleware,
};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest_middleware::ClientWithMiddleware;
use reqwest_retry::RetryTransientMiddleware;
use reqwest_retry::policies::ExponentialBackoff;
use std::collections::HashMap;

static RATTLER_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

#[pyclass(from_py_object)]
#[repr(transparent)]
#[derive(Clone)]
pub struct PyClientWithMiddleware {
    pub(crate) inner: ClientWithMiddleware,
}

/// `AzureMiddleware` may not precede `AuthenticationMiddleware`.
///
/// `AuthenticationMiddleware` skips any URL whose scheme is not `http` or
/// `https`, because its entries are keyed by host alone and `az://` carries its
/// own grant model. `AzureMiddleware` rewrites `az://` to `https://` before it
/// calls the rest of the stack. Put the azure middleware first and that gate
/// never sees an `az://` URL, so a stored `*.blob.core.windows.net` credential
/// attaches to a container that was never granted one.
fn check_middleware_order(middlewares: &[PyMiddleware]) -> PyResult<()> {
    let azure = middlewares
        .iter()
        .position(|m| matches!(m, PyMiddleware::Azure(_)));
    let authentication = middlewares
        .iter()
        .position(|m| matches!(m, PyMiddleware::Authentication(_)));

    match (azure, authentication) {
        (Some(azure), Some(authentication)) if azure < authentication => {
            Err(PyValueError::new_err(
                "AzureMiddleware must come after AuthenticationMiddleware. AzureMiddleware rewrites \
             `az://` URLs to `https://`, and AuthenticationMiddleware ignores URLs that are not \
             already http(s), so this order would let a stored `*.blob.core.windows.net` \
             credential attach to a container that has no `azure-options` grant. Write \
             `Client([AuthenticationMiddleware(), AzureMiddleware()])` instead.",
            ))
        }
        _ => Ok(()),
    }
}

#[pymethods]
impl PyClientWithMiddleware {
    /// Build a client from `middlewares`, applied in the order given.
    ///
    /// The one order this rejects is `AzureMiddleware` ahead of
    /// `AuthenticationMiddleware`; see [`check_middleware_order`].
    #[new]
    #[pyo3(signature = (middlewares=None, headers=None, user_agent=None, timeout=None))]
    pub fn new(
        middlewares: Option<Vec<PyMiddleware>>,
        headers: Option<HashMap<String, String>>,
        user_agent: Option<String>,
        timeout: Option<u64>,
    ) -> PyResult<Self> {
        let middlewares = middlewares.unwrap_or_default();
        check_middleware_order(&middlewares)?;

        let mut client_builder = reqwest::Client::builder();

        if let Some(timeout) = timeout {
            client_builder = client_builder.timeout(std::time::Duration::from_secs(timeout));
        }

        let has_headers = headers.is_some();

        if let Some(headers) = headers {
            let mut header_map = HeaderMap::new();
            for (key, value) in headers {
                let header_name =
                    HeaderName::from_bytes(key.as_bytes()).map_err(PyRattlerError::from)?;
                let header_value = HeaderValue::from_str(&value).map_err(PyRattlerError::from)?;
                header_map.insert(header_name, header_value);
            }
            client_builder = client_builder.default_headers(header_map);
        }

        if let Some(user_agent) = user_agent {
            client_builder = client_builder.user_agent(user_agent);
        } else if !has_headers {
            client_builder = client_builder.user_agent(RATTLER_USER_AGENT);
        }

        let reqwest_client = client_builder.build().unwrap();
        let mut client = reqwest_middleware::ClientBuilder::new(reqwest_client.clone());

        for middleware in middlewares {
            match middleware {
                PyMiddleware::Mirror(middleware) => {
                    client = client.with(MirrorMiddleware::from(middleware));
                }
                PyMiddleware::Authentication(_) => {
                    client = client.with(
                        AuthenticationMiddleware::from_env_and_defaults()
                            .map_err(PyRattlerError::from)?,
                    );
                }
                PyMiddleware::Retry(middleware) => {
                    let policy = ExponentialBackoff::builder()
                        .build_with_max_retries(middleware.max_retries);
                    client = client.with(RetryTransientMiddleware::new_with_policy(policy));
                }
                PyMiddleware::Oci(_middleware) => {
                    client = client.with(
                        OciMiddleware::new(reqwest_client.clone()).with_authentication_storage(
                            AuthenticationStorage::from_env_and_defaults()
                                .map_err(PyRattlerError::from)?,
                        ),
                    );
                }
                PyMiddleware::Gcs(middleware) => {
                    client = client.with(GCSMiddleware::from(middleware));
                }
                PyMiddleware::Azure(_middleware) => {
                    client = client.with(AzureMiddleware::anonymous(reqwest_client.clone()));
                }
                PyMiddleware::S3(middleware) => {
                    client = client.with(S3Middleware::new(
                        middleware
                            .s3_config
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone().into()))
                            .collect(),
                        AuthenticationStorage::from_env_and_defaults()
                            .map_err(PyRattlerError::from)?,
                    ));
                }
                PyMiddleware::AddHeaders(middleware) => {
                    client = client.with(AddHeadersMiddleware::from(middleware));
                }
            }
        }
        let client = client.build();

        Ok(Self { inner: client })
    }
}

impl From<PyClientWithMiddleware> for ClientWithMiddleware {
    fn from(value: PyClientWithMiddleware) -> Self {
        value.inner
    }
}

impl From<PyClientWithMiddleware> for LazyClient {
    fn from(value: PyClientWithMiddleware) -> Self {
        LazyClient::from(value.inner)
    }
}
