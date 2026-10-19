//! Parsing Azure Blob channel URLs and minting short-lived credentials for them.
//!
//! # Channel URLs
//!
//! A channel is written `az://host[:port]/…` and parsed into an
//! [`AzureChannelUrl`], which validates and normalizes the spelling so
//! equivalent URLs compare equal.
//!
//! # Endpoints
//!
//! An [`AzureEndpointKey`] names a storage account either host-style
//! (`acct.blob.core.windows.net`) or path-style (`proxy.internal/acct`).
//! [`locate`] reads the key and container off a channel URL.

#[cfg(feature = "opendal")]
mod azblob;
mod channel_url;
#[cfg(feature = "clap")]
pub mod clap;
mod credentials;
mod endpoint_key;
mod error;
mod host;
mod location;
mod names;
pub mod options;
#[cfg(feature = "clap")]
mod sas;
#[cfg(test)]
mod test_support;

#[cfg(feature = "opendal")]
pub use azblob::azblob_config;
pub use channel_url::AzureChannelUrl;
pub use credentials::AzureCredentials;
pub use endpoint_key::{AccountHost, AccountPath, AzureEndpointKey};
pub use error::AzureUrlError;
pub use host::AzureHost;
pub use location::{AzureAddressing, AzureLocation, locate, locate_as};
pub use names::{AccountName, ContainerName};
pub use options::{Auth, AzureEndpointOptions, AzureFetchOptions, AzureScheme};
#[cfg(feature = "clap")]
pub use sas::{AzureCliSasError, mint_user_delegation_sas};
pub use secrecy::{ExposeSecret, SecretString};
