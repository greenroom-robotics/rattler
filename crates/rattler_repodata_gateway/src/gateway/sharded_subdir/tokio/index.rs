use std::{path::Path, str::FromStr, sync::Arc, time::SystemTime};

use super::{REPODATA_SHARDS_FILENAME, SHARDS_CACHE_SUFFIX, ShardedRepodata};
use crate::{
    GatewayError, Reporter,
    fetch::CacheAction,
    gateway::{
        error::SubdirNotFoundError,
        sharded_subdir::{decode_zst_bytes_async, is_missing_sharded_repodata_status},
    },
    reporter::{DownloadReporter, ResponseReporterExt},
    utils::url_to_cache_filename,
};
use async_fd_lock::{LockWrite, RwLockWriteGuard};
use bytes::Bytes;
use fs_err::tokio as tokio_fs;
use futures::{TryFutureExt, future::OptionFuture};
use http::{HeaderMap, Method, StatusCode, Uri, header};
use http_cache_semantics::{AfterResponse, BeforeRequest, CachePolicy, RequestLike};
use rattler_conda_types::Channel;
use rattler_networking::LazyClient;
use rattler_redaction::Redact;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use simple_spawn_blocking::tokio::run_blocking_task;
use tokio::{
    fs::File,
    io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, BufWriter},
};
use url::Url;

/// Creates a `SubdirNotFoundError` for when sharded repodata is not available.
fn create_subdir_not_found_error(channel_base_url: &Url) -> GatewayError {
    GatewayError::SubdirNotFoundError(Box::new(SubdirNotFoundError {
        channel: Channel::from_url(channel_base_url.clone()),
        subdir: channel_base_url
            .path_segments()
            .and_then(|mut s| s.next_back())
            .unwrap_or("unknown")
            .to_string(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "sharded repodata not found")
            .into(),
    }))
}

// Fetches the shard index from the url or read it from the cache.
pub async fn fetch_index(
    client: LazyClient,
    channel_base_url: &Url,
    cache_dir: &Path,
    cache_action: CacheAction,
    concurrent_requests_semaphore: Option<Arc<tokio::sync::Semaphore>>,
    reporter: Option<&dyn Reporter>,
) -> Result<ShardedRepodata, GatewayError> {
    async fn from_response(
        mut cache_file: RwLockWriteGuard<File>,
        cache_path: &Path,
        policy: CachePolicy,
        response: Response,
        reporter: Option<(&dyn DownloadReporter, usize)>,
        permit: Option<tokio::sync::SemaphorePermit<'_>>,
    ) -> Result<ShardedRepodata, GatewayError> {
        let response = response.error_for_status()?;
        if !response.status().is_success() {
            let mut url = response.url().clone().redact();
            url.set_query(None);
            url.set_fragment(None);
            let status = response.status();
            let body = response.text().await.ok();
            return Err(GatewayError::ReqwestMiddlewareError(anyhow::format_err!(
                "received unexpected status code ({}) when fetching {}.\n\nBody:\n{}",
                status,
                url,
                body.as_deref().unwrap_or("<failed to get body>")
            )));
        }

        // Read the bytes of the response
        let response_url = response.url().clone();
        let bytes = response.bytes_with_progress(reporter).await?;

        if let Some((reporter, index)) = reporter {
            reporter.on_download_complete(&response_url, index);
        }

        // Decompress the bytes
        let decoded_bytes = Bytes::from(decode_zst_bytes_async(bytes, response_url.clone()).await?);

        // The response is in, so we can drop the permit
        drop(permit);

        // Write the cache to disk if the policy allows it.
        let cache_fut =
            write_shard_index_cache(cache_file.inner_mut(), policy, decoded_bytes.clone())
                .map_ok(Some)
                .map_err(|e| {
                    GatewayError::IoError(
                        format!(
                            "failed to create temporary file to cache shard index to {}",
                            cache_path.display()
                        ),
                        e,
                    )
                });

        // Parse the bytes
        let parse_fut = run_blocking_task(move || {
            rmp_serde::from_slice(&decoded_bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
                .map_err(|e| {
                    GatewayError::IoError(
                        format!("failed to parse shard index from {response_url}"),
                        e,
                    )
                })
        });

        // Parse and write the file to disk concurrently
        let (_, sharded_index) = tokio::try_join!(cache_fut, parse_fut)?;

        Ok(sharded_index)
    }

    // Fetch the sharded repodata from the remote server
    let canonical_shards_url = channel_base_url
        .join(REPODATA_SHARDS_FILENAME)
        .expect("invalid shard base url");

    let cache_file_name = format!(
        "{}{}",
        url_to_cache_filename(&canonical_shards_url),
        SHARDS_CACHE_SUFFIX
    );
    let cache_path = cache_dir.join(cache_file_name);

    // Make sure the cache directory exists
    if let Some(parent) = cache_path.parent() {
        tokio_fs::create_dir_all(parent).await.map_err(|err| {
            GatewayError::IoError(format!("failed to create '{}'", parent.display()), err)
        })?;
    }

    // Open and lock the cache file
    let cache_file = tokio::fs::OpenOptions::new()
        .write(true)
        .read(true)
        .truncate(false)
        .create(true)
        .open(&cache_path)
        .await
        .map_err(|err| {
            GatewayError::IoError(format!("failed to open '{}'", cache_path.display()), err)
        })?;

    // Acquire a lock on the file.
    let cache_lock = cache_file.lock_write().await.map_err(|err| {
        GatewayError::IoError(
            format!("failed to lock '{}'", cache_path.display()),
            err.error,
        )
    })?;
    let mut cache_reader = BufReader::new(cache_lock);

    let canonical_request = SimpleRequest::get(&canonical_shards_url);

    // Try reading the cached file
    if cache_action != CacheAction::NoCache
        && let Ok(cache_header) = read_cached_index(&mut cache_reader).await
    {
        // Check if the cache indicates the resource was unavailable
        // (404 or 501)
        if cache_header.not_found {
            tracing::debug!(
                "cached not-available response for sharded index at {channel_base_url}"
            );
            return Err(create_subdir_not_found_error(channel_base_url));
        }

        // If we are in cache-only mode we can't fetch the index from the server
        if cache_action == CacheAction::ForceCacheOnly {
            if let Ok(shard_index) = read_shard_index_from_reader(&mut cache_reader).await {
                tracing::debug!("using locally cached shard index for {channel_base_url}");
                return Ok(shard_index);
            }
        } else {
            match cache_header
                .policy
                .before_request(&canonical_request, SystemTime::now())
            {
                BeforeRequest::Fresh(_) => {
                    if let Ok(shard_index) = read_shard_index_from_reader(&mut cache_reader).await {
                        tracing::debug!("shard index cache hit");
                        return Ok(shard_index);
                    }
                }
                BeforeRequest::Stale {
                    request: state_request,
                    ..
                } => {
                    if cache_action == CacheAction::UseCacheOnly {
                        // Cache-only and what we have may not be used, so this
                        // subdir has no sharded index we can read. The caller
                        // falls back to `repodata.json`.
                        return Err(GatewayError::ShardedIndexNotCached(
                            channel_base_url.clone().redact(),
                        ));
                    }

                    // Determine the actual URL to use for the request
                    let shards_url = channel_base_url
                        .join(REPODATA_SHARDS_FILENAME)
                        .expect("invalid shard base url");

                    // Construct the actual request that we will send
                    let request = client
                        .client()
                        .get(shards_url.clone())
                        .headers(state_request.headers().clone())
                        .build()
                        .expect("failed to build request for shard index");

                    // Acquire a permit to do a request
                    let request_permit = OptionFuture::from(
                        concurrent_requests_semaphore
                            .as_deref()
                            .map(tokio::sync::Semaphore::acquire),
                    )
                    .await
                    .transpose()
                    .expect("failed to acquire semaphore permit");

                    // Send the request
                    let download_reporter = reporter
                        .and_then(Reporter::download_reporter)
                        .map(|r| (r, r.on_download_start(&shards_url)));
                    let response = client.client().execute(request).await?;

                    // Check if the resource was not found (404) or not
                    // implemented (501). Treat 501 the same as 404 so we
                    // fall back to repodata.json when a server does not
                    // support sharded repodata.
                    if is_missing_sharded_repodata_status(response.status()) {
                        tracing::debug!(
                            "sharded index unavailable ({}) at {channel_base_url}, caching this result",
                            response.status()
                        );

                        // Cache the not-available response
                        let policy = CachePolicy::new(&canonical_request, &response);
                        write_not_found_cache(cache_reader.into_inner().inner_mut(), policy)
                            .await
                            .map_err(|e| {
                                GatewayError::IoError(
                                    format!(
                                        "failed to write not-found cache for shard index to {}",
                                        cache_path.display()
                                    ),
                                    e,
                                )
                            })?;

                        if let Some((reporter, index)) = download_reporter {
                            reporter.on_download_complete(response.url(), index);
                        }

                        // Return SubdirNotFoundError to trigger fallback
                        return Err(create_subdir_not_found_error(channel_base_url));
                    }

                    let after_response = cache_header.policy.after_response(
                        &state_request,
                        &response,
                        SystemTime::now(),
                    );

                    // A 304 is taken as "the cached body still stands" on the
                    // status alone, rather than left to `after_response`, which
                    // reports `NotModified` only when the 304 echoes back the
                    // validator it matched. Azure Blob does not echo one: it answers a
                    // conditional GET with a bare 304 carrying no `etag` and no
                    // `last-modified`, just `x-ms-error-code: ConditionNotMet`. That
                    // reads as `Modified`, and the 304 then reaches `from_response`,
                    // which rejects it for not being a success — so every `az://`
                    // sharded channel failed on the *second* fetch, once there was a
                    // cache entry to revalidate.
                    //
                    // What is required in return is that the request actually asked a
                    // conditional question. A cache entry with no validator revalidates
                    // with a plain GET, and a 304 to that answers nothing: honoring it
                    // would let a proxy or CDN pin a stale shard index forever.
                    let sent_conditional_request =
                        state_request.headers().contains_key(header::IF_NONE_MATCH)
                            || state_request
                                .headers()
                                .contains_key(header::IF_MODIFIED_SINCE);
                    let is_not_modified =
                        response.status() == StatusCode::NOT_MODIFIED && sent_conditional_request;

                    if response.status() == StatusCode::NOT_MODIFIED && !sent_conditional_request {
                        tracing::warn!(
                            "ignoring a 304 for the shard index at {channel_base_url}: the request it answers carried no validator, so it cannot mean the cached index is current"
                        );
                    }

                    let unmodified_policy = match &after_response {
                        AfterResponse::NotModified(policy, _)
                        | AfterResponse::Modified(policy, _)
                            if is_not_modified =>
                        {
                            Some(policy.clone())
                        }
                        _ => None,
                    };

                    if let Some(refreshed_policy) = unmodified_policy {
                        // The cached file is still valid
                        match read_cached_shard_index(&mut cache_reader).await {
                            Ok((body, shard_index)) => {
                                tracing::debug!("shard index cache was not modified");

                                // Store the refreshed policy so a server that sends
                                // caching headers along with its 304 does not have to
                                // be revalidated again on the next run. A policy that
                                // is already stale teaches us nothing, so the rewrite
                                // is skipped in that case — which is what a bare 304
                                // carrying no `cache-control` produces.
                                if !refreshed_policy.is_stale(SystemTime::now())
                                    && let Err(e) = write_shard_index_cache(
                                        cache_reader.into_inner().inner_mut(),
                                        refreshed_policy,
                                        body,
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "failed to store the refreshed cache policy for the shard index at {}: {e}",
                                        cache_path.display()
                                    );
                                }

                                if let Some((reporter, index)) = download_reporter {
                                    reporter.on_download_complete(response.url(), index);
                                }
                                return Ok(shard_index);
                            }
                            Err(e) => {
                                tracing::warn!("the cached shard index has been corrupted: {e}");
                                if let Some((reporter, index)) = download_reporter {
                                    reporter.on_download_complete(response.url(), index);
                                }
                            }
                        }
                    } else if let AfterResponse::Modified(policy, _) = after_response {
                        // Close the old file so we can create a new one.
                        tracing::debug!("shard index cache has become stale");
                        return from_response(
                            cache_reader.into_inner(),
                            &cache_path,
                            policy,
                            response,
                            download_reporter,
                            request_permit,
                        )
                        .await;
                    }
                }
            }
        }
    }

    if cache_action == CacheAction::ForceCacheOnly {
        return Err(GatewayError::ShardedIndexNotCached(
            channel_base_url.clone().redact(),
        ));
    }

    tracing::debug!("fetching fresh shard index");

    // Determine the actual URL to use for the request
    let shards_url = channel_base_url
        .join(REPODATA_SHARDS_FILENAME)
        .expect("invalid shard base url");

    // Construct the actual request that we will send
    let request = client
        .client()
        .get(shards_url.clone())
        .build()
        .expect("failed to build request for shard index");

    // Acquire a permit to do a request
    let request_permit = OptionFuture::from(
        concurrent_requests_semaphore
            .as_deref()
            .map(tokio::sync::Semaphore::acquire),
    )
    .await
    .transpose()
    .expect("failed to acquire semaphore permit");

    // Do a fresh requests
    let reporter = reporter
        .and_then(Reporter::download_reporter)
        .map(|r| (r, r.on_download_start(&shards_url)));
    let response = client
        .client()
        .execute(
            request
                .try_clone()
                .expect("failed to clone initial request"),
        )
        .await?;

    // Check if the resource was not found (404) or not implemented (501).
    // Treat 501 the same as 404 so we fall back to repodata.json when a
    // server does not support sharded repodata.
    if is_missing_sharded_repodata_status(response.status()) {
        tracing::debug!(
            "sharded index unavailable ({}) at {channel_base_url}, caching this result",
            response.status()
        );

        // Cache the not-available response
        let policy = CachePolicy::new(&canonical_request, &response);
        write_not_found_cache(cache_reader.into_inner().inner_mut(), policy)
            .await
            .map_err(|e| {
                GatewayError::IoError(
                    format!(
                        "failed to write not-found cache for shard index to {}",
                        cache_path.display()
                    ),
                    e,
                )
            })?;

        // Return SubdirNotFoundError to trigger fallback
        return Err(create_subdir_not_found_error(channel_base_url));
    }

    let policy = CachePolicy::new(&canonical_request, &response);
    from_response(
        cache_reader.into_inner(),
        &cache_path,
        policy,
        response,
        reporter,
        request_permit,
    )
    .await
}

/// Magic number that identifies the cache file format.
const MAGIC_NUMBER: &[u8] = b"SHARD-CACHE-V1";

/// Writes cache data to disk with the given header and optional body.
async fn write_cache(
    cache_file: &mut File,
    cache_header: CacheHeader,
    body: Option<&[u8]>,
) -> std::io::Result<()> {
    let encoded_header =
        rmp_serde::encode::to_vec(&cache_header).expect("failed to encode cache header");

    // Move to the start of the file
    cache_file.rewind().await?;

    // Write the cache to disk
    let mut writer = BufWriter::new(cache_file);
    writer.write_all(MAGIC_NUMBER).await?;
    writer
        .write_all(&(encoded_header.len() as u32).to_le_bytes())
        .await?;
    writer.write_all(&encoded_header).await?;

    // Write body if present
    if let Some(body_bytes) = body {
        writer.write_all(body_bytes).await?;
    }

    writer.flush().await?;

    // Truncate the file to the correct size
    let cache_file = writer.into_inner();
    let len = cache_file.stream_position().await?;
    cache_file.set_len(len).await?;

    Ok(())
}

/// Writes the shard index cache to disk.
pub async fn write_shard_index_cache(
    cache_file: &mut File,
    policy: CachePolicy,
    decoded_bytes: Bytes,
) -> std::io::Result<()> {
    write_cache(
        cache_file,
        CacheHeader {
            policy,
            not_found: false,
        },
        Some(decoded_bytes.as_ref()),
    )
    .await
}

/// Writes a not-available marker (404 or 501) to the cache file.
async fn write_not_found_cache(cache_file: &mut File, policy: CachePolicy) -> std::io::Result<()> {
    write_cache(
        cache_file,
        CacheHeader {
            policy,
            not_found: true,
        },
        None,
    )
    .await
}

/// Read the shard index from a reader and deserialize it.
pub async fn read_shard_index_from_reader<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<ShardedRepodata, GatewayError> {
    read_cached_shard_index(reader)
        .await
        .map(|(_, shard_index)| shard_index)
}

/// Read the shard index from a reader and deserialize it, also handing back the
/// raw bytes it was parsed from so the entry can be rewritten without a second
/// read.
async fn read_cached_shard_index<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<(Bytes, ShardedRepodata), GatewayError> {
    // Read the file to memory
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .await
        .map_err(|e| GatewayError::IoError("failed to read shard index buffer".to_string(), e))?;
    let bytes = Bytes::from(bytes);

    // Deserialize the bytes
    let parse_bytes = bytes.clone();
    let shard_index = run_blocking_task(move || {
        rmp_serde::from_slice(&parse_bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
            .map_err(|e| GatewayError::IoError("failed to parse shard index".to_string(), e))
    })
    .await?;

    Ok((bytes, shard_index))
}

/// Cache information stored at the start of the cache file.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CacheHeader {
    pub policy: CachePolicy,
    /// Indicates whether the resource was reported as unavailable (404 Not
    /// Found or 501 Not Implemented) by the remote.
    #[serde(default)]
    pub not_found: bool,
}

/// Try reading the cache file from disk.
async fn read_cached_index<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> std::io::Result<CacheHeader> {
    // Read the magic from the file
    let mut magic_number = [0; MAGIC_NUMBER.len()];
    reader.read_exact(&mut magic_number).await?;
    if magic_number != MAGIC_NUMBER {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid magic number",
        ));
    }

    // Read the length of the header
    let header_length = reader.read_u32_le().await? as usize;

    // Read the header from the file
    let mut header_bytes = vec![0; header_length];
    reader.read_exact(&mut header_bytes).await?;

    // Deserialize the header
    let cache_header = rmp_serde::from_slice::<CacheHeader>(&header_bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    Ok(cache_header)
}

/// A helper struct to make it easier to construct something that implements
/// [`RequestLike`].
pub struct SimpleRequest {
    uri: Uri,
    method: Method,
    headers: HeaderMap,
}

impl SimpleRequest {
    pub fn get(url: &Url) -> Self {
        Self {
            uri: Uri::from_str(url.as_str()).expect("failed to convert Url to Uri"),
            method: Method::GET,
            headers: HeaderMap::default(),
        }
    }
}

impl RequestLike for SimpleRequest {
    fn method(&self) -> &Method {
        &self.method
    }

    fn uri(&self) -> Uri {
        self.uri.clone()
    }

    fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    fn is_same_uri(&self, other: &Uri) -> bool {
        &self.uri() == other
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::IntoFuture,
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use axum::{Router, body::Body, http::Response, routing::get};
    use rattler_conda_types::{RepodataRevisions, ShardedSubdirInfo};
    use tokio::sync::oneshot;

    use super::*;

    /// The headers a mock response carries beyond its status.
    #[derive(Clone, Copy, Default)]
    struct MockHeaders {
        etag: Option<&'static str>,
        cache_control: Option<&'static str>,
    }

    impl MockHeaders {
        fn apply(
            self,
            mut builder: axum::http::response::Builder,
        ) -> axum::http::response::Builder {
            if let Some(etag) = self.etag {
                builder = builder.header("etag", etag);
            }
            if let Some(cache_control) = self.cache_control {
                builder = builder.header("cache-control", cache_control);
            }
            builder
        }
    }

    /// Serves the shard index once with a 200 and answers every request after
    /// that with a 304.
    struct RevalidatingIndexServer {
        local_addr: SocketAddr,
        requests: Arc<AtomicUsize>,
        _shutdown_sender: oneshot::Sender<()>,
    }

    impl RevalidatingIndexServer {
        /// The default shape: nothing keeps the entry fresh, and the 304 is
        /// bare — no validator, no caching headers — which is what Azure Blob
        /// answers a conditional GET with.
        async fn new(etag: Option<&'static str>) -> Self {
            Self::with_headers(
                MockHeaders {
                    etag,
                    cache_control: None,
                },
                MockHeaders::default(),
            )
            .await
        }

        async fn with_headers(initial: MockHeaders, revalidation: MockHeaders) -> Self {
            let sharded_index = ShardedRepodata {
                info: ShardedSubdirInfo {
                    subdir: "linux-64".to_string(),
                    base_url: "./".to_string(),
                    shards_base_url: "./shards/".to_string(),
                    created_at: Some(jiff::Timestamp::now()),
                    repodata_revisions: RepodataRevisions::default(),
                    channel_relations: None,
                },
                shards: ahash::HashMap::default(),
            };
            let compressed_index =
                zstd::encode_all(rmp_serde::to_vec(&sharded_index).unwrap().as_slice(), 3).unwrap();

            let requests = Arc::new(AtomicUsize::new(0));
            let served = Arc::clone(&requests);
            let app = Router::new().route(
                "/linux-64/repodata_shards.msgpack.zst",
                get(move || async move {
                    if served.fetch_add(1, Ordering::SeqCst) == 0 {
                        initial
                            .apply(Response::builder().status(StatusCode::OK))
                            .body(Body::from(compressed_index.clone()))
                            .unwrap()
                    } else {
                        revalidation
                            .apply(Response::builder().status(StatusCode::NOT_MODIFIED))
                            .body(Body::empty())
                            .unwrap()
                    }
                }),
            );

            let listener = tokio::net::TcpListener::bind(SocketAddr::new([127, 0, 0, 1].into(), 0))
                .await
                .unwrap();
            let local_addr = listener.local_addr().unwrap();

            let (tx, rx) = oneshot::channel();
            tokio::spawn(
                axum::serve(listener, app)
                    .with_graceful_shutdown(async {
                        rx.await.ok();
                    })
                    .into_future(),
            );

            Self {
                local_addr,
                requests,
                _shutdown_sender: tx,
            }
        }

        fn channel_base_url(&self) -> Url {
            Url::parse(&format!(
                "http://localhost:{}/linux-64/",
                self.local_addr.port()
            ))
            .unwrap()
        }

        fn request_count(&self) -> usize {
            self.requests.load(Ordering::SeqCst)
        }
    }

    async fn fetch(base_url: &Url, cache_dir: &Path) -> Result<ShardedRepodata, GatewayError> {
        fetch_index(
            rattler_networking::LazyClient::default(),
            base_url,
            cache_dir,
            CacheAction::CacheOrFetch,
            None,
            None,
        )
        .await
    }

    async fn fetch_twice(etag: Option<&'static str>) -> Result<ShardedRepodata, GatewayError> {
        let server = RevalidatingIndexServer::new(etag).await;
        let base_url = server.channel_base_url();
        let cache_dir = tempfile::tempdir().unwrap();

        fetch(&base_url, cache_dir.path())
            .await
            .expect("the first fetch is served a 200");

        fetch(&base_url, cache_dir.path()).await
    }

    /// A cache entry with no validator revalidates with a plain GET. A 304
    /// answering that question means nothing — a proxy or CDN that sends one
    /// would otherwise pin the cached index forever — so it must not be
    /// honored.
    #[tokio::test]
    async fn unconditional_304_is_not_honored() {
        let err = fetch_twice(None)
            .await
            .expect_err("a 304 to a request we never made conditional is not an answer");
        assert!(
            err.to_string().contains("304"),
            "the 304 should be rejected as an unexpected status, got: {err}"
        );
    }

    /// The counterpart: once we do send a validator, a bare 304 carrying no
    /// `etag` of its own is the real answer, and the cached index is served.
    #[tokio::test]
    async fn conditional_bare_304_is_honored() {
        fetch_twice(Some("\"abc\""))
            .await
            .expect("a 304 answering our `if-none-match` serves the cached index");
    }

    /// The freshness a 304 carries has to be stored, or the entry stays stale
    /// forever and every later run pays for a revalidation it was told it
    /// could skip.
    #[tokio::test]
    async fn a_304_refreshes_the_stored_cache_policy() {
        let server = RevalidatingIndexServer::with_headers(
            // Cached, but stale on arrival, so the next fetch revalidates.
            MockHeaders {
                etag: Some("\"abc\""),
                cache_control: Some("max-age=0"),
            },
            // The 304 says the entry is good for an hour.
            MockHeaders {
                etag: Some("\"abc\""),
                cache_control: Some("max-age=3600"),
            },
        )
        .await;
        let base_url = server.channel_base_url();
        let cache_dir = tempfile::tempdir().unwrap();

        for _ in 0..3 {
            fetch(&base_url, cache_dir.path())
                .await
                .expect("the index is served, then revalidated, then read from the cache");
        }

        assert_eq!(
            server.request_count(),
            2,
            "the 304 said the entry is good for an hour, so the third fetch must not reach the server"
        );
    }
}
