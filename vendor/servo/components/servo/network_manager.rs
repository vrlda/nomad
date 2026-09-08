/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::collections::HashSet;

use http::header::CONTENT_LENGTH;
use net_traits::blob_url_store::UrlWithBlobClaim;
use net_traits::request::{
    CredentialsMode, Initiator, RedirectMode, Referrer, RequestBuilder, RequestId, RequestMode,
};
use net_traits::{FetchResponseMsg, ResourceThreads, cancel_async_fetch, fetch_async};
use servo_base::id::WebViewId;
use servo_url::ServoUrl;
use url::Url;

/// A response event emitted by Servo's shared network stack for a browser download.
#[derive(Debug)]
pub enum DownloadEvent {
    /// Response headers have arrived.
    Response { total_bytes: Option<u64> },
    /// A body chunk has arrived.
    BodyChunk(Vec<u8>),
    /// The response stream has ended.
    Finished(Result<(), String>),
}

/// Receives response events for a browser download.
pub type DownloadCallback = Box<dyn FnMut(DownloadEvent) + Send + 'static>;

fn download_request(webview_id: WebViewId, url: Url) -> RequestBuilder {
    let url = ServoUrl::from_url(url);
    let origin = url.origin();
    RequestBuilder::new(
        Some(webview_id),
        UrlWithBlobClaim::from_url_without_having_claimed_blob(url),
        Referrer::NoReferrer,
    )
    .origin(origin)
    .mode(RequestMode::Navigate)
    .credentials_mode(CredentialsMode::Include)
    .use_url_credentials(true)
    .redirect_mode(RedirectMode::Follow)
    .initiator(Initiator::Download)
}

/// Opaque handle for cancelling a browser download.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DownloadHandle(RequestId);

#[derive(Clone, Debug, PartialEq)]
pub struct CacheEntry {
    key: String,
}

impl CacheEntry {
    pub fn new(key: String) -> Self {
        Self { key }
    }

    pub fn key(&self) -> &str {
        &self.key
    }
}

/// Provides APIs for managing network-related state.
///
/// `NetworkManager` is responsible for data owned by the networking layer,
/// such as the HTTP cache. This data is not considered site data and is
/// therefore intentionally separate from `SiteDataManager`.
pub struct NetworkManager {
    public_resource_threads: ResourceThreads,
    private_resource_threads: ResourceThreads,
}

impl NetworkManager {
    pub(crate) fn new(
        public_resource_threads: ResourceThreads,
        private_resource_threads: ResourceThreads,
    ) -> Self {
        Self {
            public_resource_threads,
            private_resource_threads,
        }
    }

    /// Returns cache entries currently stored in the HTTP cache.
    ///
    /// The returned list contains one [`CacheEntry`] per unique cache key
    /// (URL) for which the networking layer currently maintains cached
    /// responses.
    ///
    /// Both public and private browsing contexts are included in the result.
    ///
    /// Note: The networking layer currently only implements an in-memory HTTP
    /// cache. Support for an on-disk cache is under development.
    pub fn cache_entries(&self) -> Vec<CacheEntry> {
        let public_entries = self.public_resource_threads.cache_entries();
        let private_entries = self.private_resource_threads.cache_entries();

        let unique_keys: HashSet<String> = public_entries
            .into_iter()
            .chain(private_entries)
            .map(|entry| entry.key)
            .collect();

        unique_keys.into_iter().map(CacheEntry::new).collect()
    }

    /// Clears the network (HTTP) cache.
    ///
    /// This removes all cached network responses maintained by the networking
    /// layer for both public and private browsing contexts.
    ///
    /// Note: The networking layer currently only implements an in-memory HTTP
    /// cache. Support for an on-disk cache is under development.
    pub fn clear_cache(&self) {
        self.public_resource_threads.clear_cache();
        self.private_resource_threads.clear_cache();
    }

    /// Starts a download through Servo's existing resource thread.
    pub(crate) fn start_download(
        &self,
        webview_id: WebViewId,
        url: Url,
        callback: DownloadCallback,
    ) -> DownloadHandle {
        let request = download_request(webview_id, url);
        let handle = DownloadHandle(request.id);
        let resource_thread = self.public_resource_threads.core_thread.clone();
        let mut callback = callback;
        let mut response_failed = false;

        fetch_async(
            &resource_thread,
            request,
            None,
            Box::new(move |message| match message {
                FetchResponseMsg::ProcessResponse(_, Ok(metadata)) => {
                    let metadata = metadata.metadata();
                    if !metadata.status.is_success() {
                        response_failed = true;
                        callback(DownloadEvent::Finished(Err(format!(
                            "HTTP status {}",
                            metadata.status.raw_code()
                        ))));
                        return;
                    }
                    let total_bytes = metadata
                        .headers
                        .as_deref()
                        .and_then(|headers| headers.get(CONTENT_LENGTH))
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.parse().ok());
                    callback(DownloadEvent::Response { total_bytes });
                },
                FetchResponseMsg::ProcessResponse(_, Err(error)) => {
                    response_failed = true;
                    callback(DownloadEvent::Finished(Err(format!("{error:?}"))));
                },
                FetchResponseMsg::ProcessResponseChunk(_, data) if !response_failed => {
                    callback(DownloadEvent::BodyChunk(data.0));
                },
                FetchResponseMsg::ProcessResponseEOF(_, result, _) if !response_failed => {
                    callback(DownloadEvent::Finished(
                        result.map_err(|error| format!("{error:?}")),
                    ));
                },
                _ => {},
            }),
        );
        handle
    }

    /// Cancels an active download through Servo's shared fetch thread.
    pub(crate) fn cancel_download(&self, handle: DownloadHandle) {
        cancel_async_fetch(vec![handle.0], &self.public_resource_threads.core_thread);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_traits::request::Origin;
    use servo_base::id::TEST_WEBVIEW_ID;

    #[test]
    fn download_request_has_explicit_origin_without_client() {
        let url = Url::parse("https://example.test/file.pdf").unwrap();
        let request = download_request(TEST_WEBVIEW_ID, url.clone());

        assert!(request.client.is_none());
        assert_eq!(
            request.origin,
            Origin::Origin(ServoUrl::from_url(url).origin())
        );
        assert_eq!(request.mode, RequestMode::Navigate);
        assert_eq!(request.initiator, Initiator::Download);
    }
}
