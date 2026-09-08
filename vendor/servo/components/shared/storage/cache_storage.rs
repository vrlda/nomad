/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::ops::{Deref, DerefMut};

use malloc_size_of_derive::MallocSizeOf;
use serde::{Deserialize, Serialize};
use servo_base::generic_channel::{GenericCallback, GenericSender};
use servo_url::ImmutableOrigin;

use crate::client_storage::StorageProxyMap;

/// A serialized Cache API response entry.
///
/// The storage thread deliberately owns this representation instead of
/// depending on DOM or network response types. This keeps the persistence
/// boundary usable by service workers and makes cached bodies independent from
/// a live script global.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CacheEntry {
    pub request_url: String,
    pub request_method: String,
    pub request_headers: Vec<(String, Vec<u8>)>,
    pub request_reload_navigation: bool,
    pub request_history_navigation: bool,
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum CacheStorageError<T> {
    QuotaExceeded,
    Internal(T),
}

#[derive(Clone, Debug, Deserialize, MallocSizeOf, Serialize)]
pub struct CacheStorageThreadHandle {
    sender: GenericSender<CacheStorageThreadMessage>,
}

impl CacheStorageThreadHandle {
    pub fn new(sender: GenericSender<CacheStorageThreadMessage>) -> Self {
        CacheStorageThreadHandle { sender }
    }
}

impl From<CacheStorageThreadHandle> for GenericSender<CacheStorageThreadMessage> {
    fn from(handle: CacheStorageThreadHandle) -> Self {
        handle.sender
    }
}

impl From<GenericSender<CacheStorageThreadMessage>> for CacheStorageThreadHandle {
    fn from(sender: GenericSender<CacheStorageThreadMessage>) -> Self {
        CacheStorageThreadHandle::new(sender)
    }
}

impl Deref for CacheStorageThreadHandle {
    type Target = GenericSender<CacheStorageThreadMessage>;

    fn deref(&self) -> &Self::Target {
        &self.sender
    }
}

impl DerefMut for CacheStorageThreadHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.sender
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum CacheStorageThreadMessage {
    /// <https://w3c.github.io/ServiceWorker/#cache-storage-open>
    OpenCache {
        cache_name: String,
        callback: GenericCallback<CacheStorageThreadResponse>,
        proxy: StorageProxyMap,
        origin: ImmutableOrigin,
    },
    /// <https://w3c.github.io/ServiceWorker/#cache-storage-has>
    HasCache {
        cache_name: String,
        callback: GenericCallback<CacheStorageThreadResponse>,
        proxy: StorageProxyMap,
        origin: ImmutableOrigin,
    },
    /// <https://w3c.github.io/ServiceWorker/#cache-storage-delete>
    DeleteCache {
        cache_name: String,
        callback: GenericCallback<CacheStorageThreadResponse>,
        proxy: StorageProxyMap,
        origin: ImmutableOrigin,
    },
    /// <https://w3c.github.io/ServiceWorker/#cache-storage-keys>
    CacheKeys {
        callback: GenericCallback<CacheStorageThreadResponse>,
        proxy: StorageProxyMap,
        origin: ImmutableOrigin,
    },
    /// <https://w3c.github.io/ServiceWorker/#cache-put>
    PutEntry {
        cache_name: String,
        entry: CacheEntry,
        callback: GenericCallback<CacheStorageThreadResponse>,
        proxy: StorageProxyMap,
        origin: ImmutableOrigin,
    },
    /// <https://w3c.github.io/ServiceWorker/#cache-match>
    MatchEntry {
        cache_name: String,
        request_url: String,
        request_method: String,
        request_headers: Vec<(String, Vec<u8>)>,
        ignore_search: bool,
        ignore_method: bool,
        ignore_vary: bool,
        callback: GenericCallback<CacheStorageThreadResponse>,
        proxy: StorageProxyMap,
        origin: ImmutableOrigin,
    },
    /// <https://w3c.github.io/ServiceWorker/#cache-storage-match>
    MatchStorageEntry {
        request_url: String,
        request_method: String,
        request_headers: Vec<(String, Vec<u8>)>,
        ignore_search: bool,
        ignore_method: bool,
        ignore_vary: bool,
        callback: GenericCallback<CacheStorageThreadResponse>,
        proxy: StorageProxyMap,
        origin: ImmutableOrigin,
    },
    MatchEntries {
        cache_name: String,
        request_url: String,
        request_method: String,
        request_headers: Vec<(String, Vec<u8>)>,
        ignore_search: bool,
        ignore_method: bool,
        ignore_vary: bool,
        callback: GenericCallback<CacheStorageThreadResponse>,
        proxy: StorageProxyMap,
        origin: ImmutableOrigin,
    },
    /// <https://w3c.github.io/ServiceWorker/#cache-delete>
    DeleteEntry {
        cache_name: String,
        request_url: String,
        request_method: String,
        request_headers: Vec<(String, Vec<u8>)>,
        ignore_search: bool,
        ignore_method: bool,
        ignore_vary: bool,
        callback: GenericCallback<CacheStorageThreadResponse>,
        proxy: StorageProxyMap,
        origin: ImmutableOrigin,
    },
    Exit(GenericSender<()>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum CacheStorageThreadResponse {
    OpenCacheResult(Result<String, String>),
    HasCacheResult(Result<bool, String>),
    DeleteCacheResult(Result<bool, String>),
    CacheKeysResult(Result<Vec<String>, String>),
    PutEntryResult(Result<(), String>),
    MatchEntryResult(Result<Option<CacheEntry>, String>),
    MatchEntriesResult(Result<Vec<CacheEntry>, String>),
    DeleteEntryResult(Result<bool, String>),
}
