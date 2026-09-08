/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Debug;
use std::path::PathBuf;
use std::thread;

use log::error;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use servo_base::generic_channel::{self, GenericReceiver, GenericSender};
use servo_url::ImmutableOrigin;
use storage_traits::cache_storage::{
    CacheEntry, CacheStorageError, CacheStorageThreadHandle, CacheStorageThreadMessage,
    CacheStorageThreadResponse,
};

/// CacheStorage uses the same conservative per-storage-shelf quota exposed by
/// StorageManager. The limit is independent of free disk space so quota
/// behavior cannot reveal device capacity.
const CACHE_STORAGE_QUOTA_BYTES: u64 = 10 * 1024 * 1024 * 1024;

fn cache_entry_size(entry: &CacheEntry) -> u64 {
    let request_headers = entry
        .request_headers
        .iter()
        .map(|(name, value)| name.len() as u64 + value.len() as u64)
        .sum::<u64>();
    let response_headers = entry
        .headers
        .iter()
        .map(|(name, value)| name.len() as u64 + value.len() as u64)
        .sum::<u64>();
    entry.request_url.len() as u64
        + entry.request_method.len() as u64
        + request_headers
        + response_headers
        + entry.status_text.len() as u64
        + entry.body.len() as u64
}

fn has_available_quota(current: u64, replaced: u64, incoming: u64) -> bool {
    current.saturating_sub(replaced).saturating_add(incoming) <= CACHE_STORAGE_QUOTA_BYTES
}

trait CacheStorageEngine {
    type Error: Debug;

    /// Select the top-level site partition for subsequent operations on this
    /// single-threaded engine. The default keeps existing direct engine users
    /// on the unpartitioned origin key.
    fn set_partition_key(&mut self, _partition_key: Option<String>) {}

    /// <https://w3c.github.io/ServiceWorker/#cache-storage-has>
    fn open_cache(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
    ) -> Result<String, CacheStorageError<Self::Error>>;
    fn has_cache(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
    ) -> Result<bool, CacheStorageError<Self::Error>>;
    fn delete_cache(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
    ) -> Result<bool, CacheStorageError<Self::Error>>;
    fn cache_keys(
        &mut self,
        origin: &ImmutableOrigin,
    ) -> Result<Vec<String>, CacheStorageError<Self::Error>>;
    fn put_entry(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
        entry: CacheEntry,
    ) -> Result<(), CacheStorageError<Self::Error>>;
    fn match_entry(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
        request_url: &str,
        request_method: &str,
        request_headers: &[(String, Vec<u8>)],
        ignore_search: bool,
        ignore_method: bool,
        ignore_vary: bool,
    ) -> Result<Option<CacheEntry>, CacheStorageError<Self::Error>>;
    fn match_storage_entry(
        &mut self,
        origin: &ImmutableOrigin,
        request_url: &str,
        request_method: &str,
        request_headers: &[(String, Vec<u8>)],
        ignore_search: bool,
        ignore_method: bool,
        ignore_vary: bool,
    ) -> Result<Option<CacheEntry>, CacheStorageError<Self::Error>> {
        for cache_name in self.cache_keys(origin)? {
            if let Some(entry) = self.match_entry(
                origin,
                &cache_name,
                request_url,
                request_method,
                request_headers,
                ignore_search,
                ignore_method,
                ignore_vary,
            )? {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }
    fn match_entries(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
        request_url: &str,
        request_method: &str,
        request_headers: &[(String, Vec<u8>)],
        ignore_search: bool,
        ignore_method: bool,
        ignore_vary: bool,
    ) -> Result<Vec<CacheEntry>, CacheStorageError<Self::Error>>;
    fn delete_entry(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
        request_url: &str,
        request_method: &str,
        request_headers: &[(String, Vec<u8>)],
        ignore_search: bool,
        ignore_method: bool,
        ignore_vary: bool,
    ) -> Result<bool, CacheStorageError<Self::Error>>;
}

pub struct InMemoryCacheStorageEngine {
    names: HashMap<String, BTreeSet<String>>,
    entries: BTreeMap<(String, String, String, String), CacheEntry>,
    partition_key: Option<String>,
}

impl InMemoryCacheStorageEngine {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            names: HashMap::new(),
            entries: BTreeMap::new(),
            partition_key: None,
        }
    }

    fn namespace_for(&self, origin: &ImmutableOrigin) -> String {
        cache_namespace(origin, self.partition_key.as_deref())
    }

    fn names_for(&mut self, origin: &ImmutableOrigin) -> &mut BTreeSet<String> {
        let namespace = self.namespace_for(origin);
        self.names.entry(namespace).or_default()
    }
}

impl CacheStorageEngine for InMemoryCacheStorageEngine {
    type Error = ();

    fn set_partition_key(&mut self, partition_key: Option<String>) {
        self.partition_key = partition_key;
    }

    fn open_cache(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
    ) -> Result<String, CacheStorageError<Self::Error>> {
        self.names_for(origin).insert(cache_name.to_owned());
        Ok(cache_name.to_owned())
    }

    /// <https://w3c.github.io/ServiceWorker/#cache-storage-has>
    /// The parallel steps.
    fn has_cache(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
    ) -> Result<bool, CacheStorageError<Self::Error>> {
        Ok(self.names_for(origin).contains(cache_name))
    }

    fn delete_cache(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
    ) -> Result<bool, CacheStorageError<Self::Error>> {
        let origin = self.namespace_for(origin);
        let deleted = self
            .names
            .entry(origin.clone())
            .or_default()
            .remove(cache_name);
        self.entries.retain(|(entry_origin, entry_cache, _, _), _| {
            entry_origin != &origin || entry_cache != cache_name
        });
        Ok(deleted)
    }

    fn cache_keys(
        &mut self,
        origin: &ImmutableOrigin,
    ) -> Result<Vec<String>, CacheStorageError<Self::Error>> {
        Ok(self.names_for(origin).iter().cloned().collect())
    }

    fn put_entry(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
        entry: CacheEntry,
    ) -> Result<(), CacheStorageError<Self::Error>> {
        let namespace = self.namespace_for(origin);
        let key = (
            namespace.clone(),
            cache_name.to_owned(),
            entry.request_url.clone(),
            entry.request_method.clone(),
        );
        let replaced = self
            .entries
            .get(&key)
            .map(cache_entry_size)
            .unwrap_or_default();
        let current = self
            .entries
            .iter()
            .filter(|((entry_namespace, _, _, _), _)| entry_namespace == &namespace)
            .map(|(_, entry)| cache_entry_size(entry))
            .sum();
        let incoming = cache_entry_size(&entry);
        if !has_available_quota(current, replaced, incoming) {
            return Err(CacheStorageError::QuotaExceeded);
        }
        self.names
            .entry(namespace)
            .or_default()
            .insert(cache_name.to_owned());
        self.entries.insert(key, entry);
        Ok(())
    }

    fn match_entry(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
        request_url: &str,
        request_method: &str,
        request_headers: &[(String, Vec<u8>)],
        ignore_search: bool,
        ignore_method: bool,
        ignore_vary: bool,
    ) -> Result<Option<CacheEntry>, CacheStorageError<Self::Error>> {
        Ok(self
            .match_entries(
                origin,
                cache_name,
                request_url,
                request_method,
                request_headers,
                ignore_search,
                ignore_method,
                ignore_vary,
            )?
            .into_iter()
            .next())
    }

    fn match_entries(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
        request_url: &str,
        request_method: &str,
        request_headers: &[(String, Vec<u8>)],
        ignore_search: bool,
        ignore_method: bool,
        ignore_vary: bool,
    ) -> Result<Vec<CacheEntry>, CacheStorageError<Self::Error>> {
        let origin = self.namespace_for(origin);
        Ok(self
            .entries
            .iter()
            .filter(
                |((entry_origin, entry_cache, entry_url, entry_method), entry)| {
                    entry_origin == &origin
                        && entry_cache == cache_name
                        && (ignore_method || entry_method == request_method)
                        && (request_url.is_empty() || ignore_search || entry_url == request_url)
                        && (request_url.is_empty()
                            || !ignore_search
                            || without_search(entry_url) == without_search(request_url))
                        && vary_matches(
                            &entry.headers,
                            &entry.request_headers,
                            request_headers,
                            ignore_vary,
                        )
                },
            )
            .map(|(_, entry)| entry.clone())
            .collect())
    }

    fn delete_entry(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
        request_url: &str,
        request_method: &str,
        request_headers: &[(String, Vec<u8>)],
        ignore_search: bool,
        ignore_method: bool,
        ignore_vary: bool,
    ) -> Result<bool, CacheStorageError<Self::Error>> {
        let origin = self.namespace_for(origin);
        let key = self
            .entries
            .iter()
            .find(
                |((entry_origin, entry_cache, entry_url, entry_method), entry)| {
                    entry_origin == &origin
                        && entry_cache == cache_name
                        && (ignore_method || entry_method == request_method)
                        && (request_url.is_empty() || ignore_search || entry_url == request_url)
                        && (request_url.is_empty()
                            || !ignore_search
                            || without_search(entry_url) == without_search(request_url))
                        && vary_matches(
                            &entry.headers,
                            &entry.request_headers,
                            request_headers,
                            ignore_vary,
                        )
                },
            )
            .map(|(key, _)| key.clone());
        Ok(key.is_some_and(|key| self.entries.remove(&key).is_some()))
    }
}

fn cache_namespace(origin: &ImmutableOrigin, partition_key: Option<&str>) -> String {
    partition_key.map_or_else(
        || origin.ascii_serialization(),
        |partition| format!("{partition}\u{1f}{}", origin.ascii_serialization()),
    )
}

fn without_search(url: &str) -> &str {
    url.split_once('?').map_or(url, |(base, _)| base)
}

fn vary_matches(
    response_headers: &[(String, Vec<u8>)],
    cached_request_headers: &[(String, Vec<u8>)],
    request_headers: &[(String, Vec<u8>)],
    ignore_vary: bool,
) -> bool {
    if ignore_vary {
        return true;
    }

    let vary = combined_header_value(response_headers, "vary");
    if vary.is_empty() {
        return true;
    }

    vary.split(|byte| *byte == b',').all(|field| {
        let field = field
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        if field == b"*" || field.is_empty() {
            return field.is_empty();
        }
        let Ok(field) = std::str::from_utf8(&field) else {
            return false;
        };
        combined_header_value(cached_request_headers, field)
            == combined_header_value(request_headers, field)
    })
}

fn combined_header_value(headers: &[(String, Vec<u8>)], name: &str) -> Vec<u8> {
    let mut value = Vec::new();
    for (_, header_value) in headers
        .iter()
        .filter(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
    {
        if !value.is_empty() {
            value.extend_from_slice(b", ");
        }
        value.extend_from_slice(header_value);
    }
    value
}

#[derive(Deserialize, Serialize)]
struct StoredCacheHeaders {
    response: Vec<(String, Vec<u8>)>,
    request: Vec<(String, Vec<u8>)>,
    #[serde(default)]
    request_reload_navigation: bool,
    #[serde(default)]
    request_history_navigation: bool,
}

struct SqliteCacheStorageEngine {
    connection: Connection,
    partition_key: Option<String>,
}

impl SqliteCacheStorageEngine {
    fn new(storage_dir: PathBuf) -> rusqlite::Result<Self> {
        let connection = Connection::open(storage_dir.join("cache.sqlite"))?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS caches (
                origin TEXT NOT NULL,
                cache_name TEXT NOT NULL,
                PRIMARY KEY (origin, cache_name)
            );
            CREATE TABLE IF NOT EXISTS cache_entries (
                origin TEXT NOT NULL,
                cache_name TEXT NOT NULL,
                request_url TEXT NOT NULL,
                request_method TEXT NOT NULL,
                status INTEGER NOT NULL,
                status_text TEXT NOT NULL,
                headers BLOB NOT NULL,
                body BLOB NOT NULL,
                PRIMARY KEY (origin, cache_name, request_url, request_method)
            );",
        )?;
        Ok(Self {
            connection,
            partition_key: None,
        })
    }

    fn namespace_for(&self, origin: &ImmutableOrigin) -> String {
        cache_namespace(origin, self.partition_key.as_deref())
    }
}

impl CacheStorageEngine for SqliteCacheStorageEngine {
    type Error = rusqlite::Error;

    fn set_partition_key(&mut self, partition_key: Option<String>) {
        self.partition_key = partition_key;
    }

    fn open_cache(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
    ) -> Result<String, CacheStorageError<Self::Error>> {
        let namespace = self.namespace_for(origin);
        self.connection
            .execute(
                "INSERT OR IGNORE INTO caches (origin, cache_name) VALUES (?1, ?2)",
                params![namespace, cache_name],
            )
            .map_err(CacheStorageError::Internal)?;
        Ok(cache_name.to_owned())
    }

    fn has_cache(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
    ) -> Result<bool, CacheStorageError<Self::Error>> {
        let namespace = self.namespace_for(origin);
        let exists: i64 = self
            .connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM caches WHERE origin = ?1 AND cache_name = ?2
                )",
                params![namespace, cache_name],
                |row| row.get(0),
            )
            .map_err(CacheStorageError::Internal)?;
        Ok(exists != 0)
    }

    fn delete_cache(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
    ) -> Result<bool, CacheStorageError<Self::Error>> {
        let namespace = self.namespace_for(origin);
        let deleted = self
            .connection
            .execute(
                "DELETE FROM caches WHERE origin = ?1 AND cache_name = ?2",
                params![namespace.clone(), cache_name],
            )
            .map_err(CacheStorageError::Internal)?;
        self.connection
            .execute(
                "DELETE FROM cache_entries WHERE origin = ?1 AND cache_name = ?2",
                params![namespace, cache_name],
            )
            .map_err(CacheStorageError::Internal)?;
        Ok(deleted != 0)
    }

    fn cache_keys(
        &mut self,
        origin: &ImmutableOrigin,
    ) -> Result<Vec<String>, CacheStorageError<Self::Error>> {
        let namespace = self.namespace_for(origin);
        let mut statement = self
            .connection
            .prepare("SELECT cache_name FROM caches WHERE origin = ?1 ORDER BY cache_name")
            .map_err(CacheStorageError::Internal)?;
        let names = statement
            .query_map(params![namespace], |row| row.get(0))
            .map_err(CacheStorageError::Internal)?
            .collect::<Result<Vec<String>, _>>()
            .map_err(CacheStorageError::Internal)?;
        Ok(names)
    }

    fn put_entry(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
        entry: CacheEntry,
    ) -> Result<(), CacheStorageError<Self::Error>> {
        let namespace = self.namespace_for(origin);
        let headers = postcard::to_stdvec(&StoredCacheHeaders {
            response: entry.headers,
            request: entry.request_headers,
            request_reload_navigation: entry.request_reload_navigation,
            request_history_navigation: entry.request_history_navigation,
        })
        .map_err(|error| {
            CacheStorageError::Internal(rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
        })?;
        let current = self
            .connection
            .query_row(
                "SELECT COALESCE(SUM(LENGTH(cache_name) + LENGTH(request_url) +
                    LENGTH(request_method) + LENGTH(headers) + LENGTH(body)), 0)
                 FROM cache_entries WHERE origin = ?1",
                params![namespace.clone()],
                |row| row.get::<_, i64>(0),
            )
            .map_err(CacheStorageError::Internal)? as u64;
        let replaced = self
            .connection
            .query_row(
                "SELECT COALESCE(LENGTH(cache_name) + LENGTH(request_url) +
                    LENGTH(request_method) + LENGTH(headers) + LENGTH(body), 0)
                 FROM cache_entries
                 WHERE origin = ?1 AND cache_name = ?2 AND request_url = ?3 AND request_method = ?4",
                params![
                    namespace.clone(),
                    cache_name,
                    entry.request_url.clone(),
                    entry.request_method.clone(),
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(CacheStorageError::Internal)?
            .unwrap_or_default() as u64;
        let incoming = cache_name.len() as u64
            + entry.request_url.len() as u64
            + entry.request_method.len() as u64
            + headers.len() as u64
            + entry.body.len() as u64;
        if !has_available_quota(current, replaced, incoming) {
            return Err(CacheStorageError::QuotaExceeded);
        }
        self.open_cache(origin, cache_name)?;
        self.connection
            .execute(
                "INSERT OR REPLACE INTO cache_entries
                 (origin, cache_name, request_url, request_method, status, status_text, headers, body)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    namespace,
                    cache_name,
                    entry.request_url,
                    entry.request_method,
                    entry.status,
                    entry.status_text,
                    headers,
                    entry.body,
                ],
            )
            .map_err(CacheStorageError::Internal)?;
        Ok(())
    }

    fn match_entry(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
        request_url: &str,
        request_method: &str,
        request_headers: &[(String, Vec<u8>)],
        ignore_search: bool,
        ignore_method: bool,
        ignore_vary: bool,
    ) -> Result<Option<CacheEntry>, CacheStorageError<Self::Error>> {
        Ok(self
            .match_entries(
                origin,
                cache_name,
                request_url,
                request_method,
                request_headers,
                ignore_search,
                ignore_method,
                ignore_vary,
            )?
            .into_iter()
            .next())
    }

    fn match_entries(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
        request_url: &str,
        request_method: &str,
        request_headers: &[(String, Vec<u8>)],
        ignore_search: bool,
        ignore_method: bool,
        ignore_vary: bool,
    ) -> Result<Vec<CacheEntry>, CacheStorageError<Self::Error>> {
        let origin_serialized = self.namespace_for(origin);
        let mut statement = self
            .connection
            .prepare(
                "SELECT request_url, request_method, status, status_text, headers, body
                 FROM cache_entries
                 WHERE origin = ?1 AND cache_name = ?2
                 ORDER BY request_url, request_method",
            )
            .map_err(CacheStorageError::Internal)?;
        let mut rows = statement
            .query(params![origin_serialized, cache_name])
            .map_err(CacheStorageError::Internal)?;
        let mut entries = Vec::new();
        while let Some(row) = rows.next().map_err(CacheStorageError::Internal)? {
            let entry_url: String = row.get(0).map_err(CacheStorageError::Internal)?;
            if !request_url.is_empty()
                && ((!ignore_search && entry_url != request_url)
                    || (ignore_search && without_search(&entry_url) != without_search(request_url)))
            {
                continue;
            }
            let entry_method: String = row.get(1).map_err(CacheStorageError::Internal)?;
            if !ignore_method && entry_method != request_method {
                continue;
            }
            let entry = cache_entry_from_row(row).map_err(CacheStorageError::Internal)?;
            if vary_matches(
                &entry.headers,
                &entry.request_headers,
                request_headers,
                ignore_vary,
            ) {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    fn delete_entry(
        &mut self,
        origin: &ImmutableOrigin,
        cache_name: &str,
        request_url: &str,
        request_method: &str,
        request_headers: &[(String, Vec<u8>)],
        ignore_search: bool,
        ignore_method: bool,
        ignore_vary: bool,
    ) -> Result<bool, CacheStorageError<Self::Error>> {
        let namespace = self.namespace_for(origin);
        let entry = self.match_entry(
            origin,
            cache_name,
            request_url,
            request_method,
            request_headers,
            ignore_search,
            ignore_method,
            ignore_vary,
        )?;
        let Some(entry) = entry else {
            return Ok(false);
        };
        let deleted = self
            .connection
            .execute(
                "DELETE FROM cache_entries
                 WHERE origin = ?1 AND cache_name = ?2 AND request_url = ?3 AND request_method = ?4",
                params![
                    namespace,
                    cache_name,
                    entry.request_url,
                    entry.request_method,
                ],
            )
            .map_err(CacheStorageError::Internal)?;
        Ok(deleted != 0)
    }
}

fn cache_entry_from_row(row: &rusqlite::Row<'_>) -> Result<CacheEntry, rusqlite::Error> {
    let encoded_headers = row.get::<_, Vec<u8>>(4)?;
    let (headers, request_headers, request_reload_navigation, request_history_navigation) =
        match postcard::from_bytes::<StoredCacheHeaders>(&encoded_headers) {
            Ok(headers) => (
                headers.response,
                headers.request,
                headers.request_reload_navigation,
                headers.request_history_navigation,
            ),
            Err(_) => (
                postcard::from_bytes(&encoded_headers).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        4,
                        rusqlite::types::Type::Blob,
                        Box::new(error),
                    )
                })?,
                Vec::new(),
                false,
                false,
            ),
        };
    Ok(CacheEntry {
        request_url: row.get(0)?,
        request_method: row.get(1)?,
        request_headers,
        request_reload_navigation,
        request_history_navigation,
        status: row.get(2)?,
        status_text: row.get(3)?,
        headers,
        body: row.get(5)?,
    })
}

pub trait CacheStorageThreadFactory {
    fn new(config_dir: Option<PathBuf>, temporary_storage: bool) -> Self;
}

impl CacheStorageThreadFactory for CacheStorageThreadHandle {
    fn new(config_dir: Option<PathBuf>, temporary_storage: bool) -> CacheStorageThreadHandle {
        let (generic_sender, generic_receiver) = generic_channel::channel().unwrap();
        let mut temp_dir: Option<tempfile::TempDir> = None;
        let base_dir = config_dir
            .unwrap_or_else(|| {
                let tmp_dir = tempfile::tempdir().unwrap();
                let path = tmp_dir.path().to_path_buf();
                temp_dir = Some(tmp_dir);
                path
            })
            .join("cachestorage");
        let storage_dir = if temporary_storage {
            let unique_id = uuid::Uuid::new_v4().to_string();
            base_dir.join("temporary").join(unique_id)
        } else {
            base_dir.join("default_v1")
        };
        std::fs::create_dir_all(&storage_dir)
            .expect("Failed to create CacheStorage storage directory");
        let sender_clone = generic_sender.clone();
        thread::Builder::new()
            .name("CacheStorageThread".to_owned())
            .spawn(move || {
                // Keep temp_dir alive while the thread runs.
                let _temp_dir = temp_dir;
                let engine = SqliteCacheStorageEngine::new(storage_dir)
                    .expect("Failed to initialize CacheStorage SQLite database");
                CacheStorageThread::new(sender_clone, generic_receiver, engine).start();
            })
            .expect("Thread spawning failed");

        CacheStorageThreadHandle::new(generic_sender)
    }
}

struct CacheStorageThread<E: CacheStorageEngine> {
    receiver: GenericReceiver<CacheStorageThreadMessage>,
    // Note: a sender to self might be required later for the storage engine.
    _sender: GenericSender<CacheStorageThreadMessage>,
    engine: E,
}

impl<E> CacheStorageThread<E>
where
    E: CacheStorageEngine,
{
    pub fn new(
        _sender: GenericSender<CacheStorageThreadMessage>,
        receiver: GenericReceiver<CacheStorageThreadMessage>,
        engine: E,
    ) -> CacheStorageThread<E> {
        CacheStorageThread {
            _sender,
            receiver,
            engine,
        }
    }

    pub fn start(&mut self) {
        while let Ok(message) = self.receiver.recv() {
            match message {
                CacheStorageThreadMessage::OpenCache {
                    cache_name,
                    callback,
                    proxy,
                    origin,
                } => {
                    self.engine.set_partition_key(proxy.partition_key.clone());
                    let result = self.engine.open_cache(&origin, &cache_name);
                    if callback
                        .send(CacheStorageThreadResponse::OpenCacheResult(
                            result.map_err(|e| format!("{:?}", e)),
                        ))
                        .is_err()
                    {
                        error!("Failed to send response to script for OpenCache message.");
                    }
                },
                CacheStorageThreadMessage::HasCache {
                    cache_name,
                    callback,
                    proxy,
                    origin,
                } => {
                    self.engine.set_partition_key(proxy.partition_key.clone());
                    let result = self.engine.has_cache(&origin, &cache_name);
                    if callback
                        .send(CacheStorageThreadResponse::HasCacheResult(
                            result.map_err(|e| format!("{:?}", e)),
                        ))
                        .is_err()
                    {
                        error!("Failed to send response to script for HasCache message.");
                    }
                },
                CacheStorageThreadMessage::DeleteCache {
                    cache_name,
                    callback,
                    proxy,
                    origin,
                } => {
                    self.engine.set_partition_key(proxy.partition_key.clone());
                    let result = self.engine.delete_cache(&origin, &cache_name);
                    if callback
                        .send(CacheStorageThreadResponse::DeleteCacheResult(
                            result.map_err(|e| format!("{:?}", e)),
                        ))
                        .is_err()
                    {
                        error!("Failed to send response to script for DeleteCache message.");
                    }
                },
                CacheStorageThreadMessage::CacheKeys {
                    callback,
                    proxy,
                    origin,
                } => {
                    self.engine.set_partition_key(proxy.partition_key.clone());
                    let result = self.engine.cache_keys(&origin);
                    if callback
                        .send(CacheStorageThreadResponse::CacheKeysResult(
                            result.map_err(|e| format!("{:?}", e)),
                        ))
                        .is_err()
                    {
                        error!("Failed to send response to script for CacheKeys message.");
                    }
                },
                CacheStorageThreadMessage::PutEntry {
                    cache_name,
                    entry,
                    callback,
                    proxy,
                    origin,
                } => {
                    self.engine.set_partition_key(proxy.partition_key.clone());
                    let result = self.engine.put_entry(&origin, &cache_name, entry);
                    if callback
                        .send(CacheStorageThreadResponse::PutEntryResult(
                            result.map_err(|e| format!("{:?}", e)),
                        ))
                        .is_err()
                    {
                        error!("Failed to send response to script for PutEntry message.");
                    }
                },
                CacheStorageThreadMessage::MatchEntry {
                    cache_name,
                    request_url,
                    request_method,
                    request_headers,
                    ignore_search,
                    ignore_method,
                    ignore_vary,
                    callback,
                    proxy,
                    origin,
                } => {
                    self.engine.set_partition_key(proxy.partition_key.clone());
                    let result = self.engine.match_entry(
                        &origin,
                        &cache_name,
                        &request_url,
                        &request_method,
                        &request_headers,
                        ignore_search,
                        ignore_method,
                        ignore_vary,
                    );
                    if callback
                        .send(CacheStorageThreadResponse::MatchEntryResult(
                            result.map_err(|e| format!("{:?}", e)),
                        ))
                        .is_err()
                    {
                        error!("Failed to send response to script for MatchEntry message.");
                    }
                },
                CacheStorageThreadMessage::MatchStorageEntry {
                    request_url,
                    request_method,
                    request_headers,
                    ignore_search,
                    ignore_method,
                    ignore_vary,
                    callback,
                    proxy,
                    origin,
                } => {
                    self.engine.set_partition_key(proxy.partition_key.clone());
                    let result = self.engine.match_storage_entry(
                        &origin,
                        &request_url,
                        &request_method,
                        &request_headers,
                        ignore_search,
                        ignore_method,
                        ignore_vary,
                    );
                    if callback
                        .send(CacheStorageThreadResponse::MatchEntryResult(
                            result.map_err(|e| format!("{:?}", e)),
                        ))
                        .is_err()
                    {
                        error!("Failed to send response to script for MatchStorageEntry message.");
                    }
                },
                CacheStorageThreadMessage::MatchEntries {
                    cache_name,
                    request_url,
                    request_method,
                    request_headers,
                    ignore_search,
                    ignore_method,
                    ignore_vary,
                    callback,
                    proxy,
                    origin,
                } => {
                    self.engine.set_partition_key(proxy.partition_key.clone());
                    let result = self.engine.match_entries(
                        &origin,
                        &cache_name,
                        &request_url,
                        &request_method,
                        &request_headers,
                        ignore_search,
                        ignore_method,
                        ignore_vary,
                    );
                    if callback
                        .send(CacheStorageThreadResponse::MatchEntriesResult(
                            result.map_err(|e| format!("{:?}", e)),
                        ))
                        .is_err()
                    {
                        error!("Failed to send response to script for MatchEntries message.");
                    }
                },
                CacheStorageThreadMessage::DeleteEntry {
                    cache_name,
                    request_url,
                    request_method,
                    request_headers,
                    ignore_search,
                    ignore_method,
                    ignore_vary,
                    callback,
                    proxy,
                    origin,
                } => {
                    self.engine.set_partition_key(proxy.partition_key.clone());
                    let result = self.engine.delete_entry(
                        &origin,
                        &cache_name,
                        &request_url,
                        &request_method,
                        &request_headers,
                        ignore_search,
                        ignore_method,
                        ignore_vary,
                    );
                    if callback
                        .send(CacheStorageThreadResponse::DeleteEntryResult(
                            result.map_err(|e| format!("{:?}", e)),
                        ))
                        .is_err()
                    {
                        error!("Failed to send response to script for DeleteEntry message.");
                    }
                },
                CacheStorageThreadMessage::Exit(sender) => {
                    let _ = sender.send(());
                    break;
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use servo_url::ServoUrl;

    fn origin(url: &str) -> ImmutableOrigin {
        ServoUrl::parse(url).unwrap().origin()
    }

    fn entry(url: &str) -> CacheEntry {
        CacheEntry {
            request_url: url.to_owned(),
            request_method: "GET".to_owned(),
            request_headers: Vec::new(),
            request_reload_navigation: false,
            request_history_navigation: false,
            status: 200,
            status_text: "OK".to_owned(),
            headers: vec![("content-type".to_owned(), b"text/plain".to_vec())],
            body: b"cached".to_vec(),
        }
    }

    #[test]
    fn named_cache_lifecycle_is_origin_scoped() {
        let first_origin = origin("https://first.example/");
        let second_origin = origin("https://second.example/");
        let mut engine = InMemoryCacheStorageEngine::new();

        assert!(!engine.has_cache(&first_origin, "assets").unwrap());
        assert_eq!(
            engine.open_cache(&first_origin, "assets").unwrap(),
            "assets"
        );
        assert!(engine.has_cache(&first_origin, "assets").unwrap());
        assert!(!engine.has_cache(&second_origin, "assets").unwrap());
        assert_eq!(engine.cache_keys(&first_origin).unwrap(), vec!["assets"]);
        assert!(engine.delete_cache(&first_origin, "assets").unwrap());
        assert!(!engine.has_cache(&first_origin, "assets").unwrap());
        assert!(!engine.delete_cache(&first_origin, "assets").unwrap());
    }

    #[test]
    fn cache_names_are_isolated_by_top_level_partition() {
        let origin = origin("https://third-party.example/");
        let mut engine = InMemoryCacheStorageEngine::new();

        engine.set_partition_key(Some("https://first-party.example".to_owned()));
        engine.open_cache(&origin, "assets").unwrap();

        engine.set_partition_key(Some("https://second-party.example".to_owned()));
        assert!(!engine.has_cache(&origin, "assets").unwrap());

        engine.set_partition_key(Some("https://first-party.example".to_owned()));
        assert!(engine.has_cache(&origin, "assets").unwrap());
    }

    #[test]
    fn cache_storage_quota_allows_replacement_without_double_counting() {
        assert!(!has_available_quota(CACHE_STORAGE_QUOTA_BYTES, 0, 1));
        assert!(has_available_quota(CACHE_STORAGE_QUOTA_BYTES, 128, 128));
        assert!(has_available_quota(CACHE_STORAGE_QUOTA_BYTES - 128, 0, 128));
        assert!(!has_available_quota(
            CACHE_STORAGE_QUOTA_BYTES - 128,
            0,
            129
        ));
    }

    #[test]
    fn sqlite_cache_names_survive_engine_reopen() {
        let origin = origin("https://persistent.example/");
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().to_path_buf();

        {
            let mut engine = SqliteCacheStorageEngine::new(path.clone()).unwrap();
            engine.open_cache(&origin, "assets").unwrap();
        }

        let mut reopened = SqliteCacheStorageEngine::new(path).unwrap();
        assert!(reopened.has_cache(&origin, "assets").unwrap());
        assert_eq!(reopened.cache_keys(&origin).unwrap(), vec!["assets"]);
    }

    #[test]
    fn sqlite_cache_names_keep_partitions_across_reopen() {
        let origin = origin("https://persistent-partition.example/");
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().to_path_buf();

        {
            let mut engine = SqliteCacheStorageEngine::new(path.clone()).unwrap();
            engine.set_partition_key(Some("https://first-party.example".to_owned()));
            engine.open_cache(&origin, "assets").unwrap();
        }

        let mut reopened = SqliteCacheStorageEngine::new(path).unwrap();
        reopened.set_partition_key(Some("https://first-party.example".to_owned()));
        assert!(reopened.has_cache(&origin, "assets").unwrap());
        reopened.set_partition_key(Some("https://second-party.example".to_owned()));
        assert!(!reopened.has_cache(&origin, "assets").unwrap());
    }

    #[test]
    fn cache_entries_match_and_delete_with_search_options() {
        let origin = origin("https://entries.example/");
        let mut engine = InMemoryCacheStorageEngine::new();
        engine
            .put_entry(
                &origin,
                "assets",
                entry("https://entries.example/app.js?v=1"),
            )
            .unwrap();

        assert!(
            engine
                .match_entry(
                    &origin,
                    "assets",
                    "https://entries.example/app.js?v=2",
                    "GET",
                    &[],
                    false,
                    false,
                    false,
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(
            engine
                .match_entry(
                    &origin,
                    "assets",
                    "https://entries.example/app.js?v=2",
                    "GET",
                    &[],
                    true,
                    false,
                    false,
                )
                .unwrap()
                .unwrap()
                .body,
            b"cached"
        );
        assert_eq!(
            engine
                .match_entries(
                    &origin,
                    "assets",
                    "https://entries.example/app.js?v=2",
                    "GET",
                    &[],
                    true,
                    false,
                    false,
                )
                .unwrap()
                .len(),
            1
        );
        assert!(
            engine
                .delete_entry(
                    &origin,
                    "assets",
                    "https://entries.example/app.js?v=2",
                    "GET",
                    &[],
                    true,
                    false,
                    false,
                )
                .unwrap()
        );
        assert!(
            engine
                .match_entry(
                    &origin,
                    "assets",
                    "https://entries.example/app.js?v=1",
                    "GET",
                    &[],
                    false,
                    false,
                    false,
                )
                .unwrap()
                .is_none()
        );

        engine
            .put_entry(&origin, "assets", entry("https://entries.example/other.js"))
            .unwrap();
        assert_eq!(
            engine
                .match_entries(&origin, "assets", "", "", &[], true, true, true)
                .unwrap()
                .len(),
            1
        );
        assert!(engine.delete_cache(&origin, "assets").unwrap());
        assert!(
            engine
                .match_entry(
                    &origin,
                    "assets",
                    "https://entries.example/other.js",
                    "GET",
                    &[],
                    false,
                    false,
                    false,
                )
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn sqlite_cache_entries_survive_engine_reopen() {
        let origin = origin("https://persistent-entries.example/");
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().to_path_buf();

        {
            let mut engine = SqliteCacheStorageEngine::new(path.clone()).unwrap();
            engine
                .put_entry(
                    &origin,
                    "assets",
                    entry("https://persistent-entries.example/app.js"),
                )
                .unwrap();
        }

        let mut reopened = SqliteCacheStorageEngine::new(path).unwrap();
        let restored = reopened
            .match_entry(
                &origin,
                "assets",
                "https://persistent-entries.example/app.js",
                "GET",
                &[],
                false,
                false,
                false,
            )
            .unwrap()
            .unwrap();
        assert_eq!(restored.status, 200);
        assert_eq!(restored.body, b"cached");
        assert_eq!(restored.headers[0].0, "content-type");
    }

    #[test]
    fn sqlite_cache_match_honors_vary_after_reopen() {
        let origin = origin("https://vary-persistent.example/");
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().to_path_buf();

        {
            let mut engine = SqliteCacheStorageEngine::new(path.clone()).unwrap();
            let mut cached = entry("https://vary-persistent.example/page");
            cached
                .headers
                .push(("vary".to_owned(), b"accept-language".to_vec()));
            cached.request_headers = vec![("accept-language".to_owned(), b"en".to_vec())];
            engine.put_entry(&origin, "pages", cached).unwrap();
        }

        let mut reopened = SqliteCacheStorageEngine::new(path).unwrap();
        let french = vec![("accept-language".to_owned(), b"fr".to_vec())];
        let english = vec![("accept-language".to_owned(), b"en".to_vec())];
        assert!(
            reopened
                .match_entry(
                    &origin,
                    "pages",
                    "https://vary-persistent.example/page",
                    "GET",
                    &french,
                    false,
                    false,
                    false,
                )
                .unwrap()
                .is_none()
        );
        assert!(
            reopened
                .match_entry(
                    &origin,
                    "pages",
                    "https://vary-persistent.example/page",
                    "GET",
                    &english,
                    false,
                    false,
                    false,
                )
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn cache_match_honors_vary_request_headers() {
        let origin = origin("https://vary.example/");
        let mut engine = InMemoryCacheStorageEngine::new();
        let mut cached = entry("https://vary.example/page");
        cached
            .headers
            .push(("vary".to_owned(), b"accept-language".to_vec()));
        cached.request_headers = vec![("accept-language".to_owned(), b"en".to_vec())];
        engine.put_entry(&origin, "pages", cached).unwrap();

        let french = vec![("accept-language".to_owned(), b"fr".to_vec())];
        let english = vec![("accept-language".to_owned(), b"en".to_vec())];
        assert!(
            engine
                .match_entry(
                    &origin,
                    "pages",
                    "https://vary.example/page",
                    "GET",
                    &french,
                    false,
                    false,
                    false,
                )
                .unwrap()
                .is_none()
        );
        assert!(
            engine
                .match_entry(
                    &origin,
                    "pages",
                    "https://vary.example/page",
                    "GET",
                    &english,
                    false,
                    false,
                    false,
                )
                .unwrap()
                .is_some()
        );
        assert!(
            engine
                .match_entry(
                    &origin,
                    "pages",
                    "https://vary.example/page",
                    "GET",
                    &french,
                    false,
                    false,
                    true,
                )
                .unwrap()
                .is_some()
        );
    }
}
