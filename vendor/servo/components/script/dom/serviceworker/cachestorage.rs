/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use dom_struct::dom_struct;
use js::context::JSContext;
use script_bindings::reflector::{Reflector, reflect_dom_object_with_cx};
use script_bindings::root::DomRoot;
use servo_base::generic_channel::{GenericCallback, GenericSend};
use servo_url::ImmutableOrigin;
use storage_traits::cache_storage::{CacheStorageThreadMessage, CacheStorageThreadResponse};
use storage_traits::client_storage::{StorageIdentifier, StorageProxyMap, StorageType};

use crate::dom::Promise;
use crate::dom::bindings::codegen::Bindings::CacheBinding::CacheQueryOptions;
use crate::dom::bindings::codegen::Bindings::CacheStorageBinding::CacheStorageMethods;
use crate::dom::bindings::codegen::Bindings::RequestBinding::RequestInfo;
use crate::dom::bindings::error::Error;
use crate::dom::bindings::refcounted::Trusted;
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::bindings::str::DOMString;
use crate::dom::fetch::response::Response;
use crate::dom::globalscope::GlobalScope;
use crate::dom::serviceworker::cache::{Cache, response_from_entry};

#[derive(Clone, Copy, Debug)]
enum CacheStorageOperation {
    Match,
    Open,
    Has,
    Delete,
    Keys,
}

fn reject_cache_storage_error(cx: &mut JSContext, promise: &Promise, error: String) {
    if error == "QuotaExceeded" {
        promise.reject_error(
            cx,
            Error::QuotaExceeded {
                quota: None,
                requested: None,
            },
        );
    } else {
        promise.reject_error(cx, Error::Operation(Some(error)));
    }
}

/// <https://w3c.github.io/ServiceWorker/#cachestorage-interface>
#[dom_struct]
pub(crate) struct CacheStorage {
    reflector_: Reflector,

    #[no_trace]
    #[ignore_malloc_size_of = "GenericCallback"]
    callback: RefCell<Option<GenericCallback<CacheStorageThreadResponse>>>,

    // Dequeue of pending promises for backend operations.
    #[conditional_malloc_size_of]
    pending_promises: RefCell<VecDeque<Rc<Promise>>>,

    #[no_trace]
    #[ignore_malloc_size_of = "small operation tags paired with pending promises"]
    pending_operations: RefCell<VecDeque<CacheStorageOperation>>,
}

impl CacheStorage {
    fn new_inherited() -> CacheStorage {
        CacheStorage {
            reflector_: Reflector::new(),
            callback: Default::default(),
            pending_promises: Default::default(),
            pending_operations: Default::default(),
        }
    }

    pub(crate) fn new(cx: &mut JSContext, global: &GlobalScope) -> DomRoot<CacheStorage> {
        reflect_dom_object_with_cx(Box::new(CacheStorage::new_inherited()), global, cx)
    }

    /// Setup the callback to the backend service, if this hasn't been done already.
    fn get_or_setup_callback(&self) -> GenericCallback<CacheStorageThreadResponse> {
        if let Some(cb) = self.callback.borrow().as_ref() {
            return cb.clone();
        }

        let global = self.global();
        let response_listener = Trusted::new(self);

        let task_source = global
            .task_manager()
            .database_access_task_source()
            .to_sendable();
        let callback = GenericCallback::new(move |message| {
            let response_listener = response_listener.clone();
            let response = match message {
                Ok(inner) => Some(inner),
                Err(err) => {
                    error!("Error in CacheStorage callback {:?}.", err);
                    None
                },
            };
            task_source.queue(task!(set_request_result_to_database: move |cx| {
                let cache_storage = response_listener.root();
                cache_storage.handle_response(cx, response)
            }));
        })
        .expect("Could not create CacheStorage callback");

        *self.callback.borrow_mut() = Some(callback.clone());

        callback
    }

    fn handle_response(&self, cx: &mut JSContext, response: Option<CacheStorageThreadResponse>) {
        let pending_promise = self.pending_promises.borrow_mut().pop_front();
        let pending_operation = self.pending_operations.borrow_mut().pop_front();
        let Some((promise, operation)) = pending_promise.zip(pending_operation) else {
            error!("No pending promise and operation for CacheStorage response.");
            return;
        };

        let response = match response {
            Some(response) => response,
            None => {
                promise.reject_error(cx, Error::Operation(None));
                return;
            },
        };

        match (operation, response) {
            (
                CacheStorageOperation::Match,
                CacheStorageThreadResponse::MatchEntryResult(result),
            ) => match result {
                Ok(Some(entry)) => {
                    let response = response_from_entry(cx, &self.global(), entry);
                    promise.resolve_native(cx, &Some(response));
                },
                Ok(None) => promise.resolve_native(cx, &None::<Option<DomRoot<Response>>>),
                Err(err) => reject_cache_storage_error(cx, &promise, err),
            },
            (CacheStorageOperation::Open, CacheStorageThreadResponse::OpenCacheResult(result)) => {
                match result {
                    Ok(cache_name) => {
                        let global = self.global();
                        let cache = Cache::new(cx, &global, cache_name);
                        promise.resolve_native(cx, &cache);
                    },
                    Err(err) => reject_cache_storage_error(cx, &promise, err),
                }
            },
            // https://w3c.github.io/ServiceWorker/#cache-storage-has
            (CacheStorageOperation::Has, CacheStorageThreadResponse::HasCacheResult(result)) => {
                match result {
                    Ok(has_cache) => promise.resolve_native(cx, &has_cache),
                    Err(err) => reject_cache_storage_error(cx, &promise, err),
                }
            },
            (
                CacheStorageOperation::Delete,
                CacheStorageThreadResponse::DeleteCacheResult(result),
            ) => match result {
                Ok(deleted) => promise.resolve_native(cx, &deleted),
                Err(err) => reject_cache_storage_error(cx, &promise, err),
            },
            (CacheStorageOperation::Keys, CacheStorageThreadResponse::CacheKeysResult(result)) => {
                match result {
                    Ok(cache_names) => {
                        let cache_names: Vec<DOMString> =
                            cache_names.into_iter().map(DOMString::from).collect();
                        promise.resolve_native(cx, &cache_names);
                    },
                    Err(err) => reject_cache_storage_error(cx, &promise, err),
                }
            },
            (operation, response) => {
                error!(
                    "Unexpected CacheStorage response for operation {:?}: {:?}",
                    operation, response
                );
                promise.reject_error(cx, Error::Operation(None));
            },
        }
    }
}

/// <https://w3c.github.io/ServiceWorker/#relevant-name-to-cache-map>
pub(crate) fn relevant_name_to_cache_map(
    global: &GlobalScope,
    origin: ImmutableOrigin,
) -> Result<StorageProxyMap, Error> {
    // The relevant name to cache map for a CacheStorage object
    // is the name to cache map associated with the result of
    // running obtain a local storage bottle map with
    // the object’s relevant settings object and "caches".
    let handle = global.storage_threads().client_storage_handle();
    let message = handle
        .obtain_a_storage_bottle_map(
            StorageType::Local,
            global.webview_id(),
            StorageIdentifier::Caches,
            origin,
        )
        .recv();
    let Ok(response) = message else {
        return Err(Error::Operation(None));
    };
    let Ok(mut proxy_map) = response else {
        return Err(Error::Operation(None));
    };
    // CacheStorage is keyed by the origin and the top-level site partition.
    // The client-storage registry still returns the origin bottle, so attach
    // the partition to the proxy before sending the operation to the cache
    // backend. Service-worker globals inherit this URL from their registering
    // client when they are created.
    proxy_map.partition_key = global.storage_partition_key().map(str::to_owned);
    Ok(proxy_map)
}

impl CacheStorageMethods<crate::DomTypeHolder> for CacheStorage {
    fn Match_(
        &self,
        cx: &mut JSContext,
        input: RequestInfo,
        options: &CacheQueryOptions,
    ) -> Rc<Promise> {
        let global = self.global();
        let promise = Promise::new(cx, &global);
        let request = match input {
            RequestInfo::Request(request) => request,
            RequestInfo::USVString(url) => match crate::dom::fetch::request::Request::constructor(
                cx,
                &global,
                None,
                RequestInfo::USVString(url),
                &crate::dom::bindings::codegen::Bindings::RequestBinding::RequestInit::empty(),
            ) {
                Ok(request) => request,
                Err(error) => {
                    promise.reject_error(cx, error);
                    return promise;
                },
            },
        };
        let net_request = request.get_request();
        let request_headers = net_request
            .headers
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect();
        let origin = global.origin().immutable().clone();
        let proxy_map = match relevant_name_to_cache_map(&global, origin.clone()) {
            Ok(proxy_map) => proxy_map,
            Err(error) => {
                promise.reject_error(cx, error);
                return promise;
            },
        };
        let callback = self.get_or_setup_callback();
        if global
            .storage_threads()
            .send(CacheStorageThreadMessage::MatchStorageEntry {
                request_url: net_request.current_url().as_str().to_owned(),
                request_method: net_request.method.as_str().to_owned(),
                request_headers,
                ignore_search: options.ignoreSearch,
                ignore_method: options.ignoreMethod,
                ignore_vary: options.ignoreVary,
                callback,
                proxy: proxy_map,
                origin,
            })
            .is_err()
        {
            promise.reject_error(cx, Error::Operation(None));
            return promise;
        }
        self.pending_promises
            .borrow_mut()
            .push_back(promise.clone());
        self.pending_operations
            .borrow_mut()
            .push_back(CacheStorageOperation::Match);
        promise
    }

    /// <https://w3c.github.io/ServiceWorker/#cache-storage-open>
    fn Open(&self, cx: &mut JSContext, cache_name: DOMString) -> Rc<Promise> {
        let global = self.global();
        let promise = Promise::new(cx, &global);
        let callback = self.get_or_setup_callback();
        let origin = global.origin().immutable().clone();
        let proxy_map = match relevant_name_to_cache_map(&global, origin.clone()) {
            Ok(proxy_map) => proxy_map,
            Err(err) => {
                promise.reject_error(cx, err);
                return promise;
            },
        };
        if global
            .storage_threads()
            .send(CacheStorageThreadMessage::OpenCache {
                cache_name: cache_name.to_string(),
                callback,
                proxy: proxy_map,
                origin,
            })
            .is_err()
        {
            promise.reject_error(cx, Error::Operation(None));
            return promise;
        }

        self.pending_promises
            .borrow_mut()
            .push_back(promise.clone());
        self.pending_operations
            .borrow_mut()
            .push_back(CacheStorageOperation::Open);
        promise
    }

    /// <https://w3c.github.io/ServiceWorker/#cache-storage-has>
    fn Has(&self, cx: &mut JSContext, cache_name: DOMString) -> Rc<Promise> {
        let global = self.global();

        // Step 1: Let promise be a new promise.
        let promise = Promise::new(cx, &global);

        // Step 2: Run the following substeps in parallel:
        let callback = self.get_or_setup_callback();
        let origin = global.origin().immutable().clone();
        let proxy_map = match relevant_name_to_cache_map(&global, origin.clone()) {
            Ok(proxy_map) => proxy_map,
            Err(err) => {
                promise.reject_error(cx, err);
                return promise;
            },
        };
        if global
            .storage_threads()
            .send(CacheStorageThreadMessage::HasCache {
                cache_name: cache_name.to_string(),
                callback,
                proxy: proxy_map,
                origin,
            })
            .is_err()
        {
            promise.reject_error(cx, Error::Operation(None));
            return promise;
        }

        self.pending_promises
            .borrow_mut()
            .push_back(promise.clone());
        self.pending_operations
            .borrow_mut()
            .push_back(CacheStorageOperation::Has);

        promise
    }

    /// <https://w3c.github.io/ServiceWorker/#cache-storage-delete>
    fn Delete(&self, cx: &mut JSContext, cache_name: DOMString) -> Rc<Promise> {
        let global = self.global();
        let promise = Promise::new(cx, &global);
        let callback = self.get_or_setup_callback();
        let origin = global.origin().immutable().clone();
        let proxy_map = match relevant_name_to_cache_map(&global, origin.clone()) {
            Ok(proxy_map) => proxy_map,
            Err(err) => {
                promise.reject_error(cx, err);
                return promise;
            },
        };
        if global
            .storage_threads()
            .send(CacheStorageThreadMessage::DeleteCache {
                cache_name: cache_name.to_string(),
                callback,
                proxy: proxy_map,
                origin,
            })
            .is_err()
        {
            promise.reject_error(cx, Error::Operation(None));
            return promise;
        }

        self.pending_promises
            .borrow_mut()
            .push_back(promise.clone());
        self.pending_operations
            .borrow_mut()
            .push_back(CacheStorageOperation::Delete);

        promise
    }

    /// <https://w3c.github.io/ServiceWorker/#cache-storage-keys>
    fn Keys(&self, cx: &mut JSContext) -> Rc<Promise> {
        let global = self.global();
        let promise = Promise::new(cx, &global);
        let callback = self.get_or_setup_callback();
        let origin = global.origin().immutable().clone();
        let proxy_map = match relevant_name_to_cache_map(&global, origin.clone()) {
            Ok(proxy_map) => proxy_map,
            Err(err) => {
                promise.reject_error(cx, err);
                return promise;
            },
        };
        if global
            .storage_threads()
            .send(CacheStorageThreadMessage::CacheKeys {
                callback,
                proxy: proxy_map,
                origin,
            })
            .is_err()
        {
            promise.reject_error(cx, Error::Operation(None));
            return promise;
        }

        self.pending_promises
            .borrow_mut()
            .push_back(promise.clone());
        self.pending_operations
            .borrow_mut()
            .push_back(CacheStorageOperation::Keys);

        promise
    }
}
