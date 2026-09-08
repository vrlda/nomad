/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://www.mozilla.org/MPL/2.0/. */

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use dom_struct::dom_struct;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use hyper_serde::Serde;
use js::context::JSContext;
use js::jsval::UndefinedValue;
use net_traits::blob_url_store::UrlWithBlobClaim;
use net_traits::http_status::HttpStatus;
use net_traits::request::{RequestBuilder, ServiceWorkersMode};
use script_bindings::reflector::{Reflector, reflect_dom_object_with_cx};
use script_bindings::root::DomRoot;
use servo_base::generic_channel::{GenericCallback, GenericSend};
use servo_url::ServoUrl;
use storage_traits::cache_storage::{
    CacheEntry, CacheStorageThreadMessage, CacheStorageThreadResponse,
};

use crate::body::BodyMixin;
use crate::dom::Promise;
use crate::dom::bindings::codegen::Bindings::CacheBinding::{CacheMethods, CacheQueryOptions};
use crate::dom::bindings::codegen::Bindings::RequestBinding::{RequestInfo, RequestInit};
use crate::dom::bindings::codegen::Bindings::ResponseBinding::ResponseMethods;
use crate::dom::bindings::error::{Error, Fallible};
use crate::dom::bindings::refcounted::Trusted;
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::csp::Violation;
use crate::dom::fetch::{request::Request, response::Response};
use crate::dom::globalscope::GlobalScope;
use crate::dom::serviceworker::cachestorage::relevant_name_to_cache_map;
use crate::fetch::{CspViolationsProcessor, RequestWithGlobalScope, load_whole_resource};

#[derive(Clone, Copy, Debug)]
enum CacheOperation {
    Match,
    MatchAll,
    Keys,
    PutAll { remaining: usize },
    Put,
    Delete,
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

/// A named Cache object backed by the browser's storage thread.
#[dom_struct]
pub(crate) struct Cache {
    reflector_: Reflector,
    name: String,

    #[no_trace]
    #[ignore_malloc_size_of = "GenericCallback"]
    callback: RefCell<Option<GenericCallback<CacheStorageThreadResponse>>>,

    #[conditional_malloc_size_of]
    pending_promises: RefCell<VecDeque<Rc<Promise>>>,

    #[no_trace]
    #[ignore_malloc_size_of = "small operation tags paired with pending promises"]
    pending_operations: RefCell<VecDeque<CacheOperation>>,
}

impl Cache {
    fn new_inherited(name: String) -> Cache {
        Cache {
            reflector_: Reflector::new(),
            name,
            callback: Default::default(),
            pending_promises: Default::default(),
            pending_operations: Default::default(),
        }
    }

    pub(crate) fn new(cx: &mut JSContext, global: &GlobalScope, name: String) -> DomRoot<Cache> {
        reflect_dom_object_with_cx(Box::new(Cache::new_inherited(name)), global, cx)
    }

    fn get_or_setup_callback(&self) -> GenericCallback<CacheStorageThreadResponse> {
        if let Some(callback) = self.callback.borrow().as_ref() {
            return callback.clone();
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
                    error!("Error in Cache callback {:?}.", err);
                    None
                },
            };
            task_source.queue(task!(set_cache_result: move |cx| {
                response_listener.root().handle_response(cx, response)
            }));
        })
        .expect("Could not create Cache callback");

        *self.callback.borrow_mut() = Some(callback.clone());
        callback
    }

    fn handle_response(&self, cx: &mut JSContext, response: Option<CacheStorageThreadResponse>) {
        let promise = self.pending_promises.borrow_mut().pop_front();
        let operation = self.pending_operations.borrow_mut().pop_front();
        let Some((promise, operation)) = promise.zip(operation) else {
            error!("No pending promise and operation for Cache response.");
            return;
        };

        let Some(response) = response else {
            promise.reject_error(cx, Error::Operation(None));
            return;
        };

        match (operation, response) {
            (CacheOperation::Match, CacheStorageThreadResponse::MatchEntryResult(result)) => {
                match result {
                    Ok(Some(entry)) => {
                        let global = self.global();
                        let response = response_from_entry(cx, &global, entry);
                        promise.resolve_native(cx, &Some(response));
                    },
                    Ok(None) => promise.resolve_native(cx, &None::<Option<DomRoot<Response>>>),
                    Err(err) => reject_cache_storage_error(cx, &promise, err),
                }
            },
            (CacheOperation::MatchAll, CacheStorageThreadResponse::MatchEntriesResult(result)) => {
                match result {
                    Ok(entries) => {
                        let global = self.global();
                        let responses: Vec<DomRoot<Response>> = entries
                            .into_iter()
                            .map(|entry| response_from_entry(cx, &global, entry))
                            .collect();
                        promise.resolve_native(cx, &responses);
                    },
                    Err(err) => reject_cache_storage_error(cx, &promise, err),
                }
            },
            (CacheOperation::Keys, CacheStorageThreadResponse::MatchEntriesResult(result)) => {
                match result {
                    Ok(entries) => {
                        let global = self.global();
                        let requests: Vec<DomRoot<Request>> = entries
                            .into_iter()
                            .filter_map(|entry| {
                                let url = ServoUrl::parse(&entry.request_url).ok()?;
                                let method =
                                    Method::from_bytes(entry.request_method.as_bytes()).ok()?;
                                let mut headers = HeaderMap::new();
                                for (name, value) in entry.request_headers {
                                    let (Ok(name), Ok(value)) = (
                                        HeaderName::from_bytes(name.as_bytes()),
                                        HeaderValue::from_bytes(&value),
                                    ) else {
                                        continue;
                                    };
                                    headers.append(name, value);
                                }
                                let net_request = RequestBuilder::new(
                                    global.webview_id(),
                                    UrlWithBlobClaim::from_url_without_having_claimed_blob(url),
                                    global.get_referrer(),
                                )
                                .method(method)
                                .headers(headers)
                                .use_url_credentials(true)
                                .service_workers_mode(ServiceWorkersMode::None)
                                .with_global_scope(&global)
                                .build();
                                let request =
                                    Request::from_net_request(cx, &global, None, net_request);
                                request.set_navigation_flags(
                                    entry.request_reload_navigation,
                                    entry.request_history_navigation,
                                );
                                Some(request)
                            })
                            .collect();
                        promise.resolve_native(cx, &requests);
                    },
                    Err(err) => reject_cache_storage_error(cx, &promise, err),
                }
            },
            (CacheOperation::Put, CacheStorageThreadResponse::PutEntryResult(result)) => {
                match result {
                    Ok(()) => promise.resolve_native(cx, &UndefinedValue()),
                    Err(err) => reject_cache_storage_error(cx, &promise, err),
                }
            },
            (
                CacheOperation::PutAll { remaining },
                CacheStorageThreadResponse::PutEntryResult(result),
            ) => match result {
                Ok(()) if remaining == 1 => promise.resolve_native(cx, &UndefinedValue()),
                Ok(()) => {},
                Err(err) => reject_cache_storage_error(cx, &promise, err),
            },
            (CacheOperation::Delete, CacheStorageThreadResponse::DeleteEntryResult(result)) => {
                match result {
                    Ok(deleted) => promise.resolve_native(cx, &deleted),
                    Err(err) => reject_cache_storage_error(cx, &promise, err),
                }
            },
            (operation, response) => {
                error!(
                    "Unexpected Cache response for operation {:?}: {:?}",
                    operation, response
                );
                promise.reject_error(cx, Error::Operation(None));
            },
        }
    }

    fn send_entry(&self, cx: &mut JSContext, promise: Rc<Promise>, entry: CacheEntry) {
        self.send_entry_with_operation(cx, promise, entry, CacheOperation::Put);
    }

    fn send_entry_with_operation(
        &self,
        cx: &mut JSContext,
        promise: Rc<Promise>,
        entry: CacheEntry,
        operation: CacheOperation,
    ) {
        let global = self.global();
        let origin = global.origin().immutable().clone();
        let proxy_map = match relevant_name_to_cache_map(&global, origin.clone()) {
            Ok(proxy_map) => proxy_map,
            Err(err) => {
                promise.reject_error(cx, err);
                return;
            },
        };
        let callback = self.get_or_setup_callback();
        let send_result = global
            .storage_threads()
            .send(CacheStorageThreadMessage::PutEntry {
                cache_name: self.name.clone(),
                entry,
                callback,
                proxy: proxy_map,
                origin,
            })
            .map_err(|_| Error::Operation(None));
        if let Err(error) = send_result {
            promise.reject_error(cx, error);
        } else {
            self.pending_promises.borrow_mut().push_back(promise);
            self.pending_operations.borrow_mut().push_back(operation);
        }
    }

    fn fetch_entry(&self, cx: &mut JSContext, request: &Request) -> Result<CacheEntry, Error> {
        let global = self.global();
        let net_request = request.get_request();
        if net_request.method != Method::GET {
            return Err(Error::Type(
                c"Cache.add() only accepts GET requests".to_owned(),
            ));
        }

        let request_builder = RequestBuilder::new(
            global.webview_id(),
            net_request.current_url_with_blob_claim(),
            net_request.referrer.clone(),
        )
        .method(net_request.method.clone())
        .headers(net_request.headers.clone())
        .destination(net_request.destination.clone())
        .mode(net_request.mode.clone())
        .cache_mode(net_request.cache_mode.clone())
        .credentials_mode(net_request.credentials_mode.clone())
        .use_url_credentials(net_request.use_url_credentials)
        .redirect_mode(net_request.redirect_mode.clone())
        .referrer_policy(net_request.referrer_policy.clone())
        .service_workers_mode(ServiceWorkersMode::None)
        .with_global_scope(&global);
        let (metadata, body, _) = load_whole_resource(
            request_builder,
            &global.core_resource_thread(),
            &global,
            &CacheCspProcessor,
            cx,
        )
        .map_err(|_| Error::Network(None))?;
        if !metadata.status.is_success() {
            return Err(Error::Network(None));
        }

        let headers = metadata
            .headers
            .map(Serde::into_inner)
            .unwrap_or_default()
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect();
        let request_headers = net_request
            .headers
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect();
        Ok(CacheEntry {
            request_url: net_request.current_url().as_str().to_owned(),
            request_method: net_request.method.as_str().to_owned(),
            request_headers,
            request_reload_navigation: net_request.reload_navigation,
            request_history_navigation: net_request.history_navigation,
            status: metadata.status.raw_code(),
            status_text: String::from_utf8_lossy(metadata.status.message()).into_owned(),
            headers,
            body,
        })
    }

    fn request_from_info(
        &self,
        cx: &mut JSContext,
        input: RequestInfo,
    ) -> Fallible<DomRoot<Request>> {
        let global = self.global();
        match input {
            RequestInfo::Request(request) => Ok(request),
            RequestInfo::USVString(url) => Request::constructor(
                cx,
                &global,
                None,
                RequestInfo::USVString(url),
                &RequestInit::empty(),
            ),
        }
    }

    fn send_request_operation(
        &self,
        promise: Rc<Promise>,
        operation: CacheOperation,
        request: Option<&Request>,
        options: &CacheQueryOptions,
    ) -> Result<(), Error> {
        let global = self.global();
        let origin = global.origin().immutable().clone();
        let proxy_map = relevant_name_to_cache_map(&global, origin.clone())?;
        let (request_url, request_method, request_headers) = match request {
            Some(request) => {
                let net_request = request.get_request();
                let request_headers = net_request
                    .headers
                    .iter()
                    .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                    .collect();
                let request_method = if options.ignoreMethod {
                    String::new()
                } else {
                    net_request.method.as_str().to_owned()
                };
                (
                    net_request.current_url().as_str().to_owned(),
                    request_method,
                    request_headers,
                )
            },
            None => (String::new(), String::new(), Vec::new()),
        };
        let keys_without_filter = matches!(operation, CacheOperation::Keys) && request.is_none();
        let ignore_search = options.ignoreSearch || keys_without_filter;
        let ignore_method = options.ignoreMethod || keys_without_filter;
        let ignore_vary = options.ignoreVary || keys_without_filter;
        let callback = self.get_or_setup_callback();
        let message = match operation {
            CacheOperation::Match => CacheStorageThreadMessage::MatchEntry {
                cache_name: self.name.clone(),
                request_url,
                request_method,
                request_headers,
                ignore_search,
                ignore_method,
                ignore_vary,
                callback,
                proxy: proxy_map,
                origin,
            },
            CacheOperation::MatchAll => CacheStorageThreadMessage::MatchEntries {
                cache_name: self.name.clone(),
                request_url,
                request_method,
                request_headers,
                ignore_search,
                ignore_method,
                ignore_vary,
                callback,
                proxy: proxy_map,
                origin,
            },
            CacheOperation::Delete => CacheStorageThreadMessage::DeleteEntry {
                cache_name: self.name.clone(),
                request_url,
                request_method,
                request_headers,
                ignore_search,
                ignore_method,
                ignore_vary,
                callback,
                proxy: proxy_map,
                origin,
            },
            CacheOperation::Keys => CacheStorageThreadMessage::MatchEntries {
                cache_name: self.name.clone(),
                request_url,
                request_method,
                request_headers,
                ignore_search,
                ignore_method,
                ignore_vary,
                callback,
                proxy: proxy_map,
                origin,
            },
            CacheOperation::PutAll { .. } => unreachable!("putAll uses send_entry"),
            CacheOperation::Put => unreachable!("put uses send_entry"),
        };
        global
            .storage_threads()
            .send(message)
            .map_err(|_| Error::Operation(None))?;
        self.pending_promises.borrow_mut().push_back(promise);
        self.pending_operations.borrow_mut().push_back(operation);
        Ok(())
    }
}

impl CacheMethods<crate::DomTypeHolder> for Cache {
    fn Add(&self, cx: &mut JSContext, input: RequestInfo) -> Rc<Promise> {
        let global = self.global();
        let promise = Promise::new(cx, &global);
        let request = match self.request_from_info(cx, input) {
            Ok(request) => request,
            Err(error) => {
                promise.reject_error(cx, error);
                return promise;
            },
        };
        let entry = match self.fetch_entry(cx, &request) {
            Ok(entry) => entry,
            Err(error) => {
                promise.reject_error(cx, error);
                return promise;
            },
        };
        self.send_entry(cx, promise.clone(), entry);
        promise
    }

    fn AddAll(&self, cx: &mut JSContext, inputs: Vec<RequestInfo>) -> Rc<Promise> {
        let global = self.global();
        let promise = Promise::new(cx, &global);
        let mut entries = Vec::with_capacity(inputs.len());
        for input in inputs {
            let request = match self.request_from_info(cx, input) {
                Ok(request) => request,
                Err(error) => {
                    promise.reject_error(cx, error);
                    return promise;
                },
            };
            match self.fetch_entry(cx, &request) {
                Ok(entry) => entries.push(entry),
                Err(error) => {
                    promise.reject_error(cx, error);
                    return promise;
                },
            }
        }
        if entries.is_empty() {
            promise.resolve_native(cx, &UndefinedValue());
            return promise;
        }
        let remaining = entries.len();
        for (index, entry) in entries.into_iter().enumerate() {
            self.send_entry_with_operation(
                cx,
                promise.clone(),
                entry,
                CacheOperation::PutAll {
                    remaining: remaining - index,
                },
            );
        }
        promise
    }

    fn Match_(
        &self,
        cx: &mut JSContext,
        input: RequestInfo,
        options: &CacheQueryOptions,
    ) -> Rc<Promise> {
        let global = self.global();
        let promise = Promise::new(cx, &global);
        let request = match self.request_from_info(cx, input) {
            Ok(request) => request,
            Err(error) => {
                promise.reject_error(cx, error);
                return promise;
            },
        };
        if let Err(error) = self.send_request_operation(
            promise.clone(),
            CacheOperation::Match,
            Some(&request),
            options,
        ) {
            promise.reject_error(cx, error);
        }
        promise
    }

    fn MatchAll(
        &self,
        cx: &mut JSContext,
        input: RequestInfo,
        options: &CacheQueryOptions,
    ) -> Rc<Promise> {
        let global = self.global();
        let promise = Promise::new(cx, &global);
        let request = match self.request_from_info(cx, input) {
            Ok(request) => request,
            Err(error) => {
                promise.reject_error(cx, error);
                return promise;
            },
        };
        if let Err(error) = self.send_request_operation(
            promise.clone(),
            CacheOperation::MatchAll,
            Some(&request),
            options,
        ) {
            promise.reject_error(cx, error);
        }
        promise
    }

    fn Keys(
        &self,
        cx: &mut JSContext,
        input: Option<RequestInfo>,
        options: &CacheQueryOptions,
    ) -> Rc<Promise> {
        let global = self.global();
        let promise = Promise::new(cx, &global);
        let request = match input {
            Some(input) => match self.request_from_info(cx, input) {
                Ok(request) => Some(request),
                Err(error) => {
                    promise.reject_error(cx, error);
                    return promise;
                },
            },
            None => None,
        };
        if let Err(error) = self.send_request_operation(
            promise.clone(),
            CacheOperation::Keys,
            request.as_deref(),
            options,
        ) {
            promise.reject_error(cx, error);
        }
        promise
    }

    fn Put(&self, cx: &mut JSContext, input: RequestInfo, response: &Response) -> Rc<Promise> {
        let global = self.global();
        let promise = Promise::new(cx, &global);
        let request = match self.request_from_info(cx, input) {
            Ok(request) => request,
            Err(error) => {
                promise.reject_error(cx, error);
                return promise;
            },
        };
        let net_request = request.get_request();
        if net_request.method != Method::GET {
            promise.reject_error(
                cx,
                Error::Type(c"Cache.put() only accepts GET requests".to_owned()),
            );
            return promise;
        }
        if response.is_unusable() {
            promise.reject_error(
                cx,
                Error::Type(c"Cache.put() cannot use a disturbed response".to_owned()),
            );
            return promise;
        }

        let entry = CacheEntry {
            request_url: net_request.current_url().as_str().to_owned(),
            request_method: net_request.method.as_str().to_owned(),
            request_headers: net_request
                .headers
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                .collect(),
            request_reload_navigation: net_request.reload_navigation,
            request_history_navigation: net_request.history_navigation,
            status: response.Status(),
            status_text: String::from_utf8_lossy(response.StatusText().as_ref()).into_owned(),
            headers: response.Headers(cx).sort_and_combine(),
            body: Vec::new(),
        };
        let trusted_cache = Trusted::new(self);
        let Some(stream) = response.body() else {
            self.send_entry(cx, promise.clone(), entry);
            return promise;
        };
        let reader = match stream.acquire_default_reader(cx) {
            Ok(reader) => reader,
            Err(error) => {
                promise.reject_error(cx, error);
                return promise;
            },
        };
        let success_promise = promise.clone();
        let failure_promise = promise.clone();
        reader.read_all_bytes(
            cx,
            Rc::new(move |cx, body| {
                let mut entry = entry.clone();
                entry.body = body.to_vec();
                trusted_cache
                    .root()
                    .send_entry(cx, success_promise.clone(), entry);
            }),
            Rc::new(move |cx, _error| {
                failure_promise.reject_error(cx, Error::Operation(None));
            }),
        );
        promise
    }

    fn Delete(
        &self,
        cx: &mut JSContext,
        input: RequestInfo,
        options: &CacheQueryOptions,
    ) -> Rc<Promise> {
        let global = self.global();
        let promise = Promise::new(cx, &global);
        let request = match self.request_from_info(cx, input) {
            Ok(request) => request,
            Err(error) => {
                promise.reject_error(cx, error);
                return promise;
            },
        };
        if let Err(error) = self.send_request_operation(
            promise.clone(),
            CacheOperation::Delete,
            Some(&request),
            options,
        ) {
            promise.reject_error(cx, error);
        }
        promise
    }
}

struct CacheCspProcessor;

impl CspViolationsProcessor for CacheCspProcessor {
    fn process_csp_violations(&self, _cx: &mut JSContext, _violations: Vec<Violation>) {}
}

pub(crate) fn response_from_entry(
    cx: &mut JSContext,
    global: &GlobalScope,
    entry: CacheEntry,
) -> DomRoot<Response> {
    let response = Response::new(cx, global);
    response.set_status(&HttpStatus::new_raw(
        entry.status,
        entry.status_text.into_bytes(),
    ));

    let mut headers = HeaderMap::new();
    for (name, value) in entry.headers {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_bytes(&value) else {
            continue;
        };
        headers.append(name, value);
    }
    response.set_headers(cx, Some(hyper_serde::Serde(headers)));
    if let Ok(url) = ServoUrl::parse(&entry.request_url) {
        response.set_final_url(url);
    }
    if !entry.body.is_empty() {
        response.stream_chunk(cx, entry.body);
    }
    response.finish(cx);
    response
}
