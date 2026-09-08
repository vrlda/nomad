/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::collections::VecDeque;
use std::rc::Rc;

use dom_struct::dom_struct;
use js::context::JSContext;
use script_bindings::cell::DomRefCell;
use script_bindings::reflector::{Reflector, reflect_dom_object_with_cx};
use script_bindings::script_runtime::temp_cx;
use servo_base::generic_channel::GenericCallback;
use servo_constellation_traits::ScriptToConstellationMessage;

use crate::dom::bindings::codegen::Bindings::ClientBinding::FrameType;
use crate::dom::bindings::codegen::Bindings::ClientsBinding::{ClientQueryOptions, ClientsMethods};
use crate::dom::bindings::error::Error;
use crate::dom::bindings::inheritance::Castable;
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::bindings::root::DomRoot;
use crate::dom::bindings::str::USVString;
use crate::dom::client::Client;
use crate::dom::globalscope::GlobalScope;
use crate::dom::promise::Promise;
use crate::dom::serviceworker::serviceworkerglobalscope::{
    ServiceWorkerGlobalScope, ServiceWorkerScriptMsg,
};
use crate::dom::serviceworker::windowclient::WindowClient;

#[dom_struct]
pub(crate) struct Clients {
    reflector_: Reflector,

    #[conditional_malloc_size_of]
    pending_match_all: DomRefCell<VecDeque<Rc<Promise>>>,

    #[conditional_malloc_size_of]
    pending_claim: DomRefCell<VecDeque<Rc<Promise>>>,

    #[conditional_malloc_size_of]
    pending_open_window: DomRefCell<VecDeque<Rc<Promise>>>,
}

impl Clients {
    fn new_inherited() -> Clients {
        Clients {
            reflector_: Reflector::new(),
            pending_match_all: DomRefCell::new(VecDeque::new()),
            pending_claim: DomRefCell::new(VecDeque::new()),
            pending_open_window: DomRefCell::new(VecDeque::new()),
        }
    }

    pub(crate) fn new(cx: &mut JSContext, global: &GlobalScope) -> DomRoot<Clients> {
        reflect_dom_object_with_cx(Box::new(Self::new_inherited()), global, cx)
    }

    pub(crate) fn handle_match_all_response(
        &self,
        cx: &mut JSContext,
        result: Result<Vec<servo_constellation_traits::ServiceWorkerClientInfo>, String>,
    ) {
        let Some(promise) = self.pending_match_all.borrow_mut().pop_front() else {
            return;
        };

        let Ok(infos) = result else {
            promise.reject_error(cx, Error::Operation(None));
            return;
        };

        let global = self.global();
        global
            .downcast::<ServiceWorkerGlobalScope>()
            .expect("Clients must belong to a service worker global");
        let clients = infos
            .into_iter()
            .map(|info| {
                let frame_type = match info.frame_type {
                    servo_constellation_traits::ServiceWorkerClientFrameType::TopLevel => {
                        FrameType::Top_level
                    },
                    servo_constellation_traits::ServiceWorkerClientFrameType::Nested => {
                        FrameType::Nested
                    },
                };
                WindowClient::new(cx, &global, info.url, frame_type, info.pipeline_id)
            })
            .map(DomRoot::upcast::<Client>)
            .collect::<Vec<_>>();
        promise.resolve_native(cx, &clients);
    }

    pub(crate) fn handle_claim_response(&self, cx: &mut JSContext, result: Result<(), String>) {
        let Some(promise) = self.pending_claim.borrow_mut().pop_front() else {
            return;
        };
        match result {
            Ok(()) => promise.resolve_native(cx, &()),
            Err(_) => promise.reject_error(cx, Error::Operation(None)),
        }
    }

    pub(crate) fn handle_open_window_response(
        &self,
        cx: &mut JSContext,
        result: Result<Option<servo_constellation_traits::ServiceWorkerClientInfo>, String>,
    ) {
        let Some(promise) = self.pending_open_window.borrow_mut().pop_front() else {
            return;
        };
        match result {
            Err(_) => promise.reject_error(cx, Error::Operation(None)),
            Ok(None) => promise.resolve_native(cx, &None::<DomRoot<WindowClient>>),
            Ok(Some(info)) => {
                let client = WindowClient::new(
                    cx,
                    &self.global(),
                    info.url,
                    FrameType::Top_level,
                    info.pipeline_id,
                );
                promise.resolve_native(cx, &Some(&*client));
            },
        }
    }
}

impl ClientsMethods<crate::DomTypeHolder> for Clients {
    /// <https://w3c.github.io/ServiceWorker/#dom-clients-matchall>
    fn MatchAll(&self, options: &ClientQueryOptions) -> Rc<Promise> {
        #[expect(unsafe_code)]
        let mut cx = unsafe { temp_cx() };
        let global = self.global();
        let promise = Promise::new(&mut cx, &global);
        let service_worker = global
            .downcast::<ServiceWorkerGlobalScope>()
            .expect("Clients must belong to a service worker global");
        let callback_sender = service_worker.client_result_sender();
        let callback = GenericCallback::new(move |message| {
            let result = match message {
                Ok(result) => result,
                Err(_) => Err("Service-worker client query failed".to_owned()),
            };
            let _ = callback_sender.send(ServiceWorkerScriptMsg::ClientsMatchAllResult(result));
        })
        .expect("Could not create service-worker client query callback");

        self.pending_match_all
            .borrow_mut()
            .push_back(promise.clone());
        let query = ScriptToConstellationMessage::ServiceWorkerClientQuery {
            origin: global.origin().immutable().clone(),
            scope_url: service_worker.scope_url().clone(),
            worker_id: service_worker.service_worker_id(),
            partition_key: global.storage_partition_key().map(str::to_owned),
            include_uncontrolled: options.includeUncontrolled,
            result_handler: callback,
        };
        if global.script_to_constellation_chan().send(query).is_err() {
            self.pending_match_all.borrow_mut().pop_back();
            promise.reject_error(&mut cx, Error::Operation(None));
        }
        promise
    }

    /// <https://w3c.github.io/ServiceWorker/#dom-clients-claim>
    fn Claim(&self) -> Rc<Promise> {
        #[expect(unsafe_code)]
        let mut cx = unsafe { temp_cx() };
        let global = self.global();
        let promise = Promise::new(&mut cx, &global);
        let service_worker = global
            .downcast::<ServiceWorkerGlobalScope>()
            .expect("Clients must belong to a service worker global");
        let callback_sender = service_worker.client_result_sender();
        let callback = GenericCallback::new(move |message| {
            let result = match message {
                Ok(result) => result,
                Err(_) => Err("Service-worker claim failed".to_owned()),
            };
            let _ = callback_sender.send(ServiceWorkerScriptMsg::ClientsClaimResult(result));
        })
        .expect("Could not create service-worker claim callback");

        self.pending_claim.borrow_mut().push_back(promise.clone());
        let query = ScriptToConstellationMessage::ServiceWorkerClaimClients {
            origin: global.origin().immutable().clone(),
            scope_url: service_worker.scope_url().clone(),
            script_url: service_worker.script_url(),
            worker_id: service_worker.service_worker_id(),
            registration_id: service_worker.registration_id(),
            partition_key: global.storage_partition_key().map(str::to_owned),
            result_handler: callback,
        };
        if global.script_to_constellation_chan().send(query).is_err() {
            self.pending_claim.borrow_mut().pop_back();
            promise.reject_error(&mut cx, Error::Operation(None));
        }
        promise
    }

    /// <https://w3c.github.io/ServiceWorker/#dom-clients-openwindow>
    fn OpenWindow(&self, url: USVString) -> Rc<Promise> {
        #[expect(unsafe_code)]
        let mut cx = unsafe { temp_cx() };
        let global = self.global();
        let promise = Promise::new(&mut cx, &global);
        let service_worker = global
            .downcast::<ServiceWorkerGlobalScope>()
            .expect("Clients must belong to a service worker global");
        let Ok(url) = global.api_base_url().join(&url.0) else {
            promise.reject_error(&mut cx, Error::Type(c"Invalid URL".to_owned()));
            return promise;
        };
        if !matches!(url.scheme(), "http" | "https") {
            promise.reject_error(&mut cx, Error::Type(c"Unsupported URL scheme".to_owned()));
            return promise;
        }
        if &url.origin() != global.origin().immutable() {
            promise.reject_error(&mut cx, Error::Security(None));
            return promise;
        }

        let callback_sender = service_worker.client_result_sender();
        let callback = GenericCallback::new(move |message| {
            let result = match message {
                Ok(result) => result,
                Err(_) => Err("Service-worker openWindow failed".to_owned()),
            };
            let _ = callback_sender.send(ServiceWorkerScriptMsg::ClientsOpenWindowResult(result));
        })
        .expect("Could not create service-worker openWindow callback");

        self.pending_open_window
            .borrow_mut()
            .push_back(promise.clone());
        let query = ScriptToConstellationMessage::ServiceWorkerOpenWindow {
            origin: global.origin().immutable().clone(),
            scope_url: service_worker.scope_url().clone(),
            script_url: service_worker.script_url(),
            worker_id: service_worker.service_worker_id(),
            opener_webview_id: service_worker.webview_id(),
            url,
            result_handler: callback,
        };
        if global.script_to_constellation_chan().send(query).is_err() {
            self.pending_open_window.borrow_mut().pop_back();
            promise.reject_error(&mut cx, Error::Operation(None));
        }
        promise
    }
}
