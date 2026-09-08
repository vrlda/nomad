/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::rc::Rc;
use std::thread;

use crossbeam_channel::Receiver;
use dom_struct::dom_struct;
use http::StatusCode;
use ipc_channel::ipc::IpcSender;
use js::context::JSContext;
use js::jsapi::IsPromiseObject;
use js::jsval::UndefinedValue;
use js::realm::CurrentRealm;
use js::rust::{HandleObject, HandleValue, IntoHandle};
use net_traits::http_status::HttpStatus;
use net_traits::{CustomResponse, CustomResponseMediator};
use script_bindings::cell::DomRefCell;
use script_bindings::reflector::reflect_dom_object_with_proto;
use script_bindings::script_runtime::temp_cx;
use stylo_atoms::Atom;

use crate::body::BodyMixin;
use crate::dom::bindings::codegen::Bindings::ExtendableEventBinding::ExtendableEventMethods;
use crate::dom::bindings::codegen::Bindings::FetchEventBinding::{
    FetchEventInit, FetchEventMethods,
};
use crate::dom::bindings::codegen::Bindings::ResponseBinding::ResponseMethods;
use crate::dom::bindings::conversions::root_from_object;
use crate::dom::bindings::error::{Error, ErrorResult, Fallible};
use crate::dom::bindings::inheritance::Castable;
use crate::dom::bindings::refcounted::Trusted;
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::bindings::root::{Dom, DomRoot};
use crate::dom::bindings::str::DOMString;
use crate::dom::event::Event;
use crate::dom::fetch::{request::Request, response::Response};
use crate::dom::promise::Promise;
use crate::dom::promise::promisenativehandler::{Callback, PromiseNativeHandler};
use crate::dom::serviceworker::extendableevent::ExtendableEvent;
use crate::dom::serviceworker::serviceworkerglobalscope::ServiceWorkerGlobalScope;

/// A response body is sent back to the resource thread only after Servo's
/// ReadableStream has reached EOF. This keeps the service-worker boundary on
/// the existing CustomResponse transport and avoids a second body protocol.
fn send_response(
    cx: &mut JSContext,
    response: DomRoot<Response>,
    response_sender: IpcSender<Option<CustomResponse>>,
) {
    let status =
        StatusCode::from_u16(response.Status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let status_text = response.StatusText().as_ref().to_vec();
    let headers = response.Headers(cx).get_headers_list();
    let Some(stream) = response.body() else {
        let _ = response_sender.send(Some(CustomResponse::new(
            headers,
            (status, String::from_utf8_lossy(&status_text).into_owned()),
            vec![],
        )));
        return;
    };

    let reader = match stream.acquire_default_reader(cx) {
        Ok(reader) => reader,
        Err(_) => {
            let _ = response_sender.send(None);
            return;
        },
    };

    let success_sender = response_sender.clone();
    let failure_sender = response_sender;
    reader.read_all_bytes(
        cx,
        Rc::new(move |_cx, body| {
            let response = CustomResponse::new(
                headers.clone(),
                (status, String::from_utf8_lossy(&status_text).into_owned()),
                body.to_vec(),
            );
            let _ = success_sender.send(Some(response));
        }),
        Rc::new(move |_cx, _error| {
            let _ = failure_sender.send(None);
        }),
    );
}

#[derive(JSTraceable, MallocSizeOf)]
#[cfg_attr(crown, crown::unrooted_must_root_lint::must_root)]
struct FetchResponsePromiseHandler {
    #[no_trace]
    response_sender: IpcSender<Option<CustomResponse>>,
}

impl Callback for FetchResponsePromiseHandler {
    #[expect(unsafe_code)]
    fn callback(&self, cx: &mut CurrentRealm, value: HandleValue) {
        if !value.is_object() {
            let _ = self.response_sender.send(None);
            return;
        }

        let response = unsafe { root_from_object::<Response>(cx, value.to_object()) };
        match response {
            Ok(response) => send_response(cx, response, self.response_sender.clone()),
            Err(_) => {
                let _ = self.response_sender.send(None);
            },
        }
    }
}

#[dom_struct]
pub(crate) struct FetchEvent {
    event: ExtendableEvent,
    request: Dom<Request>,
    #[ignore_malloc_size_of = "Promise"]
    preload_response: Rc<Promise>,
    #[no_trace]
    response_sender: DomRefCell<Option<IpcSender<Option<CustomResponse>>>>,
}

impl FetchEvent {
    fn new_inherited(
        request: &Request,
        response_sender: Option<IpcSender<Option<CustomResponse>>>,
        preload_response: Rc<Promise>,
    ) -> FetchEvent {
        FetchEvent {
            event: ExtendableEvent::new_inherited(),
            request: Dom::from_ref(request),
            preload_response,
            response_sender: DomRefCell::new(response_sender),
        }
    }

    pub(crate) fn new(
        cx: &mut JSContext,
        worker: &ServiceWorkerGlobalScope,
        request: DomRoot<Request>,
        mediator: CustomResponseMediator,
        preload_receiver: Option<Receiver<Option<CustomResponse>>>,
    ) -> DomRoot<FetchEvent> {
        Self::new_with_proto(
            cx,
            worker,
            None,
            atom!("fetch"),
            &request,
            Some(mediator.response_chan),
            preload_receiver,
        )
    }

    fn new_with_proto(
        cx: &mut JSContext,
        worker: &ServiceWorkerGlobalScope,
        proto: Option<HandleObject>,
        type_: Atom,
        request: &Request,
        response_sender: Option<IpcSender<Option<CustomResponse>>>,
        preload_receiver: Option<Receiver<Option<CustomResponse>>>,
    ) -> DomRoot<FetchEvent> {
        let preload_response = Promise::new(cx, worker.upcast());
        let event = reflect_dom_object_with_proto(
            cx,
            Box::new(FetchEvent::new_inherited(
                request,
                response_sender,
                preload_response,
            )),
            worker,
            proto,
        );
        event.upcast::<Event>().init_event(type_, false, false);

        if let Some(preload_receiver) = preload_receiver {
            let trusted_event = Trusted::new(&*event);
            let task_source = worker
                .upcast::<crate::dom::globalscope::GlobalScope>()
                .task_manager()
                .networking_task_source()
                .to_sendable();
            thread::spawn(move || {
                let response = preload_receiver.recv().ok().flatten();
                task_source.queue(task!(resolve_preload_response: move |cx| {
                    trusted_event.root().resolve_preload_response(cx, response);
                }));
            });
        } else {
            event.preload_response.resolve_native(cx, &UndefinedValue());
        }
        event
    }

    pub(crate) fn fail_if_unhandled(&self) {
        if let Some(sender) = self.response_sender.borrow_mut().take() {
            let _ = sender.send(None);
        }
    }

    pub(crate) fn finish_dispatch(&self) {
        self.event.finish_dispatch();
    }

    fn resolve_preload_response(&self, cx: &mut JSContext, response: Option<CustomResponse>) {
        let Some(response) = response else {
            self.preload_response.resolve_native(cx, &UndefinedValue());
            return;
        };

        let response_object = Response::new(cx, &self.global());
        response_object.set_status(&HttpStatus::new_raw(
            response.raw_status.0.as_u16(),
            response.raw_status.1.into_bytes(),
        ));
        response_object.set_headers(cx, Some(hyper_serde::Serde(response.headers)));
        response_object.set_final_url(self.request.current_url());
        if !response.body.is_empty() {
            response_object.stream_chunk(cx, response.body);
        }
        response_object.finish(cx);
        self.preload_response.resolve_native(cx, &response_object);
    }
}

impl FetchEventMethods<crate::DomTypeHolder> for FetchEvent {
    fn Constructor(
        cx: &mut JSContext,
        worker: &ServiceWorkerGlobalScope,
        proto: Option<HandleObject>,
        type_: DOMString,
        init: &FetchEventInit,
    ) -> Fallible<DomRoot<FetchEvent>> {
        Ok(Self::new_with_proto(
            cx,
            worker,
            proto,
            Atom::from(type_),
            &init.request,
            None,
            None,
        ))
    }

    fn Request(&self) -> DomRoot<Request> {
        DomRoot::from_ref(&*self.request)
    }

    fn PreloadResponse(&self, _cx: &mut JSContext) -> Rc<Promise> {
        self.preload_response.clone()
    }

    #[expect(unsafe_code)]
    fn RespondWith(&self, value: HandleValue) -> ErrorResult {
        let Some(response_sender) = self.response_sender.borrow_mut().take() else {
            return Err(Error::InvalidState(None));
        };

        #[expect(unsafe_code)]
        let mut cx = unsafe { temp_cx() };
        if value.is_object() {
            rooted!(&in(cx) let object = value.to_object());
            if unsafe { IsPromiseObject(object.handle().into_handle()) } {
                let promise = Promise::new_with_js_promise(&mut cx, object.handle());
                let global = self.global();
                let handler = PromiseNativeHandler::new(
                    &mut cx,
                    &global,
                    Some(Box::new(FetchResponsePromiseHandler {
                        response_sender: response_sender.clone(),
                    })),
                    Some(Box::new(FetchResponsePromiseHandler { response_sender })),
                );
                let mut realm = CurrentRealm::assert(&mut cx);
                promise.append_native_handler(&mut realm, &handler);
                return Ok(());
            }

            let response = unsafe { root_from_object::<Response>(&mut cx, object.get()) };
            if let Ok(response) = response {
                send_response(&mut cx, response, response_sender);
                return Ok(());
            }
        }

        let _ = response_sender.send(None);
        Err(Error::Type(
            c"respondWith() requires a Response or Promise<Response>".to_owned(),
        ))
    }

    fn IsTrusted(&self) -> bool {
        self.event.IsTrusted()
    }
}
