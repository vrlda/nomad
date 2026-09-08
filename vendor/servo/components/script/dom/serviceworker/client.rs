/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use dom_struct::dom_struct;
use js::context::JSContext;
use js::jsapi::{Heap, JSObject};
use js::rust::{CustomAutoRooter, CustomAutoRooterGuard, HandleValue};
use script_bindings::error::ErrorResult;
use script_bindings::reflector::{Reflector, reflect_dom_object_with_cx};
use script_bindings::root::DomRoot;
use servo_base::id::PipelineId;
use servo_constellation_traits::ScriptToConstellationMessage;
use servo_url::ServoUrl;

use crate::dom::bindings::codegen::Bindings::ClientBinding::{ClientMethods, FrameType};
use crate::dom::bindings::codegen::Bindings::MessagePortBinding::StructuredSerializeOptions;
use crate::dom::bindings::error::Error;
use crate::dom::bindings::inheritance::Castable;
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::bindings::str::{DOMString, USVString};
use crate::dom::bindings::structuredclone;
use crate::dom::bindings::trace::RootedTraceableBox;
use crate::dom::globalscope::GlobalScope;
use crate::dom::serviceworker::serviceworkerglobalscope::ServiceWorkerGlobalScope;

#[dom_struct]
pub(crate) struct Client {
    reflector_: Reflector,

    #[no_trace]
    url: ServoUrl,

    #[no_trace]
    pipeline_id: PipelineId,

    /// <https://w3c.github.io/ServiceWorker/#dfn-service-worker-client-frame-type>
    frame_type: FrameType,
}

impl Client {
    pub(crate) fn new_inherited(
        url: ServoUrl,
        frame_type: FrameType,
        pipeline_id: PipelineId,
    ) -> Client {
        Client {
            reflector_: Reflector::new(),
            url,
            pipeline_id,
            frame_type,
        }
    }

    pub(crate) fn new(
        cx: &mut JSContext,
        global: &GlobalScope,
        url: ServoUrl,
        frame_type: FrameType,
        pipeline_id: PipelineId,
    ) -> DomRoot<Client> {
        reflect_dom_object_with_cx(
            Box::new(Client::new_inherited(url, frame_type, pipeline_id)),
            global,
            cx,
        )
    }

    /// <https://w3c.github.io/ServiceWorker/#dom-client-postmessage-message-options>
    fn post_message_impl(
        &self,
        cx: &mut JSContext,
        message: HandleValue,
        transfer: CustomAutoRooterGuard<Vec<*mut JSObject>>,
    ) -> ErrorResult {
        let global = self.reflector_.global();
        let data = structuredclone::write(cx, message, Some(transfer))?;
        let service_worker = global
            .downcast::<ServiceWorkerGlobalScope>()
            .ok_or_else(|| {
                Error::Type(c"Client is not associated with a service worker".to_owned())
            })?;
        global
            .script_to_constellation_chan()
            .send(
                ScriptToConstellationMessage::ServiceWorkerClientPostMessage {
                    target_pipeline_id: self.pipeline_id,
                    scope_url: service_worker.scope_url().clone(),
                    script_url: service_worker.script_url(),
                    worker_id: service_worker.service_worker_id(),
                    origin: global.origin().immutable().clone(),
                    partition_key: global.storage_partition_key().map(str::to_owned),
                    data,
                },
            )
            .map_err(|_| Error::Type(c"Failed to send message to client".to_owned()))
    }

    pub(crate) fn pipeline_id(&self) -> PipelineId {
        self.pipeline_id
    }
}

impl ClientMethods<crate::DomTypeHolder> for Client {
    /// <https://w3c.github.io/ServiceWorker/#dom-client-postmessage>
    fn PostMessage(
        &self,
        cx: &mut JSContext,
        message: HandleValue,
        transfer: CustomAutoRooterGuard<Vec<*mut JSObject>>,
    ) -> ErrorResult {
        self.post_message_impl(cx, message, transfer)
    }

    /// <https://w3c.github.io/ServiceWorker/#dom-client-postmessage-message-options>
    fn PostMessage_(
        &self,
        cx: &mut JSContext,
        message: HandleValue,
        options: RootedTraceableBox<StructuredSerializeOptions>,
    ) -> ErrorResult {
        let mut rooted = CustomAutoRooter::new(
            options
                .transfer
                .iter()
                .map(|js: &RootedTraceableBox<Heap<*mut JSObject>>| js.get())
                .collect(),
        );
        #[expect(unsafe_code)]
        let guard = unsafe { CustomAutoRooterGuard::new(cx.raw_cx(), &mut rooted) };
        self.post_message_impl(cx, message, guard)
    }

    /// <https://w3c.github.io/ServiceWorker/#client-url-attribute>
    fn Url(&self) -> USVString {
        USVString(self.url.as_str().to_owned())
    }

    /// <https://w3c.github.io/ServiceWorker/#client-frametype>
    fn FrameType(&self) -> FrameType {
        self.frame_type
    }

    /// <https://w3c.github.io/ServiceWorker/#client-id>
    fn Id(&self) -> DOMString {
        format!("{}", self.pipeline_id).into()
    }
}
