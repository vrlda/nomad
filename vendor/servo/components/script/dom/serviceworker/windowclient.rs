/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::rc::Rc;

use dom_struct::dom_struct;
use js::context::JSContext;
use script_bindings::codegen::GenericBindings::WindowClientBinding::WindowClientMethods;
use script_bindings::inheritance::Castable;
use script_bindings::reflector::reflect_dom_object_with_cx;
use script_bindings::str::USVString;
use servo_base::id::PipelineId;
use servo_constellation_traits::ScriptToConstellationMessage;
use servo_url::ServoUrl;

use crate::dom::bindings::codegen::Bindings::ClientBinding::FrameType;
use crate::dom::bindings::error::Error;
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::bindings::root::DomRoot;
use crate::dom::client::Client;
use crate::dom::globalscope::GlobalScope;
use crate::dom::promise::Promise;
use crate::dom::serviceworker::serviceworkerglobalscope::ServiceWorkerGlobalScope;

#[dom_struct]
pub(crate) struct WindowClient {
    client: Client,
}

impl WindowClient {
    pub(crate) fn new(
        cx: &mut JSContext,
        global: &GlobalScope,
        url: ServoUrl,
        frame_type: FrameType,
        pipeline_id: PipelineId,
    ) -> DomRoot<WindowClient> {
        reflect_dom_object_with_cx(
            Box::new(WindowClient {
                client: Client::new_inherited(url, frame_type, pipeline_id),
            }),
            global,
            cx,
        )
    }
}

impl WindowClientMethods<crate::DomTypeHolder> for WindowClient {
    /// <https://w3c.github.io/ServiceWorker/#dom-windowclient-focus>
    fn Focus(&self, cx: &mut JSContext) -> Rc<Promise> {
        let global = self.global();
        let promise = Promise::new(cx, &global);
        let Some(service_worker) = global.downcast::<ServiceWorkerGlobalScope>() else {
            promise.reject_error(cx, Error::Operation(None));
            return promise;
        };
        let message = ScriptToConstellationMessage::ServiceWorkerClientFocus {
            target_pipeline_id: self.client.pipeline_id(),
            scope_url: service_worker.scope_url().clone(),
            origin: global.origin().immutable().clone(),
            worker_id: service_worker.service_worker_id(),
            partition_key: global.storage_partition_key().map(str::to_owned),
        };
        if global.script_to_constellation_chan().send(message).is_err() {
            promise.reject_error(cx, Error::Operation(None));
        } else {
            promise.resolve_native(cx, self);
        }
        promise
    }

    /// <https://w3c.github.io/ServiceWorker/#dom-windowclient-navigate>
    fn Navigate(&self, cx: &mut JSContext, url: USVString) -> Rc<Promise> {
        let global = self.global();
        let promise = Promise::new(cx, &global);
        let Some(service_worker) = global.downcast::<ServiceWorkerGlobalScope>() else {
            promise.reject_error(cx, Error::Operation(None));
            return promise;
        };
        let Ok(url) = global.api_base_url().join(&url.0) else {
            promise.reject_error(cx, Error::Type(c"Invalid URL".to_owned()));
            return promise;
        };
        if !matches!(url.scheme(), "http" | "https") {
            promise.reject_error(cx, Error::Type(c"Unsupported URL scheme".to_owned()));
            return promise;
        }
        if global
            .script_to_constellation_chan()
            .send(ScriptToConstellationMessage::ServiceWorkerClientNavigate {
                target_pipeline_id: self.client.pipeline_id(),
                url,
                scope_url: service_worker.scope_url().clone(),
                origin: global.origin().immutable().clone(),
                worker_id: service_worker.service_worker_id(),
                partition_key: global.storage_partition_key().map(str::to_owned),
            })
            .is_err()
        {
            promise.reject_error(cx, Error::Operation(None));
        } else {
            promise.resolve_native(cx, &Some(self));
        }
        promise
    }
}
