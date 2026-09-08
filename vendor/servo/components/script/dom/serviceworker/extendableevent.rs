/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use dom_struct::dom_struct;
use std::cell::Cell;

use js::context::JSContext;
use js::jsapi::IsPromiseObject;
use js::rust::{HandleObject, HandleValue, IntoHandle};
use script_bindings::reflector::reflect_dom_object_with_proto;
use script_bindings::script_runtime::temp_cx;
use stylo_atoms::Atom;

use crate::dom::bindings::codegen::Bindings::EventBinding::EventMethods;
use crate::dom::bindings::codegen::Bindings::ExtendableEventBinding::{
    ExtendableEventInit, ExtendableEventMethods,
};
use crate::dom::bindings::error::{Error, ErrorResult, Fallible};
use crate::dom::bindings::inheritance::Castable;
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::bindings::root::DomRoot;
use crate::dom::bindings::str::DOMString;
use crate::dom::event::Event;
use crate::dom::promise::Promise;
use crate::dom::serviceworkerglobalscope::ServiceWorkerGlobalScope;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExtendableEventState {
    extensions_allowed: bool,
}

impl ExtendableEventState {
    const fn can_wait_until(self) -> bool {
        self.extensions_allowed
    }

    const fn finish_dispatch(self) -> Self {
        Self {
            extensions_allowed: false,
        }
    }
}

// https://w3c.github.io/ServiceWorker/#extendable-event
#[dom_struct]
pub(crate) struct ExtendableEvent {
    event: Event,
    extensions_allowed: Cell<bool>,
}

impl ExtendableEvent {
    pub(crate) fn new_inherited() -> ExtendableEvent {
        ExtendableEvent {
            event: Event::new_inherited(),
            extensions_allowed: Cell::new(true),
        }
    }

    pub(crate) fn finish_dispatch(&self) {
        let state = ExtendableEventState {
            extensions_allowed: self.extensions_allowed.get(),
        };
        self.extensions_allowed
            .set(state.finish_dispatch().extensions_allowed);
    }

    pub(crate) fn new(
        cx: &mut JSContext,
        worker: &ServiceWorkerGlobalScope,
        type_: Atom,
        bubbles: bool,
        cancelable: bool,
    ) -> DomRoot<ExtendableEvent> {
        Self::new_with_proto(cx, worker, None, type_, bubbles, cancelable)
    }

    fn new_with_proto(
        cx: &mut JSContext,
        worker: &ServiceWorkerGlobalScope,
        proto: Option<HandleObject>,
        type_: Atom,
        bubbles: bool,
        cancelable: bool,
    ) -> DomRoot<ExtendableEvent> {
        let ev = reflect_dom_object_with_proto(
            cx,
            Box::new(ExtendableEvent::new_inherited()),
            worker,
            proto,
        );
        {
            let event = ev.upcast::<Event>();
            event.init_event(type_, bubbles, cancelable);
        }
        ev
    }
}

impl ExtendableEventMethods<crate::DomTypeHolder> for ExtendableEvent {
    /// <https://w3c.github.io/ServiceWorker/#dom-extendableevent-extendableevent>
    fn Constructor(
        cx: &mut JSContext,
        worker: &ServiceWorkerGlobalScope,
        proto: Option<HandleObject>,
        type_: DOMString,
        init: &ExtendableEventInit,
    ) -> Fallible<DomRoot<ExtendableEvent>> {
        Ok(ExtendableEvent::new_with_proto(
            cx,
            worker,
            proto,
            Atom::from(type_),
            init.parent.bubbles,
            init.parent.cancelable,
        ))
    }

    /// <https://w3c.github.io/ServiceWorker/#wait-until-method>
    #[expect(unsafe_code)]
    fn WaitUntil(&self, val: HandleValue) -> ErrorResult {
        // Step 1
        let state = ExtendableEventState {
            extensions_allowed: self.extensions_allowed.get(),
        };
        if !state.can_wait_until() {
            return Err(Error::InvalidState(None));
        }
        // Step 2
        if !val.is_object() {
            return Err(Error::Type(c"waitUntil() requires a Promise".to_owned()));
        }

        let mut cx = unsafe { temp_cx() };
        rooted!(&in(cx) let object = val.to_object());
        if !unsafe { IsPromiseObject(object.handle().into_handle()) } {
            return Err(Error::Type(c"waitUntil() requires a Promise".to_owned()));
        }

        let promise = Promise::new_with_js_promise(&mut cx, object.handle());
        let global = self.global();
        let Some(worker) = DomRoot::downcast::<ServiceWorkerGlobalScope>(global) else {
            return Err(Error::InvalidState(None));
        };
        worker.track_extendable_promise(promise);
        Ok(())
    }

    /// <https://dom.spec.whatwg.org/#dom-event-istrusted>
    fn IsTrusted(&self) -> bool {
        self.event.IsTrusted()
    }
}

#[cfg(test)]
mod tests {
    use super::ExtendableEventState;

    #[test]
    fn wait_until_is_closed_after_dispatch() {
        let state = ExtendableEventState {
            extensions_allowed: true,
        };
        assert!(state.can_wait_until());
        assert!(!state.finish_dispatch().can_wait_until());
    }
}
