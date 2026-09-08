/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use dom_struct::dom_struct;
use js::rust::HandleObject;
use script_bindings::reflector::reflect_dom_object_with_proto;
use stylo_atoms::Atom;

use crate::dom::bindings::codegen::Bindings::EventBinding::Event_Binding::EventMethods;
use crate::dom::bindings::codegen::Bindings::MediaStreamTrackEventBinding::{
    self, MediaStreamTrackEventMethods,
};
use crate::dom::bindings::inheritance::Castable;
use crate::dom::bindings::root::{Dom, DomRoot};
use crate::dom::bindings::str::DOMString;
use crate::dom::event::Event;
use crate::dom::media::mediastreamtrack::MediaStreamTrack;
use crate::dom::window::Window;

#[dom_struct]
pub(crate) struct MediaStreamTrackEvent {
    event: Event,
    track: Dom<MediaStreamTrack>,
}

impl MediaStreamTrackEvent {
    fn new_inherited(track: &MediaStreamTrack) -> Self {
        Self {
            event: Event::new_inherited(),
            track: Dom::from_ref(track),
        }
    }

    pub(crate) fn new(
        cx: &mut js::context::JSContext,
        window: &Window,
        type_: Atom,
        bubbles: bool,
        cancelable: bool,
        track: &MediaStreamTrack,
    ) -> DomRoot<Self> {
        Self::new_with_proto(cx, window, None, type_, bubbles, cancelable, track)
    }

    fn new_with_proto(
        cx: &mut js::context::JSContext,
        window: &Window,
        proto: Option<HandleObject>,
        type_: Atom,
        bubbles: bool,
        cancelable: bool,
        track: &MediaStreamTrack,
    ) -> DomRoot<Self> {
        let event =
            reflect_dom_object_with_proto(cx, Box::new(Self::new_inherited(track)), window, proto);
        event
            .upcast::<Event>()
            .init_event(type_, bubbles, cancelable);
        event
    }
}

impl MediaStreamTrackEventMethods<crate::DomTypeHolder> for MediaStreamTrackEvent {
    /// <https://w3c.github.io/mediacapture-main/#dom-mediastreamtrackevent>
    fn Constructor(
        cx: &mut js::context::JSContext,
        window: &Window,
        proto: Option<HandleObject>,
        type_: DOMString,
        init: &MediaStreamTrackEventBinding::MediaStreamTrackEventInit,
    ) -> DomRoot<MediaStreamTrackEvent> {
        Self::new_with_proto(
            cx,
            window,
            proto,
            Atom::from(type_),
            init.parent.bubbles,
            init.parent.cancelable,
            &init.track,
        )
    }

    /// <https://w3c.github.io/mediacapture-main/#dom-mediastreamtrackevent-track>
    fn Track(&self) -> DomRoot<MediaStreamTrack> {
        DomRoot::from_ref(&*self.track)
    }

    /// <https://dom.spec.whatwg.org/#dom-event-istrusted>
    fn IsTrusted(&self) -> bool {
        self.event.IsTrusted()
    }
}
