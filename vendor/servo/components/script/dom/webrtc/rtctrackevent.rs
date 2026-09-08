/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use dom_struct::dom_struct;
use js::jsapi::Heap;
use js::jsval::JSVal;
use js::rust::HandleObject;
use js::rust::MutableHandleValue;
use script_bindings::reflector::reflect_dom_object_with_proto;
use stylo_atoms::Atom;

use crate::dom::bindings::codegen::Bindings::EventBinding::Event_Binding::EventMethods;
use crate::dom::bindings::codegen::Bindings::RTCTrackEventBinding::{self, RTCTrackEventMethods};
use crate::dom::bindings::error::Fallible;
use crate::dom::bindings::inheritance::Castable;
use crate::dom::bindings::root::{Dom, DomRoot};
use crate::dom::bindings::str::DOMString;
use crate::dom::bindings::utils::to_frozen_array;
use crate::dom::event::Event;
use crate::dom::mediastream::MediaStream;
use crate::dom::mediastreamtrack::MediaStreamTrack;
use crate::dom::rtcrtpreceiver::RTCRtpReceiver;
use crate::dom::rtcrtptransceiver::RTCRtpTransceiver;
use crate::dom::window::Window;
use crate::realms::enter_auto_realm;

#[dom_struct]
pub(crate) struct RTCTrackEvent {
    event: Event,
    track: Dom<MediaStreamTrack>,
    receiver: Dom<RTCRtpReceiver>,
    #[ignore_malloc_size_of = "mozjs"]
    streams: Heap<JSVal>,
    transceiver: Dom<RTCRtpTransceiver>,
}

impl RTCTrackEvent {
    fn new_inherited(
        track: &MediaStreamTrack,
        receiver: &RTCRtpReceiver,
        transceiver: &RTCRtpTransceiver,
    ) -> RTCTrackEvent {
        RTCTrackEvent {
            event: Event::new_inherited(),
            track: Dom::from_ref(track),
            receiver: Dom::from_ref(receiver),
            streams: Heap::default(),
            transceiver: Dom::from_ref(transceiver),
        }
    }

    pub(crate) fn new(
        cx: &mut js::context::JSContext,
        window: &Window,
        type_: Atom,
        bubbles: bool,
        cancelable: bool,
        track: &MediaStreamTrack,
        receiver: &RTCRtpReceiver,
        streams: &[DomRoot<MediaStream>],
        transceiver: &RTCRtpTransceiver,
    ) -> DomRoot<RTCTrackEvent> {
        Self::new_with_proto(
            cx,
            window,
            None,
            type_,
            bubbles,
            cancelable,
            track,
            receiver,
            streams,
            transceiver,
        )
    }

    fn new_with_proto(
        cx: &mut js::context::JSContext,
        window: &Window,
        proto: Option<HandleObject>,
        type_: Atom,
        bubbles: bool,
        cancelable: bool,
        track: &MediaStreamTrack,
        receiver: &RTCRtpReceiver,
        streams: &[DomRoot<MediaStream>],
        transceiver: &RTCRtpTransceiver,
    ) -> DomRoot<RTCTrackEvent> {
        let trackevent = reflect_dom_object_with_proto(
            cx,
            Box::new(RTCTrackEvent::new_inherited(track, receiver, transceiver)),
            window,
            proto,
        );
        {
            let event = trackevent.upcast::<Event>();
            event.init_event(type_, bubbles, cancelable);
        }
        let mut realm = enter_auto_realm(cx, window);
        let cx = &mut realm.current_realm();
        rooted!(&in(cx) let mut frozen_streams: JSVal);
        to_frozen_array(cx, streams, frozen_streams.handle_mut());
        trackevent.streams.set(*frozen_streams);
        trackevent
    }
}

impl RTCTrackEventMethods<crate::DomTypeHolder> for RTCTrackEvent {
    /// <https://w3c.github.io/webrtc-pc/#dom-rtctrackevent-constructor>
    fn Constructor(
        cx: &mut js::context::JSContext,
        window: &Window,
        proto: Option<HandleObject>,
        type_: DOMString,
        init: &RTCTrackEventBinding::RTCTrackEventInit,
    ) -> Fallible<DomRoot<RTCTrackEvent>> {
        Ok(RTCTrackEvent::new_with_proto(
            cx,
            window,
            proto,
            Atom::from(type_),
            init.parent.bubbles,
            init.parent.cancelable,
            &init.track,
            &init.receiver,
            &init.streams,
            &init.transceiver,
        ))
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtctrackevent-track>
    fn Track(&self) -> DomRoot<MediaStreamTrack> {
        DomRoot::from_ref(&*self.track)
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtctrackevent-receiver>
    fn Receiver(&self) -> DomRoot<RTCRtpReceiver> {
        DomRoot::from_ref(&*self.receiver)
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtctrackevent-streams>
    fn Streams(&self, mut retval: MutableHandleValue) {
        retval.set(self.streams.get())
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtctrackevent-transceiver>
    fn Transceiver(&self) -> DomRoot<RTCRtpTransceiver> {
        DomRoot::from_ref(&*self.transceiver)
    }

    /// <https://dom.spec.whatwg.org/#dom-event-istrusted>
    fn IsTrusted(&self) -> bool {
        self.event.IsTrusted()
    }
}
