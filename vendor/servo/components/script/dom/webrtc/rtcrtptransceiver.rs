/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::cell::Cell;

use dom_struct::dom_struct;
use js::context::JSContext;
use script_bindings::cell::DomRefCell;
use script_bindings::reflector::{Reflector, reflect_dom_object_with_cx};

use crate::dom::bindings::codegen::Bindings::RTCRtpTransceiverBinding::{
    RTCRtpTransceiverDirection, RTCRtpTransceiverMethods,
};
use crate::dom::bindings::root::{Dom, DomRoot};
use crate::dom::bindings::str::DOMString;
use crate::dom::globalscope::GlobalScope;
use crate::dom::mediastreamtrack::MediaStreamTrack;
use crate::dom::rtcrtpreceiver::RTCRtpReceiver;
use crate::dom::rtcrtpsender::RTCRtpSender;
use servo_media::webrtc::WebRtcController;

#[dom_struct]
pub(crate) struct RTCRtpTransceiver {
    reflector_: Reflector,
    sender: Dom<RTCRtpSender>,
    receiver: Dom<RTCRtpReceiver>,
    direction: Cell<RTCRtpTransceiverDirection>,
    mid: DomRefCell<Option<DOMString>>,
    current_direction: Cell<Option<RTCRtpTransceiverDirection>>,
}

impl RTCRtpTransceiver {
    fn new_inherited(
        cx: &mut JSContext,
        global: &GlobalScope,
        direction: RTCRtpTransceiverDirection,
        sender_track: Option<&MediaStreamTrack>,
        receiver_track: &MediaStreamTrack,
        controller: Option<WebRtcController>,
    ) -> Self {
        let sender = RTCRtpSender::new(cx, global, sender_track, receiver_track.ty(), controller);
        let receiver = RTCRtpReceiver::new(cx, global, receiver_track);
        Self {
            reflector_: Reflector::new(),
            direction: Cell::new(direction),
            sender: Dom::from_ref(&*sender),
            receiver: Dom::from_ref(&*receiver),
            mid: DomRefCell::new(None),
            current_direction: Cell::new(None),
        }
    }

    pub(crate) fn new(
        cx: &mut JSContext,
        global: &GlobalScope,
        direction: RTCRtpTransceiverDirection,
        sender_track: Option<&MediaStreamTrack>,
        receiver_track: &MediaStreamTrack,
        controller: Option<WebRtcController>,
    ) -> DomRoot<Self> {
        reflect_dom_object_with_cx(
            Box::new(Self::new_inherited(
                cx,
                global,
                direction,
                sender_track,
                receiver_track,
                controller,
            )),
            global,
            cx,
        )
    }

    pub(crate) fn new_for_remote(
        cx: &mut JSContext,
        global: &GlobalScope,
        track: &MediaStreamTrack,
    ) -> DomRoot<Self> {
        Self::new(
            cx,
            global,
            RTCRtpTransceiverDirection::Recvonly,
            None,
            track,
            None,
        )
    }

    pub(crate) fn sender(&self) -> DomRoot<RTCRtpSender> {
        DomRoot::from_ref(&*self.sender)
    }

    pub(crate) fn receiver(&self) -> DomRoot<RTCRtpReceiver> {
        DomRoot::from_ref(&*self.receiver)
    }

    pub(crate) fn set_mid(&self, mid: Option<&str>) {
        *self.mid.borrow_mut() = mid.map(DOMString::from);
    }

    pub(crate) fn set_current_direction(&self, direction: Option<RTCRtpTransceiverDirection>) {
        if self.direction.get() == RTCRtpTransceiverDirection::Stopped {
            self.current_direction.set(None);
        } else {
            self.current_direction.set(direction);
        }
    }
}

impl RTCRtpTransceiverMethods<crate::DomTypeHolder> for RTCRtpTransceiver {
    /// <https://w3c.github.io/webrtc-pc/#dom-rtptransceiver-mid>
    fn GetMid(&self) -> Option<DOMString> {
        self.mid.borrow().clone()
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcrtptransceiver-direction>
    fn Direction(&self) -> RTCRtpTransceiverDirection {
        self.direction.get()
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtptransceiver-currentdirection>
    fn GetCurrentDirection(&self) -> Option<RTCRtpTransceiverDirection> {
        self.current_direction.get()
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcrtptransceiver-direction>
    fn SetDirection(&self, direction: RTCRtpTransceiverDirection) {
        if self.direction.get() == RTCRtpTransceiverDirection::Stopped {
            return;
        }
        self.direction.set(direction);
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcrtptransceiver-sender>
    fn Sender(&self) -> DomRoot<RTCRtpSender> {
        self.sender()
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcrtptransceiver-receiver>
    fn Receiver(&self) -> DomRoot<RTCRtpReceiver> {
        self.receiver()
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcrtptransceiver-stop>
    fn Stop(&self) {
        self.direction.set(RTCRtpTransceiverDirection::Stopped);
        self.current_direction.set(None);
    }
}
