/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use dom_struct::dom_struct;
use js::context::JSContext;
use script_bindings::reflector::{Reflector, reflect_dom_object_with_cx};

use crate::dom::bindings::codegen::Bindings::RTCRtpReceiverBinding::RTCRtpReceiverMethods;
use crate::dom::bindings::root::{Dom, DomRoot};
use crate::dom::globalscope::GlobalScope;
use crate::dom::mediastreamtrack::MediaStreamTrack;

#[dom_struct]
pub(crate) struct RTCRtpReceiver {
    reflector_: Reflector,
    track: Dom<MediaStreamTrack>,
}

impl RTCRtpReceiver {
    pub(crate) fn new(
        cx: &mut JSContext,
        global: &GlobalScope,
        track: &MediaStreamTrack,
    ) -> DomRoot<Self> {
        reflect_dom_object_with_cx(
            Box::new(Self {
                reflector_: Reflector::new(),
                track: Dom::from_ref(track),
            }),
            global,
            cx,
        )
    }

    pub(crate) fn track(&self) -> DomRoot<MediaStreamTrack> {
        DomRoot::from_ref(&*self.track)
    }
}

impl RTCRtpReceiverMethods<crate::DomTypeHolder> for RTCRtpReceiver {
    /// <https://w3c.github.io/webrtc-pc/#dom-rtcrtpreceiver-track>
    fn Track(&self) -> DomRoot<MediaStreamTrack> {
        self.track()
    }
}
