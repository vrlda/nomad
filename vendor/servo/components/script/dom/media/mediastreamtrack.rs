/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::cell::Cell;

use dom_struct::dom_struct;
use js::context::JSContext;
use script_bindings::reflector::reflect_dom_object_with_cx;
use servo_media::streams::MediaStreamType;
use servo_media::streams::registry::{MediaStreamId, get_stream, unregister_stream};

use crate::dom::bindings::codegen::Bindings::MediaStreamTrackBinding::{
    MediaStreamTrackMethods, MediaStreamTrackState,
};
use crate::dom::bindings::inheritance::Castable;
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::bindings::root::DomRoot;
use crate::dom::bindings::str::DOMString;
use crate::dom::eventtarget::EventTarget;
use crate::dom::globalscope::GlobalScope;
use stylo_atoms::atom;

#[dom_struct]
pub(crate) struct MediaStreamTrack {
    eventtarget: EventTarget,
    #[ignore_malloc_size_of = "defined in servo-media"]
    #[no_trace]
    id: MediaStreamId,
    #[ignore_malloc_size_of = "defined in servo-media"]
    #[no_trace]
    ty: MediaStreamType,
    enabled: Cell<bool>,
    ready_state: Cell<MediaStreamTrackState>,
}

impl MediaStreamTrack {
    pub(crate) fn new_inherited(id: MediaStreamId, ty: MediaStreamType) -> MediaStreamTrack {
        MediaStreamTrack {
            eventtarget: EventTarget::new_inherited(),
            id,
            ty,
            enabled: Cell::new(true),
            ready_state: Cell::new(MediaStreamTrackState::Live),
        }
    }

    pub(crate) fn new(
        cx: &mut js::context::JSContext,
        global: &GlobalScope,
        id: MediaStreamId,
        ty: MediaStreamType,
    ) -> DomRoot<MediaStreamTrack> {
        reflect_dom_object_with_cx(
            Box::new(MediaStreamTrack::new_inherited(id, ty)),
            global,
            cx,
        )
    }

    pub(crate) fn id(&self) -> MediaStreamId {
        self.id
    }

    pub(crate) fn ty(&self) -> MediaStreamType {
        self.ty
    }

    pub(crate) fn is_live(&self) -> bool {
        self.ready_state.get() == MediaStreamTrackState::Live
    }
}

impl MediaStreamTrackMethods<crate::DomTypeHolder> for MediaStreamTrack {
    /// <https://w3c.github.io/mediacapture-main/#dom-mediastreamtrack-kind>
    fn Kind(&self) -> DOMString {
        match self.ty {
            MediaStreamType::Video => "video".into(),
            MediaStreamType::Audio => "audio".into(),
        }
    }

    /// <https://w3c.github.io/mediacapture-main/#dom-mediastreamtrack-id>
    fn Id(&self) -> DOMString {
        self.id.id().to_string().into()
    }

    /// <https://w3c.github.io/mediacapture-main/#dom-mediastreamtrack-label>
    ///
    /// Device labels are intentionally not exposed by this layer yet. The
    /// permission-gated device enumeration path owns the real labels, and an
    /// empty value is safer than leaking an unauthorised hardware identifier.
    fn Label(&self) -> DOMString {
        DOMString::new()
    }

    /// <https://w3c.github.io/mediacapture-main/#dom-mediastreamtrack-enabled>
    fn Enabled(&self) -> bool {
        self.enabled.get()
    }

    /// <https://w3c.github.io/mediacapture-main/#dom-mediastreamtrack-enabled>
    fn SetEnabled(&self, value: bool) {
        self.enabled.set(value);
        if self.is_live()
            && let Some(stream) = get_stream(&self.id)
        {
            stream.lock().unwrap().set_enabled(value);
        }
    }

    /// <https://w3c.github.io/mediacapture-main/#dom-mediastreamtrack-muted>
    fn Muted(&self) -> bool {
        false
    }

    /// <https://w3c.github.io/mediacapture-main/#dom-mediastreamtrack-readystate>
    fn ReadyState(&self) -> MediaStreamTrackState {
        self.ready_state.get()
    }

    /// <https://w3c.github.io/mediacapture-main/#dom-mediastreamtrack-stop>
    fn Stop(&self, cx: &mut JSContext) {
        if self.is_live() {
            if let Some(stream) = get_stream(&self.id) {
                stream.lock().unwrap().stop();
            }
            unregister_stream(&self.id);
            self.ready_state.set(MediaStreamTrackState::Ended);
            self.upcast::<EventTarget>().fire_event(cx, atom!("ended"));
        }
    }

    event_handler!(mute, GetOnmute, SetOnmute);
    event_handler!(unmute, GetOnunmute, SetOnunmute);
    event_handler!(ended, GetOnended, SetOnended);

    /// <https://w3c.github.io/mediacapture-main/#dom-mediastreamtrack-clone>
    fn Clone(&self, cx: &mut js::context::JSContext) -> DomRoot<MediaStreamTrack> {
        let track = MediaStreamTrack::new(cx, &self.global(), self.id, self.ty);
        track.enabled.set(self.enabled.get());
        track
    }
}
