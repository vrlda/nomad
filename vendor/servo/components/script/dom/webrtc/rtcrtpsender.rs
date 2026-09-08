/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::rc::Rc;

use dom_struct::dom_struct;
use js::context::JSContext;
use script_bindings::cell::DomRefCell;
use script_bindings::num::Finite;
use script_bindings::reflector::{Reflector, reflect_dom_object_with_cx};
use script_bindings::script_runtime::temp_cx;
use servo_media::streams::MediaStreamType;
use servo_media::streams::registry::MediaStreamId;
use servo_media::webrtc::{
    RtpEncodingParameters as BackendEncodingParameters, RtpSenderParameters, WebRtcController,
};

use crate::dom::bindings::codegen::Bindings::RTCRtpSenderBinding::{
    RTCRtcpParameters, RTCRtpParameters, RTCRtpSendParameters, RTCRtpSenderMethods,
};
use crate::dom::bindings::error::Error;
use crate::dom::bindings::root::{DomRoot, MutNullableDom};
use crate::dom::bindings::str::DOMString;
use crate::dom::globalscope::GlobalScope;
use crate::dom::mediastreamtrack::MediaStreamTrack;
use crate::dom::promise::Promise;
use crate::realms::enter_auto_realm;

#[derive(MallocSizeOf)]
struct SenderEncodingState {
    rid: Option<String>,
    active: bool,
    max_bitrate: Option<u32>,
    scale_resolution_down_by: Option<f64>,
}

#[dom_struct]
pub(crate) struct RTCRtpSender {
    reflector_: Reflector,
    track: MutNullableDom<MediaStreamTrack>,
    #[ignore_malloc_size_of = "defined in servo-media"]
    #[no_trace]
    ty: MediaStreamType,
    #[ignore_malloc_size_of = "defined in servo-media"]
    #[no_trace]
    stream_id: DomRefCell<Option<MediaStreamId>>,
    #[ignore_malloc_size_of = "defined in servo-media"]
    #[no_trace]
    controller: Option<WebRtcController>,
    transaction_id: DomRefCell<String>,
    #[no_trace]
    encodings: DomRefCell<Vec<SenderEncodingState>>,
}

impl RTCRtpSender {
    fn new_inherited(
        track: Option<&MediaStreamTrack>,
        ty: MediaStreamType,
        controller: Option<WebRtcController>,
    ) -> Self {
        let stream_id = track.map(MediaStreamTrack::id);
        let transaction_id = stream_id.unwrap_or_default().id().to_string();
        Self {
            reflector_: Reflector::new(),
            track: MutNullableDom::new(track),
            ty,
            stream_id: DomRefCell::new(stream_id),
            controller,
            transaction_id: DomRefCell::new(transaction_id),
            encodings: DomRefCell::new(vec![SenderEncodingState {
                rid: None,
                active: true,
                max_bitrate: None,
                scale_resolution_down_by: None,
            }]),
        }
    }

    pub(crate) fn new(
        cx: &mut JSContext,
        global: &GlobalScope,
        track: Option<&MediaStreamTrack>,
        ty: MediaStreamType,
        controller: Option<WebRtcController>,
    ) -> DomRoot<Self> {
        reflect_dom_object_with_cx(
            Box::new(Self::new_inherited(track, ty, controller)),
            global,
            cx,
        )
    }

    pub(crate) fn track(&self) -> Option<DomRoot<MediaStreamTrack>> {
        self.track.get()
    }

    fn parameters(&self) -> RTCRtpSendParameters {
        let encodings = self
            .encodings
            .borrow()
            .iter()
            .map(|encoding| {
                let mut result = crate::dom::bindings::codegen::Bindings::RTCPeerConnectionBinding::RTCRtpEncodingParameters::empty();
                result.parent.rid = encoding.rid.clone().map(DOMString::from);
                result.active = encoding.active;
                result.maxBitrate = encoding.max_bitrate;
                result.scaleResolutionDownBy = encoding
                    .scale_resolution_down_by
                    .map(Finite::wrap);
                result
            })
            .collect();
        RTCRtpSendParameters {
            parent: RTCRtpParameters {
                headerExtensions: vec![],
                rtcp: RTCRtcpParameters {
                    cname: None,
                    reducedSize: None,
                },
                codecs: vec![],
            },
            transactionId: DOMString::from(self.transaction_id.borrow().clone()),
            encodings,
        }
    }

    fn backend_parameters(&self, active_override: Option<bool>) -> RtpSenderParameters {
        RtpSenderParameters {
            encodings: self
                .encodings
                .borrow()
                .iter()
                .map(|encoding| BackendEncodingParameters {
                    active: active_override.unwrap_or(encoding.active),
                    max_bitrate: encoding.max_bitrate,
                    scale_resolution_down_by: encoding.scale_resolution_down_by,
                })
                .collect(),
        }
    }

    fn replace_track(&self, with_track: Option<&MediaStreamTrack>) -> Rc<Promise> {
        #[expect(unsafe_code)]
        let mut cx = unsafe { temp_cx() };
        let mut realm = enter_auto_realm(&mut cx, self);
        let current_realm = &mut realm.current_realm();
        let promise = Promise::new_in_realm(current_realm);
        if with_track.is_some_and(|track| track.ty() != self.ty) {
            promise.reject_error(
                current_realm,
                Error::Type(c"replacement track kind must match the sender kind".to_owned()),
            );
            return promise;
        }

        if self.track().is_some_and(|track| {
            with_track.is_some_and(|replacement| track.id() == replacement.id())
        }) {
            promise.resolve_native(current_realm, &());
            return promise;
        }

        let old_stream_id = *self.stream_id.borrow();
        let new_stream_id = with_track.map(MediaStreamTrack::id);
        if let Some(controller) = self.controller.as_ref() {
            let result = match (old_stream_id, new_stream_id) {
                (Some(old_stream_id), Some(new_stream_id)) => {
                    controller.replace_stream(&old_stream_id, &new_stream_id)
                },
                (None, Some(new_stream_id)) => controller.add_stream(&new_stream_id),
                (Some(old_stream_id), None) => controller
                    .set_sender_parameters(&old_stream_id, self.backend_parameters(Some(false))),
                (None, None) => Ok(()),
            };
            if let Err(error) = result {
                let message = match error {
                    servo_media::webrtc::WebRtcError::Backend(message) => message,
                };
                promise.reject_error(current_realm, Error::Operation(Some(message)));
                return promise;
            }

            if let Some(new_stream_id) = new_stream_id
                && let Err(error) =
                    controller.set_sender_parameters(&new_stream_id, self.backend_parameters(None))
            {
                let message = match error {
                    servo_media::webrtc::WebRtcError::Backend(message) => message,
                };
                promise.reject_error(current_realm, Error::Operation(Some(message)));
                return promise;
            }
        } else if old_stream_id.is_some() || new_stream_id.is_some() {
            promise.reject_error(current_realm, Error::InvalidState(None));
            return promise;
        }

        self.track.set(with_track);
        if new_stream_id.is_some() {
            *self.stream_id.borrow_mut() = new_stream_id;
        }
        promise.resolve_native(current_realm, &());
        promise
    }
}

impl RTCRtpSenderMethods<crate::DomTypeHolder> for RTCRtpSender {
    /// <https://w3c.github.io/webrtc-pc/#dom-rtcrtpsender-track>
    fn GetTrack(&self) -> Option<DomRoot<MediaStreamTrack>> {
        self.track()
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcrtpsender-getparameters>
    fn GetParameters(&self) -> RTCRtpSendParameters {
        self.parameters()
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcrtpsender-replacetrack>
    fn ReplaceTrack(&self, with_track: Option<&MediaStreamTrack>) -> Rc<Promise> {
        self.replace_track(with_track)
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcrtpsender-setparameters>
    fn SetParameters(&self, cx: &mut JSContext, parameters: &RTCRtpSendParameters) -> Rc<Promise> {
        let mut realm = enter_auto_realm(cx, self);
        let cx = &mut realm.current_realm();
        let promise = Promise::new_in_realm(cx);

        if parameters.transactionId.to_string() != *self.transaction_id.borrow() {
            promise.reject_error(cx, Error::InvalidModification(None));
            return promise;
        }

        if parameters.encodings.len() != self.encodings.borrow().len() {
            promise.reject_error(cx, Error::InvalidModification(None));
            return promise;
        }

        let mut next_encodings = Vec::with_capacity(parameters.encodings.len());
        let mut backend_encodings = Vec::with_capacity(parameters.encodings.len());
        for encoding in &parameters.encodings {
            if encoding.parent.rid.is_some() {
                promise.reject_error(
                    cx,
                    Error::NotSupported(Some(
                        "RID-based sender encodings are not available in the current backend"
                            .to_owned(),
                    )),
                );
                return promise;
            }
            let scale_resolution_down_by = encoding.scaleResolutionDownBy.map(|scale| *scale);
            if scale_resolution_down_by.is_some_and(|scale| scale <= 0.0) {
                promise.reject_error(
                    cx,
                    Error::Range(c"scaleResolutionDownBy must be greater than zero".to_owned()),
                );
                return promise;
            }
            next_encodings.push(SenderEncodingState {
                rid: encoding.parent.rid.as_ref().map(ToString::to_string),
                active: encoding.active,
                max_bitrate: encoding.maxBitrate,
                scale_resolution_down_by,
            });
            backend_encodings.push(BackendEncodingParameters {
                active: encoding.active,
                max_bitrate: encoding.maxBitrate,
                scale_resolution_down_by,
            });
        }

        let Some(controller) = self.controller.as_ref() else {
            promise.reject_error(cx, Error::InvalidState(None));
            return promise;
        };
        let Some(stream_id) = self.stream_id.borrow().as_ref().copied() else {
            promise.reject_error(cx, Error::InvalidState(None));
            return promise;
        };
        if let Err(error) = controller.set_sender_parameters(
            &stream_id,
            RtpSenderParameters {
                encodings: backend_encodings,
            },
        ) {
            let message = match error {
                servo_media::webrtc::WebRtcError::Backend(message) => message,
            };
            promise.reject_error(cx, Error::Operation(Some(message)));
            return promise;
        }

        *self.encodings.borrow_mut() = next_encodings;
        *self.transaction_id.borrow_mut() = MediaStreamId::new().id().to_string();
        promise.resolve_native(cx, &());
        promise
    }
}
