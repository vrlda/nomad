/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::rc::Rc;

use dom_struct::dom_struct;
use js::context::JSContext;
use js::realm::CurrentRealm;
use script_bindings::reflector::reflect_dom_object_with_cx;
use servo_media::ServoMedia;
use servo_media::streams::MediaStreamType;
use servo_media::streams::capture::{Constrain, ConstrainRange, MediaTrackConstraintSet};

use crate::conversions::Convert;
use crate::dom::bindings::codegen::Bindings::MediaDevicesBinding::{
    MediaDevicesMethods, MediaStreamConstraints,
};
use crate::dom::bindings::codegen::Bindings::PermissionStatusBinding::{
    PermissionName, PermissionState,
};
use crate::dom::bindings::codegen::UnionTypes::{
    BooleanOrMediaTrackConstraints, ClampedUnsignedLongOrConstrainULongRange as ConstrainULong,
    DoubleOrConstrainDoubleRange as ConstrainDouble,
};
use crate::dom::bindings::error::Error;
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::bindings::root::DomRoot;
use crate::dom::eventtarget::EventTarget;
use crate::dom::globalscope::GlobalScope;
use crate::dom::media::mediadeviceinfo::MediaDeviceInfo;
use crate::dom::media::mediastream::MediaStream;
use crate::dom::media::mediastreamtrack::MediaStreamTrack;
use crate::dom::permissions::{descriptor_permission_state, request_permission_to_use};
use crate::dom::promise::Promise;

#[dom_struct]
pub(crate) struct MediaDevices {
    eventtarget: EventTarget,
}

impl MediaDevices {
    pub(crate) fn new_inherited() -> MediaDevices {
        MediaDevices {
            eventtarget: EventTarget::new_inherited(),
        }
    }

    pub(crate) fn new(cx: &mut JSContext, global: &GlobalScope) -> DomRoot<MediaDevices> {
        reflect_dom_object_with_cx(Box::new(MediaDevices::new_inherited()), global, cx)
    }
}

impl MediaDevicesMethods<crate::DomTypeHolder> for MediaDevices {
    /// <https://w3c.github.io/mediacapture-main/#dom-mediadevices-getusermedia>
    fn GetUserMedia(
        &self,
        cx: &mut CurrentRealm,
        constraints: &MediaStreamConstraints,
    ) -> Rc<Promise> {
        let p = Promise::new_in_realm(cx);
        let wants_audio = !matches!(
            constraints.audio,
            BooleanOrMediaTrackConstraints::Boolean(false)
        );
        let wants_video = !matches!(
            constraints.video,
            BooleanOrMediaTrackConstraints::Boolean(false)
        );
        if !wants_audio && !wants_video {
            p.reject_error(
                cx,
                Error::Type(c"At least one media kind must be requested".to_owned()),
            );
            return p;
        }

        let global = self.global();
        let audio_allowed = !wants_audio
            || request_permission_to_use(PermissionName::Microphone, &global)
                == PermissionState::Granted;
        let video_allowed = !wants_video
            || request_permission_to_use(PermissionName::Camera, &global)
                == PermissionState::Granted;
        if !audio_allowed || !video_allowed {
            p.reject_error(cx, Error::NotAllowed(None));
            return p;
        }

        let media = ServoMedia::get();
        let stream = MediaStream::new(cx, &global);
        let mut track_count = 0;
        if let Some(constraints) = convert_constraints(&constraints.audio)
            && let Some(audio) = media.create_audioinput_stream(constraints)
        {
            let track = MediaStreamTrack::new(cx, &global, audio, MediaStreamType::Audio);
            stream.add_track(&track);
            track_count += 1;
        }
        if let Some(constraints) = convert_constraints(&constraints.video)
            && let Some(video) = media.create_videoinput_stream(constraints)
        {
            let track = MediaStreamTrack::new(cx, &global, video, MediaStreamType::Video);
            stream.add_track(&track);
            track_count += 1;
        }
        if track_count == 0 {
            p.reject_error(cx, Error::NotFound(None));
            return p;
        }

        p.resolve_native(cx, &stream);
        p
    }

    /// <https://w3c.github.io/mediacapture-main/#dom-mediadevices-enumeratedevices>
    fn EnumerateDevices(&self, cx: &mut JSContext) -> Rc<Promise> {
        // Step 1.
        let mut realm = CurrentRealm::assert(cx);
        let p = Promise::new_in_realm(&mut realm);

        // Step 2.
        // XXX These steps should be run in parallel.
        // XXX Steps 2.1 - 2.4

        // Step 2.5
        let media = ServoMedia::get();
        let device_monitor = media.get_device_monitor();
        let global = self.global();
        let result_list = device_monitor
            .enumerate_devices()
            .map(|devices| {
                devices
                    .iter()
                    .map(|device| {
                        // Device kinds may be exposed before permission, but
                        // stable hardware IDs and human-readable labels must
                        // not leak until the corresponding capture/output
                        // permission has been granted.
                        let identity_visible = match device.kind {
                            servo_media::streams::device_monitor::MediaDeviceKind::AudioInput => {
                                descriptor_permission_state(
                                    PermissionName::Microphone,
                                    Some(&global),
                                ) == PermissionState::Granted
                            },
                            servo_media::streams::device_monitor::MediaDeviceKind::AudioOutput => {
                                descriptor_permission_state(PermissionName::Speaker, Some(&global))
                                    == PermissionState::Granted
                            },
                            servo_media::streams::device_monitor::MediaDeviceKind::VideoInput => {
                                descriptor_permission_state(PermissionName::Camera, Some(&global))
                                    == PermissionState::Granted
                            },
                        };
                        let (device_id, label) = if identity_visible {
                            (device.device_id.as_str(), device.label.as_str())
                        } else {
                            ("", "")
                        };
                        MediaDeviceInfo::new(
                            cx,
                            &global,
                            device_id,
                            device.kind.convert(),
                            label,
                            "",
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        p.resolve_native(cx, &result_list);

        // Step 3.
        p
    }
}

fn convert_constraints(js: &BooleanOrMediaTrackConstraints) -> Option<MediaTrackConstraintSet> {
    match js {
        BooleanOrMediaTrackConstraints::Boolean(false) => None,
        BooleanOrMediaTrackConstraints::Boolean(true) => Some(Default::default()),
        BooleanOrMediaTrackConstraints::MediaTrackConstraints(c) => Some(MediaTrackConstraintSet {
            height: c.parent.height.as_ref().and_then(convert_culong),
            width: c.parent.width.as_ref().and_then(convert_culong),
            aspect: c.parent.aspectRatio.as_ref().and_then(convert_cdouble),
            frame_rate: c.parent.frameRate.as_ref().and_then(convert_cdouble),
            sample_rate: c.parent.sampleRate.as_ref().and_then(convert_culong),
        }),
    }
}

fn convert_culong(js: &ConstrainULong) -> Option<Constrain<u32>> {
    match js {
        ConstrainULong::ClampedUnsignedLong(val) => Some(Constrain::Value(*val)),
        ConstrainULong::ConstrainULongRange(range) => {
            if range.parent.min.is_some() || range.parent.max.is_some() {
                Some(Constrain::Range(ConstrainRange {
                    min: range.parent.min,
                    max: range.parent.max,
                    ideal: range.ideal,
                }))
            } else {
                range.exact.map(Constrain::Value)
            }
        },
    }
}

fn convert_cdouble(js: &ConstrainDouble) -> Option<Constrain<f64>> {
    match js {
        ConstrainDouble::Double(val) => Some(Constrain::Value(**val)),
        ConstrainDouble::ConstrainDoubleRange(range) => {
            if range.parent.min.is_some() || range.parent.max.is_some() {
                Some(Constrain::Range(ConstrainRange {
                    min: range.parent.min.map(|x| *x),
                    max: range.parent.max.map(|x| *x),
                    ideal: range.ideal.map(|x| *x),
                }))
            } else {
                range.exact.map(|exact| Constrain::Value(*exact))
            }
        },
    }
}
