/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::{cmp, mem};

use glib;
use glib::prelude::*;
use gstreamer;
use gstreamer::prelude::*;
use gstreamer_sdp;
use gstreamer_webrtc;
use log::warn;
use servo_media_streams::MediaStreamType;
use servo_media_streams::registry::{MediaStreamId, get_stream};
use servo_media_webrtc::datachannel::DataChannelId;
use servo_media_webrtc::thread::InternalEvent;
use servo_media_webrtc::{WebRtcController as WebRtcThread, *};

use super::BACKEND_BASE_TIME;
use crate::datachannel::GStreamerWebRtcDataChannel;
use crate::media_stream::GStreamerMediaStream;

// TODO:
// - figure out purpose of glib loop

#[derive(Debug, Clone)]
pub struct MLineInfo {
    /// The caps for the given m-line
    caps: gstreamer::Caps,
    /// Whether or not this sink pad has already been connected
    is_used: bool,
    /// The payload value of the given m-line
    payload: i32,
}

enum DataChannelEventTarget {
    Buffered(Vec<DataChannelEvent>),
    Created(GStreamerWebRtcDataChannel),
}

pub struct GStreamerWebRtcController {
    webrtc: gstreamer::Element,
    pipeline: gstreamer::Pipeline,
    /// We can't trigger a negotiation-needed event until we have streams, or otherwise
    /// a createOffer() call will lead to bad SDP. Instead, we delay negotiation.
    delayed_negotiation: bool,
    /// A handle to the event loop abstraction surrounding the webrtc implementations,
    /// which lets gstreamer callbacks send events back to the event loop to run on this object
    thread: WebRtcThread,
    signaller: Box<dyn WebRtcSignaller>,
    /// All the streams that are actually connected to the webrtcbin (i.e., their presence has already
    /// been negotiated)
    streams: Vec<MediaStreamId>,
    /// Disconnected streams that are waiting to be linked. Streams are
    /// only linked when:
    ///
    /// - An offer is made (all pending streams are flushed)
    /// - An offer is received (all matching pending streams are flushed)
    /// - A stream is added when there is a so-far-disconnected remote-m-line
    ///
    /// In other words, these are all yet to be negotiated
    ///
    /// See link_stream
    pending_streams: Vec<MediaStreamId>,
    /// Each new webrtc stream should have a new payload/pt value, starting at 96
    ///
    /// This is maintained as a known yet-unused payload number, being incremented whenever
    /// we use it, and set to (remote_pt + 1) if the remote sends us a stream with a higher pt
    pt_counter: i32,
    /// We keep track of how many request pads have been created on webrtcbin
    /// so that we can request more to fill in the gaps and acquire a specific pad if necessary
    request_pad_counter: usize,
    /// Source/sink pads and payloads for connected local streams. This lets a sender replace its
    /// source without allocating a new media section.
    stream_links: HashMap<MediaStreamId, (gstreamer::Pad, gstreamer::Pad, i32)>,
    /// Streams need to be connected to the relevant sink pad, and we figure this out
    /// by keeping track of the caps of each m-line in the SDP.
    remote_mline_info: Vec<MLineInfo>,
    /// Temporary storage for remote_mline_info until the remote description is applied
    ///
    /// Without this, a unluckily timed call to link_stream() may happen before the webrtcbin
    /// knows the remote description, but while we _think_ it does
    pending_remote_mline_info: Vec<MLineInfo>,
    /// In case we get multiple remote offers, this lets us keep track of which is the newest
    remote_offer_generation: u32,
    _main_loop: glib::MainLoop,
    data_channels: Arc<Mutex<HashMap<DataChannelId, DataChannelEventTarget>>>,
    next_data_channel_id: Arc<AtomicUsize>,
    /// Data channels for which an Open event was already forwarded. Both the
    /// native signal path and the state-reconcile monitor below funnel through
    /// the same internal event, so this keeps exactly-once delivery.
    open_forwarded: HashSet<DataChannelId>,
}

impl WebRtcControllerBackend for GStreamerWebRtcController {
    fn add_ice_candidate(&mut self, candidate: IceCandidate) -> WebRtcResult {
        self.webrtc.emit_by_name::<()>(
            "add-ice-candidate",
            &[&candidate.sdp_mline_index, &candidate.candidate],
        );
        Ok(())
    }

    fn set_remote_description(
        &mut self,
        desc: SessionDescription,
        cb: WebRtcDescriptionCallback,
    ) -> WebRtcResult {
        self.set_description(desc, DescriptionType::Remote, cb)
    }

    fn set_local_description(
        &mut self,
        desc: SessionDescription,
        cb: WebRtcDescriptionCallback,
    ) -> WebRtcResult {
        self.set_description(desc, DescriptionType::Local, cb)
    }

    fn create_offer(
        &mut self,
        cb: Box<dyn FnOnce(SessionDescription) + Send + 'static>,
    ) -> WebRtcResult {
        self.flush_pending_streams(true)?;
        self.pipeline.set_state(gstreamer::State::Playing)?;
        let promise = gstreamer::Promise::with_change_func(move |res| {
            res.map(|s| on_offer_or_answer_created(SdpType::Offer, s.unwrap(), cb))
                .unwrap();
        });

        self.webrtc
            .emit_by_name::<()>("create-offer", &[&None::<gstreamer::Structure>, &promise]);
        Ok(())
    }

    fn create_answer(
        &mut self,
        cb: Box<dyn FnOnce(SessionDescription) + Send + 'static>,
    ) -> WebRtcResult {
        let promise = gstreamer::Promise::with_change_func(move |res| {
            res.map(|s| on_offer_or_answer_created(SdpType::Answer, s.unwrap(), cb))
                .unwrap();
        });

        self.webrtc
            .emit_by_name::<()>("create-answer", &[&None::<gstreamer::Structure>, &promise]);
        Ok(())
    }

    fn add_stream(&mut self, stream_id: &MediaStreamId) -> WebRtcResult {
        let stream =
            get_stream(stream_id).expect("Media streams registry does not contain such ID");
        let mut stream = stream.lock().unwrap();
        let stream = stream
            .as_mut_any()
            .downcast_mut::<GStreamerMediaStream>()
            .ok_or("Does not currently support non-gstreamer streams")?;
        self.link_stream(stream_id, stream, false)?;
        if self.delayed_negotiation && (self.streams.len() > 1 || self.pending_streams.len() > 1) {
            self.delayed_negotiation = false;
            self.signaller.on_negotiation_needed(&self.thread);
        }
        Ok(())
    }

    fn replace_stream(
        &mut self,
        old_stream_id: &MediaStreamId,
        new_stream_id: &MediaStreamId,
    ) -> WebRtcResult {
        if old_stream_id == new_stream_id {
            return Ok(());
        }
        if self.streams.contains(new_stream_id) || self.pending_streams.contains(new_stream_id) {
            return Err(WebRtcError::Backend(
                "replacement stream is already attached to this peer connection".to_owned(),
            ));
        }

        if let Some(index) = self
            .pending_streams
            .iter()
            .position(|stream| stream == old_stream_id)
        {
            self.pending_streams[index] = *new_stream_id;
            return Ok(());
        }

        let (old_src, sink, payload) = self
            .stream_links
            .remove(old_stream_id)
            .ok_or_else(|| WebRtcError::Backend("sender stream is not attached".to_owned()))?;
        let stream = get_stream(new_stream_id).ok_or_else(|| {
            WebRtcError::Backend("replacement media stream is unknown".to_owned())
        })?;
        let mut stream = stream.lock().unwrap();
        let stream = stream
            .as_mut_any()
            .downcast_mut::<GStreamerMediaStream>()
            .ok_or_else(|| {
                WebRtcError::Backend("sender replacement requires the GStreamer backend".to_owned())
            })?;

        old_src.unlink(&sink).map_err(|error| {
            WebRtcError::Backend(format!("failed to detach sender stream: {error}"))
        })?;
        stream.attach_to_pipeline(&self.pipeline);
        let element = stream.encoded().map_err(|_| {
            WebRtcError::Backend("failed to attach replacement encoding adapters".to_owned())
        })?;
        element.set_property("caps", stream.caps_with_payload(payload));
        let new_src = element.static_pad("src").ok_or_else(|| {
            WebRtcError::Backend("replacement stream has no source pad".to_owned())
        })?;
        if let Err(error) = new_src.link(&sink) {
            let _ = old_src.link(&sink);
            self.stream_links
                .insert(*old_stream_id, (old_src, sink, payload));
            return Err(WebRtcError::Backend(format!(
                "failed to attach replacement sender stream: {error}"
            )));
        }

        if let Some(old_stream) = get_stream(old_stream_id) {
            old_stream.lock().unwrap().stop();
        }
        self.streams.retain(|stream| stream != old_stream_id);
        self.streams.push(*new_stream_id);
        self.stream_links
            .insert(*new_stream_id, (new_src, sink, payload));
        Ok(())
    }

    fn set_sender_parameters(
        &mut self,
        stream_id: &MediaStreamId,
        parameters: &RtpSenderParameters,
    ) -> WebRtcResult {
        let stream = get_stream(stream_id)
            .ok_or_else(|| WebRtcError::Backend("unknown media stream".to_owned()))?;
        let mut stream = stream.lock().unwrap();
        let stream = stream
            .as_mut_any()
            .downcast_mut::<GStreamerMediaStream>()
            .ok_or_else(|| {
                WebRtcError::Backend("sender parameters require the GStreamer backend".to_owned())
            })?;
        stream.set_sender_parameters(parameters.clone())
    }

    fn create_data_channel(&mut self, init: &DataChannelInit) -> WebRtcDataChannelResult {
        let id = self.next_data_channel_id.fetch_add(1, Ordering::Relaxed);
        match GStreamerWebRtcDataChannel::new(&id, &self.webrtc, &self.thread, init) {
            Ok(channel) => register_data_channel(self.data_channels.clone(), id, channel),
            Err(error) => Err(WebRtcError::Backend(error)),
        }
    }

    fn close_data_channel(&mut self, id: &DataChannelId) -> WebRtcResult {
        // There is no need to unregister the channel here. It will be unregistered
        // when the data channel backend triggers the on closed event.
        let mut data_channels = self.data_channels.lock().unwrap();
        match data_channels.get(id) {
            Some(ref channel) => match channel {
                DataChannelEventTarget::Created(channel) => {
                    channel.close();
                    Ok(())
                },
                DataChannelEventTarget::Buffered(_) => data_channels
                    .remove(id)
                    .ok_or(WebRtcError::Backend("Unknown data channel".to_owned()))
                    .map(|_| ()),
            },
            None => Err(WebRtcError::Backend("Unknown data channel".to_owned())),
        }
    }

    fn send_data_channel_message(
        &mut self,
        id: &DataChannelId,
        message: &DataChannelMessage,
    ) -> WebRtcResult {
        match self.data_channels.lock().unwrap().get(id) {
            Some(ref channel) => match channel {
                DataChannelEventTarget::Created(channel) => channel.send(message),
                _ => Ok(()),
            },
            None => Err(WebRtcError::Backend("Unknown data channel".to_owned())),
        }
    }

    fn configure(&mut self, stun_server: &str, policy: BundlePolicy) -> WebRtcResult {
        self.webrtc
            .set_property_from_str("stun-server", stun_server);
        self.webrtc
            .set_property_from_str("bundle-policy", policy.as_str());
        Ok(())
    }

    fn internal_event(&mut self, e: thread::InternalEvent) -> WebRtcResult {
        match e {
            InternalEvent::OnNegotiationNeeded => {
                if self.streams.is_empty() && self.pending_streams.is_empty() {
                    // we have no streams

                    // If the pipeline starts playing and on-negotiation-needed is present before there are any
                    // media streams, an invalid SDP offer will be created. Therefore, delay emitting the signal
                    self.delayed_negotiation = true;
                } else {
                    self.signaller.on_negotiation_needed(&self.thread);
                }
            },
            InternalEvent::OnIceCandidate(candidate) => {
                self.signaller.on_ice_candidate(&self.thread, candidate);
            },
            InternalEvent::OnAddStream(stream, ty) => {
                self.pipeline.set_state(gstreamer::State::Playing)?;
                self.signaller.on_add_stream(&stream, ty);
            },
            InternalEvent::OnDataChannelEvent(channel_id, event) => {
                let mut data_channels = self.data_channels.lock().unwrap();
                match data_channels.get_mut(&channel_id) {
                    None => {
                        data_channels
                            .insert(channel_id, DataChannelEventTarget::Buffered(vec![event]));
                    },
                    Some(ref mut channel) => match channel {
                        &mut &mut DataChannelEventTarget::Buffered(ref mut events) => {
                            events.push(event);
                            return Ok(());
                        },
                        DataChannelEventTarget::Created(_) => {
                            if let DataChannelEvent::Close = event {
                                data_channels.remove(&channel_id);
                                self.open_forwarded.remove(&channel_id);
                            }
                            // Exactly-once Open delivery: the native signal
                            // path and the reconcile monitor below share this
                            // funnel.
                            if matches!(event, DataChannelEvent::Open)
                                && !self.open_forwarded.insert(channel_id)
                            {
                                return Ok(());
                            }
                            self.signaller
                                .on_data_channel_event(channel_id, event, &self.thread);
                        },
                    },
                }
            },
            InternalEvent::DescriptionAdded(
                cb,
                description_type,
                ty,
                remote_offer_generation,
                result,
            ) => {
                let result = result.and_then(|()| {
                    if description_type == DescriptionType::Remote
                        && ty == SdpType::Offer
                        && remote_offer_generation == self.remote_offer_generation
                    {
                        mem::swap(
                            &mut self.pending_remote_mline_info,
                            &mut self.remote_mline_info,
                        );
                        self.pending_remote_mline_info.clear();
                        self.flush_pending_streams(false)?;
                    }
                    self.pipeline.set_state(gstreamer::State::Playing)?;
                    Ok(())
                });
                cb(result);
            },
            InternalEvent::UpdateSignalingState => {
                use gstreamer_webrtc::WebRTCSignalingState::*;
                let val = self
                    .webrtc
                    .property::<gstreamer_webrtc::WebRTCSignalingState>("signaling-state");
                let state = match val {
                    Stable => SignalingState::Stable,
                    HaveLocalOffer => SignalingState::HaveLocalOffer,
                    HaveRemoteOffer => SignalingState::HaveRemoteOffer,
                    HaveLocalPranswer => SignalingState::HaveLocalPranswer,
                    HaveRemotePranswer => SignalingState::HaveRemotePranswer,
                    Closed => SignalingState::Closed,
                    i => {
                        return Err(WebRtcError::Backend(format!(
                            "unknown signaling state: {:?}",
                            i
                        )));
                    },
                };
                self.signaller.update_signaling_state(state);
            },
            InternalEvent::UpdateGatheringState => {
                use gstreamer_webrtc::WebRTCICEGatheringState::*;
                let val = self
                    .webrtc
                    .property::<gstreamer_webrtc::WebRTCICEGatheringState>("ice-gathering-state");
                let state = match val {
                    New => GatheringState::New,
                    Gathering => GatheringState::Gathering,
                    Complete => GatheringState::Complete,
                    i => {
                        return Err(WebRtcError::Backend(format!(
                            "unknown gathering state: {:?}",
                            i
                        )));
                    },
                };
                self.signaller.update_gathering_state(state);
            },
            InternalEvent::UpdateIceConnectionState => {
                use gstreamer_webrtc::WebRTCICEConnectionState::*;
                let val = self
                    .webrtc
                    .property::<gstreamer_webrtc::WebRTCICEConnectionState>("ice-connection-state");
                let state = match val {
                    New => IceConnectionState::New,
                    Checking => IceConnectionState::Checking,
                    Connected => IceConnectionState::Connected,
                    Completed => IceConnectionState::Completed,
                    Disconnected => IceConnectionState::Disconnected,
                    Failed => IceConnectionState::Failed,
                    Closed => IceConnectionState::Closed,
                    i => {
                        return Err(WebRtcError::Backend(format!(
                            "unknown ICE connection state: {:?}",
                            i
                        )));
                    },
                };
                self.signaller.update_ice_connection_state(state);
            },
        }
        Ok(())
    }

    fn quit(&mut self) {
        self.signaller.close();

        self.pipeline.set_state(gstreamer::State::Null).unwrap();
    }
}

impl GStreamerWebRtcController {
    fn set_description(
        &mut self,
        desc: SessionDescription,
        description_type: DescriptionType,
        cb: WebRtcDescriptionCallback,
    ) -> WebRtcResult {
        let ty = match desc.type_ {
            SdpType::Answer => gstreamer_webrtc::WebRTCSDPType::Answer,
            SdpType::Offer => gstreamer_webrtc::WebRTCSDPType::Offer,
            SdpType::Pranswer => gstreamer_webrtc::WebRTCSDPType::Pranswer,
            SdpType::Rollback => gstreamer_webrtc::WebRTCSDPType::Rollback,
        };

        let kind = match description_type {
            DescriptionType::Local => "set-local-description",
            DescriptionType::Remote => "set-remote-description",
        };

        let sdp = match gstreamer_sdp::SDPMessage::parse_buffer(desc.sdp.as_bytes()) {
            Ok(sdp) => sdp,
            Err(error) => {
                let description_name = match description_type {
                    DescriptionType::Local => "local",
                    DescriptionType::Remote => "remote",
                };
                cb(Err(WebRtcError::from(format!(
                    "failed to parse {} SDP: {}",
                    description_name, error
                ))));
                return Ok(());
            },
        };
        if description_type == DescriptionType::Remote {
            self.remote_offer_generation += 1;
            self.store_remote_mline_info(&sdp);
        }
        let answer = gstreamer_webrtc::WebRTCSessionDescription::new(ty, sdp);
        let thread = self.thread.clone();
        let remote_offer_generation = self.remote_offer_generation;
        let promise = gstreamer::Promise::with_change_func(move |promise_result| {
            // remote_offer_generation here ensures that DescriptionAdded doesn't
            // flush pending_remote_mline_info for stale remote offer callbacks
            let result = if promise_result.is_err() {
                let description_name = match description_type {
                    DescriptionType::Local => "local",
                    DescriptionType::Remote => "remote",
                };
                Err(WebRtcError::Backend(format!(
                    "GStreamer rejected {} SDP",
                    description_name
                )))
            } else {
                Ok(())
            };
            thread.internal_event(InternalEvent::DescriptionAdded(
                cb,
                description_type,
                desc.type_,
                remote_offer_generation,
                result,
            ));
        });
        self.webrtc.emit_by_name::<()>(kind, &[&answer, &promise]);
        Ok(())
    }

    fn store_remote_mline_info(&mut self, sdp: &gstreamer_sdp::SDPMessage) {
        self.pending_remote_mline_info.clear();
        for media in sdp.medias() {
            let mut caps = gstreamer::Caps::new_empty();
            let caps_mut = caps.get_mut().expect("Fresh caps should be uniquely owned");
            for format in media.formats() {
                if format == "webrtc-datachannel" {
                    return;
                }
                let pt = format
                    .parse()
                    .expect("Gstreamer provided noninteger format");
                caps_mut.append(
                    media
                        .caps_from_media(pt)
                        .expect("get_format() did not return a format from the SDP"),
                );
                self.pt_counter = cmp::max(self.pt_counter, pt + 1);
            }
            for s in caps_mut.iter_mut() {
                // the caps are application/x-unknown by default, which will fail
                // to intersect
                //
                // see https://gitlab.freedesktop.org/gstreamer/gst-plugins-bad/blob/ba62917fbfd98ea76d4e066a6f18b4a14b847362/ext/webrtc/gstwebrtcbin.c#L2521
                s.set_name("application/x-rtp")
            }
            // This info is not current until the promise from set-remote-description is resolved,
            // to avoid any races where we attempt to link streams before the promise resolves we
            // queue this up in a pending buffer
            self.pending_remote_mline_info.push(MLineInfo {
                caps,
                // XXXManishearth in the (yet unsupported) case of dynamic stream addition and renegotiation
                // this will need to be checked against the current set of streams
                is_used: false,
                // XXXManishearth ideally, we keep track of all payloads and have the capability of picking
                // the appropriate decoder. For this, a bunch of the streams code will have to be moved into
                // a webrtc-specific abstraction.
                payload: media
                    .format(0)
                    .expect("Gstreamer reported incorrect formats_len()")
                    .parse()
                    .expect("Gstreamer provided noninteger format"),
            });
        }
    }

    /// Streams need to be linked to the correct pads, so we buffer them up until we know enough
    /// to do this.
    ///
    /// When we get a remote offer, we store the relevant m-line information so that we can
    /// pick the correct sink pad and payload. Shortly after we look for any pending streams
    /// and connect them to available compatible m-lines using link_stream.
    ///
    /// When we create an offer, we're controlling the pad order, so we set request_new_pads
    /// to true and forcefully link all pending streams before generating the offer.
    ///
    /// When request_new_pads is false, we may still request new pads, however we only do this for
    /// streams that have already been negotiated by the remote.
    fn link_stream(
        &mut self,
        stream_id: &MediaStreamId,
        stream: &mut GStreamerMediaStream,
        request_new_pads: bool,
    ) -> WebRtcResult {
        let caps = stream.caps();
        let idx = self
            .remote_mline_info
            .iter()
            .enumerate()
            .filter(|(_, x)| !x.is_used)
            .find(|(_, x)| x.caps.can_intersect(caps))
            .map(|x| x.0);
        if let Some(idx) = idx {
            if idx >= self.request_pad_counter {
                for i in self.request_pad_counter..=idx {
                    // webrtcbin needs you to request pads (or use element.link(webrtcbin))
                    // however, it also wants them to be connected in the correct order.
                    //
                    // Here, we make sure all the numbered sink pads have been created beforehand, up to
                    // and including the one we need here.
                    //
                    // An alternate fix is to sort pending_streams according to the m-line index
                    // and just do it in order. This also seems brittle.
                    self.webrtc
                        .request_pad_simple(&format!("sink_{}", i))
                        .ok_or("Cannot request sink pad")?;
                }
                self.request_pad_counter = idx + 1;
            }
            stream.attach_to_pipeline(&self.pipeline);
            let element = stream.encoded().map_err(|_| {
                WebRtcError::Backend(String::from("Failed to attach encoding adapters to stream"))
            })?;
            self.remote_mline_info[idx].is_used = true;
            let caps = stream.caps_with_payload(self.remote_mline_info[idx].payload);
            element.set_property("caps", &caps);
            let src = element.static_pad("src").ok_or("Cannot request src pad")?;
            let sink = self
                .webrtc
                .static_pad(&format!("sink_{}", idx))
                .ok_or("Cannot request sink pad")?;
            src.link(&sink)?;
            let payload = self.remote_mline_info[idx].payload;
            self.stream_links.insert(*stream_id, (src, sink, payload));
            self.streams.push(*stream_id);
        } else if request_new_pads {
            stream.attach_to_pipeline(&self.pipeline);
            let element = stream.encoded().map_err(|_| {
                WebRtcError::Backend(String::from("Failed to attach encoding adapters to stream"))
            })?;
            let caps = stream.caps_with_payload(self.pt_counter);
            self.pt_counter += 1;
            element.set_property("caps", &caps);
            let src = element.static_pad("src").ok_or("Cannot request src pad")?;
            let sink = self
                .webrtc
                .request_pad_simple(&format!("sink_{}", self.request_pad_counter))
                .ok_or("Cannot request sink pad")?;
            self.request_pad_counter += 1;
            src.link(&sink)?;
            self.stream_links
                .insert(*stream_id, (src, sink, self.pt_counter - 1));
            self.streams.push(*stream_id);
        } else {
            self.pending_streams.push(*stream_id);
        }
        Ok(())
    }

    /// link_stream, but for all pending streams
    fn flush_pending_streams(&mut self, request_new_pads: bool) -> WebRtcResult {
        let pending_streams = std::mem::take(&mut self.pending_streams);
        for stream_id in pending_streams {
            let stream =
                get_stream(&stream_id).expect("Media streams registry does not contain such ID");
            let mut stream = stream.lock().unwrap();
            let stream = stream
                .as_mut_any()
                .downcast_mut::<GStreamerMediaStream>()
                .ok_or("Does not currently support non-gstreamer streams")?;
            self.link_stream(&stream_id, stream, request_new_pads)?;
        }
        Ok(())
    }

    fn start_pipeline(&mut self) -> WebRtcResult {
        self.pipeline.add(&self.webrtc)?;

        // gstreamer needs Sync on these callbacks for some reason
        // https://github.com/sdroege/gstreamer-rs/issues/154
        let thread = Mutex::new(self.thread.clone());
        self.webrtc
            .connect("on-ice-candidate", false, move |values| {
                thread
                    .lock()
                    .unwrap()
                    .internal_event(InternalEvent::OnIceCandidate(candidate(values)));
                None
            });

        let thread = Arc::new(Mutex::new(self.thread.clone()));
        self.webrtc.connect_pad_added({
            let pipeline_weak = self.pipeline.downgrade();
            move |_element, pad| {
                let Some(pipe) = pipeline_weak.upgrade() else {
                    warn!("Pipeline already deallocated");
                    return;
                };
                process_new_stream(pad, &pipe, thread.clone());
            }
        });

        // gstreamer needs Sync on these callbacks for some reason
        // https://github.com/sdroege/gstreamer-rs/issues/154
        let thread = Mutex::new(self.thread.clone());
        self.webrtc
            .connect("on-negotiation-needed", false, move |_values| {
                thread
                    .lock()
                    .unwrap()
                    .internal_event(InternalEvent::OnNegotiationNeeded);
                None
            });

        let thread = Mutex::new(self.thread.clone());
        self.webrtc
            .connect("notify::signaling-state", false, move |_values| {
                thread
                    .lock()
                    .unwrap()
                    .internal_event(InternalEvent::UpdateSignalingState);
                None
            });
        let thread = Mutex::new(self.thread.clone());
        self.webrtc
            .connect("notify::ice-connection-state", false, move |_values| {
                thread
                    .lock()
                    .unwrap()
                    .internal_event(InternalEvent::UpdateIceConnectionState);
                None
            });
        let thread = Mutex::new(self.thread.clone());
        self.webrtc
            .connect("notify::ice-gathering-state", false, move |_values| {
                thread
                    .lock()
                    .unwrap()
                    .internal_event(InternalEvent::UpdateGatheringState);
                None
            });
        let thread = Mutex::new(self.thread.clone());
        let data_channels = self.data_channels.clone();
        let next_data_channel_id = self.next_data_channel_id.clone();
        self.webrtc
            .connect("on-data-channel", false, move |channel| {
                let channel = channel[1]
                    .get::<gstreamer_webrtc::WebRTCDataChannel>()
                    .map_err(|e| e.to_string())
                    .expect("Invalid data channel");
                let id = next_data_channel_id.fetch_add(1, Ordering::Relaxed);
                let thread_ = thread.lock().unwrap().clone();
                match GStreamerWebRtcDataChannel::from(&id, channel, &thread_) {
                    Ok(channel) => {
                        let mut closed_channel = false;
                        {
                            thread_.internal_event(InternalEvent::OnDataChannelEvent(
                                id,
                                DataChannelEvent::NewChannel,
                            ));

                            let mut data_channels = data_channels.lock().unwrap();
                            if let Some(ref mut channel) = data_channels.get_mut(&id) {
                                match channel {
                                    &mut &mut DataChannelEventTarget::Buffered(ref mut events) => {
                                        for event in events.drain(0..) {
                                            if let DataChannelEvent::Close = event {
                                                closed_channel = true
                                            }
                                            thread_.internal_event(
                                                InternalEvent::OnDataChannelEvent(id, event),
                                            );
                                        }
                                    },
                                    _ => debug_assert!(
                                        false,
                                        "Trying to register a data channel with an existing ID"
                                    ),
                                }
                            }
                            data_channels.remove(&id);
                        }
                        if !closed_channel
                            && register_data_channel(data_channels.clone(), id, channel).is_err()
                        {
                            warn!("Could not register data channel {:?}", id);
                            return None;
                        }
                    },
                    Err(error) => {
                        warn!("Could not create data channel {:?}", error);
                    },
                }
                None
            });

        self.pipeline.set_state(gstreamer::State::Ready)?;
        Ok(())
    }
}

pub fn construct(
    signaller: Box<dyn WebRtcSignaller>,
    thread: WebRtcThread,
) -> Result<GStreamerWebRtcController, WebRtcError> {
    let main_loop = glib::MainLoop::new(None, false);
    let pipeline = gstreamer::Pipeline::with_name("webrtc main");
    pipeline.set_start_time(gstreamer::ClockTime::NONE);
    pipeline.set_base_time(*BACKEND_BASE_TIME);
    pipeline.use_clock(Some(&gstreamer::SystemClock::obtain()));
    let webrtc = gstreamer::ElementFactory::make("webrtcbin")
        .name("sendrecv")
        .build()
        .map_err(|error| format!("webrtcbin element not found: {error:?}"))?;
    let mut controller = GStreamerWebRtcController {
        webrtc,
        pipeline,
        signaller,
        thread,
        remote_mline_info: vec![],
        pending_remote_mline_info: vec![],
        streams: vec![],
        pending_streams: vec![],
        pt_counter: 96,
        request_pad_counter: 0,
        stream_links: HashMap::new(),
        remote_offer_generation: 0,
        delayed_negotiation: false,
        _main_loop: main_loop,
        data_channels: Arc::new(Mutex::new(HashMap::new())),
        next_data_channel_id: Arc::new(AtomicUsize::new(0)),
        open_forwarded: HashSet::new(),
    };
    controller.start_pipeline()?;
    spawn_state_reconciler(&controller);
    Ok(controller)
}

/// Poll transport and data-channel states that GStreamer may advance without
/// emitting the corresponding signals in an embedding.
///
/// Observed on macOS against GStreamer 1.28: `ice-connection-state` and data
/// channel `open` transitions happen at the transport level (verified with
/// element debug output) but their GObject notifications never reach the
/// backend, while gathering notifications and regular signals do. This
/// reconciler reads the live properties on a short interval and funnels
/// changes through the normal internal events; both the DOM layer (which
/// dedupes unchanged ICE states) and the Open exactly-once gate above make
/// this safe against double delivery should the native signals start firing.
fn spawn_state_reconciler(controller: &GStreamerWebRtcController) {
    use gstreamer_webrtc::WebRTCDataChannelState;
    use std::time::Duration;

    let webrtc = controller.webrtc.clone();
    let thread = controller.thread.clone();
    let channels = controller.data_channels.clone();
    std::thread::Builder::new()
        .name("webrtc-state-reconciler".to_owned())
        .spawn(move || {
            let mut last_ice: Option<IceConnectionState> = None;
            let mut channel_open: HashMap<DataChannelId, bool> = HashMap::new();
            // Bounded: worst case two minutes, exits early on terminal ICE.
            for _ in 0..480 {
                let ice_now: IceConnectionState = match webrtc
                    .property::<gstreamer_webrtc::WebRTCICEConnectionState>(
                    "ice-connection-state",
                ) {
                    gstreamer_webrtc::WebRTCICEConnectionState::New => IceConnectionState::New,
                    gstreamer_webrtc::WebRTCICEConnectionState::Checking => {
                        IceConnectionState::Checking
                    },
                    gstreamer_webrtc::WebRTCICEConnectionState::Connected => {
                        IceConnectionState::Connected
                    },
                    gstreamer_webrtc::WebRTCICEConnectionState::Completed => {
                        IceConnectionState::Completed
                    },
                    gstreamer_webrtc::WebRTCICEConnectionState::Disconnected => {
                        IceConnectionState::Disconnected
                    },
                    gstreamer_webrtc::WebRTCICEConnectionState::Failed => {
                        IceConnectionState::Failed
                    },
                    gstreamer_webrtc::WebRTCICEConnectionState::Closed => {
                        IceConnectionState::Closed
                    },
                    _ => IceConnectionState::New,
                };
                if Some(ice_now) != last_ice {
                    thread.internal_event(InternalEvent::UpdateIceConnectionState);
                    last_ice = Some(ice_now);
                }
                if let Ok(map) = channels.lock() {
                    for (id, target) in map.iter() {
                        if let DataChannelEventTarget::Created(channel) = target {
                            let open = channel.ready_state() == WebRTCDataChannelState::Open;
                            if open && !channel_open.get(id).copied().unwrap_or(false) {
                                channel_open.insert(*id, true);
                                thread.internal_event(InternalEvent::OnDataChannelEvent(
                                    *id,
                                    DataChannelEvent::Open,
                                ));
                            }
                        }
                    }
                }
                if matches!(
                    ice_now,
                    IceConnectionState::Connected
                        | IceConnectionState::Completed
                        | IceConnectionState::Failed
                        | IceConnectionState::Closed
                ) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        })
        .expect("webrtc reconciler thread spawn failed");
}

fn on_offer_or_answer_created(
    ty: SdpType,
    reply: &gstreamer::StructureRef,
    cb: Box<dyn FnOnce(SessionDescription) + Send + 'static>,
) {
    debug_assert!(ty == SdpType::Offer || ty == SdpType::Answer);
    let reply = reply
        .value(ty.as_str())
        .unwrap()
        .get::<gstreamer_webrtc::WebRTCSessionDescription>()
        .expect("Invalid argument");

    let type_ = match reply.type_() {
        gstreamer_webrtc::WebRTCSDPType::Answer => SdpType::Answer,
        gstreamer_webrtc::WebRTCSDPType::Offer => SdpType::Offer,
        gstreamer_webrtc::WebRTCSDPType::Pranswer => SdpType::Pranswer,
        gstreamer_webrtc::WebRTCSDPType::Rollback => SdpType::Rollback,
        _ => panic!("unknown sdp response"),
    };

    let desc = SessionDescription {
        sdp: reply.sdp().as_text().unwrap(),
        type_,
    };

    cb(desc);
}

fn media_name_of(pad: &gstreamer::Pad) -> Option<String> {
    pad.query_caps(None)
        .structure(0)
        .and_then(|structure| structure.get::<String>("media").ok())
}

fn on_incoming_stream(
    pipe: &gstreamer::Pipeline,
    thread: Arc<Mutex<WebRtcThread>>,
    pad: &gstreamer::Pad,
) {
    // Caps are often still bare templates when the pad appears; link once
    // negotiated caps with a media type arrive.
    if let Some(name) = media_name_of(pad) {
        link_incoming_stream(pipe, thread, pad, name);
        return;
    }
    let pipe_strong = pipe.clone();
    let thread_strong = thread.clone();
    let pad_strong = pad.clone();
    let handler: Arc<Mutex<Option<glib::SignalHandlerId>>> = Arc::new(Mutex::new(None));
    let handler_weak = handler.clone();
    let id = pad.connect_notify(Some("caps"), move |pad, _| {
        let Some(name) = media_name_of(pad) else {
            return;
        };
        if let Some(id) = handler_weak.lock().unwrap().take() {
            pad.disconnect(id);
        }
        link_incoming_stream(&pipe_strong, thread_strong.clone(), &pad_strong, name);
    });
    *handler.lock().unwrap() = Some(id);
}

fn link_incoming_stream(
    pipe: &gstreamer::Pipeline,
    thread: Arc<Mutex<WebRtcThread>>,
    pad: &gstreamer::Pad,
    name: String,
) {
    let decodebin = gstreamer::ElementFactory::make("decodebin")
        .build()
        .unwrap();
    let decodebin2 = decodebin.clone();
    decodebin.connect_pad_added({
        let pipeline_weak = pipe.downgrade();
        move |_element, pad| {
            let Some(pipe) = pipeline_weak.upgrade() else {
                warn!("Pipeline already deallocated");
                return;
            };
            on_incoming_decodebin_stream(pad, &pipe, thread.clone(), &name);
        }
    });
    pipe.add(&decodebin).unwrap();

    let decodepad = decodebin.static_pad("sink").unwrap();
    pad.link(&decodepad).unwrap();
    decodebin2.sync_state_with_parent().unwrap();
}

fn on_incoming_decodebin_stream(
    pad: &gstreamer::Pad,
    pipe: &gstreamer::Pipeline,
    thread: Arc<Mutex<WebRtcThread>>,
    name: &str,
) {
    let proxy_sink = gstreamer::ElementFactory::make("proxysink")
        .build()
        .unwrap();
    let proxy_src = gstreamer::ElementFactory::make("proxysrc")
        .property("proxysink", &proxy_sink)
        .build()
        .unwrap();
    pipe.add(&proxy_sink).unwrap();
    let sinkpad = proxy_sink.static_pad("sink").unwrap();

    pad.link(&sinkpad).unwrap();
    proxy_sink.sync_state_with_parent().unwrap();

    let (stream, ty) = if name == "video" {
        (
            GStreamerMediaStream::create_video_from(proxy_src),
            MediaStreamType::Video,
        )
    } else {
        (
            GStreamerMediaStream::create_audio_from(proxy_src),
            MediaStreamType::Audio,
        )
    };
    thread
        .lock()
        .unwrap()
        .internal_event(InternalEvent::OnAddStream(stream, ty));
}

fn process_new_stream(
    pad: &gstreamer::Pad,
    pipe: &gstreamer::Pipeline,
    thread: Arc<Mutex<WebRtcThread>>,
) {
    if pad.direction() != gstreamer::PadDirection::Src {
        // Ignore outgoing pad notifications.
        return;
    }
    on_incoming_stream(pipe, thread, pad)
}

fn candidate(values: &[glib::Value]) -> IceCandidate {
    let _webrtc = values[0]
        .get::<gstreamer::Element>()
        .expect("Invalid argument");
    let sdp_mline_index = values[1].get::<u32>().expect("Invalid argument");
    let candidate = values[2].get::<String>().expect("Invalid argument");

    IceCandidate {
        sdp_mline_index,
        candidate,
    }
}

fn register_data_channel(
    registry: Arc<Mutex<HashMap<DataChannelId, DataChannelEventTarget>>>,
    id: DataChannelId,
    channel: GStreamerWebRtcDataChannel,
) -> WebRtcDataChannelResult {
    if registry.lock().unwrap().contains_key(&id) {
        return Err(WebRtcError::Backend(
            "Could not register data channel. ID collision".to_owned(),
        ));
    }
    registry
        .lock()
        .unwrap()
        .insert(id, DataChannelEventTarget::Created(channel));
    Ok(id)
}
