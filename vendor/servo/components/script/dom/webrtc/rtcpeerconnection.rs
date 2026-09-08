/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::cell::Cell;
use std::rc::Rc;

use dom_struct::dom_struct;
use js::context::JSContext;
use js::realm::CurrentRealm;
use js::rust::HandleObject;
use rustc_hash::FxHashMap;
use script_bindings::cell::DomRefCell;
use script_bindings::reflector::reflect_weak_referenceable_dom_object_with_proto;
use script_bindings::script_runtime::temp_cx;
use servo_media::ServoMedia;
use servo_media::streams::MediaStreamType;
use servo_media::streams::registry::MediaStreamId;
use servo_media::webrtc::{
    BundlePolicy, DataChannelEvent, DataChannelId, DataChannelState, GatheringState, IceCandidate,
    IceConnectionState, SdpType, SessionDescription, SignalingState, WebRtcController, WebRtcError,
    WebRtcResult, WebRtcSignaller,
};

use crate::conversions::Convert;
use crate::dom::bindings::codegen::Bindings::RTCDataChannelBinding::RTCDataChannelInit;
use crate::dom::bindings::codegen::Bindings::RTCIceCandidateBinding::RTCIceCandidateInit;
use crate::dom::bindings::codegen::Bindings::RTCPeerConnectionBinding::{
    RTCAnswerOptions, RTCBundlePolicy, RTCConfiguration, RTCIceConnectionState,
    RTCIceGatheringState, RTCOfferOptions, RTCPeerConnectionMethods, RTCPeerConnectionState,
    RTCRtpTransceiverInit, RTCSignalingState,
};
use crate::dom::bindings::codegen::Bindings::RTCRtpTransceiverBinding::RTCRtpTransceiverDirection;
use crate::dom::bindings::codegen::Bindings::RTCSessionDescriptionBinding::{
    RTCSdpType, RTCSessionDescriptionInit, RTCSessionDescriptionMethods,
};
use crate::dom::bindings::codegen::UnionTypes::{MediaStreamTrackOrString, StringOrStringSequence};
use crate::dom::bindings::error::{Error, Fallible};
use crate::dom::bindings::inheritance::Castable;
use crate::dom::bindings::refcounted::{Trusted, TrustedPromise};
use crate::dom::bindings::reflector::DomGlobal;
use crate::dom::bindings::root::{Dom, DomRoot, MutNullableDom};
use crate::dom::bindings::str::USVString;
use crate::dom::event::{Event, EventBubbles, EventCancelable};
use crate::dom::eventtarget::EventTarget;
use crate::dom::mediastream::MediaStream;
use crate::dom::mediastreamtrack::MediaStreamTrack;
use crate::dom::promise::Promise;
use crate::dom::rtcdatachannel::RTCDataChannel;
use crate::dom::rtcdatachannelevent::RTCDataChannelEvent;
use crate::dom::rtcicecandidate::RTCIceCandidate;
use crate::dom::rtcpeerconnectioniceevent::RTCPeerConnectionIceEvent;
use crate::dom::rtcrtpsender::RTCRtpSender;
use crate::dom::rtcrtptransceiver::RTCRtpTransceiver;
use crate::dom::rtcsessiondescription::RTCSessionDescription;
use crate::dom::rtctrackevent::RTCTrackEvent;
use crate::dom::window::Window;
use crate::realms::enter_auto_realm;
use crate::tasks::task_source::SendableTaskSource;

#[dom_struct]
pub(crate) struct RTCPeerConnection {
    eventtarget: EventTarget,
    #[ignore_malloc_size_of = "defined in servo-media"]
    #[no_trace]
    controller: DomRefCell<Option<WebRtcController>>,
    closed: Cell<bool>,
    // Helps track state changes between the time createOffer/createAnswer
    // is called and resolved
    offer_answer_generation: Cell<u32>,
    #[conditional_malloc_size_of]
    offer_promises: DomRefCell<Vec<Rc<Promise>>>,
    #[conditional_malloc_size_of]
    answer_promises: DomRefCell<Vec<Rc<Promise>>>,
    local_description: MutNullableDom<RTCSessionDescription>,
    current_local_description: MutNullableDom<RTCSessionDescription>,
    pending_local_description: MutNullableDom<RTCSessionDescription>,
    remote_description: MutNullableDom<RTCSessionDescription>,
    current_remote_description: MutNullableDom<RTCSessionDescription>,
    pending_remote_description: MutNullableDom<RTCSessionDescription>,
    gathering_state: Cell<RTCIceGatheringState>,
    ice_connection_state: Cell<RTCIceConnectionState>,
    signaling_state: Cell<RTCSignalingState>,
    #[ignore_malloc_size_of = "defined in servo-media"]
    data_channels: DomRefCell<FxHashMap<DataChannelId, Dom<RTCDataChannel>>>,
    #[ignore_malloc_size_of = "stored DOM objects"]
    transceivers: DomRefCell<Vec<Dom<RTCRtpTransceiver>>>,
}

struct RTCSignaller {
    trusted: Trusted<RTCPeerConnection>,
    task_source: SendableTaskSource,
}

fn local_description_is_legal(state: RTCSignalingState, description: RTCSdpType) -> bool {
    match description {
        RTCSdpType::Offer => state == RTCSignalingState::Stable,
        RTCSdpType::Answer | RTCSdpType::Pranswer => matches!(
            state,
            RTCSignalingState::Have_remote_offer | RTCSignalingState::Have_remote_pranswer
        ),
        RTCSdpType::Rollback => {
            !matches!(state, RTCSignalingState::Stable | RTCSignalingState::Closed)
        },
    }
}

fn remote_description_is_legal(state: RTCSignalingState, description: RTCSdpType) -> bool {
    match description {
        RTCSdpType::Offer => matches!(
            state,
            RTCSignalingState::Stable | RTCSignalingState::Have_local_offer
        ),
        RTCSdpType::Answer | RTCSdpType::Pranswer => matches!(
            state,
            RTCSignalingState::Have_local_offer | RTCSignalingState::Have_local_pranswer
        ),
        RTCSdpType::Rollback => {
            !matches!(state, RTCSignalingState::Stable | RTCSignalingState::Closed)
        },
    }
}

fn local_description_next_state(description: RTCSdpType) -> Option<SignalingState> {
    Some(match description {
        RTCSdpType::Offer => SignalingState::HaveLocalOffer,
        RTCSdpType::Answer => SignalingState::Stable,
        RTCSdpType::Pranswer => SignalingState::HaveLocalPranswer,
        RTCSdpType::Rollback => SignalingState::Stable,
    })
}

fn remote_description_next_state(description: RTCSdpType) -> Option<SignalingState> {
    Some(match description {
        RTCSdpType::Offer => SignalingState::HaveRemoteOffer,
        RTCSdpType::Answer => SignalingState::Stable,
        RTCSdpType::Pranswer => SignalingState::HaveRemotePranswer,
        RTCSdpType::Rollback => SignalingState::Stable,
    })
}

fn mline_index_for_sdp_mid(sdp: &str, target_mid: &str) -> Option<u32> {
    let target_mid = target_mid.trim();
    if target_mid.is_empty() {
        return None;
    }

    let mut next_mline_index = 0;
    let mut current_mline_index = None;
    for raw_line in sdp.lines() {
        let line = raw_line.trim();
        if line.starts_with("m=") {
            current_mline_index = Some(next_mline_index);
            next_mline_index += 1;
            continue;
        }

        let Some(mline_index) = current_mline_index else {
            continue;
        };
        let Some(mid) = line.strip_prefix("a=mid:") else {
            continue;
        };
        if mid.trim() == target_mid {
            return Some(mline_index);
        }
    }

    None
}

fn sdp_mid_for_mline_index(sdp: &str, target_mline_index: u32) -> Option<String> {
    let mut next_mline_index = 0;
    let mut current_mline_index = None;
    for raw_line in sdp.lines() {
        let line = raw_line.trim();
        if line.starts_with("m=") {
            current_mline_index = Some(next_mline_index);
            next_mline_index += 1;
            continue;
        }

        if current_mline_index != Some(target_mline_index) {
            continue;
        }
        let Some(mid) = line.strip_prefix("a=mid:") else {
            continue;
        };
        let mid = mid.trim();
        if !mid.is_empty() {
            return Some(mid.to_owned());
        }
    }

    None
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SdpMediaDirection {
    Sendrecv,
    Sendonly,
    Recvonly,
    Inactive,
}

impl SdpMediaDirection {
    fn can_send(self) -> bool {
        matches!(self, Self::Sendrecv | Self::Sendonly)
    }

    fn can_receive(self) -> bool {
        matches!(self, Self::Sendrecv | Self::Recvonly)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SdpMediaSection {
    mid: Option<String>,
    direction: SdpMediaDirection,
}

fn sdp_media_sections(sdp: &str) -> Vec<SdpMediaSection> {
    let mut sections = Vec::new();
    let mut current = None;

    for raw_line in sdp.lines() {
        let line = raw_line.trim();
        if line.starts_with("m=") {
            if let Some(section) = current.take() {
                sections.push(section);
            }
            current = Some(SdpMediaSection {
                mid: None,
                direction: SdpMediaDirection::Sendrecv,
            });
            continue;
        }

        let Some(section) = current.as_mut() else {
            continue;
        };
        if let Some(mid) = line.strip_prefix("a=mid:") {
            let mid = mid.trim();
            if !mid.is_empty() {
                section.mid = Some(mid.to_owned());
            }
        } else {
            section.direction = match line {
                "a=sendrecv" => SdpMediaDirection::Sendrecv,
                "a=sendonly" => SdpMediaDirection::Sendonly,
                "a=recvonly" => SdpMediaDirection::Recvonly,
                "a=inactive" => SdpMediaDirection::Inactive,
                _ => section.direction,
            };
        }
    }

    if let Some(section) = current {
        sections.push(section);
    }
    sections
}

fn negotiated_direction(
    local: SdpMediaDirection,
    remote: SdpMediaDirection,
) -> RTCRtpTransceiverDirection {
    let sends = local.can_send() && remote.can_receive();
    let receives = local.can_receive() && remote.can_send();
    match (sends, receives) {
        (true, true) => RTCRtpTransceiverDirection::Sendrecv,
        (true, false) => RTCRtpTransceiverDirection::Sendonly,
        (false, true) => RTCRtpTransceiverDirection::Recvonly,
        (false, false) => RTCRtpTransceiverDirection::Inactive,
    }
}

fn peer_connection_state(ice_connection_state: RTCIceConnectionState) -> RTCPeerConnectionState {
    match ice_connection_state {
        RTCIceConnectionState::New => RTCPeerConnectionState::New,
        RTCIceConnectionState::Checking => RTCPeerConnectionState::Connecting,
        RTCIceConnectionState::Connected | RTCIceConnectionState::Completed => {
            RTCPeerConnectionState::Connected
        },
        RTCIceConnectionState::Disconnected => RTCPeerConnectionState::Disconnected,
        RTCIceConnectionState::Failed => RTCPeerConnectionState::Failed,
        RTCIceConnectionState::Closed => RTCPeerConnectionState::Closed,
    }
}

impl WebRtcSignaller for RTCSignaller {
    fn on_ice_candidate(&self, _: &WebRtcController, candidate: IceCandidate) {
        let this = self.trusted.clone();
        self.task_source.queue(task!(on_ice_candidate: move |cx| {
            let this = this.root();
            this.on_ice_candidate(cx, candidate);
        }));
    }

    fn on_negotiation_needed(&self, _: &WebRtcController) {
        let this = self.trusted.clone();
        self.task_source
            .queue(task!(on_negotiation_needed: move |cx| {
                let this = this.root();
                this.on_negotiation_needed(cx);
            }));
    }

    fn update_gathering_state(&self, state: GatheringState) {
        let this = self.trusted.clone();
        self.task_source
            .queue(task!(update_gathering_state: move |cx| {
                let this = this.root();
                this.update_gathering_state(cx, state);
            }));
    }

    fn update_ice_connection_state(&self, state: IceConnectionState) {
        let this = self.trusted.clone();
        self.task_source
            .queue(task!(update_ice_connection_state: move |cx| {
                let this = this.root();
                this.update_ice_connection_state(cx, state);
            }));
    }

    fn update_signaling_state(&self, state: SignalingState) {
        let this = self.trusted.clone();
        self.task_source
            .queue(task!(update_signaling_state: move |cx| {
                let this = this.root();
                this.update_signaling_state(cx, state);
            }));
    }

    fn on_add_stream(&self, id: &MediaStreamId, ty: MediaStreamType) {
        let this = self.trusted.clone();
        let id = *id;
        self.task_source.queue(task!(on_add_stream: move |cx| {
            let this = this.root();
            this.on_add_stream(cx, id, ty, );
        }));
    }

    fn on_data_channel_event(
        &self,
        channel: DataChannelId,
        event: DataChannelEvent,
        _: &WebRtcController,
    ) {
        // XXX(ferjm) get label and options from channel properties.
        let this = self.trusted.clone();
        self.task_source
            .queue(task!(on_data_channel_event: move |cx| {
                let this = this.root();
                let global = this.global();
                let mut realm = enter_auto_realm(cx, &*global);
                this.on_data_channel_event(&mut realm.current_realm(), channel, event);
            }));
    }

    fn close(&self) {
        // do nothing
    }
}

impl RTCPeerConnection {
    fn update_transceivers_from_sdp(&self, sdp: &str) {
        let sections = sdp_media_sections(sdp);
        let transceivers = self.transceivers.borrow();
        for (index, section) in sections.iter().enumerate() {
            let Some(transceiver) = transceivers.get(index) else {
                continue;
            };
            transceiver.set_mid(section.mid.as_deref());
        }
    }

    fn refresh_transceiver_current_directions(&self) {
        let local = self
            .current_local_description
            .get()
            .map(|description| sdp_media_sections(&description.Sdp().to_string()));
        let remote = self
            .current_remote_description
            .get()
            .map(|description| sdp_media_sections(&description.Sdp().to_string()));

        for (index, transceiver) in self.transceivers.borrow().iter().enumerate() {
            let direction = local
                .as_ref()
                .and_then(|sections| sections.get(index))
                .zip(remote.as_ref().and_then(|sections| sections.get(index)))
                .map(|(local, remote)| negotiated_direction(local.direction, remote.direction));
            transceiver.set_current_direction(direction);
        }
    }

    pub(crate) fn new_inherited() -> RTCPeerConnection {
        RTCPeerConnection {
            eventtarget: EventTarget::new_inherited(),
            controller: DomRefCell::new(None),
            closed: Cell::new(false),
            offer_answer_generation: Cell::new(0),
            offer_promises: DomRefCell::new(vec![]),
            answer_promises: DomRefCell::new(vec![]),
            local_description: Default::default(),
            current_local_description: Default::default(),
            pending_local_description: Default::default(),
            remote_description: Default::default(),
            current_remote_description: Default::default(),
            pending_remote_description: Default::default(),
            gathering_state: Cell::new(RTCIceGatheringState::New),
            ice_connection_state: Cell::new(RTCIceConnectionState::New),
            signaling_state: Cell::new(RTCSignalingState::Stable),
            data_channels: DomRefCell::new(FxHashMap::default()),
            transceivers: DomRefCell::new(Vec::new()),
        }
    }

    fn new(
        cx: &mut JSContext,
        window: &Window,
        proto: Option<HandleObject>,
        config: &RTCConfiguration,
    ) -> DomRoot<RTCPeerConnection> {
        let this = reflect_weak_referenceable_dom_object_with_proto(
            cx,
            Rc::new(RTCPeerConnection::new_inherited()),
            window,
            proto,
        );
        let signaller = this.make_signaller();
        *this.controller.borrow_mut() = Some(ServoMedia::get().create_webrtc(signaller));
        if let Some(ref servers) = config.iceServers
            && let Some(server) = servers.first()
        {
            let server = match server.urls {
                StringOrStringSequence::String(ref s) => Some(s.clone()),
                StringOrStringSequence::StringSequence(ref s) => s.first().cloned(),
            };
            if let Some(server) = server {
                let policy = match config.bundlePolicy {
                    RTCBundlePolicy::Balanced => BundlePolicy::Balanced,
                    RTCBundlePolicy::Max_compat => BundlePolicy::MaxCompat,
                    RTCBundlePolicy::Max_bundle => BundlePolicy::MaxBundle,
                };
                this.controller
                    .borrow()
                    .as_ref()
                    .unwrap()
                    .configure(String::from(server), policy);
            }
        }
        this
    }

    pub(crate) fn get_webrtc_controller(&self) -> &DomRefCell<Option<WebRtcController>> {
        &self.controller
    }

    fn make_signaller(&self) -> Box<dyn WebRtcSignaller> {
        let trusted = Trusted::new(self);
        Box::new(RTCSignaller {
            trusted,
            task_source: self.global().task_manager().networking_task_source().into(),
        })
    }

    fn on_ice_candidate(&self, cx: &mut JSContext, candidate: IceCandidate) {
        if self.closed.get() {
            return;
        }
        let sdp_mid = self.local_description.get().and_then(|description| {
            let sdp = description.Sdp();
            sdp_mid_for_mline_index(&sdp.to_string(), candidate.sdp_mline_index).map(Into::into)
        });
        let candidate = RTCIceCandidate::new(
            cx,
            self.global().as_window(),
            candidate.candidate.into(),
            sdp_mid,
            Some(candidate.sdp_mline_index as u16),
            None,
        );
        let event = RTCPeerConnectionIceEvent::new(
            cx,
            self.global().as_window(),
            atom!("icecandidate"),
            Some(&candidate),
            None,
            true,
        );
        event.upcast::<Event>().fire(cx, self.upcast());
    }

    fn on_negotiation_needed(&self, cx: &mut JSContext) {
        if self.closed.get() {
            return;
        }
        let event = Event::new(
            cx,
            &self.global(),
            atom!("negotiationneeded"),
            EventBubbles::DoesNotBubble,
            EventCancelable::NotCancelable,
        );
        event.upcast::<Event>().fire(cx, self.upcast());
    }

    fn on_add_stream(&self, cx: &mut JSContext, id: MediaStreamId, ty: MediaStreamType) {
        if self.closed.get() {
            return;
        }
        let track = MediaStreamTrack::new(cx, &self.global(), id, ty);
        let stream = MediaStream::new_with_track(cx, &self.global(), &track);
        let transceiver = RTCRtpTransceiver::new_for_remote(cx, &self.global(), &track);
        let receiver = transceiver.receiver();
        self.transceivers
            .borrow_mut()
            .push(Dom::from_ref(&*transceiver));
        let event = RTCTrackEvent::new(
            cx,
            self.global().as_window(),
            atom!("track"),
            false,
            false,
            &track,
            &receiver,
            &[stream],
            &transceiver,
        );
        event.upcast::<Event>().fire(cx, self.upcast());
    }

    fn on_data_channel_event(
        &self,
        cx: &mut CurrentRealm,
        channel_id: DataChannelId,
        event: DataChannelEvent,
    ) {
        if self.closed.get() {
            return;
        }

        match event {
            DataChannelEvent::NewChannel => {
                let Ok(channel) = RTCDataChannel::new(
                    cx,
                    &self.global(),
                    self,
                    USVString::from("".to_owned()),
                    &RTCDataChannelInit::empty(),
                    Some(channel_id),
                ) else {
                    warn!("Failed to create an incoming WebRTC data channel");
                    return;
                };

                let event = RTCDataChannelEvent::new(
                    cx,
                    self.global().as_window(),
                    atom!("datachannel"),
                    false,
                    false,
                    &channel,
                );
                event.upcast::<Event>().fire(cx, self.upcast());
            },
            _ => {
                // Clone the channel out and release the map borrow before
                // dispatching: handlers such as `on_close` unregister the
                // channel, which needs a mutable borrow of the same map.
                let channel: DomRoot<RTCDataChannel> = {
                    let channels = self.data_channels.borrow();
                    let Some(channel) = channels.get(&channel_id) else {
                        warn!(
                            "Got an event for an unregistered data channel {:?}",
                            channel_id
                        );
                        return;
                    };
                    DomRoot::from_ref(&**channel)
                };

                match event {
                    DataChannelEvent::Open => channel.on_open(cx),
                    DataChannelEvent::Close => channel.on_close(cx),
                    DataChannelEvent::Error(error) => channel.on_error(cx, error),
                    DataChannelEvent::OnMessage(message) => channel.on_message(cx, message),
                    DataChannelEvent::StateChange(state) => channel.on_state_change(cx, state),
                    DataChannelEvent::NewChannel => unreachable!(),
                }
            },
        };
    }

    pub(crate) fn register_data_channel(&self, id: DataChannelId, channel: &RTCDataChannel) {
        if self
            .data_channels
            .borrow_mut()
            .insert(id, Dom::from_ref(channel))
            .is_some()
        {
            warn!("Data channel already registered {:?}", id);
        }
    }

    pub(crate) fn unregister_data_channel(&self, id: &DataChannelId) {
        self.data_channels.borrow_mut().remove(id);
    }

    /// <https://www.w3.org/TR/webrtc/#update-ice-gathering-state>
    fn update_gathering_state(&self, cx: &mut JSContext, state: GatheringState) {
        // step 1
        if self.closed.get() {
            return;
        }

        // step 2 (state derivation already done by gstreamer)
        let state: RTCIceGatheringState = state.convert();

        // step 3
        if state == self.gathering_state.get() {
            return;
        }

        // step 4
        self.gathering_state.set(state);

        // step 5
        let event = Event::new(
            cx,
            &self.global(),
            atom!("icegatheringstatechange"),
            EventBubbles::DoesNotBubble,
            EventCancelable::NotCancelable,
        );
        event.upcast::<Event>().fire(cx, self.upcast());

        // step 6
        if state == RTCIceGatheringState::Complete {
            let event = RTCPeerConnectionIceEvent::new(
                cx,
                self.global().as_window(),
                atom!("icecandidate"),
                None,
                None,
                true,
            );
            event.upcast::<Event>().fire(cx, self.upcast());
        }
    }

    /// <https://www.w3.org/TR/webrtc/#update-ice-connection-state>
    fn update_ice_connection_state(&self, cx: &mut JSContext, state: IceConnectionState) {
        // step 1
        if self.closed.get() {
            return;
        }

        // step 2 (state derivation already done by gstreamer)
        let state: RTCIceConnectionState = state.convert();

        // step 3
        if state == self.ice_connection_state.get() {
            return;
        }

        // step 4
        self.ice_connection_state.set(state);

        // step 5
        let event = Event::new(
            cx,
            &self.global(),
            atom!("iceconnectionstatechange"),
            EventBubbles::DoesNotBubble,
            EventCancelable::NotCancelable,
        );
        event.upcast::<Event>().fire(cx, self.upcast());
    }

    fn update_signaling_state(&self, cx: &mut JSContext, state: SignalingState) {
        if self.closed.get() {
            return;
        }

        let state: RTCSignalingState = state.convert();

        if state == self.signaling_state.get() {
            return;
        }

        self.signaling_state.set(state);

        let event = Event::new(
            cx,
            &self.global(),
            atom!("signalingstatechange"),
            EventBubbles::DoesNotBubble,
            EventCancelable::NotCancelable,
        );
        event.upcast::<Event>().fire(cx, self.upcast());
    }

    fn create_offer(&self) {
        let generation = self.offer_answer_generation.get();
        let task_source = self
            .global()
            .task_manager()
            .networking_task_source()
            .to_sendable();
        let this = Trusted::new(self);
        self.controller
            .borrow_mut()
            .as_ref()
            .unwrap()
            .create_offer(Box::new(move |desc: SessionDescription| {
                task_source.queue(task!(offer_created: move |cx| {
                    let this = this.root();
                    if this.offer_answer_generation.get() != generation {
                        // the state has changed since we last created the offer,
                        // create a fresh one
                        this.create_offer();
                    } else {
                        let init: RTCSessionDescriptionInit = desc.convert();
                        for promise in this.offer_promises.borrow_mut().drain(..) {
                            promise.resolve_native(cx, &init);
                        }
                    }
                }));
            }));
    }

    fn create_answer(&self) {
        let generation = self.offer_answer_generation.get();
        let task_source = self
            .global()
            .task_manager()
            .networking_task_source()
            .to_sendable();
        let this = Trusted::new(self);
        self.controller
            .borrow_mut()
            .as_ref()
            .unwrap()
            .create_answer(Box::new(move |desc: SessionDescription| {
                task_source.queue(task!(answer_created: move |cx| {
                    let this = this.root();
                    if this.offer_answer_generation.get() != generation {
                        // the state has changed since we last created the offer,
                        // create a fresh one
                        this.create_answer();
                    } else {
                        let init: RTCSessionDescriptionInit = desc.convert();
                        for promise in this.answer_promises.borrow_mut().drain(..) {
                            promise.resolve_native(cx, &init);
                        }
                    }
                }));
            }));
    }
}

impl RTCPeerConnectionMethods<crate::DomTypeHolder> for RTCPeerConnection {
    /// <https://w3c.github.io/webrtc-pc/#dom-peerconnection>
    fn Constructor(
        cx: &mut JSContext,
        window: &Window,
        proto: Option<HandleObject>,
        config: &RTCConfiguration,
    ) -> Fallible<DomRoot<RTCPeerConnection>> {
        Ok(RTCPeerConnection::new(cx, window, proto, config))
    }

    // https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-icecandidate
    event_handler!(icecandidate, GetOnicecandidate, SetOnicecandidate);

    // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-ontrack
    event_handler!(track, GetOntrack, SetOntrack);

    // https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-iceconnectionstatechange
    event_handler!(
        iceconnectionstatechange,
        GetOniceconnectionstatechange,
        SetOniceconnectionstatechange
    );

    // https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-icegatheringstatechange
    event_handler!(
        icegatheringstatechange,
        GetOnicegatheringstatechange,
        SetOnicegatheringstatechange
    );

    // https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-onnegotiationneeded
    event_handler!(
        negotiationneeded,
        GetOnnegotiationneeded,
        SetOnnegotiationneeded
    );

    // https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-signalingstatechange
    event_handler!(
        signalingstatechange,
        GetOnsignalingstatechange,
        SetOnsignalingstatechange
    );

    // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-ondatachannel
    event_handler!(datachannel, GetOndatachannel, SetOndatachannel);

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-addicecandidate>
    fn AddIceCandidate(
        &self,
        current_realm: &mut CurrentRealm,
        candidate: &RTCIceCandidateInit,
    ) -> Rc<Promise> {
        let p = Promise::new_in_realm(current_realm);
        if self.closed.get() {
            p.reject_error(current_realm, Error::InvalidState(None));
            return p;
        }
        if candidate.sdpMid.is_none() && candidate.sdpMLineIndex.is_none() {
            p.reject_error(
                current_realm,
                Error::Type(c"one of sdpMid and sdpMLineIndex must be set".to_owned()),
            );
            return p;
        }

        let Some(remote_description) = self.remote_description.get() else {
            p.reject_error(current_realm, Error::InvalidState(None));
            return p;
        };

        let remote_sdp = remote_description.Sdp().to_string();
        let sdp_mid_mline_index = candidate
            .sdpMid
            .as_ref()
            .and_then(|mid| mline_index_for_sdp_mid(&remote_sdp, &mid.to_string()));
        if let (Some(sdp_mline_index), Some(sdp_mid_mline_index)) =
            (candidate.sdpMLineIndex, sdp_mid_mline_index)
        {
            if sdp_mline_index as u32 != sdp_mid_mline_index {
                p.reject_error(
                    current_realm,
                    Error::Type(
                        c"sdpMid and sdpMLineIndex identify different media sections".to_owned(),
                    ),
                );
                return p;
            }
        }
        let Some(sdp_mline_index) = candidate
            .sdpMLineIndex
            .map(|index| index as u32)
            .or(sdp_mid_mline_index)
        else {
            p.reject_error(
                current_realm,
                Error::Type(c"sdpMid does not identify a media section in remote SDP".to_owned()),
            );
            return p;
        };

        // XXXManishearth this should be enqueued
        // https://w3c.github.io/webrtc-pc/#enqueue-an-operation

        let Some(controller) = self.controller.borrow().as_ref().cloned() else {
            p.reject_error(current_realm, Error::InvalidState(None));
            return p;
        };
        if let Err(error) = controller.add_ice_candidate(IceCandidate {
            sdp_mline_index,
            candidate: candidate.candidate.to_string(),
        }) {
            let message = match error {
                WebRtcError::Backend(message) => message,
            };
            p.reject_error(current_realm, Error::Operation(Some(message)));
            return p;
        }

        p.resolve_native(current_realm, &());
        p
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-createoffer>
    fn CreateOffer(
        &self,
        current_realm: &mut CurrentRealm,
        _options: &RTCOfferOptions,
    ) -> Rc<Promise> {
        let p = Promise::new_in_realm(current_realm);
        if self.closed.get() {
            p.reject_error(current_realm, Error::InvalidState(None));
            return p;
        }
        self.offer_promises.borrow_mut().push(p.clone());
        self.create_offer();
        p
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-createoffer>
    fn CreateAnswer(
        &self,
        current_realm: &mut CurrentRealm,
        _options: &RTCAnswerOptions,
    ) -> Rc<Promise> {
        let p = Promise::new_in_realm(current_realm);
        if self.closed.get() {
            p.reject_error(current_realm, Error::InvalidState(None));
            return p;
        }
        self.answer_promises.borrow_mut().push(p.clone());
        self.create_answer();
        p
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-localdescription>
    fn GetLocalDescription(&self) -> Option<DomRoot<RTCSessionDescription>> {
        self.local_description.get()
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-currentlocaldescription>
    fn GetCurrentLocalDescription(&self) -> Option<DomRoot<RTCSessionDescription>> {
        self.current_local_description.get()
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-pendinglocaldescription>
    fn GetPendingLocalDescription(&self) -> Option<DomRoot<RTCSessionDescription>> {
        self.pending_local_description.get()
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-remotedescription>
    fn GetRemoteDescription(&self) -> Option<DomRoot<RTCSessionDescription>> {
        self.remote_description.get()
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-currentremotedescription>
    fn GetCurrentRemoteDescription(&self) -> Option<DomRoot<RTCSessionDescription>> {
        self.current_remote_description.get()
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-pendingremotedescription>
    fn GetPendingRemoteDescription(&self) -> Option<DomRoot<RTCSessionDescription>> {
        self.pending_remote_description.get()
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-setlocaldescription>
    fn SetLocalDescription(
        &self,
        current_realm: &mut CurrentRealm,
        desc: &RTCSessionDescriptionInit,
    ) -> Rc<Promise> {
        let p = Promise::new_in_realm(current_realm);
        if self.closed.get() {
            p.reject_error(current_realm, Error::InvalidState(None));
            return p;
        }
        if !local_description_is_legal(self.signaling_state.get(), desc.type_) {
            p.reject_error(current_realm, Error::InvalidState(None));
            return p;
        }
        let this = Trusted::new(self);
        let description_type = desc.type_;
        let desc: SessionDescription = desc.convert();
        let trusted_promise = TrustedPromise::new(p.clone());
        let task_source = self
            .global()
            .task_manager()
            .networking_task_source()
            .to_sendable();
        let Some(controller) = self.controller.borrow().as_ref().cloned() else {
            p.reject_error(current_realm, Error::InvalidState(None));
            return p;
        };
        controller.set_local_description(
            desc.clone(),
            Box::new(move |result: WebRtcResult| {
                task_source.queue(task!(local_description_set: move |current_realm| {
                    if let Err(error) = result {
                        let message = match error {
                            WebRtcError::Backend(message) => message,
                        };
                        trusted_promise.root().reject_error(
                            current_realm,
                            Error::Operation(Some(message)),
                        );
                        return;
                    }
                    // XXXManishearth spec actually asks for an intricate
                    // dance between pending/current local/remote descriptions
                    let this = this.root();
                    let sdp = desc.sdp.clone();
                    let desc = desc.convert();
                    let desc = RTCSessionDescription::new(
                        current_realm,
                        this.global().as_window(),
                        None,
                        desc.type_,
                        desc.sdp,
                    );
                    match description_type {
                        RTCSdpType::Offer | RTCSdpType::Pranswer => {
                            this.pending_local_description.set(Some(&desc));
                            this.local_description.set(Some(&desc));
                        },
                        RTCSdpType::Answer => {
                            this.current_local_description.set(Some(&desc));
                            this.pending_local_description.set(None);
                            if let Some(pending_remote) = this.pending_remote_description.get() {
                                this.current_remote_description.set(Some(&*pending_remote));
                                this.pending_remote_description.set(None);
                                this.remote_description.set(Some(&*pending_remote));
                            }
                            this.local_description.set(Some(&desc));
                        },
                        RTCSdpType::Rollback => {
                            this.pending_local_description.set(None);
                            let current = this.current_local_description.get();
                            this.local_description.set(current.as_deref());
                        },
                    }
                    if description_type != RTCSdpType::Rollback {
                        this.update_transceivers_from_sdp(&sdp);
                    }
                    this.refresh_transceiver_current_directions();
                    if let Some(next_state) = local_description_next_state(description_type) {
                        this.update_signaling_state(current_realm, next_state);
                    }
                    trusted_promise.root().resolve_native(current_realm, &())
                }));
            }),
        );
        p
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-setremotedescription>
    fn SetRemoteDescription(
        &self,
        current_realm: &mut CurrentRealm,
        desc: &RTCSessionDescriptionInit,
    ) -> Rc<Promise> {
        let p = Promise::new_in_realm(current_realm);
        if self.closed.get() {
            p.reject_error(current_realm, Error::InvalidState(None));
            return p;
        }
        if !remote_description_is_legal(self.signaling_state.get(), desc.type_) {
            p.reject_error(current_realm, Error::InvalidState(None));
            return p;
        }
        let this = Trusted::new(self);
        let description_type = desc.type_;
        let desc: SessionDescription = desc.convert();
        let trusted_promise = TrustedPromise::new(p.clone());
        let task_source = self
            .global()
            .task_manager()
            .networking_task_source()
            .to_sendable();
        let Some(controller) = self.controller.borrow().as_ref().cloned() else {
            p.reject_error(current_realm, Error::InvalidState(None));
            return p;
        };
        controller.set_remote_description(
            desc.clone(),
            Box::new(move |result: WebRtcResult| {
                task_source.queue(task!(remote_description_set: move |current_realm| {
                    if let Err(error) = result {
                        let message = match error {
                            WebRtcError::Backend(message) => message,
                        };
                        trusted_promise.root().reject_error(
                            current_realm,
                            Error::Operation(Some(message)),
                        );
                        return;
                    }
                    // XXXManishearth spec actually asks for an intricate
                    // dance between pending/current local/remote descriptions
                    let this = this.root();
                    let sdp = desc.sdp.clone();
                    let desc = desc.convert();
                    let desc = RTCSessionDescription::new(
                        current_realm,
                        this.global().as_window(),
                        None,
                        desc.type_,
                        desc.sdp,
                    );
                    match description_type {
                        RTCSdpType::Offer | RTCSdpType::Pranswer => {
                            this.pending_remote_description.set(Some(&desc));
                            this.remote_description.set(Some(&desc));
                        },
                        RTCSdpType::Answer => {
                            this.current_remote_description.set(Some(&desc));
                            this.pending_remote_description.set(None);
                            if let Some(pending_local) = this.pending_local_description.get() {
                                this.current_local_description.set(Some(&*pending_local));
                                this.pending_local_description.set(None);
                                this.local_description.set(Some(&*pending_local));
                            }
                            this.remote_description.set(Some(&desc));
                        },
                        RTCSdpType::Rollback => {
                            this.pending_remote_description.set(None);
                            let current = this.current_remote_description.get();
                            this.remote_description.set(current.as_deref());
                        },
                    }
                    if description_type != RTCSdpType::Rollback {
                        this.update_transceivers_from_sdp(&sdp);
                    }
                    this.refresh_transceiver_current_directions();
                    if let Some(next_state) = remote_description_next_state(description_type) {
                        this.update_signaling_state(current_realm, next_state);
                    }
                    trusted_promise.root().resolve_native(current_realm, &())
                }));
            }),
        );
        p
    }

    /// <https://w3c.github.io/webrtc-pc/#legacy-interface-extensions>
    fn AddStream(&self, stream: &MediaStream) {
        if self.closed.get() {
            return;
        }
        let Some(controller) = self.controller.borrow().as_ref().cloned() else {
            return;
        };
        for track in &*stream.get_tracks() {
            let _ = controller.add_stream(&track.id());
        }
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-addtrack>
    fn AddTrack(
        &self,
        track: &MediaStreamTrack,
        _streams: &[&MediaStream],
    ) -> Fallible<DomRoot<RTCRtpSender>> {
        #[expect(unsafe_code)]
        let mut cx = unsafe { temp_cx() };
        if self.closed.get() {
            return Err(Error::InvalidState(None));
        }
        if self.transceivers.borrow().iter().any(|transceiver| {
            transceiver
                .sender()
                .track()
                .is_some_and(|existing| existing.id() == track.id())
        }) {
            return Err(Error::InvalidAccess(None));
        }

        let transceiver = RTCRtpTransceiver::new(
            &mut cx,
            &self.global(),
            crate::dom::bindings::codegen::Bindings::RTCRtpTransceiverBinding::RTCRtpTransceiverDirection::Sendrecv,
            Some(track),
            track,
            self.controller.borrow().as_ref().cloned(),
        );
        self.transceivers
            .borrow_mut()
            .push(Dom::from_ref(&*transceiver));
        if let Some(controller) = self.controller.borrow().as_ref().cloned() {
            let _ = controller.add_stream(&track.id());
        }
        Ok(transceiver.sender())
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-getsenders>
    fn GetSenders(&self) -> Vec<DomRoot<RTCRtpSender>> {
        self.transceivers
            .borrow()
            .iter()
            .map(|transceiver| transceiver.sender())
            .collect()
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-getreceivers>
    fn GetReceivers(&self) -> Vec<DomRoot<crate::dom::rtcrtpreceiver::RTCRtpReceiver>> {
        self.transceivers
            .borrow()
            .iter()
            .map(|transceiver| transceiver.receiver())
            .collect()
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-gettransceivers>
    fn GetTransceivers(&self) -> Vec<DomRoot<RTCRtpTransceiver>> {
        self.transceivers
            .borrow()
            .iter()
            .map(|transceiver| DomRoot::from_ref(&**transceiver))
            .collect()
    }

    /// <https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-icegatheringstate>
    fn IceGatheringState(&self) -> RTCIceGatheringState {
        self.gathering_state.get()
    }

    /// <https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-iceconnectionstate>
    fn IceConnectionState(&self) -> RTCIceConnectionState {
        self.ice_connection_state.get()
    }

    /// <https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-signalingstate>
    fn SignalingState(&self) -> RTCSignalingState {
        self.signaling_state.get()
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-connectionstate>
    fn ConnectionState(&self) -> RTCPeerConnectionState {
        peer_connection_state(self.ice_connection_state.get())
    }

    /// <https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close>
    fn Close(&self, cx: &mut JSContext) {
        // Step 1
        if self.closed.get() {
            return;
        }
        // Step 2
        self.closed.set(true);

        // Step 4
        self.signaling_state.set(RTCSignalingState::Closed);

        // Step 5 handled by backend
        if let Some(controller) = self.controller.borrow_mut().as_ref() {
            controller.quit();
        }

        // Step 6
        // Collect first and release the map borrow: state changes unregister
        // channels, which needs a mutable borrow of the same map.
        let channels: Vec<DomRoot<RTCDataChannel>> = self
            .data_channels
            .borrow()
            .values()
            .map(|channel| DomRoot::from_ref(&**channel))
            .collect();
        for channel in channels {
            channel.on_state_change(cx, DataChannelState::Closed);
        }

        // Step 7-10
        // (no current support for transports, etc)

        // Step 11
        self.ice_connection_state.set(RTCIceConnectionState::Closed);

        // `connectionState` is derived from the ICE connection state, which
        // was set to `closed` above.
    }

    /// <https://www.w3.org/TR/webrtc/#dom-peerconnection-createdatachannel>
    fn CreateDataChannel(
        &self,
        cx: &mut JSContext,
        label: USVString,
        init: &RTCDataChannelInit,
    ) -> Fallible<DomRoot<RTCDataChannel>> {
        RTCDataChannel::new(cx, &self.global(), self, label, init, None)
    }

    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-addtransceiver>
    fn AddTransceiver(
        &self,
        cx: &mut JSContext,
        track_or_kind: MediaStreamTrackOrString,
        init: &RTCRtpTransceiverInit,
    ) -> DomRoot<RTCRtpTransceiver> {
        let track = match &track_or_kind {
            MediaStreamTrackOrString::MediaStreamTrack(track) => Some(&**track),
            MediaStreamTrackOrString::String(_) => None,
        };
        let receiver_kind = match &track_or_kind {
            MediaStreamTrackOrString::MediaStreamTrack(track) => track.ty(),
            MediaStreamTrackOrString::String(kind) if kind == "video" => MediaStreamType::Video,
            MediaStreamTrackOrString::String(_) => MediaStreamType::Audio,
        };
        let receiver_track =
            MediaStreamTrack::new(cx, &self.global(), MediaStreamId::new(), receiver_kind);
        let transceiver = RTCRtpTransceiver::new(
            cx,
            &self.global(),
            init.direction,
            track,
            &receiver_track,
            self.controller.borrow().as_ref().cloned(),
        );
        self.transceivers
            .borrow_mut()
            .push(Dom::from_ref(&*transceiver));
        if let Some(track) = track
            && let Some(controller) = self.controller.borrow().as_ref().cloned()
        {
            let _ = controller.add_stream(&track.id());
        }
        transceiver
    }
}

impl Convert<RTCSessionDescriptionInit> for SessionDescription {
    fn convert(self) -> RTCSessionDescriptionInit {
        let type_ = match self.type_ {
            SdpType::Answer => RTCSdpType::Answer,
            SdpType::Offer => RTCSdpType::Offer,
            SdpType::Pranswer => RTCSdpType::Pranswer,
            SdpType::Rollback => RTCSdpType::Rollback,
        };
        RTCSessionDescriptionInit {
            type_,
            sdp: self.sdp.into(),
        }
    }
}

impl Convert<SessionDescription> for &RTCSessionDescriptionInit {
    fn convert(self) -> SessionDescription {
        let type_ = match self.type_ {
            RTCSdpType::Answer => SdpType::Answer,
            RTCSdpType::Offer => SdpType::Offer,
            RTCSdpType::Pranswer => SdpType::Pranswer,
            RTCSdpType::Rollback => SdpType::Rollback,
        };
        SessionDescription {
            type_,
            sdp: self.sdp.to_string(),
        }
    }
}

impl Convert<RTCIceGatheringState> for GatheringState {
    fn convert(self) -> RTCIceGatheringState {
        match self {
            GatheringState::New => RTCIceGatheringState::New,
            GatheringState::Gathering => RTCIceGatheringState::Gathering,
            GatheringState::Complete => RTCIceGatheringState::Complete,
        }
    }
}

impl Convert<RTCIceConnectionState> for IceConnectionState {
    fn convert(self) -> RTCIceConnectionState {
        match self {
            IceConnectionState::New => RTCIceConnectionState::New,
            IceConnectionState::Checking => RTCIceConnectionState::Checking,
            IceConnectionState::Connected => RTCIceConnectionState::Connected,
            IceConnectionState::Completed => RTCIceConnectionState::Completed,
            IceConnectionState::Disconnected => RTCIceConnectionState::Disconnected,
            IceConnectionState::Failed => RTCIceConnectionState::Failed,
            IceConnectionState::Closed => RTCIceConnectionState::Closed,
        }
    }
}

impl Convert<RTCSignalingState> for SignalingState {
    fn convert(self) -> RTCSignalingState {
        match self {
            SignalingState::Stable => RTCSignalingState::Stable,
            SignalingState::HaveLocalOffer => RTCSignalingState::Have_local_offer,
            SignalingState::HaveRemoteOffer => RTCSignalingState::Have_remote_offer,
            SignalingState::HaveLocalPranswer => RTCSignalingState::Have_local_pranswer,
            SignalingState::HaveRemotePranswer => RTCSignalingState::Have_remote_pranswer,
            SignalingState::Closed => RTCSignalingState::Closed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        RTCIceConnectionState, RTCPeerConnectionState, RTCRtpTransceiverDirection, RTCSdpType,
        RTCSignalingState, SdpMediaDirection, SignalingState, local_description_is_legal,
        local_description_next_state, mline_index_for_sdp_mid, negotiated_direction,
        peer_connection_state, remote_description_is_legal, remote_description_next_state,
        sdp_media_sections, sdp_mid_for_mline_index,
    };

    #[test]
    fn peer_connection_state_is_derived_from_ice_state() {
        assert_eq!(
            peer_connection_state(RTCIceConnectionState::New),
            RTCPeerConnectionState::New
        );
        assert_eq!(
            peer_connection_state(RTCIceConnectionState::Checking),
            RTCPeerConnectionState::Connecting
        );
        assert_eq!(
            peer_connection_state(RTCIceConnectionState::Connected),
            RTCPeerConnectionState::Connected
        );
        assert_eq!(
            peer_connection_state(RTCIceConnectionState::Completed),
            RTCPeerConnectionState::Connected
        );
        assert_eq!(
            peer_connection_state(RTCIceConnectionState::Disconnected),
            RTCPeerConnectionState::Disconnected
        );
        assert_eq!(
            peer_connection_state(RTCIceConnectionState::Failed),
            RTCPeerConnectionState::Failed
        );
        assert_eq!(
            peer_connection_state(RTCIceConnectionState::Closed),
            RTCPeerConnectionState::Closed
        );
    }

    #[test]
    fn local_description_state_matrix_rejects_invalid_transitions() {
        assert!(local_description_is_legal(
            RTCSignalingState::Stable,
            RTCSdpType::Offer
        ));
        assert!(!local_description_is_legal(
            RTCSignalingState::Have_local_offer,
            RTCSdpType::Offer
        ));
        assert!(local_description_is_legal(
            RTCSignalingState::Have_remote_offer,
            RTCSdpType::Answer
        ));
        assert!(!local_description_is_legal(
            RTCSignalingState::Stable,
            RTCSdpType::Answer
        ));
    }

    #[test]
    fn remote_description_state_matrix_rejects_invalid_transitions() {
        assert!(remote_description_is_legal(
            RTCSignalingState::Stable,
            RTCSdpType::Offer
        ));
        assert!(remote_description_is_legal(
            RTCSignalingState::Have_local_offer,
            RTCSdpType::Answer
        ));
        assert!(!remote_description_is_legal(
            RTCSignalingState::Stable,
            RTCSdpType::Answer
        ));
    }

    #[test]
    fn description_state_updates_follow_sdp_type() {
        assert_eq!(
            local_description_next_state(RTCSdpType::Offer),
            Some(SignalingState::HaveLocalOffer)
        );
        assert_eq!(
            remote_description_next_state(RTCSdpType::Offer),
            Some(SignalingState::HaveRemoteOffer)
        );
        assert_eq!(
            local_description_next_state(RTCSdpType::Answer),
            Some(SignalingState::Stable)
        );
        assert_eq!(
            remote_description_next_state(RTCSdpType::Rollback),
            Some(SignalingState::Stable)
        );
    }

    #[test]
    fn mline_index_for_sdp_mid_finds_media_section() {
        let sdp = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:audio\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:video\r\n";

        assert_eq!(mline_index_for_sdp_mid(sdp, "audio"), Some(0));
        assert_eq!(mline_index_for_sdp_mid(sdp, "video"), Some(1));
    }

    #[test]
    fn mline_index_for_sdp_mid_rejects_unknown_or_unscoped_mid() {
        let sdp = "v=0\r\na=mid:session\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n";

        assert_eq!(mline_index_for_sdp_mid(sdp, "session"), None);
        assert_eq!(mline_index_for_sdp_mid(sdp, "missing"), None);
    }

    #[test]
    fn sdp_mid_for_mline_index_finds_media_section() {
        let sdp = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:audio\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:video\r\n";

        assert_eq!(sdp_mid_for_mline_index(sdp, 0), Some("audio".to_owned()));
        assert_eq!(sdp_mid_for_mline_index(sdp, 1), Some("video".to_owned()));
    }

    #[test]
    fn sdp_mid_for_mline_index_rejects_missing_or_unassigned_sections() {
        let sdp = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:video\r\n";

        assert_eq!(sdp_mid_for_mline_index(sdp, 0), None);
        assert_eq!(sdp_mid_for_mline_index(sdp, 2), None);
    }

    #[test]
    fn sdp_media_sections_capture_mid_and_direction() {
        let sdp = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:audio\r\na=sendonly\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:video\r\n";

        assert_eq!(
            sdp_media_sections(sdp),
            vec![
                super::SdpMediaSection {
                    mid: Some("audio".to_owned()),
                    direction: SdpMediaDirection::Sendonly,
                },
                super::SdpMediaSection {
                    mid: Some("video".to_owned()),
                    direction: SdpMediaDirection::Sendrecv,
                },
            ]
        );
    }

    #[test]
    fn negotiated_direction_intersects_local_and_remote_capabilities() {
        assert_eq!(
            negotiated_direction(SdpMediaDirection::Sendrecv, SdpMediaDirection::Sendonly),
            RTCRtpTransceiverDirection::Recvonly
        );
        assert_eq!(
            negotiated_direction(SdpMediaDirection::Sendonly, SdpMediaDirection::Recvonly),
            RTCRtpTransceiverDirection::Sendonly
        );
        assert_eq!(
            negotiated_direction(SdpMediaDirection::Inactive, SdpMediaDirection::Sendrecv),
            RTCRtpTransceiverDirection::Inactive
        );
    }
}
