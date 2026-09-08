/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;

use log::error;
use servo_media_streams::MediaStreamType;

use crate::datachannel::{DataChannelEvent, DataChannelId, DataChannelInit, DataChannelMessage};
use crate::{
    BundlePolicy, DescriptionType, IceCandidate, MediaStreamId, RtpSenderParameters, SdpType,
    SessionDescription, WebRtcBackend, WebRtcControllerBackend, WebRtcDescriptionCallback,
    WebRtcError, WebRtcResult, WebRtcSignaller,
};

#[derive(Clone)]
/// Entry point for all client webrtc interactions.
pub struct WebRtcController {
    sender: Sender<RtcThreadEvent>,
}

impl WebRtcController {
    pub fn new<T: WebRtcBackend>(signaller: Box<dyn WebRtcSignaller>) -> Self {
        let (sender, receiver) = channel();

        let t = WebRtcController { sender };

        let mut controller = T::construct_webrtc_controller(signaller, t.clone());

        thread::spawn(move || {
            while let Ok(event) = receiver.recv() {
                if !handle_rtc_event(&mut controller, event) {
                    // shut down event loop
                    break;
                }
            }
        });

        t
    }
    pub fn configure(&self, stun_server: String, policy: BundlePolicy) {
        let _ = self
            .sender
            .send(RtcThreadEvent::ConfigureStun(stun_server, policy));
    }
    pub fn set_remote_description(&self, desc: SessionDescription, cb: WebRtcDescriptionCallback) {
        if let Err(error) = self
            .sender
            .send(RtcThreadEvent::SetRemoteDescription(desc, cb))
        {
            if let RtcThreadEvent::SetRemoteDescription(_, cb) = error.0 {
                cb(Err(WebRtcError::Backend(
                    "WebRTC event loop unavailable".to_owned(),
                )));
            }
        }
    }
    pub fn set_local_description(&self, desc: SessionDescription, cb: WebRtcDescriptionCallback) {
        if let Err(error) = self
            .sender
            .send(RtcThreadEvent::SetLocalDescription(desc, cb))
        {
            if let RtcThreadEvent::SetLocalDescription(_, cb) = error.0 {
                cb(Err(WebRtcError::Backend(
                    "WebRTC event loop unavailable".to_owned(),
                )));
            }
        }
    }
    pub fn add_ice_candidate(&self, candidate: IceCandidate) -> WebRtcResult {
        let (sender, receiver) = channel();
        self.sender
            .send(RtcThreadEvent::AddIceCandidate(candidate, sender))
            .map_err(|_| WebRtcError::Backend("WebRTC event loop unavailable".to_owned()))?;
        receiver
            .recv()
            .map_err(|_| WebRtcError::Backend("WebRTC event loop stopped".to_owned()))?
    }
    pub fn create_offer(&self, cb: Box<dyn FnOnce(SessionDescription) + Send + 'static>) {
        let _ = self.sender.send(RtcThreadEvent::CreateOffer(cb));
    }
    pub fn create_answer(&self, cb: Box<dyn FnOnce(SessionDescription) + Send + 'static>) {
        let _ = self.sender.send(RtcThreadEvent::CreateAnswer(cb));
    }
    pub fn add_stream(&self, stream: &MediaStreamId) -> WebRtcResult {
        let (sender, receiver) = channel();
        self.sender
            .send(RtcThreadEvent::AddStream(*stream, sender))
            .map_err(|_| WebRtcError::Backend("WebRTC event loop unavailable".to_owned()))?;
        receiver
            .recv()
            .map_err(|_| WebRtcError::Backend("WebRTC event loop stopped".to_owned()))?
    }
    pub fn replace_stream(
        &self,
        old_stream: &MediaStreamId,
        new_stream: &MediaStreamId,
    ) -> WebRtcResult {
        let (sender, receiver) = channel();
        self.sender
            .send(RtcThreadEvent::ReplaceStream(
                *old_stream,
                *new_stream,
                sender,
            ))
            .map_err(|_| WebRtcError::Backend("WebRTC event loop unavailable".to_owned()))?;
        receiver
            .recv()
            .map_err(|_| WebRtcError::Backend("WebRTC event loop stopped".to_owned()))?
    }
    pub fn set_sender_parameters(
        &self,
        stream: &MediaStreamId,
        parameters: RtpSenderParameters,
    ) -> WebRtcResult {
        let (sender, receiver) = channel();
        self.sender
            .send(RtcThreadEvent::SetSenderParameters(
                *stream, parameters, sender,
            ))
            .map_err(|_| WebRtcError::Backend("WebRTC event loop unavailable".to_owned()))?;
        receiver
            .recv()
            .map_err(|_| WebRtcError::Backend("WebRTC event loop stopped".to_owned()))?
    }
    pub fn create_data_channel(&self, init: DataChannelInit) -> Option<DataChannelId> {
        let (sender, receiver) = channel();
        self.sender
            .send(RtcThreadEvent::CreateDataChannel(init, sender))
            .ok()?;
        receiver.recv().ok().flatten()
    }
    pub fn send_data_channel_message(
        &self,
        id: &DataChannelId,
        message: DataChannelMessage,
    ) -> WebRtcResult {
        let (sender, receiver) = channel();
        self.sender
            .send(RtcThreadEvent::SendDataChannelMessage(*id, message, sender))
            .map_err(|_| WebRtcError::Backend("WebRTC event loop unavailable".to_owned()))?;
        receiver
            .recv()
            .map_err(|_| WebRtcError::Backend("WebRTC event loop stopped".to_owned()))?
    }
    pub fn close_data_channel(&self, id: &DataChannelId) {
        let _ = self.sender.send(RtcThreadEvent::CloseDataChannel(*id));
    }

    /// This should not be invoked by clients
    pub fn internal_event(&self, event: InternalEvent) {
        let _ = self.sender.send(RtcThreadEvent::InternalEvent(event));
    }

    pub fn quit(&self) {
        let _ = self.sender.send(RtcThreadEvent::Quit);
    }
}

pub enum RtcThreadEvent {
    ConfigureStun(String, BundlePolicy),
    SetRemoteDescription(SessionDescription, WebRtcDescriptionCallback),
    SetLocalDescription(SessionDescription, WebRtcDescriptionCallback),
    AddIceCandidate(IceCandidate, Sender<WebRtcResult>),
    CreateOffer(Box<dyn FnOnce(SessionDescription) + Send + 'static>),
    CreateAnswer(Box<dyn FnOnce(SessionDescription) + Send + 'static>),
    AddStream(MediaStreamId, Sender<WebRtcResult>),
    ReplaceStream(MediaStreamId, MediaStreamId, Sender<WebRtcResult>),
    SetSenderParameters(MediaStreamId, RtpSenderParameters, Sender<WebRtcResult>),
    CreateDataChannel(DataChannelInit, Sender<Option<DataChannelId>>),
    CloseDataChannel(DataChannelId),
    SendDataChannelMessage(DataChannelId, DataChannelMessage, Sender<WebRtcResult>),
    InternalEvent(InternalEvent),
    Quit,
}

/// To allow everything to occur on the event loop,
/// the backend may need to send signals to itself
///
/// This is a somewhat leaky abstraction, but we don't
/// plan on having too many backends anyway
pub enum InternalEvent {
    OnNegotiationNeeded,
    OnIceCandidate(IceCandidate),
    OnAddStream(MediaStreamId, MediaStreamType),
    OnDataChannelEvent(DataChannelId, DataChannelEvent),
    DescriptionAdded(
        WebRtcDescriptionCallback,
        DescriptionType,
        SdpType,
        /* remote offer generation */ u32,
        WebRtcResult,
    ),
    UpdateSignalingState,
    UpdateGatheringState,
    UpdateIceConnectionState,
}

pub fn handle_rtc_event(
    controller: &mut dyn WebRtcControllerBackend,
    event: RtcThreadEvent,
) -> bool {
    let result = match event {
        RtcThreadEvent::ConfigureStun(server, policy) => controller.configure(&server, policy),
        RtcThreadEvent::SetRemoteDescription(desc, cb) => {
            dispatch_description(controller, DescriptionType::Remote, desc, cb)
        },
        RtcThreadEvent::SetLocalDescription(desc, cb) => {
            dispatch_description(controller, DescriptionType::Local, desc, cb)
        },
        RtcThreadEvent::AddIceCandidate(candidate, sender) => {
            let result = controller.add_ice_candidate(candidate);
            let _ = sender.send(result);
            Ok(())
        },
        RtcThreadEvent::CreateOffer(cb) => controller.create_offer(cb),
        RtcThreadEvent::CreateAnswer(cb) => controller.create_answer(cb),
        RtcThreadEvent::AddStream(media, sender) => {
            let result = controller.add_stream(&media);
            let _ = sender.send(result);
            Ok(())
        },
        RtcThreadEvent::ReplaceStream(old_media, new_media, sender) => {
            let result = controller.replace_stream(&old_media, &new_media);
            let _ = sender.send(result);
            Ok(())
        },
        RtcThreadEvent::SetSenderParameters(media, parameters, sender) => {
            let result = controller.set_sender_parameters(&media, &parameters);
            let _ = sender.send(result);
            Ok(())
        },
        RtcThreadEvent::CreateDataChannel(init, sender) => controller
            .create_data_channel(&init)
            .map(|id| {
                let _ = sender.send(Some(id));
            })
            .inspect_err(|_| {
                let _ = sender.send(None);
            }),
        RtcThreadEvent::CloseDataChannel(id) => controller.close_data_channel(&id),
        RtcThreadEvent::SendDataChannelMessage(id, message, sender) => {
            let result = controller.send_data_channel_message(&id, &message);
            let _ = sender.send(result);
            Ok(())
        },
        RtcThreadEvent::InternalEvent(e) => controller.internal_event(e),
        RtcThreadEvent::Quit => {
            controller.quit();
            return false;
        },
    };
    if let Err(e) = result {
        error!("WebRTC backend encountered error: {:?}", e);
    }
    true
}

fn dispatch_description(
    controller: &mut dyn WebRtcControllerBackend,
    description_type: DescriptionType,
    desc: SessionDescription,
    cb: WebRtcDescriptionCallback,
) -> WebRtcResult {
    let callback = Arc::new(Mutex::new(Some(cb)));
    let callback_for_backend = callback.clone();
    let backend_callback: WebRtcDescriptionCallback = Box::new(move |result| {
        if let Some(callback) = callback_for_backend.lock().unwrap().take() {
            callback(result);
        }
    });
    let result = match description_type {
        DescriptionType::Remote => controller.set_remote_description(desc, backend_callback),
        DescriptionType::Local => controller.set_local_description(desc, backend_callback),
    };
    if let Err(error) = result {
        return match callback.lock().unwrap().take() {
            Some(callback) => {
                callback(Err(error));
                Ok(())
            },
            None => Err(error),
        };
    }
    Ok(())
}
