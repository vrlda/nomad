/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! The websocket handler has three main responsibilities:
//! 1) initiate the initial HTTP connection and process the response
//! 2) ensure any DOM requests for sending/closing are propagated to the network
//! 3) transmit any incoming messages/closing to the DOM
//!
//! In order to accomplish this, the handler uses a long-running loop that selects
//! over events from the network and events from the DOM, using async/await to avoid
//! the need for a dedicated thread per websocket.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_tungstenite::WebSocketStream;
use async_tungstenite::tokio::{ConnectStream, client_async_tls_with_connector_and_config};
use futures::stream::StreamExt;
use headers::{
    Authorization, Connection, HeaderMapExt, SecWebsocketKey, SecWebsocketVersion, Upgrade,
};
use http::HeaderMap;
use http::Uri;
use http::header::{self, HeaderName, HeaderValue};
use ipc_channel::ipc::IpcSender;
use log::{debug, trace, warn};
use net_traits::pub_domains::is_same_site;
use net_traits::request::{RequestBuilder, RequestMode};
use net_traits::{CookieSource, MessageData, WebSocketDomAction, WebSocketNetworkEvent};
use servo_base::generic_channel::CallbackSetter;
use servo_url::ServoUrl;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::select;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};
use tokio_rustls::TlsConnector;
use tungstenite::error::{Error, ProtocolError, UrlError};
use tungstenite::handshake::client::Response;
use tungstenite::protocol::CloseFrame;
use tungstenite::{ClientRequestBuilder, Message};

use crate::async_runtime::spawn_task;
use crate::connector::TlsConfig;
use crate::cookie::ServoCookie;
use crate::hosts::replace_host;
use crate::http_loader::HttpState;
use servo_config::pref;

/// Create a Request object for the initial HTTP request.
/// This request contains `Origin`, `Sec-WebSocket-Protocol`, `Authorization`,
/// and `Cookie` headers as appropriate.
/// Returns an error if any header values are invalid or tungstenite cannot create
/// the desired request.
pub fn create_handshake_request(
    request: RequestBuilder,
    http_state: Arc<HttpState>,
) -> Result<net_traits::request::Request, Error> {
    let origin = request.url.origin();

    let mut headers = HeaderMap::new();
    headers.insert(
        "Origin",
        HeaderValue::from_str(&request.url.origin().ascii_serialization())?,
    );

    let host = format!(
        "{}",
        origin
            .host()
            .ok_or_else(|| Error::Url(UrlError::NoHostName))?
    );
    headers.insert("Host", HeaderValue::from_str(&host)?);

    // https://websockets.spec.whatwg.org/#concept-websocket-establish
    // 3. Append (`Upgrade`, `websocket`) to request’s header list.
    headers.typed_insert(Upgrade::websocket());

    // 4. Append (`Connection`, `Upgrade`) to request’s header list.
    headers.typed_insert(Connection::upgrade());

    // 5. Let keyValue be a nonce consisting of a randomly selected 16-byte value that has been
    // forgiving-base64-encoded and isomorphic encoded.
    let mut nonce: [u8; 16] = [0; 16];
    rand::fill(&mut nonce);
    let sec_websocket_key_header: SecWebsocketKey = nonce.into();

    // 6. Append (`Sec-WebSocket-Key`, keyValue) to request’s header list.
    headers.typed_insert(sec_websocket_key_header);

    // 7. Append (`Sec-WebSocket-Version`, `13`) to request’s header list.
    headers.typed_insert(SecWebsocketVersion::V13);

    // 8. For each protocol in protocols, combine (`Sec-WebSocket-Protocol`, protocol) in request’s
    // header list.
    let protocols = match request.mode {
        RequestMode::WebSocket {
            ref protocols,
            original_url: _,
        } => protocols,
        _ => unreachable!("How did we get here?"),
    };
    if !protocols.is_empty() {
        let protocols = protocols.join(",");
        headers.insert("Sec-WebSocket-Protocol", HeaderValue::from_str(&protocols)?);
    }

    let partition_url = request
        .referrer
        .to_url()
        .cloned()
        .unwrap_or_else(|| request.url.url());
    let third_party = request
        .referrer
        .to_url()
        .is_some_and(|referrer| !is_same_site(&referrer.origin(), &request.url.origin()));
    if !pref!(network_nomad_block_third_party_cookies) || !third_party {
        let mut cookie_jar = http_state.cookie_jar.write();
        let cookie_list = if pref!(network_nomad_partition_storage) {
            cookie_jar.remove_expired_cookies_for_url_in_partition(&request.url, &partition_url);
            cookie_jar.cookies_for_url_in_partition(
                &request.url,
                &partition_url,
                CookieSource::HTTP,
            )
        } else {
            cookie_jar.remove_expired_cookies_for_url(&request.url);
            cookie_jar.cookies_for_url(&request.url, CookieSource::HTTP)
        };
        if let Some(cookie_list) = cookie_list {
            headers.insert("Cookie", HeaderValue::from_str(&cookie_list)?);
        }
    }

    if request.url.password().is_some() || request.url.username() != "" {
        headers.typed_insert(Authorization::basic(
            request.url.username(),
            request.url.password().unwrap_or(""),
        ));
    }
    Ok(request.headers(headers).build())
}

/// Process an HTTP response resulting from a WS handshake.
/// This ensures that any `Cookie` or HSTS headers are recognized.
/// Returns an error if the protocol selected by the handshake doesn't
/// match the list of provided protocols in the original request.
fn process_ws_response(
    http_state: &HttpState,
    response: &Response,
    resource_url: &ServoUrl,
    partition_url: &ServoUrl,
    third_party: bool,
    protocols: &[String],
) -> Result<Option<String>, Error> {
    trace!("processing websocket http response for {}", resource_url);
    let mut protocol_in_use = None;
    if let Some(protocol_name) = response.headers().get("Sec-WebSocket-Protocol") {
        let protocol_name = protocol_name.to_str().unwrap_or("");
        if !protocols.is_empty() && !protocols.iter().any(|p| protocol_name == (*p)) {
            return Err(Error::Protocol(ProtocolError::InvalidHeader(Box::new(
                HeaderName::from_static("sec-websocket-protocol"),
            ))));
        }
        protocol_in_use = Some(protocol_name.to_string());
    }

    if !pref!(network_nomad_block_third_party_cookies) || !third_party {
        let mut jar = http_state.cookie_jar.write();
        // TODO(eijebong): Replace thise once typed headers settled on a cookie impl
        for cookie in response.headers().get_all(header::SET_COOKIE) {
            let cookie_bytes = cookie.as_bytes();
            if !ServoCookie::is_valid_name_or_value(cookie_bytes) {
                continue;
            }
            if let Ok(s) = std::str::from_utf8(cookie_bytes)
                && let Some(cookie) =
                    ServoCookie::from_cookie_string(s, resource_url, CookieSource::HTTP)
            {
                if pref!(network_nomad_partition_storage) {
                    jar.push_in_partition(cookie, resource_url, partition_url, CookieSource::HTTP);
                } else {
                    jar.push(cookie, resource_url, CookieSource::HTTP);
                }
            }
        }
    }

    http_state
        .hsts_list
        .write()
        .update_hsts_list_from_response(resource_url, response.headers());

    Ok(protocol_in_use)
}

#[derive(Debug)]
enum DomMsg {
    Send(Message),
    Close(Option<(u16, String)>),
}

/// Initialize a listener for DOM actions. These are routed from the IPC channel
/// to a tokio channel that the main WS client task uses to receive them.
fn setup_dom_listener(
    dom_action_receiver: CallbackSetter<WebSocketDomAction>,
    initiated_close: Arc<AtomicBool>,
) -> UnboundedReceiver<DomMsg> {
    let (sender, receiver) = unbounded_channel();

    dom_action_receiver.set_callback(move |message| {
        let dom_action = message.expect("Ws dom_action message to deserialize");
        trace!("handling WS DOM action: {:?}", dom_action);
        match dom_action {
            WebSocketDomAction::SendMessage(MessageData::Text(data)) => {
                if let Err(e) = sender.send(DomMsg::Send(Message::Text(data.into()))) {
                    warn!("Error sending websocket message: {:?}", e);
                }
            },
            WebSocketDomAction::SendMessage(MessageData::Binary(data)) => {
                if let Err(e) = sender.send(DomMsg::Send(Message::Binary(data.into()))) {
                    warn!("Error sending websocket message: {:?}", e);
                }
            },
            WebSocketDomAction::Close(code, reason) => {
                if initiated_close.fetch_or(true, Ordering::SeqCst) {
                    return;
                }
                let frame = code.map(move |c| (c, reason.unwrap_or_default()));
                if let Err(e) = sender.send(DomMsg::Close(frame)) {
                    warn!("Error closing websocket: {:?}", e);
                }
            },
        }
    });

    receiver
}

/// Listen for WS events from the DOM and the network until one side
/// closes the connection or an error occurs. Since this is an async
/// function that uses the select operation, it will run as a task
/// on the WS tokio runtime.
async fn run_ws_loop(
    mut dom_receiver: UnboundedReceiver<DomMsg>,
    resource_event_sender: IpcSender<WebSocketNetworkEvent>,
    mut stream: WebSocketStream<ConnectStream>,
) {
    loop {
        select! {
            dom_msg = dom_receiver.recv() => {
                trace!("processing dom msg: {:?}", dom_msg);
                let dom_msg = match dom_msg {
                    Some(msg) => msg,
                    None => break,
                };
                match dom_msg {
                    DomMsg::Send(m) => {
                        if let Err(e) = stream.send(m).await {
                            warn!("error sending websocket message: {:?}", e);
                        }
                    },
                    DomMsg::Close(frame) => {
                        if let Err(e) = stream.close(frame.map(|(code, reason)| {
                            CloseFrame {
                                code: code.into(),
                                reason: reason.into(),
                            }
                        })).await {
                            warn!("error closing websocket: {:?}", e);
                        }
                    },
                }
            }
            ws_msg = stream.next() => {
                trace!("processing WS stream: {:?}", ws_msg);
                let msg = match ws_msg {
                    Some(Ok(msg)) => msg,
                    Some(Err(e)) => {
                        warn!("Error in WebSocket communication: {:?}", e);
                        let _ = resource_event_sender.send(WebSocketNetworkEvent::Fail);
                        break;
                    },
                    None => {
                        warn!("Error in WebSocket communication");
                        let _ = resource_event_sender.send(WebSocketNetworkEvent::Fail);
                        break;
                    }
                };
                match msg {
                    Message::Text(s) => {
                        let message = MessageData::Text(s.as_str().to_owned());
                        if let Err(e) = resource_event_sender
                            .send(WebSocketNetworkEvent::MessageReceived(message))
                        {
                            warn!("Error sending websocket notification: {:?}", e);
                            break;
                        }
                    }

                    Message::Binary(v) => {
                        let message = MessageData::Binary(v.to_vec());
                        if let Err(e) = resource_event_sender
                            .send(WebSocketNetworkEvent::MessageReceived(message))
                        {
                            warn!("Error sending websocket notification: {:?}", e);
                            break;
                        }
                    }

                    Message::Ping(_) | Message::Pong(_) => {}

                    Message::Close(frame) => {
                        let (reason, code) = match frame {
                            Some(frame) => (frame.reason, Some(frame.code.into())),
                            None => ("".into(), None),
                        };
                        debug!("Websocket connection closing due to ({:?}) {}", code, reason);
                        let _ = resource_event_sender.send(WebSocketNetworkEvent::Close(
                            code,
                            reason.to_string(),
                        ));
                        break;
                    }

                    Message::Frame(_) => {
                        warn!("Unexpected websocket frame message");
                    }
                }
            }
        }
    }
}

/// Initiate a new async WS connection. Returns an error if the connection fails
/// for any reason, or if the response isn't valid. Otherwise, the endless WS
/// listening loop will be started.
pub(crate) async fn start_websocket(
    http_state: Arc<HttpState>,
    resource_event_sender: IpcSender<WebSocketNetworkEvent>,
    protocols: &[String],
    client: &net_traits::request::Request,
    tls_config: TlsConfig,
    dom_action_receiver: CallbackSetter<WebSocketDomAction>,
) -> Result<Response, Error> {
    trace!("starting WS connection to {}", client.url());

    let initiated_close = Arc::new(AtomicBool::new(false));
    let dom_receiver = setup_dom_listener(dom_action_receiver, initiated_close.clone());

    let url = client.url();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| Error::Url(UrlError::UnableToConnect("Unknown port".into())))?;
    let socket = connect_websocket_socket(&url, port).await?;
    let connector = TlsConnector::from(Arc::new(tls_config));

    // TODO(pylbrecht): move request conversion to a separate function
    let mut original_url = client.original_url();
    if original_url.scheme() == "ws" && url.scheme() == "https" {
        original_url.as_mut_url().set_scheme("wss").unwrap();
    }
    let mut builder =
        ClientRequestBuilder::new(original_url.as_str().parse().expect("unable to parse URI"));
    for (key, value) in client.headers.iter() {
        builder = builder.with_header(
            key.as_str(),
            value
                .to_str()
                .expect("unable to convert header value to string"),
        );
    }

    let (stream, response) =
        client_async_tls_with_connector_and_config(builder, socket, Some(connector), None).await?;

    let partition_url = client
        .referrer
        .to_url()
        .cloned()
        .unwrap_or_else(|| url.clone());
    let third_party = client
        .referrer
        .to_url()
        .is_some_and(|referrer| !is_same_site(&referrer.origin(), &url.origin()));
    let protocol_in_use = process_ws_response(
        &http_state,
        &response,
        &url,
        &partition_url,
        third_party,
        protocols,
    )?;

    if !initiated_close.load(Ordering::SeqCst) {
        if resource_event_sender
            .send(WebSocketNetworkEvent::ConnectionEstablished { protocol_in_use })
            .is_err()
        {
            return Ok(response);
        }

        trace!("about to start ws loop for {}", url);
        spawn_task(run_ws_loop(dom_receiver, resource_event_sender, stream));
    } else {
        trace!("client closed connection for {}, not running loop", url);
    }
    Ok(response)
}

async fn connect_websocket_socket(url: &ServoUrl, port: u16) -> Result<TcpStream, Error> {
    let target_host = url
        .host_str()
        .ok_or_else(|| Error::Url(UrlError::NoHostName))?;
    let proxy_raw = pref!(network_https_proxy_uri).to_owned();
    if proxy_raw.is_empty() {
        let direct_host = replace_host(target_host);
        return TcpStream::connect((direct_host.as_ref(), port))
            .await
            .map_err(Error::Io);
    }

    let proxy: Uri = proxy_raw.parse().map_err(|error| {
        Error::Url(UrlError::UnableToConnect(format!(
            "invalid websocket proxy: {error}"
        )))
    })?;
    let authority = proxy.authority().ok_or_else(|| {
        Error::Url(UrlError::UnableToConnect(
            "websocket proxy has no host".into(),
        ))
    })?;
    let proxy_port = authority.port_u16().ok_or_else(|| {
        Error::Url(UrlError::UnableToConnect(
            "websocket proxy has no port".into(),
        ))
    })?;
    let mut stream = TcpStream::connect((authority.host().to_owned(), proxy_port))
        .await
        .map_err(Error::Io)?;
    match proxy.scheme_str() {
        Some("socks5") | Some("socks5h") => {
            socks5_connect(&mut stream, target_host, port).await?;
        },
        Some("http") => {
            http_connect(&mut stream, target_host, port).await?;
        },
        _ => {
            return Err(Error::Url(UrlError::UnableToConnect(
                "unsupported websocket proxy scheme".into(),
            )));
        },
    }
    Ok(stream)
}

async fn socks5_connect(stream: &mut TcpStream, host: &str, port: u16) -> Result<(), Error> {
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(Error::Io)?;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await.map_err(Error::Io)?;
    if greeting != [0x05, 0x00] {
        return Err(Error::Url(UrlError::UnableToConnect(
            "SOCKS5 proxy rejected unauthenticated websocket connection".into(),
        )));
    }
    let host_bytes = host.as_bytes();
    let host_len = u8::try_from(host_bytes.len()).map_err(|_| {
        Error::Url(UrlError::UnableToConnect(
            "websocket target host is too long".into(),
        ))
    })?;
    let mut request = Vec::with_capacity(7 + host_bytes.len());
    request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_len]);
    request.extend_from_slice(host_bytes);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.map_err(Error::Io)?;

    let mut response = [0; 4];
    stream.read_exact(&mut response).await.map_err(Error::Io)?;
    if response[0] != 0x05 || response[1] != 0x00 {
        return Err(Error::Url(UrlError::UnableToConnect(
            "SOCKS5 proxy rejected websocket target".into(),
        )));
    }
    let address_length = match response[3] {
        0x01 => 4,
        0x03 => {
            let mut length = [0; 1];
            stream.read_exact(&mut length).await.map_err(Error::Io)?;
            usize::from(length[0])
        },
        0x04 => 16,
        _ => {
            return Err(Error::Url(UrlError::UnableToConnect(
                "SOCKS5 proxy returned an invalid websocket address".into(),
            )));
        },
    };
    let mut bound_address = vec![0; address_length + 2];
    stream
        .read_exact(&mut bound_address)
        .await
        .map_err(Error::Io)?;
    Ok(())
}

async fn http_connect(stream: &mut TcpStream, host: &str, port: u16) -> Result<(), Error> {
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(Error::Io)?;
    let mut response = Vec::with_capacity(1024);
    let mut buffer = [0; 1024];
    while !response.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).await.map_err(Error::Io)?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..read]);
        if response.len() > 16 * 1024 {
            return Err(Error::Url(UrlError::UnableToConnect(
                "websocket proxy response is too large".into(),
            )));
        }
    }
    let status_line = response
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .unwrap_or_default();
    let success = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse::<u16>().ok())
        .is_some_and(|status| (200..300).contains(&status));
    if !success {
        return Err(Error::Url(UrlError::UnableToConnect(
            "websocket proxy CONNECT failed".into(),
        )));
    }
    Ok(())
}
