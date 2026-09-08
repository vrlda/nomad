/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use content_security_policy::Destination;
use embedder_traits::{GenericEmbedderProxy, WebResourceRequest, WebResourceResponseMsg};
use log::error;
use net_traits::NetworkError;
use net_traits::http_status::HttpStatus;
use net_traits::request::Request;
use net_traits::response::{Response, ResponseBody};
use servo_base::id::WebViewId;
use servo_url::ServoUrl;

use crate::embedder::NetToEmbedderMsg;
use crate::fetch::methods::FetchContext;

#[derive(Clone)]
pub struct RequestInterceptor {
    embedder_proxy: GenericEmbedderProxy<NetToEmbedderMsg>,
}

impl RequestInterceptor {
    pub fn new(embedder_proxy: GenericEmbedderProxy<NetToEmbedderMsg>) -> RequestInterceptor {
        RequestInterceptor { embedder_proxy }
    }

    pub async fn intercept_request(
        &self,
        request: &mut Request,
        response: &mut Option<Response>,
        context: &FetchContext,
    ) {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let is_for_main_frame = matches!(request.destination, Destination::Document);
        let web_resource_request = WebResourceRequest {
            method: request.method.clone(),
            url: request.url().into_url(),
            headers: request.headers.clone(),
            destination: request.destination,
            referrer_url: request.referrer.to_url().map(|url| url.as_url().clone()),
            is_for_main_frame,
            is_redirect: request.redirect_count > 0,
            request_body_size: request.body.as_ref().and_then(|body| body.len()),
            request_body_unavailable: request.body.is_some(),
        };

        self.embedder_proxy
            .send(NetToEmbedderMsg::WebResourceRequested(
                request.target_webview_id,
                web_resource_request,
                sender,
            ));

        // Request continuation is synchronous: fetch cannot proceed until embedder
        // answers. Response header edits are retained for application below.
        let mut response_headers = None;
        let mut accumulated_body = Vec::new();
        while let Some(message) = receiver.recv().await {
            match message {
                WebResourceResponseMsg::Continue(decision) => {
                    if decision.cancel {
                        *response = Some(Response::network_error(NetworkError::LoadCancelled));
                        return;
                    }
                    if let Some(redirect_url) = decision.redirect_url {
                        *request.current_url_mut() = ServoUrl::from_url(redirect_url);
                    }
                    for (name, value) in decision.request_headers {
                        let Some(name) = name else {
                            continue;
                        };
                        request.headers.insert(name, value);
                    }
                    if !decision.response_headers.is_empty() {
                        response_headers = Some(decision.response_headers);
                    }
                    break;
                },
                WebResourceResponseMsg::Start(webresource_response) => {
                    let timing = context.timing.inner().clone();
                    let mut response_override =
                        Response::new(webresource_response.url.into(), timing);
                    response_override.headers = webresource_response.headers;
                    response_override.status = HttpStatus::new(
                        webresource_response.status_code,
                        webresource_response.status_message,
                    );
                    *response = Some(response_override);
                },
                WebResourceResponseMsg::SendBodyData(data) => {
                    accumulated_body.push(data);
                },
                WebResourceResponseMsg::FinishLoad => {
                    if accumulated_body.is_empty() {
                        break;
                    }
                    let Some(response) = response.as_mut() else {
                        error!("Received unexpected FinishLoad message");
                        break;
                    };
                    *response.body.lock() =
                        ResponseBody::Done(accumulated_body.into_iter().flatten().collect());
                    break;
                },
                WebResourceResponseMsg::CancelLoad => {
                    *response = Some(Response::network_error(NetworkError::LoadCancelled));
                    break;
                },
                WebResourceResponseMsg::DoNotIntercept => break,
            }
        }
        if let (Some(headers), Some(response)) = (response_headers, response.as_mut()) {
            for (name, value) in headers {
                let Some(name) = name else {
                    continue;
                };
                response.headers.insert(name, value);
            }
        }
    }

    /// Notifies the embedder that a web resource load previously surfaced
    /// through [`RequestInterceptor::intercept_request`] has completed. The
    /// HTTP status is `None` and `failed` is true when the fetch ended in a
    /// network error. Only response headers are retained.
    pub fn notify_load_finished(
        &self,
        webview_id: Option<WebViewId>,
        method: http::Method,
        url: ServoUrl,
        status: Option<u16>,
        response_headers: Vec<(String, String)>,
        failed: bool,
    ) {
        self.embedder_proxy
            .send(NetToEmbedderMsg::WebResourceLoadFinished(
                webview_id,
                method,
                url,
                status,
                response_headers,
                failed,
            ));
    }
}
