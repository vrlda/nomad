/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use embedder_traits::WebResourceRequestDecision;
use http::Method;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use net::async_runtime::spawn_blocking_task;
use net::embedder::NetToEmbedderMsg;
use net::fetch::methods::FetchContext;
use net::request_interceptor::RequestInterceptor;
use net_traits::request::{
    BodyChunkRequest, BodySource, Destination, Referrer, RequestBody, RequestBuilder,
};
use net_traits::response::Response;
use net_traits::{NetworkError, ResourceFetchTiming, ResourceTimingType};
use servo_base::id::{TEST_PIPELINE_ID, TEST_WEBVIEW_ID};
use servo_url::ServoUrl;

use crate::{
    create_generic_embedder_proxy, create_generic_embedder_proxy_and_receiver, new_fetch_context,
};

/// A recorded outbound web resource request as surfaced to the embedder.
#[derive(Clone, Debug)]
struct RecordedRequest {
    method: http::Method,
    url: url::Url,
    headers: HeaderMap,
    is_for_main_frame: bool,
    request_body_size: Option<usize>,
    request_body_unavailable: bool,
}

fn test_context(
    embedder_proxy: embedder_traits::GenericEmbedderProxy<NetToEmbedderMsg>,
) -> FetchContext {
    new_fetch_context(None, Some(embedder_proxy))
}

/// Runs [`RequestInterceptor::intercept_request`] against a recording embedder
/// that answers the `WebResourceRequested` message with the supplied decision.
/// Returns the recorded outbound request, the live post-decision request, and
/// the resulting response (a `LoadCancelled` error when cancelled).
fn intercept_with_decision(
    destination: Destination,
    body: Option<RequestBody>,
    decision: WebResourceRequestDecision,
) -> (
    RecordedRequest,
    net_traits::request::Request,
    Result<Response, NetworkError>,
) {
    // Make sure the shared async runtime is initialized, mirroring the pattern
    // used by the other net tests.
    let _runtime_proxy = create_generic_embedder_proxy::<NetToEmbedderMsg>();
    let (embedder_proxy, embedder_receiver) = create_generic_embedder_proxy_and_receiver();
    let context = test_context(embedder_proxy.clone());

    let responder = std::thread::spawn(move || {
        while let Ok(message) = embedder_receiver.recv() {
            if let NetToEmbedderMsg::WebResourceRequested(_, web_resource_request, sender) = message
            {
                let _ = sender.send(embedder_traits::WebResourceResponseMsg::Continue(
                    decision.clone(),
                ));
                return RecordedRequest {
                    method: web_resource_request.method.clone(),
                    url: web_resource_request.url.clone(),
                    headers: web_resource_request.headers.clone(),
                    is_for_main_frame: web_resource_request.is_for_main_frame,
                    request_body_size: web_resource_request.request_body_size,
                    request_body_unavailable: web_resource_request.request_body_unavailable,
                };
            }
        }
        panic!("interceptor must surface the request to the embedder");
    });

    let url = ServoUrl::parse("https://example.com/page").unwrap();
    let mut request = RequestBuilder::new(
        Some(TEST_WEBVIEW_ID),
        net_traits::blob_url_store::UrlWithBlobClaim::from_url_without_having_claimed_blob(url),
        Referrer::NoReferrer,
    )
    .method(Method::GET)
    .body(body)
    .destination(destination)
    .origin(ServoUrl::parse("https://example.com/").unwrap().origin())
    .pipeline_id(Some(TEST_PIPELINE_ID))
    .policy_container(Default::default())
    .build();
    request.headers.insert(
        HeaderName::from_static("x-trace"),
        HeaderValue::from_static("abc"),
    );

    let mut response = Some(Response::new(
        request.url(),
        ResourceFetchTiming::new(ResourceTimingType::Navigation),
    ));

    let interceptor = RequestInterceptor::new(embedder_proxy);
    spawn_blocking_task::<_, ()>(interceptor.intercept_request(
        &mut request,
        &mut response,
        &context,
    ));

    let recorded = responder.join().unwrap();
    let result = match response {
        Some(response) => Ok(response),
        None => Err(NetworkError::LoadCancelled),
    };
    (recorded, request, result)
}

fn decision_with(
    request_headers: HeaderMap,
    response_headers: HeaderMap,
) -> WebResourceRequestDecision {
    WebResourceRequestDecision {
        cancel: false,
        redirect_url: None,
        request_headers,
        response_headers,
    }
}

#[test]
fn main_document_navigation_applies_request_header_mutation_and_redirect() {
    let mut request_headers = HeaderMap::new();
    request_headers.insert(
        HeaderName::from_static("x-trace"),
        HeaderValue::from_static("redirected"),
    );
    let decision = WebResourceRequestDecision {
        redirect_url: Some(url::Url::parse("https://example.com/redirected").unwrap()),
        ..decision_with(request_headers, HeaderMap::new())
    };

    let (recorded, request, result) =
        intercept_with_decision(Destination::Document, None, decision);

    assert!(
        recorded.is_for_main_frame,
        "document destination must be reported as main frame"
    );
    assert_eq!(recorded.method, Method::GET);
    assert_eq!(
        recorded.url.as_str(),
        "https://example.com/page",
        "the embedder must observe the original outbound URL"
    );
    assert_eq!(
        recorded.headers.get("x-trace").unwrap(),
        "abc",
        "the embedder must observe the original outbound header set"
    );
    assert_eq!(
        request.current_url().as_str(),
        "https://example.com/redirected",
        "the redirect decision must replace the live request URL"
    );
    assert_eq!(
        request.headers.get("x-trace").unwrap(),
        "redirected",
        "request header mutations must be applied to the live request"
    );
    assert!(result.is_ok());
}

#[test]
fn subresource_request_applies_outbound_header_mutation_without_main_frame_flag() {
    let mut request_headers = HeaderMap::new();
    request_headers.insert(
        HeaderName::from_static("x-trace"),
        HeaderValue::from_static("mutated"),
    );
    let decision = decision_with(request_headers, HeaderMap::new());

    let (recorded, request, result) = intercept_with_decision(Destination::Script, None, decision);

    assert!(
        !recorded.is_for_main_frame,
        "script destination must not be reported as main frame"
    );
    assert_eq!(recorded.url.as_str(), "https://example.com/page");
    assert_eq!(
        request.current_url().as_str(),
        "https://example.com/page",
        "subresource requests must keep their URL without a redirect decision"
    );
    assert_eq!(
        request.headers.get("x-trace").unwrap(),
        "mutated",
        "subresource request header mutations must be applied"
    );
    assert!(result.is_ok());
}

#[test]
fn cancel_decision_yields_network_error() {
    let decision = WebResourceRequestDecision {
        cancel: true,
        ..decision_with(HeaderMap::new(), HeaderMap::new())
    };

    let (recorded, _, result) = intercept_with_decision(Destination::Document, None, decision);

    assert!(recorded.is_for_main_frame);
    let response = result.expect("cancel wraps a network-error response");
    assert_eq!(
        response.get_network_error(),
        Some(&NetworkError::LoadCancelled),
        "a cancelled blocking decision must surface LoadCancelled"
    );
}

#[test]
fn response_header_mutation_is_delivered_to_response() {
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        HeaderName::from_static("x-nomad-test"),
        HeaderValue::from_static("injected"),
    );
    let decision = decision_with(HeaderMap::new(), response_headers);

    let (recorded, _, result) = intercept_with_decision(Destination::Document, None, decision);

    let response = result.unwrap();
    assert_eq!(
        response
            .headers
            .get("x-nomad-test")
            .map(HeaderValue::as_bytes),
        Some(b"injected".as_ref()),
        "response header mutations from the blocking decision must reach the response"
    );
    assert_eq!(recorded.url.as_str(), "https://example.com/page");
}

#[test]
fn body_metadata_is_bounded_and_reported() {
    let decision = decision_with(HeaderMap::new(), HeaderMap::new());

    // A body-less request reports neither size nor unavailability.
    let (recorded, _, _) = intercept_with_decision(Destination::Document, None, decision.clone());
    assert_eq!(recorded.request_body_size, None);
    assert!(!recorded.request_body_unavailable);

    // A request with a known-size streaming body reports its declared size and
    // unavailability, without leaking body bytes.
    let (ipc_sender, _) = ipc_channel::ipc::channel::<BodyChunkRequest>().unwrap();
    let body = RequestBody::new(ipc_sender, BodySource::Null, Some(42));
    let (recorded, _, _) = intercept_with_decision(Destination::Document, Some(body), decision);
    assert_eq!(
        recorded.request_body_size,
        Some(42),
        "declared body size must be surfaced as bounded metadata"
    );
    assert!(recorded.request_body_unavailable);
}
