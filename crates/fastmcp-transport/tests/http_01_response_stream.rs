use asupersync::Cx;
use fastmcp_protocol::protocol_version::{HeaderMismatchReason, RequestAdmissionError};
use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId};
use fastmcp_transport::{
    Transport, TransportError,
    http::{
        HttpError, HttpHandlerConfig, HttpMethod, HttpRequest, HttpRequestHandler,
        HttpResponseRepresentation, StreamableHttpRequestResponseMessage, StreamableHttpTransport,
    },
};

fn modern_sse_request() -> HttpRequest {
    let request = JsonRpcRequest::new(
        "tools/call",
        Some(serde_json::json!({
            "name": "weather",
            "arguments": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28"
            }
        })),
        901_i64,
    );
    HttpRequest::new(HttpMethod::Post, "/mcp")
        .with_header("content-type", "application/json")
        .with_header("accept", "text/event-stream")
        .with_header("MCP-Protocol-Version", "2026-07-28")
        .with_header("Mcp-Method", "tools/call")
        .with_header("Mcp-Name", "weather")
        .with_body(serde_json::to_vec(&request).expect("serialize modern request"))
}

fn modern_handler() -> HttpRequestHandler {
    HttpRequestHandler::with_config(HttpHandlerConfig {
        base_path: "/mcp".to_owned(),
        ..HttpHandlerConfig::default()
    })
}

#[test]
fn http_01_a_positive() {
    let mut transport = StreamableHttpTransport::new();
    let responses = transport
        .response_stream()
        .expect("the public HTTP response stream can be externalized once");
    let request_id = RequestId::Number(701);
    let response_body = responses
        .for_request(request_id.clone())
        .expect("one public response body is registered for the request");
    let cancellation = response_body.cancellation();
    let cx = Cx::for_testing();

    transport
        .send_response_for_request(
            &cx,
            &cancellation,
            JsonRpcResponse::success(request_id.clone(), serde_json::json!({"response": "bound"})),
        )
        .expect("the request-bound final response is admitted");

    assert_eq!(
        response_body
            .recv_response(&cx)
            .expect("the public response body receives its own final response")
            .id,
        Some(request_id)
    );
    assert!(response_body.is_finished());
    assert!(cancellation.is_cancelled());
    assert_eq!(responses.pending_responses(), 0);
}

#[test]
fn http_01_a_planted_negative() {
    let mut transport = StreamableHttpTransport::new();
    let responses = transport
        .response_stream()
        .expect("the public HTTP response stream can be externalized once");
    let request_id = RequestId::Number(702);
    let response_body = responses
        .for_request(request_id.clone())
        .expect("one public response body is registered for the request");
    let cancellation = response_body.cancellation();
    let cx = Cx::for_testing();
    let pending_before = responses.pending_responses();

    // Planted forbidden dimension: only the response body is disconnected
    // before the otherwise identical handler commit.
    drop(response_body);

    assert!(matches!(
        transport.send_response_for_request(
            &cx,
            &cancellation,
            JsonRpcResponse::success(request_id, serde_json::json!({"response": "bound"})),
        ),
        Err(TransportError::Cancelled)
    ));
    assert_eq!(responses.pending_responses(), pending_before);
    assert!(!responses.is_closed());
}

#[test]
fn http_01_b_positive() {
    let mut transport =
        StreamableHttpTransport::with_capacity(1).expect("a one-entry bounded transport is valid");
    let responses = transport
        .response_stream()
        .expect("the public HTTP response stream can be externalized once");
    let first_id = RequestId::Number(801);
    let first_body = responses
        .for_request(first_id.clone())
        .expect("the first public response body is registered");
    let first_cancellation = first_body.cancellation();
    let second_id = RequestId::Number(802);
    let second_body = responses
        .for_request(second_id.clone())
        .expect("the second public response body is registered");
    let second_cancellation = second_body.cancellation();
    let cx = Cx::for_testing();

    transport
        .send_response_for_request(
            &cx,
            &first_cancellation,
            JsonRpcResponse::success(first_id.clone(), serde_json::json!({"sequence": 1})),
        )
        .expect("the first response consumes the sole bounded slot");
    assert!(first_cancellation.is_terminal_committed());
    assert!(matches!(
        transport.send_response_for_request(
            &cx,
            &second_cancellation,
            JsonRpcResponse::success(second_id.clone(), serde_json::json!({"sequence": 2})),
        ),
        Err(TransportError::Io(ref error)) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    assert_eq!(responses.pending_responses(), 1);

    assert_eq!(
        first_body
            .recv_response(&cx)
            .expect("draining the first final response releases the bounded slot")
            .id,
        Some(first_id.clone())
    );
    assert!(matches!(
        transport.send_response_for_request(
            &cx,
            &first_cancellation,
            JsonRpcResponse::success(first_id, serde_json::json!({"late": true})),
        ),
        Err(TransportError::Cancelled)
    ));
    transport
        .send_response_for_request(
            &cx,
            &second_cancellation,
            JsonRpcResponse::success(second_id.clone(), serde_json::json!({"sequence": 2})),
        )
        .expect("the released slot admits the second response");
    assert_eq!(
        second_body
            .recv_response(&cx)
            .expect("the second public response body receives its final response")
            .id,
        Some(second_id)
    );
    assert_eq!(responses.pending_responses(), 0);
}

#[test]
fn http_01_b_planted_negative() {
    let mut transport =
        StreamableHttpTransport::with_capacity(1).expect("a one-entry bounded transport is valid");
    let responses = transport
        .response_stream()
        .expect("the public HTTP response stream can be externalized once");
    let first_id = RequestId::Number(801);
    let first_body = responses
        .for_request(first_id.clone())
        .expect("the first public response body is registered");
    let first_cancellation = first_body.cancellation();
    let second_id = RequestId::Number(802);
    let second_body = responses
        .for_request(second_id.clone())
        .expect("the second public response body is registered");
    let second_cancellation = second_body.cancellation();
    let cx = Cx::for_testing();
    let pending_before = responses.pending_responses();

    // Planted forbidden dimension: only the first response body is disconnected
    // before the otherwise identical bounded final-response commit.
    drop(first_body);

    assert!(matches!(
        transport.send_response_for_request(
            &cx,
            &first_cancellation,
            JsonRpcResponse::success(first_id, serde_json::json!({"sequence": 1})),
        ),
        Err(TransportError::Cancelled)
    ));
    assert_eq!(responses.pending_responses(), pending_before);
    assert!(!responses.is_closed());
    transport
        .send_response_for_request(
            &cx,
            &second_cancellation,
            JsonRpcResponse::success(second_id.clone(), serde_json::json!({"sequence": 2})),
        )
        .expect("the cancelled first body leaves the bounded slot available");
    assert_eq!(
        second_body
            .recv_response(&cx)
            .expect("the independent second request remains live")
            .id,
        Some(second_id)
    );
}

#[test]
fn http_02_a_positive() {
    let handler = modern_handler();
    let admission = handler
        .admit_modern_request(&modern_sse_request())
        .expect("the public modern HTTP boundary admits a matching 2026 request");
    assert_eq!(
        admission.response_representation(),
        HttpResponseRepresentation::Sse
    );
    assert_eq!(admission.request().method, "tools/call");

    let mut transport = StreamableHttpTransport::with_capacity(1)
        .expect("one bounded response slot is a valid public configuration");
    let responses = transport
        .response_stream()
        .expect("one public response stream can be externalized");
    assert_eq!(
        responses
            .live_request_bodies()
            .expect("idle response registry is observable"),
        0
    );

    let response_body = admission
        .bind_sse_response_body(&responses)
        .expect("only the admitted request receives an SSE response body");
    let cancellation = response_body.cancellation();
    assert_eq!(
        responses
            .live_request_bodies()
            .expect("bound response body is observable"),
        1
    );

    let cx = Cx::for_testing();
    transport
        .send_response_for_request(
            &cx,
            &cancellation,
            JsonRpcResponse::success(
                RequestId::Number(901),
                serde_json::json!({"forecast": "clear"}),
            ),
        )
        .expect("the request-owned SSE body admits one terminal response");
    assert_eq!(responses.pending_responses(), 1);
    assert_eq!(
        response_body
            .recv_response(&cx)
            .expect("the SSE body consumes its own terminal response")
            .id,
        Some(RequestId::Number(901))
    );
    assert!(response_body.is_finished());
    assert!(cancellation.is_cancelled());
    assert_eq!(responses.pending_responses(), 0);
    assert_eq!(
        responses
            .live_request_bodies()
            .expect("finished response body is released"),
        0
    );
}

#[test]
fn http_02_a_planted_negative() {
    let handler = modern_handler();
    let baseline = modern_sse_request();
    let mut rejected = baseline.clone();
    // Planted forbidden dimension: only the required name mirror changes.
    rejected
        .headers
        .insert("mcp-name".to_owned(), "other-weather".to_owned());

    let mut transport = StreamableHttpTransport::new();
    let responses = transport
        .response_stream()
        .expect("one public response stream can be externalized");
    let before_pending = responses.pending_responses();
    let before_bodies = responses
        .live_request_bodies()
        .expect("idle response registry is observable");

    let error = handler
        .admit_modern_request(&rejected)
        .expect_err("changing only Mcp-Name must reject at the PRT-03 boundary");
    assert!(matches!(
        error,
        HttpError::ProtocolAdmission(RequestAdmissionError::HeaderMismatch(error))
            if error.reason() == HeaderMismatchReason::HeaderBodyNameMismatch
    ));
    assert_eq!(rejected.method, baseline.method);
    assert_eq!(rejected.path, baseline.path);
    assert_eq!(rejected.body, baseline.body);
    assert_eq!(responses.pending_responses(), before_pending);
    assert_eq!(
        responses
            .live_request_bodies()
            .expect("rejection cannot allocate a response body"),
        before_bodies
    );
    assert_eq!(
        handler
            .admit_modern_request(&baseline)
            .expect("the unchanged baseline remains freshly admissible")
            .response_representation(),
        HttpResponseRepresentation::Sse
    );
    assert_eq!(
        responses
            .live_request_bodies()
            .expect("fresh baseline admission has not opened a response body"),
        before_bodies
    );
}

#[test]
fn http_02_b_positive() {
    let handler = modern_handler();
    let admission = handler
        .admit_modern_request(&modern_sse_request())
        .expect("a matching request is admitted before its response body opens");
    let mut transport = StreamableHttpTransport::with_capacity(1)
        .expect("one bounded response slot is a valid public configuration");
    let responses = transport
        .response_stream()
        .expect("one public response stream can be externalized");
    let response_body = admission
        .bind_sse_response_body(&responses)
        .expect("the request owns exactly one finite response body");
    let cancellation = response_body.cancellation();
    assert_eq!(
        responses
            .live_request_bodies()
            .expect("bound response body is observable"),
        1
    );

    drop(response_body);

    assert!(cancellation.is_cancelled());
    assert_eq!(
        responses
            .live_request_bodies()
            .expect("dropped response body is released"),
        0
    );
    assert_eq!(responses.pending_responses(), 0);
}

fn assert_http_01_owner_teardown(terminate: bool) {
    let cx = Cx::for_testing();
    let mut transport = StreamableHttpTransport::new();
    let (ingress, responses) = transport.split_handles().expect("externalize the HTTP owner");
    let request_id = RequestId::Number(811);
    let body = responses
        .for_request(request_id.clone())
        .expect("register the active subscription body");
    let cancellation = body.cancellation();
    let sender = body.sender();
    let acknowledgement = JsonRpcRequest::notification(
        "notifications/subscriptions/acknowledged",
        Some(serde_json::json!({
            "_meta": {"io.modelcontextprotocol/subscriptionId": 811},
            "notifications": {"toolsListChanged": true},
        })),
    );
    sender
        .send_notification(&cx, acknowledgement)
        .expect("acknowledge the subscription before teardown");
    assert!(matches!(
        body.pop_message(),
        Ok(Some(StreamableHttpRequestResponseMessage::Notification(notification)))
            if notification.method == "notifications/subscriptions/acknowledged"
                && notification.params.as_ref().and_then(|params| {
                    params.pointer("/_meta/io.modelcontextprotocol~1subscriptionId")
                }) == Some(&serde_json::json!(811))
    ));

    let changed = JsonRpcRequest::notification(
        "notifications/tools/list_changed",
        Some(serde_json::json!({
            "_meta": {"io.modelcontextprotocol/subscriptionId": 811},
        })),
    );
    sender
        .send_notification(&cx, changed.clone())
        .expect("retain an event that the peer has not consumed");
    let final_id = RequestId::Number(812);
    let final_body = responses
        .for_request(final_id.clone())
        .expect("register an independent final-response body on this owner");
    let final_cancellation = final_body.cancellation();
    final_body
        .sender()
        .send_response(
            &cx,
            JsonRpcResponse::success(final_id.clone(), serde_json::json!({"done": true})),
        )
        .expect("retain a committed final response before teardown");
    let json_id = RequestId::Number(813);
    transport
        .send(
            &cx,
            &JsonRpcMessage::Response(JsonRpcResponse::success(
                json_id.clone(),
                serde_json::json!({"json": true}),
            )),
        )
        .expect("retain an unowned JSON response before teardown");
    ingress
        .push_request(&cx, JsonRpcRequest::new("tools/list", None, 814_i64))
        .expect("queue a request that has not been dispatched");
    assert_eq!(responses.pending_responses(), 3);
    assert_eq!(responses.live_request_bodies().unwrap(), 2);
    assert_eq!(transport.pending_requests(), 1);

    let mut sibling = StreamableHttpTransport::new();
    let sibling_responses = sibling
        .response_stream()
        .expect("externalize a sibling owner");
    let sibling_body = sibling_responses
        .for_request(request_id.clone())
        .expect("the same request ID is independent on another HTTP owner");

    if terminate {
        transport.terminate();
        transport.terminate();
    } else {
        // The sole control mutation is a graceful close in place of owner
        // termination. It seals admissions but deliberately preserves output.
        Transport::close(&mut transport, &cx).expect("graceful close succeeds");
        Transport::close(&mut transport, &cx).expect("graceful close is idempotent");
    }
    assert!(ingress.is_closed());
    assert!(responses.is_closed());
    assert_eq!(transport.pending_requests(), 0);
    assert!(matches!(transport.recv(&cx), Err(TransportError::Closed)));
    assert!(matches!(
        ingress.push_request(&cx, JsonRpcRequest::new("tools/list", None, 815_i64)),
        Err(TransportError::Closed)
    ));
    assert!(matches!(
        responses.for_request(RequestId::Number(816)),
        Err(TransportError::Closed)
    ));

    if terminate {
        assert!(cancellation.is_cancelled());
        assert!(cancellation.request_cancellation().is_cancel_requested());
        assert!(final_cancellation.is_cancelled());
        assert_eq!(responses.live_request_bodies().unwrap(), 0);
        assert_eq!(responses.pending_responses(), 0);
        assert!(matches!(body.pop_message(), Err(TransportError::Cancelled)));
        assert!(matches!(
            final_body.pop_response(),
            Err(TransportError::Cancelled)
        ));
        assert!(matches!(
            responses.pop_response(Some(&json_id)),
            Err(TransportError::Closed)
        ));
        assert!(matches!(
            sender.send_notification(&cx, changed.clone()),
            Err(TransportError::Cancelled)
        ));
        assert!(matches!(
            sender.send_response(
                &cx,
                JsonRpcResponse::success(request_id, serde_json::json!({"late": true})),
            ),
            Err(TransportError::Cancelled)
        ));
        assert_eq!(responses.pending_responses(), 0);
    } else {
        assert!(!cancellation.is_cancelled());
        assert!(!cancellation.request_cancellation().is_cancel_requested());
        assert!(!final_cancellation.is_cancelled());
        assert_eq!(responses.live_request_bodies().unwrap(), 2);
        assert_eq!(responses.pending_responses(), 3);
        assert!(matches!(
            body.pop_message(),
            Ok(Some(StreamableHttpRequestResponseMessage::Notification(notification)))
                if notification.method == changed.method && notification.params == changed.params
        ));
        assert_eq!(final_body.pop_response().unwrap().unwrap().id, Some(final_id));
        assert_eq!(
            responses.pop_response(Some(&json_id)).unwrap().unwrap().id,
            Some(json_id)
        );
        assert!(matches!(
            sender.send_notification(&cx, changed.clone()),
            Err(TransportError::Closed)
        ));
        assert_eq!(responses.pending_responses(), 0);
    }

    assert!(
        !cx.is_cancel_requested(),
        "HTTP teardown preserves the caller context"
    );
    assert!(!sibling_body.cancellation().is_cancelled());
    sibling_body
        .sender()
        .send_notification(&cx, changed.clone())
        .expect("the other HTTP owner continues publishing after teardown");
    assert!(matches!(
        sibling_body.pop_message(),
        Ok(Some(StreamableHttpRequestResponseMessage::Notification(notification)))
            if notification.method == changed.method && notification.params == changed.params
    ));
}

#[test]
fn http_01_terminate_cancels_live_bodies_and_discards_queued_messages() {
    assert_http_01_owner_teardown(true);
}

#[test]
fn http_01_graceful_close_preserves_live_bodies_and_queued_messages() {
    assert_http_01_owner_teardown(false);
}

#[test]
fn http_02_b_planted_negative() {
    let handler = modern_handler();
    let baseline = modern_sse_request();
    let mut rejected = baseline.clone();
    // Planted forbidden dimension: only the response representation changes.
    rejected
        .headers
        .insert("accept".to_owned(), "application/xml".to_owned());

    let mut transport = StreamableHttpTransport::new();
    let responses = transport
        .response_stream()
        .expect("one public response stream can be externalized");
    let before_pending = responses.pending_responses();
    let before_bodies = responses
        .live_request_bodies()
        .expect("idle response registry is observable");

    assert!(matches!(
        handler.admit_modern_request(&rejected),
        Err(HttpError::NotAcceptable)
    ));
    assert_eq!(rejected.method, baseline.method);
    assert_eq!(rejected.path, baseline.path);
    assert_eq!(rejected.body, baseline.body);
    assert_eq!(responses.pending_responses(), before_pending);
    assert_eq!(
        responses
            .live_request_bodies()
            .expect("rejection cannot allocate a response body"),
        before_bodies
    );
    assert_eq!(
        handler
            .admit_modern_request(&baseline)
            .expect("the unchanged SSE baseline remains freshly admissible")
            .response_representation(),
        HttpResponseRepresentation::Sse
    );
}

#[test]
fn http_01_i_positive() {
    let mut transport = StreamableHttpTransport::new();
    let responses = transport
        .response_stream()
        .expect("the public HTTP response stream can be externalized once");
    let request_id = RequestId::Number(991);
    let response_body = responses
        .for_request(request_id.clone())
        .expect("one public response body is registered for the request");
    let cancellation = response_body.cancellation();
    let cx = Cx::for_testing();

    transport
        .send_response_for_request(
            &cx,
            &cancellation,
            JsonRpcResponse::success(
                request_id.clone(),
                serde_json::json!({"status": "integrated"}),
            ),
        )
        .expect("the request-bound final response is admitted");

    assert_eq!(
        response_body
            .recv_response(&cx)
            .expect("the public response body receives its own final response")
            .id,
        Some(request_id)
    );
    assert!(response_body.is_finished());
    assert!(cancellation.is_cancelled());
    assert_eq!(responses.pending_responses(), 0);
}

#[test]
fn http_01_i_planted_negative() {
    let mut transport = StreamableHttpTransport::new();
    let responses = transport
        .response_stream()
        .expect("the public HTTP response stream can be externalized once");
    let request_id = RequestId::Number(992);
    let response_body = responses
        .for_request(request_id.clone())
        .expect("one public response body is registered for the request");
    let cancellation = response_body.cancellation();
    let cx = Cx::for_testing();
    let pending_before = responses.pending_responses();

    // Planted forbidden dimension: disconnected body before commit
    drop(response_body);

    assert!(matches!(
        transport.send_response_for_request(
            &cx,
            &cancellation,
            JsonRpcResponse::success(request_id, serde_json::json!({"status": "integrated"})),
        ),
        Err(TransportError::Cancelled)
    ));
    assert_eq!(responses.pending_responses(), pending_before);
    assert!(!responses.is_closed());
}

#[test]
fn http_02_i_positive() {
    http_02_integration_positive();
}

#[test]
fn http_02_integration_positive() {
    let handler = modern_handler();
    let admission = handler
        .admit_modern_request(&modern_sse_request())
        .expect("the public modern HTTP boundary admits a matching 2026 request");
    assert_eq!(
        admission.response_representation(),
        HttpResponseRepresentation::Sse
    );

    let mut transport = StreamableHttpTransport::with_capacity(2)
        .expect("bounded response slot is valid public configuration");
    let responses = transport
        .response_stream()
        .expect("one public response stream can be externalized");

    let response_body = admission
        .bind_sse_response_body(&responses)
        .expect("admitted request receives an SSE response body");
    let cancellation = response_body.cancellation();
    let cx = Cx::for_testing();

    transport
        .send_response_for_request(
            &cx,
            &cancellation,
            JsonRpcResponse::success(
                RequestId::Number(901),
                serde_json::json!({"forecast": "sunny"}),
            ),
        )
        .expect("the request-owned SSE body admits terminal response");

    assert_eq!(
        response_body
            .recv_response(&cx)
            .expect("the SSE body consumes its own terminal response")
            .id,
        Some(RequestId::Number(901))
    );
    assert!(response_body.is_finished());
    assert!(cancellation.is_cancelled());
    assert_eq!(responses.pending_responses(), 0);
}

#[test]
fn http_02_i_planted_negative() {
    http_02_integration_planted_negative();
}

#[test]
fn http_02_integration_planted_negative() {
    let handler = modern_handler();
    let baseline = modern_sse_request();
    let mut rejected = baseline.clone();
    // Planted forbidden dimension: unsupported protocol version 2025-11-25
    rejected
        .headers
        .insert("mcp-protocol-version".to_owned(), "2025-11-25".to_owned());

    let mut transport = StreamableHttpTransport::new();
    let responses = transport
        .response_stream()
        .expect("one public response stream can be externalized");
    let before_pending = responses.pending_responses();

    let error = handler
        .admit_modern_request(&rejected)
        .expect_err("unsupported 2025-11-25 version must reject at protocol admission boundary");
    assert!(matches!(
        error,
        HttpError::ProtocolAdmission(RequestAdmissionError::HeaderMismatch(err))
            if err.reason() == HeaderMismatchReason::HeaderBodyVersionMismatch
    ));
    assert_eq!(rejected.method, baseline.method);
    assert_eq!(rejected.path, baseline.path);
    assert_eq!(responses.pending_responses(), before_pending);
}
