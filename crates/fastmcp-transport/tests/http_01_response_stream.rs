use asupersync::Cx;
use fastmcp_protocol::{JsonRpcResponse, RequestId};
use fastmcp_transport::{
    TransportError,
    http::{StreamableHttpTransport},
};

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
    let mut transport = StreamableHttpTransport::with_capacity(1)
        .expect("a one-entry bounded transport is valid");
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
    let mut transport = StreamableHttpTransport::with_capacity(1)
        .expect("a one-entry bounded transport is valid");
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
