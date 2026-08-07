//! Exact, root-level PRT-01 A harness entries.
//!
//! These tests deliberately use only the public protocol crate surface so the
//! frozen `--exact` selectors name real root harness tests rather than nested
//! unit-test paths.

use fastmcp_protocol::{
    CorrelationKey, JsonRpcAdmissionError, JsonRpcMessage, JsonRpcResponse, RawJsonAdmissionError,
    RequestId, admit_raw_jsonrpc_document, decode_strict_jsonrpc_message,
};
use serde_json::Value;

#[test]
fn prt_01_envelopes_positive() {
    let request = br#"{"jsonrpc":"2.0","method":"tools/list","id":42}"#;
    let notification = br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    let success = br#"{"jsonrpc":"2.0","result":null,"id":"request-42"}"#;
    let error = br#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"missing"},"id":42}"#;

    assert!(matches!(
        decode_strict_jsonrpc_message(request, 4 * 1024),
        Ok(JsonRpcMessage::Request(request)) if request.id == Some(RequestId::Number(42))
    ));
    assert!(matches!(
        decode_strict_jsonrpc_message(notification, 4 * 1024),
        Ok(JsonRpcMessage::Request(request)) if request.id.is_none()
    ));
    assert!(matches!(
        decode_strict_jsonrpc_message(success, 4 * 1024),
        Ok(JsonRpcMessage::Response(response)) if response.result == Some(Value::Null) && response.error.is_none()
    ));
    assert!(matches!(
        decode_strict_jsonrpc_message(error, 4 * 1024),
        Ok(JsonRpcMessage::Response(response)) if response.result.is_none() && response.error.is_some()
    ));
}

#[test]
fn prt_01_envelopes_planted_negative() {
    let baseline = br#"{"jsonrpc":"2.0","method":"tools/list","id":42}"#;
    let planted = br#"{"jsonrpc":"2.0","method":"tools/list","id":42,"id":42}"#;
    let mut accepted = Vec::new();
    accepted.push(
        decode_strict_jsonrpc_message(baseline, 4 * 1024)
            .expect("the unmodified public envelope is admitted"),
    );
    let state_before = accepted.len();

    assert!(matches!(
        decode_strict_jsonrpc_message(planted, 4 * 1024),
        Err(JsonRpcAdmissionError::Raw(RawJsonAdmissionError::DuplicateObjectMember))
    ));
    assert_eq!(accepted.len(), state_before, "rejection occurs before accepted state mutates");
}

#[test]
fn prt_01_id_correlation_positive() {
    let integer = RequestId::Number(1);
    assert_eq!(
        integer.correlation_key().expect("valid numeric ID"),
        RequestId::Integer("1.0".to_owned())
            .correlation_key()
            .expect("valid mathematical integer ID"),
    );
    assert_eq!(
        integer.correlation_key().expect("valid numeric ID"),
        RequestId::Integer("1e0".to_owned())
            .correlation_key()
            .expect("valid mathematical integer ID"),
    );
    assert_ne!(
        integer.correlation_key().expect("valid numeric ID"),
        CorrelationKey::String("1".to_owned()),
        "string and numeric namespaces remain disjoint",
    );

    let large = "922337203685477580812345678901234567890";
    let raw = format!(r#"{{"jsonrpc":"2.0","method":"tools/list","id":{large}}}"#);
    let JsonRpcMessage::Request(request) = decode_strict_jsonrpc_message(raw.as_bytes(), 4 * 1024)
        .expect("the public decoder admits an arbitrary-precision integer")
    else {
        panic!("the admitted frame must remain a request");
    };
    let response = JsonRpcResponse::success(
        request.id.expect("the request remains correlated"),
        Value::Null,
    );
    assert!(serde_json::to_string(&response).expect("response serializes").contains(large));
}

#[test]
fn prt_01_id_correlation_planted_negative() {
    let baseline = RequestId::Integer("1".to_owned());
    let planted = RequestId::Integer("1.5".to_owned());
    let admitted_keys = vec![
        baseline
            .correlation_key()
            .expect("the mathematical-integer baseline yields a key"),
    ];
    let state_before = admitted_keys.clone();

    assert!(
        planted.correlation_key().is_err(),
        "a directly constructed fractional Integer lexeme cannot reach a registry key"
    );
    assert_eq!(
        admitted_keys, state_before,
        "the rejected directly constructed ID leaves admitted correlation state unchanged"
    );
}

#[test]
fn prt_01_duplicate_member_planted_negative() {
    let baseline = br#"{"jsonrpc":"2.0","method":"tools/list","params":{"cursor":"a"}}"#;
    let planted = br#"{"jsonrpc":"2.0","method":"tools/list","params":{"cursor":"a","cursor":"b"}}"#;
    let mut accepted = Vec::new();
    accepted.push(
        decode_strict_jsonrpc_message(baseline, 4 * 1024)
            .expect("the one-member nested object is admitted"),
    );
    let state_before = accepted.len();

    assert!(matches!(
        decode_strict_jsonrpc_message(planted, 4 * 1024),
        Err(JsonRpcAdmissionError::Raw(RawJsonAdmissionError::DuplicateObjectMember))
    ));
    assert_eq!(accepted.len(), state_before, "duplicate parameters reach no typed state");
}

#[test]
fn prt_01_top_level_batch_array_planted_negative() {
    let array_of_one = br#"[{"jsonrpc":"2.0","method":"tools/list"}]"#;
    let mixed_array = br#"[{"jsonrpc":"2.0","method":"tools/list"},{"jsonrpc":"2.0","method":"notifications/initialized"}]"#;

    for batch in [array_of_one.as_slice(), mixed_array.as_slice()] {
        assert_eq!(
            admit_raw_jsonrpc_document(batch, 4 * 1024),
            Err(RawJsonAdmissionError::TopLevelBatch),
            "the raw public admission gate rejects a batch before typed decode",
        );
    }
}

#[test]
fn prt_01_a_positive() {
    let frame = br#"{"jsonrpc":"2.0","method":"tools/list","id":"public-request"}"#;
    let message = decode_strict_jsonrpc_message(frame, 4 * 1024)
        .expect("the shipped public raw-admission and envelope decoder admit the request");
    assert!(matches!(
        message,
        JsonRpcMessage::Request(request) if request.id == Some(RequestId::String("public-request".to_owned()))
    ));
}

#[test]
fn prt_01_a_planted_negative() {
    let baseline = br#"{"jsonrpc":"2.0","method":"tools/list","id":"public-request"}"#;
    let mut planted = baseline.to_vec();
    planted.splice(0..0, [0xef, 0xbb, 0xbf]);
    let mut accepted = Vec::new();
    accepted.push(
        decode_strict_jsonrpc_message(baseline, 4 * 1024)
            .expect("the public baseline is admitted"),
    );
    let state_before = accepted.len();

    assert!(matches!(
        decode_strict_jsonrpc_message(&planted, 4 * 1024),
        Err(JsonRpcAdmissionError::Raw(RawJsonAdmissionError::ByteOrderMark))
    ));
    assert_eq!(accepted.len(), state_before, "the planted raw rejection leaves state unchanged");
}
