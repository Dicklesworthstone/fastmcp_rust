//! Frozen top-level PRT-03 acceptance entries.
//!
//! These functions deliberately live in an integration-test crate so the
//! unqualified frozen `--exact` selectors name executable harness entries.

use fastmcp_protocol::protocol_version::{
    FINAL_PROTOCOL_VERSION, FinalHttpRequestMetadata, HEADER_MISMATCH_ERROR_CODE,
    HeaderMismatchReason, MCP_PROTOCOL_VERSION_HEADER,
    MISSING_REQUIRED_CLIENT_CAPABILITY_ERROR_CODE, MissingRequiredClientCapabilityError,
    RequestAdmissionError, RequestVersionMetadata, admit_final_http_request, admit_final_request,
};
use serde_json::json;

#[test]
fn prt_03_a_positive() {
    let admission = admit_final_http_request(FinalHttpRequestMetadata {
        version: RequestVersionMetadata {
            header_version: Some(FINAL_PROTOCOL_VERSION),
            body_version: Some(FINAL_PROTOCOL_VERSION),
        },
        header_method: Some("tools/call"),
        body_method: Some("tools/call"),
        header_name: Some("weather"),
        body_name: Some("weather"),
    })
    .expect("matching final protocol, method, and name mirrors must be admitted");

    assert_eq!(MCP_PROTOCOL_VERSION_HEADER, "MCP-Protocol-Version");
    assert_eq!(
        admission.protocol_version().as_str(),
        FINAL_PROTOCOL_VERSION
    );
}

#[test]
fn prt_03_a_planted_negative() {
    let body_name = Some("weather");
    let error = admit_final_http_request(FinalHttpRequestMetadata {
        version: RequestVersionMetadata {
            header_version: Some(FINAL_PROTOCOL_VERSION),
            body_version: Some(FINAL_PROTOCOL_VERSION),
        },
        header_method: Some("tools/call"),
        body_method: Some("tools/call"),
        header_name: Some("other-weather"),
        body_name,
    })
    .expect_err("changing only the name header must reject the request");

    let RequestAdmissionError::HeaderMismatch(header_error) = error else {
        panic!("a name-mirror mismatch must not be classified as unsupported version");
    };
    assert_eq!(
        header_error.reason(),
        HeaderMismatchReason::HeaderBodyNameMismatch
    );
    assert_eq!(header_error.http_status(), 400);
    assert_eq!(
        header_error.jsonrpc_error_code(),
        HEADER_MISMATCH_ERROR_CODE
    );
    assert_eq!(header_error.canonical_error_data(), None);
    assert_eq!(body_name, Some("weather"));
}

#[test]
fn prt_03_b_positive() {
    let admission = admit_final_request(RequestVersionMetadata {
        header_version: Some(FINAL_PROTOCOL_VERSION),
        body_version: Some(FINAL_PROTOCOL_VERSION),
    })
    .expect("a matching supported protocol mirror must be admitted");
    let required_capabilities = json!({"roots": {"listChanged": true}});
    let missing_capability = MissingRequiredClientCapabilityError::new(required_capabilities)
        .expect("a bounded required-capabilities object must remain typed peer data");

    assert_eq!(
        admission.protocol_version().as_str(),
        FINAL_PROTOCOL_VERSION
    );
    assert_eq!(missing_capability.http_status(), 400);
    assert_eq!(
        missing_capability.jsonrpc_error_code(),
        MISSING_REQUIRED_CLIENT_CAPABILITY_ERROR_CODE
    );
    assert_eq!(
        missing_capability.canonical_error_data(),
        json!({"requiredCapabilities": {"roots": {"listChanged": true}}})
    );
}

#[test]
fn prt_03_b_planted_negative() {
    let body_version = Some(FINAL_PROTOCOL_VERSION);
    let error = admit_final_request(RequestVersionMetadata {
        header_version: Some("2025-11-25"),
        body_version,
    })
    .expect_err("changing only the version header must reject at the mirror boundary");

    let RequestAdmissionError::HeaderMismatch(header_error) = error else {
        panic!("a mismatched mirror must precede unsupported-version classification");
    };
    assert_eq!(
        header_error.reason(),
        HeaderMismatchReason::HeaderBodyVersionMismatch
    );
    assert_eq!(header_error.http_status(), 400);
    assert_eq!(
        header_error.jsonrpc_error_code(),
        HEADER_MISMATCH_ERROR_CODE
    );
    assert_eq!(header_error.canonical_error_data(), None);
    assert_eq!(body_version, Some(FINAL_PROTOCOL_VERSION));
}
