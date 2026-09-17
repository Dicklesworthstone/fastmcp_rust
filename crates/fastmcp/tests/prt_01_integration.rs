//! PRT-01 integration: strict admission enforced through the shipped codecs
//! and consumers.
//!
//! This joins the two PRT-01 implementation children through the published
//! facade rather than re-deriving either of them:
//!
//! - `bd-mcp-2026-07-28-support-ahet.5.1` — envelopes, IDs, endpoint roles, and
//!   the reusable bounded raw-JSON admission primitive.
//! - `bd-mcp-2026-07-28-support-ahet.5.2` — security-document, compact-JWS, and
//!   JWK admission reusing that same primitive.
//!
//! Every assertion runs through `fastmcp_rust` (the shipped facade) or the
//! published `fastmcp_protocol` surface. Nothing here re-implements admission,
//! and no test-local validator stands in for production code.
//!
//! PRT-01 owns the endpoint role/direction disposition matrix with synthetic
//! labels by design: the canonical package contract assigns the real transport
//! and proxy-leg fixtures to HTTP-02/03, STD-01, XPORT-01, and PXY-01 "rather
//! than creating a dependency back from PRT-01".

use fastmcp_protocol::{
    CompactJwsProfile, JwkAdmissionPolicy, RawJsonTopLevel, SecurityDocumentKind,
    admit_compact_jws, admit_public_jwk_set, admit_raw_json_document, admit_security_document,
};
use fastmcp_rust::{
    ClientIngressFailureScope, Codec, JsonRpcAdmissionError, JsonRpcEndpointRole, JsonRpcMessage,
    JsonRpcMessageDirection, JsonRpcRequest, JsonRpcResponse, RawJsonAdmissionError,
    RawJsonRpcDisposition, RequestId, admit_raw_jsonrpc_document, decode_strict_jsonrpc_message,
    dispose_raw_jsonrpc_failure,
};
use serde_json::Value;

/// The document bound handed to every protocol-level ingress class.
const LIMIT: usize = 64 * 1024;

/// RFC 7638 Section 3.1 public modulus, used for the security-document leg.
const RFC7638_MODULUS: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
/// RFC 7638 Section 3.1 thumbprint of that key.
const RFC7638_THUMBPRINT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

/// Every shipped raw-ingress class PRT-01 governs, with its verdict for one
/// frame.
///
/// A class reports `true` when it refused the frame before producing any typed
/// message. The classes deliberately span all three layers the integration
/// bead names: the protocol primitives, the server's request ingress, and the
/// transport codec in both its complete-frame form (HTTP per-response, SSE,
/// WebSocket) and its stdio line-framed form.
fn ingress_verdicts(frame: &[u8]) -> Vec<(&'static str, bool)> {
    let codec = Codec::new();
    let mut streaming = Codec::new();
    let mut line_framed = frame.to_vec();
    line_framed.push(b'\n');

    vec![
        (
            "protocol raw admission",
            admit_raw_jsonrpc_document(frame, LIMIT).is_err(),
        ),
        (
            "protocol strict envelope decode",
            decode_strict_jsonrpc_message(frame, LIMIT).is_err(),
        ),
        (
            "server request ingress (raw params sidecar)",
            JsonRpcRequest::decode_strict_with_raw_params(frame, LIMIT).is_err(),
        ),
        (
            "transport complete frame (HTTP per-response, SSE, WebSocket)",
            codec.decode_complete_message(frame).is_err(),
        ),
        (
            "transport complete request",
            codec.decode_complete_request(frame).is_err(),
        ),
        (
            "transport stdio line framing",
            streaming.decode(&line_framed).is_err(),
        ),
        (
            "security-document consumer",
            admit_security_document(SecurityDocumentKind::TokenResponse, frame).is_err(),
        ),
    ]
}

/// The endpoint role/direction/scope matrix PRT-01 must dispose identically at
/// every transport, named by the leg each label stands for.
fn role_matrix() -> Vec<(
    &'static str,
    JsonRpcEndpointRole,
    JsonRpcMessageDirection,
    ClientIngressFailureScope,
)> {
    vec![
        (
            "stdio server ingress",
            JsonRpcEndpointRole::ServerIngress,
            JsonRpcMessageDirection::ClientToServer,
            ClientIngressFailureScope::SharedChannel,
        ),
        (
            "HTTP per-response client ingress",
            JsonRpcEndpointRole::ClientIngress,
            JsonRpcMessageDirection::ServerToClient,
            ClientIngressFailureScope::OwningExchange,
        ),
        (
            "memory/custom shared-channel client ingress",
            JsonRpcEndpointRole::ClientIngress,
            JsonRpcMessageDirection::ServerToClient,
            ClientIngressFailureScope::SharedChannel,
        ),
        (
            "proxy downstream leg, server role",
            JsonRpcEndpointRole::ServerIngress,
            JsonRpcMessageDirection::ClientToServer,
            ClientIngressFailureScope::OwningExchange,
        ),
        (
            "proxy upstream leg, client role",
            JsonRpcEndpointRole::ClientIngress,
            JsonRpcMessageDirection::ServerToClient,
            ClientIngressFailureScope::OwningExchange,
        ),
    ]
}

#[test]
fn prt_01_integration_positive() {
    // The shipped transport codec round-trips a request through the same
    // admission the protocol layer owns, preserving the exact ID lexeme.
    let codec = Codec::new();
    let large_id = "922337203685477580812345678901234567890";
    let request = JsonRpcRequest::new(
        "tools/list",
        Some(serde_json::json!({"cursor": "page-2"})),
        RequestId::Integer(large_id.to_owned()),
    );
    let encoded = codec.encode_request(&request).expect("the codec encodes");
    assert!(
        String::from_utf8_lossy(&encoded).contains(large_id),
        "the encoded frame carries the arbitrary-precision id lexeme exactly",
    );
    let frame = encoded.strip_suffix(b"\n").unwrap_or(&encoded).to_vec();

    let JsonRpcMessage::Request(decoded) = codec
        .decode_complete_message(&frame)
        .expect("the shipped codec admits and decodes its own frame")
    else {
        panic!("a request frame must decode as a request");
    };
    assert_eq!(decoded.id, Some(RequestId::Integer(large_id.to_owned())));
    assert_eq!(decoded.method, "tools/list");

    // The server's own request ingress retains the exact params source beside
    // the typed value, and both agree.
    let (ingress, raw_params) = JsonRpcRequest::decode_strict_with_raw_params(&frame, LIMIT)
        .expect("the shipped server ingress admits the same frame");
    assert_eq!(ingress.id, decoded.id);
    let raw_params = raw_params.expect("params were present on the wire");
    assert_eq!(
        serde_json::from_str::<Value>(&raw_params).expect("the sidecar is valid JSON"),
        ingress.params.clone().expect("typed params are present"),
        "the exact source and the typed value describe one document",
    );

    // Stdio line framing admits two complete frames in one read.
    let mut streaming = Codec::new();
    let mut stream = codec.encode_request(&request).expect("encodes");
    if !stream.ends_with(b"\n") {
        stream.push(b'\n');
    }
    let mut second = codec
        .encode_response(&JsonRpcResponse::success(
            RequestId::Integer(large_id.to_owned()),
            Value::Null,
        ))
        .expect("encodes");
    if !second.ends_with(b"\n") {
        second.push(b'\n');
    }
    stream.extend_from_slice(&second);
    let messages = streaming
        .decode(&stream)
        .expect("stdio line framing admits both frames");
    assert_eq!(messages.len(), 2, "both complete frames are delivered");

    // Every ingress class admits the same well-formed frame. This is the
    // positive half of the shared-semantics claim: the classes agree on
    // acceptance, not only on refusal.
    for (class, refused) in ingress_verdicts(&frame) {
        assert!(
            !refused,
            "{class} must admit a well-formed single-object JSON-RPC frame",
        );
    }

    // At least one shipped security-document consumer observes the identical
    // bounded pass, then produces its own typed result.
    let key_set = format!(
        r#"{{"keys":[{{"kty":"RSA","n":"{RFC7638_MODULUS}","e":"AQAB","alg":"RS256","use":"sig","kid":"2011-04-29"}}]}}"#
    );
    assert!(
        admit_security_document(SecurityDocumentKind::JsonWebKeySet, key_set.as_bytes()).is_ok(),
        "the JWKS reaches the same bounded admission the envelope slice uses",
    );
    let keys = admit_public_jwk_set(JwkAdmissionPolicy::default(), key_set.as_bytes())
        .expect("the shipped JWK policy admits the public key");
    assert_eq!(
        keys[0]
            .thumbprint_sha256()
            .expect("the thumbprint is computable")
            .to_base64url(),
        RFC7638_THUMBPRINT,
    );

    // A compact JWS naming that key is admitted under exactly one closed
    // profile, completing the protocol -> transport -> security-consumer pass.
    let token = format!(
        "{}.{}.{}",
        base64url(br#"{"alg":"RS256","typ":"at+jwt","kid":"2011-04-29"}"#),
        base64url(
            br#"{"iss":"https://as.example","sub":"user-1","aud":"https://rs.example","exp":1700000000,"iat":1699999000,"jti":"a-1","scope":"read"}"#
        ),
        base64url(b"unverified-signature"),
    );
    let admitted = admit_compact_jws(CompactJwsProfile::Rfc9068AccessToken, &token)
        .expect("the shipped compact-JWS admission accepts the access token");
    assert_eq!(admitted.header().key_id(), keys[0].key_id());
}

#[test]
fn prt_01_integration_planted_negative() {
    // A top-level batch is refused at every raw ingress class, and never
    // reaches dispatch, correlation, or a response.
    let array_of_one = br#"[{"jsonrpc":"2.0","method":"tools/list","id":1}]"#;
    let mixed_array = br#"[{"jsonrpc":"2.0","method":"tools/list","id":1},{"jsonrpc":"2.0","method":"notifications/initialized"}]"#;

    for batch in [array_of_one.as_slice(), mixed_array.as_slice()] {
        for (class, refused) in ingress_verdicts(batch) {
            assert!(refused, "{class} must refuse a top-level batch array");
        }
        // The protocol names the refusal deliberately rather than treating it
        // as generic bad syntax.
        assert_eq!(
            admit_raw_jsonrpc_document(batch, LIMIT),
            Err(RawJsonAdmissionError::TopLevelBatch),
        );
        assert!(
            matches!(
                decode_strict_jsonrpc_message(batch, LIMIT),
                Err(JsonRpcAdmissionError::Raw(
                    RawJsonAdmissionError::TopLevelBatch
                ))
            ),
            "the strict envelope decoder names the batch refusal",
        );

        // No partial effect: feeding the batch followed by a valid frame in one
        // stdio read yields an error and zero messages, and the codec surfaces
        // no request id, so nothing could have entered a correlation registry.
        let mut streaming = Codec::new();
        let mut stream = batch.to_vec();
        stream.push(b'\n');
        stream.extend_from_slice(br#"{"jsonrpc":"2.0","method":"tools/list","id":2}"#);
        stream.push(b'\n');
        let error = streaming
            .decode(&stream)
            .expect_err("the batch fails the whole read");
        assert!(
            error.request_id().is_none(),
            "a refused batch yields no correlation id",
        );

        // And a fresh reader still admits the valid frame, so the refusal
        // poisoned no shared decoding state.
        let mut recovered = Codec::new();
        assert_eq!(
            recovered
                .decode(br#"{"jsonrpc":"2.0","method":"tools/list","id":2}"#.as_slice())
                .expect("a well-formed frame still decodes")
                .len(),
            0,
            "a frame without its newline terminator is buffered, not delivered",
        );
        assert_eq!(
            recovered
                .decode(b"\n")
                .expect("terminating the frame delivers it")
                .len(),
            1,
        );
    }

    // Bypassed raw admission is observably weaker than the shipped path. Plain
    // serde accepts a nested duplicate member with last-member-wins; every
    // shipped ingress class refuses the identical bytes. This is the concrete
    // difference the integration exists to enforce.
    let duplicated =
        br#"{"jsonrpc":"2.0","method":"tools/list","params":{"cursor":"a","cursor":"b"},"id":1}"#;
    let bypassed: JsonRpcRequest = serde_json::from_slice(duplicated)
        .expect("typed serde decoding alone accepts the duplicate member");
    assert_eq!(
        bypassed
            .params
            .as_ref()
            .and_then(|params| params.get("cursor")),
        Some(&Value::String("b".to_owned())),
        "bypassing admission silently resolves the duplicate to the last member",
    );
    for (class, refused) in ingress_verdicts(duplicated) {
        assert!(
            refused,
            "{class} must refuse what bypassed typed decoding would have accepted",
        );
    }

    // Two typed consumers cannot disagree about one document: the envelope
    // path and the security-document path refuse it for the same named reason.
    assert!(
        matches!(
            decode_strict_jsonrpc_message(duplicated, LIMIT),
            Err(JsonRpcAdmissionError::Raw(
                RawJsonAdmissionError::DuplicateObjectMember
            ))
        ),
        "the strict envelope decoder names the duplicate-member refusal",
    );
    let as_security = admit_security_document(SecurityDocumentKind::TokenResponse, duplicated)
        .expect_err("the security-document consumer refuses the same document");
    assert_eq!(
        as_security.error(),
        RawJsonAdmissionError::DuplicateObjectMember,
    );
    assert_eq!(
        as_security.path(),
        "/params/cursor",
        "and locates it identically, with the rest redacted",
    );

    // Role/direction swap over identical malformed bytes: only server ingress
    // on client-to-server traffic may emit a wire response, and no client leg
    // ever does.
    for (leg, role, direction, scope) in role_matrix() {
        let disposition =
            dispose_raw_jsonrpc_failure(role, direction, Some(RequestId::Number(7)), scope);
        match role {
            JsonRpcEndpointRole::ServerIngress => {
                assert!(
                    matches!(disposition, RawJsonRpcDisposition::CorrelatedError(_)),
                    "{leg} echoes the one readable request id",
                );
            }
            JsonRpcEndpointRole::ClientIngress => {
                assert!(
                    matches!(
                        disposition,
                        RawJsonRpcDisposition::ClientOwningFailure
                            | RawJsonRpcDisposition::ClientSharedChannelFailure
                    ),
                    "{leg} must produce no outbound wire action",
                );
            }
        }
        // A reversed direction on the same leg is not an ingress path at all,
        // so no reverse request or response loop can escape.
        let reversed = match direction {
            JsonRpcMessageDirection::ClientToServer => JsonRpcMessageDirection::ServerToClient,
            JsonRpcMessageDirection::ServerToClient => JsonRpcMessageDirection::ClientToServer,
        };
        assert_eq!(
            dispose_raw_jsonrpc_failure(role, reversed, Some(RequestId::Number(7)), scope),
            RawJsonRpcDisposition::NoAction,
            "{leg} must not leak a reverse-direction response",
        );
    }
}

#[test]
fn prt_01_i_positive() {
    // The joined slice, observed through the shipped facade in one pass: a
    // frame the transport codec admits is admitted identically by the protocol
    // primitive and by the security-document consumer, and the two children's
    // distinguishing behaviour is both present.
    let frame = br#"{"jsonrpc":"2.0","method":"tools/list","params":{"cursor":"a"},"id":"join"}"#;
    let codec = Codec::new();
    assert!(codec.decode_complete_message(frame).is_ok());
    assert!(admit_raw_jsonrpc_document(frame, LIMIT).is_ok());
    assert!(admit_security_document(SecurityDocumentKind::TokenResponse, frame).is_ok());

    // ahet.5.1 is present and current: the reusable primitive is role-neutral,
    // so the same bytes carry a JSON-RPC policy and a security-document policy
    // that differ only where they must.
    assert!(admit_raw_json_document(frame, LIMIT, RawJsonTopLevel::JsonRpcObject).is_ok());
    assert!(admit_raw_json_document(frame, LIMIT, RawJsonTopLevel::SecurityDocumentObject).is_ok());
    assert_eq!(
        admit_raw_json_document(br#"[{"a":1}]"#, LIMIT, RawJsonTopLevel::JsonRpcObject)
            .expect_err("a JSON-RPC batch is named as such")
            .error(),
        RawJsonAdmissionError::TopLevelBatch,
    );
    assert_eq!(
        admit_raw_json_document(
            br#"[{"a":1}]"#,
            LIMIT,
            RawJsonTopLevel::SecurityDocumentObject
        )
        .expect_err("a security document has no batch concept")
        .error(),
        RawJsonAdmissionError::TopLevelNotObject,
    );

    // ahet.5.2 is present and current: the closed JWS profile set and the RFC
    // 7638 thumbprint both resolve through the published surface.
    let key_set = format!(
        r#"{{"keys":[{{"kty":"RSA","n":"{RFC7638_MODULUS}","e":"AQAB","kid":"2011-04-29"}}]}}"#
    );
    let keys = admit_public_jwk_set(JwkAdmissionPolicy::default(), key_set.as_bytes())
        .expect("the published JWK policy admits the key");
    assert_eq!(
        keys[0]
            .thumbprint_sha256()
            .expect("computable")
            .to_base64url(),
        RFC7638_THUMBPRINT,
    );
    assert_eq!(CompactJwsProfile::all().len(), 5);
}

#[test]
fn prt_01_i_planted_negative() {
    // One variable changes against the admitted join frame: a duplicate
    // member. Every layer of the join refuses it, and the refusal is located
    // identically by both children.
    let admitted =
        br#"{"jsonrpc":"2.0","method":"tools/list","params":{"cursor":"a"},"id":"join"}"#;
    let planted =
        br#"{"jsonrpc":"2.0","method":"tools/list","params":{"cursor":"a","cursor":"b"},"id":"join"}"#;

    let codec = Codec::new();
    assert!(
        codec.decode_complete_message(admitted).is_ok(),
        "the unmodified join frame is admitted",
    );
    assert!(codec.decode_complete_message(planted).is_err());
    assert!(admit_raw_jsonrpc_document(planted, LIMIT).is_err());
    assert!(admit_security_document(SecurityDocumentKind::TokenResponse, planted).is_err());

    let envelope_failure = admit_raw_json_document(planted, LIMIT, RawJsonTopLevel::JsonRpcObject)
        .expect_err("the envelope policy refuses it");
    let security_failure =
        admit_raw_json_document(planted, LIMIT, RawJsonTopLevel::SecurityDocumentObject)
            .expect_err("the security-document policy refuses it");
    assert_eq!(
        envelope_failure, security_failure,
        "both children report one verdict and one redacted path for one document",
    );
    assert_eq!(
        envelope_failure.error(),
        RawJsonAdmissionError::DuplicateObjectMember,
    );
    assert_eq!(envelope_failure.path(), "/params/cursor");

    // Only the selected profile changes: bytes minted as an RFC 9068 access
    // token are not admissible as an OIDC ID token.
    let token = format!(
        "{}.{}.{}",
        base64url(br#"{"alg":"RS256","typ":"at+jwt"}"#),
        base64url(
            br#"{"iss":"https://as.example","sub":"user-1","aud":"https://rs.example","exp":1700000000,"iat":1699999000,"jti":"a-1"}"#
        ),
        base64url(b"unverified-signature"),
    );
    assert!(admit_compact_jws(CompactJwsProfile::Rfc9068AccessToken, &token).is_ok());
    assert!(admit_compact_jws(CompactJwsProfile::OidcIdToken, &token).is_err());

    // Nothing above disturbed the admitted join frame.
    assert!(codec.decode_complete_message(admitted).is_ok());
    assert!(admit_raw_jsonrpc_document(admitted, LIMIT).is_ok());
}

/// Canonical unpadded base64url, matching what the admission layer requires.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;
        let encoded = [
            ALPHABET[((triple >> 18) & 0x3f) as usize],
            ALPHABET[((triple >> 12) & 0x3f) as usize],
            ALPHABET[((triple >> 6) & 0x3f) as usize],
            ALPHABET[(triple & 0x3f) as usize],
        ];
        let keep = chunk.len() + 1;
        for byte in &encoded[..keep] {
            out.push(char::from(*byte));
        }
    }
    out
}
