//! Security admission over the unconsumed native HTTP head, before body decode.
//! The existing H1 codec remains responsible for HTTP framing and body decoding.

use std::sync::Arc;

use asupersync::http::h1::Request;
use fastmcp_transport::http::HttpResponse;

use super::super::super::{CorsResponseHeaders, HttpSecurityError, HttpSecurityHead, HttpSecurityPolicy};
use crate::{BytesMut, Decoder, Encoder, Http1DecodeError, Http1Response, NativeHttp1Codec};

const MAX_REQUEST_LINE_BYTES: usize = 8192;

pub(super) enum Ingress {
    Request { request: Request, cors: CorsResponseHeaders },
    Immediate(HttpResponse),
}

pub(super) struct SecuredCodec {
    inner: NativeHttp1Codec,
    policy: Arc<HttpSecurityPolicy>,
    body_limit: usize,
    cors: Option<CorsResponseHeaders>,
    finished: bool,
}

impl SecuredCodec {
    pub(super) fn new(policy: Arc<HttpSecurityPolicy>, body_limit: usize) -> Self {
        let body_limit = body_limit.min(policy.endpoint().limits().max_body_bytes());
        Self { inner: NativeHttp1Codec::new(body_limit, None), policy, body_limit, cors: None, finished: false }
    }

    fn refusal(&mut self, error: HttpSecurityError, source: &mut BytesMut) -> Ingress {
        let mut response = error.response();
        if let Some(cors) = &self.cors { cors.apply_to(&mut response); }
        self.finished = true;
        source.clear();
        Ingress::Immediate(response)
    }

    fn head(&self, source: &[u8], end: usize) -> Result<HttpSecurityHead, HttpSecurityError> {
        let text = std::str::from_utf8(&source[..end]).map_err(|_| HttpSecurityError::InvalidHeader)?;
        let mut lines = text.split("\r\n");
        let line = lines.next().ok_or(HttpSecurityError::InvalidHeader)?;
        if line.len() > MAX_REQUEST_LINE_BYTES { return Err(HttpSecurityError::HeaderLimit); }
        let mut words = line.split(' ');
        let method = words.next().ok_or(HttpSecurityError::InvalidHeader)?;
        let target = words.next().ok_or(HttpSecurityError::InvalidHeader)?;
        let version = words.next().ok_or(HttpSecurityError::InvalidHeader)?;
        if words.next().is_some() || !matches!(version, "HTTP/1.1" | "HTTP/1.0")
            || !target.starts_with('/') || target.starts_with("//") || target.contains('#')
            || target.bytes().any(|byte| byte <= 32 || byte == 127)
        { return Err(HttpSecurityError::InvalidHeader); }
        let path = target.split_once('?').map_or(target, |(path, _)| path);
        if self.policy.is_metadata_path(path) && target != path {
            return Err(HttpSecurityError::EndpointMismatch);
        }
        let limits = self.policy.endpoint().limits();
        let mut headers = Vec::new();
        let mut bytes = 0_usize;
        for line in lines {
            if headers.len() >= limits.max_header_count() { return Err(HttpSecurityError::HeaderLimit); }
            let (name, value) = line.split_once(':').ok_or(HttpSecurityError::InvalidHeader)?;
            // Do not trim the name: whitespace before ':' and obs-fold are not
            // equivalent to an ordinary field. Keep all duplicate fields intact.
            let value = value.trim_matches([' ', '\t']);
            bytes = bytes.checked_add(name.len()).and_then(|n| n.checked_add(value.len()))
                .ok_or(HttpSecurityError::HeaderLimit)?;
            if bytes > limits.max_header_block_bytes() { return Err(HttpSecurityError::HeaderLimit); }
            headers.push((name.to_owned(), value.to_owned()));
        }
        let head = self.policy.admit_head(method, path, &headers)?;
        let length = headers.iter().find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value);
        let encodings = headers.iter().filter(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
            .collect::<Vec<_>>();
        if encodings.len() > 1 { return Err(HttpSecurityError::DuplicateHeader); }
        if length.is_some() && !encodings.is_empty() { return Err(HttpSecurityError::ContentLengthMismatch); }
        let length = length.map(|value| {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(HttpSecurityError::ContentLengthMismatch);
            }
            value.parse::<usize>().map_err(|_| HttpSecurityError::ContentLengthMismatch)
        }).transpose()?;
        if !matches!(&head, HttpSecurityHead::Post(_)) {
            // Preflight and public metadata GET are bodyless. Never wait for a
            // claimed body, and reject already-buffered pipelining. The response
            // closes this connection, so later request data cannot dispatch.
            if length.is_some_and(|length| length != 0) || !encodings.is_empty() || source.len() != end + 4 {
                return Err(HttpSecurityError::BodyNotAllowed);
            }
        } else if length.is_some_and(|length| length > self.body_limit) {
            return Err(HttpSecurityError::BodyTooLarge);
        }
        Ok(head)
    }
}

impl Decoder for SecuredCodec {
    type Item = Ingress;
    type Error = Http1DecodeError;

    fn decode(&mut self, source: &mut BytesMut) -> Result<Option<Ingress>, Http1DecodeError> {
        if self.finished { return Ok(None); }
        if self.cors.is_none() {
            let limits = self.policy.endpoint().limits();
            let maximum = limits.max_header_block_bytes()
                .saturating_add(limits.max_header_count().saturating_mul(4))
                .saturating_add(MAX_REQUEST_LINE_BYTES + 4);
            let end = source.windows(4).position(|window| window == b"\r\n\r\n");
            let Some(end) = end else {
                if source.len() > maximum {
                    return Ok(Some(self.refusal(HttpSecurityError::HeaderLimit, source)));
                }
                // Do not delegate until the complete head has been admitted:
                // the inner decoder is allowed to consume bytes incrementally.
                return Ok(None);
            };
            if end > maximum { return Ok(Some(self.refusal(HttpSecurityError::HeaderLimit, source))); }
            match self.head(source, end) {
                Err(error) => return Ok(Some(self.refusal(error, source))),
                Ok(HttpSecurityHead::Preflight(response) | HttpSecurityHead::Metadata(response)) => {
                    source.clear();
                    self.finished = true;
                    return Ok(Some(Ingress::Immediate(response)));
                }
                Ok(HttpSecurityHead::Post(cors)) => self.cors = Some(cors),
            }
        }
        match self.inner.decode(source) {
            Ok(Some(request)) => {
                self.finished = true;
                let cors = self.cors.take().expect("POST head admission precedes body decoding");
                Ok(Some(Ingress::Request { request, cors }))
            }
            Ok(None) => Ok(None),
            Err(_) => Ok(Some(self.refusal(HttpSecurityError::InvalidHeader, source))),
        }
    }
}

impl Encoder<Http1Response> for SecuredCodec {
    type Error = Http1DecodeError;
    fn encode(&mut self, response: Http1Response, destination: &mut BytesMut) -> Result<(), Self::Error> {
        self.inner.encode(response, destination)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_admission::{HttpAdmissionLimits, HttpEndpointConfig};

    fn codec() -> SecuredCodec {
        let policy = HttpSecurityPolicy::new(
            HttpEndpointConfig::new("/mcp", HttpAdmissionLimits::new(16, 2048, 64).unwrap()).unwrap(),
            "https://service.example", vec!["https://app.example".to_owned()],
        ).unwrap();
        SecuredCodec::new(Arc::new(policy), 64)
    }

    fn status(codec: &mut SecuredCodec, wire: &str) -> u16 {
        let mut source = BytesMut::from(wire.as_bytes());
        let Some(Ingress::Immediate(response)) = codec.decode(&mut source).unwrap() else {
            panic!("expected an immediate decision before body read")
        };
        assert!(codec.decode(&mut source).unwrap().is_none());
        response.status.0
    }

    #[test]
    fn denied_origin_and_host_reject_before_a_claimed_body_arrives() {
        for (host, origin) in [("service.example", "https://attacker.example"),
            ("attacker.example", "https://app.example")]
        {
            let wire = format!("POST /mcp HTTP/1.1\r\nHost: {host}\r\nOrigin: {origin}\r\nContent-Length: 64\r\n\r\n");
            assert_eq!(status(&mut codec(), &wire), 403);
        }
    }

    #[test]
    fn exact_method_and_duplicate_authority_are_checked_before_normalization() {
        assert_eq!(status(&mut codec(), "post /mcp HTTP/1.1\r\nHost: service.example\r\n\r\n"), 405);
        assert_eq!(status(&mut codec(), "POST /mcp HTTP/1.1\r\nHost: service.example\r\nhOsT: service.example\r\n\r\n"), 400);
        assert_eq!(status(&mut codec(), "POST /mcp HTTP/1.1\r\nHost : service.example\r\n\r\n"), 400);
    }

    #[test]
    fn oversized_and_ambiguous_framing_reject_without_waiting_for_body() {
        for framing in ["Content-Length: 65", "Content-Length: 2\r\nTransfer-Encoding: chunked",
            "Content-Length: +2", "Content-Length: 2, 2", "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked"]
        {
            let wire = format!("POST /mcp HTTP/1.1\r\nHost: service.example\r\n{framing}\r\n\r\n");
            let expected = if framing == "Content-Length: 65" { 413 } else { 400 };
            assert_eq!(status(&mut codec(), &wire), expected);
        }
    }

    #[test]
    fn valid_preflight_is_immediate_but_body_claims_are_not() {
        let prefix = "OPTIONS /mcp HTTP/1.1\r\nHost: service.example\r\nOrigin: https://app.example\r\nAccess-Control-Request-Method: POST\r\n";
        assert_eq!(status(&mut codec(), &format!("{prefix}\r\n")), 204);
        assert_eq!(status(&mut codec(), &format!("{prefix}Content-Length: 0\r\n\r\n")), 204);
        assert_eq!(status(&mut codec(), &format!("{prefix}Content-Length: 1\r\n\r\n")), 400);
        assert_eq!(status(&mut codec(), &format!("{prefix}\r\nx")), 400);
    }

    #[test]
    fn partial_head_cannot_be_consumed_before_security_admission() {
        let mut codec = codec();
        let mut source = BytesMut::from(&b"POST /mcp HTTP/1.1\r\nHost: service.example\r\nContent-Length: 2\r\n"[..]);
        let original = source.to_vec();
        assert!(codec.decode(&mut source).unwrap().is_none());
        assert_eq!(&source[..], &original);
        source.extend_from_slice(b"\r\n{}");
        let Some(Ingress::Request { request, cors }) = codec.decode(&mut source).unwrap() else {
            panic!("native H1 parser must finish the admitted request")
        };
        assert_eq!(request.body, b"{}");
        assert_eq!(cors.allowed_origin(), None);
    }

    #[test]
    fn query_and_header_cardinality_survive_native_body_decode() {
        let mut codec = codec();
        let mut source = BytesMut::from(&b"POST /mcp?access_token=x HTTP/1.1\r\nHost: service.example\r\nAccept: application/json\r\nAccept: text/event-stream\r\nContent-Length: 2\r\n\r\n{}"[..]);
        let Some(Ingress::Request { request, .. }) = codec.decode(&mut source).unwrap() else {
            panic!("HTTP framing should not interpret the later credential policy")
        };
        assert_eq!(request.uri, "/mcp?access_token=x");
        assert_eq!(request.headers.iter().filter(|(name, _)| name.eq_ignore_ascii_case("accept")).count(), 2);
    }

    #[test]
    fn unfinished_headers_and_extra_pipeline_bytes_are_bounded() {
        let mut codec = codec();
        let mut source = BytesMut::from("X".repeat(12_000).as_bytes());
        assert!(matches!(codec.decode(&mut source).unwrap(), Some(Ingress::Immediate(_))));
        let mut codec = self::codec();
        let mut source = BytesMut::from(&b"POST /mcp HTTP/1.1\r\nHost: service.example\r\nContent-Length: 2\r\n\r\n{}NEXT"[..]);
        assert!(matches!(codec.decode(&mut source).unwrap(), Some(Ingress::Request { .. })));
        assert!(!source.is_empty(), "connection owner must reject buffered pipelining before dispatch");
    }

    fn metadata_codec() -> SecuredCodec {
        use crate::http_admission::security::resource_metadata::ProtectedResourceMetadata;
        let policy = (*codec().policy).clone().with_resource_metadata(ProtectedResourceMetadata::new(
            vec!["https://issuer.example".to_owned()],
        ).unwrap()).unwrap();
        SecuredCodec::new(Arc::new(policy), 64)
    }
    const METADATA_HEAD: &str = "GET /.well-known/oauth-protected-resource/mcp HTTP/1.1\r\nHost: service.example\r\n";

    #[test]
    fn native_metadata_waits_for_admitted_headers_but_never_for_authentication() {
        let mut codec = metadata_codec();
        let mut source = BytesMut::from(METADATA_HEAD.as_bytes());
        let before = source.to_vec();
        assert!(codec.decode(&mut source).unwrap().is_none());
        assert_eq!(source.as_ref(), before.as_slice());
        source.extend_from_slice(b"\r\n");
        let Some(Ingress::Immediate(response)) = codec.decode(&mut source).unwrap()
            else { panic!("metadata must complete before a request is dispatched") };
        assert_eq!(response.status.0, 200);
        let result: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(result["resource"], "https://service.example/mcp");
        assert_eq!(result["authorization_servers"], serde_json::json!(["https://issuer.example"]));
        assert!(codec.decode(&mut source).unwrap().is_none());
    }

    #[test]
    fn native_metadata_rejects_body_claims_pipelining_and_query_aliases() {
        for tail in ["Content-Length: 1\r\n\r\n", "Transfer-Encoding: chunked\r\n\r\n", "\r\nx"] {
            assert_eq!(status(&mut metadata_codec(), &format!("{METADATA_HEAD}{tail}")), 400);
        }
        assert_eq!(status(&mut metadata_codec(), &format!("{METADATA_HEAD}Content-Length: 0\r\n\r\n")), 200);
        let query = METADATA_HEAD.replace("/mcp HTTP", "/mcp?resource=other HTTP");
        assert_eq!(status(&mut metadata_codec(), &format!("{query}\r\n")), 404);
        assert_eq!(status(&mut metadata_codec(), &format!("{}\r\n", METADATA_HEAD.replacen("GET", "get", 1))), 405);
        assert_eq!(status(&mut codec(), &format!("{METADATA_HEAD}\r\n")), 404);
    }

    #[test]
    fn native_metadata_keeps_origin_and_duplicate_host_rejections_before_dispatch() {
        assert_eq!(status(&mut metadata_codec(), &format!("{METADATA_HEAD}Origin: https://attacker.example\r\n\r\n")), 403);
        assert_eq!(status(&mut metadata_codec(), &format!("{METADATA_HEAD}hOsT: service.example\r\n\r\n")), 400);
        let wire = METADATA_HEAD.replace("Host: service.example", "Host: attacker.example\r\nForwarded: host=service.example;proto=https");
        assert_eq!(status(&mut metadata_codec(), &format!("{wire}\r\n")), 403);
    }

    #[test]
    fn native_mcp_receipt_adds_metadata_to_authentication_errors_only() {
        let mut codec = metadata_codec();
        let mut source = BytesMut::from(&b"POST /mcp HTTP/1.1\r\nHost: service.example\r\nContent-Length: 2\r\n\r\n{}"[..]);
        let Some(Ingress::Request { cors, .. }) = codec.decode(&mut source).unwrap()
            else { panic!("MCP POST still requires downstream protocol/auth admission") };
        let mut response = HttpResponse::new(fastmcp_transport::http::HttpStatus(401)).with_header("www-authenticate", "Bearer");
        cors.apply_to(&mut response);
        assert_eq!(response.headers["www-authenticate"], "Bearer resource_metadata=\"https://service.example/.well-known/oauth-protected-resource/mcp\"");
        let mut success = HttpResponse::ok();
        cors.apply_to(&mut success);
        assert!(!success.headers.contains_key("www-authenticate"));
    }
}
