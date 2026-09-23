//! Real TLS fixture matching the existing public OAuth core-call tests.
//! Keys and certificates below are TEST ONLY; trust is isolated in a child.

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsStream};
use fastmcp_client::http_auth::oauth::{OAuthClient, OAuthClientConfiguration, OAuthError};
use fastmcp_core::CanonicalHttpUrl;
use serde_json::{Value, json};

pub const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

pub async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let mut one = None;
    let mut two = None;
    poll_fn(|cx| {
        if one.is_none() && let Poll::Ready(value) = left.as_mut().poll(cx) { one = Some(value); }
        if two.is_none() && let Poll::Ready(value) = right.as_mut().poll(cx) { two = Some(value); }
        if one.is_some() && two.is_some() {
            Poll::Ready((one.take().unwrap(), two.take().unwrap()))
        } else { Poll::Pending }
    }).await
}

fn url(value: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(value).unwrap() }

fn decode_component(value: &str) -> String {
    let mut decoded = Vec::new();
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        decoded.push(match byte {
            b'+' => b' ',
            b'%' => {
                let high = char::from(bytes.next().unwrap()).to_digit(16).unwrap();
                let low = char::from(bytes.next().unwrap()).to_digit(16).unwrap();
                (high * 16 + low) as u8
            }
            byte => byte,
        });
    }
    String::from_utf8(decoded).unwrap()
}

fn form(value: &str) -> BTreeMap<String, String> {
    value.split('&').map(|field| {
        let (key, value) = field.split_once('=').unwrap();
        (decode_component(key), decode_component(value))
    }).collect()
}

pub async fn browser(authorization: CanonicalHttpUrl) -> Result<(), OAuthError> {
    let params = form(authorization.query().unwrap());
    assert_eq!(params["client_id"], "typed-client");
    assert_eq!(params["code_challenge_method"], "S256");
    let address: SocketAddr = params["redirect_uri"].strip_prefix("http://").unwrap()
        .split('/').next().unwrap().parse().unwrap();
    assert!(address.ip().is_loopback());
    let request = format!("GET /oauth/callback?code=typed-code&iss=https%3A%2F%2Fissuer.example&state={} HTTP/1.1\r\nHost: {address}\r\n\r\n", params["state"]);
    let mut socket = TcpStream::connect(address).await.map_err(|_| OAuthError::CallbackRejected)?;
    socket.write_all(request.as_bytes()).await.map_err(|_| OAuthError::CallbackRejected)
}

pub struct Peer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    pub token_posts: AtomicUsize,
    pub mcp_posts: AtomicUsize,
}

impl Peer {
    pub async fn new() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            acceptor: TlsAcceptorBuilder::new(CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap())
                .alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap(),
            token_posts: AtomicUsize::new(0), mcp_posts: AtomicUsize::new(0),
        }
    }
    fn resource(&self) -> String { format!("https://{}/mcp", self.listener.local_addr().unwrap()) }
    pub fn client(&self) -> OAuthClient {
        OAuthClient::new(OAuthClientConfiguration::from_trusted_endpoints(
            "https://issuer.example", url("https://issuer.example/authorize"),
            url(&format!("https://{}/token", self.listener.local_addr().unwrap())),
            url(&self.resource()), "typed-client", vec!["tools:read".to_owned()],
        ).unwrap().with_extra_root_certificate(Certificate::from_pem(ROOT).unwrap().remove(0)).unwrap())
    }
    async fn request(&self, path: &str) -> (TlsStream<TcpStream>, Vec<u8>) {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut tls = self.acceptor.accept(socket).await.unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0; 2048];
        let end = loop {
            let count = tls.read(&mut buffer).await.unwrap();
            assert!(count > 0 && bytes.len() + count <= 16 * 1024);
            bytes.extend_from_slice(&buffer[..count]);
            if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") { break index + 4; }
        };
        let head = std::str::from_utf8(&bytes[..end]).unwrap().to_owned();
        assert!(head.starts_with(&format!("POST {path} HTTP/1.1\r\n")));
        let headers: BTreeMap<String, String> = head.lines().skip(1).filter_map(|line| {
            line.split_once(':').map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        }).collect();
        let length: usize = headers["content-length"].parse().unwrap();
        assert!(end + length <= 16 * 1024);
        while bytes.len() < end + length {
            let count = tls.read(&mut buffer).await.unwrap();
            assert!(count > 0 && bytes.len() + count <= 16 * 1024);
            bytes.extend_from_slice(&buffer[..count]);
        }
        assert_eq!(bytes.len(), end + length);
        let body = bytes[end..].to_vec();
        if path == "/token" {
            assert!(!headers.contains_key("authorization"));
            let fields = form(std::str::from_utf8(&body).unwrap());
            assert_eq!(fields["grant_type"], "authorization_code");
            assert_eq!(fields["client_id"], "typed-client");
            assert_eq!(fields["code"], "typed-code");
            assert_eq!(fields["resource"], self.resource());
            self.token_posts.fetch_add(1, Ordering::SeqCst);
        } else {
            assert_eq!(headers["authorization"], "Bearer typed-access");
            assert_eq!(headers["mcp-protocol-version"], "2026-07-28");
            for forbidden in ["mcp-session-id", "last-event-id", "cookie"] { assert!(!headers.contains_key(forbidden)); }
            assert!(!headers.keys().any(|name| name.starts_with("mcp-param-")), "annotations are not disclosure consent");
            let envelope: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(headers["mcp-method"], envelope["method"].as_str().unwrap());
            if envelope["method"] == "tools/call" { assert_eq!(headers["mcp-name"], "calculate"); }
            self.mcp_posts.fetch_add(1, Ordering::SeqCst);
        }
        (tls, body)
    }
    pub async fn login(&self) {
        let (mut tls, _) = self.request("/token").await;
        json_reply(&mut tls, r#"{"access_token":"typed-access","token_type":"Bearer","expires_in":300,"refresh_token":"typed-refresh"}"#).await;
    }
    pub async fn listen(&self, id: i64) -> TlsStream<TcpStream> {
        let (mut tls, request) = self.request("/mcp").await;
        let request: Value = serde_json::from_slice(&request).unwrap();
        assert_eq!(request["id"], id);
        assert_eq!(request["method"], "subscriptions/listen");
        assert_eq!(request["params"]["notifications"], json!({"toolsListChanged":true}));
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
        chunk(&mut tls, &json!({"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged",
            "params":{"_meta":{"io.modelcontextprotocol/subscriptionId":id},"notifications":{"toolsListChanged":true}}
        }).to_string(), false).await;
        tls
    }
    pub async fn catalog(&self, id: i64, minimum: i64, invalid: bool) {
        let (mut tls, request) = self.request("/mcp").await;
        let request: Value = serde_json::from_slice(&request).unwrap();
        assert_eq!(request["id"], id);
        assert_eq!(request["method"], "tools/list");
        assert!(request["params"].get("cursor").is_none());
        let mut input = json!({"type":"object","properties":{"count":{"type":"integer","minimum":minimum,"x-mcp-header":"Count"}},"required":["count"],"additionalProperties":false});
        if invalid { input["unknownValidationKeyword"] = json!(true); }
        let result = json!({"resultType":"complete","tools":[{"name":"calculate","inputSchema":input,
            "outputSchema":{"type":"object","properties":{"total":{"type":"integer"}},"required":["total"]}
        }],"ttlMs":0,"cacheScope":"private"});
        json_reply(&mut tls, &json!({"jsonrpc":"2.0","id":id,"result":result}).to_string()).await;
    }
    pub async fn call(&self, id: i64, count: i64) {
        let (mut tls, request) = self.request("/mcp").await;
        let request: Value = serde_json::from_slice(&request).unwrap();
        assert_eq!(request["id"], id);
        assert_eq!(request["method"], "tools/call");
        assert_eq!(request["params"]["name"], "calculate");
        assert_eq!(request["params"]["arguments"], json!({"count":count}));
        json_reply(&mut tls, &format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{{"resultType":"complete","content":[],"structuredContent":{{"total":{count}}},"x-exact":1.20e+4}}}}"#)).await;
    }
    pub fn no_extra_connections(&self) {
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(self.listener.poll_accept(&mut cx).is_pending(), "no implicit replay, reconnect or stale-handle POST");
    }
}

async fn json_reply(tls: &mut TlsStream<TcpStream>, body: &str) {
    let wire = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    tls.write_all(wire.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
}

pub async fn chunk(tls: &mut TlsStream<TcpStream>, payload: &str, terminal: bool) {
    let body = format!("data: {payload}\n\n");
    let end = if terminal { "0\r\n\r\n" } else { "" };
    tls.write_all(format!("{:X}\r\n{body}\r\n{end}", body.len()).as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
}

pub async fn closed(tls: &mut TlsStream<TcpStream>) {
    let mut byte = [0];
    assert!(!matches!(tls.read(&mut byte).await, Ok(count) if count > 0), "the watch must close its owned stream");
}
