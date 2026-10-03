//! Public machine OAuth revocation across actual TLS ownership boundaries.
//! Native discovery, token acquisition, transport and protocol decoders run
//! unchanged. The peer scripts replies and never sends traffic after the
//! revocation rendezvous. This is not an external-issuer conformance test.
#![cfg(feature = "native-tls-roots")]

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::tls::{
    Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsStream,
};
use fastmcp_client::http_auth::discovery::TrustedOAuthIssuer;
use fastmcp_client::http_auth::discovery::client_credentials::rpc::{
    ClientCredentialsCoreError, ManagedCoreEvent, ManagedCoreLimits,
};
use fastmcp_client::http_auth::discovery::client_credentials::subscriptions::{
    ClientCredentialsCoreSubscriptionError, ClientCredentialsCoreSubscriptionLimits,
    ModernHttpSubscriptionListenEvent,
};
use fastmcp_client::http_auth::discovery::client_credentials::{
    CLIENT_CREDENTIALS_EXTENSION, ClientCredentialsClient, ClientCredentialsError as Error,
    ClientCredentialsPlan, ClientCredentialsSnapshot, ClientSecretAuthenticationMethod,
};
use fastmcp_client::http_auth::rpc::ManagedCoreError;
use fastmcp_client::http_auth::{BoundBearerCredential, CanonicalHttpUrl};
use fastmcp_client::sse::SseLimits;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{
    ClientCapabilities, CoreRequest, FinalRequestMeta, RequestId, SubscriptionFilter,
};
use serde_json::{Value, json};

// Same TEST ONLY identity as oauth_client_credentials.rs. Inlined because the
// remote compiler excludes PEM/key files. Trust is explicitly scoped to these
// resource/issuer clients, never installed in an ambient or permanent store.
const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";
const BASIC: &str = "Basic c2VydmljZS1jbGllbnQ6c2VydmljZS1zZWNyZXQ=";
const ACCESS: &str = "same-access";
const NOTICE: &str = r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
const COMPLETE: &str = r#"{"resultType":"complete","content":[],"x-exact":1.20e+4}"#;

fn run<F: Future<Output = ()>>(scenario: impl FnOnce(Cx) -> F) {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .blocking_threads(0, 0)
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout_at(
                cx.now().saturating_add_nanos(30_000_000_000),
                Box::pin(scenario(cx)),
            )
            .await
            .expect("bounded public TLS scenario");
        });
}
async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = Box::pin(left);
    let mut right = Box::pin(right);
    let (mut one, mut two) = (None, None);
    poll_fn(|task| {
        if one.is_none() {
            if let Poll::Ready(value) = left.as_mut().poll(task) {
                one = Some(value);
            }
        }
        if two.is_none() {
            if let Poll::Ready(value) = right.as_mut().poll(task) {
                two = Some(value);
            }
        }
        if one.is_some() && two.is_some() {
            Poll::Ready((one.take().unwrap(), two.take().unwrap()))
        } else {
            Poll::Pending
        }
    })
    .await
}
struct WakeProbe {
    parent: Waker,
    wakes: AtomicUsize,
}
impl Wake for WakeProbe {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
        self.parent.wake_by_ref();
    }
}
// Assert that the operation itself registered a revocation wake. Merely polling
// it again from a join loop could make a passive atomic check appear sufficient.
async fn revoke_pending<F: Future>(
    cx: &Cx,
    token: &BoundBearerCredential,
    mut ready: oneshot::Receiver<()>,
    operation: F,
) -> F::Output {
    let mut operation = Box::pin(operation);
    let mut ready = Box::pin(ready.recv(cx));
    let mut revoked = false;
    poll_fn(|task| {
        let probe = Arc::new(WakeProbe {
            parent: task.waker().clone(),
            wakes: AtomicUsize::new(0),
        });
        let waker = Waker::from(probe.clone());
        let mut observed = Context::from_waker(&waker);
        let result = operation.as_mut().poll(&mut observed);
        if revoked {
            return result;
        }
        assert!(
            result.is_pending(),
            "operation must remain pending at the silent-peer boundary"
        );
        if let Poll::Ready(signal) = ready.as_mut().poll(task) {
            signal.unwrap();
            let before = probe.wakes.load(Ordering::SeqCst);
            token.revoke();
            assert!(
                probe.wakes.load(Ordering::SeqCst) > before,
                "token-local revocation must wake the actual pending public operation"
            );
            revoked = true;
            task.waker().wake_by_ref();
        }
        Poll::Pending
    })
    .await
}
fn url(text: &str) -> CanonicalHttpUrl {
    CanonicalHttpUrl::parse(text).unwrap()
}
fn core() -> CoreRequest {
    let meta = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    CoreRequest::decode(
        ProtocolEra::Modern2026,
        "tools/call",
        Some(&json!({
            "_meta":meta,"name":"effect","arguments":{"delta":1}
        })),
    )
    .unwrap()
}
fn selection(tasks: bool) -> SubscriptionFilter {
    serde_json::from_value(if tasks {
        json!({"taskIds":["one"]})
    } else {
        json!({"toolsListChanged":true})
    })
    .unwrap()
}
fn form(bytes: &[u8]) -> BTreeMap<String, String> {
    fn part(text: &str) -> String {
        let mut output = Vec::new();
        let mut bytes = text.bytes();
        while let Some(byte) = bytes.next() {
            output.push(match byte {
                b'+' => b' ',
                b'%' => {
                    (char::from(bytes.next().unwrap()).to_digit(16).unwrap() * 16
                        + char::from(bytes.next().unwrap()).to_digit(16).unwrap())
                        as u8
                }
                byte => byte,
            });
        }
        String::from_utf8(output).unwrap()
    }
    std::str::from_utf8(bytes)
        .unwrap()
        .split('&')
        .map(|field| {
            let (key, value) = field.split_once('=').unwrap();
            (part(key), part(value))
        })
        .collect()
}
async fn json_reply(socket: &mut TlsStream<TcpStream>, body: &str) {
    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    socket.flush().await.unwrap();
}
async fn stream_head(socket: &mut TlsStream<TcpStream>, sse: bool) {
    let mime = if sse {
        "text/event-stream"
    } else {
        "application/json"
    };
    socket
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {mime}\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    socket.flush().await.unwrap();
}
async fn event(socket: &mut TlsStream<TcpStream>, payload: &str) {
    let body = format!("data: {payload}\n\n");
    socket
        .write_all(format!("{:X}\r\n{body}\r\n", body.len()).as_bytes())
        .await
        .unwrap();
    socket.flush().await.unwrap();
}
async fn closed(mut socket: TlsStream<TcpStream>) {
    let mut byte = [0];
    assert!(
        !matches!(socket.read(&mut byte).await, Ok(n) if n > 0),
        "revocation releases its socket without another request"
    );
}
fn envelope(id: &Value, result: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#)
}

struct Peer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    grants: AtomicUsize,
    rpcs: AtomicUsize,
}
impl Peer {
    async fn new() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            acceptor: TlsAcceptorBuilder::new(
                CertificateChain::from_pem(LEAF).unwrap(),
                PrivateKey::from_pem(KEY).unwrap(),
            )
            .alpn_protocols(vec![b"http/1.1".to_vec()])
            .build()
            .unwrap(),
            grants: AtomicUsize::new(0),
            rpcs: AtomicUsize::new(0),
        }
    }
    fn origin(&self) -> String {
        format!("https://{}", self.listener.local_addr().unwrap())
    }
    fn resource(&self) -> String {
        format!("{}/mcp", self.origin())
    }
    fn plan(
        &self,
        lifetime: Duration,
        method: ClientSecretAuthenticationMethod,
    ) -> ClientCredentialsPlan {
        let root = Certificate::from_pem(ROOT).unwrap().remove(0);
        let issuer = TrustedOAuthIssuer::new(format!("{}/issuer", self.origin()))
            .unwrap()
            .with_root_certificate(root.clone())
            .unwrap();
        ClientCredentialsPlan::new(
            url(&self.resource()),
            issuer,
            "service-client",
            "service-secret",
            vec!["read".to_owned()],
        )
        .unwrap()
        .with_resource_root_certificate(root)
        .unwrap()
        .with_timeout(Duration::from_secs(10))
        .unwrap()
        .with_maximum_token_lifetime(lifetime)
        .unwrap()
        .with_renewal_leeway(Duration::ZERO)
        .unwrap()
        .with_secret_authentication(method)
        .unwrap()
    }
    async fn request(
        &self,
    ) -> (
        TlsStream<TcpStream>,
        String,
        BTreeMap<String, String>,
        Vec<u8>,
    ) {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut socket = self.acceptor.accept(socket).await.unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0; 2048];
        let end = loop {
            let size = socket.read(&mut chunk).await.unwrap();
            assert!(size > 0 && bytes.len() + size <= 65536);
            bytes.extend_from_slice(&chunk[..size]);
            if let Some(offset) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                break offset + 4;
            }
        };
        let mut lines = std::str::from_utf8(&bytes[..end]).unwrap().lines();
        let request = lines.next().unwrap().to_owned();
        let mut headers = BTreeMap::new();
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').unwrap();
            assert!(
                headers
                    .insert(name.to_ascii_lowercase(), value.trim().to_owned())
                    .is_none()
            );
        }
        let length = headers
            .get("content-length")
            .map_or(0, |n| n.parse::<usize>().unwrap());
        assert!(end + length <= 65536);
        while bytes.len() < end + length {
            let size = socket.read(&mut chunk).await.unwrap();
            assert!(size > 0 && bytes.len() + size <= 65536);
            bytes.extend_from_slice(&chunk[..size]);
        }
        assert_eq!(bytes.len(), end + length);
        (socket, request, headers, bytes[end..].to_vec())
    }
    async fn metadata(&self) {
        let (mut socket, head, headers, body) = self.request().await;
        assert!(head.starts_with("GET /.well-known/oauth-protected-resource/mcp "));
        assert!(!headers.contains_key("authorization") && body.is_empty());
        json_reply(&mut socket, &json!({"resource":self.resource(),"authorization_servers":[format!("{}/issuer",self.origin())],"scopes_supported":["read"]}).to_string()).await;
        drop(socket);
        let (mut socket, head, headers, body) = self.request().await;
        assert!(head.starts_with("GET /.well-known/oauth-authorization-server/issuer "));
        assert!(!headers.contains_key("authorization") && body.is_empty());
        json_reply(&mut socket, &json!({"issuer":format!("{}/issuer",self.origin()),"token_endpoint":format!("{}/token",self.origin()),
            "grant_types_supported":["client_credentials"],"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"],"scopes_supported":["read"]}).to_string()).await;
    }
    async fn grant_request(
        &self,
        method: ClientSecretAuthenticationMethod,
    ) -> TlsStream<TcpStream> {
        let (socket, head, headers, body) = self.request().await;
        assert!(head.starts_with("POST /token "));
        let form = form(&body);
        assert_eq!(form["grant_type"], "client_credentials");
        assert_eq!(form["resource"], self.resource());
        assert_eq!(form["scope"], "read");
        match method {
            ClientSecretAuthenticationMethod::Basic => {
                assert_eq!(headers["authorization"], BASIC);
                assert!(!form.contains_key("client_secret") && !form.contains_key("client_id"));
            }
            ClientSecretAuthenticationMethod::Post => {
                assert!(!headers.contains_key("authorization"));
                assert_eq!(form["client_id"], "service-client");
                assert_eq!(form["client_secret"], "service-secret");
            }
        }
        self.grants.fetch_add(1, Ordering::SeqCst);
        socket
    }
    async fn grant(&self, method: ClientSecretAuthenticationMethod, token: &str) {
        let mut socket = self.grant_request(method).await;
        json_reply(
            &mut socket,
            &json!({"access_token":token,"token_type":"Bearer","expires_in":120,"scope":"read"})
                .to_string(),
        )
        .await;
    }
    async fn connect(
        &self,
        cx: &Cx,
        lifetime: Duration,
        method: ClientSecretAuthenticationMethod,
    ) -> (ClientCredentialsClient, ClientCredentialsSnapshot) {
        let server = async {
            self.metadata().await;
            self.grant(method, ACCESS).await;
        };
        let application = async {
            let client = self.plan(lifetime, method).discover(cx).await.unwrap();
            let snapshot = client.credential(cx).await.unwrap();
            (client, snapshot)
        };
        pair(server, application).await.1
    }
    async fn rpc(&self, method: &str, token: &str, tasks: bool) -> (TlsStream<TcpStream>, Value) {
        let (socket, head, headers, body) = self.request().await;
        assert!(head.starts_with("POST /mcp "));
        assert_eq!(headers["authorization"], format!("Bearer {token}"));
        assert!(!headers.contains_key("mcp-session-id") && !headers.contains_key("last-event-id"));
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["method"], method);
        let mut extensions = json!({CLIENT_CREDENTIALS_EXTENSION:{}});
        if tasks {
            extensions["io.modelcontextprotocol/tasks"] = json!({});
        }
        assert_eq!(
            body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"],
            extensions
        );
        self.rpcs.fetch_add(1, Ordering::SeqCst);
        (socket, body)
    }
    async fn discover(&self, token: &str, tasks: bool) {
        let (mut socket, request) = self.rpc("server/discover", token, tasks).await;
        let mut extensions = json!({CLIENT_CREDENTIALS_EXTENSION:{}});
        if tasks {
            extensions["io.modelcontextprotocol/tasks"] = json!({});
        }
        let result = json!({"resultType":"complete","supportedVersions":["2026-07-28"],
            "capabilities":{"tools":{},"extensions":extensions},"ttlMs":0,"cacheScope":"private"});
        json_reply(&mut socket, &envelope(&request["id"], &result.to_string())).await;
    }
    async fn successful_call(&self, cx: &Cx, client: &ClientCredentialsClient, token: &str) {
        let server = async {
            self.discover(token, false).await;
            let (mut socket, request) = self.rpc("tools/call", token, false).await;
            assert_eq!(request["id"], 92);
            json_reply(&mut socket, &envelope(&request["id"], COMPLETE)).await;
        };
        let application = async {
            let mut call = client
                .request_core(
                    cx,
                    core(),
                    RequestId::Number(91),
                    RequestId::Number(92),
                    ManagedCoreLimits::default(),
                )
                .await
                .unwrap();
            let Some(ManagedCoreEvent::Result(result)) = call.next_event(cx).await.unwrap() else {
                panic!("typed complete result");
            };
            assert!(result.encode().unwrap().contains("1.20e+4"));
            assert!(call.next_event(cx).await.unwrap().is_none());
        };
        pair(server, application).await;
    }
    fn quiet(&self) {
        assert!(
            self.listener
                .poll_accept(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "no automatic grant, replay or reconnect"
        );
    }
}

#[derive(Clone, Copy)]
enum Case {
    DiscoveryHead,
    DiscoveryBody,
    OperationHead,
    RawJson,
    RawSse,
    CoreJson,
    CoreSse,
    CoreTerminal,
    CoreSubscription,
    #[cfg(feature = "tasks")]
    TaskDiscovery,
    #[cfg(feature = "tasks")]
    TaskTerminal,
    #[cfg(feature = "tasks")]
    TaskSubscription,
}
impl Case {
    fn tasks(self) -> bool {
        #[cfg(feature = "tasks")]
        {
            matches!(
                self,
                Self::TaskDiscovery | Self::TaskTerminal | Self::TaskSubscription
            )
        }
        #[cfg(not(feature = "tasks"))]
        {
            let _ = self;
            false
        }
    }
    fn discovery_stop(self) -> bool {
        matches!(self, Self::DiscoveryHead | Self::DiscoveryBody) || {
            #[cfg(feature = "tasks")]
            {
                matches!(self, Self::TaskDiscovery)
            }
            #[cfg(not(feature = "tasks"))]
            {
                false
            }
        }
    }
    fn subscription(self) -> bool {
        matches!(self, Self::CoreSubscription) || {
            #[cfg(feature = "tasks")]
            {
                matches!(self, Self::TaskSubscription)
            }
            #[cfg(not(feature = "tasks"))]
            {
                false
            }
        }
    }
}
async fn stalled(peer: &Peer, case: Case, ready: oneshot::Sender<()>) {
    let mut socket = if case.discovery_stop() {
        let (mut socket, _) = peer.rpc("server/discover", ACCESS, case.tasks()).await;
        if matches!(case, Case::DiscoveryBody) {
            stream_head(&mut socket, false).await;
        }
        socket
    } else {
        peer.discover(ACCESS, case.tasks()).await;
        let (mut socket, request) = peer
            .rpc(
                if case.subscription() {
                    "subscriptions/listen"
                } else {
                    "tools/call"
                },
                ACCESS,
                case.tasks(),
            )
            .await;
        if !matches!(case, Case::OperationHead) {
            let sse = !matches!(case, Case::RawJson | Case::CoreJson);
            stream_head(&mut socket, sse).await;
            if case.subscription() {
                event(&mut socket, &json!({"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{
                    "_meta":{"io.modelcontextprotocol/subscriptionId":request["id"]},"notifications":request["params"]["notifications"]
                }}).to_string()).await;
            } else if matches!(case, Case::RawSse | Case::CoreSse) {
                event(&mut socket, NOTICE).await;
            } else if sse {
                event(&mut socket, &envelope(&request["id"], COMPLETE)).await;
            }
        }
        socket
    };
    socket.flush().await.unwrap();
    ready.send_blocking(()).unwrap();
    closed(socket).await;
}
async fn interrupted(
    cx: &Cx,
    client: &ClientCredentialsClient,
    snapshot: &ClientCredentialsSnapshot,
    case: Case,
    ready: oneshot::Receiver<()>,
) {
    let token = snapshot.credential();
    match case {
        Case::DiscoveryHead | Case::DiscoveryBody | Case::OperationHead => {
            let result = revoke_pending(
                cx,
                token,
                ready,
                client.request_core(
                    cx,
                    core(),
                    RequestId::Number(1),
                    RequestId::Number(2),
                    ManagedCoreLimits::default(),
                ),
            )
            .await;
            assert!(matches!(
                result,
                Err(ClientCredentialsCoreError::Authentication(Error::Expired))
            ));
        }
        Case::RawJson | Case::RawSse => {
            let response = client
                .execute_core(cx, core(), RequestId::Number(1), RequestId::Number(2))
                .await
                .unwrap();
            if matches!(case, Case::RawSse) {
                let mut stream = response
                    .into_sse_stream(SseLimits::new(4096, 4096, 64).unwrap())
                    .unwrap();
                assert_eq!(
                    stream.next_event(cx).await.unwrap().as_deref(),
                    Some(NOTICE)
                );
                assert!(matches!(
                    revoke_pending(cx, token, ready, stream.next_event(cx)).await,
                    Err(Error::Expired)
                ));
                assert!(matches!(stream.next_event(cx).await, Err(Error::Closed)));
            } else {
                assert!(matches!(
                    revoke_pending(cx, token, ready, response.read_to_end(cx, 4096)).await,
                    Err(Error::Expired)
                ));
            }
        }
        Case::CoreJson | Case::CoreSse | Case::CoreTerminal => {
            let mut call = client
                .request_core(
                    cx,
                    core(),
                    RequestId::Number(1),
                    RequestId::Number(2),
                    ManagedCoreLimits::default(),
                )
                .await
                .unwrap();
            if matches!(case, Case::CoreSse) {
                assert!(matches!(
                    call.next_event(cx).await.unwrap(),
                    Some(ManagedCoreEvent::Notification(_))
                ));
            }
            assert!(matches!(
                revoke_pending(cx, token, ready, call.next_event(cx)).await,
                Err(ClientCredentialsCoreError::Authentication(Error::Expired))
            ));
            assert!(matches!(
                call.next_event(cx).await,
                Err(ClientCredentialsCoreError::Protocol(
                    ManagedCoreError::Closed
                ))
            ));
        }
        Case::CoreSubscription => {
            let mut listen = client
                .subscribe_core(
                    cx,
                    FinalRequestMeta::new(ClientCapabilities::default()),
                    RequestId::Number(1),
                    RequestId::Number(2),
                    selection(false),
                    ClientCredentialsCoreSubscriptionLimits::default(),
                )
                .await
                .unwrap();
            assert!(matches!(
                listen.next_event(cx).await.unwrap(),
                Some(ModernHttpSubscriptionListenEvent::Acknowledged { .. })
            ));
            assert!(matches!(
                revoke_pending(cx, token, ready, listen.next_event(cx)).await,
                Err(ClientCredentialsCoreSubscriptionError::Authentication(
                    Error::Expired
                ))
            ));
            assert!(matches!(
                listen.next_event(cx).await,
                Err(ClientCredentialsCoreSubscriptionError::Closed)
            ));
        }
        #[cfg(feature = "tasks")]
        Case::TaskDiscovery | Case::TaskTerminal | Case::TaskSubscription => {
            use fastmcp_client::http_auth::discovery::client_credentials::tasks::subscriptions::ClientCredentialsSubscriptionLimits;
            use fastmcp_client::http_auth::discovery::client_credentials::tasks::{
                ClientCredentialsTasksClient, ClientCredentialsTasksError,
                ClientCredentialsTasksLimits, ManagedTaskRequest, ManagedTasksError,
            };
            let client = ClientCredentialsTasksClient::new(
                client.clone(),
                FinalRequestMeta::new(ClientCapabilities::default()),
                ClientCredentialsTasksLimits::default(),
            )
            .unwrap();
            if matches!(case, Case::TaskSubscription) {
                let mut listen = client
                    .subscribe(
                        cx,
                        RequestId::Number(1),
                        RequestId::Number(2),
                        selection(true),
                        ClientCredentialsSubscriptionLimits::default(),
                    )
                    .await
                    .unwrap();
                assert!(matches!(
                    listen.next_event(cx).await.unwrap(),
                    Some(ModernHttpSubscriptionListenEvent::Acknowledged { .. })
                ));
                assert!(matches!(
                    revoke_pending(cx, token, ready, listen.next_event(cx)).await,
                    Err(ClientCredentialsTasksError::Authentication(Error::Expired))
                ));
                assert!(matches!(
                    listen.next_event(cx).await,
                    Err(ClientCredentialsTasksError::Protocol(
                        ManagedTasksError::Closed
                    ))
                ));
            } else {
                let request = client.request(
                    cx,
                    RequestId::Number(1),
                    RequestId::Number(2),
                    ManagedTaskRequest::CallTool {
                        name: "effect".to_owned(),
                        arguments: None,
                    },
                );
                if matches!(case, Case::TaskDiscovery) {
                    assert!(matches!(
                        revoke_pending(cx, token, ready, request).await,
                        Err(ClientCredentialsTasksError::Authentication(Error::Expired))
                    ));
                } else {
                    let mut call = request.await.unwrap();
                    assert!(matches!(
                        revoke_pending(cx, token, ready, call.next_event(cx)).await,
                        Err(ClientCredentialsTasksError::Authentication(Error::Expired))
                    ));
                    assert!(matches!(
                        call.next_event(cx).await,
                        Err(ClientCredentialsTasksError::Protocol(
                            ManagedTasksError::Closed
                        ))
                    ));
                }
            }
        }
    }
}
fn scenario(case: Case) {
    run(|cx| async move {
        let peer = Peer::new().await;
        let (client, snapshot) = peer
            .connect(
                &cx,
                Duration::from_secs(60),
                ClientSecretAuthenticationMethod::Basic,
            )
            .await;
        let (ready, entered) = oneshot::channel();
        pair(
            stalled(&peer, case, ready),
            interrupted(&cx, &client, &snapshot, case, entered),
        )
        .await;
        assert!(snapshot.credential().is_revoked());
        assert!(matches!(client.credential(&cx).await, Err(Error::Expired)));
        assert_eq!(snapshot.generation(), 1);
        assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
        assert_eq!(
            peer.rpcs.load(Ordering::SeqCst),
            if case.discovery_stop() { 1 } else { 2 }
        );
        peer.quiet();
        // Identical token text in a separately acquired client is not a global
        // revocation identity. It must remain capable of a distinct MCP call.
        let (independent, other) = peer
            .connect(
                &cx,
                Duration::from_secs(60),
                ClientSecretAuthenticationMethod::Basic,
            )
            .await;
        assert!(!other.credential().is_revoked());
        peer.successful_call(&cx, &independent, ACCESS).await;
        assert_eq!(peer.grants.load(Ordering::SeqCst), 2);
        assert!(cx.checkpoint().is_ok());
        client.close();
        independent.close();
        peer.quiet();
    });
}

#[test]
fn revoked_machine_discovery_cannot_start_the_operation() {
    for case in [Case::DiscoveryHead, Case::DiscoveryBody] {
        scenario(case);
    }
}
#[test]
fn revoked_machine_response_head_retires_its_socket() {
    scenario(Case::OperationHead);
}
#[test]
fn revoked_machine_raw_json_and_sse_reads_stop_without_peer_activity() {
    for case in [Case::RawJson, Case::RawSse] {
        scenario(case);
    }
}
#[test]
fn revoked_machine_typed_results_and_provisional_terminals_are_withheld() {
    for case in [Case::CoreJson, Case::CoreSse, Case::CoreTerminal] {
        scenario(case);
    }
}
#[test]
fn revoked_machine_core_subscription_stops_after_its_acknowledgment() {
    scenario(Case::CoreSubscription);
}
#[cfg(feature = "tasks")]
#[test]
fn revoked_machine_tasks_discovery_and_terminal_stop_without_mutation_replay() {
    for case in [Case::TaskDiscovery, Case::TaskTerminal] {
        scenario(case);
    }
}
#[cfg(feature = "tasks")]
#[test]
fn revoked_machine_tasks_subscription_stops_after_its_acknowledgment() {
    scenario(Case::TaskSubscription);
}

#[test]
fn revoking_old_machine_access_interrupts_a_pending_replacement_grant() {
    for method in [
        ClientSecretAuthenticationMethod::Basic,
        ClientSecretAuthenticationMethod::Post,
    ] {
        run(|cx| async move {
            let peer = Peer::new().await;
            let (client, original) = peer.connect(&cx, Duration::from_secs(2), method).await;
            asupersync::time::sleep(
                cx.now(),
                original
                    .expires_at()
                    .saturating_duration_since(Instant::now())
                    + Duration::from_millis(10),
            )
            .await;
            let (ready, entered) = oneshot::channel();
            let server = async {
                let socket = peer.grant_request(method).await;
                ready.send_blocking(()).unwrap();
                closed(socket).await;
            };
            let application = async {
                let (result, queued) = pair(
                    revoke_pending(&cx, original.credential(), entered, client.credential(&cx)),
                    client.credential(&cx),
                )
                .await;
                assert!(matches!(result, Err(Error::Expired)));
                assert!(matches!(queued, Err(Error::Expired)));
                assert!(matches!(client.credential(&cx).await, Err(Error::Expired)));
                assert_eq!(original.generation(), 1);
            };
            pair(server, application).await;
            assert_eq!(
                peer.grants.load(Ordering::SeqCst),
                2,
                "revocation cannot start another grant"
            );
            assert_eq!(peer.rpcs.load(Ordering::SeqCst), 0);
            assert!(cx.checkpoint().is_ok());
            client.close();
            peer.quiet();
        });
    }
}

#[test]
fn ordinary_machine_expiry_still_renews_and_old_revocation_does_not_cancel_the_new_generation() {
    run(|cx| async move {
        let peer = Peer::new().await;
        let method = ClientSecretAuthenticationMethod::Basic;
        let (client, original) = peer.connect(&cx, Duration::from_secs(2), method).await;
        asupersync::time::sleep(
            cx.now(),
            original
                .expires_at()
                .saturating_duration_since(Instant::now())
                + Duration::from_millis(10),
        )
        .await;
        let (_, replacement) = pair(
            peer.grant(method, "replacement-access"),
            client.credential(&cx),
        )
        .await;
        let replacement = replacement.unwrap();
        assert_eq!(replacement.generation(), 2);
        assert!(replacement.expires_at() > original.expires_at());
        original.credential().revoke();
        assert!(!replacement.credential().is_revoked());
        assert_eq!(client.credential(&cx).await.unwrap().generation(), 2);
        peer.successful_call(&cx, &client, "replacement-access")
            .await;
        assert_eq!(peer.grants.load(Ordering::SeqCst), 2);
        assert_eq!(peer.rpcs.load(Ordering::SeqCst), 2);
        client.close();
        peer.quiet();
    });
}
