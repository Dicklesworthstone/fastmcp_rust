//! Real-socket machine-authentication tests. The issuer/resource are local TLS
//! fixtures; no browser, DCR, external IdP or disabled TLS verification is used.
//! Run this target with native-tls-roots; a feature-filtered zero-test run is not proof.
#![cfg(feature = "native-tls-roots")]

#[cfg(feature = "tasks")]
#[path = "oauth_client_credentials/tasks.rs"]
mod tasks;
#[cfg(all(not(target_arch = "wasm32"), feature = "builtin-auth-server"))]
#[path = "oauth_client_credentials/private_key_jwt.rs"]
mod private_key_jwt;

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::time::Sleep;
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsStream};
use fastmcp_client::http_auth::discovery::{OAuthDiscoveryError, TrustedOAuthIssuer};
use fastmcp_client::http_auth::discovery::client_credentials::{
    ClientCredentialsClient, ClientCredentialsError as Error, ClientCredentialsPlan,
    CLIENT_CREDENTIALS_EXTENSION,
};
use fastmcp_client::sse::SseLimits;
use fastmcp_core::{CanonicalHttpUrl, McpRequestCancellation};
use fastmcp_protocol::{ClientCapabilities, CoreRequest, FinalCoreResult, CoreResult, FinalRequestMeta, RequestId};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use serde_json::{Value, json};

const CHILD: &str = "FASTMCP_TEST_CLIENT_CREDENTIALS_CASE";
const BASIC: &str = "Basic c2VydmljZS1jbGllbnQ6c2VydmljZS1zZWNyZXQ=";
const DISCOVERY: &str = r#"{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{},"extensions":{"io.modelcontextprotocol/oauth-client-credentials":{}}},"ttlMs":0,"cacheScope":"private"}"#;
const LIST: &str = r#"{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private","x-exact":{"z":900719925474099312345,"a":1.20e+4}}"#;
const CALL: &str = r#"{"resultType":"complete","content":[],"x-exact":1.20e+4}"#;
const NOTICE: &str = r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
// TEST ONLY CA and localhost certificate, valid 2020-2049. Installed only into
// each isolated child process through SSL_CERT_FILE, never a persistent store.
const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

#[derive(Clone, Copy)]
enum Case {
    Complete, Renew, WrongIssuer, WrongEndpoint, UnsupportedAuth, BadToken,
    TokenRedirect, LostGrant, Negotiation, LostMutation, DeniedMutation,
    Preflight, CancelGrant, CloseGrant, DropGrant, TimeoutGrant,
    Streaming, CancelRead, CloseRead, DropRead, ExpireRead, DropOwner, InputRequired,
}

struct RootFile(std::path::PathBuf);
impl RootFile {
    fn create() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        for _ in 0..64 {
            let path = std::env::temp_dir().join(format!("fastmcp-service-auth-{}-{}.pem", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => { let owned = Self(path); file.write_all(ROOT).unwrap(); return owned; }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(error) => panic!("cannot create isolated test trust: {error}"),
            }
        }
        panic!("test CA name bound exhausted");
    }
}
impl Drop for RootFile { fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); } }
struct Child(std::process::Child);
impl Drop for Child { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
fn isolated(name: &str, case: Case) {
    if let Ok(selected) = std::env::var(CHILD) { assert_eq!(selected, name); run(case); return; }
    let roots = RootFile::create();
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD, name).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() { assert!(status.success(), "service-auth TLS case failed"); return; }
        assert!(Instant::now() < end, "service-auth child exceeded its bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}
async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = Box::pin(left);
    let mut right = Box::pin(right);
    let mut one = None;
    let mut two = None;
    poll_fn(|task| {
        if one.is_none() { if let Poll::Ready(value) = left.as_mut().poll(task) { one = Some(value); } }
        if two.is_none() { if let Poll::Ready(value) = right.as_mut().poll(task) { two = Some(value); } }
        if one.is_some() && two.is_some() { Poll::Ready((one.take().unwrap(), two.take().unwrap())) }
        else { Poll::Pending }
    }).await
}
fn url(text: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(text).unwrap() }
fn core(method: &str) -> CoreRequest {
    let mut params = if method == "tools/call" { json!({"name":"mutate","arguments":{"delta":1}}) } else { json!({}) };
    params["_meta"] = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
    params["_meta"]["com.example/tenant"] = json!("unchanged");
    CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params)).unwrap()
}
fn form(text: &str) -> BTreeMap<String, String> {
    fn part(text: &str) -> String {
        let mut out = Vec::new(); let mut bytes = text.bytes();
        while let Some(byte) = bytes.next() {
            out.push(match byte {
                b'+' => b' ',
                b'%' => (char::from(bytes.next().unwrap()).to_digit(16).unwrap() * 16 + char::from(bytes.next().unwrap()).to_digit(16).unwrap()) as u8,
                byte => byte,
            });
        }
        String::from_utf8(out).unwrap()
    }
    text.split('&').map(|field| { let (k,v) = field.split_once('=').unwrap(); (part(k),part(v)) }).collect()
}
async fn json_reply(socket: &mut TlsStream<TcpStream>, body: &str) {
    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    socket.flush().await.unwrap();
}
fn terminal(id: i64, result: &str) -> String { format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#) }
async fn event(socket: &mut TlsStream<TcpStream>, payload: &str, last: bool) {
    let data = format!("data: {payload}\n\n");
    let tail = if last { "0\r\n\r\n" } else { "" };
    socket.write_all(format!("{:X}\r\n{data}\r\n{tail}", data.len()).as_bytes()).await.unwrap();
    socket.flush().await.unwrap();
}
async fn closed(mut socket: TlsStream<TcpStream>) {
    let mut byte = [0];
    assert!(!matches!(socket.read(&mut byte).await, Ok(count) if count > 0), "interruption must close the owned connection");
}

struct Peer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    gets: AtomicUsize,
    grants: AtomicUsize,
    rpcs: AtomicUsize,
}
impl Peer {
    async fn new() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            acceptor: TlsAcceptorBuilder::new(CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap())
                .alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap(),
            gets: AtomicUsize::new(0), grants: AtomicUsize::new(0), rpcs: AtomicUsize::new(0),
        }
    }
    fn origin(&self) -> String { format!("https://{}", self.listener.local_addr().unwrap()) }
    fn issuer(&self) -> String { format!("{}/issuer", self.origin()) }
    fn resource(&self) -> String { format!("{}/mcp", self.origin()) }
    fn plan(&self, timeout: Duration) -> ClientCredentialsPlan {
        let root = Certificate::from_pem(ROOT).unwrap().remove(0);
        let issuer = TrustedOAuthIssuer::new(self.issuer()).unwrap().with_root_certificate(root.clone()).unwrap();
        ClientCredentialsPlan::new(url(&self.resource()), issuer, "service-client", "service-secret", vec!["read".to_owned()]).unwrap()
            .with_resource_root_certificate(root).unwrap().with_renewal_leeway(Duration::ZERO).unwrap().with_timeout(timeout).unwrap()
    }
    async fn request(&self) -> (TlsStream<TcpStream>, String, BTreeMap<String,String>, Vec<u8>) {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut tls = self.acceptor.accept(socket).await.unwrap();
        let mut wire = Vec::new(); let mut chunk = [0;2048];
        let end = loop {
            let n = tls.read(&mut chunk).await.unwrap();
            assert!(n > 0 && wire.len()+n <= 32768);
            wire.extend_from_slice(&chunk[..n]);
            if let Some(index) = wire.windows(4).position(|part| part == b"\r\n\r\n") { break index+4; }
        };
        let head = std::str::from_utf8(&wire[..end]).unwrap();
        let start = head.lines().next().unwrap().to_owned();
        let headers: BTreeMap<String,String> = head.lines().filter_map(|line| line.split_once(':')
            .map(|(k,v)| (k.to_ascii_lowercase(),v.trim().to_owned()))).collect();
        let size = headers.get("content-length").map_or(0, |s| s.parse::<usize>().unwrap());
        assert!(end+size <= 32768 && !headers.contains_key("cookie"));
        while wire.len() < end+size {
            let n = tls.read(&mut chunk).await.unwrap(); assert!(n > 0 && wire.len()+n <= 32768);
            wire.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(wire.len(), end+size);
        (tls,start,headers,wire[end..].to_vec())
    }
    async fn metadata(&self, case: Case) {
        let (mut tls,start,headers,body) = self.request().await;
        assert_eq!(start,"GET /.well-known/oauth-protected-resource/mcp HTTP/1.1");
        assert!(!headers.contains_key("authorization") && body.is_empty());
        self.gets.fetch_add(1,Ordering::SeqCst);
        let issuer = if matches!(case,Case::WrongIssuer) { "https://unknown.example/issuer".to_owned() } else { self.issuer() };
        json_reply(&mut tls,&json!({"resource":self.resource(),"authorization_servers":[issuer],"scopes_supported":["read"]}).to_string()).await;
        drop(tls);
        if matches!(case,Case::WrongIssuer) {
            // The second constructed PRM must be tried, but it must not turn
            // the same untrusted issuer into a token endpoint or a secret sink.
            let (mut tls,start,headers,body) = self.request().await;
            assert_eq!(start,"GET /.well-known/oauth-protected-resource HTTP/1.1");
            assert!(!headers.contains_key("authorization") && body.is_empty());
            self.gets.fetch_add(1,Ordering::SeqCst);
            json_reply(&mut tls,&json!({"resource":self.resource(),"authorization_servers":["https://unknown.example/issuer"],"scopes_supported":["read"]}).to_string()).await;
            return;
        }
        let (mut tls,start,headers,body) = self.request().await;
        assert_eq!(start,"GET /.well-known/oauth-authorization-server/issuer HTTP/1.1");
        assert!(!headers.contains_key("authorization") && body.is_empty());
        self.gets.fetch_add(1,Ordering::SeqCst);
        let token = if matches!(case,Case::WrongEndpoint) { "https://untrusted.example/token".to_owned() } else { format!("{}/token",self.origin()) };
        let auth = if matches!(case,Case::UnsupportedAuth) { "private_key_jwt" } else { "client_secret_basic" };
        // Deliberately NO authorization endpoint, response_types, PKCE or DCR.
        json_reply(&mut tls,&json!({"issuer":self.issuer(),"token_endpoint":token,
            "grant_types_supported":["client_credentials"],"token_endpoint_auth_methods_supported":[auth],
            "scopes_supported":["read"]}).to_string()).await;
    }
    async fn token_request(&self) -> TlsStream<TcpStream> {
        let (tls,start,headers,body) = self.request().await;
        assert_eq!(start,"POST /token HTTP/1.1");
        assert_eq!(headers["authorization"],BASIC);
        assert_eq!(headers["content-type"],"application/x-www-form-urlencoded");
        let fields = form(std::str::from_utf8(&body).unwrap());
        assert_eq!(fields["grant_type"],"client_credentials");
        assert_eq!(fields["resource"],self.resource());
        assert_eq!(fields["scope"],"read");
        assert_eq!(fields.len(),3,"no client_secret, refresh_token, code, or assertion in the Basic form");
        self.grants.fetch_add(1,Ordering::SeqCst);
        tls
    }
    async fn grant(&self, token: &str, seconds: u64) {
        let mut tls = self.token_request().await;
        json_reply(&mut tls,&json!({"access_token":token,"token_type":"Bearer","expires_in":seconds,"scope":"read",
            "refresh_token":"MUST-NOT-BE-USED"}).to_string()).await;
    }
    async fn rpc(&self, id: i64, method: &str, token: &str) -> TlsStream<TcpStream> {
        let (tls,start,headers,body) = self.request().await;
        assert_eq!(start,"POST /mcp HTTP/1.1");
        assert_eq!(headers["authorization"],format!("Bearer {token}"));
        assert!(!headers.values().any(|value| value.contains("service-secret") || value == BASIC));
        let body:Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["method"],method); assert_eq!(body["id"],id);
        assert_eq!(headers["mcp-method"],method);
        assert_eq!(headers["mcp-protocol-version"],"2026-07-28");
        assert!(!headers.contains_key("mcp-session-id") && !headers.contains_key("last-event-id"));
        assert_eq!(body["params"]["_meta"]["com.example/tenant"],"unchanged");
        assert_eq!(body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"],json!({CLIENT_CREDENTIALS_EXTENSION:{}}));
        self.rpcs.fetch_add(1,Ordering::SeqCst);
        tls
    }
    async fn discovery(&self,id:i64,token:&str,result:&str) {
        json_reply(&mut self.rpc(id,"server/discover",token).await,&terminal(id,result)).await;
    }
    async fn operation(&self,id:i64,method:&str,token:&str,result:&str) {
        self.discovery(id,token,DISCOVERY).await;
        json_reply(&mut self.rpc(id+1,method,token).await,&terminal(id+1,result)).await;
    }
    fn quiet(&self) {
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(self.listener.poll_accept(&mut task).is_pending(),"no hidden retry, DCR, browser or token exchange");
    }
}

async fn acquire(peer:&Peer,cx:&Cx,client:&ClientCredentialsClient,token:&str,seconds:u64) {
    let ((),result) = pair(peer.grant(token,seconds),client.credential(cx)).await;
    assert!(result.is_ok());
}
fn run(case: Case) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        let scenario = Box::pin(async {
            let peer = Peer::new().await;
            let plan = peer.plan(if matches!(case,Case::TimeoutGrant) { Duration::from_secs(1) } else { Duration::from_secs(15) });
            let ((),discovered) = pair(peer.metadata(case),plan.discover(&cx)).await;
            if matches!(case,Case::WrongIssuer|Case::WrongEndpoint|Case::UnsupportedAuth) {
                let error = discovered.err().unwrap();
                match case {
                    Case::WrongIssuer => {
                        use fastmcp_client::http_auth::discovery::{ResourceMetadataCause, ResourceMetadataFailureClass, ResourceMetadataLocation};
                        let Error::Discovery(OAuthDiscoveryError::ResourceMetadataExhausted(failure)) = error else {
                            panic!("both untrusted PRM candidates must be reported");
                        };
                        assert_eq!(failure.classification(), ResourceMetadataFailureClass::TrustOrIntegrity);
                        assert_eq!(failure.attempts().iter().map(|attempt| (attempt.location(), attempt.cause())).collect::<Vec<_>>(), [
                            (ResourceMetadataLocation::PathSpecific, ResourceMetadataCause::NoTrustedIssuer),
                            (ResourceMetadataLocation::OriginRoot, ResourceMetadataCause::NoTrustedIssuer),
                        ]);
                        assert_eq!(peer.gets.load(Ordering::SeqCst),2);
                        assert_eq!(peer.rpcs.load(Ordering::SeqCst),0);
                    }
                    Case::WrongEndpoint => assert!(matches!(error,Error::Discovery(OAuthDiscoveryError::EndpointNotTrusted))),
                    _ => assert!(matches!(error,Error::UnsupportedAuthentication)),
                }
                assert_eq!(peer.grants.load(Ordering::SeqCst),0);
                peer.quiet(); return;
            }
            let client = discovered.unwrap();
            assert_eq!(peer.gets.load(Ordering::SeqCst),2);
            match case {
                Case::Complete => {
                    let clone = client.clone();
                    let server = async { peer.grant("access-one",300).await; };
                    let application = async {
                        let (one,two) = pair(client.credential(&cx),clone.credential(&cx)).await;
                        for snapshot in [one.unwrap(),two.unwrap()] {
                            assert_eq!(snapshot.generation(),1);
                            assert_eq!(snapshot.scopes(),["read"]);
                            assert!(snapshot.credential().authorization_for_target(&url(&peer.resource())).is_some());
                            assert!(snapshot.credential().authorization_for_target(&url(&format!("{}/token",peer.origin()))).is_none());
                            assert!(!format!("{snapshot:?} {client:?}").contains("access-one"));
                        }
                    };
                    pair(server,application).await;
                    let server = async {
                        peer.operation(1,"tools/list","access-one",LIST).await;
                        peer.operation(3,"tools/call","access-one",CALL).await;
                    };
                    let application = async {
                        for (id,method) in [(1,"tools/list"),(3,"tools/call")] {
                            let response = client.execute_core(&cx,core(method),RequestId::Number(id),RequestId::Number(id+1)).await.unwrap();
                            assert_eq!(response.credential_generation(),1);
                            let result = response.read_json_result(&cx,4096).await.unwrap();
                            assert!(result.encode().unwrap().contains("1.20e+4"));
                        }
                    };
                    pair(server,application).await;
                    assert_eq!(peer.grants.load(Ordering::SeqCst),1);
                    assert_eq!(peer.rpcs.load(Ordering::SeqCst),4);
                }
                Case::Renew => {
                    acquire(&peer,&cx,&client,"access-one",1).await;
                    let old = client.credential(&cx).await.unwrap();
                    Sleep::new(cx.now().saturating_add_nanos(1_100_000_000)).await;
                    assert!(old.credential().authorization_for_target(client.resource()).is_none());
                    let ((),fresh) = pair(peer.grant("access-two",300),client.credential(&cx)).await;
                    assert_eq!(fresh.unwrap().generation(),2);
                    let ((),response) = pair(peer.operation(1,"tools/list","access-two",LIST),
                        client.execute_core(&cx,core("tools/list"),RequestId::Number(1),RequestId::Number(2))).await;
                    assert_eq!(response.unwrap().read_json_result(&cx,4096).await.unwrap().era(),ProtocolEra::Modern2026);
                    assert_eq!(peer.grants.load(Ordering::SeqCst),2);
                }
                Case::BadToken => {
                    let server = async {
                        let mut tls=peer.token_request().await;
                        json_reply(&mut tls,r#"{"access_token":"rejected-secret","token_type":"Bearer","scope":"admin","expires_in":300}"#).await;
                    };
                    let ((),result)=pair(server,client.credential(&cx)).await;
                    let error=result.err().unwrap();
                    assert!(matches!(error,Error::ExpandedScope));
                    assert!(!format!("{error:?} {error}").contains("rejected-secret"));
                    assert_eq!(peer.grants.load(Ordering::SeqCst),1); peer.quiet();
                    let ((),result)=pair(peer.grant("admitted",300),client.credential(&cx)).await;
                    assert_eq!(result.unwrap().generation(),1,"failed grant cannot advance cached credential state");
                }
                Case::TokenRedirect|Case::LostGrant => {
                    let server=async {
                        let mut tls=peer.token_request().await;
                        if matches!(case,Case::TokenRedirect) {
                            tls.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://127.0.0.1:9/forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                            tls.flush().await.unwrap();
                        }
                    };
                    let ((),result)=pair(server,client.credential(&cx)).await;
                    assert!(matches!((case,result.err().unwrap()),(Case::TokenRedirect,Error::TokenEndpointRejected)|(Case::LostGrant,Error::Transport)));
                    assert_eq!(peer.grants.load(Ordering::SeqCst),1);
                }
                Case::Negotiation => {
                    acquire(&peer,&cx,&client,"access-one",300).await;
                    for (index,(from,to)) in [
                        ("\"io.modelcontextprotocol/oauth-client-credentials\":{}","\"com.example/other\":{}"),
                        ("\"io.modelcontextprotocol/oauth-client-credentials\":{}","\"io.modelcontextprotocol/oauth-client-credentials\":{\"invented\":true}"),
                        ("2026-07-28","2024-11-05"),
                    ].into_iter().enumerate() {
                        let id=1+2*index as i64;
                        let document=DISCOVERY.replace(from,to);
                        let ((),result)=pair(peer.discovery(id,"access-one",&document),
                            client.execute_core(&cx,core("tools/call"),RequestId::Number(id),RequestId::Number(id+1))).await;
                        assert!(matches!(result,Err(Error::Negotiation)));
                    }
                    assert_eq!(peer.rpcs.load(Ordering::SeqCst),3,"no business POST after rejected capability advertisement");
                    assert_eq!(peer.grants.load(Ordering::SeqCst),1);
                }
                Case::LostMutation|Case::DeniedMutation => {
                    acquire(&peer,&cx,&client,"access-one",300).await;
                    let server=async {
                        peer.discovery(1,"access-one",DISCOVERY).await;
                        let mut tls=peer.rpc(2,"tools/call","access-one").await;
                        if matches!(case,Case::DeniedMutation) {
                            tls.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                            tls.flush().await.unwrap();
                        }
                    };
                    let ((),result)=pair(server,client.execute_core(&cx,core("tools/call"),RequestId::Number(1),RequestId::Number(2))).await;
                    if let Ok(response)=result { assert!(response.read_json_result(&cx,4096).await.is_err()); }
                    assert_eq!(peer.rpcs.load(Ordering::SeqCst),2); peer.quiet();
                    let ((),response)=pair(peer.operation(3,"tools/list","access-one",LIST),
                        client.execute_core(&cx,core("tools/list"),RequestId::Number(3),RequestId::Number(4))).await;
                    assert!(response.unwrap().read_json_result(&cx,4096).await.is_ok());
                    assert_eq!(peer.grants.load(Ordering::SeqCst),1);
                }
                Case::Preflight => {
                    let alias:RequestId=serde_json::from_str("1e0").unwrap();
                    assert!(matches!(client.execute_core(&cx,core("tools/list"),RequestId::Number(1),alias).await,Err(Error::InvalidRequest)));
                    let mut params=core("tools/list").encode_params().unwrap().unwrap();
                    params["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"]=json!({"io.modelcontextprotocol/tasks":{}});
                    let other=CoreRequest::decode(ProtocolEra::Modern2026,"tools/list",Some(&params)).unwrap();
                    assert!(matches!(client.execute_core(&cx,other,RequestId::Number(1),RequestId::Number(2)).await,Err(Error::InvalidRequest)));
                    let cancel=McpRequestCancellation::new(); cancel.cancel();
                    assert!(client.credential_with_cancellation(&cx,&cancel).await.is_err());
                    assert_eq!(peer.grants.load(Ordering::SeqCst),0); assert_eq!(peer.rpcs.load(Ordering::SeqCst),0);
                }
                Case::CancelGrant|Case::CloseGrant|Case::DropGrant|Case::TimeoutGrant => {
                    let cancel=McpRequestCancellation::new();
                    let (tx,mut rx)=oneshot::channel::<()>();
                    let server=async {
                        let tls=peer.token_request().await; tx.send(&cx,()).unwrap(); closed(tls).await;
                    };
                    let application=async {
                        let mut pending=Box::pin(client.credential_with_cancellation(&cx,&cancel));
                        let mut started=std::pin::pin!(rx.recv(&cx));
                        poll_fn(|task| { assert!(pending.as_mut().poll(task).is_pending()); started.as_mut().poll(task) }).await.unwrap();
                        if matches!(case,Case::DropGrant) { drop(pending); return; }
                        match case { Case::CancelGrant => { cancel.cancel(); }, Case::CloseGrant => client.close(), _ => {} }
                        let error=pending.await.err().unwrap();
                        match case {
                            Case::CancelGrant => assert!(matches!(error,Error::Discovery(OAuthDiscoveryError::Cancelled))),
                            Case::CloseGrant => assert!(matches!(error,Error::Closed)),
                            _ => assert!(matches!(error,Error::Discovery(OAuthDiscoveryError::TimedOut))),
                        }
                    };
                    pair(server,application).await;
                    assert_eq!(peer.grants.load(Ordering::SeqCst),1);
                }
                Case::Streaming|Case::CancelRead|Case::CloseRead|Case::DropRead|Case::ExpireRead => {
                    acquire(&peer,&cx,&client,"access-one",if matches!(case,Case::ExpireRead) { 2 } else { 300 }).await;
                    let cancel=McpRequestCancellation::new();
                    let (tx,mut rx)=oneshot::channel::<()>();
                    let server=async {
                        peer.discovery(1,"access-one",DISCOVERY).await;
                        let mut tls=peer.rpc(2,"tools/list","access-one").await;
                        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
                        event(&mut tls,NOTICE,false).await;
                        rx.recv(&cx).await.unwrap();
                        if matches!(case,Case::Streaming) { event(&mut tls,&terminal(2,LIST),true).await; }
                        else { closed(tls).await; }
                    };
                    let application=async {
                        let response=client.execute_core_with_cancellation(&cx,&cancel,core("tools/list"),RequestId::Number(1),RequestId::Number(2)).await.unwrap();
                        let mut stream=response.into_sse_stream(SseLimits::new(4096,65536,8).unwrap()).unwrap();
                        assert_eq!(stream.next_event(&cx).await.unwrap(),Some(NOTICE.to_owned()));
                        tx.send(&cx,()).unwrap();
                        if matches!(case,Case::Streaming) {
                            assert!(stream.next_event(&cx).await.unwrap().unwrap().contains("1.20e+4"));
                            assert_eq!(stream.next_event(&cx).await.unwrap(),None); return;
                        }
                        let mut reading=Box::pin(stream.next_event(&cx));
                        poll_fn(|task| { assert!(reading.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                        if matches!(case,Case::DropRead) { drop(reading); }
                        else {
                            match case { Case::CancelRead => { cancel.cancel(); }, Case::CloseRead => client.close(), _ => {} }
                            assert!(reading.await.is_err());
                        }
                        assert!(matches!(stream.next_event(&cx).await,Err(Error::Closed)));
                    };
                    pair(server,application).await;
                    assert_eq!(peer.grants.load(Ordering::SeqCst),1,"opening-token expiry never renews a live response");
                    assert_eq!(peer.rpcs.load(Ordering::SeqCst),2);
                }
                Case::DropOwner => {
                    acquire(&peer,&cx,&client,"access-one",300).await;
                    let snapshot=client.credential(&cx).await.unwrap();
                    let bearer=snapshot.credential().clone();
                    assert!(bearer.authorization_for_target(client.resource()).is_some());
                    let resource=client.resource().clone();
                    drop(client);
                    assert!(bearer.authorization_for_target(&resource).is_none());
                    assert_eq!(peer.grants.load(Ordering::SeqCst),1); peer.quiet(); return;
                }
                Case::InputRequired => {
                    acquire(&peer,&cx,&client,"access-one",300).await;
                    let challenge=r#"{"resultType":"input_required","requestState":"opaque-state","x-exact":1.20e+4}"#;
                    let ((),response)=pair(peer.operation(1,"tools/call","access-one",challenge),
                        client.execute_core(&cx,core("tools/call"),RequestId::Number(1),RequestId::Number(2))).await;
                    let result=response.unwrap().read_json_result(&cx,4096).await.unwrap();
                    assert!(matches!(&result,CoreResult::Final(FinalCoreResult::ToolsCallInputRequired { .. })));
                    let encoded=result.encode().unwrap();
                    assert!(encoded.contains("opaque-state") && encoded.contains("1.20e+4"));
                    assert_eq!(peer.rpcs.load(Ordering::SeqCst),2,"input-required is not an implicit continuation or browser trigger");
                    assert_eq!(peer.grants.load(Ordering::SeqCst),1);
                }
                Case::WrongIssuer|Case::WrongEndpoint|Case::UnsupportedAuth => unreachable!(),
            }
            assert!(cx.checkpoint().is_ok(),"local interruption does not cancel the caller context");
            peer.quiet();
            client.close();
        });
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000),scenario).await.expect("machine-auth TLS fixture must settle");
    }));
}

#[test]
fn machine_login_reuses_one_grant_and_executes_typed_core_calls() { isolated("machine_login_reuses_one_grant_and_executes_typed_core_calls",Case::Complete); }
#[test]
fn expired_machine_token_uses_a_new_client_credentials_grant_not_refresh() { isolated("expired_machine_token_uses_a_new_client_credentials_grant_not_refresh",Case::Renew); }
#[test]
fn untrusted_issuer_never_receives_the_client_secret() { isolated("untrusted_issuer_never_receives_the_client_secret",Case::WrongIssuer); }
#[test]
fn cross_origin_token_endpoint_requires_a_host_grant() { isolated("cross_origin_token_endpoint_requires_a_host_grant",Case::WrongEndpoint); }
#[test]
fn jwt_only_metadata_never_triggers_basic_or_browser_fallback() { isolated("jwt_only_metadata_never_triggers_basic_or_browser_fallback",Case::UnsupportedAuth); }
#[test]
fn rejected_token_cannot_advance_cached_credential_generation() { isolated("rejected_token_cannot_advance_cached_credential_generation",Case::BadToken); }
#[test]
fn token_redirect_is_terminal_without_secret_forwarding() { isolated("token_redirect_is_terminal_without_secret_forwarding",Case::TokenRedirect); }
#[test]
fn lost_grant_response_is_not_retried() { isolated("lost_grant_response_is_not_retried",Case::LostGrant); }
#[test]
fn same_token_discovery_must_admit_the_exact_auth_extension() { isolated("same_token_discovery_must_admit_the_exact_auth_extension",Case::Negotiation); }
#[test]
fn uncertain_mutation_is_not_replayed_or_followed_by_a_token_grant() { isolated("uncertain_mutation_is_not_replayed_or_followed_by_a_token_grant",Case::LostMutation); }
#[test]
fn denied_mutation_is_not_replayed_with_fresh_credentials() { isolated("denied_mutation_is_not_replayed_with_fresh_credentials",Case::DeniedMutation); }
#[test]
fn invalid_request_ids_and_extension_composition_have_no_grant_effect() { isolated("invalid_request_ids_and_extension_composition_have_no_grant_effect",Case::Preflight); }
#[test]
fn request_cancellation_releases_an_idle_token_exchange() { isolated("request_cancellation_releases_an_idle_token_exchange",Case::CancelGrant); }
#[test]
fn source_closure_releases_an_idle_token_exchange() { isolated("source_closure_releases_an_idle_token_exchange",Case::CloseGrant); }
#[test]
fn abandoned_acquisition_releases_its_owned_exchange() { isolated("abandoned_acquisition_releases_its_owned_exchange",Case::DropGrant); }
#[test]
fn acquisition_deadline_does_not_need_peer_traffic_to_fire() { isolated("acquisition_deadline_does_not_need_peer_traffic_to_fire",Case::TimeoutGrant); }
#[test]
fn service_authenticated_sse_is_delivered_before_terminal_completion() { isolated("service_authenticated_sse_is_delivered_before_terminal_completion",Case::Streaming); }
#[test]
fn cancelled_sse_read_cannot_reuse_partial_state() { isolated("cancelled_sse_read_cannot_reuse_partial_state",Case::CancelRead); }
#[test]
fn closed_service_owner_interrupts_active_sse_reads() { isolated("closed_service_owner_interrupts_active_sse_reads",Case::CloseRead); }
#[test]
fn abandoned_sse_read_drops_its_socket() { isolated("abandoned_sse_read_drops_its_socket",Case::DropRead); }
#[test]
fn live_service_response_cannot_outlive_its_opening_token() { isolated("live_service_response_cannot_outlive_its_opening_token",Case::ExpireRead); }
#[test]
fn dropping_last_client_owner_revokes_previously_issued_snapshots() { isolated("dropping_last_client_owner_revokes_previously_issued_snapshots",Case::DropOwner); }
#[test]
fn machine_call_input_required_is_typed_without_automatic_resubmission() { isolated("machine_call_input_required_is_typed_without_automatic_resubmission",Case::InputRequired); }

// New body-password cases deliberately leave the original Basic/JWT fixture
// assertions intact. A request cannot pass by choosing whichever method arrives.
use fastmcp_client::http_auth::discovery::client_credentials::ClientSecretAuthenticationMethod;

const POST_CHILD: &str = "FASTMCP_TEST_CLIENT_SECRET_POST_CASE";
#[derive(Clone, Copy)]
enum PostCase {
    Lifecycle, Encoding, PostAgainstBasic, BasicAgainstPost, BothAdvertised,
    Denied, Redirect, Lost, Cancel, Drop, InvalidToken, WrongOrigin,
}

fn isolated_post(name: &str, case: PostCase) {
    if let Ok(selected) = std::env::var(POST_CHILD) {
        assert_eq!(selected, name);
        run_post(case);
        return;
    }
    let roots = RootFile::create();
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(POST_CHILD, name).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "secret-post TLS case failed");
            return;
        }
        assert!(Instant::now() < end, "secret-post child exceeded its bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

async fn post_metadata(peer: &Peer, case: PostCase) {
    let (mut tls, start, headers, body) = peer.request().await;
    assert_eq!(start, "GET /.well-known/oauth-protected-resource/mcp HTTP/1.1");
    assert!(!headers.contains_key("authorization") && body.is_empty());
    peer.gets.fetch_add(1, Ordering::SeqCst);
    json_reply(&mut tls, &json!({"resource":peer.resource(),
        "authorization_servers":[peer.issuer()],"scopes_supported":["read"]}).to_string()).await;
    drop(tls);
    let (mut tls, start, headers, body) = peer.request().await;
    assert_eq!(start, "GET /.well-known/oauth-authorization-server/issuer HTTP/1.1");
    assert!(!headers.contains_key("authorization") && body.is_empty());
    peer.gets.fetch_add(1, Ordering::SeqCst);
    let methods = match case {
        PostCase::PostAgainstBasic => json!(["client_secret_basic"]),
        PostCase::BothAdvertised | PostCase::Denied | PostCase::Redirect | PostCase::Lost =>
            json!(["private_key_jwt", "client_secret_basic", "client_secret_post"]),
        _ => json!(["client_secret_post"]),
    };
    let token = if matches!(case, PostCase::WrongOrigin) {
        "https://untrusted.example/token".to_owned()
    } else { format!("{}/token", peer.origin()) };
    json_reply(&mut tls, &json!({"issuer":peer.issuer(),"token_endpoint":token,
        "grant_types_supported":["client_credentials"],
        "token_endpoint_auth_methods_supported":methods,"scopes_supported":["read"]}).to_string()).await;
}

async fn post_token_request(peer: &Peer, id: &str, secret: &str) -> TlsStream<TcpStream> {
    let (tls, start, headers, body) = peer.request().await;
    assert_eq!(start, "POST /token HTTP/1.1", "credentials must not enter a query string");
    assert!(!headers.contains_key("authorization"), "body credentials must not be combined with Basic or bearer auth");
    assert!(!headers.values().any(|value| value.contains(secret)));
    assert_eq!(headers["content-type"], "application/x-www-form-urlencoded");
    let raw = std::str::from_utf8(&body).unwrap();
    let fields = form(raw);
    assert_eq!(fields.len(), 5);
    assert_eq!(raw.split('&').count(), 5, "a secret must not inject or duplicate a form field");
    assert_eq!(fields["grant_type"], "client_credentials");
    assert_eq!(fields["resource"], peer.resource());
    assert_eq!(fields["scope"], "read");
    assert_eq!(fields["client_id"], id);
    assert_eq!(fields["client_secret"], secret);
    assert!(!fields.contains_key("client_assertion") && !fields.contains_key("refresh_token"));
    peer.grants.fetch_add(1, Ordering::SeqCst);
    tls
}

async fn post_grant(peer: &Peer, id: &str, secret: &str, token: &str, seconds: u64) {
    let mut tls = post_token_request(peer, id, secret).await;
    json_reply(&mut tls, &json!({"access_token":token,"token_type":"Bearer",
        "expires_in":seconds,"scope":"read","refresh_token":"NEVER-USE-THIS"}).to_string()).await;
}

fn run_post(case: PostCase) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        let scenario = Box::pin(async {
            let peer = Peer::new().await;
            let (id, secret) = if matches!(case, PostCase::Encoding) {
                ("service:β +/%", "secret&scope=admin+%é")
            } else { ("service-client", "service-secret") };
            let root = Certificate::from_pem(ROOT).unwrap().remove(0);
            let issuer = TrustedOAuthIssuer::new(peer.issuer()).unwrap().with_root_certificate(root.clone()).unwrap();
            let mut plan = ClientCredentialsPlan::new(url(&peer.resource()), issuer, id, secret, vec!["read".to_owned()]).unwrap()
                .with_resource_root_certificate(root).unwrap().with_renewal_leeway(Duration::ZERO).unwrap()
                .with_timeout(Duration::from_secs(15)).unwrap();
            if !matches!(case, PostCase::BasicAgainstPost) {
                plan = plan.with_secret_authentication(ClientSecretAuthenticationMethod::Post).unwrap();
                assert!(format!("{plan:?}").contains("client_secret_post"));
            }
            assert!(!format!("{plan:?}").contains(secret));
            let ((), result) = pair(post_metadata(&peer, case), plan.discover(&cx)).await;
            if matches!(case, PostCase::PostAgainstBasic | PostCase::BasicAgainstPost | PostCase::WrongOrigin) {
                let error = result.err().unwrap();
                if matches!(case, PostCase::WrongOrigin) {
                    assert!(matches!(error, Error::Discovery(OAuthDiscoveryError::EndpointNotTrusted)));
                } else { assert!(matches!(error, Error::UnsupportedAuthentication)); }
                assert_eq!(peer.gets.load(Ordering::SeqCst), 2);
                assert_eq!(peer.grants.load(Ordering::SeqCst), 0);
                assert_eq!(peer.rpcs.load(Ordering::SeqCst), 0);
                peer.quiet();
                return;
            }
            let client = result.unwrap();
            match case {
                PostCase::Lifecycle | PostCase::Encoding | PostCase::BothAdvertised => {
                    let seconds = if matches!(case, PostCase::Lifecycle) { 1 } else { 300 };
                    let clone = client.clone();
                    let ((), (one, two)) = pair(post_grant(&peer, id, secret, "post-access", seconds),
                        pair(client.credential(&cx), clone.credential(&cx))).await;
                    let old = one.unwrap();
                    assert_eq!(old.generation(), 1);
                    assert_eq!(two.unwrap().generation(), 1, "concurrent consumers share the same grant");
                    assert!(!format!("{old:?} {client:?}").contains(secret));
                    let ((), response) = pair(peer.operation(1, "tools/list", "post-access", LIST),
                        client.execute_core(&cx, core("tools/list"), RequestId::Number(1), RequestId::Number(2))).await;
                    assert!(response.unwrap().read_json_result(&cx, 4096).await.unwrap().encode().unwrap().contains("1.20e+4"));
                    assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
                    if matches!(case, PostCase::Lifecycle) {
                        Sleep::new(cx.now().saturating_add_nanos(1_100_000_000)).await;
                        assert!(old.credential().authorization_for_target(client.resource()).is_none());
                        let ((), fresh) = pair(post_grant(&peer, id, secret, "post-renewed", 300), client.credential(&cx)).await;
                        assert_eq!(fresh.unwrap().generation(), 2);
                        let ((), response) = pair(peer.operation(3, "tools/call", "post-renewed", CALL),
                            client.execute_core(&cx, core("tools/call"), RequestId::Number(3), RequestId::Number(4))).await;
                        assert!(response.unwrap().read_json_result(&cx, 4096).await.is_ok());
                        assert_eq!(peer.grants.load(Ordering::SeqCst), 2, "renewal must use another Post grant, not refresh_token or Basic");
                        assert_eq!(peer.rpcs.load(Ordering::SeqCst), 4);
                    } else { assert_eq!(peer.rpcs.load(Ordering::SeqCst), 2); }
                }
                PostCase::Denied | PostCase::Redirect | PostCase::Lost | PostCase::InvalidToken => {
                    let server = async {
                        let mut tls = post_token_request(&peer, id, secret).await;
                        match case {
                            PostCase::Denied => {
                                let body = json!({"error":"invalid_client","error_description":secret}).to_string();
                                tls.write_all(format!("HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
                                tls.flush().await.unwrap();
                            }
                            PostCase::Redirect => {
                                tls.write_all(format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: {}/alternate-token\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", peer.origin()).as_bytes()).await.unwrap();
                                tls.flush().await.unwrap();
                            }
                            PostCase::InvalidToken => json_reply(&mut tls,
                                r#"{"access_token":"rejected","token_type":"Bearer","scope":"admin","expires_in":300}"#).await,
                            _ => {},
                        }
                    };
                    let ((), result) = pair(server, client.credential(&cx)).await;
                    let error = result.err().unwrap();
                    assert!(!format!("{error:?} {error}").contains(secret));
                    match case {
                        PostCase::Denied | PostCase::Redirect => assert!(matches!(error, Error::TokenEndpointRejected)),
                        PostCase::Lost => assert!(matches!(error, Error::Transport)),
                        _ => assert!(matches!(error, Error::ExpandedScope)),
                    }
                    assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
                    peer.quiet(); // Even when Basic was advertised, no fallback is sent.
                    if matches!(case, PostCase::InvalidToken) {
                        let ((), fresh) = pair(post_grant(&peer, id, secret, "corrected", 300), client.credential(&cx)).await;
                        assert_eq!(fresh.unwrap().generation(), 1, "rejected response must not install a token");
                        assert_eq!(peer.grants.load(Ordering::SeqCst), 2);
                    }
                    assert_eq!(peer.rpcs.load(Ordering::SeqCst), 0);
                }
                PostCase::Cancel | PostCase::Drop => {
                    let cancellation = McpRequestCancellation::new();
                    let (sent, mut received) = oneshot::channel::<()>();
                    let server = async {
                        let tls = post_token_request(&peer, id, secret).await;
                        sent.send(&cx, ()).unwrap();
                        closed(tls).await;
                    };
                    let application = async {
                        let mut pending = Box::pin(client.credential_with_cancellation(&cx, &cancellation));
                        let mut started = std::pin::pin!(received.recv(&cx));
                        poll_fn(|task| {
                            assert!(pending.as_mut().poll(task).is_pending());
                            started.as_mut().poll(task)
                        }).await.unwrap();
                        if matches!(case, PostCase::Drop) { drop(pending); }
                        else {
                            cancellation.cancel();
                            assert!(matches!(pending.await, Err(Error::Discovery(OAuthDiscoveryError::Cancelled))));
                        }
                    };
                    pair(server, application).await;
                    assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
                    assert_eq!(peer.rpcs.load(Ordering::SeqCst), 0);
                }
                PostCase::PostAgainstBasic | PostCase::BasicAgainstPost | PostCase::WrongOrigin => unreachable!(),
            }
            assert!(cx.checkpoint().is_ok());
            assert_eq!(peer.gets.load(Ordering::SeqCst), 2);
            peer.quiet();
            client.close();
        });
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario).await
            .expect("secret-post TLS scenario must settle within its bound");
    }));
}

#[test]
fn secret_post_login_renewal_and_protected_calls_share_the_selected_method() {
    isolated_post("secret_post_login_renewal_and_protected_calls_share_the_selected_method", PostCase::Lifecycle);
}
#[test]
fn secret_post_preserves_unicode_and_form_delimiters_without_double_encoding() {
    isolated_post("secret_post_preserves_unicode_and_form_delimiters_without_double_encoding", PostCase::Encoding);
}
#[test]
fn secret_post_selection_refuses_basic_only_metadata_before_sending_credentials() {
    isolated_post("secret_post_selection_refuses_basic_only_metadata_before_sending_credentials", PostCase::PostAgainstBasic);
}
#[test]
fn default_basic_refuses_post_only_metadata_before_sending_credentials() {
    isolated_post("default_basic_refuses_post_only_metadata_before_sending_credentials", PostCase::BasicAgainstPost);
}
#[test]
fn advertised_method_order_cannot_override_explicit_secret_post_selection() {
    isolated_post("advertised_method_order_cannot_override_explicit_secret_post_selection", PostCase::BothAdvertised);
}
#[test]
fn denied_secret_post_does_not_retry_as_basic_or_reflect_credentials() {
    isolated_post("denied_secret_post_does_not_retry_as_basic_or_reflect_credentials", PostCase::Denied);
}
#[test]
fn redirected_secret_post_is_not_forwarded_or_replayed() {
    isolated_post("redirected_secret_post_is_not_forwarded_or_replayed", PostCase::Redirect);
}
#[test]
fn lost_secret_post_reply_does_not_switch_authentication_methods() {
    isolated_post("lost_secret_post_reply_does_not_switch_authentication_methods", PostCase::Lost);
}
#[test]
fn cancelled_secret_post_releases_the_pending_exchange() {
    isolated_post("cancelled_secret_post_releases_the_pending_exchange", PostCase::Cancel);
}
#[test]
fn abandoned_secret_post_releases_the_pending_exchange() {
    isolated_post("abandoned_secret_post_releases_the_pending_exchange", PostCase::Drop);
}
#[test]
fn invalid_secret_post_token_does_not_advance_the_cached_generation() {
    isolated_post("invalid_secret_post_token_does_not_advance_the_cached_generation", PostCase::InvalidToken);
}
#[test]
fn secret_post_cannot_send_credentials_to_an_unapproved_endpoint_origin() {
    isolated_post("secret_post_cannot_send_credentials_to_an_unapproved_endpoint_origin", PostCase::WrongOrigin);
}
