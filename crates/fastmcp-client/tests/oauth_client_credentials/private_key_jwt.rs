//! Real TLS client-assertion interoperability. OpenSSL supplies a TEST-ONLY
//! RSA backend with an ephemeral local key; this is not a KMS custody proof.
//! Every received assertion is independently admitted and cryptographically
//! verified by the protocol JOSE verifier before the fixture issues a token.

use super::*;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use fastmcp_client::http_auth::discovery::client_credentials::private_key_jwt::{
    ClientAssertionAudience, PrivateKeyJwtRegistration, JWT_BEARER_ASSERTION_TYPE,
};
use fastmcp_protocol::jose::{
    AdmittedRsaJwks, AttestedRs256PublicKey, ExternalRs256OperationReceipt,
    ExternalRs256SignDisposition, ExternalRs256Signer, ExternalRs256SignerBackend,
    ExternalRs256SigningRequest, RawRs256Signature, RedactedSignerProvenance,
    Rs256SigningBinding, verify_compact_jws_rs256,
};

const PRIVATE_CHILD: &str = "FASTMCP_TEST_PRIVATE_KEY_JWT_CASE";
const KID: &str = "test-service-key";
const HEADER: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qtc2VydmljZS1rZXkifQ";

#[derive(Clone, Copy)]
enum PrivateCase {
    Issuer, Endpoint, Renew, BadMetadata, BadSigner, CancelSigner, CloseSigner,
    AbandonSigner, SignerDeadline, Precancel, RejectedGrants,
    #[cfg(feature = "tasks")]
    Tasks,
}

fn isolated_private(name: &str, case: PrivateCase) {
    if let Ok(selected) = std::env::var(PRIVATE_CHILD) {
        assert_eq!(selected, name); run_private(case); return;
    }
    let roots = RootFile::create();
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(PRIVATE_CHILD, name).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "private-key JWT TLS case failed"); return;
        }
        assert!(Instant::now() < end, "private-key JWT child exceeded its bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

struct KeyDirectory(std::path::PathBuf);
impl KeyDirectory {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        for _ in 0..64 {
            let path = std::env::temp_dir().join(format!("fastmcp-jwt-test-{}-{}",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    let directory = Self(path);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700)).unwrap();
                    }
                    return directory;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(_) => panic!("could not create owned signing fixture directory"),
            }
        }
        panic!("signing fixture directory budget exhausted");
    }
    fn key(&self) -> std::path::PathBuf { self.0.join("test-only-key.pem") }
}
impl Drop for KeyDirectory {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

struct TestSigner {
    directory: KeyDirectory,
    calls: AtomicUsize,
    in_flight: AtomicUsize,
    // 0 signs; 1 unknown; 2 not-dispatched; 3 bad signature; 4 pending;
    // 5 signs correctly but lies about the configuration generation.
    mode: AtomicUsize,
}
struct InFlight<'a>(&'a AtomicUsize);
impl Drop for InFlight<'_> {
    fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); }
}
fn signing_binding() -> Rs256SigningBinding { Rs256SigningBinding::new(1, 2, 3, 4).unwrap() }
impl TestSigner {
    fn create() -> (Arc<Self>, Arc<ExternalRs256Signer>) {
        let directory = KeyDirectory::new();
        let generated = Command::new("openssl").args(["genpkey", "-algorithm", "RSA",
            "-pkeyopt", "rsa_keygen_bits:2048", "-out"]).arg(directory.key())
            .stdout(Stdio::null()).stderr(Stdio::null()).status().expect("OpenSSL is required by this real-signature test");
        assert!(generated.success(), "test RSA key generation failed");
        let modulus = Command::new("openssl").args(["rsa", "-in"]).arg(directory.key())
            .args(["-noout", "-modulus"]).output().unwrap();
        assert!(modulus.status.success());
        let text = std::str::from_utf8(&modulus.stdout).unwrap().trim();
        let hex = text.strip_prefix("Modulus=").unwrap();
        assert_eq!(hex.len(), 512);
        let modulus: Vec<u8> = (0..hex.len()).step_by(2)
            .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).unwrap()).collect();
        let public = AttestedRs256PublicKey::admit(KID, modulus, signing_binding(),
            RedactedSignerProvenance::new("test-only-openssl").unwrap()).unwrap();
        let backend = Arc::new(Self { directory, calls: AtomicUsize::new(0),
            in_flight: AtomicUsize::new(0), mode: AtomicUsize::new(0) });
        let signer = Arc::new(ExternalRs256Signer::new(backend.clone(), public));
        (backend, signer)
    }
}
impl ExternalRs256SignerBackend for TestSigner {
    fn sign<'a>(
        &'a self, _: &'a Cx, request: ExternalRs256SigningRequest,
    ) -> Pin<Box<dyn Future<Output = ExternalRs256SignDisposition> + Send + 'a>> {
        Box::pin(async move {
            let operation = self.calls.fetch_add(1, Ordering::SeqCst) as u64 + 1;
            self.in_flight.fetch_add(1, Ordering::SeqCst);
            let _in_flight = InFlight(&self.in_flight);
            assert!(request.deadline().duration() <= Duration::from_secs(5));
            let mode = self.mode.load(Ordering::SeqCst);
            if mode == 4 { return std::future::pending().await; }
            let binding = if mode == 5 { Rs256SigningBinding::new(1, 2, 3, 99).unwrap() } else { request.binding() };
            let receipt = ExternalRs256OperationReceipt::new(binding, operation,
                RedactedSignerProvenance::new("test-only-openssl").unwrap()).unwrap();
            if mode == 1 { return ExternalRs256SignDisposition::Unknown(receipt); }
            if mode == 2 { return ExternalRs256SignDisposition::NotDispatched(receipt); }
            let signature = if mode == 3 { vec![0; 256] } else {
                // Blocking subprocess work is confined to this TEST backend.
                // Production consumers provide a cancel-correct KMS/HSM adapter.
                let mut child = Command::new("openssl").args(["dgst", "-sha256", "-sign"])
                    .arg(self.directory.key()).stdin(Stdio::piped()).stdout(Stdio::piped())
                    .stderr(Stdio::null()).spawn().unwrap();
                {
                    let mut stdin = child.stdin.take().unwrap();
                    request.input().with_bytes(|bytes| stdin.write_all(bytes).unwrap());
                }
                let signed = child.wait_with_output().unwrap();
                assert!(signed.status.success(), "test RSA signing failed");
                signed.stdout
            };
            ExternalRs256SignDisposition::Dispatched(RawRs256Signature::from_bytes(signature).unwrap(), receipt)
        })
    }
}

fn registration(peer: &Peer, signer: &ExternalRs256Signer, audience: ClientAssertionAudience) -> PrivateKeyJwtRegistration {
    let document = json!({
        "issuer":peer.issuer(), "token_endpoint":format!("{}/token", peer.origin()),
        "resource":peer.resource(), "client_id":"service-client", "grant_types":["client_credentials"],
        "token_endpoint_auth_method":"private_key_jwt", "token_endpoint_auth_signing_alg":"RS256",
        "jwks":serde_json::from_slice::<Value>(signer.canonical_public_jwks().unwrap().as_bytes()).unwrap(),
    });
    PrivateKeyJwtRegistration::from_trusted_json(&serde_json::to_vec(&document).unwrap(), 7,
        Instant::now() + Duration::from_secs(300), signing_binding(), audience).unwrap()
}
fn private_plan(peer: &Peer, signer: Arc<ExternalRs256Signer>, audience: ClientAssertionAudience) -> ClientCredentialsPlan {
    let root = Certificate::from_pem(ROOT).unwrap().remove(0);
    let issuer = TrustedOAuthIssuer::new(peer.issuer()).unwrap().with_root_certificate(root.clone()).unwrap();
    ClientCredentialsPlan::private_key_jwt(issuer, registration(peer, &signer, audience), signer,
        vec!["read".to_owned()]).unwrap().with_resource_root_certificate(root).unwrap()
        .with_timeout(Duration::from_secs(15)).unwrap().with_renewal_leeway(Duration::ZERO).unwrap()
}
fn issuer_document(peer: &Peer) -> Value {
    json!({"issuer":peer.issuer(), "token_endpoint":format!("{}/token", peer.origin()),
        "grant_types_supported":["client_credentials"],
        "token_endpoint_auth_methods_supported":["private_key_jwt", "client_secret_basic"],
        "token_endpoint_auth_signing_alg_values_supported":["RS256"], "scopes_supported":["read"]})
}
async fn serve_metadata(peer: &Peer, issuer: &Value) {
    let (mut tls, start, headers, body) = peer.request().await;
    assert_eq!(start, "GET /.well-known/oauth-protected-resource/mcp HTTP/1.1");
    assert!(!headers.contains_key("authorization") && body.is_empty());
    peer.gets.fetch_add(1, Ordering::SeqCst);
    json_reply(&mut tls, &json!({"resource":peer.resource(), "authorization_servers":[peer.issuer()],
        "scopes_supported":["read"]}).to_string()).await;
    drop(tls);
    let (mut tls, start, headers, body) = peer.request().await;
    assert_eq!(start, "GET /.well-known/oauth-authorization-server/issuer HTTP/1.1");
    assert!(!headers.contains_key("authorization") && body.is_empty());
    peer.gets.fetch_add(1, Ordering::SeqCst);
    json_reply(&mut tls, &issuer.to_string()).await;
}
async fn receive_assertion(
    peer: &Peer, signer: &ExternalRs256Signer, audience: ClientAssertionAudience,
) -> (TlsStream<TcpStream>, String) {
    let (tls, start, headers, bytes) = peer.request().await;
    assert_eq!(start, "POST /token HTTP/1.1");
    assert!(!headers.contains_key("authorization"), "JWT must never fall back to Basic");
    assert_eq!(headers["content-type"], "application/x-www-form-urlencoded");
    let body = std::str::from_utf8(&bytes).unwrap();
    let fields = form(body);
    assert_eq!(body.split('&').count(), fields.len(), "no duplicate form fields");
    assert_eq!(fields.len(), 5);
    assert!(!fields.contains_key("client_id") && !fields.contains_key("client_secret"));
    assert_eq!(fields["grant_type"], "client_credentials");
    assert_eq!(fields["resource"], peer.resource());
    assert_eq!(fields["scope"], "read");
    assert_eq!(fields["client_assertion_type"], JWT_BEARER_ASSERTION_TYPE);
    let assertion = &fields["client_assertion"];
    // Exact protected header demonstrates RS256/kid and absence of typ/jku/jwk.
    assert_eq!(assertion.split('.').next().unwrap(), HEADER);
    let keys = AdmittedRsaJwks::from_json(signer.canonical_public_jwks().unwrap().as_bytes()).unwrap();
    let verified = verify_compact_jws_rs256(assertion, &keys).expect("real RS256 signature must verify");
    assert_eq!(verified.header().kid(), KID);
    let claims = verified.claims();
    assert_eq!(claims.as_object().unwrap().len(), 6);
    assert_eq!(claims["iss"], "service-client"); assert_eq!(claims["sub"], "service-client");
    let expected = match audience { ClientAssertionAudience::Issuer => peer.issuer(),
        ClientAssertionAudience::TokenEndpoint => format!("{}/token", peer.origin()) };
    assert_eq!(claims["aud"], expected);
    let issued = claims["iat"].as_u64().unwrap(); let expiry = claims["exp"].as_u64().unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    assert!(issued <= now && expiry > now && expiry - issued <= 60);
    let jti = claims["jti"].as_str().unwrap().to_owned();
    assert_eq!(jti.len(), 64); assert!(jti.bytes().all(|byte| byte.is_ascii_hexdigit()));
    peer.grants.fetch_add(1, Ordering::SeqCst);
    (tls, jti)
}
async fn grant(peer: &Peer, signer: &ExternalRs256Signer, audience: ClientAssertionAudience, seconds: u64) -> String {
    let (mut tls, jti) = receive_assertion(peer, signer, audience).await;
    json_reply(&mut tls, &json!({"access_token":"access-one", "token_type":"Bearer",
        "expires_in":seconds, "scope":"read"}).to_string()).await;
    jti
}
async fn acquire_jwt(peer: &Peer, signer: &ExternalRs256Signer, audience: ClientAssertionAudience,
    client: &ClientCredentialsClient, cx: &Cx, seconds: u64) -> (String, u64)
{
    let (jti, credential) = pair(grant(peer, signer, audience, seconds), client.credential(cx)).await;
    let credential = credential.unwrap();
    assert!(credential.credential().authorization_for_target(client.resource()).is_some());
    (jti, credential.generation())
}

fn run_private(case: PrivateCase) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap()
        .block_on(Box::pin(async {
            let cx = Cx::current().unwrap();
            let scenario = Box::pin(async {
                let peer = Peer::new().await;
                let (backend, signer) = TestSigner::create();
                let audience = if matches!(case, PrivateCase::Endpoint) { ClientAssertionAudience::TokenEndpoint }
                    else { ClientAssertionAudience::Issuer };
                let plan = private_plan(&peer, signer.clone(), audience);
                let good = issuer_document(&peer);
                if matches!(case, PrivateCase::BadMetadata) {
                    for (field, value) in [
                        ("token_endpoint_auth_signing_alg_values_supported", json!(["ES256"])),
                        ("token_endpoint_auth_methods_supported", json!(["client_secret_basic"])),
                        ("token_endpoint", json!(format!("{}/different", peer.origin()))),
                    ] {
                        let mut wrong = good.clone(); wrong[field] = value;
                        let ((), result) = pair(serve_metadata(&peer, &wrong), plan.discover(&cx)).await;
                        assert!(result.is_err());
                        assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
                        assert_eq!(peer.grants.load(Ordering::SeqCst), 0);
                        peer.quiet();
                    }
                }
                let ((), client) = pair(serve_metadata(&peer, &good), plan.discover(&cx)).await;
                let client = client.unwrap();
                assert_eq!(backend.calls.load(Ordering::SeqCst), 0, "discovery never signs");
                match case {
                    PrivateCase::Issuer | PrivateCase::Endpoint => {
                        let clone = client.clone();
                        let application = async {
                            let (first, second) = pair(client.credential(&cx), clone.credential(&cx)).await;
                            for credential in [first.unwrap(), second.unwrap()] {
                                assert_eq!(credential.generation(), 1);
                                assert_eq!(credential.scopes(), ["read"]);
                            }
                        };
                        pair(grant(&peer, &signer, audience, 300), application).await;
                        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
                        assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
                        let (_, response) = pair(peer.operation(1, "tools/list", "access-one", LIST),
                            client.execute_core(&cx, core("tools/list"), RequestId::Number(1), RequestId::Number(2))).await;
                        let result = response.unwrap().read_json_result(&cx, 4096).await.unwrap();
                        assert!(result.encode().unwrap().contains("1.20e+4"));
                        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
                        assert_eq!(peer.rpcs.load(Ordering::SeqCst), 2);
                    }
                    PrivateCase::Renew => {
                        let (first, generation) = acquire_jwt(&peer, &signer, audience, &client, &cx, 1).await;
                        assert_eq!(generation, 1);
                        Sleep::new(cx.now().saturating_add_nanos(1_100_000_000)).await;
                        let (second, generation) = acquire_jwt(&peer, &signer, audience, &client, &cx, 300).await;
                        assert_ne!(first, second, "each grant must use a fresh jti and signature");
                        assert_eq!(generation, 2); assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
                        assert_eq!(peer.grants.load(Ordering::SeqCst), 2);
                    }
                    PrivateCase::BadMetadata => {
                        assert_eq!(acquire_jwt(&peer, &signer, audience, &client, &cx, 300).await.1, 1);
                        assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
                    }
                    PrivateCase::BadSigner => {
                        for mode in [1, 2, 3, 5] {
                            backend.mode.store(mode, Ordering::SeqCst);
                            let error = client.credential(&cx).await.err().unwrap();
                            assert!(matches!(error, Error::AssertionSigning));
                            assert!(!format!("{error:?} {error}").contains("service-client"));
                            assert_eq!(backend.in_flight.load(Ordering::SeqCst), 0);
                            assert_eq!(peer.grants.load(Ordering::SeqCst), 0);
                            peer.quiet();
                        }
                        assert_eq!(backend.calls.load(Ordering::SeqCst), 4, "no signer retry or Basic fallback");
                        backend.mode.store(0, Ordering::SeqCst);
                        assert_eq!(acquire_jwt(&peer, &signer, audience, &client, &cx, 300).await.1, 1);
                        assert_eq!(backend.calls.load(Ordering::SeqCst), 5);
                    }
                    PrivateCase::CancelSigner | PrivateCase::CloseSigner | PrivateCase::AbandonSigner
                    | PrivateCase::SignerDeadline => {
                        backend.mode.store(4, Ordering::SeqCst);
                        let cancellation = McpRequestCancellation::new();
                        let mut pending = Box::pin(client.credential_with_cancellation(&cx, &cancellation));
                        poll_fn(|task| {
                            assert!(pending.as_mut().poll(task).is_pending());
                            if backend.in_flight.load(Ordering::SeqCst) == 1 { Poll::Ready(()) } else { Poll::Pending }
                        }).await;
                        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
                        if matches!(case, PrivateCase::AbandonSigner) { drop(pending); }
                        else {
                            match case {
                                PrivateCase::CancelSigner => { cancellation.cancel(); },
                                PrivateCase::CloseSigner => client.close(),
                                _ => {},
                            }
                            let error = pending.await.err().unwrap();
                            match case {
                                PrivateCase::CancelSigner => assert!(matches!(error, Error::Discovery(OAuthDiscoveryError::Cancelled))),
                                PrivateCase::CloseSigner => assert!(matches!(error, Error::Closed)),
                                _ => assert!(matches!(error, Error::Discovery(OAuthDiscoveryError::TimedOut))),
                            }
                        }
                        assert_eq!(backend.in_flight.load(Ordering::SeqCst), 0);
                        assert_eq!(peer.grants.load(Ordering::SeqCst), 0); peer.quiet();
                        if !matches!(case, PrivateCase::CloseSigner) {
                            backend.mode.store(0, Ordering::SeqCst);
                            assert_eq!(acquire_jwt(&peer, &signer, audience, &client, &cx, 300).await.1, 1);
                            assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
                        }
                    }
                    PrivateCase::Precancel => {
                        let cancellation = McpRequestCancellation::new(); cancellation.cancel();
                        assert!(matches!(client.credential_with_cancellation(&cx, &cancellation).await,
                            Err(Error::Discovery(OAuthDiscoveryError::Cancelled))));
                        assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
                        assert_eq!(peer.grants.load(Ordering::SeqCst), 0); peer.quiet();
                        assert_eq!(acquire_jwt(&peer, &signer, audience, &client, &cx, 300).await.1, 1);
                    }
                    PrivateCase::RejectedGrants => {
                        let mut previous = None;
                        for status in [400, 307, 0] {
                            let server = async {
                                let (mut tls, jti) = receive_assertion(&peer, &signer, audience).await;
                                if status != 0 {
                                    let response = if status == 307 {
                                        "HTTP/1.1 307 Temporary Redirect\r\nLocation: https://127.0.0.1:9/forbidden\r\nContent-Length: 0\r\n\r\n"
                                    } else { "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n" };
                                    tls.write_all(response.as_bytes()).await.unwrap(); tls.flush().await.unwrap();
                                }
                                jti
                            };
                            let (jti, result) = pair(server, client.credential(&cx)).await;
                            if status == 0 { assert!(matches!(result, Err(Error::Transport))); }
                            else { assert!(matches!(result, Err(Error::TokenEndpointRejected))); }
                            assert_ne!(previous.as_ref(), Some(&jti)); previous = Some(jti);
                            peer.quiet();
                        }
                        assert_eq!(backend.calls.load(Ordering::SeqCst), 3);
                        assert_eq!(peer.grants.load(Ordering::SeqCst), 3);
                        let (fresh, generation) = acquire_jwt(&peer, &signer, audience, &client, &cx, 300).await;
                        assert_ne!(previous.as_ref(), Some(&fresh)); assert_eq!(generation, 1);
                    }
                    #[cfg(feature = "tasks")]
                    PrivateCase::Tasks => tasks_with_private_key(&peer, &signer, &client, &cx, audience).await,
                }
                assert!(cx.checkpoint().is_ok());
                assert_eq!(backend.in_flight.load(Ordering::SeqCst), 0);
                peer.quiet(); client.close();
            });
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario)
                .await.expect("private-key JWT fixture must settle within its bound");
        }));
}

#[cfg(feature = "tasks")]
async fn tasks_with_private_key(peer: &Peer, signer: &ExternalRs256Signer,
    client: &ClientCredentialsClient, cx: &Cx, audience: ClientAssertionAudience)
{
    use fastmcp_client::http_auth::discovery::client_credentials::tasks::{
        ClientCredentialsTasksClient, ClientCredentialsTasksLimits, ManagedTaskEvent, ManagedTaskRequest,
    };
    use fastmcp_client::http_auth::discovery::client_credentials::tasks::subscriptions::ClientCredentialsSubscriptionLimits;
    use fastmcp_client::http_executor::ModernHttpSubscriptionListenEvent;
    use fastmcp_protocol::tasks_extension::{Task, TaskId, TASKS_EXTENSION};
    use fastmcp_protocol::{SubscriptionFilter, FINAL_SUBSCRIPTION_ID_META_KEY};

    async fn rpc(peer: &Peer, id: i64, method: &str) -> TlsStream<TcpStream> {
        let (tls, start, headers, body) = peer.request().await;
        assert_eq!(start, "POST /mcp HTTP/1.1");
        assert_eq!(headers["authorization"], "Bearer access-one");
        assert_eq!(headers["mcp-method"], method);
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["id"], id); assert_eq!(body["method"], method);
        assert_eq!(body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"],
            json!({CLIENT_CREDENTIALS_EXTENSION:{}, TASKS_EXTENSION:{}}));
        if method == "tasks/get" { assert_eq!(body["params"]["taskId"], "signed-task"); }
        if method == "subscriptions/listen" { assert_eq!(body["params"]["notifications"]["taskIds"], json!(["signed-task"])); }
        peer.rpcs.fetch_add(1, Ordering::SeqCst); tls
    }
    let tasks = ClientCredentialsTasksClient::new(client.clone(), FinalRequestMeta::new(ClientCapabilities::default()),
        ClientCredentialsTasksLimits::default()).unwrap();
    let filter: SubscriptionFilter = serde_json::from_value(json!({"taskIds":["signed-task"]})).unwrap();
    let mut discovery: Value = serde_json::from_str(DISCOVERY).unwrap();
    discovery["capabilities"]["extensions"][TASKS_EXTENSION] = json!({});
    let server = async {
        grant(peer, signer, audience, 300).await;
        json_reply(&mut rpc(peer, 1, "server/discover").await, &terminal(1, &discovery.to_string())).await;
        let task = json!({"resultType":"complete", "taskId":"signed-task", "status":"working",
            "createdAt":"2026-09-17T00:00:00Z", "lastUpdatedAt":"2026-09-17T00:00:00Z", "ttlMs":60000});
        json_reply(&mut rpc(peer, 2, "tasks/get").await, &terminal(2, &task.to_string())).await;
        json_reply(&mut rpc(peer, 3, "server/discover").await, &terminal(3, &discovery.to_string())).await;
        let mut tls = rpc(peer, 4, "subscriptions/listen").await;
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
        let acknowledgement = json!({"jsonrpc":"2.0", "method":"notifications/subscriptions/acknowledged",
            "params":{"_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):4}, "notifications":filter}});
        event(&mut tls, &acknowledgement.to_string(), false).await;
        let terminal_result = json!({"resultType":"complete", "_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):4}});
        event(&mut tls, &terminal(4, &terminal_result.to_string()), true).await;
    };
    let application = async {
        let mut call = tasks.request(cx, RequestId::Number(1), RequestId::Number(2),
            ManagedTaskRequest::Get(TaskId::parse("signed-task").unwrap())).await.unwrap();
        let Some(ManagedTaskEvent::Snapshot(snapshot)) = call.next_event(cx).await.unwrap() else { panic!("typed task snapshot required") };
        assert!(matches!(snapshot.task, Task::Working(_)));
        assert!(call.next_event(cx).await.unwrap().is_none());
        let mut subscription = tasks.subscribe(cx, RequestId::Number(3), RequestId::Number(4), filter.clone(),
            ClientCredentialsSubscriptionLimits::default()).await.unwrap();
        assert!(matches!(subscription.next_event(cx).await.unwrap(), Some(ModernHttpSubscriptionListenEvent::Acknowledged { .. })));
        assert!(matches!(subscription.next_event(cx).await.unwrap(), Some(ModernHttpSubscriptionListenEvent::Terminal { .. })));
        assert!(subscription.next_event(cx).await.unwrap().is_none());
    };
    pair(server, application).await;
    assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
    assert_eq!(peer.rpcs.load(Ordering::SeqCst), 4);
}

#[test]
fn rs256_issuer_audience_login_shares_one_grant_and_executes_core_calls() {
    isolated_private("private_key_jwt::rs256_issuer_audience_login_shares_one_grant_and_executes_core_calls", PrivateCase::Issuer);
}
#[test]
fn token_endpoint_audience_is_an_explicit_independent_policy() {
    isolated_private("private_key_jwt::token_endpoint_audience_is_an_explicit_independent_policy", PrivateCase::Endpoint);
}
#[test]
fn renewal_signs_a_fresh_assertion_without_reusing_the_jti() {
    isolated_private("private_key_jwt::renewal_signs_a_fresh_assertion_without_reusing_the_jti", PrivateCase::Renew);
}
#[test]
fn metadata_refusals_have_no_signing_or_grant_effect_and_do_not_poison_the_plan() {
    isolated_private("private_key_jwt::metadata_refusals_have_no_signing_or_grant_effect_and_do_not_poison_the_plan", PrivateCase::BadMetadata);
}
#[test]
fn invalid_unknown_and_undispatched_signer_results_never_reach_the_token_endpoint() {
    isolated_private("private_key_jwt::invalid_unknown_and_undispatched_signer_results_never_reach_the_token_endpoint", PrivateCase::BadSigner);
}
#[test]
fn caller_cancellation_drops_a_pending_signer_without_a_grant() {
    isolated_private("private_key_jwt::caller_cancellation_drops_a_pending_signer_without_a_grant", PrivateCase::CancelSigner);
}
#[test]
fn closing_the_machine_owner_drops_a_pending_signer() {
    isolated_private("private_key_jwt::closing_the_machine_owner_drops_a_pending_signer", PrivateCase::CloseSigner);
}
#[test]
fn abandoning_acquisition_releases_the_signer_and_singleflight_lock() {
    isolated_private("private_key_jwt::abandoning_acquisition_releases_the_signer_and_singleflight_lock", PrivateCase::AbandonSigner);
}
#[test]
fn external_signing_has_its_own_finite_deadline_without_peer_activity() {
    isolated_private("private_key_jwt::external_signing_has_its_own_finite_deadline_without_peer_activity", PrivateCase::SignerDeadline);
}
#[test]
fn precancelled_acquisition_never_calls_the_signer() {
    isolated_private("private_key_jwt::precancelled_acquisition_never_calls_the_signer", PrivateCase::Precancel);
}
#[test]
fn rejected_redirected_and_lost_grants_are_not_replayed() {
    isolated_private("private_key_jwt::rejected_redirected_and_lost_grants_are_not_replayed", PrivateCase::RejectedGrants);
}
#[cfg(feature = "tasks")]
#[test]
fn private_key_login_composes_with_typed_tasks_and_subscriptions() {
    isolated_private("private_key_jwt::private_key_login_composes_with_typed_tasks_and_subscriptions", PrivateCase::Tasks);
}
