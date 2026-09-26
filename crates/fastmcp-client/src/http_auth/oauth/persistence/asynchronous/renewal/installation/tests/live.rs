//! Public persistent-renewal/install/client composition over real files and TLS.
//! Only the initial grant is injected. Renewal uses the native issuer exchange;
//! the protection/anchor are in-memory test doubles, not qualified providers.
use super::*;
use std::collections::BTreeMap;
use std::fs::File;
use std::os::unix::fs::DirBuilderExt;
use std::sync::{Arc, Mutex};

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::tls::TlsStream;
use fastmcp_core::partition::{CredentialStoreKey, DurableOwnerKey, PartitionAuthorization, PartitionDescriptor};
use fastmcp_core::runtime::ProcessGenerationGuard;
use fastmcp_protocol::{ClientCapabilities, CoreRequest, FinalRequestMeta, RequestId};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use serde_json::{Value, json};

use crate::http_auth::oauth::tests as native;
use crate::http_auth::oauth::persistence::{OAuthGrantBinding, OAuthGrantEncoding, OAuthGrantProtectionError, OAuthGrantProtector};
use crate::http_auth::oauth::persistence::asynchronous::renewal::{OAuthRefreshRenewalStage, OAuthRefreshRenewalCustody};
use crate::http_auth::rpc::{ManagedCoreEvent, ManagedCoreLimits};
use crate::http_auth::secure_file::slot::coordinator::{
    CredentialAnchorBinding, CredentialAnchorError, CredentialAnchorSnapshot,
    CredentialAnchorState, CredentialCommitAnchor,
};
use crate::http_auth::secure_file::slot::coordinator::asynchronous::{CredentialIoLane, CredentialIoLimits};
use crate::http_executor::ModernHttpRequest;

type Store = AsyncOAuthRefreshStore<Provider, Provider>;
type Renewal = OAuthRefreshRenewal<Provider, Provider>;
struct State {
    snapshot: CredentialAnchorSnapshot,
    protected: BTreeMap<Vec<u8>, (OAuthGrantBinding, Vec<u8>)>,
    seals: usize,
    writes: usize,
}
#[derive(Clone)]
struct Provider(Arc<Mutex<State>>);
impl CredentialCommitAnchor for Provider {
    fn current(&mut self, cx: &Cx, binding: &CredentialAnchorBinding) -> Result<CredentialAnchorSnapshot, CredentialAnchorError> {
        cx.checkpoint().map_err(|_| CredentialAnchorError::Unavailable)?;
        let state = self.0.lock().unwrap();
        if state.snapshot.binding() != *binding { return Err(CredentialAnchorError::NotProvisioned); }
        Ok(state.snapshot)
    }
    fn compare_exchange(&mut self, cx: &Cx, previous: &CredentialAnchorSnapshot, next: CredentialAnchorState)
        -> Result<CredentialAnchorSnapshot, CredentialAnchorError>
    {
        cx.checkpoint().map_err(|_| CredentialAnchorError::Unavailable)?;
        let mut state = self.0.lock().unwrap();
        if state.snapshot != *previous { return Err(CredentialAnchorError::Conflict); }
        state.snapshot = CredentialAnchorSnapshot::new(previous.binding(), previous.sequence() + 1, next);
        state.writes += 1;
        Ok(state.snapshot)
    }
}
impl OAuthGrantProtector for Provider {
    type Plaintext = Vec<u8>;
    fn seal(&mut self, cx: &Cx, binding: &OAuthGrantBinding, grant: &OAuthGrantEncoding<'_>)
        -> Result<Vec<u8>, OAuthGrantProtectionError>
    {
        cx.checkpoint().map_err(|_| OAuthGrantProtectionError::Cancelled)?;
        let mut bytes = Vec::new(); grant.write_to(&mut bytes)?;
        let mut state = self.0.lock().unwrap(); state.seals += 1;
        let envelope = state.seals.to_be_bytes().to_vec();
        state.protected.insert(envelope.clone(), (*binding, bytes));
        Ok(envelope)
    }
    fn open(&mut self, cx: &Cx, binding: &OAuthGrantBinding, protected: &[u8]) -> Result<Vec<u8>, OAuthGrantProtectionError> {
        cx.checkpoint().map_err(|_| OAuthGrantProtectionError::Cancelled)?;
        let state = self.0.lock().unwrap();
        let (expected, bytes) = state.protected.get(protected).ok_or(OAuthGrantProtectionError::InvalidEnvelope)?;
        if expected != binding { return Err(OAuthGrantProtectionError::InvalidEnvelope); }
        Ok(bytes.clone())
    }
}
struct Fixture { directory: std::path::PathBuf, key: CredentialStoreKey, auth: PartitionAuthorization, lane: CredentialIoLane, provider: Provider }
impl Fixture {
    fn new(client: &OAuthClient) -> Self {
        let descriptor = PartitionDescriptor::from_verified_facts(
            "provider", 1, "https://issuer.example", client.configuration.resource.as_str(),
            "tenant", "alice", "native-client", 1, 1, &[b"oauth-resource"],
        ).unwrap();
        let key = CredentialStoreKey::derive(&descriptor, "store", "refresh", "rotation").unwrap();
        let auth = PartitionAuthorization::current(&descriptor, &DurableOwnerKey::derive(&descriptor, 1).unwrap());
        let binding = CredentialAnchorBinding::for_store("rotation", &key, &auth).unwrap();
        let nonce = fastmcp_core::draw_security_identifier().unwrap();
        let directory = std::env::temp_dir().join(format!("fastmcp-install-{}-{}", std::process::id(), crate::http_auth::oauth::hex(nonce.as_bytes())));
        std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        Self {
            directory, key, auth,
            lane: CredentialIoLane::new(ProcessGenerationGuard::install().unwrap(), CredentialIoLimits::new(4, 8, 32 * 1024 * 1024).unwrap()).unwrap(),
            provider: Provider(Arc::new(Mutex::new(State {
                snapshot: CredentialAnchorSnapshot::new(binding, 0, CredentialAnchorState::Stable(None)),
                protected: BTreeMap::new(), seals: 0, writes: 0,
            }))),
        }
    }
    async fn open(&self, cx: &Cx, client: &OAuthClient) -> Store {
        AsyncOAuthRefreshStore::open(cx, &self.lane, File::open(&self.directory).unwrap(), "grant".to_owned(),
            self.key, self.auth, "rotation".to_owned(), self.provider.clone(), self.provider.clone(), client)
            .unwrap().wait(cx).await.unwrap().unwrap().0
    }
    async fn seed(&self, cx: &Cx, client: &OAuthClient) -> (Store, OAuthCredentials) {
        let store = self.open(cx, client).await;
        let mut credentials = grant(&client.configuration, "bootstrap-access", &["read"], Duration::from_secs(300));
        credentials.refresh_token = Some("refresh-seed".to_owned());
        let (store, (credentials, outcome)) = store.store_refresh(cx, self.auth, None, credentials)
            .unwrap().wait(cx).await.unwrap().into_parts();
        assert_eq!(outcome.unwrap().generation(), 1); assert!(!credentials.has_refresh_token());
        close(cx, store).await;
        (self.open(cx, client).await, credentials)
    }
    fn begin(&self, cx: &Cx, client: &OAuthClient, store: Store) -> Renewal {
        store.begin_renewal(cx, client, self.auth, &McpRequestCancellation::new(), Duration::from_secs(30)).unwrap()
    }
    fn revision(&self) -> u64 {
        let CredentialAnchorState::Stable(Some(revision)) = self.provider.0.lock().unwrap().snapshot.state() else {
            panic!("fixture requires a settled revision");
        };
        revision.generation()
    }
    fn bytes(&self) -> Vec<u8> { std::fs::read(self.directory.join("grant")).unwrap() }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.directory.join("grant"));
        let _ = std::fs::remove_file(self.directory.join(".grant.lock"));
        let _ = std::fs::remove_dir(&self.directory);
    }
}
fn run_io<F: Future<Output = ()>>(work: impl FnOnce(Cx) -> F) {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .blocking_threads(1, 4).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(45_000_000_000), Box::pin(work(cx))).await.unwrap();
        });
}
async fn peers() -> (TcpListener, TcpListener, OAuthClient) {
    let issuer = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let resource = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cfg = config();
    cfg.token_endpoint = CanonicalHttpUrl::parse(&format!("https://{}/token", issuer.local_addr().unwrap())).unwrap();
    cfg.resource = CanonicalHttpUrl::parse(&format!("https://{}/mcp", resource.local_addr().unwrap())).unwrap();
    cfg = cfg.with_extra_root_certificate(native::test_root()).unwrap().with_resource_root_certificate(native::test_root()).unwrap();
    (issuer, resource, OAuthClient::new(cfg))
}
async fn close(cx: &Cx, store: Store) { store.close(cx).unwrap().wait(cx).await.unwrap(); }
fn take_complete(renewal: Renewal) -> Store {
    let OAuthRefreshRenewalCustody::Complete { store, credentials, .. } = renewal.into_custody() else { panic!("completed custody retained"); };
    assert!(!credentials.has_refresh_token()); store
}
fn quiet(listener: &TcpListener) {
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(listener.poll_accept(&mut cx).is_pending(), "no unrequested exchange or MCP replay");
}
async fn json_reply(socket: &mut TlsStream<TcpStream>, body: &str) {
    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    socket.shutdown().await.unwrap();
}
async fn renew(cx: &Cx, fixture: &Fixture, client: &OAuthClient, issuer: &TcpListener, store: Store,
    expected_refresh: &str, new_access: &str, new_refresh: &str, tombstone: u64) -> Renewal
{
    let mut renewal = fixture.begin(cx, client, store);
    let server = async {
        let (socket, _) = issuer.accept().await.unwrap();
        let mut tls = native::test_acceptor().accept(socket).await.unwrap();
        let (head, form) = native::read_token_request(&mut tls).await.unwrap();
        assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
        assert_eq!(form["grant_type"], "refresh_token"); assert_eq!(form["refresh_token"], expected_refresh);
        assert_eq!(form["resource"], client.configuration.resource.as_str()); assert_eq!(form["scope"], "read");
        assert_eq!(fixture.revision(), tombstone, "consume settles before issuer contact");
        let body = json!({"access_token":new_access,"token_type":"Bearer","expires_in":120,
            "refresh_token":new_refresh,"scope":"read"}).to_string();
        json_reply(&mut tls, &body).await;
    };
    let (_, outcome) = native::pair(server, renewal.run(cx)).await; outcome.unwrap();
    assert_eq!(fixture.revision(), tombstone + 1);
    assert_eq!(renewal.stage(), OAuthRefreshRenewalStage::Complete);
    renewal
}
async fn request(socket: &mut TlsStream<TcpStream>) -> (String, Value) {
    let mut wire = Vec::new(); let mut chunk = [0; 2048];
    let end = loop {
        let n = socket.read(&mut chunk).await.unwrap(); assert!(n > 0 && wire.len() + n <= 65536);
        wire.extend_from_slice(&chunk[..n]);
        if let Some(i) = wire.windows(4).position(|part| part == b"\r\n\r\n") { break i + 4; }
    };
    let head = std::str::from_utf8(&wire[..end]).unwrap().to_owned();
    let length = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
    }).unwrap();
    assert!(end + length <= 65536);
    while wire.len() < end + length {
        let n = socket.read(&mut chunk).await.unwrap(); assert!(n > 0 && wire.len() + n <= 65536);
        wire.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(wire.len(), end + length);
    (head, serde_json::from_slice(&wire[end..]).unwrap())
}
fn params() -> Value {
    json!({"_meta":serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap(),
        "name":"echo","arguments":{"value":"same-owner"}})
}
async fn mcp_peer(listener: &TcpListener, fixture: &Fixture, token: &str, id: i64, revision: u64) {
    let (socket, _) = listener.accept().await.unwrap();
    let mut tls = native::test_acceptor().accept(socket).await.unwrap();
    let (head, body) = request(&mut tls).await;
    assert!(head.starts_with("POST /mcp HTTP/1.1\r\n"));
    assert!(head.to_ascii_lowercase().contains(&format!("authorization: bearer {token}\r\n")));
    assert!(!head.to_ascii_lowercase().contains("mcp-session-id:"));
    assert_eq!(body["id"], id); assert_eq!(body["method"], "tools/call"); assert_eq!(body["params"], params());
    assert_eq!(fixture.revision(), revision, "persisted replacement precedes dispatch");
    json_reply(&mut tls, &json!({"jsonrpc":"2.0","id":id,"result":{
        "resultType":"complete","content":[{"type":"text","text":token}]}}).to_string()).await;
}
async fn call(cx: &Cx, session: &ManagedOAuthSession, id: i64, generation: u64, token: &str) {
    let core = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params())).unwrap();
    let mut call = session.request_core(cx, core, RequestId::Number(id), ManagedCoreLimits::default()).await.unwrap();
    assert_eq!(call.credential_generation(), generation);
    let Some(ManagedCoreEvent::Result(result)) = call.next_event(cx).await.unwrap() else { panic!("complete result"); };
    let result: Value = serde_json::from_str(&result.encode().unwrap()).unwrap();
    assert_eq!(result["content"][0]["text"], token);
    assert!(call.next_event(cx).await.unwrap().is_none());
}

#[test]
fn two_persisted_rotations_keep_existing_clones_on_the_same_managed_session() {
    run_io(|cx| async move {
        let (issuer, resource, client) = peers().await; let fixture = Fixture::new(&client);
        let (mut store, credentials) = fixture.seed(&cx, &client).await;
        let session = ManagedOAuthSession::from_credentials(&cx, client.clone(), OAuthSessionPolicy::default(), credentials).unwrap();
        let existing = session.clone(); let old = existing.credential(&cx).await.unwrap(); let old_expiry = old.expires_at();
        for (index, refresh, access, next_refresh) in [(0_u64, "refresh-seed", "rotation-one", "refresh-one"), (1, "refresh-one", "rotation-two", "refresh-two")] {
            let mut renewal = renew(&cx, &fixture, &client, &issuer, store, refresh, access, next_refresh, 2 + 2 * index).await;
            let bytes = fixture.bytes();
            let (returned, receipt) = renewal.install_managed_access(&cx, &session, 1 + index).await.unwrap(); store = returned;
            assert_eq!(receipt.session_generation(), 2 + index); assert_eq!(receipt.stored_revision().generation(), 3 + 2 * index);
            assert_eq!(fixture.bytes(), bytes, "installation performs no storage write");
            assert!(matches!(renewal.install_managed_access(&cx, &session, 2 + index).await, Err(OAuthAccessRotationError::NotComplete)));
            native::pair(mcp_peer(&resource, &fixture, access, 100 + index as i64, 3 + 2 * index),
                call(&cx, &existing, 100 + index as i64, 2 + index, access)).await;
        }
        assert_eq!(old.generation(), 1); assert_eq!(old.expires_at(), old_expiry);
        session.close(); assert!(old.credential().authorization_for_target(&client.configuration.resource).is_none());
        close(&cx, store).await;
        let reopened = fixture.open(&cx, &client).await;
        let (reopened, outcome) = reopened.take_refresh(&cx, fixture.auth).unwrap().wait(&cx).await.unwrap().into_parts();
        assert_eq!(outcome.unwrap().unwrap().refresh_token, "refresh-two"); close(&cx, reopened).await;
        quiet(&issuer); quiet(&resource);
    });
}

#[test]
fn refused_installation_retains_the_completed_grant_without_reexchanging() {
    run_io(|cx| async move {
        let (issuer, resource, client) = peers().await; let fixture = Fixture::new(&client);
        let (store, credentials) = fixture.seed(&cx, &client).await;
        let session = ManagedOAuthSession::from_credentials(&cx, client.clone(), OAuthSessionPolicy::default(), credentials).unwrap();
        let mut renewal = renew(&cx, &fixture, &client, &issuer, store, "refresh-seed", "rotated", "refresh-one", 2).await;
        let bytes = fixture.bytes();
        assert!(matches!(renewal.install_managed_access(&cx, &session, 0).await, Err(OAuthAccessRotationError::GenerationMismatch)));
        assert_eq!(renewal.stage(), OAuthRefreshRenewalStage::Complete); assert_eq!(fixture.bytes(), bytes);
        assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
        let (store, receipt) = renewal.install_managed_access(&cx, &session, 1).await.unwrap();
        assert_eq!(receipt.session_generation(), 2); quiet(&issuer); quiet(&resource); close(&cx, store).await;
    });
}

#[test]
fn abandoned_install_wait_preserves_completed_custody_and_original_generation() {
    run_io(|cx| async move {
        let (issuer, resource, client) = peers().await; let fixture = Fixture::new(&client);
        let (store, credentials) = fixture.seed(&cx, &client).await;
        let session = ManagedOAuthSession::from_credentials(&cx, client.clone(), OAuthSessionPolicy::default(), credentials).unwrap();
        let mut renewal = renew(&cx, &fixture, &client, &issuer, store, "refresh-seed", "rotated", "refresh-one", 2).await;
        let candidate = grant(&client.configuration, "lock-only", &["read"], Duration::from_secs(300));
        let cancel = McpRequestCancellation::new();
        let held = session.reserve_access_rotation(&cx, &cancel, 1, &candidate).await.unwrap();
        let mut waiting = Box::pin(renewal.install_managed_access(&cx, &session, 1));
        pending(waiting.as_mut()).await; drop(waiting); drop(held);
        assert_eq!(renewal.stage(), OAuthRefreshRenewalStage::Complete); assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
        let (store, receipt) = renewal.install_managed_access(&cx, &session, 1).await.unwrap();
        assert_eq!(receipt.session_generation(), 2); close(&cx, store).await; quiet(&issuer); quiet(&resource);
    });
}

#[test]
fn cancellation_during_install_wait_preserves_completed_store_for_cleanup() {
    run_io(|cx| async move {
        let (issuer, resource, client) = peers().await; let fixture = Fixture::new(&client);
        let (store, credentials) = fixture.seed(&cx, &client).await;
        let session = ManagedOAuthSession::from_credentials(&cx, client.clone(), OAuthSessionPolicy::default(), credentials).unwrap();
        let mut renewal = renew(&cx, &fixture, &client, &issuer, store, "refresh-seed", "rotated", "refresh-one", 2).await;
        let candidate = grant(&client.configuration, "lock-only", &["read"], Duration::from_secs(300));
        let held_cancel = McpRequestCancellation::new();
        let held = session.reserve_access_rotation(&cx, &held_cancel, 1, &candidate).await.unwrap();
        let cancel = renewal.cancellation.clone(); let mut waiting = Box::pin(renewal.install_managed_access(&cx, &session, 1));
        pending(waiting.as_mut()).await; cancel.cancel();
        assert!(matches!(waiting.await, Err(OAuthAccessRotationError::Session(OAuthSessionError::Cancelled)) | Err(OAuthAccessRotationError::Context(OAuthError::Cancelled))));
        drop(held); assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
        assert_eq!(renewal.stage(), OAuthRefreshRenewalStage::Complete);
        close(&cx, take_complete(renewal)).await; quiet(&issuer); quiet(&resource);
    });
}

#[test]
fn closed_target_cannot_be_revived_while_an_installation_waits() {
    run_io(|cx| async move {
        let (issuer, resource, client) = peers().await; let fixture = Fixture::new(&client);
        let (store, credentials) = fixture.seed(&cx, &client).await;
        let session = ManagedOAuthSession::from_credentials(&cx, client.clone(), OAuthSessionPolicy::default(), credentials).unwrap();
        let old = session.credential(&cx).await.unwrap();
        let mut renewal = renew(&cx, &fixture, &client, &issuer, store, "refresh-seed", "rotated", "refresh-one", 2).await;
        let candidate = grant(&client.configuration, "lock-only", &["read"], Duration::from_secs(300)); let cancel = McpRequestCancellation::new();
        let held = session.reserve_access_rotation(&cx, &cancel, 1, &candidate).await.unwrap();
        let mut waiting = Box::pin(renewal.install_managed_access(&cx, &session, 1)); pending(waiting.as_mut()).await; session.close();
        assert!(matches!(waiting.await, Err(OAuthAccessRotationError::Session(OAuthSessionError::Closed)))); drop(held);
        assert!(old.credential().authorization_for_target(&client.configuration.resource).is_none());
        assert_eq!(renewal.stage(), OAuthRefreshRenewalStage::Complete);
        close(&cx, take_complete(renewal)).await; quiet(&issuer); quiet(&resource);
    });
}

#[test]
fn original_renewal_deadline_still_bounds_installation_after_persistence() {
    run_io(|cx| async move {
        let (issuer, resource, client) = peers().await; let fixture = Fixture::new(&client);
        let (store, credentials) = fixture.seed(&cx, &client).await;
        let session = ManagedOAuthSession::from_credentials(&cx, client.clone(), OAuthSessionPolicy::default(), credentials).unwrap();
        let mut renewal = renew(&cx, &fixture, &client, &issuer, store, "refresh-seed", "rotated", "refresh-one", 2).await;
        // Plant a shorter remaining original budget only after the real file
        // and token phases, so their variable runtime is not the test's clock.
        renewal.deadline = cx.now().saturating_add_nanos(30_000_000);
        let candidate = grant(&client.configuration, "lock-only", &["read"], Duration::from_secs(300)); let cancel = McpRequestCancellation::new();
        let held = session.reserve_access_rotation(&cx, &cancel, 1, &candidate).await.unwrap();
        assert!(matches!(renewal.install_managed_access(&cx, &session, 1).await, Err(OAuthAccessRotationError::Context(OAuthError::TimedOut))));
        drop(held); assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
        assert_eq!(renewal.stage(), OAuthRefreshRenewalStage::Complete);
        close(&cx, take_complete(renewal)).await; quiet(&issuer); quiet(&resource);
    });
}

#[test]
fn an_in_flight_response_keeps_old_expiry_after_persisted_access_installation() {
    run_io(|cx| async move {
        let (issuer, resource, client) = peers().await; let fixture = Fixture::new(&client);
        let (store, mut credentials) = fixture.seed(&cx, &client).await;
        let mut renewal = renew(&cx, &fixture, &client, &issuer, store, "refresh-seed", "rotated", "refresh-one", 2).await;
        // Controlled initial access fixture. Storage and TLS renewal are already
        // done; no variable fsync latency is charged to this response-expiry test.
        credentials.expires_at = Instant::now() + Duration::from_millis(500);
        let session = ManagedOAuthSession::from_credentials(&cx, client.clone(), OAuthSessionPolicy::default(), credentials).unwrap();
        let existing = session.clone();
        let server = async {
            let (socket, _) = resource.accept().await.unwrap(); let mut tls = native::test_acceptor().accept(socket).await.unwrap();
            let (head, body) = request(&mut tls).await;
            assert!(head.to_ascii_lowercase().contains("authorization: bearer bootstrap-access\r\n")); assert_eq!(body["id"], 90);
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap(); tls.flush().await.unwrap();
            let mut byte = [0]; assert!(!matches!(tls.read(&mut byte).await, Ok(n) if n > 0), "expired old response releases its socket");
            mcp_peer(&resource, &fixture, "rotated", 91, 3).await;
        };
        let application = async {
            let wire = ModernHttpRequest::new(client.configuration.resource.as_str(),
                serde_json::to_vec(&json!({"jsonrpc":"2.0","id":90,"method":"tools/call","params":params()})).unwrap(),
                "2026-07-28", "tools/call", None).unwrap();
            let response = existing.execute(&cx, &wire).await.unwrap(); assert_eq!(response.credential_generation(), 1);
            let (store, receipt) = renewal.install_managed_access(&cx, &session, 1).await.unwrap(); assert_eq!(receipt.session_generation(), 2);
            assert!(matches!(response.read_to_end(&cx, 4096).await, Err(OAuthSessionError::LoginRequired)));
            call(&cx, &existing, 91, 2, "rotated").await;
            close(&cx, store).await;
        };
        native::pair(server, application).await; quiet(&issuer); quiet(&resource);
    });
}
