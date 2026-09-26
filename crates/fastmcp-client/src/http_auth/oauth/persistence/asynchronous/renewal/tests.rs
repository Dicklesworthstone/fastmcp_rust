use super::*;
use std::collections::BTreeMap;
use std::fs::File;
use std::os::unix::fs::DirBuilderExt;
use std::sync::{Arc, Condvar, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::Instant;

use asupersync::io::AsyncWriteExt;
use fastmcp_core::{CanonicalHttpUrl, partition::{CredentialStoreKey, DurableOwnerKey, PartitionDescriptor}, runtime::ProcessGenerationGuard};
use crate::http_auth::oauth::{bind_loopback, tests as native};
use crate::http_auth::oauth::persistence::{OAuthGrantBinding, OAuthGrantEncoding, OAuthGrantProtectionError};
use crate::http_auth::secure_file::slot::coordinator::{CredentialAnchorBinding, CredentialAnchorError, CredentialAnchorSnapshot, CredentialAnchorState};
use crate::http_auth::secure_file::slot::coordinator::asynchronous::{CredentialIoLane, CredentialIoLimits};

// The file, lock, coordinator, blocking jobs and TLS token exchange are real.
// These two services are intentionally in-memory fault doubles, NOT production
// encryption or independently durable rollback protection. No crash proof.
struct State {
    snapshot: CredentialAnchorSnapshot,
    records: BTreeMap<Vec<u8>, (OAuthGrantBinding, Vec<u8>)>,
    seals: usize,
    opens: usize,
    writes: usize,
    refuse_seal: bool,
    uncertain_settlement: bool,
    open_gate: Option<Arc<OpenGate>>,
}
struct OpenGate { entered: AtomicBool, released: Mutex<bool>, wake: Condvar }
impl OpenGate {
    fn new() -> Arc<Self> { Arc::new(Self { entered: AtomicBool::new(false), released: Mutex::new(false), wake: Condvar::new() }) }
    fn block(&self) {
        self.entered.store(true, Ordering::Release);
        let (released, _) = self.wake.wait_timeout_while(self.released.lock().unwrap(), Duration::from_secs(5), |value| !*value).unwrap();
        assert!(*released, "test provider must be released within its bound");
    }
    fn release(&self) { *self.released.lock().unwrap() = true; self.wake.notify_all(); }
    async fn entered(&self, cx: &Cx) {
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(2_000_000_000), async {
            while !self.entered.load(Ordering::Acquire) { asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await; }
        }).await.unwrap();
    }
}
struct ReleaseOpen(Arc<OpenGate>);
impl Drop for ReleaseOpen { fn drop(&mut self) { self.0.release(); } }
#[derive(Clone)]
struct Provider(Arc<Mutex<State>>);
impl CredentialCommitAnchor for Provider {
    fn current(&mut self, cx: &Cx, binding: &CredentialAnchorBinding) -> Result<CredentialAnchorSnapshot, CredentialAnchorError> {
        cx.checkpoint().map_err(|_| CredentialAnchorError::Unavailable)?;
        let state = self.0.lock().unwrap();
        if state.snapshot.binding() != *binding { return Err(CredentialAnchorError::NotProvisioned); }
        Ok(state.snapshot)
    }
    fn compare_exchange(&mut self, cx: &Cx, expected: &CredentialAnchorSnapshot, next: CredentialAnchorState) -> Result<CredentialAnchorSnapshot, CredentialAnchorError> {
        cx.checkpoint().map_err(|_| CredentialAnchorError::Unavailable)?;
        let mut state = self.0.lock().unwrap();
        if state.snapshot != *expected { return Err(CredentialAnchorError::Conflict); }
        state.snapshot = CredentialAnchorSnapshot::new(expected.binding(), expected.sequence() + 1, next);
        state.writes += 1;
        if state.uncertain_settlement && matches!(next, CredentialAnchorState::Stable(_)) { return Err(CredentialAnchorError::Uncertain); }
        Ok(state.snapshot)
    }
}
impl OAuthGrantProtector for Provider {
    type Plaintext = Vec<u8>;
    fn seal(&mut self, cx: &Cx, binding: &OAuthGrantBinding, grant: &OAuthGrantEncoding<'_>) -> Result<Vec<u8>, OAuthGrantProtectionError> {
        cx.checkpoint().map_err(|_| OAuthGrantProtectionError::Cancelled)?;
        let mut state = self.0.lock().unwrap();
        state.seals += 1;
        if state.refuse_seal { return Err(OAuthGrantProtectionError::Unavailable); }
        let mut bytes = Vec::new();
        grant.write_to(&mut bytes)?;
        let envelope = state.seals.to_be_bytes().to_vec();
        state.records.insert(envelope.clone(), (*binding, bytes));
        Ok(envelope)
    }
    fn open(&mut self, cx: &Cx, binding: &OAuthGrantBinding, envelope: &[u8]) -> Result<Vec<u8>, OAuthGrantProtectionError> {
        cx.checkpoint().map_err(|_| OAuthGrantProtectionError::Cancelled)?;
        let (bytes, gate) = {
            let mut state = self.0.lock().unwrap();
            state.opens += 1;
            let (expected, bytes) = state.records.get(envelope).ok_or(OAuthGrantProtectionError::InvalidEnvelope)?;
            if expected != binding { return Err(OAuthGrantProtectionError::InvalidEnvelope); }
            (bytes.clone(), state.open_gate.take())
        };
        if let Some(gate) = gate { gate.block(); }
        Ok(bytes)
    }
}
struct Fixture {
    directory: std::path::PathBuf,
    key: CredentialStoreKey,
    auth: PartitionAuthorization,
    provider: Provider,
    lane: CredentialIoLane,
}
impl Fixture {
    fn new() -> Self {
        let descriptor = PartitionDescriptor::from_verified_facts("provider", 1, "https://issuer.example", "https://mcp.example/mcp", "tenant", "alice", "native-client", 1, 1, &[b"oauth-resource"]).unwrap();
        let key = CredentialStoreKey::derive(&descriptor, "store", "refresh", "renewal").unwrap();
        let auth = PartitionAuthorization::current(&descriptor, &DurableOwnerKey::derive(&descriptor, 1).unwrap());
        let binding = CredentialAnchorBinding::for_store("renewal", &key, &auth).unwrap();
        let provider = Provider(Arc::new(Mutex::new(State { snapshot: CredentialAnchorSnapshot::new(binding, 0, CredentialAnchorState::Stable(None)), records: BTreeMap::new(), seals: 0, opens: 0, writes: 0, refuse_seal: false, uncertain_settlement: false, open_gate: None })));
        let nonce = fastmcp_core::draw_security_identifier().unwrap();
        let directory = std::env::temp_dir().join(format!("fastmcp-renewal-{}-{}", std::process::id(), crate::http_auth::oauth::hex(nonce.as_bytes())));
        std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let lane = CredentialIoLane::new(ProcessGenerationGuard::install().unwrap(), CredentialIoLimits::new(4, 4, 16 * 1024 * 1024).unwrap()).unwrap();
        Self { directory, key, auth, provider, lane }
    }
    async fn open(&self, cx: &Cx, client: &OAuthClient) -> AsyncOAuthRefreshStore<Provider, Provider> {
        let mut task = AsyncOAuthRefreshStore::open(cx, &self.lane, File::open(&self.directory).unwrap(), "grant".to_owned(), self.key, self.auth, "renewal".to_owned(), self.provider.clone(), self.provider.clone(), client).unwrap();
        task.wait(cx).await.unwrap().unwrap().0
    }
    async fn seed(&self, cx: &Cx, client: &OAuthClient) -> AsyncOAuthRefreshStore<Provider, Provider> {
        let store = self.open(cx, client).await;
        let mut credentials = native::renewable_grant(&client.configuration);
        // Stale access lifetime is intentionally irrelevant to persistent
        // recovery: only a fresh issuer exchange may return usable access.
        credentials.expires_at = Instant::now();
        let (store, (credentials, result)) = store.store_refresh(cx, self.auth, None, credentials).unwrap().wait(cx).await.unwrap().into_parts();
        assert_eq!(result.unwrap().generation(), 1);
        assert!(!credentials.has_refresh_token());
        store.close(cx).unwrap().wait(cx).await.unwrap();
        self.open(cx, client).await
    }
    fn bytes(&self) -> Vec<u8> { std::fs::read(self.directory.join("grant")).unwrap() }
    fn begin(&self, cx: &Cx, client: &OAuthClient, store: AsyncOAuthRefreshStore<Provider, Provider>) -> OAuthRefreshRenewal<Provider, Provider> {
        store.begin_renewal(cx, client, self.auth, &McpRequestCancellation::new(), Duration::from_secs(30)).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.directory.join("grant"));
        let _ = std::fs::remove_file(self.directory.join(".grant.lock"));
        let _ = std::fs::remove_dir(&self.directory);
    }
}
fn run<F: Future<Output = ()>>(scenario: impl FnOnce(Cx) -> F) {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .blocking_threads(1, 4).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(45_000_000_000), Box::pin(scenario(cx))).await.unwrap();
        });
}
async fn peer() -> (asupersync::net::TcpListener, OAuthClient) {
    let listener = bind_loopback().await.unwrap();
    let mut config = native::config().with_extra_root_certificate(native::test_root()).unwrap();
    config.token_endpoint = CanonicalHttpUrl::parse(&format!("https://{}/token", listener.local_addr().unwrap())).unwrap();
    (listener, OAuthClient::new(config))
}
async fn token_reply(listener: &asupersync::net::TcpListener, body: Option<&str>) {
    let (socket, _) = listener.accept().await.unwrap();
    let mut tls = native::test_acceptor().accept(socket).await.unwrap();
    let (head, form) = native::read_token_request(&mut tls).await.unwrap();
    assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
    assert_eq!(form["refresh_token"], "refresh-one");
    assert_eq!(form["grant_type"], "refresh_token");
    assert_eq!(form["client_id"], "native-client");
    assert_eq!(form["resource"], "https://mcp.example/mcp");
    if let Some(body) = body {
        tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        tls.shutdown().await.unwrap();
    }
}
const ROTATED: &str = r#"{"access_token":"renewed-access","token_type":"Bearer","expires_in":120,"refresh_token":"refresh-two","scope":"tools:read"}"#;
fn quiet(listener: &asupersync::net::TcpListener) {
    let mut task = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(listener.poll_accept(&mut task).is_pending(), "no second token exchange");
}
async fn close(cx: &Cx, store: AsyncOAuthRefreshStore<Provider, Provider>) { store.close(cx).unwrap().wait(cx).await.unwrap(); }

#[test]
fn renewal_consumes_exchanges_and_persists_before_delivering_fresh_access() {
    run(|cx| async move {
        let (listener, client) = peer().await;
        let fixture = Fixture::new();
        let store = fixture.seed(&cx, &client).await;
        let before = fixture.bytes();
        let mut renewal = fixture.begin(&cx, &client, store);
        let (_, result) = native::pair(token_reply(&listener, Some(ROTATED)), renewal.run(&cx)).await;
        result.unwrap();
        assert_eq!(renewal.stage(), OAuthRefreshRenewalStage::Complete);
        renewal.run(&cx).await.unwrap(); // observation, not redelivery or replay
        quiet(&listener);
        let OAuthRefreshRenewalCustody::Complete { store, credentials, revision } = renewal.into_custody() else { panic!("completed custody"); };
        assert_eq!(revision.generation(), 3);
        assert!(!credentials.has_refresh_token());
        assert_eq!(credentials.scopes(), ["tools:read".to_owned()]);
        assert_eq!(credentials.bearer_credential().authorization_for_target(&client.configuration.resource), Some("Bearer renewed-access".to_owned()));
        assert!(credentials.expires_at() > Instant::now());
        assert!(credentials.expires_at() <= Instant::now() + Duration::from_secs(120));
        assert_ne!(fixture.bytes(), before);
        assert_eq!(fixture.provider.0.lock().unwrap().writes, 6);
        close(&cx, store).await;
        let store = fixture.open(&cx, &client).await;
        let (store, grant) = store.take_refresh(&cx, fixture.auth).unwrap().wait(&cx).await.unwrap().into_parts();
        assert_eq!(grant.unwrap().unwrap().refresh_token, "refresh-two");
        close(&cx, store).await;
    });
}

#[test]
fn renewal_omitted_rotation_persists_the_same_lineage_only_after_issuer_success() {
    run(|cx| async move {
        let (listener, client) = peer().await;
        let fixture = Fixture::new();
        let store = fixture.seed(&cx, &client).await;
        let mut renewal = fixture.begin(&cx, &client, store);
        let body = r#"{"access_token":"renewed-access","token_type":"Bearer","expires_in":120,"scope":"tools:read"}"#;
        let (_, result) = native::pair(token_reply(&listener, Some(body)), renewal.run(&cx)).await;
        result.unwrap();
        let OAuthRefreshRenewalCustody::Complete { store, .. } = renewal.into_custody() else { panic!("completed custody"); };
        let (store, grant) = store.take_refresh(&cx, fixture.auth).unwrap().wait(&cx).await.unwrap().into_parts();
        assert_eq!(grant.unwrap().unwrap().refresh_token, "refresh-one");
        close(&cx, store).await;
        quiet(&listener);
    });
}

#[test]
fn renewal_lost_or_invalid_token_reply_never_retries_or_restores_consumed_grant() {
    run(|cx| async move {
        for body in [None, Some(r#"{"access_token":"bad-access","token_type":"Bearer","scope":"unrequested:admin"}"#)] {
            let (listener, client) = peer().await;
            let fixture = Fixture::new();
            let store = fixture.seed(&cx, &client).await;
            let mut renewal = fixture.begin(&cx, &client, store);
            let (_, result) = native::pair(token_reply(&listener, body), renewal.run(&cx)).await;
            assert!(matches!(result, Err(OAuthRefreshRenewalError::Context(_))));
            assert_eq!(renewal.stage(), OAuthRefreshRenewalStage::Stopped);
            assert!(matches!(renewal.run(&cx).await, Err(OAuthRefreshRenewalError::Stopped)));
            quiet(&listener);
            let OAuthRefreshRenewalCustody::Stopped { store: Some(store), credentials: None } = renewal.into_custody() else { panic!("exchange cannot retain its old token"); };
            assert_eq!(store.revision().unwrap().generation(), 2);
            let (store, grant) = store.take_refresh(&cx, fixture.auth).unwrap().wait(&cx).await.unwrap().into_parts();
            assert!(grant.unwrap().is_none());
            assert_eq!(fixture.provider.0.lock().unwrap().seals, 1);
            close(&cx, store).await;
        }
    });
}

#[test]
fn renewal_rejects_changed_configuration_before_consuming_a_valid_store() {
    run(|cx| async move {
        let fixture = Fixture::new();
        let client = OAuthClient::new(native::config());
        let store = fixture.seed(&cx, &client).await;
        let before = fixture.bytes();
        let mut changed = client.clone(); changed.configuration.client_id.push_str("-other");
        let failure = match store.begin_renewal(&cx, &changed, fixture.auth, &McpRequestCancellation::new(), Duration::from_secs(30)) {
            Err(failure) => failure, Ok(_) => panic!("changed configuration admitted"),
        };
        let (cause, retained) = failure.into_parts();
        assert!(matches!(cause, AsyncOAuthRefreshError::Store(OAuthRefreshStoreError::ConfigurationMismatch)));
        assert_eq!(fixture.bytes(), before);
        assert_eq!(fixture.provider.0.lock().unwrap().opens, 0);
        close(&cx, retained.unwrap().0).await;
    });
}

#[test]
fn renewal_empty_store_requires_explicit_login_without_contacting_the_issuer() {
    run(|cx| async move {
        let (listener, client) = peer().await;
        let fixture = Fixture::new();
        let store = fixture.open(&cx, &client).await;
        let mut renewal = fixture.begin(&cx, &client, store);
        assert!(matches!(renewal.run(&cx).await, Err(OAuthRefreshRenewalError::NoStoredGrant)));
        quiet(&listener);
        assert_eq!(fixture.provider.0.lock().unwrap().writes, 0);
        let OAuthRefreshRenewalCustody::Stopped { store: Some(store), .. } = renewal.into_custody() else { panic!("store retained"); };
        close(&cx, store).await;
    });
}

#[test]
fn renewal_failed_persistence_keeps_the_new_credentials_but_never_exchanges_again() {
    run(|cx| async move {
        for uncertain in [false, true] {
            let (listener, client) = peer().await;
            let fixture = Fixture::new();
            let store = fixture.seed(&cx, &client).await;
            let mut renewal = fixture.begin(&cx, &client, store);
            assert_eq!(renewal.advance(&cx).await.unwrap(), OAuthRefreshRenewalStage::Taking);
            assert_eq!(renewal.advance(&cx).await.unwrap(), OAuthRefreshRenewalStage::ReadyToExchange);
            let (_, result) = native::pair(token_reply(&listener, Some(ROTATED)), renewal.advance(&cx)).await;
            assert_eq!(result.unwrap(), OAuthRefreshRenewalStage::ReadyToPersist);
            { let mut state = fixture.provider.0.lock().unwrap(); state.refuse_seal = !uncertain; state.uncertain_settlement = uncertain; }
            assert!(matches!(renewal.run(&cx).await, Err(OAuthRefreshRenewalError::Storage(_))));
            assert!(matches!(renewal.run(&cx).await, Err(OAuthRefreshRenewalError::Stopped)));
            quiet(&listener);
            let OAuthRefreshRenewalCustody::Stopped { store: Some(store), credentials: Some(credentials) } = renewal.into_custody() else { panic!("exact write outcome custody"); };
            assert_eq!(credentials.has_refresh_token(), !uncertain);
            assert_eq!(store.requires_recovery(), uncertain);
            close(&cx, store).await;
        }
    });
}

#[test]
fn renewal_shutdown_after_exchange_retains_new_grant_without_second_issuer_effect() {
    run(|cx| async move {
        let (listener, client) = peer().await;
        let fixture = Fixture::new();
        let store = fixture.seed(&cx, &client).await;
        let mut renewal = fixture.begin(&cx, &client, store);
        renewal.advance(&cx).await.unwrap(); renewal.advance(&cx).await.unwrap();
        let (_, result) = native::pair(token_reply(&listener, Some(ROTATED)), renewal.advance(&cx)).await;
        assert_eq!(result.unwrap(), OAuthRefreshRenewalStage::ReadyToPersist);
        fixture.lane.begin_shutdown().unwrap();
        assert!(matches!(renewal.run(&cx).await, Err(OAuthRefreshRenewalError::Submission(AsyncOAuthRefreshError::Io(CredentialIoError::LaneClosed)))));
        assert_eq!(renewal.stage(), OAuthRefreshRenewalStage::ReadyToPersist);
        quiet(&listener);
        let OAuthRefreshRenewalCustody::ReadyToPersist { store, credentials } = renewal.into_custody() else { panic!("admission preserves custody"); };
        assert!(credentials.has_refresh_token());
        assert_eq!(credentials.refresh_token.as_deref(), Some("refresh-two"));
        assert_eq!(store.revision().unwrap().generation(), 2);
        close(&cx, store).await;
        fixture.lane.wait_drained(&cx, Duration::from_secs(2)).await.unwrap();
    });
}

#[test]
fn renewal_precancellation_preserves_the_original_persistent_record() {
    run(|cx| async move {
        let fixture = Fixture::new(); let client = OAuthClient::new(native::config());
        let store = fixture.seed(&cx, &client).await;
        let before = fixture.bytes();
        let mut renewal = fixture.begin(&cx, &client, store);
        renewal.cancel();
        assert!(matches!(renewal.run(&cx).await, Err(OAuthRefreshRenewalError::Context(OAuthError::Cancelled))));
        assert_eq!(renewal.stage(), OAuthRefreshRenewalStage::ReadyToTake);
        assert_eq!(fixture.bytes(), before);
        assert_eq!(fixture.provider.0.lock().unwrap().opens, 0);
        let OAuthRefreshRenewalCustody::ReadyToTake(store) = renewal.into_custody() else { panic!("unstarted custody"); };
        close(&cx, store).await;
    });
}

#[test]
fn renewal_deadline_does_not_restart_when_observation_resumes() {
    run(|cx| async move {
        let fixture = Fixture::new(); let client = OAuthClient::new(native::config());
        let store = fixture.seed(&cx, &client).await;
        let before = fixture.bytes();
        let mut renewal = fixture.begin(&cx, &client, store);
        renewal.deadline = cx.now(); // Plant only the original lifetime boundary.
        for _ in 0..2 { assert!(matches!(renewal.advance(&cx).await, Err(OAuthRefreshRenewalError::Context(OAuthError::TimedOut)))); }
        assert_eq!(fixture.bytes(), before);
        let OAuthRefreshRenewalCustody::ReadyToTake(store) = renewal.into_custody() else { panic!("unstarted custody"); };
        close(&cx, store).await;
    });
}

#[test]
fn renewal_wait_errors_distinguish_terminal_mailbox_failures_from_interruption() {
    for error in [CredentialIoError::WorkerStopped, CredentialIoError::WorkerPanicked, CredentialIoError::AlreadyReceived] { assert!(terminal_completion(error)); }
    for error in [CredentialIoError::WaitCancelled, CredentialIoError::WaitTimedOut, CredentialIoError::CapabilityUnavailable, CredentialIoError::ProcessChanged] { assert!(!terminal_completion(error)); }
}

mod managed;
