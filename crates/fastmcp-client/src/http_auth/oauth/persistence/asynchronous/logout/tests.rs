//! Real files/coordinator/blocking runtime and native TLS, with declared
//! in-memory opaque-service and anchor doubles. These do not qualify a durable
//! encryption service, independent rollback protection, or process-crash recovery.
use super::*;
use super::grant_tests::{fixture as issuer, no_more_requests, peer_request};
use std::collections::BTreeMap;
use std::fs::File;
use std::os::unix::fs::DirBuilderExt;
use std::sync::{Arc, Condvar, Mutex, atomic::{AtomicBool, Ordering}};

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use crate::http_auth::managed::OAuthSessionPolicy;
use crate::http_auth::oauth::{OAuthClientConfiguration, tests as native};
use crate::http_auth::oauth::persistence::{OAuthGrantBinding, OAuthGrantEncoding, OAuthGrantProtectionError};
use crate::http_auth::secure_file::{AtomicFileError, slot::CredentialSlotError};
use crate::http_auth::secure_file::slot::coordinator::{
    CoordinatedSlotError, CredentialAnchorBinding, CredentialAnchorError,
    CredentialAnchorSnapshot, CredentialAnchorState,
};
use crate::http_auth::secure_file::slot::coordinator::asynchronous::{CredentialIoLane, CredentialIoLimits};
use fastmcp_core::{partition::{CredentialStoreKey, DurableOwnerKey, PartitionDescriptor}, runtime::ProcessGenerationGuard};

#[derive(Default)]
struct State {
    vault: BTreeMap<Vec<u8>, (OAuthGrantBinding, Vec<u8>)>,
    anchor: Option<CredentialAnchorSnapshot>,
    seals: usize, opens: usize, reads: usize, writes: usize,
    unreadable: bool, uncertain: Option<bool>,
    opening: Option<Arc<Gate>>, settled: Option<Arc<Gate>>,
}
#[derive(Clone, Default)]
struct Provider(Arc<Mutex<State>>);
impl OAuthGrantProtector for Provider {
    type Plaintext = Vec<u8>;
    fn seal(&mut self, cx: &Cx, binding: &OAuthGrantBinding, grant: &OAuthGrantEncoding<'_>)
        -> Result<Vec<u8>, OAuthGrantProtectionError>
    {
        cx.checkpoint().map_err(|_| OAuthGrantProtectionError::Cancelled)?;
        let mut bytes = Vec::new(); grant.write_to(&mut bytes)?;
        let mut s = self.0.lock().unwrap();
        s.seals += 1;
        let envelope = s.seals.to_be_bytes().to_vec();
        s.vault.insert(envelope.clone(), (*binding, bytes));
        Ok(envelope)
    }
    fn open(&mut self, cx: &Cx, binding: &OAuthGrantBinding, envelope: &[u8])
        -> Result<Vec<u8>, OAuthGrantProtectionError>
    {
        cx.checkpoint().map_err(|_| OAuthGrantProtectionError::Cancelled)?;
        let (bytes, gate) = {
            let mut s = self.0.lock().unwrap(); s.opens += 1;
            if s.unreadable { return Err(OAuthGrantProtectionError::Unavailable); }
            let (actual, bytes) = s.vault.get(envelope).ok_or(OAuthGrantProtectionError::InvalidEnvelope)?;
            if actual != binding { return Err(OAuthGrantProtectionError::InvalidEnvelope); }
            (bytes.clone(), s.opening.take())
        };
        if let Some(gate) = gate { gate.block(); }
        Ok(bytes)
    }
}
impl CredentialCommitAnchor for Provider {
    fn current(&mut self, cx: &Cx, binding: &CredentialAnchorBinding)
        -> Result<CredentialAnchorSnapshot, CredentialAnchorError>
    {
        cx.checkpoint().map_err(|_| CredentialAnchorError::Unavailable)?;
        let mut s = self.0.lock().unwrap(); s.reads += 1;
        s.anchor.filter(|value| value.binding() == *binding).ok_or(CredentialAnchorError::NotProvisioned)
    }
    fn compare_exchange(&mut self, cx: &Cx, old: &CredentialAnchorSnapshot, next: CredentialAnchorState)
        -> Result<CredentialAnchorSnapshot, CredentialAnchorError>
    {
        cx.checkpoint().map_err(|_| CredentialAnchorError::Unavailable)?;
        let (value, gate, uncertain) = {
            let mut s = self.0.lock().unwrap();
            if s.anchor.as_ref() != Some(old) { return Err(CredentialAnchorError::Conflict); }
            let value = CredentialAnchorSnapshot::new(old.binding(), old.sequence() + 1, next);
            s.anchor = Some(value); s.writes += 1;
            let settled = matches!(next, CredentialAnchorState::Stable(_));
            let gate = if settled { s.settled.take() } else { None };
            let uncertain = s.uncertain == Some(settled);
            if uncertain { s.uncertain = None; }
            (value, gate, uncertain)
        };
        if let Some(gate) = gate { gate.block(); }
        if uncertain { Err(CredentialAnchorError::Uncertain) } else { Ok(value) }
    }
}

struct Gate { entered: AtomicBool, released: Mutex<bool>, condition: Condvar }
impl Gate {
    fn new() -> Arc<Self> { Arc::new(Self { entered: AtomicBool::new(false), released: Mutex::new(false), condition: Condvar::new() }) }
    fn block(&self) {
        self.entered.store(true, Ordering::Release);
        let (released, _) = self.condition.wait_timeout_while(self.released.lock().unwrap(), Duration::from_secs(5), |r| !*r).unwrap();
        assert!(*released, "fixture gate exceeded its bound");
    }
    fn release(&self) { *self.released.lock().unwrap() = true; self.condition.notify_all(); }
    async fn entered(&self, cx: &Cx) {
        while !self.entered.load(Ordering::Acquire) { asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await; }
    }
}
struct Release(Arc<Gate>);
impl Drop for Release { fn drop(&mut self) { self.0.release(); } }

fn identity(subject: &str) -> (CredentialStoreKey, PartitionAuthorization) {
    let d = PartitionDescriptor::from_verified_facts("provider", 1, "https://issuer.example", "https://mcp.example/mcp",
        "tenant", subject, "native-client", 1, 1, &[b"oauth-resource"]).unwrap();
    let owner = DurableOwnerKey::derive(&d, 1).unwrap();
    (CredentialStoreKey::derive(&d, "store", "refresh", "logout").unwrap(), PartitionAuthorization::current(&d, &owner))
}
type Store = AsyncOAuthRefreshStore<Provider, Provider>;
struct Fixture { directory: std::path::PathBuf, provider: Provider, key: CredentialStoreKey, auth: PartitionAuthorization }
impl Fixture {
    fn new() -> Self {
        let nonce = fastmcp_core::draw_security_identifier().unwrap();
        let directory = std::env::temp_dir().join(format!("fastmcp-logout-{}-{}", std::process::id(), crate::http_auth::oauth::hex(nonce.as_bytes())));
        std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let (key, auth) = identity("alice");
        let binding = CredentialAnchorBinding::for_store("logout", &key, &auth).unwrap();
        let provider = Provider::default();
        provider.0.lock().unwrap().anchor = Some(CredentialAnchorSnapshot::new(binding, 0, CredentialAnchorState::Stable(None)));
        Self { directory, provider, key, auth }
    }
    fn opening(&self, cx: &Cx, lane: &CredentialIoLane, client: &OAuthClient)
        -> Result<CredentialSlotTask<super::super::OAuthRefreshOpen<Provider, Provider>>, AsyncOAuthRefreshError>
    {
        Store::open(cx, lane, File::open(&self.directory).unwrap(), "grant".to_owned(), self.key, self.auth,
            "logout".to_owned(), self.provider.clone(), self.provider.clone(), client)
    }
    async fn open(&self, cx: &Cx, lane: &CredentialIoLane, client: &OAuthClient) -> Store {
        done(cx, lane, self.opening(cx, lane, client)).await.unwrap().0
    }
    async fn seed(&self, cx: &Cx, lane: &CredentialIoLane, config: &OAuthClientConfiguration)
        -> (Store, super::super::OAuthCredentials)
    {
        let store = self.open(cx, lane, &OAuthClient::new(config.clone())).await;
        let (store, (credentials, outcome)) = done(cx, lane,
            store.store_refresh(cx, self.auth, None, native::renewable_grant(config))).await.into_parts();
        assert_eq!(outcome.unwrap().generation(), 1);
        assert!(!credentials.has_refresh_token());
        (store, credentials)
    }
    fn bytes(&self) -> Vec<u8> { std::fs::read(self.directory.join("grant")).unwrap() }
    fn counts(&self) -> (usize, usize, usize) { let s = self.provider.0.lock().unwrap(); (s.opens, s.reads, s.writes) }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Only this fixture's two exact leaves and empty directory are removed.
        let _ = std::fs::remove_file(self.directory.join("grant"));
        let _ = std::fs::remove_file(self.directory.join(".grant.lock"));
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn lane(operations: usize) -> CredentialIoLane {
    CredentialIoLane::new(ProcessGenerationGuard::install().unwrap(), CredentialIoLimits::new(4, operations, 8 * 1024 * 1024).unwrap()).unwrap()
}
async fn settled(cx: &Cx, lane: &CredentialIoLane) {
    loop {
        let s = lane.snapshot().unwrap();
        if s.operations == 0 && s.closes == 0 { break; }
        asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
    }
}
async fn done<T>(cx: &Cx, lane: &CredentialIoLane, task: Result<CredentialSlotTask<T>, AsyncOAuthRefreshError>) -> T {
    let value = task.unwrap().wait(cx).await.unwrap(); settled(cx, lane).await; value
}
fn run(work: impl Future<Output = ()>) {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .blocking_threads(1, 4).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(30_000_000_000), work).await.unwrap();
        });
}
fn begin(store: Store, cx: &Cx, client: &OAuthClient, auth: PartitionAuthorization) -> OAuthRefreshLogout<Provider, Provider> {
    store.begin_logout(cx, client, auth, None, &McpRequestCancellation::new(), Duration::from_secs(15)).unwrap()
}
fn take_store(logout: OAuthRefreshLogout<Provider, Provider>) -> Store {
    match logout.into_custody().1 {
        OAuthRefreshLogoutCustody::Complete(store) | OAuthRefreshLogoutCustody::Stopped(Some(store))
            | OAuthRefreshLogoutCustody::ReadyToRetire(store) => store,
        OAuthRefreshLogoutCustody::ReadyToRevoke { store, grant } => { drop(grant); store }
        _ => panic!("expected directly retained store, not pending work"),
    }
}

#[test]
fn persistent_logout_closes_session_then_retires_before_one_native_issuer_attempt() {
    run(async {
        let cx = Cx::current().unwrap();
        for status in [Some(200), Some(503), None] {
            let (listener, config) = issuer().await; let client = OAuthClient::new(config.clone());
            let f = Fixture::new(); let lane = lane(1);
            let (store, credentials) = f.seed(&cx, &lane, &config).await;
            let session = ManagedOAuthSession::from_credentials(&cx, client.clone(), OAuthSessionPolicy::default(), credentials).unwrap();
            let sibling = ManagedOAuthSession::from_credentials(&cx, client.clone(), OAuthSessionPolicy::default(), native::renewable_grant(&config)).unwrap();
            let snapshot = session.credential(&cx).await.unwrap(); let clone = session.clone();
            let mut logout = store.begin_logout(&cx, &client, f.auth, Some(&session), &McpRequestCancellation::new(), Duration::from_secs(15)).unwrap();
            assert!(snapshot.credential().is_revoked()); assert!(clone.credential(&cx).await.is_err());
            assert!(sibling.credential(&cx).await.is_ok());
            assert!(logout.report().local_session_closed()); assert_eq!(logout.report().retired_revision(), None);
            let server = async {
                let mut tls = peer_request(&listener).await;
                {
                    let s = f.provider.0.lock().unwrap();
                    let CredentialAnchorState::Stable(Some(revision)) = s.anchor.unwrap().state() else { panic!("remote request preceded durable retirement"); };
                    assert_eq!(revision.generation(), 2); assert_eq!(s.writes, 4);
                }
                if let Some(status) = status {
                    tls.write_all(format!("HTTP/1.1 {status} Fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                    tls.shutdown().await.unwrap();
                }
            };
            let ((), report) = Box::pin(native::pair(server, logout.run(&cx))).await;
            let report = report.unwrap(); assert_eq!(report.retired_revision().unwrap().generation(), 2);
            assert_eq!(report.remote(), OAuthPersistentRevocation::Outcome(match status {
                Some(200) => OAuthTokenRevocationOutcome::Succeeded,
                Some(status) => OAuthTokenRevocationOutcome::Rejected { status },
                None => OAuthTokenRevocationOutcome::Uncertain,
            }));
            assert_eq!(logout.run(&cx).await.unwrap(), report); no_more_requests(&listener);
            let store = take_store(logout); settled(&cx, &lane).await; done(&cx, &lane, store.close(&cx)).await;
            let store = f.open(&cx, &lane, &client).await;
            let (store, outcome) = done(&cx, &lane, store.take_refresh(&cx, f.auth)).await.into_parts();
            assert!(outcome.unwrap().is_none()); done(&cx, &lane, store.close(&cx)).await; sibling.close();
        }
    });
}

#[test]
fn persistent_logout_without_endpoint_skips_decryption_but_removes_stored_grant() {
    run(async {
        let cx = Cx::current().unwrap(); let config = native::config(); let client = OAuthClient::new(config.clone());
        let f = Fixture::new(); let lane = lane(1); let (store, _) = f.seed(&cx, &lane, &config).await;
        f.provider.0.lock().unwrap().unreadable = true;
        let mut logout = begin(store, &cx, &client, f.auth);
        let report = logout.run(&cx).await.unwrap();
        assert_eq!(report.remote(), OAuthPersistentRevocation::EndpointUnavailable);
        assert_eq!(report.retired_revision().unwrap().generation(), 2); assert_eq!(f.counts().0, 0);
        let store = take_store(logout); settled(&cx, &lane).await;
        let (store, result) = done(&cx, &lane, store.take_refresh(&cx, f.auth)).await.into_parts();
        assert!(result.unwrap().is_none()); done(&cx, &lane, store.close(&cx)).await;
    });
}

#[test]
fn persistent_logout_empty_store_gets_one_tombstone_and_repetition_is_read_only() {
    run(async {
        let cx = Cx::current().unwrap(); let (listener, config) = issuer().await; let client = OAuthClient::new(config);
        let f = Fixture::new(); let lane = lane(1); let mut store = f.open(&cx, &lane, &client).await;
        for _ in 0..2 {
            let mut logout = begin(store, &cx, &client, f.auth); let report = logout.run(&cx).await.unwrap();
            assert_eq!(report.retired_revision().unwrap().generation(), 1);
            assert_eq!(report.remote(), OAuthPersistentRevocation::NoStoredGrant);
            assert_eq!(f.counts().2, 2); store = take_store(logout); settled(&cx, &lane).await;
        }
        no_more_requests(&listener); done(&cx, &lane, store.close(&cx)).await;
    });
}

#[test]
fn persistent_logout_protection_failure_does_not_prevent_authorized_local_removal() {
    run(async {
        let cx = Cx::current().unwrap(); let (listener, config) = issuer().await; let client = OAuthClient::new(config.clone());
        let f = Fixture::new(); let lane = lane(1); let (store, _) = f.seed(&cx, &lane, &config).await;
        f.provider.0.lock().unwrap().unreadable = true;
        let mut logout = begin(store, &cx, &client, f.auth); let report = logout.run(&cx).await.unwrap();
        assert_eq!(report.remote(), OAuthPersistentRevocation::GrantUnavailable);
        assert_eq!(report.retired_revision().unwrap().generation(), 2); assert_eq!(f.counts().0, 1);
        no_more_requests(&listener); let store = take_store(logout); settled(&cx, &lane).await;
        done(&cx, &lane, store.close(&cx)).await;
    });
}

#[test]
fn persistent_logout_foreign_authorization_preserves_the_original_grant() {
    run(async {
        let cx = Cx::current().unwrap(); let (listener, config) = issuer().await; let client = OAuthClient::new(config.clone());
        let f = Fixture::new(); let lane = lane(1); let (store, _) = f.seed(&cx, &lane, &config).await;
        let bytes = f.bytes(); let counts = f.counts();
        let mut logout = begin(store, &cx, &client, identity("bob").1);
        assert!(matches!(logout.run(&cx).await, Err(OAuthRefreshLogoutError::Storage(OAuthRefreshStoreError::Storage(
            CoordinatedSlotError::Slot(CredentialSlotError::BindingMismatch))))));
        assert_eq!(logout.report().retired_revision(), None); assert_eq!(f.bytes(), bytes); assert_eq!(f.counts(), counts);
        no_more_requests(&listener); let store = take_store(logout); settled(&cx, &lane).await;
        let (store, result) = done(&cx, &lane, store.take_refresh(&cx, f.auth)).await.into_parts();
        assert!(result.unwrap().is_some()); done(&cx, &lane, store.close(&cx)).await;
    });
}

#[test]
fn persistent_logout_preflight_refusal_leaves_session_and_storage_unchanged() {
    run(async {
        let cx = Cx::current().unwrap(); let config = native::config(); let client = OAuthClient::new(config.clone());
        let f = Fixture::new(); let lane = lane(1); let (mut store, credentials) = f.seed(&cx, &lane, &config).await;
        let session = ManagedOAuthSession::from_credentials(&cx, client.clone(), OAuthSessionPolicy::default(), credentials).unwrap();
        let bytes = f.bytes(); let counts = f.counts();
        for case in 0..3 {
            let mut configured = config.clone(); if case == 0 { configured.client_id.push_str("-wrong"); }
            let cancel = McpRequestCancellation::new(); if case == 1 { cancel.cancel(); }
            let failure = store.begin_logout(&cx, &OAuthClient::new(configured), f.auth, Some(&session), &cancel,
                if case == 2 { Duration::ZERO } else { Duration::from_secs(10) }).err().unwrap();
            store = failure.into_parts().1.unwrap().0;
            assert!(session.credential(&cx).await.is_ok()); assert_eq!(f.bytes(), bytes); assert_eq!(f.counts(), counts);
        }
        done(&cx, &lane, store.close(&cx)).await; session.close();
    });
}

#[test]
fn persistent_logout_uncertain_storage_stops_without_remote_contact_or_auto_repair() {
    run(async {
        let cx = Cx::current().unwrap();
        for settled_failure in [false, true] {
            let (listener, config) = issuer().await; let client = OAuthClient::new(config.clone());
            let f = Fixture::new(); let lane = lane(1); let (store, _) = f.seed(&cx, &lane, &config).await;
            let bytes = f.bytes(); f.provider.0.lock().unwrap().uncertain = Some(settled_failure);
            let mut logout = begin(store, &cx, &client, f.auth);
            assert!(matches!(logout.run(&cx).await, Err(OAuthRefreshLogoutError::Storage(OAuthRefreshStoreError::Storage(
                CoordinatedSlotError::Anchor(CredentialAnchorError::Uncertain))))));
            assert_eq!(logout.report().retired_revision(), None); assert_eq!(logout.report().remote(), OAuthPersistentRevocation::NotAttempted);
            assert!(matches!(logout.run(&cx).await, Err(OAuthRefreshLogoutError::Stopped)));
            assert_eq!(f.counts().2, if settled_failure { 4 } else { 3 });
            if !settled_failure { assert_eq!(f.bytes(), bytes); }
            no_more_requests(&listener); let store = take_store(logout); assert!(store.requires_recovery());
            settled(&cx, &lane).await; done(&cx, &lane, store.close(&cx)).await;
            let store = f.open(&cx, &lane, &client).await; assert!(!store.requires_recovery());
            let (store, result) = done(&cx, &lane, store.invalidate(&cx, f.auth)).await.into_parts();
            result.unwrap(); done(&cx, &lane, store.close(&cx)).await;
        }
    });
}

#[test]
fn persistent_logout_abandoned_storage_wait_retains_socket_free_exclusive_custody() {
    run(async {
        let cx = Cx::current().unwrap(); let (listener, config) = issuer().await; let client = OAuthClient::new(config.clone());
        let f = Fixture::new(); let lane = lane(2); let (store, _) = f.seed(&cx, &lane, &config).await;
        let gate = Gate::new(); let release = Release(gate.clone()); f.provider.0.lock().unwrap().opening = Some(gate.clone());
        let mut logout = begin(store, &cx, &client, f.auth); assert_eq!(logout.advance(&cx).await.unwrap(), OAuthRefreshLogoutStage::Retiring);
        gate.entered(&cx).await;
        let mut waiting = Box::pin(logout.advance(&cx));
        poll_fn(|task| { assert!(waiting.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await; drop(waiting);
        assert_eq!(logout.stage(), OAuthRefreshLogoutStage::Retiring); assert_eq!(logout.report().retired_revision(), None);
        let stopped_observer = Cx::for_testing_with_budget(asupersync::Budget::ZERO);
        assert!(matches!(logout.advance(&stopped_observer).await,
            Err(OAuthRefreshLogoutError::Context(OAuthError::Cancelled))));
        assert_eq!(logout.stage(), OAuthRefreshLogoutStage::Retiring);
        assert!(cx.checkpoint().is_ok());
        // A competing open can enter the second worker but cannot steal the
        // first worker's actual file lock, even after its wait was abandoned.
        let refused = f.opening(&cx, &lane, &client).unwrap().wait(&cx).await.unwrap();
        assert!(matches!(refused, Err(OAuthRefreshStoreError::Storage(CoordinatedSlotError::Slot(
            CredentialSlotError::Storage(AtomicFileError::Busy))))));
        release.0.release();
        assert_eq!(logout.advance(&cx).await.unwrap(), OAuthRefreshLogoutStage::ReadyToRevoke);
        assert_eq!(f.counts().0, 1); assert_eq!(logout.report().retired_revision().unwrap().generation(), 2);
        no_more_requests(&listener); let store = take_store(logout); settled(&cx, &lane).await; done(&cx, &lane, store.close(&cx)).await;
    });
}

#[test]
fn persistent_logout_abandoned_revocation_does_not_resurrect_or_reissue_the_grant() {
    run(async {
        let cx = Cx::current().unwrap(); let (listener, config) = issuer().await; let client = OAuthClient::new(config.clone());
        let f = Fixture::new(); let lane = lane(1); let (store, _) = f.seed(&cx, &lane, &config).await;
        let mut logout = begin(store, &cx, &client, f.auth);
        logout.advance(&cx).await.unwrap(); logout.advance(&cx).await.unwrap();
        let received = AtomicBool::new(false);
        let server = async {
            let mut tls = peer_request(&listener).await; received.store(true, Ordering::Release);
            let mut byte = [0]; assert!(!matches!(tls.read(&mut byte).await, Ok(n) if n > 0));
        };
        let application = async {
            let mut waiting = Box::pin(logout.advance(&cx));
            loop {
                poll_fn(|task| { assert!(waiting.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                if received.load(Ordering::Acquire) { break; }
                asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
            }
            drop(waiting);
            assert_eq!(logout.stage(), OAuthRefreshLogoutStage::Stopped);
            assert_eq!(logout.report().remote(), OAuthPersistentRevocation::Uncertain);
            assert_eq!(logout.report().retired_revision().unwrap().generation(), 2);
            assert!(matches!(logout.run(&cx).await, Err(OAuthRefreshLogoutError::Stopped)));
        };
        Box::pin(native::pair(server, application)).await; no_more_requests(&listener);
        let store = take_store(logout); settled(&cx, &lane).await; done(&cx, &lane, store.close(&cx)).await;
    });
}

#[test]
fn persistent_logout_cancelled_worker_keeps_exact_committed_without_delivery_result() {
    run(async {
        let cx = Cx::current().unwrap(); let config = native::config(); let client = OAuthClient::new(config.clone());
        let f = Fixture::new(); let lane = lane(1); let (store, _) = f.seed(&cx, &lane, &config).await;
        let gate = Gate::new(); let release = Release(gate.clone()); f.provider.0.lock().unwrap().settled = Some(gate.clone());
        let mut logout = begin(store, &cx, &client, f.auth); logout.advance(&cx).await.unwrap(); gate.entered(&cx).await;
        logout.cancel(); release.0.release();
        assert!(matches!(logout.advance(&cx).await, Err(OAuthRefreshLogoutError::Context(OAuthError::Cancelled))));
        let (report, custody) = logout.into_custody(); assert_eq!(report.retired_revision(), None);
        let OAuthRefreshLogoutCustody::Retiring(mut task) = custody else { panic!("pending disposition must remain owned"); };
        let (store, outcome) = task.wait(&cx).await.unwrap().into_parts();
        let Err(OAuthRefreshStoreError::Storage(CoordinatedSlotError::CommittedWithoutDelivery(revision))) = outcome else {
            panic!("settled cancellation must retain its exact commit disposition");
        };
        assert_eq!(revision.generation(), 2); assert_eq!(store.revision(), Some(revision));
        assert!(cx.checkpoint().is_ok()); settled(&cx, &lane).await; done(&cx, &lane, store.close(&cx)).await;
    });
}

#[test]
fn persistent_logout_deadline_pause_cannot_start_a_late_revocation() {
    run(async {
        let cx = Cx::current().unwrap(); let (listener, config) = issuer().await; let client = OAuthClient::new(config.clone());
        let f = Fixture::new(); let lane = lane(1); let (store, _) = f.seed(&cx, &lane, &config).await;
        let mut logout = begin(store, &cx, &client, f.auth);
        logout.advance(&cx).await.unwrap(); logout.advance(&cx).await.unwrap();
        // Change only the original bound, not the supplied observer or grant.
        logout.deadline = logout.origin.now();
        assert!(matches!(logout.advance(&cx).await, Err(OAuthRefreshLogoutError::Context(OAuthError::TimedOut))));
        assert_eq!(logout.report().remote(), OAuthPersistentRevocation::NotAttempted); no_more_requests(&listener);
        let store = take_store(logout); settled(&cx, &lane).await; done(&cx, &lane, store.close(&cx)).await;
    });
}

#[test]
fn persistent_logout_saturation_retains_the_unexecuted_command_for_explicit_admission() {
    run(async {
        let cx = Cx::current().unwrap(); let (listener, config) = issuer().await; let client = OAuthClient::new(config.clone());
        let f = Fixture::new(); let other = Fixture::new(); let lane = lane(1);
        let (store, _) = f.seed(&cx, &lane, &config).await; let (occupied, _) = other.seed(&cx, &lane, &config).await;
        let gate = Gate::new(); let release = Release(gate.clone()); other.provider.0.lock().unwrap().opening = Some(gate.clone());
        let mut occupied = occupied.take_refresh(&cx, other.auth).unwrap(); gate.entered(&cx).await;
        let bytes = f.bytes(); let counts = f.counts(); let mut logout = begin(store, &cx, &client, f.auth);
        assert!(matches!(logout.advance(&cx).await, Err(OAuthRefreshLogoutError::Submission(AsyncOAuthRefreshError::Io(CredentialIoError::CapacityExceeded)))));
        assert_eq!(logout.stage(), OAuthRefreshLogoutStage::ReadyToRetire); assert_eq!(f.bytes(), bytes); assert_eq!(f.counts(), counts);
        release.0.release(); let (other_store, result) = occupied.wait(&cx).await.unwrap().into_parts(); drop(result.unwrap());
        settled(&cx, &lane).await; done(&cx, &lane, other_store.close(&cx)).await;
        let server = async { let mut tls = peer_request(&listener).await;
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap(); tls.shutdown().await.unwrap(); };
        let ((), result) = Box::pin(native::pair(server, logout.run(&cx))).await;
        assert!(result.unwrap().retired_revision().is_some()); assert_eq!(f.counts().0, 1); assert_eq!(f.counts().2, 4);
        no_more_requests(&listener); let store = take_store(logout); settled(&cx, &lane).await; done(&cx, &lane, store.close(&cx)).await;
    });
}

#[test]
fn persistent_logout_shutdown_refusal_does_not_reopen_admission_or_claim_retirement() {
    run(async {
        let cx = Cx::current().unwrap(); let config = native::config(); let client = OAuthClient::new(config.clone());
        let f = Fixture::new(); let lane = lane(1); let (store, _) = f.seed(&cx, &lane, &config).await;
        let bytes = f.bytes(); let counts = f.counts(); lane.begin_shutdown().unwrap();
        let mut logout = begin(store, &cx, &client, f.auth);
        assert!(matches!(logout.run(&cx).await, Err(OAuthRefreshLogoutError::Submission(AsyncOAuthRefreshError::Io(CredentialIoError::LaneClosed)))));
        assert_eq!(logout.report().retired_revision(), None); assert_eq!(f.bytes(), bytes); assert_eq!(f.counts(), counts);
        let store = take_store(logout); done(&cx, &lane, store.close(&cx)).await;
        lane.wait_drained(&cx, Duration::from_secs(1)).await.unwrap(); assert!(lane.is_shutting_down().unwrap());
    });
}
