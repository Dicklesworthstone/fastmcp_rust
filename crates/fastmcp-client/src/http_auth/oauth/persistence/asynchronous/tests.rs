use super::*;
use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::os::unix::fs::DirBuilderExt;
use std::sync::{Arc, Condvar, Mutex, atomic::{AtomicBool, Ordering}};
use std::task::Poll;
use std::time::{Duration, Instant};

use fastmcp_core::{CanonicalHttpUrl, partition::{DurableOwnerKey, PartitionDescriptor}, runtime::ProcessGenerationGuard};
use crate::http_auth::BoundBearerCredential;
use crate::http_auth::oauth::OAuthClientConfiguration;
use crate::http_auth::oauth::persistence::{OAuthGrantBinding, OAuthGrantEncoding, OAuthGrantProtectionError};
use crate::http_auth::secure_file::slot::coordinator::{CredentialAnchorBinding, CredentialAnchorError, CredentialAnchorSnapshot, CredentialAnchorState};
use crate::http_auth::secure_file::slot::coordinator::asynchronous::{CredentialIoLimits, CredentialIoSnapshot};

// Deliberately opaque-service doubles, not production encryption or a durable
// independent anchor. Real files, file locks, coordinator and blocking runtime
// are used. Tokens and access lifetimes are native fixture credentials.
#[derive(Default)]
struct State {
    vault: BTreeMap<Vec<u8>, (OAuthGrantBinding, Vec<u8>)>,
    snapshot: Option<CredentialAnchorSnapshot>,
    seals: usize,
    opens: usize,
    reads: usize,
    writes: usize,
    threads: Vec<std::thread::ThreadId>,
    refuse_seal: bool,
    oversized: bool,
    uncertain_settlement: bool,
    seal_gate: Option<Arc<Gate>>,
    settled_gate: Option<Arc<Gate>>,
}
#[derive(Clone)]
struct Provider(Arc<Mutex<State>>);
impl OAuthGrantProtector for Provider {
    type Plaintext = Vec<u8>;
    fn seal(&mut self, cx: &Cx, binding: &OAuthGrantBinding, grant: &OAuthGrantEncoding<'_>)
        -> Result<Vec<u8>, OAuthGrantProtectionError>
    {
        cx.checkpoint().map_err(|_| OAuthGrantProtectionError::Cancelled)?;
        let mut bytes = Vec::new();
        grant.write_to(&mut bytes)?;
        let (envelope, gate) = {
            let mut s = self.0.lock().unwrap();
            s.threads.push(std::thread::current().id());
            s.seals += 1;
            if s.refuse_seal { return Err(OAuthGrantProtectionError::Unavailable); }
            if s.oversized { return Ok(vec![0; MAX_PROTECTED_REFRESH_GRANT_BYTES + 1]); }
            let envelope = s.seals.to_be_bytes().to_vec();
            s.vault.insert(envelope.clone(), (*binding, bytes));
            (envelope, s.seal_gate.take())
        };
        if let Some(gate) = gate { gate.block(); }
        Ok(envelope)
    }
    fn open(&mut self, cx: &Cx, binding: &OAuthGrantBinding, envelope: &[u8])
        -> Result<Vec<u8>, OAuthGrantProtectionError>
    {
        cx.checkpoint().map_err(|_| OAuthGrantProtectionError::Cancelled)?;
        let mut s = self.0.lock().unwrap();
        s.threads.push(std::thread::current().id());
        s.opens += 1;
        let (expected, bytes) = s.vault.get(envelope).ok_or(OAuthGrantProtectionError::InvalidEnvelope)?;
        if expected != binding { return Err(OAuthGrantProtectionError::InvalidEnvelope); }
        Ok(bytes.clone())
    }
}
impl CredentialCommitAnchor for Provider {
    fn current(&mut self, cx: &Cx, binding: &CredentialAnchorBinding)
        -> Result<CredentialAnchorSnapshot, CredentialAnchorError>
    {
        cx.checkpoint().map_err(|_| CredentialAnchorError::Unavailable)?;
        let mut s = self.0.lock().unwrap();
        s.threads.push(std::thread::current().id());
        s.reads += 1;
        s.snapshot.filter(|current| current.binding() == *binding).ok_or(CredentialAnchorError::NotProvisioned)
    }
    fn compare_exchange(&mut self, cx: &Cx, expected: &CredentialAnchorSnapshot, next: CredentialAnchorState)
        -> Result<CredentialAnchorSnapshot, CredentialAnchorError>
    {
        cx.checkpoint().map_err(|_| CredentialAnchorError::Unavailable)?;
        let (snapshot, gate, uncertain) = {
            let mut s = self.0.lock().unwrap();
            s.threads.push(std::thread::current().id());
            if s.snapshot.as_ref() != Some(expected) { return Err(CredentialAnchorError::Conflict); }
            let snapshot = CredentialAnchorSnapshot::new(expected.binding(), expected.sequence() + 1, next);
            s.snapshot = Some(snapshot);
            s.writes += 1;
            let settled = matches!(next, CredentialAnchorState::Stable(_));
            let gate = if settled { s.settled_gate.take() } else { None };
            (snapshot, gate, settled && s.uncertain_settlement)
        };
        if let Some(gate) = gate { gate.block(); }
        if uncertain { Err(CredentialAnchorError::Uncertain) } else { Ok(snapshot) }
    }
}
struct Gate { entered: AtomicBool, release: Mutex<bool>, wake: Condvar }
impl Gate {
    fn new() -> Arc<Self> { Arc::new(Self { entered: AtomicBool::new(false), release: Mutex::new(false), wake: Condvar::new() }) }
    fn block(&self) {
        self.entered.store(true, Ordering::Release);
        let (released, _) = self.wake.wait_timeout_while(self.release.lock().unwrap(), Duration::from_secs(5), |v| !*v).unwrap();
        assert!(*released, "fixture provider gate was not released");
    }
    fn release(&self) { *self.release.lock().unwrap() = true; self.wake.notify_all(); }
    async fn entered(&self, cx: &Cx) {
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(2_000_000_000), async {
            while !self.entered.load(Ordering::Acquire) { asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await; }
        }).await.unwrap();
    }
}
struct Release(Arc<Gate>);
impl Drop for Release { fn drop(&mut self) { self.0.release(); } }

fn configuration() -> OAuthClientConfiguration {
    let url = |s| CanonicalHttpUrl::parse(s).unwrap();
    OAuthClientConfiguration::from_trusted_endpoints("https://issuer.example", url("https://issuer.example/auth"),
        url("https://issuer.example/token"), url("https://resource.example/mcp"), "native-client", vec!["tools:read".to_owned()]).unwrap()
}
fn credentials(configuration: &OAuthClientConfiguration) -> OAuthCredentials {
    let expires_at = Instant::now() + Duration::from_secs(300);
    OAuthCredentials { configuration: configuration.clone(),
        access: BoundBearerCredential::bind_with_expiry(configuration.resource.clone(), "access-secret", expires_at).unwrap(),
        refresh_token: Some("refresh-secret".to_owned()), scopes: configuration.scopes.clone(), expires_at }
}
fn identity(subject: &str) -> (CredentialStoreKey, PartitionAuthorization) {
    let d = PartitionDescriptor::from_verified_facts("provider", 1, "https://issuer.example", "https://resource.example/mcp",
        "tenant", subject, "native-client", 1, 1, &[b"oauth-resource"]).unwrap();
    let owner = DurableOwnerKey::derive(&d, 1).unwrap();
    (CredentialStoreKey::derive(&d, "store", "refresh", "instance").unwrap(), PartitionAuthorization::current(&d, &owner))
}
struct Fixture { directory: std::path::PathBuf, provider: Provider, key: CredentialStoreKey, auth: PartitionAuthorization }
impl Fixture {
    fn new() -> Self {
        let nonce = fastmcp_core::draw_security_identifier().unwrap();
        let directory = std::env::temp_dir().join(format!("fastmcp-async-refresh-{}-{}", std::process::id(), crate::http_auth::oauth::hex(nonce.as_bytes())));
        std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let (key, auth) = identity("alice");
        let binding = CredentialAnchorBinding::for_store("async-oauth", &key, &auth).unwrap();
        let provider = Provider(Arc::new(Mutex::new(State { snapshot: Some(CredentialAnchorSnapshot::new(binding, 0, CredentialAnchorState::Stable(None))), ..State::default() })));
        Self { directory, provider, key, auth }
    }
    fn opening(&self, cx: &Cx, lane: &CredentialIoLane, client: &OAuthClient)
        -> Result<CredentialSlotTask<OAuthRefreshOpen<Provider, Provider>>, AsyncOAuthRefreshError>
    {
        AsyncOAuthRefreshStore::open(cx, lane, File::open(&self.directory).unwrap(), "grant".to_owned(), self.key,
            self.auth, "async-oauth".to_owned(), self.provider.clone(), self.provider.clone(), client)
    }
    async fn open(&self, cx: &Cx, lane: &CredentialIoLane, client: &OAuthClient) -> AsyncOAuthRefreshStore<Provider, Provider> {
        let (owner, recovery) = done(cx, lane, self.opening(cx, lane, client)).await.unwrap();
        assert_eq!(recovery, None);
        owner
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
async fn settled(cx: &Cx, lane: &CredentialIoLane) {
    // Mailbox publication can precede the worker's final lease drop. Wait for
    // that actual release before a new job in this single-job test lane; do
    // not turn a transient full lane into a flaky transaction retry.
    asupersync::time::timeout_at(cx.now().saturating_add_nanos(2_000_000_000), async {
        loop {
            let usage = lane.snapshot().unwrap();
            if usage.operations == 0 && usage.closes == 0 { break; }
            asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
        }
    }).await.unwrap();
}
async fn done<T>(cx: &Cx, lane: &CredentialIoLane, task: Result<CredentialSlotTask<T>, AsyncOAuthRefreshError>) -> T {
    let value = task.unwrap().wait(cx).await.unwrap();
    settled(cx, lane).await;
    value
}
fn lane() -> CredentialIoLane {
    CredentialIoLane::new(ProcessGenerationGuard::install().unwrap(), CredentialIoLimits::new(4, 1, 8 * 1024 * 1024).unwrap()).unwrap()
}
fn run<F: Future<Output = ()>>(work: impl FnOnce(Cx) -> F) {
    asupersync::runtime::RuntimeBuilder::current_thread().with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .blocking_threads(1, 4).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(15_000_000_000), Box::pin(work(cx))).await.unwrap();
        });
}

#[test]
fn async_refresh_round_trip_reopens_and_consumes_without_persisted_access() {
    run(|cx| async move {
        let f = Fixture::new(); let lane = lane(); let cfg = configuration(); let client = OAuthClient::new(cfg.clone());
        let poller = std::thread::current().id();
        let owner = f.open(&cx, &lane, &client).await;
        let credentials = credentials(&cfg); let expiry = credentials.expires_at();
        let (owner, (credentials, result)) = done(&cx, &lane, owner.store_refresh(&cx, f.auth, None, credentials)).await.into_parts();
        assert_eq!(result.unwrap().generation(), 1); assert!(!credentials.has_refresh_token()); assert_eq!(credentials.expires_at(), expiry);
        assert!(credentials.bearer_credential().authorization_for_target(&cfg.resource).is_some());
        for secret in [b"refresh-secret".as_slice(), b"access-secret".as_slice()] { assert!(!f.bytes().windows(secret.len()).any(|bytes| bytes == secret)); }
        done(&cx, &lane, owner.close(&cx)).await;
        let owner = f.open(&cx, &lane, &client).await;
        let (owner, result) = done(&cx, &lane, owner.take_refresh(&cx, f.auth)).await.into_parts();
        let grant = result.unwrap().unwrap(); assert_eq!(grant.refresh_token, "refresh-secret"); assert_eq!(grant.scopes(), cfg.scopes);
        assert_eq!(owner.revision().unwrap().generation(), 2);
        let (owner, result) = done(&cx, &lane, owner.take_refresh(&cx, f.auth)).await.into_parts(); assert!(result.unwrap().is_none());
        done(&cx, &lane, owner.close(&cx)).await;
        assert!(f.provider.0.lock().unwrap().threads.iter().all(|id| *id != poller));
        lane.begin_shutdown().unwrap(); lane.wait_drained(&cx, Duration::from_secs(1)).await.unwrap();
    });
}

#[test]
fn async_refresh_wrong_principal_cannot_decrypt_or_consume_the_owner_grant() {
    run(|cx| async move {
        let f = Fixture::new(); let lane = lane(); let cfg = configuration(); let client = OAuthClient::new(cfg.clone());
        let owner = f.open(&cx, &lane, &client).await;
        let (owner, (_, result)) = done(&cx, &lane, owner.store_refresh(&cx, f.auth, None, credentials(&cfg))).await.into_parts(); result.unwrap();
        let before = f.bytes(); let opens = f.provider.0.lock().unwrap().opens;
        let (owner, result) = done(&cx, &lane, owner.take_refresh(&cx, identity("bob").1)).await.into_parts();
        assert!(matches!(result, Err(OAuthRefreshStoreError::Storage(CoordinatedSlotError::Slot(CredentialSlotError::BindingMismatch)))));
        assert_eq!(f.bytes(), before); assert_eq!(f.provider.0.lock().unwrap().opens, opens);
        let (owner, result) = done(&cx, &lane, owner.take_refresh(&cx, f.auth)).await.into_parts(); assert!(result.unwrap().is_some());
        done(&cx, &lane, owner.close(&cx)).await;
    });
}

#[test]
fn async_refresh_failed_protection_returns_untransferred_live_credentials() {
    run(|cx| async move {
        for oversized in [false, true] {
            let f = Fixture::new(); let lane = lane(); let cfg = configuration(); let client = OAuthClient::new(cfg.clone());
            let owner = f.open(&cx, &lane, &client).await;
            { let mut s = f.provider.0.lock().unwrap(); s.refuse_seal = !oversized; s.oversized = oversized; }
            let (owner, (credentials, result)) = done(&cx, &lane, owner.store_refresh(&cx, f.auth, None, credentials(&cfg))).await.into_parts();
            assert!(result.is_err()); assert!(credentials.has_refresh_token()); assert_eq!(owner.revision(), None); assert_eq!(f.provider.0.lock().unwrap().writes, 0);
            { let mut s = f.provider.0.lock().unwrap(); s.refuse_seal = false; s.oversized = false; }
            let (owner, (credentials, result)) = done(&cx, &lane, owner.store_refresh(&cx, f.auth, None, credentials)).await.into_parts();
            result.unwrap(); assert!(!credentials.has_refresh_token()); done(&cx, &lane, owner.close(&cx)).await;
        }
    });
}

#[test]
fn async_refresh_uncertain_commit_never_restores_live_renewal_ownership() {
    run(|cx| async move {
        let f = Fixture::new(); let lane = lane(); let cfg = configuration(); let client = OAuthClient::new(cfg.clone());
        let owner = f.open(&cx, &lane, &client).await;
        f.provider.0.lock().unwrap().uncertain_settlement = true;
        let (owner, (credentials, result)) = done(&cx, &lane, owner.store_refresh(&cx, f.auth, None, credentials(&cfg))).await.into_parts();
        assert!(matches!(result, Err(OAuthRefreshStoreError::Storage(CoordinatedSlotError::Anchor(CredentialAnchorError::Uncertain)))));
        assert!(!credentials.has_refresh_token()); assert!(owner.requires_recovery()); assert_eq!(f.provider.0.lock().unwrap().writes, 2);
        done(&cx, &lane, owner.close(&cx)).await; f.provider.0.lock().unwrap().uncertain_settlement = false;
        let owner = f.open(&cx, &lane, &client).await;
        let (owner, result) = done(&cx, &lane, owner.take_refresh(&cx, f.auth)).await.into_parts(); assert!(result.unwrap().is_some());
        let (owner, result) = done(&cx, &lane, owner.take_refresh(&cx, f.auth)).await.into_parts(); assert!(result.unwrap().is_none());
        done(&cx, &lane, owner.close(&cx)).await;
    });
}

#[test]
fn async_refresh_interrupted_wait_keeps_one_transaction_and_its_capacity() {
    run(|cx| async move {
        let f = Fixture::new(); let lane = lane(); let cfg = configuration(); let client = OAuthClient::new(cfg.clone());
        let owner = f.open(&cx, &lane, &client).await;
        let gate = Release(Gate::new()); f.provider.0.lock().unwrap().seal_gate = Some(gate.0.clone());
        let mut pending = owner.store_refresh(&cx, f.auth, None, credentials(&cfg)).unwrap(); gate.0.entered(&cx).await;
        let mut wait = Box::pin(pending.wait(&cx)); poll_fn(|task| { assert!(wait.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await; drop(wait);
        let stopped = Cx::for_testing_with_budget(asupersync::Budget::ZERO);
        assert!(matches!(pending.wait(&stopped).await, Err(CredentialIoError::WaitCancelled)));
        assert_eq!(lane.snapshot().unwrap().operations, 1); assert!(lane.snapshot().unwrap().reserved_bytes >= EXTRA_WORK_BYTES);
        gate.0.release(); let (owner, (credentials, result)) = pending.wait(&cx).await.unwrap().into_parts();
        result.unwrap(); assert!(!credentials.has_refresh_token()); assert_eq!(f.provider.0.lock().unwrap().seals, 1);
        assert!(matches!(pending.wait(&cx).await, Err(CredentialIoError::AlreadyReceived)));
        done(&cx, &lane, owner.close(&cx)).await;
    });
}

#[test]
fn async_refresh_late_worker_cancellation_preserves_committed_disposition() {
    run(|cx| async move {
        let f = Fixture::new(); let lane = lane(); let cfg = configuration(); let client = OAuthClient::new(cfg.clone());
        let owner = f.open(&cx, &lane, &client).await;
        let gate = Release(Gate::new()); f.provider.0.lock().unwrap().settled_gate = Some(gate.0.clone());
        let mut pending = owner.store_refresh(&cx, f.auth, None, credentials(&cfg)).unwrap(); gate.0.entered(&cx).await;
        pending.request_cancel().unwrap(); gate.0.release();
        let (owner, (credentials, result)) = pending.wait(&cx).await.unwrap().into_parts();
        assert!(matches!(result, Err(OAuthRefreshStoreError::Storage(CoordinatedSlotError::CommittedWithoutDelivery(_)))));
        assert!(!credentials.has_refresh_token()); assert_eq!(owner.revision().unwrap().generation(), 1); assert!(!owner.requires_recovery());
        done(&cx, &lane, owner.close(&cx)).await;
    });
}

#[test]
fn async_refresh_shared_lane_saturation_still_allows_close_and_shutdown_drain() {
    run(|cx| async move {
        let f = Fixture::new(); let other = Fixture::new(); let lane = lane(); let cfg = configuration(); let client = OAuthClient::new(cfg.clone());
        let owner = f.open(&cx, &lane, &client).await; let other_owner = other.open(&cx, &lane, &client).await;
        let gate = Release(Gate::new()); f.provider.0.lock().unwrap().seal_gate = Some(gate.0.clone());
        let mut pending = owner.store_refresh(&cx, f.auth, None, credentials(&cfg)).unwrap(); gate.0.entered(&cx).await;
        let unused = Fixture::new();
        assert!(matches!(unused.opening(&cx, &lane, &client), Err(AsyncOAuthRefreshError::Io(CredentialIoError::CapacityExceeded))));
        assert_eq!(unused.provider.0.lock().unwrap().reads, 0); assert_eq!(std::fs::read_dir(&unused.directory).unwrap().count(), 0);
        let mut sibling = cx.spawn(|_| async { 42 }).unwrap(); assert_eq!(sibling.join(&cx).await.unwrap(), 42);
        lane.begin_shutdown().unwrap();
        // Do not wait for the deliberately blocked ordinary job here. Only
        // this separately admitted close must complete before releasing it.
        other_owner.close(&cx).unwrap().wait(&cx).await.unwrap();
        gate.0.release(); let (owner, (_, result)) = pending.wait(&cx).await.unwrap().into_parts(); result.unwrap();
        let bytes = f.bytes(); done(&cx, &lane, owner.close(&cx)).await;
        lane.wait_drained(&cx, Duration::from_secs(1)).await.unwrap(); assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot::default());
        assert_eq!(f.bytes(), bytes, "shutdown does not invalidate persisted grants");
    });
}

#[test]
fn async_refresh_no_blocking_pool_refuses_before_file_or_provider_work() {
    asupersync::runtime::RuntimeBuilder::current_thread().with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .blocking_threads(0, 0).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap(); let f = Fixture::new(); let lane = lane(); let client = OAuthClient::new(configuration());
            assert!(matches!(f.opening(&cx, &lane, &client), Err(AsyncOAuthRefreshError::Io(CredentialIoError::BlockingPoolUnavailable))));
            assert_eq!(f.provider.0.lock().unwrap().reads, 0); assert_eq!(std::fs::read_dir(&f.directory).unwrap().count(), 0);
            assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot::default());
        });
}

#[test]
fn async_refresh_configuration_and_revision_refusal_preserve_source_grants() {
    run(|cx| async move {
        let f = Fixture::new(); let lane = lane(); let cfg = configuration(); let client = OAuthClient::new(cfg.clone());
        let owner = f.open(&cx, &lane, &client).await;
        let mut changed = cfg.clone();
        changed.client_id.push_str("-other");
        let (owner, (returned, result)) = done(&cx, &lane,
            owner.store_refresh(&cx, f.auth, None, credentials(&changed))).await.into_parts();
        assert_eq!(result, Err(OAuthRefreshStoreError::ConfigurationMismatch));
        assert!(returned.has_refresh_token());
        assert_eq!(f.provider.0.lock().unwrap().seals, 0);
        let (owner, (_, result)) = done(&cx, &lane,
            owner.store_refresh(&cx, f.auth, None, credentials(&cfg))).await.into_parts();
        let revision = result.unwrap();
        let before = f.bytes();
        let (owner, (returned, result)) = done(&cx, &lane,
            owner.store_refresh(&cx, f.auth, None, credentials(&cfg))).await.into_parts();
        assert_eq!(result, Err(OAuthRefreshStoreError::RevisionMismatch));
        assert!(returned.has_refresh_token());
        assert_eq!(owner.revision(), Some(revision));
        assert_eq!(f.bytes(), before);
        assert_eq!(f.provider.0.lock().unwrap().seals, 1);
        done(&cx, &lane, owner.close(&cx)).await;
    });
}

#[test]
fn async_refresh_invalidate_persists_tombstone_and_repeated_logout_is_read_only() {
    run(|cx| async move {
        let f = Fixture::new(); let lane = lane(); let cfg = configuration(); let client = OAuthClient::new(cfg.clone());
        let owner = f.open(&cx, &lane, &client).await;
        let (owner, (_, result)) = done(&cx, &lane,
            owner.store_refresh(&cx, f.auth, None, credentials(&cfg))).await.into_parts();
        result.unwrap();
        let (owner, result) = done(&cx, &lane, owner.invalidate(&cx, f.auth)).await.into_parts();
        let tombstone = result.unwrap();
        assert_eq!(tombstone.generation(), 2);
        let before = f.bytes();
        let writes = f.provider.0.lock().unwrap().writes;
        let (owner, result) = done(&cx, &lane, owner.invalidate(&cx, f.auth)).await.into_parts();
        assert_eq!(result.unwrap(), tombstone);
        assert_eq!(f.provider.0.lock().unwrap().writes, writes);
        assert_eq!(f.bytes(), before);
        assert_eq!(f.provider.0.lock().unwrap().opens, 0, "logout does not decrypt the grant");
        done(&cx, &lane, owner.close(&cx)).await;
        let owner = f.open(&cx, &lane, &client).await;
        assert_eq!(owner.revision(), Some(tombstone));
        let (owner, result) = done(&cx, &lane, owner.take_refresh(&cx, f.auth)).await.into_parts();
        assert!(result.unwrap().is_none());
        done(&cx, &lane, owner.close(&cx)).await;
    });
}

#[test]
fn async_refresh_try_write_returns_the_same_unexecuted_grant_when_lane_is_full() {
    run(|cx| async move {
        let f = Fixture::new(); let busy = Fixture::new(); let lane = lane();
        let cfg = configuration(); let client = OAuthClient::new(cfg.clone());
        let owner = f.open(&cx, &lane, &client).await;
        let blocker = busy.open(&cx, &lane, &client).await;
        let gate = Release(Gate::new()); busy.provider.0.lock().unwrap().seal_gate = Some(gate.0.clone());
        let mut pending = blocker.store_refresh(&cx, busy.auth, None, credentials(&cfg)).unwrap();
        gate.0.entered(&cx).await;
        let original = credentials(&cfg);
        let expiry = original.expires_at();
        let header = original.bearer_credential().authorization_for_target(&cfg.resource);
        let refusal = owner.try_store_refresh(&cx, f.auth, None, original).expect_err("lane is full");
        assert!(matches!(refusal.cause(), AsyncOAuthRefreshError::Io(CredentialIoError::CapacityExceeded)));
        assert!(!format!("{refusal:?} {refusal}").contains("refresh-secret"));
        let (_, retained) = refusal.into_parts();
        let (owner, original) = retained.expect("no command was handed to the runtime");
        assert!(original.has_refresh_token());
        assert_eq!(original.expires_at(), expiry);
        assert_eq!(original.bearer_credential().authorization_for_target(&cfg.resource), header);
        assert_eq!(owner.revision(), None);
        assert_eq!(f.provider.0.lock().unwrap().seals, 0);
        assert_eq!(lane.snapshot().unwrap().slots, 2);
        gate.0.release();
        let (blocker, (_, outcome)) = pending.wait(&cx).await.unwrap().into_parts();
        outcome.unwrap(); settled(&cx, &lane).await;
        // The returned owner still holds the real file lock, not a reconstructed
        // facade that another opening can replace while admission is repaired.
        let duplicate = done(&cx, &lane, f.opening(&cx, &lane, &client)).await;
        assert!(matches!(duplicate, Err(OAuthRefreshStoreError::Storage(CoordinatedSlotError::Slot(
            CredentialSlotError::Storage(crate::http_auth::secure_file::AtomicFileError::Busy))))));
        let mut write = owner.try_store_refresh(&cx, f.auth, None, original).unwrap();
        let (owner, (returned, outcome)) = write.wait(&cx).await.unwrap().into_parts();
        outcome.unwrap(); assert!(!returned.has_refresh_token());
        assert_eq!(f.provider.0.lock().unwrap().seals, 1);
        done(&cx, &lane, owner.close(&cx)).await;
        done(&cx, &lane, blocker.close(&cx)).await;
    });
}

#[test]
fn async_refresh_try_write_precancellation_returns_ownership_for_a_live_caller() {
    run(|cx| async move {
        let f = Fixture::new(); let lane = lane(); let cfg = configuration(); let client = OAuthClient::new(cfg.clone());
        let owner = f.open(&cx, &lane, &client).await;
        let stopped = Cx::for_testing_with_budget(asupersync::Budget::ZERO);
        let failure = owner.try_store_refresh(&stopped, f.auth, None, credentials(&cfg)).err().unwrap();
        assert!(matches!(failure.cause(), AsyncOAuthRefreshError::Io(CredentialIoError::SubmissionCancelled)));
        let (_, retained) = failure.into_parts();
        let (owner, original) = retained.unwrap();
        assert!(original.has_refresh_token());
        assert_eq!(f.provider.0.lock().unwrap().seals, 0);
        assert_eq!(lane.snapshot().unwrap().operations, 0);
        let mut pending = owner.try_store_refresh(&cx, f.auth, None, original).unwrap();
        let (owner, (_, result)) = pending.wait(&cx).await.unwrap().into_parts();
        result.unwrap();
        assert_eq!(f.provider.0.lock().unwrap().seals, 1);
        done(&cx, &lane, owner.close(&cx)).await;
    });
}

#[test]
fn async_refresh_try_take_and_invalidate_preserve_owner_after_shutdown() {
    run(|cx| async move {
        for invalidate in [false, true] {
            let f = Fixture::new(); let lane = lane(); let cfg = configuration(); let client = OAuthClient::new(cfg.clone());
            let owner = f.open(&cx, &lane, &client).await;
            let (owner, (_, result)) = done(&cx, &lane,
                owner.store_refresh(&cx, f.auth, None, credentials(&cfg))).await.into_parts();
            let revision = result.unwrap();
            let before = f.bytes(); let writes = f.provider.0.lock().unwrap().writes;
            lane.begin_shutdown().unwrap();
            let failure = if invalidate {
                owner.try_invalidate(&cx, f.auth).err().unwrap()
            } else {
                owner.try_take_refresh(&cx, f.auth).err().unwrap()
            };
            assert!(matches!(failure.cause(), AsyncOAuthRefreshError::Io(CredentialIoError::LaneClosed)));
            let (_, retained) = failure.into_parts();
            let (owner, ()) = retained.unwrap();
            assert_eq!(owner.revision(), Some(revision));
            assert!(!owner.requires_recovery());
            assert_eq!(f.provider.0.lock().unwrap().writes, writes);
            assert_eq!(f.provider.0.lock().unwrap().opens, 0);
            assert_eq!(f.bytes(), before);
            done(&cx, &lane, owner.close(&cx)).await;
            lane.wait_drained(&cx, Duration::from_secs(1)).await.unwrap();
            assert_eq!(f.bytes(), before);
        }
    });
}
