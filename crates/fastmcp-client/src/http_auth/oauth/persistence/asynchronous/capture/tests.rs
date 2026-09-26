use super::*;
use std::collections::BTreeMap;
use std::fs::File;
use std::os::unix::fs::DirBuilderExt;
use std::sync::{Arc, Condvar, Mutex, atomic::{AtomicBool, Ordering}};

use fastmcp_core::{partition::{CredentialStoreKey, DurableOwnerKey, PartitionDescriptor}, runtime::ProcessGenerationGuard};
use crate::http_auth::managed::OAuthSessionPolicy;
use crate::http_auth::oauth::tests as native;
use crate::http_auth::oauth::persistence::{OAuthGrantBinding, OAuthGrantEncoding, OAuthGrantProtectionError};
use crate::http_auth::secure_file::slot::coordinator::{CredentialAnchorBinding, CredentialAnchorError, CredentialAnchorSnapshot, CredentialAnchorState};
use crate::http_auth::secure_file::slot::coordinator::asynchronous::{CredentialIoLane, CredentialIoLimits};

// Real files, locks, transaction coordinator and runtime. The opaque-service
// provider and independently modeled anchor are IN-MEMORY TEST DOUBLES, not
// production cryptography, independent durability or process-restart evidence.
struct State {
    anchor: CredentialAnchorSnapshot,
    records: BTreeMap<Vec<u8>, (OAuthGrantBinding, Vec<u8>)>,
    reads: usize,
    writes: usize,
    seals: usize,
    opens: usize,
    refuse_seal: bool,
    uncertain: bool,
    gate: Option<Arc<Gate>>,
    threads: Vec<std::thread::ThreadId>,
}
#[derive(Clone)]
struct Provider(Arc<Mutex<State>>);
impl CredentialCommitAnchor for Provider {
    fn current(&mut self, cx: &Cx, binding: &CredentialAnchorBinding) -> Result<CredentialAnchorSnapshot, CredentialAnchorError> {
        cx.checkpoint().map_err(|_| CredentialAnchorError::Unavailable)?;
        let mut s = self.0.lock().unwrap();
        s.reads += 1;
        s.threads.push(std::thread::current().id());
        if s.anchor.binding() != *binding { return Err(CredentialAnchorError::NotProvisioned); }
        Ok(s.anchor)
    }
    fn compare_exchange(&mut self, cx: &Cx, expected: &CredentialAnchorSnapshot, next: CredentialAnchorState)
        -> Result<CredentialAnchorSnapshot, CredentialAnchorError>
    {
        cx.checkpoint().map_err(|_| CredentialAnchorError::Unavailable)?;
        let mut s = self.0.lock().unwrap();
        if s.anchor != *expected { return Err(CredentialAnchorError::Conflict); }
        s.anchor = CredentialAnchorSnapshot::new(expected.binding(), expected.sequence() + 1, next);
        s.writes += 1;
        s.threads.push(std::thread::current().id());
        if s.uncertain { return Err(CredentialAnchorError::Uncertain); }
        Ok(s.anchor)
    }
}
struct Plaintext(Vec<u8>);
impl AsRef<[u8]> for Plaintext { fn as_ref(&self) -> &[u8] { &self.0 } }
impl Drop for Plaintext { fn drop(&mut self) { self.0.fill(0); } }
impl OAuthGrantProtector for Provider {
    type Plaintext = Plaintext;
    fn seal(&mut self, cx: &Cx, binding: &OAuthGrantBinding, grant: &OAuthGrantEncoding<'_>) -> Result<Vec<u8>, OAuthGrantProtectionError> {
        cx.checkpoint().map_err(|_| OAuthGrantProtectionError::Cancelled)?;
        let (envelope, gate) = {
            let mut s = self.0.lock().unwrap();
            s.seals += 1;
            s.threads.push(std::thread::current().id());
            if s.refuse_seal { return Err(OAuthGrantProtectionError::Unavailable); }
            let envelope = s.seals.to_be_bytes().to_vec();
            let mut bytes = Vec::new();
            grant.write_to(&mut bytes)?;
            s.records.insert(envelope.clone(), (*binding, bytes));
            (envelope, s.gate.take())
        };
        if let Some(gate) = gate { gate.block(); }
        Ok(envelope)
    }
    fn open(&mut self, cx: &Cx, binding: &OAuthGrantBinding, envelope: &[u8]) -> Result<Plaintext, OAuthGrantProtectionError> {
        cx.checkpoint().map_err(|_| OAuthGrantProtectionError::Cancelled)?;
        let mut s = self.0.lock().unwrap();
        s.opens += 1;
        s.threads.push(std::thread::current().id());
        let (expected, bytes) = s.records.get(envelope).ok_or(OAuthGrantProtectionError::InvalidEnvelope)?;
        if expected != binding { return Err(OAuthGrantProtectionError::InvalidEnvelope); }
        Ok(Plaintext(bytes.clone()))
    }
}
struct Gate { entered: AtomicBool, released: Mutex<bool>, wake: Condvar }
impl Gate {
    fn new() -> Arc<Self> { Arc::new(Self { entered: AtomicBool::new(false), released: Mutex::new(false), wake: Condvar::new() }) }
    fn block(&self) {
        self.entered.store(true, Ordering::Release);
        let (released, _) = self.wake.wait_timeout_while(self.released.lock().unwrap(), Duration::from_secs(5), |v| !*v).unwrap();
        assert!(*released, "fixture gate must be explicitly released");
    }
    fn release(&self) { *self.released.lock().unwrap() = true; self.wake.notify_all(); }
    async fn entered(&self, cx: &Cx) {
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(2_000_000_000), async {
            while !self.entered.load(Ordering::Acquire) {
                asupersync::time::sleep(cx.now(), Duration::from_millis(1)).await;
            }
        }).await.unwrap();
    }
}
struct Release(Arc<Gate>);
impl Drop for Release { fn drop(&mut self) { self.0.release(); } }

fn identity(subject: &str) -> (CredentialStoreKey, PartitionAuthorization) {
    let d = PartitionDescriptor::from_verified_facts("provider", 1, "https://issuer.example", "https://mcp.example/mcp",
        "tenant", subject, "native-client", 1, 1, &[b"oauth-resource"]).unwrap();
    let key = CredentialStoreKey::derive(&d, "store", "refresh", "capture").unwrap();
    let auth = PartitionAuthorization::current(&d, &DurableOwnerKey::derive(&d, 1).unwrap());
    (key, auth)
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
        let (key, auth) = identity("alice");
        let binding = CredentialAnchorBinding::for_store("capture", &key, &auth).unwrap();
        let nonce = fastmcp_core::draw_security_identifier().unwrap();
        let directory = std::env::temp_dir().join(format!("fastmcp-capture-{}-{}", std::process::id(),
            crate::http_auth::oauth::hex(nonce.as_bytes())));
        std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let provider = Provider(Arc::new(Mutex::new(State {
            anchor: CredentialAnchorSnapshot::new(binding, 0, CredentialAnchorState::Stable(None)),
            records: BTreeMap::new(), reads: 0, writes: 0, seals: 0, opens: 0,
            refuse_seal: false, uncertain: false, gate: None, threads: vec![],
        })));
        let lane = CredentialIoLane::new(ProcessGenerationGuard::install().unwrap(),
            CredentialIoLimits::new(4, 4, 16 * 1024 * 1024).unwrap()).unwrap();
        Self { directory, key, auth, provider, lane }
    }
    async fn open(&self, cx: &Cx, client: &OAuthClient) -> AsyncOAuthRefreshStore<Provider, Provider> {
        let mut task = AsyncOAuthRefreshStore::open(cx, &self.lane, File::open(&self.directory).unwrap(),
            "grant".to_owned(), self.key, self.auth, "capture".to_owned(),
            self.provider.clone(), self.provider.clone(), client).unwrap();
        task.wait(cx).await.unwrap().unwrap().0
    }
    fn begin(&self, cx: &Cx, session: &ManagedOAuthSession, store: AsyncOAuthRefreshStore<Provider, Provider>) -> OAuthRefreshCapture<Provider, Provider> {
        let revision = store.revision();
        store.begin_capture(cx, session, 1, self.auth, revision, &McpRequestCancellation::new(), Duration::from_secs(30)).unwrap()
    }
    fn writes(&self) -> usize { self.provider.0.lock().unwrap().writes }
    fn seals(&self) -> usize { self.provider.0.lock().unwrap().seals }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.directory.join("grant"));
        let _ = std::fs::remove_file(self.directory.join(".grant.lock"));
        let _ = std::fs::remove_dir(&self.directory);
    }
}
fn client() -> OAuthClient { OAuthClient::new(native::config()) }
fn session(cx: &Cx, client: &OAuthClient) -> ManagedOAuthSession {
    ManagedOAuthSession::from_credentials(cx, client.clone(), OAuthSessionPolicy::default(),
        native::renewable_grant(&client.configuration)).unwrap()
}
fn run<F: Future<Output = ()>>(work: impl FnOnce(Cx) -> F) {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .blocking_threads(1, 4).build().unwrap().block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(30_000_000_000), Box::pin(work(cx))).await.unwrap();
        });
}
async fn close(cx: &Cx, store: AsyncOAuthRefreshStore<Provider, Provider>) { store.close(cx).unwrap().wait(cx).await.unwrap(); }
async fn ready_to_transfer(capture: &mut OAuthRefreshCapture<Provider, Provider>, cx: &Cx) {
    assert_eq!(capture.advance(cx).await.unwrap(), OAuthRefreshCaptureStage::Checking);
    assert_eq!(capture.advance(cx).await.unwrap(), OAuthRefreshCaptureStage::ReadyToTransfer);
}
async fn ready_to_store(capture: &mut OAuthRefreshCapture<Provider, Provider>, cx: &Cx) {
    ready_to_transfer(capture, cx).await;
    assert_eq!(capture.advance(cx).await.unwrap(), OAuthRefreshCaptureStage::ReadyToStore);
}
fn stopped_store(capture: OAuthRefreshCapture<Provider, Provider>) -> AsyncOAuthRefreshStore<Provider, Provider> {
    match capture.into_custody() {
        OAuthRefreshCaptureCustody::Stopped { store: Some(store), credentials: None }
        | OAuthRefreshCaptureCustody::ReadyToTransfer(store)
        | OAuthRefreshCaptureCustody::ReadyToCheck(store) => store,
        _ => panic!("expected exact retained store without transferred credentials"),
    }
}

#[test]
fn managed_capture_preserves_live_access_and_persists_one_refresh_owner() {
    run(|cx| async move {
        let f = Fixture::new(); let client = client(); let session = session(&cx, &client);
        let sibling = session.clone(); let snapshot = session.credential(&cx).await.unwrap();
        let expiry = snapshot.expires_at(); let scopes = snapshot.scopes().to_vec();
        let poller = std::thread::current().id();
        let store = f.open(&cx, &client).await;
        let mut capture = f.begin(&cx, &session, store);
        capture.run(&cx).await.unwrap();
        let (store, revision) = capture.take_store().unwrap();
        assert_eq!(revision.generation(), 1); assert_eq!(f.writes(), 2); assert_eq!(f.seals(), 1);
        assert!(matches!(capture.take_store(), Err(OAuthRefreshCaptureError::NotComplete)));
        let after = sibling.credential(&cx).await.unwrap();
        assert_eq!(after.generation(), snapshot.generation()); assert_eq!(after.expires_at(), expiry); assert_eq!(after.scopes(), scopes);
        assert_eq!(after.credential().authorization_for_target(session.resource()), Some("Bearer access-one".to_owned()));
        let bytes = std::fs::read(f.directory.join("grant")).unwrap();
        for secret in [b"access-one".as_slice(), b"refresh-one".as_slice()] {
            assert!(!bytes.windows(secret.len()).any(|part| part == secret));
        }
        let mut second = f.begin(&cx, &session, store);
        assert!(matches!(second.run(&cx).await, Err(OAuthRefreshCaptureError::Transfer(
            OAuthRefreshTransferError::Session(OAuthSessionError::OAuth(OAuthError::RefreshUnavailable))))));
        let store = stopped_store(second); assert_eq!(f.seals(), 1);
        close(&cx, store).await;
        let store = f.open(&cx, &client).await;
        let (store, outcome) = store.take_refresh(&cx, f.auth).unwrap().wait(&cx).await.unwrap().into_parts();
        let grant = outcome.unwrap().unwrap(); assert_eq!(grant.refresh_token, "refresh-one"); assert_eq!(grant.scopes(), scopes);
        close(&cx, store).await;
        assert!(f.provider.0.lock().unwrap().threads.iter().all(|thread| *thread != poller));
        session.close(); assert!(snapshot.credential().authorization_for_target(session.resource()).is_none());
    });
}

#[test]
fn managed_capture_checks_foreign_authority_before_taking_session_credentials() {
    run(|cx| async move {
        let f = Fixture::new(); let client = client(); let session = session(&cx, &client);
        let store = f.open(&cx, &client).await; let reads = f.provider.0.lock().unwrap().reads;
        let mut capture = store.begin_capture(&cx, &session, 1, identity("bob").1, None,
            &McpRequestCancellation::new(), Duration::from_secs(30)).unwrap();
        assert!(matches!(capture.run(&cx).await, Err(OAuthRefreshCaptureError::Storage(_))));
        assert_eq!(f.provider.0.lock().unwrap().reads, reads); assert_eq!(f.seals(), 0); assert_eq!(f.writes(), 0);
        let mut valid = f.begin(&cx, &session, stopped_store(capture));
        valid.run(&cx).await.unwrap(); close(&cx, valid.take_store().unwrap().0).await;
        session.close();
    });
}

#[test]
fn managed_capture_rejects_wrong_generation_without_retiring_refresh() {
    run(|cx| async move {
        let f = Fixture::new(); let client = client(); let session = session(&cx, &client);
        let store = f.open(&cx, &client).await;
        let mut capture = store.begin_capture(&cx, &session, 2, f.auth, None,
            &McpRequestCancellation::new(), Duration::from_secs(30)).unwrap();
        assert!(matches!(capture.run(&cx).await, Err(OAuthRefreshCaptureError::Transfer(OAuthRefreshTransferError::GenerationMismatch))));
        assert_eq!(f.writes(), 0); assert_eq!(f.seals(), 0);
        let mut valid = f.begin(&cx, &session, stopped_store(capture));
        valid.run(&cx).await.unwrap(); close(&cx, valid.take_store().unwrap().0).await;
        session.close();
    });
}

#[test]
fn managed_capture_full_client_binding_refuses_before_a_protector_sees_tokens() {
    run(|cx| async move {
        let f = Fixture::new(); let client = client(); let session = session(&cx, &client);
        let mut foreign = client.clone(); foreign.configuration.client_id.push_str("-other");
        let store = f.open(&cx, &foreign).await;
        let mut capture = f.begin(&cx, &session, store);
        assert!(matches!(capture.run(&cx).await, Err(OAuthRefreshCaptureError::Transfer(
            OAuthRefreshTransferError::Session(OAuthSessionError::OAuth(OAuthError::CredentialBindingMismatch))))));
        assert_eq!(f.seals(), 0); assert_eq!(f.writes(), 0);
        close(&cx, stopped_store(capture)).await;
        let store = f.open(&cx, &client).await;
        let mut capture = f.begin(&cx, &session, store); capture.run(&cx).await.unwrap();
        close(&cx, capture.take_store().unwrap().0).await; session.close();
    });
}

#[test]
fn managed_capture_failed_protection_keeps_the_only_transferred_grant() {
    run(|cx| async move {
        let f = Fixture::new(); let client = client(); let session = session(&cx, &client);
        let store = f.open(&cx, &client).await;
        f.provider.0.lock().unwrap().refuse_seal = true;
        let mut capture = f.begin(&cx, &session, store);
        assert!(matches!(capture.run(&cx).await, Err(OAuthRefreshCaptureError::Storage(OAuthRefreshStoreError::Protection(_)))));
        assert_eq!(f.writes(), 0);
        let OAuthRefreshCaptureCustody::Stopped { store: Some(store), credentials: Some(credentials) } = capture.into_custody() else { panic!("retained pre-commit grant"); };
        assert!(credentials.has_refresh_token());
        assert!(session.credential(&cx).await.is_ok());
        f.provider.0.lock().unwrap().refuse_seal = false;
        let (store, (credentials, outcome)) = store.try_store_refresh(&cx, f.auth, None, credentials).unwrap().wait(&cx).await.unwrap().into_parts();
        outcome.unwrap(); assert!(!credentials.has_refresh_token());
        let mut duplicate = f.begin(&cx, &session, store);
        assert!(matches!(duplicate.run(&cx).await, Err(OAuthRefreshCaptureError::Transfer(_))));
        assert_eq!(f.writes(), 2); close(&cx, stopped_store(duplicate)).await; session.close();
    });
}

#[test]
fn managed_capture_uncertain_commit_never_restores_or_reseals_refresh() {
    run(|cx| async move {
        let f = Fixture::new(); let client = client(); let session = session(&cx, &client);
        let store = f.open(&cx, &client).await; f.provider.0.lock().unwrap().uncertain = true;
        let mut capture = f.begin(&cx, &session, store);
        assert!(matches!(capture.run(&cx).await, Err(OAuthRefreshCaptureError::Storage(_))));
        assert_eq!(f.writes(), 1); assert_eq!(f.seals(), 1);
        assert!(matches!(capture.run(&cx).await, Err(OAuthRefreshCaptureError::Stopped)));
        assert_eq!(f.writes(), 1); assert_eq!(f.seals(), 1);
        let OAuthRefreshCaptureCustody::Stopped { store: Some(store), credentials: Some(credentials) } = capture.into_custody() else { panic!("uncertain receipt custody"); };
        assert!(!credentials.has_refresh_token()); assert!(store.requires_recovery());
        close(&cx, store).await; session.close();
    });
}

#[test]
fn managed_capture_dropped_storage_wait_resumes_same_job_without_holding_session_lock() {
    run(|cx| async move {
        let f = Fixture::new(); let client = client(); let session = session(&cx, &client);
        let store = f.open(&cx, &client).await;
        let release = Release(Gate::new()); f.provider.0.lock().unwrap().gate = Some(release.0.clone());
        let mut capture = f.begin(&cx, &session, store); ready_to_store(&mut capture, &cx).await;
        assert_eq!(capture.advance(&cx).await.unwrap(), OAuthRefreshCaptureStage::Storing);
        release.0.entered(&cx).await;
        let mut waiting = Box::pin(capture.advance(&cx));
        poll_fn(|task| { assert!(waiting.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
        drop(waiting);
        // The blocked provider owns only the file, not the session grant lock.
        assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
        assert_eq!(f.seals(), 1); release.0.release();
        capture.run(&cx).await.unwrap(); assert_eq!(f.seals(), 1); assert_eq!(f.writes(), 2);
        close(&cx, capture.take_store().unwrap().0).await; session.close();
    });
}

#[test]
fn managed_capture_shutdown_keeps_transferred_candidate_without_dispatch_or_restore() {
    run(|cx| async move {
        let f = Fixture::new(); let client = client(); let session = session(&cx, &client);
        let store = f.open(&cx, &client).await;
        let mut capture = f.begin(&cx, &session, store); ready_to_store(&mut capture, &cx).await;
        f.lane.begin_shutdown().unwrap();
        assert!(matches!(capture.run(&cx).await, Err(OAuthRefreshCaptureError::Submission(AsyncOAuthRefreshError::Io(CredentialIoError::LaneClosed)))));
        assert_eq!(f.writes(), 0); assert_eq!(f.seals(), 0);
        let OAuthRefreshCaptureCustody::ReadyToStore { store, credentials } = capture.into_custody() else { panic!("unexecuted storage input"); };
        assert!(credentials.has_refresh_token()); close(&cx, store).await; drop(credentials);
        f.lane.wait_drained(&cx, Duration::from_secs(2)).await.unwrap(); session.close();
    });
}

#[test]
fn managed_capture_cancellation_before_transfer_preserves_source_renewal() {
    run(|cx| async move {
        let f = Fixture::new(); let client = client(); let session = session(&cx, &client);
        let store = f.open(&cx, &client).await;
        let mut capture = f.begin(&cx, &session, store); ready_to_transfer(&mut capture, &cx).await;
        capture.cancel();
        assert!(matches!(capture.advance(&cx).await, Err(OAuthRefreshCaptureError::Context(OAuthError::Cancelled))));
        let mut valid = f.begin(&cx, &session, stopped_store(capture));
        valid.run(&cx).await.unwrap(); assert_eq!(f.seals(), 1);
        close(&cx, valid.take_store().unwrap().0).await; session.close();
    });
}

#[test]
fn managed_capture_competing_stores_cannot_copy_one_refresh_lineage() {
    run(|cx| async move {
        let one = Fixture::new(); let two = Fixture::new(); let client = client(); let session = session(&cx, &client);
        let mut first = one.begin(&cx, &session, one.open(&cx, &client).await);
        let mut second = two.begin(&cx, &session, two.open(&cx, &client).await);
        ready_to_transfer(&mut first, &cx).await; ready_to_transfer(&mut second, &cx).await;
        let (a, b) = native::pair(first.run(&cx), second.run(&cx)).await;
        assert_ne!(a.is_ok(), b.is_ok());
        assert_eq!(one.seals() + two.seals(), 1); assert_eq!(one.writes() + two.writes(), 2);
        for mut capture in [first, second] {
            let store = if capture.stage() == OAuthRefreshCaptureStage::Complete { capture.take_store().unwrap().0 }
                else { stopped_store(capture) };
            close(&cx, store).await;
        }
        session.close();
    });
}

#[test]
fn managed_capture_source_close_with_pending_storage_retains_actual_completion() {
    run(|cx| async move {
        let f = Fixture::new(); let client = client(); let session = session(&cx, &client);
        let store = f.open(&cx, &client).await;
        let release = Release(Gate::new()); f.provider.0.lock().unwrap().gate = Some(release.0.clone());
        let mut capture = f.begin(&cx, &session, store); ready_to_store(&mut capture, &cx).await;
        capture.advance(&cx).await.unwrap(); release.0.entered(&cx).await;
        session.close();
        assert!(matches!(capture.advance(&cx).await, Err(OAuthRefreshCaptureError::Session(OAuthSessionError::Closed))));
        let OAuthRefreshCaptureCustody::Storing(mut task) = capture.into_custody() else { panic!("same pending task"); };
        release.0.release();
        let (store, (credentials, result)) = task.wait(&cx).await.unwrap().into_parts();
        // Cancellation happened before storage transfer: sealing alone cannot
        // consume the live refresh handoff or imply a durable file replacement.
        assert!(result.is_err()); assert!(credentials.has_refresh_token()); assert_eq!(f.writes(), 0);
        assert!(credentials.bearer_credential().authorization_for_target(session.resource()).is_none(),
            "retained cleanup credentials cannot escape source closure");
        close(&cx, store).await;
    });
}

#[test]
fn managed_capture_deadline_and_constructor_refusals_do_not_spend_the_grant() {
    run(|cx| async move {
        let f = Fixture::new(); let client = client(); let session = session(&cx, &client);
        let store = f.open(&cx, &client).await;
        let failure = match store.begin_capture(&cx, &session, 0, f.auth, None,
            &McpRequestCancellation::new(), Duration::from_secs(1)) {
            Err(failure) => failure, Ok(_) => panic!("zero generation accepted"),
        };
        let (_, Some((store, ()))) = failure.into_parts() else { panic!("store retained"); };
        let mut capture = store.begin_capture(&cx, &session, 1, f.auth, None,
            &McpRequestCancellation::new(), Duration::from_millis(30)).unwrap();
        asupersync::time::sleep(cx.now(), Duration::from_millis(40)).await;
        assert!(matches!(capture.advance(&cx).await, Err(OAuthRefreshCaptureError::Context(OAuthError::TimedOut))));
        assert_eq!(f.writes(), 0); assert_eq!(f.seals(), 0);
        let mut valid = f.begin(&cx, &session, stopped_store(capture)); valid.run(&cx).await.unwrap();
        close(&cx, valid.take_store().unwrap().0).await; session.close();
    });
}
