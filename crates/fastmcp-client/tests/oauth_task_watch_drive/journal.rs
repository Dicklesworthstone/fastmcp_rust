//! Public driver and native HTTPS tests for write-ahead journal boundaries.
//! The fault-injecting host persistence boundary below retains serialized
//! controls across driver restarts, NOT across process crashes. Real protected
//! file reopening is covered by the journal's separate file-adapter tests.
//! No production transport, login, Task codec, driver or ledger is replaced.

use super::*;
use asupersync::types::Time;
use fastmcp_core::partition::{DurableOwnerKey, PartitionDescriptor};
use fastmcp_protocol::RequestId;
use fastmcp_protocol::tasks_extension::TaskInputRequests;
use fastmcp_client::http_auth::managed::tasks::watch::checkpoint::resume::TaskResumeBinding;
use fastmcp_client::http_auth::managed::tasks::watch::drive::TaskInputUpdateState;
use fastmcp_client::http_auth::managed::tasks::watch::drive::journal::{
    TaskInputJournal, TaskInputJournalChange, TaskInputJournalError,
    TaskInputJournalFuture, TaskInputJournalPersistence, TaskInputJournalRecord,
};
use fastmcp_client::http_auth::managed::tasks::watch::cancellation::{
    TaskCancellationError, TaskCancellationState,
};

const JOURNAL_CHILD: &str = "FASTMCP_TEST_INPUT_JOURNAL_CASE";

#[derive(Clone, Copy)]
enum JournalCase {
    Ordered, ReleasedIntent, FailedIntent, ForgedIntent, LostIntent, LostUpdate,
    FailedAck, LostAck, PartialRestart, ChangedAnswered, ChangedUnanswered,
    ChangedTask, LifetimeLimit, CancelIntent, DropIntent, CancelAck, RemoteIntent,
    DeadlineIntent,
}
impl JournalCase {
    fn partial(self) -> bool {
        matches!(self, Self::PartialRestart | Self::ChangedAnswered | Self::ChangedUnanswered
            | Self::ChangedTask | Self::LifetimeLimit)
    }
    fn completes(self) -> bool { matches!(self, Self::Ordered | Self::ReleasedIntent) }
    fn pauses(self) -> bool {
        matches!(self, Self::ReleasedIntent | Self::CancelIntent | Self::DropIntent
            | Self::CancelAck | Self::RemoteIntent | Self::DeadlineIntent)
    }
    fn restarts(self) -> bool {
        self.partial() || matches!(self, Self::LostIntent | Self::LostUpdate | Self::FailedAck | Self::LostAck)
    }
    fn resumes_input(self) -> bool { matches!(self, Self::PartialRestart | Self::LostAck) }
    fn updates(self) -> usize {
        if self.completes() { 2 }
        else { usize::from(self.partial() || matches!(self, Self::LostUpdate | Self::FailedAck | Self::LostAck | Self::CancelAck)) }
    }
    fn gets(self) -> usize { if self.completes() { 3 } else if self.partial() { 2 } else { 1 } }
    fn generation(self) -> u64 {
        if self.completes() { 4 }
        else if self.partial() || matches!(self, Self::LostAck) { 2 }
        else { u64::from(matches!(self, Self::LostIntent | Self::LostUpdate | Self::FailedAck | Self::CancelAck)) }
    }
    fn pending_save(self) -> bool {
        !self.completes() && !self.partial() && !matches!(self, Self::LostUpdate)
    }
    fn save_calls(self) -> usize {
        if self.completes() { 4 }
        else if self.partial() || matches!(self, Self::FailedAck | Self::LostAck | Self::CancelAck) { 2 }
        else { 1 }
    }
}

fn isolated_journal(name: &str, case: JournalCase) {
    let exact = format!("journal::{name}");
    if let Ok(selected) = std::env::var(JOURNAL_CHILD) {
        assert_eq!(selected, exact);
        RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(Box::pin(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), Box::pin(scenario(&cx, case)))
                .await.expect("journal HTTPS scenario exceeded its bound");
        }));
        return;
    }
    struct Root(std::path::PathBuf);
    impl Drop for Root { fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); } }
    struct Child(std::process::Child);
    impl Drop for Child { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
    let root = Root(std::env::temp_dir().join(format!("fastmcp-journal-ca-{}-{name}.pem", std::process::id())));
    std::fs::write(&root.0, ROOT).unwrap();
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &exact, "--nocapture", "--test-threads=1"])
        .env(JOURNAL_CHILD, &exact).env("SSL_CERT_FILE", &root.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() { assert!(status.success(), "journal HTTPS child failed"); return; }
        assert!(Instant::now() < deadline, "journal HTTPS child exceeded its bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn binding(peer: &Peer) -> TaskResumeBinding {
    let resource = peer.resource();
    let facts = PartitionDescriptor::from_verified_facts("fixture", 1, "https://issuer.example",
        &resource, "tenant", "subject", "watch-client", 1, 1, &[b"resource".as_slice()]).unwrap();
    let owner = DurableOwnerKey::derive(&facts, 1).unwrap();
    TaskResumeBinding::from_verified_owner(url(&resource), "https-journal", &owner,
        [1; 32], [2; 32], [3; 32]).unwrap()
}

#[derive(Clone)]
struct Storage {
    bytes: Arc<Mutex<Vec<u8>>>,
    committed: Arc<Mutex<Vec<u64>>>,
}
impl Storage {
    fn new(binding: &TaskResumeBinding) -> Self {
        let empty = TaskInputJournalRecord::empty(binding, TaskId::parse("one").unwrap()).unwrap();
        Self { bytes: Arc::new(Mutex::new(empty.encode().unwrap())), committed: Arc::new(Mutex::new(Vec::new())) }
    }
    fn snapshot(&self) -> TaskInputJournalRecord {
        TaskInputJournalRecord::decode(&self.bytes.lock().unwrap()).unwrap()
    }
}

// Model only the host persistence boundary to plant independently controlled
// before-commit failures, after-commit lost replies and abandoned pending saves.
// The file adapter and provider cryptography are NOT mocked as passing here.
#[derive(Clone)]
struct Persistence {
    storage: Storage,
    case: JournalCase,
    entered: McpRequestCancellation,
    release: McpRequestCancellation,
    calls: Arc<AtomicUsize>,
    dropped: Arc<AtomicUsize>,
}
impl Persistence {
    fn new(storage: Storage, case: JournalCase) -> Self {
        Self { storage, case, entered: McpRequestCancellation::new(), release: McpRequestCancellation::new(),
            calls: Arc::new(AtomicUsize::new(0)), dropped: Arc::new(AtomicUsize::new(0)) }
    }
}
impl TaskInputJournalPersistence for Persistence {
    fn commit<'a>(&'a mut self, cx: &'a Cx, cancellation: &'a McpRequestCancellation,
        deadline: Time, change: TaskInputJournalChange) -> TaskInputJournalFuture<'a>
    {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let _probe = DropProbe(Arc::clone(&self.dropped));
            assert!(cx.checkpoint().is_ok());
            assert!(!cancellation.is_cancel_requested());
            assert!(cx.now() < deadline);
            assert_eq!(&self.storage.snapshot(), change.expected(), "conditional predecessor must match physical controls");
            let generation = change.proposed().generation();
            let ack = change.proposed().update_state() == TaskInputUpdateState::Acknowledged;
            assert_eq!(generation, change.expected().generation() + 1);
            assert_eq!(ack, generation.is_multiple_of(2));
            let pause_generation = if matches!(self.case, JournalCase::CancelAck) { 2 } else { 1 };
            if self.case.pauses() && generation == pause_generation {
                self.entered.cancel();
                self.release.cancelled().await;
            }
            if (generation == 1 && matches!(self.case, JournalCase::FailedIntent))
                || (generation == 2 && matches!(self.case, JournalCase::FailedAck))
            { return Err(TaskInputJournalError::Persistence); }
            if generation == 1 && matches!(self.case, JournalCase::ForgedIntent) {
                return Ok(change.expected().clone());
            }
            // Serialize, install, then decode: restart cannot retain the old
            // driver's in-memory history or borrow the proposed record itself.
            let encoded = change.proposed().encode()?;
            for forbidden in [b"roots/list".as_slice(), b"watch-access".as_slice(), b"inputResponses".as_slice()] {
                assert!(!encoded.windows(forbidden.len()).any(|bytes| bytes == forbidden));
            }
            *self.storage.bytes.lock().unwrap() = encoded;
            self.storage.committed.lock().unwrap().push(generation);
            if (generation == 1 && matches!(self.case, JournalCase::LostIntent))
                || (generation == 2 && matches!(self.case, JournalCase::LostAck))
            { return Err(TaskInputJournalError::Persistence); }
            Ok(self.storage.snapshot())
        })
    }
}

fn no_resolver(_: TaskInputRequests) -> std::future::Ready<Result<ManagedTaskInputAction, ManagedTaskWatchDriveError>> {
    panic!("closed or unpolled driver must not resolve input")
}
fn no_observer(_: &Task) -> Result<(), ManagedTaskWatchDriveError> { panic!("closed or unpolled driver must not publish") }

async fn checked_get(peer: &Peer, storage: &Storage, generation: u64, result: Value) {
    peer.discover().await;
    let (mut socket, request) = peer.request("tasks/get").await;
    peer.gets.fetch_add(1, Ordering::SeqCst);
    assert_eq!(request["params"]["taskId"], "one");
    assert_eq!(storage.snapshot().generation(), generation, "get must not overtake a receipt save");
    reply(&mut socket, json!({"jsonrpc":"2.0", "id":request["id"], "result":result})).await;
}
async fn checked_update(peer: &Peer, storage: &Storage, generation: u64, key: &str, lost: bool) {
    peer.discover().await;
    let (mut socket, request) = peer.request("tasks/update").await;
    peer.updates.fetch_add(1, Ordering::SeqCst);
    assert_eq!(request["params"]["taskId"], "one");
    assert_eq!(request["params"]["inputResponses"], json!({key:{"roots":[]}}));
    let intent = storage.snapshot();
    assert_eq!(intent.generation(), generation, "update must not reach the peer before its intent is stored");
    assert_eq!(intent.update_state(), TaskInputUpdateState::Unconfirmed);
    assert_eq!(intent.acknowledged_updates() as u64, (generation - 1) / 2);
    if lost {
        // The peer has accepted the mutation, but returns no usable ACK.
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 128\r\nConnection: close\r\n\r\n{\"jsonrpc\":").await.unwrap();
        socket.shutdown().await.unwrap();
    } else {
        reply(&mut socket, json!({"jsonrpc":"2.0", "id":request["id"], "result":{"resultType":"complete"}})).await;
    }
}
async fn cancel(peer: &Peer) {
    peer.discover().await;
    let (mut socket, request) = peer.request("tasks/cancel").await;
    assert_eq!(request["id"], "journal:cancel:operation");
    assert_eq!(request["params"]["taskId"], "one");
    reply(&mut socket, json!({"jsonrpc":"2.0", "id":request["id"], "result":{"resultType":"complete"}})).await;
}

async fn scenario(cx: &Cx, case: JournalCase) {
    let peer = Peer::new().await;
    let ((), session) = pair(Box::pin(peer.login()), Box::pin(ManagedOAuthSession::authorize(
        cx, peer.client(), OAuthSessionPolicy::default(), browser,
    ))).await;
    let session = session.unwrap();
    let caps = serde_json::from_value(json!({"roots":{}})).unwrap();
    let client = ManagedTasksClient::new(session.clone(), FinalRequestMeta::new(caps), ManagedTasksLimits::default()).unwrap();
    let binding = binding(&peer);
    let storage = Storage::new(&binding);
    let persistence = Persistence::new(storage.clone(), case);
    let cancellation = McpRequestCancellation::new();
    let timeout = if matches!(case, JournalCase::DeadlineIntent) { Duration::from_secs(5) } else { Duration::from_secs(10) };
    let policy = ManagedTaskWatchDrivePolicy::new(ManagedTaskWatchPolicy::new(timeout, 8, 16).unwrap(), 4, 8, 65536).unwrap();
    let (mut stream, opened) = pair(Box::pin(peer.listen()), Box::pin(client.watch_task_inputs_with_cancellation(
        cx, &cancellation, TaskId::parse("one").unwrap(), "journal".to_owned(), policy,
    ))).await;
    let mut driver = opened.unwrap().with_input_journal(TaskInputJournal::new(
        binding.clone(), storage.snapshot(), persistence.clone(),
    ).unwrap()).unwrap();
    let handle = driver.cancel_handle();
    drop(Box::pin(driver.drive(cx, no_resolver, no_observer)));
    assert_eq!(persistence.calls.load(Ordering::SeqCst), 0);
    assert_eq!(peer.seen.lock().unwrap().len(), 2);
    let resolutions = AtomicUsize::new(0);
    let observations = AtomicUsize::new(0);
    let server = Box::pin(async {
        checked_get(&peer, &storage, 0, task("input_required")).await;
        if case.updates() != 0 {
            checked_update(&peer, &storage, 1, "first", matches!(case, JournalCase::LostUpdate)).await;
            if case.partial() || case.completes() {
                checked_get(&peer, &storage, 2, task("input_required")).await;
                if case.completes() {
                    checked_update(&peer, &storage, 3, "second", false).await;
                    checked_get(&peer, &storage, 4, task("completed")).await;
                }
            }
        } else if matches!(case, JournalCase::RemoteIntent) { cancel(&peer).await; }
        assert_closed(&mut stream).await;
    });
    let application = Box::pin(async {
        let mut driving = Box::pin(driver.drive(cx, |requests: TaskInputRequests| {
            let n = resolutions.fetch_add(1, Ordering::SeqCst);
            assert_eq!(requests.keys().map(String::as_str).collect::<Vec<_>>(),
                if n == 0 { vec!["first", "second"] } else { vec!["second"] });
            assert!(n < 2, "no resolver replay within a run");
            let key = if n == 0 { "first" } else { "second" };
            std::future::ready(Ok(if case.partial() && n == 1 { ManagedTaskInputAction::ReturnToCaller }
                else { ManagedTaskInputAction::Respond(serde_json::from_value(
                    json!({key:{"roots":[]}})).unwrap()) }))
        }, |_| { observations.fetch_add(1, Ordering::SeqCst); Ok(()) }));
        if case.pauses() {
            poll_fn(|task| {
                assert!(driving.as_mut().poll(task).is_pending());
                if persistence.entered.is_cancel_requested() { Poll::Ready(()) } else { Poll::Pending }
            }).await;
            assert_eq!(storage.snapshot().generation(), u64::from(matches!(case, JournalCase::CancelAck)));
            // The provider was actually entered; an unpolled dummy cannot
            // satisfy this boundary. No update/get may overtake its completion.
            // Do not poll the active listener with a noop waker: that could
            // replace the server future's registration while it awaits a POST.
            assert_eq!(peer.gets.load(Ordering::SeqCst), 1);
            assert_eq!(peer.updates.load(Ordering::SeqCst), usize::from(matches!(case, JournalCase::CancelAck)));
            if matches!(case, JournalCase::ReleasedIntent) { persistence.release.cancel(); }
            if matches!(case, JournalCase::CancelIntent | JournalCase::CancelAck) { cancellation.cancel(); }
        }
        if matches!(case, JournalCase::DropIntent) { drop(driving); }
        else {
            let result = if matches!(case, JournalCase::RemoteIntent) {
                let (result, cancelled) = pair(driving, Box::pin(handle.request_cancel(cx))).await;
                cancelled.unwrap(); result
            } else { driving.await };
            if case.completes() {
                assert!(matches!(result, Ok(ManagedTaskRunOutcome::Terminal(task)) if matches!(*task, Task::Completed { .. })));
            } else if case.partial() { assert!(matches!(result, Ok(ManagedTaskRunOutcome::InputRequired(_)))); }
            else {
                match (case, result) {
                    (JournalCase::FailedIntent | JournalCase::LostIntent | JournalCase::FailedAck | JournalCase::LostAck,
                        Err(ManagedTaskWatchDriveError::Journal(TaskInputJournalError::Persistence))) => {},
                    (JournalCase::ForgedIntent, Err(ManagedTaskWatchDriveError::Journal(TaskInputJournalError::InvalidReceipt))) => {},
                    (JournalCase::LostUpdate, Err(ManagedTaskWatchDriveError::Watch(_))) => {},
                    (JournalCase::CancelIntent | JournalCase::CancelAck,
                        Err(ManagedTaskWatchDriveError::Watch(ManagedTaskWatchError::Session(OAuthSessionError::Cancelled)))) => {},
                    (JournalCase::DeadlineIntent,
                        Err(ManagedTaskWatchDriveError::Watch(ManagedTaskWatchError::Session(OAuthSessionError::TimedOut)))) => {},
                    (JournalCase::RemoteIntent, Err(ManagedTaskWatchDriveError::CancellationRequested)) => {},
                    (_, result) => panic!("unexpected journaled driver outcome: {:?}", result.err()),
                }
            }
        }
    });
    pair(server, application).await;
    let acked = if matches!(case, JournalCase::LostUpdate) { 0 } else { case.updates() };
    assert_eq!(driver.acknowledged_updates(), acked);
    assert_eq!(driver.update_state(), if matches!(case, JournalCase::LostUpdate) { TaskInputUpdateState::Unconfirmed }
        else if acked != 0 { TaskInputUpdateState::Acknowledged } else { TaskInputUpdateState::NotAttempted });
    let expected_id = if case.completes() { Some(RequestId::String("journal:9".to_owned())) }
        else if case.updates() != 0 { Some(RequestId::String("journal:5".to_owned())) } else { None };
    assert_eq!(driver.last_update_request_id(), expected_id.as_ref());
    let journal = driver.input_journal().unwrap();
    assert_eq!(journal.pending_change().is_some(), case.pending_save());
    if case.pending_save() { assert_eq!(journal.record().unwrap_err(), TaskInputJournalError::ReconciliationRequired); }
    else { assert_eq!(journal.record().unwrap(), &storage.snapshot()); }
    assert_eq!(storage.snapshot().generation(), case.generation());
    assert_eq!(persistence.calls.load(Ordering::SeqCst), case.save_calls());
    assert_eq!(persistence.dropped.load(Ordering::SeqCst), case.save_calls(), "all provider futures must be released");
    assert_eq!(resolutions.load(Ordering::SeqCst), if case.partial() || case.completes() { 2 } else { 1 });
    assert_eq!(observations.load(Ordering::SeqCst), case.gets());
    assert_eq!(handle.state(), if matches!(case, JournalCase::RemoteIntent) { TaskCancellationState::Acknowledged } else { TaskCancellationState::Ready });
    driver.close();
    assert!(driver.drive(cx, no_resolver, no_observer).await.is_err());
    assert_eq!(driver.acknowledged_updates(), acked);
    assert!(matches!(handle.request_cancel(cx).await, Err(TaskCancellationError::Closed | TaskCancellationError::AlreadyAttempted)));
    drop(driver);
    let first_requests = 2 * (1 + case.gets() + case.updates());
    let mut expected: BTreeSet<_> = (0..first_requests).map(|n| format!("journal:{n}")).collect();
    if matches!(case, JournalCase::RemoteIntent) {
        expected.insert("journal:cancel:discovery".to_owned()); expected.insert("journal:cancel:operation".to_owned());
    }
    assert_eq!(*peer.seen.lock().unwrap(), expected);
    if case.restarts() {
        restart(cx, &peer, &client, &binding, &storage, case).await;
        let requests = if case.resumes_input() { 8 } else { 4 };
        expected.extend((0..requests).map(|n| format!("restart:{n}")));
    }
    assert_eq!(*peer.seen.lock().unwrap(), expected);
    assert_eq!(peer.gets.load(Ordering::SeqCst), case.gets() + if case.restarts() { if case.resumes_input() { 2 } else { 1 } } else { 0 });
    assert_eq!(peer.updates.load(Ordering::SeqCst), case.updates() + usize::from(case.resumes_input()));
    let final_generation = if case.resumes_input() { 4 } else { case.generation() };
    assert_eq!(*storage.committed.lock().unwrap(), (1..=final_generation).collect::<Vec<_>>());
    assert_eq!(cancellation.is_cancel_requested(), matches!(case, JournalCase::CancelIntent | JournalCase::CancelAck));
    assert!(cx.checkpoint().is_ok());
    assert!(session.credential(cx).await.is_ok());
    peer.no_extra_request();
}

async fn restart(cx: &Cx, peer: &Peer, client: &ManagedTasksClient, binding: &TaskResumeBinding,
    storage: &Storage, case: JournalCase)
{
    let before = storage.bytes.lock().unwrap().clone();
    // There is no old driver or input history here. Only the saved codec bytes,
    // current host binding and the still-authorized login cross this boundary.
    let record = TaskInputJournalRecord::decode(&before).unwrap();
    let persistence = Persistence::new(storage.clone(), JournalCase::Ordered);
    let policy = ManagedTaskWatchDrivePolicy::new(ManagedTaskWatchPolicy::new(Duration::from_secs(10), 8, 16).unwrap(),
        if matches!(case, JournalCase::LifetimeLimit) { 1 } else { 4 }, 8, 65536).unwrap();
    let (mut stream, opened) = pair(Box::pin(peer.listen()), Box::pin(client.watch_task_inputs(
        cx, TaskId::parse("one").unwrap(), "restart".to_owned(), policy,
    ))).await;
    let mut driver = opened.unwrap().with_input_journal(TaskInputJournal::new(binding.clone(), record, persistence.clone()).unwrap()).unwrap();
    let mut snapshot = task("input_required");
    if matches!(case, JournalCase::ChangedAnswered | JournalCase::ChangedUnanswered) {
        let key = if matches!(case, JournalCase::ChangedAnswered) { "first" } else { "second" };
        snapshot["inputRequests"][key] = json!({"method":"sampling/createMessage","params":{"messages":[],"maxTokens":1}});
    }
    if matches!(case, JournalCase::ChangedTask) {
        snapshot["createdAt"] = json!("2026-09-17T00:00:01Z");
        snapshot["lastUpdatedAt"] = json!("2026-09-17T00:00:01Z");
    }
    let resolutions = AtomicUsize::new(0);
    let observations = AtomicUsize::new(0);
    let server = Box::pin(async {
        checked_get(peer, storage, case.generation(), snapshot).await;
        if case.resumes_input() {
            checked_update(peer, storage, 3, "second", false).await;
            checked_get(peer, storage, 4, task("completed")).await;
        }
        assert_closed(&mut stream).await;
    });
    let application = Box::pin(driver.drive(cx, |requests: TaskInputRequests| {
        assert!(case.resumes_input(), "uncertain or rejected restart must not invoke a resolver");
        assert_eq!(resolutions.fetch_add(1, Ordering::SeqCst), 0);
        assert_eq!(requests.keys().map(String::as_str).collect::<Vec<_>>(), ["second"]);
        std::future::ready(Ok(ManagedTaskInputAction::Respond(serde_json::from_value(json!({"second":{"roots":[]}})).unwrap())))
    }, |_| { observations.fetch_add(1, Ordering::SeqCst); Ok(()) }));
    let ((), result) = pair(server, application).await;
    if case.resumes_input() {
        assert!(matches!(result, Ok(ManagedTaskRunOutcome::Terminal(task)) if matches!(*task, Task::Completed { .. })));
        assert_eq!(driver.acknowledged_updates(), 2);
        assert_eq!(driver.last_update_request_id(), Some(&RequestId::String("restart:5".to_owned())));
    } else {
        match (case, result) {
            (JournalCase::ChangedAnswered | JournalCase::ChangedUnanswered,
                Err(ManagedTaskWatchDriveError::Input(ManagedTaskDriverError::InputKeyReused))) => {},
            (JournalCase::ChangedTask, Err(ManagedTaskWatchDriveError::Journal(TaskInputJournalError::TaskChanged))) => {},
            (JournalCase::LifetimeLimit, Err(ManagedTaskWatchDriveError::Input(ManagedTaskDriverError::UpdateLimit))) => {},
            (JournalCase::LostIntent | JournalCase::LostUpdate | JournalCase::FailedAck,
                Err(ManagedTaskWatchDriveError::Journal(TaskInputJournalError::ReconciliationRequired))) => {},
            (_, result) => panic!("unexpected restored journal outcome: {:?}", result.err()),
        }
        assert_eq!(*storage.bytes.lock().unwrap(), before);
    }
    assert_eq!(persistence.calls.load(Ordering::SeqCst), if case.resumes_input() { 2 } else { 0 });
    assert_eq!(resolutions.load(Ordering::SeqCst), usize::from(case.resumes_input()));
    assert_eq!(observations.load(Ordering::SeqCst), if matches!(case, JournalCase::ChangedTask) { 0 }
        else if case.resumes_input() { 2 } else { 1 });
    assert_eq!(driver.input_journal().unwrap().record().unwrap(), &storage.snapshot());
}

#[test]
fn intents_precede_updates_and_receipts_precede_reconciliation() { isolated_journal("intents_precede_updates_and_receipts_precede_reconciliation", JournalCase::Ordered); }
#[test]
fn releasing_a_pending_intent_allows_the_same_update_once() { isolated_journal("releasing_a_pending_intent_allows_the_same_update_once", JournalCase::ReleasedIntent); }
#[test]
fn failed_intent_persistence_prevents_the_update_post() { isolated_journal("failed_intent_persistence_prevents_the_update_post", JournalCase::FailedIntent); }
#[test]
fn a_forged_persistence_receipt_cannot_authorize_an_update() { isolated_journal("a_forged_persistence_receipt_cannot_authorize_an_update", JournalCase::ForgedIntent); }
#[test]
fn committed_intent_with_lost_save_reply_blocks_restart_mutation() { isolated_journal("committed_intent_with_lost_save_reply_blocks_restart_mutation", JournalCase::LostIntent); }
#[test]
fn a_peer_accepted_update_with_lost_ack_is_not_replayed_after_restart() { isolated_journal("a_peer_accepted_update_with_lost_ack_is_not_replayed_after_restart", JournalCase::LostUpdate); }
#[test]
fn failed_receipt_save_retains_wire_ack_but_blocks_restart_mutation() { isolated_journal("failed_receipt_save_retains_wire_ack_but_blocks_restart_mutation", JournalCase::FailedAck); }
#[test]
fn committed_receipt_with_lost_save_reply_reopens_without_answer_replay() { isolated_journal("committed_receipt_with_lost_save_reply_reopens_without_answer_replay", JournalCase::LostAck); }
#[test]
fn restarting_partial_input_resolves_only_the_unanswered_key() { isolated_journal("restarting_partial_input_resolves_only_the_unanswered_key", JournalCase::PartialRestart); }
#[test]
fn changed_answered_descriptor_is_rejected_after_restart() { isolated_journal("changed_answered_descriptor_is_rejected_after_restart", JournalCase::ChangedAnswered); }
#[test]
fn changed_unanswered_descriptor_is_rejected_after_restart() { isolated_journal("changed_unanswered_descriptor_is_rejected_after_restart", JournalCase::ChangedUnanswered); }
#[test]
fn reused_task_creation_identity_is_rejected_before_publication() { isolated_journal("reused_task_creation_identity_is_rejected_before_publication", JournalCase::ChangedTask); }
#[test]
fn restarting_does_not_refund_the_lifetime_update_budget() { isolated_journal("restarting_does_not_refund_the_lifetime_update_budget", JournalCase::LifetimeLimit); }
#[test]
fn local_cancel_during_intent_save_prevents_the_update_post() { isolated_journal("local_cancel_during_intent_save_prevents_the_update_post", JournalCase::CancelIntent); }
#[test]
fn abandoned_intent_save_retires_driver_and_retains_pending_change() { isolated_journal("abandoned_intent_save_retires_driver_and_retains_pending_change", JournalCase::DropIntent); }
#[test]
fn local_cancel_during_receipt_save_preserves_wire_ack() { isolated_journal("local_cancel_during_receipt_save_preserves_wire_ack", JournalCase::CancelAck); }
#[test]
fn remote_cancel_ack_interrupts_a_pending_intent_save() { isolated_journal("remote_cancel_ack_interrupts_a_pending_intent_save", JournalCase::RemoteIntent); }
#[test]
fn pending_intent_save_cannot_extend_the_original_deadline() { isolated_journal("pending_intent_save_cannot_extend_the_original_deadline", JournalCase::DeadlineIntent); }
