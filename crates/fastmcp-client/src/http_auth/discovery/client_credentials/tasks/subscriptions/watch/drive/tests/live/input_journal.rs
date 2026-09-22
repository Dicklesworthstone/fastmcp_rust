//! Journaled machine input execution over the existing real native TLS peer.
//! The host persistence fixture models conditional commits and lost replies;
//! it is NOT a cryptographic provider or process-crash durability proof. Tokens
//! are pre-acquired, as in the parent fixture. No transport/driver is mocked.

use super::*;
use std::cell::Cell;
use asupersync::types::Time;
use fastmcp_core::partition::{DurableOwnerKey, PartitionDescriptor};
use crate::http_auth::discovery::client_credentials::{ClientCredentialsError, OAuthDiscoveryError};
use crate::http_auth::discovery::client_credentials::tasks::ClientCredentialsTasksError;
use crate::http_auth::discovery::client_credentials::tasks::subscriptions::watch::cancellation::{
    ClientCredentialsTaskCancellationError, TaskCancellationState,
};
use crate::http_auth::discovery::client_credentials::tasks::subscriptions::watch::recovery::ClientCredentialsTaskRecoveryPolicy;
use crate::http_auth::managed::tasks::watch::checkpoint::resume::TaskResumeBinding;
use crate::http_auth::managed::tasks::watch::drive::journal::{
    TaskInputJournal, TaskInputJournalChange, TaskInputJournalError, TaskInputJournalRecord,
};

#[derive(Clone, Copy, Debug)]
enum JournalCase {
    Order, GateIntent, GateAck, FailIntent, WrongIntent, LostIntentReceipt,
    FailAck, LostAckReceipt, LostUpdate, Resume, ChangedAnswered, ChangedUnanswered,
    ChangedTask, Limit, LocalIntent, DropIntent, RemoteIntent, RevokeIntent,
    ExpireIntent, DeadlineIntent, RemoteAck, DropAck, Recovery, SnapshotLimit,
}
impl JournalCase {
    fn gate(self) -> Option<u64> {
        match self {
            Self::GateIntent | Self::LocalIntent | Self::DropIntent | Self::RemoteIntent
            | Self::RevokeIntent | Self::ExpireIntent | Self::DeadlineIntent => Some(1),
            Self::GateAck | Self::RemoteAck | Self::DropAck => Some(2),
            _ => None,
        }
    }
    fn remote(self) -> bool { matches!(self, Self::RemoteIntent | Self::RemoteAck) }
    fn abandon(self) -> bool { matches!(self, Self::DropIntent | Self::DropAck) }
    fn pauses(self) -> bool {
        matches!(self, Self::Resume | Self::ChangedAnswered | Self::ChangedUnanswered | Self::ChangedTask | Self::Limit)
    }
    fn completes(self) -> bool { matches!(self, Self::Order | Self::GateIntent | Self::GateAck | Self::Recovery) }
    fn updates(self) -> usize {
        if self.completes() { 2 }
        else if self.pauses() || matches!(self, Self::FailAck | Self::LostAckReceipt | Self::LostUpdate | Self::RemoteAck | Self::DropAck) { 1 }
        else { 0 }
    }
    fn restarts(self) -> bool {
        self.pauses() || matches!(self, Self::LostIntentReceipt | Self::FailAck | Self::LostAckReceipt | Self::LostUpdate)
    }
    fn restart_completes(self) -> bool { matches!(self, Self::Resume | Self::LostAckReceipt) }
    fn generation(self) -> u64 {
        if self.completes() { 4 }
        else if self.pauses() || matches!(self, Self::LostAckReceipt) { 2 }
        else if self.updates() != 0 || matches!(self, Self::LostIntentReceipt) { 1 }
        else { 0 }
    }
    fn pending_generation(self) -> Option<u64> {
        match self {
            Self::FailIntent | Self::WrongIntent | Self::LostIntentReceipt | Self::LocalIntent
            | Self::DropIntent | Self::RemoteIntent | Self::RevokeIntent | Self::ExpireIntent | Self::DeadlineIntent => Some(1),
            Self::FailAck | Self::LostAckReceipt | Self::RemoteAck | Self::DropAck => Some(2),
            _ => None,
        }
    }
    fn numeric_requests(self) -> usize {
        if matches!(self, Self::Recovery) { 16 }
        else if self.completes() { 12 }
        else if self.pauses() { 8 }
        else if self.updates() != 0 { 6 }
        else { 4 }
    }
    fn saves(self) -> usize {
        if self.completes() { 4 }
        else if self.pauses() || matches!(self, Self::FailAck | Self::LostAckReceipt | Self::RemoteAck | Self::DropAck) { 2 }
        else if matches!(self, Self::SnapshotLimit) { 0 }
        else { 1 }
    }
}

fn isolated_journal(name: &str, case: JournalCase) {
    isolated_run(&format!("input_journal::{name}"), || run_journal(case));
}
fn binding(client: &ClientCredentialsTasksClient) -> TaskResumeBinding {
    let resource = client.client.resource().clone();
    let facts = PartitionDescriptor::from_verified_facts("fixture", 1, "https://issuer.example",
        resource.as_str(), "tenant", "machine-subject", "machine-client", 1, 1,
        &[b"bound-resource".as_slice()]).unwrap();
    let owner = DurableOwnerKey::derive(&facts, 1).unwrap();
    TaskResumeBinding::from_verified_owner(resource, "machine-input-journal", &owner,
        [11; 32], [3; 32], [4; 32]).unwrap()
}

struct Stored { record: TaskInputJournalRecord, calls: usize, writes: usize }
#[derive(Clone)]
struct Store {
    stored: Arc<Mutex<Stored>>,
    entered: McpRequestCancellation,
    release: McpRequestCancellation,
    dropped: Arc<AtomicUsize>,
}
struct SaveDrop(Arc<AtomicUsize>);
impl Drop for SaveDrop { fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); } }
impl Store {
    fn new(binding: &TaskResumeBinding) -> Self {
        Self {
            stored: Arc::new(Mutex::new(Stored {
                record: TaskInputJournalRecord::empty(binding, TaskId::parse("one").unwrap()).unwrap(),
                calls: 0, writes: 0,
            })),
            entered: McpRequestCancellation::new(), release: McpRequestCancellation::new(),
            dropped: Arc::new(AtomicUsize::new(0)),
        }
    }
    fn record(&self) -> TaskInputJournalRecord { self.stored.lock().unwrap().record.clone() }
    fn counts(&self) -> (usize, usize) {
        let stored = self.stored.lock().unwrap();
        (stored.calls, stored.writes)
    }
    fn require_generation(&self, generation: u64) {
        let record = self.record();
        assert_eq!(record.generation(), generation, "wire effect overtook its durable journal boundary");
        assert_eq!(record.update_state(), if generation == 0 { TaskInputUpdateState::NotAttempted }
            else if generation % 2 == 0 { TaskInputUpdateState::Acknowledged } else { TaskInputUpdateState::Unconfirmed });
    }
    fn journal(&self, binding: TaskResumeBinding, case: JournalCase) -> TaskInputJournal {
        // Reconstruct from the simulated authoritative storage, not the failed
        // driver's cached predecessor or a fabricated acknowledgement.
        let restored = TaskInputJournalRecord::decode(&self.record().encode().unwrap()).unwrap();
        let store = self.clone();
        TaskInputJournal::new(binding, restored,
            move |_: Cx, _: McpRequestCancellation, _: Time, change: TaskInputJournalChange| {
                let store = store.clone();
                async move {
                    let _drop = SaveDrop(Arc::clone(&store.dropped));
                    {
                        let mut stored = store.stored.lock().unwrap();
                        assert_eq!(&stored.record, change.expected(), "conditional predecessor changed");
                        stored.calls += 1;
                    }
                    let generation = change.proposed().generation();
                    if case.gate() == Some(generation) {
                        store.entered.cancel();
                        store.release.cancelled().await;
                    }
                    if (matches!(case, JournalCase::FailIntent) && generation == 1)
                        || (matches!(case, JournalCase::FailAck) && generation == 2)
                    { return Err(TaskInputJournalError::Persistence); }
                    if matches!(case, JournalCase::WrongIntent) && generation == 1 {
                        return Ok(change.expected().clone());
                    }
                    {
                        let mut stored = store.stored.lock().unwrap();
                        assert_eq!(&stored.record, change.expected());
                        stored.record = change.proposed().clone();
                        stored.writes += 1;
                    }
                    if (matches!(case, JournalCase::LostIntentReceipt) && generation == 1)
                        || (matches!(case, JournalCase::LostAckReceipt) && generation == 2)
                    { return Err(TaskInputJournalError::Persistence); }
                    Ok(change.proposed().clone())
                }
            }).unwrap()
    }
}

fn no_resolver(_: TaskInputRequests) -> std::future::Ready<Result<ManagedTaskInputAction, ClientCredentialsTaskWatchDriveError>> {
    panic!("closed or unpolled journaled driver must not resolve input")
}
fn no_observer(_: &Task) -> Result<(), ClientCredentialsTaskWatchDriveError> {
    panic!("closed or unpolled journaled driver must not publish a snapshot")
}
fn forbid_renewal(client: &ClientCredentialsTasksClient) {
    client.client.inner.state.try_lock_owned().unwrap().current.as_mut().unwrap().renew_after = Instant::now();
}
fn client(peer: &Peer, expiring: bool) -> ClientCredentialsTasksClient {
    let mut client = peer.client();
    let inner = Arc::get_mut(&mut client.client.inner).unwrap();
    inner.timeout = Duration::from_secs(12);
    if expiring {
        let expires_at = Instant::now() + Duration::from_secs(5);
        let bearer = BoundBearerCredential::bind_with_expiry(inner.resource.clone(), "watched-access", expires_at)
            .unwrap().for_owner(&inner.closed).unwrap();
        inner.state.try_lock_owned().unwrap().current = Some(ServiceToken {
            bearer, scopes: vec![], expires_at, renew_after: expires_at,
        });
    }
    client
}

async fn get(peer: &Peer, store: &Store, generation: u64, status: &str, changed: Option<JournalCase>) {
    peer.discover().await;
    let (mut socket, request) = peer.rpc("tasks/get").await;
    store.require_generation(generation);
    assert_eq!(request["params"]["taskId"], "one");
    let mut result = task("one", status);
    result["resultType"] = json!("complete");
    match changed {
        Some(JournalCase::ChangedTask) => result["createdAt"] = json!("2026-09-18T23:59:59Z"),
        Some(case @ (JournalCase::ChangedAnswered | JournalCase::ChangedUnanswered)) => {
            let key = if matches!(case, JournalCase::ChangedAnswered) { "one" } else { "two" };
            result["inputRequests"][key] = json!({"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16}});
        }
        _ => {},
    }
    reply(&mut socket, json!({"jsonrpc":"2.0","id":request["id"],"result":result})).await;
}
async fn update(peer: &Peer, store: &Store, generation: u64, key: &str, lose_reply: bool) {
    peer.discover().await;
    let (mut socket, request) = peer.rpc("tasks/update").await;
    store.require_generation(generation);
    assert_eq!(request["params"]["taskId"], "one");
    assert_eq!(request["params"]["inputResponses"], json!({key:{"roots":[]}}));
    peer.updates.fetch_add(1, Ordering::SeqCst);
    if lose_reply {
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 128\r\nConnection: close\r\n\r\n{\"jsonrpc\":").await.unwrap();
        socket.shutdown().await.unwrap();
    } else {
        reply(&mut socket, json!({"jsonrpc":"2.0","id":request["id"],"result":{"resultType":"complete"}})).await;
    }
}
async fn cancel(peer: &Peer) {
    peer.discover().await;
    let (mut socket, request) = peer.rpc("tasks/cancel").await;
    assert_eq!(request["id"], "journal:cancel:operation");
    assert_eq!(request["params"]["taskId"], "one");
    reply(&mut socket, json!({"jsonrpc":"2.0","id":request["id"],"result":{"resultType":"complete"}})).await;
}
async fn interrupted_get(peer: &Peer, store: &Store) {
    peer.discover().await;
    let (mut socket, request) = peer.rpc("tasks/get").await;
    assert_eq!(request["params"]["taskId"], "one");
    store.require_generation(2);
    // A complete HTTP body without a Task result is a lost observation. Unlike
    // a mutation reply, this read may use the explicitly enabled recovery path.
    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n").await.unwrap();
    socket.shutdown().await.unwrap();
}

fn require_failure(case: JournalCase, result: Result<ManagedTaskRunOutcome, ClientCredentialsTaskWatchDriveError>) {
    let error = result.err().expect("failed journal operation cannot fabricate a terminal");
    match (case, error) {
        (JournalCase::FailIntent | JournalCase::LostIntentReceipt | JournalCase::FailAck | JournalCase::LostAckReceipt,
            ClientCredentialsTaskWatchDriveError::Journal(TaskInputJournalError::Persistence)) => {},
        (JournalCase::WrongIntent, ClientCredentialsTaskWatchDriveError::Journal(TaskInputJournalError::InvalidReceipt)) => {},
        (JournalCase::LostUpdate, ClientCredentialsTaskWatchDriveError::Watch(ClientCredentialsTaskWatchError::Task(
            ClientCredentialsTasksError::Protocol(ManagedTasksError::InvalidResponse)))) => {},
        (JournalCase::RemoteIntent | JournalCase::RemoteAck, ClientCredentialsTaskWatchDriveError::CancellationRequested) => {},
        (JournalCase::LocalIntent, ClientCredentialsTaskWatchDriveError::Watch(ClientCredentialsTaskWatchError::Task(
            ClientCredentialsTasksError::Authentication(ClientCredentialsError::Discovery(OAuthDiscoveryError::Cancelled))))) => {},
        (JournalCase::RevokeIntent, ClientCredentialsTaskWatchDriveError::Watch(ClientCredentialsTaskWatchError::Task(
            ClientCredentialsTasksError::Authentication(ClientCredentialsError::Expired)))) => {},
        // The original token's expiry can win in check_token or in the outer
        // deadline timer. Both are terminal and neither authorizes renewal.
        (JournalCase::ExpireIntent, ClientCredentialsTaskWatchDriveError::Watch(ClientCredentialsTaskWatchError::Task(
            ClientCredentialsTasksError::Authentication(ClientCredentialsError::Expired
                | ClientCredentialsError::Discovery(OAuthDiscoveryError::TimedOut))))) => {},
        (JournalCase::DeadlineIntent, ClientCredentialsTaskWatchDriveError::Watch(ClientCredentialsTaskWatchError::Task(
            ClientCredentialsTasksError::Authentication(ClientCredentialsError::Discovery(OAuthDiscoveryError::TimedOut))))) => {},
        (JournalCase::SnapshotLimit, ClientCredentialsTaskWatchDriveError::Watch(ClientCredentialsTaskWatchError::SnapshotLimit)) => {},
        (_, error) => panic!("unexpected machine journal failure for {case:?}: {error:?}"),
    }
}

async fn scenario(peer: &Peer, cx: &Cx, case: JournalCase) {
    let machine = client(peer, matches!(case, JournalCase::ExpireIntent));
    let owner = binding(&machine);
    let store = Store::new(&owner);
    let cancellation = McpRequestCancellation::new();
    let timeout = if matches!(case, JournalCase::DeadlineIntent) { Duration::from_secs(3) } else { Duration::from_secs(10) };
    let snapshots = if matches!(case, JournalCase::SnapshotLimit) { 1 } else { 16 };
    let watch = ClientCredentialsTaskWatchPolicy::new(timeout, snapshots, 32).unwrap();
    // Enable observation recovery even for failed saves/mutations. Its presence
    // must not turn persistence or mutation uncertainty into a retry loop.
    let policy = ClientCredentialsTaskWatchDrivePolicy::new(watch, 4, 8, 4096).unwrap()
        .with_recovery(ClientCredentialsTaskRecoveryPolicy::new(1, Duration::from_millis(20), Duration::from_millis(20)).unwrap()).unwrap();
    let ((mut stream, _), opened) = pair(Box::pin(peer.listen(json!(["one"]), false)),
        Box::pin(machine.watch_task_inputs_with_cancellation(cx, &cancellation,
            TaskId::parse("one").unwrap(), "journal".to_owned(), policy))).await;
    let mut driver = opened.unwrap().with_input_journal(store.journal(owner, case)).unwrap();
    let handle = driver.cancel_handle();
    forbid_renewal(&machine);
    drop(Box::pin(driver.drive(cx, no_resolver, no_observer)));
    assert_eq!(peer.seen.lock().unwrap().len(), 2);
    assert_eq!(store.counts(), (0, 0));
    assert_eq!(driver.update_state(), TaskInputUpdateState::NotAttempted);
    let resolutions = Cell::new(0);
    let observations = Cell::new(0);

    let server = async {
        get(peer, &store, 0, "input_required", None).await;
        if case.updates() != 0 {
            update(peer, &store, 1, "one", matches!(case, JournalCase::LostUpdate)).await;
            if case.completes() || case.pauses() {
                if matches!(case, JournalCase::Recovery) {
                    interrupted_get(peer, &store).await;
                    closed(&mut stream).await;
                    let (replacement, _) = peer.listen(json!(["one"]), false).await;
                    stream = replacement;
                }
                get(peer, &store, 2, "input_required", None).await;
                if case.completes() {
                    update(peer, &store, 3, "two", false).await;
                    get(peer, &store, 4, "cancelled", None).await;
                }
            }
        }
        if case.remote() { cancel(peer).await; }
        closed(&mut stream).await;
    };
    let application = async {
        let mut driving = Box::pin(driver.drive(cx, |pending| {
            let count = resolutions.get() + 1;
            resolutions.set(count);
            assert!(count <= 2, "acknowledged input cannot reach the resolver twice");
            let key = if count == 1 { "one" } else { "two" };
            assert_eq!(pending.len(), if count == 1 { 2 } else { 1 });
            assert!(pending.contains_key(key));
            if count == 2 { assert!(!pending.contains_key("one")); }
            let action = if count == 2 && case.pauses() { ManagedTaskInputAction::ReturnToCaller }
                else { ManagedTaskInputAction::Respond(answers(json!({key:{"roots":[]}}))) };
            std::future::ready(Ok(action))
        }, |_| { observations.set(observations.get() + 1); Ok(()) }));
        if let Some(generation) = case.gate() {
            poll_fn(|task| {
                assert!(driving.as_mut().poll(task).is_pending());
                if store.entered.is_cancel_requested() { Poll::Ready(()) }
                else { task.waker().wake_by_ref(); Poll::Pending }
            }).await;
            assert_eq!(store.counts(), (generation as usize, (generation - 1) as usize));
            assert_eq!(peer.updates.load(Ordering::SeqCst), (generation - 1) as usize);
            assert_eq!(peer.seen.lock().unwrap().len(), if generation == 1 { 4 } else { 6 });
            peer.quiet();
            match case {
                JournalCase::GateIntent | JournalCase::GateAck => store.release.cancel(),
                JournalCase::LocalIntent => cancellation.cancel(),
                JournalCase::RevokeIntent => machine.client.inner.state.try_lock_owned().unwrap().current.as_ref().unwrap().bearer.revoke(),
                _ => {},
            }
        }
        if case.abandon() {
            drop(driving);
        } else {
            let result = if case.remote() {
                let (result, cancelled) = pair(driving, Box::pin(handle.request_cancel(cx))).await;
                cancelled.unwrap();
                result
            } else { driving.await };
            if case.completes() {
                assert!(matches!(result, Ok(ManagedTaskRunOutcome::Terminal(task)) if matches!(*task, Task::Cancelled(_))));
            } else if case.pauses() {
                assert!(matches!(result, Ok(ManagedTaskRunOutcome::InputRequired(_))));
            } else { require_failure(case, result); }
        }
        let wire_acks = if matches!(case, JournalCase::LostUpdate) { 0 } else { case.updates() };
        let wire_state = if matches!(case, JournalCase::LostUpdate) { TaskInputUpdateState::Unconfirmed }
            else if wire_acks != 0 { TaskInputUpdateState::Acknowledged } else { TaskInputUpdateState::NotAttempted };
        assert_eq!(driver.update_state(), wire_state);
        assert_eq!(driver.acknowledged_updates(), wire_acks);
        let last = if case.updates() == 0 { None }
            else { Some(RequestId::String(if matches!(case, JournalCase::Recovery) { "journal:13" }
                else if case.completes() { "journal:9" } else { "journal:5" }.to_owned())) };
        assert_eq!(driver.last_update_request_id(), last.as_ref());
        assert_eq!(driver.reconnection_attempts(), usize::from(matches!(case, JournalCase::Recovery)));
        assert_eq!(resolutions.get(), if case.completes() || case.pauses() { 2 } else { 1 });
        assert_eq!(observations.get(), if case.completes() { 3 } else if case.pauses() { 2 } else { 1 });
        assert_eq!(store.counts(), (case.saves(), case.generation() as usize));
        assert_eq!(store.dropped.load(Ordering::SeqCst), case.saves(), "owned persistence futures must be released");
        store.require_generation(case.generation());
        let journal = driver.input_journal().unwrap();
        assert_eq!(journal.pending_change().map(|change| change.proposed().generation()), case.pending_generation());
        if case.pending_generation().is_some() {
            assert!(matches!(journal.record(), Err(TaskInputJournalError::ReconciliationRequired)));
        } else { assert_eq!(journal.record().unwrap(), &store.record()); }
        assert_eq!(handle.state(), if case.remote() { TaskCancellationState::Acknowledged } else { TaskCancellationState::Ready });
        driver.close();
        assert_eq!(driver.update_state(), wire_state);
        assert_eq!(driver.acknowledged_updates(), wire_acks);
        assert_eq!(driver.last_update_request_id(), last.as_ref());
        assert!(driver.drive(cx, no_resolver, no_observer).await.is_err());
        assert!(matches!(handle.request_cancel(cx).await,
            Err(ClientCredentialsTaskCancellationError::Closed | ClientCredentialsTaskCancellationError::AlreadyAttempted)));
        assert!(!machine.client.inner.closed.is_cancel_requested());
    };
    Box::pin(pair(server, application)).await;
    let journal = driver.into_input_journal().unwrap();
    assert_eq!(journal.pending_change().map(|change| change.proposed().generation()), case.pending_generation());
    drop(journal);
    let mut expected: BTreeSet<_> = (0..case.numeric_requests()).map(|n| format!("journal:{n}")).collect();
    if case.remote() {
        expected.insert("journal:cancel:discovery".to_owned());
        expected.insert("journal:cancel:operation".to_owned());
    }
    assert_eq!(*peer.seen.lock().unwrap(), expected);
    assert_eq!(peer.updates.load(Ordering::SeqCst), case.updates());
    assert_eq!(cancellation.is_cancel_requested(), matches!(case, JournalCase::LocalIntent));
    peer.quiet();
    if case.restarts() {
        restart(peer, cx, &store, case).await;
        expected.extend((0..if case.restart_completes() { 8 } else { 4 }).map(|n| format!("journal-next:{n}")));
        assert_eq!(*peer.seen.lock().unwrap(), expected);
        assert_eq!(peer.updates.load(Ordering::SeqCst), case.updates() + usize::from(case.restart_completes()));
        peer.quiet();
    }
}

async fn restart(peer: &Peer, cx: &Cx, store: &Store, case: JournalCase) {
    // Fresh machine owner and serialized journal, not the first driver's input
    // ledger or volatile wire receipt. Authentication remains host-selected.
    let machine = client(peer, false);
    let generation = case.generation();
    let before = store.record().encode().unwrap();
    let old_counts = store.counts();
    let maximum_updates = if matches!(case, JournalCase::Limit) { 1 } else { 4 };
    let policy = ClientCredentialsTaskWatchDrivePolicy::new(
        ClientCredentialsTaskWatchPolicy::new(Duration::from_secs(10), 8, 16).unwrap(), maximum_updates, 8, 4096).unwrap();
    let ((mut stream, _), opened) = pair(Box::pin(peer.listen(json!(["one"]), false)),
        Box::pin(machine.watch_task_inputs(cx, TaskId::parse("one").unwrap(), "journal-next".to_owned(), policy))).await;
    let mut driver = opened.unwrap().with_input_journal(store.journal(binding(&machine), JournalCase::Order)).unwrap();
    assert_eq!(driver.update_state(), store.record().update_state());
    assert_eq!(driver.acknowledged_updates(), store.record().acknowledged_updates());
    forbid_renewal(&machine);
    let resolutions = Cell::new(0);
    let observations = Cell::new(0);
    let server = async {
        get(peer, store, generation, "input_required", Some(case)).await;
        if case.restart_completes() {
            update(peer, store, 3, "two", false).await;
            get(peer, store, 4, "cancelled", None).await;
        }
        closed(&mut stream).await;
    };
    let application = async {
        let result = Box::pin(driver.drive(cx, |pending| {
            assert!(case.restart_completes(), "uncertain or invalid restart cannot resolve input");
            resolutions.set(resolutions.get() + 1);
            assert_eq!(pending.keys().map(String::as_str).collect::<Vec<_>>(), ["two"]);
            std::future::ready(Ok(ManagedTaskInputAction::Respond(answers(json!({"two":{"roots":[]}})))))
        }, |_| { observations.set(observations.get() + 1); Ok(()) })).await;
        if case.restart_completes() {
            assert!(matches!(result, Ok(ManagedTaskRunOutcome::Terminal(task)) if matches!(*task, Task::Cancelled(_))));
            assert_eq!(driver.acknowledged_updates(), 2);
            assert_eq!(driver.update_state(), TaskInputUpdateState::Acknowledged);
            assert_eq!(driver.last_update_request_id(), Some(&RequestId::String("journal-next:5".to_owned())));
            assert_eq!(store.counts(), (old_counts.0 + 2, old_counts.1 + 2));
            store.require_generation(4);
        } else {
            let error = result.err().expect("restart must withhold invalid or uncertain input");
            match (case, error) {
                (JournalCase::LostIntentReceipt | JournalCase::FailAck | JournalCase::LostUpdate,
                    ClientCredentialsTaskWatchDriveError::Journal(TaskInputJournalError::ReconciliationRequired)) => {},
                (JournalCase::ChangedAnswered | JournalCase::ChangedUnanswered,
                    ClientCredentialsTaskWatchDriveError::Input(ClientCredentialsTaskWaitError::InputKeyReused)) => {},
                (JournalCase::ChangedTask, ClientCredentialsTaskWatchDriveError::Journal(TaskInputJournalError::TaskChanged)) => {},
                (JournalCase::Limit, ClientCredentialsTaskWatchDriveError::Input(ClientCredentialsTaskWaitError::UpdateLimit)) => {},
                (_, error) => panic!("unexpected restart failure for {case:?}: {error:?}"),
            }
            assert_eq!(store.record().encode().unwrap(), before);
            assert_eq!(store.counts(), old_counts);
        }
        assert_eq!(resolutions.get(), usize::from(case.restart_completes()));
        assert_eq!(observations.get(), if case.restart_completes() { 2 }
            else if matches!(case, JournalCase::ChangedTask) { 0 } else { 1 });
        assert_eq!(driver.input_journal().unwrap().record().unwrap(), &store.record());
        assert!(driver.input_journal().unwrap().pending_change().is_none());
        assert_eq!(driver.reconnection_attempts(), 0);
        driver.close();
        assert!(driver.drive(cx, no_resolver, no_observer).await.is_err());
        assert!(!machine.client.inner.closed.is_cancel_requested());
    };
    Box::pin(pair(server, application)).await;
}

fn run_journal(case: JournalCase) {
    runtime().block_on(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000),
            Box::pin(scenario(&peer, &cx, case))).await.expect("journaled machine Task case exceeded its bound");
    });
}

#[test]
fn tls_journal_orders_intent_update_ack_and_reconciliation() { isolated_journal("tls_journal_orders_intent_update_ack_and_reconciliation", JournalCase::Order); }
#[test]
fn tls_journal_waits_for_intent_before_sending_update() { isolated_journal("tls_journal_waits_for_intent_before_sending_update", JournalCase::GateIntent); }
#[test]
fn tls_journal_waits_for_ack_save_before_reconciliation() { isolated_journal("tls_journal_waits_for_ack_save_before_reconciliation", JournalCase::GateAck); }
#[test]
fn tls_journal_failed_intent_cannot_send_or_recover() { isolated_journal("tls_journal_failed_intent_cannot_send_or_recover", JournalCase::FailIntent); }
#[test]
fn tls_journal_wrong_intent_receipt_cannot_authorize_update() { isolated_journal("tls_journal_wrong_intent_receipt_cannot_authorize_update", JournalCase::WrongIntent); }
#[test]
fn tls_journal_lost_intent_receipt_blocks_restart_mutation() { isolated_journal("tls_journal_lost_intent_receipt_blocks_restart_mutation", JournalCase::LostIntentReceipt); }
#[test]
fn tls_journal_failed_ack_save_retains_wire_receipt_and_blocks_restart() { isolated_journal("tls_journal_failed_ack_save_retains_wire_receipt_and_blocks_restart", JournalCase::FailAck); }
#[test]
fn tls_journal_lost_ack_save_reply_reopens_actual_committed_receipt() { isolated_journal("tls_journal_lost_ack_save_reply_reopens_actual_committed_receipt", JournalCase::LostAckReceipt); }
#[test]
fn tls_journal_lost_update_reply_is_not_replayed_after_restart() { isolated_journal("tls_journal_lost_update_reply_is_not_replayed_after_restart", JournalCase::LostUpdate); }
#[test]
fn tls_journal_restart_answers_only_remaining_keys() { isolated_journal("tls_journal_restart_answers_only_remaining_keys", JournalCase::Resume); }
#[test]
fn tls_journal_restart_rejects_changed_answered_descriptor() { isolated_journal("tls_journal_restart_rejects_changed_answered_descriptor", JournalCase::ChangedAnswered); }
#[test]
fn tls_journal_restart_rejects_changed_unanswered_descriptor() { isolated_journal("tls_journal_restart_rejects_changed_unanswered_descriptor", JournalCase::ChangedUnanswered); }
#[test]
fn tls_journal_restart_rejects_changed_task_before_observer() { isolated_journal("tls_journal_restart_rejects_changed_task_before_observer", JournalCase::ChangedTask); }
#[test]
fn tls_journal_restart_preserves_lifetime_update_limit() { isolated_journal("tls_journal_restart_preserves_lifetime_update_limit", JournalCase::Limit); }
#[test]
fn tls_journal_local_cancel_stops_pending_save_without_remote_update() { isolated_journal("tls_journal_local_cancel_stops_pending_save_without_remote_update", JournalCase::LocalIntent); }
#[test]
fn tls_journal_abandoned_intent_save_stays_quarantined() { isolated_journal("tls_journal_abandoned_intent_save_stays_quarantined", JournalCase::DropIntent); }
#[test]
fn tls_journal_remote_cancel_interrupts_pending_intent_save() { isolated_journal("tls_journal_remote_cancel_interrupts_pending_intent_save", JournalCase::RemoteIntent); }
#[test]
fn tls_journal_revocation_during_save_never_renews_authority() { isolated_journal("tls_journal_revocation_during_save_never_renews_authority", JournalCase::RevokeIntent); }
#[test]
fn tls_journal_token_expiry_bounds_pending_save() { isolated_journal("tls_journal_token_expiry_bounds_pending_save", JournalCase::ExpireIntent); }
#[test]
fn tls_journal_original_deadline_bounds_pending_save() { isolated_journal("tls_journal_original_deadline_bounds_pending_save", JournalCase::DeadlineIntent); }
#[test]
fn tls_journal_remote_cancel_during_ack_save_retains_wire_receipt() { isolated_journal("tls_journal_remote_cancel_during_ack_save_retains_wire_receipt", JournalCase::RemoteAck); }
#[test]
fn tls_journal_abandoned_ack_save_retains_wire_receipt() { isolated_journal("tls_journal_abandoned_ack_save_retains_wire_receipt", JournalCase::DropAck); }
#[test]
fn tls_journal_recovery_preserves_saved_partial_answers() { isolated_journal("tls_journal_recovery_preserves_saved_partial_answers", JournalCase::Recovery); }
#[test]
fn tls_journal_reserves_reconciliation_before_persistence() { isolated_journal("tls_journal_reserves_reconciliation_before_persistence", JournalCase::SnapshotLimit); }
