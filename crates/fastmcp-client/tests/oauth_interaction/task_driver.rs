//! Public Task-driver composition with the existing real OAuth/MCP TLS peer.
//! Runs only under tasks,native-tls-roots; zero-test feature-off output is not proof.
use super::*;
use fastmcp_client::http_auth::managed::OAuthSessionError;
use fastmcp_client::http_auth::managed::tasks::{ManagedTasksClient, ManagedTasksError, ManagedTasksLimits, ManagedTaskRequestIds};
use fastmcp_client::http_auth::managed::tasks::driver::{ManagedTaskDriverPolicy, ManagedTaskDriverError, ManagedTaskInputAction, ManagedTaskRunOutcome};
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
use fastmcp_protocol::tasks_extension::{Task, TaskId, TaskInputResponses};

const RUN_CHILD: &str = "FASTMCP_TEST_TASK_DRIVER_CASE";
const DISCOVER: &str = r#"{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{},"extensions":{"io.modelcontextprotocol/tasks":{}}},"ttlMs":0,"cacheScope":"private"}"#;
const DONE: &str = r#"{"resultType":"complete","taskId":"task-one","status":"completed","createdAt":"2026-09-17T00:00:00Z","lastUpdatedAt":"2026-09-17T00:00:01Z","ttlMs":null,"result":{"content":[],"x-exact":{"z":900719925474099312345,"a":1.20e+4}}}"#;
const UPDATED: &str = r#"{"resultType":"complete"}"#;

#[derive(Clone, Copy)]
enum RunCase {
    Complete, ObserveOnly, Pause, InvalidReply, Capability, LostUpdate,
    CancelResolver, CloseResolver, TimeoutResolver, DropResolver, CancelSleep,
    LargeHint, RepeatId, PollLimit, UpdateLimit, InputReuse, ObserverRefusal,
    Failed, Cancelled, PreCancelled,
}

fn isolated_run(name: &str, case: RunCase) {
    if let Ok(selected) = std::env::var(RUN_CHILD) {
        assert_eq!(selected, name);
        run_task_driver(case);
        return;
    }
    let roots = RootFile::create();
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
    }
    let exact = format!("driver::task_driver::{name}");
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &exact, "--nocapture", "--test-threads=1"])
        .env(RUN_CHILD, name).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "Task driver HTTPS case failed");
            return;
        }
        assert!(Instant::now() < deadline, "Task driver child exceeded its bound");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn snapshot(status: &str, hint: u64, keys: &[&str]) -> String {
    let mut value = json!({"resultType":"complete","taskId":"task-one","status":status,
        "createdAt":"2026-09-17T00:00:00Z","lastUpdatedAt":"2026-09-17T00:00:00Z",
        "ttlMs":null,"pollIntervalMs":hint});
    if status == "input_required" {
        value["inputRequests"] = Value::Object(keys.iter().map(|key| ((*key).to_owned(), json!({"method":"roots/list"}))).collect());
    }
    if status == "failed" { value["error"] = json!({"code":-32603,"message":"task failed"}); }
    value.to_string()
}

async fn serve(peer: &Peer, number: i64, method: &str, result: Option<&str>) -> Value {
    let discovery = peer.response(number, DISCOVER).await;
    assert_eq!(discovery["method"], "server/discover");
    assert_eq!(discovery["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"], json!({"io.modelcontextprotocol/tasks":{}}));
    let (mut tls, body) = peer.request(false).await;
    let request: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(request["id"], number + 1);
    assert_eq!(request["method"], method);
    assert_eq!(request["params"]["taskId"], "task-one");
    if let Some(result) = result { json_reply(&mut tls, &terminal(number + 1, result)).await; }
    // A None response models an update accepted by the peer whose reply is lost.
    request
}

struct Resolution<'a> {
    action: Option<Result<ManagedTaskInputAction, ManagedTaskDriverError>>,
    entered: &'a Cell<bool>,
    dropped: &'a Cell<bool>,
}
impl Future for Resolution<'_> {
    type Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>;
    fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.entered.set(true);
        match this.action.take() { Some(action) => Poll::Ready(action), None => Poll::Pending }
    }
}
impl Drop for Resolution<'_> {
    fn drop(&mut self) { self.dropped.set(true); }
}

fn run_task_driver(case: RunCase) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap().block_on(Box::pin(async {
        let cx = Cx::current().unwrap();
        let scenario = Box::pin(async {
            let peer = Peer::new().await;
            let ((), login) = pair(Box::pin(peer.login()), Box::pin(ManagedOAuthSession::authorize(
                &cx, peer.client(), OAuthSessionPolicy::default(), browser,
            ))).await;
            let session = login.unwrap();
            let capabilities: ClientCapabilities = serde_json::from_value(if matches!(case, RunCase::Capability | RunCase::ObserveOnly) {
                json!({})
            } else { json!({"roots":{},"sampling":{}}) }).unwrap();
            let client = ManagedTasksClient::new(session.clone(), FinalRequestMeta::new(capabilities), ManagedTasksLimits::default()).unwrap();
            let policy = ManagedTaskDriverPolicy::new(
                Duration::from_millis(10),
                if matches!(case, RunCase::LargeHint | RunCase::TimeoutResolver) { Duration::from_secs(1) } else { Duration::from_secs(15) },
                if matches!(case, RunCase::PollLimit) { 1 } else { 20 },
                if matches!(case, RunCase::ObserveOnly) { 0 } else if matches!(case, RunCase::UpdateLimit) { 1 } else { 8 },
                if matches!(case, RunCase::ObserveOnly) { 0 } else { 16 },
                65536,
            ).unwrap();
            let cancellation = McpRequestCancellation::new();
            if matches!(case, RunCase::PreCancelled) { cancellation.cancel(); }
            let input = snapshot("input_required", 10, &["one"]);
            let server = Box::pin(async {
                match case {
                    RunCase::Complete => {
                        serve(&peer, 1, "tasks/get", Some(&snapshot("working", 100, &[]))).await;
                        let sent = Instant::now();
                        let ab = snapshot("input_required", 10, &["one", "two"]);
                        serve(&peer, 3, "tasks/get", Some(&ab)).await;
                        assert!(sent.elapsed() >= Duration::from_millis(100), "the peer polling hint is not shortened");
                        let one = serve(&peer, 5, "tasks/update", Some(UPDATED)).await;
                        assert_eq!(one["params"]["inputResponses"], json!({"one":{"roots":[]}}));
                        // A lagged snapshot still contains both keys. Only two
                        // is unresolved; the host must not be asked for one again.
                        serve(&peer, 7, "tasks/get", Some(&ab)).await;
                        let two = serve(&peer, 9, "tasks/update", Some(UPDATED)).await;
                        assert_eq!(two["params"]["inputResponses"], json!({"two":{"roots":[]}}));
                        // Both keys are now acknowledged. The stale snapshot
                        // causes another paced get, never another update.
                        serve(&peer, 11, "tasks/get", Some(&ab)).await;
                        serve(&peer, 13, "tasks/get", Some(DONE)).await;
                    }
                    RunCase::LostUpdate => {
                        serve(&peer, 1, "tasks/get", Some(&input)).await;
                        serve(&peer, 3, "tasks/update", None).await;
                    }
                    RunCase::UpdateLimit | RunCase::InputReuse => {
                        serve(&peer, 1, "tasks/get", Some(&input)).await;
                        serve(&peer, 3, "tasks/update", Some(UPDATED)).await;
                        let changed = if matches!(case, RunCase::UpdateLimit) {
                            snapshot("input_required", 10, &["two"])
                        } else {
                            let mut changed: Value = serde_json::from_str(&input).unwrap();
                            changed["inputRequests"]["one"] = json!({"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16}});
                            changed.to_string()
                        };
                        serve(&peer, 5, "tasks/get", Some(&changed)).await;
                    }
                    RunCase::CancelSleep | RunCase::LargeHint | RunCase::RepeatId | RunCase::PollLimit | RunCase::ObserverRefusal => {
                        let hint = if matches!(case, RunCase::LargeHint) { u64::MAX } else if matches!(case, RunCase::CancelSleep) { 60_000 } else { 10 };
                        serve(&peer, 1, "tasks/get", Some(&snapshot("working", hint, &[]))).await;
                    }
                    RunCase::Failed | RunCase::Cancelled => {
                        serve(&peer, 1, "tasks/get", Some(&snapshot(if matches!(case, RunCase::Failed) { "failed" } else { "cancelled" }, 10, &[]))).await;
                    }
                    RunCase::PreCancelled => {},
                    _ => { serve(&peer, 1, "tasks/get", Some(&input)).await; },
                }
            });
            let application = Box::pin(async {
                let id_calls = Cell::new(0_i64);
                let resolutions = Cell::new(0_usize);
                let observations = Cell::new(0_usize);
                let entered = Cell::new(false);
                let dropped = Cell::new(false);
                let entered_ref = &entered;
                let dropped_ref = &dropped;
                let mut run = Box::pin(client.drive_task_with_cancellation(
                    &cx, &cancellation, TaskId::parse("task-one").unwrap(), policy,
                    || {
                        let index = id_calls.get(); id_calls.set(index + 1);
                        let first = RequestId::Number(1 + index * 2);
                        let second = if matches!(case, RunCase::RepeatId) && index > 0 {
                            serde_json::from_str("2e0").unwrap()
                        } else { RequestId::Number(2 + index * 2) };
                        ManagedTaskRequestIds::new(first, second).map_err(ManagedTaskDriverError::from)
                    },
                    |pending| {
                        let index = resolutions.get(); resolutions.set(index + 1);
                        let action = if matches!(case, RunCase::CancelResolver | RunCase::CloseResolver | RunCase::TimeoutResolver | RunCase::DropResolver) {
                            None
                        } else if matches!(case, RunCase::Pause) {
                            Some(Ok(ManagedTaskInputAction::ReturnToCaller))
                        } else {
                            let key = if matches!(case, RunCase::InvalidReply) { "foreign" }
                                else if matches!(case, RunCase::Complete) && index == 1 { "two" } else { "one" };
                            if matches!(case, RunCase::Complete) {
                                assert_eq!(pending.keys().map(String::as_str).collect::<Vec<_>>(), if index == 0 { vec!["one", "two"] } else { vec!["two"] });
                            }
                            let responses: TaskInputResponses = serde_json::from_value(json!({key:{"roots":[]}})).unwrap();
                            Some(Ok(ManagedTaskInputAction::Respond(responses)))
                        };
                        Resolution { action, entered: entered_ref, dropped: dropped_ref }
                    },
                    |_| {
                        observations.set(observations.get() + 1);
                        if matches!(case, RunCase::ObserverRefusal) { Err(ManagedTaskDriverError::AbortedByHost) } else { Ok(()) }
                    },
                ));
                let interrupted = matches!(case, RunCase::CancelResolver | RunCase::CloseResolver | RunCase::TimeoutResolver | RunCase::DropResolver | RunCase::CancelSleep);
                if interrupted {
                    poll_fn(|task| {
                        assert!(run.as_mut().poll(task).is_pending());
                        if entered.get() || (matches!(case, RunCase::CancelSleep) && observations.get() > 0) { Poll::Ready(()) }
                        else { Poll::Pending }
                    }).await;
                    assert!(!dropped.get());
                    match case {
                        RunCase::CancelResolver | RunCase::CancelSleep => { cancellation.cancel(); },
                        RunCase::CloseResolver => session.close(),
                        _ => {},
                    }
                }
                if matches!(case, RunCase::DropResolver) {
                    drop(run);
                    assert!(dropped.get(), "abandoning the driver drops its live host future");
                    assert!(!cancellation.is_cancel_requested());
                    assert_eq!(resolutions.get(), 1);
                } else {
                    let result = run.await;
                    match case {
                        RunCase::Complete => {
                            let ManagedTaskRunOutcome::Terminal(task) = result.unwrap() else { panic!("terminal task expected") };
                            assert!(matches!(*task, Task::Completed { .. }));
                            let exact = serde_json::to_string(&task).unwrap();
                            assert!(exact.contains("900719925474099312345") && exact.contains("1.20e+4"));
                            assert_eq!(observations.get(), 5);
                            assert_eq!(resolutions.get(), 2);
                            assert_eq!(id_calls.get(), 7);
                        }
                        RunCase::ObserveOnly | RunCase::Pause => {
                            assert!(matches!(result.unwrap(), ManagedTaskRunOutcome::InputRequired(_)));
                            assert_eq!(resolutions.get(), usize::from(matches!(case, RunCase::Pause)));
                            assert_eq!(id_calls.get(), 1);
                        }
                        RunCase::Failed | RunCase::Cancelled => {
                            let ManagedTaskRunOutcome::Terminal(task) = result.unwrap() else { panic!("terminal task expected") };
                            assert!(matches!((case, *task), (RunCase::Failed, Task::Failed { .. }) | (RunCase::Cancelled, Task::Cancelled(_))));
                            assert_eq!(resolutions.get(), 0);
                        }
                        _ => {
                            let error = result.err().expect("explicit driver failure expected");
                            assert!(!format!("{error:?} {error}").contains("interaction-access"));
                            match case {
                                RunCase::InvalidReply => assert!(matches!(error, ManagedTaskDriverError::InvalidInputResponse)),
                                RunCase::Capability => { assert!(matches!(error, ManagedTaskDriverError::CapabilityNotAdvertised)); assert_eq!(resolutions.get(), 0); },
                                RunCase::LostUpdate => { assert!(matches!(error, ManagedTaskDriverError::Task(_))); assert_eq!(id_calls.get(), 2); },
                                RunCase::CancelResolver | RunCase::CancelSleep | RunCase::PreCancelled => assert!(matches!(error, ManagedTaskDriverError::Task(ManagedTasksError::Session(OAuthSessionError::Cancelled)))),
                                RunCase::CloseResolver => assert!(matches!(error, ManagedTaskDriverError::Task(ManagedTasksError::Session(OAuthSessionError::Closed)))),
                                RunCase::TimeoutResolver | RunCase::LargeHint => assert!(matches!(error, ManagedTaskDriverError::Task(ManagedTasksError::Session(OAuthSessionError::TimedOut)))),
                                RunCase::RepeatId => assert!(matches!(error, ManagedTaskDriverError::RepeatedRequestId)),
                                RunCase::PollLimit => assert!(matches!(error, ManagedTaskDriverError::PollLimit)),
                                RunCase::UpdateLimit => { assert!(matches!(error, ManagedTaskDriverError::UpdateLimit)); assert_eq!(resolutions.get(), 1); },
                                RunCase::InputReuse => { assert!(matches!(error, ManagedTaskDriverError::InputKeyReused)); assert_eq!(resolutions.get(), 1); },
                                RunCase::ObserverRefusal => assert!(matches!(error, ManagedTaskDriverError::AbortedByHost)),
                                _ => unreachable!(),
                            }
                        }
                    }
                    if matches!(case, RunCase::CancelResolver | RunCase::CloseResolver | RunCase::TimeoutResolver) { assert!(dropped.get()); }
                }
                assert!(cx.checkpoint().is_ok(), "driver cancellation must not cancel the host context");
            });
            pair(server, application).await;
            let expected = match case { RunCase::Complete => 14, RunCase::LostUpdate => 4, RunCase::UpdateLimit | RunCase::InputReuse => 6, RunCase::PreCancelled => 0, _ => 2 };
            assert_eq!(peer.posts.load(Ordering::SeqCst), expected);
            assert_eq!(peer.tokens.load(Ordering::SeqCst), 1);
            peer.quiet();
            session.close();
        });
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario).await.expect("Task driver TLS scenario must settle");
    }));
}

#[test]
fn polls_partial_inputs_and_stale_snapshots_to_exact_completion() { isolated_run("polls_partial_inputs_and_stale_snapshots_to_exact_completion", RunCase::Complete); }
#[test]
fn observation_only_never_invokes_input_handlers() { isolated_run("observation_only_never_invokes_input_handlers", RunCase::ObserveOnly); }
#[test]
fn host_can_return_input_without_submitting_an_update() { isolated_run("host_can_return_input_without_submitting_an_update", RunCase::Pause); }
#[test]
fn invalid_answers_have_no_update_or_new_id_effect() { isolated_run("invalid_answers_have_no_update_or_new_id_effect", RunCase::InvalidReply); }
#[test]
fn unadvertised_input_never_reaches_the_resolver() { isolated_run("unadvertised_input_never_reaches_the_resolver", RunCase::Capability); }
#[test]
fn uncertain_update_is_not_replayed_or_followed_by_polling() { isolated_run("uncertain_update_is_not_replayed_or_followed_by_polling", RunCase::LostUpdate); }
#[test]
fn cancellation_interrupts_an_idle_input_resolver() { isolated_run("cancellation_interrupts_an_idle_input_resolver", RunCase::CancelResolver); }
#[test]
fn closing_the_session_interrupts_an_idle_input_resolver() { isolated_run("closing_the_session_interrupts_an_idle_input_resolver", RunCase::CloseResolver); }
#[test]
fn whole_run_deadline_interrupts_an_idle_input_resolver() { isolated_run("whole_run_deadline_interrupts_an_idle_input_resolver", RunCase::TimeoutResolver); }
#[test]
fn dropping_the_run_releases_its_host_resolver() { isolated_run("dropping_the_run_releases_its_host_resolver", RunCase::DropResolver); }
#[test]
fn cancelling_a_poll_delay_does_not_cancel_the_remote_task() { isolated_run("cancelling_a_poll_delay_does_not_cancel_the_remote_task", RunCase::CancelSleep); }
#[test]
fn huge_peer_poll_interval_expires_without_early_polling() { isolated_run("huge_peer_poll_interval_expires_without_early_polling", RunCase::LargeHint); }
#[test]
fn numeric_request_id_reuse_is_rejected_before_discovery() { isolated_run("numeric_request_id_reuse_is_rejected_before_discovery", RunCase::RepeatId); }
#[test]
fn poll_budget_prevents_an_extra_discovery_and_get() { isolated_run("poll_budget_prevents_an_extra_discovery_and_get", RunCase::PollLimit); }
#[test]
fn update_budget_prevents_an_extra_resolver_and_update() { isolated_run("update_budget_prevents_an_extra_resolver_and_update", RunCase::UpdateLimit); }
#[test]
fn changed_answered_input_key_never_runs_a_second_resolver() { isolated_run("changed_answered_input_key_never_runs_a_second_resolver", RunCase::InputReuse); }
#[test]
fn observer_refusal_stops_the_run_without_more_peer_effects() { isolated_run("observer_refusal_stops_the_run_without_more_peer_effects", RunCase::ObserverRefusal); }
#[test]
fn failed_task_is_a_typed_terminal_not_a_success_projection() { isolated_run("failed_task_is_a_typed_terminal_not_a_success_projection", RunCase::Failed); }
#[test]
fn remotely_cancelled_task_is_a_typed_terminal() { isolated_run("remotely_cancelled_task_is_a_typed_terminal", RunCase::Cancelled); }
#[test]
fn precancelled_driver_has_no_new_peer_effects() { isolated_run("precancelled_driver_has_no_new_peer_effects", RunCase::PreCancelled); }
