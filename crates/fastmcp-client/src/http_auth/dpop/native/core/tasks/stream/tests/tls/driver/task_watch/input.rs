//! Subscription input driving through the existing authenticated loopback TLS peer.

use super::*;
use std::future::Future;
use crate::http_auth::dpop::native::core::stream::task_subscription::watch::input::{
    DpopTaskWatchDriverPolicy, ManagedTaskDriverError, ManagedTaskInputAction,
};
use fastmcp_protocol::tasks_extension::TaskInputResponses;

fn policy(gets: usize, updates: usize) -> DpopTaskWatchDriverPolicy {
    DpopTaskWatchDriverPolicy::new(gets, updates, 4, 8192, Duration::from_secs(10)).unwrap()
}

fn answer(key: &str) -> TaskInputResponses {
    serde_json::from_value(json!({key:{"roots":[]}})).unwrap()
}

fn input_task(keys: &[&str]) -> Value {
    let mut task = task_result("input_required");
    task["inputRequests"] = Value::Object(keys.iter()
        .map(|key| ((*key).to_owned(), json!({"method":"roots/list"}))).collect());
    task
}

fn update_response(prefix: &str, index: usize, discover: bool, result: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0",
        "id":format!("{prefix}.input.{index}.{}", if discover { "discover" } else { "update" }),
        "result":result})).unwrap()
}

async fn get_reply(peer: &mut Peer, prefix: &str, index: usize, result: &Value, json: bool) {
    let mut socket = peer.wait_round(prefix, index).await;
    let bytes = wait_response(prefix, index, false, result);
    if json { json_reply(&mut socket, &bytes).await; }
    else { streamed_reply(&mut socket, &bytes, None, false).await; }
}

async fn update(peer: &mut Peer, prefix: &str, index: usize, key: &str) -> TlsStream<TcpStream> {
    let (mut discover, _) = peer.receive_named(
        &format!("{prefix}.input.{index}.discover"), "server/discover",
    ).await;
    json_reply(&mut discover, &update_response(prefix, index, true, &discovery_result())).await;
    let (socket, request) = peer.receive_named(
        &format!("{prefix}.input.{index}.update"), "tasks/update",
    ).await;
    assert_eq!(request["params"]["inputResponses"], json!({key:{"roots":[]}}));
    socket
}

async fn acknowledge(peer: &mut Peer, prefix: &str, index: usize, key: &str, json: bool) {
    let mut socket = update(peer, prefix, index, key).await;
    let bytes = update_response(prefix, index, false, &json!({"resultType":"complete"}));
    if json { json_reply(&mut socket, &bytes).await; }
    else { streamed_reply(&mut socket, &bytes, None, false).await; }
}

#[test]
fn subscription_inputs_reconcile_partial_updates_without_waiting_for_events_or_replaying_stale_keys() {
    for json_get in [false, true] {
        for json_update in [false, true] {
            run(async {
                let cx = Cx::current().unwrap();
                let (mut peer, mut client, credential) = Peer::new().await;
                let cancellation = McpRequestCancellation::new();
                let (mut resolutions, mut snapshots) = (0, 0);
                let application = client.drive_task_with_subscription(
                    &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
                    "partial", policy(5, 2), watch_limits(16),
                    |pending| {
                        let expected = if resolutions == 0 { vec!["one", "two"] } else { vec!["two"] };
                        assert_eq!(pending.keys().map(String::as_str).collect::<Vec<_>>(), expected);
                        let key = if resolutions == 0 { "one" } else { "two" };
                        resolutions += 1;
                        std::future::ready(Ok(ManagedTaskInputAction::Respond(answer(key))))
                    },
                    |_| { snapshots += 1; Ok(()) },
                );
                let server = async {
                    get_reply(&mut peer, "partial", 0, &task_result("working"), json_get).await;
                    let mut listen = peer.watch_listen("partial").await;
                    listen.write_all(HEAD).await.unwrap();
                    event(&mut listen, &watch_ack("partial", true)).await;
                    get_reply(&mut peer, "partial", 1, &input_task(&["one", "two"]), json_get).await;
                    acknowledge(&mut peer, "partial", 0, "one", json_update).await;
                    // No status event accompanies either update. Each immediate
                    // authoritative get must run while the same listen is open.
                    get_reply(&mut peer, "partial", 2, &input_task(&["one", "two"]), json_get).await;
                    acknowledge(&mut peer, "partial", 1, "two", json_update).await;
                    get_reply(&mut peer, "partial", 3, &input_task(&["one", "two"]), json_get).await;
                    asupersync::time::Sleep::new(cx.now().saturating_add_nanos(10_000_000)).await;
                    peer.no_extra(7);
                    event(&mut listen, &watch_status("partial", "cancelled")).await;
                    let mut terminal = task_result("cancelled");
                    terminal["_meta"] = json!({"example.com/result-marker":"kept"});
                    get_reply(&mut peer, "partial", 4, &terminal, json_get).await;
                    assert_watch_closed(&mut listen).await;
                };
                let (result, ()) = pair(application, server).await;
                let DpopTaskWaitOutcome::Terminal(snapshot) = result.unwrap() else { panic!("terminal snapshot required") };
                assert!(matches!(&snapshot.task, Task::Cancelled(_)));
                assert_eq!(serde_json::to_value(&*snapshot).unwrap()["_meta"]["example.com/result-marker"], "kept");
                assert_eq!((resolutions, snapshots), (2, 5));
                peer.no_extra(8);
                followup(&mut peer, &mut client, &credential).await;
                peer.no_extra(9);
            });
        }
    }
}

#[derive(Clone, Copy)]
enum Refusal { NoCapability, NoSnapshots, NoUpdates, Return, Empty, Foreign, WrongKind, HostError }

#[test]
fn input_refusals_and_handoffs_do_not_dispatch_updates_or_revoke_the_login() {
    for refusal in [Refusal::NoCapability, Refusal::NoSnapshots, Refusal::NoUpdates,
        Refusal::Return, Refusal::Empty, Refusal::Foreign, Refusal::WrongKind, Refusal::HostError]
    {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let mut metadata = driver_metadata();
            if matches!(refusal, Refusal::NoCapability) { metadata.client_capabilities = Default::default(); }
            let selected = policy(if matches!(refusal, Refusal::NoSnapshots) { 2 } else { 4 },
                if matches!(refusal, Refusal::NoUpdates) { 0 } else { 1 });
            let mut resolutions = 0;
            let application = client.drive_task_with_subscription(
                &cx, &cancellation, &credential, metadata, TaskId::parse("task-one").unwrap(),
                "refuse", selected, watch_limits(8),
                |_| {
                    resolutions += 1;
                    std::future::ready(match refusal {
                        Refusal::Return => Ok(ManagedTaskInputAction::ReturnToCaller),
                        Refusal::Empty => Ok(ManagedTaskInputAction::Respond(TaskInputResponses::new())),
                        Refusal::Foreign => Ok(ManagedTaskInputAction::Respond(answer("foreign"))),
                        Refusal::WrongKind => Ok(ManagedTaskInputAction::Respond(
                            serde_json::from_value(json!({"one":{"action":"decline"}})).unwrap())),
                        Refusal::HostError => Err(ManagedTaskDriverError::AbortedByHost),
                        _ => panic!("refusal must precede host work"),
                    })
                }, |_| Ok(()),
            );
            let server = async {
                peer.watch_snapshot_reply("refuse", 0, "working").await;
                let mut listen = peer.watch_listen("refuse").await;
                listen.write_all(HEAD).await.unwrap();
                event(&mut listen, &watch_ack("refuse", true)).await;
                get_reply(&mut peer, "refuse", 1, &input_task(&["one"]), true).await;
                assert_watch_closed(&mut listen).await;
            };
            let (result, ()) = pair(application, server).await;
            match refusal {
                Refusal::Return | Refusal::NoUpdates => assert!(matches!(result.unwrap(), DpopTaskWaitOutcome::InputRequired(_))),
                Refusal::NoCapability => assert!(matches!(result, Err(DpopTaskWatchError::Driver(ManagedTaskDriverError::CapabilityNotAdvertised)))),
                Refusal::NoSnapshots => assert!(matches!(result, Err(DpopTaskWatchError::SnapshotLimit))),
                Refusal::HostError => assert!(matches!(result, Err(DpopTaskWatchError::Driver(ManagedTaskDriverError::AbortedByHost)))),
                _ => assert!(matches!(result, Err(DpopTaskWatchError::Driver(ManagedTaskDriverError::InvalidInputResponse)))),
            }
            assert_eq!(resolutions, usize::from(!matches!(refusal,
                Refusal::NoCapability | Refusal::NoSnapshots | Refusal::NoUpdates)));
            peer.no_extra(3);
            assert!(!client.revocation_handle().is_revoked());
            followup(&mut peer, &mut client, &credential).await;
        });
    }
}

#[test]
fn uncertain_streamed_update_releases_the_listen_without_a_get_or_replay() {
    for duplicate in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let mut resolutions = 0;
            let application = client.drive_task_with_subscription(
                &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
                "uncertain", policy(4, 2), watch_limits(8),
                |_| { resolutions += 1; std::future::ready(Ok(ManagedTaskInputAction::Respond(answer("one")))) },
                |_| Ok(()),
            );
            let server = async {
                peer.watch_snapshot_reply("uncertain", 0, "working").await;
                let mut listen = peer.watch_listen("uncertain").await;
                listen.write_all(HEAD).await.unwrap();
                event(&mut listen, &watch_ack("uncertain", true)).await;
                get_reply(&mut peer, "uncertain", 1, &input_task(&["one"]), true).await;
                let mut socket = update(&mut peer, "uncertain", 0, "one").await;
                let ack = update_response("uncertain", 0, false, &json!({"resultType":"complete"}));
                let mut wire = HEAD.to_vec();
                wire.extend_from_slice(&event_chunk(&ack));
                if duplicate { wire.extend_from_slice(&event_chunk(&ack)); }
                else { wire.extend_from_slice(&chunk(b"data: unfinished")); }
                wire.extend_from_slice(b"0\r\n\r\n");
                socket.write_all(&wire).await.unwrap();
                let _ = socket.shutdown().await;
                assert_watch_closed(&mut listen).await;
            };
            let (result, ()) = pair(application, server).await;
            assert!(result.is_err(), "a provisional ACK cannot advance the lifecycle");
            assert_eq!(resolutions, 1);
            peer.no_extra(4);
            followup(&mut peer, &mut client, &credential).await;
        });
    }
}

#[test]
fn initial_input_can_finish_without_a_subscription_but_final_reconciliation_cannot_mutate() {
    for initial_input in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let mut resolutions = 0;
            let application = client.drive_task_with_subscription(
                &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
                "boundary", policy(3, 1), watch_limits(4),
                |_| { resolutions += 1; std::future::ready(Ok(ManagedTaskInputAction::Respond(answer("one")))) },
                |_| Ok(()),
            );
            let server = async {
                if initial_input {
                    get_reply(&mut peer, "boundary", 0, &input_task(&["one"]), true).await;
                    acknowledge(&mut peer, "boundary", 0, "one", true).await;
                    peer.watch_snapshot_reply("boundary", 1, "cancelled").await;
                } else {
                    peer.watch_snapshot_reply("boundary", 0, "working").await;
                    let mut listen = peer.watch_listen("boundary").await;
                    listen.write_all(HEAD).await.unwrap();
                    event(&mut listen, &watch_ack("boundary", true)).await;
                    peer.watch_snapshot_reply("boundary", 1, "working").await;
                    let mut end = event_chunk(&watch_terminal("boundary"));
                    end.extend_from_slice(b"0\r\n\r\n");
                    listen.write_all(&end).await.unwrap();
                    let _ = listen.shutdown().await;
                    get_reply(&mut peer, "boundary", 2, &input_task(&["one"]), true).await;
                }
            };
            let (result, ()) = pair(application, server).await;
            if initial_input { assert!(matches!(result.unwrap(), DpopTaskWaitOutcome::Terminal(_))); }
            else { assert!(matches!(result.unwrap(), DpopTaskWaitOutcome::InputRequired(_))); }
            assert_eq!(resolutions, usize::from(initial_input));
            peer.no_extra(if initial_input { 3 } else { 4 });
        });
    }
}

#[derive(Clone, Copy)]
enum Quota { Exact, ByteShort, NotificationShort }

#[test]
fn update_progress_and_all_discoveries_spend_the_same_watch_byte_and_notification_budget() {
    for quota in [Quota::Exact, Quota::ByteShort, Quota::NotificationShort] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let mut payloads = vec![watch_discovery("quota"), watch_ack("quota", true),
                update_response("quota", 0, true, &discovery_result()), progress(json!("work"), "1"),
                update_response("quota", 0, false, &json!({"resultType":"complete"}))];
            for (round, result) in [(0, task_result("working")), (1, input_task(&["one"])), (2, task_result("cancelled"))] {
                payloads.push(wait_response("quota", round, true, &discovery_result()));
                payloads.push(wait_response("quota", round, false, &result));
            }
            let maximum = payloads.iter().map(Vec::len).max().unwrap();
            let total: usize = payloads.iter().map(Vec::len).sum();
            let core = ManagedCoreLimits::new(8192, maximum,
                total - usize::from(matches!(quota, Quota::ByteShort)),
                if matches!(quota, Quota::NotificationShort) { 1 } else { 2 }, Duration::from_secs(10)).unwrap();
            let application = client.drive_task_with_subscription(
                &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
                "quota", policy(3, 1), DpopStreamLimits::new(core, Duration::from_secs(5)).unwrap(),
                |_| std::future::ready(Ok(ManagedTaskInputAction::Respond(answer("one")))), |_| Ok(()),
            );
            let server = async {
                peer.watch_snapshot_reply("quota", 0, "working").await;
                let mut listen = peer.watch_listen("quota").await;
                listen.write_all(HEAD).await.unwrap();
                event(&mut listen, &watch_ack("quota", true)).await;
                get_reply(&mut peer, "quota", 1, &input_task(&["one"]), true).await;
                acknowledge(&mut peer, "quota", 0, "one", false).await;
                if !matches!(quota, Quota::NotificationShort) { peer.watch_snapshot_reply("quota", 2, "cancelled").await; }
                assert_watch_closed(&mut listen).await;
            };
            let (result, ()) = pair(application, server).await;
            match quota {
                Quota::Exact => assert!(matches!(result.unwrap(), DpopTaskWaitOutcome::Terminal(_))),
                Quota::ByteShort => assert!(matches!(result, Err(DpopTaskWatchError::Stream(DpopStreamError::Core(
                    DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit)))))),
                Quota::NotificationShort => assert!(matches!(result, Err(DpopTaskWatchError::Stream(DpopStreamError::Core(
                    DpopCoreError::Protocol(ManagedCoreError::NotificationLimit)))))),
            }
            peer.no_extra(if matches!(quota, Quota::NotificationShort) { 4 } else { 5 });
        });
    }
}

#[derive(Clone, Copy)]
enum HostStop { Cancel, Credential, Session, Abandon, Idle }

#[test]
fn cancellation_revocation_drop_and_idle_retire_pending_host_work_and_unacknowledged_updates() {
    for update_stalled in [false, true] {
        for stop in [HostStop::Cancel, HostStop::Credential, HostStop::Session, HostStop::Abandon, HostStop::Idle] {
            run(async {
                let cx = Cx::current().unwrap();
                let (mut peer, mut client, credential) = Peer::new().await;
                let cancellation = McpRequestCancellation::new();
                let reached = McpRequestCancellation::new();
                let revocation = client.revocation_handle();
                let selected = DpopStreamLimits::new(watch_limits(8).core,
                    if matches!(stop, HostStop::Idle) { Duration::from_secs(1) } else { Duration::from_secs(5) }).unwrap();
                let application = async {
                    type Resolution = std::pin::Pin<Box<dyn Future<Output = Result<ManagedTaskInputAction, ManagedTaskDriverError>> + Send>>;
                    let mut drive = Box::pin(client.drive_task_with_subscription(
                        &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
                        "stop", policy(4, 1), selected,
                        |_| -> Resolution {
                            if update_stalled {
                                Box::pin(std::future::ready(Ok(ManagedTaskInputAction::Respond(answer("one")))))
                            } else {
                                reached.cancel();
                                Box::pin(std::future::pending())
                            }
                        }, |_| Ok(()),
                    ));
                    if matches!(stop, HostStop::Abandon) {
                        let mut ready = std::pin::pin!(reached.cancelled());
                        poll_fn(|context| {
                            assert!(drive.as_mut().poll(context).is_pending());
                            ready.as_mut().poll(context)
                        }).await;
                        drop(drive);
                    } else {
                        let result = if matches!(stop, HostStop::Idle) {
                            asupersync::time::timeout_at(cx.now().saturating_add_nanos(3_000_000_000), drive)
                                .await.expect("one-second listen idle must also bound host resolution and update")
                        } else { drive.await };
                        match stop {
                            HostStop::Cancel => assert!(matches!(result, Err(DpopTaskWatchError::Stream(DpopStreamError::Core(
                                DpopCoreError::Transport(DpopHttpError::Cancelled)))))),
                            HostStop::Credential | HostStop::Session => assert!(matches!(result, Err(DpopTaskWatchError::Stream(DpopStreamError::Core(
                                DpopCoreError::Transport(DpopHttpError::Authorization(_))))))),
                            HostStop::Idle => assert!(matches!(result, Err(DpopTaskWatchError::Stream(DpopStreamError::Core(
                                DpopCoreError::Transport(DpopHttpError::TimedOut)))))),
                            HostStop::Abandon => unreachable!(),
                        }
                    }
                };
                let server = async {
                    peer.watch_snapshot_reply("stop", 0, "working").await;
                    let mut listen = peer.watch_listen("stop").await;
                    listen.write_all(HEAD).await.unwrap();
                    event(&mut listen, &watch_ack("stop", true)).await;
                    get_reply(&mut peer, "stop", 1, &input_task(&["one"]), true).await;
                    let mut stalled = if update_stalled {
                        let mut socket = update(&mut peer, "stop", 0, "one").await;
                        socket.write_all(HEAD).await.unwrap();
                        event(&mut socket, &progress(json!("work"), "1")).await;
                        reached.cancel();
                        Some(socket)
                    } else { None };
                    reached.cancelled().await;
                    match stop {
                        HostStop::Cancel => { cancellation.cancel(); }
                        HostStop::Credential => { credential.revoke(); }
                        HostStop::Session => { revocation.revoke(); }
                        HostStop::Abandon | HostStop::Idle => {}
                    }
                    if let Some(socket) = &mut stalled {
                        pair(assert_watch_closed(&mut listen), assert_watch_closed(socket)).await;
                    } else { assert_watch_closed(&mut listen).await; }
                };
                pair(application, server).await;
                let pairs = if update_stalled { 4 } else { 3 };
                peer.no_extra(pairs);
                assert!(cx.checkpoint().is_ok());
                assert_eq!(client.revocation_handle().is_revoked(), matches!(stop, HostStop::Session));
                if matches!(stop, HostStop::Cancel | HostStop::Abandon | HostStop::Idle) {
                    followup(&mut peer, &mut client, &credential).await;
                    peer.no_extra(pairs + 1);
                }
            });
        }
    }
}

#[test]
fn resolver_panics_are_redacted_and_constructor_revocation_prevents_first_future_poll() {
    for case in 0..3 {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let application = client.drive_task_with_subscription(
                &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
                "host", policy(4, 1), watch_limits(8),
                |_| {
                    if case == 0 { panic!("private-constructor-canary"); }
                    if case == 1 { credential.revoke(); }
                    poll_fn(|_| -> Poll<Result<ManagedTaskInputAction, ManagedTaskDriverError>> {
                        panic!("private-future-canary")
                    })
                }, |_| Ok(()),
            );
            let server = async {
                peer.watch_snapshot_reply("host", 0, "working").await;
                let mut listen = peer.watch_listen("host").await;
                listen.write_all(HEAD).await.unwrap();
                event(&mut listen, &watch_ack("host", true)).await;
                get_reply(&mut peer, "host", 1, &input_task(&["one"]), true).await;
                assert_watch_closed(&mut listen).await;
            };
            let (result, ()) = pair(application, server).await;
            let error = result.err().expect("host did not authorize an update");
            assert!(!format!("{error:?} {error}").contains("canary"));
            if case == 1 {
                assert!(matches!(error, DpopTaskWatchError::Stream(DpopStreamError::Core(
                    DpopCoreError::Transport(DpopHttpError::Authorization(_))))));
            } else { assert!(matches!(error, DpopTaskWatchError::Stream(DpopStreamError::ObserverPanicked))); }
            peer.no_extra(3);
            assert!(!client.revocation_handle().is_revoked());
        });
    }
}

#[test]
fn either_clean_peer_teardown_order_hands_final_input_back_without_a_new_update() {
    for order in 0..3 {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let mut resolutions = 0;
            let application = client.drive_task_with_subscription(
                &cx, &cancellation, &credential, driver_metadata(), TaskId::parse("task-one").unwrap(),
                "ending", policy(5, 2), watch_limits(4),
                |_| { resolutions += 1; std::future::ready(Ok(ManagedTaskInputAction::Respond(answer("one")))) },
                |_| Ok(()),
            );
            let server = async {
                peer.watch_snapshot_reply("ending", 0, "working").await;
                let mut listen = peer.watch_listen("ending").await;
                listen.write_all(HEAD).await.unwrap();
                event(&mut listen, &watch_ack("ending", true)).await;
                peer.watch_snapshot_reply("ending", 1, "working").await;
                let cancelled = serde_json::to_vec(&json!({"jsonrpc":"2.0", "method":"notifications/cancelled",
                    "params":{"requestId":"ending.listen"}})).unwrap();
                let complete = watch_terminal("ending");
                let mut tail = if order == 2 { event_chunk(&complete) } else { Vec::new() };
                tail.extend_from_slice(&event_chunk(&cancelled));
                if order == 1 { tail.extend_from_slice(&event_chunk(&complete)); }
                tail.extend_from_slice(b"0\r\n\r\n");
                listen.write_all(&tail).await.unwrap();
                let _ = listen.shutdown().await;
                // There is unused snapshot/update capacity. Only the completed
                // listen, not an exhausted budget, must prohibit automatic input.
                get_reply(&mut peer, "ending", 2, &input_task(&["one"]), true).await;
            };
            let (result, ()) = pair(application, server).await;
            assert!(matches!(result.unwrap(), DpopTaskWaitOutcome::InputRequired(_)));
            assert_eq!(resolutions, 0);
            peer.no_extra(4);
            assert!(cx.checkpoint().is_ok());
            assert!(!client.revocation_handle().is_revoked());
            followup(&mut peer, &mut client, &credential).await;
        });
    }
}
