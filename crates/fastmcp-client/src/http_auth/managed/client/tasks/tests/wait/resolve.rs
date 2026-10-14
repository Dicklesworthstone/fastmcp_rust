//! Resolve suspended Tasks through the existing native OAuth/TLS fixture.
//! These calls use public client construction; no grant or response is injected.

use super::super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::{
    ElicitResult, FinalCreateMessageResult, FinalEmbeddedRootsListResult, ReverseRequestHandlers,
};
use fastmcp_protocol::tasks_extension::TaskInputRequests;

const INPUT_BYTES: usize = 64 * 1024;

fn client(
    peer: &Peer,
    session: ManagedOAuthSession,
    handlers: ReverseRequestHandlers,
) -> ManagedHttpClient {
    let builder = ClientBuilder::new()
        .protocol_plan(
            ClientProtocolPlan::http(
                ProtocolPolicy::ModernOnly,
                Some(peer.resource()),
                None,
                None,
                "task-input-owner".into(),
                "task-input-trust".into(),
                "native-http".into(),
                0,
                0,
                0,
            )
            .unwrap(),
        )
        .http_resource_root_certificate(peer.resource(), root())
        .unwrap()
        .reverse_request_handlers(handlers);
    ManagedHttpClient::new(session, builder, Duration::from_secs(30))
        .unwrap()
        .with_tasks()
}

fn roots(count: Arc<AtomicUsize>) -> ReverseRequestHandlers {
    ReverseRequestHandlers::new().with_modern_roots_list(move |_, _, _| {
        count.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(FinalEmbeddedRootsListResult { roots: vec![] }) })
    })
}

async fn get_inputs(peer: &Peer, inputs: Value) -> Value {
    let mut snapshot = task("input_required", "complete");
    snapshot["inputRequests"] = inputs;
    let request = peer.rpc("tasks/get", "access-one", snapshot, false).await;
    assert_eq!(request["params"]["taskId"], "task-1");
    request
}

async fn updated(peer: &Peer, expected: Value) -> Value {
    let (mut stream, request) = peer.request("tasks/update", "access-one").await;
    assert_eq!(request["params"]["taskId"], "task-1");
    assert_eq!(request["params"]["inputResponses"], expected);
    reply(
        &mut stream,
        json!({"jsonrpc":"2.0", "id":request["id"],
            "result":{"resultType":"complete"}}),
        false,
    )
    .await;
    request
}

#[test]
fn resolve_fresh_task_runs_roots_sampling_and_elicitation_then_updates_once() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let count = Arc::new(AtomicUsize::new(0));
        let sampled = Arc::clone(&count);
        let elicited = Arc::clone(&count);
        let handlers = roots(Arc::clone(&count))
            .with_modern_sampling_create_message(move |_, _, params| {
                sampled.fetch_add(1, Ordering::SeqCst);
                assert!(params.include_context.is_none());
                let result: FinalCreateMessageResult = serde_json::from_value(json!({
                    "role":"assistant", "model":"fixture",
                    "content":{"type":"text", "text":"sampled"}
                }))
                .unwrap();
                Box::pin(async move { Ok(result) })
            })
            .with_modern_elicitation_create(move |_, _, _| {
                elicited.fetch_add(1, Ordering::SeqCst);
                let result: ElicitResult = serde_json::from_value(json!({
                    "action":"accept", "content":{"answer":"approved"}
                }))
                .unwrap();
                Box::pin(async move { Ok(result) })
            });
        let mut client = client(&peer, session.clone(), handlers);
        let (result, ()) = Box::pin(pair(
            client.resolve_task_inputs_final(&cx, id(), 3, INPUT_BYTES),
            async {
                peer.discovery("access-one", true).await;
                let fetched = get_inputs(
                    &peer,
                    json!({
                        "a-roots":{"method":"roots/list"},
                        "b-sampling":{"method":"sampling/createMessage","params":{
                            "messages":[{"role":"user","content":{"type":"text","text":"hello"}}],
                            "maxTokens":16, "includeContext":"allServers"
                        }},
                        "c-form":{"method":"elicitation/create","params":{
                            "mode":"form", "message":"approve",
                            "requestedSchema":{"type":"object",
                                "properties":{"answer":{"type":"string"}}, "required":["answer"]}
                        }}
                    }),
                )
                .await;
                let sent = updated(
                    &peer,
                    json!({
                        "a-roots":{"roots":[]},
                        "b-sampling":{"role":"assistant","model":"fixture",
                            "content":{"type":"text","text":"sampled"}},
                        "c-form":{"action":"accept","content":{"answer":"approved"}}
                    }),
                )
                .await;
                assert_ne!(fetched["id"], sent["id"]);
                assert_eq!(count.load(Ordering::SeqCst), 3);
            },
        ))
        .await;
        assert!(result.is_ok());
        assert_eq!(client.cached_credential_generation(), Some(1));
        assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
        peer.no_more(&cx).await;
    });
}

#[test]
fn resolve_admits_the_entire_batch_before_the_first_callback() {
    for unsupported_later in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let count = Arc::new(AtomicUsize::new(0));
            let mut client = client(&peer, session, roots(Arc::clone(&count)));
            let (result, ()) = Box::pin(pair(
                client.resolve_task_inputs_final(&cx, id(), 2, INPUT_BYTES),
                async {
                    peer.discovery("access-one", true).await;
                    let mut inputs = json!({"a-roots":{"method":"roots/list"}});
                    if unsupported_later {
                        inputs["z-form"] = json!({"method":"elicitation/create","params":{
                            "mode":"form", "message":"approve",
                            "requestedSchema":{"type":"object","properties":{}}
                        }});
                    }
                    get_inputs(&peer, inputs).await;
                    if !unsupported_later {
                        updated(&peer, json!({"a-roots":{"roots":[]}})).await;
                    }
                    peer.no_more(&cx).await;
                },
            ))
            .await;
            assert_eq!(result.is_err(), unsupported_later);
            assert_eq!(count.load(Ordering::SeqCst), usize::from(!unsupported_later));
            assert_eq!(
                client.cached_credential_generation(),
                (!unsupported_later).then_some(1)
            );
        });
    }
}

#[test]
fn resolve_exact_payload_budget_accepts_and_one_byte_short_never_updates() {
    let inputs = json!({"roots":{"method":"roots/list"}});
    let typed: TaskInputRequests = serde_json::from_value(inputs.clone()).unwrap();
    let answer = FinalEmbeddedRootsListResult { roots: vec![] };
    let exact = serde_json::to_vec(&typed).unwrap().len()
        + serde_json::to_vec(&("roots", &answer)).unwrap().len();
    for fits in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let count = Arc::new(AtomicUsize::new(0));
            let mut client = client(&peer, session, roots(Arc::clone(&count)));
            let (result, ()) = Box::pin(pair(
                client.resolve_task_inputs_final(&cx, id(), 1, exact - usize::from(!fits)),
                async {
                    peer.discovery("access-one", true).await;
                    get_inputs(&peer, inputs.clone()).await;
                    if fits {
                        updated(&peer, json!({"roots":{"roots":[]}})).await;
                    }
                    peer.no_more(&cx).await;
                },
            ))
            .await;
            assert_eq!(result.is_ok(), fits);
            assert_eq!(count.load(Ordering::SeqCst), 1);
            assert_eq!(client.cached_credential_generation(), fits.then_some(1));
        });
    }
}

#[test]
fn resolve_ready_callback_cancellation_logout_and_revocation_prevent_update() {
    for cause in 0..3 {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let snapshot = session.credential(&cx).await.unwrap();
            let credential = snapshot.credential().clone();
            let cancellation = McpRequestCancellation::new();
            let signal = cancellation.clone();
            let login = session.clone();
            let count = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&count);
            let handlers = ReverseRequestHandlers::new().with_modern_roots_list(move |_, _, _| {
                counted.fetch_add(1, Ordering::SeqCst);
                match cause {
                    0 => {
                        signal.cancel();
                    }
                    1 => {
                        login.close();
                    }
                    _ => {
                        credential.revoke();
                    }
                }
                Box::pin(async { Ok(FinalEmbeddedRootsListResult { roots: vec![] }) })
            });
            let mut client = client(&peer, session.clone(), handlers);
            let (result, ()) = Box::pin(pair(
                client.resolve_task_inputs_final_with_cancellation(
                    &cx,
                    &cancellation,
                    id(),
                    1,
                    INPUT_BYTES,
                ),
                async {
                    peer.discovery("access-one", true).await;
                    get_inputs(&peer, json!({"roots":{"method":"roots/list"}})).await;
                    peer.no_more(&cx).await;
                },
            ))
            .await;
            assert!(matches!(result, Err(ManagedHttpClientError::Session(_))));
            assert_eq!(count.load(Ordering::SeqCst), 1);
            assert_eq!(client.cached_credential_generation(), None);
            assert!(!cx.is_cancel_requested());
            if cause == 0 {
                assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
            }
        });
    }
}
#[test]
fn resolve_failed_update_is_not_replayed_and_next_explicit_call_rediscovers() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let count = Arc::new(AtomicUsize::new(0));
        let mut client = client(&peer, session.clone(), roots(Arc::clone(&count)));
        let (result, ()) = Box::pin(pair(
            client.resolve_task_inputs_final(&cx, id(), 1, INPUT_BYTES),
            async {
                peer.discovery("access-one", true).await;
                get_inputs(&peer, json!({"roots":{"method":"roots/list"}})).await;
                let (stream, request) = peer.request("tasks/update", "access-one").await;
                assert_eq!(
                    request["params"]["inputResponses"],
                    json!({"roots":{"roots":[]}})
                );
                // The request reached the peer but its outcome is unknown.
                drop(stream);
                peer.no_more(&cx).await;
            },
        ))
        .await;
        assert!(result.is_err());
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(client.cached_credential_generation(), None);
        let (next, ()) = Box::pin(pair(client.get_task_final(&cx, id()), async {
            peer.discovery("access-one", true).await;
            peer.rpc("tasks/get", "access-one", task("working", "complete"), false)
                .await;
        }))
        .await;
        assert!(matches!(next.unwrap().task, FinalTask::Working(_)));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
    });
}

struct Dropped(Arc<AtomicUsize>);
impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn resolve_abandonment_drops_pending_host_future_without_update_or_remote_cancel() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let drops = Arc::new(AtomicUsize::new(0));
        let released = Arc::clone(&drops);
        let (entered, mut receipt) = asupersync::channel::oneshot::channel::<()>();
        let entered = Arc::new(std::sync::Mutex::new(Some(entered)));
        let handlers = ReverseRequestHandlers::new().with_modern_roots_list(move |_, _, _| {
            let owner = Dropped(Arc::clone(&released));
            entered
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send_blocking(())
                .unwrap();
            Box::pin(async move {
                let _owner = owner;
                std::future::pending().await
            })
        });
        let mut client = client(&peer, session.clone(), handlers);
        {
            let mut operation =
                Box::pin(client.resolve_task_inputs_final(&cx, id(), 1, INPUT_BYTES));
            let mut server = Box::pin(async {
                peer.discovery("access-one", true).await;
                get_inputs(&peer, json!({"roots":{"method":"roots/list"}})).await;
                receipt.recv(&cx).await.unwrap();
            });
            poll_fn(|task| {
                assert!(operation.as_mut().poll(task).is_pending());
                server.as_mut().poll(task)
            })
            .await;
        }
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(client.cached_credential_generation(), None);
        assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
        assert!(!cx.is_cancel_requested());
        peer.no_more(&cx).await;
    });
}

#[test]
fn resolve_refuses_non_input_snapshots_and_invalid_local_limits_without_callbacks() {
    for phase in ["working", "completed", "cancelled"] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let count = Arc::new(AtomicUsize::new(0));
            let mut client = client(&peer, session, roots(Arc::clone(&count)));
            for (count, bytes) in [(0, 1), (1, 0), (usize::MAX, 1), (1, usize::MAX)] {
                assert!(matches!(
                    client
                        .resolve_task_inputs_final(&cx, id(), count, bytes)
                        .await,
                    Err(ManagedHttpClientError::InvalidPolicy)
                ));
            }
            peer.no_more(&cx).await;
            let (result, ()) = Box::pin(pair(
                client.resolve_task_inputs_final(&cx, id(), 1, INPUT_BYTES),
                async {
                    peer.discovery("access-one", true).await;
                    peer.rpc("tasks/get", "access-one", task(phase, "complete"), false)
                        .await;
                    peer.no_more(&cx).await;
                },
            ))
            .await;
            assert!(result.is_err());
            assert_eq!(count.load(Ordering::SeqCst), 0);
            assert_eq!(client.cached_credential_generation(), None);
        });
    }
}

#[test]
fn resolve_deadline_interrupts_a_silent_host_callback_and_retires_its_owner() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let drops = Arc::new(AtomicUsize::new(0));
        let released = Arc::clone(&drops);
        let (entered, mut receipt) = asupersync::channel::oneshot::channel::<()>();
        let entered = Arc::new(std::sync::Mutex::new(Some(entered)));
        let handlers = ReverseRequestHandlers::new().with_modern_roots_list(move |_, _, _| {
            let owner = Dropped(Arc::clone(&released));
            entered
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send_blocking(())
                .unwrap();
            Box::pin(async move {
                let _owner = owner;
                std::future::pending().await
            })
        });
        let mut client = client(&peer, session.clone(), handlers);
        // Do not charge TLS discovery latency to the short timer assertion.
        let (primed, ()) = Box::pin(pair(client.get_task_final(&cx, id()), async {
            peer.discovery("access-one", true).await;
            peer.rpc("tasks/get", "access-one", task("working", "complete"), false)
                .await;
        }))
        .await;
        primed.unwrap();
        client.operation_timeout = Duration::from_secs(2);
        let (result, ()) = Box::pin(pair(
            client.resolve_task_inputs_final(&cx, id(), 1, INPUT_BYTES),
            async {
                get_inputs(&peer, json!({"roots":{"method":"roots/list"}})).await;
                // A missing callback would not satisfy this rendezvous. After
                // entry, neither the host nor the peer produces another wake.
                receipt.recv(&cx).await.unwrap();
                peer.no_more(&cx).await;
            },
        ))
        .await;
        assert!(matches!(
            result,
            Err(ManagedHttpClientError::Session(OAuthSessionError::TimedOut))
        ));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(client.cached_credential_generation(), None);
        assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
        assert!(!cx.is_cancel_requested());
        peer.no_more(&cx).await;
    });
}

fn dependent_inputs() -> Value {
    json!({
        "a-sample":{"method":"sampling/createMessage","params":{
            "messages":[{"role":"user","content":{"type":"text","text":"hello"}}],
            "maxTokens":16
        }},
        "b-roots":{"method":"roots/list"}
    })
}

fn sample_answer() -> FinalCreateMessageResult {
    serde_json::from_value(json!({
        "role":"assistant", "model":"fixture",
        "content":{"type":"text", "text":"released by roots"}
    }))
    .unwrap()
}

fn dependent_handlers(
    calls: Arc<AtomicUsize>,
    tokens: Arc<std::sync::Mutex<Vec<crate::ReverseRequestCancellation>>>,
) -> ReverseRequestHandlers {
    use asupersync::channel::oneshot;
    use std::sync::Mutex;

    let (sender, receiver) = oneshot::channel::<()>();
    let sender = Mutex::new(Some(sender));
    let receiver = Mutex::new(Some(receiver));
    let sampled = Arc::clone(&calls);
    let sampling_tokens = Arc::clone(&tokens);
    ReverseRequestHandlers::new()
        .with_modern_sampling_create_message(move |cx, local, _| {
            sampled.fetch_add(1, Ordering::SeqCst);
            sampling_tokens.lock().unwrap().push(local);
            let mut receiver = receiver.lock().unwrap().take().unwrap();
            Box::pin(async move {
                // Only the later roots callback can release this input. A
                // serial dispatcher never reaches it and cannot send an update.
                receiver.recv(cx).await.unwrap();
                Ok(sample_answer())
            })
        })
        .with_modern_roots_list(move |_, local, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            tokens.lock().unwrap().push(local);
            sender
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send_blocking(())
                .unwrap();
            Box::pin(async { Ok(FinalEmbeddedRootsListResult { roots: vec![] }) })
        })
}

#[test]
fn parallel_inputs_overlap_keep_exact_keys_and_never_replay_an_uncertain_update() {
    let inputs = dependent_inputs();
    let typed: TaskInputRequests = serde_json::from_value(inputs.clone()).unwrap();
    let root_answer = FinalEmbeddedRootsListResult { roots: vec![] };
    let exact = serde_json::to_vec(&typed).unwrap().len()
        + serde_json::to_vec(&("a-sample", sample_answer())).unwrap().len()
        + serde_json::to_vec(&("b-roots", &root_answer)).unwrap().len();
    // Change only the byte allowance or whether the one update is acknowledged.
    // Every row still requires both input futures to overlap and retain keys.
    for case in 0..3 {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let calls = Arc::new(AtomicUsize::new(0));
            let tokens = Arc::new(std::sync::Mutex::new(Vec::new()));
            let handlers = dependent_handlers(Arc::clone(&calls), Arc::clone(&tokens));
            let mut client = client(&peer, session.clone(), handlers);
            let expected = json!({
                "a-sample":sample_answer(),
                "b-roots":{"roots":[]}
            });
            let (result, ()) = Box::pin(pair(
                client.resolve_task_inputs_final(&cx, id(), 2, exact - usize::from(case == 0)),
                async {
                    peer.discovery("access-one", true).await;
                    let fetched = get_inputs(&peer, inputs.clone()).await;
                    if case != 0 {
                        let (mut stream, request) =
                            peer.request("tasks/update", "access-one").await;
                        assert_ne!(request["id"], fetched["id"]);
                        assert_eq!(request["params"]["taskId"], "task-1");
                        assert_eq!(request["params"]["inputResponses"], expected);
                        assert_eq!(calls.load(Ordering::SeqCst), 2);
                        assert!(
                            tokens
                                .lock()
                                .unwrap()
                                .iter()
                                .all(|token| !token.is_cancel_requested())
                        );
                        if case == 2 {
                            reply(
                                &mut stream,
                                json!({
                                    "jsonrpc":"2.0", "id":request["id"],
                                    "result":{"resultType":"complete"}
                                }),
                                false,
                            )
                            .await;
                        }
                        // In case 1 the request arrived, but its outcome is
                        // unknown. Neither input callbacks nor update may replay.
                        drop(stream);
                    }
                    peer.no_more(&cx).await;
                },
            ))
            .await;
            assert_eq!(result.is_ok(), case == 2);
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            // Scoped rather than dropped by hand. The explicit `drop` this
            // replaces was already correct -- it released the guard three
            // statements before the next await -- but `clippy::await_holding_lock`
            // reads the binding's lexical scope and flagged it anyway, which
            // halts the workspace gate at -D warnings. A block makes the
            // release structural, so the invariant survives a later edit that
            // moves statements around instead of depending on the `drop` call
            // staying put.
            {
                let tokens = tokens.lock().unwrap();
                assert_eq!(tokens.len(), 2);
                assert!(
                    tokens
                        .iter()
                        .all(|token| token.is_cancel_requested() == (case != 2))
                );
            }
            assert_eq!(client.cached_credential_generation(), (case == 2).then_some(1));
            assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
            let (next, ()) = Box::pin(pair(client.get_task_final(&cx, id()), async {
                if case != 2 {
                    peer.discovery("access-one", true).await;
                }
                peer.rpc("tasks/get", "access-one", task("working", "complete"), false)
                    .await;
            }))
            .await;
            assert!(matches!(next.unwrap().task, FinalTask::Working(_)));
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn a_ready_parallel_sibling_cannot_update_after_cancellation_logout_or_revocation() {
    for cause in 0..3 {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let snapshot = session.credential(&cx).await.unwrap();
            let credential = snapshot.credential().clone();
            let cancellation = McpRequestCancellation::new();
            let cancel = cancellation.clone();
            let login = session.clone();
            let calls = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&calls);
            let drops = Arc::new(AtomicUsize::new(0));
            let disposed = Arc::clone(&drops);
            let tokens = Arc::new(std::sync::Mutex::new(Vec::new()));
            let observed = Arc::clone(&tokens);
            let handlers = ReverseRequestHandlers::new().with_modern_roots_list(move |_, local, _| {
                observed.lock().unwrap().push(local);
                match counted.fetch_add(1, Ordering::SeqCst) {
                    0 => {
                        let owner = Dropped(Arc::clone(&disposed));
                        Box::pin(async move {
                            let _owner = owner;
                            std::future::pending().await
                        })
                    }
                    1 => {
                        match cause {
                            0 => {
                                cancel.cancel();
                            }
                            1 => {
                                login.close();
                            }
                            _ => {
                                credential.revoke();
                            }
                        }
                        Box::pin(async { Ok(FinalEmbeddedRootsListResult { roots: vec![] }) })
                    }
                    _ => panic!("no callback may start after its sibling revokes the operation"),
                }
            });
            let mut client = client(&peer, session.clone(), handlers);
            let (result, ()) = Box::pin(pair(
                client.resolve_task_inputs_final_with_cancellation(
                    &cx,
                    &cancellation,
                    id(),
                    3,
                    INPUT_BYTES,
                ),
                async {
                    peer.discovery("access-one", true).await;
                    get_inputs(
                        &peer,
                        json!({
                            "a":{"method":"roots/list"},
                            "b":{"method":"roots/list"},
                            "c":{"method":"roots/list"}
                        }),
                    )
                    .await;
                    peer.no_more(&cx).await;
                },
            ))
            .await;
            match cause {
                0 => assert!(matches!(
                    result,
                    Err(ManagedHttpClientError::Session(OAuthSessionError::Cancelled))
                )),
                1 => assert!(matches!(
                    result,
                    Err(ManagedHttpClientError::Session(OAuthSessionError::Closed))
                )),
                _ => assert!(matches!(result, Err(ManagedHttpClientError::Session(_)))),
            }
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert!(
                tokens
                    .lock()
                    .unwrap()
                    .iter()
                    .all(crate::ReverseRequestCancellation::is_cancel_requested)
            );
            assert_eq!(client.cached_credential_generation(), None);
            assert!(!cx.is_cancel_requested());
            if cause == 0 {
                assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
            }
        });
    }
}

#[test]
fn a_parallel_batch_retains_one_deadline_and_disposes_all_futures_on_abandonment() {
    for abandon in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let calls = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&calls);
            let drops = Arc::new(AtomicUsize::new(0));
            let disposed = Arc::clone(&drops);
            let tokens = Arc::new(std::sync::Mutex::new(Vec::new()));
            let observed = Arc::clone(&tokens);
            let (entered, mut receipt) = asupersync::channel::oneshot::channel::<()>();
            let entered = std::sync::Mutex::new(Some(entered));
            let handlers = ReverseRequestHandlers::new().with_modern_roots_list(move |_, local, _| {
                observed.lock().unwrap().push(local);
                let owner = Dropped(Arc::clone(&disposed));
                if counted.fetch_add(1, Ordering::SeqCst) == 1 {
                    entered
                        .lock()
                        .unwrap()
                        .take()
                        .unwrap()
                        .send_blocking(())
                        .unwrap();
                }
                Box::pin(async move {
                    let _owner = owner;
                    std::future::pending().await
                })
            });
            let mut client = client(&peer, session.clone(), handlers);
            let (primed, ()) = Box::pin(pair(client.get_task_final(&cx, id()), async {
                peer.discovery("access-one", true).await;
                peer.rpc("tasks/get", "access-one", task("working", "complete"), false)
                    .await;
            }))
            .await;
            primed.unwrap();
            if !abandon {
                client.operation_timeout = Duration::from_secs(2);
            }
            {
                let operation = client.resolve_task_inputs_final(&cx, id(), 2, INPUT_BYTES);
                let server = async {
                    get_inputs(
                        &peer,
                        json!({
                            "a":{"method":"roots/list"},
                            "b":{"method":"roots/list"}
                        }),
                    )
                    .await;
                    // Both callbacks, not just the first, must enter before
                    // this rendezvous releases. Neither ever completes.
                    receipt.recv(&cx).await.unwrap();
                    peer.no_more(&cx).await;
                };
                if abandon {
                    let mut operation = Box::pin(operation);
                    let mut server = Box::pin(server);
                    poll_fn(|task| {
                        assert!(operation.as_mut().poll(task).is_pending());
                        server.as_mut().poll(task)
                    })
                    .await;
                } else {
                    let (result, ()) = Box::pin(pair(operation, server)).await;
                    assert!(matches!(
                        result,
                        Err(ManagedHttpClientError::Session(OAuthSessionError::TimedOut))
                    ));
                }
            }
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(drops.load(Ordering::SeqCst), 2);
            assert!(
                tokens
                    .lock()
                    .unwrap()
                    .iter()
                    .all(crate::ReverseRequestCancellation::is_cancel_requested)
            );
            assert_eq!(client.cached_credential_generation(), None);
            assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
            assert!(!cx.is_cancel_requested());
            peer.no_more(&cx).await;
        });
    }
}
