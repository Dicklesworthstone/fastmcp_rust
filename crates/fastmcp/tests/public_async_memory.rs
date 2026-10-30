//! Public in-process serving on a caller-owned runtime without a reactor or
//! blocking pool. The modern facade also runs with `--no-default-features`.

// An integration test is its own crate root, so it inherits no attribute from
// the facade's `src/lib.rs` -- which does not raise this either. Proving `Send`
// for the nested `Facade::serve` async block spawned below overflows the default
// limit, and rustc then ABANDONS the proof rather than failing it, leaving the
// future unchecked rather than shown `Send`. See bd-35ktc.
#![recursion_limit = "512"]
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use asupersync::runtime::RuntimeBuilder;
use fastmcp_rust::memory::{MemoryTransport, create_memory_transport_pair_with_capacity};
use fastmcp_rust::{
    Cx, FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_PROTOCOL_VERSION_META_KEY, JsonRpcMessage,
    JsonRpcRequest, JsonRpcResponse, JsonValue, McpContext, McpResult, RequestId, TransportError,
    json, modern, tool,
};

#[tool]
async fn memory_echo(ctx: &McpContext, value: String) -> McpResult<String> {
    assert!(ctx.cx().blocking_pool_handle().is_none());
    asupersync::time::sleep(ctx.cx().now(), Duration::from_millis(1)).await;
    ctx.checkpoint()?;
    Ok(value)
}

#[derive(Clone, Copy, Debug)]
enum Facade {
    Modern,
    #[cfg(feature = "legacy-2024-11-05")]
    Auto,
    #[cfg(feature = "legacy-2024-11-05")]
    Legacy,
}

impl Facade {
    async fn serve(
        self,
        cx: &Cx,
        transport: MemoryTransport,
        stopped: Arc<AtomicBool>,
    ) -> McpResult<()> {
        let shutdown = move || stopped.store(true, Ordering::Release);
        match self {
            Self::Modern => {
                modern::ServerBuilder::new("facade-memory", "1.2.3")
                    .tool(MemoryEcho)
                    .on_shutdown(shutdown)
                    .build()
                    .serve_memory(cx, transport)
                    .await
            }
            #[cfg(feature = "legacy-2024-11-05")]
            Self::Auto => {
                fastmcp_rust::auto::ServerBuilder::new("facade-memory", "1.2.3")
                    .tool(MemoryEcho)
                    .on_shutdown(shutdown)
                    .build()
                    .serve_memory(cx, transport)
                    .await
            }
            #[cfg(feature = "legacy-2024-11-05")]
            Self::Legacy => {
                fastmcp_rust::legacy_2024::ServerBuilder::new("facade-memory", "1.2.3")
                    .tool(MemoryEcho)
                    .on_shutdown(shutdown)
                    .build()
                    .serve_memory(cx, transport)
                    .await
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum PeerEra {
    Modern,
    #[cfg(feature = "legacy-2024-11-05")]
    Legacy,
}

impl PeerEra {
    fn request(self, id: i64, method: &str, mut params: JsonValue) -> JsonRpcMessage {
        match self {
            Self::Modern => {
                params["_meta"] = json!({
                    FINAL_PROTOCOL_VERSION_META_KEY: modern::PROTOCOL_VERSION,
                    FINAL_CLIENT_CAPABILITIES_META_KEY: {},
                });
            }
            #[cfg(feature = "legacy-2024-11-05")]
            Self::Legacy => {}
        }
        JsonRpcMessage::Request(JsonRpcRequest::new(method, Some(params), id))
    }

    async fn open(self, cx: &Cx, peer: &mut MemoryTransport) {
        match self {
            Self::Modern => {
                peer.send_async(cx, &self.request(1, "server/discover", json!({})))
                    .await
                    .unwrap();
                let response = response(cx, peer, 1).await;
                assert!(response.error.is_none());
                let result = response.result.unwrap();
                assert_eq!(result["resultType"], "complete");
                assert_eq!(
                    result["supportedVersions"],
                    json!([modern::PROTOCOL_VERSION])
                );
            }
            #[cfg(feature = "legacy-2024-11-05")]
            Self::Legacy => {
                peer.send_async(
                    cx,
                    &self.request(
                        1,
                        "initialize",
                        json!({
                            "protocolVersion": fastmcp_rust::legacy_2024::PROTOCOL_VERSION,
                            "capabilities": {},
                            "clientInfo": {"name": "facade-memory-peer", "version": "1"},
                        }),
                    ),
                )
                .await
                .unwrap();
                let response = response(cx, peer, 1).await;
                assert!(response.error.is_none());
                let result = response.result.unwrap();
                assert_eq!(
                    result["protocolVersion"],
                    fastmcp_rust::legacy_2024::PROTOCOL_VERSION
                );
                assert_eq!(
                    result["serverInfo"],
                    json!({"name": "facade-memory", "version": "1.2.3"})
                );
                assert!(result.get("resultType").is_none());
                peer.send_async(
                    cx,
                    &JsonRpcMessage::Request(JsonRpcRequest::notification(
                        "notifications/initialized",
                        None,
                    )),
                )
                .await
                .unwrap();
            }
        }
    }

    fn assert_echo(self, response: JsonRpcResponse, value: &str) {
        assert!(response.error.is_none(), "{:?}", response.error);
        let result = response.result.unwrap();
        assert_eq!(result["content"], json!([{"type": "text", "text": value}]));
        assert_ne!(result["isError"], true);
        match self {
            Self::Modern => assert_eq!(result["resultType"], "complete"),
            #[cfg(feature = "legacy-2024-11-05")]
            Self::Legacy => assert!(result.get("resultType").is_none()),
        }
    }
}

async fn response(cx: &Cx, peer: &mut MemoryTransport, id: i64) -> JsonRpcResponse {
    let JsonRpcMessage::Response(response) = peer.recv_async(cx).await.unwrap() else {
        panic!("expected response to {id}");
    };
    assert_eq!(response.id, Some(RequestId::Number(id)));
    response
}

fn run_facade(facade: Facade, era: PeerEra) {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        assert!(cx.blocking_pool_handle().is_none());
        asupersync::time::timeout(cx.now(), Duration::from_secs(8), async {
            let (mut peer, transport) = create_memory_transport_pair_with_capacity(1);
            let stopped = Arc::new(AtomicBool::new(false));
            let server_stopped = Arc::clone(&stopped);
            let mut serving = cx
                .spawn(move |serve_cx| async move {
                    facade.serve(&serve_cx, transport, server_stopped).await
                })
                .unwrap();
            era.open(&cx, &mut peer).await;

            let value = format!("{facade:?} {era:?} résumé 東京\\literal\nline");
            let params = json!({"name": "memory_echo", "arguments": {"value": value}});
            peer.send_async(&cx, &era.request(2, "tools/call", params.clone()))
                .await
                .unwrap();
            era.assert_echo(response(&cx, &mut peer, 2).await, &value);

            // Change only the method. A refusal must not tear down the era or
            // prevent a later request on this same bounded connection.
            peer.send_async(&cx, &era.request(3, "memory/notRegistered", params.clone()))
                .await
                .unwrap();
            let refused = response(&cx, &mut peer, 3).await;
            assert_eq!(refused.error.unwrap().code.as_i32(), Some(-32601));
            assert!(refused.result.is_none());
            peer.send_async(&cx, &era.request(4, "tools/call", params.clone()))
                .await
                .unwrap();
            era.assert_echo(response(&cx, &mut peer, 4).await, &value);
            assert!(!stopped.load(Ordering::Acquire));

            // Close ingress with accepted work outstanding. The final result
            // must drain before shutdown even with one-slot output capacity.
            peer.send_async(&cx, &era.request(5, "tools/call", params))
                .await
                .unwrap();
            let (mut input, output) = peer.into_split();
            drop(output);
            let JsonRpcMessage::Response(final_response) = input.recv_async(&cx).await.unwrap()
            else {
                panic!("half-close must retain the accepted request's result");
            };
            assert_eq!(final_response.id, Some(RequestId::Number(5)));
            era.assert_echo(final_response, &value);
            assert!(matches!(
                input.recv_async(&cx).await,
                Err(TransportError::Closed)
            ));
            serving.join(&cx).await.unwrap().unwrap();
            assert!(stopped.load(Ordering::Acquire));
            assert!(cx.checkpoint().is_ok());
        })
        .await
        .expect("public memory serving must make bounded caller-runtime progress");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn modern_facade_async_memory_runs_without_reactor_or_blocking_pool() {
    run_facade(Facade::Modern, PeerEra::Modern);
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn auto_facade_async_memory_selects_modern() {
    run_facade(Facade::Auto, PeerEra::Modern);
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn auto_facade_async_memory_selects_exact_legacy() {
    run_facade(Facade::Auto, PeerEra::Legacy);
}

#[cfg(feature = "legacy-2024-11-05")]
#[test]
fn legacy_facade_async_memory_runs_without_reactor_or_blocking_pool() {
    run_facade(Facade::Legacy, PeerEra::Legacy);
}

mod typed_client {
    use super::*;
    use fastmcp_rust::{
        ClientCapabilities, ClientInfo, ContentBlock, CoreResult, FinalCoreResult, McpErrorCode,
        McpRequestCancellation, MemoryRequestEvent, MemoryRequestExecution,
    };

    fn assert_echo(result: CoreResult, expected: &str) {
        let CoreResult::Final(FinalCoreResult::ToolsCall { result, .. }) = result else {
            panic!("memory client must retain a typed modern tool result");
        };
        assert!(!result.payload.is_error);
        assert_eq!(result.payload.content.len(), 1);
        assert!(matches!(
            &result.payload.content[0],
            ContentBlock::Text { text, .. } if text == expected
        ));
    }

    async fn finish(
        cx: &Cx,
        client: &mut fastmcp_rust::client::MemoryClient,
        cancellation: &McpRequestCancellation,
        execution: &mut MemoryRequestExecution,
    ) -> CoreResult {
        loop {
            match client
                .next_event(cx, cancellation, execution)
                .await
                .unwrap()
            {
                Some(MemoryRequestEvent::Result(result)) => {
                    assert!(
                        client
                            .next_event(cx, cancellation, execution)
                            .await
                            .unwrap()
                            .is_none()
                    );
                    return *result;
                }
                Some(MemoryRequestEvent::Notification(_)) => {}
                None => panic!("memory execution must publish its result exactly once"),
            }
        }
    }

    fn run(facade: Facade) {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            assert!(cx.blocking_pool_handle().is_none());
            asupersync::time::timeout(cx.now(), Duration::from_secs(8), async {
                let (transport, server_transport) = create_memory_transport_pair_with_capacity(1);
                let stopped = Arc::new(AtomicBool::new(false));
                let server_stopped = Arc::clone(&stopped);
                let mut serving = cx
                    .spawn(move |serve_cx| async move {
                        facade
                            .serve(&serve_cx, server_transport, server_stopped)
                            .await
                    })
                    .unwrap();
                let mut client: fastmcp_rust::prelude::MemoryClient =
                    modern::MemoryClient::connect(
                        &cx,
                        transport,
                        ClientInfo {
                            name: "public-memory-client".to_owned(),
                            version: "1".to_owned(),
                        },
                        ClientCapabilities::default(),
                    )
                    .await
                    .unwrap();
                assert!(
                    client
                        .server_discovery()
                        .supported_versions()
                        .iter()
                        .any(|version| version == modern::PROTOCOL_VERSION)
                );
                let cancellation = McpRequestCancellation::new();
                let CoreResult::Final(FinalCoreResult::ToolsList {
                    result: catalog, ..
                }) = client.list_tools(&cx, &cancellation, None).await.unwrap()
                else {
                    panic!("memory catalog must retain its typed result and cache metadata");
                };
                assert_eq!(catalog.payload.tools.len(), 1);
                assert_eq!(catalog.payload.tools[0].name, "memory_echo");
                assert_eq!(
                    catalog.payload.tools[0].input_schema["properties"]["value"]["type"],
                    "string"
                );

                // Refusal happens before publication and consumes no ID.
                assert_eq!(
                    client
                        .execute_core(&cx, &cancellation, "tools/call", json!({}))
                        .await
                        .unwrap_err()
                        .code,
                    McpErrorCode::InvalidParams
                );
                let first_value = "first résumé 東京\\literal\nline";
                let second_value = "second independent request";
                let mut first = client
                    .execute_core(
                        &cx,
                        &cancellation,
                        "tools/call",
                        json!({
                            "name": "memory_echo", "arguments": {"value": first_value},
                        }),
                    )
                    .await
                    .unwrap();
                let mut second = client
                    .execute_core(
                        &cx,
                        &cancellation,
                        "tools/call",
                        json!({
                            "name": "memory_echo", "arguments": {"value": second_value},
                        }),
                    )
                    .await
                    .unwrap();
                assert_eq!(first.request_id(), &RequestId::Number(3));
                assert_eq!(second.request_id(), &RequestId::Number(4));
                // Driving the second owner must preserve the first result,
                // including when its response arrives during send admission.
                assert_echo(
                    finish(&cx, &mut client, &cancellation, &mut second).await,
                    second_value,
                );
                assert_echo(
                    finish(&cx, &mut client, &cancellation, &mut first).await,
                    first_value,
                );
                assert_echo(
                    client
                        .call_tool(
                            &cx,
                            &cancellation,
                            "memory_echo",
                            json!({
                                "value": "same connection remains usable",
                            }),
                        )
                        .await
                        .unwrap(),
                    "same connection remains usable",
                );

                assert!(!stopped.load(Ordering::Acquire));
                client.close(&cx).unwrap();
                serving.join(&cx).await.unwrap().unwrap();
                assert!(stopped.load(Ordering::Acquire));
                assert!(cx.checkpoint().is_ok());
            })
            .await
            .expect("typed memory client and server must progress on their caller runtime");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn modern_memory_client_drives_real_server_without_reactor_or_blocking_pool() {
        run(Facade::Modern);
    }

    #[cfg(feature = "legacy-2024-11-05")]
    #[test]
    fn modern_memory_client_drives_auto_server_on_one_slot_channels() {
        run(Facade::Auto);
    }
}

#[cfg(feature = "tasks")]
mod retention_administration {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use std::time::Instant;

    use fastmcp_rust::{
        AuthContext, FinalTask, FinalTaskRetentionAuthority, FinalTaskRuntime,
        FinalTaskRuntimeConfig, FinalTaskStatusNotification, FinalTaskStatusNotificationParams,
        FinalTaskStore, InMemoryFinalTaskStore, TaskRetentionAdministrator,
        TaskRetentionAuthorization, TaskRetentionPolicy, TaskRetentionReason,
        TaskRetentionReclamation,
    };

    struct Operator {
        enabled: AtomicBool,
    }

    impl TaskRetentionAdministrator for Operator {
        fn authorize(
            &self,
            ctx: &McpContext,
            _action: &TaskRetentionAuthorization<'_>,
        ) -> McpResult<()> {
            if self.enabled.load(Ordering::Acquire)
                && ctx.auth().is_some_and(|auth| {
                    auth.scopes
                        .iter()
                        .any(|scope| scope == "tasks:retention:admin")
                })
            {
                Ok(())
            } else {
                Err(fastmcp_rust::McpError::invalid_request(
                    "operator permission denied",
                ))
            }
        }
    }

    impl FinalTaskRetentionAuthority for Operator {
        fn authorize_unlimited_retention(&self) -> McpResult<()> {
            Ok(())
        }
    }

    fn retained_task(id: &str, text: &str) -> FinalTask {
        fastmcp_rust::serde_json::from_value(json!({
            "taskId": id,
            "status": "completed",
            "createdAt": "2026-07-28T12:00:00.000Z",
            "lastUpdatedAt": "2026-07-28T12:00:00.001Z",
            "ttlMs": null,
            "result": {"content": [{"type": "text", "text": text}]},
        }))
        .unwrap()
    }

    fn retain(store: &InMemoryFinalTaskStore, task: FinalTask) -> McpResult<()> {
        let notification = FinalTaskStatusNotification::new(FinalTaskStatusNotificationParams {
            task: task.clone(),
            meta: None,
            additional: Default::default(),
        });
        store.create_task(task, notification)
    }

    #[test]
    fn facade_task_retention_reclaims_capacity_only_under_current_admin_authority() {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let now = Instant::now();
            let elapsed = Arc::new(AtomicU64::new(0));
            let clock = Arc::clone(&elapsed);
            let store = Arc::new(
                InMemoryFinalTaskStore::with_clock(
                    1,
                    Arc::new(move || now + Duration::from_millis(clock.load(Ordering::Acquire))),
                )
                .unwrap()
                .with_retention_policy(
                    TaskRetentionPolicy::new(1, 4096, Duration::from_secs(1)).unwrap(),
                )
                .unwrap(),
            );
            let operator = Arc::new(Operator {
                enabled: AtomicBool::new(true),
            });
            let tasks = FinalTaskRuntime::new(
                store.clone(),
                FinalTaskRuntimeConfig::with_unlimited_ttl(operator.as_ref(), None).unwrap(),
                Arc::new(|_| {}),
            );
            // This fixture installs a retained terminal record through the
            // public trusted-backend API, then uses only facade administration.
            let first = retained_task("retained-terminal", "private retained result");
            let id = first.base().task_id.clone();
            retain(store.as_ref(), first).unwrap();
            let bytes = store.retained_payload_bytes();
            assert!(bytes > 0);
            assert!(retain(store.as_ref(), retained_task("capacity-probe", "blocked")).is_err());

            let mut admin_auth = AuthContext::with_subject("operator");
            admin_auth.scopes.push("tasks:retention:admin".to_owned());
            let admin = McpContext::new(cx.clone(), 1).with_auth(admin_auth);
            let owner =
                McpContext::new(cx.clone(), 2).with_auth(AuthContext::with_subject("task-owner"));
            assert!(tasks.inspect_task_retention(&admin, &id).is_err());
            tasks
                .install_retention_administrator(&cx, operator.clone())
                .unwrap();
            assert!(tasks.inspect_task_retention(&owner, &id).is_err());
            assert_eq!(store.retained_payload_bytes(), bytes);

            let target = tasks.inspect_task_retention(&admin, &id).unwrap();
            let cloned_runtime = tasks.clone();
            assert!(
                cloned_runtime
                    .reclaim_task_retention(&owner, &target, TaskRetentionReason::OperatorRequest,)
                    .is_err()
            );
            operator.enabled.store(false, Ordering::Release);
            assert!(
                cloned_runtime
                    .reclaim_task_retention(&admin, &target, TaskRetentionReason::OperatorRequest,)
                    .is_err()
            );
            assert_eq!(store.retained_payload_bytes(), bytes);
            assert!(store.get_task(&id).unwrap().is_some());

            operator.enabled.store(true, Ordering::Release);
            let TaskRetentionReclamation::Reclaimed(receipt) = cloned_runtime
                .reclaim_task_retention(&admin, &target, TaskRetentionReason::OperatorRequest)
                .unwrap()
            else {
                panic!("the authorized current generation must reclaim")
            };
            assert_eq!(receipt.released_payload_bytes(), bytes);
            assert_eq!(store.retained_payload_bytes(), 0);
            assert!(store.get_task(&id).unwrap().is_none());
            assert_eq!(
                tasks
                    .reclaim_task_retention(&admin, &target, TaskRetentionReason::OperatorRequest,)
                    .unwrap(),
                TaskRetentionReclamation::AlreadyReclaimed(receipt.clone())
            );
            assert!(tasks.task_retention_audit(&owner, None, 1).is_err());
            let audit = tasks.task_retention_audit(&admin, None, 1).unwrap();
            assert_eq!(audit.records(), &[receipt.clone()]);
            assert_eq!(audit.retained_records(), 1);
            assert!(audit.retained_bytes() <= 4096);

            // Reuse the freed capacity and even the same public identifier.
            // A retained old target must never erase this later generation.
            retain(
                store.as_ref(),
                retained_task("retained-terminal", "successor result"),
            )
            .unwrap();
            let successor = tasks.inspect_task_retention(&admin, &id).unwrap();
            assert!(successor.generation() > target.generation());
            let successor_bytes = store.retained_payload_bytes();
            assert!(
                tasks
                    .reclaim_task_retention(
                        &admin,
                        &successor,
                        TaskRetentionReason::RetentionPolicy,
                    )
                    .is_err(),
                "audit capacity must refuse before releasing the record"
            );
            assert_eq!(store.retained_payload_bytes(), successor_bytes);
            assert!(store.get_task(&id).unwrap().is_some());
            let old_retry = tasks
                .reclaim_task_retention(&admin, &target, TaskRetentionReason::OperatorRequest)
                .unwrap();
            assert!(!matches!(old_retry, TaskRetentionReclamation::Reclaimed(_)));
            assert_eq!(store.retained_payload_bytes(), successor_bytes);

            elapsed.store(1001, Ordering::Release);
            assert_eq!(
                tasks
                    .reclaim_task_retention(&admin, &target, TaskRetentionReason::OperatorRequest,)
                    .unwrap(),
                TaskRetentionReclamation::NotCurrent
            );
            assert_eq!(store.retained_payload_bytes(), successor_bytes);
            let TaskRetentionReclamation::Reclaimed(next_receipt) = tasks
                .reclaim_task_retention(&admin, &successor, TaskRetentionReason::RetentionPolicy)
                .unwrap()
            else {
                panic!("expired audit capacity is reusable")
            };
            assert!(next_receipt.sequence() > receipt.sequence());
            assert_eq!(store.retained_payload_bytes(), 0);
            assert!(cx.checkpoint().is_ok());
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }
}
