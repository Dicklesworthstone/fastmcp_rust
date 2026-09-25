//! TASK-01-B: the stdio linkage proofs for every Tasks-bearing client
//! entrypoint, positive and planted negative.
//!
//! Frozen IDs: `task_01_b_positive`, `task_01_b_planted_negative`.
//!
//! # Why this file exists (bd-mcp-task-01-b-wivg)
//!
//! Both proofs previously lived inline in `crates/fastmcp-client/src/lib.rs`
//! under `#[cfg(test)] mod tests`. PL-3 refuses that placement as evidence:
//! `cfg(test)` behaviour cannot prove shipped behaviour, because the binary
//! under test is compiled with a cfg no released consumer ever sets. The
//! proofs were inline for one reason only -- their closing assertions read
//! four private members of `Client` (`child`, `child_cleanup_phase`,
//! `pending_process_cleanup_error`, `next_id`) plus one private method
//! (`transport_is_closed`), none of which an out-of-crate caller can reach.
//!
//! The remedy was to promote, not to weaken: `Client` gained four narrow
//! public accessors -- `child_cleanup_complete`, `has_pending_cleanup_error`,
//! `transport_is_closed`, `peek_next_request_id` -- each returning the
//! smallest value its assertion needs. `ClientChildCleanupPhase` and all four
//! fields remain private. The test bodies are otherwise byte-for-byte what
//! they were inline, and the inline copies were deleted in the same change so
//! each frozen ID still names exactly one test.
//!
//! # How a run of this file must be cited
//!
//! This target declares `required-features = ["tasks"]` in
//! `crates/fastmcp-client/Cargo.toml`, and every item is additionally
//! `#[cfg(all(unix, feature = "tasks"))]`, as the inline originals were.
//!
//! CORRECTION, recorded because I got this wrong when I first wrote the file:
//! I claimed a no-flags `-p fastmcp-client` run would "compile both proofs
//! away and report a green having executed nothing." It would not have. The
//! `use` block below is NOT cfg-gated, and `TASKS_EXTENSION` is re-exported
//! from `fastmcp_protocol` only under `#[cfg(feature = "tasks")]`
//! (`fastmcp-protocol/src/lib.rs:149`). So before the Cargo stanza existed
//! this target failed E0432 and took all 23 test targets in this package down
//! with it. A red, not a false green -- and not confined to this bead.
//!
//! With the stanza, the three behaviours are:
//!
//! - `cargo test --workspace ...` DISCOVERS them. `tasks` is opt-in on every
//!   package, but the published facade `fastmcp-rust` declares
//!   `default = ["legacy-2024-11-05", "tasks"]` and forwards it to the member
//!   crates, so a workspace build satisfies the requirement by unification.
//! - `cargo test -p fastmcp-client --features tasks` DISCOVERS them. This is
//!   the runner card's invocation.
//! - `cargo test -p fastmcp-client` alone SILENTLY SKIPS the whole target and
//!   exits 0. `required-features` is what makes that quiet rather than loud,
//!   which is precisely why the flag above is mandatory rather than advisory.
//!
//! A receipt citing these IDs must therefore carry the package selection, the
//! feature set and the target triple -- not just the exit status. The third
//! case is indistinguishable from success by exit code alone.
//!
//! # Which configuration a green here binds
//!
//! `--features tasks` is NOT an exotic flag: it is what the published facade
//! `fastmcp-rust` turns on by default, so a consumer depending on
//! `fastmcp-rust` ships with Tasks active. A consumer depending directly on
//! `fastmcp-client` does not, unless it opts in. A green here therefore binds
//! the default facade configuration and the opt-in direct-dependency
//! configuration -- not the default direct-dependency one, where these
//! entrypoints do not exist at all.
//!
//! # Scope limit
//!
//! These prove that each entrypoint negotiates Tasks on the wire exactly as
//! the server declared it, and that a clean close leaves the child reaped, no
//! cleanup error deferred, the transport closed, and no further request ID
//! allocated. They do not prove the peer drained every queued follow-up byte;
//! the client's failure cleanup kills the sole reader, so the peer log cannot
//! witness that. The emitted `TASK_01_B_STDIO_PROOF` record says so in its
//! `wireDrainProved` field rather than leaving the gap unstated.

use std::time::{Duration, Instant};

use asupersync::Cx;
use fastmcp_client::{
    ClientBuilder, ClientProtocolPlan, FinalToolCallOutcome, ProtocolPolicy, RequestTimeoutPolicy,
};
use fastmcp_core::{McpErrorCode, McpRequestCancellation};
use fastmcp_protocol::protocol_policy::MODERN_PROTOCOL_VERSION;
use fastmcp_protocol::{
    CoreResult, DiscoveryCacheHints, FINAL_CLIENT_CAPABILITIES_META_KEY, FinalCoreResult,
    JSONRPC_VERSION, ServerBehaviorRegistry, ServerDiscoverCapabilities, ServerDiscoverResult,
    ServerInfo, TASKS_EXTENSION,
};

/// Builds a final `server/discover` response that advertises the Tasks
/// extension with `settings`.
///
/// This is a deliberate copy of the identically named helper in the crate's
/// inline test module: that one is `cfg(test)`-private and unreachable from
/// here, and there is no shared test-support crate in this workspace. The copy
/// is kept honest by construction rather than by discipline -- it builds the
/// response out of the same public protocol types (`ServerDiscoverResult`,
/// `ServerDiscoverCapabilities`, `DiscoveryCacheHints`) instead of hand-written
/// JSON, so a change to the discovery wire shape breaks both copies together.
#[cfg(all(unix, feature = "tasks"))]
fn modern_tasks_discovery_response(server_name: &str, settings: serde_json::Value) -> String {
    let capabilities = ServerDiscoverCapabilities::from_registry(
        &ServerBehaviorRegistry::default(),
        std::collections::BTreeMap::from([(TASKS_EXTENSION.to_owned(), settings)]),
    )
    .expect("Tasks discovery settings satisfy the generic extension envelope");
    let result = ServerDiscoverResult::new(
        capabilities,
        ServerInfo {
            name: server_name.to_owned(),
            version: "1.0.0".to_owned(),
        },
        None,
        DiscoveryCacheHints::private_ttl_ms(0),
    );
    let mut response = serde_json::json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": 1,
        "result": result,
    });
    response["result"]["supportedVersions"] = serde_json::json!([MODERN_PROTOCOL_VERSION]);
    serde_json::to_string(&response).expect("Tasks discovery response serializes deterministically")
}

#[cfg(all(unix, feature = "tasks"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Task01BEntrypoint {
    DeclaredOutcome,
    CallToolWithCx,
    YieldingFinalMrtr { allow_tasks: bool },
    CallToolWithCancellation,
    RequestWithoutTasks,
    CallToolTyped,
    CallToolWithMrtrRetry,
}

#[cfg(all(unix, feature = "tasks"))]
fn assert_task_01_b_stdio_linkage(
    entrypoint: Task01BEntrypoint,
    server_tasks: bool,
    task_result: bool,
) {
    let task_declared = server_tasks
        && matches!(
            entrypoint,
            Task01BEntrypoint::DeclaredOutcome
                | Task01BEntrypoint::YieldingFinalMrtr { allow_tasks: true }
                | Task01BEntrypoint::CallToolWithCancellation
        );
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async move {
        let root = Cx::current().unwrap();
        let mut work = root.spawn(move |connection_cx| async move {
            let subject = format!("task-01-b-{}", std::process::id());
            let payload = if task_result {
                serde_json::json!({
                    "resultType": "task",
                    "taskId": subject,
                    "status": "working",
                    "createdAt": "2026-07-28T12:00:00.000Z",
                    "lastUpdatedAt": "2026-07-28T12:00:00.000Z",
                    "ttlMs": null
                })
            } else {
                serde_json::json!({
                    "resultType": "complete",
                    "content": [{"type": "text", "text": subject}]
                })
            };
            let mut discovery: serde_json::Value =
                serde_json::from_str(&modern_tasks_discovery_response(
                    "creation-peer",
                    serde_json::json!({}),
                ))
                .unwrap();
            if !server_tasks {
                discovery["result"]["capabilities"]["extensions"]
                    .as_object_mut()
                    .unwrap()
                    .remove(fastmcp_protocol::TASKS_EXTENSION);
            }
            let discovery = discovery.to_string();
            let response = format!(r#"{{"jsonrpc":"2.0","id":2,"result":{payload}}}"#);
            let log_path = std::env::temp_dir().join(format!(
                "task_01_b_{}_{:?}_{server_tasks}_{task_result}_{}.log",
                std::process::id(),
                entrypoint,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            ));
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&log_path)
                .expect("create a unique retained peer log");
            let log_argument = log_path.to_str().expect("peer log path is UTF-8");
            let script = r#"
LOG="$5"
IFS= read -r first || exit 90
printf '%s\n' "$first" >> "$LOG"
case "$first" in *'"method":"server/discover"'*'"id":1'*) ;; *) exit 91;; esac
printf '%s\n' "$1"
IFS= read -r call || exit 92
printf '%s\n' "$call" >> "$LOG"
case "$call" in *'"method":"tools/call"'*'"id":2'*) ;; *) exit 93;; esac
case "$call" in *'"name":"durable-tool"'*) ;; *) exit 94;; esac
case "$call" in *"$3"*) ;; *) exit 95;; esac
if [ "$4" = "true" ]; then
case "$call" in *'"extensions":{"io.modelcontextprotocol/tasks":{}}'*) ;; *) exit 96;; esac
else
case "$call" in *'io.modelcontextprotocol/tasks'*) exit 97;; esac
fi
printf '%s\n' "$2"
if [ "$4" = "false" ]; then
while IFS= read -r follow_up; do
    printf '%s\n' "$follow_up" >> "$LOG"
done
exit 0
fi
exec sleep 5
"#;
            let mut client = ClientBuilder::new()
                .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly))
                .request_timeout_policy(
                    RequestTimeoutPolicy::new(Duration::from_secs(2), Duration::from_secs(2)).unwrap(),
                )
                .max_retries(0)
                .connect_stdio_with_cx(
                    &connection_cx,
                    "sh",
                    &[
                        "-c",
                        script,
                        "creation-peer",
                        &discovery,
                        &response,
                        &subject,
                        if task_declared { "true" } else { "false" },
                        log_argument,
                    ],
                )
                .await
                .unwrap();

            let caller_cx = Cx::for_request();
            let cancellation = McpRequestCancellation::new();

            let result = match entrypoint {
                Task01BEntrypoint::DeclaredOutcome => {
                    client
                        .call_tool_final_outcome_with_cx(
                            &caller_cx,
                            &cancellation,
                            "durable-tool",
                            serde_json::json!({"subject": subject}),
                        )
                        .await
                        .map(|outcome| CoreResult::Final(match outcome {
                            FinalToolCallOutcome::Task(result) => {
                                FinalCoreResult::ToolsCallTask { result }
                            }
                            FinalToolCallOutcome::Complete(result) => {
                                FinalCoreResult::ToolsCall { result, diagnostic: None }
                            }
                            FinalToolCallOutcome::InputRequired(result) => {
                                FinalCoreResult::ToolsCallInputRequired { result, diagnostic: None }
                            }
                        }))
                }
                Task01BEntrypoint::CallToolWithCx => {
                    client
                        .call_tool_with_cx(
                            &caller_cx,
                            &cancellation,
                            "durable-tool",
                            serde_json::json!({"subject": subject}),
                        )
                        .await
                }
                Task01BEntrypoint::YieldingFinalMrtr { allow_tasks } => {
                    let mut execution = client
                        .start_yielding_final_mrtr_request(
                            &caller_cx,
                            "tools/call",
                            serde_json::json!({"name": "durable-tool", "arguments": {"subject": subject}}),
                            allow_tasks,
                        )
                        .unwrap();
                    let deadline = Instant::now() + Duration::from_secs(2);
                    loop {
                        match client.try_take_yielding_final_mrtr_response(&mut execution, false) {
                            Ok(Some(result)) => break Ok(result),
                            Ok(None) => {
                                assert!(Instant::now() < deadline, "timed out waiting for yielding response");
                                client.drive_yielding_stdio_slice().unwrap();
                                asupersync::runtime::yield_now().await;
                            }
                            Err(error) => break Err(error),
                        }
                    }
                }
                Task01BEntrypoint::CallToolWithCancellation => {
                    client
                        .call_tool_with_cancellation(
                            &caller_cx,
                            &cancellation,
                            "durable-tool",
                            serde_json::json!({"subject": subject}),
                        )
                }
                Task01BEntrypoint::RequestWithoutTasks => {
                    client.request_core_with_cancellation_without_tasks(
                        &caller_cx,
                        &cancellation,
                        "tools/call",
                        serde_json::json!({"name": "durable-tool", "arguments": {"subject": subject}}),
                        |_| {},
                    )
                }
                Task01BEntrypoint::CallToolTyped => {
                    client
                        .call_tool_typed("durable-tool", serde_json::json!({"subject": subject}))
                }
                Task01BEntrypoint::CallToolWithMrtrRetry => {
                    client.call_tool_with_mrtr_retry(
                        "durable-tool",
                        serde_json::json!({"subject": subject}),
                        |_| panic!("neither complete nor task permits an MRTR callback"),
                    )
                }
            };
            if task_result && !task_declared {
                let error = result.expect_err("an undeclared task result must be rejected");
                assert_eq!(error.code, McpErrorCode::InvalidRequest);
                assert_eq!(error.message, "Undeclared tools/call peer task result rejected");
                assert!(!client.is_initialized());
            } else {
                let result = result.expect("the negotiated result union accepts this branch");
                if task_result {
                    let CoreResult::Final(FinalCoreResult::ToolsCallTask { result: created, .. }) = &result else {
                        panic!("expected the task branch, got {result:?}");
                    };
                    assert_eq!(created.task.base().task_id.as_str(), subject);
                    assert!(matches!(created.task, fastmcp_protocol::tasks_extension::Task::Working(_)));
                } else {
                    assert!(matches!(result, CoreResult::Final(FinalCoreResult::ToolsCall { .. })));
                }
                assert_eq!(serde_json::from_str::<serde_json::Value>(&result.encode().unwrap()).unwrap(), payload);
                assert!(client.is_initialized());
                client.close_with_cx(&connection_cx).await.unwrap();
            }
            // The four post-close facts this proof exists to establish. Each is
            // now read through the public surface added for bd-mcp-task-01-b-wivg
            // rather than through a private field, which is what lets this file
            // sit outside the crate and satisfy PL-3.
            assert!(client.child_cleanup_complete());
            assert!(!client.has_pending_cleanup_error());
            assert!(client.transport_is_closed());
            assert_eq!(
                client.peek_next_request_id(),
                3,
                "no later request ID was allocated"
            );

            let log_content = std::fs::read_to_string(&log_path).expect("peer log must be readable");
            let recorded_lines: Vec<&str> = log_content.lines().filter(|line| !line.trim().is_empty()).collect();
            assert_eq!(recorded_lines.len(), 2, "peer recorded unexpected frames: {log_content}");
            let discovery_frame: serde_json::Value = serde_json::from_str(recorded_lines[0]).unwrap();
            let call_frame: serde_json::Value = serde_json::from_str(recorded_lines[1]).unwrap();
            assert_eq!(discovery_frame["id"], 1);
            assert_eq!(discovery_frame["method"], "server/discover");
            assert_eq!(call_frame["id"], 2);
            assert_eq!(call_frame["method"], "tools/call");
            assert_eq!(call_frame["params"]["name"], "durable-tool");
            assert_eq!(call_frame["params"]["arguments"], serde_json::json!({"subject": subject}));
            let recorded_declaration = call_frame["params"]["_meta"]
                [FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"]
                .get(fastmcp_protocol::TASKS_EXTENSION);
            assert_eq!(recorded_declaration, task_declared.then(|| serde_json::json!({})).as_ref());
            // The initial frames are logged before their responses. The
            // client's failure cleanup kills this sole reader, so its log
            // cannot prove that every queued follow-up byte was drained.
            eprintln!("TASK_01_B_STDIO_PROOF {}", serde_json::json!({
                "entrypoint": format!("{entrypoint:?}"), "serverTasks": server_tasks,
                "taskResult": task_result, "taskDeclared": task_declared,
                "subject": subject, "peerLog": log_path, "recordedFrames": recorded_lines.len(),
                "nextRequestId": 3, "cleanupComplete": true, "wireDrainProved": false
            }));
        })
        .expect("task spawns");
        work.join(&root).await.unwrap();
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(2)));
}

#[cfg(all(unix, feature = "tasks"))]
#[test]
fn task_01_b_positive() {
    for entrypoint in [
        Task01BEntrypoint::DeclaredOutcome,
        Task01BEntrypoint::YieldingFinalMrtr { allow_tasks: true },
        Task01BEntrypoint::CallToolWithCancellation,
    ] {
        for task_result in [false, true] {
            assert_task_01_b_stdio_linkage(entrypoint, true, task_result);
        }
    }
    assert_task_01_b_stdio_linkage(Task01BEntrypoint::CallToolWithCancellation, false, false);
    for entrypoint in [
        Task01BEntrypoint::CallToolWithCx,
        Task01BEntrypoint::YieldingFinalMrtr { allow_tasks: false },
        Task01BEntrypoint::RequestWithoutTasks,
        Task01BEntrypoint::CallToolTyped,
        Task01BEntrypoint::CallToolWithMrtrRetry,
    ] {
        assert_task_01_b_stdio_linkage(entrypoint, true, false);
    }
}

#[cfg(all(unix, feature = "tasks"))]
#[test]
fn task_01_b_planted_negative() {
    // The same public API and task payload as the positive differ only in
    // the server discovery's Tasks declaration. Intent to advertise Tasks
    // must not be mistaken for an actual negotiated wire declaration.
    assert_task_01_b_stdio_linkage(Task01BEntrypoint::CallToolWithCancellation, false, true);
    for entrypoint in [
        Task01BEntrypoint::CallToolWithCx,
        Task01BEntrypoint::YieldingFinalMrtr { allow_tasks: false },
        Task01BEntrypoint::RequestWithoutTasks,
        Task01BEntrypoint::CallToolTyped,
        Task01BEntrypoint::CallToolWithMrtrRetry,
    ] {
        assert_task_01_b_stdio_linkage(entrypoint, true, true);
    }
}
