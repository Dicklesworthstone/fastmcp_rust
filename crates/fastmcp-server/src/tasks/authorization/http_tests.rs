//! Composition of HTTP request admission with detached Task authorization.

use super::*;
use crate::http_admission::security::HttpSecurityPolicy;
use crate::http_admission::security::scope_policy::request::ScopeRequestPolicy;
use crate::http_admission::security::scope_policy::request::operation::{
    OperationScopePolicy, ScopedOperation,
};
use crate::http_admission::security::scope_policy::{RequiredScopes, ScopeImplicationPolicy};
use crate::{
    FinalToolOutcome, HttpAdmissionLimits, HttpEndpointConfig, Server, ServerHttpEndpoint,
    StaticTokenVerifier, TestHttpEndpoint, TokenAuthProvider, ToolHandler,
};
use fastmcp_core::AuthContext;
use fastmcp_protocol::{Content, JsonRpcResponse, Tool, protocol_policy::ProtocolPolicy};
use fastmcp_transport::http::{HttpMethod, HttpRequest};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

const RESULT_CANARY: &str = "secured-original-tool-result-canary";

struct ScopedTaskTool;

impl ToolHandler for ScopedTaskTool {
    fn definition(&self) -> Tool {
        Tool {
            name: "sensitive-tool".to_owned(),
            description: None,
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, _: &McpContext, _: serde_json::Value) -> McpResult<Vec<Content>> {
        Ok(Vec::new())
    }

    fn call_final_outcome(
        &self,
        _: &McpContext,
        _: serde_json::Value,
    ) -> McpResult<FinalToolOutcome> {
        Ok(FinalToolOutcome::CreateTask {
            work_descriptor: FinalTaskWorkDescriptor::new(serde_json::json!({
                "operation": "sensitive-tool",
            }))?,
            status_message: None,
        })
    }

    fn declares_final_tasks(&self) -> bool {
        true
    }
}

struct ScopedTaskExecutionPolicy {
    principal: Sha256Digest,
    allowed: AtomicBool,
    checks: AtomicUsize,
}

impl TaskExecutionAuthorizer for ScopedTaskExecutionPolicy {
    fn authorize(&self, task: &FinalTaskAccessMetadata) -> McpResult<()> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        if !self.allowed.load(Ordering::SeqCst)
            || task.authenticated_principal() != Some(self.principal)
            || !task.original_operation().is_some_and(|operation| {
                operation.method() == "tools/call" && operation.tool_name() == "sensitive-tool"
            })
        {
            return Err(McpError::invalid_request(
                "Current Task execution grant is unavailable",
            ));
        }
        Ok(())
    }
}

#[derive(Default)]
struct InputSupervisor {
    initial: AtomicUsize,
    resumed: AtomicUsize,
}

impl ApplicationTaskSupervisor for InputSupervisor {
    fn resume<'a>(
        &'a self,
        _: &'a Cx,
        handoff: FinalTaskSupervisorHandoff,
    ) -> FinalTaskSupervisorFuture<'a> {
        match &handoff {
            FinalTaskSupervisorHandoff::Initial(_) => {
                self.initial.fetch_add(1, Ordering::SeqCst);
            }
            FinalTaskSupervisorHandoff::Resumed(_) => {
                self.resumed.fetch_add(1, Ordering::SeqCst);
            }
        }
        Box::pin(async move {
            match handoff {
                FinalTaskSupervisorHandoff::Initial(initial) => {
                    initial.require_input(
                        serde_json::from_value(serde_json::json!({
                            "roots": {"method": "roots/list"},
                        }))
                        .unwrap(),
                        None,
                    )?;
                }
                FinalTaskSupervisorHandoff::Resumed(accepted) => {
                    accepted.complete_task(
                        serde_json::from_value(serde_json::json!({
                            "content": [{"type": "text", "text": RESULT_CANARY}],
                        }))
                        .unwrap(),
                        None,
                    )?;
                }
            }
            Ok(())
        })
    }
}

fn shared_policy() -> ScopeRequestPolicy {
    let required = |scope: &str| RequiredScopes::new(vec![scope.to_owned()]).unwrap();
    let methods = ScopeRequestPolicy::new(
        1,
        ScopeImplicationPolicy::exact(1).unwrap(),
        vec![
            ("tools/call".to_owned(), required("invoke")),
            ("tasks/get".to_owned(), required("manage")),
            ("tasks/update".to_owned(), required("manage")),
            ("tasks/cancel".to_owned(), required("manage")),
        ],
    )
    .unwrap();
    ScopeRequestPolicy::for_operations(
        OperationScopePolicy::new(
            1,
            methods,
            vec![(
                ScopedOperation::ToolCall("sensitive-tool".to_owned()),
                required("sensitive"),
            )],
        )
        .unwrap(),
    )
    .unwrap()
}

fn facts(scopes: &[&str]) -> AuthContext {
    let mut auth = AuthContext::with_subject("same-task-owner")
        .with_session_owner(Sha256Digest::from_bytes([37; 32]));
    auth.scopes = scopes.iter().map(|scope| (*scope).to_owned()).collect();
    auth
}

fn parameters(task_id: Option<&FinalTaskId>) -> serde_json::Value {
    let mut params = serde_json::json!({
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {
                "extensions": {"io.modelcontextprotocol/tasks": {}},
            },
        },
    });
    if let Some(task_id) = task_id {
        params["taskId"] = serde_json::json!(task_id);
    }
    params
}

async fn secured_rpc(
    cx: &Cx,
    endpoint: &ServerHttpEndpoint,
    security: &HttpSecurityPolicy,
    token: &str,
    method: &str,
    params: serde_json::Value,
) -> JsonRpcResponse {
    let name = if method == "tools/call" {
        "sensitive-tool"
    } else {
        params["taskId"].as_str().unwrap()
    };
    let request = HttpRequest::new(HttpMethod::Post, "/mcp")
        .with_header("host", "service.example")
        .with_header("authorization", format!("Bearer {token}"))
        .with_header("content-type", "application/json")
        .with_header("accept", "application/json")
        .with_header("mcp-protocol-version", FINAL_PROTOCOL_VERSION)
        .with_header("mcp-method", method)
        .with_header("mcp-name", name)
        .with_body(serde_json::to_vec(&JsonRpcRequest::new(method, Some(params), 1_i64)).unwrap());
    let response = Box::pin(endpoint.handle_secured_async(cx, security, request))
        .await
        .unwrap();
    assert!(!response.is_streaming());
    // The method-level HTTP gate has admitted both credentials. The Task's
    // original-operation check must still reject the narrower credential.
    assert_eq!(response.response().status.0, 200);
    serde_json::from_slice(&response.response().body).unwrap()
}

async fn while_serving<F: Future>(
    mut service: Pin<&mut impl Future<Output = McpResult<()>>>,
    scenario: F,
) -> F::Output {
    let mut scenario = std::pin::pin!(scenario);
    std::future::poll_fn(|poll| {
        if let Poll::Ready(result) = service.as_mut().poll(poll) {
            panic!("Task service exited before the HTTP scenario: {result:?}");
        }
        scenario.as_mut().poll(poll)
    })
    .await
}

#[test]
fn secured_http_shared_scope_policy_rechecks_original_task_grants() {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
        .blocking_threads(1, 4)
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            let mut task = cx
                .spawn(|cx| async move {
                    let store = Arc::new(InMemoryFinalTaskStore::default());
                    let runtime = FinalTaskRuntime::new(
                        store.clone(),
                        FinalTaskRuntimeConfig::new(60_000, None).unwrap(),
                        Arc::new(|_| {}),
                    );
                    let scopes = shared_policy();
                    // The application indexes its current grants by the same
                    // identity-only key as Task metadata. This keeps neither
                    // an ingress context nor a credential alive for a worker.
                    let execution = Arc::new(ScopedTaskExecutionPolicy {
                        principal: FinalTaskAccessMetadata::principal_for_auth(&facts(&[
                            "invoke", "manage", "sensitive",
                        ]))
                        .unwrap(),
                        allowed: AtomicBool::new(true),
                        checks: AtomicUsize::new(0),
                    });
                    let supervisor = Arc::new(InputSupervisor::default());
                    let verifier = StaticTokenVerifier::new([
                        ("full-grants", facts(&["invoke", "manage", "sensitive"])),
                        ("lost-original-grant", facts(&["invoke", "manage"])),
                    ])
                    .unwrap();
                    let endpoint = Server::new("secured-task-scopes", "1")
                        .protocol_policy(ProtocolPolicy::ModernOnly)
                        .unwrap()
                        .final_tasks(runtime.clone())
                        .unwrap()
                        .task_access_authorizer(Arc::new(scopes.clone()))
                        .task_execution_authorizer(execution.clone())
                        .auth_provider(TokenAuthProvider::new(verifier))
                        .tool(ScopedTaskTool)
                        // `http://`, not `https://`: this argument is the
                        // LEGACY 2024-11-05 origin, and that lane is
                        // plaintext-only, so `into_http_endpoint` refuses a
                        // TLS scheme with InvalidConfiguration whenever the
                        // `legacy-2024-11-05` feature is on -- which it is by
                        // default. Without that feature the argument is
                        // discarded, so an https value made this test pass in
                        // one feature lane and fail in the other, defeating
                        // the whole point of the TestHttpEndpoint helper
                        // ("a modern test names an origin once and runs in
                        // both feature lanes"). The modern endpoint's own
                        // origin is the separate https HttpSecurityPolicy
                        // value below, which is correct and unchanged.
                        .test_http_endpoint("http://service.example")
                        .unwrap();
                    let security = HttpSecurityPolicy::new(
                        HttpEndpointConfig::new(
                            "/mcp",
                            HttpAdmissionLimits::new(32, 8192, 65536).unwrap(),
                        )
                        .unwrap(),
                        "https://service.example",
                        vec![],
                    )
                    .unwrap()
                    .with_scope_authorization(scopes)
                    .unwrap();
                    let runner = runtime
                        .install_task_service(4, supervisor.clone())
                        .unwrap();
                    assert!(!runtime.is_task_service_ready());
                    {
                        // Native per-request embedding does not start a service.
                        // This caller owns and polls the public runner alongside
                        // HTTP dispatch, without a detached task or readiness stub.
                        let mut service = std::pin::pin!(runner.run(&cx));
                        asupersync::time::timeout(
                            cx.now(),
                            StdDuration::from_secs(5),
                            while_serving(service.as_mut(), async {
                                let mut create = parameters(None);
                                create["name"] = serde_json::json!("sensitive-tool");
                                create["arguments"] = serde_json::json!({});
                                let created = secured_rpc(
                                    &cx,
                                    &endpoint,
                                    &security,
                                    "full-grants",
                                    "tools/call",
                                    create,
                                )
                                .await;
                                assert!(created.error.is_none());
                                let created: CreateTaskResult =
                                    serde_json::from_value(created.result.unwrap()).unwrap();
                                let id = created.task.base().task_id.clone();
                                while runtime.get_task(&id).unwrap().task.base().status
                                    != FinalTaskStatus::InputRequired
                                {
                                    asupersync::time::sleep(cx.now(), StdDuration::from_millis(1))
                                        .await;
                                }
                                assert_eq!(supervisor.initial.load(Ordering::SeqCst), 1);
                                assert_eq!(supervisor.resumed.load(Ordering::SeqCst), 0);
                                let initial_checks = execution.checks.load(Ordering::SeqCst);
                                assert!(initial_checks > 0, "the builder installed a live policy");
                                let get = secured_rpc(
                                    &cx,
                                    &endpoint,
                                    &security,
                                    "full-grants",
                                    "tasks/get",
                                    parameters(Some(&id)),
                                )
                                .await;
                                assert!(get.error.is_none());
                                assert_eq!(get.result.unwrap()["taskId"], serde_json::json!(id));
                                let before = store.get_task_snapshot(&id).unwrap().unwrap();
                                let payload_bytes = store.retained_payload_bytes();
                                let notification =
                                    serde_json::to_value(store.latest_notification(&id)).unwrap();
                                for method in ["tasks/get", "tasks/update", "tasks/cancel"] {
                                    let mut params = parameters(Some(&id));
                                    if method == "tasks/update" {
                                        params["inputResponses"] = serde_json::json!({
                                            "roots": {"roots": []},
                                        });
                                    }
                                    let denied = secured_rpc(
                                        &cx,
                                        &endpoint,
                                        &security,
                                        "lost-original-grant",
                                        method,
                                        params,
                                    )
                                    .await;
                                    assert!(denied.result.is_none());
                                    assert_eq!(denied.error.unwrap().message, "Task not found");
                                    let after = store.get_task_snapshot(&id).unwrap().unwrap();
                                    assert_eq!(after.generation(), before.generation());
                                    assert_eq!(
                                        serde_json::to_value(after.task()).unwrap(),
                                        serde_json::to_value(before.task()).unwrap()
                                    );
                                    assert_eq!(
                                        after.authenticated_principal(),
                                        before.authenticated_principal()
                                    );
                                    assert_eq!(
                                        after.original_operation(),
                                        before.original_operation()
                                    );
                                    assert_eq!(store.retained_payload_bytes(), payload_bytes);
                                    assert_eq!(
                                        serde_json::to_value(store.latest_notification(&id))
                                            .unwrap(),
                                        notification
                                    );
                                    assert!(!store.is_cancellation_requested(&id).unwrap());
                                    assert!(
                                        store.next_accepted_input_snapshot().unwrap().is_none()
                                    );
                                }
                                let mut update = parameters(Some(&id));
                                update["inputResponses"] =
                                    serde_json::json!({"roots": {"roots": []}});
                                let updated = secured_rpc(
                                    &cx,
                                    &endpoint,
                                    &security,
                                    "full-grants",
                                    "tasks/update",
                                    update,
                                )
                                .await;
                                assert!(updated.error.is_none());
                                while runtime.get_task(&id).unwrap().task.base().status
                                    != FinalTaskStatus::Completed
                                {
                                    asupersync::time::sleep(cx.now(), StdDuration::from_millis(1))
                                        .await;
                                }
                                let completed = secured_rpc(
                                    &cx,
                                    &endpoint,
                                    &security,
                                    "full-grants",
                                    "tasks/get",
                                    parameters(Some(&id)),
                                )
                                .await;
                                assert!(completed.error.is_none());
                                assert!(
                                    serde_json::to_string(&completed.result)
                                        .unwrap()
                                        .contains(RESULT_CANARY)
                                );
                                assert_eq!(supervisor.resumed.load(Ordering::SeqCst), 1);
                                assert!(
                                    execution.checks.load(Ordering::SeqCst) > initial_checks,
                                    "input resumption rechecks the installed execution policy"
                                );
                                let denied = secured_rpc(
                                    &cx,
                                    &endpoint,
                                    &security,
                                    "lost-original-grant",
                                    "tasks/get",
                                    parameters(Some(&id)),
                                )
                                .await;
                                assert!(denied.result.is_none());
                                assert_eq!(denied.error.unwrap().message, "Task not found");

                                // Change only the current autonomous execution
                                // grant. HTTP admission and request grants still
                                // permit creation, but no second application
                                // handoff may run under the withdrawn grant.
                                execution.allowed.store(false, Ordering::SeqCst);
                                let mut create = parameters(None);
                                create["name"] = serde_json::json!("sensitive-tool");
                                create["arguments"] = serde_json::json!({});
                                let created = secured_rpc(
                                    &cx,
                                    &endpoint,
                                    &security,
                                    "full-grants",
                                    "tools/call",
                                    create,
                                )
                                .await;
                                assert!(created.error.is_none());
                                let created: CreateTaskResult =
                                    serde_json::from_value(created.result.unwrap()).unwrap();
                                let denied_id = created.task.base().task_id.clone();
                                let rejected_task = loop {
                                    let current = runtime.get_task(&denied_id).unwrap().task;
                                    if matches!(
                                        current.base().status,
                                        FinalTaskStatus::Completed
                                            | FinalTaskStatus::Failed
                                            | FinalTaskStatus::Cancelled
                                    ) {
                                        break current;
                                    }
                                    asupersync::time::sleep(cx.now(), StdDuration::from_millis(1))
                                        .await;
                                };
                                assert_eq!(rejected_task.base().status, FinalTaskStatus::Failed);
                                assert_eq!(supervisor.initial.load(Ordering::SeqCst), 1);
                                assert_eq!(supervisor.resumed.load(Ordering::SeqCst), 1);
                                assert!(
                                    !serde_json::to_string(&rejected_task)
                                        .unwrap()
                                        .contains(RESULT_CANARY)
                                );
                            }),
                        )
                        .await
                        .expect("bounded secured HTTP Task scenario");
                    }
                    assert!(!runtime.is_task_service_ready());
                })
                .unwrap();
            asupersync::time::timeout(cx.now(), StdDuration::from_secs(10), task.join(&cx))
                .await
                .expect("bounded caller-owned Task scenario")
                .unwrap();
        });
}
