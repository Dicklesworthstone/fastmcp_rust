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

struct InputSupervisor;

impl ApplicationTaskSupervisor for InputSupervisor {
    fn resume<'a>(
        &'a self,
        _: &'a Cx,
        handoff: FinalTaskSupervisorHandoff,
    ) -> FinalTaskSupervisorFuture<'a> {
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
                        .auth_provider(TokenAuthProvider::new(verifier))
                        .tool(ScopedTaskTool)
                        .test_http_endpoint("https://service.example")
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
                        .install_task_service(4, Arc::new(InputSupervisor))
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
