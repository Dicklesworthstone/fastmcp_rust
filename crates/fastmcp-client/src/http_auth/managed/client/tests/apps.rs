//! Public managed Apps flows over the parent module's real OAuth/TLS fixture.
use super::*;
use crate::http_auth::managed::client::apps::{
    ManagedMcpAppsError, ManagedMcpAppsLimits, ManagedMcpAppsOutcome,
};
use crate::mcp_apps::{
    McpAppsHostError, McpAppsInMemoryWireViewTransport, McpAppsWireHostConfiguration,
    McpAppsWireHostEffects, mcp_apps_in_memory_wire_pair,
};
use fastmcp_protocol::{
    MCP_APPS_HOST_VIEW_PROTOCOL_VERSION, McpAppsBridgeImplementation,
    McpAppsPinnedHostCapabilities, McpAppsPinnedHostContext, McpAppsRoutedMethod,
};

fn apps_builder(peer: &Peer) -> ClientBuilder {
    peer.client_builder()
        .capabilities(fastmcp_protocol::ClientCapabilities {
            sampling: Some(fastmcp_protocol::SamplingCapability::default()),
            ..fastmcp_protocol::ClientCapabilities::default()
        })
        .mcp_apps(
            fastmcp_protocol::extensions::McpAppsClientSettings::new(vec![
                fastmcp_protocol::MCP_APPS_HTML_MIME_TYPE.into(),
            ])
            .unwrap(),
        )
}

fn configuration() -> McpAppsWireHostConfiguration {
    McpAppsWireHostConfiguration {
        host_info: McpAppsBridgeImplementation {
            name: "managed-host".into(),
            version: "1".into(),
        },
        host_capabilities: McpAppsPinnedHostCapabilities {
            server_tools: Some(Default::default()),
            server_resources: Some(Default::default()),
            ..Default::default()
        },
        host_context: McpAppsPinnedHostContext::default(),
    }
}

fn apps_discovery(tasks: bool) -> Value {
    let mut value = discovery();
    value["capabilities"]["extensions"] = json!({"io.modelcontextprotocol/ui":{}});
    if tasks {
        value["capabilities"]["extensions"]["io.modelcontextprotocol/tasks"] = json!({});
    }
    value
}

async fn initialize_view(cx: &Cx, view: &mut McpAppsInMemoryWireViewTransport) {
    view.send_to_host(
        cx,
        json!({
            "jsonrpc":"2.0", "id":"view-init", "method":"ui/initialize",
            "params":{"appInfo":{"name":"managed-view","version":"1"}, "appCapabilities":{},
                "protocolVersion":MCP_APPS_HOST_VIEW_PROTOCOL_VERSION}
        })
        .to_string(),
    )
    .await
    .unwrap();
    let reply: Value = serde_json::from_str(&view.receive_from_host(cx).await.unwrap()).unwrap();
    assert_eq!(reply["id"], "view-init");
    assert_eq!(
        reply["result"]["hostCapabilities"]["serverTools"],
        json!({})
    );
    view.send_to_host(
        cx,
        json!({
            "jsonrpc":"2.0", "method":"ui/notifications/initialized"
        })
        .to_string(),
    )
    .await
    .unwrap();
}

async fn send_tool(cx: &Cx, view: &mut McpAppsInMemoryWireViewTransport) {
    view.send_to_host(
        cx,
        json!({
            "jsonrpc":"2.0", "id":"private-view-call", "method":"tools/call",
            "params":{"name":"lookup","arguments":{"subject":7}}
        })
        .to_string(),
    )
    .await
    .unwrap();
}

async fn receive_tool(cx: &Cx, view: &mut McpAppsInMemoryWireViewTransport) {
    let raw = view.receive_from_host(cx).await.unwrap();
    let reply: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(reply["id"], "private-view-call");
    assert_eq!(reply["result"]["content"][0]["text"], "done");
    assert!(reply["result"].get("resultType").is_none());
    for private in [
        "access-one",
        "access-two",
        "refresh-one",
        "private-task",
        "private-round",
    ] {
        assert!(!raw.contains(private));
    }
}

fn input_request() -> Value {
    json!({"resultType":"input_required","requestState":"private-round",
    "inputRequests":{"sample":{"method":"sampling/createMessage","params":{
        "messages":[{"role":"user","content":{"type":"text","text":"Approve this input"}}],
        "maxTokens":32
    }}}})
}

fn input_answer() -> fastmcp_protocol::FinalInputResponses {
    serde_json::from_value(json!({"sample":{
        "role":"assistant","model":"approved-host-model",
        "content":{"type":"text","text":"approved"},"stopReason":"endTurn"
    }}))
    .unwrap()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CloseAt {
    Never,
    Construction,
    Poll,
    Drop,
}

struct Effects {
    session: ManagedOAuthSession,
    close_at: CloseAt,
    calls: Arc<AtomicUsize>,
    polls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    #[cfg(feature = "tasks")]
    task_policies: Arc<AtomicUsize>,
}

struct Answer {
    session: ManagedOAuthSession,
    close_at: CloseAt,
    polls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

impl Future for Answer {
    type Output = Result<fastmcp_protocol::FinalInputResponses, McpAppsHostError>;
    fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        if self.close_at == CloseAt::Poll {
            self.session.close();
        }
        Poll::Ready(Ok(input_answer()))
    }
}
impl Drop for Answer {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
        if self.close_at == CloseAt::Drop {
            self.session.close();
        }
    }
}

#[allow(
    clippy::unused_async_trait_impl,
    clippy::manual_async_fn,
    reason = "constructor/poll/drop authority changes must remain distinct test effects"
)]
impl McpAppsWireHostEffects for Effects {
    fn resolve_server_input(
        &mut self,
        _: &Cx,
        _: &McpRequestCancellation,
        _: McpAppsRoutedMethod,
        _: &Value,
        _: &fastmcp_protocol::InputRequiredResult,
    ) -> impl Future<Output = Result<fastmcp_protocol::FinalInputResponses, McpAppsHostError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.close_at == CloseAt::Construction {
            self.session.close();
        }
        Answer {
            session: self.session.clone(),
            close_at: self.close_at,
            polls: self.polls.clone(),
            drops: self.drops.clone(),
        }
    }

    #[cfg(feature = "tasks")]
    async fn server_task_policy(
        &mut self,
        _: &Cx,
        _: &McpRequestCancellation,
        _: &Value,
    ) -> Result<Option<crate::mcp_apps::McpAppsServerTaskPolicy>, McpAppsHostError> {
        self.task_policies.fetch_add(1, Ordering::SeqCst);
        Ok(Some(
            crate::mcp_apps::McpAppsServerTaskPolicy::new(Duration::from_millis(10), 4, 64 * 1024)
                .unwrap(),
        ))
    }
    #[cfg(feature = "tasks")]
    async fn approve_server_task(
        &mut self,
        _: &Cx,
        _: &McpRequestCancellation,
        _: &Value,
        _: &crate::FinalTask,
    ) -> Result<(), McpAppsHostError> {
        Ok(())
    }
    async fn approve_view_teardown(&mut self) -> bool {
        true
    }
}

fn effects(session: &ManagedOAuthSession, close_at: CloseAt) -> Effects {
    Effects {
        session: session.clone(),
        close_at,
        calls: Arc::new(AtomicUsize::new(0)),
        polls: Arc::new(AtomicUsize::new(0)),
        drops: Arc::new(AtomicUsize::new(0)),
        #[cfg(feature = "tasks")]
        task_policies: Arc::new(AtomicUsize::new(0)),
    }
}

async fn rpc_reply(peer: &Peer, method: &str, result: Value, sse: bool) -> Value {
    let (mut stream, request, _) = peer.mcp_request(method, "access-one").await;
    assert_ne!(request["id"], json!("private-view-call"));
    let envelope = json!({"jsonrpc":"2.0","id":request["id"],"result":result});
    if sse {
        let body = format!("event: message\ndata: {envelope}\n\n");
        stream.write_all(format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len(),
        ).as_bytes()).await.unwrap();
        stream.write_all(body.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();
    } else {
        reply(&mut stream, 200, envelope).await;
    }
    request
}

#[test]
fn managed_apps_authenticated_json_sse_mrtr_resource_and_teardown() {
    for sse in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = ManagedHttpClient::new(
                session.clone(),
                apps_builder(&peer),
                Duration::from_secs(30),
            )
            .unwrap();
            let effects = effects(&session, CloseAt::Never);
            let calls = effects.calls.clone();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
            let ((result, ()), ()) = Box::pin(pair(
                pair(
                    client.serve_mcp_apps_wire_host(
                        &cx,
                        transport,
                        configuration(),
                        effects,
                        ManagedMcpAppsLimits::new(16).unwrap(),
                    ),
                    async {
                        initialize_view(&cx, &mut view).await;
                        send_tool(&cx, &mut view).await;
                        receive_tool(&cx, &mut view).await;
                        view.send_to_host(
                            &cx,
                            json!({
                                "jsonrpc":"2.0","id":"view-resource","method":"resources/read",
                                "params":{"uri":"resource://document"}
                            })
                            .to_string(),
                        )
                        .await
                        .unwrap();
                        let reply: Value =
                            serde_json::from_str(&view.receive_from_host(&cx).await.unwrap())
                                .unwrap();
                        assert_eq!(reply["result"]["contents"][0]["text"], "protected document");
                        view.send_to_host(
                            &cx,
                            json!({
                                "jsonrpc":"2.0","method":"ui/notifications/request-teardown"
                            })
                            .to_string(),
                        )
                        .await
                        .unwrap();
                        let teardown: Value =
                            serde_json::from_str(&view.receive_from_host(&cx).await.unwrap())
                                .unwrap();
                        assert_eq!(teardown["method"], "ui/resource-teardown");
                        view.send_to_host(
                            &cx,
                            json!({
                                "jsonrpc":"2.0","id":teardown["id"],"result":{}
                            })
                            .to_string(),
                        )
                        .await
                        .unwrap();
                    },
                ),
                async {
                    peer.mcp("server/discover", "access-one", apps_discovery(false))
                        .await;
                    let first = rpc_reply(&peer, "tools/call", input_request(), sse).await;
                    let second = rpc_reply(&peer, "tools/call", complete(), sse).await;
                    assert_ne!(first["id"], second["id"]);
                    assert_eq!(second["params"]["requestState"], "private-round");
                    assert_eq!(
                        second["params"]["inputResponses"]["sample"]["content"]["text"],
                        "approved"
                    );
                    rpc_reply(
                        &peer,
                        "resources/read",
                        json!({
                            "resultType":"complete", "contents":[{
                                "uri":"resource://document","text":"protected document"
                            }]
                        }),
                        sse,
                    )
                    .await;
                },
            ))
            .await;
            assert_eq!(
                result.unwrap(),
                ManagedMcpAppsOutcome::ViewClosed { processed_turns: 6 }
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(client.cached_credential_generation(), None);
            // The finished View does not retain a reusable connection. A later
            // operation reacquires/re-discovers under the shared live login.
            let (listed, ()) = pair(client.list_tools(&cx, None), async {
                peer.mcp("server/discover", "access-one", apps_discovery(false))
                    .await;
                peer.catalog("access-one", "after-view").await;
            })
            .await;
            assert_catalog(listed.unwrap(), "after-view");
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn managed_apps_callback_construction_poll_and_drop_revocation_prevent_continuation() {
    for close_at in [
        CloseAt::Never,
        CloseAt::Construction,
        CloseAt::Poll,
        CloseAt::Drop,
    ] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = ManagedHttpClient::new(
                session.clone(),
                apps_builder(&peer),
                Duration::from_secs(30),
            )
            .unwrap();
            let effects = effects(&session, close_at);
            let calls = effects.calls.clone();
            let polls = effects.polls.clone();
            let drops = effects.drops.clone();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
            let ((result, ()), ()) = Box::pin(pair(
                pair(
                    client.serve_mcp_apps_wire_host(
                        &cx,
                        transport,
                        configuration(),
                        effects,
                        ManagedMcpAppsLimits::new(3).unwrap(),
                    ),
                    async {
                        initialize_view(&cx, &mut view).await;
                        send_tool(&cx, &mut view).await;
                        if close_at == CloseAt::Never {
                            receive_tool(&cx, &mut view).await;
                        } else {
                            assert!(
                                view.receive_from_host(&cx).await.is_err(),
                                "revoked Host must not disclose even an error frame"
                            );
                        }
                    },
                ),
                async {
                    peer.mcp("server/discover", "access-one", apps_discovery(false))
                        .await;
                    rpc_reply(&peer, "tools/call", input_request(), false).await;
                    if close_at == CloseAt::Never {
                        rpc_reply(&peer, "tools/call", complete(), false).await;
                    }
                },
            ))
            .await;
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                polls.load(Ordering::SeqCst),
                usize::from(close_at != CloseAt::Construction)
            );
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            if close_at == CloseAt::Never {
                assert_eq!(
                    result.unwrap(),
                    ManagedMcpAppsOutcome::TurnLimit { processed_turns: 3 }
                );
            } else {
                assert!(result.is_err());
            }
            assert_eq!(client.cached_credential_generation(), None);
            peer.no_more(&cx).await;
        });
    }
}

#[cfg(feature = "tasks")]
#[test]
fn managed_apps_tasks_require_local_selection_before_host_creation_consent() {
    for enabled in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let client = ManagedHttpClient::new(
                session.clone(),
                apps_builder(&peer),
                Duration::from_secs(30),
            )
            .unwrap();
            let mut client = if enabled { client.with_tasks() } else { client };
            let effects = effects(&session, CloseAt::Never);
            let policies = effects.task_policies.clone();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
            let ((result, ()), ()) = Box::pin(pair(pair(
                client.serve_mcp_apps_wire_host(
                    &cx, transport, configuration(), effects, ManagedMcpAppsLimits::new(3).unwrap(),
                ),
                async {
                    initialize_view(&cx, &mut view).await;
                    send_tool(&cx, &mut view).await;
                    receive_tool(&cx, &mut view).await;
                },
            ), async {
                peer.mcp("server/discover", "access-one", apps_discovery(true)).await;
                let task = |created: bool, completed: bool| {
                    let mut value = json!({
                        "resultType": if created { "task" } else { "complete" },
                        "taskId":"private-task", "status": if completed { "completed" } else { "working" },
                        "createdAt":"2026-07-28T12:00:00.000Z",
                        "lastUpdatedAt":"2026-07-28T12:00:01.000Z",
                        "ttlMs":null, "pollIntervalMs":1
                    });
                    if completed {
                        let mut payload = complete();
                        payload.as_object_mut().unwrap().remove("resultType");
                        value["result"] = payload;
                    }
                    value
                };
                let request = rpc_reply(
                    &peer, "tools/call",
                    if enabled { task(true, false) } else { complete() }, false,
                ).await;
                let advertised = request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]
                    ["extensions"].get("io.modelcontextprotocol/tasks").is_some();
                assert_eq!(advertised, enabled);
                if enabled {
                    let get = rpc_reply(&peer, "tasks/get", task(false, true), false).await;
                    assert_eq!(get["params"]["taskId"], "private-task");
                }
            })).await;
            assert_eq!(
                result.unwrap(),
                ManagedMcpAppsOutcome::TurnLimit { processed_turns: 3 }
            );
            assert_eq!(policies.load(Ordering::SeqCst), usize::from(enabled));
            assert_eq!(client.cached_credential_generation(), None);
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn managed_apps_pending_view_cancellation_and_revocation_retire_only_owned_state() {
    for revoke in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let credential = session.credential(&cx).await.unwrap();
            let cancellation = McpRequestCancellation::new();
            let mut client = ManagedHttpClient::new(
                session.clone(),
                apps_builder(&peer),
                Duration::from_secs(30),
            )
            .unwrap();
            let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
            let ((result, ()), ()) = Box::pin(pair(
                pair(
                    client.serve_mcp_apps_wire_host_with_cancellation(
                        &cx,
                        &cancellation,
                        transport,
                        configuration(),
                        (),
                        ManagedMcpAppsLimits::default(),
                    ),
                    async {
                        initialize_view(&cx, &mut view).await;
                        if revoke {
                            credential.credential().revoke();
                        } else {
                            cancellation.cancel();
                        }
                        assert!(view.receive_from_host(&cx).await.is_err());
                    },
                ),
                peer.mcp("server/discover", "access-one", apps_discovery(false)),
            ))
            .await;
            assert!(result.is_err());
            assert_eq!(client.cached_credential_generation(), None);
            if !revoke {
                let mut sibling = ManagedHttpClient::new(
                    session.clone(),
                    peer.client_builder(),
                    Duration::from_secs(30),
                )
                .unwrap();
                let (listed, ()) = pair(sibling.list_tools(&cx, None), async {
                    peer.discovery("access-one").await;
                    peer.catalog("access-one", "sibling").await;
                })
                .await;
                assert_catalog(listed.unwrap(), "sibling");
            }
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn managed_apps_requires_authenticated_activation_and_finite_local_work() {
    assert!(ManagedMcpAppsLimits::new(0).is_err());
    assert!(ManagedMcpAppsLimits::new(4_097).is_err());
    assert!(ManagedMcpAppsLimits::new(1).is_ok());
    assert!(ManagedMcpAppsLimits::new(4_096).is_ok());
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client =
            ManagedHttpClient::new(session, apps_builder(&peer), Duration::from_secs(30)).unwrap();
        let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
        let (result, ()) = pair(
            client.serve_mcp_apps_wire_host(
                &cx,
                transport,
                configuration(),
                (),
                ManagedMcpAppsLimits::default(),
            ),
            peer.discovery("access-one"),
        )
        .await;
        assert!(matches!(result, Err(ManagedMcpAppsError::NotNegotiated)));
        assert!(view.receive_from_host(&cx).await.is_err());
        assert_eq!(client.cached_credential_generation(), None);
        peer.no_more(&cx).await;
    });
}

#[test]
fn managed_apps_idle_timeout_keeps_the_original_deadline_and_allows_later_renewal() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = ManagedHttpClient::new(
            session.clone(),
            apps_builder(&peer),
            Duration::from_secs(30),
        )
        .unwrap();
        // Finish authenticated discovery before shortening only the operation
        // deadline, so TLS setup latency is not the behavior being measured.
        let (listed, ()) = pair(client.list_tools(&cx, None), async {
            peer.mcp("server/discover", "access-one", apps_discovery(false))
                .await;
            peer.catalog("access-one", "before-view").await;
        })
        .await;
        assert_catalog(listed.unwrap(), "before-view");
        client.operation_timeout = Duration::from_secs(2);
        let (transport, mut view) = mcp_apps_in_memory_wire_pair(8);
        let (result, ()) = Box::pin(pair(
            client.serve_mcp_apps_wire_host(
                &cx,
                transport,
                configuration(),
                (),
                ManagedMcpAppsLimits::default(),
            ),
            async {
                initialize_view(&cx, &mut view).await;
                // The carrier has no further frames. Its pending receive must
                // not bypass the managed session's original deadline.
                assert!(view.receive_from_host(&cx).await.is_err());
            },
        ))
        .await;
        assert!(matches!(
            result,
            Err(ManagedMcpAppsError::Managed(
                ManagedHttpClientError::Session(OAuthSessionError::TimedOut)
            ))
        ));
        assert_eq!(client.cached_credential_generation(), None);
        client.operation_timeout = Duration::from_secs(30);
        force_renewal(&session);
        let (listed, ()) = pair(client.list_tools(&cx, None), async {
            peer.token("refresh_token", true).await;
            peer.mcp("server/discover", "access-two", apps_discovery(false))
                .await;
            peer.catalog("access-two", "after-renewal").await;
        })
        .await;
        assert_catalog(listed.unwrap(), "after-renewal");
        assert_eq!(client.cached_credential_generation(), Some(2));
        peer.no_more(&cx).await;
    });
}
