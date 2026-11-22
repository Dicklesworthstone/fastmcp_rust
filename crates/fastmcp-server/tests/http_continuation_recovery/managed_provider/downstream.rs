//! Public managed login/catalog -> separately authenticated secured gateway
//! dispatch -> native upstream MRTR over actual TLS. The downstream endpoint
//! is invoked in process; this is not an external listener/interoperability
//! claim. Parent fixtures own the runtime, trust installation and time bounds.

use super::*;
use fastmcp_client::http_auth::managed::subscriptions::ManagedSubscriptionLimits;
use fastmcp_server::providers::managed_oauth::ManagedOAuthTool;

const ALICE: &str = "GATEWAY-ALICE-CREDENTIAL";
const BOB: &str = "GATEWAY-BOB-CREDENTIAL";
const RESTRICTED: &str = "GATEWAY-ALICE-RESTRICTED";

#[derive(Clone, Copy, Debug)]
pub(crate) enum Case {
    Complete,
    Independent,
    Rebinding,
    CapabilityDrift,
    Unadvertised,
    PolicyDenied,
    ConflictingModes,
}

struct Gateway {
    endpoint: ServerHttpEndpoint,
    policy: HttpSecurityPolicy,
}

impl Gateway {
    fn new(tool: ManagedOAuthTool) -> Self {
        let identity = |name: &str, scope: &str| {
            let mut auth = AuthContext::with_subject(name.to_owned())
                .with_session_owner(fastmcp_core::sha256_bounded(name.as_bytes(), 64).unwrap());
            auth.scopes = vec![scope.to_owned()];
            auth
        };
        let builder = Server::new("managed-gateway", "1")
            .protocol_policy(ProtocolPolicy::ModernOnly)
            .unwrap()
            .auth_provider(TokenAuthProvider::new(
                StaticTokenVerifier::new([
                    (ALICE.to_owned(), identity("gateway-alice", "tools:call")),
                    (BOB.to_owned(), identity("gateway-bob", "tools:call")),
                    (
                        RESTRICTED.to_owned(),
                        identity("gateway-alice", "tools:read"),
                    ),
                ])
                .unwrap(),
            ))
            .tool(tool);
        #[cfg(feature = "legacy-2024-11-05")]
        let endpoint = builder
            .build_http_endpoint("http://gateway.example")
            .unwrap();
        #[cfg(not(feature = "legacy-2024-11-05"))]
        let endpoint = builder.build_http_endpoint().unwrap();
        Self {
            endpoint,
            policy: HttpSecurityPolicy::new(
                HttpEndpointConfig::new("/mcp", HttpAdmissionLimits::new(32, 8192, 65536).unwrap())
                    .unwrap(),
                "https://gateway.example",
                vec![],
            )
            .unwrap(),
        }
    }

    async fn send(
        &self,
        cx: &Cx,
        id: i64,
        token: &str,
        method: &str,
        mut params: Value,
        roots: bool,
    ) -> Value {
        let mut capabilities = json!({
            "extensions":{"com.example/downstream-owned":{}}
        });
        if roots {
            capabilities["roots"] = json!({"listChanged":true});
        }
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion":FINAL_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities":capabilities,
            "io.modelcontextprotocol/clientInfo":{"name":"DOWNSTREAM-CLIENT-IDENTITY","version":"1"},
            "com.example/private":"DOWNSTREAM-PRIVATE-METADATA"
        });
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("remote/checkout")
            .to_owned();
        let body = serde_json::to_vec(&json!({
            "jsonrpc":"2.0","id":id,"method":method,"params":params
        }))
        .unwrap();
        let request = HttpRequest::new(HttpMethod::Post, "/mcp")
            .with_header("Host", "gateway.example")
            .with_header("Content-Type", "application/json")
            .with_header("Accept", "application/json")
            .with_header("Authorization", format!("Bearer {token}"))
            .with_header("Mcp-Protocol-Version", FINAL_PROTOCOL_VERSION)
            .with_header("Mcp-Method", method)
            .with_header("Mcp-Name", name)
            .with_body(body);
        let reply = Box::pin(
            self.endpoint
                .handle_secured_async(cx, &self.policy, request),
        )
        .await
        .unwrap();
        assert!(!reply.is_streaming());
        let (response, stream) = reply.into_parts();
        assert!(stream.is_none());
        serde_json::from_slice(&response.body).unwrap()
    }
}

fn parameters(quantity: u64) -> Value {
    json!({
        "name":"remote/checkout",
        "arguments":{"quantity":quantity,"_meta":{"application-data":"kept"}}
    })
}

fn retry_parameters(quantity: u64, state: &Value) -> Value {
    let mut params = parameters(quantity);
    params["requestState"] = state.clone();
    params["inputResponses"] = json!({
        "left":{"roots":[{"uri":"file:///left/approved"}]},
        "right":{"roots":[{"uri":"file:///right/approved"}]}
    });
    params
}

fn assert_challenge(upstream: &Value, downstream: &Value) {
    assert!(upstream.get("error").is_none(), "{upstream}");
    assert!(downstream.get("error").is_none(), "{downstream}");
    assert_eq!(upstream["result"]["resultType"], "input_required");
    assert_eq!(downstream["result"]["resultType"], "input_required");
    let upstream_state = upstream["result"]["requestState"].as_str().unwrap();
    let downstream_state = downstream["result"]["requestState"].as_str().unwrap();
    assert!(!upstream_state.is_empty() && !downstream_state.is_empty());
    assert_ne!(upstream_state, downstream_state);
    assert_eq!(
        upstream["result"]["inputRequests"],
        downstream["result"]["inputRequests"]
    );
    let downstream = downstream.to_string();
    for private in [
        upstream_state,
        "handler-private-state",
        "fastmcp.managed-oauth.mrtr/v1",
        ALICE,
        BOB,
        RESTRICTED,
    ] {
        assert!(!downstream.contains(private));
    }
}

fn assert_refused(reply: &Value, upstream_state: &Value, peer: &Peer) {
    assert!(reply.get("error").is_some(), "{reply}");
    let diagnostic = reply.to_string();
    assert!(!diagnostic.contains(&peer.token));
    assert!(!diagnostic.contains(upstream_state.as_str().unwrap()));
    assert!(!diagnostic.contains("fastmcp.managed-oauth.mrtr/v1"));
    assert!(!diagnostic.contains("handler-private-state"));
    for credential in [ALICE, BOB, RESTRICTED] {
        assert!(!diagnostic.contains(credential));
    }
    peer.quiet();
}

async fn conflicts(cx: &Cx, peer: &Peer, provider: ManagedOAuthProvider) {
    let host = Arc::new(Host {
        case: super::Case::Complete,
        calls: AtomicUsize::new(0),
        answers: AtomicUsize::new(0),
    });
    let capabilities = ManagedOAuthInputCapabilities {
        roots: true,
        ..Default::default()
    };
    let policy = ManagedOAuthInputPolicy::new(capabilities, 1, 2).unwrap();
    assert!(
        provider
            .clone()
            .with_input_handler(policy, host.clone())
            .with_downstream_inputs(capabilities)
            .is_err()
    );
    let opted_in = provider
        .clone()
        .with_downstream_inputs(capabilities)
        .unwrap();
    let invalid = opted_in.clone().with_input_handler(policy, host.clone());
    let mode_error = invalid.validate_input_mode().unwrap_err().message;
    // Every public acquisition path shares the same refusal before a token
    // renewal, TLS connection, catalog review or host callback can begin.
    assert!(invalid.tools(cx).await.is_err());
    assert!(invalid.resources(cx).await.is_err());
    assert!(invalid.prompts(cx).await.is_err());
    assert!(invalid.resource_templates(cx).await.is_err());
    assert!(
        invalid
            .tools_with_header_review(cx, |_, _| panic!("invalid mode reached review"))
            .await
            .is_err()
    );
    let update_error = invalid
        .open_resource_updates(
            cx,
            &McpRequestCancellation::new(),
            &[],
            ManagedSubscriptionLimits::default(),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(update_error.message, mode_error);
    assert!(provider.validate_input_mode().is_ok());
    assert!(opted_in.validate_input_mode().is_ok());
    assert_eq!(host.calls.load(Ordering::SeqCst), 0);
    assert!(peer.seen.lock().unwrap().is_empty());
    assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
    peer.quiet();
}

pub(super) async fn scenario(cx: Cx, case: Case) {
    let peer = Peer::new(&cx, true).await;
    let ((), session) = pair(
        peer.login(),
        ManagedOAuthSession::authorize(&cx, peer.client(), OAuthSessionPolicy::default(), browser),
    )
    .await;
    let session = session.unwrap();
    let provider = ManagedOAuthProvider::new(session.clone())
        .with_namespace("remote")
        .unwrap();
    if matches!(case, Case::ConflictingModes) {
        conflicts(&cx, &peer, provider).await;
        session.close();
        peer.journal.close().unwrap();
        return;
    }
    let provider = provider
        .with_downstream_inputs(ManagedOAuthInputCapabilities {
            roots: !matches!(case, Case::PolicyDenied),
            ..Default::default()
        })
        .unwrap()
        .with_limits(
            ManagedCoreLimits::new(4096, 4096, 65536, 0, Duration::from_secs(10)).unwrap(),
            ManagedCatalogLimits::default(),
        );
    // Even an empty reviewed-header policy installs a different native backend.
    // Its wrapper must retain the selected input mode and capability allowlist.
    let (catalog, tools) = pair(
        peer.dispatch(&cx, Delivery::Complete),
        provider.tools_with_header_review(&cx, |_, _| true),
    )
    .await;
    assert!(catalog.get("error").is_none());
    let tool = tools
        .unwrap()
        .into_iter()
        .find(|tool| tool.catalog_definition().name == "remote/checkout")
        .unwrap();
    assert!(tool.declares_final_mrtr());
    let gateway = Gateway::new(tool);
    let roots = !matches!(case, Case::Unadvertised);
    let (upstream, downstream) = pair(
        peer.dispatch(&cx, Delivery::Complete),
        gateway.send(&cx, 100, ALICE, "tools/call", parameters(7), roots),
    )
    .await;

    if matches!(case, Case::Unadvertised | Case::PolicyDenied) {
        assert!(downstream.get("error").is_some(), "{downstream}");
        assert_eq!(peer.probe.effects.load(Ordering::SeqCst), 0);
        let seen = peer.seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(
            seen[1]["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
            json!({})
        );
        drop(seen);
        assert!(!downstream.to_string().contains(&peer.token));
        peer.quiet();
        session.close();
        peer.journal.close().unwrap();
        return;
    }
    assert_challenge(&upstream, &downstream);
    let state = downstream["result"]["requestState"].clone();
    let upstream_state = upstream["result"]["requestState"].clone();

    if matches!(case, Case::CapabilityDrift) {
        let reply = gateway
            .send(
                &cx,
                101,
                ALICE,
                "tools/call",
                retry_parameters(7, &state),
                false,
            )
            .await;
        assert_refused(&reply, &upstream_state, &peer);
        assert_eq!(peer.seen.lock().unwrap().len(), 2);
        assert_eq!(peer.probe.effects.load(Ordering::SeqCst), 0);
        session.close();
        peer.journal.close().unwrap();
        return;
    }

    if matches!(case, Case::Rebinding) {
        // All failures precede the provider hook. They must neither contact
        // the upstream nor consume the correctly bound downstream state.
        let wrong_args = gateway
            .send(
                &cx,
                110,
                ALICE,
                "tools/call",
                retry_parameters(99, &state),
                true,
            )
            .await;
        assert_refused(&wrong_args, &upstream_state, &peer);
        let mut wrong_target = retry_parameters(7, &state);
        wrong_target["name"] = json!("remote/missing");
        let wrong_target = gateway
            .send(&cx, 111, ALICE, "tools/call", wrong_target, true)
            .await;
        assert_refused(&wrong_target, &upstream_state, &peer);
        let wrong_method = gateway
            .send(
                &cx,
                112,
                ALICE,
                "prompts/get",
                json!({
                    "name":"remote/checkout","arguments":{},"requestState":state,
                    "inputResponses":{"left":{"roots":[]},"right":{"roots":[]}}
                }),
                true,
            )
            .await;
        assert_refused(&wrong_method, &upstream_state, &peer);
        let foreign = gateway
            .send(
                &cx,
                113,
                BOB,
                "tools/call",
                retry_parameters(7, &state),
                true,
            )
            .await;
        assert_refused(&foreign, &upstream_state, &peer);
        let changed_grants = gateway
            .send(
                &cx,
                114,
                RESTRICTED,
                "tools/call",
                retry_parameters(7, &state),
                true,
            )
            .await;
        assert_refused(&changed_grants, &upstream_state, &peer);
        assert_eq!(peer.seen.lock().unwrap().len(), 2);
    }

    let mut second_upstream_state = None;
    if matches!(case, Case::Independent) {
        let (upstream_second, downstream_second) = pair(
            peer.dispatch(&cx, Delivery::Complete),
            gateway.send(&cx, 120, ALICE, "tools/call", parameters(9), true),
        )
        .await;
        assert_challenge(&upstream_second, &downstream_second);
        assert_ne!(state, downstream_second["result"]["requestState"]);
        let (completed_upstream, completed_downstream) = pair(
            peer.dispatch(&cx, Delivery::Complete),
            gateway.send(
                &cx,
                121,
                ALICE,
                "tools/call",
                retry_parameters(9, &downstream_second["result"]["requestState"]),
                true,
            ),
        )
        .await;
        assert_eq!(completed_downstream["result"]["resultType"], "complete");
        assert_eq!(
            completed_downstream["result"]["structuredContent"]["quantity"],
            9
        );
        assert_eq!(
            completed_upstream["result"]["structuredContent"],
            completed_downstream["result"]["structuredContent"]
        );
        assert_eq!(peer.probe.effects.load(Ordering::SeqCst), 1);
        second_upstream_state = Some(upstream_second["result"]["requestState"].clone());
    }

    let retry = retry_parameters(7, &state);
    let (completed_upstream, completed_downstream) = pair(
        peer.dispatch(&cx, Delivery::Complete),
        gateway.send(&cx, 130, ALICE, "tools/call", retry.clone(), true),
    )
    .await;
    assert!(
        completed_downstream.get("error").is_none(),
        "{completed_downstream}"
    );
    assert_eq!(completed_downstream["result"]["resultType"], "complete");
    assert_eq!(
        completed_downstream["result"]["structuredContent"]["quantity"],
        7
    );
    assert_eq!(
        completed_upstream["result"]["structuredContent"],
        completed_downstream["result"]["structuredContent"]
    );
    assert_eq!(
        completed_downstream["result"]["structuredContent"]["left"]["roots"][0]["uri"],
        "file:///left/approved"
    );
    assert_eq!(
        completed_downstream["result"]["structuredContent"]["right"]["roots"][0]["uri"],
        "file:///right/approved"
    );
    let effects = if matches!(case, Case::Independent) {
        2
    } else {
        1
    };
    assert_eq!(peer.probe.effects.load(Ordering::SeqCst), effects);
    let replay = gateway
        .send(&cx, 131, ALICE, "tools/call", retry, true)
        .await;
    assert_refused(&replay, &upstream_state, &peer);
    assert_eq!(peer.probe.effects.load(Ordering::SeqCst), effects);

    let seen = peer.seen.lock().unwrap();
    assert_eq!(
        seen.len(),
        if second_upstream_state.is_some() {
            5
        } else {
            3
        }
    );
    assert_eq!(seen[0]["method"], "tools/list");
    assert_eq!(
        seen[0]["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
        json!({})
    );
    assert!(seen[1]["params"].get("requestState").is_none());
    assert!(seen[1]["params"].get("inputResponses").is_none());
    assert_eq!(
        seen.last().unwrap()["params"]["requestState"],
        upstream_state
    );
    assert_eq!(
        seen.last().unwrap()["params"]["arguments"],
        parameters(7)["arguments"]
    );
    if let Some(second_state) = second_upstream_state {
        assert!(seen[2]["params"].get("requestState").is_none());
        assert_eq!(seen[3]["params"]["requestState"], second_state);
        assert_eq!(seen[3]["params"]["arguments"], parameters(9)["arguments"]);
    }
    for request in seen.iter().skip(1) {
        assert_eq!(request["params"]["name"], "checkout");
        assert_eq!(
            request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
            json!({"roots":{}})
        );
        assert!(
            request["params"]["_meta"]
                .get("io.modelcontextprotocol/clientInfo")
                .is_none()
        );
        assert!(
            request["params"]["_meta"]
                .get("com.example/private")
                .is_none()
        );
        let wire = request.to_string();
        for private in [
            ALICE,
            BOB,
            RESTRICTED,
            "DOWNSTREAM-CLIENT-IDENTITY",
            "DOWNSTREAM-PRIVATE-METADATA",
            "com.example/downstream-owned",
        ] {
            assert!(!wire.contains(private));
        }
    }
    drop(seen);
    peer.quiet();
    assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
    assert!(!cx.is_cancel_requested());
    session.close();
    peer.journal.close().unwrap();
}

#[test]
fn public_gateway_downstream_inputs_complete_once_through_real_managed_tls() {
    isolated(
        "managed_provider::downstream::public_gateway_downstream_inputs_complete_once_through_real_managed_tls",
        super::super::Case::Provider(super::Case::Downstream(Case::Complete)),
    );
}

#[test]
fn public_gateway_downstream_inputs_resume_independent_calls_in_reverse_order() {
    isolated(
        "managed_provider::downstream::public_gateway_downstream_inputs_resume_independent_calls_in_reverse_order",
        super::super::Case::Provider(super::Case::Downstream(Case::Independent)),
    );
}

#[test]
fn public_gateway_downstream_inputs_reject_changed_operation_principal_and_grants() {
    isolated(
        "managed_provider::downstream::public_gateway_downstream_inputs_reject_changed_operation_principal_and_grants",
        super::super::Case::Provider(super::Case::Downstream(Case::Rebinding)),
    );
}

#[test]
fn public_gateway_downstream_inputs_reject_capability_drift_before_upstream_post() {
    isolated(
        "managed_provider::downstream::public_gateway_downstream_inputs_reject_capability_drift_before_upstream_post",
        super::super::Case::Provider(super::Case::Downstream(Case::CapabilityDrift)),
    );
}

#[test]
fn public_gateway_downstream_inputs_require_client_advertisement() {
    isolated(
        "managed_provider::downstream::public_gateway_downstream_inputs_require_client_advertisement",
        super::super::Case::Provider(super::Case::Downstream(Case::Unadvertised)),
    );
}

#[test]
fn public_gateway_downstream_inputs_require_local_permission() {
    isolated(
        "managed_provider::downstream::public_gateway_downstream_inputs_require_local_permission",
        super::super::Case::Provider(super::Case::Downstream(Case::PolicyDenied)),
    );
}

#[test]
fn public_gateway_downstream_and_host_modes_conflict_before_catalog_or_network() {
    isolated(
        "managed_provider::downstream::public_gateway_downstream_and_host_modes_conflict_before_catalog_or_network",
        super::super::Case::Provider(super::Case::Downstream(Case::ConflictingModes)),
    );
}
