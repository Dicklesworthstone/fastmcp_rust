//! A public machine provider behind a separately authenticated secured gateway.
//! Metadata discovery, client_credentials acquisition, catalog, same-token
//! discovery and each upstream continuation use actual native TLS. The upstream
//! MCP responses come from the real secured endpoint and retained router; only
//! the local issuer's metadata and token response are fixture values.
//! The downstream HTTP endpoint is invoked in process, not through a listener.

use super::managed_provider::downstream::{
    ALICE, BOB, Gateway, RESTRICTED, assert_challenge, assert_refused, parameters, retry_parameters,
};
use super::*;
use fastmcp_client::http_auth::discovery::TrustedOAuthIssuer;
use fastmcp_client::http_auth::discovery::client_credentials::rpc::catalog::ClientCredentialsCatalogLimits;
use fastmcp_client::http_auth::discovery::client_credentials::subscriptions::ClientCredentialsCoreSubscriptionLimits;
use fastmcp_client::http_auth::discovery::client_credentials::{
    CLIENT_CREDENTIALS_EXTENSION, ClientCredentialsPlan,
};
use fastmcp_server::providers::ClientCredentialsProvider;
use fastmcp_server::providers::managed_oauth::interaction::{
    ManagedOAuthInputCapabilities, ManagedOAuthInputHandler, ManagedOAuthInputPolicy,
};

const BASIC: &str = "Basic c2VydmljZS1jbGllbnQ6c2VydmljZS1zZWNyZXQ=";

#[derive(Clone, Copy, Debug)]
pub(super) enum Case {
    Complete,
    Rebinding,
    CapabilityDrift,
    Unadvertised,
    PolicyDenied,
    CloseOwner,
    ConflictingModes,
}

fn machine_plan(peer: &Peer) -> ClientCredentialsPlan {
    let root = Certificate::from_pem(ROOT).unwrap().remove(0);
    let issuer = TrustedOAuthIssuer::new(format!(
        "https://{}/issuer",
        peer.listener.local_addr().unwrap()
    ))
    .unwrap()
    .with_root_certificate(root.clone())
    .unwrap();
    ClientCredentialsPlan::new(
        peer.resource(),
        issuer,
        "service-client",
        "service-secret",
        vec!["tools:call".to_owned()],
    )
    .unwrap()
    .with_resource_root_certificate(root)
    .unwrap()
    .with_timeout(Duration::from_secs(10))
    .unwrap()
}

async fn json_reply(socket: &mut TlsStream<TcpStream>, value: Value) {
    write_reply(
        socket,
        200,
        &std::collections::HashMap::from([(
            "content-type".to_owned(),
            "application/json".to_owned(),
        )]),
        &serde_json::to_vec(&value).unwrap(),
        Delivery::Complete,
    )
    .await;
}

async fn metadata(peer: &Peer) {
    let origin = format!("https://{}", peer.listener.local_addr().unwrap());
    let issuer = format!("{origin}/issuer");
    let (mut socket, start, headers, body) = peer.receive().await;
    assert_eq!(
        start,
        "GET /.well-known/oauth-protected-resource/mcp HTTP/1.1"
    );
    assert!(body.is_empty() && !headers.contains_key("authorization"));
    json_reply(
        &mut socket,
        json!({
            "resource":peer.resource().as_str(),"authorization_servers":[issuer],
            "scopes_supported":["tools:call"]
        }),
    )
    .await;
    drop(socket);
    let (mut socket, start, headers, body) = peer.receive().await;
    assert_eq!(
        start,
        "GET /.well-known/oauth-authorization-server/issuer HTTP/1.1"
    );
    assert!(body.is_empty() && !headers.contains_key("authorization"));
    // This machine issuer deliberately has no browser, DCR, authorization code
    // endpoint or refresh token: the public machine plan must own this flow.
    json_reply(
        &mut socket,
        json!({
            "issuer":issuer,"token_endpoint":format!("{origin}/token"),
            "grant_types_supported":["client_credentials"],
            "token_endpoint_auth_methods_supported":["client_secret_basic"],
            "scopes_supported":["tools:call"]
        }),
    )
    .await;
}

async fn grant(peer: &Peer) {
    let (mut socket, start, headers, body) = peer.receive().await;
    assert_eq!(start, "POST /token HTTP/1.1");
    assert_eq!(headers["authorization"], BASIC);
    assert_eq!(headers["content-type"], "application/x-www-form-urlencoded");
    let fields = form(std::str::from_utf8(&body).unwrap());
    assert_eq!(fields["grant_type"], "client_credentials");
    assert_eq!(fields["resource"], peer.resource().as_str());
    assert_eq!(fields["scope"], "tools:call");
    assert_eq!(
        fields.len(),
        3,
        "credentials stay in the selected Basic header"
    );
    peer.grants.fetch_add(1, Ordering::SeqCst);
    json_reply(
        &mut socket,
        json!({
            "access_token":peer.token,"token_type":"Bearer","expires_in":300,
            "scope":"tools:call"
        }),
    )
    .await;
}

async fn exchange(peer: &Peer, cx: &Cx) -> Value {
    let discovery = peer.dispatch(cx, Delivery::Complete).await;
    assert!(discovery.get("error").is_none(), "{discovery}");
    assert_eq!(discovery["result"]["resultType"], "complete");
    assert!(
        discovery["result"]["supportedVersions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|version| version == FINAL_PROTOCOL_VERSION)
    );
    peer.dispatch(cx, Delivery::Complete).await
}

struct NoInput;
impl ManagedOAuthInputHandler for NoInput {
    fn resolve<'a>(
        &'a self,
        _: &'a McpContext,
        _: &'a Cx,
        _: Box<InputRequiredResult>,
    ) -> BoxFuture<'a, McpResult<Option<FinalInputResponses>>> {
        panic!("conflicting mode reached a host callback")
    }
}

async fn conflicts(cx: &Cx, peer: &Peer, provider: ClientCredentialsProvider) {
    let allowed = ManagedOAuthInputCapabilities {
        roots: true,
        ..Default::default()
    };
    let policy = ManagedOAuthInputPolicy::new(allowed, 1, 2).unwrap();
    assert!(
        provider
            .clone()
            .with_input_handler(policy, Arc::new(NoInput))
            .with_downstream_inputs(allowed)
            .is_err()
    );
    let downstream = provider.clone().with_downstream_inputs(allowed).unwrap();
    let invalid = downstream
        .clone()
        .with_input_handler(policy, Arc::new(NoInput));
    let expected = invalid.validate_input_mode().unwrap_err().message;
    for error in [
        invalid.tools(cx).await.err().unwrap(),
        invalid.resources(cx).await.err().unwrap(),
        invalid.prompts(cx).await.err().unwrap(),
        invalid.resource_templates(cx).await.err().unwrap(),
        invalid
            .open_resource_updates(
                cx,
                &McpRequestCancellation::new(),
                &[],
                ClientCredentialsCoreSubscriptionLimits::default(),
            )
            .await
            .err()
            .unwrap(),
    ] {
        assert_eq!(error.message, expected);
    }
    assert!(provider.validate_input_mode().is_ok());
    assert!(downstream.validate_input_mode().is_ok());
    assert_eq!(peer.grants.load(Ordering::SeqCst), 0);
    assert!(peer.seen.lock().unwrap().is_empty());
    peer.quiet();
}

fn assert_custody(peer: &Peer, roots: bool, operations: &[&str]) {
    let seen = peer.seen.lock().unwrap();
    assert_eq!(seen.len(), operations.len() * 2);
    let mut ids = std::collections::HashSet::new();
    for (index, operation) in operations.iter().enumerate() {
        let discovery = &seen[index * 2];
        let execution = &seen[index * 2 + 1];
        assert_eq!(discovery["method"], "server/discover");
        assert_eq!(execution["method"], *operation);
        let mut expected = json!({"extensions":{CLIENT_CREDENTIALS_EXTENSION:{}}});
        if roots && *operation == "tools/call" {
            expected["roots"] = json!({});
        }
        for request in [discovery, execution] {
            assert!(
                ids.insert(request["id"].to_string()),
                "every leg owns a fresh ID"
            );
            assert_eq!(
                request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
                expected
            );
            assert!(
                request["params"]["_meta"]
                    .get("io.modelcontextprotocol/clientInfo")
                    .is_none()
            );
            let wire = request.to_string();
            for private in [
                ALICE,
                BOB,
                RESTRICTED,
                "service-secret",
                "DOWNSTREAM-CLIENT-IDENTITY",
                "DOWNSTREAM-PRIVATE-METADATA",
                "com.example/downstream-owned",
            ] {
                assert!(!wire.contains(private));
            }
        }
        if *operation == "tools/call" {
            assert_eq!(execution["params"]["name"], "checkout");
            assert_eq!(execution["params"]["arguments"], parameters(7)["arguments"]);
        }
    }
}

pub(super) async fn scenario(cx: Cx, case: Case) {
    let peer = Peer::new(&cx, false).await;
    let plan = machine_plan(&peer);
    let ((), client) = pair(metadata(&peer), plan.discover(&cx)).await;
    let client = client.unwrap();
    let provider = ClientCredentialsProvider::new(client.clone())
        .with_namespace("remote")
        .unwrap();
    if matches!(case, Case::ConflictingModes) {
        conflicts(&cx, &peer, provider).await;
        client.close();
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
            ClientCredentialsCatalogLimits::default(),
        );
    let (catalog, tools) = pair(
        async {
            grant(&peer).await;
            exchange(&peer, &cx).await
        },
        provider.tools(&cx),
    )
    .await;
    assert!(catalog.get("error").is_none(), "{catalog}");
    let tool = tools
        .unwrap()
        .into_iter()
        .find(|tool| tool.catalog_definition().name == "remote/checkout")
        .unwrap();
    assert!(tool.declares_final_mrtr());
    let gateway = Gateway::new(tool);
    let advertised = !matches!(case, Case::Unadvertised);
    let (upstream, downstream) = pair(
        exchange(&peer, &cx),
        gateway.send(&cx, 100, ALICE, "tools/call", parameters(7), advertised),
    )
    .await;
    if matches!(case, Case::Unadvertised | Case::PolicyDenied) {
        assert_eq!(
            downstream["result"]["resultType"], "complete",
            "{downstream}"
        );
        assert_eq!(downstream["result"]["isError"], true);
        assert_eq!(
            downstream["result"]["content"][0]["text"],
            "Authenticated upstream input is not permitted"
        );
        assert!(downstream["result"].get("requestState").is_none());
        assert!(!downstream.to_string().contains(&peer.token));
        assert_eq!(peer.probe.effects.load(Ordering::SeqCst), 0);
        assert_custody(&peer, false, &["tools/list", "tools/call"]);
        assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
        peer.quiet();
        client.close();
        peer.journal.close().unwrap();
        return;
    }
    assert_challenge(&upstream, &downstream);
    assert!(!downstream.to_string().contains(&peer.token));
    let state = downstream["result"]["requestState"].clone();
    let upstream_state = upstream["result"]["requestState"].clone();
    if matches!(case, Case::CapabilityDrift | Case::CloseOwner) {
        if matches!(case, Case::CloseOwner) {
            client.close();
        }
        let refused = gateway
            .send(
                &cx,
                101,
                ALICE,
                "tools/call",
                retry_parameters(7, &state),
                matches!(case, Case::CloseOwner),
            )
            .await;
        assert_eq!(refused["result"]["resultType"], "complete", "{refused}");
        assert_eq!(refused["result"]["isError"], true);
        assert_eq!(
            refused["result"]["content"][0]["text"],
            if matches!(case, Case::CloseOwner) {
                "Machine-authenticated upstream request failed"
            } else {
                "Managed OAuth continuation is invalid or no longer authorized"
            }
        );
        assert!(refused["result"].get("requestState").is_none());
        assert!(
            !refused
                .to_string()
                .contains(upstream_state.as_str().unwrap())
        );
        assert_eq!(peer.probe.effects.load(Ordering::SeqCst), 0);
        assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
        assert_custody(&peer, true, &["tools/list", "tools/call"]);
        peer.quiet();
        client.close();
        peer.journal.close().unwrap();
        return;
    }
    if matches!(case, Case::Rebinding) {
        for (id, token, quantity) in [(110, ALICE, 99), (111, BOB, 7), (112, RESTRICTED, 7)] {
            let refused = gateway
                .send(
                    &cx,
                    id,
                    token,
                    "tools/call",
                    retry_parameters(quantity, &state),
                    true,
                )
                .await;
            assert_refused(&refused, &upstream_state, &peer);
        }
        assert_eq!(peer.seen.lock().unwrap().len(), 4);
    }
    let retry = retry_parameters(7, &state);
    let (complete_upstream, complete_downstream) = pair(
        exchange(&peer, &cx),
        gateway.send(&cx, 120, ALICE, "tools/call", retry.clone(), true),
    )
    .await;
    assert!(
        complete_downstream.get("error").is_none(),
        "{complete_downstream}"
    );
    assert_eq!(complete_downstream["result"]["resultType"], "complete");
    assert_eq!(
        complete_downstream["result"]["structuredContent"],
        complete_upstream["result"]["structuredContent"]
    );
    assert_eq!(
        complete_downstream["result"]["structuredContent"]["quantity"],
        7
    );
    assert_eq!(
        complete_downstream["result"]["structuredContent"]["left"]["roots"][0]["uri"],
        "file:///left/approved"
    );
    assert_eq!(
        complete_downstream["result"]["structuredContent"]["right"]["roots"][0]["uri"],
        "file:///right/approved"
    );
    assert_eq!(peer.probe.effects.load(Ordering::SeqCst), 1);
    let replay = gateway
        .send(&cx, 121, ALICE, "tools/call", retry, true)
        .await;
    assert_refused(&replay, &upstream_state, &peer);
    assert_custody(&peer, true, &["tools/list", "tools/call", "tools/call"]);
    let seen = peer.seen.lock().unwrap();
    assert!(seen[3]["params"].get("requestState").is_none());
    assert!(seen[3]["params"].get("inputResponses").is_none());
    assert_eq!(seen[5]["params"]["requestState"], upstream_state);
    assert_eq!(
        seen[5]["params"]["inputResponses"],
        retry_parameters(7, &state)["inputResponses"]
    );
    drop(seen);
    assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
    assert_eq!(peer.probe.effects.load(Ordering::SeqCst), 1);
    peer.quiet();
    client.close();
    peer.journal.close().unwrap();
}

#[test]
fn machine_gateway_downstream_inputs_complete_once_over_native_tls() {
    isolated(
        "machine_provider::machine_gateway_downstream_inputs_complete_once_over_native_tls",
        super::Case::MachineProvider(Case::Complete),
    );
}

#[test]
fn machine_gateway_downstream_inputs_reject_argument_principal_and_grant_rebinding() {
    isolated(
        "machine_provider::machine_gateway_downstream_inputs_reject_argument_principal_and_grant_rebinding",
        super::Case::MachineProvider(Case::Rebinding),
    );
}

#[test]
fn machine_gateway_downstream_inputs_reject_capability_drift_before_discovery() {
    isolated(
        "machine_provider::machine_gateway_downstream_inputs_reject_capability_drift_before_discovery",
        super::Case::MachineProvider(Case::CapabilityDrift),
    );
}

#[test]
fn machine_gateway_downstream_inputs_require_client_advertisement() {
    isolated(
        "machine_provider::machine_gateway_downstream_inputs_require_client_advertisement",
        super::Case::MachineProvider(Case::Unadvertised),
    );
}

#[test]
fn machine_gateway_downstream_inputs_require_local_permission() {
    isolated(
        "machine_provider::machine_gateway_downstream_inputs_require_local_permission",
        super::Case::MachineProvider(Case::PolicyDenied),
    );
}

#[test]
fn machine_gateway_closed_owner_refuses_retry_without_grant_or_effect() {
    isolated(
        "machine_provider::machine_gateway_closed_owner_refuses_retry_without_grant_or_effect",
        super::Case::MachineProvider(Case::CloseOwner),
    );
}

#[test]
fn machine_gateway_conflicting_modes_refuse_before_grant_catalog_or_subscription() {
    isolated(
        "machine_provider::machine_gateway_conflicting_modes_refuse_before_grant_catalog_or_subscription",
        super::Case::MachineProvider(Case::ConflictingModes),
    );
}
