//! Public managed OAuth typed-extension gateways against a native TLS peer.
//! Both MCP legs use secured endpoints and real extension admission. The
//! downstream endpoint runs in process; this is not an external-provider or
//! external gateway-listener interoperability claim. The parent owns the
//! isolated trust file, runtime, process bound and OAuth authorization fixture.

use super::*;
use fastmcp_client::{ClientBuilder, ClientProtocolPlan};
use fastmcp_core::McpErrorCode;
use fastmcp_derive::JsonSchema;
use fastmcp_protocol::JsonRpcRequest;
use fastmcp_server::MiddlewareDecision;
use fastmcp_server::extensions::authoring::{
    ExtensionBuilder, ExtensionContext, ExtensionHttpUpstream, ExtensionNotificationContext,
    ExtensionRegistration,
};
use fastmcp_server::http_admission::security::endpoint::{
    SecuredHttpEndpointError, SecuredHttpEndpointResponse,
};
use serde::{Deserialize, Serialize};

const EXTENSION: &str = "com.example/managed-scale";
const METHOD: &str = "com.example/managed-scale-call";
const NOTIFICATION: &str = "com.example/managed-scale-accept";
const ACTIVATION: &str = "com.example/managed-scale-settings";
const NOTICE: &str = "com.example/managed-scale-progress";
const NOTICE_OWNER: &str = "com.example/managed-scale-owner";
const GATEWAY_TOKEN: &str = "DOWNSTREAM-EXTENSION-CREDENTIAL";
const UPSTREAM_IDENTITY: &str = "managed-extension-upstream";

#[derive(Clone, Copy, Debug)]
pub(super) enum Case {
    Request,
    Notification,
    CloseOwner,
    PreCancelled,
    SettingsDrift,
    RequestNotifications,
    RefusedRelay,
}

impl Case {
    fn streaming(self) -> bool {
        matches!(self, Self::RequestNotifications | Self::RefusedRelay)
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ClientSettings {
    version: u32,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ServerSettings {
    version: u32,
    multiplier: u32,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Settings {
    multiplier: u32,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Input {
    value: u32,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Output {
    value: u32,
}

/// The same schema admits both values. Only the gateway's re-encoding of one
/// value tries to synthesize metadata; the upstream emits plain Output data.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Notice {
    value: u32,
}

impl Serialize for Notice {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut object = serializer.serialize_map(Some(if self.value == 39 { 2 } else { 1 }))?;
        object.serialize_entry("value", &self.value)?;
        if self.value == 39 {
            object.serialize_entry("_meta", &json!({"com.example/forged-authority":true}))?;
        }
        object.end()
    }
}

#[derive(Default)]
struct Observed {
    requests: AtomicUsize,
    notifications: AtomicUsize,
    authorized_notifications: AtomicUsize,
    drift: std::sync::atomic::AtomicBool,
}

fn declaration() -> ExtensionBuilder<ClientSettings, ServerSettings, Settings> {
    ExtensionBuilder::new(
        EXTENSION,
        1,
        "managed-scale-client-v1",
        "managed-scale-server-v1",
        ServerSettings {
            version: 1,
            multiplier: 3,
        },
        |client: ClientSettings, server: ServerSettings| {
            if client.version != server.version {
                return Err(McpError::invalid_params("incompatible fixture settings"));
            }
            Ok(Settings {
                multiplier: server.multiplier,
            })
        },
    )
    .unwrap()
}

fn producer(observed: Arc<Observed>, streaming: bool) -> ExtensionRegistration {
    let mut builder = declaration();
    if streaming {
        builder = builder
            .typed_request_notification::<Notice>(NOTICE, "managed-scale-notice-v1", NOTICE_OWNER)
            .unwrap();
    }
    let requests = observed.clone();
    let builder = builder
        .typed_request_sync(
            METHOD,
            "managed-scale-input-v1",
            "managed-scale-output-v1",
            move |context: ExtensionContext<'_, Settings>, input: Input| {
                context.checkpoint()?;
                assert_eq!(context.method(), METHOD);
                requests.requests.fetch_add(1, Ordering::SeqCst);
                let output = Output {
                    value: input.value * context.settings().multiplier,
                };
                if streaming {
                    context.notify(&output)?;
                }
                Ok(output)
            },
        )
        .unwrap();
    if streaming {
        return builder.build().unwrap();
    }
    let authorization = observed.clone();
    builder
        .typed_notification_sync(
            NOTIFICATION,
            "managed-scale-notification-v1",
            ACTIVATION,
            move |_: &Input| {
                authorization
                    .authorized_notifications
                    .fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            move |context: ExtensionNotificationContext<'_, Settings>, _: Input| {
                context.checkpoint()?;
                observed.notifications.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap()
        .build()
        .unwrap()
}

fn forwarded(
    upstream: ExtensionHttpUpstream,
    streaming: bool,
    authorized: Arc<AtomicUsize>,
) -> ExtensionRegistration {
    if streaming {
        return declaration()
            .typed_request_notification::<Notice>(NOTICE, "managed-scale-notice-v1", NOTICE_OWNER)
            .unwrap()
            .typed_http_proxy_request_with_notifications::<Input, Output, Notice>(
                METHOD,
                "managed-scale-input-v1",
                "managed-scale-output-v1",
                upstream,
            )
            .unwrap()
            .build()
            .unwrap();
    }
    declaration()
        .typed_http_proxy_request::<Input, Output>(
            METHOD,
            "managed-scale-input-v1",
            "managed-scale-output-v1",
            upstream.clone(),
        )
        .unwrap()
        .typed_http_proxy_notification(
            NOTIFICATION,
            "managed-scale-notification-v1",
            ACTIVATION,
            move |input: &Input| {
                authorized.fetch_add(1, Ordering::SeqCst);
                if input.value == 17 {
                    return Err(McpError::new(
                        McpErrorCode::ResourceForbidden,
                        "notification denied",
                    ));
                }
                Ok(())
            },
            upstream,
        )
        .unwrap()
        .build()
        .unwrap()
}

struct UpstreamAudit(Arc<Observed>);

impl Middleware for UpstreamAudit {
    fn on_request(
        &self,
        context: &McpContext,
        _: &JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        assert_eq!(
            context.auth().and_then(|auth| auth.subject.as_deref()),
            Some("alice")
        );
        Ok(MiddlewareDecision::Continue)
    }

    fn on_response(
        &self,
        _: &McpContext,
        request: &JsonRpcRequest,
        mut result: Value,
    ) -> McpResult<Value> {
        if request.method == "server/discover" && self.0.drift.load(Ordering::SeqCst) {
            // Change one otherwise valid advertised setting through the native
            // server middleware, after its normal discovery response is built.
            result["capabilities"]["extensions"][EXTENSION]["multiplier"] = json!(5);
        }
        if request.method == METHOD {
            result["_meta"] = json!({"com.example/upstream-only":"UPSTREAM-PRIVATE-METADATA"});
        }
        Ok(result)
    }
}

struct DownstreamAudit;

impl Middleware for DownstreamAudit {
    fn on_request(
        &self,
        context: &McpContext,
        _: &JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        assert_eq!(
            context.auth().and_then(|auth| auth.subject.as_deref()),
            Some("gateway-caller")
        );
        Ok(MiddlewareDecision::Continue)
    }
}

fn client_builder(peer: &Peer) -> ClientBuilder {
    ClientBuilder::new()
        .client_info(UPSTREAM_IDENTITY, "1")
        .protocol_plan(
            ClientProtocolPlan::http(
                ProtocolPolicy::ModernOnly,
                Some(peer.resource()),
                None,
                None,
                "managed-extension-owner".to_owned(),
                "managed-extension-trust".to_owned(),
                "native-http".to_owned(),
                0,
                0,
                0,
            )
            .unwrap(),
        )
        .http_resource_root_certificate(
            peer.resource(),
            Certificate::from_pem(ROOT).unwrap().remove(0),
        )
        .unwrap()
}

#[derive(Debug)]
struct Reply {
    status: u16,
    headers: std::collections::HashMap<String, String>,
    body: Vec<u8>,
    records: Vec<Value>,
    streaming: bool,
}

/// Preserve every native JSON/SSE record. Buffering a bounded finite stream
/// deliberately delivers its notification and terminal in the same TLS reply,
/// so refusing the first cannot accidentally release the already buffered last.
async fn collect(cx: &Cx, reply: SecuredHttpEndpointResponse) -> Reply {
    let streaming = reply.is_streaming();
    let (response, stream) = reply.into_parts();
    let mut body = response.body;
    let mut records = Vec::new();
    if let Some(mut stream) = stream {
        assert!(body.is_empty());
        while let Some(event) = stream.next_event(cx).await.unwrap() {
            assert!(records.len() < 8, "fixture extension stream is bounded");
            records.push(serde_json::from_str(&event.data).unwrap());
            body.extend(event.to_bytes().unwrap());
            assert!(body.len() <= 65_536);
        }
        stream.close(cx).await;
    } else if !body.is_empty() {
        records.push(serde_json::from_slice(&body).unwrap());
    }
    Reply {
        status: response.status.0,
        headers: response.headers,
        body,
        records,
        streaming,
    }
}

async fn dispatch(peer: &Peer, cx: &Cx) -> Reply {
    let (mut socket, start, headers, body) = peer.receive().await;
    assert_eq!(start, "POST /mcp HTTP/1.1");
    assert_eq!(headers["authorization"], format!("Bearer {}", peer.token));
    assert!(!headers.contains_key("mcp-session-id"));
    assert!(!headers.contains_key("last-event-id"));
    let wire: Value = serde_json::from_slice(&body).unwrap();
    peer.seen.lock().unwrap().push(wire);
    let mut request = HttpRequest::new(HttpMethod::Post, "/mcp");
    for (name, value) in headers {
        request = request.with_header(name, value);
    }
    let response = Box::pin(peer.endpoint.handle_secured_async(
        cx,
        &peer.policy,
        request.with_body(body),
    ))
    .await
    .unwrap();
    let reply = collect(cx, response).await;
    // The bridge supplies finite HTTP framing for the collected native body;
    // it does not parse, rewrite, synthesize or discard any MCP event payload.
    let mut headers = reply.headers.clone();
    headers.retain(|name, _| !name.eq_ignore_ascii_case("transfer-encoding"));
    write_reply(
        &mut socket,
        reply.status,
        &headers,
        &reply.body,
        Delivery::Complete,
    )
    .await;
    reply
}

async fn discovery(peer: &Peer, cx: &Cx) -> Reply {
    let reply = dispatch(peer, cx).await;
    assert_eq!(reply.status, 200);
    assert!(!reply.streaming);
    assert_eq!(reply.records.len(), 1);
    assert!(
        reply.records[0].get("error").is_none(),
        "{:?}",
        reply.records
    );
    assert_eq!(
        peer.seen.lock().unwrap().last().unwrap()["method"],
        "server/discover"
    );
    reply
}

async fn exchange(peer: &Peer, cx: &Cx) -> Reply {
    discovery(peer, cx).await;
    dispatch(peer, cx).await
}

struct Gateway {
    endpoint: ServerHttpEndpoint,
    policy: HttpSecurityPolicy,
}

impl Gateway {
    fn new(registration: ExtensionRegistration) -> Self {
        let auth = AuthContext::with_subject("gateway-caller".to_owned())
            .with_session_owner(fastmcp_core::sha256_bounded(b"gateway-caller", 64).unwrap());
        let builder = Server::new("managed-extension-gateway", "1")
            .protocol_policy(ProtocolPolicy::ModernOnly)
            .unwrap()
            .auth_provider(TokenAuthProvider::new(
                StaticTokenVerifier::new([(GATEWAY_TOKEN.to_owned(), auth)]).unwrap(),
            ))
            .extension(registration)
            .unwrap()
            .middleware(DownstreamAudit);
        #[cfg(feature = "legacy-2024-11-05")]
        let endpoint = builder
            .build_http_endpoint("http://gateway.example")
            .unwrap();
        #[cfg(not(feature = "legacy-2024-11-05"))]
        let endpoint = builder.build_http_endpoint().unwrap();
        Self {
            endpoint,
            policy: HttpSecurityPolicy::new(
                HttpEndpointConfig::new(
                    "/mcp",
                    HttpAdmissionLimits::new(32, 8192, 65_536).unwrap(),
                )
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
        message: Value,
        authenticated: bool,
    ) -> Result<Reply, SecuredHttpEndpointError> {
        let method = message["method"].as_str().unwrap();
        let mut request = HttpRequest::new(HttpMethod::Post, "/mcp")
            .with_header("Host", "gateway.example")
            .with_header("Content-Type", "application/json")
            .with_header("Accept", "application/json, text/event-stream")
            .with_header("Mcp-Protocol-Version", FINAL_PROTOCOL_VERSION)
            .with_header("Mcp-Method", method)
            .with_body(serde_json::to_vec(&message).unwrap());
        if authenticated {
            request = request.with_header("Authorization", format!("Bearer {GATEWAY_TOKEN}"));
        }
        let response = Box::pin(
            self.endpoint
                .handle_secured_async(cx, &self.policy, request),
        )
        .await?;
        Ok(collect(cx, response).await)
    }
}

fn request(id: i64, value: Value) -> Value {
    json!({
        "jsonrpc":"2.0","id":id,"method":METHOD,"params":{
            "value":value,"_meta":{
                "io.modelcontextprotocol/protocolVersion":FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities":{"extensions":{EXTENSION:{"version":1}}},
                "io.modelcontextprotocol/clientInfo":{"name":"DOWNSTREAM-IDENTITY","version":"1"},
                "com.example/private":"DOWNSTREAM-PRIVATE-METADATA"
            }
        }
    })
}

fn notification(value: u32) -> Value {
    json!({"jsonrpc":"2.0","method":NOTIFICATION,"params":{
        "value":value,"_meta":{
            ACTIVATION:{"version":1},
            "com.example/private":"DOWNSTREAM-PRIVATE-METADATA",
            "io.modelcontextprotocol/clientInfo":{"name":"DOWNSTREAM-IDENTITY","version":"1"}
        }
    }})
}

fn assert_custody(peer: &Peer) {
    let seen = peer.seen.lock().unwrap();
    for message in seen.iter() {
        let params = &message["params"];
        if message["method"] == NOTIFICATION {
            assert!(
                message.get("id").is_none(),
                "standalone notifications have no waiter ID"
            );
            assert_eq!(params["_meta"], json!({ACTIVATION:{"version":1}}));
        } else {
            assert!(message.get("id").is_some());
            assert_eq!(
                params["_meta"]["io.modelcontextprotocol/clientInfo"]["name"],
                UPSTREAM_IDENTITY
            );
            assert_eq!(
                params["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"],
                json!({EXTENSION:{"version":1}})
            );
        }
        let wire = message.to_string();
        for private in [
            GATEWAY_TOKEN,
            "DOWNSTREAM-IDENTITY",
            "DOWNSTREAM-PRIVATE-METADATA",
        ] {
            assert!(!wire.contains(private));
        }
    }
}

fn assert_result(reply: &Reply, id: i64, value: u32, notices: bool) {
    assert_eq!(reply.status, 200);
    assert_eq!(reply.streaming, notices);
    assert_eq!(reply.records.len(), if notices { 2 } else { 1 });
    if notices {
        assert_eq!(reply.records[0]["method"], NOTICE);
        assert_eq!(reply.records[0]["params"], json!({"value":value}));
        assert!(reply.records[0].get("id").is_none());
    }
    let terminal = reply.records.last().unwrap();
    assert_eq!(terminal["id"], id);
    assert!(terminal.get("error").is_none(), "{terminal}");
    assert_eq!(terminal["result"], json!({"value":value}));
    assert!(!String::from_utf8_lossy(&reply.body).contains("UPSTREAM-PRIVATE-METADATA"));
}

fn assert_refusal(reply: &Reply) {
    assert!(
        !reply.records.is_empty(),
        "a request refusal must be observable"
    );
    assert!(
        reply
            .records
            .iter()
            .all(|record| record.get("result").is_none())
    );
    assert!(
        reply
            .records
            .iter()
            .any(|record| record.get("error").is_some())
    );
    assert!(!String::from_utf8_lossy(&reply.body).contains("UPSTREAM-PRIVATE-METADATA"));
}

pub(super) async fn scenario(cx: Cx, case: Case) {
    let observed = Arc::new(Observed::default());
    let retained = observed.clone();
    let registration = producer(observed.clone(), case.streaming());
    let peer = Peer::new_with_builder(&cx, false, move |builder| {
        builder
            .extension(registration)
            .unwrap()
            .middleware(UpstreamAudit(retained))
    })
    .await;
    let ((), session) = pair(
        peer.login(),
        ManagedOAuthSession::authorize(&cx, peer.client(), OAuthSessionPolicy::default(), browser),
    )
    .await;
    let session = session.unwrap();
    let declaration_calls = Arc::new(Observed::default());
    let (initial_discovery, upstream) = pair(
        discovery(&peer, &cx),
        producer(declaration_calls.clone(), case.streaming()).connect_managed_http_upstream(
            &cx,
            session.clone(),
            client_builder(&peer),
            &ClientSettings { version: 1 },
            Duration::from_secs(10),
        ),
    )
    .await;
    assert_eq!(
        initial_discovery.records[0]["result"]["capabilities"]["extensions"][EXTENSION],
        json!({"version":1,"multiplier":3})
    );
    let upstream = upstream.unwrap();
    let authorized = Arc::new(AtomicUsize::new(0));
    let gateway = Gateway::new(forwarded(upstream, case.streaming(), authorized.clone()));

    if matches!(case, Case::Notification) {
        let initial_requests = peer.seen.lock().unwrap().len();
        let unauthenticated = gateway.send(&cx, notification(7), false).await.unwrap();
        assert_eq!(unauthenticated.status, 401);
        assert_eq!(authorized.load(Ordering::SeqCst), 0);
        let mut missing = notification(7);
        missing["params"]["_meta"]
            .as_object_mut()
            .unwrap()
            .remove(ACTIVATION);
        let rejected = gateway.send(&cx, missing, true).await.unwrap();
        assert_eq!(rejected.status, 400);
        assert_eq!(authorized.load(Ordering::SeqCst), 0);
        let denied = gateway.send(&cx, notification(17), true).await.unwrap();
        assert_eq!(denied.status, 403);
        assert_eq!(authorized.load(Ordering::SeqCst), 1);
        assert_eq!(peer.seen.lock().unwrap().len(), initial_requests);
        peer.quiet();
        let (remote, accepted) = pair(
            exchange(&peer, &cx),
            gateway.send(&cx, notification(7), true),
        )
        .await;
        let accepted = accepted.unwrap();
        assert_eq!(remote.status, 202);
        assert!(remote.body.is_empty() && remote.records.is_empty() && !remote.streaming);
        assert_eq!(accepted.status, 202);
        assert!(accepted.body.is_empty() && accepted.records.is_empty() && !accepted.streaming);
        assert_eq!(authorized.load(Ordering::SeqCst), 2);
        assert_eq!(observed.authorized_notifications.load(Ordering::SeqCst), 1);
        assert_eq!(observed.notifications.load(Ordering::SeqCst), 1);
        assert_eq!(observed.requests.load(Ordering::SeqCst), 0);
    } else {
        if matches!(case, Case::Request) {
            let unauthenticated = gateway
                .send(&cx, request(90, json!(7)), false)
                .await
                .unwrap();
            assert_eq!(unauthenticated.status, 401);
            let malformed = gateway
                .send(&cx, request(91, json!("not-an-integer")), true)
                .await
                .unwrap();
            assert_refusal(&malformed);
            assert_eq!(observed.requests.load(Ordering::SeqCst), 0);
            assert_eq!(peer.seen.lock().unwrap().len(), 1);
            peer.quiet();
        }
        let (remote, first) = pair(
            exchange(&peer, &cx),
            gateway.send(&cx, request(100, json!(7)), true),
        )
        .await;
        let first = first.unwrap();
        assert_result(&first, 100, 21, case.streaming());
        assert_eq!(remote.records.last().unwrap()["result"]["value"], 21);
        assert_eq!(observed.requests.load(Ordering::SeqCst), 1);
        assert_eq!(peer.seen.lock().unwrap().len(), 3);

        match case {
            Case::CloseOwner => {
                session.close();
                let refused = gateway
                    .send(&cx, request(101, json!(7)), true)
                    .await
                    .unwrap();
                assert_refusal(&refused);
                assert_eq!(observed.requests.load(Ordering::SeqCst), 1);
                assert_eq!(peer.seen.lock().unwrap().len(), 3);
                peer.quiet();
            }
            Case::PreCancelled => {
                let child = cx
                    .open_child_region(asupersync::cx::child_region::ChildRegionSpec::inherit())
                    .await
                    .unwrap();
                child.cx().cancel_with(
                    asupersync::types::CancelKind::Shutdown,
                    Some("cancelled gateway fixture request"),
                );
                let error = gateway
                    .send(child.cx(), request(101, json!(7)), true)
                    .await
                    .unwrap_err();
                assert_eq!(error, SecuredHttpEndpointError::Cancelled);
                child.close().await.unwrap();
                assert_eq!(observed.requests.load(Ordering::SeqCst), 1);
                assert_eq!(peer.seen.lock().unwrap().len(), 3);
                peer.quiet();
                let (_, sibling) = pair(
                    exchange(&peer, &cx),
                    gateway.send(&cx, request(102, json!(9)), true),
                )
                .await;
                assert_result(&sibling.unwrap(), 102, 27, false);
                assert_eq!(observed.requests.load(Ordering::SeqCst), 2);
            }
            Case::SettingsDrift => {
                observed.drift.store(true, Ordering::SeqCst);
                let (changed, refused) = pair(
                    discovery(&peer, &cx),
                    gateway.send(&cx, request(101, json!(7)), true),
                )
                .await;
                assert_eq!(
                    changed.records[0]["result"]["capabilities"]["extensions"][EXTENSION]["multiplier"],
                    5
                );
                assert_refusal(&refused.unwrap());
                assert_eq!(observed.requests.load(Ordering::SeqCst), 1);
                assert_eq!(
                    peer.seen.lock().unwrap().len(),
                    4,
                    "drift refuses before application POST"
                );
                peer.quiet();
                observed.drift.store(false, Ordering::SeqCst);
                let (_, recovered) = pair(
                    exchange(&peer, &cx),
                    gateway.send(&cx, request(102, json!(9)), true),
                )
                .await;
                assert_result(&recovered.unwrap(), 102, 27, false);
                assert_eq!(observed.requests.load(Ordering::SeqCst), 2);
            }
            Case::RefusedRelay => {
                let (buffered, refused) = pair(
                    exchange(&peer, &cx),
                    gateway.send(&cx, request(101, json!(13)), true),
                )
                .await;
                assert!(buffered.streaming);
                assert_eq!(
                    buffered.records.len(),
                    2,
                    "native notification and successful terminal were both buffered"
                );
                assert_eq!(buffered.records[0]["params"], json!({"value":39}));
                assert_eq!(buffered.records[1]["result"]["value"], 39);
                let refused = refused.unwrap();
                assert_refusal(&refused);
                assert!(
                    refused
                        .records
                        .iter()
                        .all(|record| record.get("method").is_none()),
                    "refused notification must not reach the downstream sink"
                );
                assert_eq!(observed.requests.load(Ordering::SeqCst), 2);
                peer.quiet();
                let (_, sibling) = pair(
                    exchange(&peer, &cx),
                    gateway.send(&cx, request(102, json!(9)), true),
                )
                .await;
                assert_result(&sibling.unwrap(), 102, 27, true);
                assert_eq!(observed.requests.load(Ordering::SeqCst), 3);
            }
            Case::Request | Case::RequestNotifications => {}
            Case::Notification => unreachable!("standalone notifications take the earlier branch"),
        }
    }
    assert_custody(&peer);
    assert_eq!(declaration_calls.requests.load(Ordering::SeqCst), 0);
    assert_eq!(declaration_calls.notifications.load(Ordering::SeqCst), 0);
    assert_eq!(
        declaration_calls
            .authorized_notifications
            .load(Ordering::SeqCst),
        0
    );
    assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
    peer.quiet();
    session.close();
    peer.journal.close().unwrap();
}

#[test]
fn managed_extension_gateway_preserves_typed_data_and_independent_authority() {
    isolated(
        "managed_extensions::managed_extension_gateway_preserves_typed_data_and_independent_authority",
        super::Case::ManagedExtensions(Case::Request),
    );
}

#[test]
fn managed_extension_gateway_notifications_require_auth_and_acknowledge_without_ids() {
    isolated(
        "managed_extensions::managed_extension_gateway_notifications_require_auth_and_acknowledge_without_ids",
        super::Case::ManagedExtensions(Case::Notification),
    );
}

#[test]
fn managed_extension_gateway_closed_session_refuses_before_discovery() {
    isolated(
        "managed_extensions::managed_extension_gateway_closed_session_refuses_before_discovery",
        super::Case::ManagedExtensions(Case::CloseOwner),
    );
}

#[test]
fn managed_extension_gateway_cancelled_request_keeps_live_siblings_usable() {
    isolated(
        "managed_extensions::managed_extension_gateway_cancelled_request_keeps_live_siblings_usable",
        super::Case::ManagedExtensions(Case::PreCancelled),
    );
}

#[test]
fn managed_extension_gateway_changed_settings_refuse_before_application_post() {
    isolated(
        "managed_extensions::managed_extension_gateway_changed_settings_refuse_before_application_post",
        super::Case::ManagedExtensions(Case::SettingsDrift),
    );
}

#[test]
fn managed_extension_gateway_relays_native_request_notifications() {
    isolated(
        "managed_extensions::managed_extension_gateway_relays_native_request_notifications",
        super::Case::ManagedExtensions(Case::RequestNotifications),
    );
}

#[test]
fn managed_extension_gateway_refused_relay_suppresses_buffered_terminal_only_for_its_owner() {
    isolated(
        "managed_extensions::managed_extension_gateway_refused_relay_suppresses_buffered_terminal_only_for_its_owner",
        super::Case::ManagedExtensions(Case::RefusedRelay),
    );
}
