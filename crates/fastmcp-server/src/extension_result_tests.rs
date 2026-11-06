//! Negotiated extension results at producer and middleware dispatch boundaries.

use super::*;
use fastmcp_protocol::extensions::{
    ExtensionDirection, ExtensionFallbackPolicy, ExtensionHttpEraDisposition,
    ExtensionMethodDescriptor, ExtensionNegotiationResolver, ExtensionSettingsSchema,
};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};

const OWNER: &str = "com.example/result-owner";
const METHOD: &str = "com.example/result";
const DISCRIMINATOR: &str = "com.example/result-value";
const FOREIGN_OWNER: &str = "com.example/foreign-owner";
const FOREIGN_METHOD: &str = "com.example/foreign";
const FOREIGN_DISCRIMINATOR: &str = "com.example/foreign-value";
const REQUEST_ID: i64 = 71;

#[derive(Default)]
struct Probe {
    handler_calls: AtomicUsize,
    resolutions: AtomicUsize,
    foreign_resolutions: AtomicUsize,
    middleware_requests: AtomicUsize,
    resolutions_at_middleware: AtomicUsize,
    middleware_responses: AtomicUsize,
    middleware_errors: AtomicUsize,
}

#[derive(Clone)]
enum ResultMiddlewareMode {
    Respond(Value),
    Replace(Value),
}

struct ResultMiddleware {
    mode: ResultMiddlewareMode,
    probe: Arc<Probe>,
}

impl Middleware for ResultMiddleware {
    fn on_request(
        &self,
        _ctx: &McpContext,
        _request: &JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        self.probe
            .middleware_requests
            .fetch_add(1, Ordering::SeqCst);
        self.probe.resolutions_at_middleware.store(
            self.probe.resolutions.load(Ordering::SeqCst),
            Ordering::SeqCst,
        );
        Ok(match &self.mode {
            ResultMiddlewareMode::Respond(value) => MiddlewareDecision::Respond(value.clone()),
            ResultMiddlewareMode::Replace(_) => MiddlewareDecision::Continue,
        })
    }

    fn on_response(
        &self,
        _ctx: &McpContext,
        _request: &JsonRpcRequest,
        value: Value,
    ) -> McpResult<Value> {
        self.probe
            .middleware_responses
            .fetch_add(1, Ordering::SeqCst);
        Ok(match &self.mode {
            ResultMiddlewareMode::Replace(replacement) => replacement.clone(),
            ResultMiddlewareMode::Respond(_) => value,
        })
    }

    fn on_error(&self, _ctx: &McpContext, _request: &JsonRpcRequest, error: McpError) -> McpError {
        self.probe.middleware_errors.fetch_add(1, Ordering::SeqCst);
        error
    }
}

fn descriptor(id: &str, method: &str, discriminator: Option<&str>) -> ExtensionDescriptor {
    ExtensionDescriptor {
        id: ExtensionId::parse(id).unwrap(),
        client_settings: ExtensionSettingsSchema {
            schema_id: "result-client-v1".to_owned(),
            codec_id: "result-client-v1".to_owned(),
        },
        server_settings: ExtensionSettingsSchema {
            schema_id: "result-server-v1".to_owned(),
            codec_id: "result-server-v1".to_owned(),
        },
        resolver: ExtensionNegotiationResolver {
            id: "result-resolver-v1".to_owned(),
            version: 1,
            fallback: ExtensionFallbackPolicy::RejectOneSided,
        },
        method: Some(ExtensionMethodDescriptor {
            name: method.to_owned(),
            direction: ExtensionDirection::ClientToServer,
            http_era_disposition: Some(ExtensionHttpEraDisposition::ModernExclusive),
            legacy_fallback: false,
        }),
        notification: None,
        result_discriminator: discriminator.map(str::to_owned),
        routing_headers: Vec::new(),
        stdio_correlation: None,
    }
}

fn server(
    result: Value,
    discriminator: Option<&str>,
    middleware: Option<ResultMiddlewareMode>,
) -> (Arc<Server>, Arc<Probe>) {
    let probe = Arc::new(Probe::default());
    let mut descriptors = ExtensionDescriptorRegistry::new();
    descriptors
        .register(descriptor(OWNER, METHOD, discriminator))
        .unwrap();
    // Both extensions are active. A result belonging to the second extension
    // must still be refused for the first extension's request.
    descriptors
        .register(descriptor(
            FOREIGN_OWNER,
            FOREIGN_METHOD,
            Some(FOREIGN_DISCRIMINATOR),
        ))
        .unwrap();
    let mut handlers = ExtensionHandlerRegistry::new(descriptors);
    let handler_probe = Arc::clone(&probe);
    handlers
        .register(
            ExtensionId::parse(OWNER).unwrap(),
            METHOD,
            move |_context: &McpContext, _params: Value| {
                handler_probe.handler_calls.fetch_add(1, Ordering::SeqCst);
                Ok(result.clone())
            },
        )
        .unwrap();
    handlers
        .register(
            ExtensionId::parse(FOREIGN_OWNER).unwrap(),
            FOREIGN_METHOD,
            |_context: &McpContext, _params: Value| {
                Ok(json!({"resultType": FOREIGN_DISCRIMINATOR, "value": 99}))
            },
        )
        .unwrap();
    let resolver_probe = Arc::clone(&probe);
    let mut builder = Server::new("extension-results", "1.0.0")
        .extension_registry(
            handlers,
            ServerExtensionDiscovery {
                extensions: [OWNER, FOREIGN_OWNER]
                    .into_iter()
                    .map(|id| {
                        (
                            ExtensionId::parse(id).unwrap(),
                            ExtensionSettings::new(json!({})).unwrap(),
                        )
                    })
                    .collect(),
            },
            move |descriptor: &ExtensionDescriptor,
                  client: &ExtensionSettings,
                  _server: &ExtensionSettings|
                  -> Result<ExtensionSettings, ExtensionNegotiationError> {
                if descriptor.id.as_str() == OWNER {
                    resolver_probe.resolutions.fetch_add(1, Ordering::SeqCst);
                } else {
                    resolver_probe
                        .foreign_resolutions
                        .fetch_add(1, Ordering::SeqCst);
                }
                Ok(client.clone())
            },
        )
        .unwrap();
    if let Some(mode) = middleware {
        builder = builder.middleware(ResultMiddleware {
            mode,
            probe: Arc::clone(&probe),
        });
    }
    (Arc::new(builder.build()), probe)
}

fn request() -> JsonRpcRequest {
    JsonRpcRequest::new(
        METHOD,
        Some(json!({
            "value": 41,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {
                    "extensions": {
                        (OWNER): {},
                        (FOREIGN_OWNER): {},
                    }
                }
            }
        })),
        REQUEST_ID,
    )
}

#[derive(Clone, Copy, Debug)]
enum Dispatch {
    Borrowed,
    Owned,
    SynchronousFallback,
}

const DISPATCHES: [Dispatch; 3] = [
    Dispatch::Borrowed,
    Dispatch::Owned,
    Dispatch::SynchronousFallback,
];

fn dispatch(server: &Arc<Server>, request: JsonRpcRequest, route: Dispatch) -> JsonRpcResponse {
    let cx = Cx::for_testing();
    let inbound = InboundRequestContext::new(
        cx.clone(),
        REQUEST_ID as u64,
        InboundRequestTransport::Memory,
    );
    match route {
        Dispatch::Borrowed => block_on(server.dispatch_stateless(&inbound, &request)).unwrap(),
        Dispatch::Owned => block_on(Arc::clone(server).dispatch_with_protocol_policy_owned(
            ProtocolPolicy::ModernOnly,
            &inbound,
            request,
            None,
            None,
            None,
            None,
            McpRequestCancellation::new(),
            None,
            Arc::new(|_| {}),
        ))
        .unwrap(),
        Dispatch::SynchronousFallback => {
            // Exercise the existing synchronous extension escape hatch in
            // session dispatch, including its middleware finalization path.
            let mut session = Session::new(server.info.clone(), server.capabilities.clone());
            session.initialize(
                fastmcp_protocol::ClientInfo {
                    name: "extension-result-client".to_owned(),
                    version: "1.0.0".to_owned(),
                },
                fastmcp_protocol::ClientCapabilities::default(),
                LEGACY_PROTOCOL_VERSION.to_owned(),
            );
            let pending = Arc::new(bidirectional::PendingRequests::new());
            let sender = bidirectional::RequestSender::new(
                pending,
                Arc::new(|_| Err("unexpected outbound request".to_owned())),
            );
            let notifications: NotificationSender = Arc::new(|_| {});
            let cancellation = McpRequestCancellation::new();
            let result = block_on(server.dispatch_method(
                &cx,
                &mut session,
                request,
                REQUEST_ID as u64,
                &cancellation,
                &Budget::INFINITE,
                &notifications,
                &sender,
                &mut None,
                None,
            ));
            match result {
                Ok(value) => JsonRpcResponse::success(REQUEST_ID, value),
                Err(error) => JsonRpcResponse::error(
                    Some(REQUEST_ID.into()),
                    JsonRpcError {
                        code: error.code.into(),
                        message: error.message,
                        data: error.data,
                    },
                ),
            }
        }
    }
}

fn cases() -> Vec<(&'static str, Value, bool)> {
    vec![
        (
            "owned discriminator",
            json!({"resultType": DISCRIMINATOR, "value": 42}),
            true,
        ),
        ("payload-only authoring object", json!({"value": 42}), true),
        (
            "core complete object",
            json!({"resultType": "complete", "value": 42}),
            true,
        ),
        (
            "owned discriminator with metadata",
            json!({
                "resultType": DISCRIMINATOR,
                "value": 42,
                "_meta": {"com.example/trace": "unchanged"},
            }),
            true,
        ),
        (
            "other active extension's discriminator",
            json!({"resultType": FOREIGN_DISCRIMINATOR}),
            false,
        ),
        (
            "unknown discriminator",
            json!({"resultType": "com.example/unknown"}),
            false,
        ),
        ("null discriminator", json!({"resultType": null}), false),
        ("numeric discriminator", json!({"resultType": 7}), false),
        ("scalar result", json!("invalid scalar result"), false),
        ("array result", json!([{"value": 42}]), false),
        (
            "malformed core input-required",
            json!({"resultType": "input_required"}),
            false,
        ),
        (
            "null metadata",
            json!({"resultType": DISCRIMINATOR, "_meta": null}),
            false,
        ),
        (
            "string metadata",
            json!({"resultType": DISCRIMINATOR, "_meta": "invalid"}),
            false,
        ),
        (
            "array metadata",
            json!({"resultType": DISCRIMINATOR, "_meta": []}),
            false,
        ),
        (
            "generic task result",
            json!({"resultType": "task", "task": {"taskId": "unowned"}}),
            false,
        ),
    ]
}

fn assert_result(response: JsonRpcResponse, expected: &Value, valid: bool, label: &str) {
    assert_eq!(response.id, Some(REQUEST_ID.into()), "{label}");
    if valid {
        assert!(response.error.is_none(), "{label}: {response:?}");
        assert_eq!(response.result.as_ref(), Some(expected), "{label}");
    } else {
        assert!(response.result.is_none(), "{label}: {response:?}");
        assert_eq!(
            response.error.map(|error| error.code),
            Some(i32::from(McpErrorCode::InternalError).into()),
            "{label}",
        );
    }
}

fn assert_one_negotiation(probe: &Probe, label: &str) {
    assert_eq!(probe.resolutions.load(Ordering::SeqCst), 1, "{label}");
    assert_eq!(
        probe.foreign_resolutions.load(Ordering::SeqCst),
        1,
        "{label}",
    );
}

#[test]
fn extension_result_producers_enforce_the_request_owner_without_rewriting_payloads() {
    for route in DISPATCHES {
        for (name, value, valid) in cases() {
            let (server, probe) = server(value.clone(), Some(DISCRIMINATOR), None);
            let label = format!("{route:?}: {name}");
            assert_result(dispatch(&server, request(), route), &value, valid, &label);
            assert_eq!(probe.handler_calls.load(Ordering::SeqCst), 1, "{label}");
            assert_one_negotiation(&probe, &label);
        }
    }
}

#[test]
fn extension_result_middleware_shortcuts_and_replacements_use_the_same_admission() {
    for route in DISPATCHES {
        for shortcut in [false, true] {
            for (name, value, valid) in cases() {
                let mode = if shortcut {
                    ResultMiddlewareMode::Respond(value.clone())
                } else {
                    ResultMiddlewareMode::Replace(value.clone())
                };
                let (server, probe) = server(
                    json!({"resultType": DISCRIMINATOR, "value": "producer"}),
                    Some(DISCRIMINATOR),
                    Some(mode),
                );
                let label = format!("{route:?}, shortcut={shortcut}: {name}");
                assert_result(dispatch(&server, request(), route), &value, valid, &label);
                assert_one_negotiation(&probe, &label);
                assert_eq!(
                    probe.resolutions_at_middleware.load(Ordering::SeqCst),
                    1,
                    "request admission must precede middleware: {label}",
                );
                assert_eq!(
                    probe.handler_calls.load(Ordering::SeqCst),
                    usize::from(!shortcut),
                    "{label}",
                );
                assert_eq!(
                    probe.middleware_requests.load(Ordering::SeqCst),
                    1,
                    "{label}"
                );
                assert_eq!(
                    probe.middleware_responses.load(Ordering::SeqCst),
                    1,
                    "{label}"
                );
                assert_eq!(
                    probe.middleware_errors.load(Ordering::SeqCst),
                    usize::from(!valid),
                    "{label}",
                );
            }
        }
    }
}

#[test]
fn extension_result_without_a_registered_discriminator_preserves_payload_only_objects() {
    for route in DISPATCHES {
        for (value, valid) in [
            (json!({"value": 42}), true),
            (json!({"resultType": "complete", "value": 42}), true),
            (json!({"resultType": DISCRIMINATOR, "value": 42}), false),
        ] {
            let (server, probe) = server(value.clone(), None, None);
            let label = format!("{route:?}, descriptor has no discriminator");
            assert_result(dispatch(&server, request(), route), &value, valid, &label);
            assert_eq!(probe.handler_calls.load(Ordering::SeqCst), 1, "{label}");
            assert_one_negotiation(&probe, &label);
        }
    }
}

#[test]
fn extension_result_shortcut_cannot_activate_an_omitted_capability() {
    for route in DISPATCHES {
        let (server, probe) = server(
            json!({"value": 42}),
            Some(DISCRIMINATOR),
            Some(ResultMiddlewareMode::Respond(json!({
                "resultType": DISCRIMINATOR,
                "value": "shortcut",
            }))),
        );
        let mut request = request();
        request.params.as_mut().unwrap()["_meta"]
            ["io.modelcontextprotocol/clientCapabilities"]["extensions"]
            .as_object_mut()
            .unwrap()
            .remove(OWNER);
        let response = dispatch(&server, request, route);
        assert!(response.result.is_none(), "{route:?}: {response:?}");
        assert_eq!(
            response.error.map(|error| error.code),
            Some(i32::from(McpErrorCode::InvalidParams).into()),
            "{route:?}",
        );
        assert_eq!(probe.handler_calls.load(Ordering::SeqCst), 0, "{route:?}");
        assert_eq!(
            probe.middleware_requests.load(Ordering::SeqCst),
            0,
            "{route:?}"
        );
    }
}

#[test]
fn extension_result_admission_does_not_claim_unregistered_middleware_requests() {
    for route in DISPATCHES {
        let payload = json!(["application-owned response"]);
        let (server, probe) = server(
            json!({"value": 42}),
            Some(DISCRIMINATOR),
            Some(ResultMiddlewareMode::Respond(payload.clone())),
        );
        let mut request = request();
        request.method = "com.example/unregistered".to_owned();
        assert_result(
            dispatch(&server, request, route),
            &payload,
            true,
            &format!("{route:?}"),
        );
        assert_eq!(probe.resolutions.load(Ordering::SeqCst), 0);
        assert_eq!(probe.foreign_resolutions.load(Ordering::SeqCst), 0);
        assert_eq!(probe.handler_calls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.middleware_requests.load(Ordering::SeqCst), 1);
    }
}
