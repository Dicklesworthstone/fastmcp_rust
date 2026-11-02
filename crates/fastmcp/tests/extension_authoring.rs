//! Live transport coverage for the restricted extension authoring facade.
//! These tests use the shipped server pump on an application-owned runtime.

#![cfg(feature = "extension-authoring")]
#![recursion_limit = "512"]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use asupersync::runtime::RuntimeBuilder;
use fastmcp_rust::extensions::authoring::{
    ExtensionBuilder, ExtensionContext, ExtensionRegistration,
};
use fastmcp_rust::memory::{MemoryTransport, create_memory_transport_pair_with_capacity};
use fastmcp_rust::serde::{Deserialize, Serialize};
use fastmcp_rust::{
    Cx, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, JsonSchema, McpError, McpResult,
    RequestId, TransportError, extension, json, modern,
};

const EXTENSION: &str = "com.example/typed-math";
const METHOD: &str = "com.example/scale";

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
struct ClientSettings {
    version: u32,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
struct ServerSettings {
    version: u32,
    multiplier: u32,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
struct Settings {
    multiplier: u32,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
struct ScaleRequest {
    value: u32,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(crate = "fastmcp_rust::serde", deny_unknown_fields)]
struct ScaleResponse {
    value: u32,
}

fn builder() -> ExtensionBuilder<ClientSettings, ServerSettings, Settings> {
    ExtensionBuilder::new(
        EXTENSION,
        1,
        "typed-math-client-v1",
        "typed-math-server-v1",
        ServerSettings {
            version: 1,
            multiplier: 3,
        },
        |client: ClientSettings, server: ServerSettings| {
            if client.version != server.version {
                return Err(McpError::invalid_params("incompatible math version"));
            }
            Ok(Settings {
                multiplier: server.multiplier,
            })
        },
    )
    .expect("admitted typed settings")
}

fn registration(calls: Arc<AtomicUsize>) -> ExtensionRegistration {
    builder()
        .typed_request_sync(
            METHOD,
            "scale-params-v1",
            "scale-result-v1",
            move |context: ExtensionContext<'_, Settings>, request: ScaleRequest| {
                context.checkpoint()?;
                assert_eq!(context.descriptor().id(), EXTENSION);
                assert_eq!(context.descriptor().version(), 1);
                assert_eq!(context.method(), METHOD);
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(ScaleResponse {
                    value: request.value * context.settings().multiplier,
                })
            },
        )
        .expect("typed method installs")
        .build()
        .expect("sealed registration")
}

#[extension(
    method = "com.example/scale",
    params_schema = "scale-params-v1",
    result_schema = "scale-result-v1"
)]
async fn scale(
    context: ExtensionContext<'_, Settings>,
    request: ScaleRequest,
) -> McpResult<ScaleResponse> {
    // Yield on the caller's executor without obtaining or constructing a Cx.
    let mut yielded = false;
    std::future::poll_fn(|task| {
        if yielded {
            std::task::Poll::Ready(())
        } else {
            yielded = true;
            task.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    })
    .await;
    context.checkpoint()?;
    Ok(ScaleResponse {
        value: request.value * context.settings().multiplier,
    })
}

fn request(
    id: i64,
    settings: Option<fastmcp_rust::JsonValue>,
    value: fastmcp_rust::JsonValue,
) -> JsonRpcMessage {
    let mut capabilities = json!({});
    if let Some(settings) = settings {
        capabilities["extensions"] = json!({(EXTENSION): settings});
    }
    JsonRpcMessage::Request(JsonRpcRequest::new(
        METHOD,
        Some(json!({
            "value": value,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": capabilities
            }
        })),
        id,
    ))
}

async fn response(cx: &Cx, peer: &mut MemoryTransport, id: i64) -> JsonRpcResponse {
    let JsonRpcMessage::Response(response) = peer.recv_async(cx).await.expect("server response")
    else {
        panic!("extension request must return a response");
    };
    assert_eq!(response.id, Some(RequestId::Number(id)));
    response
}

fn run_exchange(
    registration: ExtensionRegistration,
    requests: Vec<JsonRpcMessage>,
) -> Vec<JsonRpcResponse> {
    let server = modern::ServerBuilder::new("typed-extension", "1.0")
        .extension(registration)
        .expect("installation before freeze")
        .try_build()
        .expect("immutable server");
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .expect("application-owned runtime");
    let responses = runtime.block_on(async move {
        let cx = Cx::current().expect("caller context");
        assert!(cx.blocking_pool_handle().is_none());
        asupersync::time::timeout(cx.now(), Duration::from_secs(15), async {
            let (mut peer, transport) = create_memory_transport_pair_with_capacity(1);
            let mut serving = cx
                .spawn(move |cx| async move { server.serve_memory(&cx, transport).await })
                .expect("owned server task");
            let mut responses = Vec::new();
            for (index, request) in requests.iter().enumerate() {
                peer.send_async(&cx, request)
                    .await
                    .expect("request admitted");
                responses.push(response(&cx, &mut peer, index as i64 + 1).await);
            }
            let (mut input, output) = peer.into_split();
            drop(output);
            assert!(matches!(
                input.recv_async(&cx).await,
                Err(TransportError::Closed)
            ));
            serving
                .join(&cx)
                .await
                .expect("server task settled")
                .expect("server closed");
            responses
        })
        .await
        .expect("bounded exchange and cleanup")
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    responses
}

#[test]
fn typed_extension_settings_and_schema_are_enforced_per_request() {
    let calls = Arc::new(AtomicUsize::new(0));
    let registration = registration(Arc::clone(&calls));
    assert_eq!(registration.descriptor().id(), EXTENSION);
    assert_eq!(registration.descriptor().version(), 1);
    let responses = run_exchange(
        registration,
        vec![
            request(1, Some(json!({"version": 1})), json!(7)),
            request(2, None, json!(7)),
            request(3, Some(json!({"version": 2})), json!(7)),
            request(4, Some(json!({"version": "bad"})), json!(7)),
            request(5, Some(json!({"version": 1})), json!("bad")),
            request(6, Some(json!({"version": 1})), json!(11)),
        ],
    );
    assert!(responses[0].error.is_none(), "{:?}", responses[0]);
    assert_eq!(responses[0].result.as_ref().unwrap()["value"], 21);
    for response in &responses[1..5] {
        assert!(
            response.error.is_some(),
            "rejected request had a successful result: {response:?}"
        );
        assert!(response.result.is_none());
    }
    assert!(responses[5].error.is_none(), "{:?}", responses[5]);
    assert_eq!(responses[5].result.as_ref().unwrap()["value"], 33);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "only admitted requests run handlers"
    );
}

#[test]
fn attribute_extension_yields_on_caller_runtime_and_returns_typed_result() {
    let registration = ScaleExtension
        .register(builder())
        .expect("attribute-generated registration")
        .build()
        .unwrap();
    let responses = run_exchange(
        registration,
        vec![
            request(1, Some(json!({"version": 1})), json!(9)),
            request(2, Some(json!({"version": 2})), json!(9)),
        ],
    );
    assert!(responses[0].error.is_none(), "{:?}", responses[0]);
    assert_eq!(responses[0].result.as_ref().unwrap()["value"], 27);
    assert!(responses[1].error.is_some());
}

#[test]
fn sealed_extension_installation_preserves_existing_registration() {
    let first = registration(Arc::new(AtomicUsize::new(0)));
    let second = registration(Arc::new(AtomicUsize::new(0)));
    let builder = modern::ServerBuilder::new("typed-extension", "1.0")
        .extension(first)
        .unwrap();
    assert!(
        builder.extension(second).is_err(),
        "installation cannot silently replace a registry"
    );
}
