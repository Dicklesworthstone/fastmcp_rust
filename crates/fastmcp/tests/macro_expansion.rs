//! Integration tests for procedural macro expansion.
//!
//! These tests verify that `#[tool]`, `#[resource]`, `#[prompt]`, and
//! `#[derive(JsonSchema)]` macros generate correct handler implementations
//! with proper trait impls, parameter extraction, schema generation,
//! doc comments, async handling, and return type conversion.

// Test-specific clippy allowances:
// - unused_async: async functions are intentionally async to test macro handling
// - struct_field_names: test structs use explicit naming for clarity
// - similar_names: test functions have intentionally similar names
// - too_many_lines: test file needs comprehensive coverage
// - unnecessary_wraps: testing Result return type handling
// - enum_variant_names: test enums for schema testing
// - dead_code: test structs/enums exist only for schema generation testing
#![allow(clippy::unused_async)]
#![allow(clippy::struct_field_names)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::enum_variant_names)]
#![allow(dead_code)]

use asupersync::conformance::{ConformanceTarget, LabRuntimeTarget};
use asupersync::{LabConfig, LabRuntime};
use fastmcp_rust::serde_json::json;
#[cfg(feature = "tasks")]
use fastmcp_rust::{
    ApplicationTaskSupervisor, FinalTaskRuntime, FinalTaskRuntimeConfig, FinalTaskSupervisorFuture,
    FinalTaskSupervisorHandoff, FinalTaskWorkDescriptor, InMemoryFinalTaskStore,
    MISSING_REQUIRED_CLIENT_CAPABILITY_ERROR_CODE,
};
use fastmcp_rust::{
    CacheScope, CacheTtl, CompleteResult, Content, ContentBlock, Cx, EmbeddedResourceContents,
    FinalAbsoluteUri, FinalCallToolResult, FinalGetPromptResult, FinalPromptMessage,
    FinalReadResourceResult, FinalToolOutcome, Implementation, InboundRequestContext,
    InboundRequestTransport, InputRequiredResult, JsonRpcRequest, JsonSchema,
    MODERN_PROTOCOL_VERSION, McpContext, McpError, McpOutcome, McpResult, ModernConnection,
    Outcome, PromptHandler, PromptMessage, ResourceContent, ResourceHandler, ResultMeta, Role,
    ToolHandler, prompt, resource, tool,
};
use fastmcp_server::Server;
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
#[cfg(feature = "tasks")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "tasks")]
use std::task::Poll;

fn test_ctx() -> McpContext {
    McpContext::new(Cx::for_testing(), 1)
}

fn run_outcome<T, F>(future: F) -> McpOutcome<T>
where
    T: Send + 'static,
    F: Future<Output = McpOutcome<T>> + Send + 'static,
{
    let mut runtime = LabRuntime::new(LabConfig::new(0xF45A_5A11).max_steps(2_000));
    LabRuntimeTarget::block_on(&mut runtime, future)
}

fn expect_outcome_ok<T>(outcome: McpOutcome<T>) -> T {
    match outcome {
        Outcome::Ok(value) => value,
        Outcome::Err(error) => panic!("expected successful handler outcome, got {error}"),
        Outcome::Cancelled(_) => panic!("expected successful handler outcome, got cancellation"),
        Outcome::Panicked(_) => panic!("expected successful handler outcome, got panic"),
    }
}

fn expect_text(content: &Content) -> &str {
    if let Content::Text { text } = content {
        text
    } else {
        assert!(
            matches!(content, Content::Text { .. }),
            "Expected Text content"
        );
        ""
    }
}

/// Final input responses are a public, validated correlation map rather than
/// a caller-assembled JSON object. The root, modern, and prelude spellings
/// must remain constructible from a facade-only dependency.
#[test]
fn facade_final_input_response_surface_is_constructible() {
    use fastmcp_rust::{FinalInputResponseCorrelationError, FinalInputResponses, modern, prelude};

    let root = FinalInputResponses::try_from_entries(Vec::new()).expect("empty root responses");
    let modern =
        modern::FinalInputResponses::try_from_entries(Vec::new()).expect("empty modern responses");
    let prelude = prelude::FinalInputResponses::try_from_entries(Vec::new())
        .expect("empty prelude responses");

    assert!(root.is_empty());
    assert!(modern.is_empty());
    assert!(prelude.is_empty());
    assert_eq!(
        FinalInputResponseCorrelationError::MissingResponse.to_string(),
        "missing final input response"
    );
}

/// The experimental facade exposes the caller-driven async URI/Upgrade client
/// and the era-pinned async server lifecycle. Synchronous split-transport
/// client wrappers must not reappear through the facade.
#[cfg(feature = "websocket-experimental")]
#[test]
fn facade_websocket_surface_is_namespace_consistent() {
    use fastmcp_rust::{
        AsyncWsClientTransport, AsyncWsServerTransport, Cx, McpResult, prelude, server, transport,
    };

    async fn composes_actual_async_websocket_client(cx: &Cx) -> McpResult<()> {
        let transport = AsyncWsClientTransport::connect(cx, "ws://127.0.0.1:9000/mcp")
            .await
            .map_err(|error| McpError::internal_error(error.to_string()))?;
        let client = fastmcp_rust::ClientBuilder::new()
            .connect_websocket_with_cx(cx, transport)
            .await?;
        let _ = client.session();

        let modern_transport = AsyncWsClientTransport::connect(cx, "ws://127.0.0.1:9001/mcp")
            .await
            .map_err(|error| McpError::internal_error(error.to_string()))?;
        let modern_client = fastmcp_rust::modern::ClientBuilder::new()
            .connect_websocket_with_cx(cx, modern_transport)
            .await?;
        let _ = modern_client.session();

        let modern_listener = fastmcp_rust::modern::server_builder("modern-ws", "1.0")
            .build()
            .bind_websocket(cx, "127.0.0.1:0")
            .await?;
        let _ = modern_listener.local_addr()?;

        #[cfg(feature = "legacy-2024-11-05")]
        {
            let legacy_transport = AsyncWsClientTransport::connect(cx, "ws://127.0.0.1:9002/mcp")
                .await
                .map_err(|error| McpError::internal_error(error.to_string()))?;
            let legacy_client = fastmcp_rust::legacy_2024::ClientBuilder::new()
                .connect_websocket_with_cx(cx, legacy_transport)
                .await?;
            let _ = legacy_client.server_capabilities();

            let auto_client = fastmcp_rust::auto::ClientBuilder::new()
                .connect_websocket_auto_with_cx(cx, move |_| async move {
                    AsyncWsClientTransport::connect(cx, "ws://127.0.0.1:9003/mcp")
                        .await
                        .map_err(|error| McpError::internal_error(error.to_string()))
                })
                .await?;
            let _ = auto_client.session();

            let legacy_listener = fastmcp_rust::legacy_2024::server_builder("legacy-ws", "1.0")
                .build()
                .bind_websocket(cx, "127.0.0.1:0")
                .await?;
            let _ = legacy_listener.local_addr()?;
        }

        Ok(())
    }

    async fn binds_modern_websocket(
        server: fastmcp_rust::modern::Server,
        cx: &Cx,
    ) -> McpResult<()> {
        let listener = server.bind_websocket(cx, "127.0.0.1:0").await?;
        let _ = listener.local_addr()?;
        Ok(())
    }

    #[cfg(feature = "legacy-2024-11-05")]
    async fn binds_legacy_websocket(
        server: fastmcp_rust::legacy_2024::Server,
        cx: &Cx,
    ) -> McpResult<()> {
        let listener = server.bind_websocket(cx, "127.0.0.1:0").await?;
        let _ = listener.local_addr()?;
        Ok(())
    }

    fn exposes_async_websocket_types<IO>() {
        let _: Option<AsyncWsClientTransport<IO>> = None;
        let _: Option<AsyncWsServerTransport<()>> = None;
        let _: Option<server::BoundWebSocketServer> = None;
        let _: Option<server::WebSocketServerShutdown> = None;
        let _: Option<transport::websocket::WebSocketListener> = None;
        let _: Option<transport::websocket::WebSocketUpgradeAdmission> = None;
        let _: Option<prelude::WebSocketResponse> = None;
        let _: Option<prelude::BoundWebSocketServer> = None;
        let _: Option<prelude::WebSocketServerShutdown> = None;
        let _ = binds_modern_websocket;
        #[cfg(feature = "legacy-2024-11-05")]
        {
            let _ = binds_legacy_websocket;
        }
    }

    let _ = composes_actual_async_websocket_client;
    let _ = exposes_async_websocket_types::<()>;
}

// This module intentionally imports every macro dependency through the facade
// only. It is a focused packaging proof: a downstream user needs neither a
// component crate nor serde_json/asupersync as a direct dependency.
mod facade_only_macro_compile_proofs {
    use fastmcp_rust::{
        CompleteResult, Content, FinalCallToolResult, JsonSchema, McpContext, PromptHandler,
        PromptMessage, ResourceContent, ResourceHandler, Role, ToolHandler, prompt, resource, tool,
    };

    #[derive(JsonSchema)]
    struct FacadeOnlySchema {
        title: String,
    }

    #[tool]
    fn facade_only_legacy_tool(name: String) -> String {
        format!("hello, {name}")
    }

    #[cfg_attr(feature = "tasks", tool(tasks))]
    #[cfg_attr(not(feature = "tasks"), tool)]
    fn facade_only_final_task_tool() -> fastmcp_rust::FinalToolOutcome {
        fastmcp_rust::FinalToolOutcome::Complete(CompleteResult::new(
            FinalCallToolResult {
                content: Vec::new(),
                is_error: false,
                structured_content: None,
            },
            super::final_result_meta(),
        ))
    }

    #[resource(uri = "facade://macro-proof")]
    fn facade_only_resource(_ctx: &McpContext) -> String {
        "facade resource".to_string()
    }

    #[prompt]
    fn facade_only_prompt(name: String) -> Vec<PromptMessage> {
        vec![PromptMessage {
            role: Role::User,
            content: Content::text(name),
        }]
    }

    #[test]
    fn facade_only_paths_compile_every_macro_family_and_keep_legacy_names() {
        assert_eq!(FacadeOnlySchema::json_schema()["type"], "object");
        assert_eq!(
            FacadeOnlyLegacyTool.definition().name,
            "facade_only_legacy_tool"
        );
        assert_eq!(
            FacadeOnlyFinalTaskTool.declares_final_tasks(),
            cfg!(feature = "tasks")
        );
        assert_eq!(
            FacadeOnlyResourceResource.definition().uri,
            "facade://macro-proof"
        );
        assert_eq!(
            FacadeOnlyPromptPrompt.definition().name,
            "facade_only_prompt"
        );

        #[cfg(feature = "legacy-2024-11-05")]
        {
            let _: Option<fastmcp_rust::legacy_2024::CancelledParams> = None;
            let _: Option<fastmcp_rust::legacy_2024::InitializeParams> = None;
            let _: Option<fastmcp_rust::legacy_2024::Tool> = None;
        }
        let _: Option<fastmcp_rust::modern::FinalCallToolParams> = None;
        let _: Option<ResourceContent> = None;
    }
}

/// An Apps UI declaration belongs only to the final catalog projection.  The
/// legacy tool definition remains its exact legacy shape even when the Apps
/// facade feature is selected.
#[cfg(feature = "apps")]
#[tool(ui(resource_uri = "ui://apps.example.test/weather", visibility = ["model", "app"]))]
fn facade_apps_ui_metadata_tool() -> String {
    "weather".to_owned()
}

#[cfg(feature = "apps")]
#[test]
fn tool_apps_ui_metadata_is_final_only() {
    let handler = FacadeAppsUiMetadataTool;
    let metadata = handler
        .final_metadata()
        .expect("the Apps UI macro emits final tool metadata");
    assert_eq!(
        metadata.get("ui"),
        Some(&json!({
            "resourceUri": "ui://apps.example.test/weather",
            "visibility": ["model", "app"],
        }))
    );

    let legacy_tool = fastmcp_rust::serde_json::to_value(handler.definition())
        .expect("the legacy tool definition serializes");
    assert!(
        legacy_tool.get("_meta").is_none(),
        "Apps metadata must not be projected onto the exact legacy tool definition"
    );
}

#[cfg(feature = "apps")]
#[test]
fn facade_only_dual_era_apps_and_subscription_surfaces_compile() {
    use fastmcp_rust::{
        FinalAbsoluteUri, FinalCoreResult, HttpSubscriptionListener, MAX_MCP_APPS_CSP_DOMAIN_BYTES,
        MAX_MCP_APPS_CSP_DOMAINS_PER_DIRECTIVE, MAX_MCP_APPS_TOOL_VISIBILITY_ENTRIES,
        MAX_MCP_APPS_UI_METADATA_MEMBERS, MCP_APPS_DEPRECATED_RESOURCE_URI_METADATA_KEY,
        MCP_APPS_UI_METADATA_KEY, McpAppsDisplayMode, McpAppsLifecycleError, McpAppsMetadataError,
        McpAppsResourceBinding, McpAppsResourceBindingError, McpAppsResourceCsp,
        McpAppsResourceMetadata, McpAppsResourcePermission, McpAppsResourcePermissions,
        McpAppsResultProjectionError, McpAppsToolMetadata, McpAppsToolResult,
        McpAppsToolVisibility, McpAppsViewLifecycle, ModernHttpResponseStream,
        ModernHttpSubscriptionListenEvent, ModernHttpSubscriptionListener, RequestId, SseLimits,
        SubscriptionFilter, modern, prelude, project_final_core_tools_call_result,
    };

    let resource_uri = FinalAbsoluteUri::parse("ui://apps.example.test/view")
        .expect("facade must expose final absolute URI parsing");
    let metadata =
        McpAppsToolMetadata::try_new(Some(resource_uri), Some(vec![McpAppsToolVisibility::Model]))
            .expect("facade must expose valid final MCP Apps metadata admission");
    assert_eq!(
        metadata.effective_visibility(),
        &[McpAppsToolVisibility::Model]
    );
    assert!(
        metadata
            .to_open_metadata()
            .expect("facade metadata encoding must remain available")
            .entries()
            .contains_key(MCP_APPS_UI_METADATA_KEY)
    );

    let csp = McpAppsResourceCsp::try_new(
        Some(vec!["https://api.example.test".to_owned()]),
        None,
        None,
        None,
    )
    .expect("facade must expose bounded MCP Apps CSP admission");
    let permissions = McpAppsResourcePermissions {
        camera: Some(McpAppsResourcePermission {}),
        ..McpAppsResourcePermissions::default()
    };
    let resource_metadata = McpAppsResourceMetadata::try_new(
        Some(csp),
        Some(permissions),
        Some("apps.example.test".to_owned()),
        Some(true),
    )
    .expect("facade must expose bounded MCP Apps resource metadata admission");
    assert_eq!(resource_metadata.prefers_border, Some(true));
    let tool_result = McpAppsToolResult::try_new(Vec::new(), false, None)
        .expect("facade must expose bounded MCP Apps tool-result construction");
    assert!(tool_result.content.is_empty());
    assert_eq!(McpAppsDisplayMode::Pip, McpAppsDisplayMode::Pip);

    let mut lifecycle = McpAppsViewLifecycle::default();
    lifecycle
        .begin_initialize()
        .expect("final Apps lifecycle initialization must be admitted");
    lifecycle
        .initialization_succeeded()
        .expect("final Apps lifecycle initialization response must be admitted");
    lifecycle
        .admit_initialized()
        .expect("final Apps lifecycle notification must be admitted");
    assert!(lifecycle.permits_application_traffic());

    let non_ui_uri = FinalAbsoluteUri::parse("https://apps.example.test/view")
        .expect("only the URI scheme differs from the accepted metadata baseline");
    assert_eq!(
        McpAppsToolMetadata::try_new(Some(non_ui_uri), Some(vec![McpAppsToolVisibility::Model]),),
        Err(McpAppsMetadataError::ResourceUriMustUseUiPrefix),
        "changing only the resource URI scheme must be rejected"
    );

    let event = ModernHttpSubscriptionListenEvent::Acknowledged {
        accepted_filter: SubscriptionFilter::default(),
    };
    assert!(matches!(
        event,
        ModernHttpSubscriptionListenEvent::Acknowledged { .. }
    ));

    let _: fn(
        ModernHttpResponseStream,
        RequestId,
        SubscriptionFilter,
        SseLimits,
    ) -> Result<
        ModernHttpSubscriptionListener,
        fastmcp_rust::ModernHttpSubscriptionListenError,
    > = ModernHttpResponseStream::into_final_subscriptions_listener;
    let _: fn(&FinalCoreResult) -> Result<McpAppsToolResult, McpAppsResultProjectionError> =
        project_final_core_tools_call_result;
    let _: fn(&modern::FinalTool) -> Result<Option<McpAppsResourceBinding>, McpAppsMetadataError> =
        modern::FinalTool::mcp_apps_resource_binding;
    let _: fn(
        &modern::FinalResource,
    ) -> Result<Option<McpAppsResourceMetadata>, McpAppsMetadataError> =
        modern::FinalResource::mcp_apps_metadata;

    let _: Option<HttpSubscriptionListener<'static>> = None;
    let _: Option<modern::ModernHttpSubscriptionListenEvent> = None;
    let _: Option<modern::ModernHttpSubscriptionListener> = None;
    let _: Option<prelude::McpAppsToolMetadata> = None;
    let _: Option<prelude::McpAppsResourceBinding> = None;
    let _: Option<prelude::McpAppsResourceCsp> = None;
    let _: Option<prelude::McpAppsResourcePermission> = None;
    let _: Option<prelude::McpAppsResourcePermissions> = None;
    let _: Option<prelude::McpAppsToolResult> = None;
    let _: Option<prelude::McpAppsViewLifecycle> = None;
    let _: Option<prelude::HttpSubscriptionListener<'static>> = None;
    let _: Option<prelude::ModernHttpSubscriptionListenEvent> = None;
    let _: Option<prelude::ModernHttpSubscriptionListener> = None;
    let _: usize = prelude::MAX_MCP_APPS_CSP_DOMAINS_PER_DIRECTIVE;
    let _: usize = prelude::MAX_MCP_APPS_CSP_DOMAIN_BYTES;
    let _: usize = prelude::MAX_MCP_APPS_TOOL_VISIBILITY_ENTRIES;
    let _: usize = prelude::MAX_MCP_APPS_UI_METADATA_MEMBERS;
    assert_eq!(prelude::MCP_APPS_UI_METADATA_KEY, MCP_APPS_UI_METADATA_KEY);
    let _: Option<McpAppsLifecycleError> = None;
    let _: Option<McpAppsResourceBindingError> = None;
    let _: usize = MAX_MCP_APPS_UI_METADATA_MEMBERS;
    let _: usize = MAX_MCP_APPS_TOOL_VISIBILITY_ENTRIES;
    let _: usize = MAX_MCP_APPS_CSP_DOMAINS_PER_DIRECTIVE;
    let _: usize = MAX_MCP_APPS_CSP_DOMAIN_BYTES;
    assert_eq!(
        MCP_APPS_DEPRECATED_RESOURCE_URI_METADATA_KEY,
        "ui/resourceUri"
    );
}

#[cfg(all(feature = "apps", feature = "legacy-2024-11-05"))]
#[test]
fn facade_only_apps_with_legacy_companion_surfaces_compile() {
    use fastmcp_rust::legacy_2024;

    let _: Option<legacy_2024::LegacyReverseRequestHandlers> = None;
    let _: Option<legacy_2024::LegacySamplingRequestHandler> = None;
    let _: Option<legacy_2024::LegacyRootsRequestHandler> = None;
    let _: Option<fastmcp_rust::LegacySseHttpClient> = None;
}

#[cfg(feature = "proxy")]
#[test]
fn facade_only_typed_proxy_catalogs_compile_for_legacy_and_final_eras() {
    use fastmcp_rust::{
        CoreResult, FinalPrompt, FinalResource, FinalResourceTemplate, FinalTool, JsonValue,
        McpContext, McpResult, Prompt, ProtocolEra, ProxyClient, ProxyFinalCatalog,
        ProxyPromptCatalog, ProxyResourceCatalog, ProxyResourceTemplateCatalog, ProxyToolCatalog,
        ProxyTypedCatalog, Resource, ResourceTemplate, Tool,
    };

    let legacy = ProxyTypedCatalog {
        tools: ProxyToolCatalog::Legacy(Vec::<Tool>::new()),
        resources: ProxyResourceCatalog::Legacy(Vec::<Resource>::new()),
        resource_templates: ProxyResourceTemplateCatalog::Legacy(Vec::<ResourceTemplate>::new()),
        prompts: ProxyPromptCatalog::Legacy(Vec::<Prompt>::new()),
    };
    assert_eq!(
        legacy.era().expect("legacy catalog has one exact era"),
        ProtocolEra::Legacy2024
    );

    let final_catalog = ProxyTypedCatalog {
        tools: ProxyToolCatalog::Final(ProxyFinalCatalog::new(Vec::<FinalTool>::new())),
        resources: ProxyResourceCatalog::Final(ProxyFinalCatalog::new(Vec::<FinalResource>::new())),
        resource_templates: ProxyResourceTemplateCatalog::Final(ProxyFinalCatalog::new(Vec::<
            FinalResourceTemplate,
        >::new(
        ))),
        prompts: ProxyPromptCatalog::Final(ProxyFinalCatalog::new(Vec::<FinalPrompt>::new())),
    };
    assert_eq!(
        final_catalog
            .era()
            .expect("final catalog has one exact era"),
        ProtocolEra::Modern2026
    );
    assert!(final_catalog.final_tools().is_some());
    assert!(final_catalog.final_resources().is_some());
    assert!(final_catalog.final_resource_templates().is_some());
    assert!(final_catalog.final_prompts().is_some());

    let _: fn(&ProxyClient) -> McpResult<ProxyTypedCatalog> = ProxyClient::catalog_typed;
    let _: fn(&ProxyClient, &McpContext, &str, JsonValue) -> McpResult<CoreResult> =
        ProxyClient::call_tool_typed;
    let _: fn(&ProxyClient, &McpContext, &str) -> McpResult<CoreResult> =
        ProxyClient::read_resource_typed;
    let _: fn(
        &ProxyClient,
        &McpContext,
        &str,
        std::collections::HashMap<String, String>,
    ) -> McpResult<CoreResult> = ProxyClient::get_prompt_typed;
}

// ============================================================================
// #[tool] expansion tests
// ============================================================================

/// A simple greeting tool.
#[tool]
fn greet_simple(name: String) -> String {
    format!("Hello, {name}!")
}

#[test]
fn tool_definition_name_from_fn() {
    let handler = GreetSimple;
    let def = handler.definition();
    assert_eq!(def.name, "greet_simple");
}

#[test]
fn tool_definition_description_from_doc_comment() {
    let handler = GreetSimple;
    let def = handler.definition();
    assert_eq!(def.description, Some("A simple greeting tool.".to_string()));
}

#[test]
fn tool_definition_input_schema_string_param() {
    let handler = GreetSimple;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert!(props.contains_key("name"));
    assert_eq!(props["name"]["type"], "string");
}

#[test]
fn tool_definition_required_params() {
    let handler = GreetSimple;
    let def = handler.definition();
    let required = def.input_schema["required"].as_array().unwrap();
    assert!(required.iter().any(|v| v.as_str() == Some("name")));
}

#[test]
fn tool_call_returns_text_content() {
    let handler = GreetSimple;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"name": "World"})).unwrap();
    assert_eq!(result.len(), 1);
    let text = expect_text(&result[0]);
    assert_eq!(text, "Hello, World!");
}

// --- Tool with name override ---

/// This description should be used.
#[tool(name = "custom_name")]
fn tool_with_custom_name() -> String {
    "ok".to_string()
}

#[test]
fn tool_name_override() {
    let handler = ToolWithCustomName;
    let def = handler.definition();
    assert_eq!(def.name, "custom_name");
}

// --- Tool with description override ---

/// This doc comment should be ignored.
#[tool(description = "Explicit description")]
fn tool_with_desc_override() -> String {
    "ok".to_string()
}

#[test]
fn tool_description_override() {
    let handler = ToolWithDescOverride;
    let def = handler.definition();
    assert_eq!(def.description, Some("Explicit description".to_string()));
}

// --- Tool with no doc comment and no description attr ---

#[tool]
fn tool_no_description() -> String {
    "ok".to_string()
}

#[test]
fn tool_no_description_is_none() {
    let handler = ToolNoDescription;
    let def = handler.definition();
    assert!(def.description.is_none());
}

// --- Tool with multiple parameters (required + optional) ---

/// Adds two numbers.
#[tool]
fn add_numbers(a: i64, b: i64, label: Option<String>) -> String {
    let sum = a + b;
    match label {
        Some(l) => format!("{l}: {sum}"),
        None => format!("{sum}"),
    }
}

#[test]
fn tool_multiple_params_definition() {
    let handler = AddNumbers;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert!(props.contains_key("a"));
    assert!(props.contains_key("b"));
    assert!(props.contains_key("label"));
    assert_eq!(props["a"]["type"], "integer");
    assert_eq!(props["b"]["type"], "integer");
}

#[test]
fn tool_required_excludes_optional() {
    let handler = AddNumbers;
    let def = handler.definition();
    let required: Vec<&str> = def.input_schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(required.contains(&"a"));
    assert!(required.contains(&"b"));
    assert!(!required.contains(&"label"));
}

#[test]
fn tool_call_with_required_params() {
    let handler = AddNumbers;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"a": 3, "b": 4})).unwrap();
    let text = expect_text(&result[0]);
    assert_eq!(text, "7");
}

#[test]
fn tool_call_with_optional_param() {
    let handler = AddNumbers;
    let ctx = test_ctx();
    let result = handler
        .call(&ctx, json!({"a": 3, "b": 4, "label": "Sum"}))
        .unwrap();
    let text = expect_text(&result[0]);
    assert_eq!(text, "Sum: 7");
}

#[test]
fn tool_call_missing_required_param_errors() {
    let handler = AddNumbers;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"a": 3}));
    assert!(result.is_err());
}

#[test]
fn tool_call_optional_param_explicit_null_matches_omitted() {
    let handler = AddNumbers;
    let ctx = test_ctx();
    let result = handler
        .call(&ctx, json!({"a": 3, "b": 4, "label": null}))
        .unwrap();
    let text = expect_text(&result[0]);
    assert_eq!(text, "7");
}

#[test]
fn tool_call_required_param_still_rejects_null() {
    let handler = AddNumbers;
    let ctx = test_ctx();
    // `a` is i64, not Option<i64>: explicit null stays a loud type error.
    let result = handler.call(&ctx, json!({"a": null, "b": 4}));
    assert!(result.is_err());
}

// --- Tool with default parameter value ---

/// Greets with a default punctuation suffix.
#[tool(defaults(punctuation = "!"))]
fn greet_with_default(name: String, punctuation: String) -> String {
    format!("Hello, {name}{punctuation}")
}

#[test]
fn tool_default_param_not_required_and_in_schema() {
    let handler = GreetWithDefault;
    let def = handler.definition();
    let required = def.input_schema["required"].as_array().unwrap();
    assert!(!required.iter().any(|v| v.as_str() == Some("punctuation")));

    let props = def.input_schema["properties"].as_object().unwrap();
    assert_eq!(props["punctuation"]["default"], "!");
}

#[test]
fn tool_call_uses_default_param_when_missing() {
    let handler = GreetWithDefault;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"name": "World"})).unwrap();
    let text = expect_text(&result[0]);
    assert_eq!(text, "Hello, World!");
}

// --- Tool with a defaulted Option parameter ---

/// Echoes with a defaulted optional suffix.
#[tool(defaults(suffix = "?"))]
fn echo_defaulted_option(msg: String, suffix: Option<String>) -> String {
    format!("{msg}{}", suffix.unwrap_or_default())
}

#[test]
fn tool_defaulted_option_omitted_uses_default() {
    let handler = EchoDefaultedOption;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"msg": "hi"})).unwrap();
    assert_eq!(expect_text(&result[0]), "hi?");
}

#[test]
fn tool_defaulted_option_explicit_null_uses_default() {
    let handler = EchoDefaultedOption;
    let ctx = test_ctx();
    // null is the wire spelling of "omitted", so the default applies.
    let result = handler
        .call(&ctx, json!({"msg": "hi", "suffix": null}))
        .unwrap();
    assert_eq!(expect_text(&result[0]), "hi?");
}

#[test]
fn tool_defaulted_option_value_wins() {
    let handler = EchoDefaultedOption;
    let ctx = test_ctx();
    let result = handler
        .call(&ctx, json!({"msg": "hi", "suffix": "!"}))
        .unwrap();
    assert_eq!(expect_text(&result[0]), "hi!");
}

// --- Tool with context parameter ---

/// Tool that uses context.
#[tool]
fn tool_with_context(ctx: &McpContext, msg: String) -> String {
    // Just verify we got a valid context
    let _id = ctx.request_id();
    format!("ctx:{msg}")
}

#[test]
fn tool_with_context_call() {
    let handler = ToolWithContext;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"msg": "hello"})).unwrap();
    let text = expect_text(&result[0]);
    assert_eq!(text, "ctx:hello");
}

#[test]
fn tool_with_context_schema_excludes_ctx() {
    let handler = ToolWithContext;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    // Context should not appear in schema
    assert!(!props.contains_key("ctx"));
    assert!(props.contains_key("msg"));
}

// --- Tool returning Vec<Content> directly ---

/// Returns multiple content items.
#[tool]
fn multi_content() -> Vec<Content> {
    vec![
        Content::Text {
            text: "first".to_string(),
        },
        Content::Text {
            text: "second".to_string(),
        },
    ]
}

#[test]
fn tool_returning_vec_content() {
    let handler = MultiContent;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({})).unwrap();
    assert_eq!(result.len(), 2);
}

// --- Tool returning McpResult<String> ---

/// Fallible tool.
#[tool]
fn fallible_tool(succeed: bool) -> McpResult<String> {
    if succeed {
        Ok("success".to_string())
    } else {
        Err(fastmcp_rust::McpError::internal_error("failed"))
    }
}

#[test]
fn tool_result_ok() {
    let handler = FallibleTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"succeed": true})).unwrap();
    let text = expect_text(&result[0]);
    assert_eq!(text, "success");
}

#[test]
fn tool_result_err() {
    let handler = FallibleTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"succeed": false}));
    assert!(result.is_err());
}

// --- Tool with no parameters ---

/// Returns a fixed value.
#[tool]
fn no_params_tool() -> String {
    "fixed".to_string()
}

#[test]
fn tool_no_params_empty_schema() {
    let handler = NoParamsTool;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert!(props.is_empty());
    let required = def.input_schema["required"].as_array().unwrap();
    assert_eq!(required.len(), 0);
}

#[test]
fn tool_no_params_call() {
    let handler = NoParamsTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({})).unwrap();
    let text = expect_text(&result[0]);
    assert_eq!(text, "fixed");
}

// --- Tool with timeout ---

/// Tool with custom timeout.
#[tool(timeout = "30s")]
fn timed_tool() -> String {
    "ok".to_string()
}

#[test]
fn tool_timeout_30s() {
    let handler = TimedTool;
    let timeout = handler.timeout();
    assert_eq!(timeout, Some(std::time::Duration::from_secs(30)));
}

// --- Tool with complex timeout ---

/// Tool with compound timeout.
#[tool(timeout = "1h30m")]
fn long_timed_tool() -> String {
    "ok".to_string()
}

#[test]
fn tool_timeout_compound() {
    let handler = LongTimedTool;
    let timeout = handler.timeout();
    assert_eq!(timeout, Some(std::time::Duration::from_mins(90)));
}

// --- Tool with bool parameter ---

/// Check bool schema.
#[tool]
fn bool_tool(flag: bool) -> String {
    format!("{flag}")
}

#[test]
fn tool_bool_param_schema() {
    let handler = BoolTool;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert_eq!(props["flag"]["type"], "boolean");
}

// --- Tool with Vec parameter ---

/// Check Vec schema.
#[tool]
fn vec_tool(items: Vec<String>) -> String {
    items.join(", ")
}

#[test]
fn tool_vec_param_schema() {
    let handler = VecTool;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert_eq!(props["items"]["type"], "array");
    assert_eq!(props["items"]["items"]["type"], "string");
}

#[test]
fn tool_vec_param_call() {
    let handler = VecTool;
    let ctx = test_ctx();
    let result = handler
        .call(&ctx, json!({"items": ["a", "b", "c"]}))
        .unwrap();
    let text = expect_text(&result[0]);
    assert_eq!(text, "a, b, c");
}

// --- Tool with f64 parameter ---

/// Check numeric schema.
#[tool]
fn float_tool(value: f64) -> String {
    format!("{value:.2}")
}

#[test]
fn tool_float_param_schema() {
    let handler = FloatTool;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert_eq!(props["value"]["type"], "number");
}

// --- Async tool ---

/// An async greeting tool.
#[tool]
async fn async_greet(name: String) -> String {
    format!("Hello async, {name}!")
}

#[test]
fn async_tool_definition() {
    let handler = AsyncGreet;
    let def = handler.definition();
    assert_eq!(def.name, "async_greet");
    assert_eq!(def.description, Some("An async greeting tool.".to_string()));
}

#[test]
fn async_tool_call() {
    let handler = AsyncGreet;
    let ctx = test_ctx();
    let result = expect_outcome_ok(run_outcome(async move {
        handler.call_async(&ctx, json!({"name": "Rust"})).await
    }));
    let text = expect_text(&result[0]);
    assert_eq!(text, "Hello async, Rust!");
}

// --- Async tool with context ---

/// Async tool with context.
#[tool]
async fn async_ctx_tool(ctx: &McpContext, val: String) -> String {
    let _id = ctx.request_id();
    format!("async:{val}")
}

#[test]
fn async_tool_with_context_call() {
    let handler = AsyncCtxTool;
    let ctx = test_ctx();
    let result = expect_outcome_ok(run_outcome(async move {
        handler.call_async(&ctx, json!({"val": "test"})).await
    }));
    let text = expect_text(&result[0]);
    assert_eq!(text, "async:test");
}

// --- Tool default trait methods ---

#[test]
fn tool_default_icon_is_none() {
    let handler = GreetSimple;
    assert!(handler.icon().is_none());
}

#[test]
fn tool_default_version_is_none() {
    let handler = GreetSimple;
    assert!(handler.version().is_none());
}

#[test]
fn tool_default_tags_are_empty() {
    let handler = GreetSimple;
    assert_eq!(handler.tags().len(), 0);
}

#[test]
fn tool_default_annotations_is_none() {
    let handler = GreetSimple;
    assert!(handler.annotations().is_none());
}

#[test]
fn tool_default_output_schema_is_none() {
    let handler = GreetSimple;
    assert!(handler.output_schema().is_none());
}

#[test]
fn tool_default_timeout_is_none() {
    let handler = GreetSimple;
    assert!(handler.timeout().is_none());
}

// --- Tool with output_schema ---

/// Tool with explicit output schema.
#[tool(output_schema = serde_json::json!({
    "type": "object",
    "properties": {
        "result": { "type": "string" },
        "count": { "type": "integer" }
    },
    "required": ["result"]
}))]
fn tool_with_output_schema(input: String) -> String {
    format!("processed: {input}")
}

#[test]
fn tool_output_schema_is_set() {
    let handler = ToolWithOutputSchema;
    let schema = handler.output_schema();
    assert!(schema.is_some());
    let schema = schema.unwrap();
    assert_eq!(schema["type"], "object");
    let props = schema["properties"].as_object().unwrap();
    assert!(props.contains_key("result"));
    assert!(props.contains_key("count"));
}

#[test]
fn tool_output_schema_in_definition() {
    let handler = ToolWithOutputSchema;
    let def = handler.definition();
    assert!(def.output_schema.is_some());
    let schema = def.output_schema.unwrap();
    assert_eq!(schema["type"], "object");
}

// --- Final complete tool result projection ---

fn final_tool_payload(text: &str) -> CompleteResult<FinalCallToolResult> {
    CompleteResult::new(
        FinalCallToolResult {
            content: vec![
                ContentBlock::text(text),
                ContentBlock::image("aGVsbG8=", "image/png").expect("image content"),
                ContentBlock::audio("aGVsbG8=", "audio/ogg").expect("audio content"),
                ContentBlock::resource(
                    "final://tool/embedded-resource",
                    "embedded",
                    Some("text/plain".to_string()),
                )
                .expect("embedded resource content"),
            ],
            is_error: false,
            structured_content: None,
        },
        final_result_meta(),
    )
}

#[tool(output_schema = serde_json::json!({
    "type": "object",
    "properties": { "answer": { "type": "string" } },
    "required": ["answer"]
}))]
fn final_complete_tool_direct() -> CompleteResult<FinalCallToolResult> {
    final_tool_payload("direct")
}

#[tool]
fn final_complete_tool_result() -> Result<CompleteResult<FinalCallToolResult>, McpError> {
    Ok(final_tool_payload("result"))
}

#[tool]
fn final_complete_tool_mcp_result() -> McpResult<CompleteResult<FinalCallToolResult>> {
    Ok(final_tool_payload("mcp-result"))
}

#[test]
fn tool_final_complete_results_project_exact_legacy_content_and_output_schema() {
    let direct = FinalCompleteToolDirect;
    assert_eq!(
        direct.output_schema(),
        Some(json!({
            "type": "object",
            "properties": { "answer": { "type": "string" } },
            "required": ["answer"]
        }))
    );
    assert_eq!(direct.definition().output_schema, direct.output_schema());

    let ctx = test_ctx();
    let handlers: [Box<dyn ToolHandler>; 3] = [
        Box::new(direct),
        Box::new(FinalCompleteToolResult),
        Box::new(FinalCompleteToolMcpResult),
    ];

    for (handler, expected_text) in handlers.into_iter().zip(["direct", "result", "mcp-result"]) {
        let content = handler
            .call(&ctx, json!({}))
            .expect("final complete result projects");
        assert_eq!(content.len(), 4);
        assert_eq!(expect_text(&content[0]), expected_text);
        assert!(matches!(
            &content[1],
            Content::Image { data, mime_type } if data == "aGVsbG8=" && mime_type == "image/png"
        ));
        assert!(matches!(
            &content[2],
            Content::Audio { data, mime_type } if data == "aGVsbG8=" && mime_type == "audio/ogg"
        ));
        let Content::Resource { resource } = &content[3] else {
            panic!("embedded final resource must preserve the legacy content variant");
        };
        assert_eq!(resource.uri.as_str(), "final://tool/embedded-resource");
        assert_eq!(resource.mime_type.as_deref(), Some("text/plain"));
        assert_eq!(resource.text.as_deref(), Some("embedded"));
        assert!(resource.blob.is_none());
    }
}

#[tool]
fn final_complete_tool_with_resource_link() -> CompleteResult<FinalCallToolResult> {
    CompleteResult::new(
        FinalCallToolResult {
            content: vec![
                ContentBlock::resource_link("final://tool/embedded-resource", "embedded")
                    .expect("resource link content"),
            ],
            is_error: false,
            structured_content: None,
        },
        final_result_meta(),
    )
}

#[test]
fn tool_final_complete_resource_link_rejects_lossy_legacy_projection() {
    let error = FinalCompleteToolWithResourceLink
        .call(&test_ctx(), json!({}))
        .expect_err("changing only to a resource link must reject lossy legacy projection");

    assert_eq!(error.code, fastmcp_rust::McpErrorCode::InternalError);
    assert_eq!(
        error.message,
        "final tool content cannot be projected exactly through the legacy handler"
    );
}

// --- Final tool outcome algebra ---

fn final_tool_outcome(mode: &str) -> FinalToolOutcome {
    match mode {
        "complete" => FinalToolOutcome::Complete(final_tool_payload("outcome-complete")),
        "input-required" => FinalToolOutcome::InputRequired(
            InputRequiredResult::new(None, Some("retry-state".to_string()), final_result_meta())
                .expect("request state makes input-required valid"),
        ),
        #[cfg(feature = "tasks")]
        "create-task" => FinalToolOutcome::CreateTask {
            work_descriptor: FinalTaskWorkDescriptor::new(json!({
                "operation": "macro-expansion-final-task"
            }))
            .expect("non-null final task work descriptor"),
            status_message: Some("queued".to_string()),
        },
        _ => unreachable!("test calls only supported final tool outcome modes"),
    }
}

fn facade_final_tool_outcome_request(
    tool_name: &str,
    mode: &str,
    declare_tasks: bool,
) -> JsonRpcRequest {
    let client_capabilities = if declare_tasks {
        json!({
            "extensions": { "io.modelcontextprotocol/tasks": {} },
        })
    } else {
        json!({})
    };
    JsonRpcRequest::new(
        "tools/call",
        Some(json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": client_capabilities,
            },
            "name": tool_name,
            "arguments": { "mode": mode },
        })),
        64_i64,
    )
}

fn facade_final_inbound(connection: &ModernConnection) -> InboundRequestContext {
    InboundRequestContext::with_modern_connection(
        Cx::for_testing(),
        64,
        InboundRequestTransport::Memory,
        connection,
    )
}

#[cfg(feature = "tasks")]
struct NoopFinalTaskSupervisor;

#[cfg(feature = "tasks")]
impl ApplicationTaskSupervisor for NoopFinalTaskSupervisor {
    fn resume<'a>(
        &'a self,
        _cx: &'a Cx,
        _handoff: FinalTaskSupervisorHandoff,
    ) -> FinalTaskSupervisorFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

#[cfg_attr(feature = "tasks", tool(tasks))]
#[cfg_attr(not(feature = "tasks"), tool)]
fn final_tool_outcome_direct(mode: String) -> fastmcp_rust::FinalToolOutcome {
    final_tool_outcome(&mode)
}

#[tool]
fn final_tool_outcome_result(mode: String) -> Result<fastmcp_rust::FinalToolOutcome, McpError> {
    if mode == "error" {
        return Err(McpError::invalid_params("outcome result rejected"));
    }
    Ok(final_tool_outcome(&mode))
}

#[tool]
fn final_tool_outcome_mcp_result(mode: String) -> McpResult<fastmcp_rust::FinalToolOutcome> {
    Ok(final_tool_outcome(&mode))
}

#[tool]
async fn final_tool_outcome_async_input_required(
    ctx: &McpContext,
    cancel_request: bool,
) -> fastmcp_rust::FinalToolOutcome {
    if cancel_request {
        ctx.cx().set_cancel_requested(true);
    }
    final_tool_outcome("input-required")
}

#[test]
fn tool_final_outcome_variants_reach_the_final_outcome_hook() {
    let ctx = test_ctx();
    assert_eq!(
        FinalToolOutcomeDirect.declares_final_tasks(),
        cfg!(feature = "tasks"),
        "the explicit Tasks opt-in is only emitted when its macro feature is enabled"
    );
    assert!(
        !FinalToolOutcomeResult.declares_final_tasks(),
        "canonical final outcomes do not declare final Tasks without the opt-in"
    );
    let handlers: [Box<dyn ToolHandler>; 3] = [
        Box::new(FinalToolOutcomeDirect),
        Box::new(FinalToolOutcomeResult),
        Box::new(FinalToolOutcomeMcpResult),
    ];

    for handler in handlers {
        assert!(
            handler.declares_final_mrtr(),
            "every canonical final-outcome return algebra can mint InputRequired"
        );
        assert!(
            handler.call(&ctx, json!({"mode": "complete"})).is_err(),
            "the disjoint final outcome must not leak through the legacy hook"
        );

        match handler
            .call_final_outcome(&ctx, json!({"mode": "complete"}))
            .expect("complete outcome is preserved")
        {
            FinalToolOutcome::Complete(result) => {
                let ContentBlock::Text { text, .. } = &result.payload.content[0] else {
                    panic!("complete outcome keeps text content");
                };
                assert_eq!(text, "outcome-complete");
            }
            _ => panic!("expected complete final tool outcome"),
        }

        assert!(matches!(
            handler
                .call_final_outcome(&ctx, json!({"mode": "input-required"}))
                .expect("input-required outcome is preserved"),
            FinalToolOutcome::InputRequired(_)
        ));
        #[cfg(feature = "tasks")]
        assert!(matches!(
            handler
                .call_final_outcome(&ctx, json!({"mode": "create-task"}))
                .expect("task creation outcome is preserved"),
            FinalToolOutcome::CreateTask {
                work_descriptor,
                status_message: Some(ref message),
            } if message == "queued"
                && work_descriptor.as_value() == &json!({
                    "operation": "macro-expansion-final-task"
                })
        ));
    }
}

#[test]
fn facade_final_tool_outcome_encodes_input_required_through_modern_wire() {
    let connection = ModernConnection::new();
    let server = Server::new("facade-final-outcome", "1.0.0")
        .tool(FinalToolOutcomeResult)
        .build();
    let response = server
        .dispatch_stateless(
            &facade_final_inbound(&connection),
            &facade_final_tool_outcome_request(
                "final_tool_outcome_result",
                "input-required",
                false,
            ),
        )
        .expect("facade final tools/call returns an input-required wire response");
    let result = response
        .result
        .expect("input-required final tools/call has a result");

    assert!(response.error.is_none());
    assert_eq!(result["resultType"], "input_required");
    let request_state = result["requestState"]
        .as_str()
        .expect("the framework emits an opaque MRTR continuation state");
    assert!(!request_state.is_empty());
    assert_ne!(
        request_state, "retry-state",
        "handler-controlled state must not cross the framework MRTR boundary"
    );
}

#[cfg(feature = "tasks")]
#[test]
fn facade_final_tool_outcome_creates_task_through_modern_wire() {
    let connection = ModernConnection::new();
    let notifications = std::sync::Arc::new(AtomicUsize::new(0));
    let emitted_notifications = std::sync::Arc::clone(&notifications);
    let runtime = FinalTaskRuntime::in_memory(
        FinalTaskRuntimeConfig::new(60_000, None).expect("valid final task policy"),
        std::sync::Arc::new(move |_| {
            emitted_notifications.fetch_add(1, Ordering::SeqCst);
        }),
    );
    let service_runner = runtime
        .install_task_service(1, std::sync::Arc::new(NoopFinalTaskSupervisor))
        .expect("the facade installs an application-owned task service");
    let service_cx = Cx::for_testing();
    let mut running_service = Box::pin(service_runner.run(&service_cx));
    let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        Future::poll(running_service.as_mut(), &mut task_cx),
        Poll::Pending
    ));
    let server = Server::new("facade-final-task", "1.0.0")
        .tool(FinalToolOutcomeDirect)
        .final_tasks(runtime.clone())
        .expect("final Tasks install through the facade builder")
        .build();
    let response = server
        .dispatch_stateless(
            &facade_final_inbound(&connection),
            &facade_final_tool_outcome_request("final_tool_outcome_direct", "create-task", true),
        )
        .expect("task-capable facade final tools/call returns a wire response");
    assert!(response.error.is_none());
    let result = response.result.expect("task final tools/call has a result");
    assert_eq!(result["resultType"], "task");
    assert_eq!(result["status"], "working");
    assert_eq!(result["statusMessage"], "queued");
    let task_id = fastmcp_rust::FinalTaskId::parse(
        result["taskId"]
            .as_str()
            .expect("task creation wire result includes its public task identifier"),
    )
    .expect("task creation wire result has a valid public task identifier");
    let retained = runtime
        .get_task(&task_id)
        .expect("the created task remains readable from the caller-owned runtime");
    let mut durable_task = result.clone();
    durable_task
        .as_object_mut()
        .expect("task result is an object")
        .remove("resultType");
    assert_eq!(
        serde_json::to_value(retained.task).expect("created task serializes"),
        durable_task,
        "the public task result is the exact durable caller-owned task state"
    );
    assert_eq!(
        notifications.load(Ordering::SeqCst),
        1,
        "creation advertises one durable task state transition"
    );
}

#[cfg(feature = "tasks")]
#[test]
fn facade_final_tool_outcome_rejects_declared_task_without_client_capability() {
    let connection = ModernConnection::new();
    let notifications = std::sync::Arc::new(AtomicUsize::new(0));
    let emitted_notifications = std::sync::Arc::clone(&notifications);
    let task_store = std::sync::Arc::new(InMemoryFinalTaskStore::default());
    let runtime = FinalTaskRuntime::new(
        task_store.clone(),
        FinalTaskRuntimeConfig::new(60_000, None).expect("valid final task policy"),
        std::sync::Arc::new(move |_| {
            emitted_notifications.fetch_add(1, Ordering::SeqCst);
        }),
    );
    let service_runner = runtime
        .install_task_service(1, std::sync::Arc::new(NoopFinalTaskSupervisor))
        .expect("the facade installs an application-owned task service");
    let service_cx = Cx::for_testing();
    let mut running_service = Box::pin(service_runner.run(&service_cx));
    let mut task_cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        Future::poll(running_service.as_mut(), &mut task_cx),
        Poll::Pending
    ));
    let retained_task = runtime
        .create_task_with_work(
            FinalTaskWorkDescriptor::new(json!({
                "operation": "retained-state-for-capability-rejection"
            }))
            .expect("non-null retained task work descriptor"),
            Some("retained before capability rejection".to_owned()),
        )
        .expect("the ready caller-owned runtime creates retained work")
        .task;
    let retained_task_id = retained_task.base().task_id.clone();
    let state_before = serde_json::to_value(
        runtime
            .get_task(&retained_task_id)
            .expect("read retained task before the capability rejection")
            .task,
    )
    .expect("retained task serializes before the capability rejection");
    let task_count_before = task_store.task_count();
    let notifications_before = notifications.load(Ordering::SeqCst);
    let server = Server::new("facade-final-task", "1.0.0")
        .tool(FinalToolOutcomeDirect)
        .final_tasks(runtime.clone())
        .expect("final Tasks install through the facade builder")
        .build();
    let response = server
        .dispatch_stateless(
            &facade_final_inbound(&connection),
            &facade_final_tool_outcome_request("final_tool_outcome_direct", "create-task", false),
        )
        .expect("missing task capability returns a JSON-RPC error response");

    assert!(response.result.is_none());
    let error = response
        .error
        .expect("missing task capability returns the final capability error");
    assert_eq!(
        error.code,
        MISSING_REQUIRED_CLIENT_CAPABILITY_ERROR_CODE.into()
    );
    assert_eq!(
        error.data,
        Some(json!({
            "requiredCapabilities": {
                "extensions": { "io.modelcontextprotocol/tasks": {} },
            },
        }))
    );
    assert_eq!(
        serde_json::to_value(
            runtime
                .get_task(&retained_task_id)
                .expect("read retained task after the capability rejection")
                .task,
        )
        .expect("retained task serializes after the capability rejection"),
        state_before,
        "removing only the client Tasks capability leaves durable task state unchanged"
    );
    assert_eq!(
        task_store.task_count(),
        task_count_before,
        "removing only the client Tasks capability cannot add another durable task"
    );
    assert_eq!(
        notifications.load(Ordering::SeqCst),
        notifications_before,
        "removing only the client Tasks capability emits no task transition"
    );
}

#[cfg(not(feature = "tasks"))]
#[test]
fn facade_final_tool_outcome_rejects_undeclared_task_before_router_admission() {
    let ctx = test_ctx();
    let outcome = run_outcome(async move {
        FinalToolOutcomeDirect
            .call_final_outcome_async(&ctx, json!({"mode": "create-task"}))
            .await
    });

    match outcome {
        Outcome::Err(error) => {
            assert_eq!(error.code, fastmcp_rust::McpErrorCode::InvalidRequest);
            assert_eq!(
                error.message,
                "tool returned CreateTask without declaring final Tasks capability"
            );
        }
        Outcome::Ok(_) | Outcome::Cancelled(_) | Outcome::Panicked(_) => {
            panic!("undeclared CreateTask must be rejected before router admission");
        }
    }
}

#[test]
fn tool_final_outcome_result_preserves_mcp_error() {
    let error =
        match FinalToolOutcomeResult.call_final_outcome(&test_ctx(), json!({"mode": "error"})) {
            Err(error) => error,
            Ok(_) => panic!("the handler's McpError must cross the final outcome hook unchanged"),
        };

    assert_eq!(error.code, fastmcp_rust::McpErrorCode::InvalidParams);
    assert_eq!(error.message, "outcome result rejected");
}

#[test]
fn async_tool_final_outcome_request_hook_rejects_pre_cancelled_request() {
    let handler = FinalToolOutcomeAsyncInputRequired;
    let request_cx = Cx::for_testing();
    request_cx.set_cancel_requested(true);
    let ctx = McpContext::new(request_cx.clone(), 62);
    let outcome = run_outcome(async move {
        handler
            .call_final_outcome_async_in_request(
                &ctx,
                &request_cx,
                json!({"cancel_request": false}),
            )
            .await
    });

    assert!(matches!(outcome, Outcome::Cancelled(_)));
}

#[test]
fn async_tool_final_outcome_request_hook_discards_post_handler_cancelled_outcome() {
    let handler = FinalToolOutcomeAsyncInputRequired;
    let request_cx = Cx::for_testing();
    let ctx = McpContext::new(request_cx.clone(), 63);
    let outcome = run_outcome(async move {
        handler
            .call_final_outcome_async_in_request(&ctx, &request_cx, json!({"cancel_request": true}))
            .await
    });

    assert!(matches!(outcome, Outcome::Cancelled(_)));
}

// --- Tool with HashMap parameter ---

/// Tool with HashMap parameter.
#[tool]
fn map_tool(metadata: std::collections::HashMap<String, String>) -> String {
    metadata
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[test]
fn tool_hashmap_param_schema() {
    let handler = MapTool;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert_eq!(props["metadata"]["type"], "object");
    assert_eq!(props["metadata"]["additionalProperties"]["type"], "string");
}

#[test]
fn tool_hashmap_param_call() {
    let handler = MapTool;
    let ctx = test_ctx();
    let result = handler
        .call(&ctx, json!({"metadata": {"key1": "val1", "key2": "val2"}}))
        .unwrap();
    let text = expect_text(&result[0]);
    assert!(text.contains("key1=val1") || text.contains("key2=val2"));
}

// --- Tool with u32/i32 parameters ---

/// Tool with unsigned integer parameter.
#[tool]
fn uint_tool(count: u32) -> String {
    format!("count: {count}")
}

#[test]
fn tool_u32_param_schema() {
    let handler = UintTool;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert_eq!(props["count"]["type"], "integer");
}

#[test]
fn tool_u32_param_call() {
    let handler = UintTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"count": 42})).unwrap();
    let text = expect_text(&result[0]);
    assert_eq!(text, "count: 42");
}

/// Tool with signed integer parameter.
#[tool]
fn int_tool(value: i32) -> String {
    format!("value: {value}")
}

#[test]
fn tool_i32_param_schema() {
    let handler = IntTool;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert_eq!(props["value"]["type"], "integer");
}

#[test]
fn tool_i32_param_call_positive() {
    let handler = IntTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"value": 100})).unwrap();
    let text = expect_text(&result[0]);
    assert_eq!(text, "value: 100");
}

#[test]
fn tool_i32_param_call_negative() {
    let handler = IntTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"value": -50})).unwrap();
    let text = expect_text(&result[0]);
    assert_eq!(text, "value: -50");
}

// --- Tool with nested Vec ---

/// Tool with nested Vec parameter.
#[tool]
fn nested_vec_tool(matrix: Vec<Vec<i32>>) -> String {
    let rows: Vec<String> = matrix
        .iter()
        .map(|row| {
            row.iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(",")
        })
        .collect();
    rows.join("; ")
}

#[test]
fn tool_nested_vec_param_schema() {
    let handler = NestedVecTool;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert_eq!(props["matrix"]["type"], "array");
    assert_eq!(props["matrix"]["items"]["type"], "array");
    assert_eq!(props["matrix"]["items"]["items"]["type"], "integer");
}

#[test]
fn tool_nested_vec_param_call() {
    let handler = NestedVecTool;
    let ctx = test_ctx();
    let result = handler
        .call(&ctx, json!({"matrix": [[1, 2], [3, 4]]}))
        .unwrap();
    let text = expect_text(&result[0]);
    assert_eq!(text, "1,2; 3,4");
}

// --- Tool with multiple optional parameters ---

/// Tool with all optional parameters.
#[tool]
fn all_optional_tool(a: Option<String>, b: Option<i32>, c: Option<bool>) -> String {
    let a_str = a.unwrap_or_else(|| "none".to_string());
    let b_str = b
        .map(|n| n.to_string())
        .unwrap_or_else(|| "none".to_string());
    let c_str = c
        .map(|b| b.to_string())
        .unwrap_or_else(|| "none".to_string());
    format!("a={a_str}, b={b_str}, c={c_str}")
}

#[test]
fn tool_all_optional_none_required() {
    let handler = AllOptionalTool;
    let def = handler.definition();
    let required = def.input_schema["required"].as_array().unwrap();
    assert_eq!(required.len(), 0);
}

#[test]
fn tool_all_optional_call_empty() {
    let handler = AllOptionalTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({})).unwrap();
    let text = expect_text(&result[0]);
    assert_eq!(text, "a=none, b=none, c=none");
}

#[test]
fn tool_optional_param_schema_is_nullable_union() {
    let handler = AllOptionalTool;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert_eq!(props["a"]["type"], json!(["string", "null"]));
    assert_eq!(props["b"]["type"], json!(["integer", "null"]));
    assert_eq!(props["c"]["type"], json!(["boolean", "null"]));
    // Optional params stay out of `required` even though they admit null.
    let required = def.input_schema["required"].as_array().unwrap();
    assert_eq!(required.len(), 0);
}

#[test]
fn tool_all_optional_call_explicit_null_is_omitted() {
    let handler = AllOptionalTool;
    let ctx = test_ctx();
    let result = handler
        .call(&ctx, json!({"a": null, "b": 42, "c": null}))
        .unwrap();
    let text = expect_text(&result[0]);
    assert_eq!(text, "a=none, b=42, c=none");
}

#[test]
fn tool_all_optional_call_partial() {
    let handler = AllOptionalTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"b": 42})).unwrap();
    let text = expect_text(&result[0]);
    assert_eq!(text, "a=none, b=42, c=none");
}

#[test]
fn tool_all_optional_call_full() {
    let handler = AllOptionalTool;
    let ctx = test_ctx();
    let result = handler
        .call(&ctx, json!({"a": "hello", "b": 42, "c": true}))
        .unwrap();
    let text = expect_text(&result[0]);
    assert_eq!(text, "a=hello, b=42, c=true");
}

// --- Tool returning unit ---

/// Tool that returns nothing.
#[tool]
fn unit_tool() {}

#[test]
fn tool_unit_return_empty_content() {
    let handler = UnitTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({})).unwrap();
    assert!(result.is_empty());
}

// --- Async tool with Result return ---

/// Async tool returning Result.
#[tool]
async fn async_fallible_tool(succeed: bool) -> McpResult<String> {
    if succeed {
        Ok("async success".to_string())
    } else {
        Err(fastmcp_rust::McpError::internal_error("async failed"))
    }
}

#[test]
fn async_fallible_tool_ok() {
    let handler = AsyncFallibleTool;
    let ctx = test_ctx();
    let result = expect_outcome_ok(run_outcome(async move {
        handler.call_async(&ctx, json!({"succeed": true})).await
    }));
    let text = expect_text(&result[0]);
    assert_eq!(text, "async success");
}

#[test]
fn async_fallible_tool_err() {
    let handler = AsyncFallibleTool;
    let ctx = test_ctx();
    let outcome =
        run_outcome(async move { handler.call_async(&ctx, json!({"succeed": false})).await });
    assert!(matches!(outcome, Outcome::Err(_)));
}

// ============================================================================
// #[tool] annotations and version tests
// ============================================================================

/// A read-only, idempotent tool with a version.
#[tool(
    name = "annotated_tool",
    description = "Tool with annotations",
    version = "2.1.0",
    annotations(read_only, idempotent)
)]
fn annotated_tool(_ctx: &McpContext) -> String {
    "read-only result".to_string()
}

#[test]
fn tool_annotations_read_only_and_idempotent() {
    let handler = AnnotatedTool;
    let def = handler.definition();
    assert_eq!(def.name, "annotated_tool");
    assert_eq!(def.version.as_deref(), Some("2.1.0"));
    let ann = def.annotations.expect("annotations should be Some");
    assert_eq!(ann.read_only, Some(true));
    assert_eq!(ann.idempotent, Some(true));
    assert_eq!(ann.destructive, None);
    assert_eq!(ann.open_world_hint, None);
}

/// A destructive tool.
#[tool(annotations(destructive))]
fn destructive_tool(_ctx: &McpContext) -> String {
    "destroyed".to_string()
}

#[test]
fn tool_annotations_destructive_only() {
    let handler = DestructiveTool;
    let def = handler.definition();
    let ann = def.annotations.expect("annotations should be Some");
    assert_eq!(ann.destructive, Some(true));
    assert_eq!(ann.read_only, None);
    assert_eq!(ann.idempotent, None);
}

/// Tool with all annotations set.
#[tool(annotations(read_only, idempotent, destructive, open_world_hint = true))]
fn fully_annotated(_ctx: &McpContext) -> String {
    "full".to_string()
}

#[test]
fn tool_annotations_all_fields() {
    let handler = FullyAnnotated;
    let def = handler.definition();
    let ann = def.annotations.expect("annotations should be Some");
    assert_eq!(ann.read_only, Some(true));
    assert_eq!(ann.idempotent, Some(true));
    assert_eq!(ann.destructive, Some(true));
    assert_eq!(ann.open_world_hint, Some(true));
}

/// Tool with version only, no annotations.
#[tool(version = "0.3.0")]
fn versioned_tool(_ctx: &McpContext) -> String {
    "v0.3.0".to_string()
}

#[test]
fn tool_version_without_annotations() {
    let handler = VersionedTool;
    let def = handler.definition();
    assert_eq!(def.version.as_deref(), Some("0.3.0"));
    assert!(def.annotations.is_none());
}

/// Tool with no annotations and no version (backwards compat).
#[tool]
fn plain_tool(_ctx: &McpContext) -> String {
    "plain".to_string()
}

#[test]
fn tool_no_annotations_no_version_stays_none() {
    let handler = PlainTool;
    let def = handler.definition();
    assert!(def.version.is_none());
    assert!(def.annotations.is_none());
    assert!(def.icon.is_none());
}

/// Tool with an explicit icon source.
#[tool(icon = "https://example.com/tool.png")]
fn icon_tool(_ctx: &McpContext) -> String {
    "icon".to_string()
}

#[test]
fn tool_icon_is_advertised_on_definition() {
    let handler = IconTool;
    let def = handler.definition();
    assert_eq!(
        def.icon.as_ref().and_then(|icon| icon.src.as_deref()),
        Some("https://example.com/tool.png")
    );
    let final_icons = handler
        .final_icons()
        .expect("modern catalog must see the icon");
    assert_eq!(final_icons.len(), 1);
    assert_eq!(final_icons[0].src.as_str(), "https://example.com/tool.png");
}

#[test]
fn tool_without_icon_does_not_invent_one() {
    let def = PlainTool.definition();
    assert!(def.icon.is_none());
}

/// Tool with annotations, version, and tags combined.
#[tool(
    name = "combo_tool",
    version = "1.0.0",
    tags = ["api", "safe"],
    annotations(read_only, idempotent)
)]
fn combo_tool(_ctx: &McpContext) -> String {
    "combo".to_string()
}

#[test]
fn tool_annotations_with_tags_and_version() {
    let handler = ComboTool;
    let def = handler.definition();
    assert_eq!(def.name, "combo_tool");
    assert_eq!(def.version.as_deref(), Some("1.0.0"));
    assert_eq!(def.tags, vec!["api", "safe"]);
    let ann = def.annotations.expect("annotations should be Some");
    assert_eq!(ann.read_only, Some(true));
    assert_eq!(ann.idempotent, Some(true));
    assert_eq!(ann.destructive, None);
}

// ============================================================================
// #[resource] expansion tests
// ============================================================================

/// Application configuration.
#[resource(uri = "config://app")]
fn app_config() -> String {
    r#"{"key": "value"}"#.to_string()
}

#[test]
fn resource_definition_uri() {
    let handler = AppConfigResource;
    let def = handler.definition();
    assert_eq!(def.uri, "config://app");
}

#[test]
fn resource_definition_name_from_fn() {
    let handler = AppConfigResource;
    let def = handler.definition();
    assert_eq!(def.name, "app_config");
}

#[test]
fn resource_definition_description_from_doc_comment() {
    let handler = AppConfigResource;
    let def = handler.definition();
    assert_eq!(
        def.description,
        Some("Application configuration.".to_string())
    );
}

#[test]
fn resource_definition_default_mime_type() {
    let handler = AppConfigResource;
    let def = handler.definition();
    assert_eq!(def.mime_type, Some("text/plain".to_string()));
}

#[test]
fn resource_read_returns_content() {
    let handler = AppConfigResource;
    let ctx = test_ctx();
    let result = handler.read(&ctx).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].text, Some(r#"{"key": "value"}"#.to_string()));
    assert_eq!(result[0].uri, "config://app");
    assert_eq!(result[0].mime_type, Some("text/plain".to_string()));
}

#[test]
fn resource_no_template_for_static_uri() {
    let handler = AppConfigResource;
    assert!(handler.template().is_none());
}

// --- Resource with custom attributes ---

/// Database schema info.
#[resource(
    uri = "db://schema",
    name = "db_schema",
    description = "Database schema",
    mime_type = "application/json"
)]
fn schema_resource() -> String {
    r#"{"tables": []}"#.to_string()
}

#[test]
fn resource_custom_name() {
    let handler = SchemaResourceResource;
    let def = handler.definition();
    assert_eq!(def.name, "db_schema");
}

#[test]
fn resource_custom_description() {
    let handler = SchemaResourceResource;
    let def = handler.definition();
    assert_eq!(def.description, Some("Database schema".to_string()));
}

#[test]
fn resource_custom_mime_type() {
    let handler = SchemaResourceResource;
    let def = handler.definition();
    assert_eq!(def.mime_type, Some("application/json".to_string()));
}

#[test]
fn resource_custom_mime_in_content() {
    let handler = SchemaResourceResource;
    let ctx = test_ctx();
    let result = handler.read(&ctx).unwrap();
    assert_eq!(result[0].mime_type, Some("application/json".to_string()));
}

// --- Resource with URI template ---

/// A file resource.
#[resource(uri = "file://{path}")]
fn file_resource(path: String) -> String {
    format!("contents of {path}")
}

#[test]
fn template_resource_has_template() {
    let handler = FileResourceResource;
    let template = handler.template().expect("should have template");
    assert_eq!(template.uri_template, "file://{path}");
}

#[test]
fn template_resource_read_with_uri() {
    let handler = FileResourceResource;
    let ctx = test_ctx();
    let mut params = HashMap::new();
    params.insert("path".to_string(), "readme.md".to_string());
    let result = handler
        .read_with_uri(&ctx, "file://readme.md", &params)
        .unwrap();
    assert_eq!(result[0].text, Some("contents of readme.md".to_string()));
    assert_eq!(result[0].uri, "file://readme.md");
}

// --- Resource with context ---

/// Resource using context.
#[resource(uri = "ctx://info")]
fn ctx_resource(ctx: &McpContext) -> String {
    format!("request_id={}", ctx.request_id())
}

#[test]
fn resource_with_context_read() {
    let handler = CtxResourceResource;
    let ctx = test_ctx();
    let result = handler.read(&ctx).unwrap();
    assert_eq!(result[0].text, Some("request_id=1".to_string()));
}

// --- Async resource ---

/// Async resource.
#[resource(uri = "async://data")]
async fn async_resource() -> String {
    "async data".to_string()
}

#[test]
fn async_resource_definition() {
    let handler = AsyncResourceResource;
    let def = handler.definition();
    assert_eq!(def.uri, "async://data");
    assert_eq!(def.name, "async_resource");
}

#[test]
fn async_resource_read() {
    let handler = AsyncResourceResource;
    let ctx = test_ctx();
    let result = expect_outcome_ok(run_outcome(async move { handler.read_async(&ctx).await }));
    assert_eq!(result[0].text, Some("async data".to_string()));
}

// --- Resource with timeout ---

/// Timed resource.
#[resource(uri = "timed://data", timeout = "5s")]
fn timed_resource() -> String {
    "timed".to_string()
}

#[test]
fn resource_timeout() {
    let handler = TimedResourceResource;
    assert_eq!(handler.timeout(), Some(std::time::Duration::from_secs(5)));
}

// --- Resource returning Result ---

/// Fallible resource.
#[resource(uri = "fallible://data")]
fn fallible_resource() -> McpResult<String> {
    Ok("ok".to_string())
}

#[test]
fn resource_result_ok() {
    let handler = FallibleResourceResource;
    let ctx = test_ctx();
    let result = handler.read(&ctx).unwrap();
    assert_eq!(result[0].text, Some("ok".to_string()));
}

// --- Final complete resource result projection ---

fn final_result_meta() -> ResultMeta {
    ResultMeta::server_generated(Implementation {
        name: "macro-expansion-test".to_string(),
        version: "1.0.0".to_string(),
        title: None,
        description: None,
        website_url: None,
        icons: Vec::new(),
        additional: BTreeMap::new(),
    })
}

fn final_resource_payload(text: &str) -> CompleteResult<FinalReadResourceResult> {
    CompleteResult::new(
        FinalReadResourceResult {
            contents: vec![EmbeddedResourceContents::Text {
                uri: FinalAbsoluteUri::parse("final://resource/content").expect("valid final URI"),
                text: text.to_string(),
                mime_type: Some("application/json".to_string()),
                meta: None,
                additional: BTreeMap::new(),
            }],
            ttl_ms: CacheTtl::milliseconds(0),
            cache_scope: CacheScope::Private,
        },
        final_result_meta(),
    )
}

#[resource(uri = "final://resource/direct")]
fn final_complete_resource_direct() -> CompleteResult<FinalReadResourceResult> {
    final_resource_payload("direct")
}

#[resource(uri = "final://resource/result")]
fn final_complete_resource_result() -> Result<CompleteResult<FinalReadResourceResult>, McpError> {
    Ok(final_resource_payload("result"))
}

#[resource(uri = "final://resource/mcp-result")]
fn final_complete_resource_mcp_result() -> McpResult<CompleteResult<FinalReadResourceResult>> {
    Ok(final_resource_payload("mcp-result"))
}

#[resource(uri = "final://resource/async-outcome")]
async fn async_final_resource_outcome()
-> fastmcp_rust::server::FinalMethodOutcome<FinalReadResourceResult> {
    fastmcp_rust::server::FinalMethodOutcome::Complete(final_resource_payload("async-outcome"))
}

#[test]
fn resource_final_complete_results_keep_final_payloads() {
    let ctx = test_ctx();
    let handlers: [Box<dyn ResourceHandler>; 3] = [
        Box::new(FinalCompleteResourceDirectResource),
        Box::new(FinalCompleteResourceResultResource),
        Box::new(FinalCompleteResourceMcpResultResource),
    ];

    for (handler, expected_text) in handlers.into_iter().zip(["direct", "result", "mcp-result"]) {
        assert!(
            handler.read(&ctx).is_err(),
            "legacy hook must not project final payload"
        );
        let result = handler
            .read_final(&ctx)
            .expect("final complete result remains on the final hook");
        let [
            EmbeddedResourceContents::Text {
                uri,
                text,
                mime_type,
                meta,
                additional,
            },
        ] = result.payload.contents.as_slice()
        else {
            panic!("final resource result contains one text resource");
        };
        assert_eq!(uri.as_str(), "final://resource/content");
        assert_eq!(mime_type.as_deref(), Some("application/json"));
        assert_eq!(text, expected_text);
        assert!(meta.is_none());
        assert!(additional.is_empty());
    }
}

#[test]
fn async_macro_final_resource_outcome_reaches_public_final_resources_read() {
    let connection = ModernConnection::new();
    let server = Server::new("facade-final-resource-outcome", "1.0.0")
        .resource(AsyncFinalResourceOutcomeResource)
        .build();
    let request = JsonRpcRequest::new(
        "resources/read",
        Some(json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
            "uri": "final://resource/async-outcome",
        })),
        64_i64,
    );
    let response = server
        .dispatch_stateless(&facade_final_inbound(&connection), &request)
        .expect("the public final resources/read route invokes the async macro outcome hook");
    assert!(
        response.error.is_none(),
        "final resources/read returned an unexpected error: {:?}",
        response.error
    );
    let result = response
        .result
        .expect("final resources/read returns its outcome as a result");
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["contents"][0]["text"], "async-outcome");
}

// --- Resource default trait methods ---

#[test]
fn resource_default_icon_is_none() {
    let handler = AppConfigResource;
    assert!(handler.icon().is_none());
}

#[test]
fn resource_default_version_is_none() {
    let handler = AppConfigResource;
    assert!(handler.version().is_none());
}

#[test]
fn resource_default_tags_are_empty() {
    let handler = AppConfigResource;
    assert_eq!(handler.tags().len(), 0);
}

#[test]
fn resource_default_timeout_is_none() {
    let handler = AppConfigResource;
    assert!(handler.timeout().is_none());
}

// --- Resource with multiple URI template parameters ---

/// A resource with multiple path segments.
#[resource(uri = "files://{directory}/{filename}")]
fn multi_param_resource(directory: String, filename: String) -> String {
    format!("{directory}/{filename}")
}

#[test]
fn resource_multi_param_template() {
    let handler = MultiParamResourceResource;
    let template = handler.template().expect("should have template");
    assert_eq!(template.uri_template, "files://{directory}/{filename}");
}

#[test]
fn resource_multi_param_read_with_uri() {
    let handler = MultiParamResourceResource;
    let ctx = test_ctx();
    let mut params = HashMap::new();
    params.insert("directory".to_string(), "docs".to_string());
    params.insert("filename".to_string(), "readme.txt".to_string());
    let result = handler
        .read_with_uri(&ctx, "files://docs/readme.txt", &params)
        .unwrap();
    assert_eq!(result[0].text, Some("docs/readme.txt".to_string()));
}

/// A resource whose two Rust parameters come from one RFC 6570 expression.
#[resource(uri = "macro://resource{?collection*,revision*}")]
fn multi_variable_expression_resource(collection: String, revision: String) -> String {
    format!("{collection}:{revision}")
}

#[test]
fn resource_multi_variable_expression_flattens_every_template_parameter() {
    let handler = MultiVariableExpressionResourceResource;
    let ctx = test_ctx();
    let mut params = HashMap::new();
    params.insert("collection".to_string(), "books".to_string());
    params.insert("revision".to_string(), "stable".to_string());
    let result = handler
        .read_with_uri(
            &ctx,
            "macro://resource?collection=books&revision=stable",
            &params,
        )
        .expect("both parameters from one expression reach the resource function");
    assert_eq!(result[0].text, Some("books:stable".to_string()));
}

// --- Resource with optional URI template parameter ---

/// Resource with optional path parameter.
#[resource(uri = "search://{query}")]
fn optional_param_resource(query: Option<String>) -> String {
    match query {
        Some(q) => format!("results for: {q}"),
        None => "no query".to_string(),
    }
}

#[test]
fn resource_optional_param_with_value() {
    let handler = OptionalParamResourceResource;
    let ctx = test_ctx();
    let mut params = HashMap::new();
    params.insert("query".to_string(), "rust".to_string());
    let result = handler
        .read_with_uri(&ctx, "search://rust", &params)
        .unwrap();
    assert_eq!(result[0].text, Some("results for: rust".to_string()));
}

#[test]
fn resource_optional_param_without_value() {
    let handler = OptionalParamResourceResource;
    let ctx = test_ctx();
    let params = HashMap::new();
    let result = handler.read_with_uri(&ctx, "search://", &params).unwrap();
    assert_eq!(result[0].text, Some("no query".to_string()));
}

// --- Resource returning McpResult with error case ---

/// Resource that can fail.
#[resource(uri = "fallible://checked")]
fn fallible_error_resource() -> McpResult<String> {
    Err(fastmcp_rust::McpError::invalid_params(
        "resource failed".to_string(),
    ))
}

#[test]
fn resource_result_err() {
    let handler = FallibleErrorResourceResource;
    let ctx = test_ctx();
    let err = handler
        .read(&ctx)
        .expect_err("resource should return an error");
    assert_eq!(err.code, fastmcp_rust::McpErrorCode::InvalidParams);
}

// --- Async resource with context ---

/// Async resource using context.
#[resource(uri = "async-ctx://info")]
async fn async_ctx_resource(ctx: &McpContext) -> String {
    format!("async_request_id={}", ctx.request_id())
}

#[test]
fn async_resource_with_context_definition() {
    let handler = AsyncCtxResourceResource;
    let def = handler.definition();
    assert_eq!(def.uri, "async-ctx://info");
}

#[test]
fn async_resource_with_context_read() {
    let handler = AsyncCtxResourceResource;
    let ctx = test_ctx();
    let result = expect_outcome_ok(run_outcome(async move { handler.read_async(&ctx).await }));
    assert_eq!(result[0].text, Some("async_request_id=1".to_string()));
}

// --- Resource with context AND URI template ---

/// Resource with both context and template params.
#[resource(uri = "ctx-template://{id}")]
fn ctx_template_resource(ctx: &McpContext, id: String) -> String {
    format!("request={}, id={}", ctx.request_id(), id)
}

#[test]
fn resource_ctx_and_template_read() {
    let handler = CtxTemplateResourceResource;
    let ctx = test_ctx();
    let mut params = HashMap::new();
    params.insert("id".to_string(), "abc123".to_string());
    let result = handler
        .read_with_uri(&ctx, "ctx-template://abc123", &params)
        .unwrap();
    assert_eq!(result[0].text, Some("request=1, id=abc123".to_string()));
}

// --- Async resource with URI template ---

/// Async templated resource.
#[resource(uri = "async-file://{path}")]
async fn async_template_resource(path: String) -> String {
    format!("async contents of {path}")
}

#[test]
fn async_template_resource_definition() {
    let handler = AsyncTemplateResourceResource;
    let template = handler.template().expect("should have template");
    assert_eq!(template.uri_template, "async-file://{path}");
}

#[test]
fn async_template_resource_read() {
    let handler = AsyncTemplateResourceResource;
    let ctx = test_ctx();
    let mut params = HashMap::new();
    params.insert("path".to_string(), "data.json".to_string());
    let result = expect_outcome_ok(run_outcome(async move {
        handler
            .read_async_with_uri(&ctx, "async-file://data.json", &params)
            .await
    }));
    assert_eq!(
        result[0].text,
        Some("async contents of data.json".to_string())
    );
}

// --- Resource with no description ---

#[resource(uri = "no-desc://data")]
fn no_desc_resource() -> String {
    "data".to_string()
}

#[test]
fn resource_no_description_is_none() {
    let handler = NoDescResourceResource;
    let def = handler.definition();
    assert!(def.description.is_none());
}

// --- Resource with compound timeout ---

/// Resource with compound timeout.
#[resource(uri = "long-timed://data", timeout = "2m30s")]
fn long_timed_resource() -> String {
    "long timed".to_string()
}

#[test]
fn resource_timeout_compound() {
    let handler = LongTimedResourceResource;
    assert_eq!(handler.timeout(), Some(std::time::Duration::from_secs(150)));
}

// --- Resource with version and tags ---

/// Versioned resource with tags.
#[resource(uri = "data://metrics", version = "3.0.0", tags = ["monitoring", "metrics"])]
fn metrics_resource(_ctx: &McpContext) -> String {
    r#"{"cpu": 42}"#.to_string()
}

#[test]
fn resource_version_and_tags() {
    let handler = MetricsResourceResource;
    let def = handler.definition();
    assert_eq!(def.version.as_deref(), Some("3.0.0"));
    assert_eq!(def.tags, vec!["monitoring", "metrics"]);
    assert!(def.icon.is_none());
}

/// Resource with an explicit icon source.
#[resource(uri = "data://icon", icon = "https://example.com/resource.svg")]
fn icon_resource() -> String {
    "icon-resource".to_string()
}

#[test]
fn resource_icon_is_advertised_on_definition() {
    let handler = IconResourceResource;
    let def = handler.definition();
    assert_eq!(
        def.icon.as_ref().and_then(|icon| icon.src.as_deref()),
        Some("https://example.com/resource.svg")
    );
    let final_icons = handler
        .final_icons()
        .expect("modern catalog must see the resource icon");
    assert_eq!(final_icons.len(), 1);
    assert_eq!(
        final_icons[0].src.as_str(),
        "https://example.com/resource.svg"
    );
}

/// Resource with version only.
#[resource(uri = "data://plain", version = "1.0.0")]
fn plain_versioned_resource() -> String {
    "data".to_string()
}

#[test]
fn resource_version_without_tags() {
    let handler = PlainVersionedResourceResource;
    let def = handler.definition();
    assert_eq!(def.version.as_deref(), Some("1.0.0"));
    assert_eq!(def.tags, [] as [std::string::String; 0]);
}

/// Resource with no version or tags (backwards compat).
#[resource(uri = "data://basic")]
fn basic_resource() -> String {
    "basic".to_string()
}

#[test]
fn resource_no_version_no_tags_stays_none() {
    let handler = BasicResourceResource;
    let def = handler.definition();
    assert!(def.version.is_none());
    assert_eq!(def.tags, [] as [std::string::String; 0]);
}

// ============================================================================
// #[prompt] expansion tests
// ============================================================================

/// A greeting prompt.
#[prompt]
fn greeting_prompt(name: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!("Greet {name}"),
        },
    }]
}

#[test]
fn prompt_definition_name_from_fn() {
    let handler = GreetingPromptPrompt;
    let def = handler.definition();
    assert_eq!(def.name, "greeting_prompt");
}

#[test]
fn prompt_definition_description_from_doc() {
    let handler = GreetingPromptPrompt;
    let def = handler.definition();
    assert_eq!(def.description, Some("A greeting prompt.".to_string()));
}

#[test]
fn prompt_definition_arguments() {
    let handler = GreetingPromptPrompt;
    let def = handler.definition();
    assert_eq!(def.arguments.len(), 1);
    assert_eq!(def.arguments[0].name, "name");
    assert!(def.arguments[0].required);
    // No doc comment on parameter, so description is None
    assert!(def.arguments[0].description.is_none());
    assert!(def.icon.is_none());
}

/// Prompt with an explicit icon source.
#[prompt(icon = "https://example.com/prompt.png")]
fn icon_prompt(name: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!("Greet {name}"),
        },
    }]
}

#[test]
fn prompt_icon_is_advertised_on_definition() {
    let handler = IconPromptPrompt;
    let def = handler.definition();
    assert_eq!(
        def.icon.as_ref().and_then(|icon| icon.src.as_deref()),
        Some("https://example.com/prompt.png")
    );
    let final_icons = handler
        .final_icons()
        .expect("modern catalog must see the prompt icon");
    assert_eq!(final_icons.len(), 1);
    assert_eq!(
        final_icons[0].src.as_str(),
        "https://example.com/prompt.png"
    );
}

/// A greeting prompt with a default argument.
#[prompt(defaults(greeting = "Hi"))]
fn greeting_prompt_with_default(name: String, greeting: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!("{greeting} {name}"),
        },
    }]
}

#[test]
fn prompt_default_argument_is_not_required() {
    let handler = GreetingPromptWithDefaultPrompt;
    let def = handler.definition();
    assert_eq!(def.arguments.len(), 2);
    assert_eq!(def.arguments[0].name, "name");
    assert!(def.arguments[0].required);
    assert_eq!(def.arguments[1].name, "greeting");
    assert!(!def.arguments[1].required);
}

#[test]
fn prompt_get_uses_default_argument_when_missing() {
    let handler = GreetingPromptWithDefaultPrompt;
    let ctx = test_ctx();
    let mut args = HashMap::new();
    args.insert("name".to_string(), "Alice".to_string());
    let result = handler.get(&ctx, args).unwrap();
    let text = expect_text(&result[0].content);
    assert_eq!(text, "Hi Alice");
}

#[test]
fn prompt_get_returns_messages() {
    let handler = GreetingPromptPrompt;
    let ctx = test_ctx();
    let mut args = HashMap::new();
    args.insert("name".to_string(), "Alice".to_string());
    let result = handler.get(&ctx, args).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].role, Role::User);
    let text = expect_text(&result[0].content);
    assert_eq!(text, "Greet Alice");
}

// --- Prompt with optional arguments ---

/// Review prompt with options.
#[prompt]
fn review_prompt(code: String, focus: Option<String>) -> Vec<PromptMessage> {
    let text = match focus {
        Some(f) => format!("Review (focus: {f}):\n{code}"),
        None => format!("Review:\n{code}"),
    };
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text { text },
    }]
}

#[test]
fn prompt_optional_arg_not_required() {
    let handler = ReviewPromptPrompt;
    let def = handler.definition();
    assert_eq!(def.arguments.len(), 2);

    let code_arg = &def.arguments[0];
    assert_eq!(code_arg.name, "code");
    assert!(code_arg.required);

    let focus_arg = &def.arguments[1];
    assert_eq!(focus_arg.name, "focus");
    assert!(!focus_arg.required);
}

#[test]
fn prompt_get_without_optional() {
    let handler = ReviewPromptPrompt;
    let ctx = test_ctx();
    let mut args = HashMap::new();
    args.insert("code".to_string(), "fn main() {}".to_string());
    let result = handler.get(&ctx, args).unwrap();
    let text = expect_text(&result[0].content);
    assert!(text.starts_with("Review:\n"));
}

#[test]
fn prompt_get_with_optional() {
    let handler = ReviewPromptPrompt;
    let ctx = test_ctx();
    let mut args = HashMap::new();
    args.insert("code".to_string(), "fn main() {}".to_string());
    args.insert("focus".to_string(), "security".to_string());
    let result = handler.get(&ctx, args).unwrap();
    let text = expect_text(&result[0].content);
    assert!(text.starts_with("Review (focus: security)"));
}

#[test]
fn prompt_missing_required_arg_errors() {
    let handler = ReviewPromptPrompt;
    let ctx = test_ctx();
    let args = HashMap::new(); // No args provided
    let result = handler.get(&ctx, args);
    assert!(result.is_err());
}

// --- Prompt with name override ---

#[prompt(name = "my_prompt")]
fn prompt_custom_name() -> Vec<PromptMessage> {
    vec![]
}

#[test]
fn prompt_name_override() {
    let handler = PromptCustomNamePrompt;
    let def = handler.definition();
    assert_eq!(def.name, "my_prompt");
}

// --- Prompt with description override ---

/// Doc comment ignored.
#[prompt(description = "Explicit prompt description")]
fn prompt_desc_override() -> Vec<PromptMessage> {
    vec![]
}

#[test]
fn prompt_description_override() {
    let handler = PromptDescOverridePrompt;
    let def = handler.definition();
    assert_eq!(
        def.description,
        Some("Explicit prompt description".to_string())
    );
}

// --- Prompt with timeout ---

/// Timed prompt.
#[prompt(timeout = "10s")]
fn timed_prompt(text: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text { text },
    }]
}

#[test]
fn prompt_timeout() {
    let handler = TimedPromptPrompt;
    assert_eq!(handler.timeout(), Some(std::time::Duration::from_secs(10)));
}

// --- Prompt with context ---

/// Prompt using context.
#[prompt]
fn ctx_prompt(ctx: &McpContext, msg: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!("req:{} msg:{msg}", ctx.request_id()),
        },
    }]
}

#[test]
fn prompt_with_context_call() {
    let handler = CtxPromptPrompt;
    let ctx = test_ctx();
    let mut args = HashMap::new();
    args.insert("msg".to_string(), "hello".to_string());
    let result = handler.get(&ctx, args).unwrap();
    let text = expect_text(&result[0].content);
    assert_eq!(text, "req:1 msg:hello");
}

#[test]
fn prompt_with_context_schema_excludes_ctx() {
    let handler = CtxPromptPrompt;
    let def = handler.definition();
    // Only msg should be an argument, not ctx
    assert_eq!(def.arguments.len(), 1);
    assert_eq!(def.arguments[0].name, "msg");
}

// --- Async prompt ---

/// An async prompt.
#[prompt]
async fn async_prompt(text: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text { text },
    }]
}

#[test]
fn async_prompt_definition() {
    let handler = AsyncPromptPrompt;
    let def = handler.definition();
    assert_eq!(def.name, "async_prompt");
}

#[test]
fn async_prompt_get() {
    let handler = AsyncPromptPrompt;
    let ctx = test_ctx();
    let mut args = HashMap::new();
    args.insert("text".to_string(), "async hello".to_string());
    let result = expect_outcome_ok(run_outcome(
        async move { handler.get_async(&ctx, args).await },
    ));
    let text = expect_text(&result[0].content);
    assert_eq!(text, "async hello");
}

#[test]
fn async_generated_handlers_reject_synchronous_trait_entry_points() {
    let ctx = test_ctx();

    let tool_error = AsyncGreet
        .call(&ctx, json!({"name": "Rust"}))
        .expect_err("an async tool has no synchronous execution entry point");
    assert_eq!(tool_error.code, fastmcp_rust::McpErrorCode::InternalError);
    assert!(tool_error.message.contains("call_async"));

    let resource_error = AsyncResourceResource
        .read(&ctx)
        .expect_err("an async resource has no synchronous execution entry point");
    assert_eq!(
        resource_error.code,
        fastmcp_rust::McpErrorCode::InternalError
    );
    assert!(resource_error.message.contains("read_async"));

    let prompt_error = AsyncPromptPrompt
        .get(&ctx, HashMap::new())
        .expect_err("an async prompt has no synchronous execution entry point");
    assert_eq!(prompt_error.code, fastmcp_rust::McpErrorCode::InternalError);
    assert!(prompt_error.message.contains("get_async"));
}

// --- Prompt default trait methods ---

#[test]
fn prompt_default_icon_is_none() {
    let handler = GreetingPromptPrompt;
    assert!(handler.icon().is_none());
}

#[test]
fn prompt_default_version_is_none() {
    let handler = GreetingPromptPrompt;
    assert!(handler.version().is_none());
}

#[test]
fn prompt_default_tags_are_empty() {
    let handler = GreetingPromptPrompt;
    assert_eq!(handler.tags().len(), 0);
}

#[test]
fn prompt_default_timeout_is_none() {
    let handler = GreetingPromptPrompt;
    assert!(handler.timeout().is_none());
}

// --- Prompt with no arguments ---

/// A prompt with no arguments.
#[prompt]
fn no_args_prompt() -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: "Hello!".to_string(),
        },
    }]
}

#[test]
fn prompt_no_args_definition() {
    let handler = NoArgsPromptPrompt;
    let def = handler.definition();
    assert!(def.arguments.is_empty());
}

#[test]
fn prompt_no_args_call() {
    let handler = NoArgsPromptPrompt;
    let ctx = test_ctx();
    let args = HashMap::new();
    let result = handler.get(&ctx, args).unwrap();
    assert_eq!(result.len(), 1);
    let text = expect_text(&result[0].content);
    assert_eq!(text, "Hello!");
}

// --- Prompt returning McpResult ---

/// A fallible prompt.
#[prompt]
fn fallible_prompt(fail: Option<String>) -> McpResult<Vec<PromptMessage>> {
    if fail.is_some() {
        Err(fastmcp_rust::McpError::invalid_params(
            "prompt failed".to_string(),
        ))
    } else {
        Ok(vec![PromptMessage {
            role: Role::User,
            content: Content::Text {
                text: "success".to_string(),
            },
        }])
    }
}

#[test]
fn prompt_result_ok() {
    let handler = FalliblePromptPrompt;
    let ctx = test_ctx();
    let args = HashMap::new();
    let result = handler.get(&ctx, args).unwrap();
    let text = expect_text(&result[0].content);
    assert_eq!(text, "success");
}

#[test]
fn prompt_result_err() {
    let handler = FalliblePromptPrompt;
    let ctx = test_ctx();
    let mut args = HashMap::new();
    args.insert("fail".to_string(), "true".to_string());
    let err = handler
        .get(&ctx, args)
        .expect_err("prompt should return an error");
    assert_eq!(err.code, fastmcp_rust::McpErrorCode::InvalidParams);
}

// --- Final complete prompt result projection ---

fn final_prompt_payload(text: &str) -> CompleteResult<FinalGetPromptResult> {
    CompleteResult::new(
        FinalGetPromptResult {
            description: Some("final prompt metadata is projected by the modern layer".to_string()),
            messages: vec![FinalPromptMessage {
                role: Role::Assistant,
                content: ContentBlock::Text {
                    text: text.to_string(),
                    annotations: None,
                    meta: None,
                    additional: BTreeMap::new(),
                },
            }],
        },
        final_result_meta(),
    )
}

#[prompt]
fn final_complete_prompt_direct() -> CompleteResult<FinalGetPromptResult> {
    final_prompt_payload("direct")
}

#[prompt]
fn final_complete_prompt_result() -> Result<CompleteResult<FinalGetPromptResult>, McpError> {
    Ok(final_prompt_payload("result"))
}

#[prompt]
fn final_complete_prompt_mcp_result() -> McpResult<CompleteResult<FinalGetPromptResult>> {
    Ok(final_prompt_payload("mcp-result"))
}

#[test]
fn prompt_final_complete_results_keep_final_payloads() {
    let ctx = test_ctx();
    let handlers: [Box<dyn PromptHandler>; 3] = [
        Box::new(FinalCompletePromptDirectPrompt),
        Box::new(FinalCompletePromptResultPrompt),
        Box::new(FinalCompletePromptMcpResultPrompt),
    ];

    for (handler, expected_text) in handlers.into_iter().zip(["direct", "result", "mcp-result"]) {
        assert!(
            handler.get(&ctx, HashMap::new()).is_err(),
            "legacy hook must not project final payload"
        );
        let result = handler
            .get_final(&ctx, HashMap::new())
            .expect("final complete result remains on the final hook");
        let [FinalPromptMessage { role, content }] = result.payload.messages.as_slice() else {
            panic!("final prompt result contains one message");
        };
        assert_eq!(*role, Role::Assistant);
        assert!(matches!(content, ContentBlock::Text { text, .. } if text == expected_text));
    }
}

// --- Async prompt with context ---

/// Async prompt using context.
#[prompt]
async fn async_ctx_prompt(ctx: &McpContext, msg: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!("async_req:{} msg:{msg}", ctx.request_id()),
        },
    }]
}

#[test]
fn async_prompt_with_context_definition() {
    let handler = AsyncCtxPromptPrompt;
    let def = handler.definition();
    // Only msg should be an argument, not ctx
    assert_eq!(def.arguments.len(), 1);
    assert_eq!(def.arguments[0].name, "msg");
}

#[test]
fn async_prompt_with_context_get() {
    let handler = AsyncCtxPromptPrompt;
    let ctx = test_ctx();
    let mut args = HashMap::new();
    args.insert("msg".to_string(), "hello".to_string());
    let result = expect_outcome_ok(run_outcome(
        async move { handler.get_async(&ctx, args).await },
    ));
    let text = expect_text(&result[0].content);
    assert_eq!(text, "async_req:1 msg:hello");
}

// --- Prompt returning multiple messages ---

/// A conversation prompt.
#[prompt]
fn conversation_prompt(topic: String) -> Vec<PromptMessage> {
    vec![
        PromptMessage {
            role: Role::User,
            content: Content::Text {
                text: format!("Let's discuss {topic}"),
            },
        },
        PromptMessage {
            role: Role::Assistant,
            content: Content::Text {
                text: format!("I'd be happy to discuss {topic}"),
            },
        },
        PromptMessage {
            role: Role::User,
            content: Content::Text {
                text: "What are the key points?".to_string(),
            },
        },
    ]
}

#[test]
fn prompt_multiple_messages() {
    let handler = ConversationPromptPrompt;
    let ctx = test_ctx();
    let mut args = HashMap::new();
    args.insert("topic".to_string(), "Rust".to_string());
    let result = handler.get(&ctx, args).unwrap();
    assert_eq!(result.len(), 3);
    assert_eq!(result[0].role, Role::User);
    assert_eq!(result[1].role, Role::Assistant);
    assert_eq!(result[2].role, Role::User);
}

// --- Prompt with no description ---

#[prompt]
fn no_desc_prompt(text: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text { text },
    }]
}

#[test]
fn prompt_no_description_is_none() {
    let handler = NoDescPromptPrompt;
    let def = handler.definition();
    assert!(def.description.is_none());
}

// --- Prompt with compound timeout ---

/// Prompt with compound timeout.
#[prompt(timeout = "1m30s")]
fn compound_timeout_prompt() -> Vec<PromptMessage> {
    vec![]
}

#[test]
fn prompt_timeout_compound() {
    let handler = CompoundTimeoutPromptPrompt;
    assert_eq!(handler.timeout(), Some(std::time::Duration::from_secs(90)));
}

// --- Prompt with all optional arguments ---

/// Prompt with all optional args.
#[prompt]
fn all_optional_prompt(a: Option<String>, b: Option<String>) -> Vec<PromptMessage> {
    let a_str = a.unwrap_or_else(|| "none".to_string());
    let b_str = b.unwrap_or_else(|| "none".to_string());
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!("a={a_str}, b={b_str}"),
        },
    }]
}

#[test]
fn prompt_all_optional_none_required() {
    let handler = AllOptionalPromptPrompt;
    let def = handler.definition();
    assert!(def.arguments.iter().all(|arg| !arg.required));
}

#[test]
fn prompt_all_optional_call_empty() {
    let handler = AllOptionalPromptPrompt;
    let ctx = test_ctx();
    let args = HashMap::new();
    let result = handler.get(&ctx, args).unwrap();
    let text = expect_text(&result[0].content);
    assert_eq!(text, "a=none, b=none");
}

// --- Prompt with version and tags ---

/// Versioned prompt with tags.
#[prompt(
    name = "tagged_prompt",
    version = "2.0.0",
    tags = ["greeting", "onboarding"]
)]
fn tagged_prompt(name: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!("Welcome {name}"),
        },
    }]
}

#[test]
fn prompt_version_and_tags() {
    let handler = TaggedPromptPrompt;
    let def = handler.definition();
    assert_eq!(def.version.as_deref(), Some("2.0.0"));
    assert_eq!(def.tags, vec!["greeting", "onboarding"]);
}

/// Prompt with no version or tags (backwards compat).
#[prompt]
fn basic_prompt() -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: "hello".to_string(),
        },
    }]
}

#[test]
fn prompt_no_version_no_tags_stays_none() {
    let handler = BasicPromptPrompt;
    let def = handler.definition();
    assert!(def.version.is_none());
    assert_eq!(def.tags, [] as [std::string::String; 0]);
}

// ============================================================================
// #[derive(JsonSchema)] expansion tests
// ============================================================================

/// A person record.
#[derive(JsonSchema)]
struct Person {
    /// The person's name
    name: String,
    /// Optional age
    age: Option<u32>,
    /// List of tags
    tags: Vec<String>,
}

#[test]
fn json_schema_struct_type_is_object() {
    let schema = Person::json_schema();
    assert_eq!(schema["type"], "object");
}

#[test]
fn json_schema_struct_properties() {
    let schema = Person::json_schema();
    let props = schema["properties"].as_object().unwrap();
    assert!(props.contains_key("name"));
    assert!(props.contains_key("age"));
    assert!(props.contains_key("tags"));
}

#[test]
fn json_schema_struct_field_types() {
    let schema = Person::json_schema();
    let props = schema["properties"].as_object().unwrap();
    assert_eq!(props["name"]["type"], "string");
    // Option<u32> widens to a nullable union: explicit null == omitted.
    assert_eq!(props["age"]["type"], json!(["integer", "null"]));
    assert_eq!(props["tags"]["type"], "array");
    assert_eq!(props["tags"]["items"]["type"], "string");
}

#[test]
fn json_schema_struct_required_fields() {
    let schema = Person::json_schema();
    let required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    // name and tags are required, age is Option so not required
    assert!(required.contains(&"name"));
    assert!(required.contains(&"tags"));
    assert!(!required.contains(&"age"));
}

#[test]
fn json_schema_struct_field_descriptions() {
    let schema = Person::json_schema();
    let props = schema["properties"].as_object().unwrap();
    assert_eq!(props["name"]["description"], "The person's name");
    assert_eq!(props["age"]["description"], "Optional age");
    assert_eq!(props["tags"]["description"], "List of tags");
}

#[test]
fn json_schema_struct_description() {
    let schema = Person::json_schema();
    assert_eq!(schema["description"], "A person record.");
}

// --- Schema with numeric types ---

#[derive(JsonSchema)]
struct NumberTypes {
    integer_val: i64,
    float_val: f64,
    bool_val: bool,
    unsigned_val: u32,
}

#[test]
fn json_schema_numeric_types() {
    let schema = NumberTypes::json_schema();
    let props = schema["properties"].as_object().unwrap();
    assert_eq!(props["integer_val"]["type"], "integer");
    assert_eq!(props["float_val"]["type"], "number");
    assert_eq!(props["bool_val"]["type"], "boolean");
    assert_eq!(props["unsigned_val"]["type"], "integer");
}

// --- Schema with nested Vec/Option ---

#[derive(JsonSchema)]
struct Nested {
    items: Vec<i32>,
    optional_items: Option<Vec<String>>,
}

#[test]
fn json_schema_nested_vec() {
    let schema = Nested::json_schema();
    let props = schema["properties"].as_object().unwrap();
    assert_eq!(props["items"]["type"], "array");
    assert_eq!(props["items"]["items"]["type"], "integer");
}

#[test]
fn json_schema_optional_vec() {
    let schema = Nested::json_schema();
    let props = schema["properties"].as_object().unwrap();
    // Option<Vec<String>> → nullable array of strings, not required
    assert_eq!(props["optional_items"]["type"], json!(["array", "null"]));
    assert_eq!(props["optional_items"]["items"]["type"], "string");
    let required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(!required.contains(&"optional_items"));
}

// --- Schema with rename attribute ---

#[derive(JsonSchema)]
struct RenamedFields {
    #[json_schema(rename = "firstName")]
    first_name: String,
    #[json_schema(rename = "lastName")]
    last_name: String,
}

#[test]
fn json_schema_rename_attribute() {
    let schema = RenamedFields::json_schema();
    let props = schema["properties"].as_object().unwrap();
    assert!(props.contains_key("firstName"));
    assert!(props.contains_key("lastName"));
    assert!(!props.contains_key("first_name"));
    assert!(!props.contains_key("last_name"));
}

// --- Schema with skip attribute ---

#[derive(JsonSchema)]
struct SkippedFields {
    visible: String,
    #[json_schema(skip)]
    hidden: String,
}

#[test]
fn json_schema_skip_attribute() {
    let schema = SkippedFields::json_schema();
    let props = schema["properties"].as_object().unwrap();
    assert!(props.contains_key("visible"));
    assert!(!props.contains_key("hidden"));
}

// --- Enum schema ---

/// Color options.
#[derive(JsonSchema)]
enum Color {
    Red,
    Green,
    Blue,
}

#[test]
fn json_schema_unit_enum() {
    let schema = Color::json_schema();
    assert_eq!(schema["type"], "string");
    let variants = schema["enum"].as_array().unwrap();
    assert_eq!(variants.len(), 3);
    assert!(variants.iter().any(|v| v == "Red"));
    assert!(variants.iter().any(|v| v == "Green"));
    assert!(variants.iter().any(|v| v == "Blue"));
}

#[test]
fn json_schema_unit_enum_description() {
    let schema = Color::json_schema();
    assert_eq!(schema["description"], "Color options.");
}

// --- Newtype struct schema ---

#[derive(JsonSchema)]
struct Email(String);

#[test]
fn json_schema_newtype_struct() {
    let schema = Email::json_schema();
    assert_eq!(schema["type"], "string");
}

// --- Unit struct schema ---

#[derive(JsonSchema)]
struct Marker;

#[test]
fn json_schema_unit_struct() {
    let schema = Marker::json_schema();
    assert_eq!(schema["type"], "null");
}

// --- Struct with no doc comments ---

#[derive(JsonSchema)]
struct NoDocStruct {
    field: String,
}

#[test]
fn json_schema_no_description() {
    let schema = NoDocStruct::json_schema();
    // description key should not be present
    assert!(schema.get("description").is_none());
}

// --- Struct with HashMap field ---

#[derive(JsonSchema)]
struct MapStruct {
    metadata: HashMap<String, String>,
}

#[test]
fn json_schema_hashmap_field() {
    let schema = MapStruct::json_schema();
    let props = schema["properties"].as_object().unwrap();
    assert_eq!(props["metadata"]["type"], "object");
    assert_eq!(props["metadata"]["additionalProperties"]["type"], "string");
}

// --- Empty struct ---

#[derive(JsonSchema)]
struct EmptyStruct {}

#[test]
fn json_schema_empty_struct() {
    let schema = EmptyStruct::json_schema();
    assert_eq!(schema["type"], "object");
    let props = schema["properties"].as_object().unwrap();
    assert!(props.is_empty());
}

// --- Tagged enum schema ---

#[derive(JsonSchema)]
enum Shape {
    Circle(f64),
    Rectangle(String),
    Point,
}

#[test]
fn json_schema_tagged_enum_uses_one_of() {
    let schema = Shape::json_schema();
    let one_of = schema["oneOf"].as_array().unwrap();
    assert_eq!(one_of.len(), 3);
}

// --- Additional primitive types ---

#[derive(JsonSchema)]
struct AllPrimitives {
    i8_val: i8,
    i16_val: i16,
    i32_val: i32,
    u8_val: u8,
    u16_val: u16,
    usize_val: usize,
    isize_val: isize,
}

#[test]
fn json_schema_all_integer_types() {
    let schema = AllPrimitives::json_schema();
    let props = schema["properties"].as_object().unwrap();
    // All integer types should map to "integer"
    for key in [
        "i8_val",
        "i16_val",
        "i32_val",
        "u8_val",
        "u16_val",
        "usize_val",
        "isize_val",
    ] {
        assert_eq!(props[key]["type"], "integer", "Failed for {key}");
    }
}

// --- Tuple struct with multiple fields ---

#[derive(JsonSchema)]
struct Point3D(f64, f64, f64);

#[test]
fn json_schema_tuple_struct_multiple_fields() {
    let schema = Point3D::json_schema();
    assert_eq!(schema["type"], "array");
    let prefix_items = schema["prefixItems"].as_array().unwrap();
    assert_eq!(prefix_items.len(), 3);
    for item in prefix_items {
        assert_eq!(item["type"], "number");
    }
    assert_eq!(schema["minItems"], 3);
    assert_eq!(schema["maxItems"], 3);
}

// --- BTreeMap schema ---

#[derive(JsonSchema)]
struct BTreeMapStruct {
    sorted_map: std::collections::BTreeMap<String, i32>,
}

#[test]
fn json_schema_btreemap_field() {
    let schema = BTreeMapStruct::json_schema();
    let props = schema["properties"].as_object().unwrap();
    assert_eq!(props["sorted_map"]["type"], "object");
    assert_eq!(
        props["sorted_map"]["additionalProperties"]["type"],
        "integer"
    );
}

// --- HashSet/BTreeSet schema ---

#[derive(JsonSchema)]
struct SetStruct {
    hash_set: std::collections::HashSet<String>,
    btree_set: std::collections::BTreeSet<i32>,
}

#[test]
fn json_schema_set_fields() {
    let schema = SetStruct::json_schema();
    let props = schema["properties"].as_object().unwrap();
    // Sets should be arrays with uniqueItems
    assert_eq!(props["hash_set"]["type"], "array");
    assert_eq!(props["hash_set"]["items"]["type"], "string");
    assert_eq!(props["hash_set"]["uniqueItems"], true);

    assert_eq!(props["btree_set"]["type"], "array");
    assert_eq!(props["btree_set"]["items"]["type"], "integer");
    assert_eq!(props["btree_set"]["uniqueItems"], true);
}

// --- Deeply nested types ---

#[derive(JsonSchema)]
struct DeeplyNested {
    matrix: Vec<Vec<i32>>,
    map_of_lists: std::collections::HashMap<String, Vec<String>>,
    optional_map: Option<std::collections::HashMap<String, i32>>,
}

#[test]
fn json_schema_matrix_field() {
    let schema = DeeplyNested::json_schema();
    let props = schema["properties"].as_object().unwrap();
    // Vec<Vec<i32>>
    assert_eq!(props["matrix"]["type"], "array");
    assert_eq!(props["matrix"]["items"]["type"], "array");
    assert_eq!(props["matrix"]["items"]["items"]["type"], "integer");
}

#[test]
fn json_schema_map_of_lists_field() {
    let schema = DeeplyNested::json_schema();
    let props = schema["properties"].as_object().unwrap();
    // HashMap<String, Vec<String>>
    assert_eq!(props["map_of_lists"]["type"], "object");
    assert_eq!(
        props["map_of_lists"]["additionalProperties"]["type"],
        "array"
    );
    assert_eq!(
        props["map_of_lists"]["additionalProperties"]["items"]["type"],
        "string"
    );
}

#[test]
fn json_schema_optional_map_field() {
    let schema = DeeplyNested::json_schema();
    let props = schema["properties"].as_object().unwrap();
    // Option<HashMap<String, i32>> - nullable object, not required
    assert_eq!(props["optional_map"]["type"], json!(["object", "null"]));
    assert_eq!(
        props["optional_map"]["additionalProperties"]["type"],
        "integer"
    );
    // Verify it's not required
    let required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(!required.contains(&"optional_map"));
}

// --- Multiple optional fields ---

#[derive(JsonSchema)]
struct ManyOptionals {
    required_field: String,
    opt1: Option<String>,
    opt2: Option<i32>,
    opt3: Option<bool>,
    opt4: Option<Vec<String>>,
}

#[test]
fn json_schema_many_optionals_required() {
    let schema = ManyOptionals::json_schema();
    let required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    // Only required_field should be required
    assert_eq!(required.len(), 1);
    assert!(required.contains(&"required_field"));
}

#[test]
fn json_schema_many_optionals_properties() {
    let schema = ManyOptionals::json_schema();
    let props = schema["properties"].as_object().unwrap();
    // All 5 fields should be present
    assert_eq!(props.len(), 5);
    assert_eq!(props["opt1"]["type"], json!(["string", "null"]));
    assert_eq!(props["opt2"]["type"], json!(["integer", "null"]));
    assert_eq!(props["opt3"]["type"], json!(["boolean", "null"]));
    assert_eq!(props["opt4"]["type"], json!(["array", "null"]));
}

// --- Enum with multiple variant types ---

/// Status with mixed variants.
#[derive(JsonSchema)]
enum StatusVariants {
    /// Pending state.
    Pending,
    /// Running with progress.
    Running(f64),
    /// Complete with result.
    Complete(String),
}

#[test]
fn json_schema_mixed_enum_variants() {
    let schema = StatusVariants::json_schema();
    let one_of = schema["oneOf"].as_array().unwrap();
    assert_eq!(one_of.len(), 3);
}

#[test]
fn json_schema_enum_description() {
    let schema = StatusVariants::json_schema();
    assert_eq!(schema["description"], "Status with mixed variants.");
}

/// Every default Serde enum representation must survive schema admission.
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize, JsonSchema)]
enum WireEnum {
    Idle,
    Message(String),
    Pair(String, u32),
    Record {
        /// Required work count.
        count: u32,
        label: Option<String>,
    },
    EmptyTuple(),
    EmptyRecord {},
}

#[test]
fn json_schema_external_enum_accepts_actual_serde_payloads() {
    let schema = fastmcp_rust::schema::admit_final_schema(WireEnum::json_schema())
        .expect("derived enum is a valid final-dialect schema");
    for value in [
        WireEnum::Idle,
        WireEnum::Message("hello".to_owned()),
        WireEnum::Pair("work".to_owned(), 3),
        WireEnum::Record {
            count: 3,
            label: None,
        },
        WireEnum::Record {
            count: 3,
            label: Some("work".to_owned()),
        },
        WireEnum::EmptyTuple(),
        WireEnum::EmptyRecord {},
    ] {
        let encoded = serde_json::to_value(&value).expect("enum serializes");
        schema
            .validate(&encoded)
            .expect("actual Serde payload must be admitted");
        assert_eq!(
            serde_json::from_str::<WireEnum>(&serde_json::to_string(&value).unwrap()).unwrap(),
            value
        );
    }
    schema
        .validate(&json!({"Record": {"count": 3}}))
        .expect("omitted Option field stays optional inside a variant");
    assert!(schema.schema()["oneOf"][4]["properties"]["EmptyTuple"]
        .get("prefixItems")
        .is_none());
    assert_eq!(
        schema.schema()["oneOf"][3]["properties"]["Record"]["properties"]["count"]["description"],
        "Required work count."
    );
}

#[test]
fn json_schema_external_enum_rejects_wrong_tags_and_payload_shapes() {
    let schema = fastmcp_rust::schema::admit_final_schema(WireEnum::json_schema()).unwrap();
    // Serde accepts this alternate unit representation on input, but emits a
    // string. The generated schema describes its canonical serialized form.
    assert!(schema.validate(&json!({"Idle": null})).is_err());
    for invalid in [
        json!("Unknown"),
        json!({"Message": 3}),
        json!({"Message": "hello", "extra": true}),
        json!({"Message": "hello", "Pair": ["work", 3]}),
        json!({"Pair": {}}),
        json!({"Pair": ["work"]}),
        json!({"Pair": ["work", 3, 4]}),
        json!({"Pair": [3, "work"]}),
        json!({"Record": {}}),
        json!({"Record": {"count": "three"}}),
        json!({"Record": {"count": 3, "label": false}}),
        json!({"EmptyTuple": {}}),
        json!({"EmptyTuple": [1]}),
        json!({"EmptyRecord": []}),
    ] {
        assert!(
            serde_json::from_value::<WireEnum>(invalid.clone()).is_err(),
            "{invalid}"
        );
        assert!(schema.validate(&invalid).is_err(), "{invalid}");
    }
}

#[tool]
fn describe_wire_enum(value: WireEnum) -> String {
    format!("{value:?}")
}

#[test]
fn json_schema_external_enum_reaches_registered_modern_tool() {
    let server = Server::new("enum-schema", "1.0.0")
        .tool(DescribeWireEnum)
        .build();
    let connection = ModernConnection::new();
    for value in [
        json!("Idle"),
        json!({"Pair": ["work", 3]}),
        json!({"Record": {"count": 3}}),
    ] {
        let request = JsonRpcRequest::new(
            "tools/call",
            Some(json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
                "name": "describe_wire_enum",
                "arguments": {"value": value},
            })),
            64_i64,
        );
        let response = server
            .dispatch_stateless(&facade_final_inbound(&connection), &request)
            .expect("registered enum tool produces a response");
        assert!(response.error.is_none(), "{:?}", response.error);
        let result = response.result.expect("enum tool produced a result");
        assert_eq!(result["resultType"], "complete");
        assert!(result["content"][0]["text"]
            .as_str()
            .is_some_and(|text| !text.is_empty()));
    }
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RecursiveSchemaNode {
    value: i32,
    children: Vec<Self>,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize, JsonSchema)]
enum RecursiveSchemaExpression {
    Literal(i64),
    Negate(Box<Self>),
    Add(Box<Self>, Box<Self>),
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize, JsonSchema)]
struct RecursiveSchemaBranch {
    label: String,
    edge: Option<Box<RecursiveSchemaEdge>>,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize, JsonSchema)]
enum RecursiveSchemaEdge {
    Finish,
    Visit(RecursiveSchemaBranch),
}

#[test]
fn json_schema_recursive_struct_preserves_constraints_at_every_level() {
    let generated = RecursiveSchemaNode::try_json_schema()
        .expect("finite local definitions represent a recursive Vec");
    assert_eq!(generated, RecursiveSchemaNode::json_schema());
    assert_eq!(generated["type"], "object");
    assert_eq!(generated["$defs"].as_object().unwrap().len(), 1);
    let schema = fastmcp_rust::schema::admit_final_schema(generated)
        .expect("every recursive reference resolves inside the standalone document");
    let valid = json!({
        "value": 1,
        "children": [{"value": 2, "children": [{"value": 3, "children": []}]}]
    });
    schema.validate(&valid).expect("nested tree is admitted");
    let tree: RecursiveSchemaNode = serde_json::from_value(valid.clone()).unwrap();
    assert_eq!(serde_json::to_value(tree).unwrap(), valid);
    for invalid in [
        json!({"value": 1, "children": [{"value": "two", "children": []}]}),
        json!({"value": 1, "children": [{"value": 2, "children": [], "extra": true}]}),
        json!({"value": 1, "children": [{"value": 2}]}),
    ] {
        assert!(schema.validate(&invalid).is_err(), "{invalid}");
        assert!(serde_json::from_value::<RecursiveSchemaNode>(invalid).is_err());
    }
}

#[test]
fn json_schema_recursive_enum_and_mutual_recursion_follow_serde() {
    let expression_schema =
        fastmcp_rust::schema::admit_final_schema(RecursiveSchemaExpression::json_schema())
            .expect("recursive enum emits a closed local reference graph");
    let expression = RecursiveSchemaExpression::Add(
        Box::new(RecursiveSchemaExpression::Literal(4)),
        Box::new(RecursiveSchemaExpression::Negate(Box::new(
            RecursiveSchemaExpression::Literal(2),
        ))),
    );
    let valid = serde_json::to_value(&expression).unwrap();
    expression_schema.validate(&valid).unwrap();
    assert_eq!(
        serde_json::from_value::<RecursiveSchemaExpression>(valid.clone()).unwrap(),
        expression
    );
    let mut invalid = valid;
    invalid["Add"][1]["Negate"]["Literal"] = json!("two");
    assert!(expression_schema.validate(&invalid).is_err());
    assert!(serde_json::from_value::<RecursiveSchemaExpression>(invalid).is_err());

    let branch_schema =
        fastmcp_rust::schema::admit_final_schema(RecursiveSchemaBranch::json_schema())
            .expect("mutually recursive types resolve in one generation context");
    let valid = json!({
        "label": "root",
        "edge": {"Visit": {"label": "child", "edge": "Finish"}}
    });
    branch_schema.validate(&valid).unwrap();
    serde_json::from_value::<RecursiveSchemaBranch>(valid.clone()).unwrap();
    let mut invalid = valid;
    invalid["edge"]["Visit"]["label"] = json!(false);
    assert!(branch_schema.validate(&invalid).is_err());
    assert!(serde_json::from_value::<RecursiveSchemaBranch>(invalid).is_err());
}

#[derive(JsonSchema)]
struct RecursiveSchemaArray<const N: usize> {
    bytes: [u8; N],
    next: Option<Box<Self>>,
}

#[derive(JsonSchema)]
struct DistinctRecursiveSchemaArrays {
    two: RecursiveSchemaArray<2>,
    three: RecursiveSchemaArray<3>,
}

#[derive(JsonSchema)]
struct RecursiveSchemaPointers {
    boxed: Box<RecursiveSchemaNode>,
    shared: std::sync::Arc<RecursiveSchemaNode>,
    local: std::rc::Rc<RecursiveSchemaNode>,
    slice: Box<[RecursiveSchemaNode]>,
}

#[derive(JsonSchema)]
struct BorrowedRecursiveSchema<'a> {
    label: &'a str,
    child: Option<Box<Self>>,
}

#[test]
fn json_schema_borrowed_recursive_type_uses_static_schema_instantiation() {
    let generated = BorrowedRecursiveSchema::<'static>::try_json_schema()
        .expect("schema generation needs a type identity without constructing a value");
    let schema = fastmcp_rust::schema::admit_final_schema(generated).unwrap();
    let valid = json!({"label": "parent", "child": {"label": "child", "child": null}});
    schema.validate(&valid).unwrap();
    let mut invalid = valid;
    invalid["child"]["label"] = json!(false);
    assert!(schema.validate(&invalid).is_err());
}

#[test]
fn json_schema_recursive_generic_instances_and_shared_pointers_do_not_alias() {
    let schema =
        fastmcp_rust::schema::admit_final_schema(DistinctRecursiveSchemaArrays::json_schema())
            .expect("different const-generic instantiations retain separate definitions");
    assert_eq!(schema.schema()["$defs"].as_object().unwrap().len(), 2);
    let valid = json!({
        "two": {"bytes": [1, 2], "next": {"bytes": [3, 4]}},
        "three": {"bytes": [1, 2, 3], "next": {"bytes": [4, 5, 6]}}
    });
    schema.validate(&valid).unwrap();
    let mut invalid = valid;
    invalid["three"]["next"]["bytes"] = json!([4, 5]);
    assert!(schema.validate(&invalid).is_err());

    let pointers = fastmcp_rust::schema::admit_final_schema(RecursiveSchemaPointers::json_schema())
        .expect("transparent pointers and slices preserve the recursive payload");
    let leaf = json!({"value": 1, "children": []});
    let valid = json!({
        "boxed": leaf.clone(), "shared": leaf.clone(), "local": leaf.clone(),
        "slice": [leaf]
    });
    pointers.validate(&valid).unwrap();
    let mut invalid = valid;
    invalid["shared"]["value"] = json!(false);
    assert!(pointers.validate(&invalid).is_err());
}

static RECURSIVE_SCHEMA_TOOL_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[tool]
fn compare_recursive_schema_trees(left: RecursiveSchemaNode, right: RecursiveSchemaNode) -> String {
    RECURSIVE_SCHEMA_TOOL_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    format!("{}:{}", left.value, right.value)
}

#[test]
fn json_schema_recursive_arguments_share_definitions_in_registered_modern_tool() {
    let definition = CompareRecursiveSchemaTrees.definition();
    assert_eq!(definition.input_schema["type"], "object");
    assert_eq!(
        definition.input_schema["$defs"].as_object().unwrap().len(),
        1
    );
    fastmcp_rust::schema::admit_final_schema(definition.input_schema)
        .expect("multiple recursive arguments form one standalone input schema");
    let server = Server::new("recursive-schema", "1.0.0")
        .tool(CompareRecursiveSchemaTrees)
        .build();
    let connection = ModernConnection::new();
    let request = |arguments| {
        JsonRpcRequest::new(
            "tools/call",
            Some(json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
                "name": "compare_recursive_schema_trees",
                "arguments": arguments,
            })),
            64_i64,
        )
    };
    let valid = json!({
        "left": {"value": 1, "children": [{"value": 2, "children": []}]},
        "right": {"value": 3, "children": [{"value": 4, "children": []}]}
    });
    let before = RECURSIVE_SCHEMA_TOOL_CALLS.load(std::sync::atomic::Ordering::SeqCst);
    let response = server
        .dispatch_stateless(&facade_final_inbound(&connection), &request(valid.clone()))
        .expect("registered recursive input tool produces a response");
    assert!(response.error.is_none(), "{:?}", response.error);
    let result = response.result.unwrap();
    assert_eq!(result["resultType"], "complete");
    assert_ne!(result["isError"], json!(true));
    assert_eq!(result["content"][0]["text"], "1:3");
    assert_eq!(
        RECURSIVE_SCHEMA_TOOL_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        before + 1
    );
    let mut invalid = valid;
    invalid["right"]["children"][0]["value"] = json!("four");
    let response = server
        .dispatch_stateless(&facade_final_inbound(&connection), &request(invalid))
        .expect("nested invalid input produces a tool execution error");
    assert!(response.error.is_none(), "{:?}", response.error);
    let result = response.result.unwrap();
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["isError"], json!(true));
    assert_eq!(
        RECURSIVE_SCHEMA_TOOL_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        before + 1,
        "recursive input validation must finish before the handler runs"
    );
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize, JsonSchema)]
enum OptionalUnitChoice {
    First,
    Second,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
enum ConstChoice {
    Allowed,
}

impl ConstChoice {
    fn json_schema() -> serde_json::Value {
        json!({"type": "string", "const": "Allowed"})
    }
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
struct ConjunctionChoice(ConstChoice);

impl ConjunctionChoice {
    fn json_schema() -> serde_json::Value {
        json!({
            "allOf": [{"type": "string"}, {"enum": ["Allowed"]}],
            "not": {"const": "Denied"}
        })
    }
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
enum AlreadyNullableChoice {
    Empty(()),
    Choice(ConstChoice),
}

impl AlreadyNullableChoice {
    fn json_schema() -> serde_json::Value {
        json!({"oneOf": [{"type": "null"}, ConstChoice::json_schema()]})
    }
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
struct DialectChoice(ConstChoice);

impl DialectChoice {
    fn json_schema() -> serde_json::Value {
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "const": "Allowed"
        })
    }
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize, JsonSchema)]
struct OptionalDialectChoice(Option<DialectChoice>);

#[test]
fn json_schema_optional_newtype_keeps_custom_root_dialect_admissible() {
    let schema = fastmcp_rust::schema::admit_final_schema(OptionalDialectChoice::json_schema())
        .expect("the optional newtype retains a valid document-root dialect");
    for value in [
        OptionalDialectChoice(None),
        OptionalDialectChoice(Some(DialectChoice(ConstChoice::Allowed))),
    ] {
        let encoded = serde_json::to_value(&value).unwrap();
        schema
            .validate(&encoded)
            .expect("nullable dialect preserves accepted values");
        assert_eq!(
            serde_json::from_value::<OptionalDialectChoice>(encoded).unwrap(),
            value
        );
    }
    assert!(schema.validate(&json!("Denied")).is_err());
    assert!(serde_json::from_value::<OptionalDialectChoice>(json!("Denied")).is_err());
    assert_eq!(
        schema.schema()["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
struct IdentifiedChoice(ConstChoice);

impl IdentifiedChoice {
    fn json_schema() -> serde_json::Value {
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://schemas.example.test/nullable-choice",
            "$defs": {"choice": ConstChoice::json_schema()},
            "$ref": "#/$defs/choice"
        })
    }
}

#[derive(JsonSchema)]
struct DescribedIdentifiedSchema {
    /// The annotation must not change the handwritten resource's scope.
    choice: IdentifiedChoice,
}

struct UnscopedManualSchema;

impl UnscopedManualSchema {
    fn json_schema() -> serde_json::Value {
        json!({
            "$defs": {"type_1": {"type": "boolean"}},
            "$ref": "#/$defs/type_1"
        })
    }
}

#[derive(JsonSchema)]
struct DescribedUnscopedSchema {
    recursive: RecursiveSchemaNode,
    /// Adding a description must not bypass handwritten reference admission.
    manual: UnscopedManualSchema,
}

#[test]
fn json_schema_custom_provider_annotations_preserve_resource_boundaries() {
    let schema = fastmcp_rust::schema::admit_final_schema(
        DescribedIdentifiedSchema::try_json_schema()
            .expect("a described handwritten resource keeps its own identity"),
    )
    .unwrap();
    schema.validate(&json!({"choice": "Allowed"})).unwrap();
    assert!(schema.validate(&json!({"choice": "Denied"})).is_err());
    assert_eq!(
        DescribedUnscopedSchema::try_json_schema(),
        Err(fastmcp_rust::schema::SchemaGenerationError::ReferenceResourceBoundary),
        "a described manual local ref cannot capture the generated recursive definition"
    );
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize, JsonSchema)]
struct OptionalIdentifiedChoice {
    choice: Option<IdentifiedChoice>,
}

#[test]
fn json_schema_optional_identified_resource_keeps_its_reference_scope() {
    let schema = fastmcp_rust::schema::admit_final_schema(OptionalIdentifiedChoice::json_schema())
        .expect("an explicitly identified custom resource remains admissible when nullable");
    for encoded in [
        json!({}),
        json!({"choice": null}),
        json!({"choice": "Allowed"}),
    ] {
        schema
            .validate(&encoded)
            .expect("the resource-local ref resolves within its original id");
        serde_json::from_value::<OptionalIdentifiedChoice>(encoded).unwrap();
    }
    assert!(schema.validate(&json!({"choice": "Denied"})).is_err());
    assert!(
        serde_json::from_value::<OptionalIdentifiedChoice>(json!({"choice": "Denied"})).is_err()
    );
    assert_eq!(
        schema.schema()["properties"]["choice"]["anyOf"][0],
        IdentifiedChoice::json_schema()
    );
}

#[derive(Debug, Default, PartialEq, serde::Serialize, serde::Deserialize, JsonSchema)]
struct OptionalSchemaArguments {
    unit: Option<OptionalUnitChoice>,
    mixed: Option<WireEnum>,
    constant: Option<ConstChoice>,
    conjunction: Option<ConjunctionChoice>,
    already_nullable: Option<AlreadyNullableChoice>,
}

fn optional_schema_argument_pairs() -> [(serde_json::Value, serde_json::Value); 7] {
    [
        (json!({"unit": "First"}), json!({"unit": "Unknown"})),
        (json!({"mixed": "Idle"}), json!({"mixed": "Unknown"})),
        (
            json!({"mixed": {"Pair": ["work", 3]}}),
            json!({"mixed": {"Pair": ["work"]}}),
        ),
        (json!({"constant": "Allowed"}), json!({"constant": "Denied"})),
        (
            json!({"conjunction": "Allowed"}),
            json!({"conjunction": "Denied"}),
        ),
        (
            json!({"already_nullable": "Allowed"}),
            json!({"already_nullable": "Denied"}),
        ),
        (
            json!({"already_nullable": null}),
            json!({"already_nullable": []}),
        ),
    ]
}

#[test]
fn json_schema_optional_custom_types_accept_null_and_actual_serde_payloads() {
    let schema = fastmcp_rust::schema::admit_final_schema(OptionalSchemaArguments::json_schema())
        .expect("nullable custom schemas pass final-dialect admission");
    for value in [
        OptionalSchemaArguments::default(),
        OptionalSchemaArguments {
            unit: Some(OptionalUnitChoice::First),
            mixed: Some(WireEnum::Pair("work".to_owned(), 3)),
            constant: Some(ConstChoice::Allowed),
            conjunction: Some(ConjunctionChoice(ConstChoice::Allowed)),
            already_nullable: Some(AlreadyNullableChoice::Choice(ConstChoice::Allowed)),
        },
        OptionalSchemaArguments {
            unit: Some(OptionalUnitChoice::Second),
            mixed: Some(WireEnum::Idle),
            ..OptionalSchemaArguments::default()
        },
    ] {
        let encoded = serde_json::to_value(&value).unwrap();
        schema
            .validate(&encoded)
            .expect("Some and None preserve their Serde wire form");
        assert_eq!(
            serde_json::from_value::<OptionalSchemaArguments>(encoded).unwrap(),
            value
        );
    }
    schema
        .validate(&json!({}))
        .expect("all optional fields may be absent");
    assert_eq!(
        serde_json::from_value::<OptionalSchemaArguments>(json!({})).unwrap(),
        OptionalSchemaArguments::default()
    );
    // The inner oneOf already matches null. Adding null must use anyOf so the
    // two matching nullable branches cannot cancel each other out.
    assert_eq!(
        serde_json::from_value::<AlreadyNullableChoice>(json!(null)).unwrap(),
        AlreadyNullableChoice::Empty(())
    );
    schema.validate(&json!({"already_nullable": null})).unwrap();
}

#[test]
fn json_schema_optional_custom_types_preserve_non_null_constraints() {
    let schema = fastmcp_rust::schema::admit_final_schema(OptionalSchemaArguments::json_schema())
        .expect("optional argument schema is admitted");
    for (valid, invalid) in optional_schema_argument_pairs() {
        schema
            .validate(&valid)
            .expect("the matched valid control is admitted");
        serde_json::from_value::<OptionalSchemaArguments>(valid).unwrap();
        assert!(schema.validate(&invalid).is_err(), "{invalid}");
        assert!(
            serde_json::from_value::<OptionalSchemaArguments>(invalid.clone()).is_err(),
            "{invalid}"
        );
    }
}

static OPTIONAL_SCHEMA_TOOL_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[tool]
fn describe_optional_schema(
    unit: Option<OptionalUnitChoice>,
    mixed: Option<WireEnum>,
    constant: Option<ConstChoice>,
    conjunction: Option<ConjunctionChoice>,
    already_nullable: Option<AlreadyNullableChoice>,
) -> McpResult<String> {
    OPTIONAL_SCHEMA_TOOL_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    serde_json::to_string(&OptionalSchemaArguments {
        unit,
        mixed,
        constant,
        conjunction,
        already_nullable,
    })
    .map_err(McpError::from)
}

#[test]
fn json_schema_optional_custom_types_reach_registered_modern_tool() {
    let server = Server::new("optional-schema", "1.0.0")
        .tool(DescribeOptionalSchema)
        .build();
    let connection = ModernConnection::new();
    let request = |arguments| {
        JsonRpcRequest::new(
            "tools/call",
            Some(json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
                "name": "describe_optional_schema",
                "arguments": arguments,
            })),
            64_i64,
        )
    };
    for arguments in [
        json!({}),
        json!({"unit": null, "mixed": null, "constant": null, "conjunction": null,
            "already_nullable": null}),
        json!({"unit": "First", "mixed": {"Pair": ["work", 3]}, "constant": "Allowed",
            "conjunction": "Allowed", "already_nullable": "Allowed"}),
    ] {
        let expected: OptionalSchemaArguments =
            serde_json::from_value(arguments.clone()).unwrap();
        let before = OPTIONAL_SCHEMA_TOOL_CALLS.load(std::sync::atomic::Ordering::SeqCst);
        let response = server
            .dispatch_stateless(&facade_final_inbound(&connection), &request(arguments))
            .expect("the registered optional tool returns a response");
        assert!(response.error.is_none(), "{:?}", response.error);
        let result = response
            .result
            .expect("tool returned its actual decoded arguments");
        assert_eq!(result["resultType"], "complete");
        assert_ne!(result["isError"], json!(true));
        let actual: OptionalSchemaArguments = serde_json::from_str(
            result["content"][0]["text"]
                .as_str()
                .expect("serialized handler arguments"),
        )
        .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            OPTIONAL_SCHEMA_TOOL_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            before + 1
        );
    }
    for (valid, invalid) in optional_schema_argument_pairs() {
        let positive = server
            .dispatch_stateless(&facade_final_inbound(&connection), &request(valid))
            .expect("the matched optional argument reaches the tool");
        assert!(positive.error.is_none());
        let result = positive
            .result
            .expect("the matched positive returns application content");
        assert_eq!(result["resultType"], "complete");
        assert_ne!(result["isError"], json!(true));
        let before = OPTIONAL_SCHEMA_TOOL_CALLS.load(std::sync::atomic::Ordering::SeqCst);
        let response = server
            .dispatch_stateless(&facade_final_inbound(&connection), &request(invalid))
            .expect("invalid optional values receive a protocol response");
        assert!(
            response.error.is_some()
                || response
                    .result
                    .as_ref()
                    .is_some_and(|result| result["isError"] == json!(true))
        );
        assert_eq!(
            OPTIONAL_SCHEMA_TOOL_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            before,
            "invalid non-null values must not reach application code"
        );
    }
}

#[derive(Debug, Default, PartialEq)]
struct SerdeSchemaLocalState;

fn serde_schema_default_retry_limit() -> u32 {
    3
}

#[derive(Debug, Default, PartialEq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SerdeWireArguments {
    user_name: String,
    #[serde(rename = "account-id")]
    account_id: u32,
    #[serde(default = "serde_schema_default_retry_limit")]
    retry_limit: u32,
    #[serde(default)]
    labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(skip)]
    local_only: SerdeSchemaLocalState,
    r#type: String,
}

fn serde_schema_valid_arguments() -> serde_json::Value {
    json!({"userName": "Ada", "account-id": 7, "type": "job"})
}

fn serde_schema_argument_pairs() -> Vec<(serde_json::Value, serde_json::Value)> {
    let valid = serde_schema_valid_arguments();
    vec![
        (
            valid.clone(),
            json!({"user_name": "Ada", "account-id": 7, "type": "job"}),
        ),
        (
            valid.clone(),
            json!({"userName": "Ada", "accountId": 7, "type": "job"}),
        ),
        (valid.clone(), json!({"account-id": 7, "type": "job"})),
        (
            valid.clone(),
            json!({"userName": "Ada", "account-id": "seven", "type": "job"}),
        ),
        (
            valid.clone(),
            json!({"userName": "Ada", "account-id": 7, "type": "job", "retryLimit": null}),
        ),
        (
            valid,
            json!({"userName": "Ada", "account-id": 7, "type": "job", "localOnly": {}}),
        ),
    ]
}

#[test]
fn json_schema_serde_names_defaults_and_skips_match_wire_values() {
    let schema = fastmcp_rust::schema::admit_final_schema(SerdeWireArguments::json_schema())
        .expect("Serde field attributes produce an admissible schema");
    for value in [
        serde_schema_valid_arguments(),
        json!({"userName": "Ada", "account-id": 7, "type": "job", "retryLimit": 9,
            "labels": ["urgent"], "displayName": "Ada L."}),
    ] {
        let decoded: SerdeWireArguments = serde_json::from_value(value.clone()).unwrap();
        schema.validate(&value).unwrap();
        let encoded = serde_json::to_value(&decoded).unwrap();
        schema.validate(&encoded).unwrap();
        assert!(encoded.get("localOnly").is_none());
        assert!(encoded.get("local_only").is_none());
    }
    let defaults: SerdeWireArguments =
        serde_json::from_value(serde_schema_valid_arguments()).unwrap();
    assert_eq!(defaults.retry_limit, 3);
    assert!(defaults.labels.is_empty());
    assert_eq!(defaults.local_only, SerdeSchemaLocalState);
    assert_eq!(
        schema.schema()["required"],
        json!(["userName", "account-id", "type"])
    );
    assert_eq!(schema.schema()["additionalProperties"], false);
    assert!(schema.schema()["properties"].get("retryLimit").is_some());
    assert!(schema.schema()["properties"].get("r#type").is_none());
}

#[test]
fn json_schema_serde_names_reject_wrong_fields_and_missing_required() {
    let schema =
        fastmcp_rust::schema::admit_final_schema(SerdeWireArguments::json_schema()).unwrap();
    for (valid, invalid) in serde_schema_argument_pairs() {
        schema.validate(&valid).unwrap();
        serde_json::from_value::<SerdeWireArguments>(valid).unwrap();
        assert!(schema.validate(&invalid).is_err(), "{invalid}");
        assert!(serde_json::from_value::<SerdeWireArguments>(invalid).is_err());
    }
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(default = "serde_schema_container_default", rename_all = "kebab-case")]
struct SerdeDefaultedContainer {
    retry_limit: u32,
    queue_name: String,
}

static SERDE_SCHEMA_DEFAULT_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn serde_schema_container_default() -> SerdeDefaultedContainer {
    SERDE_SCHEMA_DEFAULT_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    SerdeDefaultedContainer {
        retry_limit: 5,
        queue_name: "general".to_owned(),
    }
}

#[test]
fn json_schema_serde_container_defaults_do_not_run_during_generation() {
    let before = SERDE_SCHEMA_DEFAULT_CALLS.load(std::sync::atomic::Ordering::SeqCst);
    let schema = fastmcp_rust::schema::admit_final_schema(SerdeDefaultedContainer::json_schema())
        .expect("container default only changes omission constraints");
    assert_eq!(
        SERDE_SCHEMA_DEFAULT_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        before
    );
    for value in [
        json!({}),
        json!({"retry-limit": 9}),
        json!({"queue-name": "urgent"}),
    ] {
        schema.validate(&value).unwrap();
        let decoded: SerdeDefaultedContainer = serde_json::from_value(value).unwrap();
        schema
            .validate(&serde_json::to_value(decoded).unwrap())
            .unwrap();
    }
    for value in [json!({"retry-limit": null}), json!({"queue-name": false})] {
        assert!(schema.validate(&value).is_err());
        assert!(serde_json::from_value::<SerdeDefaultedContainer>(value).is_err());
    }
    assert_eq!(schema.schema()["required"], json!([]));
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum SerdeWireEnum {
    HTTP2Ready,
    #[serde(rename = "manual-tag")]
    ManuallyNamed {
        job_count: u32,
        #[serde(default)]
        optional_note: String,
        #[serde(skip)]
        local_only: SerdeSchemaLocalState,
    },
    #[serde(rename_all = "kebab-case")]
    FieldOverride {
        job_count: u32,
        #[serde(rename = "exactName")]
        item_id: String,
    },
    #[serde(skip)]
    Hidden,
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize, JsonSchema)]
#[serde(rename_all(serialize = "SCREAMING-KEBAB-CASE", deserialize = "SCREAMING-KEBAB-CASE"))]
enum SerdeWireUnitEnum {
    HTTP2Ready,
    #[serde(rename(serialize = "ready-now", deserialize = "ready-now"))]
    ReadyNow,
    #[serde(skip)]
    Hidden,
}

#[test]
fn json_schema_serde_enum_names_and_field_rules_match_wire_values() {
    let schema = fastmcp_rust::schema::admit_final_schema(SerdeWireEnum::json_schema()).unwrap();
    for value in [
        json!("h_t_t_p2_ready"),
        json!({"manual-tag": {"jobCount": 2}}),
        json!({"field_override": {"job-count": 2, "exactName": "A"}}),
    ] {
        schema.validate(&value).unwrap();
        let decoded: SerdeWireEnum = serde_json::from_value(value).unwrap();
        schema
            .validate(&serde_json::to_value(decoded).unwrap())
            .unwrap();
    }
    for value in [
        json!("http2_ready"),
        json!("hidden"),
        json!({"manually_named": {"jobCount": 2}}),
        json!({"manual-tag": {"job_count": 2}}),
        json!({"field_override": {"jobCount": 2, "exactName": "A"}}),
        json!({"field_override": {"job-count": 2, "item-id": "A"}}),
        json!({"manual-tag": {"jobCount": 2, "localOnly": {}}}),
    ] {
        assert!(schema.validate(&value).is_err(), "{value}");
        assert!(serde_json::from_value::<SerdeWireEnum>(value).is_err());
    }
    let units = fastmcp_rust::schema::admit_final_schema(SerdeWireUnitEnum::json_schema()).unwrap();
    assert_eq!(units.schema()["enum"], json!(["H-T-T-P2-READY", "ready-now"]));
    for value in [SerdeWireUnitEnum::HTTP2Ready, SerdeWireUnitEnum::ReadyNow] {
        let encoded = serde_json::to_value(&value).unwrap();
        units.validate(&encoded).unwrap();
        assert_eq!(
            serde_json::from_value::<SerdeWireUnitEnum>(encoded).unwrap(),
            value
        );
    }
    assert!(units.validate(&json!("HIDDEN")).is_err());
}

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize, JsonSchema)]
struct SerdeTupleWire(
    String,
    #[serde(skip)] SerdeSchemaLocalState,
    #[serde(default)] u32,
);

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize, JsonSchema)]
struct SerdeOneRetainedTuple(#[serde(skip)] SerdeSchemaLocalState, String);

#[test]
fn json_schema_serde_tuple_skips_preserve_array_positions() {
    let schema = fastmcp_rust::schema::admit_final_schema(SerdeTupleWire::json_schema()).unwrap();
    for value in [json!(["work"]), json!(["work", 3])] {
        let decoded: SerdeTupleWire = serde_json::from_value(value.clone()).unwrap();
        schema.validate(&value).unwrap();
        schema
            .validate(&serde_json::to_value(decoded).unwrap())
            .unwrap();
    }
    for value in [json!([]), json!(["work", null]), json!(["work", {}, 3])] {
        assert!(schema.validate(&value).is_err());
        assert!(serde_json::from_value::<SerdeTupleWire>(value).is_err());
    }
    let one =
        fastmcp_rust::schema::admit_final_schema(SerdeOneRetainedTuple::json_schema()).unwrap();
    let value = SerdeOneRetainedTuple(SerdeSchemaLocalState, "work".to_owned());
    let encoded = serde_json::to_value(&value).unwrap();
    assert_eq!(encoded, json!(["work"]));
    one.validate(&encoded).unwrap();
    assert_eq!(
        serde_json::from_value::<SerdeOneRetainedTuple>(encoded).unwrap(),
        value
    );
    assert!(one.validate(&json!("work")).is_err());
}

#[derive(serde::Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct SerdeSchemaOverride {
    #[serde(rename = "serde-name")]
    #[json_schema(rename = "schema-name")]
    field_name: String,
}

#[test]
fn json_schema_serde_schema_override_precedence_is_explicit() {
    let schema =
        fastmcp_rust::schema::admit_final_schema(SerdeSchemaOverride::json_schema()).unwrap();
    assert_eq!(schema.schema()["required"], json!(["schema-name"]));
    assert!(schema.schema()["properties"].get("schema-name").is_some());
    assert!(schema.schema()["properties"].get("serde-name").is_none());
    let encoded = serde_json::to_value(SerdeSchemaOverride {
        field_name: "work".to_owned(),
    })
    .unwrap();
    assert_eq!(encoded, json!({"serde-name": "work"}));
    assert!(
        schema.validate(&encoded).is_err(),
        "explicit schema override retains responsibility for wire parity"
    );
    schema.validate(&json!({"schema-name": "work"})).unwrap();
}

static SERDE_SCHEMA_TOOL_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[tool]
fn describe_serde_schema(value: SerdeWireArguments) -> McpResult<String> {
    SERDE_SCHEMA_TOOL_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    serde_json::to_string(&value).map_err(McpError::from)
}

#[test]
fn json_schema_serde_names_and_defaults_reach_registered_modern_tool() {
    let server = Server::new("serde-schema", "1.0.0")
        .tool(DescribeSerdeSchema)
        .build();
    let connection = ModernConnection::new();
    let request = |value| {
        JsonRpcRequest::new(
            "tools/call",
            Some(json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
                "name": "describe_serde_schema",
                "arguments": {"value": value},
            })),
            64_i64,
        )
    };
    for (valid, invalid) in serde_schema_argument_pairs() {
        let expected: SerdeWireArguments = serde_json::from_value(valid.clone()).unwrap();
        let before = SERDE_SCHEMA_TOOL_CALLS.load(std::sync::atomic::Ordering::SeqCst);
        let response = server
            .dispatch_stateless(&facade_final_inbound(&connection), &request(valid))
            .unwrap();
        assert!(response.error.is_none(), "{:?}", response.error);
        let result = response.result.unwrap();
        assert_eq!(result["resultType"], "complete");
        assert_ne!(result["isError"], json!(true));
        let actual: SerdeWireArguments =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            SERDE_SCHEMA_TOOL_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            before + 1
        );
        let response = server
            .dispatch_stateless(&facade_final_inbound(&connection), &request(invalid))
            .unwrap();
        assert!(
            response.error.is_some()
                || response
                    .result
                    .as_ref()
                    .is_some_and(|result| result["isError"] == json!(true))
        );
        assert_eq!(
            SERDE_SCHEMA_TOOL_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            before + 1,
            "invalid neighboring arguments do not invoke the handler"
        );
    }
}

const SHAPED_SCHEMA_ARRAY_WIDTH: usize = 2;

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize, JsonSchema)]
struct ShapedSchemaInferredArray([u8; !0 >> (usize::BITS - 1)]);

#[allow(non_upper_case_globals)]
const __fastmcp_array_length: usize = 2;

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize, JsonSchema)]
struct ShapedSchemaHygienicArray([[u8; __fastmcp_array_length]; 1]);

#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize, JsonSchema)]
struct ShapedSchemaArguments {
    pair: (String, u16),
    singleton: (bool,),
    fixed: [i16; SHAPED_SCHEMA_ARRAY_WIDTH + 1],
    empty: [bool; 0],
    nested: Vec<(u8, [String; 2])>,
    glyph: char,
    optional_glyph: Option<char>,
    unit: (),
    tiny: i8,
}

fn shaped_schema_valid_arguments() -> serde_json::Value {
    json!({
        "pair": ["work", 65535],
        "singleton": [true],
        "fixed": [-32768, 0, 32767],
        "empty": [],
        "nested": [[255, ["A", "B"]]],
        "glyph": "🦀",
        "unit": null,
        "tiny": 127,
    })
}

fn shaped_schema_argument_pairs() -> Vec<(serde_json::Value, serde_json::Value)> {
    let valid = shaped_schema_valid_arguments();
    [
        ("pair", json!(["work"])),
        ("pair", json!(["work", 65535, true])),
        ("pair", json!(["work", 65536])),
        ("pair", json!(["work", -1])),
        ("singleton", json!(true)),
        ("fixed", json!([-32768, 0])),
        ("fixed", json!([-32768, 0, 32767, 1])),
        ("fixed", json!([-32769, 0, 32767])),
        ("empty", json!([true])),
        ("nested", json!([[256, ["A", "B"]]])),
        ("nested", json!([[255, ["A"]]])),
        ("glyph", json!("")),
        ("glyph", json!("🦀🦀")),
        ("optional_glyph", json!("AB")),
        ("unit", json!([])),
        ("tiny", json!(128)),
    ]
    .into_iter()
    .map(|(field, value)| {
        let mut invalid = valid.clone();
        invalid[field] = value;
        (valid.clone(), invalid)
    })
    .collect()
}

#[test]
fn json_schema_tuple_and_array_shapes_match_serde() {
    let schema = fastmcp_rust::schema::admit_final_schema(ShapedSchemaArguments::json_schema())
        .expect("tuples, arrays, unit, and char produce an admissible schema");
    let mut alternate = shaped_schema_valid_arguments();
    alternate["nested"] = json!([]);
    alternate["glyph"] = json!("é");
    alternate["optional_glyph"] = json!("A");
    alternate["tiny"] = json!(-128);
    for value in [shaped_schema_valid_arguments(), alternate] {
        let decoded: ShapedSchemaArguments = serde_json::from_value(value.clone()).unwrap();
        schema.validate(&value).unwrap();
        let encoded = serde_json::to_value(&decoded).unwrap();
        schema.validate(&encoded).unwrap();
        assert_eq!(
            serde_json::from_value::<ShapedSchemaArguments>(encoded).unwrap(),
            decoded
        );
    }
    let properties = &schema.schema()["properties"];
    assert_eq!(properties["pair"]["minItems"], 2);
    assert_eq!(properties["pair"]["maxItems"], 2);
    assert_eq!(properties["singleton"]["type"], "array");
    assert_eq!(properties["singleton"]["minItems"], 1);
    assert_eq!(properties["fixed"]["minItems"], 3);
    assert_eq!(properties["fixed"]["maxItems"], 3);
    assert_eq!(properties["empty"]["maxItems"], 0);
    assert!(properties["empty"].get("prefixItems").is_none());
    assert_eq!(properties["unit"]["type"], "null");
    assert!(properties["unit"].get("prefixItems").is_none());
    assert_eq!(
        properties["optional_glyph"]["type"],
        json!(["string", "null"])
    );
    {
        // The array type gives these unsuffixed literals a usize context.
        // Losing that context produces a negative bound or overflows an i32 shift.
        let inferred = fastmcp_rust::schema::admit_final_schema(
            ShapedSchemaInferredArray::json_schema(),
        )
        .unwrap();
        let value = ShapedSchemaInferredArray([7]);
        let encoded = serde_json::to_value(&value).unwrap();
        inferred.validate(&encoded).unwrap();
        assert_eq!(
            serde_json::from_value::<ShapedSchemaInferredArray>(encoded).unwrap(),
            value
        );
        assert_eq!(inferred.schema()["minItems"], 1);
        assert_eq!(inferred.schema()["maxItems"], 1);
        assert!(inferred.validate(&json!([7, 8])).is_err());
    }
    let hygienic = fastmcp_rust::schema::admit_final_schema(
        ShapedSchemaHygienicArray::json_schema(),
    )
    .unwrap();
    let value = ShapedSchemaHygienicArray([[7, 8]]);
    let encoded = serde_json::to_value(&value).unwrap();
    hygienic.validate(&encoded).unwrap();
    assert_eq!(
        serde_json::from_value::<ShapedSchemaHygienicArray>(encoded).unwrap(),
        value
    );
    assert_eq!(hygienic.schema()["items"]["minItems"], 2);
    assert_eq!(hygienic.schema()["maxItems"], 1);
    assert!(hygienic.validate(&json!([[7]])).is_err());
}

#[test]
fn json_schema_tuple_and_array_shapes_reject_near_neighbors() {
    let schema =
        fastmcp_rust::schema::admit_final_schema(ShapedSchemaArguments::json_schema()).unwrap();
    for (valid, invalid) in shaped_schema_argument_pairs() {
        schema.validate(&valid).unwrap();
        serde_json::from_value::<ShapedSchemaArguments>(valid).unwrap();
        assert!(schema.validate(&invalid).is_err(), "{invalid}");
        assert!(serde_json::from_value::<ShapedSchemaArguments>(invalid).is_err());
    }
}

#[derive(JsonSchema)]
struct NativeIntegerSchemas {
    i8_value: i8,
    i16_value: i16,
    i32_value: i32,
    i64_value: i64,
    i128_value: i128,
    isize_value: isize,
    u8_value: u8,
    u16_value: u16,
    u32_value: u32,
    u64_value: u64,
    u128_value: u128,
    usize_value: usize,
}

struct NativeIntegerSchemaCase {
    name: &'static str,
    minimum: serde_json::Value,
    maximum: serde_json::Value,
    below: serde_json::Value,
    above: serde_json::Value,
    accepts: fn(serde_json::Value) -> bool,
}

fn native_integer_schema_cases() -> Vec<NativeIntegerSchemaCase> {
    macro_rules! case {
        ($name:literal, $ty:ty, $below:expr, $above:expr) => {
            NativeIntegerSchemaCase {
                name: $name,
                minimum: json!(<$ty>::MIN),
                maximum: json!(<$ty>::MAX),
                below: serde_json::from_str($below).unwrap(),
                above: serde_json::from_str($above).unwrap(),
                accepts: |value| serde_json::from_value::<$ty>(value).is_ok(),
            }
        };
    }
    vec![
        case!("i8_value", i8, "-129", "128"),
        case!("i16_value", i16, "-32769", "32768"),
        case!("i32_value", i32, "-2147483649", "2147483648"),
        case!(
            "i64_value",
            i64,
            "-9223372036854775809",
            "9223372036854775808"
        ),
        case!(
            "i128_value",
            i128,
            "-170141183460469231731687303715884105729",
            "170141183460469231731687303715884105728"
        ),
        case!(
            "isize_value",
            isize,
            &(isize::MIN as i128 - 1).to_string(),
            &(isize::MAX as i128 + 1).to_string()
        ),
        case!("u8_value", u8, "-1", "256"),
        case!("u16_value", u16, "-1", "65536"),
        case!("u32_value", u32, "-1", "4294967296"),
        case!("u64_value", u64, "-1", "18446744073709551616"),
        case!(
            "u128_value",
            u128,
            "-1",
            "340282366920938463463374607431768211456"
        ),
        case!(
            "usize_value",
            usize,
            "-1",
            &(usize::MAX as u128 + 1).to_string()
        ),
    ]
}

#[test]
fn json_schema_native_integer_bounds_are_exact() {
    let schema = NativeIntegerSchemas::json_schema();
    for case in native_integer_schema_cases() {
        let admitted =
            fastmcp_rust::schema::admit_final_schema(schema["properties"][case.name].clone())
                .unwrap();
        assert_eq!(admitted.schema()["minimum"], case.minimum);
        assert_eq!(admitted.schema()["maximum"], case.maximum);
        for value in [case.minimum, case.maximum] {
            admitted.validate(&value).unwrap();
            assert!((case.accepts)(value));
        }
    }
    assert_eq!(
        schema["properties"]["i128_value"]["minimum"].to_string(),
        "-170141183460469231731687303715884105728"
    );
    assert_eq!(
        schema["properties"]["u128_value"]["maximum"].to_string(),
        "340282366920938463463374607431768211455"
    );
}

#[test]
fn json_schema_native_integer_bounds_reject_neighboring_values() {
    let schema = NativeIntegerSchemas::json_schema();
    for case in native_integer_schema_cases() {
        let admitted =
            fastmcp_rust::schema::admit_final_schema(schema["properties"][case.name].clone())
                .unwrap();
        admitted.validate(&case.minimum).unwrap();
        admitted.validate(&case.maximum).unwrap();
        for value in [case.below, case.above] {
            assert!(
                admitted.validate(&value).is_err(),
                "{} accepts {value}",
                case.name
            );
            assert!(!(case.accepts)(value));
        }
    }
}

static SHAPED_SCHEMA_TOOL_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[tool]
fn describe_shaped_schema(value: ShapedSchemaArguments) -> McpResult<String> {
    SHAPED_SCHEMA_TOOL_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    serde_json::to_string(&value).map_err(McpError::from)
}

#[test]
fn json_schema_shaped_arguments_reach_registered_modern_tool() {
    let server = Server::new("shaped-schema", "1.0.0")
        .tool(DescribeShapedSchema)
        .build();
    let connection = ModernConnection::new();
    let request = |value| {
        JsonRpcRequest::new(
            "tools/call",
            Some(json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
                "name": "describe_shaped_schema",
                "arguments": {"value": value},
            })),
            64_i64,
        )
    };
    for (valid, invalid) in shaped_schema_argument_pairs() {
        let expected: ShapedSchemaArguments = serde_json::from_value(valid.clone()).unwrap();
        let before = SHAPED_SCHEMA_TOOL_CALLS.load(std::sync::atomic::Ordering::SeqCst);
        let response = server
            .dispatch_stateless(&facade_final_inbound(&connection), &request(valid))
            .unwrap();
        assert!(response.error.is_none(), "{:?}", response.error);
        let result = response.result.unwrap();
        assert_eq!(result["resultType"], "complete");
        assert_ne!(result["isError"], json!(true));
        let actual: ShapedSchemaArguments =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            SHAPED_SCHEMA_TOOL_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            before + 1
        );
        let response = server
            .dispatch_stateless(&facade_final_inbound(&connection), &request(invalid))
            .unwrap();
        assert!(
            response.error.is_some()
                || response
                    .result
                    .as_ref()
                    .is_some_and(|result| result["isError"] == json!(true))
        );
        assert_eq!(
            SHAPED_SCHEMA_TOOL_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            before + 1,
            "invalid shape or out-of-range integer must not reach the handler"
        );
    }
}

// --- Struct with only description, no fields ---

/// A marker struct.
#[derive(JsonSchema)]
struct EmptyMarker;

#[test]
fn json_schema_empty_marker_is_null() {
    let schema = EmptyMarker::json_schema();
    assert_eq!(schema["type"], "null");
}

// --- Struct with renamed and skipped fields mixed ---

#[derive(JsonSchema)]
struct MixedAttributes {
    normal: String,
    #[json_schema(rename = "renamedField")]
    to_rename: i32,
    #[json_schema(skip)]
    to_skip: bool,
    #[json_schema(rename = "anotherName")]
    also_renamed: String,
}

#[test]
fn json_schema_mixed_attributes() {
    let schema = MixedAttributes::json_schema();
    let props = schema["properties"].as_object().unwrap();
    // Should have 3 fields (normal, renamedField, anotherName)
    assert_eq!(props.len(), 3);
    assert!(props.contains_key("normal"));
    assert!(props.contains_key("renamedField"));
    assert!(props.contains_key("anotherName"));
    // Skipped field should not be present
    assert!(!props.contains_key("to_skip"));
    // Original names should not be present
    assert!(!props.contains_key("to_rename"));
    assert!(!props.contains_key("also_renamed"));
}

// ============================================================================
// Resource macro: Vec<ResourceContent> return type support (bd-24s9)
// ============================================================================

/// Resource returning Vec<ResourceContent> directly for multi-part content.
#[resource(uri = "data://multi-part", description = "Multi-part resource")]
fn multi_part_vec(_ctx: &McpContext) -> Vec<ResourceContent> {
    vec![
        ResourceContent {
            uri: "data://multi-part/a".to_string(),
            mime_type: Some("text/plain".to_string()),
            text: Some("Part A".to_string()),
            blob: None,
        },
        ResourceContent {
            uri: "data://multi-part/b".to_string(),
            mime_type: Some("application/json".to_string()),
            text: Some(r#"{"key":"value"}"#.to_string()),
            blob: None,
        },
    ]
}

#[test]
fn resource_vec_resource_content_return() {
    let handler = MultiPartVecResource;
    let def = handler.definition();
    assert_eq!(def.uri, "data://multi-part");
    assert_eq!(def.description.as_deref(), Some("Multi-part resource"));

    let ctx = McpContext::new(Cx::for_testing(), 1);
    let contents = handler.read(&ctx).unwrap();
    assert_eq!(contents.len(), 2);
    assert_eq!(contents[0].uri, "data://multi-part/a");
    assert_eq!(contents[0].text.as_deref(), Some("Part A"));
    assert_eq!(contents[1].uri, "data://multi-part/b");
    assert_eq!(contents[1].mime_type.as_deref(), Some("application/json"));
}

/// Resource returning McpResult<Vec<ResourceContent>> for error handling.
#[resource(
    uri = "data://fallible-multi",
    description = "Fallible multi-part resource"
)]
fn fallible_multi(_ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
    Ok(vec![ResourceContent {
        uri: "data://fallible-multi".to_string(),
        mime_type: Some("text/plain".to_string()),
        text: Some("OK".to_string()),
        blob: None,
    }])
}

#[test]
fn resource_mcp_result_vec_resource_content_return() {
    let handler = FallibleMultiResource;
    let def = handler.definition();
    assert_eq!(def.uri, "data://fallible-multi");

    let ctx = McpContext::new(Cx::for_testing(), 1);
    let contents = handler.read(&ctx).unwrap();
    assert_eq!(contents.len(), 1);
    assert_eq!(contents[0].text.as_deref(), Some("OK"));
}

/// Resource returning McpResult<Vec<ResourceContent>> that errors.
#[resource(uri = "data://error-rc", description = "Always-error resource")]
fn error_rc(_ctx: &McpContext) -> McpResult<Vec<ResourceContent>> {
    Err(fastmcp_rust::McpError::resource_not_found("not available"))
}

#[test]
fn resource_mcp_result_vec_resource_content_error() {
    let handler = ErrorRcResource;
    let def = handler.definition();
    assert_eq!(def.uri, "data://error-rc");

    let ctx = McpContext::new(Cx::for_testing(), 1);
    let result = handler.read(&ctx);
    assert!(result.is_err());
}

/// Resource returning binary content via Vec<ResourceContent>.
#[resource(uri = "binary://test", description = "Binary resource")]
fn binary_blob(_ctx: &McpContext) -> Vec<ResourceContent> {
    vec![ResourceContent {
        uri: "binary://test".to_string(),
        mime_type: Some("application/octet-stream".to_string()),
        text: None,
        blob: Some("AQID".to_string()), // base64 for [1, 2, 3]
    }]
}

#[test]
fn resource_vec_resource_content_binary() {
    let handler = BinaryBlobResource;
    let def = handler.definition();
    assert_eq!(def.uri, "binary://test");

    let ctx = McpContext::new(Cx::for_testing(), 1);
    let contents = handler.read(&ctx).unwrap();
    assert_eq!(contents.len(), 1);
    assert!(contents[0].text.is_none());
    assert_eq!(contents[0].blob.as_deref(), Some("AQID"));
}
