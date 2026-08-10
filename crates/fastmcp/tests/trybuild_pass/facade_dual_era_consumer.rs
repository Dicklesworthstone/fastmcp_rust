//! Active downstream facade probe for both HTTP protocol eras.

use std::collections::BTreeMap;

use fastmcp_rust::{
    CompletionContext, CompletionHandler, CompletionParams, CompletionReference,
    SubscriptionFilter, auto, legacy_2024, modern, tool,
};

#[tool(tasks)]
fn downstream_final_task_tool() -> fastmcp_rust::FinalToolOutcome {
    unreachable!("the downstream macro probe only compiles the task opt-in")
}

fn assert_task_opt_in_macro_surface() {
    assert!(fastmcp_rust::ToolHandler::declares_final_tasks(
        &DownstreamFinalTaskTool
    ));
}

struct DownstreamCompletionHandler;

struct DownstreamLegacyAdapterHandler;

impl legacy_2024::Legacy2024Handler for DownstreamLegacyAdapterHandler {
    fn handle_legacy_2024(
        &mut self,
        _method: &'static str,
        _params: Option<&legacy_2024::JsonValue>,
    ) -> Result<legacy_2024::JsonValue, legacy_2024::Legacy2024HandlerError> {
        Ok(legacy_2024::JsonValue::Object(Default::default()))
    }
}

impl CompletionHandler for DownstreamCompletionHandler {
    fn complete_legacy(
        &self,
        _ctx: &fastmcp_rust::McpContext,
        _params: legacy_2024::LegacyCompletionParams,
    ) -> fastmcp_rust::McpResult<legacy_2024::CompletionValues> {
        Ok(legacy_2024::CompletionValues {
            values: Vec::new(),
            total: None,
            has_more: None,
        })
    }

    fn complete_final(
        &self,
        _ctx: &fastmcp_rust::McpContext,
        _params: modern::FinalCompletionParams,
    ) -> fastmcp_rust::McpResult<modern::FinalCompletionValues> {
        Ok(modern::FinalCompletionValues {
            values: Vec::new(),
            total: None,
            has_more: None,
        })
    }
}

fn assert_completion_handler_reachability() {
    fn accepts_modern_completion_handler<T: modern::CompletionHandler>() {}

    accepts_modern_completion_handler::<DownstreamCompletionHandler>();
}

fn assert_modern_server_builder_forwarders() {
    let _: fn(
        modern::ServerBuilder,
        modern::ExtensionHandlerRegistry,
        modern::ServerExtensionDiscovery,
        modern::OfficialTasksNegotiationResolver,
    ) -> Result<modern::ServerBuilder, modern::ServerExtensionConfigurationError> =
        modern::ServerBuilder::extension_registry::<modern::OfficialTasksNegotiationResolver>;
    let _: fn(
        modern::ServerBuilder,
        modern::FinalTaskRuntime,
    ) -> Result<modern::ServerBuilder, modern::ServerExtensionConfigurationError> =
        modern::ServerBuilder::final_tasks;
    let _: fn(modern::ServerBuilder, DownstreamCompletionHandler) -> modern::ServerBuilder =
        modern::ServerBuilder::completion_handler::<DownstreamCompletionHandler>;
}

fn assert_modern_server_final_task_forwarders(
    server: &modern::Server,
    notification: modern::FinalTaskStatusNotification,
) -> modern::McpResult<usize> {
    let _: Option<&modern::FinalTaskRuntime> = server.final_task_runtime();
    server.publish_task_status_notification(notification)
}

fn assert_mcp_apps_wire_bridge_exports<T, P>(_host: Option<fastmcp_rust::McpAppsWireHost<T, P>>)
where
    T: fastmcp_rust::McpAppsWireBridgeTransport,
    P: fastmcp_rust::McpAppsWireHostPolicy,
{
    let _: Option<fastmcp_rust::McpAppsClientWirePolicy<'static>> = None;
    let _: Option<fastmcp_rust::McpAppsHttpClientWirePolicy<'static>> = None;
    let _: Option<fastmcp_rust::McpAppsInMemoryWireHostTransport> = None;
    let _: Option<fastmcp_rust::McpAppsInMemoryWireViewTransport> = None;
    let _: Option<fastmcp_rust::McpAppsWireHostConfiguration> = None;
    let _: fn(
        usize,
    ) -> (
        fastmcp_rust::McpAppsInMemoryWireHostTransport,
        fastmcp_rust::McpAppsInMemoryWireViewTransport,
    ) = fastmcp_rust::mcp_apps_in_memory_wire_pair;
}

fn assert_mcp_apps_wire_host_forwarders<T>()
where
    T: modern::McpAppsWireBridgeTransport + auto::McpAppsWireBridgeTransport,
{
    let configuration = modern::McpAppsWireHostConfiguration {
        host_info: modern::McpAppsBridgeImplementation {
            name: "downstream-host".to_owned(),
            version: "1.0.0".to_owned(),
        },
        host_capabilities: modern::McpAppsPinnedHostCapabilities::default(),
        host_context: modern::McpAppsPinnedHostContext::default(),
    };
    let _: modern::McpAppsWireHostConfiguration = configuration;
    let _: Option<auto::McpAppsClientSettings> = None;
    let _: for<'client> fn(
        &'client mut modern::Client,
        T,
        modern::McpAppsWireHostConfiguration,
    ) -> Result<
        modern::McpAppsWireHost<T, modern::McpAppsClientWirePolicy<'client>>,
        modern::McpAppsHostError,
    > = modern::Client::mcp_apps_wire_host::<T>;
    let _: for<'client> fn(
        &'client mut modern::HttpClient,
        T,
        modern::McpAppsWireHostConfiguration,
    ) -> Result<
        modern::McpAppsWireHost<T, modern::McpAppsHttpClientWirePolicy<'client>>,
        modern::McpAppsHostError,
    > = modern::HttpClient::mcp_apps_wire_host::<T>;
    let _: for<'client> fn(
        &'client mut auto::Client,
        T,
        auto::McpAppsWireHostConfiguration,
    ) -> Result<
        auto::McpAppsWireHost<T, auto::McpAppsClientWirePolicy<'client>>,
        auto::McpAppsHostError,
    > = auto::Client::mcp_apps_wire_host::<T>;
}

fn assert_final_resource_read_cache_hint_provenance() {
    let _: fastmcp_rust::FinalResourceReadCacheHintProvenance =
        fastmcp_rust::FinalResourceReadCacheHintProvenance::RouterPolicy;
    let _: modern::FinalResourceReadCacheHintProvenance =
        modern::FinalResourceReadCacheHintProvenance::Explicit;
}

fn legacy_sampling_callback(
    _cancellation: legacy_2024::ReverseRequestCancellation,
    _params: legacy_2024::CreateMessageParams,
) -> fastmcp_rust::McpResult<legacy_2024::CreateMessageResult> {
    unreachable!("compile-only legacy callback signature")
}

fn assert_legacy_reverse_callback_cancellation_export() {
    let _: legacy_2024::LegacySamplingRequestHandler = Box::new(legacy_sampling_callback);
    let _: Option<fastmcp_rust::ReverseRequestCancellation> = None;
    let _: legacy_2024::ProgressMarker =
        legacy_2024::ProgressMarker::Number(legacy_2024::JsonInteger::from(7_i64));
    let _: legacy_2024::ElicitContentValue =
        legacy_2024::ElicitContentValue::Int(legacy_2024::JsonInteger::from(9_i64));
    let _: for<'a, 'b> fn(
        &'a legacy_2024::ElicitResult,
        &'b str,
    ) -> Option<&'a legacy_2024::JsonInteger> = legacy_2024::ElicitResult::get_int;
}

fn assert_reverse_request_exports<T: fastmcp_rust::Transport>(
    executor: &fastmcp_rust::RequestExecutor<T>,
    cx: &fastmcp_rust::Cx,
    request: &fastmcp_rust::ReverseRequest,
) -> fastmcp_rust::McpResult<()> {
    let _: &fastmcp_rust::JsonRpcRequest = request.request();
    let _: &fastmcp_rust::RequestId = request.request_id();
    let _: &fastmcp_rust::ReverseRequestCancellation = request.cancellation();
    let _: Vec<fastmcp_rust::ReverseRequest> = executor.take_reverse_requests();
    executor.respond_to_reverse_request(cx, request, fastmcp_rust::JsonValue::Null)
}

fn assert_legacy_reverse_request_exports<T: fastmcp_rust::Transport>(
    executor: &legacy_2024::RequestExecutor<T>,
    cx: &legacy_2024::Cx,
    request: &legacy_2024::ReverseRequest,
) -> legacy_2024::McpResult<()> {
    let _: &legacy_2024::JsonRpcRequest = request.request();
    let _: &legacy_2024::RequestId = request.request_id();
    let _: &legacy_2024::ReverseRequestCancellation = request.cancellation();
    let _: Vec<legacy_2024::ReverseRequest> = executor.take_reverse_requests();
    executor.respond_to_reverse_request(cx, request, legacy_2024::JsonValue::Null)
}

fn assert_auto_reverse_request_exports<T: auto::Transport>(
    executor: &auto::RequestExecutor<T>,
    cx: &auto::Cx,
    request: &auto::ReverseRequest,
) -> auto::McpResult<()> {
    let _: Option<auto::Request> = None;
    let _: Option<auto::RequestExecution<T>> = None;
    let _: &auto::JsonRpcRequest = request.request();
    let _: &auto::RequestId = request.request_id();
    let _: &auto::ReverseRequestCancellation = request.cancellation();
    let _: Vec<auto::ReverseRequest> = executor.take_reverse_requests();
    executor.respond_to_reverse_request(cx, request, auto::JsonValue::Null)
}

fn assert_root_stdio_executor_exports(
    client: &mut fastmcp_rust::Client,
    cx: &fastmcp_rust::Cx,
) -> fastmcp_rust::McpResult<()> {
    let executor: fastmcp_rust::StdioRequestExecutor = client.multiplexed_stdio_executor()?;
    let mut execution: fastmcp_rust::StdioRequestExecution =
        client.start_multiplexed_request(cx, "ping", None)?;
    let _: fastmcp_rust::ProtocolEra = executor.selected_protocol_era();
    let _: &fastmcp_rust::RequestId = execution.request_id();
    let _: fastmcp_rust::JsonRpcResponse = client.wait_multiplexed_request(cx, &mut execution)?;
    Ok(())
}

fn assert_auto_stdio_executor_exports(
    client: &mut auto::Client,
    cx: &auto::Cx,
) -> auto::McpResult<()> {
    let executor: auto::StdioRequestExecutor = client.multiplexed_stdio_executor()?;
    let mut execution: auto::StdioRequestExecution =
        client.start_multiplexed_request(cx, "ping", None)?;
    let _: auto::ProtocolEra = executor.selected_protocol_era();
    let _: &auto::RequestId = execution.request_id();
    let _: auto::JsonRpcResponse = client.wait_multiplexed_request(cx, &mut execution)?;
    Ok(())
}

fn assert_legacy_stdio_executor_exports(
    client: &mut legacy_2024::Client,
    cx: &legacy_2024::Cx,
) -> legacy_2024::McpResult<()> {
    let executor: legacy_2024::StdioRequestExecutor = client.multiplexed_stdio_executor()?;
    let mut execution: legacy_2024::StdioRequestExecution =
        client.start_multiplexed_request(cx, "ping", None)?;
    let _: legacy_2024::ProtocolEra = executor.selected_protocol_era();
    let _: &legacy_2024::RequestId = execution.request_id();
    let _: legacy_2024::JsonRpcResponse = client.wait_multiplexed_request(cx, &mut execution)?;
    Ok(())
}

fn assert_modern_stdio_mrtr_wrapper_exports(client: &mut modern::Client) -> modern::McpResult<()> {
    let _: modern::FinalCoreResult = client.call_tool_with_mrtr_retry(
        "city_lookup",
        modern::JsonValue::Object(Default::default()),
        |_| Ok(BTreeMap::new()),
    )?;
    let _: modern::FinalCoreResult = client
        .read_resource_with_mrtr_retry("resource://cities/boston", |_| Ok(BTreeMap::new()))?;
    let _: modern::FinalCoreResult =
        client.get_prompt_with_mrtr_retry("city", Default::default(), |_| Ok(BTreeMap::new()))?;
    Ok(())
}

fn assert_final_tool_schema_authority_exports<T: modern::ToolHandler>(
    handler: &T,
) -> modern::FinalToolSchemaAuthority {
    let _: Option<fastmcp_rust::FinalToolSchemaAuthority> = None;
    let _: Option<modern::FinalToolSchemaAuthority> = None;
    handler.final_tool_schema_authority()
}

fn assert_raw_http_session_metadata_exports() {
    let request = fastmcp_rust::ModernHttpRequest::new(
        "https://example.test/mcp",
        Vec::new(),
        modern::PROTOCOL_VERSION,
        "ping",
        None,
    )
    .expect("root modern request constructor is available")
    .with_mcp_session_id("session-1")
    .expect("root modern request session builder is available");
    assert_eq!(request.target(), "https://example.test/mcp");
    let _: Option<fastmcp_rust::ModernHttpResponseKind> = None;
    let _: for<'a> fn(&'a fastmcp_rust::ModernHttpResponseMetadata) -> Option<&'a str> =
        fastmcp_rust::ModernHttpResponseMetadata::mcp_session_id;
    let _: for<'a> fn(
        &'a fastmcp_rust::ModernHttpResponseStream,
    ) -> &'a fastmcp_rust::ModernHttpResponseMetadata =
        fastmcp_rust::ModernHttpResponseStream::metadata;
}

fn assert_router_cache_ttl_signatures(router: &mut fastmcp_rust::Router) {
    router.set_final_cache_hint_policy(
        fastmcp_rust::CacheTtl::milliseconds(1),
        fastmcp_rust::CacheTtl::milliseconds(2),
        fastmcp_rust::CacheScope::Private,
    );
    let _: (
        &fastmcp_rust::CacheTtl,
        &fastmcp_rust::CacheTtl,
        fastmcp_rust::CacheScope,
    ) = router.final_cache_hint_policy();
}

mod prelude_completion_handler_reachability {
    use fastmcp_rust::prelude::*;

    fn accepts_prelude_completion_handler<T: CompletionHandler>() {}

    pub(super) fn assert_reachable() {
        accepts_prelude_completion_handler::<super::DownstreamCompletionHandler>();
    }
}

mod prelude_stdio_and_http_metadata_reachability {
    use fastmcp_rust::prelude::*;

    fn final_tool_schema_authority<T: ToolHandler>(handler: &T) -> FinalToolSchemaAuthority {
        handler.final_tool_schema_authority()
    }

    fn stdio_contract(client: &mut Client, cx: &Cx) -> McpResult<()> {
        let executor: StdioRequestExecutor = client.multiplexed_stdio_executor()?;
        let mut execution: StdioRequestExecution =
            client.start_multiplexed_request(cx, "ping", None)?;
        let _: ProtocolEra = executor.selected_protocol_era();
        let _: &RequestId = execution.request_id();
        let _: fastmcp_rust::JsonRpcResponse =
            client.wait_multiplexed_request(cx, &mut execution)?;
        Ok(())
    }

    fn generic_execution_contract<T: Transport>(
        executor: &RequestExecutor<T>,
        cx: &Cx,
        request: &ReverseRequest,
    ) -> McpResult<()> {
        let _: Option<Request> = None;
        let _: Option<RequestExecution<T>> = None;
        let _: &JsonRpcRequest = request.request();
        let _: &ReverseRequestCancellation = request.cancellation();
        let _: Vec<ReverseRequest> = executor.take_reverse_requests();
        executor.respond_to_reverse_request(cx, request, JsonValue::Null)
    }

    pub(super) fn assert_reachable() {
        let _: Option<FinalToolSchemaAuthority> = None;
        let _: Option<ModernHttpResponseKind> = None;
        let _: for<'a> fn(&'a ModernHttpResponseMetadata) -> Option<&'a str> =
            ModernHttpResponseMetadata::mcp_session_id;
        let _: for<'a> fn(&'a ModernHttpResponseStream) -> &'a ModernHttpResponseMetadata =
            ModernHttpResponseStream::metadata;
        let _ = final_tool_schema_authority::<super::DownstreamFinalTaskTool>;
        let _ = stdio_contract;
        let _ = generic_execution_contract::<fastmcp_rust::StreamableHttpTransport>;
    }
}

fn assert_client_completion_input_exports() {
    let root_params = CompletionParams {
        reference: CompletionReference::Prompt {
            name: "city".to_owned(),
        },
        argument: modern::FinalCompletionArgument {
            name: "prefix".to_owned(),
            value: "bo".to_owned(),
        },
        context: Some(CompletionContext::default()),
    };
    let _: modern::CompletionParams = root_params;
    let _: modern::CompletionReference = CompletionReference::Prompt {
        name: "city".to_owned(),
    };
    let _: modern::CompletionContext = CompletionContext::default();
}

mod prelude_client_completion_input_reachability {
    use fastmcp_rust::prelude::*;

    pub(super) fn assert_reachable() {
        let params = CompletionParams {
            reference: CompletionReference::Prompt {
                name: "city".to_owned(),
            },
            argument: modern::FinalCompletionArgument {
                name: "prefix".to_owned(),
                value: "bo".to_owned(),
            },
            context: Some(CompletionContext::default()),
        };
        let _ = params;
    }
}

async fn bind_modern_http(
    server: modern::Server,
    cx: &modern::Cx,
) -> modern::McpResult<modern::HttpServer> {
    server.bind_http(cx, "127.0.0.1:0").await
}

async fn serve_modern_http(server: modern::Server, cx: &modern::Cx) -> modern::McpResult<()> {
    server.serve_http(cx, "127.0.0.1:0").await
}

async fn connect_modern_http_from_configured_builder(
    builder: modern::ClientBuilder,
    endpoint: modern::CanonicalHttpUrl,
    cx: &modern::Cx,
) -> Result<modern::HttpClient, modern::HttpClientConnectError> {
    builder.connect_http_with_cx(endpoint, cx).await
}

async fn connect_exact_legacy_http_with_explicit_context(
    sse_endpoint: legacy_2024::CanonicalHttpUrl,
    message_post_endpoint: legacy_2024::CanonicalHttpUrl,
    cx: &legacy_2024::Cx,
) -> Result<legacy_2024::HttpClient, legacy_2024::HttpClientConnectError> {
    legacy_2024::connect_http_with_cx(sse_endpoint, message_post_endpoint, cx).await
}

fn assert_typed_facade_http_builder_exports() {
    let _: fn(
        modern::ClientBuilder,
        modern::CanonicalHttpUrl,
    ) -> Result<modern::HttpClient, modern::HttpClientConnectError> =
        modern::ClientBuilder::connect_http;
    let _: fn(
        legacy_2024::CanonicalHttpUrl,
        legacy_2024::CanonicalHttpUrl,
    ) -> Result<legacy_2024::ClientBuilder, legacy_2024::HttpEndpointBundleError> =
        legacy_2024::http_client_builder;
    let _: fn(
        legacy_2024::CanonicalHttpUrl,
        legacy_2024::CanonicalHttpUrl,
    ) -> Result<legacy_2024::HttpClient, legacy_2024::HttpClientConnectError> =
        legacy_2024::connect_http;
    let _ = connect_modern_http_from_configured_builder;
    let _ = connect_exact_legacy_http_with_explicit_context;
}

async fn use_final_only_http_resource_and_completion_apis(
    client: &mut modern::HttpClient,
    cx: &modern::Cx,
) -> Result<(), modern::HttpClientError> {
    let _: modern::FinalListResourcesResult = client.list_resources(cx, None).await?;
    let _: modern::FinalListResourceTemplatesResult = client
        .list_resource_templates(cx, Some("next-page"))
        .await?;
    let _: modern::FinalReadResourceResult =
        client.read_resource(cx, "resource://cities/boston").await?;
    let _: modern::FinalCompletionResult = client
        .complete(
            cx,
            modern::CompletionParams {
                reference: modern::CompletionReference::Prompt {
                    name: "city".to_owned(),
                },
                argument: modern::FinalCompletionArgument {
                    name: "prefix".to_owned(),
                    value: "bo".to_owned(),
                },
                context: Some(modern::CompletionContext::default()),
            },
        )
        .await?;
    Ok(())
}

async fn use_final_only_http_mrtr_apis(
    client: &mut modern::HttpClient,
    cx: &modern::Cx,
    deadline: std::time::Instant,
    sse_limits: modern::SseLimits,
) -> Result<(), modern::HttpClientError> {
    let mut tool_rounds = 0_usize;
    let _: modern::FinalCoreResult = client
        .call_tool_with_mrtr_retry_until(
            cx,
            deadline,
            "city_lookup",
            fastmcp_rust::JsonValue::Object(Default::default()),
            sse_limits,
            16 * 1024,
            |_| {
                tool_rounds += 1;
                Ok(BTreeMap::new())
            },
        )
        .await?;
    let mut resource_rounds = 0_usize;
    let _: modern::FinalCoreResult = client
        .read_resource_with_mrtr_retry_until(
            cx,
            deadline,
            "resource://cities/boston",
            sse_limits,
            16 * 1024,
            |_| {
                resource_rounds += 1;
                Ok(BTreeMap::new())
            },
        )
        .await?;
    let mut prompt_rounds = 0_usize;
    let _: modern::FinalCoreResult = client
        .get_prompt_with_mrtr_retry_until(
            cx,
            deadline,
            "city",
            std::collections::HashMap::new(),
            sse_limits,
            16 * 1024,
            |_| {
                prompt_rounds += 1;
                Ok(BTreeMap::new())
            },
        )
        .await?;
    Ok(())
}

fn assert_client_http_and_subscription_exports() {
    assert_typed_facade_http_builder_exports();
    let _ = modern::HttpClient::connect;
    let _ = modern::HttpClient::call_tool_outcome;
    let _ = modern::HttpClient::list_resources;
    let _ = modern::HttpClient::list_resource_templates;
    let _ = modern::HttpClient::read_resource;
    let _ = modern::HttpClient::complete;
    let _ = modern::HttpClient::call_tool_with_mrtr_retry_until;
    let _ = modern::HttpClient::read_resource_with_mrtr_retry_until;
    let _ = modern::HttpClient::get_prompt_with_mrtr_retry_until;
    let _ = modern::HttpClient::listen_subscriptions;
    let _ = modern::HttpClient::get_task;
    let _ = modern::HttpClient::update_task;
    let _ = modern::HttpClient::cancel_task;
    let _ = use_final_only_http_resource_and_completion_apis;
    let _ = use_final_only_http_mrtr_apis;
    let _ = bind_modern_http;
    let _ = serve_modern_http;
    let _ = modern::HttpServer::serve;
    let _: modern::SubscriptionFilter = SubscriptionFilter {
        tools_list_changed: Some(true),
        ..SubscriptionFilter::default()
    };
}

mod prelude_client_http_and_subscription_reachability {
    use fastmcp_rust::prelude::*;

    pub(super) fn assert_reachable() {
        let _: Option<ClientHttpConnection> = None;
        let _: Option<ClientHttpConnectionError> = None;
        let _: Option<ClientHttpResponse> = None;
        let filter = SubscriptionFilter {
            tools_list_changed: Some(true),
            ..SubscriptionFilter::default()
        };
        let _ = filter;
    }
}

fn assert_final_typed_client_and_dual_era_http_surface() {
    let _: fn(
        &mut fastmcp_rust::Client,
        &str,
        fastmcp_rust::JsonValue,
    ) -> fastmcp_rust::McpResult<fastmcp_rust::FinalCallToolResult> =
        fastmcp_rust::Client::call_tool_final;
    let _: fn(
        &mut fastmcp_rust::Client,
        &str,
    ) -> fastmcp_rust::McpResult<fastmcp_rust::FinalReadResourceResult> =
        fastmcp_rust::Client::read_resource_final;
    let _: fn(
        &mut fastmcp_rust::Client,
        &str,
        std::collections::HashMap<String, String>,
    ) -> fastmcp_rust::McpResult<fastmcp_rust::FinalGetPromptResult> =
        fastmcp_rust::Client::get_prompt_final;
    let _: fn(
        &mut fastmcp_rust::Client,
        modern::SubscriptionFilter,
    ) -> fastmcp_rust::McpResult<modern::SubscriptionListenCollector> =
        fastmcp_rust::Client::listen_subscriptions_typed;
    let _: fn(
        &mut auto::Client,
        &str,
        auto::JsonValue,
    ) -> auto::McpResult<auto::FinalCallToolResult> = auto::Client::call_tool_final;
    let _: fn(&mut modern::Client, &str) -> modern::McpResult<modern::FinalReadResourceResult> =
        modern::Client::read_resource;

    let auto_builder = auto::client_builder();
    assert_eq!(
        auto_builder.selected_protocol_plan().policy(),
        auto::ProtocolPolicy::Auto
    );
    let legacy_builder = legacy_2024::client_builder();
    assert_eq!(
        legacy_builder.selected_protocol_plan().policy(),
        legacy_2024::ProtocolPolicy::LegacyOnly
    );
    let _: fn(&str, &[&str]) -> fastmcp_rust::McpResult<legacy_2024::Client> =
        legacy_2024::Client::stdio;

    let _: Option<fastmcp_rust::ModernHttpSubscriptionListenCollector> = None;
    let _: Option<fastmcp_rust::ModernHttpSubscriptionListenError> = None;
    let _: Option<fastmcp_rust::ServerHttpEndpoint> = None;
    let _: Option<fastmcp_rust::ServerHttpSession> = None;
    let _: Option<fastmcp_rust::ServerHttpEndpointResponse> = None;
    let _: Option<fastmcp_rust::BoundHttpServer> = None;
    let _: Option<fastmcp_rust::DualEraHttpEndpoint> = None;
    let _: Option<fastmcp_rust::DualEraHttpEndpointConfig> = None;
    let _: Option<fastmcp_rust::DualEraHttpEndpointError> = None;
    let _: Option<auto::ClientHttpConnection> = None;
    let _: Option<auto::ModernHttpSubscriptionListenCollector> = None;
    let _: Option<auto::SseLimits> = None;
    let _: Option<modern::HttpClient> = None;
    let _: Option<modern::HttpServer> = None;
}

fn assert_client_roots_facade_exports() {
    let root = fastmcp_rust::ClientRoot::new("file:///workspace");
    let named_root = fastmcp_rust::ClientRoot::with_name("file:///tmp", "temporary");
    assert_eq!(root.name, None);
    assert_eq!(named_root.name.as_deref(), Some("temporary"));

    let _: Option<std::sync::Arc<dyn fastmcp_rust::RootsProvider>> = None;
    let _: Option<modern::ClientRoot> = None;
    let _: Option<std::sync::Arc<dyn modern::RootsProvider>> = None;
    let _: Option<legacy_2024::ClientRoot> = None;
    let _: Option<std::sync::Arc<dyn legacy_2024::RootsProvider>> = None;
}

fn assert_modern_companion_facade_exports() {
    let _: modern::FinalArguments<String> = modern::FinalArguments::Absent;
    let _: modern::FinalArguments<String> = modern::FinalArguments::ExplicitNull;
    let _: modern::FinalArguments<String> = modern::FinalArguments::Value("modern".to_owned());

    let _: fn(usize) -> modern::McpResult<modern::InMemoryFinalTaskStore> =
        modern::InMemoryFinalTaskStore::new;
    let _: usize = modern::DEFAULT_IN_MEMORY_FINAL_TASKS;

    let _: Option<modern::FinalCacheStats> = None;
    let _: Option<modern::FinalTaskAcceptedInput> = None;
    let _: Option<modern::FinalTaskInitialWork> = None;
    let _: Option<std::sync::Arc<dyn modern::FinalTaskRetentionAuthority>> = None;
    let _: Option<modern::FinalTaskSnapshot> = None;
    let _: Option<modern::FinalTaskSupervisorFuture<'static>> = None;
    let _: Option<modern::FinalTaskSupervisorHandoff> = None;
    let _: Option<modern::FinalTaskWorkDescriptor> = None;
    let _: Option<std::sync::Arc<dyn modern::ApplicationTaskSupervisor>> = None;
    let _: Option<modern::AuthorizedTaskServiceRunner> = None;
    let _: Option<modern::PendingRequests> = None;
    let _: Option<modern::RequestSender> = None;
    let _: Option<modern::TransportElicitationSender> = None;
    let _: Option<modern::TransportRootsProvider> = None;
    let _: Option<modern::TransportSamplingSender> = None;

    let _: Option<modern::ClientCapabilityInfo> = None;
    let _: Option<modern::ElicitationAction> = None;
    let _: Option<modern::ElicitationMode> = None;
    let _: Option<modern::ElicitationRequest> = None;
    let _: Option<modern::ElicitationResponse> = None;
    let _: Option<std::sync::Arc<dyn modern::ElicitationSender>> = None;
    let _: u32 = modern::MAX_RESOURCE_READ_DEPTH;
    let _: u32 = modern::MAX_TOOL_CALL_DEPTH;
    let _: Option<modern::McpContextLeaseGuard> = None;
    let _: Option<modern::NoOpElicitationSender> = None;
    let _: Option<modern::NoOpNotificationSender> = None;
    let _: Option<modern::NoOpSamplingSender> = None;
    let _: Option<std::sync::Arc<dyn modern::NotificationSender>> = None;
    let _: Option<modern::ProgressReporter> = None;
    let _: Option<modern::ResourceContentItem> = None;
    let _: Option<modern::ResourceReadResult> = None;
    let _: Option<std::sync::Arc<dyn modern::ResourceReader>> = None;
    let _: Option<modern::SamplingRequest> = None;
    let _: Option<modern::SamplingRequestMessage> = None;
    let _: Option<modern::SamplingResponse> = None;
    let _: Option<modern::SamplingRole> = None;
    let _: Option<std::sync::Arc<dyn modern::SamplingSender>> = None;
    let _: Option<modern::SamplingStopReason> = None;
    let _: Option<modern::ServerCapabilityInfo> = None;
    let _: Option<modern::ToolCallResult> = None;
    let _: Option<std::sync::Arc<dyn modern::ToolCaller>> = None;
    let _: Option<modern::ToolContentItem> = None;

    let _: Option<fastmcp_rust::FinalCacheStats> = None;
    let _: fastmcp_rust::FinalArguments<String> = fastmcp_rust::FinalArguments::Absent;
    let _: fastmcp_rust::FinalArguments<String> = fastmcp_rust::FinalArguments::ExplicitNull;
    let _: fastmcp_rust::FinalArguments<String> =
        fastmcp_rust::FinalArguments::Value("root".to_owned());
    let _: Option<fastmcp_rust::FinalTaskAcceptedInput> = None;
    let _: Option<fastmcp_rust::FinalTaskInitialWork> = None;
    let _: Option<fastmcp_rust::FinalTaskNotificationEmitter> = None;
    let _: Option<std::sync::Arc<dyn fastmcp_rust::FinalTaskRetentionAuthority>> = None;
    let _: Option<fastmcp_rust::FinalTaskRuntime> = None;
    let _: Option<fastmcp_rust::FinalTaskRuntimeConfig> = None;
    let _: Option<fastmcp_rust::FinalTaskSnapshot> = None;
    let _: Option<std::sync::Arc<dyn fastmcp_rust::FinalTaskStore>> = None;
    let _: Option<fastmcp_rust::FinalTaskSupervisorFuture<'static>> = None;
    let _: Option<fastmcp_rust::FinalTaskSupervisorHandoff> = None;
    let _: Option<fastmcp_rust::FinalTaskWorkDescriptor> = None;
    let _: Option<std::sync::Arc<dyn fastmcp_rust::ApplicationTaskSupervisor>> = None;
    let _: Option<fastmcp_rust::AuthorizedTaskServiceRunner> = None;
    let _: Option<fastmcp_rust::InMemoryFinalTaskStore> = None;
    let _: Option<fastmcp_rust::PendingRequests> = None;
    let _: Option<fastmcp_rust::RequestSender> = None;
    let _: Option<fastmcp_rust::TransportElicitationSender> = None;
    let _: Option<fastmcp_rust::TransportRootsProvider> = None;
    let _: Option<fastmcp_rust::TransportSamplingSender> = None;
    let _: Option<std::sync::Arc<dyn fastmcp_rust::ContextNotificationSender>> = None;
    let _: fn(
        &[u8],
        usize,
    ) -> Result<fastmcp_rust::JsonRpcMessage, fastmcp_rust::JsonRpcAdmissionError> =
        fastmcp_rust::decode_strict_jsonrpc_message;
}

mod prelude_companion_facade_reachability {
    use fastmcp_rust::prelude::*;

    pub(super) fn assert_reachable() {
        let _: FinalArguments<String> = FinalArguments::Absent;
        let _: FinalArguments<String> = FinalArguments::ExplicitNull;
        let _: FinalArguments<String> = FinalArguments::Value("prelude".to_owned());

        let _: fn(&[u8], usize) -> Result<JsonRpcMessage, JsonRpcAdmissionError> =
            decode_strict_jsonrpc_message;
        let _: fn(usize) -> McpResult<InMemoryFinalTaskStore> = InMemoryFinalTaskStore::new;
        let _: usize = DEFAULT_IN_MEMORY_FINAL_TASKS;

        let _: Option<FinalCacheStats> = None;
        let _: Option<FinalTaskAcceptedInput> = None;
        let _: Option<FinalTaskInitialWork> = None;
        let _: Option<FinalTaskNotificationEmitter> = None;
        let _: Option<std::sync::Arc<dyn FinalTaskRetentionAuthority>> = None;
        let _: Option<FinalTaskRuntime> = None;
        let _: Option<FinalTaskRuntimeConfig> = None;
        let _: Option<FinalTaskSnapshot> = None;
        let _: Option<std::sync::Arc<dyn FinalTaskStore>> = None;
        let _: Option<FinalTaskSupervisorFuture<'static>> = None;
        let _: Option<FinalTaskSupervisorHandoff> = None;
        let _: Option<FinalTaskWorkDescriptor> = None;
        let _: Option<std::sync::Arc<dyn ApplicationTaskSupervisor>> = None;
        let _: Option<AuthorizedTaskServiceRunner> = None;
        let _: Option<PendingRequests> = None;
        let _: Option<RequestSender> = None;
        let _: Option<TransportElicitationSender> = None;
        let _: Option<TransportRootsProvider> = None;
        let _: Option<TransportSamplingSender> = None;
        let _: Option<ClientCapabilityInfo> = None;
        let _: Option<ElicitationAction> = None;
        let _: Option<ElicitationMode> = None;
        let _: Option<ElicitationRequest> = None;
        let _: Option<ElicitationResponse> = None;
        let _: Option<std::sync::Arc<dyn ElicitationSender>> = None;
        let _: u32 = MAX_RESOURCE_READ_DEPTH;
        let _: u32 = MAX_TOOL_CALL_DEPTH;
        let _: Option<McpContextLeaseGuard> = None;
        let _: Option<McpRequestCancellation> = None;
        let _: Option<NoOpElicitationSender> = None;
        let _: Option<NoOpNotificationSender> = None;
        let _: Option<NoOpSamplingSender> = None;
        let _: Option<std::sync::Arc<dyn ContextNotificationSender>> = None;
        let _: Option<ProgressReporter> = None;
        let _: Option<ResourceContentItem> = None;
        let _: Option<ResourceReadResult> = None;
        let _: Option<std::sync::Arc<dyn ResourceReader>> = None;
        let _: Option<SamplingRequest> = None;
        let _: Option<SamplingRequestMessage> = None;
        let _: Option<SamplingResponse> = None;
        let _: Option<SamplingRole> = None;
        let _: Option<std::sync::Arc<dyn SamplingSender>> = None;
        let _: Option<SamplingStopReason> = None;
        let _: Option<ServerCapabilityInfo> = None;
        let _: Option<ToolCallResult> = None;
        let _: Option<std::sync::Arc<dyn ToolCaller>> = None;
        let _: Option<ToolContentItem> = None;
        let _: Option<ClientRoot> = None;
        let _: Option<std::sync::Arc<dyn RootsProvider>> = None;
    }
}

mod prelude_final_typed_and_http_reachability {
    use std::collections::HashMap;

    use fastmcp_rust::prelude::*;

    pub(super) fn assert_reachable() {
        let _: fn(&mut Client, &str, JsonValue) -> McpResult<FinalCallToolResult> =
            Client::call_tool_final;
        let _: fn(&mut Client, &str) -> McpResult<FinalReadResourceResult> =
            Client::read_resource_final;
        let _: fn(&mut Client, &str, HashMap<String, String>) -> McpResult<FinalGetPromptResult> =
            Client::get_prompt_final;
        let _: Option<FinalCallToolResult> = None;
        let _: Option<FinalReadResourceResult> = None;
        let _: Option<FinalGetPromptResult> = None;
        let _: Option<SubscriptionListenCollector> = None;
        let _: Option<ModernHttpSubscriptionListenCollector> = None;
        let _: Option<ModernHttpSubscriptionListenError> = None;
        let _: Option<ModernHttpClient> = None;
        let _: Option<ServerHttpEndpoint> = None;
        let _: Option<ServerHttpSession> = None;
        let _: Option<ServerHttpEndpointResponse> = None;
        let _: Option<BoundHttpServer> = None;
        let _: Option<DualEraHttpEndpoint> = None;
        let _: Option<DualEraHttpEndpointConfig> = None;
        let _: Option<DualEraHttpEndpointError> = None;
        let _: Option<SseLimits> = None;
        assert_eq!(
            auto::client_builder().selected_protocol_plan().policy(),
            auto::ProtocolPolicy::Auto
        );
    }
}

fn assert_legacy_sse_method_signatures(
    cx: &legacy_2024::Cx,
    plan: legacy_2024::ClientProtocolPlan,
    client: &mut legacy_2024::LegacySseHttpClient,
) {
    let message = legacy_2024::JsonRpcMessage::Request(legacy_2024::JsonRpcRequest::new(
        "initialize",
        None,
        legacy_2024::RequestId::Number(1),
    ));
    let _connect = legacy_2024::LegacySseHttpClient::connect(cx, plan);
    let _send = client.send(cx, &message);
    let _next_message = client.next_message(cx);
}

fn assert_dual_era_completion_exports() {
    let modern_params = modern::FinalCompletionParams {
        meta: modern::OpenMetadata::default(),
        reference: modern::FinalCompletionReference::Prompt {
            name: "city".to_owned(),
        },
        argument: modern::FinalCompletionArgument {
            name: "prefix".to_owned(),
            value: "bo".to_owned(),
        },
        context: Some(modern::FinalCompletionContext::default()),
    };
    let modern_result = modern::FinalCompletionResult {
        completion: modern::FinalCompletionValues {
            values: vec!["boston".to_owned()],
            total: Some(modern::JsonInteger::from(1_i64)),
            has_more: Some(false),
        },
    };

    let legacy_params = legacy_2024::LegacyCompletionParams {
        reference: legacy_2024::LegacyCompletionReference::Resource {
            uri: "resource://cities".to_owned(),
        },
        argument: legacy_2024::LegacyCompletionArgument {
            name: "prefix".to_owned(),
            value: "bo".to_owned(),
        },
    };
    let legacy_result = legacy_2024::LegacyCompletionResult {
        completion: legacy_2024::CompletionValues {
            values: vec!["boston".to_owned()],
            total: Some(1),
            has_more: Some(false),
        },
    };

    let _ = (modern_params, modern_result, legacy_params, legacy_result);
}

fn assert_root_directional_notification_exports() {
    let client = fastmcp_rust::ClientNotification::Cancelled(
        fastmcp_rust::FinalCancelledNotificationParams {
            request_id: fastmcp_rust::RequestId::Number(41),
            reason: None,
            meta: None,
            additional: BTreeMap::new(),
        },
    );
    let client_wire = client
        .encode()
        .expect("root client notification encodes through the facade");
    assert!(client_wire.is_notification());
    assert_eq!(client_wire.method, "notifications/cancelled");

    let server =
        fastmcp_rust::ServerNotification::Progress(fastmcp_rust::FinalProgressNotificationParams {
            progress_token: fastmcp_rust::ProgressMarker::Number(fastmcp_rust::JsonInteger::from(
                41_i64,
            )),
            progress: 1.0,
            total: Some(1.0),
            message: Some("complete".to_owned()),
            meta: None,
            additional: BTreeMap::new(),
        });
    let server_wire = server
        .encode()
        .expect("root server notification encodes through the facade");
    assert!(server_wire.is_notification());
    assert_eq!(server_wire.method, "notifications/progress");
}

fn assert_modern_directional_notification_exports() {
    let client = modern::ClientNotification::Cancelled(modern::FinalCancelledNotificationParams {
        request_id: modern::RequestId::Number(42),
        reason: None,
        meta: None,
        additional: BTreeMap::new(),
    });
    let client_wire = client
        .encode()
        .expect("modern client notification encodes through the facade");
    assert!(client_wire.is_notification());
    assert_eq!(client_wire.method, "notifications/cancelled");

    let server = modern::ServerNotification::Progress(modern::FinalProgressNotificationParams {
        progress_token: modern::ProgressMarker::Number(modern::JsonInteger::from(42_i64)),
        progress: 1.0,
        total: Some(1.0),
        message: Some("complete".to_owned()),
        meta: None,
        additional: BTreeMap::new(),
    });
    let server_wire = server
        .encode()
        .expect("modern server notification encodes through the facade");
    assert!(server_wire.is_notification());
    assert_eq!(server_wire.method, "notifications/progress");
}

fn assert_lossless_dual_era_product_paths() {
    assert_eq!(
        modern::client_builder().protocol_policy(),
        modern::ModernOnly
    );
    assert_eq!(modern::PROTOCOL_VERSION, "2026-07-28");

    let discovery = modern::ServerDiscoverRequest::default();
    assert!(
        discovery
            .metadata()
            .entries()
            .contains_key(modern::FINAL_PROTOCOL_VERSION_META_KEY)
    );
    let cache_hints = modern::DiscoveryCacheHints::private_ttl_ms(250);
    assert_eq!(
        cache_hints
            .ttl_ms()
            .try_as_millis()
            .expect("locally constructed TTL fits the runtime domain"),
        250
    );
    let oversized_ttl: modern::CacheTtl = modern::CacheTtl::try_from(
        fastmcp_rust::serde_json::from_str::<modern::JsonInteger>("18446744073709551616")
            .expect("wide integer parses through the facade"),
    )
    .expect("nonnegative wide TTL is retained");
    assert_eq!(
        oversized_ttl.try_as_millis(),
        Err(modern::CacheTtlConversionError::RuntimeOutOfRange)
    );

    let exact_result = modern::parse_exact_json(r#"{"resultType":"complete","answer":7}"#)
        .expect("facade result codec must parse exact JSON");
    let result_value = modern::exact_json_to_serde(&exact_result)
        .expect("facade result codec must convert exact JSON");
    assert_eq!(result_value["answer"], 7);

    let tasks_extension = modern::official_tasks_extension_id();
    assert_eq!(
        tasks_extension.as_str(),
        modern::OFFICIAL_TASKS_EXTENSION_ID
    );
    let mut extensions = modern::ExtensionDescriptorRegistry::new();
    extensions
        .register(modern::official_tasks_descriptor())
        .expect("facade extension registry must accept the official descriptor");

    let notifications = modern::SubscriptionFilter {
        resources_list_changed: Some(true),
        ..modern::SubscriptionFilter::default()
    };
    let listen = modern::FinalSubscriptionsListenParams {
        meta: modern::OpenMetadata::default(),
        notifications: notifications.clone(),
    };
    assert_eq!(listen.notifications.resources_list_changed, Some(true));

    let final_tool = modern::FinalTool {
        name: "downstream-tool".to_owned(),
        title: Some("Downstream Tool".to_owned()),
        description: None,
        icons: None,
        input_schema: Default::default(),
        output_schema: None,
        annotations: None,
        meta: None,
    };
    let create_message = modern::FinalCreateMessageParams {
        meta: modern::OpenMetadata::default(),
        messages: Vec::new(),
        max_tokens: modern::JsonInteger::from(128_i64),
        system_prompt: None,
        temperature: None,
        stop_sequences: None,
        model_preferences: Some(modern::ModelPreferences::default()),
        include_context: None,
        metadata: None,
        tools: Some(vec![final_tool]),
        tool_choice: Some(modern::FinalToolChoice::default()),
    };
    assert_eq!(create_message.max_tokens.as_str(), "128");
    let input_required = modern::FinalCreateMessageInputRequiredResult {
        result_type: modern::FinalInputRequiredResultType::InputRequired,
        meta: None,
        input_requests: None,
        request_state: Some("downstream-state".to_owned()),
    };
    input_required
        .validate()
        .expect("facade final input-required result must validate");

    let final_template = modern::FinalResourceTemplate {
        uri_template: "resource://cities/{name}".to_owned(),
        name: "city".to_owned(),
        title: Some("City".to_owned()),
        description: Some("A city resource".to_owned()),
        icons: None,
        mime_type: Some("application/json".to_owned()),
        annotations: None,
        meta: None,
    };
    let _: modern::Server = modern::server_builder("final-only", "1.0.0")
        .resource_template(final_template)
        .build();
    let final_resource = modern::FinalResource {
        uri: modern::AbsoluteUri::parse("resource://cities/london")
            .expect("absolute resource URI parses through the facade"),
        name: "london".to_owned(),
        title: Some("London".to_owned()),
        description: None,
        icons: None,
        mime_type: Some("application/json".to_owned()),
        size: Some(
            fastmcp_rust::serde_json::from_str::<modern::JsonInteger>("18446744073709551616")
                .expect("wide resource size parses through the facade"),
        ),
        annotations: None,
        meta: None,
    };
    assert_eq!(
        final_resource
            .size
            .as_ref()
            .expect("size is retained")
            .as_str(),
        "18446744073709551616"
    );

    let partition = legacy_2024::LegacyAuthenticatedPeerPartition::from_authenticated_transport(
        [9_u8; legacy_2024::LegacyAuthenticatedPeerPartition::BYTE_LEN],
    );
    let binding = legacy_2024::LegacyPeerBinding::from_authenticated_transport(partition, 17);
    let legacy_config = legacy_2024::Legacy2024ServerConfig {
        capabilities: legacy_2024::methods::Legacy2024ServerCapabilities::default(),
        server_info: legacy_2024::Legacy2024ServerInfo {
            name: "downstream-legacy".to_owned(),
            version: "1.0.0".to_owned(),
        },
        instructions: None,
    };
    let legacy_adapter = legacy_2024::Legacy2024ServerAdapter::install(
        binding,
        legacy_config,
        DownstreamLegacyAdapterHandler,
    )
    .expect("facade legacy adapter must install for an authenticated binding");
    assert_eq!(
        legacy_adapter.lifecycle(),
        legacy_2024::Legacy2024Lifecycle::AwaitInitialize
    );
    assert!(legacy_adapter.installed_receipt().matches_binding(binding));
}

mod prelude_directional_notification_reachability {
    use std::collections::BTreeMap;

    use fastmcp_rust::prelude::*;

    pub(super) fn assert_reachable() {
        let _: Option<CacheTtl> = None;
        let _: Option<CacheTtlConversionError> = None;
        let _: Option<FinalResource> = None;
        let _: JsonInteger = JsonInteger::from(44_i64);
        let cache_hints = DiscoveryCacheHints::private_ttl_ms(1);
        assert_eq!(
            cache_hints
                .ttl_ms()
                .try_as_millis()
                .expect("prelude cache TTL uses checked runtime conversion"),
            1
        );

        let client = ClientNotification::Cancelled(FinalCancelledNotificationParams {
            request_id: fastmcp_rust::RequestId::Number(43),
            reason: None,
            meta: None,
            additional: BTreeMap::new(),
        });
        let client_wire = client
            .encode()
            .expect("prelude client notification encodes through the facade");
        assert!(client_wire.is_notification());
        assert_eq!(client_wire.method, "notifications/cancelled");

        let server = ServerNotification::Progress(FinalProgressNotificationParams {
            progress_token: ProgressMarker::Number(JsonInteger::from(43_i64)),
            progress: 1.0,
            total: Some(1.0),
            message: Some("complete".to_owned()),
            meta: None,
            additional: BTreeMap::new(),
        });
        let server_wire = server
            .encode()
            .expect("prelude server notification encodes through the facade");
        assert!(server_wire.is_notification());
        assert_eq!(server_wire.method, "notifications/progress");
    }
}

fn main() {
    assert_task_opt_in_macro_surface();
    let _ = assert_legacy_sse_method_signatures;
    assert_completion_handler_reachability();
    assert_modern_server_builder_forwarders();
    let _ = assert_modern_server_final_task_forwarders;
    let _ = assert_mcp_apps_wire_bridge_exports::<
        fastmcp_rust::McpAppsInMemoryWireHostTransport,
        fastmcp_rust::McpAppsHttpClientWirePolicy<'static>,
    >;
    let _ = assert_mcp_apps_wire_host_forwarders::<fastmcp_rust::McpAppsInMemoryWireHostTransport>;
    assert_final_resource_read_cache_hint_provenance();
    assert_legacy_reverse_callback_cancellation_export();
    let _ = assert_reverse_request_exports::<fastmcp_rust::StreamableHttpTransport>;
    let _ = assert_legacy_reverse_request_exports::<fastmcp_rust::StreamableHttpTransport>;
    let _ = assert_auto_reverse_request_exports::<fastmcp_rust::StreamableHttpTransport>;
    let _ = assert_root_stdio_executor_exports;
    let _ = assert_auto_stdio_executor_exports;
    let _ = assert_legacy_stdio_executor_exports;
    let _ = assert_modern_stdio_mrtr_wrapper_exports;
    let _ = assert_final_tool_schema_authority_exports::<DownstreamFinalTaskTool>;
    assert_raw_http_session_metadata_exports();
    let _ = assert_router_cache_ttl_signatures;
    prelude_completion_handler_reachability::assert_reachable();
    prelude_stdio_and_http_metadata_reachability::assert_reachable();
    assert_client_completion_input_exports();
    prelude_client_completion_input_reachability::assert_reachable();
    let _ = assert_client_http_and_subscription_exports;
    prelude_client_http_and_subscription_reachability::assert_reachable();
    assert_final_typed_client_and_dual_era_http_surface();
    assert_modern_companion_facade_exports();
    prelude_companion_facade_reachability::assert_reachable();
    prelude_final_typed_and_http_reachability::assert_reachable();
    assert_dual_era_completion_exports();
    assert_root_directional_notification_exports();
    assert_modern_directional_notification_exports();
    assert_lossless_dual_era_product_paths();
    prelude_directional_notification_reachability::assert_reachable();
}
