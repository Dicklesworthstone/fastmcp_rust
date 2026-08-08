//! Active downstream facade probe for both HTTP protocol eras.

use std::collections::BTreeMap;

use fastmcp_rust::{
    ClientHttpConnection, ClientHttpConnectionError, ClientHttpResponse, CompletionContext,
    CompletionHandler, CompletionParams, CompletionReference, SubscriptionFilter, auto,
    legacy_2024, modern,
};

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
    ) -> fastmcp_rust::McpResult<modern::CompletionValues> {
        Ok(modern::CompletionValues {
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

mod prelude_completion_handler_reachability {
    use fastmcp_rust::prelude::*;

    fn accepts_prelude_completion_handler<T: CompletionHandler>() {}

    pub(super) fn assert_reachable() {
        accepts_prelude_completion_handler::<super::DownstreamCompletionHandler>();
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

fn assert_client_http_and_subscription_exports(
    connection: ClientHttpConnection,
    response: ClientHttpResponse,
    error: ClientHttpConnectionError,
) {
    fn accepts_modern_connection(_connection: modern::ClientHttpConnection) {}
    fn accepts_modern_error(_error: modern::ClientHttpConnectionError) {}

    accepts_modern_connection(connection);
    accepts_modern_error(error);
    match response {
        modern::ClientHttpResponse::Modern(_) | modern::ClientHttpResponse::Legacy(_) => {}
    }

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
    let _: fn(
        &mut modern::Client,
        &str,
        modern::JsonValue,
    ) -> modern::McpResult<modern::FinalReadResourceResult> = modern::Client::read_resource_final;

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
    let _: Option<modern::ModernHttpClient> = None;
    let _: Option<modern::ServerHttpEndpoint> = None;
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
        completion: modern::CompletionValues {
            values: vec!["boston".to_owned()],
            total: Some(1),
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
            progress_token: fastmcp_rust::ProgressMarker::Number(41),
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
        progress_token: modern::ProgressMarker::Number(42),
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
    let policy = modern::ProtocolPolicy::ModernOnly;
    let plan = modern::ClientProtocolPlan::stdio(policy);
    assert_eq!(plan.policy(), policy);
    assert_eq!(modern::PROTOCOL_VERSION, "2026-07-28");
    assert_eq!(
        modern::ProtocolVersion::parse(modern::PROTOCOL_VERSION)
            .expect("modern version must parse")
            .era(),
        modern::ProtocolEra::Modern2026
    );

    let discovery = modern::ServerDiscoverRequest::default();
    assert!(
        discovery
            .metadata()
            .entries()
            .contains_key(modern::FINAL_PROTOCOL_VERSION_META_KEY)
    );
    let cache_hints = modern::DiscoveryCacheHints::private_ttl_ms(250);
    assert_eq!(cache_hints.ttl_ms(), 250);

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
        max_tokens: 128,
        system_prompt: None,
        temperature: None,
        stop_sequences: None,
        model_preferences: Some(modern::ModelPreferences::default()),
        include_context: None,
        metadata: None,
        tools: Some(vec![final_tool]),
        tool_choice: Some(modern::FinalToolChoice::default()),
    };
    assert_eq!(create_message.max_tokens, 128);
    let input_required = modern::FinalCreateMessageInputRequiredResult {
        result_type: modern::FinalInputRequiredResultType::InputRequired,
        meta: None,
        input_requests: None,
        request_state: Some("downstream-state".to_owned()),
    };
    input_required
        .validate()
        .expect("facade final input-required result must validate");

    let (client_transport, _server_transport) =
        fastmcp_rust::memory::create_memory_transport_pair();
    let executor = modern::RequestExecutor::with_result_peer_era(
        client_transport,
        modern::ResultPeerEra::Modern,
    );
    let _ = executor;

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
            progress_token: ProgressMarker::Number(43),
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
    let _ = assert_legacy_sse_method_signatures;
    assert_completion_handler_reachability();
    prelude_completion_handler_reachability::assert_reachable();
    assert_client_completion_input_exports();
    prelude_client_completion_input_reachability::assert_reachable();
    let _ = assert_client_http_and_subscription_exports;
    prelude_client_http_and_subscription_reachability::assert_reachable();
    assert_final_typed_client_and_dual_era_http_surface();
    prelude_final_typed_and_http_reachability::assert_reachable();
    assert_dual_era_completion_exports();
    assert_root_directional_notification_exports();
    assert_modern_directional_notification_exports();
    assert_lossless_dual_era_product_paths();
    prelude_directional_notification_reachability::assert_reachable();
}
