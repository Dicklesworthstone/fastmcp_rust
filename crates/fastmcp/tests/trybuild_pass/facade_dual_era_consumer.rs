//! Active downstream facade probe for both HTTP protocol eras.

use std::collections::BTreeMap;

use fastmcp_rust::{
    ClientHttpConnection, ClientHttpConnectionError, ClientHttpResponse, CompletionContext,
    CompletionHandler, CompletionParams, CompletionReference, SubscriptionFilter, legacy_2024,
    modern,
};

struct DownstreamCompletionHandler;

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
    assert_dual_era_completion_exports();
    assert_root_directional_notification_exports();
    assert_modern_directional_notification_exports();
    prelude_directional_notification_reachability::assert_reachable();
}
