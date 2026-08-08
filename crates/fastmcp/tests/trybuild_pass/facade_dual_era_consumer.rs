//! Active downstream facade probe for both HTTP protocol eras.

use fastmcp_rust::{legacy_2024, modern};

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

fn main() {
    let _ = assert_legacy_sse_method_signatures;
    assert_dual_era_completion_exports();
}
