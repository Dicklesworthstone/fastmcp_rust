//! Public modern facade requests on a real caller-owned stdio connection.

use super::*;
use fastmcp_rust::{McpErrorCode, McpRequestCancellation};
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::task::Poll;

const OTHER_EXTENSION: &str = "com.example/other";
const OTHER_RESULT: &str = "com.example/other-result";

fn configuration() -> (
    ExtensionId,
    ExtensionDescriptorRegistry,
    ClientExtensionDiscovery,
) {
    let (id, mut registry, mut discovery) = client_configuration_with_notifications(true);
    let mut other = registry.descriptor(&id).unwrap().clone();
    other.id = ExtensionId::parse(OTHER_EXTENSION).unwrap();
    other.method.as_mut().unwrap().name = "com.example/other".to_owned();
    other.notification = None;
    other.result_discriminator = Some(OTHER_RESULT.to_owned());
    discovery.extensions.insert(
        other.id.clone(),
        ExtensionSettings::new(json!({"version": 1})).unwrap(),
    );
    registry.register(other).unwrap();
    (id, registry, discovery)
}

fn discovery_response() -> String {
    let extensions = json!({
        (EXTENSION): {"version": 1, "multiplier": 3},
        (OTHER_EXTENSION): {"version": 1, "multiplier": 3}
    });
    #[cfg(feature = "tasks")]
    let extensions = {
        let mut extensions = extensions;
        extensions["io.modelcontextprotocol/tasks"] = json!({});
        extensions
    };
    // Both owners are advertised, so rejecting OTHER_RESULT for the math
    // request proves ownership rather than unknown-marker denial.
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "resultType": "complete",
            "supportedVersions": ["2026-07-28"],
            "capabilities": {"extensions": extensions},
            "ttlMs": 0,
            "cacheScope": "private"
        }
    }))
    .unwrap()
}

fn run<F: Future<Output = ()>>(exercise: impl FnOnce(Cx) -> F) {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        assert!(cx.blocking_pool_handle().is_none());
        asupersync::time::timeout(cx.now(), Duration::from_secs(15), exercise(cx))
            .await
            .expect("public stdio extensions must progress on the caller runtime");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn modern_stdio_extension_facade_defers_discovery_and_preserves_wire_authority() {
    run(|cx| async move {
        let script = format!(
            r#"IFS= read -r discovery || exit 90
printf '%s\n' '{discovery}'
IFS= read -r first || exit 91
printf '{{"jsonrpc":"2.0","id":2,"result":{{"value":21,"exact":1.20e+4,"observed":[%s,%s]}}}}\n' "$discovery" "$first"
IFS= read -r notification || exit 92
IFS= read -r second || exit 93
printf '%s\n' '{{"jsonrpc":"2.0","id":3,"result":{{"resultType":"{other}","value":99}}}}'
IFS= read -r third || exit 94
printf '{{"jsonrpc":"2.0","id":4,"result":{{"value":15,"observed":[%s,%s,%s]}}}}\n' "$notification" "$second" "$third"
while IFS= read -r ignored; do :; done
"#,
            discovery = discovery_response(),
            other = OTHER_RESULT,
        );
        let (id, registry, discovery) = configuration();
        let resolutions = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&resolutions);
        let mut client = modern::ClientBuilder::new()
            .client_info("facade-stdio-client", "1")
            .auto_initialize(true)
            .extension_registry(registry, discovery, move || {
                observed.fetch_add(1, Ordering::SeqCst);
                accept_settings
            })
            .unwrap()
            .connect_stdio_with_cx(&cx, "sh", &["-c", &script])
            .await
            .unwrap();
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            0,
            "connect preserves deferred discovery"
        );
        let first = client
            .request_final_extension(
                &cx,
                &id,
                METHOD,
                json!({
                    "value": 7,
                    "_meta": {
                        "com.example/note": "retained",
                        "io.modelcontextprotocol/protocolVersion": "2024-11-05",
                        "io.modelcontextprotocol/clientInfo": {"name": "forged", "version": "9"},
                        "io.modelcontextprotocol/clientCapabilities": {
                            "extensions": {"com.example/forged": {}}
                        }
                    }
                }),
            )
            .await
            .unwrap();
        assert_eq!(resolutions.load(Ordering::SeqCst), 1);
        assert_eq!(first["value"], 21);
        assert!(first.get("resultType").is_none());
        assert_eq!(first["exact"].as_number().unwrap().to_string(), "1.20e+4");
        assert_eq!(first["observed"][0]["method"], "server/discover");
        assert_eq!(first["observed"][0]["id"], 1);
        let request = &first["observed"][1];
        assert_eq!(request["id"], 2);
        assert_eq!(request["method"], METHOD);
        assert_eq!(request["params"]["value"], 7);
        let metadata = &request["params"]["_meta"];
        assert_eq!(
            metadata["io.modelcontextprotocol/protocolVersion"],
            "2026-07-28"
        );
        assert_eq!(
            metadata["io.modelcontextprotocol/clientInfo"]["name"],
            "facade-stdio-client"
        );
        assert_eq!(
            metadata["io.modelcontextprotocol/clientCapabilities"]["extensions"][EXTENSION],
            json!({"version": 1})
        );
        assert!(
            metadata["io.modelcontextprotocol/clientCapabilities"]["extensions"]
                .get("com.example/forged")
                .is_none()
        );
        assert_eq!(metadata["com.example/note"], "retained");

        for (owner, method, parameters) in [
            (
                ExtensionId::parse("com.example/unknown").unwrap(),
                METHOD,
                json!({"value": 1}),
            ),
            (id.clone(), "tools/list", json!({})),
            (id.clone(), METHOD, json!({"_meta": []})),
        ] {
            assert_eq!(
                client
                    .request_final_extension(&cx, &owner, method, parameters)
                    .await
                    .unwrap_err()
                    .code,
                McpErrorCode::InvalidParams
            );
        }
        assert_eq!(
            client
                .notify_final_extension(
                    &cx,
                    &id,
                    NOTIFICATION,
                    json!({"value": 17, "hold": false, "_meta": {(ACTIVATION): {"version": 2}}}),
                )
                .await
                .unwrap_err()
                .code,
            McpErrorCode::InvalidParams
        );
        client
            .notify_final_extension(
                &cx,
                &id,
                NOTIFICATION,
                json!({"value": 11, "hold": false}),
            )
            .await
            .unwrap();
        assert_eq!(
            resolutions.load(Ordering::SeqCst),
            2,
            "notification obtains fresh settings proof"
        );
        assert_eq!(
            client
                .request_final_extension(&cx, &id, METHOD, json!({"value": 13}))
                .await
                .unwrap_err()
                .code,
            McpErrorCode::InvalidRequest
        );
        let third = client
            .request_final_extension(&cx, &id, METHOD, json!({"value": 5}))
            .await
            .unwrap();
        assert_eq!(
            third["value"],
            15,
            "a foreign-owner result does not poison the next request"
        );
        let observed = third["observed"].as_array().unwrap();
        assert_eq!(observed.len(), 3);
        assert_eq!(observed[0]["method"], NOTIFICATION);
        assert!(observed[0].get("id").is_none());
        assert_eq!(
            observed[0]["params"]["_meta"][ACTIVATION],
            json!({"version": 1})
        );
        assert!(
            observed[0]["params"]["_meta"]
                .get("io.modelcontextprotocol/protocolVersion")
                .is_none()
        );
        assert_eq!(
            observed[1]["id"],
            3,
            "local refusals and notification consume no request IDs"
        );
        assert_eq!(observed[1]["method"], METHOD);
        assert_eq!(observed[2]["id"], 4);
        assert_eq!(observed[2]["params"]["value"], 5);
        client.close_with_cx(&cx).await.unwrap();
        assert!(cx.checkpoint().is_ok());
    });
}

#[test]
fn modern_stdio_extension_facade_cancels_one_request_and_preserves_later_success() {
    run(|cx| async move {
        let script = format!(
            r#"IFS= read -r discovery || exit 90
printf '%s\n' '{discovery}'
IFS= read -r warmup || exit 91
printf '%s\n' '{{"jsonrpc":"2.0","id":2,"result":{{"value":3}}}}'
IFS= read -r cancelled || exit 92
IFS= read -r control || exit 93
IFS= read -r followup || exit 94
printf '%s\n' '{{"jsonrpc":"2.0","id":3,"result":{{"resultType":"{other}","value":"late"}}}}'
printf '{{"jsonrpc":"2.0","id":4,"result":{{"value":15,"observed":[%s,%s,%s]}}}}\n' "$cancelled" "$control" "$followup"
while IFS= read -r ignored; do :; done
"#,
            discovery = discovery_response(),
            other = OTHER_RESULT,
        );
        let (id, registry, discovery) = configuration();
        let mut client = modern::ClientBuilder::new()
            .extension_registry(registry, discovery, || accept_settings)
            .unwrap()
            .connect_stdio_with_cx(&cx, "sh", &["-c", &script])
            .await
            .unwrap();
        assert_eq!(
            client
                .request_final_extension(&cx, &id, METHOD, json!({"value": 1}))
                .await
                .unwrap(),
            json!({"value": 3})
        );

        let stopped = McpRequestCancellation::new();
        stopped.cancel();
        assert_eq!(
            client
                .request_final_extension_with_cancellation(
                    &cx,
                    &stopped,
                    &id,
                    METHOD,
                    json!({"value": 0}),
                )
                .await
                .unwrap_err()
                .code,
            McpErrorCode::RequestCancelled
        );
        let cancellation = McpRequestCancellation::new();
        {
            let mut request = pin!(client.request_final_extension_with_cancellation(
                &cx,
                &cancellation,
                &id,
                METHOD,
                json!({"value": 13}),
            ));
            poll_fn(|task| {
                assert!(
                    request.as_mut().poll(task).is_pending(),
                    "the peer withholds this result"
                );
                Poll::Ready(())
            })
            .await;
            cancellation.cancel();
            assert_eq!(request.await.unwrap_err().code, McpErrorCode::RequestCancelled);
        }
        let result = client
            .request_final_extension(&cx, &id, METHOD, json!({"value": 5}))
            .await
            .unwrap();
        assert_eq!(result["value"], 15);
        let observed = result["observed"].as_array().unwrap();
        assert_eq!(
            observed[0]["id"],
            3,
            "pre-cancelled calls consume no request ID"
        );
        assert_eq!(observed[0]["method"], METHOD);
        assert_eq!(observed[0]["params"]["value"], 13);
        assert_eq!(observed[1]["method"], "notifications/cancelled");
        assert!(observed[1].get("id").is_none());
        assert_eq!(observed[1]["params"]["requestId"], 3);
        assert_eq!(observed[2]["id"], 4);
        assert_eq!(observed[2]["method"], METHOD);
        assert_eq!(observed[2]["params"]["value"], 5);
        assert!(
            cx.checkpoint().is_ok(),
            "one request token does not cancel its runtime"
        );
        client.close_with_cx(&cx).await.unwrap();
    });
}
