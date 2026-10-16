use super::*;
use std::sync::Arc;

use fastmcp_core::CanonicalHttpUrl;
use crate::http_executor::parameter_headers::ReviewedToolHeaders;

fn reviewed_operation(target: &str) -> DpopTaskOperation {
    let reviewed = Arc::new(ReviewedToolHeaders::new(
        CanonicalHttpUrl::parse(target).unwrap(),
        "work",
        json!({
            "type":"object",
            "properties":{
                "region":{"type":"string","x-mcp-header":"Region"},
                "private":{"type":"string","writeOnly":true}
            }
        }),
        |_| true,
    ).unwrap());
    DpopTaskOperation::new(
        RequestId::String("reviewed-discovery".to_owned()),
        RequestId::String("reviewed-call".to_owned()),
        ManagedTaskRequest::CallTool {
            name: "work".to_owned(),
            arguments: Some(json!({"region":"eu","private":"body-only"})),
        },
    ).unwrap()
        .with_reviewed_tool_headers(reviewed).unwrap()
}

async fn reviewed_creation(peer: &mut Peer, result: &Value) {
    let (mut discovery, _) = peer.receive_named("reviewed-discovery", "server/discover").await;
    let discovery_response = serde_json::to_vec(&json!({
        "jsonrpc":"2.0","id":"reviewed-discovery","result":discovery_result()
    })).unwrap();
    json_reply(&mut discovery, &discovery_response).await;

    let (socket, _) = peer.listener.accept().await.unwrap();
    let mut socket = peer.acceptor.accept(socket).await.unwrap();
    let (head, body) = read(&mut socket).await;
    assert_eq!(body["id"], "reviewed-call");
    assert_eq!(body["method"], "tools/call");
    assert_eq!(body["params"]["name"], "work");
    assert_eq!(
        body["params"]["arguments"],
        json!({"region":"eu","private":"body-only"})
    );
    assert_eq!(header(&head, "mcp-method"), "tools/call");
    assert_eq!(header(&head, "mcp-name"), "work");
    assert_eq!(
        header(&head, "mcp-param-region"),
        fastmcp_protocol::http_headers::encode_mcp_header_value("eu").unwrap()
    );
    assert!(!head.contains("body-only"));
    let proof = claims(header(&head, "dpop"));
    assert_eq!(proof["nonce"], "stream-next");
    assert!(peer.proofs.insert(proof["jti"].as_str().unwrap().to_owned()));

    let response = serde_json::to_vec(&json!({
        "jsonrpc":"2.0","id":"reviewed-call","result":result
    })).unwrap();
    json_reply(&mut socket, &response).await;
}

#[test]
fn reviewed_headers_survive_creation_and_do_not_change_the_task_watch_namespace() {
    run(async {
        let cx = Cx::current().unwrap();
        let (mut peer, mut client, credential) = Peer::new().await;
        let cancellation = McpRequestCancellation::new();
        let target = peer.target.clone();
        let application = client.start_and_drive_task_operation_with_subscription(
            &cx,
            &cancellation,
            &credential,
            driver_metadata(),
            reviewed_operation(&target),
            "reviewed",
            policy(2, 0),
            watch_limits(8),
            |_| std::future::ready(Ok(ManagedTaskInputAction::ReturnToCaller)),
            |_| Ok(()),
        );
        let server = async {
            reviewed_creation(&mut peer, &created("working")).await;
            // Successor identities come only from the watch namespace, never
            // from the caller-selected creation IDs or reviewed header plan.
            peer.watch_snapshot_reply("reviewed", 0, "cancelled").await;
        };
        let (result, ()) = pair(application, server).await;
        let DpopTaskSubscriptionExecutionOutcome::Observed { outcome, .. } = result.unwrap() else {
            panic!("working creation must reconcile through the Task watcher")
        };
        assert!(matches!(
            outcome,
            DpopTaskWaitOutcome::Terminal(snapshot)
                if matches!(snapshot.task, Task::Cancelled(_))
        ));
        peer.no_extra(2);
        assert!(cx.checkpoint().is_ok());
        assert!(!client.revocation_handle().is_revoked());
    });
}

#[test]
fn colliding_reviewed_creation_ids_fail_before_any_tls_request() {
    run(async {
        let cx = Cx::current().unwrap();
        let (peer, mut client, credential) = Peer::new().await;
        let cancellation = McpRequestCancellation::new();
        let target = peer.target.clone();
        let reviewed = Arc::new(ReviewedToolHeaders::new(
            CanonicalHttpUrl::parse(&target).unwrap(),
            "work",
            json!({"type":"object","properties":{}}),
            |_| true,
        ).unwrap());
        let operation = DpopTaskOperation::new(
            RequestId::String("collision.0.get".to_owned()),
            RequestId::String("initial-call".to_owned()),
            ManagedTaskRequest::CallTool { name:"work".to_owned(), arguments:None },
        ).unwrap().with_reviewed_tool_headers(reviewed).unwrap();

        let result = client.start_and_drive_task_operation_with_subscription(
            &cx, &cancellation, &credential, driver_metadata(), operation,
            "collision", policy(2, 1), watch_limits(8),
            |_| std::future::ready(Ok(ManagedTaskInputAction::ReturnToCaller)),
            |_| Ok(()),
        ).await;
        assert!(matches!(
            result,
            Err(DpopTaskWatchError::Driver(ManagedTaskDriverError::RepeatedRequestId))
        ));
        peer.no_extra(0);
        assert!(cx.checkpoint().is_ok());
    });
}
