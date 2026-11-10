//! Public managed-provider update relay over a real, isolated TLS login and
//! authenticated POST. Negative rows change an event or lifetime boundary.

use super::*;
use fastmcp_client::http_auth::managed::subscriptions::ManagedSubscriptionLimits;
use fastmcp_core::McpErrorCode;
use fastmcp_protocol::{FINAL_SUBSCRIPTION_ID_META_KEY, SubscriptionFilter};
use fastmcp_server::providers::managed_oauth::ManagedOAuthProvider;
use fastmcp_server::providers::managed_oauth::subscriptions::ManagedOAuthResourceRelayEnd;

const SELECTED: &str = "report://monthly/a%2Fb";
const NARROWED_OUT: &str = "report://monthly/other";

#[derive(Clone, Copy)]
pub(super) enum Case {
    Complete,
    Cancelled,
    OutsideAcceptedFilter,
    WidenedAck,
    MissingAck,
    MissingTerminal,
    LocalCancellation,
    ClosedLogin,
    RecordLimit,
    Deadline,
    DownstreamCancellation,
}

async fn request(peer: &Peer, method: &str) -> (TlsStream<TcpStream>, Value) {
    let (socket, start, headers, body) = peer.receive().await;
    assert_eq!(start, "POST /mcp HTTP/1.1");
    assert_eq!(headers["authorization"], format!("Bearer {}", peer.token));
    assert!(!headers.contains_key("mcp-session-id"));
    assert!(!headers.contains_key("last-event-id"));
    let wire: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(wire["method"], method);
    assert_eq!(
        wire["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
        json!({})
    );
    peer.seen.lock().unwrap().push(wire.clone());
    (socket, wire)
}

async fn catalog(peer: &Peer) {
    let (mut socket, wire) = request(peer, "resources/list").await;
    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "id": wire["id"], "result": {
            "resultType": "complete", "ttlMs": 0, "cacheScope": "private",
            "resources": [
                {"uri": SELECTED, "name": "selected"},
                {"uri": NARROWED_OUT, "name": "not-accepted"}
            ]
        }
    }))
    .unwrap();
    write_reply(
        &mut socket,
        200,
        &std::collections::HashMap::from([(
            "content-type".to_owned(),
            "application/json".to_owned(),
        )]),
        &body,
        Delivery::Complete,
    )
    .await;
}

async fn subscription(peer: &Peer, case: Case) {
    let (mut socket, wire) = request(peer, "subscriptions/listen").await;
    assert_eq!(
        wire["params"]["notifications"],
        json!({
            "resourceSubscriptions": [SELECTED, NARROWED_OUT]
        })
    );
    let id = wire["id"].clone();
    let tag = json!({FINAL_SUBSCRIPTION_ID_META_KEY: id});
    let mut records = Vec::new();
    if !matches!(case, Case::MissingAck) {
        records.push(json!({
            "jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged",
            "params": {"_meta": tag, "notifications": {"resourceSubscriptions": [
                if matches!(case, Case::WidenedAck) { "report://private/foreign" } else { SELECTED }
            ]}}
        }));
    }
    records.push(json!({
        "jsonrpc": "2.0", "method": "notifications/resources/updated",
        "params": {
            "uri": if matches!(case, Case::OutsideAcceptedFilter) { NARROWED_OUT } else { SELECTED },
            "_meta": {
                FINAL_SUBSCRIPTION_ID_META_KEY: id,
                "com.example/private": "PRIVATE-UPSTREAM-METADATA"
            },
            "private": "PRIVATE-UPSTREAM-EXTRA"
        }
    }));
    if matches!(case, Case::Cancelled) {
        records.push(json!({
            "jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"requestId": id, "reason": "PRIVATE-UPSTREAM-REASON", "_meta": tag}
        }));
    } else if !matches!(case, Case::MissingTerminal) {
        records.push(json!({
            "jsonrpc": "2.0", "id": id,
            "result": {"resultType": "complete", "_meta": tag}
        }));
    }
    let body: String = records
        .iter()
        .map(|record| format!("data: {record}\n\n"))
        .collect();
    write_reply(
        &mut socket,
        200,
        &std::collections::HashMap::from([(
            "content-type".to_owned(),
            "text/event-stream".to_owned(),
        )]),
        body.as_bytes(),
        Delivery::Complete,
    )
    .await;
}

pub(super) async fn scenario(cx: Cx, case: Case) {
    let peer = Peer::new(&cx, false).await;
    let ((), login) = pair(
        peer.login(),
        ManagedOAuthSession::authorize(&cx, peer.client(), OAuthSessionPolicy::default(), browser),
    )
    .await;
    let login = login.unwrap();
    let provider = ManagedOAuthProvider::new(login.clone())
        .with_namespace("remote")
        .unwrap();
    let ((), resources) = pair(catalog(&peer), provider.resources(&cx)).await;
    let resources = resources.unwrap();
    let selectors: Vec<_> = resources
        .iter()
        .map(|resource| resource.update_subscription())
        .collect();
    assert_eq!(selectors[0].uri().as_str(), SELECTED);

    let cancellation = McpRequestCancellation::new();
    let limits = ManagedSubscriptionLimits::new(
        4096,
        4096,
        if matches!(case, Case::RecordLimit) {
            2
        } else {
            8
        },
        if matches!(case, Case::Deadline) {
            Duration::from_secs(1)
        } else {
            Duration::from_secs(5)
        },
    )
    .unwrap();
    // Same login and same URI do not make independent providers share routes.
    let foreign = ManagedOAuthProvider::new(login.clone());
    assert!(
        foreign
            .open_resource_updates(&cx, &cancellation, &selectors, limits)
            .await
            .is_err()
    );
    let cancelled_before_open = McpRequestCancellation::new();
    cancelled_before_open.cancel();
    let error = match provider
        .open_resource_updates(&cx, &cancelled_before_open, &selectors, limits)
        .await
    {
        Err(error) => error,
        Ok(_) => panic!("pre-cancelled owner cannot open a POST"),
    };
    assert_eq!(error.code, McpErrorCode::RequestCancelled);
    peer.quiet();

    let mut builder = Server::new("managed-update-gateway", "1")
        .protocol_policy(ProtocolPolicy::ModernOnly)
        .unwrap();
    for resource in resources {
        builder = builder.resource(resource);
    }
    let server = builder.build();
    let publisher = server.subscription_publisher();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&observed);
    let downstream = McpContext::new(cx.clone(), 70);
    let selected = server
        .open_subscription_listen_in_context(
            &downstream,
            RequestId::String("downstream-selected".to_owned()),
            SubscriptionFilter {
                resource_subscriptions: Some(vec![SELECTED.to_owned()]),
                ..Default::default()
            },
            Arc::new(move |event| sink.lock().unwrap().push(event)),
        )
        .unwrap();
    let other_events = Arc::new(Mutex::new(Vec::new()));
    let other_sink = Arc::clone(&other_events);
    let other = server
        .open_subscription_listen_in_context(
            &McpContext::new(cx.clone(), 71),
            RequestId::Number(71),
            SubscriptionFilter {
                resource_subscriptions: Some(vec![NARROWED_OUT.to_owned()]),
                ..Default::default()
            },
            Arc::new(move |event| other_sink.lock().unwrap().push(event)),
        )
        .unwrap();

    let ((), opened) = pair(
        subscription(&peer, case),
        provider.open_resource_updates(&cx, &cancellation, &selectors, limits),
    )
    .await;
    let (result, expected_updates) = match opened {
        Err(error) => {
            assert!(
                matches!(case, Case::MissingAck | Case::WidenedAck),
                "unexpected open failure: {error}"
            );
            (Err(error), 0)
        }
        Ok(updates) => {
            assert!(!matches!(case, Case::MissingAck | Case::WidenedAck));
            assert_eq!(updates.accepted_resources(), &[SELECTED.to_owned()]);
            assert_eq!(updates.credential_generation(), 1);
            match case {
                Case::LocalCancellation => {
                    cancellation.cancel();
                }
                Case::ClosedLogin => login.close(),
                Case::DownstreamCancellation => {
                    downstream.request_cancellation().cancel();
                }
                Case::Deadline => {
                    asupersync::time::sleep(cx.now(), Duration::from_millis(1100)).await
                }
                _ => {}
            }
            let expected_updates = usize::from(!matches!(
                case,
                Case::OutsideAcceptedFilter
                    | Case::LocalCancellation
                    | Case::ClosedLogin
                    | Case::Deadline
                    | Case::DownstreamCancellation
            ));
            (
                updates.relay(&cx, |event| publisher.publish(event)).await,
                expected_updates,
            )
        }
    };
    match case {
        Case::Complete | Case::Cancelled | Case::DownstreamCancellation => {
            let outcome = result.unwrap();
            assert_eq!(
                outcome.end,
                if matches!(case, Case::Cancelled) {
                    ManagedOAuthResourceRelayEnd::Cancelled
                } else {
                    ManagedOAuthResourceRelayEnd::Complete
                }
            );
            assert_eq!(outcome.forwarded_updates, 1);
            assert_eq!(outcome.downstream_deliveries, expected_updates);
        }
        _ => {
            let error = result.unwrap_err();
            assert!(!error.message.contains("PRIVATE-UPSTREAM"));
            if matches!(case, Case::LocalCancellation) {
                assert_eq!(error.code, McpErrorCode::RequestCancelled);
            }
        }
    }
    let events = observed.lock().unwrap();
    assert_eq!(
        events.len(),
        expected_updates + 1,
        "only ACK plus authorized updates are delivered"
    );
    assert_eq!(events[0].method, "notifications/subscriptions/acknowledged");
    if expected_updates > 0 {
        assert_eq!(events[1].method, "notifications/resources/updated");
        assert_eq!(
            events[1].params.as_ref().unwrap(),
            &json!({
                "uri": SELECTED,
                "_meta": {FINAL_SUBSCRIPTION_ID_META_KEY: "downstream-selected"}
            })
        );
    }
    drop(events);
    assert_eq!(
        other_events.lock().unwrap().len(),
        1,
        "narrowing is never widened downstream"
    );
    assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
    assert_eq!(
        peer.seen.lock().unwrap().len(),
        2,
        "one catalog and one listen, no retries"
    );
    peer.quiet();
    drop((selected, other));
    login.close();
}

macro_rules! case {
    ($name:ident, $case:ident) => {
        #[test]
        fn $name() {
            isolated(
                concat!("provider_updates::", stringify!($name)),
                super::Case::ProviderUpdates(Case::$case),
            );
        }
    };
}

case!(
    managed_resource_updates_publish_only_the_narrowed_resource,
    Complete
);
case!(
    managed_resource_updates_report_upstream_cancellation,
    Cancelled
);
case!(
    managed_resource_updates_reject_an_event_excluded_by_ack,
    OutsideAcceptedFilter
);
case!(managed_resource_updates_reject_a_widened_ack, WidenedAck);
case!(managed_resource_updates_require_first_ack, MissingAck);
case!(
    managed_resource_updates_never_treat_lost_terminal_as_success,
    MissingTerminal
);
case!(
    managed_resource_updates_enforce_local_cancellation,
    LocalCancellation
);
case!(managed_resource_updates_enforce_login_closure, ClosedLogin);
case!(managed_resource_updates_enforce_record_bound, RecordLimit);
case!(
    managed_resource_updates_include_caller_pauses_in_deadline,
    Deadline
);
case!(
    managed_resource_updates_revalidate_downstream_lifetime,
    DownstreamCancellation
);
