//! Public machine-authenticated Tasks listens. Reuses the parent's actual
//! issuer discovery, Basic grant, TLS transport and isolated CA; no transport
//! or subscription decoder is mocked.

use super::*;
use fastmcp_client::http_auth::discovery::client_credentials::tasks::subscriptions::{
    ClientCredentialsSubscriptionLimits, ClientCredentialsTaskSubscription,
};
use fastmcp_client::http_executor::ModernHttpSubscriptionListenEvent as ListenEvent;
use fastmcp_protocol::{SubscriptionFilter, FINAL_SUBSCRIPTION_ID_META_KEY};
use fastmcp_protocol::tasks_extension::task_subscription_ids;

const SUB_CHILD: &str = "FASTMCP_TEST_MACHINE_TASK_SUBSCRIPTION_CASE";

#[derive(Clone, Copy)]
enum SubCase {
    Live, MissingTasks, MissingAuth, WrongAck, WidenedAck, BeforeAck,
    WrongTask, WrongSubscription, WrongResource, DuplicateAck, Truncated,
    RemoteError, Cancel, Close, Abandon, Expiry, Deadline, RecordLimit,
    Renewal, Preflight, Denied, Redirect, LostListen, NarrowedAck,
}

fn isolated_subscription(name: &str, case: SubCase) {
    if let Ok(selected) = std::env::var(SUB_CHILD) {
        assert_eq!(selected, name);
        run_subscription(case);
        return;
    }
    let roots = RootFile::create();
    let mut child = Child(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(SUB_CHILD, name).env("SSL_CERT_FILE", &roots.0).env_remove("SSL_CERT_DIR")
        .stdin(Stdio::null()).stdout(Stdio::inherit()).stderr(Stdio::inherit())
        .spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "machine subscription TLS case failed");
            return;
        }
        assert!(Instant::now() < deadline, "machine subscription process bound expired");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn selected() -> SubscriptionFilter {
    serde_json::from_value(json!({"taskIds":["machine-task"], "toolsListChanged":true,
        "resourceSubscriptions":["file:///watched"]})).unwrap()
}
fn ack(id: i64, filter: &SubscriptionFilter) -> String {
    json!({"jsonrpc":"2.0", "method":"notifications/subscriptions/acknowledged",
        "params":{"_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):id}, "notifications":filter}}).to_string()
}
fn terminal_listen(id: i64) -> String {
    terminal(id, &json!({"resultType":"complete", "_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):id}}).to_string())
}
fn task_notice(subscription: i64, task_id: &str, status: &str) -> String {
    json!({"jsonrpc":"2.0", "method":"notifications/tasks", "params":{
        "_meta":{(FINAL_SUBSCRIPTION_ID_META_KEY):subscription}, "taskId":task_id,
        "status":status, "createdAt":"2026-09-17T00:00:00Z",
        "lastUpdatedAt":"2026-09-17T00:00:00Z", "ttlMs":60000
    }}).to_string()
}
fn resource_notice(uri: &str) -> String {
    json!({"jsonrpc":"2.0", "method":"notifications/resources/updated", "params":{"uri":uri}}).to_string()
}
async fn stream(peer: &Peer, id: i64, token: &str, filter: &SubscriptionFilter) -> TlsStream<TcpStream> {
    discover(peer, id, token, &discovery()).await;
    let (mut tls, request) = rpc(peer, id + 1, "subscriptions/listen", token).await;
    assert_eq!(request["params"]["notifications"], serde_json::to_value(filter).unwrap());
    tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
    tls.flush().await.unwrap();
    tls
}
async fn open(tasks: &ClientCredentialsTasksClient, cx: &Cx, id: i64) -> ClientCredentialsTaskSubscription {
    tasks.subscribe(cx, RequestId::Number(id), RequestId::Number(id + 1), selected(),
        ClientCredentialsSubscriptionLimits::default()).await.unwrap()
}
async fn receive_ack(subscription: &mut ClientCredentialsTaskSubscription, cx: &Cx, filter: &SubscriptionFilter) {
    assert!(subscription.accepted_filter().is_none());
    let Some(ListenEvent::Acknowledged { accepted_filter }) = subscription.next_event(cx).await.unwrap()
        else { panic!("first record must be the admitted ACK"); };
    assert_eq!(serde_json::to_value(&accepted_filter).unwrap(), serde_json::to_value(filter).unwrap());
    assert_eq!(serde_json::to_value(subscription.accepted_filter().unwrap()).unwrap(),
        serde_json::to_value(filter).unwrap());
}
async fn receive_terminal(subscription: &mut ClientCredentialsTaskSubscription, cx: &Cx, id: i64) {
    let Some(ListenEvent::Terminal { subscription_id, .. }) = subscription.next_event(cx).await.unwrap()
        else { panic!("correlated listen terminal required"); };
    assert!(subscription_id.correlates_with(&RequestId::Number(id)));
    assert!(subscription.next_event(cx).await.unwrap().is_none());
    assert!(subscription.next_event(cx).await.unwrap().is_none());
}
async fn healthy_listen(peer: &Peer, tasks: &ClientCredentialsTasksClient, cx: &Cx, id: i64, token: &str, generation: u64) {
    let server = async {
        let mut tls = stream(peer, id, token, &selected()).await;
        event(&mut tls, &ack(id + 1, &selected()), false).await;
        event(&mut tls, &terminal_listen(id + 1), true).await;
    };
    let application = async {
        let mut subscription = open(tasks, cx, id).await;
        assert_eq!(subscription.credential_generation(), generation);
        receive_ack(&mut subscription, cx, &selected()).await;
        receive_terminal(&mut subscription, cx, id + 1).await;
    };
    pair(server, application).await;
}

fn run_subscription(case: SubCase) {
    RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap()).build().unwrap()
        .block_on(Box::pin(async {
            let cx = Cx::current().unwrap();
            let scenario = Box::pin(async {
                let peer = Peer::new().await;
                let plan = peer.plan(Duration::from_secs(15));
                let ((), client) = pair(peer.metadata(Case::Complete), plan.discover(&cx)).await;
                let client = client.unwrap();
                let tasks = ClientCredentialsTasksClient::new(client.clone(), metadata(),
                    ClientCredentialsTasksLimits::default()).unwrap();
                if matches!(case, SubCase::Preflight) {
                    let alias = serde_json::from_str::<RequestId>("1e0").unwrap();
                    assert!(matches!(tasks.subscribe(&cx, RequestId::Number(1), alias, selected(),
                        ClientCredentialsSubscriptionLimits::default()).await,
                        Err(TaskError::Protocol(ManagedTasksError::InvalidRequest))));
                    let missing = SubscriptionFilter::default();
                    assert!(matches!(tasks.subscribe(&cx, RequestId::Number(1), RequestId::Number(2), missing,
                        ClientCredentialsSubscriptionLimits::default()).await,
                        Err(TaskError::Protocol(ManagedTasksError::InvalidRequest))));
                    let tiny = ClientCredentialsSubscriptionLimits::new(1, 4096, 2, Duration::from_secs(1)).unwrap();
                    assert!(matches!(tasks.subscribe(&cx, RequestId::Number(1), RequestId::Number(2), selected(), tiny).await,
                        Err(TaskError::Protocol(ManagedTasksError::RequestTooLarge))));
                    let cancellation = McpRequestCancellation::new();
                    cancellation.cancel();
                    assert!(matches!(tasks.subscribe_with_cancellation(&cx, &cancellation,
                        RequestId::Number(1), RequestId::Number(2), selected(), ClientCredentialsSubscriptionLimits::default()).await,
                        Err(TaskError::Authentication(Error::Discovery(OAuthDiscoveryError::Cancelled)))));
                    assert_eq!(peer.grants.load(Ordering::SeqCst), 0);
                    assert_eq!(peer.rpcs.load(Ordering::SeqCst), 0);
                    peer.quiet();
                    acquire(&peer, &cx, &client, "access-one", 300).await;
                    healthy_listen(&peer, &tasks, &cx, 3, "access-one", 1).await;
                    assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
                    return;
                }
                let lifetime = if matches!(case, SubCase::Expiry | SubCase::Renewal) { 3 } else { 300 };
                acquire(&peer, &cx, &client, "access-one", lifetime).await;
                match case {
                    SubCase::Live => {
                        let (tx, mut rx) = oneshot::channel::<()>();
                        let server = async {
                            let mut tls = stream(&peer, 1, "access-one", &selected()).await;
                            event(&mut tls, &ack(2, &selected()), false).await;
                            rx.recv(&cx).await.unwrap();
                            event(&mut tls, NOTICE, false).await;
                            event(&mut tls, &resource_notice("file:///watched"), false).await;
                            event(&mut tls, &task_notice(2, "machine-task", "working"), false).await;
                            event(&mut tls, &task_notice(2, "machine-task", "cancelled"), false).await;
                            event(&mut tls, &terminal_listen(2), true).await;
                        };
                        let application = async {
                            let mut subscription = open(&tasks, &cx, 1).await;
                            assert!(subscription.request_id().correlates_with(&RequestId::Number(2)));
                            assert_eq!(subscription.credential_generation(), 1);
                            receive_ack(&mut subscription, &cx, &selected()).await;
                            tx.send(&cx, ()).unwrap();
                            assert!(matches!(subscription.next_event(&cx).await.unwrap(), Some(ListenEvent::Notification(_))));
                            assert!(matches!(subscription.next_event(&cx).await.unwrap(), Some(ListenEvent::Notification(_))));
                            for cancelled in [false, true] {
                                let Some(ListenEvent::TaskNotification(notification)) = subscription.next_event(&cx).await.unwrap()
                                    else { panic!("selected task event required"); };
                                assert_eq!(notification.params.task.base().task_id, task_id());
                                assert_eq!(matches!(notification.params.task, Task::Cancelled(_)), cancelled);
                            }
                            receive_terminal(&mut subscription, &cx, 2).await;
                        };
                        pair(server, application).await;
                        assert_eq!(peer.rpcs.load(Ordering::SeqCst), 2, "events cause no polling or mutation");
                    }
                    SubCase::MissingTasks | SubCase::MissingAuth => {
                        let mut document = discovery();
                        let key = if matches!(case, SubCase::MissingTasks) { TASKS_EXTENSION } else { CLIENT_CREDENTIALS_EXTENSION };
                        document["capabilities"]["extensions"].as_object_mut().unwrap().remove(key);
                        let ((), rejected) = pair(discover(&peer, 1, "access-one", &document),
                            tasks.subscribe(&cx, RequestId::Number(1), RequestId::Number(2), selected(),
                                ClientCredentialsSubscriptionLimits::default())).await;
                        match case {
                            SubCase::MissingTasks => assert!(matches!(rejected, Err(TaskError::Protocol(ManagedTasksError::Negotiation)))),
                            _ => assert!(matches!(rejected, Err(TaskError::Authentication(Error::Negotiation)))),
                        }
                        assert_eq!(peer.rpcs.load(Ordering::SeqCst), 1, "no listen after partial negotiation");
                        peer.quiet();
                        healthy_listen(&peer, &tasks, &cx, 3, "access-one", 1).await;
                    }
                    SubCase::WrongAck | SubCase::WidenedAck | SubCase::BeforeAck | SubCase::WrongTask
                    | SubCase::WrongSubscription | SubCase::WrongResource | SubCase::DuplicateAck
                    | SubCase::Truncated | SubCase::RemoteError => {
                        let server = async {
                            let mut tls = stream(&peer, 1, "access-one", &selected()).await;
                            let first_bad = matches!(case, SubCase::WrongAck | SubCase::WidenedAck | SubCase::BeforeAck);
                            if !first_bad { event(&mut tls, &ack(2, &selected()), matches!(case, SubCase::Truncated)).await; }
                            let bad = match case {
                                SubCase::WrongAck => ack(99, &selected()),
                                SubCase::WidenedAck => {
                                    let mut widened = selected();
                                    widened.prompts_list_changed = Some(true);
                                    ack(2, &widened)
                                }
                                SubCase::BeforeAck => task_notice(2, "machine-task", "working"),
                                SubCase::WrongTask => task_notice(2, "foreign-task", "working"),
                                SubCase::WrongSubscription => task_notice(99, "machine-task", "working"),
                                SubCase::WrongResource => resource_notice("file:///not-watched"),
                                SubCase::DuplicateAck => ack(2, &selected()),
                                SubCase::RemoteError => r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32603,"message":"private-peer-secret","data":"private-peer-secret"}}"#.to_owned(),
                                _ => return,
                            };
                            event(&mut tls, &bad, true).await;
                        };
                        let application = async {
                            let mut subscription = open(&tasks, &cx, 1).await;
                            let first_bad = matches!(case, SubCase::WrongAck | SubCase::WidenedAck | SubCase::BeforeAck);
                            if !first_bad { receive_ack(&mut subscription, &cx, &selected()).await; }
                            let before = serde_json::to_value(subscription.accepted_filter()).unwrap();
                            let error = subscription.next_event(&cx).await.expect_err("invalid stream must fail");
                            match case {
                                SubCase::Truncated => assert!(matches!(error, TaskError::Protocol(ManagedTasksError::MissingTerminal))),
                                SubCase::RemoteError => {
                                    assert!(matches!(error, TaskError::Protocol(ManagedTasksError::Remote { .. })));
                                    assert!(!format!("{error:?} {error}").contains("private-peer-secret"));
                                }
                                _ => assert!(matches!(error, TaskError::Protocol(ManagedTasksError::InvalidResponse))),
                            }
                            assert_eq!(serde_json::to_value(subscription.accepted_filter()).unwrap(), before);
                            assert!(matches!(subscription.next_event(&cx).await, Err(TaskError::Protocol(ManagedTasksError::Closed))));
                        };
                        pair(server, application).await;
                        assert_eq!(peer.rpcs.load(Ordering::SeqCst), 2);
                        healthy_listen(&peer, &tasks, &cx, 3, "access-one", 1).await;
                    }
                    SubCase::Cancel | SubCase::Close | SubCase::Abandon | SubCase::Expiry | SubCase::Deadline => {
                        let cancellation = McpRequestCancellation::new();
                        let server = async {
                            let mut tls = stream(&peer, 1, "access-one", &selected()).await;
                            event(&mut tls, &ack(2, &selected()), false).await;
                            closed(tls).await;
                        };
                        let application = async {
                            let timeout = if matches!(case, SubCase::Deadline) { Duration::from_secs(1) } else { Duration::from_secs(15) };
                            let limits = ClientCredentialsSubscriptionLimits::new(65536, 65536, 16, timeout).unwrap();
                            let mut subscription = tasks.subscribe_with_cancellation(&cx, &cancellation,
                                RequestId::Number(1), RequestId::Number(2), selected(), limits).await.unwrap();
                            receive_ack(&mut subscription, &cx, &selected()).await;
                            let mut reading = Box::pin(subscription.next_event(&cx));
                            poll_fn(|task| { assert!(reading.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
                            if matches!(case, SubCase::Abandon) { drop(reading); }
                            else {
                                match case { SubCase::Cancel => { cancellation.cancel(); }, SubCase::Close => client.close(), _ => {} }
                                let error = reading.await.err().unwrap();
                                match case {
                                    SubCase::Cancel => assert!(matches!(error, TaskError::Authentication(Error::Discovery(OAuthDiscoveryError::Cancelled)))),
                                    SubCase::Close => assert!(matches!(error, TaskError::Authentication(Error::Closed))),
                                    SubCase::Deadline => assert!(matches!(error, TaskError::Authentication(Error::Discovery(OAuthDiscoveryError::TimedOut)))),
                                    _ => assert!(matches!(error, TaskError::Authentication(Error::Expired | Error::Discovery(OAuthDiscoveryError::TimedOut)))),
                                }
                            }
                            assert!(matches!(subscription.next_event(&cx).await, Err(TaskError::Protocol(ManagedTasksError::Closed))));
                            assert!(cx.checkpoint().is_ok());
                        };
                        pair(server, application).await;
                        assert_eq!(peer.rpcs.load(Ordering::SeqCst), 2, "local interruption sends no tasks/cancel");
                        if matches!(case, SubCase::Cancel | SubCase::Abandon | SubCase::Deadline) {
                            healthy_listen(&peer, &tasks, &cx, 3, "access-one", 1).await;
                        }
                    }
                    SubCase::RecordLimit => {
                        let server = async {
                            let mut tls = stream(&peer, 1, "access-one", &selected()).await;
                            event(&mut tls, &ack(2, &selected()), false).await;
                            event(&mut tls, &task_notice(2, "machine-task", "working"), false).await;
                            closed(tls).await;
                        };
                        let application = async {
                            let limits = ClientCredentialsSubscriptionLimits::new(65536, 65536, 2, Duration::from_secs(15)).unwrap();
                            let mut subscription = tasks.subscribe(&cx, RequestId::Number(1), RequestId::Number(2), selected(), limits).await.unwrap();
                            receive_ack(&mut subscription, &cx, &selected()).await;
                            assert!(matches!(subscription.next_event(&cx).await.unwrap(), Some(ListenEvent::TaskNotification(_))));
                            assert!(matches!(subscription.next_event(&cx).await, Err(TaskError::Protocol(ManagedTasksError::RecordLimit))));
                            assert!(matches!(subscription.next_event(&cx).await, Err(TaskError::Protocol(ManagedTasksError::Closed))));
                        };
                        pair(server, application).await;
                        assert_eq!(peer.rpcs.load(Ordering::SeqCst), 2);
                    }
                    SubCase::Renewal => {
                        let server = async {
                            let mut tls = stream(&peer, 1, "access-one", &selected()).await;
                            event(&mut tls, &ack(2, &selected()), false).await;
                            peer.grant("access-two", 300).await;
                            closed(tls).await;
                        };
                        let application = async {
                            let mut subscription = open(&tasks, &cx, 1).await;
                            receive_ack(&mut subscription, &cx, &selected()).await;
                            Sleep::new(cx.now().saturating_add_nanos(3_100_000_000)).await;
                            assert_eq!(client.credential(&cx).await.unwrap().generation(), 2);
                            assert_eq!(subscription.credential_generation(), 1);
                            assert!(matches!(subscription.next_event(&cx).await, Err(TaskError::Authentication(Error::Expired))));
                            assert!(matches!(subscription.next_event(&cx).await, Err(TaskError::Protocol(ManagedTasksError::Closed))));
                        };
                        pair(server, application).await;
                        healthy_listen(&peer, &tasks, &cx, 3, "access-two", 2).await;
                        assert_eq!(peer.grants.load(Ordering::SeqCst), 2);
                        assert_eq!(peer.rpcs.load(Ordering::SeqCst), 4);
                    }
                    SubCase::Denied | SubCase::Redirect | SubCase::LostListen => {
                        let server = async {
                            discover(&peer, 1, "access-one", &discovery()).await;
                            let (mut tls, _) = rpc(&peer, 2, "subscriptions/listen", "access-one").await;
                            let head = match case {
                                SubCase::Denied => "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n",
                                SubCase::Redirect => "HTTP/1.1 307 Temporary Redirect\r\nLocation: https://127.0.0.1:9/forbidden\r\nContent-Length: 0\r\n\r\n",
                                _ => return,
                            };
                            tls.write_all(head.as_bytes()).await.unwrap();
                            tls.flush().await.unwrap();
                        };
                        let (_, response) = pair(server, tasks.subscribe(&cx, RequestId::Number(1),
                            RequestId::Number(2), selected(), ClientCredentialsSubscriptionLimits::default())).await;
                        let error = response.err().unwrap();
                        match case {
                            SubCase::Denied => assert!(matches!(error, TaskError::Protocol(ManagedTasksError::HttpStatus { status:401 }))),
                            SubCase::Redirect => assert!(matches!(error, TaskError::Protocol(ManagedTasksError::HttpStatus { status:307 }))),
                            _ => assert!(matches!(error, TaskError::Authentication(Error::Transport))),
                        }
                        assert_eq!(peer.rpcs.load(Ordering::SeqCst), 2);
                        peer.quiet();
                        healthy_listen(&peer, &tasks, &cx, 3, "access-one", 1).await;
                    }
                    SubCase::NarrowedAck => {
                        let mut requested = selected();
                        requested.additional.insert("taskIds".to_owned(), json!(["machine-task", "other-task"]));
                        let server = async {
                            let mut tls = stream(&peer, 1, "access-one", &requested).await;
                            event(&mut tls, &ack(2, &selected()), false).await;
                            event(&mut tls, &terminal_listen(2), true).await;
                        };
                        let application = async {
                            let mut subscription = tasks.subscribe(&cx, RequestId::Number(1), RequestId::Number(2),
                                requested.clone(), ClientCredentialsSubscriptionLimits::default()).await.unwrap();
                            receive_ack(&mut subscription, &cx, &selected()).await;
                            assert_eq!(task_subscription_ids(subscription.accepted_filter().unwrap()).unwrap().unwrap(), vec![task_id()]);
                            receive_terminal(&mut subscription, &cx, 2).await;
                        };
                        pair(server, application).await;
                    }
                    SubCase::Preflight => unreachable!(),
                }
                assert!(cx.checkpoint().is_ok());
                if !matches!(case, SubCase::Renewal) { assert_eq!(peer.grants.load(Ordering::SeqCst), 1); }
                peer.quiet();
                client.close();
            });
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(20_000_000_000), scenario)
                .await.expect("machine subscription must settle within its caller-owned bound");
        }));
}

#[test]
fn machine_subscriptions_deliver_live_task_catalog_and_resource_events() { isolated_subscription("tasks::subscriptions::machine_subscriptions_deliver_live_task_catalog_and_resource_events", SubCase::Live); }
#[test]
fn missing_tasks_advertisement_prevents_the_listen_post() { isolated_subscription("tasks::subscriptions::missing_tasks_advertisement_prevents_the_listen_post", SubCase::MissingTasks); }
#[test]
fn missing_auth_advertisement_prevents_the_listen_post() { isolated_subscription("tasks::subscriptions::missing_auth_advertisement_prevents_the_listen_post", SubCase::MissingAuth); }
#[test]
fn foreign_ack_identity_does_not_publish_filter_state() { isolated_subscription("tasks::subscriptions::foreign_ack_identity_does_not_publish_filter_state", SubCase::WrongAck); }
#[test]
fn widened_ack_does_not_publish_filter_state() { isolated_subscription("tasks::subscriptions::widened_ack_does_not_publish_filter_state", SubCase::WidenedAck); }
#[test]
fn task_event_before_ack_is_not_delivered() { isolated_subscription("tasks::subscriptions::task_event_before_ack_is_not_delivered", SubCase::BeforeAck); }
#[test]
fn unselected_task_event_closes_only_its_listen() { isolated_subscription("tasks::subscriptions::unselected_task_event_closes_only_its_listen", SubCase::WrongTask); }
#[test]
fn task_event_requires_the_opening_subscription_identity() { isolated_subscription("tasks::subscriptions::task_event_requires_the_opening_subscription_identity", SubCase::WrongSubscription); }
#[test]
fn unselected_resource_event_closes_only_its_listen() { isolated_subscription("tasks::subscriptions::unselected_resource_event_closes_only_its_listen", SubCase::WrongResource); }
#[test]
fn duplicate_ack_cannot_replace_the_accepted_filter() { isolated_subscription("tasks::subscriptions::duplicate_ack_cannot_replace_the_accepted_filter", SubCase::DuplicateAck); }
#[test]
fn clean_http_eof_without_a_listen_terminal_is_failure() { isolated_subscription("tasks::subscriptions::clean_http_eof_without_a_listen_terminal_is_failure", SubCase::Truncated); }
#[test]
fn subscription_errors_never_expose_peer_secrets() { isolated_subscription("tasks::subscriptions::subscription_errors_never_expose_peer_secrets", SubCase::RemoteError); }
#[test]
fn idle_listen_cancellation_is_local_and_does_not_cancel_tasks() { isolated_subscription("tasks::subscriptions::idle_listen_cancellation_is_local_and_does_not_cancel_tasks", SubCase::Cancel); }
#[test]
fn machine_owner_close_wakes_an_idle_subscription() { isolated_subscription("tasks::subscriptions::machine_owner_close_wakes_an_idle_subscription", SubCase::Close); }
#[test]
fn abandoned_subscription_read_releases_its_socket_and_parser() { isolated_subscription("tasks::subscriptions::abandoned_subscription_read_releases_its_socket_and_parser", SubCase::Abandon); }
#[test]
fn subscription_cannot_outlive_its_opening_access_token() { isolated_subscription("tasks::subscriptions::subscription_cannot_outlive_its_opening_access_token", SubCase::Expiry); }
#[test]
fn subscription_deadline_fires_without_peer_activity() { isolated_subscription("tasks::subscriptions::subscription_deadline_fires_without_peer_activity", SubCase::Deadline); }
#[test]
fn record_budget_closes_without_polling_or_reconnecting() { isolated_subscription("tasks::subscriptions::record_budget_closes_without_polling_or_reconnecting", SubCase::RecordLimit); }
#[test]
fn renewed_machine_token_cannot_extend_an_existing_subscription() { isolated_subscription("tasks::subscriptions::renewed_machine_token_cannot_extend_an_existing_subscription", SubCase::Renewal); }
#[test]
fn invalid_and_cancelled_subscription_requests_have_no_grant_effect() { isolated_subscription("tasks::subscriptions::invalid_and_cancelled_subscription_requests_have_no_grant_effect", SubCase::Preflight); }
#[test]
fn unauthorized_listen_is_not_replayed_with_a_new_token() { isolated_subscription("tasks::subscriptions::unauthorized_listen_is_not_replayed_with_a_new_token", SubCase::Denied); }
#[test]
fn listen_redirect_is_not_followed() { isolated_subscription("tasks::subscriptions::listen_redirect_is_not_followed", SubCase::Redirect); }
#[test]
fn lost_listen_response_does_not_trigger_reconnection() { isolated_subscription("tasks::subscriptions::lost_listen_response_does_not_trigger_reconnection", SubCase::LostListen); }
#[test]
fn narrowed_ack_exposes_only_the_actually_watched_selection() { isolated_subscription("tasks::subscriptions::narrowed_ack_exposes_only_the_actually_watched_selection", SubCase::NarrowedAck); }
