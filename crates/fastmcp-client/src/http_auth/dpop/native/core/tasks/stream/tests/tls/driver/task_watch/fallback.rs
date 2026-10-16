use super::*;
use crate::http_auth::dpop::native::core::stream::task_subscription::watch::input::{
    DpopTaskWatchDriverPolicy, ManagedTaskInputAction,
};

fn fallback_policy(
    snapshots: usize,
    polls: usize,
    interval: Duration,
) -> DpopTaskWatchPolicy {
    DpopTaskWatchPolicy::new(snapshots).unwrap()
        .with_polling_fallback(polls, interval).unwrap()
}

fn fallback_limits(timeout: Duration) -> DpopStreamLimits {
    DpopStreamLimits::new(
        ManagedCoreLimits::new(8192, 8192, 65536, 8, timeout).unwrap(),
        timeout,
    ).unwrap()
}

fn fallback_input_task(keys: &[&str]) -> Value {
    let mut task = task_result("input_required");
    task["inputRequests"] = Value::Object(
        keys.iter()
            .map(|key| ((*key).to_owned(), json!({"method":"roots/list"})))
            .collect(),
    );
    task
}

async fn fallback_get_reply(
    peer: &mut Peer,
    prefix: &str,
    index: usize,
    result: &Value,
) {
    let mut socket = peer.wait_round(prefix, index).await;
    json_reply(
        &mut socket,
        &wait_response(prefix, index, false, result),
    ).await;
}

async fn finish_listen(prefix: &str, listen: &mut TlsStream<TcpStream>) {
    let mut end = event_chunk(&watch_terminal(prefix));
    end.extend_from_slice(b"0\r\n\r\n");
    listen.write_all(&end).await.unwrap();
    let _ = listen.shutdown().await;
}

#[test]
fn fallback_recovers_terminal_state_after_clean_subscription_end() {
    run(async {
        let cx = Cx::current().unwrap();
        let (mut peer, mut client, credential) = Peer::new().await;
        let cancellation = McpRequestCancellation::new();
        let application = client.watch_task_with_cancellation(
            &cx, &cancellation, &credential, driver_metadata(),
            TaskId::parse("task-one").unwrap(), "fallback",
            fallback_policy(4, 1, Duration::from_millis(1)), watch_limits(8),
        );
        let server = async {
            peer.watch_snapshot_reply("fallback", 0, "working").await;
            let mut listen = peer.watch_listen("fallback").await;
            listen.write_all(HEAD).await.unwrap();
            event(&mut listen, &watch_ack("fallback", true)).await;
            peer.watch_snapshot_reply("fallback", 1, "working").await;
            finish_listen("fallback", &mut listen).await;
            peer.watch_snapshot_reply("fallback", 2, "working").await;
            peer.watch_snapshot_reply("fallback", 3, "cancelled").await;
        };
        let (result, ()) = pair(application, server).await;
        assert!(matches!(
            result.unwrap(),
            DpopTaskWaitOutcome::Terminal(snapshot)
                if matches!(snapshot.task, Task::Cancelled(_))
        ));
        peer.no_extra(5);
        assert!(cx.checkpoint().is_ok());
        assert!(!client.revocation_handle().is_revoked());
    });
}

#[test]
fn fallback_and_snapshot_limits_stop_without_hidden_extra_gets() {
    for snapshot_limited in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let snapshots = if snapshot_limited { 3 } else { 5 };
            let application = client.watch_task_with_cancellation(
                &cx, &cancellation, &credential, driver_metadata(),
                TaskId::parse("task-one").unwrap(), "bounded",
                fallback_policy(snapshots, 1, Duration::from_millis(1)), watch_limits(8),
            );
            let server = async {
                peer.watch_snapshot_reply("bounded", 0, "working").await;
                let mut listen = peer.watch_listen("bounded").await;
                listen.write_all(HEAD).await.unwrap();
                event(&mut listen, &watch_ack("bounded", true)).await;
                peer.watch_snapshot_reply("bounded", 1, "working").await;
                finish_listen("bounded", &mut listen).await;
                peer.watch_snapshot_reply("bounded", 2, "working").await;
                if !snapshot_limited {
                    peer.watch_snapshot_reply("bounded", 3, "working").await;
                }
            };
            let (result, ()) = pair(application, server).await;
            if snapshot_limited {
                assert!(matches!(result, Err(DpopTaskWatchError::SnapshotLimit)));
                peer.no_extra(4);
            } else {
                assert!(matches!(result, Err(DpopTaskWatchError::FallbackLimit)));
                peer.no_extra(5);
            }
            assert!(cx.checkpoint().is_ok());
        });
    }
}

#[test]
fn fallback_honors_peer_poll_hint_and_original_deadline() {
    run(async {
        let cx = Cx::current().unwrap();
        let (mut peer, mut client, credential) = Peer::new().await;
        let cancellation = McpRequestCancellation::new();
        let application = client.watch_task_with_cancellation(
            &cx, &cancellation, &credential, driver_metadata(),
            TaskId::parse("task-one").unwrap(), "hint",
            fallback_policy(5, 2, Duration::from_millis(1)),
            fallback_limits(Duration::from_secs(2)),
        );
        let server = async {
            peer.watch_snapshot_reply("hint", 0, "working").await;
            let mut listen = peer.watch_listen("hint").await;
            listen.write_all(HEAD).await.unwrap();
            event(&mut listen, &watch_ack("hint", true)).await;
            peer.watch_snapshot_reply("hint", 1, "working").await;
            finish_listen("hint", &mut listen).await;
            let mut task = task_result("working");
            task["pollIntervalMs"] = json!(60000);
            fallback_get_reply(&mut peer, "hint", 2, &task).await;
            asupersync::time::Sleep::new(
                cx.now().saturating_add_nanos(3_000_000_000),
            ).await;
            peer.no_extra(4);
        };
        let (result, ()) = pair(application, server).await;
        assert!(matches!(
            result,
            Err(DpopTaskWatchError::Stream(DpopStreamError::Core(
                DpopCoreError::Transport(DpopHttpError::TimedOut)
            )))
        ));
        assert!(cx.checkpoint().is_ok());
    });
}

#[test]
fn cancellation_wakes_fallback_sleep_without_dispatching_a_poll() {
    run(async {
        let cx = Cx::current().unwrap();
        let (mut peer, mut client, credential) = Peer::new().await;
        let cancellation = McpRequestCancellation::new();
        let application = client.watch_task_with_cancellation(
            &cx, &cancellation, &credential, driver_metadata(),
            TaskId::parse("task-one").unwrap(), "cancel-fallback",
            fallback_policy(5, 2, Duration::from_millis(1)), watch_limits(8),
        );
        let server = async {
            peer.watch_snapshot_reply("cancel-fallback", 0, "working").await;
            let mut listen = peer.watch_listen("cancel-fallback").await;
            listen.write_all(HEAD).await.unwrap();
            event(&mut listen, &watch_ack("cancel-fallback", true)).await;
            peer.watch_snapshot_reply("cancel-fallback", 1, "working").await;
            finish_listen("cancel-fallback", &mut listen).await;
            let mut task = task_result("working");
            task["pollIntervalMs"] = json!(60000);
            fallback_get_reply(&mut peer, "cancel-fallback", 2, &task).await;
            cancellation.cancel();
        };
        let (result, ()) = pair(application, server).await;
        assert!(matches!(
            result,
            Err(DpopTaskWatchError::Stream(DpopStreamError::Core(
                DpopCoreError::Transport(DpopHttpError::Cancelled)
            )))
        ));
        peer.no_extra(4);
        assert!(cx.checkpoint().is_ok());
        assert!(!client.revocation_handle().is_revoked());
    });
}

#[test]
fn fallback_never_restores_task_input_update_authority_after_teardown() {
    run(async {
        let cx = Cx::current().unwrap();
        let (mut peer, mut client, credential) = Peer::new().await;
        let cancellation = McpRequestCancellation::new();
        let policy = DpopTaskWatchDriverPolicy::new(
            5, 2, 4, 8192, Duration::from_secs(10),
        ).unwrap()
            .with_polling_fallback(1, Duration::from_millis(1)).unwrap();
        let application = client.drive_task_with_subscription(
            &cx, &cancellation, &credential, driver_metadata(),
            TaskId::parse("task-one").unwrap(), "input-fallback",
            policy, watch_limits(8),
            |_| {
                panic!("fallback after teardown must not resolve Task input");
                #[allow(unreachable_code)]
                std::future::ready(Ok(ManagedTaskInputAction::ReturnToCaller))
            },
            |_| Ok(()),
        );
        let server = async {
            peer.watch_snapshot_reply("input-fallback", 0, "working").await;
            let mut listen = peer.watch_listen("input-fallback").await;
            listen.write_all(HEAD).await.unwrap();
            event(&mut listen, &watch_ack("input-fallback", true)).await;
            peer.watch_snapshot_reply("input-fallback", 1, "working").await;
            finish_listen("input-fallback", &mut listen).await;
            peer.watch_snapshot_reply("input-fallback", 2, "working").await;
            let input = fallback_input_task(&["one"]);
            fallback_get_reply(&mut peer, "input-fallback", 3, &input).await;
        };
        let (result, ()) = pair(application, server).await;
        assert!(matches!(result.unwrap(), DpopTaskWaitOutcome::InputRequired(_)));
        peer.no_extra(5);
        assert!(cx.checkpoint().is_ok());
    });
}
