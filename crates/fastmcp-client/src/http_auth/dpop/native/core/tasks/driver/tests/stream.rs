//! Accounting and preflight coverage for the shared streamed lifecycle driver.
//! EOF/transport authority is tested separately through the real TLS entry point.

use super::*;
use crate::http_auth::dpop::native::core::stream::{StreamDecoder, StreamEvent};
use crate::http_auth::dpop::native::core::tasks::stream::{TaskStreamDecoder, progress_marker};

fn stream_metadata() -> FinalRequestMeta {
    let mut value = serde_json::to_value(metadata()).unwrap();
    value["progressToken"] = json!("owned");
    serde_json::from_value(value).unwrap()
}

fn stream_decoder(run: &mut Run, limits: ManagedCoreLimits) -> (RequestId, TaskStreamDecoder) {
    let prepared = run.prepare(TARGET, stream_metadata(), get(), limits, 8192).unwrap();
    let marker = progress_marker(&prepared.operation_wire, limits.request_bytes()).unwrap();
    let admitted = admit(run, prepared);
    let id = admitted.id.clone();
    let (_, decoder) = TaskStreamDecoder::with_usage(
        admitted, limits, run.stream_usage(limits).unwrap(), marker,
    ).unwrap();
    (id, decoder)
}

fn notification() -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0","method":"notifications/progress",
        "params":{"progressToken":"owned","progress":1}})).unwrap()
}

fn result(id: &RequestId) -> Vec<u8> {
    let mut result = serde_json::to_value(task("working")).unwrap();
    result["resultType"] = json!("complete");
    response(id, result).body
}

#[test]
fn notifications_and_discovery_bytes_are_carried_into_every_new_decoder() {
    let limits = ManagedCoreLimits::new(8192, 8192, 32768, 1, Duration::from_secs(10)).unwrap();
    let mut run = Run::new("stream", ManagedTaskDriverPolicy::default(), limits).unwrap();
    let (id, mut decoder) = stream_decoder(&mut run, limits);
    let first_discovery = decoder.usage().0;
    let progress = notification();
    let terminal = result(&id);
    assert!(matches!(decoder.admit(&progress, true).unwrap(), StreamEvent::Notification(_)));
    assert!(matches!(decoder.admit(&terminal, true).unwrap(), StreamEvent::Result(_)));
    let first_usage = (first_discovery + progress.len() + terminal.len(), 1);
    assert_eq!(decoder.usage(), first_usage);
    run.complete_stream(first_usage, limits).unwrap();
    assert_eq!(run.stream_usage(limits).unwrap(), first_usage);

    let (id, mut next) = stream_decoder(&mut run, limits);
    let before = next.usage();
    assert!(before.0 > first_usage.0, "the second discovery also consumes the run budget");
    assert_eq!(before.1, 1);
    assert!(matches!(next.admit(&progress, true),
        Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::NotificationLimit)))));
    assert_eq!(next.usage(), before);
    let terminal = result(&id);
    assert!(matches!(next.admit(&terminal, false).unwrap(), StreamEvent::Result(_)),
        "exhausting notifications does not forbid a JSON terminal");
    run.complete_stream(next.usage(), limits).unwrap();
    assert_eq!(run.stream_usage(limits).unwrap(), (before.0 + terminal.len(), 1));
}

#[test]
fn invalid_completion_usage_cannot_refill_either_quota_or_partially_commit() {
    let limits = ManagedCoreLimits::new(8192, 8192, 32768, 4, Duration::from_secs(10)).unwrap();
    let mut run = Run::new("stream", ManagedTaskDriverPolicy::default(), limits).unwrap();
    run.complete_stream((100, 2), limits).unwrap();
    let before = (run.remaining_bytes, run.notifications);
    for usage in [(99, 2), (100, 1), (32769, 2), (101, 5)] {
        assert!(run.complete_stream(usage, limits).is_err());
        assert_eq!((run.remaining_bytes, run.notifications), before);
    }
    run.complete_stream((32768, 4), limits).unwrap();
    assert_eq!((run.remaining_bytes, run.notifications), (0, 4));
    assert!(run.prepare(TARGET, stream_metadata(), get(), limits, 8192).is_err());
}

#[test]
fn resumed_decoder_refuses_exhausted_payload_or_overdrawn_notification_seeds() {
    let limits = ManagedCoreLimits::new(8192, 8192, 32768, 1, Duration::from_secs(10)).unwrap();
    for usage in [(32768, 0), (32769, 0), (100, 2)] {
        let mut run = Run::new("stream", ManagedTaskDriverPolicy::default(), limits).unwrap();
        let prepared = prepare(&mut run, get(), limits);
        let admitted = admit(&mut run, prepared);
        assert!(TaskStreamDecoder::with_usage(admitted, limits, usage, None).is_err());
    }
}

#[test]
fn precancelled_streamed_driver_never_invokes_any_host_callback() {
    for cancel_cx in [false, true] {
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        if cancel_cx { cx.set_cancel_requested(true); } else { cancellation.cancel(); }
        let (mut client, credential) = client();
        let mut drive = Box::pin(client.drive_task_with_events(
            &cx, &cancellation, &credential, stream_metadata(),
            TaskId::parse("task-one").unwrap(), "stream", ManagedTaskDriverPolicy::default(),
            DpopStreamLimits::default(),
            |_| {
                panic!("cancelled driver invoked resolver");
                #[allow(unreachable_code)]
                std::future::ready(Ok(ManagedTaskInputAction::ReturnToCaller))
            },
            |_| panic!("cancelled driver invoked snapshot observer"),
            |_| panic!("cancelled driver invoked notification observer"),
        ));
        assert!(matches!(drive.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(DpopTaskDriverError::Task(DpopTasksError::Core(
                DpopCoreError::Transport(DpopHttpError::Cancelled)))))));
    }
}
