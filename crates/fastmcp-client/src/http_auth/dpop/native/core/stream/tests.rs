//! Deterministic parser, observer and lifetime tests; TLS cases live below.

use super::*;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Instant;

use asupersync::http::body::Frame;
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::{TimerDriverHandle, VirtualClock};
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::dpop::DpopKey;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{ClientCapabilities, FinalCoreResult, FinalRequestMeta};
use serde_json::json;

#[cfg(feature = "native-tls-roots")]
mod tls;

const COMPLETE: &str = r#"{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private","x-exact":{"z":900719925474099312345,"a":1.20e+4,"text":"雪"}}}"#;
const CHANGE: &str = r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;

fn request() -> CoreRequest {
    let mut params = json!({"_meta": FinalRequestMeta::new(ClientCapabilities::default())});
    params["_meta"]["progressToken"] = json!("owned");
    CoreRequest::decode(ProtocolEra::Modern2026, "tools/list", Some(&params)).unwrap()
}

fn limits() -> DpopStreamLimits {
    DpopStreamLimits::new(
        ManagedCoreLimits::new(8192, 8192, 32768, 16, Duration::from_secs(60)).unwrap(),
        Duration::from_secs(10),
    ).unwrap()
}

fn reader(kind: ModernHttpResponseKind, limits: DpopStreamLimits, wire: usize) -> Reader {
    Reader::new(
        kind,
        CoreDecoder::for_request(request(), RequestId::Number(7), limits.core).unwrap(),
        limits,
        wire,
    ).unwrap()
}

fn event(json: &str) -> String {
    format!("data: {json}\r\n\r\n")
}

fn fixture(f: impl FnOnce(&Lifetime<'_>, &TimerDriverHandle, &Arc<VirtualClock>)) {
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .with_timer_driver(timer.clone())
        .build().unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    let token_endpoint = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
    let session = DpopSession::new(
        DpopKey::generate().unwrap(),
        token_endpoint.clone(),
        CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap(),
    ).unwrap();
    let credential = session.admit_token_response(
        &token_endpoint, 200,
        br#"{"access_token":"stream-token","token_type":"DPoP","expires_in":300}"#,
        Instant::now(), Duration::from_secs(300),
    ).unwrap();
    let cancellation = McpRequestCancellation::new();
    let bounds = WaitBounds::new(&cx, Duration::from_secs(60), &credential).unwrap();
    let lifetime = Lifetime { cx: &cx, cancellation: &cancellation, session: &session, credential: &credential, bounds };
    with_caller(&cx, || f(&lifetime, &timer, &clock));
    assert_eq!(timer.pending_count(), 0);
    drop(cx);
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn streaming_configuration_requires_finite_independent_bounds() {
    let core = limits().core;
    for idle in [Duration::ZERO, Duration::from_secs(61)] {
        assert!(matches!(DpopStreamLimits::new(core, idle), Err(DpopStreamError::InvalidLimits)));
    }
    assert!(DpopStreamLimits::new(core, Duration::from_secs(60)).is_ok());
    for sse in [
        SseLimits::with_data_lines(1024 * 1024 + 1, 8192, 1, 1).unwrap(),
        SseLimits::with_data_lines(1, 8 * 1024 * 1024 + 1, 1, 1).unwrap(),
        SseLimits::with_data_lines(1, 8192, 65_537, 1).unwrap(),
        SseLimits::new(1, 8192, 1).unwrap(),
    ] {
        assert!(matches!(limits().with_sse_limits(sse), Err(DpopStreamError::InvalidLimits)));
    }
}

#[test]
fn notifications_are_incremental_and_every_byte_split_preserves_exact_terminal() {
    fixture(|life, _, _| {
        let first = event(CHANGE);
        let final_event = event(COMPLETE);
        let wire = format!("\u{feff}: heartbeat\r\n{first}{final_event}");
        for split in 0..=wire.len() {
            let mut reader = reader(ModernHttpResponseKind::Sse, limits(), wire.len());
            let mut idle = Idle::new(life.cx.now(), limits().idle);
            let mut calls = 0;
            let mut observer = |_: &ServerNotification| { calls += 1; true };
            reader.push(&wire.as_bytes()[..split], life, &mut idle, &mut observer).unwrap();
            reader.push(&wire.as_bytes()[split..], life, &mut idle, &mut observer).unwrap();
            assert_eq!(calls, 1);
            let encoded = reader.finish(life, &idle).unwrap().result.encode().unwrap();
            assert!(encoded.contains("900719925474099312345"));
            assert!(encoded.contains("1.20e+4"));
            assert!(encoded.find("\"z\"").unwrap() < encoded.find("\"a\"").unwrap());
        }
        let mut reader = reader(ModernHttpResponseKind::Sse, limits(), 32768);
        let mut idle = Idle::new(life.cx.now(), limits().idle);
        let mut seen = 0;
        reader.push(first.as_bytes(), life, &mut idle, &mut |_| { seen += 1; true }).unwrap();
        assert_eq!(seen, 1, "notification must be delivered before terminal bytes exist");
        assert!(reader.terminal.is_none());
        reader.push(final_event.as_bytes(), life, &mut idle, &mut |_| true).unwrap();
        assert!(reader.terminal.is_some(), "terminal remains owned until EOF admission");
        reader.finish(life, &idle).unwrap();
    });
}

#[test]
fn second_terminal_or_late_notification_rejects_the_unpublished_first_result() {
    fixture(|life, _, _| {
        for later in [event(COMPLETE), event(CHANGE)] {
            let wire = format!("{}{later}", event(COMPLETE));
            for split in 0..=wire.len() {
                let mut reader = reader(ModernHttpResponseKind::Sse, limits(), 32768);
                let mut idle = Idle::new(life.cx.now(), limits().idle);
                let mut notifications = 0;
                let mut observe = |_: &ServerNotification| { notifications += 1; true };
                let result = reader.push(&wire.as_bytes()[..split], life, &mut idle, &mut observe)
                    .and_then(|()| reader.push(&wire.as_bytes()[split..], life, &mut idle, &mut observe));
                assert!(matches!(result, Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::InvalidResponse)))));
                assert_eq!(notifications, 0);
            }
        }
    });
}

#[test]
fn incomplete_sse_tail_never_turns_an_earlier_result_into_success() {
    fixture(|life, _, _| {
        for tail in ["data: {}\n", ": unterminated", "data:", "unknown: unfinished"] {
            let mut reader = reader(ModernHttpResponseKind::Sse, limits(), 32768);
            let mut idle = Idle::new(life.cx.now(), limits().idle);
            reader.push(format!("{}{tail}", event(COMPLETE)).as_bytes(), life, &mut idle, &mut |_| true).unwrap();
            assert!(matches!(reader.finish(life, &idle), Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::InvalidResponse)))));
        }
        let reader = reader(ModernHttpResponseKind::Sse, limits(), 32768);
        let idle = Idle::new(life.cx.now(), limits().idle);
        assert!(matches!(reader.finish(life, &idle), Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::MissingTerminal)))));
    });
}

fn progress(token: &str, number: &str) -> String {
    event(&format!(r#"{{"jsonrpc":"2.0","method":"notifications/progress","params":{{"progressToken":{token},"progress":{number}}}}}"#))
}

#[test]
fn only_admitted_matching_progress_resets_idle_and_never_the_absolute_bound() {
    fixture(|life, _, clock| {
        let fixed = limits().with_progress_idle_reset(false);
        let mut reader = reader(ModernHttpResponseKind::Sse, fixed, 32768);
        let mut idle = Idle::new(life.cx.now(), fixed.idle);
        let before = idle.deadline;
        clock.advance(9_000_000_000);
        reader.push(progress("\"owned\"", "1").as_bytes(), life, &mut idle, &mut |_| true).unwrap();
        assert_eq!(idle.deadline, before);
        clock.advance(1_000_000_000);
        assert!(matches!(
            reader.push(progress("\"owned\"", "2").as_bytes(), life, &mut idle, &mut |_| true),
            Err(DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::TimedOut)))
        ));
        assert_eq!(idle.deadline, before);
    });
    fixture(|life, _, clock| {
        let mut reader = reader(ModernHttpResponseKind::Sse, limits(), 32768);
        let mut idle = Idle::new(life.cx.now(), limits().idle);
        let original = idle.deadline;
        clock.advance(9_000_000_000);
        reader.push(format!(": alive\n\n{}", event(CHANGE)).as_bytes(), life, &mut idle, &mut |_| true).unwrap();
        assert_eq!(idle.deadline, original);
        reader.push(progress("\"owned\"", "900719925474099312345").as_bytes(), life, &mut idle, &mut |_| true).unwrap();
        assert_eq!(idle.deadline.as_nanos(), 19_000_000_000);
        clock.advance(9_000_000_000);
        reader.push(progress("\"owned\"", "900719925474099312346").as_bytes(), life, &mut idle, &mut |_| true).unwrap();
        assert_eq!(idle.deadline.as_nanos(), 28_000_000_000);
        assert_eq!(life.bounds.deadline.as_nanos(), 60_000_000_000);
        idle.progress(Time::from_nanos(59_000_000_000));
        assert_eq!(idle.bounds(life.bounds).deadline, life.bounds.deadline);
    });
    for (token, value) in [("\"foreign\"", "2"), ("7", "2"), ("\"owned\"", "1")] {
        fixture(|life, _, clock| {
            let mut reader = reader(ModernHttpResponseKind::Sse, limits(), 32768);
            let mut idle = Idle::new(life.cx.now(), limits().idle);
            reader.push(progress("\"owned\"", "1").as_bytes(), life, &mut idle, &mut |_| true).unwrap();
            clock.advance(9_000_000_000);
            let before = idle.deadline;
            assert!(matches!(reader.push(progress(token, value).as_bytes(), life, &mut idle, &mut |_| true),
                Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::InvalidProgress)))));
            assert_eq!(idle.deadline, before);
        });
    }
}

#[test]
fn observer_stop_panic_and_same_poll_revocation_prevent_later_callbacks() {
    for action in 0..5 {
        fixture(|life, _, _| {
            let wire = format!("{}{}{}", event(CHANGE), event(CHANGE), event(COMPLETE));
            let mut reader = reader(ModernHttpResponseKind::Sse, limits(), 32768);
            let mut idle = Idle::new(life.cx.now(), limits().idle);
            let mut calls = 0;
            let result = reader.push(wire.as_bytes(), life, &mut idle, &mut |_| {
                calls += 1;
                match action {
                    0 => return false,
                    1 => panic!("observer-private-canary"),
                    2 => { life.cancellation.cancel(); }
                    3 => life.credential.revoke(),
                    _ => life.session.revoke(),
                }
                true
            });
            let error = result.unwrap_err();
            assert_eq!(calls, 1);
            assert!(!format!("{error:?} {error}").contains("observer-private-canary"));
            match action {
                0 => assert!(matches!(error, DpopStreamError::ObserverStopped)),
                1 => assert!(matches!(error, DpopStreamError::ObserverPanicked)),
                _ => assert!(matches!(error, DpopStreamError::Core(DpopCoreError::Transport(_)))),
            }
        });
    }
}

#[test]
fn wire_and_payload_budgets_are_cumulative_and_chunk_invariant() {
    fixture(|life, _, _| {
        let wire = format!("{}{}", event(CHANGE), event(COMPLETE));
        let core = ManagedCoreLimits::new(8192, COMPLETE.len(), COMPLETE.len() + CHANGE.len(), 1, Duration::from_secs(60)).unwrap();
        let exact = DpopStreamLimits::new(core, Duration::from_secs(10)).unwrap();
        for split in 0..=wire.len() {
            let mut reader = reader(ModernHttpResponseKind::Sse, exact, wire.len() - 1);
            let mut idle = Idle::new(life.cx.now(), exact.idle);
            let mut seen = 0;
            let mut observe = |_: &ServerNotification| { seen += 1; true };
            let result = reader.push(&wire.as_bytes()[..split], life, &mut idle, &mut observe)
                .and_then(|()| reader.push(&wire.as_bytes()[split..], life, &mut idle, &mut observe));
            assert!(matches!(result, Err(DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::BodyTooLarge)))));
            assert_eq!(seen, 1);
        }
        let mut reader = reader(ModernHttpResponseKind::Sse, exact, wire.len());
        let mut idle = Idle::new(life.cx.now(), exact.idle);
        reader.push(wire.as_bytes(), life, &mut idle, &mut |_| true).unwrap();
        assert_eq!(reader.decoder.usage(), (COMPLETE.len() + CHANGE.len(), 1));
        reader.finish(life, &idle).unwrap();
        let too_small = DpopStreamLimits::new(
            ManagedCoreLimits::new(8192, COMPLETE.len(), COMPLETE.len() + CHANGE.len() - 1, 1, Duration::from_secs(60)).unwrap(),
            Duration::from_secs(10),
        ).unwrap();
        let mut reader = self::reader(ModernHttpResponseKind::Sse, too_small, wire.len());
        assert!(matches!(reader.push(wire.as_bytes(), life, &mut idle, &mut |_| true),
            Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit)))));
    });
}

#[test]
fn sse_syntax_and_json_payload_have_independent_exact_byte_limits() {
    fixture(|life, _, _| {
        let wire = event(COMPLETE);
        let raw_line_bytes = "data: ".len() + COMPLETE.len();
        let core = ManagedCoreLimits::new(
            8192, COMPLETE.len(), COMPLETE.len(), 0, Duration::from_secs(60),
        ).unwrap();
        for exact in [false, true] {
            let parser = SseLimits::with_data_lines(
                raw_line_bytes,
                raw_line_bytes - usize::from(!exact),
                1,
                1,
            ).unwrap();
            let limits = DpopStreamLimits::new(core, Duration::from_secs(10))
                .unwrap().with_sse_limits(parser).unwrap();
            let mut reader = reader(ModernHttpResponseKind::Sse, limits, wire.len());
            let mut idle = Idle::new(life.cx.now(), limits.idle);
            let outcome = reader.push(wire.as_bytes(), life, &mut idle, &mut |_| true);
            if exact {
                outcome.unwrap();
                assert_eq!(reader.decoder.usage(), (COMPLETE.len(), 0));
                reader.finish(life, &idle).unwrap();
            } else {
                assert!(matches!(outcome, Err(DpopStreamError::Core(
                    DpopCoreError::Protocol(ManagedCoreError::InvalidResponse)
                ))));
                assert_eq!(reader.decoder.usage(), (0, 0));
            }
        }
    });
}

#[test]
fn json_and_sse_preserve_complete_and_input_required_without_automatic_continuation() {
    fixture(|life, _, _| {
        for kind in [ModernHttpResponseKind::Json, ModernHttpResponseKind::Sse] {
            for input in [false, true] {
                let mut params = json!({"uri":"file:///sample", "_meta":FinalRequestMeta::new(ClientCapabilities::default())});
                params["_meta"]["progressToken"] = json!("owned");
                let request = CoreRequest::decode(ProtocolEra::Modern2026, "resources/read", Some(&params)).unwrap();
                let decoder = CoreDecoder::for_request(request, RequestId::Number(7), limits().core).unwrap();
                let mut reader = Reader::new(kind, decoder, limits(), 32768).unwrap();
                let source = if input {
                    r#"{"jsonrpc":"2.0","id":7,"result":{"resultType":"input_required","inputRequests":{"roots":{"method":"roots/list"}},"requestState":"opaque"}}"#
                } else {
                    r#"{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete","contents":[],"ttlMs":0,"cacheScope":"private"}}"#
                };
                let wire = if kind == ModernHttpResponseKind::Sse { event(source) } else { source.to_owned() };
                let mut idle = Idle::new(life.cx.now(), limits().idle);
                reader.push(wire.as_bytes(), life, &mut idle, &mut |_| panic!("no callback expected")).unwrap();
                let result = reader.finish(life, &idle).unwrap().result;
                assert_eq!(matches!(result, CoreResult::Final(FinalCoreResult::ResourcesReadInputRequired { .. })), input);
            }
        }
    });
}

#[derive(Default)]
struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

struct PendingBody(Arc<AtomicUsize>);
impl Body for PendingBody {
    type Data = asupersync::bytes::BytesCursor;
    type Error = ();
    fn poll_frame(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Pending
    }
}
impl Drop for PendingBody {
    fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
}

#[test]
fn pending_body_and_pending_eof_are_woken_and_disposed_on_all_terminal_transitions() {
    for have_terminal in [false, true] {
        for action in 0..6 {
            fixture(|life, timer, clock| {
                let mut reader = reader(ModernHttpResponseKind::Sse, limits(), 32768);
                let mut idle = Idle::new(life.cx.now(), limits().idle);
                if have_terminal {
                    reader.push(event(COMPLETE).as_bytes(), life, &mut idle, &mut |_| true).unwrap();
                }
                let drops = Arc::new(AtomicUsize::new(0));
                let wakes = Arc::new(Wakes::default());
                let waker = Waker::from(Arc::clone(&wakes));
                let mut observe = |_: &ServerNotification| true;
                let mut waiting = Box::pin(consume(PendingBody(Arc::clone(&drops)), life, idle, reader, &mut observe));
                assert!(waiting.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
                assert_eq!(timer.pending_count(), 1);
                match action {
                    0 => { life.cancellation.cancel(); }
                    1 => life.credential.revoke(),
                    2 => life.session.revoke(),
                    3 => life.cx.set_cancel_requested(true),
                    4 => { clock.advance(10_000_000_000); assert!(timer.process_timers() > 0); }
                    _ => {}
                }
                if action != 5 {
                    assert!(wakes.0.load(Ordering::SeqCst) > 0, "must wake before manual repoll");
                    assert!(matches!(waiting.as_mut().poll(&mut Context::from_waker(&waker)), Poll::Ready(Err(_))));
                }
                drop(waiting);
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                assert_eq!(timer.pending_count(), 0);
                assert_eq!(Arc::strong_count(&wakes), 2);
            });
        }
    }
}

// These bodies deliberately never return Pending. Scheduling must come from
// the production reader, not from a socket fixture happening to yield.
struct ReadyBody {
    frames: std::collections::VecDeque<Frame<asupersync::bytes::BytesCursor>>,
    polls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

impl Body for ReadyBody {
    type Data = asupersync::bytes::BytesCursor;
    type Error = ();

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let body = self.get_mut();
        body.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(body.frames.pop_front().map(Ok))
    }
}

impl Drop for ReadyBody {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

fn data_frame(bytes: &[u8]) -> Frame<asupersync::bytes::BytesCursor> {
    Frame::Data(asupersync::bytes::Bytes::copy_from_slice(bytes).reader())
}

#[test]
fn large_ready_buffers_yield_without_changing_notifications_or_exact_results() {
    fixture(|life, timer, _| {
        let comment = format!(":{}\n\n", "x".repeat(BYTES_PER_TURN / 2 - 3));
        let wire = format!("{}{}{}", event(CHANGE), comment.repeat(4), event(COMPLETE));
        for frame_size in [wire.len(), 4093] {
            let polls = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let body = ReadyBody {
                frames: wire.as_bytes().chunks(frame_size).map(data_frame).collect(),
                polls: Arc::clone(&polls),
                drops: Arc::clone(&drops),
            };
            let wakes = Arc::new(Wakes::default());
            let waker = Waker::from(Arc::clone(&wakes));
            let seen = std::cell::Cell::new(0);
            let mut observer = |_: &ServerNotification| { seen.set(seen.get() + 1); true };
            let mut reading = Box::pin(consume(
                body, life, Idle::new(life.cx.now(), limits().idle),
                reader(ModernHttpResponseKind::Sse, limits(), wire.len()), &mut observer,
            ));
            let mut result = None;
            let mut suspensions = 0;
            for _ in 0..8 {
                let before = wakes.0.load(Ordering::SeqCst);
                match reading.as_mut().poll(&mut Context::from_waker(&waker)) {
                    Poll::Pending => {
                        suspensions += 1;
                        assert!(wakes.0.load(Ordering::SeqCst) > before);
                        assert_eq!(seen.get(), 1, "early notification remains incremental");
                        assert_eq!(timer.pending_count(), 1);
                        if frame_size == wire.len() {
                            assert_eq!(polls.load(Ordering::SeqCst), 1);
                        }
                    }
                    Poll::Ready(outcome) => { result = Some(outcome.unwrap()); break; }
                }
            }
            assert_eq!(suspensions, 2, "one large frame must yield internally too");
            let encoded = result.expect("finite ready body must complete").result.encode().unwrap();
            assert!(encoded.contains("900719925474099312345"));
            assert!(encoded.contains("1.20e+4"));
            assert_eq!(seen.get(), 1);
            drop(reading);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(timer.pending_count(), 0);
            assert_eq!(Arc::strong_count(&wakes), 2);
        }
    });
}

#[test]
fn empty_ready_data_and_trailer_frames_cannot_evade_the_scheduling_budget() {
    fixture(|life, timer, _| {
        for trailers in [false, true] {
            let mut frames: std::collections::VecDeque<_> = (0..=2 * FRAMES_PER_TURN)
                .map(|_| {
                    if trailers {
                        // Synthetic Body stress case, not a claim that multiple
                        // HTTP/1 trailer sections form a valid wire response.
                        Frame::Trailers(asupersync::http::body::HeaderMap::new())
                    } else {
                        data_frame(b"")
                    }
                })
                .collect();
            let terminal = event(COMPLETE);
            frames.push_back(data_frame(terminal.as_bytes()));
            let polls = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let body = ReadyBody { frames, polls: Arc::clone(&polls), drops: Arc::clone(&drops) };
            let wakes = Arc::new(Wakes::default());
            let waker = Waker::from(Arc::clone(&wakes));
            let mut observer = |_: &ServerNotification| panic!("terminal-only stream");
            let mut reading = Box::pin(consume(
                body, life, Idle::new(life.cx.now(), limits().idle),
                reader(ModernHttpResponseKind::Sse, limits(), terminal.len()), &mut observer,
            ));
            for turn in 1..=2 {
                let before = wakes.0.load(Ordering::SeqCst);
                assert!(reading.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
                assert_eq!(polls.load(Ordering::SeqCst), turn * FRAMES_PER_TURN);
                assert!(wakes.0.load(Ordering::SeqCst) > before);
            }
            assert!(matches!(
                reading.as_mut().poll(&mut Context::from_waker(&waker)),
                Poll::Ready(Ok(_))
            ));
            assert_eq!(polls.load(Ordering::SeqCst), 2 * FRAMES_PER_TURN + 3);
            drop(reading);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(timer.pending_count(), 0);
        }
    });
}

#[test]
fn a_cooperative_yield_keeps_cancellation_authority_and_the_original_idle_deadline() {
    use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};

    for action in 0..7 {
        fixture(|life, timer, clock| {
            // Exactly one quantum before the first possible observer effect.
            let prefix = format!(":{}\n", "x".repeat(BYTES_PER_TURN - 2));
            let wire = format!("{prefix}{}{}", event(CHANGE), event(COMPLETE));
            let polls = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let body = ReadyBody {
                frames: std::collections::VecDeque::from([data_frame(wire.as_bytes())]),
                polls: Arc::clone(&polls),
                drops: Arc::clone(&drops),
            };
            let wakes = Arc::new(Wakes::default());
            let waker = Waker::from(Arc::clone(&wakes));
            let mut observer = |_: &ServerNotification| panic!("remaining frame must be withheld");
            let mut reading = Box::pin(consume(
                body, life, Idle::new(life.cx.now(), limits().idle),
                reader(ModernHttpResponseKind::Sse, limits(), wire.len()), &mut observer,
            ));
            assert!(reading.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
            assert!(wakes.0.load(Ordering::SeqCst) > 0);
            assert_eq!(polls.load(Ordering::SeqCst), 1);
            wakes.0.store(0, Ordering::SeqCst);
            match action {
                0 => { life.cancellation.cancel(); }
                1 => life.credential.revoke(),
                2 => life.session.revoke(),
                3 => life.cx.set_cancel_requested(true),
                4 => { clock.advance(10_000_000_000); assert!(timer.process_timers() > 0); }
                _ => {}
            }
            if action < 5 {
                assert!(wakes.0.load(Ordering::SeqCst) > 0);
                let outcome = reading.as_mut().poll(&mut Context::from_waker(&waker));
                if action == 4 {
                    assert!(matches!(outcome, Poll::Ready(Err(DpopStreamError::Core(
                        DpopCoreError::Transport(DpopHttpError::TimedOut)
                    )))));
                } else {
                    assert!(matches!(outcome, Poll::Ready(Err(_))));
                }
            } else if action == 5 {
                let _restriction = Cx::push_restriction(CapSet::<true, false, true, true, true>::MASK);
                assert!(matches!(
                    reading.as_mut().poll(&mut Context::from_waker(&waker)),
                    Poll::Ready(Err(DpopStreamError::Core(DpopCoreError::Transport(
                        DpopHttpError::RuntimeUnavailable
                    ))))
                ));
            }
            drop(reading);
            assert_eq!(polls.load(Ordering::SeqCst), 1);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(timer.pending_count(), 0);
            assert_eq!(Arc::strong_count(&wakes), 2);
            wakes.0.store(0, Ordering::SeqCst);
            life.cancellation.cancel();
            life.credential.revoke();
            life.session.revoke();
            assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
        });
    }
}

#[test]
fn a_small_ready_response_finishes_without_an_unnecessary_yield() {
    fixture(|life, timer, _| {
        for kind in [ModernHttpResponseKind::Json, ModernHttpResponseKind::Sse] {
            let wire = if kind == ModernHttpResponseKind::Json {
                COMPLETE.to_owned()
            } else {
                event(COMPLETE)
            };
            let polls = Arc::new(AtomicUsize::new(0));
            let drops = Arc::new(AtomicUsize::new(0));
            let body = ReadyBody {
                frames: std::collections::VecDeque::from([data_frame(wire.as_bytes())]),
                polls: Arc::clone(&polls),
                drops: Arc::clone(&drops),
            };
            let wakes = Arc::new(Wakes::default());
            let waker = Waker::from(Arc::clone(&wakes));
            let mut observer = |_: &ServerNotification| panic!("terminal-only stream");
            let mut reading = Box::pin(consume(
                body, life, Idle::new(life.cx.now(), limits().idle),
                reader(kind, limits(), wire.len()), &mut observer,
            ));
            assert!(matches!(
                reading.as_mut().poll(&mut Context::from_waker(&waker)),
                Poll::Ready(Ok(_))
            ));
            assert_eq!(polls.load(Ordering::SeqCst), 2);
            assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
            drop(reading);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(timer.pending_count(), 0);
        }
    });
}

#[test]
fn completed_stream_reports_inherited_and_new_usage_for_json_and_sse() {
    fixture(|life, _, _| {
        for kind in [ModernHttpResponseKind::Json, ModernHttpResponseKind::Sse] {
            let mut decoder = CoreDecoder::for_request(request(), RequestId::Number(7), limits().core).unwrap();
            decoder.resume_usage(512, 2).unwrap();
            let mut reader = Reader::new(kind, decoder, limits(), 32768).unwrap();
            let mut idle = Idle::new(life.cx.now(), limits().idle);
            let wire = if kind == ModernHttpResponseKind::Sse {
                format!("{}{}", event(CHANGE), event(COMPLETE))
            } else { COMPLETE.to_owned() };
            let mut seen = 0;
            reader.push(wire.as_bytes(), life, &mut idle, &mut |_| { seen += 1; true }).unwrap();
            let completed = reader.finish(life, &idle).unwrap();
            let notes = usize::from(kind == ModernHttpResponseKind::Sse);
            assert_eq!(seen, notes);
            assert_eq!(completed.usage, (512 + COMPLETE.len() + notes * CHANGE.len(), 2 + notes));
            assert!(completed.result.encode().unwrap().contains("1.20e+4"));
        }
    });
}

#[test]
fn resumed_json_growth_is_refused_at_the_remaining_conversation_budget() {
    fixture(|life, _, _| {
        for exact in [false, true] {
            let core = ManagedCoreLimits::new(8192, 8192, 8192, 0, Duration::from_secs(60)).unwrap();
            let limits = DpopStreamLimits::new(core, Duration::from_secs(10)).unwrap();
            let mut decoder = CoreDecoder::for_request(request(), RequestId::Number(7), core).unwrap();
            let reserved = 8192 - COMPLETE.len() + usize::from(!exact);
            decoder.resume_usage(reserved, 0).unwrap();
            let mut reader = Reader::new(ModernHttpResponseKind::Json, decoder, limits, 32768).unwrap();
            let mut idle = Idle::new(life.cx.now(), limits.idle);
            let result = reader.push(COMPLETE.as_bytes(), life, &mut idle, &mut |_| panic!("JSON is terminal-only"));
            if exact {
                result.unwrap();
                assert_eq!(reader.finish(life, &idle).unwrap().usage, (8192, 0));
            } else {
                assert!(matches!(result, Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit)))));
                assert_eq!(reader.decoder.usage(), (reserved, 0));
            }
        }
    });
}
