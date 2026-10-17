use super::*;
use std::cell::Cell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Wake, Waker};
use std::time::{Duration, Instant};

use asupersync::bytes::{Bytes, BytesCursor};
use asupersync::http::body::Frame;
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::{TimerDriverHandle, VirtualClock};
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::ClientCapabilities;
use fastmcp_protocol::dpop::DpopKey;
use serde_json::json;

struct Channel {
    frames: VecDeque<Vec<u8>>,
    eof: bool,
    waiter: Option<Waker>,
}

#[derive(Clone)]
struct Control(Arc<Mutex<Channel>>);

impl Control {
    fn send(&self, bytes: Vec<u8>) {
        let wake = {
            let mut channel = self.0.lock().unwrap();
            channel.frames.push_back(bytes);
            channel.waiter.take()
        };
        if let Some(wake) = wake { wake.wake(); }
    }

    fn finish(&self) {
        let wake = {
            let mut channel = self.0.lock().unwrap();
            channel.eof = true;
            channel.waiter.take()
        };
        if let Some(wake) = wake { wake.wake(); }
    }
}

struct TestBody {
    control: Control,
    polls: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

impl Body for TestBody {
    type Data = BytesCursor;
    type Error = ();

    fn poll_frame(self: Pin<&mut Self>, task: &mut Context<'_>)
        -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>>
    {
        self.polls.fetch_add(1, Ordering::SeqCst);
        let mut channel = self.control.0.lock().unwrap();
        if let Some(bytes) = channel.frames.pop_front() {
            return Poll::Ready(Some(Ok(Frame::Data(Bytes::copy_from_slice(&bytes).reader()))));
        }
        if channel.eof { return Poll::Ready(None); }
        channel.waiter = Some(task.waker().clone());
        Poll::Pending
    }
}

impl Drop for TestBody {
    fn drop(&mut self) { self.drops.fetch_add(1, Ordering::SeqCst); }
}

#[derive(Default)]
struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

struct Work { polls: Rc<Cell<usize>>, drops: Rc<Cell<usize>>, ready: Rc<Cell<bool>> }
impl Future for Work {
    type Output = Result<u8, DpopTaskWatchError>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        self.polls.set(self.polls.get() + 1);
        if self.ready.get() { Poll::Ready(Ok(7)) } else { Poll::Pending }
    }
}
impl Drop for Work {
    fn drop(&mut self) { self.drops.set(self.drops.get() + 1); }
}

fn event(value: serde_json::Value) -> Vec<u8> {
    format!("data: {value}\r\n\r\n").into_bytes()
}

fn ack() -> Vec<u8> {
    event(json!({"jsonrpc":"2.0", "method":"notifications/subscriptions/acknowledged",
        "params":{"notifications":{"taskIds":["task-one"]},
            "_meta":{FINAL_SUBSCRIPTION_ID_META_KEY:"watch.listen"}}}))
}

fn status() -> Vec<u8> {
    event(json!({"jsonrpc":"2.0", "method":TASK_STATUS_NOTIFICATION,
        "params":{"taskId":"task-one", "status":"working", "ttlMs":null,
            "createdAt":"2026-09-16T00:00:00Z", "lastUpdatedAt":"2026-09-16T00:00:00Z",
            "_meta":{FINAL_SUBSCRIPTION_ID_META_KEY:"watch.listen"}}}))
}

fn terminal() -> Vec<u8> {
    event(json!({"jsonrpc":"2.0", "id":"watch.listen", "result":{"resultType":"complete",
        "_meta":{FINAL_SUBSCRIPTION_ID_META_KEY:"watch.listen"}}}))
}

fn fixture(test: impl FnOnce(&ReadOwner<'_>, &TimerDriverHandle, &Arc<VirtualClock>)) {
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let runtime = RuntimeBuilder::current_thread().blocking_threads(0, 0)
        .with_timer_driver(timer.clone()).build().unwrap();
    let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
    let session = DpopSession::new(DpopKey::generate().unwrap(), issuer.clone(),
        CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap()).unwrap();
    let credential = session.admit_token_response(&issuer, 200,
        br#"{"access_token":"live-watch-test","token_type":"DPoP","expires_in":300}"#,
        Instant::now(), Duration::from_secs(300)).unwrap();
    let cancellation = McpRequestCancellation::new();
    let bounds = WaitBounds::new(&cx, Duration::from_secs(60), &credential).unwrap();
    let owner = ReadOwner::new(&cx, &cancellation, &session, &credential, bounds);
    with_caller(&cx, || test(&owner, &timer, &clock));
    assert_eq!(timer.pending_count(), 0);
    drop(owner);
    drop(cx);
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

fn listen(owner: &ReadOwner<'_>, notifications: usize)
    -> (LiveListen<TestBody>, Control, Arc<AtomicUsize>, Arc<AtomicUsize>)
{
    let limits = DpopStreamLimits::new(
        ManagedCoreLimits::new(8192, 8192, 32768, notifications, Duration::from_secs(60)).unwrap(),
        Duration::from_secs(10)).unwrap();
    let state = WatchState::new("watch", DpopTaskWatchPolicy::new(8).unwrap(), limits).unwrap();
    let task = TaskId::parse("task-one").unwrap();
    let selection = state.selection(FinalRequestMeta::new(ClientCapabilities::default()), &task).unwrap();
    let discovery_id = selection.discovery_id.clone();
    let prepared = Prepared::new("https://mcp.example/mcp", selection, limits.core, 8192).unwrap();
    let body = serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":discovery_id, "result":{
        "resultType":"complete", "supportedVersions":[FINAL_PROTOCOL_VERSION],
        "capabilities":{"extensions":{TASKS_EXTENSION:{}}}, "ttlMs":0,"cacheScope":"private",
        "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"live-peer","version":"1"}}
    }})).unwrap();
    let (_, decoder) = prepared.admit(DpopHttpResponse { status:200, headers:vec![], body }).unwrap();
    let budget = SharedStreamBudget::new(limits.core, decoder.usage()).unwrap();
    let control = Control(Arc::new(Mutex::new(Channel { frames: VecDeque::new(), eof:false, waiter:None })));
    let polls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let body = TestBody { control: control.clone(), polls: polls.clone(), drops: drops.clone() };
    let mut listen = LiveListen::new(body, crate::http_executor::ModernHttpResponseKind::Sse,
        decoder, Idle::new(owner.cx.now(), limits.idle), task, limits, 1024 * 1024, budget).unwrap();
    control.send(ack());
    {
        let mut next = Box::pin(listen.next(owner));
        assert!(matches!(next.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(LiveStep::Hint))));
    }
    listen.clear_hint();
    (listen, control, polls, drops)
}

#[test]
fn pending_companion_keeps_listening_and_teardown_drops_it_without_waiting_for_eof() {
    fixture(|owner, _, _| {
        let (mut listen, control, _, body_drops) = listen(owner, 8);
        let budget = listen.budget.clone();
        let polls = Rc::new(Cell::new(0));
        let drops = Rc::new(Cell::new(0));
        let work = Work { polls: polls.clone(), drops: drops.clone(), ready: Rc::new(Cell::new(false)) };
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut task = Context::from_waker(&waker);
        let mut follow = Box::pin(listen.follow(owner, work));
        assert!(follow.as_mut().poll(&mut task).is_pending());
        control.send(status());
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(follow.as_mut().poll(&mut task).is_pending());
        assert_eq!(budget.usage().unwrap().1, 2, "status admitted while work is pending");
        let before = polls.get();
        control.send(terminal());
        assert!(matches!(follow.as_mut().poll(&mut task), Poll::Ready(Ok(Follow::Stopped))));
        assert_eq!(polls.get(), before, "terminal wins before another host poll");
        drop(follow);
        assert_eq!(drops.get(), 1);
        assert_eq!(body_drops.load(Ordering::SeqCst), 0, "tail still needs clean EOF");
        control.finish();
        {
            let mut next = Box::pin(listen.next(owner));
            assert!(matches!(next.as_mut().poll(&mut task), Poll::Ready(Ok(LiveStep::Closed))));
        }
        assert_eq!(body_drops.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn ready_terminal_prevents_even_the_first_companion_poll() {
    fixture(|owner, _, _| {
        let (mut listen, control, _, _) = listen(owner, 8);
        control.send(terminal());
        let mut future = Box::pin(listen.follow(owner, async {
            panic!("a retired listen cannot start host or HTTP work");
            #[allow(unreachable_code)]
            Ok::<(), DpopTaskWatchError>(())
        }));
        assert!(matches!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(Follow::Stopped))));
    });
}

#[test]
fn a_large_unread_frame_suffix_cannot_be_overtaken_by_host_work() {
    fixture(|owner, _, _| {
        let (mut listen, control, polls, _) = listen(owner, 8);
        let mut wire = format!(":{}\n\n", "x".repeat(BYTES_PER_TURN + 64)).into_bytes();
        wire.extend(terminal());
        control.send(wire);
        let work_polls = Cell::new(0);
        let mut future = Box::pin(listen.follow(owner, async {
            work_polls.set(work_polls.get() + 1);
            Ok::<(), DpopTaskWatchError>(())
        }));
        let mut task = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut task).is_pending());
        let body_polls = polls.load(Ordering::SeqCst);
        assert_eq!(work_polls.get(), 0);
        assert!(matches!(future.as_mut().poll(&mut task), Poll::Ready(Ok(Follow::Stopped))));
        assert_eq!(work_polls.get(), 0);
        assert_eq!(polls.load(Ordering::SeqCst), body_polls, "consume the saved Buf before polling the body");
    });
}

#[test]
fn provisional_terminal_does_not_authorize_reconciliation_with_a_malformed_tail() {
    fixture(|owner, _, _| {
        let (mut listen, control, _, _) = listen(owner, 8);
        control.send(terminal());
        control.send(b"data: {\"unfinished\":".to_vec());
        control.finish();
        {
            let mut follow = Box::pin(listen.follow(owner, std::future::pending::<Result<(), DpopTaskWatchError>>()));
            assert!(matches!(follow.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Ok(Follow::Stopped))));
        }
        let mut next = Box::pin(listen.next(owner));
        assert!(matches!(next.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(Err(_))));
    });
}

#[test]
fn an_early_eof_is_an_error_not_a_clean_rollover() {
    fixture(|owner, _, _| {
        let (mut listen, control, _, _) = listen(owner, 8);
        control.finish();
        let mut future = Box::pin(listen.follow(owner, std::future::pending::<Result<(), DpopTaskWatchError>>()));
        assert!(matches!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(Err(_))));
    });
}

#[test]
fn a_completed_companion_is_not_repolled_across_receive_fairness_yields() {
    fixture(|owner, _, _| {
        let (mut listen, control, _, _) = listen(owner, 8);
        let calls = Cell::new(0);
        let mut future = Box::pin(listen.follow(owner, async {
            calls.set(calls.get() + 1);
            for _ in 0..100 { control.send(Vec::new()); }
            Ok::<u8, DpopTaskWatchError>(42)
        }));
        let mut task = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut task).is_pending());
        let mut completed = false;
        for _ in 0..8 {
            if let Poll::Ready(Ok(Follow::Completed(value))) = future.as_mut().poll(&mut task) {
                assert_eq!(value, 42);
                completed = true;
                break;
            }
        }
        assert!(completed);
        assert_eq!(calls.get(), 1);
    });
}

#[test]
fn all_cancellation_domains_wake_a_quiet_listen_and_pending_companion() {
    for action in 0..6 {
        fixture(|owner, timer, clock| {
            let (mut listen, _, _, body_drops) = listen(owner, 8);
            let drops = Rc::new(Cell::new(0));
            let work = Work { polls: Rc::new(Cell::new(0)), drops: drops.clone(), ready: Rc::new(Cell::new(false)) };
            let wakes = Arc::new(Wakes::default());
            let waker = Waker::from(wakes.clone());
            let mut task = Context::from_waker(&waker);
            let mut future = Box::pin(listen.follow(owner, work));
            assert!(future.as_mut().poll(&mut task).is_pending());
            match action {
                0 => { owner.cancellation.cancel(); }
                1 => owner.credential.revoke(),
                2 => { owner.owner.cancel(); }
                3 => owner.cx.set_cancel_requested(true),
                4 => { clock.advance(10_000_000_000); assert!(timer.process_timers() > 0); }
                _ => {}
            }
            if action != 5 {
                assert!(wakes.0.load(Ordering::SeqCst) > 0);
                assert!(matches!(future.as_mut().poll(&mut task), Poll::Ready(Err(_))));
            }
            drop(future);
            assert_eq!(drops.get(), 1);
            assert_eq!(timer.pending_count(), 0);
            drop(listen);
            assert_eq!(body_drops.load(Ordering::SeqCst), 1);
            if action != 2 { assert!(!owner.owner.is_cancel_requested()); }
        });
    }
}

#[test]
fn concurrent_quota_spending_is_checked_before_delivering_a_listen_event() {
    fixture(|owner, _, _| {
        let (mut listen, control, _, _) = listen(owner, 2);
        let budget = listen.budget.clone();
        budget.charge((0, 1)).unwrap(); // a companion consumed the last notification slot
        let before = budget.usage().unwrap();
        control.send(status());
        let mut future = Box::pin(listen.follow(owner, async {
            panic!("over-budget listen cannot publish a companion result");
            #[allow(unreachable_code)]
            Ok::<(), DpopTaskWatchError>(())
        }));
        assert!(matches!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Ready(Err(_))));
        assert_eq!(budget.usage().unwrap(), before);
    });
}

#[test]
fn status_hints_received_during_a_companion_remain_pending_for_reconciliation() {
    fixture(|owner, _, _| {
        let (mut listen, control, _, _) = listen(owner, 8);
        let ready = Rc::new(Cell::new(false));
        let work = Work { polls: Rc::new(Cell::new(0)), drops: Rc::new(Cell::new(0)), ready: ready.clone() };
        let mut future = Box::pin(listen.follow(owner, work));
        let mut task = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut task).is_pending());
        control.send(status());
        ready.set(true);
        assert!(matches!(future.as_mut().poll(&mut task), Poll::Ready(Ok(Follow::Completed(7)))));
        drop(future);
        assert!(listen.has_hint());
        assert!(!listen.closed);
    });
}
