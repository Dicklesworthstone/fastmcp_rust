//! Exercise the production DPoP wait, including its nested sampling consumer.

use super::*;
use asupersync::cx::cap::{CapMask, CapSet, CapSetRuntimeMask};
use std::panic::{AssertUnwindSafe, catch_unwind};

const ALL: u8 = 31;
const TIME: u8 = 2;
const IO: u8 = 8;

fn mask(bits: u8) -> CapMask {
    let mut mask = CapMask::all();
    for (bit, without) in [
        (1, CapSet::<false, true, true, true, true>::MASK),
        (TIME, CapSet::<true, false, true, true, true>::MASK),
        (4, CapSet::<true, true, false, true, true>::MASK),
        (IO, CapSet::<true, true, true, false, true>::MASK),
        (16, CapSet::<true, true, true, true, false>::MASK),
    ] {
        if bits & bit == 0 {
            mask = mask.intersect(without);
        }
    }
    mask
}

fn row(cx: &Cx) -> u8 {
    let caps = cx.capabilities();
    u8::from(caps.spawn)
        | (u8::from(caps.time) << 1)
        | (u8::from(caps.entropy) << 2)
        | (u8::from(caps.io) << 3)
        | (u8::from(caps.remote) << 4)
}

fn held(cx: &Cx, bits: u8) -> Cx {
    let _caller = Cx::set_current(Some(cx.clone()));
    let _restriction = Cx::push_restriction(mask(bits));
    Cx::current().unwrap()
}

#[test]
fn native_wait_intersects_every_explicit_and_ambient_capability_combination() {
    let (runtime, cx, timer, _) = runtime();
    let session = session();
    let credential = credential(&session);
    let cancellation = McpRequestCancellation::new();
    let bounds = WaitBounds::new(&cx, Duration::from_secs(10), &credential).unwrap();
    for explicit in 0..=ALL {
        let caller = held(&cx, explicit);
        for ambient in 0..=ALL {
            let surrounding = held(&Cx::for_testing(), ambient);
            let expected = explicit & ambient;
            let polls = AtomicUsize::new(0);
            let mut work = Box::pin(within(
                &caller,
                &cancellation,
                &session,
                &credential,
                bounds,
                async {
                    polls.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(row(&Cx::current().unwrap()), expected);
                    Ok(42)
                },
            ));
            let _surrounding = Cx::set_current(Some(surrounding));
            let depth = Cx::restriction_depth();
            let admission = WaitBounds::new(&caller, Duration::from_secs(10), &credential);
            let result = work.as_mut().poll(&mut Context::from_waker(Waker::noop()));
            let allowed = expected & (TIME | IO) == (TIME | IO);
            if allowed {
                assert!(admission.is_ok());
                assert_eq!(result, Poll::Ready(Ok(42)));
                assert_eq!(polls.load(Ordering::SeqCst), 1);
            } else {
                assert!(matches!(admission, Err(DpopHttpError::RuntimeUnavailable)));
                assert_eq!(result, Poll::Ready(Err(DpopHttpError::RuntimeUnavailable)));
                assert_eq!(polls.load(Ordering::SeqCst), 0);
            }
            assert_eq!(row(&Cx::current().unwrap()), ambient);
            assert_eq!(Cx::restriction_depth(), depth);
            drop(work);
            assert_eq!(timer.pending_count(), 0);
        }
    }
    assert!(!credential.is_revoked());
    assert!(!cancellation.is_cancel_requested());
    assert!(!cx.is_cancel_requested());
    drop(cx);
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn public_post_refuses_denied_time_or_io_before_transport_work() {
    let (runtime, cx, timer, _) = runtime();
    let session = session();
    let credential = credential(&session);
    let request = request(session.resource.as_str());
    let mut client = DpopHttpClient::new(session, DpopHttpPolicy::default()).unwrap();
    let cancellation = McpRequestCancellation::new();
    for bits in [ALL & !TIME, ALL & !IO, 0] {
        let ambient = held(&Cx::for_testing(), bits);
        let _ambient = Cx::set_current(Some(ambient));
        let mut call = Box::pin(client.post_resource(&cx, &cancellation, &credential, &request));
        assert!(matches!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(DpopHttpError::RuntimeUnavailable))
        ));
        drop(call);
        assert!(client.session.resource_nonce.is_none());
        assert!(client.session.token_nonce.is_none());
        assert_eq!(row(&Cx::current().unwrap()), bits);
        assert_eq!(timer.pending_count(), 0);
    }
    assert!(!credential.is_revoked());
    drop(cx);
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn pending_native_wait_rechecks_authority_and_releases_all_registrations() {
    for denied in [TIME, IO] {
        let (runtime, cx, timer, _) = runtime();
        let session = session();
        let credential = credential(&session);
        let cancellation = McpRequestCancellation::new();
        let bounds = WaitBounds::new(&cx, Duration::from_secs(10), &credential).unwrap();
        let observations = std::cell::RefCell::new(Vec::new());
        let drops = Arc::new(AtomicUsize::new(0));
        let owned = PendingIo(Arc::clone(&drops));
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut call = Box::pin(within(
            &cx,
            &cancellation,
            &session,
            &credential,
            bounds,
            async {
                let _owned = owned;
                poll_fn(|_| {
                    observations.borrow_mut().push(row(&Cx::current().unwrap()));
                    Poll::<Result<(), DpopHttpError>>::Pending
                })
                .await
            },
        ));
        for bits in [ALL, TIME | IO] {
            let _ambient = Cx::set_current(Some(held(&Cx::for_testing(), bits)));
            assert!(
                call.as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            assert_eq!(row(&Cx::current().unwrap()), bits);
        }
        assert_eq!(*observations.borrow(), [ALL, TIME | IO]);
        assert_eq!(timer.pending_count(), 1);
        {
            let bits = ALL & !denied;
            let _ambient = Cx::set_current(Some(held(&Cx::for_testing(), bits)));
            assert_eq!(
                call.as_mut().poll(&mut Context::from_waker(&waker)),
                Poll::Ready(Err(DpopHttpError::RuntimeUnavailable))
            );
            assert_eq!(row(&Cx::current().unwrap()), bits);
        }
        drop(call);
        assert_eq!(*observations.borrow(), [ALL, TIME | IO]);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(timer.pending_count(), 0);
        assert_eq!(Arc::strong_count(&wakes), 2);
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
        assert!(!credential.is_revoked());
        assert!(!cancellation.is_cancel_requested());
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }
}

#[test]
fn foreign_ambient_cancellation_and_clock_never_replace_the_native_owner() {
    let (caller_runtime, cx, timer, _) = runtime();
    let (foreign_runtime, foreign, foreign_timer, clock) = runtime();
    clock.advance(7_000_000_000);
    foreign.set_cancel_requested(true);
    let session = session();
    let credential = credential(&session);
    let cancellation = McpRequestCancellation::new();
    let bounds = WaitBounds::new(&cx, Duration::from_secs(10), &credential).unwrap();
    let ambient = held(&foreign, TIME | IO);
    let ambient_guard = Cx::set_current(Some(ambient));
    let mut call = Box::pin(within(
        &cx,
        &cancellation,
        &session,
        &credential,
        bounds,
        async {
            let active = Cx::current().unwrap();
            assert_eq!(active.now(), cx.now());
            assert_eq!(active.budget().deadline, cx.budget().deadline);
            assert!(!active.is_cancel_requested());
            assert_eq!(row(&active), TIME | IO);
            Ok(7)
        },
    ));
    assert_eq!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(7))
    );
    assert_eq!(Cx::current().unwrap().now(), foreign.now());
    assert!(Cx::current().unwrap().is_cancel_requested());
    drop(call);
    drop(ambient_guard);
    assert_eq!(timer.pending_count(), 0);
    assert_eq!(foreign_timer.pending_count(), 0);
    drop(foreign);
    drop(cx);
    assert!(foreign_runtime.shutdown_timeout(Duration::from_secs(1)));
    assert!(caller_runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn native_unwind_restores_the_surrounding_scope_and_retires_its_timer() {
    let (runtime, cx, timer, _) = runtime();
    let session = session();
    let credential = credential(&session);
    let cancellation = McpRequestCancellation::new();
    let bounds = WaitBounds::new(&cx, Duration::from_secs(10), &credential).unwrap();
    let ambient_guard = Cx::set_current(Some(held(&Cx::for_testing(), TIME | IO)));
    let depth = Cx::restriction_depth();
    let mut call = Box::pin(within(
        &cx,
        &cancellation,
        &session,
        &credential,
        bounds,
        poll_fn(|_| -> Poll<Result<(), DpopHttpError>> {
            assert_eq!(row(&Cx::current().unwrap()), TIME | IO);
            panic!("test-owned unwind");
        }),
    ));
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            call.as_mut().poll(&mut Context::from_waker(Waker::noop()))
        }))
        .is_err()
    );
    assert_eq!(row(&Cx::current().unwrap()), TIME | IO);
    assert_eq!(Cx::restriction_depth(), depth);
    drop(call);
    assert_eq!(timer.pending_count(), 0);
    assert!(!credential.is_revoked());
    drop(ambient_guard);
    drop(cx);
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn native_outer_wait_preserves_restrictions_inside_the_public_sampling_runner() {
    use crate::http_auth::sampling::{
        SamplingHost, SamplingHostError, SamplingHostFuture, SamplingRunLimits,
        run_sampling_tool_loop,
    };
    use fastmcp_protocol::common_types::SamplingContentBlock;
    use fastmcp_protocol::{FinalCreateMessageResult, FinalEmbeddedCreateMessageParams};

    struct Model;
    impl SamplingHost for Model {
        fn sample<'a>(
            &'a mut self,
            _: &'a Cx,
            _: &'a McpRequestCancellation,
            _: &'a FinalEmbeddedCreateMessageParams,
        ) -> SamplingHostFuture<'a, FinalCreateMessageResult> {
            assert_eq!(row(&Cx::current().unwrap()), TIME | IO);
            Box::pin(async {
                assert_eq!(row(&Cx::current().unwrap()), TIME | IO);
                Ok(serde_json::from_value(serde_json::json!({
                    "role":"assistant", "model":"test-model",
                    "content":{"type":"text","text":"done"}
                }))
                .unwrap())
            })
        }
        fn approve_tools<'a>(
            &'a mut self,
            _: &'a Cx,
            _: &'a McpRequestCancellation,
            _: &'a [SamplingContentBlock],
        ) -> SamplingHostFuture<'a, ()> {
            panic!("a final model result must not request tool approval")
        }
        fn execute_tool<'a>(
            &'a mut self,
            _: &'a Cx,
            _: &'a McpRequestCancellation,
            _: &'a SamplingContentBlock,
        ) -> SamplingHostFuture<'a, SamplingContentBlock> {
            Box::pin(async { Err(SamplingHostError::Denied) })
        }
    }

    let (runtime, cx, timer, _) = runtime();
    let session = session();
    let credential = credential(&session);
    let cancellation = McpRequestCancellation::new();
    let bounds = WaitBounds::new(&cx, Duration::from_secs(10), &credential).unwrap();
    let request = serde_json::from_value(serde_json::json!({
        "messages":[{"role":"user","content":{"type":"text","text":"hello"}}],
        "maxTokens":32
    }))
    .unwrap();
    let mut model = Model;
    let mut call = Box::pin(within(
        &cx,
        &cancellation,
        &session,
        &credential,
        bounds,
        async {
            Ok(run_sampling_tool_loop(
                &cx,
                &cancellation,
                request,
                SamplingRunLimits::default(),
                &mut model,
            )
            .await)
        },
    ));
    let ambient_guard = Cx::set_current(Some(held(&Cx::for_testing(), TIME | IO)));
    let Poll::Ready(Ok(Ok(result))) = call.as_mut().poll(&mut Context::from_waker(Waker::noop()))
    else {
        panic!("one ready model round must finish under the intersected ceiling");
    };
    assert_eq!(result.model_rounds, 1);
    assert_eq!(result.executed_tools, 0);
    assert_eq!(row(&Cx::current().unwrap()), TIME | IO);
    drop(call);
    drop(ambient_guard);
    assert_eq!(timer.pending_count(), 0);
    drop(cx);
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}
