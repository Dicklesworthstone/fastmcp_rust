//! Operation-local admission at host callback boundaries.
//!
//! An outer future guard cannot interpose between two ready awaits in one poll.
//! In particular, a reverse handler can close its login and the MRTR driver can
//! start the continuation before the outer guard observes closure. Check at the
//! callback itself, before its answer is serialized or a review is accepted.
//!
//! The enclosing managed guards still own wake registration and timers. These
//! checks neither create another runtime nor cancel the caller/shared login.
//! Only signals and the original deadlines are retained, never bearer bytes.

use std::future::{Future, poll_fn};
use std::time::Instant;

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::{McpError, McpRequestCancellation, McpResult};
use fastmcp_protocol::http_headers::ParameterHeaderBinding;

use super::super::{ManagedOAuthSession, OAuthCredentialSnapshot};
use super::{Call, CallResult};
use crate::{HttpClient, HttpClientError, ReverseRequestHandlers};

#[derive(Clone)]
pub(crate) struct CallbackBoundary {
    closed: McpRequestCancellation,
    cancellation: McpRequestCancellation,
    revoked: McpRequestCancellation,
    deadline: Time,
    expires_at: Instant,
}

impl CallbackBoundary {
    pub(crate) fn new(
        session: &ManagedOAuthSession,
        cancellation: &McpRequestCancellation,
        deadline: Time,
        snapshot: &OAuthCredentialSnapshot,
    ) -> Self {
        Self {
            closed: session.inner.closed.clone(),
            cancellation: cancellation.clone(),
            revoked: snapshot.credential.revoked.clone(),
            deadline,
            expires_at: snapshot.expires_at(),
        }
    }

    pub(super) fn check(&self, cx: &Cx) -> McpResult<()> {
        if self.closed.is_cancel_requested()
            || self.cancellation.is_cancel_requested()
            || self.revoked.is_cancel_requested()
            || Instant::now() >= self.expires_at
            || cx.now() >= self.deadline
            || cx.checkpoint().is_err()
        {
            // The enclosing managed guard retains the precise session, caller,
            // token or timeout disposition. This error only stops the ordinary
            // client's callback/continuation path, without reflecting private data.
            Err(McpError::request_cancelled())
        } else {
            Ok(())
        }
    }

    async fn run<T>(&self, cx: &Cx, future: impl Future<Output = McpResult<T>>) -> McpResult<T> {
        let mut future = std::pin::pin!(future);
        poll_fn(|task| {
            self.check(cx)?;
            let result = future.as_mut().poll(task);
            // Also withhold a Ready error: a revoked callback must not enter a
            // correctable-error branch that performs another request.
            self.check(cx)?;
            result
        })
        .await
    }

    // Constructing a callback future is itself host code. A single guarded
    // `async { construct().await }` still polls that future in the same poll
    // even when its constructor has just cancelled or revoked authority.
    // Check between these two host effects, and drop refused work unpolled.
    // Effects already performed inside the constructor cannot be undone.
    async fn construct_and_run<T, F>(
        &self,
        cx: &Cx,
        construct: impl FnOnce() -> F,
    ) -> McpResult<T>
    where
        F: Future<Output = McpResult<T>>,
    {
        self.check(cx)?;
        let future = construct();
        self.check(cx)?;
        self.run(cx, future).await
    }

    pub(crate) fn approve(&self, cx: &Cx, review: impl FnOnce() -> bool) -> bool {
        self.check(cx).is_ok() && review() && self.check(cx).is_ok()
    }

    fn wrap(&self, mut handlers: ReverseRequestHandlers) -> ReverseRequestHandlers {
        if let Some(handler) = handlers.modern_sampling_create_message.take() {
            let boundary = self.clone();
            handlers =
                handlers.with_modern_sampling_create_message(move |cx, cancelled, params| {
                    let boundary = boundary.clone();
                    let handler = handler.clone();
                    Box::pin(async move {
                        // Defer construction until admission, then recheck before
                        // the first poll of returned host work.
                        boundary
                            .construct_and_run(cx, move || handler(cx, cancelled, params))
                            .await
                    })
                });
        }
        if let Some(handler) = handlers.modern_roots_list.take() {
            let boundary = self.clone();
            handlers = handlers.with_modern_roots_list(move |cx, cancelled, params| {
                let boundary = boundary.clone();
                let handler = handler.clone();
                Box::pin(async move {
                    boundary
                        .construct_and_run(cx, move || handler(cx, cancelled, params))
                        .await
                })
            });
        }
        if let Some(handler) = handlers.modern_elicitation_create.take() {
            let boundary = self.clone();
            handlers = handlers.with_modern_elicitation_create(move |cx, cancelled, params| {
                let boundary = boundary.clone();
                let handler = handler.clone();
                Box::pin(async move {
                    boundary
                        .construct_and_run(cx, move || handler(cx, cancelled, params))
                        .await
                })
            });
        }
        handlers
    }

    // Both managed HTTP entrypoints use these same operation-local wrappers.
    // The caller owns the complete client during dispatch: abandonment drops
    // that client, while completed dispatch restores the original handlers.
    pub(crate) fn install(
        &self,
        cx: &Cx,
        client: &mut HttpClient,
    ) -> Result<Option<ReverseRequestHandlers>, HttpClientError> {
        self.check(cx).map_err(HttpClientError::CoreResult)?;
        let original = client.connection.modern_reverse_request_handlers().cloned();
        if let Some(handlers) = &original {
            client
                .connection
                .set_modern_reverse_request_handlers(self.wrap(handlers.clone()))
                .map_err(HttpClientError::CoreResult)?;
        }
        Ok(original)
    }

    pub(crate) fn restore(
        &self,
        cx: &Cx,
        client: &mut HttpClient,
        original: Option<ReverseRequestHandlers>,
    ) -> Result<(), HttpClientError> {
        if let Some(handlers) = original {
            client
                .connection
                .set_modern_reverse_request_handlers(handlers)
                .map_err(HttpClientError::CoreResult)?;
        }
        self.check(cx).map_err(HttpClientError::CoreResult)
    }

    pub(super) async fn dispatch(
        &self,
        cx: &Cx,
        call: Call<'_>,
        client: &mut HttpClient,
        wire_cursor: Option<&str>,
    ) -> Result<CallResult, HttpClientError> {
        let original = self.install(cx, client)?;
        let result = match call {
            Call::Reviewed {
                arguments,
                reviewed,
                review,
            } => {
                let checked_review =
                    |binding: &ParameterHeaderBinding| self.approve(cx, || review(binding));
                Call::Reviewed {
                    arguments,
                    reviewed,
                    review: &checked_review,
                }
                .dispatch(cx, &self.cancellation, client, wire_cursor, self)
                .await
            }
            call => {
                call.dispatch(cx, &self.cancellation, client, wire_cursor, self)
                    .await
            }
        };
        // A reusable connection must not retain a prior operation's cancellation
        // or deadline, nor accumulate wrapper layers. On abandonment the whole
        // owned client is dropped by perform_any instead of returning to cache.
        self.restore(cx, client, original)?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use crate::{FinalEmbeddedRootsListResult, ReverseRequestCancellation};
    use fastmcp_core::McpErrorCode;
    use fastmcp_protocol::FinalEmbeddedInputRequest;

    fn boundary(cx: &Cx) -> CallbackBoundary {
        CallbackBoundary {
            closed: McpRequestCancellation::new(),
            cancellation: McpRequestCancellation::new(),
            revoked: McpRequestCancellation::new(),
            deadline: cx.now().saturating_add_nanos(60_000_000_000),
            expires_at: Instant::now() + Duration::from_secs(60),
        }
    }

    struct Owned(Arc<AtomicUsize>);
    impl Drop for Owned {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn ready_roots_callback_cannot_release_an_answer_after_closing_its_owner() {
        for close in [false, true] {
            let cx = Cx::for_testing();
            let boundary = boundary(&cx);
            let closed = boundary.closed.clone();
            let calls = Arc::new(AtomicUsize::new(0));
            let count = calls.clone();
            let handlers = boundary.wrap(ReverseRequestHandlers::new().with_modern_roots_list(
                move |_, _, _| {
                    count.fetch_add(1, Ordering::SeqCst);
                    // This happens in the callback constructor, before it even
                    // returns its ready future, matching the same-poll gap.
                    if close {
                        closed.cancel();
                    }
                    Box::pin(async { Ok(FinalEmbeddedRootsListResult { roots: vec![] }) })
                },
            ));
            let request = || FinalEmbeddedInputRequest::Roots(serde_json::from_str("{}").unwrap());
            let mut answer = Box::pin(handlers.invoke_embedded_input_request_async(
                &cx,
                "roots",
                request(),
                ReverseRequestCancellation::new(),
            ));
            let Poll::Ready(result) = answer
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
            else {
                panic!("ready callback must settle in one poll");
            };
            if close {
                assert_eq!(result.unwrap_err().code, McpErrorCode::RequestCancelled);
                let mut again = Box::pin(handlers.invoke_embedded_input_request_async(
                    &cx,
                    "roots",
                    request(),
                    ReverseRequestCancellation::new(),
                ));
                assert!(matches!(
                    again.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Ready(Err(_))
                ));
            } else {
                assert_eq!(result.unwrap(), serde_json::json!({"roots": []}));
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(!boundary.cancellation.is_cancel_requested());
            assert!(!boundary.revoked.is_cancel_requested());
            assert!(cx.checkpoint().is_ok());
        }
    }

    #[test]
    fn ready_values_are_dropped_for_each_independent_revocation_signal() {
        for signal in 0..3 {
            let cx = Cx::for_testing();
            let boundary = boundary(&cx);
            let cancelled = match signal {
                0 => &boundary.closed,
                1 => &boundary.cancellation,
                _ => &boundary.revoked,
            };
            let drops = Arc::new(AtomicUsize::new(0));
            let mut guarded = Box::pin(boundary.run(&cx, async {
                cancelled.cancel();
                Ok(Owned(drops.clone()))
            }));
            assert!(matches!(
                guarded
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(_))
            ));
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(boundary.closed.is_cancel_requested(), signal == 0);
            assert_eq!(boundary.cancellation.is_cancel_requested(), signal == 1);
            assert_eq!(boundary.revoked.is_cancel_requested(), signal == 2);
            assert!(cx.checkpoint().is_ok());
        }
    }

    #[test]
    fn pending_callback_is_not_polled_again_after_owner_closure() {
        let cx = Cx::for_testing();
        let boundary = boundary(&cx);
        let polls = AtomicUsize::new(0);
        let drops = Arc::new(AtomicUsize::new(0));
        let owned = Owned(drops.clone());
        let operation = async {
            let _owned = owned;
            poll_fn(|_| {
                polls.fetch_add(1, Ordering::SeqCst);
                Poll::<McpResult<()>>::Pending
            })
            .await
        };
        let mut guarded = Box::pin(boundary.run(&cx, operation));
        let mut task = Context::from_waker(Waker::noop());
        assert!(guarded.as_mut().poll(&mut task).is_pending());
        boundary.closed.cancel();
        assert!(matches!(
            guarded.as_mut().poll(&mut task),
            Poll::Ready(Err(_))
        ));
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn live_callback_preserves_its_original_error_without_cancelling_the_owner() {
        let cx = Cx::for_testing();
        let boundary = boundary(&cx);
        let mut guarded = Box::pin(boundary.run(
            &cx,
            std::future::ready(Err::<(), _>(McpError::invalid_params("bad answer"))),
        ));
        let Poll::Ready(Err(error)) = guarded
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        else {
            panic!("the original callback error must be returned");
        };
        assert_eq!(error.code, McpErrorCode::InvalidParams);
        assert_eq!(error.message, "bad answer");
        boundary.check(&cx).unwrap();
    }

    #[test]
    fn review_cannot_approve_after_closure_or_run_after_expiry() {
        let cx = Cx::for_testing();
        let boundary = boundary(&cx);
        let calls = AtomicUsize::new(0);
        assert!(boundary.approve(&cx, || true));
        assert!(!boundary.approve(&cx, || {
            calls.fetch_add(1, Ordering::SeqCst);
            boundary.closed.cancel();
            true
        }));
        assert!(!boundary.approve(&cx, || {
            calls.fetch_add(1, Ordering::SeqCst);
            true
        }));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let mut expired = boundary.clone();
        expired.closed = McpRequestCancellation::new();
        expired.expires_at = Instant::now();
        assert!(!expired.approve(&cx, || panic!("expired review must not run")));
        expired.expires_at = Instant::now() + Duration::from_secs(60);
        expired.deadline = cx.now();
        assert!(!expired.approve(&cx, || panic!("timed-out review must not run")));
    }

    #[test]
    fn wrapping_does_not_advertise_unconfigured_reverse_methods() {
        let cx = Cx::for_testing();
        let boundary = boundary(&cx);
        let empty = boundary.wrap(ReverseRequestHandlers::new());
        assert!(!empty.has_modern_handlers());
        let roots = boundary.wrap(ReverseRequestHandlers::new().with_modern_roots_list(
            |_, _, _| Box::pin(async { Ok(FinalEmbeddedRootsListResult { roots: vec![] }) }),
        ));
        assert!(roots.modern_roots_list.is_some());
        assert!(roots.modern_sampling_create_message.is_none());
        assert!(roots.modern_elicitation_create.is_none());
        assert!(roots.roots_list.is_none());
        assert!(roots.sampling_create_message.is_none());
    }
}

#[cfg(test)]
mod construction_tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use crate::{
        ElicitResult, FinalCreateMessageResult, FinalEmbeddedRootsListResult,
        ReverseRequestCancellation,
    };
    use fastmcp_core::McpErrorCode;
    use fastmcp_protocol::FinalEmbeddedInputRequest;
    use serde_json::json;

    #[derive(Clone, Copy)]
    enum Transition {
        Live,
        Session,
        Request,
        Credential,
        Caller,
    }

    impl Transition {
        fn apply(self, boundary: &CallbackBoundary, cx: &Cx) {
            match self {
                Self::Live => {}
                Self::Session => {
                    boundary.closed.cancel();
                }
                Self::Request => {
                    boundary.cancellation.cancel();
                }
                Self::Credential => {
                    boundary.revoked.cancel();
                }
                Self::Caller => {
                    cx.set_cancel_requested(true);
                }
            }
        }
    }

    #[derive(Default)]
    struct Counts {
        constructed: AtomicUsize,
        polled: AtomicUsize,
        dropped: AtomicUsize,
    }

    struct Owned(Arc<Counts>);
    impl Owned {
        fn polled(&self) {
            self.0.polled.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl Drop for Owned {
        fn drop(&mut self) {
            self.0.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn boundary(cx: &Cx) -> CallbackBoundary {
        CallbackBoundary {
            closed: McpRequestCancellation::new(),
            cancellation: McpRequestCancellation::new(),
            revoked: McpRequestCancellation::new(),
            deadline: cx.now().saturating_add_nanos(60_000_000_000),
            expires_at: Instant::now() + Duration::from_secs(60),
        }
    }

    // Construction is observable separately from the future's first host effect.
    // The live control returns its own typed error; a lifetime refusal must not
    // poll that error-producing body either, nor retain its captured resources.
    fn construct_error<T: Send + 'static>(
        boundary: &CallbackBoundary,
        cx: &Cx,
        transition: Transition,
        counts: Arc<Counts>,
    ) -> Pin<Box<dyn Future<Output = McpResult<T>> + Send>> {
        counts.constructed.fetch_add(1, Ordering::SeqCst);
        transition.apply(boundary, cx);
        let owned = Owned(Arc::clone(&counts));
        Box::pin(async move {
            let _owned = owned;
            counts.polled.fetch_add(1, Ordering::SeqCst);
            Err(McpError::invalid_params("live callback refusal"))
        })
    }

    fn handlers(
        boundary: &CallbackBoundary,
        transition: Transition,
        counts: &Arc<Counts>,
    ) -> ReverseRequestHandlers {
        let roots_boundary = boundary.clone();
        let roots_counts = Arc::clone(counts);
        let sampling_boundary = boundary.clone();
        let sampling_counts = Arc::clone(counts);
        let elicitation_boundary = boundary.clone();
        let elicitation_counts = Arc::clone(counts);
        boundary.wrap(
            ReverseRequestHandlers::new()
                .with_modern_roots_list(move |cx, _, _| {
                    construct_error::<FinalEmbeddedRootsListResult>(
                        &roots_boundary,
                        cx,
                        transition,
                        Arc::clone(&roots_counts),
                    )
                })
                .with_modern_sampling_create_message(move |cx, _, _| {
                    construct_error::<FinalCreateMessageResult>(
                        &sampling_boundary,
                        cx,
                        transition,
                        Arc::clone(&sampling_counts),
                    )
                })
                .with_modern_elicitation_create(move |cx, _, _| {
                    construct_error::<ElicitResult>(
                        &elicitation_boundary,
                        cx,
                        transition,
                        Arc::clone(&elicitation_counts),
                    )
                }),
        )
    }

    #[test]
    fn every_wrapped_constructor_rechecks_authority_before_polling_its_future() {
        let descriptors = [
            json!({"method":"roots/list"}),
            json!({"method":"sampling/createMessage","params":{
                "messages":[{"role":"user","content":{"type":"text","text":"hello"}}],
                "maxTokens":16
            }}),
            json!({"method":"elicitation/create","params":{
                "mode":"form","message":"approve",
                "requestedSchema":{"type":"object","properties":{}}
            }}),
        ];
        for descriptor in descriptors {
            for transition in [
                Transition::Live,
                Transition::Session,
                Transition::Request,
                Transition::Credential,
                Transition::Caller,
            ] {
                let cx = Cx::for_testing();
                let boundary = boundary(&cx);
                let counts = Arc::new(Counts::default());
                let handlers = handlers(&boundary, transition, &counts);
                let request: FinalEmbeddedInputRequest =
                    serde_json::from_value(descriptor.clone()).unwrap();
                let local = ReverseRequestCancellation::new();
                let mut call = Box::pin(handlers.invoke_embedded_input_request_async(
                    &cx,
                    "selected",
                    request,
                    local,
                ));
                let Poll::Ready(Err(error)) =
                    call.as_mut().poll(&mut Context::from_waker(Waker::noop()))
                else {
                    panic!("ready or refused callback must settle on its first poll");
                };
                let live = matches!(transition, Transition::Live);
                assert_eq!(
                    error.code,
                    if live {
                        McpErrorCode::InvalidParams
                    } else {
                        McpErrorCode::RequestCancelled
                    }
                );
                assert_eq!(counts.constructed.load(Ordering::SeqCst), 1);
                assert_eq!(counts.polled.load(Ordering::SeqCst), usize::from(live));
                assert_eq!(counts.dropped.load(Ordering::SeqCst), 1);
                // No guard owns cancellation of the caller or sibling domains.
                assert_eq!(
                    boundary.closed.is_cancel_requested(),
                    matches!(transition, Transition::Session)
                );
                assert_eq!(
                    boundary.cancellation.is_cancel_requested(),
                    matches!(transition, Transition::Request)
                );
                assert_eq!(
                    boundary.revoked.is_cancel_requested(),
                    matches!(transition, Transition::Credential)
                );
                assert_eq!(
                    cx.checkpoint().is_ok(),
                    !matches!(transition, Transition::Caller)
                );
            }
        }
    }

    #[test]
    fn already_invalid_lifetimes_never_construct_host_work() {
        for refusal in 0..6 {
            let cx = Cx::for_testing();
            let mut boundary = boundary(&cx);
            match refusal {
                0 => Transition::Session.apply(&boundary, &cx),
                1 => Transition::Request.apply(&boundary, &cx),
                2 => Transition::Credential.apply(&boundary, &cx),
                3 => Transition::Caller.apply(&boundary, &cx),
                4 => boundary.expires_at = Instant::now(),
                _ => boundary.deadline = cx.now(),
            }
            let calls = AtomicUsize::new(0);
            let mut guarded = Box::pin(boundary.construct_and_run(&cx, || {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok(()))
            }));
            let Poll::Ready(Err(error)) =
                guarded.as_mut().poll(&mut Context::from_waker(Waker::noop()))
            else {
                panic!("invalid authority must fail without invoking its constructor");
            };
            assert_eq!(error.code, McpErrorCode::RequestCancelled);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn constructed_pending_work_is_dropped_without_a_post_cancellation_poll() {
        for transition in [
            Transition::Session,
            Transition::Request,
            Transition::Credential,
            Transition::Caller,
        ] {
            let cx = Cx::for_testing();
            let boundary = boundary(&cx);
            let counts = Arc::new(Counts::default());
            let mut guarded = Box::pin(boundary.construct_and_run(&cx, || {
                counts.constructed.fetch_add(1, Ordering::SeqCst);
                let owned = Owned(Arc::clone(&counts));
                poll_fn(move |_| {
                    owned.polled();
                    Poll::<McpResult<()>>::Pending
                })
            }));
            let mut task = Context::from_waker(Waker::noop());
            assert!(guarded.as_mut().poll(&mut task).is_pending());
            assert_eq!(counts.constructed.load(Ordering::SeqCst), 1);
            assert_eq!(counts.polled.load(Ordering::SeqCst), 1);
            transition.apply(&boundary, &cx);
            let Poll::Ready(Err(error)) = guarded.as_mut().poll(&mut task) else {
                panic!("retired callback must not poll pending host work again");
            };
            assert_eq!(error.code, McpErrorCode::RequestCancelled);
            assert_eq!(counts.polled.load(Ordering::SeqCst), 1);
            assert_eq!(counts.dropped.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn abandoning_a_constructor_owner_neither_starts_nor_orphans_host_work() {
        for started in [false, true] {
            let cx = Cx::for_testing();
            let boundary = boundary(&cx);
            let counts = Arc::new(Counts::default());
            let mut guarded = Box::pin(boundary.construct_and_run(&cx, || {
                counts.constructed.fetch_add(1, Ordering::SeqCst);
                let owned = Owned(Arc::clone(&counts));
                poll_fn(move |_| {
                    owned.polled();
                    Poll::<McpResult<()>>::Pending
                })
            }));
            if started {
                assert!(
                    guarded
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
            }
            drop(guarded);
            assert_eq!(counts.constructed.load(Ordering::SeqCst), usize::from(started));
            assert_eq!(counts.polled.load(Ordering::SeqCst), usize::from(started));
            assert_eq!(counts.dropped.load(Ordering::SeqCst), usize::from(started));
            assert!(!boundary.closed.is_cancel_requested());
            assert!(!boundary.cancellation.is_cancel_requested());
            assert!(!boundary.revoked.is_cancel_requested());
            assert!(cx.checkpoint().is_ok());
        }
    }
}
