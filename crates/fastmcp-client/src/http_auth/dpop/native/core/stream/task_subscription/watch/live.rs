//! A listen body and a single companion future, polled by their caller.
//!
//! No task, session, socket history queue, input replay or proof owner is
//! created here. At most one partially consumed native body frame is retained.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::{Context, Poll};

use asupersync::bytes::Buf;
use asupersync::http::body::Body;
use fastmcp_core::McpRequestCancellation;

use super::*;
use super::super::super::{BYTES_PER_TURN, FRAMES_PER_TURN};
use crate::http_auth::dpop::DpopSession;
use crate::http_auth::dpop::native::{check_live_owner, require_runtime, within_owner};
use crate::http_auth::dpop::native::core::stream::budget::{Budgeted, SharedStreamBudget};

pub(super) struct ReadOwner<'a> {
    pub(super) cx: &'a Cx,
    pub(super) cancellation: &'a McpRequestCancellation,
    owner: McpRequestCancellation,
    pub(super) credential: &'a DpopCredential,
    pub(super) bounds: WaitBounds,
}

impl<'a> ReadOwner<'a> {
    pub(super) fn new(
        cx: &'a Cx, cancellation: &'a McpRequestCancellation,
        session: &DpopSession, credential: &'a DpopCredential, bounds: WaitBounds,
    ) -> Self {
        Self { cx, cancellation, owner: session.cancellation.clone(), credential, bounds }
    }

    fn check(&self, idle: &Idle) -> Result<(), DpopHttpError> {
        check_live_owner(self.cx, self.cancellation, &self.owner, self.credential,
            idle.bounds(self.bounds))?;
        require_runtime(self.cx)
    }
}

pub(super) enum Follow<T> {
    Completed(T),
    // Only input resolution opts in. This is a request for an authoritative
    // get, not adoption of the notification's Task or permission to replay.
    Changed,
    // The first completion retired mutation authority and released its body.
    Stopped,
}

pub(super) enum LiveStep { Hint, Closed }

enum Pump { Idle, Yielded, Hint, Teardown, Closed }

pub(super) struct LiveListen<B: Body> {
    body: Option<B>,
    pending: Option<B::Data>,
    reader: Option<Reader<Budgeted<TaskSubscriptionDecoder>, DpopTaskSubscriptionEvent>>,
    idle: Idle,
    selected: TaskId,
    dirty: bool,
    closed: bool,
    pub(super) budget: SharedStreamBudget,
}

impl<B> LiveListen<B>
where
    B: Body + Unpin,
    B::Data: Buf,
{
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        body: B, kind: crate::http_executor::ModernHttpResponseKind,
        decoder: TaskSubscriptionDecoder, idle: Idle, selected: TaskId,
        limits: DpopStreamLimits, raw_limit: usize, budget: SharedStreamBudget,
    ) -> Result<Self, DpopTaskWatchError> {
        let reader = Reader::<_, DpopTaskSubscriptionEvent>::new(kind, Budgeted::new(decoder, Some(budget.clone())), limits, raw_limit)?;
        Ok(Self { body: Some(body), pending: None, reader: Some(reader), idle,
            selected, dirty: false, closed: false, budget })
    }

    pub(super) fn bounds(&self, absolute: WaitBounds) -> WaitBounds { self.idle.bounds(absolute) }
    pub(super) fn has_hint(&self) -> bool { self.dirty }
    pub(super) fn clear_hint(&mut self) { self.dirty = false; }

    fn teardown(&self) -> bool {
        self.closed || self.reader.as_ref().is_some_and(|reader| reader.terminal.is_some())
    }

    // A quantum is bounded by BOTH bytes and frames, including empty/trailer
    // frames. A pending Buf is always consumed before asking for the next one.
    // No await or application callback occurs while parsing a quantum.
    fn pump(
        &mut self, task: &mut Context<'_>, owner: &ReadOwner<'_>,
        stop_on_hint: bool, stop_on_teardown: bool,
    ) -> Result<Pump, DpopTaskWatchError> {
        owner.check(&self.idle)?;
        let (mut bytes_left, mut frames_left) = (BYTES_PER_TURN, FRAMES_PER_TURN);
        loop {
            if self.closed { return Ok(Pump::Closed); }
            if self.reader.as_ref().is_some_and(Reader::complete) {
                return self.finish_response(owner);
            }
            if self.teardown() {
                if stop_on_teardown { return Ok(Pump::Teardown); }
            } else if stop_on_hint && self.dirty {
                return Ok(Pump::Hint);
            }
            if bytes_left == 0 || frames_left == 0 {
                task.waker().wake_by_ref();
                return Ok(Pump::Yielded);
            }
            if let Some(data) = self.pending.as_mut() {
                if !data.has_remaining() {
                    self.pending = None;
                    continue;
                }
                let bytes = data.chunk();
                let count = bytes.len().min(bytes_left);
                if count == 0 { return Err(DpopHttpError::TransportFailed.into()); }
                let reader = self.reader.as_mut().ok_or(ManagedCoreError::InvalidResponse)?;
                let mut hint = false;
                reader.push_with_check(&bytes[..count], owner.cx, &mut self.idle,
                    &mut |_| { hint = true; true }, |idle| owner.check(idle))?;
                data.advance(count);
                bytes_left -= count;
                if hint {
                    WatchState::require_acknowledged(&reader.decoder.inner, &self.selected)?;
                    self.dirty = true;
                }
                continue;
            }
            let body = self.body.as_mut().ok_or(ManagedCoreError::InvalidResponse)?;
            let frame = match Pin::new(body).poll_frame(task) {
                Poll::Pending => return Ok(Pump::Idle),
                Poll::Ready(frame) => frame.transpose().map_err(|_| DpopHttpError::TransportFailed)?,
            };
            owner.check(&self.idle)?;
            frames_left -= 1;
            if let Some(frame) = frame {
                self.pending = frame.into_data();
            } else {
                return self.finish_response(owner);
            }
        }
    }

    fn finish_response(&mut self, owner: &ReadOwner<'_>) -> Result<Pump, DpopTaskWatchError> {
        let reader = self.reader.take().ok_or(ManagedCoreError::InvalidResponse)?;
        self.pending = None;
        self.body = None;
        self.closed = true;
        let completed = reader.finish_with_check(&self.idle, |idle| owner.check(idle))?;
        // Peer cancellation is not successful completion or recovery authority.
        // Propagate its typed outcome before a final get, reconnect or update.
        completed.result?;
        Ok(Pump::Closed)
    }

    pub(super) async fn next(&mut self, owner: &ReadOwner<'_>)
        -> Result<LiveStep, DpopTaskWatchError>
    {
        let bounds = self.bounds(owner.bounds);
        within_owner(owner.cx, owner.cancellation, &owner.owner, owner.credential, bounds, async {
            Ok(poll_fn(|task| {
                match self.pump(task, owner, true, false) {
                    Ok(Pump::Hint) => Poll::Ready(Ok(LiveStep::Hint)),
                    Ok(Pump::Closed) => Poll::Ready(Ok(LiveStep::Closed)),
                    Ok(_) => Poll::Pending,
                    Err(error) => Poll::Ready(Err(error)),
                }
            }).await)
        }).await?
    }

    // RPCs must settle even if a status hint arrives: aborting an update on a
    // hint could lose its acknowledgement and cause an unsafe mutation retry.
    pub(super) async fn follow<F, T>(
        &mut self, owner: &ReadOwner<'_>, future: F,
    ) -> Result<Follow<T>, DpopTaskWatchError>
    where
        F: Future<Output = Result<T, DpopTaskWatchError>>,
    {
        self.follow_using(owner, future, false).await
    }

    // Unsubmitted input is different: a selected-Task hint invalidates its
    // snapshot before another host poll or answer publication. The host future
    // is dropped, not detached. The watch must discard any unsent staging and
    // perform a fresh authenticated get; this does not acknowledge any answer.
    pub(super) async fn follow_input<F, T>(
        &mut self, owner: &ReadOwner<'_>, future: F,
    ) -> Result<Follow<T>, DpopTaskWatchError>
    where
        F: Future<Output = Result<T, DpopTaskWatchError>>,
    {
        self.follow_using(owner, future, true).await
    }

    // Drain before polling the companion and again before publishing a ready
    // result. A ready terminal therefore beats host work and successor I/O.
    // A completed companion is kept exactly once across receive-side yields;
    // it is never repolled or used before the ready listen prefix is admitted.
    async fn follow_using<F, T>(
        &mut self, owner: &ReadOwner<'_>, future: F, invalidate_on_hint: bool,
    ) -> Result<Follow<T>, DpopTaskWatchError>
    where
        F: Future<Output = Result<T, DpopTaskWatchError>>,
    {
        let bounds = self.bounds(owner.bounds);
        let mut future = std::pin::pin!(future);
        let mut ready = None;
        within_owner(owner.cx, owner.cancellation, &owner.owner, owner.credential, bounds, async {
            Ok(poll_fn(|task| {
                match self.pump(task, owner, false, true) {
                    Ok(Pump::Closed | Pump::Teardown) => return Poll::Ready(Ok(Follow::Stopped)),
                    Err(error) => return Poll::Ready(Err(error)),
                    // Never start/poll a companion or reconcile a hint ahead
                    // of a ready native suffix: it may contain invalid framing.
                    Ok(Pump::Yielded) => return Poll::Pending,
                    Ok(_) => {}
                }
                if invalidate_on_hint && self.dirty {
                    return Poll::Ready(Ok(Follow::Changed));
                }
                if ready.is_none() {
                    match future.as_mut().poll(task) {
                        Poll::Ready(Ok(value)) => ready = Some(value),
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => {}
                    }
                }
                owner.check(&self.idle)?;
                if ready.is_some() {
                    match self.pump(task, owner, false, true) {
                        Ok(Pump::Idle) => {
                            if invalidate_on_hint && self.dirty {
                                return Poll::Ready(Ok(Follow::Changed));
                            }
                            let Some(value) = ready.take() else {
                                return Poll::Ready(Err(ManagedCoreError::InvalidResponse.into()));
                            };
                            return Poll::Ready(Ok(Follow::Completed(value)));
                        }
                        Ok(Pump::Closed | Pump::Teardown) => return Poll::Ready(Ok(Follow::Stopped)),
                        Err(error) => return Poll::Ready(Err(error)),
                        Ok(_) => {}
                    }
                }
                Poll::Pending
            }).await)
        }).await?
    }
}

#[cfg(test)]
mod tests;
