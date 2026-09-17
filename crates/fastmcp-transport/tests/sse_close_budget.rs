//! B-03 capability proof: `SseWriter::close` CONSUMES the caller's budget.
//!
//! The second blocking-I/O close to observe a budget rather than merely receive
//! one, after `StdioTransport::close`. `SseWriter::close` flushes the write side,
//! and both `SseServerTransport::close` and `SseServerSendHalf::close` delegate
//! to it, so those two transports become budget-aware through this one change.
//!
//! These tests are an EXTERNAL CONSUMER: they construct the writer through the
//! public `fastmcp_transport::sse::SseWriter::new`, call the public `close`, and
//! assert only on public observables.
//!
//! WHY THIS PROOF IS STRONGER THAN THE STDIO ONE. `sse.rs` already guarded ten
//! I/O sites with `cx.is_cancel_requested()`, which observes the explicit
//! cancellation bit and nothing else. A caller whose DEADLINE has expired passes
//! that guard and proceeds into the blocking flush. `close` now uses
//! `sse_checkpoint`, mirroring the stdio and http helpers, so the expired-deadline
//! row below returns `Timeout` where the older idiom would have returned `Ok`
//! after doing the very I/O the caller had run out of budget for. That row is the
//! reason the checkpoint pattern was chosen over this module's local idiom.
//!
//! `Cx::for_testing*` is `test-internals` gated and this crate's dev-dependencies
//! enable it to CONSTRUCT a caller context. The API under test is public and
//! ships without that feature, so this is not the FND-04 B-13 trapdoor, which is
//! the reverse shape: reaching a production capability that exists only under the
//! feature.

use std::io::Write;
use std::sync::{Arc, Mutex};

use asupersync::Cx;
use fastmcp_transport::TransportError;
use fastmcp_transport::sse::SseWriter;

/// Records bytes written and how often the writer was flushed.
///
/// The flush count is the load-bearing observable: it separates "refused BEFORE
/// doing blocking I/O" from "did the I/O and reported an error afterwards",
/// which the returned error alone cannot distinguish.
#[derive(Clone, Default)]
struct CountingWriter {
    inner: Arc<Mutex<WriterState>>,
}

#[derive(Default)]
struct WriterState {
    bytes: Vec<u8>,
    flushes: usize,
}

impl CountingWriter {
    fn flushes(&self) -> usize {
        self.inner.lock().expect("writer mutex is uncontended").flushes
    }

    fn wrote_nothing(&self) -> bool {
        self.inner
            .lock()
            .expect("writer mutex is uncontended")
            .bytes
            .is_empty()
    }
}

impl Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.inner
            .lock()
            .expect("writer mutex is uncontended")
            .bytes
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.lock().expect("writer mutex is uncontended").flushes += 1;
        Ok(())
    }
}

fn cancelled_context() -> Cx {
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    cx
}

/// A context whose deadline has already passed. The cancellation bit is NEVER
/// set here, which is exactly what makes this row distinguish `checkpoint` from
/// `is_cancel_requested`.
fn expired_context() -> Cx {
    Cx::for_testing_with_budget(asupersync::Budget::new().with_deadline(asupersync::Time::ZERO))
}

/// The control: a live context commits and flushes exactly once.
#[test]
fn sse_close_under_a_live_context_commits_and_flushes() {
    let writer = CountingWriter::default();
    let mut sse = SseWriter::new(writer.clone());

    sse.close(&Cx::for_testing())
        .expect("a live caller context permits the terminal commit");

    assert_eq!(
        writer.flushes(),
        1,
        "the committed path flushes the write side exactly once"
    );
}

/// The variable: only the cancellation bit differs from the control.
#[test]
fn sse_close_under_a_cancelled_context_refuses_before_the_flush() {
    let writer = CountingWriter::default();
    let mut sse = SseWriter::new(writer.clone());

    let error = sse
        .close(&cancelled_context())
        .expect_err("a cancelled caller context must refuse the close");

    assert!(
        matches!(error, TransportError::Cancelled),
        "cancellation maps to Cancelled, not an I/O error: {error:?}"
    );
    assert_eq!(writer.flushes(), 0, "a refused close performs no flush");
    assert!(writer.wrote_nothing(), "a refused close writes nothing");
}

/// The row this module's older idiom could not produce. No cancellation bit is
/// set; only the deadline has expired. Under `cx.is_cancel_requested()` this
/// close would have returned `Ok` after flushing.
#[test]
fn sse_close_under_an_expired_deadline_refuses_as_timeout() {
    let writer = CountingWriter::default();
    let mut sse = SseWriter::new(writer.clone());

    let error = sse
        .close(&expired_context())
        .expect_err("an expired caller budget must refuse the close");

    assert!(
        matches!(error, TransportError::Timeout),
        "an exhausted deadline is reported as Timeout, distinctly from Cancelled: {error:?}"
    );
    assert_eq!(
        writer.flushes(),
        0,
        "an out-of-budget caller is not made to wait on the flush"
    );
}

/// A refusal is a retryable no-op, not a wedge. A budget-aware close that
/// stranded the writer on every cancelled caller would be worse than the
/// unbudgeted close it replaced.
#[test]
fn sse_close_refusal_leaves_the_writer_closable() {
    let writer = CountingWriter::default();
    let mut sse = SseWriter::new(writer.clone());

    sse.close(&cancelled_context())
        .expect_err("the cancelled attempt refuses");
    assert_eq!(writer.flushes(), 0);

    sse.close(&Cx::for_testing())
        .expect("a fresh budget still closes after a refusal");

    assert_eq!(
        writer.flushes(),
        1,
        "the retry performs the single flush the refusal skipped"
    );
}

/// Idempotency survives cancellation: a terminal close performs no I/O, so it
/// has no budget to spend and must not begin failing for callers whose original
/// request was cancelled. This is why the checkpoint sits after the
/// already-closed branch rather than at the top of the function.
#[test]
fn sse_close_stays_idempotent_under_a_cancelled_context() {
    let writer = CountingWriter::default();
    let mut sse = SseWriter::new(writer.clone());

    sse.close(&Cx::for_testing())
        .expect("the first close commits");
    assert_eq!(writer.flushes(), 1);

    sse.close(&cancelled_context())
        .expect("closing an already-closed writer stays Ok under cancellation");

    assert_eq!(
        writer.flushes(),
        1,
        "the idempotent close performs no second flush"
    );
}
