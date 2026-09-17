//! B-03 capability proof: `StdioTransport::close` CONSUMES the caller's budget.
//!
//! FND-04 B-03 gave `Transport::close` a `&Cx`, but the signature alone proves
//! only that a budget can be *passed*. As of that landing, zero close bodies in
//! the workspace read the context: 59 ignored it outright and 18 forwarded it
//! into bodies that ignored it. This target proves the first close that actually
//! observes one, so that a green B-03 can mean more than signature plumbing for
//! exactly this transport.
//!
//! These tests are an EXTERNAL CONSUMER of the shipped surface: they construct a
//! `StdioTransport` through `pub fn new`, call the `Transport` trait method, and
//! assert only on public observables. Nothing here reaches into the crate's
//! private test module.
//!
//! On `test-internals`: `Cx::for_testing` is gated behind it and this crate's
//! dev-dependencies enable it for that reason alone. That is NOT the FND-04 B-13
//! trapdoor. The distinction is which side of the boundary the feature sits on -
//! here the feature only CONSTRUCTS a context for the caller, while the API under
//! test (`Transport::close(&mut self, cx: &Cx)`) is fully public and ships
//! without it. The B-13 trap is the reverse: reaching a production capability
//! that exists only under the feature and can never ship.

use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};

use asupersync::Cx;
use fastmcp_transport::{StdioTransport, Transport, TransportError};

/// A writer that records the bytes it received and how often it was flushed.
///
/// The flush count is the load-bearing observable: `close` flushes exactly once
/// on the committed path, and must not flush at all when it refuses.
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

    fn recorded(&self) -> Vec<u8> {
        self.inner
            .lock()
            .expect("writer mutex is uncontended")
            .bytes
            .clone()
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

fn transport_with(writer: CountingWriter) -> StdioTransport<Cursor<Vec<u8>>, CountingWriter> {
    StdioTransport::new(Cursor::new(Vec::new()), writer)
}

fn cancelled_context() -> Cx {
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    cx
}

/// The control: a live context closes, flushes once, and latches terminal.
#[test]
fn stdio_close_under_a_live_context_commits_and_flushes() {
    let writer = CountingWriter::default();
    let mut transport = transport_with(writer.clone());

    assert!(!transport.is_closed());
    transport
        .close(&Cx::for_testing())
        .expect("a live caller context permits the write-side commit");

    assert!(transport.is_closed(), "a committed close latches terminal");
    assert_eq!(
        writer.flushes(),
        1,
        "the committed path flushes the write side exactly once"
    );
}

/// The variable: ONLY the context's cancellation bit differs from the control,
/// and the observable outcome changes. This is the whole point of B-03 -
/// before this change the two runs were indistinguishable.
#[test]
fn stdio_close_under_a_cancelled_context_refuses_before_the_write_side_commit() {
    let writer = CountingWriter::default();
    let mut transport = transport_with(writer.clone());

    let error = transport
        .close(&cancelled_context())
        .expect_err("a cancelled caller context must refuse the close");

    assert!(
        matches!(error, TransportError::Cancelled),
        "cancellation maps to TransportError::Cancelled, not an I/O error: {error:?}"
    );
    assert!(
        !transport.is_closed(),
        "refusing before the write-side commit leaves the transport untouched"
    );
    assert_eq!(
        writer.flushes(),
        0,
        "a refused close performs no blocking flush at all"
    );
    assert!(
        writer.recorded().is_empty(),
        "a refused close writes nothing"
    );
}

/// The refusal is a retryable no-op rather than a terminal failure: the caller
/// may escalate with a fresh budget and still close cleanly. A refusal that
/// stranded the transport would be worse than the unbudgeted close it replaced.
#[test]
fn stdio_close_refusal_leaves_the_transport_closable() {
    let writer = CountingWriter::default();
    let mut transport = transport_with(writer.clone());

    transport
        .close(&cancelled_context())
        .expect_err("the cancelled attempt refuses");
    assert_eq!(writer.flushes(), 0);

    transport
        .close(&Cx::for_testing())
        .expect("a fresh budget still closes after a refusal");

    assert!(transport.is_closed());
    assert_eq!(
        writer.flushes(),
        1,
        "the retry performs the single flush the refusal skipped"
    );
}

/// Idempotency survives cancellation. An already-terminal close performs no I/O,
/// so there is no budget to spend and it must not begin failing merely because
/// the request that once owned the transport was cancelled. This is why the
/// checkpoint sits after the already-closed branch rather than at the top.
#[test]
fn stdio_close_stays_idempotent_under_a_cancelled_context() {
    let writer = CountingWriter::default();
    let mut transport = transport_with(writer.clone());

    transport
        .close(&Cx::for_testing())
        .expect("the first close commits");
    assert_eq!(writer.flushes(), 1);

    transport
        .close(&cancelled_context())
        .expect("closing an already-closed transport stays Ok under cancellation");

    assert!(transport.is_closed());
    assert_eq!(
        writer.flushes(),
        1,
        "the idempotent close performs no second flush"
    );
}
