//! Caller-owned, reactor-driven Unix pipe I/O.
//!
//! Unlike the legacy standard-stream wrappers, no poll blocks on a pipe or
//! starts a helper thread. Descriptor ownership and reactor registration stay
//! together; cancellation and deadline observers belong to the same caller.

use std::fs::File;
use std::future::Future;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileTypeExt;
use std::pin::Pin;
use std::task::{Context, Poll};

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::runtime::IoRegistration;
use asupersync::runtime::reactor::Interest;
use asupersync::time::Sleep;
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};

use super::io_checkpoint;

mod stdio;

struct PipeWait {
    registration: IoRegistration,
    cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
    deadline: Option<Pin<Box<Sleep>>>,
}

impl PipeWait {
    fn new(cx: &Cx, file: &File, interest: Interest) -> io::Result<Self> {
        let registration = cx.register_io(file, interest)?;
        let owner = cx.clone();
        let cancelled = Box::pin(async move {
            let (sender, mut receiver) = oneshot::channel::<()>();
            // An unsent receive supplies the runtime's owned cancellation
            // registration. The sender cannot disappear before that wait.
            let _ = receiver.recv(&owner).await;
            drop(sender);
        });
        Ok(Self {
            registration,
            cancelled,
            deadline: cx.budget().deadline.map(|at| Box::pin(Sleep::new(at))),
        })
    }
}

struct PipeIo {
    // Fields drop in declaration order: unregister before closing/reusing fd.
    wait: Option<PipeWait>,
    file: Option<File>,
    cx: Cx,
    interest: Interest,
    // Restore process-stream flags only after registration and endpoint drop.
    process_stream: Option<stdio::ProcessStreamLease>,
}

impl std::fmt::Debug for PipeIo {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PipeIo")
            .field("closed", &self.file.is_none())
            .field("waiting", &self.wait.is_some())
            .finish_non_exhaustive()
    }
}

/// Refuses native pipe I/O while an ambient capability restriction excludes it.
///
/// THIS MUST RUN BEFORE `Cx::set_current(Some(cx.clone()))`, and the ordering is
/// the entire point. `set_current` publishes a frame carrying the supplied cx's
/// OWN `runtime_mask` (asupersync 0.5.0 cx.rs:824), so republishing a fully
/// capable caller cx on top of a narrowed ambient view SILENTLY WIDENS it: a
/// host that wrapped this call in `Cx::push_restriction(CapMask::none())` would
/// have its restriction laundered away, and the `Cx::current()` lookup that
/// follows would hand back full I/O authority. `set_current_restricted` does not
/// help here either -- it intersects the type-level caps with the cx's own
/// runtime mask, not with the frame currently in force.
///
/// Checking the active view first makes admission the INTERSECTION of the
/// explicitly passed authority and any ambient restriction, which fails closed.
/// Only the I/O dimension is examined: the ambient view is not the caller's
/// cancellation or deadline domain, so running the full `admit_context` against
/// it could refuse for reasons that have nothing to do with authority.
pub(super) fn admit_ambient_io_restriction() -> io::Result<()> {
    if let Some(active) = Cx::current() {
        if !active.capabilities().io {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "native pipe I/O is refused while an ambient restriction excludes \
                 the I/O capability",
            ));
        }
    }
    Ok(())
}

fn admit_context(cx: &Cx) -> io::Result<()> {
    io_checkpoint(cx)?;
    if !cx.capabilities().io {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "native pipe I/O requires the caller's I/O capability",
        ));
    }
    if cx.budget().deadline.is_some() && cx.timer_driver().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "native pipe deadline requires the caller's timer driver",
        ));
    }
    Ok(())
}

impl PipeIo {
    fn new(cx: &Cx, fd: OwnedFd, writable: bool) -> io::Result<Self> {
        admit_ambient_io_restriction()?;
        let _caller = Cx::set_current(Some(cx.clone()));
        let caller = Cx::current().ok_or_else(|| io::Error::other("caller context unavailable"))?;
        admit_context(&caller)?;
        let file = File::from(fd);
        if !file.metadata()?.file_type().is_fifo() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native pipe I/O requires a FIFO, not a regular file or device",
            ));
        }
        let flags = fcntl_getfl(&file).map_err(io::Error::from)?;
        if !flags.contains(OFlags::NONBLOCK) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native pipe descriptor must already be nonblocking",
            ));
        }
        let can_write = flags.intersects(OFlags::WRONLY | OFlags::RDWR);
        let can_read = !flags.contains(OFlags::WRONLY);
        if (writable && !can_write) || (!writable && !can_read) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native pipe descriptor has the wrong access direction",
            ));
        }
        let interest = if writable {
            Interest::WRITABLE
        } else {
            Interest::READABLE
        };
        // Establish that this exact caller can register the source before any
        // bytes move. Do not retain an idle noop waker between construction
        // and the first operation, or borrow another runtime as a fallback.
        caller.register_io(&file, interest)?.deregister()?;
        Ok(Self {
            wait: None,
            file: Some(file),
            cx: caller,
            interest,
            process_stream: None,
        })
    }

    fn poll_io<T>(
        &mut self,
        task: &mut Context<'_>,
        operation: impl FnOnce(&File) -> io::Result<T>,
    ) -> Poll<io::Result<T>> {
        if let Err(error) = admit_ambient_io_restriction() {
            return Poll::Ready(Err(error));
        }
        let _caller = Cx::set_current(Some(self.cx.clone()));
        let admission = (|| {
            let caller =
                Cx::current().ok_or_else(|| io::Error::other("caller context unavailable"))?;
            admit_context(&caller)?;
            if let Some(stream) = &self.process_stream {
                stream.verify_io()?;
            }
            let file = self.file.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "native pipe is closed")
            })?;
            if self.wait.is_none() {
                self.wait = Some(PipeWait::new(&caller, file, self.interest)?);
            }
            let wait = self.wait.as_mut().expect("one admitted pipe wait");
            if wait.cancelled.as_mut().poll(task).is_ready() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "native pipe caller was cancelled",
                ));
            }
            if wait
                .deadline
                .as_mut()
                .is_some_and(|deadline| deadline.as_mut().poll(task).is_ready())
            {
                // Checkpoint is authoritative under cancellation masking.
                // A completed masked timer must not be polled or self-woken
                // repeatedly while the peer remains silent.
                wait.deadline = None;
                io_checkpoint(&caller)?;
            }
            // Arm with the actual task waker BEFORE attempting the syscall.
            // Readiness arriving between EAGAIN and registration must not be
            // lost, and a migrated task must replace the previous waker.
            if !wait.registration.rearm(self.interest, task.waker())? {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "native pipe I/O registration was retired",
                ));
            }
            Ok(())
        })();
        if let Err(error) = admission {
            self.wait = None;
            return Poll::Ready(Err(error));
        }
        let result = operation(self.file.as_ref().expect("admitted owned pipe"));
        match result {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                // Yield rather than spinning through an unbounded signal
                // storm inside one poll. No bytes were committed by EINTR.
                task.waker().wake_by_ref();
                Poll::Pending
            }
            result => {
                // The syscall is the commitment boundary. Never re-check a
                // deadline/cancellation after consuming or publishing bytes.
                self.wait = None;
                Poll::Ready(result)
            }
        }
    }

    fn close(&mut self) -> io::Result<()> {
        let result = self.wait.take().map_or(Ok(()), |wait| {
            let PipeWait { registration, .. } = wait;
            registration.deregister()
        });
        // Close even if deregistration reports a failure. Close is cleanup,
        // not new work, and must remain possible on a cancelled caller.
        self.file = None;
        let restored = self
            .process_stream
            .take()
            .map_or(Ok(()), stdio::ProcessStreamLease::finish);
        result.and(restored)
    }
}

/// Nonblocking Unix pipe reader bound to an explicit caller runtime.
///
/// Pass this to `AsyncStdioTransport::from_io` or the server's `serve_stdio_io`
/// entrypoint. A silent peer parks on the caller's reactor without a blocking
/// pool or helper thread. Cancellation and finite deadlines wake that wait.
///
/// One pending registration is retained in the reader, not in the borrowed
/// `AsyncReadExt` future. It is replaced by the next operation and retired on
/// completion or reader drop. Dropping only a borrowed read future consumes
/// no additional bytes, but keep or drop the reader deliberately.
#[derive(Debug)]
pub struct NativePipeReader(PipeIo);

impl NativePipeReader {
    /// Takes ownership of an already-nonblocking readable FIFO descriptor.
    ///
    /// Does not change descriptor status flags. An `OwnedFd` can still share
    /// its open-file description with duped/inherited descriptors; the caller
    /// must keep those aliases from changing flags or competing for the same
    /// bytes while this adapter is alive. Regular files/devices, a wrong
    /// access direction, or a missing caller reactor are rejected before I/O.
    /// On error the supplied owned descriptor is closed.
    pub fn from_owned_fd(cx: &Cx, fd: OwnedFd) -> io::Result<Self> {
        PipeIo::new(cx, fd, false).map(Self)
    }
}

impl AsyncRead for NativePipeReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        task: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 || self.0.file.is_none() {
            return Poll::Ready(Ok(()));
        }
        match self.0.poll_io(task, |file| {
            rustix::io::read(file, output.unfilled()).map_err(io::Error::from)
        }) {
            Poll::Ready(Ok(read)) => {
                output.advance(read);
                if read == 0 {
                    self.0.close()?;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Nonblocking, unbuffered Unix pipe writer bound to a caller runtime.
///
/// Each successful write reports exactly the committed byte count; a full
/// pipe yields on reactor readiness. Higher-level framing owns partial-write
/// recovery. `poll_shutdown` releases this endpoint so a peer can drain bytes
/// then observe EOF; it does not close separately duplicated descriptors.
#[derive(Debug)]
pub struct NativePipeWriter(PipeIo);

impl NativePipeWriter {
    /// Takes ownership of an already-nonblocking writable FIFO descriptor.
    ///
    /// The same flag, aliasing, caller-runtime, and error-ownership contract as
    /// [`NativePipeReader::from_owned_fd`] applies. It never changes a shared
    /// open-file description merely to make a blocking descriptor appear async.
    pub fn from_owned_fd(cx: &Cx, fd: OwnedFd) -> io::Result<Self> {
        PipeIo::new(cx, fd, true).map(Self)
    }
}

impl AsyncWrite for NativePipeWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        task: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.0.file.is_none() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "native pipe writer is closed",
            )));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.0.poll_io(task, |file| {
            rustix::io::write(file, bytes).map_err(io::Error::from)
        })
    }

    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        // No user-space buffer exists. This cannot undo bytes committed by
        // write, and also retires an abandoned pending write observation.
        self.0.wait = None;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.0.close())
    }
}

fn fresh_descriptors() -> io::Result<(OwnedFd, OwnedFd)> {
    let (reader, writer) = io::pipe()?;
    let reader: OwnedFd = reader.into();
    let writer: OwnedFd = writer.into();
    // Only fresh, unpublished endpoints are changed here. The owned-fd
    // constructors intentionally never mutate caller-supplied status flags.
    for fd in [&reader, &writer] {
        let flags = fcntl_getfl(fd).map_err(io::Error::from)?;
        fcntl_setfl(fd, flags | OFlags::NONBLOCK).map_err(io::Error::from)?;
    }
    Ok((reader, writer))
}

/// Creates a new anonymous Unix pipe using the caller's reactor.
///
/// Both endpoints are nonblocking before being returned. Create two pipes
/// for full-duplex MCP framing, and pair the opposite ends with
/// `AsyncStdioTransport::from_io` or `Server::serve_stdio_io`. This function
/// neither changes process stdin/stdout nor starts a runtime or thread.
/// Existing child/process pipe endpoints can instead be explicitly admitted
/// with the owned-fd constructors after the embedding establishes nonblocking
/// mode and exclusive byte ownership.
pub fn native_pipe(cx: &Cx) -> io::Result<(NativePipeReader, NativePipeWriter)> {
    admit_context(cx)?;
    let (reader, writer) = fresh_descriptors()?;
    Ok((
        NativePipeReader::from_owned_fd(cx, reader)?,
        NativePipeWriter::from_owned_fd(cx, writer)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};
    use std::time::Duration;

    use asupersync::runtime::reactor::create_reactor;
    use asupersync::runtime::{IoDriverHandle, Runtime, RuntimeBuilder};
    use asupersync::time::{TimerDriverHandle, VirtualClock};
    use asupersync::{Budget, Time};

    #[derive(Default)]
    struct Wakes(AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn runtime() -> Runtime {
        RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().unwrap())
            .blocking_threads(0, 0)
            .build()
            .unwrap()
    }

    fn ready<T>(value: Poll<io::Result<T>>) -> T {
        match value {
            Poll::Ready(Ok(value)) => value,
            Poll::Ready(Err(error)) => panic!("unexpected I/O failure: {error}"),
            Poll::Pending => panic!("nonblocking operation unexpectedly waited"),
        }
    }

    fn read(
        reader: &mut NativePipeReader,
        waker: &Waker,
        bytes: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut output = ReadBuf::new(bytes);
        Pin::new(reader)
            .poll_read(&mut Context::from_waker(waker), &mut output)
            .map(|result| result.map(|()| output.filled().len()))
    }

    fn write(
        writer: &mut NativePipeWriter,
        waker: &Waker,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(writer).poll_write(&mut Context::from_waker(waker), bytes)
    }

    fn close(writer: &mut NativePipeWriter) {
        ready(Pin::new(writer).poll_shutdown(&mut Context::from_waker(Waker::noop())));
    }

    fn await_wake(driver: &IoDriverHandle, wakes: &Wakes) {
        // `try_turn_with` rather than `turn_with`, and the outcome is RECORDED
        // rather than discarded. `IoDriverHandle::turn_with` delegates to this
        // and collapses `Ok(None)` into `Ok(0)`, so the caller cannot tell
        // "polled the reactor, saw no events" from "never polled at all
        // because another holder had the is_polling CAS". asupersync's own doc
        // on turn_with names this: "Callers that need explicit contention
        // signaling can use try_turn_with."
        //
        // That distinction is the whole diagnosis here. A contended turn
        // returns IMMEDIATELY, so eight of them spend none of the nominal
        // 8 x 100 ms and the loop can fail in microseconds without any timeout
        // having elapsed. The driver's own `polls` counter stays 0 in that
        // case, which is outside the range the panic text below was written to
        // interpret, and it makes `events_received == 0` uninformative about
        // whether the pipe was ever armed.
        //
        // AND the contended branch now actually spends its slice. This is the
        // defect the instrumentation found: measured over five failures, every
        // one reported contended=8/8 polled=0 with elapsed between 1.2 and 5.2
        // MICROSECONDS, against a nominal 8 x 100 ms. A contended turn returns
        // instantly, so the loop burned all eight iterations and panicked
        // having waited essentially no time at all. The driver's own `polls`
        // counter was simultaneously 1, 2 or 4 while this loop polled ZERO
        // times, which proves another holder was driving the same driver, and
        // one failure reported events_received=1 wakers_dispatched=1: the
        // readiness arrived and a waker was dispatched, microseconds after
        // this loop had already given up.
        //
        // So when the CAS is lost there is a concurrent poller that will
        // deliver the wake, and the correct response is to WAIT for it rather
        // than to spin no-ops. Waiting on contention keeps the nominal budget
        // exactly as it was, 8 x 100 ms = 800 ms worst case. The bound is
        // unchanged and the assertion is unchanged; the only change is that
        // the budget is now actually spent instead of being skipped. Without
        // this the eight turns are not a wait at all.
        // The budget is a DEADLINE rather than an iteration count, so that the
        // same 800 ms covers both paths exactly. With a plain `for 0..8` the
        // two paths cost different amounts of time for the same number of
        // turns, which is how the contended path came to spend nothing at all.
        //
        // The contended slice is deliberately much finer than the turn
        // timeout. Sleeping a full 100 ms on contention is correct but
        // wasteful: measured, it took this crate's lib suite from 1.96 s to
        // 7.83 s, because a wake that arrives a few ms in still costs the
        // whole slice. 10 ms keeps the identical 800 ms ceiling while
        // surrendering at most 10 ms after the wake is actually available.
        const BUDGET: Duration = Duration::from_millis(800);
        const TURN_SLICE: Duration = Duration::from_millis(100);
        const CONTENDED_SLICE: Duration = Duration::from_millis(10);
        let started = std::time::Instant::now();
        let mut contended = 0_u32;
        let mut polled = 0_u32;
        loop {
            let left = BUDGET.saturating_sub(started.elapsed());
            if left.is_zero() {
                break;
            }
            match driver
                .try_turn_with(Some(TURN_SLICE.min(left)), |_, _| {})
                .unwrap()
            {
                Some(_) => polled += 1,
                None => {
                    contended += 1;
                    std::thread::sleep(CONTENDED_SLICE.min(left));
                }
            }
            if wakes.0.load(Ordering::SeqCst) > 0 {
                return;
            }
        }
        let elapsed = started.elapsed();
        // Name the state rather than only the symptom. "did not wake" has
        // THREE causes, and `polled` is the one that has to be read first
        // because a zero there invalidates the other two:
        //   polled == 0           -> this caller never polled the reactor at
        //                            all; every turn lost the is_polling CAS.
        //                            events_received is then 0 by construction
        //                            and says NOTHING about whether the fd was
        //                            armed. `elapsed` should still be close to
        //                            the 800ms budget, because the contended
        //                            branch now waits; an `elapsed` in the
        //                            MICROSECONDS would mean the budget is
        //                            being skipped again, which is the exact
        //                            regression this loop was repaired for.
        //   events_received == 0
        //     with contended == 0 -> the reactor really was polled and really
        //                            saw no readiness, so the fd is not armed
        //                            even though a waker slot exists
        //                            (waker_count > 0). This is the reading
        //                            that implicates the pipe.
        //   unknown_tokens > 0    -> readiness DID arrive but its token had no
        //                            waker, i.e. the registration and the
        //                            turned driver disagree.
        // `polls` is the driver's own count and should equal this loop's
        // `polled`; a disagreement means some other holder is also turning
        // this driver, which is itself the answer to the contention question.
        let stats = driver.stats();
        panic!(
            "pipe readiness did not wake its registered task \
             (contended={contended} polled={polled} elapsed={elapsed:?} \
             wakers={} polls={} events_received={} wakers_dispatched={} \
             unknown_tokens={} registrations={} deregistrations={})",
            driver.waker_count(),
            stats.polls,
            stats.events_received,
            stats.wakers_dispatched,
            stats.unknown_tokens,
            stats.registrations,
            stats.deregistrations,
        );
    }

    fn fill(file: &File) -> usize {
        let block = [7_u8; 4096];
        let mut bytes = 0;
        for _ in 0..4096 {
            match rustix::io::write(file, &block) {
                Ok(written) => bytes += written,
                Err(rustix::io::Errno::AGAIN) => return bytes,
                Err(rustix::io::Errno::INTR) => {}
                Err(error) => panic!("filling the pipe failed: {error}"),
            }
        }
        panic!("pipe did not apply backpressure within 16 MiB");
    }

    #[test]
    fn native_pipe_readiness_updates_waker_and_preserves_data_through_eof() {
        let runtime = runtime();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        assert!(cx.blocking_pool_handle().is_none());
        let driver = cx.io_driver_handle().unwrap();
        let (mut reader, mut writer) = native_pipe(&cx).unwrap();
        let old = Arc::new(Wakes::default());
        let current = Arc::new(Wakes::default());
        let old_waker = Waker::from(Arc::clone(&old));
        let waker = Waker::from(Arc::clone(&current));
        let mut bytes = [0; 8];
        assert!(read(&mut reader, &old_waker, &mut bytes).is_pending());
        assert!(read(&mut reader, &waker, &mut bytes).is_pending());
        assert_eq!(driver.waker_count(), 1);
        assert_eq!(ready(write(&mut writer, Waker::noop(), b"native")), 6);
        await_wake(&driver, &current);
        assert_eq!(old.0.load(Ordering::SeqCst), 0);
        assert_eq!(ready(read(&mut reader, &waker, &mut bytes)), 6);
        assert_eq!(&bytes[..6], b"native");
        assert_eq!(driver.waker_count(), 0);
        assert!(read(&mut reader, &waker, &mut bytes).is_pending());
        current.0.store(0, Ordering::SeqCst);
        close(&mut writer);
        await_wake(&driver, &current);
        assert_eq!(ready(read(&mut reader, &waker, &mut bytes)), 0);
        assert_eq!(ready(read(&mut reader, &waker, &mut bytes)), 0);
        assert_eq!(driver.waker_count(), 0);
        drop((reader, writer, cx));
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn native_pipe_backpressure_yields_and_wakes_without_duplicating_bytes() {
        let runtime = runtime();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let driver = cx.io_driver_handle().unwrap();
        let (mut reader, mut writer) = native_pipe(&cx).unwrap();
        let retained = fill(writer.0.file.as_ref().unwrap());
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        assert!(write(&mut writer, &waker, b"tail").is_pending());
        assert_eq!(driver.waker_count(), 1);
        let mut block = [0_u8; 8192];
        let first = ready(read(&mut reader, Waker::noop(), &mut block));
        assert!(first > 0);
        assert!(block[..first].iter().all(|byte| *byte == 7));
        await_wake(&driver, &wakes);
        assert_eq!(ready(write(&mut writer, &waker, b"tail")), 4);
        close(&mut writer);
        let mut rest = Vec::new();
        loop {
            let count = ready(read(&mut reader, Waker::noop(), &mut block));
            if count == 0 {
                break;
            }
            rest.extend_from_slice(&block[..count]);
        }
        assert_eq!(rest.len(), retained - first + 4);
        assert!(rest[..rest.len() - 4].iter().all(|byte| *byte == 7));
        assert_eq!(&rest[rest.len() - 4..], b"tail");
        assert_eq!(driver.waker_count(), 0);
        drop((reader, writer, cx));
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn native_pipe_cancellation_wakes_silent_read_without_consuming_late_bytes() {
        let runtime = runtime();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let live = runtime.request_cx_with_budget(Budget::INFINITE);
        let driver = cx.io_driver_handle().unwrap();
        let (input, output) = fresh_descriptors().unwrap();
        let mut reader = NativePipeReader::from_owned_fd(&cx, input).unwrap();
        let mut writer = NativePipeWriter::from_owned_fd(&live, output).unwrap();
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut bytes = [0; 4];
        assert!(read(&mut reader, &waker, &mut bytes).is_pending());
        cx.set_cancel_requested(true);
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            read(&mut reader, &waker, &mut bytes),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted
        ));
        assert_eq!(bytes, [0; 4]);
        assert_eq!(driver.waker_count(), 0);
        assert_eq!(ready(write(&mut writer, Waker::noop(), b"late")), 4);
        // Masked cleanup may consume the same committed bytes. The cancelled
        // attempt above did not consume them or latch the endpoint closed.
        assert_eq!(
            cx.masked(|| ready(read(&mut reader, &waker, &mut bytes))),
            4
        );
        assert_eq!(&bytes, b"late");
        close(&mut writer);
        drop((reader, writer, cx, live));
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn native_pipe_cancelled_backpressured_write_preserves_queue_and_allows_shutdown() {
        let runtime = runtime();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let live = runtime.request_cx_with_budget(Budget::INFINITE);
        let driver = cx.io_driver_handle().unwrap();
        let (input, output) = fresh_descriptors().unwrap();
        let mut reader = NativePipeReader::from_owned_fd(&live, input).unwrap();
        let mut writer = NativePipeWriter::from_owned_fd(&cx, output).unwrap();
        let retained = fill(writer.0.file.as_ref().unwrap());
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        assert!(write(&mut writer, &waker, b"must-not-publish").is_pending());
        cx.set_cancel_requested(true);
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            write(&mut writer, &waker, b"must-not-publish"),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted
        ));
        assert_eq!(driver.waker_count(), 0);
        close(&mut writer);
        close(&mut writer);
        let mut bytes = [0; 8192];
        let mut total = 0;
        loop {
            let count = ready(read(&mut reader, Waker::noop(), &mut bytes));
            if count == 0 {
                break;
            }
            assert!(bytes[..count].iter().all(|byte| *byte == 7));
            total += count;
        }
        assert_eq!(total, retained);
        drop((reader, writer, cx, live));
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn native_pipe_deadline_and_drop_retire_timer_io_and_cancellation_wakers() {
        for abandon in [false, true] {
            let clock = Arc::new(VirtualClock::new());
            let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
            let runtime = RuntimeBuilder::current_thread()
                .with_reactor(create_reactor().unwrap())
                .with_timer_driver(timer.clone())
                .blocking_threads(0, 0)
                .build()
                .unwrap();
            let cx = runtime.request_cx_with_budget(
                Budget::INFINITE.with_deadline(Time::from_nanos(10_000_000)),
            );
            let driver = cx.io_driver_handle().unwrap();
            let (mut reader, writer) = native_pipe(&cx).unwrap();
            let wakes = Arc::new(Wakes::default());
            let waker = Waker::from(Arc::clone(&wakes));
            let mut bytes = [0; 1];
            assert!(read(&mut reader, &waker, &mut bytes).is_pending());
            assert_eq!(driver.waker_count(), 1);
            assert!(timer.pending_count() > 0);
            if abandon {
                drop(reader);
                assert_eq!(timer.pending_count(), 0);
                assert_eq!(driver.waker_count(), 0);
                clock.advance(10_000_000);
                assert_eq!(timer.process_timers(), 0);
                cx.set_cancel_requested(true);
                assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
            } else {
                clock.advance(9_999_999);
                assert_eq!(timer.process_timers(), 0);
                assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
                clock.advance(1);
                assert!(timer.process_timers() > 0);
                assert!(wakes.0.load(Ordering::SeqCst) > 0);
                assert!(matches!(
                    read(&mut reader, &waker, &mut bytes),
                    Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted
                ));
                assert_eq!(timer.pending_count(), 0);
                assert_eq!(driver.waker_count(), 0);
                drop(reader);
            }
            drop((writer, cx));
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }

    #[test]
    fn native_pipe_rejects_blocking_and_wrong_direction_without_changing_alias_flags() {
        let runtime = runtime();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let (input, output) = io::pipe().unwrap();
        let alias = input.try_clone().unwrap();
        let original = fcntl_getfl(&alias).unwrap();
        assert!(!original.contains(OFlags::NONBLOCK));
        let error = NativePipeReader::from_owned_fd(&cx, input.into()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fcntl_getfl(&alias).unwrap(), original);
        drop((alias, output));
        let (input, output) = fresh_descriptors().unwrap();
        assert_eq!(
            NativePipeWriter::from_owned_fd(&cx, input)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            NativePipeReader::from_owned_fd(&cx, output)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        let regular = File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
        assert_eq!(
            NativePipeReader::from_owned_fd(&cx, regular.into())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(cx.io_driver_handle().unwrap().waker_count(), 0);
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn native_pipe_refuses_driverless_or_restricted_callers_before_consuming_bytes() {
        let detached = Cx::for_testing();
        let (input, output) = fresh_descriptors().unwrap();
        assert_eq!(
            NativePipeReader::from_owned_fd(&detached, input)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );
        drop(output);
        let runtime = runtime();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let (mut reader, mut writer) = native_pipe(&cx).unwrap();
        assert_eq!(ready(write(&mut writer, Waker::noop(), b"kept")), 4);
        let mut bytes = [0; 4];
        {
            let _ambient = Cx::set_current(Some(cx.clone()));
            let _restriction = Cx::push_restriction(asupersync::cx::cap::CapMask::none());
            assert!(matches!(
                read(&mut reader, Waker::noop(), &mut bytes),
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::PermissionDenied
            ));
            assert_eq!(bytes, [0; 4]);
            let (input, output) = fresh_descriptors().unwrap();
            assert_eq!(
                NativePipeReader::from_owned_fd(&cx, input)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
            drop(output);
        }
        assert_eq!(ready(read(&mut reader, Waker::noop(), &mut bytes)), 4);
        assert_eq!(&bytes, b"kept");
        drop((reader, writer, cx));
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn native_pipe_registers_only_with_its_bound_runtime_under_foreign_ambient_context() {
        let owner = runtime();
        let foreign = runtime();
        let cx = owner.request_cx_with_budget(Budget::INFINITE);
        let foreign_cx = foreign.request_cx_with_budget(Budget::INFINITE);
        let own_driver = cx.io_driver_handle().unwrap();
        let foreign_driver = foreign_cx.io_driver_handle().unwrap();
        let (mut reader, mut writer) = native_pipe(&cx).unwrap();
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut bytes = [0; 4];
        {
            let _ambient = Cx::set_current(Some(foreign_cx.clone()));
            assert!(read(&mut reader, &waker, &mut bytes).is_pending());
            assert_eq!(own_driver.waker_count(), 1);
            assert_eq!(foreign_driver.waker_count(), 0);
            assert_eq!(ready(write(&mut writer, Waker::noop(), b"own!")), 4);
            await_wake(&own_driver, &wakes);
            assert_eq!(ready(read(&mut reader, &waker, &mut bytes)), 4);
            assert_eq!(&bytes, b"own!");
            assert_eq!(own_driver.waker_count(), 0);
            assert_eq!(foreign_driver.waker_count(), 0);
        }
        drop((reader, writer, cx, foreign_cx));
        assert!(owner.shutdown_timeout(Duration::from_secs(1)));
        assert!(foreign.shutdown_timeout(Duration::from_secs(1)));
    }
}
