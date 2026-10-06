//! Explicit process-standard-stream ownership for the native pipe backend.
//!
//! Keep a duplicate of the open-file description until reactor deregistration
//! and endpoint close have completed. Never close or replace process fd 0/1.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::FileTypeExt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, LazyLock};

use asupersync::Cx;
use fastmcp_core::runtime::{ProcessBoundToken, ProcessGenerationGuard};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};

use super::{NativePipeReader, NativePipeWriter, PipeIo, admit_context};

const FREE: u8 = 0;
const HELD: u8 = 1;
const POISONED: u8 = 2;

static STDIN_OWNER: LazyLock<Arc<AtomicU8>> = LazyLock::new(|| Arc::new(AtomicU8::new(FREE)));
static STDOUT_OWNER: LazyLock<Arc<AtomicU8>> = LazyLock::new(|| Arc::new(AtomicU8::new(FREE)));

/// This field is dropped AFTER the pipe's I/O registration and owned endpoint.
/// Its separate descriptor keeps restoration attached to the same open-file
/// description even if somebody later replaces process fd 0 or fd 1.
pub(super) struct ProcessStreamLease {
    state: Arc<AtomicU8>,
    process: ProcessBoundToken,
    descriptor: Option<OwnedFd>,
    flags: Option<(OFlags, OFlags)>,
    finished: bool,
}

impl ProcessStreamLease {
    fn reserve(state: Arc<AtomicU8>) -> io::Result<Self> {
        let guard = ProcessGenerationGuard::install()
            .map_err(|_| io::Error::other("native stdio process guard unavailable"))?;
        guard.verify_current()
            .map_err(|_| io::Error::other("native stdio process changed"))?;
        state.compare_exchange(FREE, HELD, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|state| {
                if state == HELD {
                    io::Error::new(io::ErrorKind::AlreadyExists, "process stream already has a native owner")
                } else {
                    io::Error::other("previous native process-stream cleanup could not be verified")
                }
            })?;
        Ok(Self {
            state,
            process: guard.token(),
            descriptor: None,
            flags: None,
            finished: false,
        })
    }

    pub(super) fn verify_io(&self) -> io::Result<()> {
        self.process.verify()
            .map_err(|_| io::Error::other("native stdio process changed"))?;
        let descriptor = self.descriptor.as_ref()
            .ok_or_else(|| io::Error::other("native stdio descriptor custody unavailable"))?;
        let current = fcntl_getfl(descriptor).map_err(io::Error::from)?;
        // An alias clearing NONBLOCK must not send this poll into a blocking
        // syscall. Alias mutation concurrently with a syscall is outside the
        // constructor's exclusive-use contract; this is not a global fd lock.
        if !current.contains(OFlags::NONBLOCK) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native process stream lost nonblocking mode",
            ));
        }
        Ok(())
    }

    fn restore(&self) -> io::Result<()> {
        // A forked child must not restore flags on the parent's shared open-
        // file description. Verification comes before any descriptor syscall.
        self.process.verify()
            .map_err(|_| io::Error::other("native stdio process changed before cleanup"))?;
        let Some((original, enabled)) = self.flags else { return Ok(()); };
        let descriptor = self.descriptor.as_ref()
            .ok_or_else(|| io::Error::other("native stdio restoration descriptor unavailable"))?;
        let current = fcntl_getfl(descriptor).map_err(io::Error::from)?;
        if current == original {
            return Ok(());
        }
        if current != enabled {
            // Do not overwrite an unrelated owner's later flag changes.
            return Err(io::Error::other("native process-stream flags changed outside their owner"));
        }
        fcntl_setfl(descriptor, original).map_err(io::Error::from)
    }

    fn finish_once(&mut self) -> io::Result<()> {
        if self.finished { return Ok(()); }
        let result = self.restore();
        self.finished = true;
        // Once cleanup is uncertain, a new constructor must not reinterpret
        // the currently observed flags as the original, known-good state.
        self.state.store(if result.is_ok() { FREE } else { POISONED }, Ordering::Release);
        result
    }

    pub(super) fn finish(mut self) -> io::Result<()> {
        self.finish_once()
    }
}

impl Drop for ProcessStreamLease {
    fn drop(&mut self) {
        // Explicit reader close / writer shutdown reports this error. Drop is
        // best effort and leaves an uncertain ownership domain poisoned.
        let _ = self.finish_once();
    }
}

fn claim(cx: &Cx, source: &impl AsFd, writable: bool, state: Arc<AtomicU8>) -> io::Result<PipeIo> {
    let _caller = Cx::set_current(Some(cx.clone()));
    let caller = Cx::current().ok_or_else(|| io::Error::other("caller context unavailable"))?;
    admit_context(&caller)?;
    let mut lease = ProcessStreamLease::reserve(state)?;
    // Safe fd duplication preserves ownership and sets close-on-exec. No raw
    // descriptor conversion, process descriptor replacement, or helper thread.
    let descriptor = source.as_fd().try_clone_to_owned()?;
    let file = File::from(descriptor);
    if !file.metadata()?.file_type().is_fifo() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native process stdio requires pipes, not a terminal, regular file, or device",
        ));
    }
    let original = fcntl_getfl(&file).map_err(io::Error::from)?;
    let can_write = original.intersects(OFlags::WRONLY | OFlags::RDWR);
    let can_read = !original.contains(OFlags::WRONLY);
    if (writable && !can_write) || (!writable && !can_read) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "process stream has the wrong access direction"));
    }
    let enabled = original | OFlags::NONBLOCK;
    lease.descriptor = Some(file.as_fd().try_clone_to_owned()?);
    lease.flags = Some((original, enabled));
    if enabled != original {
        fcntl_setfl(&file, enabled).map_err(io::Error::from)?;
    }
    // Admission can still fail (for example, no caller reactor). The lease
    // rolls back flags and releases the slot on EVERY such failure.
    let mut pipe = PipeIo::new(&caller, file.into(), writable)?;
    pipe.process_stream = Some(lease);
    Ok(pipe)
}

impl NativePipeReader {
    /// Explicitly claims process stdin for native, nonblocking MCP pipe I/O.
    ///
    /// The host must dedicate stdin to this connection: do not mix this reader
    /// with `std::io::stdin`, a legacy MCP receive loop, other fd aliases, or
    /// descriptor/flag replacement. Drain any old user-space input buffer
    /// before handing ownership over. The claim excludes other native stdin
    /// constructors in this process, not foreign libraries or OS-level aliases.
    ///
    /// Unlike `from_owned_fd`, this OPT-IN constructor changes `O_NONBLOCK` on
    /// stdin's shared open-file description. It restores the original flags on
    /// EOF, explicit `close`, or Drop, AFTER retiring reactor registrations.
    /// It owns close-on-exec duplicates, never process fd 0 itself. A reactor
    /// is required; terminals and regular files are refused before flag changes.
    /// Drop restoration is best effort; use `close` to observe cleanup errors.
    ///
    /// Create this and `NativePipeWriter::from_stdout` inside the caller's
    /// runtime, then pass them to `Server::serve_stdio_io`. A failure acquiring
    /// stdout must drop/close the already acquired stdin before returning.
    pub fn from_stdin(cx: &Cx) -> io::Result<Self> {
        claim(cx, &io::stdin(), false, Arc::clone(&STDIN_OWNER)).map(Self)
    }

    /// Retires I/O and releases this endpoint, restoring claimed process flags.
    ///
    /// Cleanup does not require a live/cancellation-unmasked caller. A closed
    /// reader subsequently reports EOF. This never closes process stdin.
    pub fn close(&mut self) -> io::Result<()> {
        self.0.close()
    }
}

impl NativePipeWriter {
    /// Explicitly claims process stdout for native, nonblocking MCP pipe I/O.
    ///
    /// The host must dedicate stdout to this connection, with no pending
    /// user-space output and no concurrent writers or flag/descriptor changes.
    /// Send logs to stderr. This constructor does NOT perform a potentially
    /// blocking flush of old stdout buffers. The native-owner slot is not a
    /// synchronization mechanism for unrelated libraries using stdout.
    ///
    /// The same opt-in flag-change, alias, reactor, process-generation and
    /// restoration contract as `NativePipeReader::from_stdin` applies. Native
    /// writer shutdown reports flag-restoration errors, even after cancellation.
    /// It closes only its owned duplicates: the peer observes output EOF when
    /// the process exits or the host separately closes ALL remaining aliases.
    /// It never closes process fd 1 or claims that a duplicate's close did so.
    pub fn from_stdout(cx: &Cx) -> io::Result<Self> {
        claim(cx, &io::stdout(), true, Arc::clone(&STDOUT_OWNER)).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
    use asupersync::runtime::{Runtime, RuntimeBuilder, reactor::create_reactor};
    use asupersync::Budget;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    fn runtime() -> Runtime {
        RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().unwrap())
            .blocking_threads(0, 0)
            .build().unwrap()
    }

    fn owner() -> Arc<AtomicU8> { Arc::new(AtomicU8::new(FREE)) }

    fn read(reader: &mut NativePipeReader, bytes: &mut [u8]) -> Poll<io::Result<usize>> {
        let mut buffer = ReadBuf::new(bytes);
        match Pin::new(reader).poll_read(&mut Context::from_waker(Waker::noop()), &mut buffer) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buffer.filled().len())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn shutdown(writer: &mut NativePipeWriter) -> io::Result<()> {
        match Pin::new(writer).poll_shutdown(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("descriptor cleanup must not wait for peer activity"),
        }
    }

    #[test]
    fn pending_reader_drop_retires_registration_before_restoring_flags_and_owner() {
        let runtime = runtime();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let driver = cx.io_driver_handle().unwrap();
        let (input, output) = io::pipe().unwrap();
        let original = fcntl_getfl(&input).unwrap();
        let owner = owner();
        let mut reader = NativePipeReader(claim(&cx, &input, false, Arc::clone(&owner)).unwrap());
        assert!(fcntl_getfl(&input).unwrap().contains(OFlags::NONBLOCK));
        assert!(read(&mut reader, &mut [0; 1]).is_pending());
        assert_eq!(driver.waker_count(), 1);
        assert_eq!(claim(&cx, &input, false, Arc::clone(&owner)).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        drop(reader);
        assert_eq!(driver.waker_count(), 0);
        assert_eq!(fcntl_getfl(&input).unwrap(), original);
        assert_eq!(owner.load(Ordering::Acquire), FREE);
        // The original descriptor was neither closed nor replaced. It can be
        // claimed a second time without inheriting a stale native owner.
        let mut again = NativePipeReader(claim(&cx, &input, false, Arc::clone(&owner)).unwrap());
        again.close().unwrap();
        again.close().unwrap();
        assert_eq!(fcntl_getfl(&input).unwrap(), original);
        drop((again, input, output, cx));
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn absent_reactor_rolls_back_enabled_flags_and_releases_admission() {
        let (input, output) = io::pipe().unwrap();
        let original = fcntl_getfl(&input).unwrap();
        let owner = owner();
        let error = claim(&Cx::for_testing(), &input, false, Arc::clone(&owner)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
        assert_eq!(fcntl_getfl(&input).unwrap(), original);
        assert_eq!(owner.load(Ordering::Acquire), FREE);
        drop((input, output));
    }

    #[test]
    fn wrong_direction_and_non_pipe_sources_are_refused_before_flag_changes() {
        let runtime = runtime();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let (input, output) = io::pipe().unwrap();
        let input_flags = fcntl_getfl(&input).unwrap();
        let output_flags = fcntl_getfl(&output).unwrap();
        let owner = owner();
        assert_eq!(claim(&cx, &input, true, Arc::clone(&owner)).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(claim(&cx, &output, false, Arc::clone(&owner)).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fcntl_getfl(&input).unwrap(), input_flags);
        assert_eq!(fcntl_getfl(&output).unwrap(), output_flags);
        let regular = File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
        let regular_flags = fcntl_getfl(&regular).unwrap();
        assert_eq!(claim(&cx, &regular, false, Arc::clone(&owner)).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fcntl_getfl(&regular).unwrap(), regular_flags);
        assert_eq!(owner.load(Ordering::Acquire), FREE);
        drop((input, output, regular, cx));
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn reader_eof_restores_flags_and_keeps_the_original_descriptor_open() {
        let runtime = runtime();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let (input, output) = io::pipe().unwrap();
        let original = fcntl_getfl(&input).unwrap();
        let owner = owner();
        let mut reader = NativePipeReader(claim(&cx, &input, false, Arc::clone(&owner)).unwrap());
        assert_eq!(rustix::io::write(&output, b"kept").unwrap(), 4);
        drop(output);
        let mut bytes = [0; 4];
        assert!(matches!(read(&mut reader, &mut bytes), Poll::Ready(Ok(4))));
        assert_eq!(&bytes, b"kept");
        assert_eq!(owner.load(Ordering::Acquire), HELD);
        assert!(matches!(read(&mut reader, &mut bytes), Poll::Ready(Ok(0))));
        assert_eq!(fcntl_getfl(&input).unwrap(), original);
        assert_eq!(owner.load(Ordering::Acquire), FREE);
        assert!(matches!(read(&mut reader, &mut bytes), Poll::Ready(Ok(0))));
        drop((reader, input, cx));
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn cancelled_writer_shutdown_restores_flags_without_closing_the_hosts_alias() {
        let runtime = runtime();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let (input, output) = io::pipe().unwrap();
        let original = fcntl_getfl(&output).unwrap();
        let owner = owner();
        let mut writer = NativePipeWriter(claim(&cx, &output, true, Arc::clone(&owner)).unwrap());
        cx.set_cancel_requested(true);
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut Context::from_waker(Waker::noop()), b"forbidden"),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted
        ));
        shutdown(&mut writer).unwrap();
        shutdown(&mut writer).unwrap();
        assert_eq!(owner.load(Ordering::Acquire), FREE);
        assert_eq!(fcntl_getfl(&output).unwrap(), original);
        // A duplicate's close is not process stdout EOF. The host still owns
        // this descriptor and can use it after the native claim is released.
        assert_eq!(rustix::io::write(&output, b"host").unwrap(), 4);
        let mut bytes = [0; 4];
        assert_eq!(rustix::io::read(&input, &mut bytes).unwrap(), 4);
        assert_eq!(&bytes, b"host");
        drop((writer, input, output, cx));
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn already_nonblocking_stream_keeps_its_original_mode() {
        let runtime = runtime();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let (input, output) = super::super::fresh_descriptors().unwrap();
        let original = fcntl_getfl(&input).unwrap();
        let owner = owner();
        let mut reader = NativePipeReader(claim(&cx, &input, false, Arc::clone(&owner)).unwrap());
        reader.close().unwrap();
        assert!(original.contains(OFlags::NONBLOCK));
        assert_eq!(fcntl_getfl(&input).unwrap(), original);
        assert_eq!(owner.load(Ordering::Acquire), FREE);
        drop((reader, input, output, cx));
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn clearing_nonblocking_via_an_alias_is_refused_before_consuming_bytes() {
        let runtime = runtime();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let (input, output) = io::pipe().unwrap();
        let original = fcntl_getfl(&input).unwrap();
        let owner = owner();
        let mut reader = NativePipeReader(claim(&cx, &input, false, Arc::clone(&owner)).unwrap());
        fcntl_setfl(&input, original).unwrap();
        assert_eq!(rustix::io::write(&output, b"kept").unwrap(), 4);
        let mut bytes = [0; 4];
        assert!(matches!(read(&mut reader, &mut bytes), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::InvalidInput));
        assert_eq!(bytes, [0; 4]);
        fcntl_setfl(&input, original | OFlags::NONBLOCK).unwrap();
        assert!(matches!(read(&mut reader, &mut bytes), Poll::Ready(Ok(4))));
        assert_eq!(&bytes, b"kept");
        reader.close().unwrap();
        assert_eq!(fcntl_getfl(&input).unwrap(), original);
        drop((reader, input, output, cx));
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn restricted_context_refuses_claim_before_mutating_flags_or_ownership() {
        let runtime = runtime();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let (input, output) = io::pipe().unwrap();
        let original = fcntl_getfl(&input).unwrap();
        let owner = owner();
        {
            let _ambient = Cx::set_current(Some(cx.clone()));
            let _restricted = Cx::push_restriction(asupersync::cx::cap::CapMask::none());
            assert_eq!(claim(&cx, &input, false, Arc::clone(&owner)).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        }
        assert_eq!(fcntl_getfl(&input).unwrap(), original);
        assert_eq!(owner.load(Ordering::Acquire), FREE);
        drop((input, output, cx));
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn unrelated_alias_flag_changes_are_not_overwritten_and_poison_reacquisition() {
        let runtime = runtime();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        let (input, output) = io::pipe().unwrap();
        let original = fcntl_getfl(&input).unwrap();
        let owner = owner();
        let mut reader = NativePipeReader(claim(&cx, &input, false, Arc::clone(&owner)).unwrap());
        let foreign = original | OFlags::NONBLOCK | OFlags::APPEND;
        fcntl_setfl(&input, foreign).unwrap();
        assert_eq!(fcntl_getfl(&input).unwrap(), foreign);
        assert!(reader.close().is_err());
        assert_eq!(fcntl_getfl(&input).unwrap(), foreign);
        assert_eq!(owner.load(Ordering::Acquire), POISONED);
        assert!(claim(&cx, &input, false, Arc::clone(&owner)).is_err());
        // Only the test's external owner may restore its own planted change.
        fcntl_setfl(&input, original).unwrap();
        drop((reader, input, output, cx));
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }
}
