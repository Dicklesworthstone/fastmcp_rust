//! Async I/O wrappers for stdio integration with asupersync.
//!
//! This module provides async wrappers for stdin/stdout that implement
//! asupersync's `AsyncRead` and `AsyncWrite` traits.
//!
//! # Phase 0 Implementation
//!
//! In Phase 0, these wrappers perform blocking I/O internally but present
//! an async API. This allows the codebase to use async patterns that will
//! benefit from true async I/O when the runtime is upgraded.
//!
//! # Cancellation Integration
//!
//! The wrappers check for cancellation via `Cx::is_cancel_requested()` at
//! appropriate points, enabling cooperative cancellation even with blocking I/O.

use asupersync::Cx;
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};

/// Async wrapper for stdin.
///
/// Provides an `AsyncRead` implementation over stdin. In Phase 0, this
/// performs blocking reads internally but presents an async API.
///
/// # Example
///
/// ```ignore
/// use fastmcp_transport::async_io::AsyncStdin;
/// use asupersync::io::AsyncReadExt;
///
/// let mut stdin = AsyncStdin::new();
/// let mut buf = String::new();
/// stdin.read_to_string(&mut buf).await?;
/// ```
#[derive(Debug)]
pub struct AsyncStdin {
    inner: BufReader<std::io::Stdin>,
}

impl AsyncStdin {
    /// Creates a new `AsyncStdin` wrapping the standard input.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: BufReader::new(std::io::stdin()),
        }
    }

    /// Reads a line from stdin, checking for cancellation.
    ///
    /// This method integrates with asupersync's capability context to enable
    /// cooperative cancellation. It checks `cx.is_cancel_requested()` before
    /// the blocking read.
    ///
    /// # Errors
    ///
    /// Returns an error if cancellation is requested or an I/O error occurs.
    pub fn read_line_sync(&mut self, cx: &Cx, buf: &mut String) -> io::Result<usize> {
        // Check cancellation before blocking
        if cx.is_cancel_requested() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }

        self.inner.read_line(buf)
    }
}

impl Default for AsyncStdin {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncRead for AsyncStdin {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Phase 0: Blocking read, immediate Poll::Ready
        let n = self.inner.read(buf.unfilled())?;
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

/// Async wrapper for stdout.
///
/// Provides an `AsyncWrite` implementation over stdout. In Phase 0, this
/// performs blocking writes internally but presents an async API.
///
/// # Example
///
/// ```ignore
/// use fastmcp_transport::async_io::AsyncStdout;
/// use asupersync::io::AsyncWriteExt;
///
/// let mut stdout = AsyncStdout::new();
/// stdout.write_all(b"hello\n").await?;
/// stdout.flush().await?;
/// ```
#[derive(Debug)]
pub struct AsyncStdout {
    inner: std::io::Stdout,
}

static STDOUT_LOCK: Mutex<()> = Mutex::new(());

impl AsyncStdout {
    /// Creates a new `AsyncStdout` wrapping the standard output.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: std::io::stdout(),
        }
    }

    /// Writes data to stdout, checking for cancellation.
    ///
    /// This method integrates with asupersync's capability context to enable
    /// cooperative cancellation before the write.
    ///
    /// # Errors
    ///
    /// Returns an error if cancellation is requested or an I/O error occurs.
    pub fn write_all_sync(&mut self, cx: &Cx, buf: &[u8]) -> io::Result<()> {
        // Check cancellation before I/O
        if cx.is_cancel_requested() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }

        let _guard = STDOUT_LOCK
            .lock()
            .map_err(|_| io::Error::other("stdout lock poisoned"))?;
        self.inner.write_all(buf)
    }

    /// Flushes stdout, checking for cancellation.
    ///
    /// # Errors
    ///
    /// Returns an error if cancellation is requested or an I/O error occurs.
    pub fn flush_sync(&mut self, cx: &Cx) -> io::Result<()> {
        // Check cancellation before I/O
        if cx.is_cancel_requested() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }

        let _guard = STDOUT_LOCK
            .lock()
            .map_err(|_| io::Error::other("stdout lock poisoned"))?;
        self.inner.flush()
    }

    // --- Unchecked methods for two-phase commit ---

    /// Writes data to stdout without checking cancellation.
    ///
    /// This is used in the commit phase of two-phase sends, where
    /// cancellation has already been checked at reserve time.
    ///
    /// # Errors
    ///
    /// Returns an error only on I/O failure.
    pub fn write_all_unchecked(&mut self, buf: &[u8]) -> io::Result<()> {
        let _guard = STDOUT_LOCK
            .lock()
            .map_err(|_| io::Error::other("stdout lock poisoned"))?;
        self.inner.write_all(buf)
    }

    /// Flushes stdout without checking cancellation.
    ///
    /// This is used in the commit phase of two-phase sends, where
    /// cancellation has already been checked at reserve time.
    ///
    /// # Errors
    ///
    /// Returns an error only on I/O failure.
    pub fn flush_unchecked(&mut self) -> io::Result<()> {
        let _guard = STDOUT_LOCK
            .lock()
            .map_err(|_| io::Error::other("stdout lock poisoned"))?;
        self.inner.flush()
    }
}

/// Implement std::io::Write for AsyncStdout to enable two-phase send.
///
/// These methods bypass cancellation checks because they're used in the
/// commit phase of two-phase sends, where cancellation was already checked
/// during reservation.
impl Write for AsyncStdout {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let _guard = STDOUT_LOCK
            .lock()
            .map_err(|_| io::Error::other("stdout lock poisoned"))?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let _guard = STDOUT_LOCK
            .lock()
            .map_err(|_| io::Error::other("stdout lock poisoned"))?;
        self.inner.flush()
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        let _guard = STDOUT_LOCK
            .lock()
            .map_err(|_| io::Error::other("stdout lock poisoned"))?;
        self.inner.write_all(buf)
    }
}

impl Default for AsyncStdout {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncWrite for AsyncStdout {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Phase 0: Blocking write, immediate Poll::Ready
        let _guard = STDOUT_LOCK
            .lock()
            .map_err(|_| io::Error::other("stdout lock poisoned"))?;
        let n = self.inner.write(buf)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _guard = STDOUT_LOCK
            .lock()
            .map_err(|_| io::Error::other("stdout lock poisoned"))?;
        self.inner.flush()?;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Stdout doesn't need explicit shutdown
        Poll::Ready(Ok(()))
    }
}

/// Async line reader with cancellation support.
///
/// This struct provides a cancel-aware line reading API that integrates
/// with asupersync's capability context.
///
/// # Example
///
/// ```ignore
/// use fastmcp_transport::async_io::AsyncLineReader;
/// use asupersync::Cx;
///
/// let cx = Cx::for_testing();
/// let mut reader = AsyncLineReader::new();
///
/// loop {
///     match reader.read_line(&cx) {
///         Ok(Some(line)) => process_line(&line),
///         Ok(None) => break, // EOF
///         Err(e) if e.kind() == io::ErrorKind::Interrupted => break, // Cancelled
///         Err(e) => return Err(e),
///     }
/// }
/// ```
#[derive(Debug)]
pub struct AsyncLineReader {
    stdin: AsyncStdin,
    buffer: String,
}

impl AsyncLineReader {
    /// Creates a new `AsyncLineReader`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stdin: AsyncStdin::new(),
            buffer: String::with_capacity(4096),
        }
    }

    /// Reads a line from stdin with cancellation checking.
    ///
    /// Returns `Ok(Some(line))` when a line is read, `Ok(None)` on EOF,
    /// or an error on cancellation/I/O failure.
    ///
    /// # Errors
    ///
    /// - Returns `io::ErrorKind::Interrupted` if cancellation is requested.
    /// - Returns other I/O errors as-is.
    pub fn read_line(&mut self, cx: &Cx) -> io::Result<Option<String>> {
        self.buffer.clear();

        let bytes_read = self.stdin.read_line_sync(cx, &mut self.buffer)?;

        if bytes_read == 0 {
            return Ok(None); // EOF
        }

        // Trim trailing newline
        let line = self
            .buffer
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_string();

        Ok(Some(line))
    }

    /// Reads a non-empty line, skipping empty lines.
    ///
    /// Returns `Ok(Some(line))` when a non-empty line is read, `Ok(None)` on EOF,
    /// or an error on cancellation/I/O failure.
    ///
    /// This method checks for cancellation between each line read.
    ///
    /// # Errors
    ///
    /// - Returns `io::ErrorKind::Interrupted` if cancellation is requested.
    /// - Returns other I/O errors as-is.
    pub fn read_non_empty_line(&mut self, cx: &Cx) -> io::Result<Option<String>> {
        loop {
            // Check cancellation between reads
            if cx.is_cancel_requested() {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
            }

            match self.read_line(cx)? {
                None => return Ok(None),            // EOF
                Some(line) if line.is_empty() => {} // Skip empty lines, continue looping
                Some(line) => return Ok(Some(line)),
            }
        }
    }
}

impl Default for AsyncLineReader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn async_stdout_created() {
        let _stdout = AsyncStdout::new();
    }

    #[test]
    fn async_stdin_created() {
        let _stdin = AsyncStdin::new();
    }

    #[test]
    fn async_line_reader_created() {
        let _reader = AsyncLineReader::new();
    }

    #[test]
    fn cancellation_check_on_write() {
        let mut stdout = AsyncStdout::new();
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let result = stdout.write_all_sync(&cx, b"test");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn cancellation_check_on_flush() {
        let mut stdout = AsyncStdout::new();
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let result = stdout.flush_sync(&cx);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn cancellation_check_on_read_line() {
        let mut reader = AsyncLineReader::new();
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);

        let result = reader.read_non_empty_line(&cx);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
    }
}
