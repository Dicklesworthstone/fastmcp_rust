//! ErrorBoundary wrapper for automatic error display.
//!
//! The [`ErrorBoundary`] type wraps operations and automatically catches
//! and beautifully displays errors throughout FastMCP. This ensures consistent
//! error presentation without manual render calls everywhere.
//!
//! # Example
//!
//! ```rust,ignore
//! use fastmcp_console::error::ErrorBoundary;
//! use fastmcp_console::console;
//!
//! let boundary = ErrorBoundary::new(console());
//!
//! // Simple usage - returns Option<T>
//! let config = boundary.wrap(load_config());
//!
//! // With context message
//! let config = boundary.wrap_with_context(
//!     load_config(),
//!     "Loading server configuration"
//! );
//!
//! // Check if any errors occurred
//! if boundary.has_errors() {
//!     eprintln!("Encountered {} errors", boundary.error_count());
//! }
//! ```

use std::sync::atomic::{AtomicUsize, Ordering};

use fastmcp_core::McpError;

use crate::console::FastMcpConsole;
use crate::diagnostics::RichErrorRenderer;

/// Wraps operations and displays errors beautifully on failure.
///
/// `ErrorBoundary` provides a consistent way to handle and display errors
/// throughout a FastMCP application. Instead of manually calling error
/// rendering at every error site, wrap operations with an `ErrorBoundary`
/// and it will automatically handle display on failure.
///
/// # Thread Safety
///
/// `ErrorBoundary` is thread-safe and can be shared across threads. The
/// error count is tracked using atomic operations.
///
/// # Exit on Error
///
/// For CLI applications, you can configure the boundary to exit the process
/// on error using [`with_exit_on_error`](ErrorBoundary::with_exit_on_error).
pub struct ErrorBoundary<'a> {
    console: &'a FastMcpConsole,
    renderer: RichErrorRenderer,
    exit_on_error: bool,
    error_count: AtomicUsize,
}

impl<'a> ErrorBoundary<'a> {
    /// Creates a new `ErrorBoundary` with the given console.
    ///
    /// The boundary will use the console's theme and context for rendering
    /// errors.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use fastmcp_console::{console, error::ErrorBoundary};
    ///
    /// let boundary = ErrorBoundary::new(console());
    /// ```
    #[must_use]
    pub fn new(console: &'a FastMcpConsole) -> Self {
        Self {
            console,
            renderer: RichErrorRenderer::new(),
            exit_on_error: false,
            error_count: AtomicUsize::new(0),
        }
    }

    /// Configures the boundary to exit the process on error.
    ///
    /// When `exit` is `true`, any error will cause the process to exit
    /// with code 1 after displaying the error. This is useful for CLI
    /// applications where errors should terminate the program.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let boundary = ErrorBoundary::new(console())
    ///     .with_exit_on_error(true);
    ///
    /// // This will exit the process if load_config() fails
    /// boundary.wrap(load_config());
    /// ```
    #[must_use]
    pub fn with_exit_on_error(mut self, exit: bool) -> Self {
        self.exit_on_error = exit;
        self
    }

    /// Wraps a `Result`, displaying error if `Err`.
    ///
    /// Returns `Some(value)` on success, or `None` on error. The error
    /// is displayed using the configured console and renderer.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The success type
    /// * `E` - The error type, which must be convertible to `McpError`
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let boundary = ErrorBoundary::new(console());
    ///
    /// if let Some(config) = boundary.wrap(load_config()) {
    ///     // Use config...
    /// }
    /// ```
    pub fn wrap<T, E>(&self, result: Result<T, E>) -> Option<T>
    where
        E: Into<McpError>,
    {
        match result {
            Ok(value) => Some(value),
            Err(e) => {
                let error = e.into();
                self.handle_error(&error);
                None
            }
        }
    }

    /// Wraps a `Result` with a custom context message.
    ///
    /// Like [`wrap`](Self::wrap), but displays an additional context message
    /// before the error to help identify where the error occurred.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let boundary = ErrorBoundary::new(console());
    ///
    /// let config = boundary.wrap_with_context(
    ///     load_config(),
    ///     "Loading server configuration"
    /// );
    /// ```
    pub fn wrap_with_context<T, E>(&self, result: Result<T, E>, context: &str) -> Option<T>
    where
        E: Into<McpError>,
    {
        match result {
            Ok(value) => Some(value),
            Err(e) => {
                let error = e.into();
                self.console.print(&format!("[dim]Context: {}[/]", context));
                self.handle_error(&error);
                None
            }
        }
    }

    /// Wraps a `Result`, returning the error if present.
    ///
    /// Unlike [`wrap`](Self::wrap), this returns `Result<T, McpError>` instead
    /// of `Option<T>`. The error is still displayed, but you can also handle
    /// it programmatically.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let boundary = ErrorBoundary::new(console());
    ///
    /// match boundary.wrap_result(load_config()) {
    ///     Ok(config) => { /* use config */ }
    ///     Err(e) => { /* error was displayed, but we can also log it */ }
    /// }
    /// ```
    pub fn wrap_result<T, E>(&self, result: Result<T, E>) -> Result<T, McpError>
    where
        E: Into<McpError>,
    {
        match result {
            Ok(value) => Ok(value),
            Err(e) => {
                let error = e.into();
                self.handle_error(&error);
                Err(error)
            }
        }
    }

    /// Wraps a `Result` with context, returning the error if present.
    ///
    /// Combines [`wrap_with_context`](Self::wrap_with_context) and
    /// [`wrap_result`](Self::wrap_result) - displays context and error,
    /// then returns the error for further handling.
    pub fn wrap_result_with_context<T, E>(
        &self,
        result: Result<T, E>,
        context: &str,
    ) -> Result<T, McpError>
    where
        E: Into<McpError>,
    {
        match result {
            Ok(value) => Ok(value),
            Err(e) => {
                let error = e.into();
                self.console.print(&format!("[dim]Context: {}[/]", context));
                self.handle_error(&error);
                Err(error)
            }
        }
    }

    /// Displays an error directly without wrapping a `Result`.
    ///
    /// This is useful when you already have an `McpError` that you want
    /// to display.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let boundary = ErrorBoundary::new(console());
    /// let error = McpError::internal_error("Something went wrong");
    /// boundary.display_error(&error);
    /// ```
    pub fn display_error(&self, error: &McpError) {
        self.handle_error(error);
    }

    /// Gets the total number of errors that have occurred.
    ///
    /// This count is incremented each time an error is handled through
    /// this boundary.
    #[must_use]
    pub fn error_count(&self) -> usize {
        self.error_count.load(Ordering::Relaxed)
    }

    /// Checks if any errors have occurred.
    ///
    /// Returns `true` if at least one error has been handled through
    /// this boundary.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.error_count() > 0
    }

    /// Resets the error count to zero.
    ///
    /// This can be useful when reusing a boundary for multiple operations
    /// where you want to track errors separately.
    pub fn reset_count(&self) {
        self.error_count.store(0, Ordering::Relaxed);
    }

    /// Handles an error by rendering it and optionally exiting.
    fn handle_error(&self, error: &McpError) {
        self.error_count.fetch_add(1, Ordering::Relaxed);
        self.renderer.render(error, self.console);

        if self.exit_on_error {
            std::process::exit(1);
        }
    }
}

/// Convenience macro for trying an operation with error display.
///
/// If the operation fails, the error is displayed and the macro returns
/// early from the current function.
///
/// # Example
///
/// ```rust,ignore
/// use fastmcp_console::{try_display, error::ErrorBoundary, console};
///
/// fn process(boundary: &ErrorBoundary) {
///     let data = try_display!(boundary, fetch_data());
///     let result = try_display!(boundary, process(data), "Processing data");
///     println!("Result: {:?}", result);
/// }
/// ```
#[macro_export]
macro_rules! try_display {
    ($boundary:expr, $expr:expr) => {
        match $boundary.wrap($expr) {
            Some(v) => v,
            None => return,
        }
    };
    ($boundary:expr, $expr:expr, $ctx:expr) => {
        match $boundary.wrap_with_context($expr, $ctx) {
            Some(v) => v,
            None => return,
        }
    };
}

/// Convenience macro for trying an operation with error display, returning `Result`.
///
/// If the operation fails, the error is displayed and returned as `Err`.
///
/// # Example
///
/// ```rust,ignore
/// use fastmcp_console::{try_display_result, error::ErrorBoundary, console};
///
/// fn process(boundary: &ErrorBoundary) -> Result<(), McpError> {
///     let data = try_display_result!(boundary, fetch_data());
///     let result = try_display_result!(boundary, process(data));
///     Ok(())
/// }
/// ```
#[macro_export]
macro_rules! try_display_result {
    ($boundary:expr, $expr:expr) => {
        match $boundary.wrap_result($expr) {
            Ok(v) => v,
            Err(e) => return Err(e),
        }
    };
    ($boundary:expr, $expr:expr, $ctx:expr) => {
        match $boundary.wrap_result_with_context($expr, $ctx) {
            Ok(v) => v,
            Err(e) => return Err(e),
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_core::McpErrorCode;

    fn test_console() -> FastMcpConsole {
        // Create a console with rich output disabled for testing
        FastMcpConsole::with_enabled(false)
    }

    #[test]
    fn test_error_boundary_wrap_success() {
        let console = test_console();
        let boundary = ErrorBoundary::new(&console);

        let result: Result<i32, McpError> = Ok(42);
        assert_eq!(boundary.wrap(result), Some(42));
        assert_eq!(boundary.error_count(), 0);
        assert!(!boundary.has_errors());
    }

    #[test]
    fn test_error_boundary_wrap_error() {
        let console = test_console();
        let boundary = ErrorBoundary::new(&console);

        let result: Result<i32, McpError> = Err(McpError::internal_error("test error"));
        assert_eq!(boundary.wrap(result), None);
        assert_eq!(boundary.error_count(), 1);
        assert!(boundary.has_errors());
    }

    #[test]
    fn test_error_boundary_wrap_with_context() {
        let console = test_console();
        let boundary = ErrorBoundary::new(&console);

        let result: Result<i32, McpError> = Err(McpError::internal_error("test"));
        assert_eq!(
            boundary.wrap_with_context(result, "Loading config"),
            None
        );
        assert_eq!(boundary.error_count(), 1);
    }

    #[test]
    fn test_error_boundary_wrap_result_success() {
        let console = test_console();
        let boundary = ErrorBoundary::new(&console);

        let result: Result<i32, McpError> = Ok(42);
        let wrapped = boundary.wrap_result(result);
        assert!(wrapped.is_ok());
        assert_eq!(wrapped.unwrap(), 42);
        assert_eq!(boundary.error_count(), 0);
    }

    #[test]
    fn test_error_boundary_wrap_result_error() {
        let console = test_console();
        let boundary = ErrorBoundary::new(&console);

        let result: Result<i32, McpError> = Err(McpError::internal_error("test"));
        let wrapped = boundary.wrap_result(result);
        assert!(wrapped.is_err());
        assert_eq!(wrapped.unwrap_err().code, McpErrorCode::InternalError);
        assert_eq!(boundary.error_count(), 1);
    }

    #[test]
    fn test_error_boundary_multiple_errors() {
        let console = test_console();
        let boundary = ErrorBoundary::new(&console);

        let err1: Result<i32, McpError> = Err(McpError::internal_error("error 1"));
        let err2: Result<i32, McpError> = Err(McpError::parse_error("error 2"));
        let err3: Result<i32, McpError> = Err(McpError::method_not_found("test"));

        boundary.wrap(err1);
        boundary.wrap(err2);
        boundary.wrap(err3);

        assert_eq!(boundary.error_count(), 3);
    }

    #[test]
    fn test_error_boundary_reset_count() {
        let console = test_console();
        let boundary = ErrorBoundary::new(&console);

        let err: Result<i32, McpError> = Err(McpError::internal_error("test"));
        boundary.wrap(err);
        assert_eq!(boundary.error_count(), 1);

        boundary.reset_count();
        assert_eq!(boundary.error_count(), 0);
        assert!(!boundary.has_errors());
    }

    #[test]
    fn test_error_boundary_display_error() {
        let console = test_console();
        let boundary = ErrorBoundary::new(&console);

        let error = McpError::internal_error("direct display");
        boundary.display_error(&error);

        assert_eq!(boundary.error_count(), 1);
    }

    #[test]
    fn test_error_boundary_mixed_results() {
        let console = test_console();
        let boundary = ErrorBoundary::new(&console);

        // Some successes
        let ok1: Result<i32, McpError> = Ok(1);
        let ok2: Result<i32, McpError> = Ok(2);

        // Some failures
        let err1: Result<i32, McpError> = Err(McpError::internal_error("e1"));
        let err2: Result<i32, McpError> = Err(McpError::internal_error("e2"));

        assert_eq!(boundary.wrap(ok1), Some(1));
        assert_eq!(boundary.wrap(err1), None);
        assert_eq!(boundary.wrap(ok2), Some(2));
        assert_eq!(boundary.wrap(err2), None);

        // Only the errors should be counted
        assert_eq!(boundary.error_count(), 2);
    }

    #[test]
    fn test_error_boundary_from_other_error_types() {
        let console = test_console();
        let boundary = ErrorBoundary::new(&console);

        // serde_json::Error can be converted to McpError
        let json_result: Result<serde_json::Value, serde_json::Error> =
            serde_json::from_str("invalid json");

        // The error type must implement Into<McpError>
        let mcp_result = json_result.map_err(McpError::from);
        assert_eq!(boundary.wrap(mcp_result), None);
        assert_eq!(boundary.error_count(), 1);
    }
}
