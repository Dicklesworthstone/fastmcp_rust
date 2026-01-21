//! Testing utilities for FastMCP console output.
//!
//! Provides utilities for testing console output:
//!
//! - [`TestConsole`] - Captures console output for assertions
//! - [`SnapshotTest`] - Compares output against stored snapshots
//!
//! # Example
//!
//! ```rust,ignore
//! use fastmcp_console::testing::{TestConsole, SnapshotTest};
//!
//! #[test]
//! fn test_output() {
//!     let console = TestConsole::new();
//!     // ... render to console ...
//!
//!     // Assert specific content
//!     console.assert_contains("expected text");
//!
//!     // Or compare against snapshot
//!     SnapshotTest::new("test_name").assert_snapshot(&console);
//! }
//! ```

mod test_console;
mod snapshots;

pub use test_console::TestConsole;
pub use snapshots::SnapshotTest;
