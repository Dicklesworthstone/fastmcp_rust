//! Snapshot testing for rich console output.
//!
//! This module provides utilities for snapshot testing of rich output.
//! Snapshots store a "golden" reference of expected output and compare
//! future runs against it. When output changes, the test fails and shows
//! the diff.
//!
//! # Workflow
//!
//! 1. First run: Test fails with "snapshot does not exist"
//! 2. Run with `UPDATE_SNAPSHOTS=1 cargo test` to create snapshot
//! 3. Review generated snapshot in tests/snapshots/
//! 4. Subsequent runs compare against stored snapshot
//! 5. If output changes intentionally, run with `UPDATE_SNAPSHOTS=1` again
//!
//! # Example
//!
//! ```rust,ignore
//! use fastmcp_console::testing::{TestConsole, SnapshotTest};
//!
//! #[test]
//! fn test_banner_output() {
//!     let console = TestConsole::new();
//!     // ... render to console ...
//!
//!     SnapshotTest::new("banner_output").assert_snapshot(&console);
//! }
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use crate::testing::TestConsole;

/// Snapshot testing for rich console output.
///
/// `SnapshotTest` compares console output against stored snapshots.
/// If the output differs, the test fails with a diff. When running
/// with `UPDATE_SNAPSHOTS=1`, snapshots are created or updated.
///
/// # Snapshot Storage
///
/// By default, snapshots are stored in `tests/snapshots/` relative to
/// the crate's `Cargo.toml`. Use [`with_snapshot_dir`](Self::with_snapshot_dir)
/// to customize this location.
///
/// # File Naming
///
/// - Plain text snapshots: `{name}.txt`
/// - Raw snapshots (with ANSI): `{name}.raw.txt`
pub struct SnapshotTest {
    name: String,
    snapshot_dir: PathBuf,
    update_snapshots: bool,
}

impl SnapshotTest {
    /// Creates a new snapshot test with the given name.
    ///
    /// The name is used as the filename for the snapshot (with `.txt` extension).
    /// Snapshots are stored in `tests/snapshots/` by default.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let snap = SnapshotTest::new("error_display");
    /// // Snapshot will be at tests/snapshots/error_display.txt
    /// ```
    #[must_use]
    pub fn new(name: &str) -> Self {
        let snapshot_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("snapshots");

        Self {
            name: name.to_string(),
            snapshot_dir,
            update_snapshots: std::env::var("UPDATE_SNAPSHOTS").is_ok(),
        }
    }

    /// Sets a custom snapshot directory.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let snap = SnapshotTest::new("test")
    ///     .with_snapshot_dir("/tmp/my_snapshots");
    /// ```
    #[must_use]
    pub fn with_snapshot_dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.snapshot_dir = dir.as_ref().to_path_buf();
        self
    }

    /// Forces update mode, regardless of environment variable.
    ///
    /// Use this for programmatic snapshot updates.
    #[must_use]
    pub fn with_update_mode(mut self, update: bool) -> Self {
        self.update_snapshots = update;
        self
    }

    /// Asserts that the console output matches the stored snapshot.
    ///
    /// Compares the stripped output (without ANSI codes) against the snapshot.
    ///
    /// # Panics
    ///
    /// - If the snapshot doesn't exist and `UPDATE_SNAPSHOTS` is not set
    /// - If the output doesn't match the snapshot
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let console = TestConsole::new();
    /// console.console().print("Hello, world!");
    ///
    /// SnapshotTest::new("hello")
    ///     .assert_snapshot(&console);
    /// ```
    pub fn assert_snapshot(&self, console: &TestConsole) {
        let actual = console.output_string();
        self.assert_snapshot_string(&actual);
    }

    /// Asserts that a string matches the stored snapshot.
    ///
    /// # Panics
    ///
    /// - If the snapshot doesn't exist and `UPDATE_SNAPSHOTS` is not set
    /// - If the string doesn't match the snapshot
    pub fn assert_snapshot_string(&self, actual: &str) {
        let snapshot_path = self.snapshot_path();

        if self.update_snapshots {
            self.save_snapshot(actual);
            return;
        }

        if !snapshot_path.exists() {
            panic!(
                "Snapshot '{}' does not exist at {}.\n\
                 Run with UPDATE_SNAPSHOTS=1 to create it.\n\
                 Actual output ({} bytes):\n{}\n",
                self.name,
                snapshot_path.display(),
                actual.len(),
                truncate_for_display(actual, 1000)
            );
        }

        let expected = fs::read_to_string(&snapshot_path).unwrap_or_else(|e| {
            panic!(
                "Failed to read snapshot file '{}': {}",
                snapshot_path.display(),
                e
            )
        });

        if actual != expected {
            let diff = self.generate_diff(&expected, actual);
            panic!(
                "Snapshot '{}' does not match.\n\
                 Run with UPDATE_SNAPSHOTS=1 to update.\n\
                 Diff (expected vs actual):\n{}\n",
                self.name, diff
            );
        }
    }

    /// Asserts that the raw console output (with ANSI codes) matches the snapshot.
    ///
    /// This is useful for verifying that ANSI styling is applied correctly.
    ///
    /// # Panics
    ///
    /// - If the raw snapshot doesn't exist and `UPDATE_SNAPSHOTS` is not set
    /// - If the raw output doesn't match the snapshot
    pub fn assert_raw_snapshot(&self, console: &TestConsole) {
        let actual = console.raw_output().join("\n");
        let snapshot_path = self.snapshot_path_raw();

        if self.update_snapshots {
            fs::create_dir_all(&self.snapshot_dir).ok();
            fs::write(&snapshot_path, &actual).unwrap_or_else(|e| {
                panic!(
                    "Failed to write raw snapshot '{}': {}",
                    snapshot_path.display(),
                    e
                )
            });
            eprintln!("Updated raw snapshot: {} -> {}", self.name, snapshot_path.display());
            return;
        }

        if !snapshot_path.exists() {
            panic!(
                "Raw snapshot '{}' does not exist at {}.\n\
                 Run with UPDATE_SNAPSHOTS=1 to create.",
                self.name,
                snapshot_path.display()
            );
        }

        let expected =
            fs::read_to_string(&snapshot_path).expect("Failed to read raw snapshot");

        if actual != expected {
            let diff = self.generate_diff(&expected, &actual);
            panic!(
                "Raw snapshot '{}' does not match.\n\
                 Run with UPDATE_SNAPSHOTS=1 to update.\n\
                 Diff:\n{}",
                self.name, diff
            );
        }
    }

    /// Returns the path where the snapshot file would be stored.
    #[must_use]
    pub fn snapshot_path(&self) -> PathBuf {
        self.snapshot_dir.join(format!("{}.txt", self.name))
    }

    /// Returns the path where the raw snapshot file would be stored.
    #[must_use]
    pub fn snapshot_path_raw(&self) -> PathBuf {
        self.snapshot_dir.join(format!("{}.raw.txt", self.name))
    }

    /// Checks if a snapshot exists for this test.
    #[must_use]
    pub fn snapshot_exists(&self) -> bool {
        self.snapshot_path().exists()
    }

    /// Checks if a raw snapshot exists for this test.
    #[must_use]
    pub fn raw_snapshot_exists(&self) -> bool {
        self.snapshot_path_raw().exists()
    }

    /// Saves a snapshot to disk.
    fn save_snapshot(&self, content: &str) {
        fs::create_dir_all(&self.snapshot_dir).unwrap_or_else(|e| {
            panic!(
                "Failed to create snapshot directory '{}': {}",
                self.snapshot_dir.display(),
                e
            )
        });

        let path = self.snapshot_path();
        fs::write(&path, content).unwrap_or_else(|e| {
            panic!("Failed to write snapshot '{}': {}", path.display(), e)
        });

        eprintln!("Updated snapshot: {} -> {}", self.name, path.display());
    }

    /// Generates a simple line-by-line diff between expected and actual.
    fn generate_diff(&self, expected: &str, actual: &str) -> String {
        let expected_lines: Vec<&str> = expected.lines().collect();
        let actual_lines: Vec<&str> = actual.lines().collect();

        let mut diff = String::new();
        let max_lines = expected_lines.len().max(actual_lines.len());

        // Header
        diff.push_str(&format!(
            "Expected: {} lines, Actual: {} lines\n",
            expected_lines.len(),
            actual_lines.len()
        ));
        diff.push_str("---\n");

        let mut differences = 0;
        for i in 0..max_lines {
            let exp = expected_lines.get(i);
            let act = actual_lines.get(i);

            match (exp, act) {
                (Some(e), Some(a)) if e != a => {
                    diff.push_str(&format!("L{}: - {}\n", i + 1, e));
                    diff.push_str(&format!("L{}: + {}\n", i + 1, a));
                    differences += 1;
                }
                (Some(e), None) => {
                    diff.push_str(&format!("L{}: - {}\n", i + 1, e));
                    differences += 1;
                }
                (None, Some(a)) => {
                    diff.push_str(&format!("L{}: + {}\n", i + 1, a));
                    differences += 1;
                }
                _ => {}
            }

            // Limit diff output for very large differences
            if differences > 50 {
                diff.push_str(&format!(
                    "... ({} more differences truncated)\n",
                    max_lines - i - 1
                ));
                break;
            }
        }

        if differences == 0 {
            diff.push_str("(no line differences - possible whitespace/encoding issue)\n");

            // Show character-level comparison for debugging
            if expected.len() != actual.len() {
                diff.push_str(&format!(
                    "Byte lengths differ: expected {} vs actual {}\n",
                    expected.len(),
                    actual.len()
                ));
            }
        }

        diff
    }
}

/// Truncates a string for display in error messages.
fn truncate_for_display(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        s
    } else {
        // Find a safe truncation point (don't split UTF-8)
        let truncate_at = s
            .char_indices()
            .take_while(|(i, _)| *i < max_len - 3)
            .last()
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(max_len - 3);
        &s[..truncate_at]
    }
}

/// Convenience macro for snapshot tests.
///
/// # Example
///
/// ```rust,ignore
/// use fastmcp_console::{assert_snapshot, testing::TestConsole};
///
/// #[test]
/// fn test_output() {
///     let console = TestConsole::new();
///     console.console().print("Hello!");
///
///     assert_snapshot!("hello_output", console);
/// }
/// ```
#[macro_export]
macro_rules! assert_snapshot {
    ($name:expr, $console:expr) => {
        $crate::testing::SnapshotTest::new($name).assert_snapshot(&$console)
    };
}

/// Convenience macro for raw snapshot tests (with ANSI codes).
///
/// # Example
///
/// ```rust,ignore
/// use fastmcp_console::{assert_raw_snapshot, testing::TestConsole};
///
/// #[test]
/// fn test_styled_output() {
///     let console = TestConsole::new_rich();
///     console.console().print("[bold]Hello![/]");
///
///     assert_raw_snapshot!("hello_styled", console);
/// }
/// ```
#[macro_export]
macro_rules! assert_raw_snapshot {
    ($name:expr, $console:expr) => {
        $crate::testing::SnapshotTest::new($name).assert_raw_snapshot(&$console)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_snapshot_path() {
        let snap = SnapshotTest::new("my_test");
        let path = snap.snapshot_path();
        assert!(path.ends_with("my_test.txt"));
    }

    #[test]
    fn test_snapshot_path_raw() {
        let snap = SnapshotTest::new("my_test");
        let path = snap.snapshot_path_raw();
        assert!(path.ends_with("my_test.raw.txt"));
    }

    #[test]
    fn test_custom_snapshot_dir() {
        let snap = SnapshotTest::new("test").with_snapshot_dir("/tmp/custom");
        assert_eq!(snap.snapshot_dir, PathBuf::from("/tmp/custom"));
    }

    #[test]
    fn test_snapshot_creation_and_matching() {
        let temp_dir = tempdir().expect("Failed to create temp dir");

        let snap = SnapshotTest::new("creation_test")
            .with_snapshot_dir(temp_dir.path())
            .with_update_mode(true);

        // Create the snapshot
        let console = TestConsole::new();
        console.console().print("Test content for snapshot");
        snap.assert_snapshot(&console);

        // Verify file was created
        assert!(snap.snapshot_exists());

        // Now verify it matches on a fresh test (without update mode)
        let snap2 = SnapshotTest::new("creation_test")
            .with_snapshot_dir(temp_dir.path())
            .with_update_mode(false);

        let console2 = TestConsole::new();
        console2.console().print("Test content for snapshot");
        snap2.assert_snapshot(&console2); // Should not panic
    }

    #[test]
    fn test_snapshot_string_matching() {
        let temp_dir = tempdir().expect("Failed to create temp dir");

        // Create snapshot
        let snap = SnapshotTest::new("string_test")
            .with_snapshot_dir(temp_dir.path())
            .with_update_mode(true);
        snap.assert_snapshot_string("Hello, world!");

        // Verify match
        let snap2 = SnapshotTest::new("string_test")
            .with_snapshot_dir(temp_dir.path())
            .with_update_mode(false);
        snap2.assert_snapshot_string("Hello, world!"); // Should not panic
    }

    #[test]
    #[should_panic(expected = "does not match")]
    fn test_snapshot_mismatch_panics() {
        let temp_dir = tempdir().expect("Failed to create temp dir");

        // Create snapshot with one value
        let snap = SnapshotTest::new("mismatch_test")
            .with_snapshot_dir(temp_dir.path())
            .with_update_mode(true);
        snap.assert_snapshot_string("Original content");

        // Try to match with different value
        let snap2 = SnapshotTest::new("mismatch_test")
            .with_snapshot_dir(temp_dir.path())
            .with_update_mode(false);
        snap2.assert_snapshot_string("Different content"); // Should panic
    }

    #[test]
    #[should_panic(expected = "does not exist")]
    fn test_missing_snapshot_panics() {
        let temp_dir = tempdir().expect("Failed to create temp dir");

        let snap = SnapshotTest::new("nonexistent")
            .with_snapshot_dir(temp_dir.path())
            .with_update_mode(false);

        snap.assert_snapshot_string("Content"); // Should panic
    }

    #[test]
    fn test_raw_snapshot() {
        let temp_dir = tempdir().expect("Failed to create temp dir");

        // Create raw snapshot
        let snap = SnapshotTest::new("raw_test")
            .with_snapshot_dir(temp_dir.path())
            .with_update_mode(true);

        let console = TestConsole::new_rich();
        console.console().print("[bold]Styled text[/]");
        snap.assert_raw_snapshot(&console);

        // Verify raw snapshot exists
        assert!(snap.raw_snapshot_exists());
    }

    #[test]
    fn test_generate_diff() {
        let snap = SnapshotTest::new("diff_test");

        let expected = "line 1\nline 2\nline 3";
        let actual = "line 1\nmodified line 2\nline 3";

        let diff = snap.generate_diff(expected, actual);

        assert!(diff.contains("- line 2"));
        assert!(diff.contains("+ modified line 2"));
    }

    #[test]
    fn test_generate_diff_added_lines() {
        let snap = SnapshotTest::new("diff_test");

        let expected = "line 1";
        let actual = "line 1\nline 2";

        let diff = snap.generate_diff(expected, actual);

        assert!(diff.contains("+ line 2"));
    }

    #[test]
    fn test_generate_diff_removed_lines() {
        let snap = SnapshotTest::new("diff_test");

        let expected = "line 1\nline 2";
        let actual = "line 1";

        let diff = snap.generate_diff(expected, actual);

        assert!(diff.contains("- line 2"));
    }

    #[test]
    fn test_truncate_for_display() {
        assert_eq!(truncate_for_display("short", 10), "short");
        assert_eq!(truncate_for_display("a longer string that needs truncation", 20).len(), 17);
    }

    #[test]
    fn test_snapshot_exists() {
        let temp_dir = tempdir().expect("Failed to create temp dir");

        let snap = SnapshotTest::new("exists_test")
            .with_snapshot_dir(temp_dir.path());

        assert!(!snap.snapshot_exists());

        // Create it
        let snap_create = snap.with_update_mode(true);
        snap_create.assert_snapshot_string("content");

        // Now it should exist
        let snap_check = SnapshotTest::new("exists_test")
            .with_snapshot_dir(temp_dir.path());
        assert!(snap_check.snapshot_exists());
    }
}
