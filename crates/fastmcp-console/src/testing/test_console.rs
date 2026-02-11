//! TestConsole for capturing output in tests
//!
//! Provides a Console that captures all output for assertion instead of writing to stderr.

use crate::console::FastMcpConsole;
use std::io::Write;
use std::sync::{Arc, Mutex};
use strip_ansi_escapes::strip;

/// A Console that captures output for testing
///
/// This wraps a FastMcpConsole with a buffer writer to capture all output.
/// Use `console()` to get the inner console for rendering, then use
/// `output()`, `contains()`, and assertion methods to verify the output.
pub struct TestConsole {
    inner: Arc<FastMcpConsole>,
    buffer: Arc<Mutex<TestBuffer>>,
    /// Whether this console reports as rich (for is_rich() method)
    report_as_rich: bool,
}

#[derive(Debug, Default)]
struct TestBuffer {
    /// Lines with ANSI codes stripped
    lines: Vec<String>,
    /// Lines with ANSI codes preserved
    raw_lines: Vec<String>,
}

impl TestConsole {
    fn normalize_whitespace(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn canonicalize_for_assertions(text: &str) -> String {
        let mut out = Self::normalize_whitespace(text);
        // Undo rich-wrapping artifacts around common punctuation.
        for (from, to) in [
            ("( ", "("),
            (" )", ")"),
            ("[ ", "["),
            (" ]", "]"),
            ("{ ", "{"),
            (" }", "}"),
            ("# ", "#"),
            (" =", "="),
            ("= ", "="),
            (". ", "."),
            (" /", "/"),
            ("/ ", "/"),
        ] {
            out = out.replace(from, to);
        }
        out
    }

    fn compact_whitespace(text: &str) -> String {
        text.chars().filter(|c| !c.is_whitespace()).collect()
    }

    /// Create a new test console that captures output
    ///
    /// Note: Internally uses rich mode to ensure output goes through the writer.
    /// ANSI codes are stripped when reading via `output()` and `output_string()`.
    #[must_use]
    pub fn new() -> Self {
        Self::new_inner(false)
    }

    /// Create a test console that renders rich output (for visual testing)
    #[must_use]
    pub fn new_rich() -> Self {
        Self::new_inner(true)
    }

    /// Internal constructor
    fn new_inner(report_as_rich: bool) -> Self {
        let buffer = Arc::new(Mutex::new(TestBuffer::default()));
        let writer = BufferWriter(buffer.clone());

        // Always use enabled=true internally so output goes through the writer
        Self {
            inner: Arc::new(FastMcpConsole::with_writer(writer, true)),
            buffer,
            report_as_rich,
        }
    }

    /// Get the underlying console for passing to renderers
    #[must_use]
    pub fn console(&self) -> &FastMcpConsole {
        &self.inner
    }

    /// Get all captured output (ANSI codes stripped)
    #[must_use]
    pub fn output(&self) -> Vec<String> {
        self.buffer
            .lock()
            .map(|b| b.lines.clone())
            .unwrap_or_default()
    }

    /// Get all captured output (with ANSI codes)
    #[must_use]
    pub fn raw_output(&self) -> Vec<String> {
        self.buffer
            .lock()
            .map(|b| b.raw_lines.clone())
            .unwrap_or_default()
    }

    /// Get output as a single string
    #[must_use]
    pub fn output_string(&self) -> String {
        Self::canonicalize_for_assertions(&self.output().join("\n"))
    }

    /// Check if output contains a string (case-insensitive)
    #[must_use]
    pub fn contains(&self, needle: &str) -> bool {
        let output = self.output_string().to_lowercase();
        let needle = Self::canonicalize_for_assertions(needle).to_lowercase();
        if output.contains(&needle) {
            return true;
        }

        let output_compact = Self::compact_whitespace(&output);
        let needle_compact = Self::compact_whitespace(&needle);
        output_compact.contains(&needle_compact)
    }

    /// Check if output contains all of the given strings
    #[must_use]
    pub fn contains_all(&self, needles: &[&str]) -> bool {
        needles.iter().all(|n| self.contains(n))
    }

    /// Check if output matches a regex pattern
    #[must_use]
    pub fn matches(&self, pattern: &str) -> bool {
        match regex::Regex::new(pattern) {
            Ok(re) => {
                let output = self.output_string();
                re.is_match(&output) || re.is_match(&Self::compact_whitespace(&output))
            }
            Err(_) => false,
        }
    }

    /// Assert that output contains a string
    ///
    /// # Panics
    ///
    /// Panics if the output does not contain the needle string.
    pub fn assert_contains(&self, needle: &str) {
        assert!(
            self.contains(needle),
            "Output did not contain '{}'. Actual output:\n{}",
            needle,
            self.output_string()
        );
    }

    /// Assert that output does NOT contain a string
    ///
    /// # Panics
    ///
    /// Panics if the output contains the needle string.
    pub fn assert_not_contains(&self, needle: &str) {
        assert!(
            !self.contains(needle),
            "Output unexpectedly contained '{}'. Actual output:\n{}",
            needle,
            self.output_string()
        );
    }

    /// Assert output has specific number of lines
    ///
    /// # Panics
    ///
    /// Panics if the line count doesn't match expected.
    pub fn assert_line_count(&self, expected: usize) {
        let actual = self.output().len();
        assert_eq!(
            actual,
            expected,
            "Expected {} lines but got {}. Actual output:\n{}",
            expected,
            actual,
            self.output_string()
        );
    }

    /// Clear the buffer
    pub fn clear(&self) {
        if let Ok(mut buf) = self.buffer.lock() {
            buf.lines.clear();
            buf.raw_lines.clear();
        }
    }

    /// Print output for debugging (in tests)
    pub fn debug_print(&self) {
        eprintln!("=== TestConsole Output ===");
        for (i, line) in self.output().iter().enumerate() {
            eprintln!("{:3}: {}", i + 1, line);
        }
        eprintln!("==========================");
    }

    /// Check if the console reports as rich mode
    ///
    /// Note: The internal console is always in rich mode to capture output,
    /// but this returns the mode the TestConsole was created with.
    #[must_use]
    pub fn is_rich(&self) -> bool {
        self.report_as_rich
    }
}

impl Default for TestConsole {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for TestConsole {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            buffer: self.buffer.clone(),
            report_as_rich: self.report_as_rich,
        }
    }
}

impl std::fmt::Debug for TestConsole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestConsole")
            .field("is_rich", &self.is_rich())
            .field("line_count", &self.output().len())
            .finish()
    }
}

/// Writer that captures to a buffer
struct BufferWriter(Arc<Mutex<TestBuffer>>);

impl std::fmt::Debug for BufferWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferWriter").finish_non_exhaustive()
    }
}

impl Write for BufferWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let s = String::from_utf8_lossy(buf);

        if let Ok(mut buffer) = self.0.lock() {
            // Store raw (with ANSI)
            buffer.raw_lines.extend(s.lines().map(String::from));

            // Store stripped (without ANSI)
            let stripped = strip(buf);
            let stripped_str = String::from_utf8_lossy(&stripped);
            buffer.lines.extend(stripped_str.lines().map(String::from));
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{self, AssertUnwindSafe};

    fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
        match payload.downcast::<String>() {
            Ok(msg) => *msg,
            Err(payload) => match payload.downcast::<&'static str>() {
                Ok(msg) => (*msg).to_string(),
                Err(_) => "<non-string panic payload>".to_string(),
            },
        }
    }

    #[test]
    fn test_new_creates_plain_console() {
        let tc = TestConsole::new();
        assert!(!tc.is_rich());
    }

    #[test]
    fn test_new_rich_creates_rich_console() {
        let tc = TestConsole::new_rich();
        assert!(tc.is_rich());
    }

    #[test]
    fn test_output_capture() {
        let tc = TestConsole::new();
        tc.console().print("Hello, world!");
        assert!(tc.contains("Hello"));
        assert!(tc.contains("world"));
    }

    #[test]
    fn test_contains_case_insensitive() {
        let tc = TestConsole::new();
        tc.console().print("Hello World");
        assert!(tc.contains("hello"));
        assert!(tc.contains("WORLD"));
    }

    #[test]
    fn test_contains_all() {
        let tc = TestConsole::new();
        tc.console().print("The quick brown fox");
        assert!(tc.contains_all(&["quick", "brown", "fox"]));
        assert!(!tc.contains_all(&["quick", "lazy"]));
    }

    #[test]
    fn test_assert_not_contains() {
        let tc = TestConsole::new();
        tc.console().print("Success");
        tc.assert_not_contains("Error");
    }

    #[test]
    fn test_clear() {
        let tc = TestConsole::new();
        tc.console().print("Some output");
        assert!(!tc.output().is_empty());
        tc.clear();
        assert!(tc.output().is_empty());
    }

    #[test]
    fn test_output_string() {
        let tc = TestConsole::new();
        tc.console().print("Line 1");
        tc.console().print("Line 2");
        let output = tc.output_string();
        assert!(output.contains("Line 1"));
        assert!(output.contains("Line 2"));
    }

    #[test]
    fn test_matches_regex() {
        let tc = TestConsole::new();
        tc.console().print("Error code: 42");
        assert!(tc.matches(r"code: \d+"));
        assert!(!tc.matches(r"code: [a-z]+"));
    }

    #[test]
    fn test_matches_invalid_regex_returns_false() {
        let tc = TestConsole::new();
        tc.console().print("anything");
        assert!(!tc.matches("("));
    }

    #[test]
    fn test_assert_contains_failure_includes_output() {
        let tc = TestConsole::new();
        tc.console().print("present text");
        let panic = panic::catch_unwind(AssertUnwindSafe(|| tc.assert_contains("missing text")));
        let message = panic_message(panic.expect_err("assert_contains should panic"));
        assert!(message.contains("did not contain"));
        assert!(message.contains("present text"));
    }

    #[test]
    fn test_assert_not_contains_failure_includes_output() {
        let tc = TestConsole::new();
        tc.console().print("contains marker");
        let panic = panic::catch_unwind(AssertUnwindSafe(|| {
            tc.assert_not_contains("contains marker");
        }));
        let message = panic_message(panic.expect_err("assert_not_contains should panic"));
        assert!(message.contains("unexpectedly contained"));
        assert!(message.contains("contains marker"));
    }

    #[test]
    fn test_assert_line_count_success_and_failure() {
        let tc = TestConsole::new();
        tc.console().print("line one");
        let baseline = tc.output().len();
        tc.assert_line_count(baseline);

        let expected = baseline + 1;
        let panic = panic::catch_unwind(AssertUnwindSafe(|| tc.assert_line_count(expected)));
        let message = panic_message(panic.expect_err("assert_line_count should panic"));
        assert!(message.contains(&format!("Expected {} lines but got {}", expected, baseline)));
        assert!(message.contains("line one"));
    }

    #[test]
    fn test_debug_print_executes() {
        let tc = TestConsole::new();
        tc.console().print("debug line");
        tc.debug_print();
    }

    #[test]
    fn test_debug_impls() {
        let tc = TestConsole::new_rich();
        tc.console().print("x");
        let tc_debug = format!("{tc:?}");
        assert!(tc_debug.contains("TestConsole"));
        assert!(tc_debug.contains("is_rich"));
        assert!(tc_debug.contains("line_count"));

        let writer = BufferWriter(Arc::new(Mutex::new(TestBuffer::default())));
        let writer_debug = format!("{writer:?}");
        assert!(writer_debug.contains("BufferWriter"));
    }

    #[test]
    fn test_clone() {
        let tc = TestConsole::new();
        tc.console().print("Test");
        let tc2 = tc.clone();
        assert!(tc2.contains("Test"));
    }

    #[test]
    fn test_default() {
        let tc = TestConsole::default();
        assert!(!tc.is_rich());
    }
}
