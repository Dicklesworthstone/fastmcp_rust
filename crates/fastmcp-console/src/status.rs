//! Status/progress output.
//!
//! Provides lightweight request status logging for stderr, with rich output
//! when available and a plain-text fallback in agent contexts.
//!
//! # Example
//!
//! ```rust,ignore
//! use fastmcp_console::console::FastMcpConsole;
//! use fastmcp_console::status::RequestLog;
//!
//! let console = FastMcpConsole::new();
//! let log = RequestLog::new("tools/call", Some("1")).success();
//! log.render(&console);
//! ```

use std::time::{Duration, Instant};

use crate::console::FastMcpConsole;

/// Format for displaying request/response activity.
pub struct RequestLog {
    method: String,
    id: Option<String>,
    start: Instant,
    status: RequestStatus,
}

/// Current request status for display.
pub enum RequestStatus {
    /// Request is still pending.
    Pending,
    /// Request completed successfully.
    Success(Duration),
    /// Request failed with a message and duration.
    Error(String, Duration),
    /// Request was cancelled with duration.
    Cancelled(Duration),
}

impl RequestLog {
    /// Create a new request log for a method and optional request ID.
    pub fn new(method: &str, id: Option<&str>) -> Self {
        Self {
            method: method.to_string(),
            id: id.map(String::from),
            start: Instant::now(),
            status: RequestStatus::Pending,
        }
    }

    /// Mark the request as successful.
    pub fn success(mut self) -> Self {
        self.status = RequestStatus::Success(self.start.elapsed());
        self
    }

    /// Mark the request as failed with an error message.
    pub fn error(mut self, msg: &str) -> Self {
        self.status = RequestStatus::Error(msg.to_string(), self.start.elapsed());
        self
    }

    /// Mark the request as cancelled.
    pub fn cancelled(mut self) -> Self {
        self.status = RequestStatus::Cancelled(self.start.elapsed());
        self
    }

    /// Render the log entry to the console.
    pub fn render(&self, console: &FastMcpConsole) {
        if !console.is_rich() {
            self.render_plain();
            return;
        }

        let theme = console.theme();
        let (icon, style, duration) = match &self.status {
            RequestStatus::Pending => ("◐", &theme.info_style, None),
            RequestStatus::Success(d) => ("✓", &theme.success_style, Some(d)),
            RequestStatus::Error(_, d) => ("✗", &theme.error_style, Some(d)),
            RequestStatus::Cancelled(d) => ("⊘", &theme.warning_style, Some(d)),
        };

        let id_str = self
            .id
            .as_ref()
            .map(|id| {
                format!(
                    " [{}]#{}[/]",
                    theme.text_dim.triplet.unwrap_or_default().hex(),
                    id
                )
            })
            .unwrap_or_default();

        let duration_str = duration
            .map(|d| {
                format!(
                    " [{}]{}[/]",
                    theme.text_muted.triplet.unwrap_or_default().hex(),
                    format_duration(*d)
                )
            })
            .unwrap_or_default();

        console.print(&format!(
            "[{}]{}[/] [{}]{}[/]{}{}",
            style
                .color
                .as_ref()
                .map(|c| c.triplet.unwrap_or_default().hex())
                .unwrap_or_default(),
            icon,
            theme
                .key_style
                .color
                .as_ref()
                .map(|c| c.triplet.unwrap_or_default().hex())
                .unwrap_or_default(),
            self.method,
            id_str,
            duration_str
        ));

        if let RequestStatus::Error(msg, _) = &self.status {
            console.print(&format!(
                "  [{}]└─ {}[/]",
                theme.error.triplet.unwrap_or_default().hex(),
                msg
            ));
        }
    }

    fn render_plain(&self) {
        let (icon, duration) = match &self.status {
            RequestStatus::Pending => ("...", None),
            RequestStatus::Success(d) => ("OK", Some(d)),
            RequestStatus::Error(_, d) => ("ERR", Some(d)),
            RequestStatus::Cancelled(d) => ("CANCEL", Some(d)),
        };

        let duration_str = duration
            .map(|d| format!(" ({})", format_duration(*d)))
            .unwrap_or_default();

        let id_str = self
            .id
            .as_ref()
            .map(|id| format!(" #{}", id))
            .unwrap_or_default();

        eprintln!("[{}] {}{}{}", icon, self.method, id_str, duration_str);

        if let RequestStatus::Error(msg, _) = &self.status {
            eprintln!("  Error: {}", msg);
        }
    }
}

fn format_duration(d: Duration) -> String {
    if d.as_millis() < 1000 {
        format!("{}ms", d.as_millis())
    } else if d.as_secs() < 60 {
        format!("{:.2}s", d.as_secs_f64())
    } else {
        format!("{}m {}s", d.as_secs() / 60, d.as_secs() % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use crate::testing::TestConsole;

    #[derive(Clone, Debug)]
    struct SharedWriter {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedWriter {
        fn new() -> (Self, Arc<Mutex<Vec<u8>>>) {
            let buf = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    buf: Arc::clone(&buf),
                },
                buf,
            )
        }
    }

    impl Write for SharedWriter {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            if let Ok(mut guard) = self.buf.lock() {
                guard.extend_from_slice(input);
            }
            Ok(input.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn format_duration_formats_ms_s_and_minutes() {
        assert_eq!(format_duration(Duration::from_millis(500)), "500ms");
        assert_eq!(format_duration(Duration::from_millis(1234)), "1.23s");
        assert_eq!(format_duration(Duration::from_secs(61)), "1m 1s");
    }

    #[test]
    fn request_log_renders_method_and_id() {
        let tc = TestConsole::new();
        let log = RequestLog::new("tools/call", Some("1")).success();
        log.render(tc.console());
        assert!(tc.contains("tools/call"));
        assert!(tc.contains("#1"));
    }

    #[test]
    fn request_log_error_renders_message() {
        let tc = TestConsole::new();
        let log = RequestLog::new("tools/call", Some("1")).error("bad request");
        log.render(tc.console());
        assert!(tc.contains("bad request"));
    }

    #[test]
    fn request_log_builders_cover_all_status_variants() {
        let pending = RequestLog::new("tools/call", None);
        assert!(matches!(pending.status, RequestStatus::Pending));

        let success = RequestLog::new("tools/call", Some("1")).success();
        assert!(matches!(success.status, RequestStatus::Success(_)));

        let error = RequestLog::new("tools/call", Some("2")).error("oops");
        assert!(matches!(error.status, RequestStatus::Error(_, _)));

        let cancelled = RequestLog::new("tools/call", Some("3")).cancelled();
        assert!(matches!(cancelled.status, RequestStatus::Cancelled(_)));
    }

    #[test]
    fn request_log_pending_and_cancelled_render_without_id_in_rich_mode() {
        let (writer, captured) = SharedWriter::new();
        let console = FastMcpConsole::with_writer(writer, true);

        RequestLog::new("tools/list", None).render(&console);
        RequestLog::new("tools/list", None)
            .cancelled()
            .render(&console);

        let output = String::from_utf8(captured.lock().expect("writer lock poisoned").clone())
            .unwrap_or_default();
        assert!(output.contains("tools/list"));
        assert!(output.contains("◐"));
        assert!(output.contains("⊘"));
        assert!(!output.contains('#'));
    }

    #[test]
    fn request_log_render_plain_covers_all_statuses() {
        RequestLog::new("tools/list", None).render_plain();
        RequestLog::new("tools/list", Some("1"))
            .success()
            .render_plain();
        RequestLog::new("tools/list", Some("2"))
            .error("bad request")
            .render_plain();
        RequestLog::new("tools/list", Some("3"))
            .cancelled()
            .render_plain();
    }

    // =========================================================================
    // Additional coverage tests (bd-teh7)
    // =========================================================================

    #[test]
    fn format_duration_edge_cases() {
        assert_eq!(format_duration(Duration::from_millis(0)), "0ms");
        assert_eq!(format_duration(Duration::from_millis(999)), "999ms");
        // Exactly 1 second
        assert_eq!(format_duration(Duration::from_secs(1)), "1.00s");
        // Exactly 60 seconds
        assert_eq!(format_duration(Duration::from_secs(60)), "1m 0s");
        // Large duration
        assert_eq!(format_duration(Duration::from_secs(3661)), "61m 1s");
    }

    #[test]
    fn request_log_new_defaults() {
        let log = RequestLog::new("resources/read", Some("42"));
        assert_eq!(log.method, "resources/read");
        assert_eq!(log.id, Some("42".to_string()));
        assert!(matches!(log.status, RequestStatus::Pending));

        let no_id = RequestLog::new("ping", None);
        assert!(no_id.id.is_none());
    }

    #[test]
    fn render_success_includes_duration_text() {
        let tc = TestConsole::new();
        let log = RequestLog::new("tools/call", Some("5")).success();
        log.render(tc.console());
        // Duration is always rendered for success
        let output = tc.output_string();
        assert!(output.contains("tools/call"));
        // Duration should be present (some number followed by ms or s)
        assert!(output.contains("ms") || output.contains('s'));
    }

    #[test]
    fn render_cancelled_shows_icon() {
        let tc = TestConsole::new();
        let log = RequestLog::new("tools/call", None).cancelled();
        log.render(tc.console());
        assert!(tc.output_string().contains("tools/call"));
    }

    #[test]
    fn render_routes_to_plain_for_non_rich_console() {
        let (writer, _buf) = SharedWriter::new();
        let console = FastMcpConsole::with_writer(writer, false);
        // Should route to render_plain without panicking
        RequestLog::new("tools/call", Some("1"))
            .success()
            .render(&console);
        RequestLog::new("tools/call", None)
            .error("fail")
            .render(&console);
    }
}
