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
    use crate::testing::TestConsole;

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
}
