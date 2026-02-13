//! Stats rendering utilities.
//!
//! Provides rich and plain renderers for server statistics snapshots.

use std::time::Duration;

use rich_rust::r#box::ROUNDED;
use rich_rust::markup;
use rich_rust::prelude::*;

use crate::console::FastMcpConsole;
use crate::detection::DisplayContext;
use crate::theme::FastMcpTheme;

use super::StatsSnapshot;

/// Renders server statistics in rich and plain formats.
#[derive(Debug, Clone)]
pub struct StatsRenderer {
    theme: &'static FastMcpTheme,
    context: DisplayContext,
}

impl StatsRenderer {
    /// Create a renderer with an explicit display context.
    #[must_use]
    pub fn new(context: DisplayContext) -> Self {
        Self {
            theme: crate::theme::theme(),
            context,
        }
    }

    /// Create a renderer using auto-detected display context.
    #[must_use]
    pub fn detect() -> Self {
        Self::new(DisplayContext::detect())
    }

    /// Render a full statistics panel.
    pub fn render_panel(&self, stats: &StatsSnapshot, console: &FastMcpConsole) {
        if !self.should_use_rich(console) {
            self.render_plain(stats, console);
            return;
        }

        let content = self.build_panel_text(stats);
        let text = markup::render_or_plain(&content);
        let panel = Panel::from_rich_text(&text, console.width())
            .title("Server Statistics")
            .border_style(self.theme.border_style.clone())
            .rounded();

        console.render(&panel);
    }

    /// Render as a compact table.
    pub fn render_table(&self, stats: &StatsSnapshot, console: &FastMcpConsole) {
        if !self.should_use_rich(console) {
            self.render_plain(stats, console);
            return;
        }

        let mut table = Table::new()
            .title("Runtime Metrics")
            .title_style(self.theme.header_style.clone())
            .box_style(&ROUNDED)
            .border_style(self.theme.border_style.clone())
            .show_header(true)
            .with_column(Column::new("Metric").style(self.theme.label_style.clone()))
            .with_column(
                Column::new("Value")
                    .justify(JustifyMethod::Right)
                    .style(self.theme.value_style.clone()),
            );

        table.add_row(Row::new(vec![
            Cell::new("Uptime"),
            Cell::new(self.format_duration(stats.uptime)),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Total Requests"),
            Cell::new(stats.total_requests.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Success Rate"),
            Cell::new(self.format_percentage(stats.successful_requests, stats.total_requests)),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Failed Requests"),
            Cell::new(stats.failed_requests.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Cancelled Requests"),
            Cell::new(stats.cancelled_requests.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Tool Calls"),
            Cell::new(stats.tool_calls.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Resource Reads"),
            Cell::new(stats.resource_reads.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Prompt Gets"),
            Cell::new(stats.prompt_gets.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("List Operations"),
            Cell::new(stats.list_operations.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Avg Latency"),
            Cell::new(self.format_latency(stats.avg_latency)),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Max Latency"),
            Cell::new(self.format_latency(stats.max_latency)),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Min Latency"),
            Cell::new(self.format_latency(stats.min_latency)),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Active Connections"),
            Cell::new(stats.active_connections.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Total Connections"),
            Cell::new(stats.total_connections.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Data Received"),
            Cell::new(self.format_bytes(stats.bytes_received)),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Data Sent"),
            Cell::new(self.format_bytes(stats.bytes_sent)),
        ]));

        console.render(&table);
    }

    /// Render a compact one-line summary.
    pub fn render_oneline(&self, stats: &StatsSnapshot, console: &FastMcpConsole) {
        let line = if self.should_use_rich(console) {
            let dim = color_hex(&self.theme.text_dim);
            let info = color_hex(&self.theme.info);
            let ok = color_hex(&self.theme.success);
            let warn = color_hex(&self.theme.warning);
            format!(
                "[{dim}]⏱[/] {} [{dim}]|[/] [{info}]{}[/] reqs [{dim}]|[/] [{ok}]{:.1}%[/] ok [{dim}]|[/] [{warn}]{}[/] avg",
                self.format_duration(stats.uptime),
                stats.total_requests,
                self.success_rate(stats) * 100.0,
                self.format_latency(stats.avg_latency)
            )
        } else {
            format!(
                "Uptime: {} | Requests: {} | Success: {:.1}% | Avg latency: {}",
                self.format_duration(stats.uptime),
                stats.total_requests,
                self.success_rate(stats) * 100.0,
                self.format_latency(stats.avg_latency)
            )
        };

        console.print(&line);
    }

    fn should_use_rich(&self, console: &FastMcpConsole) -> bool {
        self.context.is_human() && console.is_rich()
    }

    fn build_panel_text(&self, stats: &StatsSnapshot) -> String {
        let label = color_hex(&self.theme.text_dim);
        let value = color_hex(&self.theme.text);

        let rows = [
            ("Uptime", self.format_duration(stats.uptime)),
            ("Total Requests", stats.total_requests.to_string()),
            (
                "Success Rate",
                self.format_percentage(stats.successful_requests, stats.total_requests),
            ),
            ("Failed Requests", stats.failed_requests.to_string()),
            ("Cancelled Requests", stats.cancelled_requests.to_string()),
            ("Tool Calls", stats.tool_calls.to_string()),
            ("Resource Reads", stats.resource_reads.to_string()),
            ("Prompt Gets", stats.prompt_gets.to_string()),
            ("List Operations", stats.list_operations.to_string()),
            ("Avg Latency", self.format_latency(stats.avg_latency)),
            ("Max Latency", self.format_latency(stats.max_latency)),
            ("Min Latency", self.format_latency(stats.min_latency)),
            ("Active Connections", stats.active_connections.to_string()),
            ("Total Connections", stats.total_connections.to_string()),
            ("Data Received", self.format_bytes(stats.bytes_received)),
            ("Data Sent", self.format_bytes(stats.bytes_sent)),
        ];

        let mut content = String::new();
        for (idx, (label_text, value_text)) in rows.iter().enumerate() {
            content.push_str(&format!(
                "[{label}]{:<18}[/] [{value}]{}[/]",
                label_text, value_text
            ));
            if idx + 1 < rows.len() {
                content.push('\n');
            }
        }
        content
    }

    fn render_plain(&self, stats: &StatsSnapshot, console: &FastMcpConsole) {
        console.print("=== Server Statistics ===");
        console.print(&format!("Uptime: {}", self.format_duration(stats.uptime)));
        console.print(&format!(
            "Requests: {} total, {} successful, {} failed, {} cancelled",
            stats.total_requests,
            stats.successful_requests,
            stats.failed_requests,
            stats.cancelled_requests
        ));
        console.print(&format!(
            "Ops: {} tool calls, {} resource reads, {} prompt gets, {} lists",
            stats.tool_calls, stats.resource_reads, stats.prompt_gets, stats.list_operations
        ));
        console.print(&format!(
            "Latency: {} avg, {} max, {} min",
            self.format_latency(stats.avg_latency),
            self.format_latency(stats.max_latency),
            self.format_latency(stats.min_latency)
        ));
        console.print(&format!(
            "Connections: {} active, {} total",
            stats.active_connections, stats.total_connections
        ));
        console.print(&format!(
            "Data: {} received, {} sent",
            self.format_bytes(stats.bytes_received),
            self.format_bytes(stats.bytes_sent)
        ));
    }

    fn format_duration(&self, d: Duration) -> String {
        let secs = d.as_secs();
        if secs < 60 {
            format!("{}s", secs)
        } else if secs < 3600 {
            format!("{}m {}s", secs / 60, secs % 60)
        } else {
            format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
        }
    }

    fn format_latency(&self, d: Duration) -> String {
        let micros = d.as_micros();
        if micros < 1000 {
            format!("{}us", micros)
        } else if micros < 1_000_000 {
            format!("{:.1}ms", micros as f64 / 1000.0)
        } else {
            format!("{:.2}s", d.as_secs_f64())
        }
    }

    fn format_bytes(&self, bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;

        if bytes < KB {
            format!("{bytes} B")
        } else if bytes < MB {
            format!("{:.1} KB", bytes as f64 / KB as f64)
        } else if bytes < GB {
            format!("{:.1} MB", bytes as f64 / MB as f64)
        } else {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        }
    }

    fn format_percentage(&self, part: u64, total: u64) -> String {
        if total == 0 {
            "N/A".to_string()
        } else {
            format!("{:.1}%", (part as f64 / total as f64) * 100.0)
        }
    }

    fn success_rate(&self, stats: &StatsSnapshot) -> f64 {
        if stats.total_requests == 0 {
            1.0
        } else {
            stats.successful_requests as f64 / stats.total_requests as f64
        }
    }
}

impl Default for StatsRenderer {
    fn default() -> Self {
        Self::detect()
    }
}

fn color_hex(color: &Color) -> String {
    color.get_truecolor().hex()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestConsole;
    use crate::theme::theme;

    fn sample_snapshot() -> StatsSnapshot {
        StatsSnapshot {
            uptime: Duration::from_secs(3661),
            total_requests: 100,
            successful_requests: 90,
            failed_requests: 8,
            cancelled_requests: 2,
            tool_calls: 70,
            resource_reads: 20,
            prompt_gets: 10,
            list_operations: 5,
            avg_latency: Duration::from_millis(12),
            max_latency: Duration::from_millis(50),
            min_latency: Duration::from_millis(2),
            active_connections: 3,
            total_connections: 5,
            bytes_received: 1024,
            bytes_sent: 2048,
        }
    }

    #[test]
    fn test_format_duration() {
        let renderer = StatsRenderer::new(DisplayContext::new_agent());
        assert_eq!(renderer.format_duration(Duration::from_secs(45)), "45s");
        assert_eq!(renderer.format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(renderer.format_duration(Duration::from_mins(185)), "3h 5m");
        assert_eq!(renderer.format_duration(Duration::from_secs(3600)), "1h 0m");
    }

    #[test]
    fn test_format_latency() {
        let renderer = StatsRenderer::new(DisplayContext::new_agent());
        assert_eq!(renderer.format_latency(Duration::from_micros(500)), "500us");
        assert_eq!(renderer.format_latency(Duration::from_millis(1)), "1.0ms");
        assert_eq!(
            renderer.format_latency(Duration::from_micros(1500)),
            "1.5ms"
        );
        assert_eq!(renderer.format_latency(Duration::from_secs(1)), "1.00s");
        assert_eq!(renderer.format_latency(Duration::from_secs(2)), "2.00s");
    }

    #[test]
    fn test_format_bytes() {
        let renderer = StatsRenderer::new(DisplayContext::new_agent());
        assert_eq!(renderer.format_bytes(500), "500 B");
        assert_eq!(renderer.format_bytes(2048), "2.0 KB");
        assert_eq!(renderer.format_bytes(3 * 1024 * 1024), "3.0 MB");
        assert_eq!(renderer.format_bytes(3 * 1024 * 1024 * 1024), "3.00 GB");
    }

    #[test]
    fn test_render_table_rich() {
        let stats = sample_snapshot();
        let console = TestConsole::new_rich();
        let renderer = StatsRenderer::new(DisplayContext::new_human());
        renderer.render_table(&stats, console.console());
        console.assert_contains("Total Requests");
        console.assert_contains("Success Rate");
    }

    #[test]
    fn test_render_oneline_plain() {
        let stats = sample_snapshot();
        let console = TestConsole::new();
        let renderer = StatsRenderer::new(DisplayContext::new_agent());
        renderer.render_oneline(&stats, console.console());
        console.assert_contains("Uptime");
        console.assert_contains("Requests");
    }

    #[test]
    fn test_render_panel_rich_and_plain_fallback() {
        let stats = sample_snapshot();

        let rich_console = TestConsole::new_rich();
        let rich_renderer = StatsRenderer::new(DisplayContext::new_human());
        rich_renderer.render_panel(&stats, rich_console.console());
        rich_console.assert_contains("Server Statistics");
        rich_console.assert_contains("Total Requests");
        rich_console.assert_contains("Data Sent");

        let plain_console = TestConsole::new();
        let plain_renderer = StatsRenderer::new(DisplayContext::new_agent());
        plain_renderer.render_panel(&stats, plain_console.console());
        plain_console.assert_contains("=== Server Statistics ===");
        plain_console.assert_contains("Requests:");
        plain_console.assert_contains("Connections:");
    }

    #[test]
    fn test_render_table_plain_fallback() {
        let stats = sample_snapshot();
        let console = TestConsole::new();
        let renderer = StatsRenderer::new(DisplayContext::new_agent());
        renderer.render_table(&stats, console.console());
        console.assert_contains("=== Server Statistics ===");
        console.assert_contains("Ops:");
        console.assert_contains("Data:");
    }

    #[test]
    fn test_render_oneline_rich() {
        let stats = sample_snapshot();
        let console = TestConsole::new_rich();
        let renderer = StatsRenderer::new(DisplayContext::new_human());
        renderer.render_oneline(&stats, console.console());
        console.assert_contains("reqs");
        console.assert_contains("avg");
        console.assert_contains("90.0%");
    }

    #[test]
    fn test_percentage_and_success_rate_edge_cases() {
        let renderer = StatsRenderer::new(DisplayContext::new_agent());
        assert_eq!(renderer.format_percentage(0, 0), "N/A");
        assert_eq!(renderer.format_percentage(1, 3), "33.3%");

        let mut zero = sample_snapshot();
        zero.total_requests = 0;
        zero.successful_requests = 0;
        assert!((renderer.success_rate(&zero) - 1.0).abs() < f64::EPSILON);

        let normal = sample_snapshot();
        assert!((renderer.success_rate(&normal) - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_build_panel_text_contains_expected_rows() {
        let renderer = StatsRenderer::new(DisplayContext::new_human());
        let content = renderer.build_panel_text(&sample_snapshot());
        assert!(content.contains("Uptime"));
        assert!(content.contains("Total Requests"));
        assert!(content.contains("Data Sent"));
    }

    #[test]
    fn test_should_use_rich_respects_context_and_console() {
        let human = StatsRenderer::new(DisplayContext::new_human());
        let agent = StatsRenderer::new(DisplayContext::new_agent());
        let rich_console = FastMcpConsole::with_enabled(true);
        let plain_console = FastMcpConsole::with_enabled(false);

        assert!(human.should_use_rich(&rich_console));
        assert!(!human.should_use_rich(&plain_console));
        assert!(!agent.should_use_rich(&rich_console));
    }

    #[test]
    fn test_default_detect_and_color_hex() {
        let _default = StatsRenderer::default();
        let _detect = StatsRenderer::detect();
        let hex = color_hex(&theme().info);
        assert_eq!(hex.len(), 7);
        assert!(hex.starts_with('#'));
    }

    // =========================================================================
    // Additional coverage tests (bd-2xpx)
    // =========================================================================

    #[test]
    fn stats_renderer_debug_and_clone() {
        let renderer = StatsRenderer::new(DisplayContext::new_agent());
        let debug = format!("{renderer:?}");
        assert!(debug.contains("StatsRenderer"));

        let cloned = renderer.clone();
        assert!(!cloned.should_use_rich(&FastMcpConsole::with_enabled(true)));
    }

    #[test]
    fn format_duration_boundary_exactly_60s() {
        let renderer = StatsRenderer::new(DisplayContext::new_agent());
        assert_eq!(renderer.format_duration(Duration::from_secs(0)), "0s");
        assert_eq!(renderer.format_duration(Duration::from_secs(59)), "59s");
        assert_eq!(renderer.format_duration(Duration::from_secs(60)), "1m 0s");
        assert_eq!(
            renderer.format_duration(Duration::from_secs(3599)),
            "59m 59s"
        );
    }

    #[test]
    fn format_latency_boundary_values() {
        let renderer = StatsRenderer::new(DisplayContext::new_agent());
        assert_eq!(renderer.format_latency(Duration::from_micros(0)), "0us");
        assert_eq!(renderer.format_latency(Duration::from_micros(999)), "999us");
        assert_eq!(renderer.format_latency(Duration::from_millis(1)), "1.0ms");
        assert_eq!(
            renderer.format_latency(Duration::from_micros(999_999)),
            "1000.0ms"
        );
    }

    #[test]
    fn format_bytes_boundary_values() {
        let renderer = StatsRenderer::new(DisplayContext::new_agent());
        assert_eq!(renderer.format_bytes(0), "0 B");
        assert_eq!(renderer.format_bytes(1023), "1023 B");
        assert_eq!(renderer.format_bytes(1024), "1.0 KB");
        assert_eq!(renderer.format_bytes(1024 * 1024 - 1), "1024.0 KB");
        assert_eq!(renderer.format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(renderer.format_bytes(1024 * 1024 * 1024 - 1), "1024.0 MB");
    }

    #[test]
    fn format_percentage_full_coverage() {
        let renderer = StatsRenderer::new(DisplayContext::new_agent());
        assert_eq!(renderer.format_percentage(100, 100), "100.0%");
        assert_eq!(renderer.format_percentage(50, 200), "25.0%");
    }

    #[test]
    fn render_oneline_with_zero_requests() {
        let tc = TestConsole::new();
        let renderer = StatsRenderer::new(DisplayContext::new_agent());
        let mut stats = sample_snapshot();
        stats.total_requests = 0;
        stats.successful_requests = 0;
        renderer.render_oneline(&stats, tc.console());
        // success_rate returns 1.0 when total_requests is 0
        tc.assert_contains("Uptime");
        tc.assert_contains("Requests");
        tc.assert_contains("100.0");
    }

    #[test]
    fn build_panel_text_has_16_rows() {
        let renderer = StatsRenderer::new(DisplayContext::new_human());
        let content = renderer.build_panel_text(&sample_snapshot());
        let line_count = content.lines().count();
        assert_eq!(line_count, 16);
    }
}
