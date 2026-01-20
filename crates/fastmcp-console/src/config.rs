//! Centralized configuration for FastMCP console output.
//!
//! `ConsoleConfig` provides a single point of configuration for all aspects
//! of rich console output, supporting both programmatic and environment
//! variable-based configuration.

use crate::detection::DisplayContext;
use std::env;

/// Comprehensive configuration for FastMCP console output
#[derive(Debug, Clone)]
pub struct ConsoleConfig {
    // Display mode
    /// Override display context (None = auto-detect)
    pub context: Option<DisplayContext>,
    /// Force color output even in non-TTY
    pub force_color: Option<bool>,
    /// Force plain text mode (no styling)
    pub force_plain: bool,

    // Theme
    /// Custom color overrides (theme accessed via crate::theme::theme())
    pub custom_colors: Option<CustomColors>,

    // Startup
    /// Show startup banner
    pub show_banner: bool,
    /// Show capabilities list in banner
    pub show_capabilities: bool,
    /// Banner display style
    pub banner_style: BannerStyle,

    // Logging
    /// Log level filter
    pub log_level: Option<log::Level>,
    /// Show timestamps in logs
    pub log_timestamps: bool,
    /// Show target module in logs
    pub log_targets: bool,
    /// Show file and line in logs
    pub log_file_line: bool,

    // Runtime
    /// Show periodic stats
    pub show_stats_periodic: bool,
    /// Stats display interval in seconds
    pub stats_interval_secs: u64,
    /// Show request/response traffic
    pub show_request_traffic: bool,
    /// Traffic logging verbosity
    pub traffic_verbosity: TrafficVerbosity,

    // Errors
    /// Show fix suggestions for errors
    pub show_suggestions: bool,
    /// Show error codes
    pub show_error_codes: bool,
    /// Show backtraces for errors
    pub show_backtrace: bool,

    // Output limits
    /// Maximum rows in tables
    pub max_table_rows: usize,
    /// Maximum depth for JSON display
    pub max_json_depth: usize,
    /// Truncate long strings at this length
    pub truncate_at: usize,
}

/// Style variants for the startup banner
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BannerStyle {
    /// Full banner with logo, info panel, and capabilities
    #[default]
    Full,
    /// Compact banner without logo
    Compact,
    /// Minimal one-line banner
    Minimal,
    /// No banner at all
    None,
}

/// Verbosity levels for traffic logging
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TrafficVerbosity {
    /// No traffic logging
    #[default]
    None,
    /// Summary only (method name, timing)
    Summary,
    /// Include headers/metadata
    Headers,
    /// Full request/response bodies
    Full,
}

/// Custom color overrides
#[derive(Debug, Clone, Default)]
pub struct CustomColors {
    /// Primary brand color override
    pub primary: Option<String>,
    /// Secondary accent color override
    pub secondary: Option<String>,
    /// Success color override
    pub success: Option<String>,
    /// Warning color override
    pub warning: Option<String>,
    /// Error color override
    pub error: Option<String>,
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self {
            context: None,
            force_color: None,
            force_plain: false,
            custom_colors: None,
            show_banner: true,
            show_capabilities: true,
            banner_style: BannerStyle::Full,
            log_level: None,
            log_timestamps: true,
            log_targets: true,
            log_file_line: false,
            show_stats_periodic: false,
            stats_interval_secs: 60,
            show_request_traffic: false,
            traffic_verbosity: TrafficVerbosity::None,
            show_suggestions: true,
            show_error_codes: true,
            show_backtrace: false,
            max_table_rows: 100,
            max_json_depth: 5,
            truncate_at: 200,
        }
    }
}

impl ConsoleConfig {
    /// Create config with defaults
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create config from environment variables
    ///
    /// # Environment Variables
    ///
    /// | Variable | Values | Description |
    /// |----------|--------|-------------|
    /// | `FASTMCP_FORCE_COLOR` | (set) | Force rich output |
    /// | `FASTMCP_PLAIN` | (set) | Force plain output |
    /// | `NO_COLOR` | (set) | Disable colors (standard) |
    /// | `FASTMCP_BANNER` | full/compact/minimal/none | Banner style |
    /// | `FASTMCP_LOG` | trace/debug/info/warn/error | Log level |
    /// | `FASTMCP_LOG_TIMESTAMPS` | 0/1 | Show timestamps |
    /// | `FASTMCP_TRAFFIC` | none/summary/headers/full | Traffic logging |
    /// | `RUST_BACKTRACE` | 1/full | Show backtraces |
    #[must_use]
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // Display mode
        if env::var("FASTMCP_FORCE_COLOR").is_ok() {
            config.force_color = Some(true);
        }
        if env::var("FASTMCP_PLAIN").is_ok() || env::var("NO_COLOR").is_ok() {
            config.force_plain = true;
        }

        // Banner
        if let Ok(val) = env::var("FASTMCP_BANNER") {
            config.banner_style = match val.to_lowercase().as_str() {
                "compact" => BannerStyle::Compact,
                "minimal" => BannerStyle::Minimal,
                "none" | "0" | "false" => BannerStyle::None,
                // "full" and any other value default to Full
                _ => BannerStyle::Full,
            };
            config.show_banner = !matches!(config.banner_style, BannerStyle::None);
        }

        // Logging
        if let Ok(level) = env::var("FASTMCP_LOG") {
            config.log_level = match level.to_lowercase().as_str() {
                "trace" => Some(log::Level::Trace),
                "debug" => Some(log::Level::Debug),
                "info" => Some(log::Level::Info),
                "warn" | "warning" => Some(log::Level::Warn),
                "error" => Some(log::Level::Error),
                _ => None,
            };
        }
        if env::var("FASTMCP_LOG_TIMESTAMPS")
            .map(|v| v == "0" || v.to_lowercase() == "false")
            .unwrap_or(false)
        {
            config.log_timestamps = false;
        }

        // Traffic
        if let Ok(val) = env::var("FASTMCP_TRAFFIC") {
            config.traffic_verbosity = match val.to_lowercase().as_str() {
                "summary" | "1" => TrafficVerbosity::Summary,
                "headers" | "2" => TrafficVerbosity::Headers,
                "full" | "3" => TrafficVerbosity::Full,
                // "none", "0", and any other value default to None
                _ => TrafficVerbosity::None,
            };
            config.show_request_traffic =
                !matches!(config.traffic_verbosity, TrafficVerbosity::None);
        }

        // Errors
        if env::var("RUST_BACKTRACE").is_ok() {
            config.show_backtrace = true;
        }

        config
    }

    // ─────────────────────────────────────────────────
    // Builder Methods
    // ─────────────────────────────────────────────────

    /// Force color output
    #[must_use]
    pub fn force_color(mut self, force: bool) -> Self {
        self.force_color = Some(force);
        self
    }

    /// Enable plain text mode (no styling)
    #[must_use]
    pub fn plain_mode(mut self) -> Self {
        self.force_plain = true;
        self
    }

    /// Set the banner style
    #[must_use]
    pub fn with_banner(mut self, style: BannerStyle) -> Self {
        self.banner_style = style;
        self.show_banner = !matches!(style, BannerStyle::None);
        self
    }

    /// Disable the banner entirely
    #[must_use]
    pub fn without_banner(mut self) -> Self {
        self.show_banner = false;
        self.banner_style = BannerStyle::None;
        self
    }

    /// Set the log level
    #[must_use]
    pub fn with_log_level(mut self, level: log::Level) -> Self {
        self.log_level = Some(level);
        self
    }

    /// Set traffic logging verbosity
    #[must_use]
    pub fn with_traffic(mut self, verbosity: TrafficVerbosity) -> Self {
        self.traffic_verbosity = verbosity;
        self.show_request_traffic = !matches!(verbosity, TrafficVerbosity::None);
        self
    }

    /// Enable periodic stats display
    #[must_use]
    pub fn with_periodic_stats(mut self, interval_secs: u64) -> Self {
        self.show_stats_periodic = true;
        self.stats_interval_secs = interval_secs;
        self
    }

    /// Disable fix suggestions for errors
    #[must_use]
    pub fn without_suggestions(mut self) -> Self {
        self.show_suggestions = false;
        self
    }

    /// Set custom colors
    #[must_use]
    pub fn with_custom_colors(mut self, colors: CustomColors) -> Self {
        self.custom_colors = Some(colors);
        self
    }

    /// Set display context explicitly
    #[must_use]
    pub fn with_context(mut self, context: DisplayContext) -> Self {
        self.context = Some(context);
        self
    }

    /// Set maximum table rows
    #[must_use]
    pub fn with_max_table_rows(mut self, max: usize) -> Self {
        self.max_table_rows = max;
        self
    }

    /// Set maximum JSON depth
    #[must_use]
    pub fn with_max_json_depth(mut self, max: usize) -> Self {
        self.max_json_depth = max;
        self
    }

    /// Set truncation length
    #[must_use]
    pub fn with_truncate_at(mut self, len: usize) -> Self {
        self.truncate_at = len;
        self
    }

    // ─────────────────────────────────────────────────
    // Accessor Methods
    // ─────────────────────────────────────────────────

    /// Get the theme (uses global theme singleton)
    #[must_use]
    pub fn theme(&self) -> &'static crate::theme::FastMcpTheme {
        crate::theme::theme()
    }

    // ─────────────────────────────────────────────────
    // Resolution Methods
    // ─────────────────────────────────────────────────

    /// Resolve the display context based on config and environment
    #[must_use]
    pub fn resolve_context(&self) -> DisplayContext {
        if self.force_plain {
            return DisplayContext::new_agent();
        }
        if let Some(true) = self.force_color {
            return DisplayContext::new_human();
        }
        self.context.unwrap_or_else(DisplayContext::detect)
    }

    /// Check if rich output should be used based on resolved context
    #[must_use]
    pub fn should_use_rich(&self) -> bool {
        self.resolve_context().is_human()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ConsoleConfig::new();
        assert!(config.show_banner);
        assert!(config.show_capabilities);
        assert_eq!(config.banner_style, BannerStyle::Full);
        assert!(config.log_timestamps);
        assert!(!config.force_plain);
        assert_eq!(config.max_table_rows, 100);
    }

    #[test]
    fn test_builder_pattern() {
        let config = ConsoleConfig::new()
            .with_banner(BannerStyle::Compact)
            .with_log_level(log::Level::Debug)
            .with_traffic(TrafficVerbosity::Summary)
            .with_periodic_stats(30);

        assert_eq!(config.banner_style, BannerStyle::Compact);
        assert_eq!(config.log_level, Some(log::Level::Debug));
        assert_eq!(config.traffic_verbosity, TrafficVerbosity::Summary);
        assert!(config.show_stats_periodic);
        assert_eq!(config.stats_interval_secs, 30);
    }

    #[test]
    fn test_plain_mode() {
        let config = ConsoleConfig::new().plain_mode();
        assert!(config.force_plain);
        assert_eq!(config.resolve_context(), DisplayContext::Agent);
    }

    #[test]
    fn test_force_color() {
        let config = ConsoleConfig::new().force_color(true);
        assert_eq!(config.force_color, Some(true));
        assert_eq!(config.resolve_context(), DisplayContext::Human);
    }

    #[test]
    fn test_without_banner() {
        let config = ConsoleConfig::new().without_banner();
        assert!(!config.show_banner);
        assert_eq!(config.banner_style, BannerStyle::None);
    }
}
