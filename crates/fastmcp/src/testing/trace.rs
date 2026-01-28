//! E2E test logging framework with structured trace output.
//!
//! Provides comprehensive logging for E2E tests with:
//! - Structured JSON output
//! - Request/response correlation IDs
//! - Timing information (start, end, duration)
//! - Nested operation tracking (spans)
//! - Log level filtering
//! - File and console output options
//!
//! # Example
//!
//! ```ignore
//! use fastmcp::testing::prelude::*;
//!
//! let mut trace = TestTrace::new("client-server-flow");
//!
//! // Log request/response pairs
//! trace.log_request("tools/list", &request);
//! // ... operation ...
//! trace.log_response("tools/list", &response, duration);
//!
//! // Save to file
//! trace.save("test_traces/client_server.json")?;
//!
//! // Or print summary
//! trace.print_summary();
//! ```
//!
//! # Environment Variable
//!
//! Set `FASTMCP_TEST_TRACE=1` to enable trace output during tests.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Check if test tracing is enabled via environment variable.
pub fn is_trace_enabled() -> bool {
    std::env::var("FASTMCP_TEST_TRACE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Global correlation ID counter.
static CORRELATION_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generates a new unique correlation ID.
fn new_correlation_id() -> String {
    let id = CORRELATION_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("trace-{id:08x}")
}

/// Entry type in a trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TraceEntry {
    /// A request was sent.
    Request {
        correlation_id: String,
        timestamp: String,
        method: String,
        params: Option<serde_json::Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        span_id: Option<String>,
    },
    /// A response was received.
    Response {
        correlation_id: String,
        timestamp: String,
        method: String,
        duration_ms: f64,
        result: Option<serde_json::Value>,
        error: Option<serde_json::Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        span_id: Option<String>,
    },
    /// A span was started.
    SpanStart {
        span_id: String,
        parent_span_id: Option<String>,
        name: String,
        timestamp: String,
    },
    /// A span was ended.
    SpanEnd {
        span_id: String,
        timestamp: String,
        duration_ms: f64,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// A log message.
    Log {
        timestamp: String,
        level: TraceLevel,
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        span_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<serde_json::Value>,
    },
    /// A metric measurement.
    Metric {
        timestamp: String,
        name: String,
        value: f64,
        #[serde(skip_serializing_if = "Option::is_none")]
        unit: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        span_id: Option<String>,
    },
}

/// Log level for trace entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TraceLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl std::fmt::Display for TraceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TraceLevel::Debug => write!(f, "DEBUG"),
            TraceLevel::Info => write!(f, "INFO"),
            TraceLevel::Warn => write!(f, "WARN"),
            TraceLevel::Error => write!(f, "ERROR"),
        }
    }
}

/// A span for tracking nested operations.
#[derive(Debug)]
pub struct Span {
    /// Unique span ID.
    pub id: String,
    /// Parent span ID, if any.
    pub parent_id: Option<String>,
    /// Span name/description.
    pub name: String,
    /// When the span started.
    pub start: Instant,
    /// Start timestamp (ISO 8601).
    pub start_timestamp: String,
}

/// Complete trace of a test execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestTraceOutput {
    /// Name of the test/trace.
    pub name: String,
    /// When the trace started.
    pub started_at: String,
    /// When the trace ended.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    /// Total duration in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<f64>,
    /// All trace entries.
    pub entries: Vec<TraceEntry>,
    /// Summary statistics.
    pub summary: TraceSummary,
    /// Custom metadata.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Summary statistics for a trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceSummary {
    /// Total number of requests.
    pub request_count: usize,
    /// Total number of responses.
    pub response_count: usize,
    /// Number of successful responses.
    pub success_count: usize,
    /// Number of error responses.
    pub error_count: usize,
    /// Total number of spans.
    pub span_count: usize,
    /// Methods called with their counts.
    pub method_counts: HashMap<String, usize>,
    /// Request/response timing by method.
    pub method_timings: HashMap<String, MethodTiming>,
}

/// Timing statistics for a method.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MethodTiming {
    /// Number of calls.
    pub count: usize,
    /// Total duration in milliseconds.
    pub total_ms: f64,
    /// Minimum duration.
    pub min_ms: Option<f64>,
    /// Maximum duration.
    pub max_ms: Option<f64>,
    /// Mean duration.
    pub mean_ms: Option<f64>,
}

/// Builder for creating test traces.
///
/// # Example
///
/// ```ignore
/// let trace = TestTrace::builder("my-test")
///     .with_metadata("env", "test")
///     .with_console_output(true)
///     .build();
/// ```
pub struct TestTraceBuilder {
    name: String,
    metadata: HashMap<String, serde_json::Value>,
    console_output: bool,
    min_level: TraceLevel,
}

impl TestTraceBuilder {
    /// Creates a new trace builder.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            metadata: HashMap::new(),
            console_output: is_trace_enabled(),
            min_level: TraceLevel::Debug,
        }
    }

    /// Adds custom metadata to the trace.
    #[must_use]
    pub fn with_metadata(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Enables or disables console output.
    #[must_use]
    pub fn with_console_output(mut self, enabled: bool) -> Self {
        self.console_output = enabled;
        self
    }

    /// Sets the minimum log level.
    #[must_use]
    pub fn with_min_level(mut self, level: TraceLevel) -> Self {
        self.min_level = level;
        self
    }

    /// Builds the trace.
    #[must_use]
    pub fn build(self) -> TestTrace {
        TestTrace {
            name: self.name,
            started_at: current_timestamp(),
            start_instant: Instant::now(),
            entries: Vec::new(),
            metadata: self.metadata,
            console_output: self.console_output,
            min_level: self.min_level,
            active_spans: Vec::new(),
            pending_requests: HashMap::new(),
        }
    }
}

/// Main test trace collector.
///
/// Collects trace entries during test execution and can output
/// them as structured JSON or console summary.
#[derive(Debug)]
pub struct TestTrace {
    /// Name of the test/trace.
    name: String,
    /// When the trace started.
    started_at: String,
    /// Start instant for duration calculation.
    start_instant: Instant,
    /// All collected entries.
    entries: Vec<TraceEntry>,
    /// Custom metadata.
    metadata: HashMap<String, serde_json::Value>,
    /// Whether to output to console.
    console_output: bool,
    /// Minimum log level.
    min_level: TraceLevel,
    /// Stack of active spans.
    active_spans: Vec<Span>,
    /// Pending requests awaiting responses (correlation_id -> (method, start_time)).
    pending_requests: HashMap<String, (String, Instant)>,
}

impl TestTrace {
    /// Creates a new test trace with the given name.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut trace = TestTrace::new("client-server-flow");
    /// ```
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        TestTraceBuilder::new(name).build()
    }

    /// Creates a trace builder for advanced configuration.
    #[must_use]
    pub fn builder(name: impl Into<String>) -> TestTraceBuilder {
        TestTraceBuilder::new(name)
    }

    /// Returns the trace name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the current span ID, if any.
    #[must_use]
    pub fn current_span_id(&self) -> Option<&str> {
        self.active_spans.last().map(|s| s.id.as_str())
    }

    /// Logs a request.
    ///
    /// Returns a correlation ID that can be used to match with the response.
    pub fn log_request(
        &mut self,
        method: impl Into<String>,
        params: Option<&impl Serialize>,
    ) -> String {
        let correlation_id = new_correlation_id();
        let method = method.into();
        let timestamp = current_timestamp();
        let span_id = self.current_span_id().map(String::from);

        let params_value = params.and_then(|p| serde_json::to_value(p).ok());

        self.pending_requests
            .insert(correlation_id.clone(), (method.clone(), Instant::now()));

        let entry = TraceEntry::Request {
            correlation_id: correlation_id.clone(),
            timestamp: timestamp.clone(),
            method: method.clone(),
            params: params_value.clone(),
            span_id: span_id.clone(),
        };

        self.entries.push(entry);

        if self.console_output {
            let params_str = params_value
                .as_ref()
                .map(|v| format!(" {v}"))
                .unwrap_or_default();
            eprintln!("[{timestamp}] -> {method}{params_str}");
        }

        correlation_id
    }

    /// Logs a response.
    ///
    /// Uses the correlation ID from the matching request to calculate duration.
    pub fn log_response(
        &mut self,
        correlation_id: &str,
        result: Option<&impl Serialize>,
        error: Option<&impl Serialize>,
    ) {
        let timestamp = current_timestamp();
        let span_id = self.current_span_id().map(String::from);

        let (method, duration_ms) =
            if let Some((method, start)) = self.pending_requests.remove(correlation_id) {
                let duration = start.elapsed();
                (method, duration.as_secs_f64() * 1000.0)
            } else {
                ("unknown".to_string(), 0.0)
            };

        let result_value = result.and_then(|r| serde_json::to_value(r).ok());
        let error_value = error.and_then(|e| serde_json::to_value(e).ok());

        let entry = TraceEntry::Response {
            correlation_id: correlation_id.to_string(),
            timestamp: timestamp.clone(),
            method: method.clone(),
            duration_ms,
            result: result_value.clone(),
            error: error_value.clone(),
            span_id,
        };

        self.entries.push(entry);

        if self.console_output {
            let status = if error_value.is_some() {
                "ERROR"
            } else {
                "OK"
            };
            eprintln!("[{timestamp}] <- {method} ({duration_ms:.2}ms) {status}");
        }
    }

    /// Logs a response with explicit duration.
    pub fn log_response_with_duration(
        &mut self,
        method: impl Into<String>,
        duration: Duration,
        result: Option<&impl Serialize>,
        error: Option<&impl Serialize>,
    ) {
        let correlation_id = new_correlation_id();
        let method = method.into();
        let timestamp = current_timestamp();
        let span_id = self.current_span_id().map(String::from);
        let duration_ms = duration.as_secs_f64() * 1000.0;

        let result_value = result.and_then(|r| serde_json::to_value(r).ok());
        let error_value = error.and_then(|e| serde_json::to_value(e).ok());

        let entry = TraceEntry::Response {
            correlation_id,
            timestamp: timestamp.clone(),
            method: method.clone(),
            duration_ms,
            result: result_value,
            error: error_value.clone(),
            span_id,
        };

        self.entries.push(entry);

        if self.console_output {
            let status = if error_value.is_some() {
                "ERROR"
            } else {
                "OK"
            };
            eprintln!("[{timestamp}] <- {method} ({duration_ms:.2}ms) {status}");
        }
    }

    /// Starts a new span for tracking a nested operation.
    ///
    /// Returns the span ID.
    pub fn start_span(&mut self, name: impl Into<String>) -> String {
        let span_id = format!("span-{:08x}", CORRELATION_ID_COUNTER.fetch_add(1, Ordering::SeqCst));
        let parent_id = self.current_span_id().map(String::from);
        let name = name.into();
        let timestamp = current_timestamp();

        let span = Span {
            id: span_id.clone(),
            parent_id: parent_id.clone(),
            name: name.clone(),
            start: Instant::now(),
            start_timestamp: timestamp.clone(),
        };

        self.entries.push(TraceEntry::SpanStart {
            span_id: span_id.clone(),
            parent_span_id: parent_id,
            name: name.clone(),
            timestamp: timestamp.clone(),
        });

        if self.console_output {
            let indent = "  ".repeat(self.active_spans.len());
            eprintln!("[{timestamp}] {indent}┌─ {name}");
        }

        self.active_spans.push(span);
        span_id
    }

    /// Ends the current span.
    ///
    /// If `error` is provided, marks the span as failed.
    pub fn end_span(&mut self, error: Option<&str>) {
        if let Some(span) = self.active_spans.pop() {
            let timestamp = current_timestamp();
            let duration_ms = span.start.elapsed().as_secs_f64() * 1000.0;

            self.entries.push(TraceEntry::SpanEnd {
                span_id: span.id.clone(),
                timestamp: timestamp.clone(),
                duration_ms,
                error: error.map(String::from),
            });

            if self.console_output {
                let indent = "  ".repeat(self.active_spans.len());
                let status = if error.is_some() { " FAILED" } else { "" };
                eprintln!("[{timestamp}] {indent}└─ {} ({duration_ms:.2}ms){status}", span.name);
            }
        }
    }

    /// Ends a specific span by ID.
    pub fn end_span_by_id(&mut self, span_id: &str, error: Option<&str>) {
        if let Some(pos) = self.active_spans.iter().position(|s| s.id == span_id) {
            let span = self.active_spans.remove(pos);
            let timestamp = current_timestamp();
            let duration_ms = span.start.elapsed().as_secs_f64() * 1000.0;

            self.entries.push(TraceEntry::SpanEnd {
                span_id: span.id.clone(),
                timestamp,
                duration_ms,
                error: error.map(String::from),
            });
        }
    }

    /// Logs a message at the specified level.
    pub fn log(&mut self, level: TraceLevel, message: impl Into<String>) {
        if (level as u8) < (self.min_level as u8) {
            return;
        }

        let timestamp = current_timestamp();
        let message = message.into();
        let span_id = self.current_span_id().map(String::from);

        self.entries.push(TraceEntry::Log {
            timestamp: timestamp.clone(),
            level,
            message: message.clone(),
            span_id,
            data: None,
        });

        if self.console_output {
            let indent = "  ".repeat(self.active_spans.len());
            eprintln!("[{timestamp}] {indent}[{level}] {message}");
        }
    }

    /// Logs a message with additional data.
    pub fn log_with_data(
        &mut self,
        level: TraceLevel,
        message: impl Into<String>,
        data: impl Serialize,
    ) {
        if (level as u8) < (self.min_level as u8) {
            return;
        }

        let timestamp = current_timestamp();
        let message = message.into();
        let span_id = self.current_span_id().map(String::from);
        let data_value = serde_json::to_value(data).ok();

        self.entries.push(TraceEntry::Log {
            timestamp: timestamp.clone(),
            level,
            message: message.clone(),
            span_id,
            data: data_value,
        });

        if self.console_output {
            let indent = "  ".repeat(self.active_spans.len());
            eprintln!("[{timestamp}] {indent}[{level}] {message}");
        }
    }

    /// Logs a debug message.
    pub fn debug(&mut self, message: impl Into<String>) {
        self.log(TraceLevel::Debug, message);
    }

    /// Logs an info message.
    pub fn info(&mut self, message: impl Into<String>) {
        self.log(TraceLevel::Info, message);
    }

    /// Logs a warning message.
    pub fn warn(&mut self, message: impl Into<String>) {
        self.log(TraceLevel::Warn, message);
    }

    /// Logs an error message.
    pub fn error(&mut self, message: impl Into<String>) {
        self.log(TraceLevel::Error, message);
    }

    /// Records a metric value.
    pub fn metric(&mut self, name: impl Into<String>, value: f64, unit: Option<&str>) {
        let timestamp = current_timestamp();
        let span_id = self.current_span_id().map(String::from);

        self.entries.push(TraceEntry::Metric {
            timestamp,
            name: name.into(),
            value,
            unit: unit.map(String::from),
            span_id,
        });
    }

    /// Adds custom metadata to the trace.
    pub fn add_metadata(&mut self, key: impl Into<String>, value: impl Into<serde_json::Value>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Computes summary statistics from the entries.
    fn compute_summary(&self) -> TraceSummary {
        let mut summary = TraceSummary::default();

        for entry in &self.entries {
            match entry {
                TraceEntry::Request { method, .. } => {
                    summary.request_count += 1;
                    *summary.method_counts.entry(method.clone()).or_insert(0) += 1;
                }
                TraceEntry::Response {
                    method,
                    duration_ms,
                    error,
                    ..
                } => {
                    summary.response_count += 1;
                    if error.is_some() {
                        summary.error_count += 1;
                    } else {
                        summary.success_count += 1;
                    }

                    let timing = summary
                        .method_timings
                        .entry(method.clone())
                        .or_insert_with(MethodTiming::default);
                    timing.count += 1;
                    timing.total_ms += duration_ms;
                    timing.min_ms = Some(
                        timing
                            .min_ms
                            .map(|m| m.min(*duration_ms))
                            .unwrap_or(*duration_ms),
                    );
                    timing.max_ms = Some(
                        timing
                            .max_ms
                            .map(|m| m.max(*duration_ms))
                            .unwrap_or(*duration_ms),
                    );
                    timing.mean_ms = Some(timing.total_ms / timing.count as f64);
                }
                TraceEntry::SpanStart { .. } => {
                    summary.span_count += 1;
                }
                _ => {}
            }
        }

        summary
    }

    /// Builds the complete trace output.
    #[must_use]
    pub fn build_output(&self) -> TestTraceOutput {
        let duration_ms = self.start_instant.elapsed().as_secs_f64() * 1000.0;

        TestTraceOutput {
            name: self.name.clone(),
            started_at: self.started_at.clone(),
            ended_at: Some(current_timestamp()),
            duration_ms: Some(duration_ms),
            entries: self.entries.clone(),
            summary: self.compute_summary(),
            metadata: self.metadata.clone(),
        }
    }

    /// Saves the trace to a JSON file.
    ///
    /// Creates parent directories if they don't exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn save(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let path = path.as_ref();

        // Create parent directories
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);

        let output = self.build_output();
        serde_json::to_writer_pretty(&mut writer, &output)?;
        writer.flush()?;

        Ok(())
    }

    /// Returns the trace as a JSON string.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(&self.build_output())
    }

    /// Prints a summary to stderr.
    pub fn print_summary(&self) {
        let output = self.build_output();
        let duration_str = output
            .duration_ms
            .map(|d| format!("{d:.2}ms"))
            .unwrap_or_else(|| "N/A".to_string());

        eprintln!("\n=== Test Trace Summary: {} ===", self.name);
        eprintln!("Duration: {duration_str}");
        eprintln!(
            "Requests: {}, Responses: {} ({} success, {} error)",
            output.summary.request_count,
            output.summary.response_count,
            output.summary.success_count,
            output.summary.error_count
        );
        eprintln!("Spans: {}", output.summary.span_count);

        if !output.summary.method_timings.is_empty() {
            eprintln!("\nMethod Timings:");
            for (method, timing) in &output.summary.method_timings {
                let mean = timing.mean_ms.map(|m| format!("{m:.2}")).unwrap_or_default();
                let min = timing.min_ms.map(|m| format!("{m:.2}")).unwrap_or_default();
                let max = timing.max_ms.map(|m| format!("{m:.2}")).unwrap_or_default();
                eprintln!(
                    "  {method}: {count}x (mean: {mean}ms, min: {min}ms, max: {max}ms)",
                    count = timing.count
                );
            }
        }

        eprintln!("===\n");
    }

    /// Returns all entries.
    #[must_use]
    pub fn entries(&self) -> &[TraceEntry] {
        &self.entries
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

/// Returns the current timestamp in ISO 8601 format.
fn current_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = now.as_secs();
    let millis = now.subsec_millis();

    // Simple ISO 8601 format (UTC)
    let (year, month, day, hour, min, sec) = epoch_to_datetime(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

/// Converts epoch seconds to date-time components.
fn epoch_to_datetime(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    // Simple calculation (doesn't account for leap seconds but good enough for logging)
    let days = secs / 86400;
    let time_of_day = secs % 86400;

    let hour = (time_of_day / 3600) as u32;
    let min = ((time_of_day % 3600) / 60) as u32;
    let sec = (time_of_day % 60) as u32;

    // Calculate year, month, day from days since epoch
    let mut year = 1970u32;
    let mut remaining_days = days as i64;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months: [i64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1u32;
    for days_in_month in days_in_months {
        if remaining_days < days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }

    let day = remaining_days as u32 + 1;

    (year, month, day, hour, min, sec)
}

/// Checks if a year is a leap year.
fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_creation() {
        let trace = TestTrace::new("test-trace");
        assert_eq!(trace.name(), "test-trace");
        assert_eq!(trace.entry_count(), 0);
    }

    #[test]
    fn test_trace_builder() {
        let trace = TestTrace::builder("my-trace")
            .with_metadata("env", "test")
            .with_console_output(false)
            .with_min_level(TraceLevel::Info)
            .build();

        assert_eq!(trace.name(), "my-trace");
        assert!(trace.metadata.contains_key("env"));
    }

    #[test]
    fn test_log_request_response() {
        let mut trace = TestTrace::builder("req-resp")
            .with_console_output(false)
            .build();

        let params = serde_json::json!({"name": "test"});
        let correlation_id = trace.log_request("tools/call", Some(&params));

        let result = serde_json::json!({"content": []});
        trace.log_response(&correlation_id, Some(&result), None::<&()>);

        assert_eq!(trace.entry_count(), 2);
    }

    #[test]
    fn test_spans() {
        let mut trace = TestTrace::builder("spans")
            .with_console_output(false)
            .build();

        let span_id = trace.start_span("outer");
        assert_eq!(trace.current_span_id(), Some(span_id.as_str()));

        let inner_span = trace.start_span("inner");
        assert_eq!(trace.current_span_id(), Some(inner_span.as_str()));

        trace.end_span(None);
        assert_eq!(trace.current_span_id(), Some(span_id.as_str()));

        trace.end_span(Some("test error"));

        assert!(trace.current_span_id().is_none());
        assert_eq!(trace.entry_count(), 4); // 2 starts + 2 ends
    }

    #[test]
    fn test_log_levels() {
        let mut trace = TestTrace::builder("levels")
            .with_console_output(false)
            .with_min_level(TraceLevel::Info)
            .build();

        trace.debug("debug message"); // Should be filtered
        trace.info("info message");
        trace.warn("warn message");
        trace.error("error message");

        assert_eq!(trace.entry_count(), 3); // debug filtered out
    }

    #[test]
    fn test_metrics() {
        let mut trace = TestTrace::builder("metrics")
            .with_console_output(false)
            .build();

        trace.metric("response_time", 45.5, Some("ms"));
        trace.metric("memory_usage", 1024.0, Some("KB"));

        assert_eq!(trace.entry_count(), 2);
    }

    #[test]
    fn test_summary_computation() {
        let mut trace = TestTrace::builder("summary")
            .with_console_output(false)
            .build();

        // Simulate some requests/responses
        let id1 = trace.log_request("tools/list", None::<&()>);
        let id2 = trace.log_request("tools/call", None::<&()>);

        trace.log_response(&id1, Some(&serde_json::json!({"tools": []})), None::<&()>);
        trace.log_response(&id2, None::<&()>, Some(&serde_json::json!({"error": "test"})));

        let output = trace.build_output();
        assert_eq!(output.summary.request_count, 2);
        assert_eq!(output.summary.response_count, 2);
        assert_eq!(output.summary.success_count, 1);
        assert_eq!(output.summary.error_count, 1);
    }

    #[test]
    fn test_to_json() {
        let mut trace = TestTrace::builder("json")
            .with_console_output(false)
            .build();

        trace.info("test message");

        let json = trace.to_json().unwrap();
        assert!(json.contains("json"));
        assert!(json.contains("test message"));
    }

    #[test]
    fn test_is_trace_enabled() {
        // By default should be false
        assert!(!is_trace_enabled());
    }

    #[test]
    fn test_timestamp_format() {
        let ts = current_timestamp();
        // Should match ISO 8601 format: YYYY-MM-DDTHH:MM:SS.mmmZ
        assert!(ts.contains("T"));
        assert!(ts.ends_with("Z"));
        assert_eq!(ts.len(), 24);
    }

    #[test]
    fn test_epoch_to_datetime() {
        // 2020-01-01 00:00:00 UTC = 1577836800
        let (year, month, day, hour, min, sec) = epoch_to_datetime(1577836800);
        assert_eq!(year, 2020);
        assert_eq!(month, 1);
        assert_eq!(day, 1);
        assert_eq!(hour, 0);
        assert_eq!(min, 0);
        assert_eq!(sec, 0);
    }
}
