//! Renderer-independent server statistics for headless and interactive hosts.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Thread-safe server statistics collector.
#[derive(Debug, Clone)]
pub struct ServerStats {
    inner: Arc<ServerStatsInner>,
}

#[derive(Debug)]
struct ServerStatsInner {
    start_time: Instant,
    total_requests: AtomicU64,
    successful_requests: AtomicU64,
    failed_requests: AtomicU64,
    cancelled_requests: AtomicU64,
    tool_calls: AtomicU64,
    resource_reads: AtomicU64,
    prompt_gets: AtomicU64,
    list_operations: AtomicU64,
    total_latency_micros: AtomicU64,
    max_latency_micros: AtomicU64,
    min_latency_micros: AtomicU64,
    active_connections: AtomicUsize,
    total_connections: AtomicU64,
    bytes_received: AtomicU64,
    bytes_sent: AtomicU64,
}

impl Default for ServerStats {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerStats {
    /// Create a new metrics collector with zeroed counters.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ServerStatsInner {
                start_time: Instant::now(),
                total_requests: AtomicU64::new(0),
                successful_requests: AtomicU64::new(0),
                failed_requests: AtomicU64::new(0),
                cancelled_requests: AtomicU64::new(0),
                tool_calls: AtomicU64::new(0),
                resource_reads: AtomicU64::new(0),
                prompt_gets: AtomicU64::new(0),
                list_operations: AtomicU64::new(0),
                total_latency_micros: AtomicU64::new(0),
                max_latency_micros: AtomicU64::new(0),
                min_latency_micros: AtomicU64::new(u64::MAX),
                active_connections: AtomicUsize::new(0),
                total_connections: AtomicU64::new(0),
                bytes_received: AtomicU64::new(0),
                bytes_sent: AtomicU64::new(0),
            }),
        }
    }

    /// Record a completed request.
    pub fn record_request(&self, method: &str, latency: Duration, success: bool) {
        self.record_request_base(method, latency);
        if success {
            self.inner
                .successful_requests
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.inner.failed_requests.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a cancelled request.
    pub fn record_cancelled(&self, method: &str, latency: Duration) {
        self.record_request_base(method, latency);
        self.inner
            .cancelled_requests
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a new client connection.
    pub fn connection_opened(&self) {
        self.inner
            .active_connections
            .fetch_add(1, Ordering::Relaxed);
        self.inner.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a closed client connection.
    pub fn connection_closed(&self) {
        let mut current = self.inner.active_connections.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                return;
            }
            match self.inner.active_connections.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(next) => current = next,
            }
        }
    }

    /// Add to the received byte counter.
    pub fn add_bytes_received(&self, bytes: u64) {
        self.inner
            .bytes_received
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add to the sent byte counter.
    pub fn add_bytes_sent(&self, bytes: u64) {
        self.inner.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get a point-in-time snapshot of all counters.
    #[must_use]
    pub fn snapshot(&self) -> StatsSnapshot {
        let total = self.inner.total_requests.load(Ordering::Relaxed);
        let total_latency = self.inner.total_latency_micros.load(Ordering::Relaxed);
        let min_latency = self.inner.min_latency_micros.load(Ordering::Relaxed);
        let max_latency = self.inner.max_latency_micros.load(Ordering::Relaxed);

        StatsSnapshot {
            uptime: self.inner.start_time.elapsed(),
            total_requests: total,
            successful_requests: self.inner.successful_requests.load(Ordering::Relaxed),
            failed_requests: self.inner.failed_requests.load(Ordering::Relaxed),
            cancelled_requests: self.inner.cancelled_requests.load(Ordering::Relaxed),
            tool_calls: self.inner.tool_calls.load(Ordering::Relaxed),
            resource_reads: self.inner.resource_reads.load(Ordering::Relaxed),
            prompt_gets: self.inner.prompt_gets.load(Ordering::Relaxed),
            list_operations: self.inner.list_operations.load(Ordering::Relaxed),
            avg_latency: total_latency
                .checked_div(total)
                .map(Duration::from_micros)
                .unwrap_or(Duration::ZERO),
            max_latency: Duration::from_micros(max_latency),
            min_latency: if min_latency == u64::MAX {
                Duration::ZERO
            } else {
                Duration::from_micros(min_latency)
            },
            active_connections: self.inner.active_connections.load(Ordering::Relaxed),
            total_connections: self.inner.total_connections.load(Ordering::Relaxed),
            bytes_received: self.inner.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.inner.bytes_sent.load(Ordering::Relaxed),
        }
    }

    fn record_request_base(&self, method: &str, latency: Duration) {
        self.inner.total_requests.fetch_add(1, Ordering::Relaxed);

        if method.starts_with("tools/") {
            self.inner.tool_calls.fetch_add(1, Ordering::Relaxed);
        } else if method.starts_with("resources/") {
            self.inner.resource_reads.fetch_add(1, Ordering::Relaxed);
        } else if method.starts_with("prompts/") {
            self.inner.prompt_gets.fetch_add(1, Ordering::Relaxed);
        }

        if method.contains("list") {
            self.inner.list_operations.fetch_add(1, Ordering::Relaxed);
        }

        let micros = u64::try_from(latency.as_micros()).unwrap_or(u64::MAX);
        self.inner
            .total_latency_micros
            .fetch_add(micros, Ordering::Relaxed);
        self.inner
            .max_latency_micros
            .fetch_max(micros, Ordering::Relaxed);
        self.inner
            .min_latency_micros
            .fetch_min(micros, Ordering::Relaxed);
    }
}

/// Point-in-time snapshot of server statistics.
#[derive(Debug, Clone)]
pub struct StatsSnapshot {
    pub uptime: Duration,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub cancelled_requests: u64,
    pub tool_calls: u64,
    pub resource_reads: u64,
    pub prompt_gets: u64,
    pub list_operations: u64,
    pub avg_latency: Duration,
    pub max_latency: Duration,
    pub min_latency: Duration,
    pub active_connections: usize,
    pub total_connections: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_statistics_keep_success_failure_and_cancellation_distinct() {
        let stats = ServerStats::new();
        let second_owner = stats.clone();
        stats.record_request("tools/call", Duration::from_millis(12), true);
        second_owner.record_request("tools/call", Duration::from_millis(6), false);
        second_owner.record_cancelled("resources/read", Duration::from_millis(3));

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.total_requests, 3);
        assert_eq!(snapshot.successful_requests, 1);
        assert_eq!(snapshot.failed_requests, 1);
        assert_eq!(snapshot.cancelled_requests, 1);
        assert_eq!(snapshot.tool_calls, 2);
        assert_eq!(snapshot.resource_reads, 1);
        assert_eq!(snapshot.avg_latency, Duration::from_millis(7));
        assert_eq!(snapshot.min_latency, Duration::from_millis(3));
        assert_eq!(snapshot.max_latency, Duration::from_millis(12));
        assert_eq!(second_owner.snapshot().total_requests, 3);
    }

    #[test]
    fn independent_collectors_do_not_share_counters_or_underflow_connections() {
        let active = ServerStats::new();
        let separate = ServerStats::new();
        active.connection_opened();
        active.add_bytes_received(128);
        active.add_bytes_sent(64);
        active.connection_closed();
        active.connection_closed();

        let snapshot = active.snapshot();
        assert_eq!(snapshot.total_connections, 1);
        assert_eq!(snapshot.active_connections, 0);
        assert_eq!(snapshot.bytes_received, 128);
        assert_eq!(snapshot.bytes_sent, 64);
        let untouched = separate.snapshot();
        assert_eq!(untouched.total_connections, 0);
        assert_eq!(untouched.bytes_received, 0);
        assert_eq!(untouched.bytes_sent, 0);
        assert_eq!(untouched.avg_latency, Duration::ZERO);
        assert_eq!(untouched.min_latency, Duration::ZERO);
        assert_eq!(untouched.max_latency, Duration::ZERO);
    }
}
