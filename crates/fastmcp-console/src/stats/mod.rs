use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
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
        self.inner
            .total_connections
            .fetch_add(1, Ordering::Relaxed);
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
        self.inner.bytes_received.fetch_add(bytes, Ordering::Relaxed);
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
            avg_latency: if total > 0 {
                Duration::from_micros(total_latency / total)
            } else {
                Duration::ZERO
            },
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
            self.inner
                .list_operations
                .fetch_add(1, Ordering::Relaxed);
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
    use std::thread;

    #[test]
    fn test_record_request_counts() {
        let stats = ServerStats::new();
        stats.record_request("tools/call", Duration::from_millis(10), true);
        stats.record_request("resources/read", Duration::from_millis(20), false);
        stats.record_request("prompts/get", Duration::from_millis(5), true);
        stats.record_request("tools/list", Duration::from_millis(7), true);

        let snap = stats.snapshot();
        assert_eq!(snap.total_requests, 4);
        assert_eq!(snap.successful_requests, 3);
        assert_eq!(snap.failed_requests, 1);
        assert_eq!(snap.cancelled_requests, 0);
        assert_eq!(snap.tool_calls, 2);
        assert_eq!(snap.resource_reads, 1);
        assert_eq!(snap.prompt_gets, 1);
        assert_eq!(snap.list_operations, 1);
        assert_eq!(snap.max_latency, Duration::from_millis(20));
        assert_eq!(snap.min_latency, Duration::from_millis(5));
    }

    #[test]
    fn test_snapshot_latency() {
        let stats = ServerStats::new();
        stats.record_request("tools/call", Duration::from_millis(10), true);
        stats.record_request("tools/call", Duration::from_millis(20), true);

        let snap = stats.snapshot();
        assert_eq!(snap.avg_latency, Duration::from_millis(15));
        assert_eq!(snap.max_latency, Duration::from_millis(20));
        assert_eq!(snap.min_latency, Duration::from_millis(10));
    }

    #[test]
    fn test_concurrent_updates() {
        let stats = ServerStats::new();
        let mut handles = Vec::new();

        for _ in 0..4 {
            let stats = stats.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..1_000 {
                    stats.record_request("tools/call", Duration::from_millis(1), true);
                }
            }));
        }

        for _ in 0..500 {
            stats.record_request("resources/read", Duration::from_millis(2), false);
        }

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        let snap = stats.snapshot();
        assert_eq!(snap.total_requests, 4_500);
        assert_eq!(snap.successful_requests, 4_000);
        assert_eq!(snap.failed_requests, 500);
        assert_eq!(snap.tool_calls, 4_000);
        assert_eq!(snap.resource_reads, 500);
    }
}
