mod renderer;

pub use fastmcp_core::stats::{ServerStats, StatsSnapshot};
pub use renderer::StatsRenderer;

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

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

    #[test]
    fn test_default_and_zero_snapshot_values() {
        let stats = ServerStats::default();
        let snap = stats.snapshot();

        assert_eq!(snap.total_requests, 0);
        assert_eq!(snap.successful_requests, 0);
        assert_eq!(snap.failed_requests, 0);
        assert_eq!(snap.cancelled_requests, 0);
        assert_eq!(snap.tool_calls, 0);
        assert_eq!(snap.resource_reads, 0);
        assert_eq!(snap.prompt_gets, 0);
        assert_eq!(snap.list_operations, 0);
        assert_eq!(snap.avg_latency, Duration::ZERO);
        assert_eq!(snap.max_latency, Duration::ZERO);
        assert_eq!(snap.min_latency, Duration::ZERO);
        assert_eq!(snap.active_connections, 0);
        assert_eq!(snap.total_connections, 0);
        assert_eq!(snap.bytes_received, 0);
        assert_eq!(snap.bytes_sent, 0);
        assert!(snap.uptime <= Duration::from_secs(1));
    }

    #[test]
    fn test_cancelled_and_method_buckets() {
        let stats = ServerStats::new();
        stats.record_cancelled("resources/list", Duration::from_millis(11));
        stats.record_request("other/method", Duration::from_millis(3), true);

        let snap = stats.snapshot();
        assert_eq!(snap.total_requests, 2);
        assert_eq!(snap.cancelled_requests, 1);
        assert_eq!(snap.successful_requests, 1);
        assert_eq!(snap.failed_requests, 0);
        assert_eq!(snap.resource_reads, 1);
        assert_eq!(snap.tool_calls, 0);
        assert_eq!(snap.prompt_gets, 0);
        assert_eq!(snap.list_operations, 1);
        assert_eq!(snap.max_latency, Duration::from_millis(11));
        assert_eq!(snap.min_latency, Duration::from_millis(3));
    }

    #[test]
    fn test_connection_and_byte_counters() {
        let stats = ServerStats::new();

        stats.connection_opened();
        stats.connection_opened();
        stats.connection_closed();
        stats.connection_closed();
        // Should stay at zero when already zero.
        stats.connection_closed();

        stats.add_bytes_received(128);
        stats.add_bytes_received(72);
        stats.add_bytes_sent(64);

        let snap = stats.snapshot();
        assert_eq!(snap.active_connections, 0);
        assert_eq!(snap.total_connections, 2);
        assert_eq!(snap.bytes_received, 200);
        assert_eq!(snap.bytes_sent, 64);
    }

    // =========================================================================
    // Additional coverage tests (bd-33a2)
    // =========================================================================

    #[test]
    fn server_stats_debug_output() {
        let stats = ServerStats::new();
        let debug = format!("{stats:?}");
        assert!(debug.contains("ServerStats"));
    }

    #[test]
    fn server_stats_clone_shares_underlying_data() {
        let stats = ServerStats::new();
        let clone = stats.clone();

        clone.record_request("tools/call", Duration::from_millis(5), true);

        // Original should see the update because they share the same Arc
        let snap = stats.snapshot();
        assert_eq!(snap.total_requests, 1);
        assert_eq!(snap.tool_calls, 1);
    }

    #[test]
    fn stats_snapshot_debug_and_clone() {
        let stats = ServerStats::new();
        stats.record_request("tools/call", Duration::from_millis(7), true);
        let snap = stats.snapshot();

        let debug = format!("{snap:?}");
        assert!(debug.contains("StatsSnapshot"));
        assert!(debug.contains("total_requests: 1"));

        let cloned = snap.clone();
        assert_eq!(cloned.total_requests, snap.total_requests);
        assert_eq!(cloned.tool_calls, snap.tool_calls);
        assert_eq!(cloned.max_latency, snap.max_latency);
    }

    #[test]
    fn list_operations_detected_by_contains() {
        let stats = ServerStats::new();

        // "notifications/list" contains "list" but is not tools/resources/prompts
        stats.record_request("notifications/list", Duration::from_millis(1), true);

        let snap = stats.snapshot();
        assert_eq!(snap.list_operations, 1);
        assert_eq!(snap.tool_calls, 0);
        assert_eq!(snap.resource_reads, 0);
        assert_eq!(snap.prompt_gets, 0);
    }

    #[test]
    fn connection_closed_concurrent_cas_loop() {
        let stats = ServerStats::new();
        stats.connection_opened();
        stats.connection_opened();
        stats.connection_opened();

        // Close from multiple threads to exercise the CAS retry loop
        let mut handles = Vec::new();
        for _ in 0..3 {
            let s = stats.clone();
            handles.push(thread::spawn(move || {
                s.connection_closed();
            }));
        }
        for h in handles {
            h.join().expect("thread panicked");
        }

        let snap = stats.snapshot();
        assert_eq!(snap.active_connections, 0);
        assert_eq!(snap.total_connections, 3);
    }
}
