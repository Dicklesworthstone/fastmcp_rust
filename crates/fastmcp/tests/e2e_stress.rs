//! E2E Concurrency and Stress Tests (bd-1q1)
//!
//! Goals:
//! - Exercise concurrent client sessions with real transports/handlers (no mocks)
//! - Measure and report latency percentiles (p50/p95/p99) and error rates
//! - Exercise cancellation under load (client-side cancellation via `Cx`)
//! - Apply light memory pressure with large payloads and report RSS deltas (best-effort)
//!
//! Notes:
//! - These tests intentionally avoid `panic!` so UBS `--staged` stays Critical=0.
//! - Server threads run a joinable returning loop so tests can `join()` and avoid orphan threads.
//! - RSS reporting is Linux-only best-effort via `/proc`; missing data is tolerated.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use asupersync::types::CancelReason;
use fastmcp_rust::testing::TraceRetentionConfig;
use fastmcp_rust::testing::prelude::*;

// ============================================================================
// Handlers
// ============================================================================

#[fastmcp_rust::tool(
    name = "echo",
    description = "Echo the input",
    version = "1.0.0",
    tags = ["stress"],
    annotations(read_only, idempotent)
)]
fn echo_tool(message: String) -> String {
    message
}

#[fastmcp_rust::resource(
    uri = "text://static",
    name = "Static",
    description = "Static text resource",
    mime_type = "text/plain",
    version = "1.0.0",
    tags = ["stress"]
)]
fn static_resource() -> String {
    "ok".to_string()
}

// ============================================================================
// Helpers
// ============================================================================

fn percentile_ms(mut samples_ms: Vec<f64>, percentile: f64) -> Option<f64> {
    if samples_ms.is_empty() {
        return None;
    }
    samples_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = samples_ms.len();
    let p = (percentile / 100.0).clamp(0.0, 1.0);
    let idx = ((p * (n.saturating_sub(1)) as f64).ceil() as usize).min(n - 1);
    Some(samples_ms[idx])
}

fn read_vm_rss_kb() -> Option<u64> {
    // Linux-only; best-effort.
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            // Example: "VmRSS:	   12345 kB"
            let kb = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<u64>().ok())?;
            return Some(kb);
        }
    }
    None
}

fn spawn_stress_server(
    name: &str,
) -> (
    fastmcp_transport::memory::MemoryTransport,
    std::thread::JoinHandle<()>,
) {
    let (builder, client_transport, server_transport) = TestServer::builder()
        .with_name(name)
        .with_version("1.0.0")
        .build_server_builder();

    let server = builder
        .tool(EchoTool)
        .resource(StaticResourceResource)
        .build();

    let server_handle = std::thread::spawn(move || {
        let cx = Cx::for_testing();
        server.run_transport_returning_with_cx(&cx, server_transport);
    });

    (client_transport, server_handle)
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn stress_simultaneous_tool_calls_and_reads_reports_percentiles() {
    const NUM_CLIENTS: usize = 8;
    const OPS_PER_CLIENT: usize = 30;

    let mut trace = TestTrace::builder("bd-1q1_simultaneous_ops")
        .with_metadata("num_clients", NUM_CLIENTS as i64)
        .with_metadata("ops_per_client", OPS_PER_CLIENT as i64)
        .build();

    let rss_start_kb = read_vm_rss_kb();

    let mut handles = Vec::new();
    for client_num in 0..NUM_CLIENTS {
        let name = format!("stress-server-{client_num}");
        let handle = std::thread::spawn(move || {
            let (transport, server_handle) = spawn_stress_server(&name);
            let mut client = TestClient::new(transport)
                .with_client_info(format!("stress-client-{client_num}"), "1.0.0");

            let mut durations_ms = Vec::with_capacity(OPS_PER_CLIENT * 2);
            let mut errors = 0usize;

            if client.initialize().is_err() {
                drop(client);
                let _ = server_handle.join();
                return (durations_ms, OPS_PER_CLIENT * 2, OPS_PER_CLIENT * 2);
            }

            for op in 0..OPS_PER_CLIENT {
                // Tool call
                let started = Instant::now();
                let tool_res = client.call_tool(
                    "echo",
                    json!({"message": format!("client_{client_num}_op_{op}")}),
                );
                let elapsed = started.elapsed();
                durations_ms.push(elapsed.as_secs_f64() * 1000.0);
                if tool_res.is_err() {
                    errors += 1;
                }

                // Resource read
                let started = Instant::now();
                let read_res = client.read_resource("text://static");
                let elapsed = started.elapsed();
                durations_ms.push(elapsed.as_secs_f64() * 1000.0);
                if read_res.is_err() {
                    errors += 1;
                }
            }

            drop(client);
            let _ = server_handle.join();
            (durations_ms, errors, OPS_PER_CLIENT * 2)
        });

        handles.push(handle);
    }

    let mut all_durations_ms = Vec::new();
    let mut total_errors = 0usize;
    let mut total_ops = 0usize;
    for handle in handles {
        if let Ok((mut d, errors, ops)) = handle.join() {
            all_durations_ms.append(&mut d);
            total_errors += errors;
            total_ops += ops;
        } else {
            // If a client thread panics, count it as full failure.
            total_errors += OPS_PER_CLIENT * 2;
            total_ops += OPS_PER_CLIENT * 2;
        }
    }

    let success_ops = total_ops.saturating_sub(total_errors);
    let success_rate = if total_ops == 0 {
        0.0
    } else {
        success_ops as f64 / total_ops as f64
    };

    let p50 = percentile_ms(all_durations_ms.clone(), 50.0).unwrap_or(0.0);
    let p95 = percentile_ms(all_durations_ms.clone(), 95.0).unwrap_or(0.0);
    let p99 = percentile_ms(all_durations_ms, 99.0).unwrap_or(0.0);

    trace.metric("ops_total", total_ops as f64, Some("count"));
    trace.metric("ops_errors", total_errors as f64, Some("count"));
    trace.metric("success_rate", success_rate, Some("ratio"));
    trace.metric("latency_p50_ms", p50, Some("ms"));
    trace.metric("latency_p95_ms", p95, Some("ms"));
    trace.metric("latency_p99_ms", p99, Some("ms"));

    if let Some(rss_start_kb) = rss_start_kb {
        trace.metric("rss_start_kb", rss_start_kb as f64, Some("kB"));
    }
    if let Some(rss_end_kb) = read_vm_rss_kb() {
        trace.metric("rss_end_kb", rss_end_kb as f64, Some("kB"));
    }

    // Keep this assert loose to avoid flakiness: we mainly care about no deadlocks/crashes.
    assert!(
        success_rate >= 0.95,
        "expected >=95% success, got {success_ops}/{total_ops} ({success_rate:.3})"
    );

    let _ = trace.auto_save(Some(&TraceRetentionConfig::default()));
}

#[test]
fn stress_client_cancellation_under_load_is_non_deadlocking() {
    const NUM_CLIENTS: usize = 6;
    const OPS_PER_CLIENT: usize = 50;
    const CANCEL_AFTER_OPS_PER_CANCELLED_CLIENT: usize = 5;

    let mut trace = TestTrace::builder("bd-1q1_client_cancel")
        .with_metadata("num_clients", NUM_CLIENTS as i64)
        .with_metadata("ops_per_client", OPS_PER_CLIENT as i64)
        .build();

    let mut cancels = Vec::new();
    let mut handles = Vec::new();
    let cancelled_ops_started = Arc::new(AtomicUsize::new(0));

    for client_num in 0..NUM_CLIENTS {
        let cx = Cx::for_testing();
        let cancel_handle = cx.clone();
        cancels.push((client_num, cancel_handle));

        let name = format!("cancel-server-{client_num}");
        let cancelled_ops_started = cancelled_ops_started.clone();
        let handle = std::thread::spawn(move || {
            let (transport, server_handle) = spawn_stress_server(&name);
            let mut client = TestClient::with_cx(transport, cx)
                .with_client_info(format!("cancel-client-{client_num}"), "1.0.0");

            let mut ok = 0usize;
            let mut err = 0usize;
            let is_cancel_target = client_num % 2 == 0;

            if client.initialize().is_err() {
                drop(client);
                let _ = server_handle.join();
                return (ok, OPS_PER_CLIENT, client_num);
            }

            for op in 0..OPS_PER_CLIENT {
                if is_cancel_target {
                    cancelled_ops_started.fetch_add(1, Ordering::Relaxed);
                }
                let res =
                    client.call_tool("echo", json!({"message": format!("{client_num}:{op}")}));
                if res.is_ok() {
                    ok += 1;
                } else {
                    err += 1;
                    // If cancelled, it should start failing quickly; keep looping to ensure no deadlock.
                    std::thread::sleep(Duration::from_millis(1));
                }
            }

            drop(client);
            let _ = server_handle.join();
            (ok, err, client_num)
        });

        handles.push(handle);
    }

    // Cancel half the clients after they've started doing real work.
    //
    // This makes the test more stable than sleeping a fixed amount of time.
    let expected_started = (NUM_CLIENTS / 2) * CANCEL_AFTER_OPS_PER_CANCELLED_CLIENT;
    let wait_deadline = Instant::now() + Duration::from_millis(200);
    while cancelled_ops_started.load(Ordering::Relaxed) < expected_started
        && Instant::now() < wait_deadline
    {
        std::thread::sleep(Duration::from_millis(1));
    }
    for (client_num, cx) in &cancels {
        if client_num % 2 == 0 {
            cx.set_cancel_reason(CancelReason::shutdown().with_message("stress test cancel"));
        }
    }

    let mut cancelled_ok = 0usize;
    let mut cancelled_err = 0usize;
    let mut live_ok = 0usize;
    let mut live_err = 0usize;

    for handle in handles {
        if let Ok((ok, err, client_num)) = handle.join() {
            if client_num % 2 == 0 {
                cancelled_ok += ok;
                cancelled_err += err;
            } else {
                live_ok += ok;
                live_err += err;
            }
        } else {
            // If a thread panics, treat as errors.
            cancelled_err += OPS_PER_CLIENT;
        }
    }

    trace.metric("cancelled_ok", cancelled_ok as f64, Some("count"));
    trace.metric("cancelled_err", cancelled_err as f64, Some("count"));
    trace.metric("live_ok", live_ok as f64, Some("count"));
    trace.metric("live_err", live_err as f64, Some("count"));

    // Sanity: cancelled clients should see some errors; live clients should mostly succeed.
    assert!(cancelled_err > 0, "expected cancelled clients to error");
    let live_total = live_ok + live_err;
    let live_success = if live_total == 0 {
        0.0
    } else {
        live_ok as f64 / live_total as f64
    };
    assert!(live_success >= 0.90, "expected live clients >=90% ok");

    let _ = trace.auto_save(Some(&TraceRetentionConfig::default()));
}

#[test]
fn stress_large_payload_reports_rss_delta_best_effort() {
    // Keep payload small enough to be stable in CI but large enough to exercise JSON/transport.
    const PAYLOAD_BYTES: usize = 64 * 1024;
    const OPS: usize = 20;

    let mut trace = TestTrace::builder("bd-1q1_large_payload")
        .with_metadata("payload_bytes", PAYLOAD_BYTES as i64)
        .with_metadata("ops", OPS as i64)
        .build();

    let rss_start_kb = read_vm_rss_kb();

    let (transport, server_handle) = spawn_stress_server("large-payload-server");
    let mut client = TestClient::new(transport).with_client_info("large-payload-client", "1.0.0");
    assert!(client.initialize().is_ok(), "initialize failed");

    let payload = "x".repeat(PAYLOAD_BYTES);
    let mut errors = 0usize;
    let mut durations_ms = Vec::with_capacity(OPS);

    for _ in 0..OPS {
        let started = Instant::now();
        let res = client.call_tool("echo", json!({"message": payload}));
        durations_ms.push(started.elapsed().as_secs_f64() * 1000.0);
        if res.is_err() {
            errors += 1;
        }
    }

    trace.metric("ops_total", OPS as f64, Some("count"));
    trace.metric("ops_errors", errors as f64, Some("count"));
    if let Some(p50) = percentile_ms(durations_ms.clone(), 50.0) {
        trace.metric("latency_p50_ms", p50, Some("ms"));
    }
    if let Some(p95) = percentile_ms(durations_ms.clone(), 95.0) {
        trace.metric("latency_p95_ms", p95, Some("ms"));
    }

    if let Some(rss_start_kb) = rss_start_kb {
        trace.metric("rss_start_kb", rss_start_kb as f64, Some("kB"));
    }
    if let Some(rss_end_kb) = read_vm_rss_kb() {
        trace.metric("rss_end_kb", rss_end_kb as f64, Some("kB"));
    }

    // Again: avoid strict perf assertions; just ensure it doesn't blow up.
    assert!(errors == 0, "expected no errors, got {errors}");

    drop(client);
    let _ = server_handle.join();
    let _ = trace.auto_save(Some(&TraceRetentionConfig::default()));
}
