//! Bounded Prometheus text exposition for the existing operational contributors.
//!
//! Encoding consumes one immutable snapshot after its contributor lock has been
//! released. It performs no I/O, captures no additional state, and never invokes
//! a provider or exporter callback. The caller owns any delivery to a separately
//! configured diagnostics endpoint or local sink; protocol stdout is never used.
//!
//! The only label is the closed `profile` vocabulary (`modern`, `legacy_2024`,
//! `auto`). Contributor, lifecycle, readiness and reason names are fixed metric
//! names. Configuration generations and schema versions are gauge values, never
//! labels. Each contributor has the same series inventory at every capture,
//! including zero-valued state/reason series. No wall-clock timestamp is invented
//! from the snapshot's process-local monotonic instant.
//!
//! The wire format is Prometheus text 0.0.4, documented at
//! <https://prometheus.io/docs/instrumenting/exposition_formats/>. This is not an
//! OpenMetrics endpoint. The exporter does not invent request, authorization,
//! task, cache, or transport counters absent from the selected contributor.

use std::fmt::{self, Write};

use super::{
    OperatorExecutorCapacity, OperatorHttpConnections, OperatorLifecycle, OperatorProfile,
    OperatorReadiness, OperatorReason, OperatorSnapshot, OperatorStdioOutput, OperatorTaskStore,
};

/// Hard encoded-byte ceiling for one operational Prometheus exposition.
///
/// Rendering requests one allocation no larger than this value. A caller may
/// choose a smaller ceiling; oversized expositions return an error without
/// returning a partial payload. This bounds requested string capacity and
/// encoded bytes, not allocator bookkeeping.
pub const MAX_OPERATOR_PROMETHEUS_BYTES: usize = 16 * 1024;

/// Content type for operational Prometheus text responses.
pub const OPERATOR_PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Version of the fixed metric names, types, units, and label vocabulary.
/// This is independent of the source snapshot's schema version.
pub const OPERATOR_PROMETHEUS_SCHEMA_VERSION: u32 = 1;

/// A bounded operational exposition could not be produced.
/// Diagnostics contain no snapshot, peer, provider, or allocator text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorMetricsError {
    /// The requested ceiling is zero or exceeds the hard encoded-byte bound.
    InvalidByteLimit,
    /// The complete exposition does not fit the caller's encoded-byte ceiling.
    ByteLimitExceeded,
    /// The one bounded output allocation was unavailable.
    AllocationFailed,
}

impl fmt::Display for OperatorMetricsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidByteLimit => "operator metrics byte limit is invalid",
            Self::ByteLimitExceeded => "operator metrics exceed the encoded byte limit",
            Self::AllocationFailed => "operator metrics output allocation failed",
        })
    }
}

impl std::error::Error for OperatorMetricsError {}

struct MetricsWriter {
    output: String,
    limit: usize,
    prefix: &'static str,
    profile: &'static str,
}

fn profile_label(profile: OperatorProfile) -> &'static str {
    match profile {
        OperatorProfile::Modern => "modern",
        OperatorProfile::Legacy2024 => "legacy_2024",
        OperatorProfile::Auto => "auto",
    }
}

impl MetricsWriter {
    fn new(
        limit: usize,
        prefix: &'static str,
        profile: OperatorProfile,
    ) -> Result<Self, OperatorMetricsError> {
        if limit == 0 || limit > MAX_OPERATOR_PROMETHEUS_BYTES {
            return Err(OperatorMetricsError::InvalidByteLimit);
        }
        let mut output = String::new();
        output
            .try_reserve_exact(limit)
            .map_err(|_| OperatorMetricsError::AllocationFailed)?;
        Ok(Self {
            output,
            limit,
            prefix,
            profile: profile_label(profile),
        })
    }

    fn metric(
        &mut self,
        name: &'static str,
        kind: &'static str,
        help: &'static str,
        value: impl fmt::Display,
    ) -> fmt::Result {
        let prefix = self.prefix;
        let profile = self.profile;
        // Every identifier, help string and label is a local static constant.
        // Only fixed-width integer values enter the formatter dynamically.
        writeln!(self, "# HELP {prefix}_{name} {help}")?;
        writeln!(self, "# TYPE {prefix}_{name} {kind}")?;
        writeln!(self, "{prefix}_{name}{{profile=\"{profile}\"}} {value}")
    }

    fn gauge(
        &mut self,
        name: &'static str,
        help: &'static str,
        value: impl fmt::Display,
    ) -> fmt::Result {
        self.metric(name, "gauge", help, value)
    }

    fn counter(&mut self, name: &'static str, help: &'static str, value: u64) -> fmt::Result {
        self.metric(name, "counter", help, value)
    }

    fn flag(&mut self, name: &'static str, help: &'static str, value: bool) -> fmt::Result {
        self.gauge(name, help, u8::from(value))
    }
}

impl Write for MetricsWriter {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self
            .output
            .len()
            .checked_add(value.len())
            .is_none_or(|length| length > self.limit)
        {
            return Err(fmt::Error);
        }
        // The complete limit was reserved at construction. No subsequent
        // write can request another allocation or retain more than the bound.
        self.output.push_str(value);
        Ok(())
    }
}

fn common<Contributor>(
    snapshot: &OperatorSnapshot<Contributor>,
    writer: &mut MetricsWriter,
    reasons: &[(OperatorReason, &'static str)],
) -> fmt::Result {
    writer.gauge(
        "metrics_schema_version",
        "Version of the fixed operational metric vocabulary.",
        OPERATOR_PROMETHEUS_SCHEMA_VERSION,
    )?;
    writer.gauge(
        "snapshot_schema_version",
        "Version of the source operational snapshot schema.",
        snapshot.schema_version(),
    )?;
    writer.gauge(
        "configuration_generation",
        "Process-local contributor generation; not an endpoint identity.",
        snapshot.configuration_generation(),
    )?;
    for (state, name) in [
        (OperatorLifecycle::Starting, "lifecycle_starting"),
        (OperatorLifecycle::Running, "lifecycle_running"),
        (OperatorLifecycle::Stopping, "lifecycle_stopping"),
        (OperatorLifecycle::Stopped, "lifecycle_stopped"),
    ] {
        writer.flag(
            name,
            "Whether this contributor is in this lifecycle state.",
            snapshot.lifecycle() == state,
        )?;
    }
    for (state, name) in [
        (OperatorReadiness::Starting, "readiness_starting"),
        (OperatorReadiness::Ready, "readiness_ready"),
        (OperatorReadiness::NotReady, "readiness_not_ready"),
        (OperatorReadiness::Stopping, "readiness_stopping"),
    ] {
        writer.flag(
            name,
            "Structural readiness; this does not reserve capacity.",
            snapshot.readiness() == state,
        )?;
    }
    for (reason, name) in reasons {
        writer.flag(
            name,
            "Whether this bounded operational reason is present.",
            snapshot.reasons.contains(&Some(*reason)),
        )?;
    }
    Ok(())
}

impl OperatorSnapshot<OperatorHttpConnections> {
    /// Encodes this HTTP admission snapshot as bounded Prometheus text 0.0.4.
    ///
    /// All metric names start with `fastmcp_operator_http_`; only the closed
    /// `profile` label is accepted. Counters describe this listener generation,
    /// and can reset when the generation changes. Saturation is separate from
    /// structural readiness. No listener callback or admission probe is invoked.
    pub fn prometheus_text(&self) -> Result<String, OperatorMetricsError> {
        self.prometheus_text_with_limit(MAX_OPERATOR_PROMETHEUS_BYTES)
    }

    /// Encodes the complete snapshot within an explicit, nonzero byte ceiling.
    /// The ceiling cannot exceed [`MAX_OPERATOR_PROMETHEUS_BYTES`].
    pub fn prometheus_text_with_limit(
        &self,
        max_bytes: usize,
    ) -> Result<String, OperatorMetricsError> {
        let mut writer = MetricsWriter::new(max_bytes, "fastmcp_operator_http", self.profile())?;
        self.write_prometheus(&mut writer)
            .map_err(|_| OperatorMetricsError::ByteLimitExceeded)?;
        Ok(writer.output)
    }

    /// Encodes a listener and its independently captured Task store in a single
    /// bounded scrape. Each contributor retains its own generation and profile.
    pub fn prometheus_text_with_tasks(
        &self,
        tasks: &OperatorSnapshot<OperatorTaskStore>,
    ) -> Result<String, OperatorMetricsError> {
        let mut writer = MetricsWriter::new(MAX_OPERATOR_PROMETHEUS_BYTES, "fastmcp_operator_http", self.profile())?;
        self.write_prometheus(&mut writer)
            .map_err(|_| OperatorMetricsError::ByteLimitExceeded)?;
        writer.prefix = "fastmcp_operator_tasks";
        writer.profile = profile_label(tasks.profile());
        tasks.write_prometheus(&mut writer)
            .map_err(|_| OperatorMetricsError::ByteLimitExceeded)?;
        Ok(writer.output)
    }

    fn write_prometheus(&self, writer: &mut MetricsWriter) -> fmt::Result {
        common(
            self,
            writer,
            &[
                (OperatorReason::StartupPending, "reason_startup_pending"),
                (
                    OperatorReason::ConnectionCapacityDisabled,
                    "reason_connection_capacity_disabled",
                ),
                (
                    OperatorReason::ConnectionCapacitySaturated,
                    "reason_connection_capacity_saturated",
                ),
                (OperatorReason::ListenerStopping, "reason_listener_stopping"),
                (OperatorReason::ListenerStopped, "reason_listener_stopped"),
            ],
        )?;
        let connections = self.connections();
        let counters = self.counters();
        writer.gauge(
            "connections_limit",
            "Configured connection slot limit.",
            connections.limit,
        )?;
        writer.gauge(
            "connections_active",
            "Slots retained by accepted connection work.",
            connections.active,
        )?;
        writer.gauge(
            "connections_reserved",
            "Slots retained by admission probes and handoffs.",
            connections.reserved,
        )?;
        writer.gauge(
            "connections_in_use",
            "Active and reserved connection slot charges.",
            connections.in_use(),
        )?;
        writer.flag(
            "connections_saturated",
            "Whether the connection slot capacity is fully charged.",
            connections.is_saturated(),
        )?;
        writer.counter(
            "connections_accepted_total",
            "Native connections admitted by this generation.",
            counters.accepted,
        )?;
        writer.counter(
            "connections_rejected_total",
            "Native connections refused by this generation.",
            counters.rejected,
        )?;
        writer.counter(
            "probes_acquired_total",
            "Connection admission probes successfully acquired.",
            counters.probes_acquired,
        )?;
        writer.counter(
            "connection_slots_released_total",
            "Connection and reservation slot charges released.",
            counters.released,
        )?;
        writer.counter(
            "probes_expired_total",
            "Unconsumed admission probes released on expiry.",
            counters.expired,
        )?;
        writer.counter(
            "probes_cancelled_total",
            "Unconsumed admission probes released on cancellation.",
            counters.cancelled,
        )?;
        writer.counter(
            "probes_shutdown_revoked_total",
            "Unconsumed admission probes revoked by shutdown.",
            counters.shutdown_revoked,
        )?;
        writer.flag(
            "counters_overflowed",
            "Whether any source counter increment overflowed.",
            counters.overflowed,
        )?;
        writer.flag(
            "arithmetic_overflowed",
            "Whether source counters or aggregate gauges overflowed.",
            counters.overflowed
                || connections
                    .active
                    .checked_add(connections.reserved)
                    .is_none(),
        )
    }
}

impl OperatorSnapshot<OperatorTaskStore> {
    /// Encodes the Task store's state counts and resource charges as fixed
    /// series, including zero counts. Owner partitions are aggregate gauges.
    pub fn prometheus_text(&self) -> Result<String, OperatorMetricsError> {
        self.prometheus_text_with_limit(MAX_OPERATOR_PROMETHEUS_BYTES)
    }

    /// Renders the complete Task contributor within the given byte limit.
    pub fn prometheus_text_with_limit(
        &self,
        max_bytes: usize,
    ) -> Result<String, OperatorMetricsError> {
        let mut writer = MetricsWriter::new(max_bytes, "fastmcp_operator_tasks", self.profile())?;
        self.write_prometheus(&mut writer).map_err(|_| OperatorMetricsError::ByteLimitExceeded)?;
        Ok(writer.output)
    }

    fn write_prometheus(&self, writer: &mut MetricsWriter) -> fmt::Result {
        common(self, writer, &[
            (OperatorReason::TaskStorageCapacitySaturated, "reason_storage_saturated"),
            (OperatorReason::TaskExecutionCapacitySaturated, "reason_execution_saturated"),
            (OperatorReason::TaskRetentionCapacitySaturated, "reason_retention_saturated"),
        ])?;
        let task = self.contributor();
        let storage = task.storage;
        let execution = task.execution;
        let retention = task.retention;
        for (name, help, value) in [
            ("working", "Retained working Tasks, including queued work.", task.states.working),
            ("input_required", "Tasks awaiting peer input.", task.states.input_required),
            ("completed", "Retained completed results.", task.states.completed),
            ("failed", "Retained failed results.", task.states.failed),
            ("cancelled", "Retained cancelled Tasks.", task.states.cancelled),
            ("storage_task_limit", "Store record limit.", storage.task_limit),
            ("storage_retained_tasks", "Records charged to storage.", storage.retained_tasks),
            ("storage_byte_limit", "Store payload and reservation byte limit.", storage.byte_limit),
            ("storage_retained_bytes", "Charged payload bytes.", storage.retained_bytes),
            ("storage_reserved_terminal_bytes", "Headroom reserved for mandatory retirement.", storage.reserved_terminal_bytes),
            ("storage_charged_bytes", "Retained and reserved bytes.", storage.charged_bytes()),
            ("storage_owner_task_limit", "Record limit per owner partition.", storage.owner_task_limit),
            ("storage_owner_byte_limit", "Byte limit per owner partition.", storage.owner_byte_limit),
            ("storage_owner_partitions", "Owner partitions retaining records.", storage.owner_partitions),
            ("storage_saturated_owner_partitions", "Partitions at a storage limit.", storage.saturated_owner_partitions),
            ("execution_limit", "Store execution slot limit.", execution.limit),
            ("execution_reserved", "Execution slots held by claims or live work.", execution.reserved),
            ("execution_owner_limit", "Execution slot limit per partition.", execution.owner_limit),
            ("execution_owner_partitions", "Partitions holding execution slots.", execution.owner_partitions),
            ("execution_saturated_owner_partitions", "Partitions at their execution limit.", execution.saturated_owner_partitions),
            ("retention_record_limit", "Reclamation receipt count limit.", retention.record_limit),
            ("retention_retained_records", "Retained reclamation receipts.", retention.retained_records),
            ("retention_byte_limit", "Reclamation receipt byte limit.", retention.byte_limit),
            ("retention_retained_bytes", "Charged reclamation receipt bytes.", retention.retained_bytes),
        ] {
            writer.gauge(name, help, value)?;
        }
        writer.flag("arithmetic_overflowed", "Whether the charged byte sum overflowed.", storage.overflowed())
    }
}

impl OperatorSnapshot<OperatorExecutorCapacity> {
    /// Encodes this client executor snapshot as bounded Prometheus text 0.0.4.
    ///
    /// All names start with `fastmcp_operator_executor_`. Pending requests,
    /// deferred controls, tombstones and retained terminal charges are distinct
    /// gauges. The contributor has no request completion counters; this exporter
    /// does not infer them from changing gauges or retained correlations.
    pub fn prometheus_text(&self) -> Result<String, OperatorMetricsError> {
        self.prometheus_text_with_limit(MAX_OPERATOR_PROMETHEUS_BYTES)
    }

    /// Encodes the complete snapshot within an explicit, nonzero byte ceiling.
    /// The ceiling cannot exceed [`MAX_OPERATOR_PROMETHEUS_BYTES`].
    pub fn prometheus_text_with_limit(
        &self,
        max_bytes: usize,
    ) -> Result<String, OperatorMetricsError> {
        let mut writer =
            MetricsWriter::new(max_bytes, "fastmcp_operator_executor", self.profile())?;
        self.write_prometheus(&mut writer)
            .map_err(|_| OperatorMetricsError::ByteLimitExceeded)?;
        Ok(writer.output)
    }

    fn write_prometheus(&self, writer: &mut MetricsWriter) -> fmt::Result {
        common(
            self,
            writer,
            &[
                (
                    OperatorReason::RequestCapacityDisabled,
                    "reason_request_capacity_disabled",
                ),
                (
                    OperatorReason::RequestCapacitySaturated,
                    "reason_request_capacity_saturated",
                ),
                (
                    OperatorReason::CorrelationCapacityDisabled,
                    "reason_correlation_capacity_disabled",
                ),
                (
                    OperatorReason::CorrelationCapacitySaturated,
                    "reason_correlation_capacity_saturated",
                ),
                (
                    OperatorReason::ExecutorGenerationExhausted,
                    "reason_executor_generation_exhausted",
                ),
                (OperatorReason::ExecutorFailed, "reason_executor_failed"),
                (OperatorReason::ExecutorStopped, "reason_executor_stopped"),
            ],
        )?;
        let requests = self.requests();
        let correlations = self.correlations();
        writer.gauge(
            "requests_limit",
            "Configured request slot limit.",
            requests.limit,
        )?;
        writer.gauge(
            "requests_pending",
            "Requests awaiting an elected terminal outcome.",
            requests.pending,
        )?;
        writer.gauge(
            "requests_deferred_controls",
            "Controls awaiting a transport commit after owner release.",
            requests.deferred_controls,
        )?;
        writer.gauge(
            "requests_in_use",
            "Pending request and deferred control charges.",
            requests.in_use(),
        )?;
        writer.flag(
            "requests_saturated",
            "Whether the request slot capacity is fully charged.",
            requests.is_saturated(),
        )?;
        writer.gauge(
            "correlations_limit",
            "Configured response correlation slot limit.",
            correlations.limit,
        )?;
        writer.gauge(
            "correlations_pending",
            "Correlations retained by pending requests.",
            correlations.pending,
        )?;
        writer.gauge(
            "correlations_tombstones",
            "Retired correlations retained against late peer frames.",
            correlations.tombstones,
        )?;
        writer.gauge(
            "correlations_retained_terminals",
            "Unconsumed outcomes or terminal receipt charges.",
            correlations.retained_terminals,
        )?;
        writer.gauge(
            "correlations_in_use",
            "Pending, tombstone and terminal correlation charges.",
            correlations.in_use(),
        )?;
        writer.flag(
            "correlations_saturated",
            "Whether the correlation slot capacity is fully charged.",
            correlations.is_saturated(),
        )?;
        writer.flag(
            "arithmetic_overflowed",
            "Whether aggregate request or correlation gauges overflowed.",
            requests.overflowed() || correlations.overflowed(),
        )
    }
}

impl OperatorSnapshot<OperatorStdioOutput> {
    /// Encodes this stdio writer snapshot as bounded Prometheus text 0.0.4.
    ///
    /// All names start with `fastmcp_operator_stdio_`. Byte gauges include
    /// retained newline framing, not kernel buffers. Released frames do not
    /// establish peer delivery. Returning text never writes to protocol stdout.
    pub fn prometheus_text(&self) -> Result<String, OperatorMetricsError> {
        self.prometheus_text_with_limit(MAX_OPERATOR_PROMETHEUS_BYTES)
    }

    /// Encodes the complete snapshot within an explicit, nonzero byte ceiling.
    /// The ceiling cannot exceed [`MAX_OPERATOR_PROMETHEUS_BYTES`].
    pub fn prometheus_text_with_limit(
        &self,
        max_bytes: usize,
    ) -> Result<String, OperatorMetricsError> {
        let mut writer = MetricsWriter::new(max_bytes, "fastmcp_operator_stdio", self.profile())?;
        self.write_prometheus(&mut writer)
            .map_err(|_| OperatorMetricsError::ByteLimitExceeded)?;
        Ok(writer.output)
    }

    fn write_prometheus(&self, writer: &mut MetricsWriter) -> fmt::Result {
        common(
            self,
            writer,
            &[
                (OperatorReason::StartupPending, "reason_startup_pending"),
                (
                    OperatorReason::OutputCapacityDisabled,
                    "reason_output_capacity_disabled",
                ),
                (
                    OperatorReason::OutputFrameCapacitySaturated,
                    "reason_output_frame_capacity_saturated",
                ),
                (
                    OperatorReason::OutputByteCapacitySaturated,
                    "reason_output_byte_capacity_saturated",
                ),
                (OperatorReason::OutputStopping, "reason_output_stopping"),
                (OperatorReason::OutputStopped, "reason_output_stopped"),
                (OperatorReason::OutputFailed, "reason_output_failed"),
            ],
        )?;
        let output = self.contributor();
        writer.gauge(
            "output_frame_limit",
            "Configured retained output frame limit.",
            output.capacity.frame_limit,
        )?;
        writer.gauge(
            "output_byte_limit",
            "Configured retained encoded output byte limit.",
            output.capacity.byte_limit,
        )?;
        writer.gauge(
            "output_retained_frames",
            "Retained queued and currently written frames.",
            output.capacity.retained_frames,
        )?;
        writer.gauge(
            "output_retained_bytes",
            "Retained encoded bytes including newline framing.",
            output.capacity.retained_bytes,
        )?;
        writer.flag(
            "output_frames_saturated",
            "Whether all output frame slots are charged.",
            output.capacity.frames_saturated(),
        )?;
        writer.flag(
            "output_bytes_saturated",
            "Whether the output byte budget is fully charged.",
            output.capacity.bytes_saturated(),
        )?;
        writer.flag(
            "output_failed",
            "Whether serving or writing encountered terminal failure.",
            output.failed,
        )?;
        writer.counter(
            "output_frames_enqueued_total",
            "Output frames admitted by this generation.",
            output.counters.enqueued,
        )?;
        writer.counter(
            "output_frames_rejected_capacity_total",
            "Output frames refused by encoded byte or frame limits.",
            output.counters.rejected_capacity,
        )?;
        writer.counter(
            "output_frames_released_total",
            "Output frame charges released without delivery acknowledgement.",
            output.counters.released,
        )?;
        writer.counter(
            "output_writer_failures_total",
            "Failed frame writes and writer closes.",
            output.counters.writer_failures,
        )?;
        writer.flag(
            "arithmetic_overflowed",
            "Whether any source counter increment overflowed.",
            output.counters.overflowed,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use super::*;
    use crate::stats::{
        OperatorConnectionCapacity, OperatorConnectionCounters, OperatorCorrelationCapacity,
        OperatorExecutorState, OperatorOutputCapacity, OperatorOutputCounters,
        OperatorRequestCapacity, OperatorSnapshotError, OperatorSnapshotSource,
    };

    fn http_snapshot(lifecycle: OperatorLifecycle) -> OperatorSnapshot {
        OperatorSnapshot::http_connections(
            Instant::now(),
            37,
            OperatorProfile::Modern,
            lifecycle,
            OperatorConnectionCapacity {
                limit: 3,
                active: 2,
                reserved: 1,
            },
            OperatorConnectionCounters {
                accepted: 11,
                rejected: 7,
                probes_acquired: 5,
                released: 13,
                expired: 2,
                cancelled: 1,
                shutdown_revoked: 3,
                overflowed: false,
            },
        )
    }

    // Parse the public text format independently of the encoder: every metric
    // must declare one HELP and one TYPE before its single, uniquely labeled
    // sample. The admitted names, labels and unsigned values need no escaping.
    fn samples(text: &str) -> BTreeMap<String, u128> {
        assert!(text.is_ascii());
        assert!(text.ends_with('\n'));
        assert!(text.len() <= MAX_OPERATOR_PROMETHEUS_BYTES);
        let mut help = BTreeSet::new();
        let mut types = BTreeMap::new();
        let mut samples = BTreeMap::new();
        for line in text.lines() {
            if let Some(line) = line.strip_prefix("# HELP ") {
                let (name, description) = line.split_once(' ').expect("HELP has a docstring");
                assert!(!description.is_empty());
                assert!(help.insert(name));
            } else if let Some(line) = line.strip_prefix("# TYPE ") {
                let (name, kind) = line.split_once(' ').expect("TYPE has a kind");
                assert!(help.contains(name));
                assert!(matches!(kind, "counter" | "gauge"));
                assert_eq!(name.ends_with("_total"), kind == "counter");
                assert!(types.insert(name, kind).is_none());
            } else {
                let (identity, value) = line.split_once(' ').expect("sample has a value");
                let (name, labels) = identity.split_once('{').expect("sample has profile label");
                assert!(types.contains_key(name), "TYPE must precede the sample");
                assert!(
                    name.bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
                );
                assert!(matches!(
                    labels,
                    "profile=\"modern\"}" | "profile=\"legacy_2024\"}" | "profile=\"auto\"}"
                ));
                assert!(
                    samples
                        .insert(identity.to_owned(), value.parse().unwrap())
                        .is_none()
                );
            }
        }
        assert_eq!(help.len(), types.len());
        assert_eq!(types.len(), samples.len());
        assert_eq!(
            samples.len(),
            30,
            "one contributor has a fixed 30-series inventory"
        );
        samples
    }

    fn value(samples: &BTreeMap<String, u128>, name: &str) -> u128 {
        samples[&format!("{name}{{profile=\"modern\"}}")]
    }

    #[test]
    fn task_scrape_preserves_store_profile_charges_and_total_byte_bound() {
        use crate::stats::{OperatorTaskExecution, OperatorTaskStorage};
        let task = OperatorSnapshot::task_store(Instant::now(), 73, OperatorTaskStore {
            storage: OperatorTaskStorage {
                retained_tasks: 7, task_limit: 12,
                retained_bytes: usize::MAX, reserved_terminal_bytes: 1,
                byte_limit: usize::MAX, saturated_owner_partitions: 2,
                ..Default::default()
            },
            execution: OperatorTaskExecution { limit: 3, reserved: 1, ..Default::default() },
            ..Default::default()
        });
        let http = OperatorSnapshot::http_connections(Instant::now(), 37, OperatorProfile::Auto,
            OperatorLifecycle::Running,
            OperatorConnectionCapacity { limit: 1, active: 0, reserved: 0 },
            OperatorConnectionCounters::default());
        let http_text = http.prometheus_text().unwrap();
        let task_text = task.prometheus_text().unwrap();
        let combined = http.prometheus_text_with_tasks(&task).unwrap();
        assert_eq!(combined.strip_prefix(&http_text), Some(task_text.as_str()));
        assert!(combined.len() <= MAX_OPERATOR_PROMETHEUS_BYTES);
        assert!(http_text.contains("profile=\"auto\""));
        for (name, value) in [("storage_retained_tasks", 7), ("storage_saturated_owner_partitions", 2),
            ("reason_storage_saturated", 1), ("reason_execution_saturated", 0),
            ("execution_reserved", 1), ("arithmetic_overflowed", 1), ("configuration_generation", 73)] {
            assert!(task_text.lines().any(|line| line == format!("fastmcp_operator_tasks_{name}{{profile=\"modern\"}} {value}")));
        }
        assert_eq!(task.prometheus_text_with_limit(task_text.len()).unwrap(), task_text);
        assert_eq!(task.prometheus_text_with_limit(task_text.len() - 1),
            Err(OperatorMetricsError::ByteLimitExceeded));
    }

    #[test]
    fn prometheus_http_preserves_counters_and_separates_readiness_from_saturation() {
        let snapshot = http_snapshot(OperatorLifecycle::Running);
        let before = snapshot.clone();
        let encoded = snapshot.prometheus_text().unwrap();
        let values = samples(&encoded);
        for (name, expected) in [
            ("metrics_schema_version", 1),
            ("snapshot_schema_version", 3),
            ("configuration_generation", 37),
            ("lifecycle_running", 1),
            ("lifecycle_stopping", 0),
            ("readiness_ready", 1),
            ("connections_limit", 3),
            ("connections_active", 2),
            ("connections_reserved", 1),
            ("connections_in_use", 3),
            ("connections_saturated", 1),
            ("reason_connection_capacity_saturated", 1),
            ("reason_connection_capacity_disabled", 0),
            ("connections_accepted_total", 11),
            ("connections_rejected_total", 7),
            ("probes_acquired_total", 5),
            ("connection_slots_released_total", 13),
            ("probes_expired_total", 2),
            ("probes_cancelled_total", 1),
            ("probes_shutdown_revoked_total", 3),
            ("counters_overflowed", 0),
            ("arithmetic_overflowed", 0),
        ] {
            assert_eq!(
                value(&values, &format!("fastmcp_operator_http_{name}")),
                expected
            );
        }
        assert_eq!(
            snapshot, before,
            "rendering cannot acquire or release a permit"
        );
    }

    #[test]
    fn prometheus_executor_reports_deferred_and_retained_correlation_charges() {
        let snapshot = OperatorSnapshot::request_executor(
            Instant::now(),
            38,
            OperatorProfile::Modern,
            OperatorExecutorState::Running,
            OperatorRequestCapacity {
                limit: 3,
                pending: 2,
                deferred_controls: 1,
            },
            OperatorCorrelationCapacity {
                limit: 7,
                pending: 2,
                tombstones: 1,
                retained_terminals: 3,
            },
        );
        let values = samples(&snapshot.prometheus_text().unwrap());
        for (name, expected) in [
            ("requests_limit", 3),
            ("requests_pending", 2),
            ("requests_deferred_controls", 1),
            ("requests_in_use", 3),
            ("requests_saturated", 1),
            ("correlations_limit", 7),
            ("correlations_pending", 2),
            ("correlations_tombstones", 1),
            ("correlations_retained_terminals", 3),
            ("correlations_in_use", 6),
            ("correlations_saturated", 0),
            ("readiness_ready", 1),
            ("reason_request_capacity_saturated", 1),
            ("reason_correlation_capacity_saturated", 0),
        ] {
            assert_eq!(
                value(&values, &format!("fastmcp_operator_executor_{name}")),
                expected
            );
        }
    }

    #[test]
    fn prometheus_stdio_reports_output_retention_without_delivery_claims() {
        let snapshot = OperatorSnapshot::stdio_output(
            Instant::now(),
            39,
            OperatorProfile::Modern,
            OperatorLifecycle::Stopping,
            OperatorStdioOutput {
                capacity: OperatorOutputCapacity {
                    frame_limit: 2,
                    byte_limit: 100,
                    retained_frames: 2,
                    retained_bytes: 99,
                },
                counters: OperatorOutputCounters {
                    enqueued: 9,
                    rejected_capacity: 4,
                    released: 7,
                    writer_failures: 1,
                    overflowed: false,
                },
                failed: false,
            },
        );
        let values = samples(&snapshot.prometheus_text().unwrap());
        for (name, expected) in [
            ("output_frame_limit", 2),
            ("output_byte_limit", 100),
            ("output_retained_frames", 2),
            ("output_retained_bytes", 99),
            ("output_frames_saturated", 1),
            ("output_bytes_saturated", 0),
            ("output_frames_enqueued_total", 9),
            ("output_frames_rejected_capacity_total", 4),
            ("output_frames_released_total", 7),
            ("output_writer_failures_total", 1),
            ("lifecycle_stopping", 1),
            ("readiness_stopping", 1),
            ("reason_output_stopping", 1),
            ("output_failed", 0),
        ] {
            assert_eq!(
                value(&values, &format!("fastmcp_operator_stdio_{name}")),
                expected
            );
        }
    }

    #[test]
    fn prometheus_exact_byte_limit_accepts_and_one_byte_less_rejects_atomically() {
        let snapshot = http_snapshot(OperatorLifecycle::Running);
        let before = snapshot.clone();
        let complete = snapshot.prometheus_text().unwrap();
        assert_eq!(
            snapshot.prometheus_text_with_limit(complete.len()).unwrap(),
            complete,
            "the exact complete exposition fits"
        );
        assert_eq!(
            snapshot.prometheus_text_with_limit(complete.len() - 1),
            Err(OperatorMetricsError::ByteLimitExceeded),
            "changing only one byte of budget cannot return truncated metrics"
        );
        for limit in [0, MAX_OPERATOR_PROMETHEUS_BYTES + 1, usize::MAX] {
            assert_eq!(
                snapshot.prometheus_text_with_limit(limit),
                Err(OperatorMetricsError::InvalidByteLimit)
            );
        }
        assert_eq!(
            snapshot, before,
            "rejected export leaves its source unchanged"
        );
        assert_eq!(snapshot.prometheus_text().unwrap(), complete);
    }

    #[test]
    fn prometheus_inventory_is_fixed_across_lifecycle_generation_and_counter_floods() {
        let mut expected = BTreeSet::new();
        for generation in 0..256 {
            for lifecycle in [
                OperatorLifecycle::Starting,
                OperatorLifecycle::Running,
                OperatorLifecycle::Stopping,
                OperatorLifecycle::Stopped,
            ] {
                let mut snapshot = http_snapshot(lifecycle);
                snapshot.configuration_generation = generation;
                snapshot.contributor.connections.active = generation as usize;
                snapshot.contributor.counters.accepted = generation;
                let values = samples(&snapshot.prometheus_text().unwrap());
                let inventory = values.into_keys().collect::<BTreeSet<_>>();
                if expected.is_empty() {
                    expected.clone_from(&inventory);
                }
                assert_eq!(inventory, expected, "observed values never become labels");
            }
        }
        let mut profiles = BTreeSet::new();
        for profile in [
            OperatorProfile::Modern,
            OperatorProfile::Legacy2024,
            OperatorProfile::Auto,
        ] {
            let mut snapshot = http_snapshot(OperatorLifecycle::Running);
            snapshot.profile = profile;
            profiles.extend(samples(&snapshot.prometheus_text().unwrap()).into_keys());
        }
        assert_eq!(
            profiles.len(),
            3 * 30,
            "the only permitted label has exactly three values"
        );
    }

    #[test]
    fn prometheus_maximum_integer_values_fit_and_overflow_is_explicit() {
        let mut http = http_snapshot(OperatorLifecycle::Running);
        http.configuration_generation = u64::MAX;
        http.contributor.connections = OperatorConnectionCapacity {
            limit: usize::MAX,
            active: usize::MAX,
            reserved: 1,
        };
        http.contributor.counters.accepted = u64::MAX;
        http.contributor.counters.overflowed = true;
        let http_values = samples(&http.prometheus_text().unwrap());
        assert_eq!(
            value(
                &http_values,
                "fastmcp_operator_http_connections_accepted_total"
            ),
            u128::from(u64::MAX)
        );
        assert_eq!(
            value(&http_values, "fastmcp_operator_http_connections_in_use"),
            usize::MAX as u128
        );
        assert_eq!(
            value(&http_values, "fastmcp_operator_http_arithmetic_overflowed"),
            1
        );
        assert_eq!(
            value(&http_values, "fastmcp_operator_http_counters_overflowed"),
            1
        );

        let executor = OperatorSnapshot::request_executor(
            Instant::now(),
            u64::MAX,
            OperatorProfile::Modern,
            OperatorExecutorState::GenerationExhausted,
            OperatorRequestCapacity {
                limit: usize::MAX,
                pending: usize::MAX,
                deferred_controls: 1,
            },
            OperatorCorrelationCapacity {
                limit: usize::MAX,
                pending: usize::MAX,
                tombstones: usize::MAX,
                retained_terminals: usize::MAX,
            },
        );
        let values = samples(&executor.prometheus_text().unwrap());
        assert_eq!(
            value(&values, "fastmcp_operator_executor_requests_in_use"),
            usize::MAX as u128
        );
        assert_eq!(
            value(&values, "fastmcp_operator_executor_correlations_in_use"),
            usize::MAX as u128
        );
        assert_eq!(
            value(&values, "fastmcp_operator_executor_arithmetic_overflowed"),
            1
        );
        assert_eq!(
            value(
                &values,
                "fastmcp_operator_executor_reason_executor_generation_exhausted"
            ),
            1
        );

        let stdio = OperatorSnapshot::stdio_output(
            Instant::now(),
            u64::MAX,
            OperatorProfile::Modern,
            OperatorLifecycle::Stopped,
            OperatorStdioOutput {
                capacity: OperatorOutputCapacity {
                    frame_limit: usize::MAX,
                    byte_limit: usize::MAX,
                    retained_frames: usize::MAX,
                    retained_bytes: usize::MAX,
                },
                counters: OperatorOutputCounters {
                    enqueued: u64::MAX,
                    rejected_capacity: u64::MAX,
                    released: u64::MAX,
                    writer_failures: u64::MAX,
                    overflowed: true,
                },
                failed: true,
            },
        );
        let values = samples(&stdio.prometheus_text().unwrap());
        assert_eq!(
            value(
                &values,
                "fastmcp_operator_stdio_output_frames_enqueued_total"
            ),
            u128::from(u64::MAX)
        );
        assert_eq!(value(&values, "fastmcp_operator_stdio_output_failed"), 1);
        assert_eq!(
            value(&values, "fastmcp_operator_stdio_arithmetic_overflowed"),
            1
        );
    }

    #[test]
    fn prometheus_export_uses_only_captured_typed_data_and_never_recaptures() {
        struct Source {
            captures: AtomicUsize,
            private_context: String,
        }
        impl OperatorSnapshotSource for Source {
            fn operator_snapshot(&self) -> Result<OperatorSnapshot, OperatorSnapshotError> {
                assert_eq!(self.captures.fetch_add(1, Ordering::SeqCst), 0);
                Ok(http_snapshot(OperatorLifecycle::Running))
            }
        }
        let source = Source {
            captures: AtomicUsize::new(0),
            private_context: "Bearer-secret-Cookie-peer-issuer-subject-task-error-canary"
                .to_owned(),
        };
        let snapshot = OperatorSnapshot::capture(&source).unwrap();
        let first = snapshot.prometheus_text().unwrap();
        for _ in 0..64 {
            assert_eq!(snapshot.prometheus_text().unwrap(), first);
        }
        assert!(!first.contains(&source.private_context));
        assert!(
            !first.contains("captured_at"),
            "monotonic instants are not exported as wall time"
        );
        assert_eq!(source.captures.load(Ordering::SeqCst), 1);
        samples(&first);
    }
}
