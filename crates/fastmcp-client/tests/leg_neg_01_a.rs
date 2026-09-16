//! LEG-NEG-01 A — disposable-process stdio modern-first classification.
//!
//! External consumer of the shipped `fastmcp_client` public surface: the
//! evaluator, the manifest, and the classification entrypoint are all reached as
//! a downstream crate reaches them, never through `use super::` or a
//! `#[cfg(test)]` module (PL-3).
//!
//! These cases spawn **real child processes**. Each fixture child is a POSIX
//! shell that appends `spawn:<pid>` and `wire:<first line>` to a per-case trace
//! file, so child identity, generation count, first-wire bytes, and probe reaping
//! are observed from the operating system rather than asserted from a mock.
//!
//! **Platform qualification:** these two tests are `#[cfg(unix)]`, matching the
//! existing disposable-process precedent in `crates/fastmcp-client/src/mcp_config.rs`.
//! On the Linux verification lane they are discovered and run; they are not
//! ignored, filtered, or feature-disabled. On a non-POSIX host the target would
//! carry no rows at all, which is a platform qualification and is declared here
//! rather than left implicit.
//!
//! **Cancellation domains:** every case builds its own `Cx::for_request()`.
//! `Cx::clone` aliases one cancellation domain rather than creating a child, so
//! sharing a context across cases would let one cancelled case poison every
//! later case.

#![cfg(unix)]

use std::path::{Path, PathBuf};

use asupersync::Cx;
use fastmcp_client::{
    LEG_NEG_01_A_EVALUATOR_MANIFEST_V1, StdioClassificationCase, StdioClassificationRecord,
    StdioFirstWireSignal, TraceOutcome, case_input_digest, evaluate_stdio_case,
    leg_neg_01_a_manifest_digest,
};
use fastmcp_protocol::protocol_policy::{ProtocolEra, ProtocolPolicy};

const MODERN_ERA: &str = "2026-07-28";
const LEGACY_ERA: &str = "2024-11-05";
/// Planted only. Never selectable.
const UNSUPPORTED_ERA: &str = "2025-11-25";

/// The JSON-RPC id the shipped client uses for its discovery probe.
const CORRELATED_ID: &str = "1";
/// A different id, which makes an otherwise identical refusal uncorrelated.
const UNCORRELATED_ID: &str = "9";

/// Reserves a unique per-case observation trace.
fn reserve_trace(case_id: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "fastmcp-leg-neg-01-a-{}-{}-{}.log",
        case_id,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock follows the Unix epoch")
            .as_nanos()
    ));
    std::fs::File::create_new(&path).expect("reserve a unique per-case observation trace");
    path
}

/// Builds the fixture child.
///
/// The child records its own pid and the exact first MCP line it read, then
/// answers according to `$2`. Every branch records before it answers, so a
/// child that spawned always leaves evidence even if it then exits.
///
/// `$1` is the trace path, `$2` the behaviour, `$3` the discovery refusal id,
/// `$4` the advertised legacy protocol version.
fn fixture_script() -> &'static str {
    r#"
printf 'spawn:%s\n' "$$" >> "$1" || exit 90
IFS= read -r first || exit 91
printf 'wire:%s\n' "$first" >> "$1" || exit 92
case "$first" in
    *'"method":"server/discover"'*) era=modern;;
    *'"method":"initialize"'*) era=legacy;;
    *) exit 93;;
esac
if [ "$era" = modern ]; then
    case "$2" in
        correlated-refusal|uncorrelated-refusal)
            printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no discovery"}}\n' "$3"
            exec sleep 5;;
        recognized-modern-error)
            printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32602,"message":"invalid params"}}\n' "$3"
            exec sleep 5;;
        modern-result)
            printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{},"ttlMs":0,"cacheScope":"private","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"leg-neg-01-a-peer","version":"1"}}}}'
            exec sleep 5;;
        *) exit 94;;
    esac
fi
printf '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"%s","capabilities":{},"serverInfo":{"name":"leg-neg-01-a-peer","version":"1"}}}\n' "$4"
IFS= read -r initialized || exit 95
case "$initialized" in *notifications/initialized*) ;; *) exit 96;; esac
exec sleep 5
"#
}

/// Declares one case bound to a fresh trace, with the fixture child as command.
fn case(
    case_id: &str,
    policy: ProtocolPolicy,
    signal: StdioFirstWireSignal,
    behaviour: &str,
    refusal_id: &str,
    legacy_version: &str,
) -> (StdioClassificationCase, PathBuf) {
    let trace = reserve_trace(case_id);
    let args = vec![
        "-c".to_owned(),
        fixture_script().to_owned(),
        "leg-neg-01-a".to_owned(),
        trace.to_str().expect("trace path is UTF-8").to_owned(),
        behaviour.to_owned(),
        refusal_id.to_owned(),
        legacy_version.to_owned(),
    ];
    let declared = StdioClassificationCase::new(case_id, policy, signal, "sh", args)
        .with_trace_path(trace.clone());
    (declared, trace)
}

/// Runs one case in its own cancellation domain.
fn run(declared: &StdioClassificationCase) -> StdioClassificationRecord {
    // A fresh context per case. `Cx::clone` would alias one cancellation domain.
    let cx = Cx::for_request();
    evaluate_stdio_case(&cx, declared)
}

/// Asserts the trace was actually read.
///
/// Three-way on purpose: a read trace continues, an unbound trace fails as a
/// declaration error, and an unreadable trace fails as **inconclusive** rather
/// than being silently read as "no children spawned".
fn assert_trace_conclusive(record: &StdioClassificationRecord) {
    match &record.trace_outcome {
        TraceOutcome::Read => {}
        TraceOutcome::NotBound => panic!(
            "{}: the case declared no observation trace, so child identity is unobservable",
            record.case_id
        ),
        TraceOutcome::Unreadable { reason } => panic!(
            "{}: the observation trace is INCONCLUSIVE, not empty: {reason}. \
             An unreadable trace must never be read as 'no children spawned'.",
            record.case_id
        ),
    }
    assert!(
        record.unrecognized_trace_records.is_empty(),
        "{}: the observation trace carried unrecognized records {:?}; a malformed trace \
         cannot be treated as a clean one",
        record.case_id,
        record.unrecognized_trace_records
    );
    assert!(
        !record.child_pids.is_empty(),
        "{}: at least the disposable probe child must have been spawned",
        record.case_id
    );
}

/// Asserts no child beyond the disposable probe was ever started.
fn assert_no_legacy_child(record: &StdioClassificationRecord) {
    assert_trace_conclusive(record);
    assert_eq!(
        record.legacy_child_count(),
        0,
        "{}: legacy_child_count must be 0, observed pids {:?}",
        record.case_id,
        record.child_pids
    );
    assert_eq!(
        record.child_generation_count(),
        1,
        "{}: exactly one disposable child may exist",
        record.case_id
    );
    assert!(
        !record.probe_reaped(),
        "{}: no fresh child means no probe-reap transition",
        record.case_id
    );
    assert_eq!(
        record.credential_boundary.mutations, 0,
        "{}: stdio must never mutate a credential",
        record.case_id
    );
    assert_eq!(
        record.credential_boundary.attached, 0,
        "{}: stdio must never attach a credential",
        record.case_id
    );
}

/// Asserts the first wire line carries the frozen marker.
fn assert_first_wire(record: &StdioClassificationRecord, index: usize, marker: &str) {
    let line = record.first_wire.get(index).unwrap_or_else(|| {
        panic!(
            "{}: no first-wire record at index {index}; observed {:?}",
            record.case_id, record.first_wire
        )
    });
    assert!(
        line.contains(marker),
        "{}: first-wire line {index} must carry {marker}, observed {line}",
        record.case_id
    );
}

fn cleanup(trace: &Path) {
    // Best effort; a retained trace never changes an assertion.
    let _ = std::fs::remove_file(trace);
}

#[test]
fn leg_neg_01_a_positive() {
    // -----------------------------------------------------------------
    // The immutable manifest.
    // -----------------------------------------------------------------
    let manifest = LEG_NEG_01_A_EVALUATOR_MANIFEST_V1;
    assert!(manifest.ends_with('\n'), "the manifest is LF-terminated");
    assert!(!manifest.contains('\r'), "the manifest is LF-canonical");
    let digest = leg_neg_01_a_manifest_digest();
    assert_eq!(
        digest.as_bytes().len(),
        32,
        "the manifest digest is a SHA-256"
    );

    let policy_cases: Vec<&str> = manifest
        .lines()
        .filter(|line| line.starts_with("policy-case "))
        .collect();
    assert!(
        policy_cases.len() >= 3,
        "the manifest declares at least three policy cases, found {}",
        policy_cases.len()
    );
    for policy in ["policy=Auto", "policy=ModernOnly", "policy=LegacyOnly"] {
        assert!(
            policy_cases.iter().any(|line| line.contains(policy)),
            "the manifest must cover {policy}"
        );
    }
    assert!(
        policy_cases
            .iter()
            .filter(|l| l.contains("eligible=true"))
            .count()
            >= 1,
        "the manifest declares at least one eligible case"
    );
    assert!(
        policy_cases
            .iter()
            .filter(|l| l.contains("eligible=false"))
            .count()
            >= 1,
        "the manifest declares at least one ineligible case"
    );
    assert!(
        manifest.contains("supported-eras 2026-07-28,2024-11-05"),
        "exactly the two supported eras are frozen"
    );
    assert!(
        !manifest.contains(UNSUPPORTED_ERA),
        "the unsupported era is never a manifest input"
    );

    // -----------------------------------------------------------------
    // Auto + valid modern discovery result selects 2026-07-28.
    // -----------------------------------------------------------------
    let (declared, trace) = case(
        "auto-modern-selected",
        ProtocolPolicy::Auto,
        StdioFirstWireSignal::ModernDiscoveryResult,
        "modern-result",
        CORRELATED_ID,
        LEGACY_ERA,
    );
    let modern = run(&declared);
    assert!(modern.connected, "a valid modern result must connect");
    assert_eq!(modern.selected_era, Some(ProtocolEra::Modern2026));
    assert_eq!(modern.protocol_version.as_deref(), Some(MODERN_ERA));
    assert_eq!(modern.transport, "stdio");
    assert_eq!(modern.policy, ProtocolPolicy::Auto);
    assert_first_wire(&modern, 0, "\"method\":\"server/discover\"");
    assert_no_legacy_child(&modern);
    cleanup(&trace);

    // -----------------------------------------------------------------
    // Auto + correlated MethodNotFound: reap the probe, start ONE fresh
    // child whose first MCP request is exact 2024-11-05 initialize.
    // -----------------------------------------------------------------
    let (eligible_case, eligible_trace) = case(
        "auto-eligible-correlated-refusal",
        ProtocolPolicy::Auto,
        StdioFirstWireSignal::CorrelatedDiscoveryRefusal,
        "correlated-refusal",
        CORRELATED_ID,
        LEGACY_ERA,
    );
    let eligible = run(&eligible_case);
    assert_trace_conclusive(&eligible);
    assert!(
        eligible.connected,
        "the eligible refusal must reach a client"
    );
    assert_eq!(eligible.selected_era, Some(ProtocolEra::Legacy2024));
    assert_eq!(eligible.protocol_version.as_deref(), Some(LEGACY_ERA));
    assert_eq!(
        eligible.child_generation_count(),
        2,
        "one disposable probe plus exactly one fresh legacy child"
    );
    assert_eq!(eligible.legacy_child_count(), 1);
    assert!(
        eligible.probe_reaped(),
        "the fresh child must be a distinct process from the reaped probe, observed {:?}",
        eligible.child_pids
    );
    assert_first_wire(&eligible, 0, "\"method\":\"server/discover\"");
    assert_first_wire(&eligible, 1, "\"method\":\"initialize\"");
    assert_first_wire(&eligible, 1, LEGACY_ERA);
    assert!(
        !eligible.first_wire[1].contains(MODERN_ERA),
        "the fresh child's first request must not carry modern metadata"
    );
    assert_eq!(eligible.credential_boundary.mutations, 0);

    // -----------------------------------------------------------------
    // The one-variable pair: the SAME refusal with a different response id
    // is uncorrelated and must not start a second child.
    // -----------------------------------------------------------------
    let (ineligible_case, ineligible_trace) = case(
        "auto-ineligible-uncorrelated-refusal",
        ProtocolPolicy::Auto,
        StdioFirstWireSignal::UncorrelatedDiscoveryRefusal,
        "uncorrelated-refusal",
        UNCORRELATED_ID,
        LEGACY_ERA,
    );
    let ineligible = run(&ineligible_case);
    assert!(
        !ineligible.connected,
        "an uncorrelated refusal must not produce a live client"
    );
    assert_eq!(ineligible.selected_era, None);
    assert_first_wire(&ineligible, 0, "\"method\":\"server/discover\"");
    assert_no_legacy_child(&ineligible);

    // The pair differs in exactly one declared field.
    assert_eq!(eligible_case.policy(), ineligible_case.policy());
    assert_eq!(eligible_case.command(), ineligible_case.command());
    assert_ne!(eligible_case.signal(), ineligible_case.signal());
    assert_ne!(
        case_input_digest(&eligible_case).as_bytes(),
        case_input_digest(&ineligible_case).as_bytes(),
        "paired input digests must differ"
    );
    assert!(eligible_case.expects_fallback());
    assert!(!ineligible_case.expects_fallback());
    cleanup(&eligible_trace);
    cleanup(&ineligible_trace);

    // -----------------------------------------------------------------
    // A recognized modern error is proof of the modern era, never a
    // downgrade signal.
    // -----------------------------------------------------------------
    let (declared, trace) = case(
        "auto-ineligible-recognized-modern-error",
        ProtocolPolicy::Auto,
        StdioFirstWireSignal::RecognizedModernError,
        "recognized-modern-error",
        CORRELATED_ID,
        LEGACY_ERA,
    );
    let recognized = run(&declared);
    assert!(
        !recognized.connected,
        "a recognized modern error must not produce a live client"
    );
    assert_eq!(recognized.selected_era, None);
    assert_no_legacy_child(&recognized);
    cleanup(&trace);

    // -----------------------------------------------------------------
    // ModernOnly never enters fallback, even on the eligible signal.
    // -----------------------------------------------------------------
    let (declared, trace) = case(
        "modern-only-never-falls-back",
        ProtocolPolicy::ModernOnly,
        StdioFirstWireSignal::CorrelatedDiscoveryRefusal,
        "correlated-refusal",
        CORRELATED_ID,
        LEGACY_ERA,
    );
    let modern_only = run(&declared);
    assert!(
        !modern_only.connected,
        "ModernOnly must not fall back on the otherwise-eligible signal"
    );
    assert_eq!(modern_only.selected_era, None);
    assert_eq!(modern_only.policy, ProtocolPolicy::ModernOnly);
    assert_first_wire(&modern_only, 0, "\"method\":\"server/discover\"");
    assert_no_legacy_child(&modern_only);
    cleanup(&trace);

    // -----------------------------------------------------------------
    // LegacyOnly never probes: its very first wire is exact-2024 initialize.
    // -----------------------------------------------------------------
    let (declared, trace) = case(
        "legacy-only-never-probes",
        ProtocolPolicy::LegacyOnly,
        StdioFirstWireSignal::NoModernProbe,
        "unused",
        CORRELATED_ID,
        LEGACY_ERA,
    );
    let legacy_only = run(&declared);
    assert!(
        legacy_only.connected,
        "LegacyOnly must complete its lifecycle"
    );
    assert_eq!(legacy_only.selected_era, Some(ProtocolEra::Legacy2024));
    assert_eq!(legacy_only.protocol_version.as_deref(), Some(LEGACY_ERA));
    assert_first_wire(&legacy_only, 0, "\"method\":\"initialize\"");
    assert!(
        !legacy_only.first_wire[0].contains("server/discover"),
        "LegacyOnly must never emit a modern discovery probe"
    );
    assert_no_legacy_child(&legacy_only);
    cleanup(&trace);
}

#[test]
fn leg_neg_01_a_planted_negative() {
    // Baseline: the accepted eligible case, unchanged.
    let (baseline_case, baseline_trace) = case(
        "auto-eligible-correlated-refusal",
        ProtocolPolicy::Auto,
        StdioFirstWireSignal::CorrelatedDiscoveryRefusal,
        "correlated-refusal",
        CORRELATED_ID,
        LEGACY_ERA,
    );
    let baseline = run(&baseline_case);
    assert!(baseline.connected);
    assert_eq!(baseline.selected_era, Some(ProtocolEra::Legacy2024));
    assert_eq!(baseline.protocol_version.as_deref(), Some(LEGACY_ERA));
    assert_eq!(baseline.child_generation_count(), 2);
    cleanup(&baseline_trace);

    // Planted: exactly one changed era field. The fresh child advertises the
    // unsupported 2025-11-25 instead of exact 2024-11-05. Policy, signal,
    // command, refusal id and call sequence are all unchanged.
    let (planted_case, planted_trace) = case(
        "auto-eligible-correlated-refusal",
        ProtocolPolicy::Auto,
        StdioFirstWireSignal::CorrelatedDiscoveryRefusal,
        "correlated-refusal",
        CORRELATED_ID,
        UNSUPPORTED_ERA,
    );
    assert_eq!(planted_case.policy(), baseline_case.policy());
    assert_eq!(planted_case.signal(), baseline_case.signal());
    assert_eq!(planted_case.command(), baseline_case.command());

    let planted = run(&planted_case);
    assert_trace_conclusive(&planted);

    // The unsupported era reaches the denial boundary and selects nothing.
    assert!(
        !planted.connected,
        "2025-11-25 must never produce a live client"
    );
    assert_eq!(
        planted.selected_era, None,
        "an unsupported era selects neither 2026-07-28 nor exact 2024-11-05"
    );
    assert_eq!(planted.protocol_version, None);
    assert_ne!(planted.selected_era, baseline.selected_era);

    // Everything else about the run is preserved: the probe still ran, the
    // fallback child was still started by the same eligible signal, and the
    // probe was still reaped into a distinct process.
    assert_eq!(
        planted.child_generation_count(),
        baseline.child_generation_count(),
        "the eligible signal is unchanged, so the child generation count is unchanged"
    );
    assert_eq!(planted.legacy_child_count(), baseline.legacy_child_count());
    assert!(planted.probe_reaped());
    assert_first_wire(&planted, 0, "\"method\":\"server/discover\"");
    assert_first_wire(&planted, 1, "\"method\":\"initialize\"");
    assert_first_wire(&planted, 1, LEGACY_ERA);

    // The client never echoes the unsupported era on the wire; it appears only
    // in the peer's rejected response.
    for (index, line) in planted.first_wire.iter().enumerate() {
        assert!(
            !line.contains(UNSUPPORTED_ERA),
            "the client must never emit {UNSUPPORTED_ERA} on wire line {index}: {line}"
        );
    }

    // Zero credential and zero cache movement on the denied path.
    assert_eq!(planted.credential_boundary.mutations, 0);
    assert_eq!(planted.credential_boundary.attached, 0);
    assert_eq!(planted.policy, baseline.policy);
    assert_eq!(planted.transport, baseline.transport);
    assert_eq!(planted.signal, baseline.signal);
    cleanup(&planted_trace);

    // The baseline is freshly reaccepted after the planted denial, proving the
    // refusal left no retained state behind it.
    let (reaccept_case, reaccept_trace) = case(
        "auto-eligible-correlated-refusal",
        ProtocolPolicy::Auto,
        StdioFirstWireSignal::CorrelatedDiscoveryRefusal,
        "correlated-refusal",
        CORRELATED_ID,
        LEGACY_ERA,
    );
    let reaccepted = run(&reaccept_case);
    assert!(
        reaccepted.connected,
        "the baseline must be freshly reaccepted after the planted denial"
    );
    assert_eq!(reaccepted.selected_era, baseline.selected_era);
    assert_eq!(reaccepted.protocol_version, baseline.protocol_version);
    assert_eq!(
        reaccepted.child_generation_count(),
        baseline.child_generation_count()
    );
    assert!(reaccepted.probe_reaped());
    cleanup(&reaccept_trace);
}
