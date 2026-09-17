//! Reservation snapshot validation for `preclaim` and `preclose`.
//!
//! The checker has no network and no mutation authority: the execution layer
//! obtains the snapshot from Agent Mail and hands it over as bytes, on a path
//! or on stdin. Both routes parse to the same value, so a snapshot cannot mean
//! one thing through a file and another through a pipe.
//!
//! Time is a parameter, never a hidden call to the system clock. A validator
//! that reads the clock internally cannot be tested at its boundaries, and
//! these boundaries -- 60 seconds of snapshot age, 30 minutes of remaining
//! lease -- are exactly what must be tested.

use std::collections::BTreeSet;

use serde::Deserialize;

use super::diagnostics::{Code, Diagnostic, Report};

/// A snapshot older than this cannot describe current reality.
pub const MAX_SNAPSHOT_AGE_SECONDS: i64 = 60;
/// A claim-time lease with less than this remaining will expire mid-work.
pub const MIN_REMAINING_SECONDS_AT_CLAIM: i64 = 30 * 60;

/// One renewal observation in a lease's history.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Renewal {
    /// Unix seconds when the lease was taken or renewed.
    pub at: i64,
    /// Unix seconds when that lease interval expired.
    pub until: i64,
}

/// One live reservation lease.
#[derive(Debug, Clone, Deserialize)]
pub struct Lease {
    pub lease_id: String,
    /// Normalized repository-relative path pattern.
    pub path: String,
    pub exclusive: bool,
    /// The issue this lease was taken for.
    pub issue_id: String,
    /// Unix seconds when the current interval expires.
    pub expires_at: i64,
    /// Ordered lease and renewal history, oldest first.
    #[serde(default)]
    pub history: Vec<Renewal>,
}

/// The snapshot the execution layer exports from Agent Mail.
#[derive(Debug, Clone, Deserialize)]
pub struct ReservationSnapshot {
    pub schema: String,
    pub project_key: String,
    pub agent_name: String,
    /// Unix seconds when the snapshot was generated.
    pub generated_at: i64,
    #[serde(default, rename = "lease")]
    pub leases: Vec<Lease>,
}

pub const SNAPSHOT_SCHEMA: &str = "fnd-02-reservation-snapshot-v1";

/// What the issue declared it would reserve, before acquisition.
#[derive(Debug, Clone)]
pub struct Declaration {
    pub project_key: String,
    pub agent_name: String,
    pub issue_id: String,
    /// Exact narrow paths. No whole-crate or repository glob.
    pub paths: Vec<String>,
}

/// Parse a snapshot from TOML bytes.
///
/// One parser serves both the `--reservations-json <path>` and the `-` stdin
/// route, so parity between them is structural rather than asserted.
pub fn parse_snapshot(text: &str, subject: &str) -> Result<ReservationSnapshot, Diagnostic> {
    let snapshot: ReservationSnapshot = toml::from_str(text).map_err(|error| {
        Diagnostic::new(Code::SchemaInvalid, subject, "toml", error.to_string())
    })?;
    if snapshot.schema != SNAPSHOT_SCHEMA {
        return Err(Diagnostic::new(
            Code::SchemaInvalid,
            subject,
            "schema",
            format!("expected {SNAPSHOT_SCHEMA}, observed {}", snapshot.schema),
        ));
    }
    Ok(snapshot)
}

/// True when `candidate` is broader than `declared`: it covers the declared
/// path and more.
///
/// A broader lease is not a harmless superset. It silently takes ownership of
/// files the issue never declared, which is how two lanes end up believing
/// they own the same file.
fn is_broader(candidate: &str, declared: &str) -> bool {
    if candidate == declared {
        return false;
    }
    match candidate.strip_suffix("**") {
        Some(prefix) => declared.starts_with(prefix),
        None => false,
    }
}

/// Which pass is validating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pass {
    /// First preclaim pass: validates the declared set only.
    DeclarationOnly,
    /// Final preclaim pass after acquisition: requires a fresh snapshot and
    /// exact equality with the declaration.
    Claim,
    /// Close: requires a contiguous claim-to-close lease history.
    Close,
}

/// Validate a declaration and, for the passes that require one, a snapshot.
///
/// `now` is Unix seconds.
pub fn validate(
    declaration: &Declaration,
    snapshot: Option<&ReservationSnapshot>,
    pass: Pass,
    now: i64,
    claimed_at: i64,
) -> Report {
    let mut report = Report::new();

    if declaration.paths.is_empty() {
        report.push(Diagnostic::new(
            Code::ReservationDeclarationMismatch,
            &declaration.issue_id,
            "paths",
            "a declaration with no path cannot certify ownership",
        ));
    }
    for path in &declaration.paths {
        if path == "**" || path == "." || path.is_empty() {
            report.push(Diagnostic::new(
                Code::ReservationPathTooBroad,
                &declaration.issue_id,
                "paths",
                format!("{path:?} is a repository glob, not an ownership card"),
            ));
        }
    }

    let Some(snapshot) = snapshot else {
        if pass != Pass::DeclarationOnly {
            report.push(Diagnostic::new(
                Code::ReservationSnapshotMissing,
                &declaration.issue_id,
                "snapshot",
                "this pass requires a fresh reservation snapshot",
            ));
        }
        return report;
    };

    if snapshot.project_key != declaration.project_key {
        report.push(Diagnostic::new(
            Code::ReservationWrongProject,
            &declaration.issue_id,
            "project_key",
            format!(
                "expected {:?}, observed {:?}",
                declaration.project_key, snapshot.project_key
            ),
        ));
    }
    if snapshot.agent_name != declaration.agent_name {
        report.push(Diagnostic::new(
            Code::ReservationWrongAgent,
            &declaration.issue_id,
            "agent_name",
            format!(
                "expected {:?}, observed {:?}",
                declaration.agent_name, snapshot.agent_name
            ),
        ));
    }

    let age = now.saturating_sub(snapshot.generated_at);
    if age > MAX_SNAPSHOT_AGE_SECONDS || age < 0 {
        report.push(Diagnostic::new(
            Code::ReservationSnapshotStale,
            &declaration.issue_id,
            "generated_at",
            format!("snapshot age {age}s is outside 0..={MAX_SNAPSHOT_AGE_SECONDS}"),
        ));
    }

    let mut seen_paths: BTreeSet<&str> = BTreeSet::new();
    let mut seen_leases: BTreeSet<&str> = BTreeSet::new();
    for lease in &snapshot.leases {
        if lease.issue_id != declaration.issue_id {
            report.push(Diagnostic::new(
                Code::ReservationWrongIssue,
                &lease.lease_id,
                "issue_id",
                format!(
                    "expected {:?}, observed {:?}",
                    declaration.issue_id, lease.issue_id
                ),
            ));
        }
        if !seen_leases.insert(lease.lease_id.as_str()) {
            report.push(Diagnostic::new(
                Code::ReservationDuplicate,
                &lease.lease_id,
                "lease_id",
                "one lease id appears twice",
            ));
        }
        if !seen_paths.insert(lease.path.as_str()) {
            report.push(Diagnostic::new(
                Code::ReservationDuplicate,
                &lease.lease_id,
                "path",
                format!("{:?} is leased twice", lease.path),
            ));
        }
        if !lease.exclusive {
            report.push(Diagnostic::new(
                Code::ReservationDeclarationMismatch,
                &lease.lease_id,
                "exclusive",
                "an owned path requires an exclusive lease",
            ));
        }
        for declared in &declaration.paths {
            if is_broader(&lease.path, declared) {
                report.push(Diagnostic::new(
                    Code::ReservationPathTooBroad,
                    &lease.lease_id,
                    "path",
                    format!("{:?} is broader than the declared {declared:?}", lease.path),
                ));
            }
        }
        if lease.expires_at <= now {
            report.push(Diagnostic::new(
                Code::ReservationExpired,
                &lease.lease_id,
                "expires_at",
                format!("expired {}s ago", now - lease.expires_at),
            ));
            continue;
        }
        if pass == Pass::Claim && lease.expires_at - now < MIN_REMAINING_SECONDS_AT_CLAIM {
            report.push(Diagnostic::new(
                Code::ReservationInsufficientRemaining,
                &lease.lease_id,
                "expires_at",
                format!(
                    "{}s remaining is below {MIN_REMAINING_SECONDS_AT_CLAIM}",
                    lease.expires_at - now
                ),
            ));
        }
    }

    // Exact set equality between declared paths and observed leases.
    let declared: BTreeSet<&str> = declaration.paths.iter().map(String::as_str).collect();
    let observed: BTreeSet<&str> = snapshot.leases.iter().map(|l| l.path.as_str()).collect();
    if pass != Pass::DeclarationOnly && declared != observed {
        let missing: Vec<&&str> = declared.difference(&observed).collect();
        let extra: Vec<&&str> = observed.difference(&declared).collect();
        report.push(Diagnostic::new(
            Code::ReservationDeclarationMismatch,
            &declaration.issue_id,
            "paths",
            format!("missing={missing:?} extra={extra:?}"),
        ));
    }

    // Close requires an unbroken lease history from claim to now. A gap means
    // the path was unowned for a while; that needs human adjudication, not a
    // fabricated reacquisition history.
    if pass == Pass::Close {
        for lease in &snapshot.leases {
            if let Some(gap) = first_history_gap(&lease.history, claimed_at, now) {
                report.push(Diagnostic::new(
                    Code::ReservationRenewalGap,
                    &lease.lease_id,
                    "history",
                    gap,
                ));
            }
        }
    }

    report
}

/// Find the first discontinuity in a lease history covering `[from, to]`.
fn first_history_gap(history: &[Renewal], from: i64, to: i64) -> Option<String> {
    let Some(first) = history.first() else {
        return Some("no lease history covers the claim-to-close interval".to_owned());
    };
    if first.at > from {
        return Some(format!(
            "history starts at {} but the claim was at {from}",
            first.at
        ));
    }
    let mut covered_until = first.until;
    for renewal in history.iter().skip(1) {
        if renewal.at > covered_until {
            return Some(format!(
                "coverage lapsed between {covered_until} and {}",
                renewal.at
            ));
        }
        covered_until = covered_until.max(renewal.until);
    }
    if covered_until < to {
        return Some(format!("coverage ends at {covered_until} before {to}"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000_000;
    const CLAIMED: i64 = 990_000;

    fn declaration() -> Declaration {
        Declaration {
            project_key: "/repo".to_owned(),
            agent_name: "MagentaOsprey".to_owned(),
            issue_id: "bd-x".to_owned(),
            paths: vec!["tools/xtask/**".to_owned()],
        }
    }

    fn lease() -> Lease {
        Lease {
            lease_id: "L1".to_owned(),
            path: "tools/xtask/**".to_owned(),
            exclusive: true,
            issue_id: "bd-x".to_owned(),
            expires_at: NOW + 7200,
            history: vec![Renewal { at: CLAIMED - 10, until: NOW + 7200 }],
        }
    }

    fn snapshot() -> ReservationSnapshot {
        ReservationSnapshot {
            schema: SNAPSHOT_SCHEMA.to_owned(),
            project_key: "/repo".to_owned(),
            agent_name: "MagentaOsprey".to_owned(),
            generated_at: NOW - 5,
            leases: vec![lease()],
        }
    }

    #[test]
    fn a_fresh_matching_snapshot_passes_every_pass() {
        for pass in [Pass::DeclarationOnly, Pass::Claim, Pass::Close] {
            let report = validate(&declaration(), Some(&snapshot()), pass, NOW, CLAIMED);
            assert!(report.is_clean(), "{pass:?}: {}", report.render());
        }
    }

    #[test]
    fn the_first_pass_needs_no_snapshot_but_later_passes_do() {
        assert!(validate(&declaration(), None, Pass::DeclarationOnly, NOW, CLAIMED).is_clean());
        for pass in [Pass::Claim, Pass::Close] {
            assert!(
                validate(&declaration(), None, pass, NOW, CLAIMED)
                    .has(Code::ReservationSnapshotMissing)
            );
        }
    }

    #[test]
    fn a_wrong_project_agent_or_issue_is_rejected() {
        let mut wrong = snapshot();
        wrong.project_key = "/other".to_owned();
        assert!(
            validate(&declaration(), Some(&wrong), Pass::Claim, NOW, CLAIMED)
                .has(Code::ReservationWrongProject)
        );

        let mut wrong = snapshot();
        wrong.agent_name = "OliveOwl".to_owned();
        assert!(
            validate(&declaration(), Some(&wrong), Pass::Claim, NOW, CLAIMED)
                .has(Code::ReservationWrongAgent)
        );

        let mut wrong = snapshot();
        wrong.leases[0].issue_id = "bd-other".to_owned();
        assert!(
            validate(&declaration(), Some(&wrong), Pass::Claim, NOW, CLAIMED)
                .has(Code::ReservationWrongIssue)
        );
    }

    #[test]
    fn snapshot_age_is_checked_at_its_exact_boundary() {
        let mut fresh = snapshot();
        fresh.generated_at = NOW - MAX_SNAPSHOT_AGE_SECONDS;
        assert!(
            validate(&declaration(), Some(&fresh), Pass::Claim, NOW, CLAIMED).is_clean(),
            "exactly at the limit is admissible"
        );

        let mut stale = snapshot();
        stale.generated_at = NOW - MAX_SNAPSHOT_AGE_SECONDS - 1;
        assert!(
            validate(&declaration(), Some(&stale), Pass::Claim, NOW, CLAIMED)
                .has(Code::ReservationSnapshotStale),
            "one second past the limit is not"
        );
    }

    #[test]
    fn a_future_dated_snapshot_is_rejected() {
        let mut future = snapshot();
        future.generated_at = NOW + 10;
        assert!(
            validate(&declaration(), Some(&future), Pass::Claim, NOW, CLAIMED)
                .has(Code::ReservationSnapshotStale)
        );
    }

    #[test]
    fn remaining_lease_time_is_checked_at_its_exact_boundary_at_claim() {
        let mut exact = snapshot();
        exact.leases[0].expires_at = NOW + MIN_REMAINING_SECONDS_AT_CLAIM;
        assert!(validate(&declaration(), Some(&exact), Pass::Claim, NOW, CLAIMED).is_clean());

        let mut short = snapshot();
        short.leases[0].expires_at = NOW + MIN_REMAINING_SECONDS_AT_CLAIM - 1;
        assert!(
            validate(&declaration(), Some(&short), Pass::Claim, NOW, CLAIMED)
                .has(Code::ReservationInsufficientRemaining)
        );

        // Close does not impose the claim-time floor.
        let mut short_close = snapshot();
        short_close.leases[0].expires_at = NOW + 60;
        assert!(
            !validate(&declaration(), Some(&short_close), Pass::Close, NOW, CLAIMED)
                .has(Code::ReservationInsufficientRemaining)
        );
    }

    #[test]
    fn an_expired_lease_is_rejected() {
        let mut expired = snapshot();
        expired.leases[0].expires_at = NOW - 1;
        assert!(
            validate(&declaration(), Some(&expired), Pass::Claim, NOW, CLAIMED)
                .has(Code::ReservationExpired)
        );
    }

    #[test]
    fn a_duplicate_lease_or_path_is_rejected() {
        let mut duplicated = snapshot();
        duplicated.leases.push(lease());
        assert!(
            validate(&declaration(), Some(&duplicated), Pass::Claim, NOW, CLAIMED)
                .has(Code::ReservationDuplicate)
        );
    }

    #[test]
    fn a_broader_lease_than_declared_is_rejected() {
        let mut broad = snapshot();
        broad.leases[0].path = "tools/**".to_owned();
        let report = validate(&declaration(), Some(&broad), Pass::Claim, NOW, CLAIMED);
        assert!(report.has(Code::ReservationPathTooBroad));
    }

    #[test]
    fn a_repository_glob_declaration_is_rejected() {
        let mut glob = declaration();
        glob.paths = vec!["**".to_owned()];
        assert!(
            validate(&glob, Some(&snapshot()), Pass::DeclarationOnly, NOW, CLAIMED)
                .has(Code::ReservationPathTooBroad)
        );
    }

    #[test]
    fn declared_and_observed_paths_must_be_the_exact_same_set() {
        // A missing lease.
        let mut two = declaration();
        two.paths.push("evidence/fnd-02/**".to_owned());
        assert!(
            validate(&two, Some(&snapshot()), Pass::Claim, NOW, CLAIMED)
                .has(Code::ReservationDeclarationMismatch)
        );

        // An extra lease nobody declared.
        let mut extra = snapshot();
        let mut second = lease();
        second.lease_id = "L2".to_owned();
        second.path = "crates/fastmcp/**".to_owned();
        extra.leases.push(second);
        assert!(
            validate(&declaration(), Some(&extra), Pass::Claim, NOW, CLAIMED)
                .has(Code::ReservationDeclarationMismatch)
        );
    }

    #[test]
    fn a_non_exclusive_lease_on_an_owned_path_is_rejected() {
        let mut shared = snapshot();
        shared.leases[0].exclusive = false;
        assert!(
            validate(&declaration(), Some(&shared), Pass::Claim, NOW, CLAIMED)
                .has(Code::ReservationDeclarationMismatch)
        );
    }

    #[test]
    fn close_rejects_a_renewal_gap_and_accepts_contiguous_coverage() {
        let mut gapped = snapshot();
        gapped.leases[0].history = vec![
            Renewal { at: CLAIMED - 10, until: CLAIMED + 100 },
            // Reacquired after a lapse.
            Renewal { at: CLAIMED + 500, until: NOW + 7200 },
        ];
        let report = validate(&declaration(), Some(&gapped), Pass::Close, NOW, CLAIMED);
        assert!(report.has(Code::ReservationRenewalGap));

        let mut contiguous = snapshot();
        contiguous.leases[0].history = vec![
            Renewal { at: CLAIMED - 10, until: CLAIMED + 600 },
            Renewal { at: CLAIMED + 500, until: NOW + 7200 },
        ];
        assert!(
            validate(&declaration(), Some(&contiguous), Pass::Close, NOW, CLAIMED).is_clean()
        );
    }

    #[test]
    fn close_rejects_a_history_that_starts_after_the_claim() {
        let mut late = snapshot();
        late.leases[0].history = vec![Renewal { at: CLAIMED + 1, until: NOW + 7200 }];
        assert!(
            validate(&declaration(), Some(&late), Pass::Close, NOW, CLAIMED)
                .has(Code::ReservationRenewalGap)
        );
    }

    #[test]
    fn close_rejects_an_empty_history() {
        let mut empty = snapshot();
        empty.leases[0].history.clear();
        assert!(
            validate(&declaration(), Some(&empty), Pass::Close, NOW, CLAIMED)
                .has(Code::ReservationRenewalGap)
        );
    }

    #[test]
    fn a_wrong_schema_tag_is_rejected() {
        let text = "schema = \"fnd-02-reservation-snapshot-v0\"\nproject_key = \"/r\"\n\
                    agent_name = \"a\"\ngenerated_at = 0\n";
        assert_eq!(parse_snapshot(text, "s").unwrap_err().field, "schema");
    }

    #[test]
    fn path_and_stdin_routes_parse_identically() {
        let text = format!(
            "schema = \"{SNAPSHOT_SCHEMA}\"\nproject_key = \"/repo\"\n\
             agent_name = \"MagentaOsprey\"\ngenerated_at = 10\n\n\
             [[lease]]\nlease_id = \"L1\"\npath = \"p\"\nexclusive = true\n\
             issue_id = \"bd-x\"\nexpires_at = 20\n"
        );
        let from_path = parse_snapshot(&text, "path").expect("parses");
        let from_stdin = parse_snapshot(&text, "-").expect("parses");
        assert_eq!(from_path.project_key, from_stdin.project_key);
        assert_eq!(from_path.leases.len(), from_stdin.leases.len());
        assert_eq!(from_path.leases[0].lease_id, from_stdin.leases[0].lease_id);
    }

    #[test]
    fn breadth_comparison_only_flags_true_supersets() {
        assert!(is_broader("tools/**", "tools/xtask/**"));
        assert!(!is_broader("tools/xtask/**", "tools/xtask/**"));
        assert!(!is_broader("tools/xtask/**", "tools/**"));
        assert!(!is_broader("crates/**", "tools/xtask/**"));
    }
}
