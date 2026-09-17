//! Stable typed diagnostics.
//!
//! Every rejection names the exact field that failed. A catch-all diagnostic
//! is worthless for drift detection: it tells you something moved without
//! telling you what, which is how a stale binding survives a review.

use std::fmt;

/// Stable machine-readable diagnostic code.
///
/// These strings are part of the checker's contract. A planted mutation is
/// expected to produce one exact code, so renaming one is a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Code {
    /// An authoritative source file's Git blob identity no longer matches the
    /// identity recorded in the binding. This is the drift detector.
    SourceBlobDrift,
    /// A declared authoritative source file is missing or unreadable.
    SourceUnreadable,
    /// An input file could not be parsed under its declared schema.
    SchemaInvalid,
    /// A trace row left a required field empty.
    TraceRowFieldEmpty,
    /// Two trace rows share one clause key.
    TraceRowDuplicateKey,
    /// A trace row declares a strength outside MUST/MUST NOT/SHOULD/MAY.
    TraceRowStrengthInvalid,
    /// An observable requirement item in the authoritative corpus has no row.
    TraceCoverageMissing,
    /// A trace row claims an item that the authoritative corpus does not contain.
    TraceCoverageExtra,
    /// The trace table contains zero rows. A zero-row green is red.
    TraceTableEmpty,
    /// A trace row cites a conformance scenario or check that the frozen
    /// inventory does not declare.
    ConformanceReferenceStale,
    /// An authorization row cites a floating specification instead of an
    /// exact immutable revision.
    AuthRevisionFloating,
    /// An authorization row cites an exact revision that is not the one the
    /// dated core page actually links.
    AuthRevisionWrong,
    /// The plan exceeds a declared parser limit.
    PlanLimitExceeded,
    /// The plan bytes are not admissible: bare CR, BOM, NUL, or invalid UTF-8.
    PlanEncodingInvalid,
    /// The canonical region boundary headings were not found outside a fence.
    PlanRegionMissing,
    /// A fence opened inside the region and never closed.
    PlanFenceUnclosed,
    /// A package heading does not match the exact structural grammar.
    PackageHeadingInvalid,
    /// A package identifier does not match the ASCII grammar.
    PackageIdInvalid,
    /// Two packages share one identifier.
    PackageDuplicate,
    /// A canonical package body exceeds the declared limit.
    PackageBodyTooLarge,
    /// The `Dependencies:` section is missing, duplicated, or malformed.
    DependencySectionInvalid,
    /// A dependency bullet does not match the exact bullet grammar.
    DependencyBulletInvalid,
    /// A dependency list mixes the `- None.` sentinel with identifiers.
    DependencyMixedSentinel,
    /// A dependency names a package the corpus does not define.
    DependencyUnresolved,
    /// A package depends on itself.
    DependencySelfEdge,
    /// One dependency edge is declared twice.
    DependencyDuplicate,
    /// Text between packages that is neither blank, a separator, nor a
    /// level-one or level-two structural heading.
    InterstitialProse,
    /// A v2 byte stream has a wrong magic, version, count, length, or order,
    /// is truncated, or carries trailing bytes.
    StreamMalformed,
    /// A canonical re-encode of a decoded stream is not byte-identical.
    StreamReencodeMismatch,
    /// A pass that requires a reservation snapshot did not get one.
    ReservationSnapshotMissing,
    /// The snapshot is older than the freshness window, or future-dated.
    ReservationSnapshotStale,
    /// The snapshot names a different project.
    ReservationWrongProject,
    /// The snapshot names a different agent.
    ReservationWrongAgent,
    /// A lease was taken for a different issue.
    ReservationWrongIssue,
    /// A lease has already expired.
    ReservationExpired,
    /// A claim-time lease has too little remaining time to cover the work.
    ReservationInsufficientRemaining,
    /// One lease id or path appears twice.
    ReservationDuplicate,
    /// A lease covers more than the declaration asked for.
    ReservationPathTooBroad,
    /// Declared and observed reservation sets are not equal.
    ReservationDeclarationMismatch,
    /// Lease coverage lapsed between claim and close.
    ReservationRenewalGap,
    /// Plan package identifiers and tracker labels are not the same set.
    PackageLabelMapping,
    /// A workspace membership, publish, alias, or unsafe-code invariant fails.
    WorkspacePolicy,
    /// The checker is not decomposed into bounded, independently tested modules.
    ModuleInventory,
}

impl Code {
    /// The stable wire string for this code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceBlobDrift => "E_FND02_SOURCE_BLOB_DRIFT",
            Self::SourceUnreadable => "E_FND02_SOURCE_UNREADABLE",
            Self::SchemaInvalid => "E_FND02_SCHEMA_INVALID",
            Self::TraceRowFieldEmpty => "E_FND02_TRACE_ROW_FIELD_EMPTY",
            Self::TraceRowDuplicateKey => "E_FND02_TRACE_ROW_DUPLICATE_KEY",
            Self::TraceRowStrengthInvalid => "E_FND02_TRACE_ROW_STRENGTH_INVALID",
            Self::TraceCoverageMissing => "E_FND02_TRACE_COVERAGE_MISSING",
            Self::TraceCoverageExtra => "E_FND02_TRACE_COVERAGE_EXTRA",
            Self::TraceTableEmpty => "E_FND02_TRACE_TABLE_EMPTY",
            Self::ConformanceReferenceStale => "E_FND02_CONFORMANCE_REFERENCE_STALE",
            Self::AuthRevisionFloating => "E_FND02_AUTH_REVISION_FLOATING",
            Self::AuthRevisionWrong => "E_FND02_AUTH_REVISION_WRONG",
            Self::PlanLimitExceeded => "E_FND02_PLAN_LIMIT_EXCEEDED",
            Self::PlanEncodingInvalid => "E_FND02_PLAN_ENCODING_INVALID",
            Self::PlanRegionMissing => "E_FND02_PLAN_REGION_MISSING",
            Self::PlanFenceUnclosed => "E_FND02_PLAN_FENCE_UNCLOSED",
            Self::PackageHeadingInvalid => "E_FND02_PACKAGE_HEADING_INVALID",
            Self::PackageIdInvalid => "E_FND02_PACKAGE_ID_INVALID",
            Self::PackageDuplicate => "E_FND02_PACKAGE_DUPLICATE",
            Self::PackageBodyTooLarge => "E_FND02_PACKAGE_BODY_TOO_LARGE",
            Self::DependencySectionInvalid => "E_FND02_DEPENDENCY_SECTION_INVALID",
            Self::DependencyBulletInvalid => "E_FND02_DEPENDENCY_BULLET_INVALID",
            Self::DependencyMixedSentinel => "E_FND02_DEPENDENCY_MIXED_SENTINEL",
            Self::DependencyUnresolved => "E_FND02_DEPENDENCY_UNRESOLVED",
            Self::DependencySelfEdge => "E_FND02_DEPENDENCY_SELF_EDGE",
            Self::DependencyDuplicate => "E_FND02_DEPENDENCY_DUPLICATE",
            Self::InterstitialProse => "E_FND02_INTERSTITIAL_PROSE",
            Self::StreamMalformed => "E_FND02_STREAM_MALFORMED",
            Self::StreamReencodeMismatch => "E_FND02_STREAM_REENCODE_MISMATCH",
            Self::ReservationSnapshotMissing => "E_FND02_RESERVATION_SNAPSHOT_MISSING",
            Self::ReservationSnapshotStale => "E_FND02_RESERVATION_SNAPSHOT_STALE",
            Self::ReservationWrongProject => "E_FND02_RESERVATION_WRONG_PROJECT",
            Self::ReservationWrongAgent => "E_FND02_RESERVATION_WRONG_AGENT",
            Self::ReservationWrongIssue => "E_FND02_RESERVATION_WRONG_ISSUE",
            Self::ReservationExpired => "E_FND02_RESERVATION_EXPIRED",
            Self::ReservationInsufficientRemaining => "E_FND02_RESERVATION_INSUFFICIENT_REMAINING",
            Self::ReservationDuplicate => "E_FND02_RESERVATION_DUPLICATE",
            Self::ReservationPathTooBroad => "E_FND02_RESERVATION_PATH_TOO_BROAD",
            Self::ReservationDeclarationMismatch => "E_FND02_RESERVATION_DECLARATION_MISMATCH",
            Self::ReservationRenewalGap => "E_FND02_RESERVATION_RENEWAL_GAP",
            Self::PackageLabelMapping => "E_FND02_PACKAGE_LABEL_MAPPING",
            Self::WorkspacePolicy => "E_FND02_WORKSPACE_POLICY",
            Self::ModuleInventory => "E_FND02_MODULE_INVENTORY",
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One rejection, naming its code, its subject, and the exact field at fault.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Diagnostic {
    pub code: Code,
    pub subject: String,
    pub field: String,
    pub detail: String,
}

impl Diagnostic {
    pub fn new(
        code: Code,
        subject: impl Into<String>,
        field: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            code,
            subject: subject.into(),
            field: field.into(),
            detail: detail.into(),
        }
    }

    /// Deterministic single-line rendering for machine consumption.
    pub fn render(&self) -> String {
        format!(
            "{} subject={} field={} detail={}",
            self.code, self.subject, self.field, self.detail
        )
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// Result of one check: either clean, or a sorted, deduplicated rejection set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    diagnostics: Vec<Diagnostic>,
}

impl Report {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, diagnostic: Diagnostic) {
        self.diagnostics.push(diagnostic);
    }

    pub fn extend(&mut self, other: Report) {
        self.diagnostics.extend(other.diagnostics);
    }

    pub fn is_clean(&self) -> bool {
        self.diagnostics.is_empty()
    }

    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// True when at least one diagnostic carries `code`.
    pub fn has(&self, code: Code) -> bool {
        self.diagnostics.iter().any(|d| d.code == code)
    }

    /// Every distinct code present, ascending. Used to assert that a
    /// one-variable mutation produces exactly the expected diagnostic and
    /// nothing else.
    pub fn codes(&self) -> Vec<Code> {
        let mut codes: Vec<Code> = self.diagnostics.iter().map(|d| d.code).collect();
        codes.sort_unstable();
        codes.dedup();
        codes
    }

    /// Sort and deduplicate so the rendering is order-independent.
    pub fn canonicalize(&mut self) {
        self.diagnostics.sort();
        self.diagnostics.dedup();
    }

    pub fn render(&self) -> String {
        let mut sorted = self.clone();
        sorted.canonicalize();
        sorted
            .diagnostics
            .iter()
            .map(Diagnostic::render)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_distinct_and_stable() {
        let all = [
            Code::SourceBlobDrift,
            Code::SourceUnreadable,
            Code::SchemaInvalid,
            Code::TraceRowFieldEmpty,
            Code::TraceRowDuplicateKey,
            Code::TraceRowStrengthInvalid,
            Code::TraceCoverageMissing,
            Code::TraceCoverageExtra,
            Code::TraceTableEmpty,
            Code::ConformanceReferenceStale,
            Code::AuthRevisionFloating,
            Code::AuthRevisionWrong,
            Code::PlanLimitExceeded,
            Code::PlanEncodingInvalid,
            Code::PlanRegionMissing,
            Code::PlanFenceUnclosed,
            Code::PackageHeadingInvalid,
            Code::PackageIdInvalid,
            Code::PackageDuplicate,
            Code::PackageBodyTooLarge,
            Code::DependencySectionInvalid,
            Code::DependencyBulletInvalid,
            Code::DependencyMixedSentinel,
            Code::DependencyUnresolved,
            Code::DependencySelfEdge,
            Code::DependencyDuplicate,
            Code::InterstitialProse,
            Code::StreamMalformed,
            Code::StreamReencodeMismatch,
            Code::ReservationSnapshotMissing,
            Code::ReservationSnapshotStale,
            Code::ReservationWrongProject,
            Code::ReservationWrongAgent,
            Code::ReservationWrongIssue,
            Code::ReservationExpired,
            Code::ReservationInsufficientRemaining,
            Code::ReservationDuplicate,
            Code::ReservationPathTooBroad,
            Code::ReservationDeclarationMismatch,
            Code::ReservationRenewalGap,
            Code::PackageLabelMapping,
            Code::WorkspacePolicy,
            Code::ModuleInventory,
        ];
        let mut rendered: Vec<&str> = all.iter().map(|c| c.as_str()).collect();
        let count = rendered.len();
        rendered.sort_unstable();
        rendered.dedup();
        assert_eq!(rendered.len(), count, "diagnostic codes must be distinct");
        assert!(all.iter().all(|c| c.as_str().starts_with("E_FND02_")));
    }

    #[test]
    fn empty_report_is_clean_and_populated_report_is_not() {
        let mut report = Report::new();
        assert!(report.is_clean());
        report.push(Diagnostic::new(Code::TraceTableEmpty, "s", "f", "d"));
        assert!(!report.is_clean());
        assert_eq!(report.codes(), vec![Code::TraceTableEmpty]);
    }

    #[test]
    fn rendering_is_order_independent() {
        let a = Diagnostic::new(Code::SourceBlobDrift, "a", "f", "d");
        let b = Diagnostic::new(Code::TraceTableEmpty, "b", "f", "d");
        let mut first = Report::new();
        first.push(a.clone());
        first.push(b.clone());
        let mut second = Report::new();
        second.push(b);
        second.push(a);
        assert_eq!(first.render(), second.render());
    }
}
