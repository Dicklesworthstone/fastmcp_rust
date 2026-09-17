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
