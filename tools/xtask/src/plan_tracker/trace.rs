//! Requirement trace rows.
//!
//! One row maps one observable requirement clause to the implementation and
//! tests that are supposed to demonstrate it. Twelve fields are required on
//! every row; a row with a blank required field is rejected rather than
//! counted, because a row that records nothing observable is indistinguishable
//! from an absent row when a reviewer is counting coverage.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::diagnostics::{Code, Diagnostic, Report};

/// Requirement strength, as written in the authoritative prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    Must,
    MustNot,
    Should,
    May,
}

impl Strength {
    /// Parse the exact uppercase spelling. Case and spacing are not normalized:
    /// `must` is a different string from `MUST` and only the latter appears in
    /// normative prose.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "MUST" => Some(Self::Must),
            "MUST NOT" => Some(Self::MustNot),
            "SHOULD" => Some(Self::Should),
            "MAY" => Some(Self::May),
            _ => None,
        }
    }

    /// MUST and MUST NOT are the strengths that must map to a test or a written
    /// explanation of why they cannot be observed.
    pub const fn is_mandatory(self) -> bool {
        matches!(self, Self::Must | Self::MustNot)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Must => "MUST",
            Self::MustNot => "MUST NOT",
            Self::Should => "SHOULD",
            Self::May => "MAY",
        }
    }
}

/// One requirement trace row, exactly as checked in.
///
/// Field order here is the canonical field order; the manifest renders rows
/// through a typed struct so serialization follows declaration order rather
/// than the alphabetical ordering a dynamic map would impose.
#[derive(Debug, Clone, Deserialize)]
pub struct TraceRow {
    /// Unique key for the clause, keyed by final SEP or specification heading.
    pub clause_key: String,
    /// MUST, MUST NOT, SHOULD, or MAY.
    pub strength: String,
    /// Observable client behavior.
    pub client_behavior: String,
    /// Observable server behavior.
    pub server_behavior: String,
    /// Transport applicability.
    pub transport_applicability: String,
    /// Owning work package.
    pub owner: String,
    /// Positive test identifier.
    pub positive_test_id: String,
    /// Negative test identifier.
    pub negative_test_id: String,
    /// Official conformance scenario/check identifier, or the explicit
    /// `none` sentinel when upstream declares no check for this clause.
    pub scenario_check_id: String,
    /// Exact immutable source revision this clause is inherited from.
    pub source_revision: String,
    /// Set when the clause is prose that cannot be observed on the wire.
    pub unobservable_prose: bool,
    /// Upstream ambiguity, tracked explicitly rather than hidden in a code
    /// comment. `none` when the clause is unambiguous.
    pub ambiguity: String,
    /// Authoritative corpus item this row covers.
    pub covers_item: String,
}

/// The number of fields the evaluator observes on every row.
pub const OBSERVED_FIELDS_PER_ROW: usize = 13;

/// FND-02 A item 3 fixes the floor at twelve observed fields per row.
/// A build that lowers the constant below it must not compile.
const _: () = assert!(OBSERVED_FIELDS_PER_ROW >= 12);

/// The explicit sentinel for "upstream declares no conformance check here".
/// An empty string is a missing field; `none` is a recorded decision.
pub const NONE_SENTINEL: &str = "none";

impl TraceRow {
    /// Every required field, paired with its name, in canonical order.
    pub fn required_fields(&self) -> [(&'static str, &str); 10] {
        [
            ("clause_key", &self.clause_key),
            ("strength", &self.strength),
            ("client_behavior", &self.client_behavior),
            ("server_behavior", &self.server_behavior),
            ("transport_applicability", &self.transport_applicability),
            ("owner", &self.owner),
            ("positive_test_id", &self.positive_test_id),
            ("negative_test_id", &self.negative_test_id),
            ("scenario_check_id", &self.scenario_check_id),
            ("source_revision", &self.source_revision),
        ]
    }

    /// Count of observed fields. Constant by construction, but returned from
    /// the value so the cardinality assertion measures the row rather than
    /// restating the constant.
    pub fn observed_field_count(&self) -> usize {
        self.required_fields().len()
            + 1 // unobservable_prose
            + 1 // ambiguity
            + 1 // covers_item
    }

    pub fn strength(&self) -> Option<Strength> {
        Strength::parse(&self.strength)
    }
}

/// The checked-in trace table.
#[derive(Debug, Clone, Deserialize)]
pub struct TraceTable {
    pub schema: String,
    #[serde(default, rename = "row")]
    pub rows: Vec<TraceRow>,
}

pub const TRACE_TABLE_SCHEMA: &str = "fnd-02-trace-table-v1";

/// Parse the trace table. The schema tag must match exactly.
pub fn parse_table(text: &str, subject: &str) -> Result<TraceTable, Diagnostic> {
    let table: TraceTable = toml::from_str(text)
        .map_err(|error| Diagnostic::new(Code::SchemaInvalid, subject, "toml", error.to_string()))?;
    if table.schema != TRACE_TABLE_SCHEMA {
        return Err(Diagnostic::new(
            Code::SchemaInvalid,
            subject,
            "schema",
            format!("expected {TRACE_TABLE_SCHEMA}, observed {}", table.schema),
        ));
    }
    Ok(table)
}

/// FND-02-A-01, first half: every row carries a complete required-field set
/// and a recognized strength.
///
/// A zero-row table is rejected outright. A checker that reports success over
/// an empty input is the single most dangerous shape here: it is green, it is
/// fast, and it proves nothing.
pub fn check_row_completeness(table: &TraceTable) -> Report {
    let mut report = Report::new();

    if table.rows.is_empty() {
        report.push(Diagnostic::new(
            Code::TraceTableEmpty,
            "trace-table",
            "row",
            "the trace table declares zero rows; a zero-row pass is a failure",
        ));
        return report;
    }

    for row in &table.rows {
        let subject = if row.clause_key.is_empty() {
            "<unkeyed-row>"
        } else {
            row.clause_key.as_str()
        };

        for (name, value) in row.required_fields() {
            if value.trim().is_empty() {
                report.push(Diagnostic::new(
                    Code::TraceRowFieldEmpty,
                    subject,
                    name,
                    "required field is empty",
                ));
            }
        }

        if row.ambiguity.trim().is_empty() {
            report.push(Diagnostic::new(
                Code::TraceRowFieldEmpty,
                subject,
                "ambiguity",
                "required field is empty; use the explicit none sentinel",
            ));
        }
        if row.covers_item.trim().is_empty() {
            report.push(Diagnostic::new(
                Code::TraceRowFieldEmpty,
                subject,
                "covers_item",
                "required field is empty",
            ));
        }

        match row.strength() {
            None => report.push(Diagnostic::new(
                Code::TraceRowStrengthInvalid,
                subject,
                "strength",
                format!("unrecognized strength {:?}", row.strength),
            )),
            Some(strength) => {
                // An observable mandatory clause must name real tests. The
                // escape hatch is to mark the clause unobservable, in writing,
                // which is a recorded decision rather than a silent omission.
                if strength.is_mandatory()
                    && !row.unobservable_prose
                    && (row.positive_test_id == NONE_SENTINEL
                        || row.negative_test_id == NONE_SENTINEL)
                {
                    report.push(Diagnostic::new(
                        Code::TraceRowFieldEmpty,
                        subject,
                        "positive_test_id",
                        "an observable MUST/MUST NOT clause must name both tests \
                         or be marked unobservable_prose",
                    ));
                }
            }
        }
    }

    report
}

/// FND-02-A-02: clause keys are unique.
pub fn check_duplicate_keys(table: &TraceTable) -> Report {
    let mut report = Report::new();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for row in &table.rows {
        *counts.entry(row.clause_key.as_str()).or_default() += 1;
    }
    for (key, count) in counts {
        if count > 1 {
            report.push(Diagnostic::new(
                Code::TraceRowDuplicateKey,
                key,
                "clause_key",
                format!("clause key appears {count} times"),
            ));
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(clause_key: &str) -> TraceRow {
        TraceRow {
            clause_key: clause_key.to_owned(),
            strength: "MUST".to_owned(),
            client_behavior: "c".to_owned(),
            server_behavior: "s".to_owned(),
            transport_applicability: "all".to_owned(),
            owner: "FND-02".to_owned(),
            positive_test_id: "p".to_owned(),
            negative_test_id: "n".to_owned(),
            scenario_check_id: NONE_SENTINEL.to_owned(),
            source_revision: "core_2026_git:5f5440bb".to_owned(),
            unobservable_prose: false,
            ambiguity: NONE_SENTINEL.to_owned(),
            covers_item: "core-changelog/major/1".to_owned(),
        }
    }

    #[test]
    fn strength_parses_only_exact_normative_spellings() {
        assert_eq!(Strength::parse("MUST"), Some(Strength::Must));
        assert_eq!(Strength::parse("MUST NOT"), Some(Strength::MustNot));
        assert_eq!(Strength::parse("SHOULD"), Some(Strength::Should));
        assert_eq!(Strength::parse("MAY"), Some(Strength::May));
        for rejected in ["must", "Must", "MUSTNOT", "MUST  NOT", "SHALL", ""] {
            assert_eq!(Strength::parse(rejected), None, "{rejected:?}");
        }
    }

    #[test]
    fn mandatory_strengths_are_exactly_must_and_must_not() {
        assert!(Strength::Must.is_mandatory());
        assert!(Strength::MustNot.is_mandatory());
        assert!(!Strength::Should.is_mandatory());
        assert!(!Strength::May.is_mandatory());
    }

    /// The AC floor is checked at COMPILE time, not here.
    ///
    /// `OBSERVED_FIELDS_PER_ROW >= 12` is evaluatable by the compiler, so as a
    /// runtime `assert!` it was reachable only by running the test -- and
    /// clippy flagged it as constant. Lowering the constant should not produce
    /// a test failure, it should produce a BUILD failure: the floor is a
    /// declared design limit, not a measurement. Moved to a `const` assertion
    /// beside the constant itself, where the next person to edit it is looking.
    /// What remains here is the real runtime claim -- that an actual row
    /// produces exactly that many observed fields.
    #[test]
    fn a_complete_row_observes_the_declared_field_cardinality() {
        assert_eq!(row("k").observed_field_count(), OBSERVED_FIELDS_PER_ROW);
    }

    #[test]
    fn a_complete_table_passes_completeness() {
        let table = TraceTable {
            schema: TRACE_TABLE_SCHEMA.to_owned(),
            rows: vec![row("a"), row("b")],
        };
        assert!(check_row_completeness(&table).is_clean());
    }

    #[test]
    fn an_empty_table_is_rejected() {
        let table = TraceTable {
            schema: TRACE_TABLE_SCHEMA.to_owned(),
            rows: Vec::new(),
        };
        let report = check_row_completeness(&table);
        assert_eq!(report.codes(), vec![Code::TraceTableEmpty]);
    }

    #[test]
    fn a_blank_required_field_is_rejected_and_names_that_field() {
        let mut blank = row("a");
        blank.server_behavior = "   ".to_owned();
        let table = TraceTable {
            schema: TRACE_TABLE_SCHEMA.to_owned(),
            rows: vec![blank],
        };
        let report = check_row_completeness(&table);
        assert_eq!(report.codes(), vec![Code::TraceRowFieldEmpty]);
        assert_eq!(report.diagnostics()[0].field, "server_behavior");
    }

    #[test]
    fn an_unrecognized_strength_is_rejected() {
        let mut bad = row("a");
        bad.strength = "SHALL".to_owned();
        let table = TraceTable {
            schema: TRACE_TABLE_SCHEMA.to_owned(),
            rows: vec![bad],
        };
        assert!(check_row_completeness(&table).has(Code::TraceRowStrengthInvalid));
    }

    #[test]
    fn a_mandatory_clause_may_not_drop_its_tests_without_declaring_itself_unobservable() {
        let mut untested = row("a");
        untested.positive_test_id = NONE_SENTINEL.to_owned();
        let table = TraceTable {
            schema: TRACE_TABLE_SCHEMA.to_owned(),
            rows: vec![untested.clone()],
        };
        assert!(check_row_completeness(&table).has(Code::TraceRowFieldEmpty));

        // The same row, explicitly marked unobservable, is accepted.
        let mut declared = untested;
        declared.unobservable_prose = true;
        let table = TraceTable {
            schema: TRACE_TABLE_SCHEMA.to_owned(),
            rows: vec![declared],
        };
        assert!(check_row_completeness(&table).is_clean());
    }

    #[test]
    fn duplicate_clause_keys_are_rejected_and_unique_ones_are_not() {
        let unique = TraceTable {
            schema: TRACE_TABLE_SCHEMA.to_owned(),
            rows: vec![row("a"), row("b")],
        };
        assert!(check_duplicate_keys(&unique).is_clean());

        let duplicated = TraceTable {
            schema: TRACE_TABLE_SCHEMA.to_owned(),
            rows: vec![row("a"), row("a")],
        };
        let report = check_duplicate_keys(&duplicated);
        assert_eq!(report.codes(), vec![Code::TraceRowDuplicateKey]);
        assert_eq!(report.diagnostics()[0].subject, "a");
    }
}
