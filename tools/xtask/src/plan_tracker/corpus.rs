//! The authoritative requirement corpus.
//!
//! The required coverage set is *derived from the authoritative sources*, not
//! hand-authored. A frozen count is a measurement of mutable content, and
//! measurements rot: if the changelog gains an item and the required set is a
//! literal `21`, the gate stays green while coverage silently falls behind.
//! Parsing the corpus means the required set moves when upstream moves, and a
//! row that no longer corresponds to anything is reported too.

use std::collections::BTreeSet;

use super::diagnostics::{Code, Diagnostic, Report};
use super::trace::TraceTable;

/// An item in the authoritative corpus that trace rows must cover.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CorpusItem {
    /// Stable key, e.g. `core-changelog/major/3`.
    pub key: String,
    /// First line of the item's text, for diagnostics.
    pub summary: String,
}

/// Extract the numbered changelog items under the `## Major changes` and
/// `## Minor changes` headings.
///
/// The document is MDX. Items are top-level ordered-list entries beginning in
/// column zero as `<n>. `; continuation lines are indented and are folded into
/// the preceding item rather than starting a new one. A heading at any level
/// ends the current section, so an item can never leak across a section
/// boundary and be counted under the wrong key.
pub fn changelog_items(text: &str) -> Vec<CorpusItem> {
    let mut items = Vec::new();
    let mut section: Option<&'static str> = None;

    for line in text.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            section = match heading.trim() {
                "Major changes" => Some("major"),
                "Minor changes" => Some("minor"),
                _ => None,
            };
            continue;
        }
        // Any other heading level also closes the section.
        if line.starts_with('#') {
            section = None;
            continue;
        }

        let Some(section_name) = section else {
            continue;
        };

        // A top-level ordered item starts in column zero.
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        let Some((ordinal_text, rest)) = line.split_once(". ") else {
            continue;
        };
        if ordinal_text.is_empty() || !ordinal_text.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(ordinal) = ordinal_text.parse::<u32>() else {
            continue;
        };

        items.push(CorpusItem {
            key: format!("core-changelog/{section_name}/{ordinal}"),
            summary: rest.chars().take(96).collect(),
        });
    }

    items
}

/// Required coverage items derived from the frozen conformance inventory.
///
/// Without these, subcase A-03 would pass over a table in which no row cites
/// a conformance check at all -- green because there was nothing to check.
/// Requiring one row per upstream scenario forces at least one live citation
/// through the stale-reference rule on every run.
pub fn conformance_items(scenario_ids: &[&str]) -> Vec<CorpusItem> {
    scenario_ids
        .iter()
        .map(|id| CorpusItem {
            key: format!("conformance-scenario/{id}"),
            summary: format!("frozen upstream conformance scenario {id}"),
        })
        .collect()
}

/// FND-02-A-01, second half: exact-set coverage.
///
/// Required set == observed set. A subset that passes is a failure, so both
/// directions are reported: an authoritative item with no row, and a row
/// claiming an item the corpus does not contain.
pub fn check_coverage(required: &[CorpusItem], table: &TraceTable) -> Report {
    let mut report = Report::new();

    if required.is_empty() {
        report.push(Diagnostic::new(
            Code::TraceCoverageMissing,
            "corpus",
            "required",
            "the authoritative corpus yielded zero required items; \
             a zero-item required set cannot certify coverage",
        ));
        return report;
    }

    let required_keys: BTreeSet<&str> = required.iter().map(|item| item.key.as_str()).collect();
    let observed_keys: BTreeSet<&str> = table
        .rows
        .iter()
        .map(|row| row.covers_item.as_str())
        .collect();

    for item in required {
        if !observed_keys.contains(item.key.as_str()) {
            report.push(Diagnostic::new(
                Code::TraceCoverageMissing,
                &item.key,
                "covers_item",
                format!("no trace row covers this item: {}", item.summary),
            ));
        }
    }

    for observed in &observed_keys {
        if !required_keys.contains(observed) {
            report.push(Diagnostic::new(
                Code::TraceCoverageExtra,
                *observed,
                "covers_item",
                "a trace row claims an item the authoritative corpus does not contain",
            ));
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::trace::{TRACE_TABLE_SCHEMA, TraceRow, TraceTable};

    const SAMPLE: &str = "\
---
title: Key Changes
---

## Major changes

1. Remove protocol-level sessions.

2. Make MCP stateless: remove the handshake.
   This continuation line belongs to item 2.

## Minor changes

1. Add `extensions` field.
2. Document OpenTelemetry trace context.

## Deprecated

1. This item is in a section we do not track.
";

    #[test]
    fn changelog_extraction_keys_items_by_section_and_ordinal() {
        let items = changelog_items(SAMPLE);
        let keys: Vec<&str> = items.iter().map(|i| i.key.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "core-changelog/major/1",
                "core-changelog/major/2",
                "core-changelog/minor/1",
                "core-changelog/minor/2",
            ]
        );
    }

    #[test]
    fn a_continuation_line_does_not_become_its_own_item() {
        let items = changelog_items(SAMPLE);
        assert_eq!(items.len(), 4);
        assert!(items[1].summary.starts_with("Make MCP stateless"));
    }

    #[test]
    fn an_untracked_section_contributes_no_items() {
        assert!(
            !changelog_items(SAMPLE)
                .iter()
                .any(|i| i.summary.contains("section we do not track"))
        );
    }

    fn covering_row(item: &str) -> TraceRow {
        TraceRow {
            clause_key: format!("clause/{item}"),
            strength: "MUST".to_owned(),
            client_behavior: "c".to_owned(),
            server_behavior: "s".to_owned(),
            transport_applicability: "all".to_owned(),
            owner: "FND-02".to_owned(),
            positive_test_id: "p".to_owned(),
            negative_test_id: "n".to_owned(),
            scenario_check_id: "none".to_owned(),
            source_revision: "r".to_owned(),
            unobservable_prose: false,
            ambiguity: "none".to_owned(),
            covers_item: item.to_owned(),
        }
    }

    fn table(items: &[&str]) -> TraceTable {
        TraceTable {
            schema: TRACE_TABLE_SCHEMA.to_owned(),
            rows: items.iter().map(|i| covering_row(i)).collect(),
        }
    }

    #[test]
    fn exact_coverage_passes() {
        let required = changelog_items(SAMPLE);
        let observed = table(&[
            "core-changelog/major/1",
            "core-changelog/major/2",
            "core-changelog/minor/1",
            "core-changelog/minor/2",
        ]);
        assert!(check_coverage(&required, &observed).is_clean());
    }

    #[test]
    fn a_subset_is_a_failure_not_a_pass() {
        let required = changelog_items(SAMPLE);
        let observed = table(&["core-changelog/major/1"]);
        let report = check_coverage(&required, &observed);
        assert_eq!(report.codes(), vec![Code::TraceCoverageMissing]);
        assert_eq!(report.diagnostics().len(), 3);
    }

    #[test]
    fn a_row_covering_a_nonexistent_item_is_a_failure() {
        let required = changelog_items(SAMPLE);
        let observed = table(&[
            "core-changelog/major/1",
            "core-changelog/major/2",
            "core-changelog/minor/1",
            "core-changelog/minor/2",
            "core-changelog/major/99",
        ]);
        let report = check_coverage(&required, &observed);
        assert_eq!(report.codes(), vec![Code::TraceCoverageExtra]);
    }

    #[test]
    fn an_empty_required_set_is_rejected() {
        let report = check_coverage(&[], &table(&[]));
        assert_eq!(report.codes(), vec![Code::TraceCoverageMissing]);
    }
}
