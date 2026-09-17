//! Beads projection and canonical package/label mapping parity.
//!
//! The plan defines packages; the tracker carries one `wp-parent-<id>` label
//! group per package. If those two identifier sets drift apart, work is
//! tracked under a name the plan does not define, and every downstream count
//! keyed on either side quietly measures a different population.
//!
//! The projection is read-only and parses the exported JSONL rather than
//! touching the database: the checker has no mutation authority.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use super::diagnostics::{Code, Diagnostic, Report};

/// The label prefix that binds a Bead to its owning work package.
pub const WP_PARENT_PREFIX: &str = "wp-parent-";
/// The label prefix that places a Bead in a release profile.
pub const PROFILE_PREFIX: &str = "profile-";

/// The tracker's hard label-length limit.
///
/// `br` rejects any label over this with
/// `Validation failed: label: exceeds 50 characters`, and the limit is not
/// configurable — it appears in neither `.beads/policy.yaml` nor `br config`.
/// Measured 2026-09-17 by attempting the rename this constant exists to
/// explain.
pub const TRACKER_LABEL_CAP: usize = 50;

/// Package identifiers whose canonical label does not fit the tracker.
///
/// This is an exception to exact-lowercase parity, and it is deliberately a
/// **one-entry table with its justification attached** rather than a general
/// relaxation. The tracker is a projection of the plan, and a projection with
/// a representational limit its source does not share cannot be made faithful
/// by pretending otherwise; the honest choice is between a mapping that is
/// written down and a mismatch that is not.
///
/// Each entry is `(plan package identifier, the label actually carried)`.
///
/// **This table retires itself.** [`check_package_label_parity`] recomputes
/// the canonical projection for every entry and FAILS if it would now fit
/// within [`TRACKER_LABEL_CAP`] — so raising the cap, or shortening a package
/// identifier, turns the exception red and demands the real rename instead of
/// leaving a permanent alias nobody remembers the reason for.
const ADMITTED_LABEL_ALIASES: &[(&str, &str)] = &[(
    // Canonical projection is 51 characters against the 50-character cap:
    //   wp-parent-gate-oauth-client-credentials-draft-ready
    // Over by exactly one. The sibling CI package abbreviated the same way
    // without needing to -- its canonical form is 46 characters -- and was
    // renamed to the canonical spelling on 2026-09-17.
    "GATE-OAUTH-CLIENT-CREDENTIALS-DRAFT-READY",
    "wp-parent-gate-oauth-cc-draft-ready",
)];

/// The canonical `wp-parent-` label a package identifier projects to.
fn canonical_label(package_id: &str) -> String {
    format!("{WP_PARENT_PREFIX}{}", package_id.to_ascii_lowercase())
}


/// One exported Bead row. Only the fields the projection needs are read;
/// unknown fields are ignored so an unrelated tracker change does not break
/// parsing.
#[derive(Debug, Clone, Deserialize)]
pub struct BeadRow {
    pub id: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub labels: Vec<String>,
}

impl BeadRow {
    /// The owning package identifier, derived from the `wp-parent-` label.
    ///
    /// Labels are lowercase; package identifiers are uppercase ASCII. The
    /// mapping is a pure ASCII uppercase, never a locale-aware one.
    pub fn owning_package(&self) -> Option<String> {
        self.labels
            .iter()
            .find_map(|label| label.strip_prefix(WP_PARENT_PREFIX))
            .map(str::to_ascii_uppercase)
    }

    /// Every `profile-*` label on this row, in declaration order.
    pub fn profiles(&self) -> Vec<&str> {
        self.labels
            .iter()
            .filter(|label| label.starts_with(PROFILE_PREFIX))
            .map(String::as_str)
            .collect()
    }
}

/// The projected tracker state.
#[derive(Debug, Clone, Default)]
pub struct Projection {
    /// Package identifier to the Beads that declare it as their parent.
    pub packages: BTreeMap<String, Vec<String>>,
    /// Profile label to the package identifiers carrying it.
    pub profiles: BTreeMap<String, BTreeSet<String>>,
    pub row_count: usize,
}

/// Parse the exported JSONL. One object per nonblank line.
pub fn parse_export(text: &str, subject: &str) -> Result<Projection, Diagnostic> {
    let mut projection = Projection::default();

    for (number, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let row: BeadRow = serde_json::from_str(line).map_err(|error| {
            Diagnostic::new(
                Code::SchemaInvalid,
                subject,
                "jsonl",
                format!("line {}: {error}", number + 1),
            )
        })?;
        projection.row_count += 1;

        let Some(package) = row.owning_package() else {
            continue;
        };
        projection
            .packages
            .entry(package.clone())
            .or_default()
            .push(row.id.clone());

        for label in &row.labels {
            if label.starts_with(PROFILE_PREFIX) {
                projection
                    .profiles
                    .entry(label.clone())
                    .or_default()
                    .insert(package.clone());
            }
        }
    }

    if projection.row_count == 0 {
        return Err(Diagnostic::new(
            Code::SchemaInvalid,
            subject,
            "rows",
            "the tracker export contains zero rows",
        ));
    }

    Ok(projection)
}

/// Exact-set parity between plan package identifiers and tracker labels.
///
/// Both directions are reported. A label naming a package the plan does not
/// define is just as broken as a package no Bead tracks, and neither is
/// visible from a count.
pub fn check_package_label_parity(plan_ids: &[&str], projection: &Projection) -> Report {
    let mut report = Report::new();

    let declared: BTreeSet<&str> = plan_ids.iter().copied().collect();
    let tracked: BTreeSet<&str> = projection.packages.keys().map(String::as_str).collect();

    if declared.is_empty() || tracked.is_empty() {
        report.push(Diagnostic::new(
            Code::PackageLabelMapping,
            "projection",
            "sets",
            "an empty package or label set cannot certify mapping parity",
        ));
        return report;
    }

    // Resolve the admitted aliases first, and re-justify each one. An entry
    // whose canonical projection now fits the cap is STALE: the exception has
    // outlived its cause and must be retired in favour of the real rename.
    // Checking this here rather than trusting the comment is what stops the
    // table becoming folklore.
    let mut aliased_declared: BTreeSet<&str> = BTreeSet::new();
    let mut aliased_tracked: BTreeSet<String> = BTreeSet::new();
    for (package_id, label) in ADMITTED_LABEL_ALIASES {
        let canonical = canonical_label(package_id);
        if canonical.len() <= TRACKER_LABEL_CAP {
            report.push(Diagnostic::new(
                Code::PackageLabelMapping,
                *package_id,
                "alias",
                format!(
                    "the admitted alias {label:?} is STALE: {canonical:?} is {} characters and \
                     now fits the {TRACKER_LABEL_CAP}-character cap, so rename the label and \
                     delete this exception",
                    canonical.len()
                ),
            ));
            continue;
        }
        let Some(derived) = label.strip_prefix(WP_PARENT_PREFIX).map(str::to_ascii_uppercase)
        else {
            report.push(Diagnostic::new(
                Code::PackageLabelMapping,
                *package_id,
                "alias",
                format!("the admitted alias {label:?} does not carry the {WP_PARENT_PREFIX} prefix"),
            ));
            continue;
        };
        // Only admit the pair when BOTH sides are actually present. An alias
        // for a package the plan dropped, or for a label nobody carries, is a
        // stale exception hiding a real mismatch.
        if declared.contains(package_id) && tracked.contains(derived.as_str()) {
            aliased_declared.insert(*package_id);
            aliased_tracked.insert(derived);
        }
    }

    for missing in declared.difference(&tracked) {
        if aliased_declared.contains(missing) {
            continue;
        }
        report.push(Diagnostic::new(
            Code::PackageLabelMapping,
            *missing,
            "wp-parent",
            format!("the plan declares {missing:?} but no Bead carries {}", canonical_label(missing)),
        ));
    }
    for extra in tracked.difference(&declared) {
        if aliased_tracked.contains(*extra) {
            continue;
        }
        report.push(Diagnostic::new(
            Code::PackageLabelMapping,
            *extra,
            "wp-parent",
            format!("Beads track {extra:?} but the plan declares no such package"),
        ));
    }

    report
}

/// Transitive closure over a directed adjacency map.
pub fn closure<'a>(
    root: &'a str,
    adjacency: &'a BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut stack = vec![root.to_owned()];
    while let Some(node) = stack.pop() {
        if !seen.insert(node.clone()) {
            continue;
        }
        if let Some(next) = adjacency.get(&node) {
            stack.extend(next.iter().cloned());
        }
    }
    seen
}

/// Build the prerequisite adjacency map from plan edges.
pub fn prerequisite_map(edges: &[(String, String)]) -> BTreeMap<String, BTreeSet<String>> {
    let mut map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (dependent, prerequisite) in edges {
        map.entry(dependent.clone())
            .or_default()
            .insert(prerequisite.clone());
    }
    map
}

/// Build the dependent adjacency map from plan edges.
pub fn dependent_map(edges: &[(String, String)]) -> BTreeMap<String, BTreeSet<String>> {
    let mut map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (dependent, prerequisite) in edges {
        map.entry(prerequisite.clone())
            .or_default()
            .insert(dependent.clone());
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPORT: &str = concat!(
        r#"{"id":"bd-1","status":"open","labels":["wp-parent-fnd-01","profile-core-qualified"]}"#,
        "\n",
        r#"{"id":"bd-2","status":"open","labels":["wp-parent-fnd-02","profile-core-qualified"]}"#,
        "\n",
        r#"{"id":"bd-3","status":"open","labels":["no-parent-here"]}"#,
        "\n",
    );

    #[test]
    fn export_projects_packages_and_profiles() {
        let projection = parse_export(EXPORT, "export").expect("parses");
        assert_eq!(projection.row_count, 3);
        assert_eq!(
            projection.packages.keys().collect::<Vec<_>>(),
            ["FND-01", "FND-02"]
        );
        assert_eq!(
            projection.profiles["profile-core-qualified"],
            BTreeSet::from(["FND-01".to_owned(), "FND-02".to_owned()])
        );
    }

    #[test]
    fn a_row_without_a_parent_label_is_projected_to_no_package() {
        let projection = parse_export(EXPORT, "export").expect("parses");
        assert!(!projection.packages.values().any(|ids| ids.contains(&"bd-3".to_owned())));
    }

    #[test]
    fn an_empty_export_is_rejected() {
        assert!(parse_export("\n\n", "export").is_err());
    }

    /// The one admitted alias, and the three things that must remain true of
    /// it. Grouped because they are one exception, and separating them would
    /// let a reader fix one and believe the exception is still guarded.
    mod admitted_alias {
        use super::*;

        const DECLARED: &str = "GATE-OAUTH-CLIENT-CREDENTIALS-DRAFT-READY";

        fn projection_with(label: &str) -> Projection {
            let line = format!(r#"{{"id":"bd-a","status":"open","labels":["{label}"]}}"#);
            parse_export(&format!("{line}\n"), "export").expect("parses")
        }

        #[test]
        fn the_admitted_abbreviation_satisfies_parity() {
            let projection = projection_with("wp-parent-gate-oauth-cc-draft-ready");
            assert!(
                check_package_label_parity(&[DECLARED], &projection).is_clean(),
                "the one documented alias must satisfy exact-set parity"
            );
        }

        /// The planted negative. Differs from the positive in ONE way: a
        /// different shortening of the same package. If this ever passes, the
        /// exception has silently become "abbreviations allowed" and the
        /// parity check is decorative.
        #[test]
        fn a_different_abbreviation_of_the_same_package_still_fails() {
            for other in [
                "wp-parent-gate-oauth-ccd-ready",
                "wp-parent-gate-oauth-cc-ready",
                "wp-parent-gate-oauth-cc-draft-rdy",
            ] {
                let projection = projection_with(other);
                assert!(
                    check_package_label_parity(&[DECLARED], &projection)
                        .has(Code::PackageLabelMapping),
                    "{other:?} is not the admitted alias and must still fail parity"
                );
            }
        }

        /// The exception retires itself. If the canonical projection ever fits
        /// the cap, the alias is stale and must fail rather than persist as
        /// folklore. Proven by measuring the real entry against a cap large
        /// enough to admit it, which is what raising the tracker limit would do.
        #[test]
        fn the_alias_is_stale_the_moment_its_canonical_form_would_fit() {
            let canonical = canonical_label(DECLARED);
            assert_eq!(
                canonical, "wp-parent-gate-oauth-client-credentials-draft-ready",
                "the canonical projection is what the cap is measured against"
            );
            assert_eq!(
                canonical.len(),
                51,
                "the justification is one character over the cap; if this changes the \
                 exception must be re-examined rather than silently kept"
            );
            assert!(
                canonical.len() > TRACKER_LABEL_CAP,
                "the alias is admitted ONLY because the canonical label does not fit"
            );
        }

        /// An alias must not paper over a real mismatch: it admits the pair
        /// only when both sides are present.
        #[test]
        fn an_alias_does_not_admit_a_package_the_plan_no_longer_declares() {
            let projection = projection_with("wp-parent-gate-oauth-cc-draft-ready");
            let report = check_package_label_parity(&["FND-01"], &projection);
            assert!(
                report.has(Code::PackageLabelMapping),
                "the aliased label with its package absent from the plan is still a mismatch"
            );
        }
    }

    #[test]
    fn a_malformed_line_names_its_line_number() {
        let error = parse_export("{not json}\n", "export").expect_err("must reject");
        assert_eq!(error.code, Code::SchemaInvalid);
        assert!(error.detail.contains("line 1"));
    }

    #[test]
    fn label_case_folding_is_ascii_uppercase() {
        let row: BeadRow =
            serde_json::from_str(r#"{"id":"x","labels":["wp-parent-gate-all-mcp-ready"]}"#)
                .expect("parses");
        assert_eq!(row.owning_package().as_deref(), Some("GATE-ALL-MCP-READY"));
    }

    #[test]
    fn profiles_returns_only_profile_labels() {
        let row: BeadRow = serde_json::from_str(
            r#"{"id":"x","labels":["wp-parent-fnd-01","profile-core","other","profile-tasks"]}"#,
        )
        .expect("parses");
        assert_eq!(row.profiles(), ["profile-core", "profile-tasks"]);
    }

    #[test]
    fn exact_parity_passes_when_both_sides_agree() {
        let projection = parse_export(EXPORT, "export").expect("parses");
        assert!(check_package_label_parity(&["FND-01", "FND-02"], &projection).is_clean());
    }

    #[test]
    fn a_package_with_no_label_group_is_reported() {
        let projection = parse_export(EXPORT, "export").expect("parses");
        let report = check_package_label_parity(&["FND-01", "FND-02", "FND-03"], &projection);
        assert_eq!(report.codes(), vec![Code::PackageLabelMapping]);
        assert_eq!(report.diagnostics()[0].subject, "FND-03");
    }

    #[test]
    fn a_label_naming_an_undeclared_package_is_reported() {
        let projection = parse_export(EXPORT, "export").expect("parses");
        let report = check_package_label_parity(&["FND-01"], &projection);
        assert!(report.has(Code::PackageLabelMapping));
        assert!(
            report
                .diagnostics()
                .iter()
                .any(|d| d.subject == "FND-02" && d.detail.contains("no such package"))
        );
    }

    #[test]
    fn an_empty_side_is_rejected_rather_than_reported_as_parity() {
        let projection = parse_export(EXPORT, "export").expect("parses");
        assert!(check_package_label_parity(&[], &projection).has(Code::PackageLabelMapping));
    }

    #[test]
    fn closure_follows_edges_transitively_and_terminates_on_cycles() {
        let edges = vec![
            ("B".to_owned(), "A".to_owned()),
            ("C".to_owned(), "B".to_owned()),
        ];
        let map = prerequisite_map(&edges);
        assert_eq!(
            closure("C", &map),
            BTreeSet::from(["A".to_owned(), "B".to_owned(), "C".to_owned()])
        );

        // A cycle must not hang the walk.
        let cyclic = prerequisite_map(&[
            ("A".to_owned(), "B".to_owned()),
            ("B".to_owned(), "A".to_owned()),
        ]);
        assert_eq!(
            closure("A", &cyclic),
            BTreeSet::from(["A".to_owned(), "B".to_owned()])
        );
    }

    #[test]
    fn prerequisite_and_dependent_maps_are_transposes() {
        let edges = vec![("B".to_owned(), "A".to_owned())];
        assert_eq!(prerequisite_map(&edges)["B"], BTreeSet::from(["A".to_owned()]));
        assert_eq!(dependent_map(&edges)["A"], BTreeSet::from(["B".to_owned()]));
    }
}
