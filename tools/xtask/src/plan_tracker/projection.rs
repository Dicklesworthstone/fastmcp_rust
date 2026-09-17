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

    for missing in declared.difference(&tracked) {
        report.push(Diagnostic::new(
            Code::PackageLabelMapping,
            *missing,
            "wp-parent",
            format!("the plan declares {missing:?} but no Bead carries {WP_PARENT_PREFIX}{}", missing.to_ascii_lowercase()),
        ));
    }
    for extra in tracked.difference(&declared) {
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
