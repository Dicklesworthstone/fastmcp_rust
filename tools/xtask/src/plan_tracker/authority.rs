//! Conformance and authorization authorities, read from FND-01's frozen
//! evidence.
//!
//! FND-02 reads FND-01 evidence and never writes it. These parsers take only
//! the fields they need and ignore the rest, so an unrelated FND-01 edit does
//! not break FND-02 parsing — but the blob binding in `sources` still notices
//! that the file changed, which is the intended split: content drift is a
//! finding, schema growth is not.

use std::collections::BTreeSet;

use serde::Deserialize;

use super::diagnostics::{Code, Diagnostic, Report};
use super::trace::{NONE_SENTINEL, TraceTable};

// ---------------------------------------------------------------- conformance

#[derive(Debug, Clone, Deserialize)]
struct ConformanceScenario {
    id: String,
    #[serde(default)]
    scenario_local_declared_check_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ConformanceDocument {
    #[serde(default)]
    conformance_scenarios: Vec<ConformanceScenario>,
}

/// The frozen conformance inventory: which scenarios exist and which check IDs
/// each one declares.
#[derive(Debug, Clone, Default)]
pub struct ConformanceInventory {
    scenarios: BTreeSet<String>,
    pairs: BTreeSet<(String, String)>,
}

impl ConformanceInventory {
    pub fn parse(text: &str, subject: &str) -> Result<Self, Diagnostic> {
        let document: ConformanceDocument = toml::from_str(text).map_err(|error| {
            Diagnostic::new(Code::SchemaInvalid, subject, "toml", error.to_string())
        })?;

        let mut scenarios = BTreeSet::new();
        let mut pairs = BTreeSet::new();
        for scenario in document.conformance_scenarios {
            for check in &scenario.scenario_local_declared_check_ids {
                pairs.insert((scenario.id.clone(), check.clone()));
            }
            scenarios.insert(scenario.id);
        }

        if scenarios.is_empty() {
            return Err(Diagnostic::new(
                Code::SchemaInvalid,
                subject,
                "conformance_scenarios",
                "the conformance authority declares zero scenarios",
            ));
        }

        Ok(Self { scenarios, pairs })
    }

    pub fn scenario_count(&self) -> usize {
        self.scenarios.len()
    }

    pub fn pair_count(&self) -> usize {
        self.pairs.len()
    }

    /// True when `scenario#check` is declared by the frozen inventory.
    pub fn declares(&self, scenario: &str, check: &str) -> bool {
        self.pairs
            .contains(&(scenario.to_owned(), check.to_owned()))
    }

    pub fn has_scenario(&self, scenario: &str) -> bool {
        self.scenarios.contains(scenario)
    }

    /// Every declared scenario id, ascending.
    pub fn scenario_ids(&self) -> Vec<&str> {
        self.scenarios.iter().map(String::as_str).collect()
    }
}

/// FND-02-A-03: every cited conformance reference still exists upstream.
///
/// A reference that once resolved and no longer does is exactly the failure
/// mode this subcase is named for: the row still *looks* traceable.
pub fn check_conformance_references(
    inventory: &ConformanceInventory,
    table: &TraceTable,
) -> Report {
    let mut report = Report::new();

    for row in &table.rows {
        let cited = row.scenario_check_id.trim();
        if cited == NONE_SENTINEL {
            continue;
        }

        let Some((scenario, check)) = cited.split_once('#') else {
            report.push(Diagnostic::new(
                Code::ConformanceReferenceStale,
                &row.clause_key,
                "scenario_check_id",
                format!("{cited:?} is not `<scenario>#<check>` and is not the none sentinel"),
            ));
            continue;
        };

        if !inventory.has_scenario(scenario) {
            report.push(Diagnostic::new(
                Code::ConformanceReferenceStale,
                &row.clause_key,
                "scenario_check_id",
                format!("scenario {scenario:?} is not in the frozen conformance inventory"),
            ));
            continue;
        }

        if !inventory.declares(scenario, check) {
            report.push(Diagnostic::new(
                Code::ConformanceReferenceStale,
                &row.clause_key,
                "scenario_check_id",
                format!("scenario {scenario:?} does not declare check {check:?}"),
            ));
        }
    }

    report
}

// --------------------------------------------------------------- authorization

#[derive(Debug, Clone, Deserialize)]
struct RequiredSets {
    #[serde(default)]
    core_authorization_drafts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuthArtifact {
    id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct AuthDocument {
    #[serde(default)]
    required_sets: Option<RequiredSets>,
    #[serde(default)]
    artifacts: Vec<AuthArtifact>,
}

/// The exact immutable authorization revisions the dated core page links.
///
/// A floating "OAuth 2.1" citation fails traceability: the draft is revised,
/// and a clause inherited from `-13` is not the same clause in `-14`.
#[derive(Debug, Clone, Default)]
pub struct AuthorityRevisions {
    known: BTreeSet<String>,
}

/// Exact revision required for general authorization security clauses.
pub const OAUTH_GENERAL_REVISION: &str = "oauth-2.1-13";
/// Exact revision required specifically for refresh-token confidentiality.
pub const OAUTH_REFRESH_TOKEN_REVISION: &str = "oauth-2.1-14";
/// Exact revision required for Client ID Metadata Documents.
pub const CIMD_REVISION: &str = "cimd-00";

/// Marks a row whose clause is refresh-token confidentiality.
pub const REFRESH_TOKEN_MARKER: &str = "refresh-token-confidentiality";

impl AuthorityRevisions {
    pub fn parse(text: &str, subject: &str) -> Result<Self, Diagnostic> {
        let document: AuthDocument = toml::from_str(text).map_err(|error| {
            Diagnostic::new(Code::SchemaInvalid, subject, "toml", error.to_string())
        })?;

        let mut known: BTreeSet<String> =
            document.artifacts.into_iter().map(|a| a.id).collect();
        if let Some(sets) = document.required_sets {
            known.extend(sets.core_authorization_drafts);
        }

        for required in [OAUTH_GENERAL_REVISION, OAUTH_REFRESH_TOKEN_REVISION, CIMD_REVISION] {
            if !known.contains(required) {
                return Err(Diagnostic::new(
                    Code::SchemaInvalid,
                    subject,
                    "required_sets.core_authorization_drafts",
                    format!("authority does not declare the exact revision {required:?}"),
                ));
            }
        }

        Ok(Self { known })
    }

    pub fn knows(&self, revision: &str) -> bool {
        self.known.contains(revision)
    }

    pub fn len(&self) -> usize {
        self.known.len()
    }

    pub fn is_empty(&self) -> bool {
        self.known.is_empty()
    }
}

/// True when `revision` is a floating citation rather than an exact one.
///
/// `oauth-2.1` names a moving draft series; `oauth-2.1-13` names bytes.
fn is_floating(revision: &str) -> bool {
    matches!(revision, "oauth-2.1" | "oauth2.1" | "OAuth 2.1" | "cimd" | "CIMD")
}

/// The authorization source prefix a row must carry to be checked here.
const AUTH_PREFIX: &str = "auth:";

/// FND-02-A-04: authorization clauses cite exact immutable revisions.
///
/// Rows whose `source_revision` begins with `auth:` are authorization rows.
/// Everything after the prefix must be an exact revision the authority
/// declares, and the refresh-token-confidentiality clause must cite `-14`
/// specifically rather than the general `-13`.
pub fn check_auth_revisions(revisions: &AuthorityRevisions, table: &TraceTable) -> Report {
    let mut report = Report::new();

    for row in &table.rows {
        let Some(cited) = row.source_revision.trim().strip_prefix(AUTH_PREFIX) else {
            continue;
        };

        if is_floating(cited) {
            report.push(Diagnostic::new(
                Code::AuthRevisionFloating,
                &row.clause_key,
                "source_revision",
                format!("{cited:?} is a floating citation; an exact immutable revision is required"),
            ));
            continue;
        }

        if !revisions.knows(cited) {
            report.push(Diagnostic::new(
                Code::AuthRevisionWrong,
                &row.clause_key,
                "source_revision",
                format!("{cited:?} is not an authority-declared immutable revision"),
            ));
            continue;
        }

        // Refresh-token confidentiality is inherited from -14 specifically.
        // Citing the general -13 here is the exact drift this subcase exists
        // to catch, and it is invisible to a spelling check.
        let is_refresh_clause = row.clause_key.contains(REFRESH_TOKEN_MARKER);
        if is_refresh_clause && cited != OAUTH_REFRESH_TOKEN_REVISION {
            report.push(Diagnostic::new(
                Code::AuthRevisionWrong,
                &row.clause_key,
                "source_revision",
                format!(
                    "refresh-token confidentiality is inherited from \
                     {OAUTH_REFRESH_TOKEN_REVISION}, observed {cited:?}"
                ),
            ));
        }
        if !is_refresh_clause && cited == OAUTH_REFRESH_TOKEN_REVISION {
            report.push(Diagnostic::new(
                Code::AuthRevisionWrong,
                &row.clause_key,
                "source_revision",
                format!(
                    "only refresh-token confidentiality is inherited from \
                     {OAUTH_REFRESH_TOKEN_REVISION}; general clauses cite \
                     {OAUTH_GENERAL_REVISION}"
                ),
            ));
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::trace::{TRACE_TABLE_SCHEMA, TraceRow, TraceTable};

    const CONFORMANCE: &str = "\
[[conformance_scenarios]]
id = \"auth/client-credentials-jwt\"
scenario_local_declared_check_ids = [
  \"client-credentials-grant-type\",
  \"client-credentials-jwt-verified\",
]

[[conformance_scenarios]]
id = \"auth/client-credentials-basic\"
scenario_local_declared_check_ids = [\"client-credentials-basic-auth\"]
";

    const AUTHORITY: &str = "\
[required_sets]
core_authorization_drafts = [\"oauth-2.1-12\", \"oauth-2.1-13\", \"oauth-2.1-14\", \"cimd-00\"]

[[artifacts]]
id = \"rfc-9207\"
";

    fn row(clause_key: &str, scenario_check_id: &str, source_revision: &str) -> TraceRow {
        TraceRow {
            clause_key: clause_key.to_owned(),
            strength: "MUST".to_owned(),
            client_behavior: "c".to_owned(),
            server_behavior: "s".to_owned(),
            transport_applicability: "all".to_owned(),
            owner: "AUTH-01".to_owned(),
            positive_test_id: "p".to_owned(),
            negative_test_id: "n".to_owned(),
            scenario_check_id: scenario_check_id.to_owned(),
            source_revision: source_revision.to_owned(),
            unobservable_prose: false,
            ambiguity: "none".to_owned(),
            covers_item: "core-changelog/major/1".to_owned(),
        }
    }

    fn table(rows: Vec<TraceRow>) -> TraceTable {
        TraceTable { schema: TRACE_TABLE_SCHEMA.to_owned(), rows }
    }

    #[test]
    fn inventory_parses_scenarios_and_pairs() {
        let inventory = ConformanceInventory::parse(CONFORMANCE, "c").expect("parses");
        assert_eq!(inventory.scenario_count(), 2);
        assert_eq!(inventory.pair_count(), 3);
        assert!(inventory.declares("auth/client-credentials-jwt", "client-credentials-grant-type"));
        assert!(!inventory.declares("auth/client-credentials-basic", "client-credentials-jwt-iss"));
    }

    #[test]
    fn an_authority_with_zero_scenarios_is_rejected() {
        let error = ConformanceInventory::parse("", "c").expect_err("must reject");
        assert_eq!(error.code, Code::SchemaInvalid);
    }

    #[test]
    fn a_live_conformance_reference_passes() {
        let inventory = ConformanceInventory::parse(CONFORMANCE, "c").unwrap();
        let rows = table(vec![row(
            "k",
            "auth/client-credentials-jwt#client-credentials-grant-type",
            "core:x",
        )]);
        assert!(check_conformance_references(&inventory, &rows).is_clean());
    }

    #[test]
    fn the_none_sentinel_is_accepted_but_an_empty_string_is_not() {
        let inventory = ConformanceInventory::parse(CONFORMANCE, "c").unwrap();
        assert!(
            check_conformance_references(&inventory, &table(vec![row("k", NONE_SENTINEL, "c:x")]))
                .is_clean()
        );
        assert!(
            check_conformance_references(&inventory, &table(vec![row("k", "", "c:x")]))
                .has(Code::ConformanceReferenceStale)
        );
    }

    #[test]
    fn a_stale_check_id_is_rejected() {
        let inventory = ConformanceInventory::parse(CONFORMANCE, "c").unwrap();
        // The scenario exists; the check does not. This is the drift shape.
        let rows = table(vec![row(
            "k",
            "auth/client-credentials-basic#client-credentials-jwt-iss",
            "core:x",
        )]);
        let report = check_conformance_references(&inventory, &rows);
        assert_eq!(report.codes(), vec![Code::ConformanceReferenceStale]);
    }

    #[test]
    fn a_stale_scenario_is_rejected() {
        let inventory = ConformanceInventory::parse(CONFORMANCE, "c").unwrap();
        let rows = table(vec![row("k", "auth/removed-scenario#some-check", "core:x")]);
        assert!(
            check_conformance_references(&inventory, &rows).has(Code::ConformanceReferenceStale)
        );
    }

    #[test]
    fn authority_requires_the_three_exact_revisions() {
        let revisions = AuthorityRevisions::parse(AUTHORITY, "a").expect("parses");
        assert!(revisions.knows("oauth-2.1-13"));
        assert!(revisions.knows("oauth-2.1-14"));
        assert!(revisions.knows("cimd-00"));

        let missing = "[required_sets]\ncore_authorization_drafts = [\"oauth-2.1-13\"]\n";
        assert!(AuthorityRevisions::parse(missing, "a").is_err());
    }

    #[test]
    fn an_exact_general_revision_passes() {
        let revisions = AuthorityRevisions::parse(AUTHORITY, "a").unwrap();
        let rows = table(vec![row("auth/general-security", NONE_SENTINEL, "auth:oauth-2.1-13")]);
        assert!(check_auth_revisions(&revisions, &rows).is_clean());
    }

    #[test]
    fn a_floating_citation_is_rejected() {
        let revisions = AuthorityRevisions::parse(AUTHORITY, "a").unwrap();
        for floating in ["auth:oauth-2.1", "auth:cimd", "auth:OAuth 2.1"] {
            let rows = table(vec![row("auth/general-security", NONE_SENTINEL, floating)]);
            let report = check_auth_revisions(&revisions, &rows);
            assert_eq!(report.codes(), vec![Code::AuthRevisionFloating], "{floating}");
        }
    }

    #[test]
    fn refresh_token_confidentiality_must_cite_dash_14_not_dash_13() {
        let revisions = AuthorityRevisions::parse(AUTHORITY, "a").unwrap();
        let key = "auth/refresh-token-confidentiality";

        let correct = table(vec![row(key, NONE_SENTINEL, "auth:oauth-2.1-14")]);
        assert!(check_auth_revisions(&revisions, &correct).is_clean());

        // -13 is a real, authority-declared revision, so a spelling or
        // membership check would pass it. Only the clause-specific rule
        // catches it.
        let drifted = table(vec![row(key, NONE_SENTINEL, "auth:oauth-2.1-13")]);
        let report = check_auth_revisions(&revisions, &drifted);
        assert_eq!(report.codes(), vec![Code::AuthRevisionWrong]);
    }

    #[test]
    fn a_general_clause_may_not_borrow_the_refresh_token_revision() {
        let revisions = AuthorityRevisions::parse(AUTHORITY, "a").unwrap();
        let rows = table(vec![row("auth/general-security", NONE_SENTINEL, "auth:oauth-2.1-14")]);
        assert!(check_auth_revisions(&revisions, &rows).has(Code::AuthRevisionWrong));
    }

    #[test]
    fn an_unknown_exact_revision_is_rejected() {
        let revisions = AuthorityRevisions::parse(AUTHORITY, "a").unwrap();
        let rows = table(vec![row("auth/general-security", NONE_SENTINEL, "auth:oauth-2.1-99")]);
        assert!(check_auth_revisions(&revisions, &rows).has(Code::AuthRevisionWrong));
    }

    #[test]
    fn a_non_auth_row_is_not_subject_to_the_auth_rule() {
        let revisions = AuthorityRevisions::parse(AUTHORITY, "a").unwrap();
        let rows = table(vec![row("core/lifecycle", NONE_SENTINEL, "core_2026_git:5f5440bb")]);
        assert!(check_auth_revisions(&revisions, &rows).is_clean());
    }
}
