//! bd-is7a7 item 4: the retrieval User-Agent recorded in checked-in
//! provenance artifacts, fenced against the CURRENT AGENTS.md rule.
//!
//! AGENTS.md requires that web retrievals identify this project honestly and
//! forbids borrowing another company's client identity. Five checked-in
//! artifacts record a retrieval User-Agent, and until this file nothing read
//! that field: `rg user_agent` over `crates/` and `tools/` returned exactly one
//! hit, an unrelated production struct field in
//! `fastmcp-protocol/src/mcp_apps_bridge.rs`. The three tests that do parse
//! these artifacts (`fnd_05_iana_fence_sweep`, `fnd_05_iana_registry_drift`,
//! `spec_2026_07_28_oracle`) read registry blocks and digest pins and never the
//! User-Agent. So the field was a recorded claim that nothing checked, which is
//! how it reached five artifacts in two formats across three trees under four
//! authors without failing anything.
//!
//! WHAT THIS GATE DOES NOT DO, stated first because it is the whole reason the
//! design is not a one-line value check. The five existing records carry the
//! string `0c5a665b` (2026-08-21) MANDATED and `88e4a266` (2026-10-14)
//! replaced. All five were written inside that window, and
//! `evidence/fnd-05/iana/provenance.toml` even cites the rule by file and line
//! on the same source line. Those records are therefore TRUTHFUL FOR THEIR
//! DATE, and rewriting them so old evidence appears to satisfy a newer rule is
//! golden regeneration of a provenance field (RH-3) that would destroy the only
//! durable trace of the former mandate. This gate does not ask for that and
//! fails if anyone does it halfway: the five are carried as an enumerated,
//! path-scoped exception register, each row bounded to the byte-exact mandated
//! string.
//!
//! The property actually enforced is forward-looking, which is the live risk a
//! peer named on the bead: nothing stops the NEXT artifact from carrying the
//! forbidden string, because the mechanism that produced it was a written
//! instruction since reversed. Under this fence a new artifact cannot inherit
//! the exception, because the exception is keyed on the five paths.
//!
//! BOTH FIELD SPELLINGS ARE READ. The inventory uses `retrieval_user_agent` in
//! four artifacts and `user_agent` in the fifth, `evidence/fnd-05/iana/
//! provenance.toml`. A gate written literally to the bead's wording would read
//! the long spelling only and silently pass that file, so four of five would
//! read the same as five of five until the next FND-05 probe. Every planted
//! negative below therefore runs under BOTH spellings; a single-spelling
//! negative passes against a single-spelling gate and proves nothing about the
//! other.
//!
//! FAIL-CLOSED. A User-Agent key whose value this file cannot read is a
//! refusal, never a skip. A gate with nothing to read otherwise reports the
//! same as a gate that read a compliant value.
//!
//! SELF-MATCH, avoided by construction rather than by an exclusion: the sweep
//! covers `evidence/` and `spec/`, and this file lives under `crates/`, so the
//! mandated string spelled out below is not itself swept. A source scan that
//! matches its own needle reports a defect it created.
//!
//! NO CAPABILITY CREDIT IS CLAIMED. This is a proof-integrity gate, not
//! product capability: it moves no MCP surface and says nothing about
//! conformance. Its consumer is the workspace test gate; its enforced property
//! is the AGENTS.md retrieval-identity rule; its observed defect class is the
//! five-artifact inventory above; its retirement condition is the removal of
//! the last `GRANDFATHERED` row, after which it guards only new records.

#![forbid(unsafe_code)]

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// Both spellings the five artifacts use. Order does not matter: a `user_agent`
/// match inside `retrieval_user_agent` is rejected by the identifier-boundary
/// check, so the long key is never read twice or read as the short one.
const UA_FIELD_NAMES: [&str; 2] = ["retrieval_user_agent", "user_agent"];

/// Lowercase tokens that satisfy "names this project". `AGENTS.md` prescribes
/// `fastmcp_rust-agent (+https://github.com/Dicklesworthstone/fastmcp_rust)` as
/// an example rather than as the only acceptable string, so the predicate asks
/// for the project's own name and not for one frozen literal.
const PROJECT_TOKENS: [&str; 2] = ["fastmcp_rust", "fastmcp-rust"];

/// Lowercase vendor tokens from the identity actually borrowed. This list is
/// the OBSERVED set, not an exhaustive borrowed-identity detector, and the
/// positive clause above is the primary rule; this clause exists so that
/// appending a project token to the old string does not launder it.
const FOREIGN_FETCHER_TOKENS: [&str; 2] = ["openai", "xai"];

/// The byte-exact User-Agent AGENTS.md required from `0c5a665b` (2026-08-21
/// 14:48:58, "require OpenAI File Downloader user-agent on curl/web fetches")
/// until `88e4a266` (2026-10-14 14:41:31, "identify honestly in web requests").
const MANDATED_UNTIL_2026_10_14: &str = "OpenAI File Downloader, XaiImageApiFetch/1.0";

/// The five artifacts written inside that mandate window, with their
/// introducing commits and dates. Every one predates the 2026-10-14 flip, so
/// none of them was written under the rule this fence enforces.
///
/// A row is an EXPIRING exception. When its artifact is re-probed under an
/// honest User-Agent and the record rewritten from that run, delete the row:
/// `grandfather_rows_are_live_and_expire_when_their_artifact_is_repaired` turns
/// red precisely so the row cannot linger as a hole a later regression could
/// fall back into.
const GRANDFATHERED: [&str; 5] = [
    // 9efcbb77, 2026-08-22
    "evidence/fnd-01/probes/asupersync/registry-0.4.9.json",
    // 19eff9a7, 2026-10-05
    "evidence/fnd-01/probes/asupersync/registry-0.5.0.json",
    // dc7de90c, 2026-08-22
    "evidence/fnd-01/probes/toolchain-2026-08-20.json",
    // 6f377528, 2026-09-17
    "evidence/fnd-05/iana/provenance.toml",
    // 26976e82, 2026-09-28
    "spec/mcp-2026-07-28/PROVENANCE.toml",
];

/// The trees that hold provenance artifacts. `crates/` is deliberately outside
/// the sweep; see the self-match note in the module header.
const SWEPT_TREES: [&str; 2] = ["evidence", "spec"];

/// How far past a key this file will look for a quoted value before calling the
/// record unreadable. A provenance key and its value sit on one line in every
/// observed form; a wider window would let a key adopt an unrelated string from
/// further down the document and report a verdict about the wrong bytes.
const VALUE_WINDOW_CHARS: usize = 200;

const BORROWS_FOREIGN: &str = "borrows a foreign fetcher identity";
const NOT_THIS_PROJECT: &str = "does not name this project";
const UNREADABLE_VALUE: &str = "records a User-Agent key with no readable quoted value";

/// A compliant User-Agent, used as the positive in the planted pairs below.
const COMPLIANT: &str = "fastmcp_rust-agent (+https://github.com/Dicklesworthstone/fastmcp_rust)";

/// A plausible next probe path, chosen so it is NOT in `GRANDFATHERED`. The
/// planted negatives use it to prove the exception does not travel.
const UNGRANDFATHERED_PATH: &str = "evidence/fnd-01/probes/asupersync/registry-0.6.0.json";

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Names this project and borrows no observed foreign fetcher identity.
    Compliant,
    /// The byte-exact former mandate, in one of the five artifacts written
    /// while it was the rule.
    GrandfatheredMandate,
    /// Refused, carrying the clause that refused it so a failure says which
    /// property broke rather than only that something did.
    Refused(&'static str),
}

#[derive(Debug, PartialEq, Eq)]
struct Occurrence {
    line: usize,
    field: &'static str,
    /// `None` means the key was present and its value could not be read, which
    /// this fence treats as a refusal rather than as an absence.
    value: Option<String>,
}

struct KeyHit {
    start: usize,
    end: usize,
    field: &'static str,
}

struct Sweep {
    files_read: usize,
    not_utf8: Vec<String>,
    links_skipped: Vec<String>,
    occurrences: Vec<(String, Occurrence)>,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root exists above crates/fastmcp")
        .to_path_buf()
}

/// The clause-by-clause verdict. Pure, so the planted negatives below exercise
/// the same function the live sweep does rather than a restatement of it.
fn judge(relative_path: &str, user_agent: &str) -> Verdict {
    let lowered = user_agent.to_ascii_lowercase();
    let borrows = FOREIGN_FETCHER_TOKENS
        .iter()
        .any(|token| lowered.contains(token));
    let names_project = PROJECT_TOKENS.iter().any(|token| lowered.contains(token));
    if names_project && !borrows {
        return Verdict::Compliant;
    }
    if user_agent == MANDATED_UNTIL_2026_10_14 && GRANDFATHERED.contains(&relative_path) {
        return Verdict::GrandfatheredMandate;
    }
    if borrows {
        return Verdict::Refused(BORROWS_FOREIGN);
    }
    Verdict::Refused(NOT_THIS_PROJECT)
}

/// True when the byte before `at` could continue an identifier, which is how
/// `user_agent` inside `retrieval_user_agent` is rejected.
fn identifier_byte_before(text: &str, at: usize) -> bool {
    text[..at]
        .chars()
        .next_back()
        .is_some_and(|previous| previous == '_' || previous.is_ascii_alphanumeric())
}

fn next_key(text: &str, from: usize) -> Option<KeyHit> {
    let mut earliest: Option<KeyHit> = None;
    for field in UA_FIELD_NAMES {
        let mut search = from;
        while let Some(offset) = text[search..].find(field) {
            let start = search + offset;
            let end = start + field.len();
            search = end;
            if identifier_byte_before(text, start) {
                continue;
            }
            if earliest
                .as_ref()
                .is_none_or(|current| start < current.start)
            {
                earliest = Some(KeyHit { start, end, field });
            }
            break;
        }
    }
    earliest
}

/// Reads the quoted value that follows a key in either JSON (`"k": "v"`) or
/// TOML (`k = "v"`) form. Walks characters rather than slicing at a byte
/// budget, so a multi-byte character near the window edge cannot panic the
/// instrument. Returns `None` for anything it will not guess at, including a
/// value placed on a line below its key: such a record is REFUSED as unreadable
/// rather than skipped, so an unanticipated layout turns the gate red instead of
/// quietly leaving the field unchecked.
fn quoted_value_after(after_key: &str) -> Option<String> {
    let mut seen = 0usize;
    let mut separated = false;
    let mut collecting = false;
    let mut value = String::new();
    for character in after_key.chars() {
        seen += 1;
        if seen > VALUE_WINDOW_CHARS {
            return None;
        }
        if collecting {
            if character == '"' {
                return Some(value);
            }
            value.push(character);
            continue;
        }
        if separated {
            match character {
                '"' => collecting = true,
                ' ' | '\t' => {}
                _ => return None,
            }
            continue;
        }
        match character {
            ':' | '=' => separated = true,
            // A JSON key's own closing quote sits here; whitespace is free.
            ' ' | '\t' | '"' => {}
            _ => return None,
        }
    }
    None
}

fn user_agent_occurrences(text: &str) -> Vec<Occurrence> {
    let mut found = Vec::new();
    let mut cursor = 0usize;
    while let Some(hit) = next_key(text, cursor) {
        found.push(Occurrence {
            line: 1 + text[..hit.start].matches('\n').count(),
            field: hit.field,
            value: quoted_value_after(&text[hit.end..]),
        });
        cursor = hit.end;
    }
    found
}

fn relative_label(root: &Path, entry: &Path) -> String {
    entry
        .strip_prefix(root)
        .unwrap_or(entry)
        .to_string_lossy()
        .into_owned()
}

fn sweep(root: &Path) -> Sweep {
    let mut result = Sweep {
        files_read: 0,
        not_utf8: Vec::new(),
        links_skipped: Vec::new(),
        occurrences: Vec::new(),
    };
    let mut pending: Vec<PathBuf> = SWEPT_TREES.iter().map(|tree| root.join(tree)).collect();
    while let Some(entry) = pending.pop() {
        let label = relative_label(root, &entry);
        let metadata = fs::symlink_metadata(&entry)
            .unwrap_or_else(|error| panic!("{label} is stat-able: {error}"));
        if metadata.is_symlink() {
            result.links_skipped.push(label);
            continue;
        }
        if metadata.is_dir() {
            let listing =
                fs::read_dir(&entry).unwrap_or_else(|error| panic!("{label} lists: {error}"));
            for child in listing {
                let child = child.unwrap_or_else(|error| panic!("{label} entry reads: {error}"));
                pending.push(child.path());
            }
            continue;
        }
        match fs::read_to_string(&entry) {
            Ok(text) => {
                result.files_read += 1;
                for occurrence in user_agent_occurrences(&text) {
                    result.occurrences.push((label.clone(), occurrence));
                }
            }
            Err(error) if error.kind() == ErrorKind::InvalidData => {
                result.not_utf8.push(label);
            }
            Err(error) => panic!("{label} reads as text or fails as non-UTF-8: {error}"),
        }
    }
    result
}

/// Every recorded User-Agent under the swept trees, as this fence judges it.
fn refusals(result: &Sweep) -> Vec<String> {
    let mut out = Vec::new();
    for (path, occurrence) in &result.occurrences {
        let line = occurrence.line;
        let field = occurrence.field;
        match occurrence.value.as_deref() {
            None => out.push(format!("{path}:{line} {field} -- {UNREADABLE_VALUE}")),
            Some(value) => {
                if let Verdict::Refused(clause) = judge(path, value) {
                    out.push(format!("{path}:{line} {field} = {value:?} -- {clause}"));
                }
            }
        }
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// The live sweep
// ---------------------------------------------------------------------------

#[test]
fn checked_in_provenance_records_name_this_project_or_are_grandfathered() {
    let root = workspace_root();
    let result = sweep(&root);
    println!(
        "swept {:?}: {} text files read, {} User-Agent records, {} non-UTF-8 files skipped, {} symlinks skipped",
        SWEPT_TREES,
        result.files_read,
        result.occurrences.len(),
        result.not_utf8.len(),
        result.links_skipped.len()
    );
    assert!(
        result.files_read > 0,
        "the swept trees {SWEPT_TREES:?} resolved to no readable file under {}, so this gate read nothing and its green would mean nothing",
        root.display()
    );
    let refused = refusals(&result);
    assert!(
        refused.is_empty(),
        "{} recorded User-Agent(s) violate the AGENTS.md retrieval-identity rule.\n\
         A record written under the former mandate belongs in GRANDFATHERED with its commit and date;\n\
         a record written after 88e4a266 (2026-10-14) must name this project instead.\n{}",
        refused.len(),
        refused.join("\n")
    );
}

/// Positive control bound to the live tree, and the retirement condition for
/// the exception register in one assertion: each `GRANDFATHERED` row must still
/// be reachable by the sweep AND still carry the byte-exact former mandate.
/// It therefore also proves the sweep reaches both formats and all three trees.
#[test]
fn grandfather_rows_are_live_and_expire_when_their_artifact_is_repaired() {
    let root = workspace_root();
    let result = sweep(&root);
    let mut stale = Vec::new();
    for path in GRANDFATHERED {
        let values: Vec<&str> = result
            .occurrences
            .iter()
            .filter(|(seen, _)| seen.as_str() == path)
            .filter_map(|(_, occurrence)| occurrence.value.as_deref())
            .collect();
        if values.is_empty() {
            stale.push(format!(
                "{path}: the sweep found no readable User-Agent record here"
            ));
            continue;
        }
        if !values
            .iter()
            .any(|value| *value == MANDATED_UNTIL_2026_10_14)
        {
            stale.push(format!(
                "{path}: no longer carries the former mandate; it records {values:?}"
            ));
        }
    }
    assert!(
        stale.is_empty(),
        "{} GRANDFATHERED row(s) no longer describe their artifact.\n\
         If the artifact was honestly re-probed and rewritten, DELETE its row -- an expired\n\
         exception is a hole a later regression can fall back into.\n{}",
        stale.len(),
        stale.join("\n")
    );
    println!(
        "{} grandfathered artifacts verified live across {:?}",
        GRANDFATHERED.len(),
        SWEPT_TREES
    );
}

// ---------------------------------------------------------------------------
// Instrument: positive and near-identical planted negatives, under BOTH
// field spellings and BOTH artifact formats
// ---------------------------------------------------------------------------

fn json_record(field: &str, value: &str) -> String {
    format!("{{\n  \"recorded_by\": \"a lane\",\n  \"{field}\": \"{value}\"\n}}\n")
}

fn toml_record(field: &str, value: &str) -> String {
    format!("[provenance]\nrecorded_by = \"a lane\"\n{field} = \"{value}\"  # a trailing comment\n")
}

/// Runs a synthetic document through the same extractor and judge the live
/// sweep uses, asserting the instrument saw exactly one record.
fn sole_verdict(path: &str, document: &str) -> Verdict {
    let occurrences = user_agent_occurrences(document);
    assert_eq!(
        occurrences.len(),
        1,
        "the extractor must see exactly one record in {document:?}, saw {occurrences:?}"
    );
    let value = occurrences[0]
        .value
        .clone()
        .unwrap_or_else(|| panic!("the record's value is readable in {document:?}"));
    judge(path, &value)
}

#[test]
fn a_new_record_naming_this_project_is_compliant_in_both_formats_and_spellings() {
    for field in UA_FIELD_NAMES {
        assert_eq!(
            sole_verdict(UNGRANDFATHERED_PATH, &json_record(field, COMPLIANT)),
            Verdict::Compliant,
            "JSON record under {field}"
        );
        assert_eq!(
            sole_verdict(UNGRANDFATHERED_PATH, &toml_record(field, COMPLIANT)),
            Verdict::Compliant,
            "TOML record under {field}"
        );
    }
}

/// The planted negative for the test above: the same documents, differing only
/// in the forbidden dimension -- the recorded User-Agent value.
#[test]
fn the_former_mandate_is_refused_in_a_new_record_in_both_formats_and_spellings() {
    for field in UA_FIELD_NAMES {
        assert_eq!(
            sole_verdict(
                UNGRANDFATHERED_PATH,
                &json_record(field, MANDATED_UNTIL_2026_10_14)
            ),
            Verdict::Refused(BORROWS_FOREIGN),
            "JSON record under {field}"
        );
        assert_eq!(
            sole_verdict(
                UNGRANDFATHERED_PATH,
                &toml_record(field, MANDATED_UNTIL_2026_10_14)
            ),
            Verdict::Refused(BORROWS_FOREIGN),
            "TOML record under {field}"
        );
    }
}

#[test]
fn grandfathering_is_path_scoped_and_bounded_to_the_mandated_string() {
    for path in GRANDFATHERED {
        assert_eq!(
            judge(path, MANDATED_UNTIL_2026_10_14),
            Verdict::GrandfatheredMandate,
            "{path} carries the former mandate by enumeration"
        );
        // The register is a bound, not a blanket pass for the path: one byte off
        // the mandated string is not the mandated string.
        assert_eq!(
            judge(path, "OpenAI File Downloader, XaiImageApiFetch/1.1"),
            Verdict::Refused(BORROWS_FOREIGN),
            "{path} with a near-identical but different vendor string"
        );
        assert_eq!(
            judge(path, "SomeOtherVendor Fetcher/2.0"),
            Verdict::Refused(NOT_THIS_PROJECT),
            "{path} with an unrelated foreign string"
        );
        // A grandfathered path may of course be repaired.
        assert_eq!(
            judge(path, COMPLIANT),
            Verdict::Compliant,
            "{path} repaired"
        );
    }
    // The exception does not travel: the same string in a new artifact is
    // exactly the forward-looking case this fence exists for.
    assert_eq!(
        judge(UNGRANDFATHERED_PATH, MANDATED_UNTIL_2026_10_14),
        Verdict::Refused(BORROWS_FOREIGN)
    );
}

#[test]
fn naming_this_project_does_not_launder_a_borrowed_identity() {
    assert_eq!(
        judge(
            UNGRANDFATHERED_PATH,
            "fastmcp_rust-agent, OpenAI File Downloader"
        ),
        Verdict::Refused(BORROWS_FOREIGN)
    );
    assert_eq!(
        judge(GRANDFATHERED[0], "fastmcp_rust-agent, XaiImageApiFetch/1.0"),
        Verdict::Refused(BORROWS_FOREIGN)
    );
}

/// `retrieval_user_agent` must be read as itself. A gate that matched the
/// shorter key inside it would take the key's own closing quote as the start of
/// the value and judge the wrong bytes, and would also double-count the record.
#[test]
fn the_long_spelling_is_not_read_as_the_short_one() {
    let document = json_record("retrieval_user_agent", COMPLIANT);
    let occurrences = user_agent_occurrences(&document);
    assert_eq!(occurrences.len(), 1, "saw {occurrences:?}");
    assert_eq!(occurrences[0].field, "retrieval_user_agent");
    assert_eq!(occurrences[0].value.as_deref(), Some(COMPLIANT));
    assert_eq!(occurrences[0].line, 3);

    let short = toml_record("user_agent", COMPLIANT);
    let occurrences = user_agent_occurrences(&short);
    assert_eq!(occurrences.len(), 1, "saw {occurrences:?}");
    assert_eq!(occurrences[0].field, "user_agent");
    assert_eq!(occurrences[0].value.as_deref(), Some(COMPLIANT));
    assert_eq!(occurrences[0].line, 3);
}

#[test]
fn the_fence_is_fail_closed_on_a_value_it_cannot_read() {
    for document in [
        "user_agent = SomethingUnquoted\n",
        "{ \"retrieval_user_agent\" }\n",
        "retrieval_user_agent\n",
    ] {
        let occurrences = user_agent_occurrences(document);
        assert_eq!(occurrences.len(), 1, "{document:?} holds one key");
        assert_eq!(
            occurrences[0].value, None,
            "{document:?} must read as unreadable, not as absent"
        );
    }
    // And an unreadable record reaches the refusal list rather than being
    // dropped on the floor by the sweep's reporting path.
    let result = Sweep {
        files_read: 1,
        not_utf8: Vec::new(),
        links_skipped: Vec::new(),
        occurrences: vec![(
            UNGRANDFATHERED_PATH.to_string(),
            Occurrence {
                line: 7,
                field: "user_agent",
                value: None,
            },
        )],
    };
    let refused = refusals(&result);
    assert_eq!(refused.len(), 1);
    assert!(
        refused[0].contains(UNREADABLE_VALUE),
        "unreadable records must be reported as such, got {refused:?}"
    );
}
