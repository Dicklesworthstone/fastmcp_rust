//! REL-071 release-binding evaluator.
//!
//! This module decides one question and nothing else: **does a recorded set of
//! provider observations for a published release bind together consistently?**
//!
//! # What this evaluator is, and is not
//!
//! It is a *regression guard on the binding relation*. Its input is a recorded
//! observation document, and it verifies that the members of that record agree
//! with one another:
//!
//! - the archive digest equals the digest the registry advertised,
//! - the commit the archive was packaged from is the commit the tag names,
//! - every archive file's bytes equal the corresponding tree blob's bytes,
//! - the observation set is complete, unique, and well formed.
//!
//! It is **not** a provider audit. It never contacts a registry, and it cannot
//! establish that the observations are themselves truthful — a registry that
//! served a false artifact *and* a matching false digest would be recorded
//! consistently and would pass. Re-observation requires the network and is out
//! of scope here. Any receipt citing this evaluator says "binding relation",
//! never "provider audit".
//!
//! # No mutation path
//!
//! [`evaluate`] is pure and total: it borrows the observations, returns a
//! verdict, and has no filesystem, network, process, or interior-mutability
//! access. Admission therefore fails by *returning* before any claim, gate, or
//! provider effect could occur, because no such effect is reachable from this
//! code at all.

use std::collections::BTreeSet;

use serde::Deserialize;

/// A typed refusal. Each variant names exactly what diverged, so a failing run
/// reports the defect rather than only its existence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Code {
    /// The archive's digest and the registry's advertised digest disagree.
    ArchiveDigestMismatch,
    /// The commit recorded in the archive is not the commit the tag names.
    TagNotPublishedCommit,
    /// An archive file's bytes differ from the tree blob it is bound to.
    FileDivergence,
    /// Fewer observations are present than the record declares are required.
    ObservationMissing,
    /// More observations are present than the record declares are required.
    ObservationUnexpected,
    /// The same path is observed more than once.
    DuplicateObservation,
    /// A digest field is not 64 lowercase hexadecimal characters.
    MalformedDigest,
}

impl Code {
    /// The stable string form used in receipts.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ArchiveDigestMismatch => "E_ARCHIVE_DIGEST_MISMATCH",
            Self::TagNotPublishedCommit => "E_TAG_NOT_PUBLISHED_COMMIT",
            Self::FileDivergence => "E_FILE_DIVERGENCE",
            Self::ObservationMissing => "E_OBSERVATION_MISSING",
            Self::ObservationUnexpected => "E_OBSERVATION_UNEXPECTED",
            Self::DuplicateObservation => "E_DUPLICATE_OBSERVATION",
            Self::MalformedDigest => "E_MALFORMED_DIGEST",
        }
    }
}

/// One observed file, bound on both sides: as it exists inside the published
/// archive, and as it exists in the source tree the archive was packaged from.
#[derive(Debug, Clone, Deserialize)]
pub struct FileObservation {
    /// Archive-relative path.
    pub path: String,
    /// SHA-256 of the file's bytes inside the published archive.
    pub archive_sha256: String,
    /// SHA-256 of the corresponding blob in the packaging commit's tree.
    pub tree_sha256: String,
}

/// A recorded set of provider observations for one published version.
#[derive(Debug, Clone, Deserialize)]
pub struct Observations {
    /// The published version these observations describe.
    pub version: String,
    /// SHA-256 the registry advertises for the published archive.
    pub advertised_sha256: String,
    /// SHA-256 computed over the archive bytes as retrieved.
    pub archive_sha256: String,
    /// Commit recorded inside the archive by `cargo package`.
    pub vcs_sha1: String,
    /// Commit the release tag resolves to, after tag-object dereference.
    pub tag_commit: String,
    /// How many file observations the record declares are required.
    pub required_file_count: usize,
    /// The file observations themselves.
    pub files: Vec<FileObservation>,
}

/// The verdict. `Admitted` means every binding held; otherwise the typed codes
/// name what diverged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// Every binding held, over `inspected` observations.
    Admitted {
        /// Number of file observations inspected.
        inspected: usize,
    },
    /// At least one binding failed. Codes are sorted and deduplicated.
    Refused {
        /// Every distinct reason the record was refused.
        codes: Vec<Code>,
        /// Human-readable detail, one line per divergence.
        detail: Vec<String>,
    },
}

impl Disposition {
    /// Whether the record was admitted.
    #[must_use]
    pub fn admitted(&self) -> bool {
        matches!(self, Self::Admitted { .. })
    }

    /// The distinct refusal codes, empty when admitted.
    #[must_use]
    pub fn codes(&self) -> Vec<Code> {
        match self {
            Self::Admitted { .. } => Vec::new(),
            Self::Refused { codes, .. } => codes.clone(),
        }
    }

    /// Rendered detail suitable for an assertion message.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Admitted { inspected } => format!("admitted; {inspected} observations inspected"),
            Self::Refused { codes, detail } => {
                let names: Vec<&str> = codes.iter().map(Code::as_str).collect();
                format!("refused [{}]\n  {}", names.join(", "), detail.join("\n  "))
            }
        }
    }
}

/// True when `value` is exactly 64 lowercase hexadecimal characters.
///
/// Uppercase is rejected deliberately: two spellings of one digest would
/// compare unequal, so the canonical form is enforced rather than normalised.
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Evaluates one recorded observation set.
///
/// Pure and total. Every divergence is collected rather than short-circuited,
/// so a caller sees the complete set of reasons rather than only the first —
/// a first-failure-only evaluator hides its siblings.
#[must_use]
pub fn evaluate(observations: &Observations) -> Disposition {
    let mut codes: BTreeSet<Code> = BTreeSet::new();
    let mut detail: Vec<String> = Vec::new();

    // (1) The archive is the artifact the registry advertised.
    if observations.archive_sha256 != observations.advertised_sha256 {
        codes.insert(Code::ArchiveDigestMismatch);
        detail.push(format!(
            "archive_sha256 {} != advertised_sha256 {}",
            observations.archive_sha256, observations.advertised_sha256
        ));
    }

    // (2) What was published is what the tag names.
    if observations.vcs_sha1 != observations.tag_commit {
        codes.insert(Code::TagNotPublishedCommit);
        detail.push(format!(
            "vcs_sha1 {} != tag_commit {}",
            observations.vcs_sha1, observations.tag_commit
        ));
    }

    // (3) The observation set is complete. Under- and over-count are distinct
    //     defects: a removed observation is a gap, an extra one is a different
    //     record than the one declared.
    let discovered = observations.files.len();
    if discovered < observations.required_file_count {
        codes.insert(Code::ObservationMissing);
        detail.push(format!(
            "discovered {discovered} file observations, required {}",
            observations.required_file_count
        ));
    } else if discovered > observations.required_file_count {
        codes.insert(Code::ObservationUnexpected);
        detail.push(format!(
            "discovered {discovered} file observations, required {}",
            observations.required_file_count
        ));
    }

    // (4) Each observation is well formed, unique, and internally consistent.
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for file in &observations.files {
        if !seen.insert(file.path.as_str()) {
            codes.insert(Code::DuplicateObservation);
            detail.push(format!("duplicate observation for {}", file.path));
        }
        if !is_sha256_hex(&file.archive_sha256) || !is_sha256_hex(&file.tree_sha256) {
            codes.insert(Code::MalformedDigest);
            detail.push(format!("malformed digest on {}", file.path));
            continue;
        }
        if file.archive_sha256 != file.tree_sha256 {
            codes.insert(Code::FileDivergence);
            detail.push(format!(
                "{}: archive {} != tree {}",
                file.path, file.archive_sha256, file.tree_sha256
            ));
        }
    }

    for (label, digest) in [
        ("advertised_sha256", &observations.advertised_sha256),
        ("archive_sha256", &observations.archive_sha256),
    ] {
        if !is_sha256_hex(digest) {
            codes.insert(Code::MalformedDigest);
            detail.push(format!("malformed {label}"));
        }
    }

    if codes.is_empty() {
        Disposition::Admitted {
            inspected: discovered,
        }
    } else {
        Disposition::Refused {
            codes: codes.into_iter().collect(),
            detail,
        }
    }
}
