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
    /// A commit field is not 40 lowercase hexadecimal characters.
    MalformedCommit,
    /// Fewer release assets are present than the record declares are required.
    ReleaseAssetMissing,
    /// No release asset was independently hashed, so the digest columns are
    /// only the release restating its own manifest.
    NoAnchoredAsset,
    /// Two assets share a digest but disagree on size, or the anchored asset's
    /// digest is absent.
    AssetDigestInconsistent,
    /// A credential-presence entry carries something other than presence.
    CredentialValueDisclosed,
    /// Fewer credential-presence entries than the record declares.
    CredentialEntryMissing,
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
            Self::MalformedCommit => "E_MALFORMED_COMMIT",
            Self::ReleaseAssetMissing => "E_RELEASE_ASSET_MISSING",
            Self::NoAnchoredAsset => "E_NO_ANCHORED_ASSET",
            Self::AssetDigestInconsistent => "E_ASSET_DIGEST_INCONSISTENT",
            Self::CredentialValueDisclosed => "E_CREDENTIAL_VALUE_DISCLOSED",
            Self::CredentialEntryMissing => "E_CREDENTIAL_ENTRY_MISSING",
        }
    }
}

/// One published release asset, as the release surface reports it.
#[derive(Debug, Clone, Deserialize)]
pub struct ReleaseAsset {
    /// Asset filename as published.
    pub name: String,
    /// Size in bytes as the release reports it.
    pub size: u64,
    /// SHA-256 where the release publishes one, otherwise absent.
    pub sha256: Option<String>,
    /// Whether this asset was downloaded and hashed independently of the
    /// release's own manifests.
    pub independently_verified: bool,
}

/// The GitHub release surface. A publication surface, not CI: no workflow run,
/// rerun state or environment is represented here, and none may be added —
/// those are permanent RULE 0.5 exclusions.
#[derive(Debug, Clone, Deserialize)]
pub struct Release {
    /// Tag the release is attached to.
    pub tag: String,
    /// How many assets the record declares are required.
    pub required_asset_count: usize,
    /// The asset whose digest was independently recomputed.
    pub anchored_asset: String,
    /// The assets themselves.
    pub assets: Vec<ReleaseAsset>,
}

/// One credential-presence observation. Presence only, never a value.
#[derive(Debug, Clone, Deserialize)]
pub struct CredentialEntry {
    /// What was checked for.
    pub name: String,
    /// Whether it was present.
    pub present: bool,
    /// Optional non-secret characterisation, such as a scope list.
    #[serde(default)]
    pub detail: Option<String>,
}

/// Host-scoped credential presence. Recording a value here is a defect, not a
/// feature, and [`evaluate`] refuses a record that does.
#[derive(Debug, Clone, Deserialize)]
pub struct CredentialPresence {
    /// How many entries the record declares are required.
    pub required_entry_count: usize,
    /// The entries themselves.
    pub entries: Vec<CredentialEntry>,
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
    /// The published release and its assets.
    pub release: Release,
    /// Host-scoped credential presence.
    pub credential_presence: CredentialPresence,
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

/// True when `value` is exactly 40 lowercase hexadecimal characters.
fn is_sha1_hex(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// True when `text` looks like it carries credential material.
///
/// Presence records must never contain a value. This is a refusal heuristic,
/// not a secret scanner: it exists so that a record which starts carrying
/// tokens fails loudly rather than being published.
fn looks_like_a_secret(text: &str) -> bool {
    const PREFIXES: [&str; 6] = ["gho_", "ghp_", "ghu_", "ghs_", "ghr_", "github_pat_"];
    if PREFIXES.iter().any(|prefix| text.contains(prefix)) {
        return true;
    }
    // Any long unbroken run of credential-shaped characters.
    let mut run = 0usize;
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() {
            run += 1;
            if run >= 32 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
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

    // (5) The commit fields are commits. Equality alone would admit two equal
    //     empty strings, which is how a self-comparing record passes without
    //     naming anything.
    for (label, commit) in [
        ("vcs_sha1", &observations.vcs_sha1),
        ("tag_commit", &observations.tag_commit),
    ] {
        if !is_sha1_hex(commit) {
            codes.insert(Code::MalformedCommit);
            detail.push(format!(
                "{label} is not a 40-character lowercase hex commit"
            ));
        }
    }

    // (6) The release surface. Publication only — no workflow, rerun state or
    //     environment is represented, and none may be: RULE 0.5, permanent.
    let release = &observations.release;
    if release.assets.len() < release.required_asset_count {
        codes.insert(Code::ReleaseAssetMissing);
        detail.push(format!(
            "release has {} assets, requires {}",
            release.assets.len(),
            release.required_asset_count
        ));
    }
    for asset in &release.assets {
        if let Some(digest) = asset.sha256.as_deref() {
            if !is_sha256_hex(digest) {
                codes.insert(Code::MalformedDigest);
                detail.push(format!("malformed digest on asset {}", asset.name));
            }
        }
    }
    // Assets sharing a digest are the same bytes, so they must share a size.
    // This catches an alias row edited on one side only.
    let mut by_digest: std::collections::BTreeMap<&str, (u64, &str)> =
        std::collections::BTreeMap::new();
    for asset in &release.assets {
        if let Some(digest) = asset.sha256.as_deref() {
            if let Some((size, first)) = by_digest.insert(digest, (asset.size, asset.name.as_str()))
            {
                if size != asset.size {
                    codes.insert(Code::AssetDigestInconsistent);
                    detail.push(format!(
                        "{} and {} share a digest but differ in size",
                        first, asset.name
                    ));
                }
            }
        }
    }
    // Without one independently recomputed digest, every digest column here is
    // the release restating its own manifest.
    match release
        .assets
        .iter()
        .find(|asset| asset.name == release.anchored_asset)
    {
        None => {
            codes.insert(Code::NoAnchoredAsset);
            detail.push(format!(
                "anchored_asset {} is not among the assets",
                release.anchored_asset
            ));
        }
        Some(anchor) => {
            if !anchor.independently_verified {
                codes.insert(Code::NoAnchoredAsset);
                detail.push(format!(
                    "{} is not marked independently verified",
                    anchor.name
                ));
            }
            if anchor.sha256.is_none() {
                codes.insert(Code::AssetDigestInconsistent);
                detail.push(format!("anchored asset {} carries no digest", anchor.name));
            }
        }
    }

    // (7) Credential presence: presence only, never a value.
    let credentials = &observations.credential_presence;
    if credentials.entries.len() < credentials.required_entry_count {
        codes.insert(Code::CredentialEntryMissing);
        detail.push(format!(
            "{} credential entries, requires {}",
            credentials.entries.len(),
            credentials.required_entry_count
        ));
    }
    for entry in &credentials.entries {
        if let Some(text) = entry.detail.as_deref() {
            if looks_like_a_secret(text) {
                codes.insert(Code::CredentialValueDisclosed);
                detail.push(format!(
                    "entry {} carries credential-shaped text",
                    entry.name
                ));
            }
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
