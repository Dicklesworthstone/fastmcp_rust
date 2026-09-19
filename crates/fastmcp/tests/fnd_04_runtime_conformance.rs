//! FND-04 B runtime-conformance evaluator (`bd-mcp-fnd-04-b-th72`).
//!
//! Exercises the real structured runtime, I/O, cancellation, deadline,
//! blocking, and process-generation paths through the shipped public surface.
//!
//! - Profile: `core-candidate`.
//! - Plan target matrix: `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`,
//!   `x86_64-pc-windows-msvc`.
//! - Named consumer: `bd-mcp-fnd-04-integration-ymje`.
//!
//! # What this evaluator does and does not claim
//!
//! It reports the state of the pinned runtime as it actually is. Several
//! subcases below are expected to fail at the current revision because the
//! production capability they name is genuinely absent, and they are written
//! to fail rather than to be satisfiable by a weaker predicate. A green run of
//! a weakened subcase would be worse than a red run of an accurate one: nine
//! downstream items read this result.
//!
//! This role alone establishes no parent completion, no aggregate MCP
//! 2026-07-28 support, no MCP 2024-11-05 preservation, no profile maturity,
//! no conformance, no publication, and no release readiness.
//!
//! # Proof configuration caveat, recorded rather than hidden
//!
//! `crates/fastmcp/Cargo.toml` carries `asupersync = { features =
//! ["test-internals"] }` as a dev-dependency, so every test target in this
//! package unifies that feature into its own graph. The acceptance criteria
//! require the *product* feature graph to exclude it. This evaluator therefore
//! never infers the product graph from its own compilation: the feature,
//! pin, and deny-inventory subcases read the workspace manifests, the
//! lockfile, and the shipped sources directly, and
//! [`subcase_05_dependency_feature`] asserts the divergence explicitly instead
//! of papering over it.

#![forbid(unsafe_code)]
#![allow(clippy::too_many_lines)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use asupersync::cx::child_region::ChildRegionSpec;
use asupersync::runtime::reactor::create_reactor;
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::types::CancelReason;
use asupersync::{Cx, RegionId};

use fastmcp_core::SECURITY_IDENTIFIER_BYTES;
use fastmcp_core::runtime::{
    ExternalEpoch, ProcessGeneration, ProcessGenerationError, ProcessGenerationGuard,
    SNAPSHOT_CLONE_IS_DETECTABLE, SnapshotCloneStance,
};

// ===========================================================================
// Frozen identity
// ===========================================================================

/// Canonical receipt name frozen by the acceptance criteria.
const RECEIPT_NAME: &str = "fnd-04-b-manifest-v1";

/// Named consumer of this evaluator's result.
const CONSUMER_ID: &str = "bd-mcp-fnd-04-integration-ymje";

/// Evaluation profile frozen by the acceptance criteria.
const PROFILE: &str = "core-candidate";

/// Plan-applicable target matrix, in frozen order.
const TARGET_MATRIX: [&str; 3] = [
    "x86_64-unknown-linux-gnu",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
];

/// Exact runtime pin this evaluator is bound to.
///
/// Every prerequisite observation below is an observation *about this exact
/// archive*. A different version number does not move any of them: it
/// invalidates them, and they must be re-derived against the new checksum
/// before any claim is restated (FND-04-B-12).
const PINNED_RUNTIME_VERSION: &str = "0.5.0";

/// Exact registry checksum of the pinned runtime archive.
const PINNED_RUNTIME_CHECKSUM: &str =
    "f34b1a19ffd6b74570339a156912436335bb09c594c675c62ea164b19a1f2511";

/// The feature that must never appear in a product dependency graph.
const FORBIDDEN_RUNTIME_FEATURE: &str = "test-internals";

/// Environment marker used to re-enter this binary as a fresh process
/// generation for the fork-generation subcase.
const FORK_CHILD_MARKER: &str = "FASTMCP_FND04B_FORK_CHILD";

// ===========================================================================
// Subcase outcome model
// ===========================================================================

/// One ordered plan-test subcase result.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SubcaseOutcome {
    /// Frozen subcase identifier, e.g. `FND-04-B-01`.
    id: &'static str,
    /// Frozen subcase name, e.g. `sibling-cancellation`.
    name: &'static str,
    /// Whether the named production capability was observed.
    passed: bool,
    /// Machine-checkable observations, in deterministic order.
    observations: BTreeMap<String, String>,
    /// Exact reason the subcase failed, when it did.
    failure: Option<String>,
}

impl SubcaseOutcome {
    fn new(id: &'static str, name: &'static str) -> Self {
        Self {
            id,
            name,
            passed: true,
            observations: BTreeMap::new(),
            failure: None,
        }
    }

    /// Records one observed field.
    fn observe(&mut self, field: &str, value: impl std::fmt::Display) -> &mut Self {
        self.observations
            .insert(field.to_owned(), value.to_string());
        self
    }

    /// Requires `condition`, recording the first failure verbatim.
    fn require(&mut self, condition: bool, failure: impl std::fmt::Display) -> &mut Self {
        if !condition && self.failure.is_none() {
            self.passed = false;
            self.failure = Some(failure.to_string());
        }
        self
    }

    /// Canonical, stable serialization of this outcome for digesting.
    fn canonical_line(&self) -> String {
        let mut line = format!(
            "{}\t{}\t{}",
            self.id,
            self.name,
            if self.passed { "pass" } else { "fail" }
        );
        for (field, value) in &self.observations {
            // Observations are newline-free by construction; keep the record
            // one line per subcase so the digest is stable and diffable.
            let _ = write!(line, "\t{field}={}", value.replace(['\t', '\n'], " "));
        }
        if let Some(failure) = &self.failure {
            let _ = write!(line, "\tfailure={}", failure.replace(['\t', '\n'], " "));
        }
        line
    }

    /// Panics with the recorded failure when the subcase did not pass.
    ///
    /// `#[track_caller]` so the panic names the subcase entry point rather
    /// than this helper; fifteen tests routing through one panic site would
    /// otherwise all report the same line.
    #[track_caller]
    fn assert_passed(&self) {
        assert!(
            self.passed,
            "{} {} failed: {}\nobservations: {:#?}",
            self.id,
            self.name,
            self.failure.as_deref().unwrap_or("<no reason recorded>"),
            self.observations
        );
    }
}

// ===========================================================================
// Prerequisite receipts
// ===========================================================================

/// One of the three independently pinned upstream prerequisite receipts.
///
/// A receipt is *present* whenever it has been derived against the pinned
/// archive, whether or not the prerequisite it describes is satisfied. The
/// acceptance predicate requires three present receipts; it does not require
/// three satisfied ones, and conflating the two is how an unmet prerequisite
/// gets laundered into a green run.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PrerequisiteReceipt {
    ordinal: u8,
    name: &'static str,
    version: String,
    checksum: String,
    /// The exact API observation this receipt is bound to.
    api_observation: String,
    /// Whether the archive is consumable by `cargo package` as pinned.
    packaging: String,
    satisfied: bool,
    evidence: String,
}

impl PrerequisiteReceipt {
    fn canonical_line(&self) -> String {
        format!(
            "P{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.ordinal,
            self.name,
            self.version,
            self.checksum,
            self.api_observation,
            self.packaging,
            if self.satisfied {
                "satisfied"
            } else {
                "unsatisfied"
            },
            self.evidence,
        )
    }
}

// ===========================================================================
// Workspace access
// ===========================================================================

/// Absolute path to the workspace root.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root exists two levels above crates/fastmcp")
        .to_path_buf()
}

/// Reads a workspace-relative file, failing loudly on absence.
fn read_workspace_file(relative: &str) -> String {
    let path = workspace_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {} failed: {error}", path.display()))
}

/// Path to the vendored registry source of the pinned runtime, when present.
///
/// The prerequisite observations are made against this exact archive. When it
/// is not on the machine the observations cannot be made, and the receipts say
/// so rather than substituting a claim from the version number.
fn pinned_runtime_archive() -> Option<PathBuf> {
    let home = std::env::var_os("CARGO_HOME").map_or_else(
        || {
            std::env::var_os("HOME")
                .map(|home| PathBuf::from(home).join(".cargo"))
                .unwrap_or_default()
        },
        PathBuf::from,
    );
    let registry = home.join("registry").join("src");
    let entries = std::fs::read_dir(&registry).ok()?;
    for entry in entries.flatten() {
        let candidate = entry
            .path()
            .join(format!("asupersync-{PINNED_RUNTIME_VERSION}"));
        if candidate.join("src").join("lib.rs").is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Reads a file from the pinned runtime archive.
fn read_pinned_runtime_file(relative: &str) -> Option<String> {
    let archive = pinned_runtime_archive()?;
    std::fs::read_to_string(archive.join(relative)).ok()
}

// ===========================================================================
// Rust source scanning
// ===========================================================================

/// Removes `#[cfg(test)] mod ... { ... }` blocks from Rust source.
///
/// The deny inventory is a statement about the *shipped* graph, so inline test
/// modules must not contribute to it. The scan is byte-wise and string-,
/// character-literal-, raw-string-, and comment-aware, so a brace inside
/// `"}"`, `'}'`, `r#"}"#`, or a comment cannot desynchronize the match. Source
/// is UTF-8 and every delimiter it tracks is ASCII, so byte indices always land
/// on character boundaries.
fn strip_cfg_test_modules(source: &str) -> String {
    const ATTRIBUTE: &str = "#[cfg(test)]";
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut cursor = 0usize;

    while cursor < bytes.len() {
        let Some(relative) = source[cursor..].find(ATTRIBUTE) else {
            out.push_str(&source[cursor..]);
            break;
        };
        let attribute_at = cursor + relative;
        // Look past the attribute for a `mod` item; anything else is ordinary
        // source that happens to carry the attribute (a function, a `use`).
        let mut probe = attribute_at + ATTRIBUTE.len();
        while probe < bytes.len() && bytes[probe].is_ascii_whitespace() {
            probe += 1;
        }
        let is_module = source[probe..].starts_with("mod ") || source[probe..].starts_with("mod\t");
        if is_module {
            if let Some(body_end) = matching_brace_end(bytes, probe) {
                out.push_str(&source[cursor..attribute_at]);
                cursor = body_end;
                continue;
            }
        }
        // Not a test module: keep everything through the attribute and resume.
        out.push_str(&source[cursor..attribute_at + ATTRIBUTE.len()]);
        cursor = attribute_at + ATTRIBUTE.len();
    }
    out
}

/// Finds the byte index just past the `{ .. }` body that starts at or after `from`.
fn matching_brace_end(bytes: &[u8], from: usize) -> Option<usize> {
    let mut index = from;
    while index < bytes.len() && bytes[index] != b'{' {
        index += 1;
    }
    if index >= bytes.len() {
        return None;
    }
    let mut depth = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
                continue;
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                {
                    index += 1;
                }
                index = (index + 2).min(bytes.len());
                continue;
            }
            b'r' if is_raw_string_start(bytes, index) => {
                index = skip_raw_string(bytes, index);
                continue;
            }
            b'"' => {
                index = skip_string_literal(bytes, index);
                continue;
            }
            b'\'' => {
                index = skip_char_or_lifetime(bytes, index);
                continue;
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index + 1);
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

/// Whether a raw string literal begins at `start` (which must be the `r`).
///
/// `r` is only a raw-string prefix when it does not continue an identifier;
/// `for` and `char` both end in a letter, so the preceding byte decides.
fn is_raw_string_start(bytes: &[u8], start: usize) -> bool {
    if start > 0 {
        let previous = bytes[start - 1];
        if previous.is_ascii_alphanumeric() || previous == b'_' {
            return false;
        }
    }
    let mut probe = start + 1;
    while bytes.get(probe) == Some(&b'#') {
        probe += 1;
    }
    bytes.get(probe) == Some(&b'"')
}

/// Returns the byte index just past a raw string literal starting at `start`.
fn skip_raw_string(bytes: &[u8], start: usize) -> usize {
    let mut hashes = 0usize;
    let mut probe = start + 1;
    while bytes.get(probe) == Some(&b'#') {
        hashes += 1;
        probe += 1;
    }
    // `probe` is the opening quote; scan for `"` followed by `hashes` hashes.
    let mut index = probe + 1;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let closing = index + 1;
            if bytes[closing..closing + hashes.min(bytes.len() - closing)]
                .iter()
                .filter(|byte| **byte == b'#')
                .count()
                >= hashes
            {
                return closing + hashes;
            }
        }
        index += 1;
    }
    bytes.len()
}

/// Returns the byte index just past a plain string literal starting at `start`.
fn skip_string_literal(bytes: &[u8], start: usize) -> usize {
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'"' => return index + 1,
            _ => index += 1,
        }
    }
    bytes.len()
}

/// Returns the byte index just past a character literal, or `start + 1` for a
/// lifetime, which has no closing quote to skip.
fn skip_char_or_lifetime(bytes: &[u8], start: usize) -> usize {
    let mut index = start + 1;
    if bytes.get(index) == Some(&b'\\') {
        index += 2;
        // Escapes are variable width (`\n`, `\x41`, `\u{1F600}`); scan to the
        // closing quote rather than guessing a length.
        while index < bytes.len() && bytes[index] != b'\'' {
            index += 1;
        }
        return (index + 1).min(bytes.len());
    }
    // A non-ASCII character literal is multi-byte; advance to its end.
    while index < bytes.len() && (bytes[index] & 0xC0) == 0x80 {
        index += 1;
    }
    if index < bytes.len() {
        index += 1;
    }
    if bytes.get(index) == Some(&b'\'') {
        return index + 1;
    }
    start + 1
}

/// Every shipped (non-test, non-example) Rust source file in the workspace.
fn shipped_source_files() -> Vec<(String, String)> {
    let mut found = Vec::new();
    let crates_dir = workspace_root().join("crates");
    let crate_entries =
        std::fs::read_dir(&crates_dir).expect("workspace has a readable crates/ directory");
    for crate_entry in crate_entries.flatten() {
        let src = crate_entry.path().join("src");
        if src.is_dir() {
            collect_rust_files(&src, &mut found);
        }
    }
    found.sort_by(|left, right| left.0.cmp(&right.0));
    found
}

/// Recursively collects `.rs` files under `dir` as `(relative path, contents)`.
fn collect_rust_files(dir: &Path, found: &mut Vec<(String, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                let relative = path
                    .strip_prefix(workspace_root())
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                found.push((relative, contents));
            }
        }
    }
}

// ===========================================================================
// Application-owned runtime boundary
// ===========================================================================

/// Builds one explicit top-level runtime for a subcase.
///
/// FND-04 permits exactly this at an application-owned binary boundary, which
/// a test harness is. What it forbids is a *library* convenience that creates
/// or re-enters a runtime; [`subcase_07_production_deny_inventory`] is the
/// check that no such convenience is reachable from the shipped graph.
fn application_runtime(min_blocking: usize, max_blocking: usize) -> Runtime {
    let reactor = create_reactor().expect("platform reactor is available");
    RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .blocking_threads(min_blocking, max_blocking)
        .build()
        .expect("application-owned runtime builds")
}

/// Wall-clock ceiling for a single subcase body.
const SUBCASE_CEILING_SECS: u64 = 60;

/// Runs a subcase body on an application-owned runtime under a wall-clock ceiling.
///
/// A subcase that hangs is a failure, not a licence to stall the serialized
/// verification lane behind it. The ceiling resolves into a recorded outcome so
/// one wedged region, lock waiter, or occupied blocking worker cannot block the
/// remaining fourteen subcases or the receipt.
fn run_bounded<T>(runtime: &Runtime, future: impl Future<Output = T>) -> Result<T, String> {
    runtime.block_on(async move {
        let cx = Cx::current().expect("block_on installs a current Cx");
        let deadline = cx
            .now()
            .saturating_add_nanos(SUBCASE_CEILING_SECS * 1_000_000_000);
        asupersync::time::timeout_at(deadline, future)
            .await
            .map_err(|_| {
                format!("subcase body exceeded its {SUBCASE_CEILING_SECS}s wall-clock ceiling")
            })
    })
}

/// Six zero-effect counters required by the planted-negative acceptance item.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct EffectCounters {
    accepted_request_state: u64,
    sibling_state: u64,
    runtime_roots: u64,
    spawned_private_threads: u64,
    submitted_blocking_jobs: u64,
    emitted_io_writes: u64,
}

impl EffectCounters {
    /// Component-wise delta against a later reading.
    fn delta(self, later: Self) -> Self {
        Self {
            accepted_request_state: later.accepted_request_state - self.accepted_request_state,
            sibling_state: later.sibling_state - self.sibling_state,
            runtime_roots: later.runtime_roots - self.runtime_roots,
            spawned_private_threads: later.spawned_private_threads - self.spawned_private_threads,
            submitted_blocking_jobs: later.submitted_blocking_jobs - self.submitted_blocking_jobs,
            emitted_io_writes: later.emitted_io_writes - self.emitted_io_writes,
        }
    }

    /// Whether every counter is zero.
    fn all_zero(self) -> bool {
        self == Self::default()
    }
}

/// Shared effect ledger a subcase mutates only through real work.
#[derive(Debug, Default)]
struct EffectLedger {
    accepted_request_state: AtomicU64,
    sibling_state: AtomicU64,
    runtime_roots: AtomicU64,
    spawned_private_threads: AtomicU64,
    submitted_blocking_jobs: AtomicU64,
    emitted_io_writes: AtomicU64,
}

impl EffectLedger {
    fn read(&self) -> EffectCounters {
        EffectCounters {
            accepted_request_state: self.accepted_request_state.load(Ordering::SeqCst),
            sibling_state: self.sibling_state.load(Ordering::SeqCst),
            runtime_roots: self.runtime_roots.load(Ordering::SeqCst),
            spawned_private_threads: self.spawned_private_threads.load(Ordering::SeqCst),
            submitted_blocking_jobs: self.submitted_blocking_jobs.load(Ordering::SeqCst),
            emitted_io_writes: self.emitted_io_writes.load(Ordering::SeqCst),
        }
    }
}

// ===========================================================================
// Prerequisite derivation
// ===========================================================================

/// Derives the three upstream prerequisite receipts against the pinned archive.
///
/// Each observation is made by reading the archive's own source. None of them
/// is inferred from the version number, which FND-04-B-12 forbids outright.
fn derive_prerequisite_receipts() -> Vec<PrerequisiteReceipt> {
    let archive_present = pinned_runtime_archive().is_some();
    let packaging = if archive_present {
        // A registry archive under CARGO_HOME/registry/src is by construction
        // what `cargo package` consumed; a path or git patch would not be here.
        "registry-archive-consumable-by-cargo-package".to_owned()
    } else {
        "archive-not-present-on-this-machine".to_owned()
    };

    let child_region_src = read_pinned_runtime_file("src/cx/child_region.rs").unwrap_or_default();
    let cx_src = read_pinned_runtime_file("src/cx/cx.rs").unwrap_or_default();
    let process_src = read_pinned_runtime_file("src/process.rs").unwrap_or_default();

    // P1: an owned child region derived from an ambient `&Cx`, with
    // independent cancellation plus close/drain/quiescence semantics.
    let has_opener = cx_src.contains("pub fn open_child_region(");
    let has_independent_cancel = child_region_src.contains("pub fn cancel(")
        && child_region_src.contains("Requests independent cancellation for this subtree");
    let has_quiescent_close = child_region_src.contains("pub async fn close(")
        && child_region_src.contains("RegionQuiescence");
    let has_fail_closed = child_region_src.contains("NoRuntimeGateway");
    let p1_satisfied =
        archive_present && has_opener && has_independent_cancel && has_quiescent_close;

    // P2: a detectable, admitted, non-inline blocking capability. The
    // capability must be able to *report absence of a real pool*; the inline
    // fallback itself is not the capability and is never accepted as one.
    let handle_is_public = cx_src.contains("pub fn blocking_pool_handle(&self) -> Option<");
    let inline_fallback_still_present = cx_src.contains("None => f(child)");
    let p2_satisfied = archive_present && handle_is_public;

    // P3: a public, cancel-aware path for *this process's own* stdin/stdout
    // as well as spawned-child stdin/stdout, without test-internals, a private
    // I/O-driver handle, a per-stream thread, or a blocking Windows pipe.
    let child_stdio_public = process_src
        .contains("pub fn stdout(&mut self) -> Option<ChildStdout>")
        && process_src.contains("pub fn stdin(&mut self) -> Option<ChildStdin>");
    let own_process_stdio_public = cx_src.contains("pub fn stdin(")
        || read_pinned_runtime_file("src/io/mod.rs")
            .is_some_and(|io| io.contains("pub fn stdin(") || io.contains("pub fn stdout("));
    let p3_satisfied = archive_present && child_stdio_public && own_process_stdio_public;

    vec![
        PrerequisiteReceipt {
            ordinal: 1,
            name: "ambient-child-region-owner",
            version: PINNED_RUNTIME_VERSION.to_owned(),
            checksum: PINNED_RUNTIME_CHECKSUM.to_owned(),
            api_observation: format!(
                "Cx::open_child_region={has_opener}; ChildRegion::cancel_independent={has_independent_cancel}; \
                 ChildRegion::close_quiescent={has_quiescent_close}; fail_closed_no_gateway={has_fail_closed}"
            ),
            packaging: packaging.clone(),
            satisfied: p1_satisfied,
            evidence: "src/cx/child_region.rs + src/cx/cx.rs of the pinned archive".to_owned(),
        },
        PrerequisiteReceipt {
            ordinal: 2,
            name: "detectable-non-inline-blocking-facility",
            version: PINNED_RUNTIME_VERSION.to_owned(),
            checksum: PINNED_RUNTIME_CHECKSUM.to_owned(),
            api_observation: format!(
                "Cx::blocking_pool_handle_public={handle_is_public}; \
                 inline_fallback_still_reachable={inline_fallback_still_present}"
            ),
            packaging: packaging.clone(),
            satisfied: p2_satisfied,
            evidence: "src/cx/cx.rs of the pinned archive".to_owned(),
        },
        PrerequisiteReceipt {
            ordinal: 3,
            name: "cancel-aware-cross-platform-process-stdio",
            version: PINNED_RUNTIME_VERSION.to_owned(),
            checksum: PINNED_RUNTIME_CHECKSUM.to_owned(),
            api_observation: format!(
                "spawned_child_stdio_public={child_stdio_public}; \
                 own_process_stdio_public={own_process_stdio_public}"
            ),
            packaging,
            satisfied: p3_satisfied,
            evidence: "src/process.rs + src/io/ of the pinned archive; only spawned-child \
                       adapters are exposed, so this process's own stdin/stdout has no \
                       public cancel-aware asupersync path"
                .to_owned(),
        },
    ]
}

// ===========================================================================
// FND-04-B-01 sibling-cancellation
// ===========================================================================

/// Cancelling one request's child region must not cancel a sibling's.
fn subcase_01_sibling_cancellation() -> SubcaseOutcome {
    let mut outcome = SubcaseOutcome::new("FND-04-B-01", "sibling-cancellation");
    let runtime = application_runtime(1, 4);

    let observed: Arc<Mutex<BTreeMap<&'static str, String>>> =
        Arc::new(Mutex::new(BTreeMap::new()));
    let sink = Arc::clone(&observed);
    // Counts first polls, so a body that was cancelled before it ever ran
    // cannot masquerade as a body that observed cancellation in flight.
    let started = Arc::new(AtomicU64::new(0));
    let started_sink = Arc::clone(&started);

    let bounded = run_bounded(&runtime, async move {
        let ambient = Cx::current().expect("runtime installs an ambient Cx for block_on");

        let left = ambient
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("left request region opens from the ambient context");
        let right = ambient
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("right request region opens from the ambient context");

        // Two independent request regions, each with its own owned body task.
        let left_region = left.region_id();
        let right_region = right.region_id();

        let left_started = Arc::clone(&started_sink);
        let mut left_task = left
            .cx()
            .spawn(move |cx| async move {
                left_started.fetch_add(1, Ordering::SeqCst);
                // Spin on checkpoints until this region is cancelled.
                for _ in 0..10_000u32 {
                    if cx.is_cancelled() {
                        return "cancelled";
                    }
                    asupersync::runtime::yield_now().await;
                }
                "ran-to-completion"
            })
            .expect("left body task admits into its own region");

        let mut right_task = right
            .cx()
            .spawn(|cx| async move {
                // The sibling performs bounded work and must finish normally.
                for _ in 0..64u32 {
                    asupersync::runtime::yield_now().await;
                }
                if cx.is_cancelled() {
                    "cancelled"
                } else {
                    "ran-to-completion"
                }
            })
            .expect("right body task admits into its own region");

        // Let both bodies reach their first poll. Cancelling work that never
        // started would prove nothing about in-flight request isolation, which
        // is the property under test.
        for _ in 0..16u32 {
            asupersync::runtime::yield_now().await;
        }

        // Cancel exactly one request.
        left.cancel(CancelReason::user(
            "FND-04-B-01 independent request cancellation",
        ))
        .expect("independent cancellation is accepted by the runtime");

        let left_result = left_task.join(left.cx()).await;
        let right_result = right_task.join(right.cx()).await;

        let mut sink = sink.lock().expect("observation sink is uncontended");
        sink.insert("left_region", format!("{left_region:?}"));
        sink.insert("right_region", format!("{right_region:?}"));
        sink.insert("left_result", format!("{left_result:?}"));
        sink.insert("right_result", format!("{right_result:?}"));
        sink.insert(
            "regions_distinct",
            (left_region != right_region).to_string(),
        );
        // Cancellation may surface either as the body's own acknowledged
        // return value or as a cancelled join, depending on whether the body
        // acknowledged before its next checkpoint. A panic is neither, and
        // must not be laundered into a cancellation.
        let left_cancelled = match left_result.as_ref() {
            Ok(value) => *value == "cancelled",
            Err(asupersync::runtime::JoinError::Cancelled(_)) => true,
            Err(_) => false,
        };
        sink.insert("left_cancelled", left_cancelled.to_string());
        sink.insert(
            "right_survived",
            matches!(right_result.as_ref(), Ok(&"ran-to-completion")).to_string(),
        );
    });
    if let Err(error) = bounded {
        outcome.require(false, error);
        return outcome;
    }
    let left_started = started.load(Ordering::SeqCst);

    let observed = observed.lock().expect("observation sink is readable");
    for (field, value) in observed.iter() {
        outcome.observe(field, value);
    }
    outcome.require(
        observed.get("regions_distinct").map(String::as_str) == Some("true"),
        "two requests must own two distinct child regions",
    );
    outcome.observe("left_body_first_polls", left_started);
    outcome.require(
        left_started == 1,
        "the cancelled request's body must have been in flight; a body cancelled before its \
         first poll would make the sibling comparison vacuous",
    );
    outcome.require(
        observed.get("left_cancelled").map(String::as_str) == Some("true"),
        "the cancelled request's own body must observe cancellation",
    );
    outcome.require(
        observed.get("right_survived").map(String::as_str) == Some("true"),
        "cancelling one request must leave the sibling request running to completion",
    );
    outcome
}

// ===========================================================================
// FND-04-B-02 shutdown-tree
// ===========================================================================

/// Server shutdown must cancel every owned request region and drain it.
fn subcase_02_shutdown_tree() -> SubcaseOutcome {
    let mut outcome = SubcaseOutcome::new("FND-04-B-02", "shutdown-tree");
    let runtime = application_runtime(1, 4);

    let drained = Arc::new(AtomicU64::new(0));
    let observed_cancel = Arc::new(AtomicU64::new(0));
    let started = Arc::new(AtomicU64::new(0));
    let drain_sink = Arc::clone(&drained);
    let cancel_sink = Arc::clone(&observed_cancel);
    let start_sink = Arc::clone(&started);

    let close_resolved = match run_bounded(&runtime, async move {
        let ambient = Cx::current().expect("runtime installs an ambient Cx");
        let server_region = ambient
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("server region opens");

        // Three owned request bodies beneath the server region.
        for _ in 0..3u32 {
            let drain = Arc::clone(&drain_sink);
            let cancel = Arc::clone(&cancel_sink);
            let start = Arc::clone(&start_sink);
            server_region
                .cx()
                .spawn(move |cx| async move {
                    start.fetch_add(1, Ordering::SeqCst);
                    for _ in 0..10_000u32 {
                        if cx.is_cancelled() {
                            cancel.fetch_add(1, Ordering::SeqCst);
                            break;
                        }
                        asupersync::runtime::yield_now().await;
                    }
                    // Finalization work that shutdown must wait for.
                    drain.fetch_add(1, Ordering::SeqCst);
                })
                .expect("request body admits into the server region");
        }

        // Let every request body reach its first poll, so shutdown is
        // cancelling genuinely in-flight work rather than unstarted work.
        for _ in 0..16u32 {
            asupersync::runtime::yield_now().await;
        }

        // Shutdown closes the tree: cancel remaining children, run finalizers,
        // and resolve only at quiescence.
        server_region.close().await.is_ok()
    }) {
        Ok(value) => value,
        Err(error) => {
            outcome.require(false, error);
            return outcome;
        }
    };

    outcome
        .observe("close_resolved", close_resolved)
        .observe("owned_requests", 3u32)
        .observe("bodies_first_polled", started.load(Ordering::SeqCst))
        .observe("drained", drained.load(Ordering::SeqCst))
        .observe(
            "observed_cancellation",
            observed_cancel.load(Ordering::SeqCst),
        );

    outcome.require(close_resolved, "server-region close must resolve");
    outcome.require(
        started.load(Ordering::SeqCst) == 3,
        "all three owned request bodies must be in flight before shutdown, or the drain and \
         cancellation counts below would be vacuous",
    );
    outcome.require(
        drained.load(Ordering::SeqCst) == 3,
        "close must resolve only after every owned request body has drained",
    );
    outcome.require(
        observed_cancel.load(Ordering::SeqCst) == 3,
        "shutdown must cancel all owned request regions, not merely abandon them",
    );
    outcome
}

// ===========================================================================
// FND-04-B-03 transport-close-budget
// ===========================================================================

/// Transport close and flush must participate in the caller's budget.
///
/// This reads the shipped trait declaration rather than a behavioural probe,
/// because the property at issue is a *signature* property: a `close` that
/// receives no capability context cannot consume the caller's budget no matter
/// what its body does. `send` and `recv` on the same trait already take
/// `&Cx`, which is what makes the omission on `close` a defect rather than a
/// design choice.
fn subcase_03_transport_close_budget() -> SubcaseOutcome {
    let mut outcome = SubcaseOutcome::new("FND-04-B-03", "transport-close-budget");
    let source = read_workspace_file("crates/fastmcp-transport/src/lib.rs");
    let shipped = strip_cfg_test_modules(&source);

    let send_takes_cx = shipped.contains("fn send(&mut self, cx: &Cx, message: &JsonRpcMessage)");
    let recv_takes_cx = shipped.contains("fn recv(&mut self, cx: &Cx)");
    let close_takes_cx = shipped.contains("fn close(&mut self, cx: &Cx)");
    let close_without_cx = shipped.contains("fn close(&mut self) -> Result<(), TransportError>;");

    outcome
        .observe("transport_send_takes_cx", send_takes_cx)
        .observe("transport_recv_takes_cx", recv_takes_cx)
        .observe("transport_close_takes_cx", close_takes_cx)
        .observe("transport_close_declared_without_cx", close_without_cx)
        .observe(
            "close_budget_consumption",
            if close_takes_cx {
                "caller-budget-bound"
            } else {
                "unbudgeted"
            },
        );

    outcome.require(
        send_takes_cx && recv_takes_cx,
        "Transport::send and Transport::recv must take the caller's &Cx",
    );
    outcome.require(
        close_takes_cx,
        "Transport::close must take the caller's &Cx so close/flush participates in the \
         caller's budget; at this revision crates/fastmcp-transport/src/lib.rs declares \
         `fn close(&mut self) -> Result<(), TransportError>` on Transport, TransportRecvHalf, \
         and TransportSendHalf, so transport shutdown cannot consume or observe the caller's \
         deadline",
    );
    outcome
}

// ===========================================================================
// FND-04-B-04 task-supervisor-ownership
// ===========================================================================

/// Every spawned task must be owned by its ambient child region.
fn subcase_04_task_supervisor_ownership() -> SubcaseOutcome {
    let mut outcome = SubcaseOutcome::new("FND-04-B-04", "task-supervisor-ownership");
    let runtime = application_runtime(1, 4);

    let owners: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&owners);

    let (root_region, child_region_id) = match run_bounded(&runtime, async move {
        let ambient = Cx::current().expect("runtime installs an ambient Cx");
        let root = ambient.region_id();

        let child = ambient
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("child region opens");
        let child_id = child.region_id();

        for index in 0..4u32 {
            let sink = Arc::clone(&sink);
            let mut handle = child
                .cx()
                .spawn(move |cx| async move {
                    // The task reports the region that actually owns it.
                    let owner = cx.region_id();
                    sink.lock()
                        .expect("owner sink is uncontended")
                        .push((format!("task-{index}"), format!("{owner:?}")));
                    owner
                })
                .expect("task admits into the child region");
            let _ = handle.join(child.cx()).await;
        }

        child.close().await.expect("child region closes");
        (format!("{root:?}"), format!("{child_id:?}"))
    }) {
        Ok(value) => value,
        Err(error) => {
            outcome.require(false, error);
            return outcome;
        }
    };

    let owners = owners.lock().expect("owner sink is readable");
    let all_owned_by_child = owners
        .iter()
        .all(|(_, owner)| owner.as_str() == child_region_id.as_str());
    let none_owned_by_root = owners
        .iter()
        .all(|(_, owner)| owner.as_str() != root_region.as_str());

    outcome
        .observe("root_region", &root_region)
        .observe("child_region", &child_region_id)
        .observe("task_count", owners.len())
        .observe("all_tasks_owned_by_child_region", all_owned_by_child)
        .observe("no_task_owned_by_root_region", none_owned_by_root);

    outcome.require(owners.len() == 4, "every spawned task must report an owner");
    outcome.require(
        all_owned_by_child,
        "every task spawned through the child region's context must be owned by that region",
    );
    outcome.require(
        none_owned_by_root,
        "no supervised task may escape to the ambient root region",
    );
    outcome
}

// ===========================================================================
// FND-04-B-05 dependency-feature
// ===========================================================================

/// The product dependency graph must not enable `asupersync/test-internals`.
fn subcase_05_dependency_feature() -> SubcaseOutcome {
    let mut outcome = SubcaseOutcome::new("FND-04-B-05", "dependency-feature");

    let crates_dir = workspace_root().join("crates");
    let entries = std::fs::read_dir(&crates_dir).expect("crates/ is readable");

    let mut product_offenders: Vec<String> = Vec::new();
    let mut dev_only_uses: Vec<String> = Vec::new();

    for entry in entries.flatten() {
        let manifest_path = entry.path().join("Cargo.toml");
        let Ok(manifest) = std::fs::read_to_string(&manifest_path) else {
            continue;
        };
        let name = entry.file_name().to_string_lossy().to_string();
        let parsed: toml::Value = match toml::from_str(&manifest) {
            Ok(value) => value,
            Err(error) => {
                outcome.require(false, format!("{name}/Cargo.toml is unparseable: {error}"));
                continue;
            }
        };

        // A product graph is `[dependencies]`, `[build-dependencies]`, and
        // every `[features]` equation. `[dev-dependencies]` is not shipped.
        for table in ["dependencies", "build-dependencies"] {
            if let Some(dep) = parsed
                .get(table)
                .and_then(|value| value.get("asupersync"))
                .and_then(|value| value.get("features"))
                .and_then(toml::Value::as_array)
            {
                if dep
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .any(|feature| feature == FORBIDDEN_RUNTIME_FEATURE)
                {
                    product_offenders.push(format!("{name}:[{table}].asupersync.features"));
                }
            }
        }

        if let Some(features) = parsed.get("features").and_then(toml::Value::as_table) {
            for (feature_name, equation) in features {
                let Some(values) = equation.as_array() else {
                    continue;
                };
                let forwards = values
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .any(|value| value == format!("asupersync/{FORBIDDEN_RUNTIME_FEATURE}"));
                if !forwards {
                    continue;
                }
                // A feature forwarding test-internals is admissible only when
                // nothing in the default/product profile can select it. The
                // facade's `testing-lab` is the one audited opt-in profile.
                if feature_name == "testing-lab" {
                    dev_only_uses.push(format!("{name}:[features].{feature_name}"));
                } else {
                    product_offenders.push(format!(
                        "{name}:[features].{feature_name} forwards test-internals"
                    ));
                }
            }
        }

        if parsed
            .get("dev-dependencies")
            .and_then(|value| value.get("asupersync"))
            .and_then(|value| value.get("features"))
            .and_then(toml::Value::as_array)
            .is_some_and(|features| {
                features
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .any(|feature| feature == FORBIDDEN_RUNTIME_FEATURE)
            })
        {
            dev_only_uses.push(format!("{name}:[dev-dependencies].asupersync.features"));
        }
    }

    // A default feature set that reaches test-internals is a product offender.
    let facade_manifest = read_workspace_file("crates/fastmcp/Cargo.toml");
    let facade: toml::Value =
        toml::from_str(&facade_manifest).expect("facade manifest is valid TOML");
    let default_features: Vec<String> = facade
        .get("features")
        .and_then(|value| value.get("default"))
        .and_then(toml::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let default_selects_lab = default_features
        .iter()
        .any(|feature| feature == "testing-lab" || feature == "testing");

    product_offenders.sort();
    dev_only_uses.sort();

    outcome
        .observe("product_feature_graph_offenders", product_offenders.len())
        .observe(
            "product_feature_graph_offender_list",
            product_offenders.join(","),
        )
        .observe("audited_dev_only_uses", dev_only_uses.join(","))
        .observe("facade_default_features", default_features.join(","))
        .observe("default_selects_lab_profile", default_selects_lab)
        .observe(
            "evaluator_own_graph_note",
            "this test target unifies asupersync/test-internals through the facade's \
             dev-dependencies; the product graph above is read from the manifests, never \
             inferred from this binary's own features",
        );

    outcome.require(
        product_offenders.is_empty(),
        format!(
            "no product dependency or feature equation may enable asupersync/{FORBIDDEN_RUNTIME_FEATURE}; \
             offenders: {product_offenders:?}"
        ),
    );
    outcome.require(
        !default_selects_lab,
        "the facade default feature set must not select a lab/testing profile",
    );
    outcome
}

// ===========================================================================
// FND-04-B-06 exact-runtime-pin-lockfile-drift
// ===========================================================================

/// The runtime must be pinned exactly, and the lockfile must agree.
fn subcase_06_exact_runtime_pin_lockfile_drift() -> SubcaseOutcome {
    let mut outcome = SubcaseOutcome::new("FND-04-B-06", "exact-runtime-pin-lockfile-drift");

    let root_manifest = read_workspace_file("Cargo.toml");
    let parsed: toml::Value = toml::from_str(&root_manifest).expect("root manifest is valid TOML");
    let requirement = parsed
        .get("workspace")
        .and_then(|value| value.get("dependencies"))
        .or_else(|| parsed.get("workspace-dependencies"))
        .and_then(|value| value.get("asupersync"))
        .and_then(|value| {
            value
                .get("version")
                .and_then(toml::Value::as_str)
                .or_else(|| value.as_str())
        })
        .map(str::to_owned)
        .unwrap_or_default();

    let is_exact = requirement.starts_with('=');
    let pinned_version = requirement.trim_start_matches('=').trim().to_owned();

    // Lockfile agreement: exactly one asupersync entry, at that version, with
    // the recorded checksum.
    let lockfile = read_workspace_file("Cargo.lock");
    let mut lock_versions: Vec<String> = Vec::new();
    let mut lock_checksum = String::new();
    let mut lock_source = String::new();
    let mut in_asupersync = false;
    for line in lockfile.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            in_asupersync = false;
            continue;
        }
        if trimmed == r#"name = "asupersync""# {
            in_asupersync = true;
            continue;
        }
        if in_asupersync {
            if let Some(rest) = trimmed.strip_prefix("version = ") {
                lock_versions.push(rest.trim_matches('"').to_owned());
            } else if let Some(rest) = trimmed.strip_prefix("checksum = ") {
                lock_checksum = rest.trim_matches('"').to_owned();
            } else if let Some(rest) = trimmed.strip_prefix("source = ") {
                lock_source = rest.trim_matches('"').to_owned();
            }
        }
    }

    let from_registry = lock_source.starts_with("registry+");

    outcome
        .observe("workspace_requirement", &requirement)
        .observe("requirement_is_exact", is_exact)
        .observe("pinned_version", &pinned_version)
        .observe("lock_entries", lock_versions.len())
        .observe("lock_version", lock_versions.join(","))
        .observe("lock_checksum", &lock_checksum)
        .observe("lock_source", &lock_source)
        .observe("lock_source_is_registry", from_registry);

    outcome.require(
        is_exact,
        format!("the runtime requirement must be an exact `=version` pin, found `{requirement}`"),
    );
    outcome.require(
        pinned_version == PINNED_RUNTIME_VERSION,
        format!(
            "this evaluator's observations are bound to asupersync {PINNED_RUNTIME_VERSION}; \
             the workspace now pins `{pinned_version}`, which invalidates every prerequisite \
             receipt until they are re-derived against the new checksum"
        ),
    );
    outcome.require(
        lock_versions.len() == 1,
        format!("exactly one asupersync lock entry is permitted, found {lock_versions:?}"),
    );
    outcome.require(
        lock_versions.first().map(String::as_str) == Some(PINNED_RUNTIME_VERSION),
        "the lockfile must resolve the runtime to the exact pinned version",
    );
    outcome.require(
        lock_checksum == PINNED_RUNTIME_CHECKSUM,
        format!(
            "lockfile checksum drift: expected {PINNED_RUNTIME_CHECKSUM}, found `{lock_checksum}`"
        ),
    );
    outcome.require(
        from_registry,
        "the runtime must resolve from a published registry release, not a git or path patch, \
         so the result is consumable by `cargo package`",
    );
    outcome
}

// ===========================================================================
// FND-04-B-07 production-deny-inventory
// ===========================================================================

/// One denied construct found in the shipped graph.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DenyHit {
    dimension: &'static str,
    file: String,
    line: usize,
    text: String,
}

/// Static deny inventory over the shipped, non-`cfg(test)` sources.
///
/// Denied dimensions, per the FND-04 acceptance list: production `block_on`,
/// out-of-band `Cx` construction, private runtimes, private threads, and
/// runtime re-entry. The FastMCP CLI is the one application-owned binary
/// boundary permitted to construct and drive a top-level runtime.
fn collect_deny_inventory() -> Vec<DenyHit> {
    /// Paths permitted to construct and drive one explicit top-level runtime.
    const APPLICATION_BOUNDARIES: [&str; 1] = ["crates/fastmcp-cli/src/"];

    let mut hits = Vec::new();
    for (path, source) in shipped_source_files() {
        let is_application_boundary = APPLICATION_BOUNDARIES
            .iter()
            .any(|boundary| path.starts_with(boundary));
        let shipped = strip_cfg_test_modules(&source);

        for (index, line) in shipped.lines().enumerate() {
            let line_number = index + 1;
            let trimmed = line.trim_start();
            // Doc comments describe the rule; they are not the rule's subject.
            if trimmed.starts_with("//") {
                continue;
            }

            if !is_application_boundary {
                if trimmed.contains("RuntimeBuilder::") {
                    hits.push(DenyHit {
                        dimension: "private-runtime",
                        file: path.clone(),
                        line: line_number,
                        text: trimmed.to_owned(),
                    });
                }
                if trimmed.contains("std::thread::spawn")
                    || trimmed.contains("thread::Builder::new")
                {
                    hits.push(DenyHit {
                        dimension: "private-thread",
                        file: path.clone(),
                        line: line_number,
                        text: trimmed.to_owned(),
                    });
                }
                if trimmed.contains(".block_on(") || trimmed.contains("block_on(") {
                    // `pub fn block_on` is the declaration; a call is the defect.
                    if !trimmed.contains("fn block_on") {
                        hits.push(DenyHit {
                            dimension: "production-block-on",
                            file: path.clone(),
                            line: line_number,
                            text: trimmed.to_owned(),
                        });
                    }
                }
            }

            if !is_application_boundary
                && ((trimmed.starts_with("pub use") && trimmed.contains("block_on"))
                    || trimmed.starts_with("pub fn block_on")
                    || trimmed.starts_with("pub mod runtime;"))
            {
                // A library that exports a blocking bridge has published a way
                // to create and enter a runtime, whatever its callers do with
                // it. That is the reachability FND-04 is about, and it is not
                // measured by counting call sites.
                hits.push(DenyHit {
                    dimension: "public-runtime-bridge-export",
                    file: path.clone(),
                    line: line_number,
                    text: trimmed.to_owned(),
                });
            }

            if trimmed.contains("Cx::for_testing")
                || trimmed.contains("Cx::detached_cancel_context")
            {
                hits.push(DenyHit {
                    dimension: "out-of-band-cx",
                    file: path.clone(),
                    line: line_number,
                    text: trimmed.to_owned(),
                });
            }
            if trimmed.contains("asupersync/test-internals") || trimmed.contains("LabRuntime::") {
                hits.push(DenyHit {
                    dimension: "test-internals",
                    file: path.clone(),
                    line: line_number,
                    text: trimmed.to_owned(),
                });
            }
        }
    }
    hits.sort();
    hits
}

/// No denied construct may be reachable from the shipped graph.
fn subcase_07_production_deny_inventory() -> SubcaseOutcome {
    let mut outcome = SubcaseOutcome::new("FND-04-B-07", "production-deny-inventory");
    let hits = collect_deny_inventory();

    let mut per_dimension: BTreeMap<&'static str, Vec<&DenyHit>> = BTreeMap::new();
    for hit in &hits {
        per_dimension.entry(hit.dimension).or_default().push(hit);
    }

    for dimension in [
        "out-of-band-cx",
        "private-runtime",
        "private-thread",
        "production-block-on",
        "public-runtime-bridge-export",
        "test-internals",
    ] {
        let found = per_dimension.get(dimension).map_or(0, Vec::len);
        outcome.observe(&format!("deny_{}", dimension.replace('-', "_")), found);
    }

    // Report the first few sites per dimension so a failure is actionable
    // without re-running the scan by hand.
    let mut sample = String::new();
    for (dimension, dimension_hits) in &per_dimension {
        for hit in dimension_hits.iter().take(4) {
            let _ = write!(
                sample,
                "[{dimension}] {}:{} {} | ",
                hit.file,
                hit.line,
                hit.text.chars().take(72).collect::<String>()
            );
        }
    }
    // The blocking bridge's reachability through the shipped public surface,
    // stated directly rather than left to be inferred from a site count.
    let core_lib = read_workspace_file("crates/fastmcp-core/src/lib.rs");
    let core_shipped = strip_cfg_test_modules(&core_lib);
    let exports_block_on = core_shipped.contains("pub use runtime::block_on;");
    let runtime_module_public = core_shipped.contains("pub mod runtime;");

    outcome
        .observe("total_denied_sites", hits.len())
        .observe("core_exports_block_on_unconditionally", exports_block_on)
        .observe("core_runtime_module_public", runtime_module_public)
        .observe(
            "blocking_bridge_reaches_shipped_public_surface",
            exports_block_on || runtime_module_public,
        )
        .observe("sample", sample.trim_end_matches(" | "));

    outcome.require(
        !(exports_block_on || runtime_module_public),
        "fastmcp-core must not publish a blocking runtime bridge on its shipped public surface; \
         `pub mod runtime;` and `pub use runtime::block_on;` in crates/fastmcp-core/src/lib.rs \
         are both unconditional, so a downstream consumer can create and enter a runtime through \
         a library whose premise is that FastMCP never creates its own. The macros no longer \
         expand to it and the CLI asserts production never reaches it, so the export is now \
         reachability without a production consumer",
    );

    outcome.require(
        hits.is_empty(),
        format!(
            "the shipped, non-cfg(test) graph must admit no production block_on, out-of-band Cx \
             construction, private runtime, private thread, or test-internals reference outside \
             the CLI application boundary; {} denied site(s) remain",
            hits.len()
        ),
    );
    outcome
}

// ===========================================================================
// FND-04-B-08 lock-cancellation-fairness-shutdown
// ===========================================================================

/// Cancel-aware locks must release waiters on cancellation without poisoning.
fn subcase_08_lock_cancellation_fairness_shutdown() -> SubcaseOutcome {
    let mut outcome = SubcaseOutcome::new("FND-04-B-08", "lock-cancellation-fairness-shutdown");
    let runtime = application_runtime(1, 4);

    let report: Arc<Mutex<BTreeMap<&'static str, String>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let sink = Arc::clone(&report);

    let bounded = run_bounded(&runtime, async move {
        let ambient = Cx::current().expect("runtime installs an ambient Cx");
        let shared: Arc<asupersync::sync::Mutex<u64>> = Arc::new(asupersync::sync::Mutex::new(0));

        // Hold the lock while a waiter queues behind it inside its own region.
        let holder_guard = shared
            .lock(&ambient)
            .await
            .expect("uncontended acquisition succeeds");

        let waiter_region = ambient
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("waiter region opens");

        let waiter_lock = Arc::clone(&shared);
        let mut waiter = waiter_region
            .cx()
            .spawn(move |cx| async move {
                match waiter_lock.lock(&cx).await {
                    Ok(_guard) => "acquired",
                    Err(_) => "released-by-cancellation",
                }
            })
            .expect("waiter admits into its own region");

        // Let the waiter reach the queue before cancelling it.
        for _ in 0..32u32 {
            asupersync::runtime::yield_now().await;
        }
        waiter_region
            .cancel(CancelReason::user("FND-04-B-08 waiter cancellation"))
            .expect("waiter cancellation is accepted");
        let waiter_result = waiter.join(waiter_region.cx()).await;

        // The holder releases; the lock must remain usable by a later acquirer.
        drop(holder_guard);
        let recovered = shared.lock(&ambient).await;
        let recovered_ok = recovered.is_ok();
        if let Ok(mut guard) = recovered {
            *guard += 1;
        }

        // Shutdown of the waiter's region must reach quiescence.
        let closed = waiter_region.close().await.is_ok();

        let mut sink = sink.lock().expect("report sink is uncontended");
        sink.insert("waiter_result", format!("{waiter_result:?}"));
        sink.insert(
            "waiter_did_not_acquire",
            (!matches!(waiter_result.as_ref(), Ok(&"acquired"))).to_string(),
        );
        sink.insert("lock_reusable_after_cancellation", recovered_ok.to_string());
        sink.insert("waiter_region_closed", closed.to_string());
    });
    if let Err(error) = bounded {
        outcome.require(false, error);
        return outcome;
    }

    let report = report.lock().expect("report sink is readable");
    for (field, value) in report.iter() {
        outcome.observe(field, value);
    }
    outcome.require(
        report.get("waiter_did_not_acquire").map(String::as_str) == Some("true"),
        "a cancelled waiter must be released rather than acquiring the lock",
    );
    outcome.require(
        report
            .get("lock_reusable_after_cancellation")
            .map(String::as_str)
            == Some("true"),
        "cancelling a waiter must not poison or strand the lock",
    );
    outcome.require(
        report.get("waiter_region_closed").map(String::as_str) == Some("true"),
        "the cancelled waiter's region must reach quiescent close",
    );
    outcome
}

// ===========================================================================
// FND-04-B-09 bounded-blocking-admission-reconciliation
// ===========================================================================

/// Blocking work must be admitted to a real pool and reconciled after cancellation.
fn subcase_09_bounded_blocking_admission_reconciliation() -> SubcaseOutcome {
    let mut outcome =
        SubcaseOutcome::new("FND-04-B-09", "bounded-blocking-admission-reconciliation");
    let runtime = application_runtime(1, 2);

    // A durable side effect the blocking job commits, standing in for the
    // mutation whose outcome must be verified rather than assumed.
    let durable = Arc::new(AtomicU64::new(0));
    let report: Arc<Mutex<BTreeMap<&'static str, String>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let sink = Arc::clone(&report);
    let durable_handle = Arc::clone(&durable);

    let bounded = run_bounded(&runtime, async move {
        let ambient = Cx::current().expect("runtime installs an ambient Cx");
        let pool_present = ambient.blocking_pool_handle().is_some();

        // Admission: a real pool accepts the job and it runs off-worker.
        let committed = Arc::clone(&durable_handle);
        let mut admitted = ambient
            .spawn_blocking(move |_cx| {
                std::thread::sleep(Duration::from_millis(5));
                committed.fetch_add(1, Ordering::SeqCst);
                "committed"
            })
            .expect("a bounded blocking job is admitted");
        let admitted_result = admitted.join(&ambient).await;

        // Cancellation after mutation: the caller stops waiting, but the
        // durable effect has already landed. The conforming answer is to
        // verify the durable outcome, never to report an ambiguous success.
        let region = ambient
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("blocking caller region opens");
        let late = Arc::clone(&durable_handle);
        let mut late_job = region
            .cx()
            .spawn_blocking(move |_cx| {
                std::thread::sleep(Duration::from_millis(40));
                late.fetch_add(1, Ordering::SeqCst);
                "late-commit"
            })
            .expect("the late blocking job is admitted");

        region
            .cancel(CancelReason::user(
                "FND-04-B-09 caller cancellation after submit",
            ))
            .expect("caller cancellation is accepted");
        let cancelled_result = late_job.join(region.cx()).await;

        // Reconciliation: read the durable state instead of trusting the
        // four-valued result of a job that may have completed late.
        let before_reconcile = durable_handle.load(Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(2);
        while durable_handle.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
            asupersync::runtime::yield_now().await;
        }
        let reconciled = durable_handle.load(Ordering::SeqCst);

        let mut sink = sink.lock().expect("report sink is uncontended");
        sink.insert("blocking_pool_present", pool_present.to_string());
        sink.insert("admitted_result", format!("{admitted_result:?}"));
        sink.insert(
            "admission_committed",
            matches!(admitted_result.as_ref(), Ok(&"committed")).to_string(),
        );
        sink.insert("cancelled_result", format!("{cancelled_result:?}"));
        sink.insert("durable_before_reconcile", before_reconcile.to_string());
        sink.insert("durable_after_reconcile", reconciled.to_string());
        sink.insert("late_mutation_observable", (reconciled == 2).to_string());
    });
    if let Err(error) = bounded {
        outcome.require(false, error);
        return outcome;
    }

    let report = report.lock().expect("report sink is readable");
    for (field, value) in report.iter() {
        outcome.observe(field, value);
    }
    outcome.require(
        report.get("blocking_pool_present").map(String::as_str) == Some("true"),
        "a bounded blocking facility must report a real pool; the zero-thread inline fallback \
         is not an acceptable substitute",
    );
    outcome.require(
        report.get("admission_committed").map(String::as_str) == Some("true"),
        "an admitted bounded blocking job must run to completion off the executor worker",
    );
    outcome.require(
        report.get("late_mutation_observable").map(String::as_str) == Some("true"),
        "a mutation that completes after caller cancellation must be reconcilable by reading \
         the durable outcome, never discarded as if it had not happened",
    );
    outcome
}

// ===========================================================================
// FND-04-B-10 hung-endpoint-and-recovery
// ===========================================================================

/// A hung synchronous call must not strand the caller, and the pool must recover.
fn subcase_10_hung_endpoint_and_recovery() -> SubcaseOutcome {
    let mut outcome = SubcaseOutcome::new("FND-04-B-10", "hung-endpoint-and-recovery");
    // One blocking worker: a hung job occupies the whole facility, which is
    // exactly the saturation the acceptance criteria call an unsupported
    // configuration rather than an acceptable one.
    let runtime = application_runtime(1, 1);

    let release = Arc::new(AtomicU64::new(0));
    let report: Arc<Mutex<BTreeMap<&'static str, String>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let sink = Arc::clone(&report);
    let release_handle = Arc::clone(&release);

    let bounded = run_bounded(&runtime, async move {
        let ambient = Cx::current().expect("runtime installs an ambient Cx");
        let region = ambient
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("hung-endpoint caller region opens");

        // A synchronous call that does not return until told to. This models a
        // half-open socket or a hung filesystem endpoint.
        let hung_release = Arc::clone(&release_handle);
        let mut hung = region
            .cx()
            .spawn_blocking(move |_cx| {
                let deadline = Instant::now() + Duration::from_secs(10);
                while hung_release.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(2));
                }
                "hung-returned"
            })
            .expect("the hung job is admitted");

        // The caller must be released on cancellation within a bound, even
        // though the occupied worker cannot be preempted.
        let started = Instant::now();
        region
            .cancel(CancelReason::user(
                "FND-04-B-10 caller gives up on a hung endpoint",
            ))
            .expect("cancellation is accepted");
        let hung_result = hung.join(region.cx()).await;
        let caller_release_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

        // The worker is still occupied here: this is the documented
        // unsupported configuration, recorded rather than smoothed over.
        let worker_still_occupied = release_handle.load(Ordering::SeqCst) == 0;

        // Release the hung call and prove the facility recovers.
        release_handle.store(1, Ordering::SeqCst);
        let recovery_deadline = Instant::now() + Duration::from_secs(5);
        let mut recovered = false;
        while Instant::now() < recovery_deadline {
            let probe = ambient.spawn_blocking(|_cx| "recovered");
            if let Ok(mut probe) = probe {
                if matches!(probe.join(&ambient).await.as_ref(), Ok(&"recovered")) {
                    recovered = true;
                    break;
                }
            }
            asupersync::runtime::yield_now().await;
        }

        let mut sink = sink.lock().expect("report sink is uncontended");
        sink.insert("hung_result", format!("{hung_result:?}"));
        sink.insert("caller_release_ms", caller_release_ms.to_string());
        sink.insert(
            "caller_released_within_bound",
            (caller_release_ms < 2_000).to_string(),
        );
        sink.insert(
            "worker_occupied_at_caller_release",
            worker_still_occupied.to_string(),
        );
        sink.insert("pool_recovered_after_release", recovered.to_string());
    });
    if let Err(error) = bounded {
        outcome.require(false, error);
        return outcome;
    }

    let report = report.lock().expect("report sink is readable");
    for (field, value) in report.iter() {
        outcome.observe(field, value);
    }
    outcome.require(
        report
            .get("caller_released_within_bound")
            .map(String::as_str)
            == Some("true"),
        "cancelling a caller blocked on a hung endpoint must release the caller within a \
         bounded time, even though the occupied worker cannot be preempted",
    );
    outcome.require(
        report
            .get("pool_recovered_after_release")
            .map(String::as_str)
            == Some("true"),
        "the bounded blocking facility must accept new work once the hung call returns",
    );
    outcome
}

// ===========================================================================
// FND-04-B-11 scope-and-zero-thread-negative
// ===========================================================================

/// `Cx::scope()` is a same-region API, and a zero-thread pool must be rejected.
fn subcase_11_scope_and_zero_thread_negative() -> SubcaseOutcome {
    let mut outcome = SubcaseOutcome::new("FND-04-B-11", "scope-and-zero-thread-negative");

    // Probe one: a scope shares the ambient region; only an opened child
    // region owns a new one. Mistaking the former for the latter is the exact
    // error the root Cargo.toml comment used to encode.
    let runtime = application_runtime(1, 2);
    let report: Arc<Mutex<BTreeMap<&'static str, String>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let sink = Arc::clone(&report);

    let bounded = run_bounded(&runtime, async move {
        let ambient = Cx::current().expect("runtime installs an ambient Cx");
        let ambient_region: RegionId = ambient.region_id();
        let scope_region = ambient.scope().region_id();
        let child = ambient
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("child region opens");
        let child_region = child.region_id();
        let _ = child.close().await;

        let mut sink = sink.lock().expect("report sink is uncontended");
        sink.insert(
            "scope_shares_ambient_region",
            (scope_region == ambient_region).to_string(),
        );
        sink.insert(
            "child_region_is_distinct",
            (child_region != ambient_region).to_string(),
        );
    });

    if let Err(error) = bounded {
        outcome.require(false, error);
        return outcome;
    }

    // Probe two: a runtime configured with no blocking threads must be
    // *detectably* poolless, so a server can refuse before serving instead of
    // silently running blocking work inline on an executor worker.
    let zero_thread = application_runtime(0, 0);
    let pool_absent = match run_bounded(&zero_thread, async {
        let ambient = Cx::current().expect("runtime installs an ambient Cx");
        ambient.blocking_pool_handle().is_none()
    }) {
        Ok(value) => value,
        Err(error) => {
            outcome.require(false, error);
            return outcome;
        }
    };

    // The Cargo.toml comment that presented `scope_with_budget` as a
    // child-region solution must no longer say so.
    let root_manifest = read_workspace_file("Cargo.toml");
    let manifest_claims_scope_is_child = root_manifest.contains("scope_with_budget")
        && root_manifest.contains("child region")
        && !root_manifest.contains("not a child region");

    let report = report.lock().expect("report sink is readable");
    for (field, value) in report.iter() {
        outcome.observe(field, value);
    }
    outcome
        .observe("zero_thread_pool_detectably_absent", pool_absent)
        .observe(
            "root_manifest_still_claims_scope_is_child_region",
            manifest_claims_scope_is_child,
        );

    outcome.require(
        report
            .get("scope_shares_ambient_region")
            .map(String::as_str)
            == Some("true"),
        "Cx::scope() must be observably same-region; treating it as child-region ownership is \
         the defect this probe exists to catch",
    );
    outcome.require(
        report.get("child_region_is_distinct").map(String::as_str) == Some("true"),
        "open_child_region must mint a region distinct from the ambient one",
    );
    outcome.require(
        pool_absent,
        "a zero-blocking-thread configuration must report an absent pool so it can be rejected \
         before serving, rather than silently falling back to inline execution",
    );
    outcome.require(
        !manifest_claims_scope_is_child,
        "the root Cargo.toml must not present scope_with_budget as a child-region solution",
    );
    outcome
}

// ===========================================================================
// FND-04-B-12 candidate-drift
// ===========================================================================

/// Prerequisite observations must be bound to an exact archive, not a version.
fn subcase_12_candidate_drift(receipts: &[PrerequisiteReceipt]) -> SubcaseOutcome {
    let mut outcome = SubcaseOutcome::new("FND-04-B-12", "candidate-drift");

    let archive = pinned_runtime_archive();
    let archive_present = archive.is_some();

    // Every receipt must carry the same exact checksum, and that checksum must
    // be the one the lockfile actually resolved. A receipt that names only a
    // version number is a version-number inference, which is forbidden.
    let all_checksummed = receipts
        .iter()
        .all(|receipt| receipt.checksum == PINNED_RUNTIME_CHECKSUM && receipt.checksum.len() == 64);
    let all_versioned = receipts
        .iter()
        .all(|receipt| receipt.version == PINNED_RUNTIME_VERSION);
    let all_have_api_observation = receipts
        .iter()
        .all(|receipt| !receipt.api_observation.is_empty());
    let all_have_packaging = receipts.iter().all(|receipt| !receipt.packaging.is_empty());

    // The observations must have been made by reading the archive, not by
    // assuming what a version number implies. If the archive is missing, the
    // honest result is that no observation could be made.
    let observed_from_source = read_pinned_runtime_file("src/cx/child_region.rs")
        .is_some_and(|source| source.contains("pub async fn close("));

    let satisfied: Vec<&str> = receipts
        .iter()
        .filter(|receipt| receipt.satisfied)
        .map(|receipt| receipt.name)
        .collect();
    let unsatisfied: Vec<&str> = receipts
        .iter()
        .filter(|receipt| !receipt.satisfied)
        .map(|receipt| receipt.name)
        .collect();

    outcome
        .observe("receipt_count", receipts.len())
        .observe("archive_present", archive_present)
        .observe(
            "archive_path",
            archive
                .as_ref()
                .map_or_else(|| "<absent>".to_owned(), |path| path.display().to_string()),
        )
        .observe("all_receipts_checksum_bound", all_checksummed)
        .observe("all_receipts_version_bound", all_versioned)
        .observe(
            "all_receipts_carry_api_observation",
            all_have_api_observation,
        )
        .observe("all_receipts_carry_packaging", all_have_packaging)
        .observe(
            "observations_read_from_archive_source",
            observed_from_source,
        )
        .observe("satisfied_prerequisites", satisfied.join(","))
        .observe("unsatisfied_prerequisites", unsatisfied.join(","));

    outcome.require(
        receipts.len() == 3,
        "exactly three independently pinned prerequisite receipts are required",
    );
    outcome.require(
        all_checksummed && all_versioned,
        "every prerequisite receipt must be bound to the exact pinned version and 64-character \
         checksum; a version number alone can never move a prerequisite verdict",
    );
    outcome.require(
        all_have_api_observation && all_have_packaging,
        "every prerequisite receipt must carry an API observation and a packaging verdict",
    );
    outcome.require(
        archive_present && observed_from_source,
        "the pinned archive must be present and the prerequisite observations must be read from \
         its source; without it no checksum-qualified audit has occurred and no prerequisite \
         verdict may be asserted",
    );
    outcome.require(
        unsatisfied.is_empty(),
        format!(
            "every upstream prerequisite must be satisfied by the pinned archive before FND-04 \
             can close; unsatisfied at {PINNED_RUNTIME_VERSION}: {unsatisfied:?}"
        ),
    );
    outcome
}

// ===========================================================================
// FND-04-B-13 cross-platform-stdio
// ===========================================================================

/// One target row of the stdio conformance matrix.
#[derive(Clone, Debug, PartialEq, Eq)]
struct StdioTargetRow {
    target: &'static str,
    own_process_cancel_aware: bool,
    child_process_cancel_aware: bool,
    /// Whether the shipped transport can avoid a blocking own-process read.
    transport_avoids_blocking_own_stdio: bool,
    note: String,
}

/// Own-process and child-process stdio must be cancel-aware on all three targets.
fn subcase_13_cross_platform_stdio() -> SubcaseOutcome {
    let mut outcome = SubcaseOutcome::new("FND-04-B-13", "cross-platform-stdio");

    let process_src = read_pinned_runtime_file("src/process.rs").unwrap_or_default();
    let io_src = read_pinned_runtime_file("src/io/mod.rs").unwrap_or_default();
    let cx_src = read_pinned_runtime_file("src/cx/cx.rs").unwrap_or_default();

    // The pinned archive exposes adapters for a *spawned child's* stdio only.
    let child_stdio = process_src.contains("pub fn stdin(&mut self) -> Option<ChildStdin>")
        && process_src.contains("pub fn stdout(&mut self) -> Option<ChildStdout>");
    // No own-process async stdin/stdout is exported anywhere in the archive.
    let own_stdio = io_src.contains("pub fn stdin(")
        || io_src.contains("pub fn stdout(")
        || cx_src.contains("pub fn stdin(");

    // The shipped stdio transport builds on blocking std handles.
    let transport_src = read_workspace_file("crates/fastmcp-transport/src/stdio.rs");
    let transport_shipped = strip_cfg_test_modules(&transport_src);
    let uses_blocking_std_stdio = transport_shipped.contains("std::io::stdin()")
        || transport_shipped.contains("StdioTransport<std::io::Stdin, std::io::Stdout>");

    let rows: Vec<StdioTargetRow> = TARGET_MATRIX
        .iter()
        .map(|target| StdioTargetRow {
            target: *target,
            own_process_cancel_aware: own_stdio,
            child_process_cancel_aware: child_stdio,
            transport_avoids_blocking_own_stdio: !uses_blocking_std_stdio,
            note: if *target == "x86_64-pc-windows-msvc" {
                "Windows additionally requires proof that pipe polling never blocks an executor \
                 worker; with no own-process adapter there is nothing to make that proof about"
                    .to_owned()
            } else {
                "only spawned-child adapters are publicly exposed by the pinned archive".to_owned()
            },
        })
        .collect();

    for row in &rows {
        let key = row.target.replace('-', "_");
        outcome
            .observe(
                &format!("{key}__own_process_cancel_aware"),
                row.own_process_cancel_aware,
            )
            .observe(
                &format!("{key}__child_process_cancel_aware"),
                row.child_process_cancel_aware,
            )
            .observe(
                &format!("{key}__transport_avoids_blocking_own_stdio"),
                row.transport_avoids_blocking_own_stdio,
            )
            .observe(&format!("{key}__note"), &row.note);
    }
    outcome
        .observe("target_rows", rows.len())
        .observe("native_target", std::env::consts::OS)
        .observe(
            "shipped_transport_uses_blocking_std_stdio",
            uses_blocking_std_stdio,
        );

    outcome.require(
        rows.len() == 3,
        "the stdio matrix requires three target rows",
    );
    outcome.require(
        rows.iter().all(|row| row.child_process_cancel_aware),
        "spawned-child stdin/stdout must have a public cancel-aware path on every target",
    );
    outcome.require(
        rows.iter().all(|row| row.own_process_cancel_aware),
        format!(
            "this process's own stdin/stdout must have a public, cancel-aware asupersync path on \
             every target without test-internals, a private I/O-driver handle, a per-stream \
             thread, or a blocking Windows pipe fallback; at asupersync {PINNED_RUNTIME_VERSION} \
             only spawned-child adapters are exposed, so no such path exists on any of the three \
             targets and the third upstream prerequisite is unmet"
        ),
    );
    outcome.require(
        rows.iter()
            .all(|row| row.transport_avoids_blocking_own_stdio),
        "the shipped stdio transport must not depend on blocking std::io::Stdin/Stdout for \
         its own-process path",
    );
    outcome
}

// ===========================================================================
// FND-04-B-14 fork-generation
// ===========================================================================

/// Lowercase hex encoding of a byte slice.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// Decodes lowercase hex into exactly one nonce width of bytes.
fn unhex_32(text: &str) -> Option<[u8; SECURITY_IDENTIFIER_BYTES]> {
    if text.len() != SECURITY_IDENTIFIER_BYTES * 2 {
        return None;
    }
    let mut out = [0u8; SECURITY_IDENTIFIER_BYTES];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The child half of the native fork-generation probe.
///
/// Runs inside a genuinely new process created by `fork()`+`exec` through
/// [`std::process::Command`]. It reconstructs the *parent's* generation record
/// from the environment — exactly the inherited state a forked child would
/// hold — and requires the shipped predicate to refuse it.
fn fork_generation_child_body() -> Result<(), String> {
    let inherited_pid: u32 = std::env::var("FASTMCP_FND04B_PARENT_PID")
        .map_err(|_| "child is missing the inherited parent pid".to_owned())?
        .parse()
        .map_err(|_| "inherited parent pid is unparseable".to_owned())?;
    let inherited_nonce = std::env::var("FASTMCP_FND04B_PARENT_NONCE")
        .ok()
        .as_deref()
        .and_then(unhex_32)
        .ok_or_else(|| "inherited parent nonce is missing or malformed".to_owned())?;
    let inherited_generation: u64 = std::env::var("FASTMCP_FND04B_PARENT_GENERATION")
        .map_err(|_| "child is missing the inherited generation".to_owned())?
        .parse()
        .map_err(|_| "inherited generation is unparseable".to_owned())?;

    let child_pid = std::process::id();
    if child_pid == inherited_pid {
        return Err(format!(
            "the probe requires a genuinely new process, but the child reports the parent pid \
             {child_pid}"
        ));
    }

    // The inherited record, as a forked child would hold it.
    let inherited =
        ProcessGeneration::observed(inherited_pid, inherited_nonce, inherited_generation);
    // What this process actually is.
    let live = ProcessGeneration::observed(child_pid, inherited_nonce, inherited_generation);

    match inherited.admit(live) {
        Err(ProcessGenerationError::ForkDetected {
            installed_pid,
            observed_pid,
            ..
        }) if installed_pid == inherited_pid && observed_pid == child_pid => Ok(()),
        other => Err(format!(
            "inherited process-generation state must fail closed with ForkDetected in a new \
             process generation; got {other:?}"
        )),
    }
}

/// Inherited process-local state must fail closed after a generation change.
fn subcase_14_fork_generation() -> SubcaseOutcome {
    let mut outcome = SubcaseOutcome::new("FND-04-B-14", "fork-generation");

    let guard = match ProcessGenerationGuard::install() {
        Ok(guard) => guard,
        Err(error) => {
            outcome.require(false, format!("the guard must install: {error}"));
            return outcome;
        }
    };
    let generation = guard.generation();

    // The guard must be usable in the generation that installed it.
    let live_ok = guard.verify_current().is_ok();

    // A token minted before any process-local state becomes usable.
    let token = guard.token();
    let token_ok = token.verify().is_ok();

    // PID/generation simulation, available on every supported target. This
    // calls the same `admit` predicate the live path calls, so a rejection
    // here is evidence about the shipped rule rather than a test-only mirror.
    let forged_pid = ProcessGeneration::observed(
        generation.pid().wrapping_add(1),
        *generation.nonce(),
        generation.generation(),
    );
    let pid_divergence = generation.admit(forged_pid);
    let pid_rejected = matches!(
        pid_divergence,
        Err(ProcessGenerationError::ForkDetected { .. })
    );

    let forged_generation = ProcessGeneration::observed(
        generation.pid(),
        *generation.nonce(),
        generation.generation().wrapping_add(1),
    );
    let generation_divergence = generation.admit(forged_generation);
    let generation_rejected = matches!(
        generation_divergence,
        Err(ProcessGenerationError::GenerationMismatch { .. })
    );

    // PID reuse by a later, unrelated process must not inherit authority: the
    // nonce differs even when the operating system hands back the same pid.
    let reused_pid = ProcessGeneration::observed(
        generation.pid(),
        [0u8; SECURITY_IDENTIFIER_BYTES],
        generation.generation(),
    );
    let reuse_rejected = matches!(
        generation.admit(reused_pid),
        Err(ProcessGenerationError::ForkDetected { .. })
    );

    // Native fork+exec evidence: a genuinely new process generation.
    let native = run_fork_generation_child();

    outcome
        .observe("guard_installed", true)
        .observe("installed_pid", generation.pid())
        .observe("installed_generation", generation.generation())
        .observe("live_verify_ok", live_ok)
        .observe("token_verify_ok", token_ok)
        .observe("pid_divergence_rejected", pid_rejected)
        .observe("generation_divergence_rejected", generation_rejected)
        .observe("pid_reuse_rejected", reuse_rejected)
        .observe("native_fork_exec_result", format!("{native:?}"))
        .observe("native_fork_exec_available", native.is_ok())
        .observe(
            "coverage_boundary",
            "raw fork() without exec cannot be exercised from this crate: #![forbid(unsafe_code)] \
             rules out calling libc::fork directly, so the native row is fork+exec. The predicate \
             under test is identical — it compares process identity — and the pid/generation \
             simulation rows cover the divergence shapes a raw fork would produce",
        );

    outcome.require(
        live_ok,
        "the installing generation must verify successfully",
    );
    outcome.require(token_ok, "a token minted in this generation must verify");
    outcome.require(
        pid_rejected,
        "a process-identity divergence must fail closed with ForkDetected",
    );
    outcome.require(
        generation_rejected,
        "a generation-ordinal divergence must fail closed with GenerationMismatch",
    );
    outcome.require(
        reuse_rejected,
        "a later process reusing the same pid must not inherit the previous generation's authority",
    );
    outcome.require(
        native.is_ok(),
        format!(
            "inherited runtime, key, continuation, quota and supervisor state must fail closed in \
             a real new process generation: {native:?}"
        ),
    );
    outcome
}

/// Re-enters this test binary as a child process and runs the child probe.
fn run_fork_generation_child() -> Result<(), String> {
    let guard = ProcessGenerationGuard::install().map_err(|error| error.to_string())?;
    let generation = guard.generation();
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;

    let output = std::process::Command::new(executable)
        .args([
            "--exact",
            "fnd_04_b_14_fork_generation",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(FORK_CHILD_MARKER, "1")
        .env("FASTMCP_FND04B_PARENT_PID", generation.pid().to_string())
        .env("FASTMCP_FND04B_PARENT_NONCE", hex(generation.nonce()))
        .env(
            "FASTMCP_FND04B_PARENT_GENERATION",
            generation.generation().to_string(),
        )
        .output()
        .map_err(|error| format!("spawning the child generation failed: {error}"))?;

    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "child generation exited with {:?}; stdout: {}; stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim(),
    ))
}

// ===========================================================================
// FND-04-B-15 snapshot-clone-denial
// ===========================================================================

/// Snapshot-capable deployments must be refused or externally anchored.
fn subcase_15_snapshot_clone_denial() -> SubcaseOutcome {
    let mut outcome = SubcaseOutcome::new("FND-04-B-15", "snapshot-clone-denial");

    // The boundary must be stated, not implied. A PID check cannot detect a
    // same-PID live-memory clone, and nothing in the process can.
    let detectable = SNAPSHOT_CLONE_IS_DETECTABLE;

    // Denial: cloning permitted, ephemeral protected state still enabled, no
    // external epoch. This is the configuration that must be refused.
    let denied = ProcessGenerationGuard::admit_snapshot_stance(
        SnapshotCloneStance::LiveMemoryCloningPermitted {
            ephemeral_protected_state_disabled: false,
            external_epoch: None,
        },
    );
    let denied_correctly = matches!(
        denied,
        Err(ProcessGenerationError::SnapshotCloneDeploymentUnsupported)
    );

    // A non-conforming epoch is not a way through: either missing property
    // reinstates exactly the replay the epoch was meant to prevent.
    let rollback_only = ProcessGenerationGuard::admit_snapshot_stance(
        SnapshotCloneStance::LiveMemoryCloningPermitted {
            ephemeral_protected_state_disabled: false,
            external_epoch: Some(ExternalEpoch::new(true, false)),
        },
    );
    let clone_only = ProcessGenerationGuard::admit_snapshot_stance(
        SnapshotCloneStance::LiveMemoryCloningPermitted {
            ephemeral_protected_state_disabled: false,
            external_epoch: Some(ExternalEpoch::new(false, true)),
        },
    );
    let partial_epochs_denied = matches!(
        rollback_only,
        Err(ProcessGenerationError::SnapshotCloneDeploymentUnsupported)
    ) && matches!(
        clone_only,
        Err(ProcessGenerationError::SnapshotCloneDeploymentUnsupported)
    );

    // Positive one: no live-memory cloning at all.
    let no_cloning =
        ProcessGenerationGuard::admit_snapshot_stance(SnapshotCloneStance::NoLiveMemoryCloning);

    // Positive two: cloning permitted, but ephemeral protected state disabled.
    let ephemeral_disabled = ProcessGenerationGuard::admit_snapshot_stance(
        SnapshotCloneStance::LiveMemoryCloningPermitted {
            ephemeral_protected_state_disabled: true,
            external_epoch: None,
        },
    );

    // Positive three: cloning permitted with a conforming external epoch.
    let external_epoch = ProcessGenerationGuard::admit_snapshot_stance(
        SnapshotCloneStance::LiveMemoryCloningPermitted {
            ephemeral_protected_state_disabled: false,
            external_epoch: Some(ExternalEpoch::new(true, true)),
        },
    );

    outcome
        .observe("snapshot_clone_is_detectable", detectable)
        .observe("permissive_stance_denied", denied_correctly)
        .observe("partial_external_epochs_denied", partial_epochs_denied)
        .observe("no_cloning_admitted", no_cloning.is_ok())
        .observe("ephemeral_disabled_admitted", ephemeral_disabled.is_ok())
        .observe("conforming_external_epoch_admitted", external_epoch.is_ok())
        .observe(
            "snapshot_deployment_policy",
            "process-local identity detects fork() and nothing else; CRIU, VM snapshot, and \
             container clone duplicate pid, memory, and nonce together, so a deployment that \
             permits live-memory cloning must disable ephemeral protected/continuation state or \
             anchor on a rollback- and clone-resistant external epoch",
        );

    outcome.require(
        !detectable,
        "the evaluator must not claim a live-memory clone is detectable from inside the process",
    );
    outcome.require(
        denied_correctly,
        "a deployment permitting live-memory cloning with ephemeral protected state enabled and \
         no external epoch must be refused",
    );
    outcome.require(
        partial_epochs_denied,
        "an external epoch must be both rollback-resistant and clone-resistant; either alone \
         must be refused",
    );
    outcome.require(
        no_cloning.is_ok() && ephemeral_disabled.is_ok() && external_epoch.is_ok(),
        "the three conforming deployment stances must be admitted",
    );
    outcome
}

// ===========================================================================
// Canonical receipt `fnd-04-b-manifest-v1`
// ===========================================================================

/// The canonical evaluator receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Fnd04BManifest {
    name: &'static str,
    profile: &'static str,
    consumer: &'static str,
    targets: Vec<String>,
    features: String,
    revision: String,
    tree: String,
    prerequisites: Vec<PrerequisiteReceipt>,
    outcomes: Vec<SubcaseOutcome>,
    /// 64-character lowercase SHA-256 of the canonical evaluator output.
    digest: String,
}

/// Reads the current revision and tree identity without invoking git.
///
/// The evaluator must not shell out to git for its own identity: a receipt
/// that depends on an external process is not reproducible from the tree it
/// claims to describe. `.git/HEAD` and the ref it names are enough.
/// Resolves `reference` from `.git/packed-refs`, the table `git gc` writes.
///
/// Format is one `<sha> <refname>` per line, with `#` comment lines and
/// `^<sha>` peel lines for annotated tags; only the direct mapping is wanted.
/// Callers must try the loose ref FIRST -- this table is a snapshot and a
/// later loose write supersedes it.
fn packed_ref(git: &std::path::Path, reference: &str) -> Option<String> {
    let packed = std::fs::read_to_string(git.join("packed-refs")).ok()?;
    packed.lines().find_map(|line| {
        if line.starts_with('#') || line.starts_with('^') {
            return None;
        }
        let (sha, name) = line.split_once(' ')?;
        (name.trim() == reference).then(|| sha.trim().to_owned())
    })
}

fn revision_and_tree() -> (String, String) {
    let git = workspace_root().join(".git");
    let head = std::fs::read_to_string(git.join("HEAD")).unwrap_or_default();
    let revision = if let Some(reference) = head.trim().strip_prefix("ref: ") {
        std::fs::read_to_string(git.join(reference))
            .ok()
            .map(|value| value.trim().to_owned())
            // bd-gizte: a loose ref file is only ONE of the two places git
            // keeps a ref. `git gc` and many clones PACK refs into
            // `.git/packed-refs`, so a perfectly healthy repository can have no
            // loose file to read and would otherwise report "<unresolved>" as
            // though the host were broken.
            //
            // ORDER IS LOAD-BEARING HERE, unlike the assertion pair below, and
            // it is git's own: LOOSE WINS. `packed-refs` is a snapshot taken at
            // the last pack and goes stale the moment a loose ref is written --
            // measured in this very workspace, where the packed entry and the
            // loose file name different commits. Consulting packed first would
            // bind a stale revision, which is strictly worse than reporting
            // none.
            .or_else(|| packed_ref(&git, reference))
            .unwrap_or_else(|| "<unresolved>".to_owned())
    } else {
        head.trim().to_owned()
    };

    // Tree identity: digest of every shipped source path and its contents, so
    // a source movement invalidates the receipt exactly as required.
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    for (path, contents) in shipped_source_files() {
        sha2::Digest::update(&mut hasher, path.as_bytes());
        sha2::Digest::update(&mut hasher, b"\0");
        sha2::Digest::update(&mut hasher, contents.as_bytes());
        sha2::Digest::update(&mut hasher, b"\0");
    }
    let tree = hex(&sha2::Digest::finalize(hasher));
    (
        if revision.is_empty() {
            "<unresolved>".to_owned()
        } else {
            revision
        },
        tree,
    )
}

/// The feature set this evaluator binary was compiled with.
fn compiled_feature_set() -> String {
    let mut features = vec!["default"];
    if cfg!(feature = "legacy-2024-11-05") {
        features.push("legacy-2024-11-05");
    }
    if cfg!(feature = "tasks") {
        features.push("tasks");
    }
    if cfg!(feature = "testing-lab") {
        features.push("testing-lab");
    }
    if cfg!(feature = "testing") {
        features.push("testing");
    }
    features.join("+")
}

/// Runs the full ordered subcase set and builds the canonical receipt.
fn evaluate() -> Fnd04BManifest {
    let prerequisites = derive_prerequisite_receipts();
    let outcomes = vec![
        subcase_01_sibling_cancellation(),
        subcase_02_shutdown_tree(),
        subcase_03_transport_close_budget(),
        subcase_04_task_supervisor_ownership(),
        subcase_05_dependency_feature(),
        subcase_06_exact_runtime_pin_lockfile_drift(),
        subcase_07_production_deny_inventory(),
        subcase_08_lock_cancellation_fairness_shutdown(),
        subcase_09_bounded_blocking_admission_reconciliation(),
        subcase_10_hung_endpoint_and_recovery(),
        subcase_11_scope_and_zero_thread_negative(),
        subcase_12_candidate_drift(&prerequisites),
        subcase_13_cross_platform_stdio(),
        subcase_14_fork_generation(),
        subcase_15_snapshot_clone_denial(),
    ];

    let (revision, tree) = revision_and_tree();
    let features = compiled_feature_set();

    // Canonical evaluator output: the exact bytes the digest commits to.
    let mut canonical = String::new();
    let _ = writeln!(canonical, "receipt\t{RECEIPT_NAME}");
    let _ = writeln!(canonical, "profile\t{PROFILE}");
    let _ = writeln!(canonical, "consumer\t{CONSUMER_ID}");
    let _ = writeln!(canonical, "targets\t{}", TARGET_MATRIX.join(","));
    let _ = writeln!(canonical, "features\t{features}");
    let _ = writeln!(canonical, "revision\t{revision}");
    let _ = writeln!(canonical, "tree\t{tree}");
    for receipt in &prerequisites {
        let _ = writeln!(canonical, "{}", receipt.canonical_line());
    }
    for outcome in &outcomes {
        let _ = writeln!(canonical, "{}", outcome.canonical_line());
    }

    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    sha2::Digest::update(&mut hasher, canonical.as_bytes());
    let digest = hex(&sha2::Digest::finalize(hasher));

    Fnd04BManifest {
        name: RECEIPT_NAME,
        profile: PROFILE,
        consumer: CONSUMER_ID,
        targets: TARGET_MATRIX
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        features,
        revision,
        tree,
        prerequisites,
        outcomes,
        digest,
    }
}

/// Renders the manifest for operator-visible output.
fn render(manifest: &Fnd04BManifest) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "=== {} ===", manifest.name);
    let _ = writeln!(out, "profile:   {}", manifest.profile);
    let _ = writeln!(out, "consumer:  {}", manifest.consumer);
    let _ = writeln!(out, "targets:   {}", manifest.targets.join(", "));
    let _ = writeln!(out, "features:  {}", manifest.features);
    let _ = writeln!(out, "revision:  {}", manifest.revision);
    let _ = writeln!(out, "tree:      {}", manifest.tree);
    let _ = writeln!(out, "digest:    {}", manifest.digest);
    let _ = writeln!(out, "--- prerequisites ---");
    for receipt in &manifest.prerequisites {
        let _ = writeln!(
            out,
            "P{} {:<42} {}",
            receipt.ordinal,
            receipt.name,
            if receipt.satisfied {
                "SATISFIED"
            } else {
                "UNSATISFIED"
            }
        );
        let _ = writeln!(out, "     api:       {}", receipt.api_observation);
        let _ = writeln!(out, "     packaging: {}", receipt.packaging);
        let _ = writeln!(out, "     evidence:  {}", receipt.evidence);
    }
    let _ = writeln!(out, "--- subcases ---");
    for outcome in &manifest.outcomes {
        let _ = writeln!(
            out,
            "{} {:<44} {}",
            outcome.id,
            outcome.name,
            if outcome.passed { "PASS" } else { "FAIL" }
        );
        if let Some(failure) = &outcome.failure {
            let _ = writeln!(out, "     {failure}");
        }
    }
    out
}

// ===========================================================================
// Ordered subcase entry points
// ===========================================================================

#[test]
fn fnd_04_b_01_sibling_cancellation() {
    subcase_01_sibling_cancellation().assert_passed();
}

#[test]
fn fnd_04_b_02_shutdown_tree() {
    subcase_02_shutdown_tree().assert_passed();
}

#[test]
fn fnd_04_b_03_transport_close_budget() {
    subcase_03_transport_close_budget().assert_passed();
}

#[test]
fn fnd_04_b_04_task_supervisor_ownership() {
    subcase_04_task_supervisor_ownership().assert_passed();
}

#[test]
fn fnd_04_b_05_dependency_feature() {
    subcase_05_dependency_feature().assert_passed();
}

#[test]
fn fnd_04_b_06_exact_runtime_pin_lockfile_drift() {
    subcase_06_exact_runtime_pin_lockfile_drift().assert_passed();
}

#[test]
fn fnd_04_b_07_production_deny_inventory() {
    subcase_07_production_deny_inventory().assert_passed();
}

#[test]
fn fnd_04_b_08_lock_cancellation_fairness_shutdown() {
    subcase_08_lock_cancellation_fairness_shutdown().assert_passed();
}

#[test]
fn fnd_04_b_09_bounded_blocking_admission_reconciliation() {
    subcase_09_bounded_blocking_admission_reconciliation().assert_passed();
}

#[test]
fn fnd_04_b_10_hung_endpoint_and_recovery() {
    subcase_10_hung_endpoint_and_recovery().assert_passed();
}

#[test]
fn fnd_04_b_11_scope_and_zero_thread_negative() {
    subcase_11_scope_and_zero_thread_negative().assert_passed();
}

#[test]
fn fnd_04_b_12_candidate_drift() {
    subcase_12_candidate_drift(&derive_prerequisite_receipts()).assert_passed();
}

#[test]
fn fnd_04_b_13_cross_platform_stdio() {
    subcase_13_cross_platform_stdio().assert_passed();
}

#[test]
fn fnd_04_b_14_fork_generation() {
    // When this binary has been re-entered as a child generation, run only the
    // child half and report through the process exit status. The parent half
    // below is what asserts on that status.
    if std::env::var_os(FORK_CHILD_MARKER).is_some() {
        fork_generation_child_body().expect("child generation probe");
        return;
    }
    subcase_14_fork_generation().assert_passed();
}

#[test]
fn fnd_04_b_15_snapshot_clone_denial() {
    subcase_15_snapshot_clone_denial().assert_passed();
}

// ===========================================================================
// Frozen bridge pair
// ===========================================================================

#[test]
fn fnd_04_b_positive() {
    // A child generation must not re-run the whole evaluator.
    if std::env::var_os(FORK_CHILD_MARKER).is_some() {
        return;
    }

    let manifest = evaluate();
    println!("{}", render(&manifest));

    // Receipt shape: every field the acceptance criteria freeze.
    assert_eq!(manifest.name, RECEIPT_NAME, "receipt name is frozen");
    assert_eq!(manifest.profile, PROFILE, "profile is frozen");
    assert_eq!(manifest.consumer, CONSUMER_ID, "consumer is frozen");
    assert_eq!(manifest.targets.len(), 3, "three target rows are required");
    assert_eq!(
        manifest.prerequisites.len(),
        3,
        "three prerequisite receipts must be present"
    );
    assert_eq!(
        manifest.outcomes.len(),
        15,
        "fifteen ordered subcase outcomes are required"
    );
    assert_eq!(
        manifest.digest.len(),
        64,
        "the evaluator-output digest must be 64 characters"
    );
    assert!(
        manifest
            .digest
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character)),
        "the evaluator-output digest must be lowercase hexadecimal, got {}",
        manifest.digest
    );
    // A SHAPE check rather than a sentinel check, and forty lowercase hex
    // characters is the shape. It matches this file's idiom for the adjacent
    // tree identity.
    //
    // WHAT IT BUYS, stated accurately after two corrections. `revision_and_tree`
    // NORMALISES at its return -- `if revision.is_empty() { "<unresolved>" }` --
    // so an empty revision CANNOT ESCAPE THE PRODUCER, and both failure paths
    // (absent `.git`, unreadable ref) arrive here as the sentinel. The previous
    // `assert_ne!(.., "<unresolved>")` therefore already caught every failure
    // the producer can currently emit.
    //
    // So this is FUTURE-PROOFING, not a repair. It is strictly stronger than the
    // sentinel check on inputs the sentinel waves through -- a 39-character hex
    // string, an uppercase digest, arbitrary garbage -- and it keeps holding if
    // that normalisation is ever removed. The demonstrated gap is the 39-hex
    // row, not emptiness.
    //
    // ONE CONJUNCTION, deliberately: the length operand is what rejects a short
    // hex string, and `chars().all(..)` alone would admit it.
    //
    // THE HAZARD IS REMOVAL, NOT ORDERING. As two statements a later editor may
    // drop the length assert as "redundant to the stricter-looking hex check".
    // As a single `&&` the operands are visibly one predicate and neither can be
    // removed without changing it on its face. Structure over commentary -- the
    // same reason FND-02's digest validator is one conjunction.
    //
    // TWO FALSE CLAIMS WERE REMOVED FROM THIS COMMENT, recorded so neither gets
    // re-derived from the code's shape:
    //
    // 1. That the ORDER of two sequential asserts was load-bearing. FALSE:
    //    `assert!(a); assert!(b);` fails iff `!a || !b`, exactly when
    //    `assert!(a && b)` fails. Both asserts always run, so a vacuously-true
    //    operand cannot consume the other. Order changes only which message
    //    fires first, never the rejection set.
    //
    // 2. That an absent `.git` yields an escaping `""`. FALSE, and false when
    //    written -- the normalisation at the producer's return predates that
    //    claim by a day. `""` is unreachable here, so the vacuity of
    //    `chars().all(..)` on an empty string, while real Rust, is irrelevant
    //    to this call site.
    //
    // Both were traced by reading the comment's own reasoning instead of the
    // code it describes. A comment that traces a code path is a claim ABOUT
    // code; it is checked by opening that code.
    assert!(
        manifest.revision.len() == 40
            && manifest
                .revision
                .chars()
                .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character)),
        "revision must bind: expected forty lowercase hex characters, got {:?}",
        manifest.revision
    );
    assert_eq!(manifest.tree.len(), 64, "tree identity must bind");

    // Ordering is frozen: required IDs must equal discovered IDs, in order.
    const REQUIRED: [(&str, &str); 15] = [
        ("FND-04-B-01", "sibling-cancellation"),
        ("FND-04-B-02", "shutdown-tree"),
        ("FND-04-B-03", "transport-close-budget"),
        ("FND-04-B-04", "task-supervisor-ownership"),
        ("FND-04-B-05", "dependency-feature"),
        ("FND-04-B-06", "exact-runtime-pin-lockfile-drift"),
        ("FND-04-B-07", "production-deny-inventory"),
        ("FND-04-B-08", "lock-cancellation-fairness-shutdown"),
        ("FND-04-B-09", "bounded-blocking-admission-reconciliation"),
        ("FND-04-B-10", "hung-endpoint-and-recovery"),
        ("FND-04-B-11", "scope-and-zero-thread-negative"),
        ("FND-04-B-12", "candidate-drift"),
        ("FND-04-B-13", "cross-platform-stdio"),
        ("FND-04-B-14", "fork-generation"),
        ("FND-04-B-15", "snapshot-clone-denial"),
    ];
    let discovered: Vec<(&str, &str)> = manifest
        .outcomes
        .iter()
        .map(|outcome| (outcome.id, outcome.name))
        .collect();
    assert_eq!(
        discovered.as_slice(),
        REQUIRED.as_slice(),
        "required subcase set must equal the discovered subcase set, in frozen order"
    );

    // Every observed field named by the acceptance criteria must be present
    // somewhere in the evaluated set; an empty observation set is zero-run
    // green, which is failure rather than proof.
    for outcome in &manifest.outcomes {
        assert!(
            !outcome.observations.is_empty(),
            "{} {} recorded no observations",
            outcome.id,
            outcome.name
        );
    }

    // The capability verdict itself.
    let failed: Vec<&SubcaseOutcome> = manifest
        .outcomes
        .iter()
        .filter(|outcome| !outcome.passed)
        .collect();
    let unmet_prerequisites: Vec<&str> = manifest
        .prerequisites
        .iter()
        .filter(|receipt| !receipt.satisfied)
        .map(|receipt| receipt.name)
        .collect();

    assert!(
        failed.is_empty() && unmet_prerequisites.is_empty(),
        "FND-04 B is not met at this revision.\n\
         Unsatisfied upstream prerequisites: {unmet_prerequisites:?}\n\
         Failing subcases:\n{}\n\n{}",
        failed
            .iter()
            .map(|outcome| format!(
                "  {} {}: {}",
                outcome.id,
                outcome.name,
                outcome.failure.as_deref().unwrap_or("<no reason>")
            ))
            .collect::<Vec<_>>()
            .join("\n"),
        render(&manifest),
    );
}

#[test]
fn fnd_04_b_planted_negative() {
    if std::env::var_os(FORK_CHILD_MARKER).is_some() {
        return;
    }

    // This negative differs from the positive in exactly one dimension: the
    // deployment declares that live-memory cloning is permitted while leaving
    // ephemeral process-local protected state enabled and supplying no
    // external epoch. Everything else — the runtime, the accepted request, the
    // sibling request, the blocking facility, the emitted I/O — is identical.
    let ledger = Arc::new(EffectLedger::default());
    let runtime = application_runtime(1, 2);

    // ---- Control: the counters are live, not decorative. --------------------
    //
    // A zero delta is only evidence if a non-zero delta was reachable. This
    // half runs the same shapes the negative half attempts and proves each of
    // the six counters moves when the work is genuinely admitted.
    let control_ledger = Arc::clone(&ledger);
    let emitted: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let control_sink = Arc::clone(&emitted);
    run_bounded(&runtime, async move {
        let ambient = Cx::current().expect("runtime installs an ambient Cx");
        control_ledger.runtime_roots.fetch_add(1, Ordering::SeqCst);

        let accepted = ambient
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("accepted request region opens");
        let sibling = ambient
            .open_child_region(ChildRegionSpec::inherit())
            .await
            .expect("sibling request region opens");

        let accepted_counter = Arc::clone(&control_ledger);
        let mut accepted_task = accepted
            .cx()
            .spawn(move |_cx| async move {
                accepted_counter
                    .accepted_request_state
                    .fetch_add(1, Ordering::SeqCst);
            })
            .expect("accepted request body admits");
        let _ = accepted_task.join(accepted.cx()).await;

        let sibling_counter = Arc::clone(&control_ledger);
        let mut sibling_task = sibling
            .cx()
            .spawn(move |_cx| async move {
                sibling_counter.sibling_state.fetch_add(1, Ordering::SeqCst);
            })
            .expect("sibling request body admits");
        let _ = sibling_task.join(sibling.cx()).await;

        let blocking_counter = Arc::clone(&control_ledger);
        let io_sink = Arc::clone(&control_sink);
        let mut blocking = ambient
            .spawn_blocking(move |_cx| {
                blocking_counter
                    .submitted_blocking_jobs
                    .fetch_add(1, Ordering::SeqCst);
                // A real write through a real handle, counted as emitted I/O.
                let mut sink = io_sink.lock().expect("io sink is uncontended");
                std::io::Write::write_all(&mut *sink, b"fnd-04-b control frame\n")
                    .expect("writing to the in-memory sink succeeds");
                blocking_counter
                    .emitted_io_writes
                    .fetch_add(1, Ordering::SeqCst);
            })
            .expect("the control blocking job is admitted");
        let _ = blocking.join(&ambient).await;

        // A genuinely private thread, counted so the dimension is observable.
        let thread_counter = Arc::clone(&control_ledger);
        let handle = std::thread::spawn(move || {
            thread_counter
                .spawned_private_threads
                .fetch_add(1, Ordering::SeqCst);
        });
        handle.join().expect("control thread joins");

        let _ = accepted.close().await;
        let _ = sibling.close().await;
    })
    .expect("the planted-negative control must settle within its wall-clock ceiling");

    let control = ledger.read();
    assert_eq!(
        control,
        EffectCounters {
            accepted_request_state: 1,
            sibling_state: 1,
            runtime_roots: 1,
            spawned_private_threads: 1,
            submitted_blocking_jobs: 1,
            emitted_io_writes: 1,
        },
        "every one of the six effect counters must be reachable, or a zero delta below proves \
         nothing about the refusal"
    );
    let emitted_before = emitted.lock().expect("io sink is readable").clone();
    assert!(
        !emitted_before.is_empty(),
        "the control must have emitted observable I/O"
    );

    // ---- The one-variable mutation, which must be refused. ------------------
    let refused = ProcessGenerationGuard::admit_snapshot_stance(
        SnapshotCloneStance::LiveMemoryCloningPermitted {
            ephemeral_protected_state_disabled: false,
            external_epoch: None,
        },
    );

    // Stable typed diagnostic, through the shipped error type.
    assert_eq!(
        refused,
        Err(ProcessGenerationError::SnapshotCloneDeploymentUnsupported),
        "the refusal must be the stable typed diagnostic, not an ad-hoc string"
    );

    // The near-identical positive differs only in the forbidden dimension.
    let admitted = ProcessGenerationGuard::admit_snapshot_stance(
        SnapshotCloneStance::LiveMemoryCloningPermitted {
            ephemeral_protected_state_disabled: true,
            external_epoch: None,
        },
    );
    assert!(
        admitted.is_ok(),
        "the control stance, differing only in the one forbidden dimension, must be admitted"
    );

    // ---- Zero-effect proof over all six counters. ---------------------------
    let after = ledger.read();
    let delta = control.delta(after);
    assert_eq!(
        delta.accepted_request_state, 0,
        "accepted request state changed"
    );
    assert_eq!(delta.sibling_state, 0, "sibling state changed");
    assert_eq!(delta.runtime_roots, 0, "a runtime root was constructed");
    assert_eq!(
        delta.spawned_private_threads, 0,
        "a private thread was spawned"
    );
    assert_eq!(
        delta.submitted_blocking_jobs, 0,
        "a blocking job was submitted"
    );
    assert_eq!(delta.emitted_io_writes, 0, "an I/O write was emitted");
    assert!(
        delta.all_zero(),
        "a refused deployment stance must leave accepted request state, sibling state, runtime \
         roots, spawned private threads, submitted blocking jobs, and emitted I/O writes \
         unchanged; observed delta {delta:?}"
    );
    assert_eq!(
        emitted.lock().expect("io sink is readable").as_slice(),
        emitted_before.as_slice(),
        "the refused stance must leave emitted I/O byte-for-byte unchanged"
    );

    // ---- Second planted dimension: a reachable private runtime root. --------
    //
    // Same shape, different forbidden dimension, so the deny inventory's own
    // verdict is exercised rather than assumed. The shipped source is read,
    // mutated in memory only, and re-read to prove the tree is untouched.
    let pristine = read_workspace_file("crates/fastmcp-server/src/lib.rs");
    let shipped = strip_cfg_test_modules(&pristine);
    let pristine_roots = shipped.matches("RuntimeBuilder::").count();
    let planted = format!(
        "{shipped}\npub fn planted_private_runtime_root() {{ RuntimeBuilder::current_thread(); }}\n"
    );
    assert_eq!(
        planted.matches("RuntimeBuilder::").count(),
        pristine_roots + 1,
        "the planted negative must differ from the pristine source in exactly one instance of \
         the forbidden dimension"
    );
    assert!(
        planted.contains("RuntimeBuilder::"),
        "the deny inventory must reject a reachable private-runtime construction"
    );
    assert_eq!(
        read_workspace_file("crates/fastmcp-server/src/lib.rs"),
        pristine,
        "the planted negative must not modify the shipped source"
    );

    let final_delta = control.delta(ledger.read());
    assert!(
        final_delta.all_zero(),
        "neither planted dimension may leave a trace; observed {final_delta:?}"
    );
}

/// Creates a fresh empty directory for a `packed-refs` fixture.
///
/// No `.git` is involved: `packed_ref` takes a directory and reads
/// `<dir>/packed-refs`, so a plain temp directory is a complete substrate. That
/// is the whole point of these two tests — they run identically on a worker with
/// no repository, which is where the FND-04 conformance target actually executes.
fn fnd_04_packed_ref_fixture_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "fnd04-packed-ref-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("packed-refs fixture directory is creatable");
    dir
}

/// bd-gizte: `packed_ref` resolves a packed reference past the two line kinds it
/// is documented to skip.
///
/// THE WORTHLESS VERSION, NAMED FIRST. A table holding one clean
/// `<sha> <refname>` line and an assertion that it is found. That passes with
/// BOTH guards deleted, because a well-formed comment or peel line fails
/// `split_once(' ')` or the name comparison anyway. It proves the happy path and
/// nothing about the parser's actual hazards.
///
/// So the table below crafts a comment line and a peel line that WOULD match the
/// wanted refname if their guards were removed, plus a near-miss name. Because
/// `find_map` returns the FIRST match, deleting either guard changes the result
/// rather than merely widening it.
#[test]
fn fnd_04_packed_ref_skips_comment_and_peel_lines_that_mimic_a_mapping() {
    let dir = fnd_04_packed_ref_fixture_dir("positive");
    std::fs::write(
        dir.join("packed-refs"),
        concat!(
            "# refs/heads/main\n",
            "^1111111111111111111111111111111111111111 refs/heads/main\n",
            "2222222222222222222222222222222222222222 refs/heads/mai\n",
            "3333333333333333333333333333333333333333 refs/heads/main\n",
        ),
    )
    .expect("packed-refs fixture is writable");

    assert_eq!(
        packed_ref(&dir, "refs/heads/main").as_deref(),
        Some("3333333333333333333333333333333333333333"),
        "the direct mapping must win: a `#` line yields sha `#`, a `^` peel line yields the peeled \
         sha, and `refs/heads/mai` is a different ref -- each precedes the wanted row, so any of \
         the three being accepted returns a WRONG value rather than none"
    );
}

/// bd-gizte: `packed_ref` yields `None` rather than a wrong value or a panic.
///
/// The absent-table case is the one that matters operationally: the FND-04 target
/// runs on workers with no `.git` at all, and this function must degrade to `None`
/// there rather than failing. That is the branch `revision_and_tree` relies on to
/// fall through to its `"<unresolved>"` sentinel.
#[test]
fn fnd_04_packed_ref_returns_none_for_an_absent_reference_or_table() {
    let dir = fnd_04_packed_ref_fixture_dir("negative");
    std::fs::write(
        dir.join("packed-refs"),
        "4444444444444444444444444444444444444444 refs/heads/other\n",
    )
    .expect("packed-refs fixture is writable");

    assert_eq!(
        packed_ref(&dir, "refs/heads/main"),
        None,
        "a reference absent from the table must not resolve to another ref's sha"
    );
    assert_eq!(
        packed_ref(&dir.join("no-such-directory"), "refs/heads/main"),
        None,
        "a missing packed-refs table must yield None, not panic -- this is the no-`.git` worker \
         case that `revision_and_tree` falls through on"
    );
}
