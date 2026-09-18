//! Fails when the two permanent copies of the LIMIT-01 acceptance rows diverge.
//!
//! WHY TWO COPIES EXIST AND CANNOT BE MERGED. `crates/fastmcp-core/src/limit_01_rows.rs`
//! must stay: AGENTS.md:325 requires the inline `#[cfg(test)]` unit tests to exist.
//! `crates/fastmcp-core/tests/limit_01_rows/mod.rs` must stay: PL-3 forbids `cfg(test)`
//! placement from being the PROOF, so the frozen LIMIT-01 IDs have to run as external
//! consumers. The `src/` module is private with zero `pub` items, so the `tests/` copy
//! cannot import it, and widening it would grow the shipped API purely for testing —
//! which `c8ff53ea` deliberately avoided. Every obvious deduplication breaches one of the
//! three constraints. The duplication is the correct outcome; UNDETECTED DRIFT is the defect.
//!
//! WHAT THIS NORMALIZES, AND THE RULE THAT DECIDES IT.
//!
//!   NORMALIZE ONLY WHAT THE TWO LOCATIONS FORCE. NOTHING ELSE.
//!
//! Exactly two differences are forced by where each copy lives:
//!   `fastmcp_core::` -> `crate::`   one is an external consumer, one is in-crate
//!   `pub(crate)` -> `pub`           one is a private mod, one is an integration module
//! Anything else must match byte for byte. Each rewrite is applied ONLY to the copy whose
//! location forces it — see [`Side`] for why a symmetric normalizer is subtly wrong.
//!
//! WHY SOURCE TEXT RATHER THAN A DIGEST OVER THE ROW DATA.
//!
//! HazyTurtle, who created the duplication, argued for a digest over the row definitions
//! (IDs, bounds, ceilings, observed-field names) on the grounds that it is silent on
//! cosmetic rewrites and loud on exactly the three cases the owning bead enumerates —
//! a reordering, a renamed row, or an edited bound. That is a real fork and the objection
//! is fair: this file WILL fire when a lint is applied to one copy and not the other.
//!
//! It is nonetheless the wrong instrument here, for a reason that is measurable. Roughly
//! half of this 909-line module is not row data at all — `build_with_override`, the six
//! `run_*_rows` functions and the six `*_receipt` formatters are ~489 lines of EXECUTION
//! LOGIC. A digest over row data cannot see any of it.
//!
//! Name the worst drift that digest would miss: someone weakens an assertion inside
//! `run_partition_rows` **in the `tests/` copy** — the copy that IS the PL-3 proof for the
//! frozen LIMIT-01 IDs. Same row IDs, same bounds, same ceilings, so the data digest is
//! identical and silent, while the proof now proves less. That is the highest-severity
//! case in the whole bead and it is precisely the blind spot.
//!
//! And "cries wolf" mistakes what the wolf is. The defect is not "the rows differ"; it is
//! **someone edited one copy and not the other**. A clippy fix landing on one side is a
//! true positive for that — it is direct evidence the two files are being maintained
//! independently, which is the condition this check exists to detect. The remedy when it
//! fires is to sync the copies, which takes seconds; it only cries wolf if you decline to.
//! To keep that cheap, the failure below names the exact line and prints both texts.
//!
//! This file reads both copies with `include_str!` and compares in-process. It shells out
//! to nothing, so it cannot be fooled by a `sed`/`awk` portability difference — HazyTurtle
//! lost a first attempt at this comparison to BSD `sed` silently not supporting `\b`.

/// The first line both copies share verbatim. Everything above it in the `tests/` copy is
/// its own header plus `#![allow(dead_code)]`, which is forced by that location and is not
/// part of the rows.
const SHARED_ANCHOR: &str =
    "//! Ordered acceptance rows and canonical receipts for LIMIT-01 A and B.";

const IN_CRATE: &str = include_str!("../src/limit_01_rows.rs");
const EXTERNAL: &str = include_str!("limit_01_rows/mod.rs");

/// Which copy is being normalized. Each rewrite is applied ONLY to the copy whose location
/// forces it, never to both.
///
/// A symmetric normalizer would be simpler and subtly wrong: rewriting `fastmcp_core::` in
/// BOTH copies means that if the in-crate copy ever names `fastmcp_core::` itself — legal,
/// since a crate may refer to itself by name — the rewrite would erase a genuine difference
/// instead of reporting it. Same for `pub(crate)` appearing in the external copy. Making the
/// rewrites directional costs one enum and removes both blind spots, which beats documenting
/// them.
enum Side {
    /// `src/limit_01_rows.rs` — a private module inside the crate.
    InCrate,
    /// `tests/limit_01_rows/mod.rs` — compiled into an integration target.
    External,
}

/// Drops each copy's location-specific header and normalizes the one difference its
/// location forces.
fn normalized(source: &str, which: &Side, label: &str) -> String {
    let start = source.find(SHARED_ANCHOR).unwrap_or_else(|| {
        panic!(
            "{label}: the shared anchor line is absent, so the two copies cannot be aligned \
             at all"
        )
    });
    // Normalize line endings before any structural work, so a stray CR cannot masquerade as
    // a content difference.
    let body = source[start..].replace("\r\n", "\n").replace('\r', "\n");
    match which {
        // Forced by being in-crate: items are `pub(crate)` because the module is private.
        Side::InCrate => body.replace("pub(crate) ", "pub "),
        // Forced by being external: the crate is reached by name, not by `crate::`.
        Side::External => body.replace("fastmcp_core::", "crate::"),
    }
}

#[test]
fn limit_01_rows_copies_do_not_drift() {
    let in_crate = normalized(IN_CRATE, &Side::InCrate, "src/limit_01_rows.rs");
    let external = normalized(EXTERNAL, &Side::External, "tests/limit_01_rows/mod.rs");

    // A digest would report only THAT they differ. Walking the lines reports WHERE, which is
    // what makes the repair cheap enough that firing on a one-sided lint fix is acceptable.
    for (index, (left, right)) in in_crate.lines().zip(external.lines()).enumerate() {
        assert_eq!(
            left,
            right,
            "the LIMIT-01 acceptance rows have DRIFTED at normalized line {}.\n  \
             src/limit_01_rows.rs:       {left:?}\n  \
             tests/limit_01_rows/mod.rs: {right:?}\n  \
             Both copies are required and neither may be deleted. Bring them back into sync \
             rather than widening the normalizer in this file — a normalizer generous enough \
             to absorb this divergence will absorb the next one, and the next one may be an \
             edited bound.",
            index + 1
        );
    }

    // `zip` stops at the shorter input, so a pure append to either copy would slip past the
    // loop above with every compared line equal.
    assert_eq!(
        in_crate.lines().count(),
        external.lines().count(),
        "the LIMIT-01 acceptance rows agree line-for-line as far as the shorter copy goes, \
         but src/ has {} normalized lines and tests/ has {} — content was appended to or \
         removed from the end of one of them",
        in_crate.lines().count(),
        external.lines().count()
    );
}

/// The normalizer must not be able to report success by erasing everything.
///
/// Without this, a future edit that broadened [`normalized`] into something degenerate would
/// make the drift check above pass vacuously on two empty strings. Name the worthless
/// implementation: `fn normalized(..) -> String { String::new() }` passes the test above and
/// fails every assertion here.
#[test]
fn the_drift_check_compares_substantive_content() {
    let in_crate = normalized(IN_CRATE, &Side::InCrate, "src/limit_01_rows.rs");

    assert!(
        in_crate.lines().count() > 400,
        "the normalized rows collapsed to {} lines; the drift check is comparing almost \
         nothing and would pass whatever the two copies said",
        in_crate.lines().count()
    );

    // One row ID from each acceptance range, so a normalizer that ate either half is caught.
    for row in ["LIMIT-A-01.01", "LIMIT-B-01.01"] {
        assert!(
            in_crate.contains(row),
            "normalization removed row {row}, so the check no longer covers the acceptance \
             rows it exists to protect"
        );
    }

    // The execution logic is the half a row-data digest could not see, and therefore the
    // half this check exists to cover. If normalization ever stopped including it, this
    // file would silently become the weaker instrument it was chosen over.
    for executor in ["fn run_bound_rows", "fn run_partition_rows", "fn run_fairness_rows"] {
        assert!(
            in_crate.contains(executor),
            "normalization removed {executor}, so the check no longer covers the row-running \
             logic — which is the only reason it compares source text instead of row data"
        );
    }
}
