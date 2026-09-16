//! LEG-HTTP-01 B — exact `2024-11-05` GET+SSE origin/auth security, framing,
//! backpressure, reconnect, and deterministic close.
//!
//! # Why this module records a conflict instead of resolving it
//!
//! The frozen acceptance floors for the legacy SSE lane and the bounds the
//! shipped transport actually enforces disagree, in one case by 512x. The
//! shipped bound is not an oversight: the pending-queue bound carries an
//! explicit rationale that the exact legacy lane shares one long-lived response
//! body, so per-event limits alone do not bound the allocation a single native
//! body frame can cause.
//!
//! Raising a production constant so an acceptance floor becomes reachable is the
//! same defect class as regenerating a golden — it buys a green row by moving
//! the thing being measured. So this evaluator **exercises the shipped bound**
//! and **records the disagreement** as a first-class observation
//! ([`LimitConflict`]). A red row naming both numbers and both rationales is the
//! honest output; resolving it belongs to the structure owner.
//!
//! # Why the bounds are measured rather than declared
//!
//! The acceptance criteria forbid copied-constant evidence, and the shipped
//! bounds are private to the transport in any case. Writing `16 * 1024` into a
//! manifest here would be both a copied constant and a restatement of the
//! implementation, so it would prove nothing.
//!
//! Instead [`ObservedLimit`] is produced by driving the real public legacy lane
//! until it refuses, which measures the bound the shipped code actually applies.
//! A manifest row then states the frozen floor, and the two are compared. If the
//! transport's bound changes, the measurement changes with it; nothing here has
//! to be kept in sync by hand.

use fastmcp_core::{Sha256Digest, sha256_bounded};

/// Bound for the manifest digest input.
const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// The exact legacy protocol version this leaf admits.
pub const LEGACY_ERA_VERSION: &str = "2024-11-05";
/// The planted unsupported version. Negative use only; never admitted.
pub const UNSUPPORTED_ERA_VERSION: &str = "2025-11-25";

/// The immutable LEG-HTTP-01 B evaluator manifest.
///
/// LF-canonical and LF-terminated. It freezes the ordered security/lifecycle
/// rows and the acceptance floors **as the acceptance criteria state them**, not
/// as the implementation currently enforces them. That distinction is the point:
/// a manifest written down to the shipped values would restate the code and
/// could never surface a disagreement with the frozen contract.
///
/// `floor-guarded` and `floor-hard` are the two-tier ceilings from the frozen
/// package contract. `unit` disambiguates a byte count from an item count.
pub const LEG_HTTP_01_B_EVALUATOR_MANIFEST_V1: &str = concat!(
    "LEG-HTTP-01-B evaluator manifest v1\n",
    "entrypoint fastmcp_client::http_executor::LegacySseHttpClient\n",
    "transport legacy-http-get-sse\n",
    "era 2024-11-05\n",
    "row 01 same-origin-uri-admission\n",
    "row 02 authentication-credential-binding\n",
    "row 03 malformed-sse-framing\n",
    "row 04 redirect-denial\n",
    "row 05 server-error-denial\n",
    "row 06 size-and-queue-backpressure\n",
    "row 07 endpoint-mutation-denial\n",
    "row 08 bounded-reconnect\n",
    "row 09 bidirectional-frames-after-reconnect\n",
    "row 10 cancellation\n",
    "row 11 deterministic-close\n",
    "limit sse-line floor-guarded=8388616 floor-hard=33554440 unit=bytes\n",
    "limit sse-event floor-guarded=9437184 floor-hard=37748736 unit=bytes\n",
    "limit sse-data-lines-per-event floor-guarded=4096 floor-hard=65536 unit=lines\n",
    "limit outbound-queue-events floor-guarded=256 floor-hard=4096 unit=events\n",
    "limit outbound-queue-bytes floor-guarded=9437184 floor-hard=37748736 unit=bytes\n",
    "limit guarded-idle-lifetime floor-guarded=60 floor-hard=600 unit=seconds\n",
    "limit absolute-lifetime floor-guarded=900 floor-hard=7200 unit=seconds\n",
    "invariant first-endpoint-count=1 per stream generation\n",
    "invariant same-origin-uri precedes credential use\n",
    "invariant no cross-generation endpoint mutation\n",
);

/// Returns the canonical LEG-HTTP-01 B evaluator manifest digest.
///
/// The manifest is an executable acceptance input, not a source-file hash: it
/// binds the ordered rows, the frozen floors, and the stream invariants.
#[must_use]
pub fn leg_http_01_b_manifest_digest() -> Sha256Digest {
    sha256_bounded(
        LEG_HTTP_01_B_EVALUATOR_MANIFEST_V1.as_bytes(),
        MAX_MANIFEST_BYTES,
    )
    .expect("the fixed LEG-HTTP-01 B manifest is within its exact byte bound")
}

/// One frozen floor parsed from the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenLimit {
    name: String,
    guarded: u64,
    hard: u64,
    unit: String,
}

impl FrozenLimit {
    /// Returns the manifest's name for this limit.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the guarded floor: the minimum the contract requires.
    #[must_use]
    pub const fn guarded(&self) -> u64 {
        self.guarded
    }

    /// Returns the hard ceiling.
    #[must_use]
    pub const fn hard(&self) -> u64 {
        self.hard
    }

    /// Returns the unit, so a byte count is never compared to an item count.
    #[must_use]
    pub fn unit(&self) -> &str {
        &self.unit
    }
}

/// Parses every `limit` row from the manifest, in declaration order.
///
/// Panics only on a malformed manifest, which is a frozen constant in this
/// crate and therefore a build-time authoring error rather than a runtime input.
#[must_use]
pub fn frozen_limits() -> Vec<FrozenLimit> {
    let mut limits = Vec::new();
    for line in LEG_HTTP_01_B_EVALUATOR_MANIFEST_V1.lines() {
        let Some(rest) = line.strip_prefix("limit ") else {
            continue;
        };
        let mut fields = rest.split(' ');
        let name = fields
            .next()
            .expect("a limit row names its limit")
            .to_owned();
        let mut guarded = None;
        let mut hard = None;
        let mut unit = None;
        for field in fields {
            if let Some(value) = field.strip_prefix("floor-guarded=") {
                guarded = value.parse::<u64>().ok();
            } else if let Some(value) = field.strip_prefix("floor-hard=") {
                hard = value.parse::<u64>().ok();
            } else if let Some(value) = field.strip_prefix("unit=") {
                unit = Some(value.to_owned());
            }
        }
        limits.push(FrozenLimit {
            name,
            guarded: guarded.expect("a limit row declares floor-guarded"),
            hard: hard.expect("a limit row declares floor-hard"),
            unit: unit.expect("a limit row declares its unit"),
        });
    }
    limits
}

/// Returns the ordered security/lifecycle row identifiers from the manifest.
#[must_use]
pub fn ordered_rows() -> Vec<(u8, String)> {
    LEG_HTTP_01_B_EVALUATOR_MANIFEST_V1
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("row ")?;
            let (ordinal, name) = rest.split_once(' ')?;
            Some((ordinal.parse::<u8>().ok()?, name.to_owned()))
        })
        .collect()
}

/// A bound observed by driving the shipped transport until it refused.
///
/// This is a measurement, never a declaration. `accepted` is the largest input
/// the transport admitted and `refused` the smallest it rejected, so the true
/// boundary lies in `accepted < boundary <= refused`. Recording both ends keeps
/// the observation honest about its own resolution instead of asserting a single
/// exact number the probe did not actually establish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedLimit {
    accepted: u64,
    refused: u64,
}

impl ObservedLimit {
    /// Records a measured boundary.
    ///
    /// # Panics
    ///
    /// Panics when `accepted >= refused`, which would mean the probe observed
    /// the transport both admitting and refusing the same size, and when
    /// `accepted == 0`.
    ///
    /// A zero `accepted` is not a small bound, it is the **absence of a
    /// measurement**: the probe never saw the transport admit anything, so the
    /// only number it carries is whatever size happened to be tried first. Any
    /// ratio derived from that describes the probe's starting point rather than
    /// the transport, and a [`LimitConflict`] built on it would put an artifact
    /// into the record as though it were evidence. Refusing it here makes a
    /// vacuous measurement unrepresentable rather than merely discouraged.
    #[must_use]
    pub fn new(accepted: u64, refused: u64) -> Self {
        assert!(
            accepted > 0,
            "an observed boundary needs at least one admitted size; accepted == 0 means the \
             probe measured nothing, and {refused} is only the size it happened to try first"
        );
        assert!(
            accepted < refused,
            "an observed boundary needs accepted < refused, got {accepted} and {refused}"
        );
        Self { accepted, refused }
    }

    /// The largest input the shipped transport admitted.
    #[must_use]
    pub const fn accepted(&self) -> u64 {
        self.accepted
    }

    /// The smallest input the shipped transport refused.
    #[must_use]
    pub const fn refused(&self) -> u64 {
        self.refused
    }
}

/// A recorded disagreement between a frozen floor and the shipped bound.
///
/// This type exists so the disagreement is *evidence* rather than a comment. The
/// evaluator emits one per limit it could measure, and the test surfaces them;
/// nothing here silently reconciles the two numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitConflict {
    limit: String,
    unit: String,
    frozen_guarded: u64,
    observed: ObservedLimit,
}

impl LimitConflict {
    /// Compares one frozen floor against one measured bound.
    ///
    /// Returns `None` when the shipped transport already admits the guarded
    /// floor, which is the non-conflicting case.
    #[must_use]
    pub fn detect(frozen: &FrozenLimit, observed: ObservedLimit) -> Option<Self> {
        if observed.accepted() >= frozen.guarded() {
            return None;
        }
        Some(Self {
            limit: frozen.name().to_owned(),
            unit: frozen.unit().to_owned(),
            frozen_guarded: frozen.guarded(),
            observed,
        })
    }

    /// Returns the manifest limit name.
    #[must_use]
    pub fn limit(&self) -> &str {
        &self.limit
    }

    /// How many times larger the frozen floor is than the shipped bound.
    ///
    /// Reported against the refusal point, the first size the transport is known
    /// to reject, so the factor is not overstated.
    #[must_use]
    pub fn factor(&self) -> u64 {
        self.frozen_guarded / self.observed.refused().max(1)
    }

    /// Renders the conflict for a failing assertion.
    ///
    /// The rendering names both numbers and both sides deliberately: whoever
    /// reads the red row needs to be able to decide the question, not just learn
    /// that a test failed.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "LIMIT CONFLICT on `{}`: the frozen acceptance floor demands >= {} {} but the shipped \
             transport admitted at most {} and refused {} ({}x). This is recorded, not resolved: \
             the shipped bound is deliberate - the exact legacy lane shares one long-lived response \
             body, so per-event limits alone do not bound the allocation one native body frame can \
             cause - and widening a production constant to reach an acceptance floor would buy a \
             green row by moving the thing being measured. The structure owner decides which number \
             is wrong.",
            self.limit,
            self.frozen_guarded,
            self.unit,
            self.observed.accepted(),
            self.observed.refused(),
            self.factor(),
        )
    }
}
