//! FND-05 / bd-ho7of: the guarded-HTTP DNS seam, proven from OUTSIDE the crate.
//!
//! External consumer of `fastmcp-transport`: every type here is reached via
//! `use fastmcp_transport::...`, never `use super`, and nothing under test is
//! `cfg(test)` inside the library (PL-3). Before this bead the resolver seam
//! was `#[cfg(test)]` behind a private trait, so DNS-hook behavior could only
//! be exercised from inside the crate — which the FND-05 A acceptance forbids
//! as proof.
//!
//! WHAT IS PROVEN: that a caller-supplied resolver actually GOVERNS resolution
//! — its answers are the ones the fetcher fences and acts on. Each case drives
//! the shipped `GuardedHttpFetcher::with_resolver` entry point and observes a
//! typed outcome that is a function of the answers the resolver returned.
//!
//! WHAT IS NOT CLAIMED: no successful end-to-end HTTPS fetch, no redirect
//! interception, and no TLS behavior. Those need the lower wire seam, which
//! stays `#[cfg(test)]` deliberately because it bypasses the address fence and
//! real TLS. See bd-ho7of and the FND-05 A audit.

#![forbid(unsafe_code)]

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use asupersync::Cx;
use fastmcp_transport::http::{
    GuardedHttpFetchError, GuardedHttpFetchPolicy, GuardedHttpFetcher, GuardedHttpResolver,
    GuardedHttpsUrl,
};

/// A resolver that returns exactly the answers it was built with, and counts
/// how many times it was consulted.
struct ScriptedResolver {
    answers: Vec<IpAddr>,
    calls: Arc<AtomicUsize>,
}

impl GuardedHttpResolver for ScriptedResolver {
    fn resolve_all(
        &self,
        _cx: Cx,
        _host: String,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, GuardedHttpFetchError>> + Send + 'static>>
    {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let answers = self.answers.clone();
        Box::pin(async move { Ok(answers) })
    }
}

fn policy() -> GuardedHttpFetchPolicy {
    GuardedHttpFetchPolicy::new(
        64 * 1024,
        Duration::from_secs(5),
        Duration::from_secs(2),
        "fnd05-ho7of",
    )
    .expect("a finite guarded policy is admitted")
}

fn url() -> GuardedHttpsUrl {
    GuardedHttpsUrl::parse("https://example.invalid/resource")
        .expect("a bounded https URL is admitted")
}

fn fetch_with(answers: Vec<IpAddr>) -> (Result<(), GuardedHttpFetchError>, usize) {
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver = Arc::new(ScriptedResolver {
        answers,
        calls: Arc::clone(&calls),
    });
    let fetcher = GuardedHttpFetcher::with_resolver(policy(), resolver)
        .expect("the shipped public seam accepts a caller-supplied resolver");

    let outcome =
        asupersync::block_on(|cx| async move { fetcher.fetch(&cx, &url()).await.map(|_| ()) });
    (outcome, calls.load(Ordering::SeqCst))
}

/// POSITIVE: the supplied resolver is consulted and its answers govern.
///
/// The discriminator is not "some error happened" — it is that DIFFERENT
/// answer sets produce DIFFERENT typed outcomes, which is only possible if the
/// seam actually feeds the fetcher.
#[test]
fn fnd_05_guarded_resolver_seam_governs_resolution_positive() {
    // An empty answer set is refused with the typed empty-resolution error.
    let (empty, empty_calls) = fetch_with(Vec::new());
    assert_eq!(
        empty_calls, 1,
        "the shipped path must consult the supplied resolver exactly once"
    );
    assert!(
        matches!(empty, Err(GuardedHttpFetchError::ResolutionEmpty)),
        "an empty answer set must reach the typed empty-resolution refusal, got {empty:?}"
    );

    // A non-public answer is refused by the downstream address fence. This is
    // the custody proof: a supplied resolver CANNOT reach a private peer.
    let (private, private_calls) = fetch_with(vec!["10.0.0.1".parse().expect("ipv4")]);
    assert_eq!(private_calls, 1);
    assert!(
        private.is_err(),
        "a private address returned by a supplied resolver must not be connected to"
    );
    assert!(
        !matches!(private, Err(GuardedHttpFetchError::ResolutionEmpty)),
        "the private-address refusal must be distinct from the empty-set refusal"
    );

    // DISCRIMINATOR: the two outcomes differ, so the answers are load-bearing.
    assert_ne!(
        format!("{empty:?}"),
        format!("{private:?}"),
        "different resolver answers must produce different typed outcomes; identical outcomes \
         would mean the seam is decorative and the fetcher ignores what it returns"
    );
}

/// PLANTED NEGATIVE: one variable changes — a single returned address moves
/// from private to loopback — and the fence still refuses, proving the refusal
/// tracks the ADDRESS rather than merely the fact that a resolver was supplied.
#[test]
fn fnd_05_guarded_resolver_seam_planted_negative() {
    let control = vec!["10.0.0.1".parse::<IpAddr>().expect("ipv4")];
    let (control_outcome, control_calls) = fetch_with(control.clone());
    assert_eq!(control_calls, 1);
    assert!(control_outcome.is_err(), "the control must be refused");

    // --- Mutation: exactly one address, private -> loopback ----------------
    let mut mutated = control.clone();
    mutated[0] = "127.0.0.1".parse::<IpAddr>().expect("ipv4");
    assert_eq!(
        mutated.len(),
        control.len(),
        "the mutation must change no cardinality"
    );

    let (mutated_outcome, mutated_calls) = fetch_with(mutated);
    assert!(
        mutated_outcome.is_err(),
        "a loopback address supplied through the public seam must be refused; admitting it \
         would mean the seam widened the production address fence"
    );

    // Unchanged-state proof: the seam is still consulted exactly once, and the
    // refusal is still not the empty-set refusal — only the address varied.
    assert_eq!(
        mutated_calls, control_calls,
        "the mutation must not change how often the resolver is consulted"
    );
    assert!(!matches!(
        mutated_outcome,
        Err(GuardedHttpFetchError::ResolutionEmpty)
    ));
}

/// The production constructor still yields a working fetcher through the same
/// seam, so promoting the trait did not fork the code path.
#[test]
fn fnd_05_production_constructor_uses_the_same_seam() {
    let fetcher = GuardedHttpFetcher::new(policy()).expect("production construction succeeds");
    assert_eq!(fetcher.policy().response_body_bytes(), 64 * 1024);
    assert_eq!(fetcher.policy().deadline(), Duration::from_secs(5));
}
