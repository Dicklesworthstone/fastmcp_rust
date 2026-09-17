//! Local revocation of resource-bound bearer credentials, proved through the
//! shipped public surface.
//!
//! These are the external-consumer proofs for `BoundBearerCredential::revoke`
//! and `is_revoked`. The inline `#[cfg(test)]` module in
//! `crates/fastmcp-client/src/http_auth.rs` retains its own coverage of the
//! same behaviour, but an inline test reaches crate internals and compiles only
//! under `cfg(test)`, so it proves the test build rather than the shipped
//! artifact (PL-3). This target links `fastmcp-client` the way a downstream
//! crate does and touches nothing that is not `pub`.
//!
//! One consequence of that boundary is visible below and is the point of the
//! exercise: the inline expiry proof calls the private `authorization_at`,
//! which injects a clock. A downstream consumer has no such seam, so the
//! expiry cases here are expressed with real `Instant` deadlines that have
//! already elapsed or are far in the future. That is deterministic without
//! sleeping, and it is the only expiry behaviour a real consumer can actually
//! observe.

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use fastmcp_client::CanonicalHttpUrl;
use fastmcp_client::http_auth::{BearerBindingError, BoundBearerCredential};

const TOKEN: &str = "revocation-external-secret";
const RESOURCE: &str = "https://mcp.example/mcp";
const OTHER_RESOURCE: &str = "https://other.example/mcp";

fn url(value: &str) -> CanonicalHttpUrl {
    CanonicalHttpUrl::parse(value).expect("test URL is canonical")
}

fn bound(resource: &str, token: &str) -> BoundBearerCredential {
    BoundBearerCredential::bind(url(resource), token).expect("an https binding is admissible")
}

fn expected_header(token: &str) -> Option<String> {
    Some(format!("Bearer {token}"))
}

/// Revocation withholds the credential from the value it was called on, from
/// clones taken before it, and from clones taken after it — while leaving a
/// separately bound credential for the same resource completely unaffected.
#[test]
fn public_revocation_withholds_existing_and_future_clones() {
    let resource = url(RESOURCE);
    let credential = bound(RESOURCE, TOKEN);
    let clone_before = credential.clone();

    // A separate binding over the same resource and the same token. Revocation
    // must be a property of one credential lineage, not of the resource.
    let independent = bound(RESOURCE, TOKEN);

    for (label, candidate) in [("original", &credential), ("clone_before", &clone_before)] {
        assert!(!candidate.is_revoked(), "{label} starts unrevoked");
        assert_eq!(
            candidate.authorization_for_target(&resource),
            expected_header(TOKEN),
            "{label} releases its header before revocation"
        );
    }

    credential.revoke();

    // Taken after revocation, from an already-revoked value.
    let clone_after = credential.clone();

    for (label, candidate) in [
        ("original", &credential),
        ("clone_before", &clone_before),
        ("clone_after", &clone_after),
    ] {
        assert!(candidate.is_revoked(), "{label} observes the revocation");
        assert_eq!(
            candidate.authorization_for_target(&resource),
            None,
            "{label} must withhold its header after revocation"
        );
        // Revocation withholds the credential without disturbing the binding's
        // other observable facts.
        assert_eq!(
            candidate.resource().as_str(),
            RESOURCE,
            "{label} keeps its resource"
        );
        assert_eq!(candidate.expires_at(), None, "{label} keeps its expiry");
        assert!(
            !format!("{candidate:?}").contains(TOKEN),
            "{label} must not render the token even once revoked"
        );
    }

    assert!(
        !independent.is_revoked(),
        "a separately bound credential must not be revoked by another lineage"
    );
    assert_eq!(
        independent.authorization_for_target(&resource),
        expected_header(TOKEN),
        "a separately bound credential still releases its header"
    );
}

/// Expiry and revocation are independent conditions, and dropping a clone does
/// not undo a revocation.
#[test]
fn public_revocation_is_independent_of_expiry_and_clone_drop() {
    let resource = url(RESOURCE);

    // Expiry alone withholds the header and does NOT set the revoked flag.
    // Expressed with an already-elapsed deadline rather than a clock seam,
    // because a downstream consumer has no way to inject a time.
    let elapsed = Instant::now()
        .checked_sub(Duration::from_secs(60))
        .expect("a one-minute-old instant exists on this clock");
    let expired = BoundBearerCredential::bind_with_expiry(url(RESOURCE), TOKEN, elapsed)
        .expect("an https binding with an expiry is admissible");
    assert_eq!(
        expired.authorization_for_target(&resource),
        None,
        "an elapsed deadline withholds the header"
    );
    assert!(
        !expired.is_revoked(),
        "expiry is not local revocation and must not set the revoked flag"
    );
    assert_eq!(
        expired.expires_at(),
        Some(elapsed),
        "the expiry stays observable"
    );

    // Revocation alone withholds a credential whose deadline is far away.
    let distant = Instant::now()
        .checked_add(Duration::from_secs(3_600))
        .expect("a one-hour-ahead instant exists on this clock");
    let live = BoundBearerCredential::bind_with_expiry(url(RESOURCE), TOKEN, distant)
        .expect("an https binding with an expiry is admissible");
    assert_eq!(
        live.authorization_for_target(&resource),
        expected_header(TOKEN),
        "an unexpired credential releases its header"
    );
    live.revoke();
    assert!(live.is_revoked());
    assert_eq!(
        live.authorization_for_target(&resource),
        None,
        "revocation withholds the header while the deadline is still in the future"
    );
    assert_eq!(
        live.expires_at(),
        Some(distant),
        "revocation does not alter the recorded expiry"
    );

    // Dropping the clone that observed the revocation does not undo it.
    let credential = bound(RESOURCE, TOKEN);
    let clone = credential.clone();
    clone.revoke();
    assert!(clone.is_revoked());
    drop(clone);
    assert!(
        credential.is_revoked(),
        "dropping a revoked clone must not resurrect the credential"
    );
    assert_eq!(
        credential.authorization_for_target(&resource),
        None,
        "the surviving value still withholds its header"
    );
}

/// A revocation performed on one thread is visible to a credential that was
/// already moved to another thread.
///
/// Ordering is established with channels rather than sleeping, so the case is
/// deterministic: the worker proves the credential is live, the main thread
/// then revokes, and only then is the worker released to observe it.
#[test]
fn public_revocation_is_visible_across_threads() {
    let credential = bound(RESOURCE, TOKEN);
    let worker_credential = credential.clone();

    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let (revoked_tx, revoked_rx) = mpsc::channel::<()>();

    let worker = thread::spawn(move || {
        let resource = url(RESOURCE);
        // Observed on the worker thread before the main thread revokes.
        assert!(!worker_credential.is_revoked());
        assert_eq!(
            worker_credential.authorization_for_target(&resource),
            expected_header(TOKEN),
            "the moved credential is live before revocation"
        );
        ready_tx.send(()).expect("the main thread is still waiting");
        revoked_rx
            .recv()
            .expect("the main thread signals after revoking");

        assert!(
            worker_credential.is_revoked(),
            "a revocation on another thread must be visible here"
        );
        assert_eq!(
            worker_credential.authorization_for_target(&resource),
            None,
            "the moved credential withholds its header after revocation"
        );
    });

    ready_rx
        .recv()
        .expect("the worker reports it observed a live credential");
    credential.revoke();
    revoked_tx.send(()).expect("the worker is still waiting");

    worker
        .join()
        .expect("the worker thread completes its assertions");

    assert!(
        credential.is_revoked(),
        "the revoking thread also observes it"
    );
}

/// The revocation API does not create a way to mint a credential that binding
/// would have refused: a cleartext resource is still refused outright, so there
/// is nothing to revoke.
#[test]
fn public_revocation_does_not_bypass_binding_admission() {
    for cleartext in [
        "http://mcp.example/mcp",
        "http://localhost:8080/mcp",
        "http://127.0.0.1:8080/mcp",
    ] {
        let error = BoundBearerCredential::bind(url(cleartext), TOKEN)
            .err()
            .unwrap_or_else(|| panic!("{cleartext} must never hold a bearer credential"));
        assert_eq!(error, BearerBindingError::CleartextResource);
    }

    // A live credential still refuses a target it is not bound to, and
    // revocation does not change that answer.
    let credential = bound(RESOURCE, TOKEN);
    let other = url(OTHER_RESOURCE);
    assert_eq!(credential.authorization_for_target(&other), None);
    credential.revoke();
    assert_eq!(credential.authorization_for_target(&other), None);
}
