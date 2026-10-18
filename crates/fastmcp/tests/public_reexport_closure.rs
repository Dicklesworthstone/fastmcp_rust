//! Consumer-position proof that the published facade root is NAME-CLOSED:
//! every type the shipped public API *forces a caller to write down* can be
//! named through `fastmcp_rust` alone.
//!
//! WHY THIS CANNOT BE AN INLINE `#[cfg(test)]` TEST. Inside a crate every item
//! is reachable through `crate::`, so an inline test cannot observe a missing
//! re-export at all — it passes identically whether the `use` bringing a type
//! into a module is `pub use` or a private `use`. Only a separate target that
//! links the crate as a dependency sees the published surface. PL-3 states the
//! same rule generally: `cfg(test)` behaviour cannot prove shipped behaviour.
//!
//! WHAT A FAILURE LOOKS LIKE. The assertions here are the import paths and the
//! function signatures, not the `#[test]` bodies. If a re-export is removed or
//! demoted to a private `use`, this target stops COMPILING; it does not fail at
//! run time. The `#[test]` fn exists so the named types are exercised rather
//! than merely imported, which is what separates this from a ceremonial
//! compile-only wrapper (SM-12).
//!
//! WHAT IT DOES NOT PROVE, stated rather than implied. Each line below is one
//! exact path. Integration targets can also see the crate's regular
//! dependencies, so this does not prove that `fastmcp_core` and
//! `fastmcp_protocol` are unreachable by some other route — only that a
//! consumer who writes these paths through the facade succeeds. That is the
//! property the re-exports exist to provide: a caller depending on the facade
//! alone must not have to add a direct dependency on an internal crate to name
//! a type the facade's own API demands. It establishes no aggregate MCP
//! conformance, no profile maturity, and nothing about any type not listed.
//!
//! THE GAP THIS CLOSES. Three closure gaps were fixed in this crate's surface
//! without a consumer-position test, leaving implementation and proof split
//! across different units of work (RH-8). The pre-fix state is the planted
//! negative: before those commits each path below failed to resolve, and the
//! existing coverage read the same types out of `fastmcp_core` DIRECTLY
//! (`crates/fastmcp/tests/auth_00_integration.rs:61`, `use
//! fastmcp_core::partition::{..}`), which is exactly the workaround the
//! re-exports remove and therefore could never have detected their absence.

#![forbid(unsafe_code)]

// Every path below goes through `fastmcp_rust`. None of them names
// `fastmcp_core` or `fastmcp_protocol`, which is the entire point.
use fastmcp_rust::http_auth::dpop::{DpopClientError, DpopError, DpopKey, DpopSession};
use fastmcp_rust::http_auth::{CanonicalHttpUrl, PartitionAuthorization};

/// `DpopKey::generate` returns `Result<DpopKey, DpopError>`, so a consumer that
/// wraps key generation must be able to name BOTH types. Declared as a real
/// signature because that is the thing under test: the `?` here only compiles
/// if `DpopError` is nameable through the facade.
fn generate_key() -> Result<DpopKey, DpopError> {
    let key = DpopKey::generate()?;
    Ok(key)
}

/// A consumer inspecting a proof failure must name `DpopError` to reach the
/// inner value of `DpopClientError::Proof`. Returning a borrow of the inner
/// error is the minimal signature that forces the name into caller code.
fn proof_failure(error: &DpopClientError) -> Option<&DpopError> {
    match error {
        DpopClientError::Proof(inner) => Some(inner),
        _ => None,
    }
}

/// The `http_auth::oauth::persistence` store constructors take
/// `&PartitionAuthorization` (for example `OAuthRefreshStore::open`), so any
/// consumer writing a wrapper over them must be able to name it. Only the
/// signature is exercised: constructing one needs a `PartitionDescriptor` and
/// an owner key, which are not themselves part of this closure claim.
fn borrows_authorization(authorization: &PartitionAuthorization) -> &PartitionAuthorization {
    authorization
}

/// `McpAppsRoutedMethod` is re-exported from the facade ROOT rather than from
/// `http_auth`, and only under the `apps` feature, so it is named here under
/// the same gate. Without the feature this item is compiled out and proves
/// nothing, which is why the `#[test]` below does not depend on it.
#[cfg(feature = "apps")]
fn names_routed_method(method: fastmcp_rust::McpAppsRoutedMethod) -> fastmcp_rust::McpAppsRoutedMethod {
    method
}

#[test]
fn facade_root_names_every_type_its_dpop_api_demands() {
    // Positive observable 1: a real key is produced through a signature that
    // names `DpopError`, so the error type is nameable and not merely present.
    let key = generate_key().expect("a DPoP key generates from the facade surface");

    // Positive observable 2: drive the shipped refusal. `DpopSession::new`
    // admits only `https://` endpoints, so a cleartext token endpoint must come
    // back as `DpopClientError::Proof(DpopError::CleartextTarget)` — which can
    // only be asserted by a caller able to name the inner error.
    let cleartext =
        CanonicalHttpUrl::parse("http://example.test/token").expect("a plain http URL parses");
    let resource =
        CanonicalHttpUrl::parse("https://example.test/mcp").expect("an https URL parses");
    let refused = DpopSession::new(key, cleartext, resource)
        .err()
        .expect("a cleartext token endpoint is refused");
    assert!(
        matches!(proof_failure(&refused), Some(DpopError::CleartextTarget)),
        "a cleartext target must surface as Proof(CleartextTarget), got {refused:?}"
    );

    // Negative control for the matcher itself: a non-proof variant must NOT be
    // reported as a proof failure. Without this, `proof_failure` returning
    // `Some(..)` unconditionally would satisfy the assertion above (RH-5).
    assert!(
        proof_failure(&DpopClientError::KeyMismatch).is_none(),
        "only the Proof variant carries an inner DpopError"
    );

    // `PartitionAuthorization` is exercised at the signature level only; taking
    // the function's address proves the type resolved without constructing one.
    let borrow: fn(&PartitionAuthorization) -> &PartitionAuthorization = borrows_authorization;
    let _ = borrow;

    #[cfg(feature = "apps")]
    {
        let routed: fn(fastmcp_rust::McpAppsRoutedMethod) -> fastmcp_rust::McpAppsRoutedMethod =
            names_routed_method;
        let _ = routed;
    }
}
