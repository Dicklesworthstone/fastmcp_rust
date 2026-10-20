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
use std::time::Duration;

use fastmcp_rust::http_auth::dpop::{DpopClientError, DpopError, DpopKey, DpopSession};
use fastmcp_rust::http_auth::sampling::{SamplingRunLimits, SamplingToolLoopLimits};
use fastmcp_rust::http_auth::{CanonicalHttpUrl, PartitionAuthorization};
use fastmcp_rust::partition::{CredentialStoreKey, DurableOwnerKey, PartitionDescriptor};
use fastmcp_rust::runtime::ProcessGenerationGuard;

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
fn names_routed_method(
    method: fastmcp_rust::McpAppsRoutedMethod,
) -> fastmcp_rust::McpAppsRoutedMethod {
    method
}

/// `SamplingRunLimits::new` takes a `SamplingToolLoopLimits` BY VALUE, so any
/// consumer wanting a conversation bound other than the default must write that
/// name. The facade forwards `http_auth` and `sampling` is `pub mod` there, but
/// `fastmcp_protocol::sampling` is NOT a forwarded module and the type is in no
/// explicit facade list, so before the re-export this function could not be
/// written against `fastmcp_rust` alone. That unwritability is the planted
/// negative for this closure claim, in the same form as the three above.
fn builds_sampling_run_limits() -> Result<SamplingRunLimits, ()> {
    let conversation = SamplingToolLoopLimits::new(1, 8, 4096).map_err(|_| ())?;
    SamplingRunLimits::new(conversation, Duration::from_secs(1), 4096).map_err(|_| ())
}

#[test]
fn facade_names_the_sampling_limits_its_run_constructor_demands() {
    // Positive observable: a NON-DEFAULT conversation bound is accepted, which
    // cannot be expressed without naming `SamplingToolLoopLimits`. Reaching
    // `SamplingRunLimits::default()` would prove nothing, because the default
    // never forces the inner type into caller code.
    assert!(
        builds_sampling_run_limits().is_ok(),
        "a non-default sampling conversation bound is constructible via the facade"
    );

    // Negative control differing only in the forbidden dimension: the same
    // constructor, same conversation bound, refuses a zero timeout. Without
    // this, a `new` returning Ok unconditionally would satisfy the positive
    // above (RH-5).
    let conversation =
        SamplingToolLoopLimits::new(1, 8, 4096).expect("the loop bounds are within the ceilings");
    assert!(
        SamplingRunLimits::new(conversation, Duration::ZERO, 4096).is_err(),
        "a zero timeout must be refused, so the positive is not vacuous"
    );
}

/// Builds the descriptor both partition keys derive from. Worth noting that
/// `from_verified_facts` takes only primitives, so a consumer needs no further
/// types to reach this point — the descriptor is the whole prerequisite.
fn verified_descriptor() -> Result<PartitionDescriptor, ()> {
    PartitionDescriptor::from_verified_facts(
        "test-provider",
        1,
        "https://issuer.example.test",
        "https://example.test/mcp",
        "tenant-a",
        "subject-a",
        "client-a",
        1,
        1,
        &[b"https://example.test/mcp"],
    )
    .map_err(|_| ())
}

#[test]
fn facade_names_the_partition_types_its_credential_store_api_demands() {
    // `http_auth::oauth::persistence::OAuthRefreshStore::open` is reachable
    // through the forwarded `http_auth` tree and its THIRD parameter is a
    // `&CredentialStoreKey`, obtainable only via the associated `derive`. So
    // the constructor was reachable while being uncallable: naming the key and
    // its descriptor required a direct dependency on `fastmcp-core`. An earlier
    // fix re-exported only `PartitionAuthorization`, the FOURTH parameter,
    // which left the call still unwritable.
    let descriptor = verified_descriptor().expect("a descriptor builds from verified facts");

    // Positive observable 1: a real credential-store key derives. The opaque
    // key macro emits `as_bytes` as its only accessor, so the 32-byte digest is
    // the observable rather than mere absence of a panic.
    let key = CredentialStoreKey::derive(
        &descriptor,
        "store-main",
        "credential-class-refresh",
        "token-instance-1",
    )
    .expect("a credential store partition derives");
    assert_eq!(key.as_bytes().len(), 32);

    // Positive observable 2: the durable owner key, demanded by
    // `http_auth::managed::tasks::watch::checkpoint::resume`, derives from the
    // same descriptor and is distinct from the credential key — two different
    // partition domains must not collide into one digest.
    let owner = DurableOwnerKey::derive(&descriptor, 7).expect("a durable owner derives");
    assert_ne!(
        owner.as_bytes(),
        key.as_bytes(),
        "distinct partition domains must derive distinct digests"
    );

    // Negative control differing only in the forbidden dimension: same
    // descriptor, same other arguments, but an EMPTY store domain is refused by
    // `require_admission_field`. Without this, a `derive` that accepted
    // anything would satisfy both positives above (RH-5).
    assert!(
        CredentialStoreKey::derive(&descriptor, "", "credential-class-refresh", "token-instance-1")
            .is_err(),
        "an empty admission field must be refused, so the positives are not vacuous"
    );

    // `ProcessGenerationGuard` is demanded by `CredentialIoLane::new` in the
    // same forwarded tree. Named at signature level ONLY: `install()` plants a
    // process-global `&'static`, which a test must not inflict on its siblings.
    // Taking the address of a declared fn rather than coercing a closure,
    // matching `borrows_authorization` below — a closure would have to be
    // generic over the lifetime to coerce to this fn pointer type.
    let names_guard: fn(&ProcessGenerationGuard) -> &ProcessGenerationGuard = borrows_guard;
    let _ = names_guard;
}

/// Signature-level companion to the test above: proves the name resolves
/// without installing the process-global that `ProcessGenerationGuard::install`
/// would plant.
fn borrows_guard(guard: &ProcessGenerationGuard) -> &ProcessGenerationGuard {
    guard
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

#[cfg(feature = "apps")]
#[test]
fn facade_sampling_effect_is_implementable_and_consent_is_explicit() {
    use fastmcp_rust::{
        Cx, McpAppsHostError, McpAppsSamplingParams, McpAppsSamplingResult, McpAppsWireHostEffects,
        McpRequestCancellation,
    };

    struct ApprovedSampling;

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "The consumer fixture returns immediately through the async effects contract."
    )]
    impl McpAppsWireHostEffects for ApprovedSampling {
        async fn sampling_create_message(
            &mut self,
            cx: &Cx,
            cancellation: &McpRequestCancellation,
            params: &McpAppsSamplingParams,
        ) -> Result<McpAppsSamplingResult, McpAppsHostError> {
            assert!(cx.checkpoint().is_ok());
            assert!(!cancellation.is_cancel_requested());
            assert_eq!(params.messages.len(), 1);
            Ok(serde_json::from_value(serde_json::json!({
                "role": "assistant", "model": "consumer-owned-model",
                "content": {"type": "text", "text": "Approved response"}
            }))
            .unwrap())
        }
    }

    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let cancellation = McpRequestCancellation::new();
        // Both public import paths must describe the callback's exact payload.
        let params: fastmcp_rust::modern::McpAppsSamplingParams =
            serde_json::from_value(serde_json::json!({
                "messages": [{"role": "user", "content": {"type": "text", "text": "Summarize"}}],
                "maxTokens": 128
            }))
            .unwrap();
        let capability: fastmcp_rust::modern::McpAppsSamplingCapability = Default::default();
        assert!(capability.tools.is_none());
        let result: fastmcp_rust::modern::McpAppsSamplingResult = ApprovedSampling
            .sampling_create_message(&cx, &cancellation, &params)
            .await
            .unwrap();
        assert_eq!(result.model, "consumer-owned-model");
        assert!(
            ().sampling_create_message(&cx, &cancellation, &params)
                .await
                .is_err()
        );
    });
}

/// MCP Apps embedder control hooks: the TRAIT-METHOD position, which the first
/// closure sweep could not see because it matched only `pub fn` parameter and
/// return lists.
///
/// WHY THIS POSITION IS STRICTLY STRONGER THAN A PARAMETER. The exemption that
/// retired several earlier candidates was "the value is obtainable from a
/// reachable accessor", and for a free function it holds: you can write
/// `f(thing.accessor())` without ever naming the argument's type. A trait impl
/// cannot do that. `impl Trait for MyType` must RESTATE each overridden
/// method's parameter and return types verbatim, so possessing a value is no
/// substitute for being able to write the name. `McpAppsJsonRpcRequestId` is
/// the exact case: it has `new`/`string`/`host` constructors AND public
/// variants, and it was still unnameable through the facade.
///
/// WHAT WAS BROKEN. The facade already exported `McpAppsWireHostPolicy`,
/// `McpAppsWireHostEffects` and `McpAppsHostRequestOutcome` — a trait an
/// embedder implements, a second trait of embedder callbacks, and the enum an
/// Apps request resolves to — while every type their signatures demand lived
/// in `fastmcp_protocol::mcp_apps_bridge`, which the facade did not forward.
/// At the parent commit each path below resolved to NOTHING: all six names
/// occurred exactly 0 times in `crates/fastmcp/src/`, against 4 occurrences of
/// the `McpAppsWireHostEffects` control, so this test is its own planted
/// negative and could not have passed before `pub use
/// fastmcp_protocol::mcp_apps_bridge`.
///
/// NO-CLAIM. Every affected method is DEFAULTED, so the traits were always
/// implementable; what was unreachable was *overriding* the progress,
/// cancellation and initialize hooks without a direct dependency on
/// `fastmcp-protocol`. This proves those six names resolve and that two
/// overrides actually run — nothing about Apps conformance, and nothing about
/// the hooks this test does not override.
#[cfg(feature = "apps")]
#[test]
fn facade_names_the_apps_control_types_its_embedder_hooks_demand() {
    use fastmcp_rust::mcp_apps_bridge::{
        McpAppsCancelledControlParams, McpAppsJsonRpcError, McpAppsJsonRpcRequestId,
        McpAppsPinnedInitializeParams, McpAppsPinnedInitializeResult,
        McpAppsProgressControlParams,
    };
    use fastmcp_rust::{Cx, McpAppsHostError, McpAppsHostRequestOutcome, McpAppsWireHostEffects};

    #[derive(Default)]
    struct RecordingEffects {
        progress_seen: usize,
        cancels_seen: usize,
        last_progress: f64,
    }

    // The two signatures are the assertion. Each one names a type that could
    // not be written through the facade at the parent commit.
    impl McpAppsWireHostEffects for RecordingEffects {
        async fn progress(
            &mut self,
            request_id: &McpAppsJsonRpcRequestId,
            params: &McpAppsProgressControlParams,
        ) -> Result<(), McpAppsHostError> {
            assert_eq!(request_id, &params.progress_token);
            self.progress_seen += 1;
            self.last_progress = params.progress;
            Ok(())
        }

        fn cancelled(
            &mut self,
            cx: &Cx,
            request_id: &McpAppsJsonRpcRequestId,
            params: &McpAppsCancelledControlParams,
        ) -> Result<(), McpAppsHostError> {
            assert!(cx.checkpoint().is_ok());
            assert_eq!(params.request_id.as_ref(), Some(request_id));
            self.cancels_seen += 1;
            Ok(())
        }
    }

    // The `initialize` override's exact shape. That hook additionally requires
    // CONSTRUCTING its result, because
    // `McpAppsWireHostConfiguration::initialize_result`
    // (crates/fastmcp-client/src/mcp_apps.rs:794) is private, so an embedder
    // cannot delegate to the default behaviour it replaces. That is a separate
    // gap, recorded on the bead and deliberately not fixed here; this binding
    // proves only that both names now resolve.
    fn initialize_override_shape(
        _params: &McpAppsPinnedInitializeParams,
        prepared: McpAppsPinnedInitializeResult,
    ) -> McpAppsPinnedInitializeResult {
        prepared
    }
    let _shape: fn(
        &McpAppsPinnedInitializeParams,
        McpAppsPinnedInitializeResult,
    ) -> McpAppsPinnedInitializeResult = initialize_override_shape;

    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let request_id = McpAppsJsonRpcRequestId::Number(7);
        let progress_params = McpAppsProgressControlParams {
            progress_token: McpAppsJsonRpcRequestId::Number(7),
            progress: 0.5,
            total: Some(1.0),
            message: None,
        };
        let cancel_params = McpAppsCancelledControlParams {
            request_id: Some(McpAppsJsonRpcRequestId::Number(7)),
            reason: Some("view closed".to_owned()),
        };

        // POSITIVE: both overrides run and mutate embedder-owned state.
        let mut effects = RecordingEffects::default();
        effects
            .progress(&request_id, &progress_params)
            .await
            .unwrap();
        effects
            .cancelled(&cx, &request_id, &cancel_params)
            .unwrap();
        assert_eq!(effects.progress_seen, 1);
        assert_eq!(effects.cancels_seen, 1);
        assert!((effects.last_progress - 0.5).abs() < f64::EPSILON);

        // NEGATIVE (RH-5): the library's own no-op impl for `()`, invoked with
        // the IDENTICAL arguments and differing only in whether the hook is
        // overridden. It must succeed while recording nothing, which is what
        // makes the counters above attributable to the override rather than to
        // the call. Without this arm the positive passes vacuously.
        ().progress(&request_id, &progress_params).await.unwrap();
        ().cancelled(&cx, &request_id, &cancel_params).unwrap();
        assert_eq!(effects.progress_seen, 1);
        assert_eq!(effects.cancels_seen, 1);
    });

    // A peer error must be nameable to be PROPAGATED, not merely matched: the
    // `let` annotation below is what an embedder storing the error in its own
    // type has to write, and matching alone would never have detected its
    // absence because a pattern binds the payload without naming it.
    let outcome = McpAppsHostRequestOutcome::PeerError(McpAppsJsonRpcError {
        code: -32601,
        message: "method not found".to_owned(),
        data: None,
    });
    let stored: McpAppsJsonRpcError = match outcome {
        McpAppsHostRequestOutcome::PeerError(err) => err,
        other => panic!("constructed PeerError must match itself, got {other:?}"),
    };
    assert_eq!(stored.code, -32601);
    assert_eq!(stored.message, "method not found");
    assert!(stored.data.is_none());
}
