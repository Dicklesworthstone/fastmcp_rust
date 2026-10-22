//! Compile-time proof that the published facade is sufficient for the APIs it
//! advertises.
//!
//! There is nothing to run here. A missing re-export makes this crate fail to
//! RESOLVE, exactly as in `crates/fastmcp/tests/public_reexport_closure.rs` --
//! with the one difference that makes this file exist at all: that test lives
//! inside the facade package, so Cargo hands it the facade's own
//! `[dependencies]` and it can resolve a component path the facade re-exports
//! nothing of. This crate's manifest names one dependency, so it cannot.
//!
//! WHAT IS COVERED, and every item here is a position that actually broke.
//!
//! 1. The three handler macros in their async shapes. The prompt and resource
//!    expansions emitted `::fastmcp_server::promote_legacy_prompt_messages`
//!    and `::fastmcp_server::promote_legacy_resource_contents` with a LEADING
//!    `::`, which names an extern crate and bypasses the
//!    `use <facade>::__private::server as fastmcp_server;` alias the same
//!    `quote!` blocks use for everything else; the facade's `__private::server`
//!    listed only the tool helper. So an async `#[prompt]` returning
//!    `Vec<PromptMessage>` and an async `#[resource]` returning `String` --
//!    precisely the two shapes below -- could not expand for a facade-only
//!    consumer. Measured across `crates/fastmcp` at HEAD by pairing each
//!    attribute with the next `fn` line: 57 `#[prompt]` uses of which 7 are
//!    async, and 82 `#[resource]` uses of which 13 are async, plus 9 trybuild
//!    failure cases and one pass case. The 20 ASYNC uses are the affected
//!    population and all of them compiled green throughout -- and 20 is an
//!    upper bound, since the broken arm additionally requires no MRTR resume
//!    parameter and a non-`Final` return. Two of those async prompts and five
//!    of those async resources are in `examples/echo_server.rs`, the binary
//!    the README tells users to run, so the unexpandable arm was in shipped
//!    example code and compiled anyway for exactly the reason this crate
//!    exists.
//! 2. The builder path the README leads with, registering all three handlers.
//! 3. The documented stdio entry point, reached with a caller-supplied `Cx`,
//!    which is the contract: the `Cx` flows down from the consumer's runtime
//!    and this framework never creates one.
//! 4. The two `FinalTaskStore` RETURN positions whose claim wrappers the facade
//!    did not name, so no external store could be written. Return positions are
//!    the stricter case: naming a type is enough to accept one as a parameter
//!    and never enough to produce one, so both constructors are bound here
//!    rather than merely imported.
//! 5. The closure surface `crates/fastmcp/tests/public_reexport_closure.rs`
//!    states in its own header that it cannot prove, because Cargo gives it
//!    the facade's dependencies. Its import list, mirrored where it is
//!    falsifiable.
//! 6. A planted negative behind an off-by-default feature, so this crate is
//!    known to be able to go red. Two halves that are not interchangeable: the
//!    extern-prelude half (a leading `::`, the defect verbatim) and the
//!    list-membership half (a name the facade deliberately withholds). Only
//!    the second would turn red if a future edit dropped a name from
//!    `__private::server`.
//!
//! NO-CLAIM. This is a verification surface and earns no capability credit. It
//! gates one property -- that `fastmcp-rust` alone suffices for the APIs it
//! publishes, with the runtime the README instructs a consumer to add treated
//! as consumer-owned rather than as a gap, for the reason recorded at
//! `serve_documented` -- under ONE feature configuration, the dependency's defaults
//! (`legacy-2024-11-05` and `tasks`). It says nothing about the `apps`,
//! `proxy`, `websocket-experimental`, `builtin-auth-server` or
//! `--no-default-features` facade profiles, whose closure is unmeasured by any
//! consumer-shaped target; extending to those means adding passthrough
//! features here and a per-profile invocation, not more code. It also says
//! nothing about runtime behaviour: resolving a path is not exercising it.

#![forbid(unsafe_code)]

use fastmcp_rust::{auto::ServerBuilder, prelude::*};

// ---------------------------------------------------------------------------
// 1. The three handler macros, in the exact async shapes that were broken.
// ---------------------------------------------------------------------------

#[tool(description = "Echo the input message")]
async fn echo(ctx: &McpContext, message: String) -> McpResult<String> {
    ctx.checkpoint()?;
    Ok(message)
}

/// Async and returning the legacy message vector, which is what selects the
/// `promote_legacy_prompt_messages` arm: the macro emits that call when the
/// handler is async, declares no MRTR resume parameter, and does NOT return a
/// `FinalGetPromptResult`. Change any one of those three and this stops
/// covering the defect it was written for.
#[prompt]
async fn review(code: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text { text: code },
    }]
}

/// The resource counterpart, selecting `promote_legacy_resource_contents`.
#[resource(uri = "probe://notes")]
async fn notes() -> String {
    "notes".to_string()
}

// ---------------------------------------------------------------------------
// 2. The builder path the README documents, with all three handlers attached.
// ---------------------------------------------------------------------------

/// Never called. Type-checking it is the whole point: the three generated
/// handler types must satisfy the facade's own `ToolHandler`, `PromptHandler`
/// and `ResourceHandler` bounds through paths a consumer can name.
pub fn build_server() -> fastmcp_rust::auto::Server {
    ServerBuilder::new("consumer-closure-probe", "0.13.0")
        .tool(Echo)
        .prompt(ReviewPrompt)
        .resource(NotesResource)
        .instructions("Consumer-closure probe; not a shipped server.")
        .build()
}

// ---------------------------------------------------------------------------
// 3. The documented stdio entry point.
// ---------------------------------------------------------------------------

/// THERE IS NO FACADE ROUTE TO THE RUNTIME, AND THAT IS DELIBERATE. My first
/// draft of this file aliased `fastmcp_rust::asupersync::runtime::RuntimeBuilder`
/// on the theory that a single-dependency consumer needs one. It does not
/// resolve: `pub use asupersync;` at crates/fastmcp/src/lib.rs:242 is
/// `#[cfg(feature = "testing-lab")]`, and its own comment says production
/// callers "receive `Cx` directly from this facade and do not need a
/// test-internals runtime dependency". The README agrees from the other side,
/// instructing `asupersync = "=0.5.0"` in the consumer's own manifest. So the
/// runtime is a CONSUMER-OWNED dependency by design, resolved through the
/// consumer's own extern prelude, and therefore not a facade closure property
/// and not probeable from here. Recorded rather than deleted because the
/// absence looks exactly like the gaps this crate hunts, and the next reader
/// should not have to re-derive that it is not one.
///
/// What IS a facade property is that a consumer can name `Cx` and hand one
/// down, which is the documented contract. This function does that and nothing
/// else; `run_stdio_with_cx` returns `!`, which coerces here exactly as it
/// does in the README's own `main`.
pub async fn serve_documented(cx: &Cx) {
    build_server().run_stdio_with_cx(cx).await
}

// ---------------------------------------------------------------------------
// 4. The `FinalTaskStore` return positions.
// ---------------------------------------------------------------------------

/// Binds both claim constructors at their published paths. The coercion to a
/// `fn` pointer is what fixes `impl Into<String>` to `String`, which is what
/// makes the binding type-check; it is also why this is a stronger check than
/// an import, since a sealed witness with no public constructor would fail
/// here and pass a mere `use`.
pub fn task_store_return_positions() {
    use fastmcp_rust::{
        FinalTaskAcceptedInputClaim, FinalTaskId, FinalTaskInitialWorkClaim,
        FinalTaskInputResponses, FinalTaskWorkDescriptor,
    };

    let _accepted: fn(
        FinalTaskId,
        u64,
        String,
        FinalTaskWorkDescriptor,
        FinalTaskInputResponses,
    ) -> FinalTaskAcceptedInputClaim = FinalTaskAcceptedInputClaim::new;
    let _initial: fn(
        FinalTaskId,
        u64,
        String,
        FinalTaskWorkDescriptor,
    ) -> FinalTaskInitialWorkClaim = FinalTaskInitialWorkClaim::new;
}

// ---------------------------------------------------------------------------
// 5. The closure surface the in-package test states it cannot prove.
// ---------------------------------------------------------------------------
//
// `crates/fastmcp/tests/public_reexport_closure.rs` names these paths and says
// so in its own header: "Integration targets can also see the crate's regular
// dependencies, so this does not prove that `fastmcp_core` and
// `fastmcp_protocol` are unreachable by some other route." Here they are where
// that is falsifiable. Only the NAMES and SIGNATURE SHAPES are mirrored; that
// file's eighteen test bodies already execute in the workspace, and copying
// them would make this crate a second integration suite.

use fastmcp_rust::http_auth::dpop::{DpopClientError, DpopError, DpopKey, DpopSession};
use fastmcp_rust::http_auth::sampling::{SamplingRunLimits, SamplingToolLoopLimits};
use fastmcp_rust::http_auth::{CanonicalHttpUrl, PartitionAuthorization};
use fastmcp_rust::partition::{CredentialStoreKey, DurableOwnerKey, PartitionDescriptor};
// `ProcessGenerationGuard` is named at the facade ROOT, not through a
// `runtime` module. The module forward was removed because FND-01's facade
// route pattern forbids `runtime` by name; the identity types it declares are
// forwarded individually instead, and this import is the consumer-side proof
// that the replacement still closes the guard parameter below.
use fastmcp_rust::ProcessGenerationGuard;

/// A name that cannot be reached through the facade makes this fail to
/// resolve, which is the entire assertion. Parameters are underscore-prefixed
/// because nothing here is meant to run.
pub fn facade_closure_signatures(
    _url: &CanonicalHttpUrl,
    _authorization: &PartitionAuthorization,
    _descriptor: &PartitionDescriptor,
    _store: &CredentialStoreKey,
    _owner: &DurableOwnerKey,
    _guard: &ProcessGenerationGuard,
    _session: &DpopSession,
    _loop_limits: &SamplingToolLoopLimits,
    _run_limits: &SamplingRunLimits,
) {
}

/// The positions where naming is not enough. `CredentialStoreKey` is
/// obtainable ONLY through `derive` and is never returned by a reachable
/// method -- which is the reason `partition` is forwarded as a module and the
/// process-generation types are forwarded by name, stated in the comment above
/// that forward in `crates/fastmcp/src/lib.rs` -- so a consumer must be able to
/// WRITE the parameter types. Binding the constructors as fn pointers fixes
/// those types; a bare `use` would pass even if they were unusable.
pub fn constructors_are_callable() {
    let _derive: fn(
        &PartitionDescriptor,
        &str,
        &str,
        &str,
    ) -> Result<CredentialStoreKey, fastmcp_rust::SealedAdmissionKeyError> =
        CredentialStoreKey::derive;
    let _generate: fn() -> Result<DpopKey, DpopError> = DpopKey::generate;
}

/// Reading a proof failure forces the inner error type to be nameable, which a
/// `let` binding cannot infer away.
pub fn proof_failure_is_nameable(error: &DpopClientError) -> Option<&DpopError> {
    match error {
        DpopClientError::Proof(inner) => Some(inner),
        _ => None,
    }
}

/// The SERVER half of the continuation-replay contract, which this crate could
/// not name until the facade forwarded it.
///
/// `http_auth::rpc::interaction::recovery::ContinuationReplayContract` was
/// already reachable here and its own doc says the native server's
/// `ContinuationReplayMiddleware` is what supplies the contract -- so a
/// consumer could declare a trusted replay deployment and had no way to build
/// the journal that makes the declaration true. Binding the authority
/// constructor as an fn pointer is the part that matters: it fixes all three
/// parameter types, so this fails to resolve if any of
/// `ContinuationPartitionKey` (through the forwarded `partition` module),
/// `PartitionAuthorization` (through `http_auth`) or `McpRequestCancellation`
/// stops being writable through the facade. A bare `use` would pass while the
/// constructor remained uncallable, which is the exact defect shape this crate
/// exists to catch.
pub fn continuation_replay_is_installable_through_the_facade() {
    use fastmcp_rust::partition::ContinuationPartitionKey;
    use fastmcp_rust::{
        ContinuationReplayAuthority, ContinuationReplayLimits, ContinuationReplayMiddleware,
    };

    let _authority: fn(
        ContinuationPartitionKey,
        fastmcp_rust::http_auth::PartitionAuthorization,
        fastmcp_rust::McpRequestCancellation,
    ) -> ContinuationReplayAuthority = ContinuationReplayAuthority::new;

    let _limits: fn(
        usize,
        usize,
        usize,
        usize,
        std::time::Duration,
    ) -> Result<ContinuationReplayLimits, fastmcp_rust::McpError> = ContinuationReplayLimits::new;

    fn journal_is_a_middleware<M: fastmcp_rust::Middleware + 'static>() {}
    journal_is_a_middleware::<ContinuationReplayMiddleware>();
}

/// All three MRTR input kinds can be answered through the facade.
///
/// Function pointers bind every payload type, proving callers can construct
/// responses and resume roots input without component dependencies or a gated
/// legacy namespace. Naming only `MrtrInputResponse` would not prove this.
///
/// Modern form and URL requests use the same final descriptor exposed to
/// client resolvers. The legacy request constructor remains reachable too.
pub fn mrtr_elicitation_is_answerable_through_the_facade() {
    use fastmcp_rust::{
        ElicitRequestParams, ElicitResult, FinalCreateMessageResult,
        FinalEmbeddedElicitationParams, FinalEmbeddedRootsListResult, McpResult,
        MrtrCompletedInputs, MrtrInputRequest, MrtrInputResponse,
    };

    let _elicitation: fn(ElicitResult) -> McpResult<MrtrInputResponse> =
        MrtrInputResponse::elicitation;
    let _sampling: fn(FinalCreateMessageResult) -> McpResult<MrtrInputResponse> =
        MrtrInputResponse::sampling;
    let _roots: fn(FinalEmbeddedRootsListResult) -> McpResult<MrtrInputResponse> =
        MrtrInputResponse::roots;
    let _roots_result: fn(&MrtrInputResponse) -> McpResult<FinalEmbeddedRootsListResult> =
        MrtrInputResponse::roots_result;
    let _completed_roots: fn(
        &MrtrCompletedInputs,
        &str,
    ) -> McpResult<Option<FinalEmbeddedRootsListResult>> = MrtrCompletedInputs::roots;

    let _final_elicitation: fn(FinalEmbeddedElicitationParams) -> McpResult<MrtrInputRequest> =
        MrtrInputRequest::final_elicitation;
    let _legacy_elicitation: fn(ElicitRequestParams) -> MrtrInputRequest =
        MrtrInputRequest::legacy_elicitation;
}

// ---------------------------------------------------------------------------
// 6. The planted negative: proof that this crate can go red.
// ---------------------------------------------------------------------------
//
// NOT WHAT bd-jwvfb'S ITEM 4 LITERALLY ASKS FOR, and the difference is
// recorded rather than glossed. That item (which I wrote) says to delete
// `promote_legacy_prompt_messages` from the facade's `__private::server` list
// and show this crate fail. Executing it means transiently breaking
// `crates/fastmcp/src/lib.rs` in a shared worktree where another lane can and
// does commit whatever it finds -- so the test for the defect could reintroduce
// the defect for every consumer. Both negatives below therefore live in THIS
// crate, behind an off-by-default feature, so the broken state is a separate
// reproducible run rather than a window of broken shared state.
//
// They are not the same experiment as the literal version, and they are not
// interchangeable with each other.

/// POSITIVE. All three helpers resolve through the path the handler macros
/// actually address. `Vec::new()` infers its element type from each parameter,
/// so no return type is named -- deliberately, since naming them would test
/// the protocol re-exports instead of the one thing under test.
pub fn promote_helpers_resolve_through_the_facade() {
    let _ = fastmcp_rust::__private::server::promote_legacy_tool_content(Vec::new());
    let _ = fastmcp_rust::__private::server::promote_legacy_resource_contents(Vec::new());
    let _ = fastmcp_rust::__private::server::promote_legacy_prompt_messages(Vec::new());
}

/// POSITIVE — THE SHIPPED JWT RESOURCE VERIFIERS ARE INSTALLABLE BY A CONSUMER.
///
/// `fastmcp-server/providers/mod.rs` documents these types with a
/// `use fastmcp_rust::providers::{...}` example, so the component crate has
/// been advertising a facade route since 2026-10-14. Until the facade gained
/// its `jwt-resource-auth` forwarding equation that route did not exist, and
/// the failure was at the MANIFEST layer, not the name layer: Cargo refused to
/// resolve `fastmcp-rust/jwt-resource-auth` and listed the fourteen features
/// the facade did declare. That refusal is this function's planted negative and
/// it needs no build to reproduce — remove the equation and `cargo metadata`
/// alone fails.
///
/// The last two lines are the claim that matters. Naming a type only proves it
/// is reachable; replicating the exact bound `TokenAuthProvider::new` demands
/// (`V: TokenVerifier + 'static`, `fastmcp-server/src/auth.rs:611`) proves the
/// shipped verifiers can actually be INSTALLED through the facade's own trait
/// as a consumer sees it. Those are different facts and only the second one is
/// the capability.
///
/// NO-CLAIM: this is a type-level proof. It does not run an RS256 verification,
/// and it says nothing about whether either verifier is correct — the 23 tests
/// inside those two modules are a separate question this probe cannot reach.
#[cfg(feature = "jwt-provider-reachable")]
pub fn jwt_resource_providers_install_through_the_facade() {
    use fastmcp_rust::providers::{
        JwksRefreshError, JwksRefreshOutcome, JwksRefreshPolicy, JwtResourceAuthError,
        JwtResourcePolicy, JwtResourceVerifier, ManagedJwtResourceVerifier,
    };

    // All seven names `providers/mod.rs` advertises, so the whole re-exported
    // surface has to close rather than just the two verifiers.
    let _: Option<JwtResourceAuthError> = None;
    let _: Option<JwtResourcePolicy> = None;
    let _: Option<JwksRefreshPolicy> = None;
    let _: Option<JwksRefreshOutcome> = None;
    let _: Option<JwksRefreshError> = None;

    fn installs_as_a_token_verifier<V: fastmcp_rust::TokenVerifier + 'static>() {}
    installs_as_a_token_verifier::<JwtResourceVerifier>();
    installs_as_a_token_verifier::<ManagedJwtResourceVerifier>();
}

/// NEGATIVE 1 — the EXTERN PRELUDE half. Differs from the positive above in
/// exactly one dimension: a leading `::`. That is the defect verbatim; the
/// prompt and resource expansions emitted
/// `::fastmcp_server::promote_legacy_prompt_messages`, and a leading `::` names
/// an extern crate instead of the `use <facade>::__private::server as
/// fastmcp_server;` alias the same `quote!` blocks use for everything else.
/// This must fail as an unresolved module or unlinked crate. The identical line
/// inside `crates/fastmcp/tests/` COMPILES, which is the whole reason this
/// crate exists.
#[cfg(feature = "planted-negative")]
pub fn negative_leading_colon_names_an_unlinked_crate() {
    let _ = ::fastmcp_server::promote_legacy_prompt_messages(Vec::new());
}

/// NEGATIVE 2 — the LIST-MEMBERSHIP half, which negative 1 does not cover.
/// Negative 1 fails because of the manifest; this one fails because of the
/// facade's re-export list, which is the property bd-jwvfb is actually about.
/// `ServerBuilder` is the right choice because the facade's own comment at
/// `crates/fastmcp/src/lib.rs:179-182` says exposing it here "would provide an
/// unpinned `Server`/`ServerBuilder` construction route around the facade
/// policy surfaces" — so this guards a stated policy, not just a mechanism.
/// Only this negative would turn red if a future edit dropped a name from
/// `__private::server`; negative 1 would stay red regardless.
#[cfg(feature = "planted-negative")]
pub fn negative_withheld_name_is_not_in_the_private_server_list() {
    let _: Option<fastmcp_rust::__private::server::ServerBuilder> = None;
}

// ---------------------------------------------------------------------------
// 7. The guard that keeps this instrument from being retired by accident.
// ---------------------------------------------------------------------------
//
// Everything above is only evidence while this crate's extern prelude stays
// narrow. The cheapest way to make a closure failure "go away" is to add the
// component crate the macro expansion failed to resolve, which turns this
// crate into another copy of the blind spot it exists to cover. These
// assertions fire during `cargo check`, so that edit cannot land green.
//
// Each check comes with a control, because a scan that silently matches
// nothing reports the same clean zero as a scan over a clean manifest.

const MANIFEST: &str = include_str!("../Cargo.toml");

/// Substring search usable in a const initializer.
const fn manifest_names(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() == 0 || needle.len() > haystack.len() {
        return false;
    }
    let last = haystack.len() - needle.len();
    let mut start = 0;
    while start <= last {
        let mut i = 0;
        let mut matched = true;
        while i < needle.len() {
            if haystack[start + i] != needle[i] {
                matched = false;
                break;
            }
            i += 1;
        }
        if matched {
            return true;
        }
        start += 1;
    }
    false
}

/// A manifest that violates the rule. The scan must find the forbidden name in
/// here, or its zeroes over the real manifest mean nothing. This fixture is
/// the planted negative for the scanner itself, not for the facade.
const PLANTED_VIOLATION: &str = concat!(
    "[dependencies]\n",
    "fastmcp-rust = { path = \"../crates/fastmcp\" }\n",
    "fastmcp-server = \"0.13.0\"\n",
);

const _: () = assert!(
    manifest_names(PLANTED_VIOLATION.as_bytes(), b"fastmcp-server"),
    "control failed: the scan cannot find a forbidden dependency that is present, so its \
     verdict on the real manifest is not a measurement"
);
const _: () = assert!(
    !manifest_names(PLANTED_VIOLATION.as_bytes(), b"[workspace]"),
    "control failed: the scan reports a section that is absent"
);
const _: () = assert!(
    manifest_names(MANIFEST.as_bytes(), b"fastmcp-rust"),
    "control failed: this manifest must name the facade it probes"
);
const _: () = assert!(
    manifest_names(MANIFEST.as_bytes(), b"[workspace]"),
    "this crate must carry its own [workspace] table; absorbed into the root workspace it \
     inherits feature unification from other members and stops binding a green to the \
     feature set on the command line"
);

// The component crates, each of which would widen this crate's extern prelude
// and silently retire the instrument.
const _: () = assert!(
    !manifest_names(MANIFEST.as_bytes(), b"fastmcp-core"),
    "this probe must depend on the facade alone"
);
const _: () = assert!(
    !manifest_names(MANIFEST.as_bytes(), b"fastmcp-protocol"),
    "this probe must depend on the facade alone"
);
const _: () = assert!(
    !manifest_names(MANIFEST.as_bytes(), b"fastmcp-transport"),
    "this probe must depend on the facade alone"
);
const _: () = assert!(
    !manifest_names(MANIFEST.as_bytes(), b"fastmcp-server"),
    "this probe must depend on the facade alone"
);
const _: () = assert!(
    !manifest_names(MANIFEST.as_bytes(), b"fastmcp-client"),
    "this probe must depend on the facade alone"
);
const _: () = assert!(
    !manifest_names(MANIFEST.as_bytes(), b"fastmcp-macros"),
    "this probe must depend on the facade alone"
);
const _: () = assert!(
    !manifest_names(MANIFEST.as_bytes(), b"fastmcp-derive"),
    "this probe must depend on the facade alone"
);
const _: () = assert!(
    !manifest_names(MANIFEST.as_bytes(), b"fastmcp-console"),
    "this probe must depend on the facade alone"
);
const _: () = assert!(
    !manifest_names(MANIFEST.as_bytes(), b"fastmcp-cli"),
    "this probe must depend on the facade alone"
);
