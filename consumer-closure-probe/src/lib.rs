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
//!    consumer. Seventeen in-workspace `#[prompt]` tests and twelve trybuild
//!    cases stayed green through all of it.
//! 2. The builder path the README leads with, registering all three handlers.
//! 3. The documented stdio entry point, reached with a caller-supplied `Cx`,
//!    which is the contract: the `Cx` flows down from the consumer's runtime
//!    and this framework never creates one.
//! 4. The two `FinalTaskStore` RETURN positions whose claim wrappers the facade
//!    did not name, so no external store could be written. Return positions are
//!    the stricter case: naming a type is enough to accept one as a parameter
//!    and never enough to produce one, so both constructors are bound here
//!    rather than merely imported.
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
// 5. The guard that keeps this instrument from being retired by accident.
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
