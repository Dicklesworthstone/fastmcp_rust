//! FND-04 A public-signature evaluator (`bd-mcp-fnd-04-a-jmi7`).
//!
//! Proves that the shipped public lifecycle surface takes the caller's
//! capability context first, and that no shipped library code builds its own
//! runtime or bridges with `block_on`.
//!
//! - Profile: `core-candidate`.
//! - Plan target matrix: `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`,
//!   `x86_64-pc-windows-msvc`.
//! - Named consumer: `bd-mcp-fnd-04-integration-ymje`.
//!
//! The five plan subcases are folded into the two frozen tests (ruling on the
//! bead, #3918), so this target defines exactly two `#[test]` functions:
//!
//! - `FND-04-A-01 cx-first-public-signatures`: every shipped `pub fn` that
//!   takes a Cx-bearing parameter takes it first, and every required
//!   lifecycle family names shipped surfaces that do, with their returned
//!   shape recorded and no ambient `Cx` conjured in their bodies.
//! - `FND-04-A-02 no-library-runtime-construction` and
//!   `FND-04-A-03 macro-no-nested-block-on`: the 4rkp9 guard's library-graph
//!   scan, shared through `tests/support/shipped_source.rs`, reports zero of
//!   each. A-02 also requires zero product features reaching
//!   `asupersync/test-internals`.
//! - `FND-04-A-04 router-client-reentrant-runtime-negative`: the planted
//!   negative, which removes only the leading Cx-bearing parameter from the
//!   proxy-forwarding surface and must be refused with every other counter
//!   unchanged.
//! - `FND-04-A-05 public-signature-compile`: this target compiles only if the
//!   shipped signatures accept the Cx-first calls in [`compile_consumer`].
//!
//! The positive prints the `fnd-04-a-manifest-v1` receipt (`--nocapture`).
//!
//! This role proves capability-flow signatures only. It establishes no parent
//! completion, no aggregate MCP 2026-07-28 support, no MCP 2024-11-05
//! preservation, no profile maturity, no conformance, no publication and no
//! release readiness.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;

#[path = "../../fastmcp-server/tests/support/shipped_source.rs"]
#[allow(
    dead_code,
    reason = "shared with the 4rkp9 block_on guard; each target uses a subset"
)]
mod shipped_source;

use shipped_source::{
    GUARDED_CRATES, Objection, ShippedFile, balanced_end, disk, guard_library_crate, mask_non_code,
    repository_root, shipped_crate_files, test_regions,
};

/// The seven lifecycle families the acceptance names, in its order.
const FAMILIES: [&str; 7] = [
    "server serve/accept",
    "client connect/request",
    "router dispatch",
    "middleware",
    "handlers",
    "transport close/flush",
    "proxy forwarding",
];

/// One shipped surface a family must expose Cx-first.
struct Surface {
    family: &'static str,
    file: &'static str,
    /// The `impl` target or trait that declares the function.
    owner: &'static str,
    function: &'static str,
}

const REQUIRED_SURFACES: [Surface; 11] = [
    Surface {
        family: "server serve/accept",
        file: "crates/fastmcp-server/src/lib.rs",
        owner: "Server",
        function: "run_stdio_with_cx",
    },
    Surface {
        family: "server serve/accept",
        file: "crates/fastmcp-server/src/lib.rs",
        owner: "Server",
        function: "run_transport_with_cx",
    },
    Surface {
        family: "client connect/request",
        file: "crates/fastmcp-client/src/builder.rs",
        owner: "ClientBuilder",
        function: "connect_stdio_with_cx",
    },
    Surface {
        family: "client connect/request",
        file: "crates/fastmcp-client/src/lib.rs",
        owner: "Client",
        function: "call_tool_with_cx",
    },
    Surface {
        family: "client connect/request",
        file: "crates/fastmcp-client/src/lib.rs",
        owner: "HttpClient",
        function: "call_tool",
    },
    Surface {
        family: "router dispatch",
        file: "crates/fastmcp-server/src/lib.rs",
        owner: "Server",
        function: "dispatch_request",
    },
    Surface {
        family: "middleware",
        file: "crates/fastmcp-server/src/middleware.rs",
        owner: "Middleware",
        function: "on_request",
    },
    Surface {
        family: "handlers",
        file: "crates/fastmcp-server/src/handler.rs",
        owner: "ToolHandler",
        function: "call",
    },
    Surface {
        family: "transport close/flush",
        file: "crates/fastmcp-transport/src/lib.rs",
        owner: "Transport",
        function: "close",
    },
    Surface {
        family: "transport close/flush",
        file: "crates/fastmcp-transport/src/lib.rs",
        owner: "Transport",
        function: "send",
    },
    Surface {
        family: "proxy forwarding",
        file: "crates/fastmcp-server/src/proxy.rs",
        owner: "ProxyClient",
        function: "call_tool",
    },
];

/// Shipped `pub fn`s that take a Cx-bearing parameter later than first by
/// design. Each exclusion states why it is outside the seven families.
const EXCLUDED: [(&str, &str, &str); 2] = [
    (
        "crates/fastmcp/src/testing/client.rs",
        "new",
        "TestClient is the opt-in `testing` harness, not a shipped lifecycle family",
    ),
    (
        "crates/fastmcp-client/src/execution.rs",
        "with_source_frame_receiver",
        "internal executor plumbing that installs a frame receiver, not a lifecycle entry",
    ),
];

/// Why the evaluator refused a surface.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Finding {
    /// A required surface is absent from its file.
    Missing {
        family: &'static str,
        owner: &'static str,
        function: &'static str,
    },
    /// A required surface does not take a Cx-bearing parameter first.
    NotCxFirst {
        family: &'static str,
        owner: &'static str,
        function: &'static str,
        first: String,
    },
    /// A shipped `pub fn` takes a Cx-bearing parameter, but not first.
    Positional {
        path: String,
        line: usize,
        function: String,
        position: usize,
        arity: usize,
    },
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing {
                family,
                owner,
                function,
            } => write!(f, "{family}: {owner}::{function} is not shipped"),
            Self::NotCxFirst {
                family,
                owner,
                function,
                first,
            } => write!(
                f,
                "Cx-first: {family}: {owner}::{function} takes `{first}` first, not a Cx"
            ),
            Self::Positional {
                path,
                line,
                function,
                position,
                arity,
            } => write!(
                f,
                "Cx-first: {path}:{line}: {function} takes its Cx as parameter {position} of {arity}"
            ),
        }
    }
}

/// One function signature found in masked source.
struct Signature {
    name: String,
    /// Byte offset of the `fn` keyword.
    at: usize,
    /// Parameters after the receiver, split at depth zero.
    params: Vec<String>,
    /// Whether the item's own visibility is exactly `pub`.
    public: bool,
    /// The returned lifecycle shape: `async` when the call yields a future,
    /// then the declared return type (`()` when none is written).
    shape: String,
    /// The braces of the body; `None` for a required trait method.
    body: Option<(usize, usize)>,
}

/// Constructors that conjure a context instead of receiving the caller's.
const AMBIENT_CX: [&str; 3] = ["Cx::current(", "Cx::for_request(", "Cx::for_testing("];

/// How many times `masked[body]` builds or fetches an ambient `Cx`.
fn ambient_cx_reads(masked: &str, body: Option<(usize, usize)>) -> usize {
    let Some((open, close)) = body else {
        return 0;
    };
    let text = &masked[open..=close];
    let bytes = text.as_bytes();
    AMBIENT_CX
        .iter()
        .map(|needle| {
            text.match_indices(needle)
                .filter(|&(at, _)| {
                    at == 0 || !(bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_')
                })
                .count()
        })
        .sum()
}

/// Whether a parameter's type carries the caller's capability context.
fn is_cx_bearing(param: &str) -> bool {
    let ty = param.split_once(':').map_or(param, |(_, ty)| ty);
    let words: Vec<&str> = ty
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|word| !word.is_empty())
        .collect();
    matches!(words.last(), Some(&("Cx" | "McpContext"))) && !ty.contains('<') && !ty.contains('(')
}

/// Splits `text` at commas outside any bracket, dropping empty parts.
fn split_top_level(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let (mut depth, mut from) = (0usize, 0usize);
    let bytes = text.as_bytes();
    for (index, &byte) in bytes.iter().enumerate() {
        match byte {
            b'(' | b'[' | b'{' | b'<' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b'>' if index == 0 || bytes[index - 1] != b'-' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                parts.push(text[from..index].trim().to_owned());
                from = index + 1;
            }
            _ => {}
        }
    }
    parts.push(text[from..].trim().to_owned());
    parts.retain(|part| !part.is_empty());
    parts
}

/// Whether `param` is a method receiver: `self`, `mut self`, `&self`,
/// `&mut self`, `&'a self`, `&'a mut self`, or a typed `self: T`.
fn is_receiver(param: &str) -> bool {
    let binding = param.split(':').next().unwrap_or_default().trim();
    let binding = binding.strip_prefix('&').map_or(binding, str::trim_start);
    let binding = if binding.starts_with('\'') {
        binding
            .split_once(char::is_whitespace)
            .map_or("", |(_, rest)| rest.trim_start())
    } else {
        binding
    };
    let binding = binding
        .strip_prefix("mut")
        .filter(|rest| rest.starts_with(char::is_whitespace))
        .map_or(binding, str::trim_start);
    binding == "self"
}

/// Every `fn` item in `masked[range]`, outside `#[cfg(test)]` regions.
fn signatures(masked: &str, range: (usize, usize), regions: &[(usize, usize)]) -> Vec<Signature> {
    let bytes = masked.as_bytes();
    let mut found = Vec::new();
    let mut search = range.0;
    while let Some(offset) = masked[search..range.1].find("fn ") {
        let at = search + offset;
        search = at + 3;
        let bounded = at == 0 || !(bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_');
        if !bounded || regions.iter().any(|&(start, end)| at >= start && at <= end) {
            continue;
        }
        let rest = &masked[at + 3..];
        let name_len = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        if name_len == 0 {
            continue;
        }
        let name = rest[..name_len].to_owned();
        let mut cursor = at + 3 + name_len;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if bytes.get(cursor) == Some(&b'<') {
            let mut depth = 0usize;
            while cursor < bytes.len() {
                match bytes[cursor] {
                    b'<' => depth += 1,
                    b'>' if bytes[cursor - 1] != b'-' => {
                        depth -= 1;
                        if depth == 0 {
                            cursor += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                cursor += 1;
            }
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
        }
        if bytes.get(cursor) != Some(&b'(') {
            continue;
        }
        let Some(close) = balanced_end(bytes, cursor) else {
            continue;
        };
        let mut params = split_top_level(&masked[cursor + 1..close]);
        if params.first().is_some_and(|param| is_receiver(param)) {
            params.remove(0);
        }
        let item_start = masked[..at]
            .rfind([';', '{', '}', ']'])
            .map_or(0, |index| index + 1);
        let prefix = masked[item_start..at].trim();
        let public = prefix == "pub" || prefix.starts_with("pub ");
        let terminator = masked[close + 1..]
            .find(['{', ';'])
            .map_or(masked.len(), |offset| close + 1 + offset);
        let returns = masked[close + 1..terminator]
            .split_whitespace()
            .take_while(|word| *word != "where")
            .collect::<Vec<_>>()
            .join(" ");
        let shape = format!(
            "{}{}",
            if prefix.split_whitespace().any(|word| word == "async") {
                "async "
            } else {
                ""
            },
            if returns.is_empty() {
                "-> ()"
            } else {
                &returns
            }
        );
        let body = (bytes.get(terminator) == Some(&b'{'))
            .then(|| balanced_end(bytes, terminator).map(|end| (terminator, end)))
            .flatten();
        found.push(Signature {
            name,
            at,
            params,
            public,
            shape,
            body,
        });
    }
    found
}

/// The byte ranges of every `impl`/`trait` block whose target is `owner`.
fn owner_blocks(masked: &str, owner: &str) -> Vec<(usize, usize)> {
    let bytes = masked.as_bytes();
    let mut blocks = Vec::new();
    for keyword in ["impl", "trait"] {
        let mut search = 0usize;
        while let Some(offset) = masked[search..].find(keyword) {
            let at = search + offset;
            search = at + keyword.len();
            let before_ok =
                at == 0 || !(bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_');
            let after = bytes.get(search).copied().unwrap_or(b' ');
            if !before_ok || !(after.is_ascii_whitespace() || after == b'<') {
                continue;
            }
            let Some(brace) = masked[search..].find('{').map(|offset| search + offset) else {
                continue;
            };
            let header = masked[search..brace]
                .split(" where ")
                .next()
                .unwrap_or_default();
            let target = if keyword == "impl" {
                let header = header.trim_start();
                let header = if header.starts_with('<') {
                    let mut depth = 0usize;
                    let mut end = 0usize;
                    for (index, byte) in header.bytes().enumerate() {
                        match byte {
                            b'<' => depth += 1,
                            b'>' => {
                                depth -= 1;
                                if depth == 0 {
                                    end = index + 1;
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    &header[end..]
                } else {
                    header
                };
                header.rsplit(" for ").next().unwrap_or(header)
            } else {
                header
            };
            let name = target
                .trim()
                .split(['<', ':', ' '])
                .next()
                .unwrap_or_default()
                .rsplit("::")
                .next()
                .unwrap_or_default();
            if name == owner {
                if let Some(close) = balanced_end(bytes, brace) {
                    blocks.push((brace, close));
                }
            }
        }
    }
    blocks
}

/// Checks the required-family inventory. Returns the accepted surfaces and
/// every refusal.
fn check_inventory(
    root: &Path,
    read: &dyn Fn(&Path) -> Option<String>,
) -> (Vec<String>, Vec<Finding>) {
    let mut accepted = Vec::new();
    let mut findings = Vec::new();
    for surface in &REQUIRED_SURFACES {
        let Some(source) = read(&root.join(surface.file)) else {
            findings.push(Finding::Missing {
                family: surface.family,
                owner: surface.owner,
                function: surface.function,
            });
            continue;
        };
        let masked = mask_non_code(&source);
        let regions = test_regions(&masked);
        let signature = owner_blocks(&masked, surface.owner)
            .into_iter()
            .flat_map(|block| signatures(&masked, block, &regions))
            .find(|signature| signature.name == surface.function);
        match signature {
            None => findings.push(Finding::Missing {
                family: surface.family,
                owner: surface.owner,
                function: surface.function,
            }),
            Some(signature) => match signature.params.first() {
                Some(first) if is_cx_bearing(first) => accepted.push(format!(
                    "{}\t{}::{}\tfirst={}\tshape={}\tambient-cx-reads={}",
                    surface.family,
                    surface.owner,
                    surface.function,
                    first,
                    signature.shape,
                    ambient_cx_reads(&masked, signature.body)
                )),
                first => findings.push(Finding::NotCxFirst {
                    family: surface.family,
                    owner: surface.owner,
                    function: surface.function,
                    first: first
                        .cloned()
                        .unwrap_or_else(|| "<no parameter>".to_owned()),
                }),
            },
        }
    }
    (accepted, findings)
}

/// Every shipped `pub fn` across the guarded library crates that takes a
/// Cx-bearing parameter later than first, excluding [`EXCLUDED`].
fn check_positional(
    root: &Path,
    read: &dyn Fn(&Path) -> Option<String>,
) -> Result<Vec<Finding>, Objection> {
    let mut findings = Vec::new();
    for crate_dir in GUARDED_CRATES {
        for ShippedFile { relative, source } in shipped_crate_files(root, crate_dir, read)? {
            let masked = mask_non_code(&source);
            let regions = test_regions(&masked);
            for signature in signatures(&masked, (0, masked.len()), &regions) {
                if !signature.public {
                    continue;
                }
                let Some(index) = signature
                    .params
                    .iter()
                    .position(|param| is_cx_bearing(param))
                else {
                    continue;
                };
                if index == 0
                    || EXCLUDED
                        .iter()
                        .any(|&(path, name, _)| path == relative && name == signature.name)
                {
                    continue;
                }
                findings.push(Finding::Positional {
                    path: relative.clone(),
                    line: masked[..signature.at].matches('\n').count() + 1,
                    function: signature.name,
                    position: index + 1,
                    arity: signature.params.len(),
                });
            }
        }
    }
    Ok(findings)
}

/// The three forbidden counts: shipped runtime entries, shipped `block_on`
/// calls, and product features reaching `asupersync/test-internals`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ForbiddenCounts {
    runtime_entries: usize,
    block_on_calls: usize,
    test_internals: usize,
}

fn forbidden_counts(root: &Path, read: &dyn Fn(&Path) -> Option<String>) -> ForbiddenCounts {
    let mut counts = ForbiddenCounts {
        runtime_entries: 0,
        block_on_calls: 0,
        test_internals: 0,
    };
    for crate_dir in GUARDED_CRATES {
        if let Err(objections) = guard_library_crate(root, crate_dir, read) {
            for objection in objections {
                match objection {
                    Objection::ShippedCallSites { lines, .. } => {
                        counts.block_on_calls += lines.len();
                    }
                    Objection::RuntimeConstruction { lines, .. } => {
                        counts.runtime_entries += lines.len();
                    }
                    other => panic!("the library-graph scan must reach every file: {other}"),
                }
            }
        }
        counts.test_internals += product_test_internals(root, crate_dir, read);
    }
    counts
}

/// How many entries of `crate_dir`'s product graph name `test-internals`:
/// normal dependency feature lists, plus every feature reached from `default`.
fn product_test_internals(
    root: &Path,
    crate_dir: &str,
    read: &dyn Fn(&Path) -> Option<String>,
) -> usize {
    let manifest = read(&root.join(crate_dir).join("Cargo.toml"))
        .unwrap_or_else(|| panic!("{crate_dir}/Cargo.toml must be readable"));
    let manifest: toml::Table = toml::from_str(&manifest)
        .unwrap_or_else(|error| panic!("{crate_dir}/Cargo.toml is not valid TOML: {error}"));
    let mut count = 0usize;
    if let Some(dependencies) = manifest.get("dependencies").and_then(toml::Value::as_table) {
        for spec in dependencies.values() {
            let features = spec.get("features").and_then(toml::Value::as_array);
            count += features.map_or(0, |features| {
                features
                    .iter()
                    .filter(|feature| feature.as_str() == Some("test-internals"))
                    .count()
            });
        }
    }
    let features: BTreeMap<String, Vec<String>> = manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .map(|table| {
            table
                .iter()
                .map(|(name, entries)| {
                    let entries = entries
                        .as_array()
                        .map(|entries| {
                            entries
                                .iter()
                                .filter_map(|e| e.as_str().map(str::to_owned))
                                .collect()
                        })
                        .unwrap_or_default();
                    (name.clone(), entries)
                })
                .collect()
        })
        .unwrap_or_default();
    let mut pending = vec!["default".to_owned()];
    let mut reached = std::collections::BTreeSet::new();
    while let Some(feature) = pending.pop() {
        if !reached.insert(feature.clone()) {
            continue;
        }
        for entry in features.get(&feature).into_iter().flatten() {
            if entry.ends_with("/test-internals") || entry == "test-internals" {
                count += 1;
            } else if !entry.contains('/') && !entry.starts_with("dep:") {
                pending.push(entry.clone());
            }
        }
    }
    count
}

/// The planted source for FND-04-A-04: `proxy.rs` with only the leading
/// Cx-bearing parameter of `ProxyClient::call_tool` removed.
fn plant_without_leading_cx(source: &str) -> String {
    let masked = mask_non_code(source);
    let regions = test_regions(&masked);
    let signature = owner_blocks(&masked, "ProxyClient")
        .into_iter()
        .flat_map(|block| signatures(&masked, block, &regions))
        .find(|signature| signature.name == "call_tool")
        .expect("the proxy-forwarding surface is shipped");
    let first = signature
        .params
        .first()
        .expect("the proxy-forwarding surface takes parameters");
    let start = signature.at
        + masked[signature.at..]
            .find(first.as_str())
            .expect("the parameter is in the source");
    let mut end = start + first.len();
    let bytes = source.as_bytes();
    while end < bytes.len() && (bytes[end] == b',' || bytes[end].is_ascii_whitespace()) {
        end += 1;
    }
    let mut planted = source.to_owned();
    planted.replace_range(start..end, "");
    planted
}

/// FND-04-A-05: this target builds only if every required family, and every
/// constructor the Cx-first reorder moved, accepts the caller's context in the
/// first position. Nothing here runs; the proof is that it type-checks.
#[allow(
    dead_code,
    reason = "FND-04-A-05 is a compile-time proof; nothing is called"
)]
mod compile_consumer {
    use fastmcp_client::{Client, ClientBuilder, HttpClient};
    use fastmcp_core::{Cx, McpContext, McpRequestCancellation};
    use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest};
    use fastmcp_server::bidirectional::RequestSender;
    use fastmcp_server::{Middleware, NotificationSender, Server, Session, ToolHandler};
    use fastmcp_transport::Transport;
    use serde_json::Value;

    async fn server_serve(server: Server, cx: &Cx) -> ! {
        server.run_stdio_with_cx(cx).await
    }

    fn server_accept<T: Transport + Send + 'static>(server: Server, cx: &Cx, transport: T) -> ! {
        server.run_transport_with_cx(cx, transport)
    }

    async fn client_connect(cx: &Cx, plan: fastmcp_client::ClientProtocolPlan) {
        let _ = ClientBuilder::new()
            .connect_stdio_with_cx(cx, "server", &[])
            .await;
        let _ = Client::stdio_with_cx(cx.clone(), "server", &[]);
        let _ = Client::stdio_with_protocol_plan_with_cx(cx.clone(), "server", &[], plan.clone());
        let _ = Client::http_with_cx(cx, plan).await;
    }

    #[cfg(unix)]
    async fn client_request(client: &mut Client, cx: &Cx, cancellation: &McpRequestCancellation) {
        let _ = client
            .call_tool_with_cx(cx, cancellation, "tool", Value::Null)
            .await;
    }

    async fn http_client_request(client: &mut HttpClient, cx: &Cx) {
        let _ = client.call_tool(cx, "tool", Value::Null).await;
    }

    async fn router_dispatch(
        server: &Server,
        cx: &Cx,
        session: &mut Session,
        request: JsonRpcRequest,
        notifications: &NotificationSender,
        requests: &RequestSender,
    ) {
        let _ = server
            .dispatch_request(cx, session, request, notifications, requests)
            .await;
    }

    fn middleware<M: Middleware + ?Sized>(
        middleware: &M,
        ctx: &McpContext,
        request: &JsonRpcRequest,
    ) {
        let _ = middleware.on_request(ctx, request);
    }

    fn handler<H: ToolHandler + ?Sized>(handler: &H, ctx: &McpContext) {
        let _ = handler.call(ctx, Value::Null);
    }

    fn transport_close_flush<T: Transport + ?Sized>(
        transport: &mut T,
        cx: &Cx,
        message: &JsonRpcMessage,
    ) {
        let _ = transport.send(cx, message);
        let _ = transport.close(cx);
    }

    #[cfg(feature = "proxy")]
    fn proxy_forwarding(proxy: &fastmcp_server::ProxyClient, ctx: &McpContext) {
        let _ = proxy.call_tool(ctx, "tool", Value::Null);
    }

    async fn modern_facade(cx: &Cx, endpoint: fastmcp_core::CanonicalHttpUrl) {
        let _ = fastmcp_rust::modern::ClientBuilder::new()
            .connect_stdio_with_cx(cx, "server", &[])
            .await;
        let _ =
            Box::pin(fastmcp_rust::modern::ClientBuilder::new().connect_http_with_cx(cx, endpoint))
                .await;
    }

    #[cfg(feature = "legacy-2024-11-05")]
    async fn legacy_and_auto(
        cx: &Cx,
        sse: fastmcp_core::CanonicalHttpUrl,
        post: fastmcp_core::CanonicalHttpUrl,
    ) {
        let _ = fastmcp_rust::auto::ClientBuilder::new()
            .connect_stdio_with_cx(cx, "server", &[])
            .await;
        let _ = fastmcp_rust::legacy_2024::ClientBuilder::new()
            .connect_stdio_with_cx(cx, "server", &[])
            .await;
        let _ = fastmcp_rust::legacy_2024::Client::stdio_with_cx(cx.clone(), "server", &[]);
        let _ =
            fastmcp_rust::legacy_2024::connect_http_with_cx(cx, sse.clone(), post.clone()).await;
        let _ = Client::sse_with_cx(cx, sse, post).await;
    }

    #[cfg(all(feature = "proxy", feature = "legacy-2024-11-05"))]
    async fn legacy_proxy(
        cx: Cx,
        plan: fastmcp_client::ClientProtocolPlan,
        info: fastmcp_protocol::ClientInfo,
        capabilities: fastmcp_protocol::ClientCapabilities,
    ) {
        let _ = Box::pin(
            fastmcp_server::ProxyClient::connect_legacy_http_with_protocol_plan_and_catalog(
                cx,
                1,
                plan,
                info,
                capabilities,
            ),
        )
        .await;
    }
}

const ZERO: ForbiddenCounts = ForbiddenCounts {
    runtime_entries: 0,
    block_on_calls: 0,
    test_internals: 0,
};

/// Everything one evaluation of a source tree observes.
struct Evaluation {
    /// One row per accepted required surface: family, surface, first
    /// argument, returned shape, and ambient-Cx reads in its body.
    accepted: Vec<String>,
    refused: Vec<Finding>,
    positional: Vec<Finding>,
    counts: ForbiddenCounts,
}

impl Evaluation {
    /// The evaluator output the receipt digests.
    fn render(&self) -> String {
        let mut out = self.accepted.join("\n");
        for finding in self.refused.iter().chain(&self.positional) {
            out.push_str(&format!("\n{finding}"));
        }
        out.push_str(&format!("\n{:?}\n", self.counts));
        out
    }
}

fn evaluate(root: &Path, read: &dyn Fn(&Path) -> Option<String>) -> Evaluation {
    let (accepted, refused) = check_inventory(root, read);
    let positional = check_positional(root, read)
        .unwrap_or_else(|objection| panic!("the shipped graph must be readable: {objection}"));
    Evaluation {
        accepted,
        refused,
        positional,
        counts: forbidden_counts(root, read),
    }
}

/// The tree with only `proxy.rs` replaced by its FND-04-A-04 plant.
fn evaluate_planted(root: &Path) -> Evaluation {
    let proxy = root.join("crates/fastmcp-server/src/proxy.rs");
    let planted = plant_without_leading_cx(&disk(&proxy).expect("proxy.rs is readable"));
    evaluate(root, &|path: &Path| {
        if path == proxy {
            Some(planted.clone())
        } else {
            disk(path)
        }
    })
}

/// The refusals the planted tree must produce: the clean tree's own, then the
/// stable Cx-first diagnostic for the planted surface, which the inventory
/// reaches last. Relative to the same tree, so the plant is the only variable.
fn expected_plant_refusals(clean: &Evaluation) -> Vec<Finding> {
    let mut refused = clean.refused.clone();
    refused.push(Finding::NotCxFirst {
        family: "proxy forwarding",
        owner: "ProxyClient",
        function: "call_tool",
        first: "name: &str".to_owned(),
    });
    refused
}

/// Whether the planted tree differs from the clean one exactly as
/// FND-04-A-04 requires: the one added refusal, every other observation
/// equal, and the three zero-effect counters at zero.
fn plant_refused_exactly(clean: &Evaluation, planted: &Evaluation) -> bool {
    planted.refused == expected_plant_refusals(clean)
        && planted.accepted.iter().eq(clean
            .accepted
            .iter()
            .filter(|line| !line.starts_with("proxy forwarding\t")))
        && planted.positional == clean.positional
        && planted.counts == clean.counts
        && planted.counts == ZERO
}

const SUBCASES: [&str; 5] = [
    "FND-04-A-01 cx-first-public-signatures",
    "FND-04-A-02 no-library-runtime-construction",
    "FND-04-A-03 macro-no-nested-block-on",
    "FND-04-A-04 router-client-reentrant-runtime-negative",
    "FND-04-A-05 public-signature-compile",
];

const PLAN_TARGETS: [&str; 3] = [
    "x86_64-unknown-linux-gnu",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
];

/// The plan target this binary was built for.
fn this_target() -> &'static str {
    if cfg!(all(
        target_arch = "x86_64",
        target_os = "linux",
        target_env = "gnu"
    )) {
        PLAN_TARGETS[0]
    } else if cfg!(all(target_arch = "aarch64", target_os = "macos")) {
        PLAN_TARGETS[1]
    } else if cfg!(all(
        target_arch = "x86_64",
        target_os = "windows",
        target_env = "msvc"
    )) {
        PLAN_TARGETS[2]
    } else {
        "outside-the-plan-matrix"
    }
}

/// The facade features this evaluator binary was compiled with.
fn compiled_features() -> String {
    let mut features = Vec::new();
    for (name, enabled) in [
        ("legacy-2024-11-05", cfg!(feature = "legacy-2024-11-05")),
        ("tasks", cfg!(feature = "tasks")),
        ("proxy", cfg!(feature = "proxy")),
        ("apps", cfg!(feature = "apps")),
        ("testing", cfg!(feature = "testing")),
        ("testing-lab", cfg!(feature = "testing-lab")),
    ] {
        if enabled {
            features.push(name);
        }
    }
    if features.is_empty() {
        "none".to_owned()
    } else {
        features.join("+")
    }
}

fn sha256_hex(chunks: &[&[u8]]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    for chunk in chunks {
        sha2::Digest::update(&mut hasher, chunk);
    }
    let mut out = String::with_capacity(64);
    for byte in sha2::Digest::finalize(hasher) {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// Content identity of the evaluated source: every shipped file of every
/// guarded crate, in walk order, as path NUL contents NUL.
fn shipped_tree_sha256(root: &Path) -> String {
    let mut chunks = Vec::new();
    for crate_dir in GUARDED_CRATES {
        let files = shipped_crate_files(root, crate_dir, &disk)
            .unwrap_or_else(|objection| panic!("the shipped graph must be readable: {objection}"));
        for ShippedFile { relative, source } in files {
            chunks.push(format!("{relative}\0{source}\0"));
        }
    }
    sha256_hex(&chunks.iter().map(String::as_bytes).collect::<Vec<_>>())
}

/// The canonical `fnd-04-a-manifest-v1` receipt for one evaluation. A worker
/// has no git checkout, so the revision is bound by content digests; the
/// other two plan targets are recorded as not run by this binary.
fn manifest_v1(root: &Path, clean: &Evaluation, outcomes: &[bool; 5]) -> String {
    let lock = disk(&root.join("Cargo.lock")).expect("Cargo.lock is readable");
    let mut lines = vec![
        "fnd-04-a-manifest-v1".to_owned(),
        "consumer bd-mcp-fnd-04-integration-ymje".to_owned(),
        "profile core-candidate".to_owned(),
        format!("features {}", compiled_features()),
    ];
    for target in PLAN_TARGETS {
        let row = if target == this_target() {
            "ran"
        } else {
            "not-run-here"
        };
        lines.push(format!("target {target} {row}"));
    }
    lines.push(format!("source-tree-sha256 {}", shipped_tree_sha256(root)));
    lines.push(format!(
        "cargo-lock-sha256 {}",
        sha256_hex(&[lock.as_bytes()])
    ));
    lines.push(format!(
        "inventory-sha256 {}",
        sha256_hex(&[clean.accepted.join("\n").as_bytes()])
    ));
    lines.push(format!(
        "evaluator-output-sha256 {}",
        sha256_hex(&[clean.render().as_bytes()])
    ));
    for (subcase, passed) in SUBCASES.iter().zip(outcomes) {
        let outcome = if *passed { "pass" } else { "fail" };
        lines.push(format!("outcome {subcase} {outcome}"));
    }
    lines.join("\n")
}

#[test]
fn fnd_04_a_positive() {
    let root = repository_root();
    let clean = evaluate(&root, &disk);
    let families: std::collections::BTreeSet<&str> = clean
        .accepted
        .iter()
        .filter_map(|line| line.split('\t').next())
        .collect();
    let outcomes = [
        clean.refused.is_empty()
            && clean.positional.is_empty()
            && families.len() == FAMILIES.len()
            && clean
                .accepted
                .iter()
                .all(|line| line.ends_with("\tambient-cx-reads=0")),
        // Runtime construction, and the product feature that would reach the
        // lab runtime's internals.
        clean.counts.runtime_entries == 0 && clean.counts.test_internals == 0,
        clean.counts.block_on_calls == 0,
        plant_refused_exactly(&clean, &evaluate_planted(&root)),
        // `compile_consumer` type-checked, or this binary would not exist.
        true,
    ];
    let manifest = manifest_v1(&root, &clean, &outcomes);
    println!("{manifest}");

    assert!(
        outcomes.iter().all(|passed| *passed),
        "FND-04 A refused:\n{}\n{manifest}",
        clean.render()
    );
    for line in manifest.lines().filter(|line| line.contains("-sha256 ")) {
        let digest = line.rsplit(' ').next().unwrap_or_default();
        assert!(
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "every receipt digest is 64 lowercase hex characters: {line}"
        );
    }
}

#[test]
fn fnd_04_a_planted_negative() {
    let root = repository_root();
    let clean = evaluate(&root, &disk);
    let planted = evaluate_planted(&root);

    assert_eq!(
        planted.refused,
        expected_plant_refusals(&clean),
        "the plant adds exactly one refusal: the stable Cx-first diagnostic"
    );
    let unplanted: Vec<&String> = clean
        .accepted
        .iter()
        .filter(|line| !line.starts_with("proxy forwarding\t"))
        .collect();
    assert_eq!(planted.accepted.iter().collect::<Vec<_>>(), unplanted);
    assert_eq!(planted.positional, clean.positional);
    assert_eq!(planted.counts, clean.counts);
    assert_eq!(planted.counts, ZERO);
    assert!(plant_refused_exactly(&clean, &planted));
}
