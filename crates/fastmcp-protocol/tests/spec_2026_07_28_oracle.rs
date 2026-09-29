//! Conformance oracle against the OFFICIAL MCP 2026-07-28 schema corpus.
//!
//! # Why this file exists
//!
//! Every other test in this workspace is self-authored: it encodes this
//! project's reading of the specification, so it cannot detect a misreading.
//! Plan section 2.6 permits an MCP 2026-07-28 support claim only once "the
//! official conformance harness passes in both client and server modes", and
//! section 2.1 requires that core protocol types "round-trip against the final
//! dated composed oracle". Until `spec/mcp-2026-07-28/` was vendored, no
//! artifact in the repository described the specification at all.
//!
//! The subjects here are instances the specification itself declares valid.
//! That inverts the usual direction of proof: a failure means THIS
//! IMPLEMENTATION disagrees with the spec, and the implementation is what
//! moves. Never edit a vendored example to make this file pass — see
//! `spec/mcp-2026-07-28/PROVENANCE.toml`.
//!
//! # What this file does NOT claim
//!
//! Admitting the official request corpus is necessary for conformance, not
//! sufficient for it. This oracle exercises inbound admission and parameter
//! round-tripping for the modern era. It does not validate emitted results
//! against the raw JSON Schema, does not cover the 92 bare sub-object examples
//! (params, content types, capabilities, error shapes), does not test the
//! legacy 2024-11-05 era, and establishes no aggregate conformance or
//! release-readiness claim (PL-4).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{ClientNotification, CoreRequest, JsonRpcRequest, ServerNotification};
use serde_json::Value;

/// Byte length of the vendored authority at the pinned upstream commit. The
/// cryptographic pin is `sha256 =
/// ef70b61f99b6d2e5e3b46863822eab08dff6a45bedc7a08914e0e5b133f40203` and lives
/// in `spec/mcp-2026-07-28/PROVENANCE.toml`, where it is checked when the spec
/// is vendored or re-vendored. It is deliberately NOT recomputed here: `ring`
/// is an optional jose-gated dependency and an integration test cannot reach a
/// normal dependency, so importing a hasher would mean adding one to the graph
/// purely to restate provenance. What this test needs is narrower - that the
/// authority is present and has not been swapped or truncated - and the
/// structural assertions below cover that.
const SPEC_SCHEMA_BYTES: usize = 181_474;

/// Framed JSON-RPC wire envelopes (`jsonrpc` + `method`) in the official corpus
/// at the pinned commit. Frozen so that a corpus which silently shrinks fails
/// loudly instead of letting this oracle pass while examining less than it used
/// to.
const EXPECTED_METHOD_ENVELOPES: usize = 18;

/// Official files that carry `method` but no `jsonrpc`: request-shape
/// illustrations rather than framed messages. All three at the pinned commit are
/// server-to-client requests (`sampling/createMessage`, `elicitation/create`,
/// `roots/list`), which belong to the reverse-direction vocabulary and not to
/// `CoreRequest`'s client-to-server one. Counted so the split stays visible.
const EXPECTED_METHOD_FRAGMENTS: usize = 3;

fn spec_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("spec/mcp-2026-07-28")
}

/// Every `*.json` under `examples/`, sorted, so failures are reported in a
/// stable order and a missing corpus is distinguishable from an empty one.
fn example_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "json") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&spec_root().join("examples"), &mut out);
    out.sort();
    out
}

fn relative(path: &Path) -> String {
    let root = spec_root();
    path.strip_prefix(&root)
        .unwrap_or(path)
        .display()
        .to_string()
}

/// The vendored authority must be present and exactly the bytes that were
/// qualified. Without this the oracle could pass against an absent or edited
/// schema, which is the inert-gate failure mode: a check with nothing to read
/// reports the same thing as a check that passed.
#[test]
fn vendored_spec_authority_is_present_and_pinned() {
    let schema_path = spec_root().join("schema.json");
    let bytes = fs::read(&schema_path).unwrap_or_else(|error| {
        panic!(
            "the vendored MCP 2026-07-28 schema must exist at {}: {error}",
            schema_path.display()
        )
    });
    assert_eq!(
        bytes.len(),
        SPEC_SCHEMA_BYTES,
        "vendored schema.json is {} bytes; the pinned authority is {SPEC_SCHEMA_BYTES}. It was \
         edited, truncated or replaced - re-vendor per PROVENANCE.toml rather than adjusting this \
         constant, which would relabel a different document as the authority",
        bytes.len()
    );
    let parsed: Value = serde_json::from_slice(&bytes).expect("vendored schema.json must be JSON");
    let defs = parsed
        .get("$defs")
        .and_then(Value::as_object)
        .expect("the schema must expose $defs");
    assert!(
        defs.len() >= 155,
        "the pinned schema declared 155 definitions; found {}",
        defs.len()
    );
    assert_eq!(
        parsed.get("$schema").and_then(Value::as_str),
        Some("https://json-schema.org/draft/2020-12/schema"),
        "the spec is a draft 2020-12 schema; plan section 2.4 requires that dialect"
    );
    // Named 2026-07-28 definitions. Length and count alone could in principle be
    // matched by a different document; these are era-defining shapes that a
    // 2025-line schema does not carry, so their presence identifies WHICH spec
    // this is rather than merely that a schema is present.
    for required in [
        "DiscoverRequest",
        "DiscoverResult",
        "CallToolResult",
        "CacheableResult",
    ] {
        assert!(
            defs.contains_key(required),
            "the vendored authority is missing `{required}`, so it is not the MCP 2026-07-28 schema"
        );
    }
}

/// THE ORACLE. Every official example that is a full JSON-RPC envelope must be
/// admitted by the modern decoder, and every request's parameters must survive
/// a decode/encode round trip.
#[test]
fn official_modern_envelopes_are_admitted_and_round_trip() {
    let files = example_files();
    assert!(
        !files.is_empty(),
        "no example files found under {}; an empty corpus would let this oracle pass while examining nothing",
        spec_root().join("examples").display()
    );

    // A `method` alone does not make an instance a WIRE ENVELOPE. Three official
    // files carry `method` while omitting `jsonrpc` -- CreateMessageRequest,
    // ElicitRequest and ListRootsRequest -- because they illustrate the request
    // SHAPE of server-to-client requests rather than a framed message. Feeding
    // them to a JSON-RPC envelope parser produced a "missing field `jsonrpc`"
    // rejection that looked like an implementation gap and was a harness bug.
    // `jsonrpc` is therefore the discriminator, and the fragment count is frozen
    // separately so neither set can silently absorb the other.
    let mut envelopes = Vec::new();
    let mut fragments = Vec::new();
    for path in &files {
        let bytes = fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", relative(path)));
        let value: Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("{}: not JSON: {error}", relative(path)));
        if value.get("method").is_none() {
            continue;
        }
        if value.get("jsonrpc").is_some() {
            envelopes.push((path.clone(), value));
        } else {
            fragments.push((path.clone(), value));
        }
    }

    assert_eq!(
        envelopes.len(),
        EXPECTED_METHOD_ENVELOPES,
        "the official corpus carried {EXPECTED_METHOD_ENVELOPES} framed wire envelopes when pinned; \
         found {}. A shrinking corpus must fail rather than quietly narrow this oracle.",
        envelopes.len()
    );
    assert_eq!(
        fragments.len(),
        EXPECTED_METHOD_FRAGMENTS,
        "the official corpus carried {EXPECTED_METHOD_FRAGMENTS} unframed method fragments when \
         pinned; found {}. A fragment turning into an envelope upstream is a real change and must \
         be looked at, not absorbed.",
        fragments.len()
    );

    // Collect every disagreement before failing, so one run names the whole
    // gap instead of revealing it one method at a time.
    let mut admission_failures: BTreeMap<String, String> = BTreeMap::new();
    let mut round_trip_failures: BTreeMap<String, String> = BTreeMap::new();
    let mut admitted_methods: Vec<String> = Vec::new();

    for (path, value) in &envelopes {
        let name = relative(path);
        let request: JsonRpcRequest = match serde_json::from_value(value.clone()) {
            Ok(request) => request,
            Err(error) => {
                admission_failures.insert(
                    name,
                    format!("official envelope is not a JsonRpcRequest: {error}"),
                );
                continue;
            }
        };
        let method = request.method.clone();

        if method.starts_with("notifications/") {
            // The corpus does not label direction, so either union admitting it
            // is conformant; only rejection by BOTH is a gap.
            let client = ClientNotification::decode(&request);
            let server = ServerNotification::decode(&request);
            if client.is_err() && server.is_err() {
                admission_failures.insert(
                    name,
                    format!(
                        "{method}: rejected by both notification unions; client={:?} server={:?}",
                        client.err(),
                        server.err()
                    ),
                );
            } else {
                admitted_methods.push(method);
            }
            continue;
        }

        let params = value.get("params");
        match CoreRequest::decode(ProtocolEra::Modern2026, &method, params) {
            Ok(decoded) => {
                admitted_methods.push(method.clone());
                match decoded.encode_params() {
                    Ok(reencoded) => {
                        let original = params.cloned();
                        if reencoded != original {
                            round_trip_failures.insert(
                                name,
                                format!(
                                    "{method}: re-encoded params differ from the official instance\n     official: {}\n     ours:     {}",
                                    serde_json::to_string(&original).unwrap_or_default(),
                                    serde_json::to_string(&reencoded).unwrap_or_default()
                                ),
                            );
                        }
                    }
                    Err(error) => {
                        round_trip_failures
                            .insert(name, format!("{method}: encode_params failed: {error:?}"));
                    }
                }
            }
            Err(error) => {
                admission_failures.insert(name, format!("{method}: {error:?}"));
            }
        }
    }

    let mut report = String::new();
    if !admission_failures.is_empty() {
        report.push_str(&format!(
            "\n{} official MCP 2026-07-28 envelope(s) REJECTED by this implementation:\n",
            admission_failures.len()
        ));
        for (file, detail) in &admission_failures {
            report.push_str(&format!("  - {file}\n     {detail}\n"));
        }
    }
    if !round_trip_failures.is_empty() {
        report.push_str(&format!(
            "\n{} official envelope(s) admitted but NOT round-tripped:\n",
            round_trip_failures.len()
        ));
        for (file, detail) in &round_trip_failures {
            report.push_str(&format!("  - {file}\n     {detail}\n"));
        }
    }
    assert!(
        report.is_empty(),
        "{report}\nadmitted cleanly: {} of {}",
        admitted_methods.len(),
        envelopes.len()
    );
}

/// Result example directories paired with the official request that selects
/// them. `decode_result` is a method ON a request, because in this protocol the
/// request chooses the result vocabulary, so a result cannot be decoded in
/// isolation. Both sides of every pair come from the specification.
///
/// `InputRequiredResult` is paired with `CallToolRequest` because
/// `input_required` is a result *type* any of tools/call, resources/read or
/// prompts/get may return rather than a method of its own; tools/call is the
/// case the official example is written against.
const RESULT_PAIRINGS: &[(&str, &str)] = &[
    ("CallToolResult", "CallToolRequest"),
    ("CompleteResult", "CompleteRequest"),
    ("DiscoverResult", "DiscoverRequest"),
    ("GetPromptResult", "GetPromptRequest"),
    ("InputRequiredResult", "CallToolRequest"),
    ("ListPromptsResult", "ListPromptsRequest"),
    (
        "ListResourceTemplatesResult",
        "ListResourceTemplatesRequest",
    ),
    ("ListResourcesResult", "ListResourcesRequest"),
    ("ListToolsResult", "ListToolsRequest"),
    ("ReadResourceResult", "ReadResourceRequest"),
    ("SubscriptionsListenResult", "SubscriptionsListenRequest"),
];

/// Official result instances decoded through the official request that selects
/// them. This is the result-side half of section 2.1: every successful modern
/// result must carry a valid `resultType`, and the two `InputRequiredResult`
/// instances are official examples of the `input_required` shape that 13 of the
/// 37 scored server scenarios exercise.
#[test]
fn official_modern_results_decode_through_their_selecting_request() {
    let mut failures: BTreeMap<String, String> = BTreeMap::new();
    let mut decoded: Vec<String> = Vec::new();
    let mut examined = 0usize;

    for (result_dir, request_dir) in RESULT_PAIRINGS {
        // Build the selecting request from its own official envelope.
        let request_files = {
            let dir = spec_root().join("examples").join(request_dir);
            let mut files: Vec<PathBuf> = fs::read_dir(&dir)
                .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
                .collect();
            files.sort();
            files
        };
        let request_path = request_files
            .first()
            .unwrap_or_else(|| panic!("{request_dir} must carry an official request example"));
        let request_value: Value = serde_json::from_slice(
            &fs::read(request_path).unwrap_or_else(|error| panic!("{request_dir}: {error}")),
        )
        .unwrap_or_else(|error| panic!("{request_dir}: not JSON: {error}"));
        let method = request_value
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{request_dir} example must carry a method"));
        let request =
            match CoreRequest::decode(ProtocolEra::Modern2026, method, request_value.get("params"))
            {
                Ok(request) => request,
                Err(error) => {
                    failures.insert(
                        (*request_dir).to_owned(),
                        format!("selecting request {method} was itself refused: {error:?}"),
                    );
                    continue;
                }
            };

        let result_dir_path = spec_root().join("examples").join(result_dir);
        let mut result_files: Vec<PathBuf> = fs::read_dir(&result_dir_path)
            .unwrap_or_else(|error| panic!("{}: {error}", result_dir_path.display()))
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .collect();
        result_files.sort();
        for result_path in &result_files {
            examined += 1;
            let raw = fs::read_to_string(result_path)
                .unwrap_or_else(|error| panic!("{}: {error}", relative(result_path)));
            match request.decode_result(&raw) {
                Ok(_) => decoded.push(relative(result_path)),
                Err(error) => {
                    failures.insert(relative(result_path), format!("via {method}: {error:?}"));
                }
            }
        }
    }

    assert!(
        examined >= 16,
        "the pinned corpus carried 16 official result instances; examined only {examined}. \
         A shrinking corpus must fail rather than quietly narrow this oracle."
    );

    let mut report = String::new();
    if !failures.is_empty() {
        report.push_str(&format!(
            "\n{} official MCP 2026-07-28 result instance(s) NOT decoded by this implementation:\n",
            failures.len()
        ));
        for (file, detail) in &failures {
            report.push_str(&format!("  - {file}\n     {detail}\n"));
        }
    }
    assert!(
        report.is_empty(),
        "{report}\ndecoded cleanly: {} of {examined}",
        decoded.len()
    );
}

/// Planted negatives (RH-5). Without these, "the implementation admitted all 21
/// official envelopes" would be equally consistent with an implementation that
/// admits anything at all. Each mutation differs from an admitted instance in
/// exactly one dimension and must be refused.
#[test]
fn near_identical_mutations_of_an_official_envelope_are_refused() {
    let path = spec_root().join("examples/CallToolRequest/call-tool-request.json");
    let bytes = fs::read(&path).expect("the official tools/call example must exist");
    let official: Value = serde_json::from_slice(&bytes).expect("official example must be JSON");

    // Control: the unmutated instance is admitted. A planted negative proves
    // nothing if the positive it is derived from does not pass.
    let method = official
        .get("method")
        .and_then(Value::as_str)
        .expect("method")
        .to_owned();
    CoreRequest::decode(ProtocolEra::Modern2026, &method, official.get("params"))
        .expect("CONTROL: the unmutated official tools/call example must be admitted");

    // One dimension: an unknown method, everything else identical.
    let unknown = CoreRequest::decode(
        ProtocolEra::Modern2026,
        "tools/callx",
        official.get("params"),
    );
    assert!(
        unknown.is_err(),
        "an unknown method must be refused; admitting it would mean method admission checks nothing"
    );

    // One dimension: the required modern request metadata removed.
    let mut stripped = official.clone();
    stripped
        .get_mut("params")
        .and_then(Value::as_object_mut)
        .expect("params object")
        .remove("_meta");
    let no_meta = CoreRequest::decode(ProtocolEra::Modern2026, &method, stripped.get("params"));
    assert!(
        no_meta.is_err(),
        "plan section 2.1 requires that every modern request carry protocol-version and \
         client-capability metadata; a request with `_meta` removed must be refused"
    );

    // One dimension: the metadata present but declaring the legacy era.
    let mut cross_era = official.clone();
    cross_era["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] =
        Value::String("2024-11-05".to_owned());
    let wrong_era = CoreRequest::decode(ProtocolEra::Modern2026, &method, cross_era.get("params"));
    assert!(
        wrong_era.is_err(),
        "a modern request declaring the 2024-11-05 protocol version must be refused; the two \
         era vocabularies are deliberately disjoint"
    );
}
