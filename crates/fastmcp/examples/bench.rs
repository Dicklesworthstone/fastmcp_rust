//! FastMCP Performance Benchmarks
//!
//! Simple benchmarks using `std::time::Instant` to measure performance characteristics.
//! Run with: `cargo run -p fastmcp-rust --example bench --release`
//!
//! Measurements:
//! - Server creation time (including 100 distinct registered tools)
//! - Direct and in-memory modern MCP handler invocation overhead
//! - JSON serialization/deserialization throughput
//! - Protocol message encoding/decoding (MCP 2026-07-28 and 2024-11-05)
//! - Transport codec encode/decode throughput
//! - Caller-owned context checkpoint/budget overhead
//! - JSON Schema validation (positive and near-identical negative cases)
//! - Protocol and context type sizes (`size_of`)
//!
//! Note: Use `--release` for representative optimized local measurements.

#![recursion_limit = "256"]

use std::collections::{BTreeSet, HashMap};
use std::hint::black_box;
use std::time::{Duration, Instant};

use fastmcp_rust::memory::create_memory_transport_pair_with_capacity;
use fastmcp_rust::modern::{
    FinalArguments, FinalCallToolParams, MemoryClient, OpenMetadata, ServerBuilder,
};
use fastmcp_rust::prelude::*;
use fastmcp_rust::{CoreResult, FinalCoreResult, McpRequestCancellation};

// ============================================================================
// Benchmark Utilities
// ============================================================================

/// Run a benchmark function multiple times and report statistics.
fn benchmark<F: FnMut()>(name: &str, iterations: u64, mut f: F) {
    // Warm-up runs
    for _ in 0..10 {
        f();
    }

    // Timed runs
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = start.elapsed();

    let per_op = elapsed.as_nanos() as f64 / iterations as f64;
    let ops_per_sec = if per_op > 0.0 {
        1_000_000_000.0 / per_op
    } else {
        f64::INFINITY
    };

    println!("{name:44} {per_op:>10.2} ns/op  {ops_per_sec:>12.0} ops/sec");
}

/// Format a duration nicely.
fn format_duration(d: Duration) -> String {
    if d.as_secs() > 0 {
        format!("{:.3} s", d.as_secs_f64())
    } else if d.as_millis() > 0 {
        format!("{:.3} ms", d.as_secs_f64() * 1000.0)
    } else if d.as_micros() > 0 {
        format!("{:.3} µs", d.as_secs_f64() * 1_000_000.0)
    } else {
        format!("{} ns", d.as_nanos())
    }
}

fn build_runtime() -> asupersync::runtime::Runtime {
    asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("caller-owned current-thread asupersync runtime")
}

// ============================================================================
// Sample Handlers for Benchmarks
// ============================================================================

#[tool(description = "A no-op tool for benchmarking")]
fn noop(_ctx: &McpContext) -> String {
    String::new()
}

#[tool(description = "Echo back the input")]
#[allow(clippy::needless_pass_by_value)] // Macro requires String
fn bench_echo(_ctx: &McpContext, message: String) -> String {
    message
}

#[tool(description = "Parse and return JSON")]
#[allow(clippy::needless_pass_by_value)] // Macro requires String
fn json_roundtrip(_ctx: &McpContext, data: String) -> String {
    // Parse then re-serialize
    match serde_json::from_str::<serde_json::Value>(&data) {
        Ok(value) => serde_json::to_string(&value).unwrap_or_default(),
        Err(_) => String::new(),
    }
}

#[resource(uri = "bench://data")]
fn bench_data(_ctx: &McpContext) -> String {
    r#"{"benchmark": "data"}"#.to_string()
}

#[prompt(description = "Benchmark prompt")]
#[allow(clippy::needless_pass_by_value)] // Macro requires String
fn bench_prompt(_ctx: &McpContext, name: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!("Hello, {name}"),
        },
    }]
}

/// Parameterized distinct tool so the 100-tool catalog benchmark registers
/// 100 unique tool names instead of overwriting `"noop"` 100 times.
struct DistinctBenchTool {
    name: String,
}

impl DistinctBenchTool {
    fn new(index: usize) -> Self {
        Self {
            name: format!("bench_tool_{index:03}"),
        }
    }
}

impl ToolHandler for DistinctBenchTool {
    fn definition(&self) -> Tool {
        Tool {
            name: self.name.clone(),
            description: Some("Distinct benchmark tool".to_owned()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    fn call(&self, _ctx: &McpContext, _arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        Ok(vec![Content::text(self.name.clone())])
    }
}

/// Builds a modern server populated with `count` uniquely named tools.
fn build_distinct_tool_server(count: usize) -> fastmcp_rust::modern::Server {
    let mut builder = ServerBuilder::new("bench", "1.0.0");
    for index in 0..count {
        builder = builder.tool(DistinctBenchTool::new(index));
    }
    builder.build()
}

/// Verifies the live registered distinct tool count over in-memory modern MCP.
fn count_registered_tools_live(
    runtime: &asupersync::runtime::Runtime,
    server: fastmcp_rust::modern::Server,
) -> usize {
    runtime.block_on(async {
        let cx = Cx::current().expect("runtime current Cx");
        let (client_transport, server_transport) = create_memory_transport_pair_with_capacity(8);
        let mut server_task =
            cx.spawn(move |serve_cx| async move {
                server.serve_memory(&serve_cx, server_transport).await
            })
            .expect("spawn in-memory benchmark server");
        let mut client = MemoryClient::builder(ClientInfo {
            name: "bench-catalog-verifier".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        })
        .connect(&cx, client_transport)
        .await
        .expect("connect modern MemoryClient");
        let cancellation = McpRequestCancellation::new();

        let mut names = BTreeSet::new();
        let mut cursor: Option<String> = None;
        loop {
            let CoreResult::Final(FinalCoreResult::ToolsList { result, .. }) = client
                .list_tools(&cx, &cancellation, cursor.as_deref())
                .await
                .expect("list_tools succeeds")
            else {
                panic!("expected FinalCoreResult::ToolsList");
            };
            for tool in result.payload.tools {
                assert!(
                    names.insert(tool.name.clone()),
                    "duplicate tool name observed in catalog: {}",
                    tool.name
                );
            }
            if result.payload.next_cursor.is_none() {
                break;
            }
            cursor = result.payload.next_cursor;
        }

        client.close(&cx).expect("close modern MemoryClient");
        server_task
            .join(&cx)
            .await
            .expect("benchmark server task joins")
            .expect("benchmark server settles cleanly on client close");
        names.len()
    })
}

// ============================================================================
// Schema Validation Cases (Positive + Near-Identical Planted Negatives)
// ============================================================================

struct SchemaBenchFixtures {
    simple_schema: serde_json::Value,
    simple_valid: serde_json::Value,
    simple_missing_required: serde_json::Value,
    simple_wrong_type: serde_json::Value,
    complex_schema: serde_json::Value,
    complex_valid: serde_json::Value,
    complex_missing_nested_id: serde_json::Value,
}

fn schema_bench_fixtures() -> SchemaBenchFixtures {
    let simple_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"}
        },
        "required": ["name"]
    });
    let simple_valid = serde_json::json!({"name": "Alice", "age": 30});
    // Near-identical negatives: each differs from `simple_valid` in one forbidden dimension.
    let simple_missing_required = serde_json::json!({"age": 30});
    let simple_wrong_type = serde_json::json!({"name": "Alice", "age": "thirty"});

    let complex_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "users": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "name": {"type": "string"},
                        "email": {"type": "string"}
                    },
                    "required": ["id", "name"]
                }
            },
            "metadata": {
                "type": "object",
                "properties": {
                    "version": {"type": "string"},
                    "timestamp": {"type": "integer"}
                }
            }
        },
        "required": ["users"]
    });
    let complex_valid = serde_json::json!({
        "users": [
            {"id": 1, "name": "Alice", "email": "alice@example.com"},
            {"id": 2, "name": "Bob"}
        ],
        "metadata": {"version": "1.0", "timestamp": 1_234_567_890}
    });
    let complex_missing_nested_id = serde_json::json!({
        "users": [
            {"id": 1, "name": "Alice", "email": "alice@example.com"},
            {"name": "Bob"}
        ],
        "metadata": {"version": "1.0", "timestamp": 1_234_567_890}
    });

    SchemaBenchFixtures {
        simple_schema,
        simple_valid,
        simple_missing_required,
        simple_wrong_type,
        complex_schema,
        complex_valid,
        complex_missing_nested_id,
    }
}

fn verify_schema_fixtures(fixtures: &SchemaBenchFixtures) {
    use fastmcp_protocol::schema::validate;

    assert!(
        validate(&fixtures.simple_schema, &fixtures.simple_valid).is_ok(),
        "valid simple instance must pass schema validation"
    );
    assert!(
        validate(&fixtures.simple_schema, &fixtures.simple_missing_required).is_err(),
        "missing required property must fail schema validation (arg-order guard)"
    );
    assert!(
        validate(&fixtures.simple_schema, &fixtures.simple_wrong_type).is_err(),
        "wrong property type must fail schema validation"
    );
    assert!(
        validate(&fixtures.complex_schema, &fixtures.complex_valid).is_ok(),
        "valid complex instance must pass schema validation"
    );
    assert!(
        validate(
            &fixtures.complex_schema,
            &fixtures.complex_missing_nested_id
        )
        .is_err(),
        "missing nested required id must fail schema validation"
    );
}

// ============================================================================
// Handler Invocation Summary & Runner
// ============================================================================

#[derive(Debug, Eq, PartialEq)]
struct HandlerInvocationSummary {
    direct_tool_calls: usize,
    direct_resource_reads: usize,
    direct_prompt_gets: usize,
    live_roundtrips: usize,
}

fn run_handler_invocation_benchmarks(
    runtime: &asupersync::runtime::Runtime,
    direct_iterations: u64,
    live_iterations: u64,
) -> HandlerInvocationSummary {
    let mut direct_tool_calls = 0usize;
    let mut direct_resource_reads = 0usize;
    let mut direct_prompt_gets = 0usize;
    let mut live_roundtrips = 0usize;

    runtime.block_on(async {
        let cx = Cx::current().expect("runtime current Cx");
        let ctx = McpContext::new(cx.clone(), 1);
        let echo_args = serde_json::json!({"message": "bench-payload"});
        let json_args = serde_json::json!({"data": r#"{"k":"v","n":42}"#});

        // Pre-verify exact handler outputs before timing.
        fn extract_text(items: &[Content]) -> Vec<&str> {
            items
                .iter()
                .map(|item| match item {
                    Content::Text { text } => text.as_str(),
                    other => panic!("expected text content, got {other:?}"),
                })
                .collect()
        }
        let noop_out = Noop.call(&ctx, serde_json::json!({})).expect("noop call");
        assert_eq!(extract_text(&noop_out), vec![""]);
        let echo_out = BenchEcho
            .call(&ctx, echo_args.clone())
            .expect("bench_echo call");
        assert_eq!(extract_text(&echo_out), vec!["bench-payload"]);
        let rt_out = JsonRoundtrip
            .call(&ctx, json_args.clone())
            .expect("json_roundtrip call");
        assert_eq!(extract_text(&rt_out), vec![r#"{"k":"v","n":42}"#]);
        let res_out = BenchDataResource.read(&ctx).expect("bench_data read");
        assert_eq!(
            res_out.first().and_then(|item| item.text.as_deref()),
            Some(r#"{"benchmark": "data"}"#)
        );
        let prompt_out = BenchPromptPrompt
            .get(&ctx, HashMap::from([("name".to_owned(), "bench".to_owned())]))
            .expect("bench_prompt get");
        assert_eq!(prompt_out.len(), 1);
        assert_eq!(
            extract_text(std::slice::from_ref(&prompt_out[0].content)),
            vec!["Hello, bench"]
        );

        benchmark("Handler call: Noop (direct)", direct_iterations, || {
            let out = Noop
                .call(&ctx, serde_json::json!({}))
                .expect("noop call succeeds");
            direct_tool_calls += 1;
            let _ = black_box(out);
        });

        benchmark("Handler call: BenchEcho (direct)", direct_iterations, || {
            let out = BenchEcho
                .call(&ctx, echo_args.clone())
                .expect("bench_echo call succeeds");
            direct_tool_calls += 1;
            let _ = black_box(out);
        });

        benchmark(
            "Handler call: JsonRoundtrip (direct)",
            direct_iterations,
            || {
                let out = JsonRoundtrip
                    .call(&ctx, json_args.clone())
                    .expect("json_roundtrip call succeeds");
                direct_tool_calls += 1;
                let _ = black_box(out);
            },
        );

        benchmark(
            "Handler read: BenchDataResource (direct)",
            direct_iterations,
            || {
                let out = BenchDataResource
                    .read(&ctx)
                    .expect("bench_data read succeeds");
                direct_resource_reads += 1;
                let _ = black_box(out);
            },
        );

        let prompt_args = HashMap::from([("name".to_owned(), "bench".to_owned())]);
        benchmark(
            "Handler get: BenchPromptPrompt (direct)",
            direct_iterations,
            || {
                let out = BenchPromptPrompt
                    .get(&ctx, prompt_args.clone())
                    .expect("bench_prompt get succeeds");
                direct_prompt_gets += 1;
                let _ = black_box(out);
            },
        );

        // Live in-memory modern MCP 2026-07-28 client -> server round-trips.
        let server = ServerBuilder::new("bench", "1.0.0")
            .tool(Noop)
            .tool(BenchEcho)
            .tool(JsonRoundtrip)
            .resource(BenchDataResource)
            .prompt(BenchPromptPrompt)
            .build();
        let (client_transport, server_transport) = create_memory_transport_pair_with_capacity(16);
        let mut server_task = cx
            .spawn(move |serve_cx| async move { server.serve_memory(&serve_cx, server_transport).await })
            .expect("spawn in-memory benchmark server");
        let mut client = MemoryClient::builder(ClientInfo {
            name: "bench-client".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        })
        .connect(&cx, client_transport)
        .await
        .expect("connect modern MemoryClient");
        let cancellation = McpRequestCancellation::new();

        let start = Instant::now();
        for _ in 0..live_iterations {
            let CoreResult::Final(FinalCoreResult::ToolsCall { result, .. }) = client
                .call_tool(
                    &cx,
                    &cancellation,
                    "bench_echo",
                    serde_json::json!({"message": "live-bench"}),
                )
                .await
                .expect("live tools/call bench_echo")
            else {
                panic!("expected FinalCoreResult::ToolsCall");
            };
            assert_eq!(
                serde_json::to_value(result.payload).expect("serialize tool result")["content"][0]
                    ["text"],
                "live-bench"
            );
            live_roundtrips += 1;
        }
        let tool_elapsed = start.elapsed();
        let tool_ns = tool_elapsed.as_nanos() as f64 / live_iterations as f64;
        println!(
            "{:44} {:>10.2} ns/op  {:>12.0} ops/sec",
            "Live MCP 2026-07-28 tools/call (memory)",
            tool_ns,
            1_000_000_000.0 / tool_ns.max(1.0)
        );

        let CoreResult::Final(FinalCoreResult::ResourcesRead { result, .. }) = client
            .read_resource(&cx, &cancellation, "bench://data")
            .await
            .expect("live resources/read bench://data")
        else {
            panic!("expected FinalCoreResult::ResourcesRead");
        };
        assert_eq!(
            serde_json::to_value(result.payload).expect("serialize resource result")["contents"][0]
                ["text"],
            r#"{"benchmark": "data"}"#
        );
        live_roundtrips += 1;

        let CoreResult::Final(FinalCoreResult::PromptsGet { result, .. }) = client
            .get_prompt(
                &cx,
                &cancellation,
                "bench_prompt",
                HashMap::from([("name".to_owned(), "live".to_owned())]),
            )
            .await
            .expect("live prompts/get bench_prompt")
        else {
            panic!("expected FinalCoreResult::PromptsGet");
        };
        assert_eq!(
            serde_json::to_value(result.payload).expect("serialize prompt result")["messages"][0]
                ["content"]["text"],
            "Hello, live"
        );
        live_roundtrips += 1;

        client.close(&cx).expect("close modern MemoryClient");
        server_task
            .join(&cx)
            .await
            .expect("benchmark server task joins")
            .expect("benchmark server settles cleanly");
    });

    HandlerInvocationSummary {
        direct_tool_calls,
        direct_resource_reads,
        direct_prompt_gets,
        live_roundtrips,
    }
}

// ============================================================================
// Benchmarks
// ============================================================================

fn bench_server_creation(runtime: &asupersync::runtime::Runtime) {
    println!("\n=== Server Creation ===");

    // Minimal server
    let start = Instant::now();
    let _server = ServerBuilder::new("bench", "1.0.0").build();
    let minimal = start.elapsed();
    println!(
        "Minimal server (no handlers):      {}",
        format_duration(minimal)
    );

    // Server with one tool
    let start = Instant::now();
    let _server = ServerBuilder::new("bench", "1.0.0").tool(Noop).build();
    let one_tool = start.elapsed();
    println!(
        "Server with 1 tool:                {}",
        format_duration(one_tool)
    );

    // Server with multiple handlers
    let start = Instant::now();
    let _server = ServerBuilder::new("bench", "1.0.0")
        .tool(Noop)
        .tool(BenchEcho)
        .tool(JsonRoundtrip)
        .resource(BenchDataResource)
        .prompt(BenchPromptPrompt)
        .build();
    let full = start.elapsed();
    println!(
        "Server with 3 tools+1 res+1 prompt:{}",
        format_duration(full)
    );

    // 100 distinct tools (verified live through tools/list)
    let start = Instant::now();
    let server_100 = build_distinct_tool_server(100);
    let many = start.elapsed();
    let registered_count = count_registered_tools_live(runtime, server_100);
    assert_eq!(
        registered_count, 100,
        "100-tool benchmark must register 100 distinct tools"
    );
    println!(
        "Server with 100 distinct tools:    {} (verified {} tools)",
        format_duration(many),
        registered_count
    );
}

fn bench_handler_invocation(runtime: &asupersync::runtime::Runtime) {
    println!("\n=== Handler Invocation ===");
    let summary = run_handler_invocation_benchmarks(runtime, 5_000, 200);
    assert!(summary.direct_tool_calls > 0);
    assert!(summary.direct_resource_reads > 0);
    assert!(summary.direct_prompt_gets > 0);
    assert!(summary.live_roundtrips > 0);
}

fn bench_json_serialization() {
    println!("\n=== JSON Serialization ===");

    // Small message
    let small_msg = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": "echo", "arguments": {"message": "hello"}},
        "id": 1
    });

    benchmark("Small JSON serialize", 100_000, || {
        let _ = black_box(serde_json::to_string(&small_msg));
    });

    benchmark("Small JSON deserialize", 100_000, || {
        let _ = black_box(serde_json::from_str::<serde_json::Value>(
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo"},"id":1}"#,
        ));
    });

    // Medium message (tool list response)
    let medium_msg = serde_json::json!({
        "jsonrpc": "2.0",
        "result": {
            "tools": [
                {"name": "tool1", "description": "Description 1", "inputSchema": {"type": "object"}},
                {"name": "tool2", "description": "Description 2", "inputSchema": {"type": "object"}},
                {"name": "tool3", "description": "Description 3", "inputSchema": {"type": "object"}},
                {"name": "tool4", "description": "Description 4", "inputSchema": {"type": "object"}},
                {"name": "tool5", "description": "Description 5", "inputSchema": {"type": "object"}},
            ]
        },
        "id": 1
    });

    benchmark("Medium JSON serialize", 50_000, || {
        let _ = black_box(serde_json::to_string(&medium_msg));
    });

    let medium_str = serde_json::to_string(&medium_msg).unwrap();
    benchmark("Medium JSON deserialize", 50_000, || {
        let _ = black_box(serde_json::from_str::<serde_json::Value>(&medium_str));
    });

    // Large message (tool call result with content)
    let large_content = "x".repeat(10_000);
    let large_msg = serde_json::json!({
        "jsonrpc": "2.0",
        "result": {
            "content": [{"type": "text", "text": large_content}],
            "isError": false
        },
        "id": 1
    });

    benchmark("Large JSON serialize (10KB)", 10_000, || {
        let _ = black_box(serde_json::to_string(&large_msg));
    });

    let large_str = serde_json::to_string(&large_msg).unwrap();
    benchmark("Large JSON deserialize (10KB)", 10_000, || {
        let _ = black_box(serde_json::from_str::<serde_json::Value>(&large_str));
    });
}

fn bench_protocol_types() {
    use fastmcp_protocol::{CallToolParams, Content, InitializeParams, JsonRpcRequest, Tool};

    println!("\n=== Protocol Type Operations ===");

    // Modern MCP 2026-07-28 FinalCallToolParams serialize
    let modern_meta = OpenMetadata::try_from_entries([(
        "protocolVersion".to_owned(),
        serde_json::json!("2026-07-28"),
    )])
    .expect("valid modern request _meta");
    benchmark(
        "FinalCallToolParams (2026-07-28) serialize",
        100_000,
        || {
            let params = FinalCallToolParams {
                meta: modern_meta.clone(),
                name: "echo".to_owned(),
                arguments: FinalArguments::Value(serde_json::json!({"message": "hello"})),
                input_responses: None,
                request_state: None,
            };
            let _ = black_box(serde_json::to_string(&params));
        },
    );

    // Legacy 2024-11-05 InitializeParams create
    benchmark("InitializeParams (2024-11-05) create", 100_000, || {
        let _ = black_box(InitializeParams {
            protocol_version: "2024-11-05".to_string(),
            capabilities: fastmcp_protocol::ClientCapabilities::default(),
            client_info: fastmcp_protocol::ClientInfo {
                name: "test".to_string(),
                version: "1.0".to_string(),
            },
        });
    });

    // Tool definition
    benchmark("Tool definition create", 100_000, || {
        let _ = black_box(Tool {
            name: "my_tool".to_string(),
            description: Some("A test tool".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            icon: None,
            version: None,
            tags: vec![],
            annotations: None,
        });
    });

    // Legacy 2024-11-05 CallToolParams
    benchmark("CallToolParams (2024-11-05) serialize", 100_000, || {
        let params = CallToolParams {
            name: "echo".to_string(),
            arguments: Some(serde_json::json!({"message": "hello"})),
            meta: None,
        };
        let _ = black_box(serde_json::to_string(&params));
    });

    // Content creation
    benchmark("Content::Text create", 100_000, || {
        let _ = black_box(Content::Text {
            text: "Hello, world!".to_string(),
        });
    });

    // JSON-RPC request
    benchmark("JsonRpcRequest create", 100_000, || {
        let _ = black_box(JsonRpcRequest::new(
            "tools/call",
            Some(serde_json::json!({"name": "test"})),
            1,
        ));
    });
}

fn bench_transport_codec() {
    use fastmcp_transport::Codec;

    println!("\n=== Transport Codec ===");

    // Create test messages
    let request = fastmcp_protocol::JsonRpcRequest::new(
        "tools/call",
        Some(serde_json::json!({"name": "echo", "arguments": {"msg": "hello"}})),
        1,
    );

    let response = fastmcp_protocol::JsonRpcResponse::success(
        fastmcp_protocol::RequestId::Number(1),
        serde_json::json!({"content": [{"type": "text", "text": "hello"}]}),
    );

    let codec = Codec::new();

    // Encode benchmarks
    benchmark("Encode request", 100_000, || {
        let _ = black_box(codec.encode_request(&request));
    });

    benchmark("Encode response", 100_000, || {
        let _ = black_box(codec.encode_response(&response));
    });

    // Decode benchmarks
    let encoded_request = codec.encode_request(&request).unwrap();
    let encoded_response = codec.encode_response(&response).unwrap();

    benchmark("Decode request", 100_000, || {
        let mut c = Codec::new();
        let _ = black_box(c.decode(&encoded_request));
    });

    benchmark("Decode response", 100_000, || {
        let mut c = Codec::new();
        let _ = black_box(c.decode(&encoded_response));
    });

    // Large message
    let large_content = "x".repeat(10_000);
    let large_response = fastmcp_protocol::JsonRpcResponse::success(
        fastmcp_protocol::RequestId::Number(1),
        serde_json::json!({"content": [{"type": "text", "text": large_content}]}),
    );

    benchmark("Encode large response (10KB)", 10_000, || {
        let _ = black_box(codec.encode_response(&large_response));
    });

    let encoded_large = codec.encode_response(&large_response).unwrap();

    benchmark("Decode large response (10KB)", 10_000, || {
        let mut c = Codec::new();
        let _ = black_box(c.decode(&encoded_large));
    });
}

fn bench_context_operations(runtime: &asupersync::runtime::Runtime) {
    println!("\n=== Context Operations ===");

    runtime.block_on(async {
        let cx = Cx::current().expect("runtime current Cx");
        let ctx = McpContext::new(cx.clone(), 1);

        // is_cancelled check (should be very fast)
        benchmark("is_cancelled check", 1_000_000, || {
            let _ = black_box(ctx.is_cancelled());
        });

        // checkpoint (also very fast)
        benchmark("checkpoint call", 1_000_000, || {
            let _ = black_box(ctx.checkpoint());
        });

        // budget check
        benchmark("budget().is_exhausted()", 1_000_000, || {
            let _ = black_box(ctx.budget().is_exhausted());
        });

        // create new context
        benchmark("McpContext::new", 100_000, || {
            let _ = black_box(McpContext::new(cx.clone(), 1));
        });
    });
}

fn bench_memory_usage() {
    use fastmcp_protocol::{
        CallToolParams, CallToolResult, Content, InitializeParams, JsonRpcMessage, JsonRpcRequest,
        JsonRpcResponse, Tool,
    };

    println!("\n=== Memory Usage (size_of) ===");

    println!(
        "McpContext:          {:>4} bytes",
        std::mem::size_of::<McpContext>()
    );
    println!(
        "Tool:                {:>4} bytes",
        std::mem::size_of::<Tool>()
    );
    println!(
        "Content:             {:>4} bytes",
        std::mem::size_of::<Content>()
    );
    println!(
        "JsonRpcRequest:      {:>4} bytes",
        std::mem::size_of::<JsonRpcRequest>()
    );
    println!(
        "JsonRpcResponse:     {:>4} bytes",
        std::mem::size_of::<JsonRpcResponse>()
    );
    println!(
        "JsonRpcMessage:      {:>4} bytes",
        std::mem::size_of::<JsonRpcMessage>()
    );
    println!(
        "CallToolParams:      {:>4} bytes",
        std::mem::size_of::<CallToolParams>()
    );
    println!(
        "FinalCallToolParams: {:>4} bytes",
        std::mem::size_of::<FinalCallToolParams>()
    );
    println!(
        "CallToolResult:      {:>4} bytes",
        std::mem::size_of::<CallToolResult>()
    );
    println!(
        "InitializeParams:    {:>4} bytes",
        std::mem::size_of::<InitializeParams>()
    );
}

fn bench_schema_validation() {
    use fastmcp_protocol::schema::validate;

    println!("\n=== Schema Validation ===");

    let fixtures = schema_bench_fixtures();
    // Prove argument order (schema first, value second) before timing.
    verify_schema_fixtures(&fixtures);

    benchmark("Validate simple (valid)", 100_000, || {
        let res = validate(&fixtures.simple_schema, &fixtures.simple_valid);
        debug_assert!(res.is_ok());
        let _ = black_box(res);
    });

    benchmark("Validate simple (missing required)", 100_000, || {
        let res = validate(&fixtures.simple_schema, &fixtures.simple_missing_required);
        debug_assert!(res.is_err());
        let _ = black_box(res);
    });

    benchmark("Validate simple (wrong type)", 100_000, || {
        let res = validate(&fixtures.simple_schema, &fixtures.simple_wrong_type);
        debug_assert!(res.is_err());
        let _ = black_box(res);
    });

    benchmark("Validate complex (valid)", 50_000, || {
        let res = validate(&fixtures.complex_schema, &fixtures.complex_valid);
        debug_assert!(res.is_ok());
        let _ = black_box(res);
    });

    benchmark("Validate complex (missing nested id)", 50_000, || {
        let res = validate(
            &fixtures.complex_schema,
            &fixtures.complex_missing_nested_id,
        );
        debug_assert!(res.is_err());
        let _ = black_box(res);
    });
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    println!("FastMCP Performance Benchmarks");
    println!("==============================");
    println!();
    println!("Note: Run with --release for accurate results!");
    println!("      cargo run -p fastmcp-rust --example bench --release");

    let runtime = build_runtime();

    bench_server_creation(&runtime);
    bench_handler_invocation(&runtime);
    bench_json_serialization();
    bench_protocol_types();
    bench_transport_codec();
    bench_context_operations(&runtime);
    bench_schema_validation();
    bench_memory_usage();

    println!("\n==============================");
    println!("Benchmarks complete!");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_schema_validation_order_positive_and_planted_negative() {
        let fixtures = schema_bench_fixtures();
        verify_schema_fixtures(&fixtures);

        // Planted regression check (RH-5): swapping arguments turns the missing-
        // required invalid fixture into a schema with no keywords, which silently
        // passes validation — proving why verify_schema_fixtures catches the bug.
        assert!(
            fastmcp_protocol::schema::validate(
                &fixtures.simple_missing_required,
                &fixtures.simple_schema,
            )
            .is_ok(),
            "swapped arguments silently accept the invalid payload, proving the negative guard is non-vacuous"
        );
    }

    #[test]
    fn bench_registers_100_distinct_tools() {
        let runtime = build_runtime();
        let server = build_distinct_tool_server(100);
        assert_eq!(count_registered_tools_live(&runtime, server), 100);
    }

    #[test]
    fn bench_invokes_real_handlers_directly_and_over_modern_memory() {
        let runtime = build_runtime();
        let summary = run_handler_invocation_benchmarks(&runtime, 2, 2);
        assert!(summary.direct_tool_calls >= 6);
        assert!(summary.direct_resource_reads >= 2);
        assert!(summary.direct_prompt_gets >= 2);
        assert_eq!(summary.live_roundtrips, 4);
    }
}
