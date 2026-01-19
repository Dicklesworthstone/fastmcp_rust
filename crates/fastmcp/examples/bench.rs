//! FastMCP Performance Benchmarks
//!
//! Simple benchmarks using std::time::Instant to measure performance characteristics.
//! Run with: `cargo run --example bench --release`
//!
//! Measurements:
//! - Server creation time
//! - JSON serialization/deserialization throughput
//! - Protocol message encoding/decoding
//! - Handler invocation overhead
//!
//! Note: For accurate results, always run with --release flag.

use std::time::{Duration, Instant};

use fastmcp::prelude::*;

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

    println!(
        "{name:40} {:>10.2} ns/op  {:>12.0} ops/sec",
        per_op, ops_per_sec
    );
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

// ============================================================================
// Sample Handlers for Benchmarks
// ============================================================================

#[tool(description = "A no-op tool for benchmarking")]
fn noop(_ctx: &McpContext) -> String {
    String::new()
}

#[tool(description = "Echo back the input")]
#[allow(clippy::needless_pass_by_value)]  // Macro requires String
fn bench_echo(_ctx: &McpContext, message: String) -> String {
    message
}

#[tool(description = "Parse and return JSON")]
#[allow(clippy::needless_pass_by_value)]  // Macro requires String
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
#[allow(clippy::needless_pass_by_value)]  // Macro requires String
fn bench_prompt(_ctx: &McpContext, name: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!("Hello, {name}"),
        },
    }]
}

// ============================================================================
// Benchmarks
// ============================================================================

fn bench_server_creation() {
    println!("\n=== Server Creation ===");

    // Minimal server
    let start = Instant::now();
    let _server = Server::new("bench", "1.0.0").build();
    let minimal = start.elapsed();
    println!(
        "Minimal server (no handlers):      {}",
        format_duration(minimal)
    );

    // Server with one tool
    let start = Instant::now();
    let _server = Server::new("bench", "1.0.0").tool(Noop).build();
    let one_tool = start.elapsed();
    println!(
        "Server with 1 tool:                {}",
        format_duration(one_tool)
    );

    // Server with multiple handlers
    let start = Instant::now();
    let _server = Server::new("bench", "1.0.0")
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

    // Stress test: many tools (simulated by repeated registration)
    let start = Instant::now();
    let mut builder = Server::new("bench", "1.0.0");
    for _ in 0..100 {
        builder = builder.tool(Noop);
    }
    let _server = builder.build();
    let many = start.elapsed();
    println!(
        "Server with 100 tools:             {}",
        format_duration(many)
    );
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
        let _ = serde_json::to_string(&small_msg);
    });

    benchmark("Small JSON deserialize", 100_000, || {
        let _ = serde_json::from_str::<serde_json::Value>(
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo"},"id":1}"#,
        );
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
        let _ = serde_json::to_string(&medium_msg);
    });

    let medium_str = serde_json::to_string(&medium_msg).unwrap();
    benchmark("Medium JSON deserialize", 50_000, || {
        let _ = serde_json::from_str::<serde_json::Value>(&medium_str);
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
        let _ = serde_json::to_string(&large_msg);
    });

    let large_str = serde_json::to_string(&large_msg).unwrap();
    benchmark("Large JSON deserialize (10KB)", 10_000, || {
        let _ = serde_json::from_str::<serde_json::Value>(&large_str);
    });
}

fn bench_protocol_types() {
    use fastmcp_protocol::{CallToolParams, Content, InitializeParams, JsonRpcRequest, Tool};

    println!("\n=== Protocol Type Operations ===");

    // Initialize params
    benchmark("InitializeParams create", 100_000, || {
        let _ = InitializeParams {
            protocol_version: "2024-11-05".to_string(),
            capabilities: fastmcp_protocol::ClientCapabilities::default(),
            client_info: fastmcp_protocol::ClientInfo {
                name: "test".to_string(),
                version: "1.0".to_string(),
            },
        };
    });

    // Tool definition
    benchmark("Tool definition create", 100_000, || {
        let _ = Tool {
            name: "my_tool".to_string(),
            description: Some("A test tool".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
        };
    });

    // CallToolParams
    benchmark("CallToolParams serialize", 100_000, || {
        let params = CallToolParams {
            name: "echo".to_string(),
            arguments: Some(serde_json::json!({"message": "hello"})),
            meta: None,
        };
        let _ = serde_json::to_string(&params);
    });

    // Content creation
    benchmark("Content::Text create", 100_000, || {
        let _ = Content::Text {
            text: "Hello, world!".to_string(),
        };
    });

    // JSON-RPC request
    benchmark("JsonRpcRequest create", 100_000, || {
        let _ = JsonRpcRequest::new("tools/call", Some(serde_json::json!({"name": "test"})), 1);
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

    let response = fastmcp_protocol::JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: Some(serde_json::json!({"content": [{"type": "text", "text": "hello"}]})),
        error: None,
        id: Some(fastmcp_protocol::RequestId::Number(1)),
    };

    let codec = Codec::new();

    // Encode benchmarks
    benchmark("Encode request", 100_000, || {
        let _ = codec.encode_request(&request);
    });

    benchmark("Encode response", 100_000, || {
        let _ = codec.encode_response(&response);
    });

    // Decode benchmarks
    let encoded_request = codec.encode_request(&request).unwrap();
    let encoded_response = codec.encode_response(&response).unwrap();

    benchmark("Decode request", 100_000, || {
        let mut c = Codec::new();
        let _ = c.decode(&encoded_request);
    });

    benchmark("Decode response", 100_000, || {
        let mut c = Codec::new();
        let _ = c.decode(&encoded_response);
    });

    // Large message
    let large_content = "x".repeat(10_000);
    let large_response = fastmcp_protocol::JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: Some(serde_json::json!({"content": [{"type": "text", "text": large_content}]})),
        error: None,
        id: Some(fastmcp_protocol::RequestId::Number(1)),
    };

    benchmark("Encode large response (10KB)", 10_000, || {
        let _ = codec.encode_response(&large_response);
    });

    let encoded_large = codec.encode_response(&large_response).unwrap();

    benchmark("Decode large response (10KB)", 10_000, || {
        let mut c = Codec::new();
        let _ = c.decode(&encoded_large);
    });
}

fn bench_context_operations() {
    println!("\n=== Context Operations ===");

    let cx = asupersync::Cx::for_testing();
    let ctx = McpContext::new(cx.clone(), 1);

    // is_cancelled check (should be very fast)
    benchmark("is_cancelled check", 1_000_000, || {
        let _ = ctx.is_cancelled();
    });

    // checkpoint (also very fast)
    benchmark("checkpoint call", 1_000_000, || {
        let _ = ctx.checkpoint();
    });

    // budget check
    benchmark("budget().is_exhausted()", 1_000_000, || {
        let _ = ctx.budget().is_exhausted();
    });

    // create new context
    benchmark("McpContext::new", 100_000, || {
        let _ = McpContext::new(cx.clone(), 1);
    });
}

fn bench_memory_usage() {
    use fastmcp_protocol::{
        CallToolParams, CallToolResult, Content, InitializeParams, JsonRpcMessage, JsonRpcRequest,
        JsonRpcResponse, Tool,
    };

    println!("\n=== Memory Usage (size_of) ===");

    println!(
        "McpContext:       {:>4} bytes",
        std::mem::size_of::<McpContext>()
    );
    println!("Tool:             {:>4} bytes", std::mem::size_of::<Tool>());
    println!(
        "Content:          {:>4} bytes",
        std::mem::size_of::<Content>()
    );
    println!(
        "JsonRpcRequest:   {:>4} bytes",
        std::mem::size_of::<JsonRpcRequest>()
    );
    println!(
        "JsonRpcResponse:  {:>4} bytes",
        std::mem::size_of::<JsonRpcResponse>()
    );
    println!(
        "JsonRpcMessage:   {:>4} bytes",
        std::mem::size_of::<JsonRpcMessage>()
    );
    println!(
        "CallToolParams:   {:>4} bytes",
        std::mem::size_of::<CallToolParams>()
    );
    println!(
        "CallToolResult:   {:>4} bytes",
        std::mem::size_of::<CallToolResult>()
    );
    println!(
        "InitializeParams: {:>4} bytes",
        std::mem::size_of::<InitializeParams>()
    );
}

fn bench_schema_validation() {
    use fastmcp_protocol::schema::validate;

    println!("\n=== Schema Validation ===");

    // Simple schema
    let simple_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"}
        },
        "required": ["name"]
    });

    let valid_value = serde_json::json!({"name": "Alice", "age": 30});
    let invalid_value = serde_json::json!({"age": 30});

    benchmark("Validate simple (valid)", 100_000, || {
        let _ = validate(&valid_value, &simple_schema);
    });

    benchmark("Validate simple (invalid)", 100_000, || {
        let _ = validate(&invalid_value, &simple_schema);
    });

    // Complex schema
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

    let complex_value = serde_json::json!({
        "users": [
            {"id": 1, "name": "Alice", "email": "alice@example.com"},
            {"id": 2, "name": "Bob"}
        ],
        "metadata": {"version": "1.0", "timestamp": 1234567890}
    });

    benchmark("Validate complex (valid)", 50_000, || {
        let _ = validate(&complex_value, &complex_schema);
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
    println!("      cargo run --example bench --release");

    bench_server_creation();
    bench_json_serialization();
    bench_protocol_types();
    bench_transport_codec();
    bench_context_operations();
    bench_schema_validation();
    bench_memory_usage();

    println!("\n==============================");
    println!("Benchmarks complete!");
}
