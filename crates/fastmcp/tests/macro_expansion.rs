//! Integration tests for procedural macro expansion.
//!
//! These tests verify that `#[tool]`, `#[resource]`, `#[prompt]`, and
//! `#[derive(JsonSchema)]` macros generate correct handler implementations
//! with proper trait impls, parameter extraction, schema generation,
//! doc comments, async handling, and return type conversion.

// Test-specific clippy allowances:
// - unused_async: async functions are intentionally async to test macro handling
// - struct_field_names: test structs use explicit naming for clarity
// - similar_names: test functions have intentionally similar names
// - too_many_lines: test file needs comprehensive coverage
// - unnecessary_wraps: testing Result return type handling
// - enum_variant_names: test enums for schema testing
// - dead_code: test structs/enums exist only for schema generation testing
#![allow(clippy::unused_async)]
#![allow(clippy::struct_field_names)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::enum_variant_names)]
#![allow(dead_code)]

use fastmcp::{
    Content, Cx, JsonSchema, McpContext, McpResult, PromptHandler, PromptMessage, ResourceHandler,
    Role, ToolHandler, prompt, resource, tool,
};
use serde_json::json;
use std::collections::HashMap;

fn test_ctx() -> McpContext {
    McpContext::new(Cx::for_testing(), 1)
}

// ============================================================================
// #[tool] expansion tests
// ============================================================================

/// A simple greeting tool.
#[tool]
fn greet_simple(name: String) -> String {
    format!("Hello, {name}!")
}

#[test]
fn tool_definition_name_from_fn() {
    let handler = GreetSimple;
    let def = handler.definition();
    assert_eq!(def.name, "greet_simple");
}

#[test]
fn tool_definition_description_from_doc_comment() {
    let handler = GreetSimple;
    let def = handler.definition();
    assert_eq!(def.description, Some("A simple greeting tool.".to_string()));
}

#[test]
fn tool_definition_input_schema_string_param() {
    let handler = GreetSimple;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert!(props.contains_key("name"));
    assert_eq!(props["name"]["type"], "string");
}

#[test]
fn tool_definition_required_params() {
    let handler = GreetSimple;
    let def = handler.definition();
    let required = def.input_schema["required"].as_array().unwrap();
    assert!(required.iter().any(|v| v.as_str() == Some("name")));
}

#[test]
fn tool_call_returns_text_content() {
    let handler = GreetSimple;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"name": "World"})).unwrap();
    assert_eq!(result.len(), 1);
    match &result[0] {
        Content::Text { text } => assert_eq!(text, "Hello, World!"),
        _ => panic!("Expected Text content"),
    }
}

// --- Tool with name override ---

/// This description should be used.
#[tool(name = "custom_name")]
fn tool_with_custom_name() -> String {
    "ok".to_string()
}

#[test]
fn tool_name_override() {
    let handler = ToolWithCustomName;
    let def = handler.definition();
    assert_eq!(def.name, "custom_name");
}

// --- Tool with description override ---

/// This doc comment should be ignored.
#[tool(description = "Explicit description")]
fn tool_with_desc_override() -> String {
    "ok".to_string()
}

#[test]
fn tool_description_override() {
    let handler = ToolWithDescOverride;
    let def = handler.definition();
    assert_eq!(def.description, Some("Explicit description".to_string()));
}

// --- Tool with no doc comment and no description attr ---

#[tool]
fn tool_no_description() -> String {
    "ok".to_string()
}

#[test]
fn tool_no_description_is_none() {
    let handler = ToolNoDescription;
    let def = handler.definition();
    assert!(def.description.is_none());
}

// --- Tool with multiple parameters (required + optional) ---

/// Adds two numbers.
#[tool]
fn add_numbers(a: i64, b: i64, label: Option<String>) -> String {
    let sum = a + b;
    match label {
        Some(l) => format!("{l}: {sum}"),
        None => format!("{sum}"),
    }
}

#[test]
fn tool_multiple_params_definition() {
    let handler = AddNumbers;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert!(props.contains_key("a"));
    assert!(props.contains_key("b"));
    assert!(props.contains_key("label"));
    assert_eq!(props["a"]["type"], "integer");
    assert_eq!(props["b"]["type"], "integer");
}

#[test]
fn tool_required_excludes_optional() {
    let handler = AddNumbers;
    let def = handler.definition();
    let required: Vec<&str> = def.input_schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(required.contains(&"a"));
    assert!(required.contains(&"b"));
    assert!(!required.contains(&"label"));
}

#[test]
fn tool_call_with_required_params() {
    let handler = AddNumbers;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"a": 3, "b": 4})).unwrap();
    match &result[0] {
        Content::Text { text } => assert_eq!(text, "7"),
        _ => panic!("Expected Text content"),
    }
}

#[test]
fn tool_call_with_optional_param() {
    let handler = AddNumbers;
    let ctx = test_ctx();
    let result = handler
        .call(&ctx, json!({"a": 3, "b": 4, "label": "Sum"}))
        .unwrap();
    match &result[0] {
        Content::Text { text } => assert_eq!(text, "Sum: 7"),
        _ => panic!("Expected Text content"),
    }
}

#[test]
fn tool_call_missing_required_param_errors() {
    let handler = AddNumbers;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"a": 3}));
    assert!(result.is_err());
}

// --- Tool with context parameter ---

/// Tool that uses context.
#[tool]
fn tool_with_context(ctx: &McpContext, msg: String) -> String {
    // Just verify we got a valid context
    let _id = ctx.request_id();
    format!("ctx:{msg}")
}

#[test]
fn tool_with_context_call() {
    let handler = ToolWithContext;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"msg": "hello"})).unwrap();
    match &result[0] {
        Content::Text { text } => assert_eq!(text, "ctx:hello"),
        _ => panic!("Expected Text content"),
    }
}

#[test]
fn tool_with_context_schema_excludes_ctx() {
    let handler = ToolWithContext;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    // Context should not appear in schema
    assert!(!props.contains_key("ctx"));
    assert!(props.contains_key("msg"));
}

// --- Tool returning Vec<Content> directly ---

/// Returns multiple content items.
#[tool]
fn multi_content() -> Vec<Content> {
    vec![
        Content::Text {
            text: "first".to_string(),
        },
        Content::Text {
            text: "second".to_string(),
        },
    ]
}

#[test]
fn tool_returning_vec_content() {
    let handler = MultiContent;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({})).unwrap();
    assert_eq!(result.len(), 2);
}

// --- Tool returning McpResult<String> ---

/// Fallible tool.
#[tool]
fn fallible_tool(succeed: bool) -> McpResult<String> {
    if succeed {
        Ok("success".to_string())
    } else {
        Err(fastmcp::McpError::internal_error("failed"))
    }
}

#[test]
fn tool_result_ok() {
    let handler = FallibleTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"succeed": true})).unwrap();
    match &result[0] {
        Content::Text { text } => assert_eq!(text, "success"),
        _ => panic!("Expected Text content"),
    }
}

#[test]
fn tool_result_err() {
    let handler = FallibleTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"succeed": false}));
    assert!(result.is_err());
}

// --- Tool with no parameters ---

/// Returns a fixed value.
#[tool]
fn no_params_tool() -> String {
    "fixed".to_string()
}

#[test]
fn tool_no_params_empty_schema() {
    let handler = NoParamsTool;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert!(props.is_empty());
    let required = def.input_schema["required"].as_array().unwrap();
    assert!(required.is_empty());
}

#[test]
fn tool_no_params_call() {
    let handler = NoParamsTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({})).unwrap();
    match &result[0] {
        Content::Text { text } => assert_eq!(text, "fixed"),
        _ => panic!("Expected Text content"),
    }
}

// --- Tool with timeout ---

/// Tool with custom timeout.
#[tool(timeout = "30s")]
fn timed_tool() -> String {
    "ok".to_string()
}

#[test]
fn tool_timeout_30s() {
    let handler = TimedTool;
    let timeout = handler.timeout();
    assert_eq!(timeout, Some(std::time::Duration::from_secs(30)));
}

// --- Tool with complex timeout ---

/// Tool with compound timeout.
#[tool(timeout = "1h30m")]
fn long_timed_tool() -> String {
    "ok".to_string()
}

#[test]
fn tool_timeout_compound() {
    let handler = LongTimedTool;
    let timeout = handler.timeout();
    assert_eq!(timeout, Some(std::time::Duration::from_secs(90 * 60)));
}

// --- Tool with bool parameter ---

/// Check bool schema.
#[tool]
fn bool_tool(flag: bool) -> String {
    format!("{flag}")
}

#[test]
fn tool_bool_param_schema() {
    let handler = BoolTool;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert_eq!(props["flag"]["type"], "boolean");
}

// --- Tool with Vec parameter ---

/// Check Vec schema.
#[tool]
fn vec_tool(items: Vec<String>) -> String {
    items.join(", ")
}

#[test]
fn tool_vec_param_schema() {
    let handler = VecTool;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert_eq!(props["items"]["type"], "array");
    assert_eq!(props["items"]["items"]["type"], "string");
}

#[test]
fn tool_vec_param_call() {
    let handler = VecTool;
    let ctx = test_ctx();
    let result = handler
        .call(&ctx, json!({"items": ["a", "b", "c"]}))
        .unwrap();
    match &result[0] {
        Content::Text { text } => assert_eq!(text, "a, b, c"),
        _ => panic!("Expected Text content"),
    }
}

// --- Tool with f64 parameter ---

/// Check numeric schema.
#[tool]
fn float_tool(value: f64) -> String {
    format!("{value:.2}")
}

#[test]
fn tool_float_param_schema() {
    let handler = FloatTool;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert_eq!(props["value"]["type"], "number");
}

// --- Async tool ---

/// An async greeting tool.
#[tool]
async fn async_greet(name: String) -> String {
    format!("Hello async, {name}!")
}

#[test]
fn async_tool_definition() {
    let handler = AsyncGreet;
    let def = handler.definition();
    assert_eq!(def.name, "async_greet");
    assert_eq!(def.description, Some("An async greeting tool.".to_string()));
}

#[test]
fn async_tool_call() {
    let handler = AsyncGreet;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"name": "Rust"})).unwrap();
    match &result[0] {
        Content::Text { text } => assert_eq!(text, "Hello async, Rust!"),
        _ => panic!("Expected Text content"),
    }
}

// --- Async tool with context ---

/// Async tool with context.
#[tool]
async fn async_ctx_tool(ctx: &McpContext, val: String) -> String {
    let _id = ctx.request_id();
    format!("async:{val}")
}

#[test]
fn async_tool_with_context_call() {
    let handler = AsyncCtxTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"val": "test"})).unwrap();
    match &result[0] {
        Content::Text { text } => assert_eq!(text, "async:test"),
        _ => panic!("Expected Text content"),
    }
}

// --- Tool default trait methods ---

#[test]
fn tool_default_icon_is_none() {
    let handler = GreetSimple;
    assert!(handler.icon().is_none());
}

#[test]
fn tool_default_version_is_none() {
    let handler = GreetSimple;
    assert!(handler.version().is_none());
}

#[test]
fn tool_default_tags_are_empty() {
    let handler = GreetSimple;
    assert!(handler.tags().is_empty());
}

#[test]
fn tool_default_annotations_is_none() {
    let handler = GreetSimple;
    assert!(handler.annotations().is_none());
}

#[test]
fn tool_default_output_schema_is_none() {
    let handler = GreetSimple;
    assert!(handler.output_schema().is_none());
}

#[test]
fn tool_default_timeout_is_none() {
    let handler = GreetSimple;
    assert!(handler.timeout().is_none());
}

// --- Tool with output_schema ---

/// Tool with explicit output schema.
#[tool(output_schema = serde_json::json!({
    "type": "object",
    "properties": {
        "result": { "type": "string" },
        "count": { "type": "integer" }
    },
    "required": ["result"]
}))]
fn tool_with_output_schema(input: String) -> String {
    format!("processed: {input}")
}

#[test]
fn tool_output_schema_is_set() {
    let handler = ToolWithOutputSchema;
    let schema = handler.output_schema();
    assert!(schema.is_some());
    let schema = schema.unwrap();
    assert_eq!(schema["type"], "object");
    let props = schema["properties"].as_object().unwrap();
    assert!(props.contains_key("result"));
    assert!(props.contains_key("count"));
}

#[test]
fn tool_output_schema_in_definition() {
    let handler = ToolWithOutputSchema;
    let def = handler.definition();
    assert!(def.output_schema.is_some());
    let schema = def.output_schema.unwrap();
    assert_eq!(schema["type"], "object");
}

// --- Tool with HashMap parameter ---

/// Tool with HashMap parameter.
#[tool]
fn map_tool(metadata: std::collections::HashMap<String, String>) -> String {
    metadata
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[test]
fn tool_hashmap_param_schema() {
    let handler = MapTool;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert_eq!(props["metadata"]["type"], "object");
    assert_eq!(props["metadata"]["additionalProperties"]["type"], "string");
}

#[test]
fn tool_hashmap_param_call() {
    let handler = MapTool;
    let ctx = test_ctx();
    let result = handler
        .call(&ctx, json!({"metadata": {"key1": "val1", "key2": "val2"}}))
        .unwrap();
    match &result[0] {
        Content::Text { text } => {
            assert!(text.contains("key1=val1") || text.contains("key2=val2"));
        }
        _ => panic!("Expected Text content"),
    }
}

// --- Tool with u32/i32 parameters ---

/// Tool with unsigned integer parameter.
#[tool]
fn uint_tool(count: u32) -> String {
    format!("count: {count}")
}

#[test]
fn tool_u32_param_schema() {
    let handler = UintTool;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert_eq!(props["count"]["type"], "integer");
}

#[test]
fn tool_u32_param_call() {
    let handler = UintTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"count": 42})).unwrap();
    match &result[0] {
        Content::Text { text } => assert_eq!(text, "count: 42"),
        _ => panic!("Expected Text content"),
    }
}

/// Tool with signed integer parameter.
#[tool]
fn int_tool(value: i32) -> String {
    format!("value: {value}")
}

#[test]
fn tool_i32_param_schema() {
    let handler = IntTool;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert_eq!(props["value"]["type"], "integer");
}

#[test]
fn tool_i32_param_call_positive() {
    let handler = IntTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"value": 100})).unwrap();
    match &result[0] {
        Content::Text { text } => assert_eq!(text, "value: 100"),
        _ => panic!("Expected Text content"),
    }
}

#[test]
fn tool_i32_param_call_negative() {
    let handler = IntTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"value": -50})).unwrap();
    match &result[0] {
        Content::Text { text } => assert_eq!(text, "value: -50"),
        _ => panic!("Expected Text content"),
    }
}

// --- Tool with nested Vec ---

/// Tool with nested Vec parameter.
#[tool]
fn nested_vec_tool(matrix: Vec<Vec<i32>>) -> String {
    let rows: Vec<String> = matrix
        .iter()
        .map(|row| {
            row.iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(",")
        })
        .collect();
    rows.join("; ")
}

#[test]
fn tool_nested_vec_param_schema() {
    let handler = NestedVecTool;
    let def = handler.definition();
    let props = def.input_schema["properties"].as_object().unwrap();
    assert_eq!(props["matrix"]["type"], "array");
    assert_eq!(props["matrix"]["items"]["type"], "array");
    assert_eq!(props["matrix"]["items"]["items"]["type"], "integer");
}

#[test]
fn tool_nested_vec_param_call() {
    let handler = NestedVecTool;
    let ctx = test_ctx();
    let result = handler
        .call(&ctx, json!({"matrix": [[1, 2], [3, 4]]}))
        .unwrap();
    match &result[0] {
        Content::Text { text } => assert_eq!(text, "1,2; 3,4"),
        _ => panic!("Expected Text content"),
    }
}

// --- Tool with multiple optional parameters ---

/// Tool with all optional parameters.
#[tool]
fn all_optional_tool(a: Option<String>, b: Option<i32>, c: Option<bool>) -> String {
    let a_str = a.unwrap_or_else(|| "none".to_string());
    let b_str = b.map(|n| n.to_string()).unwrap_or_else(|| "none".to_string());
    let c_str = c.map(|b| b.to_string()).unwrap_or_else(|| "none".to_string());
    format!("a={a_str}, b={b_str}, c={c_str}")
}

#[test]
fn tool_all_optional_none_required() {
    let handler = AllOptionalTool;
    let def = handler.definition();
    let required = def.input_schema["required"].as_array().unwrap();
    assert!(required.is_empty());
}

#[test]
fn tool_all_optional_call_empty() {
    let handler = AllOptionalTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({})).unwrap();
    match &result[0] {
        Content::Text { text } => assert_eq!(text, "a=none, b=none, c=none"),
        _ => panic!("Expected Text content"),
    }
}

#[test]
fn tool_all_optional_call_partial() {
    let handler = AllOptionalTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"b": 42})).unwrap();
    match &result[0] {
        Content::Text { text } => assert_eq!(text, "a=none, b=42, c=none"),
        _ => panic!("Expected Text content"),
    }
}

#[test]
fn tool_all_optional_call_full() {
    let handler = AllOptionalTool;
    let ctx = test_ctx();
    let result = handler
        .call(&ctx, json!({"a": "hello", "b": 42, "c": true}))
        .unwrap();
    match &result[0] {
        Content::Text { text } => assert_eq!(text, "a=hello, b=42, c=true"),
        _ => panic!("Expected Text content"),
    }
}

// --- Tool returning unit ---

/// Tool that returns nothing.
#[tool]
fn unit_tool() {}

#[test]
fn tool_unit_return_empty_content() {
    let handler = UnitTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({})).unwrap();
    assert!(result.is_empty());
}

// --- Async tool with Result return ---

/// Async tool returning Result.
#[tool]
async fn async_fallible_tool(succeed: bool) -> McpResult<String> {
    if succeed {
        Ok("async success".to_string())
    } else {
        Err(fastmcp::McpError::internal_error("async failed"))
    }
}

#[test]
fn async_fallible_tool_ok() {
    let handler = AsyncFallibleTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"succeed": true})).unwrap();
    match &result[0] {
        Content::Text { text } => assert_eq!(text, "async success"),
        _ => panic!("Expected Text content"),
    }
}

#[test]
fn async_fallible_tool_err() {
    let handler = AsyncFallibleTool;
    let ctx = test_ctx();
    let result = handler.call(&ctx, json!({"succeed": false}));
    assert!(result.is_err());
}

// ============================================================================
// #[resource] expansion tests
// ============================================================================

/// Application configuration.
#[resource(uri = "config://app")]
fn app_config() -> String {
    r#"{"key": "value"}"#.to_string()
}

#[test]
fn resource_definition_uri() {
    let handler = AppConfigResource;
    let def = handler.definition();
    assert_eq!(def.uri, "config://app");
}

#[test]
fn resource_definition_name_from_fn() {
    let handler = AppConfigResource;
    let def = handler.definition();
    assert_eq!(def.name, "app_config");
}

#[test]
fn resource_definition_description_from_doc_comment() {
    let handler = AppConfigResource;
    let def = handler.definition();
    assert_eq!(
        def.description,
        Some("Application configuration.".to_string())
    );
}

#[test]
fn resource_definition_default_mime_type() {
    let handler = AppConfigResource;
    let def = handler.definition();
    assert_eq!(def.mime_type, Some("text/plain".to_string()));
}

#[test]
fn resource_read_returns_content() {
    let handler = AppConfigResource;
    let ctx = test_ctx();
    let result = handler.read(&ctx).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].text, Some(r#"{"key": "value"}"#.to_string()));
    assert_eq!(result[0].uri, "config://app");
    assert_eq!(result[0].mime_type, Some("text/plain".to_string()));
}

#[test]
fn resource_no_template_for_static_uri() {
    let handler = AppConfigResource;
    assert!(handler.template().is_none());
}

// --- Resource with custom attributes ---

/// Database schema info.
#[resource(
    uri = "db://schema",
    name = "db_schema",
    description = "Database schema",
    mime_type = "application/json"
)]
fn schema_resource() -> String {
    r#"{"tables": []}"#.to_string()
}

#[test]
fn resource_custom_name() {
    let handler = SchemaResourceResource;
    let def = handler.definition();
    assert_eq!(def.name, "db_schema");
}

#[test]
fn resource_custom_description() {
    let handler = SchemaResourceResource;
    let def = handler.definition();
    assert_eq!(def.description, Some("Database schema".to_string()));
}

#[test]
fn resource_custom_mime_type() {
    let handler = SchemaResourceResource;
    let def = handler.definition();
    assert_eq!(def.mime_type, Some("application/json".to_string()));
}

#[test]
fn resource_custom_mime_in_content() {
    let handler = SchemaResourceResource;
    let ctx = test_ctx();
    let result = handler.read(&ctx).unwrap();
    assert_eq!(result[0].mime_type, Some("application/json".to_string()));
}

// --- Resource with URI template ---

/// A file resource.
#[resource(uri = "file://{path}")]
fn file_resource(path: String) -> String {
    format!("contents of {path}")
}

#[test]
fn template_resource_has_template() {
    let handler = FileResourceResource;
    let template = handler.template().expect("should have template");
    assert_eq!(template.uri_template, "file://{path}");
}

#[test]
fn template_resource_read_with_uri() {
    let handler = FileResourceResource;
    let ctx = test_ctx();
    let mut params = HashMap::new();
    params.insert("path".to_string(), "readme.md".to_string());
    let result = handler
        .read_with_uri(&ctx, "file://readme.md", &params)
        .unwrap();
    assert_eq!(result[0].text, Some("contents of readme.md".to_string()));
    assert_eq!(result[0].uri, "file://readme.md");
}

// --- Resource with context ---

/// Resource using context.
#[resource(uri = "ctx://info")]
fn ctx_resource(ctx: &McpContext) -> String {
    format!("request_id={}", ctx.request_id())
}

#[test]
fn resource_with_context_read() {
    let handler = CtxResourceResource;
    let ctx = test_ctx();
    let result = handler.read(&ctx).unwrap();
    assert_eq!(result[0].text, Some("request_id=1".to_string()));
}

// --- Async resource ---

/// Async resource.
#[resource(uri = "async://data")]
async fn async_resource() -> String {
    "async data".to_string()
}

#[test]
fn async_resource_definition() {
    let handler = AsyncResourceResource;
    let def = handler.definition();
    assert_eq!(def.uri, "async://data");
    assert_eq!(def.name, "async_resource");
}

#[test]
fn async_resource_read() {
    let handler = AsyncResourceResource;
    let ctx = test_ctx();
    let result = handler.read(&ctx).unwrap();
    assert_eq!(result[0].text, Some("async data".to_string()));
}

// --- Resource with timeout ---

/// Timed resource.
#[resource(uri = "timed://data", timeout = "5s")]
fn timed_resource() -> String {
    "timed".to_string()
}

#[test]
fn resource_timeout() {
    let handler = TimedResourceResource;
    assert_eq!(handler.timeout(), Some(std::time::Duration::from_secs(5)));
}

// --- Resource returning Result ---

/// Fallible resource.
#[resource(uri = "fallible://data")]
fn fallible_resource() -> McpResult<String> {
    Ok("ok".to_string())
}

#[test]
fn resource_result_ok() {
    let handler = FallibleResourceResource;
    let ctx = test_ctx();
    let result = handler.read(&ctx).unwrap();
    assert_eq!(result[0].text, Some("ok".to_string()));
}

// --- Resource default trait methods ---

#[test]
fn resource_default_icon_is_none() {
    let handler = AppConfigResource;
    assert!(handler.icon().is_none());
}

#[test]
fn resource_default_version_is_none() {
    let handler = AppConfigResource;
    assert!(handler.version().is_none());
}

#[test]
fn resource_default_tags_are_empty() {
    let handler = AppConfigResource;
    assert!(handler.tags().is_empty());
}

#[test]
fn resource_default_timeout_is_none() {
    let handler = AppConfigResource;
    assert!(handler.timeout().is_none());
}

// ============================================================================
// #[prompt] expansion tests
// ============================================================================

/// A greeting prompt.
#[prompt]
fn greeting_prompt(name: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!("Greet {name}"),
        },
    }]
}

#[test]
fn prompt_definition_name_from_fn() {
    let handler = GreetingPromptPrompt;
    let def = handler.definition();
    assert_eq!(def.name, "greeting_prompt");
}

#[test]
fn prompt_definition_description_from_doc() {
    let handler = GreetingPromptPrompt;
    let def = handler.definition();
    assert_eq!(def.description, Some("A greeting prompt.".to_string()));
}

#[test]
fn prompt_definition_arguments() {
    let handler = GreetingPromptPrompt;
    let def = handler.definition();
    assert_eq!(def.arguments.len(), 1);
    assert_eq!(def.arguments[0].name, "name");
    assert!(def.arguments[0].required);
    // No doc comment on parameter, so description is None
    assert!(def.arguments[0].description.is_none());
}

#[test]
fn prompt_get_returns_messages() {
    let handler = GreetingPromptPrompt;
    let ctx = test_ctx();
    let mut args = HashMap::new();
    args.insert("name".to_string(), "Alice".to_string());
    let result = handler.get(&ctx, args).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].role, Role::User);
    match &result[0].content {
        Content::Text { text } => assert_eq!(text, "Greet Alice"),
        _ => panic!("Expected Text content"),
    }
}

// --- Prompt with optional arguments ---

/// Review prompt with options.
#[prompt]
fn review_prompt(code: String, focus: Option<String>) -> Vec<PromptMessage> {
    let text = match focus {
        Some(f) => format!("Review (focus: {f}):\n{code}"),
        None => format!("Review:\n{code}"),
    };
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text { text },
    }]
}

#[test]
fn prompt_optional_arg_not_required() {
    let handler = ReviewPromptPrompt;
    let def = handler.definition();
    assert_eq!(def.arguments.len(), 2);

    let code_arg = &def.arguments[0];
    assert_eq!(code_arg.name, "code");
    assert!(code_arg.required);

    let focus_arg = &def.arguments[1];
    assert_eq!(focus_arg.name, "focus");
    assert!(!focus_arg.required);
}

#[test]
fn prompt_get_without_optional() {
    let handler = ReviewPromptPrompt;
    let ctx = test_ctx();
    let mut args = HashMap::new();
    args.insert("code".to_string(), "fn main() {}".to_string());
    let result = handler.get(&ctx, args).unwrap();
    match &result[0].content {
        Content::Text { text } => assert!(text.starts_with("Review:\n")),
        _ => panic!("Expected Text content"),
    }
}

#[test]
fn prompt_get_with_optional() {
    let handler = ReviewPromptPrompt;
    let ctx = test_ctx();
    let mut args = HashMap::new();
    args.insert("code".to_string(), "fn main() {}".to_string());
    args.insert("focus".to_string(), "security".to_string());
    let result = handler.get(&ctx, args).unwrap();
    match &result[0].content {
        Content::Text { text } => assert!(text.starts_with("Review (focus: security)")),
        _ => panic!("Expected Text content"),
    }
}

#[test]
fn prompt_missing_required_arg_errors() {
    let handler = ReviewPromptPrompt;
    let ctx = test_ctx();
    let args = HashMap::new(); // No args provided
    let result = handler.get(&ctx, args);
    assert!(result.is_err());
}

// --- Prompt with name override ---

#[prompt(name = "my_prompt")]
fn prompt_custom_name() -> Vec<PromptMessage> {
    vec![]
}

#[test]
fn prompt_name_override() {
    let handler = PromptCustomNamePrompt;
    let def = handler.definition();
    assert_eq!(def.name, "my_prompt");
}

// --- Prompt with description override ---

/// Doc comment ignored.
#[prompt(description = "Explicit prompt description")]
fn prompt_desc_override() -> Vec<PromptMessage> {
    vec![]
}

#[test]
fn prompt_description_override() {
    let handler = PromptDescOverridePrompt;
    let def = handler.definition();
    assert_eq!(
        def.description,
        Some("Explicit prompt description".to_string())
    );
}

// --- Prompt with timeout ---

/// Timed prompt.
#[prompt(timeout = "10s")]
fn timed_prompt(text: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text { text },
    }]
}

#[test]
fn prompt_timeout() {
    let handler = TimedPromptPrompt;
    assert_eq!(handler.timeout(), Some(std::time::Duration::from_secs(10)));
}

// --- Prompt with context ---

/// Prompt using context.
#[prompt]
fn ctx_prompt(ctx: &McpContext, msg: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text {
            text: format!("req:{} msg:{msg}", ctx.request_id()),
        },
    }]
}

#[test]
fn prompt_with_context_call() {
    let handler = CtxPromptPrompt;
    let ctx = test_ctx();
    let mut args = HashMap::new();
    args.insert("msg".to_string(), "hello".to_string());
    let result = handler.get(&ctx, args).unwrap();
    match &result[0].content {
        Content::Text { text } => assert_eq!(text, "req:1 msg:hello"),
        _ => panic!("Expected Text content"),
    }
}

#[test]
fn prompt_with_context_schema_excludes_ctx() {
    let handler = CtxPromptPrompt;
    let def = handler.definition();
    // Only msg should be an argument, not ctx
    assert_eq!(def.arguments.len(), 1);
    assert_eq!(def.arguments[0].name, "msg");
}

// --- Async prompt ---

/// An async prompt.
#[prompt]
async fn async_prompt(text: String) -> Vec<PromptMessage> {
    vec![PromptMessage {
        role: Role::User,
        content: Content::Text { text },
    }]
}

#[test]
fn async_prompt_definition() {
    let handler = AsyncPromptPrompt;
    let def = handler.definition();
    assert_eq!(def.name, "async_prompt");
}

#[test]
fn async_prompt_get() {
    let handler = AsyncPromptPrompt;
    let ctx = test_ctx();
    let mut args = HashMap::new();
    args.insert("text".to_string(), "async hello".to_string());
    let result = handler.get(&ctx, args).unwrap();
    match &result[0].content {
        Content::Text { text } => assert_eq!(text, "async hello"),
        _ => panic!("Expected Text content"),
    }
}

// --- Prompt default trait methods ---

#[test]
fn prompt_default_icon_is_none() {
    let handler = GreetingPromptPrompt;
    assert!(handler.icon().is_none());
}

#[test]
fn prompt_default_version_is_none() {
    let handler = GreetingPromptPrompt;
    assert!(handler.version().is_none());
}

#[test]
fn prompt_default_tags_are_empty() {
    let handler = GreetingPromptPrompt;
    assert!(handler.tags().is_empty());
}

#[test]
fn prompt_default_timeout_is_none() {
    let handler = GreetingPromptPrompt;
    assert!(handler.timeout().is_none());
}

// ============================================================================
// #[derive(JsonSchema)] expansion tests
// ============================================================================

/// A person record.
#[derive(JsonSchema)]
struct Person {
    /// The person's name
    name: String,
    /// Optional age
    age: Option<u32>,
    /// List of tags
    tags: Vec<String>,
}

#[test]
fn json_schema_struct_type_is_object() {
    let schema = Person::json_schema();
    assert_eq!(schema["type"], "object");
}

#[test]
fn json_schema_struct_properties() {
    let schema = Person::json_schema();
    let props = schema["properties"].as_object().unwrap();
    assert!(props.contains_key("name"));
    assert!(props.contains_key("age"));
    assert!(props.contains_key("tags"));
}

#[test]
fn json_schema_struct_field_types() {
    let schema = Person::json_schema();
    let props = schema["properties"].as_object().unwrap();
    assert_eq!(props["name"]["type"], "string");
    assert_eq!(props["age"]["type"], "integer");
    assert_eq!(props["tags"]["type"], "array");
    assert_eq!(props["tags"]["items"]["type"], "string");
}

#[test]
fn json_schema_struct_required_fields() {
    let schema = Person::json_schema();
    let required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    // name and tags are required, age is Option so not required
    assert!(required.contains(&"name"));
    assert!(required.contains(&"tags"));
    assert!(!required.contains(&"age"));
}

#[test]
fn json_schema_struct_field_descriptions() {
    let schema = Person::json_schema();
    let props = schema["properties"].as_object().unwrap();
    assert_eq!(props["name"]["description"], "The person's name");
    assert_eq!(props["age"]["description"], "Optional age");
    assert_eq!(props["tags"]["description"], "List of tags");
}

#[test]
fn json_schema_struct_description() {
    let schema = Person::json_schema();
    assert_eq!(schema["description"], "A person record.");
}

// --- Schema with numeric types ---

#[derive(JsonSchema)]
struct NumberTypes {
    integer_val: i64,
    float_val: f64,
    bool_val: bool,
    unsigned_val: u32,
}

#[test]
fn json_schema_numeric_types() {
    let schema = NumberTypes::json_schema();
    let props = schema["properties"].as_object().unwrap();
    assert_eq!(props["integer_val"]["type"], "integer");
    assert_eq!(props["float_val"]["type"], "number");
    assert_eq!(props["bool_val"]["type"], "boolean");
    assert_eq!(props["unsigned_val"]["type"], "integer");
}

// --- Schema with nested Vec/Option ---

#[derive(JsonSchema)]
struct Nested {
    items: Vec<i32>,
    optional_items: Option<Vec<String>>,
}

#[test]
fn json_schema_nested_vec() {
    let schema = Nested::json_schema();
    let props = schema["properties"].as_object().unwrap();
    assert_eq!(props["items"]["type"], "array");
    assert_eq!(props["items"]["items"]["type"], "integer");
}

#[test]
fn json_schema_optional_vec() {
    let schema = Nested::json_schema();
    let props = schema["properties"].as_object().unwrap();
    // Option<Vec<String>> → array of strings, not required
    assert_eq!(props["optional_items"]["type"], "array");
    assert_eq!(props["optional_items"]["items"]["type"], "string");
    let required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(!required.contains(&"optional_items"));
}

// --- Schema with rename attribute ---

#[derive(JsonSchema)]
struct RenamedFields {
    #[json_schema(rename = "firstName")]
    first_name: String,
    #[json_schema(rename = "lastName")]
    last_name: String,
}

#[test]
fn json_schema_rename_attribute() {
    let schema = RenamedFields::json_schema();
    let props = schema["properties"].as_object().unwrap();
    assert!(props.contains_key("firstName"));
    assert!(props.contains_key("lastName"));
    assert!(!props.contains_key("first_name"));
    assert!(!props.contains_key("last_name"));
}

// --- Schema with skip attribute ---

#[derive(JsonSchema)]
struct SkippedFields {
    visible: String,
    #[json_schema(skip)]
    hidden: String,
}

#[test]
fn json_schema_skip_attribute() {
    let schema = SkippedFields::json_schema();
    let props = schema["properties"].as_object().unwrap();
    assert!(props.contains_key("visible"));
    assert!(!props.contains_key("hidden"));
}

// --- Enum schema ---

/// Color options.
#[derive(JsonSchema)]
enum Color {
    Red,
    Green,
    Blue,
}

#[test]
fn json_schema_unit_enum() {
    let schema = Color::json_schema();
    assert_eq!(schema["type"], "string");
    let variants = schema["enum"].as_array().unwrap();
    assert_eq!(variants.len(), 3);
    assert!(variants.iter().any(|v| v == "Red"));
    assert!(variants.iter().any(|v| v == "Green"));
    assert!(variants.iter().any(|v| v == "Blue"));
}

#[test]
fn json_schema_unit_enum_description() {
    let schema = Color::json_schema();
    assert_eq!(schema["description"], "Color options.");
}

// --- Newtype struct schema ---

#[derive(JsonSchema)]
struct Email(String);

#[test]
fn json_schema_newtype_struct() {
    let schema = Email::json_schema();
    assert_eq!(schema["type"], "string");
}

// --- Unit struct schema ---

#[derive(JsonSchema)]
struct Marker;

#[test]
fn json_schema_unit_struct() {
    let schema = Marker::json_schema();
    assert_eq!(schema["type"], "null");
}

// --- Struct with no doc comments ---

#[derive(JsonSchema)]
struct NoDocStruct {
    field: String,
}

#[test]
fn json_schema_no_description() {
    let schema = NoDocStruct::json_schema();
    // description key should not be present
    assert!(schema.get("description").is_none());
}

// --- Struct with HashMap field ---

#[derive(JsonSchema)]
struct MapStruct {
    metadata: HashMap<String, String>,
}

#[test]
fn json_schema_hashmap_field() {
    let schema = MapStruct::json_schema();
    let props = schema["properties"].as_object().unwrap();
    assert_eq!(props["metadata"]["type"], "object");
    assert_eq!(props["metadata"]["additionalProperties"]["type"], "string");
}

// --- Empty struct ---

#[derive(JsonSchema)]
struct EmptyStruct {}

#[test]
fn json_schema_empty_struct() {
    let schema = EmptyStruct::json_schema();
    assert_eq!(schema["type"], "object");
    let props = schema["properties"].as_object().unwrap();
    assert!(props.is_empty());
}

// --- Tagged enum schema ---

#[derive(JsonSchema)]
enum Shape {
    Circle(f64),
    Rectangle(String),
    Point,
}

#[test]
fn json_schema_tagged_enum_uses_one_of() {
    let schema = Shape::json_schema();
    let one_of = schema["oneOf"].as_array().unwrap();
    assert_eq!(one_of.len(), 3);
}
