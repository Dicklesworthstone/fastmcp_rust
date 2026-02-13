//! Tool transformations for dynamic schema modification.
//!
//! This module provides the ability to transform tools dynamically, allowing:
//! - Renaming tools and their arguments
//! - Modifying descriptions
//! - Providing default values for arguments
//! - Hiding arguments from the schema (while still providing values)
//! - Wrapping tools with custom transformation functions
//!
//! # Example
//!
//! ```ignore
//! use fastmcp_server::transform::{ArgTransform, TransformedTool};
//!
//! // Original tool with cryptic argument names
//! let original_tool = my_search_tool();
//!
//! // Transform to be more LLM-friendly
//! let transformed = TransformedTool::from_tool(original_tool)
//!     .name("semantic_search")
//!     .description("Search for documents using natural language")
//!     .transform_arg("q", ArgTransform::new().name("query").description("Search query"))
//!     .transform_arg("n", ArgTransform::new().name("limit").default(10))
//!     .build();
//! ```

use std::collections::HashMap;

use fastmcp_core::{McpContext, McpOutcome, McpResult, Outcome};
use fastmcp_protocol::{Content, Tool};

use crate::handler::{BoxFuture, BoxedToolHandler, ToolHandler};

/// Sentinel value for unset optional fields.
#[derive(Debug, Clone, Copy, Default)]
pub struct NotSet;

/// Transformation rules for a single argument.
///
/// Use the builder methods to specify which aspects of the argument to transform.
/// Any field left as `None` will inherit from the original argument.
#[derive(Debug, Clone, Default)]
pub struct ArgTransform {
    /// New name for the argument.
    pub name: Option<String>,
    /// New description for the argument.
    pub description: Option<String>,
    /// Default value (as JSON) for the argument.
    pub default: Option<serde_json::Value>,
    /// Whether to hide this argument from the schema.
    /// Hidden arguments must have a default value.
    pub hide: bool,
    /// Override the required status.
    /// Only `Some(true)` is meaningful (to make optional → required).
    pub required: Option<bool>,
    /// New type annotation for the argument (as JSON Schema).
    pub type_schema: Option<serde_json::Value>,
}

impl ArgTransform {
    /// Creates a new empty argument transform.
    #[must_use]
    pub fn new() -> Self {
        <Self as Default>::default()
    }

    /// Sets the new name for this argument.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the new description for this argument.
    #[must_use]
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Sets the default value for this argument.
    #[must_use]
    pub fn default(mut self, value: impl Into<serde_json::Value>) -> Self {
        self.default = Some(value.into());
        self
    }

    /// Sets a string default value.
    #[must_use]
    pub fn default_str(self, value: impl Into<String>) -> Self {
        self.default(serde_json::Value::String(value.into()))
    }

    /// Sets an integer default value.
    #[must_use]
    pub fn default_int(self, value: i64) -> Self {
        self.default(serde_json::Value::Number(value.into()))
    }

    /// Sets a boolean default value.
    #[must_use]
    pub fn default_bool(self, value: bool) -> Self {
        self.default(serde_json::Value::Bool(value))
    }

    /// Hides this argument from the schema.
    ///
    /// Hidden arguments are not exposed to the LLM but must have a default
    /// value that will be used when the tool is called.
    #[must_use]
    pub fn hide(mut self) -> Self {
        self.hide = true;
        self
    }

    /// Makes this argument required (even if it was optional).
    #[must_use]
    pub fn required(mut self) -> Self {
        self.required = Some(true);
        self
    }

    /// Sets the JSON Schema type for this argument.
    #[must_use]
    pub fn type_schema(mut self, schema: serde_json::Value) -> Self {
        self.type_schema = Some(schema);
        self
    }

    /// Creates a transform that drops (hides) this argument with a default value.
    #[must_use]
    pub fn drop_with_default(value: impl Into<serde_json::Value>) -> Self {
        Self::new().default(value).hide()
    }
}

/// A transformed tool that wraps another tool and applies transformations.
///
/// Transformations can include:
/// - Renaming the tool
/// - Modifying the description
/// - Transforming arguments (rename, add defaults, hide, etc.)
/// - Applying a custom transformation function
pub struct TransformedTool {
    /// The underlying tool being transformed.
    parent: BoxedToolHandler,
    /// Transformed tool definition.
    definition: Tool,
    /// Argument transformations (keyed by original argument name).
    arg_transforms: HashMap<String, ArgTransform>,
    /// Mapping from new arg names to original arg names.
    name_mapping: HashMap<String, String>,
}

impl TransformedTool {
    /// Creates a builder for transforming an existing tool.
    pub fn from_tool<H: ToolHandler + 'static>(tool: H) -> TransformedToolBuilder {
        TransformedToolBuilder::new(Box::new(tool))
    }

    /// Creates a builder from a boxed tool handler.
    pub fn from_boxed(tool: BoxedToolHandler) -> TransformedToolBuilder {
        TransformedToolBuilder::new(tool)
    }

    /// Returns the parent tool's definition.
    #[must_use]
    pub fn parent_definition(&self) -> Tool {
        self.parent.definition()
    }

    /// Returns the argument transforms.
    #[must_use]
    pub fn arg_transforms(&self) -> &HashMap<String, ArgTransform> {
        &self.arg_transforms
    }

    /// Transforms the incoming arguments (with new names) to the original format.
    fn transform_arguments(&self, arguments: serde_json::Value) -> McpResult<serde_json::Value> {
        let mut args = match arguments {
            serde_json::Value::Object(map) => map,
            serde_json::Value::Null => serde_json::Map::new(),
            _ => {
                return Err(fastmcp_core::McpError::invalid_params(
                    "Arguments must be an object",
                ));
            }
        };

        let mut result = serde_json::Map::new();

        // Apply transformations
        for (original_name, transform) in &self.arg_transforms {
            let new_name = transform.name.as_ref().unwrap_or(original_name);

            // Check if we have a value for this argument (using new name)
            if let Some(value) = args.remove(new_name) {
                // Use the provided value with original name
                result.insert(original_name.clone(), value);
            } else if let Some(default) = &transform.default {
                // Use the default value
                result.insert(original_name.clone(), default.clone());
            } else if transform.hide {
                // Hidden argument without default - error
                return Err(fastmcp_core::McpError::invalid_params(format!(
                    "Hidden argument '{}' requires a default value",
                    original_name
                )));
            }
            // Otherwise, don't include (let the parent tool handle missing args)
        }

        // Pass through any remaining arguments that weren't transformed
        for (key, value) in args {
            // Check if this key maps back to an original name
            if let Some(original) = self.name_mapping.get(&key) {
                result.insert(original.clone(), value);
            } else {
                result.insert(key, value);
            }
        }

        Ok(serde_json::Value::Object(result))
    }
}

impl std::fmt::Debug for TransformedTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransformedTool")
            .field("definition", &self.definition)
            .field("arg_transforms", &self.arg_transforms)
            .finish_non_exhaustive()
    }
}

impl ToolHandler for TransformedTool {
    fn definition(&self) -> Tool {
        self.definition.clone()
    }

    fn call(&self, ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
        let transformed_args = self.transform_arguments(arguments)?;
        self.parent.call(ctx, transformed_args)
    }

    fn call_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        arguments: serde_json::Value,
    ) -> BoxFuture<'a, McpOutcome<Vec<Content>>> {
        Box::pin(async move {
            let transformed_args = match self.transform_arguments(arguments) {
                Ok(args) => args,
                Err(e) => return Outcome::Err(e),
            };
            self.parent.call_async(ctx, transformed_args).await
        })
    }
}

/// Builder for creating transformed tools.
pub struct TransformedToolBuilder {
    parent: BoxedToolHandler,
    name: Option<String>,
    description: Option<String>,
    arg_transforms: HashMap<String, ArgTransform>,
}

impl TransformedToolBuilder {
    /// Creates a new builder for the given parent tool.
    pub fn new(parent: BoxedToolHandler) -> Self {
        Self {
            parent,
            name: None,
            description: None,
            arg_transforms: HashMap::new(),
        }
    }

    /// Sets the new name for the transformed tool.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the new description for the transformed tool.
    #[must_use]
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Adds a transformation for the given argument.
    ///
    /// The `original_name` is the name of the argument in the parent tool.
    #[must_use]
    pub fn transform_arg(
        mut self,
        original_name: impl Into<String>,
        transform: ArgTransform,
    ) -> Self {
        self.arg_transforms.insert(original_name.into(), transform);
        self
    }

    /// Renames an argument.
    #[must_use]
    pub fn rename_arg(self, original_name: impl Into<String>, new_name: impl Into<String>) -> Self {
        self.transform_arg(original_name, ArgTransform::new().name(new_name))
    }

    /// Hides an argument and provides a default value.
    #[must_use]
    pub fn hide_arg(
        self,
        original_name: impl Into<String>,
        default: impl Into<serde_json::Value>,
    ) -> Self {
        self.transform_arg(original_name, ArgTransform::drop_with_default(default))
    }

    /// Builds the transformed tool.
    #[must_use]
    pub fn build(self) -> TransformedTool {
        let parent_def = self.parent.definition();

        // Build name mapping (new name -> original name)
        let mut name_mapping = HashMap::new();
        for (original, transform) in &self.arg_transforms {
            if let Some(new_name) = &transform.name {
                name_mapping.insert(new_name.clone(), original.clone());
            }
        }

        // Transform the tool definition
        let definition = self.build_definition(&parent_def);

        TransformedTool {
            parent: self.parent,
            definition,
            arg_transforms: self.arg_transforms,
            name_mapping,
        }
    }

    /// Builds the transformed tool definition.
    fn build_definition(&self, parent: &Tool) -> Tool {
        let name = self.name.clone().unwrap_or_else(|| parent.name.clone());
        let description = self
            .description
            .clone()
            .or_else(|| parent.description.clone());

        // Transform the input schema
        let input_schema = self.transform_schema(&parent.input_schema);

        Tool {
            name,
            description,
            input_schema,
            output_schema: parent.output_schema.clone(),
            icon: parent.icon.clone(),
            version: parent.version.clone(),
            tags: parent.tags.clone(),
            annotations: parent.annotations.clone(),
        }
    }

    /// Transforms the input schema based on argument transforms.
    fn transform_schema(&self, original: &serde_json::Value) -> serde_json::Value {
        let mut schema = original.clone();

        let Some(obj) = schema.as_object_mut() else {
            return schema;
        };

        // Ensure properties and required exist
        // Note: Using String::from() with static str is optimized by the compiler
        // but explicit owned strings are required for serde_json::Map keys
        if !obj.contains_key("properties") {
            obj.insert(String::from("properties"), serde_json::json!({}));
        }
        if !obj.contains_key("required") {
            obj.insert(String::from("required"), serde_json::json!([]));
        }

        // Track changes to apply
        // Pre-allocate based on transform count to avoid reallocations
        let capacity = self.arg_transforms.len();
        let mut props_to_remove: Vec<String> = Vec::with_capacity(capacity);
        let mut props_to_add: Vec<(String, serde_json::Value)> = Vec::with_capacity(capacity);
        let mut required_renames: Vec<(String, String)> = Vec::with_capacity(capacity);
        let mut required_removes: Vec<String> = Vec::with_capacity(capacity);

        // First pass: collect property transformations
        {
            let props = obj["properties"].as_object().unwrap();

            for (original_name, transform) in &self.arg_transforms {
                if transform.hide {
                    props_to_remove.push(original_name.clone());
                    required_removes.push(original_name.clone());
                    continue;
                }

                if let Some(prop_schema) = props.get(original_name).cloned() {
                    let new_name = transform.name.as_ref().unwrap_or(original_name);
                    let mut new_schema = prop_schema;

                    // Apply description override
                    if let (Some(desc), Some(schema_obj)) =
                        (&transform.description, new_schema.as_object_mut())
                    {
                        schema_obj.insert(String::from("description"), serde_json::json!(desc));
                    }

                    // Apply type override
                    if let Some(type_schema) = &transform.type_schema {
                        new_schema = type_schema.clone();
                    }

                    // Apply default override
                    if let (Some(default), Some(schema_obj)) =
                        (&transform.default, new_schema.as_object_mut())
                    {
                        schema_obj.insert(String::from("default"), default.clone());
                    }

                    if new_name != original_name {
                        props_to_remove.push(original_name.clone());
                        props_to_add.push((new_name.clone(), new_schema));
                        required_renames.push((original_name.clone(), new_name.clone()));
                    } else {
                        // Update in place
                        props_to_add.push((original_name.clone(), new_schema));
                    }
                }
            }
        }

        // Apply property changes
        if let Some(props) = obj.get_mut("properties").and_then(|p| p.as_object_mut()) {
            for name in &props_to_remove {
                props.remove(name);
            }
            for (name, prop_schema) in props_to_add {
                props.insert(name, prop_schema);
            }
        }

        // Apply required array changes
        if let Some(required) = obj.get_mut("required").and_then(|r| r.as_array_mut()) {
            // Handle renames
            for (old_name, new_name) in required_renames {
                if let Some(idx) = required.iter().position(|v| v.as_str() == Some(&old_name)) {
                    required[idx] = serde_json::json!(new_name);
                }
            }
            // Handle removes - compare &str directly to avoid allocation
            required.retain(|v| {
                v.as_str()
                    .is_none_or(|s| !required_removes.iter().any(|r| r == s))
            });
        }

        schema
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::Content;

    struct SearchToolFixture {
        name: String,
        description: Option<String>,
        schema: serde_json::Value,
    }

    impl SearchToolFixture {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                description: Some("Search tool".to_string()),
                schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "q": {
                            "type": "string",
                            "description": "Query"
                        },
                        "n": {
                            "type": "integer",
                            "description": "Limit"
                        }
                    },
                    "required": ["q"]
                }),
            }
        }
    }

    impl ToolHandler for SearchToolFixture {
        fn definition(&self) -> Tool {
            Tool {
                name: self.name.clone(),
                description: self.description.clone(),
                input_schema: self.schema.clone(),
                output_schema: None,
                icon: None,
                version: None,
                tags: vec![],
                annotations: None,
            }
        }

        fn call(&self, _ctx: &McpContext, arguments: serde_json::Value) -> McpResult<Vec<Content>> {
            Ok(vec![Content::Text {
                text: format!("Search called with: {}", arguments),
            }])
        }
    }

    #[test]
    fn test_rename_tool() {
        let tool = SearchToolFixture::new("search");
        let transformed = TransformedTool::from_tool(tool)
            .name("semantic_search")
            .description("Search semantically")
            .build();

        let def = transformed.definition();
        assert_eq!(def.name, "semantic_search");
        assert_eq!(def.description, Some("Search semantically".to_string()));
    }

    #[test]
    fn test_rename_arg() {
        let tool = SearchToolFixture::new("search");
        let transformed = TransformedTool::from_tool(tool)
            .rename_arg("q", "query")
            .build();

        let def = transformed.definition();
        let props = def.input_schema["properties"].as_object().unwrap();

        // Original name should be gone
        assert!(!props.contains_key("q"));
        // New name should exist
        assert!(props.contains_key("query"));
    }

    #[test]
    fn test_hide_arg() {
        let tool = SearchToolFixture::new("search");
        let transformed = TransformedTool::from_tool(tool).hide_arg("n", 10).build();

        let def = transformed.definition();
        let props = def.input_schema["properties"].as_object().unwrap();

        // Hidden arg should not be in schema
        assert!(!props.contains_key("n"));
        // But q should still be there
        assert!(props.contains_key("q"));
    }

    #[test]
    fn test_transform_arguments() {
        let tool = SearchToolFixture::new("search");
        let transformed = TransformedTool::from_tool(tool)
            .rename_arg("q", "query")
            .hide_arg("n", 10)
            .build();

        // Input uses new names
        let input = serde_json::json!({
            "query": "hello world"
        });

        // Transform should map back to original names and add defaults
        let result = transformed.transform_arguments(input).unwrap();
        let obj = result.as_object().unwrap();

        assert_eq!(obj.get("q").unwrap(), "hello world");
        assert_eq!(obj.get("n").unwrap(), 10);
    }

    #[test]
    fn test_arg_transform_builder() {
        let transform = ArgTransform::new()
            .name("search_query")
            .description("The search query string")
            .default_str("*")
            .required();

        assert_eq!(transform.name, Some("search_query".to_string()));
        assert_eq!(
            transform.description,
            Some("The search query string".to_string())
        );
        assert_eq!(transform.default, Some(serde_json::json!("*")));
        assert_eq!(transform.required, Some(true));
        assert!(!transform.hide);
    }

    // ── ArgTransform type helpers ─────────────────────────────────────

    #[test]
    fn arg_transform_default_int() {
        let t = ArgTransform::new().default_int(42);
        assert_eq!(t.default, Some(serde_json::json!(42)));
    }

    #[test]
    fn arg_transform_default_bool() {
        let t = ArgTransform::new().default_bool(true);
        assert_eq!(t.default, Some(serde_json::json!(true)));
    }

    #[test]
    fn arg_transform_type_schema() {
        let schema = serde_json::json!({"type": "number", "minimum": 0});
        let t = ArgTransform::new().type_schema(schema.clone());
        assert_eq!(t.type_schema, Some(schema));
    }

    #[test]
    fn arg_transform_drop_with_default() {
        let t = ArgTransform::drop_with_default("auto");
        assert!(t.hide);
        assert_eq!(t.default, Some(serde_json::json!("auto")));
    }

    #[test]
    fn arg_transform_hide_sets_flag() {
        let t = ArgTransform::new().hide();
        assert!(t.hide);
    }

    #[test]
    fn arg_transform_debug() {
        let t = ArgTransform::new().name("x");
        let debug = format!("{:?}", t);
        assert!(debug.contains("ArgTransform"));
    }

    #[test]
    fn arg_transform_clone() {
        let t = ArgTransform::new().name("x").default_int(5);
        let c = t.clone();
        assert_eq!(c.name, Some("x".to_string()));
        assert_eq!(c.default, Some(serde_json::json!(5)));
    }

    // ── TransformedTool accessors ─────────────────────────────────────

    #[test]
    fn transformed_tool_parent_definition() {
        let tool = SearchToolFixture::new("original");
        let transformed = TransformedTool::from_tool(tool).name("renamed").build();
        let parent_def = transformed.parent_definition();
        assert_eq!(parent_def.name, "original");
    }

    #[test]
    fn transformed_tool_arg_transforms_accessor() {
        let tool = SearchToolFixture::new("search");
        let transformed = TransformedTool::from_tool(tool)
            .rename_arg("q", "query")
            .build();
        let transforms = transformed.arg_transforms();
        assert!(transforms.contains_key("q"));
    }

    #[test]
    fn transformed_tool_debug_format() {
        let tool = SearchToolFixture::new("search");
        let transformed = TransformedTool::from_tool(tool).name("dbg_tool").build();
        let debug = format!("{:?}", transformed);
        assert!(debug.contains("TransformedTool"));
        assert!(debug.contains("dbg_tool"));
    }

    #[test]
    fn transformed_tool_from_boxed() {
        let tool = Box::new(SearchToolFixture::new("boxed")) as BoxedToolHandler;
        let transformed = TransformedTool::from_boxed(tool).name("unboxed").build();
        assert_eq!(transformed.definition().name, "unboxed");
    }

    // ── transform_arguments edge cases ───────────────────────────────

    #[test]
    fn transform_arguments_null_treated_as_empty() {
        let tool = SearchToolFixture::new("search");
        let transformed = TransformedTool::from_tool(tool).hide_arg("n", 10).build();

        let result = transformed
            .transform_arguments(serde_json::Value::Null)
            .unwrap();
        let obj = result.as_object().unwrap();
        assert_eq!(obj.get("n").unwrap(), 10);
    }

    #[test]
    fn transform_arguments_non_object_returns_error() {
        let tool = SearchToolFixture::new("search");
        let transformed = TransformedTool::from_tool(tool).build();

        let result = transformed.transform_arguments(serde_json::json!("bad"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("Arguments must be an object"));
    }

    #[test]
    fn transform_arguments_passthrough_unknown_args() {
        let tool = SearchToolFixture::new("search");
        let transformed = TransformedTool::from_tool(tool)
            .rename_arg("q", "query")
            .build();

        let input = serde_json::json!({
            "query": "test",
            "extra": "value"
        });
        let result = transformed.transform_arguments(input).unwrap();
        let obj = result.as_object().unwrap();
        assert_eq!(obj.get("q").unwrap(), "test");
        assert_eq!(obj.get("extra").unwrap(), "value");
    }

    #[test]
    fn transform_arguments_hidden_without_default_errors() {
        let tool = SearchToolFixture::new("search");
        let transformed = TransformedTool::from_tool(tool)
            .transform_arg("q", ArgTransform::new().hide())
            .build();

        let result = transformed.transform_arguments(serde_json::json!({}));
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .message
                .contains("Hidden argument 'q' requires a default value")
        );
    }

    // ── ToolHandler impl ─────────────────────────────────────────────

    #[test]
    fn transformed_tool_call_delegates_with_mapped_args() {
        let tool = SearchToolFixture::new("search");
        let transformed = TransformedTool::from_tool(tool)
            .rename_arg("q", "query")
            .build();

        let cx = asupersync::Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let result = transformed
            .call(&ctx, serde_json::json!({"query": "hello"}))
            .unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn transformed_tool_call_with_invalid_args_returns_error() {
        let tool = SearchToolFixture::new("search");
        let transformed = TransformedTool::from_tool(tool).build();

        let cx = asupersync::Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let result = transformed.call(&ctx, serde_json::json!("string_not_object"));
        assert!(result.is_err());
    }

    // ── Builder keeps parent properties ──────────────────────────────

    #[test]
    fn builder_no_name_keeps_parent_name() {
        let tool = SearchToolFixture::new("original_name");
        let transformed = TransformedTool::from_tool(tool).build();
        assert_eq!(transformed.definition().name, "original_name");
    }

    #[test]
    fn builder_no_description_keeps_parent_description() {
        let tool = SearchToolFixture::new("s");
        let transformed = TransformedTool::from_tool(tool).build();
        assert_eq!(
            transformed.definition().description,
            Some("Search tool".to_string())
        );
    }

    // ── Schema transform: description override ───────────────────────

    #[test]
    fn transform_schema_applies_description_override() {
        let tool = SearchToolFixture::new("s");
        let transformed = TransformedTool::from_tool(tool)
            .transform_arg("q", ArgTransform::new().description("Full search query"))
            .build();

        let def = transformed.definition();
        let q_schema = &def.input_schema["properties"]["q"];
        assert_eq!(q_schema["description"], "Full search query");
    }

    // ── NotSet sentinel ──────────────────────────────────────────────

    #[test]
    fn not_set_debug() {
        let n = NotSet;
        let debug = format!("{:?}", n);
        assert!(debug.contains("NotSet"));
    }

    #[test]
    fn not_set_clone_copy() {
        let n = NotSet;
        let cloned = n.clone();
        let copied = n; // Copy
        let _ = (cloned, copied);
    }

    #[test]
    fn not_set_default() {
        let _ = NotSet;
    }

    // ── ArgTransform defaults ────────────────────────────────────────

    #[test]
    fn arg_transform_new_is_all_none() {
        let t = ArgTransform::new();
        assert!(t.name.is_none());
        assert!(t.description.is_none());
        assert!(t.default.is_none());
        assert!(!t.hide);
        assert!(t.required.is_none());
        assert!(t.type_schema.is_none());
    }

    #[test]
    fn arg_transform_default_trait() {
        let t = <ArgTransform as Default>::default();
        assert!(t.name.is_none());
        assert!(!t.hide);
    }

    // ── Schema transform: type override ──────────────────────────────

    #[test]
    fn transform_schema_applies_type_override() {
        let tool = SearchToolFixture::new("s");
        let transformed = TransformedTool::from_tool(tool)
            .transform_arg(
                "q",
                ArgTransform::new().type_schema(serde_json::json!({"type": "number"})),
            )
            .build();

        let def = transformed.definition();
        let q_schema = &def.input_schema["properties"]["q"];
        assert_eq!(q_schema["type"], "number");
    }

    // ── Schema transform: default value ──────────────────────────────

    #[test]
    fn transform_schema_applies_default_value() {
        let tool = SearchToolFixture::new("s");
        let transformed = TransformedTool::from_tool(tool)
            .transform_arg("n", ArgTransform::new().default_int(25))
            .build();

        let def = transformed.definition();
        let n_schema = &def.input_schema["properties"]["n"];
        assert_eq!(n_schema["default"], 25);
    }

    // ── Schema rename updates required array ─────────────────────────

    #[test]
    fn transform_schema_rename_updates_required() {
        let tool = SearchToolFixture::new("s");
        let transformed = TransformedTool::from_tool(tool)
            .rename_arg("q", "query")
            .build();

        let def = transformed.definition();
        let required = def.input_schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "query"));
        assert!(!required.iter().any(|v| v == "q"));
    }

    // ── Schema hide removes from required ────────────────────────────

    #[test]
    fn transform_schema_hide_removes_from_required() {
        // Make a tool where "q" is required, then hide it
        let tool = SearchToolFixture::new("s");
        let transformed = TransformedTool::from_tool(tool)
            .hide_arg("q", "default-query")
            .build();

        let def = transformed.definition();
        let required = def.input_schema["required"].as_array().unwrap();
        assert!(!required.iter().any(|v| v == "q"));
    }

    // ── Combined transforms ──────────────────────────────────────────

    #[test]
    fn combined_rename_description_default() {
        let tool = SearchToolFixture::new("search");
        let transformed = TransformedTool::from_tool(tool)
            .transform_arg(
                "n",
                ArgTransform::new()
                    .name("limit")
                    .description("Max results")
                    .default_int(10),
            )
            .build();

        let def = transformed.definition();
        let props = def.input_schema["properties"].as_object().unwrap();
        assert!(!props.contains_key("n"));
        let limit = props.get("limit").unwrap();
        assert_eq!(limit["description"], "Max results");
        assert_eq!(limit["default"], 10);
    }

    // ── build_definition preserves parent metadata ───────────────────

    #[test]
    fn build_definition_preserves_parent_output_schema() {
        struct ToolWithOutputSchema;
        impl ToolHandler for ToolWithOutputSchema {
            fn definition(&self) -> Tool {
                Tool {
                    name: "parent".to_string(),
                    description: None,
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: Some(serde_json::json!({"type": "string"})),
                    icon: None,
                    version: Some("2.0".to_string()),
                    tags: vec!["tag1".to_string()],
                    annotations: None,
                }
            }
            fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
                Ok(vec![])
            }
        }

        let transformed = TransformedTool::from_tool(ToolWithOutputSchema)
            .name("child")
            .build();
        let def = transformed.definition();
        assert_eq!(
            def.output_schema,
            Some(serde_json::json!({"type": "string"}))
        );
        assert_eq!(def.version, Some("2.0".to_string()));
        assert_eq!(def.tags, vec!["tag1".to_string()]);
    }

    // ── transform_schema with non-object schema ──────────────────────

    #[test]
    fn transform_schema_non_object_returned_as_is() {
        struct ArraySchemaTool;
        impl ToolHandler for ArraySchemaTool {
            fn definition(&self) -> Tool {
                Tool {
                    name: "arr".to_string(),
                    description: None,
                    input_schema: serde_json::json!("not an object"),
                    output_schema: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                    annotations: None,
                }
            }
            fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
                Ok(vec![])
            }
        }

        let transformed = TransformedTool::from_tool(ArraySchemaTool)
            .rename_arg("x", "y")
            .build();
        let def = transformed.definition();
        // Schema is returned as-is since it's not an object
        assert_eq!(def.input_schema, serde_json::json!("not an object"));
    }

    // ── Schema without properties or required ────────────────────────

    #[test]
    fn transform_schema_adds_properties_and_required_if_missing() {
        struct MinimalSchemaTool;
        impl ToolHandler for MinimalSchemaTool {
            fn definition(&self) -> Tool {
                Tool {
                    name: "min".to_string(),
                    description: None,
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                    annotations: None,
                }
            }
            fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
                Ok(vec![])
            }
        }

        let transformed = TransformedTool::from_tool(MinimalSchemaTool).build();
        let def = transformed.definition();
        assert!(def.input_schema["properties"].is_object());
        assert!(def.input_schema["required"].is_array());
    }

    // ── TransformedTool call with hidden defaults ─────────────────────

    #[test]
    fn transformed_tool_call_injects_hidden_defaults() {
        let tool = SearchToolFixture::new("search");
        let transformed = TransformedTool::from_tool(tool)
            .rename_arg("q", "query")
            .hide_arg("n", 5)
            .build();

        let cx = asupersync::Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let result = transformed
            .call(&ctx, serde_json::json!({"query": "test"}))
            .unwrap();
        // The result should contain the search output with mapped args
        assert_eq!(result.len(), 1);
        if let Content::Text { text } = &result[0] {
            assert!(text.contains("\"n\":5"));
            assert!(text.contains("\"q\":\"test\""));
        } else {
            panic!("expected text content");
        }
    }

    // ── transform_arg with no-op transform ───────────────────────────

    #[test]
    fn transform_arg_with_noop_keeps_original() {
        let tool = SearchToolFixture::new("search");
        let transformed = TransformedTool::from_tool(tool)
            .transform_arg("q", ArgTransform::new())
            .build();

        let def = transformed.definition();
        let props = def.input_schema["properties"].as_object().unwrap();
        // q should still exist unchanged
        assert!(props.contains_key("q"));
    }

    // ── transform_arg for non-existent arg ───────────────────────────

    #[test]
    fn transform_arg_for_nonexistent_arg_is_ignored() {
        let tool = SearchToolFixture::new("search");
        let transformed = TransformedTool::from_tool(tool)
            .rename_arg("nonexistent", "renamed")
            .build();

        let def = transformed.definition();
        let props = def.input_schema["properties"].as_object().unwrap();
        // Original args should be untouched
        assert!(props.contains_key("q"));
        assert!(props.contains_key("n"));
        // Renamed nonexistent shouldn't appear
        assert!(!props.contains_key("renamed"));
    }

    #[test]
    fn call_async_delegates_with_mapped_args() {
        use fastmcp_core::block_on;

        let tool = SearchToolFixture::new("search");
        let transformed = TransformedTool::from_tool(tool)
            .rename_arg("q", "query")
            .hide_arg("n", 7)
            .build();

        let cx = asupersync::Cx::for_testing();
        let ctx = McpContext::new(cx, 1);
        let result = block_on(transformed.call_async(&ctx, serde_json::json!({"query": "async"})));
        let content = result.unwrap();
        assert_eq!(content.len(), 1);
        if let Content::Text { text } = &content[0] {
            assert!(text.contains("\"q\":\"async\""));
            assert!(text.contains("\"n\":7"));
        } else {
            panic!("expected text content");
        }
    }

    #[test]
    fn transform_arguments_no_value_no_default_not_hidden_skipped() {
        let tool = SearchToolFixture::new("search");
        let transformed = TransformedTool::from_tool(tool)
            .transform_arg("n", ArgTransform::new().description("ignored desc"))
            .build();

        // Don't supply "n" at all - should skip it (no default, not hidden)
        let result = transformed
            .transform_arguments(serde_json::json!({"q": "hello"}))
            .unwrap();
        let obj = result.as_object().unwrap();
        assert_eq!(obj.get("q").unwrap(), "hello");
        assert!(
            obj.get("n").is_none(),
            "missing arg without default should be skipped"
        );
    }

    #[test]
    fn transform_arguments_default_used_without_hide() {
        let tool = SearchToolFixture::new("search");
        let transformed = TransformedTool::from_tool(tool)
            .transform_arg("n", ArgTransform::new().default_int(99))
            .build();

        // Don't supply "n" - default should kick in even though not hidden
        let result = transformed
            .transform_arguments(serde_json::json!({"q": "test"}))
            .unwrap();
        let obj = result.as_object().unwrap();
        assert_eq!(obj.get("n").unwrap(), 99);
    }

    #[test]
    fn build_definition_parent_no_description_returns_none() {
        struct NoDescTool;
        impl ToolHandler for NoDescTool {
            fn definition(&self) -> Tool {
                Tool {
                    name: "nodesc".to_string(),
                    description: None,
                    input_schema: serde_json::json!({"type": "object"}),
                    output_schema: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                    annotations: None,
                }
            }
            fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
                Ok(vec![])
            }
        }

        let transformed = TransformedTool::from_tool(NoDescTool).build();
        assert!(transformed.definition().description.is_none());
    }

    #[test]
    fn transform_schema_preserves_unrenamed_in_required() {
        // Create a tool with two required args; rename only one
        struct TwoReqTool;
        impl ToolHandler for TwoReqTool {
            fn definition(&self) -> Tool {
                Tool {
                    name: "two".to_string(),
                    description: None,
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "a": {"type": "string"},
                            "b": {"type": "string"}
                        },
                        "required": ["a", "b"]
                    }),
                    output_schema: None,
                    icon: None,
                    version: None,
                    tags: vec![],
                    annotations: None,
                }
            }
            fn call(&self, _ctx: &McpContext, _args: serde_json::Value) -> McpResult<Vec<Content>> {
                Ok(vec![])
            }
        }

        let transformed = TransformedTool::from_tool(TwoReqTool)
            .rename_arg("a", "alpha")
            .build();
        let def = transformed.definition();
        let required = def.input_schema["required"].as_array().unwrap();
        assert!(
            required.iter().any(|v| v == "alpha"),
            "renamed arg in required"
        );
        assert!(
            required.iter().any(|v| v == "b"),
            "unrenamed arg still in required"
        );
        assert!(
            !required.iter().any(|v| v == "a"),
            "old name removed from required"
        );
    }

    #[test]
    fn type_schema_replaces_entire_property() {
        let tool = SearchToolFixture::new("s");
        let transformed = TransformedTool::from_tool(tool)
            .transform_arg(
                "q",
                ArgTransform::new()
                    .type_schema(serde_json::json!({"type": "array", "items": {"type": "string"}})),
            )
            .build();

        let def = transformed.definition();
        let q_schema = &def.input_schema["properties"]["q"];
        // Should have the new type, not the old "string"
        assert_eq!(q_schema["type"], "array");
        assert!(q_schema["items"].is_object());
        // The old description should NOT be present (type_schema replaces entirely)
        assert!(q_schema.get("description").is_none());
    }
}
