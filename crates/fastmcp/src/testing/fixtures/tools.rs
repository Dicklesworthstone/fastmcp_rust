//! Sample tool definitions for testing.
//!
//! Provides pre-built tool fixtures with various characteristics:
//! - Simple tools for basic testing
//! - Complex tools for schema validation
//! - Slow tools for timeout testing
//! - Error-prone tools for error handling tests

use fastmcp_protocol::{Tool, ToolAnnotations};
use serde_json::json;

/// Creates a simple greeting tool.
///
/// Takes a `name` parameter and returns a greeting message.
///
/// # Example
///
/// ```ignore
/// use fastmcp_rust::testing::fixtures::tools::greeting_tool;
///
/// let tool = greeting_tool();
/// assert_eq!(tool.name, "greeting");
/// ```
#[must_use]
pub fn greeting_tool() -> Tool {
    Tool {
        name: "greeting".to_string(),
        description: Some("Returns a greeting for the given name".to_string()),
        input_schema: json!({
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "The name to greet"
                }
            },
            "required": ["name"]
        }),
        output_schema: Some(json!({
            "type": "object",
            "properties": {
                "message": { "type": "string" }
            }
        })),
        icon: None,
        version: Some("1.0.0".to_string()),
        tags: vec!["greeting".to_string(), "simple".to_string()],
        annotations: Some(ToolAnnotations::new().read_only(true)),
    }
}

/// Creates a calculator tool for arithmetic operations.
///
/// Takes `a`, `b`, and `operation` parameters.
///
/// # Example
///
/// ```ignore
/// use fastmcp_rust::testing::fixtures::tools::calculator_tool;
///
/// let tool = calculator_tool();
/// assert_eq!(tool.name, "calculator");
/// ```
#[must_use]
pub fn calculator_tool() -> Tool {
    Tool {
        name: "calculator".to_string(),
        description: Some("Performs basic arithmetic operations".to_string()),
        input_schema: json!({
            "type": "object",
            "properties": {
                "a": {
                    "type": "number",
                    "description": "First operand"
                },
                "b": {
                    "type": "number",
                    "description": "Second operand"
                },
                "operation": {
                    "type": "string",
                    "enum": ["add", "subtract", "multiply", "divide"],
                    "description": "The operation to perform"
                }
            },
            "required": ["a", "b", "operation"]
        }),
        output_schema: Some(json!({
            "type": "object",
            "properties": {
                "result": { "type": "number" }
            }
        })),
        icon: None,
        version: Some("1.0.0".to_string()),
        tags: vec!["math".to_string(), "calculation".to_string()],
        annotations: Some(ToolAnnotations::new().read_only(true).idempotent(true)),
    }
}

/// Creates a slow tool for timeout testing.
///
/// Takes a `delay_ms` parameter specifying how long to sleep.
///
/// # Example
///
/// ```ignore
/// use fastmcp_rust::testing::fixtures::tools::slow_tool;
///
/// let tool = slow_tool();
/// // Use in timeout tests
/// ```
#[must_use]
pub fn slow_tool() -> Tool {
    Tool {
        name: "slow_operation".to_string(),
        description: Some("A deliberately slow operation for timeout testing".to_string()),
        input_schema: json!({
            "type": "object",
            "properties": {
                "delay_ms": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 60000,
                    "description": "How long to delay in milliseconds"
                }
            },
            "required": ["delay_ms"]
        }),
        output_schema: Some(json!({
            "type": "object",
            "properties": {
                "actual_delay_ms": { "type": "integer" }
            }
        })),
        icon: None,
        version: Some("1.0.0".to_string()),
        tags: vec!["testing".to_string(), "timeout".to_string()],
        annotations: Some(ToolAnnotations::new().read_only(true)),
    }
}

/// Creates a file write tool for testing destructive operations.
///
/// # Example
///
/// ```ignore
/// use fastmcp_rust::testing::fixtures::tools::file_write_tool;
///
/// let tool = file_write_tool();
/// assert!(tool.annotations.as_ref().unwrap().destructive.unwrap());
/// ```
#[must_use]
pub fn file_write_tool() -> Tool {
    Tool {
        name: "file_write".to_string(),
        description: Some("Writes content to a file".to_string()),
        input_schema: json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path to write to"
                },
                "content": {
                    "type": "string",
                    "description": "Content to write"
                },
                "append": {
                    "type": "boolean",
                    "default": false,
                    "description": "Whether to append or overwrite"
                }
            },
            "required": ["path", "content"]
        }),
        output_schema: Some(json!({
            "type": "object",
            "properties": {
                "bytes_written": { "type": "integer" },
                "path": { "type": "string" }
            }
        })),
        icon: None,
        version: Some("1.0.0".to_string()),
        tags: vec!["file".to_string(), "io".to_string()],
        annotations: Some(ToolAnnotations::new().destructive(true).idempotent(false)),
    }
}

/// Creates a tool with complex nested schema.
///
/// Useful for testing schema validation edge cases.
#[must_use]
pub fn complex_schema_tool() -> Tool {
    Tool {
        name: "complex_operation".to_string(),
        description: Some("A tool with complex nested input schema".to_string()),
        input_schema: json!({
            "type": "object",
            "properties": {
                "config": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "settings": {
                            "type": "object",
                            "properties": {
                                "enabled": { "type": "boolean" },
                                "threshold": { "type": "number", "minimum": 0, "maximum": 100 }
                            },
                            "required": ["enabled"]
                        },
                        "tags": {
                            "type": "array",
                            "items": { "type": "string" },
                            "minItems": 1
                        }
                    },
                    "required": ["name", "settings"]
                },
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "value": { "oneOf": [
                                { "type": "string" },
                                { "type": "number" },
                                { "type": "boolean" }
                            ]}
                        },
                        "required": ["id", "value"]
                    }
                }
            },
            "required": ["config"]
        }),
        output_schema: None,
        icon: None,
        version: Some("2.0.0".to_string()),
        tags: vec!["complex".to_string(), "nested".to_string()],
        annotations: None,
    }
}

/// Creates a minimal tool with no optional fields.
///
/// Useful for testing minimum viable tool definitions.
#[must_use]
pub fn minimal_tool() -> Tool {
    Tool {
        name: "minimal".to_string(),
        description: None,
        input_schema: json!({ "type": "object" }),
        output_schema: None,
        icon: None,
        version: None,
        tags: vec![],
        annotations: None,
    }
}

/// Creates a tool that simulates errors.
///
/// The `error_type` parameter controls what kind of error to simulate.
#[must_use]
pub fn error_tool() -> Tool {
    Tool {
        name: "error_simulator".to_string(),
        description: Some("Simulates various error conditions for testing".to_string()),
        input_schema: json!({
            "type": "object",
            "properties": {
                "error_type": {
                    "type": "string",
                    "enum": ["invalid_params", "internal", "timeout", "not_found"],
                    "description": "Type of error to simulate"
                },
                "message": {
                    "type": "string",
                    "description": "Custom error message"
                }
            },
            "required": ["error_type"]
        }),
        output_schema: None,
        icon: None,
        version: Some("1.0.0".to_string()),
        tags: vec!["testing".to_string(), "error".to_string()],
        annotations: None,
    }
}

/// Returns a collection of all sample tools.
///
/// # Example
///
/// ```ignore
/// use fastmcp_rust::testing::fixtures::tools::all_sample_tools;
///
/// let tools = all_sample_tools();
/// assert!(tools.len() >= 5);
/// ```
#[must_use]
pub fn all_sample_tools() -> Vec<Tool> {
    vec![
        greeting_tool(),
        calculator_tool(),
        slow_tool(),
        file_write_tool(),
        complex_schema_tool(),
        minimal_tool(),
        error_tool(),
    ]
}

/// Builder for customizing tool fixtures.
///
/// # Example
///
/// ```ignore
/// use fastmcp_rust::testing::fixtures::tools::ToolBuilder;
///
/// let tool = ToolBuilder::new("custom_tool")
///     .description("A custom tool for testing")
///     .with_string_param("input", "The input string", true)
///     .with_number_param("count", "Number of times", false)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct ToolBuilder {
    name: String,
    description: Option<String>,
    properties: serde_json::Map<String, serde_json::Value>,
    required: Vec<String>,
    output_schema: Option<serde_json::Value>,
    version: Option<String>,
    tags: Vec<String>,
    annotations: Option<ToolAnnotations>,
}

impl ToolBuilder {
    /// Creates a new tool builder with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            properties: serde_json::Map::new(),
            required: Vec::new(),
            output_schema: None,
            version: None,
            tags: Vec::new(),
            annotations: None,
        }
    }

    /// Sets the tool description.
    #[must_use]
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Adds a string parameter.
    #[must_use]
    pub fn with_string_param(
        mut self,
        name: impl Into<String>,
        desc: impl Into<String>,
        required: bool,
    ) -> Self {
        let name = name.into();
        self.properties.insert(
            name.clone(),
            json!({
                "type": "string",
                "description": desc.into()
            }),
        );
        if required {
            self.required.push(name);
        }
        self
    }

    /// Adds a number parameter.
    #[must_use]
    pub fn with_number_param(
        mut self,
        name: impl Into<String>,
        desc: impl Into<String>,
        required: bool,
    ) -> Self {
        let name = name.into();
        self.properties.insert(
            name.clone(),
            json!({
                "type": "number",
                "description": desc.into()
            }),
        );
        if required {
            self.required.push(name);
        }
        self
    }

    /// Adds a boolean parameter.
    #[must_use]
    pub fn with_bool_param(
        mut self,
        name: impl Into<String>,
        desc: impl Into<String>,
        required: bool,
    ) -> Self {
        let name = name.into();
        self.properties.insert(
            name.clone(),
            json!({
                "type": "boolean",
                "description": desc.into()
            }),
        );
        if required {
            self.required.push(name);
        }
        self
    }

    /// Sets the output schema.
    #[must_use]
    pub fn output_schema(mut self, schema: serde_json::Value) -> Self {
        self.output_schema = Some(schema);
        self
    }

    /// Sets the version.
    #[must_use]
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Adds tags.
    #[must_use]
    pub fn tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Sets the annotations.
    #[must_use]
    pub fn annotations(mut self, annotations: ToolAnnotations) -> Self {
        self.annotations = Some(annotations);
        self
    }

    /// Builds the tool.
    #[must_use]
    pub fn build(self) -> Tool {
        let input_schema = json!({
            "type": "object",
            "properties": self.properties,
            "required": self.required
        });

        Tool {
            name: self.name,
            description: self.description,
            input_schema,
            output_schema: self.output_schema,
            icon: None,
            version: self.version,
            tags: self.tags,
            annotations: self.annotations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_greeting_tool() {
        let tool = greeting_tool();
        assert_eq!(tool.name, "greeting");
        assert!(tool.description.is_some());
        assert!(tool.input_schema.get("properties").is_some());
    }

    #[test]
    fn test_calculator_tool() {
        let tool = calculator_tool();
        assert_eq!(tool.name, "calculator");
        let props = tool.input_schema.get("properties").unwrap();
        assert!(props.get("a").is_some());
        assert!(props.get("b").is_some());
        assert!(props.get("operation").is_some());
    }

    #[test]
    fn test_slow_tool() {
        let tool = slow_tool();
        assert_eq!(tool.name, "slow_operation");
        let props = tool.input_schema.get("properties").unwrap();
        assert!(props.get("delay_ms").is_some());
    }

    #[test]
    fn test_file_write_tool_annotations() {
        let tool = file_write_tool();
        let annotations = tool.annotations.as_ref().unwrap();
        assert_eq!(annotations.destructive, Some(true));
        assert_eq!(annotations.idempotent, Some(false));
    }

    #[test]
    fn test_minimal_tool() {
        let tool = minimal_tool();
        assert_eq!(tool.name, "minimal");
        assert!(tool.description.is_none());
        assert!(tool.version.is_none());
        assert!(tool.tags.is_empty());
    }

    #[test]
    fn test_all_sample_tools() {
        let tools = all_sample_tools();
        assert!(tools.len() >= 5);

        // Verify uniqueness of names
        let names: Vec<_> = tools.iter().map(|t| &t.name).collect();
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(names.len(), unique.len());
    }

    #[test]
    fn test_tool_builder_basic() {
        let tool = ToolBuilder::new("test_tool")
            .description("A test tool")
            .with_string_param("input", "The input", true)
            .build();

        assert_eq!(tool.name, "test_tool");
        assert_eq!(tool.description, Some("A test tool".to_string()));
    }

    #[test]
    fn test_tool_builder_with_all_param_types() {
        let tool = ToolBuilder::new("multi_param")
            .with_string_param("text", "Text input", true)
            .with_number_param("count", "Count", false)
            .with_bool_param("enabled", "Enable flag", false)
            .build();

        let props = tool.input_schema.get("properties").unwrap();
        assert!(props.get("text").is_some());
        assert!(props.get("count").is_some());
        assert!(props.get("enabled").is_some());
    }

    #[test]
    fn test_tool_builder_with_annotations() {
        let tool = ToolBuilder::new("annotated")
            .annotations(ToolAnnotations::new().read_only(true).idempotent(true))
            .build();

        let annotations = tool.annotations.as_ref().unwrap();
        assert_eq!(annotations.read_only, Some(true));
        assert_eq!(annotations.idempotent, Some(true));
    }

    // =========================================================================
    // Additional coverage tests (bd-3w50)
    // =========================================================================

    #[test]
    fn error_tool_fields() {
        let tool = error_tool();
        assert_eq!(tool.name, "error_simulator");
        assert!(tool.description.is_some());
        assert_eq!(tool.version, Some("1.0.0".to_string()));
        assert!(tool.tags.contains(&"error".to_string()));
        assert!(tool.annotations.is_none());

        let props = tool.input_schema.get("properties").unwrap();
        assert!(props.get("error_type").is_some());
        assert!(props.get("message").is_some());
    }

    #[test]
    fn complex_schema_tool_fields() {
        let tool = complex_schema_tool();
        assert_eq!(tool.name, "complex_operation");
        assert_eq!(tool.version, Some("2.0.0".to_string()));
        assert!(tool.output_schema.is_none());
        assert!(tool.annotations.is_none());
        assert!(tool.tags.contains(&"nested".to_string()));

        let props = tool.input_schema.get("properties").unwrap();
        assert!(props.get("config").is_some());
        assert!(props.get("items").is_some());
    }

    #[test]
    fn greeting_tool_annotations_read_only() {
        let tool = greeting_tool();
        let annotations = tool.annotations.as_ref().unwrap();
        assert_eq!(annotations.read_only, Some(true));
        assert!(tool.tags.contains(&"greeting".to_string()));
        assert_eq!(tool.version, Some("1.0.0".to_string()));
    }

    #[test]
    fn calculator_tool_annotations_idempotent() {
        let tool = calculator_tool();
        let annotations = tool.annotations.as_ref().unwrap();
        assert_eq!(annotations.read_only, Some(true));
        assert_eq!(annotations.idempotent, Some(true));
        assert!(tool.tags.contains(&"math".to_string()));
    }

    #[test]
    fn tool_builder_version_tags_output_schema() {
        let tool = ToolBuilder::new("full")
            .version("3.0.0")
            .tags(vec!["a".to_string(), "b".to_string()])
            .output_schema(json!({"type": "string"}))
            .build();

        assert_eq!(tool.version, Some("3.0.0".to_string()));
        assert_eq!(tool.tags.len(), 2);
        assert!(tool.output_schema.is_some());
    }

    #[test]
    fn tool_builder_debug_and_clone() {
        let builder = ToolBuilder::new("dbg")
            .description("test")
            .with_string_param("x", "desc", true);
        let debug = format!("{builder:?}");
        assert!(debug.contains("ToolBuilder"));
        assert!(debug.contains("dbg"));

        let cloned = builder.clone();
        let tool = cloned.build();
        assert_eq!(tool.name, "dbg");
    }

    #[test]
    fn tool_builder_required_params_tracked() {
        let tool = ToolBuilder::new("req")
            .with_string_param("a", "desc-a", true)
            .with_number_param("b", "desc-b", false)
            .with_bool_param("c", "desc-c", true)
            .build();

        let required = tool.input_schema.get("required").unwrap();
        let required_arr = required.as_array().unwrap();
        assert_eq!(required_arr.len(), 2);
        assert!(required_arr.contains(&json!("a")));
        assert!(required_arr.contains(&json!("c")));
    }

    #[test]
    fn all_sample_tools_count() {
        let tools = all_sample_tools();
        assert_eq!(tools.len(), 7);
    }
}
