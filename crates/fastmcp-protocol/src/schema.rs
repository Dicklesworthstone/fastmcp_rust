//! JSON Schema validation for MCP tool inputs.
//!
//! This module provides a simple JSON Schema validator that covers the core
//! requirements for MCP tool input validation:
//!
//! - Type checking (string, number, integer, boolean, object, array, null)
//! - Required field validation
//! - Enum validation
//! - Property validation for objects
//! - Items validation for arrays
//!
//! This is not a full JSON Schema implementation but covers the subset used by MCP.

use serde_json::Value;
use std::fmt;

/// Error returned when JSON Schema validation fails.
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// Path to the invalid value (e.g., `root.foo.bar` or `root[0]`).
    pub path: String,
    /// Description of what went wrong.
    pub message: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

impl std::error::Error for ValidationError {}

/// Result of JSON Schema validation.
pub type ValidationResult = Result<(), Vec<ValidationError>>;

/// Validates a JSON value against a JSON Schema.
///
/// # Arguments
///
/// * `schema` - The JSON Schema to validate against
/// * `value` - The value to validate
///
/// # Returns
///
/// `Ok(())` if the value is valid, or `Err(Vec<ValidationError>)` with all
/// validation errors found.
///
/// # Example
///
/// ```
/// use fastmcp_protocol::schema::validate;
/// use serde_json::json;
///
/// let schema = json!({
///     "type": "object",
///     "properties": {
///         "name": { "type": "string" },
///         "age": { "type": "integer" }
///     },
///     "required": ["name"]
/// });
///
/// let valid = json!({ "name": "Alice", "age": 30 });
/// assert!(validate(&schema, &valid).is_ok());
///
/// let invalid = json!({ "age": 30 });
/// assert!(validate(&schema, &invalid).is_err());
/// ```
pub fn validate(schema: &Value, value: &Value) -> ValidationResult {
    let mut errors = Vec::new();
    validate_internal(schema, value, "root", &mut errors);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Internal recursive validation function.
fn validate_internal(schema: &Value, value: &Value, path: &str, errors: &mut Vec<ValidationError>) {
    // Handle boolean schemas (true = accept all, false = reject all)
    if let Some(b) = schema.as_bool() {
        if !b {
            errors.push(ValidationError {
                path: path.to_string(),
                message: "schema rejects all values".to_string(),
            });
        }
        return;
    }

    // Schema must be an object
    let Some(schema_obj) = schema.as_object() else {
        return; // Invalid schema, skip validation
    };

    // Check type constraint
    if let Some(type_val) = schema_obj.get("type") {
        if !validate_type(type_val, value) {
            let expected = type_val
                .as_str()
                .map(String::from)
                .or_else(|| type_val.as_array().map(|arr| format!("{arr:?}")))
                .unwrap_or_else(|| "unknown".to_string());
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("expected type {expected}, got {}", json_type_name(value)),
            });
            return; // Type mismatch, skip further validation
        }
    }

    // Check enum constraint
    if let Some(enum_val) = schema_obj.get("enum") {
        if let Some(enum_arr) = enum_val.as_array() {
            if !enum_arr.contains(value) {
                errors.push(ValidationError {
                    path: path.to_string(),
                    message: format!("value must be one of: {enum_arr:?}"),
                });
            }
        }
    }

    // Check const constraint
    if let Some(const_val) = schema_obj.get("const") {
        if value != const_val {
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("value must equal {const_val}"),
            });
        }
    }

    // Type-specific validation
    match value {
        Value::Object(obj) => {
            validate_object(schema_obj, obj, path, errors);
        }
        Value::Array(arr) => {
            validate_array(schema_obj, arr, path, errors);
        }
        Value::String(s) => {
            validate_string(schema_obj, s, path, errors);
        }
        Value::Number(n) => {
            validate_number(schema_obj, n, path, errors);
        }
        _ => {}
    }
}

/// Validates type constraint.
fn validate_type(type_val: &Value, value: &Value) -> bool {
    match type_val {
        Value::String(t) => matches_type(t, value),
        Value::Array(types) => types.iter().any(|t| {
            t.as_str()
                .is_some_and(|type_str| matches_type(type_str, value))
        }),
        _ => true, // Invalid type constraint, skip
    }
}

/// Checks if a value matches a single type name.
fn matches_type(type_name: &str, value: &Value) -> bool {
    match type_name {
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.is_i64() || value.is_u64(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "null" => value.is_null(),
        _ => true, // Unknown type, accept
    }
}

/// Returns the JSON type name for a value.
fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                "integer"
            } else {
                "number"
            }
        }
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Validates object-specific constraints.
fn validate_object(
    schema: &serde_json::Map<String, Value>,
    obj: &serde_json::Map<String, Value>,
    path: &str,
    errors: &mut Vec<ValidationError>,
) {
    // Check required fields
    if let Some(required) = schema.get("required").and_then(|v| v.as_array()) {
        for req in required {
            if let Some(req_name) = req.as_str() {
                if !obj.contains_key(req_name) {
                    errors.push(ValidationError {
                        path: path.to_string(),
                        message: format!("missing required field: {req_name}"),
                    });
                }
            }
        }
    }

    // Validate properties
    if let Some(properties) = schema.get("properties").and_then(|v| v.as_object()) {
        for (key, value) in obj {
            if let Some(prop_schema) = properties.get(key) {
                let prop_path = format!("{path}.{key}");
                validate_internal(prop_schema, value, &prop_path, errors);
            }
        }
    }

    // Check additionalProperties constraint
    if let Some(additional) = schema.get("additionalProperties") {
        let properties = schema
            .get("properties")
            .and_then(|v| v.as_object())
            .map(|p| p.keys().collect::<Vec<_>>())
            .unwrap_or_default();

        for (key, value) in obj {
            if !properties.contains(&key) {
                match additional {
                    Value::Bool(false) => {
                        errors.push(ValidationError {
                            path: path.to_string(),
                            message: format!("additional property not allowed: {key}"),
                        });
                    }
                    Value::Object(_) => {
                        let prop_path = format!("{path}.{key}");
                        validate_internal(additional, value, &prop_path, errors);
                    }
                    _ => {}
                }
            }
        }
    }

    // Check minProperties/maxProperties
    if let Some(min) = schema
        .get("minProperties")
        .and_then(serde_json::Value::as_u64)
    {
        if (obj.len() as u64) < min {
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("object must have at least {min} properties"),
            });
        }
    }
    if let Some(max) = schema
        .get("maxProperties")
        .and_then(serde_json::Value::as_u64)
    {
        if (obj.len() as u64) > max {
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("object must have at most {max} properties"),
            });
        }
    }
}

/// Validates array-specific constraints.
fn validate_array(
    schema: &serde_json::Map<String, Value>,
    arr: &[Value],
    path: &str,
    errors: &mut Vec<ValidationError>,
) {
    // Validate prefixItems (tuple validation)
    let mut prefix_len = 0;
    if let Some(prefix_items) = schema.get("prefixItems").and_then(|v| v.as_array()) {
        prefix_len = prefix_items.len();
        for (i, item_schema) in prefix_items.iter().enumerate() {
            if let Some(item) = arr.get(i) {
                let item_path = format!("{path}[{i}]");
                validate_internal(item_schema, item, &item_path, errors);
            }
        }
    }

    // Validate items (remaining items or all items)
    if let Some(items_schema) = schema.get("items") {
        // If items is an array (Draft 4-7 tuple), treat as prefixItems fallback if prefixItems absent
        if items_schema.is_array() && prefix_len == 0 {
            if let Some(items_arr) = items_schema.as_array() {
                for (i, item_schema) in items_arr.iter().enumerate() {
                    if let Some(item) = arr.get(i) {
                        let item_path = format!("{path}[{i}]");
                        validate_internal(item_schema, item, &item_path, errors);
                    }
                }
                // In older drafts, 'additionalItems' controls the rest. We skip that for simplicity unless needed.
            }
        } else if items_schema.is_object() || items_schema.is_boolean() {
            // Validate items starting from where prefixItems left off
            for (i, item) in arr.iter().enumerate().skip(prefix_len) {
                let item_path = format!("{path}[{i}]");
                validate_internal(items_schema, item, &item_path, errors);
            }
        }
    }

    // Check minItems/maxItems
    if let Some(min) = schema.get("minItems").and_then(serde_json::Value::as_u64) {
        if (arr.len() as u64) < min {
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("array must have at least {min} items"),
            });
        }
    }
    if let Some(max) = schema.get("maxItems").and_then(serde_json::Value::as_u64) {
        if (arr.len() as u64) > max {
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("array must have at most {max} items"),
            });
        }
    }

    // Check uniqueItems
    if schema
        .get("uniqueItems")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        let mut seen = Vec::with_capacity(arr.len());
        for (i, item) in arr.iter().enumerate() {
            if seen.contains(&item) {
                errors.push(ValidationError {
                    path: format!("{path}[{i}]"),
                    message: "duplicate item in array".to_string(),
                });
            }
            seen.push(item);
        }
    }
}

/// Validates string-specific constraints.
fn validate_string(
    schema: &serde_json::Map<String, Value>,
    s: &str,
    path: &str,
    errors: &mut Vec<ValidationError>,
) {
    // Check minLength/maxLength
    let len = s.chars().count();
    if let Some(min) = schema.get("minLength").and_then(serde_json::Value::as_u64) {
        if (len as u64) < min {
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("string must be at least {min} characters"),
            });
        }
    }
    if let Some(max) = schema.get("maxLength").and_then(serde_json::Value::as_u64) {
        if (len as u64) > max {
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("string must be at most {max} characters"),
            });
        }
    }

    // Check pattern (basic regex support could be added here)
    // For now, we skip pattern validation to avoid regex dependency
}

/// Validates number-specific constraints.
fn validate_number(
    schema: &serde_json::Map<String, Value>,
    n: &serde_json::Number,
    path: &str,
    errors: &mut Vec<ValidationError>,
) {
    let val = n.as_f64().unwrap_or(0.0);

    // Check minimum/maximum
    if let Some(min) = schema.get("minimum").and_then(serde_json::Value::as_f64) {
        if val < min {
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("value must be >= {min}"),
            });
        }
    }
    if let Some(max) = schema.get("maximum").and_then(serde_json::Value::as_f64) {
        if val > max {
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("value must be <= {max}"),
            });
        }
    }

    // Check exclusiveMinimum/exclusiveMaximum
    if let Some(min) = schema
        .get("exclusiveMinimum")
        .and_then(serde_json::Value::as_f64)
    {
        if val <= min {
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("value must be > {min}"),
            });
        }
    }
    if let Some(max) = schema
        .get("exclusiveMaximum")
        .and_then(serde_json::Value::as_f64)
    {
        if val >= max {
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("value must be < {max}"),
            });
        }
    }

    // Check multipleOf
    if let Some(multiple) = schema.get("multipleOf").and_then(serde_json::Value::as_f64) {
        if multiple != 0.0 && (val % multiple).abs() > f64::EPSILON {
            errors.push(ValidationError {
                path: path.to_string(),
                message: format!("value must be a multiple of {multiple}"),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_type_validation_string() {
        let schema = json!({"type": "string"});
        assert!(validate(&schema, &json!("hello")).is_ok());
        assert!(validate(&schema, &json!(123)).is_err());
    }

    #[test]
    fn test_type_validation_number() {
        let schema = json!({"type": "number"});
        assert!(validate(&schema, &json!(123)).is_ok());
        assert!(validate(&schema, &json!(12.5)).is_ok());
        assert!(validate(&schema, &json!("hello")).is_err());
    }

    #[test]
    fn test_type_validation_integer() {
        let schema = json!({"type": "integer"});
        assert!(validate(&schema, &json!(123)).is_ok());
        assert!(validate(&schema, &json!(12.5)).is_err());
    }

    #[test]
    fn test_type_validation_boolean() {
        let schema = json!({"type": "boolean"});
        assert!(validate(&schema, &json!(true)).is_ok());
        assert!(validate(&schema, &json!(false)).is_ok());
        assert!(validate(&schema, &json!(1)).is_err());
    }

    #[test]
    fn test_type_validation_object() {
        let schema = json!({"type": "object"});
        assert!(validate(&schema, &json!({})).is_ok());
        assert!(validate(&schema, &json!({"a": 1})).is_ok());
        assert!(validate(&schema, &json!([])).is_err());
    }

    #[test]
    fn test_type_validation_array() {
        let schema = json!({"type": "array"});
        assert!(validate(&schema, &json!([])).is_ok());
        assert!(validate(&schema, &json!([1, 2, 3])).is_ok());
        assert!(validate(&schema, &json!({})).is_err());
    }

    #[test]
    fn test_type_validation_null() {
        let schema = json!({"type": "null"});
        assert!(validate(&schema, &json!(null)).is_ok());
        assert!(validate(&schema, &json!(0)).is_err());
    }

    #[test]
    fn test_type_validation_union() {
        let schema = json!({"type": ["string", "number"]});
        assert!(validate(&schema, &json!("hello")).is_ok());
        assert!(validate(&schema, &json!(123)).is_ok());
        assert!(validate(&schema, &json!(true)).is_err());
    }

    #[test]
    fn test_required_fields() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"}
            },
            "required": ["name"]
        });

        assert!(validate(&schema, &json!({"name": "Alice"})).is_ok());
        assert!(validate(&schema, &json!({"name": "Alice", "age": 30})).is_ok());
        assert!(validate(&schema, &json!({"age": 30})).is_err());
        assert!(validate(&schema, &json!({})).is_err());
    }

    #[test]
    fn test_enum_validation() {
        let schema = json!({"enum": ["red", "green", "blue"]});
        assert!(validate(&schema, &json!("red")).is_ok());
        assert!(validate(&schema, &json!("yellow")).is_err());
    }

    #[test]
    fn test_const_validation() {
        let schema = json!({"const": "fixed"});
        assert!(validate(&schema, &json!("fixed")).is_ok());
        assert!(validate(&schema, &json!("other")).is_err());
    }

    #[test]
    fn test_string_length() {
        let schema = json!({
            "type": "string",
            "minLength": 2,
            "maxLength": 5
        });

        assert!(validate(&schema, &json!("ab")).is_ok());
        assert!(validate(&schema, &json!("abcde")).is_ok());
        assert!(validate(&schema, &json!("a")).is_err());
        assert!(validate(&schema, &json!("abcdef")).is_err());
    }

    #[test]
    fn test_number_range() {
        let schema = json!({
            "type": "number",
            "minimum": 0,
            "maximum": 100
        });

        assert!(validate(&schema, &json!(0)).is_ok());
        assert!(validate(&schema, &json!(50)).is_ok());
        assert!(validate(&schema, &json!(100)).is_ok());
        assert!(validate(&schema, &json!(-1)).is_err());
        assert!(validate(&schema, &json!(101)).is_err());
    }

    #[test]
    fn test_number_exclusive_range() {
        let schema = json!({
            "type": "number",
            "exclusiveMinimum": 0,
            "exclusiveMaximum": 10
        });

        assert!(validate(&schema, &json!(1)).is_ok());
        assert!(validate(&schema, &json!(9)).is_ok());
        assert!(validate(&schema, &json!(0)).is_err());
        assert!(validate(&schema, &json!(10)).is_err());
    }

    #[test]
    fn test_array_items() {
        let schema = json!({
            "type": "array",
            "items": {"type": "integer"}
        });

        assert!(validate(&schema, &json!([1, 2, 3])).is_ok());
        assert!(validate(&schema, &json!([])).is_ok());
        assert!(validate(&schema, &json!([1, "two", 3])).is_err());
    }

    #[test]
    fn test_array_length() {
        let schema = json!({
            "type": "array",
            "minItems": 1,
            "maxItems": 3
        });

        assert!(validate(&schema, &json!([1])).is_ok());
        assert!(validate(&schema, &json!([1, 2, 3])).is_ok());
        assert!(validate(&schema, &json!([])).is_err());
        assert!(validate(&schema, &json!([1, 2, 3, 4])).is_err());
    }

    #[test]
    fn test_unique_items() {
        let schema = json!({
            "type": "array",
            "uniqueItems": true
        });

        assert!(validate(&schema, &json!([1, 2, 3])).is_ok());
        assert!(validate(&schema, &json!([1, 1, 2])).is_err());
    }

    #[test]
    fn test_nested_object() {
        let schema = json!({
            "type": "object",
            "properties": {
                "person": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "age": {"type": "integer"}
                    },
                    "required": ["name"]
                }
            }
        });

        assert!(validate(&schema, &json!({"person": {"name": "Alice"}})).is_ok());
        assert!(validate(&schema, &json!({"person": {"name": "Alice", "age": 30}})).is_ok());
        assert!(validate(&schema, &json!({"person": {"age": 30}})).is_err());
    }

    #[test]
    fn test_additional_properties_false() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"}
            },
            "additionalProperties": false
        });

        assert!(validate(&schema, &json!({"name": "Alice"})).is_ok());
        assert!(validate(&schema, &json!({})).is_ok());
        assert!(validate(&schema, &json!({"name": "Alice", "extra": 1})).is_err());
    }

    #[test]
    fn test_boolean_schema() {
        // true schema accepts everything
        assert!(validate(&json!(true), &json!("anything")).is_ok());
        assert!(validate(&json!(true), &json!(123)).is_ok());

        // false schema rejects everything
        assert!(validate(&json!(false), &json!("anything")).is_err());
    }

    #[test]
    fn test_multiple_errors() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"}
            },
            "required": ["name", "age"]
        });

        let result = validate(&schema, &json!({}));
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 2); // Missing both name and age
    }

    #[test]
    fn test_error_path() {
        let schema = json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {"type": "integer"}
                }
            }
        });

        let result = validate(&schema, &json!({"items": [1, "two", 3]}));
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "root.items[1]");
    }
}
