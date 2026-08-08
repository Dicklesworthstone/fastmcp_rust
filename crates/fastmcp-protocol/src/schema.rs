//! JSON Schema validation for MCP tool inputs.
//!
//! This module provides a bounded JSON Schema Draft 2020-12 validator for the
//! high-impact core keywords used by MCP tool input validation:
//!
//! - Type checking (string, number, integer, boolean, object, array, null)
//! - Required field validation
//! - Enum validation
//! - Property, pattern-property, dependency, and property-name validation
//! - Items, tuple, and contains validation for arrays
//! - Local `$defs`/`$ref`, composition, and conditional applicators
//!
//! External references are never resolved through network or filesystem I/O.

use regex::Regex;
use serde_json::Value;
use std::fmt;

/// Maximum nested schema applications on a single validation path.
pub const MAX_SCHEMA_VALIDATION_DEPTH: usize = 64;

/// Maximum local `$ref` hops on a single validation path.
pub const MAX_LOCAL_REFERENCE_DEPTH: usize = 32;

/// Maximum schemas evaluated by one composition keyword.
pub const MAX_COMPOSITION_BRANCHES: usize = 64;

/// Maximum `patternProperties` entries compiled for one object schema.
pub const MAX_PATTERN_PROPERTIES: usize = 64;

/// Maximum UTF-8 bytes in one locally compiled pattern-property expression.
pub const MAX_PATTERN_PROPERTY_BYTES: usize = 4 * 1024;

/// Maximum validation errors retained for one public `validate` call.
pub const MAX_VALIDATION_ERRORS: usize = 64;

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
    validate_internal(
        schema,
        value,
        "root",
        &mut errors,
        ValidationContext::new(schema),
    );

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validates a JSON value against a JSON Schema in strict mode.
///
/// Strict mode enforces `additionalProperties: false` on all object schemas,
/// rejecting any properties not explicitly defined in the schema.
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
/// use fastmcp_protocol::schema::validate_strict;
/// use serde_json::json;
///
/// let schema = json!({
///     "type": "object",
///     "properties": {
///         "name": { "type": "string" }
///     }
/// });
///
/// // Extra property "age" is rejected in strict mode
/// let with_extra = json!({ "name": "Alice", "age": 30 });
/// assert!(validate_strict(&schema, &with_extra).is_err());
///
/// // Only defined properties pass
/// let valid = json!({ "name": "Alice" });
/// assert!(validate_strict(&schema, &valid).is_ok());
/// ```
pub fn validate_strict(schema: &Value, value: &Value) -> ValidationResult {
    // Clone and modify the schema to enforce additionalProperties: false
    let strict_schema = make_strict_schema(schema);
    validate(&strict_schema, value)
}

/// Recursively adds `additionalProperties: false` to all object schemas.
fn make_strict_schema(schema: &Value) -> Value {
    match schema {
        Value::Object(obj) => {
            let mut new_obj = obj.clone();

            // Add additionalProperties: false if this is an object type schema
            // and doesn't already have additionalProperties defined
            if let Some(type_val) = obj.get("type") {
                let is_object_type = type_val == "object"
                    || type_val
                        .as_array()
                        .is_some_and(|arr| arr.iter().any(|t| t == "object"));

                if is_object_type && !obj.contains_key("additionalProperties") {
                    new_obj.insert("additionalProperties".to_string(), Value::Bool(false));
                }
            }

            for keyword in [
                "properties",
                "patternProperties",
                "dependentSchemas",
                "$defs",
            ] {
                if let Some(Value::Object(subschemas)) = obj.get(keyword) {
                    let strict_subschemas: serde_json::Map<String, Value> = subschemas
                        .iter()
                        .map(|(key, subschema)| (key.clone(), make_strict_schema(subschema)))
                        .collect();
                    new_obj.insert(keyword.to_owned(), Value::Object(strict_subschemas));
                }
            }

            for keyword in [
                "additionalProperties",
                "items",
                "contains",
                "not",
                "if",
                "then",
                "else",
                "propertyNames",
            ] {
                if let Some(subschema) = obj.get(keyword) {
                    new_obj.insert(keyword.to_owned(), make_strict_schema(subschema));
                }
            }

            for keyword in ["prefixItems", "allOf", "anyOf", "oneOf"] {
                if let Some(Value::Array(subschemas)) = obj.get(keyword) {
                    let strict_subschemas = subschemas.iter().map(make_strict_schema).collect();
                    new_obj.insert(keyword.to_owned(), Value::Array(strict_subschemas));
                }
            }

            Value::Object(new_obj)
        }
        Value::Array(arr) => {
            // Handle array schemas (union types in older drafts)
            Value::Array(arr.iter().map(make_strict_schema).collect())
        }
        _ => schema.clone(),
    }
}

#[derive(Clone, Copy)]
struct ValidationContext<'a> {
    root_schema: &'a Value,
    schema_depth: usize,
    reference_depth: usize,
}

impl<'a> ValidationContext<'a> {
    const fn new(root_schema: &'a Value) -> Self {
        Self {
            root_schema,
            schema_depth: 0,
            reference_depth: 0,
        }
    }

    const fn descend(self) -> Self {
        Self {
            root_schema: self.root_schema,
            schema_depth: self.schema_depth + 1,
            reference_depth: self.reference_depth,
        }
    }

    const fn follow_reference(self) -> Self {
        Self {
            root_schema: self.root_schema,
            schema_depth: self.schema_depth,
            reference_depth: self.reference_depth + 1,
        }
    }
}

fn push_error(errors: &mut Vec<ValidationError>, path: &str, message: impl Into<String>) {
    if errors.len() < MAX_VALIDATION_ERRORS {
        errors.push(ValidationError {
            path: path.to_owned(),
            message: message.into(),
        });
    }
}

/// Internal recursive validation function.
fn validate_internal(
    schema: &Value,
    value: &Value,
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: ValidationContext<'_>,
) {
    if context.schema_depth >= MAX_SCHEMA_VALIDATION_DEPTH {
        push_error(
            errors,
            path,
            "schema validation nesting limit exceeded",
        );
        return;
    }
    let context = context.descend();

    // Handle boolean schemas (true = accept all, false = reject all)
    if let Some(b) = schema.as_bool() {
        if !b {
            push_error(errors, path, "schema rejects all values");
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
            push_error(
                errors,
                path,
                format!("expected type {expected}, got {}", json_type_name(value)),
            );
            return; // Type mismatch, skip further validation
        }
    }

    validate_local_reference(schema_obj, value, path, errors, context);
    validate_composition(schema_obj, value, path, errors, context);

    // Check enum constraint
    if let Some(enum_val) = schema_obj.get("enum") {
        if let Some(enum_arr) = enum_val.as_array() {
            if !enum_arr.contains(value) {
                push_error(errors, path, format!("value must be one of: {enum_arr:?}"));
            }
        }
    }

    // Check const constraint
    if let Some(const_val) = schema_obj.get("const") {
        if value != const_val {
            push_error(errors, path, format!("value must equal {const_val}"));
        }
    }

    // Type-specific validation
    match value {
        Value::Object(obj) => {
            validate_object(schema_obj, obj, path, errors, context);
        }
        Value::Array(arr) => {
            validate_array(schema_obj, arr, path, errors, context);
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

fn validate_local_reference(
    schema: &serde_json::Map<String, Value>,
    value: &Value,
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: ValidationContext<'_>,
) {
    let Some(reference) = schema.get("$ref").and_then(Value::as_str) else {
        return;
    };
    if context.reference_depth >= MAX_LOCAL_REFERENCE_DEPTH {
        push_error(errors, path, "local schema reference depth limit exceeded");
        return;
    }
    match resolve_local_reference(context.root_schema, reference) {
        Ok(target) => validate_internal(target, value, path, errors, context.follow_reference()),
        Err(message) => push_error(errors, path, message),
    }
}

fn resolve_local_reference<'a>(root_schema: &'a Value, reference: &str) -> Result<&'a Value, &'static str> {
    if reference == "#" {
        return Ok(root_schema);
    }
    let Some(pointer) = reference.strip_prefix("#/") else {
        return Err("external schema reference is not allowed");
    };

    let mut target = root_schema;
    for encoded_segment in pointer.split('/') {
        let segment = unescape_json_pointer_segment(encoded_segment)
            .ok_or("invalid local schema reference")?;
        target = match target {
            Value::Object(object) => object.get(&segment),
            Value::Array(array) => segment
                .parse::<usize>()
                .ok()
                .and_then(|index| array.get(index)),
            _ => None,
        }
        .ok_or("unresolved local schema reference")?;
    }
    Ok(target)
}

fn unescape_json_pointer_segment(segment: &str) -> Option<String> {
    let mut decoded = String::with_capacity(segment.len());
    let mut characters = segment.chars();
    while let Some(character) = characters.next() {
        if character != '~' {
            decoded.push(character);
            continue;
        }
        match characters.next()? {
            '0' => decoded.push('~'),
            '1' => decoded.push('/'),
            _ => return None,
        }
    }
    Some(decoded)
}

fn validate_composition(
    schema: &serde_json::Map<String, Value>,
    value: &Value,
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: ValidationContext<'_>,
) {
    validate_all_of(schema, value, path, errors, context);
    validate_any_of(schema, value, path, errors, context);
    validate_one_of(schema, value, path, errors, context);
    validate_not(schema, value, path, errors, context);
    validate_conditional(schema, value, path, errors, context);
}

fn bounded_subschemas<'a>(
    schema: &'a serde_json::Map<String, Value>,
    keyword: &str,
    path: &str,
    errors: &mut Vec<ValidationError>,
) -> Option<&'a [Value]> {
    let subschemas = schema.get(keyword)?.as_array()?;
    if subschemas.len() > MAX_COMPOSITION_BRANCHES {
        push_error(errors, path, format!("{keyword} exceeds composition branch limit"));
        return None;
    }
    Some(subschemas)
}

fn validate_all_of(
    schema: &serde_json::Map<String, Value>,
    value: &Value,
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: ValidationContext<'_>,
) {
    if let Some(subschemas) = bounded_subschemas(schema, "allOf", path, errors) {
        for subschema in subschemas {
            validate_internal(subschema, value, path, errors, context);
        }
    }
}

fn validate_any_of(
    schema: &serde_json::Map<String, Value>,
    value: &Value,
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: ValidationContext<'_>,
) {
    let Some(subschemas) = bounded_subschemas(schema, "anyOf", path, errors) else {
        return;
    };
    if !subschemas
        .iter()
        .any(|subschema| branch_is_valid(subschema, value, path, context))
    {
        push_error(errors, path, "no subschema in anyOf matched");
    }
}

fn validate_one_of(
    schema: &serde_json::Map<String, Value>,
    value: &Value,
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: ValidationContext<'_>,
) {
    let Some(subschemas) = bounded_subschemas(schema, "oneOf", path, errors) else {
        return;
    };
    let matches = subschemas
        .iter()
        .filter(|subschema| branch_is_valid(subschema, value, path, context))
        .count();
    if matches != 1 {
        push_error(errors, path, "exactly one subschema in oneOf must match");
    }
}

fn validate_not(
    schema: &serde_json::Map<String, Value>,
    value: &Value,
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: ValidationContext<'_>,
) {
    if let Some(subschema) = schema.get("not") {
        if branch_is_valid(subschema, value, path, context) {
            push_error(errors, path, "value must not match the not subschema");
        }
    }
}

fn validate_conditional(
    schema: &serde_json::Map<String, Value>,
    value: &Value,
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: ValidationContext<'_>,
) {
    let Some(condition) = schema.get("if") else {
        return;
    };
    let branch_keyword = if branch_is_valid(condition, value, path, context) {
        "then"
    } else {
        "else"
    };
    if let Some(subschema) = schema.get(branch_keyword) {
        validate_internal(subschema, value, path, errors, context);
    }
}

fn branch_is_valid(
    schema: &Value,
    value: &Value,
    path: &str,
    context: ValidationContext<'_>,
) -> bool {
    let mut branch_errors = Vec::new();
    validate_internal(schema, value, path, &mut branch_errors, context);
    branch_errors.is_empty()
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
        // Get properties map directly - avoid collecting keys into Vec
        let properties = schema.get("properties").and_then(|v| v.as_object());

        for (key, value) in obj {
            // Use contains_key directly on the Map (O(1) lookup) instead of Vec::contains (O(n))
            let is_defined_property = properties.is_some_and(|p| p.contains_key(key));
            if !is_defined_property {
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
        // Use HashSet with serialized JSON strings for O(1) lookup instead of O(n) Vec::contains
        // This makes the overall algorithm O(n) instead of O(n²)
        let mut seen = std::collections::HashSet::with_capacity(arr.len());
        for (i, item) in arr.iter().enumerate() {
            // Serialize to canonical JSON string for comparison
            // serde_json produces consistent output for equal values
            let key = serde_json::to_string(item).unwrap_or_default();
            if !seen.insert(key) {
                errors.push(ValidationError {
                    path: format!("{path}[{i}]"),
                    message: "duplicate item in array".to_string(),
                });
            }
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

    // Check pattern (JSON Schema semantics: pattern matches if any substring matches).
    if let Some(pattern) = schema.get("pattern").and_then(serde_json::Value::as_str) {
        match Regex::new(pattern) {
            Ok(re) => {
                if !re.is_match(s) {
                    errors.push(ValidationError {
                        path: path.to_string(),
                        message: format!("string does not match pattern {pattern:?}"),
                    });
                }
            }
            Err(e) => {
                // Invalid schema: treat as a validation error rather than silently skipping.
                errors.push(ValidationError {
                    path: path.to_string(),
                    message: format!("invalid schema pattern {pattern:?}: {e}"),
                });
            }
        }
    }
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
    fn test_string_pattern() {
        let schema = json!({
            "type": "string",
            "pattern": "^[a-z]+$"
        });

        assert!(validate(&schema, &json!("hello")).is_ok());
        assert!(validate(&schema, &json!("Hello")).is_err());
        assert!(validate(&schema, &json!("hello123")).is_err());
    }

    #[test]
    fn test_string_pattern_invalid_regex_is_error() {
        let schema = json!({
            "type": "string",
            "pattern": "("
        });

        assert!(validate(&schema, &json!("anything")).is_err());
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

    // ========================================================================
    // Strict Validation Tests
    // ========================================================================

    #[test]
    fn test_validate_strict_rejects_extra_properties() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"}
            }
        });

        // Regular validate allows extra properties
        assert!(validate(&schema, &json!({"name": "Alice", "extra": 123})).is_ok());

        // Strict validate rejects extra properties
        assert!(validate_strict(&schema, &json!({"name": "Alice", "extra": 123})).is_err());

        // Strict validate allows only defined properties
        assert!(validate_strict(&schema, &json!({"name": "Alice"})).is_ok());
    }

    #[test]
    fn test_validate_strict_nested_objects() {
        let schema = json!({
            "type": "object",
            "properties": {
                "person": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"}
                    }
                }
            }
        });

        // Regular validate allows extra properties at any level
        assert!(
            validate(
                &schema,
                &json!({
                    "person": {"name": "Alice", "age": 30}
                })
            )
            .is_ok()
        );

        // Strict validate rejects extra properties at nested level
        assert!(
            validate_strict(
                &schema,
                &json!({
                    "person": {"name": "Alice", "age": 30}
                })
            )
            .is_err()
        );

        // Strict validate passes with only defined properties
        assert!(
            validate_strict(
                &schema,
                &json!({
                    "person": {"name": "Alice"}
                })
            )
            .is_ok()
        );
    }

    #[test]
    fn test_validate_strict_preserves_explicit_additional_properties() {
        // Schema explicitly allows additional properties with a specific type
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"}
            },
            "additionalProperties": {"type": "integer"}
        });

        // With explicit additionalProperties schema, strict mode should honor it
        assert!(
            validate_strict(
                &schema,
                &json!({
                    "name": "Alice",
                    "count": 42
                })
            )
            .is_ok()
        );

        // But still validate the type of additional properties
        assert!(
            validate_strict(
                &schema,
                &json!({
                    "name": "Alice",
                    "count": "not an integer"
                })
            )
            .is_err()
        );
    }

    #[test]
    fn test_validate_strict_array_items() {
        let schema = json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"}
                }
            }
        });

        // Regular validate allows extra properties in array items
        assert!(
            validate(
                &schema,
                &json!([
                    {"id": 1, "extra": "value"}
                ])
            )
            .is_ok()
        );

        // Strict validate rejects extra properties in array items
        assert!(
            validate_strict(
                &schema,
                &json!([
                    {"id": 1, "extra": "value"}
                ])
            )
            .is_err()
        );

        // Strict validate passes with only defined properties
        assert!(
            validate_strict(
                &schema,
                &json!([
                    {"id": 1}
                ])
            )
            .is_ok()
        );
    }

    #[test]
    fn test_validate_strict_empty_schema() {
        // Empty schema or true accepts everything
        let schema = json!({});

        // Empty schema doesn't have type: "object", so strict doesn't add additionalProperties
        assert!(validate_strict(&schema, &json!({"anything": "goes"})).is_ok());
    }

    #[test]
    fn test_validate_strict_non_object_types() {
        // Strict mode shouldn't affect non-object types
        let string_schema = json!({"type": "string"});
        assert!(validate_strict(&string_schema, &json!("hello")).is_ok());

        let number_schema = json!({"type": "number"});
        assert!(validate_strict(&number_schema, &json!(42)).is_ok());

        let array_schema = json!({"type": "array"});
        assert!(validate_strict(&array_schema, &json!([1, 2, 3])).is_ok());
    }

    // =========================================================================
    // Additional coverage tests (bd-qpwf)
    // =========================================================================

    #[test]
    fn validation_error_display_and_error_trait() {
        let err = ValidationError {
            path: "root.name".to_string(),
            message: "expected string".to_string(),
        };
        assert_eq!(err.to_string(), "root.name: expected string");
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn validation_error_debug_and_clone() {
        let err = ValidationError {
            path: "root".to_string(),
            message: "missing".to_string(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("ValidationError"));

        let cloned = err.clone();
        assert_eq!(cloned.path, "root");
        assert_eq!(cloned.message, "missing");
    }

    #[test]
    fn json_type_name_all_types() {
        assert_eq!(json_type_name(&json!(null)), "null");
        assert_eq!(json_type_name(&json!(true)), "boolean");
        assert_eq!(json_type_name(&json!(42)), "integer");
        assert_eq!(json_type_name(&json!(3.14)), "number");
        assert_eq!(json_type_name(&json!("hello")), "string");
        assert_eq!(json_type_name(&json!([])), "array");
        assert_eq!(json_type_name(&json!({})), "object");
    }

    #[test]
    fn number_multiple_of() {
        let schema = json!({"type": "number", "multipleOf": 3});
        assert!(validate(&schema, &json!(9)).is_ok());
        assert!(validate(&schema, &json!(6)).is_ok());
        assert!(validate(&schema, &json!(0)).is_ok());
        assert!(validate(&schema, &json!(7)).is_err());
    }

    #[test]
    fn object_min_max_properties() {
        let schema = json!({
            "type": "object",
            "minProperties": 1,
            "maxProperties": 2
        });

        assert!(validate(&schema, &json!({"a": 1})).is_ok());
        assert!(validate(&schema, &json!({"a": 1, "b": 2})).is_ok());
        assert!(validate(&schema, &json!({})).is_err());
        assert!(validate(&schema, &json!({"a": 1, "b": 2, "c": 3})).is_err());
    }

    #[test]
    fn prefix_items_tuple_validation() {
        let schema = json!({
            "type": "array",
            "prefixItems": [
                {"type": "string"},
                {"type": "integer"}
            ]
        });

        assert!(validate(&schema, &json!(["hello", 42])).is_ok());
        assert!(validate(&schema, &json!(["hello", 42, true])).is_ok()); // extra items allowed by default
        assert!(validate(&schema, &json!([123, "wrong"])).is_err()); // first should be string
    }

    #[test]
    fn prefix_items_with_additional_items_schema() {
        let schema = json!({
            "type": "array",
            "prefixItems": [
                {"type": "string"}
            ],
            "items": {"type": "integer"}
        });

        // First item must be string, rest must be integers
        assert!(validate(&schema, &json!(["hello", 1, 2])).is_ok());
        assert!(validate(&schema, &json!(["hello", "bad"])).is_err());
    }

    #[test]
    fn items_as_array_draft4_fallback() {
        // Draft 4-7 style: items is an array (treated as prefixItems when no prefixItems present)
        let schema = json!({
            "type": "array",
            "items": [
                {"type": "string"},
                {"type": "integer"}
            ]
        });

        assert!(validate(&schema, &json!(["hello", 42])).is_ok());
        assert!(validate(&schema, &json!([123, "wrong"])).is_err());
    }

    #[test]
    fn additional_properties_as_schema() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"}
            },
            "additionalProperties": {"type": "integer"}
        });

        assert!(validate(&schema, &json!({"name": "Alice", "count": 42})).is_ok());
        assert!(validate(&schema, &json!({"name": "Alice", "bad": "string"})).is_err());
    }

    #[test]
    fn strict_schema_with_prefix_items() {
        let schema = json!({
            "type": "array",
            "prefixItems": [
                {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"}
                    }
                }
            ]
        });

        // Strict mode adds additionalProperties: false to nested objects in prefixItems
        assert!(validate_strict(&schema, &json!([{"id": 1}])).is_ok());
        assert!(validate_strict(&schema, &json!([{"id": 1, "extra": "val"}])).is_err());
    }

    #[test]
    fn strict_schema_with_union_type() {
        let schema = json!({
            "type": ["object", "null"],
            "properties": {
                "name": {"type": "string"}
            }
        });

        // Strict mode should add additionalProperties for union types including object
        assert!(validate_strict(&schema, &json!(null)).is_ok());
        assert!(validate_strict(&schema, &json!({"name": "Alice"})).is_ok());
        assert!(validate_strict(&schema, &json!({"name": "Alice", "extra": 1})).is_err());
    }

    #[test]
    fn unknown_type_in_matches_type_is_permissive() {
        let schema = json!({"type": "custom_extension"});
        // Unknown types accept everything
        assert!(validate(&schema, &json!("anything")).is_ok());
        assert!(validate(&schema, &json!(42)).is_ok());
    }

    #[test]
    fn invalid_schema_not_an_object() {
        // Non-object, non-boolean schemas are silently skipped
        assert!(validate(&json!(42), &json!("anything")).is_ok());
        assert!(validate(&json!("bad_schema"), &json!(123)).is_ok());
    }
}
