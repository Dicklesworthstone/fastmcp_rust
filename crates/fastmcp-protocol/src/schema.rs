//! JSON Schema validation for MCP tool inputs.
//!
//! This module provides a bounded JSON Schema Draft 2020-12 validator for the
//! high-impact core keywords used by MCP tool input validation:
//!
//! - Type checking (string, number, integer, boolean, object, array, null)
//! - Required field validation
//! - Enum validation
//! - Property, pattern-property, dependency, property-name, and
//!   unevaluated-property validation
//! - Items, tuple, and contains validation for arrays
//! - Local `$defs`/`$ref`, composition, and conditional applicators
//!
//! External references are never resolved through network or filesystem I/O.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use regex::Regex;
use serde_json::Value;
use std::fmt;

/// The sole JSON Schema dialect accepted by the final core schema-admission
/// boundary.
pub const FINAL_JSON_SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

/// Maximum nested schema applications on a single validation path.
pub const MAX_SCHEMA_VALIDATION_DEPTH: usize = 64;

/// Maximum schema nodes admitted for one final-dialect schema document.
pub const MAX_SCHEMA_ADMISSION_NODES: usize = 4_096;

/// Maximum JSON instance nodes traversed by one validation call.
pub const MAX_SCHEMA_INSTANCE_NODES: usize = 4_096;

/// Maximum JSON instance nesting depth accepted by one validation call.
pub const MAX_SCHEMA_INSTANCE_DEPTH: usize = 64;

/// Maximum UTF-8 bytes in one instance string or object member name.
pub const MAX_SCHEMA_INSTANCE_STRING_BYTES: usize = 64 * 1024;

/// Maximum work units performed by one validation call, including schema
/// applications, branch probes, regular-expression compilation and matching,
/// and object-property annotation bookkeeping.
pub const MAX_SCHEMA_VALIDATION_WORK: usize = 4_096;

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

/// A stable refusal emitted before an untrusted schema reaches validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaAdmissionError {
    path: String,
    reason: &'static str,
}

impl SchemaAdmissionError {
    fn new(path: impl Into<String>, reason: &'static str) -> Self {
        Self {
            path: path.into(),
            reason,
        }
    }

    /// JSON path of the malformed schema member.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Stable refusal category for the malformed schema member.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for SchemaAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.path, self.reason)
    }
}

impl std::error::Error for SchemaAdmissionError {}

/// A final-dialect schema that passed structural admission.
///
/// Construction is intentionally restricted to [`admit_final_schema`] so a
/// caller cannot present malformed schema syntax as a validated schema.
#[derive(Debug, Clone)]
pub struct AdmittedSchema {
    schema: Value,
}

impl AdmittedSchema {
    /// Returns the admitted schema without altering its wire representation.
    #[must_use]
    pub const fn schema(&self) -> &Value {
        &self.schema
    }

    /// Validates an instance using this admitted schema.
    #[must_use]
    pub fn validate(&self, value: &Value) -> ValidationResult {
        validate_admitted_final_schema(&self.schema, value)
    }
}

/// A final core result discriminator admitted by this protocol surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalCoreResultType {
    /// An ordinary method result.
    Complete,
    /// A result asking the client to supply an input before retrying.
    InputRequired,
}

impl FinalCoreResultType {
    /// Exact final wire spelling of the discriminator.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::InputRequired => "input_required",
        }
    }
}

/// Validates a final-dialect schema before any caller uses it for tool input,
/// tool output, or another final core schema-bearing field.
///
/// The final wire boundary accepts only JSON Schema booleans or objects. A
/// present `$schema` must identify the canonical Draft 2020-12 dialect, and
/// every structural keyword consumed by this validator is checked before the
/// schema can be retained. External references are refused rather than being
/// interpreted as I/O authority.
pub fn admit_final_schema(schema: Value) -> Result<AdmittedSchema, SchemaAdmissionError> {
    let mut node_count = 0;
    validate_final_schema_node(&schema, &schema, "$", true, 0, &mut node_count)?;
    Ok(AdmittedSchema { schema })
}

/// Validates a final core result against an admitted schema and its expected
/// discriminator.
///
/// This is intentionally stricter than peer-result compatibility decoding:
/// safe final emission must carry an explicit core `resultType`; absent,
/// non-string, extension, and cross-branch values are rejected here.
pub fn validate_final_core_result(
    schema: &AdmittedSchema,
    value: &Value,
    expected_result_type: FinalCoreResultType,
) -> ValidationResult {
    let mut errors = Vec::new();
    let Some(result) = value.as_object() else {
        push_error(&mut errors, "root", "final result must be an object");
        return Err(errors);
    };

    match result.get("resultType") {
        Some(Value::String(result_type)) if result_type == expected_result_type.as_str() => {}
        Some(Value::String(_)) => push_error(
            &mut errors,
            "root.resultType",
            "resultType does not match the selected final core result branch",
        ),
        Some(_) => push_error(
            &mut errors,
            "root.resultType",
            "resultType must be a final core result discriminator string",
        ),
        None => push_error(&mut errors, "root", "final result requires resultType"),
    }

    if let Err(schema_errors) = schema.validate(value) {
        for error in schema_errors {
            if errors.len() == MAX_VALIDATION_ERRORS {
                break;
            }
            errors.push(error);
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn validate_final_schema_node(
    schema: &Value,
    root_schema: &Value,
    path: &str,
    root: bool,
    depth: usize,
    node_count: &mut usize,
) -> Result<(), SchemaAdmissionError> {
    if depth >= MAX_SCHEMA_VALIDATION_DEPTH {
        return Err(SchemaAdmissionError::new(
            path,
            "schema admission nesting limit exceeded",
        ));
    }
    *node_count += 1;
    if *node_count > MAX_SCHEMA_ADMISSION_NODES {
        return Err(SchemaAdmissionError::new(
            path,
            "schema admission node limit exceeded",
        ));
    }
    if schema.is_boolean() {
        return Ok(());
    }
    let object = schema
        .as_object()
        .ok_or_else(|| SchemaAdmissionError::new(path, "schema must be an object or boolean"))?;

    if root {
        if let Some(dialect) = object.get("$schema") {
            if dialect.as_str() != Some(FINAL_JSON_SCHEMA_DIALECT) {
                return Err(SchemaAdmissionError::new(
                    format!("{path}.$schema"),
                    "unsupported schema dialect",
                ));
            }
        }
    }

    if let Some(reference) = object.get("$ref") {
        let reference = reference.as_str().ok_or_else(|| {
            SchemaAdmissionError::new(format!("{path}.$ref"), "$ref must be a string")
        })?;
        if reference != "#" && !reference.starts_with("#/") {
            return Err(SchemaAdmissionError::new(
                format!("{path}.$ref"),
                "external schema reference is not allowed",
            ));
        }
        if resolve_local_reference(root_schema, reference).is_err() {
            return Err(SchemaAdmissionError::new(
                format!("{path}.$ref"),
                "unresolved local schema reference",
            ));
        }
    }

    if let Some(type_value) = object.get("type") {
        validate_schema_type(type_value, &format!("{path}.type"))?;
    }
    validate_string_array_keyword(object, "required", path)?;
    validate_string_array_keyword(object, "dependentRequired", path)?;
    validate_nonnegative_integer_keywords(
        object,
        path,
        &[
            "minProperties",
            "maxProperties",
            "minItems",
            "maxItems",
            "minContains",
            "maxContains",
            "minLength",
            "maxLength",
        ],
    )?;
    validate_number_keywords(
        object,
        path,
        &[
            "minimum",
            "maximum",
            "exclusiveMinimum",
            "exclusiveMaximum",
            "multipleOf",
        ],
    )?;
    if object
        .get("multipleOf")
        .is_some_and(|value| value.as_f64().is_none_or(|multiple| multiple <= 0.0))
    {
        return Err(SchemaAdmissionError::new(
            format!("{path}.multipleOf"),
            "multipleOf must be a positive number",
        ));
    }
    validate_boolean_keywords(object, path, &["uniqueItems"])?;
    validate_enum_keyword(object, path)?;
    validate_pattern_keyword(object, path)?;
    validate_format_keyword(object, path)?;

    for keyword in [
        "properties",
        "patternProperties",
        "$defs",
        "dependentSchemas",
    ] {
        if let Some(subschemas) = object.get(keyword) {
            let subschemas = subschemas.as_object().ok_or_else(|| {
                SchemaAdmissionError::new(
                    format!("{path}.{keyword}"),
                    "schema map keyword must be an object",
                )
            })?;
            if keyword == "patternProperties" {
                if subschemas.len() > MAX_PATTERN_PROPERTIES {
                    return Err(SchemaAdmissionError::new(
                        format!("{path}.{keyword}"),
                        "patternProperties exceeds entry limit",
                    ));
                }
                for pattern in subschemas.keys() {
                    if pattern.len() > MAX_PATTERN_PROPERTY_BYTES {
                        return Err(SchemaAdmissionError::new(
                            format!("{path}.{keyword}"),
                            "patternProperties pattern exceeds byte limit",
                        ));
                    }
                    if Regex::new(pattern).is_err() {
                        return Err(SchemaAdmissionError::new(
                            format!("{path}.{keyword}"),
                            "invalid patternProperties pattern",
                        ));
                    }
                }
            }
            for (name, subschema) in subschemas {
                validate_final_schema_node(
                    subschema,
                    root_schema,
                    &format!("{path}.{keyword}.{name}"),
                    false,
                    depth + 1,
                    node_count,
                )?;
            }
        }
    }

    for keyword in [
        "additionalProperties",
        "unevaluatedProperties",
        "items",
        "contains",
        "not",
        "if",
        "then",
        "else",
        "propertyNames",
    ] {
        if let Some(subschema) = object.get(keyword) {
            validate_final_schema_node(
                subschema,
                root_schema,
                &format!("{path}.{keyword}"),
                false,
                depth + 1,
                node_count,
            )?;
        }
    }

    for keyword in ["prefixItems", "allOf", "anyOf", "oneOf"] {
        if let Some(subschemas) = object.get(keyword) {
            let subschemas = subschemas.as_array().ok_or_else(|| {
                SchemaAdmissionError::new(
                    format!("{path}.{keyword}"),
                    "schema array keyword must be an array",
                )
            })?;
            for (index, subschema) in subschemas.iter().enumerate() {
                validate_final_schema_node(
                    subschema,
                    root_schema,
                    &format!("{path}.{keyword}[{index}]"),
                    false,
                    depth + 1,
                    node_count,
                )?;
            }
        }
    }

    Ok(())
}

fn validate_schema_type(value: &Value, path: &str) -> Result<(), SchemaAdmissionError> {
    let valid_type = |type_name: &str| {
        matches!(
            type_name,
            "array" | "boolean" | "integer" | "null" | "number" | "object" | "string"
        )
    };
    match value {
        Value::String(type_name) if valid_type(type_name) => Ok(()),
        Value::Array(types)
            if !types.is_empty()
                && types
                    .iter()
                    .all(|type_name| type_name.as_str().is_some_and(valid_type)) =>
        {
            Ok(())
        }
        _ => Err(SchemaAdmissionError::new(
            path,
            "type must contain only JSON Schema primitive type names",
        )),
    }
}

fn validate_string_array_keyword(
    object: &serde_json::Map<String, Value>,
    keyword: &str,
    path: &str,
) -> Result<(), SchemaAdmissionError> {
    let Some(value) = object.get(keyword) else {
        return Ok(());
    };
    if keyword == "dependentRequired" {
        let dependencies = value.as_object().ok_or_else(|| {
            SchemaAdmissionError::new(
                format!("{path}.{keyword}"),
                "dependentRequired must be an object",
            )
        })?;
        if dependencies.values().all(|required| {
            required
                .as_array()
                .is_some_and(|members| members.iter().all(Value::is_string))
        }) {
            return Ok(());
        }
        return Err(SchemaAdmissionError::new(
            format!("{path}.{keyword}"),
            "dependentRequired values must be arrays of strings",
        ));
    }
    if value
        .as_array()
        .is_some_and(|members| members.iter().all(Value::is_string))
    {
        Ok(())
    } else {
        Err(SchemaAdmissionError::new(
            format!("{path}.{keyword}"),
            "schema string-array keyword must be an array of strings",
        ))
    }
}

fn validate_nonnegative_integer_keywords(
    object: &serde_json::Map<String, Value>,
    path: &str,
    keywords: &[&str],
) -> Result<(), SchemaAdmissionError> {
    for keyword in keywords {
        if object.get(*keyword).is_some_and(|value| !value.is_u64()) {
            return Err(SchemaAdmissionError::new(
                format!("{path}.{keyword}"),
                "schema count keyword must be a nonnegative integer",
            ));
        }
    }
    Ok(())
}

fn validate_number_keywords(
    object: &serde_json::Map<String, Value>,
    path: &str,
    keywords: &[&str],
) -> Result<(), SchemaAdmissionError> {
    for keyword in keywords {
        if object.get(*keyword).is_some_and(|value| !value.is_number()) {
            return Err(SchemaAdmissionError::new(
                format!("{path}.{keyword}"),
                "schema numeric keyword must be a number",
            ));
        }
    }
    Ok(())
}

fn validate_boolean_keywords(
    object: &serde_json::Map<String, Value>,
    path: &str,
    keywords: &[&str],
) -> Result<(), SchemaAdmissionError> {
    for keyword in keywords {
        if object
            .get(*keyword)
            .is_some_and(|value| !value.is_boolean())
        {
            return Err(SchemaAdmissionError::new(
                format!("{path}.{keyword}"),
                "schema boolean keyword must be a boolean",
            ));
        }
    }
    Ok(())
}

fn validate_enum_keyword(
    object: &serde_json::Map<String, Value>,
    path: &str,
) -> Result<(), SchemaAdmissionError> {
    if object
        .get("enum")
        .is_some_and(|value| !value.as_array().is_some_and(|values| !values.is_empty()))
    {
        return Err(SchemaAdmissionError::new(
            format!("{path}.enum"),
            "enum must be a nonempty array",
        ));
    }
    Ok(())
}

fn validate_pattern_keyword(
    object: &serde_json::Map<String, Value>,
    path: &str,
) -> Result<(), SchemaAdmissionError> {
    let Some(pattern) = object.get("pattern") else {
        return Ok(());
    };
    let pattern = pattern.as_str().ok_or_else(|| {
        SchemaAdmissionError::new(format!("{path}.pattern"), "pattern must be a string")
    })?;
    if Regex::new(pattern).is_ok() {
        Ok(())
    } else {
        Err(SchemaAdmissionError::new(
            format!("{path}.pattern"),
            "invalid schema pattern",
        ))
    }
}

fn validate_format_keyword(
    object: &serde_json::Map<String, Value>,
    path: &str,
) -> Result<(), SchemaAdmissionError> {
    if object.get("format").is_some_and(|value| !value.is_string()) {
        Err(SchemaAdmissionError::new(
            format!("{path}.format"),
            "format must be a string",
        ))
    } else {
        Ok(())
    }
}

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
    validate_with_schema_features(schema, value, false)
}

/// Validates an instance with the final-schema vocabulary accepted by
/// [`admit_final_schema`].
fn validate_admitted_final_schema(schema: &Value, value: &Value) -> ValidationResult {
    validate_with_schema_features(schema, value, true)
}

fn validate_with_schema_features(
    schema: &Value,
    value: &Value,
    enforce_unevaluated_properties: bool,
) -> ValidationResult {
    let mut errors = Vec::new();
    let mut instance_nodes = 0;
    if !validate_instance_bounds(value, "root", 0, &mut instance_nodes, &mut errors) {
        return Err(errors);
    }
    let mut context = ValidationContext::new(schema, enforce_unevaluated_properties);
    validate_internal(schema, value, "root", &mut errors, &mut context);
    if context.work_exhausted
        && !errors
            .iter()
            .any(|error| error.message == "schema validation work limit exceeded")
    {
        push_error(&mut errors, "root", "schema validation work limit exceeded");
    }

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
                "unevaluatedProperties",
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

struct ValidationContext<'a> {
    root_schema: &'a Value,
    schema_depth: usize,
    reference_depth: usize,
    remaining_work: usize,
    work_exhausted: bool,
    enforce_unevaluated_properties: bool,
}

impl<'a> ValidationContext<'a> {
    const fn new(root_schema: &'a Value, enforce_unevaluated_properties: bool) -> Self {
        Self {
            root_schema,
            schema_depth: 0,
            reference_depth: 0,
            remaining_work: MAX_SCHEMA_VALIDATION_WORK,
            work_exhausted: false,
            enforce_unevaluated_properties,
        }
    }

    fn consume_work(&mut self) -> bool {
        let Some(remaining_work) = self.remaining_work.checked_sub(1) else {
            self.work_exhausted = true;
            return false;
        };
        self.remaining_work = remaining_work;
        true
    }

    fn enter_schema(&mut self) -> bool {
        if self.schema_depth >= MAX_SCHEMA_VALIDATION_DEPTH || !self.consume_work() {
            return false;
        }
        self.schema_depth += 1;
        true
    }

    fn leave_schema(&mut self) {
        self.schema_depth -= 1;
    }

    fn enter_reference(&mut self) -> bool {
        if self.reference_depth >= MAX_LOCAL_REFERENCE_DEPTH {
            return false;
        }
        self.reference_depth += 1;
        true
    }

    fn leave_reference(&mut self) {
        self.reference_depth -= 1;
    }
}

fn consume_validation_work(
    context: &mut ValidationContext<'_>,
    path: &str,
    errors: &mut Vec<ValidationError>,
) -> bool {
    if !context.enforce_unevaluated_properties {
        return true;
    }
    if context.consume_work() {
        true
    } else {
        push_error(errors, path, "schema validation work limit exceeded");
        false
    }
}

fn charged_regex_is_match(
    pattern: &Regex,
    candidate: &str,
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: &mut ValidationContext<'_>,
) -> Option<bool> {
    consume_validation_work(context, path, errors).then(|| pattern.is_match(candidate))
}

fn validate_instance_bounds(
    value: &Value,
    path: &str,
    depth: usize,
    node_count: &mut usize,
    errors: &mut Vec<ValidationError>,
) -> bool {
    if depth >= MAX_SCHEMA_INSTANCE_DEPTH {
        push_error(errors, path, "instance nesting limit exceeded");
        return false;
    }
    *node_count += 1;
    if *node_count > MAX_SCHEMA_INSTANCE_NODES {
        push_error(errors, path, "instance node limit exceeded");
        return false;
    }

    match value {
        Value::String(string) => {
            if string.len() > MAX_SCHEMA_INSTANCE_STRING_BYTES {
                push_error(errors, path, "instance string byte limit exceeded");
                return false;
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                if !validate_instance_bounds(
                    item,
                    &format!("{path}[{index}]"),
                    depth + 1,
                    node_count,
                    errors,
                ) {
                    return false;
                }
            }
        }
        Value::Object(members) => {
            for (name, member) in members {
                if name.len() > MAX_SCHEMA_INSTANCE_STRING_BYTES {
                    push_error(
                        errors,
                        path,
                        "instance object member-name byte limit exceeded",
                    );
                    return false;
                }
                if !validate_instance_bounds(
                    member,
                    &format!("{path}.{name}"),
                    depth + 1,
                    node_count,
                    errors,
                ) {
                    return false;
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    true
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
    context: &mut ValidationContext<'_>,
) {
    if !context.enter_schema() {
        let reason = if context.remaining_work == 0 {
            "schema validation work limit exceeded"
        } else {
            "schema validation nesting limit exceeded"
        };
        push_error(errors, path, reason);
        return;
    }

    // Handle boolean schemas (true = accept all, false = reject all)
    if let Some(b) = schema.as_bool() {
        if !b {
            push_error(errors, path, "schema rejects all values");
        }
        context.leave_schema();
        return;
    }

    // Schema must be an object
    let Some(schema_obj) = schema.as_object() else {
        context.leave_schema();
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
            context.leave_schema();
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
            validate_object(schema_obj, value, obj, path, errors, context);
        }
        Value::Array(arr) => {
            validate_array(schema_obj, arr, path, errors, context);
        }
        Value::String(s) => {
            validate_string(schema_obj, s, path, errors, context);
        }
        Value::Number(n) => {
            validate_number(schema_obj, n, path, errors);
        }
        _ => {}
    }
    context.leave_schema();
}

fn validate_local_reference(
    schema: &serde_json::Map<String, Value>,
    value: &Value,
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: &mut ValidationContext<'_>,
) {
    let Some(reference) = schema.get("$ref").and_then(Value::as_str) else {
        return;
    };
    if !context.enter_reference() {
        push_error(errors, path, "local schema reference depth limit exceeded");
        return;
    }
    let root_schema = context.root_schema;
    match resolve_local_reference(root_schema, reference) {
        Ok(target) => validate_internal(target, value, path, errors, context),
        Err(message) => push_error(errors, path, message),
    }
    context.leave_reference();
}

fn resolve_local_reference<'a>(
    root_schema: &'a Value,
    reference: &str,
) -> Result<&'a Value, &'static str> {
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
    context: &mut ValidationContext<'_>,
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
        push_error(
            errors,
            path,
            format!("{keyword} exceeds composition branch limit"),
        );
        return None;
    }
    Some(subschemas)
}

fn validate_all_of(
    schema: &serde_json::Map<String, Value>,
    value: &Value,
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: &mut ValidationContext<'_>,
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
    context: &mut ValidationContext<'_>,
) {
    let Some(subschemas) = bounded_subschemas(schema, "anyOf", path, errors) else {
        return;
    };
    let mut matched = false;
    for subschema in subschemas {
        if branch_is_valid(subschema, value, path, context) {
            matched = true;
            break;
        }
    }
    if !matched {
        push_error(errors, path, "no subschema in anyOf matched");
    }
}

fn validate_one_of(
    schema: &serde_json::Map<String, Value>,
    value: &Value,
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: &mut ValidationContext<'_>,
) {
    let Some(subschemas) = bounded_subschemas(schema, "oneOf", path, errors) else {
        return;
    };
    let mut matches = 0;
    for subschema in subschemas {
        if branch_is_valid(subschema, value, path, context) {
            matches += 1;
        }
    }
    if matches != 1 {
        push_error(errors, path, "exactly one subschema in oneOf must match");
    }
}

fn validate_not(
    schema: &serde_json::Map<String, Value>,
    value: &Value,
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: &mut ValidationContext<'_>,
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
    context: &mut ValidationContext<'_>,
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
    context: &mut ValidationContext<'_>,
) -> bool {
    if context.enforce_unevaluated_properties && !context.consume_work() {
        return false;
    }
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
    value: &Value,
    obj: &serde_json::Map<String, Value>,
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: &mut ValidationContext<'_>,
) {
    // Check required fields
    if let Some(required) = schema.get("required").and_then(|v| v.as_array()) {
        for req in required {
            if let Some(req_name) = req.as_str() {
                if !obj.contains_key(req_name) {
                    push_error(errors, path, format!("missing required field: {req_name}"));
                }
            }
        }
    }

    let properties = schema.get("properties").and_then(Value::as_object);
    let patterns = compile_pattern_properties(schema, path, errors, context);
    if context.work_exhausted {
        return;
    }

    for (key, value) in obj {
        let property_path = format!("{path}.{key}");
        if let Some(property_schema) = properties.and_then(|properties| properties.get(key)) {
            validate_internal(property_schema, value, &property_path, errors, context);
        }
        for (pattern, pattern_schema) in &patterns {
            let Some(matches) =
                charged_regex_is_match(pattern, key, &property_path, errors, context)
            else {
                return;
            };
            if matches {
                validate_internal(pattern_schema, value, &property_path, errors, context);
            }
        }
    }

    if let Some(property_name_schema) = schema.get("propertyNames") {
        for key in obj.keys() {
            let property_path = format!("{path}.{key}");
            validate_internal(
                property_name_schema,
                &Value::String(key.clone()),
                &property_path,
                errors,
                context,
            );
        }
    }

    validate_dependencies(schema, value, obj, path, errors, context);

    // Check additionalProperties after applying both named and pattern properties.
    if let Some(additional) = schema.get("additionalProperties") {
        for (key, value) in obj {
            let mut matches_pattern = false;
            for (pattern, _) in &patterns {
                let Some(matches) = charged_regex_is_match(pattern, key, path, errors, context)
                else {
                    return;
                };
                if matches {
                    matches_pattern = true;
                    break;
                }
            }
            let is_defined_property = properties
                .is_some_and(|properties| properties.contains_key(key))
                || matches_pattern;
            if !is_defined_property {
                match additional {
                    Value::Bool(false) => {
                        push_error(
                            errors,
                            path,
                            format!("additional property not allowed: {key}"),
                        );
                    }
                    Value::Object(_) => {
                        let prop_path = format!("{path}.{key}");
                        validate_internal(additional, value, &prop_path, errors, context);
                    }
                    _ => {}
                }
            }
        }
    }

    if context.enforce_unevaluated_properties {
        validate_unevaluated_properties(schema, value, obj, path, errors, context);
    }

    // Check minProperties/maxProperties
    if let Some(min) = schema
        .get("minProperties")
        .and_then(serde_json::Value::as_u64)
    {
        if (obj.len() as u64) < min {
            push_error(
                errors,
                path,
                format!("object must have at least {min} properties"),
            );
        }
    }
    if let Some(max) = schema
        .get("maxProperties")
        .and_then(serde_json::Value::as_u64)
    {
        if (obj.len() as u64) > max {
            push_error(
                errors,
                path,
                format!("object must have at most {max} properties"),
            );
        }
    }
}

/// Applies the Draft 2020-12 `unevaluatedProperties` keyword after every
/// sibling applicator has had an opportunity to evaluate object members.
fn validate_unevaluated_properties(
    schema: &serde_json::Map<String, Value>,
    value: &Value,
    obj: &serde_json::Map<String, Value>,
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: &mut ValidationContext<'_>,
) {
    let Some(unevaluated_schema) = schema.get("unevaluatedProperties") else {
        return;
    };

    let mut evaluated = std::collections::HashSet::with_capacity(obj.len());
    mark_evaluated_object_properties(
        schema,
        value,
        obj,
        path,
        false,
        &mut evaluated,
        errors,
        context,
    );

    for (key, member) in obj {
        if !consume_validation_work(context, path, errors) {
            return;
        }
        if !evaluated.contains(key) {
            validate_internal(
                unevaluated_schema,
                member,
                &format!("{path}.{key}"),
                errors,
                context,
            );
        }
    }
}

/// Marks the object members evaluated by a successful schema application.
///
/// `unevaluatedProperties` consumes all remaining members when it belongs to
/// a successful nested applicator. The outer invocation leaves its own keyword
/// out of the annotation set so that it can validate those remaining members.
fn mark_evaluated_object_properties(
    schema: &serde_json::Map<String, Value>,
    value: &Value,
    obj: &serde_json::Map<String, Value>,
    path: &str,
    include_unevaluated_properties: bool,
    evaluated: &mut std::collections::HashSet<String>,
    errors: &mut Vec<ValidationError>,
    context: &mut ValidationContext<'_>,
) {
    if !context.consume_work() {
        push_error(errors, path, "schema validation work limit exceeded");
        return;
    }

    let properties = schema.get("properties").and_then(Value::as_object);
    let patterns = compile_pattern_properties(schema, path, errors, context);
    if context.work_exhausted {
        return;
    }
    for key in obj.keys() {
        if !consume_validation_work(context, path, errors) {
            return;
        }
        let matched_property = properties.is_some_and(|properties| properties.contains_key(key));
        let mut matched_pattern = false;
        for (pattern, _) in &patterns {
            let Some(matches) = charged_regex_is_match(pattern, key, path, errors, context) else {
                return;
            };
            if matches {
                matched_pattern = true;
                break;
            }
        }
        if matched_property || matched_pattern || schema.contains_key("additionalProperties") {
            evaluated.insert(key.clone());
        }
    }

    if include_unevaluated_properties && schema.contains_key("unevaluatedProperties") {
        for key in obj.keys() {
            if !consume_validation_work(context, path, errors) {
                return;
            }
            evaluated.insert(key.clone());
        }
    }

    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        if !context.enter_reference() {
            push_error(errors, path, "local schema reference depth limit exceeded");
        } else {
            let root_schema = context.root_schema;
            match resolve_local_reference(root_schema, reference) {
                Ok(target) if branch_is_valid(target, value, path, context) => {
                    if let Some(target) = target.as_object() {
                        mark_evaluated_object_properties(
                            target, value, obj, path, true, evaluated, errors, context,
                        );
                    }
                }
                Ok(_) => {}
                Err(message) => push_error(errors, path, message),
            }
            context.leave_reference();
        }
    }

    if let Some(dependent_schemas) = schema.get("dependentSchemas").and_then(Value::as_object) {
        for (trigger, dependent_schema) in dependent_schemas {
            if obj.contains_key(trigger)
                && branch_is_valid(dependent_schema, value, path, context)
                && let Some(dependent_schema) = dependent_schema.as_object()
            {
                mark_evaluated_object_properties(
                    dependent_schema,
                    value,
                    obj,
                    path,
                    true,
                    evaluated,
                    errors,
                    context,
                );
            }
        }
    }

    mark_composition_evaluated_properties(
        schema, "allOf", value, obj, path, evaluated, errors, context,
    );
    mark_composition_evaluated_properties(
        schema, "anyOf", value, obj, path, evaluated, errors, context,
    );

    if let Some(subschemas) = bounded_subschemas(schema, "oneOf", path, errors) {
        let matching: Vec<_> = subschemas
            .iter()
            .filter(|subschema| branch_is_valid(subschema, value, path, context))
            .collect();
        if matching.len() == 1
            && let Some(subschema) = matching[0].as_object()
        {
            mark_evaluated_object_properties(
                subschema, value, obj, path, true, evaluated, errors, context,
            );
        }
    }

    if let Some(condition) = schema.get("if") {
        let condition_matched = branch_is_valid(condition, value, path, context);
        if condition_matched && let Some(condition) = condition.as_object() {
            mark_evaluated_object_properties(
                condition, value, obj, path, true, evaluated, errors, context,
            );
        }

        let branch = if condition_matched { "then" } else { "else" };
        if let Some(subschema) = schema.get(branch)
            && branch_is_valid(subschema, value, path, context)
            && let Some(subschema) = subschema.as_object()
        {
            mark_evaluated_object_properties(
                subschema, value, obj, path, true, evaluated, errors, context,
            );
        }
    }
}

/// Merges annotations from every successful `allOf` or `anyOf` branch.
fn mark_composition_evaluated_properties(
    schema: &serde_json::Map<String, Value>,
    keyword: &str,
    value: &Value,
    obj: &serde_json::Map<String, Value>,
    path: &str,
    evaluated: &mut std::collections::HashSet<String>,
    errors: &mut Vec<ValidationError>,
    context: &mut ValidationContext<'_>,
) {
    let Some(subschemas) = bounded_subschemas(schema, keyword, path, errors) else {
        return;
    };
    for subschema in subschemas {
        if branch_is_valid(subschema, value, path, context)
            && let Some(subschema) = subschema.as_object()
        {
            mark_evaluated_object_properties(
                subschema, value, obj, path, true, evaluated, errors, context,
            );
        }
    }
}

fn compile_pattern_properties<'a>(
    schema: &'a serde_json::Map<String, Value>,
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: &mut ValidationContext<'_>,
) -> Vec<(Regex, &'a Value)> {
    let Some(pattern_properties) = schema.get("patternProperties").and_then(Value::as_object)
    else {
        return Vec::new();
    };
    if pattern_properties.len() > MAX_PATTERN_PROPERTIES {
        push_error(errors, path, "patternProperties exceeds entry limit");
        return Vec::new();
    }

    let mut patterns = Vec::with_capacity(pattern_properties.len());
    for (source, pattern_schema) in pattern_properties {
        if !consume_validation_work(context, path, errors) {
            break;
        }
        if source.len() > MAX_PATTERN_PROPERTY_BYTES {
            push_error(errors, path, "patternProperties pattern exceeds byte limit");
            continue;
        }
        match Regex::new(source) {
            Ok(pattern) => patterns.push((pattern, pattern_schema)),
            Err(_) => push_error(errors, path, "invalid patternProperties pattern"),
        }
    }
    patterns
}

fn validate_dependencies(
    schema: &serde_json::Map<String, Value>,
    value: &Value,
    obj: &serde_json::Map<String, Value>,
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: &mut ValidationContext<'_>,
) {
    if let Some(dependent_required) = schema.get("dependentRequired").and_then(Value::as_object) {
        for (trigger, required) in dependent_required {
            if !obj.contains_key(trigger) {
                continue;
            }
            if let Some(required) = required.as_array() {
                for required_property in required {
                    if let Some(required_property) = required_property.as_str() {
                        if !obj.contains_key(required_property) {
                            push_error(
                                errors,
                                path,
                                format!("property {trigger} requires property {required_property}"),
                            );
                        }
                    }
                }
            }
        }
    }

    if let Some(dependent_schemas) = schema.get("dependentSchemas").and_then(Value::as_object) {
        for (trigger, dependent_schema) in dependent_schemas {
            if obj.contains_key(trigger) {
                validate_internal(dependent_schema, value, path, errors, context);
            }
        }
    }
}

/// Validates array-specific constraints.
fn validate_array(
    schema: &serde_json::Map<String, Value>,
    arr: &[Value],
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: &mut ValidationContext<'_>,
) {
    // Validate prefixItems (tuple validation)
    let mut prefix_len = 0;
    if let Some(prefix_items) = schema.get("prefixItems").and_then(|v| v.as_array()) {
        prefix_len = prefix_items.len();
        for (i, item_schema) in prefix_items.iter().enumerate() {
            if let Some(item) = arr.get(i) {
                let item_path = format!("{path}[{i}]");
                validate_internal(item_schema, item, &item_path, errors, context);
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
                        validate_internal(item_schema, item, &item_path, errors, context);
                    }
                }
                // In older drafts, 'additionalItems' controls the rest. We skip that for simplicity unless needed.
            }
        } else if items_schema.is_object() || items_schema.is_boolean() {
            // Validate items starting from where prefixItems left off
            for (i, item) in arr.iter().enumerate().skip(prefix_len) {
                let item_path = format!("{path}[{i}]");
                validate_internal(items_schema, item, &item_path, errors, context);
            }
        }
    }

    // Check minItems/maxItems
    if let Some(min) = schema.get("minItems").and_then(serde_json::Value::as_u64) {
        if (arr.len() as u64) < min {
            push_error(
                errors,
                path,
                format!("array must have at least {min} items"),
            );
        }
    }
    if let Some(max) = schema.get("maxItems").and_then(serde_json::Value::as_u64) {
        if (arr.len() as u64) > max {
            push_error(errors, path, format!("array must have at most {max} items"));
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
                push_error(errors, &format!("{path}[{i}]"), "duplicate item in array");
            }
        }
    }

    if let Some(contains) = schema.get("contains") {
        let mut matches = 0;
        for item in arr {
            if branch_is_valid(contains, item, path, context) {
                matches += 1;
            }
        }
        let minimum = schema
            .get("minContains")
            .and_then(Value::as_u64)
            .unwrap_or(1);
        let maximum = schema.get("maxContains").and_then(Value::as_u64);
        if (matches as u64) < minimum {
            push_error(
                errors,
                path,
                format!("array must contain at least {minimum} matching items"),
            );
        }
        if let Some(maximum) = maximum {
            if (matches as u64) > maximum {
                push_error(
                    errors,
                    path,
                    format!("array must contain at most {maximum} matching items"),
                );
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
    context: &mut ValidationContext<'_>,
) {
    // Check minLength/maxLength
    let len = s.chars().count();
    if let Some(min) = schema.get("minLength").and_then(serde_json::Value::as_u64) {
        if (len as u64) < min {
            push_error(
                errors,
                path,
                format!("string must be at least {min} characters"),
            );
        }
    }
    if let Some(max) = schema.get("maxLength").and_then(serde_json::Value::as_u64) {
        if (len as u64) > max {
            push_error(
                errors,
                path,
                format!("string must be at most {max} characters"),
            );
        }
    }

    // Check pattern (JSON Schema semantics: pattern matches if any substring matches).
    if let Some(pattern) = schema.get("pattern").and_then(serde_json::Value::as_str) {
        if !consume_validation_work(context, path, errors) {
            return;
        }
        match Regex::new(pattern) {
            Ok(re) => {
                let Some(matches) = charged_regex_is_match(&re, s, path, errors, context) else {
                    return;
                };
                if !matches {
                    push_error(
                        errors,
                        path,
                        format!("string does not match pattern {pattern:?}"),
                    );
                }
            }
            Err(e) => {
                // Invalid schema: treat as a validation error rather than silently skipping.
                push_error(
                    errors,
                    path,
                    format!("invalid schema pattern {pattern:?}: {e}"),
                );
            }
        }
    }

    validate_format(schema, s, path, errors);
}

fn validate_format(
    schema: &serde_json::Map<String, Value>,
    value: &str,
    path: &str,
    errors: &mut Vec<ValidationError>,
) {
    let Some(format) = schema.get("format").and_then(Value::as_str) else {
        return;
    };

    let valid = match format {
        "byte" => BASE64_STANDARD.decode(value).is_ok(),
        "uri" => is_valid_uri(value),
        "uri-template" => is_valid_uri_template(value),
        // Draft 2020-12 permits custom format names. Only the formats pinned
        // by the final MCP schemas are assertions at this boundary.
        _ => true,
    };
    if !valid {
        push_error(
            errors,
            path,
            format!("string does not match format {format:?}"),
        );
    }
}

fn is_valid_uri(value: &str) -> bool {
    let Some((scheme, remainder)) = value.split_once(':') else {
        return false;
    };
    is_valid_uri_scheme(scheme) && is_valid_uri_reference_segment(remainder)
}

fn is_valid_uri_template(value: &str) -> bool {
    crate::UriTemplate::parse(value).is_ok()
}

fn is_valid_uri_scheme(scheme: &str) -> bool {
    let bytes = scheme.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes
            .iter()
            .skip(1)
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'+' | b'-' | b'.'))
}

fn is_valid_uri_reference_segment(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else if is_valid_uri_reference_byte(bytes[index]) {
            index += 1;
        } else {
            return false;
        }
    }
    true
}

fn is_valid_uri_reference_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b':'
                | b'/'
                | b'?'
                | b'#'
                | b'['
                | b']'
                | b'@'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b'%'
        )
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
            push_error(errors, path, format!("value must be >= {min}"));
        }
    }
    if let Some(max) = schema.get("maximum").and_then(serde_json::Value::as_f64) {
        if val > max {
            push_error(errors, path, format!("value must be <= {max}"));
        }
    }

    // Check exclusiveMinimum/exclusiveMaximum
    if let Some(min) = schema
        .get("exclusiveMinimum")
        .and_then(serde_json::Value::as_f64)
    {
        if val <= min {
            push_error(errors, path, format!("value must be > {min}"));
        }
    }
    if let Some(max) = schema
        .get("exclusiveMaximum")
        .and_then(serde_json::Value::as_f64)
    {
        if val >= max {
            push_error(errors, path, format!("value must be < {max}"));
        }
    }

    // Check multipleOf
    if let Some(multiple) = schema.get("multipleOf").and_then(serde_json::Value::as_f64) {
        if multiple != 0.0 && (val % multiple).abs() > f64::EPSILON {
            push_error(
                errors,
                path,
                format!("value must be a multiple of {multiple}"),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sch_01_a_schema() -> Value {
        json!({
            "$defs": {
                "positive-id": {"type": "integer", "minimum": 1}
            },
            "type": "object",
            "properties": {
                "id": {"$ref": "#/$defs/positive-id"},
                "mode": {"enum": ["fast", "safe"]},
                "items": {
                    "type": "array",
                    "contains": {"type": "integer", "multipleOf": 2},
                    "minContains": 2,
                    "maxContains": 2
                }
            },
            "required": ["id", "mode", "items"],
            "patternProperties": {
                "^x-": {"type": "string"}
            },
            "propertyNames": {"pattern": "^[A-Za-z-]+$"},
            "dependentRequired": {
                "creditCard": ["billingAddress"]
            },
            "dependentSchemas": {
                "creditCard": {"required": ["billingAddress"]}
            },
            "allOf": [{"required": ["id"]}],
            "anyOf": [
                {"properties": {"mode": {"const": "fast"}}, "required": ["mode"]},
                {"properties": {"mode": {"const": "safe"}}, "required": ["mode"]}
            ],
            "oneOf": [
                {"properties": {"mode": {"const": "fast"}}, "required": ["mode"]},
                {"properties": {"mode": {"const": "safe"}}, "required": ["mode"]}
            ],
            "not": {
                "properties": {"mode": {"const": "disabled"}},
                "required": ["mode"]
            },
            "if": {
                "properties": {"mode": {"const": "fast"}},
                "required": ["mode"]
            },
            "then": {"required": ["fastConfig"]},
            "else": {"required": ["safeConfig"]}
        })
    }

    fn sch_01_a_valid_instance() -> Value {
        json!({
            "id": 7,
            "mode": "fast",
            "fastConfig": true,
            "items": [2, 4, 5],
            "x-label": "bounded",
            "creditCard": "4111",
            "billingAddress": "42 Schema Street"
        })
    }

    #[test]
    fn sch_01_a_positive() {
        let schema = sch_01_a_schema();
        let instance = sch_01_a_valid_instance();

        assert!(validate(&schema, &instance).is_ok());
    }

    #[test]
    fn sch_01_a_planted_negative() {
        let schema = sch_01_a_schema();
        let schema_before = schema.clone();
        let mut instance = sch_01_a_valid_instance();
        instance["items"][1] = json!(3);

        let errors = validate(&schema, &instance)
            .expect_err("changing only one array item must violate minContains");
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "root.items");
        assert_eq!(
            errors[0].message,
            "array must contain at least 2 matching items"
        );
        assert_eq!(schema, schema_before);
    }

    #[test]
    fn final_core_result_schema_positive() {
        let schema = admit_final_schema(json!({
            "$schema": FINAL_JSON_SCHEMA_DIALECT,
            "type": "object",
            "properties": {
                "resultType": {"const": "complete"},
                "content": {"type": "array", "items": {"type": "string"}}
            },
            "required": ["resultType", "content"],
            "additionalProperties": false
        }))
        .expect("a strict final core result schema admits");
        let result = json!({"resultType": "complete", "content": ["ready"]});

        validate_final_core_result(&schema, &result, FinalCoreResultType::Complete)
            .expect("the selected final core branch and schema both admit the result");
        assert_eq!(schema.schema()["$schema"], FINAL_JSON_SCHEMA_DIALECT);
        assert_eq!(FinalCoreResultType::Complete.as_str(), "complete");
    }

    #[test]
    fn final_core_result_schema_cross_era_and_unknown_field_negatives() {
        let schema = admit_final_schema(json!({
            "$schema": FINAL_JSON_SCHEMA_DIALECT,
            "type": "object",
            "properties": {
                "resultType": {"const": "complete"},
                "content": {"type": "array", "items": {"type": "string"}}
            },
            "required": ["resultType", "content"],
            "additionalProperties": false
        }))
        .expect("the final schema admits");
        let accepted = json!({"resultType": "complete", "content": ["ready"]});

        let mut cross_era = accepted.clone();
        cross_era["resultType"] = json!("legacy_complete");
        let cross_era_errors =
            validate_final_core_result(&schema, &cross_era, FinalCoreResultType::Complete)
                .expect_err("changing only resultType to a non-final branch must reject");
        assert!(cross_era_errors.iter().any(|error| {
            error.path == "root.resultType"
                && error.message
                    == "resultType does not match the selected final core result branch"
        }));

        let mut with_legacy_field = accepted.clone();
        with_legacy_field["protocolVersion"] = json!("2024-11-05");
        let unknown_field_errors =
            validate_final_core_result(&schema, &with_legacy_field, FinalCoreResultType::Complete)
                .expect_err("adding only a legacy result field must reject");
        assert!(unknown_field_errors.iter().any(|error| {
            error.path == "root"
                && error.message == "additional property not allowed: protocolVersion"
        }));
        assert_eq!(
            accepted,
            json!({"resultType": "complete", "content": ["ready"]})
        );
    }

    fn bounded_draft_2020_12_schema() -> AdmittedSchema {
        admit_final_schema(json!({
            "$schema": FINAL_JSON_SCHEMA_DIALECT,
            "$defs": {
                "positive": {
                    "allOf": [
                        {"type": "integer"},
                        {"minimum": 1}
                    ]
                },
                "entry": {
                    "type": "object",
                    "properties": {
                        "kind": {"enum": ["number", "label"]},
                        "value": {}
                    },
                    "required": ["kind", "value"],
                    "additionalProperties": false,
                    "allOf": [{
                        "if": {
                            "properties": {"kind": {"const": "number"}},
                            "required": ["kind"]
                        },
                        "then": {
                            "properties": {"value": {"$ref": "#/$defs/positive"}}
                        },
                        "else": {
                            "properties": {"value": {"type": "string", "minLength": 3}}
                        }
                    }]
                }
            },
            "type": "object",
            "properties": {
                "entries": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/entry"}
                }
            },
            "required": ["entries"],
            "additionalProperties": false
        }))
        .expect("bounded local-reference schema admits")
    }

    #[test]
    fn bounded_draft_2020_12_local_ref_composition_conditional_positive() {
        let schema = bounded_draft_2020_12_schema();
        let instance = json!({
            "entries": [
                {"kind": "number", "value": 7},
                {"kind": "label", "value": "ready"}
            ]
        });

        schema
            .validate(&instance)
            .expect("local references, allOf, and the selected conditional branch validate");
    }

    #[test]
    fn bounded_draft_2020_12_local_ref_composition_conditional_planted_negative() {
        let schema = bounded_draft_2020_12_schema();
        let accepted = json!({
            "entries": [
                {"kind": "number", "value": 7},
                {"kind": "label", "value": "ready"}
            ]
        });
        let mut planted = accepted.clone();
        planted["entries"][0]["value"] = json!(0);

        let errors = schema.validate(&planted).expect_err(
            "changing only the local-reference value violates the selected then branch",
        );
        assert!(errors.iter().any(|error| {
            error.path == "root.entries[0].value" && error.message == "value must be >= 1"
        }));
        assert_eq!(
            accepted,
            json!({
                "entries": [
                    {"kind": "number", "value": 7},
                    {"kind": "label", "value": "ready"}
                ]
            })
        );
    }

    fn bounded_draft_2020_12_unevaluated_properties_schema() -> AdmittedSchema {
        admit_final_schema(json!({
            "$schema": FINAL_JSON_SCHEMA_DIALECT,
            "type": "object",
            "allOf": [{
                "properties": {
                    "label": {"type": "string"}
                },
                "required": ["label"]
            }],
            "unevaluatedProperties": false
        }))
        .expect("the bounded unevaluated-properties schema admits")
    }

    #[test]
    fn bounded_draft_2020_12_unevaluated_properties_positive() {
        let schema = bounded_draft_2020_12_unevaluated_properties_schema();
        let accepted = json!({"label": "ready"});

        schema
            .validate(&accepted)
            .expect("a property evaluated by a successful allOf branch remains accepted");
        assert_eq!(accepted, json!({"label": "ready"}));
    }

    #[test]
    fn bounded_draft_2020_12_unevaluated_properties_planted_negative() {
        let schema = bounded_draft_2020_12_unevaluated_properties_schema();
        let accepted = json!({"label": "ready"});
        let mut planted = accepted.clone();
        planted["unexpected"] = json!(true);

        let errors = schema
            .validate(&planted)
            .expect_err("adding only an unevaluated property must be rejected by the false schema");
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "root.unexpected");
        assert_eq!(errors[0].message, "schema rejects all values");
        assert_eq!(accepted, json!({"label": "ready"}));
    }

    #[test]
    fn raw_validate_preserves_legacy_unevaluated_properties_behavior() {
        let legacy_schema = json!({
            "type": "object",
            "unevaluatedProperties": false
        });
        let legacy_instance = json!({"legacy": true});

        assert!(validate(&legacy_schema, &legacy_instance).is_ok());
        assert_eq!(legacy_instance, json!({"legacy": true}));
    }

    fn assert_admitted_annotations_accept_only_evaluated_members(schema: Value, accepted: Value) {
        let schema = admit_final_schema(schema).expect("the bounded annotation schema admits");
        schema
            .validate(&accepted)
            .expect("members annotated by successful applicators remain accepted");

        let mut planted = accepted.clone();
        planted
            .as_object_mut()
            .expect("the annotation fixture is an object")
            .insert("unexpected".to_owned(), Value::Bool(true));
        let errors = schema
            .validate(&planted)
            .expect_err("adding only an unevaluated member must reject");
        assert!(errors.iter().any(|error| {
            error.path == "root.unexpected" && error.message == "schema rejects all values"
        }));
        assert!(accepted.get("unexpected").is_none());
    }

    #[test]
    fn admitted_ref_annotations_reach_unevaluated_properties() {
        assert_admitted_annotations_accept_only_evaluated_members(
            json!({
                "$schema": FINAL_JSON_SCHEMA_DIALECT,
                "$defs": {
                    "referenced": {
                        "properties": {"viaRef": {"type": "integer"}},
                        "required": ["viaRef"]
                    }
                },
                "$ref": "#/$defs/referenced",
                "unevaluatedProperties": false
            }),
            json!({"viaRef": 1}),
        );
    }

    #[test]
    fn admitted_all_of_annotations_reach_unevaluated_properties() {
        assert_admitted_annotations_accept_only_evaluated_members(
            json!({
                "$schema": FINAL_JSON_SCHEMA_DIALECT,
                "allOf": [{
                    "properties": {"viaAllOf": {"type": "integer"}},
                    "required": ["viaAllOf"]
                }],
                "unevaluatedProperties": false
            }),
            json!({"viaAllOf": 1}),
        );
    }

    #[test]
    fn admitted_any_of_unions_all_successful_branch_annotations() {
        assert_admitted_annotations_accept_only_evaluated_members(
            json!({
                "$schema": FINAL_JSON_SCHEMA_DIALECT,
                "anyOf": [
                    {
                        "properties": {"alpha": {"type": "integer"}},
                        "required": ["alpha"]
                    },
                    {
                        "properties": {"beta": {"type": "integer"}},
                        "required": ["beta"]
                    }
                ],
                "unevaluatedProperties": false
            }),
            json!({"alpha": 1, "beta": 2}),
        );
    }

    #[test]
    fn admitted_one_of_uses_only_the_unique_successful_branch_annotations() {
        assert_admitted_annotations_accept_only_evaluated_members(
            json!({
                "$schema": FINAL_JSON_SCHEMA_DIALECT,
                "oneOf": [
                    {
                        "properties": {"alpha": {"type": "integer"}},
                        "required": ["alpha"]
                    },
                    {
                        "properties": {"beta": {"type": "integer"}},
                        "required": ["beta"]
                    }
                ],
                "unevaluatedProperties": false
            }),
            json!({"alpha": 1}),
        );
    }

    #[test]
    fn admitted_dependent_schema_annotations_reach_unevaluated_properties() {
        assert_admitted_annotations_accept_only_evaluated_members(
            json!({
                "$schema": FINAL_JSON_SCHEMA_DIALECT,
                "properties": {"trigger": {"const": true}},
                "required": ["trigger"],
                "dependentSchemas": {
                    "trigger": {
                        "properties": {"payload": {"type": "string"}},
                        "required": ["payload"]
                    }
                },
                "unevaluatedProperties": false
            }),
            json!({"trigger": true, "payload": "ready"}),
        );
    }

    #[test]
    fn admitted_if_without_then_or_else_propagates_successful_annotations() {
        assert_admitted_annotations_accept_only_evaluated_members(
            json!({
                "$schema": FINAL_JSON_SCHEMA_DIALECT,
                "if": {
                    "properties": {"kind": {"const": "ready"}},
                    "required": ["kind"]
                },
                "unevaluatedProperties": false
            }),
            json!({"kind": "ready"}),
        );
    }

    #[test]
    fn admitted_if_and_then_union_successful_annotations() {
        assert_admitted_annotations_accept_only_evaluated_members(
            json!({
                "$schema": FINAL_JSON_SCHEMA_DIALECT,
                "if": {
                    "properties": {"kind": {"const": "ready"}},
                    "required": ["kind"]
                },
                "then": {
                    "properties": {"payload": {"type": "string"}},
                    "required": ["payload"]
                },
                "unevaluatedProperties": false
            }),
            json!({"kind": "ready", "payload": "complete"}),
        );
    }

    #[test]
    fn admitted_else_propagates_only_the_selected_branch_annotations() {
        assert_admitted_annotations_accept_only_evaluated_members(
            json!({
                "$schema": FINAL_JSON_SCHEMA_DIALECT,
                "if": {
                    "properties": {"kind": {"const": "primary"}},
                    "required": ["kind"]
                },
                "else": {
                    "properties": {
                        "kind": {"const": "fallback"},
                        "payload": {"type": "string"}
                    },
                    "required": ["kind", "payload"]
                },
                "unevaluatedProperties": false
            }),
            json!({"kind": "fallback", "payload": "complete"}),
        );
    }

    #[test]
    fn admitted_nested_unevaluated_properties_annotations_reach_outer_schema() {
        assert_admitted_annotations_accept_only_evaluated_members(
            json!({
                "$schema": FINAL_JSON_SCHEMA_DIALECT,
                "allOf": [{
                    "properties": {"nested": {"type": "string"}},
                    "required": ["nested"],
                    "unevaluatedProperties": false
                }],
                "unevaluatedProperties": false
            }),
            json!({"nested": "ready"}),
        );
    }

    fn pattern_property_work_schema() -> AdmittedSchema {
        let mut patterns = serde_json::Map::new();
        for index in 0..MAX_PATTERN_PROPERTIES {
            patterns.insert(format!("^never-{index}$"), Value::Bool(true));
        }
        admit_final_schema(json!({
            "$schema": FINAL_JSON_SCHEMA_DIALECT,
            "type": "object",
            "patternProperties": patterns
        }))
        .expect("the maximum bounded pattern family admits")
    }

    fn object_with_null_members(count: usize) -> Value {
        let members: serde_json::Map<String, Value> = (0..count)
            .map(|index| (format!("field-{index}"), Value::Null))
            .collect();
        Value::Object(members)
    }

    #[test]
    fn admitted_pattern_compilation_and_key_matching_share_work_limit() {
        let schema = pattern_property_work_schema();
        let accepted = object_with_null_members(62);
        schema
            .validate(&accepted)
            .expect("pattern compilation and 62 bounded key scans fit the work budget");

        let planted = object_with_null_members(63);
        let errors = schema
            .validate(&planted)
            .expect_err("adding one key must exceed the shared regex work budget");
        assert!(
            errors
                .iter()
                .any(|error| error.message == "schema validation work limit exceeded")
        );
        assert_eq!(accepted.as_object().unwrap().len(), 62);
    }

    #[test]
    fn raw_pattern_work_remains_legacy_while_admitted_final_is_bounded() {
        let mut patterns = serde_json::Map::new();
        for index in 0..MAX_PATTERN_PROPERTIES {
            patterns.insert(format!("^never-{index}$"), Value::Bool(true));
        }
        let schema = json!({
            "$schema": FINAL_JSON_SCHEMA_DIALECT,
            "type": "object",
            "patternProperties": patterns,
            "additionalProperties": true
        });
        let instance = object_with_null_members(63);

        validate(&schema, &instance)
            .expect("raw validation preserves its legacy pattern-work behavior");
        validate_strict(&schema, &instance)
            .expect("raw strict validation preserves its legacy pattern-work behavior");

        let admitted = admit_final_schema(schema).expect("the bounded final schema admits");
        let errors = admitted
            .validate(&instance)
            .expect_err("admitted-final validation enforces the shared regex work budget");
        assert!(
            errors
                .iter()
                .any(|error| error.message == "schema validation work limit exceeded")
        );
    }

    fn named_property_annotation_work_schema(count: usize) -> AdmittedSchema {
        let properties: serde_json::Map<String, Value> = (0..count)
            .map(|index| (format!("field-{index}"), Value::Bool(true)))
            .collect();
        admit_final_schema(json!({
            "$schema": FINAL_JSON_SCHEMA_DIALECT,
            "type": "object",
            "properties": properties,
            "unevaluatedProperties": false
        }))
        .expect("the bounded named-property schema admits")
    }

    #[test]
    fn admitted_key_annotation_bookkeeping_shares_work_limit() {
        let accepted_schema = named_property_annotation_work_schema(1_364);
        let accepted = object_with_null_members(1_364);
        accepted_schema
            .validate(&accepted)
            .expect("1,364 property validations and annotations fit the work budget");

        let planted_schema = named_property_annotation_work_schema(1_365);
        let planted = object_with_null_members(1_365);
        let errors = planted_schema
            .validate(&planted)
            .expect_err("adding one property must exceed the shared annotation work budget");
        assert!(
            errors
                .iter()
                .any(|error| error.message == "schema validation work limit exceeded")
        );
        assert_eq!(accepted.as_object().unwrap().len(), 1_364);
    }

    fn repeated_pattern_work_schema(units: usize) -> AdmittedSchema {
        let unit = json!({
            "allOf": vec![
                json!({"$ref": "#/$defs/matching-pattern"});
                MAX_COMPOSITION_BRANCHES
            ]
        });
        admit_final_schema(json!({
            "$schema": FINAL_JSON_SCHEMA_DIALECT,
            "$defs": {
                "matching-pattern": {"type": "string", "pattern": "^ready$"}
            },
            "allOf": vec![unit; units]
        }))
        .expect("the bounded repeated-pattern schema admits")
    }

    #[test]
    fn admitted_string_pattern_compilation_and_matching_share_work_limit() {
        repeated_pattern_work_schema(15)
            .validate(&json!("ready"))
            .expect("15 bounded repeated pattern units fit the work budget");

        let errors = repeated_pattern_work_schema(16)
            .validate(&json!("ready"))
            .expect_err("adding one repeated pattern unit must exceed the shared work budget");
        assert!(
            errors
                .iter()
                .any(|error| error.message == "schema validation work limit exceeded")
        );
    }

    fn repeated_branch_probe_work_schema(units: usize) -> AdmittedSchema {
        let mut branches = vec![Value::Bool(false); MAX_COMPOSITION_BRANCHES];
        branches[0] = Value::Bool(true);
        let unit = json!({"oneOf": branches});
        admit_final_schema(json!({
            "$schema": FINAL_JSON_SCHEMA_DIALECT,
            "allOf": vec![unit; units],
            "unevaluatedProperties": true
        }))
        .expect("the bounded repeated-branch schema admits")
    }

    #[test]
    fn admitted_repeated_branch_probes_share_work_limit() {
        repeated_branch_probe_work_schema(10)
            .validate(&json!({}))
            .expect("ten repeated branch-probe units fit the work budget");

        let errors = repeated_branch_probe_work_schema(11)
            .validate(&json!({}))
            .expect_err("adding one repeated branch unit must exceed the shared work budget");
        assert!(
            errors
                .iter()
                .any(|error| error.message == "schema validation work limit exceeded")
        );
    }

    fn final_schema_format_schema() -> AdmittedSchema {
        admit_final_schema(json!({
            "$schema": FINAL_JSON_SCHEMA_DIALECT,
            "type": "object",
            "properties": {
                "data": {"type": "string", "format": "byte"},
                "uri": {"type": "string", "format": "uri"},
                "template": {"type": "string", "format": "uri-template"}
            },
            "required": ["data", "uri", "template"],
            "additionalProperties": false
        }))
        .expect("the pinned final format family admits")
    }

    fn final_schema_format_instance() -> Value {
        json!({
            "data": "cGlubmVkIGZpbmFs",
            "uri": "https://example.test/resources?id=1#ready",
            "template": "mcp://resources/{id}{?cursor}"
        })
    }

    #[test]
    fn final_schema_format_positive() {
        final_schema_format_schema()
            .validate(&final_schema_format_instance())
            .expect("the pinned byte, uri, and uri-template formats validate");
    }

    #[test]
    fn final_schema_format_planted_negative() {
        let schema = final_schema_format_schema();
        let accepted = final_schema_format_instance();
        let mut planted = accepted.clone();
        planted["uri"] = json!("not a uri");

        let errors = schema
            .validate(&planted)
            .expect_err("changing only the uri field to a non-URI must reject");
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "root.uri");
        assert_eq!(errors[0].message, "string does not match format \"uri\"");
        assert_eq!(accepted, final_schema_format_instance());
    }

    #[test]
    fn final_schema_uri_template_format_uses_level_four_parser() {
        let schema = final_schema_format_schema();
        let mut accepted = final_schema_format_instance();
        accepted["template"] = json!("mcp://resources/{item:3}{?cursor,labels*}");
        schema
            .validate(&accepted)
            .expect("a valid RFC 6570 Level 4 resource template is admitted");

        let mut planted = accepted.clone();
        planted["template"] = json!("mcp://resources/{item:0}{?cursor,labels*}");
        let errors = schema
            .validate(&planted)
            .expect_err("changing only the positive prefix length to zero must reject");
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "root.template");
        assert_eq!(
            errors[0].message,
            "string does not match format \"uri-template\""
        );
        assert_eq!(
            accepted["template"],
            json!("mcp://resources/{item:3}{?cursor,labels*}"),
            "a rejected format value cannot mutate the accepted instance"
        );
    }

    #[test]
    fn schema_admission_node_limit_positive_and_planted_negative() {
        let mut properties = serde_json::Map::new();
        for index in 0..(MAX_SCHEMA_ADMISSION_NODES - 1) {
            properties.insert(format!("field-{index}"), Value::Bool(true));
        }
        let accepted = json!({"type": "object", "properties": properties});
        admit_final_schema(accepted.clone())
            .expect("the exact schema-admission node budget is accepted");

        let mut planted = accepted.clone();
        planted["properties"]
            .as_object_mut()
            .expect("schema properties stay an object")
            .insert(
                format!("field-{}", MAX_SCHEMA_ADMISSION_NODES - 1),
                Value::Bool(true),
            );
        let error = admit_final_schema(planted)
            .expect_err("adding one schema node beyond the admission budget must reject");
        assert_eq!(error.reason(), "schema admission node limit exceeded");
        assert_eq!(
            accepted["properties"].as_object().unwrap().len(),
            MAX_SCHEMA_ADMISSION_NODES - 1
        );
    }

    #[test]
    fn instance_node_limit_positive_and_planted_negative() {
        let schema = admit_final_schema(json!({"type": "array", "items": true}))
            .expect("the bounded array schema admits");
        let accepted = Value::Array(vec![Value::Null; MAX_SCHEMA_INSTANCE_NODES - 1]);
        schema
            .validate(&accepted)
            .expect("the exact instance-node budget is accepted");

        let mut planted = accepted.clone();
        planted.as_array_mut().unwrap().push(Value::Null);
        let errors = schema
            .validate(&planted)
            .expect_err("adding one instance node beyond the budget must reject");
        assert_eq!(
            errors[0].path,
            format!("root[{}]", MAX_SCHEMA_INSTANCE_NODES - 1)
        );
        assert_eq!(errors[0].message, "instance node limit exceeded");
        assert_eq!(
            accepted.as_array().unwrap().len(),
            MAX_SCHEMA_INSTANCE_NODES - 1
        );
    }

    fn composition_work_schema(branches: usize) -> Value {
        let unit = json!({"allOf": vec![Value::Bool(true); MAX_COMPOSITION_BRANCHES]});
        json!({"allOf": vec![unit; branches]})
    }

    #[test]
    fn composition_work_limit_positive_and_planted_negative() {
        let accepted = composition_work_schema(MAX_COMPOSITION_BRANCHES - 1);
        validate(&accepted, &Value::Null)
            .expect("the exact shared composition-work budget is accepted");

        let planted = composition_work_schema(MAX_COMPOSITION_BRANCHES);
        let errors = validate(&planted, &Value::Null)
            .expect_err("adding one composition branch beyond the shared work budget must reject");
        assert!(
            errors
                .iter()
                .any(|error| error.message == "schema validation work limit exceeded")
        );
        assert_eq!(
            accepted["allOf"].as_array().unwrap().len(),
            MAX_COMPOSITION_BRANCHES - 1
        );
    }

    #[test]
    fn admitted_schema_rejects_unresolved_local_reference() {
        let error = admit_final_schema(json!({"$ref": "#/$defs/missing"}))
            .expect_err("unresolved local references fail before validation");
        assert_eq!(error.path(), "$.$ref");
        assert_eq!(error.reason(), "unresolved local schema reference");
    }

    #[test]
    fn external_references_fail_closed_without_resolution() {
        let errors = validate(
            &json!({"$ref": "https://schemas.example.test/tool.json"}),
            &json!({"input": "value"}),
        )
        .expect_err("external references must not acquire network or filesystem authority");

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "root");
        assert_eq!(
            errors[0].message,
            "external schema reference is not allowed"
        );
    }

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
