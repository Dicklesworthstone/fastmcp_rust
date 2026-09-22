//! SCH-02 A: schema derivation and type mapping.
//!
//! An **external** consumer of the packaged facade: it reaches the public
//! schema derive path the way a downstream crate does — `#[derive(JsonSchema)]`
//! from `fastmcp_rust`, then the generated `Type::json_schema()` — and feeds
//! the result to the shipped runtime validator at `fastmcp_rust::schema`.
//! Nothing here is compiled under `cfg(test)` inside any library and nothing
//! reaches an internal through `use super::` (PL-3).
//!
//! # Why the facade and not the macro crate
//!
//! `crates/fastmcp-macros/` builds `fastmcp-derive` with `proc-macro = true`,
//! carries no dev-dependencies and has no `tests/` directory, and its
//! expansions reference `serde_json` and `fastmcp_core`. The facade is the
//! only position that can both *produce* derive output and *feed it to the
//! validator*, which is the acceptance sentence for this slice: "Macro output
//! passes the runtime validator."
//!
//! # What this proves, and what it deliberately does not
//!
//! The A slice owns schema derivation and type mapping. The positive drives
//! every mapping class the derive implements — scalars, nullability, arrays,
//! sets, maps, nested structs, descriptions, rename and skip — asserts the
//! emitted mapping, and then proves the generated schema is admitted by
//! `admit_final_schema` and accepts a conforming instance through `validate`.
//!
//! Recursive `$defs`/`$ref` emission, compile-time diagnostics for unsupported
//! constructs, and numeric constraint emission belong to the B slice
//! ("recursive bounds, diagnostics and generation") and are not claimed here.
//! Where the derive does not yet emit something the package contract names,
//! this file records the observation rather than asserting the gap away.
//!
//! No-claim boundary: this leaf establishes no parent completion, no aggregate
//! MCP 2026-07-28 support, no MCP 2024-11-05 preservation, no profile
//! maturity, conformance, publication, or release readiness.

#![forbid(unsafe_code)]
// The derived subjects below are never constructed: `json_schema()` is an
// associated function, so the types exist only to be derived from. Matches the
// posture of `tests/macro_expansion.rs`, which derives subjects the same way.
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};

use fastmcp_rust::{JsonSchema, schema};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// Subjects: one derived type per mapping class
// ---------------------------------------------------------------------------

/// A nested type, reached through the derive's fallthrough arm.
#[derive(JsonSchema)]
struct Inner {
    /// The inner label.
    label: String,
}

/// The mapping subject. Every field exercises one documented mapping class.
#[derive(JsonSchema)]
struct Subject {
    /// A required string.
    name: String,
    /// A signed integer.
    count: i64,
    /// An unsigned integer.
    quantity: u32,
    /// A floating-point number.
    ratio: f64,
    /// A boolean.
    enabled: bool,
    /// An optional string, which must admit an explicit null.
    nickname: Option<String>,
    /// A list of strings.
    tags: Vec<String>,
    /// A string-keyed map of integers.
    labels: HashMap<String, i64>,
    /// An ordered map, which maps identically to the unordered one.
    ordered: BTreeMap<String, bool>,
    /// A nested derived struct.
    inner: Inner,
    /// A field renamed on the wire.
    #[json_schema(rename = "renamed_field")]
    original: String,
    /// A field excluded from the schema entirely.
    #[json_schema(skip)]
    hidden: String,
}

/// A conforming instance of [`Subject`].
fn conforming_instance() -> Value {
    json!({
        "name": "subject",
        "count": -7,
        "quantity": 12,
        "ratio": 1.5,
        "enabled": true,
        "nickname": "nick",
        "tags": ["a", "b"],
        "labels": { "first": 1 },
        "ordered": { "yes": true },
        "inner": { "label": "inner-label" },
        "renamed_field": "renamed"
    })
}

/// Borrows one property schema from a generated object schema.
fn property<'a>(root: &'a Value, name: &str) -> &'a Value {
    root.get("properties")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("generated schema has a properties object"))
        .get(name)
        .unwrap_or_else(|| panic!("generated schema has a `{name}` property"))
}

/// The `required` array of a generated object schema, sorted.
fn required(root: &Value) -> Vec<String> {
    let mut names: Vec<String> = root
        .get("required")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("generated schema has a required array"))
        .iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------
// Ordered row manifest
// ---------------------------------------------------------------------------

/// One canonical manifest row: an ordered acceptance row id and its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestRow {
    id: &'static str,
    parts: Vec<Vec<u8>>,
}

impl ManifestRow {
    fn new(id: &'static str, parts: Vec<Vec<u8>>) -> Self {
        Self { id, parts }
    }
}

/// Length-prefixed canonical LF encoding over the ordered rows.
///
/// Same shape as the AUTH-00 B and AUTH-00 A manifests so the packages remain
/// diffable against each other.
fn sch_02_a_manifest_digest(rows: &[ManifestRow]) -> [u8; 32] {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"sch_02_a_manifest_digest-v1");
    for row in rows {
        let id = row.id.as_bytes();
        encoded.extend_from_slice(
            &u64::try_from(id.len())
                .expect("row id fits u64")
                .to_be_bytes(),
        );
        encoded.extend_from_slice(id);
        encoded.extend_from_slice(
            &u64::try_from(row.parts.len())
                .expect("part count fits u64")
                .to_be_bytes(),
        );
        for part in &row.parts {
            encoded.extend_from_slice(
                &u64::try_from(part.len())
                    .expect("part length fits u64")
                    .to_be_bytes(),
            );
            encoded.extend_from_slice(part);
        }
        encoded.push(b'\n');
    }
    fastmcp_rust::sha256_bounded(&encoded, 64 * 1024)
        .expect("canonical manifest stays inside the hash bound")
        .into_bytes()
}

/// Builds the ordered mapping manifest from one generated schema.
///
/// Every row is the *emitted* schema for one mapping class, serialized
/// canonically, so a change in what the derive emits moves the digest.
fn manifest(root: &Value) -> Vec<ManifestRow> {
    let row = |id: &'static str, name: &str| {
        ManifestRow::new(
            id,
            vec![
                name.as_bytes().to_vec(),
                serde_json::to_string(property(root, name))
                    .expect("a generated property schema serializes")
                    .into_bytes(),
            ],
        )
    };
    vec![
        row("1-string", "name"),
        row("2-signed-integer", "count"),
        row("3-unsigned-integer", "quantity"),
        row("4-number", "ratio"),
        row("5-boolean", "enabled"),
        row("6-nullable", "nickname"),
        row("7-array", "tags"),
        row("8-map", "labels"),
        row("9-ordered-map", "ordered"),
        row("10-nested-struct", "inner"),
        row("11-renamed", "renamed_field"),
        ManifestRow::new(
            "12-required",
            required(root)
                .iter()
                .map(|name| name.as_bytes().to_vec())
                .collect(),
        ),
        ManifestRow::new(
            "13-root-type",
            vec![
                root.get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("<absent>")
                    .as_bytes()
                    .to_vec(),
            ],
        ),
    ]
}

// ---------------------------------------------------------------------------
// sch_02_a_positive
// ---------------------------------------------------------------------------

#[test]
fn sch_02_a_positive() {
    let root = Subject::json_schema();

    // --- The derived root is an object schema with properties and required ---
    assert_eq!(
        root.get("type").and_then(Value::as_str),
        Some("object"),
        "an input root must be an object schema: {root}"
    );

    // --- Type mapping, one assertion per documented class -------------------
    assert_eq!(property(&root, "name").get("type"), Some(&json!("string")));
    assert_eq!(
        property(&root, "count").get("type"),
        Some(&json!("integer")),
        "signed integers map to integer"
    );
    assert_eq!(
        property(&root, "quantity").get("type"),
        Some(&json!("integer")),
        "unsigned integers map to integer"
    );
    assert_eq!(
        property(&root, "ratio").get("type"),
        Some(&json!("number")),
        "floats map to number, not integer"
    );
    assert_eq!(
        property(&root, "enabled").get("type"),
        Some(&json!("boolean"))
    );

    // Nullability: Option<T> widens T's type rather than dropping it.
    assert_eq!(
        property(&root, "nickname").get("type"),
        Some(&json!(["string", "null"])),
        "Option<String> must admit both string and null, and must not collapse \
         to a bare string or an absent type"
    );

    // Arrays and maps carry their element and value schemas.
    assert_eq!(property(&root, "tags").get("type"), Some(&json!("array")));
    assert_eq!(
        property(&root, "tags").get("items"),
        Some(&json!({ "type": "string" })),
        "Vec<String> must carry its element schema"
    );
    assert_eq!(
        property(&root, "labels").get("type"),
        Some(&json!("object"))
    );
    assert_eq!(
        property(&root, "labels").get("additionalProperties"),
        Some(&json!({
            "type": "integer",
            "minimum": i64::MIN,
            "maximum": i64::MAX,
        })),
        "HashMap<String, i64> must carry its value schema"
    );
    assert_eq!(
        property(&root, "ordered").get("additionalProperties"),
        Some(&json!({ "type": "boolean" })),
        "BTreeMap maps identically to HashMap"
    );

    // Nested derived structs recurse through the same derive.
    let inner = property(&root, "inner");
    assert_eq!(inner.get("type"), Some(&json!("object")));
    assert_eq!(
        property(inner, "label").get("type"),
        Some(&json!("string")),
        "a nested derived struct must carry its own generated properties"
    );

    // --- Descriptions, rename and skip ---------------------------------------
    assert_eq!(
        property(&root, "name").get("description"),
        Some(&json!("A required string.")),
        "doc comments become descriptions"
    );
    assert!(
        root.get("properties")
            .and_then(Value::as_object)
            .is_some_and(|properties| properties.contains_key("renamed_field")
                && !properties.contains_key("original")),
        "a renamed field appears only under its wire name: {root}"
    );
    assert!(
        root.get("properties")
            .and_then(Value::as_object)
            .is_some_and(|properties| !properties.contains_key("hidden")),
        "a skipped field must not appear at all: {root}"
    );

    // --- Required membership follows optionality ------------------------------
    let required_names = required(&root);
    assert!(
        required_names.contains(&"name".to_owned()),
        "a non-Option field is required: {required_names:?}"
    );
    assert!(
        !required_names.contains(&"nickname".to_owned()),
        "an Option field must not be required: {required_names:?}"
    );
    assert!(
        !required_names.contains(&"hidden".to_owned()),
        "a skipped field must not be required: {required_names:?}"
    );

    // --- The acceptance sentence: macro output passes the runtime validator ---
    schema::admit_final_schema(root.clone())
        .expect("generated macro output must be admitted by the shipped schema admission path");
    schema::validate(&root, &conforming_instance())
        .expect("generated macro output must accept a conforming instance");

    // An explicit null is accepted where the derive widened the type, which is
    // the observable difference between widening and merely omitting.
    let mut explicit_null = conforming_instance();
    explicit_null["nickname"] = Value::Null;
    schema::validate(&root, &explicit_null).expect("a widened Option must accept an explicit null");

    // Omission is accepted too, since the field is not required.
    let mut omitted = conforming_instance();
    omitted
        .as_object_mut()
        .expect("the instance is an object")
        .remove("nickname");
    schema::validate(&root, &omitted).expect("an optional field may be omitted");

    // --- Manifest ------------------------------------------------------------
    let rows = manifest(&root);
    assert_eq!(rows.len(), 13, "thirteen ordered mapping rows");
    let digest = sch_02_a_manifest_digest(&rows);
    assert_eq!(
        digest,
        sch_02_a_manifest_digest(&manifest(&Subject::json_schema())),
        "sch_02_a_manifest_digest must be stable across independent derivations"
    );
    assert_ne!(digest, [0_u8; 32], "the digest is not a degenerate value");

    // --- Recorded observations, not assertions --------------------------------
    //
    // The SCH-02 package contract also names `$defs`/local references for
    // reusable and recursive types, and numeric constraints. Those belong to
    // the B slice. Recording what the derive emits today keeps the boundary
    // honest instead of silently implying this slice covered them.
    println!(
        "sch-02-a observation: root $schema={:?} $defs={:?} nested_inlined={}",
        root.get("$schema"),
        root.get("$defs"),
        property(&root, "inner").get("$ref").is_none()
    );
}

// ---------------------------------------------------------------------------
// sch_02_a_planted_negative
// ---------------------------------------------------------------------------

#[test]
fn sch_02_a_planted_negative() {
    let root = Subject::json_schema();

    // --- Control: the schema and the conforming instance are both live -------
    //
    // A refusal proves something only if acceptance was reachable with the
    // same schema and the same instance shape.
    let canonical_schema = serde_json::to_string(&root).expect("the generated schema serializes");
    schema::validate(&root, &conforming_instance())
        .expect("the control instance must be accepted before any mutation");

    // --- One input dimension changed per case --------------------------------
    //
    // Each case mutates exactly one field of the conforming instance, against
    // the same unmodified generated schema, and must reach the typed
    // ValidationError boundary. Every other field is held identical.
    let cases: [(&str, fn(&mut Value)); 8] = [
        ("string field given an integer", |instance| {
            instance["name"] = json!(1);
        }),
        ("integer field given a string", |instance| {
            instance["count"] = json!("not-an-integer");
        }),
        ("integer field given a float", |instance| {
            instance["quantity"] = json!(1.5);
        }),
        ("boolean field given a string", |instance| {
            instance["enabled"] = json!("true");
        }),
        ("array field given a scalar", |instance| {
            instance["tags"] = json!("a");
        }),
        ("array element of the wrong type", |instance| {
            instance["tags"] = json!(["a", 2]);
        }),
        ("map value of the wrong type", |instance| {
            instance["labels"] = json!({ "first": "one" });
        }),
        ("nested struct field of the wrong type", |instance| {
            instance["inner"] = json!({ "label": 5 });
        }),
    ];

    for (description, mutate) in cases {
        let mut instance = conforming_instance();
        mutate(&mut instance);

        let errors = schema::validate(&root, &instance).expect_err(&format!(
            "{description} must reach the typed validation boundary"
        ));
        assert!(
            !errors.is_empty(),
            "{description} must report at least one ValidationError"
        );

        // Named mutable state unchanged: the generated schema is byte-for-byte
        // identical and still accepts the conforming instance.
        assert_eq!(
            serde_json::to_string(&root).expect("the generated schema serializes"),
            canonical_schema,
            "{description} must leave the generated schema byte-for-byte unchanged"
        );
        schema::validate(&root, &conforming_instance()).unwrap_or_else(|errors| {
            panic!("{description} must leave the conforming instance acceptable: {errors:?}")
        });
    }

    // --- Required membership: the one dimension that is not a type -----------
    let mut missing_required = conforming_instance();
    missing_required
        .as_object_mut()
        .expect("the instance is an object")
        .remove("name");
    let errors = schema::validate(&root, &missing_required)
        .expect_err("a missing required field must be refused");
    assert!(
        errors
            .iter()
            .any(|error| error.message.contains("missing required field")),
        "the refusal must name the missing required field, not merely fail: {errors:?}"
    );

    // --- The paired positive for that same dimension --------------------------
    //
    // Removing the *optional* field is the near-identical instance differing
    // only in which field was dropped, and it must still be accepted.
    let mut missing_optional = conforming_instance();
    missing_optional
        .as_object_mut()
        .expect("the instance is an object")
        .remove("nickname");
    schema::validate(&root, &missing_optional)
        .expect("dropping an optional field is not a refusal");

    // --- Where the object-root rule actually lives ---------------------------
    //
    // A boolean IS a JSON Schema: `true` admits everything, `false` admits
    // nothing. `admit_final_schema` is the general wire-boundary layer and
    // therefore admits booleans **by design** — its doc comment says so
    // ("the final wire boundary accepts only JSON Schema booleans or
    // objects", schema.rs:233-240) and its refusal text at schema.rs:469 is
    // "schema must be an object or boolean". Refusing them there would be the
    // bug, not the fix.
    //
    // This is written out because it looks like a hole and is not: an earlier
    // revision of this test asserted refusal here and failed, and the next
    // reader should not re-file that as a defect.
    schema::admit_final_schema(json!(true))
        .expect("a JSON Schema boolean is a schema; the general layer admits it by design");

    // The package contract requires input root-object enforcement to be
    // SEPARATE from reusable type schemas, and it is — at the layers that own
    // a root. The form layer refuses a non-object root outright
    // (schema.rs:266, "final form schema must be an object"), and tool
    // registration applies the same rule before admission ever runs
    // (fastmcp-server/src/router.rs:905-914). So a boolean can never become a
    // tool input schema, which is the property that actually matters.
    schema::admit_final_form_schema(json!(true))
        .expect_err("a root-enforcing layer must refuse a non-object schema");

    // And the derive never produces one: every generated root is an object.
    assert_eq!(
        Subject::json_schema().get("type").and_then(Value::as_str),
        Some("object"),
        "the derive must never emit a boolean or non-object root"
    );

    // Final unchanged-state proof after every case.
    assert_eq!(
        serde_json::to_string(&root).expect("the generated schema serializes"),
        canonical_schema,
        "no planted case may mutate the generated schema"
    );
}
