//! Bounded object composition for Serde flattening and tagged newtypes.
//!
//! Flattening copies object members, not an `allOf` of closed objects or maps.
//! Property schemas keep the generation document's original reference scope.

use super::{JsonSchemaType, SchemaAdmissionError, SchemaGenerationError, SchemaGenerator};
use serde_json::{Map, Value};
use std::any::TypeId;
use std::collections::BTreeSet;

/// Object-shape evidence emitted for a nontransparent named-struct derive.
///
/// This is an implementation detail of `#[derive(JsonSchema)]`. A handwritten
/// provider cannot be flattened merely because its root happens to be an
/// object: its resource scope and arbitrary applicators must be preserved.
#[doc(hidden)]
pub trait FlattenableSchemaObject: JsonSchemaType {
    /// Whether Serde's container closes unknown fields.
    const DENY_UNKNOWN_FIELDS: bool;
    /// Whether this object itself uses one or more non-skipped flattened fields.
    const HAS_FLATTEN_FIELDS: bool;
}

/// Collects one named object's fields and optional final catch-all map.
///
/// Generated code inserts ordinary fields before flattened fields, matching
/// Serde's removal of ordinary members before its flattened-field visitors run.
/// Every failure is sticky on the shared generator; no partial object can be
/// published by `SchemaGenerator::finish`.
#[doc(hidden)]
#[derive(Default)]
pub struct FlattenedObjectSchema {
    properties: Map<String, Value>,
    required: BTreeSet<String>,
    catch_all: Option<Value>,
    nested_flatten: bool,
}

impl FlattenedObjectSchema {
    /// Starts an independent object inside the caller's generation document.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Composes the discriminator of an internally tagged newtype with one
    /// derived named-object payload. The cached payload body remains unchanged
    /// so another variant or an ordinary property can reuse its original refs.
    ///
    /// This deliberately shares the bounded object-composition profile with
    /// flattening. Arbitrary root applicators/resources, closed payloads and
    /// catch-all maps require an explicit schema; no constraint is discarded.
    #[must_use]
    pub fn internally_tagged<T: FlattenableSchemaObject>(
        context: &mut SchemaGenerator,
        tag: &str,
        variant: &str,
    ) -> Value {
        if context.error.is_some() {
            return Value::Bool(false);
        }
        if T::DENY_UNKNOWN_FIELDS {
            context.reject_flatten(
                "$",
                "internally tagged newtype payloads with deny_unknown_fields require an explicit schema",
            );
            return Value::Bool(false);
        }
        let mut object = Self::new();
        object.flatten::<T>(context);
        if context.error.is_some() {
            return Value::Bool(false);
        }
        if object.properties.contains_key(tag) {
            context.reject_flatten(
                tag,
                "internally tagged newtype payload property conflicts with the serde tag key",
            );
            return Value::Bool(false);
        }
        // Bound both caller-supplied strings before constructing the tag's
        // schema. property() then charges its complete retained representation,
        // including the separately retained required property name.
        if tag
            .len()
            .checked_add(variant.len())
            .is_none_or(|bytes| bytes > context.limits.max_bytes.saturating_sub(context.bytes))
        {
            context.error = Some(SchemaGenerationError::ByteLimit);
            return Value::Bool(false);
        }
        object.property(
            context,
            tag,
            serde_json::json!({ "type": "string", "const": variant }),
            true,
        );
        object.finish()
    }

    /// Adds an ordinary field without silently replacing a renamed collision.
    pub fn property(
        &mut self,
        context: &mut SchemaGenerator,
        name: &str,
        schema: Value,
        required: bool,
    ) {
        if context.error.is_some() {
            return;
        }
        if self.properties.contains_key(name) {
            context.reject_flatten(name, "flattened object property names must be distinct");
            return;
        }
        // Bound the key before retaining it, then account for the complete
        // newly retained member, including its value and object overhead.
        if name.len() > context.limits.max_bytes.saturating_sub(context.bytes) {
            context.error = Some(SchemaGenerationError::ByteLimit);
            return;
        }
        let mut member = Map::new();
        member.insert(name.to_owned(), schema);
        let member = Value::Object(member);
        // Conservatively charge a second member for the separately retained
        // required name before cloning that name into the required set.
        if context
            .account(&member, if required { 2 } else { 1 })
            .is_none()
        {
            return;
        }
        let Value::Object(member) = member else {
            unreachable!()
        };
        let (name, schema) = member.into_iter().next().expect("one composed property");
        if required {
            self.required.insert(name.clone());
        }
        self.properties.insert(name, schema);
    }

    /// Merges the completed, bounded body of one derived named object.
    pub fn flatten<T: FlattenableSchemaObject>(&mut self, context: &mut SchemaGenerator) {
        if context.error.is_some() {
            return;
        }
        if self.catch_all.is_some() {
            context.reject_flatten("$", "the flattened catch-all map must be last");
            return;
        }
        if T::DENY_UNKNOWN_FIELDS {
            context.reject_flatten(
                "$",
                "serde(flatten) cannot compose a deny_unknown_fields object; use an explicit schema",
            );
            return;
        }
        let Some(body) = context.completed_flatten_body::<T>() else {
            return;
        };
        let Value::Object(mut body) = body else {
            context.reject_flatten("$", "serde(flatten) requires a derived named object");
            return;
        };
        if body.get("type").and_then(Value::as_str) != Some("object")
            || body.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "type" | "properties" | "required" | "description"
                )
            })
        {
            // Do not strip $id, $defs, applicators, closure, or a nested map.
            // Their meaning cannot be recovered by moving only properties.
            context.reject_flatten(
                "$",
                "flattened object resources, applicators, closure, and nested catch-all maps require an explicit schema",
            );
            return;
        }
        let Some(Value::Object(properties)) = body.remove("properties") else {
            context.reject_flatten("$", "flattened object properties must be an object");
            return;
        };
        let Some(Value::Array(required)) = body.remove("required") else {
            context.reject_flatten("$", "flattened object required fields must be an array");
            return;
        };
        let mut required_names = BTreeSet::new();
        for name in required {
            let Value::String(name) = name else {
                context.reject_flatten("$", "flattened required names must be strings");
                return;
            };
            if !properties.contains_key(&name) || !required_names.insert(name) {
                context.reject_flatten(
                    "$",
                    "flattened required names must identify distinct properties",
                );
                return;
            }
        }
        if let Some(name) = properties
            .keys()
            .find(|name| self.properties.contains_key(*name))
        {
            context.reject_flatten(name, "flattened object property names must be distinct");
            return;
        }
        // completed_flatten_body charged the copied body before cloning it.
        // Moving its members here preserves property $refs and nested $ids.
        self.properties.extend(properties);
        self.required.extend(required_names);
        self.nested_flatten |= T::HAS_FLATTEN_FIELDS;
    }

    /// Installs the value schema for a single final flattened String-keyed map.
    pub fn catch_all(&mut self, context: &mut SchemaGenerator, value_schema: Value) {
        if context.error.is_some() {
            return;
        }
        if self.catch_all.is_some() {
            context.reject_flatten("$", "only one flattened catch-all map is supported");
            return;
        }
        if self.nested_flatten {
            // A nested flattened object's Serde map visitor does not consume
            // the same parent entries as a plain named-struct visitor. Treating
            // every merged name as removed would weaken the following map.
            context.reject_flatten(
                "$",
                "a catch-all map after a nested flattened object requires an explicit schema",
            );
            return;
        }
        if context.account(&value_schema, 1).is_some() {
            self.catch_all = Some(value_schema);
        }
    }

    /// Returns the composed body for the generator's normal admission step.
    #[must_use]
    pub fn finish(self) -> Value {
        // Move the charged members rather than serializing or cloning them
        // into another intermediate copy of the object.
        let mut schema = Map::new();
        schema.insert("type".to_owned(), Value::String("object".to_owned()));
        schema.insert("properties".to_owned(), Value::Object(self.properties));
        schema.insert(
            "required".to_owned(),
            Value::Array(self.required.into_iter().map(Value::String).collect()),
        );
        if let Some(catch_all) = self.catch_all {
            schema.insert("additionalProperties".to_owned(), catch_all);
        }
        Value::Object(schema)
    }
}

impl SchemaGenerator {
    fn reject_flatten(&mut self, property: &str, reason: &'static str) {
        if self.error.is_none() {
            self.error = Some(SchemaGenerationError::InvalidSchema(
                SchemaAdmissionError::new(property, reason),
            ));
        }
    }

    /// A repeated type may have returned only a $ref, but flattening needs its
    /// completed object body. The cache remains the source of truth; copying
    /// it never follows arbitrary reference URIs or recursively expands refs.
    fn completed_flatten_body<T: FlattenableSchemaObject>(&mut self) -> Option<Value> {
        drop(self.subschema_for::<T>());
        if self.error.is_some() {
            return None;
        }
        let identity = TypeId::of::<T>();
        let Some(body) = self
            .definitions
            .get_mut(&identity)
            .and_then(|entry| entry.body.take())
        else {
            self.reject_flatten(
                "$",
                "recursive flatten expansion requires an explicit schema; recursive ordinary fields remain supported",
            );
            return None;
        };
        // Temporarily move the cached body so accounting can borrow the whole
        // generator. Restore it on both success and failure, and clone only
        // after the additional retained copy fits the aggregate limits.
        let result = self.account(&body, 1).map(|_| body.clone());
        self.definitions
            .get_mut(&identity)
            .expect("generated flatten definition")
            .body = Some(body);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ConstrainedObject<const CASE: u8>;

    impl<const CASE: u8> JsonSchemaType for ConstrainedObject<CASE> {
        fn schema_body(_: &mut SchemaGenerator) -> Value {
            let mut schema = serde_json::json!({
                "type":"object", "properties":{"name":{"type":"string"}}, "required":["name"],
            });
            match CASE {
                0 => schema["$id"] = serde_json::json!("https://schemas.example.test/flatten-root"),
                1 => schema["allOf"] = serde_json::json!([{"minProperties":2}]),
                2 => schema["additionalProperties"] = Value::Bool(false),
                _ => schema["$defs"] = serde_json::json!({"choice":{"const":"fixed"}}),
            }
            schema
        }
    }

    impl<const CASE: u8> FlattenableSchemaObject for ConstrainedObject<CASE> {
        const DENY_UNKNOWN_FIELDS: bool = false;
        const HAS_FLATTEN_FIELDS: bool = false;
    }

    fn constrained_root_is_refused<const CASE: u8>() {
        let mut context = SchemaGenerator::new();
        let mut object = FlattenedObjectSchema::new();
        object.flatten::<ConstrainedObject<CASE>>(&mut context);
        let error = context
            .finish(object.finish())
            .expect_err("composition must not discard a root resource or constraint");
        assert!(
            error
                .to_string()
                .contains("resources, applicators, closure"),
            "{error}"
        );
    }

    #[test]
    fn flattened_root_constraints_cannot_be_stripped_by_a_handwritten_marker() {
        constrained_root_is_refused::<0>();
        constrained_root_is_refused::<1>();
        constrained_root_is_refused::<2>();
        constrained_root_is_refused::<3>();
    }

    struct PlainObject;

    impl JsonSchemaType for PlainObject {
        fn schema_body(_: &mut SchemaGenerator) -> Value {
            serde_json::json!({
                "type":"object", "properties":{"name":{"type":"string"}}, "required":["name"],
            })
        }
    }

    impl FlattenableSchemaObject for PlainObject {
        const DENY_UNKNOWN_FIELDS: bool = false;
        const HAS_FLATTEN_FIELDS: bool = false;
    }

    #[test]
    fn internal_tagging_keeps_shared_payload_bodies_unmodified() {
        let mut context = SchemaGenerator::new();
        drop(context.subschema_for::<PlainObject>());
        let cached = context.definitions[&TypeId::of::<PlainObject>()]
            .body
            .clone()
            .unwrap();
        let first =
            FlattenedObjectSchema::internally_tagged::<PlainObject>(&mut context, "kind", "first");
        let second =
            FlattenedObjectSchema::internally_tagged::<PlainObject>(&mut context, "kind", "second");
        assert_eq!(
            context.definitions[&TypeId::of::<PlainObject>()]
                .body
                .as_ref(),
            Some(&cached)
        );
        let document = context
            .finish(serde_json::json!({"oneOf":[first,second]}))
            .unwrap();
        let schema = super::super::admit_final_schema(document).unwrap();
        for variant in ["first", "second"] {
            schema
                .validate(&serde_json::json!({"kind":variant,"name":"present"}))
                .unwrap();
            assert!(
                schema
                    .validate(&serde_json::json!({"kind":variant}))
                    .is_err()
            );
        }
        assert!(
            schema
                .validate(&serde_json::json!({"kind":"third","name":"present"}))
                .is_err()
        );
    }

    #[test]
    fn internal_tagging_preserves_root_constraint_and_discriminator_budget_failures() {
        fn constrained<const CASE: u8>() {
            let mut context = SchemaGenerator::new();
            let root = FlattenedObjectSchema::internally_tagged::<ConstrainedObject<CASE>>(
                &mut context,
                "kind",
                "value",
            );
            assert!(matches!(
                context.finish(root),
                Err(SchemaGenerationError::InvalidSchema(_))
            ));
        }
        constrained::<0>();
        constrained::<1>();
        constrained::<2>();
        constrained::<3>();

        let mut context = SchemaGenerator::new();
        let cached = context.subschema_for::<PlainObject>();
        let limit = context.limits.max_bytes;
        let oversized = "x".repeat(limit + 1);
        let root = FlattenedObjectSchema::internally_tagged::<PlainObject>(
            &mut context,
            "kind",
            &oversized,
        );
        assert_eq!(context.error, Some(SchemaGenerationError::ByteLimit));
        assert_eq!(
            context.definitions[&TypeId::of::<PlainObject>()]
                .body
                .as_ref(),
            Some(&cached)
        );
        assert!(matches!(
            context.finish(root),
            Err(SchemaGenerationError::ByteLimit)
        ));
    }

    #[test]
    fn copying_a_cached_flatten_body_obeys_the_remaining_budget_and_restores_the_cache() {
        let mut context = SchemaGenerator::new();
        drop(context.subschema_for::<PlainObject>());
        let cached = context.definitions[&TypeId::of::<PlainObject>()]
            .body
            .clone()
            .unwrap();
        let reference_nodes = 2;
        // The reference lookup fits; another complete body does not. This
        // isolates the flatten copy from initial derivation and final admission.
        context.limits.max_nodes = context.nodes + reference_nodes;
        let mut object = FlattenedObjectSchema::new();
        object.flatten::<PlainObject>(&mut context);
        assert_eq!(context.error, Some(SchemaGenerationError::NodeLimit));
        assert_eq!(
            context.definitions[&TypeId::of::<PlainObject>()]
                .body
                .as_ref(),
            Some(&cached)
        );
        assert!(
            object.properties.is_empty(),
            "a refused copy cannot leak partial properties"
        );
        assert!(matches!(
            context.finish(object.finish()),
            Err(SchemaGenerationError::NodeLimit)
        ));

        let mut healthy = SchemaGenerator::new();
        let mut object = FlattenedObjectSchema::new();
        object.flatten::<PlainObject>(&mut healthy);
        let schema = healthy.finish(object.finish()).unwrap();
        assert!(
            super::super::admit_final_schema(schema)
                .unwrap()
                .validate(&serde_json::json!({"name":"preserved"}),)
                .is_ok()
        );
    }
}
