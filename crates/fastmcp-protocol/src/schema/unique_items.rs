//! Bounded semantic indexing for final-dialect `uniqueItems` validation.
//!
//! Fingerprints select candidates, never establish equality. Every candidate
//! collision is confirmed by the existing fuel-metered JSON Schema equality
//! evaluator. This keeps adversarial collisions bounded without rejecting
//! distinct values just because their fingerprints collide. No JSON values or
//! canonical serialized copies are retained by the index.

use std::collections::{HashMap, hash_map::RandomState};
use std::hash::{BuildHasher, Hash, Hasher};

use serde_json::Value;

use super::{
    ExactDecimal, ValidationContext, ValidationError, additional_string_work,
    consume_required_work_units, consume_validation_work, json_schema_equal_with_work, push_error,
};

// Tiny arrays avoid an index allocation and retain their existing comparison
// accounting. This is an algorithm-selection threshold, not an admission limit.
pub(super) const PAIRWISE_LIMIT: usize = 8;

/// Records duplicate diagnostics; returns false only when evaluation cannot
/// continue. Shared instance admission has already bounded bytes and nesting.
pub(super) fn validate(
    items: &[Value],
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: &mut ValidationContext<'_>,
) -> bool {
    validate_with_hasher(items, &RandomState::new(), path, errors, context)
}

fn validate_with_hasher<S: BuildHasher>(
    items: &[Value],
    seed: &S,
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: &mut ValidationContext<'_>,
) -> bool {
    let mut seen: HashMap<u64, Vec<usize>> = HashMap::new();
    for (index, item) in items.iter().enumerate() {
        let Some(key) = fingerprint(item, seed, path, errors, context) else {
            return false;
        };
        let candidates = seen.entry(key).or_default();
        let mut duplicate = false;
        for &previous in candidates.iter() {
            // Keep the existing per-comparison charge as well as the recursive
            // equality charge. A deliberately colliding index cannot evade fuel.
            if !consume_validation_work(context, path, errors) {
                return false;
            }
            let Some(equal) =
                json_schema_equal_with_work(&items[previous], item, path, errors, context)
            else {
                return false;
            };
            if equal {
                push_error(errors, &format!("{path}[{index}]"), "duplicate item in array");
                duplicate = true;
                break;
            }
        }
        if !duplicate {
            // One representative per distinct value, even for a long run of
            // duplicates. Retained indexes are bounded by admitted item count.
            candidates.push(index);
        }
    }
    true
}

fn fingerprint<S: BuildHasher>(
    value: &Value,
    seed: &S,
    path: &str,
    errors: &mut Vec<ValidationError>,
    context: &mut ValidationContext<'_>,
) -> Option<u64> {
    if !consume_validation_work(context, path, errors) {
        return None;
    }
    let mut hasher = seed.build_hasher();
    match value {
        Value::Null => 0_u8.hash(&mut hasher),
        Value::Bool(value) => {
            1_u8.hash(&mut hasher);
            value.hash(&mut hasher);
        }
        Value::Number(value) => {
            2_u8.hash(&mut hasher);
            let Some(decimal) = ExactDecimal::from_number(value) else {
                push_error(errors, path, "instance number exceeds exact comparison bound");
                return None;
            };
            // ExactDecimal already canonicalizes signed zero. Strip trailing
            // coefficient zeros so 1, 1.0, and 10e-1 select the same candidates.
            // The admitted exponent and coefficient are each bounded by 4096,
            // so adding at most one coefficient's length cannot overflow i64.
            let significant = decimal.digits.trim_end_matches('0');
            let exponent = if significant.is_empty() {
                0
            } else {
                decimal.exponent + (decimal.digits.len() - significant.len()) as i64
            };
            decimal.negative.hash(&mut hasher);
            significant.hash(&mut hasher);
            exponent.hash(&mut hasher);
        }
        Value::String(value) => {
            if !consume_required_work_units(
                context,
                additional_string_work(value.len()),
                path,
                errors,
            ) {
                return None;
            }
            3_u8.hash(&mut hasher);
            value.hash(&mut hasher);
        }
        Value::Array(values) => {
            4_u8.hash(&mut hasher);
            values.len().hash(&mut hasher);
            for value in values {
                fingerprint(value, seed, path, errors, context)?.hash(&mut hasher);
            }
        }
        Value::Object(values) => {
            5_u8.hash(&mut hasher);
            values.len().hash(&mut hasher);
            let mut members = 0_u64;
            for (key, value) in values {
                if !consume_validation_work(context, path, errors)
                    || !consume_required_work_units(
                        context,
                        additional_string_work(key.len()),
                        path,
                        errors,
                    )
                {
                    return None;
                }
                let mut member = seed.build_hasher();
                key.hash(&mut member);
                fingerprint(value, seed, path, errors, context)?.hash(&mut member);
                // JSON object equality is independent of insertion order,
                // including when serde_json's preserve_order feature is unified
                // by a downstream crate. The sum is only a candidate key:
                // any collision still undergoes exact structural comparison.
                members = members.wrapping_add(member.finish());
            }
            members.hash(&mut hasher);
        }
    }
    Some(hasher.finish())
}

#[cfg(test)]
mod tests {
    use std::hash::BuildHasherDefault;

    use serde_json::json;

    use super::*;

    #[derive(Default)]
    struct ConstantHasher;

    impl Hasher for ConstantHasher {
        fn write(&mut self, _bytes: &[u8]) {}

        fn finish(&self) -> u64 {
            0
        }
    }

    #[test]
    fn fingerprint_collisions_do_not_reject_distinct_values() {
        let root = json!({});
        let items = [json!(null), json!(false), json!(0), json!("0"), json!([0])];
        let mut context = ValidationContext::new(&root, true);
        let mut errors = Vec::new();
        assert!(validate_with_hasher(
            &items,
            &BuildHasherDefault::<ConstantHasher>::default(),
            "$",
            &mut errors,
            &mut context,
        ));
        assert!(errors.is_empty());
        assert!(!context.work_exhausted);
    }

    #[test]
    fn fingerprint_collisions_still_find_exact_numeric_duplicates() {
        let root = json!({});
        let items = [json!(null), json!(false), json!(0), json!("0"), json!(-0.0)];
        let mut context = ValidationContext::new(&root, true);
        let mut errors = Vec::new();
        assert!(validate_with_hasher(
            &items,
            &BuildHasherDefault::<ConstantHasher>::default(),
            "$",
            &mut errors,
            &mut context,
        ));
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].path, "$[4]");
        assert_eq!(errors[0].message, "duplicate item in array");
    }

    #[test]
    fn collision_flood_stops_at_the_existing_work_limit() {
        let root = json!({});
        let items: Vec<Value> = (0..128).map(|value| json!(value)).collect();
        let mut context = ValidationContext::new(&root, true);
        let mut errors = Vec::new();
        assert!(!validate_with_hasher(
            &items,
            &BuildHasherDefault::<ConstantHasher>::default(),
            "$",
            &mut errors,
            &mut context,
        ));
        assert!(context.work_exhausted);
        assert!(!errors.is_empty());
    }

    #[test]
    fn exhausted_work_never_becomes_successful_uniqueness() {
        let root = json!({});
        let mut context = ValidationContext::new(&root, true);
        context.remaining_work = 0;
        let mut errors = Vec::new();
        assert!(!validate(&[json!(1)], "$", &mut errors, &mut context));
        assert!(context.work_exhausted);
        assert!(!errors.is_empty());
    }

    #[test]
    fn fingerprint_charges_large_strings_before_hashing_them() {
        let root = json!({});
        let value = json!("x".repeat(2 * 64 * 1024 + 1));
        let seed = RandomState::new();
        // One node plus two additional 64 KiB chunks requires three units.
        // Only the available fuel changes in the otherwise identical case.
        for (fuel, succeeds) in [(3, true), (2, false)] {
            let mut context = ValidationContext::new(&root, true);
            context.remaining_work = fuel;
            let mut errors = Vec::new();
            assert_eq!(
                fingerprint(&value, &seed, "$", &mut errors, &mut context).is_some(),
                succeeds
            );
            assert_eq!(context.work_exhausted, !succeeds);
            assert_eq!(errors.is_empty(), succeeds);
        }
    }

    #[test]
    fn semantic_fingerprints_conserve_numeric_and_structural_equality() {
        let root = json!({});
        let seed = RandomState::new();
        for (left, right) in [
            ("1", "1.0"),
            ("10", "1e1"),
            ("-1.20", "-12e-1"),
            ("0", "-0.0"),
            ("9007199254740993", "90071992547409930e-1"),
            (r#"{"a":1,"b":[2,3]}"#, r#"{"b":[2.0,30e-1],"a":1e0}"#),
        ] {
            let mut context = ValidationContext::new(&root, true);
            let mut errors = Vec::new();
            let left: Value = serde_json::from_str(left).expect("valid fixture");
            let right: Value = serde_json::from_str(right).expect("valid fixture");
            let left = fingerprint(&left, &seed, "$", &mut errors, &mut context)
                .expect("bounded left fingerprint");
            let right = fingerprint(&right, &seed, "$", &mut errors, &mut context)
                .expect("bounded right fingerprint");
            assert_eq!(left, right);
            assert!(errors.is_empty());
        }
    }
}
