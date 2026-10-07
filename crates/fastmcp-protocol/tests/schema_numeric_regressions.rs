//! Regression coverage for exact, bounded JSON Schema `multipleOf` arithmetic.
//!
//! All cases enter through public schema admission and validation. Integer
//! expectations use Rust integer remainder, independently of the validator's
//! decimal digit arithmetic. Decimal fixtures are parsed without an f64 step.

use fastmcp_protocol::schema::admit_final_schema;
use serde_json::{Value, json};

fn number(source: &str) -> Value {
    let value: Value = serde_json::from_str(source).expect("valid JSON number fixture");
    assert!(value.is_number());
    value
}

#[test]
fn multiple_of_accepts_multiples_requiring_a_wider_partial_remainder() {
    let schema = admit_final_schema(json!({"multipleOf": 3})).expect("valid schema");
    for value in [0, 3, 12, 102, 105, 108, 111, 114, 999, -102, -105] {
        schema
            .validate(&json!(value))
            .unwrap_or_else(|error| panic!("{value} is a multiple of 3: {error:?}"));
    }
}

#[test]
fn multiple_of_rejects_nonmultiples_previously_accepted_by_digit_repetition() {
    let schema = admit_final_schema(json!({"multipleOf": 3})).expect("valid schema");
    for value in [10, 11, 13, 14, 16, 101, 103, -10, -13, -103] {
        assert!(
            schema.validate(&json!(value)).is_err(),
            "{value} is not a multiple of 3"
        );
    }
}

#[test]
fn multiple_of_matches_independent_integer_remainders() {
    for divisor in 1_i64..=32 {
        let schema = admit_final_schema(json!({"multipleOf": divisor})).expect("valid schema");
        for value in -256_i64..=256 {
            assert_eq!(
                schema.validate(&json!(value)).is_ok(),
                value % divisor == 0,
                "dividend={value}, divisor={divisor}"
            );
        }
    }
}

#[test]
fn multiple_of_preserves_exact_fractional_and_exponent_semantics() {
    for (divisor, accepted, rejected) in [
        ("0.03", "1.02", "0.13"),
        ("3e-2", "102e-2", "13e-2"),
        ("0.003", "-0.102", "-0.013"),
        ("0.12", "1.20", "1.21"),
        ("0.125", "1.000", "1.001"),
        ("30", "1.02e3", "1.03e3"),
    ] {
        let schema = admit_final_schema(json!({"multipleOf": number(divisor)}))
            .expect("positive finite divisor schema");
        schema
            .validate(&number(accepted))
            .unwrap_or_else(|error| panic!("{accepted} / {divisor} is integral: {error:?}"));
        assert!(
            schema.validate(&number(rejected)).is_err(),
            "{rejected} / {divisor} is not integral"
        );
        schema.validate(&number("-0.0")).expect("zero is a multiple");
    }
}

#[test]
fn multiple_of_preserves_integers_beyond_f64_and_u64_precision() {
    for (divisor, multiplier) in [
        (3_u128, 9_007_199_254_740_993_u128),
        (37, 18_446_744_073_709_551_617),
        (125, 1_000_000_000_000_000_000_001),
    ] {
        let product = divisor.checked_mul(multiplier).expect("bounded fixture");
        let schema = admit_final_schema(json!({"multipleOf": number(&divisor.to_string())}))
            .expect("valid schema");
        for value in [product.to_string(), format!("-{product}")] {
            schema
                .validate(&number(&value))
                .unwrap_or_else(|error| panic!("exact product {value} rejected: {error:?}"));
        }
        for value in [(product - 1).to_string(), (product + 1).to_string()] {
            assert!(
                schema.validate(&number(&value)).is_err(),
                "adjacent nonmultiple {value} accepted"
            );
        }
    }
}

#[test]
fn multiple_of_constraints_apply_through_references_without_mutating_inputs() {
    let source = json!({
        "$defs": {"amount": {"type": "number", "multipleOf": 3}},
        "type": "object",
        "properties": {"amount": {"$ref": "#/$defs/amount"}},
        "required": ["amount"]
    });
    let schema = admit_final_schema(source).expect("valid referenced schema");
    let accepted = json!({"amount": 102});
    let rejected = json!({"amount": 103});
    let before = rejected.clone();
    schema.validate(&accepted).expect("valid referenced amount");
    assert!(schema.validate(&rejected).is_err());
    assert_eq!(rejected, before);
    schema
        .validate(&accepted)
        .expect("a rejected instance does not poison subsequent validation");
}
