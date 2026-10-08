//! Public-path semantic and capacity regressions for final `uniqueItems`.

use fastmcp_protocol::schema::{admit_final_schema, validate};
use serde_json::{Value, json};

fn padded(value: Value) -> Vec<Value> {
    let mut values: Vec<Value> = (0..32).map(|index| json!(format!("pad-{index}"))).collect();
    values.push(value);
    values
}

#[test]
fn unique_items_accepts_large_distinct_primitive_arrays() {
    let schema = admit_final_schema(json!({"type": "array", "uniqueItems": true}))
        .expect("valid schema");
    let numbers: Vec<Value> = (0..512).map(|index| json!(index)).collect();
    let strings: Vec<Value> = (0..512).map(|index| json!(format!("item-{index}"))).collect();
    schema.validate(&json!(numbers)).expect("512 distinct numbers");
    schema.validate(&json!(strings)).expect("512 distinct strings");
}

#[test]
fn unique_items_rejects_one_late_duplicate_without_poisoning_next_validation() {
    let schema = admit_final_schema(json!({"uniqueItems": true})).expect("valid schema");
    let accepted = json!((0..512).collect::<Vec<_>>());
    let mut rejected = accepted.clone();
    rejected[511] = serde_json::from_str("0e10").expect("exact zero fixture");
    let before = rejected.clone();
    schema.validate(&accepted).expect("distinct baseline");
    let errors = schema.validate(&rejected).expect_err("one semantic duplicate");
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].path, "root[511]");
    assert_eq!(errors[0].message, "duplicate item in array");
    assert_eq!(rejected, before);
    schema.validate(&accepted).expect("no retained cross-call state");
}

#[test]
fn unique_items_accepts_distinct_nested_values() {
    let schema = admit_final_schema(json!({"uniqueItems": true})).expect("valid schema");
    let values: Vec<Value> = (0..64)
        .map(|index| json!({"number": index, "nested": [index, {"label": "shared"}]}))
        .collect();
    schema.validate(&json!(values)).expect("bounded distinct trees");
    let mut distinct_types = padded(json!(null));
    distinct_types.extend([json!(false), json!(true), json!(0), json!("0"), json!([]), json!({})]);
    schema.validate(&json!(distinct_types)).expect("JSON types remain distinct");
}

#[test]
fn unique_items_numeric_spellings_select_the_same_candidates() {
    let schema = admit_final_schema(json!({"uniqueItems": true})).expect("valid schema");
    for (left, equal, distinct) in [
        ("1", "10e-1", "2"),
        ("-1.20", "-12e-1", "-1.21"),
        ("0", "-0.0", "0.1"),
        ("9007199254740993", "90071992547409930e-1", "9007199254740994"),
    ] {
        let mut values = padded(serde_json::from_str(left).expect("left number"));
        values.push(serde_json::from_str(distinct).expect("distinct number"));
        schema.validate(&json!(values)).expect("distinct numeric control");
        *values.last_mut().expect("last item") = serde_json::from_str(equal).expect("equal number");
        let errors = schema.validate(&json!(values)).expect_err("equal numeric spellings");
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "duplicate item in array");
    }
}

#[test]
fn unique_items_ignores_object_order_but_preserves_array_order() {
    let schema = admit_final_schema(json!({"uniqueItems": true})).expect("valid schema");
    let left: Value = serde_json::from_str(r#"{"a":1,"b":[2,3]}"#).expect("left object");
    let same: Value = serde_json::from_str(r#"{"b":[2.0,30e-1],"a":1e0}"#).expect("equal object");
    let different: Value = serde_json::from_str(r#"{"b":[3,2],"a":1}"#).expect("different object");
    let mut values = padded(left);
    values.push(different);
    schema.validate(&json!(values)).expect("array order differs");
    *values.last_mut().expect("last item") = same;
    let errors = schema.validate(&json!(values)).expect_err("object member order is irrelevant");
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].message, "duplicate item in array");
}

#[test]
fn unique_items_keeps_raw_representation_equality_unchanged() {
    let mut values = padded(json!(1));
    values.push(json!(1.0));
    validate(&json!({"uniqueItems": true}), &json!(values))
        .expect("raw compatibility path still distinguishes numeric representations");
    let schema = admit_final_schema(json!({"uniqueItems": true})).expect("valid schema");
    assert!(schema.validate(&json!(values)).is_err());
}

#[test]
fn unique_items_matches_small_array_semantics_across_index_cutover() {
    let schema = admit_final_schema(json!({"uniqueItems": true})).expect("valid schema");
    for length in [7, 8, 9, 10, 64] {
        let mut values: Vec<Value> = (0..length).map(|index| json!(index)).collect();
        schema.validate(&json!(values)).expect("distinct control");
        *values.last_mut().expect("nonempty array") = json!(0.0);
        let errors = schema.validate(&json!(values)).expect_err("one duplicate");
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "duplicate item in array");
    }
}
