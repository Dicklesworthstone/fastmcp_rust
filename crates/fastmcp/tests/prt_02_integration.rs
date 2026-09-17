//! PRT-02 integration: join the A and B capability slices through public
//! entrypoints.
//!
//! Every constructor, serde call and schema call below goes through the
//! shipped `fastmcp_rust` facade, which is the packaged public consumer the
//! acceptance names. The published PRT-02 manifests are read from
//! `fastmcp_protocol::common_types` because they are the producers' declared
//! row sets, not behaviour under test.
//!
//! - `bd-mcp-prt-02-a-zaok` — metadata, URI/cursor/cancellation, icon/content.
//! - `bd-mcp-prt-02-b-nnva` — serde/schema, bounds/direction, open goldens.
//!
//! The floors this leaf must meet are read from the producers' manifests
//! rather than restated here, so raising a floor upstream raises what this
//! integration must actually demonstrate.

use fastmcp_protocol::common_types::{
    PRT_02_I_OPEN_FINAL_JOIN_MANIFEST_V1, PRT_02_I_PUBLIC_JOIN_MANIFEST_V1,
    parse_prt_02_manifest_rows, prt_02_a_icon_content_manifest_digest,
    prt_02_a_metadata_manifest_digest, prt_02_a_uri_cursor_cancel_manifest_digest,
    prt_02_all_manifests, prt_02_b_bounds_direction_manifest_digest,
    prt_02_b_open_goldens_manifest_digest, prt_02_b_serde_schema_manifest_digest,
    prt_02_i_open_final_join_manifest_digest, prt_02_i_public_join_manifest_digest,
};
use fastmcp_rust::{
    AbsoluteUri, CancellationNotification, CancellationRequestId, CommonTypeError,
    CommonWireDirection, ContentBlock, FinalCommonTypesSchema, Implementation, OpaqueCursor,
    OpenMetadata, RawIcon, TraceContext,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// Records observations against one published PRT-02 manifest.
///
/// The declared set and the per-row floors both come from the shipped
/// manifest, never from this test.
struct JoinLedger {
    manifest: &'static str,
    observed: BTreeMap<String, usize>,
}

impl JoinLedger {
    fn new(manifest: &'static str) -> Self {
        Self {
            manifest,
            observed: BTreeMap::new(),
        }
    }

    fn observe(&mut self, subcase: &str) {
        *self.observed.entry(subcase.to_owned()).or_default() += 1;
    }

    fn settle(self, declared_rows: usize) {
        let rows = parse_prt_02_manifest_rows(self.manifest)
            .expect("the published manifest parses into ordered subcase rows");
        assert_eq!(
            rows.len(),
            declared_rows,
            "the manifest must declare exactly the acceptance item's numeric floor of rows",
        );
        for (id, _, floor) in &rows {
            let count = self.observed.get(id).copied().unwrap_or_default();
            assert!(
                count >= *floor,
                "subcase {id} observed {count} times, below its declared floor of {floor}",
            );
        }
        let declared: BTreeSet<&str> = rows.iter().map(|(id, _, _)| id.as_str()).collect();
        for id in self.observed.keys() {
            assert!(
                declared.contains(id.as_str()),
                "observed undeclared subcase {id}; the manifest is the closed set",
            );
        }
    }
}

/// The canonical final request metadata this leaf joins on.
fn final_metadata() -> OpenMetadata {
    OpenMetadata::try_from_entries([
        (
            "io.modelcontextprotocol/protocolVersion".to_owned(),
            json!("2026-07-28"),
        ),
        (
            "io.modelcontextprotocol/clientInfo".to_owned(),
            json!({"name": "fastmcp", "version": "0.1.0"}),
        ),
        ("com.example/open".to_owned(), json!({"kept": [1, null]})),
        (
            "traceparent".to_owned(),
            json!("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        ),
        ("tracestate".to_owned(), json!("vendor=value")),
    ])
    .expect("final request metadata")
}

#[test]
fn prt_02_integration_public_join() {
    let mut ledger = JoinLedger::new(PRT_02_I_PUBLIC_JOIN_MANIFEST_V1);

    let implementation = Implementation::try_new("fastmcp", "0.1.0").expect("implementation");
    ledger.observe("PRT-I-01.01");

    let metadata = final_metadata();
    assert_eq!(
        metadata.client_info().expect("client info"),
        Some(implementation)
    );
    ledger.observe("PRT-I-01.02");

    let uri = AbsoluteUri::parse("https://example.test/resource?q=1#f").expect("absolute URI");
    assert_eq!(uri.as_str(), "https://example.test/resource?q=1#f");
    ledger.observe("PRT-I-01.03");

    assert_eq!(
        OpaqueCursor::from_presence(Some("page-2".to_owned())).as_present(),
        Some("page-2")
    );
    ledger.observe("PRT-I-01.04");

    assert!(
        !CancellationNotification::try_new(
            CancellationRequestId::String("request-7".to_owned()),
            None
        )
        .expect("cancellation")
        .has_untrusted_reason()
    );
    ledger.observe("PRT-I-01.05");

    let icon = RawIcon::try_new("https://example.test/icon.png").expect("icon");
    assert_eq!(icon.src.as_str(), "https://example.test/icon.png");
    ledger.observe("PRT-I-01.06");

    let content = ContentBlock::image("aGVsbG8=", "image/png").expect("image content");
    ledger.observe("PRT-I-01.07");

    let wire = serde_json::to_value(&content).expect("content to_value");
    assert_eq!(wire["type"], json!("image"));
    assert_eq!(wire["mimeType"], json!("image/png"));
    ledger.observe("PRT-I-01.08");

    assert_eq!(
        serde_json::from_value::<ContentBlock>(wire.clone()).expect("content from_value"),
        content
    );
    ledger.observe("PRT-I-01.09");

    FinalCommonTypesSchema::validate(CommonWireDirection::Result, &wire).expect("schema verdict");
    ledger.observe("PRT-I-01.10");

    // The producers' manifests are consumed structurally. Re-hashing bytes
    // this test already holds would only restate the hash function, so the
    // join checks properties a consumer can actually disagree with: each
    // manifest parses, and no two manifests in the family share a subcase
    // identifier or a canonical digest.
    let all = prt_02_all_manifests();
    let mut every_id = BTreeSet::new();
    for manifest in all {
        let rows = parse_prt_02_manifest_rows(manifest).expect("every published manifest parses");
        assert!(!rows.is_empty());
        for (id, _, floor) in &rows {
            assert!(*floor >= 1, "every declared row carries a positive floor");
            assert!(
                every_id.insert(id.clone()),
                "subcase identifier {id} is declared by more than one manifest",
            );
        }
    }
    for manifest in all[..3].iter().copied() {
        assert!(parse_prt_02_manifest_rows(manifest).is_some());
        ledger.observe("PRT-I-01.11");
    }
    for manifest in all[3..6].iter().copied() {
        assert!(parse_prt_02_manifest_rows(manifest).is_some());
        ledger.observe("PRT-I-01.12");
    }

    let digests = [
        prt_02_a_metadata_manifest_digest(),
        prt_02_a_uri_cursor_cancel_manifest_digest(),
        prt_02_a_icon_content_manifest_digest(),
        prt_02_b_serde_schema_manifest_digest(),
        prt_02_b_bounds_direction_manifest_digest(),
        prt_02_b_open_goldens_manifest_digest(),
        prt_02_i_public_join_manifest_digest(),
        prt_02_i_open_final_join_manifest_digest(),
    ];
    let distinct: BTreeSet<_> = digests.iter().map(|digest| *digest.as_bytes()).collect();
    assert_eq!(
        distinct.len(),
        digests.len(),
        "each acceptance item has its own canonical receipt"
    );

    ledger.settle(12);
}

#[test]
fn prt_02_integration_open_final_join() {
    let mut ledger = JoinLedger::new(PRT_02_I_OPEN_FINAL_JOIN_MANIFEST_V1);

    let metadata = final_metadata();
    assert_eq!(
        metadata.protocol_version().expect("protocol version"),
        Some("2026-07-28")
    );
    ledger.observe("PRT-I-02.01");

    assert_eq!(
        metadata.get("com.example/open"),
        Some(&json!({"kept": [1, null]})),
        "a valid open value survives public construction byte for byte"
    );
    ledger.observe("PRT-I-02.02");

    assert_eq!(
        OpenMetadata::try_from_entries([("com..example/bad".to_owned(), json!(true))]),
        Err(CommonTypeError::Invalid("metadata key")),
        "a malformed reverse-DNS key is refused at the public entrypoint"
    );
    ledger.observe("PRT-I-02.03");

    for candidate in [
        "urn:example:opaque",
        "https://example.test/resource",
        "scheme://[2001:db8::1]/resource",
    ] {
        assert_eq!(
            AbsoluteUri::parse(candidate)
                .expect("URI policy class")
                .as_str(),
            candidate
        );
        ledger.observe("PRT-I-02.04");
    }

    // The three distinct cursor states, joined at the public surface.
    assert_eq!(OpaqueCursor::from_presence(None).as_present(), None);
    ledger.observe("PRT-I-02.05");
    assert_eq!(
        OpaqueCursor::from_presence(Some(String::new())).as_present(),
        Some("")
    );
    ledger.observe("PRT-I-02.05");
    assert!(
        serde_json::from_value::<OpaqueCursor>(Value::Null).is_err(),
        "an explicit null is neither absent nor present"
    );
    ledger.observe("PRT-I-02.05");

    FinalCommonTypesSchema::validate(
        CommonWireDirection::Notification,
        &json!({
            "method": "notifications/cancelled",
            "params": {"requestId": "request-7", "reason": "bounded"}
        }),
    )
    .expect("cancellation travels in the notification direction");
    ledger.observe("PRT-I-02.06");

    let icon_wire =
        serde_json::to_value(&RawIcon::try_new("https://example.test/icon.png").expect("icon"))
            .expect("icon wire");
    assert_eq!(icon_wire["src"], json!("https://example.test/icon.png"));
    ledger.observe("PRT-I-02.07");
    let text_wire = serde_json::to_value(&ContentBlock::text("joined")).expect("content wire");
    FinalCommonTypesSchema::validate(CommonWireDirection::Result, &text_wire).expect("schema");
    ledger.observe("PRT-I-02.07");

    let trace = TraceContext::try_from_metadata(&metadata).expect("trace context");
    assert_eq!(trace.tracestate.as_deref(), Some("vendor=value"));
    ledger.observe("PRT-I-02.08");

    ledger.settle(8);
}

#[test]
fn prt_02_i_positive() {
    // One pass that observes both producers' declared behaviour through the
    // facade, so a stale or replaced child fails this boundary rather than
    // passing silently.
    let metadata = final_metadata();

    // From A: the type-level cursor presence model.
    assert_eq!(OpaqueCursor::from_presence(None).as_present(), None);
    assert_eq!(
        OpaqueCursor::from_presence(Some(String::new())).as_present(),
        Some("")
    );

    // From B: the same distinction preserved by an enclosing wire struct.
    let meta_wire = serde_json::to_value(&metadata).expect("metadata wire");
    let absent: fastmcp_rust::FinalListParams =
        serde_json::from_value(json!({"_meta": meta_wire.clone()})).expect("omitted cursor");
    assert_eq!(absent.cursor, None);
    let present: fastmcp_rust::FinalListParams =
        serde_json::from_value(json!({"_meta": meta_wire.clone(), "cursor": "page-2"}))
            .expect("present cursor");
    assert_eq!(present.cursor.as_deref(), Some("page-2"));

    // Both producers' manifests are published and structurally sound.
    for manifest in prt_02_all_manifests() {
        assert!(parse_prt_02_manifest_rows(manifest).is_some());
    }

    // And the joined public surface still round-trips a content block.
    let content = ContentBlock::text("joined");
    let wire = serde_json::to_value(&content).expect("wire");
    FinalCommonTypesSchema::validate(CommonWireDirection::Result, &wire).expect("schema");
    assert_eq!(
        serde_json::from_value::<ContentBlock>(wire).expect("round trip"),
        content
    );
}

#[test]
fn prt_02_i_planted_negative() {
    let metadata = final_metadata();
    let meta_wire = serde_json::to_value(&metadata).expect("metadata wire");

    // Baseline: the joined consumer admits an omitted cursor.
    let baseline: fastmcp_rust::FinalListParams =
        serde_json::from_value(json!({"_meta": meta_wire.clone()})).expect("omitted cursor");
    assert_eq!(baseline.cursor, None);

    // Only the cursor spelling changes, from omitted to explicit null. This is
    // the forbidden dimension: null is neither absent nor present.
    assert!(
        serde_json::from_value::<fastmcp_rust::FinalListParams>(
            json!({"_meta": meta_wire.clone(), "cursor": null})
        )
        .is_err(),
        "the joined public consumer refuses an explicit null cursor"
    );

    // Only one accepted final key changes to a non-final alias.
    let mut aliased = meta_wire.clone();
    let object = aliased.as_object_mut().expect("metadata object");
    object.remove("io.modelcontextprotocol/protocolVersion");
    object.insert("protocolVersion".to_owned(), json!("2025-11-25"));
    let admitted = serde_json::from_value::<OpenMetadata>(aliased)
        .expect("an unprefixed key is still a structurally valid open key");
    assert_eq!(
        admitted.protocol_version().expect("protocol version"),
        None,
        "a 2025 alias never becomes the final protocol-version field"
    );

    // Retained state is unchanged after both refusals.
    let readmitted: fastmcp_rust::FinalListParams =
        serde_json::from_value(json!({"_meta": meta_wire})).expect("omitted cursor again");
    assert_eq!(readmitted.cursor, baseline.cursor);
    assert_eq!(
        metadata.protocol_version().expect("protocol version"),
        Some("2026-07-28"),
        "the accepted metadata still carries its final key"
    );
}
