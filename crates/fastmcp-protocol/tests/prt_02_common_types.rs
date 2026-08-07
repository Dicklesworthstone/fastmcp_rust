//! Frozen PRT-02 runner entries.
//!
//! These functions intentionally live at the integration-test harness root: the frozen RCH
//! runners invoke their literal names with `--exact`, so nested unit-test names are insufficient.

use fastmcp_protocol::common_types::{
    AbsoluteUri, Annotations, CancellationNotification, CancellationRequestId, CommonTypeError,
    CommonWireDirection, ContentBlock, EmbeddedResourceContents, FinalCommonTypesSchema,
    Implementation, MAX_ABSOLUTE_URI_BYTES, MAX_CANCELLATION_REASON_BYTES,
    MAX_CONTENT_ENCODED_BYTES, MAX_CURSOR_BYTES, MAX_ICON_DATA_URI_DECODED_BYTES,
    MAX_ICON_DATA_URI_ENCODED_BYTES, MAX_ICON_DATA_URI_PREFIX_BYTES, MAX_ICON_SIZE_BYTES,
    MAX_ICON_SIZE_ENTRIES, MAX_METADATA_ENTRIES, MAX_TRACE_FIELD_BYTES, OpaqueCursor, OpenMetadata,
    RawIcon, TraceContext,
};
use serde_json::{Value, json};

fn request_metadata() -> OpenMetadata {
    OpenMetadata::try_from_entries([
        (
            "io.modelcontextprotocol/protocolVersion".to_owned(),
            json!("2026-07-28"),
        ),
        (
            "io.modelcontextprotocol/clientCapabilities".to_owned(),
            json!({"roots": {"listChanged": true}}),
        ),
        (
            "io.modelcontextprotocol/clientInfo".to_owned(),
            json!({"name": "fastmcp", "version": "0.1.0"}),
        ),
        ("com.example/".to_owned(), json!({"open": null})),
        (
            "traceparent".to_owned(),
            json!("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        ),
        ("tracestate".to_owned(), json!("vendor=value")),
        ("baggage".to_owned(), json!("user=opaque")),
    ])
    .expect("valid final request metadata")
}

#[test]
fn prt_02_a_positive() {
    let implementation = Implementation::try_new("fastmcp", "0.1.0").expect("implementation");
    let metadata = request_metadata();
    assert_eq!(
        metadata.protocol_version().expect("protocol version"),
        Some("2026-07-28")
    );
    assert_eq!(
        metadata.client_info().expect("client info"),
        Some(implementation)
    );
    assert_eq!(metadata.get("com.example/"), Some(&json!({"open": null})));
    let trace = TraceContext::try_from_metadata(&metadata).expect("trace context");
    assert_eq!(trace.tracestate.as_deref(), Some("vendor=value"));
    assert_eq!(trace.baggage.as_deref(), Some("user=opaque"));

    let uri_rows = [
        "urn:example:opaque?query#fragment",
        "custom:path?x#y",
        "HTTPS://user@example.test:8443/a%2Fb?x=%FF#fragment",
        "scheme://[2001:db8::1]/resource",
        "scheme://[vF.future:opaque]/resource",
    ];
    for uri in uri_rows {
        let parsed = AbsoluteUri::parse(uri).expect("final URI row");
        assert_eq!(parsed.as_str(), uri, "wire URI must remain byte-preserving");
    }
    let authority_with_port = "HTTPS://user@example.test:8443/a%2Fb?x=%FF#fragment";
    assert_eq!(
        AbsoluteUri::parse(authority_with_port)
            .expect("authority port is a valid byte-preserving URI")
            .as_str(),
        authority_with_port
    );

    assert_eq!(OpaqueCursor::from_presence(None).as_present(), None);
    assert_eq!(
        OpaqueCursor::from_presence(Some(String::new())).as_present(),
        Some("")
    );
    assert_eq!(
        OpaqueCursor::from_presence(Some("next".to_owned())).as_present(),
        Some("next")
    );
    let present_cursor = OpaqueCursor::try_from_presence(Some(String::new())).expect("cursor");
    assert_eq!(
        serde_json::from_value::<OpaqueCursor>(
            serde_json::to_value(&present_cursor).expect("present cursor wire")
        )
        .expect("present cursor round trip"),
        present_cursor
    );
    assert!(
        !CancellationNotification::try_new(CancellationRequestId::String("req".to_owned()), None)
            .expect("cancellation without reason")
            .has_untrusted_reason()
    );
    assert!(
        CancellationNotification::try_new(CancellationRequestId::Integer(7), Some(String::new()))
            .expect("cancellation with empty reason")
            .has_untrusted_reason()
    );

    let icon = RawIcon::try_with_details(
        "https://example.test/icon.svg?variant=1#exact",
        Some("image/svg+xml".to_owned()),
        Some(vec!["any".to_owned(), "32x32".to_owned()]),
        None,
    )
    .expect("raw icon");
    let icon_wire = serde_json::to_value(&icon).expect("icon wire");
    assert_eq!(
        serde_json::from_value::<RawIcon>(icon_wire).expect("icon round trip"),
        icon
    );
    let data_icon = RawIcon::try_new("DATA:image/png;base64,aGVsbG8=?cache=opaque#fragment")
        .expect("raw data icon with preserved query and fragment");
    assert_eq!(
        data_icon.src.as_str(),
        "DATA:image/png;base64,aGVsbG8=?cache=opaque#fragment"
    );
    let over_ordinary_uri_limit = format!(
        "data:image/png;base64,{}",
        "A".repeat(MAX_ABSOLUTE_URI_BYTES)
    );
    RawIcon::try_new(over_ordinary_uri_limit)
        .expect("data icon uses its dedicated bound rather than the ordinary URI bound");
    assert_eq!(
        MAX_ICON_DATA_URI_ENCODED_BYTES,
        4 * MAX_ICON_DATA_URI_DECODED_BYTES.div_ceil(3) + MAX_ICON_DATA_URI_PREFIX_BYTES
    );

    let content_rows = [
        ContentBlock::text("text"),
        ContentBlock::image("aGVsbG8=", "image/png").expect("image"),
        ContentBlock::audio("aGVsbG8=", "audio/ogg").expect("audio"),
        ContentBlock::resource_link("https://example.test/resource", "resource").expect("link"),
        ContentBlock::Resource {
            resource: EmbeddedResourceContents::Text {
                uri: AbsoluteUri::parse("https://example.test/embedded").expect("embedded URI"),
                text: "embedded".to_owned(),
                mime_type: Some("text/plain".to_owned()),
            },
            annotations: None,
            meta: Some(metadata),
        },
    ];
    for content in content_rows {
        let wire = serde_json::to_value(&content).expect("content wire");
        if matches!(&content, ContentBlock::Resource { .. }) {
            assert_eq!(wire["resource"]["mimeType"], json!("text/plain"));
            assert!(wire["resource"].get("mime_type").is_none());
        }
        FinalCommonTypesSchema::validate(CommonWireDirection::Result, &wire)
            .expect("content schema");
        assert_eq!(
            serde_json::from_value::<ContentBlock>(wire).expect("content round trip"),
            content
        );
    }
}

#[test]
fn prt_02_a_planted_negative() {
    let accepted = RawIcon::try_new("https://example.test/icon.png").expect("accepted baseline");
    let baseline = accepted.clone();
    assert_eq!(
        RawIcon::try_new("relative/icon.png"),
        Err(CommonTypeError::Invalid("URI scheme")),
        "only the source URI's required scheme changes"
    );
    assert_eq!(
        accepted, baseline,
        "rejected input cannot mutate accepted icon state"
    );

    let accepted_metadata = request_metadata();
    let metadata_baseline = accepted_metadata.clone();
    assert_eq!(
        OpenMetadata::try_from_entries([("com..example/valid".to_owned(), json!(true))]),
        Err(CommonTypeError::Invalid("metadata key")),
        "only the reverse-DNS prefix is malformed"
    );
    assert_eq!(
        accepted_metadata, metadata_baseline,
        "rejected key cannot mutate metadata"
    );

    let cursor = OpaqueCursor::from_presence(None);
    assert!(
        serde_json::to_value(&cursor).is_err(),
        "a standalone absent cursor must not serialize as explicit null"
    );
    assert!(
        serde_json::from_value::<OpaqueCursor>(Value::Null).is_err(),
        "explicit null is distinct from an omitted nextCursor member"
    );

    let accepted_resource = json!({
        "type": "resource",
        "resource": {
            "uri": "https://example.test/embedded",
            "text": "baseline"
        }
    });
    let resource_baseline = accepted_resource.clone();
    let mut conflicting_resource = accepted_resource.clone();
    conflicting_resource["resource"]["blob"] = json!("aGVsbG8=");
    assert!(
        serde_json::from_value::<ContentBlock>(conflicting_resource).is_err(),
        "only the conflicting content member changes"
    );
    assert_eq!(
        accepted_resource, resource_baseline,
        "a rejected conflicting member cannot mutate accepted wire"
    );

    let mut snake_case_resource = accepted_resource.clone();
    snake_case_resource["resource"]["mime_type"] = json!("text/plain");
    assert!(
        serde_json::from_value::<ContentBlock>(snake_case_resource).is_err(),
        "only the unrecognized snake_case MIME member changes"
    );
    assert_eq!(
        accepted_resource, resource_baseline,
        "a rejected snake_case MIME member cannot mutate accepted wire"
    );

    let accepted_content = json!({"type": "text", "text": "baseline"});
    let content_baseline = accepted_content.clone();
    let mut unknown_member = accepted_content.clone();
    unknown_member["unrecognized"] = json!(true);
    assert!(
        serde_json::from_value::<ContentBlock>(unknown_member).is_err(),
        "only one unknown content member changes"
    );
    assert_eq!(
        accepted_content, content_baseline,
        "a rejected unknown member cannot mutate accepted wire"
    );

    let accepted_data_icon = RawIcon::try_new("data:image/png;base64,aGVsbG8=")
        .expect("accepted image data icon baseline");
    let data_icon_baseline = accepted_data_icon.clone();
    assert_eq!(
        RawIcon::try_new("data:text/plain;base64,aGVsbG8="),
        Err(CommonTypeError::Invalid("icon data MIME type")),
        "only the data URI media type changes from image to text"
    );
    assert_eq!(
        accepted_data_icon, data_icon_baseline,
        "a rejected data MIME cannot mutate accepted icon state"
    );

    let accepted_authority =
        AbsoluteUri::parse("https://user@example.test:8443/resource").expect("authority port");
    let authority_baseline = accepted_authority.clone();
    assert_eq!(
        AbsoluteUri::parse("https://user@example.test:not-a-port/resource"),
        Err(CommonTypeError::Invalid("absolute URI")),
        "only the authority port changes from decimal digits to invalid characters"
    );
    assert_eq!(
        accepted_authority, authority_baseline,
        "a rejected authority port cannot mutate the accepted URI"
    );
}

#[test]
fn prt_02_b_positive() {
    let implementation = Implementation::try_new("fastmcp", "0.1.0").expect("implementation");
    let implementation_wire = serde_json::to_value(&implementation).expect("implementation wire");
    assert_eq!(
        serde_json::from_value::<Implementation>(implementation_wire)
            .expect("implementation round trip"),
        implementation
    );

    let request = json!({"_meta": request_metadata()});
    let request_golden = "{\"_meta\":{\"baggage\":\"user=opaque\",\"com.example/\":{\"open\":null},\"io.modelcontextprotocol/clientCapabilities\":{\"roots\":{\"listChanged\":true}},\"io.modelcontextprotocol/clientInfo\":{\"name\":\"fastmcp\",\"version\":\"0.1.0\"},\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"traceparent\":\"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\",\"tracestate\":\"vendor=value\"}}";
    FinalCommonTypesSchema::validate_golden(CommonWireDirection::Request, &request, request_golden)
        .expect("request golden");
    assert_eq!(
        serde_json::from_value::<OpenMetadata>(request["_meta"].clone()).expect("metadata serde"),
        request_metadata()
    );
    assert_eq!(
        serde_json::from_value::<Annotations>(json!({"audience": ["user", "assistant"], "priority": 1.0, "lastModified": "2026-08-07T00:00:00Z"}))
            .expect("annotation serde")
            .priority,
        Some(1.0)
    );
    let cursor = OpaqueCursor::try_from_presence(Some(String::new())).expect("empty cursor");
    assert_eq!(
        serde_json::from_value::<OpaqueCursor>(serde_json::to_value(&cursor).expect("cursor wire"))
            .expect("cursor round trip"),
        cursor
    );
    assert_eq!(
        serde_json::from_value::<CancellationRequestId>(json!(42)).expect("request ID serde"),
        CancellationRequestId::Integer(42)
    );

    let icon = json!({"src": "HTTPS://example.test/icon.svg", "sizes": [], "theme": "dark"});
    assert!(
        !FinalCommonTypesSchema::validate_icon(&icon)
            .expect("icon schema")
            .effective_any_size()
    );
    let cancellation = json!({
        "method": "notifications/cancelled",
        "params": {"requestId": "request-7", "reason": "bounded"}
    });
    FinalCommonTypesSchema::validate(CommonWireDirection::Notification, &cancellation)
        .expect("notification direction");

    let metadata_n_minus_one =
        (0..MAX_METADATA_ENTRIES - 1).map(|index| (format!("com.example/key{index}"), Value::Null));
    OpenMetadata::try_from_entries(metadata_n_minus_one).expect("metadata N-1");
    let metadata_n =
        (0..MAX_METADATA_ENTRIES).map(|index| (format!("com.example/key{index}"), Value::Null));
    OpenMetadata::try_from_entries(metadata_n).expect("metadata N");
    for length in [MAX_ABSOLUTE_URI_BYTES - 1, MAX_ABSOLUTE_URI_BYTES] {
        let uri = format!("x:{}", "a".repeat(length - 2));
        assert_eq!(
            AbsoluteUri::parse(uri)
                .expect("URI at bound")
                .as_str()
                .len(),
            length
        );
    }
    for length in [MAX_CURSOR_BYTES - 1, MAX_CURSOR_BYTES] {
        assert_eq!(
            OpaqueCursor::try_from_presence(Some("x".repeat(length)))
                .expect("cursor at bound")
                .as_present()
                .map(str::len),
            Some(length)
        );
    }
    for length in [
        MAX_CANCELLATION_REASON_BYTES - 1,
        MAX_CANCELLATION_REASON_BYTES,
    ] {
        assert!(
            CancellationNotification::try_new(
                CancellationRequestId::Integer(1),
                Some("x".repeat(length))
            )
            .expect("cancellation reason at bound")
            .has_untrusted_reason()
        );
    }
    let sizes = vec!["x".repeat(MAX_ICON_SIZE_BYTES); MAX_ICON_SIZE_ENTRIES];
    RawIcon::try_with_details("https://example.test/icon", None, Some(sizes), None)
        .expect("icon sizes at bound");
    RawIcon::try_with_details(
        "https://example.test/icon",
        None,
        Some(vec![
            "x".repeat(MAX_ICON_SIZE_BYTES - 1);
            MAX_ICON_SIZE_ENTRIES - 1
        ]),
        None,
    )
    .expect("icon sizes at N-1");
    ContentBlock::image("A".repeat(MAX_CONTENT_ENCODED_BYTES - 1), "image/png")
        .expect("content at encoded N-1 bound");
    ContentBlock::image("A".repeat(MAX_CONTENT_ENCODED_BYTES), "image/png")
        .expect("content at encoded bound");
    let trace_n_minus_one = OpenMetadata::try_from_entries([
        (
            "traceparent".to_owned(),
            json!("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        ),
        (
            "tracestate".to_owned(),
            json!("x".repeat(MAX_TRACE_FIELD_BYTES - 1)),
        ),
    ])
    .expect("trace metadata");
    TraceContext::try_from_metadata(&trace_n_minus_one).expect("trace at N-1");
    let trace_n = OpenMetadata::try_from_entries([
        (
            "traceparent".to_owned(),
            json!("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        ),
        (
            "tracestate".to_owned(),
            json!("x".repeat(MAX_TRACE_FIELD_BYTES)),
        ),
    ])
    .expect("trace metadata");
    TraceContext::try_from_metadata(&trace_n).expect("trace at bound");

    assert_eq!(
        OpenMetadata::try_from_entries(
            (0..=MAX_METADATA_ENTRIES)
                .map(|index| (format!("com.example/key{index}"), Value::Null))
        ),
        Err(CommonTypeError::Invalid("metadata key"))
    );
    assert_eq!(
        AbsoluteUri::parse(format!("x:{}", "a".repeat(MAX_ABSOLUTE_URI_BYTES - 1))),
        Err(CommonTypeError::TooLong("URI"))
    );
    assert!(matches!(
        CancellationNotification::try_new(
            CancellationRequestId::Integer(1),
            Some("x".repeat(MAX_CANCELLATION_REASON_BYTES + 1))
        ),
        Err(CommonTypeError::TooLong("cancellation reason"))
    ));
    assert_eq!(
        RawIcon::try_with_details(
            "https://example.test/icon",
            None,
            Some(vec!["x".to_owned(); MAX_ICON_SIZE_ENTRIES + 1]),
            None,
        ),
        Err(CommonTypeError::TooLong("icon sizes"))
    );
    assert_eq!(
        ContentBlock::image("A".repeat(MAX_CONTENT_ENCODED_BYTES + 1), "image/png"),
        Err(CommonTypeError::TooLong("binary content"))
    );
    let trace_n_plus_one = OpenMetadata::try_from_entries([
        (
            "traceparent".to_owned(),
            json!("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        ),
        (
            "tracestate".to_owned(),
            json!("x".repeat(MAX_TRACE_FIELD_BYTES + 1)),
        ),
    ])
    .expect("bounded metadata value");
    assert_eq!(
        TraceContext::try_from_metadata(&trace_n_plus_one),
        Err(CommonTypeError::TooLong("trace context"))
    );
}

#[test]
fn prt_02_b_planted_negative() {
    let accepted = OpaqueCursor::try_from_presence(Some("x".repeat(MAX_CURSOR_BYTES)))
        .expect("accepted cursor baseline");
    let baseline = accepted.clone();
    assert_eq!(
        OpaqueCursor::try_from_presence(Some("x".repeat(MAX_CURSOR_BYTES + 1))),
        Err(CommonTypeError::TooLong("pagination cursor")),
        "only the cursor length changes from N to N+1"
    );
    assert_eq!(
        accepted, baseline,
        "rejected cursor cannot mutate retained state"
    );

    let accepted_wire = json!({"_meta": request_metadata()});
    let wire_baseline = accepted_wire.clone();
    let mut planted = accepted_wire.clone();
    let meta = planted["_meta"].as_object_mut().expect("metadata object");
    let preserved = meta.remove("com.example/").expect("valid open key");
    meta.insert("io.modelcontextprotocol/future".to_owned(), preserved);
    assert_eq!(
        FinalCommonTypesSchema::validate(CommonWireDirection::Request, &planted),
        Err(CommonTypeError::Invalid("metadata key")),
        "only the open key becomes an unrecognized reserved key"
    );
    assert_eq!(
        accepted_wire, wire_baseline,
        "rejected golden cannot mutate retained wire state"
    );

    let content = json!({"type": "text", "text": "baseline"});
    let content_baseline = content.clone();
    let mut wrong_discriminator = content.clone();
    wrong_discriminator["type"] = json!("textual");
    assert!(serde_json::from_value::<ContentBlock>(wrong_discriminator).is_err());
    assert_eq!(
        content, content_baseline,
        "rejected discriminator cannot mutate accepted wire"
    );

    let reversed_cancellation = json!({
        "_meta": request_metadata(),
        "method": "notifications/cancelled",
        "params": {"requestId": 1}
    });
    assert_eq!(
        FinalCommonTypesSchema::validate(CommonWireDirection::Request, &reversed_cancellation),
        Err(CommonTypeError::Invalid("cancellation direction")),
        "only the notification direction is reversed"
    );
}
