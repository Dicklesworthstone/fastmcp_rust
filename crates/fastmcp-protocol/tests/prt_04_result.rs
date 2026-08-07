use fastmcp_protocol::{
    CompleteResultPayload, CoreResultDiscriminatorPolicy, DecodedResult, ExactJsonObject,
    ExactJsonValue, ResultDecodeError, ResultDecodeErrorKind, ResultPeerEra, TypedCompleteMembers,
    decode_peer_result, decode_typed_complete, encode_result,
};

#[derive(Debug, PartialEq, Eq)]
struct LookupResult {
    status: String,
    record: ExactJsonObject,
}

impl CompleteResultPayload for LookupResult {
    const KNOWN_MEMBER_NAMES: &'static [&'static str] = &["status", "record"];

    fn decode_known_members(
        members: &mut TypedCompleteMembers<'_>,
    ) -> Result<Self, ResultDecodeError> {
        let Some(ExactJsonValue::String(status)) = members.take("status")? else {
            return Err(ResultDecodeError::invalid_known_member("$.status"));
        };
        let Some(ExactJsonValue::Object(record)) = members.take("record")? else {
            return Err(ResultDecodeError::invalid_known_member("$.record"));
        };
        Ok(Self { status, record })
    }
}

#[test]
fn prt_04_a_positive() {
    let source = r#"{"resultType":"complete","_meta":{"trace":true},"serverInfo":{"name":"FastMCP","version":"0.1"},"extension":{"integer":123456789012345678901234567890,"decimal":1.20e+4,"nil":null}}"#;
    let (decoded, diagnostic) = decode_peer_result(
        source,
        ResultPeerEra::Modern,
        &CoreResultDiscriminatorPolicy,
    )
    .expect("public result codec accepts a bounded complete result");
    assert_eq!(diagnostic, None);
    let DecodedResult::Complete(complete) = decoded else {
        panic!("complete result");
    };
    assert_eq!(
        complete
            .meta
            .server_info
            .as_ref()
            .map(|info| info.name.as_str()),
        Some("FastMCP")
    );
    assert!(matches!(
        complete.meta.metadata().get("trace"),
        Some(ExactJsonValue::Bool(true))
    ));
    assert_eq!(complete.extras.members().len(), 1);
    let Some(ExactJsonValue::Object(extension)) = complete
        .extras
        .members()
        .first()
        .map(|member| &member.value)
    else {
        panic!("extension is retained as an exact open member");
    };
    assert_eq!(
        extension.get("integer"),
        Some(&ExactJsonValue::Number(
            "123456789012345678901234567890".to_owned()
        ))
    );
    assert_eq!(
        extension.get("decimal"),
        Some(&ExactJsonValue::Number("1.20e+4".to_owned()))
    );
    assert_eq!(encode_result(&DecodedResult::Complete(complete)), source);
}

#[test]
fn prt_04_a_planted_negative() {
    let accepted = r#"{"resultType":"complete","extension":{"count":1.20e+4}}"#;
    let (baseline, _) = decode_peer_result(
        accepted,
        ResultPeerEra::Legacy,
        &CoreResultDiscriminatorPolicy,
    )
    .expect("baseline complete result");
    let planted = r#"{"resultType":null,"extension":{"count":1.20e+4}}"#;
    let error = decode_peer_result(
        planted,
        ResultPeerEra::Legacy,
        &CoreResultDiscriminatorPolicy,
    )
    .expect_err("only resultType changed from a string to null");
    assert_eq!(error.kind(), ResultDecodeErrorKind::InvalidDiscriminator);
    assert_eq!(error.path(), "$.resultType");
    let (reaccepted, _) = decode_peer_result(
        accepted,
        ResultPeerEra::Legacy,
        &CoreResultDiscriminatorPolicy,
    )
    .expect("rejection cannot mutate the stateless codec");
    let (DecodedResult::Complete(before), DecodedResult::Complete(after)) = (baseline, reaccepted)
    else {
        panic!("complete baseline");
    };
    assert_eq!(before.extras, after.extras);
    assert_eq!(encode_result(&DecodedResult::Complete(before)), accepted);
}

#[test]
fn prt_04_b_positive() {
    let source = r#"{"resultType":"complete","status":"ready","record":{"id":123456789012345678901234567890},"opaque":{"null":null,"decimal":1.20e+4}}"#;
    let (decoded, diagnostic) =
        decode_typed_complete::<LookupResult>(source, ResultPeerEra::Modern)
            .expect("public typed result codec consumes only selected known members");
    assert_eq!(diagnostic, None);
    assert_eq!(decoded.payload.status, "ready");
    assert_eq!(
        decoded.payload.record.get("id"),
        Some(&ExactJsonValue::Number(
            "123456789012345678901234567890".to_owned()
        ))
    );
    assert_eq!(decoded.extras.members().len(), 1);
    let Some(ExactJsonValue::Object(opaque)) =
        decoded.extras.members().first().map(|member| &member.value)
    else {
        panic!("unknown member is retained");
    };
    assert_eq!(opaque.get("null"), Some(&ExactJsonValue::Null));
    assert_eq!(
        opaque.get("decimal"),
        Some(&ExactJsonValue::Number("1.20e+4".to_owned()))
    );
}

#[test]
fn prt_04_b_planted_negative() {
    let accepted = r#"{"resultType":"complete","status":"ready","record":{"id":123456789012345678901234567890},"opaque":{"decimal":1.20e+4}}"#;
    let (baseline, _) = decode_typed_complete::<LookupResult>(accepted, ResultPeerEra::Modern)
        .expect("baseline selected complete result");
    let planted = r#"{"resultType":"complete","status":false,"record":{"id":123456789012345678901234567890},"opaque":{"decimal":1.20e+4}}"#;
    let error = decode_typed_complete::<LookupResult>(planted, ResultPeerEra::Modern)
        .expect_err("only the selected status JSON kind changed");
    assert_eq!(error.kind(), ResultDecodeErrorKind::InvalidKnownMember);
    assert_eq!(error.path(), "$.status");
    let (reaccepted, _) = decode_typed_complete::<LookupResult>(accepted, ResultPeerEra::Modern)
        .expect("rejection cannot mutate subsequent typed decode state");
    assert_eq!(reaccepted.payload, baseline.payload);
    assert_eq!(reaccepted.extras, baseline.extras);
}
