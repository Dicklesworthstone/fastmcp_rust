//! PRT-04 integration: join implementation A and implementation B through the
//! public result codec API.
//!
//! This target consumes `fastmcp-protocol` the way any downstream crate does.
//! It deliberately imports no `cfg(test)` helper and enables no feature, so it
//! is auto-discovered under the default facade feature set and what passes here
//! is what ships.
//!
//! The join consumes the producers' own published acceptance inputs —
//! `PRT_04_A_EVALUATOR_MANIFEST_V1` and `PRT_04_B_EVALUATOR_MANIFEST_V1` and
//! their digests — and **never reconstructs or substitutes either half**. A
//! locally authored copy of a manifest would prove nothing about what ships.
//!
//! Two properties keep this from degenerating into ceremony:
//!
//! 1. **Floors are honoured by execution.** There is no local floor table. The
//!    minimum for each case is read from the producer's shipped bytes, and this
//!    file must perform at least that many real observations against the public
//!    codec or fail. Lowering a floor visibly weakens the producer's own
//!    published input and changes its digest; raising one turns this red.
//! 2. **Coherence is keyed on the subject, never on the ordinal.** Each
//!    predicate below is selected by the producer's declared *case name*. No
//!    contract fixes the numbering, so an `(ordinal, name)` table would rot on
//!    the next renumber while still agreeing on counts — the failure shape that
//!    lets a join emit a receipt for behaviour it never exercised. Selecting on
//!    the name means a rename turns this red and a renumber does not.

use fastmcp_core::crypto::sha256_bounded;
use fastmcp_protocol::{
    CompleteResultPayload, CoreResultDiscriminatorPolicy, DecodedResult,
    DeferringResultDiscriminatorPolicy, ExactJsonMember, ExactJsonObject, ExactJsonValue,
    MAX_PRT_04_MANIFEST_BYTES, PRT_04_A_EVALUATOR_MANIFEST_V1, PRT_04_B_EVALUATOR_MANIFEST_V1,
    PeerCacheTtl, PeerCacheTtlDeviation, ResultDecodeError, ResultDecodeErrorKind, ResultMeta,
    ResultPeerDiagnostic, ResultPeerEra,
    TypedCompleteMembers, UnknownResultMembers, decode_peer_result, decode_typed_complete,
    decode_peer_cache_ttl, encode_complete_result, encode_result, prt_04_a_manifest_digest,
    prt_04_b_manifest_digest,
};

// ---------------------------------------------------------------------------
// Manifest consumption
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct JoinedCase {
    id: String,
    name: String,
    floor: usize,
    half: &'static str,
}

/// Parses one published half without rebuilding it.
fn parse_published_half(text: &str, half: &'static str, header: &str) -> Vec<JoinedCase> {
    assert!(
        text.ends_with('\n') && !text.contains('\r'),
        "{half}: a published manifest must be LF-canonical and LF-terminated"
    );
    let mut lines = text.split('\n');
    let mut rows: Vec<&str> = Vec::new();
    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
        assert_eq!(
            line.trim_end(),
            line,
            "{half}: manifest rows carry no trailing whitespace"
        );
        rows.push(line);
    }
    assert!(
        lines.next().is_none(),
        "{half}: the manifest contains no blank or trailing line"
    );
    assert!(rows.len() > 4, "{half}: four header rows plus case rows");
    assert_eq!(rows[0], header, "{half}: frozen manifest header");
    assert!(
        rows[1].starts_with("producer-revision "),
        "{half}: row 2 binds the producer revision"
    );
    assert!(
        rows[2].starts_with("producer-tree "),
        "{half}: row 3 binds the producer tree"
    );
    assert!(
        rows[3]
            .strip_prefix("entrypoint ")
            .is_some_and(|entrypoint| entrypoint.starts_with("fastmcp")),
        "{half}: row 4 names a shipped public entrypoint"
    );

    rows[4..]
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let fields: Vec<&str> = row.split(' ').collect();
            assert_eq!(
                fields.len(),
                3,
                "{half}: case row {index} is `<id> <name> floor=<N>`"
            );
            let floor: usize = fields[2]
                .strip_prefix("floor=")
                .expect("each case row declares `floor=<N>`")
                .parse()
                .expect("each floor is numeric");
            assert!(floor >= 1, "{half}: case row {index} declares a positive floor");
            JoinedCase {
                id: fields[0].to_owned(),
                name: fields[1].to_owned(),
                floor,
                half,
            }
        })
        .collect()
}

/// Consumes both published halves and returns their ordered union.
///
/// The union is required to be contiguous from `PRT-04.01` with no omission,
/// duplication, or reorder, and no case name may appear in both halves. Each
/// published digest must still recompute over its own published bytes.
fn joined_manifest() -> Vec<JoinedCase> {
    let a_cases = parse_published_half(
        PRT_04_A_EVALUATOR_MANIFEST_V1,
        "A",
        "PRT-04-A evaluator manifest v1",
    );
    let b_cases = parse_published_half(
        PRT_04_B_EVALUATOR_MANIFEST_V1,
        "B",
        "PRT-04-B evaluator manifest v1",
    );
    assert!(!a_cases.is_empty() && !b_cases.is_empty());

    let a_digest = sha256_bounded(
        PRT_04_A_EVALUATOR_MANIFEST_V1.as_bytes(),
        MAX_PRT_04_MANIFEST_BYTES,
    )
    .expect("the published A manifest is within its byte bound");
    assert_eq!(
        prt_04_a_manifest_digest().as_bytes(),
        a_digest.as_bytes(),
        "the published A digest must bind the published A bytes"
    );
    let b_digest = sha256_bounded(
        PRT_04_B_EVALUATOR_MANIFEST_V1.as_bytes(),
        MAX_PRT_04_MANIFEST_BYTES,
    )
    .expect("the published B manifest is within its byte bound");
    assert_eq!(
        prt_04_b_manifest_digest().as_bytes(),
        b_digest.as_bytes(),
        "the published B digest must bind the published B bytes"
    );
    assert_ne!(
        a_digest.as_bytes(),
        b_digest.as_bytes(),
        "the two halves are distinct published inputs"
    );

    let union: Vec<JoinedCase> = a_cases.into_iter().chain(b_cases).collect();
    for (index, case) in union.iter().enumerate() {
        assert_eq!(
            case.id,
            format!("PRT-04.{:02}", index + 1),
            "the ordered union must be contiguous with no omission, duplication, or reorder"
        );
        assert!(
            union[..index].iter().all(|earlier| earlier.name != case.name),
            "case names must be unique across both halves; `{}` repeats",
            case.name
        );
    }
    union
}

// ---------------------------------------------------------------------------
// Fixtures and a selected composition, exercised through the public codec
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
struct JoinLookupResult {
    status: String,
    record: ExactJsonObject,
}

impl CompleteResultPayload for JoinLookupResult {
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

/// Declares a member it never consumes.
#[derive(Debug)]
struct JoinResidualResult;

impl CompleteResultPayload for JoinResidualResult {
    const KNOWN_MEMBER_NAMES: &'static [&'static str] = &["status", "audit"];

    fn decode_known_members(
        members: &mut TypedCompleteMembers<'_>,
    ) -> Result<Self, ResultDecodeError> {
        let _ = members.take("status")?;
        Ok(Self)
    }
}

/// Reaches for a member it never declared.
#[derive(Debug)]
struct JoinGrabResult;

impl CompleteResultPayload for JoinGrabResult {
    const KNOWN_MEMBER_NAMES: &'static [&'static str] = &["status"];

    fn decode_known_members(
        members: &mut TypedCompleteMembers<'_>,
    ) -> Result<Self, ResultDecodeError> {
        let _ = members.take("opaque")?;
        Ok(Self)
    }
}

/// Declares a common name as its own.
#[derive(Debug)]
struct JoinCommonClaimResult;

impl CompleteResultPayload for JoinCommonClaimResult {
    const KNOWN_MEMBER_NAMES: &'static [&'static str] = &["status", "serverInfo"];

    fn decode_known_members(
        members: &mut TypedCompleteMembers<'_>,
    ) -> Result<Self, ResultDecodeError> {
        let _ = members.take("status")?;
        Ok(Self)
    }
}

const OPEN_KINDS: &str = concat!(
    r#"{"resultType":"complete","#,
    r#""zeta":null,"alpha":true,"mid":"text","#,
    r#""num":123456789012345678901234567890,"#,
    r#""arr":[1.20e+4,null],"obj":{"inner":-0.0,"before":1}}"#,
);

const FOREIGN_INPUT_REQUIRED: &str = concat!(
    r#"{"resultType":"input_required","requestState":"retry-1","#,
    r#""ttlMs":60000,"cacheScope":"public","nextCursor":"opaque-1"}"#,
);

const UNCLAIMED: &str = r#"{"resultType":"x.example/stream","cursor":"c-1","payload":{"n":10}}"#;

const TYPED_CANONICAL: &str = concat!(
    r#"{"resultType":"complete","status":"ready","#,
    r#""record":{"id":123456789012345678901234567890},"#,
    r#""_meta":{"trace":true},"#,
    r#""zeta":null,"alpha":false,"mid":"text","num":-1.20e-4,"#,
    r#""arr":[1,"two",null],"obj":{"inner":0,"before":1}}"#,
);

const TYPED_NO_META: &str =
    r#"{"resultType":"complete","status":"ready","record":{"id":1},"opaque":{"decimal":1.20e+4}}"#;

fn extra_names(extras: &UnknownResultMembers) -> Vec<&str> {
    extras
        .members()
        .iter()
        .map(|member| member.name.as_str())
        .collect()
}

fn known_members_of(payload: &JoinLookupResult) -> Vec<ExactJsonMember> {
    vec![
        ExactJsonMember {
            name: "status".to_owned(),
            value: ExactJsonValue::String(payload.status.clone()),
        },
        ExactJsonMember {
            name: "record".to_owned(),
            value: ExactJsonValue::Object(payload.record.clone()),
        },
    ]
}

fn decode_complete(source: &str) -> (Vec<ExactJsonMember>, Option<ResultPeerDiagnostic>) {
    let (decoded, diagnostic) =
        decode_peer_result(source, ResultPeerEra::Modern, &CoreResultDiscriminatorPolicy)
            .expect("the public codec admits this bounded complete result");
    let DecodedResult::Complete(complete) = decoded else {
        panic!("complete result");
    };
    (complete.extras.into_members(), diagnostic)
}

// ---------------------------------------------------------------------------
// Predicates, selected by the producer's declared case NAME
// ---------------------------------------------------------------------------

/// Runs the observations this consumer performs for one producer-declared
/// case and returns how many it actually performed.
///
/// The `match` below *is* the coherence table, keyed on the subject. An unknown
/// name panics rather than silently scoring zero, so a producer that renames a
/// case turns this join red instead of letting it certify a subject nobody
/// exercised.
#[allow(clippy::too_many_lines)]
fn observe(case: &str) -> usize {
    match case {
        // --- A half -------------------------------------------------------
        "core-discriminator-selection" => {
            let (complete, _) = decode_peer_result(
                r#"{"resultType":"complete","k":1}"#,
                ResultPeerEra::Modern,
                &CoreResultDiscriminatorPolicy,
            )
            .expect("complete is a core discriminator");
            assert!(matches!(complete, DecodedResult::Complete(_)));
            let (input_required, _) = decode_peer_result(
                r#"{"resultType":"input_required","requestState":"s"}"#,
                ResultPeerEra::Modern,
                &CoreResultDiscriminatorPolicy,
            )
            .expect("input_required is a core discriminator");
            assert!(matches!(input_required, DecodedResult::InputRequired(_)));
            2
        }
        "absent-discriminator-defaults-complete" => {
            let absent = r#"{"note":"no discriminator"}"#;
            let (legacy, legacy_diagnostic) =
                decode_peer_result(absent, ResultPeerEra::Legacy, &CoreResultDiscriminatorPolicy)
                    .expect("an earlier-era peer may omit resultType");
            assert!(matches!(legacy, DecodedResult::Complete(_)));
            assert_eq!(legacy_diagnostic, None);
            let (modern, modern_diagnostic) =
                decode_peer_result(absent, ResultPeerEra::Modern, &CoreResultDiscriminatorPolicy)
                    .expect("a final-era omission still decodes as complete");
            assert!(matches!(modern, DecodedResult::Complete(_)));
            assert_eq!(
                modern_diagnostic,
                Some(ResultPeerDiagnostic::ModernMissingResultType),
                "the compatibility default must not silently excuse a final peer"
            );
            2
        }
        "nonstring-discriminator-refused" => {
            let mut observed = 0;
            for wrong in [
                r#"{"resultType":null,"n":1}"#,
                r#"{"resultType":7,"n":1}"#,
                r#"{"resultType":true,"n":1}"#,
            ] {
                let error =
                    decode_peer_result(wrong, ResultPeerEra::Modern, &CoreResultDiscriminatorPolicy)
                        .expect_err("a non-string resultType is never guessed at");
                assert_eq!(error.kind(), ResultDecodeErrorKind::InvalidDiscriminator);
                assert_eq!(error.path(), "$.resultType");
                assert!(
                    error.raw_envelope().is_none(),
                    "a structural refusal never reached the policy seam"
                );
                observed += 1;
            }
            observed
        }
        "policy-seam-core-deferred-rejected" => {
            let (core, _) = decode_peer_result(
                r#"{"resultType":"complete","k":1}"#,
                ResultPeerEra::Modern,
                &DeferringResultDiscriminatorPolicy,
            )
            .expect("a core discriminator stays core under either policy");
            assert!(matches!(core, DecodedResult::Complete(_)));
            let (deferred, _) = decode_peer_result(
                UNCLAIMED,
                ResultPeerEra::Modern,
                &DeferringResultDiscriminatorPolicy,
            )
            .expect("an unclaimed discriminator defers");
            assert!(matches!(deferred, DecodedResult::Deferred(_)));
            let rejected =
                decode_peer_result(UNCLAIMED, ResultPeerEra::Modern, &CoreResultDiscriminatorPolicy)
                    .expect_err("the core policy refuses what it cannot claim");
            assert_eq!(rejected.kind(), ResultDecodeErrorKind::RejectedExtension);
            assert_eq!(
                rejected
                    .raw_envelope()
                    .expect("a rejection preserves its bounded envelope")
                    .discriminator(),
                "x.example/stream"
            );
            3
        }
        "deferred-envelope-never-activated" => {
            let (deferred, _) = decode_peer_result(
                UNCLAIMED,
                ResultPeerEra::Modern,
                &DeferringResultDiscriminatorPolicy,
            )
            .expect("baseline deferral");
            let DecodedResult::Deferred(envelope) = &deferred else {
                panic!("a deferred decision yields a raw envelope");
            };
            assert_eq!(envelope.discriminator(), "x.example/stream");
            assert_eq!(
                envelope
                    .members()
                    .iter()
                    .map(|member| member.name.as_str())
                    .collect::<Vec<_>>(),
                ["resultType", "cursor", "payload"],
                "the raw envelope retains every admitted member in order"
            );
            assert!(
                !matches!(
                    deferred,
                    DecodedResult::Complete(_) | DecodedResult::InputRequired(_)
                ),
                "deferring is not activating"
            );
            assert_eq!(encode_result(&deferred), UNCLAIMED);
            3
        }
        "open-member-kind-and-order-preservation" => {
            let (extras, _) = decode_complete(OPEN_KINDS);
            assert_eq!(
                extras
                    .iter()
                    .map(|member| member.name.as_str())
                    .collect::<Vec<_>>(),
                ["zeta", "alpha", "mid", "num", "arr", "obj"],
                "admitted order is preserved; an alphabetical map round trip would sort these"
            );
            assert_eq!(extras[0].value, ExactJsonValue::Null);
            assert_eq!(extras[1].value, ExactJsonValue::Bool(true));
            assert_eq!(extras[2].value, ExactJsonValue::String("text".to_owned()));
            assert_eq!(
                extras[3].value,
                ExactJsonValue::Number("123456789012345678901234567890".to_owned())
            );
            assert_eq!(
                extras[4].value,
                ExactJsonValue::Array(vec![
                    ExactJsonValue::Number("1.20e+4".to_owned()),
                    ExactJsonValue::Null,
                ])
            );
            let ExactJsonValue::Object(nested) = &extras[5].value else {
                panic!("a nested object stays an object");
            };
            assert_eq!(
                nested.get("inner"),
                Some(&ExactJsonValue::Number("-0.0".to_owned())),
                "negative zero is not normalised away"
            );
            6
        }
        "open-member-byte-faithful-reencode" => {
            let (complete, _) =
                decode_peer_result(OPEN_KINDS, ResultPeerEra::Modern, &CoreResultDiscriminatorPolicy)
                    .expect("complete admits");
            assert_eq!(encode_result(&complete), OPEN_KINDS);
            let (input_required, _) = decode_peer_result(
                FOREIGN_INPUT_REQUIRED,
                ResultPeerEra::Modern,
                &CoreResultDiscriminatorPolicy,
            )
            .expect("input-required admits");
            assert_eq!(encode_result(&input_required), FOREIGN_INPUT_REQUIRED);
            2
        }
        "common-name-never-demoted-to-extras" => {
            let (extras, _) = decode_complete(
                r#"{"resultType":"complete","_meta":{"trace":true},"serverInfo":{"name":"FastMCP","version":"0.1"},"other":1}"#,
            );
            assert_eq!(
                extras
                    .iter()
                    .map(|member| member.name.as_str())
                    .collect::<Vec<_>>(),
                ["other"],
                "no common name is demoted into the open-member set"
            );
            let mut observed = 0;
            for common in ["resultType", "_meta", "serverInfo"] {
                let error = UnknownResultMembers::try_new(
                    vec![ExactJsonMember {
                        name: common.to_owned(),
                        value: ExactJsonValue::Bool(true),
                    }],
                    &[],
                )
                .expect_err("a locally authored extra cannot borrow a common name");
                assert_eq!(error.kind(), ResultDecodeErrorKind::KnownMemberCollision);
                assert_eq!(error.path(), common);
                observed += 1;
            }
            observed
        }
        "foreign-composition-names-inert" => {
            let (decoded, _) = decode_peer_result(
                FOREIGN_INPUT_REQUIRED,
                ResultPeerEra::Modern,
                &CoreResultDiscriminatorPolicy,
            )
            .expect("input-required admits open siblings");
            let DecodedResult::InputRequired(input_required) = decoded else {
                panic!("input-required result");
            };
            assert_eq!(
                extra_names(&input_required.extras),
                ["ttlMs", "cacheScope", "nextCursor"],
                "foreign standard names are retained, in order, as open siblings"
            );
            assert_eq!(input_required.input_requests(), None);
            assert_eq!(input_required.request_state(), Some("retry-1"));
            assert_eq!(
                input_required.extras.members()[0].value,
                ExactJsonValue::Number("60000".to_owned()),
                "`ttlMs` here is data, not a cache hint"
            );
            assert_eq!(
                input_required.extras.members()[1].value,
                ExactJsonValue::String("public".to_owned()),
                "`cacheScope` here cannot mint a shareable result"
            );
            assert_eq!(
                input_required.extras.members()[2].value,
                ExactJsonValue::String("opaque-1".to_owned()),
                "`nextCursor` here cannot select a pagination continuation"
            );
            3
        }

        // --- B half -------------------------------------------------------
        "typed-known-member-selection" => {
            let (typed, diagnostic) =
                decode_typed_complete::<JoinLookupResult>(TYPED_CANONICAL, ResultPeerEra::Modern)
                    .expect("the typed codec admits a bounded complete result");
            assert_eq!(diagnostic, None);
            assert_eq!(typed.payload.status, "ready");
            assert_eq!(
                typed.payload.record.get("id"),
                Some(&ExactJsonValue::Number(
                    "123456789012345678901234567890".to_owned()
                ))
            );
            2
        }
        "unknown-preserved-through-typed-decode" => {
            let (typed, _) =
                decode_typed_complete::<JoinLookupResult>(TYPED_CANONICAL, ResultPeerEra::Modern)
                    .expect("typed decode");
            assert_eq!(
                extra_names(&typed.extras),
                ["zeta", "alpha", "mid", "num", "arr", "obj"],
                "typed decode preserves unknown siblings in admitted order, unsorted"
            );
            let members = typed.extras.members();
            assert_eq!(members[0].value, ExactJsonValue::Null);
            assert_eq!(members[1].value, ExactJsonValue::Bool(false));
            assert_eq!(members[2].value, ExactJsonValue::String("text".to_owned()));
            assert_eq!(
                members[3].value,
                ExactJsonValue::Number("-1.20e-4".to_owned()),
                "a negative exponent lexeme survives without an f64 round trip"
            );
            assert_eq!(
                members[4].value,
                ExactJsonValue::Array(vec![
                    ExactJsonValue::Number("1".to_owned()),
                    ExactJsonValue::String("two".to_owned()),
                    ExactJsonValue::Null,
                ])
            );
            let ExactJsonValue::Object(nested) = &members[5].value else {
                panic!("a nested unknown object stays an object");
            };
            assert_eq!(
                nested
                    .members()
                    .iter()
                    .map(|member| member.name.as_str())
                    .collect::<Vec<_>>(),
                ["inner", "before"]
            );
            6
        }
        "typed-reencode-byte-faithful" => {
            let (typed, _) =
                decode_typed_complete::<JoinLookupResult>(TYPED_CANONICAL, ResultPeerEra::Modern)
                    .expect("typed decode");
            assert_eq!(
                encode_complete_result(
                    &typed.meta,
                    known_members_of(&typed.payload),
                    JoinLookupResult::KNOWN_MEMBER_NAMES,
                    &typed.extras,
                )
                .expect("re-encode"),
                TYPED_CANONICAL
            );
            let (no_meta, _) =
                decode_typed_complete::<JoinLookupResult>(TYPED_NO_META, ResultPeerEra::Modern)
                    .expect("a modern result may omit _meta");
            assert_eq!(
                encode_complete_result(
                    &no_meta.meta,
                    known_members_of(&no_meta.payload),
                    JoinLookupResult::KNOWN_MEMBER_NAMES,
                    &no_meta.extras,
                )
                .expect("re-encode"),
                TYPED_NO_META,
                "an absent _meta must not be synthesized back onto the wire"
            );
            2
        }
        "invalid-known-member-not-smuggled-into-extras" => {
            let wrong =
                TYPED_CANONICAL.replacen(r#""status":"ready""#, r#""status":false"#, 1);
            let error = decode_typed_complete::<JoinLookupResult>(&wrong, ResultPeerEra::Modern)
                .expect_err("a selected member of the wrong kind fails at that member");
            assert_eq!(error.kind(), ResultDecodeErrorKind::InvalidKnownMember);
            assert_eq!(error.path(), "$.status");
            let residual =
                r#"{"resultType":"complete","status":"ready","audit":{"who":"x"},"free":1}"#;
            let error = decode_typed_complete::<JoinResidualResult>(residual, ResultPeerEra::Modern)
                .expect_err("a declared but unconsumed member cannot become an extra");
            assert_eq!(error.kind(), ResultDecodeErrorKind::InvalidKnownMember);
            assert_eq!(error.path(), "$.audit");
            let clean = r#"{"resultType":"complete","status":"ready","free":1}"#;
            let (partial, _) =
                decode_typed_complete::<JoinResidualResult>(clean, ResultPeerEra::Modern)
                    .expect("the same composition without the declared member decodes");
            assert_eq!(extra_names(&partial.extras), ["free"]);
            3
        }
        "undeclared-name-unconsumable" => {
            let error = decode_typed_complete::<JoinGrabResult>(
                r#"{"resultType":"complete","status":"ready","opaque":1}"#,
                ResultPeerEra::Modern,
            )
            .expect_err("an undeclared open sibling is not consumable");
            assert_eq!(error.kind(), ResultDecodeErrorKind::KnownMemberCollision);
            assert_eq!(error.path(), "$.opaque");
            let (kept, _) = decode_typed_complete::<JoinLookupResult>(
                r#"{"resultType":"complete","status":"ready","record":{},"opaque":1}"#,
                ResultPeerEra::Modern,
            )
            .expect("a well-behaved composition leaves it inert");
            assert_eq!(
                extra_names(&kept.extras),
                ["opaque"],
                "the member a greedy decoder could not take stays an inert sibling"
            );
            2
        }
        "payload-declaration-collision-refused" => {
            let error = decode_typed_complete::<JoinCommonClaimResult>(
                r#"{"resultType":"complete","status":"ready"}"#,
                ResultPeerEra::Modern,
            )
            .expect_err("a composition cannot declare a common member as its own");
            assert_eq!(error.kind(), ResultDecodeErrorKind::KnownMemberCollision);
            assert_eq!(error.path(), "serverInfo");
            let mut observed = 1;
            for claimed in ["resultType", "_meta"] {
                let error = encode_complete_result(
                    &ResultMeta::empty(),
                    Vec::new(),
                    &[claimed],
                    &UnknownResultMembers::default(),
                )
                .expect_err("encoding refuses a composition that claims a common name");
                assert_eq!(error.kind(), ResultDecodeErrorKind::KnownMemberCollision);
                assert_eq!(error.path(), claimed);
                observed += 1;
            }
            observed
        }
        "wrong-core-composition-refused" => {
            let error = decode_typed_complete::<JoinLookupResult>(
                r#"{"resultType":"input_required","requestState":"retry-1"}"#,
                ResultPeerEra::Modern,
            )
            .expect_err("input_required is not a complete composition");
            assert_eq!(error.kind(), ResultDecodeErrorKind::UnexpectedResultType);
            assert_eq!(error.path(), "$.resultType");
            let error = decode_typed_complete::<JoinLookupResult>(UNCLAIMED, ResultPeerEra::Modern)
                .expect_err("typed decode cannot activate an unclaimed discriminator");
            assert_eq!(error.kind(), ResultDecodeErrorKind::RejectedExtension);
            2
        }
        "local-extra-collision-refused" => {
            let (typed, _) =
                decode_typed_complete::<JoinLookupResult>(TYPED_CANONICAL, ResultPeerEra::Modern)
                    .expect("typed decode");
            let mut observed = 0;
            for claimed in ["status", "record"] {
                let error = encode_complete_result(
                    &ResultMeta::empty(),
                    known_members_of(&typed.payload),
                    JoinLookupResult::KNOWN_MEMBER_NAMES,
                    &UnknownResultMembers::try_new(
                        vec![ExactJsonMember {
                            name: claimed.to_owned(),
                            value: ExactJsonValue::Bool(true),
                        }],
                        &[],
                    )
                    .expect("fine in isolation"),
                )
                .expect_err("an extra cannot borrow a selected-known name");
                assert_eq!(error.kind(), ResultDecodeErrorKind::KnownMemberCollision);
                assert_eq!(error.path(), claimed);
                observed += 1;
            }
            let duplicate = UnknownResultMembers::try_new(
                vec![
                    ExactJsonMember {
                        name: "free".to_owned(),
                        value: ExactJsonValue::Bool(true),
                    },
                    ExactJsonMember {
                        name: "free".to_owned(),
                        value: ExactJsonValue::Bool(false),
                    },
                ],
                &[],
            )
            .expect_err("locally authored extras cannot repeat a name");
            assert_eq!(duplicate.kind(), ResultDecodeErrorKind::DuplicateMember);
            observed + 1
        }
        "absent-meta-and-server-info-valid" => {
            let (no_meta, _) =
                decode_typed_complete::<JoinLookupResult>(TYPED_NO_META, ResultPeerEra::Modern)
                    .expect("a modern result may omit _meta and serverInfo");
            assert!(
                no_meta.meta.metadata().is_empty(),
                "an absent _meta presents as an empty view, not an error"
            );
            assert!(no_meta.meta.server_info.is_none());
            assert_eq!(
                no_meta
                    .meta
                    .final_server_info()
                    .expect("absent identity metadata is valid"),
                None,
                "decoders accept an absent serverInfo; the final requirement is SHOULD"
            );
            let error = decode_typed_complete::<JoinLookupResult>(
                r#"{"resultType":"complete","status":"ready","record":{},"_meta":null}"#,
                ResultPeerEra::Modern,
            )
            .expect_err("explicit null _meta is not an absent _meta");
            assert_eq!(error.kind(), ResultDecodeErrorKind::InvalidKnownMember);
            assert_eq!(error.path(), "$._meta");
            3
        }

        unknown => panic!(
            "the producers published case `{unknown}`, which this join has no predicate for. \
             A renamed case must be re-agreed, never scored zero."
        ),
    }
}


// ---------------------------------------------------------------------------
// Integration-owned capability: tolerant peer cache TTL
// ---------------------------------------------------------------------------
//
// This is NOT part of the A/B floor union and is deliberately not counted
// against any producer's published floor — neither implementation slice owns
// it. The PRT-04 package body mandates it and names its consumer ("the
// tolerant peer client layer"), so under the orchestrator's in-scope rule it
// lands here rather than falling between the two slices and quietly becoming
// nobody's (RH-9). It is asserted directly instead of through `observe`.

/// Exercises every branch the package body enumerates for a peer `ttlMs`.
///
/// The two tolerated deviations and the four protocol errors are checked
/// together, because the whole point of the clause is that they are different
/// answers: tolerating a deviation is only safe if the neighbouring malformed
/// cases are still refused.
fn assert_peer_cache_ttl_contract() {
    // Conforming: a nonnegative integer is usable and carries no diagnostic.
    let (ttl, diagnostic) = decode_peer_cache_ttl(Some(&ExactJsonValue::Number("60000".to_owned())))
        .expect("a nonnegative peer ttlMs conforms");
    assert_eq!(diagnostic, None);
    assert_eq!(
        ttl.conforming().map(fastmcp_protocol::CacheTtl::as_str),
        Some("60000")
    );
    assert_eq!(ttl.freshness_millis(), Ok(60_000));
    assert_eq!(ttl.deviation(), None);

    // Tolerated deviation 1 — negative. Zero freshness, diagnosed, and it
    // cannot be read back out as a server-constructible TTL.
    let (negative, diagnostic) =
        decode_peer_cache_ttl(Some(&ExactJsonValue::Number("-1".to_owned())))
            .expect("a negative peer ttlMs is tolerated, not fatal");
    assert_eq!(
        negative,
        PeerCacheTtl::ImmediatelyStale {
            reason: PeerCacheTtlDeviation::Negative
        }
    );
    assert_eq!(diagnostic, Some(ResultPeerDiagnostic::PeerNegativeCacheTtl));
    assert_eq!(negative.freshness_millis(), Ok(0));
    assert!(
        negative.conforming().is_none(),
        "a tolerated deviation must never re-enter as a valid TTL"
    );

    // Tolerated deviation 2 — absent. Distinguished from explicit null below.
    let (missing, diagnostic) =
        decode_peer_cache_ttl(None).expect("an omitted peer ttlMs is tolerated");
    assert_eq!(
        missing,
        PeerCacheTtl::ImmediatelyStale {
            reason: PeerCacheTtlDeviation::Missing
        }
    );
    assert_eq!(diagnostic, Some(ResultPeerDiagnostic::PeerMissingCacheTtl));
    assert_eq!(missing.freshness_millis(), Ok(0));
    assert!(missing.conforming().is_none());

    // The two deviations stay distinguishable; collapsing them would lose the
    // difference between a hostile peer and an old one.
    assert_ne!(negative, missing);

    // Explicit null is NOT absence. This is the presence-aware distinction the
    // clause depends on, and it is the single most likely thing to regress.
    let error = decode_peer_cache_ttl(Some(&ExactJsonValue::Null))
        .expect_err("explicit null ttlMs is a protocol error, not a tolerated absence");
    assert_eq!(error.kind(), ResultDecodeErrorKind::InvalidKnownMember);
    assert_eq!(error.path(), "$.ttlMs");

    // Fractional, nonnumeric and overflowing values remain protocol errors.
    for rejected in [
        ExactJsonValue::Number("1.5".to_owned()),
        ExactJsonValue::Number("-2.5".to_owned()),
        ExactJsonValue::String("60000".to_owned()),
        ExactJsonValue::Bool(true),
        ExactJsonValue::Array(Vec::new()),
        ExactJsonValue::Object(ExactJsonObject::default()),
        ExactJsonValue::Number("123456789012345678901234567890".to_owned()),
    ] {
        let error = decode_peer_cache_ttl(Some(&rejected))
            .expect_err("only a negative integer or an absent member is tolerated");
        assert_eq!(error.kind(), ResultDecodeErrorKind::InvalidKnownMember);
        assert_eq!(error.path(), "$.ttlMs");
    }

    // An integral exponent spelling is a conforming integer, not a fraction.
    let (exponent, diagnostic) = decode_peer_cache_ttl(Some(&ExactJsonValue::Number(
        "6e4".to_owned(),
    )))
    .expect("an integral exponent spelling is still an integer");
    assert_eq!(diagnostic, None);
    assert_eq!(exponent.freshness_millis(), Ok(60_000));
}

/// The join's floor gate, as a fallible operation both entry points run.
///
/// It is a function rather than an inline `assert!` so the planted negative can
/// drive the *same* code path the positive depends on. An assertion that only
/// restates arithmetic — `observed < observed + 1` — cannot fail and would
/// prove nothing about whether the gate works.
fn meets_floor(case: &JoinedCase, floor: usize) -> Result<usize, String> {
    let observed = observe(&case.name);
    if observed >= floor {
        Ok(observed)
    } else {
        Err(format!(
            "{} ({}, half {}) requires floor={floor} but the join performed only {observed} \
             observation(s)",
            case.id, case.name, case.half
        ))
    }
}

// ---------------------------------------------------------------------------
// Frozen entry points
// ---------------------------------------------------------------------------

#[test]
fn prt_04_i_positive() {
    let union = joined_manifest();
    assert!(
        union.iter().any(|case| case.half == "A") && union.iter().any(|case| case.half == "B"),
        "the join must consume both halves, not one twice"
    );

    let mut total = 0;
    for case in &union {
        total += meets_floor(case, case.floor).unwrap_or_else(|failure| panic!("{failure}"));
    }

    assert_peer_cache_ttl_contract();
    assert!(
        total >= union.iter().map(|case| case.floor).sum::<usize>(),
        "the join must meet the summed published floors"
    );
}

#[test]
fn prt_04_i_planted_negative() {
    // Named state, captured before any planted input is offered.
    let union = joined_manifest();
    let a_bytes = PRT_04_A_EVALUATOR_MANIFEST_V1.to_owned();
    let b_bytes = PRT_04_B_EVALUATOR_MANIFEST_V1.to_owned();
    let a_digest = prt_04_a_manifest_digest();
    let b_digest = prt_04_b_manifest_digest();

    // Planted mutation 1 — one manifest dimension: a single case row is
    // renamed in a local copy of the published A bytes. Nothing else differs,
    // and the row still parses as a well-formed `<id> <name> floor=<N>`.
    // A substituted manifest must not reproduce the producer's digest.
    let renamed = PRT_04_A_EVALUATOR_MANIFEST_V1.replacen(
        "PRT-04.01 core-discriminator-selection floor=2\n",
        "PRT-04.01 core-discriminator-selektion floor=2\n",
        1,
    );
    assert_ne!(renamed, PRT_04_A_EVALUATOR_MANIFEST_V1);
    assert_eq!(
        renamed.len(),
        PRT_04_A_EVALUATOR_MANIFEST_V1.len(),
        "the planted copy differs only in that one name, not in length"
    );
    let renamed_digest = sha256_bounded(renamed.as_bytes(), MAX_PRT_04_MANIFEST_BYTES)
        .expect("within bound");
    assert_ne!(
        renamed_digest.as_bytes(),
        prt_04_a_manifest_digest().as_bytes(),
        "a reconstructed or substituted manifest cannot reproduce the published digest"
    );

    // Planted mutation 2 — one floor dimension: a floor is raised past what the
    // join actually performs. The consumer keeps no local floor table, so the
    // only honest outcome is failure, and that is exactly what is asserted.
    let case = union
        .iter()
        .find(|case| case.name == "core-discriminator-selection")
        .expect("the producer publishes this case");
    let performed = meets_floor(case, case.floor)
        .expect("the published floor is met, which is what makes this a baseline");
    let planted_floor = performed + 1;
    let refusal = meets_floor(case, planted_floor).expect_err(
        "a floor one above the executed observation count must fail the join, \
         not be rounded down to what the consumer happened to do",
    );
    assert!(
        refusal.contains(&case.name) && refusal.contains(&performed.to_string()),
        "the refusal must name the case and the count it actually reached: {refusal}"
    );
    assert!(
        meets_floor(case, case.floor).is_ok(),
        "and the published floor must still pass, so only the floor dimension changed"
    );

    // Planted mutation 3 — one public-entrypoint dimension: the same bytes are
    // offered to the same codec with only the injected policy changed, and the
    // refusal must still preserve the bounded envelope without activating it.
    let (accepted, _) = decode_peer_result(
        UNCLAIMED,
        ResultPeerEra::Modern,
        &DeferringResultDiscriminatorPolicy,
    )
    .expect("baseline deferral");
    assert!(matches!(accepted, DecodedResult::Deferred(_)));
    let error = decode_peer_result(UNCLAIMED, ResultPeerEra::Modern, &CoreResultDiscriminatorPolicy)
        .expect_err("only the injected policy changed");
    assert_eq!(error.kind(), ResultDecodeErrorKind::RejectedExtension);
    assert_eq!(
        error
            .raw_envelope()
            .expect("the rejection preserves its raw envelope")
            .discriminator(),
        "x.example/stream"
    );

    // Planted mutation 4 — one TTL dimension: the peer's `ttlMs` sign. The
    // accepted baseline is `60000`; the planted input is `-60000`, identical in
    // every other respect. It must become a zero-freshness tolerated deviation
    // that cannot be read back as a usable TTL, never a usable 60-second one.
    let (accepted_ttl, accepted_diagnostic) =
        decode_peer_cache_ttl(Some(&ExactJsonValue::Number("60000".to_owned())))
            .expect("baseline conforming ttlMs");
    assert_eq!(accepted_ttl.freshness_millis(), Ok(60_000));
    assert_eq!(accepted_diagnostic, None);
    let (planted_ttl, planted_diagnostic) =
        decode_peer_cache_ttl(Some(&ExactJsonValue::Number("-60000".to_owned())))
            .expect("a negative ttlMs is tolerated, not fatal");
    assert_eq!(
        planted_ttl,
        PeerCacheTtl::ImmediatelyStale {
            reason: PeerCacheTtlDeviation::Negative
        }
    );
    assert_eq!(
        planted_diagnostic,
        Some(ResultPeerDiagnostic::PeerNegativeCacheTtl)
    );
    assert_eq!(
        planted_ttl.freshness_millis(),
        Ok(0),
        "a negative peer TTL has exactly zero freshness and cannot cause cache reuse"
    );
    assert!(
        planted_ttl.conforming().is_none(),
        "the tolerated deviation must not expose a server-constructible TTL"
    );
    // And the accepted baseline is unaffected by having decoded the deviation.
    assert_eq!(
        decode_peer_cache_ttl(Some(&ExactJsonValue::Number("60000".to_owned())))
            .expect("still conforming")
            .0
            .freshness_millis(),
        Ok(60_000)
    );

    // Named state, byte-for-byte unchanged. In particular the producers' own
    // published bytes and digests are untouched by anything above: the planted
    // rename happened in a local copy and never reached the shipped constant.
    assert_eq!(PRT_04_A_EVALUATOR_MANIFEST_V1, a_bytes);
    assert_eq!(PRT_04_B_EVALUATOR_MANIFEST_V1, b_bytes);
    assert_eq!(prt_04_a_manifest_digest().as_bytes(), a_digest.as_bytes());
    assert_eq!(prt_04_b_manifest_digest().as_bytes(), b_digest.as_bytes());
    let reparsed = joined_manifest();
    assert_eq!(reparsed.len(), union.len());
    for (before, after) in union.iter().zip(&reparsed) {
        assert_eq!(before.id, after.id);
        assert_eq!(before.name, after.name);
        assert_eq!(before.floor, after.floor);
    }
}
