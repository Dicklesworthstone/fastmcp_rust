//! Bounded, lossless MCP result envelopes.
//!
//! This module deliberately keeps result decoding separate from the legacy MCP
//! message structs.  It admits one JSON object, preserves open members in their
//! received order, and does not activate an unrecognised discriminator.

use std::fmt;

use crate::jsonrpc::{admit_raw_jsonrpc_document, RawJsonAdmissionError};
use crate::ServerInfo;

/// Maximum encoded bytes accepted by the result codec.
pub const MAX_RESULT_ENCODED_BYTES: usize = 1_048_576;
/// Maximum nesting depth accepted by the result codec.
pub const MAX_RESULT_DEPTH: usize = 64;
/// Maximum members/elements accepted by one JSON object or array.
pub const MAX_RESULT_CONTAINER_MEMBERS: usize = 1_024;
/// Maximum decoded bytes in one JSON string or object key.
pub const MAX_RESULT_STRING_BYTES: usize = 65_536;
/// Maximum source bytes in one JSON number lexeme.
pub const MAX_RESULT_NUMBER_BYTES: usize = 1_024;

/// A recursively bounded JSON value which preserves each number's source
/// lexeme. This is the result codec's exact-value boundary; it never uses an
/// `f64` or a fixed-width integer for an admitted JSON number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactJsonValue {
    /// JSON `null`.
    Null,
    /// A JSON boolean.
    Bool(bool),
    /// A decoded JSON string.
    String(String),
    /// The exact source lexeme of a syntactically valid JSON number.
    Number(String),
    /// An ordered JSON array.
    Array(Vec<ExactJsonValue>),
    /// An ordered JSON object with duplicate names rejected at admission.
    Object(ExactJsonObject),
}

/// One JSON object member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactJsonMember {
    /// Member name as decoded from JSON.
    pub name: String,
    /// Member value.
    pub value: ExactJsonValue,
}

/// An ordered JSON object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExactJsonObject {
    members: Vec<ExactJsonMember>,
}

impl ExactJsonObject {
    /// Returns the object's members in their admitted order.
    #[must_use]
    pub fn members(&self) -> &[ExactJsonMember] {
        &self.members
    }

    /// Finds one member by its exact decoded name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ExactJsonValue> {
        self.members
            .iter()
            .find(|member| member.name == name)
            .map(|member| &member.value)
    }

    fn take(&mut self, name: &str) -> Option<ExactJsonValue> {
        self.members
            .iter()
            .position(|member| member.name == name)
            .map(|index| self.members.remove(index).value)
    }
}

/// An error raised while admitting or decoding a result envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultDecodeError {
    kind: ResultDecodeErrorKind,
    path: String,
    raw_envelope: Option<RawResultEnvelope>,
}

/// Stable result-decoding failure categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultDecodeErrorKind {
    /// The input did not contain exactly one complete JSON value.
    InvalidJson,
    /// A configured result bound was exceeded.
    BoundExceeded,
    /// An object contained the same member name more than once.
    DuplicateMember,
    /// The result envelope was not a JSON object.
    ExpectedObject,
    /// A selected, known field has the wrong JSON kind.
    InvalidKnownMember,
    /// `resultType` was explicit `null` or another non-string value.
    InvalidDiscriminator,
    /// `input_required` had neither `input` nor `request`.
    MissingInputRequest,
    /// A deferred extension was rejected by the supplied discriminator policy.
    RejectedExtension,
    /// A local custom-extra request collided with a known member name.
    KnownMemberCollision,
    /// A typed complete decoder was given a non-complete core result.
    UnexpectedResultType,
}

impl ResultDecodeError {
    fn new(kind: ResultDecodeErrorKind, path: impl Into<String>) -> Self {
        Self {
            kind,
            path: path.into(),
            raw_envelope: None,
        }
    }

    fn rejected_extension(raw_envelope: RawResultEnvelope) -> Self {
        Self {
            kind: ResultDecodeErrorKind::RejectedExtension,
            path: "$.resultType".to_owned(),
            raw_envelope: Some(raw_envelope),
        }
    }

    /// Returns the stable category of this error.
    #[must_use]
    pub const fn kind(&self) -> ResultDecodeErrorKind {
        self.kind
    }

    /// Returns the bounded logical path at which admission failed.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Constructs a precise selected-known-member failure for a typed decoder.
    #[must_use]
    pub fn invalid_known_member(path: impl Into<String>) -> Self {
        Self::new(ResultDecodeErrorKind::InvalidKnownMember, path)
    }

    /// Returns the bounded raw envelope retained when a discriminator policy
    /// rejected an otherwise structurally admitted extension result.
    #[must_use]
    pub fn raw_envelope(&self) -> Option<&RawResultEnvelope> {
        self.raw_envelope.as_ref()
    }
}

impl fmt::Display for ResultDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "result decode error {:?} at {}", self.kind, self.path)
    }
}

impl std::error::Error for ResultDecodeError {}

/// Parses one bounded exact JSON value.
pub fn parse_exact_json(input: &str) -> Result<ExactJsonValue, ResultDecodeError> {
    if input.len() > MAX_RESULT_ENCODED_BYTES {
        return Err(ResultDecodeError::new(
            ResultDecodeErrorKind::BoundExceeded,
            "$",
        ));
    }
    let mut parser = ExactJsonParser::new(input);
    parser.skip_whitespace();
    let value = parser.value(0, "$")?;
    parser.skip_whitespace();
    if parser.offset != input.len() {
        return Err(ResultDecodeError::new(
            ResultDecodeErrorKind::InvalidJson,
            "$",
        ));
    }
    Ok(value)
}

fn parse_exact_result_object(input: &str) -> Result<ExactJsonObject, ResultDecodeError> {
    admit_raw_jsonrpc_document(input.as_bytes(), MAX_RESULT_ENCODED_BYTES)
        .map_err(result_raw_admission_error)?;
    let ExactJsonValue::Object(object) = parse_exact_json(input)? else {
        return Err(ResultDecodeError::new(ResultDecodeErrorKind::ExpectedObject, "$"));
    };
    Ok(object)
}

fn result_raw_admission_error(error: RawJsonAdmissionError) -> ResultDecodeError {
    let kind = match error {
        RawJsonAdmissionError::DuplicateObjectMember => ResultDecodeErrorKind::DuplicateMember,
        RawJsonAdmissionError::DocumentTooLarge
        | RawJsonAdmissionError::NestingTooDeep
        | RawJsonAdmissionError::TooManyContainerEntries
        | RawJsonAdmissionError::NumberTooLong
        | RawJsonAdmissionError::TooManyNumberBytes
        | RawJsonAdmissionError::ExponentTooLarge
        | RawJsonAdmissionError::TooManyDecodedStringBytes => ResultDecodeErrorKind::BoundExceeded,
        RawJsonAdmissionError::InvalidUtf8
        | RawJsonAdmissionError::ByteOrderMark
        | RawJsonAdmissionError::InvalidSyntax
        | RawJsonAdmissionError::TopLevelBatch
        | RawJsonAdmissionError::TopLevelNotObject => ResultDecodeErrorKind::InvalidJson,
    };
    ResultDecodeError::new(kind, "$")
}

/// Result metadata common to complete and input-required results.
#[derive(Debug, Clone)]
pub struct ResultMeta {
    /// SDK-created successful results carry a server identity by default.
    pub server_info: Option<ServerInfo>,
    meta: Option<ExactJsonObject>,
}

impl ResultMeta {
    /// Creates metadata for a locally constructed successful result.
    #[must_use]
    pub fn server_generated(server_info: ServerInfo) -> Self {
        Self {
            server_info: Some(server_info),
            meta: None,
        }
    }

    /// Returns a view that behaves as an empty metadata object when `_meta` was
    /// absent, without causing serialization to synthesize `_meta`.
    #[must_use]
    pub fn metadata(&self) -> MetadataView<'_> {
        MetadataView {
            object: self.meta.as_ref(),
        }
    }
}

/// Read-only view of optional result metadata.
#[derive(Debug, Clone, Copy)]
pub struct MetadataView<'a> {
    object: Option<&'a ExactJsonObject>,
}

impl MetadataView<'_> {
    /// Looks up one metadata member.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ExactJsonValue> {
        self.object.and_then(|object| object.get(name))
    }

    /// Returns whether `_meta` was absent or had no members.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.object.is_none_or(|object| object.members().is_empty())
    }
}

/// Bounded, inert open members retained after known-field consumption.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnknownResultMembers {
    members: Vec<ExactJsonMember>,
}

impl UnknownResultMembers {
    /// Constructs locally authored extras while refusing collisions with the
    /// selected composition's common and method-specific member names.
    pub fn try_new(
        members: Vec<ExactJsonMember>,
        known_names: &[&str],
    ) -> Result<Self, ResultDecodeError> {
        if members.len() > MAX_RESULT_CONTAINER_MEMBERS {
            return Err(ResultDecodeError::new(ResultDecodeErrorKind::BoundExceeded, "$"));
        }
        for (index, member) in members.iter().enumerate() {
            if COMMON_RESULT_MEMBER_NAMES.contains(&member.name.as_str())
                || known_names.contains(&member.name.as_str())
            {
                return Err(ResultDecodeError::new(
                    ResultDecodeErrorKind::KnownMemberCollision,
                    member.name.clone(),
                ));
            }
            if members[..index]
                .iter()
                .any(|preceding| preceding.name == member.name)
            {
                return Err(ResultDecodeError::new(
                    ResultDecodeErrorKind::DuplicateMember,
                    member.name.clone(),
                ));
            }
        }
        validate_local_result_members(&members)?;
        Ok(Self { members })
    }

    /// Returns the retained members in their admitted order.
    #[must_use]
    pub fn members(&self) -> &[ExactJsonMember] {
        &self.members
    }
}

const COMMON_RESULT_MEMBER_NAMES: [&str; 3] = ["resultType", "_meta", "serverInfo"];

fn validate_local_result_members(members: &[ExactJsonMember]) -> Result<(), ResultDecodeError> {
    let encoded_bytes = exact_json_members_len(members, 0)?;
    if encoded_bytes > MAX_RESULT_ENCODED_BYTES {
        return Err(ResultDecodeError::new(ResultDecodeErrorKind::BoundExceeded, "$"));
    }
    Ok(())
}

fn exact_json_members_len(
    members: &[ExactJsonMember],
    depth: usize,
) -> Result<usize, ResultDecodeError> {
    if depth > MAX_RESULT_DEPTH || members.len() > MAX_RESULT_CONTAINER_MEMBERS {
        return Err(ResultDecodeError::new(ResultDecodeErrorKind::BoundExceeded, "$"));
    }
    let mut encoded_bytes = 2_usize;
    for (index, member) in members.iter().enumerate() {
        if member.name.len() > MAX_RESULT_STRING_BYTES {
            return Err(ResultDecodeError::new(
                ResultDecodeErrorKind::BoundExceeded,
                "$.<extra-name>",
            ));
        }
        if members[..index]
            .iter()
            .any(|preceding| preceding.name == member.name)
        {
            return Err(ResultDecodeError::new(
                ResultDecodeErrorKind::DuplicateMember,
                member.name.clone(),
            ));
        }
        let value_bytes = exact_json_value_len(&member.value, depth + 1)?;
        let member_bytes = encoded_json_string_len(&member.name)?
            .checked_add(1)
            .and_then(|size| size.checked_add(value_bytes))
            .ok_or_else(|| ResultDecodeError::new(ResultDecodeErrorKind::BoundExceeded, "$"))?;
        encoded_bytes = encoded_bytes
            .checked_add(usize::from(index != 0))
            .and_then(|size| size.checked_add(member_bytes))
            .ok_or_else(|| ResultDecodeError::new(ResultDecodeErrorKind::BoundExceeded, "$"))?;
        if encoded_bytes > MAX_RESULT_ENCODED_BYTES {
            return Err(ResultDecodeError::new(ResultDecodeErrorKind::BoundExceeded, "$"));
        }
    }
    Ok(encoded_bytes)
}

fn exact_json_value_len(value: &ExactJsonValue, depth: usize) -> Result<usize, ResultDecodeError> {
    if depth > MAX_RESULT_DEPTH {
        return Err(ResultDecodeError::new(ResultDecodeErrorKind::BoundExceeded, "$"));
    }
    match value {
        ExactJsonValue::Null => Ok(4),
        ExactJsonValue::Bool(true) => Ok(4),
        ExactJsonValue::Bool(false) => Ok(5),
        ExactJsonValue::String(value) => {
            if value.len() > MAX_RESULT_STRING_BYTES {
                return Err(ResultDecodeError::new(ResultDecodeErrorKind::BoundExceeded, "$"));
            }
            encoded_json_string_len(value)
        }
        ExactJsonValue::Number(value) => {
            if value.len() > MAX_RESULT_NUMBER_BYTES {
                return Err(ResultDecodeError::new(ResultDecodeErrorKind::BoundExceeded, "$"));
            }
            match parse_exact_json(value)? {
                ExactJsonValue::Number(parsed) if parsed == *value => Ok(value.len()),
                _ => Err(ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, "$")),
            }
        }
        ExactJsonValue::Array(values) => {
            if values.len() > MAX_RESULT_CONTAINER_MEMBERS {
                return Err(ResultDecodeError::new(ResultDecodeErrorKind::BoundExceeded, "$"));
            }
            let mut encoded_bytes = 2_usize;
            for (index, value) in values.iter().enumerate() {
                let separator_bytes = usize::from(index != 0);
                let value_bytes = exact_json_value_len(value, depth + 1)?;
                encoded_bytes = encoded_bytes
                    .checked_add(separator_bytes)
                    .and_then(|size| size.checked_add(value_bytes))
                    .ok_or_else(|| {
                        ResultDecodeError::new(ResultDecodeErrorKind::BoundExceeded, "$")
                    })?;
                if encoded_bytes > MAX_RESULT_ENCODED_BYTES {
                    return Err(ResultDecodeError::new(ResultDecodeErrorKind::BoundExceeded, "$"));
                }
            }
            Ok(encoded_bytes)
        }
        ExactJsonValue::Object(object) => {
            exact_json_members_len(&object.members, depth + 1)
        }
    }
}

fn encoded_json_string_len(value: &str) -> Result<usize, ResultDecodeError> {
    let mut encoded_bytes = 2_usize;
    for character in value.chars() {
        let bytes = match character {
            '"' | '\\' | '\u{0008}' | '\u{000c}' | '\n' | '\r' | '\t' => 2,
            '\u{0000}'..='\u{001f}' => 6,
            _ => character.len_utf8(),
        };
        encoded_bytes = encoded_bytes
            .checked_add(bytes)
            .ok_or_else(|| ResultDecodeError::new(ResultDecodeErrorKind::BoundExceeded, "$"))?;
    }
    Ok(encoded_bytes)
}

/// A typed core `complete` result with inert open siblings.
#[derive(Debug, Clone)]
pub struct CompleteResult<T> {
    /// Method-specific complete payload.
    pub payload: T,
    /// Common result metadata.
    pub meta: ResultMeta,
    /// Open siblings that did not belong to the selected complete composition.
    pub extras: UnknownResultMembers,
}

impl<T> CompleteResult<T> {
    /// Creates a strict complete result. Serialization always emits
    /// `resultType: "complete"`.
    #[must_use]
    pub fn new(payload: T, meta: ResultMeta) -> Self {
        Self {
            payload,
            meta,
            extras: UnknownResultMembers::default(),
        }
    }
}

/// Guarded access to one selected complete composition's declared members.
pub struct TypedCompleteMembers<'a> {
    members: &'a mut ExactJsonObject,
    declared_names: &'static [&'static str],
}

impl TypedCompleteMembers<'_> {
    /// Removes one declared method-specific member.
    ///
    /// An implementation cannot consume an undeclared open member; it remains
    /// inert and is preserved in `UnknownResultMembers` instead.
    pub fn take(&mut self, name: &str) -> Result<Option<ExactJsonValue>, ResultDecodeError> {
        if !self.declared_names.contains(&name) {
            return Err(ResultDecodeError::new(
                ResultDecodeErrorKind::KnownMemberCollision,
                format!("$.{name}"),
            ));
        }
        Ok(self.members.take(name))
    }
}

/// Method-specific decoder for a selected core `complete` result composition.
///
/// Implementations declare every method-specific name they own, consume those
/// names from the raw object, and reject an invalid value at that exact member.
/// The result codec verifies that no declared name remains before it retains
/// all other members as inert `UnknownResultMembers`.
pub trait CompleteResultPayload: Sized {
    /// All method-specific names owned by this selected complete composition.
    const KNOWN_MEMBER_NAMES: &'static [&'static str];

    /// Consumes and validates this composition's method-specific members.
    fn decode_known_members(
        members: &mut TypedCompleteMembers<'_>,
    ) -> Result<Self, ResultDecodeError>;
}

/// A typed core `input_required` result with inert open siblings.
#[derive(Debug, Clone)]
pub struct InputRequiredResult {
    /// Request/input supplied by the server. At least one is always present.
    pub input_or_request: ExactJsonValue,
    /// Common result metadata.
    pub meta: ResultMeta,
    /// Open siblings, including standard names from another composition.
    pub extras: UnknownResultMembers,
}

impl InputRequiredResult {
    /// Creates an input-required result. Its safe encoding never emits cache or
    /// pagination hints.
    #[must_use]
    pub fn new(input_or_request: ExactJsonValue, meta: ResultMeta) -> Self {
        Self {
            input_or_request,
            meta,
            extras: UnknownResultMembers::default(),
        }
    }
}

/// A nonnegative cache TTL used only by server-side safe constructors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheTtl(u64);

impl CacheTtl {
    /// Creates a nonnegative TTL in milliseconds.
    #[must_use]
    pub const fn milliseconds(value: u64) -> Self {
        Self(value)
    }

    /// Returns the TTL in milliseconds.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }
}

/// Peer cache scope. `Public` is a wire value, not an authority grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheScope {
    /// Shareable only when a separately sealed cache registration permits it.
    Public,
    /// The safe default for locally generated cache hints.
    Private,
}

/// A complete-result composition with strict cache hints.
#[derive(Debug, Clone)]
pub struct CacheableResult<T> {
    /// The wrapped complete result.
    pub result: CompleteResult<T>,
    /// Server-generated nonnegative cache TTL.
    pub ttl: CacheTtl,
    /// Server-generated cache scope, defaulting to private.
    pub scope: CacheScope,
}

/// A complete-result composition with a pagination cursor.
#[derive(Debug, Clone)]
pub struct PaginatedResult<T> {
    /// The wrapped complete result.
    pub result: CompleteResult<T>,
    /// Cursor for the following page.
    pub next_cursor: String,
}

/// A raw result envelope for a non-core discriminator. It is diagnostic data,
/// not an activated extension result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawResultEnvelope {
    discriminator: String,
    members: ExactJsonObject,
}

impl RawResultEnvelope {
    /// Returns the losslessly retained non-core discriminator.
    #[must_use]
    pub fn discriminator(&self) -> &str {
        &self.discriminator
    }

    /// Returns every admitted member of the raw envelope.
    #[must_use]
    pub fn members(&self) -> &[ExactJsonMember] {
        self.members.members()
    }
}

/// Result-discriminator decision made after raw structural admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultDiscriminatorDecision {
    /// Decode one of the core result discriminators.
    Core,
    /// Retain the raw envelope for a later negotiated extension decoder.
    DeferredExtension,
    /// Reject the raw envelope without activating it.
    Rejected,
}

mod sealed {
    pub trait Sealed {}
}

/// Registry-agnostic policy seam for already-admitted non-core result types.
/// No policy in this module owns a descriptor registry or activates extensions.
pub trait ResultDiscriminatorPolicy: sealed::Sealed {
    /// Decides whether an admitted discriminator is core, deferred, or rejected.
    fn decide(&self, discriminator: &str) -> ResultDiscriminatorDecision;
}

/// The default policy: only core discriminators are accepted locally.
#[derive(Debug, Clone, Copy, Default)]
pub struct CoreResultDiscriminatorPolicy;

impl sealed::Sealed for CoreResultDiscriminatorPolicy {}

impl ResultDiscriminatorPolicy for CoreResultDiscriminatorPolicy {
    fn decide(&self, discriminator: &str) -> ResultDiscriminatorDecision {
        match discriminator {
            "complete" | "input_required" => ResultDiscriminatorDecision::Core,
            _ => ResultDiscriminatorDecision::Rejected,
        }
    }
}

/// Protocol era used only for peer-ingress compatibility diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultPeerEra {
    /// A peer negotiated an earlier initialize-handshake era.
    Legacy,
    /// A peer negotiated the modern per-request-metadata era.
    Modern,
}

/// Bounded diagnostics produced while preserving interoperable peer input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultPeerDiagnostic {
    /// A modern peer omitted `resultType`; it is decoded as `complete` but
    /// remains nonconformant to the final wire requirement.
    ModernPeerOmittedResultType,
}

/// Core or deferred result decoded from a peer envelope.
#[derive(Debug, Clone)]
pub enum DecodedResult {
    /// A complete result with all non-common members retained as inert extras.
    Complete(CompleteResult<ExactJsonObject>),
    /// An input-required result.
    InputRequired(InputRequiredResult),
    /// A policy-deferred, non-activated raw extension envelope.
    Deferred(RawResultEnvelope),
}

/// Decodes one peer result through the public result codec.
///
/// An absent discriminator defaults to `complete` for either peer era. Explicit
/// null and non-string discriminators are rejected instead of conflating them
/// with absence.
pub fn decode_peer_result(
    input: &str,
    era: ResultPeerEra,
    policy: &dyn ResultDiscriminatorPolicy,
) -> Result<(DecodedResult, Option<ResultPeerDiagnostic>), ResultDecodeError> {
    let mut members = parse_exact_result_object(input)?;
    let result_type = match members.get("resultType") {
        None => ("complete".to_owned(), (era == ResultPeerEra::Modern).then_some(ResultPeerDiagnostic::ModernPeerOmittedResultType)),
        Some(ExactJsonValue::String(value)) => (value.clone(), None),
        Some(_) => {
            return Err(ResultDecodeError::new(
                ResultDecodeErrorKind::InvalidDiscriminator,
                "$.resultType",
            ));
        }
    };
    match policy.decide(&result_type.0) {
        ResultDiscriminatorDecision::Rejected => {
            return Err(ResultDecodeError::rejected_extension(RawResultEnvelope {
                discriminator: result_type.0,
                members,
            }));
        }
        ResultDiscriminatorDecision::DeferredExtension => {
            return Ok((
                DecodedResult::Deferred(RawResultEnvelope {
                    discriminator: result_type.0,
                    members,
                }),
                result_type.1,
            ));
        }
        ResultDiscriminatorDecision::Core => {}
    }
    let _ = members.take("resultType");
    let meta = decode_result_meta(&mut members)?;
    match result_type.0.as_str() {
        "complete" => Ok((
            DecodedResult::Complete(CompleteResult {
                payload: ExactJsonObject::default(),
                meta,
                extras: UnknownResultMembers { members: members.members },
            }),
            result_type.1,
        )),
        "input_required" => {
            let input_or_request = members
                .take("input")
                .or_else(|| members.take("request"))
                .ok_or_else(|| {
                    ResultDecodeError::new(ResultDecodeErrorKind::MissingInputRequest, "$")
                })?;
            Ok((
                DecodedResult::InputRequired(InputRequiredResult {
                    input_or_request,
                    meta,
                    extras: UnknownResultMembers { members: members.members },
                }),
                result_type.1,
            ))
        }
        _ => Err(ResultDecodeError::new(
            ResultDecodeErrorKind::InvalidDiscriminator,
            "$.resultType",
        )),
    }
}

/// Decodes a selected method-specific `complete` composition.
///
/// The core result envelope is admitted first. The selected payload then
/// consumes precisely its declared members; any declared member that remains
/// is rejected as a known-field failure, never demoted to an inert extra.
pub fn decode_typed_complete<T: CompleteResultPayload>(
    input: &str,
    era: ResultPeerEra,
) -> Result<(CompleteResult<T>, Option<ResultPeerDiagnostic>), ResultDecodeError> {
    validate_complete_payload_names::<T>()?;
    let (decoded, diagnostic) = decode_peer_result(input, era, &CoreResultDiscriminatorPolicy)?;
    let DecodedResult::Complete(complete) = decoded else {
        return Err(ResultDecodeError::new(
            ResultDecodeErrorKind::UnexpectedResultType,
            "$.resultType",
        ));
    };
    let CompleteResult { meta, extras, .. } = complete;
    let mut members = ExactJsonObject {
        members: extras.members,
    };
    let payload = {
        let mut typed_members = TypedCompleteMembers {
            members: &mut members,
            declared_names: T::KNOWN_MEMBER_NAMES,
        };
        T::decode_known_members(&mut typed_members)?
    };
    for name in T::KNOWN_MEMBER_NAMES {
        if members.get(name).is_some() {
            return Err(ResultDecodeError::new(
                ResultDecodeErrorKind::InvalidKnownMember,
                format!("$.{name}"),
            ));
        }
    }
    Ok((
        CompleteResult {
            payload,
            meta,
            extras: UnknownResultMembers {
                members: members.members,
            },
        },
        diagnostic,
    ))
}

fn validate_complete_payload_names<T: CompleteResultPayload>() -> Result<(), ResultDecodeError> {
    for (index, name) in T::KNOWN_MEMBER_NAMES.iter().enumerate() {
        if COMMON_RESULT_MEMBER_NAMES.contains(name)
            || T::KNOWN_MEMBER_NAMES[..index]
                .iter()
                .any(|previous| previous == name)
        {
            return Err(ResultDecodeError::new(
                ResultDecodeErrorKind::KnownMemberCollision,
                (*name).to_owned(),
            ));
        }
    }
    Ok(())
}

fn decode_result_meta(members: &mut ExactJsonObject) -> Result<ResultMeta, ResultDecodeError> {
    let meta = match members.take("_meta") {
        None => None,
        Some(ExactJsonValue::Object(value)) => Some(value),
        Some(_) => {
            return Err(ResultDecodeError::new(
                ResultDecodeErrorKind::InvalidKnownMember,
                "$._meta",
            ));
        }
    };
    let server_info = match members.take("serverInfo") {
        None => None,
        Some(ExactJsonValue::Object(mut value)) => {
            let Some(ExactJsonValue::String(name)) = value.take("name") else {
                return Err(ResultDecodeError::new(ResultDecodeErrorKind::InvalidKnownMember, "$.serverInfo.name"));
            };
            let Some(ExactJsonValue::String(version)) = value.take("version") else {
                return Err(ResultDecodeError::new(ResultDecodeErrorKind::InvalidKnownMember, "$.serverInfo.version"));
            };
            if !value.members.is_empty() {
                return Err(ResultDecodeError::new(ResultDecodeErrorKind::InvalidKnownMember, "$.serverInfo"));
            }
            Some(ServerInfo { name, version })
        }
        Some(_) => {
            return Err(ResultDecodeError::new(
                ResultDecodeErrorKind::InvalidKnownMember,
                "$.serverInfo",
            ));
        }
    };
    Ok(ResultMeta { server_info, meta })
}

/// Re-emits a result without discarding or semantically rewriting any retained
/// open member. Safe complete and input-required variants always emit their
/// explicit core discriminator.
#[must_use]
pub fn encode_result(result: &DecodedResult) -> String {
    let mut members = Vec::new();
    match result {
        DecodedResult::Complete(complete) => {
            members.push(ExactJsonMember {
                name: "resultType".to_owned(),
                value: ExactJsonValue::String("complete".to_owned()),
            });
            append_result_meta(&mut members, &complete.meta);
            members.extend(complete.payload.members.clone());
            members.extend(complete.extras.members.clone());
        }
        DecodedResult::InputRequired(input_required) => {
            members.push(ExactJsonMember {
                name: "resultType".to_owned(),
                value: ExactJsonValue::String("input_required".to_owned()),
            });
            append_result_meta(&mut members, &input_required.meta);
            members.push(ExactJsonMember {
                name: "input".to_owned(),
                value: input_required.input_or_request.clone(),
            });
            members.extend(input_required.extras.members.clone());
        }
        DecodedResult::Deferred(deferred) => return encode_exact_object(&deferred.members),
    }
    encode_exact_object(&ExactJsonObject { members })
}

fn append_result_meta(members: &mut Vec<ExactJsonMember>, meta: &ResultMeta) {
    if let Some(value) = &meta.meta {
        members.push(ExactJsonMember {
            name: "_meta".to_owned(),
            value: ExactJsonValue::Object(value.clone()),
        });
    }
    if let Some(server_info) = &meta.server_info {
        members.push(ExactJsonMember {
            name: "serverInfo".to_owned(),
            value: ExactJsonValue::Object(ExactJsonObject {
                members: vec![
                    ExactJsonMember {
                        name: "name".to_owned(),
                        value: ExactJsonValue::String(server_info.name.clone()),
                    },
                    ExactJsonMember {
                        name: "version".to_owned(),
                        value: ExactJsonValue::String(server_info.version.clone()),
                    },
                ],
            }),
        });
    }
}

fn encode_exact_object(object: &ExactJsonObject) -> String {
    let mut output = String::from("{");
    for (index, member) in object.members.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        encode_json_string(&member.name, &mut output);
        output.push(':');
        encode_exact_value(&member.value, &mut output);
    }
    output.push('}');
    output
}

fn encode_exact_value(value: &ExactJsonValue, output: &mut String) {
    match value {
        ExactJsonValue::Null => output.push_str("null"),
        ExactJsonValue::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        ExactJsonValue::String(value) => encode_json_string(value, output),
        ExactJsonValue::Number(value) => output.push_str(value),
        ExactJsonValue::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                encode_exact_value(value, output);
            }
            output.push(']');
        }
        ExactJsonValue::Object(object) => output.push_str(&encode_exact_object(object)),
    }
}

fn encode_json_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{0000}'..='\u{001f}' => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", u32::from(character));
            }
            _ => output.push(character),
        }
    }
    output.push('"');
}

struct ExactJsonParser<'a> {
    input: &'a str,
    offset: usize,
}

impl<'a> ExactJsonParser<'a> {
    const fn new(input: &'a str) -> Self {
        Self { input, offset: 0 }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.byte(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.offset += 1;
        }
    }

    fn byte(&self) -> Option<u8> {
        self.input.as_bytes().get(self.offset).copied()
    }

    fn value(&mut self, depth: usize, path: &str) -> Result<ExactJsonValue, ResultDecodeError> {
        if depth > MAX_RESULT_DEPTH {
            return Err(ResultDecodeError::new(ResultDecodeErrorKind::BoundExceeded, path));
        }
        match self.byte() {
            Some(b'n') if self.consume(b"null") => Ok(ExactJsonValue::Null),
            Some(b't') if self.consume(b"true") => Ok(ExactJsonValue::Bool(true)),
            Some(b'f') if self.consume(b"false") => Ok(ExactJsonValue::Bool(false)),
            Some(b'"') => self.string(path).map(ExactJsonValue::String),
            Some(b'[') => self.array(depth, path),
            Some(b'{') => self.object(depth, path),
            Some(b'-' | b'0'..=b'9') => self.number(path).map(ExactJsonValue::Number),
            _ => Err(ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path)),
        }
    }

    fn consume(&mut self, token: &[u8]) -> bool {
        if self.input.as_bytes().get(self.offset..self.offset + token.len()) == Some(token) {
            self.offset += token.len();
            true
        } else {
            false
        }
    }

    fn string(&mut self, path: &str) -> Result<String, ResultDecodeError> {
        self.offset += 1;
        let mut value = String::new();
        loop {
            let Some(byte) = self.byte() else {
                return Err(ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path));
            };
            match byte {
                b'"' => {
                    self.offset += 1;
                    if value.len() > MAX_RESULT_STRING_BYTES {
                        return Err(ResultDecodeError::new(ResultDecodeErrorKind::BoundExceeded, path));
                    }
                    return Ok(value);
                }
                0x00..=0x1f => return Err(ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path)),
                b'\\' => {
                    self.offset += 1;
                    let escaped = self.byte().ok_or_else(|| ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path))?;
                    self.offset += 1;
                    match escaped {
                        b'"' => value.push('"'),
                        b'\\' => value.push('\\'),
                        b'/' => value.push('/'),
                        b'b' => value.push('\u{0008}'),
                        b'f' => value.push('\u{000c}'),
                        b'n' => value.push('\n'),
                        b'r' => value.push('\r'),
                        b't' => value.push('\t'),
                        b'u' => value.push(self.unicode_escape(path)?),
                        _ => return Err(ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path)),
                    }
                }
                _ => {
                    let tail = &self.input[self.offset..];
                    let character = tail.chars().next().ok_or_else(|| ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path))?;
                    value.push(character);
                    self.offset += character.len_utf8();
                }
            }
            if value.len() > MAX_RESULT_STRING_BYTES {
                return Err(ResultDecodeError::new(ResultDecodeErrorKind::BoundExceeded, path));
            }
        }
    }

    fn unicode_escape(&mut self, path: &str) -> Result<char, ResultDecodeError> {
        let unit = self.hex_unit(path)?;
        if !(0xd800..=0xdbff).contains(&unit) {
            return char::from_u32(u32::from(unit))
                .ok_or_else(|| ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path));
        }
        if !self.consume(b"\\u") {
            return Err(ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path));
        }
        let low = self.hex_unit(path)?;
        if !(0xdc00..=0xdfff).contains(&low) {
            return Err(ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path));
        }
        let codepoint = 0x10000 + ((u32::from(unit) - 0xd800) << 10) + (u32::from(low) - 0xdc00);
        char::from_u32(codepoint)
            .ok_or_else(|| ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path))
    }

    fn hex_unit(&mut self, path: &str) -> Result<u16, ResultDecodeError> {
        let bytes = self.input.as_bytes().get(self.offset..self.offset + 4).ok_or_else(|| ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path))?;
        self.offset += 4;
        bytes.iter().try_fold(0_u16, |value, byte| {
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return Err(ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path)),
            };
            Ok((value << 4) | u16::from(digit))
        })
    }

    fn number(&mut self, path: &str) -> Result<String, ResultDecodeError> {
        let start = self.offset;
        if self.byte() == Some(b'-') { self.offset += 1; }
        match self.byte() {
            Some(b'0') => self.offset += 1,
            Some(b'1'..=b'9') => {
                self.offset += 1;
                while matches!(self.byte(), Some(b'0'..=b'9')) { self.offset += 1; }
            }
            _ => return Err(ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path)),
        }
        if self.byte() == Some(b'.') {
            self.offset += 1;
            let fraction = self.offset;
            while matches!(self.byte(), Some(b'0'..=b'9')) { self.offset += 1; }
            if self.offset == fraction { return Err(ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path)); }
        }
        if matches!(self.byte(), Some(b'e' | b'E')) {
            self.offset += 1;
            if matches!(self.byte(), Some(b'+' | b'-')) { self.offset += 1; }
            let exponent = self.offset;
            while matches!(self.byte(), Some(b'0'..=b'9')) { self.offset += 1; }
            if self.offset == exponent { return Err(ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path)); }
        }
        let value = &self.input[start..self.offset];
        if value.len() > MAX_RESULT_NUMBER_BYTES {
            return Err(ResultDecodeError::new(ResultDecodeErrorKind::BoundExceeded, path));
        }
        Ok(value.to_owned())
    }

    fn array(&mut self, depth: usize, path: &str) -> Result<ExactJsonValue, ResultDecodeError> {
        self.offset += 1;
        self.skip_whitespace();
        let mut values = Vec::new();
        if self.byte() == Some(b']') { self.offset += 1; return Ok(ExactJsonValue::Array(values)); }
        loop {
            if values.len() == MAX_RESULT_CONTAINER_MEMBERS { return Err(ResultDecodeError::new(ResultDecodeErrorKind::BoundExceeded, path)); }
            let item_path = format!("{path}/{}", values.len());
            values.push(self.value(depth + 1, &item_path)?);
            self.skip_whitespace();
            match self.byte() {
                Some(b',') => { self.offset += 1; self.skip_whitespace(); }
                Some(b']') => { self.offset += 1; return Ok(ExactJsonValue::Array(values)); }
                _ => return Err(ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path)),
            }
        }
    }

    fn object(&mut self, depth: usize, path: &str) -> Result<ExactJsonValue, ResultDecodeError> {
        self.offset += 1;
        self.skip_whitespace();
        let mut members = Vec::new();
        if self.byte() == Some(b'}') { self.offset += 1; return Ok(ExactJsonValue::Object(ExactJsonObject { members })); }
        loop {
            if members.len() == MAX_RESULT_CONTAINER_MEMBERS { return Err(ResultDecodeError::new(ResultDecodeErrorKind::BoundExceeded, path)); }
            if self.byte() != Some(b'"') { return Err(ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path)); }
            let name = self.string(path)?;
            if members.iter().any(|member: &ExactJsonMember| member.name == name) {
                return Err(ResultDecodeError::new(ResultDecodeErrorKind::DuplicateMember, format!("{path}/{name}")));
            }
            self.skip_whitespace();
            if self.byte() != Some(b':') { return Err(ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path)); }
            self.offset += 1;
            self.skip_whitespace();
            let member_path = format!("{path}/{name}");
            let value = self.value(depth + 1, &member_path)?;
            members.push(ExactJsonMember { name, value });
            self.skip_whitespace();
            match self.byte() {
                Some(b',') => { self.offset += 1; self.skip_whitespace(); }
                Some(b'}') => { self.offset += 1; return Ok(ExactJsonValue::Object(ExactJsonObject { members })); }
                _ => return Err(ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_unit_a_positive_round_trip() {
        let source = r#"{"resultType":"complete","_meta":{"trace":true},"serverInfo":{"name":"FastMCP","version":"0.1"},"first":{"integer":123456789012345678901234567890,"decimal":1.20e+4,"nil":null,"array":[false,"text"]},"second":{"nested":{"ok":true}}}"#;
        let (decoded, diagnostic) = decode_peer_result(
            source,
            ResultPeerEra::Modern,
            &CoreResultDiscriminatorPolicy,
        )
        .expect("complete result must round-trip through the public codec");
        assert_eq!(diagnostic, None);
        let DecodedResult::Complete(complete) = decoded else { panic!("complete result"); };
        assert_eq!(complete.meta.server_info.as_ref().map(|info| info.name.as_str()), Some("FastMCP"));
        assert!(matches!(complete.meta.metadata().get("trace"), Some(ExactJsonValue::Bool(true))));
        let extras = complete.extras.members();
        assert_eq!(extras.iter().map(|member| member.name.as_str()).collect::<Vec<_>>(), ["first", "second"]);
        let Some(ExactJsonValue::Object(first)) = complete.extras.members().first().map(|member| &member.value) else { panic!("first extra"); };
        assert_eq!(first.get("integer"), Some(&ExactJsonValue::Number("123456789012345678901234567890".to_owned())));
        assert_eq!(first.get("decimal"), Some(&ExactJsonValue::Number("1.20e+4".to_owned())));
        assert_eq!(encode_result(&DecodedResult::Complete(complete)), source);
    }

    #[test]
    fn result_unit_a_rejects_null_discriminator() {
        let accepted = r#"{"resultType":"complete","extension":{"count":1.20e+4}}"#;
        let (baseline, _) = decode_peer_result(accepted, ResultPeerEra::Legacy, &CoreResultDiscriminatorPolicy)
            .expect("baseline");
        let planted = r#"{"resultType":null,"extension":{"count":1.20e+4}}"#;
        let error = decode_peer_result(planted, ResultPeerEra::Legacy, &CoreResultDiscriminatorPolicy)
            .expect_err("only the discriminator dimension changed");
        assert_eq!(error.kind(), ResultDecodeErrorKind::InvalidDiscriminator);
        assert_eq!(error.path(), "$.resultType");
        let (reaccepted, _) = decode_peer_result(accepted, ResultPeerEra::Legacy, &CoreResultDiscriminatorPolicy)
            .expect("pristine input is unchanged by the rejection");
        let (DecodedResult::Complete(before), DecodedResult::Complete(after)) = (baseline, reaccepted) else { panic!("complete baseline"); };
        assert_eq!(before.extras, after.extras);
        assert_eq!(before.extras.members().first().map(|member| &member.value), Some(&ExactJsonValue::Object(ExactJsonObject { members: vec![ExactJsonMember { name: "count".to_owned(), value: ExactJsonValue::Number("1.20e+4".to_owned()) }] })));
        assert_eq!(encode_result(&DecodedResult::Complete(before)), accepted);
    }

    #[test]
    fn rejected_extension_retains_its_raw_envelope() {
        let source = r#"{"before":true,"resultType":"example/extension","after":1.20e+4}"#;
        let error = decode_peer_result(source, ResultPeerEra::Modern, &CoreResultDiscriminatorPolicy)
            .expect_err("the default policy must not activate an unclaimed extension");
        assert_eq!(error.kind(), ResultDecodeErrorKind::RejectedExtension);
        assert_eq!(error.path(), "$.resultType");
        let envelope = error.raw_envelope().expect("rejected envelope is diagnostic data");
        assert_eq!(envelope.discriminator(), "example/extension");
        assert_eq!(envelope.members().iter().map(|member| member.name.as_str()).collect::<Vec<_>>(), ["before", "resultType", "after"]);
        assert_eq!(envelope.members()[2].value, ExactJsonValue::Number("1.20e+4".to_owned()));
    }

    #[test]
    fn locally_authored_extras_use_the_bounded_exact_value_boundary() {
        let valid = UnknownResultMembers::try_new(
            vec![ExactJsonMember {
                name: "extension".to_owned(),
                value: ExactJsonValue::Number("123456789012345678901234567890".to_owned()),
            }],
            &["resultType", "_meta", "serverInfo"],
        )
        .expect("a bounded exact numeric lexeme is retained");
        assert_eq!(valid.members()[0].value, ExactJsonValue::Number("123456789012345678901234567890".to_owned()));

        let invalid = UnknownResultMembers::try_new(
            vec![ExactJsonMember {
                name: "extension".to_owned(),
                value: ExactJsonValue::Number("1.".to_owned()),
            }],
            &["resultType", "_meta", "serverInfo"],
        )
        .expect_err("an invalid numeric lexeme never enters an open-member result");
        assert_eq!(invalid.kind(), ResultDecodeErrorKind::InvalidJson);

        let collision = UnknownResultMembers::try_new(
            vec![ExactJsonMember {
                name: "resultType".to_owned(),
                value: ExactJsonValue::String("complete".to_owned()),
            }],
            &[],
        )
        .expect_err("a common discriminator can never be locally authored as an extra");
        assert_eq!(collision.kind(), ResultDecodeErrorKind::KnownMemberCollision);
    }

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
    fn result_unit_b_typed_decode_preserves_open_members() {
        let source = r#"{"resultType":"complete","status":"ready","record":{"id":123456789012345678901234567890},"opaque":{"null":null,"bool":true,"decimal":1.20e+4,"array":["kept"]}}"#;
        let (decoded, diagnostic) = decode_typed_complete::<LookupResult>(source, ResultPeerEra::Modern)
            .expect("selected complete members decode through the public result codec");
        assert_eq!(diagnostic, None);
        assert_eq!(decoded.payload.status, "ready");
        assert_eq!(decoded.payload.record.get("id"), Some(&ExactJsonValue::Number("123456789012345678901234567890".to_owned())));
        assert_eq!(decoded.extras.members().iter().map(|member| member.name.as_str()).collect::<Vec<_>>(), ["opaque"]);
        assert_eq!(decoded.extras.members().first().map(|member| &member.value), Some(&ExactJsonValue::Object(ExactJsonObject { members: vec![ExactJsonMember { name: "null".to_owned(), value: ExactJsonValue::Null }, ExactJsonMember { name: "bool".to_owned(), value: ExactJsonValue::Bool(true) }, ExactJsonMember { name: "decimal".to_owned(), value: ExactJsonValue::Number("1.20e+4".to_owned()) }, ExactJsonMember { name: "array".to_owned(), value: ExactJsonValue::Array(vec![ExactJsonValue::String("kept".to_owned())]) }] })));
    }

    #[test]
    fn result_unit_b_typed_decode_rejects_wrong_known_kind() {
        let accepted = r#"{"resultType":"complete","status":"ready","record":{"id":123456789012345678901234567890},"opaque":{"decimal":1.20e+4}}"#;
        let (baseline, _) = decode_typed_complete::<LookupResult>(accepted, ResultPeerEra::Modern)
            .expect("baseline selected complete result");
        let planted = r#"{"resultType":"complete","status":false,"record":{"id":123456789012345678901234567890},"opaque":{"decimal":1.20e+4}}"#;
        let error = decode_typed_complete::<LookupResult>(planted, ResultPeerEra::Modern)
            .expect_err("only the selected status kind changed");
        assert_eq!(error.kind(), ResultDecodeErrorKind::InvalidKnownMember);
        assert_eq!(error.path(), "$.status");
        let (reaccepted, _) = decode_typed_complete::<LookupResult>(accepted, ResultPeerEra::Modern)
            .expect("the rejected peer document cannot mutate future typed decodes");
        assert_eq!(reaccepted.payload, baseline.payload);
        assert_eq!(reaccepted.extras, baseline.extras);
        assert_eq!(reaccepted.extras.members().first().map(|member| &member.value), Some(&ExactJsonValue::Object(ExactJsonObject { members: vec![ExactJsonMember { name: "decimal".to_owned(), value: ExactJsonValue::Number("1.20e+4".to_owned()) }] })));
    }
}
