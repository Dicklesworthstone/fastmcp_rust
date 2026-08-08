//! Bounded, lossless MCP result envelopes.
//!
//! This module deliberately keeps result decoding separate from the legacy MCP
//! message structs.  It admits one JSON object, preserves open members in their
//! received order, and does not activate an unrecognised discriminator.

use std::fmt;

use crate::common_types::{Implementation, OpenMetadata};
use crate::jsonrpc::{RawJsonAdmissionError, admit_raw_jsonrpc_document};
use crate::protocol_policy::ProtocolEra;

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
    /// A modern result omitted its required `resultType` discriminator.
    MissingDiscriminator,
    /// `input_required` had neither `inputRequests` nor `requestState`.
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
        write!(
            formatter,
            "result decode error {:?} at {}",
            self.kind, self.path
        )
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

/// Converts an ordinary serde value into the result algebra's bounded exact
/// representation before it is attached to a locally authored result.
pub fn exact_json_from_serde(
    value: &serde_json::Value,
) -> Result<ExactJsonValue, ResultDecodeError> {
    let exact = exact_json_from_serde_unchecked(value);
    let _ = exact_json_value_len(&exact, 0)?;
    Ok(exact)
}

fn exact_json_from_serde_unchecked(value: &serde_json::Value) -> ExactJsonValue {
    match value {
        serde_json::Value::Null => ExactJsonValue::Null,
        serde_json::Value::Bool(value) => ExactJsonValue::Bool(*value),
        serde_json::Value::String(value) => ExactJsonValue::String(value.clone()),
        serde_json::Value::Number(value) => ExactJsonValue::Number(value.to_string()),
        serde_json::Value::Array(values) => {
            ExactJsonValue::Array(values.iter().map(exact_json_from_serde_unchecked).collect())
        }
        serde_json::Value::Object(values) => ExactJsonValue::Object(ExactJsonObject {
            members: values
                .iter()
                .map(|(name, value)| ExactJsonMember {
                    name: name.clone(),
                    value: exact_json_from_serde_unchecked(value),
                })
                .collect(),
        }),
    }
}

/// Converts one exact result value into a serde value for a selected typed
/// method payload. Open result siblings remain exact and are never converted
/// unless that payload explicitly owns their member name.
pub fn exact_json_to_serde(value: &ExactJsonValue) -> Result<serde_json::Value, ResultDecodeError> {
    match value {
        ExactJsonValue::Null => Ok(serde_json::Value::Null),
        ExactJsonValue::Bool(value) => Ok(serde_json::Value::Bool(*value)),
        ExactJsonValue::String(value) => Ok(serde_json::Value::String(value.clone())),
        ExactJsonValue::Number(value) => serde_json::from_str(value)
            .map_err(|_| ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, "$")),
        ExactJsonValue::Array(values) => values
            .iter()
            .map(exact_json_to_serde)
            .collect::<Result<Vec<_>, _>>()
            .map(serde_json::Value::Array),
        ExactJsonValue::Object(object) => object
            .members()
            .iter()
            .map(|member| Ok((member.name.clone(), exact_json_to_serde(&member.value)?)))
            .collect::<Result<serde_json::Map<_, _>, ResultDecodeError>>()
            .map(serde_json::Value::Object),
    }
}

fn parse_exact_result_object(input: &str) -> Result<ExactJsonObject, ResultDecodeError> {
    admit_raw_jsonrpc_document(input.as_bytes(), MAX_RESULT_ENCODED_BYTES)
        .map_err(result_raw_admission_error)?;
    let ExactJsonValue::Object(object) = parse_exact_json(input)? else {
        return Err(ResultDecodeError::new(
            ResultDecodeErrorKind::ExpectedObject,
            "$",
        ));
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
    /// Compatibility view of a locally authored server identity.
    ///
    /// Final encoding moves this identity into
    /// `_meta.io.modelcontextprotocol/serverInfo`; it is never emitted as a
    /// top-level result member.
    pub server_info: Option<Implementation>,
    meta: Option<OpenMetadata>,
    exact_meta: Option<ExactJsonObject>,
}

impl ResultMeta {
    /// Creates metadata for a locally constructed successful result.
    #[must_use]
    pub fn server_generated(server_info: Implementation) -> Self {
        let value = serde_json::to_value(server_info)
            .expect("final implementation identity always serializes");
        let metadata = OpenMetadata::try_from_entries([(
            "io.modelcontextprotocol/serverInfo".to_owned(),
            value,
        )])
        .expect("final implementation identity is valid result metadata");
        Self {
            server_info: None,
            meta: None,
            exact_meta: None,
        }
        .with_metadata(metadata)
    }

    /// Attaches final common metadata without synthesizing it when absent.
    #[must_use]
    pub fn with_metadata(mut self, metadata: OpenMetadata) -> Self {
        let object = metadata.entries().clone().into_iter().collect();
        let exact = exact_json_from_serde_unchecked(&serde_json::Value::Object(object));
        let ExactJsonValue::Object(exact_meta) = exact else {
            unreachable!("metadata always encodes as an object");
        };
        self.meta = Some(metadata);
        self.exact_meta = Some(exact_meta);
        self
    }

    /// Returns a view that behaves as an empty metadata object when `_meta` was
    /// absent, without causing serialization to synthesize `_meta`.
    #[must_use]
    pub fn metadata(&self) -> MetadataView<'_> {
        MetadataView {
            object: self.exact_meta.as_ref(),
        }
    }

    /// Decodes the final server identity from its reserved metadata location.
    pub fn final_server_info(&self) -> Result<Option<Implementation>, ResultDecodeError> {
        self.meta.as_ref().map_or(Ok(None), |metadata| {
            metadata.server_info().map_err(|_| {
                ResultDecodeError::new(ResultDecodeErrorKind::InvalidKnownMember, "$._meta")
            })
        })
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
            return Err(ResultDecodeError::new(
                ResultDecodeErrorKind::BoundExceeded,
                "$",
            ));
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

    /// Returns the retained members for a selected typed composition.
    #[must_use]
    pub fn into_members(self) -> Vec<ExactJsonMember> {
        self.members
    }
}

const COMMON_RESULT_MEMBER_NAMES: [&str; 3] = ["resultType", "_meta", "serverInfo"];

fn validate_local_result_members(members: &[ExactJsonMember]) -> Result<(), ResultDecodeError> {
    let encoded_bytes = exact_json_members_len(members, 0)?;
    if encoded_bytes > MAX_RESULT_ENCODED_BYTES {
        return Err(ResultDecodeError::new(
            ResultDecodeErrorKind::BoundExceeded,
            "$",
        ));
    }
    Ok(())
}

fn exact_json_members_len(
    members: &[ExactJsonMember],
    depth: usize,
) -> Result<usize, ResultDecodeError> {
    if depth > MAX_RESULT_DEPTH || members.len() > MAX_RESULT_CONTAINER_MEMBERS {
        return Err(ResultDecodeError::new(
            ResultDecodeErrorKind::BoundExceeded,
            "$",
        ));
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
            return Err(ResultDecodeError::new(
                ResultDecodeErrorKind::BoundExceeded,
                "$",
            ));
        }
    }
    Ok(encoded_bytes)
}

fn exact_json_value_len(value: &ExactJsonValue, depth: usize) -> Result<usize, ResultDecodeError> {
    if depth > MAX_RESULT_DEPTH {
        return Err(ResultDecodeError::new(
            ResultDecodeErrorKind::BoundExceeded,
            "$",
        ));
    }
    match value {
        ExactJsonValue::Null => Ok(4),
        ExactJsonValue::Bool(true) => Ok(4),
        ExactJsonValue::Bool(false) => Ok(5),
        ExactJsonValue::String(value) => {
            if value.len() > MAX_RESULT_STRING_BYTES {
                return Err(ResultDecodeError::new(
                    ResultDecodeErrorKind::BoundExceeded,
                    "$",
                ));
            }
            encoded_json_string_len(value)
        }
        ExactJsonValue::Number(value) => {
            if value.len() > MAX_RESULT_NUMBER_BYTES {
                return Err(ResultDecodeError::new(
                    ResultDecodeErrorKind::BoundExceeded,
                    "$",
                ));
            }
            match parse_exact_json(value)? {
                ExactJsonValue::Number(parsed) if parsed == *value => Ok(value.len()),
                _ => Err(ResultDecodeError::new(
                    ResultDecodeErrorKind::InvalidJson,
                    "$",
                )),
            }
        }
        ExactJsonValue::Array(values) => {
            if values.len() > MAX_RESULT_CONTAINER_MEMBERS {
                return Err(ResultDecodeError::new(
                    ResultDecodeErrorKind::BoundExceeded,
                    "$",
                ));
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
                    return Err(ResultDecodeError::new(
                        ResultDecodeErrorKind::BoundExceeded,
                        "$",
                    ));
                }
            }
            Ok(encoded_bytes)
        }
        ExactJsonValue::Object(object) => exact_json_members_len(&object.members, depth + 1),
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
    /// Final input requests supplied by the server, when present.
    input_requests: Option<ExactJsonObject>,
    /// Opaque state supplied for the final retry, when present.
    request_state: Option<String>,
    /// Common result metadata.
    pub meta: ResultMeta,
    /// Open siblings, including standard names from another composition.
    pub extras: UnknownResultMembers,
}

impl InputRequiredResult {
    /// Creates an input-required result using final retry members only.
    pub fn new(
        input_requests: Option<ExactJsonObject>,
        request_state: Option<String>,
        meta: ResultMeta,
    ) -> Result<Self, ResultDecodeError> {
        if input_requests.is_none() && request_state.is_none() {
            return Err(ResultDecodeError::new(
                ResultDecodeErrorKind::MissingInputRequest,
                "$",
            ));
        }
        Ok(Self {
            input_requests,
            request_state,
            meta,
            extras: UnknownResultMembers::default(),
        })
    }

    /// Returns final input requests without converting their exact members.
    #[must_use]
    pub fn input_requests(&self) -> Option<&ExactJsonObject> {
        self.input_requests.as_ref()
    }

    /// Returns the opaque final retry state, if supplied.
    #[must_use]
    pub fn request_state(&self) -> Option<&str> {
        self.request_state.as_deref()
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

impl From<ProtocolEra> for ResultPeerEra {
    fn from(era: ProtocolEra) -> Self {
        match era {
            ProtocolEra::Legacy2024 => Self::Legacy,
            ProtocolEra::Modern2026 => Self::Modern,
        }
    }
}

/// Bounded diagnostics reserved for optional legacy peer compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultPeerDiagnostic {
    /// A legacy peer used a compatibility result shape.
    LegacyCompatibilityShape,
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
/// A final peer must provide `resultType`. An absent discriminator defaults to
/// `complete` only for the legacy era. Explicit null and non-string
/// discriminators are rejected instead of conflating them with absence.
pub fn decode_peer_result(
    input: &str,
    era: ResultPeerEra,
    policy: &dyn ResultDiscriminatorPolicy,
) -> Result<(DecodedResult, Option<ResultPeerDiagnostic>), ResultDecodeError> {
    let mut members = parse_exact_result_object(input)?;
    let result_type = match members.get("resultType") {
        None if era == ResultPeerEra::Legacy => ("complete".to_owned(), None),
        None => {
            return Err(ResultDecodeError::new(
                ResultDecodeErrorKind::MissingDiscriminator,
                "$.resultType",
            ));
        }
        Some(ExactJsonValue::String(value)) => (value.clone(), None),
        Some(_) => {
            return Err(ResultDecodeError::new(
                ResultDecodeErrorKind::InvalidDiscriminator,
                "$.resultType",
            ));
        }
    };
    if members.get("serverInfo").is_some() {
        return Err(ResultDecodeError::new(
            ResultDecodeErrorKind::InvalidKnownMember,
            "$.serverInfo",
        ));
    }
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
                extras: UnknownResultMembers {
                    members: members.members,
                },
            }),
            result_type.1,
        )),
        "input_required" => {
            if members.get("input").is_some() {
                return Err(ResultDecodeError::new(
                    ResultDecodeErrorKind::InvalidKnownMember,
                    "$.input",
                ));
            }
            if members.get("request").is_some() {
                return Err(ResultDecodeError::new(
                    ResultDecodeErrorKind::InvalidKnownMember,
                    "$.request",
                ));
            }
            let input_requests = match members.take("inputRequests") {
                None => None,
                Some(ExactJsonValue::Object(value)) => Some(value),
                Some(_) => {
                    return Err(ResultDecodeError::new(
                        ResultDecodeErrorKind::InvalidKnownMember,
                        "$.inputRequests",
                    ));
                }
            };
            let request_state = match members.take("requestState") {
                None => None,
                Some(ExactJsonValue::String(value)) => Some(value),
                Some(_) => {
                    return Err(ResultDecodeError::new(
                        ResultDecodeErrorKind::InvalidKnownMember,
                        "$.requestState",
                    ));
                }
            };
            let input_required = InputRequiredResult::new(input_requests, request_state, meta)?;
            Ok((
                DecodedResult::InputRequired(InputRequiredResult {
                    extras: UnknownResultMembers {
                        members: members.members,
                    },
                    ..input_required
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

/// Decodes one peer result using the protocol era selected for its request.
///
/// This is the dispatch-facing entry point. It keeps the older
/// [`ResultPeerEra`] spelling available for existing callers while ensuring
/// that request and result selection share one exact era source of truth.
pub fn decode_peer_result_for_era(
    input: &str,
    era: ProtocolEra,
    policy: &dyn ResultDiscriminatorPolicy,
) -> Result<(DecodedResult, Option<ResultPeerDiagnostic>), ResultDecodeError> {
    decode_peer_result(input, era.into(), policy)
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
    validate_known_member_names(T::KNOWN_MEMBER_NAMES)
}

fn validate_known_member_names(names: &[&str]) -> Result<(), ResultDecodeError> {
    for (index, name) in names.iter().enumerate() {
        if COMMON_RESULT_MEMBER_NAMES.contains(name)
            || names[..index].iter().any(|previous| previous == name)
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
    let (meta, exact_meta) = match members.take("_meta") {
        None => (None, None),
        Some(ExactJsonValue::Object(value)) => (
            Some(
                serde_json::from_value(exact_json_to_serde(&ExactJsonValue::Object(
                    value.clone(),
                ))?)
                .map_err(|_| {
                    ResultDecodeError::new(ResultDecodeErrorKind::InvalidKnownMember, "$._meta")
                })?,
            ),
            Some(value),
        ),
        Some(_) => {
            return Err(ResultDecodeError::new(
                ResultDecodeErrorKind::InvalidKnownMember,
                "$._meta",
            ));
        }
    };
    if members.get("serverInfo").is_some() {
        return Err(ResultDecodeError::new(
            ResultDecodeErrorKind::InvalidKnownMember,
            "$.serverInfo",
        ));
    }
    Ok(ResultMeta {
        server_info: None,
        meta,
        exact_meta,
    })
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
            if let Some(input_requests) = &input_required.input_requests {
                members.push(ExactJsonMember {
                    name: "inputRequests".to_owned(),
                    value: ExactJsonValue::Object(input_requests.clone()),
                });
            }
            if let Some(request_state) = &input_required.request_state {
                members.push(ExactJsonMember {
                    name: "requestState".to_owned(),
                    value: ExactJsonValue::String(request_state.clone()),
                });
            }
            members.extend(input_required.extras.members.clone());
        }
        DecodedResult::Deferred(deferred) => return encode_exact_object(&deferred.members),
    }
    encode_exact_object(&ExactJsonObject { members })
}

/// Encodes one selected typed `complete` result through the final result
/// algebra. Method dispatch supplies exactly the members it owns; every other
/// admitted member remains an inert [`UnknownResultMembers`] sibling.
pub fn encode_complete_result(
    meta: &ResultMeta,
    known_members: Vec<ExactJsonMember>,
    known_names: &[&str],
    extras: &UnknownResultMembers,
) -> Result<String, ResultDecodeError> {
    validate_known_member_names(known_names)?;
    for (index, member) in known_members.iter().enumerate() {
        if !known_names.contains(&member.name.as_str())
            || known_members[..index]
                .iter()
                .any(|previous| previous.name == member.name)
        {
            return Err(ResultDecodeError::new(
                ResultDecodeErrorKind::KnownMemberCollision,
                member.name.clone(),
            ));
        }
    }
    let checked_extras = UnknownResultMembers::try_new(extras.members.clone(), known_names)?;
    let mut members = vec![ExactJsonMember {
        name: "resultType".to_owned(),
        value: ExactJsonValue::String("complete".to_owned()),
    }];
    append_result_meta(&mut members, meta);
    members.extend(known_members);
    members.extend(checked_extras.members);
    validate_local_result_members(&members)?;
    Ok(encode_exact_object(&ExactJsonObject { members }))
}

fn append_result_meta(members: &mut Vec<ExactJsonMember>, meta: &ResultMeta) {
    let mut exact_meta = meta.exact_meta.clone();
    if let Some(server_info) = &meta.server_info {
        let exact_server_info = exact_json_from_serde_unchecked(
            &serde_json::to_value(server_info)
                .expect("final implementation identity always serializes"),
        );
        let object = exact_meta.get_or_insert_with(ExactJsonObject::default);
        if object.get("io.modelcontextprotocol/serverInfo").is_none() {
            object.members.push(ExactJsonMember {
                name: "io.modelcontextprotocol/serverInfo".to_owned(),
                value: exact_server_info,
            });
        }
    }
    if let Some(exact_meta) = exact_meta {
        members.push(ExactJsonMember {
            name: "_meta".to_owned(),
            value: ExactJsonValue::Object(exact_meta),
        });
    } else if let Some(value) = &meta.meta {
        let object = value.entries().clone().into_iter().collect();
        members.push(ExactJsonMember {
            name: "_meta".to_owned(),
            value: exact_json_from_serde_unchecked(&serde_json::Value::Object(object)),
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
            return Err(ResultDecodeError::new(
                ResultDecodeErrorKind::BoundExceeded,
                path,
            ));
        }
        match self.byte() {
            Some(b'n') if self.consume(b"null") => Ok(ExactJsonValue::Null),
            Some(b't') if self.consume(b"true") => Ok(ExactJsonValue::Bool(true)),
            Some(b'f') if self.consume(b"false") => Ok(ExactJsonValue::Bool(false)),
            Some(b'"') => self.string(path).map(ExactJsonValue::String),
            Some(b'[') => self.array(depth, path),
            Some(b'{') => self.object(depth, path),
            Some(b'-' | b'0'..=b'9') => self.number(path).map(ExactJsonValue::Number),
            _ => Err(ResultDecodeError::new(
                ResultDecodeErrorKind::InvalidJson,
                path,
            )),
        }
    }

    fn consume(&mut self, token: &[u8]) -> bool {
        if self
            .input
            .as_bytes()
            .get(self.offset..self.offset + token.len())
            == Some(token)
        {
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
                return Err(ResultDecodeError::new(
                    ResultDecodeErrorKind::InvalidJson,
                    path,
                ));
            };
            match byte {
                b'"' => {
                    self.offset += 1;
                    if value.len() > MAX_RESULT_STRING_BYTES {
                        return Err(ResultDecodeError::new(
                            ResultDecodeErrorKind::BoundExceeded,
                            path,
                        ));
                    }
                    return Ok(value);
                }
                0x00..=0x1f => {
                    return Err(ResultDecodeError::new(
                        ResultDecodeErrorKind::InvalidJson,
                        path,
                    ));
                }
                b'\\' => {
                    self.offset += 1;
                    let escaped = self.byte().ok_or_else(|| {
                        ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path)
                    })?;
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
                        _ => {
                            return Err(ResultDecodeError::new(
                                ResultDecodeErrorKind::InvalidJson,
                                path,
                            ));
                        }
                    }
                }
                _ => {
                    let tail = &self.input[self.offset..];
                    let character = tail.chars().next().ok_or_else(|| {
                        ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path)
                    })?;
                    value.push(character);
                    self.offset += character.len_utf8();
                }
            }
            if value.len() > MAX_RESULT_STRING_BYTES {
                return Err(ResultDecodeError::new(
                    ResultDecodeErrorKind::BoundExceeded,
                    path,
                ));
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
            return Err(ResultDecodeError::new(
                ResultDecodeErrorKind::InvalidJson,
                path,
            ));
        }
        let low = self.hex_unit(path)?;
        if !(0xdc00..=0xdfff).contains(&low) {
            return Err(ResultDecodeError::new(
                ResultDecodeErrorKind::InvalidJson,
                path,
            ));
        }
        let codepoint = 0x10000 + ((u32::from(unit) - 0xd800) << 10) + (u32::from(low) - 0xdc00);
        char::from_u32(codepoint)
            .ok_or_else(|| ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path))
    }

    fn hex_unit(&mut self, path: &str) -> Result<u16, ResultDecodeError> {
        let bytes = self
            .input
            .as_bytes()
            .get(self.offset..self.offset + 4)
            .ok_or_else(|| ResultDecodeError::new(ResultDecodeErrorKind::InvalidJson, path))?;
        self.offset += 4;
        bytes.iter().try_fold(0_u16, |value, byte| {
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => {
                    return Err(ResultDecodeError::new(
                        ResultDecodeErrorKind::InvalidJson,
                        path,
                    ));
                }
            };
            Ok((value << 4) | u16::from(digit))
        })
    }

    fn number(&mut self, path: &str) -> Result<String, ResultDecodeError> {
        let start = self.offset;
        if self.byte() == Some(b'-') {
            self.offset += 1;
        }
        match self.byte() {
            Some(b'0') => self.offset += 1,
            Some(b'1'..=b'9') => {
                self.offset += 1;
                while matches!(self.byte(), Some(b'0'..=b'9')) {
                    self.offset += 1;
                }
            }
            _ => {
                return Err(ResultDecodeError::new(
                    ResultDecodeErrorKind::InvalidJson,
                    path,
                ));
            }
        }
        if self.byte() == Some(b'.') {
            self.offset += 1;
            let fraction = self.offset;
            while matches!(self.byte(), Some(b'0'..=b'9')) {
                self.offset += 1;
            }
            if self.offset == fraction {
                return Err(ResultDecodeError::new(
                    ResultDecodeErrorKind::InvalidJson,
                    path,
                ));
            }
        }
        if matches!(self.byte(), Some(b'e' | b'E')) {
            self.offset += 1;
            if matches!(self.byte(), Some(b'+' | b'-')) {
                self.offset += 1;
            }
            let exponent = self.offset;
            while matches!(self.byte(), Some(b'0'..=b'9')) {
                self.offset += 1;
            }
            if self.offset == exponent {
                return Err(ResultDecodeError::new(
                    ResultDecodeErrorKind::InvalidJson,
                    path,
                ));
            }
        }
        let value = &self.input[start..self.offset];
        if value.len() > MAX_RESULT_NUMBER_BYTES {
            return Err(ResultDecodeError::new(
                ResultDecodeErrorKind::BoundExceeded,
                path,
            ));
        }
        Ok(value.to_owned())
    }

    fn array(&mut self, depth: usize, path: &str) -> Result<ExactJsonValue, ResultDecodeError> {
        self.offset += 1;
        self.skip_whitespace();
        let mut values = Vec::new();
        if self.byte() == Some(b']') {
            self.offset += 1;
            return Ok(ExactJsonValue::Array(values));
        }
        loop {
            if values.len() == MAX_RESULT_CONTAINER_MEMBERS {
                return Err(ResultDecodeError::new(
                    ResultDecodeErrorKind::BoundExceeded,
                    path,
                ));
            }
            let item_path = format!("{path}/{}", values.len());
            values.push(self.value(depth + 1, &item_path)?);
            self.skip_whitespace();
            match self.byte() {
                Some(b',') => {
                    self.offset += 1;
                    self.skip_whitespace();
                }
                Some(b']') => {
                    self.offset += 1;
                    return Ok(ExactJsonValue::Array(values));
                }
                _ => {
                    return Err(ResultDecodeError::new(
                        ResultDecodeErrorKind::InvalidJson,
                        path,
                    ));
                }
            }
        }
    }

    fn object(&mut self, depth: usize, path: &str) -> Result<ExactJsonValue, ResultDecodeError> {
        self.offset += 1;
        self.skip_whitespace();
        let mut members = Vec::new();
        if self.byte() == Some(b'}') {
            self.offset += 1;
            return Ok(ExactJsonValue::Object(ExactJsonObject { members }));
        }
        loop {
            if members.len() == MAX_RESULT_CONTAINER_MEMBERS {
                return Err(ResultDecodeError::new(
                    ResultDecodeErrorKind::BoundExceeded,
                    path,
                ));
            }
            if self.byte() != Some(b'"') {
                return Err(ResultDecodeError::new(
                    ResultDecodeErrorKind::InvalidJson,
                    path,
                ));
            }
            let name = self.string(path)?;
            if members
                .iter()
                .any(|member: &ExactJsonMember| member.name == name)
            {
                return Err(ResultDecodeError::new(
                    ResultDecodeErrorKind::DuplicateMember,
                    format!("{path}/{name}"),
                ));
            }
            self.skip_whitespace();
            if self.byte() != Some(b':') {
                return Err(ResultDecodeError::new(
                    ResultDecodeErrorKind::InvalidJson,
                    path,
                ));
            }
            self.offset += 1;
            self.skip_whitespace();
            let member_path = format!("{path}/{name}");
            let value = self.value(depth + 1, &member_path)?;
            members.push(ExactJsonMember { name, value });
            self.skip_whitespace();
            match self.byte() {
                Some(b',') => {
                    self.offset += 1;
                    self.skip_whitespace();
                }
                Some(b'}') => {
                    self.offset += 1;
                    return Ok(ExactJsonValue::Object(ExactJsonObject { members }));
                }
                _ => {
                    return Err(ResultDecodeError::new(
                        ResultDecodeErrorKind::InvalidJson,
                        path,
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_unit_a_positive_round_trip() {
        let source = r#"{"resultType":"complete","_meta":{"trace":true,"io.modelcontextprotocol/serverInfo":{"name":"FastMCP","version":"0.1"}},"first":{"integer":123456789012345678901234567890,"decimal":1.20e+4,"nil":null,"array":[false,"text"]},"second":{"nested":{"ok":true}}}"#;
        let (decoded, diagnostic) = decode_peer_result(
            source,
            ResultPeerEra::Modern,
            &CoreResultDiscriminatorPolicy,
        )
        .expect("complete result must round-trip through the public codec");
        assert_eq!(diagnostic, None);
        let DecodedResult::Complete(complete) = decoded else {
            panic!("complete result");
        };
        assert!(complete.meta.server_info.is_none());
        assert!(matches!(
            complete.meta.metadata().get("trace"),
            Some(ExactJsonValue::Bool(true))
        ));
        assert!(matches!(
            complete
                .meta
                .metadata()
                .get("io.modelcontextprotocol/serverInfo"),
            Some(ExactJsonValue::Object(server_info))
                if server_info.get("name") == Some(&ExactJsonValue::String("FastMCP".to_owned()))
        ));
        let extras = complete.extras.members();
        assert_eq!(
            extras
                .iter()
                .map(|member| member.name.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
        let Some(ExactJsonValue::Object(first)) = complete
            .extras
            .members()
            .first()
            .map(|member| &member.value)
        else {
            panic!("first extra");
        };
        assert_eq!(
            first.get("integer"),
            Some(&ExactJsonValue::Number(
                "123456789012345678901234567890".to_owned()
            ))
        );
        assert_eq!(
            first.get("decimal"),
            Some(&ExactJsonValue::Number("1.20e+4".to_owned()))
        );
        assert_eq!(encode_result(&DecodedResult::Complete(complete)), source);
    }

    #[test]
    fn final_results_require_result_type_and_reject_top_level_server_info() {
        let accepted = r#"{"resultType":"complete","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"FastMCP","version":"0.1"}},"extension":true}"#;
        let (baseline, diagnostic) = decode_peer_result(
            accepted,
            ResultPeerEra::Modern,
            &CoreResultDiscriminatorPolicy,
        )
        .expect("final result with a metadata serverInfo is admitted");
        assert_eq!(diagnostic, None);

        let missing = r#"{"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"FastMCP","version":"0.1"}},"extension":true}"#;
        let error = decode_peer_result(
            missing,
            ResultPeerEra::Modern,
            &CoreResultDiscriminatorPolicy,
        )
        .expect_err("only the required final resultType is absent");
        assert_eq!(error.kind(), ResultDecodeErrorKind::MissingDiscriminator);
        assert_eq!(error.path(), "$.resultType");

        let wrong_type = r#"{"resultType":false,"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"FastMCP","version":"0.1"}},"extension":true}"#;
        let error = decode_peer_result(
            wrong_type,
            ResultPeerEra::Modern,
            &CoreResultDiscriminatorPolicy,
        )
        .expect_err("only resultType changes from a string to a boolean");
        assert_eq!(error.kind(), ResultDecodeErrorKind::InvalidDiscriminator);
        assert_eq!(error.path(), "$.resultType");

        let top_level_server_info = r#"{"resultType":"complete","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"FastMCP","version":"0.1"}},"serverInfo":{"name":"legacy-location","version":"0.1"},"extension":true}"#;
        let error = decode_peer_result(
            top_level_server_info,
            ResultPeerEra::Modern,
            &CoreResultDiscriminatorPolicy,
        )
        .expect_err("final serverInfo is never admitted as a top-level result member");
        assert_eq!(error.kind(), ResultDecodeErrorKind::InvalidKnownMember);
        assert_eq!(error.path(), "$.serverInfo");

        let (reaccepted, _) = decode_peer_result(
            accepted,
            ResultPeerEra::Modern,
            &CoreResultDiscriminatorPolicy,
        )
        .expect("rejections do not mutate final result admission");
        assert_eq!(encode_result(&baseline), accepted);
        assert_eq!(encode_result(&reaccepted), accepted);
    }

    #[test]
    fn locally_authored_final_server_info_encodes_only_in_metadata() {
        let server_info =
            Implementation::try_new("FastMCP", "0.1").expect("valid final implementation identity");
        let result = DecodedResult::Complete(CompleteResult::new(
            ExactJsonObject::default(),
            ResultMeta::server_generated(server_info),
        ));
        let encoded = encode_result(&result);
        assert_eq!(
            encoded,
            r#"{"resultType":"complete","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"FastMCP","version":"0.1"}}}"#
        );
        let wire: serde_json::Value =
            serde_json::from_str(&encoded).expect("final result encoding is JSON");
        assert!(wire.get("serverInfo").is_none());
    }

    #[test]
    fn final_input_required_uses_retry_members_not_legacy_input() {
        let accepted = r#"{"resultType":"input_required","inputRequests":{"consent":{"type":"form"}},"requestState":"retry-7"}"#;
        let (decoded, diagnostic) = decode_peer_result(
            accepted,
            ResultPeerEra::Modern,
            &CoreResultDiscriminatorPolicy,
        )
        .expect("final retry result is admitted");
        assert_eq!(diagnostic, None);
        let DecodedResult::InputRequired(input_required) = &decoded else {
            panic!("input-required result");
        };
        assert_eq!(input_required.request_state(), Some("retry-7"));
        assert!(matches!(
            input_required
                .input_requests()
                .and_then(|requests| requests.get("consent")),
            Some(ExactJsonValue::Object(_))
        ));
        assert_eq!(encode_result(&decoded), accepted);

        let missing = r#"{"resultType":"input_required"}"#;
        let error = decode_peer_result(
            missing,
            ResultPeerEra::Modern,
            &CoreResultDiscriminatorPolicy,
        )
        .expect_err("input-required needs a retry member");
        assert_eq!(error.kind(), ResultDecodeErrorKind::MissingInputRequest);
        assert_eq!(error.path(), "$");

        let wrong_type =
            r#"{"resultType":"input_required","inputRequests":[],"requestState":"retry-7"}"#;
        let error = decode_peer_result(
            wrong_type,
            ResultPeerEra::Modern,
            &CoreResultDiscriminatorPolicy,
        )
        .expect_err("inputRequests must be an object");
        assert_eq!(error.kind(), ResultDecodeErrorKind::InvalidKnownMember);
        assert_eq!(error.path(), "$.inputRequests");

        let legacy_input =
            r#"{"resultType":"input_required","input":{"type":"form"},"requestState":"retry-7"}"#;
        let error = decode_peer_result(
            legacy_input,
            ResultPeerEra::Modern,
            &CoreResultDiscriminatorPolicy,
        )
        .expect_err("the obsolete input field is not admitted in final input-required results");
        assert_eq!(error.kind(), ResultDecodeErrorKind::InvalidKnownMember);
        assert_eq!(error.path(), "$.input");
    }

    #[test]
    fn result_unit_a_rejects_null_discriminator() {
        let accepted = r#"{"resultType":"complete","extension":{"count":1.20e+4}}"#;
        let (baseline, _) = decode_peer_result(
            accepted,
            ResultPeerEra::Legacy,
            &CoreResultDiscriminatorPolicy,
        )
        .expect("baseline");
        let planted = r#"{"resultType":null,"extension":{"count":1.20e+4}}"#;
        let error = decode_peer_result(
            planted,
            ResultPeerEra::Legacy,
            &CoreResultDiscriminatorPolicy,
        )
        .expect_err("only the discriminator dimension changed");
        assert_eq!(error.kind(), ResultDecodeErrorKind::InvalidDiscriminator);
        assert_eq!(error.path(), "$.resultType");
        let (reaccepted, _) = decode_peer_result(
            accepted,
            ResultPeerEra::Legacy,
            &CoreResultDiscriminatorPolicy,
        )
        .expect("pristine input is unchanged by the rejection");
        let (DecodedResult::Complete(before), DecodedResult::Complete(after)) =
            (baseline, reaccepted)
        else {
            panic!("complete baseline");
        };
        assert_eq!(before.extras, after.extras);
        assert_eq!(
            before.extras.members().first().map(|member| &member.value),
            Some(&ExactJsonValue::Object(ExactJsonObject {
                members: vec![ExactJsonMember {
                    name: "count".to_owned(),
                    value: ExactJsonValue::Number("1.20e+4".to_owned())
                }]
            }))
        );
        assert_eq!(encode_result(&DecodedResult::Complete(before)), accepted);
    }

    #[test]
    fn rejected_extension_retains_its_raw_envelope() {
        let source = r#"{"before":true,"resultType":"example/extension","after":1.20e+4}"#;
        let error = decode_peer_result(
            source,
            ResultPeerEra::Modern,
            &CoreResultDiscriminatorPolicy,
        )
        .expect_err("the default policy must not activate an unclaimed extension");
        assert_eq!(error.kind(), ResultDecodeErrorKind::RejectedExtension);
        assert_eq!(error.path(), "$.resultType");
        let envelope = error
            .raw_envelope()
            .expect("rejected envelope is diagnostic data");
        assert_eq!(envelope.discriminator(), "example/extension");
        assert_eq!(
            envelope
                .members()
                .iter()
                .map(|member| member.name.as_str())
                .collect::<Vec<_>>(),
            ["before", "resultType", "after"]
        );
        assert_eq!(
            envelope.members()[2].value,
            ExactJsonValue::Number("1.20e+4".to_owned())
        );
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
        assert_eq!(
            valid.members()[0].value,
            ExactJsonValue::Number("123456789012345678901234567890".to_owned())
        );

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
        assert_eq!(
            collision.kind(),
            ResultDecodeErrorKind::KnownMemberCollision
        );
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
        let (decoded, diagnostic) =
            decode_typed_complete::<LookupResult>(source, ResultPeerEra::Modern)
                .expect("selected complete members decode through the public result codec");
        assert_eq!(diagnostic, None);
        assert_eq!(decoded.payload.status, "ready");
        assert_eq!(
            decoded.payload.record.get("id"),
            Some(&ExactJsonValue::Number(
                "123456789012345678901234567890".to_owned()
            ))
        );
        assert_eq!(
            decoded
                .extras
                .members()
                .iter()
                .map(|member| member.name.as_str())
                .collect::<Vec<_>>(),
            ["opaque"]
        );
        assert_eq!(
            decoded.extras.members().first().map(|member| &member.value),
            Some(&ExactJsonValue::Object(ExactJsonObject {
                members: vec![
                    ExactJsonMember {
                        name: "null".to_owned(),
                        value: ExactJsonValue::Null
                    },
                    ExactJsonMember {
                        name: "bool".to_owned(),
                        value: ExactJsonValue::Bool(true)
                    },
                    ExactJsonMember {
                        name: "decimal".to_owned(),
                        value: ExactJsonValue::Number("1.20e+4".to_owned())
                    },
                    ExactJsonMember {
                        name: "array".to_owned(),
                        value: ExactJsonValue::Array(vec![ExactJsonValue::String(
                            "kept".to_owned()
                        )])
                    }
                ]
            }))
        );
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
        let (reaccepted, _) =
            decode_typed_complete::<LookupResult>(accepted, ResultPeerEra::Modern)
                .expect("the rejected peer document cannot mutate future typed decodes");
        assert_eq!(reaccepted.payload, baseline.payload);
        assert_eq!(reaccepted.extras, baseline.extras);
        assert_eq!(
            reaccepted
                .extras
                .members()
                .first()
                .map(|member| &member.value),
            Some(&ExactJsonValue::Object(ExactJsonObject {
                members: vec![ExactJsonMember {
                    name: "decimal".to_owned(),
                    value: ExactJsonValue::Number("1.20e+4".to_owned())
                }]
            }))
        );
    }
}
