//! Exact wire types for the `io.modelcontextprotocol/tasks` extension.
//!
//! These types deliberately model the final Tasks vocabulary independently of
//! the legacy task runtime. They admit only decoded task identifiers within
//! the protocol's 1 KiB limit; enforcement of the larger pre-unescape raw
//! JSON-token limit remains at the raw-ingress security boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::common_types::{JsonInteger, OpenMetadata};
use crate::jsonrpc::{JSONRPC_VERSION, RequestId};
use crate::messages::{
    FinalCallToolResult, FinalEmbeddedInputKind, FinalEmbeddedInputRequest,
    FinalEmbeddedInputResponse,
};
use crate::protocol_version::FINAL_PROTOCOL_VERSION;

/// The negotiated Tasks extension identifier.
pub const TASKS_EXTENSION: &str = "io.modelcontextprotocol/tasks";
/// Exact task-get method name.
pub const TASK_GET: &str = "tasks/get";
/// Exact task-update method name.
pub const TASK_UPDATE: &str = "tasks/update";
/// Exact task-cancel method name.
pub const TASK_CANCEL: &str = "tasks/cancel";
/// Exact task-status notification method name.
pub const TASK_STATUS_NOTIFICATION: &str = "notifications/tasks";
/// Legacy task-link metadata is forbidden inside a Task's inlined result.
pub const RELATED_TASK_META_KEY: &str = "io.modelcontextprotocol/related-task";
/// Maximum decoded UTF-8 bytes in a task ID.
pub const MAX_TASK_ID_BYTES: usize = 1024;
/// Maximum entries retained in either task input map.
pub const MAX_TASK_INPUT_MAP_ENTRIES: usize = 128;

/// A decoded opaque task identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TaskId(String);

impl TaskId {
    /// Validates and retains an opaque task identifier byte-for-byte.
    pub fn parse(value: impl Into<String>) -> Result<Self, TaskWireError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_TASK_ID_BYTES {
            return Err(TaskWireError::Invalid("taskId"));
        }
        if value.chars().any(char::is_control) {
            return Err(TaskWireError::Invalid("taskId"));
        }
        Ok(Self(value))
    }

    /// Returns the exact decoded identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for TaskId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)
            .and_then(|value| Self::parse(value).map_err(serde::de::Error::custom))
    }
}

/// One exact reason a Tasks wire value was rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskWireError {
    /// A field was absent, malformed, out of range, or inconsistent.
    Invalid(&'static str),
    /// An embedded input response did not match its request descriptor.
    InputResponseKind,
}

impl fmt::Display for TaskWireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(field) => write!(formatter, "invalid {field}"),
            Self::InputResponseKind => {
                formatter.write_str("task input response kind does not match request")
            }
        }
    }
}

impl std::error::Error for TaskWireError {}

/// A positive integer millisecond duration with canonical integer emission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskDuration(u64);

impl TaskDuration {
    /// Admits an exactly representable positive JSON mathematical integer.
    pub fn from_json_integer(value: JsonInteger) -> Result<Self, TaskWireError> {
        let canonical = canonical_positive_integer(value.as_str())?;
        canonical
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .map(Self)
            .ok_or(TaskWireError::Invalid("duration"))
    }

    /// Returns the retained millisecond count.
    #[must_use]
    pub const fn as_millis(&self) -> u64 {
        self.0
    }
}

impl Serialize for TaskDuration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for TaskDuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        JsonInteger::deserialize(deserializer)
            .and_then(|value| Self::from_json_integer(value).map_err(serde::de::Error::custom))
    }
}

fn canonical_positive_integer(value: &str) -> Result<String, TaskWireError> {
    let (negative, body) = match value.strip_prefix('-') {
        Some(body) => (true, body),
        None => (false, value),
    };
    if negative {
        return Err(TaskWireError::Invalid("duration"));
    }
    let (mantissa, exponent) = match body.find(['e', 'E']) {
        Some(index) => (&body[..index], body[index + 1..].parse::<i32>().ok()),
        None => (body, Some(0)),
    };
    let exponent = exponent.ok_or(TaskWireError::Invalid("duration"))?;
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(TaskWireError::Invalid("duration"));
    }
    let digits = format!("{whole}{fraction}");
    let shift =
        exponent - i32::try_from(fraction.len()).map_err(|_| TaskWireError::Invalid("duration"))?;
    let result = if shift >= 0 {
        let zeros = usize::try_from(shift).map_err(|_| TaskWireError::Invalid("duration"))?;
        format!("{digits}{}", "0".repeat(zeros))
    } else {
        let trim = usize::try_from(-shift).map_err(|_| TaskWireError::Invalid("duration"))?;
        if digits.len() < trim
            || !digits.as_bytes()[digits.len() - trim..]
                .iter()
                .all(|byte| *byte == b'0')
        {
            return Err(TaskWireError::Invalid("duration"));
        }
        digits[..digits.len() - trim].to_owned()
    };
    let canonical = result.trim_start_matches('0');
    (!canonical.is_empty())
        .then(|| canonical.to_owned())
        .ok_or(TaskWireError::Invalid("duration"))
}

/// A strict final task timestamp retained in canonical final spelling.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TaskTimestamp(String);

impl TaskTimestamp {
    /// Parses an exact final timestamp, preserving only its canonical UTC form.
    pub fn parse(value: impl Into<String>) -> Result<Self, TaskWireError> {
        let value = value.into();
        if value.len() > 64
            || !value.is_ascii()
            || value.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
        {
            return Err(TaskWireError::Invalid("timestamp"));
        }
        let bytes = value.as_bytes();
        if bytes.len() < 20
            || bytes[4] != b'-'
            || bytes[7] != b'-'
            || bytes[10] != b'T'
            || bytes[13] != b':'
            || bytes[16] != b':'
        {
            return Err(TaskWireError::Invalid("timestamp"));
        }
        let year = decimal(&bytes[0..4])?;
        let month = decimal(&bytes[5..7])?;
        let day = decimal(&bytes[8..10])?;
        let hour = decimal(&bytes[11..13])?;
        let minute = decimal(&bytes[14..16])?;
        let second = decimal(&bytes[17..19])?;
        if year == 0
            || month == 0
            || month > 12
            || day == 0
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return Err(TaskWireError::Invalid("timestamp"));
        }
        let zone_index = if bytes.get(19) == Some(&b'.') {
            let mut index = 20;
            while bytes.get(index).is_some_and(u8::is_ascii_digit) {
                index += 1;
            }
            if index == 20 || index - 20 > 9 {
                return Err(TaskWireError::Invalid("timestamp"));
            }
            index
        } else {
            19
        };
        if bytes.get(zone_index) == Some(&b'Z') && bytes.len() == zone_index + 1 {
            Ok(Self(value))
        } else if matches!(bytes.get(zone_index), Some(b'+') | Some(b'-'))
            && bytes.len() == zone_index + 6
            && bytes[zone_index + 3] == b':'
        {
            let offset_hour = decimal(&bytes[zone_index + 1..zone_index + 3])?;
            let offset_minute = decimal(&bytes[zone_index + 4..zone_index + 6])?;
            if offset_hour > 23
                || offset_minute > 59
                || (bytes[zone_index] == b'-' && offset_hour == 0 && offset_minute == 0)
            {
                return Err(TaskWireError::Invalid("timestamp"));
            }
            Ok(Self(value))
        } else {
            Err(TaskWireError::Invalid("timestamp"))
        }
    }

    /// Returns the exact admitted timestamp spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for TaskTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)
            .and_then(|value| Self::parse(value).map_err(serde::de::Error::custom))
    }
}

fn decimal(bytes: &[u8]) -> Result<u32, TaskWireError> {
    if !bytes.iter().all(u8::is_ascii_digit) {
        return Err(TaskWireError::Invalid("timestamp"));
    }
    bytes
        .iter()
        .try_fold(0_u32, |number, byte| {
            number
                .checked_mul(10)
                .and_then(|number| number.checked_add(u32::from(*byte - b'0')))
        })
        .ok_or(TaskWireError::Invalid("timestamp"))
}

const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 400 == 0 || (year % 4 == 0 && year % 100 != 0) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Exact task lifecycle status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Working,
    InputRequired,
    Completed,
    Failed,
    Cancelled,
}

/// Typed descriptor map carried by an input-required task.
pub type TaskInputRequests = BTreeMap<String, FinalEmbeddedInputRequest>;
/// Typed result map carried by a task update.
pub type TaskInputResponses = BTreeMap<String, FinalEmbeddedInputResponse>;

/// Correlates input responses with the exact embedded descriptors that requested them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskInputLedger(BTreeMap<String, FinalEmbeddedInputKind>);

impl TaskInputLedger {
    /// Records every request kind in an input-required task.
    pub fn from_requests(requests: &TaskInputRequests) -> Result<Self, TaskWireError> {
        if requests.len() > MAX_TASK_INPUT_MAP_ENTRIES {
            return Err(TaskWireError::Invalid("inputRequests"));
        }
        Ok(Self(
            requests
                .iter()
                .map(|(key, request)| (key.clone(), request.response_kind()))
                .collect(),
        ))
    }
    /// Requires each supplied response to match an outstanding request key.
    ///
    /// Task updates may acknowledge a strict subset of outstanding requests;
    /// the task remains `input_required` until all required input arrives.
    pub fn validate_responses(&self, responses: &TaskInputResponses) -> Result<(), TaskWireError> {
        if responses.len() > MAX_TASK_INPUT_MAP_ENTRIES {
            return Err(TaskWireError::Invalid("inputResponses"));
        }
        for (key, response) in responses {
            if !self
                .0
                .get(key)
                .is_some_and(|kind| response.matches_kind(*kind))
            {
                return Err(TaskWireError::InputResponseKind);
            }
        }
        Ok(())
    }
}

/// Open-preserving final inner error used only by failed Tasks.
#[derive(Clone, Debug, PartialEq)]
pub struct FinalTaskError {
    pub code: JsonInteger,
    pub message: String,
    pub data: Option<Value>,
    pub additional: BTreeMap<String, Value>,
}

impl Serialize for FinalTaskError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut members = Map::new();
        members.insert(
            "code".to_owned(),
            serde_json::to_value(&self.code).map_err(serde::ser::Error::custom)?,
        );
        members.insert("message".to_owned(), Value::String(self.message.clone()));
        if let Some(data) = &self.data {
            members.insert("data".to_owned(), data.clone());
        }
        for (key, value) in &self.additional {
            if members.insert(key.clone(), value.clone()).is_some() {
                return Err(serde::ser::Error::custom(
                    "task error additional member collides",
                ));
            }
        }
        Value::Object(members).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FinalTaskError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let Value::Object(mut members) = Value::deserialize(deserializer)? else {
            return Err(D::Error::custom("task error must be an object"));
        };
        let code = serde_json::from_value(
            members
                .remove("code")
                .ok_or_else(|| D::Error::custom("task error requires code"))?,
        )
        .map_err(D::Error::custom)?;
        let message = serde_json::from_value(
            members
                .remove("message")
                .ok_or_else(|| D::Error::custom("task error requires message"))?,
        )
        .map_err(D::Error::custom)?;
        Ok(Self {
            code,
            message,
            data: members.remove("data"),
            additional: members.into_iter().collect(),
        })
    }
}

/// The final nested `tools/call` result required by a completed Task.
#[derive(Clone, Debug)]
pub struct FinalTaskCallToolResult {
    pub result: FinalCallToolResult,
    pub meta: Option<OpenMetadata>,
    pub additional: BTreeMap<String, Value>,
}

impl Serialize for FinalTaskCallToolResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let Value::Object(mut members) =
            serde_json::to_value(&self.result).map_err(serde::ser::Error::custom)?
        else {
            unreachable!("tool result serializes as object")
        };
        if let Some(meta) = &self.meta {
            if meta.entries().contains_key(RELATED_TASK_META_KEY) {
                return Err(serde::ser::Error::custom(
                    "completed task result forbids related-task metadata",
                ));
            }
            members.insert(
                "_meta".to_owned(),
                serde_json::to_value(meta).map_err(serde::ser::Error::custom)?,
            );
        }
        for (key, value) in &self.additional {
            if members.insert(key.clone(), value.clone()).is_some() {
                return Err(serde::ser::Error::custom(
                    "task result additional member collides",
                ));
            }
        }
        Value::Object(members).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FinalTaskCallToolResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let Value::Object(mut members) = Value::deserialize(deserializer)? else {
            return Err(D::Error::custom("completed task result must be an object"));
        };
        if members.contains_key("resultType") {
            return Err(D::Error::custom(
                "completed task result must be a flattened tools/call result",
            ));
        }
        let meta: Option<OpenMetadata> = members
            .remove("_meta")
            .map(serde_json::from_value)
            .transpose()
            .map_err(D::Error::custom)?;
        if meta
            .as_ref()
            .is_some_and(|meta| meta.entries().contains_key(RELATED_TASK_META_KEY))
        {
            return Err(D::Error::custom(
                "completed task result forbids related-task metadata",
            ));
        }
        let mut result_members = Map::new();
        for key in ["content", "isError", "structuredContent"] {
            if let Some(value) = members.remove(key) {
                result_members.insert(key.to_owned(), value);
            }
        }
        let result =
            serde_json::from_value(Value::Object(result_members)).map_err(D::Error::custom)?;
        Ok(Self {
            result,
            meta,
            additional: members.into_iter().collect(),
        })
    }
}

/// Shared final task fields.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TaskBase {
    #[serde(rename = "taskId")]
    pub task_id: TaskId,
    pub status: TaskStatus,
    #[serde(
        rename = "statusMessage",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub status_message: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: TaskTimestamp,
    #[serde(rename = "lastUpdatedAt")]
    pub last_updated_at: TaskTimestamp,
    #[serde(rename = "ttlMs")]
    pub ttl_ms: Option<TaskDuration>,
    #[serde(
        rename = "pollIntervalMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub poll_interval_ms: Option<TaskDuration>,
}

struct RequiredTaskTtl(Option<TaskDuration>);

impl<'de> Deserialize<'de> for RequiredTaskTtl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<TaskDuration>::deserialize(deserializer).map(Self)
    }
}

struct OptionalTaskField<T>(Option<T>);

impl<T> Default for OptionalTaskField<T> {
    fn default() -> Self {
        Self(None)
    }
}

impl<'de, T> Deserialize<'de> for OptionalTaskField<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(|value| Self(Some(value)))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskBaseWire {
    #[serde(rename = "taskId")]
    task_id: TaskId,
    status: TaskStatus,
    #[serde(rename = "statusMessage", default)]
    status_message: OptionalTaskField<String>,
    #[serde(rename = "createdAt")]
    created_at: TaskTimestamp,
    #[serde(rename = "lastUpdatedAt")]
    last_updated_at: TaskTimestamp,
    #[serde(rename = "ttlMs")]
    ttl_ms: RequiredTaskTtl,
    #[serde(rename = "pollIntervalMs", default)]
    poll_interval_ms: OptionalTaskField<TaskDuration>,
}

impl<'de> Deserialize<'de> for TaskBase {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = TaskBaseWire::deserialize(deserializer)?;
        Ok(Self {
            task_id: wire.task_id,
            status: wire.status,
            status_message: wire.status_message.0,
            created_at: wire.created_at,
            last_updated_at: wire.last_updated_at,
            ttl_ms: wire.ttl_ms.0,
            poll_interval_ms: wire.poll_interval_ms.0,
        })
    }
}

/// Status-discriminated final Task payload.
#[derive(Clone, Debug)]
pub enum Task {
    Working(TaskBase),
    InputRequired {
        base: TaskBase,
        input_requests: TaskInputRequests,
    },
    Completed {
        base: TaskBase,
        result: FinalTaskCallToolResult,
    },
    Failed {
        base: TaskBase,
        error: FinalTaskError,
    },
    Cancelled(TaskBase),
}

impl Task {
    /// Returns common fields.
    #[must_use]
    pub fn base(&self) -> &TaskBase {
        match self {
            Self::Working(base) | Self::Cancelled(base) => base,
            Self::InputRequired { base, .. }
            | Self::Completed { base, .. }
            | Self::Failed { base, .. } => base,
        }
    }
}

impl Serialize for Task {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let Value::Object(mut members) =
            serde_json::to_value(self.base()).map_err(serde::ser::Error::custom)?
        else {
            unreachable!()
        };
        match self {
            Self::InputRequired { input_requests, .. } => {
                members.insert(
                    "inputRequests".to_owned(),
                    serde_json::to_value(input_requests).map_err(serde::ser::Error::custom)?,
                );
            }
            Self::Completed { result, .. } => {
                members.insert(
                    "result".to_owned(),
                    serde_json::to_value(result).map_err(serde::ser::Error::custom)?,
                );
            }
            Self::Failed { error, .. } => {
                members.insert(
                    "error".to_owned(),
                    serde_json::to_value(error).map_err(serde::ser::Error::custom)?,
                );
            }
            Self::Working(_) | Self::Cancelled(_) => {}
        }
        Value::Object(members).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Task {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let Value::Object(mut members) = Value::deserialize(deserializer)? else {
            return Err(D::Error::custom("task must be an object"));
        };
        let status: TaskStatus = serde_json::from_value(
            members
                .get("status")
                .cloned()
                .ok_or_else(|| D::Error::custom("task requires status"))?,
        )
        .map_err(D::Error::custom)?;
        let special = match status {
            TaskStatus::InputRequired => Some(("inputRequests", members.remove("inputRequests"))),
            TaskStatus::Completed => Some(("result", members.remove("result"))),
            TaskStatus::Failed => Some(("error", members.remove("error"))),
            TaskStatus::Working | TaskStatus::Cancelled => None,
        };
        if matches!(status, TaskStatus::Working | TaskStatus::Cancelled)
            && (members.contains_key("inputRequests")
                || members.contains_key("result")
                || members.contains_key("error"))
        {
            return Err(D::Error::custom(
                "task status forbids status-specific fields",
            ));
        }
        let base: TaskBase =
            serde_json::from_value(Value::Object(members)).map_err(D::Error::custom)?;
        match (status, special) {
            (TaskStatus::Working, _) => Ok(Self::Working(base)),
            (TaskStatus::Cancelled, _) => Ok(Self::Cancelled(base)),
            (TaskStatus::InputRequired, Some((_, Some(value)))) => {
                let input_requests: TaskInputRequests =
                    serde_json::from_value(value).map_err(D::Error::custom)?;
                TaskInputLedger::from_requests(&input_requests).map_err(D::Error::custom)?;
                Ok(Self::InputRequired {
                    base,
                    input_requests,
                })
            }
            (TaskStatus::Completed, Some((_, Some(value)))) => serde_json::from_value(value)
                .map(|result| Self::Completed { base, result })
                .map_err(D::Error::custom),
            (TaskStatus::Failed, Some((_, Some(value)))) => serde_json::from_value(value)
                .map(|error| Self::Failed { base, error })
                .map_err(D::Error::custom),
            _ => Err(D::Error::custom("task requires status-specific field")),
        }
    }
}

/// Required final request parameters shared by all task methods.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRequestMeta {
    #[serde(rename = "_meta")]
    pub meta: OpenMetadata,
}

impl TaskRequestMeta {
    fn validate(&self) -> Result<(), TaskWireError> {
        if self
            .meta
            .protocol_version()
            .map_err(|_| TaskWireError::Invalid("_meta"))?
            != Some(FINAL_PROTOCOL_VERSION)
            || self
                .meta
                .client_capabilities()
                .map_err(|_| TaskWireError::Invalid("_meta"))?
                .is_none()
        {
            return Err(TaskWireError::Invalid("_meta"));
        }
        Ok(())
    }
}

/// Parameters for `tasks/get`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetTaskParams {
    #[serde(flatten)]
    pub request: TaskRequestMeta,
    #[serde(rename = "taskId")]
    pub task_id: TaskId,
}
/// Parameters for `tasks/cancel`.
pub type CancelTaskParams = GetTaskParams;
/// Parameters for `tasks/update`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateTaskParams {
    #[serde(flatten)]
    pub request: TaskRequestMeta,
    #[serde(rename = "taskId")]
    pub task_id: TaskId,
    #[serde(rename = "inputResponses")]
    pub input_responses: TaskInputResponses,
}

/// JSON-RPC task request wire value. Its `method` is validated by [`TaskMethodRequest::decode`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskMethodRequest<P> {
    pub jsonrpc: String,
    pub id: RequestId,
    pub method: String,
    pub params: P,
}

impl<P> TaskMethodRequest<P> {
    /// Creates an exact JSON-RPC request with this method's fixed wire name.
    #[must_use]
    pub fn new(id: RequestId, method: impl Into<String>, params: P) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            id,
            method: method.into(),
            params,
        }
    }
}

impl TaskMethodRequest<GetTaskParams> {
    /// Decodes and validates `tasks/get`.
    pub fn decode(value: Value) -> Result<Self, TaskWireError> {
        let request: Self =
            serde_json::from_value(value).map_err(|_| TaskWireError::Invalid("tasks/get"))?;
        if request.jsonrpc != JSONRPC_VERSION || request.method != TASK_GET {
            return Err(TaskWireError::Invalid("tasks/get"));
        }
        request.params.request.validate()?;
        Ok(request)
    }
}
impl TaskMethodRequest<CancelTaskParams> {
    /// Decodes and validates `tasks/cancel`.
    pub fn decode_cancel(value: Value) -> Result<Self, TaskWireError> {
        let request: Self =
            serde_json::from_value(value).map_err(|_| TaskWireError::Invalid("tasks/cancel"))?;
        if request.jsonrpc != JSONRPC_VERSION || request.method != TASK_CANCEL {
            return Err(TaskWireError::Invalid("tasks/cancel"));
        }
        request.params.request.validate()?;
        Ok(request)
    }
}
impl TaskMethodRequest<UpdateTaskParams> {
    /// Decodes and validates `tasks/update` against its input ledger.
    pub fn decode_update(value: Value, ledger: &TaskInputLedger) -> Result<Self, TaskWireError> {
        let request: Self =
            serde_json::from_value(value).map_err(|_| TaskWireError::Invalid("tasks/update"))?;
        if request.jsonrpc != JSONRPC_VERSION || request.method != TASK_UPDATE {
            return Err(TaskWireError::Invalid("tasks/update"));
        }
        request.params.request.validate()?;
        ledger.validate_responses(&request.params.input_responses)?;
        Ok(request)
    }
}

/// The `tasks/create` result envelope.
#[derive(Clone, Debug)]
pub struct CreateTaskResult {
    pub task: Task,
    pub meta: Option<OpenMetadata>,
    pub additional: BTreeMap<String, Value>,
}

impl Serialize for CreateTaskResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let Value::Object(mut members) =
            serde_json::to_value(&self.task).map_err(serde::ser::Error::custom)?
        else {
            unreachable!()
        };
        members.insert("resultType".to_owned(), Value::String("task".to_owned()));
        if let Some(meta) = &self.meta {
            members.insert(
                "_meta".to_owned(),
                serde_json::to_value(meta).map_err(serde::ser::Error::custom)?,
            );
        }
        for (key, value) in &self.additional {
            if members.insert(key.clone(), value.clone()).is_some() {
                return Err(serde::ser::Error::custom(
                    "task create additional member collides",
                ));
            }
        }
        Value::Object(members).serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for CreateTaskResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let Value::Object(mut members) = Value::deserialize(deserializer)? else {
            return Err(D::Error::custom("task/create result must be an object"));
        };
        if members.remove("resultType") != Some(Value::String("task".to_owned())) {
            return Err(D::Error::custom(
                "task/create result requires resultType task",
            ));
        }
        let meta = members
            .remove("_meta")
            .map(serde_json::from_value)
            .transpose()
            .map_err(D::Error::custom)?;
        let task_fields: BTreeSet<&str> = [
            "taskId",
            "status",
            "statusMessage",
            "createdAt",
            "lastUpdatedAt",
            "ttlMs",
            "pollIntervalMs",
            "inputRequests",
            "result",
            "error",
        ]
        .into_iter()
        .collect();
        let task_members: Map<String, Value> = members
            .iter()
            .filter(|(key, _)| task_fields.contains(key.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let task = serde_json::from_value(Value::Object(task_members)).map_err(D::Error::custom)?;
        members.retain(|key, _| !task_fields.contains(key.as_str()));
        Ok(Self {
            task,
            meta,
            additional: members.into_iter().collect(),
        })
    }
}

/// Final `complete` result envelope used by get, update, and cancel.
#[derive(Clone, Debug)]
pub struct CompleteTaskResult {
    pub task: Task,
    pub meta: Option<OpenMetadata>,
    pub additional: BTreeMap<String, Value>,
}

/// Exact empty `complete` acknowledgement used by `tasks/update` and
/// `tasks/cancel`.
#[derive(Clone, Debug, Default)]
pub struct EmptyTaskResult {
    /// Optional final result metadata.
    pub meta: Option<OpenMetadata>,
    /// Schema-open result siblings retained without authority.
    pub additional: BTreeMap<String, Value>,
}

impl Serialize for EmptyTaskResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut members = Map::new();
        members.insert(
            "resultType".to_owned(),
            Value::String("complete".to_owned()),
        );
        if let Some(meta) = &self.meta {
            members.insert(
                "_meta".to_owned(),
                serde_json::to_value(meta).map_err(serde::ser::Error::custom)?,
            );
        }
        for (key, value) in &self.additional {
            if members.insert(key.clone(), value.clone()).is_some() {
                return Err(serde::ser::Error::custom(
                    "task acknowledgement additional member collides",
                ));
            }
        }
        Value::Object(members).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EmptyTaskResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let Value::Object(mut members) = Value::deserialize(deserializer)? else {
            return Err(D::Error::custom("task acknowledgement must be an object"));
        };
        if members.remove("resultType") != Some(Value::String("complete".to_owned())) {
            return Err(D::Error::custom(
                "task acknowledgement requires resultType complete",
            ));
        }
        let meta = members
            .remove("_meta")
            .map(serde_json::from_value)
            .transpose()
            .map_err(D::Error::custom)?;
        Ok(Self {
            meta,
            additional: members.into_iter().collect(),
        })
    }
}

/// `tasks/get`'s detailed `complete` result.
pub type GetTaskResult = CompleteTaskResult;
/// `tasks/update`'s empty `complete` acknowledgement.
pub type UpdateTaskResult = EmptyTaskResult;
/// `tasks/cancel`'s empty `complete` acknowledgement.
pub type CancelTaskResult = EmptyTaskResult;
impl Serialize for CompleteTaskResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let create = CreateTaskResult {
            task: self.task.clone(),
            meta: self.meta.clone(),
            additional: self.additional.clone(),
        };
        let mut value = serde_json::to_value(create).map_err(serde::ser::Error::custom)?;
        value.as_object_mut().expect("object").insert(
            "resultType".to_owned(),
            Value::String("complete".to_owned()),
        );
        value.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for CompleteTaskResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = Value::deserialize(deserializer)?;
        let Value::Object(members) = &mut value else {
            return Err(D::Error::custom("task result must be an object"));
        };
        if members.remove("resultType") != Some(Value::String("complete".to_owned())) {
            return Err(D::Error::custom("task result requires resultType complete"));
        }
        members.insert("resultType".to_owned(), Value::String("task".to_owned()));
        let create: CreateTaskResult = serde_json::from_value(value).map_err(D::Error::custom)?;
        Ok(Self {
            task: create.task,
            meta: create.meta,
            additional: create.additional,
        })
    }
}

/// Parameters carried by `notifications/tasks`.
#[derive(Clone, Debug)]
pub struct TaskStatusNotificationParams {
    pub task: Task,
    pub meta: Option<OpenMetadata>,
    pub additional: BTreeMap<String, Value>,
}
impl Serialize for TaskStatusNotificationParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut members =
            match serde_json::to_value(&self.task).map_err(serde::ser::Error::custom)? {
                Value::Object(members) => members,
                _ => unreachable!(),
            };
        if let Some(meta) = &self.meta {
            members.insert(
                "_meta".to_owned(),
                serde_json::to_value(meta).map_err(serde::ser::Error::custom)?,
            );
        }
        for (key, value) in &self.additional {
            if members.insert(key.clone(), value.clone()).is_some() {
                return Err(serde::ser::Error::custom(
                    "task notification additional member collides",
                ));
            }
        }
        Value::Object(members).serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for TaskStatusNotificationParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let Value::Object(mut members) = Value::deserialize(deserializer)? else {
            return Err(D::Error::custom(
                "task notification params must be an object",
            ));
        };
        let meta = members
            .remove("_meta")
            .map(serde_json::from_value)
            .transpose()
            .map_err(D::Error::custom)?;
        let task_keys: BTreeSet<&str> = [
            "taskId",
            "status",
            "statusMessage",
            "createdAt",
            "lastUpdatedAt",
            "ttlMs",
            "pollIntervalMs",
            "inputRequests",
            "result",
            "error",
        ]
        .into_iter()
        .collect();
        let task_members: Map<String, Value> = members
            .iter()
            .filter(|(key, _)| task_keys.contains(key.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let task = serde_json::from_value(Value::Object(task_members)).map_err(D::Error::custom)?;
        members.retain(|key, _| !task_keys.contains(key.as_str()));
        Ok(Self {
            task,
            meta,
            additional: members.into_iter().collect(),
        })
    }
}

/// Exact `notifications/tasks` JSON-RPC notification.
#[derive(Clone, Debug)]
pub struct TaskStatusNotification {
    pub params: TaskStatusNotificationParams,
}

impl TaskStatusNotification {
    /// Creates an exact `notifications/tasks` notification.
    #[must_use]
    pub const fn new(params: TaskStatusNotificationParams) -> Self {
        Self { params }
    }
}

impl Serialize for TaskStatusNotification {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut members = Map::new();
        members.insert(
            "jsonrpc".to_owned(),
            Value::String(JSONRPC_VERSION.to_owned()),
        );
        members.insert(
            "method".to_owned(),
            Value::String(TASK_STATUS_NOTIFICATION.to_owned()),
        );
        members.insert(
            "params".to_owned(),
            serde_json::to_value(&self.params).map_err(serde::ser::Error::custom)?,
        );
        Value::Object(members).serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskStatusNotificationWire {
    jsonrpc: String,
    method: String,
    params: TaskStatusNotificationParams,
}

impl<'de> Deserialize<'de> for TaskStatusNotification {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = TaskStatusNotificationWire::deserialize(deserializer)?;
        if wire.jsonrpc != JSONRPC_VERSION || wire.method != TASK_STATUS_NOTIFICATION {
            return Err(D::Error::custom("invalid notifications/tasks notification"));
        }
        Ok(Self::new(wire.params))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(status: TaskStatus) -> TaskBase {
        TaskBase {
            task_id: TaskId::parse("task-1").expect("id"),
            status,
            status_message: None,
            created_at: TaskTimestamp::parse("2026-07-28T12:00:00.000Z").expect("timestamp"),
            last_updated_at: TaskTimestamp::parse("2026-07-28T12:00:00.000Z").expect("timestamp"),
            ttl_ms: Some(TaskDuration(1)),
            poll_interval_ms: None,
        }
    }

    #[test]
    fn tasks_wire_round_trip_preserves_open_error_and_ledger() {
        let requests = serde_json::from_value::<TaskInputRequests>(serde_json::json!({ "sample": { "method": "sampling/createMessage", "params": { "messages": [], "maxTokens": 16 } }, "roots": { "method": "roots/list" } })).expect("input descriptors");
        let ledger = TaskInputLedger::from_requests(&requests).expect("ledger");
        let responses = serde_json::from_value::<TaskInputResponses>(serde_json::json!({ "sample": { "role": "assistant", "model": "m", "content": { "type": "text", "text": "ok" } }, "roots": { "roots": [] } })).expect("input responses");
        ledger
            .validate_responses(&responses)
            .expect("matching responses");
        let arbitrary_precision_code: Value =
            serde_json::from_str("123456789012345678901234567890")
                .expect("arbitrary-precision JSON integer");
        let task = Task::Failed { base: base(TaskStatus::Failed), error: serde_json::from_value(serde_json::json!({ "code": arbitrary_precision_code, "message": "no", "x-peer": { "n": 1 } })).expect("open error") };
        let wire = serde_json::to_value(CreateTaskResult {
            task,
            meta: None,
            additional: BTreeMap::new(),
        })
        .expect("serialize");
        let decoded: CreateTaskResult = serde_json::from_value(wire.clone()).expect("deserialize");
        assert_eq!(serde_json::to_value(decoded).expect("reserialize"), wire);

        let get: GetTaskResult = serde_json::from_value(serde_json::json!({
            "resultType": "complete",
            "taskId": "task-1",
            "status": "working",
            "createdAt": "2026-07-28T12:00:00.000Z",
            "lastUpdatedAt": "2026-07-28T12:00:00.000Z",
            "ttlMs": 1.0
        }))
        .expect("complete get result");
        assert_eq!(
            serde_json::to_value(get).expect("get result serializes")["resultType"],
            "complete"
        );
        let acknowledgement: UpdateTaskResult =
            serde_json::from_value(serde_json::json!({ "resultType": "complete" }))
                .expect("empty update acknowledgement");
        assert_eq!(
            serde_json::to_value(acknowledgement).expect("acknowledgement serializes"),
            serde_json::json!({ "resultType": "complete" })
        );
        let get_request = TaskMethodRequest::<GetTaskParams>::decode(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tasks/get",
            "params": {
                "taskId": "task-1",
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {
                        "extensions": { "io.modelcontextprotocol/tasks": {} }
                    }
                }
            }
        }))
        .expect("final task request");
        assert_eq!(get_request.method, TASK_GET);
    }

    #[test]
    fn tasks_rejects_one_wrong_response_kind_without_mutating_ledger() {
        let requests = serde_json::from_value::<TaskInputRequests>(
            serde_json::json!({ "roots": { "method": "roots/list" } }),
        )
        .expect("request");
        let ledger = TaskInputLedger::from_requests(&requests).expect("ledger");
        let before = requests.clone();
        let wrong = serde_json::from_value::<TaskInputResponses>(
            serde_json::json!({ "roots": { "action": "accept" } }),
        )
        .expect("well-formed response");
        assert_eq!(
            ledger.validate_responses(&wrong),
            Err(TaskWireError::InputResponseKind)
        );
        assert_eq!(
            serde_json::to_value(&requests).expect("before state"),
            serde_json::to_value(before).expect("after state"),
            "rejection must not alter task input state"
        );
    }

    #[test]
    fn completed_task_flattens_inner_result_and_preserves_open_fields() {
        let wire = serde_json::json!({
            "resultType": "complete",
            "taskId": "task-1",
            "status": "completed",
            "createdAt": "2026-07-28T12:00:00.000Z",
            "lastUpdatedAt": "2026-07-28T12:00:00.000Z",
            "ttlMs": null,
            "result": {
                "content": [],
                "x-inner": { "preserved": true }
            },
            "x-envelope": { "preserved": true }
        });

        let decoded: GetTaskResult =
            serde_json::from_value(wire.clone()).expect("flattened completed task");
        let reencoded = serde_json::to_value(decoded).expect("reserialize completed task");
        assert_eq!(reencoded, wire);
        assert!(reencoded["result"].get("resultType").is_none());
        assert_eq!(reencoded["result"]["x-inner"]["preserved"], true);
        assert_eq!(reencoded["x-envelope"]["preserved"], true);

        let mut with_result_type = wire.clone();
        with_result_type["result"]["resultType"] = serde_json::json!("complete");
        assert!(serde_json::from_value::<GetTaskResult>(with_result_type).is_err());

        let mut with_legacy_related_task = wire;
        with_legacy_related_task["result"]["_meta"] = serde_json::json!({
            (RELATED_TASK_META_KEY): { "taskId": "task-1" }
        });
        assert!(serde_json::from_value::<GetTaskResult>(with_legacy_related_task).is_err());
    }

    #[test]
    fn task_base_requires_ttl_and_rejects_present_null_optional_fields() {
        let wire = serde_json::json!({
            "resultType": "complete",
            "taskId": "task-1",
            "status": "working",
            "createdAt": "2026-07-28T12:00:00.000Z",
            "lastUpdatedAt": "2026-07-28T12:00:00.000Z",
            "ttlMs": null
        });
        let accepted: GetTaskResult =
            serde_json::from_value(wire.clone()).expect("unlimited TTL is valid");
        assert_eq!(
            serde_json::to_value(accepted).expect("unlimited TTL serializes"),
            wire
        );

        let mut missing_ttl = wire.clone();
        missing_ttl
            .as_object_mut()
            .expect("result object")
            .remove("ttlMs");
        assert!(serde_json::from_value::<GetTaskResult>(missing_ttl).is_err());

        let mut null_poll_interval = wire.clone();
        null_poll_interval["pollIntervalMs"] = Value::Null;
        assert!(serde_json::from_value::<GetTaskResult>(null_poll_interval).is_err());

        let mut null_status_message = wire;
        null_status_message["statusMessage"] = Value::Null;
        assert!(serde_json::from_value::<GetTaskResult>(null_status_message).is_err());
    }

    #[test]
    fn task_status_notification_enforces_exact_method_vocabulary() {
        let wire = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/tasks",
            "params": {
                "taskId": "task-1",
                "status": "working",
                "createdAt": "2026-07-28T12:00:00.000Z",
                "lastUpdatedAt": "2026-07-28T12:00:00.000Z",
                "ttlMs": null,
                "x-notification": { "preserved": true }
            }
        });
        let notification: TaskStatusNotification =
            serde_json::from_value(wire.clone()).expect("exact notification");
        assert_eq!(
            serde_json::to_value(notification).expect("notification serializes"),
            wire
        );

        let mut wrong_method = wire;
        wrong_method["method"] = serde_json::json!("notifications/tasks/status");
        assert!(serde_json::from_value::<TaskStatusNotification>(wrong_method).is_err());
    }
}
