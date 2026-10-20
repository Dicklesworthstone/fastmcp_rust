//! Caller-owned execution of final-protocol sampling conversations.
//!
//! Hosts supply model access, whole-batch approval and tool execution. The
//! driver reuses the protocol's sampling controller, never selects a model,
//! opens a URL, grants a capability, or retries an external effect on its own.
//! It is suitable for resolving embedded sampling in an OAuth-backed MRTR
//! interaction; choosing this runner does not itself advertise sampling support.
//!
//! One absolute deadline covers model calls, consent and tools. All futures are
//! polled inline under the supplied Cx; there is no runtime or detached worker.
//! Host futures must be cancellation-correct on drop and must not hide blocking
//! work or detached children. Already-committed host effects cannot be undone.

use std::collections::BTreeMap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::time::Sleep;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::common_types::SamplingContentBlock;
use fastmcp_protocol::sampling::{SamplingToolLoop, SamplingToolLoopStep};
use fastmcp_protocol::{
    AdmittedSchema, FinalCreateMessageResult, FinalEmbeddedCreateMessageParams, admit_final_schema,
};

use super::caller::with_caller;

/// Re-exported because `SamplingRunLimits::new` below takes one BY VALUE, so a
/// consumer depending only on the `fastmcp-rust` facade must be able to write
/// the name. Without this the constructor is reachable but uncallable with a
/// non-default conversation bound: the facade forwards `http_auth`
/// (`crates/fastmcp/src/lib.rs:936`) and `sampling` is `pub mod`, yet
/// `fastmcp_protocol::sampling` is NOT among the facade's forwarded modules and
/// the type appears nowhere in the facade's explicit re-export lists, so the
/// caller's only alternative was a direct dependency on `fastmcp-protocol`.
///
/// It lives here rather than in the parent `http_auth` root because the
/// signature demanding it is here; the parent closed the identical defect class
/// for `OAuthCredentialStore::open` with
/// `pub use fastmcp_core::partition::PartitionAuthorization`.
///
/// `SamplingToolLoopError` joins it for a position the first pass did not
/// examine: `SamplingRunError::Protocol` below carries one as its payload, and
/// that enum IS facade-reachable. Matching the variant binds the payload
/// without naming it, but a consumer who PROPAGATES the error -- storing it in
/// their own error type or returning it -- must write the name, and could not.
/// When this re-export was first added only `pub fn` parameter and return
/// positions had been swept, which is why three of the four imported siblings
/// were judged internal; an enum-variant payload is the same defect.
pub use fastmcp_protocol::sampling::{SamplingToolLoopError, SamplingToolLoopLimits};

/// Bounded sampling-only resolution of final input-required response maps.
pub mod inputs;
/// Opt-in bounded concurrency for independently executable, approved tools.
pub mod parallel;

/// A host-owned operation borrowing its model/tool implementation and caller.
/// There is no 'static requirement and no task is spawned by this driver.
pub type SamplingHostFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, SamplingHostError>> + Send + 'a>>;

/// Fixed host errors. Provider diagnostics, arguments and credentials must not
/// be copied into these errors. A tool's ordinary application error should be
/// returned as an explicit isError tool-result block, not a transport failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SamplingHostError {
    Denied,
    Failed,
}

/// The explicit trusted host boundary. Implementations must make their own
/// capability, consent and disclosure decisions using their retained context.
/// A schema annotation, tool name or model response is never authorization.
pub trait SamplingHost: Send {
    /// Review model disclosure and perform exactly one model call. The request
    /// is borrowed and immutable; the host must not silently retry it.
    fn sample<'a>(
        &'a mut self,
        cx: &'a Cx,
        cancellation: &'a McpRequestCancellation,
        request: &'a FinalEmbeddedCreateMessageParams,
    ) -> SamplingHostFuture<'a, FinalCreateMessageResult>;

    /// Approve the entire admitted batch before its first tool is executed.
    /// A denial rejects all calls, including any earlier reviewed sibling.
    fn approve_tools<'a>(
        &'a mut self,
        cx: &'a Cx,
        cancellation: &'a McpRequestCancellation,
        calls: &'a [SamplingContentBlock],
    ) -> SamplingHostFuture<'a, ()>;

    /// Execute one approved tool-use block. Calls are sequential in model
    /// order. The result must retain this call's exact toolUseId. The host must
    /// recheck any revocable application authority at its own effect boundary.
    fn execute_tool<'a>(
        &'a mut self,
        cx: &'a Cx,
        cancellation: &'a McpRequestCancellation,
        call: &'a SamplingContentBlock,
    ) -> SamplingHostFuture<'a, SamplingContentBlock>;

    /// Opt into concurrent execution of this approved batch. The default keeps
    /// the existing sequential `execute_tool` path. This hook runs only after
    /// whole-batch approval, under the caller's Cx and lifetime checks.
    ///
    /// The host must select only tools safe to overlap under its own policy.
    /// The returned executor is borrowed until the batch finishes or is
    /// dropped; the model and approval callbacks cannot overlap that batch.
    /// Embedded sampling resolvers use this same hook through the runner.
    fn parallel_tools(&self) -> Option<parallel::ParallelSamplingTools<'_>> {
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SamplingStage {
    Model,
    Approval,
    Tool,
}

/// Errors do not retain model content, tool IDs, arguments, schemas or tokens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SamplingRunError {
    InvalidLimits,
    RuntimeUnavailable,
    Cancelled,
    TimedOut,
    Host {
        stage: SamplingStage,
        reason: SamplingHostError,
    },
    Protocol(SamplingToolLoopError),
    ToolResultByteLimit,
}

impl fmt::Display for SamplingRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sampling execution: {self:?}")
    }
}
impl std::error::Error for SamplingRunError {}
impl From<SamplingToolLoopError> for SamplingRunError {
    fn from(error: SamplingToolLoopError) -> Self {
        Self::Protocol(error)
    }
}

/// Limits for the whole run, never reset between rounds. The protocol limits
/// bound retained conversation, model rounds and admitted tool calls. The
/// additional result budget counts every encoded tool-result block returned
/// during this run, including results later discarded after a failure.
#[derive(Clone, Copy, Debug)]
pub struct SamplingRunLimits {
    conversation: SamplingToolLoopLimits,
    timeout: Duration,
    tool_result_bytes: usize,
}

impl SamplingRunLimits {
    pub fn new(
        conversation: SamplingToolLoopLimits,
        timeout: Duration,
        tool_result_bytes: usize,
    ) -> Result<Self, SamplingRunError> {
        if timeout.is_zero()
            || timeout > Duration::from_secs(3600)
            || tool_result_bytes == 0
            || tool_result_bytes > 16 * 1024 * 1024
        {
            return Err(SamplingRunError::InvalidLimits);
        }
        Ok(Self {
            conversation,
            timeout,
            tool_result_bytes,
        })
    }
}

impl Default for SamplingRunLimits {
    fn default() -> Self {
        Self {
            conversation: SamplingToolLoopLimits::default(),
            timeout: Duration::from_secs(300),
            tool_result_bytes: 4 * 1024 * 1024,
        }
    }
}

/// The exact final response and counts for this invocation. Initial history
/// does not count as newly executed work. Content is deliberately not Debug.
pub struct SamplingRunResult {
    pub response: FinalCreateMessageResult,
    pub model_rounds: usize,
    pub executed_tools: usize,
}

/// Runs a complete bounded sampling conversation using explicit host callbacks.
///
/// Initial schemas/history and each whole model batch are admitted before host
/// tool approval or execution. Sequential execution validates each result
/// before starting the next tool. An explicitly installed parallel executor
/// validates each completion before admitting queued work and preserves model
/// order in the next request. Explicit null, metadata, multimodal content,
/// model names and open stop-reason values remain in their typed wire forms.
///
/// Dropping this future retires the conversation and its pending host future;
/// no controller or partial transcript is returned for accidental replay. A
/// failure after a host effect cannot roll that effect back. Callers requiring
/// durable exactly-once behavior must implement it at the tool boundary.
pub async fn run_sampling_tool_loop<H: SamplingHost + ?Sized>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    request: FinalEmbeddedCreateMessageParams,
    limits: SamplingRunLimits,
    host: &mut H,
) -> Result<SamplingRunResult, SamplingRunError> {
    let deadline = deadline(cx, cancellation, limits.timeout)?;
    let mut conversation = SamplingToolLoop::new(request, limits.conversation)?;
    // Reuse the shared schema service for immediate per-result validation.
    // The protocol controller owns final batch admission; retaining these
    // admitted outputs avoids executing later tools after an invalid result.
    let mut outputs: BTreeMap<String, AdmittedSchema> = BTreeMap::new();
    for tool in conversation
        .request()
        .into_iter()
        .flat_map(|request| request.tools.iter().flatten())
    {
        if let Some(schema) = &tool.output_schema {
            outputs.insert(
                tool.name.clone(),
                admit_final_schema(schema.clone())
                    .map_err(|_| SamplingToolLoopError::InvalidSchema)?,
            );
        }
    }
    let mut executed_tools = 0;
    let mut result_bytes = 0_usize;
    loop {
        check(cx, cancellation, deadline)?;
        let request = conversation
            .request()
            .ok_or(SamplingToolLoopError::WrongPhase)?;
        // Callback construction itself is inside the guarded future, not an
        // eager argument expression that could perform work before admission.
        let response = within(cx, cancellation, deadline, async {
            host.sample(cx, cancellation, request)
                .await
                .map_err(|reason| SamplingRunError::Host {
                    stage: SamplingStage::Model,
                    reason,
                })
        })
        .await?;
        match conversation.accept_response(response)? {
            SamplingToolLoopStep::Complete => {
                check(cx, cancellation, deadline)?;
                let response = conversation
                    .result()
                    .ok_or(SamplingToolLoopError::WrongPhase)?
                    .clone();
                check(cx, cancellation, deadline)?;
                return Ok(SamplingRunResult {
                    response,
                    model_rounds: conversation.round_count(),
                    executed_tools,
                });
            }
            SamplingToolLoopStep::Tools { count } => {
                let calls: Vec<_> = conversation.pending_tool_calls().cloned().collect();
                within(cx, cancellation, deadline, async {
                    host.approve_tools(cx, cancellation, &calls)
                        .await
                        .map_err(|reason| SamplingRunError::Host {
                            stage: SamplingStage::Approval,
                            reason,
                        })
                })
                .await?;
                let parallel = with_caller(cx, || {
                    check(cx, cancellation, deadline)?;
                    let executor = host.parallel_tools();
                    check(cx, cancellation, deadline)?;
                    Ok::<_, SamplingRunError>(executor)
                })?;
                let results = if let Some(executor) = parallel {
                    executor
                        .execute(
                            cx,
                            cancellation,
                            deadline,
                            &calls,
                            &outputs,
                            limits.tool_result_bytes,
                            &mut result_bytes,
                        )
                        .await?
                } else {
                    let mut results = Vec::with_capacity(count);
                    for call in &calls {
                        // Yield even when every host callback is immediately ready.
                        cooperate(cx, cancellation, deadline).await?;
                        let result = within(cx, cancellation, deadline, async {
                            host.execute_tool(cx, cancellation, call)
                                .await
                                .map_err(|reason| SamplingRunError::Host {
                                    stage: SamplingStage::Tool,
                                    reason,
                                })
                        })
                        .await?;
                        let remaining = limits.tool_result_bytes - result_bytes;
                        let bytes = encoded_size(&result, remaining)?;
                        validate_output(call, &result, &outputs)?;
                        result_bytes += bytes;
                        results.push(result);
                    }
                    results
                };
                executed_tools += results.len();
                conversation.submit_tool_results(results)?;
                cooperate(cx, cancellation, deadline).await?;
            }
        }
    }
}

fn validate_output(
    call: &SamplingContentBlock,
    result: &SamplingContentBlock,
    outputs: &BTreeMap<String, AdmittedSchema>,
) -> Result<(), SamplingRunError> {
    let SamplingContentBlock::ToolUse { id, name, .. } = call else {
        return Err(SamplingToolLoopError::InvalidResponse.into());
    };
    let SamplingContentBlock::ToolResult {
        tool_use_id,
        structured_content,
        is_error,
        ..
    } = result
    else {
        return Err(SamplingToolLoopError::InvalidToolResults.into());
    };
    if tool_use_id != id {
        return Err(SamplingToolLoopError::InvalidToolResults.into());
    }
    if *is_error != Some(true) {
        if let Some(schema) = outputs.get(name) {
            let value = structured_content
                .as_ref()
                .ok_or(SamplingToolLoopError::InvalidToolOutput)?;
            schema
                .validate(value)
                .map_err(|_| SamplingToolLoopError::InvalidToolOutput)?;
        }
    }
    Ok(())
}

// Measure without allocating an extra unbounded serialization buffer.
fn encoded_size(value: &impl serde::Serialize, maximum: usize) -> Result<usize, SamplingRunError> {
    struct Counter {
        bytes: usize,
        maximum: usize,
        exceeded: bool,
    }
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.maximum - self.bytes {
                self.exceeded = true;
                return Err(io::Error::other("sampling result budget"));
            }
            self.bytes += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter {
        bytes: 0,
        maximum,
        exceeded: false,
    };
    if serde_json::to_writer(&mut counter, value).is_err() {
        return Err(if counter.exceeded {
            SamplingRunError::ToolResultByteLimit
        } else {
            SamplingToolLoopError::InvalidToolResults.into()
        });
    }
    Ok(counter.bytes)
}

fn deadline(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    timeout: Duration,
) -> Result<Time, SamplingRunError> {
    with_caller(cx, || {
        check(cx, cancellation, Time::from_nanos(u64::MAX))?;
        require_timer(cx)?;
        let nanos =
            u64::try_from(timeout.as_nanos()).map_err(|_| SamplingRunError::InvalidLimits)?;
        let end = cx
            .now()
            .as_nanos()
            .checked_add(nanos)
            .ok_or(SamplingRunError::InvalidLimits)?;
        let deadline = Time::from_nanos(end);
        check(cx, cancellation, deadline)?;
        Ok(deadline)
    })
}

// Called inside with_caller, before any timer registration or host effect.
// Possession of a driver is not permission to use it. Never fall back to a
// different runtime when the effective caller cannot drive a bounded wait.
fn require_timer(cx: &Cx) -> Result<(), SamplingRunError> {
    if cx.timer_driver().is_none()
        || !Cx::current().is_some_and(|active| active.capabilities().time)
    {
        return Err(SamplingRunError::RuntimeUnavailable);
    }
    Ok(())
}

fn check(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    deadline: Time,
) -> Result<(), SamplingRunError> {
    use asupersync::{CancelKind, error::ErrorKind};
    if cancellation.is_cancel_requested() {
        return Err(SamplingRunError::Cancelled);
    }
    if cx.now() >= deadline || cx.budget().deadline.is_some_and(|end| cx.now() >= end) {
        return Err(SamplingRunError::TimedOut);
    }
    cx.checkpoint()
        .map_err(|error| match cx.cancel_reason().map(|reason| reason.kind) {
            Some(CancelKind::Deadline | CancelKind::Timeout) => SamplingRunError::TimedOut,
            Some(_) => SamplingRunError::Cancelled,
            None => match error.kind() {
                ErrorKind::DeadlineExceeded | ErrorKind::CancelTimeout => {
                    SamplingRunError::TimedOut
                }
                _ => SamplingRunError::Cancelled,
            },
        })
}

async fn within<T>(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    deadline: Time,
    future: impl Future<Output = Result<T, SamplingRunError>>,
) -> Result<T, SamplingRunError> {
    let deadline = cx
        .budget()
        .deadline
        .map_or(deadline, |parent| parent.min(deadline));
    let mut sleep = std::pin::pin!(Sleep::new(deadline));
    let mut cancelled = std::pin::pin!(cancellation.cancelled());
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut caller_cancelled = std::pin::pin!(receiver.recv(cx));
    let mut future = std::pin::pin!(future);
    poll_fn(|task| {
        with_caller(cx, || {
            check(cx, cancellation, deadline)?;
            require_timer(cx)?;
            if cancelled.as_mut().poll(task).is_ready()
                || caller_cancelled.as_mut().poll(task).is_ready()
            {
                return Poll::Ready(Err(SamplingRunError::Cancelled));
            }
            if sleep.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(SamplingRunError::TimedOut));
            }
            let result = future.as_mut().poll(task);
            check(cx, cancellation, deadline)?;
            result
        })
    })
    .await
}

async fn cooperate(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    deadline: Time,
) -> Result<(), SamplingRunError> {
    let mut yielded = false;
    within(
        cx,
        cancellation,
        deadline,
        poll_fn(|task| {
            if yielded {
                Poll::Ready(Ok(()))
            } else {
                yielded = true;
                task.waker().wake_by_ref();
                Poll::Pending
            }
        }),
    )
    .await
}

#[cfg(test)]
mod authority;
