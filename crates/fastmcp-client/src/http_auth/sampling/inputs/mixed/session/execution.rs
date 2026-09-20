//! Complete authenticated core calls with a typed, cumulatively budgeted host.
//!
//! These entry points own initial dispatch, incremental notifications, mixed
//! input resolution and exact continuation resumption. Authentication, discovery,
//! framing and state correlation stay with the existing interaction clients.

use std::fmt;
use std::future::{Future, poll_fn};
use std::task::Poll;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{CoreRequest, CoreResult, InputRequiredResult, RequestId, ServerNotification};

use super::{CoreInputHost, CoreInputLimits, CoreInputSession, CoreInputSessionError, CoreInputUsage, deadline, within};
use crate::http_auth::managed::ManagedOAuthSession;
use crate::http_auth::rpc::ManagedCoreError;
use crate::http_auth::rpc::interaction::{ManagedInteraction, ManagedInteractionError, ManagedInteractionEvent, ManagedInteractionLimits};
use crate::http_auth::discovery::client_credentials::ClientCredentialsClient;
use crate::http_auth::discovery::client_credentials::rpc::interaction::{ClientCredentialsInteraction, ClientCredentialsInteractionError};

/// Network budgets cover the whole interaction; host budgets cover every
/// resolution cumulatively. Their original absolute deadlines are intersected,
/// so neither acquisition, host pauses nor later rounds can extend the run.
#[derive(Clone, Copy, Debug)]
pub struct CoreInputExecutionLimits {
    interaction: ManagedInteractionLimits,
    inputs: CoreInputLimits,
    resolutions: usize,
}
impl Default for CoreInputExecutionLimits {
    fn default() -> Self {
        Self { interaction: ManagedInteractionLimits::default(), inputs: CoreInputLimits::default(), resolutions: 8 }
    }
}
impl CoreInputExecutionLimits {
    pub fn new(interaction: ManagedInteractionLimits, inputs: CoreInputLimits, resolutions: usize)
        -> Result<Self, CoreInputSessionError>
    {
        if resolutions > 64 { return Err(CoreInputSessionError::InvalidLimits); }
        Ok(Self { interaction, inputs, resolutions })
    }
}

/// Host selection, not a replacement descriptor map or continuation state.
/// Selection is synchronous and must return promptly without external effects;
/// actual approval and disclosure occur through CoreInputHost afterwards.
/// Selected keys are validated and executed in the server's original order.
pub enum CoreInputSelection {
    All,
    Keys(Vec<String>),
}

/// Complete protocol result plus non-secret usage. Ordinary tool-level errors
/// remain protocol results; they are not transport failures or retry signals.
pub struct CoreInputExecutionResult {
    pub result: Box<CoreResult>,
    pub usage: CoreInputUsage,
    pub continuations: usize,
    pub credential_generation: u64,
}

/// No raw payload or caller string is copied into execution diagnostics.
#[derive(Debug)]
pub enum CoreInputExecutionError {
    InvalidIdPrefix,
    IdentityExhausted,
    OwnerUnavailable,
    OwnerClosed,
    AbortedByHost,
    Input(CoreInputSessionError),
    Managed(ManagedInteractionError),
    Machine(ClientCredentialsInteractionError),
}
impl fmt::Display for CoreInputExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdPrefix => f.write_str("invalid host-driven core request ID prefix"),
            Self::IdentityExhausted => f.write_str("host-driven core request IDs exhausted"),
            Self::OwnerUnavailable => f.write_str("authenticated core owner signal unavailable"),
            Self::OwnerClosed => f.write_str("authenticated core owner closed"),
            Self::AbortedByHost => f.write_str("core execution stopped by its host"),
            Self::Input(error) => error.fmt(f),
            Self::Managed(error) => error.fmt(f),
            Self::Machine(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for CoreInputExecutionError {}
impl From<CoreInputSessionError> for CoreInputExecutionError {
    fn from(error: CoreInputSessionError) -> Self { Self::Input(error) }
}
impl From<ManagedInteractionError> for CoreInputExecutionError {
    fn from(error: ManagedInteractionError) -> Self { Self::Managed(error) }
}
impl From<ClientCredentialsInteractionError> for CoreInputExecutionError {
    fn from(error: ClientCredentialsInteractionError) -> Self { Self::Machine(error) }
}

impl ManagedOAuthSession {
    /// Runs an initial modern tool/resource/prompt call through a typed host
    /// until a complete result. Uses the same original metadata throughout.
    /// There is no new login, implicit consent, background worker or failed-POST
    /// retry. `notify` is incremental and must return promptly.
    ///
    /// Use a distinct prefix for concurrent executions on the same endpoint.
    /// IDs are generated without reuse within this run, not as idempotency keys.
    /// On the first input challenge one credential lookup obtains the session's
    /// existing closure signal. That lookup may renew under normal session
    /// policy; it does not pin a token or grant host disclosure authority.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_core_with_input_host<H, N>(
        &self, cx: &Cx, cancellation: &McpRequestCancellation, request: CoreRequest,
        id_prefix: String, limits: CoreInputExecutionLimits, host: &mut H, notify: N,
    ) -> Result<CoreInputExecutionResult, CoreInputExecutionError>
    where H: CoreInputHost + ?Sized,
        N: FnMut(Box<ServerNotification>) -> Result<(), CoreInputExecutionError>,
    {
        execute(Authentication::Managed(self), cx, cancellation, request, id_prefix,
            limits, host, |_| Ok(CoreInputSelection::All), notify).await
    }

    /// Like `execute_core_with_input_host`, with explicit per-challenge partial
    /// selection. A proper subset requires nonempty server continuation state.
    /// Any selector, resolver, notification or transport failure ends the run;
    /// previously performed host effects cannot be undone or silently repeated.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_core_with_selected_input_host<H, S, N>(
        &self, cx: &Cx, cancellation: &McpRequestCancellation, request: CoreRequest,
        id_prefix: String, limits: CoreInputExecutionLimits, host: &mut H, select: S, notify: N,
    ) -> Result<CoreInputExecutionResult, CoreInputExecutionError>
    where H: CoreInputHost + ?Sized,
        S: FnMut(&InputRequiredResult) -> Result<CoreInputSelection, CoreInputExecutionError>,
        N: FnMut(Box<ServerNotification>) -> Result<(), CoreInputExecutionError>,
    {
        execute(Authentication::Managed(self), cx, cancellation, request, id_prefix,
            limits, host, select, notify).await
    }
}
impl ClientCredentialsClient {
    /// Machine-authenticated counterpart of the managed host execution path.
    /// Each round retains fresh same-token discovery before its operation POST.
    /// Generated discovery and operation IDs share one non-reusing sequence.
    /// The first challenge performs one credential lookup for the owner's closure
    /// signal; ordinary acquisition/renewal policy remains with this client.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_core_with_input_host<H, N>(
        &self, cx: &Cx, cancellation: &McpRequestCancellation, request: CoreRequest,
        id_prefix: String, limits: CoreInputExecutionLimits, host: &mut H, notify: N,
    ) -> Result<CoreInputExecutionResult, CoreInputExecutionError>
    where H: CoreInputHost + ?Sized,
        N: FnMut(Box<ServerNotification>) -> Result<(), CoreInputExecutionError>,
    {
        execute(Authentication::Machine(self), cx, cancellation, request, id_prefix,
            limits, host, |_| Ok(CoreInputSelection::All), notify).await
    }

    /// Selectively resolves machine-authenticated challenges without resetting
    /// host budgets or replacing the original request or authorization owner.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_core_with_selected_input_host<H, S, N>(
        &self, cx: &Cx, cancellation: &McpRequestCancellation, request: CoreRequest,
        id_prefix: String, limits: CoreInputExecutionLimits, host: &mut H, select: S, notify: N,
    ) -> Result<CoreInputExecutionResult, CoreInputExecutionError>
    where H: CoreInputHost + ?Sized,
        S: FnMut(&InputRequiredResult) -> Result<CoreInputSelection, CoreInputExecutionError>,
        N: FnMut(Box<ServerNotification>) -> Result<(), CoreInputExecutionError>,
    {
        execute(Authentication::Machine(self), cx, cancellation, request, id_prefix,
            limits, host, select, notify).await
    }
}

// Private enum composition, not a new public transport/plugin abstraction.
// Both arms keep their existing authentication and protocol implementations.
enum Authentication<'a> { Managed(&'a ManagedOAuthSession), Machine(&'a ClientCredentialsClient) }
enum Interaction { Managed(ManagedInteraction), Machine(ClientCredentialsInteraction) }
impl Authentication<'_> {
    async fn start(&self, cx: &Cx, cancellation: &McpRequestCancellation,
        request: CoreRequest, ids: &mut Ids, limits: ManagedInteractionLimits,
    ) -> Result<Interaction, CoreInputExecutionError> {
        match self {
            Self::Managed(client) => Ok(Interaction::Managed(client.start_core_interaction_with_cancellation(
                cx, cancellation, request, ids.next()?, limits).await?)),
            Self::Machine(client) => Ok(Interaction::Machine(client.start_core_interaction_with_cancellation(
                cx, cancellation, request, ids.next()?, ids.next()?, limits).await?)),
        }
    }
    async fn owner(&self, cx: &Cx, cancellation: &McpRequestCancellation)
        -> Result<McpRequestCancellation, CoreInputExecutionError>
    {
        let owner = match self {
            Self::Managed(client) => client.credential_with_cancellation(cx, cancellation).await
                .map_err(|error| ManagedInteractionError::from(ManagedCoreError::from(error)))?
                .credential().owner_cancellation.clone(),
            Self::Machine(client) => client.credential_with_cancellation(cx, cancellation).await
                .map_err(ClientCredentialsInteractionError::from)?
                .credential().owner_cancellation.clone(),
        };
        // Keep only the owner's existing notification handle, not a credential
        // copy or a permission to replace that owner's lifetime with another.
        owner.ok_or(CoreInputExecutionError::OwnerUnavailable)
    }
}
impl Interaction {
    async fn next(&mut self, cx: &Cx) -> Result<ManagedInteractionEvent, CoreInputExecutionError> {
        match self {
            Self::Managed(operation) => operation.next_event(cx).await?,
            Self::Machine(operation) => operation.next_event(cx).await?,
        }.ok_or(CoreInputExecutionError::AbortedByHost)
    }
    fn continuation_ids(&self, ids: &mut Ids) -> Result<(Option<RequestId>, RequestId), CoreInputExecutionError> {
        let discovery = if matches!(self, Self::Machine(_)) { Some(ids.next()?) } else { None };
        Ok((discovery, ids.next()?))
    }
    async fn resume(&mut self, cx: &Cx, discovery: Option<RequestId>,
        reply: super::ManagedInputReply, partial: bool,
    ) -> Result<(), CoreInputExecutionError> {
        match self {
            Self::Managed(operation) => {
                if partial {
                    operation.resume_partial(cx, reply.request_id, reply.input_responses
                        .ok_or(ManagedInteractionError::InvalidInputResponses)?).await?;
                } else { operation.resume(cx, reply.request_id, reply.input_responses).await?; }
            }
            Self::Machine(operation) => {
                let discovery = discovery.ok_or(CoreInputExecutionError::IdentityExhausted)?;
                if partial {
                    operation.resume_partial(cx, discovery, reply.request_id, reply.input_responses
                        .ok_or(ManagedInteractionError::InvalidInputResponses)?).await?;
                } else { operation.resume(cx, discovery, reply.request_id, reply.input_responses).await?; }
            }
        }
        Ok(())
    }
    fn counts(&self) -> (usize, u64) {
        match self {
            Self::Managed(operation) => (operation.continuation_count(), operation.credential_generation()),
            Self::Machine(operation) => (operation.continuation_count(), operation.credential_generation()),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute<H, S, N>(
    authentication: Authentication<'_>, cx: &Cx, cancellation: &McpRequestCancellation,
    request: CoreRequest, prefix: String, limits: CoreInputExecutionLimits,
    host: &mut H, mut select: S, mut notify: N,
) -> Result<CoreInputExecutionResult, CoreInputExecutionError>
where H: CoreInputHost + ?Sized,
    S: FnMut(&InputRequiredResult) -> Result<CoreInputSelection, CoreInputExecutionError>,
    N: FnMut(Box<ServerNotification>) -> Result<(), CoreInputExecutionError>,
{
    let mut ids = Ids::new(prefix)?;
    let mut inputs = CoreInputSession::new(cx, cancellation, request.clone(), limits.inputs, limits.resolutions)?;
    let network_end = deadline(cx, cancellation, limits.interaction.core().timeout())
        .map_err(CoreInputSessionError::from)?;
    inputs.deadline = inputs.deadline.min(network_end);
    let end = inputs.deadline;
    let mut interaction = Box::pin(guarded(cx, cancellation, end, None,
        authentication.start(cx, cancellation, request, &mut ids, limits.interaction))).await?;
    let mut owner = None;
    loop {
        match Box::pin(guarded(cx, cancellation, end, owner.as_ref(), interaction.next(cx))).await? {
            ManagedInteractionEvent::Notification(notification) => {
                guarded(cx, cancellation, end, owner.as_ref(), async { notify(notification) }).await?;
            }
            ManagedInteractionEvent::InputRequired(input) => {
                if inputs.usage().resolutions >= limits.resolutions {
                    return Err(CoreInputSessionError::ResolutionLimit.into());
                }
                if owner.is_none() {
                    owner = Some(Box::pin(guarded(cx, cancellation, end, None, authentication.owner(cx, cancellation))).await?);
                }
                let (discovery, request_id) = interaction.continuation_ids(&mut ids)?;
                let selection = guarded(cx, cancellation, end, owner.as_ref(), async { select(&input) }).await?;
                let partial = matches!(&selection, CoreInputSelection::Keys(_));
                let reply = guarded(cx, cancellation, end, owner.as_ref(), async {
                    Ok(match selection {
                        CoreInputSelection::All => inputs.resolve(cx, *input, request_id, host).await?,
                        CoreInputSelection::Keys(keys) => {
                            // Do not allocate another key vector from an unbounded
                            // host selection. The resolver also validates identity.
                            if keys.len() > limits.inputs.sampling.inputs {
                                return Err(CoreInputSessionError::Input(super::CoreInputError::InvalidSelection).into());
                            }
                            let borrowed: Vec<_> = keys.iter().map(String::as_str).collect();
                            inputs.resolve_selected(cx, *input, request_id, &borrowed, host).await?
                        }
                    })
                }).await?;
                Box::pin(guarded(cx, cancellation, end, owner.as_ref(), interaction.resume(cx, discovery, reply, partial))).await?;
            }
            ManagedInteractionEvent::Complete(result) => {
                let (continuations, credential_generation) = interaction.counts();
                return Ok(CoreInputExecutionResult { result, usage: inputs.usage(), continuations, credential_generation });
            }
        }
    }
}

async fn guarded<T>(cx: &Cx, cancellation: &McpRequestCancellation, end: asupersync::Time,
    owner: Option<&McpRequestCancellation>, future: impl Future<Output = Result<T, CoreInputExecutionError>>,
) -> Result<T, CoreInputExecutionError> {
    within(cx, cancellation, end, async {
        Ok(if let Some(owner) = owner {
            let mut closed = std::pin::pin!(owner.cancelled());
            let mut future = std::pin::pin!(future);
            poll_fn(|task| {
                if closed.as_mut().poll(task).is_ready() { return Poll::Ready(Err(CoreInputExecutionError::OwnerClosed)); }
                let result = future.as_mut().poll(task);
                if owner.is_cancel_requested() { return Poll::Ready(Err(CoreInputExecutionError::OwnerClosed)); }
                result
            }).await
        } else { future.await })
    }).await.map_err(CoreInputSessionError::from)?
}

struct Ids { prefix: String, next: u64 }
impl Ids {
    fn new(prefix: String) -> Result<Self, CoreInputExecutionError> {
        if prefix.is_empty() || prefix.len() > 128 || !prefix.bytes().all(|byte|
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')) {
            return Err(CoreInputExecutionError::InvalidIdPrefix);
        }
        Ok(Self { prefix, next: 0 })
    }
    fn next(&mut self) -> Result<RequestId, CoreInputExecutionError> {
        let next = self.next.checked_add(1).ok_or(CoreInputExecutionError::IdentityExhausted)?;
        let id = RequestId::String(format!("{}:{}", self.prefix, self.next));
        self.next = next;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generated_ids_have_a_bounded_prefix_and_do_not_reuse_capacity_on_exhaustion() {
        for prefix in [String::new(), "x".repeat(129), "unsafe:prefix".to_owned(), "é".to_owned()] {
            assert!(Ids::new(prefix).is_err());
        }
        let mut ids = Ids::new("caller-_.1".to_owned()).unwrap();
        assert_eq!(ids.next().unwrap(), RequestId::String("caller-_.1:0".to_owned()));
        assert_eq!(ids.next().unwrap(), RequestId::String("caller-_.1:1".to_owned()));
        ids.next = u64::MAX;
        assert!(matches!(ids.next(), Err(CoreInputExecutionError::IdentityExhausted)));
        assert_eq!(ids.next, u64::MAX);
    }
    #[test]
    fn execution_resolution_limits_admit_zero_and_reject_unbounded_rounds() {
        assert!(CoreInputExecutionLimits::new(ManagedInteractionLimits::default(), CoreInputLimits::default(), 0).is_ok());
        assert!(CoreInputExecutionLimits::new(ManagedInteractionLimits::default(), CoreInputLimits::default(), 65).is_err());
    }
}
