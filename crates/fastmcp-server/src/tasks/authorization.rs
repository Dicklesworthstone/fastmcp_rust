//! Current request and execution authorization for process-local Tasks.
//!
//! The original operation is an immutable, nonserializable registration
//! binding. It is deliberately not a recoverable execution grant. A future
//! persistent backend needs its own protected durable authorization contract.

use super::*;
use std::fmt;

const MAX_TASK_ACCESS_AUTHORIZERS: usize = 16;
const MAX_TASK_EXECUTION_AUTHORIZERS: usize = 16;
const MAX_TASK_OPERATION_NAME_BYTES: usize = 2_048;

/// The current request action, independent of the operation that created a Task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskAccessAction {
    Create,
    Get,
    Update,
    Cancel,
    Listen,
}

impl TaskAccessAction {
    /// Exact MCP method whose management grants must also be satisfied.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Self::Create => "tools/call",
            Self::Get => "tasks/get",
            Self::Update => "tasks/update",
            Self::Cancel => "tasks/cancel",
            Self::Listen => "subscriptions/listen",
        }
    }
}

/// Framework-bound original tool registration for a process-local Task.
///
/// Stores retain this value unchanged with the principal and Task. It contains
/// no arguments, credentials, result, or authorization grant. Only the router
/// constructs it; a removed or replaced registration invalidates it even when
/// another handler subsequently uses the same tool name. It cannot be restored
/// across process restart and does not establish durable Task authorization.
#[derive(Clone)]
pub struct FinalTaskOperation {
    tool_name: String,
    registration: Weak<()>,
}

impl FinalTaskOperation {
    pub(crate) fn for_tool(tool_name: &str, registration: &Arc<()>) -> McpResult<Self> {
        if tool_name.is_empty()
            || tool_name.len() > MAX_TASK_OPERATION_NAME_BYTES
            || tool_name.chars().any(char::is_control)
        {
            return Err(McpError::invalid_params("Invalid Task original operation"));
        }
        Ok(Self {
            tool_name: tool_name.to_owned(),
            registration: Arc::downgrade(registration),
        })
    }

    #[must_use]
    pub const fn method(&self) -> &'static str {
        "tools/call"
    }

    #[must_use]
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }

    fn is_visible(&self, ctx: &McpContext) -> bool {
        self.is_registered() && ctx.is_tool_enabled(&self.tool_name)
    }

    fn is_registered(&self) -> bool {
        self.registration.strong_count() != 0
    }

    pub(super) fn retained_bytes(&self) -> usize {
        self.tool_name.len() + std::mem::size_of::<Self>()
    }
}

impl PartialEq for FinalTaskOperation {
    fn eq(&self, other: &Self) -> bool {
        self.tool_name == other.tool_name && Weak::ptr_eq(&self.registration, &other.registration)
    }
}

impl Eq for FinalTaskOperation {}

impl fmt::Debug for FinalTaskOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalTaskOperation")
            .finish_non_exhaustive()
    }
}

/// Payload-free, immutable authority facts returned before opening Task state.
///
/// A backend must read these facts atomically from the same record as its Task
/// snapshot. In particular it must never derive the owner or operation from an
/// application work descriptor or from the current request. Constructors are
/// for trusted store implementations, not for granting access to a caller.
#[derive(Clone)]
pub struct FinalTaskAccessMetadata {
    task_id: FinalTaskId,
    generation: u64,
    creation_generation: u64,
    principal: Option<Sha256Digest>,
    operation: Option<FinalTaskOperation>,
}

impl FinalTaskAccessMetadata {
    /// Returns the Task owner lookup key for already-verified authentication.
    ///
    /// An execution-policy provider may use this key to index independently
    /// maintained current grants. It is only stable identity: it verifies
    /// neither this authentication value nor its freshness and grants no
    /// permission by itself. The caller must obtain `auth` from its trusted
    /// authentication boundary and authorize the original operation against
    /// current policy. Refreshed credentials for the same provider-scoped
    /// owner yield the same key even when their scopes change.
    pub fn principal_for_auth(auth: &fastmcp_core::AuthContext) -> McpResult<Sha256Digest> {
        crate::auth::principal_fingerprint(Some(auth))
    }

    #[must_use]
    pub fn new(
        task_id: FinalTaskId,
        generation: u64,
        creation_generation: u64,
        principal: Option<Sha256Digest>,
        operation: Option<FinalTaskOperation>,
    ) -> Self {
        Self {
            task_id,
            generation,
            creation_generation,
            principal,
            operation,
        }
    }

    #[must_use]
    pub const fn task_id(&self) -> &FinalTaskId {
        &self.task_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Immutable store generation allocated by the original insert.
    #[must_use]
    pub const fn creation_generation(&self) -> u64 {
        self.creation_generation
    }

    #[must_use]
    pub const fn authenticated_principal(&self) -> Option<Sha256Digest> {
        self.principal
    }

    #[must_use]
    pub fn original_operation(&self) -> Option<&FinalTaskOperation> {
        self.operation.as_ref()
    }

    pub(super) fn admits_snapshot(&self, snapshot: &FinalTaskSnapshot) -> bool {
        self.task_id == snapshot.task().base().task_id
            && snapshot.generation() >= self.generation
            && snapshot.creation_generation() == self.creation_generation
            && self.principal == snapshot.authenticated_principal()
            && self.operation.as_ref() == snapshot.original_operation()
    }
}

impl fmt::Debug for FinalTaskAccessMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalTaskAccessMetadata")
            .finish_non_exhaustive()
    }
}

/// Current application authorization for a Task's original operation.
///
/// Every call must recheck the complete current grants and any application
/// visibility or revocation policy for both the original operation and the
/// requested management action. The framework separately enforces stable
/// principal equality, registration lifetime and context tool visibility.
/// Verified authentication facts also retain their original opaque expiry:
/// a long listener must close when that receipt expires. Reopening with fresh
/// facts or an application policy is required for renewed grants; this layer
/// does not renew credentials or discover provider revocation on its own.
/// Callbacks are synchronous, bounded and must not perform blocking I/O. Errors
/// and panics are sanitized to the same missing-Task response. Multiple
/// installed authorizers intersect; none can widen an earlier decision.
pub trait TaskAccessAuthorizer: Send + Sync {
    fn authorize(
        &self,
        ctx: &McpContext,
        action: TaskAccessAction,
        original: &FinalTaskOperation,
    ) -> McpResult<()>;
}

/// Current application permission to execute one process-local Task attempt.
///
/// Each call must freshly decide the complete current grants, visibility and
/// revocation policy for the retained owner and exact original operation.
/// Metadata identifies the operation to authorize; owner equality, handle
/// possession and a previously successful request are not execution grants.
/// The framework separately checks registration lifetime and the exact Task
/// incarnation and generation before consulting these policies.
///
/// A protected router-created Task requires at least one installed execution
/// policy. The provider obtains current authority from trusted application
/// policy; it must not reuse the ingress context, a bearer token, or an expired
/// request authorization receipt. This interface retains no such credential
/// or request context and does not establish restart-safe durable authorization
/// or renew credentials. A persistent backend needs its own protected durable
/// authorization contract.
///
/// Callbacks must be synchronous, bounded, and perform no blocking I/O. They
/// run outside runtime and store locks. Every installed policy must allow the
/// attempt; errors and panics become the same sanitized execution denial.
/// Framework polling, lease and mutation boundaries recheck permission; this
/// cannot undo an external side effect already performed by application code.
pub trait TaskExecutionAuthorizer: Send + Sync {
    fn authorize(&self, task: &FinalTaskAccessMetadata) -> McpResult<()>;
}

impl FinalTaskRuntime {
    /// Adds an intersecting current-access policy shared by runtime clones.
    ///
    /// Configure before accepting requests. Protected router-created Tasks
    /// require at least one policy before creation. Trusted embedding APIs
    /// remain separate: their direct reads and writes are not request grants.
    /// Installing a policy makes unbound embedding-created Tasks inaccessible
    /// through wire requests, because their original operation is unknown.
    pub fn install_access_authorizer(
        &self,
        authorizer: Arc<dyn TaskAccessAuthorizer>,
    ) -> McpResult<()> {
        self.install_access_authorizers(vec![authorizer])
    }

    /// Installs a complete builder batch or leaves the shared runtime unchanged.
    pub(crate) fn install_access_authorizers(
        &self,
        authorizers: Vec<Arc<dyn TaskAccessAuthorizer>>,
    ) -> McpResult<()> {
        self.install_task_authorizers(authorizers, Vec::new())
    }

    /// Adds an intersecting execution policy shared by runtime clones.
    ///
    /// Configure before accepting Tasks. At most sixteen policies may be
    /// installed. Policies also apply to trusted embedding-created work;
    /// installing one does not confer an original-operation binding on that
    /// work or turn a principal digest into an execution grant.
    pub fn install_execution_authorizer(
        &self,
        authorizer: Arc<dyn TaskExecutionAuthorizer>,
    ) -> McpResult<()> {
        self.install_execution_authorizers(vec![authorizer])
    }

    pub(crate) fn install_execution_authorizers(
        &self,
        authorizers: Vec<Arc<dyn TaskExecutionAuthorizer>>,
    ) -> McpResult<()> {
        self.install_task_authorizers(Vec::new(), authorizers)
    }

    /// Installs both builder policy batches atomically under a fixed lock order.
    /// Neither policy set changes if either set would exceed its bound.
    pub(crate) fn install_task_authorizers(
        &self,
        access: Vec<Arc<dyn TaskAccessAuthorizer>>,
        execution: Vec<Arc<dyn TaskExecutionAuthorizer>>,
    ) -> McpResult<()> {
        let mut installed_access = self
            .access_authorizers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut installed_execution = self
            .execution_authorizers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if access.len()
            > MAX_TASK_ACCESS_AUTHORIZERS.saturating_sub(installed_access.len())
        {
            return Err(McpError::invalid_params(
                "Task access policy capacity reached",
            ));
        }
        if execution.len()
            > MAX_TASK_EXECUTION_AUTHORIZERS.saturating_sub(installed_execution.len())
        {
            return Err(McpError::invalid_params(
                "Task execution policy capacity reached",
            ));
        }
        installed_access.extend(access);
        installed_execution.extend(execution);
        Ok(())
    }

    pub(super) fn ensure_execution_policy_available(
        &self,
        principal: Option<Sha256Digest>,
    ) -> McpResult<()> {
        if principal.is_some()
            && self
                .execution_authorizers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        {
            return Err(task_execution_denied());
        }
        Ok(())
    }

    pub(super) fn authorize_task_execution(
        &self,
        metadata: &FinalTaskAccessMetadata,
    ) -> McpResult<()> {
        let authorizers = self.execution_authorizers_snapshot();
        authorize_task_execution_with_policies(metadata, &authorizers)
    }

    /// Rechecks the exact elected record without opening application payload.
    pub(super) fn revalidate_task_execution(
        &self,
        expected: &FinalTaskAccessMetadata,
    ) -> McpResult<()> {
        let authorizers = self.execution_authorizers_snapshot();
        // Existing trusted embedding stores may have no request metadata API.
        // Only their anonymous, unbound, policy-free execution retains that
        // contract; the runner's elected store fence still owns its generation.
        if expected.authenticated_principal().is_none()
            && expected.original_operation().is_none()
            && authorizers.is_empty()
        {
            return authorize_task_execution_with_policies(expected, &authorizers);
        }
        let current = self
            .store
            .get_task_access_metadata(expected.task_id())
            .map_err(|_| task_execution_denied())?
            .ok_or_else(task_execution_denied)?;
        if current.task_id() != expected.task_id()
            || current.generation() != expected.generation()
            || current.creation_generation() != expected.creation_generation()
            || current.authenticated_principal() != expected.authenticated_principal()
            || current.original_operation() != expected.original_operation()
        {
            return Err(task_execution_denied());
        }
        authorize_task_execution_with_policies(&current, &authorizers)
    }

    fn execution_authorizers_snapshot(&self) -> Vec<Arc<dyn TaskExecutionAuthorizer>> {
        self.execution_authorizers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(super) fn authorize_original_operation(
        &self,
        ctx: &McpContext,
        action: TaskAccessAction,
        original: Option<&FinalTaskOperation>,
    ) -> McpResult<()> {
        ensure_current_task_authentication(ctx)?;
        let authorizers = self
            .access_authorizers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(original) = original else {
            return if authorizers.is_empty() {
                Ok(())
            } else {
                Err(task_access_denied())
            };
        };
        if action == TaskAccessAction::Create && ctx.auth().is_some() && authorizers.is_empty() {
            return Err(McpError::invalid_request(
                "Protected Task creation requires a current original-operation access policy",
            ));
        }
        if !original.is_visible(ctx) || (ctx.auth().is_some() && authorizers.is_empty()) {
            return Err(task_access_denied());
        }
        for authorizer in authorizers {
            let allowed = catch_unwind(AssertUnwindSafe(|| {
                authorizer.authorize(ctx, action, original)
            }))
            .is_ok_and(|result| result.is_ok());
            ensure_current_task_authentication(ctx)?;
            if !allowed || !original.is_visible(ctx) {
                return Err(task_access_denied());
            }
        }
        ensure_current_task_authentication(ctx)
    }

    pub(crate) fn admit_task_for_request(
        &self,
        ctx: &McpContext,
        task_id: &FinalTaskId,
        action: TaskAccessAction,
    ) -> McpResult<FinalTaskAccessMetadata> {
        ensure_current_task_authentication(ctx)?;
        let principal = task_request_principal(ctx)?;
        let metadata = self
            .store
            .get_task_access_metadata(task_id)?
            .ok_or_else(task_access_denied)?;
        if metadata.task_id() != task_id
            || metadata.generation() == 0
            || metadata.creation_generation() == 0
            || metadata.creation_generation() > metadata.generation()
            || metadata.authenticated_principal() != principal
        {
            return Err(task_access_denied());
        }
        self.authorize_original_operation(ctx, action, metadata.original_operation())?;
        ensure_current_task_authentication(ctx)?;
        Ok(metadata)
    }

    pub(crate) fn notification_matches_task_access(
        &self,
        ctx: &McpContext,
        admitted: &FinalTaskAccessMetadata,
        notification: &FinalTaskStatusNotification,
    ) -> McpResult<bool> {
        if notification.params.task.base().task_id != *admitted.task_id() {
            return Ok(false);
        }
        // Authorization precedes the payload read. An emitter's optimistic
        // current-state check can be overtaken by another write or by ID
        // reclamation before this callback runs. Reject an old notification
        // even when a new listener owns the same ID and original operation.
        if !self.task_access_is_current(ctx, admitted) {
            return Err(task_access_denied());
        }
        let current = self
            .store
            .get_task_snapshot(admitted.task_id())
            .map_err(|_| task_access_denied())?
            .ok_or_else(task_access_denied)?;
        if !admitted.admits_snapshot(&current) {
            return Err(task_access_denied());
        }
        let current = self
            .validate_loaded_task_snapshot(current, Some(admitted.task_id()))
            .map_err(|_| task_access_denied())?;
        self.authorize_original_operation(
            ctx,
            TaskAccessAction::Listen,
            current.original_operation(),
        )?;
        // A same-incarnation transition may simply have superseded this event.
        // Drop that event without terminating a still-authorized subscription.
        final_tasks_match_exactly(current.task(), &notification.params.task)
            .map_err(|_| task_access_denied())
    }

    pub(crate) fn task_access_is_current(
        &self,
        ctx: &McpContext,
        admitted: &FinalTaskAccessMetadata,
    ) -> bool {
        self.admit_task_for_request(ctx, admitted.task_id(), TaskAccessAction::Listen)
            .is_ok_and(|current| {
                current.authenticated_principal() == admitted.authenticated_principal()
                    && current.original_operation() == admitted.original_operation()
                    && current.creation_generation() == admitted.creation_generation()
                    && current.generation() >= admitted.generation()
            })
    }

    /// Keeps an upstream read alive while current local Task grants are
    /// rechecked. Reconstructing the future after a timer tick could lose an
    /// admitted frame or repeat transport work, so it is pinned exactly once.
    #[cfg(feature = "proxy")]
    pub(crate) async fn guard_task_subscription_operation<T>(
        &self,
        cx: &Cx,
        ctx: &McpContext,
        admitted: &BTreeMap<FinalTaskId, FinalTaskAccessMetadata>,
        cancellation: &fastmcp_core::McpRequestCancellation,
        operation: impl Future<Output = McpResult<T>>,
    ) -> McpResult<T> {
        let mut operation = std::pin::pin!(operation);
        let mut cancelled = std::pin::pin!(cancellation.cancelled());
        let mut timer = std::pin::pin!(asupersync::time::Sleep::new(cx.now()));
        std::future::poll_fn(|poll| {
            if cancellation.is_cancel_requested()
                || cancelled.as_mut().poll(poll).is_ready()
                || ctx.ensure_live().is_err()
            {
                return std::task::Poll::Ready(Err(McpError::request_cancelled()));
            }
            if !cx.capabilities().time
                || cx.timer_driver().is_none()
                || Cx::current().is_some_and(|current| !current.capabilities().time)
            {
                cancellation.cancel();
                return std::task::Poll::Ready(Err(McpError::request_cancelled()));
            }
            if let Some(deadline) = ctx.budget().deadline
                && deadline < timer.deadline()
            {
                timer.as_mut().get_mut().reset(deadline);
            }
            let check = {
                let _current = Cx::set_current(Some(cx.clone()));
                timer.as_mut().poll(poll).is_ready()
            };
            if check {
                if !admitted
                    .values()
                    .all(|metadata| self.task_access_is_current(ctx, metadata))
                {
                    cancellation.cancel();
                    return std::task::Poll::Ready(Err(McpError::request_cancelled()));
                }
                let next = cx.now().saturating_add_nanos(1_000_000_000);
                timer.as_mut().get_mut().reset(
                    ctx.budget()
                        .deadline
                        .map_or(next, |deadline| deadline.min(next)),
                );
                // Register the next revalidation before yielding to a read
                // which might otherwise never wake this request again.
                let _current = Cx::set_current(Some(cx.clone()));
                let _ = timer.as_mut().poll(poll);
            }
            match operation.as_mut().poll(poll) {
                std::task::Poll::Ready(result) => {
                    if cancellation.is_cancel_requested()
                        || ctx.ensure_live().is_err()
                        || !admitted
                            .values()
                            .all(|metadata| self.task_access_is_current(ctx, metadata))
                    {
                        cancellation.cancel();
                        std::task::Poll::Ready(Err(McpError::request_cancelled()))
                    } else {
                        std::task::Poll::Ready(result)
                    }
                }
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        })
        .await
    }
}

fn authorize_task_execution_with_policies(
    metadata: &FinalTaskAccessMetadata,
    authorizers: &[Arc<dyn TaskExecutionAuthorizer>],
) -> McpResult<()> {
    if metadata.generation() == 0
        || metadata.creation_generation() == 0
        || metadata.creation_generation() > metadata.generation()
        || (metadata.authenticated_principal().is_some()
            && (metadata.original_operation().is_none() || authorizers.is_empty()))
        || metadata
            .original_operation()
            .is_some_and(|operation| !operation.is_registered())
    {
        return Err(task_execution_denied());
    }
    for authorizer in authorizers {
        let allowed = catch_unwind(AssertUnwindSafe(|| authorizer.authorize(metadata)))
            .is_ok_and(|result| result.is_ok());
        if !allowed
            || metadata
                .original_operation()
                .is_some_and(|operation| !operation.is_registered())
        {
            return Err(task_execution_denied());
        }
    }
    Ok(())
}

pub(super) fn task_execution_denied() -> McpError {
    McpError::invalid_request("Task execution is no longer authorized")
}

pub(super) fn task_access_denied() -> McpError {
    McpError::invalid_params("Task not found")
}

fn ensure_current_task_authentication(ctx: &McpContext) -> McpResult<()> {
    ctx.ensure_live()?;
    crate::Server::enforce_authentication_freshness(ctx.auth().as_ref())
        .map_err(|_| task_access_denied())
}

#[cfg(test)]
mod http_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_admission::security::scope_policy::request::ScopeRequestPolicy;
    use crate::http_admission::security::scope_policy::request::operation::{
        OperationScopePolicy, ScopedOperation,
    };
    use crate::http_admission::security::scope_policy::{RequiredScopes, ScopeImplicationPolicy};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn context(scopes: &[&str]) -> McpContext {
        let mut auth = fastmcp_core::AuthContext::with_subject("same-owner")
            .with_session_owner(Sha256Digest::from_bytes([17; 32]));
        auth.scopes = scopes.iter().map(|scope| (*scope).to_owned()).collect();
        McpContext::new(Cx::for_testing(), 1).with_auth(auth)
    }

    fn policy() -> OperationScopePolicy {
        let required = |scope: &str| RequiredScopes::new(vec![scope.to_owned()]).unwrap();
        let methods = ScopeRequestPolicy::new(
            1,
            ScopeImplicationPolicy::new(1, vec![]).unwrap(),
            vec![
                ("tools/call".to_owned(), required("invoke")),
                ("tasks/get".to_owned(), required("manage")),
                ("tasks/update".to_owned(), required("manage")),
                ("tasks/cancel".to_owned(), required("manage")),
                ("subscriptions/listen".to_owned(), required("manage")),
            ],
        )
        .unwrap();
        OperationScopePolicy::new(
            1,
            methods,
            vec![(
                ScopedOperation::ToolCall("sensitive-tool".to_owned()),
                required("sensitive"),
            )],
        )
        .unwrap()
    }

    fn task(id: &str) -> FinalTask {
        let now = FinalTaskTimestamp::parse("2026-07-28T12:00:00.000Z").unwrap();
        FinalTask::Working(FinalTaskBase {
            task_id: FinalTaskId::parse(id).unwrap(),
            status: FinalTaskStatus::Working,
            status_message: None,
            created_at: now.clone(),
            last_updated_at: now,
            ttl_ms: Some(final_task_duration(60_000).unwrap()),
            poll_interval_ms: None,
        })
    }

    fn work() -> FinalTaskWorkDescriptor {
        FinalTaskWorkDescriptor::new(serde_json::json!({"secret":"application-canary"})).unwrap()
    }

    fn parameters(task_id: &FinalTaskId) -> serde_json::Value {
        serde_json::json!({
            "taskId": task_id.as_str(),
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": FINAL_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {"extensions":{"io.modelcontextprotocol/tasks":{}}}
            }
        })
    }

    struct ProbeStore {
        inner: InMemoryFinalTaskStore,
        metadata_reads: AtomicUsize,
        payload_reads: AtomicUsize,
        strip_operation: AtomicBool,
        metadata_supported: AtomicBool,
        cancel_before_execution_failure: AtomicBool,
        injected_execution_cancellations: AtomicUsize,
    }

    impl ProbeStore {
        fn new() -> Self {
            Self {
                inner: InMemoryFinalTaskStore::default(),
                metadata_reads: AtomicUsize::new(0),
                payload_reads: AtomicUsize::new(0),
                strip_operation: AtomicBool::new(false),
                metadata_supported: AtomicBool::new(true),
                cancel_before_execution_failure: AtomicBool::new(false),
                injected_execution_cancellations: AtomicUsize::new(0),
            }
        }
    }

    impl FinalTaskStore for ProbeStore {
        fn create_task(
            &self,
            task: FinalTask,
            notification: FinalTaskStatusNotification,
        ) -> McpResult<()> {
            self.inner.create_task(task, notification)
        }
        fn get_task_access_metadata(
            &self,
            id: &FinalTaskId,
        ) -> McpResult<Option<FinalTaskAccessMetadata>> {
            self.metadata_reads.fetch_add(1, Ordering::SeqCst);
            if !self.metadata_supported.load(Ordering::SeqCst) {
                return Ok(None);
            }
            self.inner.get_task_access_metadata(id)
        }
        fn get_task(&self, id: &FinalTaskId) -> McpResult<Option<FinalTask>> {
            self.payload_reads.fetch_add(1, Ordering::SeqCst);
            self.inner.get_task(id)
        }
        fn get_task_snapshot(&self, id: &FinalTaskId) -> McpResult<Option<FinalTaskSnapshot>> {
            self.payload_reads.fetch_add(1, Ordering::SeqCst);
            self.inner.get_task_snapshot(id).map(|snapshot| {
                snapshot.map(|snapshot| {
                    if self.strip_operation.load(Ordering::SeqCst) {
                        snapshot.with_original_operation(None)
                    } else {
                        snapshot
                    }
                })
            })
        }
        fn replace_task(
            &self,
            task: FinalTask,
            notification: FinalTaskStatusNotification,
        ) -> McpResult<()> {
            self.inner.replace_task(task, notification)
        }
        fn replace_task_if_current(
            &self,
            expected: &FinalTaskSnapshot,
            task: FinalTask,
            notification: FinalTaskStatusNotification,
        ) -> McpResult<bool> {
            self.inner
                .replace_task_if_current(expected, task, notification)
        }
        fn replace_task_and_clear_input_for_handoff_if_current(
            &self,
            expected: &FinalTaskSnapshot,
            owner_id: &str,
            dispatch_fence: u64,
            cancellation_required: bool,
            task: FinalTask,
            notification: FinalTaskStatusNotification,
        ) -> McpResult<Option<FinalTaskSnapshot>> {
            if matches!(&task, FinalTask::Failed { .. })
                && self
                    .cancel_before_execution_failure
                    .swap(false, Ordering::SeqCst)
            {
                assert!(self.inner.request_cancellation_if_current(expected)?);
                self.injected_execution_cancellations
                    .fetch_add(1, Ordering::SeqCst);
            }
            self.inner.replace_task_and_clear_input_for_handoff_if_current(
                expected,
                owner_id,
                dispatch_fence,
                cancellation_required,
                task,
                notification,
            )
        }
        fn request_cancellation(&self, id: &FinalTaskId) -> McpResult<()> {
            self.inner.request_cancellation(id)
        }
        fn request_cancellation_if_current(&self, expected: &FinalTaskSnapshot) -> McpResult<bool> {
            self.inner.request_cancellation_if_current(expected)
        }
        fn is_cancellation_requested(&self, id: &FinalTaskId) -> McpResult<bool> {
            self.inner.is_cancellation_requested(id)
        }
        fn retention_clock_now(&self) -> Instant {
            self.inner.retention_clock_now()
        }
        fn task_retention_deadline_if_current(
            &self,
            id: &FinalTaskId,
            generation: u64,
        ) -> McpResult<Option<FinalTaskRetentionDeadline>> {
            self.inner
                .task_retention_deadline_if_current(id, generation)
        }
        fn expire_task_execution_if_current(
            &self,
            expected: &FinalTaskSnapshot,
        ) -> McpResult<Option<FinalTaskSnapshot>> {
            self.inner.expire_task_execution_if_current(expected)
        }
    }

    fn fixture() -> (Arc<ProbeStore>, FinalTaskRuntime, FinalTaskId, Arc<()>) {
        let store = Arc::new(ProbeStore::new());
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, None).unwrap(),
            Arc::new(|_| {}),
        );
        runtime
            .install_access_authorizer(Arc::new(policy()))
            .unwrap();
        let registration = Arc::new(());
        let task = task("original-operation");
        let id = task.base().task_id.clone();
        store
            .inner
            .create_task_with_operation(
                task.clone(),
                final_task_notification(&task),
                work(),
                task_request_principal(&context(&["invoke", "manage", "sensitive"])).unwrap(),
                FinalTaskOperation::for_tool("sensitive-tool", &registration).unwrap(),
            )
            .unwrap();
        (store, runtime, id, registration)
    }

    struct ExecutionPolicy {
        principal: Option<Sha256Digest>,
        operation: FinalTaskOperation,
        revoked: AtomicBool,
        calls: AtomicUsize,
    }

    impl ExecutionPolicy {
        fn new(principal: Option<Sha256Digest>, operation: FinalTaskOperation) -> Self {
            Self {
                principal,
                operation,
                revoked: AtomicBool::new(false),
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl TaskExecutionAuthorizer for ExecutionPolicy {
        fn authorize(&self, metadata: &FinalTaskAccessMetadata) -> McpResult<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if !self.revoked.load(Ordering::SeqCst)
                && metadata.authenticated_principal() == self.principal
                && metadata.original_operation() == Some(&self.operation)
            {
                Ok(())
            } else {
                Err(McpError::with_data(
                    fastmcp_core::McpErrorCode::InvalidParams,
                    "private-execution-policy-canary",
                    serde_json::json!({"private": "execution-policy-data-canary"}),
                ))
            }
        }
    }

    fn execution_policy(
        runtime: &FinalTaskRuntime,
        metadata: &FinalTaskAccessMetadata,
    ) -> Arc<ExecutionPolicy> {
        let policy = Arc::new(ExecutionPolicy::new(
            metadata.authenticated_principal(),
            metadata.original_operation().unwrap().clone(),
        ));
        runtime.install_execution_authorizer(policy.clone()).unwrap();
        policy
    }

    fn assert_execution_denied<T>(result: McpResult<T>) {
        let Err(error) = result else {
            panic!("execution must require current authority")
        };
        assert_eq!(error.code, fastmcp_core::McpErrorCode::InvalidRequest);
        assert_eq!(error.message, "Task execution is no longer authorized");
        assert!(error.data.is_none());
    }

    #[test]
    fn execution_owner_lookup_survives_credential_refresh_without_granting_permission() {
        let authenticated = context(&["invoke", "sensitive"]).auth().unwrap();
        let principal = FinalTaskAccessMetadata::principal_for_auth(&authenticated).unwrap();
        let mut refreshed = authenticated.clone();
        refreshed.scopes = vec!["manage".to_owned()];
        refreshed = refreshed
            .with_verification_valid_until(Instant::now() + StdDuration::from_secs(60));
        assert_eq!(
            FinalTaskAccessMetadata::principal_for_auth(&refreshed).unwrap(),
            principal
        );
        let other_owner = refreshed.with_session_owner(Sha256Digest::from_bytes([18; 32]));
        assert_ne!(
            FinalTaskAccessMetadata::principal_for_auth(&other_owner).unwrap(),
            principal
        );
        let (_store, runtime, id, _registration) = fixture();
        assert_execution_denied(runtime.ensure_execution_policy_available(Some(principal)));
        assert!(runtime
            .admit_task_for_request(&context(&["manage"]), &id, TaskAccessAction::Get)
            .is_err());
    }

    #[test]
    fn execution_rechecks_current_grants_without_opening_payload_or_changing_state() {
        let (store, runtime, id, _registration) = fixture();
        let metadata = store.inner.get_task_access_metadata(&id).unwrap().unwrap();
        assert_execution_denied(runtime.authorize_task_execution(&metadata));
        let policy = execution_policy(&runtime, &metadata);
        assert!(runtime.revalidate_task_execution(&metadata).is_ok());
        assert_eq!(policy.calls.load(Ordering::SeqCst), 1);
        policy.revoked.store(true, Ordering::SeqCst);
        assert_execution_denied(runtime.revalidate_task_execution(&metadata));
        assert_eq!(policy.calls.load(Ordering::SeqCst), 2);
        assert_eq!(store.payload_reads.load(Ordering::SeqCst), 0);
        let after = store.inner.get_task_access_metadata(&id).unwrap().unwrap();
        assert_eq!(after.generation(), metadata.generation());
        assert_eq!(after.creation_generation(), metadata.creation_generation());
        assert!(!store.inner.is_cancellation_requested(&id).unwrap());
    }

    struct RemovingRegistrationPolicy(Mutex<Option<Arc<()>>>);

    impl TaskExecutionAuthorizer for RemovingRegistrationPolicy {
        fn authorize(&self, _: &FinalTaskAccessMetadata) -> McpResult<()> {
            drop(self.0.lock().unwrap().take());
            Ok(())
        }
    }

    #[test]
    fn execution_requires_original_registration_before_and_after_policy_callbacks() {
        for remove_during_callback in [false, true] {
            let (store, runtime, id, registration) = fixture();
            let metadata = store.inner.get_task_access_metadata(&id).unwrap().unwrap();
            let policy = execution_policy(&runtime, &metadata);
            runtime.revalidate_task_execution(&metadata).unwrap();
            if remove_during_callback {
                runtime
                    .install_execution_authorizer(Arc::new(RemovingRegistrationPolicy(
                        Mutex::new(Some(registration)),
                    )))
                    .unwrap();
            } else {
                drop(registration);
            }
            let replacement = Arc::new(());
            assert_ne!(
                metadata.original_operation(),
                Some(&FinalTaskOperation::for_tool("sensitive-tool", &replacement).unwrap())
            );
            assert_execution_denied(runtime.revalidate_task_execution(&metadata));
            assert_eq!(
                policy.calls.load(Ordering::SeqCst),
                if remove_during_callback { 2 } else { 1 }
            );
            assert_eq!(store.payload_reads.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn execution_metadata_requires_exact_generation_owner_operation_and_incarnation() {
        let (store, runtime, id, _registration) = fixture();
        let metadata = store.inner.get_task_access_metadata(&id).unwrap().unwrap();
        let policy = execution_policy(&runtime, &metadata);
        runtime.revalidate_task_execution(&metadata).unwrap();
        let replacement = Arc::new(());
        let replacement_operation =
            FinalTaskOperation::for_tool("sensitive-tool", &replacement).unwrap();
        for expected in [
            FinalTaskAccessMetadata::new(
                id.clone(),
                metadata.generation() + 1,
                metadata.creation_generation(),
                metadata.authenticated_principal(),
                metadata.original_operation().cloned(),
            ),
            FinalTaskAccessMetadata::new(
                id.clone(),
                metadata.generation(),
                metadata.creation_generation(),
                Some(Sha256Digest::from_bytes([99; 32])),
                metadata.original_operation().cloned(),
            ),
            FinalTaskAccessMetadata::new(
                id.clone(),
                metadata.generation(),
                metadata.creation_generation(),
                metadata.authenticated_principal(),
                Some(replacement_operation),
            ),
            FinalTaskAccessMetadata::new(
                id.clone(),
                metadata.generation(),
                metadata.creation_generation() + 1,
                metadata.authenticated_principal(),
                metadata.original_operation().cloned(),
            ),
        ] {
            assert_execution_denied(runtime.revalidate_task_execution(&expected));
        }
        for (generation, creation_generation) in [(0, 1), (1, 0), (1, 2)] {
            let invalid = FinalTaskAccessMetadata::new(
                id.clone(),
                generation,
                creation_generation,
                metadata.authenticated_principal(),
                metadata.original_operation().cloned(),
            );
            assert_execution_denied(runtime.authorize_task_execution(&invalid));
        }
        let unbound_protected = FinalTaskAccessMetadata::new(
            id.clone(),
            metadata.generation(),
            metadata.creation_generation(),
            metadata.authenticated_principal(),
            None,
        );
        assert_execution_denied(runtime.authorize_task_execution(&unbound_protected));
        assert_eq!(policy.calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.payload_reads.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn only_unbound_anonymous_execution_without_policies_can_skip_store_metadata() {
        let store = Arc::new(ProbeStore::new());
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, None).unwrap(),
            Arc::new(|_| {}),
        );
        let original = task("trusted-embedding");
        let id = original.base().task_id.clone();
        store
            .inner
            .create_task(original.clone(), final_task_notification(&original))
            .unwrap();
        let metadata = store.inner.get_task_access_metadata(&id).unwrap().unwrap();
        store.metadata_supported.store(false, Ordering::SeqCst);
        runtime.revalidate_task_execution(&metadata).unwrap();
        assert_eq!(store.metadata_reads.load(Ordering::SeqCst), 0);
        let registration = Arc::new(());
        let operation = FinalTaskOperation::for_tool("sensitive-tool", &registration).unwrap();
        let bound = FinalTaskAccessMetadata::new(
            id,
            metadata.generation(),
            metadata.creation_generation(),
            None,
            Some(operation.clone()),
        );
        assert_execution_denied(runtime.revalidate_task_execution(&bound));
        assert_eq!(store.metadata_reads.load(Ordering::SeqCst), 1);
        runtime
            .install_execution_authorizer(Arc::new(ExecutionPolicy::new(None, operation)))
            .unwrap();
        assert_execution_denied(runtime.revalidate_task_execution(&metadata));
        assert_eq!(store.metadata_reads.load(Ordering::SeqCst), 2);
        assert_eq!(store.payload_reads.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn cancellation_between_authorization_loss_probe_and_fenced_failure_wins() {
        for cancellation_races in [false, true] {
            let (store, runtime, id, _registration) = fixture();
            let current = store.inner.get_task_snapshot(&id).unwrap().unwrap();
            let owner = "authorization-retirement-race";
            let _claim = store
                .inner
                .take_initial_work_handoff_for_owner_if_current(&current, owner)
                .unwrap()
                .unwrap();
            let fence = store
                .inner
                .begin_handoff_dispatch_for_owner_if_current(&id, current.generation(), owner)
                .unwrap()
                .unwrap();
            let metadata = store.inner.get_task_access_metadata(&id).unwrap().unwrap();
            let policy = execution_policy(&runtime, &metadata);
            runtime.revalidate_task_execution(&metadata).unwrap();
            policy.revoked.store(true, Ordering::SeqCst);
            assert_execution_denied(runtime.revalidate_task_execution(&metadata));
            store
                .cancel_before_execution_failure
                .store(cancellation_races, Ordering::SeqCst);
            assert!(runtime
                .retire_unauthorized_handoff(&metadata, owner, fence)
                .unwrap());
            let retired = store.inner.get_task_snapshot(&id).unwrap().unwrap();
            let expected_status = if cancellation_races {
                FinalTaskStatus::Cancelled
            } else {
                FinalTaskStatus::Failed
            };
            assert_eq!(retired.task().base().status, expected_status);
            assert_eq!(
                store.inner.latest_notification(&id).unwrap().params.task.base().status,
                expected_status
            );
            assert_eq!(
                store.injected_execution_cancellations.load(Ordering::SeqCst),
                usize::from(cancellation_races)
            );
            assert!(!runtime
                .retire_unauthorized_handoff(&metadata, owner, fence)
                .unwrap());
            assert!(runtime
                .fenced_complete_task(
                    &id,
                    metadata.generation(),
                    owner,
                    fence,
                    completed_execution_result(),
                    None,
                )
                .is_err());
            let after = store.inner.get_task_snapshot(&id).unwrap().unwrap();
            assert_eq!(after.generation(), retired.generation());
            assert!(final_tasks_match_exactly(after.task(), retired.task()).unwrap());
        }
    }

    #[test]
    fn every_management_action_rechecks_complete_original_and_method_grants_before_payload() {
        let (store, runtime, id, _registration) = fixture();
        let allowed = context(&["invoke", "manage", "sensitive"]);
        let before = store.inner.get_task_snapshot(&id).unwrap().unwrap();
        for action in [
            TaskAccessAction::Get,
            TaskAccessAction::Update,
            TaskAccessAction::Cancel,
            TaskAccessAction::Listen,
        ] {
            assert!(runtime.task_for_request(&allowed, &id, action).is_ok());
            for grants in [
                &["manage", "sensitive"][..],
                &["invoke", "manage"][..],
                &["invoke", "sensitive"][..],
            ] {
                let reads = store.payload_reads.load(Ordering::SeqCst);
                let error = runtime
                    .task_for_request(&context(grants), &id, action)
                    .unwrap_err();
                assert_eq!(error.message, "Task not found");
                assert_eq!(store.payload_reads.load(Ordering::SeqCst), reads);
                assert_eq!(
                    store
                        .inner
                        .get_task_snapshot(&id)
                        .unwrap()
                        .unwrap()
                        .generation(),
                    before.generation()
                );
            }
        }
    }

    #[test]
    fn wire_get_update_cancel_share_non_oracular_scope_loss_and_no_mutation() {
        let (store, runtime, id, _registration) = fixture();
        let caller = context(&["manage"]);
        let missing = FinalTaskId::parse("missing-task").unwrap();
        for selected in [&id, &missing] {
            let get =
                dispatch_final_tasks_get(&runtime, &caller, parameters(selected)).unwrap_err();
            let mut update = parameters(selected);
            update["inputResponses"] = serde_json::json!({});
            let update = dispatch_final_tasks_update(&runtime, &caller, update).unwrap_err();
            let cancel =
                dispatch_final_tasks_cancel(&runtime, &caller, parameters(selected)).unwrap_err();
            for error in [get, update, cancel] {
                assert_eq!(error.code, task_access_denied().code);
                assert_eq!(error.message, "Task not found");
                assert!(error.data.is_none());
            }
        }
        assert_eq!(store.payload_reads.load(Ordering::SeqCst), 0);
        assert!(!store.inner.is_cancellation_requested(&id).unwrap());
    }

    #[test]
    fn disabled_or_replaced_original_registration_denies_even_same_name_and_owner() {
        let (store, runtime, id, registration) = fixture();
        let caller = context(&["invoke", "manage", "sensitive"]);
        assert!(
            runtime
                .admit_task_for_request(&caller, &id, TaskAccessAction::Get)
                .is_ok()
        );
        assert!(caller.disable_tool("sensitive-tool"));
        assert!(
            runtime
                .task_for_request(&caller, &id, TaskAccessAction::Get)
                .is_err()
        );
        let refreshed = context(&["invoke", "manage", "sensitive"]);
        drop(registration);
        let replacement = Arc::new(());
        assert!(
            FinalTaskOperation::for_tool("sensitive-tool", &replacement)
                .unwrap()
                .is_visible(&refreshed)
        );
        assert!(
            runtime
                .task_for_request(&refreshed, &id, TaskAccessAction::Get)
                .is_err()
        );
        assert_eq!(store.payload_reads.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn task_binding_cannot_be_stripped_by_a_custom_snapshot() {
        let (store, runtime, id, _registration) = fixture();
        let caller = context(&["invoke", "manage", "sensitive"]);
        assert!(
            runtime
                .task_for_request(&caller, &id, TaskAccessAction::Get)
                .is_ok()
        );
        store.strip_operation.store(true, Ordering::SeqCst);
        let error = runtime
            .task_for_request(&caller, &id, TaskAccessAction::Get)
            .unwrap_err();
        assert_eq!(error.message, "Task not found");
        assert!(
            store
                .inner
                .get_task_snapshot(&id)
                .unwrap()
                .unwrap()
                .original_operation()
                .is_some()
        );
    }

    #[test]
    fn metadata_contract_is_required_without_disabling_trusted_embedding_reads() {
        let (store, runtime, id, _registration) = fixture();
        store.metadata_supported.store(false, Ordering::SeqCst);
        assert!(
            runtime
                .task_for_request(
                    &context(&["invoke", "manage", "sensitive"]),
                    &id,
                    TaskAccessAction::Get
                )
                .is_err()
        );
        assert_eq!(store.payload_reads.load(Ordering::SeqCst), 0);
        assert!(runtime.get_task(&id).is_ok());
    }

    struct RevocablePolicy(AtomicBool);
    impl TaskAccessAuthorizer for RevocablePolicy {
        fn authorize(
            &self,
            _: &McpContext,
            _: TaskAccessAction,
            _: &FinalTaskOperation,
        ) -> McpResult<()> {
            if self.0.load(Ordering::SeqCst) {
                Err(McpError::invalid_params("private-policy-canary"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn subscription_admission_and_events_revalidate_revocation_and_refreshed_scopes() {
        let (store, runtime, id, _registration) = fixture();
        let caller = context(&["invoke", "manage", "sensitive"]);
        let policy = Arc::new(RevocablePolicy(AtomicBool::new(false)));
        runtime.install_access_authorizer(policy.clone()).unwrap();
        let admitted = runtime
            .admit_task_for_request(&caller, &id, TaskAccessAction::Listen)
            .unwrap();
        let event = store.inner.latest_notification(&id).unwrap();
        assert!(
            runtime
                .notification_matches_task_access(&caller, &admitted, &event)
                .unwrap()
        );
        let admitted_payload_reads = store.payload_reads.load(Ordering::SeqCst);
        let narrowed = context(&["manage"]);
        assert!(
            runtime
                .notification_matches_task_access(&narrowed, &admitted, &event)
                .is_err()
        );
        policy.0.store(true, Ordering::SeqCst);
        assert!(!runtime.task_access_is_current(&caller, &admitted));
        assert!(
            runtime
                .notification_matches_task_access(&caller, &admitted, &event)
                .is_err()
        );
        assert_eq!(
            store.payload_reads.load(Ordering::SeqCst),
            admitted_payload_reads
        );
    }

    #[test]
    fn expired_verification_receipts_deny_all_access_before_metadata_or_payload() {
        let (store, runtime, id, registration) = fixture();
        let caller = context(&["invoke", "manage", "sensitive"]);
        let fresh = McpContext::new(Cx::for_testing(), 2).with_auth(
            caller
                .auth()
                .unwrap()
                .with_verification_valid_until(Instant::now() + StdDuration::from_secs(60)),
        );
        let admitted = runtime
            .admit_task_for_request(&fresh, &id, TaskAccessAction::Listen)
            .unwrap();
        let event = store.inner.latest_notification(&id).unwrap();
        assert!(
            runtime
                .notification_matches_task_access(&fresh, &admitted, &event)
                .unwrap()
        );
        let reads = store.payload_reads.load(Ordering::SeqCst);
        let metadata_reads = store.metadata_reads.load(Ordering::SeqCst);
        let expired = McpContext::new(Cx::for_testing(), 3).with_auth(
            caller
                .auth()
                .unwrap()
                .with_verification_valid_until(Instant::now() - StdDuration::from_secs(1)),
        );
        for action in [
            TaskAccessAction::Get,
            TaskAccessAction::Update,
            TaskAccessAction::Cancel,
            TaskAccessAction::Listen,
        ] {
            assert_eq!(
                runtime
                    .task_for_request(&expired, &id, action)
                    .unwrap_err()
                    .message,
                "Task not found"
            );
        }
        let operation = FinalTaskOperation::for_tool("sensitive-tool", &registration).unwrap();
        assert_eq!(
            runtime
                .create_task_for_operation(&expired, operation, work(), None)
                .unwrap_err()
                .message,
            "Task not found"
        );
        assert!(
            runtime
                .notification_matches_task_access(&expired, &admitted, &event)
                .is_err()
        );
        assert!(!runtime.task_access_is_current(&expired, &admitted));
        assert_eq!(store.payload_reads.load(Ordering::SeqCst), reads);
        assert_eq!(store.metadata_reads.load(Ordering::SeqCst), metadata_reads);
        assert_eq!(store.inner.task_count(), 1);
    }

    #[test]
    fn same_owner_same_operation_recreated_id_cannot_inherit_a_subscription() {
        let now = Arc::new(Mutex::new(Instant::now()));
        let clock = Arc::clone(&now);
        let store = Arc::new(
            InMemoryFinalTaskStore::with_clock(4, Arc::new(move || *clock.lock().unwrap()))
                .unwrap(),
        );
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, None).unwrap(),
            Arc::new(|_| {}),
        );
        runtime
            .install_access_authorizer(Arc::new(policy()))
            .unwrap();
        let registration = Arc::new(());
        let operation = FinalTaskOperation::for_tool("sensitive-tool", &registration).unwrap();
        let caller = context(&["invoke", "manage", "sensitive"]);
        let original = task("reused-same-owner-id");
        let id = &original.base().task_id;
        let principal = task_request_principal(&caller).unwrap();
        store
            .create_task_with_operation(
                original.clone(),
                final_task_notification(&original),
                work(),
                principal,
                operation.clone(),
            )
            .unwrap();
        let admitted = runtime
            .admit_task_for_request(&caller, id, TaskAccessAction::Listen)
            .unwrap();
        execution_policy(&runtime, &admitted);
        runtime.revalidate_task_execution(&admitted).unwrap();
        runtime.complete_task(id, serde_json::from_value(serde_json::json!({"content":[{"type":"text","text":"old-incarnation-result"}]})).unwrap(), None).unwrap();
        let stale_event = store.latest_notification(id).unwrap();
        *now.lock().unwrap() += StdDuration::from_secs(61);
        // Deliberately reuse the exact wire task, owner, tool registration,
        // and operation object. Only the atomic insert incarnation changes.
        store
            .create_task_with_operation(
                original.clone(),
                final_task_notification(&original),
                work(),
                principal,
                operation,
            )
            .unwrap();
        let current = runtime
            .admit_task_for_request(&caller, id, TaskAccessAction::Listen)
            .unwrap();
        assert_ne!(
            current.creation_generation(),
            admitted.creation_generation()
        );
        assert_execution_denied(runtime.revalidate_task_execution(&admitted));
        runtime.revalidate_task_execution(&current).unwrap();
        let event = store.latest_notification(id).unwrap();
        assert!(
            runtime
                .notification_matches_task_access(&caller, &admitted, &event)
                .is_err()
        );
        assert!(
            !runtime
                .notification_matches_task_access(&caller, &current, &stale_event)
                .unwrap()
        );
        assert!(
            runtime
                .notification_matches_task_access(&caller, &current, &event)
                .unwrap()
        );
        dispatch_final_tasks_cancel(&runtime, &caller, parameters(id)).unwrap();
        let cancelled = store.get_task_snapshot(id).unwrap().unwrap();
        assert!(matches!(cancelled.task(), FinalTask::Cancelled(_)));
        assert_eq!(
            cancelled.creation_generation(),
            current.creation_generation()
        );
    }

    #[test]
    fn application_observer_cannot_publish_an_old_incarnation_with_identical_wire_payload() {
        let now = Arc::new(Mutex::new(Instant::now()));
        let clock = Arc::clone(&now);
        let store = Arc::new(
            InMemoryFinalTaskStore::with_clock(4, Arc::new(move || *clock.lock().unwrap()))
                .unwrap(),
        );
        let registration = Arc::new(());
        let operation = FinalTaskOperation::for_tool("sensitive-tool", &registration).unwrap();
        let original = task("identical-wire-reincarnation");
        let principal =
            task_request_principal(&context(&["invoke", "manage", "sensitive"])).unwrap();
        let committed = store
            .create_task_with_operation(
                original.clone(),
                final_task_notification(&original),
                work(),
                principal,
                operation.clone(),
            )
            .unwrap();
        let observer_store = Arc::clone(&store);
        let observer_task = original.clone();
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, None).unwrap(),
            Arc::new(move |_| {
                *now.lock().unwrap() += StdDuration::from_secs(61);
                observer_store
                    .create_task_with_operation(
                        observer_task.clone(),
                        final_task_notification(&observer_task),
                        work(),
                        principal,
                        operation.clone(),
                    )
                    .unwrap();
            }),
        );
        let deliveries = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&deliveries);
        let _observer = runtime.add_owned_notification_emitter(Arc::new(move |_, _| {
            count.fetch_add(1, Ordering::SeqCst);
        }));
        runtime.emit_committed(final_task_notification(&original), &committed);
        let current = store
            .get_task_snapshot(&original.base().task_id)
            .unwrap()
            .unwrap();
        assert!(final_tasks_match_exactly(current.task(), committed.task()).unwrap());
        assert_eq!(
            current.authenticated_principal(),
            committed.authenticated_principal()
        );
        assert_eq!(current.original_operation(), committed.original_operation());
        assert_ne!(
            current.creation_generation(),
            committed.creation_generation()
        );
        assert_eq!(deliveries.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn task_listener_requires_caller_timer_and_drops_stale_events_without_cancellation() {
        let (store, runtime, id, _registration) = fixture();
        let caller = context(&["invoke", "manage", "sensitive"]);
        let server = Arc::new(
            crate::Server::new("task-listener-authority", "1.0")
                .final_tasks(runtime.clone())
                .unwrap()
                .build(),
        );
        let mut notifications = fastmcp_protocol::SubscriptionFilter::default();
        fastmcp_protocol::set_task_subscription_ids(&mut notifications, vec![id.clone()]).unwrap();
        let request = fastmcp_protocol::JsonRpcRequest::new(
            "subscriptions/listen",
            Some(serde_json::json!({
                "_meta": parameters(&id)["_meta"], "notifications": notifications,
            })),
            71_i64,
        );
        let deliveries = Arc::new(AtomicUsize::new(0));
        let cancellation = fastmcp_core::McpRequestCancellation::new();
        let count = Arc::clone(&deliveries);
        let sender: crate::NotificationSender = Arc::new(move |_| {
            count.fetch_add(1, Ordering::SeqCst);
        });
        let mut poll = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(caller.cx().timer_driver().is_none());
        let mut refused = Box::pin(server.dispatch_final_subscriptions_listen(
            &caller,
            &request,
            None,
            cancellation.clone(),
            None,
            sender.clone(),
        ));
        assert!(matches!(
            refused.as_mut().poll(&mut poll),
            std::task::Poll::Ready(Err(_))
        ));
        assert_eq!(deliveries.load(Ordering::SeqCst), 0);
        drop(refused);
        let clock = Arc::new(asupersync::time::VirtualClock::new());
        let executor = asupersync::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(asupersync::time::TimerDriverHandle::with_virtual_clock(
                clock,
            ))
            .build()
            .unwrap();
        let ctx = McpContext::new(
            executor.request_cx_with_budget(asupersync::Budget::INFINITE),
            72,
        )
        .with_auth(caller.auth().unwrap());
        let mut listening = Box::pin(server.dispatch_final_subscriptions_listen(
            &ctx,
            &request,
            None,
            cancellation.clone(),
            None,
            sender,
        ));
        assert!(listening.as_mut().poll(&mut poll).is_pending());
        let acknowledged = deliveries.load(Ordering::SeqCst);
        assert_eq!(acknowledged, 1);
        let old_event = store.inner.latest_notification(&id).unwrap();
        let current = store.inner.get_task_snapshot(&id).unwrap().unwrap();
        let mut changed = current.task().clone();
        if let FinalTask::Working(base) = &mut changed {
            base.status_message = Some("later progress".to_owned());
        }
        store
            .inner
            .replace_task(changed.clone(), final_task_notification(&changed))
            .unwrap();
        let principal = task_request_principal(&ctx).unwrap();
        server
            .final_subscriptions
            .publish_owned_task(old_event, principal)
            .unwrap();
        assert_eq!(deliveries.load(Ordering::SeqCst), acknowledged);
        assert!(!cancellation.is_cancel_requested());
        let latest = store.inner.latest_notification(&id).unwrap();
        server
            .final_subscriptions
            .publish_owned_task(latest.clone(), principal)
            .unwrap();
        assert_eq!(deliveries.load(Ordering::SeqCst), acknowledged + 1);
        assert!(!cancellation.is_cancel_requested());
        runtime
            .install_access_authorizer(Arc::new(RevocablePolicy(AtomicBool::new(true))))
            .unwrap();
        server
            .final_subscriptions
            .publish_owned_task(latest, principal)
            .unwrap();
        assert_eq!(deliveries.load(Ordering::SeqCst), acknowledged + 1);
        assert!(cancellation.is_cancel_requested());
        drop(listening);
        executor.shutdown_timeout(StdDuration::from_secs(2));
    }

    #[test]
    fn public_operation_policy_installation_covers_retained_tasks_without_duplicate_policy_setup() {
        for through_method_policy in [false, true] {
            let store = Arc::new(InMemoryFinalTaskStore::default());
            let runtime = FinalTaskRuntime::new(
                store.clone(),
                FinalTaskRuntimeConfig::new(60_000, None).unwrap(),
                Arc::new(|_| {}),
            );
            let server = crate::Server::new("task-access", "1.0")
                .final_tasks(runtime.clone())
                .unwrap()
                .build();
            let _server = if through_method_policy {
                server
                    .with_scope_authorization(ScopeRequestPolicy::for_operations(policy()).unwrap())
                    .unwrap()
            } else {
                server.with_operation_scope_authorization(policy()).unwrap()
            };
            let registration = Arc::new(());
            let operation = FinalTaskOperation::for_tool("sensitive-tool", &registration).unwrap();
            let original = task("installed-policy");
            let id = &original.base().task_id;
            let owner = context(&["invoke", "manage", "sensitive"]);
            store
                .create_task_with_operation(
                    original.clone(),
                    final_task_notification(&original),
                    work(),
                    task_request_principal(&owner).unwrap(),
                    operation,
                )
                .unwrap();
            assert!(dispatch_final_tasks_get(&runtime, &owner, parameters(id)).is_ok());
            assert_eq!(
                dispatch_final_tasks_get(&runtime, &context(&["manage"]), parameters(id))
                    .unwrap_err()
                    .message,
                "Task not found"
            );
        }
    }

    struct PanickingPolicy;
    impl TaskAccessAuthorizer for PanickingPolicy {
        fn authorize(
            &self,
            _: &McpContext,
            _: TaskAccessAction,
            _: &FinalTaskOperation,
        ) -> McpResult<()> {
            panic!("private-policy-canary")
        }
    }

    #[test]
    fn authorizer_panic_and_caller_cancellation_do_not_open_task_payload() {
        let (store, runtime, id, _registration) = fixture();
        runtime
            .install_access_authorizer(Arc::new(PanickingPolicy))
            .unwrap();
        let caller = context(&["invoke", "manage", "sensitive"]);
        let error = runtime
            .task_for_request(&caller, &id, TaskAccessAction::Get)
            .unwrap_err();
        assert_eq!(error.message, "Task not found");
        caller
            .cx()
            .cancel_with(asupersync::CancelKind::User, Some("test cancellation"));
        assert!(
            runtime
                .task_for_request(&caller, &id, TaskAccessAction::Get)
                .is_err()
        );
        assert_eq!(store.payload_reads.load(Ordering::SeqCst), 0);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn pending_subscription_read_keeps_one_future_and_rechecks_at_the_caller_timer() {
        let (_store, runtime, id, _registration) = fixture();
        let clock = Arc::new(asupersync::time::VirtualClock::new());
        let executor = asupersync::runtime::RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(asupersync::time::TimerDriverHandle::with_virtual_clock(
                clock.clone(),
            ))
            .build()
            .unwrap();
        let cx = executor.request_cx_with_budget(asupersync::Budget::INFINITE);
        let ctx = McpContext::new(cx.clone(), 1)
            .with_auth(context(&["invoke", "manage", "sensitive"]).auth().unwrap());
        let policy = Arc::new(RevocablePolicy(AtomicBool::new(false)));
        runtime.install_access_authorizer(policy.clone()).unwrap();
        let admitted = BTreeMap::from([(
            id.clone(),
            runtime
                .admit_task_for_request(&ctx, &id, TaskAccessAction::Listen)
                .unwrap(),
        )]);
        let polls = AtomicUsize::new(0);
        let read = std::future::poll_fn(|_| {
            polls.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::<McpResult<()>>::Pending
        });
        let cancellation = fastmcp_core::McpRequestCancellation::new();
        let mut guarded = Box::pin(runtime.guard_task_subscription_operation(
            &cx,
            &ctx,
            &admitted,
            &cancellation,
            read,
        ));
        let mut poll = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(guarded.as_mut().poll(&mut poll).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        clock.advance_to(asupersync::Time::from_nanos(1_000_000_000));
        assert!(guarded.as_mut().poll(&mut poll).is_pending());
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        policy.0.store(true, Ordering::SeqCst);
        clock.advance_to(asupersync::Time::from_nanos(2_000_000_000));
        assert!(matches!(
            guarded.as_mut().poll(&mut poll),
            std::task::Poll::Ready(Err(_))
        ));
        assert_eq!(
            polls.load(Ordering::SeqCst),
            2,
            "revocation stops the pending read before another poll"
        );
        drop(guarded);
        assert!(executor.shutdown_timeout(StdDuration::from_secs(2)));
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn subscription_guard_refuses_missing_caller_timer_before_polling_the_read() {
        let (_store, runtime, _, _registration) = fixture();
        let cx = Cx::for_testing();
        let ctx = McpContext::new(cx.clone(), 1);
        let cancellation = fastmcp_core::McpRequestCancellation::new();
        let admitted = BTreeMap::new();
        let polls = AtomicUsize::new(0);
        let read = std::future::poll_fn(|_| {
            polls.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::Ready(Ok(()))
        });
        let mut guarded = Box::pin(runtime.guard_task_subscription_operation(
            &cx,
            &ctx,
            &admitted,
            &cancellation,
            read,
        ));
        assert!(matches!(
            guarded
                .as_mut()
                .poll(&mut std::task::Context::from_waker(std::task::Waker::noop())),
            std::task::Poll::Ready(Err(_))
        ));
        assert_eq!(polls.load(Ordering::SeqCst), 0);
    }

    struct IdleSupervisor;
    impl ApplicationTaskSupervisor for IdleSupervisor {
        fn resume<'a>(
            &'a self,
            _: &'a Cx,
            _: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            Box::pin(async { Ok(()) })
        }
    }

    struct ExecutionFixture {
        store: Arc<InMemoryFinalTaskStore>,
        runtime: FinalTaskRuntime,
        caller: McpContext,
        registration: Option<Arc<()>>,
        operation: FinalTaskOperation,
        policy: Arc<ExecutionPolicy>,
    }

    impl ExecutionFixture {
        fn new() -> Self {
            let store = Arc::new(InMemoryFinalTaskStore::default());
            let runtime = FinalTaskRuntime::new(
                store.clone(),
                FinalTaskRuntimeConfig::new(60_000, None).unwrap(),
                Arc::new(|_| {}),
            );
            let caller = context(&["invoke", "manage", "sensitive"]);
            let registration = Arc::new(());
            let operation = FinalTaskOperation::for_tool("sensitive-tool", &registration).unwrap();
            let execution = Arc::new(ExecutionPolicy::new(
                task_request_principal(&caller).unwrap(),
                operation.clone(),
            ));
            runtime
                .install_task_authorizers(vec![Arc::new(policy())], vec![execution.clone()])
                .unwrap();
            Self {
                store,
                runtime,
                caller,
                registration: Some(registration),
                operation,
                policy: execution,
            }
        }

        fn create(&self) -> FinalTaskId {
            self.runtime
                .create_task_for_operation(
                    &self.caller,
                    self.operation.clone(),
                    work(),
                    None,
                )
                .unwrap()
                .task
                .base()
                .task_id
                .clone()
        }

        fn status(&self, id: &FinalTaskId) -> FinalTaskStatus {
            self.store.get_task(id).unwrap().unwrap().base().status
        }
    }

    fn poll_service(
        cx: &Cx,
        service: std::pin::Pin<&mut impl Future<Output = McpResult<()>>>,
    ) -> std::task::Poll<McpResult<()>> {
        let _current = Cx::set_current(Some(cx.clone()));
        service.poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    }

    fn completed_execution_result() -> FinalTaskCallToolResult {
        serde_json::from_value(serde_json::json!({
            "content": [{"type": "text", "text": "authorized execution completed"}]
        }))
        .unwrap()
    }

    struct InputExecutionSupervisor {
        initial: AtomicUsize,
        resumed: AtomicUsize,
    }

    impl ApplicationTaskSupervisor for InputExecutionSupervisor {
        fn resume<'a>(
            &'a self,
            _: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            Box::pin(async move {
                match handoff {
                    FinalTaskSupervisorHandoff::Initial(initial) => {
                        self.initial.fetch_add(1, Ordering::SeqCst);
                        initial.require_input(
                            serde_json::from_value(serde_json::json!({
                                "roots": {"method": "roots/list"}
                            }))
                            .unwrap(),
                            None,
                        )?;
                    }
                    FinalTaskSupervisorHandoff::Resumed(accepted) => {
                        self.resumed.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(accepted.input_responses().len(), 1);
                        accepted.complete_task(completed_execution_result(), None)?;
                    }
                }
                Ok(())
            })
        }
    }

    #[test]
    fn authorized_execution_service_runs_initial_and_resumed_work() {
        let fixture = ExecutionFixture::new();
        let supervisor = Arc::new(InputExecutionSupervisor {
            initial: AtomicUsize::new(0),
            resumed: AtomicUsize::new(0),
        });
        let mut runner = fixture
            .runtime
            .install_task_service(8, supervisor.clone())
            .unwrap();
        let cx = Cx::for_testing();
        let mut service = Box::pin(runner.run_service(&cx));
        assert!(poll_service(&cx, service.as_mut()).is_pending());
        let id = fixture.create();
        assert!(poll_service(&cx, service.as_mut()).is_pending());
        assert_eq!(fixture.status(&id), FinalTaskStatus::InputRequired);
        assert_eq!(supervisor.initial.load(Ordering::SeqCst), 1);
        assert_eq!(supervisor.resumed.load(Ordering::SeqCst), 0);
        let mut update = parameters(&id);
        update["inputResponses"] = serde_json::json!({"roots": {"roots": []}});
        dispatch_final_tasks_update(&fixture.runtime, &fixture.caller, update).unwrap();
        assert!(poll_service(&cx, service.as_mut()).is_pending());
        assert_eq!(fixture.status(&id), FinalTaskStatus::Completed);
        assert_eq!(supervisor.initial.load(Ordering::SeqCst), 1);
        assert_eq!(supervisor.resumed.load(Ordering::SeqCst), 1);
        assert!(fixture.policy.calls.load(Ordering::SeqCst) >= 4);
        assert!(dispatch_final_tasks_get(
            &fixture.runtime,
            &fixture.caller,
            parameters(&id)
        )
        .is_ok());
        assert!(fixture.runtime.is_task_service_ready());
    }

    struct CompletingExecutionSupervisor(AtomicUsize);

    impl ApplicationTaskSupervisor for CompletingExecutionSupervisor {
        fn resume<'a>(
            &'a self,
            _: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                match handoff {
                    FinalTaskSupervisorHandoff::Initial(initial) => {
                        initial.complete_task(completed_execution_result(), None)?;
                    }
                    FinalTaskSupervisorHandoff::Resumed(accepted) => {
                        accepted.complete_task(completed_execution_result(), None)?;
                    }
                }
                Ok(())
            })
        }
    }

    #[test]
    fn pre_dispatch_execution_revocation_never_invokes_supervisor() {
        for remove_registration in [false, true] {
            let mut fixture = ExecutionFixture::new();
            let supervisor = Arc::new(CompletingExecutionSupervisor(AtomicUsize::new(0)));
            let mut runner = fixture
                .runtime
                .install_task_service(8, supervisor.clone())
                .unwrap();
            let cx = Cx::for_testing();
            let mut service = Box::pin(runner.run_service(&cx));
            assert!(poll_service(&cx, service.as_mut()).is_pending());
            let id = fixture.create();
            if remove_registration {
                drop(fixture.registration.take());
            } else {
                fixture.policy.revoked.store(true, Ordering::SeqCst);
            }
            assert!(poll_service(&cx, service.as_mut()).is_pending());
            assert_eq!(supervisor.0.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.status(&id), FinalTaskStatus::Failed);
            let task = fixture.store.get_task(&id).unwrap().unwrap();
            let encoded = serde_json::to_string(&task).unwrap();
            assert!(!encoded.contains("application-canary"));
            assert!(!encoded.contains("private-execution-policy-canary"));
            assert!(!encoded.contains("execution-policy-data-canary"));
            assert!(fixture.runtime.is_task_service_ready());
        }
    }

    struct PendingExecutionSupervisor {
        calls: AtomicUsize,
        polls: AtomicUsize,
        handoff: Mutex<Option<FinalTaskSupervisorHandoff>>,
    }

    impl ApplicationTaskSupervisor for PendingExecutionSupervisor {
        fn resume<'a>(
            &'a self,
            _: &'a Cx,
            handoff: FinalTaskSupervisorHandoff,
        ) -> FinalTaskSupervisorFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.handoff.lock().unwrap() = Some(handoff);
            Box::pin(std::future::poll_fn(move |_| {
                self.polls.fetch_add(1, Ordering::SeqCst);
                std::task::Poll::Pending
            }))
        }
    }

    #[test]
    fn pending_execution_revocation_stops_polling_and_invalidates_retained_handoff() {
        for drop_without_polling in [false, true] {
            let fixture = ExecutionFixture::new();
            let supervisor = Arc::new(PendingExecutionSupervisor {
                calls: AtomicUsize::new(0),
                polls: AtomicUsize::new(0),
                handoff: Mutex::new(None),
            });
            let mut runner = fixture
                .runtime
                .install_task_service(8, supervisor.clone())
                .unwrap();
            let cx = Cx::for_testing();
            let mut service = Box::pin(runner.run_service(&cx));
            assert!(poll_service(&cx, service.as_mut()).is_pending());
            let id = fixture.create();
            assert!(poll_service(&cx, service.as_mut()).is_pending());
            assert_eq!(supervisor.calls.load(Ordering::SeqCst), 1);
            assert_eq!(supervisor.polls.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.status(&id), FinalTaskStatus::Working);
            fixture.policy.revoked.store(true, Ordering::SeqCst);
            if !drop_without_polling {
                assert!(poll_service(&cx, service.as_mut()).is_pending());
                assert!(fixture.runtime.is_task_service_ready());
            }
            drop(service);
            assert_eq!(fixture.status(&id), FinalTaskStatus::Failed);
            assert_eq!(supervisor.polls.load(Ordering::SeqCst), 1);
            let retired = fixture.store.get_task_snapshot(&id).unwrap().unwrap();
            // A later grant cannot resurrect the old handed-out authority.
            fixture.policy.revoked.store(false, Ordering::SeqCst);
            let handoff = supervisor.handoff.lock().unwrap().take().unwrap();
            let late = match handoff {
                FinalTaskSupervisorHandoff::Initial(initial) => {
                    initial.complete_task(completed_execution_result(), None)
                }
                FinalTaskSupervisorHandoff::Resumed(accepted) => {
                    accepted.complete_task(completed_execution_result(), None)
                }
            };
            assert_execution_denied(late);
            let after = fixture.store.get_task_snapshot(&id).unwrap().unwrap();
            assert_eq!(after.generation(), retired.generation());
            assert!(final_tasks_match_exactly(after.task(), retired.task()).unwrap());
        }
    }

    struct SelectiveExecutionPolicy {
        refused: Mutex<Option<FinalTaskId>>,
        panic_on_refusal: bool,
    }

    impl TaskExecutionAuthorizer for SelectiveExecutionPolicy {
        fn authorize(&self, metadata: &FinalTaskAccessMetadata) -> McpResult<()> {
            if self.refused.lock().unwrap().as_ref() != Some(metadata.task_id()) {
                return Ok(());
            }
            assert!(!self.panic_on_refusal, "private-execution-panic-canary");
            Err(McpError::invalid_request("private-execution-error-canary"))
        }
    }

    #[test]
    fn per_task_execution_policy_error_and_panic_leave_sibling_service_live() {
        for panic_on_refusal in [false, true] {
            let fixture = ExecutionFixture::new();
            let selective = Arc::new(SelectiveExecutionPolicy {
                refused: Mutex::new(None),
                panic_on_refusal,
            });
            fixture
                .runtime
                .install_execution_authorizer(selective.clone())
                .unwrap();
            let supervisor = Arc::new(CompletingExecutionSupervisor(AtomicUsize::new(0)));
            let mut runner = fixture
                .runtime
                .install_task_service(8, supervisor.clone())
                .unwrap();
            let cx = Cx::for_testing();
            let mut service = Box::pin(runner.run_service(&cx));
            assert!(poll_service(&cx, service.as_mut()).is_pending());
            let refused = fixture.create();
            let sibling = fixture.create();
            *selective.refused.lock().unwrap() = Some(refused.clone());
            assert!(poll_service(&cx, service.as_mut()).is_pending());
            assert_eq!(fixture.status(&refused), FinalTaskStatus::Failed);
            assert_eq!(fixture.status(&sibling), FinalTaskStatus::Completed);
            assert_eq!(supervisor.0.load(Ordering::SeqCst), 1);
            let encoded =
                serde_json::to_string(&fixture.store.get_task(&refused).unwrap().unwrap()).unwrap();
            assert!(!encoded.contains("private-execution-error-canary"));
            assert!(!encoded.contains("private-execution-panic-canary"));
            assert!(fixture.runtime.is_task_service_ready());
            let later = fixture.create();
            assert!(poll_service(&cx, service.as_mut()).is_pending());
            assert_eq!(fixture.status(&later), FinalTaskStatus::Completed);
            assert_eq!(supervisor.0.load(Ordering::SeqCst), 2);
        }
    }

    #[test]
    fn refused_builder_policy_batch_leaves_shared_runtime_authority_and_service_unchanged() {
        let (_store, runtime, id, _registration) = fixture();
        for _ in 1..15 {
            runtime
                .install_access_authorizer(Arc::new(RevocablePolicy(AtomicBool::new(false))))
                .unwrap();
        }
        let rejected = crate::Server::new("atomic-task-policies", "1.0")
            .final_tasks(runtime.clone())
            .unwrap()
            .task_supervisor(Arc::new(IdleSupervisor))
            .task_access_authorizer(Arc::new(RevocablePolicy(AtomicBool::new(true))))
            .task_access_authorizer(Arc::new(RevocablePolicy(AtomicBool::new(true))))
            .try_build();
        assert!(rejected.is_err());
        assert!(!runtime.has_installed_task_service());
        assert!(
            dispatch_final_tasks_get(
                &runtime,
                &context(&["invoke", "manage", "sensitive"]),
                parameters(&id)
            )
            .is_ok()
        );
        let _runner = runtime
            .install_task_service(1, Arc::new(IdleSupervisor))
            .unwrap();
        let rejected = crate::Server::new("conflicting-task-service", "1.0")
            .final_tasks(runtime.clone())
            .unwrap()
            .task_supervisor(Arc::new(IdleSupervisor))
            .task_access_authorizer(Arc::new(RevocablePolicy(AtomicBool::new(true))))
            .try_build();
        assert!(rejected.is_err());
        assert!(runtime.has_installed_task_service());
        assert!(
            dispatch_final_tasks_get(
                &runtime,
                &context(&["invoke", "manage", "sensitive"]),
                parameters(&id)
            )
            .is_ok()
        );
    }

    #[test]
    fn protected_creation_requires_policy_and_atomically_retains_original_operation() {
        let store = Arc::new(InMemoryFinalTaskStore::default());
        let runtime = FinalTaskRuntime::new(
            store.clone(),
            FinalTaskRuntimeConfig::new(60_000, None).unwrap(),
            Arc::new(|_| {}),
        );
        let registration = Arc::new(());
        let operation = FinalTaskOperation::for_tool("sensitive-tool", &registration).unwrap();
        let caller = context(&["invoke", "manage", "sensitive"]);
        assert!(
            runtime
                .create_task_for_operation(&caller, operation.clone(), work(), None)
                .is_err()
        );
        assert_eq!(store.task_count(), 0);
        runtime
            .install_access_authorizer(Arc::new(policy()))
            .unwrap();
        assert_execution_denied(runtime.create_task_for_operation(
            &caller,
            operation.clone(),
            work(),
            None,
        ));
        assert_eq!(store.task_count(), 0);
        runtime
            .install_execution_authorizer(Arc::new(ExecutionPolicy::new(
                task_request_principal(&caller).unwrap(),
                operation.clone(),
            )))
            .unwrap();
        let runner = runtime
            .install_task_service(1, Arc::new(IdleSupervisor))
            .unwrap();
        let cx = Cx::for_testing();
        let mut service = Box::pin(runner.run(&cx));
        let mut poll = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            Future::poll(service.as_mut(), &mut poll),
            std::task::Poll::Pending
        ));
        let created = runtime
            .create_task_for_operation(&caller, operation.clone(), work(), None)
            .unwrap();
        let id = &created.task.base().task_id;
        let metadata = store.get_task_access_metadata(id).unwrap().unwrap();
        assert_eq!(metadata.original_operation(), Some(&operation));
        assert_eq!(
            metadata.authenticated_principal(),
            task_request_principal(&caller).unwrap()
        );
        runtime
            .require_input(
                id,
                serde_json::from_value(serde_json::json!({"roots":{"method":"roots/list"}}))
                    .unwrap(),
                None,
            )
            .unwrap();
        let mut update = parameters(id);
        update["inputResponses"] = serde_json::json!({"roots":{"roots":[]}});
        dispatch_final_tasks_update(&runtime, &caller, update).unwrap();
        let completed: FinalTaskCallToolResult =
            serde_json::from_value(serde_json::json!({"content":[]})).unwrap();
        runtime.complete_task(id, completed, None).unwrap();
        assert!(dispatch_final_tasks_get(&runtime, &caller, parameters(id)).is_ok());
        assert!(dispatch_final_tasks_get(&runtime, &context(&["manage"]), parameters(id)).is_err());
        assert_eq!(
            store
                .get_task_snapshot(id)
                .unwrap()
                .unwrap()
                .original_operation(),
            Some(&operation)
        );
        assert!(store.retained_payload_bytes() >= operation.retained_bytes());
    }

    #[test]
    fn retained_task_metadata_diagnostics_do_not_disclose_original_names_or_principals() {
        let (store, _, id, _registration) = fixture();
        let metadata = store.get_task_access_metadata(&id).unwrap().unwrap();
        let text = format!("{metadata:?} {:?}", metadata.original_operation());
        assert!(!text.contains("sensitive-tool"));
        assert!(!text.contains("same-owner"));
        assert!(!text.contains(id.as_str()));
    }
}
