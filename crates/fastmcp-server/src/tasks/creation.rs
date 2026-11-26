//! Atomic Task creation driven by its caller's asynchronous context.

#[allow(clippy::wildcard_imports)]
use super::*;
use crate::extensions::TaskControlReceipt;

/// Caller-owned admission for one atomic Task creation.
///
/// The framework reserves bounded custody from an entered Task service before
/// constructing this value. Stores use [`Self::context`] for I/O and call
/// [`Self::checkpoint_before_write`] immediately before their first irreversible
/// write, including after suspension. Request creation additionally rechecks its
/// original operation and current access policy. Trusted embedding creation has
/// no authenticated principal or original-operation grant.
///
/// Once a write may have committed, settle the original receipt instead of
/// discarding a successful write. This value cannot be constructed by an
/// application, cloned, or retained beyond the operation.
pub struct FinalTaskCreationAdmission<'a> {
    runtime: &'a FinalTaskRuntime,
    ctx: &'a McpContext,
    operation: Option<&'a FinalTaskOperation>,
    permit: &'a TaskServiceAdmissionPermit,
}

impl<'a> FinalTaskCreationAdmission<'a> {
    /// Returns the caller context; trusted embedding creation carries no credentials.
    #[must_use]
    pub fn context(&self) -> &'a McpContext {
        self.ctx
    }

    /// Revalidates admission immediately before the backend's first write.
    pub fn checkpoint_before_write(&self) -> McpResult<()> {
        if let Some(operation) = self.operation {
            self.runtime.authorize_original_operation(
                self.ctx,
                TaskAccessAction::Create,
                Some(operation),
            )?;
        }
        self.permit.admit_commit(self.runtime, Some(self.ctx))
    }
}

impl FinalTaskRuntime {
    /// Enqueues trusted application work through caller-owned asynchronous storage.
    ///
    /// This is the asynchronous counterpart of [`Self::create_task_with_work`].
    /// It creates unprotected work with no router registration or authenticated
    /// owner; never use it to implement a credential-bearing request handler.
    /// The caller supplies its existing `Cx`; no runtime or worker is created.
    ///
    /// A ready Task service and bounded creation reservation are required. The
    /// reservation remains charged across storage and notification suspension.
    /// Cancellation before the backend's write refuses admission. A validated
    /// committed receipt remains accepted after cancellation or service exit,
    /// and recovery is signalled before best-effort notification delivery.
    /// A storage error that may hide a commit must be reconciled, never retried
    /// as a fresh creation merely because the caller was cancelled.
    pub fn create_task_with_work_with_cx<'a>(
        &'a self,
        cx: &'a Cx,
        work_descriptor: FinalTaskWorkDescriptor,
        status_message: Option<String>,
    ) -> impl Future<Output = McpResult<CreateTaskResult>> + Send + 'a {
        CallerContextFuture::new(cx, async move {
            let ctx = McpContext::new(cx.clone(), 0);
            ctx.checkpoint()?;
            let task = self.new_task_for_creation(status_message)?;
            let (permit, notification) =
                self.prepare_task_creation(&task, &work_descriptor, None, Some(&ctx))?;
            let admission = FinalTaskCreationAdmission {
                runtime: self,
                ctx: &ctx,
                operation: None,
                permit: &permit,
            };
            // Capability callbacks may cancel the caller or retire readiness.
            // Revalidate before constructing the backend's mutation future.
            admission.checkpoint_before_write()?;
            let committed = self
                .store
                .create_task_with_work_with_context(
                    admission,
                    task.clone(),
                    notification,
                    work_descriptor,
                )
                .await
                .map_err(|error| control::control_write_error(&ctx, "Task creation", error))?;
            let committed = self.validate_committed_new_task(&task, None, None, committed)?;
            self.signal_task_service(task.base().task_id.clone());
            self.emit_recovery_commit(ctx.cx(), &committed).await;
            drop(permit);
            Ok(CreateTaskResult {
                task,
                meta: None,
                additional: BTreeMap::new(),
            })
        })
    }

    #[cfg(test)]
    pub(crate) fn create_task_for_operation_with_cx<'a>(
        &'a self,
        ctx: &'a McpContext,
        operation: FinalTaskOperation,
        work_descriptor: FinalTaskWorkDescriptor,
        status_message: Option<String>,
    ) -> impl Future<Output = McpResult<CreateTaskResult>> + Send + 'a {
        self.create_task_for_operation_with_receipt(
            ctx,
            operation,
            work_descriptor,
            status_message,
            TaskControlReceipt::default(),
        )
    }

    pub(crate) fn create_task_for_operation_with_receipt<'a>(
        &'a self,
        ctx: &'a McpContext,
        operation: FinalTaskOperation,
        work_descriptor: FinalTaskWorkDescriptor,
        status_message: Option<String>,
        receipt: TaskControlReceipt,
    ) -> impl Future<Output = McpResult<CreateTaskResult>> + Send + 'a {
        CallerContextFuture::new(ctx.cx(), async move {
            self.authorize_original_operation(ctx, TaskAccessAction::Create, Some(&operation))?;
            let principal = task_request_principal(ctx)?;
            self.ensure_execution_policy_available(principal)?;
            ctx.checkpoint()?;
            let task = self.new_task_for_creation(status_message)?;
            let (permit, notification) =
                self.prepare_task_creation(&task, &work_descriptor, principal, Some(ctx))?;

            // Capability discovery is application code and may re-enter the
            // runtime. Check the current registration, request authority and
            // entered service generation immediately before invoking storage.
            let admission = FinalTaskCreationAdmission {
                runtime: self,
                ctx,
                operation: Some(&operation),
                permit: &permit,
            };
            admission.checkpoint_before_write()?;
            receipt.admit_write();
            let committed = self
                .store
                .create_task_with_operation_with_context(
                    admission,
                    task.clone(),
                    notification.clone(),
                    work_descriptor,
                    principal,
                    operation.clone(),
                )
                .await
                .map_err(|error| control::control_write_error(ctx, "Task creation", error))?;
            let committed =
                self.validate_committed_new_task(&task, principal, Some(&operation), committed)?;
            receipt.committed();

            // A proven commit remains accepted after request cancellation or
            // service exit. Wake recovery before best-effort publication;
            // observer I/O, revocation or failure cannot erase the handle.
            // The admission permit remains charged across every suspension.
            self.signal_task_service(task.base().task_id.clone());
            self.emit_control_commit(ctx, TaskAccessAction::Create, notification, &committed)
                .await;
            drop(permit);
            Ok(CreateTaskResult {
                task,
                meta: None,
                additional: BTreeMap::new(),
            })
        })
    }
}

#[cfg(test)]
mod tests;
