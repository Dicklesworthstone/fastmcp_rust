//! Atomic task creation driven by the originating request's async context.

#[allow(clippy::wildcard_imports)]
use super::*;
use crate::extensions::TaskControlReceipt;

/// Request-owned admission for one atomic Task creation.
///
/// The framework constructs this value only after reserving bounded custody
/// from an entered Task service. Asynchronous stores use [`Self::context`] for
/// I/O, then call [`Self::checkpoint_before_write`] immediately before their
/// first irreversible write, including after any suspension. It rechecks
/// current request authority, the exact original tool registration and its
/// access policies, the service generation, and the reservation deadline.
///
/// Once a write may have committed, settle the original receipt instead of
/// using this check to discard a successful write. This value cannot be
/// constructed by an application, cloned, or retained beyond the operation.
pub struct FinalTaskCreationAdmission<'a> {
    runtime: &'a FinalTaskRuntime,
    ctx: &'a McpContext,
    operation: &'a FinalTaskOperation,
    permit: &'a TaskServiceAdmissionPermit,
}

impl<'a> FinalTaskCreationAdmission<'a> {
    /// Returns the original request context and its cancellation authority.
    #[must_use]
    pub fn context(&self) -> &'a McpContext {
        self.ctx
    }

    /// Revalidates admission immediately before the backend's first write.
    pub fn checkpoint_before_write(&self) -> McpResult<()> {
        self.runtime.authorize_original_operation(
            self.ctx,
            TaskAccessAction::Create,
            Some(self.operation),
        )?;
        self.permit.admit_commit(self.runtime, Some(self.ctx))
    }
}

impl FinalTaskRuntime {
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
                operation: &operation,
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
