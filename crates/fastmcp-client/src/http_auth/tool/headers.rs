//! Explicit disclosure review for schema-bound and catalog-derived tool clients.
//!
//! The client supplies its exact resource, name, and already-admitted schema.
//! The reviewer sees paths, field names, and primitive types, never invocation
//! values. A callback is host code and must cooperate; it is not executed by a
//! worker or treated as authorization to invoke a tool. Approval is immutable
//! once installed and is retained by the existing multi-round operation owner.
//!
//! Review cannot resurrect a retired catalog or tool contract. Invalidation is
//! checked before and after every callback, before installing the completed
//! plan, and by the normal call and result-publication boundaries. Already
//! admitted calls can be dispatching; use their cancellation handles to abort
//! pending reads. Neither review nor invalidation recalls committed effects.

use std::sync::Arc;

use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::http_headers::ParameterHeaderBinding;

use super::{ManagedToolClient, ManagedToolError, ToolContract};
use super::catalog::{ManagedToolCatalogError, ManagedToolCatalogSnapshot};
use crate::http_executor::parameter_headers::{ReviewedToolHeaders, ToolHeaderDispatchError};

/// Explicit one-shot header repair without dropping schema or invalidation checks.
pub mod repair;

impl ManagedToolClient {
    /// Reviews the exact schema already bound to this client, not a replacement
    /// supplied by the host. Refusing any binding refuses the entire approval.
    /// There is no credential acquisition, invocation, or network schema fetch.
    ///
    /// Existing clones remain unconfigured; future clones share this approval
    /// and the original contract's invalidation state. A catalog change or local
    /// policy change still requires retiring handles and reviewing again.
    pub fn review_headers(
        self,
        review: impl FnMut(&ParameterHeaderBinding) -> bool,
    ) -> Result<Self, ManagedToolError> {
        self.require_unconfigured_headers()?;
        let reviewed = self.contract.review_headers(self.session.resource(), review)?;
        self.with_reviewed_headers(reviewed)
    }

    /// Installs one independently reviewed plan only when its canonical HTTPS
    /// resource, exact case-sensitive tool name, and complete source schema all
    /// match this contract. Matching field names alone are insufficient.
    /// An empty approved projection also seals the configuration.
    pub fn with_reviewed_headers(
        mut self,
        reviewed: Arc<ReviewedToolHeaders>,
    ) -> Result<Self, ManagedToolError> {
        self.require_unconfigured_headers()?;
        self.contract.admit_headers(self.session.resource(), &reviewed)?;
        self.header_review = Some(reviewed);
        Ok(self)
    }

    fn require_unconfigured_headers(&self) -> Result<(), ManagedToolError> {
        self.contract.check()?;
        if self.header_review.is_some() {
            return Err(ManagedToolError::Headers(ToolHeaderDispatchError::AlreadyProjected));
        }
        Ok(())
    }
}

impl ManagedToolCatalogSnapshot {
    /// Looks up a tool and reviews its own immutable contract. An absent name
    /// invokes no callback. A retired snapshot cannot yield a newly approved
    /// handle, including when the callback itself triggers invalidation.
    /// This does not approve other tools in the catalog or execute this tool.
    pub fn tool_with_reviewed_headers(
        &self,
        name: &str,
        review: impl FnMut(&ParameterHeaderBinding) -> bool,
    ) -> Result<Option<ManagedToolClient>, ManagedToolCatalogError> {
        self.tool(name)?
            .map(|tool| tool.review_headers(review).map_err(ManagedToolCatalogError::Tool))
            .transpose()
    }
}

impl ToolContract {
    fn admit_headers(
        &self,
        resource: &CanonicalHttpUrl,
        reviewed: &ReviewedToolHeaders,
    ) -> Result<(), ManagedToolError> {
        self.check()?;
        if reviewed.resource() != resource
            || reviewed.tool_name() != self.name.as_str()
            || reviewed.schema() != self.input.schema()
        {
            return Err(ManagedToolError::HeaderBindingMismatch);
        }
        self.check()
    }

    fn review_headers(
        &self,
        resource: &CanonicalHttpUrl,
        mut review: impl FnMut(&ParameterHeaderBinding) -> bool,
    ) -> Result<Arc<ReviewedToolHeaders>, ManagedToolError> {
        self.check()?;
        // Source admission already bounded this clone. The reviewed wrapper
        // repeats syntax admission before any callback and binds the resource.
        let reviewed = ReviewedToolHeaders::new(
            resource.clone(), self.name.clone(), self.input.schema().clone(),
            |binding| {
                if self.is_invalidated() { return false; }
                let approved = review(binding);
                approved && !self.is_invalidated()
            },
        );
        // Preserve invalidation rather than disguising it as a policy refusal.
        // In particular no later callback runs after the one that invalidates.
        self.check()?;
        let reviewed = reviewed.map_err(ManagedToolError::Headers)?;
        self.admit_headers(resource, &reviewed)?;
        Ok(Arc::new(reviewed))
    }
}

#[cfg(test)]
mod tests;
