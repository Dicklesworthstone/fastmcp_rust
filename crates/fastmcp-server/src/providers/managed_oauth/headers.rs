//! Explicit parameter-header disclosure for authenticated gateway tools.
//!
//! Catalog annotations are not consent. The host reviews each annotated path
//! from the fully collected upstream catalog before any reviewed handler is
//! returned. Headers are subsequently derived by the managed client's exact-body
//! projector, never copied from downstream headers or metadata. The review is
//! bound to the original upstream name, complete input schema and HTTPS resource.
//!
//! Registration still delegates the configured login's authority. The host must
//! approve each invocation and retire handlers when its catalog or disclosure
//! policy changes. Review does not install a watch, refresh a stale definition,
//! authorize automatic retry, or guarantee the remote deployment's behavior.

use std::sync::Arc;

use asupersync::Cx;
use fastmcp_client::http_auth::managed::ManagedOAuthSession;
use fastmcp_client::http_auth::rpc::tool_headers::ManagedToolHeaderError;
use fastmcp_client::http_auth::rpc::{ManagedCoreEvent, ManagedCoreLimits};
use fastmcp_client::http_executor::parameter_headers::ReviewedToolHeaders;
use fastmcp_core::{CanonicalHttpUrl, McpContext, McpError, McpResult};
use fastmcp_protocol::http_headers::ParameterHeaderBinding;
use fastmcp_protocol::{CoreRequest, CoreResult, FinalCoreResult, FinalTool, RequestId};

use super::{
    BoxFuture, CoreBackend, Forwarder, ManagedOAuthProvider, ManagedOAuthTool,
    UNEXPECTED_RESULT, check_cx, forward_notification, upstream_error,
};

const HEADER_FAILURE: &str = "Managed OAuth tool header review or projection failed";

impl ManagedOAuthProvider {
    /// Collects the complete authenticated tool catalog and reviews disclosure.
    /// `review` receives the original upstream definition (before namespacing)
    /// and one exact property path, field name and primitive type, not argument
    /// values. Every annotated binding requires approval. One refusal or invalid
    /// plan rejects the whole returned list; previously obtained handlers and
    /// provider clones are unchanged. No tool is invoked during this method.
    ///
    /// The selected backend, call limits and shared ID allocator remain attached
    /// to each handler. Ordinary `tools()` does not enable parameter headers.
    /// Reviewed handlers do not copy ingress headers, cookies, authorization or
    /// request metadata. Downstream argument values remain unmodified body data.
    /// The host callback is synchronous and must cooperate with the caller's Cx.
    pub async fn tools_with_header_review(
        &self,
        cx: &Cx,
        review: impl FnMut(&FinalTool, &ParameterHeaderBinding) -> bool,
    ) -> McpResult<Vec<ManagedOAuthTool>> {
        let tools = self.tools(cx).await?;
        review_tools(cx, self.session.resource(), tools, review)
    }
}

fn review_tools(
    cx: &Cx,
    resource: &CanonicalHttpUrl,
    mut tools: Vec<ManagedOAuthTool>,
    mut review: impl FnMut(&FinalTool, &ParameterHeaderBinding) -> bool,
) -> McpResult<Vec<ManagedOAuthTool>> {
    check_cx(cx)?;
    for tool in &mut tools {
        check_cx(cx)?;
        let mut upstream = tool.definition.clone();
        upstream.name.clone_from(&tool.upstream_name);
        let reviewed = ReviewedToolHeaders::new(
            resource.clone(), upstream.name.clone(), upstream.input_schema.clone(),
            |binding| {
                if check_cx(cx).is_err() { return false; }
                let approved = review(&upstream, binding);
                approved && check_cx(cx).is_ok()
            },
        );
        // Cancellation wins over a callback refusal; no subsequent callback or
        // handler publication can disguise it as a disclosure-policy decision.
        check_cx(cx)?;
        let reviewed = Arc::new(reviewed.map_err(|_| McpError::invalid_params(HEADER_FAILURE))?);
        let backend = tool.forwarder.backend.with_reviewed_headers(reviewed)?;
        tool.forwarder = Arc::new(Forwarder {
            backend,
            next_id: Arc::clone(&tool.forwarder.next_id),
            limits: tool.forwarder.limits,
        });
    }
    check_cx(cx)?;
    Ok(tools)
}

pub(super) fn admit_resource(
    resource: &CanonicalHttpUrl,
    reviewed: &ReviewedToolHeaders,
) -> McpResult<()> {
    if resource != reviewed.resource() {
        return Err(McpError::invalid_params(HEADER_FAILURE));
    }
    Ok(())
}

pub(super) fn native_backend(
    session: ManagedOAuthSession,
    reviewed: Arc<ReviewedToolHeaders>,
) -> McpResult<Arc<dyn CoreBackend>> {
    admit_resource(session.resource(), &reviewed)?;
    Ok(Arc::new(ReviewedNativeBackend { session, reviewed }))
}

struct ReviewedNativeBackend {
    session: ManagedOAuthSession,
    reviewed: Arc<ReviewedToolHeaders>,
}

impl CoreBackend for ReviewedNativeBackend {
    fn execute<'a>(
        &'a self, ctx: &'a McpContext, cx: &'a Cx, request: CoreRequest,
        id: RequestId, limits: ManagedCoreLimits,
    ) -> BoxFuture<'a, McpResult<FinalCoreResult>> {
        Box::pin(async move {
            ctx.checkpoint()?;
            check_cx(cx)?;
            let cancellation = ctx.request_cancellation();
            let mut call = self.session.request_tool_with_headers_and_cancellation(
                cx, &cancellation, request, id, &self.reviewed, limits,
            ).await.map_err(header_error)?;
            while let Some(event) = call.next_event(cx).await.map_err(upstream_error)? {
                ctx.checkpoint()?;
                check_cx(cx)?;
                match event {
                    ManagedCoreEvent::Result(result) => return match *result {
                        CoreResult::Final(result) => Ok(result),
                        _ => Err(McpError::invalid_request(UNEXPECTED_RESULT)),
                    },
                    ManagedCoreEvent::Notification(notification) => forward_notification(ctx, *notification)?,
                }
            }
            Err(McpError::invalid_request(UNEXPECTED_RESULT))
        })
    }
}

fn header_error(error: ManagedToolHeaderError) -> McpError {
    match error {
        ManagedToolHeaderError::Core(error) => upstream_error(error),
        ManagedToolHeaderError::Headers(_) => McpError::invalid_params(HEADER_FAILURE),
    }
}

#[cfg(test)]
mod tests;
