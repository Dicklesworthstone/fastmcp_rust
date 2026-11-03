//! Apps composition on the caller-owned experimental WebSocket connection.
//!
//! Only standard-reused core methods cross this transport. View frames and
//! model/renderer consent remain owned by the separate Apps Host.

use std::time::Instant;

use asupersync::io::{AsyncRead, AsyncWrite};
use fastmcp_protocol::{CoreRequest, JsonRpcRequest};

use super::{
    CoreResult, Cx, McpAppsActivationProof, McpAppsHostError, McpAppsRoutedMethod,
    McpAppsServerInputClient, McpAppsWireBridgeTransport, McpAppsWireHost,
    McpAppsWireHostCleanup, McpAppsWireHostConfiguration, McpAppsWireHostEffects,
    McpAppsWireHostPolicy, McpError, McpRequestCancellation, McpResult, Value,
    dispatch_apps_server_input, project_reused_core_result, wire_policy_checkpoint,
};
use crate::{ProtocolEra, WebSocketClient};

/// Forwards one View's reused core methods through a negotiated experimental
/// WebSocket client. The caller supplied the already-upgraded asynchronous
/// stream and continues to own the runtime and its context.
///
/// Tools and resource reads use the Host's bounded MRTR/Task composition and
/// its explicit per-View consent. A cancelled request commits its View-side
/// cancellation before the Host drives bounded native request retirement.
pub struct McpAppsWebSocketClientWirePolicy<'client, IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    client: &'client mut WebSocketClient<IO>,
}

impl<IO> WebSocketClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Reports live bilateral Apps activation on this exact connection.
    #[must_use]
    pub fn mcp_apps_active(&self) -> bool {
        !self.closed && self.session.mcp_apps_active()
    }

    fn apps_activation_proof(&self) -> Result<McpAppsActivationProof, McpAppsHostError> {
        if !self.mcp_apps_active() {
            return Err(McpAppsHostError::NotNegotiated);
        }
        McpAppsActivationProof::from_activation_receipt(
            self.session.mcp_apps_activation_receipt(),
        )
    }

    /// Starts a closed Apps View bridge with explicit embedder forwarding.
    /// No effect or server access is authorized by constructing the Host.
    pub fn mcp_apps_wire_host_with_policy<T, P>(
        &self,
        transport: T,
        configuration: McpAppsWireHostConfiguration,
        policy: P,
    ) -> Result<McpAppsWireHost<T, P>, McpAppsHostError>
    where
        T: McpAppsWireBridgeTransport,
        P: McpAppsWireHostPolicy,
    {
        Ok(McpAppsWireHost::new_negotiated(
            transport,
            configuration,
            policy,
            self.apps_activation_proof()?,
        ))
    }

    /// Starts one Apps Host on this live caller-upgraded WebSocket connection.
    /// Reused methods allocate fresh core IDs; View IDs never cross it.
    ///
    /// The default refuses server input and Task creation. Use the returned
    /// Host's with_effects method to install explicit View-bound consent. This
    /// does not provide a URI connector, HTTP Upgrade or authenticated handshake.
    pub fn mcp_apps_wire_host<T>(
        &mut self,
        transport: T,
        configuration: McpAppsWireHostConfiguration,
    ) -> Result<McpAppsWireHost<T, McpAppsWebSocketClientWirePolicy<'_, IO>>, McpAppsHostError>
    where
        T: McpAppsWireBridgeTransport,
        IO: Send + 'static,
    {
        let activation_proof = self.apps_activation_proof()?;
        Ok(McpAppsWireHost::new_negotiated(
            transport,
            configuration,
            McpAppsWebSocketClientWirePolicy { client: self },
            activation_proof,
        ))
    }

    fn apps_request_parameters(&self, params: Value) -> McpResult<Value> {
        if !self.mcp_apps_active() {
            return Err(McpError::invalid_request(
                "MCP Apps reused methods require the current bilateral activation receipt",
            ));
        }
        let params = self.with_modern_request_metadata(params)?;
        // The general client advertises negotiated Tasks automatically. A
        // View grants no creation authority: only this call's Host policy
        // may add the extension back after approving bounded observation.
        #[cfg(feature = "tasks")]
        let params = {
            let mut params = params;
            if let Some(extensions) = params
                .get_mut("_meta")
                .and_then(Value::as_object_mut)
                .and_then(|meta| meta.get_mut(crate::FINAL_CLIENT_CAPABILITIES_META_KEY))
                .and_then(Value::as_object_mut)
                .and_then(|capabilities| capabilities.get_mut("extensions"))
                .and_then(Value::as_object_mut)
            {
                extensions.remove(fastmcp_protocol::OFFICIAL_TASKS_EXTENSION_ID);
            }
            params
        };
        Ok(params)
    }

    async fn request_apps_core_prepared(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Instant,
        method: &str,
        params: Value,
    ) -> McpResult<CoreResult>
    where
        IO: Send + 'static,
    {
        crate::check_mrtr_operation(cx, Some(cancellation), deadline)?;
        if !self.mcp_apps_active() {
            return Err(McpError::invalid_request(
                "Apps WebSocket connection is inactive",
            ));
        }
        // Preserve the original operation's consent-scoped metadata across
        // every continuation. Decorating again here would re-enable Tasks.
        self.admit_raw_client_request(method, Some(&params))?;
        let request = CoreRequest::decode(ProtocolEra::Modern2026, method, Some(&params))
            .map_err(|_| McpError::invalid_params("Invalid selected-era Apps core request"))?;
        let request_id = self.allocate_request_id().await?;
        crate::check_mrtr_operation(cx, Some(cancellation), deadline)?;
        let received = self
            .request_admitted_with_raw_result_with_deadline(
                cx,
                JsonRpcRequest::new(method, Some(params), request_id),
                Some(cancellation),
                Some(deadline),
            )
            .await?;
        crate::check_mrtr_operation(cx, Some(cancellation), deadline)?;
        if let Some(error) = received.response.error {
            return Err(crate::json_rpc_error_to_mcp(error));
        }
        let result = received.response.result.as_ref().ok_or_else(|| {
            McpError::invalid_request("Apps WebSocket response has no result")
        })?;
        let source = received.raw_result.as_deref().ok_or_else(|| {
            McpError::invalid_request("Apps WebSocket response has no admitted result source")
        })?;
        crate::decode_core_result_from_source(&request, result, Some(source))
    }

    async fn settle_apps_transport(&mut self) -> Result<(), McpAppsHostError>
    where
        IO: Send + 'static,
    {
        let result = self.settle_abandoned_websocket_request().await;
        if result.is_err() || self.closed {
            // An interrupted cancellation send has already installed its
            // exact tombstone and marked the stream uncertain. Its transient
            // request owner is gone; resume the retained close election too,
            // without sending a second cancellation or resetting its budget.
            let cx = self.connection_cx.clone();
            let closed = self.close(&cx).await;
            return Err(McpAppsHostError::Core(
                result
                    .err()
                    .or_else(|| closed.err())
                    .unwrap_or_else(|| {
                        McpError::internal_error("Apps WebSocket connection is closed")
                    }),
            ));
        }
        Ok(())
    }
}

impl<IO> McpAppsServerInputClient for WebSocketClient<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn prepare_apps_server_input(
        &self,
        cx: &Cx,
        params: Value,
    ) -> McpResult<(Instant, Value)> {
        Ok((
            crate::mrtr_operation_deadline(cx, self.request_timeout_policy)?,
            self.apps_request_parameters(params)?,
        ))
    }

    async fn request_apps_server_input(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Instant,
        method: &str,
        params: Value,
        allow_tasks: bool,
    ) -> McpResult<CoreResult> {
        #[cfg(feature = "tasks")]
        let params = if allow_tasks {
            self.admit_apps_tasks()?;
            let mut params = params;
            let metadata = params
                .get_mut("_meta")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| McpError::invalid_params("Apps request has no final metadata"))?;
            crate::insert_negotiated_tasks_client_extension(
                metadata,
                self.session.server_discovery(),
            )?;
            params
        } else {
            params
        };
        #[cfg(not(feature = "tasks"))]
        let _ = allow_tasks;
        self.request_apps_core_prepared(cx, cancellation, deadline, method, params)
            .await
    }

    #[cfg(feature = "tasks")]
    fn admit_apps_tasks(&self) -> McpResult<()> {
        super::admit_apps_task_discovery(self.session.server_discovery().ok_or_else(|| {
            McpError::invalid_request("Apps server Tasks require current discovery")
        })?)
    }

    #[cfg(feature = "tasks")]
    async fn get_apps_task(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Instant,
        task_id: crate::FinalTaskId,
    ) -> McpResult<crate::FinalTask> {
        // The enclosing Apps watchdog retains the same absolute deadline and
        // cancellation domain while this existing typed Task request runs.
        crate::check_mrtr_operation(cx, Some(cancellation), deadline)?;
        self.get_task_final(cx, task_id)
            .await
            .map(|result| result.task)
    }

    #[cfg(feature = "tasks")]
    async fn update_apps_task(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        deadline: Instant,
        task: &crate::FinalTask,
        responses: crate::FinalTaskInputResponses,
    ) -> McpResult<()> {
        crate::check_mrtr_operation(cx, Some(cancellation), deadline)?;
        self.update_task_final(cx, task, responses).await.map(|_| ())
    }
}

impl<IO> McpAppsWireHostPolicy for McpAppsWebSocketClientWirePolicy<'_, IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn transport_cleanup(&mut self) -> McpAppsWireHostCleanup<'_> {
        McpAppsWireHostCleanup::native(self.client.settle_apps_transport())
    }

    async fn dispatch_reused_request(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: McpAppsRoutedMethod,
        params: Option<Value>,
    ) -> Result<Value, McpAppsHostError> {
        self.dispatch_reused_request_with_effects(cx, cancellation, method, params, &mut ())
            .await
    }

    async fn dispatch_reused_request_with_effects<E: McpAppsWireHostEffects>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: McpAppsRoutedMethod,
        params: Option<Value>,
        effects: &mut E,
    ) -> Result<Value, McpAppsHostError> {
        wire_policy_checkpoint(cx, cancellation)?;
        if matches!(
            method,
            McpAppsRoutedMethod::ToolsCall | McpAppsRoutedMethod::ResourcesRead
        ) {
            return dispatch_apps_server_input(
                self.client, cx, cancellation, method, params, effects,
            )
            .await;
        }
        let core_method = match method {
            McpAppsRoutedMethod::ResourcesList => "resources/list",
            McpAppsRoutedMethod::ResourceTemplatesList => "resources/templates/list",
            McpAppsRoutedMethod::PromptsList => "prompts/list",
            _ => return Err(McpError::invalid_params("Unsupported Apps reused method").into()),
        };
        let (deadline, params) = self
            .client
            .prepare_apps_server_input(cx, params.unwrap_or_else(|| super::json!({})))?;
        // Native response timers begin after its frame is committed. This
        // outer owner also bounds a stalled initial write and drops its
        // request guard so post-disposition cleanup can retire the stream.
        let result = crate::wait_for_mrtr_operation(
            cx,
            Some(cancellation),
            deadline,
            self.client
                .request_apps_core_prepared(cx, cancellation, deadline, core_method, params),
        )
        .await?;
        project_reused_core_result(method, result).map_err(McpAppsHostError::Core)
    }
}

#[cfg(test)]
mod tests;
