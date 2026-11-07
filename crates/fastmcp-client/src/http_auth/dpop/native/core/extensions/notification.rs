//! Current-message extension notifications over authenticated DPoP HTTPS.
//!
//! The existing client runtime stamps and validates the notification's local
//! proof before contact, then negotiates only that owner after authenticated
//! discovery. The exact encoded wire and validated settings stay paired in one
//! private preparation. Native DPoP owns both POSTs and their original deadline;
//! the shared HTTP notification constructor owns the absence of routing headers.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::extensions::ExtensionSettings;
use fastmcp_protocol::{ExtensionId, FinalRequestMeta, JsonRpcRequest, RequestId};
use serde_json::Value;

use super::{DpopExtensionConfiguration, PreparedDiscovery};
use super::super::{
    DpopCoreError, DpopCredential, DpopHttpClient, DpopHttpError, DpopHttpResponse,
    ManagedCoreError, ManagedCoreLimits, WaitBounds, check_live,
};
use crate::http_auth::caller::with_caller;
use crate::http_executor::{
    ModernHttpRequest, ModernHttpResponseKind, validate_response_head,
};
use crate::session::ClientExtensionRuntime;

/// One notification with an identity for its preceding discovery only.
///
/// The notification itself has no JSON-RPC ID or response owner. This consumed
/// value is deliberately neither Clone nor Debug: callers choose every explicit
/// publication, including whether to retry an uncertain remote effect.
pub struct DpopExtensionNotification {
    discovery_id: RequestId,
    extension_id: ExtensionId,
    method: String,
    parameters: Value,
}

impl DpopExtensionNotification {
    /// Validates local envelope shape without signing a proof or contacting a peer.
    ///
    /// Descriptor ownership, direction, configured settings, notification-role
    /// metadata, activation proof and complete encoded bounds are admitted when
    /// the operation is polled, before either authenticated POST.
    pub fn new(
        discovery_id: RequestId,
        extension_id: ExtensionId,
        method: impl Into<String>,
        parameters: Value,
    ) -> Result<Self, ManagedCoreError> {
        discovery_id.validate().map_err(|_| ManagedCoreError::InvalidRequest)?;
        if !parameters.is_object()
            || parameters.get("_meta").is_some_and(|value| !value.is_object())
        {
            return Err(ManagedCoreError::InvalidRequest);
        }
        Ok(Self {
            discovery_id,
            extension_id,
            method: method.into(),
            parameters,
        })
    }
}

// Only this constructor pairs the current validated settings with their encoded
// notification. No public caller can replace either member after preparation.
struct Prepared {
    runtime: Arc<ClientExtensionRuntime>,
    extension_id: ExtensionId,
    method: String,
    current: ExtensionSettings,
    discovery: PreparedDiscovery,
    wire: ModernHttpRequest,
}

impl Prepared {
    fn new(
        target: &str,
        configuration: &DpopExtensionConfiguration,
        metadata: FinalRequestMeta,
        notification: DpopExtensionNotification,
        limits: ManagedCoreLimits,
        native_maximum: usize,
    ) -> Result<Self, ManagedCoreError> {
        let (parameters, current) = configuration.runtime.prepare_local_notification(
            &notification.extension_id, &notification.method, notification.parameters,
        ).map_err(|_| ManagedCoreError::UnsupportedRequest)?;
        let message = JsonRpcRequest::notification(
            notification.method.as_str(), Some(parameters),
        );
        // Measure through the bounded writer before allocating an encoded body.
        // The same typed envelope is consumed by the shared wire constructor.
        crate::measure_serialized_bytes(&message, limits.request_bytes().min(native_maximum))
            .map_err(|_| ManagedCoreError::RequestTooLarge)?;
        let wire = ModernHttpRequest::notification(
            target,
            &notification.method,
            message.params.ok_or(ManagedCoreError::InvalidRequest)?,
        ).map_err(|_| ManagedCoreError::InvalidRequest)?;
        let (discovery, _) = PreparedDiscovery::new(
            target, configuration, metadata, notification.discovery_id, limits, native_maximum,
        )?;
        Ok(Self {
            runtime: Arc::clone(&configuration.runtime),
            extension_id: notification.extension_id,
            method: notification.method,
            current,
            discovery,
            wire,
        })
    }

    fn admit(self, response: DpopHttpResponse) -> Result<ModernHttpRequest, DpopCoreError> {
        let (discovery, _) = self.discovery.admit(response)?;
        // These settings came from the exact encoded message, not a prior
        // request or connection. Only this owner participates in negotiation;
        // another configured extension's one-sided fallback cannot veto it.
        self.runtime.admit_notification_settings(
            &discovery, &self.extension_id, &self.method, self.current,
        ).map_err(|_| ManagedCoreError::UnsupportedRequest)?;
        // Discovery may consume the entire payload allowance. A valid
        // acknowledgement has no body and requires no residual result budget.
        Ok(self.wire)
    }
}

fn admit_acknowledgement(response: DpopHttpResponse) -> Result<(), DpopCoreError> {
    // Reuse modern media/encoding/redirect semantics after native DPoP's own
    // bounded response admission. A response session header remains inert;
    // neither this adapter nor its transport adopts or forwards it.
    let metadata = validate_response_head(response.status(), response.headers())
        .map_err(|_| DpopHttpError::InvalidResponseHeaders)?;
    if response.status() != 202 {
        return Err(ManagedCoreError::HttpStatus { status: response.status() }.into());
    }
    if metadata.kind() != ModernHttpResponseKind::EmptyAcknowledgement
        || !response.body().is_empty()
    {
        return Err(DpopHttpError::InvalidResponseHeaders.into());
    }
    Ok(())
}

impl DpopHttpClient {
    /// Discovers the authenticated peer, then publishes one proof-bound notification.
    ///
    /// Local descriptor ownership, direction, runtime enablement, proof placement,
    /// notification metadata, proof size and both complete request bodies are
    /// checked before signing or network contact. The registry supplies the
    /// proof from locally configured settings; conflicting caller proof is
    /// refused. The final discovery metadata is used only on discovery and is
    /// never copied into the notification's metadata.
    ///
    /// After discovery, fresh negotiation admits exactly this notification's
    /// extension. An unrelated missing extension cannot veto it. The encoded
    /// message has no ID, MCP protocol/method/name routing headers, parameter
    /// mirrors or server-issued session state. Each POST receives a fresh DPoP
    /// proof for the same credential and canonical resource.
    ///
    /// Only an empty 202 acknowledgement without Content-Type completes this
    /// operation. The existing HTTP header, encoding and native body bounds
    /// remain authoritative. The typed request/frame/aggregate limits cover
    /// preparation and discovery; a valid acknowledgement adds zero payload
    /// bytes and no notification events. No result body is interpreted.
    ///
    /// One original native/typed/caller/credential deadline covers preparation,
    /// both POSTs, resolver work and acknowledgement publication. Cancellation,
    /// expiry or revocation wins over a ready result or error. Resolver execution
    /// uses the supplied caller's effect ceiling; factories must be brief and
    /// nonblocking. Drop releases the pending HTTP operation. No challenge,
    /// acknowledgement failure or uncertain delivery is automatically retried.
    /// Already committed remote effects cannot be recalled.
    #[allow(clippy::too_many_arguments)]
    pub async fn notify_final_extension(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        configuration: &DpopExtensionConfiguration,
        metadata: FinalRequestMeta,
        notification: DpopExtensionNotification,
        limits: ManagedCoreLimits,
    ) -> Result<(), DpopCoreError> {
        let bounds = WaitBounds::new(cx, self.policy.timeout.min(limits.timeout()), credential)?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let prepared = Prepared::new(
            self.resource().as_str(), configuration, metadata, notification,
            limits, self.policy.max_body_bytes,
        );
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let prepared = prepared?;
        let response = self.post_resource_with_bounds(
            cx, cancellation, credential, &prepared.discovery.wire, bounds,
        ).await;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let response = response?;
        let admitted = with_caller(cx, || {
            catch_unwind(AssertUnwindSafe(|| prepared.admit(response)))
        });
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let wire = admitted.map_err(|_| ManagedCoreError::UnsupportedRequest)??;
        let response = self.post_resource_with_bounds(
            cx, cancellation, credential, &wire, bounds,
        ).await;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let outcome = admit_acknowledgement(response?);
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        outcome
    }
}
