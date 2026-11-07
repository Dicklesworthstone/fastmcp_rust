//! Negotiated extension requests over the existing DPoP HTTPS owner.
//!
//! One immutable client registry supplies local settings and exact method
//! ownership. Fresh authenticated discovery produces the request's result
//! authority. The existing DPoP stream reader owns proof signing, nonce updates,
//! credential expiry, cancellation, observers, framing and clean HTTP EOF.
//! No discovery receipt, credential, live response or retry capability escapes.

use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use asupersync::Cx;
use fastmcp_core::{McpRequestCancellation, McpResult};
use fastmcp_protocol::common_types::ExactNonNegativeJsonNumber;
use fastmcp_protocol::extensions::{
    ClientExtensionDiscovery, ExtensionDescriptorRegistry,
    ExtensionSettingsCompatibilityResolver,
};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{
    CoreRequest, CoreResult, ExtensionId, FINAL_CLIENT_CAPABILITIES_META_KEY,
    FINAL_CLIENT_INFO_META_KEY, FINAL_PROTOCOL_VERSION, FINAL_PROTOCOL_VERSION_META_KEY,
    FinalCoreResult, FinalRequestMeta, JsonRpcMessage, ProgressMarker, RequestId,
    ServerNotification, decode_strict_jsonrpc_message, decode_strict_jsonrpc_response,
};
use serde_json::{Value, json};

use super::stream::{
    DpopStreamError, DpopStreamLimits, Idle, PreparedStream, StreamDecoder, StreamEvent,
};
use super::{
    BoundedWriter, CoreDecoder, DpopCredential, DpopHttpClient, DpopHttpResponse,
    ManagedCoreError, ManagedCoreLimits, ModernHttpRequest, WaitBounds, check_live,
    decode_response,
};
use crate::http_auth::rpc::admit_http_notification;
use crate::http_auth::caller::with_caller;
use crate::session::{ClientExtensionResultAdmission, ClientExtensionRuntime};

/// Immutable local extension configuration, without credentials or peer state.
///
/// This wraps the same descriptor/settings runtime used by `ClientBuilder`.
/// Every operation receives a fresh resolver from the factory and negotiates
/// against its own authenticated discovery. Cloning configuration cannot share
/// a mutable resolver or confer authority from an earlier request.
#[derive(Clone, Debug)]
pub struct DpopExtensionConfiguration {
    runtime: Arc<ClientExtensionRuntime>,
}

impl DpopExtensionConfiguration {
    /// Validates and freezes descriptors and explicit local settings before I/O.
    /// The factory must return an independent resolver for each negotiation.
    /// Factories and resolvers must be brief and nonblocking. Invocation runs
    /// inside the caller's effect ceiling; panic rejects negotiation without
    /// retaining its payload. The host's global panic hook remains its own.
    pub fn new<F, R>(
        descriptors: ExtensionDescriptorRegistry,
        client_discovery: ClientExtensionDiscovery,
        resolver_factory: F,
    ) -> McpResult<Self>
    where
        F: Fn() -> R + Send + Sync + 'static,
        R: ExtensionSettingsCompatibilityResolver + Send + 'static,
    {
        Ok(Self {
            runtime: Arc::new(ClientExtensionRuntime::new(
                descriptors,
                client_discovery,
                resolver_factory,
            )?),
        })
    }
}

/// One explicit operation with distinct discovery and operation identities.
///
/// IDs correlate responses; they are not idempotency keys. This value is neither
/// Clone nor Debug and is consumed once. Construct a new operation for every
/// explicit invocation. Construction performs no network or cryptographic work.
pub struct DpopExtensionOperation {
    discovery_id: RequestId,
    operation_id: RequestId,
    extension_id: ExtensionId,
    method: String,
    parameters: Value,
}

impl DpopExtensionOperation {
    pub fn new(
        discovery_id: RequestId,
        operation_id: RequestId,
        extension_id: ExtensionId,
        method: impl Into<String>,
        parameters: Value,
    ) -> Result<Self, ManagedCoreError> {
        discovery_id.validate().map_err(|_| ManagedCoreError::InvalidRequest)?;
        operation_id.validate().map_err(|_| ManagedCoreError::InvalidRequest)?;
        if discovery_id.correlates_with(&operation_id)
            || !parameters.is_object()
            || parameters.get("_meta").is_some_and(|value| !value.is_object())
        {
            return Err(ManagedCoreError::InvalidRequest);
        }
        Ok(Self {
            discovery_id,
            operation_id,
            extension_id,
            method: method.into(),
            parameters,
        })
    }
}

/// An admitted, completed result published under its original credential.
///
/// Open members and exact number lexemes remain available in the raw source.
/// Result metadata cannot grant another extension, Tasks, or continuation
/// authority. No credential or live request is retained.
pub struct DpopExtensionResult {
    request_id: RequestId,
    result: Value,
    raw_result_source: String,
}

impl fmt::Debug for DpopExtensionResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("DpopExtensionResult")
            .field("result_bytes", &self.raw_result_source.len())
            .finish_non_exhaustive()
    }
}

impl DpopExtensionResult {
    #[must_use]
    pub fn request_id(&self) -> &RequestId { &self.request_id }

    #[must_use]
    pub fn result(&self) -> &Value { &self.result }

    #[must_use]
    pub fn raw_result_source(&self) -> &str { &self.raw_result_source }

    #[must_use]
    pub fn into_result(self) -> Value { self.result }
}

// Local preparation retains no negotiated receipt. Both bounded wire bodies
// and their metadata are admitted before signing or sending discovery.
struct Prepared {
    runtime: Arc<ClientExtensionRuntime>,
    extension_id: ExtensionId,
    method: String,
    discovery_wire: ModernHttpRequest,
    discovery_decoder: CoreDecoder,
    operation_wire: ModernHttpRequest,
    operation_id: RequestId,
    progress: Option<ProgressMarker>,
    limits: ManagedCoreLimits,
}

fn wire(
    target: &str,
    method: &str,
    id: &RequestId,
    parameters: Value,
    maximum: usize,
) -> Result<ModernHttpRequest, ManagedCoreError> {
    let mut writer = BoundedWriter { bytes: Vec::new(), maximum };
    serde_json::to_writer(&mut writer, &json!({
        "jsonrpc":"2.0", "id":id, "method":method, "params":parameters,
    })).map_err(|_| ManagedCoreError::RequestTooLarge)?;
    ModernHttpRequest::new(target, writer.bytes, FINAL_PROTOCOL_VERSION, method, None)
        .map_err(|_| ManagedCoreError::InvalidRequest)
}

impl Prepared {
    fn new(
        target: &str,
        configuration: &DpopExtensionConfiguration,
        metadata: FinalRequestMeta,
        operation: DpopExtensionOperation,
        limits: ManagedCoreLimits,
        native_maximum: usize,
    ) -> Result<Self, ManagedCoreError> {
        configuration.runtime
            .admit_local_method(&operation.extension_id, &operation.method)
            .map_err(|_| ManagedCoreError::UnsupportedRequest)?;
        if metadata.protocol_version != FINAL_PROTOCOL_VERSION
            || [FINAL_PROTOCOL_VERSION_META_KEY, FINAL_CLIENT_CAPABILITIES_META_KEY,
                FINAL_CLIENT_INFO_META_KEY].iter()
                .any(|key| metadata.additional_metadata.contains_key(*key))
        {
            return Err(ManagedCoreError::InvalidRequest);
        }
        let mut metadata = serde_json::to_value(metadata)
            .map_err(|_| ManagedCoreError::InvalidRequest)?;
        let capabilities = metadata.get_mut(FINAL_CLIENT_CAPABILITIES_META_KEY)
            .and_then(Value::as_object_mut).ok_or(ManagedCoreError::InvalidRequest)?;
        if capabilities.get("extensions")
            .is_some_and(|value| !value.as_object().is_some_and(serde_json::Map::is_empty))
        {
            return Err(ManagedCoreError::UnsupportedRequest);
        }
        capabilities.insert("extensions".to_owned(),
            serde_json::to_value(configuration.runtime.client_wire_extensions())
                .map_err(|_| ManagedCoreError::InvalidRequest)?);

        let maximum = limits.request_bytes().min(native_maximum);
        let discovery = CoreRequest::decode(
            ProtocolEra::Modern2026, "server/discover", Some(&json!({"_meta":metadata})),
        ).map_err(|_| ManagedCoreError::InvalidRequest)?;
        let discovery_parameters = discovery.encode_params()
            .map_err(|_| ManagedCoreError::InvalidRequest)?
            .ok_or(ManagedCoreError::InvalidRequest)?;
        let discovery_wire = wire(target, "server/discover", &operation.discovery_id,
            discovery_parameters, maximum)?;
        let discovery_decoder = CoreDecoder::for_request(discovery, operation.discovery_id, limits)?;

        let mut parameters = operation.parameters;
        let object = parameters.as_object_mut().ok_or(ManagedCoreError::InvalidRequest)?;
        let metadata_object = metadata.as_object_mut().ok_or(ManagedCoreError::InvalidRequest)?;
        if let Some(extra) = object.remove("_meta") {
            let extra = extra.as_object().ok_or(ManagedCoreError::InvalidRequest)?;
            for (name, value) in extra {
                if metadata_object.get(name).is_some_and(|previous| previous != value)
                    || (name == FINAL_CLIENT_INFO_META_KEY && !metadata_object.contains_key(name))
                {
                    return Err(ManagedCoreError::InvalidRequest);
                }
                metadata_object.insert(name.clone(), value.clone());
            }
        }
        // Reuse the final request metadata grammar without promoting a core
        // method or synthetic discovery result into extension authority.
        CoreRequest::decode(
            ProtocolEra::Modern2026, "server/discover", Some(&json!({"_meta":metadata})),
        ).map_err(|_| ManagedCoreError::InvalidRequest)?;
        let progress = metadata.get("progressToken")
            .map(|value| serde_json::from_value(value.clone())
                .map_err(|_| ManagedCoreError::InvalidRequest))
            .transpose()?;
        object.insert("_meta".to_owned(), metadata);
        let operation_wire = wire(target, &operation.method, &operation.operation_id,
            parameters, maximum)?;
        Ok(Self {
            runtime: Arc::clone(&configuration.runtime),
            extension_id: operation.extension_id,
            method: operation.method,
            discovery_wire,
            discovery_decoder,
            operation_wire,
            operation_id: operation.operation_id,
            progress,
            limits,
        })
    }

    fn admit(mut self, response: DpopHttpResponse)
        -> Result<(ModernHttpRequest, ExtensionDecoder), DpopStreamError>
    {
        let result = decode_response(&mut self.discovery_decoder, response)?;
        let CoreResult::Final(FinalCoreResult::Discover(discovery)) = result else {
            return Err(ManagedCoreError::InvalidResponse.into());
        };
        if !discovery.supported_versions().iter().any(|version| version == FINAL_PROTOCOL_VERSION) {
            return Err(ManagedCoreError::UnsupportedRequest.into());
        }
        let negotiated = self.runtime.negotiate(&discovery)
            .map_err(|_| ManagedCoreError::UnsupportedRequest)?;
        let admission = self.runtime.admit_request(&negotiated, &self.extension_id, &self.method)
            .map_err(|_| ManagedCoreError::UnsupportedRequest)?;
        let (bytes, notifications) = self.discovery_decoder.usage();
        if bytes >= self.limits.total_bytes() {
            return Err(ManagedCoreError::ResponseByteLimit.into());
        }
        Ok((self.operation_wire, ExtensionDecoder {
            admission,
            id: self.operation_id,
            limits: self.limits,
            bytes,
            notifications,
            progress: self.progress,
            last_progress: None,
            terminal: false,
        }))
    }
}

// Only authenticated discovery can construct this request-owned authority.
// The shared transport reader owns all socket and observer lifetime behavior.
struct ExtensionDecoder {
    admission: ClientExtensionResultAdmission,
    id: RequestId,
    limits: ManagedCoreLimits,
    bytes: usize,
    notifications: usize,
    progress: Option<ProgressMarker>,
    last_progress: Option<ExactNonNegativeJsonNumber>,
    terminal: bool,
}

impl StreamDecoder for ExtensionDecoder {
    type Terminal = DpopExtensionResult;

    fn admit(&mut self, frame: &[u8], allow_notification: bool)
        -> Result<StreamEvent<Self::Terminal>, DpopStreamError>
    {
        if self.terminal {
            return Err(ManagedCoreError::InvalidResponse.into());
        }
        let maximum = self.limits.frame_bytes()
            .min(self.limits.total_bytes().saturating_sub(self.bytes));
        if frame.len() > maximum {
            return Err(ManagedCoreError::ResponseByteLimit.into());
        }
        let message = decode_strict_jsonrpc_message(frame, maximum)
            .map_err(|_| ManagedCoreError::InvalidResponse)?;
        let event = match message {
            JsonRpcMessage::Response(_) => {
                let admitted = decode_strict_jsonrpc_response(frame, maximum)
                    .map_err(|_| ManagedCoreError::InvalidResponse)?;
                let (response, source) = admitted.into_parts();
                if !response.id.as_ref().is_some_and(|id| id.correlates_with(&self.id)) {
                    return Err(ManagedCoreError::ResponseIdMismatch.into());
                }
                if let Some(error) = response.error {
                    return Err(ManagedCoreError::Remote { code: error.code }.into());
                }
                let raw_result_source = source.ok_or(ManagedCoreError::InvalidResult)?;
                self.admission.decode_result(&raw_result_source)
                    .map_err(|_| ManagedCoreError::InvalidResult)?;
                let result = response.result.ok_or(ManagedCoreError::InvalidResult)?;
                self.terminal = true;
                StreamEvent::Result(DpopExtensionResult {
                    request_id: self.id.clone(), result, raw_result_source,
                })
            }
            JsonRpcMessage::Request(request) => {
                if !allow_notification || request.id.is_some() {
                    return Err(ManagedCoreError::UnexpectedNotification.into());
                }
                if self.notifications >= self.limits.notifications() {
                    return Err(ManagedCoreError::NotificationLimit.into());
                }
                let notification = admit_http_notification(
                    frame, &request, self.progress.as_ref(), self.last_progress.as_ref(),
                )?;
                if let ServerNotification::Progress(progress) = &notification {
                    self.last_progress = Some(progress.progress.clone());
                }
                self.notifications += 1;
                StreamEvent::Notification(Box::new(notification))
            }
        };
        self.bytes += frame.len();
        Ok(event)
    }

    fn usage(&self) -> (usize, usize) { (self.bytes, self.notifications) }
}

impl DpopHttpClient {
    /// Completes one registered extension request after fresh authenticated discovery.
    ///
    /// JSON and SSE replies share the same decoder. Valid request notifications
    /// are consumed under the supplied bounds; use the event variant to observe
    /// them incrementally. An input-required value is returned without a retry.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_final_extension(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        configuration: &DpopExtensionConfiguration,
        metadata: FinalRequestMeta,
        operation: DpopExtensionOperation,
        limits: DpopStreamLimits,
    ) -> Result<DpopExtensionResult, DpopStreamError> {
        self.request_final_extension_with_events(
            cx, cancellation, credential, configuration, metadata, operation, limits, |_| true,
        ).await
    }

    /// Executes discovery followed by exactly one admitted extension operation.
    ///
    /// Both POSTs use the same resource, credential, and original deadline with
    /// fresh DPoP proofs. Registry ownership, direction, local enablement, both
    /// request byte bounds, and metadata are checked before discovery. Only that
    /// discovery can admit the operation and freeze its result discriminator.
    /// Supply extension-free final metadata; the registry stamps its settings.
    /// Operation `_meta` fields may add open metadata but cannot conflict with
    /// that canonical metadata or acquire additional capability authority.
    ///
    /// The aggregate payload budget includes discovery and every operation
    /// frame. Native body and SSE framing caps remain independent. The idle
    /// budget begins before discovery; only matching, increasing progress can
    /// reset it. Credential expiry and the original absolute bound never move.
    /// Results remain provisional until clean EOF and a final lifetime check.
    /// This observer receives core notifications only. Custom extension
    /// notifications require a different consumer and are refused here.
    ///
    /// The observer must be brief and nonblocking. It returns false to stop;
    /// panic, cancellation, expiry, revocation, and drop release this response.
    /// No automatic retry, refresh, challenge replay, remote cancellation, Apps
    /// Host, or Tasks lifecycle is introduced. Committed effects and previously
    /// delivered notifications cannot be recalled by later cancellation.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_final_extension_with_events<N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        configuration: &DpopExtensionConfiguration,
        metadata: FinalRequestMeta,
        operation: DpopExtensionOperation,
        limits: DpopStreamLimits,
        mut observer: N,
    ) -> Result<DpopExtensionResult, DpopStreamError>
    where
        N: FnMut(&ServerNotification) -> bool,
    {
        let bounds = WaitBounds::new(cx, self.policy.timeout.min(limits.core.timeout()), credential)?;
        let idle = Idle::new(cx.now(), limits.idle);
        check_live(cx, cancellation, &self.session, credential, idle.bounds(bounds))?;
        let prepared = Prepared::new(
            self.resource().as_str(), configuration, metadata, operation,
            limits.core, self.policy.max_body_bytes,
        );
        check_live(cx, cancellation, &self.session, credential, idle.bounds(bounds))?;
        let prepared = prepared?;
        let response = self.post_resource_with_bounds(
            cx, cancellation, credential, &prepared.discovery_wire, idle.bounds(bounds),
        ).await?;
        check_live(cx, cancellation, &self.session, credential, idle.bounds(bounds))?;
        // The resolver factory and resolver are caller code. Select the
        // supplied identity while intersecting ambient effects, contain panic,
        // and let same-poll cancellation/revocation win before any second POST.
        let admitted = with_caller(cx, || {
            catch_unwind(AssertUnwindSafe(|| prepared.admit(response)))
        });
        check_live(cx, cancellation, &self.session, credential, idle.bounds(bounds))?;
        let (wire, decoder) = admitted.map_err(|_| ManagedCoreError::UnsupportedRequest)??;
        let outcome = self.execute_prepared_core_stream(
            cx, cancellation, credential,
            PreparedStream { wire, decoder, limits, bounds, idle }, &mut observer,
        ).await;
        // Apply the outer owner check to error publication too. A decoder or
        // callback failure cannot bypass cancellation or original token expiry.
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        outcome.map(|completed| completed.result)
    }
}

#[cfg(test)]
mod tests;
