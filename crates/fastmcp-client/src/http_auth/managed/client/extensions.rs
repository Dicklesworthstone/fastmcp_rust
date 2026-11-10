//! Negotiated extension operations inside the managed credential lifetime.
//!
//! The ordinary HTTP client freezes request/result authority and owns each
//! response. This module keeps that owner inside the managed operation, bounds
//! event delivery, and publishes only completed values after the outer guards.

use std::fmt;
use std::io::{self, Write};

use asupersync::Cx;
use fastmcp_core::{McpError, McpErrorCode, McpRequestCancellation};
use fastmcp_protocol::extensions::validate_extension_notification_metadata;
use fastmcp_protocol::{ExtensionId, RequestId, ServerNotification};
use serde::Serialize;
use serde_json::Value;

use super::callbacks::CallbackBoundary;
use super::{Call, CallResult, ManagedHttpClient, ManagedHttpClientError};
use crate::http_executor::{ModernHttpExtensionEvent, ModernHttpFinalCoreListenError};
use crate::sse::SseLimits;
use crate::{
    ClientHttpConnectionError, HttpClient, HttpClientError, MAX_HTTP_EXECUTION_REQUEST_BYTES,
    catch_client_callback_unwind, measure_serialized_bytes,
};

const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = 128 * 1024 * 1024;
const MAX_NOTIFICATIONS: usize = 4_096;

/// Independent frame, aggregate payload, and notification bounds for one call.
///
/// The managed operation's deadline includes discovery, request execution, and
/// callbacks. The original credential expiry and native idle/absolute response
/// bounds still apply. These are encoded-byte limits, not heap-size estimates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedExtensionLimits {
    frame_bytes: usize,
    payload_bytes: usize,
    notifications: usize,
}

impl Default for ManagedExtensionLimits {
    fn default() -> Self {
        Self {
            frame_bytes: MAX_FRAME_BYTES,
            payload_bytes: 32 * 1024 * 1024,
            notifications: 64,
        }
    }
}

impl ManagedExtensionLimits {
    /// Frames are 1..=8 MiB; total payload is frame_bytes..=128 MiB;
    /// notifications are 0..=4096. Zero notifications selects terminal-only
    /// responses. The terminal result consumes bytes, not a notification slot.
    pub fn new(
        frame_bytes: usize,
        payload_bytes: usize,
        notifications: usize,
    ) -> Result<Self, ManagedHttpClientError> {
        if !(1..=MAX_FRAME_BYTES).contains(&frame_bytes)
            || !(frame_bytes..=MAX_PAYLOAD_BYTES).contains(&payload_bytes)
            || notifications > MAX_NOTIFICATIONS
        {
            return Err(ManagedHttpClientError::InvalidPolicy);
        }
        Ok(Self {
            frame_bytes,
            payload_bytes,
            notifications,
        })
    }
}

/// One completed extension result admitted under its original OAuth grant.
///
/// The parsed value and exact original result JSON are both retained. Numbers,
/// open members, and their spelling survive without promoting result metadata
/// into extension authority. No credential, client, or live response escapes.
pub struct ManagedExtensionResult {
    request_id: RequestId,
    result: Value,
    raw_result_source: String,
}

impl fmt::Debug for ManagedExtensionResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedExtensionResult")
            .field("result_bytes", &self.raw_result_source.len())
            .finish_non_exhaustive()
    }
}

impl ManagedExtensionResult {
    /// The JSON-RPC identity that owns this completed result.
    #[must_use]
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// The admitted parsed result, including its open extension members.
    #[must_use]
    pub fn result(&self) -> &Value {
        &self.result
    }

    /// The exact JSON source of the result member, with original number lexemes.
    #[must_use]
    pub fn raw_result_source(&self) -> &str {
        &self.raw_result_source
    }

    /// Consumes the completed result and returns its parsed value.
    #[must_use]
    pub fn into_result(self) -> Value {
        self.result
    }
}

type Observer<'a> = &'a mut (dyn FnMut(&ModernHttpExtensionEvent) + Send);

pub(super) struct ExtensionRequest<'a> {
    extension_id: &'a ExtensionId,
    method: &'a str,
    parameters: Value,
    limits: ManagedExtensionLimits,
    observer: Option<Observer<'a>>,
}

pub(super) struct ExtensionNotification<'a> {
    extension_id: &'a ExtensionId,
    method: &'a str,
    parameters: Value,
}

fn preflight_parameters(parameters: &Value) -> Result<(), ManagedHttpClientError> {
    if !parameters.is_object()
        || parameters
            .get("_meta")
            .is_some_and(|metadata| !metadata.is_object())
    {
        return Err(ManagedHttpClientError::InvalidPolicy);
    }
    measure_serialized_bytes(parameters, MAX_HTTP_EXECUTION_REQUEST_BYTES)
        .map_err(|_| ManagedHttpClientError::InvalidPolicy)?;
    Ok(())
}

fn refusal(message: &'static str) -> HttpClientError {
    HttpClientError::CoreResult(McpError::invalid_request(message))
}

fn response_error(error: ModernHttpFinalCoreListenError) -> HttpClientError {
    match error {
        ModernHttpFinalCoreListenError::ExtensionAdmission(error) => {
            HttpClientError::CoreResult(error)
        }
        ModernHttpFinalCoreListenError::RemoteError { code, .. } => {
            // Match the high-level client's bounded error-code vocabulary.
            // Never retain a remote message or data in managed diagnostics.
            HttpClientError::CoreResult(McpError::new(
                code.as_i32()
                    .map_or(McpErrorCode::InternalError, McpErrorCode::from),
                "Managed extension request failed",
            ))
        }
        error => HttpClientError::Connection(ClientHttpConnectionError::FinalCoreListen(error)),
    }
}

struct ByteBudget(usize);

impl Write for ByteBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("managed extension payload limit"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct EventBudget {
    notifications: usize,
    bytes: usize,
}

impl EventBudget {
    fn charge_notification(&mut self, value: &impl Serialize) -> Result<(), HttpClientError> {
        if self.notifications == 0 {
            return Err(refusal("Managed extension notification limit exceeded"));
        }
        let mut remaining = ByteBudget(self.bytes);
        serde_json::to_writer(&mut remaining, value)
            .map_err(|_| refusal("Managed extension payload limit exceeded"))?;
        self.bytes = remaining.0;
        self.notifications -= 1;
        Ok(())
    }

    fn charge_result(&mut self, source: &str) -> Result<(), HttpClientError> {
        self.bytes = self
            .bytes
            .checked_sub(source.len())
            .ok_or_else(|| refusal("Managed extension payload limit exceeded"))?;
        Ok(())
    }
}

impl ExtensionRequest<'_> {
    pub(super) async fn dispatch(
        mut self,
        cx: &Cx,
        client: &mut HttpClient,
        boundary: &CallbackBoundary,
    ) -> Result<ManagedExtensionResult, HttpClientError> {
        boundary.check(cx).map_err(HttpClientError::CoreResult)?;
        let limits = SseLimits::with_data_lines(
            self.limits.frame_bytes + 8,
            self.limits.frame_bytes,
            64,
            4_096,
        )
        .ok_or_else(|| refusal("Invalid managed extension framing limits"))?;
        let mut execution = client.execute_final_extension(
            cx,
            self.extension_id,
            self.method,
            self.parameters,
            limits,
        )?;
        let mut budget = EventBudget {
            notifications: self.limits.notifications,
            bytes: self.limits.payload_bytes,
        };
        loop {
            boundary.check(cx).map_err(HttpClientError::CoreResult)?;
            let event = execution
                .next_event(cx)
                .await
                .map_err(response_error)?
                .ok_or_else(|| refusal("Managed extension response ended without a result"))?;
            boundary.check(cx).map_err(HttpClientError::CoreResult)?;
            match &event {
                ModernHttpExtensionEvent::Progress(progress) => {
                    let wire = ServerNotification::Progress(progress.clone())
                        .encode()
                        .map_err(|_| refusal("Invalid managed extension progress"))?;
                    budget.charge_notification(&wire)?;
                }
                ModernHttpExtensionEvent::Notification(notification) => {
                    let wire = notification
                        .encode()
                        .map_err(|_| refusal("Invalid managed extension notification"))?;
                    budget.charge_notification(&wire)?;
                    // This owner consumes events directly. Invalidate cached
                    // results without filling an inaccessible shared queue.
                    client.final_result_cache.invalidate_notification(notification);
                }
                ModernHttpExtensionEvent::ExtensionNotification {
                    notification,
                    raw_params,
                } => {
                    #[derive(Serialize)]
                    struct NotificationWire<'a> {
                        jsonrpc: &'a str,
                        method: &'a str,
                        #[serde(skip_serializing_if = "Option::is_none")]
                        params: Option<&'a serde_json::value::RawValue>,
                    }
                    // Charge the exact retained params before invoking user
                    // code. Re-encoding Value would undercount whitespace and
                    // replace numeric source spellings in this byte budget.
                    let params = raw_params
                        .as_deref()
                        .map(serde_json::from_str::<&serde_json::value::RawValue>)
                        .transpose()
                        .map_err(|_| refusal("Invalid managed extension notification"))?;
                    budget.charge_notification(&NotificationWire {
                        jsonrpc: notification.jsonrpc.as_ref(),
                        method: &notification.method,
                        params,
                    })?;
                }
                ModernHttpExtensionEvent::Terminal(_) => {}
            }
            if let ModernHttpExtensionEvent::Terminal(result) = event {
                let source = execution
                    .raw_result_source()
                    .ok_or_else(|| refusal("Managed extension result omitted its exact source"))?;
                budget.charge_result(source)?;
                boundary.check(cx).map_err(HttpClientError::CoreResult)?;
                return Ok(ManagedExtensionResult {
                    request_id: execution.request_id().clone(),
                    result,
                    raw_result_source: source.to_owned(),
                });
            }
            if let Some(observer) = self.observer.as_deref_mut() {
                boundary.check(cx).map_err(HttpClientError::CoreResult)?;
                let observed = catch_client_callback_unwind(|| observer(&event));
                // A callback may close the session, revoke its original token,
                // or cancel this request in the same poll as buffered results.
                boundary.check(cx).map_err(HttpClientError::CoreResult)?;
                observed.map_err(|_| {
                    HttpClientError::CoreResult(McpError::internal_error(
                        "Managed extension observer failed",
                    ))
                })?;
            }
            asupersync::runtime::yield_now().await;
        }
    }
}

impl ExtensionNotification<'_> {
    pub(super) async fn dispatch(
        self,
        cx: &Cx,
        client: &mut HttpClient,
        boundary: &CallbackBoundary,
    ) -> Result<(), HttpClientError> {
        boundary.check(cx).map_err(HttpClientError::CoreResult)?;
        client
            .notify_final_extension(cx, self.extension_id, self.method, self.parameters)
            .await?;
        boundary.check(cx).map_err(HttpClientError::CoreResult)
    }
}

impl ManagedHttpClient {
    /// Executes one registered extension call under the original managed grant.
    ///
    /// Authenticated discovery negotiates the configured descriptor/settings;
    /// each request freezes its owner before the POST. JSON and SSE terminal
    /// results preserve their exact source. Progress and notifications are
    /// bounded and consumed; use the event variant to observe them live.
    /// No result cache, MRTR retry, or failed-call replay is introduced.
    pub async fn request_final_extension(
        &mut self,
        cx: &Cx,
        extension_id: &ExtensionId,
        method: &str,
        parameters: Value,
    ) -> Result<ManagedExtensionResult, ManagedHttpClientError> {
        self.request_final_extension_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            extension_id,
            method,
            parameters,
        )
        .await
    }

    /// Completes an extension call with cancellation isolated from the login.
    pub async fn request_final_extension_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        extension_id: &ExtensionId,
        method: &str,
        parameters: Value,
    ) -> Result<ManagedExtensionResult, ManagedHttpClientError> {
        self.perform_extension(
            cx,
            cancellation,
            ExtensionRequest {
                extension_id,
                method,
                parameters,
                limits: ManagedExtensionLimits::default(),
                observer: None,
            },
        )
        .await
    }

    /// Delivers bounded live progress and server notifications inside the grant.
    ///
    /// The observer receives nonterminal events only; the result is returned
    /// after cancellation, session closure, revocation, expiry, and deadline
    /// checks. A callback cannot retain a client or response owner. It must not
    /// block, and effects it already performed cannot be undone by a later
    /// failure. Callback panic is contained and retires the connection.
    ///
    /// Encoded notifications and the exact terminal result consume the total
    /// payload allowance. Core cache-invalidating notifications are applied to
    /// this client's cache before observation; no shared event queue is filled.
    pub async fn request_final_extension_with_events(
        &mut self,
        cx: &Cx,
        extension_id: &ExtensionId,
        method: &str,
        parameters: Value,
        limits: ManagedExtensionLimits,
        observer: &mut (dyn FnMut(&ModernHttpExtensionEvent) + Send),
    ) -> Result<ManagedExtensionResult, ManagedHttpClientError> {
        self.request_final_extension_with_events_and_cancellation(
            cx,
            &McpRequestCancellation::new(),
            extension_id,
            method,
            parameters,
            limits,
            observer,
        )
        .await
    }

    /// Event delivery with one caller-owned request cancellation domain.
    ///
    /// Cancelling from an observer suppresses all remaining buffered events and
    /// the result without cancelling sibling clients or the shared login.
    pub async fn request_final_extension_with_events_and_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        extension_id: &ExtensionId,
        method: &str,
        parameters: Value,
        limits: ManagedExtensionLimits,
        observer: &mut (dyn FnMut(&ModernHttpExtensionEvent) + Send),
    ) -> Result<ManagedExtensionResult, ManagedHttpClientError> {
        self.perform_extension(
            cx,
            cancellation,
            ExtensionRequest {
                extension_id,
                method,
                parameters,
                limits,
                observer: Some(observer),
            },
        )
        .await
    }

    async fn perform_extension(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        request: ExtensionRequest<'_>,
    ) -> Result<ManagedExtensionResult, ManagedHttpClientError> {
        self.extension_preflight(cx, cancellation, &request.parameters)?;
        match self
            .perform_any(cx, cancellation, Call::Extension(request))
            .await?
        {
            CallResult::Extension(result) => Ok(*result),
            _ => Err(ManagedHttpClientError::InvalidPolicy),
        }
    }

    /// Publishes one configured extension notification with its current proof.
    ///
    /// The ordinary client constructs activation proof from locally configured
    /// settings and rejects a conflicting caller proof. Authenticated discovery
    /// cannot substitute for the current message's proof. Success requires an
    /// empty native HTTP 202 acknowledgement; no request ID or retry is created.
    pub async fn notify_final_extension(
        &mut self,
        cx: &Cx,
        extension_id: &ExtensionId,
        method: &str,
        parameters: Value,
    ) -> Result<(), ManagedHttpClientError> {
        self.notify_final_extension_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            extension_id,
            method,
            parameters,
        )
        .await
    }

    /// Notification publication under request-local cancellation and the grant.
    pub async fn notify_final_extension_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        extension_id: &ExtensionId,
        method: &str,
        parameters: Value,
    ) -> Result<(), ManagedHttpClientError> {
        self.extension_preflight(cx, cancellation, &parameters)?;
        validate_extension_notification_metadata(&parameters)
            .map_err(|_| ManagedHttpClientError::InvalidPolicy)?;
        match self
            .perform_any(
                cx,
                cancellation,
                Call::ExtensionNotification(ExtensionNotification {
                    extension_id,
                    method,
                    parameters,
                }),
            )
            .await?
        {
            CallResult::ExtensionNotification => Ok(()),
            _ => Err(ManagedHttpClientError::InvalidPolicy),
        }
    }

    fn extension_preflight(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        parameters: &Value,
    ) -> Result<(), ManagedHttpClientError> {
        if self.closed {
            return Err(ManagedHttpClientError::Closed);
        }
        if let Err(error) = self.session.check(cx, cancellation) {
            // A lifecycle refusal retires prior state even when the supplied
            // parameters would independently fail structural preflight.
            self.connection = None;
            return Err(error.into());
        }
        preflight_parameters(parameters)
    }
}
