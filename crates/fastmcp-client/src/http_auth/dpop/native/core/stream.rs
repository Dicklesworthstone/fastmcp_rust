//! One explicit DPoP POST with incremental, strictly admitted notifications.
//!
//! Uses the native HTTP body and the shared SSE/core codecs, not a second
//! event-stream dialect. A final result is retained until clean HTTP EOF;
//! a second result, later notification or unfinished SSE tail rejects it.
//! No response owner, proof, raw cursor or credential escapes to the observer.

/// Streaming multi-round operations with an explicitly supplied typed input host.
pub mod interaction;

use std::fmt;
use std::future::poll_fn;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use asupersync::Cx;
use asupersync::bytes::Buf;
use asupersync::http::body::Body;
use asupersync::http::h1::Method;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{CoreRequest, CoreResult, RequestId, ServerNotification};

use super::super::{
    DpopCredential, DpopHttpClient, DpopHttpError, DpopSession, WaitBounds, check_live,
    require_runtime, resource_headers, within,
};
use super::{DpopCoreError, ModernHttpRequest, prepare};
use crate::http_auth::caller::with_caller;
use crate::http_auth::rpc::{CoreDecoder, ManagedCoreError, ManagedCoreEvent, ManagedCoreLimits};
use crate::http_executor::{MODERN_MCP_ACCEPT, ModernHttpResponseKind, validate_response_head};
use crate::sse::{BoundedSseParser, SseLimits, SsePushError};

// Bound ready-body work independently from retained bytes. Neither many empty
// frames nor one large buffer may monopolize a caller-owned executor. A single
// admitted JSON frame is still decoded synchronously under the core byte cap.
const BYTES_PER_TURN: usize = 32 * 1024;
const FRAMES_PER_TURN: usize = 32;

/// Independent core, parser and no-progress limits for one explicit exchange.
/// The native DPoP policy still bounds the complete HTTP body, including SSE
/// comments and framing; core payload limits do not replace that wire cap.
#[derive(Clone, Copy, Debug)]
pub struct DpopStreamLimits {
    core: ManagedCoreLimits,
    sse: SseLimits,
    idle: Duration,
    reset_idle_on_progress: bool,
}

impl Default for DpopStreamLimits {
    fn default() -> Self {
        Self {
            core: ManagedCoreLimits::default(),
            sse: SseLimits::with_data_lines(64 * 1024, 8 * 1024 * 1024, 1024, 4096)
                .expect("nonzero fixed SSE bounds"),
            idle: Duration::from_secs(30),
            reset_idle_on_progress: true,
        }
    }
}

impl DpopStreamLimits {
    /// Idle is nonzero and cannot exceed the core absolute timeout. Unlike a
    /// post-send timer, this conservative budget starts before preparation and
    /// therefore also bounds DNS, TLS and response-head acquisition. Only valid,
    /// matching, strictly increasing progress can reset it; never the absolute
    /// deadline. Bytes, comments, headers and other notifications cannot reset it.
    pub fn new(core: ManagedCoreLimits, idle: Duration) -> Result<Self, DpopStreamError> {
        if idle.is_zero() || idle > core.timeout() {
            return Err(DpopStreamError::InvalidLimits);
        }
        Ok(Self {
            core,
            // SSE bounds include raw `data:` fields and the parser's appended
            // LF. They are not the JSON payload limit: equating the two would
            // reject an otherwise valid exact-sized core frame before decoding.
            sse: SseLimits::with_data_lines(64 * 1024, 8 * 1024 * 1024, 1024, 4096)
                .ok_or(DpopStreamError::InvalidLimits)?,
            idle,
            reset_idle_on_progress: true,
        })
    }

    /// Disable progress-based idle extension for a stricter fixed idle budget.
    /// Enabling it still cannot extend the original absolute or token deadline.
    pub fn with_progress_idle_reset(mut self, enabled: bool) -> Self {
        self.reset_idle_on_progress = enabled;
        self
    }

    /// Choose finite parser limits. Raw event bytes have an 8 MiB ceiling;
    /// line bytes, keepalive lines and data lines have independent ceilings.
    /// These include SSE syntax overhead, unlike the core JSON frame limit.
    pub fn with_sse_limits(mut self, sse: SseLimits) -> Result<Self, DpopStreamError> {
        if sse.max_line_bytes() > 1024 * 1024
            || sse.max_event_bytes() > 8 * 1024 * 1024
            || sse.max_keepalive_lines() > 65_536
            || sse.max_data_lines() > 65_536
        {
            return Err(DpopStreamError::InvalidLimits);
        }
        self.sse = sse;
        Ok(self)
    }
}

/// Fixed observer failures never retain observer text or a panic payload.
/// The host's process-global panic hook remains outside this library's control.
#[derive(Debug)]
pub enum DpopStreamError {
    Core(DpopCoreError),
    InvalidLimits,
    ObserverStopped,
    ObserverPanicked,
}

impl fmt::Display for DpopStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => error.fmt(f),
            Self::InvalidLimits => f.write_str("invalid DPoP core stream limits"),
            Self::ObserverStopped => f.write_str("DPoP core stream stopped by observer"),
            Self::ObserverPanicked => f.write_str("DPoP core stream observer panicked"),
        }
    }
}

impl std::error::Error for DpopStreamError {}

impl From<DpopCoreError> for DpopStreamError {
    fn from(error: DpopCoreError) -> Self {
        Self::Core(error)
    }
}

impl From<DpopHttpError> for DpopStreamError {
    fn from(error: DpopHttpError) -> Self {
        Self::Core(error.into())
    }
}

impl From<ManagedCoreError> for DpopStreamError {
    fn from(error: ManagedCoreError) -> Self {
        Self::Core(error.into())
    }
}

// An internal continuation can supply the original absolute deadline and a
// fresh decoder carrying cumulative usage. It cannot select another transport,
// credential or response parser. This is not a public retry capability.
struct PreparedStream {
    wire: ModernHttpRequest,
    decoder: CoreDecoder,
    limits: DpopStreamLimits,
    bounds: WaitBounds,
    idle: Idle,
}

struct CompletedStream {
    result: CoreResult,
    usage: (usize, usize),
}

impl DpopHttpClient {
    /// Perform one HTTPS core request and deliver notifications as they arrive.
    /// `observer` returns true to continue or false to stop. It must be brief,
    /// nonblocking and apply its own disclosure policy to peer-controlled data.
    /// Observations already delivered cannot be recalled after a later failure.
    ///
    /// Both JSON and SSE are advertised. The shared decoder validates exact
    /// correlation, progress, known result fields and open-field preservation.
    /// Complete and input-required remain separate typed terminal branches.
    /// No Tasks negotiation, automatic continuation, OAuth login, refresh,
    /// retry, redirect or event-history buffer is introduced. The existing
    /// JSON-only APIs are unchanged.
    ///
    /// Preparation, headers, body, observer work and EOF share the original
    /// credential/deadline. Cancellation or drop disposes the owned socket;
    /// no automatic remote cancellation POST is sent.
    /// Ready body processing yields after bounded byte/frame quanta without
    /// resetting either deadline or moving work to another task or runtime.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_core_with_events<N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        request: CoreRequest,
        request_id: RequestId,
        limits: DpopStreamLimits,
        mut observer: N,
    ) -> Result<CoreResult, DpopStreamError>
    where
        N: FnMut(&ServerNotification) -> bool,
    {
        let bounds = WaitBounds::new(cx, self.policy.timeout.min(limits.core.timeout()), credential)?;
        let lifetime = Lifetime { cx, cancellation, session: &self.session, credential, bounds };
        let idle = Idle::new(cx.now(), limits.idle);
        with_caller(cx, || lifetime.check(&idle))?;
        let (wire, decoder) = prepare(
            self.resource().as_str(), request, request_id, limits.core, self.policy.max_body_bytes,
        )?;
        self.execute_prepared_core_stream(
            cx, cancellation, credential,
            PreparedStream { wire, decoder, limits, bounds, idle }, &mut observer,
        ).await.map(|completed| completed.result)
    }

    // Both one-shot and host-driven calls execute here. A new network round
    // never creates a new absolute deadline or resets the decoder's quotas.
    async fn execute_prepared_core_stream<N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        prepared: PreparedStream,
        observer: &mut N,
    ) -> Result<CompletedStream, DpopStreamError>
    where
        N: FnMut(&ServerNotification) -> bool,
    {
        let PreparedStream { wire, decoder, limits, bounds, idle } = prepared;
        let lifetime = Lifetime { cx, cancellation, session: &self.session, credential, bounds };
        with_caller(cx, || lifetime.check(&idle))?;
        // Signing and header construction occur only after effective runtime
        // admission, inside the same guard as the first transport poll.
        let response = within(
            cx, cancellation, &self.session, credential, idle.bounds(bounds),
            async {
                let mut headers = resource_headers(&self.session, credential, &wire, &self.policy)?;
                for (name, value) in &mut headers {
                    if name.eq_ignore_ascii_case("Accept") {
                        *value = MODERN_MCP_ACCEPT.to_owned();
                    }
                }
                let body = wire.body().to_vec();
                check_live(cx, cancellation, &self.session, credential, idle.bounds(bounds))?;
                self.transport.request_streaming(
                    cx, Method::Post, self.session.resource.as_str(), headers, body,
                ).await.map_err(|_| DpopHttpError::TransportFailed)
            },
        ).await?;

        // Use the same media, encoding and forbidden-header admission as the
        // native MCP executor. No sniffing or independently invented SSE type.
        let kind = with_caller(cx, || -> Result<_, DpopStreamError> {
            lifetime.check(&idle)?;
            let metadata = validate_response_head(response.head.status, &response.head.headers)
                .map_err(|_| DpopHttpError::InvalidResponseHeaders)?;
            lifetime.check(&idle)?;
            Ok(metadata.kind())
        })?;
        // Header nonce admission needs a short mutable session borrow, outside
        // the immutable lifetime guard. No await, callback or I/O occurs here.
        let source = self.session.resource.clone();
        self.session.observe_resource_nonce(&source, &response.head.headers)
            .map_err(DpopHttpError::from)?;
        let lifetime = Lifetime { cx, cancellation, session: &self.session, credential, bounds };
        with_caller(cx, || lifetime.check(&idle))?;
        if response.head.status != 200 {
            return Err(ManagedCoreError::HttpStatus { status: response.head.status }.into());
        }
        let state = Reader::new(kind, decoder, limits, self.policy.max_body_bytes)?;
        consume(response.body, &lifetime, idle, state, observer).await
    }
}

struct Lifetime<'a> {
    cx: &'a Cx,
    cancellation: &'a McpRequestCancellation,
    session: &'a DpopSession,
    credential: &'a DpopCredential,
    bounds: WaitBounds,
}

impl Lifetime<'_> {
    fn check(&self, idle: &Idle) -> Result<(), DpopHttpError> {
        check_live(
            self.cx, self.cancellation, self.session, self.credential, idle.bounds(self.bounds),
        )?;
        require_runtime(self.cx)
    }
}

struct Idle {
    deadline: Time,
    timeout: Duration,
}

impl Idle {
    fn new(now: Time, timeout: Duration) -> Self {
        Self {
            deadline: now.saturating_add_nanos(u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX)),
            timeout,
        }
    }

    fn bounds(&self, absolute: WaitBounds) -> WaitBounds {
        if self.deadline < absolute.deadline {
            WaitBounds { deadline: self.deadline, terminal: DpopHttpError::TimedOut }
        } else {
            absolute
        }
    }

    fn progress(&mut self, now: Time) {
        self.deadline = now.saturating_add_nanos(
            u64::try_from(self.timeout.as_nanos()).unwrap_or(u64::MAX),
        );
    }
}

enum WireBody {
    Json(Vec<u8>),
    Sse(BoundedSseParser),
}

struct Reader {
    body: WireBody,
    decoder: CoreDecoder,
    terminal: Option<CoreResult>,
    wire_remaining: usize,
    frame_limit: usize,
    reset_idle_on_progress: bool,
}

impl Reader {
    fn new(
        kind: ModernHttpResponseKind,
        decoder: CoreDecoder,
        limits: DpopStreamLimits,
        wire_limit: usize,
    ) -> Result<Self, DpopStreamError> {
        let body = match kind {
            ModernHttpResponseKind::Json => WireBody::Json(Vec::new()),
            ModernHttpResponseKind::Sse => WireBody::Sse(BoundedSseParser::new(limits.sse)),
            _ => return Err(ManagedCoreError::InvalidResponse.into()),
        };
        // A resumed conversation can have less budget left than one frame.
        // Refuse JSON growth at that remaining budget, not only at EOF.
        let frame_limit = limits.core.frame_bytes().min(
            limits.core.total_bytes().saturating_sub(decoder.usage().0),
        );
        Ok(Self {
            body,
            decoder,
            terminal: None,
            wire_remaining: wire_limit,
            frame_limit,
            reset_idle_on_progress: limits.reset_idle_on_progress,
        })
    }

    fn push<N: FnMut(&ServerNotification) -> bool>(
        &mut self, bytes: &[u8], lifetime: &Lifetime<'_>, idle: &mut Idle, observer: &mut N,
    ) -> Result<(), DpopStreamError> {
        lifetime.check(idle)?;
        // Admit the same byte prefix regardless of HTTP frame boundaries. A
        // large native frame must not suppress notifications that a fragmented
        // delivery would have emitted before the raw-body cap was reached.
        let admitted = bytes.len().min(self.wire_remaining);
        let exceeded = admitted != bytes.len();
        let bytes = &bytes[..admitted];
        self.wire_remaining -= admitted;
        let reset_idle_on_progress = self.reset_idle_on_progress;
        match &mut self.body {
            WireBody::Json(buffer) => {
                if bytes.len() > self.frame_limit.saturating_sub(buffer.len()) {
                    return Err(ManagedCoreError::ResponseByteLimit.into());
                }
                buffer.extend_from_slice(bytes);
            }
            WireBody::Sse(parser) => {
                let decoder = &mut self.decoder;
                let terminal = &mut self.terminal;
                parser.push_with(bytes, |frame| {
                    lifetime.check(idle)?;
                    if terminal.is_some() {
                        return Err(ManagedCoreError::InvalidResponse.into());
                    }
                    let event = decoder.admit(frame.as_bytes(), true)?;
                    // Decoder work cannot revive a deadline that it exhausted.
                    lifetime.check(idle)?;
                    match event {
                        ManagedCoreEvent::Result(result) => *terminal = Some(*result),
                        ManagedCoreEvent::Notification(notification) => {
                            if reset_idle_on_progress
                                && matches!(&*notification, ServerNotification::Progress(_))
                            {
                                idle.progress(lifetime.cx.now());
                            }
                            let observed = catch_unwind(AssertUnwindSafe(|| observer(&notification)));
                            // Same-poll cancellation/revocation wins over a ready
                            // observer, its decline, or its captured panic.
                            lifetime.check(idle)?;
                            match observed {
                                Ok(true) => {}
                                Ok(false) => return Err(DpopStreamError::ObserverStopped),
                                Err(_) => return Err(DpopStreamError::ObserverPanicked),
                            }
                        }
                    }
                    Ok(())
                }).map_err(|error| match error {
                    SsePushError::Parse(_) => ManagedCoreError::InvalidResponse.into(),
                    SsePushError::Consumer(error) => error,
                })?;
            }
        }
        lifetime.check(idle)?;
        if exceeded {
            return Err(DpopHttpError::BodyTooLarge.into());
        }
        Ok(())
    }

    fn finish(mut self, lifetime: &Lifetime<'_>, idle: &Idle) -> Result<CompletedStream, DpopStreamError> {
        lifetime.check(idle)?;
        let result = match self.body {
            WireBody::Json(bytes) => match self.decoder.admit(&bytes, false)? {
                ManagedCoreEvent::Result(result) => *result,
                ManagedCoreEvent::Notification(_) => {
                    return Err(ManagedCoreError::UnexpectedNotification.into());
                }
            },
            WireBody::Sse(parser) => {
                let end = parser.finish().map_err(|_| ManagedCoreError::InvalidResponse)?;
                if end.discarded_pending_event || end.discarded_partial_line {
                    return Err(ManagedCoreError::InvalidResponse.into());
                }
                self.terminal.ok_or(ManagedCoreError::MissingTerminal)?
            }
        };
        lifetime.check(idle)?;
        Ok(CompletedStream { result, usage: self.decoder.usage() })
    }
}

async fn consume<B, N>(
    mut body: B, lifetime: &Lifetime<'_>, mut idle: Idle, mut reader: Reader, observer: &mut N,
) -> Result<CompletedStream, DpopStreamError>
where
    B: Body + Unpin,
    B::Data: Buf,
    N: FnMut(&ServerNotification) -> bool,
{
    let mut bytes_left = BYTES_PER_TURN;
    let mut frames_left = FRAMES_PER_TURN;
    loop {
        if bytes_left == 0 || frames_left == 0 {
            cooperate(lifetime, &idle).await?;
            bytes_left = BYTES_PER_TURN;
            frames_left = FRAMES_PER_TURN;
        }
        let frame = within(
            lifetime.cx, lifetime.cancellation, lifetime.session, lifetime.credential,
            idle.bounds(lifetime.bounds),
            async {
                poll_fn(|task| Pin::new(&mut body).poll_frame(task)).await
                    .transpose().map_err(|_| DpopHttpError::TransportFailed)
            },
        ).await?;
        let Some(frame) = frame else {
            return with_caller(lifetime.cx, || reader.finish(lifetime, &idle));
        };
        // Empty data and trailer frames consume scheduling budget too, even
        // though they cannot consume the raw-body byte budget.
        frames_left -= 1;
        let Some(mut data) = frame.into_data() else { continue };
        while data.has_remaining() {
            if bytes_left == 0 {
                cooperate(lifetime, &idle).await?;
                bytes_left = BYTES_PER_TURN;
                frames_left = FRAMES_PER_TURN;
            }
            let bytes = data.chunk();
            let consumed = bytes.len().min(bytes_left);
            if consumed == 0 {
                // A broken Buf must not spin forever without advancing.
                return Err(DpopHttpError::TransportFailed.into());
            }
            with_caller(lifetime.cx, || {
                reader.push(&bytes[..consumed], lifetime, &mut idle, observer)
            })?;
            data.advance(consumed);
            bytes_left -= consumed;
        }
    }
}

async fn cooperate(lifetime: &Lifetime<'_>, idle: &Idle) -> Result<(), DpopHttpError> {
    let mut yielded = false;
    within(
        lifetime.cx,
        lifetime.cancellation,
        lifetime.session,
        lifetime.credential,
        idle.bounds(lifetime.bounds),
        poll_fn(|task| {
            if yielded {
                Poll::Ready(Ok(()))
            } else {
                yielded = true;
                task.waker().wake_by_ref();
                Poll::Pending
            }
        }),
    )
    .await
}

#[cfg(test)]
mod tests;
