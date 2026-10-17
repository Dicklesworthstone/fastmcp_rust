//! One explicit DPoP POST with incremental, strictly admitted notifications.
//!
//! Uses the native HTTP body and the shared SSE/core codecs, not a second
//! event-stream dialect. A final result is retained until clean HTTP EOF;
//! a second result, later notification or unfinished SSE tail rejects it.
//! Subscription decoders alone may admit the complementary teardown signal.
//! No response owner, proof, raw cursor or credential escapes to the observer.

/// Streaming multi-round operations with an explicitly supplied typed input host.
pub mod interaction;
/// Acknowledged and filter-bound core subscriptions over explicit DPoP HTTPS.
pub mod subscription;
mod subscription_end;
/// Authenticated Tasks discovery and exact-ID status subscriptions.
#[cfg(feature = "tasks")]
pub mod task_subscription;
#[cfg(feature = "tasks")]
pub(super) mod budget;

use std::fmt;
use std::future::poll_fn;
use std::marker::PhantomData;
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
    pub(super) core: ManagedCoreLimits,
    sse: SseLimits,
    pub(super) idle: Duration,
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
    #[cfg(feature = "tasks")]
    Task(super::tasks::DpopTasksError),
    InvalidLimits,
    ObserverStopped,
    ObserverPanicked,
    /// The peer ended this subscription with notifications/cancelled. This
    /// is published only after clean EOF, not as a fabricated complete result.
    /// It does not mean a watched Task or the caller's context was cancelled.
    SubscriptionCancelled,
}

impl fmt::Display for DpopStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => error.fmt(f),
            #[cfg(feature = "tasks")]
            Self::Task(error) => error.fmt(f),
            Self::InvalidLimits => f.write_str("invalid DPoP core stream limits"),
            Self::ObserverStopped => f.write_str("DPoP core stream stopped by observer"),
            Self::ObserverPanicked => f.write_str("DPoP core stream observer panicked"),
            Self::SubscriptionCancelled => f.write_str("DPoP subscription ended by peer cancellation"),
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

#[cfg(feature = "tasks")]
impl From<super::tasks::DpopTasksError> for DpopStreamError {
    fn from(error: super::tasks::DpopTasksError) -> Self {
        match error {
            super::tasks::DpopTasksError::Core(error) => Self::Core(error),
            error => Self::Task(error),
        }
    }
}

// The prepared method owns both vocabularies. Extension notifications never
// become fabricated core notifications or grant authority to a core-only call.
pub(super) enum StreamEvent<T, E = ServerNotification> {
    Notification(Box<E>),
    Result(T),
}

// Only a decoder-admitted core progress event may extend the idle budget.
// Task statuses and subscription acknowledgements are not request progress.
pub(super) trait StreamNotification {
    fn is_progress(&self) -> bool {
        false
    }
}

impl StreamNotification for ServerNotification {
    fn is_progress(&self) -> bool {
        matches!(self, Self::Progress(_))
    }
}

impl From<ManagedCoreEvent> for StreamEvent<CoreResult> {
    fn from(event: ManagedCoreEvent) -> Self {
        match event {
            ManagedCoreEvent::Notification(notification) => Self::Notification(notification),
            ManagedCoreEvent::Result(result) => Self::Result(*result),
        }
    }
}

// Only private, already-admitted method decoders implement this seam.
// Method/filter admission stays with those codecs; socket, deadline,
// cancellation, framing and observer ownership stay with this reader.
pub(super) trait StreamDecoder<E: StreamNotification = ServerNotification> {
    type Terminal;

    fn admit(
        &mut self,
        frame: &[u8],
        allow_notification: bool,
    ) -> Result<StreamEvent<Self::Terminal, E>, DpopStreamError>;

    // Ordinary RPCs reject every post-terminal record. Only subscription
    // codecs may opt in to bounded admission of their complementary teardown
    // signal, with exact correlation and cumulative accounting. No callback
    // or replacement terminal can escape this seam.
    fn admit_terminal_tail(&mut self, _frame: &[u8]) -> Result<(), DpopStreamError> {
        Err(ManagedCoreError::InvalidResponse.into())
    }

    fn usage(&self) -> (usize, usize);
}

impl StreamDecoder for CoreDecoder {
    type Terminal = CoreResult;

    fn admit(
        &mut self,
        frame: &[u8],
        allow_notification: bool,
    ) -> Result<StreamEvent<CoreResult>, DpopStreamError> {
        CoreDecoder::admit(self, frame, allow_notification)
            .map(StreamEvent::from)
            .map_err(DpopStreamError::from)
    }

    fn usage(&self) -> (usize, usize) {
        CoreDecoder::usage(self)
    }
}

// An internal continuation can supply the original absolute deadline and a
// fresh decoder carrying cumulative usage. It cannot select another transport,
// credential or response parser. This is not a public retry capability.
pub(super) struct PreparedStream<D = CoreDecoder> {
    pub(super) wire: ModernHttpRequest,
    pub(super) decoder: D,
    pub(super) limits: DpopStreamLimits,
    pub(super) bounds: WaitBounds,
    pub(super) idle: Idle,
}

pub(super) struct CompletedStream<T = CoreResult> {
    pub(super) result: T,
    pub(super) usage: (usize, usize),
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

    // Ordinary, host-driven, subscription and Tasks calls execute here. A new
    // round never creates a new absolute deadline or resets the decoder's quotas.
    pub(super) async fn execute_prepared_core_stream<D, E, N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        prepared: PreparedStream<D>,
        observer: &mut N,
    ) -> Result<CompletedStream<D::Terminal>, DpopStreamError>
    where
        D: StreamDecoder<E>,
        E: StreamNotification,
        N: FnMut(&E) -> bool,
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
        let state = Reader::<D, E>::new(kind, decoder, limits, self.policy.max_body_bytes)?;
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

pub(super) struct Idle {
    deadline: Time,
    timeout: Duration,
}

impl Idle {
    pub(super) fn new(now: Time, timeout: Duration) -> Self {
        Self {
            deadline: now.saturating_add_nanos(u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX)),
            timeout,
        }
    }

    pub(super) fn bounds(&self, absolute: WaitBounds) -> WaitBounds {
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

struct Reader<D = CoreDecoder, E = ServerNotification>
where
    D: StreamDecoder<E>,
    E: StreamNotification,
{
    body: WireBody,
    decoder: D,
    terminal: Option<D::Terminal>,
    wire_remaining: usize,
    frame_limit: usize,
    reset_idle_on_progress: bool,
    notification: PhantomData<fn(&E)>,
}

impl<D, E> Reader<D, E>
where
    D: StreamDecoder<E>,
    E: StreamNotification,
{
    fn new(
        kind: ModernHttpResponseKind,
        decoder: D,
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
            notification: PhantomData,
        })
    }

    fn push<N: FnMut(&E) -> bool>(
        &mut self, bytes: &[u8], lifetime: &Lifetime<'_>, idle: &mut Idle, observer: &mut N,
    ) -> Result<(), DpopStreamError> {
        self.push_with_check(bytes, lifetime.cx, idle, observer, |idle| lifetime.check(idle))
    }

    // Private receive-side seam. The watch supplies the same caller, token,
    // owner revocation and deadline checks without borrowing the mutable nonce
    // owner. Grammar, byte limits, terminal custody and observers stay here.
    fn push_with_check<N, C>(
        &mut self, bytes: &[u8], cx: &Cx, idle: &mut Idle, observer: &mut N, mut check: C,
    ) -> Result<(), DpopStreamError>
    where
        N: FnMut(&E) -> bool,
        C: FnMut(&Idle) -> Result<(), DpopHttpError>,
    {
        check(idle)?;
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
                    check(idle)?;
                    if terminal.is_some() {
                        decoder.admit_terminal_tail(frame.as_bytes())?;
                        // A tolerated peer teardown cannot bypass the same
                        // lifetime guard used for every other admitted frame.
                        check(idle)?;
                        return Ok(());
                    }
                    let event = decoder.admit(frame.as_bytes(), true)?;
                    // Decoder work cannot revive a deadline that it exhausted.
                    check(idle)?;
                    match event {
                        StreamEvent::Result(result) => *terminal = Some(result),
                        StreamEvent::Notification(notification) => {
                            if reset_idle_on_progress && notification.is_progress() {
                                idle.progress(cx.now());
                            }
                            let observed = catch_unwind(AssertUnwindSafe(|| observer(&notification)));
                            // Same-poll cancellation/revocation wins over a ready
                            // observer, its decline, or its captured panic.
                            check(idle)?;
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
        check(idle)?;
        if exceeded {
            return Err(DpopHttpError::BodyTooLarge.into());
        }
        Ok(())
    }

    fn finish(self, lifetime: &Lifetime<'_>, idle: &Idle) -> Result<CompletedStream<D::Terminal>, DpopStreamError> {
        self.finish_with_check(idle, |idle| lifetime.check(idle))
    }

    fn finish_with_check<C>(
        mut self, idle: &Idle, mut check: C,
    ) -> Result<CompletedStream<D::Terminal>, DpopStreamError>
    where
        C: FnMut(&Idle) -> Result<(), DpopHttpError>,
    {
        check(idle)?;
        let result = match self.body {
            WireBody::Json(bytes) => match self.decoder.admit(&bytes, false)? {
                StreamEvent::Result(result) => result,
                StreamEvent::Notification(_) => {
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
        check(idle)?;
        Ok(CompletedStream { result, usage: self.decoder.usage() })
    }
}

async fn consume<B, N, D, E>(
    mut body: B, lifetime: &Lifetime<'_>, mut idle: Idle, mut reader: Reader<D, E>, observer: &mut N,
) -> Result<CompletedStream<D::Terminal>, DpopStreamError>
where
    B: Body + Unpin,
    B::Data: Buf,
    N: FnMut(&E) -> bool,
    D: StreamDecoder<E>,
    E: StreamNotification,
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
