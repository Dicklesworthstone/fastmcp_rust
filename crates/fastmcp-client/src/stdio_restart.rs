//! Explicit, bounded recovery of an owned modern stdio subprocess.
//!
//! Recovery replaces a settled connection and repeats discovery. Explicitly
//! configured catalog subscriptions are re-established with fresh IDs and a
//! visible observation gap. It never repeats an application RPC or transfers a
//! request handle between generations. Applications must reconcile effects
//! before choosing to reissue.

use std::collections::VecDeque;
use std::fmt;
use std::future::{Future, poll_fn};
use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitStatus;
use std::sync::atomic::Ordering;
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use fastmcp_core::runtime::{CallerContextFuture, with_caller_context};
use fastmcp_core::{McpError, McpErrorCode, McpRequestCancellation, McpResult};
use fastmcp_protocol::RequestId;
use serde::{Deserialize, Serialize};

use crate::{
    Client, ClientBuilder, StdioSubscriptionEvent, SubscriptionListenRequest,
    SubscriptionTimeoutPolicy, is_cleanup_unverified,
};

const MAX_ATTEMPTS: u32 = 8;
const MAX_WINDOW: Duration = Duration::from_secs(300);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const CANCEL_SLICE: Duration = Duration::from_millis(25);

/// Validated finite restart limits for one supervised connection.
///
/// At most `max_attempts` replacement processes may be started in any `window`.
/// One recovery incident also has that elapsed deadline; cancelling or dropping
/// recovery does not reset it. Exhausting either bound opens this owner's
/// circuit permanently. A new owner requires a new explicit connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StdioRestartPolicy {
    max_attempts: u32,
    window: Duration,
    initial_backoff: Duration,
    max_backoff: Duration,
}

impl StdioRestartPolicy {
    /// Admits 1–8 attempts, a positive window of at most five minutes, and
    /// positive backoff bounds of at most thirty seconds inside that window.
    pub fn new(
        max_attempts: u32,
        window: Duration,
        initial_backoff: Duration,
        max_backoff: Duration,
    ) -> McpResult<Self> {
        if !(1..=MAX_ATTEMPTS).contains(&max_attempts)
            || window.is_zero()
            || window > MAX_WINDOW
            || initial_backoff.is_zero()
            || initial_backoff > max_backoff
            || max_backoff > MAX_BACKOFF
            || max_backoff > window
        {
            return Err(McpError::invalid_params(
                "Stdio restart requires 1–8 attempts, a positive window up to 300s, and 0 < initial backoff <= maximum backoff <= min(30s, window)",
            ));
        }
        Ok(Self {
            max_attempts,
            window,
            initial_backoff,
            max_backoff,
        })
    }

    #[must_use]
    pub const fn max_attempts(self) -> u32 {
        self.max_attempts
    }

    #[must_use]
    pub const fn window(self) -> Duration {
        self.window
    }

    #[must_use]
    pub const fn initial_backoff(self) -> Duration {
        self.initial_backoff
    }

    #[must_use]
    pub const fn max_backoff(self) -> Duration {
        self.max_backoff
    }
}

impl Default for StdioRestartPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            window: Duration::from_secs(60),
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
        }
    }
}

/// OS exit evidence obtained before FastMCP signals or reaps for cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StdioProcessExit {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

impl From<ExitStatus> for StdioProcessExit {
    fn from(status: ExitStatus) -> Self {
        Self {
            code: status.code(),
            signal: status.signal(),
        }
    }
}

/// An interrupted request's outcome is unknown and explicit reissue is required.
///
/// The server may have committed effects before the connection was lost. This evidence never
/// authorizes replay. It is attached to the terminal error delivered to every
/// outstanding request on the failed generation, including cloned executors.
/// An absent `process_exit` explicitly means natural exit has not been proven;
/// connection loss alone cannot authorize process recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StdioInterruptedRequest {
    pub generation: u64,
    /// Natural exit proof, when the connection owner observed it before cleanup.
    /// A send failure reaches pending handles before that OS probe, so those
    /// handles carry `None`. Missing proof never authorizes a replacement.
    pub process_exit: Option<StdioProcessExit>,
}

impl StdioInterruptedRequest {
    /// Reads local diagnostic data from a returned error. This is informational:
    /// peer errors can carry arbitrary data, so recovery uses private OS evidence
    /// rather than accepting this value as authority.
    #[must_use]
    pub fn from_error(error: &McpError) -> Option<Self> {
        let data = error.data.as_ref()?;
        let interruption = data
            .get("stdioInterruption")
            .or_else(|| data.get("operation")?.get("data")?.get("stdioInterruption"))?;
        if interruption.get("kind")?.as_str()? != "reissue_required"
            || interruption.get("outcome")?.as_str()? != "unknown"
        {
            return None;
        }
        serde_json::from_value(interruption.get("evidence")?.clone()).ok()
    }

    pub(super) fn into_error(self) -> McpError {
        McpError::with_data(
            McpErrorCode::InternalError,
            "Stdio connection lost; request outcome is unknown and explicit reissue is required",
            serde_json::json!({"stdioInterruption": {
                "kind": "reissue_required", "outcome": "unknown", "evidence": self,
            }}),
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum StdioRestartObservation {
    Active(u64),
    Exited {
        generation: u64,
        exit: StdioProcessExit,
    },
    /// Replacement discovery has no published process generation yet.
    Provisional,
    /// Proof survives the handshake's own close so its owner can decide whether
    /// a further attempt is admissible under the original recovery incident.
    ProvisionalExited {
        exit: StdioProcessExit,
    },
    Refused,
}

/// A local transport classification retained before terminal send fanout. Peer
/// error data never constructs this value, and it is not itself exit evidence.
#[derive(Clone, Copy, Debug)]
pub(crate) enum StdioDisconnectKind {
    Closed,
    BrokenPipe,
    ConnectionReset,
    UnexpectedEof,
}

impl StdioDisconnectKind {
    pub(crate) fn from_transport(error: &fastmcp_transport::TransportError) -> Option<Self> {
        use fastmcp_transport::TransportError;
        match error {
            TransportError::Closed => Some(Self::Closed),
            TransportError::Io(error) => match error.kind() {
                std::io::ErrorKind::BrokenPipe => Some(Self::BrokenPipe),
                std::io::ErrorKind::ConnectionReset => Some(Self::ConnectionReset),
                std::io::ErrorKind::UnexpectedEof => Some(Self::UnexpectedEof),
                _ => None,
            },
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct StdioSendDisconnect {
    pub(crate) generation: u64,
    pub(crate) kind: StdioDisconnectKind,
}

/// A configured listener was acknowledged on a replacement connection.
///
/// Events between these two IDs may have been lost. Applications must refresh
/// the affected catalogs/resources; this is not a replay or continuity receipt.
/// The old ID remains terminal. The replacement's acknowledgement is still the
/// first event returned by [`SupervisedStdioClient::next_subscription_event_with_cx`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdioSubscriptionRecovery {
    pub previous_subscription_id: RequestId,
    pub subscription_id: RequestId,
}

/// Emitted only after a new subprocess completes fresh modern discovery and
/// any configured catalog listener receives a valid acknowledgement.
/// All handles and subscriptions from `previous_generation` remain terminal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdioRecovery {
    pub previous_generation: u64,
    pub generation: u64,
    pub process_exit: StdioProcessExit,
    pub attempts: u32,
    /// A fresh listener, with an explicit gap requiring application resync.
    pub catalog_subscription: Option<StdioSubscriptionRecovery>,
}

/// A bounded supervision failure. No variant promises that an RPC had no effect.
#[derive(Clone, Debug)]
pub enum StdioRestartError {
    Configuration(McpError),
    Connection(McpError),
    Cleanup(McpError),
    /// A configured subscription could not be opened or restored.
    Subscription(McpError),
    /// Caller or request-local cancellation won; the same owner retains limits.
    Cancelled,
    /// No admissible natural exit was observed at the terminal I/O boundary.
    NotRestartable,
    /// Replacement discovery is pending; finish recovery before issuing work.
    RecoveryInProgress,
    AttemptsExhausted,
    WindowExpired,
    /// The supplied/ambient context denies an effect or has no timer driver.
    CallerUnavailable,
    Closed,
}

impl fmt::Display for StdioRestartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(error) => write!(
                formatter,
                "Invalid stdio supervision configuration: {error}"
            ),
            Self::Connection(error) => write!(formatter, "Stdio replacement failed: {error}"),
            Self::Cleanup(error) => write!(formatter, "Stdio cleanup did not settle: {error}"),
            Self::Subscription(error) => {
                write!(formatter, "Supervised stdio subscription failed: {error}")
            }
            Self::Cancelled => formatter.write_str("Stdio recovery cancelled"),
            Self::NotRestartable => {
                formatter.write_str("Stdio failure is not an admissible subprocess exit")
            }
            Self::RecoveryInProgress => {
                formatter.write_str("Stdio recovery must finish before issuing requests")
            }
            Self::AttemptsExhausted => formatter.write_str("Stdio restart attempt limit exhausted"),
            Self::WindowExpired => formatter.write_str("Stdio restart window expired"),
            Self::CallerUnavailable => formatter.write_str(
                "Stdio supervision requires caller-owned spawn, I/O, time and timer capabilities",
            ),
            Self::Closed => formatter.write_str("Supervised stdio connection is closed"),
        }
    }
}

impl std::error::Error for StdioRestartError {}

#[derive(Clone, Copy, Debug)]
enum RecoveryPhase {
    Settling,
    Waiting { until: Instant },
    Initializing,
    Restoring,
}

#[derive(Debug)]
struct RecoveryIncident {
    previous_generation: u64,
    exit: StdioProcessExit,
    deadline: Instant,
    attempts: u32,
    phase: RecoveryPhase,
    acknowledgement_deadline: Option<Instant>,
}

#[derive(Debug)]
struct ConfiguredCatalogSubscription {
    request: SubscriptionListenRequest,
    timeout_policy: SubscriptionTimeoutPolicy,
    request_id: RequestId,
}

/// A caller-owned Unix subprocess connection with explicit crash recovery.
///
/// Configure [`ClientBuilder`] with an explicit `ModernOnly` stdio plan, then
/// use [`Self::client_mut`] for ordinary operations. After a naturally observed
/// child exit interrupts an operation, [`Self::recover`] settles the old scope,
/// waits with bounded exponential jitter, spawns from frozen configuration and
/// performs fresh discovery. It never retries the interrupted operation.
///
/// Command resolution, cwd and the complete Unicode environment are frozen at
/// construction. This freezes configuration, not executable file contents.
/// The owner retains its replacement client and counters if a recovery future
/// is cancelled or dropped. Explicitly close it to report cleanup failures.
/// [`Self::open_subscriptions_listener`] opts one catalog/resource listener into
/// recovery. Recovery acknowledges a fresh listener before publishing the new
/// generation and reports the observation gap. Legacy/Auto selection and Tasks
/// listener recovery are not provided.
///
/// ```no_run
/// use fastmcp_client::{
///     ClientBuilder, ClientProtocolPlan, ProtocolPolicy, StdioInterruptedRequest,
///     StdioRestartPolicy,
/// };
/// use fastmcp_core::McpRequestCancellation;
///
/// # async fn example(cx: &asupersync::Cx) -> Result<(), Box<dyn std::error::Error>> {
/// let mut server = ClientBuilder::new()
///     .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly))
///     .connect_supervised_stdio_with_cx(
///         cx, "/path/to/mcp-server", &[], StdioRestartPolicy::default(),
///     ).await?;
/// let cancellation = McpRequestCancellation::new();
/// let result = server.client_mut()?.request_core_with_cx(
///     cx, &cancellation, "tools/list", serde_json::json!({}),
/// ).await;
/// if let Err(error) = result {
///     if StdioInterruptedRequest::from_error(&error).is_some() {
///         let fresh = server.recover(cx, &cancellation).await?;
///         assert!(fresh.generation > fresh.previous_generation);
///         // Reconcile any uncertain effects before explicitly issuing new work.
///     }
/// }
/// server.close_with_cx(cx).await?;
/// # Ok(())
/// # }
/// ```
pub struct SupervisedStdioClient {
    builder: ClientBuilder,
    command: String,
    args: Vec<String>,
    policy: StdioRestartPolicy,
    client: Client,
    generation: u64,
    attempts: VecDeque<Instant>,
    total_attempts: u64,
    jitter_seed: u64,
    jitter_counter: u64,
    /// Every replacement, including its discovery, starts above IDs allocated
    /// by any previous attempt. Failed and dropped attempts consume IDs too.
    request_id_floor: u64,
    catalog_subscription: Option<ConfiguredCatalogSubscription>,
    recovery: Option<RecoveryIncident>,
    circuit: Option<StdioRestartError>,
    closed: bool,
}

impl fmt::Debug for SupervisedStdioClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupervisedStdioClient")
            .field("policy", &self.policy)
            .field("generation", &self.generation)
            .field("restart_attempts", &self.total_attempts)
            .field("recovery", &self.recovery)
            .field("circuit_open", &self.circuit.is_some())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl SupervisedStdioClient {
    /// Connects one eagerly initialized generation. Initial startup is a single
    /// attempt; the restart policy is used only after an observed connection loss.
    pub async fn connect(
        cx: &Cx,
        builder: ClientBuilder,
        command: &str,
        args: &[&str],
        policy: StdioRestartPolicy,
    ) -> Result<Self, StdioRestartError> {
        CallerContextFuture::new(cx, async move {
            let caller = admit_caller(cx, None)?;
            if !caller.capabilities().entropy {
                return Err(StdioRestartError::CallerUnavailable);
            }
            validate_arguments(command, args).map_err(StdioRestartError::Configuration)?;
            let (builder, command) = builder
                .freeze_stdio_restart(command)
                .map_err(StdioRestartError::Configuration)?;
            let random = fastmcp_core::draw_security_identifier().map_err(|_| {
                StdioRestartError::Configuration(McpError::internal_error(
                    "Stdio restart entropy unavailable",
                ))
            })?;
            let mut seed = [0u8; 8];
            seed.copy_from_slice(&random.as_bytes()[..8]);
            let deadline = bounded_deadline(&caller, policy.window);
            let client = builder
                .spawn_supervised_stdio(&caller, &command, args, deadline)
                .map_err(StdioRestartError::Connection)?;
            let mut owner = Self {
                builder,
                command,
                args: args.iter().map(|arg| (*arg).to_owned()).collect(),
                policy,
                client,
                generation: 1,
                attempts: VecDeque::new(),
                total_attempts: 0,
                jitter_seed: u64::from_le_bytes(seed),
                jitter_counter: 0,
                request_id_floor: 1,
                catalog_subscription: None,
                recovery: None,
                circuit: None,
                closed: false,
            };
            let initialized = owner
                .client
                .ensure_initialized_with_cancellation_until(&caller, None, Some(deadline))
                .await;
            if let Err(error) = initialized {
                return Err(owner
                    .fail_and_close(&caller, StdioRestartError::Connection(error))
                    .await);
            }
            if caller.checkpoint().is_err() || Instant::now() >= deadline {
                let error = if caller.checkpoint().is_err() {
                    StdioRestartError::Cancelled
                } else {
                    StdioRestartError::WindowExpired
                };
                return Err(owner.fail_and_close(&caller, error).await);
            }
            owner.client.enable_stdio_supervision(1);
            owner.retain_request_id_floor();
            Ok(owner)
        })
        .await
    }

    /// Returns the committed generation, starting at one. It changes only after
    /// complete discovery and never wraps or reuses an earlier generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Counts all replacement spawn attempts, including failed or cancelled ones.
    #[must_use]
    pub const fn restart_attempts(&self) -> u64 {
        self.total_attempts
    }

    /// Exposes the current client's immutable diagnostics, even after failure.
    #[must_use]
    pub const fn client(&self) -> &Client {
        &self.client
    }

    /// Borrows the current generation for explicit application requests.
    pub fn client_mut(&mut self) -> Result<&mut Client, StdioRestartError> {
        if self.closed {
            return Err(StdioRestartError::Closed);
        }
        if let Some(error) = &self.circuit {
            return Err(error.clone());
        }
        if self.recovery.is_some() {
            return Err(StdioRestartError::RecoveryInProgress);
        }
        Ok(&mut self.client)
    }

    /// Opens one catalog/resource listener and opts it into process recovery.
    ///
    /// The request and local resource relationships are bounded by the ordinary
    /// subscription admission rules. This commits the initial listen; consume
    /// its acknowledgement through [`Self::next_subscription_event_with_cx`].
    /// Every replacement uses the same requested filter and timeout policy,
    /// but negotiates a new accepted subset and reports a gap in [`StdioRecovery`].
    /// Tasks listeners and application requests are never replayed.
    pub async fn open_subscriptions_listener(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        notifications: impl Into<SubscriptionListenRequest>,
        timeout_policy: SubscriptionTimeoutPolicy,
    ) -> Result<RequestId, StdioRestartError> {
        let request = notifications.into();
        request
            .validate()
            .map_err(StdioRestartError::Configuration)?;
        timeout_policy
            .validate()
            .map_err(StdioRestartError::Configuration)?;
        CallerContextFuture::new(cx, async move {
            self.client_mut()?;
            if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
                return Err(StdioRestartError::Cancelled);
            }
            self.client
                .open_subscriptions_listener_with_timeout_policy(request.clone(), timeout_policy)
                .map_err(StdioRestartError::Subscription)?;
            let request_id = self
                .client
                .live_catalog_subscription
                .as_ref()
                .expect("a successful listen installs its owner")
                .execution
                .request_id()
                .clone();
            self.catalog_subscription = Some(ConfiguredCatalogSubscription {
                request,
                timeout_policy,
                request_id: request_id.clone(),
            });
            self.retain_request_id_floor();
            Ok(request_id)
        })
        .await
    }

    /// Observes the configured listener without introducing another reader.
    ///
    /// Dropping this wait preserves its listener. Explicit cancellation or a
    /// validated peer terminal also removes the recovery configuration, so a
    /// later process restart cannot resurrect it. A naturally observed process
    /// exit preserves the configuration for an explicit [`Self::recover`].
    /// Use this adapter to observe the configured listener; a terminal consumed
    /// directly through [`Self::client_mut`] is conservatively not restored.
    pub async fn next_subscription_event_with_cx(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
    ) -> Result<StdioSubscriptionEvent, StdioRestartError> {
        CallerContextFuture::new(cx, async move {
            self.client_mut()?;
            let owns_listener = self
                .catalog_subscription
                .as_ref()
                .is_some_and(|configured| {
                    self.client
                        .live_catalog_subscription
                        .as_ref()
                        .is_some_and(|live| {
                            configured
                                .request_id
                                .correlates_with(live.execution.request_id())
                        })
                });
            if !owns_listener {
                self.catalog_subscription = None;
                return Err(StdioRestartError::Subscription(McpError::invalid_request(
                    "No supervised catalog subscription is active",
                )));
            }
            let result = loop {
                match self
                    .client
                    .try_next_subscription_event_preserving_connection_loss(cx, cancellation, true)
                {
                    Ok(Some(event)) => break Ok(event),
                    Ok(None) => asupersync::runtime::yield_now().await,
                    Err(error) => break Err(error),
                }
            };
            if cancellation.is_cancel_requested()
                || cx.checkpoint().is_err()
                || matches!(result, Ok(StdioSubscriptionEvent::Terminal))
            {
                self.catalog_subscription = None;
            } else if result.is_err() {
                let naturally_exited = matches!(
                    self.client.stdio_restart_observation,
                    Some(StdioRestartObservation::Exited { generation, .. })
                        if generation == self.generation
                );
                if naturally_exited {
                    self.retain_restartable_catalog_subscription();
                } else {
                    self.catalog_subscription = None;
                }
            }
            result.map_err(StdioRestartError::Subscription)
        })
        .await
    }

    /// Cancels only the configured listener and permanently removes its opt-in.
    ///
    /// A failed wire cancellation still removes the recovery configuration;
    /// its underlying listener/error remains owned by the client for cleanup.
    pub fn cancel_live_catalog_subscription(&mut self, cx: &Cx) -> Result<(), StdioRestartError> {
        self.client_mut()?;
        let Some(configured) = self.catalog_subscription.take() else {
            return Ok(());
        };
        let Some(live) = &self.client.live_catalog_subscription else {
            return Ok(());
        };
        if !configured
            .request_id
            .correlates_with(live.execution.request_id())
        {
            return Err(StdioRestartError::Subscription(McpError::invalid_request(
                "The live catalog subscription is not owned by the supervisor",
            )));
        }
        self.client
            .cancel_live_catalog_subscription(cx)
            .map_err(StdioRestartError::Subscription)
    }

    fn retain_request_id_floor(&mut self) {
        self.request_id_floor = self
            .request_id_floor
            .max(self.client.peek_next_request_id());
    }

    fn retain_restartable_catalog_subscription(&mut self) {
        let restartable = self
            .catalog_subscription
            .as_ref()
            .is_some_and(|configured| {
                self.client
                    .live_catalog_subscription
                    .as_ref()
                    .is_some_and(|live| {
                        configured
                            .request_id
                            .correlates_with(live.execution.request_id())
                            && live.cancellation_failure.is_none()
                            && matches!(
                                live.execution.execution.terminal_reason(),
                                None | Some(crate::ExecutionTerminalReason::ConnectionLost)
                            )
                    })
            });
        if !restartable {
            self.catalog_subscription = None;
        }
    }

    /// Recovers only a child exit proven before cleanup began. Protocol errors,
    /// application errors, cancellation, timeouts, explicit shutdown and EOF
    /// from a still-live process cannot authorize a replacement.
    ///
    /// Cancellation is independently request-owned. A later call may resume the
    /// same incident with a fresh cancellation token, within its original bounds.
    pub async fn recover(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
    ) -> Result<StdioRecovery, StdioRestartError> {
        CallerContextFuture::new(cx, self.recover_inner(cx, cancellation)).await
    }

    async fn recover_inner(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
    ) -> Result<StdioRecovery, StdioRestartError> {
        if self.closed {
            return Err(StdioRestartError::Closed);
        }
        if let Some(error) = &self.circuit {
            return Err(error.clone());
        }
        if self.recovery.is_none() {
            self.client.settle_supervised_stdio_send_failure();
            let Some(StdioRestartObservation::Exited { generation, exit }) =
                self.client.stdio_restart_observation
            else {
                return Err(StdioRestartError::NotRestartable);
            };
            self.retain_restartable_catalog_subscription();
            self.retain_request_id_floor();
            let now = Instant::now();
            while self
                .attempts
                .front()
                .is_some_and(|attempt| now.duration_since(*attempt) >= self.policy.window)
            {
                self.attempts.pop_front();
            }
            // Create this incident before observing cancellation. Repeatedly
            // cancelling recovery must not manufacture fresh elapsed windows.
            self.recovery = Some(RecoveryIncident {
                previous_generation: generation,
                exit,
                deadline: bounded_deadline(cx, self.policy.window),
                attempts: 0,
                phase: RecoveryPhase::Settling,
                acknowledgement_deadline: None,
            });
        }
        loop {
            self.retain_request_id_floor();
            let phase = self
                .recovery
                .as_ref()
                .expect("recovery incident retained")
                .phase;
            // Settlement runs before cancellation can return. The old client
            // remains owned if an interrupted close needs a later explicit close.
            if matches!(phase, RecoveryPhase::Settling) {
                if let Err(error) = self.client.close_with_cx(cx).await {
                    let error = StdioRestartError::Cleanup(error);
                    self.circuit = Some(error.clone());
                    return Err(error);
                }
                if !self.cleanly_settled() {
                    let error = StdioRestartError::Cleanup(McpError::internal_error(
                        "Previous stdio generation is not settled",
                    ));
                    self.circuit = Some(error.clone());
                    return Err(error);
                }
                self.schedule_backoff();
            }
            if matches!(
                phase,
                RecoveryPhase::Initializing | RecoveryPhase::Restoring
            ) && (cancellation.is_cancel_requested() || cx.checkpoint().is_err())
            {
                // Explicit cancellation settles a retained provisional child.
                // Dropping the future instead leaves that child owned so a
                // later call can resume its single in-flight discovery/listen.
                if let Err(error) = self.client.close_with_cx(cx).await {
                    let error = StdioRestartError::Cleanup(error);
                    self.circuit = Some(error.clone());
                    return Err(error);
                }
                if !self.cleanly_settled() {
                    let error = StdioRestartError::Cleanup(McpError::internal_error(
                        "Cancelled replacement is not settled",
                    ));
                    self.circuit = Some(error.clone());
                    return Err(error);
                }
                self.schedule_backoff();
                return Err(StdioRestartError::Cancelled);
            }
            let caller = admit_caller(cx, Some(cancellation))?;
            let remaining = caller.budget().remaining_time(caller.now());
            let incident = self.recovery.as_mut().expect("recovery incident retained");
            if let Some(remaining) = remaining {
                incident.deadline = incident
                    .deadline
                    .min(Instant::now() + remaining.min(self.policy.window));
            }
            if Instant::now() >= incident.deadline {
                return Err(self
                    .fail_and_close(&caller, StdioRestartError::WindowExpired)
                    .await);
            }
            match incident.phase {
                RecoveryPhase::Settling => unreachable!("settlement advances before admission"),
                RecoveryPhase::Waiting { until } => {
                    if self.attempts.len() >= self.policy.max_attempts as usize {
                        return Err(self
                            .fail_and_close(&caller, StdioRestartError::AttemptsExhausted)
                            .await);
                    }
                    let remaining = until.saturating_duration_since(Instant::now());
                    if !remaining.is_zero() {
                        let delay = remaining
                            .min(CANCEL_SLICE)
                            .min(incident.deadline.saturating_duration_since(Instant::now()));
                        wait_slice(&caller, cancellation, delay).await?;
                        continue;
                    }
                    let deadline = incident.deadline;
                    incident.attempts += 1;
                    self.total_attempts += 1;
                    self.attempts.push_back(Instant::now());
                    let args: Vec<&str> = self.args.iter().map(String::as_str).collect();
                    match self.builder.spawn_supervised_stdio(
                        &caller,
                        &self.command,
                        &args,
                        deadline,
                    ) {
                        Ok(mut client) => {
                            // Store ownership and phase before the handshake's
                            // first await. Cancellation/drop cannot refund spawn.
                            client.stdio_restart_observation =
                                Some(StdioRestartObservation::Provisional);
                            client
                                .next_id
                                .fetch_max(self.request_id_floor, Ordering::SeqCst);
                            self.client = client;
                            self.recovery
                                .as_mut()
                                .expect("recovery incident retained")
                                .phase = RecoveryPhase::Initializing;
                        }
                        Err(error) if is_cleanup_unverified(&error) => {
                            let error = StdioRestartError::Cleanup(error);
                            self.circuit = Some(error.clone());
                            return Err(error);
                        }
                        Err(_) => {
                            self.schedule_backoff();
                        }
                    }
                }
                RecoveryPhase::Initializing => {
                    let deadline = incident.deadline;
                    match self
                        .client
                        .ensure_initialized_with_cancellation_until(
                            &caller,
                            Some(cancellation),
                            Some(deadline),
                        )
                        .await
                    {
                        Ok(()) => {
                            if cancellation.is_cancel_requested() || caller.checkpoint().is_err() {
                                // Do not expose a fully initialized provisional
                                // executor under the previous generation when
                                // cancellation wins publication.
                                if let Err(error) = self.client.close_with_cx(&caller).await {
                                    let error = StdioRestartError::Cleanup(error);
                                    self.circuit = Some(error.clone());
                                    return Err(error);
                                }
                                if !self.cleanly_settled() {
                                    return Err(self
                                        .fail_and_close(
                                            &caller,
                                            StdioRestartError::Cleanup(McpError::internal_error(
                                                "Cancelled replacement is not settled",
                                            )),
                                        )
                                        .await);
                                }
                                self.schedule_backoff();
                                return Err(StdioRestartError::Cancelled);
                            }
                            if Instant::now() >= deadline {
                                return Err(self
                                    .fail_and_close(&caller, StdioRestartError::WindowExpired)
                                    .await);
                            }
                            if let Some(configured) = &self.catalog_subscription {
                                if let Err(error) =
                                    self.client.open_subscriptions_listener_with_timeout_policy(
                                        configured.request.clone(),
                                        configured.timeout_policy,
                                    )
                                {
                                    return Err(self
                                        .fail_and_close(
                                            &caller,
                                            StdioRestartError::Subscription(error),
                                        )
                                        .await);
                                }
                                let acknowledgement_wait = self
                                    .client
                                    .timeout_policy
                                    .idle_timeout()
                                    .min(self.client.timeout_policy.absolute_timeout());
                                let incident = self
                                    .recovery
                                    .as_mut()
                                    .expect("restoring recovery incident retained");
                                incident.acknowledgement_deadline = Some(
                                    Instant::now()
                                        .checked_add(acknowledgement_wait)
                                        .unwrap_or(incident.deadline)
                                        .min(incident.deadline),
                                );
                                // Publication follows acknowledgement, not just
                                // the write. This phase and the client retain
                                // the one sent request across dropped futures.
                                incident.phase = RecoveryPhase::Restoring;
                                continue;
                            }
                            return self.publish_recovery(&caller, cancellation, None).await;
                        }
                        Err(error) => {
                            let natural_exit = match self.client.stdio_restart_observation {
                                Some(StdioRestartObservation::ProvisionalExited { exit }) => {
                                    Some(exit)
                                }
                                _ => None,
                            };
                            // A cancellation before discovery's first write may
                            // return without its internal terminal cleanup. Own
                            // that close here before considering another spawn.
                            if let Err(cleanup) = self.client.close_with_cx(&caller).await {
                                let error = StdioRestartError::Cleanup(cleanup);
                                self.circuit = Some(error.clone());
                                return Err(error);
                            }
                            if is_cleanup_unverified(&error) || !self.cleanly_settled() {
                                return Err(self
                                    .fail_and_close(&caller, StdioRestartError::Cleanup(error))
                                    .await);
                            }
                            if cancellation.is_cancel_requested() || caller.checkpoint().is_err() {
                                self.schedule_backoff();
                                return Err(StdioRestartError::Cancelled);
                            }
                            if natural_exit.is_some() {
                                // The failed discovery never exposed a usable
                                // generation. Only a pre-cleanup natural exit
                                // admits another attempt in this SAME incident.
                                self.schedule_backoff();
                                continue;
                            }
                            // A fresh peer's protocol/handshake rejection is
                            // terminal, not an invitation to start more peers.
                            return Err(self
                                .fail_and_close(&caller, StdioRestartError::Connection(error))
                                .await);
                        }
                    }
                }
                RecoveryPhase::Restoring => {
                    if incident
                        .acknowledgement_deadline
                        .is_some_and(|deadline| Instant::now() >= deadline)
                    {
                        return Err(self
                            .fail_and_close(
                                &caller,
                                StdioRestartError::Subscription(McpError::internal_error(
                                    "Supervised subscription acknowledgement deadline elapsed",
                                )),
                            )
                            .await);
                    }
                    let event = self
                        .client
                        .try_next_subscription_event(&caller, cancellation);
                    if cancellation.is_cancel_requested() || caller.checkpoint().is_err() {
                        // The top-of-loop cancellation path settles the child
                        // before returning and keeps the original attempt/window.
                        continue;
                    }
                    match event {
                        Ok(Some(StdioSubscriptionEvent::Acknowledged(_))) => {
                            let live = self
                                .client
                                .live_catalog_subscription
                                .as_mut()
                                .expect("an acknowledged listener retains its owner");
                            let subscription_id = live.execution.request_id().clone();
                            // Recovery privately checked this acknowledgement;
                            // its first public delivery still belongs to the
                            // caller's event loop after publication.
                            live.acknowledgement_delivered = false;
                            let previous_subscription_id = self
                                .catalog_subscription
                                .as_ref()
                                .expect("restoration retains its configuration")
                                .request_id
                                .clone();
                            return self
                                .publish_recovery(
                                    &caller,
                                    cancellation,
                                    Some(StdioSubscriptionRecovery {
                                        previous_subscription_id,
                                        subscription_id,
                                    }),
                                )
                                .await;
                        }
                        Ok(None) => asupersync::runtime::yield_now().await,
                        Ok(Some(_)) => {
                            return Err(self
                                .fail_and_close(
                                    &caller,
                                    StdioRestartError::Subscription(McpError::invalid_request(
                                        "Restored subscription ended before acknowledgement",
                                    )),
                                )
                                .await);
                        }
                        Err(error) => {
                            return Err(self
                                .fail_and_close(&caller, StdioRestartError::Subscription(error))
                                .await);
                        }
                    }
                }
            }
        }
    }

    async fn publish_recovery(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        catalog_subscription: Option<StdioSubscriptionRecovery>,
    ) -> Result<StdioRecovery, StdioRestartError> {
        if cancellation.is_cancel_requested() || cx.checkpoint().is_err() {
            if let Err(error) = self.client.close_with_cx(cx).await {
                let error = StdioRestartError::Cleanup(error);
                self.circuit = Some(error.clone());
                return Err(error);
            }
            if !self.cleanly_settled() {
                return Err(self
                    .fail_and_close(
                        cx,
                        StdioRestartError::Cleanup(McpError::internal_error(
                            "Cancelled replacement is not settled",
                        )),
                    )
                    .await);
            }
            self.schedule_backoff();
            return Err(StdioRestartError::Cancelled);
        }
        let incident = self
            .recovery
            .as_ref()
            .expect("publication retains recovery incident");
        if Instant::now() >= incident.deadline
            || incident
                .acknowledgement_deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(self
                .fail_and_close(cx, StdioRestartError::WindowExpired)
                .await);
        }
        let Some(generation) = self.generation.checked_add(1) else {
            return Err(self
                .fail_and_close(cx, StdioRestartError::AttemptsExhausted)
                .await);
        };
        if let Some(restored) = &catalog_subscription {
            let configured = self
                .catalog_subscription
                .as_mut()
                .expect("restoration retains its configuration");
            configured.request_id = restored.subscription_id.clone();
        }
        self.generation = generation;
        self.client.enable_stdio_supervision(generation);
        self.retain_request_id_floor();
        let incident = self.recovery.take().expect("completed recovery incident");
        Ok(StdioRecovery {
            previous_generation: incident.previous_generation,
            generation,
            process_exit: incident.exit,
            attempts: incident.attempts,
            catalog_subscription,
        })
    }

    fn cleanly_settled(&self) -> bool {
        self.client.child_cleanup_complete()
            && self.client.transport_is_closed()
            && !self.client.has_pending_cleanup_error()
            && self.client.cleanup_error.is_none()
    }

    fn schedule_backoff(&mut self) {
        self.retain_request_id_floor();
        let attempts = self
            .recovery
            .as_ref()
            .expect("recovery incident retained")
            .attempts;
        let delay = jittered_delay(self.policy, attempts, self.jitter_seed, self.jitter_counter);
        self.jitter_counter = self.jitter_counter.wrapping_add(1);
        let incident = self.recovery.as_mut().expect("recovery incident retained");
        incident.acknowledgement_deadline = None;
        incident.phase = RecoveryPhase::Waiting {
            until: Instant::now() + delay,
        };
    }

    async fn fail_and_close(&mut self, cx: &Cx, error: StdioRestartError) -> StdioRestartError {
        self.circuit = Some(error.clone());
        match self.client.close_with_cx(cx).await {
            Ok(()) if self.cleanly_settled() => error,
            Ok(()) => {
                let error = StdioRestartError::Cleanup(McpError::internal_error(
                    "Stdio ownership remains unsettled",
                ));
                self.circuit = Some(error.clone());
                error
            }
            Err(cleanup) => {
                let error = StdioRestartError::Cleanup(cleanup);
                self.circuit = Some(error.clone());
                error
            }
        }
    }

    /// Permanently disables recovery and awaits cleanup of the retained child.
    /// Calling again retries unfinished cleanup; it can never spawn a process.
    pub async fn close_with_cx(&mut self, cx: &Cx) -> McpResult<()> {
        self.closed = true;
        self.catalog_subscription = None;
        CallerContextFuture::new(cx, self.client.close_with_cx(cx)).await
    }
}

impl ClientBuilder {
    /// Connects an explicitly supervised ModernOnly Unix stdio session.
    pub async fn connect_supervised_stdio_with_cx(
        self,
        cx: &Cx,
        command: &str,
        args: &[&str],
        policy: StdioRestartPolicy,
    ) -> Result<SupervisedStdioClient, StdioRestartError> {
        SupervisedStdioClient::connect(cx, self, command, args, policy).await
    }
}

fn validate_arguments(command: &str, args: &[&str]) -> McpResult<()> {
    if command.is_empty()
        || command.len() > 16 * 1024
        || command.contains('\0')
        || args.len() > 1024
        || args.iter().any(|arg| arg.contains('\0'))
        || args
            .iter()
            .fold(0usize, |total, arg| total.saturating_add(arg.len()))
            > 1024 * 1024
    {
        return Err(McpError::invalid_params(
            "Invalid or oversized supervised stdio command/arguments",
        ));
    }
    Ok(())
}

fn admit_caller(
    cx: &Cx,
    cancellation: Option<&McpRequestCancellation>,
) -> Result<Cx, StdioRestartError> {
    let caller = with_caller_context(cx, || Cx::current().expect("explicit caller installed"));
    if caller.checkpoint().is_err()
        || cancellation.is_some_and(McpRequestCancellation::is_cancel_requested)
    {
        return Err(StdioRestartError::Cancelled);
    }
    let caps = caller.capabilities();
    if !caps.spawn || !caps.io || !caps.time || caller.timer_driver().is_none() {
        return Err(StdioRestartError::CallerUnavailable);
    }
    Ok(caller)
}

fn bounded_deadline(cx: &Cx, window: Duration) -> Instant {
    Instant::now()
        + cx.budget()
            .remaining_time(cx.now())
            .map_or(window, |remaining| remaining.min(window))
}

// Deterministic equal jitter from one core entropy draw: [base/2, base]. The
// capped exponential base is never exceeded and no fresh ambient RNG is used.
fn jittered_delay(policy: StdioRestartPolicy, attempts: u32, seed: u64, counter: u64) -> Duration {
    let base = policy
        .initial_backoff
        .saturating_mul(1u32 << attempts.min(31))
        .min(policy.max_backoff);
    let nanos = base.as_nanos() as u64;
    let half = nanos / 2;
    let mut random = seed.wrapping_add(counter.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    random = (random ^ (random >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    random = (random ^ (random >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    random ^= random >> 31;
    Duration::from_nanos(half + random % (nanos - half + 1)).max(Duration::from_nanos(1))
}

async fn wait_slice(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    delay: Duration,
) -> Result<(), StdioRestartError> {
    let mut sleep = std::pin::pin!(asupersync::time::sleep(cx.now(), delay));
    let mut cancelled = std::pin::pin!(cancellation.cancelled());
    poll_fn(|task_cx| {
        if cx.checkpoint().is_err() || cancelled.as_mut().poll(task_cx).is_ready() {
            return Poll::Ready(Err(StdioRestartError::Cancelled));
        }
        sleep.as_mut().poll(task_cx).map(|()| Ok(()))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ClientProtocolPlan, ProtocolPolicy, RequestTimeoutPolicy, StdioRequestExecution,
        StdioRequestExecutor,
    };
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    // Every process accepts discovery only as its first message. A tool commits
    // an observable effect and exits WITHOUT a response. A replacement records
    // a new discovery and remains idle until the caller explicitly sends work.
    const PEER: &str = r#"
printf '%s\n' start >> "$SUPERVISION_LOG"
IFS= read -r discovery || exit 81
case "$discovery" in *'"method":"server/discover"'*) ;; *) exit 82 ;; esac
discovery_id=$(printf '%s\n' "$discovery" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
case "$discovery_id" in ''|*[!0-9]*) exit 83 ;; esac
printf '%s\n' discovery >> "$SUPERVISION_LOG"
printf 'discovery-id:%s\n' "$discovery_id" >> "$SUPERVISION_LOG"
first_process=no
if [ ! -f "$SUPERVISION_FIRST" ]; then first_process=yes; fi
if [ "$first_process" = no ]; then
    case "$SUPERVISION_MODE" in
        recover-discovery-crash)
            if [ ! -f "$SUPERVISION_FIRST.crashed" ]; then
                : > "$SUPERVISION_FIRST.crashed"
                printf '%s\n' discovery-crash-wait >> "$SUPERVISION_LOG"
                while [ ! -f "$SUPERVISION_GATE" ]; do sleep 0.01; done
                exit 24
            fi
            ;;
        recover-discovery-malformed)
            printf '%s\n' 'not-json'
            exit 24
            ;;
        recover-discovery-rejected)
            printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"unsupported"}}\n' "$discovery_id"
            exit 24
            ;;
    esac
fi
if [ "$SUPERVISION_MODE" = gated ] && [ -f "$SUPERVISION_FIRST" ]; then
    while [ ! -f "$SUPERVISION_GATE" ]; do sleep 0.01; done
fi
: > "$SUPERVISION_FIRST"
printf '{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"ttlMs":0,"cacheScope":"private","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"restart-peer","version":"1"}}}}\n' "$discovery_id"
if [ "$SUPERVISION_MODE" = idle-exit ] && [ "$first_process" = yes ]; then exit 23; fi
if [ "$SUPERVISION_MODE" = live-stdin ]; then
    exec 0<&-
    printf '%s\n' stdin-closed >> "$SUPERVISION_LOG"
    exec sleep 30
fi
while IFS= read -r request; do
    request_id=$(printf '%s\n' "$request" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
    case "$request" in
        *'"method":"tools/list"'*)
            printf '%s\n' list >> "$SUPERVISION_LOG"
            printf '{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","tools":[]}}\n' "$request_id"
            ;;
        *'"method":"subscriptions/listen"'*)
            printf '%s\n' listen >> "$SUPERVISION_LOG"
            printf 'listen-id:%s\n' "$request_id" >> "$SUPERVISION_LOG"
            accepted='{"toolsListChanged":true}'
            if [ "$first_process" = no ]; then
                case "$SUPERVISION_MODE" in
                    restore-rejected)
                        printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"unsupported"}}\n' "$request_id"
                        continue
                        ;;
                    restore-broadens) accepted='{"toolsListChanged":true,"promptsListChanged":true}' ;;
                    restore-silent) continue ;;
                    restore-gated)
                        printf '%s\n' restore-wait >> "$SUPERVISION_LOG"
                        while [ ! -f "$SUPERVISION_GATE" ]; do sleep 0.01; done
                        ;;
                esac
            fi
            printf '{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":%s},"notifications":%s}}\n' "$request_id" "$accepted"
            if [ "$SUPERVISION_MODE" = subscription-terminal ]; then
                printf '{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":%s}}}\n' "$request_id" "$request_id"
            else
                printf '{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":%s}}}\n' "$request_id"
            fi
            ;;
        *'"method":"notifications/cancelled"'*)
            printf '%s\n' cancel >> "$SUPERVISION_LOG"
            ;;
        *'"method":"tools/call"'*)
            case "$SUPERVISION_MODE" in
                malformed)
                    printf '%s\n' 'not-json'
                    exit 23
                    ;;
                live-eof)
                    printf '%s\n' stdout-closed >> "$SUPERVISION_LOG"
                    exec 1>&-
                    while IFS= read -r ignored; do :; done
                    exit 0
                    ;;
                application)
                    printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32602,"message":"Rejected by application"}}\n' "$request_id"
                    ;;
                *)
                    printf '%s\n' effect >> "$SUPERVISION_LOG"
                    exit 23
                    ;;
            esac
            ;;
        *) exit 84 ;;
    esac
done
"#;

    struct Fixture {
        directory: PathBuf,
        log: PathBuf,
        first: PathBuf,
        gate: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let identifier = fastmcp_core::draw_security_identifier().unwrap();
            let nonce = identifier.as_bytes()[..8]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let directory = std::env::temp_dir().join(format!(
                "fastmcp-stdio-restart-{}-{sequence}-{nonce}",
                std::process::id(),
            ));
            std::fs::create_dir_all(&directory).unwrap();
            Self {
                log: directory.join("events"),
                first: directory.join("first"),
                gate: directory.join("gate"),
                directory,
            }
        }

        fn count(&self, event: &str) -> usize {
            std::fs::read_to_string(&self.log)
                .unwrap_or_default()
                .lines()
                .filter(|line| *line == event)
                .count()
        }

        fn ids(&self, kind: &str) -> Vec<i64> {
            let prefix = format!("{kind}-id:");
            std::fs::read_to_string(&self.log)
                .unwrap_or_default()
                .lines()
                .filter_map(|line| line.strip_prefix(&prefix))
                .map(|id| id.parse().unwrap())
                .collect()
        }

        fn builder(&self, mode: &str) -> ClientBuilder {
            ClientBuilder::new()
                .protocol_plan(ClientProtocolPlan::stdio(ProtocolPolicy::ModernOnly))
                .request_timeout_policy(
                    RequestTimeoutPolicy::new(Duration::from_secs(2), Duration::from_secs(2))
                        .unwrap(),
                )
                .working_dir(&self.directory)
                .env("SUPERVISION_LOG", self.log.to_str().unwrap())
                .env("SUPERVISION_FIRST", self.first.to_str().unwrap())
                .env("SUPERVISION_GATE", self.gate.to_str().unwrap())
                .env("SUPERVISION_MODE", mode)
        }

        async fn connect(
            &self,
            cx: &Cx,
            mode: &str,
            policy: StdioRestartPolicy,
        ) -> SupervisedStdioClient {
            self.builder(mode)
                .connect_supervised_stdio_with_cx(cx, "sh", &["-c", PEER], policy)
                .await
                .unwrap()
        }
    }

    fn quick_policy(attempts: u32) -> StdioRestartPolicy {
        StdioRestartPolicy::new(
            attempts,
            Duration::from_secs(5),
            Duration::from_millis(1),
            Duration::from_millis(5),
        )
        .unwrap()
    }

    fn issue_effect(
        owner: &mut SupervisedStdioClient,
        cx: &Cx,
    ) -> (StdioRequestExecutor, StdioRequestExecution) {
        let client = owner.client_mut().unwrap();
        let executor = client.multiplexed_stdio_executor().unwrap();
        let request = client
            .start_multiplexed_request(
                cx,
                "tools/call",
                Some(json!({
                    "name": "effect", "arguments": {},
                })),
            )
            .unwrap();
        (executor, request)
    }

    async fn wait_for_exit(owner: &mut SupervisedStdioClient, cx: &Cx) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if owner
                .client
                .child
                .as_mut()
                .unwrap()
                .try_wait()
                .unwrap()
                .is_some()
            {
                return;
            }
            assert!(Instant::now() < deadline, "fixture child did not exit");
            asupersync::time::sleep(cx.now(), Duration::from_millis(2)).await;
        }
    }

    async fn crash(
        owner: &mut SupervisedStdioClient,
        cx: &Cx,
    ) -> (StdioRequestExecutor, StdioRequestExecution, McpError) {
        let (executor, request) = issue_effect(owner, cx);
        wait_for_exit(owner, cx).await;
        let error = owner
            .client_mut()
            .unwrap()
            .drive_multiplexed_stdio(cx)
            .unwrap_err();
        (executor, request, error)
    }

    fn catalog_filter() -> fastmcp_protocol::SubscriptionFilter {
        fastmcp_protocol::SubscriptionFilter {
            tools_list_changed: Some(true),
            ..Default::default()
        }
    }

    async fn open_catalog(owner: &mut SupervisedStdioClient, cx: &Cx) -> RequestId {
        let cancellation = McpRequestCancellation::new();
        let id = owner
            .open_subscriptions_listener(
                cx,
                &cancellation,
                catalog_filter(),
                SubscriptionTimeoutPolicy::default(),
            )
            .await
            .unwrap();
        assert!(matches!(
            owner.next_subscription_event_with_cx(cx, &cancellation).await.unwrap(),
            StdioSubscriptionEvent::Acknowledged(filter) if filter == catalog_filter(),
        ));
        assert!(matches!(
            owner
                .next_subscription_event_with_cx(cx, &cancellation)
                .await
                .unwrap(),
            StdioSubscriptionEvent::Notification(crate::ServerNotification::ToolsListChanged(_)),
        ));
        id
    }

    async fn drop_recovery_after_listen(
        owner: &mut SupervisedStdioClient,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        fixture: &Fixture,
    ) {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut recovery = Box::pin(owner.recover(cx, cancellation));
        loop {
            poll_fn(|task_cx| {
                assert!(recovery.as_mut().poll(task_cx).is_pending());
                Poll::Ready(())
            })
            .await;
            if fixture.count("listen") == 2 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "replacement listen was never committed"
            );
            asupersync::time::sleep(cx.now(), Duration::from_millis(2)).await;
        }
    }

    #[test]
    fn supervised_stdio_subscription_recovery_reports_gap_and_fresh_ids_without_rpc_replay() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let fixture = Fixture::new();
                let mut owner = fixture.connect(&cx, "effect", quick_policy(3)).await;
                let old_subscription = open_catalog(&mut owner, &cx).await;
                let (old_executor, mut old_request, error) = crash(&mut owner, &cx).await;
                let interrupted = StdioInterruptedRequest::from_error(&error).unwrap();
                let old_request_id = old_request.request_id().clone();
                assert!(matches!(
                    owner
                        .next_subscription_event_with_cx(&cx, &McpRequestCancellation::new())
                        .await,
                    Err(StdioRestartError::Subscription(_)),
                ));
                assert!(
                    owner.client.live_catalog_subscription.is_some(),
                    "the supervised error observation retains the interrupted listener owner"
                );
                let recovery = owner
                    .recover(&cx, &McpRequestCancellation::new())
                    .await
                    .unwrap();
                assert_eq!((recovery.previous_generation, recovery.generation), (1, 2));
                let restored = recovery.catalog_subscription.unwrap();
                assert_eq!(restored.previous_subscription_id, old_subscription);
                assert_ne!(restored.subscription_id, old_subscription);
                assert_ne!(restored.subscription_id, old_request_id);
                let discoveries = fixture.ids("discovery");
                let listeners = fixture.ids("listen");
                assert_eq!(discoveries.len(), 2);
                assert_eq!(listeners.len(), 2);
                assert!(discoveries[1] > listeners[0]);
                assert!(listeners[1] > discoveries[1]);
                assert_eq!(restored.subscription_id, RequestId::Number(listeners[1]));
                assert_eq!(fixture.count("effect"), 1);
                let old_error = old_executor
                    .try_take_response(&mut old_request)
                    .unwrap_err();
                assert_eq!(
                    StdioInterruptedRequest::from_error(&old_error),
                    Some(interrupted)
                );
                let cancellation = McpRequestCancellation::new();
                assert!(matches!(
                    owner.next_subscription_event_with_cx(&cx, &cancellation).await.unwrap(),
                    StdioSubscriptionEvent::Acknowledged(filter) if filter == catalog_filter(),
                ));
                assert!(matches!(
                    owner
                        .next_subscription_event_with_cx(&cx, &cancellation)
                        .await
                        .unwrap(),
                    StdioSubscriptionEvent::Notification(
                        crate::ServerNotification::ToolsListChanged(_)
                    ),
                ));
                owner
                    .client_mut()
                    .unwrap()
                    .request_core_with_cx(&cx, &cancellation, "tools/list", json!({}))
                    .await
                    .unwrap();
                assert_eq!(
                    fixture.count("list"),
                    1,
                    "ordinary RPCs remain usable beside the listener"
                );
                assert_eq!(
                    fixture.count("effect"),
                    1,
                    "restoration never replays the uncertain tool call"
                );
                owner.close_with_cx(&cx).await.unwrap();
            });
    }

    #[test]
    fn supervised_stdio_subscription_cancelled_through_either_api_is_not_resurrected() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                for raw_client in [false, true] {
                    let fixture = Fixture::new();
                    let mut owner = fixture.connect(&cx, "effect", quick_policy(3)).await;
                    open_catalog(&mut owner, &cx).await;
                    if raw_client {
                        owner
                            .client_mut()
                            .unwrap()
                            .cancel_live_catalog_subscription(&cx)
                            .unwrap();
                    } else {
                        owner.cancel_live_catalog_subscription(&cx).unwrap();
                    }
                    let _ = crash(&mut owner, &cx).await;
                    let recovery = owner
                        .recover(&cx, &McpRequestCancellation::new())
                        .await
                        .unwrap();
                    assert!(recovery.catalog_subscription.is_none());
                    assert!(owner.catalog_subscription.is_none());
                    assert_eq!(fixture.count("listen"), 1);
                    assert_eq!(fixture.count("effect"), 1);
                    owner.close_with_cx(&cx).await.unwrap();
                }
            });
    }

    #[test]
    fn supervised_stdio_subscription_raw_retirement_after_observed_exit_is_not_resurrected() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                for raw_cancel in [false, true] {
                    let fixture = Fixture::new();
                    let mut owner = fixture.connect(&cx, "effect", quick_policy(3)).await;
                    open_catalog(&mut owner, &cx).await;
                    let _ = crash(&mut owner, &cx).await;
                    let cancellation = McpRequestCancellation::new();
                    assert!(matches!(
                        owner
                            .next_subscription_event_with_cx(&cx, &cancellation)
                            .await,
                        Err(StdioRestartError::Subscription(_)),
                    ));
                    assert!(owner.catalog_subscription.is_some());
                    assert!(owner.client.live_catalog_subscription.is_some());
                    if raw_cancel {
                        owner
                            .client_mut()
                            .unwrap()
                            .cancel_live_catalog_subscription(&cx)
                            .unwrap();
                    } else {
                        assert!(
                            owner
                                .client_mut()
                                .unwrap()
                                .next_subscription_event_with_cx(&cx, &cancellation)
                                .await
                                .is_err()
                        );
                    }
                    assert!(owner.client.live_catalog_subscription.is_none());
                    let recovery = owner.recover(&cx, &cancellation).await.unwrap();
                    assert!(recovery.catalog_subscription.is_none());
                    assert!(owner.catalog_subscription.is_none());
                    assert_eq!(fixture.count("listen"), 1);
                    assert_eq!(fixture.count("effect"), 1);
                    owner.close_with_cx(&cx).await.unwrap();
                }
            });
    }

    #[test]
    fn supervised_stdio_subscription_terminal_consumed_through_raw_client_is_not_resurrected() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let fixture = Fixture::new();
                let mut owner = fixture
                    .connect(&cx, "subscription-terminal", quick_policy(3))
                    .await;
                let cancellation = McpRequestCancellation::new();
                owner
                    .open_subscriptions_listener(
                        &cx,
                        &cancellation,
                        catalog_filter(),
                        SubscriptionTimeoutPolicy::default(),
                    )
                    .await
                    .unwrap();
                assert!(matches!(
                    owner
                        .client_mut()
                        .unwrap()
                        .next_subscription_event_with_cx(&cx, &cancellation)
                        .await
                        .unwrap(),
                    StdioSubscriptionEvent::Acknowledged(_)
                ));
                assert!(matches!(
                    owner
                        .client_mut()
                        .unwrap()
                        .next_subscription_event_with_cx(&cx, &cancellation)
                        .await
                        .unwrap(),
                    StdioSubscriptionEvent::Terminal
                ));
                let _ = crash(&mut owner, &cx).await;
                let recovery = owner.recover(&cx, &cancellation).await.unwrap();
                assert!(recovery.catalog_subscription.is_none());
                assert!(owner.catalog_subscription.is_none());
                assert_eq!(fixture.count("listen"), 1);
                owner.close_with_cx(&cx).await.unwrap();
            });
    }

    #[test]
    fn supervised_stdio_subscription_dropped_restoration_resumes_one_committed_listen() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let fixture = Fixture::new();
                let mut owner = fixture.connect(&cx, "restore-gated", quick_policy(3)).await;
                let old_id = open_catalog(&mut owner, &cx).await;
                let _ = crash(&mut owner, &cx).await;
                let cancellation = McpRequestCancellation::new();
                drop_recovery_after_listen(&mut owner, &cx, &cancellation, &fixture).await;
                assert!(matches!(
                    owner.recovery.as_ref().unwrap().phase,
                    RecoveryPhase::Restoring
                ));
                let original_deadline = owner.recovery.as_ref().unwrap().deadline;
                let original_ack_deadline =
                    owner.recovery.as_ref().unwrap().acknowledgement_deadline;
                let id = owner
                    .client
                    .live_catalog_subscription
                    .as_ref()
                    .unwrap()
                    .execution
                    .request_id()
                    .clone();
                assert_eq!(
                    owner.generation(),
                    1,
                    "an unacknowledged replacement stays unpublished"
                );
                assert!(matches!(
                    owner.client_mut(),
                    Err(StdioRestartError::RecoveryInProgress)
                ));
                drop_recovery_after_listen(&mut owner, &cx, &cancellation, &fixture).await;
                assert_eq!(owner.recovery.as_ref().unwrap().deadline, original_deadline);
                assert_eq!(
                    owner.recovery.as_ref().unwrap().acknowledgement_deadline,
                    original_ack_deadline
                );
                std::fs::write(&fixture.gate, b"acknowledge").unwrap();
                let recovery = owner.recover(&cx, &cancellation).await.unwrap();
                assert_eq!(
                    recovery.catalog_subscription,
                    Some(StdioSubscriptionRecovery {
                        previous_subscription_id: old_id,
                        subscription_id: id,
                    })
                );
                assert_eq!(owner.restart_attempts(), 1);
                assert_eq!(fixture.count("start"), 2);
                assert_eq!(fixture.count("listen"), 2);
                assert_eq!(fixture.count("effect"), 1);
                owner.close_with_cx(&cx).await.unwrap();
            });
    }

    #[test]
    fn supervised_stdio_subscription_cancelled_restoration_settles_then_uses_fresh_attempt_ids() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let fixture = Fixture::new();
                let mut owner = fixture.connect(&cx, "restore-gated", quick_policy(3)).await;
                let old_id = open_catalog(&mut owner, &cx).await;
                let _ = crash(&mut owner, &cx).await;
                let cancellation = McpRequestCancellation::new();
                drop_recovery_after_listen(&mut owner, &cx, &cancellation, &fixture).await;
                let original_deadline = owner.recovery.as_ref().unwrap().deadline;
                cancellation.cancel();
                assert!(matches!(
                    owner.recover(&cx, &cancellation).await,
                    Err(StdioRestartError::Cancelled)
                ));
                assert!(owner.client.child_cleanup_complete());
                assert_eq!(owner.generation(), 1);
                assert_eq!(owner.restart_attempts(), 1);
                assert_eq!(owner.recovery.as_ref().unwrap().deadline, original_deadline);
                std::fs::write(&fixture.gate, b"acknowledge").unwrap();
                let recovery = owner
                    .recover(&cx, &McpRequestCancellation::new())
                    .await
                    .unwrap();
                assert_eq!(recovery.attempts, 2);
                assert_eq!(
                    recovery
                        .catalog_subscription
                        .as_ref()
                        .unwrap()
                        .previous_subscription_id,
                    old_id
                );
                let listeners = fixture.ids("listen");
                let discoveries = fixture.ids("discovery");
                assert_eq!(listeners.len(), 3);
                assert_eq!(discoveries.len(), 3);
                assert!(listeners.windows(2).all(|pair| pair[0] < pair[1]));
                assert!(discoveries.windows(2).all(|pair| pair[0] < pair[1]));
                assert!(
                    discoveries[2] > listeners[1],
                    "cancelled attempts cannot refund IDs"
                );
                assert_eq!(fixture.count("effect"), 1);
                owner.close_with_cx(&cx).await.unwrap();
            });
    }

    #[test]
    fn supervised_stdio_subscription_rejection_or_broadened_ack_keeps_replacement_unpublished() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                for mode in ["restore-rejected", "restore-broadens"] {
                    let fixture = Fixture::new();
                    let mut owner = fixture.connect(&cx, mode, quick_policy(3)).await;
                    open_catalog(&mut owner, &cx).await;
                    let _ = crash(&mut owner, &cx).await;
                    assert!(matches!(
                        owner.recover(&cx, &McpRequestCancellation::new()).await,
                        Err(StdioRestartError::Subscription(_))
                    ));
                    assert_eq!(owner.generation(), 1);
                    assert!(owner.client.child_cleanup_complete());
                    assert!(matches!(
                        owner.recover(&cx, &McpRequestCancellation::new()).await,
                        Err(StdioRestartError::Subscription(_))
                    ));
                    assert_eq!(owner.restart_attempts(), 1);
                    assert_eq!(fixture.count("listen"), 2);
                    assert_eq!(fixture.count("effect"), 1);
                    owner.close_with_cx(&cx).await.unwrap();
                }
            });
    }

    #[test]
    fn supervised_stdio_subscription_expired_ack_or_recovery_budget_never_publishes() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                for acknowledgement in [true, false] {
                    let fixture = Fixture::new();
                    let mut owner = fixture
                        .connect(&cx, "restore-silent", quick_policy(3))
                        .await;
                    open_catalog(&mut owner, &cx).await;
                    let _ = crash(&mut owner, &cx).await;
                    let cancellation = McpRequestCancellation::new();
                    drop_recovery_after_listen(&mut owner, &cx, &cancellation, &fixture).await;
                    let incident = owner.recovery.as_mut().unwrap();
                    assert!(incident.acknowledgement_deadline.unwrap() <= incident.deadline);
                    // Deterministically cross the retained boundary after the live
                    // write, without a load-sensitive sleep or an extra request.
                    if acknowledgement {
                        incident.acknowledgement_deadline = Some(Instant::now());
                    } else {
                        incident.deadline = Instant::now();
                    }
                    let error = owner.recover(&cx, &cancellation).await.unwrap_err();
                    assert!(matches!(
                        error,
                        StdioRestartError::Subscription(_) | StdioRestartError::WindowExpired
                    ));
                    assert_eq!(owner.generation(), 1);
                    assert_eq!(owner.restart_attempts(), 1);
                    assert!(owner.client.child_cleanup_complete());
                    assert_eq!(fixture.count("listen"), 2);
                    assert_eq!(fixture.count("effect"), 1);
                    owner.close_with_cx(&cx).await.unwrap();
                }
            });
    }

    #[test]
    fn supervised_stdio_subscription_invalid_configuration_and_pre_cancel_do_not_send() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let fixture = Fixture::new();
                let mut owner = fixture.connect(&cx, "effect", quick_policy(3)).await;
                let before = owner.client().peek_next_request_id();
                let invalid = fastmcp_protocol::SubscriptionFilter {
                    resource_subscriptions: Some(vec!["relative/path".to_owned()]),
                    ..catalog_filter()
                };
                assert!(matches!(
                    owner
                        .open_subscriptions_listener(
                            &cx,
                            &McpRequestCancellation::new(),
                            invalid,
                            SubscriptionTimeoutPolicy::default(),
                        )
                        .await,
                    Err(StdioRestartError::Configuration(_))
                ));
                let cancellation = McpRequestCancellation::new();
                cancellation.cancel();
                assert!(matches!(
                    owner
                        .open_subscriptions_listener(
                            &cx,
                            &cancellation,
                            catalog_filter(),
                            SubscriptionTimeoutPolicy::default(),
                        )
                        .await,
                    Err(StdioRestartError::Cancelled)
                ));
                assert_eq!(owner.client().peek_next_request_id(), before);
                assert!(owner.catalog_subscription.is_none());
                assert!(owner.client.live_catalog_subscription.is_none());
                assert_eq!(fixture.count("listen"), 0);
                owner.close_with_cx(&cx).await.unwrap();
            });
    }

    #[test]
    fn supervised_stdio_recovers_without_replaying_committed_effect() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let fixture = Fixture::new();
                let mut owner = fixture.connect(&cx, "effect", quick_policy(3)).await;
                assert!(std::path::Path::new(&owner.command).is_absolute());
                let (old_executor, mut old_request, error) = crash(&mut owner, &cx).await;
                let interrupted = StdioInterruptedRequest::from_error(&error).unwrap();
                assert_eq!(interrupted.generation, 1);
                assert_eq!(interrupted.process_exit.unwrap().code, Some(23));
                assert_eq!(fixture.count("effect"), 1);
                let event = owner
                    .recover(&cx, &McpRequestCancellation::new())
                    .await
                    .unwrap();
                assert_eq!(
                    (event.previous_generation, event.generation, event.attempts),
                    (1, 2, 1)
                );
                assert_eq!(owner.generation(), 2);
                assert_eq!(fixture.count("start"), 2);
                assert_eq!(fixture.count("discovery"), 2);
                assert_eq!(
                    fixture.count("effect"),
                    1,
                    "uncertain committed RPC must never be replayed"
                );
                let old_error = old_executor
                    .try_take_response(&mut old_request)
                    .unwrap_err();
                assert_eq!(
                    StdioInterruptedRequest::from_error(&old_error),
                    Some(interrupted)
                );
                let result = owner
                    .client_mut()
                    .unwrap()
                    .request_core_with_cx(
                        &cx,
                        &McpRequestCancellation::new(),
                        "tools/list",
                        json!({}),
                    )
                    .await
                    .unwrap();
                assert!(matches!(result, crate::CoreResult::Final(_)));
                assert_eq!(fixture.count("list"), 1);
                assert_eq!(fixture.count("effect"), 1);
                owner.close_with_cx(&cx).await.unwrap();
                assert!(owner.client().child_cleanup_complete());
            });
    }

    #[test]
    fn supervised_stdio_idle_exit_recovers_after_the_first_send_failure() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let fixture = Fixture::new();
                let mut owner = fixture.connect(&cx, "idle-exit", quick_policy(2)).await;
                wait_for_exit(&mut owner, &cx).await;
                let error = owner
                    .client_mut()
                    .unwrap()
                    .request_core_with_cx(
                        &cx,
                        &McpRequestCancellation::new(),
                        "tools/list",
                        json!({}),
                    )
                    .await
                    .unwrap_err();
                assert_eq!(
                    StdioInterruptedRequest::from_error(&error)
                        .unwrap()
                        .generation,
                    1
                );
                assert_eq!(fixture.count("list"), 0);
                let recovery = owner
                    .recover(&cx, &McpRequestCancellation::new())
                    .await
                    .unwrap();
                assert_eq!((recovery.previous_generation, recovery.generation), (1, 2));
                assert_eq!(recovery.process_exit.code, Some(23));
                assert_eq!(fixture.count("discovery"), 2);
                assert_eq!(fixture.count("list"), 0, "failed send must not be replayed");
                owner
                    .client_mut()
                    .unwrap()
                    .request_core_with_cx(
                        &cx,
                        &McpRequestCancellation::new(),
                        "tools/list",
                        json!({}),
                    )
                    .await
                    .unwrap();
                assert_eq!(fixture.count("list"), 1);
                owner.close_with_cx(&cx).await.unwrap();
            });
    }

    #[test]
    fn supervised_stdio_send_failure_publishes_uncertainty_to_existing_handles() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let fixture = Fixture::new();
                let mut owner = fixture.connect(&cx, "effect", quick_policy(2)).await;
                let (executor, mut request) = issue_effect(&mut owner, &cx);
                wait_for_exit(&mut owner, &cx).await;
                // Observe failure through a cloned public executor, before the
                // connection owner probes the child or drives an inbound frame.
                let send_error = executor
                    .execute(&cx, "tools/list", Some(json!({})))
                    .unwrap_err();
                let send_evidence = StdioInterruptedRequest::from_error(&send_error).unwrap();
                assert_eq!(send_evidence.generation, 1);
                assert_eq!(send_evidence.process_exit, None);
                let old_error = executor.try_take_response(&mut request).unwrap_err();
                assert_eq!(
                    StdioInterruptedRequest::from_error(&old_error),
                    Some(send_evidence)
                );
                assert_eq!(fixture.count("effect"), 1);
                let recovery = owner
                    .recover(&cx, &McpRequestCancellation::new())
                    .await
                    .unwrap();
                assert_eq!(recovery.process_exit.code, Some(23));
                assert_eq!(recovery.generation, 2);
                assert_eq!(fixture.count("effect"), 1);
                assert_eq!(fixture.count("start"), 2);
                owner.close_with_cx(&cx).await.unwrap();
            });
    }

    #[test]
    fn supervised_stdio_live_stdin_failure_has_uncertainty_but_cannot_restart() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let fixture = Fixture::new();
                let mut owner = fixture.connect(&cx, "live-stdin", quick_policy(2)).await;
                let deadline = Instant::now() + Duration::from_secs(2);
                while fixture.count("stdin-closed") == 0 {
                    assert!(Instant::now() < deadline);
                    asupersync::time::sleep(cx.now(), Duration::from_millis(2)).await;
                }
                assert!(
                    owner
                        .client
                        .child
                        .as_mut()
                        .unwrap()
                        .try_wait()
                        .unwrap()
                        .is_none()
                );
                let error = owner
                    .client_mut()
                    .unwrap()
                    .request_core_with_cx(
                        &cx,
                        &McpRequestCancellation::new(),
                        "tools/list",
                        json!({}),
                    )
                    .await
                    .unwrap_err();
                let evidence = StdioInterruptedRequest::from_error(&error).unwrap();
                assert_eq!(evidence.process_exit, None);
                assert!(!error.message.contains("process exited"));
                assert!(matches!(
                    owner.recover(&cx, &McpRequestCancellation::new()).await,
                    Err(StdioRestartError::NotRestartable)
                ));
                assert_eq!(fixture.count("start"), 1);
                assert_eq!(owner.restart_attempts(), 0);
                assert!(owner.client().child_cleanup_complete());
                owner.close_with_cx(&cx).await.unwrap();
            });
    }

    #[test]
    fn supervised_stdio_retries_proven_replacement_discovery_exit_within_original_cap() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                for attempts in [1, 2] {
                    let fixture = Fixture::new();
                    let mut owner = fixture
                        .connect(&cx, "recover-discovery-crash", quick_policy(attempts))
                        .await;
                    let _ = crash(&mut owner, &cx).await;
                    let token = McpRequestCancellation::new();
                    let deadline = Instant::now() + Duration::from_secs(2);
                    {
                        let mut recovery = Box::pin(owner.recover(&cx, &token));
                        loop {
                            poll_fn(|task_cx| {
                                assert!(recovery.as_mut().poll(task_cx).is_pending());
                                Poll::Ready(())
                            })
                            .await;
                            if fixture.count("discovery-crash-wait") == 1 {
                                break;
                            }
                            assert!(Instant::now() < deadline);
                            asupersync::time::sleep(cx.now(), Duration::from_millis(2)).await;
                        }
                    }
                    let original_deadline = owner.recovery.as_ref().unwrap().deadline;
                    assert_eq!(owner.restart_attempts(), 1);
                    std::fs::write(&fixture.gate, b"exit").unwrap();
                    wait_for_exit(&mut owner, &cx).await;
                    let result = owner.recover(&cx, &McpRequestCancellation::new()).await;
                    if attempts == 1 {
                        assert!(matches!(result, Err(StdioRestartError::AttemptsExhausted)));
                        assert_eq!(owner.generation(), 1);
                        assert_eq!(owner.recovery.as_ref().unwrap().deadline, original_deadline);
                        assert_eq!(fixture.count("start"), 2);
                    } else {
                        let recovery = result.unwrap();
                        assert_eq!(recovery.attempts, 2);
                        assert_eq!((recovery.previous_generation, recovery.generation), (1, 2));
                        assert_eq!(fixture.count("start"), 3);
                        assert_eq!(fixture.count("discovery"), 3);
                        owner
                            .client_mut()
                            .unwrap()
                            .request_core_with_cx(
                                &cx,
                                &McpRequestCancellation::new(),
                                "tools/list",
                                json!({}),
                            )
                            .await
                            .unwrap();
                    }
                    assert_eq!(owner.restart_attempts(), u64::from(attempts));
                    assert_eq!(fixture.count("effect"), 1);
                    owner.close_with_cx(&cx).await.unwrap();
                }
            });
    }

    #[test]
    fn supervised_stdio_replacement_discovery_protocol_failures_are_not_retried() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                for mode in ["recover-discovery-malformed", "recover-discovery-rejected"] {
                    let fixture = Fixture::new();
                    let mut owner = fixture.connect(&cx, mode, quick_policy(3)).await;
                    let _ = crash(&mut owner, &cx).await;
                    assert!(matches!(
                        owner.recover(&cx, &McpRequestCancellation::new()).await,
                        Err(StdioRestartError::Connection(_))
                    ));
                    assert_eq!(owner.generation(), 1);
                    assert_eq!(owner.restart_attempts(), 1);
                    assert_eq!(fixture.count("start"), 2);
                    assert!(owner.client().child_cleanup_complete());
                    owner.close_with_cx(&cx).await.unwrap();
                }
            });
    }

    #[test]
    fn supervised_stdio_crash_loop_cap_survives_successful_discovery() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let fixture = Fixture::new();
                let mut owner = fixture.connect(&cx, "effect", quick_policy(1)).await;
                let _ = crash(&mut owner, &cx).await;
                owner
                    .recover(&cx, &McpRequestCancellation::new())
                    .await
                    .unwrap();
                let _ = crash(&mut owner, &cx).await;
                assert!(matches!(
                    owner.recover(&cx, &McpRequestCancellation::new()).await,
                    Err(StdioRestartError::AttemptsExhausted)
                ));
                assert!(matches!(
                    owner.recover(&cx, &McpRequestCancellation::new()).await,
                    Err(StdioRestartError::AttemptsExhausted)
                ));
                assert_eq!(owner.generation(), 2);
                assert_eq!(owner.restart_attempts(), 1);
                assert_eq!(fixture.count("start"), 2);
                owner.close_with_cx(&cx).await.unwrap();
            });
    }

    #[test]
    fn supervised_stdio_replacement_uses_the_frozen_executable_path() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let fixture = Fixture::new();
                let executable = fixture.directory.join("server");
                std::os::unix::fs::symlink("/bin/sh", &executable).unwrap();
                let mut owner = fixture
                    .builder("effect")
                    .connect_supervised_stdio_with_cx(
                        &cx,
                        "./server",
                        &["-c", PEER],
                        quick_policy(2),
                    )
                    .await
                    .unwrap();
                let _ = crash(&mut owner, &cx).await;
                // Preserve the original fixture while changing the configured
                // relative path. Recovery must use the initially resolved path.
                std::fs::rename(&executable, fixture.directory.join("original-server")).unwrap();
                std::os::unix::fs::symlink("/bin/false", &executable).unwrap();
                owner
                    .recover(&cx, &McpRequestCancellation::new())
                    .await
                    .unwrap();
                assert_eq!(owner.generation(), 2);
                assert_eq!(fixture.count("start"), 2);
                assert_eq!(fixture.count("discovery"), 2);
                assert_eq!(fixture.count("effect"), 1);
                owner.close_with_cx(&cx).await.unwrap();
            });
    }

    #[test]
    fn supervised_stdio_cancelled_and_dropped_backoff_never_spawns_or_resets_window() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let fixture = Fixture::new();
                let policy = StdioRestartPolicy::new(
                    2,
                    Duration::from_secs(3),
                    Duration::from_millis(200),
                    Duration::from_millis(200),
                )
                .unwrap();
                let mut owner = fixture.connect(&cx, "effect", policy).await;
                let _ = crash(&mut owner, &cx).await;
                let cancelled = McpRequestCancellation::new();
                cancelled.cancel();
                assert!(matches!(
                    owner.recover(&cx, &cancelled).await,
                    Err(StdioRestartError::Cancelled)
                ));
                let deadline = owner.recovery.as_ref().unwrap().deadline;
                let token = McpRequestCancellation::new();
                {
                    let mut recovery = Box::pin(owner.recover(&cx, &token));
                    poll_fn(|task_cx| {
                        assert!(recovery.as_mut().poll(task_cx).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                }
                assert_eq!(owner.recovery.as_ref().unwrap().deadline, deadline);
                assert_eq!(owner.restart_attempts(), 0);
                assert_eq!(fixture.count("start"), 1);
                let token = McpRequestCancellation::new();
                let mut recovery = Box::pin(owner.recover(&cx, &token));
                poll_fn(|task_cx| {
                    assert!(recovery.as_mut().poll(task_cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                token.cancel();
                assert!(matches!(recovery.await, Err(StdioRestartError::Cancelled)));
                assert_eq!(owner.recovery.as_ref().unwrap().deadline, deadline);
                assert_eq!(owner.restart_attempts(), 0);
                assert_eq!(fixture.count("start"), 1);
                owner
                    .recover(&cx, &McpRequestCancellation::new())
                    .await
                    .unwrap();
                assert_eq!(owner.restart_attempts(), 1);
                assert_eq!(fixture.count("start"), 2);
                owner.close_with_cx(&cx).await.unwrap();
            });
    }

    #[test]
    fn supervised_stdio_cancelled_incident_expires_without_a_new_spawn() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let fixture = Fixture::new();
                // Startup receives its own window; make the short recovery limit
                // effective only after the real initial connection has completed.
                let mut owner = fixture.connect(&cx, "effect", quick_policy(2)).await;
                owner.policy = StdioRestartPolicy::new(
                    2,
                    Duration::from_millis(40),
                    Duration::from_millis(30),
                    Duration::from_millis(30),
                )
                .unwrap();
                let _ = crash(&mut owner, &cx).await;
                let cancelled = McpRequestCancellation::new();
                cancelled.cancel();
                assert!(matches!(
                    owner.recover(&cx, &cancelled).await,
                    Err(StdioRestartError::Cancelled)
                ));
                asupersync::time::sleep(cx.now(), Duration::from_millis(60)).await;
                assert!(matches!(
                    owner.recover(&cx, &McpRequestCancellation::new()).await,
                    Err(StdioRestartError::WindowExpired)
                ));
                assert_eq!(owner.restart_attempts(), 0);
                assert_eq!(fixture.count("start"), 1);
                owner.close_with_cx(&cx).await.unwrap();
            });
    }

    #[test]
    fn supervised_stdio_dropped_discovery_retains_child_and_attempt() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let fixture = Fixture::new();
                let mut owner = fixture.connect(&cx, "gated", quick_policy(2)).await;
                let _ = crash(&mut owner, &cx).await;
                let token = McpRequestCancellation::new();
                let deadline = Instant::now() + Duration::from_secs(2);
                {
                    let mut recovery = Box::pin(owner.recover(&cx, &token));
                    loop {
                        poll_fn(|task_cx| {
                            assert!(recovery.as_mut().poll(task_cx).is_pending());
                            Poll::Ready(())
                        })
                        .await;
                        if fixture.count("discovery") == 2 {
                            break;
                        }
                        assert!(
                            Instant::now() < deadline,
                            "replacement discovery never began"
                        );
                        asupersync::time::sleep(cx.now(), Duration::from_millis(2)).await;
                    }
                }
                assert_eq!(owner.restart_attempts(), 1);
                assert_eq!(owner.generation(), 1);
                assert!(owner.client.child.is_some());
                assert!(matches!(
                    owner.client_mut(),
                    Err(StdioRestartError::RecoveryInProgress)
                ));
                std::fs::write(&fixture.gate, b"continue").unwrap();
                owner
                    .recover(&cx, &McpRequestCancellation::new())
                    .await
                    .unwrap();
                assert_eq!(owner.generation(), 2);
                assert_eq!(owner.restart_attempts(), 1);
                assert_eq!(fixture.count("start"), 2);
                assert_eq!(
                    fixture.count("discovery"),
                    2,
                    "retained handshake must not send discovery twice"
                );
                assert_eq!(fixture.count("effect"), 1);
                owner.close_with_cx(&cx).await.unwrap();
            });
    }

    #[test]
    fn supervised_stdio_malformed_exit_is_not_a_restartable_crash() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let fixture = Fixture::new();
                let mut owner = fixture.connect(&cx, "malformed", quick_policy(2)).await;
                let (_, _, error) = crash(&mut owner, &cx).await;
                assert!(StdioInterruptedRequest::from_error(&error).is_none());
                assert!(matches!(
                    owner.recover(&cx, &McpRequestCancellation::new()).await,
                    Err(StdioRestartError::NotRestartable)
                ));
                assert_eq!(fixture.count("start"), 1);
                owner.close_with_cx(&cx).await.unwrap();
            });
    }

    #[test]
    fn supervised_stdio_live_eof_cannot_become_crash_evidence_after_cleanup() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let fixture = Fixture::new();
                let mut owner = fixture.connect(&cx, "live-eof", quick_policy(2)).await;
                let _request = issue_effect(&mut owner, &cx);
                let deadline = Instant::now() + Duration::from_secs(2);
                while fixture.count("stdout-closed") == 0 {
                    assert!(Instant::now() < deadline);
                    asupersync::time::sleep(cx.now(), Duration::from_millis(2)).await;
                }
                assert!(
                    owner
                        .client
                        .child
                        .as_mut()
                        .unwrap()
                        .try_wait()
                        .unwrap()
                        .is_none()
                );
                let error = owner
                    .client_mut()
                    .unwrap()
                    .drive_multiplexed_stdio(&cx)
                    .unwrap_err();
                assert!(StdioInterruptedRequest::from_error(&error).is_none());
                assert!(matches!(
                    owner.recover(&cx, &McpRequestCancellation::new()).await,
                    Err(StdioRestartError::NotRestartable)
                ));
                assert_eq!(fixture.count("start"), 1);
                assert!(owner.client().child_cleanup_complete());
                owner.close_with_cx(&cx).await.unwrap();
            });
    }

    #[test]
    fn supervised_stdio_cleanup_error_vetoes_replacement() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let fixture = Fixture::new();
                let mut owner = fixture.connect(&cx, "effect", quick_policy(2)).await;
                let _ = crash(&mut owner, &cx).await;
                // Inject a retained teardown failure after a real subprocess exit.
                // The same sticky error field is populated by transport/OS cleanup.
                owner.client.cleanup_error =
                    Some(McpError::internal_error("fixture cleanup failure"));
                assert!(matches!(
                    owner.recover(&cx, &McpRequestCancellation::new()).await,
                    Err(StdioRestartError::Cleanup(_))
                ));
                assert!(matches!(
                    owner.recover(&cx, &McpRequestCancellation::new()).await,
                    Err(StdioRestartError::Cleanup(_))
                ));
                assert_eq!(owner.restart_attempts(), 0);
                assert_eq!(fixture.count("start"), 1);
                let _ = owner.close_with_cx(&cx).await;
            });
    }

    #[test]
    fn supervised_stdio_application_and_cancellation_errors_do_not_spawn() {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                let fixture = Fixture::new();
                let mut owner = fixture.connect(&cx, "application", quick_policy(2)).await;
                let error = owner
                    .client_mut()
                    .unwrap()
                    .request_core_with_cx(
                        &cx,
                        &McpRequestCancellation::new(),
                        "tools/call",
                        json!({"name":"effect","arguments":{}}),
                    )
                    .await
                    .unwrap_err();
                assert_eq!(error.code, McpErrorCode::InvalidParams);
                assert!(StdioInterruptedRequest::from_error(&error).is_none());
                assert!(matches!(
                    owner.recover(&cx, &McpRequestCancellation::new()).await,
                    Err(StdioRestartError::NotRestartable)
                ));
                let cancelled = McpRequestCancellation::new();
                cancelled.cancel();
                let error = owner
                    .client_mut()
                    .unwrap()
                    .request_core_with_cx(&cx, &cancelled, "tools/list", json!({}))
                    .await
                    .unwrap_err();
                assert_eq!(error.code, McpErrorCode::RequestCancelled);
                assert!(matches!(
                    owner.recover(&cx, &McpRequestCancellation::new()).await,
                    Err(StdioRestartError::NotRestartable)
                ));
                assert_eq!(fixture.count("start"), 1);
                assert_eq!(fixture.count("list"), 0);
                owner.close_with_cx(&cx).await.unwrap();
            });
    }

    #[test]
    fn supervised_stdio_policy_and_era_admission_are_bounded() {
        assert!(
            StdioRestartPolicy::new(
                0,
                Duration::from_secs(1),
                Duration::from_millis(1),
                Duration::from_millis(1)
            )
            .is_err()
        );
        assert!(
            StdioRestartPolicy::new(
                9,
                Duration::from_secs(1),
                Duration::from_millis(1),
                Duration::from_millis(1)
            )
            .is_err()
        );
        assert!(
            StdioRestartPolicy::new(
                1,
                Duration::from_secs(301),
                Duration::from_millis(1),
                Duration::from_millis(1)
            )
            .is_err()
        );
        for policy in [ProtocolPolicy::Auto, ProtocolPolicy::LegacyOnly] {
            let builder = ClientBuilder::new().protocol_plan(ClientProtocolPlan::stdio(policy));
            assert!(builder.freeze_stdio_restart("sh").is_err());
        }
        let policy = quick_policy(3);
        for attempt in 0..10 {
            let delay = jittered_delay(policy, attempt, 123, 456);
            assert_eq!(delay, jittered_delay(policy, attempt, 123, 456));
            assert!(!delay.is_zero());
            assert!(delay <= policy.max_backoff());
        }
    }
}
