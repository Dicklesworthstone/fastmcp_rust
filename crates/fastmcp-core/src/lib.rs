//! Core types and traits for FastMCP.
//!
//! This crate provides the fundamental building blocks:
//! - [`McpContext`] wrapping asupersync's [`Cx`]
//! - Error types for MCP operations
//! - Capability traits for progress, sampling, elicitation, and nested calls
//!
//! MCP 2026-07-28 support is under implementation and remains unverified. The
//! public protocol constant is still `2024-11-05`; this crate's primitives are
//! not aggregate conformance or release evidence.
//!
//! # Design Principles
//!
//! - Serde-backed protocol and context types
//! - No runtime reflection (compile-time via macros)
//! - `Send + Sync` bounds on concurrency-facing APIs where required
//! - Explicit cancellation and budget surfaces through asupersync
//!
//! # Role in the System
//!
//! `fastmcp-core` is the **foundation layer** shared by every other crate.
//! It defines:
//! - `McpContext`, the capability-carrying handle that wraps asupersync's `Cx`
//! - The FastMCP error model (`McpError`, `McpErrorCode`, `McpResult`)
//! - Budget and cancellation primitives used by handlers and transports
//! - Outcome bridging utilities so server/client code can stay 4-valued
//!
//! If you are implementing a new transport, handler, or runtime adapter, this
//! is the crate that gives you the shared primitives used everywhere else.
//!
//! # Asupersync Integration
//!
//! This crate uses [asupersync](https://github.com/Dicklesworthstone/asupersync) as its async
//! runtime foundation, providing:
//!
//! - **Context propagation**: `McpContext` carries an asupersync `Cx`
//! - **Cooperative cancellation**: Explicit checkpoints surface cancellation
//! - **Budgets**: Deadline, poll, and cost dimensions travel with contexts
//! - **Deterministic test support**: The lab runtime is available to tests

#![forbid(unsafe_code)]
// Allow dead code during Phase 0 development
#![allow(dead_code)]

mod auth;
pub mod combinator;
mod context;
pub mod crypto;
mod duration;
mod error;
pub mod logging;
pub mod runtime;
mod state;
pub mod uri;

/// Immutable protocol-limit snapshots and cumulative logical-exchange admission.
pub mod limits {
    use std::fmt;
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::Duration;

    use asupersync::Time;

    use crate::McpContext;

    /// Default maximum number of rounds in one logical exchange.
    pub const DEFAULT_LOGICAL_EXCHANGE_MAX_ROUNDS: u16 = 8;
    /// Hard maximum number of rounds in one logical exchange.
    pub const HARD_LOGICAL_EXCHANGE_MAX_ROUNDS: u16 = 32;
    /// Default maximum inputs admitted in one logical-exchange round.
    pub const DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS_PER_ROUND: u16 = 32;
    /// Hard maximum inputs admitted in one logical-exchange round.
    pub const HARD_LOGICAL_EXCHANGE_MAX_INPUTS_PER_ROUND: u16 = 128;
    /// Default maximum inputs admitted cumulatively in one logical exchange.
    pub const DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS: u16 = 128;
    /// Hard maximum inputs admitted cumulatively in one logical exchange.
    pub const HARD_LOGICAL_EXCHANGE_MAX_INPUTS: u16 = 512;
    /// Default maximum encoded state bytes admitted in one logical exchange.
    pub const DEFAULT_LOGICAL_EXCHANGE_MAX_STATE_BYTES: usize = 64 * 1024;
    /// Hard maximum encoded state bytes admitted in one logical exchange.
    pub const HARD_LOGICAL_EXCHANGE_MAX_STATE_BYTES: usize = 256 * 1024;
    /// Default absolute wall-clock allowance for one logical exchange.
    pub const DEFAULT_LOGICAL_EXCHANGE_MAX_WALL_CLOCK: Duration = Duration::from_mins(15);
    /// Hard absolute wall-clock allowance for one logical exchange.
    pub const HARD_LOGICAL_EXCHANGE_MAX_WALL_CLOCK: Duration = Duration::from_hours(1);

    /// A configurable logical-exchange limit in [`ProtocolLimits`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ProtocolLimit {
        /// The cumulative round limit.
        LogicalExchangeRounds,
        /// The per-round input limit.
        LogicalExchangeInputsPerRound,
        /// The cumulative input limit.
        LogicalExchangeInputs,
        /// The cumulative encoded-state-byte limit.
        LogicalExchangeStateBytes,
        /// The absolute wall-clock allowance.
        LogicalExchangeWallClock,
    }

    impl fmt::Display for ProtocolLimit {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            let name = match self {
                Self::LogicalExchangeRounds => "logical-exchange rounds",
                Self::LogicalExchangeInputsPerRound => "logical-exchange inputs per round",
                Self::LogicalExchangeInputs => "logical-exchange inputs",
                Self::LogicalExchangeStateBytes => "logical-exchange state bytes",
                Self::LogicalExchangeWallClock => "logical-exchange wall-clock allowance",
            };
            formatter.write_str(name)
        }
    }

    /// A validation failure while constructing immutable [`ProtocolLimits`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ProtocolLimitsError {
        /// A limit that must be positive was configured as zero.
        Zero { limit: ProtocolLimit },
        /// A soft limit exceeded its documented hard ceiling.
        ExceedsHardCeiling { limit: ProtocolLimit },
        /// A per-round input limit exceeded the exchange-wide input limit.
        InputsPerRoundExceedExchangeTotal { per_round: u16, total: u16 },
    }

    impl fmt::Display for ProtocolLimitsError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Zero { limit } => write!(formatter, "{limit} must be positive"),
                Self::ExceedsHardCeiling { limit } => {
                    write!(formatter, "{limit} exceeds its hard ceiling")
                }
                Self::InputsPerRoundExceedExchangeTotal { per_round, total } => write!(
                    formatter,
                    "logical-exchange inputs per round ({per_round}) exceed the exchange total ({total})"
                ),
            }
        }
    }

    impl std::error::Error for ProtocolLimitsError {}

    /// Immutable, validated limits captured by a logical operation at admission.
    ///
    /// This initial catalog owns the limits used by a logical multi-round
    /// exchange. Additional LIMIT-01 rows can extend the builder without
    /// allowing an already-created snapshot to change.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ProtocolLimits {
        max_rounds: u16,
        max_inputs_per_round: u16,
        max_inputs: u16,
        max_state_bytes: usize,
        max_wall_clock: Duration,
    }

    impl ProtocolLimits {
        /// Starts a builder configured with the documented default limits.
        #[must_use]
        pub fn builder() -> ProtocolLimitsBuilder {
            ProtocolLimitsBuilder::default()
        }

        /// Returns the cumulative logical-exchange round limit.
        #[must_use]
        pub const fn logical_exchange_max_rounds(&self) -> u16 {
            self.max_rounds
        }

        /// Returns the logical-exchange per-round input limit.
        #[must_use]
        pub const fn logical_exchange_max_inputs_per_round(&self) -> u16 {
            self.max_inputs_per_round
        }

        /// Returns the cumulative logical-exchange input limit.
        #[must_use]
        pub const fn logical_exchange_max_inputs(&self) -> u16 {
            self.max_inputs
        }

        /// Returns the cumulative encoded-state-byte limit for one exchange.
        #[must_use]
        pub const fn logical_exchange_max_state_bytes(&self) -> usize {
            self.max_state_bytes
        }

        /// Returns the absolute wall-clock allowance for one exchange.
        #[must_use]
        pub const fn logical_exchange_max_wall_clock(&self) -> Duration {
            self.max_wall_clock
        }

        /// Returns the componentwise stricter snapshot of `self` and `other`.
        ///
        /// A logical exchange can retain its original snapshot while meeting it
        /// with a tighter current policy or hard ceiling. No field in the
        /// returned snapshot can be looser than its counterpart in either
        /// input.
        #[must_use]
        pub fn meet(&self, other: &Self) -> Self {
            Self {
                max_rounds: self.max_rounds.min(other.max_rounds),
                max_inputs_per_round: self.max_inputs_per_round.min(other.max_inputs_per_round),
                max_inputs: self.max_inputs.min(other.max_inputs),
                max_state_bytes: self.max_state_bytes.min(other.max_state_bytes),
                max_wall_clock: self.max_wall_clock.min(other.max_wall_clock),
            }
        }

        /// Tightens this snapshot against `ceiling` componentwise.
        #[must_use]
        pub fn tighten(&self, ceiling: &Self) -> Self {
            self.meet(ceiling)
        }
    }

    impl Default for ProtocolLimits {
        fn default() -> Self {
            Self {
                max_rounds: DEFAULT_LOGICAL_EXCHANGE_MAX_ROUNDS,
                max_inputs_per_round: DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS_PER_ROUND,
                max_inputs: DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS,
                max_state_bytes: DEFAULT_LOGICAL_EXCHANGE_MAX_STATE_BYTES,
                max_wall_clock: DEFAULT_LOGICAL_EXCHANGE_MAX_WALL_CLOCK,
            }
        }
    }

    /// Builder for an immutable [`ProtocolLimits`] snapshot.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ProtocolLimitsBuilder {
        max_rounds: u16,
        max_inputs_per_round: u16,
        max_inputs: u16,
        max_state_bytes: usize,
        max_wall_clock: Duration,
    }

    impl Default for ProtocolLimitsBuilder {
        fn default() -> Self {
            Self {
                max_rounds: DEFAULT_LOGICAL_EXCHANGE_MAX_ROUNDS,
                max_inputs_per_round: DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS_PER_ROUND,
                max_inputs: DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS,
                max_state_bytes: DEFAULT_LOGICAL_EXCHANGE_MAX_STATE_BYTES,
                max_wall_clock: DEFAULT_LOGICAL_EXCHANGE_MAX_WALL_CLOCK,
            }
        }
    }

    impl ProtocolLimitsBuilder {
        /// Sets the cumulative logical-exchange round limit.
        #[must_use]
        pub const fn logical_exchange_max_rounds(mut self, value: u16) -> Self {
            self.max_rounds = value;
            self
        }

        /// Sets the logical-exchange per-round input limit.
        #[must_use]
        pub const fn logical_exchange_max_inputs_per_round(mut self, value: u16) -> Self {
            self.max_inputs_per_round = value;
            self
        }

        /// Sets the cumulative logical-exchange input limit.
        #[must_use]
        pub const fn logical_exchange_max_inputs(mut self, value: u16) -> Self {
            self.max_inputs = value;
            self
        }

        /// Sets the cumulative encoded-state-byte limit for one exchange.
        #[must_use]
        pub const fn logical_exchange_max_state_bytes(mut self, value: usize) -> Self {
            self.max_state_bytes = value;
            self
        }

        /// Sets the absolute wall-clock allowance for one exchange.
        #[must_use]
        pub const fn logical_exchange_max_wall_clock(mut self, value: Duration) -> Self {
            self.max_wall_clock = value;
            self
        }

        /// Validates and creates an immutable limit snapshot.
        pub fn build(self) -> Result<ProtocolLimits, ProtocolLimitsError> {
            validate_positive_u16(self.max_rounds, ProtocolLimit::LogicalExchangeRounds)?;
            validate_u16_ceiling(
                self.max_rounds,
                HARD_LOGICAL_EXCHANGE_MAX_ROUNDS,
                ProtocolLimit::LogicalExchangeRounds,
            )?;
            validate_positive_u16(
                self.max_inputs_per_round,
                ProtocolLimit::LogicalExchangeInputsPerRound,
            )?;
            validate_u16_ceiling(
                self.max_inputs_per_round,
                HARD_LOGICAL_EXCHANGE_MAX_INPUTS_PER_ROUND,
                ProtocolLimit::LogicalExchangeInputsPerRound,
            )?;
            validate_positive_u16(self.max_inputs, ProtocolLimit::LogicalExchangeInputs)?;
            validate_u16_ceiling(
                self.max_inputs,
                HARD_LOGICAL_EXCHANGE_MAX_INPUTS,
                ProtocolLimit::LogicalExchangeInputs,
            )?;
            if self.max_inputs_per_round > self.max_inputs {
                return Err(ProtocolLimitsError::InputsPerRoundExceedExchangeTotal {
                    per_round: self.max_inputs_per_round,
                    total: self.max_inputs,
                });
            }
            if self.max_state_bytes == 0 {
                return Err(ProtocolLimitsError::Zero {
                    limit: ProtocolLimit::LogicalExchangeStateBytes,
                });
            }
            if self.max_state_bytes > HARD_LOGICAL_EXCHANGE_MAX_STATE_BYTES {
                return Err(ProtocolLimitsError::ExceedsHardCeiling {
                    limit: ProtocolLimit::LogicalExchangeStateBytes,
                });
            }
            if self.max_wall_clock.is_zero() {
                return Err(ProtocolLimitsError::Zero {
                    limit: ProtocolLimit::LogicalExchangeWallClock,
                });
            }
            if self.max_wall_clock > HARD_LOGICAL_EXCHANGE_MAX_WALL_CLOCK {
                return Err(ProtocolLimitsError::ExceedsHardCeiling {
                    limit: ProtocolLimit::LogicalExchangeWallClock,
                });
            }

            Ok(ProtocolLimits {
                max_rounds: self.max_rounds,
                max_inputs_per_round: self.max_inputs_per_round,
                max_inputs: self.max_inputs,
                max_state_bytes: self.max_state_bytes,
                max_wall_clock: self.max_wall_clock,
            })
        }
    }

    fn validate_positive_u16(value: u16, limit: ProtocolLimit) -> Result<(), ProtocolLimitsError> {
        if value == 0 {
            Err(ProtocolLimitsError::Zero { limit })
        } else {
            Ok(())
        }
    }

    fn validate_u16_ceiling(
        value: u16,
        hard_ceiling: u16,
        limit: ProtocolLimit,
    ) -> Result<(), ProtocolLimitsError> {
        if value > hard_ceiling {
            Err(ProtocolLimitsError::ExceedsHardCeiling { limit })
        } else {
            Ok(())
        }
    }

    /// A resource whose cumulative logical-exchange accounting overflowed.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum LogicalExchangeBudgetResource {
        /// The number of started rounds.
        Rounds,
        /// The number of inputs in the current round.
        InputsInRound,
        /// The total number of inputs in the exchange.
        TotalInputs,
        /// The total number of charged encoded state bytes.
        StateBytes,
        /// The configured wall-clock duration in nanoseconds.
        WallClockNanos,
        /// The deadline instant in nanoseconds.
        DeadlineNanos,
    }

    /// A rejected logical-exchange admission or accounting operation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum LogicalExchangeBudgetError {
        /// The caller context was cancelled, expired, or otherwise no longer live.
        Cancelled,
        /// The exchange's immutable absolute deadline has expired.
        DeadlineExceeded,
        /// An input was admitted before a round began.
        InputOutsideRound,
        /// Starting another round would exceed the configured limit.
        RoundLimitExceeded { limit: u16 },
        /// The next input would exceed the current round's input limit.
        InputsPerRoundLimitExceeded { limit: u16 },
        /// The next input would exceed the exchange-wide input limit.
        InputsLimitExceeded { limit: u16 },
        /// The next byte charge would exceed the exchange-wide byte limit.
        StateByteLimitExceeded { limit: usize },
        /// Checked accounting could not represent the next value.
        ArithmeticOverflow {
            resource: LogicalExchangeBudgetResource,
        },
    }

    impl fmt::Display for LogicalExchangeBudgetError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Cancelled => formatter.write_str("logical-exchange caller context cancelled"),
                Self::DeadlineExceeded => formatter.write_str("logical-exchange deadline exceeded"),
                Self::InputOutsideRound => {
                    formatter.write_str("logical-exchange input requires a round")
                }
                Self::RoundLimitExceeded { limit } => {
                    write!(
                        formatter,
                        "logical-exchange round limit of {limit} exceeded"
                    )
                }
                Self::InputsPerRoundLimitExceeded { limit } => write!(
                    formatter,
                    "logical-exchange per-round input limit of {limit} exceeded"
                ),
                Self::InputsLimitExceeded { limit } => {
                    write!(
                        formatter,
                        "logical-exchange input limit of {limit} exceeded"
                    )
                }
                Self::StateByteLimitExceeded { limit } => {
                    write!(
                        formatter,
                        "logical-exchange state-byte limit of {limit} exceeded"
                    )
                }
                Self::ArithmeticOverflow { resource } => {
                    write!(
                        formatter,
                        "logical-exchange {resource:?} accounting overflowed"
                    )
                }
            }
        }
    }

    impl std::error::Error for LogicalExchangeBudgetError {}

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    struct LogicalExchangeCounters {
        rounds_started: u16,
        inputs_in_current_round: u16,
        inputs_admitted: u16,
        state_bytes_admitted: usize,
    }

    /// Cumulative, checked admission accounting for one logical exchange.
    ///
    /// The budget owns one immutable [`ProtocolLimits`] snapshot and an
    /// absolute deadline. Every failed operation leaves its counters unchanged;
    /// callers can therefore reserve an input and its prospective state bytes
    /// atomically before performing the associated work.
    #[derive(Debug, Clone)]
    pub struct LogicalExchangeBudget {
        limits: ProtocolLimits,
        deadline: Time,
        context: McpContext,
        counters: Arc<Mutex<LogicalExchangeCounters>>,
        #[cfg(test)]
        before_counter_lock: Option<Arc<std::sync::Barrier>>,
    }

    impl PartialEq for LogicalExchangeBudget {
        fn eq(&self, other: &Self) -> bool {
            if self.limits != other.limits || self.deadline != other.deadline {
                return false;
            }

            // Clones intentionally share counters. Do not attempt to lock the
            // same non-reentrant mutex twice when comparing a budget with
            // itself or one of its clones.
            if Arc::ptr_eq(&self.counters, &other.counters) {
                return true;
            }

            // Take snapshots in allocation-address order. Each lock guard is
            // dropped before acquiring the next one, so two threads comparing
            // the same distinct budgets in opposite orders cannot deadlock.
            let self_counters_address = Arc::as_ptr(&self.counters).addr();
            let other_counters_address = Arc::as_ptr(&other.counters).addr();
            let (self_counters, other_counters) = if self_counters_address < other_counters_address
            {
                let self_counters = *self.counters();
                let other_counters = *other.counters();
                (self_counters, other_counters)
            } else {
                let other_counters = *other.counters();
                let self_counters = *self.counters();
                (self_counters, other_counters)
            };

            self_counters == other_counters
        }
    }

    impl Eq for LogicalExchangeBudget {}

    impl LogicalExchangeBudget {
        /// Captures `limits` and the caller context's time, deadline, and cancellation domain.
        pub fn new(
            limits: ProtocolLimits,
            context: &McpContext,
        ) -> Result<Self, LogicalExchangeBudgetError> {
            Self::with_external_deadline(limits, context, None)
        }

        /// Captures `limits` and meets its deadline with the caller context and `external_deadline`.
        ///
        /// The earlier of the configured logical-exchange deadline and
        /// the caller context's budget deadline and `external_deadline` is
        /// retained. The deadline can never be extended after construction.
        pub fn with_external_deadline(
            limits: ProtocolLimits,
            context: &McpContext,
            external_deadline: Option<Time>,
        ) -> Result<Self, LogicalExchangeBudgetError> {
            context
                .ensure_live()
                .map_err(|_| LogicalExchangeBudgetError::Cancelled)?;
            let started_at = context.cx().now();
            let outer_deadline = match (context.budget().deadline, external_deadline) {
                (Some(context_deadline), Some(external_deadline)) => {
                    Some(context_deadline.min(external_deadline))
                }
                (Some(context_deadline), None) => Some(context_deadline),
                (None, Some(external_deadline)) => Some(external_deadline),
                (None, None) => None,
            };
            let deadline = Self::calculate_deadline(&limits, started_at, outer_deadline)?;

            Ok(Self {
                limits,
                deadline,
                context: context.clone(),
                counters: Arc::new(Mutex::new(LogicalExchangeCounters::default())),
                #[cfg(test)]
                before_counter_lock: None,
            })
        }

        fn calculate_deadline(
            limits: &ProtocolLimits,
            started_at: Time,
            external_deadline: Option<Time>,
        ) -> Result<Time, LogicalExchangeBudgetError> {
            let duration_nanos = u64::try_from(limits.max_wall_clock.as_nanos()).map_err(|_| {
                LogicalExchangeBudgetError::ArithmeticOverflow {
                    resource: LogicalExchangeBudgetResource::WallClockNanos,
                }
            })?;
            let deadline_nanos = started_at.as_nanos().checked_add(duration_nanos).ok_or(
                LogicalExchangeBudgetError::ArithmeticOverflow {
                    resource: LogicalExchangeBudgetResource::DeadlineNanos,
                },
            )?;
            let configured_deadline = Time::from_nanos(deadline_nanos);
            let deadline = external_deadline
                .map_or(configured_deadline, |outer| outer.min(configured_deadline));

            Ok(deadline)
        }

        fn counters(&self) -> MutexGuard<'_, LogicalExchangeCounters> {
            #[cfg(test)]
            if let Some(barrier) = &self.before_counter_lock {
                barrier.wait();
            }

            self.counters
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }

        #[cfg(test)]
        fn with_before_counter_lock_barrier(mut self, barrier: Arc<std::sync::Barrier>) -> Self {
            self.before_counter_lock = Some(barrier);
            self
        }

        fn check_admission(&self) -> Result<(), LogicalExchangeBudgetError> {
            if self.context.cx().now() >= self.deadline {
                return Err(LogicalExchangeBudgetError::DeadlineExceeded);
            }
            self.context
                .ensure_live()
                .map_err(|_| LogicalExchangeBudgetError::Cancelled)
        }

        /// Checks caller liveness while the clone-shared counters are locked.
        ///
        /// Mutators use this at their commit boundary so an admission that
        /// waited behind another clone cannot commit after cancellation or a
        /// deadline transition.
        fn check_admission_while_holding_counters(
            &self,
            _counters: &MutexGuard<'_, LogicalExchangeCounters>,
        ) -> Result<(), LogicalExchangeBudgetError> {
            self.check_admission()
        }

        /// Returns the immutable limit snapshot used by this exchange.
        #[must_use]
        pub const fn limits(&self) -> &ProtocolLimits {
            &self.limits
        }

        /// Returns the immutable absolute deadline for this exchange.
        #[must_use]
        pub const fn deadline(&self) -> Time {
            self.deadline
        }

        /// Returns the number of successfully started rounds.
        #[must_use]
        pub fn rounds_started(&self) -> u16 {
            self.counters().rounds_started
        }

        /// Returns the number of inputs admitted in the active round.
        #[must_use]
        pub fn inputs_in_current_round(&self) -> u16 {
            self.counters().inputs_in_current_round
        }

        /// Returns the total inputs admitted by the exchange.
        #[must_use]
        pub fn inputs_admitted(&self) -> u16 {
            self.counters().inputs_admitted
        }

        /// Returns the total encoded state bytes admitted by the exchange.
        #[must_use]
        pub fn state_bytes_admitted(&self) -> usize {
            self.counters().state_bytes_admitted
        }

        /// Fails when the caller context is cancelled or the immutable deadline has elapsed.
        pub fn check_deadline(&self) -> Result<(), LogicalExchangeBudgetError> {
            self.check_admission()
        }

        /// Starts one round after checking the exchange deadline and round limit.
        pub fn try_start_round(&self) -> Result<(), LogicalExchangeBudgetError> {
            let mut counters = self.counters();
            self.check_admission_while_holding_counters(&counters)?;
            let next_rounds = counters.rounds_started.checked_add(1).ok_or(
                LogicalExchangeBudgetError::ArithmeticOverflow {
                    resource: LogicalExchangeBudgetResource::Rounds,
                },
            )?;
            if next_rounds > self.limits.max_rounds {
                return Err(LogicalExchangeBudgetError::RoundLimitExceeded {
                    limit: self.limits.max_rounds,
                });
            }

            let next_counters = LogicalExchangeCounters {
                rounds_started: next_rounds,
                inputs_in_current_round: 0,
                inputs_admitted: counters.inputs_admitted,
                state_bytes_admitted: counters.state_bytes_admitted,
            };
            self.check_admission_while_holding_counters(&counters)?;
            *counters = next_counters;
            Ok(())
        }

        /// Atomically reserves one input and its prospective encoded state bytes.
        pub fn try_reserve_input(
            &self,
            state_bytes: usize,
        ) -> Result<(), LogicalExchangeBudgetError> {
            let mut counters = self.counters();
            self.check_admission_while_holding_counters(&counters)?;
            if counters.rounds_started == 0 {
                return Err(LogicalExchangeBudgetError::InputOutsideRound);
            }

            let next_round_inputs = counters.inputs_in_current_round.checked_add(1).ok_or(
                LogicalExchangeBudgetError::ArithmeticOverflow {
                    resource: LogicalExchangeBudgetResource::InputsInRound,
                },
            )?;
            if next_round_inputs > self.limits.max_inputs_per_round {
                return Err(LogicalExchangeBudgetError::InputsPerRoundLimitExceeded {
                    limit: self.limits.max_inputs_per_round,
                });
            }
            let next_total_inputs = counters.inputs_admitted.checked_add(1).ok_or(
                LogicalExchangeBudgetError::ArithmeticOverflow {
                    resource: LogicalExchangeBudgetResource::TotalInputs,
                },
            )?;
            if next_total_inputs > self.limits.max_inputs {
                return Err(LogicalExchangeBudgetError::InputsLimitExceeded {
                    limit: self.limits.max_inputs,
                });
            }
            let next_state_bytes = counters
                .state_bytes_admitted
                .checked_add(state_bytes)
                .ok_or(LogicalExchangeBudgetError::ArithmeticOverflow {
                    resource: LogicalExchangeBudgetResource::StateBytes,
                })?;
            if next_state_bytes > self.limits.max_state_bytes {
                return Err(LogicalExchangeBudgetError::StateByteLimitExceeded {
                    limit: self.limits.max_state_bytes,
                });
            }

            let next_counters = LogicalExchangeCounters {
                rounds_started: counters.rounds_started,
                inputs_in_current_round: next_round_inputs,
                inputs_admitted: next_total_inputs,
                state_bytes_admitted: next_state_bytes,
            };
            self.check_admission_while_holding_counters(&counters)?;
            *counters = next_counters;
            Ok(())
        }

        /// Atomically reserves encoded state bytes not associated with a new input.
        pub fn try_reserve_state_bytes(
            &self,
            state_bytes: usize,
        ) -> Result<(), LogicalExchangeBudgetError> {
            let mut counters = self.counters();
            self.check_admission_while_holding_counters(&counters)?;
            let next_state_bytes = counters
                .state_bytes_admitted
                .checked_add(state_bytes)
                .ok_or(LogicalExchangeBudgetError::ArithmeticOverflow {
                    resource: LogicalExchangeBudgetResource::StateBytes,
                })?;
            if next_state_bytes > self.limits.max_state_bytes {
                return Err(LogicalExchangeBudgetError::StateByteLimitExceeded {
                    limit: self.limits.max_state_bytes,
                });
            }

            let next_counters = LogicalExchangeCounters {
                rounds_started: counters.rounds_started,
                inputs_in_current_round: counters.inputs_in_current_round,
                inputs_admitted: counters.inputs_admitted,
                state_bytes_admitted: next_state_bytes,
            };
            self.check_admission_while_holding_counters(&counters)?;
            *counters = next_counters;
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use std::sync::{Arc, Barrier};

        use super::*;
        use crate::{Budget, Cx, McpRequestCancellation};

        fn small_limits() -> ProtocolLimits {
            ProtocolLimits::builder()
                .logical_exchange_max_rounds(2)
                .logical_exchange_max_inputs_per_round(2)
                .logical_exchange_max_inputs(3)
                .logical_exchange_max_state_bytes(9)
                .logical_exchange_max_wall_clock(Duration::from_secs(5))
                .build()
                .unwrap()
        }

        #[test]
        fn protocol_limits_default_and_boundary_validation_are_exact() {
            let defaults = ProtocolLimits::default();
            assert_eq!(
                defaults.logical_exchange_max_rounds(),
                DEFAULT_LOGICAL_EXCHANGE_MAX_ROUNDS
            );
            assert_eq!(
                defaults.logical_exchange_max_inputs_per_round(),
                DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS_PER_ROUND
            );
            assert_eq!(
                defaults.logical_exchange_max_inputs(),
                DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS
            );
            assert_eq!(
                defaults.logical_exchange_max_state_bytes(),
                DEFAULT_LOGICAL_EXCHANGE_MAX_STATE_BYTES
            );
            assert_eq!(
                defaults.logical_exchange_max_wall_clock(),
                DEFAULT_LOGICAL_EXCHANGE_MAX_WALL_CLOCK
            );

            assert!(
                ProtocolLimits::builder()
                    .logical_exchange_max_rounds(HARD_LOGICAL_EXCHANGE_MAX_ROUNDS)
                    .logical_exchange_max_inputs_per_round(
                        HARD_LOGICAL_EXCHANGE_MAX_INPUTS_PER_ROUND
                    )
                    .logical_exchange_max_inputs(HARD_LOGICAL_EXCHANGE_MAX_INPUTS)
                    .logical_exchange_max_state_bytes(HARD_LOGICAL_EXCHANGE_MAX_STATE_BYTES)
                    .logical_exchange_max_wall_clock(HARD_LOGICAL_EXCHANGE_MAX_WALL_CLOCK)
                    .build()
                    .is_ok()
            );
            assert_eq!(
                ProtocolLimits::builder()
                    .logical_exchange_max_rounds(HARD_LOGICAL_EXCHANGE_MAX_ROUNDS + 1)
                    .build(),
                Err(ProtocolLimitsError::ExceedsHardCeiling {
                    limit: ProtocolLimit::LogicalExchangeRounds,
                })
            );
            assert_eq!(
                ProtocolLimits::builder()
                    .logical_exchange_max_inputs_per_round(2)
                    .logical_exchange_max_inputs(1)
                    .build(),
                Err(ProtocolLimitsError::InputsPerRoundExceedExchangeTotal {
                    per_round: 2,
                    total: 1,
                })
            );
        }

        #[test]
        fn protocol_limits_meet_tightens_every_field_without_mutating_inputs() {
            let original = ProtocolLimits::builder()
                .logical_exchange_max_rounds(8)
                .logical_exchange_max_inputs_per_round(7)
                .logical_exchange_max_inputs(9)
                .logical_exchange_max_state_bytes(80)
                .logical_exchange_max_wall_clock(Duration::from_secs(12))
                .build()
                .unwrap();
            let ceiling = ProtocolLimits::builder()
                .logical_exchange_max_rounds(6)
                .logical_exchange_max_inputs_per_round(5)
                .logical_exchange_max_inputs(6)
                .logical_exchange_max_state_bytes(64)
                .logical_exchange_max_wall_clock(Duration::from_secs(9))
                .build()
                .unwrap();

            let tightened = original.meet(&ceiling);
            assert_eq!(tightened.logical_exchange_max_rounds(), 6);
            assert_eq!(tightened.logical_exchange_max_inputs_per_round(), 5);
            assert_eq!(tightened.logical_exchange_max_inputs(), 6);
            assert_eq!(tightened.logical_exchange_max_state_bytes(), 64);
            assert_eq!(
                tightened.logical_exchange_max_wall_clock(),
                Duration::from_secs(9)
            );
            assert_eq!(original.tighten(&ceiling), tightened);
            assert_eq!(original.logical_exchange_max_rounds(), 8);
            assert_eq!(original.logical_exchange_max_inputs_per_round(), 7);
            assert_eq!(original.logical_exchange_max_inputs(), 9);
            assert_eq!(original.logical_exchange_max_state_bytes(), 80);
            assert_eq!(
                original.logical_exchange_max_wall_clock(),
                Duration::from_secs(12)
            );
        }

        #[test]
        fn logical_exchange_budget_cumulatively_charges_valid_rounds_inputs_and_bytes() {
            let context = McpContext::new(Cx::for_testing(), 1);
            let budget = LogicalExchangeBudget::new(small_limits(), &context).unwrap();

            budget.try_start_round().unwrap();
            budget.try_reserve_input(3).unwrap();
            budget.try_reserve_input(4).unwrap();
            budget.try_start_round().unwrap();
            budget.try_reserve_input(2).unwrap();

            assert_eq!(budget.rounds_started(), 2);
            assert_eq!(budget.inputs_in_current_round(), 1);
            assert_eq!(budget.inputs_admitted(), 3);
            assert_eq!(budget.state_bytes_admitted(), 9);
            assert_eq!(budget.check_deadline(), Ok(()));
        }

        #[test]
        fn logical_exchange_budget_rejects_overages_without_mutating_accounting() {
            let context = McpContext::new(Cx::for_testing(), 1);
            let budget = LogicalExchangeBudget::new(small_limits(), &context).unwrap();

            assert_eq!(
                budget.try_reserve_input(1),
                Err(LogicalExchangeBudgetError::InputOutsideRound)
            );
            budget.try_start_round().unwrap();
            budget.try_reserve_input(3).unwrap();
            budget.try_reserve_input(4).unwrap();
            assert_eq!(
                budget.try_reserve_input(1),
                Err(LogicalExchangeBudgetError::InputsPerRoundLimitExceeded { limit: 2 })
            );
            assert_eq!(budget.inputs_in_current_round(), 2);
            assert_eq!(budget.inputs_admitted(), 2);
            assert_eq!(budget.state_bytes_admitted(), 7);

            budget.try_start_round().unwrap();
            budget.try_reserve_input(2).unwrap();
            assert_eq!(
                budget.try_reserve_input(0),
                Err(LogicalExchangeBudgetError::InputsLimitExceeded { limit: 3 })
            );
            assert_eq!(
                budget.try_reserve_state_bytes(1),
                Err(LogicalExchangeBudgetError::StateByteLimitExceeded { limit: 9 })
            );
            assert_eq!(
                budget.try_reserve_state_bytes(usize::MAX),
                Err(LogicalExchangeBudgetError::ArithmeticOverflow {
                    resource: LogicalExchangeBudgetResource::StateBytes,
                })
            );
            assert_eq!(
                budget.try_start_round(),
                Err(LogicalExchangeBudgetError::RoundLimitExceeded { limit: 2 })
            );
            assert_eq!(budget.rounds_started(), 2);
            assert_eq!(budget.inputs_in_current_round(), 1);
            assert_eq!(budget.inputs_admitted(), 3);
            assert_eq!(budget.state_bytes_admitted(), 9);
        }

        #[test]
        fn logical_exchange_budget_clones_share_counters_across_threads() {
            let context = McpContext::new(Cx::for_testing(), 1);
            let limits = ProtocolLimits::builder()
                .logical_exchange_max_rounds(2)
                .logical_exchange_max_inputs_per_round(2)
                .logical_exchange_max_inputs(3)
                .logical_exchange_max_state_bytes(9)
                .logical_exchange_max_wall_clock(HARD_LOGICAL_EXCHANGE_MAX_WALL_CLOCK)
                .build()
                .unwrap();
            let budget = LogicalExchangeBudget::new(limits, &context).unwrap();
            budget.try_start_round().unwrap();

            let barrier = Arc::new(Barrier::new(3));
            let first_budget = budget.clone();
            let first_barrier = barrier.clone();
            let first = std::thread::spawn(move || {
                first_barrier.wait();
                first_budget.try_reserve_input(5)
            });
            let second_budget = budget.clone();
            let second_barrier = barrier.clone();
            let second = std::thread::spawn(move || {
                second_barrier.wait();
                second_budget.try_reserve_input(5)
            });

            barrier.wait();
            let first = first.join().expect("first admission worker panicked");
            let second = second.join().expect("second admission worker panicked");

            assert!(matches!(first, Ok(())) ^ matches!(second, Ok(())));
            assert!(matches!(
                first.as_ref().err().or(second.as_ref().err()),
                Some(LogicalExchangeBudgetError::StateByteLimitExceeded { limit: 9 })
            ));
            assert_eq!(budget.inputs_admitted(), 1);
            assert_eq!(budget.state_bytes_admitted(), 5);
        }

        #[test]
        fn logical_exchange_budget_equality_handles_self_and_shared_clones() {
            let context = McpContext::new(Cx::for_testing(), 1);
            let budget = LogicalExchangeBudget::new(small_limits(), &context).unwrap();
            let clone = budget.clone();

            assert!(Arc::ptr_eq(&budget.counters, &clone.counters));
            assert_eq!(budget, budget);
            assert_eq!(budget, clone);

            budget.try_start_round().unwrap();
            budget.try_reserve_input(3).unwrap();
            assert_eq!(budget, clone);
        }

        #[test]
        fn logical_exchange_budget_equality_is_safe_across_threads_for_distinct_states() {
            let context = McpContext::new(Cx::for_testing(), 1);
            // Equality includes the deadline, and the testing clock advances
            // between constructions; pin one external deadline below the
            // configured window so both budgets agree and the comparison
            // reaches the ordered counter locking under test.
            let shared_deadline = Some(Time::from_nanos(1_000_000));
            let first_budget = LogicalExchangeBudget::with_external_deadline(
                small_limits(),
                &context,
                shared_deadline,
            )
            .unwrap();
            let second_budget = LogicalExchangeBudget::with_external_deadline(
                small_limits(),
                &context,
                shared_deadline,
            )
            .unwrap();
            assert!(!Arc::ptr_eq(
                &first_budget.counters,
                &second_budget.counters
            ));

            let barrier = Arc::new(Barrier::new(3));
            let first_other = second_budget.clone();
            let second_other = first_budget.clone();
            let first_barrier = barrier.clone();
            let first = std::thread::spawn(move || {
                first_barrier.wait();
                first_budget == first_other
            });
            let second_barrier = barrier.clone();
            let second = std::thread::spawn(move || {
                second_barrier.wait();
                second_budget == second_other
            });

            barrier.wait();
            assert!(first.join().expect("first equality worker panicked"));
            assert!(second.join().expect("second equality worker panicked"));
        }

        #[test]
        fn logical_exchange_budget_rejects_caller_context_cancellation() {
            let request_cancellation = McpRequestCancellation::new();
            let context = McpContext::new(Cx::for_testing(), 1)
                .with_request_cancellation(request_cancellation.clone());
            let budget = LogicalExchangeBudget::new(small_limits(), &context).unwrap();

            assert!(request_cancellation.cancel());
            assert_eq!(
                budget.try_start_round(),
                Err(LogicalExchangeBudgetError::Cancelled)
            );
            assert_eq!(budget.rounds_started(), 0);

            let cx = Cx::for_testing();
            let context = McpContext::new(cx.clone(), 2);
            let budget = LogicalExchangeBudget::new(small_limits(), &context).unwrap();
            cx.set_cancel_requested(true);
            assert_eq!(
                budget.try_start_round(),
                Err(LogicalExchangeBudgetError::Cancelled)
            );
            assert_eq!(budget.rounds_started(), 0);
        }

        #[test]
        fn logical_exchange_budget_rechecks_cancellation_after_counter_lock_contention() {
            let request_cancellation = McpRequestCancellation::new();
            let context = McpContext::new(Cx::for_testing(), 1)
                .with_request_cancellation(request_cancellation.clone());
            let budget = LogicalExchangeBudget::new(small_limits(), &context).unwrap();

            let held_counters = budget.counters();
            let before_counter_lock = Arc::new(Barrier::new(2));
            let delayed_clone = budget
                .clone()
                .with_before_counter_lock_barrier(before_counter_lock.clone());
            let worker = std::thread::spawn(move || delayed_clone.try_start_round());

            // The worker is poised immediately before acquiring the shared
            // counter lock. A pre-lock liveness check has therefore either
            // already happened (the former TOCTOU ordering) or is still ahead
            // of the lock (the fixed ordering).
            before_counter_lock.wait();
            assert!(request_cancellation.cancel());
            drop(held_counters);

            assert_eq!(
                worker.join().expect("delayed admission worker panicked"),
                Err(LogicalExchangeBudgetError::Cancelled)
            );
            assert_eq!(budget.rounds_started(), 0);
        }

        #[test]
        fn logical_exchange_budget_uses_context_time_without_a_caller_supplied_instant() {
            let context = McpContext::new(Cx::for_testing(), 1);
            let budget = LogicalExchangeBudget::with_external_deadline(
                small_limits(),
                &context,
                Some(Time::ZERO),
            )
            .unwrap();
            assert_eq!(budget.deadline(), Time::ZERO);
            assert_eq!(
                budget.try_start_round(),
                Err(LogicalExchangeBudgetError::DeadlineExceeded)
            );
            assert_eq!(budget.rounds_started(), 0);
        }

        #[test]
        fn logical_exchange_budget_meets_the_caller_context_deadline() {
            let cx = Cx::for_testing();
            let context_deadline = cx.now().saturating_add_nanos(1_000_000_000_000);
            let context = McpContext::new(cx, 1)
                .with_budget_ceiling(Budget::new().with_deadline(context_deadline));
            let limits = ProtocolLimits::builder()
                .logical_exchange_max_wall_clock(HARD_LOGICAL_EXCHANGE_MAX_WALL_CLOCK)
                .build()
                .unwrap();

            let budget = LogicalExchangeBudget::new(limits, &context).unwrap();

            assert_eq!(budget.deadline(), context_deadline);
        }

        #[test]
        fn logical_exchange_budget_preserves_checked_deadline_arithmetic() {
            assert_eq!(
                LogicalExchangeBudget::calculate_deadline(&small_limits(), Time::MAX, None),
                Err(LogicalExchangeBudgetError::ArithmeticOverflow {
                    resource: LogicalExchangeBudgetResource::DeadlineNanos,
                })
            );
        }
    }
}

pub use auth::{AccessToken, AuthContext, MAX_ACCESS_SCHEME_BYTES, MAX_ACCESS_TOKEN_BYTES};
pub use context::{
    CancelledError, ClientCapabilityInfo, ElicitationAction, ElicitationMode, ElicitationRequest,
    ElicitationResponse, ElicitationSender, IntoOutcome, MAX_RESOURCE_READ_DEPTH,
    MAX_TOOL_CALL_DEPTH, McpContext, McpContextLeaseGuard, McpRequestCancellation,
    NoOpElicitationSender, NoOpNotificationSender, NoOpSamplingSender, NotificationSender,
    ProgressReporter, ResourceContentItem, ResourceReadResult, ResourceReader, SamplingRequest,
    SamplingRequestMessage, SamplingResponse, SamplingRole, SamplingSender, SamplingStopReason,
    ServerCapabilityInfo, ToolCallResult, ToolCaller, ToolContentItem,
};
pub use crypto::{
    CryptoInputTooLongError, EPHEMERAL_KEY_MATERIAL_BYTES, EphemeralKeyMaterial,
    HMAC_SHA256_KEY_BYTES, HMAC_SHA256_TAG_BYTES, HmacSha256Key, HmacSha256Tag,
    HmacVerificationError, NONCE_DOMAIN_MATERIAL_BYTES, NonceDomainMaterial, RandomDrawError,
    SECURITY_IDENTIFIER_BYTES, SHA256_DIGEST_BYTES, SecurityIdentifier, Sha256Digest,
    WEBSOCKET_MASK_BYTES, WebSocketMask, draw_ephemeral_key_material, draw_hmac_sha256_key,
    draw_nonce_domain_material, draw_security_identifier, draw_websocket_mask, sha256_bounded,
};
pub use duration::{ParseDurationError, parse_duration};
pub use error::{
    McpError, McpErrorCode, McpOutcome, McpResult, OutcomeExt, ResultExt, cancelled, err, ok,
};
pub use limits::{
    DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS, DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS_PER_ROUND,
    DEFAULT_LOGICAL_EXCHANGE_MAX_ROUNDS, DEFAULT_LOGICAL_EXCHANGE_MAX_STATE_BYTES,
    DEFAULT_LOGICAL_EXCHANGE_MAX_WALL_CLOCK, HARD_LOGICAL_EXCHANGE_MAX_INPUTS,
    HARD_LOGICAL_EXCHANGE_MAX_INPUTS_PER_ROUND, HARD_LOGICAL_EXCHANGE_MAX_ROUNDS,
    HARD_LOGICAL_EXCHANGE_MAX_STATE_BYTES, HARD_LOGICAL_EXCHANGE_MAX_WALL_CLOCK,
    LogicalExchangeBudget, LogicalExchangeBudgetError, LogicalExchangeBudgetResource,
    ProtocolLimit, ProtocolLimits, ProtocolLimitsBuilder, ProtocolLimitsError,
};
pub use runtime::block_on;
pub use state::{DISABLED_PROMPTS_KEY, DISABLED_RESOURCES_KEY, DISABLED_TOOLS_KEY, SessionState};
pub use uri::{
    ABSOLUTE_URI_HARD_MAX_BYTES, AbsoluteUri, AbsoluteUriComponent, AbsoluteUriError,
    AbsoluteUriScheme, AuthorityErrorKind, CANONICAL_HTTP_URL_POLICY, CANONICAL_URL_HARD_MAX_BYTES,
    CanonicalHttpUrl, CanonicalHttpUrlError, CanonicalResourceId, CanonicalResourceIdError,
    CanonicalResourceIdPolicy, CanonicalUrlPolicy, DEFAULT_ABSOLUTE_URI_MAX_BYTES,
    DEFAULT_CANONICAL_URL_MAX_BYTES, DefaultPortPolicy, DotSegmentPolicy, FragmentPolicy,
    IdnaPolicy, PercentEncodingPolicy, QueryPolicy, ResourceEndpointPathPolicy,
    SchemeHostCasePolicy, SyntaxViolationPolicy, TrailingSlashPolicy, UriComponentState,
    UserinfoPolicy,
};

// Re-export key asupersync types for convenience
pub use asupersync::{Budget, Cx, LabConfig, LabRuntime, Outcome, RegionId, Scope, TaskId};
