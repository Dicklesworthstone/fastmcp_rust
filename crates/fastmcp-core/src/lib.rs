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
    use std::time::Duration;

    use asupersync::Time;

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
    pub const DEFAULT_LOGICAL_EXCHANGE_MAX_WALL_CLOCK: Duration = Duration::from_secs(15 * 60);
    /// Hard absolute wall-clock allowance for one logical exchange.
    pub const HARD_LOGICAL_EXCHANGE_MAX_WALL_CLOCK: Duration = Duration::from_secs(60 * 60);

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
        logical_exchange_max_rounds: u16,
        logical_exchange_max_inputs_per_round: u16,
        logical_exchange_max_inputs: u16,
        logical_exchange_max_state_bytes: usize,
        logical_exchange_max_wall_clock: Duration,
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
            self.logical_exchange_max_rounds
        }

        /// Returns the logical-exchange per-round input limit.
        #[must_use]
        pub const fn logical_exchange_max_inputs_per_round(&self) -> u16 {
            self.logical_exchange_max_inputs_per_round
        }

        /// Returns the cumulative logical-exchange input limit.
        #[must_use]
        pub const fn logical_exchange_max_inputs(&self) -> u16 {
            self.logical_exchange_max_inputs
        }

        /// Returns the cumulative encoded-state-byte limit for one exchange.
        #[must_use]
        pub const fn logical_exchange_max_state_bytes(&self) -> usize {
            self.logical_exchange_max_state_bytes
        }

        /// Returns the absolute wall-clock allowance for one exchange.
        #[must_use]
        pub const fn logical_exchange_max_wall_clock(&self) -> Duration {
            self.logical_exchange_max_wall_clock
        }
    }

    impl Default for ProtocolLimits {
        fn default() -> Self {
            Self {
                logical_exchange_max_rounds: DEFAULT_LOGICAL_EXCHANGE_MAX_ROUNDS,
                logical_exchange_max_inputs_per_round:
                    DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS_PER_ROUND,
                logical_exchange_max_inputs: DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS,
                logical_exchange_max_state_bytes: DEFAULT_LOGICAL_EXCHANGE_MAX_STATE_BYTES,
                logical_exchange_max_wall_clock: DEFAULT_LOGICAL_EXCHANGE_MAX_WALL_CLOCK,
            }
        }
    }

    /// Builder for an immutable [`ProtocolLimits`] snapshot.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ProtocolLimitsBuilder {
        logical_exchange_max_rounds: u16,
        logical_exchange_max_inputs_per_round: u16,
        logical_exchange_max_inputs: u16,
        logical_exchange_max_state_bytes: usize,
        logical_exchange_max_wall_clock: Duration,
    }

    impl Default for ProtocolLimitsBuilder {
        fn default() -> Self {
            Self {
                logical_exchange_max_rounds: DEFAULT_LOGICAL_EXCHANGE_MAX_ROUNDS,
                logical_exchange_max_inputs_per_round:
                    DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS_PER_ROUND,
                logical_exchange_max_inputs: DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS,
                logical_exchange_max_state_bytes: DEFAULT_LOGICAL_EXCHANGE_MAX_STATE_BYTES,
                logical_exchange_max_wall_clock: DEFAULT_LOGICAL_EXCHANGE_MAX_WALL_CLOCK,
            }
        }
    }

    impl ProtocolLimitsBuilder {
        /// Sets the cumulative logical-exchange round limit.
        #[must_use]
        pub const fn logical_exchange_max_rounds(mut self, value: u16) -> Self {
            self.logical_exchange_max_rounds = value;
            self
        }

        /// Sets the logical-exchange per-round input limit.
        #[must_use]
        pub const fn logical_exchange_max_inputs_per_round(mut self, value: u16) -> Self {
            self.logical_exchange_max_inputs_per_round = value;
            self
        }

        /// Sets the cumulative logical-exchange input limit.
        #[must_use]
        pub const fn logical_exchange_max_inputs(mut self, value: u16) -> Self {
            self.logical_exchange_max_inputs = value;
            self
        }

        /// Sets the cumulative encoded-state-byte limit for one exchange.
        #[must_use]
        pub const fn logical_exchange_max_state_bytes(mut self, value: usize) -> Self {
            self.logical_exchange_max_state_bytes = value;
            self
        }

        /// Sets the absolute wall-clock allowance for one exchange.
        #[must_use]
        pub const fn logical_exchange_max_wall_clock(mut self, value: Duration) -> Self {
            self.logical_exchange_max_wall_clock = value;
            self
        }

        /// Validates and creates an immutable limit snapshot.
        pub fn build(self) -> Result<ProtocolLimits, ProtocolLimitsError> {
            validate_positive_u16(
                self.logical_exchange_max_rounds,
                ProtocolLimit::LogicalExchangeRounds,
            )?;
            validate_u16_ceiling(
                self.logical_exchange_max_rounds,
                HARD_LOGICAL_EXCHANGE_MAX_ROUNDS,
                ProtocolLimit::LogicalExchangeRounds,
            )?;
            validate_positive_u16(
                self.logical_exchange_max_inputs_per_round,
                ProtocolLimit::LogicalExchangeInputsPerRound,
            )?;
            validate_u16_ceiling(
                self.logical_exchange_max_inputs_per_round,
                HARD_LOGICAL_EXCHANGE_MAX_INPUTS_PER_ROUND,
                ProtocolLimit::LogicalExchangeInputsPerRound,
            )?;
            validate_positive_u16(
                self.logical_exchange_max_inputs,
                ProtocolLimit::LogicalExchangeInputs,
            )?;
            validate_u16_ceiling(
                self.logical_exchange_max_inputs,
                HARD_LOGICAL_EXCHANGE_MAX_INPUTS,
                ProtocolLimit::LogicalExchangeInputs,
            )?;
            if self.logical_exchange_max_inputs_per_round > self.logical_exchange_max_inputs {
                return Err(ProtocolLimitsError::InputsPerRoundExceedExchangeTotal {
                    per_round: self.logical_exchange_max_inputs_per_round,
                    total: self.logical_exchange_max_inputs,
                });
            }
            if self.logical_exchange_max_state_bytes == 0 {
                return Err(ProtocolLimitsError::Zero {
                    limit: ProtocolLimit::LogicalExchangeStateBytes,
                });
            }
            if self.logical_exchange_max_state_bytes > HARD_LOGICAL_EXCHANGE_MAX_STATE_BYTES {
                return Err(ProtocolLimitsError::ExceedsHardCeiling {
                    limit: ProtocolLimit::LogicalExchangeStateBytes,
                });
            }
            if self.logical_exchange_max_wall_clock.is_zero() {
                return Err(ProtocolLimitsError::Zero {
                    limit: ProtocolLimit::LogicalExchangeWallClock,
                });
            }
            if self.logical_exchange_max_wall_clock > HARD_LOGICAL_EXCHANGE_MAX_WALL_CLOCK {
                return Err(ProtocolLimitsError::ExceedsHardCeiling {
                    limit: ProtocolLimit::LogicalExchangeWallClock,
                });
            }

            Ok(ProtocolLimits {
                logical_exchange_max_rounds: self.logical_exchange_max_rounds,
                logical_exchange_max_inputs_per_round: self.logical_exchange_max_inputs_per_round,
                logical_exchange_max_inputs: self.logical_exchange_max_inputs,
                logical_exchange_max_state_bytes: self.logical_exchange_max_state_bytes,
                logical_exchange_max_wall_clock: self.logical_exchange_max_wall_clock,
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

    /// Cumulative, checked admission accounting for one logical exchange.
    ///
    /// The budget owns one immutable [`ProtocolLimits`] snapshot and an
    /// absolute deadline. Every failed operation leaves its counters unchanged;
    /// callers can therefore reserve an input and its prospective state bytes
    /// atomically before performing the associated work.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct LogicalExchangeBudget {
        limits: ProtocolLimits,
        deadline: Time,
        rounds_started: u16,
        inputs_in_current_round: u16,
        inputs_admitted: u16,
        state_bytes_admitted: usize,
    }

    impl LogicalExchangeBudget {
        /// Captures `limits` and calculates its absolute deadline from `started_at`.
        pub fn new(
            limits: ProtocolLimits,
            started_at: Time,
        ) -> Result<Self, LogicalExchangeBudgetError> {
            Self::with_external_deadline(limits, started_at, None)
        }

        /// Captures `limits` and meets its deadline with an existing outer deadline.
        ///
        /// The earlier of the configured logical-exchange deadline and
        /// `external_deadline` is retained. The deadline can never be extended
        /// after construction.
        pub fn with_external_deadline(
            limits: ProtocolLimits,
            started_at: Time,
            external_deadline: Option<Time>,
        ) -> Result<Self, LogicalExchangeBudgetError> {
            let duration_nanos = u64::try_from(limits.logical_exchange_max_wall_clock.as_nanos())
                .map_err(|_| LogicalExchangeBudgetError::ArithmeticOverflow {
                resource: LogicalExchangeBudgetResource::WallClockNanos,
            })?;
            let deadline_nanos = started_at.as_nanos().checked_add(duration_nanos).ok_or(
                LogicalExchangeBudgetError::ArithmeticOverflow {
                    resource: LogicalExchangeBudgetResource::DeadlineNanos,
                },
            )?;
            let configured_deadline = Time::from_nanos(deadline_nanos);
            let deadline = external_deadline
                .map_or(configured_deadline, |outer| outer.min(configured_deadline));

            Ok(Self {
                limits,
                deadline,
                rounds_started: 0,
                inputs_in_current_round: 0,
                inputs_admitted: 0,
                state_bytes_admitted: 0,
            })
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
        pub const fn rounds_started(&self) -> u16 {
            self.rounds_started
        }

        /// Returns the number of inputs admitted in the active round.
        #[must_use]
        pub const fn inputs_in_current_round(&self) -> u16 {
            self.inputs_in_current_round
        }

        /// Returns the total inputs admitted by the exchange.
        #[must_use]
        pub const fn inputs_admitted(&self) -> u16 {
            self.inputs_admitted
        }

        /// Returns the total encoded state bytes admitted by the exchange.
        #[must_use]
        pub const fn state_bytes_admitted(&self) -> usize {
            self.state_bytes_admitted
        }

        /// Fails once the immutable absolute deadline has been reached.
        pub fn check_deadline(&self, now: Time) -> Result<(), LogicalExchangeBudgetError> {
            if now >= self.deadline {
                Err(LogicalExchangeBudgetError::DeadlineExceeded)
            } else {
                Ok(())
            }
        }

        /// Starts one round after checking the exchange deadline and round limit.
        pub fn try_start_round(&mut self, now: Time) -> Result<(), LogicalExchangeBudgetError> {
            self.check_deadline(now)?;
            let next_rounds = self.rounds_started.checked_add(1).ok_or(
                LogicalExchangeBudgetError::ArithmeticOverflow {
                    resource: LogicalExchangeBudgetResource::Rounds,
                },
            )?;
            if next_rounds > self.limits.logical_exchange_max_rounds {
                return Err(LogicalExchangeBudgetError::RoundLimitExceeded {
                    limit: self.limits.logical_exchange_max_rounds,
                });
            }

            self.rounds_started = next_rounds;
            self.inputs_in_current_round = 0;
            Ok(())
        }

        /// Atomically reserves one input and its prospective encoded state bytes.
        pub fn try_reserve_input(
            &mut self,
            now: Time,
            state_bytes: usize,
        ) -> Result<(), LogicalExchangeBudgetError> {
            self.check_deadline(now)?;
            if self.rounds_started == 0 {
                return Err(LogicalExchangeBudgetError::InputOutsideRound);
            }

            let next_round_inputs = self.inputs_in_current_round.checked_add(1).ok_or(
                LogicalExchangeBudgetError::ArithmeticOverflow {
                    resource: LogicalExchangeBudgetResource::InputsInRound,
                },
            )?;
            if next_round_inputs > self.limits.logical_exchange_max_inputs_per_round {
                return Err(LogicalExchangeBudgetError::InputsPerRoundLimitExceeded {
                    limit: self.limits.logical_exchange_max_inputs_per_round,
                });
            }
            let next_total_inputs = self.inputs_admitted.checked_add(1).ok_or(
                LogicalExchangeBudgetError::ArithmeticOverflow {
                    resource: LogicalExchangeBudgetResource::TotalInputs,
                },
            )?;
            if next_total_inputs > self.limits.logical_exchange_max_inputs {
                return Err(LogicalExchangeBudgetError::InputsLimitExceeded {
                    limit: self.limits.logical_exchange_max_inputs,
                });
            }
            let next_state_bytes = self.state_bytes_admitted.checked_add(state_bytes).ok_or(
                LogicalExchangeBudgetError::ArithmeticOverflow {
                    resource: LogicalExchangeBudgetResource::StateBytes,
                },
            )?;
            if next_state_bytes > self.limits.logical_exchange_max_state_bytes {
                return Err(LogicalExchangeBudgetError::StateByteLimitExceeded {
                    limit: self.limits.logical_exchange_max_state_bytes,
                });
            }

            self.inputs_in_current_round = next_round_inputs;
            self.inputs_admitted = next_total_inputs;
            self.state_bytes_admitted = next_state_bytes;
            Ok(())
        }

        /// Atomically reserves encoded state bytes not associated with a new input.
        pub fn try_reserve_state_bytes(
            &mut self,
            now: Time,
            state_bytes: usize,
        ) -> Result<(), LogicalExchangeBudgetError> {
            self.check_deadline(now)?;
            let next_state_bytes = self.state_bytes_admitted.checked_add(state_bytes).ok_or(
                LogicalExchangeBudgetError::ArithmeticOverflow {
                    resource: LogicalExchangeBudgetResource::StateBytes,
                },
            )?;
            if next_state_bytes > self.limits.logical_exchange_max_state_bytes {
                return Err(LogicalExchangeBudgetError::StateByteLimitExceeded {
                    limit: self.limits.logical_exchange_max_state_bytes,
                });
            }

            self.state_bytes_admitted = next_state_bytes;
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

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
        fn logical_exchange_budget_cumulatively_charges_valid_rounds_inputs_and_bytes() {
            let start = Time::from_secs(100);
            let mut budget = LogicalExchangeBudget::new(small_limits(), start).unwrap();

            budget.try_start_round(start).unwrap();
            budget.try_reserve_input(start, 3).unwrap();
            budget.try_reserve_input(start, 4).unwrap();
            budget.try_start_round(Time::from_secs(101)).unwrap();
            budget.try_reserve_input(Time::from_secs(101), 2).unwrap();

            assert_eq!(budget.rounds_started(), 2);
            assert_eq!(budget.inputs_in_current_round(), 1);
            assert_eq!(budget.inputs_admitted(), 3);
            assert_eq!(budget.state_bytes_admitted(), 9);
            assert_eq!(budget.deadline(), Time::from_secs(105));
            assert_eq!(
                budget.check_deadline(Time::from_secs(105)),
                Err(LogicalExchangeBudgetError::DeadlineExceeded)
            );
        }

        #[test]
        fn logical_exchange_budget_rejects_overages_without_mutating_accounting() {
            let start = Time::from_secs(100);
            let mut budget = LogicalExchangeBudget::new(small_limits(), start).unwrap();

            assert_eq!(
                budget.try_reserve_input(start, 1),
                Err(LogicalExchangeBudgetError::InputOutsideRound)
            );
            budget.try_start_round(start).unwrap();
            budget.try_reserve_input(start, 3).unwrap();
            budget.try_reserve_input(start, 4).unwrap();
            let after_first_round = budget.clone();
            assert_eq!(
                budget.try_reserve_input(start, 1),
                Err(LogicalExchangeBudgetError::InputsPerRoundLimitExceeded { limit: 2 })
            );
            assert_eq!(budget, after_first_round);

            budget.try_start_round(Time::from_secs(101)).unwrap();
            budget.try_reserve_input(Time::from_secs(101), 2).unwrap();
            let after_total_inputs = budget.clone();
            assert_eq!(
                budget.try_reserve_input(Time::from_secs(101), 0),
                Err(LogicalExchangeBudgetError::InputsLimitExceeded { limit: 3 })
            );
            assert_eq!(budget, after_total_inputs);
            assert_eq!(
                budget.try_reserve_state_bytes(Time::from_secs(101), 1),
                Err(LogicalExchangeBudgetError::StateByteLimitExceeded { limit: 9 })
            );
            assert_eq!(budget, after_total_inputs);
            assert_eq!(
                budget.try_start_round(Time::from_secs(101)),
                Err(LogicalExchangeBudgetError::RoundLimitExceeded { limit: 2 })
            );
            assert_eq!(budget, after_total_inputs);
            assert_eq!(
                budget.try_reserve_state_bytes(Time::from_secs(105), 0),
                Err(LogicalExchangeBudgetError::DeadlineExceeded)
            );
            assert_eq!(budget, after_total_inputs);
        }

        #[test]
        fn logical_exchange_budget_meets_an_outer_deadline_and_rejects_deadline_overflow() {
            let limits = small_limits();
            let budget = LogicalExchangeBudget::with_external_deadline(
                limits,
                Time::from_secs(100),
                Some(Time::from_secs(102)),
            )
            .unwrap();
            assert_eq!(budget.deadline(), Time::from_secs(102));
            assert_eq!(
                LogicalExchangeBudget::new(small_limits(), Time::MAX),
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
