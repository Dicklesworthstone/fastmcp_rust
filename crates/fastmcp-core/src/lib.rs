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
/// AUTH-00 B security-partition admission and non-oracular lookup.
pub mod partition;
pub mod runtime;
mod state;
pub mod uri;

/// Immutable protocol-limit snapshots and cumulative logical-exchange admission.
pub mod limits {
    use std::collections::HashMap;
    use std::fmt;
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::{Duration, Instant};

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

    /// Default JSON-RPC message body (request, notification, or response).
    pub const DEFAULT_JSON_RPC_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
    /// Hard JSON-RPC message body ceiling.
    pub const HARD_JSON_RPC_MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
    /// Default metadata entry count.
    pub const DEFAULT_METADATA_MAX_ENTRIES: u16 = 256;
    /// Hard metadata entry ceiling.
    pub const HARD_METADATA_MAX_ENTRIES: u16 = 1_024;
    /// Default encoded metadata bytes.
    pub const DEFAULT_METADATA_MAX_BYTES: usize = 256 * 1024;
    /// Hard encoded metadata-byte ceiling.
    pub const HARD_METADATA_MAX_BYTES: usize = 1024 * 1024;
    /// Default `AbsoluteUri` encoded UTF-8 bytes.
    pub const DEFAULT_URI_MAX_BYTES: usize = 16 * 1024;
    /// Hard `AbsoluteUri` encoded-byte ceiling.
    pub const HARD_URI_MAX_BYTES: usize = 64 * 1024;
    /// Default cancellation-notification reason UTF-8 bytes.
    pub const DEFAULT_CANCELLATION_REASON_MAX_BYTES: usize = 4 * 1024;
    /// Hard cancellation-reason-byte ceiling.
    pub const HARD_CANCELLATION_REASON_MAX_BYTES: usize = 64 * 1024;
    /// Default core catalog cursor encoded bytes.
    pub const DEFAULT_CURSOR_MAX_BYTES: usize = 4 * 1024;
    /// Hard catalog-cursor-byte ceiling.
    pub const HARD_CURSOR_MAX_BYTES: usize = 64 * 1024;

    /// Snapshot generation assigned to every newly admitted [`ProtocolLimits`].
    pub const PROTOCOL_LIMITS_INITIAL_GENERATION: u64 = 1;

    /// A configurable logical-exchange or catalog limit in [`ProtocolLimits`].
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
        /// JSON-RPC message body bytes.
        JsonRpcBodyBytes,
        /// Metadata entry count.
        MetadataEntries,
        /// Encoded metadata bytes.
        MetadataBytes,
        /// Absolute URI encoded UTF-8 bytes.
        UriBytes,
        /// Cancellation-notification reason UTF-8 bytes.
        CancellationReasonBytes,
        /// Core catalog cursor encoded bytes.
        CursorBytes,
    }

    impl fmt::Display for ProtocolLimit {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            let name = match self {
                Self::LogicalExchangeRounds => "logical-exchange rounds",
                Self::LogicalExchangeInputsPerRound => "logical-exchange inputs per round",
                Self::LogicalExchangeInputs => "logical-exchange inputs",
                Self::LogicalExchangeStateBytes => "logical-exchange state bytes",
                Self::LogicalExchangeWallClock => "logical-exchange wall-clock allowance",
                Self::JsonRpcBodyBytes => "JSON-RPC message body bytes",
                Self::MetadataEntries => "metadata entries",
                Self::MetadataBytes => "encoded metadata bytes",
                Self::UriBytes => "absolute URI encoded bytes",
                Self::CancellationReasonBytes => "cancellation-reason UTF-8 bytes",
                Self::CursorBytes => "catalog cursor encoded bytes",
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
        /// Charging `additional` units would exceed the configured row.
        ChargeExceedsLimit {
            /// The bound that refused the charge.
            limit: ProtocolLimit,
            /// The saturating next counter that was not admitted.
            requested: usize,
            /// The configured ceiling for this snapshot.
            ceiling: usize,
        },
        /// Adding the requested units overflowed `usize`.
        ChargeOverflow {
            /// The bound whose counter would have wrapped.
            limit: ProtocolLimit,
        },
        /// The selected row is a `Duration`, not a usize charge counter.
        NotCountable {
            /// The duration-valued catalog row.
            limit: ProtocolLimit,
        },
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
                Self::ChargeExceedsLimit {
                    limit,
                    requested,
                    ceiling,
                } => write!(
                    formatter,
                    "{limit} charge {requested} exceeds the configured ceiling {ceiling}"
                ),
                Self::ChargeOverflow { limit } => {
                    write!(formatter, "{limit} charge overflowed the counter width")
                }
                Self::NotCountable { limit } => write!(
                    formatter,
                    "{limit} is a duration row and cannot be projected into usize"
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
        generation: u64,
        rounds: u16,
        inputs_per_round: u16,
        inputs: u16,
        state_bytes: usize,
        wall_clock: Duration,
        json_rpc_body_bytes: usize,
        metadata_entries: u16,
        metadata_bytes: usize,
        uri_bytes: usize,
        cancellation_reason_bytes: usize,
        cursor_bytes: usize,
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
            self.rounds
        }

        /// Returns the logical-exchange per-round input limit.
        #[must_use]
        pub const fn logical_exchange_max_inputs_per_round(&self) -> u16 {
            self.inputs_per_round
        }

        /// Returns the cumulative logical-exchange input limit.
        #[must_use]
        pub const fn logical_exchange_max_inputs(&self) -> u16 {
            self.inputs
        }

        /// Returns the cumulative encoded-state-byte limit for one exchange.
        #[must_use]
        pub const fn logical_exchange_max_state_bytes(&self) -> usize {
            self.state_bytes
        }

        /// Returns the absolute wall-clock allowance for one exchange.
        #[must_use]
        pub const fn logical_exchange_max_wall_clock(&self) -> Duration {
            self.wall_clock
        }

        /// Returns the JSON-RPC message-body byte limit.
        #[must_use]
        pub const fn json_rpc_max_body_bytes(&self) -> usize {
            self.json_rpc_body_bytes
        }

        /// Returns the metadata entry-count limit.
        #[must_use]
        pub const fn metadata_max_entries(&self) -> u16 {
            self.metadata_entries
        }

        /// Returns the encoded metadata-byte limit.
        #[must_use]
        pub const fn metadata_max_bytes(&self) -> usize {
            self.metadata_bytes
        }

        /// Returns the AbsoluteUri encoded-byte limit.
        #[must_use]
        pub const fn uri_max_bytes(&self) -> usize {
            self.uri_bytes
        }

        /// Returns the cancellation-reason UTF-8 byte limit.
        #[must_use]
        pub const fn cancellation_reason_max_bytes(&self) -> usize {
            self.cancellation_reason_bytes
        }

        /// Returns the catalog-cursor encoded-byte limit.
        #[must_use]
        pub const fn cursor_max_bytes(&self) -> usize {
            self.cursor_bytes
        }

        /// Returns the immutable snapshot generation captured at admission.
        #[must_use]
        pub const fn generation(&self) -> u64 {
            self.generation
        }

        /// Constructs an immutable catalog from the six AC-LIMIT-A-01 rows.
        ///
        /// Logical-exchange fields keep their documented defaults. Each row is
        /// accepted only inside its hard ceiling; a successful snapshot cannot
        /// later be mutated by another configuration attempt.
        pub fn try_new(
            json_rpc_body_bytes: usize,
            metadata_entries: u16,
            metadata_bytes: usize,
            uri_bytes: usize,
            cancellation_reason_bytes: usize,
            cursor_bytes: usize,
        ) -> Result<Self, ProtocolLimitsError> {
            Self::builder()
                .json_rpc_max_body_bytes(json_rpc_body_bytes)
                .metadata_max_entries(metadata_entries)
                .metadata_max_bytes(metadata_bytes)
                .uri_max_bytes(uri_bytes)
                .cancellation_reason_max_bytes(cancellation_reason_bytes)
                .cursor_max_bytes(cursor_bytes)
                .build()
        }

        /// Re-validates this snapshot against the same hard ceilings.
        pub fn validate(&self) -> Result<(), ProtocolLimitsError> {
            Self::builder()
                .logical_exchange_max_rounds(self.rounds)
                .logical_exchange_max_inputs_per_round(self.inputs_per_round)
                .logical_exchange_max_inputs(self.inputs)
                .logical_exchange_max_state_bytes(self.state_bytes)
                .logical_exchange_max_wall_clock(self.wall_clock)
                .json_rpc_max_body_bytes(self.json_rpc_body_bytes)
                .metadata_max_entries(self.metadata_entries)
                .metadata_max_bytes(self.metadata_bytes)
                .uri_max_bytes(self.uri_bytes)
                .cancellation_reason_max_bytes(self.cancellation_reason_bytes)
                .cursor_max_bytes(self.cursor_bytes)
                .build()
                .map(|_| ())
        }

        /// Returns a clone that remains byte-identical after later builders run.
        #[must_use]
        pub fn snapshot(&self) -> Self {
            self.clone()
        }

        /// Documented hard ceiling for one countable catalog row.
        ///
        /// Wall-clock rows stay on [`Duration`] and are not narrowed through
        /// `as_nanos() as usize`.
        pub const fn hard_ceiling(limit: ProtocolLimit) -> Result<usize, ProtocolLimitsError> {
            match limit {
                ProtocolLimit::LogicalExchangeRounds => {
                    Ok(HARD_LOGICAL_EXCHANGE_MAX_ROUNDS as usize)
                }
                ProtocolLimit::LogicalExchangeInputsPerRound => {
                    Ok(HARD_LOGICAL_EXCHANGE_MAX_INPUTS_PER_ROUND as usize)
                }
                ProtocolLimit::LogicalExchangeInputs => {
                    Ok(HARD_LOGICAL_EXCHANGE_MAX_INPUTS as usize)
                }
                ProtocolLimit::LogicalExchangeStateBytes => {
                    Ok(HARD_LOGICAL_EXCHANGE_MAX_STATE_BYTES)
                }
                ProtocolLimit::LogicalExchangeWallClock => {
                    Err(ProtocolLimitsError::NotCountable { limit })
                }
                ProtocolLimit::JsonRpcBodyBytes => Ok(HARD_JSON_RPC_MAX_BODY_BYTES),
                ProtocolLimit::MetadataEntries => Ok(HARD_METADATA_MAX_ENTRIES as usize),
                ProtocolLimit::MetadataBytes => Ok(HARD_METADATA_MAX_BYTES),
                ProtocolLimit::UriBytes => Ok(HARD_URI_MAX_BYTES),
                ProtocolLimit::CancellationReasonBytes => Ok(HARD_CANCELLATION_REASON_MAX_BYTES),
                ProtocolLimit::CursorBytes => Ok(HARD_CURSOR_MAX_BYTES),
            }
        }

        /// Configured units for one countable catalog row on this snapshot.
        pub const fn configured_units(
            &self,
            limit: ProtocolLimit,
        ) -> Result<usize, ProtocolLimitsError> {
            match limit {
                ProtocolLimit::LogicalExchangeRounds => Ok(self.rounds as usize),
                ProtocolLimit::LogicalExchangeInputsPerRound => Ok(self.inputs_per_round as usize),
                ProtocolLimit::LogicalExchangeInputs => Ok(self.inputs as usize),
                ProtocolLimit::LogicalExchangeStateBytes => Ok(self.state_bytes),
                ProtocolLimit::LogicalExchangeWallClock => {
                    Err(ProtocolLimitsError::NotCountable { limit })
                }
                ProtocolLimit::JsonRpcBodyBytes => Ok(self.json_rpc_body_bytes),
                ProtocolLimit::MetadataEntries => Ok(self.metadata_entries as usize),
                ProtocolLimit::MetadataBytes => Ok(self.metadata_bytes),
                ProtocolLimit::UriBytes => Ok(self.uri_bytes),
                ProtocolLimit::CancellationReasonBytes => Ok(self.cancellation_reason_bytes),
                ProtocolLimit::CursorBytes => Ok(self.cursor_bytes),
            }
        }

        /// Checked charge against one configured row.
        ///
        /// `N-1` and `N` succeed. `N+1` and `usize` overflow refuse before any
        /// caller-owned counter is expected to change.
        pub fn try_charge(
            &self,
            limit: ProtocolLimit,
            current: usize,
            additional: usize,
        ) -> Result<usize, ProtocolLimitsError> {
            let ceiling = self.configured_units(limit)?;
            let Some(requested) = current.checked_add(additional) else {
                return Err(ProtocolLimitsError::ChargeOverflow { limit });
            };
            if requested > ceiling {
                return Err(ProtocolLimitsError::ChargeExceedsLimit {
                    limit,
                    requested,
                    ceiling,
                });
            }
            Ok(requested)
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
                generation: self.generation.min(other.generation),
                rounds: self.rounds.min(other.rounds),
                inputs_per_round: self.inputs_per_round.min(other.inputs_per_round),
                inputs: self.inputs.min(other.inputs),
                state_bytes: self.state_bytes.min(other.state_bytes),
                wall_clock: self.wall_clock.min(other.wall_clock),
                json_rpc_body_bytes: self.json_rpc_body_bytes.min(other.json_rpc_body_bytes),
                metadata_entries: self.metadata_entries.min(other.metadata_entries),
                metadata_bytes: self.metadata_bytes.min(other.metadata_bytes),
                uri_bytes: self.uri_bytes.min(other.uri_bytes),
                cancellation_reason_bytes: self
                    .cancellation_reason_bytes
                    .min(other.cancellation_reason_bytes),
                cursor_bytes: self.cursor_bytes.min(other.cursor_bytes),
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
                generation: PROTOCOL_LIMITS_INITIAL_GENERATION,
                rounds: DEFAULT_LOGICAL_EXCHANGE_MAX_ROUNDS,
                inputs_per_round: DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS_PER_ROUND,
                inputs: DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS,
                state_bytes: DEFAULT_LOGICAL_EXCHANGE_MAX_STATE_BYTES,
                wall_clock: DEFAULT_LOGICAL_EXCHANGE_MAX_WALL_CLOCK,
                json_rpc_body_bytes: DEFAULT_JSON_RPC_MAX_BODY_BYTES,
                metadata_entries: DEFAULT_METADATA_MAX_ENTRIES,
                metadata_bytes: DEFAULT_METADATA_MAX_BYTES,
                uri_bytes: DEFAULT_URI_MAX_BYTES,
                cancellation_reason_bytes: DEFAULT_CANCELLATION_REASON_MAX_BYTES,
                cursor_bytes: DEFAULT_CURSOR_MAX_BYTES,
            }
        }
    }

    /// Builder for an immutable [`ProtocolLimits`] snapshot.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ProtocolLimitsBuilder {
        rounds: u16,
        inputs_per_round: u16,
        inputs: u16,
        state_bytes: usize,
        wall_clock: Duration,
        json_rpc_body_bytes: usize,
        metadata_entries: u16,
        metadata_bytes: usize,
        uri_bytes: usize,
        cancellation_reason_bytes: usize,
        cursor_bytes: usize,
    }

    impl Default for ProtocolLimitsBuilder {
        fn default() -> Self {
            Self {
                rounds: DEFAULT_LOGICAL_EXCHANGE_MAX_ROUNDS,
                inputs_per_round: DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS_PER_ROUND,
                inputs: DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS,
                state_bytes: DEFAULT_LOGICAL_EXCHANGE_MAX_STATE_BYTES,
                wall_clock: DEFAULT_LOGICAL_EXCHANGE_MAX_WALL_CLOCK,
                json_rpc_body_bytes: DEFAULT_JSON_RPC_MAX_BODY_BYTES,
                metadata_entries: DEFAULT_METADATA_MAX_ENTRIES,
                metadata_bytes: DEFAULT_METADATA_MAX_BYTES,
                uri_bytes: DEFAULT_URI_MAX_BYTES,
                cancellation_reason_bytes: DEFAULT_CANCELLATION_REASON_MAX_BYTES,
                cursor_bytes: DEFAULT_CURSOR_MAX_BYTES,
            }
        }
    }

    impl ProtocolLimitsBuilder {
        /// Sets the cumulative logical-exchange round limit.
        #[must_use]
        pub const fn logical_exchange_max_rounds(mut self, value: u16) -> Self {
            self.rounds = value;
            self
        }

        /// Sets the logical-exchange per-round input limit.
        #[must_use]
        pub const fn logical_exchange_max_inputs_per_round(mut self, value: u16) -> Self {
            self.inputs_per_round = value;
            self
        }

        /// Sets the cumulative logical-exchange input limit.
        #[must_use]
        pub const fn logical_exchange_max_inputs(mut self, value: u16) -> Self {
            self.inputs = value;
            self
        }

        /// Sets the cumulative encoded-state-byte limit for one exchange.
        #[must_use]
        pub const fn logical_exchange_max_state_bytes(mut self, value: usize) -> Self {
            self.state_bytes = value;
            self
        }

        /// Sets the absolute wall-clock allowance for one exchange.
        #[must_use]
        pub const fn logical_exchange_max_wall_clock(mut self, value: Duration) -> Self {
            self.wall_clock = value;
            self
        }

        /// Sets the JSON-RPC message-body byte limit.
        #[must_use]
        pub const fn json_rpc_max_body_bytes(mut self, value: usize) -> Self {
            self.json_rpc_body_bytes = value;
            self
        }

        /// Sets the metadata entry-count limit.
        #[must_use]
        pub const fn metadata_max_entries(mut self, value: u16) -> Self {
            self.metadata_entries = value;
            self
        }

        /// Sets the encoded metadata-byte limit.
        #[must_use]
        pub const fn metadata_max_bytes(mut self, value: usize) -> Self {
            self.metadata_bytes = value;
            self
        }

        /// Sets the AbsoluteUri encoded-byte limit.
        #[must_use]
        pub const fn uri_max_bytes(mut self, value: usize) -> Self {
            self.uri_bytes = value;
            self
        }

        /// Sets the cancellation-reason UTF-8 byte limit.
        #[must_use]
        pub const fn cancellation_reason_max_bytes(mut self, value: usize) -> Self {
            self.cancellation_reason_bytes = value;
            self
        }

        /// Sets the catalog-cursor encoded-byte limit.
        #[must_use]
        pub const fn cursor_max_bytes(mut self, value: usize) -> Self {
            self.cursor_bytes = value;
            self
        }

        /// Validates and creates an immutable limit snapshot.
        pub fn build(self) -> Result<ProtocolLimits, ProtocolLimitsError> {
            validate_positive_u16(self.rounds, ProtocolLimit::LogicalExchangeRounds)?;
            validate_u16_ceiling(
                self.rounds,
                HARD_LOGICAL_EXCHANGE_MAX_ROUNDS,
                ProtocolLimit::LogicalExchangeRounds,
            )?;
            validate_positive_u16(
                self.inputs_per_round,
                ProtocolLimit::LogicalExchangeInputsPerRound,
            )?;
            validate_u16_ceiling(
                self.inputs_per_round,
                HARD_LOGICAL_EXCHANGE_MAX_INPUTS_PER_ROUND,
                ProtocolLimit::LogicalExchangeInputsPerRound,
            )?;
            validate_positive_u16(self.inputs, ProtocolLimit::LogicalExchangeInputs)?;
            validate_u16_ceiling(
                self.inputs,
                HARD_LOGICAL_EXCHANGE_MAX_INPUTS,
                ProtocolLimit::LogicalExchangeInputs,
            )?;
            if self.inputs_per_round > self.inputs {
                return Err(ProtocolLimitsError::InputsPerRoundExceedExchangeTotal {
                    per_round: self.inputs_per_round,
                    total: self.inputs,
                });
            }
            if self.state_bytes == 0 {
                return Err(ProtocolLimitsError::Zero {
                    limit: ProtocolLimit::LogicalExchangeStateBytes,
                });
            }
            if self.state_bytes > HARD_LOGICAL_EXCHANGE_MAX_STATE_BYTES {
                return Err(ProtocolLimitsError::ExceedsHardCeiling {
                    limit: ProtocolLimit::LogicalExchangeStateBytes,
                });
            }
            if self.wall_clock.is_zero() {
                return Err(ProtocolLimitsError::Zero {
                    limit: ProtocolLimit::LogicalExchangeWallClock,
                });
            }
            if self.wall_clock > HARD_LOGICAL_EXCHANGE_MAX_WALL_CLOCK {
                return Err(ProtocolLimitsError::ExceedsHardCeiling {
                    limit: ProtocolLimit::LogicalExchangeWallClock,
                });
            }
            validate_positive_usize(self.json_rpc_body_bytes, ProtocolLimit::JsonRpcBodyBytes)?;
            validate_usize_ceiling(
                self.json_rpc_body_bytes,
                HARD_JSON_RPC_MAX_BODY_BYTES,
                ProtocolLimit::JsonRpcBodyBytes,
            )?;
            validate_positive_u16(self.metadata_entries, ProtocolLimit::MetadataEntries)?;
            validate_u16_ceiling(
                self.metadata_entries,
                HARD_METADATA_MAX_ENTRIES,
                ProtocolLimit::MetadataEntries,
            )?;
            validate_positive_usize(self.metadata_bytes, ProtocolLimit::MetadataBytes)?;
            validate_usize_ceiling(
                self.metadata_bytes,
                HARD_METADATA_MAX_BYTES,
                ProtocolLimit::MetadataBytes,
            )?;
            validate_positive_usize(self.uri_bytes, ProtocolLimit::UriBytes)?;
            validate_usize_ceiling(self.uri_bytes, HARD_URI_MAX_BYTES, ProtocolLimit::UriBytes)?;
            validate_positive_usize(
                self.cancellation_reason_bytes,
                ProtocolLimit::CancellationReasonBytes,
            )?;
            validate_usize_ceiling(
                self.cancellation_reason_bytes,
                HARD_CANCELLATION_REASON_MAX_BYTES,
                ProtocolLimit::CancellationReasonBytes,
            )?;
            validate_positive_usize(self.cursor_bytes, ProtocolLimit::CursorBytes)?;
            validate_usize_ceiling(
                self.cursor_bytes,
                HARD_CURSOR_MAX_BYTES,
                ProtocolLimit::CursorBytes,
            )?;

            Ok(ProtocolLimits {
                generation: PROTOCOL_LIMITS_INITIAL_GENERATION,
                rounds: self.rounds,
                inputs_per_round: self.inputs_per_round,
                inputs: self.inputs,
                state_bytes: self.state_bytes,
                wall_clock: self.wall_clock,
                json_rpc_body_bytes: self.json_rpc_body_bytes,
                metadata_entries: self.metadata_entries,
                metadata_bytes: self.metadata_bytes,
                uri_bytes: self.uri_bytes,
                cancellation_reason_bytes: self.cancellation_reason_bytes,
                cursor_bytes: self.cursor_bytes,
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

    fn validate_positive_usize(
        value: usize,
        limit: ProtocolLimit,
    ) -> Result<(), ProtocolLimitsError> {
        if value == 0 {
            Err(ProtocolLimitsError::Zero { limit })
        } else {
            Ok(())
        }
    }

    fn validate_usize_ceiling(
        value: usize,
        hard_ceiling: usize,
        limit: ProtocolLimit,
    ) -> Result<(), ProtocolLimitsError> {
        if value > hard_ceiling {
            Err(ProtocolLimitsError::ExceedsHardCeiling { limit })
        } else {
            Ok(())
        }
    }

    const OPAQUE_ADMISSION_KEY_HASH_LIMIT: usize = 64 * 1024;
    const MAX_ADMISSION_FIELD_BYTES: usize = 8 * 1024;

    pub(crate) fn require_admission_field(value: &str) -> Result<&[u8], SealedAdmissionKeyError> {
        if value.is_empty() {
            return Err(SealedAdmissionKeyError::EmptyField);
        }
        if value.len() > MAX_ADMISSION_FIELD_BYTES {
            return Err(SealedAdmissionKeyError::FieldTooLong);
        }
        Ok(value.as_bytes())
    }

    pub(crate) fn opaque_admission_digest(parts: &[&[u8]]) -> [u8; 32] {
        let mut encoded = Vec::new();
        for part in parts {
            encoded.extend_from_slice(&(part.len() as u64).to_be_bytes());
            encoded.extend_from_slice(part);
        }
        crate::crypto::sha256_bounded(&encoded, OPAQUE_ADMISSION_KEY_HASH_LIMIT)
            .expect("admission-key material stays inside the hash bound")
            .into_bytes()
    }

    /// Refusal while minting a sealed, non-authorizing admission key.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SealedAdmissionKeyError {
        /// A required configured or transport-observed field was empty.
        EmptyField,
        /// A configured or transport-observed field exceeded the sealed-key bound.
        FieldTooLong,
        /// A request-supplied identifier cannot mint a verified partition key.
        RequestSuppliedIdentifier,
    }

    impl fmt::Display for SealedAdmissionKeyError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::EmptyField => {
                    formatter.write_str("sealed admission key field must be nonempty")
                }
                Self::FieldTooLong => {
                    formatter.write_str("sealed admission key field exceeds the 8 KiB bound")
                }
                Self::RequestSuppliedIdentifier => formatter.write_str(
                    "request-supplied identifiers cannot mint a verified quota partition key",
                ),
            }
        }
    }

    impl std::error::Error for SealedAdmissionKeyError {}

    /// Opaque pre-authentication source bucket.
    ///
    /// Derived only from the listener domain and a transport-observed source.
    /// Request body, query, and credential bytes are not inputs.
    #[derive(Clone, PartialEq, Eq)]
    pub struct PreAuthSourceBucketKey {
        digest: [u8; 32],
    }

    impl fmt::Debug for PreAuthSourceBucketKey {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("PreAuthSourceBucketKey")
                .finish_non_exhaustive()
        }
    }

    impl PreAuthSourceBucketKey {
        /// Builds a pre-auth key from listener domain plus transport-observed source.
        pub fn from_listener_and_source(
            listener_domain: &str,
            transport_observed_source: &str,
        ) -> Result<Self, SealedAdmissionKeyError> {
            Ok(Self {
                digest: opaque_admission_digest(&[
                    b"pre-auth-source-v1",
                    require_admission_field(listener_domain)?,
                    require_admission_field(transport_observed_source)?,
                ]),
            })
        }

        /// Returns the opaque digest without exposing a public constructor.
        #[must_use]
        pub const fn as_bytes(&self) -> &[u8; 32] {
            &self.digest
        }
    }

    /// Opaque verified quota partition.
    ///
    /// AUTH-00 owns production derivation from verified security facts.
    /// LIMIT-01 exposes no public constructor from caller or request bytes.
    #[derive(Clone, PartialEq, Eq)]
    pub struct QuotaPartitionKey {
        digest: [u8; 32],
    }

    impl fmt::Debug for QuotaPartitionKey {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("QuotaPartitionKey")
                .finish_non_exhaustive()
        }
    }

    impl QuotaPartitionKey {
        /// Public producer from verified security facts, not request identifiers.
        ///
        /// AUTH-00 later supplies these fields from provider output. A token
        /// claim or raw request identifier still cannot use this path.
        pub fn from_verified_security_facts(
            provider: &str,
            configuration_generation: u64,
            issuer: &str,
            canonical_resource: &str,
            tenant: &str,
            subject: &str,
        ) -> Result<Self, SealedAdmissionKeyError> {
            Ok(Self {
                digest: opaque_admission_digest(&[
                    b"verified-quota-partition-v1",
                    require_admission_field(provider)?,
                    &configuration_generation.to_be_bytes(),
                    require_admission_field(issuer)?,
                    require_admission_field(canonical_resource)?,
                    require_admission_field(tenant)?,
                    require_admission_field(subject)?,
                ]),
            })
        }

        /// Request-supplied identifiers never mint a verified key.
        pub fn try_from_request_identifier(_raw: &str) -> Result<Self, SealedAdmissionKeyError> {
            Err(SealedAdmissionKeyError::RequestSuppliedIdentifier)
        }

        /// Returns the opaque digest.
        #[must_use]
        pub const fn as_bytes(&self) -> &[u8; 32] {
            &self.digest
        }
    }

    /// Opaque non-authorizing key for client-side pre-token authorization flows.
    #[derive(Clone, PartialEq, Eq)]
    pub struct AuthorizationFlowQuotaKey {
        digest: [u8; 32],
    }

    impl fmt::Debug for AuthorizationFlowQuotaKey {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("AuthorizationFlowQuotaKey")
                .finish_non_exhaustive()
        }
    }

    impl AuthorizationFlowQuotaKey {
        /// Builds a flow key from configured issuer/resource/client/driver/profile.
        ///
        /// Access tokens, resource-owner claims, attacker-supplied client IDs,
        /// and network addresses are not accepted fields.
        pub fn from_configured_flow(
            issuer: &str,
            canonical_resource: &str,
            client_registration_id: &str,
            redirect_driver_class: &str,
            auth_profile: &str,
        ) -> Result<Self, SealedAdmissionKeyError> {
            Ok(Self {
                digest: opaque_admission_digest(&[
                    b"authorization-flow-quota-v1",
                    require_admission_field(issuer)?,
                    require_admission_field(canonical_resource)?,
                    require_admission_field(client_registration_id)?,
                    require_admission_field(redirect_driver_class)?,
                    require_admission_field(auth_profile)?,
                ]),
            })
        }

        /// Returns the opaque digest.
        #[must_use]
        pub const fn as_bytes(&self) -> &[u8; 32] {
            &self.digest
        }
    }

    /// Admission domain for a request, subscription, exchange, or OAuth flow.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum AdmissionPartition {
        /// Unauthenticated work charged to a transport-observed source bucket.
        PreAuth(PreAuthSourceBucketKey),
        /// Authenticated work charged to a verified quota partition.
        Verified(QuotaPartitionKey),
        /// Pre-token authorization-flow work charged to a configured flow key.
        AuthorizationFlow(AuthorizationFlowQuotaKey),
    }

    impl AdmissionPartition {
        /// Places unauthenticated work in the pre-auth domain.
        #[must_use]
        pub const fn pre_auth(key: PreAuthSourceBucketKey) -> Self {
            Self::PreAuth(key)
        }

        /// Places verified work in the verified domain.
        #[must_use]
        pub const fn verified(key: QuotaPartitionKey) -> Self {
            Self::Verified(key)
        }

        /// Places pre-token flow work in the authorization-flow domain.
        #[must_use]
        pub const fn authorization_flow(key: AuthorizationFlowQuotaKey) -> Self {
            Self::AuthorizationFlow(key)
        }

        /// Request-supplied identifiers cannot manufacture a verified partition.
        pub fn try_from_request_identifier(raw: &str) -> Result<Self, SealedAdmissionKeyError> {
            QuotaPartitionKey::try_from_request_identifier(raw).map(Self::verified)
        }

        /// Returns whether this partition is still pre-auth.
        #[must_use]
        pub const fn is_pre_auth(&self) -> bool {
            matches!(self, Self::PreAuth(_))
        }

        /// Returns whether this partition is verified.
        #[must_use]
        pub const fn is_verified(&self) -> bool {
            matches!(self, Self::Verified(_))
        }

        fn occupancy_key(&self) -> OccupancyKey {
            match self {
                Self::PreAuth(key) => OccupancyKey::PreAuth(*key.as_bytes()),
                Self::Verified(key) => OccupancyKey::Verified(*key.as_bytes()),
                Self::AuthorizationFlow(key) => OccupancyKey::AuthorizationFlow(*key.as_bytes()),
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    enum OccupancyKey {
        PreAuth([u8; 32]),
        Verified([u8; 32]),
        AuthorizationFlow([u8; 32]),
    }

    /// Refusal from [`AdmissionController`] reserve/commit/release.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AdmissionError {
        /// A reserve requested zero units.
        ZeroUnits,
        /// A constructor received a zero global or partition capacity.
        ZeroCapacity,
        /// The next reserve would exceed the controller-wide capacity.
        GlobalCapacityExceeded {
            /// Units requested by this reserve.
            requested: usize,
            /// Current global occupancy.
            in_use: usize,
            /// Configured global ceiling.
            limit: usize,
        },
        /// The next reserve would exceed that partition's capacity.
        PartitionCapacityExceeded {
            /// Units requested by this reserve.
            requested: usize,
            /// Current occupancy of the requested partition.
            in_use: usize,
            /// Configured per-partition ceiling.
            limit: usize,
        },
        /// Commit or release ran against a reservation that is not held.
        ReservationNotHeld,
        /// A second commit or release was attempted after settlement.
        AlreadySettled,
        /// Commit ran after the reservation deadline.
        DeadlineExceeded,
        /// Occupancy arithmetic overflowed `usize`.
        ArithmeticOverflow,
    }

    impl fmt::Display for AdmissionError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::ZeroUnits => {
                    formatter.write_str("admission reserve requires a positive unit count")
                }
                Self::ZeroCapacity => {
                    formatter.write_str("admission controller capacity must be positive")
                }
                Self::GlobalCapacityExceeded {
                    requested,
                    in_use,
                    limit,
                } => write!(
                    formatter,
                    "global admission capacity {limit} exceeded (in_use {in_use}, requested {requested})"
                ),
                Self::PartitionCapacityExceeded {
                    requested,
                    in_use,
                    limit,
                } => write!(
                    formatter,
                    "partition admission capacity {limit} exceeded (in_use {in_use}, requested {requested})"
                ),
                Self::ReservationNotHeld => {
                    formatter.write_str("admission reservation is not held")
                }
                Self::AlreadySettled => {
                    formatter.write_str("admission reservation already settled")
                }
                Self::DeadlineExceeded => {
                    formatter.write_str("admission reservation deadline exceeded")
                }
                Self::ArithmeticOverflow => formatter.write_str("admission occupancy overflowed"),
            }
        }
    }

    impl std::error::Error for AdmissionError {}

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ReservationLifecycle {
        Held,
        Committed,
        Released,
    }

    struct ReservationRecord {
        units: usize,
        key: OccupancyKey,
        lifecycle: ReservationLifecycle,
        deadline: Option<Instant>,
    }

    struct AdmissionState {
        global_in_use: usize,
        partition_in_use: HashMap<OccupancyKey, usize>,
        committed_work: usize,
        release_count: usize,
        next_id: u64,
        reservations: HashMap<u64, ReservationRecord>,
        admission_count: usize,
    }

    /// Process-wide plus per-partition admission controller.
    ///
    /// Capacities are taken from an immutable [`ProtocolLimits`] snapshot and
    /// cannot grow after construction. Every failed reserve, commit, or release
    /// leaves occupancy counters unchanged.
    #[derive(Clone)]
    pub struct AdmissionController {
        snapshot: ProtocolLimits,
        global_limit: usize,
        partition_limit: usize,
        inner: Arc<Mutex<AdmissionState>>,
    }

    impl fmt::Debug for AdmissionController {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("AdmissionController")
                .field("generation", &self.snapshot.generation())
                .field("global_limit", &self.global_limit)
                .field("partition_limit", &self.partition_limit)
                .finish_non_exhaustive()
        }
    }

    fn lock_admission(state: &Mutex<AdmissionState>) -> MutexGuard<'_, AdmissionState> {
        state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    impl AdmissionController {
        /// Builds a controller whose global and partition ceilings equal `capacity`.
        pub fn with_capacity(
            snapshot: ProtocolLimits,
            capacity: usize,
        ) -> Result<Self, AdmissionError> {
            Self::with_capacities(snapshot, capacity, capacity)
        }

        /// Builds a controller with independent global and per-partition ceilings.
        pub fn with_capacities(
            snapshot: ProtocolLimits,
            global_limit: usize,
            partition_limit: usize,
        ) -> Result<Self, AdmissionError> {
            if global_limit == 0 || partition_limit == 0 {
                return Err(AdmissionError::ZeroCapacity);
            }
            Ok(Self {
                snapshot,
                global_limit,
                partition_limit,
                inner: Arc::new(Mutex::new(AdmissionState {
                    global_in_use: 0,
                    partition_in_use: HashMap::new(),
                    committed_work: 0,
                    release_count: 0,
                    next_id: 1,
                    reservations: HashMap::new(),
                    admission_count: 0,
                })),
            })
        }

        /// Returns the immutable limits snapshot captured at construction.
        #[must_use]
        pub const fn limits(&self) -> &ProtocolLimits {
            &self.snapshot
        }

        /// Current global occupancy.
        #[must_use]
        pub fn global_in_use(&self) -> usize {
            lock_admission(&self.inner).global_in_use
        }

        /// Current occupancy of one partition.
        #[must_use]
        pub fn partition_in_use(&self, partition: &AdmissionPartition) -> usize {
            lock_admission(&self.inner)
                .partition_in_use
                .get(&partition.occupancy_key())
                .copied()
                .unwrap_or(0)
        }

        /// Units whose reservations have committed and not yet released.
        #[must_use]
        pub fn committed_work(&self) -> usize {
            lock_admission(&self.inner).committed_work
        }

        /// Number of occupancy-releasing settlements (release, cancel, or drop).
        #[must_use]
        pub fn release_count(&self) -> usize {
            lock_admission(&self.inner).release_count
        }

        /// Successful reserve count. Historical keys are not retained.
        #[must_use]
        pub fn admission_count(&self) -> usize {
            lock_admission(&self.inner).admission_count
        }

        /// Currently live (held or committed, not yet released) reservations.
        #[must_use]
        pub fn live_reservation_count(&self) -> usize {
            lock_admission(&self.inner).reservations.len()
        }

        /// Reserves `units` against `partition` and the global ceiling.
        pub fn reserve(
            &self,
            partition: AdmissionPartition,
            units: usize,
        ) -> Result<AdmissionReservation, AdmissionError> {
            self.reserve_until(partition, units, None)
        }

        /// Reserves `units` that must commit before `deadline`.
        pub fn reserve_with_deadline(
            &self,
            partition: AdmissionPartition,
            units: usize,
            deadline: Instant,
        ) -> Result<AdmissionReservation, AdmissionError> {
            self.reserve_until(partition, units, Some(deadline))
        }

        fn reserve_until(
            &self,
            partition: AdmissionPartition,
            units: usize,
            deadline: Option<Instant>,
        ) -> Result<AdmissionReservation, AdmissionError> {
            if units == 0 {
                return Err(AdmissionError::ZeroUnits);
            }
            let key = partition.occupancy_key();
            let mut state = lock_admission(&self.inner);
            let partition_in_use = state.partition_in_use.get(&key).copied().unwrap_or(0);
            let next_global = state
                .global_in_use
                .checked_add(units)
                .ok_or(AdmissionError::ArithmeticOverflow)?;
            let next_partition = partition_in_use
                .checked_add(units)
                .ok_or(AdmissionError::ArithmeticOverflow)?;
            if next_partition > self.partition_limit {
                return Err(AdmissionError::PartitionCapacityExceeded {
                    requested: units,
                    in_use: partition_in_use,
                    limit: self.partition_limit,
                });
            }
            if next_global > self.global_limit {
                return Err(AdmissionError::GlobalCapacityExceeded {
                    requested: units,
                    in_use: state.global_in_use,
                    limit: self.global_limit,
                });
            }
            let id = state.next_id;
            state.next_id = state
                .next_id
                .checked_add(1)
                .ok_or(AdmissionError::ArithmeticOverflow)?;
            state.global_in_use = next_global;
            state.partition_in_use.insert(key, next_partition);
            state.reservations.insert(
                id,
                ReservationRecord {
                    units,
                    key,
                    lifecycle: ReservationLifecycle::Held,
                    deadline,
                },
            );
            state.admission_count = state.admission_count.saturating_add(1);
            drop(state);
            Ok(AdmissionReservation {
                inner: Arc::clone(&self.inner),
                id,
                live: true,
            })
        }
    }

    /// One live occupancy charge returned by [`AdmissionController::reserve`].
    pub struct AdmissionReservation {
        inner: Arc<Mutex<AdmissionState>>,
        id: u64,
        live: bool,
    }

    impl fmt::Debug for AdmissionReservation {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("AdmissionReservation")
                .field("id", &self.id)
                .finish_non_exhaustive()
        }
    }

    impl AdmissionReservation {
        /// Transfers a held charge into committed work without duplicating occupancy.
        pub fn commit(&mut self) -> Result<(), AdmissionError> {
            if !self.live {
                return Err(AdmissionError::AlreadySettled);
            }
            let mut state = lock_admission(&self.inner);
            let units = {
                let record = state
                    .reservations
                    .get_mut(&self.id)
                    .ok_or(AdmissionError::ReservationNotHeld)?;
                match record.lifecycle {
                    ReservationLifecycle::Released | ReservationLifecycle::Committed => {
                        return Err(AdmissionError::AlreadySettled);
                    }
                    ReservationLifecycle::Held => {}
                }
                if record
                    .deadline
                    .is_some_and(|deadline| Instant::now() >= deadline)
                {
                    return Err(AdmissionError::DeadlineExceeded);
                }
                record.units
            };
            let next_committed = state
                .committed_work
                .checked_add(units)
                .ok_or(AdmissionError::ArithmeticOverflow)?;
            if let Some(record) = state.reservations.get_mut(&self.id) {
                record.lifecycle = ReservationLifecycle::Committed;
            }
            state.committed_work = next_committed;
            Ok(())
        }

        /// Releases occupancy exactly once.
        pub fn release(&mut self) -> Result<(), AdmissionError> {
            self.settle(ReservationLifecycle::Released, true)
        }

        /// Cancels a held reservation. Identical occupancy effect to [`Self::release`].
        pub fn cancel(&mut self) -> Result<(), AdmissionError> {
            self.release()
        }

        fn settle(
            &mut self,
            target: ReservationLifecycle,
            report_already_settled: bool,
        ) -> Result<(), AdmissionError> {
            if !self.live {
                return if report_already_settled {
                    Err(AdmissionError::AlreadySettled)
                } else {
                    Ok(())
                };
            }
            let mut state = lock_admission(&self.inner);
            let settled = {
                let Some(record) = state.reservations.get_mut(&self.id) else {
                    self.live = false;
                    return Err(AdmissionError::ReservationNotHeld);
                };
                match record.lifecycle {
                    ReservationLifecycle::Released => {
                        self.live = false;
                        return if report_already_settled {
                            Err(AdmissionError::AlreadySettled)
                        } else {
                            Ok(())
                        };
                    }
                    ReservationLifecycle::Held | ReservationLifecycle::Committed => {
                        let units = record.units;
                        let key = record.key;
                        let was_committed = record.lifecycle == ReservationLifecycle::Committed;
                        Some((units, key, was_committed))
                    }
                }
            };
            let Some((units, key, was_committed)) = settled else {
                self.live = false;
                return Ok(());
            };
            state.reservations.remove(&self.id);
            let partition_in_use = state.partition_in_use.get(&key).copied().unwrap_or(0);
            state.global_in_use = state.global_in_use.saturating_sub(units);
            let remaining = partition_in_use.saturating_sub(units);
            if remaining == 0 {
                state.partition_in_use.remove(&key);
            } else {
                state.partition_in_use.insert(key, remaining);
            }
            if was_committed {
                state.committed_work = state.committed_work.saturating_sub(units);
            }
            state.release_count = state.release_count.saturating_add(1);
            self.live = false;
            let _ = target;
            Ok(())
        }
    }

    impl Drop for AdmissionReservation {
        fn drop(&mut self) {
            let _ = self.settle(ReservationLifecycle::Released, false);
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
            let duration_nanos = u64::try_from(limits.wall_clock.as_nanos()).map_err(|_| {
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
            if next_rounds > self.limits.rounds {
                return Err(LogicalExchangeBudgetError::RoundLimitExceeded {
                    limit: self.limits.rounds,
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
            if next_round_inputs > self.limits.inputs_per_round {
                return Err(LogicalExchangeBudgetError::InputsPerRoundLimitExceeded {
                    limit: self.limits.inputs_per_round,
                });
            }
            let next_total_inputs = counters.inputs_admitted.checked_add(1).ok_or(
                LogicalExchangeBudgetError::ArithmeticOverflow {
                    resource: LogicalExchangeBudgetResource::TotalInputs,
                },
            )?;
            if next_total_inputs > self.limits.inputs {
                return Err(LogicalExchangeBudgetError::InputsLimitExceeded {
                    limit: self.limits.inputs,
                });
            }
            let next_state_bytes = counters
                .state_bytes_admitted
                .checked_add(state_bytes)
                .ok_or(LogicalExchangeBudgetError::ArithmeticOverflow {
                    resource: LogicalExchangeBudgetResource::StateBytes,
                })?;
            if next_state_bytes > self.limits.state_bytes {
                return Err(LogicalExchangeBudgetError::StateByteLimitExceeded {
                    limit: self.limits.state_bytes,
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
            if next_state_bytes > self.limits.state_bytes {
                return Err(LogicalExchangeBudgetError::StateByteLimitExceeded {
                    limit: self.limits.state_bytes,
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
    CancelledError, CatalogChangePublisher, ClientCapabilityInfo, ClientImplementationInfo,
    ClientRoot, ElicitationAction, ElicitationMode, ElicitationRequest, ElicitationResponse,
    ElicitationSender, IntoOutcome, MAX_PROMPT_GET_DEPTH, MAX_RESOURCE_READ_DEPTH,
    MAX_TOOL_CALL_DEPTH, McpCatalogKind, McpContext, McpContextLeaseGuard, McpLogLevel,
    McpRequestCancellation, NoOpElicitationSender, NoOpNotificationSender, NoOpSamplingSender,
    NotificationSender, ProgressReporter, PromptCaller, PromptGetResult, PromptMessageItem,
    PromptMessageRole, ResourceContentItem, ResourceReadResult, ResourceReader, RootsProvider,
    SamplingRequest, SamplingRequestMessage, SamplingResponse, SamplingRole, SamplingSender,
    SamplingStopReason, ServerCapabilityInfo, ToolCallResult, ToolCaller, ToolContentItem,
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
    AdmissionController, AdmissionError, AdmissionPartition, AdmissionReservation,
    AuthorizationFlowQuotaKey, DEFAULT_CANCELLATION_REASON_MAX_BYTES, DEFAULT_CURSOR_MAX_BYTES,
    DEFAULT_JSON_RPC_MAX_BODY_BYTES, DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS,
    DEFAULT_LOGICAL_EXCHANGE_MAX_INPUTS_PER_ROUND, DEFAULT_LOGICAL_EXCHANGE_MAX_ROUNDS,
    DEFAULT_LOGICAL_EXCHANGE_MAX_STATE_BYTES, DEFAULT_LOGICAL_EXCHANGE_MAX_WALL_CLOCK,
    DEFAULT_METADATA_MAX_BYTES, DEFAULT_METADATA_MAX_ENTRIES, DEFAULT_URI_MAX_BYTES,
    HARD_CANCELLATION_REASON_MAX_BYTES, HARD_CURSOR_MAX_BYTES, HARD_JSON_RPC_MAX_BODY_BYTES,
    HARD_LOGICAL_EXCHANGE_MAX_INPUTS, HARD_LOGICAL_EXCHANGE_MAX_INPUTS_PER_ROUND,
    HARD_LOGICAL_EXCHANGE_MAX_ROUNDS, HARD_LOGICAL_EXCHANGE_MAX_STATE_BYTES,
    HARD_LOGICAL_EXCHANGE_MAX_WALL_CLOCK, HARD_METADATA_MAX_BYTES, HARD_METADATA_MAX_ENTRIES,
    HARD_URI_MAX_BYTES, LogicalExchangeBudget, LogicalExchangeBudgetError,
    LogicalExchangeBudgetResource, PROTOCOL_LIMITS_INITIAL_GENERATION, PreAuthSourceBucketKey,
    ProtocolLimit, ProtocolLimits, ProtocolLimitsBuilder, ProtocolLimitsError, QuotaPartitionKey,
    SealedAdmissionKeyError,
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

// Re-export production-safe asupersync types for convenience.  Lab runtime
// internals are intentionally exposed only by the facade's `testing-lab`
// feature, so downstream production code cannot acquire them by depending on
// `fastmcp-core` directly.
pub use asupersync::{Budget, Cx, Outcome, RegionId, Scope, TaskId};

#[cfg(test)]
fn limit_01_a_bound_rows() -> [(crate::ProtocolLimit, usize, usize); 6] {
    [
        (
            crate::ProtocolLimit::JsonRpcBodyBytes,
            crate::DEFAULT_JSON_RPC_MAX_BODY_BYTES,
            crate::HARD_JSON_RPC_MAX_BODY_BYTES,
        ),
        (
            crate::ProtocolLimit::MetadataEntries,
            crate::DEFAULT_METADATA_MAX_ENTRIES as usize,
            crate::HARD_METADATA_MAX_ENTRIES as usize,
        ),
        (
            crate::ProtocolLimit::MetadataBytes,
            crate::DEFAULT_METADATA_MAX_BYTES,
            crate::HARD_METADATA_MAX_BYTES,
        ),
        (
            crate::ProtocolLimit::UriBytes,
            crate::DEFAULT_URI_MAX_BYTES,
            crate::HARD_URI_MAX_BYTES,
        ),
        (
            crate::ProtocolLimit::CancellationReasonBytes,
            crate::DEFAULT_CANCELLATION_REASON_MAX_BYTES,
            crate::HARD_CANCELLATION_REASON_MAX_BYTES,
        ),
        (
            crate::ProtocolLimit::CursorBytes,
            crate::DEFAULT_CURSOR_MAX_BYTES,
            crate::HARD_CURSOR_MAX_BYTES,
        ),
    ]
}

/// LIMIT-01 A positive: six catalog rows, sealed partitions, and N-1/N charges.
#[cfg(test)]
#[test]
fn limit_01_a_positive() {
    let defaults = crate::ProtocolLimits::try_new(
        crate::DEFAULT_JSON_RPC_MAX_BODY_BYTES,
        crate::DEFAULT_METADATA_MAX_ENTRIES,
        crate::DEFAULT_METADATA_MAX_BYTES,
        crate::DEFAULT_URI_MAX_BYTES,
        crate::DEFAULT_CANCELLATION_REASON_MAX_BYTES,
        crate::DEFAULT_CURSOR_MAX_BYTES,
    )
    .expect("documented defaults must admit");
    defaults.validate().expect("defaults remain valid");
    let snapshot = defaults.snapshot();
    assert_eq!(
        snapshot.generation(),
        crate::PROTOCOL_LIMITS_INITIAL_GENERATION
    );
    for (limit, default, ceiling) in limit_01_a_bound_rows() {
        assert_eq!(
            snapshot.configured_units(limit).expect("countable row"),
            default
        );
        assert_eq!(
            crate::ProtocolLimits::hard_ceiling(limit).expect("countable row"),
            ceiling
        );
        let at_ceiling = crate::ProtocolLimits::builder()
            .json_rpc_max_body_bytes(if limit == crate::ProtocolLimit::JsonRpcBodyBytes {
                ceiling
            } else {
                crate::DEFAULT_JSON_RPC_MAX_BODY_BYTES
            })
            .metadata_max_entries(if limit == crate::ProtocolLimit::MetadataEntries {
                u16::try_from(ceiling).expect("metadata entries fit u16")
            } else {
                crate::DEFAULT_METADATA_MAX_ENTRIES
            })
            .metadata_max_bytes(if limit == crate::ProtocolLimit::MetadataBytes {
                ceiling
            } else {
                crate::DEFAULT_METADATA_MAX_BYTES
            })
            .uri_max_bytes(if limit == crate::ProtocolLimit::UriBytes {
                ceiling
            } else {
                crate::DEFAULT_URI_MAX_BYTES
            })
            .cancellation_reason_max_bytes(
                if limit == crate::ProtocolLimit::CancellationReasonBytes {
                    ceiling
                } else {
                    crate::DEFAULT_CANCELLATION_REASON_MAX_BYTES
                },
            )
            .cursor_max_bytes(if limit == crate::ProtocolLimit::CursorBytes {
                ceiling
            } else {
                crate::DEFAULT_CURSOR_MAX_BYTES
            })
            .build()
            .expect("hard ceiling must admit");
        assert_eq!(
            at_ceiling.configured_units(limit).expect("countable row"),
            ceiling
        );
        assert_eq!(
            snapshot
                .try_charge(limit, default - 1, 1)
                .expect("N-1 admits"),
            default
        );
        assert_eq!(
            snapshot.try_charge(limit, 0, default).expect("N admits"),
            default
        );
    }

    assert_eq!(
        crate::ProtocolLimits::hard_ceiling(crate::ProtocolLimit::LogicalExchangeWallClock),
        Err(crate::ProtocolLimitsError::NotCountable {
            limit: crate::ProtocolLimit::LogicalExchangeWallClock,
        })
    );
    assert_eq!(
        snapshot.configured_units(crate::ProtocolLimit::LogicalExchangeWallClock),
        Err(crate::ProtocolLimitsError::NotCountable {
            limit: crate::ProtocolLimit::LogicalExchangeWallClock,
        })
    );

    let later = crate::ProtocolLimits::try_new(
        crate::HARD_JSON_RPC_MAX_BODY_BYTES,
        crate::HARD_METADATA_MAX_ENTRIES,
        crate::HARD_METADATA_MAX_BYTES,
        crate::HARD_URI_MAX_BYTES,
        crate::HARD_CANCELLATION_REASON_MAX_BYTES,
        crate::HARD_CURSOR_MAX_BYTES,
    )
    .expect("hard ceilings must admit");
    assert_eq!(snapshot, defaults.snapshot());
    assert_ne!(later.snapshot(), snapshot);

    let pre_auth = crate::AdmissionPartition::pre_auth(
        crate::PreAuthSourceBucketKey::from_listener_and_source(
            "mcp.example.test",
            "tcp:203.0.113.8",
        )
        .expect("transport-observed source is admitted"),
    );
    assert!(pre_auth.is_pre_auth());
    assert!(!pre_auth.is_verified());
    let verified = crate::AdmissionPartition::verified(
        crate::QuotaPartitionKey::from_verified_security_facts(
            "static-token",
            1,
            "https://issuer.example.test",
            "https://mcp.example.test/mcp",
            "tenant-a",
            "subject-a",
        )
        .expect("verified security facts mint a partition key"),
    );
    assert!(verified.is_verified());
    let flow = crate::AdmissionPartition::authorization_flow(
        crate::AuthorizationFlowQuotaKey::from_configured_flow(
            "https://issuer.example.test",
            "https://mcp.example.test/mcp",
            "registered-client-1",
            "loopback",
            "oauth-authorization-code",
        )
        .expect("configured flow is admitted"),
    );
    assert!(!flow.is_verified());
    assert!(!flow.is_pre_auth());
}

/// LIMIT-01 A planted negative: one-row N+1 and raw identifiers leave state unchanged.
#[cfg(test)]
#[test]
fn limit_01_a_planted_negative() {
    let limits = crate::ProtocolLimits::try_new(
        crate::DEFAULT_JSON_RPC_MAX_BODY_BYTES,
        crate::DEFAULT_METADATA_MAX_ENTRIES,
        crate::DEFAULT_METADATA_MAX_BYTES,
        crate::DEFAULT_URI_MAX_BYTES,
        crate::DEFAULT_CANCELLATION_REASON_MAX_BYTES,
        crate::DEFAULT_CURSOR_MAX_BYTES,
    )
    .expect("documented defaults must admit");
    let snapshot_before = limits.snapshot();
    let mut admitted = 0_usize;
    let planted = crate::ProtocolLimit::MetadataEntries;
    let ceiling = limits.configured_units(planted).expect("countable row");
    let refused = limits
        .try_charge(planted, ceiling, 1)
        .expect_err("N+1 must refuse");
    assert_eq!(
        refused,
        crate::ProtocolLimitsError::ChargeExceedsLimit {
            limit: planted,
            requested: ceiling + 1,
            ceiling,
        }
    );
    let overflow = limits
        .try_charge(planted, usize::MAX, 1)
        .expect_err("overflow must refuse");
    assert_eq!(
        overflow,
        crate::ProtocolLimitsError::ChargeOverflow { limit: planted }
    );
    assert_eq!(admitted, 0);
    admitted = limits
        .try_charge(planted, admitted, ceiling)
        .expect("exact N still admits after refused N+1");
    assert_eq!(admitted, ceiling);
    assert_eq!(limits.snapshot(), snapshot_before);
    assert_eq!(
        crate::ProtocolLimits::builder()
            .metadata_max_entries(crate::HARD_METADATA_MAX_ENTRIES + 1)
            .build()
            .expect_err("ceiling+1 must refuse configuration"),
        crate::ProtocolLimitsError::ExceedsHardCeiling {
            limit: crate::ProtocolLimit::MetadataEntries,
        }
    );
    assert_eq!(limits.snapshot(), snapshot_before);

    let partition_before = crate::AdmissionPartition::pre_auth(
        crate::PreAuthSourceBucketKey::from_listener_and_source(
            "mcp.example.test",
            "tcp:203.0.113.8",
        )
        .expect("transport-observed source is admitted"),
    );
    assert_eq!(
        crate::QuotaPartitionKey::try_from_request_identifier("raw-request-id"),
        Err(crate::SealedAdmissionKeyError::RequestSuppliedIdentifier)
    );
    assert_eq!(
        crate::AdmissionPartition::try_from_request_identifier("raw-request-id"),
        Err(crate::SealedAdmissionKeyError::RequestSuppliedIdentifier)
    );
    assert!(partition_before.is_pre_auth());
    assert!(!partition_before.is_verified());
    assert_eq!(limits.snapshot(), snapshot_before);
}

#[cfg(test)]
fn limit_01_b_limits() -> crate::ProtocolLimits {
    crate::ProtocolLimits::try_new(
        crate::DEFAULT_JSON_RPC_MAX_BODY_BYTES,
        crate::DEFAULT_METADATA_MAX_ENTRIES,
        crate::DEFAULT_METADATA_MAX_BYTES,
        crate::DEFAULT_URI_MAX_BYTES,
        crate::DEFAULT_CANCELLATION_REASON_MAX_BYTES,
        crate::DEFAULT_CURSOR_MAX_BYTES,
    )
    .expect("documented defaults must admit")
}

#[cfg(test)]
fn limit_01_b_partition(source: &str) -> crate::AdmissionPartition {
    crate::AdmissionPartition::pre_auth(
        crate::PreAuthSourceBucketKey::from_listener_and_source("mcp.example.test", source)
            .expect("transport-observed source is admitted"),
    )
}

/// LIMIT-01 B positive: reserve N-1/N, commit/release lifecycle, two-partition fairness.
#[cfg(test)]
#[test]
fn limit_01_b_positive() {
    const N: usize = 4;
    let snapshot = limit_01_b_limits();
    let controller =
        crate::AdmissionController::with_capacity(snapshot.snapshot(), N).expect("capacity N");
    let partition = limit_01_b_partition("tcp:203.0.113.8");

    let mut held_n_minus_one = controller
        .reserve(partition.clone(), N - 1)
        .expect("N-1 admits");
    assert_eq!(controller.global_in_use(), N - 1);
    assert_eq!(controller.partition_in_use(&partition), N - 1);
    held_n_minus_one.release().expect("release N-1");
    assert_eq!(controller.global_in_use(), 0);
    assert_eq!(controller.release_count(), 1);

    let mut held_n = controller.reserve(partition.clone(), N).expect("N admits");
    assert_eq!(controller.global_in_use(), N);
    assert_eq!(
        controller
            .reserve(partition.clone(), 1)
            .expect_err("N+1 partition"),
        crate::AdmissionError::PartitionCapacityExceeded {
            requested: 1,
            in_use: N,
            limit: N,
        }
    );
    assert_eq!(controller.global_in_use(), N);
    held_n.commit().expect("commit transfers occupancy");
    assert_eq!(controller.global_in_use(), N);
    assert_eq!(controller.committed_work(), N);
    held_n.release().expect("release committed work");
    assert_eq!(controller.global_in_use(), 0);
    assert_eq!(controller.committed_work(), 0);
    assert_eq!(controller.release_count(), 2);

    {
        let _dropped = controller
            .reserve(partition.clone(), 1)
            .expect("drop path admits");
        assert_eq!(controller.global_in_use(), 1);
    }
    assert_eq!(controller.global_in_use(), 0);
    assert_eq!(controller.release_count(), 3);

    let mut expired = controller
        .reserve_with_deadline(partition.clone(), 1, std::time::Instant::now())
        .expect("deadline reserve still holds occupancy");
    assert_eq!(
        expired.commit().expect_err("expired commit rejects"),
        crate::AdmissionError::DeadlineExceeded
    );
    assert_eq!(controller.global_in_use(), 1);
    assert_eq!(controller.committed_work(), 0);
    expired.release().expect("release after commit-reject");
    assert_eq!(controller.global_in_use(), 0);

    let peer = crate::AdmissionController::with_capacities(snapshot.snapshot(), 2, 2)
        .expect("fairness capacities");
    let left = limit_01_b_partition("tcp:203.0.113.10");
    let right = limit_01_b_partition("tcp:203.0.113.11");
    let mut left_hold = peer
        .reserve(left.clone(), 2)
        .expect("left saturates global");
    assert_eq!(
        peer.reserve(right.clone(), 1)
            .expect_err("saturated global rejects the other partition"),
        crate::AdmissionError::GlobalCapacityExceeded {
            requested: 1,
            in_use: 2,
            limit: 2,
        }
    );
    assert_eq!(peer.partition_in_use(&right), 0);
    assert_eq!(peer.partition_in_use(&left), 2);
    left_hold.release().expect("left release frees global");
    let mut right_hold = peer
        .reserve(right.clone(), 1)
        .expect("release admits only the eligible other partition");
    assert_eq!(peer.partition_in_use(&left), 0);
    assert_eq!(peer.partition_in_use(&right), 1);
    assert_eq!(peer.global_in_use(), 1);
    assert_eq!(peer.admission_count(), 2);
    right_hold.release().expect("right release");
    assert_eq!(peer.live_reservation_count(), 0);

    let leak_probe =
        crate::AdmissionController::with_capacity(snapshot.snapshot(), 1).expect("capacity one");
    let leak_partition = limit_01_b_partition("tcp:203.0.113.12");
    for cycle in 0..64 {
        let mut reservation = leak_probe
            .reserve(leak_partition.clone(), 1)
            .expect("capacity-one cycle admits");
        assert_eq!(leak_probe.live_reservation_count(), 1);
        reservation.release().expect("capacity-one cycle releases");
        assert_eq!(leak_probe.live_reservation_count(), 0);
        assert_eq!(leak_probe.global_in_use(), 0);
        assert_eq!(leak_probe.release_count(), cycle + 1);
    }
}

/// LIMIT-01 B planted negative: one-variable N+1 and second release leave counters unchanged.
#[cfg(test)]
#[test]
fn limit_01_b_planted_negative() {
    let snapshot = limit_01_b_limits();
    let controller =
        crate::AdmissionController::with_capacities(snapshot.snapshot(), 4, 2).expect("capacities");
    let left = limit_01_b_partition("tcp:203.0.113.10");
    let right = limit_01_b_partition("tcp:203.0.113.11");
    let mut left_hold = controller.reserve(left.clone(), 1).expect("left holds 1");
    let before_global = controller.global_in_use();
    let before_left = controller.partition_in_use(&left);
    let before_right = controller.partition_in_use(&right);
    let before_committed = controller.committed_work();
    let before_releases = controller.release_count();
    let before_admitted = controller.admission_count();
    assert_eq!(
        controller
            .reserve(right.clone(), 3)
            .expect_err("partition N+1 rejects"),
        crate::AdmissionError::PartitionCapacityExceeded {
            requested: 3,
            in_use: 0,
            limit: 2,
        }
    );
    assert_eq!(controller.global_in_use(), before_global);
    assert_eq!(controller.partition_in_use(&left), before_left);
    assert_eq!(controller.partition_in_use(&right), before_right);
    assert_eq!(controller.committed_work(), before_committed);
    assert_eq!(controller.release_count(), before_releases);
    assert_eq!(controller.admission_count(), before_admitted);
    assert_eq!(controller.live_reservation_count(), 1);

    left_hold.release().expect("first release");
    let after_first = (
        controller.global_in_use(),
        controller.partition_in_use(&left),
        controller.committed_work(),
        controller.release_count(),
        controller.live_reservation_count(),
        controller.admission_count(),
    );
    assert_eq!(after_first.4, 0, "a released reservation is not retained");
    assert_eq!(
        left_hold
            .release()
            .expect_err("second release is already settled"),
        crate::AdmissionError::AlreadySettled
    );
    assert_eq!(
        (
            controller.global_in_use(),
            controller.partition_in_use(&left),
            controller.committed_work(),
            controller.release_count(),
            controller.live_reservation_count(),
            controller.admission_count(),
        ),
        after_first
    );
}
