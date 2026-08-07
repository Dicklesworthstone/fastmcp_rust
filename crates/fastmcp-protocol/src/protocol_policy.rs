//! Exact MCP protocol-version identity and immutable era-policy selection.
//!
//! This module intentionally models only the two supported protocol eras. It
//! does not normalize date strings or treat intermediate protocol revisions as
//! aliases. The crate-root integration is owned separately so that this policy
//! surface can remain independent of transport classification and lifecycle
//! state.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The exact modern MCP protocol revision supported by this policy surface.
pub const MODERN_PROTOCOL_VERSION: &str = "2026-07-28";

/// The exact legacy MCP protocol revision supported by this policy surface.
pub const LEGACY_PROTOCOL_VERSION: &str = "2024-11-05";

/// A protocol era selected from one exact, supported protocol revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProtocolEra {
    /// MCP 2026-07-28 per-request metadata semantics.
    Modern2026,
    /// MCP 2024-11-05 initialize-handshake semantics.
    Legacy2024,
}

impl ProtocolEra {
    /// Returns this era's only supported wire version.
    #[must_use]
    pub const fn version(self) -> ProtocolVersion {
        match self {
            Self::Modern2026 => ProtocolVersion::MODERN_2026,
            Self::Legacy2024 => ProtocolVersion::LEGACY_2024,
        }
    }
}

/// An exact, supported MCP protocol-version value.
///
/// This type can contain only the two revisions defined by this module.
/// Callers must retain an unsupported input separately after
/// [`ProtocolVersion::parse`] rejects it; in particular, `2025-11-25` cannot
/// be parsed, aliased, or normalized into either supported era.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct ProtocolVersion(ProtocolEra);

impl ProtocolVersion {
    /// The exact MCP 2026-07-28 protocol version.
    pub const MODERN_2026: Self = Self(ProtocolEra::Modern2026);

    /// The exact MCP 2024-11-05 protocol version.
    pub const LEGACY_2024: Self = Self(ProtocolEra::Legacy2024);

    /// Parses one exact supported protocol-version string.
    pub fn parse(value: &str) -> Result<Self, ProtocolVersionError> {
        match value {
            MODERN_PROTOCOL_VERSION => Ok(Self::MODERN_2026),
            LEGACY_PROTOCOL_VERSION => Ok(Self::LEGACY_2024),
            _ => Err(ProtocolVersionError::UnsupportedVersion {
                received: value.to_owned(),
            }),
        }
    }

    /// Returns the exact protocol-version spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self.0 {
            ProtocolEra::Modern2026 => MODERN_PROTOCOL_VERSION,
            ProtocolEra::Legacy2024 => LEGACY_PROTOCOL_VERSION,
        }
    }

    /// Returns the era identified by this exact version.
    #[must_use]
    pub const fn era(self) -> ProtocolEra {
        self.0
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ProtocolVersion {
    type Err = ProtocolVersionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Typed refusal for an unsupported protocol-version spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolVersionError {
    /// The string is not one of FastMCP's two exact supported revisions.
    UnsupportedVersion {
        /// The input spelling, retained without normalization.
        received: String,
    },
}

impl fmt::Display for ProtocolVersionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { received } => {
                write!(formatter, "unsupported MCP protocol version {received:?}")
            }
        }
    }
}

impl std::error::Error for ProtocolVersionError {}

/// Immutable policy chosen before a client connects or a server binds.
///
/// `Auto` remains the default policy. A policy value does not itself classify
/// a peer or mutate in response to peer bytes, errors, timeouts, or auth
/// events; transport-specific classification belongs to FND-03 integration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolPolicy {
    /// Permit both supported eras; transport-specific code classifies once.
    #[default]
    Auto,
    /// Permit only MCP 2026-07-28.
    ModernOnly,
    /// Permit only exact MCP 2024-11-05.
    LegacyOnly,
}

const MODERN_ONLY_VERSIONS: [ProtocolVersion; 1] = [ProtocolVersion::MODERN_2026];
const LEGACY_ONLY_VERSIONS: [ProtocolVersion; 1] = [ProtocolVersion::LEGACY_2024];
const AUTO_SUPPORTED_VERSIONS: [ProtocolVersion; 2] =
    [ProtocolVersion::MODERN_2026, ProtocolVersion::LEGACY_2024];

impl ProtocolPolicy {
    /// Returns whether this immutable policy admits a version.
    #[must_use]
    pub const fn permits(self, version: ProtocolVersion) -> bool {
        match self {
            Self::Auto => true,
            Self::ModernOnly => matches!(version.era(), ProtocolEra::Modern2026),
            Self::LegacyOnly => matches!(version.era(), ProtocolEra::Legacy2024),
        }
    }

    /// Returns the server's exact supported-version set for this policy.
    #[must_use]
    pub const fn supported_versions(self) -> &'static [ProtocolVersion] {
        match self {
            Self::Auto => &AUTO_SUPPORTED_VERSIONS,
            Self::ModernOnly => &MODERN_ONLY_VERSIONS,
            Self::LegacyOnly => &LEGACY_ONLY_VERSIONS,
        }
    }

    /// Returns the client preference order for this policy.
    ///
    /// Auto prefers the modern revision first; a fallback decision is owned by
    /// the isolated client-negotiation layer, never by this value type.
    #[must_use]
    pub const fn preferred_versions(self) -> &'static [ProtocolVersion] {
        self.supported_versions()
    }

    /// Returns whether using this policy requires a legacy adapter receipt.
    #[must_use]
    pub const fn requires_legacy_adapter(self) -> bool {
        !matches!(self, Self::ModernOnly)
    }

    /// Validates a client policy before any connect-side effect.
    pub fn validate_for_client(
        self,
        legacy_receipt: Option<&LegacyClientAdapterInstalledReceipt>,
    ) -> Result<ProtocolPolicySelection, ProtocolPolicyError> {
        self.validate(
            ProtocolRole::Client,
            legacy_receipt.map(LegacyReceipt::Client),
        )
    }

    /// Validates a server policy before any bind-side effect.
    pub fn validate_for_server(
        self,
        legacy_receipt: Option<&LegacyServerAdapterInstalledReceipt>,
    ) -> Result<ProtocolPolicySelection, ProtocolPolicyError> {
        self.validate(
            ProtocolRole::Server,
            legacy_receipt.map(LegacyReceipt::Server),
        )
    }

    fn validate(
        self,
        role: ProtocolRole,
        legacy_receipt: Option<LegacyReceipt<'_>>,
    ) -> Result<ProtocolPolicySelection, ProtocolPolicyError> {
        if !self.requires_legacy_adapter() {
            return Ok(ProtocolPolicySelection { policy: self, role });
        }

        let Some(receipt) = legacy_receipt else {
            return Err(ProtocolPolicyError::FeatureUnavailable { policy: self, role });
        };

        if receipt.policy() != self {
            return Err(ProtocolPolicyError::ReceiptPolicyMismatch {
                policy: self,
                receipt_policy: receipt.policy(),
                role,
            });
        }

        Ok(ProtocolPolicySelection { policy: self, role })
    }
}

/// The role for which an immutable policy is validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolRole {
    /// A client policy before connect.
    Client,
    /// A server policy before bind.
    Server,
}

/// A validated immutable policy and role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtocolPolicySelection {
    policy: ProtocolPolicy,
    role: ProtocolRole,
}

impl ProtocolPolicySelection {
    /// Returns the selected immutable policy.
    #[must_use]
    pub const fn policy(self) -> ProtocolPolicy {
        self.policy
    }

    /// Returns the role for which the policy was validated.
    #[must_use]
    pub const fn role(self) -> ProtocolRole {
        self.role
    }
}

/// Typed policy-validation refusals raised before connect or bind side effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolPolicyError {
    /// A legacy-capable policy was selected without its required feature and
    /// sealed adapter-installation receipt.
    FeatureUnavailable {
        /// The rejected policy.
        policy: ProtocolPolicy,
        /// The role whose adapter receipt was required.
        role: ProtocolRole,
    },
    /// A sealed receipt was installed for a different immutable policy.
    ReceiptPolicyMismatch {
        /// The selected policy.
        policy: ProtocolPolicy,
        /// The policy to which the receipt is bound.
        receipt_policy: ProtocolPolicy,
        /// The role whose receipt was supplied.
        role: ProtocolRole,
    },
}

impl fmt::Display for ProtocolPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FeatureUnavailable { policy, role } => {
                write!(
                    formatter,
                    "{policy:?} is unavailable for {role:?} without a legacy adapter receipt"
                )
            }
            Self::ReceiptPolicyMismatch {
                policy,
                receipt_policy,
                role,
            } => write!(
                formatter,
                "{role:?} legacy receipt is bound to {receipt_policy:?}, not {policy:?}"
            ),
        }
    }
}

impl std::error::Error for ProtocolPolicyError {}

/// Immutable facts bound into a sealed legacy-adapter installation receipt.
///
/// Only the exact adapter installers can supply this value to the sealed
/// issuer. It deliberately has no serializer or public constructor.
#[derive(Debug, PartialEq, Eq)]
pub struct LegacyReceiptBinding {
    policy: ProtocolPolicy,
    transport_binding: String,
    endpoint_or_process_configuration: String,
    security_partition: String,
    adapter_generation: u64,
    store_generation: u64,
    configuration_generation: u64,
    limits_profile_identity: String,
}

impl LegacyReceiptBinding {
    /// Creates a binding only from trusted in-crate adapter installation code.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        policy: ProtocolPolicy,
        transport_binding: String,
        endpoint_or_process_configuration: String,
        security_partition: String,
        adapter_generation: u64,
        store_generation: u64,
        configuration_generation: u64,
        limits_profile_identity: String,
    ) -> Self {
        Self {
            policy,
            transport_binding,
            endpoint_or_process_configuration,
            security_partition,
            adapter_generation,
            store_generation,
            configuration_generation,
            limits_profile_identity,
        }
    }
}

/// Opaque, non-cloneable proof that the exact legacy client adapter is installed.
#[derive(Debug, PartialEq, Eq)]
pub struct LegacyClientAdapterInstalledReceipt {
    binding: LegacyReceiptBinding,
}

/// Opaque, non-cloneable proof that the exact legacy server adapter is installed.
#[derive(Debug, PartialEq, Eq)]
pub struct LegacyServerAdapterInstalledReceipt {
    binding: LegacyReceiptBinding,
}

impl LegacyClientAdapterInstalledReceipt {
    /// Returns the immutable policy bound at client-adapter installation.
    #[must_use]
    pub const fn policy(&self) -> ProtocolPolicy {
        self.binding.policy
    }
}

impl LegacyServerAdapterInstalledReceipt {
    /// Returns the immutable policy bound at server-adapter installation.
    #[must_use]
    pub const fn policy(&self) -> ProtocolPolicy {
        self.binding.policy
    }
}

enum LegacyReceipt<'a> {
    Client(&'a LegacyClientAdapterInstalledReceipt),
    Server(&'a LegacyServerAdapterInstalledReceipt),
}

impl LegacyReceipt<'_> {
    const fn policy(&self) -> ProtocolPolicy {
        match self {
            Self::Client(receipt) => receipt.policy(),
            Self::Server(receipt) => receipt.policy(),
        }
    }
}

mod sealed {
    pub trait ReceiptIssuerSealed {}
}

/// Sealed issuer interface for the exact legacy-adapter installation path.
///
/// External crates cannot implement this trait and therefore cannot forge a
/// client or server installation receipt. The future LEG-02 and LEG-03
/// installers are the only intended in-crate implementers.
#[allow(private_bounds)]
pub trait LegacyAdapterReceiptIssuer: sealed::ReceiptIssuerSealed {
    /// Issues a client receipt from trusted installation facts.
    #[doc(hidden)]
    fn issue_client_receipt(binding: LegacyReceiptBinding) -> LegacyClientAdapterInstalledReceipt {
        LegacyClientAdapterInstalledReceipt { binding }
    }

    /// Issues a server receipt from trusted installation facts.
    #[doc(hidden)]
    fn issue_server_receipt(binding: LegacyReceiptBinding) -> LegacyServerAdapterInstalledReceipt {
        LegacyServerAdapterInstalledReceipt { binding }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnd_03_policy_receipts_positive() {
        assert_eq!(
            ProtocolVersion::parse(MODERN_PROTOCOL_VERSION),
            Ok(ProtocolVersion::MODERN_2026)
        );
        assert_eq!(
            ProtocolVersion::parse(LEGACY_PROTOCOL_VERSION),
            Ok(ProtocolVersion::LEGACY_2024)
        );
        assert_eq!(ProtocolVersion::MODERN_2026.era(), ProtocolEra::Modern2026);
        assert_eq!(ProtocolVersion::LEGACY_2024.era(), ProtocolEra::Legacy2024);

        let policy = ProtocolPolicy::default();
        assert_eq!(policy, ProtocolPolicy::Auto);
        assert_eq!(
            policy.supported_versions(),
            [ProtocolVersion::MODERN_2026, ProtocolVersion::LEGACY_2024]
        );
        assert_eq!(policy.preferred_versions(), policy.supported_versions());
        assert!(policy.permits(ProtocolVersion::MODERN_2026));
        assert!(policy.permits(ProtocolVersion::LEGACY_2024));

        let modern_client = ProtocolPolicy::ModernOnly
            .validate_for_client(None)
            .expect("modern-only client policy requires no legacy receipt");
        let modern_server = ProtocolPolicy::ModernOnly
            .validate_for_server(None)
            .expect("modern-only server policy requires no legacy receipt");
        assert_eq!(modern_client.policy(), ProtocolPolicy::ModernOnly);
        assert_eq!(modern_client.role(), ProtocolRole::Client);
        assert_eq!(modern_server.policy(), ProtocolPolicy::ModernOnly);
        assert_eq!(modern_server.role(), ProtocolRole::Server);
    }

    #[test]
    fn fnd_03_policy_receipts_planted_negative() {
        let accepted_policy = ProtocolPolicy::ModernOnly;
        let accepted_state = accepted_policy
            .validate_for_client(None)
            .expect("modern-only baseline must be accepted");
        let state_before_refusal = accepted_state;

        // The selected policy is the sole planted dimension. Neither the role
        // nor the receipt input changes from the accepted baseline.
        let planted_policy = ProtocolPolicy::LegacyOnly;
        let refusal = planted_policy
            .validate_for_client(None)
            .expect_err("legacy-only policy without a receipt must be refused");

        assert_eq!(
            refusal,
            ProtocolPolicyError::FeatureUnavailable {
                policy: ProtocolPolicy::LegacyOnly,
                role: ProtocolRole::Client,
            }
        );
        assert_eq!(accepted_state, state_before_refusal);
        assert_eq!(accepted_state.policy(), ProtocolPolicy::ModernOnly);
        assert_eq!(accepted_state.role(), ProtocolRole::Client);
        assert_eq!(
            ProtocolVersion::parse("2025-11-25"),
            Err(ProtocolVersionError::UnsupportedVersion {
                received: "2025-11-25".to_owned(),
            })
        );
    }
}
