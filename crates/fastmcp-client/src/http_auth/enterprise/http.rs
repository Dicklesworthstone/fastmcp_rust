//! Request-local HTTP binding of an already exchanged enterprise access token.
//!
//! This boundary consumes the exchange driver's protected grant. It keeps the
//! admitted authorization metadata separate from MCP server discovery and
//! requires the exact empty client declaration on each outgoing MCP request.
//! It does not acquire assertions, attest browser custody, or implement an
//! authorization server. The embedding supplies trusted metadata freshness and
//! rotates this owner when its deployment policy or metadata changes.

use std::fmt;
use std::time::Instant;

use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{
    FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_PROTOCOL_VERSION, FINAL_PROTOCOL_VERSION_META_KEY,
    JsonRpcMessage, decode_strict_jsonrpc_message,
};

use super::identity::EnterpriseIdentitySnapshotKey;
use super::policy::EnterpriseProfile;
use super::replay::IdentityAssertionExchangeGuard;

/// Keeps the exchange's sealed process/restore fence alive after conversion.
/// This is private custody, never a caller-constructible attestation.
pub(in crate::http_auth) struct EnterpriseHttpGrantGuard(IdentityAssertionExchangeGuard);

impl EnterpriseHttpGrantGuard {
    pub(super) fn new(reservation: IdentityAssertionExchangeGuard) -> Self {
        Self(reservation)
    }

    pub(in crate::http_auth) fn is_valid(&self) -> bool {
        self.0.check().is_ok()
    }
}

/// Exact official client declaration. This is an authorization overlay, not
/// an extension descriptor advertised by `server/discover`.
pub const ENTERPRISE_AUTHORIZATION_EXTENSION_ID: &str =
    "io.modelcontextprotocol/enterprise-managed-authorization";

/// Fixed post-exchange binding failures; no credential, issuer or peer document
/// is included in these diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterpriseHttpPolicyError {
    /// Either independently admitted metadata document is no longer fresh.
    StaleMetadata,
    /// The owning policy was explicitly revoked or replaced.
    Revoked,
    /// The complete exchange profile differs from the current policy.
    ProfileMismatch,
    /// The exchanged subject binding differs from the current reviewed mapping.
    IdentitySnapshotMismatch,
    /// A replacement must advance policy and cannot roll back any generation.
    GenerationRollback,
    /// The exchanged token failed its existing expiry or replay-owner check.
    CredentialUnavailable,
}

impl fmt::Display for EnterpriseHttpPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::StaleMetadata => "enterprise authorization metadata is stale",
            Self::Revoked => "enterprise HTTP policy is revoked",
            Self::ProfileMismatch => "enterprise token does not match the HTTP policy",
            Self::IdentitySnapshotMismatch => {
                "enterprise subject mapping does not match the HTTP policy"
            }
            Self::GenerationRollback => "enterprise HTTP policy generation did not advance",
            Self::CredentialUnavailable => "enterprise HTTP credential is unavailable",
        })
    }
}

impl std::error::Error for EnterpriseHttpPolicyError {}

/// Explicit deployment owner for using an exchanged enterprise token with the
/// public [`crate::ClientBuilder`] HTTP client.
///
/// The two deadlines must come from the embedding's independent, trusted IdP
/// and resource-AS metadata admission. They are not remote attestations. The
/// earlier deadline bounds every credential, so reconnecting cannot refresh
/// metadata or extend a token. Full profile equality binds scopes, resources,
/// registrations, cryptographic purposes, document identities and generations.
/// The identity snapshot must be selected from the embedding's current reviewed
/// mapping configuration, independently of the incoming token. Exact equality
/// prevents a grant from an older or different subject mapping from being bound
/// to the current policy, even when its authorization profile is unchanged.
///
/// This owner is deliberately not `Clone`: dropping it, revoking it or replacing
/// it revokes every credential it issued. Credential clones are leases, and
/// dropping one lease never revokes its siblings. A replacement requires a
/// newer deployment policy generation and nondecreasing metadata, key and
/// registration and identity snapshot generations. A changed identity snapshot
/// must advance its generation. The caller must reacquire a token under the new
/// profile; previously issued credentials cannot be reparented.
pub struct EnterpriseHttpPolicy {
    profile: EnterpriseProfile,
    identity_snapshot: EnterpriseIdentitySnapshotKey,
    metadata_valid_until: Instant,
    cancellation: McpRequestCancellation,
}

impl fmt::Debug for EnterpriseHttpPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnterpriseHttpPolicy")
            .field("generation", &self.profile.policy_generation())
            .field("revoked", &self.cancellation.is_cancel_requested())
            .finish_non_exhaustive()
    }
}

impl EnterpriseHttpPolicy {
    /// Opts in after local profile admission. Performs no network access and
    /// does not prove assertion acquisition or end-to-end EMA activation.
    pub fn new(
        profile: EnterpriseProfile,
        identity_snapshot: EnterpriseIdentitySnapshotKey,
        idp_metadata_valid_until: Instant,
        resource_as_metadata_valid_until: Instant,
    ) -> Result<Self, EnterpriseHttpPolicyError> {
        let metadata_valid_until = idp_metadata_valid_until.min(resource_as_metadata_valid_until);
        if Instant::now() >= metadata_valid_until {
            return Err(EnterpriseHttpPolicyError::StaleMetadata);
        }
        Ok(Self {
            profile,
            identity_snapshot,
            metadata_valid_until,
            cancellation: McpRequestCancellation::new(),
        })
    }

    /// The current immutable, locally admitted authorization overlay.
    pub fn profile(&self) -> &EnterpriseProfile {
        &self.profile
    }

    /// The independently selected current subject-mapping snapshot.
    pub fn identity_snapshot(&self) -> &EnterpriseIdentitySnapshotKey {
        &self.identity_snapshot
    }

    /// Earliest of the two original metadata freshness deadlines.
    pub fn metadata_valid_until(&self) -> Instant {
        self.metadata_valid_until
    }

    /// Irreversibly revokes this generation without affecting other policies.
    pub fn revoke(&self) {
        self.cancellation.cancel();
    }

    /// Replaces the whole admitted overlay and revokes all old credential
    /// leases. Validation happens first; a rejected replacement changes nothing.
    pub fn replace(
        &mut self,
        profile: EnterpriseProfile,
        identity_snapshot: EnterpriseIdentitySnapshotKey,
        idp_metadata_valid_until: Instant,
        resource_as_metadata_valid_until: Instant,
    ) -> Result<(), EnterpriseHttpPolicyError> {
        if profile.policy_generation() <= self.profile.policy_generation()
            || profile.idp_metadata_generation() < self.profile.idp_metadata_generation()
            || profile.resource_as_metadata_generation()
                < self.profile.resource_as_metadata_generation()
            || profile.idp_registration_generation() < self.profile.idp_registration_generation()
            || profile.resource_as_registration_generation()
                < self.profile.resource_as_registration_generation()
            || profile.aggregate_registration_generation()
                < self.profile.aggregate_registration_generation()
            || profile.oidc_key_generation() < self.profile.oidc_key_generation()
            || profile.id_jag_key_generation() < self.profile.id_jag_key_generation()
            || profile.id_jag_policy_generation() < self.profile.id_jag_policy_generation()
            || identity_snapshot.generation() < self.identity_snapshot.generation()
            || (identity_snapshot.generation() == self.identity_snapshot.generation()
                && identity_snapshot != self.identity_snapshot)
        {
            return Err(EnterpriseHttpPolicyError::GenerationRollback);
        }
        let replacement = Self::new(
            profile,
            identity_snapshot,
            idp_metadata_valid_until,
            resource_as_metadata_valid_until,
        )?;
        self.revoke();
        *self = replacement;
        Ok(())
    }

    pub(super) fn admit(
        &self,
        profile: &EnterpriseProfile,
        identity_snapshot: &EnterpriseIdentitySnapshotKey,
    ) -> Result<(), EnterpriseHttpPolicyError> {
        if self.cancellation.is_cancel_requested() {
            return Err(EnterpriseHttpPolicyError::Revoked);
        }
        if Instant::now() >= self.metadata_valid_until {
            return Err(EnterpriseHttpPolicyError::StaleMetadata);
        }
        if profile != &self.profile {
            return Err(EnterpriseHttpPolicyError::ProfileMismatch);
        }
        if identity_snapshot != &self.identity_snapshot {
            return Err(EnterpriseHttpPolicyError::IdentitySnapshotMismatch);
        }
        Ok(())
    }

    pub(super) fn cancellation(&self) -> &McpRequestCancellation {
        &self.cancellation
    }
}

impl Drop for EnterpriseHttpPolicy {
    fn drop(&mut self) {
        self.revoke();
    }
}

/// A policy may synthesize absent metadata, but must refuse a malformed
/// explicit declaration before any higher-level metadata normalization.
pub(crate) fn admits_caller_parameters(parameters: &serde_json::Value) -> bool {
    let Some(metadata) = parameters.get("_meta") else {
        return true;
    };
    let Some(metadata) = metadata.as_object() else {
        return false;
    };
    let Some(capabilities) = metadata.get(FINAL_CLIENT_CAPABILITIES_META_KEY) else {
        return true;
    };
    let Some(capabilities) = capabilities.as_object() else {
        return false;
    };
    let Some(extensions) = capabilities.get("extensions") else {
        return true;
    };
    let Some(extensions) = extensions.as_object() else {
        return false;
    };
    extensions
        .get(ENTERPRISE_AUTHORIZATION_EXTENSION_ID)
        .is_none_or(|settings| settings.as_object().is_some_and(serde_json::Map::is_empty))
}

/// Validates the *encoded* outgoing document, before returning a credential.
/// The strict decoder rejects duplicate keys at every depth. Control replies
/// and notifications do not carry request metadata in the final protocol.
pub(crate) fn admits_http_document(
    bytes: &[u8],
    method: &str,
    name: Option<&str>,
    request_routing_headers: bool,
) -> bool {
    if bytes.len() > crate::MAX_HTTP_EXECUTION_REQUEST_BYTES {
        return false;
    }
    let Ok(message) = decode_strict_jsonrpc_message(bytes, crate::MAX_HTTP_EXECUTION_REQUEST_BYTES)
    else {
        return false;
    };
    match message {
        JsonRpcMessage::Request(request) if request.id.is_some() => {
            if !request_routing_headers || request.method != method {
                return false;
            }
            let Some(parameters) = request
                .params
                .as_ref()
                .and_then(serde_json::Value::as_object)
            else {
                return false;
            };
            let Ok(expected_name) =
                crate::http_executor::request_name_header_value(&request.method, parameters)
            else {
                return false;
            };
            if expected_name.as_deref() != name {
                return false;
            }
            let Some(metadata) = parameters
                .get("_meta")
                .and_then(serde_json::Value::as_object)
            else {
                return false;
            };
            metadata
                .get(FINAL_PROTOCOL_VERSION_META_KEY)
                .and_then(serde_json::Value::as_str)
                == Some(FINAL_PROTOCOL_VERSION)
                && metadata
                    .get(FINAL_CLIENT_CAPABILITIES_META_KEY)
                    .and_then(|capabilities| capabilities.get("extensions"))
                    .and_then(|extensions| extensions.get(ENTERPRISE_AUTHORIZATION_EXTENSION_ID))
                    .and_then(serde_json::Value::as_object)
                    .is_some_and(serde_json::Map::is_empty)
        }
        JsonRpcMessage::Request(_) | JsonRpcMessage::Response(_) => {
            !request_routing_headers && name.is_none()
        }
    }
}
