//! Explicit validation and discard of optional signed ID-JAG disclosures.
//!
//! A trusted local policy fixes the exact IdP/resource-AS relationship, review
//! window and purpose of each permitted claim. This is not deployment
//! attestation. Only claim names and policy identity survive verification;
//! optional values cannot become identity, authorization or diagnostic facts.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fastmcp_core::{Sha256Digest, crypto::sha256_bounded};
use serde_json::{Map, Value};

use super::{EnterpriseVerificationError, ID_JAG_CLAIMS, numeric_date, validate_issuer};

/// A finite review window; expiry never inherits a JWT clock-skew allowance.
pub const MAX_DISCLOSURE_REVIEW_LIFETIME: Duration = Duration::from_hours(365 * 24);
const MAX_POLICY_ID_BYTES: usize = 128;
const MAX_PURPOSE_BYTES: usize = 256;
const MAX_POLICY_BYTES: usize = 4096;
const MAX_EMAIL_BYTES: usize = 1024;
const MAX_AUTHENTICATION_CONTEXT_BYTES: usize = 256;
const MAX_AUTHENTICATION_METHOD_BYTES: usize = 64;
const MAX_AUTHENTICATION_METHODS: usize = 16;

/// This revision implements four concrete schemas, all ValidateAndDiscard.
/// There is no arbitrary-claim escape hatch. Actor, RAR, subject-alias,
/// display-name, key-location and sender-constraining claims cannot be enabled.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum IdJagDisclosureClaim {
    Email,
    AuthenticationTime,
    AuthenticationContext,
    AuthenticationMethods,
}

impl IdJagDisclosureClaim {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::AuthenticationTime => "auth_time",
            Self::AuthenticationContext => "acr",
            Self::AuthenticationMethods => "amr",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "email" => Some(Self::Email),
            "auth_time" => Some(Self::AuthenticationTime),
            "acr" => Some(Self::AuthenticationContext),
            "amr" => Some(Self::AuthenticationMethods),
            _ => None,
        }
    }
}

/// Purpose is reviewed configuration, never a peer-supplied claim value.
pub struct IdJagDisclosureRule {
    pub claim: IdJagDisclosureClaim,
    pub purpose: String,
}

/// Explicit trusted input; importing it does not prove who reviewed it.
pub struct IdJagDisclosureConfiguration {
    pub policy_id: String,
    pub generation: u64,
    pub idp_issuer: String,
    pub resource_as_issuer: String,
    pub reviewed_at: SystemTime,
    pub review_expires_at: SystemTime,
    pub rules: Vec<IdJagDisclosureRule>,
}

/// Immutable allowlist tied to one exact issuer/audience and finite review.
/// Rules have one fixed disposition: validate their schema, then discard values.
pub struct IdJagDisclosurePolicy {
    policy_id: String,
    generation: u64,
    idp_issuer: String,
    resource_as_issuer: String,
    reviewed_at: SystemTime,
    review_expires_at: SystemTime,
    rules: BTreeMap<IdJagDisclosureClaim, String>,
    configuration_digest: Sha256Digest,
}

impl fmt::Debug for IdJagDisclosurePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("IdJagDisclosurePolicy").finish_non_exhaustive()
    }
}

impl IdJagDisclosurePolicy {
    pub fn from_trusted_configuration(
        configuration: IdJagDisclosureConfiguration,
    ) -> Result<Self, EnterpriseVerificationError> {
        let invalid = EnterpriseVerificationError::InvalidConfiguration;
        validate_issuer(&configuration.idp_issuer)?;
        validate_issuer(&configuration.resource_as_issuer)?;
        if configuration.generation == 0
            || !bounded_text(&configuration.policy_id, MAX_POLICY_ID_BYTES)
            || configuration.rules.len() > 4
            || configuration.reviewed_at < UNIX_EPOCH
            || configuration.review_expires_at <= configuration.reviewed_at
            || configuration.review_expires_at.duration_since(configuration.reviewed_at)
                .map_err(|_| invalid)? > MAX_DISCLOSURE_REVIEW_LIFETIME
        {
            return Err(invalid);
        }
        let mut rules = BTreeMap::new();
        for rule in configuration.rules {
            if !bounded_text(&rule.purpose, MAX_PURPOSE_BYTES)
                || rules.insert(rule.claim, rule.purpose).is_some()
            {
                return Err(invalid);
            }
        }
        // A versioned, length-framed encoding avoids ordering, concatenation
        // and equivalent JSON-spelling aliases without retaining peer values.
        let mut bytes = b"fastmcp/id-jag-disclosure/v1\0".to_vec();
        framed(&mut bytes, configuration.policy_id.as_bytes());
        bytes.extend_from_slice(&configuration.generation.to_be_bytes());
        framed(&mut bytes, configuration.idp_issuer.as_bytes());
        framed(&mut bytes, configuration.resource_as_issuer.as_bytes());
        for time in [configuration.reviewed_at, configuration.review_expires_at] {
            let duration = time.duration_since(UNIX_EPOCH).map_err(|_| invalid)?;
            bytes.extend_from_slice(&duration.as_secs().to_be_bytes());
            bytes.extend_from_slice(&duration.subsec_nanos().to_be_bytes());
        }
        bytes.extend_from_slice(&(rules.len() as u64).to_be_bytes());
        for (claim, purpose) in &rules {
            framed(&mut bytes, claim.name().as_bytes());
            framed(&mut bytes, purpose.as_bytes());
        }
        let configuration_digest = sha256_bounded(&bytes, MAX_POLICY_BYTES)
            .map_err(|_| invalid)?;
        Ok(Self {
            policy_id: configuration.policy_id,
            generation: configuration.generation,
            idp_issuer: configuration.idp_issuer,
            resource_as_issuer: configuration.resource_as_issuer,
            reviewed_at: configuration.reviewed_at,
            review_expires_at: configuration.review_expires_at,
            rules,
            configuration_digest,
        })
    }

    #[must_use]
    pub fn policy_id(&self) -> &str { &self.policy_id }
    #[must_use]
    pub const fn generation(&self) -> u64 { self.generation }
    #[must_use]
    pub const fn configuration_digest(&self) -> Sha256Digest { self.configuration_digest }
    #[must_use]
    pub const fn review_expires_at(&self) -> SystemTime { self.review_expires_at }

    pub(super) fn admit_context(
        &self,
        issuer: &str,
        audience: &str,
        now: SystemTime,
    ) -> Result<(), EnterpriseVerificationError> {
        if issuer != self.idp_issuer || audience != self.resource_as_issuer {
            return Err(EnterpriseVerificationError::BindingMismatch);
        }
        if now < self.reviewed_at || now >= self.review_expires_at {
            return Err(EnterpriseVerificationError::InvalidConfiguration);
        }
        Ok(())
    }

    pub(super) fn admit_claims(
        &self,
        claims: &Map<String, Value>,
    ) -> Result<IdJagDisclosureFacts, EnterpriseVerificationError> {
        let mut names = Vec::new();
        for (name, value) in claims {
            if ID_JAG_CLAIMS.contains(&name.as_str()) {
                continue;
            }
            let claim = IdJagDisclosureClaim::from_name(name)
                .filter(|claim| self.rules.contains_key(claim))
                .ok_or(EnterpriseVerificationError::InvalidClaims)?;
            validate_optional_claim(claim, value, claims)?;
            names.push(claim);
        }
        names.sort_unstable();
        Ok(IdJagDisclosureFacts {
            policy_id: self.policy_id.clone(),
            generation: self.generation,
            configuration_digest: self.configuration_digest,
            review_expires_at: self.review_expires_at,
            admitted_claims: names,
        })
    }
}

/// Policy identity and admitted claim names only, never their discarded values.
/// This does not assert deployment attestation, mapping or flow provenance.
#[derive(Clone)]
pub struct IdJagDisclosureFacts {
    policy_id: String,
    generation: u64,
    configuration_digest: Sha256Digest,
    review_expires_at: SystemTime,
    admitted_claims: Vec<IdJagDisclosureClaim>,
}

impl IdJagDisclosureFacts {
    #[must_use]
    pub fn policy_id(&self) -> &str { &self.policy_id }
    #[must_use]
    pub const fn generation(&self) -> u64 { self.generation }
    #[must_use]
    pub const fn configuration_digest(&self) -> Sha256Digest { self.configuration_digest }
    #[must_use]
    pub const fn review_expires_at(&self) -> SystemTime { self.review_expires_at }
    #[must_use]
    pub fn admitted_claims(&self) -> &[IdJagDisclosureClaim] { &self.admitted_claims }
}

impl fmt::Debug for IdJagDisclosureFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("IdJagDisclosureFacts").finish_non_exhaustive()
    }
}

fn framed(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn validate_optional_claim(
    claim: IdJagDisclosureClaim,
    value: &Value,
    claims: &Map<String, Value>,
) -> Result<(), EnterpriseVerificationError> {
    let invalid = EnterpriseVerificationError::InvalidClaims;
    match claim {
        IdJagDisclosureClaim::Email | IdJagDisclosureClaim::AuthenticationContext => {
            let maximum = if claim == IdJagDisclosureClaim::Email {
                MAX_EMAIL_BYTES
            } else {
                MAX_AUTHENTICATION_CONTEXT_BYTES
            };
            if !value.as_str().is_some_and(|value| bounded_text(value, maximum)) {
                return Err(invalid);
            }
        }
        IdJagDisclosureClaim::AuthenticationTime => {
            let authentication = numeric_date(value).map_err(|_| invalid)?;
            let issued = numeric_date(claims.get("iat").ok_or(invalid)?).map_err(|_| invalid)?;
            if authentication > issued { return Err(invalid); }
        }
        IdJagDisclosureClaim::AuthenticationMethods => {
            let methods = value.as_array().ok_or(invalid)?;
            if methods.is_empty() || methods.len() > MAX_AUTHENTICATION_METHODS {
                return Err(invalid);
            }
            // At most sixteen bounded strings: no cloning of their values.
            let mut unique = std::collections::BTreeSet::new();
            for method in methods {
                let method = method.as_str().ok_or(invalid)?;
                if !bounded_text(method, MAX_AUTHENTICATION_METHOD_BYTES) || !unique.insert(method) {
                    return Err(invalid);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
