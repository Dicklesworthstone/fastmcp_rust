//! Explicit, preregistered `private_key_jwt` client authentication.
//!
//! This development API imports an operator-trusted registration, binds it to
//! the exact external signer's public key and generations, and uses FND-09's
//! self-verifying RFC 7523 signing profile. It never accepts private-key bytes,
//! a caller-created assertion, a request-time audience, or a Basic fallback.
//!
//! Importing metadata is NOT independent proof of remote registration, KMS/HSM
//! custody, or deployment attestation. Those remain deployment obligations;
//! this source surface does not promote the complete AUTHX-02 security profile.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use asupersync::Cx;
use asupersync::types::Time;
use fastmcp_core::{CanonicalHttpUrl, draw_security_identifier};
use fastmcp_protocol::jose::{
    AdmittedRsaJwks, BoundedJwsClaims, ExternalRs256Signer,
    ExternalRs256SigningDeadline, JwsSigningProfile, Rs256SigningBinding,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    ClientCredentialsError, ClientCredentialsPlan, MachineAuthentication,
    MachineIssuerMetadata, OAuthDiscoveryPlan, PreparedMachineGrant,
    TrustedOAuthIssuer, check_context, decode_metadata, discovery_deadline,
    form, has, validate_array,
};

/// Fixed RFC 7523 assertion type; there is no caller-supplied alternative.
pub const JWT_BEARER_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const ASSERTION_LIFETIME: Duration = Duration::from_secs(60);
const SIGNING_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REGISTRATION_LIFETIME: Duration = Duration::from_secs(86_400);

/// Explicit audience policy, selected once when importing the registration.
/// Both variants use the exact imported spelling, never URL normalization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientAssertionAudience {
    Issuer,
    TokenEndpoint,
}

/// An immutable, finite-lived operator import, NOT an attestation receipt.
/// The JSON document contains `issuer`, `token_endpoint`, `resource`,
/// `client_id`, `grant_types`, `token_endpoint_auth_method`,
/// `token_endpoint_auth_signing_alg`, and a one-key public `jwks` object.
/// Client registration metadata and authorization-server metadata are checked
/// separately; server `*_supported` fields cannot replace registration fields.
pub struct PrivateKeyJwtRegistration {
    issuer: String,
    token_endpoint: String,
    resource: CanonicalHttpUrl,
    client_id: String,
    keys: AdmittedRsaJwks,
    binding: Rs256SigningBinding,
    generation: u64,
    valid_until: Instant,
    audience: ClientAssertionAudience,
}

#[derive(Deserialize)]
struct RegistrationDocument {
    issuer: String,
    token_endpoint: String,
    resource: String,
    client_id: String,
    grant_types: Vec<String>,
    token_endpoint_auth_method: String,
    token_endpoint_auth_signing_alg: String,
    jwks: Value,
}

impl PrivateKeyJwtRegistration {
    /// Imports out-of-band metadata under a host-selected validity and signer
    /// binding. Supply only independently trusted registration data, never a
    /// resource response, DCR response, portable CIMD document, or plugin input.
    /// Import validity is nonzero and at most one day. A new registration/key
    /// generation requires a new plan/client; existing clients are immutable.
    pub fn from_trusted_json(
        document: &[u8],
        generation: u64,
        valid_until: Instant,
        binding: Rs256SigningBinding,
        audience: ClientAssertionAudience,
    ) -> Result<Self, ClientCredentialsError> {
        let remaining = valid_until.checked_duration_since(Instant::now())
            .ok_or(ClientCredentialsError::InvalidRegistration)?;
        if generation == 0 || remaining.is_zero() || remaining > MAX_REGISTRATION_LIFETIME {
            return Err(ClientCredentialsError::InvalidRegistration);
        }
        let document: RegistrationDocument = decode_metadata(document)
            .map_err(|_| ClientCredentialsError::InvalidRegistration)?;
        validate_array(&document.grant_types)
            .map_err(|_| ClientCredentialsError::InvalidRegistration)?;
        if !has(&document.grant_types, "client_credentials")
            || document.token_endpoint_auth_method != "private_key_jwt"
            || document.token_endpoint_auth_signing_alg != "RS256"
            || document.client_id.is_empty() || document.client_id.len() > 4096
            || document.client_id.chars().any(char::is_control)
            || document.client_id.starts_with("https://")
            || document.client_id.starts_with("http://")
        {
            return Err(ClientCredentialsError::InvalidRegistration);
        }
        // Validate URLs without replacing their exact issuer/audience spelling.
        let _ = endpoint(&document.issuer)?;
        let _ = endpoint(&document.token_endpoint)?;
        let resource = CanonicalHttpUrl::parse(&document.resource)
            .map_err(|_| ClientCredentialsError::InvalidRegistration)?;
        if !resource.as_str().starts_with("https://") || resource.has_userinfo()
            || resource.fragment().is_some() || resource.as_str() != document.resource
        {
            return Err(ClientCredentialsError::InvalidRegistration);
        }
        let keys = AdmittedRsaJwks::from_json(
            &serde_json::to_vec(&document.jwks)
                .map_err(|_| ClientCredentialsError::InvalidRegistration)?,
        ).map_err(|_| ClientCredentialsError::InvalidRegistration)?;
        if keys.len() != 1 {
            return Err(ClientCredentialsError::InvalidRegistration);
        }
        Ok(Self {
            issuer: document.issuer, token_endpoint: document.token_endpoint,
            resource, client_id: document.client_id, keys, binding, generation,
            valid_until, audience,
        })
    }

    pub fn generation(&self) -> u64 { self.generation }
    pub fn valid_until(&self) -> Instant { self.valid_until }
    pub fn audience_policy(&self) -> ClientAssertionAudience { self.audience }

    fn audience(&self) -> &str {
        match self.audience {
            ClientAssertionAudience::Issuer => &self.issuer,
            ClientAssertionAudience::TokenEndpoint => &self.token_endpoint,
        }
    }
}

impl fmt::Debug for PrivateKeyJwtRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKeyJwtRegistration")
            .field("generation", &self.generation)
            .field("audience_policy", &self.audience)
            .field("signing_binding", &self.binding).finish_non_exhaustive()
    }
}

fn endpoint(value: &str) -> Result<CanonicalHttpUrl, ClientCredentialsError> {
    let url = CanonicalHttpUrl::parse(value)
        .map_err(|_| ClientCredentialsError::InvalidRegistration)?;
    if value.len() > 16 * 1024 || !url.as_str().starts_with("https://")
        || url.has_userinfo() || url.fragment().is_some() || url.query().is_some()
    {
        return Err(ClientCredentialsError::InvalidRegistration);
    }
    Ok(url)
}

pub(super) struct PrivateKeyJwtAuthentication {
    registration: PrivateKeyJwtRegistration,
    signer: Arc<ExternalRs256Signer>,
}

impl PrivateKeyJwtAuthentication {
    fn new(
        registration: PrivateKeyJwtRegistration,
        signer: Arc<ExternalRs256Signer>,
    ) -> Result<Self, ClientCredentialsError> {
        let public = signer.canonical_public_jwks()
            .map_err(|_| ClientCredentialsError::InvalidRegistration)?;
        let keys = AdmittedRsaJwks::from_json(public.as_bytes())
            .map_err(|_| ClientCredentialsError::InvalidRegistration)?;
        // Equality compares admitted RSA material AND kid, not kid alone.
        if signer.binding() != registration.binding || keys != registration.keys {
            return Err(ClientCredentialsError::InvalidRegistration);
        }
        let selected = Self { registration, signer };
        selected.check()?;
        Ok(selected)
    }

    pub(super) fn check(&self) -> Result<(), ClientCredentialsError> {
        if Instant::now() >= self.registration.valid_until {
            return Err(ClientCredentialsError::InvalidRegistration);
        }
        if self.signer.binding() != self.registration.binding {
            return Err(ClientCredentialsError::InvalidRegistration);
        }
        Ok(())
    }

    pub(super) fn valid_until(&self) -> Instant { self.registration.valid_until }

    pub(super) fn admit_metadata(
        &self,
        metadata: &MachineIssuerMetadata,
        bytes: &[u8],
    ) -> Result<(), ClientCredentialsError> {
        self.check()?;
        if metadata.issuer != self.registration.issuer
            || metadata.token_endpoint != self.registration.token_endpoint
        {
            return Err(ClientCredentialsError::InvalidRegistration);
        }
        #[derive(Deserialize)]
        struct SigningAlgorithms {
            token_endpoint_auth_signing_alg_values_supported: Vec<String>,
        }
        let algorithms: SigningAlgorithms = decode_metadata(bytes)
            .map_err(|_| ClientCredentialsError::UnsupportedAuthentication)?;
        validate_array(&algorithms.token_endpoint_auth_signing_alg_values_supported)
            .map_err(|_| ClientCredentialsError::UnsupportedAuthentication)?;
        if !has(&algorithms.token_endpoint_auth_signing_alg_values_supported, "RS256") {
            return Err(ClientCredentialsError::UnsupportedAuthentication);
        }
        Ok(())
    }

    pub(super) async fn prepare(
        &self,
        cx: &Cx,
        deadline: Time,
        client_id: &str,
        resource: &CanonicalHttpUrl,
        scopes: &[String],
    ) -> Result<PreparedMachineGrant, ClientCredentialsError> {
        self.check()?;
        check_context(cx, deadline)?;
        if client_id != self.registration.client_id || resource != &self.registration.resource {
            return Err(ClientCredentialsError::InvalidRegistration);
        }
        let started = SystemTime::now();
        let issued_at = started.duration_since(UNIX_EPOCH)
            .map_err(|_| ClientCredentialsError::AssertionSigning)?.as_secs();
        let lifetime = self.registration.valid_until.saturating_duration_since(Instant::now())
            .min(ASSERTION_LIFETIME).as_secs();
        if lifetime == 0 {
            return Err(ClientCredentialsError::InvalidRegistration);
        }
        let expires_at = issued_at.checked_add(lifetime)
            .filter(|expiry| *expiry <= i64::MAX as u64)
            .ok_or(ClientCredentialsError::AssertionSigning)?;
        let wall_expiry = UNIX_EPOCH.checked_add(Duration::from_secs(expires_at))
            .ok_or(ClientCredentialsError::AssertionSigning)?;
        let remaining = wall_expiry.duration_since(started)
            .map_err(|_| ClientCredentialsError::AssertionSigning)?;
        // A wall-clock rollback cannot extend the assertion's monotonic budget.
        let assertion_deadline = discovery_deadline(cx, remaining)?.min(deadline);
        let signer_deadline = discovery_deadline(cx, SIGNING_TIMEOUT)?.min(assertion_deadline);
        let allowance = Duration::from_nanos(signer_deadline.as_nanos().saturating_sub(cx.now().as_nanos()));
        let allowance = ExternalRs256SigningDeadline::new(allowance)
            .map_err(|_| ClientCredentialsError::AssertionSigning)?;
        let nonce = draw_security_identifier().map_err(|_| ClientCredentialsError::AssertionSigning)?;
        let jti = nonce.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let claims = BoundedJwsClaims::from_value(&json!({
            "iss": client_id, "sub": client_id, "aud": self.registration.audience(),
            "iat": issued_at, "exp": expires_at, "jti": jti,
        })).map_err(|_| ClientCredentialsError::AssertionSigning)?;
        // The outer acquisition guard supplies owner/caller cancellation. This
        // additional bound drives the external signing timeout independently.
        let candidate = super::within(cx, signer_deadline, async {
            Ok(self.signer.sign(cx, JwsSigningProfile::ClientAssertion, claims, allowance).await)
        }).await?.map_err(|_| ClientCredentialsError::AssertionSigning)?;
        self.check()?;
        check_context(cx, assertion_deadline)?;
        if SystemTime::now() >= wall_expiry || candidate.binding() != self.registration.binding {
            return Err(ClientCredentialsError::AssertionSigning);
        }
        let assertion = candidate.into_compact_jws();
        let body = form(&[
            ("grant_type", "client_credentials"), ("resource", resource.as_str()),
            ("scope", &scopes.join(" ")),
            ("client_assertion_type", JWT_BEARER_ASSERTION_TYPE),
            ("client_assertion", &assertion),
        ]).into_bytes();
        if body.len() > super::MAX_TOKEN_BYTES {
            return Err(ClientCredentialsError::RequestTooLarge);
        }
        // Pinned draft: sub carries client identity. No form client_id, secret,
        // Authorization header, caller-supplied JOSE field or compact assertion.
        Ok(PreparedMachineGrant { body, authorization: None, deadline: assertion_deadline })
    }
}

impl ClientCredentialsPlan {
    /// Selects private-key JWT authentication before discovery or signer access.
    /// The host retains responsibility for verifying the imported registration
    /// and the external backend's custody/attestation. No private key or shared
    /// secret enters this API. The issuer allowlist is independent of the import.
    ///
    /// Successful discovery returns the SAME ClientCredentialsClient used by
    /// core calls, Tasks and subscriptions, with shared single-flight renewal.
    /// No failure falls back to client_secret_basic or another algorithm.
    pub fn private_key_jwt(
        issuer: TrustedOAuthIssuer,
        registration: PrivateKeyJwtRegistration,
        signer: Arc<ExternalRs256Signer>,
        scopes: Vec<String>,
    ) -> Result<Self, ClientCredentialsError> {
        if issuer.identifier != registration.issuer {
            return Err(ClientCredentialsError::InvalidRegistration);
        }
        issuer.endpoint(&registration.token_endpoint)?;
        let discovery = OAuthDiscoveryPlan::new(
            registration.resource.clone(), vec![issuer], registration.client_id.clone(), scopes,
        )?;
        let authentication = PrivateKeyJwtAuthentication::new(registration, signer)?;
        Ok(Self {
            discovery,
            authentication: MachineAuthentication::PrivateKeyJwt(Arc::new(authentication)),
            maximum_lifetime: Duration::from_secs(3600),
            leeway: Duration::from_secs(30),
        })
    }
}
