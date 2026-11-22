//! Enterprise authorization at the protected MCP resource boundary.
//!
//! An explicit owner admits the two authorization-server metadata overlays.
//! Each MCP request must independently declare the exact official extension
//! with empty settings. A provisioned or managed JWT verifier still performs
//! the actual access-token signature, type, issuer, audience and expiry checks;
//! neither an extension declaration nor metadata is token authority. ID Tokens
//! and ID-JAGs cannot substitute for an RFC 9068 access token.
//!
//! This is the resource-side JWT subset, not an assertion-acquisition, token-
//! exchange, SAML, built-in issuer or durable-deployment implementation. Metadata
//! provenance and the match between this configured resource and the listener's
//! public endpoint remain trusted deployment inputs. Guarded key refresh uses
//! an independently configured trusted source; metadata cannot select it. No
//! RPC extension descriptor is added to `server/discover`.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, RwLock, Weak};
use std::time::Instant;

use fastmcp_core::runtime::{ProcessBoundToken, ProcessGenerationGuard};
use fastmcp_core::{
    AuthContext, CanonicalHttpUrl, CanonicalResourceId, McpContext, McpError, McpErrorCode,
    McpRequestCancellation, McpResult, Sha256Digest, sha256_bounded,
};
use fastmcp_protocol::{
    FINAL_CLIENT_CAPABILITIES_META_KEY, FINAL_PROTOCOL_VERSION, SecurityDocumentKind,
    admit_security_document_object,
};
use serde_json::{Map, Value};

use super::{AuthFuture, AuthProvider, AuthRequest, TokenAuthProvider};
use crate::providers::{
    GuardedJwtResourceVerifier, JwtResourceVerifier, ManagedJwtResourceVerifier,
};

/// The official authentication-profile identifier; its settings are exactly `{}`.
pub const ENTERPRISE_AUTHORIZATION_EXTENSION_ID: &str =
    "io.modelcontextprotocol/enterprise-managed-authorization";
const PROTOCOL_VERSION_META_KEY: &str = "io.modelcontextprotocol/protocolVersion";
const ID_JAG_PROFILE: &str = "urn:ietf:params:oauth:grant-profile:id-jag";
const ID_JAG_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id-jag";
const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const MAX_IDENTIFIER_BYTES: usize = 4096;
const MAX_METADATA_VALUES: usize = 64;
const OWNER_DOMAIN: &[u8] = b"fastmcp/enterprise-resource-owner/v1\0";

/// Trusted administrative bindings, never obtained from an MCP request.
/// Issuers retain their exact spelling. Metadata must match both expected
/// issuer/endpoint pairs. Generations are nonzero and replacement is monotonic.
#[derive(Clone)]
pub struct EnterpriseResourceConfiguration {
    pub idp_issuer: String,
    pub idp_token_endpoint: String,
    pub resource_as_issuer: String,
    pub resource_as_token_endpoint: String,
    pub resource: CanonicalResourceId,
    pub policy_generation: u64,
    pub idp_metadata_generation: u64,
    pub resource_as_metadata_generation: u64,
}

impl fmt::Debug for EnterpriseResourceConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnterpriseResourceConfiguration")
            .field("policy_generation", &self.policy_generation)
            .field("idp_metadata_generation", &self.idp_metadata_generation)
            .field(
                "resource_as_metadata_generation",
                &self.resource_as_metadata_generation,
            )
            .finish_non_exhaustive()
    }
}

/// Bounded diagnostics never retain metadata, credentials or identity values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterpriseResourceError {
    InvalidConfiguration,
    InvalidMetadata,
    MetadataMismatch,
    UnsupportedGrant,
    StaleMetadata,
    GenerationRollback,
    VerifierMismatch,
    Unavailable,
}

impl fmt::Display for EnterpriseResourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid enterprise resource configuration",
            Self::InvalidMetadata => "invalid enterprise authorization metadata",
            Self::MetadataMismatch => "enterprise metadata differs from trusted configuration",
            Self::UnsupportedGrant => "enterprise authorization metadata is incomplete",
            Self::StaleMetadata => "enterprise authorization metadata is stale",
            Self::GenerationRollback => "enterprise resource generation did not advance",
            Self::VerifierMismatch => "access-token verifier differs from enterprise resource",
            Self::Unavailable => "enterprise resource policy is unavailable",
        })
    }
}

impl std::error::Error for EnterpriseResourceError {}

struct PolicySnapshot {
    configuration: EnterpriseResourceConfiguration,
    documents: [Sha256Digest; 2],
    metadata_valid_until: Instant,
    cancellation: McpRequestCancellation,
    process: ProcessBoundToken,
}

impl PolicySnapshot {
    fn admit(
        configuration: EnterpriseResourceConfiguration,
        idp_metadata: &[u8],
        resource_as_metadata: &[u8],
        idp_metadata_valid_until: Instant,
        resource_as_metadata_valid_until: Instant,
        process: ProcessBoundToken,
    ) -> Result<Self, EnterpriseResourceError> {
        process
            .verify()
            .map_err(|_| EnterpriseResourceError::Unavailable)?;
        for url in [
            configuration.idp_issuer.as_str(),
            configuration.idp_token_endpoint.as_str(),
            configuration.resource_as_issuer.as_str(),
            configuration.resource_as_token_endpoint.as_str(),
        ] {
            admit_https_identifier(url, true)?;
        }
        admit_https_identifier(configuration.resource.as_str(), false)?;
        if configuration.idp_issuer == configuration.resource_as_issuer
            || [
                configuration.policy_generation,
                configuration.idp_metadata_generation,
                configuration.resource_as_metadata_generation,
            ]
            .contains(&0)
        {
            return Err(EnterpriseResourceError::InvalidConfiguration);
        }
        let idp = admit_security_document_object(
            SecurityDocumentKind::OidcProviderMetadata,
            idp_metadata,
        )
        .map_err(|_| EnterpriseResourceError::InvalidMetadata)?;
        let resource_as = admit_security_document_object(
            SecurityDocumentKind::AuthorizationServerMetadata,
            resource_as_metadata,
        )
        .map_err(|_| EnterpriseResourceError::InvalidMetadata)?;
        for (document, issuer, endpoint) in [
            (
                &idp,
                configuration.idp_issuer.as_str(),
                configuration.idp_token_endpoint.as_str(),
            ),
            (
                &resource_as,
                configuration.resource_as_issuer.as_str(),
                configuration.resource_as_token_endpoint.as_str(),
            ),
        ] {
            if document.get("issuer").and_then(Value::as_str) != Some(issuer)
                || document.get("token_endpoint").and_then(Value::as_str) != Some(endpoint)
            {
                return Err(EnterpriseResourceError::MetadataMismatch);
            }
        }
        require_advertisement(&idp, "grant_types_supported", TOKEN_EXCHANGE)?;
        require_advertisement(
            &idp,
            "identity_chaining_requested_token_types_supported",
            ID_JAG_TOKEN_TYPE,
        )?;
        require_advertisement(
            &resource_as,
            "authorization_grant_profiles_supported",
            ID_JAG_PROFILE,
        )?;
        require_advertisement(&resource_as, "grant_types_supported", JWT_BEARER)?;
        let documents = [
            sha256_bounded(
                idp_metadata,
                SecurityDocumentKind::OidcProviderMetadata.byte_limit(),
            )
            .map_err(|_| EnterpriseResourceError::InvalidMetadata)?,
            sha256_bounded(
                resource_as_metadata,
                SecurityDocumentKind::AuthorizationServerMetadata.byte_limit(),
            )
            .map_err(|_| EnterpriseResourceError::InvalidMetadata)?,
        ];
        let metadata_valid_until = idp_metadata_valid_until.min(resource_as_metadata_valid_until);
        if Instant::now() >= metadata_valid_until {
            return Err(EnterpriseResourceError::StaleMetadata);
        }
        process
            .verify()
            .map_err(|_| EnterpriseResourceError::Unavailable)?;
        Ok(Self {
            configuration,
            documents,
            metadata_valid_until,
            cancellation: McpRequestCancellation::new(),
            process,
        })
    }

    fn check(&self) -> Result<(), EnterpriseResourceError> {
        self.process
            .verify()
            .map_err(|_| EnterpriseResourceError::Unavailable)?;
        if self.cancellation.is_cancel_requested() {
            return Err(EnterpriseResourceError::Unavailable);
        }
        if Instant::now() >= self.metadata_valid_until {
            return Err(EnterpriseResourceError::StaleMetadata);
        }
        Ok(())
    }
}

/// Administrative owner for one live resource-side enterprise policy.
///
/// Keep this owner alive while its providers are installed. Revocation, drop or
/// successful replacement invalidates all previously admitted authentication
/// leases. Providers take a fresh policy snapshot on every request; they never
/// carry extension activation from another request, session or connection.
/// Replacement can refresh metadata but cannot rebind the protected resource
/// or its token issuer; that requires another explicitly configured provider.
/// The verified issuer/resource/client/subject owner remains stable across
/// refresh, so current authorization can still reach existing owned Tasks.
pub struct EnterpriseResourcePolicy {
    current: Arc<PolicySnapshot>,
    shared: Arc<RwLock<Arc<PolicySnapshot>>>,
}

impl fmt::Debug for EnterpriseResourcePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnterpriseResourcePolicy")
            .field("configuration", &self.current.configuration)
            .field("revoked", &self.current.cancellation.is_cancel_requested())
            .finish_non_exhaustive()
    }
}

impl EnterpriseResourcePolicy {
    /// Imports bounded, duplicate-free public AS metadata already obtained and
    /// trusted by the deployment. The two deadlines preserve that admission's
    /// original monotonic freshness bounds; creating a provider cannot renew it.
    pub fn new(
        configuration: EnterpriseResourceConfiguration,
        idp_metadata: &[u8],
        resource_as_metadata: &[u8],
        idp_metadata_valid_until: Instant,
        resource_as_metadata_valid_until: Instant,
    ) -> Result<Self, EnterpriseResourceError> {
        let process = ProcessGenerationGuard::install()
            .map_err(|_| EnterpriseResourceError::Unavailable)?
            .token();
        let current = Arc::new(PolicySnapshot::admit(
            configuration,
            idp_metadata,
            resource_as_metadata,
            idp_metadata_valid_until,
            resource_as_metadata_valid_until,
            process,
        )?);
        Ok(Self {
            shared: Arc::new(RwLock::new(Arc::clone(&current))),
            current,
        })
    }

    /// Installs only an access-token verifier with exactly this issuer/resource
    /// pair. Its provisioned keys and optional accepted-audience mapping remain
    /// independent of the authorization metadata and cannot be supplied by it.
    pub fn provider(
        &self,
        verifier: JwtResourceVerifier,
    ) -> Result<EnterpriseAuthProvider, EnterpriseResourceError> {
        self.admit_verifier_binding(verifier.issuer(), verifier.resource())?;
        Ok(EnterpriseAuthProvider {
            policy: Arc::downgrade(&self.shared),
            process: self.current.process,
            verifier: TokenAuthProvider::new(verifier),
        })
    }

    /// Installs a verifier whose administratively managed keys retain their
    /// original hard expiry and live rotation/revocation guards. The exact
    /// issuer/resource binding must match this policy. Metadata supplies no
    /// keys and cannot renew their lifetime.
    pub fn managed_provider(
        &self,
        verifier: ManagedJwtResourceVerifier,
    ) -> Result<EnterpriseAuthProvider, EnterpriseResourceError> {
        self.admit_verifier_binding(verifier.issuer(), verifier.resource())?;
        Ok(EnterpriseAuthProvider {
            policy: Arc::downgrade(&self.shared),
            process: self.current.process,
            verifier: TokenAuthProvider::new(verifier),
        })
    }

    /// Installs automatic asynchronous key refresh from an independently
    /// configured guarded HTTPS source with its own roots, freshness, backoff
    /// and capacity policy. Request declarations are admitted before any fetch;
    /// metadata replacement or revocation during refresh prevents final
    /// authentication. The synchronous path uses installed fresh keys without
    /// performing I/O.
    pub fn guarded_provider(
        &self,
        verifier: GuardedJwtResourceVerifier,
    ) -> Result<EnterpriseAuthProvider, EnterpriseResourceError> {
        self.admit_verifier_binding(verifier.issuer(), verifier.resource())?;
        Ok(EnterpriseAuthProvider {
            policy: Arc::downgrade(&self.shared),
            process: self.current.process,
            verifier: TokenAuthProvider::new(verifier),
        })
    }

    fn admit_verifier_binding(
        &self,
        issuer: &str,
        resource: &str,
    ) -> Result<(), EnterpriseResourceError> {
        self.current.check()?;
        if issuer != self.current.configuration.resource_as_issuer
            || resource != self.current.configuration.resource.as_str()
        {
            return Err(EnterpriseResourceError::VerifierMismatch);
        }
        Ok(())
    }

    /// Stops new admission and invalidates retained facts without contacting an
    /// issuer or cancelling work that has already completed.
    pub fn revoke(&self) {
        // Process-bound facts already fail closed after fork. Avoid notifying
        // inherited cancellation waiters, including through this owner's Drop.
        if self.current.process.verify().is_ok() {
            self.current.cancellation.cancel();
        }
    }

    /// Atomically replaces the metadata snapshot. Validate first, then publish
    /// once and revoke old leases before returning. Rejection changes nothing.
    /// Every replacement advances policy generation; changing either metadata
    /// document must also advance that document's generation. No generation may
    /// decrease, and the issuer/resource binding cannot change in place.
    pub fn replace(
        &mut self,
        configuration: EnterpriseResourceConfiguration,
        idp_metadata: &[u8],
        resource_as_metadata: &[u8],
        idp_metadata_valid_until: Instant,
        resource_as_metadata_valid_until: Instant,
    ) -> Result<(), EnterpriseResourceError> {
        let candidate = Arc::new(PolicySnapshot::admit(
            configuration,
            idp_metadata,
            resource_as_metadata,
            idp_metadata_valid_until,
            resource_as_metadata_valid_until,
            self.current.process,
        )?);
        let old = &self.current.configuration;
        let next = &candidate.configuration;
        if old.resource != next.resource || old.resource_as_issuer != next.resource_as_issuer {
            return Err(EnterpriseResourceError::VerifierMismatch);
        }
        if next.policy_generation <= old.policy_generation
            || next.idp_metadata_generation < old.idp_metadata_generation
            || next.resource_as_metadata_generation < old.resource_as_metadata_generation
            || (candidate.documents[0] != self.current.documents[0]
                && next.idp_metadata_generation == old.idp_metadata_generation)
            || (candidate.documents[1] != self.current.documents[1]
                && next.resource_as_metadata_generation == old.resource_as_metadata_generation)
        {
            return Err(EnterpriseResourceError::GenerationRollback);
        }
        candidate
            .process
            .verify()
            .map_err(|_| EnterpriseResourceError::Unavailable)?;
        let mut active = self
            .shared
            .write()
            .map_err(|_| EnterpriseResourceError::Unavailable)?;
        candidate
            .process
            .verify()
            .map_err(|_| EnterpriseResourceError::Unavailable)?;
        *active = Arc::clone(&candidate);
        let retired = std::mem::replace(&mut self.current, candidate);
        drop(active);
        retired.cancellation.cancel();
        Ok(())
    }
}

impl Drop for EnterpriseResourcePolicy {
    fn drop(&mut self) {
        self.revoke();
    }
}

/// Install using the ordinary `ServerBuilder::auth_provider` hook. Clones share
/// the policy owner's revocation but cannot keep that owner alive. There is no
/// fallback to a different profile when settings, metadata or a token fail.
#[derive(Clone)]
pub struct EnterpriseAuthProvider {
    policy: Weak<RwLock<Arc<PolicySnapshot>>>,
    process: ProcessBoundToken,
    verifier: TokenAuthProvider,
}

impl fmt::Debug for EnterpriseAuthProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnterpriseAuthProvider")
            .finish_non_exhaustive()
    }
}

impl EnterpriseAuthProvider {
    fn snapshot(&self) -> McpResult<Arc<PolicySnapshot>> {
        self.process.verify().map_err(|_| denied())?;
        let policy = self.policy.upgrade().ok_or_else(denied)?;
        let snapshot = Arc::clone(&policy.read().map_err(|_| denied())?);
        snapshot.check().map_err(|_| denied())?;
        Ok(snapshot)
    }

    fn finish(&self, snapshot: &Arc<PolicySnapshot>, auth: AuthContext) -> McpResult<AuthContext> {
        self.process.verify().map_err(|_| denied())?;
        let policy = self.policy.upgrade().ok_or_else(denied)?;
        let current = policy.read().map_err(|_| denied())?;
        if !Arc::ptr_eq(&current, snapshot) {
            return Err(denied());
        }
        snapshot.check().map_err(|_| denied())?;
        let owner = auth.session_owner().ok_or_else(denied)?;
        // The underlying verifier binds issuer/resource/client/subject and any
        // explicit audience-mapping identity. Metadata/key generations are
        // authorization freshness, not durable owner identity. Changing them
        // retires the old lease without stranding an otherwise authorized Task.
        let mut binding = Vec::with_capacity(OWNER_DOMAIN.len() + 32);
        binding.extend_from_slice(OWNER_DOMAIN);
        binding.extend_from_slice(owner.as_bytes());
        let owner = sha256_bounded(&binding, OWNER_DOMAIN.len() + 32).map_err(|_| denied())?;
        let auth = auth
            .with_session_owner(owner)
            .with_verification_valid_until(snapshot.metadata_valid_until)
            .with_verification_cancellation(snapshot.cancellation.clone());
        if !auth.verification_is_current() {
            return Err(denied());
        }
        Ok(auth)
    }
}

impl AuthProvider for EnterpriseAuthProvider {
    fn authenticate(&self, ctx: &McpContext, request: AuthRequest<'_>) -> McpResult<AuthContext> {
        let snapshot = self.snapshot()?;
        admit_request(request)?;
        let auth = self.verifier.authenticate(ctx, request)?;
        self.finish(&snapshot, auth)
    }

    fn authenticate_async<'a>(
        &'a self,
        ctx: &'a McpContext,
        request: AuthRequest<'a>,
    ) -> AuthFuture<'a> {
        Box::pin(async move {
            let snapshot = self.snapshot()?;
            admit_request(request)?;
            let auth = self.verifier.authenticate_async(ctx, request).await?;
            self.finish(&snapshot, auth)
        })
    }
}

fn denied() -> McpError {
    McpError::new(
        McpErrorCode::ResourceForbidden,
        "Enterprise authorization failed",
    )
}

fn admit_request(request: AuthRequest<'_>) -> McpResult<()> {
    // Only native Authorization is accepted, even if this provider is directly
    // installed on another transport. The shared token provider enforces the
    // credential grammar and refuses coexisting in-band sources.
    if request.transport_authorization.is_none() || request.has_in_band_credential_source() {
        return Err(denied());
    }
    // Final cancellation is a control notification, not a capability-bearing
    // request. The server's typed notification/ownership gate still admits its
    // shape and target; this exception does not activate any profile or method.
    if request.method == fastmcp_protocol::methods::NOTIFICATIONS_CANCELLED {
        return Ok(());
    }
    let metadata = request
        .params
        .and_then(|params| params.get("_meta"))
        .and_then(Value::as_object)
        .ok_or_else(denied)?;
    if metadata
        .get(PROTOCOL_VERSION_META_KEY)
        .and_then(Value::as_str)
        != Some(FINAL_PROTOCOL_VERSION)
    {
        return Err(denied());
    }
    let settings = metadata
        .get(FINAL_CLIENT_CAPABILITIES_META_KEY)
        .and_then(Value::as_object)
        .and_then(|capabilities| capabilities.get("extensions"))
        .and_then(Value::as_object)
        .and_then(|extensions| extensions.get(ENTERPRISE_AUTHORIZATION_EXTENSION_ID));
    if settings.is_some_and(|settings| settings.as_object().is_some_and(Map::is_empty)) {
        Ok(())
    } else {
        Err(denied())
    }
}

fn admit_https_identifier(value: &str, query_free: bool) -> Result<(), EnterpriseResourceError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(EnterpriseResourceError::InvalidConfiguration);
    }
    let url = CanonicalHttpUrl::parse(value)
        .map_err(|_| EnterpriseResourceError::InvalidConfiguration)?;
    if url.scheme() != "https"
        || url.has_userinfo()
        || url.has_syntax_violation()
        || url.fragment().is_some()
        || (query_free && url.query().is_some())
    {
        return Err(EnterpriseResourceError::InvalidConfiguration);
    }
    Ok(())
}

fn require_advertisement(
    metadata: &Map<String, Value>,
    field: &str,
    required: &str,
) -> Result<(), EnterpriseResourceError> {
    let values = metadata
        .get(field)
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty() && values.len() <= MAX_METADATA_VALUES)
        .ok_or(EnterpriseResourceError::InvalidMetadata)?;
    let mut admitted = BTreeSet::new();
    for value in values {
        let value = value
            .as_str()
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= MAX_IDENTIFIER_BYTES
                    && !value.chars().any(char::is_control)
            })
            .ok_or(EnterpriseResourceError::InvalidMetadata)?;
        if !admitted.insert(value) {
            return Err(EnterpriseResourceError::InvalidMetadata);
        }
    }
    if admitted.contains(required) {
        Ok(())
    } else {
        Err(EnterpriseResourceError::UnsupportedGrant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::JwtResourcePolicy;
    use crate::providers::jwt_resource::tests as jwt;
    use serde_json::json;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn configuration(generation: u64) -> EnterpriseResourceConfiguration {
        let endpoint = CanonicalHttpUrl::parse("https://tools.example/mcp").unwrap();
        EnterpriseResourceConfiguration {
            idp_issuer: "https://idp.example".to_owned(),
            idp_token_endpoint: "https://idp.example/token".to_owned(),
            resource_as_issuer: "https://issuer.example".to_owned(),
            resource_as_token_endpoint: "https://issuer.example/token".to_owned(),
            resource: CanonicalResourceId::parse_for_endpoint(
                endpoint.as_str(),
                &endpoint,
                fastmcp_core::CanonicalResourceIdPolicy::default(),
            )
            .unwrap(),
            policy_generation: generation,
            idp_metadata_generation: generation,
            resource_as_metadata_generation: generation,
        }
    }

    fn documents() -> [Vec<u8>; 2] {
        [
            serde_json::to_vec(&json!({
                "issuer":"https://idp.example", "token_endpoint":"https://idp.example/token",
                "grant_types_supported":[TOKEN_EXCHANGE],
                "identity_chaining_requested_token_types_supported":[ID_JAG_TOKEN_TYPE]
            }))
            .unwrap(),
            serde_json::to_vec(&json!({
                "issuer":"https://issuer.example", "token_endpoint":"https://issuer.example/token",
                "authorization_grant_profiles_supported":[ID_JAG_PROFILE],
                "grant_types_supported":[JWT_BEARER]
            }))
            .unwrap(),
        ]
    }

    fn policy() -> EnterpriseResourcePolicy {
        let documents = documents();
        let deadline = Instant::now() + Duration::from_secs(120);
        EnterpriseResourcePolicy::new(
            configuration(1),
            &documents[0],
            &documents[1],
            deadline,
            deadline,
        )
        .unwrap()
    }

    fn verifier() -> JwtResourceVerifier {
        JwtResourceVerifier::new(
            JwtResourcePolicy::new(
                "https://issuer.example",
                "https://tools.example/mcp",
                Duration::from_secs(3600),
                Duration::ZERO,
            )
            .unwrap(),
            &jwt::jwks("one"),
        )
        .unwrap()
    }

    fn params() -> Value {
        json!({"_meta":{
            PROTOCOL_VERSION_META_KEY:FINAL_PROTOCOL_VERSION,
            FINAL_CLIENT_CAPABILITIES_META_KEY:{"extensions":{
                ENTERPRISE_AUTHORIZATION_EXTENSION_ID:{}, "com.example/unrelated":{}
            }}
        }})
    }

    fn request<'a>(params: &'a Value, authorization: &'a str) -> AuthRequest<'a> {
        AuthRequest {
            method: "tools/list",
            params: Some(params),
            transport_authorization: Some(authorization),
            request_id: 1,
        }
    }

    fn context() -> McpContext {
        McpContext::new(asupersync::Cx::for_testing(), 1)
    }

    fn token() -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        format!(
            "Bearer {}",
            jwt::sign(&jwt::header(), &jwt::claims(now)).token
        )
    }

    #[test]
    fn enterprise_resource_admits_signed_access_with_exact_request_overlay() {
        let owner = policy();
        let provider = owner.provider(verifier()).unwrap();
        let token = token();
        let params = params();
        let admitted = provider
            .authenticate(&context(), request(&params, &token))
            .unwrap();
        assert_eq!(admitted.subject.as_deref(), Some("alice"));
        assert_eq!(admitted.scopes, vec!["read", "write"]);
        assert_eq!(
            admitted.claims.as_ref().unwrap()["aud"],
            "https://tools.example/mcp"
        );
        assert!(admitted.verification_is_current());
        assert!(admitted.verification_valid_until().unwrap() < owner.current.metadata_valid_until);
        let again = provider
            .authenticate(&context(), request(&params, &token))
            .unwrap();
        assert_eq!(admitted.session_owner(), again.session_owner());
        assert!(!format!("{owner:?} {provider:?} {admitted:?}").contains("alice"));
        assert!(!format!("{owner:?}").contains("idp.example"));
    }

    #[test]
    fn enterprise_resource_requires_fresh_exact_settings_without_remembering_requests() {
        let owner = policy();
        let provider = owner.provider(verifier()).unwrap();
        let token = token();
        let baseline = params();
        let before = provider
            .authenticate(&context(), request(&baseline, &token))
            .unwrap();
        for settings in [Value::Null, json!(true), json!([]), json!({"enabled":true})] {
            let mut changed = baseline.clone();
            changed["_meta"][FINAL_CLIENT_CAPABILITIES_META_KEY]["extensions"]
                [ENTERPRISE_AUTHORIZATION_EXTENSION_ID] = settings;
            assert!(
                provider
                    .authenticate(&context(), request(&changed, &token))
                    .is_err()
            );
            assert!(before.verification_is_current());
        }
        for changed in [
            json!({}),
            json!({"_meta":{PROTOCOL_VERSION_META_KEY:FINAL_PROTOCOL_VERSION,
                FINAL_CLIENT_CAPABILITIES_META_KEY:{"extensions":{"com.example/enterprise":{}}}}}),
            json!({"_meta":{PROTOCOL_VERSION_META_KEY:"2024-11-05",
                FINAL_CLIENT_CAPABILITIES_META_KEY:{"extensions":{ENTERPRISE_AUTHORIZATION_EXTENSION_ID:{}}}}}),
        ] {
            assert!(
                provider
                    .authenticate(&context(), request(&changed, &token))
                    .is_err()
            );
        }
        let mut in_band = baseline.clone();
        in_band["authorization"] = json!(token);
        assert!(
            provider
                .authenticate(&context(), request(&in_band, &token))
                .is_err()
        );
        let mut missing_header = request(&baseline, &token);
        missing_header.transport_authorization = None;
        assert!(provider.authenticate(&context(), missing_header).is_err());
        let after = provider
            .authenticate(&context(), request(&baseline, &token))
            .unwrap();
        assert_eq!(before.session_owner(), after.session_owner());
    }

    #[test]
    fn enterprise_resource_metadata_rejects_one_sided_duplicate_and_mismatched_inputs() {
        let baseline = documents();
        let deadline = Instant::now() + Duration::from_secs(60);
        for (side, field) in [
            (0, "grant_types_supported"),
            (0, "identity_chaining_requested_token_types_supported"),
            (1, "authorization_grant_profiles_supported"),
            (1, "grant_types_supported"),
        ] {
            let mut changed: Value = serde_json::from_slice(&baseline[side]).unwrap();
            changed.as_object_mut().unwrap().remove(field);
            let changed = serde_json::to_vec(&changed).unwrap();
            let mut documents = baseline.clone();
            documents[side] = changed;
            assert!(
                EnterpriseResourcePolicy::new(
                    configuration(1),
                    &documents[0],
                    &documents[1],
                    deadline,
                    deadline
                )
                .is_err()
            );
        }
        let duplicate = br#"{"issuer":"https://idp.example","issuer":"https://idp.example"}"#;
        assert_eq!(
            EnterpriseResourcePolicy::new(
                configuration(1),
                duplicate,
                &baseline[1],
                deadline,
                deadline
            )
            .unwrap_err(),
            EnterpriseResourceError::InvalidMetadata
        );
        let mut mismatch = configuration(1);
        mismatch.resource_as_issuer = "https://other.example".to_owned();
        assert_eq!(
            EnterpriseResourcePolicy::new(mismatch, &baseline[0], &baseline[1], deadline, deadline)
                .unwrap_err(),
            EnterpriseResourceError::MetadataMismatch
        );
        assert_eq!(
            EnterpriseResourcePolicy::new(
                configuration(1),
                &baseline[0],
                &baseline[1],
                Instant::now(),
                deadline
            )
            .unwrap_err(),
            EnterpriseResourceError::StaleMetadata
        );
        assert!(
            EnterpriseResourcePolicy::new(
                configuration(1),
                &baseline[0],
                &baseline[1],
                deadline,
                deadline
            )
            .is_ok()
        );
    }

    #[test]
    fn enterprise_resource_rejects_identity_assertions_wrong_issuer_and_wrong_resource() {
        let owner = policy();
        let provider = owner.provider(verifier()).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let params = params();
        for typ in ["JWT", "oauth-id-jag+jwt", "id_token"] {
            let mut header = jwt::header();
            header["typ"] = json!(typ);
            let token = format!("Bearer {}", jwt::sign(&header, &jwt::claims(now)).token);
            assert!(
                provider
                    .authenticate(&context(), request(&params, &token))
                    .is_err()
            );
        }
        for (field, value) in [
            ("iss", "https://idp.example"),
            ("aud", "https://other.example/mcp"),
        ] {
            let mut claims = jwt::claims(now);
            claims[field] = json!(value);
            let token = format!("Bearer {}", jwt::sign(&jwt::header(), &claims).token);
            assert!(
                provider
                    .authenticate(&context(), request(&params, &token))
                    .is_err()
            );
        }
        let wrong_verifier = JwtResourceVerifier::new(
            JwtResourcePolicy::new(
                "https://idp.example",
                "https://tools.example/mcp",
                Duration::from_secs(3600),
                Duration::ZERO,
            )
            .unwrap(),
            &jwt::jwks("one"),
        )
        .unwrap();
        assert_eq!(
            owner.provider(wrong_verifier).unwrap_err(),
            EnterpriseResourceError::VerifierMismatch
        );
        assert!(
            provider
                .authenticate(&context(), request(&params, &token()))
                .is_ok()
        );
    }

    #[test]
    fn enterprise_resource_replacement_revokes_old_facts_and_preserves_rejected_updates() {
        let mut owner = policy();
        let provider = owner.provider(verifier()).unwrap();
        let params = params();
        let token = token();
        let before = provider
            .authenticate(&context(), request(&params, &token))
            .unwrap();
        let in_flight = provider.snapshot().unwrap();
        let documents = documents();
        let deadline = Instant::now() + Duration::from_secs(20);
        assert_eq!(
            owner.replace(
                configuration(1),
                &documents[0],
                &documents[1],
                deadline,
                deadline
            ),
            Err(EnterpriseResourceError::GenerationRollback)
        );
        assert!(before.verification_is_current());
        let mut changed: Value = serde_json::from_slice(&documents[0]).unwrap();
        changed["bounded_unknown_extension"] = json!(true);
        let changed = serde_json::to_vec(&changed).unwrap();
        let mut reused_generation = configuration(2);
        reused_generation.idp_metadata_generation = 1;
        assert_eq!(
            owner.replace(
                reused_generation,
                &changed,
                &documents[1],
                deadline,
                deadline
            ),
            Err(EnterpriseResourceError::GenerationRollback)
        );
        assert!(before.verification_is_current());
        owner
            .replace(
                configuration(2),
                &documents[0],
                &documents[1],
                deadline,
                deadline,
            )
            .unwrap();
        assert!(!before.verification_is_current());
        assert!(provider.finish(&in_flight, before.clone()).is_err());
        let after = provider
            .authenticate(&context(), request(&params, &token))
            .unwrap();
        assert!(after.verification_is_current());
        assert_eq!(after.verification_valid_until(), Some(deadline));
        assert_eq!(before.session_owner(), after.session_owner());
        owner.revoke();
        assert!(!after.verification_is_current());
        assert!(
            provider
                .authenticate(&context(), request(&params, &token))
                .is_err()
        );
    }

    #[test]
    fn enterprise_resource_owner_drop_revokes_provider_clones_and_retained_facts() {
        let owner = policy();
        let provider = owner.provider(verifier()).unwrap();
        let copy = provider.clone();
        let token = token();
        let params = params();
        let auth = provider
            .authenticate(&context(), request(&params, &token))
            .unwrap();
        drop(provider);
        assert!(
            copy.authenticate(&context(), request(&params, &token))
                .is_ok()
        );
        assert!(auth.verification_is_current());
        drop(owner);
        assert!(!auth.verification_is_current());
        assert!(
            copy.authenticate(&context(), request(&params, &token))
                .is_err()
        );
    }
}
