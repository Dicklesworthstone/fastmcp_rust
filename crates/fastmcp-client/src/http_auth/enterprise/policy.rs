//! Local admission of the two enterprise authorization roles and their grants.
//!
//! These values are imported from explicitly trusted deployment configuration
//! and preregistration records. They are not deployment attestations, proof of
//! registration at a remote server, an identity mapping, or authorization to
//! acquire or dispatch an assertion. In particular, constructing a profile does
//! not activate EMA. The complete flow still needs its sealed OIDC acquisition,
//! credential custody, subject continuity, and durable one-use owners.

use std::collections::BTreeSet;
use std::fmt;

use fastmcp_core::{CanonicalHttpUrl, CanonicalResourceId};
use fastmcp_protocol::security_admission::{
    SecurityDocumentKind, admit_security_document, admit_security_document_object,
};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

/// The exact enterprise authorization grant profile.
pub const ID_JAG_GRANT_PROFILE: &str = "urn:ietf:params:oauth:grant-profile:id-jag";
/// The first enterprise exchange's OAuth grant type.
pub const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// The second enterprise exchange's OAuth grant type.
pub const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// The exact requested and issued ID-JAG token type.
pub const ID_JAG_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id-jag";

const MAX_ARRAY_ENTRIES: usize = 128;
const MAX_STRING_BYTES: usize = 4096;
const MAX_SCOPE_BYTES: usize = 4096;
const MAX_SCOPE_TOKENS: usize = 64;
const MAX_SCOPE_TOKEN_BYTES: usize = 256;
const MAX_SETTINGS_BYTES: usize = 1024;

/// Fixed diagnostics never include an issuer, a client identifier, or peer JSON.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterprisePolicyError {
    /// A trusted configuration field or generation is invalid.
    InvalidConfiguration,
    /// Raw security JSON or a required metadata member was refused.
    InvalidDocument,
    /// A document belongs to a different exact issuer.
    IssuerMismatch,
    /// A document selects an endpoint outside its exact configured role.
    EndpointMismatch,
    /// A client record does not match the independently configured registration.
    RegistrationMismatch,
    /// A required grant or profile advertisement is absent or unsupported.
    UnsupportedGrant,
    /// A role does not admit its exact confidential-client authentication method.
    UnsupportedAuthentication,
    /// The OIDC signing metadata or registration does not select RS256.
    UnsupportedOidcAlgorithm,
    /// Encrypted ID tokens are outside this signed-only profile.
    EncryptedIdTokenUnsupported,
    /// The independently supplied ID-JAG crypto configuration is inconsistent.
    UnsupportedIdJagPolicy,
    /// A scope set is empty where forbidden, malformed, duplicated, or too large.
    InvalidScopes,
    /// A requested or granted scope exceeds its independently configured allowance.
    ScopeExpansion,
    /// Response and signed scope representations do not describe one exact grant.
    ScopeMismatch,
    /// Request-local enterprise client settings are not an empty JSON object.
    InvalidClientSettings,
}

impl fmt::Display for EnterprisePolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid enterprise deployment configuration",
            Self::InvalidDocument => "invalid enterprise metadata or registration document",
            Self::IssuerMismatch => "enterprise issuer differs from its configured role",
            Self::EndpointMismatch => "enterprise endpoint differs from its configured role",
            Self::RegistrationMismatch => "enterprise client registration differs from its role",
            Self::UnsupportedGrant => "enterprise grant or profile is not explicitly admitted",
            Self::UnsupportedAuthentication => "enterprise client authentication is not admitted",
            Self::UnsupportedOidcAlgorithm => "enterprise OIDC registration does not select RS256",
            Self::EncryptedIdTokenUnsupported => "encrypted enterprise ID tokens are unsupported",
            Self::UnsupportedIdJagPolicy => "enterprise ID-JAG crypto configuration is inconsistent",
            Self::InvalidScopes => "invalid enterprise scope set",
            Self::ScopeExpansion => "enterprise scope exceeds its admitted allowance",
            Self::ScopeMismatch => "enterprise scope representations disagree",
            Self::InvalidClientSettings => "enterprise client settings must be an empty object",
        })
    }
}

impl std::error::Error for EnterprisePolicyError {}

/// The two confidential-client methods in this enterprise profile.
///
/// Choosing a method here neither obtains its credential nor grants access to
/// it. Credential custody and transport admission are separate flow obligations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnterpriseClientAuthentication {
    /// HTTP Basic client authentication.
    ClientSecretBasic,
    /// Explicit form-body client authentication.
    ClientSecretPost,
}

impl EnterpriseClientAuthentication {
    /// Returns the exact OAuth registration and metadata spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
        }
    }
}

/// One exact, operator-trusted, issuer-bound client preregistration.
#[derive(Clone, Debug)]
pub struct EnterpriseRegistrationConfiguration {
    /// Exact issuer spelling; it is validated as HTTPS but never normalized.
    pub issuer: String,
    /// Exact token endpoint independently allowed for this registration.
    pub token_endpoint: String,
    /// Non-URL client ID belonging only to this role's issuer.
    pub client_id: String,
    /// Exact preregistered confidential-client method.
    pub authentication: EnterpriseClientAuthentication,
    /// Nonzero deployment registration generation.
    pub generation: u64,
    /// Explicit literal scopes allowed for this registration, including empty.
    pub scope_allowance: Vec<String>,
}

/// Independently configured local ID-JAG verification authority.
///
/// This is deliberately separate from OIDC discovery's `jwks_uri` and
/// `id_token_signing_alg_values_supported`. It is an operator trust input, not
/// the complete attested `IdJagIssuerCryptoPolicy` or a key-rotation provider.
/// Reusing an OIDC JWKS requires explicitly configuring it here as well.
#[derive(Clone, Debug)]
pub struct IdJagCryptoConfiguration {
    /// Exact IdP issuer authorized for this purpose.
    pub issuer: String,
    /// Independently trusted JWKS identity for ID-JAG verification keys.
    pub jwks_uri: String,
    /// Exact resource authorization server trusting this issuer for this flow.
    pub resource_as_issuer: String,
    /// Explicit algorithm selection; this implementation admits only `RS256`.
    pub algorithm: String,
    /// Nonzero imported verification-key generation.
    pub key_generation: u64,
    /// Nonzero local crypto-policy generation.
    pub policy_generation: u64,
}

/// Explicit deployment inputs to local metadata and registration admission.
///
/// Every generation is immutable in the resulting profile. These integers are
/// bindings, not attestations or rollback resistance. Changing metadata, keys,
/// registrations, or allowances requires constructing a new profile.
#[derive(Clone, Debug)]
pub struct EnterpriseProfileConfiguration {
    /// Client-to-IdP registration, independently from the resource-AS client.
    pub idp: EnterpriseRegistrationConfiguration,
    /// Client-to-resource-AS registration.
    pub resource_as: EnterpriseRegistrationConfiguration,
    /// Exact trusted OIDC authorization endpoint.
    pub idp_authorization_endpoint: String,
    /// Exact trusted OIDC JWKS identity, independent of the ID-JAG authority.
    pub oidc_jwks_uri: String,
    /// Nonzero OIDC verification-key generation.
    pub oidc_key_generation: u64,
    /// Independently configured ID-JAG purpose and trust relationship.
    pub id_jag_crypto: IdJagCryptoConfiguration,
    /// The one already-admitted canonical MCP resource.
    pub resource: CanonicalResourceId,
    /// The one literal scope request selected for this resource.
    pub requested_scopes: RequestedEnterpriseScopeSet,
    /// Explicit enterprise deployment scope allowance.
    pub deployment_scope_allowance: Vec<String>,
    /// Nonzero local deployment policy generation.
    pub policy_generation: u64,
    /// Nonzero independently admitted IdP metadata generation.
    pub idp_metadata_generation: u64,
    /// Nonzero independently admitted resource-AS metadata generation.
    pub resource_as_metadata_generation: u64,
    /// Nonzero aggregate client-profile registration generation.
    pub aggregate_registration_generation: u64,
}

/// A locally consistent, immutable pair of enterprise authorization roles.
///
/// This type contains no assertion or secret and performs no network access.
/// It does not prove a remote registration, third-party subject mapping,
/// deployment custody, replay protection, or complete EMA activation.
#[derive(Clone, Debug)]
pub struct EnterpriseProfile {
    configuration: EnterpriseProfileConfiguration,
    oidc_openid_allowed: bool,
}

impl EnterpriseProfile {
    /// Imports five bounded, duplicate-free metadata/registration documents.
    ///
    /// Both endpoint registration documents are trusted preregistration records
    /// containing their exact `issuer`, `token_endpoint`, `client_id`,
    /// `grant_types`, and `token_endpoint_auth_method`. The aggregate client
    /// record must independently declare `authorization_grant_profiles_supported`
    /// and client `grant_types`. AS `grant_types_supported` never substitutes
    /// for either client declaration. Unknown metadata fields are bounded and
    /// ignored; they never supply missing authority. Raw credentials and DCR
    /// management fields are refused by presence before any JSON map is built.
    ///
    /// This only validates local inputs. Callers must obtain the documents and
    /// configuration from their trusted deployment and separately enforce
    /// custody, lifetime, discovery provenance, identity mapping, and replay.
    pub fn from_documents(
        configuration: EnterpriseProfileConfiguration,
        idp_metadata: &[u8],
        resource_as_metadata: &[u8],
        aggregate_client_metadata: &[u8],
        idp_registration: &[u8],
        resource_registration: &[u8],
    ) -> Result<Self, EnterprisePolicyError> {
        validate_configuration(&configuration)?;
        let idp = document(SecurityDocumentKind::OidcProviderMetadata, idp_metadata)?;
        let resource_as = document(
            SecurityDocumentKind::AuthorizationServerMetadata,
            resource_as_metadata,
        )?;
        let aggregate = document(
            SecurityDocumentKind::ClientRegistration,
            aggregate_client_metadata,
        )?;
        let idp_client = document(SecurityDocumentKind::ClientRegistration, idp_registration)?;
        let resource_client = document(
            SecurityDocumentKind::ClientRegistration,
            resource_registration,
        )?;

        admit_metadata_role(&idp, &configuration.idp)?;
        admit_metadata_role(&resource_as, &configuration.resource_as)?;
        exact_endpoint(
            &idp,
            "authorization_endpoint",
            &configuration.idp_authorization_endpoint,
        )?;
        exact_endpoint(&idp, "jwks_uri", &configuration.oidc_jwks_uri)?;
        require_values(
            &idp,
            "grant_types_supported",
            &["authorization_code", TOKEN_EXCHANGE_GRANT],
        )?;
        require_values(&idp, "response_types_supported", &["code"])?;
        require_values(&idp, "code_challenge_methods_supported", &["S256"])?;
        require_values(
            &idp,
            "identity_chaining_requested_token_types_supported",
            &[ID_JAG_TOKEN_TYPE],
        )?;
        require_values(
            &resource_as,
            "authorization_grant_profiles_supported",
            &[ID_JAG_GRANT_PROFILE],
        )?;
        require_values(
            &resource_as,
            "grant_types_supported",
            &[JWT_BEARER_GRANT],
        )?;
        require_values(
            &idp,
            "id_token_signing_alg_values_supported",
            &["RS256"],
        )
        .map_err(|_| EnterprisePolicyError::UnsupportedOidcAlgorithm)?;
        require_values(
            &aggregate,
            "authorization_grant_profiles_supported",
            &[ID_JAG_GRANT_PROFILE],
        )?;
        let aggregate_grants = required_array(&aggregate, "grant_types")?;
        require_grant_set(
            &aggregate_grants,
            &[TOKEN_EXCHANGE_GRANT, JWT_BEARER_GRANT],
            &["authorization_code", TOKEN_EXCHANGE_GRANT, JWT_BEARER_GRANT],
        )?;
        admit_registration(
            &idp_client,
            &configuration.idp,
            &["authorization_code", TOKEN_EXCHANGE_GRANT],
        )?;
        admit_registration(
            &resource_client,
            &configuration.resource_as,
            &[JWT_BEARER_GRANT],
        )?;
        if idp_client.contains_key("id_token_encrypted_response_alg")
            || idp_client.contains_key("id_token_encrypted_response_enc")
        {
            return Err(EnterprisePolicyError::EncryptedIdTokenUnsupported);
        }
        if idp_client
            .get("id_token_signed_response_alg")
            .is_some_and(|value| value.as_str() != Some("RS256"))
        {
            return Err(EnterprisePolicyError::UnsupportedOidcAlgorithm);
        }

        for metadata in [&idp, &resource_as] {
            if metadata.contains_key("scopes_supported") {
                let supported = required_array(metadata, "scopes_supported")?;
                let supported = scope_literals(supported.iter().map(|scope| (*scope).to_owned()))?;
                require_scope_subset(configuration.requested_scopes.as_slice(), &supported)?;
            }
        }
        for registration in [&idp_client, &resource_client, &aggregate] {
            if let Some(value) = registration.get("scope") {
                let allowed = scope_string(
                    value.as_str().ok_or(EnterprisePolicyError::InvalidScopes)?,
                )?;
                require_scope_subset(configuration.requested_scopes.as_slice(), &allowed)?;
            }
        }
        let mut oidc_openid_allowed = configuration.idp.scope_allowance.iter()
            .any(|scope| scope == "openid");
        if idp.contains_key("scopes_supported") {
            oidc_openid_allowed &= required_array(&idp, "scopes_supported")?.contains(&"openid");
        }
        if let Some(value) = idp_client.get("scope") {
            oidc_openid_allowed &= scope_string(
                value.as_str().ok_or(EnterprisePolicyError::InvalidScopes)?,
            )?.iter().any(|scope| scope == "openid");
        }
        Ok(Self { configuration, oidc_openid_allowed })
    }

    /// Whether the original IdP deployment, metadata and registration scope
    /// allowances permit the separate OIDC openid request. MCP scope grants
    /// cannot fill a missing OIDC permission; later metadata cannot widen it.
    pub fn permits_oidc_openid(&self) -> bool {
        self.oidc_openid_allowed
    }

    /// Admits the request-local client extension value, never a server overlay.
    /// The caller must separately require the exact official extension key.
    pub fn admit_client_settings(&self, settings: &[u8]) -> Result<(), EnterprisePolicyError> {
        if settings.len() > MAX_SETTINGS_BYTES {
            return Err(EnterprisePolicyError::InvalidClientSettings);
        }
        let settings = admit_security_document_object(
            SecurityDocumentKind::ClientRegistration,
            settings,
        )
        .map_err(|_| EnterprisePolicyError::InvalidClientSettings)?;
        if settings.is_empty() {
            Ok(())
        } else {
            Err(EnterprisePolicyError::InvalidClientSettings)
        }
    }

    /// Exact IdP issuer for OIDC and ID-JAG issuer comparisons.
    pub fn idp_issuer(&self) -> &str {
        &self.configuration.idp.issuer
    }

    /// Exact first-stage token endpoint.
    pub fn idp_token_endpoint(&self) -> &str {
        &self.configuration.idp.token_endpoint
    }

    /// Exact OIDC authorization endpoint.
    pub fn idp_authorization_endpoint(&self) -> &str {
        &self.configuration.idp_authorization_endpoint
    }

    /// Exact OIDC client identifier; never the resource-AS client identifier.
    pub fn idp_client_id(&self) -> &str {
        &self.configuration.idp.client_id
    }

    /// Exact first-stage confidential-client method.
    pub fn idp_authentication(&self) -> EnterpriseClientAuthentication {
        self.configuration.idp.authentication
    }

    /// Exact resource-AS issuer and ID-JAG audience.
    pub fn resource_as_issuer(&self) -> &str {
        &self.configuration.resource_as.issuer
    }

    /// Exact second-stage token endpoint.
    pub fn resource_as_token_endpoint(&self) -> &str {
        &self.configuration.resource_as.token_endpoint
    }

    /// Exact second-stage client identifier and signed ID-JAG `client_id`.
    pub fn resource_as_client_id(&self) -> &str {
        &self.configuration.resource_as.client_id
    }

    /// Exact second-stage confidential-client method.
    pub fn resource_as_authentication(&self) -> EnterpriseClientAuthentication {
        self.configuration.resource_as.authentication
    }

    /// The one canonical MCP resource bound before any assertion acquisition.
    pub fn resource(&self) -> &CanonicalResourceId {
        &self.configuration.resource
    }

    /// The one requested scope set admitted by every configured allowance.
    pub fn requested_scopes(&self) -> &RequestedEnterpriseScopeSet {
        &self.configuration.requested_scopes
    }

    /// Exact discovered OIDC JWKS identity, independent from ID-JAG authority.
    pub fn oidc_jwks_uri(&self) -> &str {
        &self.configuration.oidc_jwks_uri
    }

    /// Imported OIDC verification keys must match this generation and issuer.
    pub fn oidc_key_generation(&self) -> u64 {
        self.configuration.oidc_key_generation
    }

    /// Independently configured ID-JAG JWKS identity.
    pub fn id_jag_jwks_uri(&self) -> &str {
        &self.configuration.id_jag_crypto.jwks_uri
    }

    /// Imported ID-JAG verification keys must match this generation and issuer.
    pub fn id_jag_key_generation(&self) -> u64 {
        self.configuration.id_jag_crypto.key_generation
    }

    /// Local ID-JAG crypto-policy generation, distinct from OIDC metadata.
    pub fn id_jag_policy_generation(&self) -> u64 {
        self.configuration.id_jag_crypto.policy_generation
    }

    /// Local deployment policy generation.
    pub fn policy_generation(&self) -> u64 {
        self.configuration.policy_generation
    }

    /// Independently admitted IdP metadata generation.
    pub fn idp_metadata_generation(&self) -> u64 {
        self.configuration.idp_metadata_generation
    }

    /// Independently admitted resource-AS metadata generation.
    pub fn resource_as_metadata_generation(&self) -> u64 {
        self.configuration.resource_as_metadata_generation
    }

    /// Exact IdP preregistration generation.
    pub fn idp_registration_generation(&self) -> u64 {
        self.configuration.idp.generation
    }

    /// Exact resource-AS preregistration generation.
    pub fn resource_as_registration_generation(&self) -> u64 {
        self.configuration.resource_as.generation
    }

    /// Aggregate profile declaration generation.
    pub fn aggregate_registration_generation(&self) -> u64 {
        self.configuration.aggregate_registration_generation
    }
}

/// A bounded literal OAuth scope request. No hierarchy or defaults are inferred.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestedEnterpriseScopeSet {
    scopes: Vec<String>,
}

impl RequestedEnterpriseScopeSet {
    /// Admits at most 64 unique RFC 6749 scope tokens and 4096 wire bytes.
    /// Each individual token is bounded to 256 bytes.
    /// Empty is supported, but empty tokens and duplicate literals are refused.
    pub fn from_literals(
        scopes: impl IntoIterator<Item = String>,
    ) -> Result<Self, EnterprisePolicyError> {
        Ok(Self {
            scopes: scope_literals(scopes)?,
        })
    }

    /// Returns the exact literals in deterministic lexical order.
    pub fn as_slice(&self) -> &[String] {
        &self.scopes
    }

    /// Returns the exact form value, or absence for the empty request.
    pub fn as_wire_value(&self) -> Option<String> {
        (!self.scopes.is_empty()).then(|| self.scopes.join(" "))
    }

    /// Admits requested, top-level response, and signed ID-JAG scope together.
    ///
    /// A nonempty request needs a nonempty signed subset. Narrowing requires an
    /// explicit equal top-level response scope; an unchanged grant may omit it.
    /// An empty request requires both representations to be absent.
    pub fn admit_id_jag_grant(
        &self,
        response_scope: Option<&str>,
        signed_scope: Option<&str>,
    ) -> Result<IdJagGrantedScopeSet, EnterprisePolicyError> {
        if self.scopes.is_empty() {
            return if response_scope.is_none() && signed_scope.is_none() {
                Ok(IdJagGrantedScopeSet { scopes: Vec::new() })
            } else {
                Err(EnterprisePolicyError::ScopeMismatch)
            };
        }
        let granted = scope_string(signed_scope.ok_or(EnterprisePolicyError::ScopeMismatch)?)?;
        require_scope_subset(&granted, &self.scopes)?;
        match response_scope {
            Some(scope) if scope_string(scope)? == granted => {}
            None if granted == self.scopes => {}
            _ => return Err(EnterprisePolicyError::ScopeMismatch),
        }
        Ok(IdJagGrantedScopeSet { scopes: granted })
    }
}

/// The literal IdP grant admitted jointly with the request and signed claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdJagGrantedScopeSet {
    scopes: Vec<String>,
}

impl IdJagGrantedScopeSet {
    /// Returns the admitted literal IdP grant in lexical order.
    pub fn as_slice(&self) -> &[String] {
        &self.scopes
    }

    /// Admits the final access-token scope overlay without inferring a default.
    /// A nonempty IdP grant requires an explicit nonempty literal subset. The
    /// empty grant requires omission, never an empty string or invented scope.
    pub fn admit_access_grant(
        &self,
        response_scope: Option<&str>,
    ) -> Result<Vec<String>, EnterprisePolicyError> {
        if self.scopes.is_empty() {
            return if response_scope.is_none() {
                Ok(Vec::new())
            } else {
                Err(EnterprisePolicyError::ScopeMismatch)
            };
        }
        let granted = scope_string(response_scope.ok_or(EnterprisePolicyError::ScopeMismatch)?)?;
        require_scope_subset(&granted, &self.scopes)?;
        Ok(granted)
    }
}

fn validate_configuration(
    configuration: &EnterpriseProfileConfiguration,
) -> Result<(), EnterprisePolicyError> {
    for registration in [&configuration.idp, &configuration.resource_as] {
        exact_https_url(&registration.issuer, true)?;
        exact_https_url(&registration.token_endpoint, true)?;
        validate_client_id(&registration.client_id)?;
        if registration.generation == 0 {
            return Err(EnterprisePolicyError::InvalidConfiguration);
        }
        let allowance = scope_literals(registration.scope_allowance.iter().cloned())?;
        require_scope_subset(configuration.requested_scopes.as_slice(), &allowance)?;
    }
    exact_https_url(&configuration.idp_authorization_endpoint, true)?;
    exact_https_url(&configuration.oidc_jwks_uri, false)?;
    let crypto = &configuration.id_jag_crypto;
    if crypto.issuer != configuration.idp.issuer
        || crypto.resource_as_issuer != configuration.resource_as.issuer
        || crypto.algorithm != "RS256"
        || crypto.key_generation == 0
        || crypto.policy_generation == 0
        || exact_https_url(&crypto.jwks_uri, false).is_err()
    {
        return Err(EnterprisePolicyError::UnsupportedIdJagPolicy);
    }
    if [
        configuration.policy_generation,
        configuration.idp_metadata_generation,
        configuration.resource_as_metadata_generation,
        configuration.aggregate_registration_generation,
        configuration.oidc_key_generation,
    ]
    .contains(&0)
    {
        return Err(EnterprisePolicyError::InvalidConfiguration);
    }
    let allowance = scope_literals(configuration.deployment_scope_allowance.iter().cloned())?;
    require_scope_subset(configuration.requested_scopes.as_slice(), &allowance)
}

fn exact_https_url(value: &str, query_free: bool) -> Result<(), EnterprisePolicyError> {
    if value.is_empty()
        || value.len() > MAX_STRING_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(EnterprisePolicyError::InvalidConfiguration);
    }
    let parsed = CanonicalHttpUrl::parse(value)
        .map_err(|_| EnterprisePolicyError::InvalidConfiguration)?;
    if parsed.scheme() != "https"
        || parsed.has_userinfo()
        || parsed.has_syntax_violation()
        || parsed.fragment().is_some()
        || (query_free && parsed.query().is_some())
    {
        return Err(EnterprisePolicyError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_client_id(value: &str) -> Result<(), EnterprisePolicyError> {
    if value.is_empty()
        || value.len() > MAX_STRING_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
        || value
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
    {
        return Err(EnterprisePolicyError::InvalidConfiguration);
    }
    Ok(())
}

#[derive(Default)]
struct ForbiddenRegistrationMember(bool);

impl<'de> Deserialize<'de> for ForbiddenRegistrationMember {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde::de::IgnoredAny::deserialize(deserializer)?;
        Ok(Self(true))
    }
}

#[derive(Deserialize)]
struct RegistrationCustodyOverlay {
    #[serde(default)]
    client_secret: ForbiddenRegistrationMember,
    #[serde(default)]
    registration_access_token: ForbiddenRegistrationMember,
    #[serde(default)]
    registration_client_uri: ForbiddenRegistrationMember,
}

fn document(
    kind: SecurityDocumentKind,
    bytes: &[u8],
) -> Result<Map<String, Value>, EnterprisePolicyError> {
    // The raw pass fixes duplicate/depth/number admission. The presence-only
    // overlay then skips values without allocating a credential string. Only
    // documents without credential or DCR management members become a Map.
    admit_security_document(kind, bytes).map_err(|_| EnterprisePolicyError::InvalidDocument)?;
    let custody: RegistrationCustodyOverlay =
        serde_json::from_slice(bytes).map_err(|_| EnterprisePolicyError::InvalidDocument)?;
    if custody.client_secret.0
        || custody.registration_access_token.0
        || custody.registration_client_uri.0
    {
        return Err(EnterprisePolicyError::RegistrationMismatch);
    }
    serde_json::from_slice(bytes).map_err(|_| EnterprisePolicyError::InvalidDocument)
}

fn required_string<'a>(
    document: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, EnterprisePolicyError> {
    let value = document
        .get(key)
        .and_then(Value::as_str)
        .ok_or(EnterprisePolicyError::InvalidDocument)?;
    if value.is_empty()
        || value.len() > MAX_STRING_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(EnterprisePolicyError::InvalidDocument);
    }
    Ok(value)
}

fn required_array<'a>(
    document: &'a Map<String, Value>,
    key: &str,
) -> Result<Vec<&'a str>, EnterprisePolicyError> {
    let values = document
        .get(key)
        .and_then(Value::as_array)
        .ok_or(EnterprisePolicyError::InvalidDocument)?;
    if values.is_empty() || values.len() > MAX_ARRAY_ENTRIES {
        return Err(EnterprisePolicyError::InvalidDocument);
    }
    let mut seen = BTreeSet::new();
    for value in values {
        let value = value.as_str().ok_or(EnterprisePolicyError::InvalidDocument)?;
        if value.is_empty()
            || value.len() > MAX_STRING_BYTES
            || value.chars().any(char::is_control)
            || !seen.insert(value)
        {
            return Err(EnterprisePolicyError::InvalidDocument);
        }
    }
    Ok(seen.into_iter().collect())
}

fn require_values(
    document: &Map<String, Value>,
    key: &str,
    required: &[&str],
) -> Result<(), EnterprisePolicyError> {
    let values = required_array(document, key)?;
    if required.iter().all(|value| values.contains(value)) {
        Ok(())
    } else {
        Err(EnterprisePolicyError::UnsupportedGrant)
    }
}

fn exact_endpoint(
    document: &Map<String, Value>,
    key: &str,
    expected: &str,
) -> Result<(), EnterprisePolicyError> {
    if required_string(document, key)? == expected {
        Ok(())
    } else {
        Err(EnterprisePolicyError::EndpointMismatch)
    }
}

fn admit_metadata_role(
    metadata: &Map<String, Value>,
    configuration: &EnterpriseRegistrationConfiguration,
) -> Result<(), EnterprisePolicyError> {
    if required_string(metadata, "issuer")? != configuration.issuer {
        return Err(EnterprisePolicyError::IssuerMismatch);
    }
    exact_endpoint(metadata, "token_endpoint", &configuration.token_endpoint)?;
    require_values(
        metadata,
        "token_endpoint_auth_methods_supported",
        &[configuration.authentication.as_str()],
    )
    .map_err(|_| EnterprisePolicyError::UnsupportedAuthentication)?;
    Ok(())
}

fn admit_registration(
    registration: &Map<String, Value>,
    configuration: &EnterpriseRegistrationConfiguration,
    allowed_grants: &[&str],
) -> Result<(), EnterprisePolicyError> {
    if required_string(registration, "issuer")? != configuration.issuer {
        return Err(EnterprisePolicyError::IssuerMismatch);
    }
    exact_endpoint(registration, "token_endpoint", &configuration.token_endpoint)?;
    if required_string(registration, "client_id")? != configuration.client_id {
        return Err(EnterprisePolicyError::RegistrationMismatch);
    }
    if required_string(registration, "token_endpoint_auth_method")?
        != configuration.authentication.as_str()
    {
        return Err(EnterprisePolicyError::UnsupportedAuthentication);
    }
    let grants = required_array(registration, "grant_types")?;
    require_grant_set(&grants, allowed_grants, allowed_grants)
}

fn require_grant_set(
    grants: &[&str],
    required: &[&str],
    allowed: &[&str],
) -> Result<(), EnterprisePolicyError> {
    if required.iter().all(|grant| grants.contains(grant))
        && grants.iter().all(|grant| allowed.contains(grant))
    {
        Ok(())
    } else {
        Err(EnterprisePolicyError::UnsupportedGrant)
    }
}

fn scope_literals(
    values: impl IntoIterator<Item = String>,
) -> Result<Vec<String>, EnterprisePolicyError> {
    let mut seen = BTreeSet::new();
    let mut bytes = 0usize;
    for value in values {
        if seen.len() >= MAX_SCOPE_TOKENS
            || value.is_empty()
            || value.len() > MAX_SCOPE_TOKEN_BYTES
            || !value
                .bytes()
                .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
        {
            return Err(EnterprisePolicyError::InvalidScopes);
        }
        bytes = bytes
            .checked_add(value.len() + usize::from(!seen.is_empty()))
            .ok_or(EnterprisePolicyError::InvalidScopes)?;
        if bytes > MAX_SCOPE_BYTES || !seen.insert(value) {
            return Err(EnterprisePolicyError::InvalidScopes);
        }
    }
    Ok(seen.into_iter().collect())
}

fn scope_string(value: &str) -> Result<Vec<String>, EnterprisePolicyError> {
    if value.is_empty() || value.len() > MAX_SCOPE_BYTES {
        return Err(EnterprisePolicyError::InvalidScopes);
    }
    scope_literals(value.split(' ').map(str::to_owned))
}

fn require_scope_subset(
    selected: &[String],
    allowed: &[String],
) -> Result<(), EnterprisePolicyError> {
    if selected.iter().all(|scope| allowed.contains(scope)) {
        Ok(())
    } else {
        Err(EnterprisePolicyError::ScopeExpansion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_core::CanonicalResourceIdPolicy;
    use serde_json::json;

    fn configuration() -> EnterpriseProfileConfiguration {
        let endpoint = CanonicalHttpUrl::parse("https://mcp.example/api").unwrap();
        EnterpriseProfileConfiguration {
            idp: EnterpriseRegistrationConfiguration {
                issuer: "https://idp.example".to_owned(),
                token_endpoint: "https://idp.example/token".to_owned(),
                client_id: "client-at-idp".to_owned(),
                authentication: EnterpriseClientAuthentication::ClientSecretBasic,
                generation: 11,
                scope_allowance: vec!["tool:read".to_owned(), "tool:write".to_owned()],
            },
            resource_as: EnterpriseRegistrationConfiguration {
                issuer: "https://authorization.example".to_owned(),
                token_endpoint: "https://authorization.example/token".to_owned(),
                client_id: "client-at-resource-as".to_owned(),
                authentication: EnterpriseClientAuthentication::ClientSecretPost,
                generation: 12,
                scope_allowance: vec!["tool:read".to_owned(), "tool:write".to_owned()],
            },
            idp_authorization_endpoint: "https://idp.example/authorize".to_owned(),
            oidc_jwks_uri: "https://idp.example/oidc-keys".to_owned(),
            oidc_key_generation: 21,
            id_jag_crypto: IdJagCryptoConfiguration {
                issuer: "https://idp.example".to_owned(),
                jwks_uri: "https://idp.example/id-jag-keys".to_owned(),
                resource_as_issuer: "https://authorization.example".to_owned(),
                algorithm: "RS256".to_owned(),
                key_generation: 22,
                policy_generation: 23,
            },
            resource: CanonicalResourceId::parse_for_endpoint(
                endpoint.as_str(),
                &endpoint,
                CanonicalResourceIdPolicy::default(),
            )
            .unwrap(),
            requested_scopes: RequestedEnterpriseScopeSet::from_literals([
                "tool:write".to_owned(),
                "tool:read".to_owned(),
            ])
            .unwrap(),
            deployment_scope_allowance: vec!["tool:read".to_owned(), "tool:write".to_owned()],
            policy_generation: 30,
            idp_metadata_generation: 31,
            resource_as_metadata_generation: 32,
            aggregate_registration_generation: 33,
        }
    }

    fn documents() -> [Value; 5] {
        [
            json!({
                "issuer": "https://idp.example",
                "authorization_endpoint": "https://idp.example/authorize",
                "token_endpoint": "https://idp.example/token",
                "jwks_uri": "https://idp.example/oidc-keys",
                "grant_types_supported": ["authorization_code", TOKEN_EXCHANGE_GRANT],
                "response_types_supported": ["code"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                "identity_chaining_requested_token_types_supported": [ID_JAG_TOKEN_TYPE],
                "id_token_signing_alg_values_supported": ["RS256", "ES256"],
                "scopes_supported": ["openid", "tool:read", "tool:write"]
            }),
            json!({
                "issuer": "https://authorization.example",
                "token_endpoint": "https://authorization.example/token",
                "authorization_grant_profiles_supported": [ID_JAG_GRANT_PROFILE],
                "grant_types_supported": [JWT_BEARER_GRANT, "client_credentials"],
                "token_endpoint_auth_methods_supported": ["client_secret_post"]
            }),
            json!({
                "authorization_grant_profiles_supported": [ID_JAG_GRANT_PROFILE],
                "grant_types": [TOKEN_EXCHANGE_GRANT, JWT_BEARER_GRANT],
                "unrecognized_metadata": {"grant_types_supported": ["wrong-authority"]}
            }),
            json!({
                "issuer": "https://idp.example",
                "token_endpoint": "https://idp.example/token",
                "client_id": "client-at-idp",
                "grant_types": ["authorization_code", TOKEN_EXCHANGE_GRANT],
                "token_endpoint_auth_method": "client_secret_basic"
            }),
            json!({
                "issuer": "https://authorization.example",
                "token_endpoint": "https://authorization.example/token",
                "client_id": "client-at-resource-as",
                "grant_types": [JWT_BEARER_GRANT],
                "token_endpoint_auth_method": "client_secret_post"
            }),
        ]
    }

    fn admit(
        configuration: EnterpriseProfileConfiguration,
        documents: &[Value; 5],
    ) -> Result<EnterpriseProfile, EnterprisePolicyError> {
        let bytes: Vec<_> = documents
            .iter()
            .map(|document| serde_json::to_vec(document).unwrap())
            .collect();
        EnterpriseProfile::from_documents(
            configuration,
            &bytes[0],
            &bytes[1],
            &bytes[2],
            &bytes[3],
            &bytes[4],
        )
    }

    #[test]
    fn enterprise_profile_keeps_roles_and_crypto_purposes_distinct() {
        let profile = admit(configuration(), &documents()).unwrap();
        assert_eq!(profile.idp_client_id(), "client-at-idp");
        assert_eq!(profile.resource_as_client_id(), "client-at-resource-as");
        assert_eq!(
            profile.idp_authentication(),
            EnterpriseClientAuthentication::ClientSecretBasic
        );
        assert_eq!(
            profile.resource_as_authentication(),
            EnterpriseClientAuthentication::ClientSecretPost
        );
        assert_eq!(profile.oidc_key_generation(), 21);
        assert_eq!(profile.id_jag_key_generation(), 22);
        assert_ne!(profile.oidc_jwks_uri(), profile.id_jag_jwks_uri());
        assert_eq!(profile.idp_registration_generation(), 11);
        assert_eq!(profile.resource_as_registration_generation(), 12);
        assert_eq!(profile.resource().as_str(), "https://mcp.example/api");
        assert_eq!(
            profile.requested_scopes().as_wire_value().as_deref(),
            Some("tool:read tool:write")
        );
        profile.admit_client_settings(b" {} ").unwrap();
        for settings in [
            b"null".as_slice(),
            b"[]",
            b"{\"enabled\":true}",
            b"{\"x\":null,\"x\":null}",
        ] {
            assert_eq!(
                profile.admit_client_settings(settings),
                Err(EnterprisePolicyError::InvalidClientSettings)
            );
        }
    }

    #[test]
    fn enterprise_metadata_requires_both_independent_role_advertisements() {
        for (index, field) in [
            (0, "identity_chaining_requested_token_types_supported"),
            (0, "grant_types_supported"),
            (1, "authorization_grant_profiles_supported"),
            (1, "grant_types_supported"),
            (0, "token_endpoint_auth_methods_supported"),
            (1, "token_endpoint_auth_methods_supported"),
        ] {
            let mut documents = documents();
            documents[index].as_object_mut().unwrap().remove(field);
            assert!(admit(configuration(), &documents).is_err(), "{index}:{field}");
        }
        for (index, field, value, expected) in [
            (0, "issuer", "https://idp.example/", EnterprisePolicyError::IssuerMismatch),
            (1, "issuer", "https://idp.example", EnterprisePolicyError::IssuerMismatch),
            (0, "token_endpoint", "https://authorization.example/token", EnterprisePolicyError::EndpointMismatch),
            (1, "token_endpoint", "https://idp.example/token", EnterprisePolicyError::EndpointMismatch),
            (0, "jwks_uri", "https://idp.example/id-jag-keys", EnterprisePolicyError::EndpointMismatch),
        ] {
            let mut documents = documents();
            documents[index][field] = json!(value);
            assert_eq!(admit(configuration(), &documents).unwrap_err(), expected);
        }
        for replacement in [json!(null), json!(ID_JAG_TOKEN_TYPE), json!([]), json!([ID_JAG_TOKEN_TYPE, ID_JAG_TOKEN_TYPE])] {
            let mut documents = documents();
            documents[0]["identity_chaining_requested_token_types_supported"] = replacement;
            assert!(admit(configuration(), &documents).is_err());
        }
    }

    #[test]
    fn enterprise_preregistration_never_inherits_the_other_roles_grants() {
        for (index, field, value) in [
            (2, "grant_types", json!([TOKEN_EXCHANGE_GRANT])),
            (2, "grant_types", json!([JWT_BEARER_GRANT])),
            (3, "grant_types", json!(["authorization_code"])),
            (3, "grant_types", json!([TOKEN_EXCHANGE_GRANT, JWT_BEARER_GRANT])),
            (4, "grant_types", json!([TOKEN_EXCHANGE_GRANT])),
            (4, "grant_types", json!([JWT_BEARER_GRANT, "authorization_code"])),
            (3, "client_id", json!("client-at-resource-as")),
            (4, "client_id", json!("client-at-idp")),
            (3, "token_endpoint_auth_method", json!("none")),
            (4, "token_endpoint_auth_method", json!("private_key_jwt")),
        ] {
            let mut documents = documents();
            documents[index][field] = value;
            assert!(admit(configuration(), &documents).is_err(), "{index}:{field}");
        }
        for index in [2, 3, 4] {
            let mut documents = documents();
            let record = documents[index].as_object_mut().unwrap();
            let grants = record.remove("grant_types").unwrap();
            record.insert("grant_types_supported".to_owned(), grants);
            assert!(admit(configuration(), &documents).is_err());
        }
        let mut documents = documents();
        documents.swap(3, 4);
        assert_eq!(
            admit(configuration(), &documents).unwrap_err(),
            EnterprisePolicyError::IssuerMismatch
        );
        for client_id in ["https://client.example/metadata", "HTTP://client.example/id", " client", "client\n"] {
            let mut configuration = configuration();
            configuration.idp.client_id = client_id.to_owned();
            assert_eq!(
                admit(configuration, &documents).unwrap_err(),
                EnterprisePolicyError::InvalidConfiguration
            );
        }
    }

    #[test]
    fn enterprise_oidc_and_idjag_crypto_policies_never_substitute() {
        for algorithm in [json!("ES256"), json!("none"), json!(null), json!(false)] {
            let mut documents = documents();
            documents[3]["id_token_signed_response_alg"] = algorithm;
            assert_eq!(
                admit(configuration(), &documents).unwrap_err(),
                EnterprisePolicyError::UnsupportedOidcAlgorithm
            );
        }
        for field in ["id_token_encrypted_response_alg", "id_token_encrypted_response_enc"] {
            let mut documents = documents();
            documents[3][field] = Value::Null;
            assert_eq!(
                admit(configuration(), &documents).unwrap_err(),
                EnterprisePolicyError::EncryptedIdTokenUnsupported
            );
        }
        let mut documents = documents();
        documents[0]["id_token_signing_alg_values_supported"] = json!(["ES256"]);
        assert_eq!(
            admit(configuration(), &documents).unwrap_err(),
            EnterprisePolicyError::UnsupportedOidcAlgorithm
        );
        for mutation in 0..5 {
            let mut configuration = configuration();
            match mutation {
                0 => configuration.id_jag_crypto.algorithm = "PS256".to_owned(),
                1 => configuration.id_jag_crypto.issuer = "https://another.example".to_owned(),
                2 => configuration.id_jag_crypto.resource_as_issuer = "https://another.example".to_owned(),
                3 => configuration.id_jag_crypto.jwks_uri = "http://idp.example/keys".to_owned(),
                _ => configuration.id_jag_crypto.key_generation = 0,
            }
            assert_eq!(
                admit(configuration, &self::documents()).unwrap_err(),
                EnterprisePolicyError::UnsupportedIdJagPolicy
            );
        }
        // Equality is allowed only because both purpose configurations say so.
        let mut configuration = configuration();
        configuration.id_jag_crypto.jwks_uri = configuration.oidc_jwks_uri.clone();
        configuration.id_jag_crypto.key_generation = configuration.oidc_key_generation;
        admit(configuration, &self::documents()).unwrap();
    }

    #[test]
    fn enterprise_profile_refuses_query_bearing_authorization_and_token_endpoints() {
        for role in 0..3 {
            let mut configuration = configuration();
            match role {
                0 => configuration.idp_authorization_endpoint.push_str("?extra=1"),
                1 => configuration.idp.token_endpoint.push_str("?extra=1"),
                _ => configuration.resource_as.token_endpoint.push_str("?extra=1"),
            }
            assert_eq!(
                admit(configuration, &documents()).unwrap_err(),
                EnterprisePolicyError::InvalidConfiguration
            );
        }
    }

    #[test]
    fn enterprise_documents_use_bounded_duplicate_aware_raw_admission() {
        let documents = documents();
        let mut bytes: Vec<_> = documents
            .iter()
            .map(|document| serde_json::to_vec(document).unwrap())
            .collect();
        bytes[0] = br#"{"issuer":"https://idp.example","issuer":"https://foreign.example"}"#.to_vec();
        assert_eq!(
            EnterpriseProfile::from_documents(configuration(), &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4]).unwrap_err(),
            EnterprisePolicyError::InvalidDocument
        );
        bytes[0] = serde_json::to_vec(&documents[0]).unwrap();
        bytes[2] = br#"{"unknown":{"scope":"read","scope":"write"}}"#.to_vec();
        assert_eq!(
            EnterpriseProfile::from_documents(configuration(), &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4]).unwrap_err(),
            EnterprisePolicyError::InvalidDocument
        );
        bytes[2] = serde_json::to_vec(&documents[2]).unwrap();
        bytes[3] = vec![b' '; SecurityDocumentKind::ClientRegistration.byte_limit() + 1];
        assert_eq!(
            EnterpriseProfile::from_documents(configuration(), &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4]).unwrap_err(),
            EnterprisePolicyError::InvalidDocument
        );
    }

    #[test]
    fn enterprise_preregistration_refuses_raw_credentials_and_dynamic_management() {
        for index in 0..5 {
            for field in [
                "client_secret",
                "registration_access_token",
                "registration_client_uri",
            ] {
                for value in [Value::Null, json!("protected-value"), json!({"nested": true})] {
                    let mut documents = documents();
                    documents[index][field] = value;
                    assert_eq!(
                        admit(configuration(), &documents).unwrap_err(),
                        EnterprisePolicyError::RegistrationMismatch,
                        "{index}:{field}"
                    );
                }
            }
        }
    }

    #[test]
    fn enterprise_requested_scope_requires_every_independent_allowance() {
        for role in 0..3 {
            let mut configuration = configuration();
            match role {
                0 => configuration.idp.scope_allowance = vec!["tool:read".to_owned()],
                1 => configuration.resource_as.scope_allowance = vec!["tool:read".to_owned()],
                _ => configuration.deployment_scope_allowance = vec!["tool:read".to_owned()],
            }
            assert_eq!(
                admit(configuration, &documents()).unwrap_err(),
                EnterprisePolicyError::ScopeExpansion
            );
        }
        for index in 0..5 {
            let mut documents = documents();
            if index < 2 {
                documents[index]["scopes_supported"] = json!(["tool:read"]);
            } else {
                documents[index]["scope"] = json!("tool:read");
            }
            assert_eq!(
                admit(configuration(), &documents).unwrap_err(),
                EnterprisePolicyError::ScopeExpansion
            );
        }
    }

    #[test]
    fn enterprise_oidc_scope_permission_retains_each_original_idp_allowance() {
        assert!(!admit(configuration(), &documents()).unwrap().permits_oidc_openid());
        let mut configured = configuration();
        configured.idp.scope_allowance.push("openid".to_owned());
        assert!(admit(configured.clone(), &documents()).unwrap().permits_oidc_openid());
        for source in 0..2 {
            let mut docs = documents();
            if source == 0 {
                docs[0]["scopes_supported"] = json!(["tool:read", "tool:write"]);
            } else {
                docs[3]["scope"] = json!("tool:read tool:write");
            }
            assert!(!admit(configured.clone(), &docs).unwrap().permits_oidc_openid());
        }
        let mut docs = documents();
        docs[3]["scope"] = json!("tool:read openid tool:write");
        assert!(admit(configured, &docs).unwrap().permits_oidc_openid());
    }

    #[test]
    fn enterprise_scope_grants_preserve_the_exact_three_way_decision() {
        let requested = configuration().requested_scopes;
        let unchanged = requested.admit_id_jag_grant(None, Some("tool:write tool:read")).unwrap();
        assert_eq!(unchanged.as_slice(), requested.as_slice());
        let narrowed = requested.admit_id_jag_grant(Some("tool:read"), Some("tool:read")).unwrap();
        assert_eq!(narrowed.as_slice(), &["tool:read"]);
        assert_eq!(narrowed.admit_access_grant(Some("tool:read")).unwrap(), ["tool:read"]);
        for (response, signed) in [
            (None, Some("tool:read")),
            (Some("tool:write"), Some("tool:read")),
            (Some("tool:read"), None),
            (None, Some("")),
            (Some("tool:*"), Some("tool:*")),
            (Some("Tool:read"), Some("Tool:read")),
        ] {
            assert!(requested.admit_id_jag_grant(response, signed).is_err());
        }
        assert!(narrowed.admit_access_grant(None).is_err());
        assert!(narrowed.admit_access_grant(Some("tool:write")).is_err());
        assert!(narrowed.admit_access_grant(Some("")).is_err());
        let empty = RequestedEnterpriseScopeSet::from_literals([]).unwrap();
        assert_eq!(empty.as_wire_value(), None);
        let empty_grant = empty.admit_id_jag_grant(None, None).unwrap();
        assert!(empty_grant.admit_access_grant(None).unwrap().is_empty());
        assert!(empty_grant.admit_access_grant(Some("tool:read")).is_err());
        assert!(empty.admit_id_jag_grant(Some(""), None).is_err());
        assert!(empty.admit_id_jag_grant(None, Some("tool:read")).is_err());
    }

    #[test]
    fn enterprise_scope_grammar_and_limits_do_not_normalize_authority() {
        for invalid in ["", " read", "read ", "read\twrite", "réad", "read\"", "read\\write"] {
            assert!(RequestedEnterpriseScopeSet::from_literals([invalid.to_owned()]).is_err());
        }
        assert!(RequestedEnterpriseScopeSet::from_literals(["read".to_owned(), "read".to_owned()]).is_err());
        assert!(RequestedEnterpriseScopeSet::from_literals(["r".repeat(257)]).is_err());
        RequestedEnterpriseScopeSet::from_literals(["r".repeat(256)]).unwrap();
        RequestedEnterpriseScopeSet::from_literals((0..64).map(|index| format!("s{index}"))).unwrap();
        assert!(RequestedEnterpriseScopeSet::from_literals((0..65).map(|index| format!("s{index}"))).is_err());
        assert!(RequestedEnterpriseScopeSet::from_literals((0..17).map(|index| format!("{index:03}{}", "r".repeat(253)))).is_err());
        let requested = RequestedEnterpriseScopeSet::from_literals(["read".to_owned(), "write".to_owned()]).unwrap();
        for malformed in ["read  write", " read write", "read write ", "read read"] {
            assert!(requested.admit_id_jag_grant(Some(malformed), Some(malformed)).is_err());
        }
        assert_eq!(requested.as_slice(), &["read", "write"]);
    }
}
