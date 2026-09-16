//! Explicit RFC 7591 dynamic registration for RFC 8252 native public clients.
//!
//! One non-cloneable owner performs trusted resource/issuer discovery followed
//! by at most one registration POST. Retain the returned [`RegisteredNativeClient`]
//! for subsequent explicit login attempts: retrying browser login must not create
//! another remote registration. No persistent store or registration-management
//! client is implemented here, and this is not confidential-client registration.
//!
//! Registration creates remote state. Cancellation, a lost response, or rejected
//! response metadata cannot undo a registration the server may already have made.
//! Such failures never automatically retry, switch issuer, follow a redirect, or
//! claim rollback. Only a new explicit owner can attempt registration again.

use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::http::h1::{HttpClient, Method, RedirectPolicy, RetryPolicy};
use asupersync::tls::Certificate;
use fastmcp_core::{AccessToken, CanonicalHttpUrl};
use serde::Deserialize;

use super::{
    OAuthDiscoveryError, OAuthDiscoveryPlan, TrustedOAuthIssuer, MAX_OAUTH_METADATA_BYTES,
    check_context, decode_metadata, discovery_deadline, has, https_url, origin_of,
    present, validate_headers, validate_https, within,
};
use super::super::BoundBearerCredential;
use super::super::managed::{ManagedOAuthSession, OAuthSessionError, OAuthSessionPolicy};
use super::super::oauth::{OAuthClient, OAuthClientConfiguration, OAuthError};

/// Exact loopback URI templates used by the existing native OAuth driver.
/// RFC 8252 section 7.3 requires the authorization server to permit the actual
/// ephemeral port at authorization time. Both address families are registered
/// so the driver can use its IPv4-then-IPv6 binding fallback. Hostname, scheme
/// and callback path remain fixed; this is not wildcard redirect registration.
pub const NATIVE_REGISTRATION_REDIRECT_URIS: [&str; 2] = [
    "http://127.0.0.1/oauth/callback",
    "http://[::1]/oauth/callback",
];

/// Sanitized failure categories; no variant retains remote bodies or secrets.
#[derive(Debug)]
pub enum OAuthRegistrationError {
    InvalidPolicy,
    Discovery(OAuthDiscoveryError),
    EndpointNotTrusted,
    InvalidRegistrationMetadata,
    InitialCredentialRejected,
    HttpStatus { status: u16 },
    ResponseRejected,
}

impl fmt::Display for OAuthRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid native OAuth registration policy",
            Self::Discovery(_) => "native OAuth registration discovery or exchange failed",
            Self::EndpointNotTrusted => "registration origin has no explicit write grant",
            Self::InvalidRegistrationMetadata => "issuer registration metadata is unusable",
            Self::InitialCredentialRejected => "initial registration credential is invalid for this endpoint",
            Self::HttpStatus { .. } => "OAuth registration did not return HTTP 201; not retried",
            Self::ResponseRejected => "OAuth registration response did not preserve the requested native client",
        })
    }
}

impl std::error::Error for OAuthRegistrationError {}

impl From<OAuthDiscoveryError> for OAuthRegistrationError {
    fn from(error: OAuthDiscoveryError) -> Self { Self::Discovery(error) }
}

/// A single explicit registration attempt. This type intentionally has no
/// Clone or serde implementation. It never accepts an MCP access token as
/// implicit registration authority or silently falls back from an existing ID.
pub struct NativeClientRegistration {
    discovery: OAuthDiscoveryPlan,
    client_name: String,
    registration_origins: Vec<String>,
    initial_credential: Option<BoundBearerCredential>,
}

impl fmt::Debug for NativeClientRegistration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeClientRegistration")
            .field("initial_credential", &self.initial_credential.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

impl NativeClientRegistration {
    /// Opts into creating one native public-client registration at the selected
    /// trusted issuer's own origin. A separate registration origin needs an
    /// additional grant through `with_registration_origin`; login/token origin
    /// grants alone never authorize registration writes.
    ///
    /// Requests authorization-code access and, only when issuer metadata
    /// explicitly advertises it, refresh-token access. The returned registration
    /// must echo that exact grant set, scopes, public authentication method and
    /// both loopback redirects before any browser login becomes possible.
    pub fn new(
        resource: CanonicalHttpUrl,
        issuers: Vec<TrustedOAuthIssuer>,
        client_name: impl Into<String>,
        scopes: Vec<String>,
    ) -> Result<Self, OAuthRegistrationError> {
        let client_name = client_name.into();
        if client_name.trim().is_empty() || client_name.len() > 256
            || client_name.chars().any(char::is_control)
        {
            return Err(OAuthRegistrationError::InvalidPolicy);
        }
        Ok(Self {
            discovery: OAuthDiscoveryPlan::with_client_id(resource, issuers, None, scopes)?,
            client_name,
            registration_origins: Vec::new(),
            initial_credential: None,
        })
    }

    /// One absolute deadline covers ALL discovery GETs and the registration
    /// POST. It is not reset per location or when registration starts.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, OAuthRegistrationError> {
        self.discovery = self.discovery.with_timeout(timeout)?;
        Ok(self)
    }

    pub fn with_resource_root_certificate(mut self, root: Certificate) -> Result<Self, OAuthRegistrationError> {
        self.discovery = self.discovery.with_resource_root_certificate(root)?;
        Ok(self)
    }

    /// Authorizes writes to one additional HTTPS registration origin, not to
    /// arbitrary origins named by the issuer. The issuer's configured roots
    /// still apply; registration does not import the resource's private roots.
    pub fn with_registration_origin(mut self, origin: CanonicalHttpUrl) -> Result<Self, OAuthRegistrationError> {
        validate_https(&origin).map_err(|_| OAuthRegistrationError::InvalidPolicy)?;
        let value = origin_of(&origin);
        if origin.path() != "/" || self.registration_origins.len() >= 8
            || self.registration_origins.contains(&value)
        {
            return Err(OAuthRegistrationError::InvalidPolicy);
        }
        self.registration_origins.push(value);
        Ok(self)
    }

    /// Supplies an explicit initial access token for a protected registration
    /// endpoint. It must be bound to that exact HTTPS endpoint and still fresh
    /// when the POST is constructed. It is never sent on metadata GETs, login,
    /// token redemption or refresh, and is dropped after this attempt. A local
    /// token expiry additionally bounds the entire attempt's lifetime.
    pub fn with_initial_access_token(mut self, credential: BoundBearerCredential) -> Result<Self, OAuthRegistrationError> {
        if self.initial_credential.is_some() {
            return Err(OAuthRegistrationError::InvalidPolicy);
        }
        let header = credential.authorization_for_target(credential.resource())
            .ok_or(OAuthRegistrationError::InitialCredentialRejected)?;
        if !header.strip_prefix("Bearer ").is_some_and(AccessToken::is_valid_token68) {
            return Err(OAuthRegistrationError::InitialCredentialRejected);
        }
        self.initial_credential = Some(credential);
        Ok(self)
    }

    /// Discovers and registers exactly once. Success returns a reusable local
    /// registration, not an access token. No browser is launched by this method.
    /// Its consuming receiver prevents accidental replay of this attempt.
    pub async fn register(self, cx: &Cx) -> Result<RegisteredNativeClient, OAuthRegistrationError> {
        let mut deadline = discovery_deadline(cx, self.discovery.timeout)?;
        if let Some(expiry) = self.initial_credential.as_ref().and_then(BoundBearerCredential::expires_at) {
            let remaining = expiry.checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or(OAuthRegistrationError::InitialCredentialRejected)?;
            deadline = deadline.min(discovery_deadline(cx, remaining)?);
        }
        let (issuer, body) = self.discovery.discover_issuer_document(cx, deadline).await?;
        let (authorization, token) = self.discovery.admit_issuer_endpoints(issuer, &body)?;
        let (endpoint, grants) = self.registration_endpoint(issuer, &body)?;
        let payload = self.request_body(&grants)?;
        let headers = self.request_headers(&endpoint)?;
        check_context(cx, deadline)?;

        let mut builder = HttpClient::builder()
            .redirect_policy(RedirectPolicy::None)
            .retry_policy(RetryPolicy::None)
            .no_proxy()
            .no_cookie_store()
            .max_body_size(MAX_OAUTH_METADATA_BYTES)
            .max_total_connections(1);
        for root in &issuer.roots {
            builder = builder.add_root_certificate(root.clone());
        }
        let client = builder.build();
        let response = within(cx, deadline, async {
            client.request(cx, Method::Post, endpoint.as_str(), headers, payload)
                .await.map_err(|_| OAuthDiscoveryError::TransportFailed)
        }).await?;
        if response.status != 201 {
            return Err(OAuthRegistrationError::HttpStatus { status: response.status });
        }
        validate_headers(&response.headers).map_err(|_| OAuthRegistrationError::ResponseRejected)?;
        if !response.trailers.is_empty() {
            return Err(OAuthRegistrationError::ResponseRejected);
        }
        let client_id = self.admit_response(&response.body, &grants)?;
        let configuration = self.discovery.configure_client(issuer, authorization, token, &client_id)?;
        check_context(cx, deadline)?;
        Ok(RegisteredNativeClient { client_id, configuration })
    }

    fn registration_endpoint(
        &self,
        issuer: &TrustedOAuthIssuer,
        body: &[u8],
    ) -> Result<(CanonicalHttpUrl, Vec<&'static str>), OAuthRegistrationError> {
        let metadata: RegistrationEndpointMetadata = decode_metadata(body)
            .map_err(|_| OAuthRegistrationError::InvalidRegistrationMetadata)?;
        let endpoint = https_url(&metadata.registration_endpoint)
            .map_err(|_| OAuthRegistrationError::InvalidRegistrationMetadata)?;
        let origin = origin_of(&endpoint);
        if origin != origin_of(&issuer.url) && !self.registration_origins.contains(&origin) {
            return Err(OAuthRegistrationError::EndpointNotTrusted);
        }
        // The complete metadata has already passed ordinary code-flow
        // admission. RFC 8414's absent grant_types_supported default does not
        // promise refresh_token, so it cannot cause that grant to be requested.
        let mut grants = vec!["authorization_code"];
        if metadata.grant_types_supported.as_ref().is_some_and(|values| has(values, "refresh_token")) {
            grants.push("refresh_token");
        }
        Ok((endpoint, grants))
    }

    fn request_body(&self, grants: &[&str]) -> Result<Vec<u8>, OAuthRegistrationError> {
        let mut payload = serde_json::json!({
            "client_name": self.client_name,
            "application_type": "native",
            "redirect_uris": NATIVE_REGISTRATION_REDIRECT_URIS,
            "token_endpoint_auth_method": "none",
            "grant_types": grants,
            "response_types": ["code"],
        });
        if !self.discovery.scopes.is_empty() {
            payload["scope"] = serde_json::Value::String(self.discovery.scopes.join(" "));
        }
        let bytes = serde_json::to_vec(&payload).map_err(|_| OAuthRegistrationError::InvalidPolicy)?;
        if bytes.len() > MAX_OAUTH_METADATA_BYTES {
            return Err(OAuthRegistrationError::InvalidPolicy);
        }
        Ok(bytes)
    }

    fn request_headers(&self, endpoint: &CanonicalHttpUrl) -> Result<Vec<(String, String)>, OAuthRegistrationError> {
        let mut headers = vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Accept".to_owned(), "application/json".to_owned()),
            ("Accept-Encoding".to_owned(), "identity".to_owned()),
            ("Connection".to_owned(), "close".to_owned()),
        ];
        if let Some(credential) = &self.initial_credential {
            let header = credential.authorization_for_target(endpoint)
                .ok_or(OAuthRegistrationError::InitialCredentialRejected)?;
            headers.push(("Authorization".to_owned(), header));
        }
        Ok(headers)
    }

    fn admit_response(&self, body: &[u8], grants: &[&str]) -> Result<String, OAuthRegistrationError> {
        let metadata: RegisteredMetadata = decode_metadata(body)
            .map_err(|_| OAuthRegistrationError::ResponseRejected)?;
        if metadata.client_id.is_empty() || metadata.client_id.len() > 1024
            || metadata.client_id.chars().any(char::is_control)
            || metadata.application_type != "native"
            || metadata.token_endpoint_auth_method != "none"
            || !exact_set(&metadata.redirect_uris, &NATIVE_REGISTRATION_REDIRECT_URIS)
            || !exact_set(&metadata.grant_types, grants)
            || !exact_set(&metadata.response_types, &["code"])
            || metadata.client_secret.is_some()
            || metadata.client_secret_expires_at.is_some()
            || metadata.software_statement.is_some()
            || metadata.error.is_some()
        {
            return Err(OAuthRegistrationError::ResponseRejected);
        }
        let scopes: Vec<String> = match metadata.scope {
            None => Vec::new(),
            Some(scope) if scope.is_empty() => return Err(OAuthRegistrationError::ResponseRejected),
            Some(scope) => scope.split(' ').map(str::to_owned).collect(),
        };
        let requested: Vec<&str> = self.discovery.scopes.iter().map(String::as_str).collect();
        if !exact_set(&scopes, &requested) {
            return Err(OAuthRegistrationError::ResponseRejected);
        }
        // A hostile endpoint must not launder an initial secret into the
        // reusable configuration's public client_id or its Debug output.
        if self.initial_credential.as_ref().is_some_and(|credential| {
            credential.is_reflected_by_value(&serde_json::Value::String(metadata.client_id.clone()))
        }) {
            return Err(OAuthRegistrationError::ResponseRejected);
        }
        Ok(metadata.client_id)
    }
}

/// Admitted public-client registration. Keep it across browser-login failures
/// so subsequent explicit logins reuse the same registration. It holds no
/// initial access token, client secret or registration-management credential.
/// Registration management URIs from the peer are not followed or persisted.
pub struct RegisteredNativeClient {
    client_id: String,
    configuration: OAuthClientConfiguration,
}

impl fmt::Debug for RegisteredNativeClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisteredNativeClient").finish_non_exhaustive()
    }
}

impl RegisteredNativeClient {
    pub fn client_id(&self) -> &str { &self.client_id }

    pub fn configuration(&self) -> &OAuthClientConfiguration { &self.configuration }

    /// Runs the existing S256 loopback login with this already-admitted ID.
    /// It never contacts the registration endpoint or rediscovers another issuer.
    pub async fn authorize_managed<L, F>(
        &self,
        cx: &Cx,
        policy: OAuthSessionPolicy,
        launch_browser: L,
    ) -> Result<ManagedOAuthSession, OAuthSessionError>
    where
        L: FnOnce(CanonicalHttpUrl) -> F,
        F: Future<Output = Result<(), OAuthError>>,
    {
        ManagedOAuthSession::authorize(
            cx, OAuthClient::new(self.configuration.clone()), policy, launch_browser,
        ).await
    }
}

fn exact_set(actual: &[String], expected: &[&str]) -> bool {
    actual.len() == expected.len()
        && actual.iter().map(String::as_str).collect::<BTreeSet<_>>().len() == actual.len()
        && actual.iter().all(|value| expected.contains(&value.as_str()))
}

#[derive(Deserialize)]
struct RegistrationEndpointMetadata {
    registration_endpoint: String,
    #[serde(default, deserialize_with = "present")]
    grant_types_supported: Option<Vec<String>>,
}

// Object-only decoding and declared-field duplicate detection run before any
// client ID can become usable. Unknown management extensions remain inert.
#[derive(Deserialize)]
struct RegisteredMetadata {
    client_id: String,
    application_type: String,
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: String,
    grant_types: Vec<String>,
    response_types: Vec<String>,
    #[serde(default, deserialize_with = "present")]
    scope: Option<String>,
    #[serde(default, deserialize_with = "present")]
    client_secret: Option<String>,
    #[serde(default, deserialize_with = "present")]
    client_secret_expires_at: Option<u64>,
    #[serde(default, deserialize_with = "present")]
    software_statement: Option<String>,
    #[serde(default, deserialize_with = "present")]
    error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn url(text: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(text).unwrap() }

    fn registration() -> NativeClientRegistration {
        NativeClientRegistration::new(
            url("https://resource.example/mcp"),
            vec![TrustedOAuthIssuer::new("https://issuer.example/tenant").unwrap()],
            "Native app", vec!["tools:read".to_owned(), "tools:write".to_owned()],
        ).unwrap()
    }

    fn response() -> Value {
        json!({
            "client_id": "new-client", "application_type": "native",
            "redirect_uris": NATIVE_REGISTRATION_REDIRECT_URIS,
            "token_endpoint_auth_method": "none", "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"], "scope": "tools:read tools:write",
        })
    }

    fn admit(owner: &NativeClientRegistration, body: &Value) -> Result<String, OAuthRegistrationError> {
        owner.admit_response(&serde_json::to_vec(body).unwrap(), &["authorization_code", "refresh_token"])
    }

    #[test]
    fn registration_request_and_response_preserve_exact_native_public_profile() {
        let owner = registration();
        assert!(owner.discovery.client_id.is_none());
        let payload: Value = serde_json::from_slice(&owner.request_body(&["authorization_code", "refresh_token"]).unwrap()).unwrap();
        assert_eq!(payload["redirect_uris"], json!(NATIVE_REGISTRATION_REDIRECT_URIS));
        assert_eq!(payload["application_type"], "native");
        assert_eq!(payload["token_endpoint_auth_method"], "none");
        assert!(payload.get("client_id").is_none());
        assert!(payload.get("client_secret").is_none());
        assert_eq!(admit(&owner, &response()).unwrap(), "new-client");
        let mut reordered = response();
        reordered["redirect_uris"].as_array_mut().unwrap().reverse();
        reordered["grant_types"].as_array_mut().unwrap().reverse();
        reordered["scope"] = json!("tools:write tools:read");
        assert_eq!(admit(&owner, &reordered).unwrap(), "new-client");
    }

    #[test]
    fn registration_response_cannot_replace_redirects_auth_method_or_grants() {
        let owner = registration();
        for (key, value) in [
            ("redirect_uris", json!(["https://attacker.invalid/callback", NATIVE_REGISTRATION_REDIRECT_URIS[1]])),
            ("redirect_uris", json!([NATIVE_REGISTRATION_REDIRECT_URIS[0], NATIVE_REGISTRATION_REDIRECT_URIS[0]])),
            ("redirect_uris", json!([NATIVE_REGISTRATION_REDIRECT_URIS[0]])),
            ("token_endpoint_auth_method", json!("client_secret_basic")),
            ("application_type", json!("web")),
            ("grant_types", json!(["authorization_code", "client_credentials"])),
            ("grant_types", json!(["authorization_code"])),
            ("response_types", json!(["token"])),
            ("client_secret", json!("not-a-public-client")),
            ("client_secret", Value::Null),
            ("scope", json!("admin")), ("scope", json!("tools:read tools:read")),
            ("scope", Value::Null), ("client_id", json!("")),
        ] {
            let mut body = response();
            body[key] = value;
            assert!(admit(&owner, &body).is_err(), "changed {key} must prevent login");
        }
        assert_eq!(admit(&owner, &response()).unwrap(), "new-client");
    }

    #[test]
    fn registration_response_is_object_only_duplicate_aware_and_bounded() {
        let owner = registration();
        let body = response().to_string();
        for suffix in [",\"client_id\":\"duplicate\"", ",\"client_\\u0069d\":\"duplicate\""] {
            let duplicate = format!("{}{suffix}}}", &body[..body.len() - 1]);
            assert!(owner.admit_response(duplicate.as_bytes(), &["authorization_code", "refresh_token"]).is_err());
        }
        for body in [json!([response()]), json!(["client", "native", NATIVE_REGISTRATION_REDIRECT_URIS, "none", ["authorization_code"], ["code"]]), Value::Null] {
            assert!(admit(&owner, &body).is_err());
        }
        assert!(owner.admit_response(&vec![b' '; MAX_OAUTH_METADATA_BYTES + 1], &["authorization_code"]).is_err());
    }

    #[test]
    fn token_origin_permission_does_not_grant_registration_write_authority() {
        let mut owner = registration();
        owner.discovery.issuers[0] = owner.discovery.issuers[0].clone()
            .with_endpoint_origin(url("https://separate.example/")).unwrap();
        let body = br#"{"registration_endpoint":"https://separate.example/register","grant_types_supported":["authorization_code","refresh_token"]}"#;
        assert!(matches!(owner.registration_endpoint(&owner.discovery.issuers[0], body), Err(OAuthRegistrationError::EndpointNotTrusted)));
        let owner = owner.with_registration_origin(url("https://separate.example/")).unwrap();
        let (endpoint, grants) = owner.registration_endpoint(&owner.discovery.issuers[0], body).unwrap();
        assert_eq!(endpoint.as_str(), "https://separate.example/register");
        assert_eq!(grants, ["authorization_code", "refresh_token"]);
    }

    #[test]
    fn missing_refresh_advertisement_requests_only_authorization_code() {
        let owner = registration();
        let body = br#"{"registration_endpoint":"https://issuer.example/register"}"#;
        let (_, grants) = owner.registration_endpoint(&owner.discovery.issuers[0], body).unwrap();
        assert_eq!(grants, ["authorization_code"]);
        for body in [
            br#"{}"#.as_slice(),
            br#"{"registration_endpoint":null}"#.as_slice(),
            br#"{"registration_endpoint":"http://issuer.example/register"}"#.as_slice(),
            br#"{"registration_endpoint":"https://issuer.example/register?q=1"}"#.as_slice(),
            br#"{"registration_endpoint":"https://issuer.example/register","registration_endpoint":"https://issuer.example/other"}"#.as_slice(),
        ] {
            assert!(owner.registration_endpoint(&owner.discovery.issuers[0], body).is_err());
        }
    }

    #[test]
    fn initial_access_token_is_endpoint_bound_redacted_and_not_laundered_as_client_id() {
        let endpoint = url("https://issuer.example/register");
        let owner = registration().with_initial_access_token(
            BoundBearerCredential::bind(endpoint.clone(), "initial-secret").unwrap(),
        ).unwrap();
        assert!(!format!("{owner:?}").contains("initial-secret"));
        assert!(owner.request_headers(&endpoint).unwrap().contains(&("Authorization".to_owned(), "Bearer initial-secret".to_owned())));
        assert!(matches!(owner.request_headers(&url("https://issuer.example/token")), Err(OAuthRegistrationError::InitialCredentialRejected)));
        let mut reflected = response();
        reflected["client_id"] = json!("prefix-initial-secret-suffix");
        assert!(matches!(admit(&owner, &reflected), Err(OAuthRegistrationError::ResponseRejected)));
        assert!(admit(&owner, &response()).is_ok());
    }

    #[test]
    fn empty_scopes_are_not_replaced_with_peer_default_authority() {
        let mut owner = registration();
        owner.discovery.scopes.clear();
        let mut body = response();
        body.as_object_mut().unwrap().remove("scope");
        assert!(admit(&owner, &body).is_ok());
        body["scope"] = json!("admin");
        assert!(admit(&owner, &body).is_err());
    }
}
