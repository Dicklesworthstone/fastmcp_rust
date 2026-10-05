//! Explicit selection of preregistration, CIMD and one-shot DCR.
//!
//! Constructing the input `NativeClientRegistration` explicitly authorizes the
//! DCR fallback. A discovered flag alone never creates registration authority.
//! Preferred identity failure does not try the next method: selection happens
//! before login, not in response to a rejected credential or callback.

use std::fmt;
use std::future::Future;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::http::h1::{HttpClient, Method, RedirectPolicy, RetryPolicy};
use asupersync::types::Time;

use super::{NativeClientRegistration, OAuthRegistrationError, RegisteredNativeClient};
use super::metadata_document::{
    MAX_NATIVE_CLIENT_ID_BYTES, MetadataDocumentDiscovery, MetadataDocumentError,
    NativeClientMetadata,
};
use super::super::{
    MAX_OAUTH_METADATA_BYTES, OAuthDiscoveryError, TrustedOAuthIssuer, check_context,
    decode_metadata, discovery_deadline, issuer, present, validate_headers, within,
};
use crate::http_auth::CanonicalHttpUrl;
use crate::http_auth::managed::{ManagedOAuthSession, OAuthSessionError, OAuthSessionPolicy};
use crate::http_auth::oauth::{OAuthClient, OAuthClientConfiguration, OAuthError};

#[derive(serde::Deserialize)]
struct CimdIssuerMetadata {
    #[serde(default, deserialize_with = "present")]
    client_id_metadata_document_supported: Option<bool>,
}

/// Provenance of the selected client identity, not an authentication claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeClientRegistrationMethod {
    Preregistered,
    MetadataDocument,
    DynamicRegistration,
}

#[derive(Debug)]
pub enum NativeClientSelectionError {
    InvalidPolicy,
    Metadata(MetadataDocumentError),
    Discovery(OAuthDiscoveryError),
    Registration(OAuthRegistrationError),
}

impl fmt::Display for NativeClientSelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid native client registration selection policy",
            Self::Metadata(_) => "native client metadata declaration rejected",
            Self::Discovery(_) => "native client registration selection discovery failed",
            Self::Registration(_) => "explicit native client registration attempt failed",
        })
    }
}

impl std::error::Error for NativeClientSelectionError {}

impl From<OAuthDiscoveryError> for NativeClientSelectionError {
    fn from(error: OAuthDiscoveryError) -> Self { Self::Discovery(error) }
}

/// One explicit resolver with registration priority frozen before network I/O.
///
/// The input owns the same resource, issuer allowlist, scope, TLS and DCR write
/// grants used by standalone registration. A supplied preregistered ID wins;
/// otherwise a supplied CIMD document wins when supported by the selected issuer;
/// otherwise the already-authorized DCR attempt is used. No automatic retry or
/// fallback occurs after a method has been selected. This owner is not Clone.
pub struct NativeClientRegistrationChoice {
    registration: NativeClientRegistration,
    preregistered: Option<String>,
    metadata: Option<NativeClientMetadata>,
}

impl fmt::Debug for NativeClientRegistrationChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeClientRegistrationChoice")
            .field("has_preregistration", &self.preregistered.is_some())
            .field("has_metadata_document", &self.metadata.is_some())
            .finish_non_exhaustive()
    }
}

impl NativeClientRegistrationChoice {
    pub fn new(registration: NativeClientRegistration) -> Self {
        Self { registration, preregistered: None, metadata: None }
    }

    /// Adds an independently provisioned ID for this plan's selected issuer.
    /// URL-form preregistered IDs remain preregistered: they do not implicitly
    /// enable CIMD or authorize any metadata fetch. Multiple candidate issuers
    /// are refused because one opaque registration cannot belong to them all.
    pub fn with_preregistered_client_id(mut self, client_id: impl Into<String>) -> Result<Self, NativeClientSelectionError> {
        let client_id = client_id.into();
        if self.preregistered.is_some() || self.registration.discovery.issuers.len() != 1
            || client_id.is_empty() || client_id.len() > MAX_NATIVE_CLIENT_ID_BYTES
            || client_id.chars().any(char::is_control)
        {
            return Err(NativeClientSelectionError::InvalidPolicy);
        }
        self.preregistered = Some(client_id);
        Ok(self)
    }

    /// Adds a portable final-core CIMD identity. This grants no DCR permission
    /// beyond the consuming input registration owner and no enterprise identity.
    pub fn with_metadata_document(mut self, metadata: NativeClientMetadata) -> Result<Self, NativeClientSelectionError> {
        if self.metadata.is_some() { return Err(NativeClientSelectionError::InvalidPolicy); }
        // Reuse the CIMD profile's scope admission; do not create a second
        // parser or interpret the public document differently in selection.
        MetadataDocumentDiscovery::new(
            self.registration.discovery.resource.clone(),
            self.registration.discovery.issuers.clone(),
            metadata.clone(),
            self.registration.discovery.scopes.clone(),
        ).map_err(NativeClientSelectionError::Metadata)?;
        self.metadata = Some(metadata);
        Ok(self)
    }

    /// Resolves exactly one identity after one bounded PRM/issuer traversal.
    /// The selected document is reused for a DCR POST, not rediscovered after
    /// selection. Private roots and endpoint write grants cannot change mid-flow.
    pub async fn resolve(self, cx: &Cx) -> Result<ResolvedNativeClient, NativeClientSelectionError> {
        let deadline = discovery_deadline(cx, self.registration.discovery.timeout)?;
        let issuer = self.registration.discovery.discover_resource_issuer(cx, deadline).await?;
        let selected = issuer::discover(cx, deadline, issuer, |body| self.select(issuer, body)).await?;
        check_context(cx, deadline)?;
        match selected {
            Selection::Configured { method, client_id, configuration } => Ok(ResolvedNativeClient {
                method,
                client: RegisteredNativeClient { client_id, configuration },
            }),
            Selection::Dynamic(body) => {
                let client = self.registration.register_from_discovery(cx, deadline, issuer, &body)
                    .await.map_err(NativeClientSelectionError::Registration)?;
                Ok(ResolvedNativeClient { method: NativeClientRegistrationMethod::DynamicRegistration, client })
            }
        }
    }

    fn select(&self, issuer: &TrustedOAuthIssuer, body: &[u8]) -> Result<Selection, OAuthDiscoveryError> {
        let discovery = &self.registration.discovery;
        let (authorization, token) = discovery.admit_issuer_endpoints(issuer, body)?;
        let revocation = discovery.admit_revocation_endpoint(issuer, body)?;
        let selected = if let Some(client_id) = self.preregistered.as_ref() {
            Some((NativeClientRegistrationMethod::Preregistered, client_id.as_str()))
        } else if let Some(metadata) = self.metadata.as_ref() {
            // A malformed flag is an invalid document, never false-by-default.
            let supports: CimdIssuerMetadata = decode_metadata(body)?;
            (supports.client_id_metadata_document_supported == Some(true))
                .then_some((NativeClientRegistrationMethod::MetadataDocument, metadata.client_id()))
        } else {
            None
        };
        if let Some((method, client_id)) = selected {
            let configuration = discovery.configure_client(issuer, authorization, token, revocation, client_id)?;
            return Ok(Selection::Configured { method, client_id: client_id.to_owned(), configuration });
        }
        // Admission is candidate-local, including the separate DCR write grant.
        // A valid HTTPS token endpoint alone cannot authorize registration.
        self.registration.registration_endpoint(issuer, body).map_err(|error| match error {
            OAuthRegistrationError::EndpointNotTrusted => OAuthDiscoveryError::EndpointNotTrusted,
            OAuthRegistrationError::Discovery(error) => error,
            _ => OAuthDiscoveryError::InvalidMetadata,
        })?;
        Ok(Selection::Dynamic(body.to_vec()))
    }
}

enum Selection {
    Configured {
        method: NativeClientRegistrationMethod,
        client_id: String,
        configuration: OAuthClientConfiguration,
    },
    Dynamic(Vec<u8>),
}

/// Reusable local identity; DCR, when selected, has already happened once.
/// Retrying an explicit browser login cannot create another registration.
pub struct ResolvedNativeClient {
    method: NativeClientRegistrationMethod,
    client: RegisteredNativeClient,
}

impl fmt::Debug for ResolvedNativeClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedNativeClient").field("method", &self.method).finish_non_exhaustive()
    }
}

impl ResolvedNativeClient {
    pub fn registration_method(&self) -> NativeClientRegistrationMethod { self.method }
    pub fn client(&self) -> &RegisteredNativeClient { &self.client }
    pub fn into_client(self) -> RegisteredNativeClient { self.client }

    /// Logs in with the already-selected identity; never chooses a new method
    /// because an issuer refuses a client, callback, code, scope or token.
    pub async fn authorize_managed_with_browser_driver<D, F>(
        &self, cx: &Cx, policy: OAuthSessionPolicy, timeout: Duration, driver: D,
    ) -> Result<ManagedOAuthSession, OAuthSessionError>
    where D: FnOnce(CanonicalHttpUrl) -> F,
          F: Future<Output = Result<(), OAuthError>>,
    {
        ManagedOAuthSession::authorize_with_browser_driver(cx,
            OAuthClient::new(self.client.configuration.clone()), policy, timeout, driver).await
    }
}

impl NativeClientRegistration {
    // Both standalone DCR and selection use this single POST implementation.
    // The public consuming entry points own the one-attempt guarantee; this
    // helper is visible only inside the registration module subtree.
    pub(super) async fn register_from_discovery(
        &self, cx: &Cx, mut deadline: Time, issuer: &TrustedOAuthIssuer, body: &[u8],
    ) -> Result<RegisteredNativeClient, OAuthRegistrationError> {
        if let Some(expiry) = self.initial_credential.as_ref().and_then(|credential| credential.expires_at()) {
            let remaining = expiry.checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or(OAuthRegistrationError::InitialCredentialRejected)?;
            deadline = deadline.min(discovery_deadline(cx, remaining)?);
        }
        let (authorization, token) = self.discovery.admit_issuer_endpoints(issuer, body)?;
        let revocation = self.discovery.admit_revocation_endpoint(issuer, body)?;
        let (endpoint, grants) = self.registration_endpoint(issuer, body)?;
        let payload = self.request_body(&grants)?;
        let headers = self.request_headers(&endpoint)?;
        check_context(cx, deadline)?;
        let mut builder = HttpClient::builder()
            .redirect_policy(RedirectPolicy::None).retry_policy(RetryPolicy::None)
            .no_proxy().no_cookie_store().max_body_size(MAX_OAUTH_METADATA_BYTES)
            .max_total_connections(1);
        for root in &issuer.roots { builder = builder.add_root_certificate(root.clone()); }
        let client = builder.build();
        let response = within(cx, deadline, async {
            client.request(cx, Method::Post, endpoint.as_str(), headers, payload).await
                .map_err(|_| OAuthDiscoveryError::TransportFailed)
        }).await?;
        if response.status != 201 { return Err(OAuthRegistrationError::HttpStatus { status: response.status }); }
        validate_headers(&response.headers).map_err(|_| OAuthRegistrationError::ResponseRejected)?;
        if !response.trailers.is_empty() { return Err(OAuthRegistrationError::ResponseRejected); }
        let client_id = self.admit_response(&response.body, &grants)?;
        let configuration = self.discovery.configure_client(issuer, authorization, token, revocation, &client_id)?;
        check_context(cx, deadline)?;
        Ok(RegisteredNativeClient { client_id, configuration })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn url(value: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(value).unwrap() }
    fn choice() -> NativeClientRegistrationChoice {
        NativeClientRegistrationChoice::new(NativeClientRegistration::new(
            url("https://resource.example/mcp"), vec![TrustedOAuthIssuer::new("https://issuer.example").unwrap()], "Native", Vec::new(),
        ).unwrap())
    }
    fn metadata() -> NativeClientMetadata { NativeClientMetadata::new("https://client.example/cimd.json", "Native").unwrap() }
    fn document() -> Value {
        json!({"issuer":"https://issuer.example", "authorization_endpoint":"https://issuer.example/authorize", "token_endpoint":"https://issuer.example/token", "registration_endpoint":"https://issuer.example/register", "response_types_supported":["code"], "grant_types_supported":["authorization_code","refresh_token"], "token_endpoint_auth_methods_supported":["none"], "code_challenge_methods_supported":["S256"], "authorization_response_iss_parameter_supported":true, "client_id_metadata_document_supported":true})
    }
    fn select(choice: &NativeClientRegistrationChoice, document: &Value) -> Result<Selection, OAuthDiscoveryError> {
        choice.select(&choice.registration.discovery.issuers[0], &serde_json::to_vec(document).unwrap())
    }

    #[test]
    fn preregistration_then_cimd_then_explicit_dcr_are_selected_before_login() {
        let full = choice().with_metadata_document(metadata()).unwrap().with_preregistered_client_id("already-registered").unwrap();
        assert!(matches!(select(&full, &document()).unwrap(), Selection::Configured { method: NativeClientRegistrationMethod::Preregistered, client_id, .. } if client_id == "already-registered"));
        let cimd = choice().with_metadata_document(metadata()).unwrap();
        assert!(matches!(select(&cimd, &document()).unwrap(), Selection::Configured { method: NativeClientRegistrationMethod::MetadataDocument, client_id, .. } if client_id == metadata().client_id()));
        for present in [true, false] {
            let mut body = document();
            if present { body["client_id_metadata_document_supported"] = json!(false); }
            else { body.as_object_mut().unwrap().remove("client_id_metadata_document_supported"); }
            assert!(matches!(select(&cimd, &body).unwrap(), Selection::Dynamic(bytes) if bytes == serde_json::to_vec(&body).unwrap()));
        }
        assert!(matches!(select(&choice(), &document()).unwrap(), Selection::Dynamic(_)));
    }

    #[test]
    fn malformed_cimd_advertisement_never_downgrades_to_a_registration_write() {
        let choice = choice().with_metadata_document(metadata()).unwrap();
        for value in [Value::Null, json!("true"), json!(1), json!({})] {
            let mut body = document(); body["client_id_metadata_document_supported"] = value;
            assert!(select(&choice, &body).is_err());
        }
        let body = document().to_string();
        let duplicate = format!("{},\"client_id_metadata_document_supported\":false}}", &body[..body.len()-1]);
        assert!(choice.select(&choice.registration.discovery.issuers[0], duplicate.as_bytes()).is_err());
        assert!(select(&choice, &document()).is_ok());
    }

    #[test]
    fn selected_identity_does_not_require_or_authorize_a_dcr_endpoint() {
        let mut body = document(); body.as_object_mut().unwrap().remove("registration_endpoint");
        assert!(matches!(select(&choice().with_metadata_document(metadata()).unwrap(), &body).unwrap(), Selection::Configured { method: NativeClientRegistrationMethod::MetadataDocument, .. }));
        assert!(select(&choice(), &body).is_err());
        body["registration_endpoint"] = json!("https://untrusted.example/register");
        assert!(matches!(select(&choice(), &body), Err(OAuthDiscoveryError::EndpointNotTrusted)));
        assert!(select(&choice().with_preregistered_client_id("opaque-id").unwrap(), &body).is_ok());
    }

    #[test]
    fn preregistered_url_is_not_implicitly_a_portable_metadata_identity() {
        let choice = choice().with_preregistered_client_id("https://client.example/registered").unwrap();
        let mut body = document(); body["client_id_metadata_document_supported"] = json!(false);
        assert!(matches!(select(&choice, &body).unwrap(), Selection::Configured { method: NativeClientRegistrationMethod::Preregistered, .. }));
        let registration = NativeClientRegistration::new(url("https://resource.example/mcp"),
            vec![TrustedOAuthIssuer::new("https://one.example").unwrap(), TrustedOAuthIssuer::new("https://two.example").unwrap()], "Native", Vec::new()).unwrap();
        assert!(NativeClientRegistrationChoice::new(registration).with_preregistered_client_id("not-portable").is_err());
    }

    #[test]
    fn shared_issuer_and_pkce_checks_precede_every_identity_method() {
        for candidate in [choice(), choice().with_metadata_document(metadata()).unwrap(), choice().with_preregistered_client_id("registered").unwrap()] {
            for (key, value) in [("issuer", json!("https://wrong.example")), ("code_challenge_methods_supported", json!(["plain"])), ("token_endpoint", json!("http://issuer.example/token"))] {
                let mut body = document(); body[key] = value;
                assert!(select(&candidate, &body).is_err());
            }
        }
    }
}
