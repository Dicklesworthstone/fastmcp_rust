//! Native public clients identified by an operator-published metadata document.
//!
//! Implements the final-core CIMD -00 client profile, not enterprise client
//! registration. The host publishes the exact admitted JSON at its HTTPS
//! client-ID URL. This module neither uploads nor fetches that document: the
//! authorization server retrieves it. Local possession of a document proves
//! neither domain ownership nor that an issuer trusts that domain.
//!
//! Trusted PRM/issuer discovery, HTTPS endpoint admission and S256 login remain
//! the existing native implementation. CIMD support is checked on each complete
//! candidate issuer document before selection. No DCR POST, client-secret
//! fallback, issuer switch or silent relogin occurs on failure.

use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use asupersync::Cx;
use asupersync::tls::Certificate;
use fastmcp_core::{AbsoluteUri, CanonicalHttpUrl};
use fastmcp_protocol::security_admission::{SecurityDocumentKind, admit_security_document_object};
use serde::Deserialize;
use serde_json::{Value, json};

use super::super::{
    OAuthDiscoveryError, OAuthDiscoveryPlan, TrustedOAuthIssuer, check_context, decode_metadata,
    discovery_deadline, issuer, present,
};
use super::{NATIVE_REGISTRATION_REDIRECT_URIS, exact_set};
use crate::http_auth::driver::{AuthorizationDriverError, with_authorization_driver};
use crate::http_auth::managed::{ManagedOAuthSession, OAuthSessionError, OAuthSessionPolicy};
use crate::http_auth::oauth::{OAuthClient, OAuthClientConfiguration, OAuthError};

/// The exact final-core metadata-document revision used by this client.
pub const CLIENT_ID_METADATA_REVISION: &str = "draft-ietf-oauth-client-id-metadata-document-00";
/// Matches the existing native client's client-ID retention limit.
pub const MAX_NATIVE_CLIENT_ID_BYTES: usize = 1024;

/// Fixed diagnostics never retain document bytes, client IDs or peer URLs.
#[derive(Debug)]
pub enum MetadataDocumentError {
    InvalidClientId,
    InvalidDocument,
    ClientIdMismatch,
    UnsupportedNativeProfile,
    ScopeNotDeclared,
    Discovery(OAuthDiscoveryError),
}

impl fmt::Display for MetadataDocumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidClientId => "invalid native metadata-document client ID",
            Self::InvalidDocument => "native client metadata document rejected",
            Self::ClientIdMismatch => {
                "metadata client ID does not exactly match its publication URL"
            }
            Self::UnsupportedNativeProfile => {
                "client metadata does not admit the native public-client profile"
            }
            Self::ScopeNotDeclared => "requested scope is outside the client metadata declaration",
            Self::Discovery(_) => "metadata-document client discovery or authorization failed",
        })
    }
}

impl std::error::Error for MetadataDocumentError {}

impl From<OAuthDiscoveryError> for MetadataDocumentError {
    fn from(error: OAuthDiscoveryError) -> Self {
        Self::Discovery(error)
    }
}

/// An exact, bounded document for the host to publish at its client-ID URL.
///
/// The native profile requires `token_endpoint_auth_method: "none"`, a client
/// name, both existing RFC 8252 loopback redirects and the authorization-code
/// grant. Refresh is optional. Unknown members stay inert and their original
/// bytes are preserved. Query-bearing IDs are deliberately refused by this
/// profile (CIMD -00 recommends omitting the query).
#[derive(Clone)]
pub struct NativeClientMetadata {
    client_id: String,
    document: Arc<[u8]>,
    scopes: Option<BTreeSet<String>>,
}

impl fmt::Debug for NativeClientMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeClientMetadata")
            .field("document_bytes", &self.document.len())
            .finish_non_exhaustive()
    }
}

impl NativeClientMetadata {
    /// Builds the native public-client metadata to serve over HTTPS.
    /// This performs no publication or registration. The host owns publication.
    pub fn new(client_id: &str, client_name: &str) -> Result<Self, MetadataDocumentError> {
        admit_client_id(client_id)?;
        if client_name.trim().is_empty()
            || client_name.len() > 256
            || client_name.chars().any(char::is_control)
        {
            return Err(MetadataDocumentError::UnsupportedNativeProfile);
        }
        let document = serde_json::to_vec(&json!({
            "client_id": client_id,
            "client_name": client_name,
            "application_type": "native",
            "redirect_uris": NATIVE_REGISTRATION_REDIRECT_URIS,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        }))
        .map_err(|_| MetadataDocumentError::InvalidDocument)?;
        Self::from_json(client_id, &document)
    }

    /// Admits the exact publication URL and document, without URL normalization
    /// for identity comparison. Raw, nested and escaped duplicate members are
    /// rejected by the shared security-document pass BEFORE materialization.
    /// The public native redirect set cannot be replaced by document fields.
    pub fn from_json(client_id: &str, bytes: &[u8]) -> Result<Self, MetadataDocumentError> {
        admit_client_id(client_id)?;
        let object =
            admit_security_document_object(SecurityDocumentKind::ClientIdMetadataDocument, bytes)
                .map_err(|_| MetadataDocumentError::InvalidDocument)?;
        if object.get("client_id").and_then(Value::as_str) != Some(client_id) {
            return Err(MetadataDocumentError::ClientIdMismatch);
        }
        let name = object
            .get("client_name")
            .and_then(Value::as_str)
            .ok_or(MetadataDocumentError::UnsupportedNativeProfile)?;
        if name.trim().is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
            return Err(MetadataDocumentError::UnsupportedNativeProfile);
        }
        if object
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            != Some("none")
            || object
                .get("application_type")
                .is_some_and(|value| value.as_str() != Some("native"))
            || [
                "client_secret",
                "client_secret_expires_at",
                "registration_access_token",
            ]
            .iter()
            .any(|name| object.contains_key(*name))
        {
            return Err(MetadataDocumentError::UnsupportedNativeProfile);
        }
        let redirects = strings(object.get("redirect_uris"))?;
        if !exact_set(&redirects, &NATIVE_REGISTRATION_REDIRECT_URIS) {
            return Err(MetadataDocumentError::UnsupportedNativeProfile);
        }
        // RFC 7591 defaults apply only to true absence, never explicit null.
        let grants = object.get("grant_types").map_or_else(
            || Ok(vec!["authorization_code".to_owned()]),
            |value| strings(Some(value)),
        )?;
        if !exact_set(&grants, &["authorization_code"])
            && !exact_set(&grants, &["authorization_code", "refresh_token"])
        {
            return Err(MetadataDocumentError::UnsupportedNativeProfile);
        }
        let responses = object
            .get("response_types")
            .map_or_else(|| Ok(vec!["code".to_owned()]), |value| strings(Some(value)))?;
        if !exact_set(&responses, &["code"]) {
            return Err(MetadataDocumentError::UnsupportedNativeProfile);
        }
        let scopes = object
            .get("scope")
            .map(|value| {
                let scope = value
                    .as_str()
                    .ok_or(MetadataDocumentError::UnsupportedNativeProfile)?;
                let parts: Vec<_> = scope.split(' ').collect();
                if parts.is_empty()
                    || parts.len() > 128
                    || parts.iter().any(|part| {
                        part.is_empty()
                            || !part
                                .bytes()
                                .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
                    })
                {
                    return Err(MetadataDocumentError::UnsupportedNativeProfile);
                }
                let set: BTreeSet<_> = parts.iter().map(|part| (*part).to_owned()).collect();
                if set.len() != parts.len() {
                    return Err(MetadataDocumentError::UnsupportedNativeProfile);
                }
                Ok(set)
            })
            .transpose()?;
        Ok(Self {
            client_id: client_id.to_owned(),
            document: Arc::from(bytes),
            scopes,
        })
    }

    /// Exact URL spelling used in both authorization and token requests.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Exact admitted bytes for the host's HTTPS `application/json` response.
    /// Returning these bytes does not verify that the document was published.
    pub fn document_json(&self) -> &[u8] {
        &self.document
    }

    fn admits_scopes(&self, scopes: &[String]) -> bool {
        self.scopes
            .as_ref()
            .is_none_or(|declared| scopes.iter().all(|scope| declared.contains(scope)))
    }
}

fn strings(value: Option<&Value>) -> Result<Vec<String>, MetadataDocumentError> {
    let values = value
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty() && values.len() <= 128)
        .ok_or(MetadataDocumentError::UnsupportedNativeProfile)?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(MetadataDocumentError::UnsupportedNativeProfile)
        })
        .collect()
}

fn admit_client_id(value: &str) -> Result<(), MetadataDocumentError> {
    let wire = AbsoluteUri::parse_with_max_bytes(value, MAX_NATIVE_CLIENT_ID_BYTES)
        .map_err(|_| MetadataDocumentError::InvalidClientId)?;
    if !wire.scheme().is("https") || wire.query().is_some() || wire.fragment().is_some() {
        return Err(MetadataDocumentError::InvalidClientId);
    }
    let (authority, path) = wire
        .hier_part()
        .strip_prefix("//")
        .and_then(|hier| hier.split_once('/'))
        .ok_or(MetadataDocumentError::InvalidClientId)?;
    if authority.is_empty() || authority.contains('@') || path.split('/').any(dot_segment) {
        return Err(MetadataDocumentError::InvalidClientId);
    }
    // Network syntax validation is separate. Never replace `value` with the
    // WHATWG spelling: scheme/host case, explicit port and percent-hex spelling
    // are significant in the required simple-string client-ID comparison.
    let network =
        CanonicalHttpUrl::parse(value).map_err(|_| MetadataDocumentError::InvalidClientId)?;
    if network.scheme() != "https" || network.has_userinfo() || network.fragment().is_some() {
        return Err(MetadataDocumentError::InvalidClientId);
    }
    Ok(())
}

fn dot_segment(segment: &str) -> bool {
    // WHATWG collapses percent-encoded dots too. Inspect the original path
    // before parsing can erase an illegal single-dot or double-dot segment.
    let normalized = segment.replace("%2e", ".").replace("%2E", ".");
    matches!(normalized.as_str(), "." | "..")
}

/// Resource- and issuer-bound native CIMD discovery. The document is chosen
/// locally, never from a peer challenge, DCR response or enterprise registration.
/// A supplied PRM/issuer allowlist remains the sole source of issuer trust.
pub struct MetadataDocumentDiscovery {
    discovery: OAuthDiscoveryPlan,
    metadata: NativeClientMetadata,
}

impl fmt::Debug for MetadataDocumentDiscovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetadataDocumentDiscovery")
            .finish_non_exhaustive()
    }
}

impl MetadataDocumentDiscovery {
    pub fn new(
        resource: CanonicalHttpUrl,
        issuers: Vec<TrustedOAuthIssuer>,
        metadata: NativeClientMetadata,
        scopes: Vec<String>,
    ) -> Result<Self, MetadataDocumentError> {
        let discovery = OAuthDiscoveryPlan::with_client_id(resource, issuers, None, scopes)?;
        if !metadata.admits_scopes(&discovery.scopes) {
            return Err(MetadataDocumentError::ScopeNotDeclared);
        }
        Ok(Self {
            discovery,
            metadata,
        })
    }

    /// Sets the shared discovery deadline, with the existing 120-second cap.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, MetadataDocumentError> {
        self.discovery = self.discovery.with_timeout(timeout)?;
        Ok(self)
    }

    /// Adds explicit trust only for the configured resource's PRM and MCP POSTs.
    pub fn with_resource_root_certificate(
        mut self,
        root: Certificate,
    ) -> Result<Self, MetadataDocumentError> {
        self.discovery = self.discovery.with_resource_root_certificate(root)?;
        Ok(self)
    }

    pub fn metadata(&self) -> &NativeClientMetadata {
        &self.metadata
    }

    /// Reads PRM and issuer metadata, then returns a native OAuth configuration.
    /// Only an explicitly true CIMD support flag is accepted. Each permitted
    /// metadata location passes the COMPLETE code-flow/CIMD admission before
    /// becoming the selected document. No registration or client-document fetch
    /// is performed, and no failure falls back to another registration method.
    pub async fn discover(
        &self,
        cx: &Cx,
    ) -> Result<OAuthClientConfiguration, MetadataDocumentError> {
        let deadline = discovery_deadline(cx, self.discovery.timeout)?;
        let selected = self
            .discovery
            .discover_resource_issuer(cx, deadline)
            .await?;
        let configuration = issuer::discover(cx, deadline, selected, |body| {
            self.admit_issuer(selected, body)
        })
        .await?;
        check_context(cx, deadline)?;
        Ok(configuration)
    }

    fn admit_issuer(
        &self,
        selected: &TrustedOAuthIssuer,
        body: &[u8],
    ) -> Result<OAuthClientConfiguration, OAuthDiscoveryError> {
        let (authorization, token) = self.discovery.admit_issuer_endpoints(selected, body)?;
        let metadata: CimdIssuerMetadata = decode_metadata(body)?;
        if metadata.client_id_metadata_document_supported != Some(true) {
            return Err(OAuthDiscoveryError::UnsupportedFlow);
        }
        let revocation = self.discovery.admit_revocation_endpoint(selected, body)?;
        self.discovery.configure_client(
            selected,
            authorization,
            token,
            revocation,
            self.metadata.client_id(),
        )
    }

    /// Uses the discovered URL-form client ID in the existing native PKCE login
    /// and rotating-grant owner. Discovery and login share the outer deadline.
    /// The host driver may wait for the callback response without deadlocking
    /// the listener. No client metadata URL is treated as authentication proof.
    pub async fn authorize_managed_with_browser_driver<D, F>(
        &self,
        cx: &Cx,
        policy: OAuthSessionPolicy,
        timeout: Duration,
        driver: D,
    ) -> Result<ManagedOAuthSession, MetadataDocumentError>
    where
        D: FnOnce(CanonicalHttpUrl) -> F,
        F: Future<Output = Result<(), OAuthError>>,
    {
        with_authorization_driver(
            cx,
            timeout,
            |launcher| async move {
                let configuration = self.discover(cx).await?;
                ManagedOAuthSession::authorize(
                    cx,
                    OAuthClient::new(configuration),
                    policy,
                    move |url| launcher.launch(url),
                )
                .await
                .map_err(|error| {
                    MetadataDocumentError::Discovery(OAuthDiscoveryError::Login(error))
                })
            },
            driver,
        )
        .await
        .map_err(|error| match error {
            AuthorizationDriverError::Operation(error) => error,
            AuthorizationDriverError::Driver(error) => {
                let error = match error {
                    OAuthError::Cancelled => OAuthSessionError::Cancelled,
                    OAuthError::TimedOut => OAuthSessionError::TimedOut,
                    error => OAuthSessionError::OAuth(error),
                };
                MetadataDocumentError::Discovery(OAuthDiscoveryError::Login(error))
            }
        })
    }
}

#[derive(Deserialize)]
struct CimdIssuerMetadata {
    #[serde(default, deserialize_with = "present")]
    client_id_metadata_document_supported: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "https://client.example/metadata.json";

    fn document() -> Value {
        serde_json::from_slice(
            NativeClientMetadata::new(ID, "Native app")
                .unwrap()
                .document_json(),
        )
        .unwrap()
    }

    fn url(value: &str) -> CanonicalHttpUrl {
        CanonicalHttpUrl::parse(value).unwrap()
    }

    fn plan(
        metadata: NativeClientMetadata,
        scopes: Vec<String>,
    ) -> Result<MetadataDocumentDiscovery, MetadataDocumentError> {
        MetadataDocumentDiscovery::new(
            url("https://resource.example/mcp"),
            vec![TrustedOAuthIssuer::new("https://issuer.example/tenant").unwrap()],
            metadata,
            scopes,
        )
    }

    fn issuer_document() -> Value {
        json!({
            "issuer":"https://issuer.example/tenant",
            "authorization_endpoint":"https://issuer.example/authorize",
            "token_endpoint":"https://issuer.example/token",
            "response_types_supported":["code"],
            "grant_types_supported":["authorization_code","refresh_token"],
            "token_endpoint_auth_methods_supported":["none"],
            "code_challenge_methods_supported":["S256"],
            "authorization_response_iss_parameter_supported":true,
            "client_id_metadata_document_supported":true
        })
    }

    #[test]
    fn generated_native_document_is_usable_without_remote_registration() {
        let metadata = NativeClientMetadata::new(ID, "Native app").unwrap();
        let value: Value = serde_json::from_slice(metadata.document_json()).unwrap();
        assert_eq!(value["client_id"], ID);
        assert_eq!(
            value["redirect_uris"],
            json!(NATIVE_REGISTRATION_REDIRECT_URIS)
        );
        assert_eq!(value["token_endpoint_auth_method"], "none");
        assert!(value.get("client_secret").is_none());
        let plan = plan(metadata, Vec::new()).unwrap();
        assert!(
            plan.discovery.client_id.is_none(),
            "this is not preregistered discovery"
        );
        assert!(
            plan.admit_issuer(
                &plan.discovery.issuers[0],
                &serde_json::to_vec(&issuer_document()).unwrap()
            )
            .is_ok()
        );
    }

    #[test]
    fn client_id_identity_preserves_spelling_and_refuses_canonical_aliases() {
        for id in [
            "HTTPS://CLIENT.EXAMPLE:443/meta%64ata.json",
            "https://client.example/",
            "https://client.example/m%2Fname.json",
        ] {
            let metadata = NativeClientMetadata::new(id, "Native app").unwrap();
            assert_eq!(metadata.client_id(), id);
            let value: Value = serde_json::from_slice(metadata.document_json()).unwrap();
            assert_eq!(value["client_id"], id);
            if id != "https://client.example/" {
                assert!(matches!(
                    NativeClientMetadata::from_json(ID, metadata.document_json()),
                    Err(MetadataDocumentError::ClientIdMismatch)
                ));
            }
        }
        let a =
            NativeClientMetadata::new("https://CLIENT.example:443/metadata.json", "App").unwrap();
        assert_eq!(url(a.client_id()), url(ID));
        assert!(matches!(
            NativeClientMetadata::from_json(ID, a.document_json()),
            Err(MetadataDocumentError::ClientIdMismatch)
        ));
    }

    #[test]
    fn illegal_identifiers_are_refused_before_normalization_can_hide_them() {
        for id in [
            "http://client.example/metadata.json",
            "https://client.example",
            "https://user@client.example/m",
            "https://@client.example/m",
            "https://client.example/m#",
            "https://client.example/m?",
            "https://client.example/m?q=1",
            "https://client.example/a/../m",
            "https://client.example/a/./m",
            "https://client.example/a/%2e%2E/m",
            "https://client.example/a/.%2e/m",
            "https://client.example/a/%2E/m",
            "https://client.example/a\\m",
            "https://client.example/雪",
        ] {
            assert!(
                matches!(
                    NativeClientMetadata::new(id, "App"),
                    Err(MetadataDocumentError::InvalidClientId)
                ),
                "unexpected admission for {id}"
            );
        }
        assert!(
            NativeClientMetadata::new(
                &format!(
                    "https://client.example/{}",
                    "x".repeat(MAX_NATIVE_CLIENT_ID_BYTES)
                ),
                "App"
            )
            .is_err()
        );
    }

    #[test]
    fn nested_duplicate_members_and_malformed_security_documents_are_refused() {
        let valid = document().to_string();
        let duplicate = valid.replacen(
            "\"client_id\":",
            "\"client_id\":\"other\",\"client_id\":",
            1,
        );
        let nested = format!(
            "{},\"custom\":{{\"x\":1,\"\\u0078\":2}}}}",
            &valid[..valid.len() - 1]
        );
        for source in [
            duplicate,
            nested,
            format!("[{valid}]"),
            format!("{valid}{valid}"),
            format!("\u{feff}{valid}"),
        ] {
            assert!(matches!(
                NativeClientMetadata::from_json(ID, source.as_bytes()),
                Err(MetadataDocumentError::InvalidDocument)
            ));
        }
        assert!(NativeClientMetadata::from_json(ID, &[0xff]).is_err());
        let mut exact = valid.into_bytes();
        exact.resize(
            SecurityDocumentKind::ClientIdMetadataDocument.byte_limit(),
            b' ',
        );
        assert!(NativeClientMetadata::from_json(ID, &exact).is_ok());
        exact.push(b' ');
        assert!(matches!(
            NativeClientMetadata::from_json(ID, &exact),
            Err(MetadataDocumentError::InvalidDocument)
        ));
    }

    #[test]
    fn public_native_profile_cannot_acquire_secrets_or_change_callback_authority() {
        let original = document();
        for (key, value) in [
            ("client_secret", json!("private-canary")),
            ("client_secret", Value::Null),
            ("client_secret_expires_at", json!(0)),
            ("registration_access_token", Value::Null),
            ("token_endpoint_auth_method", json!("client_secret_basic")),
            ("token_endpoint_auth_method", json!("private_key_jwt")),
            ("application_type", json!("web")),
            ("client_name", json!("\nprivate-canary")),
            (
                "redirect_uris",
                json!([
                    "http://127.0.0.1/other",
                    NATIVE_REGISTRATION_REDIRECT_URIS[1]
                ]),
            ),
            (
                "redirect_uris",
                json!([
                    NATIVE_REGISTRATION_REDIRECT_URIS[0],
                    NATIVE_REGISTRATION_REDIRECT_URIS[0]
                ]),
            ),
            ("grant_types", json!(["client_credentials"])),
            ("grant_types", Value::Null),
            ("response_types", json!(["token"])),
            ("scope", json!("read read")),
            ("scope", json!("read\twrite")),
            ("scope", Value::Null),
        ] {
            let mut changed = original.clone();
            changed[key] = value;
            let error = NativeClientMetadata::from_json(ID, &serde_json::to_vec(&changed).unwrap())
                .unwrap_err();
            assert!(!format!("{error:?} {error}").contains("private-canary"));
            assert!(
                NativeClientMetadata::from_json(ID, &serde_json::to_vec(&original).unwrap())
                    .is_ok()
            );
        }
    }

    #[test]
    fn optional_grants_and_inert_extensions_keep_exact_source_bytes() {
        let mut value = document();
        value.as_object_mut().unwrap().remove("grant_types");
        value.as_object_mut().unwrap().remove("response_types");
        value.as_object_mut().unwrap().remove("application_type");
        value["custom"] = json!({"label":"private-canary", "nested":[1,2,3]});
        let source = format!(" \n{}\n ", value);
        let metadata = NativeClientMetadata::from_json(ID, source.as_bytes()).unwrap();
        assert_eq!(metadata.document_json(), source.as_bytes());
        assert!(!format!("{metadata:?}").contains("private-canary"));
    }

    #[test]
    fn declared_scopes_bound_discovery_without_inventing_authority() {
        let mut value = document();
        value["scope"] = json!("read write");
        let metadata =
            NativeClientMetadata::from_json(ID, &serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(plan(metadata.clone(), vec!["read".to_owned()]).is_ok());
        assert!(plan(metadata.clone(), Vec::new()).is_ok());
        assert!(matches!(
            plan(metadata, vec!["admin".to_owned()]),
            Err(MetadataDocumentError::ScopeNotDeclared)
        ));
    }

    #[test]
    fn issuer_must_explicitly_support_cimd_and_the_unchanged_secure_code_flow() {
        let plan = plan(NativeClientMetadata::new(ID, "App").unwrap(), Vec::new()).unwrap();
        let issuer = &plan.discovery.issuers[0];
        let positive = issuer_document();
        let admit = |value: &Value| plan.admit_issuer(issuer, &serde_json::to_vec(value).unwrap());
        assert!(admit(&positive).is_ok());
        let mut absent = positive.clone();
        absent
            .as_object_mut()
            .unwrap()
            .remove("client_id_metadata_document_supported");
        assert!(matches!(
            admit(&absent),
            Err(OAuthDiscoveryError::UnsupportedFlow)
        ));
        for (key, value) in [
            ("client_id_metadata_document_supported", json!(false)),
            ("client_id_metadata_document_supported", json!("true")),
            ("client_id_metadata_document_supported", Value::Null),
            ("issuer", json!("https://issuer.example/other")),
            (
                "authorization_endpoint",
                json!("https://other.example/authorize"),
            ),
            (
                "token_endpoint_auth_methods_supported",
                json!(["client_secret_basic"]),
            ),
            ("code_challenge_methods_supported", json!(["plain"])),
            (
                "authorization_response_iss_parameter_supported",
                json!(false),
            ),
        ] {
            let mut negative = positive.clone();
            negative[key] = value;
            assert!(admit(&negative).is_err());
            assert!(admit(&positive).is_ok());
        }
        let source = positive.to_string();
        let duplicate = format!(
            "{},\"client_id_metadata_document_supported\":false}}",
            &source[..source.len() - 1]
        );
        assert!(plan.admit_issuer(issuer, duplicate.as_bytes()).is_err());
    }
}
