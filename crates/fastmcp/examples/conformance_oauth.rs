//! Explicit HTTPS OAuth for operator-controlled conformance peers.
//!
//! With no `discovery` member, the existing preregistered trusted-endpoints
//! configuration is used. With `discovery`, protected-resource and issuer
//! metadata supply the token endpoint; `token_endpoint` and `token_root_pem`
//! must be absent. The locally configured `issuer` remains the sole trusted
//! issuer. `authorization_endpoint` remains an exact front-channel target pin.
//!
//! `discovery: {}` selects a supplied preregistered `client_id`. Alternatively,
//! `discovery.client_metadata` has `url` and `document_json` strings for the
//! exact operator-published CIMD document. The string preserves the document's
//! original bytes and duplicate members for the library's admission pass.
//! Without a preregistered ID, CIMD-only discovery never attempts registration.
//!
//! Dynamic registration requires `discovery.allow_dynamic_registration: true`
//! AND `discovery.client_name`. This selects preregistration before supported
//! CIMD before one explicitly authorized DCR attempt. Registration failure or
//! failed login never triggers another method, issuer, or anonymous fallback.
//! Registration can create remote state even when a later login fails.
//!
//! Optional `discovery.issuer_root_pem` trusts only issuer metadata and token/
//! registration endpoints. `authorization_root_pem` is still front-channel-only;
//! `resource_root_pem` covers the exact resource's PRM retrieval and MCP POSTs.
//! No peer document adds a trusted issuer, cross-origin grant, or root.
//! One absolute deadline covers discovery, registration, callback and redemption.
//! The existing short-lived grant lease separately bounds authenticated traffic.
//!
//! This is a native public-client, pre-authorized direct-redirect profile, not
//! a browser/consent agent or complete auth-suite claim. The fixed-credential
//! entry point below does not renew; `managed` composes the same login policy
//! with the library's shared refresh-grant owner and high-level HTTP client.

use std::future::Future;
use std::time::{Duration, Instant};

use asupersync::tls::{Certificate, RootCertStore};
use fastmcp_client::http_auth::BoundBearerCredential;
use fastmcp_client::http_auth::discovery::{OAuthDiscoveryPlan, TrustedOAuthIssuer};
use fastmcp_client::http_auth::discovery::registration::NativeClientRegistration;
use fastmcp_client::http_auth::discovery::registration::metadata_document::{
    MetadataDocumentDiscovery, NativeClientMetadata,
};
use fastmcp_client::http_auth::discovery::registration::selection::NativeClientRegistrationChoice;
use fastmcp_client::http_auth::driver::redirect::RedirectAuthorizationDriver;
use fastmcp_client::http_auth::driver::with_authorization_driver;
use fastmcp_client::http_auth::oauth::{OAuthClient, OAuthClientConfiguration};
use fastmcp_client::{ClientBuilder, ProtocolPolicy};
use fastmcp_core::{CanonicalHttpUrl, Cx};
use serde::{Deserialize, Deserializer};

/// Opt-in managed renewal using the same local configuration and login policy.
pub(super) mod managed;

pub(super) const ENVIRONMENT: &str = "FASTMCP_CONFORMANCE_OAUTH";
const INVALID: &str = "invalid explicit HTTPS OAuth fixture configuration";
const MAX_CONFIG_BYTES: usize = 96 * 1024;
const MAX_ROOT_PEM_BYTES: usize = 24 * 1024;

/// Deliberately no Debug: configuration can contain private infrastructure.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    preauthorized_redirect: bool,
    issuer: String,
    authorization_endpoint: String,
    #[serde(default, deserialize_with = "present")]
    token_endpoint: Option<String>,
    resource: String,
    #[serde(default, deserialize_with = "present")]
    client_id: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default = "default_timeout")]
    timeout_seconds: u64,
    authorization_root_pem: Option<String>,
    token_root_pem: Option<String>,
    resource_root_pem: Option<String>,
    #[serde(default, deserialize_with = "present")]
    discovery: Option<DiscoveryConfiguration>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoveryConfiguration {
    #[serde(default, deserialize_with = "present")]
    issuer_root_pem: Option<String>,
    #[serde(default, deserialize_with = "present")]
    client_metadata: Option<MetadataConfiguration>,
    #[serde(default)]
    allow_dynamic_registration: bool,
    #[serde(default, deserialize_with = "present")]
    client_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataConfiguration {
    url: String,
    document_json: String,
}

fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    // Null cannot select the absent/default path for mode or identity fields.
    T::deserialize(deserializer).map(Some)
}

fn default_timeout() -> u64 {
    60
}

/// A fully validated local plan, not a grant or a discovery result.
/// Boxing keeps the async operation independent of each library plan's size.
enum LoginPlan {
    TrustedEndpoints(Box<OAuthClientConfiguration>),
    PreregisteredDiscovery(Box<OAuthDiscoveryPlan>),
    MetadataDocument(Box<MetadataDocumentDiscovery>),
    RegistrationChoice(Box<NativeClientRegistrationChoice>),
}

impl LoginPlan {
    async fn resolve(self, cx: &Cx) -> Result<OAuthClientConfiguration, String> {
        match self {
            Self::TrustedEndpoints(configuration) => Ok(*configuration),
            Self::PreregisteredDiscovery(plan) => plan
                .discover(cx)
                .await
                .map_err(|_| "OAuth discovery failed".to_owned()),
            Self::MetadataDocument(plan) => plan
                .discover(cx)
                .await
                .map_err(|_| "OAuth metadata-document discovery failed".to_owned()),
            Self::RegistrationChoice(choice) => {
                let resolved = (*choice)
                    .resolve(cx)
                    .await
                    .map_err(|_| "OAuth registration selection failed".to_owned())?;
                Ok(resolved.client().configuration().clone())
            }
        }
    }
}

struct PreparedOAuth {
    login: LoginPlan,
    driver: RedirectAuthorizationDriver,
    resource: CanonicalHttpUrl,
    resource_root: Option<Certificate>,
    timeout: Duration,
}

fn parse_url(text: &str) -> Result<CanonicalHttpUrl, String> {
    CanonicalHttpUrl::parse(text).map_err(|_| INVALID.to_owned())
}

fn root(source: Option<&str>) -> Result<Option<Certificate>, String> {
    let Some(source) = source else {
        return Ok(None);
    };
    if source.is_empty() || source.len() > MAX_ROOT_PEM_BYTES {
        return Err(INVALID.to_owned());
    }
    let mut certificates =
        Certificate::from_pem(source.as_bytes()).map_err(|_| INVALID.to_owned())?;
    if certificates.len() != 1 {
        return Err(INVALID.to_owned());
    }
    let certificate = certificates.remove(0);
    if certificate.as_der().is_empty() || certificate.as_der().len() > 16 * 1024 {
        return Err(INVALID.to_owned());
    }
    RootCertStore::empty()
        .add(&certificate)
        .map_err(|_| INVALID.to_owned())?;
    Ok(Some(certificate))
}

impl DiscoveryConfiguration {
    fn prepare(
        self,
        resource: &CanonicalHttpUrl,
        issuer: String,
        client_id: Option<String>,
        scopes: Vec<String>,
        resource_root: Option<&Certificate>,
        timeout: Duration,
    ) -> Result<LoginPlan, String> {
        // A registration name without permission is almost certainly a typo;
        // never ignore it and silently choose a different path.
        if self.allow_dynamic_registration != self.client_name.is_some() {
            return Err(INVALID.to_owned());
        }
        let mut issuer = TrustedOAuthIssuer::new(issuer).map_err(|_| INVALID.to_owned())?;
        if let Some(certificate) = root(self.issuer_root_pem.as_deref())? {
            issuer = issuer
                .with_root_certificate(certificate)
                .map_err(|_| INVALID.to_owned())?;
        }
        let metadata = self
            .client_metadata
            .map(|metadata| {
                NativeClientMetadata::from_json(&metadata.url, metadata.document_json.as_bytes())
                    .map_err(|_| INVALID.to_owned())
            })
            .transpose()?;
        // Admit configured metadata and scope ceilings even if preregistration
        // wins. No invalid local policy is hidden by the preference order.
        let mut metadata_plan = metadata
            .as_ref()
            .map(|metadata| {
                MetadataDocumentDiscovery::new(
                    resource.clone(),
                    vec![issuer.clone()],
                    metadata.clone(),
                    scopes.clone(),
                )
                .map_err(|_| INVALID.to_owned())
            })
            .transpose()?;
        let discovery_timeout = timeout.min(Duration::from_secs(120));
        if self.allow_dynamic_registration {
            let mut registration = NativeClientRegistration::new(
                resource.clone(),
                vec![issuer],
                self.client_name.ok_or_else(|| INVALID.to_owned())?,
                scopes,
            )
            .map_err(|_| INVALID.to_owned())?
            .with_timeout(discovery_timeout)
            .map_err(|_| INVALID.to_owned())?;
            if let Some(certificate) = resource_root {
                registration = registration
                    .with_resource_root_certificate(certificate.clone())
                    .map_err(|_| INVALID.to_owned())?;
            }
            let mut choice = NativeClientRegistrationChoice::new(registration);
            if let Some(client_id) = client_id {
                choice = choice
                    .with_preregistered_client_id(client_id)
                    .map_err(|_| INVALID.to_owned())?;
            }
            if let Some(metadata) = metadata {
                choice = choice
                    .with_metadata_document(metadata)
                    .map_err(|_| INVALID.to_owned())?;
            }
            return Ok(LoginPlan::RegistrationChoice(Box::new(choice)));
        }
        if let Some(client_id) = client_id {
            let mut plan = OAuthDiscoveryPlan::new(
                resource.clone(),
                vec![issuer],
                client_id,
                scopes,
            )
            .map_err(|_| INVALID.to_owned())?
            .with_timeout(discovery_timeout)
            .map_err(|_| INVALID.to_owned())?;
            if let Some(certificate) = resource_root {
                plan = plan
                    .with_resource_root_certificate(certificate.clone())
                    .map_err(|_| INVALID.to_owned())?;
            }
            return Ok(LoginPlan::PreregisteredDiscovery(Box::new(plan)));
        }
        let mut plan = metadata_plan
            .take()
            .ok_or_else(|| INVALID.to_owned())?
            .with_timeout(discovery_timeout)
            .map_err(|_| INVALID.to_owned())?;
        if let Some(certificate) = resource_root {
            plan = plan
                .with_resource_root_certificate(certificate.clone())
                .map_err(|_| INVALID.to_owned())?;
        }
        Ok(LoginPlan::MetadataDocument(Box::new(plan)))
    }
}

impl PreparedOAuth {
    fn parse(raw: &str, endpoint: &CanonicalHttpUrl) -> Result<Self, String> {
        if raw.is_empty() || raw.len() > MAX_CONFIG_BYTES {
            return Err(INVALID.to_owned());
        }
        // Closed structs reject duplicate and unknown fields at every local
        // configuration level. The CIMD JSON string is separately raw-admitted.
        let config: Configuration = serde_json::from_str(raw).map_err(|_| INVALID.to_owned())?;
        if !config.preauthorized_redirect || !(1..=900).contains(&config.timeout_seconds) {
            return Err(INVALID.to_owned());
        }
        let resource = parse_url(&config.resource)?;
        if &resource != endpoint || resource.scheme() != "https" {
            return Err(INVALID.to_owned());
        }
        let timeout = Duration::from_secs(config.timeout_seconds);
        let authorization_endpoint = parse_url(&config.authorization_endpoint)?;
        let mut driver = RedirectAuthorizationDriver::new(authorization_endpoint.clone())
            .map_err(|_| INVALID.to_owned())?
            .with_timeout(timeout)
            .map_err(|_| INVALID.to_owned())?;
        if let Some(certificate) = root(config.authorization_root_pem.as_deref())? {
            driver = driver
                .with_extra_root_certificate(certificate)
                .map_err(|_| INVALID.to_owned())?;
        }
        let resource_root = root(config.resource_root_pem.as_deref())?;
        let login = match config.discovery {
            Some(discovery) => {
                // No token endpoint or token-root override may silently replace
                // the configuration that issuer discovery is meant to admit.
                if config.token_endpoint.is_some() || config.token_root_pem.is_some() {
                    return Err(INVALID.to_owned());
                }
                discovery.prepare(
                    &resource,
                    config.issuer,
                    config.client_id,
                    config.scopes,
                    resource_root.as_ref(),
                    timeout,
                )?
            }
            None => {
                let mut native = OAuthClientConfiguration::from_trusted_endpoints(
                    config.issuer,
                    authorization_endpoint,
                    parse_url(&config.token_endpoint.ok_or_else(|| INVALID.to_owned())?)?,
                    resource.clone(),
                    config.client_id.ok_or_else(|| INVALID.to_owned())?,
                    config.scopes,
                )
                .map_err(|_| INVALID.to_owned())?
                .with_authorization_timeout(timeout)
                .map_err(|_| INVALID.to_owned())?;
                if let Some(certificate) = root(config.token_root_pem.as_deref())? {
                    native = native
                        .with_extra_root_certificate(certificate)
                        .map_err(|_| INVALID.to_owned())?;
                }
                LoginPlan::TrustedEndpoints(Box::new(native))
            }
        };
        Ok(Self { login, driver, resource, resource_root, timeout })
    }
}

/// One run's access capability. Clones installed on the HTTP client share its
/// irreversible local revocation. A token is never written to stdout or a file.
pub(super) struct GrantLease {
    credential: BoundBearerCredential,
    timeout: Duration,
}

impl Drop for GrantLease {
    fn drop(&mut self) {
        self.credential.revoke();
    }
}

impl GrantLease {
    fn remaining(&self) -> Result<Duration, String> {
        let remaining = self
            .credential
            .expires_at()
            .ok_or_else(|| "OAuth credential has no expiry".to_owned())?
            .saturating_duration_since(Instant::now());
        if self.credential.is_revoked() || remaining.is_zero() {
            return Err("OAuth credential expired or was revoked".to_owned());
        }
        Ok(remaining.min(self.timeout))
    }

    /// The adapter exercises one short-lived grant. It does not claim managed
    /// refresh: stop at expiry rather than silently starting a new login.
    pub(super) async fn run<T>(
        &self,
        cx: &Cx,
        future: impl Future<Output = Result<T, String>>,
    ) -> Result<T, String> {
        if cx.checkpoint().is_err() {
            return Err("authenticated MCP run cancelled".to_owned());
        }
        if cx.timer_driver().is_none() {
            return Err("authenticated MCP run requires a timer".to_owned());
        }
        let remaining = self.remaining()?;
        let nanos = u64::try_from(remaining.as_nanos())
            .map_err(|_| "authenticated MCP deadline is invalid".to_owned())?;
        let deadline = cx.now().saturating_add_nanos(nanos);
        let deadline = cx
            .budget()
            .deadline
            .map_or(deadline, |parent| parent.min(deadline));
        let result = asupersync::time::timeout_at(deadline, future)
            .await
            .map_err(|_| "authenticated MCP run reached its deadline".to_owned())?;
        if cx.checkpoint().is_err() {
            return Err("authenticated MCP run cancelled".to_owned());
        }
        self.remaining()?;
        result
    }
}

pub(super) async fn configure(
    cx: &Cx,
    endpoint: &CanonicalHttpUrl,
    mut builder: ClientBuilder,
    raw: Option<&str>,
) -> Result<(ClientBuilder, Option<GrantLease>), String> {
    let Some(raw) = raw else {
        return Ok((builder, None));
    };
    let PreparedOAuth { login, driver, resource, resource_root, timeout } =
        PreparedOAuth::parse(raw, endpoint)?;
    // Validate the consumer before discovery or a registration write, not only
    // before redemption. Auto and a different protected resource are refused.
    if builder.selected_protocol_plan().policy() != ProtocolPolicy::ModernOnly
        || builder.selected_protocol_plan().modern_post_target() != Some(endpoint.as_str())
    {
        return Err(INVALID.to_owned());
    }
    if let Some(certificate) = resource_root {
        builder = builder
            .http_resource_root_certificate(resource, certificate)
            .map_err(|_| INVALID.to_owned())?;
    }
    let grant = with_authorization_driver(
        cx,
        timeout,
        |launcher| async move {
            let configuration = login.resolve(cx).await?;
            let client = OAuthClient::new(configuration);
            client
                .authorize(cx, move |url| launcher.launch(url))
                .await
                .map_err(|_| "OAuth login failed".to_owned())
        },
        |url| driver.drive(cx, url),
    )
    .await
    .map_err(|_| "explicit OAuth authorization failed".to_owned())?;
    let lease = GrantLease {
        credential: grant.bearer_credential().clone(),
        timeout,
    };
    lease.remaining()?;
    builder = builder.http_bearer_credential(lease.credential.clone());
    Ok((builder, Some(lease)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn endpoint() -> CanonicalHttpUrl {
        parse_url("https://resource.example/mcp").unwrap()
    }

    fn configuration() -> Value {
        json!({
            "preauthorized_redirect": true,
            "issuer": "https://issuer.example",
            "authorization_endpoint": "https://issuer.example/authorize",
            "token_endpoint": "https://issuer.example/token",
            "resource": "https://resource.example/mcp",
            "client_id": "native-client",
            "scopes": ["tools:read"]
        })
    }

    fn discovered() -> Value {
        let mut config = configuration();
        config.as_object_mut().unwrap().remove("token_endpoint");
        config["discovery"] = json!({});
        config
    }

    fn metadata() -> Value {
        let document = NativeClientMetadata::new(
            "https://CLIENT.example:443/metadata%2ejson", "Fixture",
        ).unwrap();
        json!({
            "url": document.client_id(),
            "document_json": std::str::from_utf8(document.document_json()).unwrap(),
        })
    }

    #[test]
    fn explicit_configuration_binds_resource_and_requires_preauthorization() {
        let positive = configuration();
        let prepared = PreparedOAuth::parse(&positive.to_string(), &endpoint()).unwrap();
        assert_eq!(prepared.resource, endpoint());
        assert_eq!(prepared.timeout, Duration::from_secs(60));
        for (key, value) in [
            ("preauthorized_redirect", json!(false)),
            ("resource", json!("https://resource.example/other")),
            ("resource", json!("https://resource.example/mcp?other=1")),
            ("authorization_endpoint", json!("http://127.0.0.1:8080/authorize")),
            ("token_endpoint", json!("http://127.0.0.1:8080/token")),
            ("timeout_seconds", json!(0)),
            ("timeout_seconds", json!(901)),
            ("client_id", json!("")),
        ] {
            let mut negative = positive.clone();
            negative[key] = value;
            assert!(PreparedOAuth::parse(&negative.to_string(), &endpoint()).is_err());
        }
        let mut cleartext = positive;
        cleartext["resource"] = json!("http://127.0.0.1:8080/mcp");
        assert!(PreparedOAuth::parse(
            &cleartext.to_string(), &parse_url("http://127.0.0.1:8080/mcp").unwrap(),
        ).is_err());
    }

    #[test]
    fn duplicate_unknown_and_oversized_configuration_is_not_silently_accepted() {
        let source = configuration().to_string();
        let duplicate = source.replacen(
            "\"client_id\":", "\"client_id\":\"other\",\"client_id\":", 1,
        );
        assert_ne!(source, duplicate);
        assert!(PreparedOAuth::parse(&duplicate, &endpoint()).is_err());
        let mut unknown = configuration();
        unknown["access_token"] = json!("secret-canary");
        let error = PreparedOAuth::parse(&unknown.to_string(), &endpoint()).err().unwrap();
        assert!(!error.contains("secret-canary"));
        assert!(PreparedOAuth::parse(&" ".repeat(MAX_CONFIG_BYTES + 1), &endpoint()).is_err());
        assert!(PreparedOAuth::parse("{}", &endpoint()).is_err());
    }

    #[test]
    fn malformed_private_roots_fail_during_preflight() {
        assert!(root(None).unwrap().is_none());
        for field in ["authorization_root_pem", "token_root_pem", "resource_root_pem"] {
            let mut config = configuration();
            config[field] = json!("not a certificate, secret-canary");
            let error = PreparedOAuth::parse(&config.to_string(), &endpoint()).err().unwrap();
            assert_eq!(error, INVALID);
            assert!(!error.contains("secret-canary"));
        }
        let mut config = discovered();
        config["discovery"]["issuer_root_pem"] = json!("invalid secret-canary");
        assert_eq!(PreparedOAuth::parse(&config.to_string(), &endpoint()).err().unwrap(), INVALID);
    }

    #[test]
    fn discovery_profiles_are_explicit_and_metadata_never_implies_dcr_permission() {
        let direct = PreparedOAuth::parse(&configuration().to_string(), &endpoint()).unwrap();
        assert!(matches!(direct.login, LoginPlan::TrustedEndpoints(_)));
        let mut config = discovered();
        assert!(matches!(
            PreparedOAuth::parse(&config.to_string(), &endpoint()).unwrap().login,
            LoginPlan::PreregisteredDiscovery(_)
        ));
        config["discovery"]["client_metadata"] = metadata();
        assert!(matches!(
            PreparedOAuth::parse(&config.to_string(), &endpoint()).unwrap().login,
            LoginPlan::PreregisteredDiscovery(_)
        ));
        config.as_object_mut().unwrap().remove("client_id");
        assert!(matches!(
            PreparedOAuth::parse(&config.to_string(), &endpoint()).unwrap().login,
            LoginPlan::MetadataDocument(_)
        ));
        config["discovery"]["allow_dynamic_registration"] = json!(true);
        assert!(PreparedOAuth::parse(&config.to_string(), &endpoint()).is_err());
        config["discovery"]["client_name"] = json!("Fixture");
        assert!(matches!(
            PreparedOAuth::parse(&config.to_string(), &endpoint()).unwrap().login,
            LoginPlan::RegistrationChoice(_)
        ));
        config["discovery"].as_object_mut().unwrap().remove("client_metadata");
        assert!(matches!(
            PreparedOAuth::parse(&config.to_string(), &endpoint()).unwrap().login,
            LoginPlan::RegistrationChoice(_)
        ));
        config["discovery"]["allow_dynamic_registration"] = json!(false);
        assert!(PreparedOAuth::parse(&config.to_string(), &endpoint()).is_err());
    }

    #[test]
    fn mixed_modes_and_missing_identity_fail_before_discovery() {
        let mut config = discovered();
        config.as_object_mut().unwrap().remove("client_id");
        assert!(PreparedOAuth::parse(&config.to_string(), &endpoint()).is_err());
        for (key, value) in [
            ("token_endpoint", json!("https://issuer.example/token")),
            ("token_root_pem", json!("must-not-be-ignored")),
            ("client_id", Value::Null),
            ("discovery", Value::Null),
        ] {
            let mut config = discovered();
            config[key] = value;
            assert!(PreparedOAuth::parse(&config.to_string(), &endpoint()).is_err());
        }
        for field in ["token_endpoint", "client_id"] {
            let mut config = configuration();
            config.as_object_mut().unwrap().remove(field);
            assert!(PreparedOAuth::parse(&config.to_string(), &endpoint()).is_err());
        }
    }

    #[test]
    fn nested_discovery_configuration_is_closed_presence_aware_and_duplicate_aware() {
        let source = discovered().to_string();
        for discovery in [
            r#"{"allow_dynamic_registration":true,"allow_dynamic_registration":false}"#,
            r#"{"allow_dynamic_registration":null}"#,
            r#"{"client_name":null}"#,
            r#"{"client_metadata":null}"#,
            r#"{"issuer_root_pem":null}"#,
            r#"{"unknown_grant":true}"#,
        ] {
            let negative = source.replacen("\"discovery\":{}", &format!("\"discovery\":{discovery}"), 1);
            assert_ne!(negative, source);
            assert!(PreparedOAuth::parse(&negative, &endpoint()).is_err());
        }
    }

    #[test]
    fn cimd_source_is_admitted_exactly_and_invalid_shadowed_metadata_is_not_ignored() {
        let mut config = discovered();
        config["discovery"]["client_metadata"] = metadata();
        assert!(PreparedOAuth::parse(&config.to_string(), &endpoint()).is_ok());
        let original = config["discovery"]["client_metadata"]["document_json"].as_str().unwrap().to_owned();
        let duplicate = format!("{},\"client_id\":\"https://other.example/client\"}}", &original[..original.len()-1]);
        config["discovery"]["client_metadata"]["document_json"] = json!(duplicate);
        assert!(PreparedOAuth::parse(&config.to_string(), &endpoint()).is_err());
        config["discovery"]["client_metadata"] = metadata();
        config["discovery"]["client_metadata"]["url"] = json!("https://client.example/metadata%2ejson");
        assert!(PreparedOAuth::parse(&config.to_string(), &endpoint()).is_err());
        config["discovery"]["client_metadata"] = metadata();
        let mut document: Value = serde_json::from_str(&original).unwrap();
        document["scope"] = json!("different:scope");
        config["discovery"]["client_metadata"]["document_json"] = json!(document.to_string());
        assert!(PreparedOAuth::parse(&config.to_string(), &endpoint()).is_err());
    }

    #[test]
    fn grant_lifetime_caps_traffic_and_revokes_installed_clones_on_drop() {
        let credential = BoundBearerCredential::bind_with_expiry(
            endpoint(), "test-access", Instant::now() + Duration::from_secs(300),
        ).unwrap();
        let installed = credential.clone();
        let independent = BoundBearerCredential::bind(endpoint(), "independent").unwrap();
        let lease = GrantLease { credential, timeout: Duration::from_secs(30) };
        assert_eq!(lease.remaining().unwrap(), Duration::from_secs(30));
        assert!(installed.authorization_for_target(&endpoint()).is_some());
        drop(lease);
        assert!(installed.is_revoked());
        assert!(installed.authorization_for_target(&endpoint()).is_none());
        assert!(!independent.is_revoked());
        let expired = GrantLease {
            credential: BoundBearerCredential::bind_with_expiry(endpoint(), "expired", Instant::now()).unwrap(),
            timeout: Duration::from_secs(30),
        };
        assert!(expired.remaining().is_err());
    }

    #[test]
    fn configured_oauth_rejects_an_unbound_builder_before_any_runtime_or_network_use() {
        let cx = Cx::for_testing();
        let target = endpoint();
        let mut dcr = discovered();
        dcr.as_object_mut().unwrap().remove("client_id");
        dcr["discovery"] = json!({"allow_dynamic_registration":true,"client_name":"Fixture"});
        for config in [configuration(), discovered(), dcr] {
            let raw = config.to_string();
            let mut operation = Box::pin(configure(&cx, &target, ClientBuilder::new(), Some(&raw)));
            let mut task = std::task::Context::from_waker(std::task::Waker::noop());
            match operation.as_mut().poll(&mut task) {
                std::task::Poll::Ready(Err(error)) => assert_eq!(error, INVALID),
                _ => panic!("an unbound consumer must be refused before an await or side effect"),
            }
        }
        let mut ordinary = Box::pin(configure(&cx, &target, ClientBuilder::new(), None));
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            ordinary.as_mut().poll(&mut task),
            std::task::Poll::Ready(Ok((_, None)))
        ));
    }
}
