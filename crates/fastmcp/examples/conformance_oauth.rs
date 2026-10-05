//! Opt-in, preregistered OAuth for operator-controlled HTTPS conformance peers.
//!
//! Configuration is local trust input, never inferred from a scenario name,
//! challenge, redirect, or an existing bearer token. This is the direct-redirect
//! authorization-code profile only; it does not emulate a browser, approve
//! consent, perform DCR, discover issuers, or claim the complete auth suite.

use std::future::Future;
use std::time::{Duration, Instant};

use asupersync::tls::{Certificate, RootCertStore};
use fastmcp_client::http_auth::BoundBearerCredential;
use fastmcp_client::http_auth::driver::redirect::RedirectAuthorizationDriver;
use fastmcp_client::http_auth::oauth::{OAuthClient, OAuthClientConfiguration};
use fastmcp_client::{ClientBuilder, ProtocolPolicy};
use fastmcp_core::{CanonicalHttpUrl, Cx};
use serde::Deserialize;

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
    token_endpoint: String,
    resource: String,
    client_id: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default = "default_timeout")]
    timeout_seconds: u64,
    authorization_root_pem: Option<String>,
    token_root_pem: Option<String>,
    resource_root_pem: Option<String>,
}

fn default_timeout() -> u64 {
    60
}

struct PreparedOAuth {
    client: OAuthClient,
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

impl PreparedOAuth {
    fn parse(raw: &str, endpoint: &CanonicalHttpUrl) -> Result<Self, String> {
        if raw.is_empty() || raw.len() > MAX_CONFIG_BYTES {
            return Err(INVALID.to_owned());
        }
        // Deriving a closed struct rejects duplicate known members as well as
        // unknown ones; do not deserialize through Value and lose duplicates.
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
        let mut native = OAuthClientConfiguration::from_trusted_endpoints(
            config.issuer,
            authorization_endpoint.clone(),
            parse_url(&config.token_endpoint)?,
            resource.clone(),
            config.client_id,
            config.scopes,
        )
        .map_err(|_| INVALID.to_owned())?
        .with_authorization_timeout(timeout)
        .map_err(|_| INVALID.to_owned())?;
        let mut driver = RedirectAuthorizationDriver::new(authorization_endpoint)
            .map_err(|_| INVALID.to_owned())?
            .with_timeout(timeout)
            .map_err(|_| INVALID.to_owned())?;
        if let Some(certificate) = root(config.authorization_root_pem.as_deref())? {
            driver = driver
                .with_extra_root_certificate(certificate)
                .map_err(|_| INVALID.to_owned())?;
        }
        if let Some(certificate) = root(config.token_root_pem.as_deref())? {
            native = native
                .with_extra_root_certificate(certificate)
                .map_err(|_| INVALID.to_owned())?;
        }
        let resource_root = root(config.resource_root_pem.as_deref())?;
        Ok(Self {
            client: OAuthClient::new(native),
            driver,
            resource,
            resource_root,
            timeout,
        })
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
    let prepared = PreparedOAuth::parse(raw, endpoint)?;
    // Validate the consumer before spending the authorization code. This
    // cannot add a credential to Auto fallback or to a different resource.
    if builder.selected_protocol_plan().policy() != ProtocolPolicy::ModernOnly
        || builder.selected_protocol_plan().modern_post_target() != Some(endpoint.as_str())
    {
        return Err(INVALID.to_owned());
    }
    if let Some(certificate) = prepared.resource_root {
        builder = builder
            .http_resource_root_certificate(prepared.resource, certificate)
            .map_err(|_| INVALID.to_owned())?;
    }
    let grant = prepared
        .client
        .authorize_with_browser_driver(cx, prepared.timeout, |url| prepared.driver.drive(cx, url))
        .await
        .map_err(|_| "explicit OAuth authorization failed".to_owned())?;
    let lease = GrantLease {
        credential: grant.bearer_credential().clone(),
        timeout: prepared.timeout,
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
            (
                "authorization_endpoint",
                json!("http://127.0.0.1:8080/authorize"),
            ),
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
        assert!(
            PreparedOAuth::parse(
                &cleartext.to_string(),
                &parse_url("http://127.0.0.1:8080/mcp").unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn duplicate_unknown_and_oversized_configuration_is_not_silently_accepted() {
        let source = configuration().to_string();
        let duplicate = source.replacen(
            "\"client_id\":",
            "\"client_id\":\"other\",\"client_id\":",
            1,
        );
        assert_ne!(source, duplicate);
        assert!(PreparedOAuth::parse(&duplicate, &endpoint()).is_err());
        let mut unknown = configuration();
        unknown["access_token"] = json!("secret-canary");
        let error = PreparedOAuth::parse(&unknown.to_string(), &endpoint())
            .err()
            .unwrap();
        assert!(!error.contains("secret-canary"));
        assert!(PreparedOAuth::parse(&" ".repeat(MAX_CONFIG_BYTES + 1), &endpoint()).is_err());
        assert!(PreparedOAuth::parse("{}", &endpoint()).is_err());
    }

    #[test]
    fn malformed_private_roots_fail_during_preflight() {
        assert!(root(None).unwrap().is_none());
        for field in [
            "authorization_root_pem",
            "token_root_pem",
            "resource_root_pem",
        ] {
            let mut config = configuration();
            config[field] = json!("not a certificate, secret-canary");
            let error = PreparedOAuth::parse(&config.to_string(), &endpoint())
                .err()
                .unwrap();
            assert_eq!(error, INVALID);
            assert!(!error.contains("secret-canary"));
        }
    }

    #[test]
    fn grant_lifetime_caps_traffic_and_revokes_installed_clones_on_drop() {
        let credential = BoundBearerCredential::bind_with_expiry(
            endpoint(),
            "test-access",
            Instant::now() + Duration::from_secs(300),
        )
        .unwrap();
        let installed = credential.clone();
        let independent = BoundBearerCredential::bind(endpoint(), "independent").unwrap();
        let lease = GrantLease {
            credential,
            timeout: Duration::from_secs(30),
        };
        assert_eq!(lease.remaining().unwrap(), Duration::from_secs(30));
        assert!(installed.authorization_for_target(&endpoint()).is_some());
        drop(lease);
        assert!(installed.is_revoked());
        assert!(installed.authorization_for_target(&endpoint()).is_none());
        assert!(!independent.is_revoked());
        let expired = GrantLease {
            credential: BoundBearerCredential::bind_with_expiry(
                endpoint(),
                "expired",
                Instant::now(),
            )
            .unwrap(),
            timeout: Duration::from_secs(30),
        };
        assert!(expired.remaining().is_err());
    }

    #[test]
    fn configured_oauth_rejects_an_unbound_builder_before_any_runtime_or_network_use() {
        let cx = Cx::for_testing();
        let target = endpoint();
        let raw = configuration().to_string();
        let mut operation = Box::pin(configure(&cx, &target, ClientBuilder::new(), Some(&raw)));
        let mut task = std::task::Context::from_waker(std::task::Waker::noop());
        match operation.as_mut().poll(&mut task) {
            std::task::Poll::Ready(Err(error)) => assert_eq!(error, INVALID),
            _ => panic!("an unbound consumer must be refused before an await or side effect"),
        }
        let mut ordinary = Box::pin(configure(&cx, &target, ClientBuilder::new(), None));
        assert!(matches!(
            ordinary.as_mut().poll(&mut task),
            std::task::Poll::Ready(Ok((_, None)))
        ));
    }
}
