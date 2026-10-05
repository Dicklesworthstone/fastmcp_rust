//! A bounded front-channel driver for explicitly pre-authorized HTTPS issuers.
//!
//! This is not a browser or an automatic consent agent. It makes one GET to
//! one host-configured HTTPS authorization endpoint and accepts only a direct
//! 302/303 to the exact native loopback callback with the original state.
//! A login page, consent form, intermediate redirect, or other destination
//! requires a different host driver. No credentials, cookies, proxy settings,
//! Referer, retries, or general redirect policy are inherited.
//!
//! Use with `OAuthClient::authorize_with_browser_driver` or the managed-session
//! equivalent. Native OAuth still validates issuer/state and redeems the code;
//! successful delivery of the redirect is not a successful login.

use std::collections::BTreeMap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::task::Poll;
use std::time::Duration;

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::http::h1::{HttpClient, Method, RedirectPolicy, RetryPolicy};
use asupersync::time::Sleep;
use asupersync::tls::{Certificate, RootCertStore};
use asupersync::types::Time;

use super::check_lifetime;
use crate::http_auth::CanonicalHttpUrl;
use crate::http_auth::oauth::OAuthError;

const MAX_QUERY_BYTES: usize = 16 * 1024;
const MAX_QUERY_FIELDS: usize = 32;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// A single trusted authorization endpoint and its explicit TLS trust additions.
///
/// Constructing this value is a host decision, never discovery of trust from
/// an untrusted challenge or redirect. The endpoint must be HTTPS and contain
/// no userinfo, query, or fragment. A native launch URL must match its complete
/// canonical endpoint before the first network effect.
pub struct RedirectAuthorizationDriver {
    endpoint: CanonicalHttpUrl,
    timeout: Duration,
    roots: Vec<Certificate>,
}

impl fmt::Debug for RedirectAuthorizationDriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedirectAuthorizationDriver")
            .field("timeout", &self.timeout)
            .field("extra_root_count", &self.roots.len())
            .finish_non_exhaustive()
    }
}

impl RedirectAuthorizationDriver {
    pub fn new(endpoint: CanonicalHttpUrl) -> Result<Self, OAuthError> {
        if endpoint.scheme() != "https"
            || endpoint.has_userinfo()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(OAuthError::InvalidConfiguration);
        }
        Ok(Self {
            endpoint,
            timeout: Duration::from_secs(30),
            roots: Vec::new(),
        })
    }

    /// Bounds both front-channel requests under one absolute deadline.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, OAuthError> {
        if timeout.is_zero() || timeout > Duration::from_secs(15 * 60) {
            return Err(OAuthError::InvalidConfiguration);
        }
        self.timeout = timeout;
        Ok(self)
    }

    /// Adds a private CA only for the already-bound authorization endpoint.
    /// This does not change token/resource trust or disable TLS verification.
    pub fn with_extra_root_certificate(
        mut self,
        certificate: Certificate,
    ) -> Result<Self, OAuthError> {
        if certificate.as_der().is_empty()
            || certificate.as_der().len() > 16 * 1024
            || self.roots.len() >= 8
            || self
                .roots
                .iter()
                .any(|root| root.as_der() == certificate.as_der())
        {
            return Err(OAuthError::InvalidConfiguration);
        }
        RootCertStore::empty()
            .add(&certificate)
            .map_err(|_| OAuthError::InvalidConfiguration)?;
        self.roots.push(certificate);
        Ok(self)
    }

    /// Drives one already-authorized front-channel redirect and its receipt.
    /// No form is submitted, no grant is invented, and no token is handled.
    /// The callback's 200/400 receipt is left to native OAuth to interpret.
    pub async fn drive(&self, cx: &Cx, authorization: CanonicalHttpUrl) -> Result<(), OAuthError> {
        if cx.checkpoint().is_err() {
            return Err(OAuthError::Cancelled);
        }
        if cx.timer_driver().is_none() {
            return Err(OAuthError::RuntimeTimerUnavailable);
        }
        if !cx.capabilities().io {
            return Err(OAuthError::RuntimeCapabilityUnavailable);
        }
        let binding = CallbackBinding::new(&self.endpoint, &authorization)?;
        let nanos = u64::try_from(self.timeout.as_nanos())
            .map_err(|_| OAuthError::InvalidConfiguration)?;
        let deadline = cx.now().saturating_add_nanos(nanos);
        let deadline = cx
            .budget()
            .deadline
            .map_or(deadline, |parent| parent.min(deadline));
        check_lifetime(cx, deadline)?;
        bounded(cx, deadline, async {
            let mut builder = HttpClient::builder()
                .redirect_policy(RedirectPolicy::None)
                .retry_policy(RetryPolicy::None)
                .no_proxy()
                .no_cookie_store()
                .max_body_size(MAX_RESPONSE_BYTES)
                .max_total_connections(1);
            for root in &self.roots {
                builder =
                    builder.add_root_certificate(Certificate::from_der(root.as_der().to_vec()));
            }
            let client = builder.build();
            let response = client
                .request(
                    cx,
                    Method::Get,
                    authorization.as_str(),
                    request_headers(),
                    Vec::new(),
                )
                .await
                .map_err(|_| OAuthError::TransportFailed)?;
            check_lifetime(cx, deadline)?;
            if !matches!(response.status, 302 | 303) {
                return Err(OAuthError::BrowserLaunchFailed);
            }
            let callback = binding.location(&response.headers)?;
            // The sole allowed second target is the original native callback.
            // No Authorization/Cookie/Referer reaches either request.
            let receipt = client
                .request(
                    cx,
                    Method::Get,
                    callback.as_str(),
                    request_headers(),
                    Vec::new(),
                )
                .await
                .map_err(|_| OAuthError::CallbackRejected)?;
            check_lifetime(cx, deadline)?;
            if !matches!(receipt.status, 200 | 400) {
                return Err(OAuthError::CallbackRejected);
            }
            Ok(())
        })
        .await
    }
}

fn request_headers() -> Vec<(String, String)> {
    vec![
        ("Accept".to_owned(), "text/html".to_owned()),
        ("Accept-Encoding".to_owned(), "identity".to_owned()),
        ("Connection".to_owned(), "close".to_owned()),
    ]
}

struct CallbackBinding {
    callback: CanonicalHttpUrl,
    state: String,
}

impl CallbackBinding {
    fn new(
        endpoint: &CanonicalHttpUrl,
        authorization: &CanonicalHttpUrl,
    ) -> Result<Self, OAuthError> {
        if authorization.scheme() != "https"
            || authorization.has_userinfo()
            || authorization.fragment().is_some()
            || without_query(authorization) != endpoint.as_str()
        {
            return Err(OAuthError::BrowserLaunchFailed);
        }
        let fields = query(authorization)?;
        if fields.get("response_type").map(String::as_str) != Some("code")
            || fields.get("code_challenge_method").map(String::as_str) != Some("S256")
            || fields.get("code_challenge").is_none_or(String::is_empty)
            || fields.get("client_id").is_none_or(String::is_empty)
        {
            return Err(OAuthError::BrowserLaunchFailed);
        }
        let state = fields
            .get("state")
            .filter(|value| !value.is_empty())
            .ok_or(OAuthError::BrowserLaunchFailed)?
            .clone();
        let callback = fields
            .get("redirect_uri")
            .ok_or(OAuthError::BrowserLaunchFailed)?;
        let callback =
            CanonicalHttpUrl::parse(callback).map_err(|_| OAuthError::BrowserLaunchFailed)?;
        if callback.scheme() != "http"
            || callback.has_userinfo()
            || callback.query().is_some()
            || callback.fragment().is_some()
            || callback.path() != "/oauth/callback"
        {
            return Err(OAuthError::BrowserLaunchFailed);
        }
        let authority = callback
            .as_str()
            .strip_prefix("http://")
            .and_then(|rest| rest.split_once('/').map(|(authority, _)| authority))
            .ok_or(OAuthError::BrowserLaunchFailed)?;
        let address = authority
            .parse::<SocketAddr>()
            .map_err(|_| OAuthError::BrowserLaunchFailed)?;
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(OAuthError::BrowserLaunchFailed);
        }
        Ok(Self { callback, state })
    }

    fn location(&self, headers: &[(String, String)]) -> Result<CanonicalHttpUrl, OAuthError> {
        let mut locations = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("location"));
        let (_, location) = locations.next().ok_or(OAuthError::BrowserLaunchFailed)?;
        if locations.next().is_some() || location.len() > MAX_QUERY_BYTES {
            return Err(OAuthError::BrowserLaunchFailed);
        }
        let location =
            CanonicalHttpUrl::parse(location).map_err(|_| OAuthError::BrowserLaunchFailed)?;
        if location.has_userinfo()
            || location.fragment().is_some()
            || without_query(&location) != self.callback.as_str()
        {
            return Err(OAuthError::BrowserLaunchFailed);
        }
        let fields = query(&location)?;
        if fields.get("state") != Some(&self.state)
            || fields.contains_key("code") == fields.contains_key("error")
            || fields.get("code").is_some_and(String::is_empty)
            || fields.get("error").is_some_and(String::is_empty)
        {
            return Err(OAuthError::BrowserLaunchFailed);
        }
        Ok(location)
    }
}

fn without_query(url: &CanonicalHttpUrl) -> &str {
    url.as_str()
        .split_once('?')
        .map_or(url.as_str(), |(base, _)| base)
}

fn query(url: &CanonicalHttpUrl) -> Result<BTreeMap<String, String>, OAuthError> {
    let source = url.query().ok_or(OAuthError::BrowserLaunchFailed)?;
    if source.is_empty() || source.len() > MAX_QUERY_BYTES {
        return Err(OAuthError::BrowserLaunchFailed);
    }
    let mut fields = BTreeMap::new();
    for field in source.split('&') {
        if fields.len() >= MAX_QUERY_FIELDS {
            return Err(OAuthError::BrowserLaunchFailed);
        }
        let (key, value) = field
            .split_once('=')
            .ok_or(OAuthError::BrowserLaunchFailed)?;
        let key = decode(key)?;
        let value = decode(value)?;
        if key.is_empty() || fields.insert(key, value).is_some() {
            return Err(OAuthError::BrowserLaunchFailed);
        }
    }
    Ok(fields)
}

fn decode(source: &str) -> Result<String, OAuthError> {
    let mut decoded = Vec::with_capacity(source.len());
    let mut bytes = source.bytes();
    while let Some(byte) = bytes.next() {
        decoded.push(match byte {
            b'+' => b' ',
            b'%' => {
                let high = bytes
                    .next()
                    .and_then(|b| char::from(b).to_digit(16))
                    .ok_or(OAuthError::BrowserLaunchFailed)?;
                let low = bytes
                    .next()
                    .and_then(|b| char::from(b).to_digit(16))
                    .ok_or(OAuthError::BrowserLaunchFailed)?;
                u8::try_from(high * 16 + low).map_err(|_| OAuthError::BrowserLaunchFailed)?
            }
            byte => byte,
        });
    }
    String::from_utf8(decoded).map_err(|_| OAuthError::BrowserLaunchFailed)
}

async fn bounded<T>(
    cx: &Cx,
    deadline: Time,
    future: impl Future<Output = Result<T, OAuthError>>,
) -> Result<T, OAuthError> {
    let mut future = std::pin::pin!(future);
    let sleep = {
        let _caller = Cx::set_current(Some(cx.clone()));
        Sleep::new(deadline)
    };
    let mut sleep = std::pin::pin!(sleep);
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut cancelled = std::pin::pin!(receiver.recv(cx));
    poll_fn(|task| {
        if let Err(error) = check_lifetime(cx, deadline) {
            return Poll::Ready(Err(error));
        }
        let _caller = Cx::set_current(Some(cx.clone()));
        if cancelled.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(OAuthError::Cancelled));
        }
        if sleep.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(OAuthError::TimedOut));
        }
        let result = future.as_mut().poll(task);
        if let Err(error) = check_lifetime(cx, deadline) {
            return Poll::Ready(Err(error));
        }
        result
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(value: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(value).unwrap() }

    pub(super) fn encode(value: &str) -> String {
        value.bytes().map(|byte| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => char::from(byte).to_string(),
            byte => format!("%{byte:02X}"),
        }).collect()
    }

    fn authorization(callback: &str) -> CanonicalHttpUrl {
        url(&format!(
            "https://issuer.example/authorize?client_id=native&response_type=code&code_challenge_method=S256&code_challenge=challenge&state=state%2Bbound&redirect_uri={}",
            encode(callback),
        ))
    }

    #[test]
    fn exact_ipv4_and_ipv6_callbacks_accept_code_and_denial() {
        for callback in ["http://127.0.0.1:12345/oauth/callback", "http://[::1]:12345/oauth/callback"] {
            let binding = CallbackBinding::new(&url("https://issuer.example/authorize"), &authorization(callback)).unwrap();
            for outcome in ["code=code", "error=access_denied"] {
                let location = format!("{callback}?{outcome}&state=state%2Bbound&iss=https%3A%2F%2Fissuer.example");
                let admitted = binding.location(&[("Location".to_owned(), location.clone())]).unwrap();
                assert_eq!(admitted.as_str(), location);
            }
        }
    }

    #[test]
    fn callback_binding_refuses_names_nonloopback_and_ambiguous_routes() {
        for callback in [
            "http://localhost:12345/oauth/callback", "http://192.168.1.2:12345/oauth/callback",
            "http://0.0.0.0:12345/oauth/callback", "http://[::ffff:127.0.0.1]:12345/oauth/callback",
            "http://127.0.0.1:0/oauth/callback", "https://127.0.0.1:12345/oauth/callback",
            "http://user@127.0.0.1:12345/oauth/callback", "http://127.0.0.1:12345/other",
            "http://127.0.0.1:12345/oauth/callback?x=1", "http://127.0.0.1:12345/oauth/callback#",
        ] {
            assert!(CallbackBinding::new(&url("https://issuer.example/authorize"), &authorization(callback)).is_err());
        }
    }

    #[test]
    fn redirects_cannot_change_endpoint_state_or_callback_outcome_cardinality() {
        let callback = "http://127.0.0.1:12345/oauth/callback";
        let binding = CallbackBinding::new(&url("https://issuer.example/authorize"), &authorization(callback)).unwrap();
        for location in [
            "http://127.0.0.1:12346/oauth/callback?code=c&state=state%2Bbound",
            "http://127.0.0.1:12345/other?code=c&state=state%2Bbound",
            "http://127.0.0.2:12345/oauth/callback?code=c&state=state%2Bbound",
            "https://issuer.example/elsewhere?code=c&state=state%2Bbound",
            "http://127.0.0.1:12345/oauth/callback?code=c&state=changed",
            "http://127.0.0.1:12345/oauth/callback?code=c&state=state%2Bbound&%73tate=state%2Bbound",
            "http://127.0.0.1:12345/oauth/callback?code=c&error=access_denied&state=state%2Bbound",
            "http://127.0.0.1:12345/oauth/callback?state=state%2Bbound",
            "http://127.0.0.1:12345/oauth/callback?code=c&state=state%2Bbound#",
        ] {
            assert!(binding.location(&[("Location".to_owned(), location.to_owned())]).is_err());
        }
        let valid = format!("{callback}?code=c&state=state%2Bbound");
        assert!(binding.location(&[("Location".into(), valid.clone()), ("location".into(), valid)]).is_err());
        assert!(binding.location(&[]).is_err());
    }

    #[test]
    fn authorization_and_query_admission_are_bounded_and_duplicate_aware() {
        let endpoint = url("https://issuer.example/authorize");
        let good = authorization("http://127.0.0.1:12345/oauth/callback");
        assert!(CallbackBinding::new(&endpoint, &good).is_ok());
        assert!(CallbackBinding::new(&url("https://other.example/authorize"), &good).is_err());
        assert!(CallbackBinding::new(&url("https://issuer.example/other"), &good).is_err());
        for suffix in ["&state=x", "&%73tate=x"] {
            assert!(CallbackBinding::new(&endpoint, &url(&format!("{}{suffix}", good.as_str()))).is_err());
        }
        for invalid in ["%", "%GG", "%ff"] {
            assert!(decode(invalid).is_err());
        }
        let overflow = (0..33).map(|n| format!("k{n}=v")).collect::<Vec<_>>().join("&");
        assert!(query(&url(&format!("https://issuer.example/?{overflow}"))).is_err());
    }

    #[test]
    fn issuer_configuration_and_front_channel_headers_do_not_relax_bearer_policy() {
        for endpoint in ["http://127.0.0.1/authorize", "https://user@issuer.example/authorize", "https://issuer.example/authorize?", "https://issuer.example/authorize#"] {
            assert!(RedirectAuthorizationDriver::new(url(endpoint)).is_err());
        }
        let driver = RedirectAuthorizationDriver::new(url("https://issuer.example/authorize")).unwrap();
        assert!(!format!("{driver:?}").contains("issuer.example"));
        assert!(request_headers().iter().all(|(name, _)| !matches!(name.to_ascii_lowercase().as_str(), "authorization" | "cookie" | "referer")));
        assert!(crate::http_auth::BoundBearerCredential::bind(url("http://127.0.0.1:12345/mcp"), "secret").is_err());
    }
}

#[cfg(test)]
mod live_tests {
    use super::tests::encode;
    use super::*;
    use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use asupersync::net::{TcpListener, TcpStream};
    use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
    use asupersync::tls::{CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder};
    use crate::http_auth::managed::{ManagedOAuthSession, OAuthSessionPolicy};
    use crate::http_auth::oauth::{OAuthClient, OAuthClientConfiguration};

    // TEST ONLY, the same 2020-2049 private CA used by oauth_managed.rs.
    // Inline because remote build transfer excludes standalone PEM files.
    const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
    const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
    const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

    fn url(value: &str) -> CanonicalHttpUrl {
        CanonicalHttpUrl::parse(value).unwrap()
    }

    fn root() -> Certificate {
        Certificate::from_pem(ROOT).unwrap().remove(0)
    }

    fn run(future: impl Future<Output = ()>) {
        RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().unwrap())
            .blocking_threads(0, 8)
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                asupersync::time::timeout_at(
                    cx.now().saturating_add_nanos(20_000_000_000),
                    future,
                )
                .await
                .expect("complete TLS test must settle, not hang on a callback");
            });
    }

    async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
        let mut left = std::pin::pin!(left);
        let mut right = std::pin::pin!(right);
        let mut left_result = None;
        let mut right_result = None;
        poll_fn(|task| {
            if left_result.is_none() {
                if let Poll::Ready(result) = left.as_mut().poll(task) {
                    left_result = Some(result);
                }
            }
            if right_result.is_none() {
                if let Poll::Ready(result) = right.as_mut().poll(task) {
                    right_result = Some(result);
                }
            }
            if left_result.is_some() && right_result.is_some() {
                Poll::Ready((left_result.take().unwrap(), right_result.take().unwrap()))
            } else {
                Poll::Pending
            }
        })
        .await
    }

    /// Only the fixture needs a base64url encoder; no new library dependency.
    fn base64url(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut encoded = String::new();
        for chunk in bytes.chunks(3) {
            let first = chunk[0];
            let second = chunk.get(1).copied().unwrap_or(0);
            let third = chunk.get(2).copied().unwrap_or(0);
            encoded.push(char::from(ALPHABET[usize::from(first >> 2)]));
            encoded.push(char::from(ALPHABET[usize::from((first & 3) << 4 | second >> 4)]));
            if chunk.len() > 1 {
                encoded.push(char::from(ALPHABET[usize::from((second & 15) << 2 | third >> 6)]));
            }
            if chunk.len() > 2 {
                encoded.push(char::from(ALPHABET[usize::from(third & 63)]));
            }
        }
        encoded
    }

    async fn read_http<IO: AsyncRead + Unpin>(io: &mut IO) -> (String, BTreeMap<String, String>, String) {
        let mut wire = Vec::new();
        let mut buffer = [0_u8; 2048];
        let end = loop {
            let count = io.read(&mut buffer).await.unwrap();
            assert!(count > 0 && wire.len() + count <= 64 * 1024);
            wire.extend_from_slice(&buffer[..count]);
            if let Some(index) = wire.windows(4).position(|part| part == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let head = std::str::from_utf8(&wire[..end]).unwrap();
        let mut lines = head.split("\r\n");
        let line = lines.next().unwrap().to_owned();
        let headers: BTreeMap<String, String> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        for forbidden in ["authorization", "cookie", "referer"] {
            assert!(!headers.contains_key(forbidden), "front channel leaked {forbidden}");
        }
        let length = headers
            .get("content-length")
            .map_or(0, |value| value.parse::<usize>().unwrap());
        assert!(end + length <= 64 * 1024);
        while wire.len() < end + length {
            let count = io.read(&mut buffer).await.unwrap();
            assert!(count > 0 && wire.len() + count <= 64 * 1024);
            wire.extend_from_slice(&buffer[..count]);
        }
        assert_eq!(wire.len(), end + length);
        (line, headers, String::from_utf8(wire[end..].to_vec()).unwrap())
    }

    #[derive(Clone, Copy)]
    enum Mode {
        Success(u16),
        WrongState,
        WrongIssuer,
        Denied,
        LoginPage,
        ForeignRedirect,
    }

    struct Peer {
        listener: TcpListener,
        acceptor: TlsAcceptor,
    }

    impl Peer {
        async fn new() -> Self {
            Self {
                listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
                acceptor: TlsAcceptorBuilder::new(
                    CertificateChain::from_pem(LEAF).unwrap(),
                    PrivateKey::from_pem(KEY).unwrap(),
                )
                .alpn_protocols(vec![b"http/1.1".to_vec()])
                .build()
                .unwrap(),
            }
        }

        fn issuer(&self) -> String {
            format!("https://{}", self.listener.local_addr().unwrap())
        }

        fn client(&self) -> OAuthClient {
            OAuthClient::new(
                OAuthClientConfiguration::from_trusted_endpoints(
                    self.issuer(),
                    url(&format!("{}/authorize", self.issuer())),
                    url(&format!("{}/token", self.issuer())),
                    url("https://resource.example/mcp"),
                    "native-client",
                    vec!["tools:read".to_owned()],
                )
                .unwrap()
                .with_extra_root_certificate(root())
                .unwrap(),
            )
        }

        fn driver(&self) -> RedirectAuthorizationDriver {
            RedirectAuthorizationDriver::new(url(&format!("{}/authorize", self.issuer())))
                .unwrap()
                .with_extra_root_certificate(root())
                .unwrap()
        }

        async fn accept(&self) -> asupersync::tls::TlsStream<TcpStream> {
            let (socket, _) = self.listener.accept().await.unwrap();
            self.acceptor.accept(socket).await.unwrap()
        }

        async fn serve(&self, mode: Mode) -> usize {
            let mut tls = self.accept().await;
            let (line, _, body) = read_http(&mut tls).await;
            assert!(line.starts_with("GET /authorize?") && line.ends_with(" HTTP/1.1"));
            assert!(body.is_empty());
            let target = line.split(' ').nth(1).unwrap();
            let fields = query(&url(&format!("{}{target}", self.issuer()))).unwrap();
            assert_eq!(fields["response_type"], "code");
            assert_eq!(fields["code_challenge_method"], "S256");
            assert_eq!(fields["client_id"], "native-client");
            assert_eq!(fields["resource"], "https://resource.example/mcp");
            assert_eq!(fields["scope"], "tools:read");
            assert!(!fields.contains_key("code_verifier"));
            let state = if matches!(mode, Mode::WrongState) { "changed" } else { &fields["state"] };
            let issuer = if matches!(mode, Mode::WrongIssuer) {
                "https://different.example".to_owned()
            } else {
                self.issuer()
            };
            let outcome = if matches!(mode, Mode::Denied) {
                "error=access_denied"
            } else {
                "code=wire-code"
            };
            let location = if matches!(mode, Mode::ForeignRedirect) {
                // A real listening forbidden sink; never contact it.
                format!("{}/other?code=wire-code&state={}", self.issuer(), encode(state))
            } else {
                format!("{}?{outcome}&state={}&iss={}", fields["redirect_uri"], encode(state), encode(&issuer))
            };
            let status = match mode {
                Mode::Success(status) => status,
                Mode::LoginPage => 200,
                _ => 302,
            };
            tls.write_all(format!(
                "HTTP/1.1 {status} Test\r\nLocation: {location}\r\nSet-Cookie: forbidden=canary\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ).as_bytes()).await.unwrap();
            tls.shutdown().await.unwrap();
            drop(tls);
            if !matches!(mode, Mode::Success(_)) {
                return 1;
            }
            let mut tls = self.accept().await;
            let (line, headers, body) = read_http(&mut tls).await;
            assert_eq!(line, "POST /token HTTP/1.1");
            assert_eq!(headers["content-type"], "application/x-www-form-urlencoded");
            let token = query(&url(&format!("https://fixture.example/?{body}"))).unwrap();
            assert_eq!(token["grant_type"], "authorization_code");
            assert_eq!(token["code"], "wire-code");
            assert_eq!(token["redirect_uri"], fields["redirect_uri"]);
            assert_eq!(token["resource"], fields["resource"]);
            assert_eq!(token["client_id"], fields["client_id"]);
            let digest = fastmcp_core::sha256_bounded(token["code_verifier"].as_bytes(), 128).unwrap();
            assert_eq!(base64url(digest.as_bytes()), fields["code_challenge"]);
            let body = r#"{"access_token":"wire-access","token_type":"Bearer","expires_in":300,"refresh_token":"wire-refresh","scope":"tools:read"}"#;
            tls.write_all(format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nPragma: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()
            ).as_bytes()).await.unwrap();
            tls.shutdown().await.unwrap();
            2
        }

        async fn assert_no_more_connections(&self, cx: &Cx) {
            let result = asupersync::time::timeout_at(
                cx.now().saturating_add_nanos(100_000_000),
                self.listener.accept(),
            )
            .await;
            assert!(result.is_err(), "an extra request was sent after terminal authorization");
        }
    }

    #[test]
    fn native_login_follows_tls_redirect_and_redeems_the_actual_pkce_code_once() {
        assert_eq!(base64url(b"foo"), "Zm9v");
        for status in [302, 303] {
            run(async {
                let cx = Cx::current().unwrap();
                let peer = Peer::new().await;
                let client = peer.client();
                let driver = peer.driver();
                let (grant, requests) = pair(
                    client.authorize_with_browser_driver(&cx, Duration::from_secs(5), |url| {
                        driver.drive(&cx, url)
                    }),
                    peer.serve(Mode::Success(status)),
                )
                .await;
                let grant = grant.unwrap();
                assert_eq!(requests, 2);
                assert!(grant.has_refresh_token());
                assert_eq!(grant.scopes(), &["tools:read".to_owned()]);
                let credential = grant.bearer_credential();
                assert_eq!(
                    credential.authorization_for_target(&url("https://resource.example/mcp")),
                    Some("Bearer wire-access".to_owned()),
                );
                assert!(credential.authorization_for_target(&url("https://resource.example/other")).is_none());
                peer.assert_no_more_connections(&cx).await;
            });
        }
    }

    #[test]
    fn managed_login_owns_and_revokes_the_redirect_obtained_grant() {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let driver = peer.driver();
            let (session, requests) = pair(
                ManagedOAuthSession::authorize_with_browser_driver(
                    &cx,
                    peer.client(),
                    OAuthSessionPolicy::default(),
                    Duration::from_secs(5),
                    |url| driver.drive(&cx, url),
                ),
                peer.serve(Mode::Success(302)),
            )
            .await;
            let session = session.unwrap();
            assert_eq!(requests, 2);
            let snapshot = session.credential(&cx).await.unwrap();
            assert_eq!(snapshot.generation(), 1);
            assert!(snapshot.credential().authorization_for_target(session.resource()).is_some());
            session.close();
            assert!(snapshot.credential().is_revoked());
            assert!(snapshot.credential().authorization_for_target(session.resource()).is_none());
            peer.assert_no_more_connections(&cx).await;
        });
    }

    #[test]
    fn rejected_front_channel_outcomes_never_reach_the_token_endpoint() {
        for (mode, expected) in [
            (Mode::WrongState, OAuthError::BrowserLaunchFailed),
            (Mode::WrongIssuer, OAuthError::IssuerMismatch),
            (Mode::Denied, OAuthError::AuthorizationDenied),
            (Mode::LoginPage, OAuthError::BrowserLaunchFailed),
            (Mode::ForeignRedirect, OAuthError::BrowserLaunchFailed),
        ] {
            run(async {
                let cx = Cx::current().unwrap();
                let peer = Peer::new().await;
                let client = peer.client();
                let driver = peer.driver();
                let (grant, requests) = pair(
                    client.authorize_with_browser_driver(&cx, Duration::from_secs(5), |url| {
                        driver.drive(&cx, url)
                    }),
                    peer.serve(mode),
                )
                .await;
                assert_eq!(grant.err(), Some(expected));
                assert_eq!(requests, 1);
                peer.assert_no_more_connections(&cx).await;
            });
        }
    }
}
