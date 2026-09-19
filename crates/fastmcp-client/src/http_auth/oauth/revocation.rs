//! Remote OAuth token revocation for an explicitly trusted native public client.
//!
//! This implements the RFC 7009 request boundary used by managed logout. It
//! never discovers an endpoint, follows a redirect, retries a request, or sends
//! a client secret. The endpoint is configured only by an explicit trusted
//! caller or by discovery metadata that advertises the public-client `none`
//! authentication method and passes the selected issuer's origin policy.
//!
//! Local access-token admission is revoked and the refresh token is removed
//! from reusable custody before the first network await. A transport failure
//! after dispatch is therefore reported as `Uncertain`, never as permission
//! to retry the same token. The access-token attempt is independent and may
//! still run after a refresh-token transport failure while the caller remains
//! active. Cancellation or deadline expiry stops additional remote effects.

use std::fmt;

use asupersync::Cx;
use asupersync::http::h1::{HttpClient, Method, RedirectPolicy, RetryPolicy};
use asupersync::types::Time;

use super::{
    OAuthClient, OAuthClientConfiguration, OAuthCredentials, OAuthError,
    encode_form, operation_deadline, within,
};
use crate::http_auth::CanonicalHttpUrl;

const REVOCATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const MAX_REVOCATION_RESPONSE_BYTES: usize = 4096;

/// Outcome of exactly one token's single remote revocation attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthTokenRevocationOutcome {
    /// This credential lineage had no token of this kind.
    NotPresent,
    /// HTTP 200: the endpoint accepted the revocation request.
    Succeeded,
    /// The endpoint responded, but not with RFC 7009 success.
    Rejected { status: u16 },
    /// Dispatch may have reached the endpoint, but no authoritative response was obtained.
    Uncertain,
    /// The caller cancelled before another remote effect could complete.
    Cancelled,
    /// The caller's absolute revocation deadline expired.
    TimedOut,
    /// No request was started because an earlier token consumed the caller budget.
    NotAttempted,
}

/// Complete, non-secret report for one credential lineage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OAuthRevocationReport {
    refresh_token: OAuthTokenRevocationOutcome,
    access_token: OAuthTokenRevocationOutcome,
}

impl OAuthRevocationReport {
    pub fn refresh_token(&self) -> OAuthTokenRevocationOutcome { self.refresh_token }
    pub fn access_token(&self) -> OAuthTokenRevocationOutcome { self.access_token }

    /// True only when every token that existed received HTTP 200.
    pub fn fully_revoked(&self) -> bool {
        matches!(self.refresh_token, OAuthTokenRevocationOutcome::NotPresent | OAuthTokenRevocationOutcome::Succeeded)
            && self.access_token == OAuthTokenRevocationOutcome::Succeeded
    }
}

/// Preflight errors happen before local credential custody is changed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthRevocationError {
    InvalidConfiguration,
    EndpointUnavailable,
    CredentialBindingMismatch,
    RuntimeUnavailable,
    Cancelled,
    TimedOut,
}

impl fmt::Display for OAuthRevocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "invalid OAuth revocation configuration",
            Self::EndpointUnavailable => "OAuth revocation endpoint is unavailable",
            Self::CredentialBindingMismatch => "OAuth credential belongs to a different revocation client",
            Self::RuntimeUnavailable => "OAuth revocation requires caller-owned I/O and time",
            Self::Cancelled => "OAuth revocation cancelled before local invalidation",
            Self::TimedOut => "OAuth revocation deadline expired before local invalidation",
        })
    }
}
impl std::error::Error for OAuthRevocationError {}

impl OAuthClientConfiguration {
    /// Adds an explicitly trusted RFC 7009 endpoint for this public client.
    ///
    /// This method performs URL-shape admission only. A cross-origin endpoint
    /// must already be trusted by the caller; discovery uses the stricter
    /// selected-issuer origin policy before calling this method.
    pub fn with_trusted_revocation_endpoint(
        mut self,
        endpoint: CanonicalHttpUrl,
    ) -> Result<Self, OAuthRevocationError> {
        if endpoint.scheme() != "https"
            || endpoint.has_userinfo()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(OAuthRevocationError::InvalidConfiguration);
        }
        self.revocation_endpoint = Some(endpoint);
        Ok(self)
    }

    pub fn revocation_endpoint(&self) -> Option<&CanonicalHttpUrl> {
        self.revocation_endpoint.as_ref()
    }
}

impl OAuthClient {
    /// Locally disables the access token and removes the reusable refresh token,
    /// then performs at most one remote revocation request per token.
    ///
    /// A configuration/binding/runtime refusal happens before local mutation.
    /// After mutation starts, network failures are returned in the report rather
    /// than as retryable errors. This method does not close a managed session;
    /// [`ManagedOAuthSession::logout`](crate::http_auth::managed::ManagedOAuthSession::logout)
    /// is the lifecycle API for that case.
    pub async fn revoke_credentials(
        &self,
        cx: &Cx,
        credentials: &mut OAuthCredentials,
    ) -> Result<OAuthRevocationReport, OAuthRevocationError> {
        if credentials.configuration != self.configuration {
            return Err(OAuthRevocationError::CredentialBindingMismatch);
        }
        let endpoint = self.configuration.revocation_endpoint.as_ref()
            .ok_or(OAuthRevocationError::EndpointUnavailable)?;
        let deadline = operation_deadline(cx, REVOCATION_TIMEOUT).map_err(map_preflight)?;
        // Preflight is now complete. From this point forward the old lineage is
        // never made reusable merely because a remote request is ambiguous.
        credentials.access.revoke();
        let refresh = credentials.refresh_token.take();

        let refresh_token = match refresh.as_deref() {
            Some(token) => self.revoke_one(cx, deadline, endpoint, token, "refresh_token").await,
            None => OAuthTokenRevocationOutcome::NotPresent,
        };
        let access_token = if matches!(
            refresh_token,
            OAuthTokenRevocationOutcome::Cancelled | OAuthTokenRevocationOutcome::TimedOut
        ) {
            OAuthTokenRevocationOutcome::NotAttempted
        } else {
            self.revoke_one(cx, deadline, endpoint, &credentials.access.token, "access_token").await
        };
        Ok(OAuthRevocationReport { refresh_token, access_token })
    }

    async fn revoke_one(
        &self,
        cx: &Cx,
        deadline: Time,
        endpoint: &CanonicalHttpUrl,
        token: &str,
        hint: &str,
    ) -> OAuthTokenRevocationOutcome {
        let body = match encode_form(&[
            ("token", token),
            ("token_type_hint", hint),
            ("client_id", self.configuration.client_id.as_str()),
        ]) {
            Ok(body) => body,
            Err(_) => return OAuthTokenRevocationOutcome::Uncertain,
        };
        let mut builder = HttpClient::builder()
            .redirect_policy(RedirectPolicy::None)
            .retry_policy(RetryPolicy::None)
            .no_proxy()
            .no_cookie_store()
            .max_body_size(MAX_REVOCATION_RESPONSE_BYTES)
            .max_total_connections(1);
        for der in &self.configuration.extra_root_certificates {
            builder = builder.add_root_certificate(asupersync::tls::Certificate::from_der(der.clone()));
        }
        let client = builder.build();
        let response = within(cx, deadline, async {
            client.request(
                cx,
                Method::Post,
                endpoint.as_str(),
                vec![
                    ("Content-Type".to_owned(), "application/x-www-form-urlencoded".to_owned()),
                    ("Accept-Encoding".to_owned(), "identity".to_owned()),
                    ("Connection".to_owned(), "close".to_owned()),
                ],
                body.into_bytes(),
            ).await.map_err(|_| OAuthError::TransportFailed)
        }).await;
        match response {
            Ok(response) if response.status == 200 => OAuthTokenRevocationOutcome::Succeeded,
            Ok(response) => OAuthTokenRevocationOutcome::Rejected { status: response.status },
            Err(OAuthError::Cancelled) => OAuthTokenRevocationOutcome::Cancelled,
            Err(OAuthError::TimedOut) => OAuthTokenRevocationOutcome::TimedOut,
            Err(_) => OAuthTokenRevocationOutcome::Uncertain,
        }
    }
}

fn map_preflight(error: OAuthError) -> OAuthRevocationError {
    match error {
        OAuthError::Cancelled => OAuthRevocationError::Cancelled,
        OAuthError::TimedOut => OAuthRevocationError::TimedOut,
        OAuthError::RuntimeTimerUnavailable | OAuthError::RuntimeCapabilityUnavailable => {
            OAuthRevocationError::RuntimeUnavailable
        }
        _ => OAuthRevocationError::InvalidConfiguration,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use crate::http_auth::BoundBearerCredential;

    fn url(value: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(value).unwrap() }

    fn config() -> OAuthClientConfiguration {
        OAuthClientConfiguration::from_trusted_endpoints(
            "https://issuer.example",
            url("https://issuer.example/authorize"),
            url("https://issuer.example/token"),
            url("https://resource.example/mcp"),
            "native-client",
            vec![],
        ).unwrap()
    }

    fn credentials(configuration: OAuthClientConfiguration) -> OAuthCredentials {
        let expiry = Instant::now() + Duration::from_secs(60);
        OAuthCredentials {
            configuration,
            access: BoundBearerCredential::bind_with_expiry(
                url("https://resource.example/mcp"), "access-secret", expiry,
            ).unwrap(),
            refresh_token: Some("refresh-secret".to_owned()),
            scopes: vec![],
            expires_at: expiry,
        }
    }

    #[test]
    fn revocation_endpoint_requires_strict_https_shape() {
        for invalid in [
            "http://issuer.example/revoke",
            "https://user@issuer.example/revoke",
            "https://issuer.example/revoke?x=1",
            "https://issuer.example/revoke#fragment",
        ] {
            assert_eq!(
                config().with_trusted_revocation_endpoint(url(invalid)).err(),
                Some(OAuthRevocationError::InvalidConfiguration),
            );
        }
        let admitted = config().with_trusted_revocation_endpoint(
            url("https://issuer.example/revoke"),
        ).unwrap();
        assert_eq!(
            admitted.revocation_endpoint().map(CanonicalHttpUrl::as_str),
            Some("https://issuer.example/revoke"),
        );
    }

    #[test]
    fn unavailable_endpoint_and_wrong_client_are_preflight_only() {
        let mut credential = credentials(config());
        let client = OAuthClient::new(config());
        let cx = Cx::for_testing();
        // `pin!` binds the future to the enclosing scope, so the `&mut credential`
        // it captures stays live until that scope ends. Confining it to this block
        // releases the borrow before the post-conditions, which read `credential`
        // immutably and are the content of this test.
        let result = {
            let mut future = std::pin::pin!(client.revoke_credentials(&cx, &mut credential));
            let mut task = std::task::Context::from_waker(std::task::Waker::noop());
            let std::task::Poll::Ready(result) =
                std::future::Future::poll(future.as_mut(), &mut task)
            else {
                panic!("endpoint-unavailable preflight became asynchronous");
            };
            result
        };
        assert_eq!(result.unwrap_err(), OAuthRevocationError::EndpointUnavailable);
        assert!(credential.has_refresh_token());
        assert!(!credential.bearer_credential().is_revoked());
    }

    #[test]
    fn report_requires_success_for_every_present_token() {
        let success = OAuthRevocationReport {
            refresh_token: OAuthTokenRevocationOutcome::Succeeded,
            access_token: OAuthTokenRevocationOutcome::Succeeded,
        };
        assert!(success.fully_revoked());
        assert!(!OAuthRevocationReport {
            refresh_token: OAuthTokenRevocationOutcome::Uncertain,
            ..success
        }.fully_revoked());
        assert!(OAuthRevocationReport {
            refresh_token: OAuthTokenRevocationOutcome::NotPresent,
            ..success
        }.fully_revoked());
    }
}
