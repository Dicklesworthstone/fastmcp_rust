//! Persistent refresh-grant retirement using the native revocation transport.
//!
//! A refresh grant is not an access credential. Revoking it must not first
//! renew it, invent an access token, or reconstruct an old access lifetime.
//! Revocation and local durable removal are distinct outcomes.

use asupersync::Cx;

use super::{OAuthClient, OAuthRefreshGrant};
use crate::http_auth::oauth::operation_deadline;
use crate::http_auth::oauth::revocation::{
    OAuthRevocationError, OAuthTokenRevocationOutcome, REVOCATION_TIMEOUT, map_preflight,
};

impl OAuthClient {
    /// Consumes an exclusively owned refresh grant and attempts its revocation
    /// once, without acquiring or sending an access token. The complete native
    /// client configuration must match, including resource, issuer, registration,
    /// scope ceiling and explicitly configured trust and revocation endpoint.
    ///
    /// This consumes the grant even on preflight refusal or future abandonment.
    /// After dispatch a lost reply is Uncertain, not authorization to recreate
    /// the grant or send it again. No redirects, cookies, proxy or retries are
    /// enabled; request encoding, response bounds and TLS are the same path used
    /// by `revoke_credentials`. The endpoint's HTTP 200 is an acknowledgement,
    /// not proof that the token was previously valid or that all related access
    /// tokens have been revoked. No access-token revocation is attempted here.
    ///
    /// Take persistent custody before calling this method. It does not itself
    /// access storage or close previously created managed sessions; the caller
    /// must retire those owners separately. Already-delivered credentials and
    /// already-sent network bytes cannot be recalled.
    pub async fn revoke_refresh_grant(
        &self,
        cx: &Cx,
        grant: OAuthRefreshGrant,
    ) -> Result<OAuthTokenRevocationOutcome, OAuthRevocationError> {
        if grant.configuration != self.configuration {
            return Err(OAuthRevocationError::CredentialBindingMismatch);
        }
        let endpoint = self.configuration.revocation_endpoint.as_ref()
            .ok_or(OAuthRevocationError::EndpointUnavailable)?;
        let deadline = operation_deadline(cx, REVOCATION_TIMEOUT).map_err(map_preflight)?;
        Ok(self.revoke_one(cx, deadline, endpoint, &grant.refresh_token, "refresh_token").await)
    }
}

#[cfg(test)]
mod grant_tests;
