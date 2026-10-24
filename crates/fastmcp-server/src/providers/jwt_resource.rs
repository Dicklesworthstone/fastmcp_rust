//! Explicitly provisioned RS256 JWT access-token authentication.
//!
//! Enable `jwt-resource-auth`, construct a [`JwtResourceVerifier`] with trusted
//! public JWKS, and install it with `TokenAuthProvider::new(verifier)` through
//! the existing server auth hook. A request cannot select the issuer, audience,
//! algorithm or key source. This code performs no network I/O or runtime creation.
//!
//! This bounded RFC 9068 profile requires all seven mandatory claims and
//! `at+jwt` or `application/at+jwt` typing. Local policy additionally requires
//! HTTPS issuer/resource identifiers, nonnegative integer-second NumericDates,
//! at most 24-hour lifetimes and at most five minutes of explicit clock skew.
//! Tokens with `cnf` are refused: Bearer authentication cannot substitute for
//! DPoP or mutual-TLS proof. These restrictions are not general JWT support.
//!
//! Only verified subject, scopes and stable issuer/resource/client identifiers
//! reach AuthContext. Private claims, compact credentials, jti and refresh-only
//! timestamps do not. Session ownership binds issuer/resource/client/subject;
//! changing grants still changes the returned scopes. Individual operations
//! still need authorization. Admission does not cancel already-admitted work,
//! prevent normal bearer reuse, or establish aggregate profile qualification.
//!
//! Clones share explicit public-key rotation and local revocation. A candidate
//! verified against a retired key generation cannot publish authentication
//! facts. There is no automatic key fetching or retry after a generation change.

use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fastmcp_core::{AccessToken, AuthContext, McpContext, McpError, McpErrorCode, McpResult};
use fastmcp_protocol::jose::{
    AdmittedRsaJwks, VerifiedCompactJws, verify_compact_jws_rs256,
};
use serde_json::{Value, json};

use crate::auth::{AuthRequest, TokenVerifier, principal_fingerprint};

const MAX_IDENTIFIER_BYTES: usize = 1024;
const MAX_AUDIENCES: usize = 16;
const MAX_SCOPES: usize = 64;
const MAX_SCOPE_BYTES: usize = 256;
const MAX_NUMERIC_DATE: u64 = 9_007_199_254_740_991;
const MAX_TOKEN_LIFETIME_SECONDS: u64 = 86_400;
const MAX_CLOCK_SKEW_SECONDS: u64 = 300;
const OWNER_DOMAIN: &[u8] = b"fastmcp/jwt-resource-owner/v1\0";
const MAX_OWNER_BYTES: usize = OWNER_DOMAIN.len() + 4 * (8 + MAX_IDENTIFIER_BYTES);

/// Fixed diagnostics never retain a token, claim, identifier or key value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JwtResourceAuthError {
    InvalidPolicy,
    InvalidKeys,
    InvalidToken,
    InvalidClaims,
    ClockUnavailable,
    Cancelled,
    TimedOut,
    /// All keys were revoked, or the shared registry is poisoned.
    KeysUnavailable,
    /// The verified key generation was replaced before claim admission.
    KeysChanged,
}

impl fmt::Display for JwtResourceAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid JWT resource authentication policy",
            Self::InvalidKeys => "invalid JWT resource verification keys",
            Self::InvalidToken => "invalid JWT access token",
            Self::InvalidClaims => "JWT access token does not satisfy resource policy",
            Self::ClockUnavailable => "JWT authentication clock unavailable",
            Self::Cancelled => "JWT authentication cancelled",
            Self::TimedOut => "JWT authentication deadline exceeded",
            Self::KeysUnavailable => "JWT resource verification keys unavailable",
            Self::KeysChanged => "JWT resource verification keys changed during admission",
        })
    }
}

impl std::error::Error for JwtResourceAuthError {}

/// Immutable administrative issuer, exact audience and finite time policy.
/// URLs are structurally admitted but retained and compared verbatim. Token
/// normalization must not turn a different issuer or audience into a match.
#[derive(Clone)]
pub struct JwtResourcePolicy {
    issuer: String,
    resource: String,
    maximum_lifetime_seconds: u64,
    clock_skew_seconds: u64,
}

impl JwtResourcePolicy {
    /// Requires a nonzero lifetime of at most 24 hours and skew of at most
    /// five minutes, both in whole seconds. Zero skew is allowed. Issuers
    /// cannot contain queries; neither URL may contain userinfo, fragments,
    /// whitespace or controls. Each identifier is limited to 1024 UTF-8 bytes.
    pub fn new(
        issuer: impl Into<String>,
        resource: impl Into<String>,
        maximum_lifetime: Duration,
        clock_skew: Duration,
    ) -> Result<Self, JwtResourceAuthError> {
        let issuer = issuer.into();
        let resource = resource.into();
        if !valid_https_identifier(&issuer, false)
            || !valid_https_identifier(&resource, true)
            || maximum_lifetime.is_zero()
            || maximum_lifetime.as_secs() > MAX_TOKEN_LIFETIME_SECONDS
            || maximum_lifetime.subsec_nanos() != 0
            || clock_skew.as_secs() > MAX_CLOCK_SKEW_SECONDS
            || clock_skew.subsec_nanos() != 0
        {
            return Err(JwtResourceAuthError::InvalidPolicy);
        }
        Ok(Self {
            issuer,
            resource,
            maximum_lifetime_seconds: maximum_lifetime.as_secs(),
            clock_skew_seconds: clock_skew.as_secs(),
        })
    }
}

impl fmt::Debug for JwtResourcePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtResourcePolicy")
            .field("maximum_lifetime_seconds", &self.maximum_lifetime_seconds)
            .field("clock_skew_seconds", &self.clock_skew_seconds)
            .finish_non_exhaustive()
    }
}

/// Resource-server authentication using only provisioned public keys.
/// Install with [`crate::auth::TokenAuthProvider`] to retain existing native
/// Authorization admission, credential stripping and request-local auth commit.
/// The protocol verifier's larger JWS ceiling never widens the shared access
/// credential ceiling enforced here.
///
/// Retain a clone before installation to rotate or revoke the keys without
/// rebuilding the provider. All clones share the registry; independently
/// constructed verifiers do not. The issuer/resource policy is immutable.
#[derive(Clone)]
pub struct JwtResourceVerifier {
    policy: JwtResourcePolicy,
    // TokenVerifier is synchronous. These bounded in-memory critical sections
    // contain no RSA verification, I/O, await, or public application callback.
    keys: Arc<RwLock<Option<Arc<AdmittedRsaJwks>>>>,
}

// Retaining the exact Arc both identifies its generation and prevents an ABA
// address reuse while a signature verified with that generation is in flight.
struct VerifiedJwt {
    keys: Arc<AdmittedRsaJwks>,
    verified: VerifiedCompactJws,
}

impl JwtResourceVerifier {
    /// Admits the complete bounded public JWKS before exposing a verifier.
    pub fn new(policy: JwtResourcePolicy, jwks: &[u8]) -> Result<Self, JwtResourceAuthError> {
        let keys =
            AdmittedRsaJwks::from_json(jwks).map_err(|_| JwtResourceAuthError::InvalidKeys)?;
        Ok(Self {
            policy,
            keys: Arc::new(RwLock::new(Some(Arc::new(keys)))),
        })
    }

    /// Atomically replaces all trusted public keys for this verifier's clones.
    ///
    /// The complete replacement is admitted before locking or changing active
    /// state. Invalid, empty, duplicate or unsupported JWKS leave the previous
    /// state intact. Every successful replacement starts a new generation,
    /// even when the key IDs or complete bytes match the previous generation.
    /// In-flight old-generation candidates fail rather than retrying silently.
    ///
    /// This administrative grant also reinstalls keys after [`Self::revoke_all`].
    /// It never changes issuer/resource policy, fetches keys, or cancels already
    /// admitted work. A poisoned registry cannot be repaired through this API.
    pub fn replace_jwks(&self, jwks: &[u8]) -> Result<(), JwtResourceAuthError> {
        let replacement = Arc::new(
            AdmittedRsaJwks::from_json(jwks).map_err(|_| JwtResourceAuthError::InvalidKeys)?,
        );
        let mut active = self
            .keys
            .write()
            .map_err(|_| JwtResourceAuthError::KeysUnavailable)?;
        let retired = active.replace(replacement);
        drop(active);
        drop(retired);
        Ok(())
    }

    /// Revokes all trusted keys across every clone, returning whether any were
    /// active. Repeated calls are harmless. Subsequent admission fails until an
    /// administrator explicitly installs a valid set with [`Self::replace_jwks`].
    ///
    /// Candidates signed under revoked keys cannot finish admission. Existing
    /// AuthContext values and work admitted before revocation cannot be recalled.
    /// This is local trust revocation, not an OAuth revocation-endpoint request.
    pub fn revoke_all(&self) -> Result<bool, JwtResourceAuthError> {
        let mut active = self
            .keys
            .write()
            .map_err(|_| JwtResourceAuthError::KeysUnavailable)?;
        let retired = active.take();
        drop(active);
        Ok(retired.is_some())
    }

    /// Verifies on the caller's context, with cancellation/deadline checks on
    /// both sides of bounded work. Wall time is sampled after RSA verification
    /// and after acquiring the final key-generation admission lock.
    pub fn verify_access_token(
        &self,
        ctx: &McpContext,
        token: &AccessToken,
    ) -> Result<AuthContext, JwtResourceAuthError> {
        self.verify_with_clock(ctx, token, || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .map_err(|_| JwtResourceAuthError::ClockUnavailable)
        })
    }

    fn verify_with_clock(
        &self,
        ctx: &McpContext,
        token: &AccessToken,
        clock: impl FnOnce() -> Result<u64, JwtResourceAuthError>,
    ) -> Result<AuthContext, JwtResourceAuthError> {
        let candidate = self.prepare_verification(ctx, token)?;
        self.admit_verified(ctx, candidate, clock)
    }

    fn prepare_verification(
        &self,
        ctx: &McpContext,
        token: &AccessToken,
    ) -> Result<VerifiedJwt, JwtResourceAuthError> {
        checkpoint(ctx)?;
        if !token.scheme.eq_ignore_ascii_case("Bearer")
            || !AccessToken::is_valid_token68(&token.token)
        {
            return Err(JwtResourceAuthError::InvalidToken);
        }
        let keys = self
            .keys
            .read()
            .map_err(|_| JwtResourceAuthError::KeysUnavailable)?
            .as_ref()
            .cloned()
            .ok_or(JwtResourceAuthError::KeysUnavailable)?;
        // The snapshot guard was dropped above: RSA never delays key mutation.
        let verified = verify_compact_jws_rs256(&token.token, &keys)
            .map_err(|_| JwtResourceAuthError::InvalidToken)?;
        require_access_token_type(&token.token)?;
        checkpoint(ctx)?;
        Ok(VerifiedJwt { keys, verified })
    }

    fn admit_verified(
        &self,
        ctx: &McpContext,
        candidate: VerifiedJwt,
        clock: impl FnOnce() -> Result<u64, JwtResourceAuthError>,
    ) -> Result<AuthContext, JwtResourceAuthError> {
        let active = self
            .keys
            .read()
            .map_err(|_| JwtResourceAuthError::KeysUnavailable)?;
        let current = active
            .as_ref()
            .ok_or(JwtResourceAuthError::KeysUnavailable)?;
        if !Arc::ptr_eq(current, &candidate.keys) {
            return Err(JwtResourceAuthError::KeysChanged);
        }
        checkpoint(ctx)?;
        // The private clock seam is SystemTime in production, never an external
        // callback. Sample after lock acquisition so contention cannot preserve
        // a stale pre-lock expiry reading. Hold the generation through this
        // bounded decision; revocation after it cannot recall returned facts.
        let context = admit_claims(&self.policy, candidate.verified.claims(), clock()?)?;
        checkpoint(ctx)?;
        drop(active);
        Ok(context)
    }
}

impl fmt::Debug for JwtResourceVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key_count = self
            .keys
            .try_read()
            .ok()
            .map(|active| active.as_ref().map_or(0, |keys| keys.len()));
        f.debug_struct("JwtResourceVerifier")
            .field("policy", &self.policy)
            .field("key_count", &key_count)
            .finish()
    }
}

impl TokenVerifier for JwtResourceVerifier {
    fn verify(
        &self,
        ctx: &McpContext,
        _request: AuthRequest<'_>,
        token: &AccessToken,
    ) -> McpResult<AuthContext> {
        self.verify_access_token(ctx, token)
            .map_err(|error| match error {
                JwtResourceAuthError::Cancelled => McpError::request_cancelled(),
                JwtResourceAuthError::TimedOut => {
                    McpError::new(McpErrorCode::RequestCancelled, "Request timeout exceeded")
                }
                _ => McpError::new(McpErrorCode::ResourceForbidden, "Invalid access token"),
            })
    }
}

fn checkpoint(ctx: &McpContext) -> Result<(), JwtResourceAuthError> {
    if ctx.checkpoint().is_err() {
        return Err(if ctx.deadline_expired() {
            JwtResourceAuthError::TimedOut
        } else {
            JwtResourceAuthError::Cancelled
        });
    }
    if ctx.deadline_expired() {
        return Err(JwtResourceAuthError::TimedOut);
    }
    Ok(())
}

fn identifier(value: &Value) -> Result<&str, JwtResourceAuthError> {
    value
        .as_str()
        .filter(|text| {
            !text.is_empty()
                && text.len() <= MAX_IDENTIFIER_BYTES
                && !text.chars().any(char::is_control)
        })
        .ok_or(JwtResourceAuthError::InvalidClaims)
}

fn valid_https_identifier(value: &str, allow_query: bool) -> bool {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.contains('\\')
        || value.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return false;
    }
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    if rest
        .split(['/', '?', '#'])
        .next()
        .is_none_or(|host| host.is_empty() || host.contains('@'))
    {
        return false;
    }
    url::Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.fragment().is_none()
            && (allow_query || url.query().is_none())
    })
}

// The shared verifier already authenticated these exact canonical, bounded,
// duplicate-free header bytes. Inspect the typ it does not retain; no value
// parsed here selects an algorithm, key or key source.
fn require_access_token_type(compact: &str) -> Result<(), JwtResourceAuthError> {
    let (header, _) = compact
        .split_once('.')
        .ok_or(JwtResourceAuthError::InvalidToken)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_| JwtResourceAuthError::InvalidToken)?;
    let header: Value =
        serde_json::from_slice(&bytes).map_err(|_| JwtResourceAuthError::InvalidToken)?;
    if !matches!(
        header.get("typ").and_then(Value::as_str),
        Some("at+jwt" | "application/at+jwt")
    ) {
        return Err(JwtResourceAuthError::InvalidToken);
    }
    Ok(())
}

fn numeric_date(value: &Value) -> Result<u64, JwtResourceAuthError> {
    value
        .as_u64()
        .filter(|n| *n <= MAX_NUMERIC_DATE)
        .ok_or(JwtResourceAuthError::InvalidClaims)
}

fn admit_audience(value: &Value, expected: &str) -> Result<(), JwtResourceAuthError> {
    let matches = match value {
        Value::String(_) => identifier(value)? == expected,
        Value::Array(values) if !values.is_empty() && values.len() <= MAX_AUDIENCES => {
            let mut matched = false;
            for value in values {
                matched |= identifier(value)? == expected;
            }
            matched
        }
        _ => false,
    };
    if !matches {
        return Err(JwtResourceAuthError::InvalidClaims);
    }
    Ok(())
}

fn admit_scopes(value: Option<&Value>) -> Result<Vec<String>, JwtResourceAuthError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let text = value.as_str().ok_or(JwtResourceAuthError::InvalidClaims)?;
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let mut scopes = Vec::new();
    for scope in text.split(' ') {
        if scopes.len() >= MAX_SCOPES
            || scope.is_empty()
            || scope.len() > MAX_SCOPE_BYTES
            || !scope
                .bytes()
                .all(|b| matches!(b, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
        {
            return Err(JwtResourceAuthError::InvalidClaims);
        }
        scopes.push(scope.to_owned());
    }
    scopes.sort_unstable();
    scopes.dedup();
    Ok(scopes)
}

fn admit_claims(
    policy: &JwtResourcePolicy,
    claims: &Value,
    now: u64,
) -> Result<AuthContext, JwtResourceAuthError> {
    let object = claims
        .as_object()
        .ok_or(JwtResourceAuthError::InvalidClaims)?;
    let required = |name: &str| object.get(name).ok_or(JwtResourceAuthError::InvalidClaims);
    if identifier(required("iss")?)? != policy.issuer || object.contains_key("cnf") {
        return Err(JwtResourceAuthError::InvalidClaims);
    }
    admit_audience(required("aud")?, &policy.resource)?;
    let subject = identifier(required("sub")?)?;
    let client = identifier(required("client_id")?)?;
    identifier(required("jti")?)?;
    let issued = numeric_date(required("iat")?)?;
    let expires = numeric_date(required("exp")?)?;
    let not_before = object.get("nbf").map(numeric_date).transpose()?;
    let latest = now
        .checked_add(policy.clock_skew_seconds)
        .ok_or(JwtResourceAuthError::InvalidClaims)?;
    let expiry_with_skew = expires
        .checked_add(policy.clock_skew_seconds)
        .ok_or(JwtResourceAuthError::InvalidClaims)?;
    if now > MAX_NUMERIC_DATE
        || issued >= expires
        || expires - issued > policy.maximum_lifetime_seconds
        || issued > latest
        || now >= expiry_with_skew
        || not_before.is_some_and(|nbf| nbf > latest || nbf >= expires)
    {
        return Err(JwtResourceAuthError::InvalidClaims);
    }
    let scopes = admit_scopes(object.get("scope"))?;
    // Domain separation and length framing prevent concatenation collisions.
    // Client identity prevents two clients for one subject sharing state.
    let mut owner = Vec::with_capacity(MAX_OWNER_BYTES);
    owner.extend_from_slice(OWNER_DOMAIN);
    for component in [
        policy.issuer.as_str(),
        policy.resource.as_str(),
        client,
        subject,
    ] {
        let length =
            u64::try_from(component.len()).map_err(|_| JwtResourceAuthError::InvalidClaims)?;
        owner.extend_from_slice(&length.to_be_bytes());
        owner.extend_from_slice(component.as_bytes());
    }
    let owner = fastmcp_core::sha256_bounded(&owner, MAX_OWNER_BYTES)
        .map_err(|_| JwtResourceAuthError::InvalidClaims)?;
    let mut context = AuthContext::with_subject(subject).with_session_owner(owner);
    context.scopes = scopes;
    // Refresh-only timestamps and jti are not grants. Publishing them here
    // would make unchanged authorization facts differ on every token refresh.
    context.claims = Some(json!({
        "iss":policy.issuer, "aud":policy.resource, "client_id":client
    }));
    principal_fingerprint(Some(&context)).map_err(|_| JwtResourceAuthError::InvalidClaims)?;
    Ok(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthProvider, TokenAuthProvider};
    use base64::engine::general_purpose::STANDARD;
    use ring::rand::SystemRandom;
    use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};

    const ISSUER: &str = "https://issuer.example";
    const RESOURCE: &str = "https://tools.example/mcp";
    const NOW: u64 = 1_800_000_000;
    // Public test-only RSA key. Never issue non-test credentials with it.
    const PRIVATE_KEY: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC3wxLvB3SX9fKLLBY8rXXENHK3d78DfxpG7Uq1q9RbtvOHs2m/iU4p0xqHeD35ZG4FGXdzhQWtfp4ydwdqd098z5JHMWyR5naVmF37sykkkNSyBKA6eRYfurtlep9GVlrjpTbqEvo6777nSL9Ozq6hUzU4fPdmk8U1yZ/prSbiDbUcH8HgrgoOHfBM0vg9bM8EVtpKJtwjc1sAfG96k2TEB5tRSCaolhkpMpXdHF6zCZukHvK1DrLVpUvYlgrPfIfucb/8Ws4WxNMOg7M36actazuged0lVpNpbRNHIg+Wss+wUsRKgXhDCAlmWivcyhoLM+Jj5dnWZpeqNE4J6cXBAgMBAAECgf9ofHL3lrWk8iPHHnpGZhrgRTI1P9FMm6jFS4d/ZQSKYax3LHyke94FyhL7lFMoywIDxEc3WBuyWpx49VUyJET+Ish50pB5JSGoTcqio2xxbiiCUD8LAG6j+/kx6ldGFzP23Koszj2Z5VgXCjY9CSgicr2AMQ47NSqdOtfCdsH1Jf4A2D8U6sLFR1FDKZVie5SiZC41/91897QyySDdxEO2bbxb4ZA47EBF+dfQyEXtXDJ34oBrncVepELv9B5hWu+Z4Uf5DK78Ww8NiU1U1+bLVIL5yreK/UaHgVgEJQepTKAzTr4OMT0ZXTAZT5OfoMKmWbq6iQ5mukU8rLUg1xLECgYEA8g2q98V+XvyZQ5kFI/Skj6bxwbRw+mr0SbrWoCSP0VOV4gQ5ED7VnPwGFW8GPR3nqA4Rdx9qul7kttHQnEpbYgk4A2NTRzgqWeu0dfOS2+u+UB44SstamiZfxbNKzLHayJzPMZSZMq2fJhNs8FQtGa3ES3qRJavSOtB34meI4HECgYEAwlmY9AEthueuEaU4ZDHNeYaNwv+TO8QAixl6lj2vztTmVAAFOL7aXNWb+WCQ3SyyDkSty/Kk19e+e5s496keZLxUbyTsboP2LTu0H+45gIUkDAVp/ACXK5dOJT4Vj3jjPUuY9R3CxXvIUEDuzN2hmxTVOq7y53u71sYx5mRn4lECgYEAmNq8vp7/AKjveFqnfl89lGHOhY6XUew8vFq6soKkN4JbQlF8X5/ucaZNiTeFbw71fZD0wo8abPsD39d7r1bdgnlj3+/XZUA4rnREj7/zW+HxWtLapZDpdDMLg+OHNuCR0uIDjcHTRMeTmw3lW5csq+yp6yhJhMqOhgmjy1uqemECgYEAtNeWQYZPDLbL/FNW87R709bmVkpmgDhToRtmPCLOUpE8eXFDapf8rGF/rz6xzXxnemthpOL1jHqOHopDKgBN7cJodrtO3U8hZNmnNAcBrps0/ZKUGg+ams9BwdnRSh1cpY6Ql5THxeb2b+bbzfl1BM8P0nk0QT2bfbASgqVvHOECgYEA2D+89N+YGmI052k8Ow/QBjB/IBhO90syi3TvinbK4B2Y1wQDqt7f50lPvWzoUYFH0cq8RlroCou71gkiBxFnd7BFHVDFuyA24o7sPctQ322KMty/eSHXwQugJRRylNBXFvJXrIhfdiV+OvZ9NVXTESeVT0x5eGAI+1QTdjZCKiQ=";
    const MODULUS: &str = "t8MS7wd0l_XyiywWPK11xDRyt3e_A38aRu1KtavUW7bzh7Npv4lOKdMah3g9-WRuBRl3c4UFrX6eMncHandPfM-SRzFskeZ2lZhd-7MpJJDUsgSgOnkWH7q7ZXqfRlZa46U26hL6Ou--50i_Ts6uoVM1OHz3ZpPFNcmf6a0m4g21HB_B4K4KDh3wTNL4PWzPBFbaSibcI3NbAHxvepNkxAebUUgmqJYZKTKV3RxeswmbpB7ytQ6y1aVL2JYKz3yH7nG__FrOFsTTDoOzN-mnLWs7oHndJVaTaW0TRyIPlrLPsFLESoF4QwgJZlor3MoaCzPiY-XZ1maXqjROCenFwQ";
    // Independently signed test-only token under a second RSA key, deliberately
    // using the SAME kid. Its private key is not retained by these fixtures.
    const ROTATED_MODULUS: &str = "nglMZYxKVQoNbg1eyTOptTNw5GbItWLTcvYNFx1fIffaj5yjvmwBg1hZ3WXWnrPiHGQLmWJA8DhSF4ivZsNGR8DT_EZMhCV6oJiiwr-B_I4jiSdVwPkMCNKaI9WNFaZKh5-no6suh4V4-rVVjIecT8N60qlKkpCxlYkgtQ28AUM6RiDrd33DTZdRTjLHxWA5dyz2mlPwdMQvu0vlnZckAPgZauymb8KL5tXl2nv0Am9z08HtNkj259Y4d1KvsjZKczPbuKFiA9zAVOl1hNDQ7dI1ZxvHDJikifFUlx7gMioUOr0Im0MJuDMy6LIAHDpiqTtX5BXssw8IqOHEBV8_sQ";
    const ROTATED_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6Im9uZSIsInR5cCI6ImF0K2p3dCJ9.eyJhdWQiOiJodHRwczovL3Rvb2xzLmV4YW1wbGUvbWNwIiwiY2xpZW50X2lkIjoiY2xpZW50LW9uZSIsImV4cCI6MTgwMDAwMDA2MCwiaWF0IjoxNzk5OTk5OTkwLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwianRpIjoicm90YXRlZC1rZXktdG9rZW4iLCJzY29wZSI6InJlYWQgd3JpdGUiLCJzdWIiOiJhbGljZSJ9.PE504KsHfHAcyycg7SNeg5gyQKGWEbF4o-rbI6-fIdjiRQ6T_bEfcICjcTPxQAJmc532ooS9f4Wvgk712d9tqZZsX1Y6cZgfvs4TN9xQhRGUxoa935yVm1oIoOl2SQGuHUwPYZnnzhtpLz9h2msSFwl9lj6bjv0Ol0GuTvyvT_osAEvaptMQYfdpOxwFf04sPoCzs0lb9fYEaRKjFXiXFFq1-GRdgOomUppCbyEng7r0YlBDbDtwftzKDIdOrj0KjQBu8zXpdVRJRRevFiiPglHSwDHkNFBOF2KSGl2ev_8QB9Eoi85lc_NtDSdO9QI873RZdCCTGk49LsUmWxLWng";

    fn ctx() -> McpContext {
        McpContext::new(asupersync::Cx::for_testing(), 1)
    }

    fn policy() -> JwtResourcePolicy {
        JwtResourcePolicy::new(ISSUER, RESOURCE, Duration::from_secs(3600), Duration::ZERO)
            .unwrap()
    }

    fn jwks(kid: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"keys":[{
            "kty":"RSA", "alg":"RS256", "use":"sig", "kid":kid, "n":MODULUS, "e":"AQAB"
        }]}))
        .unwrap()
    }

    fn rotated_jwks() -> Vec<u8> {
        serde_json::to_vec(&json!({"keys":[{
            "kty":"RSA", "alg":"RS256", "use":"sig", "kid":"one",
            "n":ROTATED_MODULUS, "e":"AQAB"
        }]}))
        .unwrap()
    }

    fn rotated_token() -> AccessToken {
        AccessToken {
            scheme: "Bearer".to_owned(),
            token: ROTATED_TOKEN.to_owned(),
        }
    }

    fn verifier() -> JwtResourceVerifier {
        JwtResourceVerifier::new(policy(), &jwks("one")).unwrap()
    }

    fn claims(now: u64) -> Value {
        json!({"iss":ISSUER, "aud":RESOURCE, "sub":"alice", "client_id":"client-one",
            "iat":now - 10, "exp":now + 60, "jti":"test-token-one", "scope":"read write"})
    }

    fn header() -> Value {
        json!({"alg":"RS256", "kid":"one", "typ":"at+jwt"})
    }

    fn sign_raw(header: &[u8], claims: &[u8]) -> AccessToken {
        let key = RsaKeyPair::from_pkcs8(&STANDARD.decode(PRIVATE_KEY).unwrap()).unwrap();
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
        );
        let mut signature = vec![0_u8; 256];
        key.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            input.as_bytes(),
            &mut signature,
        )
        .unwrap();
        AccessToken {
            scheme: "Bearer".to_owned(),
            token: format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)),
        }
    }

    fn sign(header: &Value, claims: &Value) -> AccessToken {
        sign_raw(
            &serde_json::to_vec(header).unwrap(),
            &serde_json::to_vec(claims).unwrap(),
        )
    }

    fn verify_at(
        verifier: &JwtResourceVerifier,
        token: &AccessToken,
        now: u64,
    ) -> Result<AuthContext, JwtResourceAuthError> {
        verifier.verify_with_clock(&ctx(), token, || Ok(now))
    }

    #[test]
    fn signed_token_authenticates_through_the_existing_provider_without_private_claims() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut source = claims(now);
        source["exp"] = json!(now + 600);
        source["private"] = json!({"refresh_token":"DO_NOT_EXPOSE"});
        let token = sign(&header(), &source);
        let authorization = format!("Bearer {}", token.token);
        let provider = TokenAuthProvider::new(verifier());
        let request = AuthRequest {
            method: "tools/list",
            params: None,
            transport_authorization: Some(&authorization),
            request_id: 1,
        };
        let auth = provider.authenticate(&ctx(), request).unwrap();
        assert_eq!(auth.subject.as_deref(), Some("alice"));
        assert_eq!(auth.scopes, ["read", "write"]);
        assert!(auth.session_owner().is_some());
        let facts = serde_json::to_string(&auth).unwrap();
        assert!(!facts.contains("DO_NOT_EXPOSE"));
        assert!(!facts.contains(&token.token));
        assert!(!format!("{auth:?} {:?}", verifier()).contains("alice"));
        source["aud"] = json!("https://other.example/mcp");
        let wrong = sign(&header(), &source);
        let authorization = format!("Bearer {}", wrong.token);
        let request = AuthRequest {
            method: "tools/list",
            params: None,
            transport_authorization: Some(&authorization),
            request_id: 1,
        };
        let error = provider.authenticate(&ctx(), request).unwrap_err();
        assert!(!format!("{error:?}").contains(&wrong.token));
    }

    #[test]
    fn signed_wrong_claims_and_missing_required_members_are_refused() {
        let verifier = verifier();
        assert!(verify_at(&verifier, &sign(&header(), &claims(NOW)), NOW).is_ok());
        for (name, value) in [
            ("iss", json!("https://ISSUER.example")),
            ("aud", json!("https://tools.example/other")),
            ("aud", json!([RESOURCE, 7])),
            ("aud", json!([])),
            ("sub", json!("")),
            ("client_id", json!(null)),
            ("jti", json!(42)),
            ("cnf", json!(null)),
            ("scope", json!(["read"])),
            ("scope", json!("read\twrite")),
            ("scope", json!(" read")),
            ("scope", json!("read  write")),
            ("scope", json!("réad")),
        ] {
            let mut source = claims(NOW);
            source[name] = value;
            assert!(
                verify_at(&verifier, &sign(&header(), &source), NOW).is_err(),
                "{name}"
            );
        }
        for name in ["iss", "aud", "exp", "iat", "sub", "client_id", "jti"] {
            let mut source = claims(NOW);
            source.as_object_mut().unwrap().remove(name);
            assert!(
                verify_at(&verifier, &sign(&header(), &source), NOW).is_err(),
                "{name}"
            );
        }
        let mut source = claims(NOW);
        source["aud"] = json!(["https://other.example/mcp", RESOURCE]);
        source["scope"] = json!("write read read");
        assert_eq!(
            verify_at(&verifier, &sign(&header(), &source), NOW)
                .unwrap()
                .scopes,
            ["read", "write"]
        );
    }

    #[test]
    fn token_type_algorithm_key_and_signature_cannot_be_substituted() {
        let verifier = verifier();
        for typ in ["at+jwt", "application/at+jwt"] {
            let mut h = header();
            h["typ"] = json!(typ);
            assert!(verify_at(&verifier, &sign(&h, &claims(NOW)), NOW).is_ok());
        }
        for (name, value) in [
            ("typ", json!("JWT")),
            ("typ", json!(null)),
            ("alg", json!("none")),
            ("alg", json!("HS256")),
            ("kid", json!("unknown")),
            ("jku", json!("https://attacker.example/jwks")),
            ("crit", json!([])),
        ] {
            let mut h = header();
            h[name] = value;
            assert!(verify_at(&verifier, &sign(&h, &claims(NOW)), NOW).is_err());
        }
        let good = sign(&header(), &claims(NOW));
        let (input, encoded) = good.token.rsplit_once('.').unwrap();
        let mut signature = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        signature[0] ^= 1;
        let corrupt = AccessToken {
            scheme: "Bearer".to_owned(),
            token: format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)),
        };
        assert_eq!(
            verify_at(&verifier, &corrupt, NOW).unwrap_err(),
            JwtResourceAuthError::InvalidToken
        );
        let mut non_bearer = good;
        non_bearer.scheme = "DPoP".to_owned();
        assert!(verify_at(&verifier, &non_bearer, NOW).is_err());
    }

    #[test]
    fn exact_time_boundaries_and_explicit_skew_use_no_floating_point() {
        let verifier = verifier();
        let token = sign(&header(), &claims(NOW));
        assert!(verify_at(&verifier, &token, NOW + 59).is_ok());
        assert!(verify_at(&verifier, &token, NOW + 60).is_err());
        assert!(verify_at(&verifier, &token, NOW - 11).is_err());
        for (name, value) in [
            ("exp", json!(NOW - 10)),
            ("exp", json!(NOW + 3591)),
            ("iat", json!(NOW + 1)),
            ("iat", json!(-1)),
            ("exp", json!("1800000060")),
            ("exp", json!(1.5)),
            ("exp", json!(u64::MAX)),
            ("nbf", json!(NOW + 1)),
            ("nbf", json!(null)),
        ] {
            let mut source = claims(NOW);
            source[name] = value;
            assert!(
                verify_at(&verifier, &sign(&header(), &source), NOW).is_err(),
                "{name}"
            );
        }
        let policy = JwtResourcePolicy::new(
            ISSUER,
            RESOURCE,
            Duration::from_secs(3600),
            Duration::from_secs(2),
        )
        .unwrap();
        let tolerant = JwtResourceVerifier::new(policy, &jwks("one")).unwrap();
        assert!(verify_at(&tolerant, &token, NOW + 61).is_ok());
        assert!(verify_at(&tolerant, &token, NOW + 62).is_err());
        let mut source = claims(NOW);
        source["nbf"] = json!(NOW + 2);
        assert!(verify_at(&tolerant, &sign(&header(), &source), NOW).is_ok());
        source["nbf"] = json!(NOW + 3);
        assert!(verify_at(&tolerant, &sign(&header(), &source), NOW).is_err());
    }

    #[test]
    fn refreshed_tokens_preserve_identity_and_unchanged_grants() {
        let verifier = verifier();
        let original = verify_at(&verifier, &sign(&header(), &claims(NOW)), NOW).unwrap();
        let mut refresh = claims(NOW + 1);
        refresh["jti"] = json!("rotated-token");
        let same_grants = verify_at(&verifier, &sign(&header(), &refresh), NOW + 1).unwrap();
        assert_eq!(original.session_owner(), same_grants.session_owner());
        assert_eq!(
            serde_json::to_value(&original).unwrap(),
            serde_json::to_value(&same_grants).unwrap()
        );
        refresh["scope"] = json!("read");
        let renewed = verify_at(&verifier, &sign(&header(), &refresh), NOW + 1).unwrap();
        assert_eq!(original.session_owner(), renewed.session_owner());
        assert_ne!(original.scopes, renewed.scopes);
        for (name, value) in [("sub", "bob"), ("client_id", "client-two")] {
            let mut source = claims(NOW);
            source[name] = json!(value);
            assert_ne!(
                original.session_owner(),
                verify_at(&verifier, &sign(&header(), &source), NOW)
                    .unwrap()
                    .session_owner()
            );
        }
        let other_resource = "https://tools.example/other";
        let other = JwtResourceVerifier::new(
            JwtResourcePolicy::new(
                ISSUER,
                other_resource,
                Duration::from_secs(3600),
                Duration::ZERO,
            )
            .unwrap(),
            &jwks("one"),
        )
        .unwrap();
        let mut source = claims(NOW);
        source["aud"] = json!(other_resource);
        assert_ne!(
            original.session_owner(),
            verify_at(&other, &sign(&header(), &source), NOW)
                .unwrap()
                .session_owner()
        );
    }

    #[test]
    fn duplicate_signed_members_and_shared_credential_limit_fail_closed() {
        let verifier = verifier();
        let source = serde_json::to_string(&claims(NOW)).unwrap();
        let duplicate = format!("{{\"sub\":\"mallory\",{}", &source[1..]);
        let token = sign_raw(&serde_json::to_vec(&header()).unwrap(), duplicate.as_bytes());
        assert!(verify_at(&verifier, &token, NOW).is_err());
        let duplicate_header =
            br#"{"alg":"RS256","kid":"one","typ":"at+jwt","typ":"JWT"}"#;
        let token = sign_raw(duplicate_header, source.as_bytes());
        assert!(verify_at(&verifier, &token, NOW).is_err());
        let token = AccessToken {
            scheme: "Bearer".to_owned(),
            token: "a".repeat(fastmcp_core::MAX_ACCESS_TOKEN_BYTES + 1),
        };
        let mut clock_called = false;
        assert!(
            verifier
                .verify_with_clock(&ctx(), &token, || {
                    clock_called = true;
                    Ok(NOW)
                })
                .is_err()
        );
        assert!(!clock_called);
        let good = sign(&header(), &claims(NOW));
        assert_eq!(
            verifier
                .verify_with_clock(&ctx(), &good, || Err(JwtResourceAuthError::ClockUnavailable))
                .unwrap_err(),
            JwtResourceAuthError::ClockUnavailable
        );
    }

    #[test]
    fn unsafe_configuration_and_unbounded_claim_sets_are_not_admitted() {
        for issuer in [
            "http://issuer.example",
            "https://user@issuer.example",
            "https://@issuer.example",
            "https://issuer.example#",
            "https://issuer.example?q=1",
            " https://issuer.example",
        ] {
            assert!(
                JwtResourcePolicy::new(issuer, RESOURCE, Duration::from_secs(60), Duration::ZERO)
                    .is_err()
            );
        }
        for (lifetime, skew) in [
            (Duration::ZERO, Duration::ZERO),
            (Duration::from_secs(86_401), Duration::ZERO),
            (Duration::from_secs(60), Duration::from_secs(301)),
            (Duration::from_millis(1500), Duration::ZERO),
        ] {
            assert!(JwtResourcePolicy::new(ISSUER, RESOURCE, lifetime, skew).is_err());
        }
        assert!(JwtResourceVerifier::new(policy(), b"{\"keys\":[]}").is_err());
        let verifier = verifier();
        for (name, value) in [
            ("scope", json!("read ".repeat(64) + "read")),
            ("sub", json!("x".repeat(MAX_IDENTIFIER_BYTES + 1))),
            ("aud", json!(vec![RESOURCE; MAX_AUDIENCES + 1])),
        ] {
            let mut source = claims(NOW);
            source[name] = value;
            assert!(verify_at(&verifier, &sign(&header(), &source), NOW).is_err());
        }
    }

    #[test]
    fn same_kid_key_rotation_reaches_all_clones_without_crossing_independent_verifiers() {
        let admin = verifier();
        let installed = admin.clone();
        let independent = verifier();
        let old = sign(&header(), &claims(NOW));
        let rotated = rotated_token();
        let original = verify_at(&installed, &old, NOW).unwrap();
        assert!(verify_at(&installed, &rotated, NOW).is_err());

        admin.replace_jwks(&rotated_jwks()).unwrap();
        for handle in [&admin, &installed] {
            assert!(verify_at(handle, &old, NOW).is_err());
            let admitted = verify_at(handle, &rotated, NOW).unwrap();
            assert_eq!(admitted.session_owner(), original.session_owner());
            assert_eq!(
                serde_json::to_value(admitted).unwrap(),
                serde_json::to_value(&original).unwrap()
            );
        }
        assert!(verify_at(&independent, &old, NOW).is_ok());
        assert!(verify_at(&independent, &rotated, NOW).is_err());
        assert!(!format!("{admin:?}").contains(ROTATED_MODULUS));
    }

    #[test]
    fn invalid_replacement_preserves_keys_and_already_verified_candidates() {
        let admin = verifier();
        let installed = admin.clone();
        let token = sign(&header(), &claims(NOW));
        let document: Value = serde_json::from_slice(&jwks("one")).unwrap();
        let duplicate = serde_json::to_vec(&json!({"keys":[
            document["keys"][0], document["keys"][0]
        ]}))
        .unwrap();
        for invalid in [
            b"not-json".as_slice(),
            b"{\"keys\":[]}".as_slice(),
            duplicate.as_slice(),
        ] {
            let candidate = installed.prepare_verification(&ctx(), &token).unwrap();
            assert_eq!(
                admin.replace_jwks(invalid),
                Err(JwtResourceAuthError::InvalidKeys)
            );
            assert!(installed.admit_verified(&ctx(), candidate, || Ok(NOW)).is_ok());
            assert!(verify_at(&admin, &token, NOW).is_ok());
        }
    }

    #[test]
    fn replacement_fences_verified_candidates_even_when_jwks_bytes_are_identical() {
        let admin = verifier();
        let installed = admin.clone();
        let token = sign(&header(), &claims(NOW));
        let unchanged = installed.prepare_verification(&ctx(), &token).unwrap();
        assert!(installed.admit_verified(&ctx(), unchanged, || Ok(NOW)).is_ok());
        let stale = installed.prepare_verification(&ctx(), &token).unwrap();
        admin.replace_jwks(&jwks("one")).unwrap();
        let mut clock_called = false;
        assert_eq!(
            installed
                .admit_verified(&ctx(), stale, || {
                    clock_called = true;
                    Ok(NOW)
                })
                .unwrap_err(),
            JwtResourceAuthError::KeysChanged
        );
        assert!(!clock_called);
        assert!(verify_at(&installed, &token, NOW).is_ok());
    }

    #[test]
    fn revocation_stops_clones_and_inflight_candidates_until_explicit_reinstallation() {
        let admin = verifier();
        let installed = admin.clone();
        let independent = verifier();
        let token = sign(&header(), &claims(NOW));
        let candidate = installed.prepare_verification(&ctx(), &token).unwrap();
        assert!(admin.revoke_all().unwrap());
        assert!(!installed.revoke_all().unwrap());
        for handle in [&admin, &installed] {
            assert_eq!(
                verify_at(handle, &token, NOW).unwrap_err(),
                JwtResourceAuthError::KeysUnavailable
            );
        }
        assert_eq!(
            installed.admit_verified(&ctx(), candidate, || Ok(NOW)).unwrap_err(),
            JwtResourceAuthError::KeysUnavailable
        );
        assert!(verify_at(&independent, &token, NOW).is_ok());
        assert!(admin.replace_jwks(b"{\"keys\":[]}").is_err());
        assert_eq!(
            verify_at(&installed, &token, NOW).unwrap_err(),
            JwtResourceAuthError::KeysUnavailable
        );
        admin.replace_jwks(&rotated_jwks()).unwrap();
        assert!(verify_at(&installed, &rotated_token(), NOW).is_ok());
        assert!(verify_at(&installed, &token, NOW).is_err());
    }

    #[test]
    fn poisoned_key_registry_never_recovers_into_an_authentication_grant() {
        let admin = verifier();
        let installed = admin.clone();
        let token = sign(&header(), &claims(NOW));
        let candidate = installed.prepare_verification(&ctx(), &token).unwrap();
        let poisoned = std::panic::catch_unwind(|| {
            let _guard = admin.keys.write().unwrap();
            panic!("test-only registry poison");
        });
        assert!(poisoned.is_err());
        assert_eq!(
            verify_at(&installed, &token, NOW).unwrap_err(),
            JwtResourceAuthError::KeysUnavailable
        );
        assert_eq!(
            installed.admit_verified(&ctx(), candidate, || Ok(NOW)).unwrap_err(),
            JwtResourceAuthError::KeysUnavailable
        );
        assert_eq!(admin.replace_jwks(&jwks("one")), Err(JwtResourceAuthError::KeysUnavailable));
        assert_eq!(admin.revoke_all(), Err(JwtResourceAuthError::KeysUnavailable));
        assert!(verify_at(&verifier(), &token, NOW).is_ok());
    }

    #[test]
    fn expiry_is_rechecked_when_a_verified_candidate_reaches_final_admission() {
        let verifier = verifier();
        let token = sign(&header(), &claims(NOW));
        let live = verifier.prepare_verification(&ctx(), &token).unwrap();
        assert!(verifier.admit_verified(&ctx(), live, || Ok(NOW + 59)).is_ok());
        let expired = verifier.prepare_verification(&ctx(), &token).unwrap();
        assert_eq!(
            verifier.admit_verified(&ctx(), expired, || Ok(NOW + 60)).unwrap_err(),
            JwtResourceAuthError::InvalidClaims
        );
    }
}
