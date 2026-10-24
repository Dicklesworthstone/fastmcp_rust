//! Bounded device-flow wire admission, shared by native I/O and scripted tests.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use asupersync::security::SecretString;
use fastmcp_protocol::{SecurityDocumentKind, admit_security_document};
use serde::{Deserialize, Deserializer};

use super::{BoundBearerCredential, CanonicalHttpUrl, DeviceAuthorizationClient, DeviceAuthorizationError as Error, DeviceOAuthCredentials, DeviceVerification};

pub(super) const MAX_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_FORM_BYTES: usize = 32 * 1024;

fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}
fn secret<'de, D: Deserializer<'de>>(d: D) -> Result<SecretString, D::Error> {
    String::deserialize(d).map(SecretString::from_string)
}
fn optional_secret<'de, D: Deserializer<'de>>(d: D) -> Result<Option<SecretString>, D::Error> {
    secret(d).map(Some)
}

#[derive(Deserialize)]
struct DeviceResponse {
    #[serde(deserialize_with = "secret")]
    device_code: SecretString,
    #[serde(deserialize_with = "secret")]
    user_code: SecretString,
    verification_uri: String,
    #[serde(default, deserialize_with = "present")]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    #[serde(default, deserialize_with = "present")]
    interval: Option<u64>,
    #[serde(default, deserialize_with = "present")]
    error: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    #[serde(default, deserialize_with = "present")]
    expires_in: Option<u64>,
    #[serde(default, deserialize_with = "optional_secret")]
    refresh_token: Option<SecretString>,
    #[serde(default, deserialize_with = "present")]
    scope: Option<String>,
    #[serde(default, deserialize_with = "present")]
    error: Option<String>,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
    // A success payload cannot be laundered into permission to poll again.
    #[serde(default, deserialize_with = "optional_secret")]
    access_token: Option<SecretString>,
    #[serde(default, deserialize_with = "optional_secret")]
    refresh_token: Option<SecretString>,
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    // Use the common bounded security-JSON pass before serde: all duplicate
    // members (including unknown/nested ones), depth and number limits apply.
    if bytes.len() > MAX_RESPONSE_BYTES { return Err(Error::InvalidResponse); }
    admit_security_document(SecurityDocumentKind::TokenResponse, bytes).map_err(|_| Error::InvalidResponse)?;
    serde_json::from_slice(bytes).map_err(|_| Error::InvalidResponse)
}

pub(super) fn https(url: &CanonicalHttpUrl, query_allowed: bool) -> Result<(), Error> {
    if url.as_str().len() > 4096 || url.scheme() != "https" || url.has_userinfo()
        || url.fragment().is_some() || (!query_allowed && url.query().is_some())
    {
        return Err(Error::InvalidResponse);
    }
    Ok(())
}

fn origin(url: &CanonicalHttpUrl) -> &str {
    // CanonicalHttpUrl always has a path. No userinfo or fragment was admitted.
    let rest = url.as_str().strip_prefix("https://").unwrap_or("");
    rest.split('/').next().unwrap_or("")
}

fn verification(client: &DeviceAuthorizationClient, raw: &str) -> Result<CanonicalHttpUrl, Error> {
    if raw.len() > 4096 || raw.chars().any(|c| c.is_whitespace() || c.is_control()) || raw.contains('\\') {
        return Err(Error::UntrustedVerificationUri);
    }
    let url = CanonicalHttpUrl::parse(raw).map_err(|_| Error::UntrustedVerificationUri)?;
    https(&url, true).map_err(|_| Error::UntrustedVerificationUri)?;
    if origin(&url) != origin(&client.verification_origin) {
        return Err(Error::UntrustedVerificationUri);
    }
    Ok(url)
}

fn opaque(text: &str, maximum: usize) -> bool {
    !text.is_empty() && text.len() <= maximum && text.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

pub(super) fn device(client: &DeviceAuthorizationClient, body: &[u8]) -> Result<(DeviceVerification, SecretString, Duration, Duration), Error> {
    let response: DeviceResponse = decode(body)?;
    let interval = response.interval.unwrap_or(5);
    if response.error.is_some() || !opaque(response.device_code.as_str(), 4096)
        || !opaque(response.user_code.as_str(), 256)
        || !(1..=86_400).contains(&response.expires_in) || !(1..=3600).contains(&interval)
    {
        return Err(Error::InvalidResponse);
    }
    let verification_uri = verification(client, &response.verification_uri)?;
    let verification_uri_complete = response.verification_uri_complete.as_deref()
        .map(|raw| verification(client, raw)).transpose()?;
    let lifetime = Duration::from_secs(response.expires_in);
    Ok((DeviceVerification {
        user_code: response.user_code, verification_uri, verification_uri_complete,
        expires_in: lifetime,
    }, response.device_code, Duration::from_secs(interval), lifetime))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PollResponse { Token, Pending, SlowDown }

pub(super) fn poll_response(status: u16, body: &[u8]) -> Result<PollResponse, Error> {
    if status == 200 { return Ok(PollResponse::Token); }
    if status != 400 { return Err(Error::EndpointRejected { status }); }
    let response: ErrorResponse = decode(body)?;
    if response.access_token.is_some() || response.refresh_token.is_some() { return Err(Error::InvalidResponse); }
    match response.error.as_str() {
        "authorization_pending" => Ok(PollResponse::Pending),
        "slow_down" => Ok(PollResponse::SlowDown),
        "access_denied" => Err(Error::AccessDenied),
        "expired_token" => Err(Error::ExpiredCode),
        _ => Err(Error::EndpointRejected { status }),
    }
}

pub(super) fn validate_scopes(scopes: &[String]) -> Result<(), Error> {
    if scopes.len() > 32 || scopes.iter().map(String::len).sum::<usize>() > 4096 { return Err(Error::InvalidResponse); }
    let mut seen = BTreeSet::new();
    for scope in scopes {
        if scope.is_empty() || scope.len() > 256 || !seen.insert(scope)
            || !scope.bytes().all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
        {
            return Err(Error::InvalidResponse);
        }
    }
    Ok(())
}

pub(super) fn credentials(client: &DeviceAuthorizationClient, ceiling: &[String], body: &[u8], started: Instant) -> Result<DeviceOAuthCredentials, Error> {
    let response: TokenResponse = decode(body)?;
    if response.error.is_some() || !response.token_type.eq_ignore_ascii_case("Bearer")
        || response.expires_in == Some(0)
        || response.refresh_token.as_ref().is_some_and(|token| !opaque(token.as_str(), 4096))
    {
        return Err(Error::InvalidResponse);
    }
    let scopes = match response.scope {
        None => ceiling.to_vec(),
        Some(scope) => scope.split(' ').map(str::to_owned).collect(),
    };
    validate_scopes(&scopes)?;
    if scopes.iter().any(|scope| !ceiling.contains(scope)) { return Err(Error::ScopeExpansion); }
    let lifetime = response.expires_in.map(Duration::from_secs)
        .unwrap_or(client.policy.maximum_token_lifetime).min(client.policy.maximum_token_lifetime);
    let expires_at = started.checked_add(lifetime).ok_or(Error::InvalidResponse)?;
    if Instant::now() >= expires_at { return Err(Error::InvalidResponse); }
    let access = BoundBearerCredential::bind_with_expiry(client.resource.clone(), response.access_token, expires_at)
        .map_err(|_| Error::InvalidResponse)?;
    Ok(DeviceOAuthCredentials {
        client: client.clone(), access, refresh_token: response.refresh_token, scopes, expires_at,
    })
}

pub(super) fn headers(headers: &[(String, String)]) -> Result<(), Error> {
    let mut media = None;
    let mut encoding = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-type") && media.replace(value.as_str()).is_some() { return Err(Error::InvalidResponse); }
        if name.eq_ignore_ascii_case("content-encoding") {
            if encoding || !value.trim().eq_ignore_ascii_case("identity") { return Err(Error::InvalidResponse); }
            encoding = true;
        }
    }
    let mut parts = media.ok_or(Error::InvalidResponse)?.split(';');
    if !parts.next().is_some_and(|p| p.trim().eq_ignore_ascii_case("application/json")) { return Err(Error::InvalidResponse); }
    if let Some(parameter) = parts.next() {
        let (name, value) = parameter.trim().split_once('=').ok_or(Error::InvalidResponse)?;
        if !name.trim().eq_ignore_ascii_case("charset")
            || !(value.trim().eq_ignore_ascii_case("utf-8") || value.trim().eq_ignore_ascii_case("\"utf-8\""))
            || parts.next().is_some()
        {
            return Err(Error::InvalidResponse);
        }
    }
    Ok(())
}

pub(super) fn form(fields: &[(&str, &str)]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for (index, (name, value)) in fields.iter().enumerate() {
        if index != 0 { out.push(b'&'); }
        for (part, text) in [*name, *value].into_iter().enumerate() {
            if part != 0 { out.push(b'='); }
            for b in text.bytes() {
                let count = if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b' ') { 1 } else { 3 };
                if out.len().checked_add(count).is_none_or(|size| size > MAX_FORM_BYTES) { return Err(Error::InvalidConfiguration); }
                match b {
                    b' ' => out.push(b'+'),
                    b if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') => out.push(b),
                    _ => out.extend_from_slice(&[b'%', HEX[(b >> 4) as usize], HEX[(b & 15) as usize]]),
                }
            }
        }
    }
    if out.len() > MAX_FORM_BYTES { return Err(Error::InvalidConfiguration); }
    Ok(out)
}
