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

// Refresh is an explicit, exclusively owned operation on a device grant. It
// uses the same bounded native exchange without entering device-code polling.
impl DeviceAuthorizationClient {
    /// Renews a device grant through its original trusted HTTPS token endpoint.
    ///
    /// Exclusive access serializes renewal. The endpoint, client, resource,
    /// trust roots, requested scopes and local policy must match the grant's
    /// original client exactly; a mismatch returns InvalidConfiguration without
    /// consuming custody. An already revoked or nonrenewable grant returns
    /// AccessDenied. Access-token expiry alone does not prevent renewal.
    /// Missing runtime capabilities or an already cancelled caller also leave
    /// the existing grant untouched and start no endpoint request.
    ///
    /// The public-client refresh token must rotate to a nonempty, byte-distinct
    /// successor. Returned scopes may narrow the current grant and become the
    /// ceiling for its next renewal. The complete pair is replaced only after
    /// all response and caller-lifetime checks succeed.
    ///
    /// After request custody transfers, every failure, cancellation or dropped
    /// future discards the old refresh token and revokes all old bearer clones.
    /// Success also retires old bearer clones; only the new pair remains usable.
    /// No request is retried, including a device-style pending/slow_down reply.
    /// Previously emitted headers cannot be recalled. Revocation observed before
    /// the final replacement check wins; revoking an old bearer after successful
    /// replacement cannot revoke the independently admitted successor.
    pub async fn refresh(
        &self,
        cx: &asupersync::Cx,
        cancellation: &fastmcp_core::McpRequestCancellation,
        grant: &mut DeviceOAuthCredentials,
    ) -> Result<(), Error> {
        let mut exchange = super::NativeExchange { roots: &self.roots };
        Box::pin(self.refresh_using(cx, cancellation, grant, &mut exchange)).await
    }

    async fn refresh_using<X: super::FormExchange>(
        &self,
        cx: &asupersync::Cx,
        cancellation: &fastmcp_core::McpRequestCancellation,
        grant: &mut DeviceOAuthCredentials,
        exchange: &mut X,
    ) -> Result<(), Error> {
        let timeout = self.policy.timeout.min(self.policy.exchange_timeout);
        let deadline = super::operation_deadline(cx, cancellation, timeout)?;
        if &grant.client != self {
            return Err(Error::InvalidConfiguration);
        }
        if grant.access.is_revoked() {
            return Err(Error::AccessDenied);
        }
        let previous = grant.refresh_token.as_ref().ok_or(Error::AccessDenied)?;
        let scope = grant.scopes.join(" ");
        let mut fields = vec![
            ("grant_type", "refresh_token"),
            ("client_id", self.client_id.as_str()),
            ("refresh_token", previous.as_str()),
            ("resource", self.resource.as_str()),
        ];
        if !scope.is_empty() {
            fields.push(("scope", scope.as_str()));
        }
        let body = form(&fields)?;
        super::check(cx, cancellation, deadline)?;
        if grant.access.is_revoked() {
            return Err(Error::AccessDenied);
        }
        // There is no await between the final local preflight and transferring
        // one-use custody. Once transferred, even an abandoned exchange retires
        // the old family instead of making uncertain remote consumption reusable.
        let previous = grant.refresh_token.take().ok_or(Error::AccessDenied)?;
        let retirement = RefreshRetirement(grant.access.revoked.clone());
        let started = Instant::now();
        let response = while_refresh_live(
            &retirement.0,
            self.exchange(
                cx,
                cancellation,
                deadline,
                exchange,
                &self.token_endpoint,
                body,
            ),
        )
        .await?;
        if response.status != 200 {
            return Err(Error::EndpointRejected {
                status: response.status,
            });
        }
        let overlay: RefreshResponseOverlay = decode(&response.body)?;
        if overlay.id_token.is_some() || overlay.issued_token_type.is_some() {
            return Err(Error::InvalidResponse);
        }
        let replacement = credentials(self, &grant.scopes, &response.body, started)?;
        let successor = replacement
            .refresh_token
            .as_ref()
            .ok_or(Error::InvalidResponse)?;
        if successor.as_str() == previous.as_str() {
            return Err(Error::InvalidResponse);
        }
        super::check(cx, cancellation, deadline)?;
        if retirement.0.is_cancel_requested() {
            return Err(Error::AccessDenied);
        }
        // This synchronous check/replace is the local publication boundary.
        // The new bearer has an independent revocation signal, so retiring the
        // old family cannot disable the newly admitted pair.
        *grant = replacement;
        Ok(())
    }
}

// Presence-aware overlays reject an unnegotiated identity/token-exchange
// profile even when its extra member is null. Values are never retained.
#[derive(Deserialize)]
struct RefreshResponseOverlay {
    #[serde(default, deserialize_with = "present")]
    id_token: Option<serde::de::IgnoredAny>,
    #[serde(default, deserialize_with = "present")]
    issued_token_type: Option<serde::de::IgnoredAny>,
}

struct RefreshRetirement(fastmcp_core::McpRequestCancellation);

impl Drop for RefreshRetirement {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

async fn while_refresh_live<T>(
    revoked: &fastmcp_core::McpRequestCancellation,
    operation: impl std::future::Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    use std::future::Future;
    use std::task::Poll;

    let mut revoked_wait = std::pin::pin!(revoked.cancelled());
    let mut operation = std::pin::pin!(operation);
    std::future::poll_fn(|task| {
        if revoked.is_cancel_requested() || revoked_wait.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(Error::AccessDenied));
        }
        let result = operation.as_mut().poll(task);
        if revoked.is_cancel_requested() {
            Poll::Ready(Err(Error::AccessDenied))
        } else {
            result
        }
    })
    .await
}

#[cfg(test)]
mod refresh_tests {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Wake, Waker};

    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::time::{TimerDriverHandle, VirtualClock};
    use fastmcp_core::McpRequestCancellation;
    use serde_json::{Value, json};

    use super::super::{ExchangeFuture, ExchangeResponse, FormExchange};
    use super::*;

    fn url(value: &str) -> CanonicalHttpUrl {
        CanonicalHttpUrl::parse(value).unwrap()
    }

    fn client() -> DeviceAuthorizationClient {
        DeviceAuthorizationClient::from_trusted_endpoints(
            url("https://issuer.example/device"),
            url("https://issuer.example/token"),
            url("https://issuer.example/"),
            url("https://resource.example/mcp"),
            "native-client",
            vec!["read".to_owned(), "write".to_owned()],
        )
        .unwrap()
    }

    fn token(refresh: &str) -> Value {
        json!({
            "access_token": "replacement-access",
            "token_type": "Bearer",
            "expires_in": 120,
            "refresh_token": refresh
        })
    }

    fn seed(client: &DeviceAuthorizationClient) -> DeviceOAuthCredentials {
        credentials(
            client,
            &client.scopes,
            &serde_json::to_vec(&token("refresh-before")).unwrap(),
            Instant::now(),
        )
        .unwrap()
    }

    fn reply(status: u16, body: Value) -> Result<ExchangeResponse, Error> {
        Ok(ExchangeResponse {
            status,
            body: serde_json::to_vec(&body).unwrap(),
        })
    }

    type Seen = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    struct Script {
        replies: VecDeque<Result<ExchangeResponse, Error>>,
        seen: Seen,
        revoke_before_reply: Option<BoundBearerCredential>,
    }

    impl Script {
        fn new(replies: impl IntoIterator<Item = Result<ExchangeResponse, Error>>) -> Self {
            Self {
                replies: replies.into_iter().collect(),
                seen: Arc::new(Mutex::new(Vec::new())),
                revoke_before_reply: None,
            }
        }
    }

    impl FormExchange for Script {
        fn post<'a>(
            &'a mut self,
            cx: &'a asupersync::Cx,
            endpoint: &'a CanonicalHttpUrl,
            body: Vec<u8>,
        ) -> ExchangeFuture<'a> {
            assert_eq!(asupersync::Cx::current().unwrap().task_id(), cx.task_id());
            self.seen
                .lock()
                .unwrap()
                .push((endpoint.as_str().to_owned(), body));
            Box::pin(async move {
                if let Some(credential) = self.revoke_before_reply.take() {
                    credential.revoke();
                }
                self.replies.pop_front().expect("refresh must never replay")
            })
        }
    }

    fn runtime(test: impl FnOnce(&asupersync::Cx, &Arc<VirtualClock>)) {
        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(timer.clone())
            .build()
            .unwrap();
        let cx = runtime.request_cx_with_budget(Budget::INFINITE);
        test(&cx, &clock);
        assert_eq!(timer.pending_count(), 0);
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    fn once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn refresh_rotates_expired_access_and_preserves_each_narrowed_scope_ceiling() {
        runtime(|cx, _| {
            let client = client();
            let mut grant = seed(&client);
            let expired = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
            grant.access = BoundBearerCredential::bind_with_expiry(
                client.resource.clone(),
                "expired-access",
                expired,
            )
            .unwrap();
            grant.expires_at = expired;
            let old = grant.bearer_credential().clone();
            let mut first = token("refresh-after");
            first["scope"] = json!("read");
            let mut script = Script::new([reply(200, first), reply(200, token("refresh-final"))]);
            let seen = Arc::clone(&script.seen);
            let cancellation = McpRequestCancellation::new();
            let mut future =
                Box::pin(client.refresh_using(cx, &cancellation, &mut grant, &mut script));
            assert_eq!(once(future.as_mut()), Poll::Ready(Ok(())));
            drop(future);
            assert!(old.is_revoked());
            assert_eq!(grant.scopes(), ["read"]);
            assert_eq!(
                grant.refresh_token.as_ref().unwrap().as_str(),
                "refresh-after"
            );
            assert!(!grant.access.is_revoked());
            assert_eq!(
                grant
                    .bearer_credential()
                    .authorization_for_target(&client.resource),
                Some("Bearer replacement-access".to_owned())
            );
            let middle = grant.bearer_credential().clone();
            let mut future =
                Box::pin(client.refresh_using(cx, &cancellation, &mut grant, &mut script));
            assert_eq!(once(future.as_mut()), Poll::Ready(Ok(())));
            drop(future);
            assert!(middle.is_revoked());
            assert!(!grant.access.is_revoked());
            assert_eq!(grant.scopes(), ["read"]);
            assert_eq!(
                grant.refresh_token.as_ref().unwrap().as_str(),
                "refresh-final"
            );
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 2);
            assert_eq!(seen[0].0, "https://issuer.example/token");
            assert_eq!(seen[1].0, seen[0].0);
            assert_eq!(
                std::str::from_utf8(&seen[0].1).unwrap(),
                "grant_type=refresh_token&client_id=native-client&refresh_token=refresh-before&resource=https%3A%2F%2Fresource.example%2Fmcp&scope=read+write"
            );
            assert_eq!(
                std::str::from_utf8(&seen[1].1).unwrap(),
                "grant_type=refresh_token&client_id=native-client&refresh_token=refresh-after&resource=https%3A%2F%2Fresource.example%2Fmcp&scope=read"
            );
        });
    }

    #[test]
    fn refresh_refuses_missing_identical_malformed_or_expanded_successors() {
        runtime(|cx, _| {
            let client = client();
            let cancellation = McpRequestCancellation::new();
            let mut missing = token("unused");
            missing.as_object_mut().unwrap().remove("refresh_token");
            let mut null = token("unused");
            null["refresh_token"] = Value::Null;
            let mut expanded = token("refresh-after");
            expanded["scope"] = json!("admin");
            let mut empty = token("refresh-after");
            empty["scope"] = json!("");
            let mut mixed = token("refresh-after");
            mixed["error"] = json!("invalid_grant");
            let mut identity = token("refresh-after");
            identity["id_token"] = Value::Null;
            let mut exchange = token("refresh-after");
            exchange["issued_token_type"] = json!("urn:ietf:params:oauth:token-type:id-jag");
            for body in [
                missing,
                token("refresh-before"),
                token(""),
                null,
                expanded,
                empty,
                mixed,
                identity,
                exchange,
            ] {
                let mut grant = seed(&client);
                let old = grant.bearer_credential().clone();
                let mut script = Script::new([reply(200, body)]);
                let seen = Arc::clone(&script.seen);
                let mut future =
                    Box::pin(client.refresh_using(cx, &cancellation, &mut grant, &mut script));
                assert!(matches!(
                    once(future.as_mut()),
                    Poll::Ready(Err(Error::InvalidResponse | Error::ScopeExpansion))
                ));
                drop(future);
                assert!(old.is_revoked());
                assert!(
                    grant
                        .bearer_credential()
                        .authorization_for_target(&client.resource)
                        .is_none()
                );
                assert!(!grant.has_refresh_token());
                let mut retry =
                    Box::pin(client.refresh_using(cx, &cancellation, &mut grant, &mut script));
                assert_eq!(once(retry.as_mut()), Poll::Ready(Err(Error::AccessDenied)));
                drop(retry);
                assert_eq!(seen.lock().unwrap().len(), 1);
            }
        });
    }

    #[test]
    fn refresh_never_polls_retries_or_restores_after_endpoint_or_transport_failure() {
        runtime(|cx, _| {
            let client = client();
            let cancellation = McpRequestCancellation::new();
            for response in [
                reply(400, json!({"error":"authorization_pending"})),
                reply(400, json!({"error":"slow_down"})),
                reply(400, json!({"error":"invalid_grant"})),
                reply(307, token("refresh-after")),
                reply(201, token("refresh-after")),
                Err(Error::TransportFailed),
            ] {
                let mut grant = seed(&client);
                let old = grant.bearer_credential().clone();
                let mut script = Script::new([response]);
                let seen = Arc::clone(&script.seen);
                let mut future =
                    Box::pin(client.refresh_using(cx, &cancellation, &mut grant, &mut script));
                assert!(matches!(
                    once(future.as_mut()),
                    Poll::Ready(Err(Error::EndpointRejected { .. } | Error::TransportFailed))
                ));
                drop(future);
                assert!(old.is_revoked());
                assert!(!grant.has_refresh_token());
                assert_eq!(seen.lock().unwrap().len(), 1);
            }
        });
    }

    #[test]
    fn public_refresh_preflight_and_unpolled_drop_preserve_existing_custody() {
        runtime(|cx, _| {
            let client = client();
            let mut grant = seed(&client);
            let old = grant.bearer_credential().clone();
            let cancellation = McpRequestCancellation::new();
            for dimension in 0..7 {
                let mut foreign = client.clone();
                match dimension {
                    0 => foreign.device_endpoint = url("https://other.example/device"),
                    1 => foreign.token_endpoint = url("https://other.example/token"),
                    2 => foreign.resource = url("https://other.example/mcp"),
                    3 => foreign.client_id = "another-client".to_owned(),
                    4 => foreign.scopes = vec!["read".to_owned()],
                    5 => foreign.roots.push(vec![1]),
                    _ => foreign.policy.exchange_timeout = Duration::from_secs(1),
                }
                let mut future = Box::pin(foreign.refresh(cx, &cancellation, &mut grant));
                assert_eq!(
                    once(future.as_mut()),
                    Poll::Ready(Err(Error::InvalidConfiguration))
                );
                drop(future);
                assert!(!old.is_revoked());
                assert_eq!(
                    grant.refresh_token.as_ref().unwrap().as_str(),
                    "refresh-before"
                );
            }
            let cancelled = McpRequestCancellation::new();
            cancelled.cancel();
            let mut future = Box::pin(client.refresh(cx, &cancelled, &mut grant));
            assert_eq!(once(future.as_mut()), Poll::Ready(Err(Error::Cancelled)));
            drop(future);
            drop(client.refresh(cx, &cancellation, &mut grant));
            assert!(!old.is_revoked());
            assert!(grant.has_refresh_token());

            grant.refresh_token = None;
            let mut future = Box::pin(client.refresh(cx, &cancellation, &mut grant));
            assert_eq!(once(future.as_mut()), Poll::Ready(Err(Error::AccessDenied)));
            drop(future);
            assert!(!old.is_revoked());
        });
    }

    #[test]
    fn public_refresh_without_runtime_leaves_grant_usable() {
        let cx = asupersync::Cx::for_testing();
        let client = client();
        let mut grant = seed(&client);
        let old = grant.bearer_credential().clone();
        let cancellation = McpRequestCancellation::new();
        let mut future = Box::pin(client.refresh(&cx, &cancellation, &mut grant));
        assert_eq!(
            once(future.as_mut()),
            Poll::Ready(Err(Error::RuntimeUnavailable))
        );
        drop(future);
        assert!(!old.is_revoked());
        assert_eq!(
            grant.refresh_token.as_ref().unwrap().as_str(),
            "refresh-before"
        );
        assert!(
            grant
                .bearer_credential()
                .authorization_for_target(client.resource())
                .is_some()
        );
    }

    struct OwnedExchange(Arc<AtomicUsize>);
    impl Drop for OwnedExchange {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct Quiet {
        calls: Arc<AtomicUsize>,
        dropped: Arc<AtomicUsize>,
    }

    impl FormExchange for Quiet {
        fn post<'a>(
            &'a mut self,
            _: &'a asupersync::Cx,
            _: &'a CanonicalHttpUrl,
            _: Vec<u8>,
        ) -> ExchangeFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let owned = OwnedExchange(Arc::clone(&self.dropped));
            Box::pin(async move {
                let _owned = owned;
                std::future::pending().await
            })
        }
    }

    #[derive(Default)]
    struct Wakes(AtomicUsize);
    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn quiet_refresh_drop_cancellation_revocation_and_deadline_retire_old_family() {
        for outcome in 0..4 {
            runtime(|cx, clock| {
                let client = client();
                let cancellation = McpRequestCancellation::new();
                let mut grant = seed(&client);
                let old = grant.bearer_credential().clone();
                let calls = Arc::new(AtomicUsize::new(0));
                let dropped = Arc::new(AtomicUsize::new(0));
                let mut quiet = Quiet {
                    calls: Arc::clone(&calls),
                    dropped: Arc::clone(&dropped),
                };
                let wakes = Arc::new(Wakes::default());
                let waker = Waker::from(Arc::clone(&wakes));
                let mut future =
                    Box::pin(client.refresh_using(cx, &cancellation, &mut grant, &mut quiet));
                assert!(
                    future
                        .as_mut()
                        .poll(&mut Context::from_waker(&waker))
                        .is_pending()
                );
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                let wakes_before = wakes.0.load(Ordering::SeqCst);
                match outcome {
                    0 => {}
                    1 => {
                        cancellation.cancel();
                        assert!(wakes.0.load(Ordering::SeqCst) > wakes_before);
                        assert_eq!(once(future.as_mut()), Poll::Ready(Err(Error::Cancelled)));
                    }
                    2 => {
                        old.revoke();
                        assert!(wakes.0.load(Ordering::SeqCst) > wakes_before);
                        assert_eq!(once(future.as_mut()), Poll::Ready(Err(Error::AccessDenied)));
                    }
                    _ => {
                        clock.advance(31_000_000_000);
                        assert_eq!(once(future.as_mut()), Poll::Ready(Err(Error::TimedOut)));
                    }
                }
                drop(future);
                assert!(old.is_revoked());
                assert!(!grant.has_refresh_token());
                assert_eq!(dropped.load(Ordering::SeqCst), 1);
                assert_eq!(calls.load(Ordering::SeqCst), 1);
            });
        }
    }

    #[test]
    fn revocation_during_ready_token_response_prevents_successor_publication() {
        runtime(|cx, _| {
            let client = client();
            let cancellation = McpRequestCancellation::new();
            let mut grant = seed(&client);
            let old = grant.bearer_credential().clone();
            let mut script = Script::new([reply(200, token("refresh-after"))]);
            script.revoke_before_reply = Some(old.clone());
            let mut future =
                Box::pin(client.refresh_using(cx, &cancellation, &mut grant, &mut script));
            assert_eq!(once(future.as_mut()), Poll::Ready(Err(Error::AccessDenied)));
            drop(future);
            assert!(old.is_revoked());
            assert!(!grant.has_refresh_token());
            assert!(
                grant
                    .bearer_credential()
                    .authorization_for_target(&client.resource)
                    .is_none()
            );
        });
    }

    #[test]
    fn refresh_uses_the_earliest_total_exchange_and_caller_deadline() {
        for (total, exchange, caller) in [(1, 30, 60), (60, 1, 60), (60, 30, 1)] {
            let clock = Arc::new(VirtualClock::new());
            let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
            let runtime = RuntimeBuilder::current_thread()
                .blocking_threads(0, 0)
                .with_timer_driver(timer.clone())
                .build()
                .unwrap();
            let cx = runtime.request_cx_with_budget(
                Budget::INFINITE.with_deadline(asupersync::types::Time::from_secs(caller)),
            );
            let mut client = client();
            client.policy.timeout = Duration::from_secs(total);
            client.policy.exchange_timeout = Duration::from_secs(exchange);
            let mut grant = seed(&client);
            let old = grant.bearer_credential().clone();
            let cancellation = McpRequestCancellation::new();
            let calls = Arc::new(AtomicUsize::new(0));
            let dropped = Arc::new(AtomicUsize::new(0));
            let mut quiet = Quiet {
                calls: Arc::clone(&calls),
                dropped: Arc::clone(&dropped),
            };
            let mut future =
                Box::pin(client.refresh_using(&cx, &cancellation, &mut grant, &mut quiet));
            assert!(once(future.as_mut()).is_pending());
            clock.advance(999_999_999);
            assert!(once(future.as_mut()).is_pending());
            clock.advance(1);
            assert_eq!(once(future.as_mut()), Poll::Ready(Err(Error::TimedOut)));
            drop(future);
            assert!(old.is_revoked());
            assert!(!grant.has_refresh_token());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            assert_eq!(timer.pending_count(), 0);
            drop(cx);
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }

    #[cfg(feature = "native-tls-roots")]
    mod native {
        use std::future::poll_fn;

        use asupersync::io::{AsyncReadExt, AsyncWriteExt};
        use asupersync::net::TcpListener;
        use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder};

        use super::*;

        // TEST ONLY: the same localhost CA/leaf/key used by native OAuth tests.
        const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
        const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
        const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";

        async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
            let mut left = std::pin::pin!(left);
            let mut right = std::pin::pin!(right);
            let mut left_output = None;
            let mut right_output = None;
            poll_fn(|task| {
                if left_output.is_none() {
                    if let Poll::Ready(value) = left.as_mut().poll(task) {
                        left_output = Some(value);
                    }
                }
                if right_output.is_none() {
                    if let Poll::Ready(value) = right.as_mut().poll(task) {
                        right_output = Some(value);
                    }
                }
                if left_output.is_some() && right_output.is_some() {
                    Poll::Ready((left_output.take().unwrap(), right_output.take().unwrap()))
                } else {
                    Poll::Pending
                }
            })
            .await
        }

        async fn request<IO: asupersync::io::AsyncRead + Unpin>(stream: &mut IO) -> String {
            let mut bytes = Vec::new();
            let mut buffer = [0; 1024];
            let header_end = loop {
                let count = stream.read(&mut buffer).await.unwrap();
                assert!(count > 0 && bytes.len() + count <= MAX_FORM_BYTES);
                bytes.extend_from_slice(&buffer[..count]);
                if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let header = std::str::from_utf8(&bytes[..header_end]).unwrap();
            assert!(header.starts_with("POST /token HTTP/1.1\r\n"));
            assert!(!header.to_ascii_lowercase().contains("authorization:"));
            assert!(!header.to_ascii_lowercase().contains("cookie:"));
            let length = header
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            assert!(header_end + length <= MAX_FORM_BYTES);
            while bytes.len() < header_end + length {
                let count = stream.read(&mut buffer).await.unwrap();
                assert!(count > 0 && bytes.len() + count <= MAX_FORM_BYTES);
                bytes.extend_from_slice(&buffer[..count]);
            }
            assert_eq!(bytes.len(), header_end + length);
            String::from_utf8(bytes[header_end..].to_vec()).unwrap()
        }

        #[test]
        fn public_native_https_refresh_rotates_and_rejects_missing_or_repeated_successor() {
            let runtime = RuntimeBuilder::current_thread()
                .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
                .blocking_threads(0, 8)
                .build()
                .unwrap();
            runtime.block_on(async {
                let cx = asupersync::Cx::current().unwrap();
                for successor in [Some("refresh-after"), Some("refresh-before"), None] {
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let address = listener.local_addr().unwrap();
                    let mut configured = client();
                    configured.token_endpoint = url(&format!("https://{address}/token"));
                    configured = configured.with_extra_root_certificate(
                        Certificate::from_pem(ROOT).unwrap().remove(0),
                    ).unwrap();
                    let mut grant = seed(&configured);
                    let old = grant.bearer_credential().clone();
                    let cancellation = McpRequestCancellation::new();
                    let deadline = super::super::super::operation_deadline(
                        &cx, &cancellation, Duration::from_secs(10),
                    ).unwrap();
                    let acceptor = TlsAcceptorBuilder::new(
                        CertificateChain::from_pem(LEAF).unwrap(),
                        PrivateKey::from_pem(KEY).unwrap(),
                    ).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap();
                    let server = async {
                        let (socket, _) = listener.accept().await.unwrap();
                        let mut tls = acceptor.accept(socket).await.unwrap();
                        let body = request(&mut tls).await;
                        assert_eq!(
                            body,
                            "grant_type=refresh_token&client_id=native-client&refresh_token=refresh-before&resource=https%3A%2F%2Fresource.example%2Fmcp&scope=read+write"
                        );
                        let mut response = token(successor.unwrap_or("unused"));
                        response["scope"] = json!("read");
                        if successor.is_none() {
                            response.as_object_mut().unwrap().remove("refresh_token");
                        }
                        let body = serde_json::to_string(&response).unwrap();
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        tls.write_all(response.as_bytes()).await.unwrap();
                        tls.shutdown().await.unwrap();
                    };
                    let application = configured.refresh(&cx, &cancellation, &mut grant);
                    let (_, outcome) = super::super::super::within(
                        &cx, &cancellation, deadline,
                        async { Ok(pair(server, application).await) },
                    ).await.unwrap();
                    assert!(old.is_revoked());
                    if successor == Some("refresh-after") {
                        assert_eq!(outcome, Ok(()));
                        assert_eq!(grant.scopes(), ["read"]);
                        assert!(grant.has_refresh_token());
                        assert_eq!(
                            grant.bearer_credential().authorization_for_target(configured.resource()),
                            Some("Bearer replacement-access".to_owned())
                        );
                        assert!(grant.bearer_credential().authorization_for_target(
                            &url("https://resource.example/other")
                        ).is_none());
                    } else {
                        assert_eq!(outcome, Err(Error::InvalidResponse));
                        assert!(!grant.has_refresh_token());
                        assert!(grant.bearer_credential().authorization_for_target(configured.resource()).is_none());
                    }
                }
            });
            assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        }
    }
}
