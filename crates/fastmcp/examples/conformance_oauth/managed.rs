//! Explicit managed-refresh profile for the same conformance operations.
//!
//! Login uses the parent's admitted trust/registration plan. The session keeps
//! refresh-token custody; no access snapshot is installed as a permanent client.
//! New operations may renew, but failed operations are never replayed. The run
//! owner closes all generations on drop, including clients retained by a caller.

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::Duration;

use asupersync::channel::oneshot;
use asupersync::time::Sleep;
use fastmcp_client::http_auth::managed::{ManagedOAuthSession, OAuthSessionPolicy};
use fastmcp_client::http_auth::managed::client::{ManagedHttpClient, ManagedHttpClientError};
use fastmcp_client::http_executor::parameter_headers::ReviewedToolHeaders;
use fastmcp_client::{ClientBuilder, HttpClient, HttpClientError, ProtocolPolicy};
use fastmcp_core::{CanonicalHttpUrl, Cx, McpErrorCode};
use fastmcp_protocol::CoreResult;
use fastmcp_protocol::http_headers::ParameterHeaderBinding;
use serde_json::Value;

use super::{INVALID, OAuthClient, PreparedOAuth, with_authorization_driver};

pub(crate) const ENVIRONMENT: &str = "FASTMCP_CONFORMANCE_MANAGED_REFRESH";

/// Mode selection is local policy, never a scenario or challenge instruction.
pub(crate) fn selected(flag: Option<&str>, oauth_present: bool) -> Result<bool, String> {
    match flag {
        None | Some("0" | "false") => Ok(false),
        Some("1" | "true") if oauth_present => Ok(true),
        _ => Err("managed refresh requires a valid flag and explicit OAuth configuration".to_owned()),
    }
}

pub(crate) struct ManagedGrant {
    session: ManagedOAuthSession,
    builder: ClientBuilder,
    timeout: Duration,
}

impl Drop for ManagedGrant {
    fn drop(&mut self) {
        // Local revocation and grant disposal, not an RFC 7009 network request.
        self.session.close();
    }
}

impl ManagedGrant {
    pub(crate) fn client(&self) -> Result<FixtureClient, String> {
        ManagedHttpClient::new(self.session.clone(), self.builder.clone(), self.timeout)
            .map(|client| FixtureClient::Managed(Box::new(client)))
            .map_err(|_| "managed MCP client configuration failed".to_owned())
    }

    pub(crate) async fn run<T>(
        &self,
        cx: &Cx,
        future: impl Future<Output = Result<T, String>>,
    ) -> Result<T, String> {
        // Do not cap the whole run at the first token's expiry. Each logical
        // operation retains its own original token lifetime in ManagedHttpClient.
        // Renewal can extend subsequent operations, never the overall deadline.
        bounded_run(cx, self.timeout, future).await
    }
}

pub(crate) async fn configure(
    cx: &Cx,
    endpoint: &CanonicalHttpUrl,
    mut builder: ClientBuilder,
    raw: &str,
) -> Result<ManagedGrant, String> {
    let PreparedOAuth { login, driver, resource, resource_root, timeout } =
        PreparedOAuth::parse(raw, endpoint)?;
    if builder.selected_protocol_plan().policy() != ProtocolPolicy::ModernOnly
        || builder.selected_protocol_plan().modern_post_target() != Some(endpoint.as_str())
    {
        return Err(INVALID.to_owned());
    }
    if let Some(certificate) = resource_root {
        builder = builder.http_resource_root_certificate(resource, certificate)
            .map_err(|_| INVALID.to_owned())?;
    }
    builder.http_negotiation().map_err(|_| INVALID.to_owned())?;
    // The scope includes discovery and an explicitly authorized DCR write,
    // not just browser launch. No failed login can switch identity or mode.
    with_authorization_driver(
        cx,
        timeout,
        |launcher| async move {
            let configuration = login.resolve(cx).await?;
            let session = ManagedOAuthSession::authorize(
                cx,
                OAuthClient::new(configuration),
                OAuthSessionPolicy::default(),
                move |url| launcher.launch(url),
            ).await.map_err(|_| "managed OAuth login failed".to_owned())?;
            // Construct the drop guard before returning through the outer
            // lifetime checks, so late cancellation also closes the new grant.
            Ok::<ManagedGrant, String>(ManagedGrant { session, builder, timeout })
        },
        |url| driver.drive(cx, url),
    ).await.map_err(|_| "explicit managed OAuth authorization failed".to_owned())
}

async fn bounded_run<T>(
    cx: &Cx,
    timeout: Duration,
    future: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    if cx.checkpoint().is_err() {
        return Err("authenticated MCP run cancelled".to_owned());
    }
    if cx.timer_driver().is_none() || timeout.is_zero() || timeout > Duration::from_secs(900) {
        return Err("invalid authenticated MCP runtime or deadline".to_owned());
    }
    let nanos = u64::try_from(timeout.as_nanos())
        .map_err(|_| "invalid authenticated MCP deadline".to_owned())?;
    let deadline = cx.now().saturating_add_nanos(nanos);
    let deadline = cx.budget().deadline.map_or(deadline, |parent| parent.min(deadline));
    let sleep = {
        let _caller = Cx::set_current(Some(cx.clone()));
        Sleep::new(deadline)
    };
    let mut sleep = std::pin::pin!(sleep);
    let (_sender, mut receiver) = oneshot::channel::<()>();
    let mut cancelled = std::pin::pin!(receiver.recv(cx));
    let mut future = std::pin::pin!(future);
    poll_fn(|task| {
        let _caller = Cx::set_current(Some(cx.clone()));
        if cx.checkpoint().is_err() || cancelled.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err("authenticated MCP run cancelled".to_owned()));
        }
        if cx.now() >= deadline || sleep.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err("authenticated MCP run reached its deadline".to_owned()));
        }
        let result = future.as_mut().poll(task);
        if cx.checkpoint().is_err() {
            return Poll::Ready(Err("authenticated MCP run cancelled".to_owned()));
        }
        if cx.now() >= deadline {
            return Poll::Ready(Err("authenticated MCP run reached its deadline".to_owned()));
        }
        result
    }).await
}

/// Both profiles use the same generic fixture sequence, not scenario branches.
pub(crate) enum FixtureClient {
    Ordinary(Box<HttpClient>),
    Managed(Box<ManagedHttpClient>),
}

#[derive(Debug)]
pub(crate) enum ClientError {
    Ordinary(HttpClientError),
    Managed(ManagedHttpClientError),
}

impl From<HttpClientError> for ClientError {
    fn from(error: HttpClientError) -> Self { Self::Ordinary(error) }
}
impl From<ManagedHttpClientError> for ClientError {
    fn from(error: ManagedHttpClientError) -> Self { Self::Managed(error) }
}
impl ClientError {
    pub(crate) fn is_method_not_found(&self) -> bool {
        match self {
            Self::Ordinary(HttpClientError::CoreResult(error)) => error.code == McpErrorCode::MethodNotFound,
            Self::Managed(ManagedHttpClientError::Request { code }) => *code == Some(McpErrorCode::MethodNotFound),
            _ => false,
        }
    }
}

impl FixtureClient {
    pub(crate) async fn ordinary(cx: &Cx, builder: ClientBuilder) -> Result<Self, ClientError> {
        Ok(Self::Ordinary(Box::new(builder.connect_http_client_with_cx(cx).await?)))
    }

    pub(crate) async fn list_tools(&mut self, cx: &Cx, cursor: Option<&str>) -> Result<CoreResult, ClientError> {
        match self {
            Self::Ordinary(client) => client.list_tools(cx, cursor).await.map_err(Into::into),
            Self::Managed(client) => client.list_tools(cx, cursor).await.map_err(Into::into),
        }
    }
    pub(crate) async fn list_resources(&mut self, cx: &Cx, cursor: Option<&str>) -> Result<CoreResult, ClientError> {
        match self {
            Self::Ordinary(client) => client.list_resources(cx, cursor).await.map_err(Into::into),
            Self::Managed(client) => client.list_resources(cx, cursor).await.map_err(Into::into),
        }
    }
    pub(crate) async fn list_prompts(&mut self, cx: &Cx, cursor: Option<&str>) -> Result<CoreResult, ClientError> {
        match self {
            Self::Ordinary(client) => client.list_prompts(cx, cursor).await.map_err(Into::into),
            Self::Managed(client) => client.list_prompts(cx, cursor).await.map_err(Into::into),
        }
    }
    pub(crate) async fn call_tool(&mut self, cx: &Cx, name: &str, arguments: Value) -> Result<CoreResult, ClientError> {
        match self {
            Self::Ordinary(client) => client.call_tool(cx, name, arguments).await.map_err(Into::into),
            Self::Managed(client) => client.call_tool(cx, name, arguments).await.map_err(Into::into),
        }
    }
    pub(crate) async fn call_tool_with_reviewed_headers(
        &mut self, cx: &Cx, arguments: Value, reviewed: &ReviewedToolHeaders,
        review: &(dyn Fn(&ParameterHeaderBinding) -> bool + Send + Sync),
    ) -> Result<CoreResult, ClientError> {
        match self {
            Self::Ordinary(client) => client.call_tool_with_reviewed_headers(cx, arguments, reviewed, review).await.map_err(Into::into),
            Self::Managed(client) => client.call_tool_with_reviewed_headers(cx, arguments, reviewed, review).await.map_err(Into::into),
        }
    }
    pub(crate) async fn read_resource(&mut self, cx: &Cx, uri: &str) -> Result<CoreResult, ClientError> {
        match self {
            Self::Ordinary(client) => client.read_resource(cx, uri).await.map_err(Into::into),
            Self::Managed(client) => client.read_resource(cx, uri).await.map_err(Into::into),
        }
    }
    pub(crate) async fn get_prompt(&mut self, cx: &Cx, name: &str, arguments: HashMap<String, String>) -> Result<CoreResult, ClientError> {
        match self {
            Self::Ordinary(client) => client.get_prompt(cx, name, arguments).await.map_err(Into::into),
            Self::Managed(client) => client.get_prompt(cx, name, arguments).await.map_err(Into::into),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use fastmcp_core::McpError;
    use fastmcp_client::http_auth::managed::OAuthSessionError;

    #[test]
    fn invalid_consumer_is_rejected_before_discovery_or_registration() {
        let cx = Cx::for_testing();
        let endpoint = CanonicalHttpUrl::parse("https://resource.example/mcp").unwrap();
        for discovery in [serde_json::json!({}), serde_json::json!({
            "allow_dynamic_registration":true, "client_name":"Fixture"
        })] {
            let raw = serde_json::json!({
                "preauthorized_redirect":true,
                "resource":endpoint.as_str(),
                "issuer":"https://issuer.example",
                "authorization_endpoint":"https://issuer.example/authorize",
                "client_id":"native-client",
                "discovery":discovery
            }).to_string();
            let mut future = Box::pin(configure(&cx, &endpoint, ClientBuilder::new(), &raw));
            let mut task = std::task::Context::from_waker(std::task::Waker::noop());
            match future.as_mut().poll(&mut task) {
                Poll::Ready(Err(error)) => assert_eq!(error, INVALID),
                _ => panic!("invalid consumer must fail before any await or network effect"),
            }
        }
    }

    #[test]
    fn managed_refresh_is_explicit_and_cannot_run_without_oauth_policy() {
        for present in [false, true] {
            for flag in [None, Some("0"), Some("false")] {
                assert!(!selected(flag, present).unwrap());
            }
        }
        for flag in [Some("1"), Some("true")] {
            assert!(selected(flag, true).unwrap());
            assert!(selected(flag, false).is_err());
        }
        for flag in ["", "yes", "TRUE", "secret-canary"] {
            let error = selected(Some(flag), true).unwrap_err();
            assert!(!error.contains("secret-canary"));
        }
    }

    #[test]
    fn only_protocol_method_not_found_can_skip_an_optional_managed_catalog() {
        let plain = ClientError::from(HttpClientError::CoreResult(McpError::method_not_found("tools/list")));
        let managed = ClientError::from(ManagedHttpClientError::Request { code: Some(McpErrorCode::MethodNotFound) });
        assert!(plain.is_method_not_found() && managed.is_method_not_found());
        for error in [
            ManagedHttpClientError::Request { code: Some(McpErrorCode::InvalidRequest) },
            ManagedHttpClientError::Request { code: None },
            ManagedHttpClientError::Session(OAuthSessionError::AuthorizationRejected { status: 403 }),
            ManagedHttpClientError::CatalogGenerationChanged,
        ] {
            assert!(!ClientError::from(error).is_method_not_found());
        }
    }

    #[test]
    fn managed_diagnostics_do_not_print_nested_peer_errors() {
        let error = ClientError::from(ManagedHttpClientError::Session(OAuthSessionError::LoginRequired));
        assert_eq!(format!("{error:?}"), "Managed(ManagedHttpClientError::Session(..))");
    }

    fn run(future: impl Future<Output = ()>) {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build().unwrap().block_on(future);
    }

    #[test]
    fn run_deadline_ends_a_quiet_future_without_an_expired_access_token() {
        run(async {
            let cx = Cx::current().unwrap();
            let result = bounded_run(&cx, Duration::from_millis(100),
                std::future::pending::<Result<(), String>>()).await;
            assert_eq!(result.unwrap_err(), "authenticated MCP run reached its deadline");
        });
    }

    #[test]
    fn cancelled_run_never_polls_work_or_publishes_a_late_value() {
        run(async {
            let cx = Cx::current().unwrap();
            let polls = AtomicUsize::new(0);
            let result = bounded_run(&cx, Duration::from_secs(5), async {
                polls.fetch_add(1, Ordering::SeqCst);
                cx.set_cancel_requested(true);
                Ok(42)
            }).await;
            assert_eq!(result.unwrap_err(), "authenticated MCP run cancelled");
            assert_eq!(polls.load(Ordering::SeqCst), 1);
            let result = bounded_run(&cx, Duration::from_secs(5), async {
                polls.fetch_add(1, Ordering::SeqCst);
                Ok(43)
            }).await;
            assert!(result.is_err());
            assert_eq!(polls.load(Ordering::SeqCst), 1);
        });
    }
}
