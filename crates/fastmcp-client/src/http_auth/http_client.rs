//! High-level MCP calls backed by one shared, rotating OAuth login.
//!
//! Renewal precedes a logical call. A new credential generation gets a new
//! high-level connection, so discovery, catalog caches and negotiated extensions
//! cannot cross a token/scope change. There is no retry of a failed MCP call,
//! implicit login, detached worker, or runtime owned by this module.

use std::collections::HashMap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::time::Sleep;
use asupersync::types::Time;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::CoreResult;
use fastmcp_protocol::http_headers::ParameterHeaderBinding;
use serde_json::Value;

use super::managed::{ManagedOAuthSession, OAuthCredentialSnapshot, OAuthSessionError};
use super::{BoundBearerCredential, CanonicalHttpUrl};
use crate::http_executor::parameter_headers::ReviewedToolHeaders;
use crate::{ClientBuilder, HttpClient, HttpClientError, ProtocolPolicy};

/// A terminal failure. Formatting never includes protected peer diagnostics.
/// Callers may explicitly inspect the underlying error under their own policy.
pub enum ManagedHttpClientError {
    InvalidPolicy,
    RuntimeTimerUnavailable,
    Closed,
    Cancelled,
    TimedOut,
    CredentialUnavailable,
    OAuth(OAuthSessionError),
    Http(HttpClientError),
}

impl fmt::Display for ManagedHttpClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid managed HTTP client policy",
            Self::RuntimeTimerUnavailable => "managed HTTP requires the caller's timer",
            Self::Closed => "managed HTTP client or OAuth owner is closed",
            Self::Cancelled => "managed HTTP operation cancelled",
            Self::TimedOut => "managed HTTP operation deadline exceeded",
            Self::CredentialUnavailable => "managed HTTP credential expired or was revoked",
            Self::OAuth(_) => "managed HTTP credential acquisition failed",
            Self::Http(_) => "authenticated MCP operation failed; not replayed",
        })
    }
}

impl fmt::Debug for ManagedHttpClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for ManagedHttpClientError {}

/// One complete high-level operation. Results are owned, admitted core values;
/// no response stream or unguarded client can escape the credential lifetime.
/// Catalog cursors remain server-owned opaque values, not refreshed credentials.
pub enum ManagedHttpOperation<'a> {
    ListTools {
        cursor: Option<String>,
    },
    ListResources {
        cursor: Option<String>,
    },
    ListResourceTemplates {
        cursor: Option<String>,
    },
    ListPrompts {
        cursor: Option<String>,
    },
    CallTool {
        name: &'a str,
        arguments: Value,
    },
    ReadResource {
        uri: &'a str,
    },
    GetPrompt {
        name: &'a str,
        arguments: HashMap<String, String>,
    },
}

impl ManagedHttpOperation<'_> {
    async fn dispatch(
        self,
        client: &mut HttpClient,
        cx: &Cx,
    ) -> Result<CoreResult, HttpClientError> {
        match self {
            Self::ListTools { cursor } => client.list_tools(cx, cursor.as_deref()).await,
            Self::ListResources { cursor } => client.list_resources(cx, cursor.as_deref()).await,
            Self::ListResourceTemplates { cursor } => {
                client.list_resource_templates(cx, cursor.as_deref()).await
            }
            Self::ListPrompts { cursor } => client.list_prompts(cx, cursor.as_deref()).await,
            Self::CallTool { name, arguments } => client.call_tool(cx, name, arguments).await,
            Self::ReadResource { uri } => client.read_resource(cx, uri).await,
            Self::GetPrompt { name, arguments } => client.get_prompt(cx, name, arguments).await,
        }
    }
}

struct ReadyClient {
    generation: u64,
    client: HttpClient,
}

// Never stored in the owner: abandoning a future drops its in-flight client.
struct RequestLease {
    ready: ReadyClient,
    snapshot: OAuthCredentialSnapshot,
    deadline: Time,
}

/// A caller-owned high-level client with on-demand OAuth renewal.
///
/// The supplied builder is frozen and cloned only for initial discovery or a
/// new credential generation. It retains client metadata, reverse handlers,
/// extensions, timeout policy and explicitly configured MCP-resource TLS roots.
/// Its bearer setting is replaced by the managed snapshot before any network
/// effect. Authorization/token-endpoint roots are never imported as resource
/// trust. ModernOnly and the session's exact HTTPS resource are mandatory.
///
/// Each logical operation obtains a fresh snapshot from the session's existing
/// single-flight renewal path. Connection and result caches are reused only in
/// that generation. Failed, cancelled, expired or abandoned operations discard
/// their owned connection; the next explicit operation may rediscover, but the
/// failed operation itself is never replayed or resumed with another token.
/// Dropping a request cannot undo effects or bytes already sent to the server.
///
/// The original snapshot bounds the entire request, reverse callbacks, schema
/// repair and result delivery. Refresh in a sibling client does not prolong it.
/// This is local expiry/revocation, not remote introspection or an auth lease.
/// Streaming subscriptions and Tasks are available through the separate managed
/// APIs, not by extracting a bare HttpClient from this owner.
pub struct ManagedHttpClient {
    session: ManagedOAuthSession,
    builder: ClientBuilder,
    timeout: Duration,
    ready: Option<ReadyClient>,
    closed: bool,
}

impl fmt::Debug for ManagedHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedHttpClient")
            .field("closed", &self.closed)
            .field("connected_generation", &self.connected_generation())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

fn admit_consumer(
    builder: &ClientBuilder,
    resource: &CanonicalHttpUrl,
) -> Result<(), ManagedHttpClientError> {
    let plan = builder.selected_protocol_plan();
    if resource.scheme() != "https"
        || plan.policy() != ProtocolPolicy::ModernOnly
        || plan.modern_post_target() != Some(resource.as_str())
    {
        return Err(ManagedHttpClientError::InvalidPolicy);
    }
    Ok(())
}

impl ManagedHttpClient {
    /// Binds an existing login without network I/O or a second authorization.
    /// Connection is lazy: the first operation performs authenticated discovery.
    pub fn new(
        session: ManagedOAuthSession,
        builder: ClientBuilder,
    ) -> Result<Self, ManagedHttpClientError> {
        admit_consumer(&builder, session.resource())?;
        Ok(Self {
            session,
            builder,
            timeout: Duration::from_secs(120),
            ready: None,
            closed: false,
        })
    }

    /// Sets one bound for acquisition, discovery, callbacks and result delivery.
    /// The caller's earlier deadline and original token expiry still win.
    pub fn with_request_timeout(
        mut self,
        timeout: Duration,
    ) -> Result<Self, ManagedHttpClientError> {
        if timeout.is_zero() || timeout > Duration::from_mins(15) {
            return Err(ManagedHttpClientError::InvalidPolicy);
        }
        self.timeout = timeout;
        Ok(self)
    }

    pub fn resource(&self) -> &CanonicalHttpUrl {
        self.session.resource()
    }

    /// The retained successful connection's generation, not a global cache key.
    pub fn connected_generation(&self) -> Option<u64> {
        self.ready.as_ref().map(|ready| ready.generation)
    }

    /// Closes this client only. Other clients sharing the login remain usable.
    /// Call ManagedOAuthSession::close/logout to revoke the shared login itself.
    pub fn close(&mut self) {
        self.closed = true;
        self.ready = None;
    }

    pub async fn execute(
        &mut self,
        cx: &Cx,
        operation: ManagedHttpOperation<'_>,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        self.execute_with_cancellation(cx, &McpRequestCancellation::new(), operation)
            .await
    }

    pub async fn execute_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        operation: ManagedHttpOperation<'_>,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        let mut lease = self.acquire(cx, cancellation).await?;
        let result = guarded(
            cx,
            cancellation,
            lease.deadline,
            Some(lease.snapshot.credential()),
            async {
                operation
                    .dispatch(&mut lease.ready.client, cx)
                    .await
                    .map_err(ManagedHttpClientError::Http)
            },
        )
        .await?;
        self.ready = Some(lease.ready);
        Ok(result)
    }

    /// Runs the existing reviewed-header repair and MRTR exchange under the
    /// original token lifetime. No access-token refresh occurs between rounds.
    /// As in HttpClient, the review callback is borrowed for this operation.
    pub async fn call_tool_with_reviewed_headers(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        arguments: Value,
        reviewed: &ReviewedToolHeaders,
        review: &dyn Fn(&ParameterHeaderBinding) -> bool,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        if reviewed.resource() != self.resource() {
            return Err(ManagedHttpClientError::InvalidPolicy);
        }
        let mut lease = self.acquire(cx, cancellation).await?;
        let result = guarded(
            cx,
            cancellation,
            lease.deadline,
            Some(lease.snapshot.credential()),
            async {
                lease
                    .ready
                    .client
                    .call_tool_with_reviewed_headers_and_cancellation(
                        cx,
                        cancellation,
                        arguments,
                        reviewed,
                        review,
                    )
                    .await
                    .map_err(ManagedHttpClientError::Http)
            },
        )
        .await?;
        self.ready = Some(lease.ready);
        Ok(result)
    }

    async fn acquire(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
    ) -> Result<RequestLease, ManagedHttpClientError> {
        if self.closed {
            return Err(ManagedHttpClientError::Closed);
        }
        // Transfer custody BEFORE any await. Dropping acquisition, discovery or
        // dispatch can never leave a partially driven connection in this owner.
        let retained = self.ready.take();
        let deadline = cx.now().saturating_add_nanos(
            u64::try_from(self.timeout.as_nanos())
                .map_err(|_| ManagedHttpClientError::InvalidPolicy)?,
        );
        let snapshot = guarded(cx, cancellation, deadline, None, async {
            self.session
                .credential_with_cancellation(cx, cancellation)
                .await
                .map_err(ManagedHttpClientError::OAuth)
        })
        .await?;
        let generation = snapshot.generation();
        let ready = guarded(
            cx,
            cancellation,
            deadline,
            Some(snapshot.credential()),
            async {
                let client = match retained {
                    Some(ready) if ready.generation == generation => ready.client,
                    previous => {
                        drop(previous);
                        self.builder
                            .clone()
                            .http_bearer_credential(snapshot.credential().clone())
                            .connect_http_client_with_cx(cx)
                            .await
                            .map_err(ManagedHttpClientError::Http)?
                    }
                };
                Ok(ReadyClient { generation, client })
            },
        )
        .await?;
        Ok(RequestLease {
            ready,
            snapshot,
            deadline,
        })
    }

    pub async fn list_tools(
        &mut self,
        cx: &Cx,
        cursor: Option<String>,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        self.execute(cx, ManagedHttpOperation::ListTools { cursor })
            .await
    }

    pub async fn call_tool(
        &mut self,
        cx: &Cx,
        name: &str,
        arguments: Value,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        self.execute(cx, ManagedHttpOperation::CallTool { name, arguments })
            .await
    }

    pub async fn read_resource(
        &mut self,
        cx: &Cx,
        uri: &str,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        self.execute(cx, ManagedHttpOperation::ReadResource { uri })
            .await
    }
}

fn checkpoint(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    deadline: Time,
    credential: Option<&BoundBearerCredential>,
) -> Result<(), ManagedHttpClientError> {
    if cx.checkpoint().is_err() || cancellation.is_cancel_requested() {
        return Err(ManagedHttpClientError::Cancelled);
    }
    if let Some(credential) = credential {
        if credential
            .owner_cancellation
            .as_ref()
            .is_some_and(McpRequestCancellation::is_cancel_requested)
        {
            return Err(ManagedHttpClientError::Closed);
        }
        if credential.is_revoked()
            || credential
                .expires_at()
                .is_none_or(|expiry| Instant::now() >= expiry)
        {
            return Err(ManagedHttpClientError::CredentialUnavailable);
        }
    }
    if cx.now() >= deadline {
        return Err(ManagedHttpClientError::TimedOut);
    }
    Ok(())
}

/// Returns a BOXED future deliberately.
///
/// This helper holds the caller's `operation` future inline alongside a pinned
/// `Sleep` and four pinned cancellation futures, so its state is 42-46 KB. Every
/// public method on the managed client awaits it, which made one inner future
/// surface as fifteen `clippy::large_futures` errors across three files and left
/// the crate's `-D warnings` gate closed for every dependent. Boxing here, at
/// the single inner step, collapses all of those call sites at once; boxing at
/// each await point instead would be fifteen edits that only move the bytes.
///
/// Do not turn this back into a plain `async fn` without re-measuring the
/// caller future sizes.
fn guarded<'a, T: 'a>(
    cx: &'a Cx,
    cancellation: &'a McpRequestCancellation,
    deadline: Time,
    credential: Option<&'a BoundBearerCredential>,
    operation: impl Future<Output = Result<T, ManagedHttpClientError>> + 'a,
) -> std::pin::Pin<Box<dyn Future<Output = Result<T, ManagedHttpClientError>> + 'a>> {
    Box::pin(async move {
        let deadline = cx
            .budget()
            .deadline
            .map_or(deadline, |parent| parent.min(deadline));
        checkpoint(cx, cancellation, deadline, credential)?;
        if cx.timer_driver().is_none() {
            return Err(ManagedHttpClientError::RuntimeTimerUnavailable);
        }
        let expiry_deadline =
            credential
                .and_then(BoundBearerCredential::expires_at)
                .map(|expiry| {
                    let remaining = expiry.saturating_duration_since(Instant::now());
                    cx.now().saturating_add_nanos(
                        u64::try_from(remaining.as_nanos()).unwrap_or(u64::MAX),
                    )
                });
        let wake_deadline = expiry_deadline.map_or(deadline, |expiry| deadline.min(expiry));
        let sleep = {
            let _caller = Cx::set_current(Some(cx.clone()));
            Sleep::new(wake_deadline)
        };
        let mut sleep = std::pin::pin!(sleep);
        let idle = McpRequestCancellation::new();
        let revoked = credential.map_or(&idle, |credential| &credential.revoked);
        let owner = credential
            .and_then(|credential| credential.owner_cancellation.as_ref())
            .unwrap_or(&idle);
        let mut revoked = std::pin::pin!(revoked.cancelled());
        let mut owner = std::pin::pin!(owner.cancelled());
        let mut cancelled = std::pin::pin!(cancellation.cancelled());
        let (_sender, mut receiver) = oneshot::channel::<()>();
        let mut caller_cancelled = std::pin::pin!(receiver.recv(cx));
        let mut operation = std::pin::pin!(operation);
        poll_fn(|task| {
            if let Err(error) = checkpoint(cx, cancellation, deadline, credential) {
                return Poll::Ready(Err(error));
            }
            let _caller = Cx::set_current(Some(cx.clone()));
            if cancelled.as_mut().poll(task).is_ready()
                || caller_cancelled.as_mut().poll(task).is_ready()
            {
                return Poll::Ready(Err(ManagedHttpClientError::Cancelled));
            }
            if owner.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(ManagedHttpClientError::Closed));
            }
            if revoked.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(ManagedHttpClientError::CredentialUnavailable));
            }
            if sleep.as_mut().poll(task).is_ready() {
                return Poll::Ready(Err(
                    if expiry_deadline.is_some_and(|expiry| expiry <= deadline) {
                        ManagedHttpClientError::CredentialUnavailable
                    } else {
                        ManagedHttpClientError::TimedOut
                    },
                ));
            }
            let result = operation.as_mut().poll(task);
            if let Err(error) = checkpoint(cx, cancellation, deadline, credential) {
                return Poll::Ready(Err(error));
            }
            result
        })
        .await
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClientProtocolPlan;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};

    fn url(value: &str) -> CanonicalHttpUrl {
        CanonicalHttpUrl::parse(value).unwrap()
    }
    fn builder(target: &str, policy: ProtocolPolicy) -> ClientBuilder {
        ClientBuilder::new().protocol_plan(
            ClientProtocolPlan::http(
                policy,
                Some(url(target)),
                None,
                None,
                "managed-principal".to_owned(),
                "trust".to_owned(),
                "native-http".to_owned(),
                0,
                0,
                0,
            )
            .unwrap(),
        )
    }
    fn run(future: impl Future<Output = ()>) {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .build()
            .unwrap()
            .block_on(future);
    }
    struct Dropped(Arc<AtomicUsize>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
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
    fn credential() -> BoundBearerCredential {
        BoundBearerCredential::bind_with_expiry(
            url("https://resource.example/mcp"),
            "private-token",
            Instant::now() + Duration::from_secs(60),
        )
        .unwrap()
    }

    #[test]
    fn consumer_requires_the_exact_modern_https_resource() {
        let resource = url("https://resource.example/mcp");
        assert!(
            admit_consumer(
                &builder(resource.as_str(), ProtocolPolicy::ModernOnly),
                &resource
            )
            .is_ok()
        );
        for target in [
            "https://resource.example/other",
            "https://other.example/mcp",
            "http://resource.example/mcp",
            "https://resource.example/mcp?q=1",
        ] {
            assert!(
                admit_consumer(&builder(target, ProtocolPolicy::ModernOnly), &resource).is_err()
            );
        }
        assert!(admit_consumer(&ClientBuilder::new(), &resource).is_err());
    }

    #[test]
    fn pre_cancelled_work_has_no_operation_effect() {
        run(async {
            let cx = Cx::current().unwrap();
            let cancellation = McpRequestCancellation::new();
            cancellation.cancel();
            let polls = AtomicUsize::new(0);
            let result = guarded(
                &cx,
                &cancellation,
                cx.now().saturating_add_nanos(1_000_000_000),
                None,
                async {
                    polls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            )
            .await;
            assert!(matches!(result, Err(ManagedHttpClientError::Cancelled)));
            assert_eq!(polls.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn revocation_during_a_ready_poll_discards_the_result() {
        run(async {
            let cx = Cx::current().unwrap();
            let credential = credential();
            let drops = Arc::new(AtomicUsize::new(0));
            let result = guarded(
                &cx,
                &McpRequestCancellation::new(),
                cx.now().saturating_add_nanos(1_000_000_000),
                Some(&credential),
                async {
                    credential.revoke();
                    Ok(Dropped(drops.clone()))
                },
            )
            .await;
            assert!(matches!(
                result,
                Err(ManagedHttpClientError::CredentialUnavailable)
            ));
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn quiet_requests_wake_on_token_revocation_owner_close_and_request_cancel() {
        for kind in 0..3 {
            run(async {
                let cx = Cx::current().unwrap();
                let owner = McpRequestCancellation::new();
                let credential = credential().for_owner(&owner).unwrap();
                let cancellation = McpRequestCancellation::new();
                let wakes = Arc::new(Wakes::default());
                let waker = Waker::from(wakes.clone());
                let mut task = Context::from_waker(&waker);
                let mut future = Box::pin(guarded(
                    &cx,
                    &cancellation,
                    cx.now().saturating_add_nanos(60_000_000_000),
                    Some(&credential),
                    std::future::pending::<Result<(), ManagedHttpClientError>>(),
                ));
                assert!(future.as_mut().poll(&mut task).is_pending());
                let before = wakes.0.load(Ordering::SeqCst);
                // `revoke` returns (), both `cancel`s return bool, so the arms
                // need unifying; neither cancel is #[must_use] and the wake is
                // asserted below rather than taken from the return value.
                match kind {
                    0 => credential.revoke(),
                    1 => {
                        owner.cancel();
                    }
                    _ => {
                        cancellation.cancel();
                    }
                }
                assert!(wakes.0.load(Ordering::SeqCst) > before);
                let result = future.await;
                match kind {
                    0 => assert!(matches!(
                        result,
                        Err(ManagedHttpClientError::CredentialUnavailable)
                    )),
                    1 => assert!(matches!(result, Err(ManagedHttpClientError::Closed))),
                    _ => assert!(matches!(result, Err(ManagedHttpClientError::Cancelled))),
                }
                assert!(cx.checkpoint().is_ok());
            });
        }
    }

    #[test]
    fn original_expiry_and_operation_deadline_end_quiet_work() {
        for expires_first in [false, true] {
            run(async {
                let cx = Cx::current().unwrap();
                let credential = BoundBearerCredential::bind_with_expiry(
                    url("https://resource.example/mcp"),
                    "private-token",
                    Instant::now()
                        + if expires_first {
                            Duration::from_millis(20)
                        } else {
                            Duration::from_secs(60)
                        },
                )
                .unwrap();
                let deadline = cx.now().saturating_add_nanos(if expires_first {
                    60_000_000_000
                } else {
                    20_000_000
                });
                let result = guarded(
                    &cx,
                    &McpRequestCancellation::new(),
                    deadline,
                    Some(&credential),
                    std::future::pending::<Result<(), ManagedHttpClientError>>(),
                )
                .await;
                if expires_first {
                    assert!(matches!(
                        result,
                        Err(ManagedHttpClientError::CredentialUnavailable)
                    ));
                } else {
                    assert!(matches!(result, Err(ManagedHttpClientError::TimedOut)));
                }
                assert!(!credential.is_revoked());
            });
        }
    }

    #[test]
    fn errors_do_not_format_protected_peer_data() {
        let error = ManagedHttpClientError::Http(HttpClientError::CoreResult(
            fastmcp_core::McpError::invalid_request("private-token"),
        ));
        assert!(!format!("{error:?} {error}").contains("private-token"));
        assert!(matches!(error, ManagedHttpClientError::Http(_)));
    }
}
