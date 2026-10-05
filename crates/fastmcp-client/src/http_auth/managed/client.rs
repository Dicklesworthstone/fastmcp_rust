//! High-level MCP calls under a shared, rotating OAuth grant.
//!
//! Each logical operation obtains a current managed credential before using the
//! ordinary `HttpClient`. A new credential generation creates a new discovery
//! connection and cache; old catalog entries cannot survive a scope change.
//! Renewal happens before the operation, never in response to an HTTP error.
//!
//! Discovery, schema repair, reverse handlers, and the completed response all
//! share the operation's deadline and the original token's lifetime. There is
//! deliberately no accessor for the raw client or an escaping response stream.
//! Dropping a polled operation drops its connection rather than returning
//! possibly half-consumed state to the next operation.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use asupersync::Cx;
use fastmcp_core::{CanonicalHttpUrl, McpErrorCode, McpRequestCancellation};
use fastmcp_protocol::CoreResult;
use fastmcp_protocol::http_headers::ParameterHeaderBinding;
use serde_json::Value;

use super::{ManagedOAuthSession, OAuthSessionError, deadline_after};
use crate::http_executor::parameter_headers::ReviewedToolHeaders;
use crate::{ClientBuilder, HttpClient, HttpClientError, ProtocolPolicy};

/// Sanitized high-level failures. The original session error remains available
/// for typed handling, but formatting never includes transport or peer data.
pub enum ManagedHttpClientError {
    InvalidPolicy,
    Closed,
    Session(OAuthSessionError),
    Connection,
    Request { code: Option<McpErrorCode> },
    /// A cursor cannot cross a reconnect or a credential-generation change.
    CatalogGenerationChanged,
}

impl fmt::Debug for ManagedHttpClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => f.write_str("ManagedHttpClientError::InvalidPolicy"),
            Self::Closed => f.write_str("ManagedHttpClientError::Closed"),
            Self::Session(_) => f.write_str("ManagedHttpClientError::Session(..)"),
            Self::Connection => f.write_str("ManagedHttpClientError::Connection"),
            Self::Request { code } => f.debug_struct("ManagedHttpClientError::Request")
                .field("code", code).finish(),
            Self::CatalogGenerationChanged => {
                f.write_str("ManagedHttpClientError::CatalogGenerationChanged")
            }
        }
    }
}

impl fmt::Display for ManagedHttpClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicy => "invalid managed HTTP client policy",
            Self::Closed => "managed HTTP client is closed",
            Self::Session(_) => "managed OAuth operation failed",
            Self::Connection => "authenticated MCP discovery failed",
            Self::Request { .. } => "authenticated MCP request failed; not replayed",
            Self::CatalogGenerationChanged => {
                "catalog credential generation changed; restart listing without a cursor"
            }
        })
    }
}

impl std::error::Error for ManagedHttpClientError {}

impl From<OAuthSessionError> for ManagedHttpClientError {
    fn from(error: OAuthSessionError) -> Self {
        Self::Session(error)
    }
}

fn request_error(error: HttpClientError) -> ManagedHttpClientError {
    let code = match error {
        HttpClientError::CoreResult(error) => Some(error.code),
        _ => None,
    };
    // Messages/data can reflect tokens, resource names, or private inputs.
    // Keep only the typed protocol error code, not the original diagnostics.
    ManagedHttpClientError::Request { code }
}

struct Connection {
    client: HttpClient,
    generation: u64,
}

/// A reusable high-level HTTP client whose authentication is caller-owned.
///
/// `new` performs no I/O. The first operation performs authenticated discovery.
/// Further operations reuse its connection only while the credential generation
/// is unchanged. Acquisition uses the session's existing bounded single-flight
/// renewal, so independent clients sharing that session share one refresh.
///
/// Resource TLS trust belongs to the supplied `ClientBuilder`; configure
/// `http_resource_root_certificate` there for private-resource deployments.
/// Token-issuer roots do not grant resource trust. The builder's bearer, if any,
/// is replaced by this explicitly selected session before every connection.
/// `Auto` and legacy plans are rejected before acquiring a grant.
///
/// The wrapper accepts completed core calls only. Subscription streams, Tasks
/// response owners, and arbitrary callbacks into a raw `HttpClient` are not
/// exposed, because those could escape the credential lifetime guard.
pub struct ManagedHttpClient {
    session: ManagedOAuthSession,
    builder: ClientBuilder,
    operation_timeout: Duration,
    connection: Option<Connection>,
    closed: bool,
}

impl fmt::Debug for ManagedHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedHttpClient")
            .field("closed", &self.closed)
            .field("cached_generation", &self.cached_credential_generation())
            .field("operation_timeout", &self.operation_timeout)
            .finish_non_exhaustive()
    }
}

fn admit_builder(
    builder: &ClientBuilder,
    resource: &CanonicalHttpUrl,
    timeout: Duration,
) -> Result<(), ManagedHttpClientError> {
    let plan = builder.selected_protocol_plan();
    if timeout.is_zero()
        || timeout > Duration::from_secs(15 * 60)
        || resource.scheme() != "https"
        || plan.policy() != ProtocolPolicy::ModernOnly
        || plan.modern_post_target() != Some(resource.as_str())
    {
        return Err(ManagedHttpClientError::InvalidPolicy);
    }
    // The public side-effect-free admission path also checks the compiled
    // protocol feature surface. No discovery, refresh, or callback runs here.
    builder.http_negotiation().map_err(|_| ManagedHttpClientError::InvalidPolicy)?;
    Ok(())
}

impl ManagedHttpClient {
    /// Selects one managed login and exact ModernOnly resource before any I/O.
    /// The finite timeout covers acquisition, discovery, and the whole logical
    /// operation, including MRTR and reviewed parameter-header repair.
    pub fn new(
        session: ManagedOAuthSession,
        builder: ClientBuilder,
        operation_timeout: Duration,
    ) -> Result<Self, ManagedHttpClientError> {
        admit_builder(&builder, session.resource(), operation_timeout)?;
        Ok(Self {
            session,
            builder,
            operation_timeout,
            connection: None,
            closed: false,
        })
    }

    pub fn resource(&self) -> &CanonicalHttpUrl {
        self.session.resource()
    }

    /// Introspection only: generation is local to the selected OAuth session.
    pub fn cached_credential_generation(&self) -> Option<u64> {
        self.connection.as_ref().map(|connection| connection.generation)
    }

    /// Permanently closes this client, not sibling clients sharing its login.
    /// To revoke the shared login as well, close its `ManagedOAuthSession`.
    pub fn close(&mut self) {
        self.closed = true;
        self.connection = None;
    }

    pub async fn list_tools(
        &mut self, cx: &Cx, cursor: Option<&str>,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        self.list_tools_with_cancellation(cx, &McpRequestCancellation::new(), cursor).await
    }

    pub async fn list_tools_with_cancellation(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation, cursor: Option<&str>,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        self.perform(cx, cancellation, Call::Tools(cursor)).await
    }

    pub async fn list_resources(
        &mut self, cx: &Cx, cursor: Option<&str>,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        self.list_resources_with_cancellation(cx, &McpRequestCancellation::new(), cursor).await
    }

    pub async fn list_resources_with_cancellation(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation, cursor: Option<&str>,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        self.perform(cx, cancellation, Call::Resources(cursor)).await
    }

    pub async fn list_resource_templates(
        &mut self, cx: &Cx, cursor: Option<&str>,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        self.list_resource_templates_with_cancellation(
            cx, &McpRequestCancellation::new(), cursor,
        ).await
    }

    pub async fn list_resource_templates_with_cancellation(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation, cursor: Option<&str>,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        self.perform(cx, cancellation, Call::Templates(cursor)).await
    }

    pub async fn list_prompts(
        &mut self, cx: &Cx, cursor: Option<&str>,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        self.list_prompts_with_cancellation(cx, &McpRequestCancellation::new(), cursor).await
    }

    pub async fn list_prompts_with_cancellation(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation, cursor: Option<&str>,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        self.perform(cx, cancellation, Call::Prompts(cursor)).await
    }

    pub async fn call_tool(
        &mut self, cx: &Cx, name: &str, arguments: Value,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        self.call_tool_with_cancellation(
            cx, &McpRequestCancellation::new(), name, arguments,
        ).await
    }

    pub async fn call_tool_with_cancellation(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation,
        name: &str, arguments: Value,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        self.perform(cx, cancellation, Call::Tool { name, arguments }).await
    }

    pub async fn call_tool_with_reviewed_headers(
        &mut self, cx: &Cx, arguments: Value, reviewed: &ReviewedToolHeaders,
        review: &(dyn Fn(&ParameterHeaderBinding) -> bool + Send + Sync),
    ) -> Result<CoreResult, ManagedHttpClientError> {
        self.call_tool_with_reviewed_headers_and_cancellation(
            cx, &McpRequestCancellation::new(), arguments, reviewed, review,
        ).await
    }

    pub async fn call_tool_with_reviewed_headers_and_cancellation(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation,
        arguments: Value, reviewed: &ReviewedToolHeaders,
        review: &(dyn Fn(&ParameterHeaderBinding) -> bool + Send + Sync),
    ) -> Result<CoreResult, ManagedHttpClientError> {
        // A mismatching disclosure plan is not a reason to spend a refresh
        // token or open a connection before the ordinary client rejects it.
        if reviewed.resource() != self.session.resource() {
            return Err(ManagedHttpClientError::InvalidPolicy);
        }
        self.perform(cx, cancellation, Call::Reviewed { arguments, reviewed, review }).await
    }

    pub async fn read_resource(
        &mut self, cx: &Cx, uri: &str,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        self.read_resource_with_cancellation(cx, &McpRequestCancellation::new(), uri).await
    }

    pub async fn read_resource_with_cancellation(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation, uri: &str,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        self.perform(cx, cancellation, Call::Read(uri)).await
    }

    pub async fn get_prompt(
        &mut self, cx: &Cx, name: &str, arguments: HashMap<String, String>,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        self.get_prompt_with_cancellation(
            cx, &McpRequestCancellation::new(), name, arguments,
        ).await
    }

    pub async fn get_prompt_with_cancellation(
        &mut self, cx: &Cx, cancellation: &McpRequestCancellation,
        name: &str, arguments: HashMap<String, String>,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        self.perform(cx, cancellation, Call::Prompt { name, arguments }).await
    }

    async fn perform(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        call: Call<'_>,
    ) -> Result<CoreResult, ManagedHttpClientError> {
        if self.closed {
            return Err(ManagedHttpClientError::Closed);
        }
        self.session.check(cx, cancellation)?;
        let deadline = deadline_after(cx, self.operation_timeout)?;
        let continuation = call.has_cursor();
        if continuation && self.connection.is_none() {
            return Err(ManagedHttpClientError::CatalogGenerationChanged);
        }

        // Taking custody before the first await makes abandonment terminal for
        // this connection. A subsequent explicit operation must discover anew.
        let previous = self.connection.take();
        let session = self.session.clone();
        let builder = self.builder.clone();
        let guarded = session.await_active(cx, cancellation, deadline, None, Box::pin(async {
            let snapshot = session.credential_with_cancellation(cx, cancellation).await?;
            let generation = snapshot.generation();
            if continuation
                && previous.as_ref().is_none_or(|old| old.generation != generation)
            {
                return Ok(Err(ManagedHttpClientError::CatalogGenerationChanged));
            }
            // Scope/credential changes invalidate the entire ordinary client,
            // including its discovery capabilities and response/catalog caches.
            let reusable = previous.filter(|old| old.generation == generation);
            session.await_credential(
                cx, cancellation, deadline, snapshot.expires_at(),
                &snapshot.credential.revoked,
                Box::pin(async {
                    let mut client = match reusable {
                        Some(connection) => connection.client,
                        None => match builder
                            .http_bearer_credential(snapshot.credential().clone())
                            .connect_http_client_with_cx(cx)
                            .await
                        {
                            Ok(client) => client,
                            Err(_) => return Ok(Err(ManagedHttpClientError::Connection)),
                        },
                    };
                    let result = call.dispatch(cx, cancellation, &mut client).await;
                    Ok(result
                        .map(|value| (value, Connection { client, generation }))
                        .map_err(request_error))
                }),
            ).await
        })).await?;
        let (value, connection) = guarded?;
        // Both managed guards have made their final cancellation/expiry checks.
        // Failed or abandoned requests never restore their connection or cache.
        self.connection = Some(connection);
        Ok(value)
    }
}

enum Call<'a> {
    Tools(Option<&'a str>),
    Resources(Option<&'a str>),
    Templates(Option<&'a str>),
    Prompts(Option<&'a str>),
    Tool { name: &'a str, arguments: Value },
    Reviewed {
        arguments: Value,
        reviewed: &'a ReviewedToolHeaders,
        review: &'a (dyn Fn(&ParameterHeaderBinding) -> bool + Send + Sync),
    },
    Read(&'a str),
    Prompt { name: &'a str, arguments: HashMap<String, String> },
}

impl Call<'_> {
    fn has_cursor(&self) -> bool {
        matches!(self, Self::Tools(Some(_)) | Self::Resources(Some(_))
            | Self::Templates(Some(_)) | Self::Prompts(Some(_)))
    }

    async fn dispatch(
        self, cx: &Cx, cancellation: &McpRequestCancellation, client: &mut HttpClient,
    ) -> Result<CoreResult, HttpClientError> {
        match self {
            Self::Tools(cursor) => client.list_tools(cx, cursor).await,
            Self::Resources(cursor) => client.list_resources(cx, cursor).await,
            Self::Templates(cursor) => client.list_resource_templates(cx, cursor).await,
            Self::Prompts(cursor) => client.list_prompts(cx, cursor).await,
            Self::Tool { name, arguments } => {
                client.call_tool_with_cancellation(cx, cancellation, name, arguments).await
            }
            Self::Reviewed { arguments, reviewed, review } => client
                .call_tool_with_reviewed_headers_and_cancellation(
                    cx, cancellation, arguments, reviewed, review,
                ).await,
            Self::Read(uri) => client.read_resource(cx, uri).await,
            Self::Prompt { name, arguments } => client.get_prompt(cx, name, arguments).await,
        }
    }
}

#[cfg(test)]
mod tests;
