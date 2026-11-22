//! Explicitly installed, independently authorized HTTP metrics diagnostics.

use std::sync::Arc;

use fastmcp_core::{
    HmacSha256Key, HmacSha256Tag, McpError, McpResult, OPERATOR_PROMETHEUS_CONTENT_TYPE,
    OperatorSnapshot, draw_hmac_sha256_key,
};
use fastmcp_transport::http::{HttpResponse, HttpStatus};

use crate::HttpOperatorHandle;

const MAX_METRICS_TOKEN_BYTES: usize = 4096;
const MAX_METRICS_HEADERS: usize = 64;

/// An opt-in Prometheus endpoint with access control independent of MCP auth.
///
/// Install with [`crate::HttpServerConfig::metrics`]. The route is disabled
/// until configured. Choose [`Self::public`] only when public diagnostics are
/// intended or a trusted ingress separately protects the route. [`Self::bearer`]
/// accepts a dedicated scrape credential, never an MCP principal or token
/// verifier. Use HTTPS or a trusted TLS terminator when sending that credential.
///
/// This exports the listener's live connection snapshot, including saturation
/// and drain state. It does not claim health for auth, Tasks, or upstreams.
#[derive(Clone)]
pub struct HttpMetricsConfig {
    path: String,
    access: MetricsAccess,
}

#[derive(Clone)]
enum MetricsAccess {
    Public,
    Bearer(Arc<MetricsBearerVerifier>),
}

struct MetricsBearerVerifier {
    // One independently drawn process-local key has exactly this purpose.
    // Neither the configured credential nor a plaintext-equivalent hash is
    // retained. Verification uses the core's constant-time full-tag verifier.
    key: HmacSha256Key,
    tag: HmacSha256Tag,
}

impl std::fmt::Debug for HttpMetricsConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpMetricsConfig")
            .field("path", &self.path)
            .field(
                "access",
                &match self.access {
                    MetricsAccess::Public => "public",
                    MetricsAccess::Bearer(_) => "bearer [redacted]",
                },
            )
            .finish()
    }
}

impl HttpMetricsConfig {
    /// Explicitly allows unauthenticated scrapes on this diagnostic path.
    ///
    /// Route syntax and collisions are checked before binding the listener.
    #[must_use]
    pub fn public(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            access: MetricsAccess::Public,
        }
    }

    /// Requires a dedicated bearer credential on this diagnostic path.
    ///
    /// The credential must be a nonempty HTTP bearer token of at most 4096
    /// bytes. Only a purpose-specific keyed verifier is retained; neither
    /// configuration diagnostics nor HTTP failures reveal credential bytes.
    pub fn bearer(path: impl Into<String>, token: &str) -> McpResult<Self> {
        if !valid_bearer_token(token) {
            return Err(McpError::invalid_request(
                "invalid metrics bearer credential",
            ));
        }
        let key = draw_hmac_sha256_key()
            .map_err(|_| McpError::internal_error("metrics credential verifier unavailable"))?;
        let tag = key
            .authenticate_bounded(token.as_bytes(), MAX_METRICS_TOKEN_BYTES)
            .map_err(|_| McpError::invalid_request("invalid metrics bearer credential"))?;
        Ok(Self {
            path: path.into(),
            access: MetricsAccess::Bearer(Arc::new(MetricsBearerVerifier { key, tag })),
        })
    }

    /// Returns the configured absolute diagnostic path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    pub(crate) fn authorizes<'a>(
        &self,
        headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> bool {
        let mut authorization = None;
        for (index, (name, value)) in headers.into_iter().enumerate() {
            if index >= MAX_METRICS_HEADERS {
                return false;
            }
            if name.eq_ignore_ascii_case("authorization") {
                if authorization.replace(value).is_some() {
                    return false;
                }
            }
        }
        match &self.access {
            MetricsAccess::Public => true,
            MetricsAccess::Bearer(verifier) => {
                let Some((scheme, token)) = authorization.and_then(|value| value.split_once(' '))
                else {
                    return false;
                };
                scheme.eq_ignore_ascii_case("bearer")
                    && valid_bearer_token(token)
                    && verifier
                        .key
                        .verify_bounded(token.as_bytes(), MAX_METRICS_TOKEN_BYTES, &verifier.tag)
                        .is_ok()
            }
        }
    }
}

fn valid_bearer_token(token: &str) -> bool {
    if token.is_empty() || token.len() > MAX_METRICS_TOKEN_BYTES {
        return false;
    }
    let unpadded = token.trim_end_matches('=');
    !unpadded.is_empty()
        && unpadded.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
}

/// Closed classification shared by raw and secured listeners.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HttpDiagnosticRoute {
    Health,
    Readiness,
    Metrics,
}

pub(crate) fn metrics_response(
    operator: Option<&HttpOperatorHandle>,
    authorized: bool,
) -> HttpResponse {
    if !authorized {
        return HttpResponse::new(HttpStatus::UNAUTHORIZED)
            .with_header("www-authenticate", "Bearer realm=\"fastmcp-metrics\"")
            .with_header("cache-control", "no-store");
    }
    let Some(Ok(snapshot)) = operator.map(OperatorSnapshot::capture) else {
        return HttpResponse::new(HttpStatus::SERVICE_UNAVAILABLE)
            .with_header("cache-control", "no-store");
    };
    match snapshot.prometheus_text() {
        Ok(body) => HttpResponse::ok()
            .with_header("content-type", OPERATOR_PROMETHEUS_CONTENT_TYPE)
            .with_header("cache-control", "no-store")
            .with_body(body.into_bytes()),
        Err(_) => HttpResponse::new(HttpStatus::SERVICE_UNAVAILABLE)
            .with_header("cache-control", "no-store"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_bearer_authorizes_only_its_dedicated_credential() {
        let config = HttpMetricsConfig::bearer("/metrics", "scrape-credential+/==").unwrap();
        assert!(config.authorizes([("Authorization", "bEaReR scrape-credential+/==")]));
        for token in [
            "Bearer mcp-token",
            "Basic scrape-credential+/==",
            "Bearer scrape-credential+/=x",
            "Bearer  scrape-credential+/==",
            "Bearer scrape-credential+/== ",
        ] {
            assert!(!config.authorizes([("authorization", token)]));
        }
        assert!(!config.authorizes([]));
        assert!(!config.authorizes([
            ("authorization", "Bearer scrape-credential+/=="),
            ("Authorization", "Bearer scrape-credential+/=="),
        ]));
        assert!(!format!("{config:?}").contains("scrape-credential"));
        assert!(HttpMetricsConfig::public("/metrics").authorizes([]));
    }

    #[test]
    fn metrics_bearer_bounds_credential_and_header_work() {
        for token in ["", "=", "a b", "a\r\nb", "a=b", "é"] {
            assert!(HttpMetricsConfig::bearer("/metrics", token).is_err());
        }
        assert!(
            HttpMetricsConfig::bearer("/metrics", &"a".repeat(MAX_METRICS_TOKEN_BYTES)).is_ok()
        );
        assert!(
            HttpMetricsConfig::bearer("/metrics", &"a".repeat(MAX_METRICS_TOKEN_BYTES + 1))
                .is_err()
        );
        let config = HttpMetricsConfig::public("/metrics");
        assert!(config.authorizes(std::iter::repeat_n(
            ("x-bounded", "value"),
            MAX_METRICS_HEADERS
        )));
        assert!(!config.authorizes(std::iter::repeat(("x-bounded", "value"))));
    }
}
