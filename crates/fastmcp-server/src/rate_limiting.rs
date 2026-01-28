//! Rate limiting middleware for protecting FastMCP servers from abuse.
//!
//! This module provides two rate limiting strategies:
//!
//! - [`RateLimitingMiddleware`]: Token bucket algorithm for burst-friendly limits
//! - [`SlidingWindowRateLimitingMiddleware`]: Sliding window for precise tracking
//!
//! # Example
//!
//! ```ignore
//! use fastmcp::prelude::*;
//! use fastmcp_server::rate_limiting::RateLimitingMiddleware;
//!
//! // Allow 10 requests per second with bursts up to 20
//! let rate_limiter = RateLimitingMiddleware::new(10.0)
//!     .burst_capacity(20);
//!
//! Server::new("my-server", "1.0.0")
//!     .middleware(rate_limiter)
//!     .run_stdio();
//! ```

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Instant;

use fastmcp_core::{McpContext, McpError, McpErrorCode, McpResult};
use fastmcp_protocol::JsonRpcRequest;

use crate::{Middleware, MiddlewareDecision};

/// Error code for rate limit exceeded (-32005).
///
/// This is in the MCP server error range (-32000 to -32099).
pub const RATE_LIMIT_ERROR_CODE: i32 = -32005;

/// Creates a rate limit exceeded error.
#[must_use]
pub fn rate_limit_error(message: impl Into<String>) -> McpError {
    McpError::new(McpErrorCode::Custom(RATE_LIMIT_ERROR_CODE), message)
}

/// Token bucket implementation for rate limiting.
///
/// The token bucket algorithm allows for burst traffic while maintaining
/// a sustainable long-term rate. Tokens are added at a constant rate and
/// consumed when requests arrive.
#[derive(Debug)]
pub struct TokenBucketRateLimiter {
    /// Maximum number of tokens in the bucket.
    capacity: usize,
    /// Tokens added per second.
    refill_rate: f64,
    /// Current number of tokens (as f64 for fractional tokens).
    tokens: Mutex<f64>,
    /// Last time tokens were refilled.
    last_refill: Mutex<Instant>,
}

impl TokenBucketRateLimiter {
    /// Creates a new token bucket rate limiter.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of tokens (burst capacity)
    /// * `refill_rate` - Tokens added per second (sustained rate)
    #[must_use]
    pub fn new(capacity: usize, refill_rate: f64) -> Self {
        Self {
            capacity,
            refill_rate,
            tokens: Mutex::new(capacity as f64),
            last_refill: Mutex::new(Instant::now()),
        }
    }

    /// Tries to consume tokens from the bucket.
    ///
    /// Returns `true` if tokens were available and consumed, `false` otherwise.
    pub fn try_consume(&self, tokens: usize) -> bool {
        let mut current_tokens = self
            .tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut last_refill = self
            .last_refill
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let now = Instant::now();
        let elapsed = now.duration_since(*last_refill).as_secs_f64();

        // Add tokens based on elapsed time
        *current_tokens = (*current_tokens + elapsed * self.refill_rate).min(self.capacity as f64);
        *last_refill = now;

        let tokens_needed = tokens as f64;
        if *current_tokens >= tokens_needed {
            *current_tokens -= tokens_needed;
            true
        } else {
            false
        }
    }

    /// Returns the current number of available tokens.
    #[must_use]
    pub fn available_tokens(&self) -> f64 {
        let mut current_tokens = self
            .tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut last_refill = self
            .last_refill
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let now = Instant::now();
        let elapsed = now.duration_since(*last_refill).as_secs_f64();

        // Update tokens without consuming
        *current_tokens = (*current_tokens + elapsed * self.refill_rate).min(self.capacity as f64);
        *last_refill = now;

        *current_tokens
    }
}

/// Sliding window rate limiter implementation.
///
/// Tracks individual request timestamps within a time window for precise
/// rate limiting. More memory-intensive than token bucket but provides
/// exact request counting.
#[derive(Debug)]
pub struct SlidingWindowRateLimiter {
    /// Maximum requests allowed in the time window.
    max_requests: usize,
    /// Time window in seconds.
    window_seconds: u64,
    /// Request timestamps (as durations from a fixed start time).
    requests: Mutex<VecDeque<Instant>>,
}

impl SlidingWindowRateLimiter {
    /// Creates a new sliding window rate limiter.
    ///
    /// # Arguments
    ///
    /// * `max_requests` - Maximum requests allowed in the time window
    /// * `window_seconds` - Time window duration in seconds
    #[must_use]
    pub fn new(max_requests: usize, window_seconds: u64) -> Self {
        Self {
            max_requests,
            window_seconds,
            requests: Mutex::new(VecDeque::new()),
        }
    }

    /// Checks if a request is allowed under the rate limit.
    ///
    /// If allowed, records the request timestamp and returns `true`.
    /// Otherwise returns `false`.
    pub fn is_allowed(&self) -> bool {
        let mut requests = self
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let now = Instant::now();
        let cutoff = now - std::time::Duration::from_secs(self.window_seconds);

        // Remove old requests outside the window
        while let Some(&oldest) = requests.front() {
            if oldest < cutoff {
                requests.pop_front();
            } else {
                break;
            }
        }

        if requests.len() < self.max_requests {
            requests.push_back(now);
            true
        } else {
            false
        }
    }

    /// Returns the current number of requests in the window.
    #[must_use]
    pub fn current_requests(&self) -> usize {
        let mut requests = self
            .requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let now = Instant::now();
        let cutoff = now - std::time::Duration::from_secs(self.window_seconds);

        // Remove old requests outside the window
        while let Some(&oldest) = requests.front() {
            if oldest < cutoff {
                requests.pop_front();
            } else {
                break;
            }
        }

        requests.len()
    }
}

/// Function type for extracting client ID from request context.
pub type ClientIdExtractor =
    Box<dyn Fn(&McpContext, &JsonRpcRequest) -> Option<String> + Send + Sync>;

/// Rate limiting middleware using token bucket algorithm.
///
/// Uses a token bucket algorithm by default, allowing for burst traffic
/// while maintaining a sustainable long-term rate.
///
/// # Example
///
/// ```ignore
/// use fastmcp_server::rate_limiting::RateLimitingMiddleware;
///
/// // Allow 10 requests per second with bursts up to 20
/// let rate_limiter = RateLimitingMiddleware::new(10.0)
///     .burst_capacity(20);
/// ```
pub struct RateLimitingMiddleware {
    /// Sustained requests per second allowed.
    max_requests_per_second: f64,
    /// Maximum burst capacity.
    burst_capacity: usize,
    /// Function to extract client ID from context (for per-client limiting).
    get_client_id: Option<ClientIdExtractor>,
    /// If true, apply limit globally; if false, per-client.
    global_limit: bool,
    /// Storage for rate limiters per client.
    limiters: Mutex<HashMap<String, TokenBucketRateLimiter>>,
    /// Global rate limiter (used when global_limit is true).
    global_limiter: Option<TokenBucketRateLimiter>,
}

impl std::fmt::Debug for RateLimitingMiddleware {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitingMiddleware")
            .field("max_requests_per_second", &self.max_requests_per_second)
            .field("burst_capacity", &self.burst_capacity)
            .field("global_limit", &self.global_limit)
            .finish()
    }
}

impl RateLimitingMiddleware {
    /// Creates a new rate limiting middleware with the specified rate.
    ///
    /// # Arguments
    ///
    /// * `max_requests_per_second` - Sustained requests per second allowed
    ///
    /// Burst capacity defaults to 2x the sustained rate.
    #[must_use]
    pub fn new(max_requests_per_second: f64) -> Self {
        let burst_capacity = (max_requests_per_second * 2.0) as usize;
        Self {
            max_requests_per_second,
            burst_capacity,
            get_client_id: None,
            global_limit: false,
            limiters: Mutex::new(HashMap::new()),
            global_limiter: None,
        }
    }

    /// Sets the burst capacity (maximum tokens in the bucket).
    #[must_use]
    pub fn burst_capacity(mut self, capacity: usize) -> Self {
        self.burst_capacity = capacity;
        // Re-create global limiter if it exists
        if self.global_limit {
            self.global_limiter = Some(TokenBucketRateLimiter::new(
                capacity,
                self.max_requests_per_second,
            ));
        }
        self
    }

    /// Sets a custom function to extract client ID from the request context.
    ///
    /// If not set, all clients share a single rate limit (global limiting).
    #[must_use]
    pub fn client_id_extractor<F>(mut self, extractor: F) -> Self
    where
        F: Fn(&McpContext, &JsonRpcRequest) -> Option<String> + Send + Sync + 'static,
    {
        self.get_client_id = Some(Box::new(extractor));
        self
    }

    /// Enables global rate limiting (all clients share one limit).
    ///
    /// When enabled, all requests count against a single rate limit
    /// regardless of client identity.
    #[must_use]
    pub fn global(mut self) -> Self {
        self.global_limit = true;
        self.global_limiter = Some(TokenBucketRateLimiter::new(
            self.burst_capacity,
            self.max_requests_per_second,
        ));
        self
    }

    fn get_client_identifier(&self, ctx: &McpContext, request: &JsonRpcRequest) -> String {
        if let Some(ref extractor) = self.get_client_id {
            if let Some(id) = extractor(ctx, request) {
                return id;
            }
        }
        "global".to_string()
    }

    fn get_or_create_limiter(&self, client_id: &str) -> bool {
        let mut limiters = self
            .limiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if !limiters.contains_key(client_id) {
            limiters.insert(
                client_id.to_string(),
                TokenBucketRateLimiter::new(self.burst_capacity, self.max_requests_per_second),
            );
        }

        limiters.get(client_id).unwrap().try_consume(1)
    }
}

impl Middleware for RateLimitingMiddleware {
    fn on_request(
        &self,
        ctx: &McpContext,
        request: &JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        let allowed = if self.global_limit {
            // Global rate limiting
            if let Some(ref limiter) = self.global_limiter {
                limiter.try_consume(1)
            } else {
                true
            }
        } else {
            // Per-client rate limiting
            let client_id = self.get_client_identifier(ctx, request);
            self.get_or_create_limiter(&client_id)
        };

        if allowed {
            Ok(MiddlewareDecision::Continue)
        } else {
            let msg = if self.global_limit {
                "Global rate limit exceeded".to_string()
            } else {
                let client_id = self.get_client_identifier(ctx, request);
                format!("Rate limit exceeded for client: {client_id}")
            };
            Err(rate_limit_error(msg))
        }
    }
}

/// Rate limiting middleware using sliding window algorithm.
///
/// Uses a sliding window approach which provides more precise rate limiting
/// but uses more memory to track individual request timestamps.
///
/// # Example
///
/// ```ignore
/// use fastmcp_server::rate_limiting::SlidingWindowRateLimitingMiddleware;
///
/// // Allow 100 requests per minute
/// let rate_limiter = SlidingWindowRateLimitingMiddleware::new(100, 60);
/// ```
pub struct SlidingWindowRateLimitingMiddleware {
    /// Maximum requests allowed in the time window.
    max_requests: usize,
    /// Time window in seconds.
    window_seconds: u64,
    /// Function to extract client ID from context.
    get_client_id: Option<ClientIdExtractor>,
    /// Storage for rate limiters per client.
    limiters: Mutex<HashMap<String, SlidingWindowRateLimiter>>,
}

impl std::fmt::Debug for SlidingWindowRateLimitingMiddleware {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlidingWindowRateLimitingMiddleware")
            .field("max_requests", &self.max_requests)
            .field("window_seconds", &self.window_seconds)
            .finish()
    }
}

impl SlidingWindowRateLimitingMiddleware {
    /// Creates a new sliding window rate limiting middleware.
    ///
    /// # Arguments
    ///
    /// * `max_requests` - Maximum requests allowed in the time window
    /// * `window_seconds` - Time window duration in seconds
    #[must_use]
    pub fn new(max_requests: usize, window_seconds: u64) -> Self {
        Self {
            max_requests,
            window_seconds,
            get_client_id: None,
            limiters: Mutex::new(HashMap::new()),
        }
    }

    /// Creates a sliding window rate limiter with minutes-based window.
    ///
    /// # Arguments
    ///
    /// * `max_requests` - Maximum requests allowed in the time window
    /// * `window_minutes` - Time window duration in minutes
    #[must_use]
    pub fn per_minute(max_requests: usize, window_minutes: u64) -> Self {
        Self::new(max_requests, window_minutes * 60)
    }

    /// Sets a custom function to extract client ID from the request context.
    #[must_use]
    pub fn client_id_extractor<F>(mut self, extractor: F) -> Self
    where
        F: Fn(&McpContext, &JsonRpcRequest) -> Option<String> + Send + Sync + 'static,
    {
        self.get_client_id = Some(Box::new(extractor));
        self
    }

    fn get_client_identifier(&self, ctx: &McpContext, request: &JsonRpcRequest) -> String {
        if let Some(ref extractor) = self.get_client_id {
            if let Some(id) = extractor(ctx, request) {
                return id;
            }
        }
        "global".to_string()
    }

    fn is_request_allowed(&self, client_id: &str) -> bool {
        let mut limiters = self
            .limiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if !limiters.contains_key(client_id) {
            limiters.insert(
                client_id.to_string(),
                SlidingWindowRateLimiter::new(self.max_requests, self.window_seconds),
            );
        }

        limiters.get(client_id).unwrap().is_allowed()
    }
}

impl Middleware for SlidingWindowRateLimitingMiddleware {
    fn on_request(
        &self,
        ctx: &McpContext,
        request: &JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        let client_id = self.get_client_identifier(ctx, request);
        let allowed = self.is_request_allowed(&client_id);

        if allowed {
            Ok(MiddlewareDecision::Continue)
        } else {
            let window_display = if self.window_seconds >= 60 {
                format!("{} minute(s)", self.window_seconds / 60)
            } else {
                format!("{} second(s)", self.window_seconds)
            };
            Err(rate_limit_error(format!(
                "Rate limit exceeded: {} requests per {} for client: {}",
                self.max_requests, window_display, client_id
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::Cx;

    fn test_context() -> McpContext {
        let cx = Cx::for_testing();
        McpContext::new(cx, 1)
    }

    fn test_request(method: &str) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
            method: method.to_string(),
            params: None,
            id: Some(fastmcp_protocol::RequestId::Number(1)),
        }
    }

    // ========================================
    // TokenBucketRateLimiter tests
    // ========================================

    #[test]
    fn test_token_bucket_allows_burst() {
        let limiter = TokenBucketRateLimiter::new(5, 1.0);

        // Should allow burst up to capacity
        assert!(limiter.try_consume(1));
        assert!(limiter.try_consume(1));
        assert!(limiter.try_consume(1));
        assert!(limiter.try_consume(1));
        assert!(limiter.try_consume(1));

        // Should deny once capacity exhausted
        assert!(!limiter.try_consume(1));
    }

    #[test]
    fn test_token_bucket_refills_over_time() {
        let limiter = TokenBucketRateLimiter::new(2, 100.0); // 100 tokens per second

        // Exhaust tokens
        assert!(limiter.try_consume(1));
        assert!(limiter.try_consume(1));
        assert!(!limiter.try_consume(1));

        // Wait for refill (10ms should add ~1 token at 100 t/s)
        std::thread::sleep(std::time::Duration::from_millis(15));

        // Should have refilled
        assert!(limiter.try_consume(1));
    }

    #[test]
    fn test_token_bucket_available_tokens() {
        let limiter = TokenBucketRateLimiter::new(10, 1.0);
        assert!((limiter.available_tokens() - 10.0).abs() < 0.1);

        limiter.try_consume(5);
        assert!((limiter.available_tokens() - 5.0).abs() < 0.1);
    }

    // ========================================
    // SlidingWindowRateLimiter tests
    // ========================================

    #[test]
    fn test_sliding_window_allows_up_to_limit() {
        let limiter = SlidingWindowRateLimiter::new(3, 60);

        assert!(limiter.is_allowed());
        assert!(limiter.is_allowed());
        assert!(limiter.is_allowed());
        assert!(!limiter.is_allowed()); // Fourth request denied
    }

    #[test]
    fn test_sliding_window_current_requests() {
        let limiter = SlidingWindowRateLimiter::new(10, 60);

        assert_eq!(limiter.current_requests(), 0);
        limiter.is_allowed();
        assert_eq!(limiter.current_requests(), 1);
        limiter.is_allowed();
        assert_eq!(limiter.current_requests(), 2);
    }

    // ========================================
    // RateLimitingMiddleware tests
    // ========================================

    #[test]
    fn test_rate_limiting_middleware_allows_initial_requests() {
        let middleware = RateLimitingMiddleware::new(10.0).global();
        let ctx = test_context();
        let request = test_request("tools/call");

        let result = middleware.on_request(&ctx, &request);
        assert!(matches!(result, Ok(MiddlewareDecision::Continue)));
    }

    #[test]
    fn test_rate_limiting_middleware_denies_after_burst() {
        let middleware = RateLimitingMiddleware::new(10.0).burst_capacity(2).global();
        let ctx = test_context();
        let request = test_request("tools/call");

        // First two should succeed (burst capacity = 2)
        assert!(middleware.on_request(&ctx, &request).is_ok());
        assert!(middleware.on_request(&ctx, &request).is_ok());

        // Third should fail
        let result = middleware.on_request(&ctx, &request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(i32::from(err.code), RATE_LIMIT_ERROR_CODE);
        assert!(err.message.contains("Global rate limit exceeded"));
    }

    #[test]
    fn test_rate_limiting_middleware_per_client() {
        let middleware = RateLimitingMiddleware::new(10.0)
            .burst_capacity(1)
            .client_id_extractor(|_ctx, req| Some(req.method.clone()));
        let ctx = test_context();

        let request1 = test_request("method_a");
        let request2 = test_request("method_b");

        // Each "client" (method) gets their own bucket
        assert!(middleware.on_request(&ctx, &request1).is_ok());
        assert!(middleware.on_request(&ctx, &request2).is_ok());

        // Now both are exhausted
        assert!(middleware.on_request(&ctx, &request1).is_err());
        assert!(middleware.on_request(&ctx, &request2).is_err());
    }

    // ========================================
    // SlidingWindowRateLimitingMiddleware tests
    // ========================================

    #[test]
    fn test_sliding_window_middleware_allows_up_to_limit() {
        let middleware = SlidingWindowRateLimitingMiddleware::new(2, 60);
        let ctx = test_context();
        let request = test_request("tools/call");

        assert!(middleware.on_request(&ctx, &request).is_ok());
        assert!(middleware.on_request(&ctx, &request).is_ok());

        let result = middleware.on_request(&ctx, &request);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(i32::from(err.code), RATE_LIMIT_ERROR_CODE);
    }

    #[test]
    fn test_sliding_window_middleware_per_minute() {
        let middleware = SlidingWindowRateLimitingMiddleware::per_minute(100, 1);
        let ctx = test_context();
        let request = test_request("tools/call");

        // Should allow many requests
        for _ in 0..100 {
            assert!(middleware.on_request(&ctx, &request).is_ok());
        }

        // 101st should fail
        assert!(middleware.on_request(&ctx, &request).is_err());
    }

    #[test]
    fn test_rate_limit_error_code() {
        let err = rate_limit_error("test");
        assert_eq!(i32::from(err.code), RATE_LIMIT_ERROR_CODE);
        assert_eq!(err.message, "test");
    }
}
