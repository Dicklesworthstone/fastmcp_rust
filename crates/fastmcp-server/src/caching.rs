//! Response caching middleware for MCP servers.
//!
//! This module provides a caching middleware that can cache responses for
//! various MCP methods to improve performance and reduce redundant processing.
//!
//! # Cached Methods
//!
//! By default, the middleware caches responses for:
//! - `tools/list` - 5 minute TTL
//! - `resources/list` - 5 minute TTL
//! - `prompts/list` - 5 minute TTL
//! - `resources/read` - 1 hour TTL
//! - `prompts/get` - 1 hour TTL
//! - `tools/call` - 1 hour TTL (configurable per tool)
//!
//! # Example
//!
//! ```ignore
//! use fastmcp::prelude::*;
//! use fastmcp_server::caching::ResponseCachingMiddleware;
//!
//! let caching = ResponseCachingMiddleware::new()
//!     .list_ttl_secs(600)  // 10 minute TTL for list operations
//!     .call_ttl_secs(3600); // 1 hour TTL for call operations
//!
//! Server::new("my-server", "1.0.0")
//!     .middleware(caching)
//!     .run_stdio();
//! ```

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use fastmcp_core::{McpContext, McpError, McpResult};
use fastmcp_protocol::JsonRpcRequest;

use crate::{Middleware, MiddlewareDecision};

/// Default TTL for list operations (5 minutes).
pub const DEFAULT_LIST_TTL_SECS: u64 = 300;

/// Default TTL for call/get/read operations (1 hour).
pub const DEFAULT_CALL_TTL_SECS: u64 = 3600;

/// Maximum cache item size in bytes (1 MB).
pub const DEFAULT_MAX_ITEM_SIZE: usize = 1024 * 1024;

/// A cached response with expiration time.
#[derive(Debug, Clone)]
struct CacheEntry {
    value: serde_json::Value,
    expires_at: Instant,
    size_bytes: usize,
}

impl CacheEntry {
    fn new(value: serde_json::Value, ttl: Duration) -> Self {
        let size_bytes = value.to_string().len();
        Self {
            value,
            expires_at: Instant::now() + ttl,
            size_bytes,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

/// Cache key derived from method and parameters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    method: String,
    params_hash: u64,
}

impl CacheKey {
    fn new(method: &str, params: Option<&serde_json::Value>) -> Self {
        let params_hash = match params {
            Some(v) => hash_json_value(v),
            None => 0,
        };
        Self {
            method: method.to_string(),
            params_hash,
        }
    }
}

/// Computes a stable hash of a JSON value.
fn hash_json_value(value: &serde_json::Value) -> u64 {
    use std::collections::hash_map::DefaultHasher;

    let mut hasher = DefaultHasher::new();

    // Convert to canonical JSON string for consistent hashing
    // This handles key ordering in objects
    let json_str = serde_json::to_string(value).unwrap_or_default();
    json_str.hash(&mut hasher);

    hasher.finish()
}

/// Configuration for caching specific methods.
#[derive(Debug, Clone)]
pub struct MethodCacheConfig {
    /// Whether caching is enabled for this method.
    pub enabled: bool,
    /// Time to live in seconds.
    pub ttl_secs: u64,
}

impl Default for MethodCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ttl_secs: DEFAULT_CALL_TTL_SECS,
        }
    }
}

/// Configuration for `tools/call` caching.
#[derive(Debug, Clone, Default)]
pub struct ToolCallCacheConfig {
    /// Base configuration.
    pub base: MethodCacheConfig,
    /// Tools to include (if empty, include all).
    pub included_tools: Vec<String>,
    /// Tools to exclude (takes precedence over included).
    pub excluded_tools: Vec<String>,
}

impl ToolCallCacheConfig {
    /// Checks if a specific tool should be cached.
    fn should_cache_tool(&self, tool_name: &str) -> bool {
        if !self.base.enabled {
            return false;
        }

        // Check exclusions first (takes precedence)
        if self.excluded_tools.contains(&tool_name.to_string()) {
            return false;
        }

        // If include list is specified, tool must be in it
        if !self.included_tools.is_empty() {
            return self.included_tools.contains(&tool_name.to_string());
        }

        // Default: include all
        true
    }
}

/// Simple LRU cache with TTL support.
#[derive(Debug)]
struct LruCache {
    /// Map of keys to entries.
    entries: HashMap<CacheKey, CacheEntry>,
    /// Order of keys for LRU eviction (most recent at the end).
    order: Vec<CacheKey>,
    /// Maximum number of entries.
    max_entries: usize,
    /// Maximum total size in bytes.
    max_size_bytes: usize,
    /// Maximum size per item in bytes.
    max_item_size: usize,
    /// Current total size in bytes.
    current_size_bytes: usize,
}

impl LruCache {
    fn new(max_entries: usize, max_size_bytes: usize, max_item_size: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: Vec::new(),
            max_entries,
            max_size_bytes,
            max_item_size,
            current_size_bytes: 0,
        }
    }

    fn get(&mut self, key: &CacheKey) -> Option<serde_json::Value> {
        // Check if entry exists and is not expired
        if let Some(entry) = self.entries.get(key) {
            if entry.is_expired() {
                // Remove expired entry
                self.remove(key);
                return None;
            }

            // Move to end of order (most recently used)
            if let Some(pos) = self.order.iter().position(|k| k == key) {
                let k = self.order.remove(pos);
                self.order.push(k);
            }

            return Some(entry.value.clone());
        }
        None
    }

    fn insert(&mut self, key: CacheKey, value: serde_json::Value, ttl: Duration) {
        let entry = CacheEntry::new(value, ttl);

        // Check item size limit
        if entry.size_bytes > self.max_item_size {
            // Silently skip oversized items (matching Python behavior)
            return;
        }

        // Remove old entry if it exists
        if self.entries.contains_key(&key) {
            self.remove(&key);
        }

        // Evict entries if needed to make room
        while self.entries.len() >= self.max_entries
            || self.current_size_bytes + entry.size_bytes > self.max_size_bytes
        {
            if self.order.is_empty() {
                break;
            }
            // Evict least recently used (first in order)
            let oldest_key = self.order.remove(0);
            if let Some(old_entry) = self.entries.remove(&oldest_key) {
                self.current_size_bytes -= old_entry.size_bytes;
            }
        }

        // Also remove expired entries opportunistically
        self.evict_expired();

        // Insert new entry
        self.current_size_bytes += entry.size_bytes;
        self.entries.insert(key.clone(), entry);
        self.order.push(key);
    }

    fn remove(&mut self, key: &CacheKey) {
        if let Some(entry) = self.entries.remove(key) {
            self.current_size_bytes -= entry.size_bytes;
            if let Some(pos) = self.order.iter().position(|k| k == key) {
                self.order.remove(pos);
            }
        }
    }

    fn evict_expired(&mut self) {
        let expired_keys: Vec<CacheKey> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .map(|(key, _)| key.clone())
            .collect();

        for key in expired_keys {
            self.remove(&key);
        }
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
        self.current_size_bytes = 0;
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Cache statistics.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Number of entries currently in cache.
    pub entries: usize,
    /// Current cache size in bytes.
    pub size_bytes: usize,
}

impl CacheStats {
    /// Returns the hit rate as a percentage.
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }
}

/// Response caching middleware for MCP servers.
///
/// Caches responses for list and call operations with configurable TTL.
/// Uses an LRU eviction strategy when the cache is full.
pub struct ResponseCachingMiddleware {
    /// Cache storage.
    cache: Mutex<LruCache>,
    /// TTL for list operations.
    list_ttl: Duration,
    /// TTL for call/get/read operations.
    call_ttl: Duration,
    /// Configuration for tools/list caching.
    tools_list_config: MethodCacheConfig,
    /// Configuration for resources/list caching.
    resources_list_config: MethodCacheConfig,
    /// Configuration for prompts/list caching.
    prompts_list_config: MethodCacheConfig,
    /// Configuration for tools/call caching.
    tools_call_config: ToolCallCacheConfig,
    /// Configuration for resources/read caching.
    resources_read_config: MethodCacheConfig,
    /// Configuration for prompts/get caching.
    prompts_get_config: MethodCacheConfig,
    /// Statistics tracking.
    stats: Mutex<CacheStats>,
}

impl std::fmt::Debug for ResponseCachingMiddleware {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseCachingMiddleware")
            .field("list_ttl", &self.list_ttl)
            .field("call_ttl", &self.call_ttl)
            .finish()
    }
}

impl Default for ResponseCachingMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl ResponseCachingMiddleware {
    /// Creates a new response caching middleware with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(LruCache::new(
                1000,
                100 * 1024 * 1024,
                DEFAULT_MAX_ITEM_SIZE,
            )),
            list_ttl: Duration::from_secs(DEFAULT_LIST_TTL_SECS),
            call_ttl: Duration::from_secs(DEFAULT_CALL_TTL_SECS),
            tools_list_config: MethodCacheConfig {
                enabled: true,
                ttl_secs: DEFAULT_LIST_TTL_SECS,
            },
            resources_list_config: MethodCacheConfig {
                enabled: true,
                ttl_secs: DEFAULT_LIST_TTL_SECS,
            },
            prompts_list_config: MethodCacheConfig {
                enabled: true,
                ttl_secs: DEFAULT_LIST_TTL_SECS,
            },
            tools_call_config: ToolCallCacheConfig {
                base: MethodCacheConfig {
                    enabled: true,
                    ttl_secs: DEFAULT_CALL_TTL_SECS,
                },
                included_tools: Vec::new(),
                excluded_tools: Vec::new(),
            },
            resources_read_config: MethodCacheConfig {
                enabled: true,
                ttl_secs: DEFAULT_CALL_TTL_SECS,
            },
            prompts_get_config: MethodCacheConfig {
                enabled: true,
                ttl_secs: DEFAULT_CALL_TTL_SECS,
            },
            stats: Mutex::new(CacheStats::default()),
        }
    }

    /// Sets the maximum number of cache entries.
    #[must_use]
    pub fn max_entries(self, max: usize) -> Self {
        let max_size = {
            let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.max_size_bytes
        };
        let max_item_size = {
            let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.max_item_size
        };
        Self {
            cache: Mutex::new(LruCache::new(max, max_size, max_item_size)),
            ..self
        }
    }

    /// Sets the maximum cache size in bytes.
    #[must_use]
    pub fn max_size_bytes(self, max: usize) -> Self {
        let max_entries = {
            let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.max_entries
        };
        let max_item_size = {
            let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.max_item_size
        };
        Self {
            cache: Mutex::new(LruCache::new(max_entries, max, max_item_size)),
            ..self
        }
    }

    /// Sets the maximum size per cache item in bytes.
    #[must_use]
    pub fn max_item_size(self, max: usize) -> Self {
        let max_entries = {
            let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.max_entries
        };
        let max_size = {
            let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.max_size_bytes
        };
        Self {
            cache: Mutex::new(LruCache::new(max_entries, max_size, max)),
            ..self
        }
    }

    /// Sets the TTL for list operations (tools/list, resources/list, prompts/list).
    #[must_use]
    pub fn list_ttl_secs(mut self, secs: u64) -> Self {
        self.list_ttl = Duration::from_secs(secs);
        self.tools_list_config.ttl_secs = secs;
        self.resources_list_config.ttl_secs = secs;
        self.prompts_list_config.ttl_secs = secs;
        self
    }

    /// Sets the TTL for call/get/read operations.
    #[must_use]
    pub fn call_ttl_secs(mut self, secs: u64) -> Self {
        self.call_ttl = Duration::from_secs(secs);
        self.tools_call_config.base.ttl_secs = secs;
        self.resources_read_config.ttl_secs = secs;
        self.prompts_get_config.ttl_secs = secs;
        self
    }

    /// Disables caching for tools/list.
    #[must_use]
    pub fn disable_tools_list(mut self) -> Self {
        self.tools_list_config.enabled = false;
        self
    }

    /// Disables caching for resources/list.
    #[must_use]
    pub fn disable_resources_list(mut self) -> Self {
        self.resources_list_config.enabled = false;
        self
    }

    /// Disables caching for prompts/list.
    #[must_use]
    pub fn disable_prompts_list(mut self) -> Self {
        self.prompts_list_config.enabled = false;
        self
    }

    /// Disables caching for tools/call.
    #[must_use]
    pub fn disable_tools_call(mut self) -> Self {
        self.tools_call_config.base.enabled = false;
        self
    }

    /// Disables caching for resources/read.
    #[must_use]
    pub fn disable_resources_read(mut self) -> Self {
        self.resources_read_config.enabled = false;
        self
    }

    /// Disables caching for prompts/get.
    #[must_use]
    pub fn disable_prompts_get(mut self) -> Self {
        self.prompts_get_config.enabled = false;
        self
    }

    /// Sets the list of tools to include in caching (empty = all).
    #[must_use]
    pub fn include_tools(mut self, tools: Vec<String>) -> Self {
        self.tools_call_config.included_tools = tools;
        self
    }

    /// Sets the list of tools to exclude from caching.
    #[must_use]
    pub fn exclude_tools(mut self, tools: Vec<String>) -> Self {
        self.tools_call_config.excluded_tools = tools;
        self
    }

    /// Returns current cache statistics.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let mut stats = self.stats.lock().unwrap_or_else(|e| e.into_inner()).clone();
        stats.entries = cache.len();
        stats.size_bytes = cache.current_size_bytes;
        stats
    }

    /// Clears the entire cache.
    pub fn clear(&self) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.clear();
    }

    /// Invalidates a specific cache entry by method and params.
    pub fn invalidate(&self, method: &str, params: Option<&serde_json::Value>) {
        let key = CacheKey::new(method, params);
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.remove(&key);
    }

    /// Checks if a method should be cached.
    fn should_cache_method(&self, method: &str, params: Option<&serde_json::Value>) -> bool {
        match method {
            "tools/list" => self.tools_list_config.enabled,
            "resources/list" => self.resources_list_config.enabled,
            "prompts/list" => self.prompts_list_config.enabled,
            "resources/read" => self.resources_read_config.enabled,
            "prompts/get" => self.prompts_get_config.enabled,
            "tools/call" => {
                if !self.tools_call_config.base.enabled {
                    return false;
                }
                // Extract tool name from params
                if let Some(params) = params {
                    if let Some(tool_name) = params.get("name").and_then(|v| v.as_str()) {
                        return self.tools_call_config.should_cache_tool(tool_name);
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// Gets the TTL for a specific method.
    fn get_ttl(&self, method: &str) -> Duration {
        match method {
            "tools/list" => Duration::from_secs(self.tools_list_config.ttl_secs),
            "resources/list" => Duration::from_secs(self.resources_list_config.ttl_secs),
            "prompts/list" => Duration::from_secs(self.prompts_list_config.ttl_secs),
            "tools/call" => Duration::from_secs(self.tools_call_config.base.ttl_secs),
            "resources/read" => Duration::from_secs(self.resources_read_config.ttl_secs),
            "prompts/get" => Duration::from_secs(self.prompts_get_config.ttl_secs),
            _ => self.call_ttl,
        }
    }

    fn record_hit(&self) {
        let mut stats = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        stats.hits += 1;
    }

    fn record_miss(&self) {
        let mut stats = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        stats.misses += 1;
    }
}

impl Middleware for ResponseCachingMiddleware {
    fn on_request(
        &self,
        _ctx: &McpContext,
        request: &JsonRpcRequest,
    ) -> McpResult<MiddlewareDecision> {
        // Check if this method should be cached
        if !self.should_cache_method(&request.method, request.params.as_ref()) {
            return Ok(MiddlewareDecision::Continue);
        }

        // Try to get cached response
        let key = CacheKey::new(&request.method, request.params.as_ref());
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if let Some(value) = cache.get(&key) {
            self.record_hit();
            return Ok(MiddlewareDecision::Respond(value));
        }

        self.record_miss();
        Ok(MiddlewareDecision::Continue)
    }

    fn on_response(
        &self,
        _ctx: &McpContext,
        request: &JsonRpcRequest,
        response: serde_json::Value,
    ) -> McpResult<serde_json::Value> {
        // Only cache if this method is cacheable
        if !self.should_cache_method(&request.method, request.params.as_ref()) {
            return Ok(response);
        }

        // Store in cache
        let key = CacheKey::new(&request.method, request.params.as_ref());
        let ttl = self.get_ttl(&request.method);

        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        cache.insert(key, response.clone(), ttl);

        Ok(response)
    }

    fn on_error(&self, _ctx: &McpContext, _request: &JsonRpcRequest, error: McpError) -> McpError {
        // Don't cache errors, just pass them through
        error
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

    fn test_request(method: &str, params: Option<serde_json::Value>) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: std::borrow::Cow::Borrowed(fastmcp_protocol::JSONRPC_VERSION),
            method: method.to_string(),
            params,
            id: Some(fastmcp_protocol::RequestId::Number(1)),
        }
    }

    // ========================================
    // LruCache tests
    // ========================================

    #[test]
    fn test_lru_cache_basic_operations() {
        let mut cache = LruCache::new(10, 1024 * 1024, 1024);

        let key = CacheKey::new("test", None);
        let value = serde_json::json!({"result": "cached"});

        // Insert and retrieve
        cache.insert(key.clone(), value.clone(), Duration::from_secs(60));
        let retrieved = cache.get(&key);
        assert_eq!(retrieved, Some(value));
    }

    #[test]
    fn test_lru_cache_expiration() {
        let mut cache = LruCache::new(10, 1024 * 1024, 1024);

        let key = CacheKey::new("test", None);
        let value = serde_json::json!({"result": "cached"});

        // Insert with very short TTL
        cache.insert(key.clone(), value, Duration::from_millis(1));

        // Wait for expiration
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Should be expired
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_lru_cache_eviction() {
        let mut cache = LruCache::new(2, 1024 * 1024, 1024);

        let key1 = CacheKey::new("test1", None);
        let key2 = CacheKey::new("test2", None);
        let key3 = CacheKey::new("test3", None);

        cache.insert(
            key1.clone(),
            serde_json::json!("v1"),
            Duration::from_secs(60),
        );
        cache.insert(
            key2.clone(),
            serde_json::json!("v2"),
            Duration::from_secs(60),
        );

        // Should evict key1 (LRU)
        cache.insert(
            key3.clone(),
            serde_json::json!("v3"),
            Duration::from_secs(60),
        );

        assert!(cache.get(&key1).is_none());
        assert!(cache.get(&key2).is_some());
        assert!(cache.get(&key3).is_some());
    }

    #[test]
    fn test_lru_cache_size_limit() {
        // Very small size limit
        let mut cache = LruCache::new(100, 50, 1024);

        let key1 = CacheKey::new("test1", None);
        let key2 = CacheKey::new("test2", None);

        // First entry should fit
        cache.insert(
            key1.clone(),
            serde_json::json!("short"),
            Duration::from_secs(60),
        );
        assert_eq!(cache.len(), 1);

        // Second entry should cause eviction
        cache.insert(
            key2.clone(),
            serde_json::json!("another"),
            Duration::from_secs(60),
        );
        // Cache should have evicted the first entry to make room
        assert!(cache.len() <= 2);
    }

    #[test]
    fn test_lru_cache_oversized_item_rejected() {
        let mut cache = LruCache::new(10, 1024 * 1024, 10); // max 10 bytes per item

        let key = CacheKey::new("test", None);
        let large_value = serde_json::json!({"data": "this is much longer than 10 bytes"});

        cache.insert(key.clone(), large_value, Duration::from_secs(60));

        // Should not be stored
        assert!(cache.get(&key).is_none());
    }

    // ========================================
    // ResponseCachingMiddleware tests
    // ========================================

    #[test]
    fn test_caching_middleware_caches_tools_list() {
        let middleware = ResponseCachingMiddleware::new();
        let ctx = test_context();
        let request = test_request("tools/list", None);

        // First request: miss, continue
        let decision = middleware.on_request(&ctx, &request).unwrap();
        assert!(matches!(decision, MiddlewareDecision::Continue));

        // Simulate response
        let response = serde_json::json!({"tools": []});
        middleware
            .on_response(&ctx, &request, response.clone())
            .unwrap();

        // Second request: hit, respond from cache
        let decision = middleware.on_request(&ctx, &request).unwrap();
        match decision {
            MiddlewareDecision::Respond(cached) => assert_eq!(cached, response),
            MiddlewareDecision::Continue => panic!("Expected cache hit"),
        }

        // Check stats
        let stats = middleware.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_caching_middleware_skips_non_cacheable_methods() {
        let middleware = ResponseCachingMiddleware::new();
        let ctx = test_context();
        let request = test_request("initialize", None);

        // Should continue (not cached)
        let decision = middleware.on_request(&ctx, &request).unwrap();
        assert!(matches!(decision, MiddlewareDecision::Continue));

        // Even after response, next request should not hit cache
        middleware
            .on_response(&ctx, &request, serde_json::json!({}))
            .unwrap();

        let decision = middleware.on_request(&ctx, &request).unwrap();
        assert!(matches!(decision, MiddlewareDecision::Continue));
    }

    #[test]
    fn test_caching_middleware_different_params_different_keys() {
        let middleware = ResponseCachingMiddleware::new();
        let ctx = test_context();

        let request1 = test_request(
            "tools/call",
            Some(serde_json::json!({"name": "tool_a", "arguments": {}})),
        );
        let request2 = test_request(
            "tools/call",
            Some(serde_json::json!({"name": "tool_b", "arguments": {}})),
        );

        // Cache response for request1
        middleware.on_request(&ctx, &request1).unwrap();
        let response1 = serde_json::json!({"result": "a"});
        middleware
            .on_response(&ctx, &request1, response1.clone())
            .unwrap();

        // Request2 should not hit cache
        let decision = middleware.on_request(&ctx, &request2).unwrap();
        assert!(matches!(decision, MiddlewareDecision::Continue));

        // Request1 should hit cache
        let decision = middleware.on_request(&ctx, &request1).unwrap();
        match decision {
            MiddlewareDecision::Respond(cached) => assert_eq!(cached, response1),
            MiddlewareDecision::Continue => panic!("Expected cache hit"),
        }
    }

    #[test]
    fn test_caching_middleware_tool_exclusion() {
        let middleware =
            ResponseCachingMiddleware::new().exclude_tools(vec!["excluded_tool".to_string()]);
        let ctx = test_context();

        let excluded_request = test_request(
            "tools/call",
            Some(serde_json::json!({"name": "excluded_tool", "arguments": {}})),
        );
        let included_request = test_request(
            "tools/call",
            Some(serde_json::json!({"name": "included_tool", "arguments": {}})),
        );

        // Excluded tool should not be cached
        middleware.on_request(&ctx, &excluded_request).unwrap();
        middleware
            .on_response(&ctx, &excluded_request, serde_json::json!({}))
            .unwrap();

        let decision = middleware.on_request(&ctx, &excluded_request).unwrap();
        assert!(matches!(decision, MiddlewareDecision::Continue));

        // Included tool should be cached
        middleware.on_request(&ctx, &included_request).unwrap();
        let response = serde_json::json!({"result": "included"});
        middleware
            .on_response(&ctx, &included_request, response.clone())
            .unwrap();

        let decision = middleware.on_request(&ctx, &included_request).unwrap();
        match decision {
            MiddlewareDecision::Respond(cached) => assert_eq!(cached, response),
            MiddlewareDecision::Continue => panic!("Expected cache hit for included tool"),
        }
    }

    #[test]
    fn test_caching_middleware_disable_method() {
        let middleware = ResponseCachingMiddleware::new().disable_tools_list();
        let ctx = test_context();
        let request = test_request("tools/list", None);

        // Should not cache
        middleware.on_request(&ctx, &request).unwrap();
        middleware
            .on_response(&ctx, &request, serde_json::json!({}))
            .unwrap();

        let decision = middleware.on_request(&ctx, &request).unwrap();
        assert!(matches!(decision, MiddlewareDecision::Continue));
    }

    #[test]
    fn test_caching_middleware_clear() {
        let middleware = ResponseCachingMiddleware::new();
        let ctx = test_context();
        let request = test_request("tools/list", None);

        // Cache a response
        middleware.on_request(&ctx, &request).unwrap();
        middleware
            .on_response(&ctx, &request, serde_json::json!({}))
            .unwrap();

        // Verify cached
        let decision = middleware.on_request(&ctx, &request).unwrap();
        assert!(matches!(decision, MiddlewareDecision::Respond(_)));

        // Clear cache
        middleware.clear();

        // Should miss now
        let decision = middleware.on_request(&ctx, &request).unwrap();
        assert!(matches!(decision, MiddlewareDecision::Continue));
    }

    #[test]
    fn test_caching_middleware_invalidate() {
        let middleware = ResponseCachingMiddleware::new();
        let ctx = test_context();
        let request = test_request("tools/list", None);

        // Cache a response
        middleware.on_request(&ctx, &request).unwrap();
        middleware
            .on_response(&ctx, &request, serde_json::json!({}))
            .unwrap();

        // Invalidate specific entry
        middleware.invalidate("tools/list", None);

        // Should miss now
        let decision = middleware.on_request(&ctx, &request).unwrap();
        assert!(matches!(decision, MiddlewareDecision::Continue));
    }

    #[test]
    fn test_cache_stats_hit_rate() {
        let stats = CacheStats {
            hits: 75,
            misses: 25,
            entries: 10,
            size_bytes: 1000,
        };

        assert!((stats.hit_rate() - 75.0).abs() < 0.001);
    }
}
