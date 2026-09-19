//! Encrypted terminal-result replay for exact modern MRTR retries.
//!
//! Install this middleware FIRST, so it captures the final successful result
//! after the other response hooks and replays without running those hooks again.
//! Authentication still runs normally. The authorization callback must check
//! current permission and handler/configuration revisions on EVERY invocation.
//!
//! Only requests carrying a nonempty requestState participate. Initial calls
//! are never cached, and this layer never creates or retries a remote operation.
//! The normal router remains responsible for validating/consuming continuation
//! state. This is a bounded process-local reply journal, not durable exactly-once
//! execution, successor-state recovery, or SSE/progress/log replay.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Write};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use asupersync::Cx;
use fastmcp_core::{McpContext, McpError, McpRequestCancellation, McpResult, sha256_bounded};
use fastmcp_core::partition::{ContinuationPartitionKey, PartitionAuthorization};
use fastmcp_core::runtime::{ProcessBoundToken, ProcessGenerationGuard, SnapshotCloneStance};
use fastmcp_core::runtime::envelope::{EnvelopeBinding, EnvelopePolicy, EnvelopePurpose, EphemeralEnvelopeProtector};
use fastmcp_protocol::{CoreRequest, JsonRpcRequest, FINAL_PROTOCOL_VERSION};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use serde_json::Value;
use zeroize::Zeroizing;

use super::{Middleware, MiddlewareDecision};

const VERSION_META: &str = "io.modelcontextprotocol/protocolVersion";
const IDENTITY_BYTES: usize = 64;
const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 16 * 1024;

/// Current host-authorized continuation identity and its revocation domain.
/// This constructor does not authenticate anything. Derive the key from verified
/// ingress, including method/handler revision and capability/configuration policy.
/// The lifetime is the authorization/continuation lifetime, NOT the individual
/// HTTP request: losing a response must not itself revoke a recoverable result.
pub struct ContinuationReplayAuthority {
    key: ContinuationPartitionKey,
    authorization: PartitionAuthorization,
    lifetime: McpRequestCancellation,
}
impl ContinuationReplayAuthority {
    pub fn new(key: ContinuationPartitionKey, authorization: PartitionAuthorization,
        lifetime: McpRequestCancellation) -> Self
    { Self { key, authorization, lifetime } }
}

type Authorize = dyn Fn(&McpContext, &JsonRpcRequest) -> McpResult<ContinuationReplayAuthority> + Send + Sync;

/// Hard bounds include pending reservations. A pending call reserves its maximum
/// response size BEFORE dispatch; completing it cannot discover a quota shortage.
#[derive(Clone, Copy, Debug)]
pub struct ContinuationReplayLimits {
    maximum_entries: usize,
    maximum_bytes: usize,
    request_bytes: usize,
    result_bytes: usize,
    lifetime: Duration,
}
impl Default for ContinuationReplayLimits {
    fn default() -> Self {
        Self { maximum_entries: 128, maximum_bytes: 16 * 1024 * 1024,
            request_bytes: 64 * 1024, result_bytes: 64 * 1024, lifetime: Duration::from_secs(300) }
    }
}
impl ContinuationReplayLimits {
    pub fn new(maximum_entries: usize, maximum_bytes: usize, request_bytes: usize,
        result_bytes: usize, lifetime: Duration) -> McpResult<Self>
    {
        if !(1..=4096).contains(&maximum_entries) || !(1..=64 * 1024 * 1024).contains(&maximum_bytes)
            || !(1..=1024 * 1024).contains(&request_bytes) || !(1..=1024 * 1024).contains(&result_bytes)
            || lifetime.is_zero() || lifetime > Duration::from_secs(3600)
        { return Err(McpError::invalid_params("Invalid continuation replay limits")); }
        Ok(Self { maximum_entries, maximum_bytes, request_bytes, result_bytes, lifetime })
    }
}

struct Identity {
    slot: [u8; 32],
    fingerprint: [u8; 32],
    binding: EnvelopeBinding,
    lifetime: McpRequestCancellation,
    decoder: CoreRequest,
}
struct Entry {
    fingerprint: [u8; 32],
    lifetime: McpRequestCancellation,
    expires_at: Instant,
    // None fences an in-flight or uncertain attempt. Never discard this fence
    // on on_error: a duplicate's error must not release the original dispatch.
    result: Option<Vec<u8>>,
    charge: usize,
}
struct Journal {
    protector: EphemeralEnvelopeProtector,
    entries: BTreeMap<[u8; 32], Entry>,
    retained_bytes: usize,
    closed: bool,
}

/// Middleware that recovers a completed continuation result after reply loss.
/// Only an EXACT retry within its original lifetime is replayed. New JSON-RPC
/// IDs are permitted; the server wraps the result in the current request ID.
/// Changed arguments, answers, or metadata under the same bound continuation
/// fail closed instead of reaching the handler.
///
/// Hooks use try_lock, never wait on another hook, and hold no lock across a
/// handler or host authorization callback. Synchronous JSON/crypto work is
/// bounded by the limits; the embedding host owns scheduling and admission.
/// Pending/uncertain fences survive pruning until close. A host must replace a
/// saturated journal only after quiescing its requests; this is not a generic
/// idempotency cache for handlers that ignore the router's one-use MRTR state.
pub struct ContinuationReplayMiddleware {
    process: ProcessBoundToken,
    limits: ContinuationReplayLimits,
    authorize: Arc<Authorize>,
    journal: Mutex<Journal>,
}
impl ContinuationReplayMiddleware {
    pub fn new<F>(cx: &Cx, guard: &ProcessGenerationGuard, stance: SnapshotCloneStance,
        limits: ContinuationReplayLimits, authorize: F) -> McpResult<Self>
    where F: Fn(&McpContext, &JsonRpcRequest) -> McpResult<ContinuationReplayAuthority> + Send + Sync + 'static,
    {
        let policy = EnvelopePolicy::new(limits.result_bytes, limits.lifetime, 4).map_err(|_| unavailable())?;
        let protector = EphemeralEnvelopeProtector::new(cx, guard, stance, EnvelopePurpose::Continuation, policy)
            .map_err(|_| unavailable())?;
        Ok(Self { process: guard.token(), limits, authorize: Arc::new(authorize),
            journal: Mutex::new(Journal { protector, entries: BTreeMap::new(), retained_bytes: 0, closed: false }) })
    }

    fn lock(&self) -> McpResult<MutexGuard<'_, Journal>> {
        // A forked process must never touch an inherited mutex or key owner.
        self.process.verify().map_err(|_| unavailable())?;
        let state = self.journal.try_lock().map_err(|_| unavailable())?;
        if state.closed { return Err(unavailable()); }
        Ok(state)
    }

    fn identity(&self, ctx: &McpContext, request: &JsonRpcRequest) -> McpResult<Option<Identity>> {
        let Some(params) = request.params.as_ref() else { return Ok(None); };
        if !matches!(request.method.as_str(), "tools/call" | "resources/read" | "prompts/get")
            || params.get("_meta").and_then(|meta| meta.get(VERSION_META)).and_then(Value::as_str) != Some(FINAL_PROTOCOL_VERSION)
        { return Ok(None); }
        let Some(state) = params.get("requestState") else { return Ok(None); };
        let state = state.as_str().ok_or_else(unavailable)?;
        // An empty initial state is not a replay key. The router decides its
        // normal protocol meaning; this middleware does not invent one.
        if state.is_empty() { return Ok(None); }
        self.process.verify().map_err(|_| unavailable())?;
        let id = request.id.as_ref().ok_or_else(unavailable)?;
        id.validate().map_err(|_| unavailable())?;
        check_context(ctx)?;
        check_shape(params)?;
        let mut encoded = LimitedWriter::new(self.limits.request_bytes);
        serde_json::to_writer(&mut encoded, &(&request.method, params)).map_err(|_| unavailable())?;
        let fingerprint = sha256_bounded(&encoded.bytes, self.limits.request_bytes).map_err(|_| unavailable())?.into_bytes();
        let decoder = CoreRequest::decode(ProtocolEra::Modern2026, &request.method, Some(params))
            .map_err(|_| unavailable())?;
        let authority = (self.authorize)(ctx, request)?;
        check_context(ctx)?;
        if authority.lifetime.is_cancel_requested() { return Err(unavailable()); }
        let mut selector = LimitedWriter::new(self.limits.request_bytes + 256);
        selector.write_all(b"fastmcp/mrtr-terminal-slot/v1\0").map_err(|_| unavailable())?;
        selector.write_all(authority.key.as_bytes()).map_err(|_| unavailable())?;
        selector.write_all(authority.authorization.as_bytes()).map_err(|_| unavailable())?;
        serde_json::to_writer(&mut selector, &(&request.method, state)).map_err(|_| unavailable())?;
        let slot = sha256_bounded(&selector.bytes, self.limits.request_bytes + 256).map_err(|_| unavailable())?.into_bytes();
        let namespace = format!("mrtr-terminal:{}", hex(&slot));
        let binding = EnvelopeBinding::continuation(&authority.key, &authority.authorization, &namespace)
            .map_err(|_| unavailable())?;
        Ok(Some(Identity { slot, fingerprint, binding, lifetime: authority.lifetime, decoder }))
    }

    /// Reclaims only finished, expired/revoked replies. Uncertain dispatches
    /// remain fenced because neither expiry nor cancellation proves no effect.
    pub fn prune(&self, cx: &Cx) -> McpResult<usize> {
        cx.checkpoint().map_err(|_| unavailable())?;
        let mut state = self.lock()?;
        let now = Instant::now();
        let before = state.entries.len();
        let mut released = 0;
        state.entries.retain(|_, entry| {
            let remove = entry.result.is_some() && (now >= entry.expires_at || entry.lifetime.is_cancel_requested());
            if remove { released += entry.charge; }
            !remove
        });
        state.retained_bytes -= released;
        Ok(before - state.entries.len())
    }

    /// Rotates keys without invalidating unexpired retained replies.
    pub fn rotate(&self, cx: &Cx) -> McpResult<u64> {
        self.lock()?.protector.rotate(cx).map_err(|_| unavailable())
    }

    /// Irreversible shutdown. It does not cancel any application lifetime or
    /// authorize retrying uncertain work. Quiesce requests before replacing it.
    pub fn close(&self) -> McpResult<()> {
        let mut state = self.lock()?;
        state.closed = true;
        state.protector.close();
        state.entries.clear();
        state.retained_bytes = 0;
        Ok(())
    }
}

impl Middleware for ContinuationReplayMiddleware {
    fn on_request(&self, ctx: &McpContext, request: &JsonRpcRequest) -> McpResult<MiddlewareDecision> {
        let Some(identity) = self.identity(ctx, request)? else { return Ok(MiddlewareDecision::Continue); };
        let mut state = self.lock()?;
        check_context(ctx)?;
        if let Some(entry) = state.entries.get(&identity.slot) {
            check_entry(ctx, entry, &identity)?;
            let ciphertext = entry.result.as_ref().ok_or_else(unavailable)?;
            let opened = state.protector.open(ctx.cx(), &identity.binding, ciphertext).map_err(|_| unavailable())?;
            let result: Value = serde_json::from_slice(opened.as_bytes()).map_err(|_| unavailable())?;
            check_entry(ctx, entry, &identity)?;
            return Ok(MiddlewareDecision::Respond(result));
        }
        let charge = state.protector.maximum_envelope_bytes() + IDENTITY_BYTES;
        let retained = state.retained_bytes.checked_add(charge).filter(|bytes| *bytes <= self.limits.maximum_bytes)
            .ok_or_else(unavailable)?;
        if state.entries.len() >= self.limits.maximum_entries { return Err(unavailable()); }
        let expires_at = Instant::now().checked_add(self.limits.lifetime).ok_or_else(unavailable)?;
        if identity.lifetime.is_cancel_requested() { return Err(unavailable()); }
        state.entries.insert(identity.slot, Entry { fingerprint: identity.fingerprint,
            lifetime: identity.lifetime, expires_at, result: None, charge });
        state.retained_bytes = retained;
        Ok(MiddlewareDecision::Continue)
    }

    fn on_response(&self, ctx: &McpContext, request: &JsonRpcRequest, response: Value) -> McpResult<Value> {
        let Some(identity) = self.identity(ctx, request)? else { return Ok(response); };
        let mut state = self.lock()?;
        let entry = state.entries.get(&identity.slot).ok_or_else(unavailable)?;
        check_entry(ctx, entry, &identity)?;
        // The ordinary middleware stack runs this hook for short-circuited
        // replies too. Never reset lifetime, reseal, or grow state on a hit.
        if entry.result.is_some() { return Ok(response); }
        if response.get("resultType").and_then(Value::as_str) != Some("complete") {
            return Ok(response); // keep the uncertain fence, not a reusable successor
        }
        check_shape(&response)?;
        let mut encoded = LimitedWriter::new(self.limits.result_bytes);
        serde_json::to_writer(&mut encoded, &response).map_err(|_| unavailable())?;
        let text = std::str::from_utf8(&encoded.bytes).map_err(|_| unavailable())?;
        identity.decoder.decode_result(text).map_err(|_| unavailable())?;
        let lifetime = entry.expires_at.saturating_duration_since(Instant::now());
        let envelope = state.protector.seal(ctx.cx(), &identity.binding, &encoded.bytes, lifetime)
            .map_err(|_| unavailable())?;
        let entry = state.entries.get_mut(&identity.slot).ok_or_else(unavailable)?;
        check_entry(ctx, entry, &identity)?;
        let charge = envelope.len() + IDENTITY_BYTES;
        let released = entry.charge.checked_sub(charge).ok_or_else(unavailable)?;
        entry.charge = charge;
        entry.result = Some(envelope);
        state.retained_bytes -= released;
        Ok(response)
    }
    // Deliberately retain fences on errors. on_error can be called for a
    // rejected duplicate or even before on_request (authentication failures).
}
impl fmt::Debug for ContinuationReplayMiddleware {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContinuationReplayMiddleware").finish_non_exhaustive()
    }
}
fn unavailable() -> McpError { McpError::invalid_params("Continuation replay is unavailable") }
fn check_context(ctx: &McpContext) -> McpResult<()> {
    ctx.ensure_live()?;
    ctx.checkpoint().map_err(|_| unavailable())?;
    if ctx.budget().deadline.is_some_and(|deadline| ctx.cx().now() >= deadline) { return Err(unavailable()); }
    Ok(())
}
fn check_entry(ctx: &McpContext, entry: &Entry, identity: &Identity) -> McpResult<()> {
    check_context(ctx)?;
    if entry.fingerprint != identity.fingerprint || Instant::now() >= entry.expires_at
        || entry.lifetime.is_cancel_requested() || identity.lifetime.is_cancel_requested()
    { return Err(unavailable()); }
    Ok(())
}
fn hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes { out.push(char::from(HEX[usize::from(byte >> 4)])); out.push(char::from(HEX[usize::from(byte & 15)])); }
    out
}
fn check_shape(value: &Value) -> McpResult<()> {
    let mut stack = vec![(value, 0)];
    let mut nodes = 0;
    while let Some((value, depth)) = stack.pop() {
        nodes += 1;
        if nodes > MAX_NODES || depth > MAX_DEPTH { return Err(unavailable()); }
        match value {
            Value::Array(values) => {
                if nodes.saturating_add(stack.len()).saturating_add(values.len()) > MAX_NODES { return Err(unavailable()); }
                stack.extend(values.iter().map(|v| (v, depth + 1)));
            }
            Value::Object(values) => {
                if nodes.saturating_add(stack.len()).saturating_add(values.len()) > MAX_NODES { return Err(unavailable()); }
                stack.extend(values.values().map(|v| (v, depth + 1)));
            }
            _ => {},
        }
    }
    Ok(())
}
struct LimitedWriter { bytes: Zeroizing<Vec<u8>>, maximum: usize }
impl LimitedWriter {
    // Reserve the complete bound before plaintext enters the allocation: a
    // growing Vec could otherwise free an unwiped intermediate allocation.
    fn new(maximum: usize) -> Self {
        Self { bytes: Zeroizing::new(Vec::with_capacity(maximum)), maximum }
    }
}
impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("continuation replay byte limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

#[cfg(test)]
mod tests;
