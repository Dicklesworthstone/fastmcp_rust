//! Live, schema-bound tool handles owned by a caller-driven catalog watch.
//!
//! This composes the existing managed catalog collector/watcher and tool-call
//! owner. It creates no transport, runtime, reconnect loop or automatic tool
//! invocation. Catalog definitions and annotations never grant execution or
//! header-disclosure permission; the host still approves each invocation.
//!
//! Every snapshot has one shared invalidation flag. An observed tools change
//! retires all its handles before the host sees that notification. Replacement,
//! Stop, clean subscription completion, failure and dropping the watch future
//! also retire the current snapshot. Already-dispatched effects and delivered
//! results cannot be recalled. Invalidation fences subsequent admission and
//! publication and wakes pending tool requests, reads and continuations. Their
//! caller-owned futures release their resources on the next poll or Drop; no
//! cancellation is sent to the shared login or the caller's context.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{CoreRequest, CoreResult, FinalCoreResult, ServerNotification, SubscriptionFilter};
use fastmcp_protocol::protocol_policy::ProtocolEra;

use super::{ManagedOAuthSession, ManagedToolClient, ManagedToolError, ToolContract};
use crate::http_auth::rpc::catalog::{
    CollectedCatalog, ManagedCatalogClient, ManagedCatalogError, ManagedCatalogLimits,
};
use crate::http_auth::rpc::catalog::watch::{
    ManagedCatalogWatchControl, ManagedCatalogWatchError, ManagedCatalogWatchEvent,
    ManagedCatalogWatchLimits, ManagedCatalogWatchOutcome,
};
use fastmcp_protocol::RequestId;

/// Bounds for compiling a complete tool catalog, in addition to the existing
/// per-contract schema and whole-watch transport/collection bounds.
#[derive(Clone, Copy, Debug)]
pub struct ManagedToolCatalogLimits {
    catalog: ManagedCatalogLimits,
    watch: ManagedCatalogWatchLimits,
    maximum_tools: usize,
    maximum_definition_bytes: usize,
}

impl Default for ManagedToolCatalogLimits {
    fn default() -> Self {
        Self {
            catalog: ManagedCatalogLimits::default(),
            watch: ManagedCatalogWatchLimits::default(),
            maximum_tools: 256,
            maximum_definition_bytes: 4 * 1024 * 1024,
        }
    }
}

impl ManagedToolCatalogLimits {
    /// Definition bytes count the encoded definitions before they are cloned
    /// for schema compilation; this is not an estimate of allocator overhead.
    pub fn new(
        catalog: ManagedCatalogLimits,
        watch: ManagedCatalogWatchLimits,
        maximum_tools: usize,
        maximum_definition_bytes: usize,
    ) -> Result<Self, ManagedToolCatalogError> {
        if !(1..=1024).contains(&maximum_tools)
            || !(1..=8 * 1024 * 1024).contains(&maximum_definition_bytes)
        {
            return Err(ManagedToolCatalogError::InvalidLimits);
        }
        Ok(Self { catalog, watch, maximum_tools, maximum_definition_bytes })
    }
}

/// Fixed diagnostics retain no tool names, definitions, arguments or payloads.
#[derive(Debug)]
pub enum ManagedToolCatalogError {
    InvalidLimits,
    NotToolsList,
    InvalidSnapshot,
    ToolLimit,
    DefinitionBudget,
    DuplicateTool,
    Invalidated,
    AbortedByHost,
    Tool(ManagedToolError),
    Watch(ManagedCatalogWatchError),
}

impl fmt::Display for ManagedToolCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimits => "invalid managed tool catalog limits",
            Self::NotToolsList => "tool catalog watch requires modern tools/list",
            Self::InvalidSnapshot => "tool catalog snapshot contains an invalid page",
            Self::ToolLimit => "managed tool catalog tool limit exceeded",
            Self::DefinitionBudget => "managed tool catalog definition-byte limit exceeded",
            Self::DuplicateTool => "managed tool catalog contains a duplicate tool name",
            Self::Invalidated => "managed tool catalog snapshot has been invalidated",
            Self::AbortedByHost => "managed tool catalog stopped by the host",
            Self::Tool(error) => return fmt::Display::fmt(error, f),
            Self::Watch(error) => return fmt::Display::fmt(error, f),
        })
    }
}

impl std::error::Error for ManagedToolCatalogError {}

/// Notifications are delivered after the old tool handles have been retired.
pub enum ManagedToolCatalogEvent {
    Acknowledged { accepted_filter: SubscriptionFilter },
    Notification(Box<ServerNotification>),
    Snapshot(ManagedToolCatalogSnapshot),
}

type Contracts = BTreeMap<String, Arc<ToolContract>>;

struct Snapshot {
    session: ManagedOAuthSession,
    catalog: CollectedCatalog,
    contracts: Contracts,
    invalidated: Arc<AtomicBool>,
}

/// A complete observed catalog plus clients bound to the same managed login.
/// Clones share schemas and invalidation state, not independent validity.
/// Historical pages remain readable after invalidation, but their tool handles
/// cannot admit new calls or publish later results through the old contract.
#[derive(Clone)]
pub struct ManagedToolCatalogSnapshot(Arc<Snapshot>);

impl fmt::Debug for ManagedToolCatalogSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedToolCatalogSnapshot")
            .field("tool_count", &self.len())
            .field("invalidated", &self.is_invalidated())
            .finish_non_exhaustive()
    }
}

impl ManagedToolCatalogSnapshot {
    pub fn len(&self) -> usize { self.0.contracts.len() }
    pub fn is_empty(&self) -> bool { self.0.contracts.is_empty() }
    pub fn is_invalidated(&self) -> bool { self.0.invalidated.load(Ordering::Acquire) }
    pub fn catalog(&self) -> &CollectedCatalog { &self.0.catalog }
    pub fn names(&self) -> impl Iterator<Item = &str> { self.0.contracts.keys().map(String::as_str) }

    /// A case-sensitive lookup, not permission to execute. A change racing this
    /// lookup still fences the returned client's own request/result admission.
    /// Invalidating an individual client does not invalidate sibling tools.
    pub fn tool(&self, name: &str) -> Result<Option<ManagedToolClient>, ManagedToolCatalogError> {
        if self.is_invalidated() { return Err(ManagedToolCatalogError::Invalidated); }
        let client = self.0.contracts.get(name).map(|contract| ManagedToolClient {
            session: self.0.session.clone(),
            contract: Arc::clone(contract),
            header_review: None,
        });
        if self.is_invalidated() { return Err(ManagedToolCatalogError::Invalidated); }
        Ok(client)
    }
}

impl ManagedOAuthSession {
    /// Watches the complete tools catalog and publishes schema-checked clients.
    /// Subscription acknowledgment and full traversal precede publication. A
    /// duplicate name or one invalid definition refuses the entire replacement.
    /// No raw or partially admitted catalog becomes an executable tool set.
    ///
    /// Keep this host-owned future alive and polled while using its snapshots.
    /// Returning Stop invalidates even the snapshot just delivered. The observer
    /// is synchronous, runs without a catalog-cache lock, and must cooperate.
    /// Observed consistency is not server snapshot isolation or gap recovery.
    pub async fn watch_tool_catalog<I, O>(
        &self,
        cx: &Cx,
        request: CoreRequest,
        limits: ManagedToolCatalogLimits,
        next_id: I,
        observe: O,
    ) -> Result<ManagedCatalogWatchOutcome, ManagedToolCatalogError>
    where
        I: FnMut() -> Result<RequestId, ManagedCatalogError>,
        O: FnMut(ManagedToolCatalogEvent) -> Result<ManagedCatalogWatchControl, ManagedToolCatalogError>,
    {
        self.watch_tool_catalog_with_cancellation(
            cx, &McpRequestCancellation::new(), request, limits, next_id, observe,
        ).await
    }

    /// One cancellation domain covers the existing listen and catalog calls.
    /// No caller context or shared OAuth session is cancelled by local cleanup.
    #[allow(clippy::too_many_arguments)]
    pub async fn watch_tool_catalog_with_cancellation<I, O>(
        &self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        request: CoreRequest,
        limits: ManagedToolCatalogLimits,
        next_id: I,
        mut observe: O,
    ) -> Result<ManagedCatalogWatchOutcome, ManagedToolCatalogError>
    where
        I: FnMut() -> Result<RequestId, ManagedCatalogError>,
        O: FnMut(ManagedToolCatalogEvent) -> Result<ManagedCatalogWatchControl, ManagedToolCatalogError>,
    {
        if request.era() != ProtocolEra::Modern2026 || request.method() != "tools/list" {
            return Err(ManagedToolCatalogError::NotToolsList);
        }
        // The collector and every published tool share this exact session.
        // This wrapper cannot attach a foreign collector's definitions to it.
        let collector = ManagedCatalogClient::new(self.clone(), limits.catalog);
        let mut active = ActiveCatalog::default();
        let mut callback_error = None;
        let result = collector.watch_with_cancellation(
            cx, cancellation, request, limits.watch, next_id,
            |event| {
                let delivered = (|| {
                    let event = match event {
                        ManagedCatalogWatchEvent::Acknowledged { accepted_filter } => {
                            ManagedToolCatalogEvent::Acknowledged { accepted_filter }
                        }
                        ManagedCatalogWatchEvent::Notification(notification) => {
                            active.observe_notification(&notification);
                            ManagedToolCatalogEvent::Notification(notification)
                        }
                        ManagedCatalogWatchEvent::Snapshot(catalog) => {
                            // Retire first, including when replacement admission
                            // fails. Failed refresh must never restore old handles.
                            active.invalidate();
                            let (contracts, invalidated) = admit_contracts(catalog.pages(), limits)?;
                            active.install_contracts(Arc::clone(&invalidated), &contracts);
                            ManagedToolCatalogEvent::Snapshot(ManagedToolCatalogSnapshot(Arc::new(Snapshot {
                                session: self.clone(), catalog, contracts, invalidated,
                            })))
                        }
                    };
                    observe(event)
                })();
                match delivered {
                    Ok(control) => Ok(control),
                    Err(error) => {
                        callback_error = Some(error);
                        Err(ManagedCatalogError::AbortedByHost)
                    }
                }
            },
        ).await;
        // This same guard runs on future Drop and unwinding as well as ordinary
        // completion, including a clean subscription terminal without a change.
        drop(active);
        match callback_error {
            Some(error) => Err(error),
            None => result.map_err(ManagedToolCatalogError::Watch),
        }
    }
}

#[derive(Default)]
struct ActiveCatalog(Option<Arc<AtomicBool>>, Vec<McpRequestCancellation>);

impl ActiveCatalog {
    fn invalidate(&mut self) {
        if let Some(invalidated) = self.0.take() {
            // Publish group invalidity before waking any single tool. A waker
            // may immediately schedule another sibling's next poll.
            invalidated.store(true, Ordering::Release);
        }
        for signal in self.1.drain(..) { signal.cancel(); }
    }
    fn install(&mut self, invalidated: Arc<AtomicBool>) {
        self.invalidate();
        self.0 = Some(invalidated);
    }
    fn install_contracts(&mut self, invalidated: Arc<AtomicBool>, contracts: &Contracts) {
        self.install(invalidated);
        // The admitted catalog's hard tool-count bound also bounds this set.
        // Keep only wake signals, not schemas, pages, tool clients or sessions.
        self.1.extend(contracts.values().map(|contract| contract.invalidation.clone()));
    }
    fn observe_notification(&mut self, notification: &ServerNotification) {
        if matches!(notification, ServerNotification::ToolsListChanged(_)) { self.invalidate(); }
    }
}

impl Drop for ActiveCatalog {
    fn drop(&mut self) { self.invalidate(); }
}

fn admit_contracts(
    pages: &[CoreResult],
    limits: ManagedToolCatalogLimits,
) -> Result<(Contracts, Arc<AtomicBool>), ManagedToolCatalogError> {
    if pages.is_empty() { return Err(ManagedToolCatalogError::InvalidSnapshot); }
    let invalidated = Arc::new(AtomicBool::new(false));
    let mut contracts = BTreeMap::new();
    let mut bytes = DefinitionBytes { used: 0, maximum: limits.maximum_definition_bytes };
    for page in pages {
        let CoreResult::Final(FinalCoreResult::ToolsList { result, .. }) = page else {
            return Err(ManagedToolCatalogError::InvalidSnapshot);
        };
        for definition in &result.payload.tools {
            if contracts.len() >= limits.maximum_tools { return Err(ManagedToolCatalogError::ToolLimit); }
            // Bound retained source before cloning it for contract compilation.
            serde_json::to_writer(&mut bytes, definition).map_err(|_| ManagedToolCatalogError::DefinitionBudget)?;
            if contracts.contains_key(&definition.name) { return Err(ManagedToolCatalogError::DuplicateTool); }
            let mut contract = ToolContract::admit(definition.clone()).map_err(ManagedToolCatalogError::Tool)?;
            contract.catalog_invalidated = Some(Arc::clone(&invalidated));
            contracts.insert(contract.name.clone(), Arc::new(contract));
        }
    }
    Ok((contracts, invalidated))
}

struct DefinitionBytes { used: usize, maximum: usize }

impl Write for DefinitionBytes {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.maximum.saturating_sub(self.used) {
            return Err(io::Error::other("managed tool definition byte limit"));
        }
        self.used += buffer.len();
        Ok(buffer.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod wake_tests;
