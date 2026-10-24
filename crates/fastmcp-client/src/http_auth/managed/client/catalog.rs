//! Complete, bounded catalog traversal under one managed OAuth operation.
//!
//! Acquisition and discovery happen once. Every page uses that connection and
//! original credential; no mid-traversal refresh or failed-page replay occurs.
//! The managed operation owns the deadline, cancellation, and connection until
//! the entire catalog succeeds. Errors and abandonment discard partial entries.

use std::fmt;
use std::io::{self, Write};

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{
    CacheScope, CacheTtl, CompleteResult, CoreResult, FinalCoreResult, FinalListPromptsResult,
    FinalListResourceTemplatesResult, FinalListResourcesResult, FinalListToolsResult, FinalPrompt,
    FinalResource, FinalResourceTemplate, FinalTool, ResultMeta, ResultPeerDiagnostic,
    UnknownResultMembers,
};
use serde::Serialize;

use super::callbacks::CallbackBoundary;
use super::cursors::CatalogKind;
use super::{Call, CallResult, ManagedHttpClient, ManagedHttpClientError, request_error};
use crate::{HttpClient, HttpClientError};

/// Finite bounds for one complete catalog, independent of native page limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogLimits {
    pages: usize,
    entries: usize,
    bytes: usize,
}

impl Default for CatalogLimits {
    fn default() -> Self {
        Self {
            pages: 64,
            entries: 4096,
            bytes: 8 * 1024 * 1024,
        }
    }
}

impl CatalogLimits {
    /// Selects ceilings of at most 256 pages, 16,384 entries and 32 MiB.
    ///
    /// `bytes` counts the protocol codec's encoding of every complete result,
    /// including entries, cursor, cache hints, metadata and exact open siblings.
    /// It excludes the JSON-RPC envelope and is not a heap-size estimate. One
    /// bounded page is encoded temporarily for accounting, never retained as a
    /// second serialized copy. Native response/parser bounds still apply.
    pub fn new(pages: usize, entries: usize, bytes: usize) -> Result<Self, CatalogError> {
        if !(1..=256).contains(&pages)
            || !(1..=16_384).contains(&entries)
            || !(1..=32 * 1024 * 1024).contains(&bytes)
        {
            return Err(CatalogError::InvalidLimits);
        }
        Ok(Self {
            pages,
            entries,
            bytes,
        })
    }
}

/// Bounded traversal failures never retain a peer cursor, entry or diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogError {
    InvalidLimits,
    PageLimit,
    EntryLimit,
    ByteLimit,
    CursorLimit,
    UnexpectedResult,
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimits => "invalid managed catalog limits",
            Self::PageLimit => "managed catalog page limit exceeded",
            Self::EntryLimit => "managed catalog entry limit exceeded",
            Self::ByteLimit => "managed catalog encoded-byte limit exceeded",
            Self::CursorLimit => "managed catalog cursor limit exceeded",
            Self::UnexpectedResult => "managed catalog returned an unexpected result",
        })
    }
}

impl std::error::Error for CatalogError {}

// Metadata, open fields, cache hints and diagnostics move intact. The consumed
// cursor moves directly into the next request, never into a public page view.
// Ranges retain empty page boundaries without cloning catalog entries.
// Exhaustive payload destructuring makes new fields an integration obligation.
struct Page {
    entry_start: usize,
    entry_count: usize,
    has_continuation: bool,
    ttl_ms: CacheTtl,
    cache_scope: CacheScope,
    meta: ResultMeta,
    extras: UnknownResultMembers,
    diagnostic: Option<ResultPeerDiagnostic>,
}

/// Complete entries and per-page result details under one credential lifetime.
///
/// This is NOT an atomic server snapshot or a cache entry. A peer can mutate its
/// catalog between pages. Per-page cache hints, metadata, exact open siblings
/// and diagnostics remain available through per-page views in received order.
/// The collector never combines their cache authority. Consumed raw cursors
/// remain private; page views expose only whether a continuation was present.
/// Result fields are peer-controlled; apply a disclosure policy before logging.
/// Duplicate entries remain entries, not silently overwritten identities.
/// Debug prints only counts, never entries, metadata or continuation tokens.
/// Cursor equality conveys no progress or completion information: even a
/// repeated empty token is followed until absence or a configured limit.
pub struct ManagedCatalog<T> {
    entries: Vec<T>,
    pages: Vec<Page>,
}

impl<T> ManagedCatalog<T> {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            pages: Vec::new(),
        }
    }

    /// Borrow the flat entry view without discarding retained page results.
    pub fn entries(&self) -> &[T] {
        &self.entries
    }

    /// Explicitly select entries only, discarding page metadata and open fields.
    /// Inspect the per-page views before consuming when those fields are needed.
    pub fn into_entries(self) -> Vec<T> {
        self.entries
    }

    /// Includes empty pages and the terminal page.
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    /// Entries from one zero-based page, including a present empty slice for
    /// an empty page. No entry values are cloned or reordered for this view.
    pub fn page_entries(&self, index: usize) -> Option<&[T]> {
        let page = self.pages.get(index)?;
        self.entries
            .get(page.entry_start..page.entry_start + page.entry_count)
    }

    /// The page's original common result metadata, without a serde round-trip.
    pub fn page_metadata(&self, index: usize) -> Option<&ResultMeta> {
        self.pages.get(index).map(|page| &page.meta)
    }

    /// Inert open result siblings, preserving number lexemes and member order.
    /// Their names and values never become pagination or extension authority.
    pub fn page_extras(&self, index: usize) -> Option<&UnknownResultMembers> {
        self.pages.get(index).map(|page| &page.extras)
    }

    /// Exact per-page cache hints. These are not a TTL or scope for the combined
    /// catalog, which may have changed on the server between page requests.
    pub fn page_cache_hints(&self, index: usize) -> Option<(&CacheTtl, &CacheScope)> {
        self.pages
            .get(index)
            .map(|page| (&page.ttl_ms, &page.cache_scope))
    }

    /// A page's bounded peer diagnostic, when one was emitted by its decoder.
    pub fn page_diagnostic(&self, index: usize) -> Option<&ResultPeerDiagnostic> {
        self.pages.get(index).and_then(|page| page.diagnostic.as_ref())
    }

    /// Cursor presence only: no raw token or reusable pagination handle escapes.
    pub fn page_has_continuation(&self, index: usize) -> Option<bool> {
        self.pages.get(index).map(|page| page.has_continuation)
    }

    fn append_page(
        &mut self,
        entries: Vec<T>,
        mut page: Page,
        cursor: Option<String>,
        meter: &mut Meter,
        encoded_bytes: usize,
    ) -> Result<Option<String>, CatalogError>
    where
        T: Serialize,
    {
        // Stage all checks on a small counter copy. No retained entry, page,
        // cursor or accounting field changes after a refused page.
        let mut next = meter.clone();
        next.admit(&entries, cursor.as_deref())?;
        let entry_bytes = meter.remaining_bytes - next.remaining_bytes;
        let remaining_fields = encoded_bytes
            .checked_sub(entry_bytes)
            .ok_or(CatalogError::UnexpectedResult)?;
        next.remaining_bytes = next
            .remaining_bytes
            .checked_sub(remaining_fields)
            .ok_or(CatalogError::ByteLimit)?;
        if cursor.is_some() && next.remaining_bytes == 0 {
            return Err(CatalogError::ByteLimit);
        }
        page.entry_start = self.entries.len();
        self.entries.extend(entries);
        self.pages.push(page);
        *meter = next;
        Ok(cursor)
    }
}

impl<T> fmt::Debug for ManagedCatalog<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedCatalog")
            .field("entries", &self.entries.len())
            .field("pages", &self.pages.len())
            .finish()
    }
}

// The four list payloads share precisely these fields. No serde round-trip of
// ResultMeta or UnknownResultMembers is permitted for storage or public views.
macro_rules! catalog_result {
    ($entry:ty, $payload:ident, $field:ident) => {
        impl ManagedCatalog<$entry> {
            fn append(
                &mut self,
                result: CompleteResult<$payload>,
                diagnostic: Option<ResultPeerDiagnostic>,
                meter: &mut Meter,
                encoded_bytes: usize,
            ) -> Result<Option<String>, CatalogError> {
                let CompleteResult {
                    payload,
                    meta,
                    extras,
                } = result;
                let $payload {
                    $field,
                    next_cursor,
                    ttl_ms,
                    cache_scope,
                } = payload;
                let page = Page {
                    entry_start: 0,
                    entry_count: $field.len(),
                    has_continuation: next_cursor.is_some(),
                    ttl_ms,
                    cache_scope,
                    meta,
                    extras,
                    diagnostic,
                };
                self.append_page($field, page, next_cursor, meter, encoded_bytes)
            }
        }
    };
}

catalog_result!(FinalTool, FinalListToolsResult, tools);
catalog_result!(
    FinalResource,
    FinalListResourcesResult,
    resources
);
catalog_result!(
    FinalResourceTemplate,
    FinalListResourceTemplatesResult,
    resource_templates
);
catalog_result!(FinalPrompt, FinalListPromptsResult, prompts);

/// A complete catalog selected by its original list method.
///
/// Publicly exported as `CatalogCollection`. Both managed bearer and explicit
/// DPoP traversal retain the same typed entries, exact per-page metadata, cache
/// hints and open result siblings. This is not an atomic snapshot or cache grant.
/// Debug includes only the catalog kind and counts, never peer-controlled data.
#[derive(Debug)]
pub enum Collected {
    /// A complete tools/list traversal.
    Tools(ManagedCatalog<FinalTool>),
    /// A complete resources/list traversal.
    Resources(ManagedCatalog<FinalResource>),
    /// A complete resources/templates/list traversal.
    Templates(ManagedCatalog<FinalResourceTemplate>),
    /// A complete prompts/list traversal.
    Prompts(ManagedCatalog<FinalPrompt>),
}

impl CallResult {
    fn into_catalog(self) -> Result<Collected, ManagedHttpClientError> {
        match self {
            Self::Catalog(result) => result,
            _ => Err(CatalogError::UnexpectedResult.into()),
        }
    }
}

impl ManagedHttpClient {
    /// Lists the complete tool catalog under one acquisition and deadline.
    pub async fn list_all_tools(
        &mut self,
        cx: &Cx,
        limits: CatalogLimits,
    ) -> Result<ManagedCatalog<FinalTool>, ManagedHttpClientError> {
        self.list_all_tools_with_cancellation(cx, &McpRequestCancellation::new(), limits)
            .await
    }

    /// Like `list_all_tools`, with cancellation isolated from the shared login.
    pub async fn list_all_tools_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        limits: CatalogLimits,
    ) -> Result<ManagedCatalog<FinalTool>, ManagedHttpClientError> {
        match self
            .perform_any(cx, cancellation, Call::Catalog(CatalogKind::Tools, limits))
            .await?
            .into_catalog()?
        {
            Collected::Tools(catalog) => Ok(catalog),
            _ => Err(CatalogError::UnexpectedResult.into()),
        }
    }

    /// Lists all resources without restarting the timeout on each page.
    pub async fn list_all_resources(
        &mut self,
        cx: &Cx,
        limits: CatalogLimits,
    ) -> Result<ManagedCatalog<FinalResource>, ManagedHttpClientError> {
        self.list_all_resources_with_cancellation(cx, &McpRequestCancellation::new(), limits)
            .await
    }

    /// Lists all resources, discarding partial results on caller cancellation.
    pub async fn list_all_resources_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        limits: CatalogLimits,
    ) -> Result<ManagedCatalog<FinalResource>, ManagedHttpClientError> {
        match self
            .perform_any(
                cx,
                cancellation,
                Call::Catalog(CatalogKind::Resources, limits),
            )
            .await?
            .into_catalog()?
        {
            Collected::Resources(catalog) => Ok(catalog),
            _ => Err(CatalogError::UnexpectedResult.into()),
        }
    }

    /// Lists all resource templates using one credential generation.
    pub async fn list_all_resource_templates(
        &mut self,
        cx: &Cx,
        limits: CatalogLimits,
    ) -> Result<ManagedCatalog<FinalResourceTemplate>, ManagedHttpClientError> {
        self.list_all_resource_templates_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            limits,
        )
        .await
    }

    /// Lists all templates with finite, request-local cancellation and limits.
    pub async fn list_all_resource_templates_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        limits: CatalogLimits,
    ) -> Result<ManagedCatalog<FinalResourceTemplate>, ManagedHttpClientError> {
        match self
            .perform_any(
                cx,
                cancellation,
                Call::Catalog(CatalogKind::Templates, limits),
            )
            .await?
            .into_catalog()?
        {
            Collected::Templates(catalog) => Ok(catalog),
            _ => Err(CatalogError::UnexpectedResult.into()),
        }
    }

    /// Lists all prompts. A failed page is never retried or returned as success.
    pub async fn list_all_prompts(
        &mut self,
        cx: &Cx,
        limits: CatalogLimits,
    ) -> Result<ManagedCatalog<FinalPrompt>, ManagedHttpClientError> {
        self.list_all_prompts_with_cancellation(cx, &McpRequestCancellation::new(), limits)
            .await
    }

    /// Lists all prompts without cancelling sibling clients sharing this login.
    pub async fn list_all_prompts_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        limits: CatalogLimits,
    ) -> Result<ManagedCatalog<FinalPrompt>, ManagedHttpClientError> {
        match self
            .perform_any(
                cx,
                cancellation,
                Call::Catalog(CatalogKind::Prompts, limits),
            )
            .await?
            .into_catalog()?
        {
            Collected::Prompts(catalog) => Ok(catalog),
            _ => Err(CatalogError::UnexpectedResult.into()),
        }
    }
}

// This alternate all-pages admission path retains the single-page ledger's
// 16 KiB per-token ceiling. Termination is bounded by page/item/byte/deadline
// budgets, never by examining or comparing these opaque token contents.
const MAX_CURSOR_BYTES: usize = 16 * 1024;

#[derive(Clone)]
struct Meter {
    limits: CatalogLimits,
    pages: usize,
    entries: usize,
    remaining_bytes: usize,
}

impl Meter {
    fn new(limits: CatalogLimits) -> Self {
        Self {
            limits,
            pages: 0,
            entries: 0,
            remaining_bytes: limits.bytes,
        }
    }

    // First admit entries/cursor on a staged counter copy. append_page then
    // charges the rest of the complete result before publishing this copy.
    fn admit<T: Serialize>(
        &mut self,
        entries: &[T],
        cursor: Option<&str>,
    ) -> Result<(), CatalogError> {
        if self.pages >= self.limits.pages {
            return Err(CatalogError::PageLimit);
        }
        let count = self
            .entries
            .checked_add(entries.len())
            .ok_or(CatalogError::EntryLimit)?;
        if count > self.limits.entries {
            return Err(CatalogError::EntryLimit);
        }
        if let Some(cursor) = cursor {
            if cursor.len() > MAX_CURSOR_BYTES {
                return Err(CatalogError::CursorLimit);
            }
        }
        let mut writer = BudgetWriter {
            remaining: self.remaining_bytes,
            exhausted: false,
        };
        // Serialize to a counting sink, not to a second complete response buffer.
        if serde_json::to_writer(&mut writer, &(entries, cursor)).is_err() {
            return Err(if writer.exhausted {
                CatalogError::ByteLimit
            } else {
                CatalogError::UnexpectedResult
            });
        }
        if cursor.is_some() && self.pages + 1 == self.limits.pages {
            // An incomplete final allowed page is not a successful truncated list.
            // Refuse now rather than making a request we cannot admit.
            return Err(CatalogError::PageLimit);
        }
        self.pages += 1;
        self.entries = count;
        self.remaining_bytes = writer.remaining;
        Ok(())
    }
}

struct BudgetWriter {
    remaining: usize,
    exhausted: bool,
}

impl Write for BudgetWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(remaining) = self.remaining.checked_sub(bytes.len()) else {
            self.exhausted = true;
            return Err(io::ErrorKind::FileTooLarge.into());
        };
        self.remaining = remaining;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

enum Entries {
    Tools(ManagedCatalog<FinalTool>),
    Resources(ManagedCatalog<FinalResource>),
    Templates(ManagedCatalog<FinalResourceTemplate>),
    Prompts(ManagedCatalog<FinalPrompt>),
}

impl Entries {
    fn new(kind: CatalogKind) -> Self {
        match kind {
            CatalogKind::Tools => Self::Tools(ManagedCatalog::new()),
            CatalogKind::Resources => Self::Resources(ManagedCatalog::new()),
            CatalogKind::Templates => Self::Templates(ManagedCatalog::new()),
            CatalogKind::Prompts => Self::Prompts(ManagedCatalog::new()),
        }
    }

    fn append(
        &mut self,
        page: CoreResult,
        meter: &mut Meter,
    ) -> Result<Option<String>, CatalogError> {
        // Use the protocol encoder so exact number lexemes and metadata
        // presence are counted without a lossy serde_json::Value conversion.
        let encoded_bytes = page
            .encode()
            .map_err(|_| CatalogError::UnexpectedResult)?
            .len();
        match (self, page) {
            (
                Self::Tools(entries),
                CoreResult::Final(FinalCoreResult::ToolsList { result, diagnostic }),
            ) => {
                entries.append(result, diagnostic, meter, encoded_bytes)
            }
            (
                Self::Resources(entries),
                CoreResult::Final(FinalCoreResult::ResourcesList { result, diagnostic }),
            ) => {
                entries.append(result, diagnostic, meter, encoded_bytes)
            }
            (
                Self::Templates(entries),
                CoreResult::Final(FinalCoreResult::ResourceTemplatesList { result, diagnostic }),
            ) => {
                entries.append(result, diagnostic, meter, encoded_bytes)
            }
            (
                Self::Prompts(entries),
                CoreResult::Final(FinalCoreResult::PromptsList { result, diagnostic }),
            ) => {
                entries.append(result, diagnostic, meter, encoded_bytes)
            }
            _ => Err(CatalogError::UnexpectedResult),
        }
    }

    fn finish(self) -> Collected {
        match self {
            Self::Tools(catalog) => Collected::Tools(catalog),
            Self::Resources(catalog) => Collected::Resources(catalog),
            Self::Templates(catalog) => Collected::Templates(catalog),
            Self::Prompts(catalog) => Collected::Prompts(catalog),
        }
    }
}

/// Shared assembly, not transport or credential authority. Every consumer must
/// decode/correlate a page and enforce its original lifetime before appending.
/// A failed append retires all partial data; only cursor absence permits finish.
pub(crate) struct CatalogCollector {
    entries: Option<Entries>,
    meter: Meter,
    complete: bool,
}

impl CatalogCollector {
    pub(crate) fn new(method: &str, limits: CatalogLimits) -> Result<Self, CatalogError> {
        let kind = match method {
            "tools/list" => CatalogKind::Tools,
            "resources/list" => CatalogKind::Resources,
            "resources/templates/list" => CatalogKind::Templates,
            "prompts/list" => CatalogKind::Prompts,
            _ => return Err(CatalogError::UnexpectedResult),
        };
        Ok(Self::from_kind(kind, limits))
    }

    fn from_kind(kind: CatalogKind, limits: CatalogLimits) -> Self {
        Self {
            entries: Some(Entries::new(kind)),
            meter: Meter::new(limits),
            complete: false,
        }
    }

    pub(crate) fn append(&mut self, page: CoreResult) -> Result<Option<String>, CatalogError> {
        if self.complete {
            self.entries = None;
            return Err(CatalogError::UnexpectedResult);
        }
        let result = self
            .entries
            .as_mut()
            .ok_or(CatalogError::UnexpectedResult)?
            .append(page, &mut self.meter);
        match result {
            Ok(cursor) => {
                self.complete = cursor.is_none();
                Ok(cursor)
            }
            Err(error) => {
                self.entries = None;
                Err(error)
            }
        }
    }

    pub(crate) fn finish(self) -> Result<Collected, CatalogError> {
        if !self.complete {
            return Err(CatalogError::UnexpectedResult);
        }
        self.entries
            .map(Entries::finish)
            .ok_or(CatalogError::UnexpectedResult)
    }
}

pub(super) async fn collect(
    cx: &Cx,
    boundary: &CallbackBoundary,
    client: &mut HttpClient,
    kind: CatalogKind,
    limits: CatalogLimits,
) -> Result<Collected, ManagedHttpClientError> {
    let mut collector = CatalogCollector::from_kind(kind, limits);
    let mut cursor: Option<String> = None;
    loop {
        boundary
            .check(cx)
            .map_err(|error| request_error(HttpClientError::CoreResult(error)))?;
        let page = match kind {
            CatalogKind::Tools => client.list_tools(cx, cursor.as_deref()).await,
            CatalogKind::Resources => client.list_resources(cx, cursor.as_deref()).await,
            CatalogKind::Templates => client.list_resource_templates(cx, cursor.as_deref()).await,
            CatalogKind::Prompts => client.list_prompts(cx, cursor.as_deref()).await,
        }
        .map_err(request_error)?;
        boundary
            .check(cx)
            .map_err(|error| request_error(HttpClientError::CoreResult(error)))?;
        cursor = collector.append(page)?;
        // Even cached, immediately ready pages cannot replenish time or publish
        // after local revocation. The outer guard supplies wakeups while pending.
        boundary
            .check(cx)
            .map_err(|error| request_error(HttpClientError::CoreResult(error)))?;
        if cursor.is_none() {
            return Ok(collector.finish()?);
        }
    }
}

#[cfg(test)]
mod page_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn limits_reject_zero_and_overflow_instead_of_clamping() {
        assert!(CatalogLimits::new(256, 16_384, 32 * 1024 * 1024).is_ok());
        for (pages, entries, bytes) in [
            (0, 1, 1),
            (1, 0, 1),
            (1, 1, 0),
            (257, 1, 1),
            (1, 16_385, 1),
            (1, 1, 32 * 1024 * 1024 + 1),
            (usize::MAX, usize::MAX, usize::MAX),
        ] {
            assert_eq!(
                CatalogLimits::new(pages, entries, bytes),
                Err(CatalogError::InvalidLimits)
            );
        }
    }

    #[test]
    fn cumulative_entry_limit_accepts_the_boundary_and_refuses_the_next_item() {
        let mut meter = Meter::new(CatalogLimits::new(3, 2, 4096).unwrap());
        meter.admit(&[json!(1)], Some("page-two")).unwrap();
        assert_eq!(
            meter.admit(&[json!(2), json!(3)], None),
            Err(CatalogError::EntryLimit)
        );
        assert_eq!(meter.entries, 1);
        meter.admit(&[json!(2)], None).unwrap();
        assert_eq!(meter.entries, 2);
        assert_eq!(meter.pages, 2);
    }

    #[test]
    fn encoded_bytes_include_json_escaping_and_cumulative_cursor_storage() {
        let first = [json!({"quoted": "\"\\\n雪"})];
        let second = [json!("second")];
        let cursor = Some("private-\"-雪");
        let first_bytes = serde_json::to_vec(&(&first[..], cursor)).unwrap().len();
        let last_bytes = serde_json::to_vec(&(&second[..], None::<&str>))
            .unwrap()
            .len();
        for (budget, accepted) in [
            (first_bytes + last_bytes, true),
            (first_bytes + last_bytes - 1, false),
        ] {
            let mut meter = Meter::new(CatalogLimits::new(2, 2, budget).unwrap());
            meter.admit(&first, cursor).unwrap();
            let result = meter.admit(&second, None);
            assert_eq!(result.is_ok(), accepted);
            if accepted {
                assert_eq!(meter.remaining_bytes, 0);
            } else {
                assert_eq!(result, Err(CatalogError::ByteLimit));
                assert_eq!(meter.pages, 1);
            }
        }
    }

    #[test]
    fn repeated_empty_and_non_ascii_cursors_do_not_imply_completion_or_failure() {
        for cursor in ["", "opaque-雪%2F", "private-cursor", " \t\"\\\n "] {
            let mut meter = Meter::new(CatalogLimits::default());
            for page in 1..=3 {
                meter.admit::<serde_json::Value>(&[], Some(cursor)).unwrap();
                assert_eq!(meter.pages, page);
            }
            meter.admit::<serde_json::Value>(&[], None).unwrap();
            assert_eq!(meter.pages, 4);
        }
    }

    #[test]
    fn nonterminating_repeated_tokens_stop_at_page_limit_without_advancing_state() {
        for sequence in [["a", "a", "a", "a"], ["a", "b", "c", "a"], ["", "", "", ""]] {
            let mut meter = Meter::new(CatalogLimits::new(4, 4, 4096).unwrap());
            for cursor in &sequence[..3] {
                meter.admit(&[json!("duplicate entry")], Some(cursor)).unwrap();
            }
            let before = (meter.pages, meter.entries, meter.remaining_bytes);
            assert_eq!(
                meter.admit(&[json!("not published")], Some(sequence[3])),
                Err(CatalogError::PageLimit)
            );
            assert_eq!((meter.pages, meter.entries, meter.remaining_bytes), before);
            // The identical page is admissible when cursor absence actually
            // marks completion, including duplicate entry identities.
            meter.admit(&[json!("duplicate entry")], None).unwrap();
            assert_eq!((meter.pages, meter.entries), (4, 4));
        }
    }

    #[test]
    fn repeated_tokens_still_consume_every_encoded_byte() {
        let empty: &[serde_json::Value] = &[];
        let cursor = Some(" \"雪\\\n ");
        let page_bytes = serde_json::to_vec(&(empty, cursor)).unwrap().len();
        let terminal_bytes = serde_json::to_vec(&(empty, None::<&str>)).unwrap().len();
        let total = 3 * page_bytes + terminal_bytes;
        for exact in [false, true] {
            let limits = CatalogLimits::new(4, 1, total - usize::from(!exact)).unwrap();
            let mut meter = Meter::new(limits);
            for _ in 0..3 {
                meter.admit(empty, cursor).unwrap();
            }
            let before = (meter.pages, meter.entries, meter.remaining_bytes);
            let result = meter.admit(empty, None);
            if exact {
                result.unwrap();
                assert_eq!((meter.pages, meter.entries, meter.remaining_bytes), (4, 0, 0));
            } else {
                assert_eq!(result, Err(CatalogError::ByteLimit));
                assert_eq!((meter.pages, meter.entries, meter.remaining_bytes), before);
            }
        }
    }

    #[test]
    fn empty_pages_consume_page_budget_and_truncation_is_not_success() {
        for terminal in [false, true] {
            let mut meter = Meter::new(CatalogLimits::new(2, 1, 4096).unwrap());
            meter.admit::<serde_json::Value>(&[], Some("first")).unwrap();
            let result =
                meter.admit::<serde_json::Value>(&[], if terminal { None } else { Some("second") });
            assert_eq!(result.is_ok(), terminal);
            if !terminal {
                assert_eq!(result, Err(CatalogError::PageLimit));
            }
        }
    }

    #[test]
    fn oversized_cursor_is_refused_without_advancing_any_counter() {
        let mut meter = Meter::new(CatalogLimits::default());
        let before = (meter.pages, meter.entries, meter.remaining_bytes);
        assert_eq!(
            meter.admit::<serde_json::Value>(&[], Some(&"x".repeat(MAX_CURSOR_BYTES + 1))),
            Err(CatalogError::CursorLimit)
        );
        assert_eq!((meter.pages, meter.entries, meter.remaining_bytes), before);
        for _ in 0..2 {
            meter
                .admit::<serde_json::Value>(&[], Some(&"x".repeat(MAX_CURSOR_BYTES)))
                .unwrap();
        }
        assert_eq!(meter.pages, 2);
    }

    #[test]
    fn serialization_failure_is_not_misreported_as_a_byte_limit() {
        struct Invalid;
        impl Serialize for Invalid {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("private-diagnostic"))
            }
        }
        let mut meter = Meter::new(CatalogLimits::default());
        let error = meter.admit(&[Invalid], None).unwrap_err();
        assert_eq!(error, CatalogError::UnexpectedResult);
        assert_eq!(meter.pages, 0);
        assert!(!format!("{error:?} {error}").contains("private-diagnostic"));
    }

    #[test]
    fn collection_debug_does_not_expose_entries_or_tokens() {
        let mut catalog = ManagedCatalog::new();
        catalog.entries.push("private-catalog-entry");
        assert_eq!(catalog.entries(), &["private-catalog-entry"]);
        assert!(!format!("{catalog:?}").contains("private-catalog-entry"));
        assert_eq!(catalog.into_entries(), vec!["private-catalog-entry"]);
    }
}
