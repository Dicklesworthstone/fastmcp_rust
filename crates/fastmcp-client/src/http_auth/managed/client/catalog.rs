//! Complete, bounded catalog traversal under one managed OAuth operation.
//!
//! Acquisition and discovery happen once. Every page uses that connection and
//! original credential; no mid-traversal refresh or failed-page replay occurs.
//! The managed operation owns the deadline, cancellation, and connection until
//! the entire catalog succeeds. Errors and abandonment discard partial entries.

use std::collections::HashSet;
use std::fmt;
use std::io::{self, Write};

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{
    CoreResult, FinalCoreResult, FinalPrompt, FinalResource, FinalResourceTemplate, FinalTool,
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
    /// `bytes` counts each page's serialized entry array and continuation token,
    /// including JSON escaping and framing, without retaining serialized copies.
    /// It is not a heap-size estimate. Native response/parser bounds still apply
    /// to each page, including result metadata that this collection discards.
    pub fn new(pages: usize, entries: usize, bytes: usize) -> Result<Self, CatalogError> {
        if !(1..=256).contains(&pages)
            || !(1..=16_384).contains(&entries)
            || !(1..=32 * 1024 * 1024).contains(&bytes)
        {
            return Err(CatalogError::InvalidLimits);
        }
        Ok(Self { pages, entries, bytes })
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
    CursorCycle,
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
            Self::CursorCycle => "managed catalog contains a continuation cycle",
            Self::UnexpectedResult => "managed catalog returned an unexpected result",
        })
    }
}

impl std::error::Error for CatalogError {}

/// Complete entries in peer page order, obtained under one credential lifetime.
///
/// This is NOT an atomic server snapshot or a cache entry. A peer can mutate its
/// catalog between pages. Per-page TTL/cache-scope/result metadata is deliberately
/// not combined; use the single-page APIs when that information is needed.
/// Duplicate entries remain entries, not silently overwritten identities. Raw
/// continuation tokens never escape this collection, including through Debug.
pub struct ManagedCatalog<T> {
    entries: Vec<T>,
    pages: usize,
}

impl<T> ManagedCatalog<T> {
    pub fn entries(&self) -> &[T] {
        &self.entries
    }

    pub fn into_entries(self) -> Vec<T> {
        self.entries
    }

    /// Includes empty pages and the terminal page.
    pub fn page_count(&self) -> usize {
        self.pages
    }
}

impl<T> fmt::Debug for ManagedCatalog<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedCatalog")
            .field("entries", &self.entries.len())
            .field("pages", &self.pages)
            .finish()
    }
}

pub(super) enum Collected {
    Tools(ManagedCatalog<FinalTool>),
    Resources(ManagedCatalog<FinalResource>),
    Templates(ManagedCatalog<FinalResourceTemplate>),
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
        self.list_all_tools_with_cancellation(cx, &McpRequestCancellation::new(), limits).await
    }

    /// Like `list_all_tools`, with cancellation isolated from the shared login.
    pub async fn list_all_tools_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        limits: CatalogLimits,
    ) -> Result<ManagedCatalog<FinalTool>, ManagedHttpClientError> {
        match self.perform_any(cx, cancellation, Call::Catalog(CatalogKind::Tools, limits))
            .await?.into_catalog()? {
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
        self.list_all_resources_with_cancellation(cx, &McpRequestCancellation::new(), limits).await
    }

    /// Lists all resources, discarding partial results on caller cancellation.
    pub async fn list_all_resources_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        limits: CatalogLimits,
    ) -> Result<ManagedCatalog<FinalResource>, ManagedHttpClientError> {
        match self.perform_any(cx, cancellation, Call::Catalog(CatalogKind::Resources, limits))
            .await?.into_catalog()? {
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
        self.list_all_resource_templates_with_cancellation(cx, &McpRequestCancellation::new(), limits)
            .await
    }

    /// Lists all templates with finite, request-local cancellation and limits.
    pub async fn list_all_resource_templates_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        limits: CatalogLimits,
    ) -> Result<ManagedCatalog<FinalResourceTemplate>, ManagedHttpClientError> {
        match self.perform_any(cx, cancellation, Call::Catalog(CatalogKind::Templates, limits))
            .await?.into_catalog()? {
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
        self.list_all_prompts_with_cancellation(cx, &McpRequestCancellation::new(), limits).await
    }

    /// Lists all prompts without cancelling sibling clients sharing this login.
    pub async fn list_all_prompts_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        limits: CatalogLimits,
    ) -> Result<ManagedCatalog<FinalPrompt>, ManagedHttpClientError> {
        match self.perform_any(cx, cancellation, Call::Catalog(CatalogKind::Prompts, limits))
            .await?.into_catalog()? {
            Collected::Prompts(catalog) => Ok(catalog),
            _ => Err(CatalogError::UnexpectedResult.into()),
        }
    }
}

// This alternate all-pages admission path retains the single-page ledger's
// 16 KiB per-token ceiling. The aggregate byte and page ceilings also bound
// the cycle index; no process-global cursor state or canonicalization is used.
const MAX_CURSOR_BYTES: usize = 16 * 1024;

struct Meter {
    limits: CatalogLimits,
    pages: usize,
    entries: usize,
    remaining_bytes: usize,
    seen: HashSet<String>,
}

impl Meter {
    fn new(limits: CatalogLimits) -> Self {
        Self {
            limits,
            pages: 0,
            entries: 0,
            remaining_bytes: limits.bytes,
            seen: HashSet::new(),
        }
    }

    // Called before entries or cursor copies enter the accumulated result.
    fn admit<T: Serialize>(&mut self, entries: &[T], cursor: Option<&str>) -> Result<(), CatalogError> {
        if self.pages >= self.limits.pages {
            return Err(CatalogError::PageLimit);
        }
        let count = self.entries.checked_add(entries.len()).ok_or(CatalogError::EntryLimit)?;
        if count > self.limits.entries {
            return Err(CatalogError::EntryLimit);
        }
        if let Some(cursor) = cursor {
            if cursor.len() > MAX_CURSOR_BYTES {
                return Err(CatalogError::CursorLimit);
            }
            if self.seen.contains(cursor) {
                return Err(CatalogError::CursorCycle);
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
        if let Some(cursor) = cursor {
            self.seen.insert(cursor.to_owned());
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
    Tools(Vec<FinalTool>),
    Resources(Vec<FinalResource>),
    Templates(Vec<FinalResourceTemplate>),
    Prompts(Vec<FinalPrompt>),
}

impl Entries {
    fn new(kind: CatalogKind) -> Self {
        match kind {
            CatalogKind::Tools => Self::Tools(Vec::new()),
            CatalogKind::Resources => Self::Resources(Vec::new()),
            CatalogKind::Templates => Self::Templates(Vec::new()),
            CatalogKind::Prompts => Self::Prompts(Vec::new()),
        }
    }

    fn append(&mut self, page: CoreResult, meter: &mut Meter) -> Result<Option<String>, CatalogError> {
        match (self, page) {
            (Self::Tools(entries), CoreResult::Final(FinalCoreResult::ToolsList { result, .. })) => {
                meter.admit(&result.payload.tools, result.payload.next_cursor.as_deref())?;
                entries.extend(result.payload.tools);
                Ok(result.payload.next_cursor)
            }
            (Self::Resources(entries), CoreResult::Final(FinalCoreResult::ResourcesList { result, .. })) => {
                meter.admit(&result.payload.resources, result.payload.next_cursor.as_deref())?;
                entries.extend(result.payload.resources);
                Ok(result.payload.next_cursor)
            }
            (Self::Templates(entries), CoreResult::Final(FinalCoreResult::ResourceTemplatesList { result, .. })) => {
                meter.admit(&result.payload.resource_templates, result.payload.next_cursor.as_deref())?;
                entries.extend(result.payload.resource_templates);
                Ok(result.payload.next_cursor)
            }
            (Self::Prompts(entries), CoreResult::Final(FinalCoreResult::PromptsList { result, .. })) => {
                meter.admit(&result.payload.prompts, result.payload.next_cursor.as_deref())?;
                entries.extend(result.payload.prompts);
                Ok(result.payload.next_cursor)
            }
            _ => Err(CatalogError::UnexpectedResult),
        }
    }

    fn finish(self, pages: usize) -> Collected {
        match self {
            Self::Tools(entries) => Collected::Tools(ManagedCatalog { entries, pages }),
            Self::Resources(entries) => Collected::Resources(ManagedCatalog { entries, pages }),
            Self::Templates(entries) => Collected::Templates(ManagedCatalog { entries, pages }),
            Self::Prompts(entries) => Collected::Prompts(ManagedCatalog { entries, pages }),
        }
    }
}

pub(super) async fn collect(
    cx: &Cx,
    boundary: &CallbackBoundary,
    client: &mut HttpClient,
    kind: CatalogKind,
    limits: CatalogLimits,
) -> Result<Collected, ManagedHttpClientError> {
    let mut entries = Entries::new(kind);
    let mut meter = Meter::new(limits);
    let mut cursor: Option<String> = None;
    loop {
        boundary.check(cx).map_err(|error| request_error(HttpClientError::CoreResult(error)))?;
        let page = match kind {
            CatalogKind::Tools => client.list_tools(cx, cursor.as_deref()).await,
            CatalogKind::Resources => client.list_resources(cx, cursor.as_deref()).await,
            CatalogKind::Templates => client.list_resource_templates(cx, cursor.as_deref()).await,
            CatalogKind::Prompts => client.list_prompts(cx, cursor.as_deref()).await,
        }.map_err(request_error)?;
        boundary.check(cx).map_err(|error| request_error(HttpClientError::CoreResult(error)))?;
        cursor = entries.append(page, &mut meter)?;
        // Even cached, immediately ready pages cannot replenish time or publish
        // after local revocation. The outer guard supplies wakeups while pending.
        boundary.check(cx).map_err(|error| request_error(HttpClientError::CoreResult(error)))?;
        if cursor.is_none() {
            return Ok(entries.finish(meter.pages));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn limits_reject_zero_and_overflow_instead_of_clamping() {
        assert!(CatalogLimits::new(256, 16_384, 32 * 1024 * 1024).is_ok());
        for (pages, entries, bytes) in [
            (0, 1, 1), (1, 0, 1), (1, 1, 0),
            (257, 1, 1), (1, 16_385, 1), (1, 1, 32 * 1024 * 1024 + 1),
            (usize::MAX, usize::MAX, usize::MAX),
        ] {
            assert_eq!(CatalogLimits::new(pages, entries, bytes), Err(CatalogError::InvalidLimits));
        }
    }

    #[test]
    fn cumulative_entry_limit_accepts_the_boundary_and_refuses_the_next_item() {
        let mut meter = Meter::new(CatalogLimits::new(3, 2, 4096).unwrap());
        meter.admit(&[json!(1)], Some("page-two")).unwrap();
        assert_eq!(meter.admit(&[json!(2), json!(3)], None), Err(CatalogError::EntryLimit));
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
        let last_bytes = serde_json::to_vec(&(&second[..], None::<&str>)).unwrap().len();
        for (budget, accepted) in [(first_bytes + last_bytes, true), (first_bytes + last_bytes - 1, false)] {
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
    fn opaque_empty_and_non_ascii_cursors_are_not_end_of_catalog() {
        for cursor in ["", "opaque-雪%2F", "private-cursor"] {
            let mut meter = Meter::new(CatalogLimits::default());
            meter.admit::<serde_json::Value>(&[], Some(cursor)).unwrap();
            assert_eq!(meter.admit::<serde_json::Value>(&[], Some(cursor)), Err(CatalogError::CursorCycle));
            assert_eq!(meter.pages, 1);
            meter.admit::<serde_json::Value>(&[], None).unwrap();
            assert_eq!(meter.pages, 2);
        }
    }

    #[test]
    fn a_longer_cursor_cycle_is_refused_before_another_request() {
        let mut meter = Meter::new(CatalogLimits::default());
        for cursor in ["a", "b", "c"] {
            meter.admit(&[json!(cursor)], Some(cursor)).unwrap();
        }
        assert_eq!(meter.admit(&[json!("not published")], Some("a")), Err(CatalogError::CursorCycle));
        assert_eq!(meter.entries, 3);
        assert_eq!(meter.pages, 3);
    }

    #[test]
    fn empty_pages_consume_page_budget_and_truncation_is_not_success() {
        for terminal in [false, true] {
            let mut meter = Meter::new(CatalogLimits::new(2, 1, 4096).unwrap());
            meter.admit::<serde_json::Value>(&[], Some("first")).unwrap();
            let result = meter.admit::<serde_json::Value>(&[], if terminal { None } else { Some("second") });
            assert_eq!(result.is_ok(), terminal);
            if !terminal {
                assert_eq!(result, Err(CatalogError::PageLimit));
            }
        }
    }

    #[test]
    fn oversized_cursor_is_not_copied_into_the_cycle_index() {
        let mut meter = Meter::new(CatalogLimits::default());
        assert_eq!(meter.admit::<serde_json::Value>(&[], Some(&"x".repeat(MAX_CURSOR_BYTES + 1))), Err(CatalogError::CursorLimit));
        assert!(meter.seen.is_empty());
        assert_eq!(meter.pages, 0);
        meter.admit::<serde_json::Value>(&[], Some(&"x".repeat(MAX_CURSOR_BYTES))).unwrap();
        assert_eq!(meter.seen.len(), 1);
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
        let catalog = ManagedCatalog { entries: vec!["private-catalog-entry"], pages: 2 };
        assert_eq!(catalog.entries(), &["private-catalog-entry"]);
        assert_eq!(catalog.page_count(), 2);
        assert!(!format!("{catalog:?}").contains("private-catalog-entry"));
        assert_eq!(catalog.into_entries(), vec!["private-catalog-entry"]);
    }
}
