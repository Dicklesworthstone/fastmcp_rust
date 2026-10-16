//! Complete catalog traversal under one explicit DPoP credential.
//!
//! Each continuation is a new, correlated core request, not a replay. The
//! original native/core/caller deadline and token lifetime span every page.
//! Assembly and cumulative limits are shared with managed bearer catalogs.
//! No discovery, credential renewal, cache grant or extension activation is
//! inferred from a successful list response.

use std::fmt;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{CoreRequest, CoreResult, RequestId, ServerNotification};
use serde_json::Value;

use super::{
    CoreDecoder, DpopCoreError, DpopCredential, DpopHttpClient, DpopHttpError,
    ManagedCoreError, ManagedCoreLimits, ModernHttpRequest, WaitBounds,
    admit_core_metadata, check_live, decode_response, prepare,
};
use super::stream::{DpopStreamError, DpopStreamLimits, Idle, PreparedStream};
use crate::http_auth::managed::client::CatalogCollector;
pub use crate::http_auth::managed::client::{
    CatalogCollection, CatalogError, CatalogLimits, ManagedCatalog,
};

/// Refusals contain no request metadata, cursor, proof, token or peer message.
#[derive(Debug)]
pub enum DpopCatalogError {
    /// Only a first-page request for one of the four core catalogs is allowed.
    InvalidRequest,
    /// Prefixes must be nonempty, bounded, printable local identifiers.
    InvalidIdPrefix,
    /// The local per-page request identity counter cannot advance.
    IdentityExhausted,
    /// The shared cumulative catalog bounds or page shape were refused.
    Catalog(CatalogError),
    /// Native credential, transport, correlation or typed core admission failed.
    Core(DpopCoreError),
    /// Streaming admission or the notification observer terminated traversal.
    Stream(DpopStreamError),
}

impl fmt::Display for DpopCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => f.write_str("DPoP catalog requires an initial core list request"),
            Self::InvalidIdPrefix => f.write_str("invalid DPoP catalog request identity prefix"),
            Self::IdentityExhausted => f.write_str("DPoP catalog request identities exhausted"),
            Self::Catalog(error) => error.fmt(f),
            Self::Core(error) => error.fmt(f),
            Self::Stream(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for DpopCatalogError {}

impl From<CatalogError> for DpopCatalogError {
    fn from(error: CatalogError) -> Self {
        Self::Catalog(error)
    }
}

impl From<DpopCoreError> for DpopCatalogError {
    fn from(error: DpopCoreError) -> Self {
        Self::Core(error)
    }
}

impl From<DpopHttpError> for DpopCatalogError {
    fn from(error: DpopHttpError) -> Self {
        Self::Core(error.into())
    }
}

impl From<ManagedCoreError> for DpopCatalogError {
    fn from(error: ManagedCoreError) -> Self {
        Self::Core(error.into())
    }
}

impl From<DpopStreamError> for DpopCatalogError {
    fn from(error: DpopStreamError) -> Self {
        match error {
            DpopStreamError::Core(error) => Self::Core(error),
            error => Self::Stream(error),
        }
    }
}

// No Clone, Debug, or serialization: partially collected entries and raw
// continuation tokens never escape the one operation that admitted them.
struct Traversal {
    method: String,
    params: Value,
    prefix: String,
    sequence: usize,
    complete: bool,
    limits: ManagedCoreLimits,
    native_limit: usize,
    collector: CatalogCollector,
}

impl Traversal {
    fn new(
        request: CoreRequest,
        prefix: &str,
        limits: ManagedCoreLimits,
        catalog_limits: CatalogLimits,
        native_limit: usize,
    ) -> Result<Self, DpopCatalogError> {
        if prefix.is_empty()
            || prefix.len() > 128
            || !prefix.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        {
            return Err(DpopCatalogError::InvalidIdPrefix);
        }
        let method = request.method().to_owned();
        // Validate the original typed era before rebuilding continuation
        // requests. Peer-shaped metadata cannot retag a legacy request.
        if request.era() != ProtocolEra::Modern2026
            || !matches!(
                method.as_str(),
                "tools/list" | "resources/list" | "resources/templates/list" | "prompts/list"
            )
        {
            return Err(DpopCatalogError::InvalidRequest);
        }
        let params = request
            .encode_params()
            .map_err(|_| DpopCatalogError::InvalidRequest)?
            .ok_or(DpopCatalogError::InvalidRequest)?;
        let object = params.as_object().ok_or(DpopCatalogError::InvalidRequest)?;
        // A caller-supplied continuation has no provenance under this operation's
        // credential. Start at the first page; only admitted responses may mint
        // a continuation. Even an empty supplied cursor is not an initial page.
        if object.contains_key("cursor") {
            return Err(DpopCatalogError::InvalidRequest);
        }
        admit_core_metadata(&params)?;
        let collector = CatalogCollector::new(&method, catalog_limits)?;
        Ok(Self {
            method,
            params,
            prefix: prefix.to_owned(),
            sequence: 0,
            complete: false,
            limits,
            native_limit,
            collector,
        })
    }

    fn next_request(
        &mut self,
        target: &str,
    ) -> Result<(ModernHttpRequest, CoreDecoder), DpopCatalogError> {
        self.next_request_with_usage(target, None)
    }

    fn next_request_with_usage(
        &mut self,
        target: &str,
        usage: Option<(usize, usize)>,
    ) -> Result<(ModernHttpRequest, CoreDecoder), DpopCatalogError> {
        if self.complete {
            return Err(DpopCatalogError::InvalidRequest);
        }
        let next = self.sequence.checked_add(1).ok_or(DpopCatalogError::IdentityExhausted)?;
        let id = RequestId::String(format!("{}.{}", self.prefix, self.sequence));
        let request = CoreRequest::decode(ProtocolEra::Modern2026, &self.method, Some(&self.params))
            .map_err(|_| DpopCatalogError::InvalidRequest)?;
        let (wire, mut decoder) = prepare(target, request, id, self.limits, self.native_limit)?;
        if let Some((bytes, notifications)) = usage {
            let charged = bytes.checked_add(wire.body().len())
                .ok_or(ManagedCoreError::RequestTooLarge)?;
            // A new page cannot reset stream accounting or spend the final
            // available byte sending a request with no room for any response.
            // Admit before advancing identity, signing, I/O or observer work.
            if charged >= self.limits.total_bytes() {
                return Err(ManagedCoreError::RequestTooLarge.into());
            }
            decoder.resume_usage(charged, notifications)?;
        }
        self.sequence = next;
        Ok((wire, decoder))
    }

    fn append(&mut self, page: CoreResult) -> Result<bool, DpopCatalogError> {
        let cursor = self.collector.append(page)?;
        if let Some(cursor) = cursor {
            // Change only the core cursor. Filters, final metadata, exact
            // method and endpoint remain frozen throughout the traversal.
            self.params
                .as_object_mut()
                .ok_or(DpopCatalogError::InvalidRequest)?
                .insert("cursor".to_owned(), Value::String(cursor));
        } else {
            self.complete = true;
        }
        Ok(self.complete)
    }

    fn finish(self) -> Result<CatalogCollection, DpopCatalogError> {
        Ok(self.collector.finish()?)
    }
}

impl DpopHttpClient {
    /// Collects every page of a typed core catalog under one credential.
    ///
    /// `request` must be an initial modern tools/list, resources/list,
    /// resources/templates/list or prompts/list request with final metadata
    /// and no cursor. Other parameters, including catalog filters, are retained.
    /// Nonempty extension offers remain unavailable on this core-only path.
    /// The returned variant matches the original method and preserves duplicate
    /// entries, empty pages, metadata, exact open siblings and per-page cache hints.
    /// It is not an atomic server snapshot or authority to cache the aggregate.
    ///
    /// Each POST has a new string ID derived from `id_prefix` and a fresh DPoP
    /// proof. Use a distinct prefix per logical operation in the endpoint's
    /// request namespace; the prefix is not an idempotency key. Prefixes accept
    /// 1..=128 ASCII alphanumeric, underscore, dot or dash bytes.
    ///
    /// `core_limits` applies to each individual page request/response. The
    /// earlier core/native timeout is frozen once for the ENTIRE traversal,
    /// further bounded by caller and original credential expiry. `catalog_limits`
    /// additionally bounds cumulative pages, entries and complete encoded result
    /// bytes, including metadata and open fields. Opaque repeated or empty peer
    /// cursors are followed until absence or a bound, never interpreted as EOF.
    ///
    /// JSON-only native transport, TLS/redirect policy, nonce validation and
    /// all revocation checks are unchanged. An HTTP/nonce challenge, invalid
    /// page, exhausted bound, cancellation or abandonment discards partial data.
    /// Nothing retries a page, refreshes a token, restarts a deadline, follows a
    /// peer URL, or returns a cursor reusable under a different credential.
    #[allow(clippy::too_many_arguments)]
    pub async fn collect_catalog(
        &mut self,
        cx: &Cx,
        credential: &DpopCredential,
        request: CoreRequest,
        id_prefix: &str,
        core_limits: ManagedCoreLimits,
        catalog_limits: CatalogLimits,
    ) -> Result<CatalogCollection, DpopCatalogError> {
        self.collect_catalog_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            credential,
            request,
            id_prefix,
            core_limits,
            catalog_limits,
        )
        .await
    }

    /// The supplied cancellation domain owns all pages but not sibling calls
    /// or the DPoP session. No remote mutation or cancellation POST is sent.
    #[allow(clippy::too_many_arguments)]
    pub async fn collect_catalog_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        request: CoreRequest,
        id_prefix: &str,
        core_limits: ManagedCoreLimits,
        catalog_limits: CatalogLimits,
    ) -> Result<CatalogCollection, DpopCatalogError> {
        let timeout = self.policy.timeout.min(core_limits.timeout());
        let bounds = WaitBounds::new(cx, timeout, credential)?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let prepared = Traversal::new(
            request, id_prefix, core_limits, catalog_limits, self.policy.max_body_bytes,
        );
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let mut traversal = prepared?;
        loop {
            let prepared = traversal.next_request(self.resource().as_str());
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            let (wire, mut decoder) = prepared?;
            let response = self
                .post_resource_with_bounds(cx, cancellation, credential, &wire, bounds)
                .await?;
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            let result = decode_response(&mut decoder, response)
                .map_err(DpopCatalogError::from)
                .and_then(|page| traversal.append(page));
            // Include decoding/accounting and their error arms in the original
            // lifetime, not just successful network reads. No page reset exists.
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            if result? {
                let result = traversal.finish();
                check_live(cx, cancellation, &self.session, credential, bounds)?;
                return result;
            }
        }
    }

    /// Collects a complete catalog over JSON or incremental SSE page responses.
    ///
    /// Admission, cursor custody, lossless page views and the initial-request
    /// requirements are identical to `collect_catalog`. Each page advertises
    /// both response types and runs through the existing native streaming reader.
    /// The observer receives only decoder-admitted core notifications. It must
    /// be brief and nonblocking; return false to stop the whole traversal.
    /// Observations already delivered cannot be recalled after a later failure.
    ///
    /// The original credential and absolute core/native/caller deadline span
    /// EVERY page. Stream core byte and notification limits are cumulative:
    /// outgoing request bodies and admitted response payloads share one budget.
    /// Catalog limits additionally bound retained pages, entries and complete
    /// result bytes. Native body and SSE parser limits apply per page. Each
    /// page's idle budget starts before preparation; valid progress can extend
    /// only that idle budget, never the original absolute deadline.
    ///
    /// A page is appended only after clean HTTP EOF. Duplicate results, a
    /// malformed trailing event, wrong correlation, observer failure, expiry,
    /// cancellation or abandonment discards the partial catalog without issuing
    /// its next page. No replay, refresh, redirect, implicit extension activation
    /// or background task is introduced. The JSON-only methods are unchanged.
    #[allow(clippy::too_many_arguments)]
    pub async fn collect_catalog_with_events<N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        request: CoreRequest,
        id_prefix: &str,
        stream_limits: DpopStreamLimits,
        catalog_limits: CatalogLimits,
        mut observer: N,
    ) -> Result<CatalogCollection, DpopCatalogError>
    where
        N: FnMut(&ServerNotification) -> bool,
    {
        let timeout = self.policy.timeout.min(stream_limits.core.timeout());
        let bounds = WaitBounds::new(cx, timeout, credential)?;
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let prepared = Traversal::new(
            request, id_prefix, stream_limits.core, catalog_limits, self.policy.max_body_bytes,
        );
        check_live(cx, cancellation, &self.session, credential, bounds)?;
        let mut traversal = prepared?;
        let mut usage = (0, 0);
        loop {
            let idle = Idle::new(cx.now(), stream_limits.idle);
            check_live(cx, cancellation, &self.session, credential, idle.bounds(bounds))?;
            let prepared = traversal.next_request_with_usage(self.resource().as_str(), Some(usage));
            check_live(cx, cancellation, &self.session, credential, idle.bounds(bounds))?;
            let (wire, decoder) = prepared?;
            let completed = self.execute_prepared_core_stream(
                cx, cancellation, credential,
                PreparedStream { wire, decoder, limits: stream_limits, bounds, idle },
                &mut observer,
            ).await?;
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            let result = traversal.append(completed.result);
            check_live(cx, cancellation, &self.session, credential, bounds)?;
            usage = completed.usage;
            if result? {
                let result = traversal.finish();
                check_live(cx, cancellation, &self.session, credential, bounds)?;
                return result;
            }
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "native-tls-roots"))]
#[path = "catalog/https_tests.rs"]
mod https_tests;

#[cfg(all(test, feature = "legacy-2024-11-05"))]
mod era_tests {
    use super::*;
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
    use serde_json::json;

    #[test]
    fn modern_looking_metadata_cannot_retag_a_legacy_typed_catalog() {
        for method in ["tools/list", "resources/list", "resources/templates/list", "prompts/list"] {
            let params = json!({"_meta": FinalRequestMeta::new(ClientCapabilities::default())});
            for era in [ProtocolEra::Legacy2024, ProtocolEra::Modern2026] {
                let request = CoreRequest::decode(era, method, Some(&params)).unwrap();
                assert_eq!(request.era(), era);
                let result = Traversal::new(
                    request, "era", ManagedCoreLimits::default(), CatalogLimits::default(), 8 * 1024 * 1024,
                );
                if era == ProtocolEra::Modern2026 {
                    assert!(result.is_ok());
                } else {
                    assert!(matches!(result, Err(DpopCatalogError::InvalidRequest)));
                }
            }
        }
    }
}

#[cfg(test)]
mod streaming_tests {
    use super::*;
    use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
    use crate::http_auth::rpc::ManagedCoreEvent;
    use serde_json::json;

    const TARGET: &str = "https://mcp.example/mcp";

    fn traversal() -> Traversal {
        let params = json!({
            "includeTags": ["selected"],
            "_meta": FinalRequestMeta::new(ClientCapabilities::default()),
        });
        Traversal::new(
            CoreRequest::decode(ProtocolEra::Modern2026, "tools/list", Some(&params)).unwrap(),
            "stream", ManagedCoreLimits::default(), CatalogLimits::default(), 8 * 1024 * 1024,
        ).unwrap()
    }

    fn response(wire: &ModernHttpRequest, cursor: Option<&str>) -> Vec<u8> {
        let request: Value = serde_json::from_slice(wire.body()).unwrap();
        let mut result = json!({
            "resultType": "complete", "tools": [], "ttlMs": 0, "cacheScope": "private",
        });
        if let Some(cursor) = cursor {
            result["nextCursor"] = json!(cursor);
        }
        serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": request["id"], "result": result})).unwrap()
    }

    #[test]
    fn streaming_pages_carry_usage_and_require_the_new_page_identity() {
        let mut walk = traversal();
        let (first, mut decoder) = walk.next_request_with_usage(TARGET, Some((0, 0))).unwrap();
        assert_eq!(decoder.usage(), (first.body().len(), 0));
        let bytes = response(&first, Some("opaque-雪%2F"));
        let ManagedCoreEvent::Result(result) = decoder.admit(&bytes, true).unwrap() else {
            panic!("expected the first catalog page");
        };
        assert!(!walk.append(*result).unwrap());
        let usage = decoder.usage();
        assert_eq!(usage, (first.body().len() + bytes.len(), 0));
        let (second, mut decoder) = walk.next_request_with_usage(TARGET, Some(usage)).unwrap();
        let sent: Value = serde_json::from_slice(second.body()).unwrap();
        assert_eq!(sent["id"], "stream.1");
        assert_eq!(sent["params"]["cursor"], "opaque-雪%2F");
        assert_eq!(sent["params"]["includeTags"], json!(["selected"]));
        assert_eq!(decoder.usage(), (usage.0 + second.body().len(), 0));
        let final_bytes = response(&second, None);
        let ManagedCoreEvent::Result(result) = decoder.admit(&final_bytes, true).unwrap() else {
            panic!("expected the terminal catalog page");
        };
        assert!(walk.append(*result).unwrap());
        let CatalogCollection::Tools(catalog) = walk.finish().unwrap() else {
            panic!("expected tools");
        };
        assert_eq!(catalog.page_count(), 2);
        assert_eq!(catalog.page_has_continuation(0), Some(true));
        assert_eq!(catalog.page_has_continuation(1), Some(false));

        // Change only correlation: a first-page response is not a second page.
        let mut walk = traversal();
        let (first, mut first_decoder) = walk.next_request_with_usage(TARGET, Some((0, 0))).unwrap();
        let bytes = response(&first, Some("opaque-雪%2F"));
        let ManagedCoreEvent::Result(result) = first_decoder.admit(&bytes, true).unwrap() else {
            panic!("expected the first page");
        };
        walk.append(*result).unwrap();
        let (_, mut second_decoder) = walk.next_request_with_usage(TARGET, Some(first_decoder.usage())).unwrap();
        assert!(second_decoder.admit(&response(&first, None), true).is_err());
        assert!(walk.finish().is_err());
    }

    #[test]
    fn streaming_response_byte_limit_is_cumulative_and_exact() {
        let (wire, _) = traversal().next_request_with_usage(TARGET, Some((0, 0))).unwrap();
        let bytes = response(&wire, None);
        let total = ManagedCoreLimits::default().total_bytes();
        let prior = total - wire.body().len() - bytes.len();
        for excess in [0, 1] {
            let mut walk = traversal();
            let (_, mut decoder) = walk.next_request_with_usage(TARGET, Some((prior + excess, 0))).unwrap();
            let result = decoder.admit(&bytes, true);
            if excess == 0 {
                let ManagedCoreEvent::Result(result) = result.unwrap() else {
                    panic!("expected an exact-boundary catalog result");
                };
                assert!(walk.append(*result).unwrap());
                assert!(walk.finish().is_ok());
                assert_eq!(decoder.usage().0, total);
            } else {
                assert!(matches!(result, Err(ManagedCoreError::ResponseByteLimit)));
                assert!(walk.finish().is_err());
            }
        }
    }

    #[test]
    fn streaming_request_budget_refusal_does_not_advance_cursor_or_identity() {
        let mut walk = traversal();
        let original = walk.params.clone();
        for bytes in [ManagedCoreLimits::default().total_bytes(), usize::MAX] {
            assert!(matches!(
                walk.next_request_with_usage(TARGET, Some((bytes, 0))),
                Err(DpopCatalogError::Core(DpopCoreError::Protocol(ManagedCoreError::RequestTooLarge))),
            ));
            assert_eq!(walk.sequence, 0);
            assert_eq!(walk.params, original);
        }
        let (wire, _) = walk.next_request_with_usage(TARGET, Some((0, 0))).unwrap();
        let sent: Value = serde_json::from_slice(wire.body()).unwrap();
        assert_eq!(sent["id"], "stream.0");
    }
}
