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
use fastmcp_protocol::{CoreRequest, CoreResult, RequestId};
use serde_json::Value;

use super::{
    CoreDecoder, DpopCoreError, DpopCredential, DpopHttpClient, DpopHttpError,
    ManagedCoreError, ManagedCoreLimits, ModernHttpRequest, WaitBounds,
    admit_core_metadata, check_live, decode_response, prepare,
};
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
}

impl fmt::Display for DpopCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => f.write_str("DPoP catalog requires an initial core list request"),
            Self::InvalidIdPrefix => f.write_str("invalid DPoP catalog request identity prefix"),
            Self::IdentityExhausted => f.write_str("DPoP catalog request identities exhausted"),
            Self::Catalog(error) => error.fmt(f),
            Self::Core(error) => error.fmt(f),
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
        if self.complete {
            return Err(DpopCatalogError::InvalidRequest);
        }
        let next = self.sequence.checked_add(1).ok_or(DpopCatalogError::IdentityExhausted)?;
        let id = RequestId::String(format!("{}.{}", self.prefix, self.sequence));
        let request = CoreRequest::decode(ProtocolEra::Modern2026, &self.method, Some(&self.params))
            .map_err(|_| DpopCatalogError::InvalidRequest)?;
        let prepared = prepare(target, request, id, self.limits, self.native_limit)?;
        self.sequence = next;
        Ok(prepared)
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
