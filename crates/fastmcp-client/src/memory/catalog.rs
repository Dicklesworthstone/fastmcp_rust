//! Bounded catalog acquisition and complete-result replay on a Memory connection.

use std::pin::pin;

use asupersync::Cx;
use fastmcp_core::{McpError, McpErrorCode, McpRequestCancellation, McpResult};
use fastmcp_protocol::{
    CoreResult, ListPromptsParams, ListResourceTemplatesParams, ListResourcesParams, ListToolsParams,
};
use serde_json::Value;

use super::{MemoryClient, checkpoint, wait_turn};
use crate::cache::final_cache_hints;
use crate::{
    CollectedCatalog, FinalCachePageState, FinalCacheResultSet, PaginationBudget, catalog_page,
    list_catalog_wire_parameters,
};

impl MemoryClient {
    /// Lists one tools page with exact cursor and tag-filter parameters.
    ///
    /// The complete modern result retains its metadata, cache hints and open
    /// members. A fresh connection-local cache entry may satisfy this page;
    /// otherwise one request is sent. This method never follows its cursor.
    pub async fn list_tools_with_params(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        params: ListToolsParams,
    ) -> McpResult<CoreResult> {
        self.cached_core_request(
            cx,
            cancellation,
            "tools/list",
            list_catalog_wire_parameters(
                params.cursor.as_deref(),
                params.include_tags.as_ref(),
                params.exclude_tags.as_ref(),
            ),
            true,
        )
        .await
        .map(|(result, _)| result)
    }

    /// Lists one resource page, retaining all modern result fields.
    pub async fn list_resources(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        params: ListResourcesParams,
    ) -> McpResult<CoreResult> {
        self.cached_core_request(
            cx,
            cancellation,
            "resources/list",
            list_catalog_wire_parameters(
                params.cursor.as_deref(),
                params.include_tags.as_ref(),
                params.exclude_tags.as_ref(),
            ),
            true,
        )
        .await
        .map(|(result, _)| result)
    }

    /// Lists one resource-template page with the caller's exact filters.
    pub async fn list_resource_templates(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        params: ListResourceTemplatesParams,
    ) -> McpResult<CoreResult> {
        self.cached_core_request(
            cx,
            cancellation,
            "resources/templates/list",
            list_catalog_wire_parameters(
                params.cursor.as_deref(),
                params.include_tags.as_ref(),
                params.exclude_tags.as_ref(),
            ),
            true,
        )
        .await
        .map(|(result, _)| result)
    }

    /// Lists one prompt page without discarding metadata or open result members.
    pub async fn list_prompts(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        params: ListPromptsParams,
    ) -> McpResult<CoreResult> {
        self.cached_core_request(
            cx,
            cancellation,
            "prompts/list",
            list_catalog_wire_parameters(
                params.cursor.as_deref(),
                params.include_tags.as_ref(),
                params.exclude_tags.as_ref(),
            ),
            true,
        )
        .await
        .map(|(result, _)| result)
    }

    /// Collects every tools page within one caller-owned operation.
    ///
    /// The initial cursor must be absent. Every present peer cursor, including
    /// an empty or repeated value, is returned verbatim on the next request.
    /// All filters and locally configured client metadata survive each page.
    ///
    /// The shared catalog policy bounds the complete traversal, including any
    /// discarded rebuild pages, to 1,024 requests, 100,000 entries, 64 MiB of
    /// encoded results, 4 KiB cursors, and the earliest of five minutes, the
    /// configured absolute request timeout, or the caller deadline. This bound
    /// includes waiting for channel capacity. Cancellation or drop retires only
    /// the current page; unrelated request and subscription owners survive.
    ///
    /// An observed matching catalog change, changed cache scope, or rejected
    /// continuation cursor permits one cursorless rebuild. Events remain in
    /// their existing queues. A fresh terminal first page may satisfy the
    /// collection from this connection's complete-result cache. A cached
    /// prefix with a continuation cursor causes the same bounded cursorless
    /// rebuild; all remaining pages are freshly requested, so a fresh prefix
    /// cannot be combined with stale later pages. Each page retains its own
    /// cache hints, metadata and exact open members. No merged result,
    /// synthetic TTL or background listener is created. This local consistency
    /// policy does not promise a server snapshot. Failure returns no partial
    /// collection.
    pub async fn list_all_tools(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        params: ListToolsParams,
    ) -> McpResult<CollectedCatalog> {
        self.collect_catalog_with_budget(
            cx,
            cancellation,
            "tools/list",
            list_catalog_wire_parameters(
                params.cursor.as_deref(),
                params.include_tags.as_ref(),
                params.exclude_tags.as_ref(),
            ),
            PaginationBudget::for_request(self.timeout_policy),
        )
        .await
    }

    /// Collects all resource pages with the bounds and consistency policy of
    /// [`Self::list_all_tools`]. The initial cursor must be absent.
    pub async fn list_all_resources(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        params: ListResourcesParams,
    ) -> McpResult<CollectedCatalog> {
        self.collect_catalog_with_budget(
            cx,
            cancellation,
            "resources/list",
            list_catalog_wire_parameters(
                params.cursor.as_deref(),
                params.include_tags.as_ref(),
                params.exclude_tags.as_ref(),
            ),
            PaginationBudget::for_request(self.timeout_policy),
        )
        .await
    }

    /// Collects all resource-template pages within the same cumulative bounds
    /// as [`Self::list_all_tools`], preserving each complete result unchanged.
    pub async fn list_all_resource_templates(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        params: ListResourceTemplatesParams,
    ) -> McpResult<CollectedCatalog> {
        self.collect_catalog_with_budget(
            cx,
            cancellation,
            "resources/templates/list",
            list_catalog_wire_parameters(
                params.cursor.as_deref(),
                params.include_tags.as_ref(),
                params.exclude_tags.as_ref(),
            ),
            PaginationBudget::for_request(self.timeout_policy),
        )
        .await
    }

    /// Collects all prompt pages with the bounds and one-rebuild policy of
    /// [`Self::list_all_tools`]. No cursor contents are interpreted.
    pub async fn list_all_prompts(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        params: ListPromptsParams,
    ) -> McpResult<CollectedCatalog> {
        self.collect_catalog_with_budget(
            cx,
            cancellation,
            "prompts/list",
            list_catalog_wire_parameters(
                params.cursor.as_deref(),
                params.include_tags.as_ref(),
                params.exclude_tags.as_ref(),
            ),
            PaginationBudget::for_request(self.timeout_policy),
        )
        .await
    }

    async fn collect_catalog_with_budget(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: &'static str,
        parameters: Value,
        mut budget: PaginationBudget,
    ) -> McpResult<CollectedCatalog> {
        self.ensure_open()?;
        checkpoint(cx, cancellation)?;
        if parameters.get("cursor").is_some() {
            return Err(McpError::invalid_params(
                "Complete Memory catalog collection requires an absent initial cursor",
            ));
        }
        let result_set = match method {
            "tools/list" => FinalCacheResultSet::Tools,
            "resources/list" => FinalCacheResultSet::Resources,
            "resources/templates/list" => FinalCacheResultSet::ResourceTemplates,
            "prompts/list" => FinalCacheResultSet::Prompts,
            _ => return Err(McpError::invalid_params("Unknown Memory catalog method")),
        };
        let mut rebuilds = 0;
        'rebuild: loop {
            let mut pages = Vec::new();
            let mut item_count = 0;
            let mut cursor: Option<String> = None;
            let mut scope = None;
            let generation = self.subscriptions.catalog_generation(method);
            loop {
                checkpoint(cx, cancellation)?;
                budget.begin_page()?;
                let mut page_parameters = parameters.clone();
                if let Some(cursor) = &cursor {
                    page_parameters["cursor"] = Value::String(cursor.clone());
                }
                let page = self
                    .catalog_request_with_budget(cx, cancellation, method, page_parameters, &budget)
                    .await;
                let (result, cache_state) = match page {
                    Err(error)
                        if !self.closed
                            && cursor.is_some()
                            && error.code == McpErrorCode::InvalidParams
                            && rebuilds == 0 =>
                    {
                        checkpoint(cx, cancellation)?;
                        budget.check_deadline()?;
                        self.subscriptions
                            .final_result_cache
                            .invalidate_result_set(&result_set);
                        rebuilds += 1;
                        continue 'rebuild;
                    }
                    other => other?,
                };
                checkpoint(cx, cancellation)?;
                budget.check_deadline()?;
                let (page_items, next_cursor) = catalog_page(method, &result)?;
                budget.account_core_page(&result, page_items)?;
                let next_cursor = budget.admit_next_cursor(next_cursor)?;
                let page_scope = final_cache_hints(&result).map(|(_, scope)| scope);
                let changed_scope = scope.is_some_and(|previous| Some(previous) != page_scope);
                if let Some(page_scope) = page_scope {
                    scope.get_or_insert(page_scope);
                }
                let cache_changed = cache_state.is_some_and(|state| {
                    state.generation
                        != self
                            .subscriptions
                            .final_result_cache
                            .begin_fetch(&result_set)
                        || (state.miss.is_none() && next_cursor.is_some())
                });
                if changed_scope
                    || cache_changed
                    || self.subscriptions.catalog_generation(method) != generation
                {
                    self.subscriptions
                        .final_result_cache
                        .invalidate_result_set(&result_set);
                    if rebuilds != 0 {
                        return Err(McpError::invalid_request(
                            "Memory catalog changed during its bounded rebuild",
                        ));
                    }
                    rebuilds += 1;
                    continue 'rebuild;
                }
                item_count += page_items;
                pages.push(result);
                cursor = next_cursor;
                budget.check_deadline()?;
                if cursor.is_none() {
                    return Ok(CollectedCatalog {
                        method,
                        pages,
                        item_count,
                    });
                }
            }
        }
    }

    async fn catalog_request_with_budget(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        method: &str,
        parameters: Value,
        budget: &PaginationBudget,
    ) -> McpResult<(CoreResult, Option<FinalCachePageState>)> {
        // This future owns its page execution. Dropping it at the traversal
        // boundary either releases an unpublished reservation or retires that
        // exact committed request through the existing executor tombstone path.
        let mut request =
            pin!(
                self.cached_core_request(cx, cancellation, method, parameters, budget.pages == 1,)
            );
        loop {
            checkpoint(cx, cancellation)?;
            budget.check_deadline()?;
            match wait_turn(cx, cancellation, Some(budget.deadline), request.as_mut()).await {
                Ok(Some(result)) => {
                    // Preserve an already elected peer/transport failure. A
                    // successful late result cannot escape the outer budget.
                    let result = result?;
                    checkpoint(cx, cancellation)?;
                    budget.check_deadline()?;
                    return Ok(result);
                }
                Ok(None) => {}
                Err(error) => {
                    budget.check_deadline()?;
                    return Err(error);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    use std::time::{Duration, Instant};

    use asupersync::runtime::RuntimeBuilder;
    use fastmcp_protocol::{
        ClientInfo, JsonRpcError, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId,
        SubscriptionFilter,
    };
    use fastmcp_transport::memory::{MemoryTransport, create_memory_transport_pair_with_capacity};
    use serde_json::json;

    use super::*;
    use crate::memory::{MemoryRequestEvent, MemorySubscriptionEvent};
    use crate::{
        PAGINATION_BYTE_LIMIT_ERROR, PAGINATION_CURSOR_LIMIT_ERROR, PAGINATION_DEADLINE_ERROR,
        PAGINATION_ITEM_LIMIT_ERROR, PAGINATION_PAGE_LIMIT_ERROR, PaginationLimits,
    };

    const METHODS: [&str; 4] = [
        "tools/list",
        "resources/list",
        "resources/templates/list",
        "prompts/list",
    ];

    fn run<F: Future<Output = ()>>(test: impl FnOnce(Cx) -> F) {
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        runtime.block_on(async {
            let cx = Cx::current().unwrap();
            assert!(cx.blocking_pool_handle().is_none());
            asupersync::time::timeout(cx.now(), Duration::from_secs(8), test(cx))
                .await
                .expect("Memory catalogs must progress on the caller runtime");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    fn response(id: i64, result: Value) -> JsonRpcMessage {
        JsonRpcMessage::Response(JsonRpcResponse::success(RequestId::Number(id), result))
    }

    fn rejected_cursor(id: i64) -> JsonRpcMessage {
        JsonRpcMessage::Response(JsonRpcResponse::error(
            Some(RequestId::Number(id)),
            JsonRpcError {
                code: (-32602).into(),
                message: "cursor is no longer valid".into(),
                data: None,
            },
        ))
    }

    fn page(method: &str, name: Option<&str>, cursor: Option<&str>, scope: &str) -> Value {
        let (field, item) = match method {
            "tools/list" => ("tools", json!({"name":name,"inputSchema":{"type":"object"}})),
            "resources/list" => ("resources", json!({"name":name,"uri":"file:///catalog"})),
            "resources/templates/list" => (
                "resourceTemplates",
                json!({"name":name,"uriTemplate":"file:///{name}"}),
            ),
            "prompts/list" => ("prompts", json!({"name":name})),
            _ => unreachable!(),
        };
        let mut result = json!({
            "resultType":"complete", "ttlMs":0, "cacheScope":scope,
            "_meta":{"com.example/page":name},
            "vendorHints":{"nextCursor":"inert", "ttlMs":999},
        });
        result[field] = if name.is_some() { json!([item]) } else { json!([]) };
        if let Some(cursor) = cursor {
            result["nextCursor"] = json!(cursor);
        }
        for (key, exact) in [
            ("vendorDecimal", "7.30e-2"),
            ("vendorHuge", "18446744073709551617"),
        ] {
            result[key] = Value::Number(serde_json::Number::from_string_unchecked(exact.to_owned()));
        }
        result
    }

    async fn receive(
        cx: &Cx,
        peer: &mut MemoryTransport,
        method: &str,
        id: Option<i64>,
    ) -> JsonRpcRequest {
        let JsonRpcMessage::Request(request) = peer.recv_async(cx).await.unwrap() else {
            panic!("expected a Memory client request");
        };
        assert_eq!(request.method, method);
        assert_eq!(request.id, id.map(RequestId::Number));
        request
    }

    async fn connected(cx: &Cx) -> (MemoryClient, MemoryTransport) {
        let (transport, mut peer) = create_memory_transport_pair_with_capacity(1);
        peer.send_async(cx, &response(1, json!({
            "resultType":"complete", "supportedVersions":["2026-07-28"],
            "capabilities":{}, "ttlMs":0, "cacheScope":"private",
        }))).await.unwrap();
        let client = MemoryClient::builder(ClientInfo {
            name: "memory-catalog".into(), version: "7".into(),
        }).connect(cx, transport).await.unwrap();
        receive(cx, &mut peer, "server/discover", Some(1)).await;
        (client, peer)
    }

    fn assert_parameters(request: JsonRpcRequest, cursor: Option<&str>) {
        let parameters = request.params.unwrap();
        assert_eq!(parameters.get("cursor"), cursor.map(|value| json!(value)).as_ref());
        assert_eq!(parameters["includeTags"], json!(["visible", " visible "]));
        assert_eq!(parameters["excludeTags"], json!([]));
        assert_eq!(parameters["_meta"]["io.modelcontextprotocol/clientInfo"]["name"], "memory-catalog");
        assert_eq!(parameters["_meta"]["io.modelcontextprotocol/clientInfo"]["version"], "7");
    }

    async fn one_page(
        client: &mut MemoryClient,
        cx: &Cx,
        token: &McpRequestCancellation,
        method: &str,
        cursor: Option<String>,
    ) -> McpResult<CoreResult> {
        let include_tags = Some(vec!["visible".into(), " visible ".into()]);
        let exclude_tags = Some(Vec::new());
        macro_rules! call {
            ($params:ident, $method:ident) => {
                client.$method(cx, token, $params { cursor, include_tags, exclude_tags }).await
            };
        }
        match method {
            "tools/list" => call!(ListToolsParams, list_tools_with_params),
            "resources/list" => call!(ListResourcesParams, list_resources),
            "resources/templates/list" => call!(ListResourceTemplatesParams, list_resource_templates),
            "prompts/list" => call!(ListPromptsParams, list_prompts),
            _ => unreachable!(),
        }
    }

    async fn collect(
        client: &mut MemoryClient,
        cx: &Cx,
        token: &McpRequestCancellation,
        method: &str,
        cursor: Option<String>,
    ) -> McpResult<CollectedCatalog> {
        let include_tags = Some(vec!["visible".into(), " visible ".into()]);
        let exclude_tags = Some(Vec::new());
        macro_rules! call {
            ($params:ident, $method:ident) => {
                client.$method(cx, token, $params { cursor, include_tags, exclude_tags }).await
            };
        }
        match method {
            "tools/list" => call!(ListToolsParams, list_all_tools),
            "resources/list" => call!(ListResourcesParams, list_all_resources),
            "resources/templates/list" => call!(ListResourceTemplatesParams, list_all_resource_templates),
            "prompts/list" => call!(ListPromptsParams, list_all_prompts),
            _ => unreachable!(),
        }
    }

    fn fresh_page(method: &str, name: &str, cursor: Option<&str>) -> Value {
        let mut result = page(method, Some(name), cursor, "public");
        result["ttlMs"] = json!(60_000);
        result
    }

    fn page_name(result: &CoreResult) -> String {
        let value: Value = serde_json::from_str(&result.encode().unwrap()).unwrap();
        value["_meta"]["com.example/page"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn memory_cache_all_catalogs_replay_complete_results_on_the_exact_connection() {
        run(|cx| async move {
            for method in METHODS {
                let (mut client, mut peer) = connected(&cx).await;
                let token = McpRequestCancellation::new();
                peer.send_async(&cx, &response(2, fresh_page(method, "original", None)))
                    .await
                    .unwrap();
                let original = one_page(&mut client, &cx, &token, method, None)
                    .await
                    .unwrap();
                receive(&cx, &mut peer, method, Some(2)).await;
                let replay = one_page(&mut client, &cx, &token, method, None)
                    .await
                    .unwrap();
                let original_source = original.encode().unwrap();
                let replay_source = replay.encode().unwrap();
                assert!(replay_source.contains("7.30e-2"));
                assert!(replay_source.contains("18446744073709551617"));
                let mut original: Value = serde_json::from_str(&original_source).unwrap();
                let mut replay: Value = serde_json::from_str(&replay_source).unwrap();
                let ttl = replay.as_object_mut().unwrap().remove("ttlMs").unwrap();
                let original_ttl = original.as_object_mut().unwrap().remove("ttlMs").unwrap();
                assert!(ttl.as_u64().unwrap() <= original_ttl.as_u64().unwrap());
                assert_eq!(original, replay, "only the typed top-level TTL may age");
                let collected = collect(&mut client, &cx, &token, method, None)
                    .await
                    .unwrap();
                assert_eq!(collected.pages().len(), 1);
                assert_eq!(client.next_id, 3, "both replays must avoid publication");
                assert_eq!(client.final_result_cache_stats().hits, 2);
                assert_eq!(client.final_result_cache_stats().fills, 1);

                let (mut other, mut other_peer) = connected(&cx).await;
                other_peer
                    .send_async(&cx, &response(2, fresh_page(method, "other", None)))
                    .await
                    .unwrap();
                assert_eq!(
                    page_name(
                        &one_page(&mut other, &cx, &token, method, None)
                            .await
                            .unwrap()
                    ),
                    "other"
                );
                receive(&cx, &mut other_peer, method, Some(2)).await;
                assert_eq!(
                    other.final_result_cache_stats().hits,
                    0,
                    "public is still connection-private"
                );
                other.close(&cx).unwrap();
                client.close(&cx).unwrap();
                assert!(
                    one_page(&mut client, &cx, &token, method, None)
                        .await
                        .is_err()
                );
            }
        });
    }

    #[test]
    fn memory_cache_preserves_cursor_presence_filters_and_explicit_controls() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let token = McpRequestCancellation::new();
            for (id, cursor, name) in [
                (2, None, "absent"),
                (3, Some(""), "empty"),
                (4, Some("opaque"), "opaque"),
            ] {
                peer.send_async(&cx, &response(id, fresh_page("tools/list", name, None)))
                    .await
                    .unwrap();
                assert_eq!(
                    page_name(
                        &one_page(
                            &mut client,
                            &cx,
                            &token,
                            "tools/list",
                            cursor.map(str::to_owned)
                        )
                        .await
                        .unwrap()
                    ),
                    name
                );
                assert_parameters(
                    receive(&cx, &mut peer, "tools/list", Some(id)).await,
                    cursor,
                );
            }
            for (cursor, name) in [
                (None, "absent"),
                (Some(""), "empty"),
                (Some("opaque"), "opaque"),
            ] {
                assert_eq!(
                    page_name(
                        &one_page(
                            &mut client,
                            &cx,
                            &token,
                            "tools/list",
                            cursor.map(str::to_owned)
                        )
                        .await
                        .unwrap()
                    ),
                    name
                );
            }
            peer.send_async(
                &cx,
                &response(5, fresh_page("tools/list", "unfiltered", None)),
            )
            .await
            .unwrap();
            assert_eq!(
                page_name(&client.list_tools(&cx, &token, None).await.unwrap()),
                "unfiltered"
            );
            receive(&cx, &mut peer, "tools/list", Some(5)).await;
            assert_eq!(client.final_result_cache_stats().fills, 4);
            assert_eq!(client.final_result_cache_stats().hits, 3);

            client.set_final_result_cache_enabled(false);
            assert!(!client.final_result_cache_enabled());
            peer.send_async(
                &cx,
                &response(6, fresh_page("tools/list", "disabled", None)),
            )
            .await
            .unwrap();
            assert_eq!(
                page_name(&client.list_tools(&cx, &token, None).await.unwrap()),
                "disabled"
            );
            receive(&cx, &mut peer, "tools/list", Some(6)).await;
            assert_eq!(client.final_result_cache_stats().fills, 4);
            client.set_final_result_cache_enabled(true);
            assert_eq!(
                page_name(&client.list_tools(&cx, &token, None).await.unwrap()),
                "unfiltered"
            );
            client.clear_final_result_cache();
            peer.send_async(
                &cx,
                &response(7, fresh_page("tools/list", "after-clear", None)),
            )
            .await
            .unwrap();
            assert_eq!(
                page_name(&client.list_tools(&cx, &token, None).await.unwrap()),
                "after-clear"
            );
            receive(&cx, &mut peer, "tools/list", Some(7)).await;

            let stopped = McpRequestCancellation::new();
            stopped.cancel();
            assert_eq!(
                client
                    .list_tools(&cx, &stopped, None)
                    .await
                    .unwrap_err()
                    .code,
                McpErrorCode::RequestCancelled
            );
            assert_eq!(client.next_id, 8);
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_cache_ready_invalidation_precedes_hits_and_preserves_listener_events() {
        run(|cx| async move {
            for owned in [false, true] {
                let (mut client, mut peer) = connected(&cx).await;
                let token = McpRequestCancellation::new();
                let mut listener = if owned {
                    let mut listener = client
                        .subscribe(
                            &cx,
                            &token,
                            SubscriptionFilter {
                                tools_list_changed: Some(true),
                                ..SubscriptionFilter::default()
                            },
                        )
                        .await
                        .unwrap();
                    receive(&cx, &mut peer, "subscriptions/listen", Some(2)).await;
                    peer.send_async(
                        &cx,
                        &JsonRpcMessage::Request(JsonRpcRequest::notification(
                            "notifications/subscriptions/acknowledged",
                            Some(json!({
                                "notifications":{"toolsListChanged":true},
                                "_meta":{"io.modelcontextprotocol/subscriptionId":2},
                            })),
                        )),
                    )
                    .await
                    .unwrap();
                    assert!(matches!(
                        client
                            .next_subscription_event(&cx, &token, &mut listener)
                            .await
                            .unwrap(),
                        Some(MemorySubscriptionEvent::Acknowledged { .. })
                    ));
                    Some(listener)
                } else {
                    None
                };
                let first_id = client.next_id;
                peer.send_async(
                    &cx,
                    &response(first_id, fresh_page("tools/list", "before", None)),
                )
                .await
                .unwrap();
                client.list_tools(&cx, &token, None).await.unwrap();
                receive(&cx, &mut peer, "tools/list", Some(first_id)).await;
                peer.send_async(
                    &cx,
                    &catalog_notification("notifications/tools/list_changed", owned.then_some(2)),
                )
                .await
                .unwrap();
                let mut serving = cx
                    .spawn(move |peer_cx| async move {
                        receive(&peer_cx, &mut peer, "tools/list", Some(first_id + 1)).await;
                        peer.send_async(
                            &peer_cx,
                            &response(first_id + 1, fresh_page("tools/list", "after", None)),
                        )
                        .await
                        .unwrap();
                        peer
                    })
                    .unwrap();
                assert_eq!(
                    page_name(&client.list_tools(&cx, &token, None).await.unwrap()),
                    "after"
                );
                assert_eq!(
                    client.final_result_cache_stats().hits,
                    0,
                    "invalidated candidates are not reported as hits"
                );
                assert_eq!(client.final_result_cache_stats().invalidations, 1);
                if let Some(listener) = &mut listener {
                    assert!(matches!(
                        client
                            .next_subscription_event(&cx, &token, listener)
                            .await
                            .unwrap(),
                        Some(MemorySubscriptionEvent::Notification(_))
                    ));
                    assert!(client.take_server_notifications().is_empty());
                } else {
                    assert_eq!(client.take_server_notifications().len(), 1);
                }
                let _peer = serving.join(&cx).await.unwrap();
                client.close(&cx).unwrap();
            }
        });
    }

    #[test]
    fn memory_cache_invalidation_during_fetch_prevents_repopulation() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let mut serving = cx
                .spawn(move |peer_cx| async move {
                    receive(&peer_cx, &mut peer, "tools/list", Some(2)).await;
                    peer.send_async(
                        &peer_cx,
                        &catalog_notification("notifications/tools/list_changed", None),
                    )
                    .await
                    .unwrap();
                    peer.send_async(
                        &peer_cx,
                        &response(2, fresh_page("tools/list", "racing", None)),
                    )
                    .await
                    .unwrap();
                    receive(&peer_cx, &mut peer, "tools/list", Some(3)).await;
                    peer.send_async(
                        &peer_cx,
                        &response(3, fresh_page("tools/list", "current", None)),
                    )
                    .await
                    .unwrap();
                    peer
                })
                .unwrap();
            let token = McpRequestCancellation::new();
            assert_eq!(
                page_name(&client.list_tools(&cx, &token, None).await.unwrap()),
                "racing"
            );
            assert_eq!(client.final_result_cache_stats().fills, 0);
            assert_eq!(
                page_name(&client.list_tools(&cx, &token, None).await.unwrap()),
                "current"
            );
            assert_eq!(client.final_result_cache_stats().fills, 1);
            assert_eq!(client.final_result_cache_stats().hits, 0);
            let _peer = serving.join(&cx).await.unwrap();
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_cache_drains_sibling_responses_without_stealing_their_ownership() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let token = McpRequestCancellation::new();
            peer.send_async(&cx, &response(2, fresh_page("tools/list", "cached", None)))
                .await
                .unwrap();
            client.list_tools(&cx, &token, None).await.unwrap();
            receive(&cx, &mut peer, "tools/list", Some(2)).await;
            let mut sibling = client
                .execute_core(&cx, &token, "prompts/get", json!({"name":"other"}))
                .await
                .unwrap();
            receive(&cx, &mut peer, "prompts/get", Some(3)).await;
            peer.send_async(
                &cx,
                &response(3, json!({"resultType":"complete","messages":[]})),
            )
            .await
            .unwrap();
            assert_eq!(
                page_name(&client.list_tools(&cx, &token, None).await.unwrap()),
                "cached"
            );
            assert_eq!(client.next_id, 4);
            assert!(matches!(
                client.next_event(&cx, &token, &mut sibling).await.unwrap(),
                Some(MemoryRequestEvent::Result(_))
            ));
            assert!(
                client
                    .next_event(&cx, &token, &mut sibling)
                    .await
                    .unwrap()
                    .is_none()
            );
            peer.send_async(
                &cx,
                &catalog_notification("notifications/tools/list_changed", Some(999)),
            )
            .await
            .unwrap();
            assert_eq!(
                page_name(&client.list_tools(&cx, &token, None).await.unwrap()),
                "cached"
            );
            assert_eq!(
                client.final_result_cache_stats().invalidations,
                0,
                "a foreign listener cannot invalidate this cache"
            );
            assert_eq!(client.final_result_cache_stats().hits, 2);
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_cache_full_catalog_rebuilds_cached_prefix_instead_of_mixing_pages() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let token = McpRequestCancellation::new();
            peer.send_async(
                &cx,
                &response(2, fresh_page("tools/list", "old-head", Some("old"))),
            )
            .await
            .unwrap();
            one_page(&mut client, &cx, &token, "tools/list", None)
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/list", Some(2)).await;
            peer.send_async(
                &cx,
                &response(3, fresh_page("tools/list", "old-tail", None)),
            )
            .await
            .unwrap();
            one_page(&mut client, &cx, &token, "tools/list", Some("old".into()))
                .await
                .unwrap();
            receive(&cx, &mut peer, "tools/list", Some(3)).await;
            let mut serving = cx
                .spawn(move |peer_cx| async move {
                    assert_parameters(
                        receive(&peer_cx, &mut peer, "tools/list", Some(4)).await,
                        None,
                    );
                    peer.send_async(
                        &peer_cx,
                        &response(4, fresh_page("tools/list", "new-head", Some("new"))),
                    )
                    .await
                    .unwrap();
                    assert_parameters(
                        receive(&peer_cx, &mut peer, "tools/list", Some(5)).await,
                        Some("new"),
                    );
                    peer.send_async(
                        &peer_cx,
                        &response(5, fresh_page("tools/list", "new-tail", None)),
                    )
                    .await
                    .unwrap();
                    peer
                })
                .unwrap();
            let result = collect(&mut client, &cx, &token, "tools/list", None)
                .await
                .unwrap();
            assert_eq!(
                result.pages().iter().map(page_name).collect::<Vec<_>>(),
                ["new-head", "new-tail"]
            );
            assert_eq!(client.final_result_cache_stats().invalidations, 1);
            assert_eq!(client.next_id, 6);
            let _peer = serving.join(&cx).await.unwrap();
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_cache_zero_missing_negative_and_expired_ttl_never_replay() {
        run(|cx| async move {
            for ttl in [None, Some(-1), Some(0), Some(1)] {
                let (mut client, mut peer) = connected(&cx).await;
                let token = McpRequestCancellation::new();
                let mut first = fresh_page("tools/list", "expired", None);
                if let Some(ttl) = ttl {
                    first["ttlMs"] = json!(ttl);
                } else {
                    first.as_object_mut().unwrap().remove("ttlMs");
                }
                peer.send_async(&cx, &response(2, first)).await.unwrap();
                client.list_tools(&cx, &token, None).await.unwrap();
                receive(&cx, &mut peer, "tools/list", Some(2)).await;
                if ttl == Some(1) {
                    asupersync::time::sleep(cx.now(), Duration::from_millis(20)).await;
                }
                peer.send_async(&cx, &response(3, fresh_page("tools/list", "fresh", None)))
                    .await
                    .unwrap();
                assert_eq!(
                    page_name(&client.list_tools(&cx, &token, None).await.unwrap()),
                    "fresh"
                );
                receive(&cx, &mut peer, "tools/list", Some(3)).await;
                assert_eq!(client.final_result_cache_stats().hits, 0);
                if matches!(ttl, None | Some(-1)) {
                    assert_eq!(client.take_cache_ttl_diagnostics().len(), 1);
                }
                if ttl == Some(1) {
                    assert_eq!(client.final_result_cache_stats().stale, 1);
                }
                client.close(&cx).unwrap();
            }
        });
    }

    async fn ordinary_survives(cx: &Cx, client: &mut MemoryClient, peer: &mut MemoryTransport) {
        let token = McpRequestCancellation::new();
        let id = client.next_id;
        peer.send_async(cx, &response(id, page("tools/list", Some("healthy"), None, "private")))
            .await.unwrap();
        let result = client.list_tools(cx, &token, None).await.unwrap();
        receive(cx, peer, "tools/list", Some(id)).await;
        assert_eq!(catalog_page("tools/list", &result).unwrap(), (1, None));
    }

    #[test]
    fn memory_catalog_typed_pages_preserve_parameters_and_complete_results() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let token = McpRequestCancellation::new();
            for (index, method) in METHODS.into_iter().enumerate() {
                let expected = page(method, Some("one"), Some("next"), "private");
                peer.send_async(&cx, &response(index as i64 + 2, expected.clone())).await.unwrap();
                let result = one_page(&mut client, &cx, &token, method, Some("".into())).await.unwrap();
                assert_parameters(receive(&cx, &mut peer, method, Some(index as i64 + 2)).await, Some(""));
                assert_eq!(serde_json::from_str::<Value>(&result.encode().unwrap()).unwrap(), expected);
                assert_eq!(catalog_page(method, &result).unwrap(), (1, Some("next".into())));
            }
            assert_eq!(client.next_id, 6, "one-page APIs never follow nextCursor");
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_catalog_all_families_follow_empty_and_repeated_opaque_cursors() {
        run(|cx| async move {
            for method in METHODS {
                let (mut client, mut peer) = connected(&cx).await;
                let mut server = cx.spawn(move |peer_cx| async move {
                    for (index, (cursor, next_cursor, name)) in [
                        (None, Some(""), None),
                        (Some(""), Some(" opaque "), Some("first")),
                        (Some(" opaque "), Some(" opaque "), None),
                        (Some(" opaque "), None, Some("last")),
                    ].into_iter().enumerate() {
                        let id = index as i64 + 2;
                        assert_parameters(receive(&peer_cx, &mut peer, method, Some(id)).await, cursor);
                        peer.send_async(&peer_cx, &response(id, page(method, name, next_cursor, "private")))
                            .await.unwrap();
                    }
                    peer
                }).unwrap();
                let collection = collect(&mut client, &cx, &McpRequestCancellation::new(), method, None)
                    .await.unwrap();
                assert_eq!(collection.method(), method);
                assert_eq!(collection.item_count(), 2);
                assert_eq!(collection.pages().len(), 4);
                for page in collection.pages() {
                    let encoded = page.encode().unwrap();
                    assert!(encoded.contains("7.30e-2"));
                    assert!(encoded.contains("18446744073709551617"));
                    let parsed: Value = serde_json::from_str(&encoded).unwrap();
                    assert_eq!(parsed["ttlMs"], 0);
                    assert_eq!(parsed["vendorHints"]["nextCursor"], "inert");
                    assert!(parsed.get("_meta").is_some());
                }
                assert_eq!(client.next_id, 6);
                let mut peer = server.join(&cx).await.unwrap();
                ordinary_survives(&cx, &mut client, &mut peer).await;
                client.close(&cx).unwrap();
            }
        });
    }

    #[test]
    fn memory_catalog_refuses_initial_cursor_and_does_not_retry_first_page_error() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let token = McpRequestCancellation::new();
            for method in METHODS {
                for cursor in ["", "opaque"] {
                    let error = collect(&mut client, &cx, &token, method, Some(cursor.into()))
                        .await.unwrap_err();
                    assert_eq!(error.code, McpErrorCode::InvalidParams);
                    assert_eq!(client.next_id, 2);
                    assert!(client.executor.pending_records().is_empty());
                }
            }
            peer.send_async(&cx, &rejected_cursor(2)).await.unwrap();
            let error = collect(&mut client, &cx, &token, "tools/list", None).await.unwrap_err();
            assert_eq!(error.code, McpErrorCode::InvalidParams);
            receive(&cx, &mut peer, "tools/list", Some(2)).await;
            assert_eq!(client.next_id, 3);
            ordinary_survives(&cx, &mut client, &mut peer).await;
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_catalog_bounds_charge_whole_pages_without_an_extra_request() {
        run(|cx| async move {
            let first = page("tools/list", Some("first"), Some("next"), "private");
            let last = page("tools/list", Some("last"), None, "private");
            for dimension in ["pages", "items", "bytes", "cursor"] {
                for rejected in [false, true] {
                    let (mut client, mut peer) = connected(&cx).await;
                    let mut limits = PaginationLimits::DEFAULT;
                    let expected_error = match dimension {
                        "pages" => {
                            limits.pages = if rejected { 1 } else { 2 };
                            PAGINATION_PAGE_LIMIT_ERROR
                        }
                        "items" => {
                            limits.items = if rejected { 1 } else { 2 };
                            PAGINATION_ITEM_LIMIT_ERROR
                        }
                        "bytes" => {
                            limits.serialized_bytes = first.to_string().len() + last.to_string().len()
                                - usize::from(rejected);
                            PAGINATION_BYTE_LIMIT_ERROR
                        }
                        "cursor" => {
                            limits.cursor_bytes = if rejected { 3 } else { 4 };
                            PAGINATION_CURSOR_LIMIT_ERROR
                        }
                        _ => unreachable!(),
                    };
                    let count = if rejected && matches!(dimension, "pages" | "cursor") { 1 } else { 2 };
                    let pages = [first.clone(), last.clone()];
                    let mut server = cx.spawn(move |peer_cx| async move {
                        for (index, page) in pages.into_iter().take(count).enumerate() {
                            let id = index as i64 + 2;
                            receive(&peer_cx, &mut peer, "tools/list", Some(id)).await;
                            peer.send_async(&peer_cx, &response(id, page)).await.unwrap();
                        }
                        peer
                    }).unwrap();
                    let result = client.collect_catalog_with_budget(
                        &cx, &McpRequestCancellation::new(), "tools/list", json!({}),
                        PaginationBudget::with_limits(limits),
                    ).await;
                    if rejected {
                        let error = result.unwrap_err();
                        assert_eq!(error.code, McpErrorCode::InternalError, "{dimension}");
                        assert_eq!(error.message, expected_error, "{dimension}");
                    } else {
                        let collection = result.unwrap();
                        assert_eq!(collection.item_count(), 2, "{dimension}");
                        assert_eq!(collection.pages().len(), 2, "{dimension}");
                    }
                    assert_eq!(client.next_id, count as i64 + 2, "{dimension}");
                    let mut peer = server.join(&cx).await.unwrap();
                    ordinary_survives(&cx, &mut client, &mut peer).await;
                    client.close(&cx).unwrap();
                }
            }
        });
    }

    #[test]
    fn memory_catalog_rebuilds_once_for_scope_or_cursor_without_resetting_budget() {
        run(|cx| async move {
            for cause in ["scope", "cursor"] {
                for second_failure in [false, true] {
                    let (mut client, mut peer) = connected(&cx).await;
                    let mut server = cx.spawn(move |peer_cx| async move {
                        for (id, cursor) in [(2, None), (3, Some("old")), (4, None)] {
                            assert_parameters(receive(&peer_cx, &mut peer, "tools/list", Some(id)).await, cursor);
                            let message = match id {
                                2 => response(id, page("tools/list", Some("discarded"), Some("old"), "private")),
                                3 if cause == "cursor" => rejected_cursor(id),
                                3 => response(id, page("tools/list", Some("discarded"), None, "public")),
                                _ => response(id, page("tools/list", Some("fresh"), second_failure.then_some("new"), "private")),
                            };
                            peer.send_async(&peer_cx, &message).await.unwrap();
                        }
                        if second_failure {
                            assert_parameters(receive(&peer_cx, &mut peer, "tools/list", Some(5)).await, Some("new"));
                            let message = if cause == "cursor" {
                                rejected_cursor(5)
                            } else {
                                response(5, page("tools/list", Some("unstable"), None, "public"))
                            };
                            peer.send_async(&peer_cx, &message).await.unwrap();
                        }
                        peer
                    }).unwrap();
                    let result = collect(&mut client, &cx, &McpRequestCancellation::new(), "tools/list", None).await;
                    if second_failure {
                        assert_eq!(result.unwrap_err().code, if cause == "cursor" {
                            McpErrorCode::InvalidParams
                        } else {
                            McpErrorCode::InvalidRequest
                        });
                    } else {
                        let collection = result.unwrap();
                        assert_eq!(collection.pages().len(), 1);
                        assert_eq!(collection.item_count(), 1);
                        let result: Value = serde_json::from_str(&collection.pages()[0].encode().unwrap()).unwrap();
                        assert_eq!(result["_meta"]["com.example/page"], "fresh");
                    }
                    assert_eq!(client.next_id, if second_failure { 6 } else { 5 });
                    let mut peer = server.join(&cx).await.unwrap();
                    ordinary_survives(&cx, &mut client, &mut peer).await;
                    client.close(&cx).unwrap();
                }
            }

            let (mut client, mut peer) = connected(&cx).await;
            let mut server = cx.spawn(move |peer_cx| async move {
                for id in 2..=4 {
                    receive(&peer_cx, &mut peer, "tools/list", Some(id)).await;
                    let message = if id == 3 { rejected_cursor(id) } else {
                        response(id, page("tools/list", Some("one"), Some("next"), "private"))
                    };
                    peer.send_async(&peer_cx, &message).await.unwrap();
                }
                peer
            }).unwrap();
            let error = client.collect_catalog_with_budget(
                &cx, &McpRequestCancellation::new(), "tools/list", json!({}),
                PaginationBudget::with_limits(PaginationLimits { pages: 3, ..PaginationLimits::DEFAULT }),
            ).await.unwrap_err();
            assert_eq!(error.message, PAGINATION_PAGE_LIMIT_ERROR);
            assert_eq!(client.next_id, 5, "the rejected page and abandoned traversal still consume budget");
            let mut peer = server.join(&cx).await.unwrap();
            ordinary_survives(&cx, &mut client, &mut peer).await;
            client.close(&cx).unwrap();
        });
    }

    fn catalog_notification(method: &str, subscription_id: Option<i64>) -> JsonRpcMessage {
        let mut parameters = json!({"com.example/change":"retained"});
        if let Some(id) = subscription_id {
            parameters["_meta"] = json!({"io.modelcontextprotocol/subscriptionId":id});
        }
        JsonRpcMessage::Request(JsonRpcRequest::notification(method, Some(parameters)))
    }

    #[test]
    fn memory_catalog_invalidation_observes_owned_and_unsolicited_events_without_draining() {
        run(|cx| async move {
            for method in METHODS {
                for owned in [false, true] {
                    let (mut client, mut peer) = connected(&cx).await;
                    let token = McpRequestCancellation::new();
                    let notification_method = match method {
                        "tools/list" => "notifications/tools/list_changed",
                        "prompts/list" => "notifications/prompts/list_changed",
                        _ => "notifications/resources/list_changed",
                    };
                    let mut listener = if owned {
                        let listener = client.subscribe(&cx, &token, SubscriptionFilter {
                            tools_list_changed: Some(true), resources_list_changed: Some(true),
                            prompts_list_changed: Some(true), ..SubscriptionFilter::default()
                        }).await.unwrap();
                        receive(&cx, &mut peer, "subscriptions/listen", Some(2)).await;
                        peer.send_async(&cx, &JsonRpcMessage::Request(JsonRpcRequest::notification(
                            "notifications/subscriptions/acknowledged",
                            Some(json!({
                                "notifications":{"toolsListChanged":true,"resourcesListChanged":true,"promptsListChanged":true},
                                "_meta":{"io.modelcontextprotocol/subscriptionId":2},
                            })),
                        ))).await.unwrap();
                        Some(listener)
                    } else { None };
                    if let Some(listener) = &mut listener {
                        assert!(matches!(client.next_subscription_event(&cx, &token, listener).await.unwrap(),
                            Some(MemorySubscriptionEvent::Acknowledged { .. })));
                    }
                    let first_id = if owned { 3 } else { 2 };
                    let mut server = cx.spawn(move |peer_cx| async move {
                        assert_parameters(receive(&peer_cx, &mut peer, method, Some(first_id)).await, None);
                        peer.send_async(&peer_cx, &catalog_notification(notification_method, owned.then_some(2)))
                            .await.unwrap();
                        peer.send_async(&peer_cx, &response(first_id, page(method, Some("stale"), Some("old"), "private")))
                            .await.unwrap();
                        assert_parameters(receive(&peer_cx, &mut peer, method, Some(first_id + 1)).await, None);
                        peer.send_async(&peer_cx, &response(first_id + 1, page(method, Some("fresh"), None, "private")))
                            .await.unwrap();
                        peer
                    }).unwrap();
                    let collection = collect(&mut client, &cx, &token, method, None).await.unwrap();
                    assert_eq!(collection.pages().len(), 1);
                    let result: Value = serde_json::from_str(&collection.pages()[0].encode().unwrap()).unwrap();
                    assert_eq!(result["_meta"]["com.example/page"], "fresh");
                    assert_eq!(client.subscriptions.catalog_generation(method), 1);
                    if let Some(listener) = &mut listener {
                        let Some(MemorySubscriptionEvent::Notification(notification)) = client
                            .next_subscription_event(&cx, &token, listener).await.unwrap() else {
                                panic!("catalog traversal must not drain its listener");
                            };
                        assert_eq!(notification.method(), notification_method);
                        assert!(client.take_server_notifications().is_empty());
                    } else {
                        let events = client.take_server_notifications();
                        assert_eq!(events.len(), 1);
                        assert_eq!(events[0].method, notification_method);
                        assert_eq!(events[0].params.as_ref().unwrap()["com.example/change"], "retained");
                    }
                    let _peer = server.join(&cx).await.unwrap();
                    client.close(&cx).unwrap();
                }
            }
        });
    }

    #[test]
    fn memory_catalog_foreign_and_other_catalog_events_do_not_restart() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let mut server = cx.spawn(move |peer_cx| async move {
                receive(&peer_cx, &mut peer, "tools/list", Some(2)).await;
                for notification in [
                    catalog_notification("notifications/tools/list_changed", Some(999)),
                    catalog_notification("notifications/resources/list_changed", None),
                ] {
                    peer.send_async(&peer_cx, &notification).await.unwrap();
                }
                peer.send_async(&peer_cx, &response(2, page("tools/list", Some("kept"), None, "private")))
                    .await.unwrap();
                peer
            }).unwrap();
            let collection = collect(&mut client, &cx, &McpRequestCancellation::new(), "tools/list", None).await.unwrap();
            assert_eq!(collection.item_count(), 1);
            assert_eq!(client.next_id, 3);
            assert_eq!(client.subscriptions.catalog_generation("tools/list"), 0);
            assert_eq!(client.subscriptions.catalog_generation("resources/list"), 1);
            assert_eq!(client.subscriptions.catalog_generation("resources/templates/list"), 1);
            let events = client.take_server_notifications();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].method, "notifications/resources/list_changed");
            let _peer = server.join(&cx).await.unwrap();
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_catalog_unpublished_drop_cancel_and_deadline_preserve_sibling() {
        run(|cx| async move {
            let (mut client, mut peer) = connected(&cx).await;
            let live = McpRequestCancellation::new();
            let mut sibling = client.execute_core(&cx, &live, "tools/list", json!({})).await.unwrap();
            let original = client.executor.pending_records();
            for mode in ["drop", "cancel", "deadline"] {
                let token = McpRequestCancellation::new();
                let mut budget = PaginationBudget::new();
                if mode == "deadline" { budget.deadline = Instant::now() + Duration::from_millis(25); }
                {
                    let mut collection = pin!(client.collect_catalog_with_budget(
                        &cx, &token, "tools/list", json!({}), budget,
                    ));
                    poll_fn(|task| {
                        assert!(collection.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    }).await;
                    if mode == "cancel" {
                        token.cancel();
                        assert_eq!(collection.await.unwrap_err().code, McpErrorCode::RequestCancelled);
                    } else if mode == "deadline" {
                        let started = Instant::now();
                        assert_eq!(collection.await.unwrap_err().message, PAGINATION_DEADLINE_ERROR);
                        assert!(started.elapsed() < Duration::from_secs(1));
                    }
                }
                assert_eq!(client.next_id, 3);
                assert_eq!(client.executor.pending_records(), original);
                assert!(!client.executor.has_external_controls(&cx).unwrap());
            }
            receive(&cx, &mut peer, "tools/list", Some(2)).await;
            peer.send_async(&cx, &response(2, page("tools/list", Some("sibling"), None, "private"))).await.unwrap();
            assert!(matches!(client.next_event(&cx, &live, &mut sibling).await.unwrap(),
                Some(MemoryRequestEvent::Result(_))));
            ordinary_survives(&cx, &mut client, &mut peer).await;
            client.close(&cx).unwrap();
        });
    }

    #[test]
    fn memory_catalog_published_drop_cancel_and_deadline_retire_only_current_page() {
        run(|cx| async move {
            for mode in ["drop", "cancel", "deadline"] {
                let (mut client, mut peer) = connected(&cx).await;
                let live = McpRequestCancellation::new();
                let mut sibling = client.execute_core(&cx, &live, "tools/list", json!({})).await.unwrap();
                receive(&cx, &mut peer, "tools/list", Some(2)).await;
                peer.send_async(&cx, &response(2, page("tools/list", Some("sibling"), None, "private"))).await.unwrap();
                let token = McpRequestCancellation::new();
                let mut budget = PaginationBudget::new();
                if mode == "deadline" { budget.deadline = Instant::now() + Duration::from_millis(25); }
                {
                    let mut collection = pin!(client.collect_catalog_with_budget(
                        &cx, &token, "tools/list", json!({}), budget,
                    ));
                    poll_fn(|task| {
                        assert!(collection.as_mut().poll(task).is_pending());
                        Poll::Ready(())
                    }).await;
                    receive(&cx, &mut peer, "tools/list", Some(3)).await;
                    if mode == "cancel" {
                        token.cancel();
                        assert_eq!(collection.await.unwrap_err().code, McpErrorCode::RequestCancelled);
                    } else if mode == "deadline" {
                        assert_eq!(collection.await.unwrap_err().message, PAGINATION_DEADLINE_ERROR);
                    }
                }
                assert_eq!(client.next_id, 4);
                let mut server = cx.spawn(move |peer_cx| async move {
                    let control = receive(&peer_cx, &mut peer, "notifications/cancelled", None).await;
                    assert_eq!(control.params.unwrap()["requestId"], 3);
                    receive(&peer_cx, &mut peer, "tools/list", Some(4)).await;
                    peer.send_async(&peer_cx, &response(3, page("tools/list", Some("late"), None, "private"))).await.unwrap();
                    peer.send_async(&peer_cx, &response(4, page("tools/list", Some("healthy"), None, "private"))).await.unwrap();
                    peer
                }).unwrap();
                assert!(matches!(client.next_event(&cx, &live, &mut sibling).await.unwrap(),
                    Some(MemoryRequestEvent::Result(_))));
                let result = client.list_tools(&cx, &live, None).await.unwrap();
                let value: Value = serde_json::from_str(&result.encode().unwrap()).unwrap();
                assert_eq!(value["_meta"]["com.example/page"], "healthy");
                assert_eq!(client.take_cancellation_events().len(), 1);
                assert!(!client.executor.has_external_controls(&cx).unwrap());
                let _peer = server.join(&cx).await.unwrap();
                client.close(&cx).unwrap();
            }
        });
    }
}
