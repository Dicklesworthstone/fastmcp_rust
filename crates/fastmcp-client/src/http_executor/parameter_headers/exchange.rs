//! Reviewed parameter headers across one bounded, cancellable tool exchange.

use std::time::Duration;

use asupersync::Cx;
use fastmcp_core::{McpError, McpErrorCode, McpRequestCancellation};
use fastmcp_protocol::http_headers::ParameterHeaderBinding;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{CoreResult, FinalCoreResult};
use serde_json::{Value, json};

use super::{ReviewedToolHeaders, ToolHeaderDispatchError};
use crate::{
    ClientHttpConnectionError, FinalCacheResultSet, HttpClient, HttpClientError,
    MAX_MRTR_CONTINUATION_ROUNDS, ModernHttpClientError, mrtr_input_required_for_method,
    mrtr_retry_parameters,
};

const MAX_REVIEWED_HEADER_REFRESH_PAGES: usize = 64;

fn header_error(error: ToolHeaderDispatchError) -> HttpClientError {
    HttpClientError::Connection(ClientHttpConnectionError::Modern(
        ModernHttpClientError::ParameterHeaders(error),
    ))
}

fn checkpoint(
    cx: &Cx,
    cancellation: Option<&McpRequestCancellation>,
) -> Result<(), HttpClientError> {
    if cx.checkpoint().is_err()
        || cancellation.is_some_and(McpRequestCancellation::is_cancel_requested)
    {
        return Err(McpError::request_cancelled().into());
    }
    Ok(())
}

impl ReviewedToolHeaders {
    /// Reviews a replacement schema without changing the approved endpoint or
    /// tool identity. Every new binding requires fresh approval, even when its
    /// spelling has not changed. A refusal leaves this original plan untouched.
    ///
    /// An explicit numeric-loopback HTTP approval stays loopback-only; an HTTPS
    /// approval cannot turn into cleartext. No invocation data is retained.
    pub fn re_review(
        &self,
        schema: Value,
        review: impl FnMut(&ParameterHeaderBinding) -> bool,
    ) -> Result<Self, ToolHeaderDispatchError> {
        if self.resource().scheme() == "http" {
            Self::new_for_loopback_http(self.resource().clone(), self.tool_name(), schema, review)
        } else {
            Self::new(self.resource().clone(), self.tool_name(), schema, review)
        }
    }
}

impl HttpClient {
    /// Calls the reviewed tool and follows installed modern reverse handlers.
    ///
    /// Unlike the one-round `call_tool_with_parameter_headers` API, this method
    /// composes parameter mirrors with MRTR. Every initial/continuation request
    /// gets a fresh ID and projects its headers from its own immutable body.
    /// Original arguments survive every continuation; only the shared admitted
    /// MRTR helper constructs `inputResponses` and carries peer request state.
    /// With no installed reverse handlers, `input_required` is returned intact.
    ///
    /// Exactly one correlated, canonical HTTP 400 HeaderMismatch refusal may
    /// refresh the tool schema and retry, across the ENTIRE logical exchange.
    /// Refresh bypasses the tools cache, visits at most 64 pages, and re-reviews
    /// every binding while preserving the approved HTTPS/loopback boundary.
    /// Other errors and a second refusal are never replayed. A changed schema
    /// does not replace the caller's plan; the owner still owns catalog policy.
    ///
    /// The client's absolute timeout bounds the whole exchange, including
    /// catalog refresh and reverse handlers, rather than restarting each round.
    pub async fn call_tool_with_reviewed_headers(
        &mut self,
        cx: &Cx,
        arguments: Value,
        reviewed: &ReviewedToolHeaders,
        review: &dyn Fn(&ParameterHeaderBinding) -> bool,
    ) -> Result<CoreResult, HttpClientError> {
        self.bounded_reviewed_tool_call(cx, None, arguments, reviewed, review)
            .await
    }

    /// The reviewed, multi-round call with a caller-owned cancellation domain.
    /// Cancellation is checked before each request, during catalog refresh and
    /// in reverse-handler processing. It never authorizes an unreviewed retry.
    pub async fn call_tool_with_reviewed_headers_and_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        arguments: Value,
        reviewed: &ReviewedToolHeaders,
        review: &dyn Fn(&ParameterHeaderBinding) -> bool,
    ) -> Result<CoreResult, HttpClientError> {
        self.bounded_reviewed_tool_call(cx, Some(cancellation), arguments, reviewed, review)
            .await
    }

    async fn bounded_reviewed_tool_call(
        &mut self,
        cx: &Cx,
        cancellation: Option<&McpRequestCancellation>,
        arguments: Value,
        reviewed: &ReviewedToolHeaders,
        review: &dyn Fn(&ParameterHeaderBinding) -> bool,
    ) -> Result<CoreResult, HttpClientError> {
        checkpoint(cx, cancellation)?;
        if self.selected_protocol_era() != ProtocolEra::Modern2026 {
            return Err(header_error(ToolHeaderDispatchError::OperationMismatch));
        }
        if self.protocol_plan().modern_post_target() != Some(reviewed.resource().as_str()) {
            return Err(header_error(ToolHeaderDispatchError::TargetMismatch));
        }
        let now = cx.now();
        let timeout = self.request_timeout_policy.absolute_timeout();
        let remaining = cx.budget().deadline.map_or(timeout, |deadline| {
            timeout.min(Duration::from_nanos(deadline.duration_since(now)))
        });
        let deadline =
            now.saturating_add_nanos(u64::try_from(remaining.as_nanos()).unwrap_or(u64::MAX));
        match asupersync::time::timeout_at(
            deadline,
            self.drive_reviewed_tool_call(cx, cancellation, arguments, reviewed, review),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                checkpoint(cx, cancellation)?;
                Err(McpError::with_data(
                    McpErrorCode::InternalError,
                    "Reviewed tool call absolute timeout exceeded",
                    json!({"timeoutSource":"absolute"}),
                )
                .into())
            }
        }
    }

    async fn drive_reviewed_tool_call(
        &mut self,
        cx: &Cx,
        cancellation: Option<&McpRequestCancellation>,
        arguments: Value,
        reviewed: &ReviewedToolHeaders,
        review: &dyn Fn(&ParameterHeaderBinding) -> bool,
    ) -> Result<CoreResult, HttpClientError> {
        let handlers = self
            .connection
            .modern_reverse_request_handlers()
            .filter(|handlers| handlers.has_modern_handlers())
            .cloned();
        let original = json!({"name":reviewed.tool_name(), "arguments":arguments});
        let mut parameters = original.clone();
        let mut refreshed = None;
        let mut repair_used = false;
        let mut rounds = 0;
        loop {
            checkpoint(cx, cancellation)?;
            let result = self
                .request_final_core_with_optional_cancellation(
                    cx,
                    cancellation,
                    "tools/call",
                    parameters.clone(),
                    Some(refreshed.as_ref().unwrap_or(reviewed)),
                )
                .await;
            let result = match result {
                Err(HttpClientError::Connection(
                    ClientHttpConnectionError::ParameterHeaderMismatch { .. },
                )) if !repair_used => {
                    repair_used = true;
                    refreshed = Some(
                        self.refresh_reviewed_tool_headers(cx, cancellation, reviewed, review)
                            .await?,
                    );
                    continue;
                }
                result => result?,
            };
            checkpoint(cx, cancellation)?;
            let Some(input_required) = mrtr_input_required_for_method("tools/call", &result) else {
                return Ok(result);
            };
            let Some(handlers) = handlers.as_ref() else {
                return Ok(result);
            };
            if rounds >= MAX_MRTR_CONTINUATION_ROUNDS {
                return Err(
                    McpError::invalid_request("MRTR continuation-round limit exceeded").into(),
                );
            }
            rounds += 1;
            let responses = handlers
                .respond_to_input_required_async(cx, input_required, || {
                    if cancellation.is_some_and(McpRequestCancellation::is_cancel_requested) {
                        return Err(McpError::request_cancelled());
                    }
                    cx.checkpoint().map_err(|_| McpError::request_cancelled())
                })
                .await?;
            parameters = mrtr_retry_parameters(original.clone(), input_required, responses)?;
        }
    }

    async fn refresh_reviewed_tool_headers(
        &mut self,
        cx: &Cx,
        cancellation: Option<&McpRequestCancellation>,
        reviewed: &ReviewedToolHeaders,
        review: &dyn Fn(&ParameterHeaderBinding) -> bool,
    ) -> Result<ReviewedToolHeaders, HttpClientError> {
        checkpoint(cx, cancellation)?;
        self.final_result_cache
            .invalidate_result_set(&FinalCacheResultSet::Tools);
        let mut cursor = None;
        for _ in 0..MAX_REVIEWED_HEADER_REFRESH_PAGES {
            checkpoint(cx, cancellation)?;
            let parameters = match cursor.take() {
                Some(cursor) => json!({"cursor":cursor}),
                None => json!({}),
            };
            // Never reuse any cached page after a pre-dispatch schema refusal.
            let (result, _) = self
                .request_final_core_with_cache_policy(
                    cx,
                    cancellation,
                    "tools/list",
                    parameters,
                    None,
                    false,
                )
                .await?;
            checkpoint(cx, cancellation)?;
            let CoreResult::Final(FinalCoreResult::ToolsList { result, .. }) = result else {
                return Err(McpError::invalid_request(
                    "Parameter-header refresh requires a final tools/list result",
                )
                .into());
            };
            let payload = result.payload;
            if let Some(tool) = payload
                .tools
                .into_iter()
                .find(|tool| tool.name == reviewed.tool_name())
            {
                return reviewed
                    .re_review(tool.input_schema, review)
                    .map_err(header_error);
            }
            cursor = payload.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        Err(McpError::invalid_params(
            "Reviewed tool was not found within the header-refresh page limit",
        )
        .into())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashSet, VecDeque};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::Instant;

    use fastmcp_core::CanonicalHttpUrl;
    use fastmcp_protocol::{
        ClientCapabilities, DiscoveryCacheHints, HEADER_MISMATCH_ERROR_CODE,
        HEADER_MISMATCH_MESSAGE, ServerBehavior, ServerBehaviorRegistry,
        ServerDiscoverCapabilities, ServerDiscoverResult, ServerInfo,
    };

    use super::*;
    use crate::{ClientBuilder, ClientProtocolPlan, ProtocolPolicy, ReverseRequestHandlers};

    fn schema(field: &str) -> Value {
        json!({"type":"object","properties":{
            "region":{"type":"string","x-mcp-header":field}
        }})
    }

    #[test]
    fn re_review_retains_endpoint_and_identity_and_requires_fresh_consent() {
        for target in ["https://tools.example/mcp", "http://127.0.0.1:8123/mcp"] {
            let resource = CanonicalHttpUrl::parse(target).unwrap();
            let original = if resource.scheme() == "http" {
                ReviewedToolHeaders::new_for_loopback_http(
                    resource,
                    "lookup",
                    schema("Old"),
                    |_| true,
                )
            } else {
                ReviewedToolHeaders::new(resource, "lookup", schema("Old"), |_| true)
            }
            .unwrap();
            let mut count = 0;
            let updated = original
                .re_review(schema("New"), |_| {
                    count += 1;
                    true
                })
                .unwrap();
            assert_eq!(count, 1);
            assert_eq!(updated.resource(), original.resource());
            assert_eq!(updated.tool_name(), "lookup");
            assert_eq!(updated.bindings()[0].header_name(), "Mcp-Param-New");
            assert!(matches!(
                original.re_review(schema("New"), |_| false),
                Err(ToolHeaderDispatchError::DisclosureDenied)
            ));
            assert_eq!(original.bindings()[0].header_name(), "Mcp-Param-Old");
        }
    }

    #[derive(Clone)]
    struct Captured {
        headers: String,
        body: Value,
    }

    struct Reply {
        method: &'static str,
        status: u16,
        payload: Result<Value, Value>,
        wrong_id: bool,
    }

    fn result(method: &'static str, payload: Value) -> Reply {
        Reply {
            method,
            status: 200,
            payload: Ok(payload),
            wrong_id: false,
        }
    }

    fn mismatch() -> Reply {
        Reply {
            method: "tools/call",
            status: 400,
            payload: Err(json!({
                "code":HEADER_MISMATCH_ERROR_CODE,
                "message":HEADER_MISMATCH_MESSAGE
            })),
            wrong_id: false,
        }
    }

    fn catalog() -> Reply {
        result(
            "tools/list",
            json!({
                "resultType":"complete", "ttlMs":0, "cacheScope":"private",
                "tools":[{"name":"lookup", "inputSchema":schema("Region")}]
            }),
        )
    }

    fn input_required() -> Reply {
        result(
            "tools/call",
            json!({
                "resultType":"input_required", "requestState":"opaque-state",
                "inputRequests":{"roots":{"method":"roots/list"}}
            }),
        )
    }

    fn complete() -> Reply {
        result(
            "tools/call",
            json!({
                "resultType":"complete", "content":[{"type":"text","text":"done"}],
                "isError":false
            }),
        )
    }

    fn read_request(stream: &mut TcpStream) -> Captured {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            assert!(bytes.len() < 64 * 1024, "test request head exceeded bound");
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            bytes.push(byte[0]);
        }
        let headers = String::from_utf8(bytes).unwrap();
        let length: usize = headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .expect("native JSON request supplies content length")
            .1
            .trim()
            .parse()
            .unwrap();
        assert!(length <= 1024 * 1024);
        let mut body = vec![0; length];
        stream.read_exact(&mut body).unwrap();
        Captured {
            headers,
            body: serde_json::from_slice(&body).unwrap(),
        }
    }

    struct Peer {
        endpoint: CanonicalHttpUrl,
        captured: Arc<Mutex<Vec<Captured>>>,
        stop: Arc<AtomicBool>,
        join: Option<JoinHandle<()>>,
    }

    impl Peer {
        fn start(replies: Vec<Reply>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint =
                CanonicalHttpUrl::parse(&format!("http://{}/mcp", listener.local_addr().unwrap()))
                    .unwrap();
            listener.set_nonblocking(true).unwrap();
            let captured = Arc::new(Mutex::new(Vec::new()));
            let worker_captured = captured.clone();
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = stop.clone();
            let capabilities = ServerDiscoverCapabilities::from_registry(
                &ServerBehaviorRegistry::from_behaviors([ServerBehavior::ToolsList]),
                Default::default(),
            )
            .unwrap();
            let discovery = ServerDiscoverResult::new(
                capabilities,
                ServerInfo {
                    name: "reviewed-header-peer".into(),
                    version: "1".into(),
                },
                None,
                DiscoveryCacheHints::private_ttl_ms(0),
            );
            let mut replies: VecDeque<_> = replies.into();
            replies.push_front(result(
                "server/discover",
                serde_json::to_value(discovery).unwrap(),
            ));
            let join = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(15);
                while !worker_stop.load(Ordering::SeqCst) {
                    assert!(Instant::now() < deadline, "test peer exceeded its deadline");
                    let (mut stream, _) = match listener.accept() {
                        Ok(stream) => stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                            continue;
                        }
                        Err(error) => panic!("accept failed: {error}"),
                    };
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let request = read_request(&mut stream);
                    let reply = replies.pop_front().unwrap_or_else(|| Reply {
                        method: "unexpected",
                        status: 500,
                        payload: Err(json!({"code":-32603,"message":"unexpected extra request"})),
                        wrong_id: false,
                    });
                    // Keep accepting unexpected traffic so a forbidden retry
                    // is captured, rather than hidden by a closed listener.
                    if reply.method != "unexpected" {
                        assert_eq!(request.body["method"], reply.method);
                    }
                    let id = if reply.wrong_id {
                        json!("uncorrelated")
                    } else {
                        request.body["id"].clone()
                    };
                    worker_captured.lock().unwrap().push(request);
                    let envelope = match reply.payload {
                        Ok(payload) => json!({"jsonrpc":"2.0","id":id,"result":payload}),
                        Err(error) => json!({"jsonrpc":"2.0","id":id,"error":error}),
                    };
                    let body = serde_json::to_vec(&envelope).unwrap();
                    write!(stream,
                        "HTTP/1.1 {} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        reply.status, body.len()
                    ).unwrap();
                    stream.write_all(&body).unwrap();
                }
                assert!(replies.is_empty(), "client omitted an expected exchange");
            });
            Self {
                endpoint,
                captured,
                stop,
                join: Some(join),
            }
        }

        fn finish(mut self) -> Vec<Captured> {
            self.stop.store(true, Ordering::SeqCst);
            self.join.take().unwrap().join().unwrap();
            let captured = self.captured.lock().unwrap().clone();
            captured
        }
    }

    impl Drop for Peer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    fn exercise(
        replies: Vec<Reply>,
        with_handlers: bool,
        deny_review: bool,
        pre_cancel: bool,
    ) -> (Result<CoreResult, HttpClientError>, Vec<Captured>, usize) {
        let peer = Peer::start(replies);
        let reviewed = ReviewedToolHeaders::new_for_loopback_http(
            peer.endpoint.clone(),
            "lookup",
            schema("OldRegion"),
            |_| true,
        )
        .unwrap();
        let callback_count = Arc::new(AtomicUsize::new(0));
        let observed_count = callback_count.clone();
        let handlers = if with_handlers {
            ReverseRequestHandlers::new().with_modern_roots_list(move |_, _, _| {
                callback_count.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(serde_json::from_value(json!({"roots":[]})).unwrap()) })
            })
        } else {
            ReverseRequestHandlers::new()
        };
        let mut runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .blocking_threads(0, 2)
            .build()
            .unwrap();
        let outcome = runtime.block_on(async {
            let cx = Cx::current().unwrap();
            let plan = ClientProtocolPlan::http(
                ProtocolPolicy::ModernOnly,
                Some(peer.endpoint.clone()),
                None,
                None,
                "test-anonymous".into(),
                "test-local".into(),
                "native-http".into(),
                0,
                0,
                0,
            )
            .unwrap();
            let capabilities: ClientCapabilities =
                serde_json::from_value(json!({"roots":{}})).unwrap();
            let mut client = ClientBuilder::new()
                .protocol_plan(plan)
                .capabilities(capabilities)
                .reverse_request_handlers(handlers)
                .connect_http_client_with_cx(&cx)
                .await
                .unwrap();
            let arguments = json!({"region":"east","bodyOnly":"private"});
            if pre_cancel {
                let cancelled = Cx::for_testing();
                cancelled.set_cancel_requested(true);
                client
                    .call_tool_with_reviewed_headers_and_cancellation(
                        &cancelled,
                        &McpRequestCancellation::new(),
                        arguments,
                        &reviewed,
                        &|_| !deny_review,
                    )
                    .await
            } else {
                client
                    .call_tool_with_reviewed_headers(&cx, arguments, &reviewed, &|_| !deny_review)
                    .await
            }
        });
        (
            outcome,
            peer.finish(),
            observed_count.load(Ordering::SeqCst),
        )
    }

    fn mirrored(request: &Captured, field: &str) -> Option<String> {
        request
            .headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case(field))
            .map(|(_, value)| value.trim().to_owned())
    }

    #[test]
    fn live_loopback_repair_then_mrtr_reprojects_every_request_with_fresh_ids() {
        let (outcome, captured, callbacks) = exercise(
            vec![mismatch(), catalog(), input_required(), complete()],
            true,
            false,
            false,
        );
        assert!(matches!(
            outcome,
            Ok(CoreResult::Final(FinalCoreResult::ToolsCall { .. }))
        ));
        assert_eq!(callbacks, 1);
        assert_eq!(captured.len(), 5);
        let calls: Vec<_> = captured
            .iter()
            .filter(|call| call.body["method"] == "tools/call")
            .collect();
        assert_eq!(calls.len(), 3);
        assert_eq!(
            mirrored(calls[0], "Mcp-Param-OldRegion").as_deref(),
            Some("east")
        );
        assert_eq!(mirrored(calls[0], "Mcp-Param-Region"), None);
        for call in &calls[1..] {
            assert_eq!(mirrored(call, "Mcp-Param-Region").as_deref(), Some("east"));
            assert_eq!(mirrored(call, "Mcp-Param-OldRegion"), None);
        }
        for call in &calls {
            assert_eq!(
                call.body["params"]["arguments"],
                json!({"region":"east","bodyOnly":"private"})
            );
            assert!(!call.headers.contains("private"));
        }
        assert_ne!(calls[1].body["params"], calls[2].body["params"]);
        let ids: HashSet<_> = captured
            .iter()
            .map(|call| call.body["id"].to_string())
            .collect();
        assert_eq!(ids.len(), captured.len());
    }

    #[test]
    fn live_loopback_denied_refresh_cannot_send_a_repaired_call() {
        let (outcome, captured, callbacks) =
            exercise(vec![mismatch(), catalog()], true, true, false);
        assert!(matches!(
            outcome,
            Err(HttpClientError::Connection(
                ClientHttpConnectionError::Modern(ModernHttpClientError::ParameterHeaders(
                    ToolHeaderDispatchError::DisclosureDenied
                ))
            ))
        ));
        assert_eq!(captured.len(), 3);
        assert_eq!(callbacks, 0);
    }

    #[test]
    fn live_loopback_second_refusal_does_not_reset_the_repair_budget() {
        let (outcome, captured, callbacks) = exercise(
            vec![mismatch(), catalog(), input_required(), mismatch()],
            true,
            false,
            false,
        );
        assert!(matches!(
            outcome,
            Err(HttpClientError::Connection(
                ClientHttpConnectionError::ParameterHeaderMismatch { .. }
            ))
        ));
        assert_eq!(captured.len(), 5);
        assert_eq!(callbacks, 1);
        assert_eq!(
            captured
                .iter()
                .filter(|call| call.body["method"] == "tools/list")
                .count(),
            1
        );
    }

    #[test]
    fn live_loopback_noncanonical_refusals_never_trigger_catalog_or_replay() {
        for changed in 0..5 {
            let mut reply = mismatch();
            match changed {
                0 => reply.status = 200,
                1 => reply.payload.as_mut().unwrap_err()["code"] = json!(-32602),
                2 => reply.payload.as_mut().unwrap_err()["message"] = json!("not canonical"),
                3 => reply.wrong_id = true,
                _ => reply.payload.as_mut().unwrap_err()["data"] = json!({}),
            }
            let (outcome, captured, callbacks) = exercise(vec![reply], true, false, false);
            assert!(outcome.is_err(), "refusal variant {changed}");
            assert_eq!(captured.len(), 2, "refusal variant {changed}");
            assert_eq!(callbacks, 0);
        }
    }

    #[test]
    fn live_loopback_without_handlers_returns_input_required_without_following() {
        let (outcome, captured, callbacks) = exercise(vec![input_required()], false, false, false);
        assert!(matches!(
            outcome,
            Ok(CoreResult::Final(
                FinalCoreResult::ToolsCallInputRequired { .. }
            ))
        ));
        assert_eq!(captured.len(), 2);
        assert_eq!(callbacks, 0);
    }

    #[test]
    fn live_loopback_precancelled_call_does_not_allocate_a_network_exchange() {
        let (outcome, captured, callbacks) = exercise(vec![], true, false, true);
        assert!(matches!(outcome, Err(HttpClientError::CoreResult(error))
            if error.code == McpErrorCode::RequestCancelled));
        assert_eq!(captured.len(), 1);
        assert_eq!(callbacks, 0);
    }
}
