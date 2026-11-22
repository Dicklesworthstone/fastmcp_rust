//! Provider integration tests. The private source seam replaces authentication
//! and HTTP only; catalog construction, public handler hooks, exact decoding,
//! completion routing, ID allocation and response ownership are production code.
//! These tests do not establish native OAuth interoperability or TLS behavior.

mod downstream;

use super::*;
use crate::handler::{CompletionHandler, PromptHandler, ResourceHandler, ToolHandler, UriParams};
use crate::providers::managed_oauth::interaction::{
    ManagedOAuthInputCapabilities, ManagedOAuthInputHandler, ManagedOAuthInputPolicy,
    ManagedOAuthInputResponseMode,
};
use crate::providers::managed_oauth::subscriptions::{
    ManagedOAuthResourceRelayEnd, ManagedOAuthResourceRelayOutcome,
};
use fastmcp_core::{McpErrorCode, McpRequestCancellation};
use fastmcp_protocol::{
    FINAL_SUBSCRIPTION_ID_META_KEY, FinalCancelledNotificationParams, FinalCompletionParams,
    FinalInputResponses, FinalResourceUpdatedNotificationParams, InputRequiredResult,
    ServerNotification,
};
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::{Future, pending};
use std::pin::pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

const TOOL_RESULT: &str = r#"{"resultType":"complete","content":[{"type":"text","text":"machine answer"}],"isError":false,"x-exact":{"n":900719925474099312345,"d":1.20e+4}}"#;
const RESOURCE_RESULT: &str = r#"{"resultType":"complete","contents":[{"uri":"note://documents/one","text":"document"}],"ttlMs":731,"cacheScope":"private"}"#;
const PROMPT_RESULT: &str = r#"{"resultType":"complete","messages":[{"role":"user","content":{"type":"text","text":"prompt answer"}}]}"#;
const COMPLETION_RESULT: &str =
    r#"{"resultType":"complete","completion":{"values":["one","only"],"total":2,"hasMore":false}}"#;

fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("fixture unexpectedly suspended"),
    }
}

fn decode(method: &str, parameters: Value, result: &str) -> CoreResult {
    core_request(method, parameters, None)
        .unwrap()
        .decode_result(result)
        .unwrap()
}

struct Source {
    catalogs: Mutex<HashMap<&'static str, Vec<CoreResult>>>,
    replies: Mutex<VecDeque<&'static str>>,
    calls: Mutex<Vec<Value>>,
    ids: Mutex<Vec<RequestId>>,
    input_modes: Mutex<Vec<Option<ManagedOAuthInputResponseMode>>>,
    call_policies: Mutex<Vec<String>>,
    cancel: AtomicBool,
    suspend: AtomicBool,
    fail: AtomicBool,
    drops: Arc<AtomicUsize>,
    subscription_streams: Mutex<VecDeque<Box<dyn ResourceUpdateStream>>>,
    subscription_filters: Mutex<Vec<SubscriptionFilter>>,
    subscription_policies: Mutex<Vec<ClientCredentialsCoreSubscriptionLimits>>,
}

fn source(replies: Vec<&'static str>) -> Arc<Source> {
    Arc::new(Source {
        catalogs: Mutex::new(HashMap::from([
            (
                "tools/list",
                vec![decode(
                    "tools/list",
                    json!({}),
                    r#"{"resultType":"complete","tools":[{"name":"lookup","title":"Machine lookup","inputSchema":{"type":"object"}}],"ttlMs":0,"cacheScope":"private"}"#,
                )],
            ),
            (
                "resources/list",
                vec![decode(
                    "resources/list",
                    json!({}),
                    r#"{"resultType":"complete","resources":[{"uri":"note://documents/one","name":"Note","title":"Machine note"}],"ttlMs":0,"cacheScope":"private"}"#,
                )],
            ),
            (
                "prompts/list",
                vec![decode(
                    "prompts/list",
                    json!({}),
                    r#"{"resultType":"complete","prompts":[{"name":"summarize","arguments":[{"name":"subject","required":false}]}],"ttlMs":0,"cacheScope":"private"}"#,
                )],
            ),
            (
                "resources/templates/list",
                vec![decode(
                    "resources/templates/list",
                    json!({}),
                    r#"{"resultType":"complete","resourceTemplates":[{"uriTemplate":"note://documents/{name}","name":"Notes"}],"ttlMs":0,"cacheScope":"private"}"#,
                )],
            ),
        ])),
        replies: Mutex::new(replies.into()),
        calls: Mutex::new(Vec::new()),
        ids: Mutex::new(Vec::new()),
        input_modes: Mutex::new(Vec::new()),
        call_policies: Mutex::new(Vec::new()),
        cancel: AtomicBool::new(false),
        suspend: AtomicBool::new(false),
        fail: AtomicBool::new(false),
        drops: Arc::new(AtomicUsize::new(0)),
        subscription_streams: Mutex::new(VecDeque::new()),
        subscription_filters: Mutex::new(Vec::new()),
        subscription_policies: Mutex::new(Vec::new()),
    })
}

impl MachineSource for Source {
    fn collect<'a>(
        &'a self,
        _cx: &'a Cx,
        method: &'static str,
        ids: &'a AtomicU64,
        _limits: ClientCredentialsCatalogLimits,
    ) -> BoxFuture<'a, McpResult<Vec<CoreResult>>> {
        Box::pin(async move {
            let (discovery, operation) = next_pair(ids)?;
            self.ids.lock().unwrap().extend([discovery, operation]);
            Ok(self
                .catalogs
                .lock()
                .unwrap()
                .get(method)
                .expect("known catalog")
                .clone())
        })
    }

    fn start<'a>(
        &'a self,
        ctx: &'a McpContext,
        _cx: &'a Cx,
        call: MachineCall,
    ) -> BoxFuture<'a, McpResult<Box<dyn MachineResponse>>> {
        Box::pin(async move {
            let MachineCall {
                request,
                discovery_id,
                request_id,
                limits,
                inputs,
            } = call;
            assert!(!discovery_id.correlates_with(&request_id));
            self.ids.lock().unwrap().extend([discovery_id, request_id]);
            self.calls
                .lock()
                .unwrap()
                .push(request.encode_params().unwrap().unwrap());
            self.input_modes
                .lock()
                .unwrap()
                .push(inputs.as_ref().map(|inputs| inputs.policy.response_mode()));
            // Debug observes the private numeric policy without adding public
            // getters to the client solely for a server-side wiring test.
            self.call_policies
                .lock()
                .unwrap()
                .push(format!("{limits:?}"));
            let wire = self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("one response per call");
            let result = request
                .decode_result(wire)
                .expect("request-typed fixture response");
            Ok(Box::new(Response {
                result: Some(result),
                cancellation: ctx.request_cancellation(),
                cancel: self.cancel.load(Ordering::SeqCst),
                suspend: self.suspend.load(Ordering::SeqCst),
                fail: self.fail.load(Ordering::SeqCst),
                drops: Arc::clone(&self.drops),
            }) as Box<dyn MachineResponse>)
        })
    }

    fn subscribe<'a>(
        &'a self,
        _cx: &'a Cx,
        cancellation: &'a McpRequestCancellation,
        ids: &'a AtomicU64,
        filter: SubscriptionFilter,
        limits: ClientCredentialsCoreSubscriptionLimits,
    ) -> BoxFuture<'a, McpResult<Box<dyn ResourceUpdateStream>>> {
        Box::pin(async move {
            let (discovery, operation) = next_pair(ids)?;
            self.ids.lock().unwrap().extend([discovery, operation]);
            self.subscription_filters.lock().unwrap().push(filter);
            self.subscription_policies.lock().unwrap().push(limits);
            let stream = self
                .subscription_streams
                .lock()
                .unwrap()
                .pop_front()
                .expect("one fixture stream per admitted listen");
            if self.cancel.load(Ordering::SeqCst) {
                cancellation.cancel();
            }
            Ok(stream)
        })
    }
}

struct Response {
    result: Option<CoreResult>,
    cancellation: McpRequestCancellation,
    cancel: bool,
    suspend: bool,
    fail: bool,
    drops: Arc<AtomicUsize>,
}
impl MachineResponse for Response {
    fn next_event<'a>(
        &'a mut self,
        _cx: &'a Cx,
    ) -> BoxFuture<'a, McpResult<Option<ManagedCoreEvent>>> {
        Box::pin(async move {
            if self.suspend {
                pending::<()>().await;
            }
            if self.cancel {
                self.cancellation.cancel();
            }
            if self.fail {
                return Err(McpError::invalid_request(MACHINE_FAILURE));
            }
            Ok(self
                .result
                .take()
                .map(|result| ManagedCoreEvent::Result(Box::new(result))))
        })
    }
}
impl Drop for Response {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn all_catalogs_install_existing_exact_handlers_and_route_bound_completions() {
    let source = source(vec![]);
    let provider = ClientCredentialsProvider::from_source(source.clone())
        .with_namespace("machine")
        .unwrap();
    let cx = Cx::for_testing();
    let tool = ready(provider.tools(&cx)).unwrap().pop().unwrap();
    assert_eq!(tool.catalog_definition().name, "machine/lookup");
    assert_eq!(
        tool.catalog_definition().title.as_deref(),
        Some("Machine lookup")
    );
    assert!(tool.upstream_final_tool_schema_registration().is_some());
    assert!(!tool.declares_final_tasks());
    let resource = ready(provider.resources(&cx)).unwrap().pop().unwrap();
    assert_eq!(
        resource.catalog_definition().uri.as_str(),
        "note://documents/one"
    );
    let prompt = ready(provider.prompts(&cx)).unwrap().pop().unwrap();
    assert_eq!(prompt.catalog_definition().name, "machine/summarize");
    assert_eq!(
        prompt.catalog_definition().arguments.as_ref().unwrap()[0].required,
        Some(false)
    );
    assert!(prompt.completion_handler().is_ok());
    let template = ready(provider.resource_templates(&cx))
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        template.catalog_definition().uri_template,
        "note://documents/{name}"
    );
    assert!(template.completion_handler().is_ok());
    assert!(source.calls.lock().unwrap().is_empty());
}

#[test]
fn calls_preserve_exact_results_and_only_rewrite_published_names() {
    let source = source(vec![
        TOOL_RESULT,
        RESOURCE_RESULT,
        PROMPT_RESULT,
        RESOURCE_RESULT,
        COMPLETION_RESULT,
    ]);
    let provider = ClientCredentialsProvider::from_source(source.clone())
        .with_namespace("machine")
        .unwrap();
    let cx = Cx::for_testing();
    let ctx = McpContext::new(cx.clone(), 81);
    let tool = ready(provider.tools(&cx)).unwrap().pop().unwrap();
    let result = ready(tool.call_final_async_in_request(
        &ctx,
        &cx,
        json!({
            "_meta":{"authorization":"ordinary argument"},"key":"日本語"
        }),
    ))
    .unwrap();
    let actual = CoreResult::Final(FinalCoreResult::ToolsCall {
        result,
        diagnostic: None,
    })
    .encode()
    .unwrap();
    let expected = decode("tools/call", json!({"name":"lookup"}), TOOL_RESULT)
        .encode()
        .unwrap();
    assert_eq!(actual, expected);
    assert!(
        actual.contains("900719925474099312345") && actual.contains("1.20e+4"),
        "{actual}"
    );
    let resource = ready(provider.resources(&cx)).unwrap().pop().unwrap();
    let result = ready(resource.read_final_async_with_uri_in_request(
        &ctx,
        &cx,
        "note://documents/one",
        &UriParams::new(),
    ))
    .unwrap();
    assert_eq!(
        CoreResult::Final(FinalCoreResult::ResourcesRead {
            result,
            diagnostic: None
        })
        .encode()
        .unwrap(),
        decode(
            "resources/read",
            json!({"uri":"note://documents/one"}),
            RESOURCE_RESULT
        )
        .encode()
        .unwrap()
    );
    let prompt = ready(provider.prompts(&cx)).unwrap().pop().unwrap();
    assert!(
        ready(prompt.get_final_async_in_request(
            &ctx,
            &cx,
            HashMap::from([("subject".to_owned(), "日本語".to_owned())])
        ))
        .is_ok()
    );
    let template = ready(provider.resource_templates(&cx))
        .unwrap()
        .pop()
        .unwrap();
    let outcome = ready(template.read_final_async_with_uri_in_request(
        &ctx,
        &cx,
        "note://documents/one",
        &UriParams::new(),
    ));
    assert!(
        outcome.is_ok(),
        "{}",
        if outcome.is_err() {
            "Err"
        } else if outcome.is_cancelled() {
            "Cancelled"
        } else {
            "Panicked"
        }
    );
    let completion = prompt.completion_handler().unwrap();
    let parameters: FinalCompletionParams = serde_json::from_value(json!({
        "_meta":{},
        "ref":{"type":"ref/prompt","name":"machine/summarize"},
        "argument":{"name":"subject","value":"o"}
    }))
    .unwrap();
    let outcome = ready(completion.complete_final_async_in_request(&ctx, &cx, parameters));
    assert!(
        outcome.is_ok(),
        "{}",
        if outcome.is_err() {
            "Err"
        } else if outcome.is_cancelled() {
            "Cancelled"
        } else {
            "Panicked"
        }
    );
    let calls = source.calls.lock().unwrap();
    assert_eq!(calls.len(), 5);
    assert_eq!(calls[0]["name"], "lookup");
    assert_eq!(
        calls[0]["arguments"]["_meta"]["authorization"],
        "ordinary argument"
    );
    assert_eq!(calls[1]["uri"], "note://documents/one");
    assert_eq!(calls[2]["name"], "summarize");
    assert_eq!(calls[2]["arguments"]["subject"], "日本語");
    assert_eq!(calls[4]["ref"]["name"], "summarize");
    for call in calls.iter() {
        assert!(
            call["_meta"].get("authorization").is_none(),
            "{:?}",
            call["_meta"]
        );
        assert_eq!(
            call["_meta"][fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY],
            json!({})
        );
    }
    let ids = source.ids.lock().unwrap();
    let unique: HashSet<String> = ids
        .iter()
        .map(|id| serde_json::to_string(id).unwrap())
        .collect();
    assert_eq!(ids.len(), 2 * (4 + 5));
    assert_eq!(unique.len(), ids.len());
}

#[test]
fn duplicate_catalogs_and_route_substitution_fail_without_partial_execution() {
    let source = source(vec![RESOURCE_RESULT]);
    let provider = ClientCredentialsProvider::from_source(source.clone());
    let cx = Cx::for_testing();
    {
        let mut catalogs = source.catalogs.lock().unwrap();
        let pages = catalogs.get_mut("tools/list").unwrap();
        pages.push(pages[0].clone());
    }
    assert!(ready(provider.tools(&cx)).is_err());
    let resource = ready(provider.resources(&cx)).unwrap().pop().unwrap();
    let ctx = McpContext::new(cx.clone(), 81);
    let before = source.ids.lock().unwrap().len();
    assert!(
        ready(resource.read_final_async_with_uri_in_request(
            &ctx,
            &cx,
            "note://documents/another-owner",
            &UriParams::new()
        ))
        .is_err()
    );
    assert!(source.calls.lock().unwrap().is_empty());
    assert_eq!(source.ids.lock().unwrap().len(), before);
}

#[test]
fn cancellation_before_or_during_a_call_never_publishes_a_result() {
    for late in [false, true] {
        let source = source(vec![TOOL_RESULT]);
        let provider = ClientCredentialsProvider::from_source(source.clone());
        let cx = Cx::for_testing();
        let tool = ready(provider.tools(&cx)).unwrap().pop().unwrap();
        let ctx = McpContext::new(cx.clone(), 81);
        source.cancel.store(late, Ordering::SeqCst);
        if !late {
            ctx.request_cancellation().cancel();
        }
        let result = ready(tool.call_final_async_in_request(&ctx, &cx, json!({})));
        assert!(result.is_err());
        assert_eq!(source.calls.lock().unwrap().len(), usize::from(late));
        assert_eq!(source.drops.load(Ordering::SeqCst), usize::from(late));
    }
}

#[test]
fn abandoning_a_parked_handler_releases_its_response_owner() {
    let source = source(vec![TOOL_RESULT]);
    source.suspend.store(true, Ordering::SeqCst);
    let provider = ClientCredentialsProvider::from_source(source.clone());
    let cx = Cx::for_testing();
    let tool = ready(provider.tools(&cx)).unwrap().pop().unwrap();
    let ctx = McpContext::new(cx.clone(), 81);
    {
        let mut call = tool.call_final_async_in_request(&ctx, &cx, json!({}));
        assert!(
            call.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(source.drops.load(Ordering::SeqCst), 0);
    }
    assert_eq!(source.calls.lock().unwrap().len(), 1);
    assert_eq!(source.drops.load(Ordering::SeqCst), 1);
    assert!(!ctx.request_cancellation().is_cancel_requested());
}

#[test]
fn failed_and_input_required_operations_are_not_replayed() {
    for (wire, fail) in [
        (TOOL_RESULT, true),
        (
            r#"{"resultType":"input_required","requestState":"opaque"}"#,
            false,
        ),
    ] {
        let source = source(vec![wire, TOOL_RESULT]);
        source.fail.store(fail, Ordering::SeqCst);
        let provider = ClientCredentialsProvider::from_source(source.clone());
        let cx = Cx::for_testing();
        let tool = ready(provider.tools(&cx)).unwrap().pop().unwrap();
        let ctx = McpContext::new(cx.clone(), 81);
        assert!(ready(tool.call_final_async_in_request(&ctx, &cx, json!({}))).is_err());
        assert_eq!(source.calls.lock().unwrap().len(), 1);
        assert_eq!(source.replies.lock().unwrap().len(), 1);
        assert_eq!(source.drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn provider_clones_share_ids_and_policy_changes_do_not_replace_handlers() {
    let source = source(vec![TOOL_RESULT, TOOL_RESULT]);
    let provider = ClientCredentialsProvider::from_source(source.clone());
    let clone = provider
        .clone()
        .with_namespace("second")
        .unwrap()
        .with_limits(
            ManagedCoreLimits::default(),
            ClientCredentialsCatalogLimits::default(),
        );
    let cx = Cx::for_testing();
    let first = ready(provider.tools(&cx)).unwrap().pop().unwrap();
    let second = ready(clone.tools(&cx)).unwrap().pop().unwrap();
    assert_eq!(first.catalog_definition().name, "lookup");
    assert_eq!(second.catalog_definition().name, "second/lookup");
    let ctx = McpContext::new(cx.clone(), 81);
    assert!(ready(first.call_final_async_in_request(&ctx, &cx, json!({}))).is_ok());
    assert!(ready(second.call_final_async_in_request(&ctx, &cx, json!({}))).is_ok());
    let ids = source.ids.lock().unwrap();
    for (index, id) in ids.iter().enumerate() {
        assert!(
            ids[..index]
                .iter()
                .all(|previous| !id.correlates_with(previous))
        );
    }
    assert!(provider.clone().with_namespace("bad/namespace").is_err());
    assert!(provider.with_namespace("").is_err());
}

#[test]
fn native_failures_preserve_cancellation_but_expose_no_auth_details() {
    for cause in [
        OAuthDiscoveryError::Cancelled,
        OAuthDiscoveryError::TimedOut,
    ] {
        let error = machine_error(ClientCredentialsCoreError::Authentication(
            ClientCredentialsError::Discovery(cause),
        ));
        assert_eq!(error.code, McpErrorCode::RequestCancelled);
    }
    assert_eq!(
        machine_error(ClientCredentialsCoreError::Authentication(
            ClientCredentialsError::InvalidToken,
        ))
        .message,
        MACHINE_FAILURE
    );
    assert_eq!(
        catalog_error(ClientCredentialsCatalogError::Catalog(
            ManagedCatalogError::AbortedByHost,
        ))
        .message,
        CATALOG_FAILURE
    );
}

#[test]
fn partial_pair_allocation_never_wraps_or_reuses_an_id() {
    let ids = AtomicU64::new(u64::MAX - 1);
    assert!(next_pair(&ids).is_err());
    assert_eq!(ids.load(Ordering::Relaxed), u64::MAX);
    assert!(next_pair(&ids).is_err());
    assert_eq!(ids.load(Ordering::Relaxed), u64::MAX);
}

struct NoInput;
impl ManagedOAuthInputHandler for NoInput {
    fn resolve<'a>(
        &'a self,
        _ctx: &'a McpContext,
        _cx: &'a Cx,
        _input: Box<InputRequiredResult>,
    ) -> BoxFuture<'a, McpResult<Option<FinalInputResponses>>> {
        panic!("these complete response fixtures have no host input")
    }
}

#[test]
fn configured_inputs_reach_all_execution_routes_but_not_old_handlers_or_completion() {
    for mode in [
        ManagedOAuthInputResponseMode::Complete,
        ManagedOAuthInputResponseMode::Partial,
    ] {
        let source = source(vec![
            TOOL_RESULT,
            TOOL_RESULT,
            RESOURCE_RESULT,
            PROMPT_RESULT,
            RESOURCE_RESULT,
            COMPLETION_RESULT,
        ]);
        let provider = ClientCredentialsProvider::from_source(source.clone());
        let cx = Cx::for_testing();
        let old_tool = ready(provider.tools(&cx)).unwrap().pop().unwrap();
        let policy = ManagedOAuthInputPolicy::new(
            ManagedOAuthInputCapabilities {
                roots: true,
                ..Default::default()
            },
            3,
            8,
        )
        .unwrap()
        .with_response_mode(mode);
        let calls = ManagedCoreLimits::new(4096, 4096, 8192, 32, Duration::from_secs(7)).unwrap();
        let configured = provider
            .clone()
            .with_input_handler(policy, Arc::new(NoInput))
            .with_limits(calls, ClientCredentialsCatalogLimits::default())
            .with_namespace("interactive")
            .unwrap();
        let ctx = McpContext::new(cx.clone(), 81);
        let outcome = ready(old_tool.call_final_async_in_request(&ctx, &cx, json!({})));
        assert!(
            outcome.is_ok(),
            "{}",
            if outcome.is_err() {
                "Err"
            } else if outcome.is_cancelled() {
                "Cancelled"
            } else {
                "Panicked"
            }
        );
        let tool = ready(configured.tools(&cx)).unwrap().pop().unwrap();
        assert_eq!(tool.catalog_definition().name, "interactive/lookup");
        let outcome = ready(tool.call_final_async_in_request(&ctx, &cx, json!({})));
        assert!(
            outcome.is_ok(),
            "{}",
            if outcome.is_err() {
                "Err"
            } else if outcome.is_cancelled() {
                "Cancelled"
            } else {
                "Panicked"
            }
        );
        let resource = ready(configured.resources(&cx)).unwrap().pop().unwrap();
        let outcome = ready(resource.read_final_async_with_uri_in_request(
            &ctx,
            &cx,
            "note://documents/one",
            &UriParams::new(),
        ));
        assert!(
            outcome.is_ok(),
            "{}",
            if outcome.is_err() {
                "Err"
            } else if outcome.is_cancelled() {
                "Cancelled"
            } else {
                "Panicked"
            }
        );
        let prompt = ready(configured.prompts(&cx)).unwrap().pop().unwrap();
        let outcome = ready(prompt.get_final_async_in_request(&ctx, &cx, HashMap::new()));
        assert!(
            outcome.is_ok(),
            "{}",
            if outcome.is_err() {
                "Err"
            } else if outcome.is_cancelled() {
                "Cancelled"
            } else {
                "Panicked"
            }
        );
        let template = ready(configured.resource_templates(&cx))
            .unwrap()
            .pop()
            .unwrap();
        let outcome = ready(template.read_final_async_with_uri_in_request(
            &ctx,
            &cx,
            "note://documents/one",
            &UriParams::new(),
        ));
        assert!(
            outcome.is_ok(),
            "{}",
            if outcome.is_err() {
                "Err"
            } else if outcome.is_cancelled() {
                "Cancelled"
            } else {
                "Panicked"
            }
        );
        let completion = prompt.completion_handler().unwrap();
        let params: FinalCompletionParams = serde_json::from_value(json!({
            "_meta":{},
            "ref":{"type":"ref/prompt","name":"interactive/summarize"},
            "argument":{"name":"subject","value":"o"}
        }))
        .unwrap();
        let outcome = ready(completion.complete_final_async_in_request(&ctx, &cx, params));
        assert!(
            outcome.is_ok(),
            "{}",
            if outcome.is_err() {
                "Err"
            } else if outcome.is_cancelled() {
                "Cancelled"
            } else {
                "Panicked"
            }
        );
        // Observe the actual MachineCall handed to the transport, not policy
        // fields at construction. Native source owns authentication/HTTP; this
        // test establishes only production policy routing and handler wiring.
        assert_eq!(
            *source.input_modes.lock().unwrap(),
            [None, Some(mode), Some(mode), Some(mode), Some(mode), None]
        );
        let policies = source.call_policies.lock().unwrap();
        assert_eq!(policies[0], format!("{:?}", ManagedCoreLimits::default()));
        let configured_policy = format!("{calls:?}");
        assert!(
            policies[1..]
                .iter()
                .all(|policy| policy == &configured_policy),
            "policies {policies:?} against {configured_policy}"
        );
        let calls = source.calls.lock().unwrap();
        let capability_key = fastmcp_protocol::FINAL_CLIENT_CAPABILITIES_META_KEY;
        assert_eq!(calls[0]["_meta"][capability_key], json!({}));
        for request in &calls[1..5] {
            assert_eq!(request["_meta"][capability_key], json!({"roots":{}}));
            assert!(
                request["_meta"].get("authorization").is_none(),
                "{:?}",
                request["_meta"]
            );
        }
        assert_eq!(calls[5]["_meta"][capability_key], json!({}));
        let ids = source.ids.lock().unwrap();
        for (index, id) in ids.iter().enumerate() {
            assert!(
                ids[..index]
                    .iter()
                    .all(|previous| !id.correlates_with(previous)),
                "id {index} of {} correlates with an earlier one",
                ids.len()
            );
        }
    }
}

// These fixtures replace only the already-authorized native stream. The public
// provider path, selector origin, shared ID allocator, acknowledgment handling,
// resource projection and real downstream publisher are production code. Native
// TLS, same-token discovery and credential expiry remain client-layer tests.
enum ResourceStreamStep {
    Record(ManagedSubscriptionEvent),
    Failure(McpError),
    Park,
}

#[derive(Default)]
struct ResourceStreamProbe {
    reads: AtomicUsize,
    closes: AtomicUsize,
    drops: AtomicUsize,
}

struct ResourceStream {
    steps: VecDeque<ResourceStreamStep>,
    probe: Arc<ResourceStreamProbe>,
    closed: bool,
}

impl ResourceUpdateStream for ResourceStream {
    fn credential_generation(&self) -> u64 {
        23
    }

    fn close(&mut self) {
        self.closed = true;
        self.probe.closes.fetch_add(1, Ordering::SeqCst);
    }

    fn next_event<'a>(
        &'a mut self,
        _cx: &'a Cx,
    ) -> BoxFuture<'a, McpResult<Option<ManagedSubscriptionEvent>>> {
        Box::pin(async move {
            if self.closed {
                return Err(McpError::invalid_request("fixture stream closed"));
            }
            self.probe.reads.fetch_add(1, Ordering::SeqCst);
            match self.steps.pop_front() {
                Some(ResourceStreamStep::Record(event)) => Ok(Some(event)),
                Some(ResourceStreamStep::Failure(error)) => Err(error),
                Some(ResourceStreamStep::Park) => pending().await,
                None => Ok(None),
            }
        })
    }
}

impl Drop for ResourceStream {
    fn drop(&mut self) {
        self.probe.drops.fetch_add(1, Ordering::SeqCst);
    }
}

fn queue_resource_stream(
    source: &Source,
    steps: Vec<ResourceStreamStep>,
) -> Arc<ResourceStreamProbe> {
    let probe = Arc::new(ResourceStreamProbe::default());
    source
        .subscription_streams
        .lock()
        .unwrap()
        .push_back(Box::new(ResourceStream {
            steps: steps.into(),
            probe: Arc::clone(&probe),
            closed: false,
        }));
    probe
}

fn resource_ack(uris: &[&str]) -> ResourceStreamStep {
    ResourceStreamStep::Record(ManagedSubscriptionEvent::Acknowledged {
        accepted_filter: SubscriptionFilter {
            resource_subscriptions: Some(uris.iter().map(|uri| (*uri).to_owned()).collect()),
            ..Default::default()
        },
    })
}

fn resource_update_record(uri: &str) -> ResourceStreamStep {
    let mut additional = std::collections::BTreeMap::new();
    additional.insert(
        "upstreamPrivate".to_owned(),
        json!("private extension value"),
    );
    let notification =
        ServerNotification::ResourceUpdated(FinalResourceUpdatedNotificationParams {
            uri: fastmcp_protocol::common_types::AbsoluteUri::parse(uri).unwrap(),
            meta: Some(
                serde_json::from_value(json!({
                    FINAL_SUBSCRIPTION_ID_META_KEY: "machine-upstream-id",
                    "com.example/private": "upstream private authority"
                }))
                .unwrap(),
            ),
            additional,
        });
    ResourceStreamStep::Record(
        machine_subscription_event(ModernHttpSubscriptionListenEvent::Notification(
            notification,
        ))
        .unwrap(),
    )
}

fn resource_terminal(cancelled: bool) -> ResourceStreamStep {
    let native = if cancelled {
        ModernHttpSubscriptionListenEvent::Cancelled {
            subscription_id: RequestId::Number(73),
            params: FinalCancelledNotificationParams {
                request_id: RequestId::Number(73),
                reason: Some("private upstream cancellation reason".to_owned()),
                meta: None,
                additional: std::collections::BTreeMap::new(),
            },
        }
    } else {
        let CoreResult::Final(FinalCoreResult::SubscriptionsListen {
            result,
            subscription_id,
            ..
        }) = decode(
            "subscriptions/listen",
            json!({"notifications": {}}),
            r#"{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":73}}"#,
        )
        else {
            panic!("the authoritative protocol decoder must admit a listen terminal");
        };
        ModernHttpSubscriptionListenEvent::Terminal {
            subscription_id,
            result,
        }
    };
    ResourceStreamStep::Record(machine_subscription_event(native).unwrap())
}

fn selected_resource(
    provider: &ClientCredentialsProvider,
    cx: &Cx,
) -> ManagedOAuthResourceSelector {
    ready(provider.resources(cx))
        .unwrap()
        .pop()
        .unwrap()
        .update_subscription()
}

#[test]
fn machine_resource_updates_preserve_exact_uris_and_shared_ids() {
    let source = source(vec![]);
    let provider = ClientCredentialsProvider::from_source(source.clone())
        .with_namespace("machine")
        .unwrap();
    let cx = Cx::for_testing();
    let concrete = selected_resource(&provider, &cx);
    let template = ready(provider.resource_templates(&cx))
        .unwrap()
        .pop()
        .unwrap();
    let exact = "note://documents/a%2Fb";
    let selected = vec![concrete, template.update_subscription(exact).unwrap()];
    let probe = queue_resource_stream(
        &source,
        vec![
            resource_ack(&["note://documents/one", exact]),
            resource_terminal(false),
        ],
    );
    let clone = provider.clone().with_namespace("another").unwrap();
    let limits = ClientCredentialsCoreSubscriptionLimits::new(
        32 * 1024,
        32 * 1024,
        4,
        Duration::from_secs(19),
    )
    .unwrap();
    let updates =
        ready(clone.open_resource_updates(&cx, &McpRequestCancellation::new(), &selected, limits))
            .unwrap();
    assert_eq!(updates.credential_generation(), 23);
    assert_eq!(
        updates.accepted_resources(),
        &["note://documents/one".to_owned(), exact.to_owned()],
    );
    let filters = source.subscription_filters.lock().unwrap();
    assert_eq!(
        filters[0].resource_subscriptions.as_deref(),
        Some(["note://documents/one".to_owned(), exact.to_owned()].as_slice()),
    );
    assert!(filters[0].additional.is_empty());
    assert!(filters[0].tools_list_changed.is_none());
    drop(filters);
    let policies = source.subscription_policies.lock().unwrap();
    assert_eq!(policies[0].timeout(), Duration::from_secs(19));
    assert_eq!(policies[0].request_bytes(), 32 * 1024);
    assert_eq!(policies[0].frame_bytes(), 32 * 1024);
    assert_eq!(policies[0].records(), 4);
    drop(policies);
    let ids = source.ids.lock().unwrap();
    assert_eq!(ids.len(), 6, "two catalog pairs and one subscription pair");
    for (index, id) in ids.iter().enumerate() {
        assert!(
            ids[..index]
                .iter()
                .all(|previous| !id.correlates_with(previous))
        );
    }
    drop(ids);
    let outcome = ready(updates.relay(&cx, |_| {
        panic!("an ACK and terminal must never be relayed as resource updates")
    }))
    .unwrap();
    assert_eq!(
        outcome,
        ManagedOAuthResourceRelayOutcome {
            end: ManagedOAuthResourceRelayEnd::Complete,
            forwarded_updates: 0,
            downstream_deliveries: 0,
        }
    );
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn machine_resource_updates_reject_foreign_and_invalid_selectors_before_io() {
    let source = source(vec![]);
    let provider = ClientCredentialsProvider::from_source(source.clone());
    let cx = Cx::for_testing();
    let selected = selected_resource(&provider, &cx);
    let foreign_source = self::source(vec![]);
    let foreign = ClientCredentialsProvider::from_source(foreign_source);
    let foreign_selection = selected_resource(&foreign, &cx);
    let template = ready(provider.resource_templates(&cx))
        .unwrap()
        .pop()
        .unwrap();
    let oversized = (0..20)
        .map(|index| {
            template
                .update_subscription(&format!("note://documents/{index}{}", "a".repeat(15_000)))
                .unwrap()
        })
        .collect::<Vec<_>>();
    let ids_before = source.ids.lock().unwrap().len();
    for selection in [
        Vec::new(),
        vec![selected.clone(), selected.clone()],
        vec![foreign_selection],
        vec![selected.clone(); fastmcp_protocol::MAX_RESOURCE_SUBSCRIPTIONS + 1],
        oversized,
    ] {
        assert!(
            ready(provider.open_resource_updates(
                &cx,
                &McpRequestCancellation::new(),
                &selection,
                ClientCredentialsCoreSubscriptionLimits::default(),
            ))
            .is_err()
        );
        assert!(source.subscription_filters.lock().unwrap().is_empty());
        assert_eq!(source.ids.lock().unwrap().len(), ids_before);
    }
    let cancellation = McpRequestCancellation::new();
    cancellation.cancel();
    let error = ready(provider.open_resource_updates(
        &cx,
        &cancellation,
        std::slice::from_ref(&selected),
        ClientCredentialsCoreSubscriptionLimits::default(),
    ))
    .err()
    .unwrap();
    assert_eq!(error.code, McpErrorCode::RequestCancelled);
    assert_eq!(source.ids.lock().unwrap().len(), ids_before);
    let probe = queue_resource_stream(
        &source,
        vec![
            resource_ack(&["note://documents/one"]),
            resource_terminal(false),
        ],
    );
    let updates = ready(provider.open_resource_updates(
        &cx,
        &McpRequestCancellation::new(),
        &[selected],
        ClientCredentialsCoreSubscriptionLimits::default(),
    ))
    .unwrap();
    assert!(ready(updates.relay(&cx, |_| Ok(0))).is_ok());
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn machine_resource_updates_require_ack_and_honor_narrowing() {
    let source = source(vec![]);
    let provider = ClientCredentialsProvider::from_source(source.clone());
    let cx = Cx::for_testing();
    let concrete = selected_resource(&provider, &cx);
    let template = ready(provider.resource_templates(&cx))
        .unwrap()
        .pop()
        .unwrap();
    let other_uri = "note://documents/two";
    let selected = vec![concrete, template.update_subscription(other_uri).unwrap()];
    for opening in [vec![], vec![resource_update_record("note://documents/one")]] {
        let probe = queue_resource_stream(&source, opening);
        assert!(
            ready(provider.open_resource_updates(
                &cx,
                &McpRequestCancellation::new(),
                &selected,
                ClientCredentialsCoreSubscriptionLimits::default(),
            ))
            .is_err()
        );
        assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    }
    for accepted in [vec!["note://documents/one"], vec![]] {
        let probe = queue_resource_stream(
            &source,
            vec![resource_ack(&accepted), resource_terminal(false)],
        );
        let updates = ready(provider.open_resource_updates(
            &cx,
            &McpRequestCancellation::new(),
            &selected,
            ClientCredentialsCoreSubscriptionLimits::default(),
        ))
        .unwrap();
        assert_eq!(
            updates
                .accepted_resources()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            accepted,
        );
        assert!(ready(updates.relay(&cx, |_| Ok(0))).is_ok());
        assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    }
    let probe = queue_resource_stream(
        &source,
        vec![
            resource_ack(&["note://documents/one"]),
            resource_update_record(other_uri),
        ],
    );
    let updates = ready(provider.open_resource_updates(
        &cx,
        &McpRequestCancellation::new(),
        &selected,
        ClientCredentialsCoreSubscriptionLimits::default(),
    ))
    .unwrap();
    let mut published = 0;
    assert!(
        ready(updates.relay(&cx, |_| {
            published += 1;
            Ok(1)
        }))
        .is_err()
    );
    assert_eq!(
        published, 0,
        "a requested but unaccepted URI is never published"
    );
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn machine_resource_updates_strip_authority_and_use_downstream_publisher() {
    let source = source(vec![]);
    let provider = ClientCredentialsProvider::from_source(source.clone());
    let cx = Cx::for_testing();
    let template = ready(provider.resource_templates(&cx))
        .unwrap()
        .pop()
        .unwrap();
    let uri = "note://documents/a%2Fb";
    let selected = template.update_subscription(uri).unwrap();
    let probe = queue_resource_stream(
        &source,
        vec![
            resource_ack(&[uri]),
            resource_update_record(uri),
            resource_terminal(false),
        ],
    );
    let server = crate::Server::new("machine-resource-relay", "1").build();
    let publisher = server.subscription_publisher();
    let events = Arc::new(Mutex::new(Vec::new()));
    let delivered = Arc::clone(&events);
    let registration = server
        .open_subscription_listen(
            RequestId::String("downstream-selected".to_owned()),
            SubscriptionFilter {
                resource_subscriptions: Some(vec![uri.to_owned()]),
                ..Default::default()
            },
            Arc::new(move |event| delivered.lock().unwrap().push(event)),
        )
        .unwrap();
    let unrelated = server
        .open_subscription_listen(
            RequestId::String("downstream-unrelated".to_owned()),
            SubscriptionFilter {
                resource_subscriptions: Some(vec!["note://documents/a/b".to_owned()]),
                ..Default::default()
            },
            Arc::new(|event| assert_eq!(event.method, "notifications/subscriptions/acknowledged",)),
        )
        .unwrap();
    let updates = ready(provider.open_resource_updates(
        &cx,
        &McpRequestCancellation::new(),
        &[selected],
        ClientCredentialsCoreSubscriptionLimits::default(),
    ))
    .unwrap();
    let outcome = ready(updates.relay(&cx, |event| publisher.publish(event))).unwrap();
    assert_eq!(outcome.forwarded_updates, 1);
    assert_eq!(outcome.downstream_deliveries, 1);
    let observed = events.lock().unwrap();
    assert_eq!(observed.len(), 2);
    let parameters = observed[1].params.as_ref().unwrap();
    assert_eq!(parameters["uri"], uri);
    assert_eq!(
        parameters["_meta"][FINAL_SUBSCRIPTION_ID_META_KEY],
        "downstream-selected",
    );
    assert!(parameters.get("upstreamPrivate").is_none());
    assert!(parameters["_meta"].get("com.example/private").is_none());
    assert!(!parameters.to_string().contains("machine-upstream-id"));
    assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    drop((registration, unrelated));
}

#[test]
fn machine_resource_updates_distinguish_terminals_and_refuse_incomplete_streams() {
    let source = source(vec![]);
    let provider = ClientCredentialsProvider::from_source(source.clone());
    let cx = Cx::for_testing();
    let selected = selected_resource(&provider, &cx);
    for cancelled in [false, true] {
        let cancellation = McpRequestCancellation::new();
        let probe = queue_resource_stream(
            &source,
            vec![
                resource_ack(&["note://documents/one"]),
                resource_update_record("note://documents/one"),
                resource_terminal(cancelled),
            ],
        );
        let updates = ready(provider.open_resource_updates(
            &cx,
            &cancellation,
            std::slice::from_ref(&selected),
            ClientCredentialsCoreSubscriptionLimits::default(),
        ))
        .unwrap();
        let outcome = ready(updates.relay(&cx, |_| Ok(2))).unwrap();
        assert_eq!(
            outcome.end,
            if cancelled {
                ManagedOAuthResourceRelayEnd::Cancelled
            } else {
                ManagedOAuthResourceRelayEnd::Complete
            }
        );
        assert_eq!(outcome.forwarded_updates, 1);
        assert_eq!(outcome.downstream_deliveries, 2);
        assert!(!cancellation.is_cancel_requested());
        assert!(!cx.is_cancel_requested());
        assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    }
    for tail in [
        Vec::new(),
        vec![resource_ack(&["note://documents/one"])],
        vec![ResourceStreamStep::Failure(McpError::request_cancelled())],
    ] {
        let mut steps = vec![resource_ack(&["note://documents/one"])];
        steps.extend(tail);
        let probe = queue_resource_stream(&source, steps);
        let updates = ready(provider.open_resource_updates(
            &cx,
            &McpRequestCancellation::new(),
            std::slice::from_ref(&selected),
            ClientCredentialsCoreSubscriptionLimits::default(),
        ))
        .unwrap();
        let mut published = 0;
        assert!(
            ready(updates.relay(&cx, |_| {
                published += 1;
                Ok(1)
            }))
            .is_err()
        );
        assert_eq!(published, 0);
        assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn machine_resource_updates_cancel_drop_and_sink_failure_preserve_siblings() {
    for mode in 0..5 {
        let source = source(vec![]);
        let provider = ClientCredentialsProvider::from_source(source.clone());
        let cx = Cx::for_testing();
        let selected = selected_resource(&provider, &cx);
        let mut steps = if mode == 1 {
            vec![ResourceStreamStep::Park]
        } else {
            vec![resource_ack(&["note://documents/one"])]
        };
        steps.push(if mode == 2 {
            ResourceStreamStep::Park
        } else {
            resource_update_record("note://documents/one")
        });
        steps.push(resource_terminal(false));
        let probe = queue_resource_stream(&source, steps);
        let cancellation = McpRequestCancellation::new();
        if mode == 0 {
            source.cancel.store(true, Ordering::SeqCst);
            let error = ready(provider.open_resource_updates(
                &cx,
                &cancellation,
                std::slice::from_ref(&selected),
                ClientCredentialsCoreSubscriptionLimits::default(),
            ))
            .err()
            .unwrap();
            assert_eq!(error.code, McpErrorCode::RequestCancelled);
            assert_eq!(probe.reads.load(Ordering::SeqCst), 0);
            source.cancel.store(false, Ordering::SeqCst);
        } else if mode == 1 {
            let mut opening = Box::pin(provider.open_resource_updates(
                &cx,
                &cancellation,
                std::slice::from_ref(&selected),
                ClientCredentialsCoreSubscriptionLimits::default(),
            ));
            assert!(
                opening
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            drop(opening);
        } else {
            let mut updates = ready(provider.open_resource_updates(
                &cx,
                &cancellation,
                std::slice::from_ref(&selected),
                ClientCredentialsCoreSubscriptionLimits::default(),
            ))
            .unwrap();
            if mode == 2 {
                let mut relay = Box::pin(updates.relay(&cx, |_| Ok(0)));
                assert!(
                    relay
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
                drop(relay);
            } else if mode == 3 {
                let mut called = 0;
                assert!(
                    ready(updates.relay(&cx, |_| {
                        called += 1;
                        Err(McpError::invalid_request("downstream publisher closed"))
                    }))
                    .is_err()
                );
                assert_eq!(called, 1);
            } else {
                updates.close();
                assert_eq!(probe.closes.load(Ordering::SeqCst), 1);
                assert!(
                    ready(updates.relay(&cx, |_| {
                        panic!("a closed response cannot publish a queued event")
                    }))
                    .is_err()
                );
            }
        }
        assert_eq!(probe.drops.load(Ordering::SeqCst), 1);
        assert!(!cx.is_cancel_requested());
        let sibling_probe = queue_resource_stream(
            &source,
            vec![
                resource_ack(&["note://documents/one"]),
                resource_terminal(false),
            ],
        );
        let sibling = ready(provider.open_resource_updates(
            &cx,
            &McpRequestCancellation::new(),
            &[selected],
            ClientCredentialsCoreSubscriptionLimits::default(),
        ))
        .unwrap();
        assert!(ready(sibling.relay(&cx, |_| Ok(0))).is_ok());
        assert_eq!(sibling_probe.drops.load(Ordering::SeqCst), 1);
    }
}
