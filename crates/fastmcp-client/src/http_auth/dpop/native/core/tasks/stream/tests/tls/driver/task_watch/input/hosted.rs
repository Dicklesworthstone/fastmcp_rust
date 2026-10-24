//! One public hosted execution through the existing authenticated TLS fixture.
//! Request continuations, Task gets, listen and input updates use real sockets.

use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::common_types::SamplingContentBlock;
use fastmcp_protocol::{
    CoreResult, FinalCoreResult, FinalCreateMessageResult, FinalEmbeddedCreateMessageParams,
    FinalEmbeddedElicitationResult, FinalEmbeddedFormElicitationParams,
    FinalEmbeddedRootsListParams, FinalEmbeddedRootsListResult, FinalEmbeddedUrlElicitationParams,
};
use crate::http_auth::dpop::native::core::tasks::stream::interaction::{
    DpopTaskHostError, DpopTaskHostLimits,
    execution::{DpopTaskHostedExecutionError, DpopTaskHostedExecutionOutcome},
};
use crate::http_auth::sampling::{SamplingHost, SamplingHostError, SamplingHostFuture};
use crate::http_auth::sampling::inputs::mixed::{
    CoreInputHost, CoreInputHostError, CoreInputHostFuture, CoreInputLimits, CoreInputRequest,
};
use crate::http_executor::parameter_headers::ReviewedToolHeaders;

const STATE: &str = "  request-private+/%\0  ";

#[derive(Default)]
struct Host {
    approvals: usize,
    roots: usize,
    deny: bool,
    pending: Option<McpRequestCancellation>,
    drops: Arc<AtomicUsize>,
}

struct DropProbe(Arc<AtomicUsize>);
impl Drop for DropProbe {
    fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
}

impl SamplingHost for Host {
    fn sample<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a FinalEmbeddedCreateMessageParams) -> SamplingHostFuture<'a, FinalCreateMessageResult>
    {
        panic!("a roots-only challenge must not sample");
    }
    fn approve_tools<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a [SamplingContentBlock]) -> SamplingHostFuture<'a, ()>
    {
        Box::pin(async { Err(SamplingHostError::Denied) })
    }
    fn execute_tool<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a SamplingContentBlock) -> SamplingHostFuture<'a, SamplingContentBlock>
    {
        panic!("a roots-only challenge must not execute a sampling tool");
    }
}

impl CoreInputHost for Host {
    fn approve_inputs<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        requests: &'a [CoreInputRequest]) -> CoreInputHostFuture<'a, ()>
    {
        self.approvals += 1;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].key(), "r");
        let deny = self.deny;
        Box::pin(async move { if deny { Err(CoreInputHostError::Denied) } else { Ok(()) } })
    }
    fn roots<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a FinalEmbeddedRootsListParams) -> CoreInputHostFuture<'a, FinalEmbeddedRootsListResult>
    {
        self.roots += 1;
        let pending = self.pending.clone();
        let drops = Arc::clone(&self.drops);
        Box::pin(async move {
            let _probe = DropProbe(drops);
            if let Some(reached) = pending {
                reached.cancel();
                std::future::pending::<()>().await;
            }
            Ok(serde_json::from_value(json!({"roots":[{"uri":"file:///host-private"}]})).unwrap())
        })
    }
    fn form<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a FinalEmbeddedFormElicitationParams) -> CoreInputHostFuture<'a, FinalEmbeddedElicitationResult>
    {
        panic!("a roots-only challenge must not elicit form data");
    }
    fn url<'a>(&'a mut self, _: &'a Cx, _: &'a McpRequestCancellation,
        _: &'a FinalEmbeddedUrlElicitationParams) -> CoreInputHostFuture<'a, FinalEmbeddedElicitationResult>
    {
        panic!("a roots-only challenge must not open a URL");
    }
}

fn hosted_limits(notifications: usize, continuations: usize) -> DpopTaskHostLimits {
    DpopTaskHostLimits::new(watch_limits(notifications), CoreInputLimits::default(), continuations, 4).unwrap()
}

fn initial_operation(target: &str, prefix: &str) -> DpopTaskOperation {
    let review = ReviewedToolHeaders::new(CanonicalHttpUrl::parse(target).unwrap(), "work",
        json!({"type":"object","properties":{
            "region":{"type":"string","x-mcp-header":"Region"},
            "private":{"type":"string","writeOnly":true}
        }}), |_| true).unwrap();
    DpopTaskOperation::new(
        RequestId::String(format!("{prefix}.begin.discover")),
        RequestId::String(format!("{prefix}.begin.tool")),
        ManagedTaskRequest::CallTool {
            name:"work".to_owned(), arguments:Some(json!({"region":"eu","private":"body-private"})),
        },
    ).unwrap().with_reviewed_tool_headers(Arc::new(review)).unwrap()
}

fn round_id(prefix: &str, round: usize, discover: bool) -> String {
    let suffix = if discover { "discover" } else { "tool" };
    if round == 0 { format!("{prefix}.begin.{suffix}") } else { format!("{prefix}:{round}:{suffix}") }
}

fn reply(prefix: &str, round: usize, discover: bool, result: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":round_id(prefix, round, discover),"result":result})).unwrap()
}

fn challenge() -> Value {
    json!({"resultType":"input_required", "requestState":STATE,
        "inputRequests":{"r":{"method":"roots/list"}}})
}

fn creation(status: &str) -> Value {
    let mut result = task_result(status);
    result["resultType"] = json!("task");
    result["_meta"] = json!({"example.com/creation":"preserved"});
    result
}

impl Peer {
    async fn hosted_tool(&mut self, prefix: &str, round: usize) -> TlsStream<TcpStream> {
        let (mut discovery, body) = self.receive_named(&round_id(prefix, round, true), "server/discover").await;
        assert_eq!(body["params"].as_object().unwrap().len(), 1,
            "discovery must not receive arguments, answers or requestState");
        json_reply(&mut discovery, &reply(prefix, round, true, &discovery_result())).await;
        let (tcp, _) = self.listener.accept().await.unwrap();
        let mut socket = self.acceptor.accept(tcp).await.unwrap();
        let (head, body) = read(&mut socket).await;
        assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
        assert_eq!(body["id"], round_id(prefix, round, false));
        assert_eq!(body["method"], "tools/call");
        assert_eq!(body["params"]["name"], "work");
        assert_eq!(body["params"]["arguments"], json!({"region":"eu","private":"body-private"}));
        assert_eq!(header(&head, "authorization"), "DPoP stream-task-token");
        assert_eq!(header(&head, "mcp-method"), "tools/call");
        assert_eq!(header(&head, "mcp-name"), "work");
        assert_eq!(header(&head, "mcp-param-region"), "eu");
        assert_eq!(header(&head, "accept"), "application/json, text/event-stream");
        for private in ["body-private", "request-private", "host-private"] {
            assert!(!head.contains(private), "body-only values must not become headers");
        }
        let proof = claims(header(&head, "dpop"));
        assert_eq!(proof["htm"], "POST");
        assert_eq!(proof["htu"], self.target.split('?').next().unwrap());
        assert_eq!(proof["nonce"], "stream-next");
        assert!(proof["ath"].as_str().is_some_and(|value| !value.is_empty()));
        assert!(self.proofs.insert(proof["jti"].as_str().unwrap().to_owned()));
        let expected = serde_json::to_value(driver_metadata()).unwrap();
        assert_eq!(body["params"]["_meta"]["progressToken"], expected["progressToken"]);
        assert_eq!(body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
            json!({"roots":{},"extensions":{TASKS_EXTENSION:{}}}));
        if round == 0 {
            assert!(body["params"].get("inputResponses").is_none());
            assert!(body["params"].get("requestState").is_none());
        } else {
            assert_eq!(body["params"]["requestState"], STATE);
            assert_eq!(body["params"]["inputResponses"], json!({"r":{"roots":[{"uri":"file:///host-private"}]}}));
        }
        socket
    }

    async fn hosted_reply(&mut self, prefix: &str, round: usize, result: &Value, json: bool) {
        let mut socket = self.hosted_tool(prefix, round).await;
        let bytes = reply(prefix, round, false, result);
        if json { json_reply(&mut socket, &bytes).await; }
        else { streamed_reply(&mut socket, &bytes, None, false).await; }
    }
}

#[test]
fn hosted_conversation_preserves_reviews_and_drives_subscribed_partial_task_inputs() {
    for json_tool in [false, true] {
        for json_task in [false, true] {
            run(async {
                let cx = Cx::current().unwrap();
                let (mut peer, mut client, credential) = Peer::new().await;
                let cancellation = McpRequestCancellation::new();
                let operation = initial_operation(&peer.target, "hosted");
                let limits = hosted_limits(16, 2);
                let mut host = Host::default();
                let (mut resolutions, mut snapshots, mut notifications) = (0, 0, 0);
                let application = client.execute_and_drive_task_with_input_host(
                    &cx, &cancellation, &credential, driver_metadata(), operation, "hosted",
                    &limits, policy(4, 2), &mut host,
                    |requests| {
                        assert_eq!(requests.keys().map(String::as_str).collect::<Vec<_>>(),
                            if resolutions == 0 { vec!["one", "two"] } else { vec!["two"] });
                        let key = if resolutions == 0 { "one" } else { "two" };
                        resolutions += 1;
                        std::future::ready(Ok(ManagedTaskInputAction::Respond(answer(key))))
                    },
                    |_| { snapshots += 1; Ok(()) },
                    |_| { notifications += 1; true },
                );
                let server = async {
                    peer.hosted_reply("hosted", 0, &challenge(), json_tool).await;
                    peer.hosted_reply("hosted", 1, &creation("working"), json_tool).await;
                    get_reply(&mut peer, "hosted", 0, &task_result("working"), json_task).await;
                    let mut listen = peer.watch_listen("hosted").await;
                    listen.write_all(HEAD).await.unwrap();
                    event(&mut listen, &watch_ack("hosted", true)).await;
                    get_reply(&mut peer, "hosted", 1, &input_task(&["one", "two"]), json_task).await;
                    acknowledge(&mut peer, "hosted", 0, "one", json_task).await;
                    // No status hint authorizes the second answer: the clean
                    // update acknowledgement must trigger a real get itself.
                    get_reply(&mut peer, "hosted", 2, &input_task(&["one", "two"]), json_task).await;
                    acknowledge(&mut peer, "hosted", 1, "two", json_task).await;
                    let mut final_task = task_result("cancelled");
                    final_task["_meta"] = json!({"example.com/final":"preserved"});
                    get_reply(&mut peer, "hosted", 3, &final_task, json_task).await;
                    assert_watch_closed(&mut listen).await;
                };
                let (result, ()) = pair(application, server).await;
                let DpopTaskHostedExecutionOutcome::Observed { initial, outcome } = result.unwrap()
                    else { panic!("expected the authoritative Task outcome") };
                assert_eq!(initial.continuations, 1);
                assert_eq!((initial.usage.resolutions, initial.usage.selected_inputs, initial.usage.roots), (1, 1, 1));
                let encoded = CoreResult::Final(*initial.result).encode().unwrap();
                let encoded: Value = serde_json::from_str(&encoded).unwrap();
                assert_eq!(encoded["_meta"]["example.com/creation"], "preserved");
                let DpopTaskWaitOutcome::Terminal(snapshot) = outcome else { panic!("terminal Task required") };
                assert!(matches!(&snapshot.task, Task::Cancelled(_)));
                assert_eq!(serde_json::to_value(&*snapshot).unwrap()["_meta"]["example.com/final"], "preserved");
                assert_eq!((host.approvals, host.roots, resolutions, snapshots), (1, 1, 2, 5));
                assert_eq!(notifications, if json_tool { 0 } else { 2 },
                    "request-host usage and notifications must not silently include Task callbacks");
                peer.no_extra(9);
                followup(&mut peer, &mut client, &credential).await;
                peer.no_extra(10);
            });
        }
    }
}

#[test]
fn hosted_immediate_completions_and_terminal_creations_need_no_watch() {
    for json in [false, true] {
        for input_first in [false, true] {
            for task in [false, true] {
                run(async {
                    let cx = Cx::current().unwrap();
                    let (mut peer, mut client, credential) = Peer::new().await;
                    let cancellation = McpRequestCancellation::new();
                    let operation = initial_operation(&peer.target, "immediate");
                    let limits = hosted_limits(4, 1);
                    let mut host = Host::default();
                    let mut snapshots = 0;
                    let application = client.execute_and_drive_task_with_input_host(
                        &cx, &cancellation, &credential, driver_metadata(), operation, "immediate",
                        &limits, policy(1, 0), &mut host,
                        |_| {
                            panic!("a complete tool or terminal creation cannot resolve Task input");
                            #[allow(unreachable_code)]
                            std::future::ready(Ok(ManagedTaskInputAction::ReturnToCaller))
                        },
                        |_| { snapshots += 1; Ok(()) }, |_| true,
                    );
                    let server = async {
                        if input_first { peer.hosted_reply("immediate", 0, &challenge(), json).await; }
                        let result = if task { creation("cancelled") }
                            else { json!({"resultType":"complete","content":[],"isError":true}) };
                        peer.hosted_reply("immediate", usize::from(input_first), &result, json).await;
                    };
                    let (result, ()) = pair(application, server).await;
                    let DpopTaskHostedExecutionOutcome::Initial(initial) = result.unwrap()
                        else { panic!("there must be no Task network continuation") };
                    assert_eq!(initial.continuations, usize::from(input_first));
                    let encoded = CoreResult::Final(*initial.result).encode().unwrap();
                    let encoded: Value = serde_json::from_str(&encoded).unwrap();
                    if task { assert_eq!(encoded["status"], "cancelled"); }
                    else { assert_eq!(encoded["isError"], true); }
                    assert_eq!(snapshots, usize::from(task));
                    assert_eq!((host.approvals, host.roots), (usize::from(input_first), usize::from(input_first)));
                    peer.no_extra(1 + usize::from(input_first));
                });
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Refuse { Host, Limit, ChallengeTail, CreationTail, Observer }

#[test]
fn refused_hosted_stages_never_replay_or_enter_the_task_driver() {
    for refusal in [Refuse::Host, Refuse::Limit, Refuse::ChallengeTail, Refuse::CreationTail, Refuse::Observer] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let limits = hosted_limits(8, if matches!(refusal, Refuse::Limit) { 0 } else { 1 });
            let operation = initial_operation(&peer.target, "refused-host");
            let mut host = Host { deny:matches!(refusal, Refuse::Host), ..Host::default() };
            let mut snapshots = 0;
            let application = client.execute_and_drive_task_with_input_host(
                &cx, &cancellation, &credential, driver_metadata(), operation, "refused-host",
                &limits, policy(3, 1), &mut host,
                |_| {
                    panic!("refused conversation must not invoke a Task resolver");
                    #[allow(unreachable_code)]
                    std::future::ready(Ok(ManagedTaskInputAction::ReturnToCaller))
                },
                |_| { snapshots += 1; Err(ManagedTaskDriverError::AbortedByHost) }, |_| true,
            );
            let server = async {
                let mut first = peer.hosted_tool("refused-host", 0).await;
                streamed_reply(&mut first, &reply("refused-host", 0, false, &challenge()),
                    None, matches!(refusal, Refuse::ChallengeTail)).await;
                if matches!(refusal, Refuse::CreationTail | Refuse::Observer) {
                    let mut second = peer.hosted_tool("refused-host", 1).await;
                    streamed_reply(&mut second, &reply("refused-host", 1, false, &creation("working")),
                        None, matches!(refusal, Refuse::CreationTail)).await;
                }
            };
            let (result, ()) = pair(application, server).await;
            let error = result.err().expect("a refused stage cannot return a successful execution");
            if matches!(refusal, Refuse::Observer) {
                assert!(matches!(error, DpopTaskHostedExecutionError::Watch(DpopTaskWatchError::Driver(
                    ManagedTaskDriverError::AbortedByHost))));
            } else { assert!(matches!(error, DpopTaskHostedExecutionError::Conversation(_))); }
            assert_eq!(snapshots, usize::from(matches!(refusal, Refuse::Observer)));
            assert_eq!(host.approvals, usize::from(matches!(refusal, Refuse::Host | Refuse::CreationTail | Refuse::Observer)));
            assert_eq!(host.roots, usize::from(matches!(refusal, Refuse::CreationTail | Refuse::Observer)));
            let pairs = if matches!(refusal, Refuse::CreationTail | Refuse::Observer) { 2 } else { 1 };
            peer.no_extra(pairs);
            assert!(cx.checkpoint().is_ok());
            assert!(!client.revocation_handle().is_revoked());
            followup(&mut peer, &mut client, &credential).await;
            peer.no_extra(pairs + 1);
        });
    }
}

// Derive outgoing conversation charges from the actual admitted protocol
// requests. The byte-short control changes only the final total allowance.
fn conversation_request_bytes(target: &str, prefix: &str) -> usize {
    use crate::http_auth::dpop::native::core::tasks::{Prepared, Reply, wire};
    use crate::http_auth::rpc::interaction::continuation_request;
    let prepared = Prepared::new(target, driver_metadata(), initial_operation(target, prefix),
        ManagedCoreLimits::default(), 8192).unwrap();
    let Reply::Tool(original) = &prepared.reply else { panic!("tool request required") };
    let CoreResult::Final(FinalCoreResult::ToolsCallInputRequired { result: input, .. }) =
        original.decode_result(&challenge().to_string()).unwrap() else { panic!("input required") };
    let answers = serde_json::from_value(json!({"r":{"roots":[{"uri":"file:///host-private"}]}})).unwrap();
    let next = continuation_request(original, &input, Some(answers)).unwrap();
    let params = next.encode_params().unwrap().unwrap();
    let discovery = wire(target, "server/discover", &RequestId::String(round_id(prefix, 1, true)),
        json!({"_meta":params["_meta"]}), None, 8192).unwrap();
    let tool = wire(target, "tools/call", &RequestId::String(round_id(prefix, 1, false)),
        params, Some("work".to_owned()), 8192).unwrap();
    prepared.discovery_wire.body().len() + prepared.operation_wire.body().len()
        + discovery.body().len() + tool.body().len()
}

#[test]
fn hosted_conversation_charges_survive_adoption_into_the_subscription_budget() {
    for quota in [Quota::Exact, Quota::ByteShort, Quota::NotificationShort] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let mut frames = vec![watch_discovery("host-quota"), watch_ack("host-quota", true)];
            for (round, result) in [(0, challenge()), (1, creation("working"))] {
                frames.push(reply("host-quota", round, true, &discovery_result()));
                frames.push(reply("host-quota", round, false, &result));
                frames.push(progress(json!("work"), "1"));
            }
            for (round, status) in [(0, "working"), (1, "cancelled")] {
                frames.push(wait_response("host-quota", round, true, &discovery_result()));
                frames.push(wait_response("host-quota", round, false, &task_result(status)));
            }
            let maximum = frames.iter().map(Vec::len).max().unwrap();
            let total = conversation_request_bytes(&peer.target, "host-quota")
                + frames.iter().map(Vec::len).sum::<usize>();
            let core = ManagedCoreLimits::new(8192, maximum,
                total - usize::from(matches!(quota, Quota::ByteShort)),
                if matches!(quota, Quota::NotificationShort) { 2 } else { 3 }, Duration::from_secs(10)).unwrap();
            let limits = DpopTaskHostLimits::new(DpopStreamLimits::new(core, Duration::from_secs(5)).unwrap(),
                CoreInputLimits::default(), 1, 1).unwrap();
            let mut host = Host::default();
            let mut snapshots = 0;
            let application = client.execute_and_drive_task_with_input_host(
                &cx, &cancellation, &credential, driver_metadata(), initial_operation(&peer.target, "host-quota"),
                "host-quota", &limits, policy(2, 0), &mut host,
                |_| std::future::ready(Ok(ManagedTaskInputAction::ReturnToCaller)),
                |_| { snapshots += 1; Ok(()) }, |_| true,
            );
            let server = async {
                peer.hosted_reply("host-quota", 0, &challenge(), false).await;
                peer.hosted_reply("host-quota", 1, &creation("working"), false).await;
                peer.watch_snapshot_reply("host-quota", 0, "working").await;
                if matches!(quota, Quota::NotificationShort) { return; }
                let mut listen = peer.watch_listen("host-quota").await;
                listen.write_all(HEAD).await.unwrap();
                event(&mut listen, &watch_ack("host-quota", true)).await;
                peer.watch_snapshot_reply("host-quota", 1, "cancelled").await;
                assert_watch_closed(&mut listen).await;
            };
            let (result, ()) = pair(application, server).await;
            match quota {
                Quota::Exact => assert!(matches!(result.unwrap(), DpopTaskHostedExecutionOutcome::Observed { .. })),
                Quota::ByteShort => assert!(matches!(result, Err(DpopTaskHostedExecutionError::Watch(
                    DpopTaskWatchError::Stream(DpopStreamError::Core(DpopCoreError::Protocol(
                        ManagedCoreError::ResponseByteLimit))))))),
                Quota::NotificationShort => assert!(matches!(result, Err(DpopTaskHostedExecutionError::Watch(
                    DpopTaskWatchError::Stream(DpopStreamError::Core(DpopCoreError::Protocol(
                        ManagedCoreError::NotificationLimit))))))),
            }
            assert_eq!(snapshots, if matches!(quota, Quota::Exact) { 3 } else { 2 });
            assert_eq!((host.approvals, host.roots), (1, 1));
            peer.no_extra(if matches!(quota, Quota::NotificationShort) { 3 } else { 5 });
        });
    }
}

#[derive(Clone, Copy)]
enum Retire { Cancel, Revoke, Drop }

#[test]
fn hosted_cancellation_revocation_and_drop_retire_each_owned_stage_without_replay() {
    for phase in 0..3 {
        for retire in [Retire::Cancel, Retire::Revoke, Retire::Drop] {
            run(async {
                let cx = Cx::current().unwrap();
                let (mut peer, mut client, credential) = Peer::new().await;
                let cancellation = McpRequestCancellation::new();
                let reached = McpRequestCancellation::new();
                let mut host = Host { pending:if phase == 0 { Some(reached.clone()) } else { None }, ..Host::default() };
                let task_drops = Arc::new(AtomicUsize::new(0));
                let operation = initial_operation(&peer.target, "retire-host");
                let limits = hosted_limits(8, 1);
                let mut snapshots = 0;
                let application = async {
                    let mut drive = Box::pin(client.execute_and_drive_task_with_input_host(
                        &cx, &cancellation, &credential, driver_metadata(), operation, "retire-host",
                        &limits, policy(3, 1), &mut host,
                        |_| {
                            assert_eq!(phase, 2);
                            let reached = reached.clone();
                            let drops = Arc::clone(&task_drops);
                            async move {
                                let _probe = DropProbe(drops);
                                reached.cancel();
                                std::future::pending::<Result<ManagedTaskInputAction, ManagedTaskDriverError>>().await
                            }
                        }, |_| { snapshots += 1; Ok(()) }, |_| true,
                    ));
                    if matches!(retire, Retire::Drop) {
                        let mut ready = std::pin::pin!(reached.cancelled());
                        poll_fn(|context| {
                            assert!(drive.as_mut().poll(context).is_pending());
                            ready.as_mut().poll(context)
                        }).await;
                        drop(drive);
                    } else {
                        let error = drive.await.err().expect("retired execution cannot succeed");
                        let error = match error {
                            DpopTaskHostedExecutionError::Conversation(DpopTaskHostError::Stream(DpopStreamError::Core(
                                DpopCoreError::Transport(error))))
                            | DpopTaskHostedExecutionError::Watch(DpopTaskWatchError::Stream(DpopStreamError::Core(
                                DpopCoreError::Transport(error)))) => error,
                            error => panic!("expected original transport lifetime failure: {error:?}"),
                        };
                        if matches!(retire, Retire::Cancel) { assert_eq!(error, DpopHttpError::Cancelled); }
                        else { assert!(matches!(error, DpopHttpError::Authorization(_))); }
                    }
                };
                let server = async {
                    peer.hosted_reply("retire-host", 0, &challenge(), true).await;
                    let mut owned = if phase == 1 {
                        let mut tool = peer.hosted_tool("retire-host", 1).await;
                        tool.write_all(HEAD).await.unwrap();
                        event(&mut tool, &reply("retire-host", 1, false, &creation("working"))).await;
                        // The creation is still provisional: do not send HTTP EOF.
                        reached.cancel();
                        Some(tool)
                    } else if phase == 2 {
                        peer.hosted_reply("retire-host", 1, &creation("working"), true).await;
                        peer.watch_snapshot_reply("retire-host", 0, "working").await;
                        let mut listen = peer.watch_listen("retire-host").await;
                        listen.write_all(HEAD).await.unwrap();
                        event(&mut listen, &watch_ack("retire-host", true)).await;
                        get_reply(&mut peer, "retire-host", 1, &input_task(&["one"]), true).await;
                        Some(listen)
                    } else { None };
                    reached.cancelled().await;
                    match retire {
                        Retire::Cancel => { cancellation.cancel(); }
                        Retire::Revoke => { credential.revoke(); }
                        Retire::Drop => {}
                    }
                    if let Some(socket) = &mut owned { assert_watch_closed(socket).await; }
                };
                pair(application, server).await;
                assert_eq!(snapshots, if phase == 2 { 3 } else { 0 });
                assert_eq!(host.drops.load(Ordering::SeqCst), 1);
                assert_eq!(task_drops.load(Ordering::SeqCst), usize::from(phase == 2));
                let pairs = [1, 2, 5][phase];
                peer.no_extra(pairs);
                assert!(cx.checkpoint().is_ok());
                assert!(!client.revocation_handle().is_revoked());
                if !matches!(retire, Retire::Revoke) {
                    followup(&mut peer, &mut client, &credential).await;
                    peer.no_extra(pairs + 1);
                }
            });
        }
    }
}

#[test]
fn both_original_task_policy_and_request_host_deadlines_survive_task_creation() {
    use crate::http_auth::sampling::{SamplingRunLimits, inputs::SamplingInputLimits};
    use fastmcp_protocol::sampling::SamplingToolLoopLimits;
    for host_deadline in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let (mut peer, mut client, credential) = Peer::new().await;
            let cancellation = McpRequestCancellation::new();
            let run_limits = SamplingRunLimits::new(SamplingToolLoopLimits::default(),
                Duration::from_secs(if host_deadline { 3 } else { 10 }), 4096).unwrap();
            let inputs = CoreInputLimits::new(
                SamplingInputLimits::new(run_limits, 4, 4, 4, 8192, 8192).unwrap(), 4, 4,
            ).unwrap();
            let limits = DpopTaskHostLimits::new(watch_limits(8), inputs, 1, 1).unwrap();
            let selected = DpopTaskWatchDriverPolicy::new(3, 0, 0, 8192,
                Duration::from_secs(if host_deadline { 10 } else { 3 })).unwrap();
            let operation = initial_operation(&peer.target, "deadline-host");
            let mut host = Host::default();
            let mut snapshots = 0;
            let started = cx.now();
            let application = async {
                let drive = client.execute_and_drive_task_with_input_host(
                    &cx, &cancellation, &credential, driver_metadata(), operation, "deadline-host",
                    &limits, selected, &mut host,
                    |_| std::future::ready(Ok(ManagedTaskInputAction::ReturnToCaller)),
                    |_| { snapshots += 1; Ok(()) }, |_| true,
                );
                asupersync::time::timeout_at(started.saturating_add_nanos(4_000_000_000), drive)
                    .await.expect("resetting the three-second lifetime after creation must not pass")
            };
            let server = async {
                peer.hosted_reply("deadline-host", 0, &challenge(), true).await;
                let mut tool = peer.hosted_tool("deadline-host", 1).await;
                asupersync::time::Sleep::new(started.saturating_add_nanos(2_000_000_000)).await;
                json_reply(&mut tool, &reply("deadline-host", 1, false, &creation("working"))).await;
                peer.watch_snapshot_reply("deadline-host", 0, "working").await;
                let mut listen = peer.watch_listen("deadline-host").await;
                listen.write_all(HEAD).await.unwrap();
                event(&mut listen, &watch_ack("deadline-host", true)).await;
                let mut get = peer.wait_round("deadline-host", 1).await;
                pair(assert_watch_closed(&mut listen), assert_watch_closed(&mut get)).await;
            };
            let (result, ()) = pair(application, server).await;
            assert!(matches!(result, Err(DpopTaskHostedExecutionError::Watch(DpopTaskWatchError::Stream(
                DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::TimedOut)))))));
            assert_eq!(snapshots, 2);
            assert_eq!((host.approvals, host.roots), (1, 1));
            peer.no_extra(5);
            assert!(cx.checkpoint().is_ok());
            followup(&mut peer, &mut client, &credential).await;
            peer.no_extra(6);
        });
    }
}
