//! Explicit, one-shot resolution of a fresh Task input snapshot.
//!
//! This is not a retry loop: one get, one admitted callback batch, one update.
//! The enclosing managed operation owns the original credential and deadline.

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::io::{self, Write};
use std::task::Poll;

use asupersync::Cx;
use fastmcp_core::{McpError, McpRequestCancellation, McpResult};
use fastmcp_protocol::tasks_extension::{
    MAX_TASK_INPUT_MAP_ENTRIES, TaskInputLedger, TaskInputRequests,
};
use fastmcp_protocol::{FinalEmbeddedInputRequest, FinalEmbeddedInputResponse, RequestId};
use serde::Serialize;
use serde_json::Value;

use super::{
    MAX_TASK_RESPONSE_BYTES, ManagedHttpClient, ManagedHttpClientError, TaskCall, TaskResult,
    checkpoint,
};
use crate::http_auth::rpc::interaction::{
    admit_embedded_input, normalize_embedded_input_context,
};
use crate::{
    FinalTask, FinalTaskId, FinalTaskInputResponses, FinalUpdateTaskResult, HttpClient,
    HttpClientError, MrtrCallbackOwner, ReverseRequestCancellation, ReverseRequestHandlers,
    catch_client_callback_unwind,
};

fn invalid(message: &'static str) -> McpError {
    McpError::invalid_params(message)
}

fn admit_limits(max_inputs: usize, max_payload_bytes: usize) -> Result<(), ManagedHttpClientError> {
    if !(1..=MAX_TASK_INPUT_MAP_ENTRIES).contains(&max_inputs)
        || !(1..=MAX_TASK_RESPONSE_BYTES).contains(&max_payload_bytes)
    {
        return Err(ManagedHttpClientError::InvalidPolicy);
    }
    Ok(())
}

// Count encoded descriptors and keyed answers without another response buffer.
// Counts bound container overhead; bytes are a serialization budget, not RSS.
struct PayloadBudget(usize);

impl PayloadBudget {
    fn charge(&mut self, value: &impl Serialize) -> McpResult<()> {
        let mut counter = Self(self.0);
        serde_json::to_writer(&mut counter, value)
            .map_err(|_| invalid("Managed Task input payload limit exceeded"))?;
        self.0 = counter.0;
        Ok(())
    }
}

impl Write for PayloadBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("Task input payload limit"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct PreparedInputs {
    ledger: TaskInputLedger,
    effective: TaskInputRequests,
    budget: PayloadBudget,
    omitted_contexts: usize,
}

fn prepare_inputs(
    task: &FinalTask,
    handlers: &ReverseRequestHandlers,
    capabilities: &Value,
    max_inputs: usize,
    max_payload_bytes: usize,
) -> McpResult<PreparedInputs> {
    let FinalTask::InputRequired { input_requests, .. } = task else {
        return Err(invalid("Task is not awaiting input"));
    };
    if input_requests.is_empty() || input_requests.len() > max_inputs {
        return Err(invalid("Managed Task input count is outside its bounds"));
    }
    let ledger = TaskInputLedger::from_requests(input_requests)
        .map_err(|_| invalid("Invalid Task input descriptors"))?;
    let mut budget = PayloadBudget(max_payload_bytes);
    budget.charge(input_requests)?;
    let mut effective = BTreeMap::new();
    let mut omitted_contexts = 0;
    for (key, request) in input_requests {
        let installed = match request {
            FinalEmbeddedInputRequest::Roots(_) => handlers.modern_roots_list.is_some(),
            FinalEmbeddedInputRequest::Sampling(_) => {
                handlers.modern_sampling_create_message.is_some()
            }
            FinalEmbeddedInputRequest::Elicitation(_) => {
                handlers.modern_elicitation_create.is_some()
            }
        };
        if !installed {
            return Err(invalid("Task input requires an unconfigured reverse handler"));
        }
        let encoded = serde_json::to_value(request)
            .map_err(|_| invalid("Task input descriptor could not be encoded"))?;
        let mut admitted = admit_embedded_input(capabilities, encoded)
            .map_err(|_| invalid("Task input requires an unadvertised capability"))?;
        if normalize_embedded_input_context(capabilities, &mut admitted) {
            omitted_contexts += 1;
        }
        effective.insert(key.clone(), admitted);
    }
    Ok(PreparedInputs {
        ledger,
        effective,
        budget,
        omitted_contexts,
    })
}

async fn resolve_one(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    handlers: &ReverseRequestHandlers,
    key: &str,
    request: FinalEmbeddedInputRequest,
) -> Result<(FinalEmbeddedInputResponse, MrtrCallbackOwner), HttpClientError> {
    checkpoint(cx, cancellation)?;
    let kind = request.response_kind();
    let local = ReverseRequestCancellation::new();
    let mut callback = std::pin::pin!(handlers.invoke_embedded_input_request_async(
        cx,
        key,
        request,
        local.clone(),
    ));
    // Declared after the callback: abandonment records local cancellation before
    // disposing the callback future. Successful owners remain live until ACK.
    let owner = MrtrCallbackOwner(local);
    let value = poll_fn(|task| {
        if let Err(error) = checkpoint(cx, cancellation) {
            return Poll::Ready(Err(error));
        }
        let result = catch_client_callback_unwind(|| callback.as_mut().poll(task))
            .unwrap_or_else(|_| {
                Poll::Ready(Err(McpError::internal_error(
                    "Client Task input handler failed",
                )))
            });
        if let Err(error) = checkpoint(cx, cancellation) {
            return Poll::Ready(Err(error));
        }
        result.map(|value| value.map_err(HttpClientError::CoreResult))
    })
    .await?;
    let response: FinalEmbeddedInputResponse = serde_json::from_value(value)
        .map_err(|_| HttpClientError::CoreResult(invalid("Invalid Task input response")))?;
    if !response.matches_kind(kind) {
        return Err(HttpClientError::CoreResult(invalid(
            "Task input response does not match its descriptor",
        )));
    }
    Ok((response, owner))
}

// Poll every admitted input before waiting. A host input can itself wait for
// another input in the same batch; awaiting them serially never starts that
// sibling. These futures remain owned by this operation, not spawned tasks.
async fn resolve_batch(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    handlers: &ReverseRequestHandlers,
    effective: TaskInputRequests,
    budget: &mut PayloadBudget,
) -> Result<(FinalTaskInputResponses, Vec<MrtrCallbackOwner>), HttpClientError> {
    if effective.is_empty() || effective.len() > MAX_TASK_INPUT_MAP_ENTRIES {
        return Err(HttpClientError::CoreResult(invalid(
            "Managed Task input count is outside its bounds",
        )));
    }
    let mut pending: Vec<_> = effective
        .into_iter()
        .map(|(key, request)| {
            Some(Box::pin(async move {
                let (response, owner) =
                    resolve_one(cx, cancellation, handlers, &key, request).await?;
                Ok::<_, HttpClientError>((key, response, owner))
            }))
        })
        .collect();
    let mut responses = FinalTaskInputResponses::new();
    let mut owners = Vec::with_capacity(pending.len());
    poll_fn(|task| {
        checkpoint(cx, cancellation)?;
        for slot in &mut pending {
            checkpoint(cx, cancellation)?;
            let Some(future) = slot else {
                continue;
            };
            let Poll::Ready(result) = future.as_mut().poll(task) else {
                continue;
            };
            // A completed child must never be polled again. On any subsequent
            // failure, dropping this batch cancels both completed owners and
            // still-pending callbacks before dispatch can submit an update.
            *slot = None;
            let (key, response, owner) = result?;
            budget
                .charge(&(&key, &response))
                .map_err(HttpClientError::CoreResult)?;
            responses.insert(key, response);
            owners.push(owner);
        }
        checkpoint(cx, cancellation)?;
        if owners.len() == pending.len() {
            Poll::Ready(Ok((
                std::mem::take(&mut responses),
                std::mem::take(&mut owners),
            )))
        } else {
            Poll::Pending
        }
    })
    .await
}

pub(super) async fn dispatch(
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    client: &mut HttpClient,
    request_id: RequestId,
    task_id: FinalTaskId,
    max_inputs: usize,
    max_payload_bytes: usize,
) -> Result<TaskResult, HttpClientError> {
    // Let both managed lifetime guards check before each new network boundary,
    // including immediately ready cached discovery and ready host callbacks.
    asupersync::runtime::yield_now().await;
    checkpoint(cx, cancellation)?;
    let snapshot = client
        .connection
        .get_task_final(cx, request_id, task_id, MAX_TASK_RESPONSE_BYTES)
        .await
        .map_err(HttpClientError::Connection)?;
    asupersync::runtime::yield_now().await;
    checkpoint(cx, cancellation)?;
    // CallbackBoundary installed these operation-local wrapped handlers. Never
    // reach into the builder for unguarded copies or derive extra capabilities.
    let handlers = client
        .connection
        .modern_reverse_request_handlers()
        .cloned()
        .ok_or_else(|| {
            HttpClientError::CoreResult(invalid("No Task input handlers are configured"))
        })?;
    let capabilities = serde_json::to_value(&client.client_capabilities)
        .map_err(|_| HttpClientError::CoreResult(invalid("Invalid client capabilities")))?;
    let PreparedInputs {
        ledger,
        effective,
        mut budget,
        omitted_contexts,
    } = prepare_inputs(
        &snapshot.task,
        &handlers,
        &capabilities,
        max_inputs,
        max_payload_bytes,
    )
    .map_err(HttpClientError::CoreResult)?;
    // Emit no peer-controlled keys or values. The diagnostic precedes host
    // effects, and only after the entire batch passed capability admission.
    if omitted_contexts != 0 {
        log::debug!("Unadvertised sampling context omitted from managed Task inputs");
    }
    let (responses, owners) =
        resolve_batch(cx, cancellation, &handlers, effective, &mut budget).await?;
    ledger
        .validate_responses(&responses)
        .map_err(|_| HttpClientError::CoreResult(invalid("Invalid Task input response batch")))?;
    asupersync::runtime::yield_now().await;
    checkpoint(cx, cancellation)?;
    let update_id = client.next_request_id()?;
    let acknowledged = client
        .connection
        .update_task_final(cx, update_id, &snapshot.task, responses, MAX_TASK_RESPONSE_BYTES)
        .await
        .map_err(HttpClientError::Connection)?;
    asupersync::runtime::yield_now().await;
    checkpoint(cx, cancellation)?;
    for owner in &owners {
        owner.0.record_response_sent();
    }
    Ok(TaskResult::Update(acknowledged))
}

impl ManagedHttpClient {
    /// Fetches one fresh input-required Task, resolves its inputs using the
    /// configured modern reverse handlers, and submits exactly one update.
    ///
    /// Requires `with_tasks` and live bilateral Tasks admission. Every input's
    /// descriptor, advertised capability and installed handler is checked before
    /// any callback runs. Sampling tools and URL elicitation need their specific
    /// capability leaves; unsupported sampling context is omitted with a fixed
    /// diagnostic before host effects. The original snapshot is not rewritten.
    ///
    /// Admitted callbacks progress concurrently within this operation, up to
    /// `max_inputs` live futures; no runtime tasks or threads are spawned. A
    /// pending input does not prevent an independent input from starting.
    /// Replies retain their original keys regardless of completion order. All
    /// replies must pass the shared payload budget and input ledger before the
    /// single update is sent. Failure disposes the entire local batch.
    ///
    /// This is an explicit disclosure operation, not part of get/wait/watch.
    /// The caller must authorize use of its configured roots, sampling and
    /// elicitation handlers for this task. Callbacks may perform side effects;
    /// those cannot be undone if a later callback or the update fails.
    ///
    /// One credential and one managed deadline cover discovery, snapshot, host
    /// input and update. Cancellation, logout, revocation, expiry and abandonment
    /// dispose local callback owners and prevent further updates. No uncertain
    /// update is retried; no task is created, polled, watched or cancelled. An
    /// acknowledgement is not evidence that the task subsequently completed.
    /// Invoking this API again is a new disclosure decision, not exactly-once
    /// recovery. The server still authorizes current task state at update time.
    ///
    /// `max_inputs` is 1..=MAX_TASK_INPUT_MAP_ENTRIES. `max_payload_bytes` is
    /// 1..=8 MiB and counts the encoded descriptor map plus each encoded
    /// `(input_key, answer)` pair. Native response/envelope limits are separate.
    /// Invalid local bounds refuse before acquisition or network contact.
    pub async fn resolve_task_inputs_final(
        &mut self,
        cx: &Cx,
        task_id: FinalTaskId,
        max_inputs: usize,
        max_payload_bytes: usize,
    ) -> Result<FinalUpdateTaskResult, ManagedHttpClientError> {
        self.resolve_task_inputs_final_with_cancellation(
            cx,
            &McpRequestCancellation::new(),
            task_id,
            max_inputs,
            max_payload_bytes,
        )
        .await
    }

    /// One-shot Task input resolution with caller-owned cancellation. Cancelling
    /// this operation never closes a sibling client or the shared OAuth login.
    pub async fn resolve_task_inputs_final_with_cancellation(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        task_id: FinalTaskId,
        max_inputs: usize,
        max_payload_bytes: usize,
    ) -> Result<FinalUpdateTaskResult, ManagedHttpClientError> {
        self.admit_tasks(cx, cancellation)?;
        admit_limits(max_inputs, max_payload_bytes)?;
        match self
            .perform_task(
                cx,
                cancellation,
                TaskCall::Resolve {
                    task_id,
                    max_inputs,
                    max_payload_bytes,
                },
            )
            .await?
        {
            TaskResult::Update(result) => Ok(result),
            _ => Err(ManagedHttpClientError::InvalidPolicy),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Waker};

    use crate::{FinalEmbeddedRootsListResult, FinalGetTaskResult};
    use serde_json::json;

    fn task(inputs: Value) -> FinalTask {
        serde_json::from_str::<FinalGetTaskResult>(&json!({
            "resultType":"complete", "taskId":"task-1", "status":"input_required",
            "createdAt":"2026-07-28T12:00:00Z", "lastUpdatedAt":"2026-07-28T12:00:00Z",
            "ttlMs":60000, "inputRequests":inputs
        }).to_string())
        .unwrap()
        .task
    }

    fn roots() -> ReverseRequestHandlers {
        ReverseRequestHandlers::new().with_modern_roots_list(|_, _, _| {
            Box::pin(async { Ok(FinalEmbeddedRootsListResult { roots: vec![] }) })
        })
    }

    #[test]
    fn local_limits_are_finite_and_not_clamped() {
        assert!(admit_limits(1, 1).is_ok());
        assert!(admit_limits(MAX_TASK_INPUT_MAP_ENTRIES, MAX_TASK_RESPONSE_BYTES).is_ok());
        for (count, bytes) in [
            (0, 1),
            (1, 0),
            (MAX_TASK_INPUT_MAP_ENTRIES + 1, 1),
            (1, MAX_TASK_RESPONSE_BYTES + 1),
            (usize::MAX, usize::MAX),
        ] {
            assert!(matches!(
                admit_limits(count, bytes),
                Err(ManagedHttpClientError::InvalidPolicy)
            ));
        }
    }

    #[test]
    fn entire_input_batch_requires_both_handler_and_advertised_capability() {
        let task = task(json!({"roots":{"method":"roots/list"}}));
        let original = serde_json::to_value(&task).unwrap();
        assert!(prepare_inputs(&task, &roots(), &json!({"roots":{}}), 1, 4096).is_ok());
        assert!(prepare_inputs(&task, &roots(), &json!({}), 1, 4096).is_err());
        assert!(prepare_inputs(
            &task,
            &ReverseRequestHandlers::new(),
            &json!({"roots":{}}),
            1,
            4096,
        )
        .is_err());
        assert_eq!(serde_json::to_value(&task).unwrap(), original);
    }

    #[test]
    fn mixed_batch_cannot_admit_an_unsupported_later_input() {
        let task = task(json!({
            "a-roots":{"method":"roots/list"},
            "z-form":{"method":"elicitation/create","params":{
                "mode":"form", "message":"approve", "requestedSchema":{"type":"object"}
            }}
        }));
        assert!(prepare_inputs(
            &task,
            &roots(),
            &json!({"roots":{}, "elicitation":{"form":{}}}),
            2,
            4096,
        )
        .is_err());
    }

    #[test]
    fn descriptor_limit_is_checked_before_any_answer_is_retained() {
        let task = task(json!({"one":{"method":"roots/list"},"two":{"method":"roots/list"}}));
        assert!(prepare_inputs(&task, &roots(), &json!({"roots":{}}), 1, 4096).is_err());
        assert!(prepare_inputs(&task, &roots(), &json!({"roots":{}}), 2, 1).is_err());
        assert!(prepare_inputs(&task, &roots(), &json!({"roots":{}}), 2, 4096).is_ok());
    }

    #[test]
    fn keyed_answer_bytes_include_escaping_and_failed_charge_is_atomic() {
        let value = ("key-\"-雪", json!({"roots":[]}));
        let bytes = serde_json::to_vec(&value).unwrap().len();
        let mut exact = PayloadBudget(bytes);
        exact.charge(&value).unwrap();
        assert_eq!(exact.0, 0);
        let mut short = PayloadBudget(bytes - 1);
        assert!(short.charge(&value).is_err());
        assert_eq!(short.0, bytes - 1);
    }

    #[test]
    fn ready_callback_cancellation_withholds_the_answer() {
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        let signal = cancellation.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let handlers = ReverseRequestHandlers::new().with_modern_roots_list(move |_, _, _| {
            counted.fetch_add(1, Ordering::SeqCst);
            signal.cancel();
            Box::pin(async { Ok(FinalEmbeddedRootsListResult { roots: vec![] }) })
        });
        let request = serde_json::from_value(json!({"method":"roots/list"})).unwrap();
        let mut future = Box::pin(resolve_one(&cx, &cancellation, &handlers, "one", request));
        assert!(matches!(
            future.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(_))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(cx.checkpoint().is_ok());
    }

    #[test]
    fn callback_panic_is_a_sanitized_failure_not_an_update_answer() {
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        let handlers = ReverseRequestHandlers::new().with_modern_roots_list(|_, _, _| {
            panic!("private-handler-payload")
        });
        let request = serde_json::from_value(json!({"method":"roots/list"})).unwrap();
        let mut future = Box::pin(resolve_one(&cx, &cancellation, &handlers, "one", request));
        let Poll::Ready(Err(HttpClientError::CoreResult(error))) =
            future.as_mut().poll(&mut Context::from_waker(Waker::noop()))
        else {
            panic!("callback panic must settle as an error");
        };
        assert!(!error.message.contains("private-handler-payload"));
        assert!(cx.checkpoint().is_ok());
    }

    fn root_inputs(keys: &[&str]) -> TaskInputRequests {
        keys.iter()
            .map(|key| {
                (
                    (*key).to_owned(),
                    serde_json::from_value(json!({"method":"roots/list"})).unwrap(),
                )
            })
            .collect()
    }

    struct WakeCount(AtomicUsize);

    impl std::task::Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct PendingInput {
        cancellation: ReverseRequestCancellation,
        drops: Arc<AtomicUsize>,
    }

    impl Future for PendingInput {
        type Output = McpResult<FinalEmbeddedRootsListResult>;

        fn poll(self: std::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for PendingInput {
        fn drop(&mut self) {
            assert!(
                self.cancellation.is_cancel_requested(),
                "the callback owner must cancel before dropping its pending future"
            );
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn pending_first_input_does_not_block_its_sibling_and_replies_keep_their_keys() {
        use asupersync::channel::oneshot;
        use std::sync::Mutex;

        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        let (sender, receiver) = oneshot::channel::<()>();
        let sender = Mutex::new(Some(sender));
        let receiver = Mutex::new(Some(receiver));
        let calls = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&calls);
        let handlers = ReverseRequestHandlers::new().with_modern_roots_list(move |cx, _, _| {
            let index = called.fetch_add(1, Ordering::SeqCst);
            assert!(index < 2, "a completed callback must not run twice");
            if index == 0 {
                let mut receiver = receiver.lock().unwrap().take().unwrap();
                Box::pin(async move {
                    receiver.recv(cx).await.unwrap();
                    Ok(serde_json::from_value(json!({
                        "roots":[{"uri":"file:///first"}]
                    }))
                    .unwrap())
                })
            } else {
                sender
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send_blocking(())
                    .unwrap();
                Box::pin(async {
                    Ok(serde_json::from_value(json!({
                        "roots":[{"uri":"file:///second"}]
                    }))
                    .unwrap())
                })
            }
        });
        let mut budget = PayloadBudget(4096);
        let mut batch = Box::pin(resolve_batch(
            &cx,
            &cancellation,
            &handlers,
            root_inputs(&["a", "b"]),
            &mut budget,
        ));
        let wakes = Arc::new(WakeCount(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        let mut context = Context::from_waker(&waker);
        assert!(batch.as_mut().poll(&mut context).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        let Poll::Ready(Ok((responses, owners))) = batch.as_mut().poll(&mut context) else {
            panic!("the later sibling must release the earlier input without external polling");
        };
        assert_eq!(
            serde_json::to_value(responses).unwrap(),
            json!({
                "a":{"roots":[{"uri":"file:///first"}]},
                "b":{"roots":[{"uri":"file:///second"}]}
            })
        );
        assert_eq!(owners.len(), 2);
        for owner in &owners {
            assert!(!owner.0.is_cancel_requested());
            owner.0.record_response_sent();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(cx.checkpoint().is_ok());
    }

    #[test]
    fn batch_failure_disposes_pending_and_completed_owners_without_starting_later_inputs() {
        use std::sync::Mutex;

        for failure in 0..3 {
            let cx = Cx::for_testing();
            let cancellation = McpRequestCancellation::new();
            let tokens = Arc::new(Mutex::new(Vec::new()));
            let observed = Arc::clone(&tokens);
            let drops = Arc::new(AtomicUsize::new(0));
            let disposed = Arc::clone(&drops);
            let calls = Arc::new(AtomicUsize::new(0));
            let called = Arc::clone(&calls);
            let handlers = ReverseRequestHandlers::new().with_modern_roots_list(
                move |_, local, _| {
                    observed.lock().unwrap().push(local.clone());
                    match called.fetch_add(1, Ordering::SeqCst) {
                        0 => Box::pin(async { Ok(FinalEmbeddedRootsListResult { roots: vec![] }) }),
                        1 => Box::pin(PendingInput {
                            cancellation: local,
                            drops: Arc::clone(&disposed),
                        }),
                        2 => match failure {
                            0 => Box::pin(async { Err(McpError::invalid_params("host declined")) }),
                            1 => panic!("private-batch-panic"),
                            _ => Box::pin(async {
                                Ok(serde_json::from_value(json!({
                                    "roots":[{"uri":format!("file:///{}", "x".repeat(4096))}]
                                }))
                                .unwrap())
                            }),
                        },
                        _ => panic!("later callback ran after a terminal batch failure"),
                    }
                },
            );
            let mut budget = PayloadBudget(1024);
            let mut batch = Box::pin(resolve_batch(
                &cx,
                &cancellation,
                &handlers,
                root_inputs(&["a", "b", "c", "d"]),
                &mut budget,
            ));
            let Poll::Ready(Err(HttpClientError::CoreResult(error))) =
                batch.as_mut().poll(&mut Context::from_waker(Waker::noop()))
            else {
                panic!("one rejected input must terminate the whole batch");
            };
            assert!(!error.message.contains("private-batch-panic"));
            drop(batch);
            assert_eq!(calls.load(Ordering::SeqCst), 3);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert!(
                tokens
                    .lock()
                    .unwrap()
                    .iter()
                    .all(ReverseRequestCancellation::is_cancel_requested)
            );
            assert!(!cancellation.is_cancel_requested());
            assert!(cx.checkpoint().is_ok());
        }
    }

    #[test]
    fn abandoning_a_parallel_batch_cancels_every_started_callback_before_disposal() {
        use std::sync::Mutex;

        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        let tokens = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&tokens);
        let drops = Arc::new(AtomicUsize::new(0));
        let disposed = Arc::clone(&drops);
        let handlers = ReverseRequestHandlers::new().with_modern_roots_list(move |_, local, _| {
            observed.lock().unwrap().push(local.clone());
            Box::pin(PendingInput {
                cancellation: local,
                drops: Arc::clone(&disposed),
            })
        });
        let mut budget = PayloadBudget(4096);
        let mut batch = Box::pin(resolve_batch(
            &cx,
            &cancellation,
            &handlers,
            root_inputs(&["a", "b", "c"]),
            &mut budget,
        ));
        assert!(
            batch
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(tokens.lock().unwrap().len(), 3);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(batch);
        assert_eq!(drops.load(Ordering::SeqCst), 3);
        assert!(
            tokens
                .lock()
                .unwrap()
                .iter()
                .all(ReverseRequestCancellation::is_cancel_requested)
        );
        assert!(!cancellation.is_cancel_requested());
        assert_eq!(budget.0, 4096);
        assert!(cx.checkpoint().is_ok());
    }

    #[test]
    fn ready_sibling_cancellation_stops_other_inputs_in_the_same_poll() {
        use std::sync::Mutex;

        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        let cancel = cancellation.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&calls);
        let drops = Arc::new(AtomicUsize::new(0));
        let disposed = Arc::clone(&drops);
        let tokens = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&tokens);
        let handlers = ReverseRequestHandlers::new().with_modern_roots_list(move |_, local, _| {
            observed.lock().unwrap().push(local.clone());
            match called.fetch_add(1, Ordering::SeqCst) {
                0 => Box::pin(PendingInput {
                    cancellation: local,
                    drops: Arc::clone(&disposed),
                }),
                1 => {
                    cancel.cancel();
                    Box::pin(async { Ok(FinalEmbeddedRootsListResult { roots: vec![] }) })
                }
                _ => panic!("a cancelled batch must not construct another host callback"),
            }
        });
        let mut budget = PayloadBudget(4096);
        let mut batch = Box::pin(resolve_batch(
            &cx,
            &cancellation,
            &handlers,
            root_inputs(&["a", "b", "c"]),
            &mut budget,
        ));
        assert!(matches!(
            batch.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(HttpClientError::CoreResult(error)))
                if error.code == fastmcp_core::McpErrorCode::RequestCancelled
        ));
        drop(batch);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(
            tokens
                .lock()
                .unwrap()
                .iter()
                .all(ReverseRequestCancellation::is_cancel_requested)
        );
        assert_eq!(budget.0, 4096);
        assert!(cx.checkpoint().is_ok());
    }

    #[test]
    fn parallel_answers_share_one_exact_byte_budget() {
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        let response: FinalEmbeddedInputResponse =
            serde_json::from_value(json!({"roots":[]})).unwrap();
        let bytes: usize = ["a", "b", "c"]
            .iter()
            .map(|key| serde_json::to_vec(&(key, &response)).unwrap().len())
            .sum();
        let handlers = roots();
        for exact in [false, true] {
            let mut budget = PayloadBudget(bytes - usize::from(!exact));
            let mut batch = Box::pin(resolve_batch(
                &cx,
                &cancellation,
                &handlers,
                root_inputs(&["a", "b", "c"]),
                &mut budget,
            ));
            let Poll::Ready(result) =
                batch.as_mut().poll(&mut Context::from_waker(Waker::noop()))
            else {
                panic!("all-ready inputs must settle in one poll");
            };
            assert_eq!(result.is_ok(), exact);
            if let Ok((responses, owners)) = result {
                assert_eq!(responses.len(), 3);
                assert_eq!(owners.len(), 3);
            }
            drop(batch);
            if exact {
                assert_eq!(budget.0, 0);
            }
        }
    }

    #[test]
    fn precancelled_batch_does_not_invoke_any_host_handler() {
        let cx = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        cancellation.cancel();
        let handlers = ReverseRequestHandlers::new().with_modern_roots_list(|_, _, _| {
            panic!("precancelled input handler must never be invoked")
        });
        let mut budget = PayloadBudget(4096);
        let mut batch = Box::pin(resolve_batch(
            &cx,
            &cancellation,
            &handlers,
            root_inputs(&["a", "b"]),
            &mut budget,
        ));
        assert!(matches!(
            batch.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(_))
        ));
        drop(batch);
        assert_eq!(budget.0, 4096);
        assert!(cx.checkpoint().is_ok());
    }
}
