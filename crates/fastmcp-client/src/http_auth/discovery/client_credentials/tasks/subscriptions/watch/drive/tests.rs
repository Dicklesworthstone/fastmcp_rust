use super::*;
use serde_json::json;
use super::super::tests::{consumer, runtime};

fn requests(value: serde_json::Value) -> TaskInputRequests { serde_json::from_value(value).unwrap() }
fn two() -> TaskInputRequests { requests(json!({"one":{"method":"roots/list"},"two":{"method":"roots/list"}})) }
fn answers(value: serde_json::Value) -> TaskInputResponses { serde_json::from_value(value).unwrap() }
fn metadata(value: serde_json::Value) -> serde_json::Value { json!({(FINAL_CLIENT_CAPABILITIES_META_KEY):value}) }

#[test]
fn watched_task_partial_answers_advance_only_after_acknowledgement() {
    let policy=ClientCredentialsTaskWatchDrivePolicy::default();
    let mut history=InputHistory::default();
    let pending=history.unanswered(&two(),policy).unwrap();
    let reply=answers(json!({"one":{"roots":[]}}));
    let next=history.with_answers(&pending,&reply).unwrap();
    assert_eq!(history.unanswered(&two(),policy).unwrap().requests.len(),2,
        "preparing an update does not acknowledge either key");
    history=next;
    let pending=history.unanswered(&two(),policy).unwrap();
    assert_eq!(pending.requests.keys().map(String::as_str).collect::<Vec<_>>(),["two"]);
    assert!(history.with_answers(&pending,&reply).is_err());
    history=history.with_answers(&pending,&answers(json!({"two":{"roots":[]}}))).unwrap();
    assert!(history.unanswered(&two(),policy).unwrap().requests.is_empty());
}
#[test]
fn watched_task_rejects_changed_answered_and_unanswered_observed_keys() {
    let policy=ClientCredentialsTaskWatchDrivePolicy::default();
    let mut history=InputHistory::default();
    let pending=history.unanswered(&two(),policy).unwrap();
    history=history.with_answers(&pending,&answers(json!({"one":{"roots":[]}}))).unwrap();
    let before=history.entries.clone();
    for key in ["one","two"] {
        let changed=requests(json!({key:{"method":"sampling/createMessage","params":{"messages":[],"maxTokens":16}}}));
        assert!(matches!(history.unanswered(&changed,policy),Err(ClientCredentialsTaskWaitError::InputKeyReused)));
        assert_eq!(history.entries,before);
    }
    assert_eq!(history.unanswered(&two(),policy).unwrap().requests.len(),1);
}
#[test]
fn watched_task_rejects_empty_unknown_wrong_kind_and_duplicate_answers() {
    let policy=ClientCredentialsTaskWatchDrivePolicy::default();
    let mut history=InputHistory::default();
    let pending=history.unanswered(&two(),policy).unwrap();
    for wire in [json!({}),json!({"unknown":{"roots":[]}}),json!({"one":{"action":"decline"}})] {
        assert!(matches!(history.with_answers(&pending,&answers(wire)),Err(ClientCredentialsTaskWaitError::InvalidInputResponse)));
    }
    let reply=answers(json!({"one":{"roots":[]}}));
    history=history.with_answers(&pending,&reply).unwrap();
    assert!(matches!(history.with_answers(&pending,&reply),Err(ClientCredentialsTaskWaitError::InputKeyReused)));
}
#[test]
fn watched_task_lifetime_key_budget_counts_unanswered_history_transactionally() {
    let policy=ClientCredentialsTaskWatchDrivePolicy::new(ClientCredentialsTaskWatchPolicy::default(),8,1,4096).unwrap();
    let mut history=InputHistory::default();
    assert!(matches!(history.unanswered(&two(),policy),Err(ClientCredentialsTaskWaitError::InputLimit)));
    assert!(history.entries.is_empty());
    assert_eq!(history.bytes,0);
    history.unanswered(&requests(json!({"one":{"method":"roots/list"}})),policy).unwrap();
    assert!(matches!(history.unanswered(&requests(json!({"two":{"method":"roots/list"}})),policy),Err(ClientCredentialsTaskWaitError::InputLimit)));
    assert_eq!(history.entries.len(),1);
}
#[test]
fn watched_task_descriptor_byte_limit_rejects_before_observation_or_callback() {
    let policy=ClientCredentialsTaskWatchDrivePolicy::new(ClientCredentialsTaskWatchPolicy::default(),8,8,1).unwrap();
    let mut history=InputHistory::default();
    assert!(matches!(history.unanswered(&two(),policy),Err(ClientCredentialsTaskWaitError::StateByteLimit)));
    assert!(history.entries.is_empty());
    assert_eq!(history.bytes,0);
}
#[test]
fn watched_task_capability_gate_does_not_grant_roots_or_elicitation_implicitly() {
    assert!(admit_capabilities(&metadata(json!({})),&two()).is_err());
    assert!(admit_capabilities(&metadata(json!({"roots":{}})),&two()).is_ok());
    let form=requests(json!({"form":{"method":"elicitation/create","params":{
        "mode":"form","message":"select","requestedSchema":{"type":"object"}}}}));
    let url=requests(json!({"url":{"method":"elicitation/create","params":{
        "mode":"url","message":"select","url":"https://example.com/action"}}}));
    let only_form=metadata(json!({"elicitation":{"form":{}}}));
    assert!(admit_capabilities(&only_form,&form).is_ok());
    assert!(admit_capabilities(&only_form,&url).is_err());
    assert!(admit_capabilities(&metadata(json!({"elicitation":{"url":{}}})),&url).is_ok());
}
#[test]
fn watched_task_sampling_requires_its_tools_and_context_subcapabilities() {
    let sample=requests(json!({"sample":{"method":"sampling/createMessage","params":{
        "messages":[],"maxTokens":16,"tools":[],"includeContext":"allServers"}}}));
    for caps in [json!({}),json!({"sampling":{}}),json!({"sampling":{"tools":{}}}),json!({"sampling":{"context":{}}})] {
        assert!(matches!(admit_capabilities(&metadata(caps),&sample),Err(ClientCredentialsTaskWaitError::CapabilityNotAdvertised)));
    }
    assert!(admit_capabilities(&metadata(json!({"sampling":{"tools":{},"context":{}}})),&sample).is_ok());
}
#[test]
fn watched_task_drive_policy_is_bounded_and_can_select_observation_only() {
    let watch=ClientCredentialsTaskWatchPolicy::default();
    assert!(ClientCredentialsTaskWatchDrivePolicy::new(watch,0,0,1).is_ok());
    for (updates,keys,bytes) in [(129,1,1),(1,4097,1),(1,1,0),(1,1,4*1024*1024+1)] {
        assert!(ClientCredentialsTaskWatchDrivePolicy::new(watch,updates,keys,bytes).is_err());
    }
}
#[test]
fn watched_task_public_precancellation_never_enters_host_callbacks() {
    runtime().block_on(async {
        let cx=Cx::current().unwrap();
        let client=consumer();
        let cancellation=McpRequestCancellation::new();
        cancellation.cancel();
        let result=client.drive_task_watching_with_cancellation(&cx,&cancellation,TaskId::parse("one").unwrap(),
            "drive".to_owned(),ClientCredentialsTaskWatchDrivePolicy::default(),
            |_| { panic!("cancelled run must not resolve input"); #[allow(unreachable_code)]
                std::future::ready(Ok(ManagedTaskInputAction::ReturnToCaller)) },
            |_| panic!("cancelled run must not observe snapshots")).await;
        assert!(matches!(result,Err(ClientCredentialsTaskWatchDriveError::Watch(ClientCredentialsTaskWatchError::Task(
            ClientCredentialsTasksError::Authentication(ClientCredentialsError::Discovery(_)))))));
        assert!(client.client.inner.state.try_lock_owned().unwrap().current.is_none());
    });
}

#[cfg(all(unix, feature = "native-tls-roots"))]
mod live;
