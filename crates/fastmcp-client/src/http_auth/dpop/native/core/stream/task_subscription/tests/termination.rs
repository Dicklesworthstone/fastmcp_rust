//! Subscription teardown is control traffic, never a Task status or local cancel.
use super::*;

fn cancelled(id: Value, marker: Option<Value>) -> Vec<u8> {
    let mut params = json!({"requestId":id,"reason":"peer-reason-canary"});
    if let Some(marker) = marker {
        params["_meta"] = json!({FINAL_SUBSCRIPTION_ID_META_KEY:marker});
    }
    serde_json::to_vec(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":params})).unwrap()
}

#[test]
fn all_terminal_orders_keep_the_first_outcome_at_every_byte_split() {
    fixture(|life| {
        let acknowledged = ack(json!(2), json!({"taskIds":["task-one"]}));
        for marker in [None, Some(json!(2))] {
            let cancel = cancelled(json!(2), marker);
            for (first, second, is_cancelled) in [
                (&cancel[..], None, true),
                (COMPLETE.as_bytes(), None, false),
                (&cancel[..], Some(COMPLETE.as_bytes()), true),
                (COMPLETE.as_bytes(), Some(&cancel[..]), false),
            ] {
                let mut wire = event(&acknowledged);
                wire.extend_from_slice(&event(first));
                if let Some(second) = second { wire.extend_from_slice(&event(second)); }
                for split in 0..=wire.len() {
                    // ACK exhausts the notification allowance; control teardown
                    // still works, including a second signal in the same frame.
                    let selected = limits(1);
                    let mut reader = Reader::new(ModernHttpResponseKind::Sse,
                        decoder(selected), selected, 32768).unwrap();
                    let mut idle = Idle::new(life.cx.now(), selected.idle);
                    let deadline = idle.deadline;
                    let mut observed = 0;
                    let mut observer = |event: &DpopTaskSubscriptionEvent| {
                        assert!(matches!(event, DpopTaskSubscriptionEvent::Acknowledged(_)));
                        observed += 1;
                        true
                    };
                    reader.push(&wire[..split], life, &mut idle, &mut observer).unwrap();
                    reader.push(&wire[split..], life, &mut idle, &mut observer).unwrap();
                    assert_eq!(observed, 1);
                    assert_eq!(idle.deadline, deadline);
                    let completed = reader.finish(life, &idle).unwrap();
                    assert_eq!(completed.usage.1, 1);
                    assert_eq!(completed.usage.0, discovery(discovery_result()).len()
                        + acknowledged.len() + first.len() + second.map_or(0, <[u8]>::len));
                    if is_cancelled {
                        assert!(matches!(completed.result, Err(DpopStreamError::SubscriptionCancelled)));
                    } else {
                        let encoded = completed.result.unwrap().encode().unwrap();
                        assert!(encoded.contains("900719925474099312345"));
                        assert!(encoded.contains("1.20e+4"));
                    }
                    assert!(!life.cancellation.is_cancel_requested());
                    assert!(life.cx.checkpoint().is_ok());
                }
            }
        }
    });
}

#[test]
fn cancellation_uses_request_identity_and_invalid_frames_leave_every_field_unchanged() {
    let valid = cancelled(json!(2), None);
    let mut decoder = decoder(limits(1));
    let before = (snapshot(&decoder), decoder.end);
    assert!(decoder.admit(&valid, true).is_err(), "ACK must establish the selection first");
    assert_eq!((snapshot(&decoder), decoder.end), before);
    decoder.admit(&ack(json!(2), json!({"taskIds":["task-one"]})), true).unwrap();
    for bad in [
        cancelled(json!("2"), None),
        cancelled(json!(3), Some(json!(2))),
        cancelled(json!(2), Some(json!(3))),
        cancelled(json!(2), Some(Value::Null)),
        br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2,"requestId":2}}"#.to_vec(),
        br#"{"jsonrpc":"2.0","id":2,"method":"notifications/cancelled","params":{"requestId":2}}"#.to_vec(),
        br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2,"reason":17}}"#.to_vec(),
        br#"[{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}]"#.to_vec(),
    ] {
        let before = (snapshot(&decoder), decoder.end);
        assert!(decoder.admit(&bad, true).is_err());
        assert_eq!((snapshot(&decoder), decoder.end), before);
    }
    assert!(matches!(decoder.admit(&valid, true).unwrap(),
        StreamEvent::Result(Err(DpopStreamError::SubscriptionCancelled))));
    assert_eq!(decoder.notifications, 1);
    let diagnostic = format!("{:?} {}", DpopStreamError::SubscriptionCancelled,
        DpopStreamError::SubscriptionCancelled);
    assert!(!diagnostic.contains("canary"));
}

#[test]
fn complementary_terminal_spends_bytes_and_cannot_replenish_the_notification_budget() {
    let discovery = discovery(discovery_result());
    let ack = ack(json!(2), json!({"taskIds":["task-one"]}));
    let cancel = cancelled(json!(2), None);
    let total = discovery.len() + ack.len() + cancel.len() + COMPLETE.len();
    let maximum = discovery.len().max(ack.len()).max(cancel.len()).max(COMPLETE.len());
    for cancelled_first in [false, true] {
        for short in [false, true] {
            let core = ManagedCoreLimits::new(8192, maximum, total - usize::from(short),
                1, Duration::from_secs(60)).unwrap();
            let (_, mut decoder) = Prepared::new(TARGET, selection(&["task-one"]), core, 8192)
                .unwrap().admit(response(discovery.clone())).unwrap();
            decoder.admit(&ack, true).unwrap();
            let (first, second) = if cancelled_first {
                (&cancel[..], COMPLETE.as_bytes())
            } else { (COMPLETE.as_bytes(), &cancel[..]) };
            decoder.admit(first, true).unwrap();
            let before = (snapshot(&decoder), decoder.end);
            let tail = decoder.admit_terminal_tail(second);
            if short {
                assert!(matches!(tail, Err(DpopStreamError::Core(DpopCoreError::Protocol(
                    ManagedCoreError::ResponseByteLimit)))));
                assert_eq!((snapshot(&decoder), decoder.end), before);
            } else {
                tail.unwrap();
                assert_eq!(decoder.usage(), (total, 1));
                let before = (snapshot(&decoder), decoder.end);
                assert!(decoder.admit_terminal_tail(second).is_err());
                assert_eq!((snapshot(&decoder), decoder.end), before);
            }
        }
    }
}

#[test]
fn cancellation_first_ignores_a_late_error_but_never_a_foreign_response() {
    let mut decoder = decoder(limits(1));
    decoder.admit(&ack(json!(2), json!({"taskIds":["task-one"]})), true).unwrap();
    decoder.admit(&cancelled(json!(2), None), true).unwrap();
    for bad in [
        br#"{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete"}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":2,"result":{"_meta":{"io.modelcontextprotocol/subscriptionId":3}}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":2,"id":2,"error":{"code":-32603,"message":"x"}}"#.as_slice(),
    ] {
        let before = (snapshot(&decoder), decoder.end);
        assert!(decoder.admit_terminal_tail(bad).is_err());
        assert_eq!((snapshot(&decoder), decoder.end), before);
    }
    let late = br#"{"jsonrpc":"2.0","id":2,"error":{"code":-32603,"message":"late-error-canary"}}"#;
    decoder.admit_terminal_tail(late).unwrap();
    assert_eq!(decoder.notifications, 1);
}

#[test]
fn a_terminal_pair_does_not_admit_task_traffic_duplicate_signals_or_incomplete_tails() {
    fixture(|life| {
        let ack = event(&ack(json!(2), json!({"taskIds":["task-one"]})));
        let cancel = event(&cancelled(json!(2), None));
        let complete = event(COMPLETE.as_bytes());
        for cancelled_first in [false, true] {
            let (first, second) = if cancelled_first { (&cancel, &complete) } else { (&complete, &cancel) };
            for tail in [
                event(&status(json!(2), "task-one")),
                first.clone(),
                [second.as_slice(), second.as_slice()].concat(),
                [second.as_slice(), b"data: unfinished"].concat(),
                event(&cancelled(json!(999), None)),
            ] {
                let mut reader = reader(ModernHttpResponseKind::Sse);
                let mut idle = Idle::new(life.cx.now(), limits(8).idle);
                reader.push(&ack, life, &mut idle, &mut |_| true).unwrap();
                reader.push(first, life, &mut idle, &mut |_| panic!("terminal is not a Task event")).unwrap();
                let pushed = reader.push(&tail, life, &mut idle,
                    &mut |_| panic!("post-terminal traffic escaped"));
                assert!(pushed.is_err() || reader.finish(life, &idle).is_err());
            }
        }
    });
}

#[test]
fn local_cancellation_or_revocation_before_eof_overrides_the_remote_terminal() {
    for revoked in [false, true] {
        fixture(|life| {
            let mut reader = reader(ModernHttpResponseKind::Sse);
            let mut idle = Idle::new(life.cx.now(), limits(8).idle);
            let wire = [event(&ack(json!(2), json!({"taskIds":["task-one"]}))),
                event(&cancelled(json!(2), None))].concat();
            reader.push(&wire, life, &mut idle, &mut |_| true).unwrap();
            if revoked { life.credential.revoke(); } else { life.cancellation.cancel(); }
            assert!(matches!(reader.finish(life, &idle),
                Err(DpopStreamError::Core(DpopCoreError::Transport(_)))));
            assert!(life.cx.checkpoint().is_ok());
        });
    }
}
