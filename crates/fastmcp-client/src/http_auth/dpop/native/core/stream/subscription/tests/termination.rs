use super::*;

const CANCEL: &str = r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"reason":"remote-only-canary"}}"#;

#[test]
fn core_subscription_terminal_orders_preserve_one_outcome_at_every_split() {
    fixture(|life, _| {
        for (first, second, cancelled) in [
            (CANCEL, None, true),
            (COMPLETE, None, false),
            (CANCEL, Some(COMPLETE), true),
            (COMPLETE, Some(CANCEL), false),
        ] {
            let ack = ack(json!(7), filter());
            let wire = format!("{}{}{}", event(&ack), event(first), second.map(event).unwrap_or_default());
            let core = ManagedCoreLimits::new(8192, 8192, 32768, 1, Duration::from_secs(60)).unwrap();
            let selected = DpopStreamLimits::new(core, Duration::from_secs(10)).unwrap();
            for split in 0..=wire.len() {
                let mut reader = reader(ModernHttpResponseKind::Sse, filter(), selected);
                let mut idle = Idle::new(life.cx.now(), selected.idle);
                let deadline = idle.deadline;
                let mut calls = 0;
                let mut observe = |notification: &ServerNotification| {
                    assert!(matches!(notification, ServerNotification::SubscriptionsAcknowledged(_)));
                    calls += 1;
                    true
                };
                reader.push(&wire.as_bytes()[..split], life, &mut idle, &mut observe).unwrap();
                reader.push(&wire.as_bytes()[split..], life, &mut idle, &mut observe).unwrap();
                let completed = reader.finish(life, &idle).unwrap();
                assert_eq!(completed.usage, (ack.len() + first.len() + second.map_or(0, str::len), 1));
                assert_eq!(calls, 1);
                assert_eq!(idle.deadline, deadline);
                if cancelled {
                    assert!(matches!(completed.result, Err(DpopStreamError::SubscriptionCancelled)));
                } else {
                    let result = completed.result.unwrap().encode().unwrap();
                    assert!(result.contains("900719925474099312345"));
                    assert!(result.contains("1.20e+4"));
                }
                assert!(!life.cancellation.is_cancel_requested());
                assert!(life.cx.checkpoint().is_ok());
            }
        }
    });
}

#[test]
fn core_control_signals_obey_exact_total_and_frame_bounds_without_event_slots() {
    fixture(|life, _| {
        let ack = ack(json!(7), filter());
        let total = ack.len() + CANCEL.len() + COMPLETE.len();
        let maximum = ack.len().max(CANCEL.len()).max(COMPLETE.len());
        for reverse in [false, true] {
            for short in [false, true] {
                let core = ManagedCoreLimits::new(8192, maximum, total - usize::from(short),
                    1, Duration::from_secs(60)).unwrap();
                let selected = DpopStreamLimits::new(core, Duration::from_secs(10)).unwrap();
                let mut reader = reader(ModernHttpResponseKind::Sse, filter(), selected);
                let mut idle = Idle::new(life.cx.now(), selected.idle);
                let (first, second) = if reverse { (COMPLETE, CANCEL) } else { (CANCEL, COMPLETE) };
                reader.push(event(&ack).as_bytes(), life, &mut idle, &mut |_| true).unwrap();
                reader.push(event(first).as_bytes(), life, &mut idle, &mut |_| panic!("terminal callback")).unwrap();
                let before = reader.decoder.usage();
                let tail = reader.push(event(second).as_bytes(), life, &mut idle,
                    &mut |_| panic!("late callback"));
                if short {
                    assert!(matches!(tail, Err(DpopStreamError::Core(DpopCoreError::Protocol(
                        ManagedCoreError::ResponseByteLimit)))));
                    assert_eq!(reader.decoder.usage(), before);
                } else {
                    tail.unwrap();
                    assert_eq!(reader.finish(life, &idle).unwrap().usage, (total, 1));
                }
            }
        }
    });
}

#[test]
fn core_teardown_cannot_target_another_listen_or_hide_nonterminal_or_malformed_data() {
    fixture(|life, _| {
        for (established, first, bad) in [
            (false, None, CANCEL.to_owned()),
            (true, None, CANCEL.replace("\"requestId\":7", "\"requestId\":8")),
            (true, None, notification(json!(8), "notifications/cancelled", json!({"requestId":7}))),
            (true, Some(COMPLETE), CANCEL.replace("\"requestId\":7", "\"requestId\":\"7\"")),
            (true, Some(CANCEL), COMPLETE.replace("\"id\":7", "\"id\":8")),
            (true, Some(CANCEL), change(json!(7))),
            (true, Some(COMPLETE), COMPLETE.to_owned()),
            (true, Some(CANCEL), CANCEL.to_owned()),
            (true, None, r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"requestId":7}}"#.to_owned()),
        ] {
            let mut reader = reader(ModernHttpResponseKind::Sse, filter(), limits());
            let mut idle = Idle::new(life.cx.now(), limits().idle);
            if established {
                reader.push(event(&ack(json!(7), filter())).as_bytes(), life, &mut idle, &mut |_| true).unwrap();
            }
            if let Some(first) = first {
                reader.push(event(first).as_bytes(), life, &mut idle, &mut |_| true).unwrap();
            }
            let before = reader.decoder.usage();
            assert!(reader.push(event(&bad).as_bytes(), life, &mut idle,
                &mut |_| panic!("refused traffic cannot reach the observer")).is_err());
            assert_eq!(reader.decoder.usage(), before);
        }
        let mut reader = reader(ModernHttpResponseKind::Sse, filter(), limits());
        let mut idle = Idle::new(life.cx.now(), limits().idle);
        let wire = format!("{}{}data: unfinished", event(&ack(json!(7), filter())), event(CANCEL));
        reader.push(wire.as_bytes(), life, &mut idle, &mut |_| true).unwrap();
        assert!(reader.finish(life, &idle).is_err());
    });
}

#[test]
fn ordinary_core_rpc_still_rejects_the_subscription_tail_exception() {
    use fastmcp_protocol::protocol_policy::ProtocolEra;
    let request = CoreRequest::decode(ProtocolEra::Modern2026, "tools/list", Some(&json!({
        "_meta":FinalRequestMeta::new(ClientCapabilities::default())
    }))).unwrap();
    let mut decoder = CoreDecoder::for_request(request, RequestId::Number(7), limits().core).unwrap();
    let result = br#"{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete","tools":[]}}"#;
    assert!(matches!(StreamDecoder::admit(&mut decoder, result, true).unwrap(), StreamEvent::Result(_)));
    assert!(matches!(decoder.admit_terminal_tail(CANCEL.as_bytes()),
        Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::InvalidResponse)))));
}
