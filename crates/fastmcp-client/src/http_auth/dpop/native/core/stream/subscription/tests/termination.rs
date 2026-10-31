use super::*;

const CANCEL: &str = r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"_meta":{"io.modelcontextprotocol/subscriptionId":7},"reason":"remote-only-canary"}}"#;

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
                assert_eq!(completed.usage, (ack.len() + first.len(), 1));
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
        let maximum = ack.len().max(CANCEL.len()).max(COMPLETE.len());
        for reverse in [false, true] {
            let first = if reverse { COMPLETE } else { CANCEL };
            let total = ack.len() + first.len();
            for short in [false, true] {
                let core = ManagedCoreLimits::new(8192, maximum, total - usize::from(short),
                    1, Duration::from_secs(60)).unwrap();
                let selected = DpopStreamLimits::new(core, Duration::from_secs(10)).unwrap();
                let mut reader = reader(ModernHttpResponseKind::Sse, filter(), selected);
                let mut idle = Idle::new(life.cx.now(), selected.idle);
                reader.push(event(&ack).as_bytes(), life, &mut idle, &mut |_| true).unwrap();
                let before = reader.decoder.usage();
                let terminal = reader.push(event(first).as_bytes(), life, &mut idle,
                    &mut |_| panic!("terminal callback"));
                if short {
                    assert!(matches!(terminal, Err(DpopStreamError::Core(DpopCoreError::Protocol(
                        ManagedCoreError::ResponseByteLimit)))));
                    assert_eq!(reader.decoder.usage(), before);
                } else {
                    terminal.unwrap();
                    assert!(reader.complete());
                    assert_eq!(reader.finish(life, &idle).unwrap().usage, (total, 1));
                }
            }
        }
    });
}

#[test]
fn core_teardown_requires_acknowledgement_and_both_exact_ids_before_state_changes() {
    fixture(|life, _| {
        for (established, bad) in [
            (false, CANCEL.to_owned()),
            (true, CANCEL.replace("\"requestId\":7", "\"requestId\":8")),
            (true, notification(json!(8), "notifications/cancelled", json!({"requestId":7}))),
            (true, CANCEL.replace("\"requestId\":7", "\"requestId\":\"7\"")),
            (true, notification(json!("7"), "notifications/cancelled", json!({"requestId":7}))),
            (true, notification(Value::Null, "notifications/cancelled", json!({"requestId":7}))),
            (true, r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}"#.to_owned()),
            (true, r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"requestId":7}}"#.to_owned()),
        ] {
            let mut reader = reader(ModernHttpResponseKind::Sse, filter(), limits());
            let mut idle = Idle::new(life.cx.now(), limits().idle);
            if established {
                reader.push(event(&ack(json!(7), filter())).as_bytes(), life, &mut idle, &mut |_| true).unwrap();
            }
            let before = reader.decoder.usage();
            assert!(reader.push(event(&bad).as_bytes(), life, &mut idle,
                &mut |_| panic!("refused traffic cannot reach the observer")).is_err());
            assert_eq!(reader.decoder.usage(), before);
            assert!(!reader.complete());
        }
    });
}

#[test]
fn core_first_terminal_discards_buffered_suffix_and_rechecks_original_authority() {
    for first in [CANCEL, COMPLETE] {
        for suffix in ["data: unfinished".to_owned(), event(CANCEL), event(COMPLETE),
            event(&change(json!(999))), "data: {malformed}\n\n".to_owned()] {
            fixture(|life, _| {
                let mut reader = reader(ModernHttpResponseKind::Sse, filter(), limits());
                let mut idle = Idle::new(life.cx.now(), limits().idle);
                let acknowledged = ack(json!(7), filter());
                let wire = format!("{}{}{suffix}", event(&acknowledged), event(first));
                reader.push(wire.as_bytes(), life, &mut idle, &mut |_| true).unwrap();
                assert!(reader.complete());
                assert_eq!(reader.finish(life, &idle).unwrap().usage,
                    (acknowledged.len() + first.len(), 1));
            });
        }
        for retire in 0..4 {
            fixture(|life, clock| {
                let mut reader = reader(ModernHttpResponseKind::Sse, filter(), limits());
                let mut idle = Idle::new(life.cx.now(), limits().idle);
                let wire = format!("{}{}", event(&ack(json!(7), filter())), event(first));
                reader.push(wire.as_bytes(), life, &mut idle, &mut |_| true).unwrap();
                match retire {
                    0 => { life.cancellation.cancel(); }
                    1 => { life.credential.revoke(); }
                    2 => { life.session.revoke(); }
                    _ => { clock.advance(11_000_000_000); }
                }
                assert!(matches!(reader.finish(life, &idle),
                    Err(DpopStreamError::Core(DpopCoreError::Transport(_)))));
                assert!(life.cx.checkpoint().is_ok());
            });
        }
    }
}

#[test]
fn original_credential_expiry_remains_a_terminal_publication_ceiling() {
    for first in [CANCEL, COMPLETE] {
        fixture(|life, clock| {
            let credential = life.session.admit_token_response(
                &CanonicalHttpUrl::parse("https://issuer.example/token").unwrap(), 200,
                br#"{"access_token":"short-lived-subscription","token_type":"DPoP","expires_in":1}"#,
                Instant::now(), Duration::from_secs(1),
            ).unwrap();
            let bounds = WaitBounds::new(life.cx, Duration::from_secs(60), &credential).unwrap();
            let original = Lifetime { cx: life.cx, cancellation: life.cancellation,
                session: life.session, credential: &credential, bounds };
            let mut reader = reader(ModernHttpResponseKind::Sse, filter(), limits());
            let mut idle = Idle::new(life.cx.now(), limits().idle);
            let wire = format!("{}{}", event(&ack(json!(7), filter())), event(first));
            reader.push(wire.as_bytes(), &original, &mut idle, &mut |_| true).unwrap();
            clock.advance(2_000_000_000);
            assert!(matches!(reader.finish(&original, &idle),
                Err(DpopStreamError::Core(DpopCoreError::Transport(DpopHttpError::Authorization(_))))));
            assert!(!life.cancellation.is_cancel_requested());
            assert!(life.cx.checkpoint().is_ok());
        });
    }
}

#[test]
fn ordinary_core_rpc_still_rejects_the_subscription_tail_exception() {
    use fastmcp_protocol::protocol_policy::ProtocolEra;
    let request = CoreRequest::decode(ProtocolEra::Modern2026, "tools/list", Some(&json!({
        "_meta":FinalRequestMeta::new(ClientCapabilities::default())
    }))).unwrap();
    let mut decoder = CoreDecoder::for_request(request, RequestId::Number(7), limits().core).unwrap();
    // Modern `tools/list` is a cache-hinted result family, so `ttlMs` and
    // `cacheScope` are required members. Without them the result decodes as
    // `Protocol(InvalidResult)` and the `admit` below unwraps on an error, so
    // the terminal-tail refusal this test actually asserts is never reached.
    // Every other modern complete-result fixture in this crate carries both.
    let result = br#"{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"}}"#;
    assert!(matches!(StreamDecoder::admit(&mut decoder, result, true).unwrap(), StreamEvent::Result(_)));
    assert!(matches!(decoder.admit_terminal_tail(CANCEL.as_bytes()),
        Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::InvalidResponse)))));
}
