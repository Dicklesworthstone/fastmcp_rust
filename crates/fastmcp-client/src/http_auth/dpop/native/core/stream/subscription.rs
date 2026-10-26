//! Core subscriptions on the existing explicit DPoP HTTPS stream owner.
//!
//! A subscription is not an ordinary core call: its acknowledgement establishes
//! an accepted filter and every later notification must belong to that filter
//! and request ID. Both Bearer and DPoP use the same subscription decoder. The
//! transport owner remains the ordinary DPoP reader, including its bounded
//! ready-work turns, original credential and cancellation guards. Only the
//! subscription owner releases its body on the first valid terminal signal.

mod termination;
use termination::TerminalDecoder;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{
    CoreResult, FinalSubscriptionsListenParams, RequestId, ServerNotification,
};

use super::{
    DpopCredential, DpopHttpClient, DpopStreamError, DpopStreamLimits, Idle, Lifetime,
    PreparedStream, StreamDecoder, StreamEvent, WaitBounds, with_caller,
};
use crate::http_auth::rpc::subscription::{SubscriptionDecoder, prepare_bounded};

impl StreamDecoder for SubscriptionDecoder {
    type Terminal = CoreResult;

    fn admit(
        &mut self,
        frame: &[u8],
        allow_notification: bool,
    ) -> Result<StreamEvent<CoreResult>, DpopStreamError> {
        if !allow_notification {
            // A finite JSON response can report a correlated refusal, never
            // establish a subscription or pretend it delivered an SSE ack.
            return Err(self.json_error(frame).into());
        }
        SubscriptionDecoder::admit(self, frame)
            .map(StreamEvent::from)
            .map_err(DpopStreamError::from)
    }

    fn usage(&self) -> (usize, usize) {
        SubscriptionDecoder::usage(self)
    }
}

impl DpopHttpClient {
    /// Opens one authenticated core `subscriptions/listen` POST and delivers
    /// its admitted acknowledgement and selected changes incrementally.
    ///
    /// The host supplies exact final metadata and a filter for tool, resource,
    /// prompt catalog changes and/or exact resource URIs. The peer may narrow
    /// that filter, never widen it. Acknowledgement is delivered first and counts
    /// against the notification quota. Task selectors and nonempty extension
    /// offers are refused before signing or I/O; this method does not negotiate
    /// extensions or turn an ordinary call into a subscription.
    ///
    /// The observer returns true to continue or false to release the socket.
    /// It must be brief and nonblocking. Already-observed notifications cannot
    /// be recalled after a later failure. The returned result is the shared
    /// typed subscription completion. Peer cancellation after ACK instead
    /// returns SubscriptionCancelled; it never cancels the caller or fabricates
    /// completion. Both its request ID and subscription metadata must match.
    /// The first valid terminal releases the body without waiting for HTTP EOF,
    /// and later buffered signals are discarded. Terminal control spends
    /// payload bytes but not event slots. Before that terminal, premature EOF,
    /// foreign IDs, unselected events and incomplete SSE frames are errors.
    /// A finite JSON refusal exposes only its error code.
    ///
    /// This is a bounded listen, not an indefinitely renewed connection. The
    /// original native/core/caller/token deadlines and raw/payload/parser bounds
    /// apply to the whole exchange. Subscription events and comments do not
    /// extend the configured idle budget. Cancellation, credential revocation,
    /// observer refusal/panic or dropping the future stops this owned request;
    /// no reconnect, credential refresh, bearer downgrade, cancellation POST or
    /// detached task is created. A later listen is a new explicit host action.
    #[allow(clippy::too_many_arguments)]
    pub async fn listen_core_with_events<N>(
        &mut self,
        cx: &Cx,
        cancellation: &McpRequestCancellation,
        credential: &DpopCredential,
        params: FinalSubscriptionsListenParams,
        request_id: RequestId,
        limits: DpopStreamLimits,
        mut observer: N,
    ) -> Result<CoreResult, DpopStreamError>
    where
        N: FnMut(&ServerNotification) -> bool,
    {
        let bounds = WaitBounds::new(cx, self.policy.timeout.min(limits.core.timeout()), credential)?;
        let lifetime = Lifetime {
            cx,
            cancellation,
            session: &self.session,
            credential,
            bounds,
        };
        let idle = Idle::new(cx.now(), limits.idle);
        with_caller(cx, || lifetime.check(&idle))?;
        let (wire, decoder) = prepare_bounded(
            self.resource().as_str(),
            params,
            request_id.clone(),
            limits.core,
            self.policy.max_body_bytes,
        )?;
        let decoder = TerminalDecoder::new(decoder, request_id, limits.core);
        self.execute_prepared_core_stream(
            cx,
            cancellation,
            credential,
            PreparedStream {
                wire,
                decoder,
                limits,
                bounds,
                idle,
            },
            &mut observer,
        )
        .await?
        .result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use asupersync::runtime::RuntimeBuilder;
    use asupersync::time::{TimerDriverHandle, VirtualClock};
    use fastmcp_core::CanonicalHttpUrl;
    use fastmcp_protocol::dpop::DpopKey;
    use fastmcp_protocol::{
        ClientCapabilities, CoreRequest, FINAL_SUBSCRIPTION_ID_META_KEY, FinalCoreRequest,
        FinalCoreResult, FinalRequestMeta,
    };
    use serde_json::{Value, json};

    use super::super::{
        CoreDecoder, DpopCoreError, DpopHttpError, DpopSession, ManagedCoreError, ManagedCoreLimits,
        ModernHttpResponseKind, Reader,
    };

    mod termination;

    #[cfg(feature = "native-tls-roots")]
    mod tls;

    const TARGET: &str = "https://mcp.example/mcp";
    const RESOURCE: &str = "file:///a%2Fb?scope=one";
    const COMPLETE: &str = r#"{"jsonrpc":"2.0","id":7,"result":{"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":7},"x-exact":{"z":900719925474099312345,"a":1.20e+4,"text":"雪"}}}"#;

    fn params(filter: Value) -> FinalSubscriptionsListenParams {
        serde_json::from_value(json!({
            "_meta":FinalRequestMeta::new(ClientCapabilities::default()),
            "notifications":filter
        }))
        .unwrap()
    }

    fn filter() -> Value {
        json!({"toolsListChanged":true,"resourceSubscriptions":[RESOURCE]})
    }

    fn limits() -> DpopStreamLimits {
        DpopStreamLimits::new(
            ManagedCoreLimits::new(8192, 8192, 32768, 16, Duration::from_secs(60)).unwrap(),
            Duration::from_secs(10),
        )
        .unwrap()
    }

    fn notification(id: Value, method: &str, mut payload: Value) -> String {
        payload["_meta"] = json!({});
        payload["_meta"][FINAL_SUBSCRIPTION_ID_META_KEY] = id;
        serde_json::to_string(&json!({
            "jsonrpc":"2.0","method":method,"params":payload
        }))
        .unwrap()
    }

    fn ack(id: Value, accepted: Value) -> String {
        notification(
            id,
            "notifications/subscriptions/acknowledged",
            json!({"notifications":accepted}),
        )
    }

    fn change(id: Value) -> String {
        notification(id, "notifications/tools/list_changed", json!({}))
    }

    fn updated(uri: &str) -> String {
        notification(json!(7), "notifications/resources/updated", json!({"uri":uri}))
    }

    fn event(payload: &str) -> String {
        format!("data: {payload}\r\n\r\n")
    }

    fn reader(
        kind: ModernHttpResponseKind,
        requested: Value,
        limits: DpopStreamLimits,
    ) -> Reader<TerminalDecoder> {
        let (_, decoder) = prepare_bounded(
            TARGET, params(requested), RequestId::Number(7), limits.core, 8192,
        )
        .unwrap();
        Reader::new(kind, TerminalDecoder::new(decoder, RequestId::Number(7), limits.core), limits, 32768).unwrap()
    }

    fn fixture(f: impl FnOnce(&Lifetime<'_>, &Arc<VirtualClock>)) {
        let clock = Arc::new(VirtualClock::new());
        let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(0, 0)
            .with_timer_driver(timer.clone())
            .build()
            .unwrap();
        let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
        let session = DpopSession::new(
            DpopKey::generate().unwrap(), issuer.clone(), CanonicalHttpUrl::parse(TARGET).unwrap(),
        )
        .unwrap();
        let credential = session.admit_token_response(
            &issuer, 200,
            br#"{"access_token":"subscription-token","token_type":"DPoP","expires_in":300}"#,
            Instant::now(), Duration::from_secs(300),
        )
        .unwrap();
        let cancellation = McpRequestCancellation::new();
        let bounds = WaitBounds::new(&cx, Duration::from_secs(60), &credential).unwrap();
        let lifetime = Lifetime {
            cx: &cx, cancellation: &cancellation, session: &session, credential: &credential, bounds,
        };
        with_caller(&cx, || f(&lifetime, &clock));
        assert_eq!(timer.pending_count(), 0);
        drop(cx);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn subscription_preparation_preserves_identity_and_both_exact_request_caps() {
        let (wire, _) = prepare_bounded(
            TARGET, params(filter()), RequestId::Number(7), limits().core, 8192,
        )
        .unwrap();
        let encoded: Value = serde_json::from_slice(wire.body()).unwrap();
        assert_eq!(encoded["id"], 7);
        assert_eq!(encoded["method"], "subscriptions/listen");
        assert_eq!(encoded["params"]["notifications"], filter());
        assert!(wire.headers().iter().any(|(name, value)|
            name == "Mcp-Method" && value == "subscriptions/listen"));
        assert!(!wire.headers().iter().any(|(name, _)|
            name == "Authorization" || name == "DPoP" || name == "Mcp-Name"));
        let length = wire.body().len();
        for native_bound in [false, true] {
            for exact in [false, true] {
                let cap = length - usize::from(!exact);
                let core = ManagedCoreLimits::new(
                    if native_bound { 8192 } else { cap },
                    8192, 32768, 16, Duration::from_secs(60),
                )
                .unwrap();
                let result = prepare_bounded(
                    TARGET, params(filter()), RequestId::Number(7), core,
                    if native_bound { cap } else { 8192 },
                );
                if exact {
                    assert!(result.is_ok());
                } else {
                    assert!(matches!(result, Err(ManagedCoreError::RequestTooLarge)));
                }
            }
        }
        // The new operation must not weaken the ordinary call's method table.
        assert!(matches!(
            CoreDecoder::for_request(
                CoreRequest::Final(FinalCoreRequest::SubscriptionsListen(params(filter()))),
                RequestId::Number(7), limits().core,
            ),
            Err(ManagedCoreError::UnsupportedRequest)
        ));
    }

    #[test]
    fn subscription_preparation_refuses_unnegotiated_selectors_and_extension_offers() {
        for forbidden in [
            json!({"taskIds":["task-private"]}),
            json!({"resourceSubscriptions":[RESOURCE,RESOURCE]}),
        ] {
            assert!(prepare_bounded(
                TARGET, params(forbidden), RequestId::Number(7), limits().core, 8192,
            ).is_err());
        }
        let mut source = json!({
            "_meta":FinalRequestMeta::new(ClientCapabilities::default()),
            "notifications":filter(),
        });
        source["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"] =
            json!({"io.modelcontextprotocol/tasks":{}});
        assert!(matches!(
            prepare_bounded(
                TARGET, serde_json::from_value(source).unwrap(), RequestId::Number(7),
                limits().core, 8192,
            ),
            Err(ManagedCoreError::UnsupportedRequest)
        ));
        let no_events = ManagedCoreLimits::new(
            8192, 8192, 32768, 0, Duration::from_secs(60),
        ).unwrap();
        assert!(matches!(
            prepare_bounded(TARGET, params(filter()), RequestId::Number(7), no_events, 8192),
            Err(ManagedCoreError::InvalidLimits)
        ));
    }

    #[test]
    fn subscription_reader_is_incremental_and_chunk_invariant_with_lossless_completion() {
        fixture(|life, _| {
            let acknowledgement = ack(json!(7), filter());
            let changed = change(json!(7));
            let resource = updated(RESOURCE);
            let wire = format!("{}{}{}{}", event(&acknowledgement), event(&changed), event(&resource), event(COMPLETE));
            for split in 0..=wire.len() {
                let mut reader = reader(ModernHttpResponseKind::Sse, filter(), limits());
                let mut idle = Idle::new(life.cx.now(), limits().idle);
                let mut observations = Vec::new();
                let mut observe = |notification: &ServerNotification| {
                    observations.push(matches!(notification, ServerNotification::SubscriptionsAcknowledged(_)));
                    true
                };
                reader.push(&wire.as_bytes()[..split], life, &mut idle, &mut observe).unwrap();
                reader.push(&wire.as_bytes()[split..], life, &mut idle, &mut observe).unwrap();
                assert_eq!(observations, [true, false, false]);
                assert_eq!(reader.decoder.usage(), (acknowledgement.len() + changed.len() + resource.len() + COMPLETE.len(), 3));
                let result = reader.finish(life, &idle).unwrap().result.unwrap();
                assert!(matches!(&result, CoreResult::Final(FinalCoreResult::SubscriptionsListen { .. })));
                let encoded = result.encode().unwrap();
                assert!(encoded.contains("900719925474099312345"));
                assert!(encoded.contains("1.20e+4"));
            }
            let mut reader = reader(ModernHttpResponseKind::Sse, filter(), limits());
            let mut idle = Idle::new(life.cx.now(), limits().idle);
            let mut calls = 0;
            reader.push(event(&acknowledgement).as_bytes(), life, &mut idle, &mut |_| {
                calls += 1; true
            }).unwrap();
            assert_eq!(calls, 1, "acknowledgement is delivered before final bytes exist");
            assert!(reader.terminal.is_none());
        });
    }

    #[test]
    fn rejected_subscription_events_never_reach_the_observer_or_advance_the_decoder() {
        fixture(|life, _| {
            for (established, invalid) in [
                (false, change(json!(7))),
                (false, COMPLETE.to_owned()),
                (false, ack(json!("7"), filter())),
                (false, ack(json!(7), json!({"promptsListChanged":true}))),
                (true, change(json!(8))),
                (true, updated("file:///a/b?scope=one")),
                (true, ack(json!(7), filter())),
                (true, notification(json!(7), "notifications/prompts/list_changed", json!({}))),
            ] {
                let mut reader = reader(ModernHttpResponseKind::Sse, filter(), limits());
                let mut idle = Idle::new(life.cx.now(), limits().idle);
                if established {
                    reader.push(event(&ack(json!(7), filter())).as_bytes(), life, &mut idle, &mut |_| true).unwrap();
                }
                let before = reader.decoder.usage();
                let mut calls = 0;
                assert!(reader.push(event(&invalid).as_bytes(), life, &mut idle, &mut |_| {
                    calls += 1; true
                }).is_err());
                assert_eq!(calls, 0);
                assert_eq!(reader.decoder.usage(), before);
                assert!(reader.terminal.is_none());
            }
        });
    }

    #[test]
    fn subscription_acknowledgement_spends_quota_without_extending_deadlines() {
        fixture(|life, clock| {
            let core = ManagedCoreLimits::new(8192, 8192, 32768, 1, Duration::from_secs(60)).unwrap();
            let bounded = DpopStreamLimits::new(core, Duration::from_secs(10)).unwrap();
            let mut reader = reader(ModernHttpResponseKind::Sse, filter(), bounded);
            let mut idle = Idle::new(life.cx.now(), bounded.idle);
            let original = idle.deadline;
            clock.advance(9_000_000_000);
            reader.push(event(&ack(json!(7), filter())).as_bytes(), life, &mut idle, &mut |_| true).unwrap();
            assert_eq!(reader.decoder.usage().1, 1);
            assert_eq!(idle.deadline, original);
            let mut calls = 0;
            let error = reader.push(event(&change(json!(7))).as_bytes(), life, &mut idle, &mut |_| {
                calls += 1; true
            }).unwrap_err();
            assert!(matches!(error, DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::NotificationLimit))));
            assert_eq!(calls, 0);
            assert_eq!(idle.deadline, original);
            clock.advance(1_000_000_000);
            assert!(matches!(life.check(&idle), Err(DpopHttpError::TimedOut)));
        });
    }

    #[test]
    fn subscription_observer_stop_and_same_poll_cancellation_withhold_completion() {
        for action in 0..4 {
            fixture(|life, _| {
                let wire = format!("{}{}{}", event(&ack(json!(7), filter())), event(&change(json!(7))), event(COMPLETE));
                let mut reader = reader(ModernHttpResponseKind::Sse, filter(), limits());
                let mut idle = Idle::new(life.cx.now(), limits().idle);
                let mut calls = 0;
                let result = reader.push(wire.as_bytes(), life, &mut idle, &mut |_| {
                    calls += 1;
                    match action {
                        0 => return false,
                        1 => { life.cancellation.cancel(); }
                        2 => life.credential.revoke(),
                        _ => panic!("subscription-observer-private-canary"),
                    }
                    true
                });
                let error = result.unwrap_err();
                assert_eq!(calls, 1);
                assert!(reader.terminal.is_none());
                assert!(!format!("{error:?} {error}").contains("subscription-observer-private-canary"));
                match action {
                    0 => assert!(matches!(error, DpopStreamError::ObserverStopped)),
                    3 => assert!(matches!(error, DpopStreamError::ObserverPanicked)),
                    _ => assert!(matches!(error, DpopStreamError::Core(DpopCoreError::Transport(_)))),
                }
                assert!(!life.cx.is_cancel_requested(), "request-local retirement preserves the caller");
            });
        }
    }

    #[test]
    fn subscription_json_refusals_and_sse_eof_cannot_fabricate_establishment() {
        fixture(|life, _| {
            let refusal = r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"private-peer-canary","data":{"token":"private-data-canary"}}}"#;
            for (frame, remote) in [(refusal, true), (COMPLETE, false)] {
                let mut reader = reader(ModernHttpResponseKind::Json, filter(), limits());
                let mut idle = Idle::new(life.cx.now(), limits().idle);
                let mut calls = 0;
                reader.push(frame.as_bytes(), life, &mut idle, &mut |_| { calls += 1; true }).unwrap();
                let error = reader.finish(life, &idle).err().unwrap();
                assert_eq!(calls, 0);
                assert_eq!(matches!(&error, DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::Remote { .. }))), remote);
                assert!(!format!("{error:?} {error}").contains("private-peer-canary"));
                assert!(!format!("{error:?} {error}").contains("private-data-canary"));
            }
            for tail in ["data: unfinished", ": unfinished"] {
                let mut reader = reader(ModernHttpResponseKind::Sse, filter(), limits());
                let mut idle = Idle::new(life.cx.now(), limits().idle);
                let wire = format!("{}{tail}", event(&ack(json!(7), filter())));
                reader.push(wire.as_bytes(), life, &mut idle, &mut |_| true).unwrap();
                assert!(reader.terminal.is_none());
                assert!(matches!(reader.finish(life, &idle), Err(DpopStreamError::Core(DpopCoreError::Protocol(ManagedCoreError::InvalidResponse)))));
            }
        });
    }
}
