//! Shared wire admission and result commitment for synchronous and async callers.
//!
//! Admission never constructs an application future. The public receive entry
//! point selects exactly one handler hook after admission; both paths return
//! through the same result validator and lifecycle commit boundary.

use super::*;

pub(super) enum PreparedReceive {
    Outbound(Legacy2024Outbound),
    Dispatch {
        id: Value,
        method: &'static str,
        params: Option<Value>,
    },
}

impl<H: Legacy2024Handler> Legacy2024ServerAdapter<H> {
    pub(super) fn prepare_receive(
        &mut self,
        binding: LegacyPeerBinding,
        wire: Value,
    ) -> Result<PreparedReceive, Legacy2024AdapterError> {
        self.require_binding(binding)?;
        let response_shaped = wire.as_object().is_some_and(|object| {
            // A conflicting method does not turn a peer response into a request.
            // JSON-RPC must never answer a response attempt with another response.
            object.contains_key("result")
                || object.contains_key("error")
                || (!object.contains_key("method") && object.contains_key("id"))
        });
        let request_id = response_id_from_wire(&wire);
        let envelope = match decode_legacy_2024_11_05_envelope_classified(wire) {
            Ok(envelope) => envelope,
            Err(error) => {
                let error = match error {
                    Legacy2024EnvelopeError::MethodParams(_) => {
                        Legacy2024AdapterError::invalid_params(
                            "invalid exact MCP 2024-11-05 parameters",
                        )
                    }
                    Legacy2024EnvelopeError::Method(_) => Legacy2024AdapterError::method_not_found(
                        "method is not part of exact MCP 2024-11-05",
                    ),
                    Legacy2024EnvelopeError::Envelope(_) => {
                        Legacy2024AdapterError::invalid_request(
                            "invalid exact MCP 2024-11-05 envelope",
                        )
                    }
                };
                return match (response_shaped, request_id) {
                    (true, _) | (false, None) => Err(error),
                    (false, Some(id)) => Ok(PreparedReceive::Outbound(
                        Legacy2024Outbound::Response(error_response(id, error)),
                    )),
                };
            }
        };
        match envelope {
            Legacy2024Envelope::Request { method, id, params } => {
                match self.prepare_request(method.name, params.as_ref()) {
                    Ok(Some(result)) => Ok(PreparedReceive::Outbound(
                        Legacy2024Outbound::Response(success_response(id, result)),
                    )),
                    Ok(None) => Ok(PreparedReceive::Dispatch {
                        id,
                        method: method.name,
                        params,
                    }),
                    Err(error) => Ok(PreparedReceive::Outbound(
                        Legacy2024Outbound::Response(error_response(id, error)),
                    )),
                }
            }
            Legacy2024Envelope::Notification { method, params } => {
                self.receive_notification(method.name, params.as_ref())?;
                Ok(PreparedReceive::Outbound(Legacy2024Outbound::NoResponse))
            }
            Legacy2024Envelope::Response { id, .. } | Legacy2024Envelope::Error { id, .. } => {
                self.complete_reverse_request(id)?;
                Ok(PreparedReceive::Outbound(Legacy2024Outbound::NoResponse))
            }
        }
    }

    // Some is a result owned entirely by the adapter; None admits one application
    // call. There is no handler construction, polling, or runtime entry here.
    fn prepare_request(
        &mut self,
        method: &'static str,
        params: Option<&Value>,
    ) -> Result<Option<Value>, Legacy2024AdapterError> {
        match self.lifecycle {
            Legacy2024Lifecycle::AwaitInitialize => {
                if method != INITIALIZE {
                    return Err(Legacy2024AdapterError::invalid_request(
                        "initialize is the only request allowed before lifecycle admission",
                    ));
                }
                self.admit_initialize(params).map(Some)
            }
            Legacy2024Lifecycle::AwaitInitialized => Err(Legacy2024AdapterError::invalid_request(
                "notifications/initialized is required before operating requests",
            )),
            Legacy2024Lifecycle::Operating => match method {
                PING => Ok(Some(json!({}))),
                RESOURCES_SUBSCRIBE | RESOURCES_UNSUBSCRIBE => {
                    self.require_resource_subscribe_capability()?;
                    Ok(None)
                }
                LOGGING_SET_LEVEL => self.set_logging_level(params).map(Some),
                TOOLS_LIST
                | TOOLS_CALL
                | RESOURCES_LIST
                | RESOURCES_TEMPLATES_LIST
                | RESOURCES_READ
                | PROMPTS_LIST
                | PROMPTS_GET
                | COMPLETION_COMPLETE => {
                    self.require_server_capability(method)?;
                    Ok(None)
                }
                _ => Err(Legacy2024AdapterError::method_not_found(
                    "method direction or lifecycle is not admitted by exact MCP 2024-11-05",
                )),
            },
            Legacy2024Lifecycle::Closed => Err(Legacy2024AdapterError::invalid_request(
                "legacy adapter lifecycle is closed",
            )),
        }
    }

    pub(super) fn finish_receive(
        &mut self,
        id: Value,
        method: &'static str,
        params: Option<&Value>,
        result: Result<Value, Legacy2024HandlerError>,
    ) -> Legacy2024Outbound {
        let result = result
            .map_err(|error| Legacy2024AdapterError {
                code: error.code().clone(),
                message: error.message().to_owned(),
            })
            .and_then(|result| match method {
                // Subscription state changes only after the selected handler
                // succeeds. Dropping a pending async receive never commits it.
                RESOURCES_SUBSCRIBE => self.subscribe(params),
                RESOURCES_UNSUBSCRIBE => self.unsubscribe(params),
                TOOLS_CALL if self.application_tool_content => {
                    validate_application_tool_result(result)
                }
                TOOLS_CALL | RESOURCES_READ | PROMPTS_GET => {
                    translate_legacy_2024_result(method, result).map_err(|_| {
                        Legacy2024AdapterError {
                            code: JsonInteger::from(-32603),
                            message: "handler result is not losslessly representable in exact MCP 2024-11-05"
                                .to_owned(),
                        }
                    })
                }
                _ => Ok(result),
            });
        Legacy2024Outbound::Response(match result {
            Ok(result) => success_response(id, result),
            Err(error) => error_response(id, error),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::future::{Future, poll_fn};
    use std::pin::pin;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    fn binding() -> LegacyPeerBinding {
        LegacyPeerBinding::from_authenticated_transport(
            LegacyAuthenticatedPeerPartition::from_authenticated_transport([0x61; 32]),
            61,
        )
    }

    fn adapter<H: Legacy2024Handler>(handler: H) -> Legacy2024ServerAdapter<H> {
        use fastmcp_protocol::methods::{
            Legacy2024ListChangedCapability, Legacy2024ResourcesCapability,
        };
        let config = Legacy2024ServerConfig {
            capabilities: Legacy2024ServerCapabilities {
                tools: Some(Legacy2024ListChangedCapability::default()),
                resources: Some(Legacy2024ResourcesCapability {
                    subscribe: true,
                    ..Legacy2024ResourcesCapability::default()
                }),
                ..Legacy2024ServerCapabilities::default()
            },
            server_info: Legacy2024ServerInfo { name: "dispatch-test".into(), version: "1".into() },
            instructions: None,
        };
        Legacy2024ServerAdapter::install(binding(), config, handler).unwrap()
    }

    fn initialize<H: Legacy2024Handler>(adapter: &mut Legacy2024ServerAdapter<H>) {
        let response = adapter.receive(binding(), json!({
            "jsonrpc":"2.0", "id":1, "method":INITIALIZE,
            "params":{"protocolVersion":"2024-11-05", "capabilities":{},
                "clientInfo":{"name":"test", "version":"1"}}
        })).unwrap();
        let Legacy2024Outbound::Response(response) = response else { panic!("initialize response") };
        assert!(response.get("error").is_none(), "{response}");
        assert_eq!(adapter.receive(binding(), json!({
            "jsonrpc":"2.0", "method":NOTIFICATIONS_INITIALIZED,
        })).unwrap(), Legacy2024Outbound::NoResponse);
    }

    // No executor is created: only a future known to be immediately ready may
    // pass this helper. Suspension tests explicitly observe Pending themselves.
    fn ready<T>(future: impl Future<Output = T>) -> T {
        let mut future = pin!(future);
        match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("unexpected suspension"),
        }
    }

    struct SyncOnly {
        calls: Rc<Cell<usize>>,
    }

    impl Legacy2024Handler for SyncOnly {
        fn handle_legacy_2024(&mut self, _: &'static str, _: Option<&Value>)
            -> Result<Value, Legacy2024HandlerError>
        {
            panic!("the exact request-ID hook must be selected")
        }

        fn handle_legacy_2024_with_request_id(
            &mut self, id: &Value, method: &'static str, params: Option<&Value>,
        ) -> Result<Value, Legacy2024HandlerError> {
            assert!(asupersync::Cx::current().is_none(), "adapter installed a hidden runtime");
            self.calls.set(self.calls.get() + 1);
            Ok(json!({"id":id, "method":method, "params":params}))
        }

        fn handle_legacy_2024_with_request_id_async<'a>(
            &'a mut self, _: &'a Value, _: &'static str, _: Option<&'a Value>,
        ) -> crate::BoxFuture<'a, Result<Value, Legacy2024HandlerError>> {
            panic!("synchronous receive must not construct an async handler future")
        }
    }

    #[test]
    fn synchronous_receive_calls_the_exact_sync_hook_without_a_runtime() {
        let _ambient = asupersync::Cx::set_current(None);
        let calls = Rc::new(Cell::new(0));
        let mut adapter = adapter(SyncOnly { calls: Rc::clone(&calls) });
        initialize(&mut adapter);
        let id = json!("sync-request-61");
        let params = json!({"cursor":"exact-cursor"});
        let response = adapter.receive(binding(), json!({
            "jsonrpc":"2.0", "id":id, "method":TOOLS_LIST, "params":params,
        })).unwrap();
        assert_eq!(response, Legacy2024Outbound::Response(json!({
            "jsonrpc":"2.0", "id":id,
            "result":{"id":id, "method":TOOLS_LIST, "params":params},
        })));
        assert_eq!(calls.get(), 1);
        assert!(asupersync::Cx::current().is_none());
    }

    struct AsyncOnly {
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }

    struct Dropped(Arc<AtomicUsize>);
    impl Drop for Dropped {
        fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
    }

    impl Legacy2024Handler for AsyncOnly {
        fn handle_legacy_2024(&mut self, _: &'static str, _: Option<&Value>)
            -> Result<Value, Legacy2024HandlerError>
        {
            panic!("async receive must not invoke a synchronous application hook")
        }

        fn handle_legacy_2024_with_request_id_async<'a>(
            &'a mut self, id: &'a Value, method: &'static str, params: Option<&'a Value>,
        ) -> crate::BoxFuture<'a, Result<Value, Legacy2024HandlerError>> {
            let polls = Arc::clone(&self.polls);
            let dropped = Dropped(Arc::clone(&self.drops));
            let mut pending = true;
            Box::pin(poll_fn(move |task| {
                let _keep_until_completion = &dropped;
                polls.fetch_add(1, Ordering::SeqCst);
                if pending {
                    pending = false;
                    task.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    Poll::Ready(Ok(json!({"id":id, "method":method, "params":params})))
                }
            }))
        }
    }

    #[test]
    fn async_receive_suspends_and_preserves_the_exact_request_hook() {
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut adapter = adapter(AsyncOnly { polls: Arc::clone(&polls), drops: Arc::clone(&drops) });
        initialize(&mut adapter);
        let before = adapter.snapshot();
        let params = json!({"cursor":"async-cursor"});
        let request = json!({"jsonrpc":"2.0", "id":"async-61", "method":TOOLS_LIST, "params":params});
        let mut task = Context::from_waker(Waker::noop());
        {
            let mut future = pin!(adapter.receive_async(binding(), request));
            assert_eq!(polls.load(Ordering::SeqCst), 0);
            assert!(future.as_mut().poll(&mut task).is_pending());
            assert_eq!(polls.load(Ordering::SeqCst), 1);
            let Poll::Ready(result) = future.as_mut().poll(&mut task) else { panic!("second poll") };
            assert_eq!(result.unwrap(), Legacy2024Outbound::Response(json!({
                "jsonrpc":"2.0", "id":"async-61",
                "result":{"id":"async-61", "method":TOOLS_LIST, "params":params},
            })));
        }
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(adapter.snapshot(), before);
    }

    #[test]
    fn abandoning_async_subscription_drops_the_handler_without_committing_state() {
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut adapter = adapter(AsyncOnly { polls: Arc::clone(&polls), drops: Arc::clone(&drops) });
        initialize(&mut adapter);
        let before = adapter.snapshot();
        {
            let mut future = pin!(adapter.receive_async(binding(), json!({
                "jsonrpc":"2.0", "id":2, "method":RESOURCES_SUBSCRIBE,
                "params":{"uri":"file:///abandoned"},
            })));
            assert!(future.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        }
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(adapter.snapshot(), before);
        assert_eq!(ready(adapter.receive_async(binding(), json!({
            "jsonrpc":"2.0", "id":3, "method":PING,
        }))).unwrap(), Legacy2024Outbound::Response(json!({"jsonrpc":"2.0", "id":3, "result":{}})));
    }
}
