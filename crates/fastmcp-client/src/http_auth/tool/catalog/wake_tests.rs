use super::*;
use super::super::await_validity;
use fastmcp_protocol::{ClientCapabilities, FinalRequestMeta};
use serde_json::json;
use std::future::{Future, pending};
use std::sync::atomic::AtomicUsize;
use std::task::{Context, Poll, Wake, Waker};

#[derive(Default)]
struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

fn admitted() -> (Contracts, Arc<AtomicBool>) {
    let params = json!({"_meta": FinalRequestMeta::new(ClientCapabilities::default())});
    let request = CoreRequest::decode(ProtocolEra::Modern2026, "tools/list", Some(&params)).unwrap();
    let page = request.decode_result(r#"{"resultType":"complete","ttlMs":0,"cacheScope":"private","tools":[{"name":"alpha","inputSchema":{"type":"object"}},{"name":"beta","inputSchema":{"type":"object"}}]}"#).unwrap();
    admit_contracts(&[page], ManagedToolCatalogLimits::default()).unwrap()
}

#[test]
fn catalog_change_wakes_every_tool_after_publishing_shared_invalidity() {
    let cx = Cx::for_testing();
    let cancellation = McpRequestCancellation::new();
    let (contracts, flag) = admitted();
    let mut active = ActiveCatalog::default();
    active.install_contracts(flag.clone(), &contracts);
    let wakes: Vec<_> = contracts.values().map(|_| Arc::new(Wakes::default())).collect();
    let mut readers: Vec<_> = contracts.values().map(|contract| Box::pin(
        await_validity(&cx, &cancellation, contract, pending::<()>()),
    )).collect();
    for (reader, wakes) in readers.iter_mut().zip(&wakes) {
        let waker = Waker::from(wakes.clone());
        assert!(reader.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    }
    active.observe_notification(&ServerNotification::ToolsListChanged(None));
    assert!(flag.load(Ordering::Acquire));
    for (reader, wakes) in readers.iter_mut().zip(&wakes) {
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(reader.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(ManagedToolError::Invalidated))));
    }
    assert!(active.1.is_empty());
    assert!(!cancellation.is_cancel_requested());
    assert!(cx.checkpoint().is_ok());
}

#[test]
fn individual_and_unrelated_changes_do_not_wake_sibling_tools() {
    let cx = Cx::for_testing();
    let cancellation = McpRequestCancellation::new();
    let (contracts, flag) = admitted();
    let mut active = ActiveCatalog::default();
    active.install_contracts(flag.clone(), &contracts);
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    let mut reader = Box::pin(await_validity(&cx, &cancellation, &contracts["beta"], pending::<()>()));
    assert!(reader.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    contracts["alpha"].invalidate();
    active.observe_notification(&ServerNotification::PromptsListChanged(None));
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    assert!(!flag.load(Ordering::Acquire));
    assert!(reader.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    active.invalidate();
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(reader.as_mut().poll(&mut Context::from_waker(&waker)),
        Poll::Ready(Err(ManagedToolError::Invalidated))));
}

#[test]
fn replacement_wakes_old_work_without_retiring_replacement_contracts() {
    let cx = Cx::for_testing();
    let cancellation = McpRequestCancellation::new();
    let (old, old_flag) = admitted();
    let (new, new_flag) = admitted();
    let mut active = ActiveCatalog::default();
    active.install_contracts(old_flag.clone(), &old);
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    let mut reader = Box::pin(await_validity(&cx, &cancellation, &old["alpha"], pending::<()>()));
    assert!(reader.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    active.install_contracts(new_flag.clone(), &new);
    assert!(old_flag.load(Ordering::Acquire));
    assert!(!new_flag.load(Ordering::Acquire));
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(new.values().all(|contract| contract.check().is_ok() && !contract.invalidation.is_cancel_requested()));
    assert!(matches!(reader.as_mut().poll(&mut Context::from_waker(&waker)),
        Poll::Ready(Err(ManagedToolError::Invalidated))));
    assert_eq!(active.1.len(), new.len());
}

#[test]
fn dropping_the_watch_owner_wakes_current_work_without_a_peer_event() {
    let cx = Cx::for_testing();
    let cancellation = McpRequestCancellation::new();
    let (contracts, flag) = admitted();
    let mut active = ActiveCatalog::default();
    active.install_contracts(flag.clone(), &contracts);
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    let mut reader = Box::pin(await_validity(&cx, &cancellation, &contracts["alpha"], pending::<()>()));
    assert!(reader.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    drop(active);
    assert!(flag.load(Ordering::Acquire));
    assert!(wakes.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(reader.as_mut().poll(&mut Context::from_waker(&waker)),
        Poll::Ready(Err(ManagedToolError::Invalidated))));
    assert!(!cancellation.is_cancel_requested());
}
