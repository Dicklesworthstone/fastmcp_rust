//! Cancelled public waiters must not require a runtime or publish a callback.

use super::*;
use crate::http_auth::dpop::DpopSession;
use crate::http_auth::dpop::native::DpopHttpPolicy;
use crate::http_auth::dpop::native::core::DpopCoreError;
use fastmcp_core::CanonicalHttpUrl;
use fastmcp_protocol::ClientCapabilities;
use fastmcp_protocol::dpop::DpopKey;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Instant;

#[derive(Clone, Copy)]
enum Entry {
    Default,
    WithCancellation,
    WithEvents,
}

fn client() -> (DpopHttpClient, DpopCredential) {
    let issuer = CanonicalHttpUrl::parse("https://issuer.example/token").unwrap();
    let resource = CanonicalHttpUrl::parse("https://mcp.example/mcp").unwrap();
    let session = DpopSession::new(
        DpopKey::generate().unwrap(), issuer.clone(), resource,
    ).unwrap();
    let credential = session.admit_token_response(
        &issuer, 200,
        br#"{"access_token":"preflight-token","token_type":"DPoP","expires_in":60}"#,
        Instant::now(), Duration::from_secs(60),
    ).unwrap();
    (DpopHttpClient::new(session, DpopHttpPolicy::default()).unwrap(), credential)
}

fn first_poll(
    entry: Entry,
    client: &mut DpopHttpClient,
    cx: &Cx,
    cancellation: &McpRequestCancellation,
    credential: &DpopCredential,
    prefix: &str,
) -> DpopHttpError {
    let metadata = FinalRequestMeta::new(ClientCapabilities::default());
    let task = TaskId::parse("task-one").unwrap();
    let policy = DpopTaskWaitPolicy::default();
    let mut operation: Pin<Box<dyn Future<Output = Result<
        DpopTaskWaitOutcome, DpopTaskWaitError,
    >> + '_>> = match entry {
        Entry::Default => Box::pin(client.wait_task(
            cx, credential, metadata, task, prefix, policy, ManagedCoreLimits::default(),
        )),
        Entry::WithCancellation => Box::pin(client.wait_task_with_cancellation(
            cx, cancellation, credential, metadata, task, prefix, policy,
            ManagedCoreLimits::default(),
        )),
        Entry::WithEvents => Box::pin(client.wait_task_with_events(
            cx, cancellation, credential, metadata, task, prefix, policy,
            DpopStreamLimits::default(),
            |_| panic!("a refused waiter must not publish notifications"),
        )),
    };
    match operation.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(Err(DpopTaskWaitError::Task(DpopTasksError::Core(
            DpopCoreError::Transport(error),
        )))) => error,
        _ => panic!("the first poll must return the exact local transport disposition"),
    }
}

#[test]
fn all_waiter_entrypoints_honor_caller_cancellation_without_a_runtime() {
    for entry in [Entry::Default, Entry::WithCancellation, Entry::WithEvents] {
        for prefix in ["valid", ""] {
            for revoked in [false, true] {
                let cx = Cx::for_testing();
                assert!(cx.timer_driver().is_none());
                cx.set_cancel_requested(true);
                let cancellation = McpRequestCancellation::new();
                let (mut client, credential) = client();
                if revoked {
                    credential.revoke();
                }
                assert_eq!(
                    first_poll(entry, &mut client, &cx, &cancellation, &credential, prefix),
                    DpopHttpError::Cancelled,
                );
                assert!(cx.checkpoint().is_err());
                // Retiring a call is not permission to revoke sibling users.
                assert!(!client.revocation_handle().is_revoked());
                assert!(!cancellation.is_cancel_requested());
            }
        }
    }
}

#[test]
fn request_cancellation_precedes_runtime_prefix_and_credential_checks() {
    for entry in [Entry::WithCancellation, Entry::WithEvents] {
        for prefix in ["valid", ""] {
            for revoked in [false, true] {
                let cx = Cx::for_testing();
                assert!(cx.timer_driver().is_none());
                let cancellation = McpRequestCancellation::new();
                cancellation.cancel();
                let (mut client, credential) = client();
                if revoked {
                    credential.revoke();
                }
                assert_eq!(
                    first_poll(entry, &mut client, &cx, &cancellation, &credential, prefix),
                    DpopHttpError::Cancelled,
                );
                assert!(cx.checkpoint().is_ok());
                assert!(!client.revocation_handle().is_revoked());
                assert!(cancellation.is_cancel_requested());
            }
        }
    }
}

#[test]
fn a_live_waiter_still_requires_a_runtime_and_cancellation_does_not_poison_the_client() {
    for entry in [Entry::Default, Entry::WithCancellation, Entry::WithEvents] {
        let (mut client, credential) = client();
        let live = Cx::for_testing();
        let cancellation = McpRequestCancellation::new();
        // Near-identical control: lack of a runtime is not itself cancellation.
        assert_eq!(
            first_poll(entry, &mut client, &live, &cancellation, &credential, "valid"),
            DpopHttpError::RuntimeUnavailable,
        );
        let cancelled = Cx::for_testing();
        cancelled.set_cancel_requested(true);
        assert_eq!(
            first_poll(entry, &mut client, &cancelled, &cancellation, &credential, "valid"),
            DpopHttpError::Cancelled,
        );
        assert_eq!(
            first_poll(entry, &mut client, &live, &cancellation, &credential, "valid"),
            DpopHttpError::RuntimeUnavailable,
        );
        assert!(live.checkpoint().is_ok());
        assert!(!client.revocation_handle().is_revoked());
    }
}
