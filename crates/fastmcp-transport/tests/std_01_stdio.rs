//! Public STD-01 stdio acceptance entries.
//!
//! These top-level test names deliberately match the frozen RCH runners. They
//! exercise the crate's exported stdio transport rather than its private test
//! module so `--exact` discovers one and only one entry for each frozen ID.

use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};

#[cfg(unix)]
use std::process::{Command, Stdio};
#[cfg(unix)]
use std::time::Duration;

use asupersync::Cx;
use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest, JsonRpcResponse};
use fastmcp_transport::{StdioTransport, TransportError};

#[derive(Clone, Default)]
struct SharedWriter {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl SharedWriter {
    fn recorded(&self) -> Vec<u8> {
        self.bytes
            .lock()
            .expect("test writer mutex must not be poisoned")
            .clone()
    }
}

impl Write for SharedWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.bytes
            .lock()
            .expect("test writer mutex must not be poisoned")
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(unix)]
struct ChildGuard {
    child: Option<std::process::Child>,
}

#[cfg(unix)]
impl ChildGuard {
    fn new(child: std::process::Child) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> &mut std::process::Child {
        self.child.as_mut().expect("test child already reaped")
    }
}

#[cfg(unix)]
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn std_01_a_positive() {
    let input = b"{\"jsonrpc\":\"2.0\",\"result\":{\"ok\":true},\"id\":\"request-7\"}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":1}}\n{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":\"request-8\"}\n";
    assert_eq!(input.split(|byte| *byte == b'\n').count(), 4);
    assert!(input.ends_with(b"\n"));

    let writer = SharedWriter::default();
    let mut transport = StdioTransport::new(Cursor::new(input.to_vec()), writer.clone());
    let cx = Cx::for_testing();
    let mut requests = Vec::new();
    let mut responses = Vec::new();
    let mut on_request = |request: JsonRpcRequest| {
        requests.push((
            request.method,
            request
                .id
                .map(|id| serde_json::to_value(id).expect("request ID is serializable")),
        ));
    };
    let mut on_response = |response: JsonRpcResponse| {
        responses.push(serde_json::to_value(response.id).expect("response ID is serializable"));
    };

    for _ in 0..3 {
        transport
            .dispatch_next(&cx, &mut on_request, &mut on_response)
            .expect("each complete newline frame dispatches exactly once");
    }

    assert_eq!(
        responses,
        vec![serde_json::json!("request-7")],
        "the response remains correlated with its exact wire ID"
    );
    assert_eq!(
        requests,
        vec![
            ("notifications/progress".to_owned(), None),
            (
                "tools/list".to_owned(),
                Some(serde_json::json!("request-8"))
            ),
        ],
        "request and notification frames retain order while responses multiplex separately"
    );
    assert!(
        writer.recorded().is_empty(),
        "bidirectional dispatch never invents a reverse response"
    );
}

#[test]
fn std_01_a_planted_negative() {
    let valid = b"{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":\"request-8\"}\n";
    let forbidden = b"{\"jsonrpc\":\"2.0\",\"method\":\"tools\n/list\",\"id\":\"request-8\"}\n";
    let mut restored = forbidden.to_vec();
    let embedded_newline = restored
        .iter()
        .position(|byte| *byte == b'\n')
        .expect("the planted frame contains an embedded newline");
    restored.remove(embedded_newline);
    assert_eq!(
        restored, valid,
        "the planted negative differs only by one forbidden embedded newline byte"
    );

    let writer = SharedWriter::default();
    let mut transport = StdioTransport::new(Cursor::new(forbidden.to_vec()), writer.clone());
    let cx = Cx::for_testing();
    let mut request_count = 0;
    let mut response_count = 0;
    let error = transport
        .dispatch_next(&cx, &mut |_| request_count += 1, &mut |_| {
            response_count += 1
        })
        .expect_err("an embedded newline must reject before either direction dispatches");

    assert!(matches!(error, TransportError::Codec(_)));
    assert_eq!(
        request_count, 0,
        "rejected framing cannot dispatch a request"
    );
    assert_eq!(
        response_count, 0,
        "rejected framing cannot dispatch a response"
    );
    assert!(
        writer.recorded().is_empty(),
        "a rejected inbound frame never emits a reverse parse or invalid-request response"
    );
}

#[cfg(unix)]
#[test]
fn std_01_b_positive() {
    let mut child = ChildGuard::new(
        Command::new("sh")
            .args([
                "-c",
                "IFS= read -r line; test -n \"$line\"; cat >/dev/null; exit 0",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn stdio lifecycle child"),
    );
    let writer = child.child_mut().stdin.take().expect("child stdin");
    let reader = child.child_mut().stdout.take().expect("child stdout");
    let mut transport = StdioTransport::new(reader, writer);
    let control = JsonRpcMessage::Request(JsonRpcRequest::notification(
        "notifications/cancelled",
        Some(serde_json::json!({"requestId": "request-8"})),
    ));
    transport
        .try_send_control_message(&control)
        .expect("reserved control capacity commits one complete cancellation frame");

    let (status, forced) = transport
        .close_and_reap_child(
            &Cx::for_testing(),
            child.child_mut(),
            Duration::from_secs(2),
        )
        .expect("closing stdin lets the exact child exit and reap");

    assert!(
        status.success(),
        "the child observed the committed control frame"
    );
    assert!(!forced, "EOF-driven child exit must not require escalation");
    assert!(
        transport.is_closed(),
        "lifecycle close rejects later application writes"
    );
    assert!(
        child
            .child_mut()
            .try_wait()
            .expect("inspect reaped child")
            .is_some(),
        "a returned lifecycle outcome is reaped, not merely signalled"
    );
}

#[cfg(unix)]
#[test]
fn std_01_b_planted_negative() {
    let mut child = ChildGuard::new(
        Command::new("sh")
            .args([
                "-c",
                "IFS= read -r line; test -n \"$line\"; cat >/dev/null; exit 0",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn stdio lifecycle child"),
    );
    let writer = child.child_mut().stdin.take().expect("child stdin");
    let reader = child.child_mut().stdout.take().expect("child stdout");
    let mut transport = StdioTransport::new(reader, writer);
    let control = JsonRpcMessage::Request(JsonRpcRequest::notification(
        "notifications/cancelled",
        Some(serde_json::json!({"requestId": "request-8"})),
    ));
    transport
        .try_send_control_message(&control)
        .expect("the same reserved control frame commits before the plant");
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);

    let error = transport
        .close_and_reap_child(&cancelled, child.child_mut(), Duration::from_secs(2))
        .expect_err("one changed cancellation bit refuses before stdin close");

    assert!(matches!(error, TransportError::Cancelled));
    assert!(
        !transport.is_closed(),
        "pre-close cancellation leaves the transport write side unchanged"
    );
    assert!(
        child
            .child_mut()
            .try_wait()
            .expect("inspect live child")
            .is_none(),
        "pre-close cancellation cannot reap or terminate the unrelated child"
    );

    let (status, forced) = transport
        .close_and_reap_child(
            &Cx::for_testing(),
            child.child_mut(),
            Duration::from_secs(2),
        )
        .expect("fresh connection cleanup reaps the still-live child");
    assert!(status.success());
    assert!(!forced);
}
