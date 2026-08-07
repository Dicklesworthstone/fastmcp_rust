use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use asupersync::Cx;
use fastmcp_protocol::{JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId};
use fastmcp_transport::{
    Transport, TransportError,
    http::LegacySseHttpPostSink,
    sse::{LegacySseClientTransport, LegacySseServerTransport, SseEvent, SseEventType},
};

fn read_http_request(stream: TcpStream) -> String {
    let mut reader = BufReader::new(stream);
    let mut request = String::new();
    let mut content_length = 0;
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .expect("the loopback peer sends a complete HTTP header line");
        if line.is_empty() {
            panic!("the loopback peer closed before the HTTP header terminator");
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value
                .trim()
                .parse()
                .expect("the loopback POST content length is numeric");
        }
        request.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    let mut body = vec![0_u8; content_length];
    reader
        .read_exact(&mut body)
        .expect("the loopback peer sends the declared HTTP body");
    request.push_str(std::str::from_utf8(&body).expect("JSON-RPC body is UTF-8"));
    request
}

#[test]
fn leg_http_01_a_positive() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener binds");
    let authority = listener
        .local_addr()
        .expect("the listener exposes its loopback address")
        .to_string();
    let endpoint = format!("http://{authority}/legacy/messages");
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captured_server = Arc::clone(&captured);
    let endpoint_server = endpoint.clone();
    let server = thread::spawn(move || {
        let (mut sse_socket, _) = listener.accept().expect("the SSE GET connects");
        let get = read_http_request(sse_socket.try_clone().expect("the SSE socket clones"));
        let mut legacy_server = LegacySseServerTransport::new(
            sse_socket.try_clone().expect("the SSE socket clones"),
            std::iter::empty::<JsonRpcRequest>(),
            endpoint_server,
        );
        let server_cx = Cx::for_testing();
        legacy_server
            .open(&server_cx)
            .expect("the exact legacy adapter opens with its endpoint event");
        legacy_server
            .send(
                &server_cx,
                &JsonRpcMessage::Response(JsonRpcResponse::success(
                    RequestId::Number(2),
                    serde_json::json!({"from": "legacy-sse"}),
                )),
            )
            .expect("server JSON-RPC stays on the SSE stream");

        let (post_socket, _) = listener.accept().expect("the advertised POST connects");
        let post = read_http_request(post_socket);
        captured_server
            .lock()
            .expect("capture mutex remains available")
            .extend([get, post]);
    });

    let sse_socket = TcpStream::connect(&authority).expect("the configured SSE GET connects");
    sse_socket
        .write_all(b"GET /legacy/sse HTTP/1.1\r\nHost: loopback\r\n\r\n")
        .expect("the configured legacy SSE GET writes");
    sse_socket
        .flush()
        .expect("the configured legacy SSE GET flushes");
    sse_socket
        .shutdown(Shutdown::Write)
        .expect("the configured legacy SSE GET completes its request body");
    let mut client = LegacySseClientTransport::new(sse_socket, LegacySseHttpPostSink::new());
    let cx = Cx::for_testing();

    assert_eq!(
        client
            .establish(&cx)
            .expect("first SSE event establishes the endpoint"),
        endpoint
    );
    client
        .send(
            &cx,
            &JsonRpcMessage::Request(JsonRpcRequest::new("tools/list", None, 1_i64)),
        )
        .expect("client JSON-RPC travels only through the advertised POST");
    assert!(matches!(
        client.recv(&cx),
        Ok(JsonRpcMessage::Response(response)) if response.id == Some(RequestId::Number(2))
    ));
    server.join().expect("the loopback server completes");

    let captured = captured.lock().expect("capture mutex remains available");
    assert!(captured[0].starts_with("GET /legacy/sse HTTP/1.1\r\n"));
    assert!(captured[1].starts_with("POST /legacy/messages HTTP/1.1\r\n"));
    assert!(captured[1].contains("\"method\":\"tools/list\""));
}

#[test]
fn leg_http_01_a_planted_negative() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener binds");
    let authority = listener
        .local_addr()
        .expect("the listener exposes its loopback address")
        .to_string();
    let endpoint = format!("http://{authority}/legacy/messages");
    let (post_probe_sender, post_probe_receiver) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut sse_socket, _) = listener.accept().expect("the SSE GET connects");
        let _get = read_http_request(sse_socket.try_clone().expect("the SSE socket clones"));
        // Planted forbidden dimension: only the first event type changes from
        // endpoint to message; the advertised URI bytes remain identical.
        let wrong_first_event = SseEvent {
            event_type: SseEventType::Message,
            data: endpoint,
            id: None,
            retry: None,
        }
        .to_bytes()
        .expect("the planted event remains valid SSE framing");
        sse_socket
            .write_all(&wrong_first_event)
            .expect("the planted event writes");
        sse_socket.flush().expect("the planted event flushes");
        post_probe_receiver
            .recv()
            .expect("the client signals its denied POST attempt boundary");
        listener
            .set_nonblocking(true)
            .expect("the loopback listener becomes probeable");
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    });

    let sse_socket = TcpStream::connect(&authority).expect("the configured SSE GET connects");
    sse_socket
        .write_all(b"GET /legacy/sse HTTP/1.1\r\nHost: loopback\r\n\r\n")
        .expect("the configured legacy SSE GET writes");
    sse_socket
        .flush()
        .expect("the configured legacy SSE GET flushes");
    sse_socket
        .shutdown(Shutdown::Write)
        .expect("the configured legacy SSE GET completes its request body");
    let mut client = LegacySseClientTransport::new(sse_socket, LegacySseHttpPostSink::new());
    let cx = Cx::for_testing();

    assert!(matches!(
        client.establish(&cx),
        Err(TransportError::Io(ref error)) if error.kind() == std::io::ErrorKind::InvalidData
    ));
    assert!(client.advertised_endpoint().is_none());
    assert!(matches!(
        client.send(
            &cx,
            &JsonRpcMessage::Request(JsonRpcRequest::new("tools/list", None, 1_i64)),
        ),
        Err(TransportError::Closed)
    ));
    post_probe_sender
        .send(())
        .expect("the loopback server remains available for the no-POST probe");
    server.join().expect("the loopback server completes");
}
