//! Managed response-custody tests over the actual HTTP body/SSE pipeline.
//! As in the parent fixture, session state and access lifetime are injected;
//! these are not authentication, TLS or issuer-integration proofs.
use super::*;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use crate::http_auth::rpc::{ManagedCoreError, finish_finite_sse};

#[derive(Clone, Copy)]
enum Ending { Length, Chunked, ShortLength, MissingLastChunk }

async fn receive_request(socket: &mut TcpStream) {
    let mut wire = Vec::new();
    let mut chunk = [0; 1024];
    let end = loop {
        let count = socket.read(&mut chunk).await.unwrap();
        assert!(count > 0 && wire.len() + count <= 4096);
        wire.extend_from_slice(&chunk[..count]);
        if let Some(index) = wire.windows(4).position(|part| part == b"\r\n\r\n") { break index + 4; }
    };
    let head = std::str::from_utf8(&wire[..end]).unwrap();
    let length = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
    }).unwrap();
    assert_eq!(length, 2);
    while wire.len() < end + length {
        let count = socket.read(&mut chunk).await.unwrap();
        assert!(count > 0 && wire.len() + count <= 4096);
        wire.extend_from_slice(&chunk[..count]);
    }
    assert_eq!(&wire[end..], b"{}");
}

async fn peer(listener: &TcpListener, body: &str, ending: Ending) {
    let (mut socket, _) = listener.accept().await.unwrap();
    receive_request(&mut socket).await;
    let headers = match ending {
        Ending::Length | Ending::ShortLength => format!("Content-Length: {}\r\n",
            body.len() + usize::from(matches!(ending, Ending::ShortLength))),
        Ending::Chunked | Ending::MissingLastChunk => "Transfer-Encoding: chunked\r\n".to_owned(),
    };
    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n{headers}Connection: close\r\n\r\n").as_bytes()).await.unwrap();
    match ending {
        Ending::Length | Ending::ShortLength => socket.write_all(body.as_bytes()).await.unwrap(),
        Ending::Chunked | Ending::MissingLastChunk => {
            // HTTP framing splits both CRLF and UTF-8 sequences deliberately.
            for bytes in body.as_bytes().chunks(1) {
                socket.write_all(b"1\r\n").await.unwrap();
                socket.write_all(bytes).await.unwrap();
                socket.write_all(b"\r\n").await.unwrap();
            }
            if matches!(ending, Ending::Chunked) { socket.write_all(b"0\r\n\r\n").await.unwrap(); }
        }
    }
    socket.shutdown().await.unwrap();
}

fn limits() -> SseLimits { SseLimits::new(4096, 65536, 64).unwrap() }

fn incomplete(error: &OAuthSessionError) {
    assert!(matches!(error, OAuthSessionError::IncompleteSseResponse));
    assert!(!format!("{error:?} {error}").contains("private-unfinished"));
}

#[test]
fn managed_sse_clean_eof_accepts_line_endings_and_complete_comment_tails() {
    for newline in ["\n", "\r\n", "\r"] {
        for ending in [Ending::Length, Ending::Chunked] {
            run(async {
                let cx = Cx::current().unwrap();
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let session = response_custody_session();
                let cancel = McpRequestCancellation::new();
                let body = format!("data: héllo{newline}{newline}: final comment{newline}{newline}");
                let client = async {
                    let response = open_response(&cx, &listener, &session, &cancel, Duration::from_secs(30)).await;
                    let mut stream = response.into_sse_stream(limits()).unwrap();
                    assert_eq!(stream.next_event(&cx).await.unwrap().as_deref(), Some("héllo"));
                    assert!(stream.next_event(&cx).await.unwrap().is_none());
                    assert!(stream.next_event(&cx).await.unwrap().is_none());
                    assert!(stream.finished);
                    assert!(stream.stream.is_none());
                };
                pair(peer(&listener, &body, ending), client).await;
            });
        }
    }
}

#[test]
fn managed_sse_rejects_partial_lines_and_pending_events_after_delivered_data() {
    for tail in ["data: private-unfinished", "data: private-unfinished\n", ": private-unfinished", "data: \n"] {
        for ending in [Ending::Length, Ending::Chunked] {
            run(async {
                let cx = Cx::current().unwrap();
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let session = response_custody_session();
                let cancel = McpRequestCancellation::new();
                let body = format!("data: first\n\n{tail}");
                let client = async {
                    let response = open_response(&cx, &listener, &session, &cancel, Duration::from_secs(30)).await;
                    let mut stream = response.into_sse_stream(limits()).unwrap();
                    assert_eq!(stream.next_event(&cx).await.unwrap().as_deref(), Some("first"));
                    incomplete(&stream.next_event(&cx).await.unwrap_err());
                    assert!(!stream.finished, "malformed EOF is never successful completion");
                    assert!(stream.stream.is_none());
                    assert!(matches!(stream.next_event(&cx).await, Err(OAuthSessionError::Http(ModernHttpExecutorError::SseStreamClosed))));
                    assert!(session.check(&cx, &cancel).is_ok(), "only this response is retired");
                };
                pair(peer(&listener, &body, ending), client).await;
            });
        }
    }
}

#[test]
fn managed_sse_never_synthesizes_an_event_or_clean_eof_from_unterminated_data() {
    for body in ["data: private-unfinished", "data: private-unfinished\n"] {
        run(async {
            let cx = Cx::current().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let session = response_custody_session();
            let cancel = McpRequestCancellation::new();
            let client = async {
                let response = open_response(&cx, &listener, &session, &cancel, Duration::from_secs(30)).await;
                let mut stream = response.into_sse_stream(limits()).unwrap();
                incomplete(&stream.next_event(&cx).await.unwrap_err());
                assert!(!stream.finished);
            };
            pair(peer(&listener, body, Ending::Length), client).await;
        });
    }
}

#[test]
fn managed_sse_empty_or_comment_only_complete_bodies_remain_clean() {
    for body in ["", "\n\n", ": complete\n", ": complete\r\n\r\n"] {
        run(async {
            let cx = Cx::current().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let session = response_custody_session();
            let cancel = McpRequestCancellation::new();
            let client = async {
                let response = open_response(&cx, &listener, &session, &cancel, Duration::from_secs(30)).await;
                let mut stream = response.into_sse_stream(limits()).unwrap();
                assert!(stream.next_event(&cx).await.unwrap().is_none());
                assert!(stream.finished);
            };
            pair(peer(&listener, body, Ending::Length), client).await;
        });
    }
}

#[test]
fn managed_finite_completion_withholds_candidate_when_native_eof_discarded_data() {
    // This is the production finite-response helper used by core calls, with
    // a real managed stream rather than a future returning a fabricated None.
    for tail in ["", ": complete\n", "data: private-unfinished", "data: private-unfinished\n"] {
        run(async {
            let cx = Cx::current().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let session = response_custody_session();
            let cancel = McpRequestCancellation::new();
            let body = format!("data: candidate-result\n\n{tail}");
            let client = async {
                let response = open_response(&cx, &listener, &session, &cancel, Duration::from_secs(30)).await;
                let mut stream = response.into_sse_stream(limits()).unwrap();
                let candidate = stream.next_event(&cx).await.unwrap().unwrap();
                let outcome = finish_finite_sse(&cx, &cancel, cx.now().saturating_add_nanos(1_000_000_000), async {
                    stream.next_event(&cx).await.map_err(ManagedCoreError::from)
                }).await.map(|()| candidate);
                if tail.starts_with("data:") {
                    assert!(matches!(outcome, Err(ManagedCoreError::Session(OAuthSessionError::IncompleteSseResponse))));
                } else { assert_eq!(outcome.unwrap(), "candidate-result"); }
            };
            pair(peer(&listener, &body, Ending::Chunked), client).await;
        });
    }
}

#[test]
fn managed_sse_cannot_confuse_truncated_http_with_clean_sse_completion() {
    for ending in [Ending::ShortLength, Ending::MissingLastChunk] {
        run(async {
            let cx = Cx::current().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let session = response_custody_session();
            let cancel = McpRequestCancellation::new();
            let client = async {
                let response = open_response(&cx, &listener, &session, &cancel, Duration::from_secs(30)).await;
                let mut stream = response.into_sse_stream(limits()).unwrap();
                // A transport can detect truncation before or after making
                // its first complete data record available. Neither ordering
                // may expose successful EOF to the finite-response consumer.
                match stream.next_event(&cx).await {
                    Ok(Some(event)) => {
                        assert_eq!(event, "first");
                        assert!(stream.next_event(&cx).await.is_err());
                    }
                    Err(_) => {},
                    Ok(None) => panic!("truncated HTTP cannot become clean EOF"),
                }
                assert!(!stream.finished);
                assert!(stream.stream.is_none());
            };
            pair(peer(&listener, "data: first\n\n", ending), client).await;
        });
    }
}
