//! Native managed Tasks tests: real OAuth callback/exchange, TLS and MCP POSTs.
//! The certificates below are the existing managed-client TEST ONLY CA/key.

use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::future::{Future, poll_fn};
use std::task::Poll;
use std::time::{Duration, Instant};

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder};
use fastmcp_core::{CanonicalHttpUrl, McpErrorCode};
use fastmcp_protocol::{FINAL_PROTOCOL_VERSION, TASKS_EXTENSION};
use serde_json::json;

use crate::http_auth::managed::{ManagedOAuthSession, OAuthSessionError, OAuthSessionPolicy};
use crate::http_auth::oauth::{OAuthClient, OAuthClientConfiguration, OAuthError};
use crate::{ClientBuilder, ClientProtocolPlan, ProtocolPolicy};

const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6iNs7lbtVY9mysZBIqm6pKQO2o0UwQzAS\nBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQU6QNI\nrmvMiLoV3jIoCyohXARwI8gwCgYIKoZIzj0EAwIDSAAwRQIgCKOrW3vhzUJ2EyuY\nvQUTdqGFhy0zEHj4ITFLvXPz1X8CIQCLKD4EKCvS/zkBSu/6uee1WV9d97UpK3yW\nX/aCEJ5+hA==\n-----END CERTIFICATE-----\n";
const LEAF: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBjjCCATSgAwIBAgICA+owCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPPKylLna9VpWAlpshHBhSsQHNOv3BaEGX4HSBhHiBVel0ce+qfHF15O\n0T63Zlp7TtxlMdEY+rPpgioSFDQVadijYzBhMAwGA1UdEwEB/wQCMAAwLAYDVR0R\nBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMBMGA1UdJQQM\nMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNIADBFAiEA\n6qrAr2qp/t6K62T9Et2mUU/zfd4kJb+ekyoAim1yTFcCICb6SdVY2fg15/SXf0vE\nIvYelqtTk8FQInCEcIxvfF3m\n-----END CERTIFICATE-----\n";
const KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcCe44IBKhbw+D/s7\nBjDHOOV0g+EoxFno7VJGKhJeer2hRANCAATzyspS52vVaVgJabIRwYUrEBzTr9wW\nhBl+B0gYR4gVXpdHHvqnxxdeTtE+t2Zae07cZTHRGPqz6YIqEhQ0FWnY\n-----END PRIVATE KEY-----\n";
type Tls = asupersync::tls::TlsStream<TcpStream>;

fn url(value: &str) -> CanonicalHttpUrl {
    CanonicalHttpUrl::parse(value).unwrap()
}
fn root() -> Certificate {
    Certificate::from_pem(ROOT).unwrap().remove(0)
}
fn id() -> FinalTaskId {
    FinalTaskId::parse("task-1").unwrap()
}

fn run(future: impl Future<Output = ()>) {
    RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .blocking_threads(0, 8)
        .build()
        .unwrap()
        .block_on(async {
            let cx = Cx::current().unwrap();
            asupersync::time::timeout_at(cx.now().saturating_add_nanos(120_000_000_000), future)
                .await
                .expect("managed Tasks fixture must settle");
        });
}

async fn pair<L: Future, R: Future>(left: L, right: R) -> (L::Output, R::Output) {
    let mut left = std::pin::pin!(left);
    let mut right = std::pin::pin!(right);
    let mut l = None;
    let mut r = None;
    poll_fn(|cx| {
        if l.is_none() {
            if let Poll::Ready(value) = left.as_mut().poll(cx) {
                l = Some(value);
            }
        }
        if r.is_none() {
            if let Poll::Ready(value) = right.as_mut().poll(cx) {
                r = Some(value);
            }
        }
        if l.is_some() && r.is_some() {
            Poll::Ready((l.take().unwrap(), r.take().unwrap()))
        } else {
            Poll::Pending
        }
    })
    .await
}

fn encode(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(b).to_string()
            }
            b => format!("%{b:02X}"),
        })
        .collect()
}

fn decode(text: &str) -> String {
    let mut output = Vec::new();
    let mut bytes = text.bytes();
    while let Some(b) = bytes.next() {
        output.push(match b {
            b'+' => b' ',
            b'%' => {
                let a = char::from(bytes.next().unwrap()).to_digit(16).unwrap();
                let b = char::from(bytes.next().unwrap()).to_digit(16).unwrap();
                u8::try_from(a * 16 + b).unwrap()
            }
            b => b,
        });
    }
    String::from_utf8(output).unwrap()
}

fn form(text: &str) -> BTreeMap<String, String> {
    text.split('&')
        .map(|field| {
            let (key, value) = field.split_once('=').unwrap();
            (decode(key), decode(value))
        })
        .collect()
}

async fn callback(authorization: CanonicalHttpUrl, issuer: String) -> Result<(), OAuthError> {
    let fields = form(authorization.query().unwrap());
    assert_eq!(fields["code_challenge_method"], "S256");
    let redirect = url(&fields["redirect_uri"]);
    let authority = redirect
        .as_str()
        .strip_prefix("http://")
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .to_owned();
    let mut stream = TcpStream::connect(authority.clone())
        .await
        .map_err(|_| OAuthError::TransportFailed)?;
    stream.write_all(format!(
        "GET /oauth/callback?code=fixture-code&state={}&iss={} HTTP/1.1\r\nHost: {authority}\r\n\r\n",
        encode(&fields["state"]), encode(&issuer),
    ).as_bytes()).await.map_err(|_| OAuthError::TransportFailed)
}

struct Peer {
    listener: TcpListener,
    tls: TlsAcceptor,
}
impl Peer {
    async fn new() -> Self {
        Self {
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            tls: TlsAcceptorBuilder::new(
                CertificateChain::from_pem(LEAF).unwrap(),
                PrivateKey::from_pem(KEY).unwrap(),
            )
            .alpn_protocols(vec![b"http/1.1".to_vec()])
            .build()
            .unwrap(),
        }
    }
    fn origin(&self) -> String {
        format!("https://{}", self.listener.local_addr().unwrap())
    }
    fn resource(&self) -> CanonicalHttpUrl {
        url(&format!("{}/mcp", self.origin()))
    }
    fn client(&self, session: ManagedOAuthSession) -> ManagedHttpClient {
        let builder = ClientBuilder::new()
            .protocol_plan(
                ClientProtocolPlan::http(
                    ProtocolPolicy::ModernOnly,
                    Some(self.resource()),
                    None,
                    None,
                    "managed-task-owner".into(),
                    "managed-task-trust".into(),
                    "native-http".into(),
                    0,
                    0,
                    0,
                )
                .unwrap(),
            )
            .http_resource_root_certificate(self.resource(), root())
            .unwrap();
        ManagedHttpClient::new(session, builder, Duration::from_secs(30)).unwrap()
    }
    async fn next(&self) -> (Tls, String, BTreeMap<String, String>, Vec<u8>) {
        let (tcp, _) = self.listener.accept().await.unwrap();
        let mut stream = self.tls.accept(tcp).await.unwrap();
        let mut wire = Vec::new();
        let mut buffer = [0_u8; 2048];
        let end = loop {
            let n = stream.read(&mut buffer).await.unwrap();
            assert!(n > 0 && wire.len() + n <= 128 * 1024);
            wire.extend_from_slice(&buffer[..n]);
            if let Some(at) = wire.windows(4).position(|part| part == b"\r\n\r\n") {
                break at + 4;
            }
        };
        let head = std::str::from_utf8(&wire[..end]).unwrap();
        let mut lines = head.split("\r\n");
        let first: Vec<_> = lines.next().unwrap().split(' ').collect();
        assert_eq!(first[0], "POST");
        let target = first[1].to_owned();
        let headers: BTreeMap<_, _> = lines
            .filter(|line| !line.is_empty())
            .map(|line| {
                let (key, value) = line.split_once(':').unwrap();
                (key.to_ascii_lowercase(), value.trim().to_owned())
            })
            .collect();
        let length: usize = headers["content-length"].parse().unwrap();
        assert!(end + length <= 128 * 1024);
        while wire.len() < end + length {
            let n = stream.read(&mut buffer).await.unwrap();
            assert!(n > 0 && wire.len() + n <= 128 * 1024);
            wire.extend_from_slice(&buffer[..n]);
        }
        assert_eq!(wire.len(), end + length);
        (stream, target, headers, wire[end..].to_vec())
    }
    async fn token(&self, second: bool) {
        let (mut stream, target, headers, bytes) = self.next().await;
        assert_eq!(target, "/token");
        assert!(!headers.contains_key("authorization"));
        let fields = form(std::str::from_utf8(&bytes).unwrap());
        assert_eq!(fields["resource"], self.resource().as_str());
        assert_eq!(
            fields["grant_type"],
            if second {
                "refresh_token"
            } else {
                "authorization_code"
            }
        );
        if second {
            assert_eq!(fields["refresh_token"], "refresh-one");
        }
        reply(&mut stream, json!({
            "access_token":if second {"access-two"} else {"access-one"}, "token_type":"Bearer", "expires_in":3600,
            "refresh_token":if second {"refresh-two"} else {"refresh-one"}, "scope":"read write"
        }), false).await;
    }
    async fn login(&self, cx: &Cx) -> ManagedOAuthSession {
        let oauth = OAuthClient::new(
            OAuthClientConfiguration::from_trusted_endpoints(
                self.origin(),
                url(&format!("{}/authorize", self.origin())),
                url(&format!("{}/token", self.origin())),
                self.resource(),
                "native-client",
                vec!["read".into(), "write".into()],
            )
            .unwrap()
            .with_extra_root_certificate(root())
            .unwrap()
            .with_authorization_timeout(Duration::from_secs(90))
            .unwrap(),
        );
        let (session, ()) = Box::pin(pair(
            ManagedOAuthSession::authorize(
                cx,
                oauth,
                OAuthSessionPolicy::default(),
                |authorization| callback(authorization, self.origin()),
            ),
            self.token(false),
        ))
        .await;
        session.unwrap()
    }
    async fn request(&self, method: &str, token: &str) -> (Tls, Value) {
        let (stream, target, headers, bytes) = self.next().await;
        assert_eq!(target, "/mcp");
        assert_eq!(headers["authorization"], format!("Bearer {token}"));
        assert!(!headers.contains_key("cookie"));
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["method"], method);
        assert_eq!(
            body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            FINAL_PROTOCOL_VERSION
        );
        if method != "server/discover" {
            assert_eq!(
                body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["extensions"]
                    [TASKS_EXTENSION],
                json!({})
            );
        }
        (stream, body)
    }
    async fn rpc(&self, method: &str, token: &str, result: Value, sse: bool) -> Value {
        let (mut stream, body) = self.request(method, token).await;
        reply(
            &mut stream,
            json!({"jsonrpc":"2.0","id":body["id"],"result":result}),
            sse,
        )
        .await;
        body
    }
    async fn discovery(&self, token: &str, enabled: bool) {
        self.rpc("server/discover", token, discovery_result(enabled), false)
            .await;
    }
    async fn no_more(&self, cx: &Cx) {
        assert!(
            asupersync::time::timeout_at(
                cx.now().saturating_add_nanos(100_000_000),
                self.listener.accept()
            )
            .await
            .is_err(),
            "unexpected refresh, discovery, task request or replay"
        );
    }
}

fn discovery_result(enabled: bool) -> Value {
    let mut capabilities = json!({"tools":{}});
    if enabled {
        capabilities["extensions"] = json!({TASKS_EXTENSION:{}});
    }
    json!({
        "resultType":"complete", "supportedVersions":[FINAL_PROTOCOL_VERSION], "capabilities":capabilities,
        "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"managed-tasks-peer","version":"1"}},
        "ttlMs":0, "cacheScope":"private"
    })
}

async fn reply(stream: &mut Tls, value: Value, sse: bool) {
    let text = serde_json::to_string(&value).unwrap();
    let body = if sse {
        format!("event: message\ndata: {text}\n\n")
    } else {
        text
    };
    let content_type = if sse {
        "text/event-stream"
    } else {
        "application/json"
    };
    stream.write_all(format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len(),
    ).as_bytes()).await.unwrap();
    stream.write_all(body.as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
}

fn task(status: &str, envelope: &str) -> Value {
    let mut value = json!({
        "resultType":envelope, "taskId":"task-1", "status":status,
        "createdAt":"2026-07-28T12:00:00.000Z", "lastUpdatedAt":"2026-07-28T12:00:00.000Z",
        "ttlMs":null, "pollIntervalMs":10
    });
    if status == "input_required" {
        value["inputRequests"] = json!({"roots":{"method":"roots/list"}});
    }
    if status == "completed" {
        value["result"] = json!({"content":[{"type":"text","text":"done"}],"isError":false});
    }
    value
}

fn finite_task(status: &str, envelope: &str, lifetime: Duration) -> Value {
    let mut value = task(status, envelope);
    // An epoch creation instant makes the finite expiry independent of a
    // hard-coded civil date while preserving the exact wire duration.
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .checked_add(lifetime)
        .unwrap();
    value["createdAt"] = json!("1970-01-01T00:00:00Z");
    value["ttlMs"] = json!(u64::try_from(expires.as_millis()).unwrap());
    value
}

fn task_snapshot(value: Value) -> FinalTask {
    serde_json::from_str::<FinalGetTaskResult>(&value.to_string())
        .unwrap()
        .task
}

fn responses(value: Value) -> FinalTaskInputResponses {
    serde_json::from_value(value).unwrap()
}
fn input_task() -> FinalTask {
    let value: FinalGetTaskResult =
        serde_json::from_str(&task("input_required", "complete").to_string()).unwrap();
    value.task
}
fn renew(session: &ManagedOAuthSession) {
    let mut state = session.inner.state.try_lock_owned().unwrap();
    state.as_mut().unwrap().renew_after = Instant::now();
}

#[test]
fn managed_tasks_create_get_update_cancel_keep_wire_identity_and_credentials() {
    for sse in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session.clone()).with_tasks();
            let (created, ()) = pair(
                client.call_tool_final_outcome(&cx, "build", json!({"input":7})),
                async {
                    peer.discovery("access-one", true).await;
                    let request = peer
                        .rpc("tools/call", "access-one", task("working", "task"), sse)
                        .await;
                    assert_eq!(request["params"]["name"], "build");
                    assert_eq!(request["params"]["arguments"], json!({"input":7}));
                },
            )
            .await;
            let FinalToolCallOutcome::Task(created) = created.unwrap() else {
                panic!("created task was flattened");
            };
            assert_eq!(created.task.base().task_id, id());
            let (fetched, first) = pair(
                client.get_task_final(&cx, id()),
                peer.rpc(
                    "tasks/get",
                    "access-one",
                    task("input_required", "complete"),
                    false,
                ),
            )
            .await;
            let snapshot = fetched.unwrap().task;
            let before = serde_json::to_string(&snapshot).unwrap();
            assert!(matches!(
                client
                    .update_task_final(
                        &cx,
                        &snapshot,
                        responses(json!({"roots":{"action":"accept"}}))
                    )
                    .await,
                Err(ManagedHttpClientError::Request {
                    code: Some(McpErrorCode::InvalidParams)
                })
            ));
            assert_eq!(serde_json::to_string(&snapshot).unwrap(), before);
            assert_eq!(client.cached_credential_generation(), Some(1));
            peer.no_more(&cx).await;
            let (updated, second) = pair(
                client.update_task_final(&cx, &snapshot, responses(json!({"roots":{"roots":[]}}))),
                peer.rpc(
                    "tasks/update",
                    "access-one",
                    json!({"resultType":"complete"}),
                    false,
                ),
            )
            .await;
            assert_eq!(
                serde_json::to_value(updated.unwrap()).unwrap(),
                json!({"resultType":"complete"})
            );
            assert_eq!(second["params"]["taskId"], "task-1");
            assert_eq!(
                second["params"]["inputResponses"],
                json!({"roots":{"roots":[]}})
            );
            let (cancelled, third) = pair(
                client.cancel_task_final(&cx, id()),
                peer.rpc(
                    "tasks/cancel",
                    "access-one",
                    json!({"resultType":"complete"}),
                    false,
                ),
            )
            .await;
            assert_eq!(
                serde_json::to_value(cancelled.unwrap()).unwrap(),
                json!({"resultType":"complete"})
            );
            let (last, fourth) = pair(
                client.get_task_final(&cx, id()),
                peer.rpc(
                    "tasks/get",
                    "access-one",
                    task("cancelled", "complete"),
                    false,
                ),
            )
            .await;
            assert!(matches!(last.unwrap().task, FinalTask::Cancelled(_)));
            let ids: BTreeSet<_> = [first, second, third, fourth]
                .into_iter()
                .map(|r| r["id"].to_string())
                .collect();
            assert_eq!(ids.len(), 4);
            assert_eq!(client.cached_credential_generation(), Some(1));
            assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn managed_tasks_require_local_enablement_and_peer_advertisement() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session);
        assert!(matches!(
            client.get_task_final(&cx, id()).await,
            Err(ManagedHttpClientError::InvalidPolicy)
        ));
        assert!(matches!(
            client.cancel_task_final(&cx, id()).await,
            Err(ManagedHttpClientError::InvalidPolicy)
        ));
        assert!(matches!(
            client
                .call_tool_final_outcome(&cx, "build", json!({}))
                .await,
            Err(ManagedHttpClientError::InvalidPolicy)
        ));
        peer.no_more(&cx).await;
        let mut client = client.with_tasks();
        let (result, ()) = pair(
            client.get_task_final(&cx, id()),
            peer.discovery("access-one", false),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(client.cached_credential_generation(), None);
        peer.no_more(&cx).await;
        // Change only the peer extension advertisement; the operation is usable.
        let (result, ()) = pair(client.get_task_final(&cx, id()), async {
            peer.discovery("access-one", true).await;
            peer.rpc(
                "tasks/get",
                "access-one",
                task("working", "complete"),
                false,
            )
            .await;
        })
        .await;
        assert!(matches!(result.unwrap().task, FinalTask::Working(_)));
    });
}

#[test]
fn managed_tasks_preserve_complete_and_input_required_tool_outcomes_without_retries() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session).with_tasks();
        let (result, ()) = pair(
            client.call_tool_final_outcome(&cx, "build", json!({})),
            async {
                peer.discovery("access-one", true).await;
                peer.rpc(
                    "tools/call",
                    "access-one",
                    json!({"resultType":"complete","content":[],"isError":true}),
                    false,
                )
                .await;
            },
        )
        .await;
        let FinalToolCallOutcome::Complete(result) = result.unwrap() else {
            panic!("complete branch lost");
        };
        assert!(result.payload.is_error);
        let wire = json!({"resultType":"input_required","requestState":"bound-state","inputRequests":{"roots":{"method":"roots/list"}}});
        let (result, _) = pair(
            client.call_tool_final_outcome(&cx, "build", json!({})),
            peer.rpc("tools/call", "access-one", wire.clone(), true),
        )
        .await;
        let FinalToolCallOutcome::InputRequired(result) = result.unwrap() else {
            panic!("input-required branch lost");
        };
        // Results are encoded by the result algebra, not serde.
        let encoded = fastmcp_protocol::encode_result(
            &fastmcp_protocol::DecodedResult::InputRequired(result),
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&encoded).unwrap(),
            wire
        );
        peer.no_more(&cx).await;
    });
}

#[test]
fn managed_tasks_reject_wrong_task_identity_without_restoring_the_connection() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session).with_tasks();
        let mut wrong = task("working", "complete");
        wrong["taskId"] = json!("another-task");
        let (result, ()) = pair(client.get_task_final(&cx, id()), async {
            peer.discovery("access-one", true).await;
            peer.rpc("tasks/get", "access-one", wrong, false).await;
        })
        .await;
        assert!(result.is_err());
        assert_eq!(client.cached_credential_generation(), None);
        peer.no_more(&cx).await;
    });
}

#[test]
fn managed_tasks_cancellation_during_silent_response_retires_only_that_operation() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session.clone()).with_tasks();
        let cancellation = McpRequestCancellation::new();
        let (result, ()) = pair(
            client.get_task_final_with_cancellation(&cx, &cancellation, id()),
            async {
                peer.discovery("access-one", true).await;
                let (stream, _) = peer.request("tasks/get", "access-one").await;
                cancellation.cancel();
                drop(stream);
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(ManagedHttpClientError::Session(
                OAuthSessionError::Cancelled
            ))
        ));
        assert_eq!(client.cached_credential_generation(), None);
        assert!(!cx.is_cancel_requested());
        assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
        peer.no_more(&cx).await;
        let (result, ()) = pair(client.get_task_final(&cx, id()), async {
            peer.discovery("access-one", true).await;
            peer.rpc(
                "tasks/get",
                "access-one",
                task("working", "complete"),
                false,
            )
            .await;
        })
        .await;
        assert!(result.is_ok());
    });
}

#[test]
fn managed_tasks_renew_credentials_before_contact_and_never_contact_after_close() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session.clone()).with_tasks();
        let (first, ()) = pair(client.get_task_final(&cx, id()), async {
            peer.discovery("access-one", true).await;
            peer.rpc(
                "tasks/get",
                "access-one",
                task("working", "complete"),
                false,
            )
            .await;
        })
        .await;
        first.unwrap();
        renew(&session);
        let (second, ()) = pair(client.get_task_final(&cx, id()), async {
            peer.token(true).await;
            peer.discovery("access-two", true).await;
            peer.rpc(
                "tasks/get",
                "access-two",
                task("completed", "complete"),
                false,
            )
            .await;
        })
        .await;
        assert!(matches!(second.unwrap().task, FinalTask::Completed { .. }));
        assert_eq!(client.cached_credential_generation(), Some(2));
        session.close();
        assert!(matches!(
            client.cancel_task_final(&cx, id()).await,
            Err(ManagedHttpClientError::Session(OAuthSessionError::Closed))
        ));
        peer.no_more(&cx).await;
    });
}

#[test]
fn managed_task_input_admission_preserves_partial_and_unknown_key_semantics() {
    let snapshot = input_task();
    let before = serde_json::to_string(&snapshot).unwrap();
    assert!(admit_input(&snapshot, &responses(json!({}))).is_ok());
    assert!(
        admit_input(
            &snapshot,
            &responses(json!({"roots":{"roots":[]},"already-satisfied":{"action":"accept"}}))
        )
        .is_ok()
    );
    assert!(
        admit_input(
            &snapshot,
            &responses(json!({"roots":{"action":"accept"},"already-satisfied":{"roots":[]}}))
        )
        .is_err()
    );
    assert_eq!(serde_json::to_string(&snapshot).unwrap(), before);
    let working: FinalGetTaskResult =
        serde_json::from_str(&task("working", "complete").to_string()).unwrap();
    assert!(admit_input(&working.task, &responses(json!({}))).is_err());
}

#[test]
fn managed_task_expired_input_refuses_before_refresh_and_live_partial_updates_succeed() {
    for finite in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let session = peer.login(&cx).await;
            let mut client = peer.client(session.clone()).with_tasks();
            let (primed, ()) = pair(client.get_task_final(&cx, id()), async {
                peer.discovery("access-one", true).await;
                peer.rpc(
                    "tasks/get",
                    "access-one",
                    task("working", "complete"),
                    false,
                )
                .await;
            })
            .await;
            primed.unwrap();
            renew(&session);

            let mut expired = task("input_required", "complete");
            expired["createdAt"] = json!("1970-01-01T00:00:00Z");
            expired["ttlMs"] = json!(1);
            let expired = task_snapshot(expired);
            let before = serde_json::to_vec(&expired).unwrap();
            assert!(matches!(
                client
                    .update_task_final(&cx, &expired, responses(json!({"roots":{"roots":[]}})))
                    .await,
                Err(ManagedHttpClientError::Request {
                    code: Some(McpErrorCode::InvalidRequest)
                })
            ));
            assert_eq!(serde_json::to_vec(&expired).unwrap(), before);
            assert_eq!(client.cached_credential_generation(), Some(1));
            peer.no_more(&cx).await;

            let mut live = if finite {
                finite_task("input_required", "complete", Duration::from_secs(60))
            } else {
                task("input_required", "complete")
            };
            live["inputRequests"]["later"] = json!({"method":"roots/list"});
            let live = task_snapshot(live);
            let before = serde_json::to_vec(&live).unwrap();
            let (updated, request) = pair(
                client.update_task_final(&cx, &live, responses(json!({"roots":{"roots":[]}}))),
                async {
                    // Expired input did not consume the pending renewal or any
                    // connection/request custody. The live call owns it now.
                    peer.token(true).await;
                    peer.discovery("access-two", true).await;
                    peer.rpc(
                        "tasks/update",
                        "access-two",
                        json!({"resultType":"complete"}),
                        false,
                    )
                    .await
                },
            )
            .await;
            updated.unwrap();
            assert_eq!(request["id"], 2);
            assert_eq!(
                request["params"]["inputResponses"],
                json!({"roots":{"roots":[]}})
            );
            assert_eq!(serde_json::to_vec(&live).unwrap(), before);
            assert_eq!(client.cached_credential_generation(), Some(2));
            assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
            peer.no_more(&cx).await;
        });
    }
}

#[test]
fn managed_task_input_expiring_during_discovery_never_reaches_update_dispatch() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let session = peer.login(&cx).await;
        let mut client = peer.client(session.clone()).with_tasks();
        let snapshot = task_snapshot(finite_task(
            "input_required",
            "complete",
            Duration::from_secs(2),
        ));
        let before = serde_json::to_vec(&snapshot).unwrap();
        let (result, ()) = pair(
            client.update_task_final(&cx, &snapshot, responses(json!({"roots":{"roots":[]}}))),
            async {
                let (mut stream, request) = peer.request("server/discover", "access-one").await;
                // The snapshot was live at API entry. Let its actual retention
                // expire while discovery, under the original OAuth guard, waits.
                while crate::task_wait::admit_input_retention(&snapshot).is_ok() {
                    asupersync::time::sleep(cx.now(), Duration::from_millis(25)).await;
                }
                reply(
                    &mut stream,
                    json!({
                        "jsonrpc":"2.0", "id":request["id"], "result":discovery_result(true)
                    }),
                    false,
                )
                .await;
                peer.no_more(&cx).await;
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(ManagedHttpClientError::Request {
                code: Some(McpErrorCode::InvalidRequest)
            })
        ));
        assert_eq!(serde_json::to_vec(&snapshot).unwrap(), before);
        assert_eq!(client.cached_credential_generation(), None);
        assert!(session.check(&cx, &McpRequestCancellation::new()).is_ok());
        assert!(!cx.is_cancel_requested());
        let (next, ()) = pair(client.get_task_final(&cx, id()), async {
            peer.discovery("access-one", true).await;
            peer.rpc(
                "tasks/get",
                "access-one",
                task("working", "complete"),
                false,
            )
            .await;
        })
        .await;
        assert!(next.is_ok());
        peer.no_more(&cx).await;
    });
}

mod listen;
mod wait;
