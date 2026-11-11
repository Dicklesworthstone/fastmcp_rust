//! Real TLS code exchange, callback and protected MCP request with the parent
//! fixture's real file/coordinator/lane. Protection and anchor providers remain
//! explicitly in-memory test doubles, not deployment or crash-recovery proof.

use super::*;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::task::{Context, Waker};

use asupersync::cx::cap::{CapMask, CapSet, CapSetRuntimeMask};
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::tls::TlsStream;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{ClientCapabilities, CoreRequest, FinalRequestMeta, RequestId};
use serde_json::{Value, json};

use crate::http_auth::managed::{ManagedOAuthSession, OAuthSessionPolicy};
use crate::http_auth::oauth::persistence::asynchronous::authorization::{
    OAuthAuthorization, OAuthAuthorizationCustody, OAuthAuthorizationError, OAuthAuthorizationStage,
};
use crate::http_auth::oauth::{
    OAuthError, decode_form, encode_form, pkce_challenge, tests as native,
};
use crate::http_auth::rpc::{ManagedCoreEvent, ManagedCoreLimits};

const INITIAL: &str = r#"{"access_token":"initial-access","token_type":"Bearer","expires_in":300,"refresh_token":"initial-refresh"}"#;
const RENEWED: &str = r#"{"access_token":"renewed-access","token_type":"Bearer","expires_in":300,"refresh_token":"renewed-refresh"}"#;

fn url(value: &str) -> CanonicalHttpUrl {
    CanonicalHttpUrl::parse(value).unwrap()
}

struct Peer {
    listener: TcpListener,
    client: OAuthClient,
}

impl Peer {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let configuration = OAuthClientConfiguration::from_trusted_endpoints(
            "https://issuer.example",
            url("https://issuer.example/authorize"),
            url(&format!("https://{address}/token")),
            url(&format!("https://{address}/mcp")),
            "native-client",
            vec!["tools:read".to_owned()],
        )
        .unwrap()
        .with_extra_root_certificate(native::test_root())
        .unwrap()
        .with_resource_root_certificate(native::test_root())
        .unwrap();
        Self {
            listener,
            client: OAuthClient::new(configuration),
        }
    }

    async fn token_request(
        &self,
        expected_launch: Option<&Mutex<Option<BTreeMap<String, String>>>>,
    ) -> TlsStream<TcpStream> {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut socket = native::test_acceptor().accept(socket).await.unwrap();
        let (head, fields) = native::read_token_request(&mut socket).await.unwrap();
        assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
        assert!(!head.to_ascii_lowercase().contains("authorization:"));
        assert_eq!(fields["client_id"], "native-client");
        assert_eq!(
            fields["resource"],
            self.client.configuration.resource.as_str()
        );
        if let Some(expected_launch) = expected_launch {
            let launch = expected_launch.lock().unwrap();
            let launch = launch.as_ref().unwrap();
            assert_eq!(fields["grant_type"], "authorization_code");
            assert_eq!(fields["code"], "initial-code");
            assert_eq!(fields["redirect_uri"], launch["redirect_uri"]);
            assert_eq!(
                pkce_challenge(&fields["code_verifier"]).unwrap(),
                launch["code_challenge"]
            );
            assert!(!fields.contains_key("state"));
        } else {
            assert_eq!(fields["grant_type"], "refresh_token");
            assert_eq!(fields["refresh_token"], "initial-refresh");
            assert_eq!(fields["scope"], "tools:read");
        }
        socket
    }

    async fn token(&self, launch: &Mutex<Option<BTreeMap<String, String>>>, body: &str) {
        reply(&mut self.token_request(Some(launch)).await, body).await;
    }

    fn quiet(&self) {
        let mut task = Context::from_waker(Waker::noop());
        assert!(
            self.listener.poll_accept(&mut task).is_pending(),
            "no implicit login, exchange or MCP request"
        );
    }

    async fn mcp(&self, bearer: &str, f: &Fixture, expected_writes: usize) {
        let (socket, _) = self.listener.accept().await.unwrap();
        let mut socket = native::test_acceptor().accept(socket).await.unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0; 2048];
        let end = loop {
            let count = socket.read(&mut chunk).await.unwrap();
            assert!(count > 0 && bytes.len() + count <= 64 * 1024);
            bytes.extend_from_slice(&chunk[..count]);
            if let Some(at) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
                break at + 4;
            }
        };
        let head = std::str::from_utf8(&bytes[..end]).unwrap().to_owned();
        let length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap();
        assert!(end + length <= 64 * 1024);
        while bytes.len() < end + length {
            let count = socket.read(&mut chunk).await.unwrap();
            assert!(count > 0 && bytes.len() + count <= 64 * 1024);
            bytes.extend_from_slice(&chunk[..count]);
        }
        assert_eq!(bytes.len(), end + length);
        assert!(head.starts_with("POST /mcp HTTP/1.1\r\n"));
        assert!(
            head.to_ascii_lowercase()
                .contains(&format!("authorization: bearer {bearer}\r\n"))
        );
        let request: Value = serde_json::from_slice(&bytes[end..]).unwrap();
        assert_eq!(request["method"], "tools/call");
        assert_eq!(
            request["params"]["arguments"],
            json!({"text":"persisted-login"})
        );
        assert_eq!(request["id"], 73);
        assert_eq!(
            f.provider.0.lock().unwrap().writes,
            expected_writes,
            "protected persistence must settle before managed access is exposed"
        );
        reply(
            &mut socket,
            &json!({"jsonrpc":"2.0","id":73,"result":{
                "resultType":"complete","content":[{"type":"text","text":"persisted-login"}]
            }})
            .to_string(),
        )
        .await;
    }
}

async fn reply(socket: &mut TlsStream<TcpStream>, body: &str) {
    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    socket.shutdown().await.unwrap();
}

fn hosted_callback(
    authorization: CanonicalHttpUrl,
    launch: &Mutex<Option<BTreeMap<String, String>>>,
) -> Result<String, OAuthError> {
    let fields = decode_form(authorization.query().unwrap())?;
    assert_eq!(authorization.scheme(), "https");
    assert_eq!(fields["code_challenge_method"], "S256");
    assert_eq!(fields["scope"], "tools:read");
    let query = encode_form(&[
        ("code", "initial-code"),
        ("iss", "https://issuer.example"),
        ("state", &fields["state"]),
    ])?;
    let callback = format!("{}?{query}", fields["redirect_uri"]);
    *launch.lock().unwrap() = Some(fields);
    Ok(callback)
}

async fn browser_callback(
    authorization: CanonicalHttpUrl,
    launch: &Mutex<Option<BTreeMap<String, String>>>,
) -> Result<(), OAuthError> {
    let callback = url(&hosted_callback(authorization, launch)?);
    let address: SocketAddr = callback
        .as_str()
        .strip_prefix("http://")
        .unwrap()
        .split('/')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(address.ip().is_loopback());
    let mut socket = TcpStream::connect(address)
        .await
        .map_err(|_| OAuthError::CallbackRejected)?;
    socket
        .write_all(
            format!(
                "GET {}?{} HTTP/1.1\r\nHost: {address}\r\n\r\n",
                callback.path(),
                callback.query().unwrap()
            )
            .as_bytes(),
        )
        .await
        .map_err(|_| OAuthError::CallbackRejected)?;
    // Deliberately wait for the response. This requires the joint browser
    // driver; the launch-only API would deadlock with this host behavior.
    let mut status = [0; 12];
    socket
        .read_exact(&mut status)
        .await
        .map_err(|_| OAuthError::CallbackRejected)?;
    assert_eq!(&status, b"HTTP/1.1 200");
    Ok(())
}

fn begin(
    f: &Fixture,
    cx: &Cx,
    peer: &Peer,
    store: AsyncOAuthRefreshStore<Provider, Provider>,
    cancellation: &McpRequestCancellation,
) -> OAuthAuthorization<Provider, Provider> {
    let expected = store.revision();
    store
        .begin_authorization(
            cx,
            &peer.client,
            f.auth,
            expected,
            cancellation,
            Duration::from_secs(10),
        )
        .unwrap()
}

async fn protected_call(cx: &Cx, session: &ManagedOAuthSession) {
    let params = json!({
        "_meta":serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap(),
        "name":"echo","arguments":{"text":"persisted-login"},
    });
    let request =
        CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params)).unwrap();
    let mut call = session
        .request_core(
            cx,
            request,
            RequestId::Number(73),
            ManagedCoreLimits::default(),
        )
        .await
        .unwrap();
    let Some(ManagedCoreEvent::Result(result)) = call.next_event(cx).await.unwrap() else {
        panic!("the protected request must complete");
    };
    let result: Value = serde_json::from_str(&result.encode().unwrap()).unwrap();
    assert_eq!(result["content"][0]["text"], "persisted-login");
    assert!(call.next_event(cx).await.unwrap().is_none());
}

fn not_delivered(login: &mut OAuthAuthorization<Provider, Provider>, cx: &Cx) {
    assert!(matches!(
        login.take_managed_session(cx, OAuthSessionPolicy::default()),
        Err(OAuthAuthorizationError::NotComplete)
    ));
}

#[test]
fn persistent_initial_authorization_commits_before_access_and_reopens_for_renewal() {
    run(|cx| async move {
        for hosted in [false, true] {
            let f = Fixture::new();
            let lane = lane();
            let peer = Peer::new().await;
            let store = f.open(&cx, &lane, &peer.client).await;
            let mut login = begin(&f, &cx, &peer, store, &McpRequestCancellation::new());
            not_delivered(&mut login, &cx);
            let launch = Mutex::new(None);
            let launches = AtomicUsize::new(0);
            let operation = async {
                if hosted {
                    login
                        .run_with_redirect_driver(
                            &cx,
                            url("https://app.example/callback"),
                            |authorization| {
                                launches.fetch_add(1, Ordering::SeqCst);
                                std::future::ready(hosted_callback(authorization, &launch))
                            },
                        )
                        .await
                } else {
                    login
                        .run_with_browser_driver(&cx, |authorization| {
                            launches.fetch_add(1, Ordering::SeqCst);
                            browser_callback(authorization, &launch)
                        })
                        .await
                }
            };
            let ((), result) =
                Box::pin(native::pair(peer.token(&launch, INITIAL), operation)).await;
            result.unwrap();
            assert_eq!(launches.load(Ordering::SeqCst), 1);
            assert_eq!(login.stage(), OAuthAuthorizationStage::Complete);
            assert_eq!(f.provider.0.lock().unwrap().writes, 2);
            let (session, store, revision) = login
                .take_managed_session(&cx, OAuthSessionPolicy::default())
                .unwrap();
            assert_eq!(revision.generation(), 1);
            not_delivered(&mut login, &cx);
            let persisted = f.bytes();
            for secret in [
                "initial-access",
                "initial-refresh",
                "initial-code",
                "code_verifier",
            ] {
                assert!(
                    !persisted
                        .windows(secret.len())
                        .any(|bytes| bytes == secret.as_bytes())
                );
            }
            assert_eq!(session.credential(&cx).await.unwrap().generation(), 1);
            Box::pin(native::pair(
                peer.mcp("initial-access", &f, 2),
                protected_call(&cx, &session),
            ))
            .await;
            peer.quiet();
            done(&cx, &lane, store.close(&cx)).await;
            let store = f.open(&cx, &lane, &peer.client).await;
            let mut renewal = store
                .begin_renewal(
                    &cx,
                    &peer.client,
                    f.auth,
                    &McpRequestCancellation::new(),
                    Duration::from_secs(10),
                )
                .unwrap();
            let exchange = async {
                reply(&mut peer.token_request(None).await, RENEWED).await;
            };
            let ((), result) = Box::pin(native::pair(exchange, renewal.run(&cx))).await;
            result.unwrap();
            let (store, installed) = renewal
                .install_managed_access(&cx, &session, 1)
                .await
                .unwrap();
            assert_eq!(installed.session_generation(), 2);
            assert_eq!(installed.stored_revision().generation(), 3);
            assert_eq!(f.provider.0.lock().unwrap().writes, 6);
            Box::pin(native::pair(
                peer.mcp("renewed-access", &f, 6),
                protected_call(&cx, &session),
            ))
            .await;
            peer.quiet();
            session.close();
            done(&cx, &lane, store.close(&cx)).await;
        }
    });
}

#[test]
fn persistent_initial_authorization_preflight_refuses_foreign_partition_and_stale_revision() {
    run(|cx| async move {
        for foreign in [false, true] {
            let f = Fixture::new();
            let lane = lane();
            let peer = Peer::new().await;
            let store = f.open(&cx, &lane, &peer.client).await;
            let (store, (_, result)) = done(
                &cx,
                &lane,
                store.store_refresh(&cx, f.auth, None, credentials(&peer.client.configuration)),
            )
            .await
            .into_parts();
            let revision = result.unwrap();
            let before = f.bytes();
            let expected = if foreign { Some(revision) } else { None };
            let authorization = if foreign {
                identity("another-user").1
            } else {
                f.auth
            };
            let prepared = store.begin_authorization(
                &cx,
                &peer.client,
                authorization,
                expected,
                &McpRequestCancellation::new(),
                Duration::from_secs(10),
            );
            let store =
                if foreign {
                    let mut login = prepared.unwrap();
                    let result = login.run_with_browser_driver(&cx, |_| async {
                    panic!("foreign storage partition must be refused before launching a browser");
                }).await;
                    assert!(matches!(
                        result,
                        Err(OAuthAuthorizationError::Storage(
                            OAuthRefreshStoreError::Storage(_)
                        ))
                    ));
                    not_delivered(&mut login, &cx);
                    let OAuthAuthorizationCustody::Stopped {
                        store: Some(store),
                        credentials: None,
                    } = login.into_custody()
                    else {
                        panic!("preflight failure retains the unchanged store");
                    };
                    store
                } else {
                    let (error, retained) = prepared.err().unwrap().into_parts();
                    assert!(matches!(
                        error,
                        AsyncOAuthRefreshError::Store(OAuthRefreshStoreError::RevisionMismatch)
                    ));
                    retained.unwrap().0
                };
            peer.quiet();
            assert_eq!(f.bytes(), before);
            assert_eq!(f.provider.0.lock().unwrap().writes, 2);
            assert_eq!(f.provider.0.lock().unwrap().seals, 1);
            done(&cx, &lane, store.close(&cx)).await;
        }
    });
}

#[test]
fn persistent_initial_authorization_dropped_commit_wait_resumes_without_relogin() {
    run(|cx| async move {
        let f = Fixture::new();
        let lane = lane();
        let peer = Peer::new().await;
        let store = f.open(&cx, &lane, &peer.client).await;
        let mut login = begin(&f, &cx, &peer, store, &McpRequestCancellation::new());
        let gate = Release(Gate::new());
        f.provider.0.lock().unwrap().settled_gate = Some(Arc::clone(&gate.0));
        let launch = Mutex::new(None);
        let mut pending = Box::pin(login.run_with_redirect_driver(
            &cx,
            url("https://app.example/callback"),
            |authorization| std::future::ready(hosted_callback(authorization, &launch)),
        ));
        let arrived = async {
            peer.token(&launch, INITIAL).await;
            gate.0.entered(&cx).await;
        };
        let mut arrived = Box::pin(arrived);
        poll_fn(|task| {
            assert!(pending.as_mut().poll(task).is_pending());
            arrived.as_mut().poll(task)
        })
        .await;
        drop(arrived);
        drop(pending);
        assert_eq!(login.stage(), OAuthAuthorizationStage::Persisting);
        not_delivered(&mut login, &cx);
        assert_eq!(f.provider.0.lock().unwrap().writes, 2);
        gate.0.release();
        login
            .run_with_redirect_driver(&cx, url("https://app.example/callback"), |_| async {
                panic!(
                    "resuming the existing commit must not start another browser or code exchange"
                );
            })
            .await
            .unwrap();
        assert_eq!(f.provider.0.lock().unwrap().seals, 1);
        assert_eq!(f.provider.0.lock().unwrap().writes, 2);
        peer.quiet();
        let (session, store, revision) = login
            .take_managed_session(&cx, OAuthSessionPolicy::default())
            .unwrap();
        assert_eq!(revision.generation(), 1);
        Box::pin(native::pair(
            peer.mcp("initial-access", &f, 2),
            protected_call(&cx, &session),
        ))
        .await;
        session.close();
        done(&cx, &lane, store.close(&cx)).await;
    });
}

#[test]
fn persistent_initial_authorization_cancelled_commit_retains_its_exact_mailbox() {
    run(|cx| async move {
        let f = Fixture::new();
        let lane = lane();
        let peer = Peer::new().await;
        let store = f.open(&cx, &lane, &peer.client).await;
        let cancellation = McpRequestCancellation::new();
        let mut login = begin(&f, &cx, &peer, store, &cancellation);
        let gate = Release(Gate::new());
        f.provider.0.lock().unwrap().settled_gate = Some(Arc::clone(&gate.0));
        let launch = Mutex::new(None);
        let mut pending = Box::pin(login.run_with_redirect_driver(
            &cx,
            url("https://app.example/callback"),
            |authorization| std::future::ready(hosted_callback(authorization, &launch)),
        ));
        let arrived = async {
            peer.token(&launch, INITIAL).await;
            gate.0.entered(&cx).await;
        };
        let mut arrived = Box::pin(arrived);
        poll_fn(|task| {
            assert!(pending.as_mut().poll(task).is_pending());
            arrived.as_mut().poll(task)
        })
        .await;
        drop(arrived);
        cancellation.cancel();
        assert!(matches!(
            pending.as_mut().await,
            Err(OAuthAuthorizationError::Context(OAuthError::Cancelled))
        ));
        drop(pending);
        assert!(matches!(
            login.take_managed_session(&cx, OAuthSessionPolicy::default()),
            Err(OAuthAuthorizationError::Context(OAuthError::Cancelled))
        ));
        let OAuthAuthorizationCustody::Persisting(mut task) = login.into_custody() else {
            panic!("cancellation cannot discard a possibly committed transaction");
        };
        gate.0.release();
        let (store, (credentials, outcome)) = task.wait(&cx).await.unwrap().into_parts();
        assert!(matches!(
            outcome,
            Err(OAuthRefreshStoreError::Storage(CoordinatedSlotError::CommittedWithoutDelivery(revision)))
                if revision.generation() == 1
        ));
        assert!(!credentials.has_refresh_token());
        assert_eq!(store.revision().unwrap().generation(), 1);
        assert_eq!(f.provider.0.lock().unwrap().writes, 2);
        assert_eq!(f.provider.0.lock().unwrap().seals, 1);
        peer.quiet();
        drop(credentials);
        done(&cx, &lane, store.close(&cx)).await;
    });
}

#[test]
fn persistent_initial_authorization_failed_storage_never_delivers_or_repeats_the_flow() {
    run(|cx| async move {
        for failure in ["no-refresh", "seal", "uncertain"] {
            let f = Fixture::new();
            let lane = lane();
            let peer = Peer::new().await;
            let store = f.open(&cx, &lane, &peer.client).await;
            let mut login = begin(&f, &cx, &peer, store, &McpRequestCancellation::new());
            {
                let mut state = f.provider.0.lock().unwrap();
                state.refuse_seal = failure == "seal";
                state.uncertain_settlement = failure == "uncertain";
            }
            let launch = Mutex::new(None);
            let body = if failure == "no-refresh" {
                r#"{"access_token":"initial-access","token_type":"Bearer","expires_in":300}"#
            } else {
                INITIAL
            };
            let operation = login.run_with_redirect_driver(
                &cx,
                url("https://app.example/callback"),
                |authorization| std::future::ready(hosted_callback(authorization, &launch)),
            );
            let ((), result) = Box::pin(native::pair(peer.token(&launch, body), operation)).await;
            let expected = match failure {
                "no-refresh" => OAuthRefreshStoreError::RefreshUnavailable,
                "seal" => {
                    OAuthRefreshStoreError::Protection(OAuthGrantProtectionError::Unavailable)
                }
                _ => OAuthRefreshStoreError::Storage(CoordinatedSlotError::Anchor(
                    CredentialAnchorError::Uncertain,
                )),
            };
            assert!(
                matches!(result, Err(OAuthAuthorizationError::Storage(error)) if error == expected)
            );
            not_delivered(&mut login, &cx);
            assert!(matches!(
                login
                    .run_with_browser_driver(&cx, |_| async {
                        panic!("failed persistence must not restart browser authorization");
                    })
                    .await,
                Err(OAuthAuthorizationError::Stopped)
            ));
            peer.quiet();
            let OAuthAuthorizationCustody::Stopped {
                store: Some(store),
                credentials: Some(credentials),
            } = login.into_custody()
            else {
                panic!("retain the actual storage and credential disposition");
            };
            assert_eq!(credentials.has_refresh_token(), failure == "seal");
            assert_eq!(store.requires_recovery(), failure == "uncertain");
            assert_eq!(
                f.provider.0.lock().unwrap().writes,
                if failure == "uncertain" { 2 } else { 0 }
            );
            assert_eq!(
                f.provider.0.lock().unwrap().seals,
                usize::from(failure != "no-refresh")
            );
            drop(credentials);
            done(&cx, &lane, store.close(&cx)).await;
        }
    });
}

#[test]
fn persistent_initial_authorization_cancelled_or_dropped_exchange_cannot_replay_code() {
    run(|cx| async move {
        for cancelled in [false, true] {
            let f = Fixture::new();
            let lane = lane();
            let peer = Peer::new().await;
            let store = f.open(&cx, &lane, &peer.client).await;
            let cancellation = McpRequestCancellation::new();
            let mut login = begin(&f, &cx, &peer, store, &cancellation);
            let launch = Mutex::new(None);
            let launches = AtomicUsize::new(0);
            let mut pending = Box::pin(login.run_with_redirect_driver(
                &cx,
                url("https://app.example/callback"),
                |authorization| {
                    launches.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(hosted_callback(authorization, &launch))
                },
            ));
            let mut receiving = Box::pin(peer.token_request(Some(&launch)));
            let socket = poll_fn(|task| {
                assert!(pending.as_mut().poll(task).is_pending());
                receiving.as_mut().poll(task)
            })
            .await;
            drop(receiving);
            if cancelled {
                cancellation.cancel();
                assert!(matches!(
                    pending.as_mut().await,
                    Err(OAuthAuthorizationError::Context(OAuthError::Cancelled))
                ));
            }
            drop(pending);
            drop(socket);
            assert_eq!(login.stage(), OAuthAuthorizationStage::Stopped);
            assert_eq!(launches.load(Ordering::SeqCst), 1);
            assert!(matches!(
                login
                    .run_with_redirect_driver(&cx, url("https://app.example/callback"), |_| async {
                        panic!("a possibly redeemed code must never be retried");
                    })
                    .await,
                Err(OAuthAuthorizationError::Stopped)
            ));
            peer.quiet();
            assert_eq!(f.provider.0.lock().unwrap().seals, 0);
            assert_eq!(f.provider.0.lock().unwrap().writes, 0);
            let OAuthAuthorizationCustody::Stopped {
                store: Some(store),
                credentials: None,
            } = login.into_custody()
            else {
                panic!("dropped/cancelled code exchange retains only its original store");
            };
            assert!(
                cx.checkpoint().is_ok(),
                "request-local cancellation preserves the caller"
            );
            done(&cx, &lane, store.close(&cx)).await;
        }
    });
}

fn restricted(cx: &Cx, mask: CapMask) -> Cx {
    let _current = Cx::set_current(Some(cx.clone()));
    let _restriction = Cx::push_restriction(mask);
    Cx::current().unwrap()
}

fn poll_under<F: Future>(
    future: Pin<&mut F>,
    task: &mut Context<'_>,
    ambient: &Cx,
) -> Poll<F::Output> {
    let _current = Cx::set_current(Some(ambient.clone()));
    future.poll(task)
}

#[test]
fn persistent_initial_authorization_honors_host_capabilities_before_storage_or_browser() {
    run(|cx| async move {
        for mask in [
            CapSet::<true, true, true, false, true>::MASK,
            CapSet::<true, false, true, true, true>::MASK,
            CapSet::<false, true, true, true, true>::MASK,
        ] {
            let f = Fixture::new();
            let lane = lane();
            let peer = Peer::new().await;
            let store = f.open(&cx, &lane, &peer.client).await;
            let mut login = begin(&f, &cx, &peer, store, &McpRequestCancellation::new());
            let reads = f.provider.0.lock().unwrap().reads;
            let ambient = restricted(&cx, mask);
            let mut future = Box::pin(login.run_with_browser_driver(&cx, |_| async {
                panic!("the host's withheld effects must prevent browser launch");
            }));
            let mut task = Context::from_waker(Waker::noop());
            assert!(matches!(
                poll_under(future.as_mut(), &mut task, &ambient),
                Poll::Ready(Err(OAuthAuthorizationError::Context(
                    OAuthError::RuntimeCapabilityUnavailable | OAuthError::RuntimeTimerUnavailable
                ) | OAuthAuthorizationError::Submission(
                    AsyncOAuthRefreshError::Io(CredentialIoError::CapabilityUnavailable)
                )))
            ));
            drop(future);
            assert_eq!(login.stage(), OAuthAuthorizationStage::ReadyToCheck);
            assert_eq!(f.provider.0.lock().unwrap().reads, reads);
            assert_eq!(f.provider.0.lock().unwrap().writes, 0);
            peer.quiet();
            // The same unstarted owner remains usable under the actual caller.
            let launch = Mutex::new(None);
            let ((), result) = Box::pin(native::pair(
                peer.token(&launch, INITIAL),
                login.run_with_redirect_driver(
                    &cx,
                    url("https://app.example/callback"),
                    |authorization| {
                        assert_eq!(Cx::current().unwrap().task_id(), cx.task_id());
                        std::future::ready(hosted_callback(authorization, &launch))
                    },
                ),
            ))
            .await;
            result.unwrap();
            let (session, store, _) = login
                .take_managed_session(&cx, OAuthSessionPolicy::default())
                .unwrap();
            session.close();
            done(&cx, &lane, store.close(&cx)).await;
        }
    });
}
