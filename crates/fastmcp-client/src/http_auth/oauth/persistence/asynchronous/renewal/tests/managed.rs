//! Native renewed-grant adoption, including one complete file/TLS/MCP journey.
//! The peer scripts protocol replies; it is not the native server registry.
//! Persistence services are the explicitly in-memory parent fixture doubles.
use super::*;
use asupersync::io::AsyncReadExt;
use crate::http_auth::managed::{ManagedOAuthSession, OAuthSessionError, OAuthSessionPolicy};
use crate::http_auth::rpc::{ManagedCoreEvent, ManagedCoreLimits};
use fastmcp_protocol::{ClientCapabilities, CoreRequest, FinalRequestMeta, RequestId};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use serde_json::{Value, json};

#[test]
fn adopted_native_credentials_keep_expiry_scopes_and_shared_session_closure() {
    run(|cx| async move {
        let configuration = native::config();
        let client = OAuthClient::new(configuration.clone());
        let mut credentials = native::renewable_grant(&configuration);
        credentials.refresh_token = None;
        let expiry = credentials.expires_at();
        let scopes = credentials.scopes().to_vec();
        let session = ManagedOAuthSession::from_credentials(&cx, client, OAuthSessionPolicy::default(), credentials).unwrap();
        let sibling = session.clone();
        let snapshot = session.credential(&cx).await.unwrap();
        assert_eq!(snapshot.generation(), 1);
        assert_eq!(snapshot.expires_at(), expiry);
        assert_eq!(snapshot.scopes(), scopes);
        drop(session);
        assert_eq!(sibling.credential(&cx).await.unwrap().expires_at(), expiry);
        let credential = snapshot.credential().clone();
        assert!(credential.authorization_for_target(&configuration.resource).is_some());
        drop(sibling);
        assert!(credential.authorization_for_target(&configuration.resource).is_none());
        assert!(snapshot.credential().authorization_for_target(&configuration.resource).is_none());
        assert!(cx.checkpoint().is_ok());
    });
}

#[test]
fn adoption_rejects_foreign_configuration_expiry_revocation_and_stopped_caller() {
    run(|cx| async move {
        let original = native::config();
        for case in 0..4 {
            let mut configuration = original.clone();
            let mut credentials = native::renewable_grant(&original);
            match case {
                0 => configuration.client_id.push_str("-foreign"),
                1 => credentials.expires_at = Instant::now(),
                2 => { credentials.access.revoke(); },
                _ => {},
            }
            let cancelled = Cx::for_testing_with_budget(asupersync::Budget::ZERO);
            let result = ManagedOAuthSession::from_credentials(if case == 3 { &cancelled } else { &cx },
                OAuthClient::new(configuration), OAuthSessionPolicy::default(), credentials);
            match case {
                0 => assert!(matches!(result, Err(OAuthSessionError::OAuth(OAuthError::CredentialBindingMismatch)))),
                1 | 2 => assert!(matches!(result, Err(OAuthSessionError::LoginRequired))),
                _ => assert!(matches!(result, Err(OAuthSessionError::Cancelled))),
            }
        }
        let session = ManagedOAuthSession::from_credentials(&cx, OAuthClient::new(original.clone()),
            OAuthSessionPolicy::default(), native::renewable_grant(&original)).unwrap();
        assert!(session.credential(&cx).await.is_ok());
        session.close();
    });
}

#[test]
fn adopted_access_only_grant_never_reacquires_after_its_original_expiry() {
    run(|cx| async move {
        let (listener, client) = peer().await;
        let mut credentials = native::renewable_grant(&client.configuration);
        credentials.refresh_token = None;
        credentials.expires_at = Instant::now() + Duration::from_millis(500);
        let session = ManagedOAuthSession::from_credentials(&cx, client, OAuthSessionPolicy::default(), credentials).unwrap();
        let snapshot = session.credential(&cx).await.unwrap();
        asupersync::time::sleep(cx.now(), Duration::from_millis(550)).await;
        assert!(matches!(session.credential(&cx).await, Err(OAuthSessionError::LoginRequired)));
        assert!(Instant::now() >= snapshot.expires_at());
        quiet(&listener);
        session.close();
    });
}

async fn http_request(socket: &mut asupersync::tls::TlsStream<asupersync::net::TcpStream>) -> (String, Value) {
    let mut bytes = Vec::new();
    let mut chunk = [0; 2048];
    let end = loop {
        let size = socket.read(&mut chunk).await.unwrap();
        assert!(size > 0 && bytes.len() + size <= 64 * 1024);
        bytes.extend_from_slice(&chunk[..size]);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") { break index + 4; }
    };
    let head = std::str::from_utf8(&bytes[..end]).unwrap().to_owned();
    let length = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
    }).unwrap();
    assert!(end + length <= 64 * 1024);
    while bytes.len() < end + length {
        let size = socket.read(&mut chunk).await.unwrap();
        assert!(size > 0 && bytes.len() + size <= 64 * 1024);
        bytes.extend_from_slice(&chunk[..size]);
    }
    assert_eq!(bytes.len(), end + length);
    (head, serde_json::from_slice(&bytes[end..]).unwrap())
}

#[test]
fn persisted_renewal_adopts_into_typed_authenticated_mcp_without_browser_login() {
    run(|cx| async move {
        let (issuer, mut client) = peer().await;
        let resource = bind_loopback().await.unwrap();
        let resource_url = CanonicalHttpUrl::parse(&format!("https://{}/mcp", resource.local_addr().unwrap())).unwrap();
        client.configuration.resource = resource_url.clone();
        client.configuration = client.configuration.with_resource_root_certificate(native::test_root()).unwrap();
        let fixture = Fixture::new();
        let store = fixture.seed(&cx, &client).await;
        let mut renewal = fixture.begin(&cx, &client, store);
        assert!(matches!(renewal.take_managed_session(&cx, OAuthSessionPolicy::default()), Err(OAuthRefreshRenewalError::NotComplete)));
        assert_eq!(renewal.stage(), OAuthRefreshRenewalStage::ReadyToTake);
        let metadata = serde_json::to_value(FinalRequestMeta::new(ClientCapabilities::default())).unwrap();
        let params = json!({"_meta": metadata, "name": "echo", "arguments": {"value": "persisted-path"}});
        let request = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params)).unwrap();
        let server = async {
            let (socket, _) = issuer.accept().await.unwrap();
            let mut tls = native::test_acceptor().accept(socket).await.unwrap();
            let (_, form) = native::read_token_request(&mut tls).await.unwrap();
            assert_eq!(form["refresh_token"], "refresh-one");
            assert_eq!(form["grant_type"], "refresh_token");
            assert_eq!(form["resource"], resource_url.as_str());
            tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{ROTATED}", ROTATED.len()).as_bytes()).await.unwrap();
            tls.shutdown().await.unwrap();
            let (socket, _) = resource.accept().await.unwrap();
            let mut tls = native::test_acceptor().accept(socket).await.unwrap();
            let (head, body) = http_request(&mut tls).await;
            assert!(head.starts_with("POST /mcp HTTP/1.1\r\n"));
            assert!(head.to_ascii_lowercase().contains("authorization: bearer renewed-access\r\n"));
            assert!(!head.to_ascii_lowercase().contains("mcp-session-id:"));
            assert_eq!(body["id"], 41);
            assert_eq!(body["method"], "tools/call");
            assert_eq!(body["params"], params);
            {
                let state = fixture.provider.0.lock().unwrap();
                assert_eq!(state.writes, 6, "replacement must settle before MCP dispatch");
                assert!(matches!(state.snapshot.state(), CredentialAnchorState::Stable(Some(revision)) if revision.generation() == 3));
            }
            let body = json!({"jsonrpc":"2.0","id":41,"result":{"resultType":"complete","content":[{"type":"text","text":"persisted-path"}]}}).to_string();
            tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            tls.shutdown().await.unwrap();
        };
        let application = async {
            renewal.run(&cx).await.unwrap();
            let (session, store, revision) = renewal.take_managed_session(&cx, OAuthSessionPolicy::default()).unwrap();
            assert_eq!(revision.generation(), 3);
            assert!(matches!(renewal.take_managed_session(&cx, OAuthSessionPolicy::default()), Err(OAuthRefreshRenewalError::NotComplete)));
            let snapshot = session.credential(&cx).await.unwrap();
            assert_eq!(snapshot.generation(), 1, "session-local generation is not the file revision");
            let mut call = session.request_core(&cx, request, RequestId::Number(41), ManagedCoreLimits::default()).await.unwrap();
            let Some(ManagedCoreEvent::Result(result)) = call.next_event(&cx).await.unwrap() else { panic!("typed complete result"); };
            let result: Value = serde_json::from_str(&result.encode().unwrap()).unwrap();
            assert_eq!(result["content"][0]["text"], "persisted-path");
            assert!(call.next_event(&cx).await.unwrap().is_none());
            session.close();
            assert!(snapshot.credential().authorization_for_target(&resource_url).is_none());
            // Session close is local access revocation, not a persistent logout.
            close(&cx, store).await;
            let store = fixture.open(&cx, &client).await;
            let (store, outcome) = store.take_refresh(&cx, fixture.auth).unwrap().wait(&cx).await.unwrap().into_parts();
            assert_eq!(outcome.unwrap().unwrap().refresh_token, "refresh-two");
            close(&cx, store).await;
        };
        Box::pin(native::pair(server, application)).await;
        quiet(&issuer); quiet(&resource);
    });
}

#[test]
fn cancelled_session_handoff_leaves_the_completed_store_available_for_cleanup() {
    run(|cx| async move {
        let (listener, client) = peer().await;
        let fixture = Fixture::new();
        let store = fixture.seed(&cx, &client).await;
        let mut renewal = fixture.begin(&cx, &client, store);
        let ((), result) = native::pair(token_reply(&listener, Some(ROTATED)), renewal.run(&cx)).await;
        result.unwrap();
        renewal.cancel();
        assert!(matches!(renewal.take_managed_session(&cx, OAuthSessionPolicy::default()), Err(OAuthRefreshRenewalError::Context(OAuthError::Cancelled))));
        assert_eq!(renewal.stage(), OAuthRefreshRenewalStage::Complete);
        let OAuthRefreshRenewalCustody::Complete { store, credentials, revision } = renewal.into_custody() else { panic!("complete custody preserved"); };
        assert_eq!(revision.generation(), 3);
        assert!(!credentials.has_refresh_token());
        close(&cx, store).await;
        quiet(&listener);
    });
}

#[test]
fn rejected_access_adoption_retains_the_completed_store_without_reexchanging() {
    run(|cx| async move {
        let (listener, client) = peer().await;
        let fixture = Fixture::new();
        let store = fixture.seed(&cx, &client).await;
        let mut renewal = fixture.begin(&cx, &client, store);
        let ((), result) = native::pair(token_reply(&listener, Some(ROTATED)), renewal.run(&cx)).await;
        result.unwrap();
        let OAuthRefreshRenewalCustody::Complete { credentials, .. } = &renewal.custody else { panic!("completed"); };
        credentials.bearer_credential().revoke();
        assert!(matches!(renewal.take_managed_session(&cx, OAuthSessionPolicy::default()), Err(OAuthRefreshRenewalError::Session(OAuthSessionError::LoginRequired))));
        assert_eq!(renewal.stage(), OAuthRefreshRenewalStage::Stopped);
        let OAuthRefreshRenewalCustody::Stopped { store: Some(store), credentials: None } = renewal.into_custody() else { panic!("store retained"); };
        assert_eq!(store.revision().unwrap().generation(), 3);
        close(&cx, store).await;
        quiet(&listener);
    });
}

#[test]
fn abandoned_or_cancelled_refresh_exchange_never_restores_issuer_replay_authority() {
    run(|cx| async move {
        for cancel_run in [false, true] {
            let (listener, client) = peer().await;
            let fixture = Fixture::new();
            let store = fixture.seed(&cx, &client).await;
            let cancellation = McpRequestCancellation::new();
            let mut renewal = store.begin_renewal(&cx, &client, fixture.auth, &cancellation, Duration::from_secs(30)).unwrap();
            renewal.advance(&cx).await.unwrap(); renewal.advance(&cx).await.unwrap();
            let (received, mut arrival) = asupersync::channel::oneshot::channel();
            let server = async {
                let (socket, _) = listener.accept().await.unwrap();
                let mut tls = native::test_acceptor().accept(socket).await.unwrap();
                let (_, form) = native::read_token_request(&mut tls).await.unwrap();
                assert_eq!(form["refresh_token"], "refresh-one");
                received.send(&cx, ()).unwrap();
                let mut byte = [0];
                assert!(!matches!(tls.read(&mut byte).await, Ok(size) if size > 0), "abandonment must release the socket");
            };
            let application = async {
                let mut exchange = Box::pin(renewal.advance(&cx));
                let mut arrived = Box::pin(arrival.recv(&cx));
                poll_fn(|task| {
                    assert!(exchange.as_mut().poll(task).is_pending());
                    arrived.as_mut().poll(task)
                }).await.unwrap();
                if cancel_run {
                    cancellation.cancel();
                    assert!(matches!(exchange.await, Err(OAuthRefreshRenewalError::Context(OAuthError::Cancelled))));
                } else { drop(exchange); }
                assert_eq!(renewal.stage(), OAuthRefreshRenewalStage::Stopped);
                assert!(renewal.run(&cx).await.is_err());
                let OAuthRefreshRenewalCustody::Stopped { store: Some(store), credentials: None } = renewal.into_custody() else { panic!("no old grant retained"); };
                assert_eq!(store.revision().unwrap().generation(), 2);
                close(&cx, store).await;
            };
            Box::pin(native::pair(server, application)).await;
            quiet(&listener);
        }
    });
}

#[test]
fn dropped_storage_wait_retains_the_same_take_until_its_one_commit_completes() {
    run(|cx| async move {
        let fixture = Fixture::new(); let client = OAuthClient::new(native::config());
        let store = fixture.seed(&cx, &client).await;
        let release = ReleaseOpen(OpenGate::new());
        fixture.provider.0.lock().unwrap().open_gate = Some(release.0.clone());
        let mut renewal = fixture.begin(&cx, &client, store);
        assert_eq!(renewal.advance(&cx).await.unwrap(), OAuthRefreshRenewalStage::Taking);
        release.0.entered(&cx).await;
        let mut waiting = Box::pin(renewal.advance(&cx));
        poll_fn(|task| { assert!(waiting.as_mut().poll(task).is_pending()); Poll::Ready(()) }).await;
        drop(waiting);
        assert_eq!(renewal.stage(), OAuthRefreshRenewalStage::Taking);
        assert_eq!(fixture.provider.0.lock().unwrap().writes, 2);
        release.0.release();
        assert_eq!(renewal.advance(&cx).await.unwrap(), OAuthRefreshRenewalStage::ReadyToExchange);
        { let state = fixture.provider.0.lock().unwrap(); assert_eq!(state.opens, 1); assert_eq!(state.writes, 4); }
        let OAuthRefreshRenewalCustody::ReadyToExchange { store, grant } = renewal.into_custody() else { panic!("single committed take"); };
        assert_eq!(grant.refresh_token, "refresh-one");
        close(&cx, store).await;
    });
}

#[test]
fn cancelled_storage_wait_keeps_its_completion_and_does_not_release_an_uncommitted_grant() {
    run(|cx| async move {
        let fixture = Fixture::new(); let client = OAuthClient::new(native::config());
        let store = fixture.seed(&cx, &client).await;
        let before = fixture.bytes();
        let release = ReleaseOpen(OpenGate::new());
        fixture.provider.0.lock().unwrap().open_gate = Some(release.0.clone());
        let mut renewal = fixture.begin(&cx, &client, store);
        renewal.advance(&cx).await.unwrap();
        release.0.entered(&cx).await;
        renewal.cancel();
        assert!(matches!(renewal.advance(&cx).await, Err(OAuthRefreshRenewalError::Context(OAuthError::Cancelled))));
        let OAuthRefreshRenewalCustody::Taking(mut task) = renewal.into_custody() else { panic!("retain the original completion"); };
        release.0.release();
        // The cancellation-dominant task join must not erase the storage outcome.
        let (store, outcome) = task.wait(&cx).await.unwrap().into_parts();
        assert!(outcome.is_err());
        assert_eq!(fixture.bytes(), before);
        assert_eq!(store.revision().unwrap().generation(), 1);
        assert_eq!(fixture.provider.0.lock().unwrap().writes, 2);
        close(&cx, store).await;
    });
}
