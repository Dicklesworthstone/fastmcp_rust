//! Successful machine grants must remain in the explicitly selected bearer
//! profile. These tests use public discovery/acquisition/MCP APIs and native
//! TLS with the parent's explicit trust configuration. The peer scripts issuer
//! responses; this is not external-provider or durable-custody qualification.

use super::*;

#[path = "token_admission/singleflight.rs"]
mod singleflight;

fn run_admission<F, Fut>(scenario: F)
where
    F: FnOnce(Cx) -> Fut,
    Fut: Future<Output = ()>,
{
    RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .build()
        .unwrap()
        .block_on(async move {
            let cx = Cx::current().unwrap();
            let deadline = cx.now().saturating_add_nanos(30_000_000_000);
            asupersync::time::timeout_at(deadline, Box::pin(scenario(cx)))
                .await
                .expect("machine token admission fixture must settle");
        });
}

async fn discover(peer: &Peer, cx: &Cx, post: bool) -> ClientCredentialsClient {
    let mut plan = peer.plan(Duration::from_secs(10));
    if post {
        plan = plan
            .with_secret_authentication(ClientSecretAuthenticationMethod::Post)
            .unwrap();
        let ((), client) = pair(post_metadata(peer, PostCase::Lifecycle), plan.discover(cx)).await;
        client.unwrap()
    } else {
        let ((), client) = pair(peer.metadata(Case::Complete), plan.discover(cx)).await;
        client.unwrap()
    }
}

async fn reply(peer: &Peer, post: bool, body: &str) {
    let mut socket = if post {
        post_token_request(peer, "service-client", "service-secret").await
    } else {
        peer.token_request().await
    };
    json_reply(&mut socket, body).await;
}

fn ordinary_token() -> Value {
    json!({"access_token":"admitted-access", "token_type":"Bearer",
        "expires_in":300, "scope":"read"})
}

async fn core_succeeds(peer: &Peer, cx: &Cx, client: &ClientCredentialsClient, token: &str) {
    let ((), response) = pair(
        peer.operation(41, "tools/call", token, CALL),
        client.execute_core(
            cx,
            core("tools/call"),
            RequestId::Number(41),
            RequestId::Number(42),
        ),
    )
    .await;
    let result = response.unwrap().read_json_result(cx, 4096).await.unwrap();
    assert!(matches!(
        result,
        CoreResult::Final(FinalCoreResult::ToolsCall { .. })
    ));
    peer.quiet();
}

#[test]
fn incompatible_machine_grants_stop_dispatch_without_installing_a_generation() {
    for post in [false, true] {
        run_admission(|cx| async move {
            let peer = Peer::new().await;
            let client = discover(&peer, &cx, post).await;
            for (index, (key, value)) in [
                ("refresh_token", json!("private-refresh-canary")),
                ("id_token", json!("private-identity-canary")),
                ("cnf", json!({"jkt":"private-proof-canary"})),
                (
                    "issued_token_type",
                    json!("urn:ietf:params:oauth:token-type:access_token"),
                ),
                ("error_description", json!("private-error-canary")),
                ("error_uri", json!("https://untrusted.example/error")),
            ]
            .into_iter()
            .enumerate()
            {
                let mut document = ordinary_token();
                document[key] = value;
                let body = document.to_string();
                let ((), result) = pair(
                    reply(&peer, post, &body),
                    client.execute_core(
                        &cx,
                        core("tools/call"),
                        RequestId::Number(1),
                        RequestId::Number(2),
                    ),
                )
                .await;
                let error = result
                    .err()
                    .expect("incompatible success must not reach MCP dispatch");
                assert!(matches!(error, Error::InvalidToken));
                let diagnostic = format!("{error:?} {error}");
                assert!(
                    !diagnostic.contains("private-") && !diagnostic.contains("admitted-access")
                );
                assert_eq!(peer.grants.load(Ordering::SeqCst), index + 1);
                assert_eq!(peer.rpcs.load(Ordering::SeqCst), 0);
                peer.quiet();
            }
            // This is an explicit new acquisition after rejection, not an
            // automatic retry. Every failed candidate left generation zero.
            let body = ordinary_token().to_string();
            let ((), admitted) = pair(reply(&peer, post, &body), client.credential(&cx)).await;
            let admitted = admitted.unwrap();
            assert_eq!(admitted.generation(), 1);
            assert_eq!(admitted.scopes(), ["read"]);
            core_succeeds(&peer, &cx, &client, "admitted-access").await;
            assert_eq!(peer.grants.load(Ordering::SeqCst), 7);
            assert_eq!(peer.rpcs.load(Ordering::SeqCst), 2);
            assert_eq!(peer.gets.load(Ordering::SeqCst), 2);
            assert!(cx.checkpoint().is_ok());
            client.close();
        });
    }
}

#[test]
fn ignored_machine_metadata_is_not_mistaken_for_top_level_token_authority() {
    for post in [false, true] {
        run_admission(|cx| async move {
            let peer = Peer::new().await;
            let client = discover(&peer, &cx, post).await;
            let mut document = ordinary_token();
            document["token_type"] = json!("bEaReR");
            document["x-extension"] = json!({"refresh_token":null, "id_token":"nested",
                "cnf":{"jkt":"nested"}, "error_description":"nested", "scope":"admin"});
            document["token_endpoint"] = json!("https://untrusted.example/alternate");
            document["registration_client_uri"] = json!("https://untrusted.example/registration");
            let body = document.to_string();
            let ((), admitted) = pair(reply(&peer, post, &body), client.credential(&cx)).await;
            let admitted = admitted.unwrap();
            assert_eq!(admitted.generation(), 1);
            assert_eq!(admitted.scopes(), ["read"]);
            assert_eq!(admitted.credential().resource(), client.resource());
            assert!(
                admitted
                    .credential()
                    .authorization_for_target(&url("https://untrusted.example/alternate"))
                    .is_none()
            );
            core_succeeds(&peer, &cx, &client, "admitted-access").await;
            assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
            assert_eq!(peer.rpcs.load(Ordering::SeqCst), 2);
            assert_eq!(peer.gets.load(Ordering::SeqCst), 2);
            assert!(cx.checkpoint().is_ok());
            client.close();
        });
    }
}

#[test]
fn rejected_machine_renewal_preserves_the_original_lineage_and_generation() {
    for post in [false, true] {
        for renew_again in [false, true] {
            run_admission(|cx| async move {
                let peer = Peer::new().await;
                let client = discover(&peer, &cx, post).await;
                let mut first = ordinary_token();
                first["expires_in"] = json!(1);
                let body = first.to_string();
                let ((), old) = pair(reply(&peer, post, &body), client.credential(&cx)).await;
                let old = old.unwrap();
                let expiry = old.expires_at();
                assert_eq!(old.generation(), 1);
                // Real access expiry is monotonic wall time, not the runtime's
                // virtual timer. Do not mutate private cache state to force it.
                let remaining = expiry.saturating_duration_since(Instant::now());
                asupersync::time::sleep(cx.now(), remaining + Duration::from_millis(20)).await;
                assert!(Instant::now() >= expiry);
                assert!(
                    old.credential()
                        .authorization_for_target(client.resource())
                        .is_none()
                );
                let mut invalid = ordinary_token();
                invalid["access_token"] = json!("must-not-install");
                invalid["cnf"] = json!({"x5t#S256":"certificate-bound"});
                let body = invalid.to_string();
                let ((), refused) = pair(reply(&peer, post, &body), client.credential(&cx)).await;
                assert!(matches!(refused, Err(Error::InvalidToken)));
                assert_eq!(peer.grants.load(Ordering::SeqCst), 2);
                assert_eq!(old.expires_at(), expiry);
                assert_eq!(old.generation(), 1);
                assert_eq!(old.scopes(), ["read"]);
                peer.quiet();
                if renew_again {
                    let mut replacement = ordinary_token();
                    replacement["access_token"] = json!("replacement-access");
                    let body = replacement.to_string();
                    let ((), new) = pair(reply(&peer, post, &body), client.credential(&cx)).await;
                    let new = new.unwrap();
                    assert_eq!(
                        new.generation(),
                        2,
                        "a rejected candidate must not increment generation"
                    );
                    old.credential().revoke();
                    assert!(!new.credential().is_revoked());
                    core_succeeds(&peer, &cx, &client, "replacement-access").await;
                    assert_eq!(peer.grants.load(Ordering::SeqCst), 3);
                } else {
                    // Observing the old snapshot alone cannot prove the cache
                    // retained it. Revoking it must ALSO stop the actual next
                    // acquisition locally. A replaced/cleared cache would fail
                    // this assertion or try to send a third grant instead.
                    old.credential().revoke();
                    let mut next = Box::pin(client.credential(&cx));
                    poll_fn(|task| {
                        assert!(matches!(
                            next.as_mut().poll(task),
                            Poll::Ready(Err(Error::Expired))
                        ));
                        Poll::Ready(())
                    })
                    .await;
                    assert_eq!(peer.grants.load(Ordering::SeqCst), 2);
                    assert_eq!(peer.rpcs.load(Ordering::SeqCst), 0);
                    peer.quiet();
                }
                assert!(cx.checkpoint().is_ok());
                client.close();
            });
        }
    }
}

#[test]
fn a_complete_json_token_prefix_is_not_a_complete_http_token_response() {
    for post in [false, true] {
        for truncated in [false, true] {
            run_admission(|cx| async move {
                let peer = Peer::new().await;
                let client = discover(&peer, &cx, post).await;
                let body = ordinary_token().to_string();
                let server = async {
                    let mut socket = if post {
                        post_token_request(&peer, "service-client", "service-secret").await
                    } else {
                        peer.token_request().await
                    };
                    // The only changed wire dimension is the declared length.
                    // Both peers send the SAME complete, valid JSON document.
                    let length = body.len() + if truncated { 9 } else { 0 };
                    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{body}").as_bytes()).await.unwrap();
                    socket.flush().await.unwrap();
                    socket.shutdown().await.unwrap();
                };
                let ((), result) = pair(server, client.credential(&cx)).await;
                if truncated {
                    assert!(matches!(result, Err(Error::Transport)));
                    assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
                    peer.quiet();
                    let ((), result) =
                        pair(reply(&peer, post, &body), client.credential(&cx)).await;
                    assert_eq!(result.unwrap().generation(), 1);
                } else {
                    assert_eq!(result.unwrap().generation(), 1);
                }
                core_succeeds(&peer, &cx, &client, "admitted-access").await;
                assert_eq!(
                    peer.grants.load(Ordering::SeqCst),
                    if truncated { 2 } else { 1 }
                );
                assert!(cx.checkpoint().is_ok());
                client.close();
            });
        }
    }
}

#[test]
fn escaped_duplicate_and_null_authority_fields_fail_on_the_real_token_path() {
    for post in [false, true] {
        run_admission(|cx| async move {
            let peer = Peer::new().await;
            let client = discover(&peer, &cx, post).await;
            for (index, field) in [
                r#""refresh\u005ftoken":null"#,
                r#""id\u005ftoken":"private-token""#,
                r#""c\u006ef":{}"#,
                r#""error_description":null"#,
                r#""refresh_token":null,"refresh_token":"private-token""#,
                r#""issued_token_type":null"#,
            ]
            .into_iter()
            .enumerate()
            {
                let body = format!(
                    r#"{{"access_token":"admitted-access","token_type":"Bearer","expires_in":300,"scope":"read",{field}}}"#
                );
                let ((), result) = pair(reply(&peer, post, &body), client.credential(&cx)).await;
                let error = result
                    .err()
                    .expect("wire spelling cannot erase incompatible authority");
                assert!(matches!(error, Error::InvalidToken));
                assert!(!format!("{error:?} {error}").contains("private-token"));
                assert_eq!(peer.grants.load(Ordering::SeqCst), index + 1);
                assert_eq!(peer.rpcs.load(Ordering::SeqCst), 0);
                peer.quiet();
            }
            let body = ordinary_token().to_string();
            let ((), result) = pair(reply(&peer, post, &body), client.credential(&cx)).await;
            assert_eq!(result.unwrap().generation(), 1);
            core_succeeds(&peer, &cx, &client, "admitted-access").await;
            assert_eq!(peer.grants.load(Ordering::SeqCst), 7);
            client.close();
        });
    }
}

#[test]
fn cancelling_after_token_json_before_http_completion_cannot_seed_the_cache() {
    for post in [false, true] {
        run_admission(|cx| async move {
            let peer = Peer::new().await;
            let client = discover(&peer, &cx, post).await;
            let body = ordinary_token().to_string();
            let cancellation = McpRequestCancellation::new();
            let (sent, mut received) = oneshot::channel::<()>();
            let server = async {
                let mut socket = if post {
                    post_token_request(&peer, "service-client", "service-secret").await
                } else {
                    peer.token_request().await
                };
                // A full JSON grant is on the wire, but HTTP has not completed.
                // The final zero-length chunk is deliberately never sent.
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{:X}\r\n{body}\r\n", body.len()).as_bytes()).await.unwrap();
                socket.flush().await.unwrap();
                sent.send(&cx, ()).unwrap();
                closed(socket).await;
            };
            let application = async {
                let mut pending = Box::pin(client.credential_with_cancellation(&cx, &cancellation));
                let mut ready = std::pin::pin!(received.recv(&cx));
                poll_fn(|task| {
                    assert!(pending.as_mut().poll(task).is_pending());
                    ready.as_mut().poll(task)
                })
                .await
                .unwrap();
                cancellation.cancel();
                assert!(matches!(
                    pending.await,
                    Err(Error::Discovery(OAuthDiscoveryError::Cancelled))
                ));
            };
            pair(server, application).await;
            assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
            assert_eq!(peer.rpcs.load(Ordering::SeqCst), 0);
            peer.quiet();
            // A fresh explicit caller can acquire, but cannot observe the
            // cancelled candidate as cached generation one and skip its POST.
            let ((), admitted) = pair(reply(&peer, post, &body), client.credential(&cx)).await;
            assert_eq!(admitted.unwrap().generation(), 1);
            assert_eq!(peer.grants.load(Ordering::SeqCst), 2);
            core_succeeds(&peer, &cx, &client, "admitted-access").await;
            assert!(cx.checkpoint().is_ok());
            client.close();
        });
    }
}
