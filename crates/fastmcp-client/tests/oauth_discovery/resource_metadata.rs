//! Constructed protected-resource metadata fallbacks over the production TLS
//! transport. Included in oauth_discovery so it reuses that target's exact
//! certificate, peer and browser fixture rather than a second parser or mock.

use super::*;
use fastmcp_client::http_auth::discovery::{
    ResourceMetadataCause, ResourceMetadataFailureClass, ResourceMetadataLocation,
    MAX_OAUTH_METADATA_BYTES,
};
use fastmcp_client::http_auth::discovery::challenge::{
    ChallengedOAuthDiscovery, OAuthChallengeError, ResourceMetadataChallenge,
};
use fastmcp_client::http_auth::discovery::client_credentials::ClientCredentialsPlan;
use fastmcp_client::http_auth::oauth::OAuthClientConfiguration;

const PATH: &str = "/.well-known/oauth-protected-resource/mcp";
const ROOT_PATH: &str = "/.well-known/oauth-protected-resource";
const ISSUER_PATH: &str = "/.well-known/oauth-authorization-server/tenant";

fn expected(peer: &Peer, resource: &str) -> OAuthClientConfiguration {
    OAuthClientConfiguration::from_trusted_endpoints(
        peer.issuer(), url(&format!("{}/authorize", peer.origin())),
        url(&format!("{}/token", peer.origin())), url(resource),
        "registered-native-client", vec!["tools:read".to_owned()],
    ).unwrap().with_extra_root_certificate(root()).unwrap()
}

async fn root_and_issuer(peer: &Peer) {
    peer.serve(ROOT_PATH, 200, &peer.resource_document().to_string()).await;
    peer.serve(ISSUER_PATH, 200, &peer.issuer_document().to_string()).await;
}

async fn assert_closed(mut socket: TlsStream<TcpStream>) {
    let mut byte = [0];
    assert!(!matches!(socket.read(&mut byte).await, Ok(n) if n > 0),
        "retired candidate must release its owned connection");
}

#[test]
fn root_recovers_every_http_refusal_without_following_its_location() {
    for status in [204, 302, 307, 401, 403, 404, 410, 429, 500, 503] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let plan = peer.plan(true, true);
            let server = async {
                peer.serve(PATH, status, "").await;
                root_and_issuer(&peer).await;
            };
            let ((), result) = pair(server, plan.discover(&cx)).await;
            assert_eq!(result.unwrap(), expected(&peer, &peer.resource()));
            assert_eq!(*peer.paths.lock().unwrap(), [PATH, ROOT_PATH, ISSUER_PATH]);
            peer.assert_no_extra_connections();
        });
    }
}

#[test]
fn root_recovery_requires_full_metadata_admission_not_just_http_success() {
    for dimension in 0..8 {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let plan = peer.plan(true, true);
            let mut document = peer.resource_document();
            match dimension {
                0 => document["resource"] = json!(format!("{}/different", peer.origin())),
                1 => document["authorization_servers"] = json!(["https://127.0.0.1:9/forbidden"]),
                2 => document["scopes_supported"] = json!(["admin"]),
                3 => document["bearer_methods_supported"] = json!(["body"]),
                4 => document["signed_metadata"] = json!("must-not-verify-this.jwt"),
                5 => document["authorization_servers"] = Value::Null,
                _ => {},
            }
            let mut raw = document.to_string();
            if dimension == 6 { raw = "{broken-json".to_owned(); }
            if dimension == 7 {
                raw.pop();
                raw.push_str(",\"res\\u006furce\":\"https://duplicate.invalid\"}");
            }
            let server = async {
                peer.serve(PATH, 200, &raw).await;
                root_and_issuer(&peer).await;
            };
            let ((), result) = pair(server, plan.discover(&cx)).await;
            assert_eq!(result.unwrap(), expected(&peer, &peer.resource()));
            assert_eq!(*peer.paths.lock().unwrap(), [PATH, ROOT_PATH, ISSUER_PATH]);
            peer.assert_no_extra_connections();
        });
    }
}

#[test]
fn malformed_representation_does_not_erase_the_reserved_root_attempt() {
    for extra in [
        "Content-Type: text/html\r\n",
        "Content-Type: application/json\r\nContent-Encoding: gzip\r\n",
        "Content-Type: application/json\r\nContent-Type: application/json\r\n",
    ] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let plan = peer.plan(true, true);
            let server = async {
                let (mut socket, _) = peer.request("GET", PATH).await;
                socket.write_all(format!("HTTP/1.1 200 OK\r\n{extra}Content-Length: 2\r\nConnection: close\r\n\r\n{{}}").as_bytes()).await.unwrap();
                // A strict native codec may refuse duplicate media headers at
                // head admission; either way it must retire this connection.
                let _ = socket.shutdown().await;
                drop(socket);
                root_and_issuer(&peer).await;
            };
            let ((), result) = pair(server, plan.discover(&cx)).await;
            assert_eq!(result.unwrap(), expected(&peer, &peer.resource()));
            assert_eq!(*peer.paths.lock().unwrap(), [PATH, ROOT_PATH, ISSUER_PATH]);
            peer.assert_no_extra_connections();
        });
    }
}

#[test]
fn stalled_first_head_or_body_cannot_starve_root_or_issuer() {
    for body_started in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let plan = peer.plan(true, true).with_timeout(Duration::from_secs(4)).unwrap();
            let server = async {
                let (mut socket, _) = peer.request("GET", PATH).await;
                if body_started {
                    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1024\r\n\r\n{").await.unwrap();
                    socket.flush().await.unwrap();
                }
                // This blocks until the candidate deadline drops its client.
                // Only then is the root served: no fake timer drives the proof.
                assert_closed(socket).await;
                root_and_issuer(&peer).await;
            };
            let ((), result) = pair(server, plan.discover(&cx)).await;
            assert_eq!(result.unwrap(), expected(&peer, &peer.resource()));
            assert!(cx.checkpoint().is_ok());
            assert_eq!(*peer.paths.lock().unwrap(), [PATH, ROOT_PATH, ISSUER_PATH]);
            peer.assert_no_extra_connections();
        });
    }
}

#[test]
fn lost_first_connection_does_not_retry_its_url_or_skip_root() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let plan = peer.plan(true, true);
        let server = async {
            let (socket, _) = peer.request("GET", PATH).await;
            drop(socket);
            root_and_issuer(&peer).await;
        };
        let ((), result) = pair(server, plan.discover(&cx)).await;
        assert_eq!(result.unwrap(), expected(&peer, &peer.resource()));
        assert_eq!(*peer.paths.lock().unwrap(), [PATH, ROOT_PATH, ISSUER_PATH]);
        peer.assert_no_extra_connections();
    });
}

#[test]
fn each_resource_candidate_keeps_an_independent_full_body_allowance() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let plan = peer.plan(true, true);
        let invalid = " ".repeat(MAX_OAUTH_METADATA_BYTES);
        let mut valid = peer.resource_document().to_string();
        valid.push_str(&" ".repeat(MAX_OAUTH_METADATA_BYTES - valid.len()));
        let server = async {
            peer.serve(PATH, 200, &invalid).await;
            peer.serve(ROOT_PATH, 200, &valid).await;
            peer.serve(ISSUER_PATH, 200, &peer.issuer_document().to_string()).await;
        };
        let ((), result) = pair(server, plan.discover(&cx)).await;
        assert_eq!(result.unwrap(), expected(&peer, &peer.resource()));
        assert_eq!(*peer.paths.lock().unwrap(), [PATH, ROOT_PATH, ISSUER_PATH]);
        peer.assert_no_extra_connections();
    });
}

#[test]
fn an_oversized_first_body_is_retired_before_the_root_is_read() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let plan = peer.plan(true, true);
        let server = async {
            let (mut socket, _) = peer.request("GET", PATH).await;
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", MAX_OAUTH_METADATA_BYTES + 1).as_bytes()).await.unwrap();
            socket.flush().await.unwrap();
            assert_closed(socket).await;
            root_and_issuer(&peer).await;
        };
        let ((), result) = pair(server, plan.discover(&cx)).await;
        assert_eq!(result.unwrap(), expected(&peer, &peer.resource()));
        assert_eq!(*peer.paths.lock().unwrap(), [PATH, ROOT_PATH, ISSUER_PATH]);
        peer.assert_no_extra_connections();
    });
}

#[test]
fn both_failures_remain_ordered_redacted_and_cannot_invoke_login() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let plan = peer.plan(true, true);
        let mut invalid = peer.resource_document();
        invalid["resource"] = json!("https://tenant-secret.invalid/not-this-resource");
        let launches = AtomicUsize::new(0);
        let server = async {
            peer.serve(PATH, 200, &invalid.to_string()).await;
            peer.serve(ROOT_PATH, 503, "body-secret-canary").await;
        };
        let application = plan.authorize_managed(&cx, OAuthSessionPolicy::default(), |_| {
            launches.fetch_add(1, Ordering::SeqCst);
            async { Err(OAuthError::BrowserLaunchFailed) }
        });
        let ((), result) = Box::pin(pair(server, application)).await;
        let error = result.err().unwrap();
        let diagnostics = format!("{error:?} {error}");
        assert!(!diagnostics.contains("secret") && !diagnostics.contains("https://"));
        let OAuthDiscoveryError::ResourceMetadataExhausted(failure) = error else { panic!("ordered aggregate expected") };
        assert_eq!(failure.classification(), ResourceMetadataFailureClass::TrustOrIntegrity);
        assert_eq!(failure.attempts().iter().map(|attempt| (attempt.location(), attempt.cause())).collect::<Vec<_>>(), [
            (ResourceMetadataLocation::PathSpecific, ResourceMetadataCause::ResourceMismatch),
            (ResourceMetadataLocation::OriginRoot, ResourceMetadataCause::HttpStatus(503)),
        ]);
        assert_eq!(launches.load(Ordering::SeqCst), 0);
        assert_eq!(*peer.paths.lock().unwrap(), [PATH, ROOT_PATH]);
        peer.assert_no_extra_connections();
    });
}

#[test]
fn two_stalled_candidates_settle_without_misreporting_caller_cancellation() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let plan = peer.plan(true, true).with_timeout(Duration::from_secs(4)).unwrap();
        let server = async {
            for path in [PATH, ROOT_PATH] {
                let (socket, _) = peer.request("GET", path).await;
                assert_closed(socket).await;
            }
        };
        let ((), result) = pair(server, plan.discover(&cx)).await;
        let OAuthDiscoveryError::ResourceMetadataExhausted(failure) = result.unwrap_err() else { panic!("aggregate expected") };
        assert_eq!(failure.classification(), ResourceMetadataFailureClass::Transport);
        assert_eq!(failure.attempts().iter().map(|attempt| attempt.cause()).collect::<Vec<_>>(),
            [ResourceMetadataCause::CandidateDeadline, ResourceMetadataCause::CandidateDeadline]);
        assert!(cx.checkpoint().is_ok());
        assert_eq!(*peer.paths.lock().unwrap(), [PATH, ROOT_PATH]);
        peer.assert_no_extra_connections();
    });
}

#[test]
fn root_resource_fetches_one_exact_candidate_on_success_or_failure() {
    for valid in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let resource = format!("{}/", peer.origin());
            let issuer = TrustedOAuthIssuer::new(peer.issuer()).unwrap().with_root_certificate(root()).unwrap();
            let plan = OAuthDiscoveryPlan::new(url(&resource), vec![issuer], "registered-native-client", vec!["tools:read".to_owned()])
                .unwrap().with_resource_root_certificate(root()).unwrap();
            let mut prm = peer.resource_document();
            prm["resource"] = json!(resource);
            let mut issuer = peer.issuer_document();
            issuer["protected_resources"] = json!([resource]);
            let server = async {
                peer.serve(ROOT_PATH, if valid { 200 } else { 404 }, &if valid { prm.to_string() } else { String::new() }).await;
                if valid { peer.serve(ISSUER_PATH, 200, &issuer.to_string()).await; }
            };
            let ((), result) = pair(server, plan.discover(&cx)).await;
            if valid {
                assert_eq!(result.unwrap(), expected(&peer, &resource));
                assert_eq!(*peer.paths.lock().unwrap(), [ROOT_PATH, ISSUER_PATH]);
            } else {
                let OAuthDiscoveryError::ResourceMetadataExhausted(failure) = result.unwrap_err() else { panic!("aggregate expected") };
                assert_eq!(failure.attempts().len(), 1);
                assert_eq!(failure.attempts()[0].location(), ResourceMetadataLocation::OriginRoot);
                assert_eq!(failure.attempts()[0].cause(), ResourceMetadataCause::NotFound);
                assert_eq!(*peer.paths.lock().unwrap(), [ROOT_PATH]);
            }
            peer.assert_no_extra_connections();
        });
    }
}

#[test]
fn explicit_hint_failure_cannot_use_constructed_fallback_but_no_hint_can() {
    for explicit in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let field = if explicit {
                format!("Bearer resource_metadata=\"{}/hint\"", peer.origin())
            } else { "Bearer realm=fixture".to_owned() };
            let challenge = ResourceMetadataChallenge::from_response(url(&peer.resource()), 401,
                &[("WWW-Authenticate".to_owned(), field)]).unwrap();
            let plan = ChallengedOAuthDiscovery::new(peer.plan(true, true), challenge).unwrap();
            let server = async {
                peer.serve(if explicit { "/hint" } else { PATH }, 503, "").await;
                if !explicit { root_and_issuer(&peer).await; }
            };
            let ((), result) = Box::pin(pair(server, plan.discover(&cx))).await;
            if explicit {
                assert!(matches!(result, Err(OAuthChallengeError::Discovery(OAuthDiscoveryError::HttpStatus { status: 503 }))));
                assert_eq!(*peer.paths.lock().unwrap(), ["/hint"]);
            } else {
                assert_eq!(result.unwrap(), expected(&peer, &peer.resource()));
                assert_eq!(*peer.paths.lock().unwrap(), [PATH, ROOT_PATH, ISSUER_PATH]);
            }
            peer.assert_no_extra_connections();
        });
    }
}

#[test]
fn registration_reaches_one_write_after_root_metadata_wins() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let owner = peer.registration();
        let document = peer.registration_document(&format!("{}/register", peer.origin()));
        let server = async {
            peer.serve(PATH, 404, "").await;
            peer.serve(ROOT_PATH, 200, &peer.resource_document().to_string()).await;
            peer.serve(ISSUER_PATH, 200, &document.to_string()).await;
            let (mut socket, request) = peer.request("POST", "/register").await;
            reply(&mut socket, 201, &registration_reply(&request, "root-discovered-client").to_string()).await;
        };
        let ((), registered) = pair(server, owner.register(&cx)).await;
        assert_eq!(registered.unwrap().client_id(), "root-discovered-client");
        assert_eq!(*peer.paths.lock().unwrap(), [PATH, ROOT_PATH, ISSUER_PATH, "/register"]);
        peer.assert_no_extra_connections();
    });
}

#[test]
fn machine_authentication_uses_root_metadata_without_a_browser_or_secret_on_get() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let issuer = TrustedOAuthIssuer::new(peer.issuer()).unwrap().with_root_certificate(root()).unwrap();
        let plan = ClientCredentialsPlan::new(url(&peer.resource()), issuer, "machine", "secret", vec!["tools:read".to_owned()])
            .unwrap().with_resource_root_certificate(root()).unwrap();
        let server = async {
            peer.serve(PATH, 500, "").await;
            peer.serve(ROOT_PATH, 200, &peer.resource_document().to_string()).await;
            peer.serve(ISSUER_PATH, 200, &json!({
                "issuer":peer.issuer(), "token_endpoint":format!("{}/token", peer.origin()),
                "grant_types_supported":["client_credentials"],
                "token_endpoint_auth_methods_supported":["client_secret_basic"],
            }).to_string()).await;
            let (mut socket, request) = peer.request_with_authorization("POST", "/token", Some("Basic bWFjaGluZTpzZWNyZXQ=")).await;
            let fields = form(std::str::from_utf8(&request).unwrap());
            assert_eq!(fields["grant_type"], "client_credentials");
            assert_eq!(fields["resource"], peer.resource());
            assert!(!fields.contains_key("client_secret"));
            reply(&mut socket, 200, r#"{"access_token":"root-service-token","token_type":"Bearer","expires_in":300,"scope":"tools:read"}"#).await;
        };
        let application = async {
            let client = plan.discover(&cx).await.unwrap();
            let snapshot = client.credential(&cx).await.unwrap();
            assert_eq!(snapshot.generation(), 1);
            assert_eq!(snapshot.credential().authorization_for_target(client.resource()), Some("Bearer root-service-token".to_owned()));
            client.close();
        };
        Box::pin(pair(server, application)).await;
        assert_eq!(*peer.paths.lock().unwrap(), [PATH, ROOT_PATH, ISSUER_PATH, "/token"]);
        peer.assert_no_extra_connections();
    });
}

#[test]
fn dropping_either_resource_candidate_releases_it_without_another_get() {
    for on_root in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let plan = peer.plan(true, true);
            let (sender, mut receiver) = oneshot::channel::<()>();
            let server = async {
                if on_root { peer.serve(PATH, 404, "").await; }
                let (socket, _) = peer.request("GET", if on_root { ROOT_PATH } else { PATH }).await;
                sender.send(&cx, ()).unwrap();
                assert_closed(socket).await;
            };
            let application = async {
                let mut discovery = Box::pin(plan.discover(&cx));
                let mut started = std::pin::pin!(receiver.recv(&cx));
                poll_fn(|task| {
                    assert!(discovery.as_mut().poll(task).is_pending());
                    started.as_mut().poll(task)
                }).await.unwrap();
                drop(discovery);
                assert!(cx.checkpoint().is_ok());
            };
            pair(server, application).await;
            assert_eq!(peer.paths.lock().unwrap().len(), if on_root { 2 } else { 1 });
            peer.assert_no_extra_connections();
        });
    }
}

#[test]
fn caller_cancellation_prevents_reserved_root_and_retains_attempted_cause() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let plan = peer.plan(true, true);
        let (sender, mut receiver) = oneshot::channel::<()>();
        let server = async {
            let (socket, _) = peer.request("GET", PATH).await;
            sender.send(&cx, ()).unwrap();
            assert_closed(socket).await;
        };
        let application = async {
            let mut discovery = Box::pin(plan.discover(&cx));
            let mut started = std::pin::pin!(receiver.recv(&cx));
            poll_fn(|task| {
                assert!(discovery.as_mut().poll(task).is_pending());
                started.as_mut().poll(task)
            }).await.unwrap();
            cx.cancel_with(asupersync::CancelKind::User, Some("stop resource discovery"));
            let OAuthDiscoveryError::ResourceMetadataExhausted(failure) = discovery.await.unwrap_err() else { panic!("aggregate expected") };
            assert_eq!(failure.classification(), ResourceMetadataFailureClass::Cancelled);
            assert_eq!(failure.attempts().len(), 1);
            assert_eq!(failure.attempts()[0].cause(), ResourceMetadataCause::Cancelled);
        };
        pair(server, application).await;
        assert_eq!(*peer.paths.lock().unwrap(), [PATH]);
        peer.assert_no_extra_connections();
    });
}
