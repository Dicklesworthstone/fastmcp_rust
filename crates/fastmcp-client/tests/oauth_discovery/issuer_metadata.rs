//! Same-issuer fallback through the public OAuth APIs and real loopback TLS.
//! Included by oauth_discovery to share its existing peer and certificate fixture.

use super::*;
use fastmcp_client::http_auth::discovery::issuer::{
    IssuerMetadataCause as Cause, IssuerMetadataFailureClass as Class,
    IssuerMetadataLocation as Location,
};
use fastmcp_client::http_auth::discovery::challenge::{ChallengedOAuthDiscovery, ResourceMetadataChallenge};
use fastmcp_client::http_auth::discovery::client_credentials::ClientCredentialsPlan;
use fastmcp_client::http_auth::oauth::OAuthClientConfiguration;
use fastmcp_client::http_auth::discovery::MAX_OAUTH_METADATA_BYTES;

const PRM: &str = "/.well-known/oauth-protected-resource/mcp";
const A: &str = "/.well-known/oauth-authorization-server/tenant";
const B: &str = "/.well-known/openid-configuration/tenant";
const C: &str = "/tenant/.well-known/openid-configuration";

fn expected(peer: &Peer) -> OAuthClientConfiguration {
    OAuthClientConfiguration::from_trusted_endpoints(peer.issuer(),
        url(&format!("{}/authorize", peer.origin())), url(&format!("{}/token", peer.origin())),
        url(&peer.resource()), "registered-native-client", vec!["tools:read".to_owned()],
    ).unwrap().with_extra_root_certificate(root()).unwrap()
}
async fn closed(mut socket: TlsStream<TcpStream>) {
    let mut byte = [0];
    assert!(!matches!(socket.read(&mut byte).await, Ok(n) if n > 0), "retired metadata connection must be released");
}

#[test]
fn second_issuer_location_recovers_http_failures_without_redirect_or_url_retry() {
    for status in [204, 302, 307, 401, 403, 404, 410, 429, 500, 503] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let plan = peer.plan(true, true);
            let server = async {
                peer.serve(PRM, 200, &peer.resource_document().to_string()).await;
                peer.serve(A, status, "").await;
                peer.serve(B, 200, &peer.issuer_document().to_string()).await;
            };
            let ((), result) = pair(server, plan.discover(&cx)).await;
            assert_eq!(result.unwrap(), expected(&peer));
            assert_eq!(*peer.paths.lock().unwrap(), [PRM, A, B]);
            peer.assert_no_extra_connections();
        });
    }
}

#[test]
fn last_issuer_location_wins_after_mismatched_identity_and_malformed_json() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let plan = peer.plan(true, true);
        let mut foreign = peer.issuer_document();
        foreign["issuer"] = json!(format!("{}/other", peer.origin()));
        foreign["token_endpoint"] = json!("https://127.0.0.1:9/must-not-use");
        let server = async {
            peer.serve(PRM, 200, &peer.resource_document().to_string()).await;
            peer.serve(A, 200, &foreign.to_string()).await;
            peer.serve(B, 200, "{broken").await;
            peer.serve(C, 200, &peer.issuer_document().to_string()).await;
        };
        let ((), result) = pair(server, plan.discover(&cx)).await;
        assert_eq!(result.unwrap(), expected(&peer));
        assert_eq!(*peer.paths.lock().unwrap(), [PRM, A, B, C]);
        peer.assert_no_extra_connections();
    });
}

#[test]
fn native_candidate_election_checks_the_entire_unchanged_host_flow() {
    for dimension in 0..8 {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let plan = peer.plan(true, true);
            let mut invalid = peer.issuer_document();
            match dimension {
                0 => invalid["code_challenge_methods_supported"] = json!(["plain"]),
                1 => invalid["token_endpoint"] = json!("https://127.0.0.1:9/foreign"),
                2 => invalid["scopes_supported"] = json!(["admin"]),
                3 => invalid["authorization_response_iss_parameter_supported"] = json!(false),
                4 => invalid["token_endpoint_auth_methods_supported"] = json!(["client_secret_basic"]),
                5 => invalid["issuer"] = json!(format!("{}/tenant?bad", peer.origin())),
                6 => { invalid.as_object_mut().unwrap().remove("authorization_endpoint"); },
                _ => {},
            }
            let mut body = invalid.to_string();
            if dimension == 7 { body.pop(); body.push_str(",\"iss\\u0075er\":\"https://duplicate.invalid\"}"); }
            let server = async {
                peer.serve(PRM, 200, &peer.resource_document().to_string()).await;
                peer.serve(A, 200, &body).await;
                peer.serve(B, 200, &peer.issuer_document().to_string()).await;
            };
            let ((), result) = pair(server, plan.discover(&cx)).await;
            assert_eq!(result.unwrap(), expected(&peer));
            assert_eq!(*peer.paths.lock().unwrap(), [PRM, A, B]);
            peer.assert_no_extra_connections();
        });
    }
}

#[test]
fn stalled_first_and_second_issuer_candidates_leave_a_live_third_attempt() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let plan = peer.plan(true, true).with_timeout(Duration::from_secs(6)).unwrap();
        let server = async {
            peer.serve(PRM, 200, &peer.resource_document().to_string()).await;
            let (socket, _) = peer.request("GET", A).await;
            closed(socket).await;
            let (mut socket, _) = peer.request("GET", B).await;
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1024\r\n\r\n{").await.unwrap();
            socket.flush().await.unwrap();
            closed(socket).await;
            peer.serve(C, 200, &peer.issuer_document().to_string()).await;
        };
        let ((), result) = pair(server, plan.discover(&cx)).await;
        assert_eq!(result.unwrap(), expected(&peer));
        assert!(cx.checkpoint().is_ok());
        assert_eq!(*peer.paths.lock().unwrap(), [PRM, A, B, C]);
        peer.assert_no_extra_connections();
    });
}

#[test]
fn oversized_issuer_head_and_lost_connection_do_not_consume_the_next_budget() {
    for oversized in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let plan = peer.plan(true, true);
            let mut valid = peer.issuer_document().to_string();
            valid.push_str(&" ".repeat(MAX_OAUTH_METADATA_BYTES - valid.len()));
            let server = async {
                peer.serve(PRM, 200, &peer.resource_document().to_string()).await;
                let (mut socket, _) = peer.request("GET", A).await;
                if oversized {
                    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", MAX_OAUTH_METADATA_BYTES + 1).as_bytes()).await.unwrap();
                    socket.flush().await.unwrap();
                    closed(socket).await;
                } else { drop(socket); }
                peer.serve(B, 200, &valid).await;
            };
            let ((), result) = pair(server, plan.discover(&cx)).await;
            assert_eq!(result.unwrap(), expected(&peer));
            assert_eq!(*peer.paths.lock().unwrap(), [PRM, A, B]);
            peer.assert_no_extra_connections();
        });
    }
}

#[test]
fn root_issuer_has_two_candidates_and_keeps_its_exact_trailing_slash_identity() {
    for trailing in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let identifier = format!("{}{}", peer.origin(), if trailing { "/" } else { "" });
            let plan = OAuthDiscoveryPlan::new(url(&peer.resource()),
                vec![TrustedOAuthIssuer::new(&identifier).unwrap().with_root_certificate(root()).unwrap()],
                "registered-native-client", vec!["tools:read".to_owned()],
            ).unwrap().with_resource_root_certificate(root()).unwrap();
            let mut prm = peer.resource_document(); prm["authorization_servers"] = json!([identifier]);
            let mut metadata = peer.issuer_document(); metadata["issuer"] = json!(identifier);
            let server = async {
                peer.serve(PRM, 200, &prm.to_string()).await;
                peer.serve("/.well-known/oauth-authorization-server", 503, "").await;
                peer.serve("/.well-known/openid-configuration", 200, &metadata.to_string()).await;
            };
            let ((), result) = pair(server, plan.discover(&cx)).await;
            let expected = OAuthClientConfiguration::from_trusted_endpoints(identifier,
                url(&format!("{}/authorize", peer.origin())), url(&format!("{}/token", peer.origin())),
                url(&peer.resource()), "registered-native-client", vec!["tools:read".to_owned()],
            ).unwrap().with_extra_root_certificate(root()).unwrap();
            assert_eq!(result.unwrap(), expected);
            assert_eq!(*peer.paths.lock().unwrap(), [PRM, "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"]);
            peer.assert_no_extra_connections();
        });
    }
}

#[test]
fn exhausted_issuer_sequence_retains_all_causes_and_never_selects_another_issuer() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let other = Peer::new().await;
        let plan = OAuthDiscoveryPlan::new(url(&peer.resource()), vec![
            TrustedOAuthIssuer::new(peer.issuer()).unwrap().with_root_certificate(root()).unwrap(),
            TrustedOAuthIssuer::new(other.issuer()).unwrap().with_root_certificate(root()).unwrap(),
        ], "registered-native-client", vec!["tools:read".to_owned()]).unwrap().with_resource_root_certificate(root()).unwrap();
        let mut prm = peer.resource_document(); prm["authorization_servers"] = json!([other.issuer(), peer.issuer()]);
        let mut foreign = peer.issuer_document(); foreign["issuer"] = json!(other.issuer());
        let launched = AtomicUsize::new(0);
        let server = async {
            peer.serve(PRM, 200, &prm.to_string()).await;
            peer.serve(A, 200, &foreign.to_string()).await;
            peer.serve(B, 503, "secret-error-canary").await;
            peer.serve(C, 404, "").await;
        };
        let ((), result) = pair(server, plan.authorize_managed(&cx, OAuthSessionPolicy::default(), |_| {
            launched.fetch_add(1, Ordering::SeqCst); async { Err(OAuthError::BrowserLaunchFailed) }
        })).await;
        let error = result.err().unwrap();
        assert!(!format!("{error:?} {error}").contains("secret-error-canary"));
        let OAuthDiscoveryError::IssuerMetadataExhausted(failure) = error else { panic!("ordered aggregate expected") };
        assert_eq!(failure.classification(), Class::TrustOrIntegrity);
        assert_eq!(failure.attempts().iter().map(|attempt| (attempt.location(), attempt.cause())).collect::<Vec<_>>(), [
            (Location::OAuthAuthorizationServer, Cause::IssuerMismatch),
            (Location::OpenIdInserted, Cause::HttpStatus(503)),
            (Location::OpenIdAppended, Cause::NotFound),
        ]);
        assert_eq!(launched.load(Ordering::SeqCst), 0);
        assert_eq!(*peer.paths.lock().unwrap(), [PRM, A, B, C]);
        assert!(other.paths.lock().unwrap().is_empty());
        peer.assert_no_extra_connections(); other.assert_no_extra_connections();
    });
}

#[test]
fn explicit_resource_hint_uses_the_same_issuer_resolver_before_real_pkce_login() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let challenge = ResourceMetadataChallenge::from_response(url(&peer.resource()), 401,
            &[("WWW-Authenticate".to_owned(), format!("Bearer resource_metadata=\"{}/hint\"", peer.origin()))]).unwrap();
        let plan = ChallengedOAuthDiscovery::new(peer.plan(true, true), challenge).unwrap();
        let issuer = peer.issuer(); let resource = peer.resource();
        let server = async {
            peer.serve("/hint", 200, &peer.resource_document().to_string()).await;
            peer.serve(A, 500, "").await;
            peer.serve(B, 200, &peer.issuer_document().to_string()).await;
            let (mut socket, body) = peer.request("POST", "/token").await;
            let form = form(std::str::from_utf8(&body).unwrap());
            assert_eq!(form["grant_type"], "authorization_code");
            assert_eq!(form["client_id"], "registered-native-client");
            assert_eq!(form["resource"], resource);
            assert_eq!(form["code_verifier"].len(), 64);
            reply(&mut socket, 200, r#"{"access_token":"fallback-access","token_type":"Bearer","expires_in":300,"scope":"tools:read"}"#).await;
        };
        let application = async {
            let session = plan.authorize_managed(&cx, OAuthSessionPolicy::default(), |authorization| callback(authorization, &issuer, &resource)).await.unwrap();
            assert_eq!(session.credential(&cx).await.unwrap().credential().authorization_for_target(&url(&resource)), Some("Bearer fallback-access".to_owned()));
            session.close();
        };
        pair(server, application).await;
        assert_eq!(*peer.paths.lock().unwrap(), ["/hint", A, B, "/token"]);
        peer.assert_no_extra_connections();
    });
}

#[test]
fn registration_recovers_issuer_transport_failure_then_writes_only_once() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let owner = peer.registration();
        let document = peer.registration_document(&format!("{}/register", peer.origin()));
        let server = async {
            peer.serve(PRM, 200, &peer.resource_document().to_string()).await;
            let (socket, _) = peer.request("GET", A).await; drop(socket);
            peer.serve(B, 200, &document.to_string()).await;
            let (mut socket, body) = peer.request("POST", "/register").await;
            reply(&mut socket, 201, &registration_reply(&body, "recovered-native").to_string()).await;
        };
        let ((), result) = pair(server, owner.register(&cx)).await;
        assert_eq!(result.unwrap().client_id(), "recovered-native");
        assert_eq!(*peer.paths.lock().unwrap(), [PRM, A, B, "/register"]);
        peer.assert_no_extra_connections();
    });
}

#[test]
fn machine_registration_recovers_same_issuer_metadata_without_browser_fields() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let trusted = TrustedOAuthIssuer::new(peer.issuer()).unwrap().with_root_certificate(root()).unwrap();
        let plan = ClientCredentialsPlan::new(url(&peer.resource()), trusted, "machine", "secret", vec!["tools:read".to_owned()]).unwrap()
            .with_resource_root_certificate(root()).unwrap();
        let document = json!({"issuer":peer.issuer(),"token_endpoint":format!("{}/token",peer.origin()),
            "grant_types_supported":["client_credentials"],"token_endpoint_auth_methods_supported":["client_secret_basic"]});
        let server = async {
            peer.serve(PRM, 200, &peer.resource_document().to_string()).await;
            peer.serve(A, 503, "").await;
            peer.serve(B, 200, &document.to_string()).await;
            let (mut socket, body) = peer.request_with_authorization("POST", "/token", Some("Basic bWFjaGluZTpzZWNyZXQ=")).await;
            let form = form(std::str::from_utf8(&body).unwrap());
            assert_eq!(form["grant_type"], "client_credentials");
            assert_eq!(form["resource"], peer.resource());
            reply(&mut socket, 200, r#"{"access_token":"machine-fallback","token_type":"Bearer","expires_in":300,"scope":"tools:read"}"#).await;
        };
        let application = async {
            let client = plan.discover(&cx).await.unwrap();
            assert_eq!(client.credential(&cx).await.unwrap().credential().authorization_for_target(&url(&peer.resource())), Some("Bearer machine-fallback".to_owned()));
            client.close();
        };
        pair(server, application).await;
        assert_eq!(*peer.paths.lock().unwrap(), [PRM, A, B, "/token"]);
        peer.assert_no_extra_connections();
    });
}

#[test]
fn cancelled_or_abandoned_issuer_fetch_does_not_start_another_candidate() {
    for cancel in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let peer = Peer::new().await;
            let plan = peer.plan(true, true);
            let (sent, mut received) = oneshot::channel::<()>();
            let server = async {
                peer.serve(PRM, 200, &peer.resource_document().to_string()).await;
                let (socket, _) = peer.request("GET", A).await;
                sent.send(&cx, ()).unwrap(); closed(socket).await;
            };
            let application = async {
                let mut pending = Box::pin(plan.discover(&cx));
                let mut ready = std::pin::pin!(received.recv(&cx));
                poll_fn(|task| {
                    assert!(pending.as_mut().poll(task).is_pending()); ready.as_mut().poll(task)
                }).await.unwrap();
                if cancel {
                    cx.cancel_with(asupersync::CancelKind::User, Some("issuer cancellation"));
                    let OAuthDiscoveryError::IssuerMetadataExhausted(failure) = pending.await.unwrap_err() else { panic!("aggregate expected") };
                    assert_eq!(failure.classification(), Class::Cancelled);
                    assert_eq!(failure.attempts().len(), 1);
                } else { drop(pending); assert!(cx.checkpoint().is_ok()); }
            };
            pair(server, application).await;
            assert_eq!(*peer.paths.lock().unwrap(), [PRM, A]);
            peer.assert_no_extra_connections();
        });
    }
}

#[test]
fn exhausted_candidate_time_preserves_each_deadline_cause_without_cancelling_caller() {
    run(async {
        let cx = Cx::current().unwrap();
        let peer = Peer::new().await;
        let plan = peer.plan(true, true).with_timeout(Duration::from_secs(6)).unwrap();
        let server = async {
            peer.serve(PRM, 200, &peer.resource_document().to_string()).await;
            for path in [A, B, C] { let (socket, _) = peer.request("GET", path).await; closed(socket).await; }
        };
        let ((), result) = pair(server, plan.discover(&cx)).await;
        let OAuthDiscoveryError::IssuerMetadataExhausted(failure) = result.unwrap_err() else { panic!("aggregate expected") };
        assert_eq!(failure.classification(), Class::Transport);
        assert_eq!(failure.attempts().iter().map(|attempt| attempt.cause()).collect::<Vec<_>>(), [Cause::CandidateDeadline; 3]);
        assert!(cx.checkpoint().is_ok());
        assert_eq!(*peer.paths.lock().unwrap(), [PRM, A, B, C]);
        peer.assert_no_extra_connections();
    });
}
