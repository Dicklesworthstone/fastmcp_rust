use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::task::{Context, Waker};

use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use fastmcp_protocol::protocol_policy::ProtocolEra;
use fastmcp_protocol::{ClientCapabilities, CoreRequest, FinalRequestMeta, RequestId};
use serde_json::{Value, json};

use super::*;
use super::super::{decode_form, pkce_challenge};
use super::super::tests::{pair, read_token_request, test_acceptor, test_root};
use crate::http_auth::dpop::native::{DpopHttpClient, DpopHttpPolicy};
use crate::http_auth::rpc::ManagedCoreLimits;

const ISSUER: &str = "https://issuer.example";
const REDIRECT: &str = "https://client.example/oauth/callback";
const TOKEN: &str = "mF_9.B5f-4.1JqM";

fn url(value: &str) -> CanonicalHttpUrl {
    CanonicalHttpUrl::parse(value).unwrap()
}

fn config(endpoint: CanonicalHttpUrl, resource: CanonicalHttpUrl) -> OAuthClientConfiguration {
    OAuthClientConfiguration::from_trusted_endpoints(
        ISSUER,
        url("https://issuer.example/authorize"),
        endpoint,
        resource,
        "native-client",
        vec!["tools:read".to_owned(), "resources:read".to_owned()],
    )
    .unwrap()
    .with_extra_root_certificate(test_root())
    .unwrap()
}

fn run<F, Fut>(test: F)
where
    F: FnOnce(Cx) -> Fut,
    Fut: Future<Output = ()>,
{
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(create_reactor().unwrap())
        .blocking_threads(0, 0)
        .build()
        .unwrap();
    let caller = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    runtime.block_on(async {
        let host = Cx::current().unwrap();
        let test = CallerContextFuture::new(&caller, test(caller.clone()));
        asupersync::time::timeout(host.now(), Duration::from_secs(20), test)
            .await
            .expect("DPoP authorization test exceeded its external bound");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

fn callback(authorization: &CanonicalHttpUrl, issuer: &str) -> String {
    let fields = decode_form(authorization.query().unwrap()).unwrap();
    format!(
        "{}?{}",
        fields["redirect_uri"],
        encode_form(&[("code", "issued-code"), ("iss", issuer), ("state", &fields["state"])]).unwrap(),
    )
}

fn response_headers(nonce: Option<&str>) -> Vec<(String, String)> {
    let mut headers = vec![
        ("Content-Type".to_owned(), "application/json".to_owned()),
        ("Cache-Control".to_owned(), "no-store".to_owned()),
    ];
    if let Some(nonce) = nonce {
        headers.push(("DPoP-Nonce".to_owned(), nonce.to_owned()));
    }
    headers
}

fn header<'a>(headers: &'a str, wanted: &str) -> &'a str {
    let fields: Vec<_> = headers.lines().filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case(wanted))
        .map(|(_, value)| value.trim()).collect();
    assert_eq!(fields.len(), 1, "one {wanted} field must reach the peer");
    fields[0]
}

// Assertion-only decoder for proofs produced by this client. Signature
// verification is covered by the protocol DPoP tests, not claimed by decoding.
fn segment(segment: &str) -> Value {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    assert!(segment.len() <= 8192);
    let (mut bits, mut accumulator) = (0_u32, 0_u32);
    let mut bytes = Vec::new();
    for byte in segment.bytes() {
        let value = ALPHABET.iter().position(|candidate| *candidate == byte).unwrap() as u32;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    assert_eq!(accumulator, 0);
    serde_json::from_slice(&bytes).unwrap()
}

fn proof(headers: &str) -> (Value, Value) {
    let parts: Vec<_> = header(headers, "DPoP").split('.').collect();
    assert_eq!(parts.len(), 3);
    (segment(parts[0]), segment(parts[1]))
}

async fn respond<IO: AsyncWrite + Unpin>(io: &mut IO, status: u16, body: &Value, nonce: Option<&str>) {
    let body = serde_json::to_vec(body).unwrap();
    let nonce = nonce.map_or_else(String::new, |nonce| format!("DPoP-Nonce: {nonce}\r\n"));
    io.write_all(format!(
        "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\n{nonce}Connection: close\r\n\r\n", body.len(),
    ).as_bytes()).await.unwrap();
    io.write_all(&body).await.unwrap();
    io.shutdown().await.unwrap();
}

async fn read_resource_request<IO: AsyncRead + Unpin>(io: &mut IO) -> (String, Value) {
    let mut bytes = Vec::new();
    let mut buffer = [0; 2048];
    let end = loop {
        let count = io.read(&mut buffer).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 32 * 1024);
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..end]).unwrap().to_owned();
    let length: usize = header(&headers, "content-length").parse().unwrap();
    assert!(end + length <= 32 * 1024);
    while bytes.len() < end + length {
        let count = io.read(&mut buffer).await.unwrap();
        assert!(count > 0 && bytes.len() + count <= 32 * 1024);
        bytes.extend_from_slice(&buffer[..count]);
    }
    assert_eq!(bytes.len(), end + length);
    (headers, serde_json::from_slice(&bytes[end..]).unwrap())
}

#[test]
fn hosted_dpop_code_and_explicit_nonce_retry_reach_a_native_typed_resource() {
    run(|cx| async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let token_endpoint = url(&format!("https://{address}/token"));
        let resource = url(&format!("https://{address}/mcp"));
        let configuration = config(token_endpoint.clone(), resource.clone());
        let client = OAuthClient::new(configuration);
        let key = DpopKey::generate().unwrap();
        let jkt = key.thumbprint().to_owned();
        let jwk = key.public_jwk().clone();
        let browser = RefCell::new(None::<BTreeMap<String, String>>);
        let posts = Cell::new(0);
        let acceptor = test_acceptor();
        let server = async {
            let mut first_form = None;
            let mut proof_ids = Vec::new();
            for index in 0..3 {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                posts.set(posts.get() + 1);
                if index < 2 {
                    let (head, form) = read_token_request(&mut socket).await.unwrap();
                    assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
                    assert!(!head.to_ascii_lowercase().contains("authorization:"));
                    assert!(!head.to_ascii_lowercase().contains("cookie:"));
                    let (header, claims) = proof(&head);
                    assert_eq!(header["typ"], "dpop+jwt");
                    assert_eq!(header["alg"], "ES256");
                    assert_eq!(header["jwk"], jwk);
                    assert_eq!(claims["htm"], "POST");
                    assert_eq!(claims["htu"], token_endpoint.as_str());
                    assert!(claims.get("ath").is_none());
                    assert!(!proof_ids.contains(&claims["jti"]));
                    proof_ids.push(claims["jti"].clone());
                    if index == 0 {
                        assert!(claims.get("nonce").is_none());
                        assert_eq!(form["grant_type"], "authorization_code");
                        assert_eq!(form["client_id"], "native-client");
                        assert_eq!(form["code"], "issued-code");
                        assert_eq!(form["resource"], resource.as_str());
                        assert_eq!(form["redirect_uri"], REDIRECT);
                        let browser = browser.borrow();
                        let browser = browser.as_ref().unwrap();
                        assert_eq!(browser["dpop_jkt"], jkt);
                        assert_eq!(browser["code_challenge_method"], "S256");
                        assert_eq!(pkce_challenge(&form["code_verifier"]).unwrap(), browser["code_challenge"]);
                        first_form = Some(form);
                        respond(&mut socket, 400, &json!({"error":"use_dpop_nonce"}), Some("as-challenge")).await;
                    } else {
                        assert_eq!(first_form.as_ref(), Some(&form));
                        assert_eq!(claims["nonce"], "as-challenge");
                        respond(&mut socket, 200, &json!({
                            "access_token":TOKEN, "token_type":"DPoP", "expires_in":60,
                            "scope":"tools:read", "resource":resource.as_str(), "cnf":{"jkt":jkt},
                        }), Some("as-next")).await;
                    }
                } else {
                    let (head, payload) = read_resource_request(&mut socket).await;
                    assert!(head.starts_with("POST /mcp HTTP/1.1\r\n"));
                    assert_eq!(header(&head, "authorization"), format!("DPoP {TOKEN}"));
                    assert_eq!(payload["method"], "tools/list");
                    let (header, claims) = proof(&head);
                    assert_eq!(header["jwk"], jwk);
                    assert_eq!(claims["htm"], "POST");
                    assert_eq!(claims["htu"], format!("https://{address}/mcp"));
                    assert_eq!(claims["ath"], "uOFIVFsTx4vHTaLxpydd1x5W3ezhKdfS97PswG95lNo");
                    assert!(claims.get("nonce").is_none(), "AS nonce must not become RS nonce");
                    assert!(!proof_ids.contains(&claims["jti"]));
                    respond(&mut socket, 200, &json!({
                        "jsonrpc":"2.0", "id":payload["id"],
                        "result":{"resultType":"complete", "tools":[], "ttlMs":0, "cacheScope":"private"},
                    }), Some("rs-nonce")).await;
                }
            }
        };
        let application = async {
            let outcome = client.authorize_dpop_with_redirect_driver(
                &cx, key, url(REDIRECT), |authorization| {
                    let browser = &browser;
                    async move {
                        *browser.borrow_mut() = Some(decode_form(authorization.query().unwrap()).unwrap());
                        Ok(callback(&authorization, ISSUER))
                    }
                },
            ).await.unwrap();
            let DpopAuthorizationOutcome::NonceRequired(challenge) = outcome else {
                panic!("the first nonce response must return control to the caller");
            };
            assert_eq!(posts.get(), 1, "a nonce response must not auto-replay the code");
            poll_fn(|task| {
                assert!(listener.poll_accept(task).is_pending());
                Poll::Ready(())
            }).await;
            let original_deadline = challenge.exchange.bounds.deadline;
            assert!(original_deadline > cx.now());
            let grant = challenge.retry(&cx).await.unwrap();
            assert_eq!(grant.scopes(), ["tools:read"]);
            assert_eq!(grant.credential().resource(), &resource);
            let (session, credential) = grant.into_parts();
            assert_eq!(
                session.resource_request_headers("POST", &url(&format!("{}?tenant=other", resource.as_str())), &credential).unwrap_err(),
                DpopClientError::EndpointMismatch,
            );
            let policy = DpopHttpPolicy::default().with_resource_root_der(test_root().as_der().to_vec()).unwrap();
            let mut native = DpopHttpClient::new(session, policy).unwrap();
            let request = CoreRequest::decode(ProtocolEra::Modern2026, "tools/list", Some(&json!({
                "_meta":FinalRequestMeta::new(ClientCapabilities::default()),
            }))).unwrap();
            let result = native.request_core(&cx, &credential, request, RequestId::Number(7), ManagedCoreLimits::default()).await.unwrap();
            assert!(result.encode().unwrap().contains("\"tools\":[]"));
            let clone = credential.clone();
            drop(native);
            assert!(clone.is_revoked());
        };
        pair(server, application).await;
        assert_eq!(posts.get(), 3);
        assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
    });
}

#[test]
fn loopback_dpop_authorization_uses_the_same_pkce_and_key_binding() {
    run(|cx| async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let configuration = config(
            url(&format!("https://{}/token", listener.local_addr().unwrap())),
            url("https://mcp.example/mcp"),
        );
        let client = OAuthClient::new(configuration);
        let key = DpopKey::generate().unwrap();
        let jkt = key.thumbprint().to_owned();
        let launched = RefCell::new(None::<BTreeMap<String, String>>);
        let acceptor = test_acceptor();
        let server = async {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let (head, form) = read_token_request(&mut socket).await.unwrap();
            let launched = launched.borrow();
            let launched = launched.as_ref().unwrap();
            assert_eq!(launched["dpop_jkt"], jkt);
            assert_eq!(pkce_challenge(&form["code_verifier"]).unwrap(), launched["code_challenge"]);
            assert_eq!(form["redirect_uri"], launched["redirect_uri"]);
            assert_eq!(form["code"], "issued-code");
            assert!(proof(&head).1.get("ath").is_none());
            respond(&mut socket, 200, &json!({"access_token":TOKEN,"token_type":"DPoP","cnf":{"jkt":jkt}}), None).await;
        };
        let application = async {
            let outcome = client.authorize_dpop(&cx, key, |authorization| {
                let launched = &launched;
                async move {
                    let fields = decode_form(authorization.query().unwrap()).unwrap();
                    let redirect = url(&fields["redirect_uri"]);
                    let address: std::net::SocketAddr = redirect.as_str().strip_prefix("http://").unwrap().split('/').next().unwrap().parse().unwrap();
                    let callback = callback(&authorization, ISSUER);
                    let query = callback.split_once('?').unwrap().1;
                    let mut stream = TcpStream::connect(address).await.map_err(|_| OAuthError::CallbackRejected)?;
                    stream.write_all(format!("GET {CALLBACK_PATH}?{query} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes()).await.map_err(|_| OAuthError::CallbackRejected)?;
                    *launched.borrow_mut() = Some(fields);
                    Ok(())
                }
            }).await.unwrap();
            assert!(matches!(outcome, DpopAuthorizationOutcome::Authorized(_)));
        };
        pair(server, application).await;
        assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
    });
}

fn exchange(cx: &Cx, configuration: &OAuthClientConfiguration) -> CodeExchange {
    let session = DpopSession::new(DpopKey::generate().unwrap(), configuration.token_endpoint.clone(), configuration.resource.clone()).unwrap();
    CodeExchange::new(
        FlowBounds::new(cx, Duration::from_secs(60)).unwrap(), configuration, session,
        AuthorizationAttempt::new().unwrap(), REDIRECT, "issued-code".to_owned(),
        RefreshPolicy::Refuse,
    ).unwrap()
}

#[test]
fn dpop_admission_rejects_bearer_wrong_key_scope_and_foreign_credential_profiles() {
    run(|cx| async move {
        let configuration = config(url("https://issuer.example/token"), url("https://mcp.example/mcp"));
        for (member, value, expected) in [
            ("token_type", json!("Bearer"), DpopAuthorizationError::Dpop(DpopClientError::UnexpectedTokenType)),
            ("cnf", json!({"jkt":"another-key"}), DpopAuthorizationError::Dpop(DpopClientError::KeyMismatch)),
            ("scope", json!("tools:admin"), DpopAuthorizationError::OAuth(OAuthError::ScopeExpansion)),
            ("scope", Value::Null, DpopAuthorizationError::OAuth(OAuthError::InvalidTokenResponse)),
            ("resource", json!("https://mcp.example/other"), DpopAuthorizationError::OAuth(OAuthError::InvalidTokenResponse)),
            ("refresh_token", json!("uncustodied-refresh"), DpopAuthorizationError::OAuth(OAuthError::InvalidTokenResponse)),
            ("id_token", Value::Null, DpopAuthorizationError::OAuth(OAuthError::InvalidTokenResponse)),
            ("issued_token_type", json!("urn:ietf:params:oauth:token-type:access_token"), DpopAuthorizationError::OAuth(OAuthError::InvalidTokenResponse)),
            ("error_description", json!("reflected-private-value"), DpopAuthorizationError::OAuth(OAuthError::InvalidTokenResponse)),
        ] {
            let pending = exchange(&cx, &configuration);
            let mut body = json!({"access_token":TOKEN,"token_type":"DPoP","expires_in":60});
            body[member] = value;
            let error = pending.admit_response(200, &response_headers(None), &serde_json::to_vec(&body).unwrap(), Instant::now(), true).unwrap_err();
            assert_eq!(error, expected, "{member}");
            assert!(!format!("{error:?} {error}").contains(TOKEN));
        }
        let pending = exchange(&cx, &configuration);
        let result = pending.admit_response(200, &response_headers(None), br#"{"access_token":"safe","token_type":"DPoP","extension":{"nested":1,"nested":2}}"#, Instant::now(), true);
        assert_eq!(result.unwrap_err(), DpopAuthorizationError::OAuth(OAuthError::InvalidTokenResponse));
        let pending = exchange(&cx, &configuration);
        let body = json!({"access_token":TOKEN,"token_type":"DPoP","scope":"tools:read","extension":{"bounded":true}});
        let DpopAuthorizationOutcome::Authorized(grant) = pending.admit_response(200, &response_headers(None), &serde_json::to_vec(&body).unwrap(), Instant::now(), true).unwrap() else { panic!("positive control"); };
        assert_eq!(grant.scopes(), ["tools:read"]);
        assert!(grant.credential().expires_at().unwrap() > Instant::now());
    });
}

#[test]
fn only_a_single_valid_token_nonce_challenge_authorizes_explicit_retry() {
    run(|cx| async move {
        let configuration = config(url("https://issuer.example/token"), url("https://mcp.example/mcp"));
        let challenge = json!({"error":"use_dpop_nonce"});
        let mut duplicate = response_headers(Some("one"));
        duplicate.push(("dpop-nonce".to_owned(), "one".to_owned()));
        for (status, headers, body) in [
            (401, response_headers(Some("one")), challenge.clone()),
            (400, response_headers(None), challenge.clone()),
            (400, duplicate, challenge.clone()),
            (400, response_headers(Some("invalid nonce")), challenge.clone()),
            (400, response_headers(Some("one")), json!({"error":"use_dpop_nonce","access_token":TOKEN})),
            (400, response_headers(Some("one")), json!({"error":"use_dpop_nonce","error_uri":null})),
            (400, response_headers(Some("one")), json!({"error":"invalid_grant"})),
            (200, response_headers(Some("one")), challenge.clone()),
        ] {
            assert!(exchange(&cx, &configuration).admit_response(status, &headers, &serde_json::to_vec(&body).unwrap(), Instant::now(), true).is_err());
        }
        for next_nonce in ["one", "two"] {
            let pending = exchange(&cx, &configuration);
            let deadline = pending.bounds.deadline;
            let expires_at = pending.bounds.expires_at;
            let body = serde_json::to_vec(&challenge).unwrap();
            let DpopAuthorizationOutcome::NonceRequired(challenge) = pending.admit_response(400, &response_headers(Some("one")), &body, Instant::now(), true).unwrap() else { panic!("positive nonce control"); };
            assert_eq!(challenge.exchange.bounds.deadline, deadline);
            assert_eq!(challenge.exchange.bounds.expires_at, expires_at);
            assert_eq!(challenge.exchange.admit_response(400, &response_headers(Some(next_nonce)), &body, Instant::now(), false).unwrap_err(), DpopAuthorizationError::NonceRetryLimit);
        }
    });
}

#[test]
fn hosted_dpop_callback_mismatch_never_dispatches_a_token() {
    run(|cx| async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = OAuthClient::new(config(url(&format!("https://{}/token", listener.local_addr().unwrap())), url("https://mcp.example/mcp")));
        for mutation in ["issuer", "state", "route", "mixed"] {
            let result = client.authorize_dpop_with_redirect_driver(&cx, DpopKey::generate().unwrap(), url(REDIRECT), |authorization| async move {
                let value = callback(&authorization, if mutation == "issuer" { "https://foreign.example" } else { ISSUER });
                Ok(match mutation {
                    "state" => { let fields = decode_form(authorization.query().unwrap()).unwrap(); value.replace(&fields["state"], "wrong-state") },
                    "route" => value.replacen(REDIRECT, "https://client.example/other", 1),
                    "mixed" => format!("{value}&access_token=foreign"),
                    _ => value,
                })
            }).await;
            assert_eq!(result.unwrap_err(), DpopAuthorizationError::OAuth(if mutation == "issuer" { OAuthError::IssuerMismatch } else { OAuthError::CallbackRejected }));
            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
        }
    });
}

#[test]
fn nonce_continuation_cannot_reset_deadlines_or_restore_withheld_authority() {
    run(|cx| async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let configuration = config(url(&format!("https://{}/token", listener.local_addr().unwrap())), url("https://mcp.example/mcp"));
        for stop in ["deadline", "entropy", "io", "held_entropy", "held_io", "held_spawn", "held_remote", "cancel"] {
            let pending = exchange(&cx, &configuration);
            let DpopAuthorizationOutcome::NonceRequired(mut challenge) = pending.admit_response(400, &response_headers(Some("one")), br#"{"error":"use_dpop_nonce"}"#, Instant::now(), true).unwrap() else { panic!("positive nonce control"); };
            let expected = match stop {
                "deadline" => { challenge.exchange.bounds.deadline = cx.now(); OAuthError::TimedOut },
                "cancel" => { cx.set_cancel_requested(true); OAuthError::Cancelled },
                _ => OAuthError::RuntimeCapabilityUnavailable,
            };
            let result = match stop {
                "entropy" => {
                    let _restriction = Cx::push_restriction(CapSet::<true, true, false, true, true>::MASK);
                    challenge.retry(&cx).await
                }
                "io" => {
                    let _restriction = Cx::push_restriction(CapSet::<true, true, true, false, true>::MASK);
                    challenge.retry(&cx).await
                }
                "held_entropy" | "held_io" | "held_spawn" | "held_remote" => {
                    let restricted = {
                        let mask = match stop {
                            "held_entropy" => CapSet::<true, true, false, true, true>::MASK,
                            "held_io" => CapSet::<true, true, true, false, true>::MASK,
                            "held_spawn" => CapSet::<false, true, true, true, true>::MASK,
                            _ => CapSet::<true, true, true, true, false>::MASK,
                        };
                        let _restriction = Cx::push_restriction(mask);
                        Cx::current().unwrap()
                    };
                    challenge.retry(&restricted).await
                }
                _ => challenge.retry(&cx).await,
            };
            assert_eq!(result.unwrap_err(), DpopAuthorizationError::OAuth(expected), "{stop}");
            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
        }
    });
}

#[test]
fn quiet_nonce_retry_obeys_the_supplied_callers_independent_deadline_and_cancellation() {
    for stop in ["deadline", "cancel"] {
        // Request IDs are runtime-local. These independently owned callers
        // deliberately have matching IDs but different budgets/cancel signals,
        // demonstrating why an identity check cannot replace either wait.
        let runtime = RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().unwrap())
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        let supplied_runtime = RuntimeBuilder::current_thread()
            .with_reactor(create_reactor().unwrap())
            .blocking_threads(0, 0)
            .build()
            .unwrap();
        let original = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let budget = if stop == "deadline" {
            asupersync::Budget::INFINITE.with_deadline(original.now().saturating_add_nanos(2_000_000_000))
        } else {
            asupersync::Budget::INFINITE
        };
        let supplied = supplied_runtime.request_cx_with_budget(budget);
        assert_eq!(original.task_id(), supplied.task_id());
        assert_eq!(original.region_id(), supplied.region_id());
        runtime.block_on(async {
            let active = Cx::current().unwrap();
            asupersync::time::timeout(active.now(), Duration::from_secs(15), async {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let configuration = config(
                    url(&format!("https://{}/token", listener.local_addr().unwrap())),
                    url("https://mcp.example/mcp"),
                );
                let challenge = with_caller(&original, || {
                    let pending = exchange(&original, &configuration);
                    let DpopAuthorizationOutcome::NonceRequired(challenge) = pending.admit_response(
                        400, &response_headers(Some("one")), br#"{"error":"use_dpop_nonce"}"#,
                        Instant::now(), true,
                    ).unwrap() else { panic!("positive nonce control"); };
                    challenge
                });
                let acceptor = test_acceptor();
                let received = Cell::new(false);
                let server = async {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut socket = acceptor.accept(socket).await.unwrap();
                    let (head, form) = read_token_request(&mut socket).await.unwrap();
                    assert_eq!(form["code"], "issued-code");
                    assert_eq!(proof(&head).1["nonce"], "one");
                    received.set(true);
                    if stop == "cancel" {
                        supplied.set_cancel_requested(true);
                    }
                    // No response, local timer or other traffic wakes this
                    // read. The retained active timer must enforce even the
                    // supplied caller's independently owned shorter deadline.
                    let mut byte = [0];
                    assert!(matches!(socket.read(&mut byte).await, Ok(0) | Err(_)));
                };
                let application = async {
                    let error = challenge.retry(&supplied).await.unwrap_err();
                    assert!(received.get(), "the retry must have reached the quiet peer");
                    assert_eq!(error, DpopAuthorizationError::OAuth(if stop == "deadline" {
                        OAuthError::TimedOut
                    } else {
                        OAuthError::Cancelled
                    }));
                    assert!(!original.is_cancel_requested());
                };
                pair(server, application).await;
                assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
            }).await.expect("the supplied caller must interrupt a quiet nonce retry");
        });
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        assert!(supplied_runtime.shutdown_timeout(Duration::from_secs(1)));
    }
}


#[test]
fn renewable_dpop_acquisition_requires_explicit_valid_refresh_custody() {
    run(|cx| async move {
        for refresh in [
            Some(json!("refresh +/=&? one")),
            None,
            Some(Value::Null),
            Some(json!("")),
            Some(json!("refresh\nprivate")),
            Some(json!("refresh-\u{00e9}")),
            Some(json!("r".repeat(4097))),
            Some(json!(["refresh-one"])),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = url(&format!("https://{}/token", listener.local_addr().unwrap()));
            let resource = url("https://mcp.example/mcp");
            let client = OAuthClient::new(config(endpoint, resource.clone()));
            let acceptor = test_acceptor();
            let positive = refresh.as_ref() == Some(&json!("refresh +/=&? one"));
            let server = async {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                let (head, form) = read_token_request(&mut socket).await.unwrap();
                assert_eq!(form["grant_type"], "authorization_code");
                assert_eq!(form["resource"], resource.as_str());
                assert!(!head.to_ascii_lowercase().contains("authorization:"));
                assert!(proof(&head).1.get("ath").is_none());
                let mut response = json!({
                    "access_token": TOKEN, "token_type": "DPoP", "expires_in": 60,
                    "scope": "tools:read", "resource": resource.as_str(),
                });
                if let Some(refresh) = &refresh {
                    response["refresh_token"] = refresh.clone();
                }
                respond(&mut socket, 200, &response, Some("initial-as-nonce")).await;
            };
            let application = async {
                let outcome = client.authorize_renewable_dpop_with_redirect_driver(
                    &cx, DpopKey::generate().unwrap(), url(REDIRECT),
                    |authorization| async move { Ok(callback(&authorization, ISSUER)) },
                ).await;
                if positive {
                    let DpopAuthorizationOutcome::Authorized(grant) = outcome.unwrap() else {
                        panic!("valid refresh custody must accompany the DPoP grant");
                    };
                    assert!(grant.has_refresh_token());
                    assert_eq!(grant.scopes(), ["tools:read"]);
                    let (session, credential, refresh) = grant.into_renewable_parts();
                    let refresh = refresh.expect("explicit renewable acquisition retains custody");
                    assert_eq!(refresh.scopes(), ["tools:read"]);
                    assert_eq!(refresh.credential().resource(), &resource);
                    assert_eq!(format!("{refresh:?}"), "DpopRefreshToken(<redacted>)");
                    drop(refresh);
                    assert!(!credential.is_revoked(), "discarding unused refresh custody preserves access");
                    assert!(session.resource_request_headers("POST", &resource, &credential).is_ok());
                    drop(session);
                    assert!(credential.is_revoked());
                } else {
                    assert_eq!(outcome.unwrap_err(), DpopAuthorizationError::OAuth(OAuthError::InvalidTokenResponse));
                }
            };
            pair(server, application).await;
            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
        }
    });
}

#[test]
fn rotating_dpop_refresh_preserves_key_nonce_and_scope_bindings_across_generations() {
    run(|cx| async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let endpoint = url(&format!("https://{address}/token"));
        let resource = url(&format!("https://{address}/mcp"));
        let client = OAuthClient::new(config(endpoint.clone(), resource.clone()));
        let key = DpopKey::generate().unwrap();
        let jwk = key.public_jwk().clone();
        let acceptor = test_acceptor();
        let posts = Cell::new(0);
        let server = async {
            let mut ids = Vec::new();
            let mut first_refresh = None;
            for index in 0..6 {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                posts.set(posts.get() + 1);
                if index == 3 {
                    let (head, payload) = read_resource_request(&mut socket).await;
                    assert_eq!(header(&head, "authorization"), "DPoP access-two");
                    let (protected, claims) = proof(&head);
                    assert_eq!(protected["jwk"], jwk);
                    assert_eq!(claims["htu"], resource.as_str());
                    assert_eq!(claims["nonce"], "resource-before-refresh");
                    assert!(claims["ath"].is_string());
                    assert!(!ids.contains(&claims["jti"]));
                    ids.push(claims["jti"].clone());
                    respond(&mut socket, 200, &json!({
                        "jsonrpc": "2.0", "id": payload["id"],
                        "result": {"resultType": "complete", "tools": [], "ttlMs": 0, "cacheScope": "private"},
                    }), Some("resource-after-refresh")).await;
                    continue;
                }
                let (head, form) = read_token_request(&mut socket).await.unwrap();
                assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
                assert!(!head.to_ascii_lowercase().contains("authorization:"));
                assert!(!head.to_ascii_lowercase().contains("cookie:"));
                let (protected, claims) = proof(&head);
                assert_eq!(protected["jwk"], jwk);
                assert_eq!(claims["htu"], endpoint.as_str());
                assert_eq!(claims["htm"], "POST");
                assert!(claims.get("ath").is_none());
                assert!(!ids.contains(&claims["jti"]), "each attempt must sign a fresh proof");
                ids.push(claims["jti"].clone());
                assert_eq!(form["client_id"], "native-client");
                assert_eq!(form["resource"], resource.as_str());
                match index {
                    0 => {
                        assert_eq!(form["grant_type"], "authorization_code");
                        assert!(claims.get("nonce").is_none());
                        respond(&mut socket, 200, &json!({
                            "access_token": "access-one", "token_type": "DPoP", "expires_in": 60,
                            "refresh_token": "refresh +/=&? one",
                        }), Some("as-initial")).await;
                    }
                    1 | 2 => {
                        assert_eq!(form["grant_type"], "refresh_token");
                        assert_eq!(form["refresh_token"], "refresh +/=&? one");
                        assert_eq!(form["scope"], "tools:read resources:read");
                        assert_eq!(form.len(), 5, "no code, PKCE verifier or client secret on refresh");
                        if index == 1 {
                            assert_eq!(claims["nonce"], "as-initial");
                            first_refresh = Some(form);
                            respond(&mut socket, 400, &json!({"error": "use_dpop_nonce"}), Some("as-challenge")).await;
                        } else {
                            assert_eq!(first_refresh.as_ref(), Some(&form));
                            assert_eq!(claims["nonce"], "as-challenge");
                            respond(&mut socket, 200, &json!({
                                "access_token": "access-two", "token_type": "DPoP", "expires_in": 60,
                                "refresh_token": "refresh-two", "scope": "tools:read",
                            }), Some("as-rotated")).await;
                        }
                    }
                    4 => {
                        assert_eq!(form["refresh_token"], "refresh-two");
                        assert_eq!(form["scope"], "tools:read");
                        assert_eq!(claims["nonce"], "as-rotated");
                        respond(&mut socket, 200, &json!({
                            "access_token": "access-three", "token_type": "DPoP", "expires_in": 60,
                            "refresh_token": "refresh-three",
                        }), None).await;
                    }
                    5 => {
                        assert_eq!(form["refresh_token"], "refresh-three");
                        assert_eq!(form["scope"], "tools:read", "omission must not restore original broader scopes");
                        assert_eq!(claims["nonce"], "as-rotated");
                        respond(&mut socket, 200, &json!({
                            "access_token": "access-four", "token_type": "DPoP", "expires_in": 60,
                            "refresh_token": "refresh-four", "scope": "tools:read resources:read",
                        }), None).await;
                    }
                    _ => unreachable!(),
                }
            }
        };
        let application = async {
            let DpopAuthorizationOutcome::Authorized(grant) = client.authorize_renewable_dpop_with_redirect_driver(
                &cx, key, url(REDIRECT),
                |authorization| async move { Ok(callback(&authorization, ISSUER)) },
            ).await.unwrap() else { panic!("initial renewable grant"); };
            let (mut session, first_access, refresh) = grant.into_renewable_parts();
            session.observe_resource_nonce(&resource, &response_headers(Some("resource-before-refresh"))).unwrap();
            let first_expiry = first_access.expires_at();
            let DpopRefreshOutcome::NonceRequired(challenge) = refresh.unwrap().refresh(&cx, &mut session).await.unwrap() else {
                panic!("an explicit nonce continuation must reach the application");
            };
            assert_eq!(posts.get(), 2, "no automatic refresh replay");
            poll_fn(|task| {
                assert!(listener.poll_accept(task).is_pending());
                Poll::Ready(())
            }).await;
            let replacement = challenge.retry(&cx).await.unwrap();
            assert_eq!(replacement.scopes(), ["tools:read"]);
            let (second_access, second_refresh) = replacement.into_parts();
            assert!(!first_access.is_revoked());
            assert_eq!(first_access.expires_at(), first_expiry);
            let policy = DpopHttpPolicy::default().with_resource_root_der(test_root().as_der().to_vec()).unwrap();
            let mut native = DpopHttpClient::new(session, policy).unwrap();
            let request = CoreRequest::decode(ProtocolEra::Modern2026, "tools/list", Some(&json!({
                "_meta": FinalRequestMeta::new(ClientCapabilities::default()),
            }))).unwrap();
            native.request_core(&cx, &second_access, request, RequestId::Number(91), ManagedCoreLimits::default()).await.unwrap();
            session = native.into_session();
            let DpopRefreshOutcome::Refreshed(replacement) = second_refresh.refresh(&cx, &mut session).await.unwrap() else {
                panic!("second direct rotation");
            };
            assert_eq!(replacement.scopes(), ["tools:read"]);
            let (third_access, third_refresh) = replacement.into_parts();
            assert!(!first_access.is_revoked());
            assert!(!second_access.is_revoked());
            let error = third_refresh.refresh(&cx, &mut session).await.unwrap_err();
            assert_eq!(error, DpopAuthorizationError::OAuth(OAuthError::ScopeExpansion));
            for access in [&first_access, &second_access, &third_access] {
                assert!(access.is_revoked(), "failed rotation retires every generation in its family");
                assert!(session.resource_request_headers("POST", &resource, access).is_err());
            }
        };
        pair(server, application).await;
        assert_eq!(posts.get(), 6);
        assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
    });
}


fn renewable_parts(
    cx: &Cx,
    configuration: &OAuthClientConfiguration,
    key: DpopKey,
) -> (DpopSession, DpopCredential, DpopRefreshToken) {
    let pending = CodeExchange::new(
        FlowBounds::new(cx, Duration::from_secs(60)).unwrap(), configuration,
        DpopSession::new(key, configuration.token_endpoint.clone(), configuration.resource.clone()).unwrap(),
        AuthorizationAttempt::new().unwrap(), REDIRECT, "issued-code".to_owned(),
        RefreshPolicy::RequireRotation,
    ).unwrap();
    let DpopAuthorizationOutcome::Authorized(grant) = pending.admit_response(
        200, &response_headers(Some("initial-as-nonce")),
        br#"{"access_token":"access-one","token_type":"DPoP","expires_in":60,"refresh_token":"refresh-one"}"#,
        Instant::now(), true,
    ).unwrap() else { panic!("renewable grant fixture"); };
    let (session, access, refresh) = grant.into_renewable_parts();
    (session, access, refresh.unwrap())
}

#[test]
fn invalid_dpop_rotation_quarantines_the_family_without_replaying_the_refresh() {
    run(|cx| async move {
        for mutation in [
            "missing", "same", "empty", "null", "control", "oversized", "bearer",
            "key", "resource", "scope", "id_token", "mixed", "redirect", "server_error",
            "duplicate", "nonce_missing", "nonce_status", "nonce_duplicate",
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = url(&format!("https://{}/token", listener.local_addr().unwrap()));
            let configuration = config(endpoint, url("https://mcp.example/mcp"));
            let (mut session, access, refresh) = renewable_parts(&cx, &configuration, DpopKey::generate().unwrap());
            let acceptor = test_acceptor();
            let server = async {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                let (head, form) = read_token_request(&mut socket).await.unwrap();
                assert_eq!(form["refresh_token"], "refresh-one");
                assert_eq!(proof(&head).1["nonce"], "initial-as-nonce");
                let mut body = json!({
                    "access_token": "access-two", "token_type": "DPoP", "expires_in": 60,
                    "refresh_token": "refresh-two",
                });
                let status = match mutation {
                    "missing" => { body.as_object_mut().unwrap().remove("refresh_token"); 200 }
                    "same" => { body["refresh_token"] = json!("refresh-one"); 200 }
                    "empty" => { body["refresh_token"] = json!(""); 200 }
                    "null" => { body["refresh_token"] = Value::Null; 200 }
                    "control" => { body["refresh_token"] = json!("refresh\nprivate"); 200 }
                    "oversized" => { body["refresh_token"] = json!("r".repeat(4097)); 200 }
                    "bearer" => { body["token_type"] = json!("Bearer"); 200 }
                    "key" => { body["cnf"] = json!({"jkt": "another-key"}); 200 }
                    "resource" => { body["resource"] = json!("https://mcp.example/mcp?foreign"); 200 }
                    "scope" => { body["scope"] = json!("tools:admin"); 200 }
                    "id_token" => { body["id_token"] = Value::Null; 200 }
                    "mixed" => { body["error"] = json!("invalid_grant"); 200 }
                    "redirect" => 302,
                    "server_error" => 503,
                    "nonce_missing" | "nonce_duplicate" => { body = json!({"error": "use_dpop_nonce"}); 400 }
                    "nonce_status" => { body = json!({"error": "use_dpop_nonce"}); 401 }
                    _ => 200,
                };
                if mutation == "duplicate" {
                    let raw = r#"{"access_token":"access-two","token_type":"DPoP","refresh_token":"refresh-two","extension":{"nested":1,"nested":2}}"#;
                    socket.write_all(format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{raw}", raw.len(),
                    ).as_bytes()).await.unwrap();
                    socket.shutdown().await.unwrap();
                } else if mutation == "nonce_duplicate" {
                    let raw = serde_json::to_string(&body).unwrap();
                    socket.write_all(format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nDPoP-Nonce: one\r\ndpop-nonce: one\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{raw}", raw.len(),
                    ).as_bytes()).await.unwrap();
                    socket.shutdown().await.unwrap();
                } else {
                    respond(&mut socket, status, &body, (mutation != "nonce_missing").then_some("next-as-nonce")).await;
                }
            };
            let application = async {
                let result = refresh.refresh(&cx, &mut session).await;
                assert!(result.is_err(), "mutation {mutation} must not produce any successor or continuation");
                let error = result.unwrap_err();
                assert!(!format!("{error:?} {error}").contains("refresh-one"));
                assert!(access.is_revoked(), "{mutation} must retire the old access token");
                assert_eq!(session.token_request_headers(&configuration.token_endpoint).unwrap_err(), DpopClientError::SessionRevoked);
            };
            pair(server, application).await;
            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending(), "no retry after {mutation}");
        }
    });
}

#[test]
fn refresh_preflight_refuses_same_key_foreign_session_without_retiring_either_owner() {
    run(|cx| async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let configuration = config(
            url(&format!("https://{}/token", listener.local_addr().unwrap())),
            url("https://mcp.example/mcp"),
        );
        let key = DpopKey::generate().unwrap();
        let (original_session, original_access, refresh) = renewable_parts(&cx, &configuration, key.clone());
        let (mut foreign_session, foreign_access, foreign_refresh) = renewable_parts(&cx, &configuration, key);
        assert_eq!(original_session.authorization_jkt(), foreign_session.authorization_jkt());
        assert!(refresh.refresh(&cx, &mut foreign_session).await.is_err());
        assert!(!original_access.is_revoked());
        assert!(!foreign_access.is_revoked());
        assert!(original_session.resource_request_headers("POST", &configuration.resource, &original_access).is_ok());
        assert!(foreign_session.resource_request_headers("POST", &configuration.resource, &foreign_access).is_ok());
        drop(foreign_refresh);
        assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
    });
}


#[test]
fn expired_dpop_access_can_rotate_but_local_revocation_cannot_dispatch() {
    run(|cx| async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut configuration = config(
            url(&format!("https://{}/token", listener.local_addr().unwrap())),
            url("https://mcp.example/mcp"),
        );
        configuration.max_access_token_lifetime = Duration::from_secs(1);
        let (mut session, access, refresh) = renewable_parts(&cx, &configuration, DpopKey::generate().unwrap());
        asupersync::time::sleep(cx.now(), Duration::from_millis(1100)).await;
        assert!(access.expires_at().unwrap() <= Instant::now());
        assert!(!access.is_revoked());
        assert_eq!(
            session.resource_request_headers("POST", &configuration.resource, &access).unwrap_err(),
            DpopClientError::CredentialUnavailable,
        );
        let acceptor = test_acceptor();
        let server = async {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let (head, form) = read_token_request(&mut socket).await.unwrap();
            assert_eq!(form["refresh_token"], "refresh-one");
            assert!(proof(&head).1.get("ath").is_none());
            respond(&mut socket, 200, &json!({
                "access_token": "access-two", "token_type": "DPoP", "expires_in": 60,
                "refresh_token": "refresh-two",
            }), None).await;
        };
        let application = async {
            let DpopRefreshOutcome::Refreshed(replacement) = refresh.refresh(&cx, &mut session).await.unwrap() else {
                panic!("expiry must permit a direct refresh");
            };
            let (replacement_access, replacement_refresh) = replacement.into_parts();
            assert!(replacement_access.expires_at().unwrap() > Instant::now());
            assert!(!access.is_revoked());
            assert!(session.resource_request_headers("POST", &configuration.resource, &replacement_access).is_ok());
            replacement_access.revoke();
            assert!(replacement_refresh.refresh(&cx, &mut session).await.is_err());
        };
        pair(server, application).await;
        assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending(), "revoked access cannot authorize another refresh POST");
    });
}

#[test]
fn quiet_or_abandoned_dpop_refresh_retires_the_session_and_closes_its_socket() {
    for stop in ["drop", "token_revoke", "session_revoke", "disconnect", "cancel"] {
        run(|cx| async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let configuration = config(
                url(&format!("https://{}/token", listener.local_addr().unwrap())),
                url("https://mcp.example/mcp"),
            );
            let (session, access, refresh) = renewable_parts(&cx, &configuration, DpopKey::generate().unwrap());
            let native = DpopHttpClient::new(session, DpopHttpPolicy::default()).unwrap();
            let owner = native.revocation_handle();
            let mut session = native.into_session();
            let acceptor = test_acceptor();
            let received = Cell::new(false);
            let server = async {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                let (_, form) = read_token_request(&mut socket).await.unwrap();
                assert_eq!(form["refresh_token"], "refresh-one");
                received.set(true);
                match stop {
                    "token_revoke" => access.revoke(),
                    "session_revoke" => owner.revoke(),
                    "cancel" => cx.set_cancel_requested(true),
                    "disconnect" => {
                        socket.shutdown().await.unwrap();
                        return;
                    }
                    _ => {}
                }
                let mut byte = [0];
                assert!(matches!(socket.read(&mut byte).await, Ok(0) | Err(_)), "quiet refresh socket must close on {stop}");
            };
            let application = async {
                if stop == "drop" {
                    let mut pending = Box::pin(refresh.refresh(&cx, &mut session));
                    poll_fn(|task| {
                        if received.get() {
                            return Poll::Ready(());
                        }
                        assert!(pending.as_mut().poll(task).is_pending());
                        Poll::Pending
                    }).await;
                    drop(pending);
                } else {
                    let error = refresh.refresh(&cx, &mut session).await.unwrap_err();
                    assert!(received.get(), "the {stop} control must occur after credential dispatch");
                    if stop == "cancel" {
                        assert_eq!(error, DpopAuthorizationError::OAuth(OAuthError::Cancelled));
                    }
                }
                assert!(access.is_revoked());
                assert!(owner.is_revoked(), "{stop} must retire the entire original session");
                assert_eq!(session.token_request_headers(&configuration.token_endpoint).unwrap_err(), DpopClientError::SessionRevoked);
            };
            pair(server, application).await;
            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending(), "{stop} never retries");
        });
    }
}

#[test]
fn dpop_refresh_nonce_challenge_is_consuming_and_cannot_start_a_retry_loop() {
    for stop in ["drop", "second_challenge", "cancel", "restricted"] {
        run(|cx| async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let configuration = config(
                url(&format!("https://{}/token", listener.local_addr().unwrap())),
                url("https://mcp.example/mcp"),
            );
            let (mut session, access, refresh) = renewable_parts(&cx, &configuration, DpopKey::generate().unwrap());
            let acceptor = test_acceptor();
            let posts = Cell::new(0);
            let server = async {
                let mut first = None;
                for index in 0..(if stop == "second_challenge" { 2 } else { 1 }) {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut socket = acceptor.accept(socket).await.unwrap();
                    let (head, form) = read_token_request(&mut socket).await.unwrap();
                    posts.set(posts.get() + 1);
                    let claims = proof(&head).1;
                    if index == 0 {
                        assert_eq!(claims["nonce"], "initial-as-nonce");
                        first = Some((form, claims["jti"].clone()));
                    } else {
                        let (original_form, original_jti) = first.as_ref().unwrap();
                        assert_eq!(original_form, &form);
                        assert_ne!(original_jti, &claims["jti"]);
                        assert_eq!(claims["nonce"], "challenge-one");
                    }
                    respond(&mut socket, 400, &json!({"error": "use_dpop_nonce"}), Some("challenge-one")).await;
                }
            };
            let application = async {
                let DpopRefreshOutcome::NonceRequired(challenge) = refresh.refresh(&cx, &mut session).await.unwrap() else {
                    panic!("first valid challenge must return control");
                };
                assert_eq!(posts.get(), 1);
                assert!(!access.is_revoked(), "nonce continuation temporarily retains the family");
                match stop {
                    "drop" => drop(challenge),
                    "cancel" => {
                        cx.set_cancel_requested(true);
                        assert_eq!(challenge.retry(&cx).await.unwrap_err(), DpopAuthorizationError::OAuth(OAuthError::Cancelled));
                    }
                    "restricted" => {
                        let _restriction = Cx::push_restriction(CapSet::<true, true, true, false, true>::MASK);
                        assert_eq!(challenge.retry(&cx).await.unwrap_err(), DpopAuthorizationError::OAuth(OAuthError::RuntimeCapabilityUnavailable));
                    }
                    _ => assert_eq!(challenge.retry(&cx).await.unwrap_err(), DpopAuthorizationError::NonceRetryLimit),
                }
                assert!(access.is_revoked(), "{stop} must retire the grant instead of releasing a retryable token");
                assert_eq!(session.token_request_headers(&configuration.token_endpoint).unwrap_err(), DpopClientError::SessionRevoked);
            };
            pair(server, application).await;
            assert_eq!(posts.get(), if stop == "second_challenge" { 2 } else { 1 });
            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
        });
    }
}


fn renewal_tools_request() -> CoreRequest {
    CoreRequest::decode(
        ProtocolEra::Modern2026,
        "tools/list",
        Some(&json!({
            "_meta": FinalRequestMeta::new(ClientCapabilities::default()),
        })),
    )
    .unwrap()
}

#[test]
fn native_client_renewal_preserves_resource_trust_limits_nonces_and_revocation_handles() {
    for nonce_required in [false, true] {
        run(|cx| async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let endpoint = url(&format!("https://{address}/token"));
            let resource = url(&format!("https://{address}/mcp"));
            let configuration = config(endpoint.clone(), resource.clone());
            let (mut session, original_access, refresh) =
                renewable_parts(&cx, &configuration, DpopKey::generate().unwrap());
            session
                .observe_resource_nonce(&resource, &response_headers(Some("resource-before-renewal")))
                .unwrap();
            let policy = DpopHttpPolicy::default()
                .with_resource_root_der(test_root().as_der().to_vec())
                .unwrap()
                .with_timeout(Duration::from_secs(3))
                .unwrap()
                .with_max_body_bytes(512)
                .unwrap();
            let mut native = DpopHttpClient::new(session, policy).unwrap();
            let owner = native.revocation_handle();
            let original_expiry = original_access.expires_at();
            let posts = Cell::new(0);
            let acceptor = test_acceptor();
            let server = async {
                let token_posts = if nonce_required { 2 } else { 1 };
                let mut first_proof = None;
                for index in 0..token_posts {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut socket = acceptor.accept(socket).await.unwrap();
                    let (head, form) = read_token_request(&mut socket).await.unwrap();
                    posts.set(posts.get() + 1);
                    assert!(head.starts_with("POST /token HTTP/1.1\r\n"));
                    assert_eq!(form["grant_type"], "refresh_token");
                    assert_eq!(form["refresh_token"], "refresh-one");
                    let (_, claims) = proof(&head);
                    assert_eq!(claims["htu"], endpoint.as_str());
                    assert!(claims.get("ath").is_none());
                    if index == 0 {
                        assert_eq!(claims["nonce"], "initial-as-nonce");
                        first_proof = Some(claims["jti"].clone());
                    } else {
                        assert_ne!(first_proof.as_ref(), Some(&claims["jti"]));
                        assert_eq!(claims["nonce"], "renewal-challenge");
                    }
                    if nonce_required && index == 0 {
                        respond(
                            &mut socket,
                            400,
                            &json!({"error": "use_dpop_nonce"}),
                            Some("renewal-challenge"),
                        )
                        .await;
                    } else {
                        respond(
                            &mut socket,
                            200,
                            &json!({
                                "access_token": "access-two",
                                "token_type": "DPoP",
                                "expires_in": 60,
                                "refresh_token": "refresh-two",
                                "scope": "tools:read",
                            }),
                            Some("token-after-renewal"),
                        )
                        .await;
                    }
                }
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                let (head, request) = read_resource_request(&mut socket).await;
                posts.set(posts.get() + 1);
                assert!(head.starts_with("POST /mcp HTTP/1.1\r\n"));
                assert_eq!(header(&head, "authorization"), "DPoP access-two");
                assert_eq!(proof(&head).1["nonce"], "resource-before-renewal");
                assert_eq!(request["method"], "tools/list");
                respond(
                    &mut socket,
                    200,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": request["id"],
                        "result": {
                            "resultType": "complete",
                            "tools": [],
                            "ttlMs": 0,
                            "cacheScope": "private",
                        },
                    }),
                    Some("resource-after-renewal"),
                )
                .await;
            };
            let application = async {
                let replacement = match native.refresh_authorization(&cx, refresh).await.unwrap() {
                    DpopRefreshOutcome::Refreshed(replacement) => {
                        assert!(!nonce_required);
                        replacement
                    }
                    DpopRefreshOutcome::NonceRequired(challenge) => {
                        assert!(nonce_required);
                        assert_eq!(posts.get(), 1, "the client must wait for an explicit retry");
                        poll_fn(|task| {
                            assert!(listener.poll_accept(task).is_pending());
                            Poll::Ready(())
                        })
                        .await;
                        challenge.retry(&cx).await.unwrap()
                    }
                };
                assert_eq!(replacement.scopes(), ["tools:read"]);
                assert!(!original_access.is_revoked());
                assert_eq!(original_access.expires_at(), original_expiry);
                assert!(!owner.is_revoked());
                let (access, next_refresh) = replacement.into_parts();

                // Preserve the resource policy's request cap. No oversized
                // request may reach the waiting resource peer after renewal.
                let oversized = crate::http_executor::ModernHttpRequest::new(
                    resource.as_str(),
                    serde_json::to_vec(&json!({
                        "jsonrpc": "2.0",
                        "id": 8,
                        "method": "tools/call",
                        "params": {"name": "echo", "arguments": {"text": "x".repeat(512)}},
                    }))
                    .unwrap(),
                    fastmcp_protocol::FINAL_PROTOCOL_VERSION,
                    "tools/call",
                    Some("echo".to_owned()),
                )
                .unwrap();
                assert!(matches!(
                    native
                        .post_resource(
                            &cx,
                            &fastmcp_core::McpRequestCancellation::new(),
                            &access,
                            &oversized,
                        )
                        .await,
                    Err(crate::http_auth::dpop::native::DpopHttpError::BodyTooLarge)
                ));
                let result = native
                    .request_core(
                        &cx,
                        &access,
                        renewal_tools_request(),
                        RequestId::Number(9),
                        ManagedCoreLimits::default(),
                    )
                    .await
                    .unwrap();
                assert!(result.encode().unwrap().contains("\"tools\":[]"));

                // This handle predates renewal. It must still retire every
                // access generation and prevent another token request.
                owner.revoke();
                assert!(original_access.is_revoked());
                assert!(access.is_revoked());
                assert!(native.refresh_authorization(&cx, next_refresh).await.is_err());
            };
            pair(server, application).await;
            assert_eq!(posts.get(), if nonce_required { 3 } else { 2 });
            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
        });
    }
}

#[test]
fn native_renewal_cannot_promote_token_roots_or_reset_resource_timeouts() {
    for restriction in ["untrusted-resource", "short-resource-timeout"] {
        run(|cx| async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let endpoint = url(&format!("https://{address}/token"));
            let resource = url(&format!("https://{address}/mcp"));
            let configuration = config(endpoint, resource);
            let (session, _, refresh) =
                renewable_parts(&cx, &configuration, DpopKey::generate().unwrap());
            let policy = if restriction == "untrusted-resource" {
                DpopHttpPolicy::default()
            } else {
                DpopHttpPolicy::default()
                    .with_resource_root_der(test_root().as_der().to_vec())
                    .unwrap()
                    .with_timeout(Duration::from_secs(1))
                    .unwrap()
            };
            let mut native = DpopHttpClient::new(session, policy).unwrap();
            let resource_received = Cell::new(false);
            let acceptor = test_acceptor();
            let server = async {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                let (_, form) = read_token_request(&mut socket).await.unwrap();
                assert_eq!(form["refresh_token"], "refresh-one");
                respond(
                    &mut socket,
                    200,
                    &json!({
                        "access_token": "access-two",
                        "token_type": "DPoP",
                        "expires_in": 60,
                        "refresh_token": "refresh-two",
                    }),
                    None,
                )
                .await;
                let (socket, _) = listener.accept().await.unwrap();
                let secured = acceptor.accept(socket).await;
                if restriction == "untrusted-resource" {
                    assert!(secured.is_err(), "token roots must not become resource roots");
                } else {
                    let mut socket = secured.unwrap();
                    let (_, request) = read_resource_request(&mut socket).await;
                    assert_eq!(request["method"], "tools/list");
                    resource_received.set(true);
                    // A reset to the default 120-second resource timeout
                    // would exceed the enclosing test's 20-second bound.
                    let mut byte = [0];
                    assert!(matches!(socket.read(&mut byte).await, Ok(0) | Err(_)));
                }
            };
            let application = async {
                let DpopRefreshOutcome::Refreshed(replacement) =
                    native.refresh_authorization(&cx, refresh).await.unwrap()
                else {
                    panic!("fixture grants a direct renewal");
                };
                let (access, _) = replacement.into_parts();
                let error = native
                    .request_core(
                        &cx,
                        &access,
                        renewal_tools_request(),
                        RequestId::Number(10),
                        ManagedCoreLimits::default(),
                    )
                    .await
                    .unwrap_err();
                if restriction == "short-resource-timeout" {
                    assert!(resource_received.get(), "the original timeout must bound quiet I/O");
                    assert!(matches!(
                        error,
                        crate::http_auth::dpop::native::core::DpopCoreError::Transport(
                            crate::http_auth::dpop::native::DpopHttpError::TimedOut
                        )
                    ));
                }
            };
            pair(server, application).await;
            assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending());
        });
    }
}
