//! Real native TLS coverage of registered, current-message notifications.
//! The parent module supplies the existing certificate, runtime and wire helpers.

use super::*;
use crate::http_auth::dpop::native::core::extensions::notification::DpopExtensionNotification;
use fastmcp_protocol::extensions::{
    ExtensionNotificationDescriptor, NotificationActivationProofDescriptor,
    NotificationActivationProofLocation as Location,
};

const NOTIFICATION: &str = "example/dpop-notify";
const PROOF: &str = "com.example/notification-proof";

fn notification_descriptor(location: Location) -> ExtensionDescriptor {
    let mut descriptor = descriptor();
    descriptor.notification = Some(ExtensionNotificationDescriptor {
        name: NOTIFICATION.to_owned(),
        direction: ExtensionDirection::ClientToServer,
        activation_proof: Some(NotificationActivationProofDescriptor::SelfContained {
            location,
            key: PROOF.to_owned(),
        }),
    });
    descriptor
}

fn notification_parameters(sequence: usize) -> Value {
    json!({
        "sequence":sequence,
        "private":"notification-body-canary",
        "_meta":{
            "com.example/note":"notification-only",
            "io.modelcontextprotocol/clientCapabilities":{
                "extensions":{"com.example/forged":{}},
            },
        },
    })
}

fn notification(discovery_id: i64, sequence: usize, location: Location) -> DpopExtensionNotification {
    let mut parameters = notification_parameters(sequence);
    if sequence > 0 {
        // An identical explicitly supplied proof is allowed. It cannot widen
        // the frozen local settings or borrow another extension's authority.
        match location {
            Location::Params => parameters[PROOF] = json!({"format":"echo-v1"}),
            Location::Metadata => parameters["_meta"][PROOF] = json!({"format":"echo-v1"}),
        }
    }
    DpopExtensionNotification::new(
        RequestId::Number(discovery_id), extension_id(), NOTIFICATION, parameters,
    ).unwrap()
}

fn scoped_discovery() -> Value {
    let mut offer = discovery();
    offer["capabilities"]["extensions"].as_object_mut().unwrap().remove(OTHER_EXTENSION);
    offer
}

fn absent_header(head: &str, expected: &str) {
    assert!(!head.lines().filter_map(|line| line.split_once(':'))
        .any(|(name, _)| name.eq_ignore_ascii_case(expected)),
        "{expected} must not be emitted");
}

fn inspect_discovery(
    head: &str,
    body: &Value,
    target: &str,
    id: i64,
    proofs: &mut BTreeSet<String>,
) {
    inspect(head, body, target, "server/discover", &RequestId::Number(id), proofs);
    absent_header(head, "mcp-session-id");
}

fn inspect_notification(
    head: &str,
    body: &Value,
    target: &str,
    sequence: usize,
    location: Location,
    proofs: &mut BTreeSet<String>,
) {
    assert!(head.starts_with("POST /mcp?tenant=one HTTP/1.1\r\n"));
    assert_eq!(body["jsonrpc"], "2.0");
    assert!(body.get("id").is_none(), "a notification must not allocate a request ID");
    assert_eq!(body["method"], NOTIFICATION);
    assert_eq!(body["params"]["sequence"], sequence);
    assert_eq!(body["params"]["private"], "notification-body-canary");
    assert_eq!(body["params"]["_meta"]["com.example/note"], "notification-only");
    assert_eq!(body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
        json!({"extensions":{"com.example/forged":{}}}));
    assert!(body["params"]["_meta"].get("io.modelcontextprotocol/protocolVersion").is_none());
    for name in ["mcp-method", "mcp-name", "mcp-protocol-version", "mcp-session-id"] {
        absent_header(head, name);
    }
    assert_eq!(header(head, "authorization"), "DPoP extension-access");
    assert_eq!(header(head, "accept"), "application/json");
    assert_eq!(header(head, "content-type"), "application/json");
    assert!(!head.contains("notification-body-canary"));
    let settings = match location {
        Location::Params => &body["params"][PROOF],
        Location::Metadata => &body["params"]["_meta"][PROOF],
    };
    assert_eq!(settings, &json!({"format":"echo-v1"}));
    match location {
        Location::Params => assert!(body["params"]["_meta"].get(PROOF).is_none()),
        Location::Metadata => assert!(body["params"].get(PROOF).is_none()),
    }
    let proof = claims(header(head, "dpop"));
    assert_eq!(proof["htm"], "POST");
    assert_eq!(proof["htu"], target.split('?').next().unwrap());
    assert_eq!(proof["nonce"], "extension-next");
    assert!(proof["ath"].as_str().is_some_and(|hash| !hash.is_empty()));
    assert!(proofs.insert(proof["jti"].as_str().unwrap().to_owned()),
        "notification must sign its own fresh proof");
}

#[derive(Clone, Copy, Debug)]
enum Reply {
    Accepted,
    SessionHeader,
    Body,
    ContentType,
    Encoded,
    Status200,
    Status204,
    Challenge,
    NoOffer,
    IncompatibleOffer,
    ForeignDiscoveryId,
    UnsupportedVersion,
}

impl Reply {
    fn ends_at_discovery(self) -> bool {
        matches!(self, Self::NoOffer | Self::IncompatibleOffer
            | Self::ForeignDiscoveryId | Self::UnsupportedVersion)
    }
}

async fn acknowledgement<IO: AsyncWrite + Unpin>(io: &mut IO, reply: Reply) {
    let (status, extra, body) = match reply {
        Reply::SessionHeader => ("202 Accepted", "Mcp-Session-Id: ignored-legacy-canary\r\n", ""),
        Reply::Body => ("202 Accepted", "", "x"),
        Reply::ContentType => ("202 Accepted", "Content-Type: application/json\r\n", ""),
        Reply::Encoded => ("202 Accepted", "Content-Encoding: gzip\r\n", ""),
        Reply::Status200 => ("200 OK", "Content-Type: application/json\r\n", "{}"),
        Reply::Status204 => ("204 No Content", "Content-Type: application/json\r\n", ""),
        Reply::Challenge => ("401 Unauthorized", "Content-Type: application/json\r\n", "{}"),
        _ => ("202 Accepted", "", ""),
    };
    let wire = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n{extra}DPoP-Nonce: extension-next\r\nConnection: close\r\n\r\n{body}", body.len());
    io.write_all(wire.as_bytes()).await.unwrap();
    let _closed = io.shutdown().await;
}

async fn exercise_notification(location: Location, reply: Reply) {
    let cx = Cx::current().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap());
    let (mut client, credential, acceptor) = configured(&target);
    // The unrelated configured owner rejects one-sided support. Its absence
    // from discovery must not veto the selected notification owner's proof.
    let (configuration, factories) = configuration(notification_descriptor(location), true);
    let cancellation = McpRequestCancellation::new();
    let mut proofs = BTreeSet::new();
    let application = client.notify_final_extension(
        &cx, &cancellation, &credential, &configuration, metadata(),
        notification(1, 0, location), limits(0).core,
    );
    let peer = async {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = acceptor.accept(socket).await.unwrap();
        let (head, body) = read(&mut socket).await;
        inspect_discovery(&head, &body, &target, 1, &mut proofs);
        let mut offer = scoped_discovery();
        if matches!(reply, Reply::NoOffer) {
            offer["capabilities"]["extensions"].as_object_mut().unwrap().remove(EXTENSION);
        }
        if matches!(reply, Reply::IncompatibleOffer) {
            offer["capabilities"]["extensions"][EXTENSION]["format"] = json!("foreign-v1");
        }
        if matches!(reply, Reply::UnsupportedVersion) {
            offer["supportedVersions"] = json!(["2024-11-05"]);
        }
        let id = if matches!(reply, Reply::ForeignDiscoveryId) {
            RequestId::String("1".to_owned())
        } else {
            RequestId::Number(1)
        };
        json_reply(&mut socket, &frame(&id, &offer.to_string())).await;
        if reply.ends_at_discovery() {
            return;
        }
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = acceptor.accept(socket).await.unwrap();
        let (head, body) = read(&mut socket).await;
        inspect_notification(&head, &body, &target, 0, location, &mut proofs);
        acknowledgement(&mut socket, reply).await;
    };
    let (outcome, ()) = pair(application, peer).await;
    match reply {
        Reply::Accepted | Reply::SessionHeader => outcome.unwrap(),
        Reply::Body | Reply::ContentType | Reply::Encoded => assert!(matches!(outcome,
            Err(DpopCoreError::Transport(DpopHttpError::InvalidResponseHeaders)))),
        Reply::Status200 => assert!(matches!(outcome,
            Err(DpopCoreError::Protocol(ManagedCoreError::HttpStatus { status: 200 })))),
        Reply::Status204 => assert!(matches!(outcome,
            Err(DpopCoreError::Protocol(ManagedCoreError::HttpStatus { status: 204 })))),
        Reply::Challenge => assert!(matches!(outcome,
            Err(DpopCoreError::Protocol(ManagedCoreError::HttpStatus { status: 401 })))),
        Reply::NoOffer | Reply::IncompatibleOffer | Reply::UnsupportedVersion => assert!(matches!(outcome,
            Err(DpopCoreError::Protocol(ManagedCoreError::UnsupportedRequest)))),
        Reply::ForeignDiscoveryId => assert!(matches!(outcome,
            Err(DpopCoreError::Protocol(ManagedCoreError::ResponseIdMismatch)))),
    }
    assert_eq!(proofs.len(), if reply.ends_at_discovery() { 1 } else { 2 });
    assert_eq!(factories.load(Ordering::SeqCst),
        usize::from(!matches!(reply, Reply::ForeignDiscoveryId | Reply::UnsupportedVersion)));
    no_extra(&listener);
    assert_eq!(client.session.resource_nonce, Some(DpopNonce::new("extension-next").unwrap()));
    assert!(client.session.token_nonce.is_none());
    assert!(cx.checkpoint().is_ok());

    // Success and refusal both leave a usable explicit owner. This next call
    // must rediscover and resign; no server-provided legacy session is reused.
    let next_cancel = McpRequestCancellation::new();
    let application = client.notify_final_extension(
        &cx, &next_cancel, &credential, &configuration, metadata(),
        notification(3, 1, location), limits(0).core,
    );
    let peer = async {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = acceptor.accept(socket).await.unwrap();
        let (head, body) = read(&mut socket).await;
        inspect_discovery(&head, &body, &target, 3, &mut proofs);
        json_reply(&mut socket, &frame(&RequestId::Number(3), &scoped_discovery().to_string())).await;
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = acceptor.accept(socket).await.unwrap();
        let (head, body) = read(&mut socket).await;
        inspect_notification(&head, &body, &target, 1, location, &mut proofs);
        acknowledgement(&mut socket, Reply::Accepted).await;
    };
    let (outcome, ()) = pair(application, peer).await;
    outcome.unwrap();
    assert_eq!(proofs.len(), if reply.ends_at_discovery() { 3 } else { 4 });
    assert_eq!(factories.load(Ordering::SeqCst),
        1 + usize::from(!matches!(reply, Reply::ForeignDiscoveryId | Reply::UnsupportedVersion)));
    assert!(!next_cancel.is_cancel_requested());
    assert!(!client.revocation_handle().is_revoked());
    no_extra(&listener);
}

#[test]
fn notification_proof_locations_are_current_message_scoped_and_session_headers_stay_inert() {
    for location in [Location::Params, Location::Metadata] {
        for reply in [Reply::Accepted, Reply::SessionHeader] {
            run(exercise_notification(location, reply));
        }
    }
}

#[test]
fn notification_peer_refusals_never_replay_and_preserve_a_fresh_explicit_call() {
    for reply in [
        Reply::Body, Reply::ContentType, Reply::Encoded, Reply::Status200,
        Reply::Status204, Reply::Challenge, Reply::NoOffer, Reply::IncompatibleOffer,
        Reply::ForeignDiscoveryId, Reply::UnsupportedVersion,
    ] {
        run(exercise_notification(Location::Params, reply));
    }
}

#[test]
fn notification_constructor_rejects_invalid_ids_and_nonobject_parameters() {
    for parameters in [Value::Null, json!([]), json!({"_meta":[]})] {
        assert!(matches!(DpopExtensionNotification::new(
            RequestId::Number(1), extension_id(), NOTIFICATION, parameters,
        ), Err(ManagedCoreError::InvalidRequest)));
    }
    assert!(matches!(DpopExtensionNotification::new(
        RequestId::Integer("1.5".to_owned()), extension_id(), NOTIFICATION, json!({}),
    ), Err(ManagedCoreError::InvalidRequest)));
    assert!(DpopExtensionNotification::new(
        RequestId::String("discovery".to_owned()), extension_id(), NOTIFICATION, json!({}),
    ).is_ok());
}

#[test]
fn notification_local_owner_direction_proof_and_bounds_fail_before_any_connection() {
    #[derive(Clone, Copy, Debug)]
    enum Rejection {
        Owner,
        UnknownOwner,
        Disabled,
        Direction,
        MissingProof,
        Method,
        ProofConflict,
        MalformedProof,
        BaseCapabilities,
        Version,
        RequestLimit,
        Cancelled,
        Revoked,
    }
    for location in [Location::Params, Location::Metadata] {
        for rejection in [
            Rejection::Owner, Rejection::UnknownOwner, Rejection::Disabled,
            Rejection::Direction, Rejection::MissingProof, Rejection::Method,
            Rejection::ProofConflict, Rejection::MalformedProof, Rejection::BaseCapabilities,
            Rejection::Version, Rejection::RequestLimit, Rejection::Cancelled, Rejection::Revoked,
        ] {
            run(async {
                let cx = Cx::current().unwrap();
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let target = format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap());
                let (mut client, credential, _acceptor) = configured(&target);
                let mut descriptor = notification_descriptor(location);
                if matches!(rejection, Rejection::Direction | Rejection::MissingProof) {
                    descriptor.notification.as_mut().unwrap().activation_proof = None;
                }
                if matches!(rejection, Rejection::Direction) {
                    descriptor.notification.as_mut().unwrap().direction = ExtensionDirection::ServerToClient;
                }
                let (configuration, factories) =
                    configuration(descriptor, !matches!(rejection, Rejection::Disabled));
                let mut parameters = notification_parameters(0);
                if matches!(rejection, Rejection::ProofConflict | Rejection::MalformedProof) {
                    let proof = if matches!(rejection, Rejection::ProofConflict) {
                        json!({"format":"forged-v1"})
                    } else {
                        json!([])
                    };
                    match location {
                        Location::Params => parameters[PROOF] = proof,
                        Location::Metadata => parameters["_meta"][PROOF] = proof,
                    }
                }
                let mut metadata = metadata();
                if matches!(rejection, Rejection::BaseCapabilities) {
                    metadata.client_capabilities.extensions =
                        Some(BTreeMap::from([("com.example/forged".to_owned(), json!({}))]));
                }
                if matches!(rejection, Rejection::Version) {
                    metadata.protocol_version = "2024-11-05".to_owned();
                }
                let selected = if matches!(rejection, Rejection::RequestLimit) {
                    parameters["oversized"] = json!("x".repeat(2048));
                    ManagedCoreLimits::new(1024, 8192, 32768, 0, Duration::from_secs(60)).unwrap()
                } else {
                    limits(0).core
                };
                let owner = match rejection {
                    Rejection::Owner => ExtensionId::parse(OTHER_EXTENSION).unwrap(),
                    Rejection::UnknownOwner => ExtensionId::parse("com.example/unknown").unwrap(),
                    _ => extension_id(),
                };
                let method = if matches!(rejection, Rejection::Method) { METHOD } else { NOTIFICATION };
                let operation = DpopExtensionNotification::new(
                    RequestId::Number(1), owner, method, parameters,
                ).unwrap();
                let cancellation = McpRequestCancellation::new();
                if matches!(rejection, Rejection::Cancelled) {
                    cancellation.cancel();
                }
                if matches!(rejection, Rejection::Revoked) {
                    credential.revoke();
                }
                let error = client.notify_final_extension(
                    &cx, &cancellation, &credential, &configuration, metadata, operation, selected,
                ).await.err().expect("local rejection cannot acknowledge a notification");
                let expected = match (rejection, &error) {
                    (Rejection::Version, DpopCoreError::Protocol(ManagedCoreError::InvalidRequest))
                    | (Rejection::RequestLimit, DpopCoreError::Protocol(ManagedCoreError::RequestTooLarge))
                    | (Rejection::Cancelled, DpopCoreError::Transport(DpopHttpError::Cancelled))
                    | (Rejection::Revoked, DpopCoreError::Transport(DpopHttpError::Authorization(_)))
                    | (Rejection::Owner | Rejection::UnknownOwner | Rejection::Disabled
                        | Rejection::Direction | Rejection::MissingProof | Rejection::Method
                        | Rejection::ProofConflict | Rejection::MalformedProof | Rejection::BaseCapabilities,
                        DpopCoreError::Protocol(ManagedCoreError::UnsupportedRequest)) => true,
                    _ => false,
                };
                assert!(expected, "unexpected local notification rejection {rejection:?}: {error:?}");
                assert_eq!(factories.load(Ordering::SeqCst), 0);
                assert!(client.session.resource_nonce.is_none());
                no_extra(&listener);
                assert!(cx.checkpoint().is_ok());
            });
        }
    }
}

#[test]
fn notification_cancellation_revocation_and_drop_retire_only_the_owned_exchange() {
    #[derive(Clone, Copy)]
    enum Stop { Cancel, Revoke, Drop }

    for at_notification in [false, true] {
        for stop in [Stop::Cancel, Stop::Revoke, Stop::Drop] {
            run(async {
                let cx = Cx::current().unwrap();
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let target = format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap());
                let (mut client, credential, acceptor) = configured(&target);
                let (configuration, factories) = configuration(notification_descriptor(Location::Params), true);
                let cancellation = McpRequestCancellation::new();
                let observed = McpRequestCancellation::new();
                let mut proofs = BTreeSet::new();
                let application = async {
                    let mut call = Box::pin(client.notify_final_extension(
                        &cx, &cancellation, &credential, &configuration, metadata(),
                        notification(1, 0, Location::Params), limits(0).core,
                    ));
                    let mut observed_wait = std::pin::pin!(observed.cancelled());
                    poll_fn(|task| {
                        assert!(call.as_mut().poll(task).is_pending());
                        if observed_wait.as_mut().poll(task).is_ready() {
                            Poll::Ready(())
                        } else {
                            Poll::Pending
                        }
                    }).await;
                    match stop {
                        Stop::Drop => drop(call),
                        Stop::Cancel => {
                            cancellation.cancel();
                            assert!(matches!(call.await,
                                Err(DpopCoreError::Transport(DpopHttpError::Cancelled))));
                        }
                        Stop::Revoke => {
                            credential.revoke();
                            assert!(matches!(call.await,
                                Err(DpopCoreError::Transport(DpopHttpError::Authorization(_)))));
                        }
                    }
                };
                let peer = async {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut socket = acceptor.accept(socket).await.unwrap();
                    let (head, body) = read(&mut socket).await;
                    inspect_discovery(&head, &body, &target, 1, &mut proofs);
                    if at_notification {
                        json_reply(&mut socket, &frame(&RequestId::Number(1), &scoped_discovery().to_string())).await;
                        let (next, _) = listener.accept().await.unwrap();
                        socket = acceptor.accept(next).await.unwrap();
                        let (head, body) = read(&mut socket).await;
                        inspect_notification(&head, &body, &target, 0, Location::Params, &mut proofs);
                    }
                    observed.cancel();
                    // No response exists to unblock a buffering implementation.
                    // Local interruption must release the owned TLS stream.
                    let mut byte = [0];
                    assert!(!matches!(socket.read(&mut byte).await, Ok(count) if count > 0));
                };
                pair(application, peer).await;
                assert_eq!(proofs.len(), if at_notification { 2 } else { 1 });
                assert_eq!(factories.load(Ordering::SeqCst), usize::from(at_notification));
                assert_eq!(cancellation.is_cancel_requested(), matches!(stop, Stop::Cancel));
                assert!(!client.revocation_handle().is_revoked());
                assert!(cx.checkpoint().is_ok());
                no_extra(&listener);
            });
        }
    }
}

#[test]
fn empty_notification_acknowledgement_needs_no_budget_beyond_exact_discovery_bytes() {
    for extra_byte in [false, true] {
        run(async {
            let cx = Cx::current().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap());
            let (mut client, credential, acceptor) = configured(&target);
            let (configuration, factories) = configuration(notification_descriptor(Location::Params), true);
            let mut discovery_frame = frame(&RequestId::Number(1), &scoped_discovery().to_string());
            let exact = discovery_frame.len();
            let selected = ManagedCoreLimits::new(
                8192, exact, exact, 0, Duration::from_secs(60),
            ).unwrap();
            if extra_byte {
                // JSON meaning is unchanged; only its charged wire length grows.
                discovery_frame.push(b' ');
            }
            let cancellation = McpRequestCancellation::new();
            let mut proofs = BTreeSet::new();
            let application = client.notify_final_extension(
                &cx, &cancellation, &credential, &configuration, metadata(),
                notification(1, 0, Location::Params), selected,
            );
            let peer = async {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                let (head, body) = read(&mut socket).await;
                inspect_discovery(&head, &body, &target, 1, &mut proofs);
                json_reply(&mut socket, &discovery_frame).await;
                if extra_byte {
                    return;
                }
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                let (head, body) = read(&mut socket).await;
                inspect_notification(&head, &body, &target, 0, Location::Params, &mut proofs);
                acknowledgement(&mut socket, Reply::Accepted).await;
            };
            let (outcome, ()) = pair(application, peer).await;
            if extra_byte {
                assert!(matches!(outcome,
                    Err(DpopCoreError::Protocol(ManagedCoreError::ResponseByteLimit))));
            } else {
                outcome.unwrap();
            }
            assert_eq!(proofs.len(), if extra_byte { 1 } else { 2 });
            assert_eq!(factories.load(Ordering::SeqCst), usize::from(!extra_byte));
            no_extra(&listener);
        });
    }
}

#[test]
fn notification_discovery_cannot_restart_the_original_absolute_deadline() {
    use asupersync::time::{TimerDriverHandle, VirtualClock};

    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .with_reactor(create_reactor().unwrap())
        .with_timer_driver(timer.clone())
        .build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap());
        let (mut client, credential, acceptor) = configured(&target);
        let (configuration, factories) = configuration(notification_descriptor(Location::Params), true);
        let cancellation = McpRequestCancellation::new();
        let reached = McpRequestCancellation::new();
        let selected = ManagedCoreLimits::new(
            8192, 8192, 32768, 0, Duration::from_secs(10),
        ).unwrap();
        let mut proofs = BTreeSet::new();
        let application = async {
            let mut call = Box::pin(client.notify_final_extension(
                &cx, &cancellation, &credential, &configuration, metadata(),
                notification(1, 0, Location::Params), selected,
            ));
            let mut reached_wait = std::pin::pin!(reached.cancelled());
            poll_fn(|task| {
                let result = call.as_mut().poll(task);
                if reached_wait.as_mut().poll(task).is_ready() {
                    assert!(matches!(result,
                        Poll::Ready(Err(DpopCoreError::Transport(DpopHttpError::TimedOut)))));
                    Poll::Ready(())
                } else {
                    assert!(result.is_pending());
                    Poll::Pending
                }
            }).await;
        };
        let peer = async {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let (head, body) = read(&mut socket).await;
            inspect_discovery(&head, &body, &target, 1, &mut proofs);
            clock.advance(6_000_000_000);
            json_reply(&mut socket, &frame(&RequestId::Number(1), &scoped_discovery().to_string())).await;
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let (head, body) = read(&mut socket).await;
            inspect_notification(&head, &body, &target, 0, Location::Params, &mut proofs);
            // Hold the acknowledgement past the original deadline. The second
            // POST cannot receive another ten seconds after discovery used six.
            clock.advance(4_000_000_000);
            assert!(timer.process_timers() > 0);
            reached.cancel();
            let mut byte = [0];
            assert!(!matches!(socket.read(&mut byte).await, Ok(count) if count > 0));
        };
        pair(application, peer).await;
        assert_eq!(cx.now().as_nanos(), 10_000_000_000);
        assert_eq!(proofs.len(), 2);
        assert_eq!(factories.load(Ordering::SeqCst), 1);
        assert!(cx.checkpoint().is_ok());
        no_extra(&listener);
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn oversized_configured_activation_proof_is_rejected_before_discovery() {
    for location in [Location::Params, Location::Metadata] {
        run(async {
            let cx = Cx::current().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = format!("https://{}/mcp?tenant=one", listener.local_addr().unwrap());
            let (mut client, credential, _acceptor) = configured(&target);
            let mut settings = json!({"format":"echo-v1"});
            for index in 0..5 {
                settings[format!("part-{index}")] = json!("x".repeat(14 * 1024));
            }
            assert!(serde_json::to_vec(&settings).unwrap().len() > 64 * 1024);
            // Generic settings bound each value separately, so this remains a
            // legal local configuration. Its current-message proof has a
            // smaller aggregate limit that must be enforced before contact.
            let settings = ExtensionSettings::new(settings).unwrap();
            let mut registry = ExtensionDescriptorRegistry::new();
            registry.register(notification_descriptor(location)).unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let factory_calls = Arc::clone(&calls);
            let configuration = DpopExtensionConfiguration::new(
                registry,
                ClientExtensionDiscovery {
                    extensions: BTreeMap::from([(extension_id(), settings)]),
                },
                move || {
                    factory_calls.fetch_add(1, Ordering::SeqCst);
                    compatible
                },
            ).unwrap();
            let cancellation = McpRequestCancellation::new();
            let outcome = client.notify_final_extension(
                &cx, &cancellation, &credential, &configuration, metadata(),
                notification(1, 0, location), limits(0).core,
            ).await;
            // A missing proof-size gate would fall through to RequestTooLarge
            // on this fixture's independent wire cap, which is also a failure.
            assert!(matches!(outcome,
                Err(DpopCoreError::Protocol(ManagedCoreError::UnsupportedRequest))));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert!(client.session.resource_nonce.is_none());
            assert!(cx.checkpoint().is_ok());
            no_extra(&listener);
        });
    }
}
