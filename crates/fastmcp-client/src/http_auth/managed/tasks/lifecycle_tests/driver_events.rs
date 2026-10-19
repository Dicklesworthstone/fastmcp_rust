//! Public managed Task driving through native OAuth and the parent's TLS peer.
//! The existing fixture owns test identity, HTTP capture and routing admission.
//! No substitute grant, decoder, transport, or process trust change is used.

use super::*;
use crate::http_auth::managed::tasks::driver::{
    ManagedTaskDriverError, ManagedTaskDriverPolicy, ManagedTaskInputAction, ManagedTaskRunOutcome,
};
use crate::http_auth::oauth::OAuthError;

#[derive(Clone, Copy, Debug)]
enum Failure {
    Decline,
    Cancel,
    Revoke,
    Close,
    Abandon,
    Trailing,
    Missing,
    BadProgress,
    RecordLimit,
    SnapshotRevoke,
    ResolverCancelConstructor,
    ResolverRevokeConstructor,
    ResolverRevokePending,
}

fn snapshot(status: &str) -> Value {
    let mut result = json!({
        "resultType":"complete", "taskId":"task-one", "status":status,
        "createdAt":"2026-09-16T00:00:00Z", "lastUpdatedAt":"2026-09-16T00:00:00Z",
        "ttlMs":60000, "pollIntervalMs":1,
    });
    if status == "input_required" {
        result["inputRequests"] = json!({"roots":{"method":"roots/list"}});
    }
    result
}

fn failure_at(failure: Option<(usize, Failure)>, round: usize) -> Option<Failure> {
    failure.and_then(|(selected, failure)| (selected == round).then_some(failure))
}

async fn exercise(streams: [bool; 4], events: bool, failure: Option<(usize, Failure)>) {
    let cx = Cx::current().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("https://{}", listener.local_addr().unwrap());
    let url = |text: &str| CanonicalHttpUrl::parse(text).unwrap();
    let resource = url(&format!("{issuer}/mcp?tenant=one"));
    let config = OAuthClientConfiguration::from_trusted_endpoints(
        issuer.clone(), url(&format!("{issuer}/authorize")), url(&format!("{issuer}/token")),
        resource.clone(), "native-client", vec![],
    ).unwrap()
        .with_extra_root_certificate(Certificate::from_pem(ROOT).unwrap().remove(0)).unwrap()
        .with_resource_root_certificate(Certificate::from_pem(ROOT).unwrap().remove(0)).unwrap()
        .with_authorization_timeout(Duration::from_secs(10)).unwrap();
    let acceptor = TlsAcceptorBuilder::new(
        CertificateChain::from_pem(LEAF).unwrap(), PrivateKey::from_pem(KEY).unwrap(),
    ).alpn_protocols(vec![b"http/1.1".to_vec()]).build().unwrap();
    let observed: [_; 4] = std::array::from_fn(|_| McpRequestCancellation::new());
    let rounds = failure.map_or(4, |(round, _)| round + 1);
    let follow_up = !matches!(failure, Some((_, Failure::Revoke | Failure::Close
        | Failure::SnapshotRevoke | Failure::ResolverRevokeConstructor
        | Failure::ResolverRevokePending)));

    let application = async {
        let callback_issuer = issuer.clone();
        let session = ManagedOAuthSession::authorize(
            &cx, OAuthClient::new(config), OAuthSessionPolicy::default(),
            move |authorization| {
                let fields = form_fields(authorization.query().unwrap());
                assert_eq!(fields["code_challenge_method"], "S256");
                let redirect = fields["redirect_uri"].clone();
                let state = fields["state"].clone();
                async move {
                    let (address, path) = redirect.strip_prefix("http://").unwrap().split_once('/').unwrap();
                    // Owned: TcpStream::connect is `A: ToSocketAddrs + Send + 'static`, so a
                    // borrow of `redirect` cannot satisfy it (E0597). Mirrors the working
                    // sibling fixture in managed/client/tests.rs.
                    let (address, path) = (address.to_owned(), path.to_owned());
                    let mut callback = asupersync::net::TcpStream::connect(address.clone()).await
                        .map_err(|_| OAuthError::BrowserLaunchFailed)?;
                    callback.write_all(format!(
                        "GET /{path}?code=fixture-code&state={}&iss={} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n",
                        form_component(&state), form_component(&callback_issuer),
                    ).as_bytes()).await.map_err(|_| OAuthError::BrowserLaunchFailed)?;
                    Ok(())
                }
            },
        ).await.unwrap();
        let original = session.credential(&cx).await.unwrap();
        let capabilities = serde_json::from_value(json!({"roots":{}})).unwrap();
        let mut metadata = serde_json::to_value(FinalRequestMeta::new(capabilities)).unwrap();
        metadata["progressToken"] = json!("owned");
        let records = if matches!(failure, Some((_, Failure::RecordLimit))) { 2 } else { 8 };
        let client = ManagedTasksClient::new(
            session.clone(), serde_json::from_value(metadata).unwrap(),
            ManagedTasksLimits::new(8192, 8192, records, Duration::from_secs(15)).unwrap(),
        ).unwrap();
        let cancellation = McpRequestCancellation::new();
        let policy = ManagedTaskDriverPolicy::new(
            Duration::from_millis(1), Duration::from_secs(15), 3, 1, 1, 8192,
        ).unwrap();
        let id_pairs = std::cell::Cell::new(0_i64);
        let (mut resolutions, mut snapshots, mut notifications) = (0, 0, 0);
        let resolver_polls = std::cell::Cell::new(0);
        let host_polls = &resolver_polls;
        let host_bearer = original.credential();
        let next_ids = || {
            let ids = sequential_ids(1 + 2 * id_pairs.get());
            id_pairs.set(id_pairs.get() + 1);
            Ok(ids)
        };
        let resolve = |requests: fastmcp_protocol::tasks_extension::TaskInputRequests| {
            resolutions += 1;
            assert_eq!(requests.keys().map(String::as_str).collect::<Vec<_>>(), ["roots"]);
            let selected = failure_at(failure, 0);
            match selected {
                Some(Failure::ResolverCancelConstructor) => { cancellation.cancel(); }
                Some(Failure::ResolverRevokeConstructor) => { host_bearer.revoke(); }
                _ => {}
            }
            async move {
                host_polls.set(host_polls.get() + 1);
                if matches!(selected, Some(Failure::ResolverRevokePending)) {
                    host_bearer.revoke();
                    // No result and no self-wake: the response credential's
                    // guard must stop this pending host work on the same poll.
                    std::future::pending::<()>().await;
                }
                Ok(ManagedTaskInputAction::Respond(
                    serde_json::from_value(json!({"roots":{"roots":[]}})).unwrap(),
                ))
            }
        };
        let observe = |_: &Task| {
            snapshots += 1;
            if matches!(failure_at(failure, 0), Some(Failure::SnapshotRevoke)) {
                original.credential().revoke();
            }
            Ok(())
        };
        let result = if events {
            let mut drive = Box::pin(client.drive_task_with_events(
                &cx, &cancellation, TaskId::parse("task-one").unwrap(), policy,
                next_ids, resolve, observe,
                |notification| {
                    assert!(matches!(notification, ServerNotification::Progress(_)));
                    let round = usize::try_from(id_pairs.get() - 1).unwrap();
                    notifications += 1;
                    observed[round].cancel();
                    match failure_at(failure, round) {
                        Some(Failure::Decline) => return false,
                        Some(Failure::Cancel) => { cancellation.cancel(); }
                        Some(Failure::Revoke) => { original.credential().revoke(); }
                        Some(Failure::Close) => session.close(),
                        _ => {}
                    }
                    true
                },
            ));
            if let Some((round, Failure::Abandon)) = failure {
                poll_fn(|task| {
                    assert!(drive.as_mut().poll(task).is_pending());
                    if observed[round].is_cancel_requested() { Poll::Ready(()) } else { Poll::Pending }
                }).await;
                drop(drive);
                None
            } else {
                Some(drive.await)
            }
        } else {
            Some(client.drive_task_with_cancellation(
                &cx, &cancellation, TaskId::parse("task-one").unwrap(), policy,
                next_ids, resolve, observe,
            ).await)
        };

        match failure {
            None => {
                assert!(matches!(result.unwrap().unwrap(), ManagedTaskRunOutcome::Terminal(task)
                    if matches!(*task, Task::Cancelled(_))));
                // The unchanged input snapshot after the ACK is observed but
                // neither resolved nor submitted a second time.
                assert_eq!((id_pairs.get(), resolutions, snapshots), (4, 1, 3));
                assert_eq!(resolver_polls.get(), 1);
                assert_eq!(notifications, if events { streams.iter().filter(|s| **s).count() } else { 0 });
            }
            Some((round, failure)) => {
                assert_eq!(id_pairs.get(), (round + 1) as i64);
                if matches!(failure, Failure::SnapshotRevoke | Failure::ResolverCancelConstructor
                    | Failure::ResolverRevokeConstructor | Failure::ResolverRevokePending)
                {
                    assert_eq!(round, 0);
                    assert_eq!(snapshots, 1);
                    assert_eq!(resolutions, usize::from(!matches!(failure, Failure::SnapshotRevoke)));
                    assert_eq!(resolver_polls.get(), usize::from(matches!(failure, Failure::ResolverRevokePending)),
                        "constructor-time refusal must drop the returned host future without polling it");
                    assert_eq!(notifications, usize::from(events && streams[0]));
                } else {
                    assert_eq!(resolutions, round);
                    assert_eq!(snapshots, round);
                    assert_eq!(notifications, round + if matches!(failure, Failure::RecordLimit) { 2 } else { 1 });
                }
                if matches!(failure, Failure::Abandon) {
                    assert!(result.is_none());
                } else {
                    let error = result.unwrap().err().expect("failed stream must not publish a snapshot/ACK");
                    match failure {
                        Failure::Decline => assert!(matches!(error, ManagedTaskDriverError::AbortedByHost)),
                        Failure::Cancel | Failure::ResolverCancelConstructor => assert!(matches!(error, ManagedTaskDriverError::Task(
                            ManagedTasksError::Session(OAuthSessionError::Cancelled)))),
                        Failure::Revoke | Failure::SnapshotRevoke | Failure::ResolverRevokeConstructor
                        | Failure::ResolverRevokePending => assert!(matches!(error, ManagedTaskDriverError::Task(
                            ManagedTasksError::Session(OAuthSessionError::LoginRequired)))),
                        Failure::Close => assert!(matches!(error, ManagedTaskDriverError::Task(
                            ManagedTasksError::Session(OAuthSessionError::Closed)))),
                        Failure::Trailing => assert!(matches!(error, ManagedTaskDriverError::Task(
                            ManagedTasksError::InvalidResponse))),
                        Failure::Missing => assert!(matches!(error, ManagedTaskDriverError::Task(
                            ManagedTasksError::MissingTerminal))),
                        Failure::BadProgress => assert!(matches!(error, ManagedTaskDriverError::Task(
                            ManagedTasksError::InvalidProgress))),
                        Failure::RecordLimit => assert!(matches!(error, ManagedTaskDriverError::Task(
                            ManagedTasksError::RecordLimit))),
                        Failure::Abandon => unreachable!(),
                    }
                }
            }
        }
        assert!(cx.checkpoint().is_ok());
        if follow_up {
            // Request-local cancellation/refusal/drop did not poison the login.
            // This request is deliberate, not a replay of the failed operation.
            let mut call = client.request(&cx, sequential_ids(41),
                ManagedTaskRequest::Get(TaskId::parse("task-one").unwrap())).await.unwrap();
            assert!(matches!(call.next_event(&cx).await.unwrap(),
                Some(ManagedTaskEvent::Snapshot(snapshot)) if matches!(snapshot.task, Task::Cancelled(_))));
            assert!(call.next_event(&cx).await.unwrap().is_none());
            assert!(!session.inner.closed.is_cancel_requested());
        }
    };

    let peer = async {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = acceptor.accept(socket).await.unwrap();
        let form = read_token_form(&mut socket).await;
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["resource"], resource.as_str());
        assert_eq!(form["code"], "fixture-code");
        assert_eq!(form["code_verifier"].len(), 64);
        json_reply(&mut socket, &json!({
            "access_token":"reviewed-task-token", "token_type":"Bearer", "expires_in":120,
        })).await;
        drop(socket);
        for round in 0..rounds {
            let id = 1 + 2 * round as i64;
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            reviewed_discovery(&mut socket, id).await;
            drop(socket);
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let (fields, body) = read_request(&mut socket).await;
            let method = if round == 1 { TASK_UPDATE } else { TASK_GET };
            assert_eq!(body["id"], id + 1);
            assert_eq!(body["method"], method, "no replay, creation, cancellation or extra poll");
            assert_eq!(body["params"]["taskId"], "task-one");
            assert_eq!(header(&fields, "authorization"), Some("Bearer reviewed-task-token"));
            assert!(projected_fields(&fields).is_empty());
            assert!(admit(&fields, &body, header(&fields, "mcp-name")));
            assert!(!admit(&fields, &body, None));
            if round == 1 {
                assert_eq!(body["params"]["inputResponses"], json!({"roots":{"roots":[]}}));
            } else { assert!(body["params"].get("inputResponses").is_none()); }
            let result = if round == 1 { json!({"resultType":"complete"}) }
                else { snapshot(if round == 3 { "cancelled" } else { "input_required" }) };
            let reply = json!({"jsonrpc":"2.0", "id":id + 1, "result":result});
            if !streams[round] {
                json_reply(&mut socket, &reply).await;
                continue;
            }
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").await.unwrap();
            chunk(&mut socket, &format!("data: {PROGRESS}\r\n\r\n")).await;
            if events {
                // In particular, an update's ACK does not exist until its
                // progress was observed through the PUBLIC driver callback.
                observed[round].cancelled().await;
            }
            let selected = failure_at(failure, round);
            if matches!(selected, Some(Failure::Decline | Failure::Cancel | Failure::Revoke
                | Failure::Close | Failure::Abandon))
            {
                let mut byte = [0];
                assert!(!matches!(socket.read(&mut byte).await, Ok(n) if n > 0),
                    "stopped driver must release a silent response");
                continue;
            }
            let mut data = String::new();
            if matches!(selected, Some(Failure::BadProgress | Failure::RecordLimit)) {
                let progress = if matches!(selected, Some(Failure::RecordLimit)) { 2 } else { 1 };
                let second = json!({"jsonrpc":"2.0", "method":"notifications/progress",
                    "params":{"progressToken":"owned", "progress":progress}});
                data.push_str(&format!("data: {second}\r\n\r\n"));
            }
            if !matches!(selected, Some(Failure::Missing)) {
                data.push_str(&format!("data: {reply}\r\n\r\n"));
            }
            if matches!(selected, Some(Failure::Trailing)) {
                data.push_str(&format!("data: {PROGRESS}\r\n\r\n"));
            }
            let tail = if data.is_empty() { "0\r\n\r\n".to_owned() }
                else { format!("{:X}\r\n{data}\r\n0\r\n\r\n", data.len()) };
            socket.write_all(tail.as_bytes()).await.unwrap();
            socket.flush().await.unwrap();
        }
        if follow_up {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            reviewed_discovery(&mut socket, 41).await;
            drop(socket);
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let (fields, body) = read_request(&mut socket).await;
            assert_eq!(body["id"], 42);
            assert_eq!(body["method"], TASK_GET);
            assert!(admit(&fields, &body, header(&fields, "mcp-name")));
            json_reply(&mut socket, &json!({"jsonrpc":"2.0", "id":42, "result":snapshot("cancelled")})).await;
        }
    };
    pair(application, peer).await;
    assert!(listener.poll_accept(&mut Context::from_waker(Waker::noop())).is_pending(),
        "driver must not leave another automatic request or credential refresh");
}

fn run(future: impl Future<Output = ()>) {
    let runtime = RuntimeBuilder::current_thread().with_reactor(create_reactor().unwrap())
        .build().unwrap();
    runtime.block_on(async {
        let cx = Cx::current().unwrap();
        asupersync::time::timeout_at(cx.now().saturating_add_nanos(30_000_000_000), future)
            .await.expect("bounded public managed Task event fixture");
    });
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}

#[test]
fn managed_driver_delivers_get_and_update_progress_without_repeating_acknowledged_inputs() {
    for events in [false, true] {
        for streams in [[false; 4], [true; 4], [true, false, true, false]] {
            run(exercise(streams, events, None));
        }
    }
}

#[test]
fn managed_driver_retires_streams_without_publishing_failed_gets_or_update_acks() {
    for round in [0, 1] {
        for failure in [Failure::Decline, Failure::Cancel, Failure::Revoke, Failure::Close,
            Failure::Abandon, Failure::Trailing, Failure::Missing, Failure::BadProgress, Failure::RecordLimit]
        {
            run(exercise([true; 4], true, Some((round, failure))));
        }
    }
}

#[test]
fn managed_driver_guards_snapshot_and_resolver_authority_on_both_entrypoints() {
    for events in [false, true] {
        for sse in [false, true] {
            for failure in [Failure::SnapshotRevoke, Failure::ResolverCancelConstructor,
                Failure::ResolverRevokeConstructor, Failure::ResolverRevokePending]
            {
                run(exercise([sse; 4], events, Some((0, failure))));
            }
        }
    }
}
