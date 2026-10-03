//! Public concurrent-grant regressions over the existing native TLS fixture.
//! All clients discover and acquire normally; no token or flight is injected.
//! The peer withholds its response until every tested follower has been polled,
//! making the overlapping requests deterministic instead of timing-dependent.

use super::*;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Wake, Waker};

async fn pending_once<F: Future + ?Sized>(mut future: Pin<&mut F>) {
    poll_fn(|task| {
        assert!(
            future.as_mut().poll(task).is_pending(),
            "operation must remain pending at this rendezvous"
        );
        Poll::Ready(())
    })
    .await;
}

async fn reached_issuer<F: Future + ?Sized>(
    cx: &Cx,
    mut future: Pin<&mut F>,
    notice: &mut oneshot::Receiver<()>,
) {
    let mut notice = std::pin::pin!(notice.recv(cx));
    poll_fn(|task| {
        assert!(future.as_mut().poll(task).is_pending());
        notice.as_mut().poll(task)
    })
    .await
    .unwrap();
}

async fn incoming(peer: &Peer, post: bool) -> TlsStream<TcpStream> {
    if post {
        post_token_request(peer, "service-client", "service-secret").await
    } else {
        peer.token_request().await
    }
}

#[derive(Clone, Copy)]
enum Rejection {
    InvalidToken,
    Denied,
    Lost,
}
async fn reject(socket: &mut TlsStream<TcpStream>, rejection: Rejection) {
    match rejection {
        Rejection::InvalidToken => {
            let mut document = ordinary_token();
            document["refresh_token"] = json!("private-rejected-grant");
            json_reply(socket, &document.to_string()).await;
        }
        Rejection::Denied => {
            let body = r#"{"error":"invalid_client","error_description":"private-issuer-detail"}"#;
            socket.write_all(format!("HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            socket.flush().await.unwrap();
        }
        Rejection::Lost => {} // Drop the accepted TLS connection without a reply.
    }
}
fn assert_leader_error(error: Error, rejection: Rejection) {
    assert!(!format!("{error:?} {error}").contains("private-"));
    match rejection {
        Rejection::InvalidToken => assert!(matches!(error, Error::InvalidToken)),
        Rejection::Denied => assert!(matches!(error, Error::TokenEndpointRejected)),
        Rejection::Lost => assert!(matches!(error, Error::Transport)),
    }
}

#[test]
fn failed_grant_does_not_turn_joined_callers_into_issuer_retries() {
    for post in [false, true] {
        for rejection in [Rejection::InvalidToken, Rejection::Denied, Rejection::Lost] {
            run_admission(|cx| async move {
                let peer = Peer::new().await;
                let client = discover(&peer, &cx, post).await;
                let (arrived, mut arrival) = oneshot::channel();
                let (release, mut released) = oneshot::channel();
                let server = async {
                    let mut socket = incoming(&peer, post).await;
                    arrived.send(&cx, ()).unwrap();
                    released.recv(&cx).await.unwrap();
                    reject(&mut socket, rejection).await;
                };
                let application = async {
                    let mut leader = Box::pin(client.credential(&cx));
                    reached_issuer(&cx, leader.as_mut(), &mut arrival).await;
                    let mut followers: Vec<_> =
                        (0..8).map(|_| Box::pin(client.credential(&cx))).collect();
                    for follower in &mut followers {
                        pending_once(follower.as_mut()).await;
                    }
                    release.send(&cx, ()).unwrap();
                    assert_leader_error(leader.await.err().unwrap(), rejection);
                    for follower in followers {
                        assert!(matches!(
                            follower.await,
                            Err(Error::ConcurrentAcquisitionFailed)
                        ));
                    }
                };
                pair(server, application).await;
                assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
                assert_eq!(peer.rpcs.load(Ordering::SeqCst), 0);
                peer.quiet();
                let body = ordinary_token().to_string();
                let ((), result) = pair(reply(&peer, post, &body), client.credential(&cx)).await;
                assert_eq!(
                    result.unwrap().generation(),
                    1,
                    "later explicit acquisition is not a follower retry"
                );
                core_succeeds(&peer, &cx, &client, "admitted-access").await;
                assert_eq!(peer.grants.load(Ordering::SeqCst), 2);
                assert!(cx.checkpoint().is_ok());
                client.close();
            });
        }
    }
}

struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn abandoned_leader_wakes_every_joiner_and_cannot_be_replaced_by_a_later_success() {
    for post in [false, true] {
        run_admission(|cx| async move {
            let peer = Peer::new().await;
            let client = discover(&peer, &cx, post).await;
            let (arrived, mut arrival) = oneshot::channel();
            let server = async {
                let socket = incoming(&peer, post).await;
                arrived.send(&cx, ()).unwrap();
                closed(socket).await;
            };
            let application = async {
                let mut leader = Box::pin(client.credential(&cx));
                reached_issuer(&cx, leader.as_mut(), &mut arrival).await;
                let mut followers: Vec<_> =
                    (0..8).map(|_| Box::pin(client.credential(&cx))).collect();
                let counters: Vec<_> = (0..followers.len())
                    .map(|_| Arc::new(WakeCount(AtomicUsize::new(0))))
                    .collect();
                for (follower, counter) in followers.iter_mut().zip(&counters) {
                    let waker = Waker::from(counter.clone());
                    assert!(
                        follower
                            .as_mut()
                            .poll(&mut Context::from_waker(&waker))
                            .is_pending()
                    );
                }
                let before: Vec<_> = counters
                    .iter()
                    .map(|counter| counter.0.load(Ordering::SeqCst))
                    .collect();
                drop(leader);
                for (counter, before) in counters.iter().zip(before) {
                    assert!(
                        counter.0.load(Ordering::SeqCst) > before,
                        "abandonment must actually wake EVERY registered public caller"
                    );
                }
                followers
            };
            let ((), followers) = pair(server, application).await;
            assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
            peer.quiet();
            // Deliberately finish a later explicit grant before observing the
            // original followers. They cannot adopt its result or re-elect.
            let body = ordinary_token().to_string();
            let ((), fresh) = pair(reply(&peer, post, &body), client.credential(&cx)).await;
            assert_eq!(fresh.unwrap().generation(), 1);
            for follower in followers {
                assert!(matches!(
                    follower.await,
                    Err(Error::ConcurrentAcquisitionFailed)
                ));
            }
            core_succeeds(&peer, &cx, &client, "admitted-access").await;
            assert_eq!(peer.grants.load(Ordering::SeqCst), 2);
            assert!(cx.checkpoint().is_ok());
            client.close();
        });
    }
}

#[test]
fn cancelled_and_dropped_joiners_release_capacity_without_stopping_the_leader() {
    for post in [false, true] {
        run_admission(|cx| async move {
            let peer = Peer::new().await;
            let client = discover(&peer, &cx, post).await;
            let (arrived, mut arrival) = oneshot::channel();
            let (release, mut released) = oneshot::channel();
            let server = async {
                let mut socket = incoming(&peer, post).await;
                arrived.send(&cx, ()).unwrap();
                released.recv(&cx).await.unwrap();
                json_reply(&mut socket, &ordinary_token().to_string()).await;
            };
            let application = async {
                let mut leader = Box::pin(client.credential(&cx));
                reached_issuer(&cx, leader.as_mut(), &mut arrival).await;
                let cancelled = McpRequestCancellation::new();
                let mut stopped = Box::pin(client.credential_with_cancellation(&cx, &cancelled));
                pending_once(stopped.as_mut()).await;
                let mut dropped = Box::pin(client.credential(&cx));
                pending_once(dropped.as_mut()).await;
                // The existing declared bound is 64, counting the elected
                // leader and every waiting caller, not just network sockets.
                let mut followers: Vec<_> =
                    (0..61).map(|_| Box::pin(client.credential(&cx))).collect();
                for follower in &mut followers {
                    pending_once(follower.as_mut()).await;
                }
                assert!(matches!(
                    client.credential(&cx).await,
                    Err(Error::Saturated)
                ));
                cancelled.cancel();
                assert!(matches!(
                    stopped.await,
                    Err(Error::Discovery(OAuthDiscoveryError::Cancelled))
                ));
                drop(dropped);
                for _ in 0..2 {
                    let mut replacement = Box::pin(client.credential(&cx));
                    pending_once(replacement.as_mut()).await;
                    followers.push(replacement);
                }
                assert!(matches!(
                    client.credential(&cx).await,
                    Err(Error::Saturated)
                ));
                release.send(&cx, ()).unwrap();
                let admitted = leader.await.unwrap();
                for follower in followers {
                    let snapshot = follower.await.unwrap();
                    assert_eq!(snapshot.generation(), admitted.generation());
                    assert_eq!(snapshot.expires_at(), admitted.expires_at());
                    assert_eq!(snapshot.scopes(), admitted.scopes());
                }
                assert_eq!(admitted.generation(), 1);
            };
            pair(server, application).await;
            assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
            assert_eq!(client.credential(&cx).await.unwrap().generation(), 1);
            core_succeeds(&peer, &cx, &client, "admitted-access").await;
            assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
            assert!(cx.checkpoint().is_ok());
            client.close();
        });
    }
}

#[test]
fn shared_renewal_handoffs_keep_the_new_generation_after_old_revocation() {
    for post in [false, true] {
        run_admission(|cx| async move {
            let peer = Peer::new().await;
            let client = discover(&peer, &cx, post).await;
            let mut first = ordinary_token();
            first["expires_in"] = json!(1);
            let body = first.to_string();
            let ((), old) = pair(reply(&peer, post, &body), client.credential(&cx)).await;
            let old = old.unwrap();
            let old_expiry = old.expires_at();
            asupersync::time::sleep(
                cx.now(),
                old_expiry.saturating_duration_since(Instant::now()) + Duration::from_millis(20),
            )
            .await;
            assert!(Instant::now() >= old_expiry);
            let (arrived, mut arrival) = oneshot::channel();
            let (release, mut released) = oneshot::channel();
            let server = async {
                let mut socket = incoming(&peer, post).await;
                arrived.send(&cx, ()).unwrap();
                released.recv(&cx).await.unwrap();
                let mut document = ordinary_token();
                document["access_token"] = json!("renewed-shared-access");
                json_reply(&mut socket, &document.to_string()).await;
            };
            let application = async {
                let mut leader = Box::pin(client.credential(&cx));
                reached_issuer(&cx, leader.as_mut(), &mut arrival).await;
                let mut followers: Vec<_> =
                    (0..8).map(|_| Box::pin(client.credential(&cx))).collect();
                for follower in &mut followers {
                    pending_once(follower.as_mut()).await;
                }
                release.send(&cx, ()).unwrap();
                let admitted = leader.await.unwrap();
                assert_eq!(admitted.generation(), 2);
                old.credential().revoke();
                for follower in followers {
                    let snapshot = follower.await.unwrap();
                    assert_eq!(snapshot.generation(), 2);
                    assert_eq!(snapshot.expires_at(), admitted.expires_at());
                    assert!(!snapshot.credential().is_revoked());
                }
            };
            pair(server, application).await;
            assert_eq!(old.generation(), 1);
            assert_eq!(old.expires_at(), old_expiry);
            assert_eq!(peer.grants.load(Ordering::SeqCst), 2);
            core_succeeds(&peer, &cx, &client, "renewed-shared-access").await;
            assert_eq!(peer.grants.load(Ordering::SeqCst), 2);
            client.close();
        });
    }
}

#[test]
fn owner_closure_wakes_all_joiners_and_never_dispatches_a_second_grant() {
    for post in [false, true] {
        run_admission(|cx| async move {
            let peer = Peer::new().await;
            let client = discover(&peer, &cx, post).await;
            let (arrived, mut arrival) = oneshot::channel();
            let server = async {
                let socket = incoming(&peer, post).await;
                arrived.send(&cx, ()).unwrap();
                closed(socket).await;
            };
            let application = async {
                let mut leader = Box::pin(client.credential(&cx));
                reached_issuer(&cx, leader.as_mut(), &mut arrival).await;
                let mut followers: Vec<_> =
                    (0..8).map(|_| Box::pin(client.credential(&cx))).collect();
                for follower in &mut followers {
                    pending_once(follower.as_mut()).await;
                }
                client.close();
                assert!(matches!(leader.await, Err(Error::Closed)));
                for follower in followers {
                    assert!(matches!(follower.await, Err(Error::Closed)));
                }
            };
            pair(server, application).await;
            assert_eq!(peer.grants.load(Ordering::SeqCst), 1);
            assert_eq!(peer.rpcs.load(Ordering::SeqCst), 0);
            assert!(matches!(client.credential(&cx).await, Err(Error::Closed)));
            assert!(cx.checkpoint().is_ok());
            peer.quiet();
        });
    }
}

#[test]
fn separately_discovered_clients_do_not_share_a_failed_flight_or_token() {
    for post in [false, true] {
        run_admission(|cx| async move {
            let peer = Peer::new().await;
            let first = discover(&peer, &cx, post).await;
            let second = discover(&peer, &cx, post).await;
            let (arrived, mut arrival) = oneshot::channel();
            let (release, mut released) = oneshot::channel();
            let server = async {
                let mut held = incoming(&peer, post).await;
                arrived.send(&cx, ()).unwrap();
                // The same configured issuer and registration serve an
                // independent client while the first client's flight is idle.
                let mut separate = incoming(&peer, post).await;
                json_reply(&mut separate, &ordinary_token().to_string()).await;
                drop(separate);
                released.recv(&cx).await.unwrap();
                reject(&mut held, Rejection::InvalidToken).await;
            };
            let application = async {
                let mut leader = Box::pin(first.credential(&cx));
                reached_issuer(&cx, leader.as_mut(), &mut arrival).await;
                let mut follower = Box::pin(first.credential(&cx));
                pending_once(follower.as_mut()).await;
                let independent = second.credential(&cx).await.unwrap();
                assert_eq!(independent.generation(), 1);
                release.send(&cx, ()).unwrap();
                assert!(matches!(leader.await, Err(Error::InvalidToken)));
                assert!(matches!(
                    follower.await,
                    Err(Error::ConcurrentAcquisitionFailed)
                ));
                first.close();
                assert!(!independent.credential().is_revoked());
            };
            pair(server, application).await;
            assert_eq!(peer.grants.load(Ordering::SeqCst), 2);
            assert_eq!(peer.gets.load(Ordering::SeqCst), 4);
            core_succeeds(&peer, &cx, &second, "admitted-access").await;
            assert_eq!(peer.grants.load(Ordering::SeqCst), 2);
            assert!(cx.checkpoint().is_ok());
            second.close();
        });
    }
}
