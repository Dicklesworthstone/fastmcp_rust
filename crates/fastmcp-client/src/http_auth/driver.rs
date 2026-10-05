//! Caller-owned browser driving for native OAuth authorization.
//!
//! The native launch callback returns before the callback listener is polled.
//! A host that follows an authorization redirect all the way to the loopback
//! HTTP response must therefore be polled alongside authorization, not awaited
//! inside that launch callback. This module owns both futures in one scope.
//! It creates no runtime, task, thread, browser process, or network policy.
//!
//! Driver completion is not authorization. Only the native operation admits
//! the issuer/state-bound callback and redeems its S256 code. An authorization
//! terminal drops the driver; a driver failure drops authorization. Neither is
//! replayed. Host drivers must keep their work in the returned future and must
//! not log authorization URLs or submit consent on a user's behalf.

use std::fmt;
use std::future::{Future, Ready, poll_fn, ready};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::Poll;
use std::time::Duration;

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::time::Sleep;
use asupersync::types::Time;

use super::CanonicalHttpUrl;
use super::managed::{ManagedOAuthSession, OAuthSessionError, OAuthSessionPolicy};
use super::oauth::{OAuthClient, OAuthCredentials, OAuthError};

/// Direct-redirect driving for explicitly pre-authorized HTTPS issuers.
pub mod redirect;

/// The operation's original error or a sanitized driver/lifetime failure.
/// Diagnostic formatting deliberately does not print the operation's error.
pub enum AuthorizationDriverError<E> {
    Operation(E),
    Driver(OAuthError),
}

impl<E> fmt::Debug for AuthorizationDriverError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Operation(_) => f.write_str("AuthorizationDriverError::Operation(..)"),
            Self::Driver(error) => f
                .debug_tuple("AuthorizationDriverError::Driver")
                .field(error)
                .finish(),
        }
    }
}

impl<E> fmt::Display for AuthorizationDriverError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Operation(_) => f.write_str("OAuth authorization operation failed"),
            Self::Driver(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl<E> std::error::Error for AuthorizationDriverError<E> {}

#[derive(Default)]
struct LaunchSlot {
    url: Option<CanonicalHttpUrl>,
    retired: bool,
}

/// Single-use launcher passed to an authorization operation.
///
/// Pass `move |url| launcher.launch(url)` to an existing native OAuth,
/// discovery, registration, or managed-session authorization method. The URL
/// is handed to this scope's driver, never logged or treated as a credential.
/// This value intentionally has no Clone, Debug, or serialization surface.
pub struct AuthorizationLauncher {
    slot: Arc<Mutex<LaunchSlot>>,
}

impl AuthorizationLauncher {
    /// Enqueues one HTTPS authorization URL without waiting for a callback.
    /// The original operation remains responsible for endpoint trust and PKCE.
    pub fn launch(self, url: CanonicalHttpUrl) -> Ready<Result<(), OAuthError>> {
        ready(self.submit(url))
    }

    fn submit(self, url: CanonicalHttpUrl) -> Result<(), OAuthError> {
        if url.scheme() != "https" || url.has_userinfo() || url.fragment().is_some() {
            return Err(OAuthError::BrowserLaunchFailed);
        }
        let mut slot = self
            .slot
            .lock()
            .map_err(|_| OAuthError::BrowserLaunchFailed)?;
        if slot.retired || slot.url.is_some() {
            return Err(OAuthError::BrowserLaunchFailed);
        }
        slot.url = Some(url);
        Ok(())
    }
}

struct LaunchScope(Arc<Mutex<LaunchSlot>>);

impl Drop for LaunchScope {
    fn drop(&mut self) {
        // Poison recovery is used only to retire custody, never to continue
        // an authorization. A launcher retained by a host cannot resurrect it.
        let mut slot = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        slot.retired = true;
        slot.url = None;
    }
}

fn check_lifetime(cx: &Cx, deadline: Time) -> Result<(), OAuthError> {
    if cx.checkpoint().is_err() {
        Err(OAuthError::Cancelled)
    } else if cx.now() >= deadline {
        Err(OAuthError::TimedOut)
    } else {
        Ok(())
    }
}

/// Runs an existing authorization operation alongside one host-owned driver.
///
/// `operation` gets a one-use launcher. `driver` is constructed only after that
/// launcher receives the native operation's HTTPS URL. It may await the full
/// callback HTTP response. The native callback listener remains polled while
/// it does so. A driver returning `Ok(())` does not complete authorization; the
/// operation must still admit and redeem the grant. Once the operation returns,
/// any remaining driver work is dropped before this function returns.
///
/// `timeout` is nonzero and at most fifteen minutes. One absolute deadline
/// covers discovery, launch, callback, and redemption; the caller's earlier
/// deadline and the native operation's own bounds still win. Cancellation
/// wakes the scope even when both futures are quiet. Dropping the scope also
/// retires a launcher the host retained. No automatic retry or consent occurs.
/// The caller supplies the runtime and all authorization/driver policy.
pub async fn with_authorization_driver<T, E, O, OF, D, DF>(
    cx: &Cx,
    timeout: Duration,
    operation: O,
    driver: D,
) -> Result<T, AuthorizationDriverError<E>>
where
    O: FnOnce(AuthorizationLauncher) -> OF,
    OF: Future<Output = Result<T, E>>,
    D: FnOnce(CanonicalHttpUrl) -> DF,
    DF: Future<Output = Result<(), OAuthError>>,
{
    if cx.checkpoint().is_err() {
        return Err(AuthorizationDriverError::Driver(OAuthError::Cancelled));
    }
    if timeout.is_zero() || timeout > Duration::from_mins(15) {
        return Err(AuthorizationDriverError::Driver(
            OAuthError::InvalidConfiguration,
        ));
    }
    if cx.timer_driver().is_none() {
        return Err(AuthorizationDriverError::Driver(
            OAuthError::RuntimeTimerUnavailable,
        ));
    }
    let nanos = u64::try_from(timeout.as_nanos())
        .map_err(|_| AuthorizationDriverError::Driver(OAuthError::InvalidConfiguration))?;
    let deadline = cx
        .now()
        .as_nanos()
        .checked_add(nanos)
        .map(Time::from_nanos)
        .ok_or(AuthorizationDriverError::Driver(
            OAuthError::InvalidConfiguration,
        ))?;
    let deadline = cx
        .budget()
        .deadline
        .map_or(deadline, |parent| parent.min(deadline));
    check_lifetime(cx, deadline).map_err(AuthorizationDriverError::Driver)?;

    let scope = LaunchScope(Arc::new(Mutex::new(LaunchSlot::default())));
    let launcher = AuthorizationLauncher {
        slot: Arc::clone(&scope.0),
    };
    let operation = {
        let _caller = Cx::set_current(Some(cx.clone()));
        operation(launcher)
    };
    let mut operation = std::pin::pin!(operation);
    let mut driver_factory = Some(driver);
    let mut driving: Option<std::pin::Pin<Box<DF>>> = None;
    let sleep = {
        let _caller = Cx::set_current(Some(cx.clone()));
        Sleep::new(deadline)
    };
    let mut sleep = std::pin::pin!(sleep);
    let (_cancel_sender, mut cancel_receiver) = oneshot::channel::<()>();
    let mut cancelled = std::pin::pin!(cancel_receiver.recv(cx));
    poll_fn(|task| {
        if let Err(error) = check_lifetime(cx, deadline) {
            return Poll::Ready(Err(AuthorizationDriverError::Driver(error)));
        }
        let _caller = Cx::set_current(Some(cx.clone()));
        if cancelled.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(AuthorizationDriverError::Driver(OAuthError::Cancelled)));
        }
        if sleep.as_mut().poll(task).is_ready() {
            return Poll::Ready(Err(AuthorizationDriverError::Driver(OAuthError::TimedOut)));
        }
        // A known driver failure wins before any further authorization work.
        if let Some(future) = driving.as_mut() {
            match future.as_mut().poll(task) {
                Poll::Ready(Err(_)) => {
                    let error = check_lifetime(cx, deadline)
                        .err()
                        .unwrap_or(OAuthError::BrowserLaunchFailed);
                    return Poll::Ready(Err(AuthorizationDriverError::Driver(error)));
                }
                Poll::Ready(Ok(())) => driving = None,
                Poll::Pending => {}
            }
        }
        // A driver can cancel the caller or consume the remaining budget in
        // this very poll. Do not poll a token-redemption future afterward.
        if let Err(error) = check_lifetime(cx, deadline) {
            return Poll::Ready(Err(AuthorizationDriverError::Driver(error)));
        }
        if let Poll::Ready(result) = operation.as_mut().poll(task) {
            if let Err(error) = check_lifetime(cx, deadline) {
                return Poll::Ready(Err(AuthorizationDriverError::Driver(error)));
            }
            return Poll::Ready(result.map_err(AuthorizationDriverError::Operation));
        }
        if driver_factory.is_some() {
            let url = match scope.0.lock() {
                Ok(mut slot) => slot.url.take(),
                Err(_) => {
                    return Poll::Ready(Err(AuthorizationDriverError::Driver(
                        OAuthError::BrowserLaunchFailed,
                    )));
                }
            };
            if let Some(url) = url {
                if let Err(error) = check_lifetime(cx, deadline) {
                    return Poll::Ready(Err(AuthorizationDriverError::Driver(error)));
                }
                if let Some(factory) = driver_factory.take() {
                    driving = Some(Box::pin(factory(url)));
                    // The newly installed driver has not registered a waker yet.
                    // Schedule one poll rather than spawning or busy-waiting.
                    task.waker().wake_by_ref();
                }
            }
        }
        Poll::Pending
    })
    .await
}

impl OAuthClient {
    /// Authorizes with a driver allowed to await the loopback callback response.
    /// Uses the same HTTPS, issuer, state, PKCE, and token-admission path as
    /// [`Self::authorize`]; only ownership and polling of the host driver differ.
    pub async fn authorize_with_browser_driver<D, F>(
        &self,
        cx: &Cx,
        timeout: Duration,
        driver: D,
    ) -> Result<OAuthCredentials, OAuthError>
    where
        D: FnOnce(CanonicalHttpUrl) -> F,
        F: Future<Output = Result<(), OAuthError>>,
    {
        with_authorization_driver(
            cx,
            timeout,
            |launcher| self.authorize(cx, move |url| launcher.launch(url)),
            driver,
        )
        .await
        .map_err(|error| match error {
            AuthorizationDriverError::Operation(error)
            | AuthorizationDriverError::Driver(error) => error,
        })
    }
}

impl ManagedOAuthSession {
    /// Creates a rotating-grant owner using a jointly-polled browser driver.
    /// A successful driver alone never creates a session. Native login and
    /// session custody remain those of [`Self::authorize`].
    pub async fn authorize_with_browser_driver<D, F>(
        cx: &Cx,
        client: OAuthClient,
        policy: OAuthSessionPolicy,
        timeout: Duration,
        driver: D,
    ) -> Result<Self, OAuthSessionError>
    where
        D: FnOnce(CanonicalHttpUrl) -> F,
        F: Future<Output = Result<(), OAuthError>>,
    {
        with_authorization_driver(
            cx,
            timeout,
            |launcher| Self::authorize(cx, client, policy, move |url| launcher.launch(url)),
            driver,
        )
        .await
        .map_err(|error| match error {
            AuthorizationDriverError::Operation(error) => error,
            AuthorizationDriverError::Driver(OAuthError::Cancelled) => OAuthSessionError::Cancelled,
            AuthorizationDriverError::Driver(OAuthError::TimedOut) => OAuthSessionError::TimedOut,
            AuthorizationDriverError::Driver(error) => OAuthSessionError::OAuth(error),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn run<F: Future>(future: F) -> F::Output {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .with_reactor(asupersync::runtime::reactor::create_reactor().unwrap())
            .blocking_threads(0, 8)
            .build()
            .unwrap();
        runtime.block_on(future)
    }

    fn url() -> CanonicalHttpUrl {
        CanonicalHttpUrl::parse("https://issuer.example/authorize?state=private-canary").unwrap()
    }

    struct Dropped(Arc<AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn driver_and_callback_can_wait_for_each_other_without_detached_work() {
        run(async {
            let cx = Cx::current().unwrap();
            let stage = Arc::new(AtomicUsize::new(0));
            let calls = AtomicUsize::new(0);
            let operation_stage = Arc::clone(&stage);
            let result = with_authorization_driver(
                &cx,
                Duration::from_secs(1),
                |launcher| async move {
                    launcher.launch(url()).await?;
                    poll_fn(|task| {
                        if operation_stage.load(Ordering::SeqCst) == 1 {
                            operation_stage.store(2, Ordering::SeqCst);
                            task.waker().wake_by_ref();
                        }
                        if operation_stage.load(Ordering::SeqCst) == 3 {
                            Poll::Ready(Ok::<_, OAuthError>(42))
                        } else {
                            Poll::Pending
                        }
                    })
                    .await
                },
                |received| {
                    assert_eq!(received, url());
                    calls.fetch_add(1, Ordering::SeqCst);
                    async {
                        stage.store(1, Ordering::SeqCst);
                        poll_fn(|task| {
                            if stage.load(Ordering::SeqCst) == 2 {
                                stage.store(3, Ordering::SeqCst);
                                task.waker().wake_by_ref();
                                Poll::Ready(Ok(()))
                            } else {
                                Poll::Pending
                            }
                        })
                        .await
                    }
                },
            )
            .await;
            assert_eq!(result.unwrap(), 42);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(stage.load(Ordering::SeqCst), 3);
        });
    }

    #[test]
    fn driver_failure_drops_pending_authorization() {
        run(async {
            let cx = Cx::current().unwrap();
            let dropped = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&dropped);
            let result = with_authorization_driver(
                &cx,
                Duration::from_secs(1),
                |launcher| async move {
                    let _guard = Dropped(flag);
                    launcher.launch(url()).await?;
                    std::future::pending::<Result<(), OAuthError>>().await
                },
                |_| ready(Err(OAuthError::TransportFailed)),
            )
            .await;
            assert!(matches!(
                result,
                Err(AuthorizationDriverError::Driver(
                    OAuthError::BrowserLaunchFailed
                ))
            ));
            assert!(dropped.load(Ordering::SeqCst));
        });
    }

    #[test]
    fn authorization_terminal_drops_a_quiet_driver_on_success_and_failure() {
        for succeeds in [false, true] {
            run(async {
                let cx = Cx::current().unwrap();
                let started = Arc::new(AtomicBool::new(false));
                let dropped = Arc::new(AtomicBool::new(false));
                let driver_started = Arc::clone(&started);
                let flag = Arc::clone(&dropped);
                let result = with_authorization_driver(
                    &cx,
                    Duration::from_secs(1),
                    |launcher| async {
                        launcher.launch(url()).await?;
                        poll_fn(|_| {
                            if started.load(Ordering::SeqCst) {
                                Poll::Ready(if succeeds {
                                    Ok(7)
                                } else {
                                    Err(OAuthError::AuthorizationDenied)
                                })
                            } else {
                                Poll::Pending
                            }
                        })
                        .await
                    },
                    |_| async move {
                        let _guard = Dropped(flag);
                        driver_started.store(true, Ordering::SeqCst);
                        std::future::pending::<Result<(), OAuthError>>().await
                    },
                )
                .await;
                if succeeds {
                    assert_eq!(result.unwrap(), 7);
                } else {
                    assert!(matches!(
                        result,
                        Err(AuthorizationDriverError::Operation(
                            OAuthError::AuthorizationDenied
                        ))
                    ));
                }
                assert!(dropped.load(Ordering::SeqCst));
            });
        }
    }

    #[test]
    fn preflight_failure_does_not_construct_the_driver() {
        run(async {
            let cx = Cx::current().unwrap();
            let calls = AtomicUsize::new(0);
            let result = with_authorization_driver(
                &cx,
                Duration::from_secs(1),
                |_| ready(Err::<(), _>(OAuthError::InvalidConfiguration)),
                |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    ready(Ok(()))
                },
            )
            .await;
            assert!(matches!(
                result,
                Err(AuthorizationDriverError::Operation(
                    OAuthError::InvalidConfiguration
                ))
            ));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn deadline_drops_both_quiet_futures_even_after_driver_launch() {
        run(async {
            let cx = Cx::current().unwrap();
            let operation_dropped = Arc::new(AtomicBool::new(false));
            let driver_dropped = Arc::new(AtomicBool::new(false));
            let op_flag = Arc::clone(&operation_dropped);
            let driver_flag = Arc::clone(&driver_dropped);
            let result = with_authorization_driver(
                &cx,
                Duration::from_millis(100),
                |launcher| async move {
                    let _guard = Dropped(op_flag);
                    launcher.launch(url()).await?;
                    std::future::pending::<Result<(), OAuthError>>().await
                },
                |_| async move {
                    let _guard = Dropped(driver_flag);
                    std::future::pending::<Result<(), OAuthError>>().await
                },
            )
            .await;
            assert!(matches!(
                result,
                Err(AuthorizationDriverError::Driver(OAuthError::TimedOut))
            ));
            assert!(operation_dropped.load(Ordering::SeqCst));
            assert!(driver_dropped.load(Ordering::SeqCst));
        });
    }

    #[test]
    fn invalid_timeout_prevents_operation_and_driver_construction() {
        run(async {
            let cx = Cx::current().unwrap();
            let operations = AtomicUsize::new(0);
            let drivers = AtomicUsize::new(0);
            for timeout in [Duration::ZERO, Duration::from_secs(901)] {
                let result = with_authorization_driver(
                    &cx,
                    timeout,
                    |_| {
                        operations.fetch_add(1, Ordering::SeqCst);
                        ready(Ok::<(), OAuthError>(()))
                    },
                    |_| {
                        drivers.fetch_add(1, Ordering::SeqCst);
                        ready(Ok(()))
                    },
                )
                .await;
                assert!(matches!(
                    result,
                    Err(AuthorizationDriverError::Driver(
                        OAuthError::InvalidConfiguration
                    ))
                ));
            }
            assert_eq!(operations.load(Ordering::SeqCst), 0);
            assert_eq!(drivers.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn dropped_scope_retires_a_launcher_retained_by_the_host() {
        run(async {
            let cx = Cx::current().unwrap();
            let retained = Arc::new(Mutex::new(None));
            let slot = Arc::clone(&retained);
            let future = with_authorization_driver(
                &cx,
                Duration::from_secs(1),
                |launcher| async move {
                    *slot.lock().unwrap() = Some(launcher);
                    std::future::pending::<Result<(), OAuthError>>().await
                },
                |_| ready(Ok(())),
            );
            let mut future = Box::pin(future);
            poll_fn(|task| {
                assert!(future.as_mut().poll(task).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(future);
            let launcher = retained.lock().unwrap().take().unwrap();
            assert_eq!(
                launcher.launch(url()).await,
                Err(OAuthError::BrowserLaunchFailed)
            );
        });
    }

    #[test]
    fn launcher_rejects_cleartext_and_ambiguous_targets_before_driver_effects() {
        for target in [
            "http://127.0.0.1/authorize",
            "https://user@issuer.example/authorize",
            "https://issuer.example/authorize#fragment",
        ] {
            run(async {
                let cx = Cx::current().unwrap();
                let calls = AtomicUsize::new(0);
                let result = with_authorization_driver(
                    &cx,
                    Duration::from_secs(1),
                    |launcher| async {
                        launcher
                            .launch(CanonicalHttpUrl::parse(target).unwrap())
                            .await
                    },
                    |_| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        ready(Ok(()))
                    },
                )
                .await;
                assert!(matches!(
                    result,
                    Err(AuthorizationDriverError::Operation(
                        OAuthError::BrowserLaunchFailed
                    ))
                ));
                assert_eq!(calls.load(Ordering::SeqCst), 0);
            });
        }
    }

    #[test]
    fn diagnostics_do_not_print_operation_secrets() {
        let error = AuthorizationDriverError::Operation("private-code-and-token");
        assert!(!format!("{error:?} {error}").contains("private-code-and-token"));
    }

    #[test]
    fn driver_completion_is_not_an_authorization_grant() {
        run(async {
            let cx = Cx::current().unwrap();
            let result = with_authorization_driver(
                &cx,
                Duration::from_millis(100),
                |launcher| async {
                    launcher.launch(url()).await?;
                    std::future::pending::<Result<(), OAuthError>>().await
                },
                |_| ready(Ok(())),
            )
            .await;
            assert!(matches!(
                result,
                Err(AuthorizationDriverError::Driver(OAuthError::TimedOut))
            ));
        });
    }

    #[test]
    fn cancellation_inside_driver_prevents_another_authorization_poll() {
        run(async {
            let cx = Cx::current().unwrap();
            let polls = AtomicUsize::new(0);
            let dropped = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&dropped);
            let result = with_authorization_driver(
                &cx,
                Duration::from_secs(1),
                |launcher| async {
                    let _guard = Dropped(flag);
                    launcher.launch(url()).await?;
                    poll_fn(|_| {
                        polls.fetch_add(1, Ordering::SeqCst);
                        Poll::<Result<(), OAuthError>>::Pending
                    })
                    .await
                },
                |_| async {
                    cx.set_cancel_requested(true);
                    Ok(())
                },
            )
            .await;
            assert!(matches!(
                result,
                Err(AuthorizationDriverError::Driver(OAuthError::Cancelled))
            ));
            assert_eq!(polls.load(Ordering::SeqCst), 1);
            assert!(dropped.load(Ordering::SeqCst));
        });
    }
}
