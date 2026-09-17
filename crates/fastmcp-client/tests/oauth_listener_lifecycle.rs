//! OAUTH-LISTENER-EXT — external-consumer proof of the shipped callback-listener
//! lifecycle.
//!
//! `bd-p6wg3`. This target exists because the lifecycle was previously proved
//! only from inside the crate. `dropping_public_login_future_closes_its_bound_callback_listener`
//! drives the public `OAuthClient::authorize`, but it lives in a
//! `#[cfg(test)] mod tests` inside `src/http_auth/oauth.rs`, and `cfg(test)`
//! behaviour cannot prove shipped behaviour (PL-3). So there was no
//! external-consumer proof of it anywhere.
//!
//! Everything here is reached the way a downstream crate reaches it. The only
//! names used are `fastmcp_client::http_auth::oauth::{OAuthClient,
//! OAuthClientConfiguration, OAuthError}`, `fastmcp_client::CanonicalHttpUrl`,
//! and the asupersync runtime — no private symbol, and no `use super::`.
//!
//! In particular the loopback address is recovered from the **authorization URL
//! handed to the caller's `launch_browser` callback**, which is the only place a
//! downstream consumer can observe it, and its `redirect_uri` is percent-decoded
//! by this file rather than by the crate's private `decode_form`.

use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::rc::Rc;
use std::task::Poll;

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use fastmcp_client::CanonicalHttpUrl;
use fastmcp_client::http_auth::oauth::{OAuthClient, OAuthClientConfiguration, OAuthError};

/// Guards against a pathological spin if the callback never fires. It cannot
/// rescue a genuine hang - nothing would re-poll us - but it turns a runaway
/// loop into a named failure instead of a silent stall.
const MAX_LOGIN_POLLS: u32 = 10_000;

fn url(value: &str) -> CanonicalHttpUrl {
    CanonicalHttpUrl::parse(value).expect("fixture endpoint is canonical")
}

/// Builds a configuration entirely from the public constructor.
fn configuration() -> OAuthClientConfiguration {
    OAuthClientConfiguration::from_trusted_endpoints(
        "https://issuer.example",
        url("https://issuer.example/authorize"),
        url("https://issuer.example/token"),
        url("https://mcp.example/mcp"),
        "oauth-listener-ext-client",
        vec!["tools:read".to_owned()],
    )
    .expect("the trusted-endpoint configuration is accepted")
}

/// Percent-decodes one query value.
///
/// Deliberately local: the crate's `decode_form` is private, and reaching for it
/// would make this an internal test wearing an external test's clothes.
fn percent_decode(value: &str) -> String {
    let mut out = Vec::new();
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'+' => out.push(b' '),
            b'%' => {
                let high = bytes.next().expect("a percent escape has two digits");
                let low = bytes.next().expect("a percent escape has two digits");
                let decode = |digit: u8| {
                    char::from(digit)
                        .to_digit(16)
                        .expect("a percent escape is hexadecimal") as u8
                };
                out.push(decode(high) * 16 + decode(low));
            }
            other => out.push(other),
        }
    }
    String::from_utf8(out).expect("the redirect target is UTF-8")
}

/// Extracts the loopback callback address from the authorization URL's
/// `redirect_uri`, using only the public `CanonicalHttpUrl::query`.
fn callback_address(authorization: &CanonicalHttpUrl) -> SocketAddr {
    let query = authorization
        .query()
        .expect("the authorization URL carries its parameters");
    let redirect = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("redirect_uri="))
        .map(percent_decode)
        .expect("the authorization URL names a redirect_uri");
    let authority = redirect
        .strip_prefix("http://")
        .expect("the loopback callback is cleartext by design")
        .split('/')
        .next()
        .expect("the redirect target has an authority");
    authority
        .parse()
        .expect("the callback authority is a socket address")
}

/// Asserts the loopback listener at `address` is CLOSED, not merely unreachable.
///
/// These are different claims, and the difference is the whole point. A
/// `TcpStream::connect` that fails proves only that nobody answered; a connect
/// that SUCCEEDS proves only that *somebody* is listening, never that *ours* is.
/// Test binaries in this workspace run hundreds of cases in parallel with many
/// ephemeral loopback binds, so a port freed a microsecond earlier can be handed
/// straight to a concurrent test and satisfy a connect against a listener with
/// nothing to do with OAuth.
///
/// Binding the same address inverts the evidence: a successful bind proves
/// NOBODY is listening, which is direct proof the descriptor was closed, and it
/// reclaims the port so nothing can occupy it mid-observation.
///
/// DO NOT add `SO_REUSEADDR` or `SO_REUSEPORT` to this bind. `SO_REUSEADDR` only
/// permits rebinding a port left in `TIME_WAIT` by an already-closed socket; it
/// does NOT permit two live listeners on one port, and that refusal is the
/// entire mechanism of this probe. `SO_REUSEPORT` does permit exactly that, so
/// setting it would let a leaked listener coexist with the probe bind and
/// silently turn this proof into a no-op.
///
/// No sleep, no retry, no timing tolerance: the close is synchronous in `Drop`,
/// so there is nothing to wait for and a tolerance would hide the very leak this
/// exists to catch.
/// SYNCHRONOUS ON PURPOSE. The previous form awaited asupersync's `bind`, and
/// that `.await` is a scheduling point: between `drop(login)` closing the
/// descriptor and the bind reaching the kernel, the runtime polls other tasks
/// and other harness threads get a full async round trip in which to claim the
/// just-freed ephemeral port. The failure that produces is indistinguishable
/// from the leak this exists to catch, and a test that only passes in isolation
/// lies in every wave. `std::net`'s blocking bind removes the await, making the
/// drop and the bind straight-line code with no yield between them. Theft is
/// not impossible - other OS threads still run - but the structural cause is
/// gone rather than tolerated, at no cost in sleep, retry or timing tolerance.
///
/// DO NOT reintroduce an `.await` between the drop and this bind.
///
/// The same argument and the same pair live at
/// `fastmcp-client/src/http_auth/oauth.rs` (`assert_listener_bound` /
/// `probe_listener_released`, with the same `RELEASE_TRIALS`) for the internal
/// unit test. They cannot share code across the crate boundary without putting
/// a test helper on the public surface, so if you change the concurrency
/// argument here, change it there. Both were changed together in the wave-50
/// repair; neither is the authority on its own.
/// What one release trial observed. `StillBound` is deliberately NOT a panic: a
/// single trial cannot distinguish a leak from a stolen port, and the caller
/// resolves that by repeating the whole experiment.
#[derive(Debug, PartialEq, Eq)]
enum ReleaseTrial {
    /// The bind succeeded, so nothing holds the port. The descriptor was
    /// closed. One such observation is conclusive on its own.
    Released,
    /// The port was still held. Either the listener leaked or a concurrent
    /// ephemeral bind won it inside the straight-line window.
    StillBound,
}

/// Number of independent release trials before a leak is declared.
///
/// Sized against the two hypotheses, not against a clock. A leaked listener
/// fails EVERY trial - the close is unconditional, so a leak is not a
/// probabilistic event. A thief must win a fresh, kernel-assigned ephemeral port
/// on each trial, so the chance of a clean run failing throughout is the
/// per-trial probability raised to the fifth power.
const RELEASE_TRIALS: usize = 5;

/// Runs ONE release trial and reports what it saw.
///
/// Everything the old assertion did, it still does: `std::net`'s blocking bind
/// with no `.await` between the drop and the syscall, no sleep, no timing
/// tolerance, no `SO_REUSEADDR`, no `SO_REUSEPORT`. Only the reporting changed -
/// an ambiguous single observation is returned rather than thrown, because it is
/// resolvable by repetition instead of by tolerance.
///
/// This is not a retry in the forbidden sense. A retry would re-observe THE SAME
/// port after a delay, which is the tolerance that would hide a slow close. Each
/// trial re-runs the entire experiment from a fresh `authorize` on a fresh
/// ephemeral port, so the trials are independent samples of one property.
///
/// The unexpected-errno arm still fails immediately and is never retried: an
/// unrecognised error is not a race.
fn probe_listener_released(address: SocketAddr) -> ReleaseTrial {
    match std::net::TcpListener::bind(address) {
        Ok(listener) => {
            drop(listener);
            ReleaseTrial::Released
        }
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => ReleaseTrial::StillBound,
        Err(error) => panic!(
            "the bind probe for {address} is INCONCLUSIVE ({error}); it proves neither closure \
             nor a leak and must not be read as either"
        ),
    }
}

/// Asserts the listener at `address` is STILL bound.
///
/// This is the control that gives the positive its meaning: a bind probe that
/// could never fail would prove nothing, so this proves the probe can in fact
/// observe a live listener.
/// Synchronous for the same reason as [`probe_listener_released`], though this
/// direction cannot be stolen in any case: we hold the port. It needs no trial
/// loop for that same reason - there is no race for it to lose.
fn assert_listener_still_bound(address: SocketAddr) {
    match std::net::TcpListener::bind(address) {
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
        Ok(_) => panic!(
            "{address} was rebindable while the public login future was still alive, so the \
             callback listener was released early - or this probe cannot detect a live listener \
             at all, which would make the released-case assertion vacuous"
        ),
        Err(error) => panic!(
            "the bind probe for {address} is INCONCLUSIVE ({error}); it proves neither that the \
             listener is live nor that it is closed"
        ),
    }
}

/// Drives the public `authorize` until its callback reports the bound address,
/// returning the still-live login future alongside it.
///
/// The future is returned rather than dropped so each case decides its own fate
/// for it; that choice is the single variable between the two tests here.
type LoginFuture<'client> = std::pin::Pin<
    Box<
        dyn Future<Output = Result<fastmcp_client::http_auth::oauth::OAuthCredentials, OAuthError>>
            + 'client,
    >,
>;

/// Drives the public `authorize` until its callback reports the bound address,
/// returning the still-live login future alongside it.
///
/// The future is returned rather than dropped so each case decides its own fate
/// for it; that choice is the single variable between the two tests here.
///
/// The address cell is an `Rc` rather than a borrowed local on purpose: the
/// closure is captured by the returned future, so borrowing a local here would
/// make that future outlive the thing it points at.
async fn login_until_bound<'client>(
    client: &'client OAuthClient,
    cx: &'client Cx,
) -> (LoginFuture<'client>, SocketAddr) {
    let bound: Rc<Cell<Option<SocketAddr>>> = Rc::new(Cell::new(None));
    let observed = Rc::clone(&bound);
    let mut login: LoginFuture<'client> = Box::pin(client.authorize(cx, move |authorization| {
        observed.set(Some(callback_address(&authorization)));
        async move { Ok(()) }
    }));

    let mut polls = 0_u32;
    let address = poll_fn(|task| {
        polls += 1;
        assert!(
            polls < MAX_LOGIN_POLLS,
            "the authorization URL never reached the caller's browser callback"
        );
        if let Poll::Ready(result) = login.as_mut().poll(task) {
            // The success arm deliberately does not format `result`.
            // `OAuthCredentials` has no `Debug` on purpose (oauth.rs:219-222) so
            // refresh-token bytes are not formattable; deriving it to enrich a
            // panic message would trade a shipped confidentiality property for
            // test convenience. Returning at all is the finding, and the arm
            // itself already reports which way it returned. `OAuthError` is
            // `Debug`, so the failure arm can name the cause.
            match result {
                Ok(_) => panic!(
                    "authorize completed successfully before its callback bound a listener"
                ),
                Err(error) => panic!(
                    "authorize failed before its callback bound a listener: {error:?}"
                ),
            }
        }
        match bound.get() {
            Some(address) => Poll::Ready(address),
            None => Poll::Pending,
        }
    })
    .await;
    (login, address)
}

#[test]
fn oauth_callback_listener_is_released_when_the_public_login_future_is_dropped() {
    RuntimeBuilder::current_thread()
        .build()
        .expect("the test owns its caller runtime")
        .block_on(async {
            let cx = Cx::current().expect("the caller runtime installs a current Cx");
            let client = OAuthClient::new(configuration());
            // Each iteration is a COMPLETE, independent experiment: its own
            // login, its own listener, its own kernel-assigned ephemeral port.
            // A leaked listener fails all of them; a port thief would have to
            // win a different port every time.
            let mut still_bound = Vec::new();
            let mut released = false;
            for _ in 0..RELEASE_TRIALS {
                let (login, address) = login_until_bound(&client, &cx).await;

                assert!(
                    address.ip().is_loopback(),
                    "the shipped client must bind its callback on loopback, observed {address}"
                );

                // The one variable: the caller abandons the login.
                drop(login);
                match probe_listener_released(address) {
                    ReleaseTrial::Released => {
                        released = true;
                        break;
                    }
                    ReleaseTrial::StillBound => still_bound.push(address),
                }
            }

            assert!(
                released,
                "the public callback listener was still bound after the login future was \
                 dropped in all {RELEASE_TRIALS} independent trials, on these separately \
                 assigned ephemeral ports: {still_bound:?}. Each trial issued its bind with no \
                 await between it and the drop. A concurrent test can steal one freed port; it \
                 cannot steal {RELEASE_TRIALS} different ones in a row. The listener leaked."
            );
        });
}

#[test]
fn oauth_callback_listener_remains_bound_while_the_public_login_future_is_held() {
    RuntimeBuilder::current_thread()
        .build()
        .expect("the test owns its caller runtime")
        .block_on(async {
            let cx = Cx::current().expect("the caller runtime installs a current Cx");
            let client = OAuthClient::new(configuration());
            let (login, address) = login_until_bound(&client, &cx).await;

            assert!(address.ip().is_loopback());

            // The one changed variable against the case above: the login future
            // is HELD rather than dropped. Everything else - the configuration,
            // the client, the callback, the address - is identical.
            assert_listener_still_bound(address);

            // Held across the probe on purpose; dropping it earlier would make
            // this the other case.
            drop(login);
        });
}
