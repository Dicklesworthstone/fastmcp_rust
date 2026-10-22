//! Scripted exchanges exercise the production driver and real caller timers.
//! These are not live-issuer, browser, TLS or conformance qualifications.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

use asupersync::Budget;
use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::{TimerDriverHandle, VirtualClock};
use serde_json::{Value, json};

use super::*;

type Error = DeviceAuthorizationError;
fn url(value: &str) -> CanonicalHttpUrl { CanonicalHttpUrl::parse(value).unwrap() }
fn client() -> DeviceAuthorizationClient {
    DeviceAuthorizationClient::from_trusted_endpoints(
        url("https://issuer.example/device"), url("https://issuer.example/token"),
        url("https://issuer.example/"), url("https://resource.example/mcp"),
        "native-client", vec!["read".to_owned(), "write".to_owned()],
    ).unwrap()
}
fn device() -> Value {
    json!({"device_code":"device-secret", "user_code":"ABCD-EFGH",
        "verification_uri":"https://issuer.example/activate", "expires_in":100, "interval":2})
}
fn token() -> Value {
    json!({"access_token":"access-secret", "token_type":"Bearer", "expires_in":60,
        "refresh_token":"refresh-secret", "scope":"read"})
}
fn bytes(value: &Value) -> Vec<u8> { serde_json::to_vec(value).unwrap() }
fn reply(status: u16, value: Value) -> Result<ExchangeResponse, Error> {
    Ok(ExchangeResponse { status, body: bytes(&value) })
}
fn verify(_: DeviceVerification) -> impl Future<Output = Result<(), Error>> { async { Ok(()) } }
fn once<F: Future>(f: Pin<&mut F>) -> Poll<F::Output> {
    f.poll(&mut Context::from_waker(Waker::noop()))
}

struct Seen { at: Time, endpoint: String, body: Vec<u8> }
struct Script {
    responses: VecDeque<Result<ExchangeResponse, Error>>,
    seen: Arc<Mutex<Vec<Seen>>>,
    delay_first: Option<(Arc<VirtualClock>, u64)>,
}
impl Script {
    fn new(responses: impl IntoIterator<Item = Result<ExchangeResponse, Error>>) -> Self {
        Self { responses: responses.into_iter().collect(), seen: Arc::new(Mutex::new(Vec::new())), delay_first: None }
    }
}
impl FormExchange for Script {
    fn post<'a>(&'a mut self, cx: &'a Cx, endpoint: &'a CanonicalHttpUrl, body: Vec<u8>) -> ExchangeFuture<'a> {
        assert_eq!(Cx::current().unwrap().task_id(), cx.task_id());
        self.seen.lock().unwrap().push(Seen { at: cx.now(), endpoint: endpoint.as_str().to_owned(), body });
        Box::pin(async move {
            if let Some((clock, delay)) = self.delay_first.take() { clock.advance(delay); }
            self.responses.pop_front().expect("unexpected replay or extra endpoint contact")
        })
    }
}

fn runtime(test: impl FnOnce(&Cx, &Arc<VirtualClock>, &TimerDriverHandle)) {
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
    let runtime = RuntimeBuilder::current_thread().blocking_threads(0, 0)
        .with_timer_driver(timer.clone()).build().unwrap();
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    test(&cx, &clock, &timer);
    assert_eq!(timer.pending_count(), 0, "scope must retire every timer");
    drop(cx);
    assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
}
fn advance(clock: &VirtualClock, seconds: u64) { clock.advance(seconds * 1_000_000_000); }

#[test]
fn configuration_requires_explicit_https_endpoints_origin_and_scope_bounds() {
    for endpoint in ["http://issuer.example/device", "https://user@issuer.example/device", "https://issuer.example/device?q=1", "https://issuer.example/device#part"] {
        assert_eq!(DeviceAuthorizationClient::from_trusted_endpoints(url(endpoint), url("https://issuer.example/token"), url("https://issuer.example/"), url("https://resource.example/mcp"), "client", vec![]).err(), Some(Error::InvalidConfiguration));
    }
    for scopes in [vec!["read read".into()], vec!["read".into(), "read".into()], vec!["".into()], vec!["a".repeat(257)]] {
        assert!(DeviceAuthorizationClient::from_trusted_endpoints(url("https://issuer.example/device"), url("https://issuer.example/token"), url("https://issuer.example/"), url("https://resource.example/mcp"), "client", scopes).is_err());
    }
    assert!(client().resource().as_str().ends_with("/mcp"));
    assert!(DeviceAuthorizationPolicy::new(Duration::ZERO, Duration::from_secs(1), 1, Duration::from_secs(1)).is_err());
    assert!(DeviceAuthorizationPolicy::new(Duration::from_secs(1), Duration::ZERO, 1, Duration::from_secs(1)).is_err());
    assert!(DeviceAuthorizationPolicy::new(Duration::from_secs(1), Duration::from_secs(1), 0, Duration::from_secs(1)).is_err());
}

#[test]
fn device_response_defaults_to_five_seconds_and_preserves_verification_values() {
    let mut response = device();
    response.as_object_mut().unwrap().remove("interval");
    response["verification_uri_complete"] = json!("https://issuer.example/activate?user_code=ABCD-EFGH");
    let (prompt, secret, interval, lifetime) = wire::device(&client(), &bytes(&response)).unwrap();
    assert_eq!(interval, Duration::from_secs(5));
    assert_eq!(lifetime, Duration::from_secs(100));
    assert_eq!(secret.as_str(), "device-secret");
    assert_eq!(prompt.user_code(), "ABCD-EFGH");
    assert_eq!(prompt.verification_uri().as_str(), "https://issuer.example/activate");
    assert!(prompt.verification_uri_complete().unwrap().as_str().ends_with("ABCD-EFGH"));
}

#[test]
fn device_response_cannot_redirect_user_to_an_untrusted_origin() {
    for field in ["verification_uri", "verification_uri_complete"] {
        for uri in ["http://issuer.example/activate", "https://other.example/activate", "https://issuer.example:444/activate", "https://user@issuer.example/activate", "https://issuer.example/activate#code"] {
            let mut value = device(); value[field] = json!(uri);
            assert_eq!(wire::device(&client(), &bytes(&value)).err(), Some(Error::UntrustedVerificationUri));
        }
    }
    assert!(wire::device(&client(), &bytes(&device())).is_ok());
}

#[test]
fn device_expiry_interval_codes_and_explicit_null_are_strict() {
    for (field, value) in [("expires_in", json!(0)), ("expires_in", json!(-1)), ("interval", json!(0)), ("interval", json!(null)), ("device_code", json!("")), ("user_code", json!("x\n")), ("verification_uri_complete", json!(null)), ("expires_in", json!(1.5)), ("error", json!("denied"))] {
        let mut changed = device(); changed[field] = value;
        assert!(wire::device(&client(), &bytes(&changed)).is_err(), "field {field}");
    }
    for malformed in [b"[]".as_slice(), br#"{"device_code":"one","device_code":"two"}"#, br#"{"unknown":1,"unknown":2}"#] {
        assert!(wire::device(&client(), malformed).is_err());
    }
    assert!(wire::device(&client(), &vec![b' '; wire::MAX_RESPONSE_BYTES + 1]).is_err());
}

#[test]
fn token_admission_bounds_scope_expiry_and_exact_resource() {
    let client = client();
    let started = Instant::now();
    let credential = wire::credentials(&client, &client.scopes, &bytes(&token()), started).unwrap();
    assert_eq!(credential.scopes(), ["read"]);
    assert!(credential.has_refresh_token());
    assert_eq!(credential.expires_at(), started + Duration::from_secs(60));
    assert!(credential.bearer_credential().authorization_for_target(client.resource()).is_some());
    assert!(credential.bearer_credential().authorization_for_target(&url("https://resource.example/other")).is_none());
    for (field, value) in [("scope", json!("read admin")), ("expires_in", json!(0)), ("refresh_token", json!(null)), ("token_type", json!("DPoP")), ("access_token", json!("invalid token")), ("scope", json!("read read")), ("scope", json!(null)), ("error", json!("authorization_pending"))] {
        let mut changed = token(); changed[field] = value;
        assert!(wire::credentials(&client, &client.scopes, &bytes(&changed), started).is_err());
    }
    let mut absent = token(); absent.as_object_mut().unwrap().remove("scope");
    assert_eq!(wire::credentials(&client, &client.scopes, &bytes(&absent), started).unwrap().scopes(), client.scopes);
}

#[test]
fn only_explicit_pending_and_slow_down_on_http_400_permit_polling() {
    assert_eq!(wire::poll_response(400, br#"{"error":"authorization_pending"}"#).unwrap(), wire::PollResponse::Pending);
    assert_eq!(wire::poll_response(400, br#"{"error":"slow_down"}"#).unwrap(), wire::PollResponse::SlowDown);
    assert_eq!(wire::poll_response(400, br#"{"error":"access_denied"}"#).err(), Some(Error::AccessDenied));
    assert_eq!(wire::poll_response(400, br#"{"error":"expired_token"}"#).err(), Some(Error::ExpiredCode));
    for body in [br#"{"error":"invalid_grant"}"#.as_slice(), br#"{"error":"authorization_pending","access_token":"injected"}"#, br#"{"error":"slow_down","error":"authorization_pending"}"#] {
        assert!(wire::poll_response(400, body).is_err());
    }
    for status in [302, 401, 429, 500, 503] { assert!(wire::poll_response(status, br#"{"error":"authorization_pending"}"#).is_err()); }
    assert!(wire::credentials(&client(), &[], br#"{"error":"authorization_pending"}"#, Instant::now()).is_err());
}

#[test]
fn forms_escape_every_value_and_never_put_device_codes_in_urls() {
    let encoded = wire::form(&[("client_id", "a b&c=+"), ("device_code", "secret/?%")]).unwrap();
    assert_eq!(encoded, b"client_id=a+b%26c%3D%2B&device_code=secret%2F%3F%25");
    assert!(wire::form(&[("code", &"%".repeat(32 * 1024))]).is_err());
    assert!(!format!("{:?}", client()).contains("issuer.example"));
}

#[test]
fn response_headers_reject_duplicate_media_type_and_compression() {
    assert!(wire::headers(&[("Content-Type".into(), "application/json; charset=\"UTF-8\"".into())]).is_ok());
    for headers in [vec![], vec![("Content-Type".into(), "text/html".into())], vec![("Content-Type".into(), "application/json".into()), ("content-type".into(), "application/json".into())], vec![("Content-Type".into(), "application/json".into()), ("Content-Encoding".into(), "gzip".into())]] {
        assert_eq!(wire::headers(&headers), Err(Error::InvalidResponse));
    }
}

#[test]
fn schedule_keeps_slow_down_increases_and_checks_limits_before_the_next_poll() {
    let mut schedule = PollSchedule { interval: Duration::from_secs(5), polls: 0, maximum: 3 };
    let end = Time::from_nanos(100_000_000_000);
    assert_eq!(schedule.next(Time::ZERO, end).unwrap(), Time::from_nanos(5_000_000_000));
    schedule.slow_down().unwrap();
    assert_eq!(schedule.next(Time::from_nanos(5_000_000_000), end).unwrap(), Time::from_nanos(15_000_000_000));
    schedule.slow_down().unwrap();
    assert_eq!(schedule.next(Time::from_nanos(15_000_000_000), end).unwrap(), Time::from_nanos(30_000_000_000));
    assert_eq!(schedule.next(Time::ZERO, end), Err(Error::PollLimitExceeded));
    let mut schedule = PollSchedule { interval: Duration::from_secs(5), polls: 0, maximum: 3 };
    assert_eq!(schedule.next(Time::ZERO, Time::from_nanos(5_000_000_000)), Err(Error::TimedOut));
    assert_eq!(schedule.polls, 0);
}

#[test]
fn production_loop_obeys_interval_and_slow_down_and_presents_only_once() {
    runtime(|cx, clock, _| {
        let client = client(); let cancellation = McpRequestCancellation::new();
        let mut script = Script::new([reply(200, device()), reply(400, json!({"error":"authorization_pending"})), reply(400, json!({"error":"slow_down"})), reply(200, token())]);
        let seen = script.seen.clone(); let presentations = AtomicUsize::new(0);
        let mut run = Box::pin(client.authorize_using(cx, &cancellation, |prompt| {
            presentations.fetch_add(1, Ordering::SeqCst);
            assert_eq!(prompt.user_code(), "ABCD-EFGH");
            verify(prompt)
        }, &mut script));
        assert!(once(run.as_mut()).is_pending()); assert_eq!(seen.lock().unwrap().len(), 1);
        advance(clock, 1); assert!(once(run.as_mut()).is_pending()); assert_eq!(seen.lock().unwrap().len(), 1);
        advance(clock, 1); assert!(once(run.as_mut()).is_pending()); assert_eq!(seen.lock().unwrap().len(), 2);
        advance(clock, 2); assert!(once(run.as_mut()).is_pending()); assert_eq!(seen.lock().unwrap().len(), 3);
        advance(clock, 6); assert!(once(run.as_mut()).is_pending()); assert_eq!(seen.lock().unwrap().len(), 3);
        advance(clock, 1);
        let Poll::Ready(Ok(credential)) = once(run.as_mut()) else { panic!("expected admitted grant"); };
        assert_eq!(credential.scopes(), ["read"]);
        drop(run);
        assert_eq!(presentations.load(Ordering::SeqCst), 1);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.iter().map(|call| call.at.as_nanos()).collect::<Vec<_>>(), [0, 2_000_000_000, 4_000_000_000, 11_000_000_000]);
        for call in &seen[1..] {
            assert_eq!(call.endpoint, "https://issuer.example/token");
            let body = std::str::from_utf8(&call.body).unwrap();
            assert!(body.contains("device_code=device-secret"));
            assert!(body.contains("resource=https%3A%2F%2Fresource.example%2Fmcp"));
        }
    });
}

#[test]
fn denial_unknown_errors_and_transport_failures_never_repeat_an_exchange() {
    for result in [reply(400, json!({"error":"access_denied"})), reply(400, json!({"error":"invalid_client"})), Err(Error::TransportFailed)] {
        runtime(|cx, clock, _| {
            let client = client(); let cancellation = McpRequestCancellation::new();
            let mut script = Script::new([reply(200, device()), result]); let seen = script.seen.clone();
            let mut run = Box::pin(client.authorize_using(cx, &cancellation, verify, &mut script));
            assert!(once(run.as_mut()).is_pending()); advance(clock, 2);
            assert!(matches!(once(run.as_mut()), Poll::Ready(Err(_))));
            drop(run); assert_eq!(seen.lock().unwrap().len(), 2);
        });
    }
}

#[test]
fn failed_presentation_and_post_presentation_cancellation_prevent_all_token_polls() {
    for cancel in [false, true] {
        runtime(|cx, _, _| {
            let client = client(); let cancellation = McpRequestCancellation::new();
            let mut script = Script::new([reply(200, device())]); let seen = script.seen.clone();
            let mut run = Box::pin(client.authorize_using(cx, &cancellation, |_| async {
                if cancel { cancellation.cancel(); Ok(()) } else { Err(Error::AccessDenied) }
            }, &mut script));
            let Poll::Ready(Err(error)) = once(run.as_mut()) else { panic!("presentation must stop flow"); };
            assert_eq!(error, if cancel { Error::Cancelled } else { Error::PresentationFailed });
            drop(run); assert_eq!(seen.lock().unwrap().len(), 1);
        });
    }
}

struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

#[test]
fn cancellation_wakes_a_quiet_presentation_and_retires_its_future() {
    runtime(|cx, _, _| {
        struct Dropped(Arc<AtomicUsize>);
        impl Drop for Dropped { fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); } }
        let client = client(); let cancellation = McpRequestCancellation::new();
        let mut script = Script::new([reply(200, device())]); let seen = script.seen.clone();
        let drops = Arc::new(AtomicUsize::new(0)); let guard = Dropped(drops.clone());
        let mut run = Box::pin(client.authorize_using(cx, &cancellation, |_| async move {
            let _guard = guard; std::future::pending::<Result<(), Error>>().await
        }, &mut script));
        let wakes = Arc::new(Wakes(AtomicUsize::new(0))); let waker = Waker::from(wakes.clone());
        assert!(run.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        let before = wakes.0.load(Ordering::SeqCst);
        cancellation.cancel(); assert!(wakes.0.load(Ordering::SeqCst) > before);
        assert!(matches!(once(run.as_mut()), Poll::Ready(Err(Error::Cancelled))));
        drop(run); assert_eq!(drops.load(Ordering::SeqCst), 1); assert_eq!(seen.lock().unwrap().len(), 1);
    });
}

#[test]
fn cancellation_or_drop_while_waiting_never_starts_an_early_poll() {
    for cancel in [false, true] {
        runtime(|cx, _, _| {
            let client = client(); let cancellation = McpRequestCancellation::new();
            let mut script = Script::new([reply(200, device())]); let seen = script.seen.clone();
            let mut run = Box::pin(client.authorize_using(cx, &cancellation, verify, &mut script));
            assert!(once(run.as_mut()).is_pending());
            if cancel { cancellation.cancel(); assert!(matches!(once(run.as_mut()), Poll::Ready(Err(Error::Cancelled)))); }
            drop(run); assert_eq!(seen.lock().unwrap().len(), 1);
        });
    }
}

#[test]
fn issuer_expiry_includes_the_time_spent_acquiring_the_device_code() {
    runtime(|cx, clock, _| {
        let client = client(); let cancellation = McpRequestCancellation::new();
        let mut response = device(); response["expires_in"] = json!(4);
        let mut script = Script::new([reply(200, response)]);
        script.delay_first = Some((clock.clone(), 5_000_000_000));
        let mut run = Box::pin(client.authorize_using(cx, &cancellation, |_| async { panic!("expired code was presented") }, &mut script));
        assert!(matches!(once(run.as_mut()), Poll::Ready(Err(Error::TimedOut))));
        drop(run);
    });
}

#[test]
fn ambient_effect_denial_refuses_before_contact_or_presentation() {
    runtime(|cx, _, _| {
        for restriction in [CapSet::<true, false, true, true, true>::MASK, CapSet::<true, true, false, true, true>::MASK, CapSet::<true, true, true, false, true>::MASK, CapSet::<true, true, true, true, false>::MASK] {
            let client = client(); let cancellation = McpRequestCancellation::new();
            let mut script = Script::new([]); let seen = script.seen.clone();
            let mut run = Box::pin(client.authorize_using(cx, &cancellation, |_| async { panic!("denied effect reached host") }, &mut script));
            let _ambient = Cx::set_current(Some(cx.clone())); let _restriction = Cx::push_restriction(restriction);
            assert!(matches!(once(run.as_mut()), Poll::Ready(Err(Error::RuntimeUnavailable))));
            drop(run); assert!(seen.lock().unwrap().is_empty());
        }
    });
}

#[test]
fn local_revoke_clears_refresh_and_all_access_clones_without_network() {
    let client = client();
    let mut grant = wire::credentials(&client, &client.scopes, &bytes(&token()), Instant::now()).unwrap();
    let clone = grant.bearer_credential().clone();
    grant.revoke(); grant.revoke();
    assert!(!grant.has_refresh_token()); assert!(clone.is_revoked());
    assert!(clone.authorization_for_target(client.resource()).is_none());
}
