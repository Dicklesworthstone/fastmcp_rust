//! Bounded Argon2id work for the built-in issuer's confidential clients.
//!
//! The synchronous issuer API waits on a dedicated Asupersync blocking pool;
//! the native HTTP adapter must itself run that API on a blocking lane. No
//! password hashing falls back to execution on an async worker. A cancelled
//! waiter does not release a running job's reservation or publish its result.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use argon2::password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};
use argon2::{Algorithm, Argon2, Params, Version};
use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::runtime::{BlockingPool, BlockingTaskHandle};
use fastmcp_core::{OAUTH_CLIENT_SECRET_SALT_BYTES, draw_oauth_client_secret_salt};
use zeroize::Zeroizing;

use super::{ClientSecret, MAX_OAUTH_CLIENT_CREDENTIAL_BYTES, OAuthError};

const MEMORY_KIB: u32 = 64 * 1_024;
const ITERATIONS: u32 = 3;
const LANES: u32 = 1;
const OUTPUT_BYTES: usize = 32;
const MAX_PHC_BYTES: usize = 128;
// At most 128 MiB of Argon2 memory is live, plus bounded queued inputs.
const MAX_WORKERS: usize = 2;
const MAX_ADMITTED: usize = 32;
const MAX_STARTS_PER_SECOND: usize = 64;
const MAX_WAIT: Duration = Duration::from_secs(30);
const WAIT_SLICE: Duration = Duration::from_millis(10);

// A syntactically valid verifier with no known secret. Unknown-client and
// wrong-method requests perform the same bounded KDF as real registrations.
const DUMMY_PHC: &str = concat!(
    "$argon2id$v=19$m=65536,t=3,p=1$WlpaWlpaWlpaWlpaWlpaWg$",
    "paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaU"
);

#[derive(Clone)]
pub(super) struct ClientSecretVerifier {
    phc: Arc<str>,
}

impl std::fmt::Debug for ClientSecretVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientSecretVerifier([redacted])")
    }
}

impl ClientSecretVerifier {
    pub(super) fn create(secret: &ClientSecret) -> Result<Self, OAuthError> {
        admit_secret(secret.as_bytes())?;
        // Entropy failure happens before any job or client-store mutation.
        let salt = draw_oauth_client_secret_salt().map_err(|_| unavailable())?;
        let secret = Zeroizing::new(secret.as_bytes().to_vec());
        executor().execute(Cx::current(), move || {
            // Argon2 0.6's explicit-salt API encodes the PHC salt from these
            // exact core-owned bytes; it never invokes an ambient RNG.
            let phc = algorithm()?
                .hash_password_with_salt(&secret, salt.as_bytes())
                .map_err(|_| unavailable())?
                .to_string();
            admit_phc(&phc)?;
            Ok(Self { phc: phc.into() })
        })
    }

    pub(super) fn dummy() -> Self {
        Self {
            phc: DUMMY_PHC.into(),
        }
    }

    pub(super) fn verify(&self, provided: &[u8]) -> Result<bool, OAuthError> {
        admit_secret(provided)?;
        // PasswordVerifier reads parameters from the PHC, not from the
        // configured Argon2 instance. Validate BEFORE allocation/dispatch.
        let hash = admit_phc(&self.phc)?;
        let provided = Zeroizing::new(provided.to_vec());
        executor().execute(Cx::current(), move || {
            match algorithm()?.verify_password(&provided, &hash) {
                Ok(()) => Ok(true),
                Err(argon2::password_hash::Error::PasswordInvalid) => Ok(false),
                Err(_) => Err(unavailable()),
            }
        })
    }
}

fn unavailable() -> OAuthError {
    OAuthError::TemporarilyUnavailable("client credential verification is unavailable".to_owned())
}

fn admit_secret(secret: &[u8]) -> Result<(), OAuthError> {
    if secret.len() > MAX_OAUTH_CLIENT_CREDENTIAL_BYTES {
        return Err(OAuthError::InvalidClient(
            super::OAUTH_CLIENT_AUTHENTICATION_ERROR.to_owned(),
        ));
    }
    Ok(())
}

fn algorithm() -> Result<Argon2<'static>, OAuthError> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, LANES, Some(OUTPUT_BYTES))
        .map_err(|_| unavailable())?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn admit_phc(phc: &str) -> Result<PasswordHash, OAuthError> {
    if phc.len() > MAX_PHC_BYTES {
        return Err(unavailable());
    }
    let hash = PasswordHash::new(phc).map_err(|_| unavailable())?;
    // The supported range is deliberately one reviewed policy. Do not accept
    // arbitrary imported cost parameters or silent weaker legacy verifiers.
    if hash.algorithm.as_str() != "argon2id"
        || hash.version != Some(19)
        || hash.params.iter().count() != 3
        || hash.params.get_decimal("m") != Some(MEMORY_KIB)
        || hash.params.get_decimal("t") != Some(ITERATIONS)
        || hash.params.get_decimal("p") != Some(LANES)
        || hash
            .salt
            .as_ref()
            .is_none_or(|salt| salt.as_ref().len() != OAUTH_CLIENT_SECRET_SALT_BYTES)
        || hash
            .hash
            .as_ref()
            .is_none_or(|output| output.len() != OUTPUT_BYTES)
        || hash.to_string() != phc
    {
        return Err(unavailable());
    }
    Ok(hash)
}

struct AdmissionState {
    live: usize,
    starts: usize,
    window: Instant,
}

struct Permit(Arc<Mutex<AdmissionState>>);

impl Drop for Permit {
    fn drop(&mut self) {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.live -= 1;
    }
}

struct TaskGuard(BlockingTaskHandle);

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

struct KdfExecutor {
    pool: BlockingPool,
    admission: Arc<Mutex<AdmissionState>>,
}

fn executor() -> &'static KdfExecutor {
    static EXECUTOR: OnceLock<KdfExecutor> = OnceLock::new();
    EXECUTOR.get_or_init(KdfExecutor::new)
}

impl KdfExecutor {
    fn new() -> Self {
        Self {
            pool: BlockingPool::new(0, MAX_WORKERS),
            admission: Arc::new(Mutex::new(AdmissionState {
                live: 0,
                starts: 0,
                window: Instant::now(),
            })),
        }
    }

    fn reserve(&self) -> Result<Permit, OAuthError> {
        let mut state = self.admission.try_lock().map_err(|_| unavailable())?;
        let now = Instant::now();
        if now.duration_since(state.window) >= Duration::from_secs(1) {
            state.window = now;
            state.starts = 0;
        }
        if state.live >= MAX_ADMITTED || state.starts >= MAX_STARTS_PER_SECOND {
            return Err(unavailable());
        }
        state.live += 1;
        state.starts += 1;
        Ok(Permit(Arc::clone(&self.admission)))
    }

    fn execute<T, F>(&self, cx: Option<Cx>, work: F) -> Result<T, OAuthError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, OAuthError> + Send + 'static,
    {
        let started = Instant::now();
        let check = || check_wait(cx.as_ref(), started);
        check()?;
        let permit = self.reserve()?;
        let worker_cx = cx.clone();
        let (sender, mut receiver) = oneshot::channel();
        let task = TaskGuard(self.pool.spawn(move || {
            // Captures, including this reservation, remain owned until the
            // pool retires even if the waiter has already timed out/dropped.
            let _lane = fastmcp_core::runtime::enter_blocking_lane();
            let result = check_wait(worker_cx.as_ref(), started)
                .and_then(|()| work())
                .and_then(|value| check_wait(worker_cx.as_ref(), started).map(|()| value));
            drop(permit);
            let _ = sender.send_blocking(result);
        }));
        loop {
            check()?;
            match receiver.try_recv() {
                Ok(result) => {
                    // A deadline/cancellation racing publication still wins.
                    check()?;
                    return result;
                }
                Err(oneshot::TryRecvError::Closed) => return Err(unavailable()),
                Err(oneshot::TryRecvError::Empty) => {
                    let remaining = MAX_WAIT.saturating_sub(started.elapsed());
                    let _ = task.0.wait_timeout(WAIT_SLICE.min(remaining));
                }
            }
        }
    }
}

fn check_wait(cx: Option<&Cx>, started: Instant) -> Result<(), OAuthError> {
    if started.elapsed() >= MAX_WAIT
        || cx.is_some_and(|cx| {
            cx.checkpoint().is_err()
                || cx
                    .budget()
                    .deadline
                    .is_some_and(|deadline| cx.now() >= deadline)
        })
    {
        return Err(unavailable());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn argon2id_verifier_uses_fresh_salt_and_rejects_one_byte_wrong_secret() {
        let secret = ClientSecret::new("correct-client-secret".to_owned());
        let first = ClientSecretVerifier::create(&secret).unwrap();
        let second = ClientSecretVerifier::create(&secret).unwrap();
        assert_ne!(first.phc, second.phc);
        assert!(first.phc.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"));
        assert!(first.verify(b"correct-client-secret").unwrap());
        assert!(!first.verify(b"correct-client-secreu").unwrap());
        assert!(!format!("{first:?}").contains("correct-client-secret"));
        assert!(!format!("{first:?}").contains(first.phc.as_ref()));
    }

    #[test]
    fn phc_admission_rejects_cost_algorithm_version_salt_and_output_changes() {
        admit_phc(DUMMY_PHC).unwrap();
        for corrupted in [
            DUMMY_PHC.replace("m=65536", "m=4294967295"),
            DUMMY_PHC.replace("m=65536", "m=8192"),
            DUMMY_PHC.replace("t=3", "t=4294967295"),
            DUMMY_PHC.replace("p=1", "p=2"),
            DUMMY_PHC.replace("argon2id", "argon2i"),
            DUMMY_PHC.replace("v=19", "v=16"),
            DUMMY_PHC.replace("p=1$", "p=1,keyid=YQ$"),
            DUMMY_PHC.replace("WlpaWlpaWlpaWlpaWlpaWg", "WlpaWlpaWlo"),
            DUMMY_PHC[..DUMMY_PHC.len() - 4].to_owned(),
            "x".repeat(MAX_PHC_BYTES + 1),
        ] {
            let verifier = ClientSecretVerifier {
                phc: corrupted.into(),
            };
            assert!(verifier.verify(b"candidate").is_err());
        }
        assert!(
            ClientSecretVerifier::dummy()
                .verify(&vec![b'x'; MAX_OAUTH_CLIENT_CREDENTIAL_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn admission_reservations_are_bounded_and_released_exactly_once() {
        let executor = KdfExecutor::new();
        let permits: Vec<_> = (0..MAX_ADMITTED)
            .map(|_| executor.reserve().unwrap())
            .collect();
        assert_eq!(executor.admission.lock().unwrap().live, MAX_ADMITTED);
        assert!(executor.reserve().is_err());
        drop(permits);
        assert_eq!(executor.admission.lock().unwrap().live, 0);
        drop(executor.reserve().unwrap());
        assert_eq!(executor.admission.lock().unwrap().live, 0);
    }

    #[test]
    fn admission_rate_is_bounded_even_when_no_work_remains_live() {
        let executor = KdfExecutor::new();
        // Reserve directly to make the rate boundary independent of KDF speed.
        for _ in 0..MAX_STARTS_PER_SECOND {
            drop(executor.reserve().unwrap());
        }
        assert_eq!(executor.admission.lock().unwrap().live, 0);
        assert!(executor.reserve().is_err());
        executor.admission.lock().unwrap().window = Instant::now() - Duration::from_secs(1);
        drop(executor.reserve().unwrap());
    }

    #[test]
    fn cancelled_context_never_dispatches_or_reserves_kdf_work() {
        let executor = KdfExecutor::new();
        let cx = Cx::for_testing();
        cx.set_cancel_requested(true);
        let ran = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&ran);
        assert!(
            executor
                .execute(Some(cx), move || {
                    observed.store(true, Ordering::Release);
                    Ok(())
                })
                .is_err()
        );
        assert!(!ran.load(Ordering::Acquire));
        let state = executor.admission.lock().unwrap();
        assert_eq!((state.live, state.starts), (0, 0));
    }

    #[test]
    fn executor_never_runs_work_on_the_calling_thread() {
        let executor = KdfExecutor::new();
        let caller = std::thread::current().id();
        let worker = executor
            .execute(None, || Ok(std::thread::current().id()))
            .unwrap();
        assert_ne!(worker, caller);
    }

    #[test]
    fn cancelled_waiter_retains_running_work_permit_until_retirement() {
        use std::sync::{Condvar, mpsc};

        let executor = Arc::new(KdfExecutor::new());
        let cx = Cx::for_testing();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let worker_gate = Arc::clone(&gate);
        let worker_executor = Arc::clone(&executor);
        let worker_cx = cx.clone();
        let (started_tx, started_rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            worker_executor.execute(Some(worker_cx), move || {
                started_tx.send(()).unwrap();
                let (released, wake) = &*worker_gate;
                let (released, timeout) = wake
                    .wait_timeout_while(
                        released.lock().unwrap(),
                        Duration::from_secs(5),
                        |released| !*released,
                    )
                    .unwrap();
                assert!(*released && !timeout.timed_out());
                Ok(())
            })
        });
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        cx.set_cancel_requested(true);
        let result = waiter.join().unwrap();
        assert!(result.is_err());
        assert_eq!(executor.admission.lock().unwrap().live, 1);
        let (released, wake) = &*gate;
        *released.lock().unwrap() = true;
        wake.notify_all();
        let limit = Instant::now() + Duration::from_secs(2);
        while executor.admission.lock().unwrap().live != 0 {
            assert!(Instant::now() < limit, "running KDF reservation leaked");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
