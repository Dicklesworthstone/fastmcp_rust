//! Minimal runtime helpers for FastMCP.
//!
//! This module provides the [`ProcessGenerationGuard`] that every
//! process-local protector, handle store, limiter, and supervisor must be
//! bound to before it becomes usable (FND-04), and a small `block_on` bridge.
//!
//! # Status of the `block_on` bridge
//!
//! This helper was introduced for the `#[tool]`/`#[resource]`/`#[prompt]`
//! macros, and that is no longer what it is. The macros expand to a directly
//! awaited handler future and assert as much:
//! `crates/fastmcp-macros/src/lib.rs` requires that no expansion contains
//! `block_on` or a `runtime::` path. The FastMCP CLI drives its own explicit
//! top-level runtime and asserts that production never reaches
//! `fastmcp_core::runtime::block_on`.
//!
//! What remains is a thread-local blocking bridge still exported
//! unconditionally from this library's public API — `pub mod runtime` plus
//! `pub use runtime::block_on` in `lib.rs`, neither `cfg(test)`-gated — in a
//! crate whose stated premise is that FastMCP never creates its own runtime.
//! FND-04 requires that production `block_on`, out-of-band `Cx` construction,
//! and private runtimes be non-exported and test-only, or have their
//! production reachability removed. That has not happened yet, and
//! `FND-04-B-07 production-deny-inventory` in
//! `crates/fastmcp/tests/fnd_04_runtime_conformance.rs` measures the gap
//! rather than asserting it away. The remaining consumers are cross-crate
//! test modules (for example `fastmcp-protocol`'s `jose.rs`), so gating the
//! export is a cross-crate change tracked separately; it is deliberately not
//! attempted here.
//!
//! The runtime is configured with a platform I/O reactor (epoll on Linux,
//! kqueue on macOS, IOCP on Windows) so that async network I/O works
//! correctly inside `block_on`. `Runtime::block_on` itself installs an
//! ambient `Cx` (backed by the runtime's drivers — including the reactor
//! we attach below) before polling, so asupersync networking primitives
//! can discover the I/O driver via `Cx::current()` without us having to
//! build a context out of band.

/// Process-bound authenticated encryption for ephemeral protected state.
pub mod envelope;

use std::cell::{Cell, OnceCell};
use std::fmt;
use std::future::Future;
use std::sync::OnceLock;

use asupersync::runtime::Runtime;
use asupersync::runtime::RuntimeBuilder;
use asupersync::runtime::reactor::create_reactor;

use crate::crypto::{RandomDrawError, SECURITY_IDENTIFIER_BYTES, draw_security_identifier};

/// Whether a live-memory clone of this process is detectable from inside it.
///
/// It is not, and no amount of process-local bookkeeping changes that.
/// `fork()` gives the child a new PID, so [`ProcessGenerationGuard`] catches
/// it. Process-memory checkpoint/restore (CRIU), a VM snapshot, or a container
/// clone duplicate the PID *and* every byte of process memory, including the
/// install nonce below. The duplicate is bit-identical to the original and
/// cannot be told apart by any observation the duplicated code can make.
///
/// This constant exists so that a caller reasoning about replay, nonce, or
/// one-use state has to read the boundary rather than assume a PID check
/// covers it. See [`SnapshotCloneStance`] for the deployment-level answer.
pub const SNAPSHOT_CLONE_IS_DETECTABLE: bool = false;

/// Identity of one process generation.
///
/// Two generations compare equal only when the operating-system process
/// identity *and* the random nonce drawn at install time both match. The
/// nonce closes the PID-reuse window: a later process that happens to be
/// assigned the same PID draws its own nonce and therefore never inherits a
/// previous generation's authority.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProcessGeneration {
    pid: u32,
    nonce: [u8; SECURITY_IDENTIFIER_BYTES],
    generation: u64,
}

impl ProcessGeneration {
    /// The operating-system process identifier recorded for this generation.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// The monotonically increasing generation ordinal within one process image.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// The random install nonce that distinguishes this generation from a
    /// later process that reuses the same PID.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; SECURITY_IDENTIFIER_BYTES] {
        &self.nonce
    }

    /// Builds a generation record for an explicitly supplied identity.
    ///
    /// This constructs a *claim*, never an authority: the value it returns
    /// can only ever be an argument to [`Self::admit`], which is the same
    /// predicate the live path runs. It exists so that a conformance caller
    /// can exercise PID and generation divergence on a target where a real
    /// `fork()` is unavailable, without the evaluator reimplementing the
    /// predicate it is supposed to be testing.
    #[must_use]
    pub const fn observed(
        pid: u32,
        nonce: [u8; SECURITY_IDENTIFIER_BYTES],
        generation: u64,
    ) -> Self {
        Self {
            pid,
            nonce,
            generation,
        }
    }

    /// Admits `observed` against this recorded generation, failing closed on
    /// any divergence.
    ///
    /// This is the single predicate behind every process-local check. The
    /// live path in [`ProcessBoundToken::verify`] calls it with the identity
    /// read from the operating system; a conformance caller may call it with
    /// a simulated identity. Both run the same comparison, so a simulated
    /// rejection is evidence about the shipped rule rather than about a
    /// test-only mirror of it.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessGenerationError::ForkDetected`] when the process
    /// identity differs, and [`ProcessGenerationError::GenerationMismatch`]
    /// when the ordinal differs within the same process identity.
    pub fn admit(&self, observed: Self) -> Result<(), ProcessGenerationError> {
        if self.pid != observed.pid || self.nonce != observed.nonce {
            return Err(ProcessGenerationError::ForkDetected {
                installed_pid: self.pid,
                observed_pid: observed.pid,
                generation: self.generation,
            });
        }
        if self.generation != observed.generation {
            return Err(ProcessGenerationError::GenerationMismatch {
                expected: self.generation,
                observed: observed.generation,
            });
        }
        Ok(())
    }
}

impl fmt::Debug for ProcessGeneration {
    /// Prints the PID and ordinal but never the nonce.
    ///
    /// The nonce is the value that distinguishes an inherited record from a
    /// legitimate one; logging it would hand an attacker with log access the
    /// one input needed to forge a `ProcessGeneration` that passes admission.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessGeneration")
            .field("pid", &self.pid)
            .field("generation", &self.generation)
            .field("nonce", &"<redacted>")
            .finish()
    }
}

/// Why a process-generation check failed closed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProcessGenerationError {
    /// The observed process identity differs from the installed one. This is
    /// what a post-initialization `fork()` looks like from inside the child.
    ForkDetected {
        /// PID recorded when the guard was installed.
        installed_pid: u32,
        /// PID observed at the failing check.
        observed_pid: u32,
        /// Generation ordinal recorded at install.
        generation: u64,
    },
    /// The process identity matched but the generation ordinal did not.
    GenerationMismatch {
        /// Ordinal recorded at install.
        expected: u64,
        /// Ordinal presented by the caller.
        observed: u64,
    },
    /// A process-local resource was used before the guard was installed.
    NotInstalled,
    /// The operating-system entropy source refused the install nonce draw.
    EntropyUnavailable(RandomDrawError),
    /// The deployment permits live-memory cloning without either disabling
    /// ephemeral process-local protected state or supplying a conforming
    /// external epoch.
    SnapshotCloneDeploymentUnsupported,
}

impl fmt::Display for ProcessGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForkDetected {
                installed_pid,
                observed_pid,
                generation,
            } => write!(
                formatter,
                "process generation {generation} was installed in pid {installed_pid} but is \
                 being used from pid {observed_pid}; inherited runtime, key, continuation, \
                 quota and supervisor state is not usable after fork — the child must exec or \
                 build a wholly new FastMCP instance"
            ),
            Self::GenerationMismatch { expected, observed } => write!(
                formatter,
                "process generation mismatch: resource carries generation {observed} but the \
                 installed generation is {expected}"
            ),
            Self::NotInstalled => formatter
                .write_str("process-local state was used before ProcessGenerationGuard::install()"),
            Self::EntropyUnavailable(source) => write!(
                formatter,
                "process generation nonce could not be drawn: {source}"
            ),
            Self::SnapshotCloneDeploymentUnsupported => formatter.write_str(
                "deployment permits live-memory snapshot/CRIU/VM/container cloning but neither \
                 disables ephemeral process-local protected state nor supplies a \
                 rollback-and-clone-resistant external epoch; process-local replay and nonce \
                 safety cannot be claimed under such cloning",
            ),
        }
    }
}

impl std::error::Error for ProcessGenerationError {}

/// An external epoch source that survives live-memory cloning.
///
/// Both dimensions are required. A monotone counter that a snapshot can roll
/// back is not rollback-resistant, and a counter that two restored clones can
/// read identically is not clone-resistant. Either hole reinstates exactly the
/// replay the epoch was introduced to prevent, so a stance carrying an epoch
/// that is not both is refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExternalEpoch {
    rollback_resistant: bool,
    clone_resistant: bool,
}

impl ExternalEpoch {
    /// Declares an external epoch with its two required properties.
    #[must_use]
    pub const fn new(rollback_resistant: bool, clone_resistant: bool) -> Self {
        Self {
            rollback_resistant,
            clone_resistant,
        }
    }

    /// Whether this epoch satisfies both requirements.
    #[must_use]
    pub const fn is_conforming(&self) -> bool {
        self.rollback_resistant && self.clone_resistant
    }
}

/// What the deployment guarantees about live-memory cloning.
///
/// [`SNAPSHOT_CLONE_IS_DETECTABLE`] is `false`, so this is a declaration the
/// operator makes, not something the process can measure. It is admitted by
/// [`ProcessGenerationGuard::admit_snapshot_stance`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SnapshotCloneStance {
    /// The deployment guarantees the process image is never checkpointed,
    /// snapshotted, or cloned while live.
    NoLiveMemoryCloning,
    /// The deployment permits live-memory cloning.
    LiveMemoryCloningPermitted {
        /// Whether ephemeral process-local protected and continuation state
        /// has been disabled.
        ephemeral_protected_state_disabled: bool,
        /// A conforming persistent provider's external epoch, when present.
        external_epoch: Option<ExternalEpoch>,
    },
}

/// Binds one process-local resource to the installed process generation.
///
/// A protector, handle store, nonce or cursor store, quota registry, or
/// supervisor holds one of these and calls [`Self::verify`] before every
/// operation. The token is `Copy` and carries no authority of its own: it is
/// a record of which generation minted the resource, and it is worthless in
/// any other generation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProcessBoundToken {
    minted_in: ProcessGeneration,
}

impl ProcessBoundToken {
    /// The generation this resource was minted in.
    #[must_use]
    pub const fn minted_in(&self) -> ProcessGeneration {
        self.minted_in
    }

    /// Verifies that this resource is being used in the generation that
    /// minted it, reading the live process identity.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessGenerationError::NotInstalled`] when no guard is
    /// installed, and otherwise whatever [`ProcessGeneration::admit`] returns
    /// for the live identity — in practice
    /// [`ProcessGenerationError::ForkDetected`] in a forked child.
    pub fn verify(&self) -> Result<(), ProcessGenerationError> {
        let installed = ProcessGenerationGuard::installed()
            .ok_or(ProcessGenerationError::NotInstalled)?
            .generation;
        // The live identity keeps the installed nonce and ordinal and takes
        // its PID from the operating system. A fork changes exactly that one
        // field, which is the divergence `admit` is looking for.
        let observed =
            ProcessGeneration::observed(std::process::id(), installed.nonce, installed.generation);
        installed.admit(observed)?;
        self.minted_in.admit(observed)
    }
}

/// Process-wide guard establishing the generation that owns process-local state.
///
/// Install this before any runtime, process-local key, nonce/cursor store,
/// quota registry, or supervisor becomes usable. Every such resource takes a
/// [`ProcessBoundToken`] from [`Self::token`] and verifies it before each
/// operation, so a post-`fork()` child fails closed instead of redrawing a key
/// while retaining inherited ciphertext, continuations, counters, or quota.
///
/// # Boundary
///
/// This detects `fork()`. It does not, and cannot, detect a live-memory clone
/// — see [`SNAPSHOT_CLONE_IS_DETECTABLE`] and [`SnapshotCloneStance`].
pub struct ProcessGenerationGuard {
    generation: ProcessGeneration,
}

static GUARD: OnceLock<ProcessGenerationGuard> = OnceLock::new();

impl ProcessGenerationGuard {
    /// Installs the guard for this process, or returns the one already installed.
    ///
    /// Installation is idempotent within a process image: the first caller
    /// draws the nonce and every later caller observes the same generation.
    /// An inherited guard is verified before it can be returned to a caller.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessGenerationError::EntropyUnavailable`] when the
    /// operating-system entropy source refuses the nonce draw. The guard is
    /// not installed in that case, so process-local state stays unusable
    /// rather than falling back to a predictable nonce. Returns
    /// [`ProcessGenerationError::ForkDetected`] if the installed generation
    /// belongs to another process.
    pub fn install() -> Result<&'static Self, ProcessGenerationError> {
        if let Some(existing) = GUARD.get() {
            existing.verify_current()?;
            return Ok(existing);
        }
        let nonce =
            draw_security_identifier().map_err(ProcessGenerationError::EntropyUnavailable)?;
        let candidate = Self {
            generation: ProcessGeneration {
                pid: std::process::id(),
                nonce: *nonce.as_bytes(),
                generation: 0,
            },
        };
        // A racing installer may win; verify the published generation, not
        // merely the candidate, before making its authority available.
        let installed = GUARD.get_or_init(|| candidate);
        installed.verify_current()?;
        Ok(installed)
    }

    /// Returns the installed guard, or `None` when nothing has installed one.
    #[must_use]
    pub fn installed() -> Option<&'static Self> {
        GUARD.get()
    }

    /// The generation this guard installed.
    #[must_use]
    pub const fn generation(&self) -> ProcessGeneration {
        self.generation
    }

    /// Mints a token binding a process-local resource to this generation.
    #[must_use]
    pub const fn token(&self) -> ProcessBoundToken {
        ProcessBoundToken {
            minted_in: self.generation,
        }
    }

    /// Verifies that the calling code is running in the installed generation.
    ///
    /// # Errors
    ///
    /// See [`ProcessBoundToken::verify`].
    pub fn verify_current(&self) -> Result<(), ProcessGenerationError> {
        self.token().verify()
    }

    /// Admits a deployment's declared stance on live-memory cloning.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessGenerationError::SnapshotCloneDeploymentUnsupported`]
    /// when the deployment permits live-memory cloning but neither disables
    /// ephemeral process-local protected state nor supplies a conforming
    /// external epoch.
    pub fn admit_snapshot_stance(
        stance: SnapshotCloneStance,
    ) -> Result<(), ProcessGenerationError> {
        match stance {
            SnapshotCloneStance::NoLiveMemoryCloning => Ok(()),
            SnapshotCloneStance::LiveMemoryCloningPermitted {
                ephemeral_protected_state_disabled,
                external_epoch,
            } => {
                if ephemeral_protected_state_disabled {
                    return Ok(());
                }
                match external_epoch {
                    Some(epoch) if epoch.is_conforming() => Ok(()),
                    _ => Err(ProcessGenerationError::SnapshotCloneDeploymentUnsupported),
                }
            }
        }
    }
}

/// Upper bound on on-demand blocking threads for the shared bridge runtime.
///
/// The bridge hosts a transport receive pump and any handler the embedder puts
/// on `Cx::spawn_blocking`; it is not a general-purpose worker pool, so the
/// ceiling stays small, host-independent and deterministic. Threads are created
/// only when blocking work is admitted and retire when idle.
const MAX_BLOCKING_THREADS: usize = 16;

thread_local! {
    /// Lazily initialized single-thread runtime with a platform I/O reactor.
    ///
    /// The bridge is thread-local because `Runtime::block_on` polls its future
    /// on the calling thread. Sharing one current-thread runtime across
    /// concurrent blocking adapters can couple an adapter to a reactor being
    /// driven by another thread and starve sibling tasks on that runtime.
    static RUNTIME: OnceCell<Runtime> = const { OnceCell::new() };
    static BRIDGE_ACTIVE: Cell<bool> = const { Cell::new(false) };
    /// Whether the live bridge entry on this thread was made from INSIDE a task
    /// context.
    ///
    /// Recorded at entry because that is the only moment it is observable:
    /// `Runtime::block_on` installs its own ambient `Cx` for the duration of the
    /// poll, so afterwards a bridge entered from a task and a bridge entered
    /// from a bare thread look identical.
    static BRIDGE_NESTED_IN_TASK: Cell<bool> = const { Cell::new(false) };
    /// Whether this thread is a dedicated blocking lane whose owner keeps an
    /// async driver running elsewhere.
    ///
    /// A pool thread is never the driver, so bridging an async operation on one
    /// cannot starve the thread that would complete it. Without this
    /// distinction the detection below would reject the paths that work today.
    static BLOCKING_LANE: Cell<bool> = const { Cell::new(false) };
}

/// Declares the current thread a dedicated blocking lane until dropped.
///
/// Set this on threads owned by a blocking pool, never on an async worker: it
/// is an assertion that some OTHER thread is driving the runtime, which is what
/// makes a blocking bridge safe here.
#[must_use = "the lane declaration ends when the guard is dropped"]
pub struct BlockingLaneGuard {
    previous: bool,
}

impl Drop for BlockingLaneGuard {
    fn drop(&mut self) {
        BLOCKING_LANE.with(|lane| lane.set(self.previous));
    }
}

/// Enters a dedicated blocking lane on the current thread.
pub fn enter_blocking_lane() -> BlockingLaneGuard {
    BlockingLaneGuard {
        previous: BLOCKING_LANE.with(|lane| lane.replace(true)),
    }
}

/// Reports whether an async operation awaited here is being driven by a bridge
/// that would block the only thread able to complete it.
///
/// True when [`block_on`] was entered from inside a task context on a thread
/// that is not a dedicated blocking lane. In that position the bridge occupies
/// the driver, so an operation whose completion arrives through that driver --
/// a reverse request to the peer, for instance -- can never become ready, and
/// the symptom is a hang with no error and no timeout.
///
/// This reports a POSITION, not an outcome. A caller that can return an error
/// should use it to name the situation instead of parking; it deliberately does
/// not gate [`block_on`] itself, whose signature has no error channel and whose
/// other uses are unaffected.
#[must_use]
pub fn bridge_would_starve_its_driver() -> bool {
    BRIDGE_NESTED_IN_TASK.with(Cell::get) && !BLOCKING_LANE.with(Cell::get)
}

/// Keeps reentrancy rejection unwind-safe without holding a TLS borrow while
/// user code is polled. A rejected nested entry must not reset the outer entry.
struct BridgeEntry {
    previous_nested_in_task: bool,
}

impl BridgeEntry {
    fn enter() -> Self {
        BRIDGE_ACTIVE.with(|active| {
            assert!(
                !active.replace(true),
                "nested fastmcp_core::runtime::block_on is not supported"
            );
        });
        // Read the ambient context BEFORE the runtime installs its own. A
        // rejected nested entry panics above and never reaches here, so this
        // records only the live entry, and the prior value is restored on drop
        // rather than assumed false.
        Self {
            previous_nested_in_task: BRIDGE_NESTED_IN_TASK
                .with(|nested| nested.replace(asupersync::Cx::is_active())),
        }
    }
}

impl Drop for BridgeEntry {
    fn drop(&mut self) {
        BRIDGE_NESTED_IN_TASK.with(|nested| nested.set(self.previous_nested_in_task));
        BRIDGE_ACTIVE.with(|active| active.set(false));
    }
}

/// Blocks the current thread on the provided future.
///
/// Uses a lazily initialized, per-thread asupersync runtime that has a platform
/// I/O reactor enabled. The runtime's own `block_on` installs an ambient `Cx`
/// carrying the runtime drivers (I/O, timer, blocking pool, entropy,
/// observability) for the duration of the poll, so asupersync networking
/// primitives that look up the driver via `Cx::current()` work correctly.
/// Because we attach the reactor via [`RuntimeBuilder::with_reactor`], that
/// ambient `Cx`'s I/O driver is backed by the calling thread's reactor.
///
/// The process-generation guard is installed before the first runtime is
/// created, including when the caller has not initialized any other FastMCP
/// state. Subsequent calls verify that same generation before touching TLS.
///
/// # Panics
///
/// Panics if the process-generation guard cannot be installed or verified,
/// including in a child of a post-initialization `fork()`. Also panics on
/// recursive calls on the same thread: an already-running current-thread
/// executor cannot safely be driven recursively. Both normal completion and
/// unwinding release the entry so that later independent calls remain usable.
pub fn block_on<F: Future>(future: F) -> F::Output {
    // Installation is mandatory, not conditional on another subsystem having
    // installed a guard. Otherwise the first bridge could mint a reactor and
    // blocking pool with no generation record for a forked child to reject.
    ProcessGenerationGuard::install().unwrap_or_else(|error| {
        panic!("refusing to drive a FastMCP runtime across a process generation: {error}")
    });
    let _entry = BridgeEntry::enter();

    RUNTIME.with(|runtime| {
        let runtime = runtime.get_or_init(|| {
            // Create the platform reactor (epoll/kqueue/IOCP). The runtime
            // derives its I/O driver from this reactor, and `Runtime::block_on`
            // installs an ambient `Cx` carrying that driver for each poll.
            let reactor = create_reactor().expect("failed to create platform I/O reactor");

            RuntimeBuilder::current_thread()
                .with_reactor(reactor)
                // A blocking pool is REQUIRED, not an optimization.
                // `Cx::spawn_blocking` falls back to running its closure INLINE
                // when the ambient runtime has none, and the default pool
                // configuration is `max_threads = 0` — no pool at all. A server
                // that puts its receive pump on `Cx::spawn_blocking` (the stdio
                // transport does) would then run that pump on the single worker
                // thread, so the worker can never poll the request-owned child
                // the router spawns for an ordinary request: the first request
                // that admits a child never completes and the process stops
                // answering (GitHub #65).
                //
                // `min_threads = 0` keeps the pool on-demand, so a process that
                // never blocks still starts no extra thread.
                .blocking_threads(0, MAX_BLOCKING_THREADS)
                .build()
                .expect("failed to build asupersync runtime")
        });

        runtime.block_on(future)
    })
}

#[cfg(test)]
mod tests {
    use super::{ProcessGenerationGuard, block_on};

    #[test]
    fn block_on_runs_async_blocks() {
        let out = block_on(async { 1 + 1 });
        assert_eq!(out, 2);
    }

    #[test]
    fn block_on_can_be_called_multiple_times() {
        let a = block_on(async { "a" });
        let b = block_on(async { "b" });
        assert_eq!(a, "a");
        assert_eq!(b, "b");
    }

    #[test]
    fn block_on_installs_guard_before_polling() {
        const CHILD: &str = "FASTMCP_TEST_BRIDGE_FIRST_ENTRY";
        // The global guard cannot be uninstalled. Run only this test in a
        // fresh process to prove initialization order independently of the
        // parallel test harness and all other guard users.
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "runtime::tests::block_on_installs_guard_before_polling",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "fresh-process bridge test failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        assert!(ProcessGenerationGuard::installed().is_none());
        let generation = block_on(async {
            let guard = ProcessGenerationGuard::installed()
                .expect("the guard must exist before user code is polled");
            guard.verify_current().unwrap();
            guard.generation()
        });
        assert_eq!(generation.pid(), std::process::id());
        assert_eq!(ProcessGenerationGuard::install().unwrap().generation(), generation);
    }

    #[test]
    fn nested_bridge_is_rejected_without_poisoning_outer_entry() {
        block_on(async {
            for _ in 0..2 {
                let error = std::panic::catch_unwind(|| block_on(async { 1 }));
                assert!(error.is_err(), "each nested entry must be rejected");
            }
        });
        assert_eq!(block_on(async { 7 }), 7);
    }

    #[test]
    fn bridge_entry_is_released_when_the_future_panics() {
        let error = std::panic::catch_unwind(|| {
            block_on(async { panic!("bridge test panic") });
        });
        assert!(error.is_err());
        assert_eq!(block_on(async { 11 }), 11);
    }

    #[test]
    fn guard_install_is_idempotent_across_threads() {
        let expected = ProcessGenerationGuard::install().unwrap().generation();
        let installers: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    let guard = ProcessGenerationGuard::install().unwrap();
                    guard.verify_current().unwrap();
                    guard.generation()
                })
            })
            .collect();
        for installer in installers {
            assert_eq!(installer.join().unwrap(), expected);
        }
    }
}
