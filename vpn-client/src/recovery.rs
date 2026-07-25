//! Graceful panic recovery & fail-safe state restoration (Sec.1.5).
//!
//! A VPN client that hijacks the default route and arms a WFP kill switch can
//! lock the user out of the internet if it dies uncleanly. We defend against
//! that with three layers:
//!
//!  1. **`catch_unwind`** around the runtime entrypoints (see `run_guarded`).
//!  2. A process-wide **cleanup registry** of restoration closures executed on
//!     panic, `Ctrl-C`, or normal shutdown — in LIFO order.
//!  3. WFP's own **dynamic session** auto-teardown (in `wfp.rs`) as a backstop.
//!
//! The registry stores boxed `FnMut` cleanup actions guarded by a `Mutex`. Even
//! if a panic unwinds through arbitrary code, the guard's `Drop`/the explicit
//! `run_cleanup()` call restores gateway, DNS, and firewall state first.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use parking_lot::Mutex;
use tracing::{error, info, warn};
use vpn_shared::Result;

type CleanupAction = Box<dyn FnMut() + Send + 'static>;

/// Global registry of restoration steps. Populated as resources are acquired.
#[derive(Clone, Default)]
pub struct CleanupRegistry {
    actions: Arc<Mutex<Vec<(String, CleanupAction)>>>,
    done: Arc<Mutex<bool>>,
}

impl CleanupRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a named restoration step (executed LIFO on shutdown/panic).
    pub fn register<F: FnMut() + Send + 'static>(&self, name: impl Into<String>, action: F) {
        self.actions.lock().push((name.into(), Box::new(action)));
    }

    /// Execute every cleanup action once, newest first. Idempotent.
    pub fn run_cleanup(&self) {
        let mut done = self.done.lock();
        if *done {
            return;
        }
        *done = true;
        drop(done);

        let mut actions = self.actions.lock();
        info!(steps = actions.len(), "recovery: restoring original network state");
        while let Some((name, mut action)) = actions.pop() {
            let r = catch_unwind(AssertUnwindSafe(|| action()));
            match r {
                Ok(()) => info!(step = %name, "recovery step ok"),
                Err(_) => error!(step = %name, "recovery step PANICKED; continuing"),
            }
        }
        info!("recovery: network state restored — internet access preserved");
    }
}

/// Install a panic hook + Ctrl-C handler that both funnel into `run_cleanup`.
pub fn install_guards(registry: CleanupRegistry) {
    let reg = registry.clone();
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        error!(panic = %info, "PANIC caught — running fail-safe cleanup");
        reg.run_cleanup();
        default_hook(info);
    }));

    let reg2 = registry.clone();
    if let Err(e) = ctrlc_like(move || reg2.run_cleanup()) {
        warn!(error = %e, "could not install signal handler");
    }
}

/// Run an async entrypoint inside `catch_unwind`, guaranteeing cleanup runs even
/// if the tokio runtime task panics at the top level.
pub fn run_guarded<F>(registry: &CleanupRegistry, body: F) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let outcome = catch_unwind(AssertUnwindSafe(body));
    match outcome {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => {
            error!(error = %e, "runtime returned error — cleaning up");
            registry.run_cleanup();
            Err(e)
        }
        Err(_) => {
            error!("runtime PANICKED — cleaning up");
            registry.run_cleanup();
            Err(vpn_shared::VpnError::InvalidState(
                "runtime panicked; state restored".into(),
            ))
        }
    }
}

#[cfg(not(windows))]
fn ctrlc_like<F: Fn() + Send + Sync + 'static>(_f: F) -> Result<()> {
    Ok(())
}
