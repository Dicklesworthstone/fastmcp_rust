//! One admitted-payload ledger for concurrently polled, caller-owned streams.
//!
//! Wire/body/parser caps remain per response. This ledger accounts decoded
//! payloads and notifications before they can reach an observer or successor.

use std::sync::{Arc, Mutex};

use super::{DpopStreamError, ManagedCoreError, ManagedCoreLimits, StreamDecoder,
    StreamEvent, StreamNotification};

#[derive(Clone)]
pub(in crate::http_auth::dpop::native::core) struct SharedStreamBudget {
    state: Arc<Mutex<BudgetState>>,
}

struct BudgetState {
    used: (usize, usize),
    maximum: (usize, usize),
}

impl SharedStreamBudget {
    pub(in crate::http_auth::dpop::native::core) fn new(
        limits: ManagedCoreLimits, used: (usize, usize),
    ) -> Result<Self, DpopStreamError> {
        let budget = Self {
            state: Arc::new(Mutex::new(BudgetState {
                used: (0, 0),
                maximum: (limits.total_bytes(), limits.notifications()),
            })),
        };
        budget.charge(used)?;
        Ok(budget)
    }

    pub(in crate::http_auth::dpop::native::core) fn usage(
        &self,
    ) -> Result<(usize, usize), DpopStreamError> {
        Ok(self.state.lock().map_err(|_| ManagedCoreError::InvalidResponse)?.used)
    }

    pub(in crate::http_auth::dpop::native::core) fn charge(
        &self, delta: (usize, usize),
    ) -> Result<(), DpopStreamError> {
        let mut state = self.state.lock().map_err(|_| ManagedCoreError::InvalidResponse)?;
        let bytes = state.used.0.checked_add(delta.0)
            .filter(|value| *value <= state.maximum.0)
            .ok_or(ManagedCoreError::ResponseByteLimit)?;
        let events = state.used.1.checked_add(delta.1)
            .filter(|value| *value <= state.maximum.1)
            .ok_or(ManagedCoreError::NotificationLimit)?;
        state.used = (bytes, events);
        Ok(())
    }

    fn preflight(&self, bytes: usize) -> Result<(), DpopStreamError> {
        let state = self.state.lock().map_err(|_| ManagedCoreError::InvalidResponse)?;
        if bytes > state.maximum.0.saturating_sub(state.used.0) {
            return Err(ManagedCoreError::ResponseByteLimit.into());
        }
        Ok(())
    }
}

// The decoder retains its method/correlation/terminal grammar and local caps.
// Refusal by the shared ledger aborts this exchange; no decoded event escapes
// and the caller cannot resume or replay the rejected decoder afterwards.
pub(in crate::http_auth::dpop::native::core) struct Budgeted<D> {
    pub(in crate::http_auth::dpop::native::core) inner: D,
    budget: Option<SharedStreamBudget>,
}

impl<D> Budgeted<D> {
    pub(in crate::http_auth::dpop::native::core) fn new(
        inner: D, budget: Option<SharedStreamBudget>,
    ) -> Self {
        Self { inner, budget }
    }

    fn charge_delta(
        &self, before: (usize, usize), after: (usize, usize),
    ) -> Result<(), DpopStreamError> {
        if let Some(budget) = &self.budget {
            let bytes = after.0.checked_sub(before.0).ok_or(ManagedCoreError::InvalidResponse)?;
            let events = after.1.checked_sub(before.1).ok_or(ManagedCoreError::InvalidResponse)?;
            budget.charge((bytes, events))?;
        }
        Ok(())
    }
}

impl<D, E> StreamDecoder<E> for Budgeted<D>
where
    D: StreamDecoder<E>,
    E: StreamNotification,
{
    type Terminal = D::Terminal;

    fn admit(
        &mut self, frame: &[u8], allow_notification: bool,
    ) -> Result<StreamEvent<Self::Terminal, E>, DpopStreamError> {
        if let Some(budget) = &self.budget { budget.preflight(frame.len())?; }
        let before = self.inner.usage();
        let event = self.inner.admit(frame, allow_notification)?;
        self.charge_delta(before, self.inner.usage())?;
        Ok(event)
    }

    fn admit_terminal_tail(&mut self, frame: &[u8]) -> Result<(), DpopStreamError> {
        if let Some(budget) = &self.budget { budget.preflight(frame.len())?; }
        let before = self.inner.usage();
        self.inner.admit_terminal_tail(frame)?;
        self.charge_delta(before, self.inner.usage())
    }

    fn usage(&self) -> (usize, usize) { self.inner.usage() }

    fn completes_on_terminal(&self) -> bool { self.inner.completes_on_terminal() }
}

#[cfg(test)]
mod tests;
