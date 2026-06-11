//! Session lifetime: the auto-lock state machine.
//!
//! Rules (from the brief):
//!   * The vault auto-locks after **90 seconds** of inactivity.
//!   * The user may keep it open for **up to 5 minutes** total, but extending
//!     past the first idle window requires presenting a **second, distinct**
//!     factor (enforced by the [`PolicyEngine`] with [`Gate::Extend`]).
//!   * After the 5-minute hard cap the vault re-locks no matter what.
//!
//! Time is injected (`now: Instant`) so the logic is unit-testable without real
//! sleeps. The GUI calls [`Session::poll`] on a timer and on every user action
//! calls [`Session::touch`].

use crate::auth::{FactorProof, Gate, PolicyEngine};
use std::time::{Duration, Instant};

/// Idle window before auto-lock.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// Absolute cap on how long a session may stay unlocked, even with extensions.
pub const MAX_SESSION: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Locked,
    Unlocked,
}

/// What [`Session::poll`] tells the caller to do this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollResult {
    /// Still unlocked, nothing to do.
    Active,
    /// Just transitioned to locked (idle timeout or hard cap) — the GUI should
    /// drop the in-memory vault keys and show the lock screen.
    JustLocked,
    /// Already locked.
    Locked,
}

pub struct Session {
    state: SessionState,
    /// When the current unlocked session began (for the 5-minute hard cap).
    opened_at: Option<Instant>,
    /// Last user activity (for the 90-second idle timeout).
    last_activity: Option<Instant>,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub fn new() -> Self {
        Self {
            state: SessionState::Locked,
            opened_at: None,
            last_activity: None,
        }
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn is_unlocked(&self) -> bool {
        self.state == SessionState::Unlocked
    }

    /// Open the vault. Caller has already satisfied the unlock policy.
    pub fn unlock(&mut self, now: Instant) {
        self.state = SessionState::Unlocked;
        self.opened_at = Some(now);
        self.last_activity = Some(now);
    }

    /// Record user activity, resetting the idle timer (but not the hard cap).
    pub fn touch(&mut self, now: Instant) {
        if self.state == SessionState::Unlocked {
            self.last_activity = Some(now);
        }
    }

    /// Force a lock and clear timers. The caller is responsible for zeroizing the
    /// in-memory DEK/vault.
    pub fn lock(&mut self) {
        self.state = SessionState::Locked;
        self.opened_at = None;
        self.last_activity = None;
    }

    /// Seconds until the idle timeout fires (0 if already past / locked).
    pub fn idle_seconds_remaining(&self, now: Instant) -> u64 {
        match self.last_activity {
            Some(last) => IDLE_TIMEOUT
                .saturating_sub(now.duration_since(last))
                .as_secs(),
            None => 0,
        }
    }

    /// Seconds until the absolute session cap (0 if already past / locked).
    pub fn session_seconds_remaining(&self, now: Instant) -> u64 {
        match self.opened_at {
            Some(opened) => MAX_SESSION
                .saturating_sub(now.duration_since(opened))
                .as_secs(),
            None => 0,
        }
    }

    /// Drive the state machine. Locks on idle timeout OR hard cap.
    pub fn poll(&mut self, now: Instant) -> PollResult {
        if self.state == SessionState::Locked {
            return PollResult::Locked;
        }
        let idle_expired = self
            .last_activity
            .map(|last| now.duration_since(last) >= IDLE_TIMEOUT)
            .unwrap_or(true);
        let cap_expired = self
            .opened_at
            .map(|opened| now.duration_since(opened) >= MAX_SESSION)
            .unwrap_or(true);

        if idle_expired || cap_expired {
            self.lock();
            PollResult::JustLocked
        } else {
            PollResult::Active
        }
    }

    /// Extend the session: reset the idle timer if (and only if) the supplied
    /// factor proofs satisfy the `Extend` gate AND we are still under the hard
    /// cap. Returns whether the extension was granted.
    pub fn try_extend(
        &mut self,
        now: Instant,
        engine: &PolicyEngine,
        proofs: &[FactorProof],
    ) -> bool {
        if self.state != SessionState::Unlocked {
            return false;
        }
        // The hard cap is inviolable.
        if self.session_seconds_remaining(now) == 0 {
            self.lock();
            return false;
        }
        if engine.is_satisfied(Gate::Extend, proofs) {
            self.last_activity = Some(now);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::FactorKind;
    use crate::vault::FactorPolicy;

    fn engine() -> PolicyEngine {
        PolicyEngine::new(FactorPolicy {
            unlock_factors: 1,
            extend_factors: 1,
        })
    }

    fn proof(k: FactorKind) -> FactorProof {
        FactorProof { kind: k }
    }

    #[test]
    fn locks_after_idle_timeout() {
        let t0 = Instant::now();
        let mut s = Session::new();
        s.unlock(t0);
        assert_eq!(s.poll(t0 + Duration::from_secs(89)), PollResult::Active);
        assert_eq!(s.poll(t0 + Duration::from_secs(90)), PollResult::JustLocked);
        assert_eq!(s.state(), SessionState::Locked);
    }

    #[test]
    fn touch_resets_idle_timer() {
        let t0 = Instant::now();
        let mut s = Session::new();
        s.unlock(t0);
        s.touch(t0 + Duration::from_secs(80));
        // 80 + 89 = 169s after open, but only 89s since last touch -> still active.
        assert_eq!(s.poll(t0 + Duration::from_secs(169)), PollResult::Active);
    }

    #[test]
    fn hard_cap_locks_even_with_activity() {
        let t0 = Instant::now();
        let mut s = Session::new();
        s.unlock(t0);
        // Keep touching every 10s up to 5 minutes; the cap still fires.
        let mut t = t0;
        for _ in 0..30 {
            t += Duration::from_secs(10);
            s.touch(t);
        }
        assert_eq!(s.poll(t0 + MAX_SESSION), PollResult::JustLocked);
    }

    #[test]
    fn extend_requires_satisfying_factor() {
        let t0 = Instant::now();
        let mut s = Session::new();
        s.unlock(t0);
        let at = t0 + Duration::from_secs(85);
        // No proofs -> 0 distinct kinds, extend_factors=1 -> not granted.
        assert!(!s.try_extend(at, &engine(), &[]));
        // A factor proof -> granted, idle timer reset.
        assert!(s.try_extend(at, &engine(), &[proof(FactorKind::Biometric)]));
        assert_eq!(s.poll(at + Duration::from_secs(89)), PollResult::Active);
    }

    #[test]
    fn extend_denied_past_hard_cap() {
        let t0 = Instant::now();
        let mut s = Session::new();
        s.unlock(t0);
        let past_cap = t0 + MAX_SESSION + Duration::from_secs(1);
        assert!(!s.try_extend(past_cap, &engine(), &[proof(FactorKind::Biometric)]));
        assert_eq!(s.state(), SessionState::Locked);
    }
}
