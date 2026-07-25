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
//! sleeps. The GUI calls [`Session::poll`] on a timer and reports every user
//! interaction to [`Session::note_interaction`], which resets the idle timer for
//! the interactions [`Interaction::is_user_activity`] classifies as real
//! activity. That classification lives here, in the library, so it is unit-
//! testable without a display server (`src/ui.rs` is GUI-only and never compiled
//! by CI's headless build).

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

/// Something the user (or the app's own timer) did, as reported by the GUI.
///
/// Only some of these are *user activity* for the purposes of the idle timer —
/// see [`Interaction::is_user_activity`]. Keeping the list explicit (rather than
/// sprinkling bare `touch` calls through the Slint callbacks) means the decision
/// is reviewable and testable in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interaction {
    /// A digit or backspace on the passcode pad.
    KeypadInput,
    /// Enrolling an account from a pasted/typed `otpauth://` URI.
    AddAccount,
    /// Starting a QR scan (image import or webcam).
    ScanQr,
    /// Revealing / copying a code to the clipboard.
    CopyCode,
    /// Moving between screens (vault ⇄ settings).
    Navigate,
    /// A sync, sign-in or PIN-unlock action from the settings screen.
    Sync,
    /// The 1 Hz refresh tick. **Not** activity: an app that touches itself has
    /// no idle timeout at all, only the hard cap.
    TimerTick,
    /// Pressing "Keep open (+factor)". **Not** activity: extending is gated on a
    /// second, distinct factor ([`Gate::Extend`]); letting the mere button press
    /// reset the idle timer would silently route around that gate.
    ExtendRequest,
    /// Pressing "Lock now". **Not** activity: it locks the vault, and touching a
    /// session on its way down is meaningless.
    LockNow,
}

impl Interaction {
    /// Whether this interaction is genuine user activity that should reset the
    /// idle timer. Never resets the 5-minute hard cap — that is deliberate, and
    /// is the reason both timers exist.
    pub fn is_user_activity(self) -> bool {
        match self {
            Interaction::KeypadInput
            | Interaction::AddAccount
            | Interaction::ScanQr
            | Interaction::CopyCode
            | Interaction::Navigate
            | Interaction::Sync => true,
            Interaction::TimerTick | Interaction::ExtendRequest | Interaction::LockNow => false,
        }
    }
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

    /// Report a GUI interaction. Resets the idle timer iff the interaction is
    /// [user activity](Interaction::is_user_activity) and the vault is unlocked.
    /// Returns whether the idle timer was actually reset.
    pub fn note_interaction(&mut self, interaction: Interaction, now: Instant) -> bool {
        if !interaction.is_user_activity() || self.state != SessionState::Unlocked {
            return false;
        }
        self.touch(now);
        true
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

    /// Seconds until the vault actually locks: whichever of the idle timeout and
    /// the hard cap fires first. This — not either timer alone — is what the
    /// "locks in {N}s" countdown must show, because [`Session::poll`] locks on
    /// the *earlier* of the two.
    pub fn lock_seconds_remaining(&self, now: Instant) -> u64 {
        if self.state != SessionState::Unlocked {
            return 0;
        }
        self.idle_seconds_remaining(now)
            .min(self.session_seconds_remaining(now))
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
    fn user_interactions_are_activity_and_app_driven_ones_are_not() {
        for i in [
            Interaction::KeypadInput,
            Interaction::AddAccount,
            Interaction::ScanQr,
            Interaction::CopyCode,
            Interaction::Navigate,
            Interaction::Sync,
        ] {
            assert!(i.is_user_activity(), "{i:?} should reset the idle timer");
        }
        // A self-touching timer would abolish the idle timeout; "Keep open"
        // must go through the factor gate; "Lock now" locks.
        for i in [
            Interaction::TimerTick,
            Interaction::ExtendRequest,
            Interaction::LockNow,
        ] {
            assert!(
                !i.is_user_activity(),
                "{i:?} must NOT reset the idle timer"
            );
        }
    }

    #[test]
    fn note_interaction_resets_idle_timer_only_for_activity() {
        let t0 = Instant::now();
        let mut s = Session::new();
        s.unlock(t0);

        assert!(s.note_interaction(Interaction::CopyCode, t0 + Duration::from_secs(80)));
        // 89 s since the copy, 169 s since unlock -> still open.
        assert_eq!(s.poll(t0 + Duration::from_secs(169)), PollResult::Active);

        // Ticks do not push the deadline out: 90 s after the last real activity
        // the vault locks regardless of how many ticks happened in between.
        for n in 1..=9 {
            assert!(!s.note_interaction(Interaction::TimerTick, t0 + Duration::from_secs(80 + n)));
        }
        assert_eq!(s.poll(t0 + Duration::from_secs(170)), PollResult::JustLocked);
    }

    #[test]
    fn note_interaction_is_inert_while_locked() {
        let t0 = Instant::now();
        let mut s = Session::new();
        assert!(!s.note_interaction(Interaction::KeypadInput, t0));
        assert_eq!(s.state(), SessionState::Locked);
        assert_eq!(s.lock_seconds_remaining(t0), 0);
    }

    #[test]
    fn hard_cap_still_fires_under_continuous_activity() {
        let t0 = Instant::now();
        let mut s = Session::new();
        s.unlock(t0);
        // Interact every 10 s for the full 5 minutes: the idle timer never
        // expires, but the cap is inviolable.
        let mut t = t0;
        for _ in 0..29 {
            t += Duration::from_secs(10);
            assert!(s.note_interaction(Interaction::KeypadInput, t));
            assert_eq!(s.poll(t), PollResult::Active);
        }
        assert_eq!(s.poll(t0 + MAX_SESSION), PollResult::JustLocked);
    }

    #[test]
    fn lock_countdown_tracks_whichever_deadline_fires_first() {
        let t0 = Instant::now();
        let mut s = Session::new();
        s.unlock(t0);
        // Fresh session: the 90 s idle timer is the nearer deadline, not the 300 s cap.
        assert_eq!(s.lock_seconds_remaining(t0), IDLE_TIMEOUT.as_secs());
        assert_eq!(s.lock_seconds_remaining(t0 + Duration::from_secs(30)), 60);

        // Activity pushes the idle deadline out; the countdown follows it.
        s.note_interaction(Interaction::AddAccount, t0 + Duration::from_secs(30));
        assert_eq!(s.lock_seconds_remaining(t0 + Duration::from_secs(30)), 90);

        // Late in the session the hard cap becomes the nearer deadline, so the
        // countdown must switch to it even though activity just reset idle.
        let late = t0 + MAX_SESSION - Duration::from_secs(20);
        s.note_interaction(Interaction::CopyCode, late);
        assert_eq!(s.lock_seconds_remaining(late), 20);

        // And the number never outlives the session itself.
        s.lock();
        assert_eq!(s.lock_seconds_remaining(late), 0);
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
