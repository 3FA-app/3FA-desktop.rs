//! Authentication factors and the policy engine that decides whether a set of
//! presented factors satisfies a gate (unlock / reveal / extend).
//!
//! Each concrete factor (passcode, biometric, passkey, voice) implements
//! [`AuthFactor`]. The [`PolicyEngine`] is deliberately ignorant of *which*
//! factors exist — it only counts **distinct kinds**, so adding a new factor
//! never requires touching the policy logic.

pub mod passcode;
pub mod passkey;
pub mod voice;

#[cfg(target_os = "macos")]
#[path = "biometric/macos.rs"]
pub mod biometric;
#[cfg(target_os = "windows")]
#[path = "biometric/windows.rs"]
pub mod biometric;
#[cfg(target_os = "linux")]
#[path = "biometric/linux.rs"]
pub mod biometric;

use crate::vault::FactorPolicy;
use std::collections::BTreeSet;

/// The category of an authentication factor. The policy engine counts *distinct*
/// kinds, so presenting the same kind twice never counts as two factors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FactorKind {
    /// Something you know — the 6-digit app passcode.
    Passcode,
    /// Something you are — Touch ID / Windows Hello / fprintd.
    Biometric,
    /// Something you have — platform passkey (Secure Enclave / TPM).
    Passkey,
    /// Something you are (cross-platform) — spoken-PIN + voiceprint.
    Voice,
}

impl FactorKind {
    pub fn label(self) -> &'static str {
        match self {
            FactorKind::Passcode => "Passcode",
            FactorKind::Biometric => "Biometric",
            FactorKind::Passkey => "Passkey",
            FactorKind::Voice => "Voice",
        }
    }
}

/// Proof that a factor was successfully verified. Carrying the kind lets the
/// policy engine de-duplicate by kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactorProof {
    pub kind: FactorKind,
}

/// Which gate is being satisfied. Each maps to a different requirement in the
/// [`FactorPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Open the vault from a locked state.
    Unlock,
    /// Extend an already-open session toward the 5-minute cap.
    Extend,
}

#[derive(Debug, thiserror::Error)]
pub enum FactorError {
    #[error("factor not available on this device")]
    Unavailable,
    #[error("verification failed")]
    Rejected,
    #[error("factor backend error: {0}")]
    Backend(String),
}

/// A challenge handed to a factor at verification time. Most factors ignore the
/// payload; the voice factor uses `nonce` for its random-digit challenge mode.
#[derive(Debug, Clone, Default)]
pub struct Challenge {
    pub nonce: Option<[u8; 16]>,
}

/// Common interface for every authentication factor.
pub trait AuthFactor {
    fn kind(&self) -> FactorKind;
    /// Whether this factor is usable right now (hardware present, enrolled, …).
    fn is_available(&self) -> bool;
    /// Attempt verification, producing a [`FactorProof`] on success.
    fn verify(&mut self, challenge: &Challenge) -> Result<FactorProof, FactorError>;
}

/// Counts distinct factor kinds against a [`FactorPolicy`] requirement.
pub struct PolicyEngine {
    policy: FactorPolicy,
}

impl PolicyEngine {
    pub fn new(policy: FactorPolicy) -> Self {
        Self { policy }
    }

    fn required(&self, gate: Gate) -> u8 {
        match gate {
            Gate::Unlock => self.policy.unlock_factors.max(1),
            Gate::Extend => self.policy.extend_factors.max(1),
        }
    }

    /// True iff the presented proofs cover at least the required number of
    /// **distinct** factor kinds for the gate.
    pub fn is_satisfied(&self, gate: Gate, proofs: &[FactorProof]) -> bool {
        let distinct: BTreeSet<FactorKind> = proofs.iter().map(|p| p.kind).collect();
        distinct.len() as u8 >= self.required(gate)
    }

    /// How many more distinct kinds are still needed for the gate.
    pub fn remaining(&self, gate: Gate, proofs: &[FactorProof]) -> u8 {
        let distinct: BTreeSet<FactorKind> = proofs.iter().map(|p| p.kind).collect();
        self.required(gate).saturating_sub(distinct.len() as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof(k: FactorKind) -> FactorProof {
        FactorProof { kind: k }
    }

    #[test]
    fn single_factor_policy_satisfied_by_one() {
        let eng = PolicyEngine::new(FactorPolicy {
            unlock_factors: 1,
            extend_factors: 1,
        });
        assert!(eng.is_satisfied(Gate::Unlock, &[proof(FactorKind::Passcode)]));
    }

    #[test]
    fn two_factor_needs_two_distinct_kinds() {
        let eng = PolicyEngine::new(FactorPolicy {
            unlock_factors: 2,
            extend_factors: 1,
        });
        // Same kind twice does NOT satisfy 2FA.
        assert!(!eng.is_satisfied(
            Gate::Unlock,
            &[proof(FactorKind::Passcode), proof(FactorKind::Passcode)]
        ));
        // Two distinct kinds do.
        assert!(eng.is_satisfied(
            Gate::Unlock,
            &[proof(FactorKind::Passcode), proof(FactorKind::Biometric)]
        ));
    }

    #[test]
    fn three_factor_requires_three_kinds() {
        let eng = PolicyEngine::new(FactorPolicy {
            unlock_factors: 3,
            extend_factors: 1,
        });
        let two = [proof(FactorKind::Passcode), proof(FactorKind::Biometric)];
        assert_eq!(eng.remaining(Gate::Unlock, &two), 1);
        let three = [
            proof(FactorKind::Passcode),
            proof(FactorKind::Biometric),
            proof(FactorKind::Voice),
        ];
        assert!(eng.is_satisfied(Gate::Unlock, &three));
    }
}
