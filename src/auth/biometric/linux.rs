//! Linux biometric factor — fingerprint via `fprintd` over D-Bus, with the
//! unwrap key sealed to a TPM2 PCR policy where a TPM is present (otherwise the
//! vault falls back to passcode-only, which the policy engine enforces).
//!
//! This is the weakest of the three platform backends (see plan); native wiring
//! sits behind the `native` seam.

use crate::auth::{AuthFactor, Challenge, FactorError, FactorKind, FactorProof};

pub struct BiometricFactor {
    reason: String,
}

impl BiometricFactor {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl AuthFactor for BiometricFactor {
    fn kind(&self) -> FactorKind {
        FactorKind::Biometric
    }

    fn is_available(&self) -> bool {
        native::has_enrolled_print()
    }

    fn verify(&mut self, _challenge: &Challenge) -> Result<FactorProof, FactorError> {
        native::verify(&self.reason).map(|()| FactorProof {
            kind: FactorKind::Biometric,
        })
    }
}

mod native {
    use crate::auth::FactorError;

    pub fn has_enrolled_print() -> bool {
        // TODO(native): query fprintd ListEnrolledFingers over zbus.
        false
    }

    pub fn verify(_reason: &str) -> Result<(), FactorError> {
        Err(FactorError::Unavailable)
    }
}
