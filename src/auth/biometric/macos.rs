//! macOS biometric factor — Touch ID via the LocalAuthentication framework,
//! with the unwrap key held in the Secure Enclave (`kSecAccessControl` with
//! `biometryCurrentSet`).
//!
//! Native wiring (LAContext `evaluatePolicy:` + SecItem Enclave key) is added via
//! `objc2-local-authentication` / `security-framework` behind the seam below.
//! Until that is linked, [`is_available`] performs a cheap runtime probe and
//! `verify` reports [`FactorError::Unavailable`] so the policy engine simply
//! treats biometrics as an absent factor rather than a failing one.

use crate::auth::{AuthFactor, Challenge, FactorError, FactorKind, FactorProof};

pub struct BiometricFactor {
    /// Reason string surfaced in the system Touch ID prompt.
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
        // Apple Silicon / T2 Macs expose Touch ID. The native probe will call
        // `LAContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`.
        native::can_evaluate()
    }

    fn verify(&mut self, _challenge: &Challenge) -> Result<FactorProof, FactorError> {
        native::evaluate(&self.reason).map(|()| FactorProof {
            kind: FactorKind::Biometric,
        })
    }
}

/// Native seam. Replace the bodies with `objc2-local-authentication` calls; the
/// signatures are what the rest of the app depends on.
mod native {
    use crate::auth::FactorError;

    pub fn can_evaluate() -> bool {
        // TODO(native): LAContext canEvaluatePolicy(...). Stubbed false until the
        // objc2 binding is linked, so the factor is treated as absent.
        false
    }

    pub fn evaluate(_reason: &str) -> Result<(), FactorError> {
        Err(FactorError::Unavailable)
    }
}
