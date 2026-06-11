//! Windows biometric factor — Windows Hello via `UserConsentVerifier`
//! (WinRT `Windows.Security.Credentials.UI`), with the unwrap key protected by
//! the TPM-backed CNG key store.
//!
//! Native wiring (WinRT `windows` crate) sits behind the `native` seam; until
//! linked, the factor reports as unavailable.

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
        native::available()
    }

    fn verify(&mut self, _challenge: &Challenge) -> Result<FactorProof, FactorError> {
        native::request_consent(&self.reason).map(|()| FactorProof {
            kind: FactorKind::Biometric,
        })
    }
}

mod native {
    use crate::auth::FactorError;

    pub fn available() -> bool {
        // TODO(native): UserConsentVerifier::CheckAvailabilityAsync.
        false
    }

    pub fn request_consent(_reason: &str) -> Result<(), FactorError> {
        Err(FactorError::Unavailable)
    }
}
