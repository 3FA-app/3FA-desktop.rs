//! macOS biometric factor — Face ID / Touch ID / Optic ID via LocalAuthentication.
//!
//! `can_evaluate` and `evaluate` call `LAContext` through `objc2`. The unwrap
//! key for the vault DEK is stored in the platform keychain by the GUI; this
//! module only proves the user is the device owner.

use crate::auth::{
    AuthFactor, BiometryKind, Challenge, FactorError, FactorKind, FactorProof,
};

pub struct BiometricFactor {
    /// Reason string surfaced in the system Face ID / Touch ID prompt.
    reason: String,
}

impl BiometricFactor {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    pub fn kind_available() -> BiometryKind {
        native::biometry_kind()
    }
}

impl AuthFactor for BiometricFactor {
    fn kind(&self) -> FactorKind {
        FactorKind::Biometric
    }

    fn is_available(&self) -> bool {
        native::can_evaluate()
    }

    fn verify(&mut self, _challenge: &Challenge) -> Result<FactorProof, FactorError> {
        native::evaluate(&self.reason).map(|()| FactorProof {
            kind: FactorKind::Biometric,
        })
    }
}

mod native {
    use super::BiometryKind;
    use crate::auth::FactorError;
    use std::sync::mpsc;
    use std::time::Duration;

    use block2::{Block, RcBlock};
    use objc2::rc::Retained;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LABiometryType, LAContext, LAPolicy};

    const EVALUATE_TIMEOUT: Duration = Duration::from_secs(30);

    pub fn can_evaluate() -> bool {
        !matches!(biometry_kind(), BiometryKind::Unavailable)
    }

    pub fn biometry_kind() -> BiometryKind {
        let ctx = LAContext::new();
        let mut error: Option<Retained<NSError>> = None;
        let ok = unsafe {
            ctx.canEvaluatePolicy_error(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                Some(&mut error),
            )
        };
        if !ok {
            return BiometryKind::Unavailable;
        }
        match ctx.biometryType() {
            LABiometryType::TouchID => BiometryKind::TouchId,
            LABiometryType::FaceID => BiometryKind::FaceId,
            LABiometryType::OpticID => BiometryKind::OpticId,
            _ => BiometryKind::Unavailable,
        }
    }

    pub fn evaluate(reason: &str) -> Result<(), FactorError> {
        let ctx = LAContext::new();
        let mut error: Option<Retained<NSError>> = None;
        let ready = unsafe {
            ctx.canEvaluatePolicy_error(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                Some(&mut error),
            )
        };
        if !ready {
            return Err(FactorError::Unavailable);
        }

        let (tx, rx) = mpsc::channel();
        let reply: RcBlock<dyn Fn(*mut NSError)> = RcBlock::new(move |err: *mut NSError| {
            let result = if err.is_null() {
                Ok(())
            } else {
                Err(FactorError::Rejected)
            };
            let _ = tx.send(result);
        });
        let reason = NSString::from_str(reason);
        unsafe {
            ctx.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                &reason,
                Block::as_ptr(&reply).cast(),
            );
        }
        match rx.recv_timeout(EVALUATE_TIMEOUT) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(FactorError::Backend("biometric prompt timed out".into())),
        }
    }

    #[allow(dead_code)]
    fn _bool_from(value: Bool) -> bool {
        value.as_bool()
    }
}
