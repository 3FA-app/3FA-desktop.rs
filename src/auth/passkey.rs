//! Platform passkey factor — a WebAuthn platform authenticator whose private key
//! lives in the Secure Enclave (macOS) / TPM (Windows/Linux). "Something you
//! have": possession of *this* machine's hardware-bound credential.
//!
//! At enrollment we register a credential and store its `credential_id`. At
//! verification we ask the platform authenticator to sign a fresh challenge; a
//! valid assertion proves the hardware key is present and user-verified.
//!
//! Native wiring (Apple `AuthenticationServices` / Windows WebAuthn API) sits
//! behind the `native` seam; until linked the factor reports unavailable.

use super::{AuthFactor, Challenge, FactorError, FactorKind, FactorProof};

pub struct PasskeyFactor {
    /// The registered credential id (opaque handle), if enrolled.
    credential_id: Option<Vec<u8>>,
}

impl PasskeyFactor {
    pub fn new(credential_id: Option<Vec<u8>>) -> Self {
        Self { credential_id }
    }

    pub fn is_enrolled(&self) -> bool {
        self.credential_id.is_some()
    }
}

impl AuthFactor for PasskeyFactor {
    fn kind(&self) -> FactorKind {
        FactorKind::Passkey
    }

    fn is_available(&self) -> bool {
        self.credential_id.is_some() && native::platform_authenticator_present()
    }

    fn verify(&mut self, challenge: &Challenge) -> Result<FactorProof, FactorError> {
        let cred = self
            .credential_id
            .as_deref()
            .ok_or(FactorError::Unavailable)?;
        let nonce = challenge.nonce.unwrap_or([0u8; 16]);
        native::assert(cred, &nonce).map(|()| FactorProof {
            kind: FactorKind::Passkey,
        })
    }
}

mod native {
    use crate::auth::FactorError;

    pub fn platform_authenticator_present() -> bool {
        // TODO(native): ASAuthorizationController / WebAuthnApiGetPlatformCredentialList.
        false
    }

    pub fn assert(_credential_id: &[u8], _challenge: &[u8]) -> Result<(), FactorError> {
        Err(FactorError::Unavailable)
    }
}
