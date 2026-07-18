//! The 6-digit app passcode factor.
//!
//! Two roles:
//!   1. As the vault KEK source (handled in `vault`/`crypto`): the passcode
//!      derives the key that unwraps the DEK.
//!   2. As a presence check at the lock screen / for re-auth, where we don't want
//!      to pay a full Argon2 KEK derivation just to confirm "the user knows the
//!      passcode" — for that we keep a separate Argon2id PHC hash here.
//!
//! Both use Argon2id; the verification hash uses lighter params since it guards
//! nothing on its own (the real secret is the AEAD-sealed DEK).

use super::{AuthFactor, Challenge, FactorError, FactorKind, FactorProof};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::OsRng;
use subtle::ConstantTimeEq;

/// Validate that a passcode is exactly 6 ASCII digits.
pub fn is_valid_format(passcode: &[u8]) -> bool {
    passcode.len() == 6 && passcode.iter().all(|b| b.is_ascii_digit())
}

/// Produce an Argon2id PHC hash string for a passcode (for the presence check).
pub fn hash_passcode(passcode: &[u8]) -> Result<String, FactorError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon = presence_hasher();
    argon
        .hash_password(passcode, &salt)
        .map(|h| h.to_string())
        .map_err(|e| FactorError::Backend(e.to_string()))
}

/// Lighter Argon2id parameters for the presence-check hash (not the KEK).
fn presence_hasher() -> Argon2<'static> {
    let params = Params::new(64 * 1024, 2, 1, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// The passcode factor: verifies an entered passcode against a stored PHC hash.
pub struct PasscodeFactor {
    phc_hash: String,
    entered: Vec<u8>,
}

impl PasscodeFactor {
    pub fn new(phc_hash: String) -> Self {
        Self {
            phc_hash,
            entered: Vec::new(),
        }
    }

    /// Supply the passcode the user just typed, to be checked on `verify`.
    pub fn submit(&mut self, passcode: &[u8]) {
        self.entered = passcode.to_vec();
    }
}

impl AuthFactor for PasscodeFactor {
    fn kind(&self) -> FactorKind {
        FactorKind::Passcode
    }

    fn is_available(&self) -> bool {
        !self.phc_hash.is_empty()
    }

    fn verify(&mut self, _challenge: &Challenge) -> Result<FactorProof, FactorError> {
        if !is_valid_format(&self.entered) {
            self.entered.clear();
            return Err(FactorError::Rejected);
        }
        let parsed =
            PasswordHash::new(&self.phc_hash).map_err(|e| FactorError::Backend(e.to_string()))?;
        let result = presence_hasher().verify_password(&self.entered, &parsed);
        // Wipe the entered passcode regardless of outcome.
        self.entered.iter_mut().for_each(|b| *b = 0);
        self.entered.clear();
        match result {
            Ok(()) => Ok(FactorProof {
                kind: FactorKind::Passcode,
            }),
            Err(_) => Err(FactorError::Rejected),
        }
    }
}

/// Constant-time comparison of two short codes (e.g. spoken-PIN digit strings),
/// exposed for reuse by the voice factor.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_validation() {
        assert!(is_valid_format(b"123456"));
        assert!(!is_valid_format(b"12345"));
        assert!(!is_valid_format(b"1234567"));
        assert!(!is_valid_format(b"12a456"));
    }

    #[test]
    fn correct_passcode_verifies() {
        let hash = hash_passcode(b"314159").unwrap();
        let mut f = PasscodeFactor::new(hash);
        f.submit(b"314159");
        assert!(f.verify(&Challenge::default()).is_ok());
    }

    #[test]
    fn wrong_passcode_rejected() {
        let hash = hash_passcode(b"314159").unwrap();
        let mut f = PasscodeFactor::new(hash);
        f.submit(b"000000");
        assert!(matches!(
            f.verify(&Challenge::default()),
            Err(FactorError::Rejected)
        ));
    }

    #[test]
    fn malformed_passcode_rejected_without_hash_check() {
        let hash = hash_passcode(b"314159").unwrap();
        let mut f = PasscodeFactor::new(hash);
        f.submit(b"abc");
        assert!(matches!(
            f.verify(&Challenge::default()),
            Err(FactorError::Rejected)
        ));
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"1234", b"1234"));
        assert!(!ct_eq(b"1234", b"1235"));
        assert!(!ct_eq(b"1234", b"123"));
    }
}
