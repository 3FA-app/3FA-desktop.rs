//! Sidecar wrap of the vault DEK so Face ID / Touch ID / Windows Hello can
//! unlock after a one-time passcode enrollment.
//!
//! The wrap key is *not* derived from the biometric sample. Biometrics only
//! gate access to that key (Secure Enclave / platform keychain / this
//! process). This module is the platform-independent AEAD half so it stays
//! unit-testable without a display or LocalAuthentication.

use crate::crypto::{self, CryptoError, Sealed, SecretKey, KEY_LEN};
use serde::{Deserialize, Serialize};

/// Domain-separated AAD so a biometric wrap cannot be swapped for a
/// passcode wrap (or a PIN-sealed session).
const BIOMETRIC_WRAP_AAD: &[u8] = b"3fa-biometric-dek-wrap-v1";

/// On-disk sidecar next to `default.vault`. Contains no wrap key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricDekSidecar {
    pub format_version: u32,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl BiometricDekSidecar {
    pub const CURRENT_FORMAT: u32 = 1;

    pub fn from_sealed(sealed: &Sealed) -> Self {
        Self {
            format_version: Self::CURRENT_FORMAT,
            nonce: sealed.nonce.to_vec(),
            ciphertext: sealed.ciphertext.clone(),
        }
    }

    pub fn to_sealed(&self) -> Result<Sealed, CryptoError> {
        if self.format_version != Self::CURRENT_FORMAT {
            return Err(CryptoError::Decrypt);
        }
        let nonce: [u8; crypto::NONCE_LEN] = self
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Decrypt)?;
        Ok(Sealed {
            nonce,
            ciphertext: self.ciphertext.clone(),
        })
    }
}

/// Wrap `dek` under a random high-entropy wrap key.
pub fn wrap_dek(wrap_key: &SecretKey, dek: &SecretKey) -> Result<Sealed, CryptoError> {
    if wrap_key.len() != KEY_LEN || dek.len() != KEY_LEN {
        return Err(CryptoError::KeyLen);
    }
    crypto::seal(wrap_key, dek, BIOMETRIC_WRAP_AAD)
}

/// Unwrap a DEK previously produced by [`wrap_dek`].
pub fn unwrap_dek(wrap_key: &SecretKey, sealed: &Sealed) -> Result<SecretKey, CryptoError> {
    let mut plaintext = crypto::open(wrap_key, sealed, BIOMETRIC_WRAP_AAD)?;
    if plaintext.len() != KEY_LEN {
        plaintext.fill(0);
        return Err(CryptoError::KeyLen);
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&plaintext);
    plaintext.fill(0);
    Ok(zeroize::Zeroizing::new(key))
}

/// Path of the biometric DEK sidecar beside `vault_path`.
pub fn sidecar_path(vault_path: &std::path::Path) -> std::path::PathBuf {
    let mut name = vault_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("default.vault")
        .to_owned();
    name.push_str(".bio-wrap");
    vault_path.with_file_name(name)
}

/// Persist a newly enrolled biometric wrap beside the vault.
pub fn enroll(
    vault_path: &std::path::Path,
    wrap_key: &SecretKey,
    dek: &SecretKey,
) -> Result<(), CryptoError> {
    let sealed = wrap_dek(wrap_key, dek)?;
    let sidecar = BiometricDekSidecar::from_sealed(&sealed);
    let bytes = serde_json::to_vec(&sidecar).map_err(|_| CryptoError::Encrypt)?;
    crate::write_private_atomic(&sidecar_path(vault_path), &bytes).map_err(|_| CryptoError::Encrypt)
}

/// Load and unwrap the sidecar DEK.
pub fn unlock_dek(
    vault_path: &std::path::Path,
    wrap_key: &SecretKey,
) -> Result<SecretKey, CryptoError> {
    let bytes = std::fs::read(sidecar_path(vault_path)).map_err(|_| CryptoError::Decrypt)?;
    let sidecar: BiometricDekSidecar =
        serde_json::from_slice(&bytes).map_err(|_| CryptoError::Decrypt)?;
    let sealed = sidecar.to_sealed()?;
    unwrap_dek(wrap_key, &sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_round_trip() {
        let wrap_key = crypto::random_key();
        let dek = crypto::random_key();
        let sealed = wrap_dek(&wrap_key, &dek).expect("wrap");
        let opened = unwrap_dek(&wrap_key, &sealed).expect("unwrap");
        assert_eq!(&*dek, &*opened);
    }

    #[test]
    fn wrong_wrap_key_fails_closed() {
        let dek = crypto::random_key();
        let sealed = wrap_dek(&crypto::random_key(), &dek).expect("wrap");
        assert!(unwrap_dek(&crypto::random_key(), &sealed).is_err());
    }

    #[test]
    fn sidecar_path_is_sibling_not_nested_extension_collision() {
        let path = std::path::Path::new("/tmp/default.vault");
        assert_eq!(
            sidecar_path(path),
            std::path::PathBuf::from("/tmp/default.vault.bio-wrap")
        );
    }

    #[test]
    fn sidecar_rejects_unknown_format() {
        let sidecar = BiometricDekSidecar {
            format_version: 99,
            nonce: vec![0; crypto::NONCE_LEN],
            ciphertext: vec![1, 2, 3],
        };
        assert!(sidecar.to_sealed().is_err());
    }

    #[test]
    fn enroll_then_unlock_round_trips_on_disk() {
        let dir = std::env::temp_dir().join(format!(
            "3fa-bio-wrap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let vault = dir.join("default.vault");
        let wrap_key = crypto::random_key();
        let dek = crypto::random_key();
        enroll(&vault, &wrap_key, &dek).expect("enroll");
        let opened = unlock_dek(&vault, &wrap_key).expect("unlock");
        assert_eq!(&*dek, &*opened);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
