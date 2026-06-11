//! Local cryptography for the vault: key derivation, AEAD sealing, and key
//! material hygiene.
//!
//! Design (see plan "Crypto & security model"):
//!   * A random 256-bit **DEK** encrypts the vault with XChaCha20-Poly1305.
//!   * The DEK is wrapped by a **KEK** = Argon2id(passcode, salt).
//!   * On macOS the wrapped DEK is additionally sealed by the Secure Enclave
//!     (see `auth::biometric`); that layer lives outside this module so the
//!     pure-crypto path stays platform-independent and testable.
//!
//! Every key buffer is held in `Zeroizing`/`Zeroize` so it is wiped on drop.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use crate::protocol::KdfParams;
use zeroize::{Zeroize, Zeroizing};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key derivation failed")]
    Kdf,
    #[error("decryption failed: wrong passcode or corrupt data")]
    Decrypt,
    #[error("encryption failed")]
    Encrypt,
    #[error("invalid key length")]
    KeyLen,
}

/// A 256-bit symmetric key that wipes itself on drop.
pub type SecretKey = Zeroizing<[u8; KEY_LEN]>;

/// Derive a key from a low-entropy secret (passcode or account password) using
/// Argon2id with the supplied parameters and salt.
pub fn derive_key(
    secret: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<SecretKey, CryptoError> {
    let p = Params::new(
        params.mem_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| CryptoError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);

    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(secret, salt, &mut key)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(Zeroizing::new(key))
}

/// Generate a fresh random salt.
pub fn random_salt() -> [u8; SALT_LEN] {
    let mut s = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

/// Generate a fresh random 256-bit data-encryption key.
pub fn random_key() -> SecretKey {
    let mut k = [0u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut k);
    Zeroizing::new(k)
}

/// AEAD ciphertext bundle. `nonce` is unique per seal; `aad` is authenticated
/// but not encrypted (used to bind a blob to e.g. a vault version).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Encrypt `plaintext` under `key`, authenticating `aad`.
pub fn seal(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Sealed, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::Encrypt)?;

    Ok(Sealed {
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypt a [`Sealed`] bundle, verifying `aad`. Returns the plaintext in a
/// zeroizing buffer. A wrong key or any tampering yields [`CryptoError::Decrypt`]
/// and never partial plaintext (AEAD is all-or-nothing).
pub fn open(
    key: &[u8; KEY_LEN],
    sealed: &Sealed,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(&sealed.nonce);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &sealed.ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(Zeroizing::new(plaintext))
}

/// Wrap (encrypt) a DEK with a KEK. Just `seal` with no AAD, but named for intent.
pub fn wrap_key(kek: &[u8; KEY_LEN], dek: &[u8; KEY_LEN]) -> Result<Sealed, CryptoError> {
    seal(kek, dek, b"3fa-dek-wrap-v1")
}

/// Unwrap a DEK previously wrapped by [`wrap_key`].
pub fn unwrap_key(kek: &[u8; KEY_LEN], wrapped: &Sealed) -> Result<SecretKey, CryptoError> {
    let mut pt = open(kek, wrapped, b"3fa-dek-wrap-v1")?;
    if pt.len() != KEY_LEN {
        pt.zeroize();
        return Err(CryptoError::KeyLen);
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&pt);
    Ok(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fast KDF params for tests only — production uses KdfParams::default().
    fn fast_params() -> KdfParams {
        KdfParams {
            mem_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn seal_open_round_trip() {
        let key = random_key();
        let sealed = seal(&key, b"top secret seed", b"aad").unwrap();
        let opened = open(&key, &sealed, b"aad").unwrap();
        assert_eq!(&*opened, b"top secret seed");
    }

    #[test]
    fn wrong_key_fails_closed() {
        let key = random_key();
        let other = random_key();
        let sealed = seal(&key, b"secret", b"").unwrap();
        assert!(matches!(open(&other, &sealed, b""), Err(CryptoError::Decrypt)));
    }

    #[test]
    fn wrong_aad_fails() {
        let key = random_key();
        let sealed = seal(&key, b"secret", b"version-1").unwrap();
        assert!(matches!(
            open(&key, &sealed, b"version-2"),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = random_key();
        let mut sealed = seal(&key, b"secret", b"").unwrap();
        sealed.ciphertext[0] ^= 0xff;
        assert!(open(&key, &sealed, b"").is_err());
    }

    #[test]
    fn derive_key_is_deterministic() {
        let salt = [7u8; SALT_LEN];
        let a = derive_key(b"123456", &salt, fast_params()).unwrap();
        let b = derive_key(b"123456", &salt, fast_params()).unwrap();
        assert_eq!(&*a, &*b);
        let c = derive_key(b"654321", &salt, fast_params()).unwrap();
        assert_ne!(&*a, &*c);
    }

    #[test]
    fn key_wrap_round_trip() {
        let kek = random_key();
        let dek = random_key();
        let wrapped = wrap_key(&kek, &dek).unwrap();
        let unwrapped = unwrap_key(&kek, &wrapped).unwrap();
        assert_eq!(&*dek, &*unwrapped);
    }
}
