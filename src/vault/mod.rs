//! The encrypted vault: at-rest storage of OTP accounts, factor policy, and the
//! optional voiceprint, plus the sealed on-disk file format.
//!
//! On-disk layout (`VaultFile`, serialized as JSON then written to `*.vault`):
//!
//! ```text
//! VaultFile {
//!   kdf_salt, kdf_params,         // to re-derive the KEK from the passcode
//!   wrapped_dek: Sealed,          // DEK encrypted under KEK (and, on macOS,
//!                                 //   additionally under the Secure Enclave)
//!   payload: Sealed,              // the VaultData JSON, encrypted under the DEK
//! }
//! ```
//!
//! The passcode (and/or biometric) yields the KEK → unwraps the DEK → opens the
//! payload. Without a valid factor the file is opaque ciphertext.

use crate::crypto::{self, CryptoError, Sealed, KEY_LEN, SALT_LEN};
use crate::otp::uri::{OtpAccount, OtpKind};
use crate::otp::Algorithm;
use crate::protocol::KdfParams;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Factor policy: how many distinct factor kinds each gate requires.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct FactorPolicy {
    /// Factors required to unlock the vault (2 = 2FA, 3 = 3FA).
    pub unlock_factors: u8,
    /// Factors required to extend an unlocked session toward the 5-min cap.
    pub extend_factors: u8,
}

impl Default for FactorPolicy {
    fn default() -> Self {
        // Out of the box: passcode-or-biometric to unlock (1), a *distinct*
        // second factor to extend. Users can raise to true 3FA in settings.
        Self {
            unlock_factors: 1,
            extend_factors: 1,
        }
    }
}

/// Serializable form of an enrolled account (the runtime [`OtpAccount`] carries
/// zeroizing semantics; this is its on-disk projection, encrypted at rest).
///
/// Like [`OtpAccount`], the decrypted form wipes its `secret` on drop so raw OTP
/// seeds don't linger in freed heap after the vault re-locks. Non-secret fields
/// are `#[zeroize(skip)]` (the enums also don't implement `Zeroize`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct StoredAccount {
    #[zeroize(skip)]
    pub id: String,
    #[zeroize(skip)]
    pub issuer: String,
    #[zeroize(skip)]
    pub label: String,
    /// Raw key bytes. Only ever exists inside the DEK-encrypted payload, and is
    /// zeroized on drop.
    pub secret: Vec<u8>,
    #[zeroize(skip)]
    pub kind: StoredKind,
    #[zeroize(skip)]
    pub algorithm: StoredAlg,
    #[zeroize(skip)]
    pub digits: u32,
    #[zeroize(skip)]
    pub period: u64,
    #[zeroize(skip)]
    pub counter: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum StoredKind {
    Totp,
    Hotp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum StoredAlg {
    Sha1,
    Sha256,
    Sha512,
}

impl From<&OtpAccount> for StoredAccount {
    fn from(a: &OtpAccount) -> Self {
        StoredAccount {
            id: format!("{}:{}", a.issuer, a.label),
            issuer: a.issuer.clone(),
            label: a.label.clone(),
            secret: a.secret.clone(),
            kind: match a.kind {
                OtpKind::Totp => StoredKind::Totp,
                OtpKind::Hotp => StoredKind::Hotp,
            },
            algorithm: match a.algorithm {
                Algorithm::Sha1 => StoredAlg::Sha1,
                Algorithm::Sha256 => StoredAlg::Sha256,
                Algorithm::Sha512 => StoredAlg::Sha512,
            },
            digits: a.digits,
            period: a.period,
            counter: a.counter,
        }
    }
}

impl StoredAccount {
    pub fn algorithm(&self) -> Algorithm {
        match self.algorithm {
            StoredAlg::Sha1 => Algorithm::Sha1,
            StoredAlg::Sha256 => Algorithm::Sha256,
            StoredAlg::Sha512 => Algorithm::Sha512,
        }
    }

    /// Compute the current TOTP code (or HOTP at the stored counter).
    pub fn current_code(&self, unix_time: u64) -> Result<String, crate::otp::OtpError> {
        let code = match self.kind {
            StoredKind::Totp => crate::otp::totp_at(
                self.algorithm(),
                &self.secret,
                unix_time,
                self.period.max(1),
                0,
                self.digits,
            )?,
            StoredKind::Hotp => {
                crate::otp::hotp(self.algorithm(), &self.secret, self.counter, self.digits)?
            }
        };
        Ok(crate::otp::format_code(code, self.digits))
    }
}

/// The decrypted vault contents held in memory while unlocked. Wipes its
/// secret-bearing fields on drop (each account's seed, the voiceprint, and the
/// voice-PIN hash) so they don't outlive a re-lock in freed memory.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultData {
    pub accounts: Vec<StoredAccount>,
    #[zeroize(skip)]
    pub policy: FactorPolicy,
    /// Speaker-verification embedding for the voice factor, if enrolled. Stored
    /// only inside the encrypted payload and never uploaded to the server.
    pub voiceprint: Option<Vec<f32>>,
    /// Argon2id hash of the spoken 4-digit PIN (knowledge half of the voice
    /// factor). Stored as an encoded PHC string.
    pub voice_pin_hash: Option<String>,
}

/// The sealed on-disk file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultFile {
    pub format_version: u32,
    pub kdf_salt: Vec<u8>,
    pub kdf_params: KdfParams,
    pub wrapped_dek: SealedRepr,
    pub payload: SealedRepr,
}

/// Serde-friendly mirror of [`crypto::Sealed`] (fixed-size arrays serialize
/// awkwardly, so we use Vecs on the wire and validate lengths on load).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedRepr {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl From<Sealed> for SealedRepr {
    fn from(s: Sealed) -> Self {
        SealedRepr {
            nonce: s.nonce.to_vec(),
            ciphertext: s.ciphertext,
        }
    }
}

impl TryFrom<&SealedRepr> for Sealed {
    type Error = VaultError;
    fn try_from(r: &SealedRepr) -> Result<Self, Self::Error> {
        let nonce: [u8; crypto::NONCE_LEN] = r
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Corrupt)?;
        Ok(Sealed {
            nonce,
            ciphertext: r.ciphertext.clone(),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("vault file is corrupt or truncated")]
    Corrupt,
    #[error("unsupported vault format version {0} (supported: {expected})", expected = VaultFile::CURRENT_FORMAT)]
    UnsupportedVersion(u32),
    #[error("serialization error: {0}")]
    Serde(String),
}

impl VaultFile {
    pub const CURRENT_FORMAT: u32 = 1;

    /// Create a brand-new sealed vault from a passcode and initial data.
    ///
    /// Generates a random DEK, wraps it under KEK = Argon2id(passcode), and seals
    /// the payload under the DEK. Returns the file plus the live DEK so the
    /// caller can keep the vault unlocked without re-deriving.
    pub fn create(
        passcode: &[u8],
        data: &VaultData,
    ) -> Result<(Self, crypto::SecretKey), VaultError> {
        let kdf_params = KdfParams::default();
        let salt = crypto::random_salt();
        let kek = crypto::derive_key(passcode, &salt, kdf_params)?;
        let dek = crypto::random_key();

        let wrapped = crypto::wrap_key(&kek, &dek)?;
        let payload = Self::seal_payload(&dek, data)?;

        Ok((
            VaultFile {
                format_version: Self::CURRENT_FORMAT,
                kdf_salt: salt.to_vec(),
                kdf_params,
                wrapped_dek: wrapped.into(),
                payload: payload.into(),
            },
            dek,
        ))
    }

    /// Unlock with a passcode: re-derive KEK, unwrap DEK, decrypt payload.
    pub fn unlock(&self, passcode: &[u8]) -> Result<(VaultData, crypto::SecretKey), VaultError> {
        // Refuse a file written by a newer/unknown format rather than risk
        // misinterpreting its fields (fail closed on forward-incompatibility).
        if self.format_version != Self::CURRENT_FORMAT {
            return Err(VaultError::UnsupportedVersion(self.format_version));
        }
        let salt: [u8; SALT_LEN] = self
            .kdf_salt
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Corrupt)?;
        let kek = crypto::derive_key(passcode, &salt, self.kdf_params)?;
        let wrapped = Sealed::try_from(&self.wrapped_dek)?;
        let dek = crypto::unwrap_key(&kek, &wrapped)?;
        let data = self.open_payload(&dek)?;
        Ok((data, dek))
    }

    /// Re-seal updated data under an already-unwrapped DEK (no KDF cost).
    pub fn reseal(&mut self, dek: &[u8; KEY_LEN], data: &VaultData) -> Result<(), VaultError> {
        self.payload = Self::seal_payload(dek, data)?.into();
        Ok(())
    }

    fn seal_payload(dek: &[u8; KEY_LEN], data: &VaultData) -> Result<Sealed, VaultError> {
        let json = serde_json::to_vec(data).map_err(|e| VaultError::Serde(e.to_string()))?;
        let json = Zeroizing::new(json);
        Ok(crypto::seal(dek, &json, b"3fa-vault-payload-v1")?)
    }

    fn open_payload(&self, dek: &[u8; KEY_LEN]) -> Result<VaultData, VaultError> {
        let sealed = Sealed::try_from(&self.payload)?;
        let plain = crypto::open(dek, &sealed, b"3fa-vault-payload-v1")?;
        serde_json::from_slice(&plain).map_err(|e| VaultError::Serde(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data() -> VaultData {
        let acct = OtpAccount::from_uri(
            "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
        )
        .unwrap();
        // Construct fields explicitly: `..Default::default()` can't partial-move
        // out of a `Drop` type (VaultData now zeroizes on drop).
        VaultData {
            accounts: vec![StoredAccount::from(&acct)],
            policy: FactorPolicy::default(),
            voiceprint: None,
            voice_pin_hash: None,
        }
    }

    #[test]
    fn create_then_unlock_round_trips() {
        let data = sample_data();
        let (file, _dek) = VaultFile::create(b"123456", &data).unwrap();
        let (loaded, _) = file.unlock(b"123456").unwrap();
        assert_eq!(loaded.accounts.len(), 1);
        assert_eq!(loaded.accounts[0].issuer, "GitHub");
    }

    #[test]
    fn wrong_passcode_is_rejected() {
        let (file, _dek) = VaultFile::create(b"123456", &sample_data()).unwrap();
        let err = file.unlock(b"000000").unwrap_err();
        assert!(matches!(err, VaultError::Crypto(CryptoError::Decrypt)));
    }

    #[test]
    fn survives_json_serialization() {
        let (file, _) = VaultFile::create(b"123456", &sample_data()).unwrap();
        let json = serde_json::to_string(&file).unwrap();
        let back: VaultFile = serde_json::from_str(&json).unwrap();
        let (loaded, _) = back.unlock(b"123456").unwrap();
        assert_eq!(loaded.accounts.len(), 1);
    }

    #[test]
    fn reseal_persists_new_accounts() {
        let (mut file, dek) = VaultFile::create(b"123456", &sample_data()).unwrap();
        let mut data = sample_data();
        let acct =
            OtpAccount::from_uri("otpauth://totp/AWS:root?secret=JBSWY3DPEHPK3PXP&issuer=AWS")
                .unwrap();
        data.accounts.push(StoredAccount::from(&acct));
        file.reseal(&dek, &data).unwrap();
        let (loaded, _) = file.unlock(b"123456").unwrap();
        assert_eq!(loaded.accounts.len(), 2);
    }

    #[test]
    fn rejects_unknown_format_version() {
        let (mut file, _dek) = VaultFile::create(b"123456", &sample_data()).unwrap();
        file.format_version = VaultFile::CURRENT_FORMAT + 1;
        let err = file.unlock(b"123456").unwrap_err();
        assert!(
            matches!(err, VaultError::UnsupportedVersion(v) if v == VaultFile::CURRENT_FORMAT + 1)
        );
    }

    /// A truncated on-disk nonce must surface as `Corrupt`, not panic or decrypt.
    #[test]
    fn corrupt_nonce_length_is_rejected() {
        let (mut file, _dek) = VaultFile::create(b"123456", &sample_data()).unwrap();
        file.wrapped_dek.nonce.truncate(4);
        assert!(matches!(file.unlock(b"123456"), Err(VaultError::Corrupt)));
    }

    /// An HOTP account computes codes from its *stored counter* — pinned against
    /// the RFC 4226 Appendix D vectors (counter 3 -> 969429, counter 7 -> 162583).
    #[test]
    fn hotp_account_uses_stored_counter() {
        let mut acct = StoredAccount {
            id: "x".into(),
            issuer: "x".into(),
            label: "x".into(),
            secret: b"12345678901234567890".to_vec(),
            kind: StoredKind::Hotp,
            algorithm: StoredAlg::Sha1,
            digits: 6,
            period: 30,
            counter: 3,
        };
        // unix_time is irrelevant for HOTP.
        assert_eq!(acct.current_code(0).unwrap(), "969429");
        assert_eq!(acct.current_code(999_999).unwrap(), "969429");
        acct.counter = 7;
        assert_eq!(acct.current_code(0).unwrap(), "162583");
    }

    #[test]
    fn computes_known_totp_code() {
        // Cross-check: secret "12345678901234567890" at t=59 / 8 digits = 94287082.
        let acct = StoredAccount {
            id: "x".into(),
            issuer: "x".into(),
            label: "x".into(),
            secret: b"12345678901234567890".to_vec(),
            kind: StoredKind::Totp,
            algorithm: StoredAlg::Sha1,
            digits: 8,
            period: 30,
            counter: 0,
        };
        assert_eq!(acct.current_code(59).unwrap(), "94287082");
    }
}
