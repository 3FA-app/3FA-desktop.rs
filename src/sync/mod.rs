//! Client side of the zero-knowledge sync protocol.
//!
//! The vault is serialized, encrypted under an **E2E key** derived from the
//! account password (separate from the device passcode), and only then handed to
//! a [`Transport`]. The server stores the resulting [`SealedBlob`] verbatim and
//! can never decrypt it.
//!
//! Network I/O is abstracted behind [`Transport`] so this module — and its
//! crypto — builds and tests without pulling an HTTP stack into the core lib.

use crate::crypto::{self, CryptoError};
use crate::protocol::{
    KdfParams, PullResponse, PushRequest, PushResponse, SealedBlob, VersionVector,
};
use crate::vault::{VaultData, VaultError};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error("serialization error: {0}")]
    Serde(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("server is ahead; pull and merge before retrying")]
    Conflict(VersionVector),
}

/// Pluggable network transport (real impl wraps `reqwest` + the account's auth
/// token; tests use an in-memory fake).
pub trait Transport {
    fn push(&mut self, req: &PushRequest) -> Result<PushResponse, SyncError>;
    fn pull(&mut self) -> Result<PullResponse, SyncError>;
}

/// Encrypt a vault into a [`SealedBlob`] under the E2E key derived from the
/// account password. Pure function — the heart of the zero-knowledge guarantee.
pub fn seal_for_upload(data: &VaultData, account_password: &[u8]) -> Result<SealedBlob, SyncError> {
    let kdf_params = KdfParams::default();
    let salt = crypto::random_salt();
    let key = crypto::derive_key(account_password, &salt, kdf_params)?;

    let json = serde_json::to_vec(data).map_err(|e| SyncError::Serde(e.to_string()))?;
    let json = Zeroizing::new(json);
    let sealed = crypto::seal(&key, &json, b"3fa-sync-blob-v1")?;

    Ok(SealedBlob {
        ciphertext: sealed.ciphertext,
        nonce: sealed.nonce.to_vec(),
        kdf_salt: salt.to_vec(),
        kdf_params,
    })
}

/// Decrypt a downloaded [`SealedBlob`] back into vault data.
pub fn open_downloaded(blob: &SealedBlob, account_password: &[u8]) -> Result<VaultData, SyncError> {
    // The blob came from the (untrusted) network: a malicious or compromised
    // server can return arbitrary `kdf_params`. Validate the envelope shape and
    // clamp the KDF cost *before* calling `derive_key`, so the server can't make
    // this device allocate gigabytes / spin forever in Argon2 (a client-side DoS).
    if !blob.is_well_formed() {
        return Err(SyncError::Crypto(CryptoError::Decrypt));
    }
    let key = crypto::derive_key(account_password, &blob.kdf_salt, blob.kdf_params)?;
    let nonce: [u8; crypto::NONCE_LEN] = blob
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| SyncError::Crypto(CryptoError::Decrypt))?;
    let sealed = crypto::Sealed {
        nonce,
        ciphertext: blob.ciphertext.clone(),
    };
    let plain = crypto::open(&key, &sealed, b"3fa-sync-blob-v1")?;
    serde_json::from_slice(&plain).map_err(|e| SyncError::Serde(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{FactorPolicy, StoredAccount, StoredAlg, StoredKind};

    fn sample() -> VaultData {
        VaultData {
            accounts: vec![StoredAccount {
                id: "GitHub:octocat".into(),
                issuer: "GitHub".into(),
                label: "octocat".into(),
                secret: b"12345678901234567890".to_vec(),
                kind: StoredKind::Totp,
                algorithm: StoredAlg::Sha1,
                digits: 6,
                period: 30,
                counter: 0,
            }],
            policy: FactorPolicy::default(),
            voiceprint: None,
            voice_pin_hash: None,
        }
    }

    #[test]
    fn seal_then_open_round_trips() {
        let data = sample();
        let blob = seal_for_upload(&data, b"correct horse battery").unwrap();
        let back = open_downloaded(&blob, b"correct horse battery").unwrap();
        assert_eq!(back.accounts.len(), 1);
        assert_eq!(back.accounts[0].issuer, "GitHub");
    }

    #[test]
    fn wrong_account_password_fails_closed() {
        let blob = seal_for_upload(&sample(), b"right-password").unwrap();
        let err = open_downloaded(&blob, b"wrong-password").unwrap_err();
        assert!(matches!(err, SyncError::Crypto(CryptoError::Decrypt)));
    }

    /// Every uploaded blob must satisfy the shared protocol shape contract —
    /// the same `is_well_formed` the server enforces on push.
    #[test]
    fn uploaded_blob_is_well_formed_per_protocol() {
        let blob = seal_for_upload(&sample(), b"pw").unwrap();
        assert!(blob.is_well_formed());
        assert_eq!(blob.nonce.len(), crypto::NONCE_LEN);
        assert!(blob.kdf_params.is_sane());
    }

    /// A malicious server cannot drive this client into a gigabyte-scale KDF:
    /// insane `kdf_params` are rejected by the envelope check *before*
    /// `derive_key` runs. Same for a wrong-length nonce.
    #[test]
    fn hostile_envelope_is_rejected_before_kdf() {
        let mut blob = seal_for_upload(&sample(), b"pw").unwrap();
        blob.kdf_params.mem_kib = 64 * 1024 * 1024; // 64 GiB
        let start = std::time::Instant::now();
        let err = open_downloaded(&blob, b"pw").unwrap_err();
        assert!(matches!(err, SyncError::Crypto(CryptoError::Decrypt)));
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "rejection must happen before the KDF runs"
        );

        let mut bad_nonce = seal_for_upload(&sample(), b"pw").unwrap();
        bad_nonce.nonce.truncate(12);
        assert!(matches!(
            open_downloaded(&bad_nonce, b"pw"),
            Err(SyncError::Crypto(CryptoError::Decrypt))
        ));
    }

    /// In-memory fake transport: a full push -> pull cycle returns a blob that
    /// decrypts to the original vault, and a second client's stale push
    /// surfaces the server's version as a Conflict.
    #[test]
    fn push_pull_round_trip_through_transport() {
        use crate::protocol::VersionEntry;

        /// Minimal server double: stores the last accepted blob and bumps the
        /// pushing device's counter, conflicting when base_version is stale.
        struct FakeServer {
            blob: Option<SealedBlob>,
            version: VersionVector,
        }
        impl Transport for FakeServer {
            fn push(&mut self, req: &PushRequest) -> Result<PushResponse, SyncError> {
                let stale = self.version.iter().any(|s| {
                    req.base_version
                        .iter()
                        .find(|b| b.device_id == s.device_id)
                        .map(|b| b.counter < s.counter)
                        .unwrap_or(true)
                });
                if stale {
                    return Ok(PushResponse::Conflict {
                        server_version: self.version.clone(),
                    });
                }
                let mut version = req.base_version.clone();
                match version.iter_mut().find(|e| e.device_id == req.device_id) {
                    Some(e) => e.counter += 1,
                    None => version.push(VersionEntry {
                        device_id: req.device_id.clone(),
                        counter: 1,
                    }),
                }
                self.blob = Some(req.blob.clone());
                self.version = version.clone();
                Ok(PushResponse::Ok { version })
            }
            fn pull(&mut self) -> Result<PullResponse, SyncError> {
                Ok(PullResponse {
                    blob: self.blob.clone(),
                    version: self.version.clone(),
                })
            }
        }

        let mut server = FakeServer {
            blob: None,
            version: Vec::new(),
        };

        // Device A pushes the sealed vault.
        let blob = seal_for_upload(&sample(), b"account-pw").unwrap();
        let resp = server
            .push(&PushRequest {
                device_id: "dev-a".into(),
                blob,
                base_version: Vec::new(),
            })
            .unwrap();
        let version = match resp {
            PushResponse::Ok { version } => version,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_eq!(version.len(), 1);
        assert_eq!(version[0].counter, 1);

        // Any device pulls and decrypts the identical vault.
        let pulled = server.pull().unwrap();
        let data = open_downloaded(pulled.blob.as_ref().unwrap(), b"account-pw").unwrap();
        assert_eq!(data.accounts.len(), 1);
        assert_eq!(data.accounts[0].issuer, "GitHub");

        // Device B pushing with an empty (stale) base_version gets a Conflict
        // carrying the server's authoritative version.
        let stale_blob = seal_for_upload(&sample(), b"account-pw").unwrap();
        let resp = server
            .push(&PushRequest {
                device_id: "dev-b".into(),
                blob: stale_blob,
                base_version: Vec::new(),
            })
            .unwrap();
        match resp {
            PushResponse::Conflict { server_version } => assert_eq!(server_version, version),
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn uploaded_blob_carries_no_plaintext() {
        // The ciphertext must not contain the recognizable issuer string.
        let blob = seal_for_upload(&sample(), b"pw").unwrap();
        let needle = b"GitHub";
        assert!(
            !blob.ciphertext.windows(needle.len()).any(|w| w == needle),
            "plaintext issuer leaked into ciphertext"
        );
    }
}
