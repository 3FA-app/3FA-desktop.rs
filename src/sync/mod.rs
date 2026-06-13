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
use crate::vault::{VaultData, VaultError};
use crate::protocol::{
    KdfParams, PullResponse, PushRequest, PushResponse, SealedBlob, VersionVector,
};
use zeroize::Zeroizing;

#[cfg(feature = "sync-net")]
pub mod http;

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
pub fn seal_for_upload(
    data: &VaultData,
    account_password: &[u8],
) -> Result<SealedBlob, SyncError> {
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
pub fn open_downloaded(
    blob: &SealedBlob,
    account_password: &[u8],
) -> Result<VaultData, SyncError> {
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

/// Merge a remote vault into the local one without losing enrollments.
///
/// Accounts are unioned by their stable `id` (`issuer:label`); on a tie the local
/// copy wins (it may hold a fresher HOTP counter). Local policy / voiceprint are
/// authoritative for this device. This is deliberately additive: a sync can add
/// accounts seen on another device but never silently drop one you hold.
pub fn merge_vault(local: &VaultData, remote: &VaultData) -> VaultData {
    let mut accounts = local.accounts.clone();
    for r in &remote.accounts {
        if !accounts.iter().any(|a| a.id == r.id) {
            accounts.push(r.clone());
        }
    }
    VaultData {
        accounts,
        policy: local.policy,
        voiceprint: local.voiceprint.clone(),
        voice_pin_hash: local.voice_pin_hash.clone(),
    }
}

/// Maximum push retries when another device races us between pull and push.
const SYNC_MAX_ATTEMPTS: u32 = 4;

/// Run one full reconcile against the server: pull the current sealed blob, merge
/// it into `local`, and push the result. Returns the merged vault and the new
/// authoritative version vector. Retries on a version-vector conflict (someone
/// else pushed in between) by re-pulling and re-merging.
///
/// The blob is sealed under the **account password** E2E key, so the server only
/// ever sees ciphertext — the zero-knowledge guarantee holds across sync.
pub fn synchronize<T: Transport>(
    transport: &mut T,
    account_password: &[u8],
    device_id: &str,
    local: &VaultData,
) -> Result<(VaultData, VersionVector), SyncError> {
    let mut working = local.clone();
    for _ in 0..SYNC_MAX_ATTEMPTS {
        let pulled = transport.pull()?;
        let merged = match &pulled.blob {
            Some(blob) => {
                let remote = open_downloaded(blob, account_password)?;
                merge_vault(&working, &remote)
            }
            None => working.clone(),
        };

        let blob = seal_for_upload(&merged, account_password)?;
        let req = PushRequest {
            device_id: device_id.to_string(),
            blob,
            base_version: pulled.version.clone(),
        };
        match transport.push(&req)? {
            PushResponse::Ok { version } => return Ok((merged, version)),
            PushResponse::Conflict { .. } => {
                // Server advanced under us; fold what we just merged back into the
                // working set and try again from a fresh pull.
                working = merged;
                continue;
            }
        }
    }
    Err(SyncError::Transport(
        "sync did not converge after repeated conflicts".into(),
    ))
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

    #[test]
    fn uploaded_blob_carries_no_plaintext() {
        // The ciphertext must not contain the recognizable issuer string.
        let blob = seal_for_upload(&sample(), b"pw").unwrap();
        let needle = b"GitHub";
        assert!(
            !blob
                .ciphertext
                .windows(needle.len())
                .any(|w| w == needle),
            "plaintext issuer leaked into ciphertext"
        );
    }

    fn account(id: &str) -> StoredAccount {
        StoredAccount {
            id: id.into(),
            issuer: id.split(':').next().unwrap_or(id).into(),
            label: id.into(),
            secret: b"12345678901234567890".to_vec(),
            kind: StoredKind::Totp,
            algorithm: StoredAlg::Sha1,
            digits: 6,
            period: 30,
            counter: 0,
        }
    }

    fn vault_with(ids: &[&str]) -> VaultData {
        VaultData {
            accounts: ids.iter().map(|i| account(i)).collect(),
            policy: FactorPolicy::default(),
            voiceprint: None,
            voice_pin_hash: None,
        }
    }

    #[test]
    fn merge_is_additive_and_dedups_by_id() {
        let local = vault_with(&["GitHub:a", "AWS:b"]);
        let remote = vault_with(&["AWS:b", "GitLab:c"]);
        let merged = merge_vault(&local, &remote);
        let mut ids: Vec<_> = merged.accounts.iter().map(|a| a.id.clone()).collect();
        ids.sort();
        assert_eq!(ids, vec!["AWS:b", "GitHub:a", "GitLab:c"]);
    }

    /// In-memory stand-in for the server: mirrors the backend's version-vector
    /// reconcile (`vault_blob::reconcile`) so `synchronize` can be exercised
    /// without a database or network.
    struct FakeServer {
        password: Vec<u8>,
        stored: Option<SealedBlob>,
        version: VersionVector,
    }

    fn dominates(a: &VersionVector, b: &VersionVector) -> bool {
        b.iter().all(|e| {
            a.iter()
                .find(|x| x.device_id == e.device_id)
                .map(|x| x.counter)
                .unwrap_or(0)
                >= e.counter
        })
    }

    fn bump(base: &VersionVector, device: &str) -> VersionVector {
        use crate::protocol::VersionEntry;
        let mut out = base.clone();
        match out.iter_mut().find(|e| e.device_id == device) {
            Some(e) => e.counter += 1,
            None => out.push(VersionEntry {
                device_id: device.into(),
                counter: 1,
            }),
        }
        out
    }

    impl Transport for FakeServer {
        fn push(&mut self, req: &PushRequest) -> Result<PushResponse, SyncError> {
            if dominates(&req.base_version, &self.version) {
                self.version = bump(&req.base_version, &req.device_id);
                self.stored = Some(req.blob.clone());
                Ok(PushResponse::Ok {
                    version: self.version.clone(),
                })
            } else {
                Ok(PushResponse::Conflict {
                    server_version: self.version.clone(),
                })
            }
        }
        fn pull(&mut self) -> Result<PullResponse, SyncError> {
            Ok(PullResponse {
                blob: self.stored.clone(),
                version: self.version.clone(),
            })
        }
    }

    #[test]
    fn synchronize_uploads_then_merges_remote_changes() {
        let password = b"correct horse battery".to_vec();
        let mut server = FakeServer {
            password: password.clone(),
            stored: None,
            version: Vec::new(),
        };

        // Device A pushes its first account.
        let a_local = vault_with(&["GitHub:a"]);
        let (a_merged, _v) = synchronize(&mut server, &password, "devA", &a_local).unwrap();
        assert_eq!(a_merged.accounts.len(), 1);

        // Device B (different local set) syncs and should end up holding both.
        let b_local = vault_with(&["AWS:b"]);
        let (b_merged, _v) = synchronize(&mut server, &password, "devB", &b_local).unwrap();
        let mut ids: Vec<_> = b_merged.accounts.iter().map(|a| a.id.clone()).collect();
        ids.sort();
        assert_eq!(ids, vec!["AWS:b", "GitHub:a"]);

        // And what's stored decrypts back to the union under the same password.
        let stored = server.stored.clone().unwrap();
        let back = open_downloaded(&stored, &server.password).unwrap();
        assert_eq!(back.accounts.len(), 2);
    }
}
