//! Emit cross-compatibility fixtures for the Flutter app's test suite.
//!
//! Prints two JSON lines (fast Argon2 params so the Dart side opens them quickly):
//!   VAULTFILE <json>   — a sealed `VaultFile`, passcode "123456"
//!   SYNCBLOB  <json>   — a sealed sync `SealedBlob`, account password "account-pw"
//!
//! Both wrap the same single account. The mobile test (`cross_compat_test.dart`)
//! unlocks these to prove a Rust-sealed vault opens in Dart. Run:
//!   cargo run --no-default-features --example gen_fixture

use threefa_core::crypto;
use threefa_core::protocol::{KdfParams, SealedBlob};
use threefa_core::vault::{
    FactorPolicy, StoredAccount, StoredAlg, StoredKind, VaultData, VaultFile,
};

fn sample_data() -> VaultData {
    VaultData {
        accounts: vec![StoredAccount {
            id: "GitHub:octocat".into(),
            issuer: "GitHub".into(),
            label: "GitHub:octocat".into(),
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

fn main() {
    // Minimum sane Argon2 params (8 MiB / 1 pass) so the Dart test stays fast.
    let params = KdfParams {
        mem_kib: 8 * 1024,
        iterations: 1,
        parallelism: 1,
    };
    let data = sample_data();

    // ---- sealed VaultFile (passcode-wrapped DEK) ----
    let salt = crypto::random_salt();
    let kek = crypto::derive_key(b"123456", &salt, params).unwrap();
    let dek = crypto::random_key();
    let wrapped = crypto::wrap_key(&kek, &dek).unwrap();
    let payload_json = serde_json::to_vec(&data).unwrap();
    let payload = crypto::seal(&dek, &payload_json, b"3fa-vault-payload-v1").unwrap();
    let file = VaultFile {
        format_version: VaultFile::CURRENT_FORMAT,
        kdf_salt: salt.to_vec(),
        kdf_params: params,
        wrapped_dek: wrapped.into(),
        payload: payload.into(),
    };
    println!("VAULTFILE {}", serde_json::to_string(&file).unwrap());

    // ---- sealed sync SealedBlob (account-password E2E key) ----
    let bsalt = crypto::random_salt();
    let bkey = crypto::derive_key(b"account-pw", &bsalt, params).unwrap();
    let bjson = serde_json::to_vec(&data).unwrap();
    let bsealed = crypto::seal(&bkey, &bjson, b"3fa-sync-blob-v1").unwrap();
    let blob = SealedBlob {
        ciphertext: bsealed.ciphertext,
        nonce: bsealed.nonce.to_vec(),
        kdf_salt: bsalt.to_vec(),
        kdf_params: params,
    };
    println!("SYNCBLOB {}", serde_json::to_string(&blob).unwrap());
}
