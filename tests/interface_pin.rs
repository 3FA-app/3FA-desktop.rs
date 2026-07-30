use threefa_core::protocol as desktop;
use threefa_interfaces as canonical;

fn desktop_blob() -> desktop::SealedBlob {
    desktop::SealedBlob {
        ciphertext: vec![1, 2, 3, 4],
        nonce: vec![5; desktop::NONCE_LEN],
        kdf_salt: vec![6; 16],
        kdf_params: desktop::KdfParams {
            mem_kib: 262_144,
            iterations: 3,
            parallelism: 1,
        },
    }
}

fn canonical_blob() -> canonical::SealedBlob {
    canonical::SealedBlob {
        ciphertext: vec![1, 2, 3, 4],
        nonce: vec![5; canonical::NONCE_LEN],
        kdf_salt: vec![6; 16],
        kdf_params: canonical::KdfParams {
            mem_kib: 262_144,
            iterations: 3,
            parallelism: 1,
        },
    }
}

#[test]
fn legacy_constants_match_the_canonical_contract() {
    assert_eq!(desktop::PROTOCOL_VERSION, canonical::PROTOCOL_VERSION);
    assert_eq!(desktop::NONCE_LEN, canonical::NONCE_LEN);
    assert_eq!(desktop::MIN_KDF_SALT_LEN, canonical::MIN_KDF_SALT_LEN);
    assert_eq!(desktop::MAX_KDF_SALT_LEN, canonical::MAX_KDF_SALT_LEN);
    assert_eq!(desktop::MAX_CIPHERTEXT_LEN, canonical::MAX_CIPHERTEXT_LEN);
    assert_eq!(desktop::MAX_VERSION_ENTRIES, canonical::MAX_VERSION_ENTRIES);
    assert_eq!(desktop::MAX_DEVICE_ID_LEN, canonical::MAX_DEVICE_ID_LEN);
}

#[test]
fn legacy_vault_json_matches_the_canonical_generated_types() {
    assert_eq!(
        serde_json::to_value(desktop_blob()).unwrap(),
        serde_json::to_value(canonical_blob()).unwrap(),
    );

    let desktop_request = desktop::PushRequest {
        device_id: "device-a".into(),
        blob: desktop_blob(),
        base_version: vec![desktop::VersionEntry {
            device_id: "device-a".into(),
            counter: 7,
        }],
    };
    let canonical_request = canonical::PushRequest {
        device_id: "device-a".into(),
        blob: canonical_blob(),
        base_version: vec![canonical::VersionEntry {
            device_id: "device-a".into(),
            counter: 7,
        }],
    };
    assert_eq!(
        serde_json::to_value(desktop_request).unwrap(),
        serde_json::to_value(canonical_request).unwrap(),
    );
}

#[test]
fn new_signal_types_are_canonical_reexports() {
    let envelope = desktop::SignalCiphertextEnvelope {
        metadata: desktop::SignalEnvelopeMetadata {
            version: 1,
            envelope_id: "envelope-1".into(),
            account_id: "account-1".into(),
            sender_device_id: "sender-1".into(),
            recipient_device_id: "recipient-1".into(),
            session_id: "session-1".into(),
            message_number: 1,
            kind: "vault_mutation".into(),
            created_at_ms: 1,
            expires_at_ms: 2,
        },
        ciphertext: vec![9, 8, 7],
    };
    let value = serde_json::to_value(envelope).unwrap();
    assert_eq!(value["metadata"]["recipient_device_id"], "recipient-1");
    for forbidden in [
        "identity_private_key",
        "ratchet_state",
        "vault_plaintext",
        "pin_verifier",
        "biometric_template",
        "recovery_key",
    ] {
        assert!(value.get(forbidden).is_none());
    }
}
