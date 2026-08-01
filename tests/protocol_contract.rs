use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use threefa_core::protocol as local;
use threefa_interfaces as canonical;

fn assert_same_wire<L, C>(local_value: &L, canonical_value: &C)
where
    L: Serialize + DeserializeOwned,
    C: Serialize + DeserializeOwned,
{
    let local_json = serde_json::to_value(local_value).expect("serialize desktop adapter");
    let canonical_json =
        serde_json::to_value(canonical_value).expect("serialize canonical interface");
    assert_eq!(local_json, canonical_json);

    let _: L = serde_json::from_value(canonical_json).expect("canonical wire decodes locally");
    let _: C = serde_json::from_value(local_json).expect("desktop wire decodes canonically");
}

fn local_kdf() -> local::KdfParams {
    local::KdfParams {
        mem_kib: 256 * 1024,
        iterations: 3,
        parallelism: 1,
    }
}

fn canonical_kdf() -> canonical::KdfParams {
    canonical::KdfParams {
        mem_kib: 256 * 1024,
        iterations: 3,
        parallelism: 1,
    }
}

fn local_blob() -> local::SealedBlob {
    local::SealedBlob {
        ciphertext: vec![1, 3, 3, 7],
        nonce: vec![5; local::NONCE_LEN],
        kdf_salt: vec![8; 16],
        kdf_params: local_kdf(),
    }
}

fn canonical_blob() -> canonical::SealedBlob {
    canonical::SealedBlob {
        ciphertext: vec![1, 3, 3, 7],
        nonce: vec![5; canonical::NONCE_LEN],
        kdf_salt: vec![8; 16],
        kdf_params: canonical_kdf(),
    }
}

fn local_version() -> local::VersionVector {
    vec![local::VersionEntry {
        device_id: "device-a".to_owned(),
        counter: 7,
    }]
}

fn canonical_version() -> canonical::VersionVector {
    vec![canonical::VersionEntry {
        device_id: "device-a".to_owned(),
        counter: 7,
    }]
}

#[test]
fn vendored_interface_constants_match_desktop_validation_bounds() {
    assert_eq!(local::PROTOCOL_VERSION, canonical::PROTOCOL_VERSION);
    assert_eq!(local::NONCE_LEN, canonical::NONCE_LEN);
    assert_eq!(local::MIN_KDF_SALT_LEN, canonical::MIN_KDF_SALT_LEN);
    assert_eq!(local::MAX_KDF_SALT_LEN, canonical::MAX_KDF_SALT_LEN);
    assert_eq!(local::MAX_CIPHERTEXT_LEN, canonical::MAX_CIPHERTEXT_LEN);
    assert_eq!(local::MAX_VERSION_ENTRIES, canonical::MAX_VERSION_ENTRIES);
    assert_eq!(local::MAX_DEVICE_ID_LEN, canonical::MAX_DEVICE_ID_LEN);
}

#[test]
fn legacy_desktop_adapters_match_the_vendored_canonical_wire_contract() {
    assert_same_wire(&local_kdf(), &canonical_kdf());
    assert_same_wire(&local_blob(), &canonical_blob());

    let local_entry = local::VersionEntry {
        device_id: "device-a".to_owned(),
        counter: 7,
    };
    let canonical_entry = canonical::VersionEntry {
        device_id: "device-a".to_owned(),
        counter: 7,
    };
    assert_same_wire(&local_entry, &canonical_entry);
    assert_same_wire(&local_version(), &canonical_version());

    let local_push = local::PushRequest {
        device_id: "device-a".to_owned(),
        blob: local_blob(),
        base_version: local_version(),
    };
    let canonical_push = canonical::PushRequest {
        device_id: "device-a".to_owned(),
        blob: canonical_blob(),
        base_version: canonical_version(),
    };
    assert_same_wire(&local_push, &canonical_push);

    assert_same_wire(
        &local::PushResponse::Ok {
            version: local_version(),
        },
        &canonical::PushResponse::Ok {
            version: canonical_version(),
        },
    );
    assert_same_wire(
        &local::PushResponse::Conflict {
            server_version: local_version(),
        },
        &canonical::PushResponse::Conflict {
            server_version: canonical_version(),
        },
    );

    assert_same_wire(
        &local::PullResponse {
            blob: Some(local_blob()),
            version: local_version(),
        },
        &canonical::PullResponse {
            blob: Some(canonical_blob()),
            version: canonical_version(),
        },
    );
    assert_same_wire(
        &local::PullResponse {
            blob: None,
            version: Vec::new(),
        },
        &canonical::PullResponse {
            blob: None,
            version: Vec::new(),
        },
    );
}

#[test]
fn representative_contract_json_contains_no_plaintext_secret_fields() {
    let json: Value = serde_json::to_value(local::PushRequest {
        device_id: "device-a".to_owned(),
        blob: local_blob(),
        base_version: local_version(),
    })
    .expect("serialize representative push request");
    let encoded = json.to_string().to_ascii_lowercase();
    for forbidden in ["otp_seed", "password", "vault_key", "plaintext"] {
        assert!(
            !encoded.contains(forbidden),
            "wire contract exposed {forbidden}"
        );
    }
}
