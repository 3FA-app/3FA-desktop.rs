#!/usr/bin/env python3
"""One-shot DEN-277 migration to canonical generated 3FA interfaces."""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
GENERATED = (
    pathlib.Path(os.environ["RUNNER_TEMP"])
    / "generated"
    / "generated"
    / "rust"
)
INTERFACES_COMMIT = os.environ["INTERFACES_COMMIT"]


def replace_once(source: str, old: str, new: str, *, name: str) -> str:
    if old not in source:
        raise RuntimeError(f"expected {name} anchor was not found")
    return source.replace(old, new, 1)


def git_blob(path: pathlib.Path) -> str:
    return subprocess.check_output(
        ["git", "hash-object", str(path)], text=True
    ).strip()


def main() -> None:
    if not GENERATED.joinpath("Cargo.toml").is_file():
        raise RuntimeError("generated Rust interface package is missing")

    vendor = ROOT / "vendor" / "threefa-interfaces"
    vendor.joinpath("src").mkdir(parents=True, exist_ok=True)
    shutil.copy2(GENERATED / "Cargo.toml", vendor / "Cargo.toml")
    shutil.copy2(GENERATED / "src" / "lib.rs", vendor / "src" / "lib.rs")

    cargo_path = ROOT / "Cargo.toml"
    cargo = cargo_path.read_text(encoding="utf-8")
    dependency = 'threefa-interfaces = { path = "vendor/threefa-interfaces" }\n'
    if dependency not in cargo:
        cargo = replace_once(
            cargo,
            "[dependencies]\n",
            "[dependencies]\n" + dependency,
            name="Cargo dependencies",
        )
    cargo_path.write_text(cargo, encoding="utf-8")

    protocol_path = ROOT / "src" / "protocol.rs"
    protocol = protocol_path.read_text(encoding="utf-8")
    old_header = """//! ⚠️ DUPLICATED across the frontend (`3fa-desktop.rs`) and backend
//! (`3fa-backend.rs`) repos by design — they are separate repos with no shared
//! crate. Keep the two copies byte-for-byte in sync; any divergence MUST bump
//! [`PROTOCOL_VERSION`] so a mismatch is detected at the boundary rather than
//! silently corrupting a sync.
"""
    new_header = """//! Legacy vault-sync DTOs remain local adapters while they carry desktop-only
//! validation methods. Their wire shape is checked against the vendored canonical
//! `threefa-interfaces` crate on every CI run. New Signal/device/recovery types are
//! re-exported directly from that immutable generated package rather than copied.
"""
    protocol = replace_once(
        protocol, old_header, new_header, name="duplicated protocol warning"
    )
    exports = """
pub use threefa_interfaces::{
    AccountDeviceSummary, DeviceEnrollmentRequest, DeviceRevocationRequest,
    EncryptedRecoveryPackage, LocalUnlockPolicy, PinKdfPolicy, RecoveryChallenge,
    RecoveryChannelSummary, SignalCiphertextEnvelope, SignalDevicePreKeyBundle,
    SignalDeviceRevisionResponse, SignalEnvelopeMetadata, SignalMailboxAckItem,
    SignalMailboxAckRequest, SignalMailboxAckResponse, SignalMailboxItem,
    SignalMailboxPullResponse, SignalOneTimePreKey, SignalPreKeyBundleResponse,
    SignalPublishPreKeysRequest, SignalPublishPreKeysResponse,
    SignalQueueEnvelopeRequest, SignalQueueEnvelopeResponse,
    UpsertRecoveryChannelRequest, VerifyRecoveryChallengeRequest,
};
"""
    if exports.strip() not in protocol:
        protocol = replace_once(
            protocol,
            "use std::collections::HashSet;\n",
            "use std::collections::HashSet;\n" + exports,
            name="protocol imports",
        )
    protocol_path.write_text(protocol, encoding="utf-8")

    readme_path = ROOT / "README.md"
    readme = readme_path.read_text(encoding="utf-8")
    old_readme = """> The sync wire-protocol types live in [`src/protocol.rs`](src/protocol.rs), a
> copy kept byte-for-byte in sync with the backend's copy (guarded by
> `PROTOCOL_VERSION`)."""
    new_readme = """> Canonical sync, Signal, device, and recovery wire types are vendored from
> `3fa-interfaces` at an immutable commit with exact Git-blob provenance. Legacy
> desktop vault-sync adapters in `src/protocol.rs` are JSON-parity tested against it."""
    readme = replace_once(readme, old_readme, new_readme, name="README protocol note")
    readme = replace_once(
        readme,
        "src/protocol.rs  Wire-protocol DTOs (duplicated with the backend)",
        "src/protocol.rs  Legacy adapters + canonical Signal type re-exports",
        name="README layout entry",
    )
    readme_path.write_text(readme, encoding="utf-8")

    tests = ROOT / "tests"
    tests.mkdir(exist_ok=True)
    tests.joinpath("interface_pin.rs").write_text(
        r'''use threefa_core::protocol as desktop;
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
''',
        encoding="utf-8",
    )

    provenance_paths = [
        pathlib.Path("vendor/threefa-interfaces/Cargo.toml"),
        pathlib.Path("vendor/threefa-interfaces/src/lib.rs"),
    ]
    manifest_lines = [
        'source_repository = "3FA-app/3fa-interfaces"',
        f'source_commit = "{INTERFACES_COMMIT}"',
        "",
        "[files]",
    ]
    for relative in provenance_paths:
        manifest_lines.append(f'"{relative.as_posix()}" = "{git_blob(ROOT / relative)}"')
    ROOT.joinpath("VENDORED_INTERFACES.toml").write_text(
        "\n".join(manifest_lines) + "\n", encoding="utf-8"
    )

    checker = ROOT / "scripts" / "check_vendored_interfaces.py"
    checker.write_text(
        r'''#!/usr/bin/env python3
import pathlib
import subprocess
import tomllib

root = pathlib.Path(__file__).resolve().parents[1]
with (root / "VENDORED_INTERFACES.toml").open("rb") as handle:
    manifest = tomllib.load(handle)
assert manifest["source_repository"] == "3FA-app/3fa-interfaces"
commit = manifest["source_commit"]
assert len(commit) == 40 and all(ch in "0123456789abcdef" for ch in commit)
for relative, expected in manifest["files"].items():
    path = root / relative
    assert path.is_file(), f"missing vendored interface file: {relative}"
    actual = subprocess.check_output(["git", "hash-object", str(path)], text=True).strip()
    assert actual == expected, f"vendored interface drift: {relative}"
print(f"verified vendored interfaces from {commit}")
''',
        encoding="utf-8",
    )

    ci_path = ROOT / ".github" / "workflows" / "ci.yml"
    ci = ci_path.read_text(encoding="utf-8")
    marker = "  # src/protocol.rs must stay byte-identical to the backend's copy"
    if marker not in ci:
        raise RuntimeError("legacy private backend checkout job was not found")
    ci = ci.split(marker, 1)[0].rstrip() + """

  interface-provenance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Verify immutable generated interface provenance
        run: python3 scripts/check_vendored_interfaces.py
      - name: Verify legacy JSON parity and canonical Signal re-exports
        run: cargo test --no-default-features --test interface_pin
"""
    ci_path.write_text(ci, encoding="utf-8")


if __name__ == "__main__":
    main()
