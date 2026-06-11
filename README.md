# 3FA — Desktop Authenticator (frontend)

The native desktop app: generates standard TOTP/HOTP codes and keeps the seeds
sealed behind multi-factor security. Written in Rust with a pure-native
[Slint](https://slint.dev) UI — no Electron, no webview.

> One of three repos:
> - **`3fa-desktop.rs`** — this app (Rust + Slint)
> - **`3fa-backend.rs`** — zero-knowledge sync server (Rust + axum)
> - **`3fa-website`** — marketing/download site (Astro)
>
> The sync wire-protocol types live in [`src/protocol.rs`](src/protocol.rs), a
> copy kept byte-for-byte in sync with the backend's copy (guarded by
> `PROTOCOL_VERSION`).

## Security model

- **Encrypted vault** — seeds encrypted with XChaCha20-Poly1305 under an
  Argon2id key from your passcode, sealed to the Secure Enclave / TPM. Keys are
  zeroized on lock.
- **Multi-factor (2FA/3FA)** — a policy engine counting *distinct* factor kinds:
  passcode, biometric (Touch ID / Windows Hello / fprintd), platform passkey,
  and voice.
- **Auto-lock** — 90 s idle; extending up to 5 min requires a second, distinct
  factor.
- **Voice factor** — speak a 4-digit PIN; verifies *what* was said (on-device
  STT) and *who* said it (on-device voiceprint). Optional challenge mode defeats
  replay. Audio never leaves the device.
- **Standards** — RFC 6238 (TOTP) / RFC 4226 (HOTP), verified against the RFC
  test vectors.

## Layout

```
src/otp/       RFC 6238 / 4226, otpauth:// parsing
src/crypto/    Argon2id KDF, XChaCha20-Poly1305 seal/open, key wrap
src/vault/     Encrypted at-rest vault file format
src/auth/      AuthFactor trait, passcode, biometric (per-OS), passkey, voice
src/session.rs Auto-lock state machine (90s / 5min)
src/sync/      Zero-knowledge sync client
src/protocol.rs  Wire-protocol DTOs (duplicated with the backend)
ui/            Slint UI markup
scripts/release/ Package binaries into per-OS zips + publish to S3
```

## Build, test, run

```bash
cargo test --workspace                 # or: cargo test
cargo test --no-default-features       # headless core only (CI, no display)
cargo run                              # launch the desktop app
```

## Releasing

Per-OS binaries are built (one CI runner per OS), wrapped into uniform zips with
an installer, and uploaded to S3 where the website's download buttons point. See
[`scripts/release/README.md`](scripts/release/README.md).

## Roadmap (staged behind seams)

1. Native biometrics — wire `LAContext` / `UserConsentVerifier` / `fprintd` into
   `auth::biometric`.
2. Platform passkey assertions in `auth::passkey`.
3. Voice ML backend (`whisper-rs` + ONNX speaker model) behind a `voice-ml`
   feature implementing `auth::voice::VoiceBackend`.

## License

MIT OR Apache-2.0
