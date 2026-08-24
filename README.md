# 3FA — Desktop Authenticator (frontend)

The native desktop app: generates standard TOTP/HOTP codes and keeps the seeds
in an encrypted vault behind a 6-digit passcode and an idle auto-lock. Written in
Rust with a pure-native
[Slint](https://slint.dev) UI — no Electron, no webview.

> One of three repos:
> - **`3fa-desktop.rs`** — this app (Rust + Slint)
> - **`3fa-backend.rs`** — zero-knowledge sync server (Rust + axum)
> - **`3fa-website`** — marketing/download site (Astro)
>
> Canonical sync, Signal, device, recovery, and future deep-link wire types are
> vendored from `3fa-interfaces` at an immutable commit with exact Git-blob
> provenance. Legacy desktop vault-sync adapters in `src/protocol.rs` are
> JSON-parity tested against it.

## Desktop toolkit and Flutter companion

The selected Rust desktop strategy is **Slint with no WebView**. This decision is
intentional for security, startup performance, memory use, deterministic native
behavior, and direct operating-system integration. See
[`docs/DESKTOP_TOOLKIT.md`](docs/DESKTOP_TOOLKIT.md) for the complete toolkit,
privilege-boundary, test, packaging, and HTTPS-first deep-link contract.

The current Flutter companion is
[`ORESoftware/3fa-client-ui.dart`](https://github.com/ORESoftware/3fa-client-ui.dart).
The private organization mirror is
[`3FA-app/3fa-flutter`](https://github.com/3FA-app/3fa-flutter), seeded from the
current companion history on 2026-08-24. Its existence does not establish
release authority or platform support; native builds, packaging, signing,
migration ownership, and reciprocal release links remain gated separately.

Rust and Flutter are both first-class product implementations. Every
desktop-facing feature must inspect both repositories and normally update both.
A one-sided change requires an explicit no-change rationale and recorded parity
gap. The pair is maintained to compare security, performance, OS integration,
accessibility, developer velocity, mobile reuse, release engineering, and
long-term maintenance with real product features.

Deep links use an HTTPS-first route family under a verified 3FA-owned host, with
`threefa://` as the desktop fallback scheme. URLs are untrusted input and must
never contain passwords, tokens, TOTP/HOTP seeds, recovery secrets, vault
contents, or encryption keys.

## Security model

- **Encrypted vault** — seeds encrypted with XChaCha20-Poly1305 under an
  Argon2id key from your passcode. Keys are zeroized on lock. (The extra
  Secure-Enclave / TPM wrap of the DEK is designed for but not implemented — it
  depends on the biometric backend below.)
- **Secure Bluetooth substrate** — ephemeral X25519, transcript-bound
  HKDF-SHA256, explicit six-digit SAS confirmation, and directional
  ChaCha20-Poly1305 frames are implemented and cross-tested with Dart. Platform
  Bluetooth adapters and permissions remain disabled until they satisfy the
  [adapter acceptance gate](docs/SECURE_BLUETOOTH_PROTOCOL.md).
- **Multi-factor policy engine** — counts *distinct* factor kinds (passcode,
  biometric, platform passkey, voice) against a per-vault [`FactorPolicy`].
  **Today only the passcode factor is actually wired into the app**: the vault
  unlocks on the 6-digit passcode, and the default policy requires one factor
  ([`src/vault/mod.rs`](src/vault/mod.rs)). The biometric and passkey backends
  are unimplemented seams that report "unavailable"
  ([`src/auth/biometric/`](src/auth), [`src/auth/passkey.rs`](src/auth/passkey.rs)),
  the voice factor ships only with its `NullBackend`, and the GUI hides all three
  factor buttons ([`src/ui.rs`](src/ui.rs)). Multi-factor *unlock* is therefore
  not a shipped capability — see the roadmap below.
- **Auto-lock** — 90 s idle (reset by user activity: keypad, adding an account,
  scanning, copying a code, navigating, syncing) with a 5-minute hard cap that
  fires regardless of activity. The vault screen counts down to whichever fires
  first. The "Keep open (+factor)" button asks the policy engine for a second,
  *distinct* factor to reset the idle timer — which, until a second factor
  backend exists (above), nothing can currently satisfy.
- **Voice factor (verification logic only)** — speak a 4-digit PIN; verifies
  *what* was said (on-device STT) and *who* said it (on-device voiceprint).
  Optional challenge mode defeats replay. Audio never leaves the device. The
  comparison logic and its tests exist; the STT/speaker backend does not, so the
  factor is inert in shipped builds.
- **Supabase login (zero-knowledge).** Sign in with Supabase using
  **email + password** (`grant_type=password`, plus `refresh_token` for silent
  renewal — no OAuth/social provider flow is implemented); the app never sends
  the password to *our* sync server — it presents the
  Supabase access JWT to `/v1/auth/supabase` and gets a per-device sync token in
  return. Login is fully separate from the vault's E2E key. See
  [`src/sync/supabase.rs`](src/sync/supabase.rs).
- **6-digit PIN (skip re-auth on token expiry).** The Supabase refresh token and
  the sync token are sealed at rest under a 6-digit PIN
  ([`src/pin_session.rs`](src/pin_session.rs), same Argon2id + XChaCha20-Poly1305
  as the vault). When the ~1 h access JWT expires you re-enter the PIN instead of
  the full email/password, and the app silently refreshes the session. PIN entry
  is throttled with escalating backoff and wipe-after-N (`PinGuard`), and weak
  PINs are rejected at setup — the PIN is a convenience credential scoped to a
  server-revocable refresh token, never to the vault seeds.
- **HTTPS-only sync.** The sync/identity client refuses any non-`https://`
  endpoint (loopback excepted in debug builds), so credentials and the JWT can't
  be sent in cleartext via a typo or tampered config.
- **Standards** — RFC 6238 (TOTP) / RFC 4226 (HOTP), verified against the RFC
  test vectors.

## Layout

```
src/otp/       RFC 6238 / 4226, otpauth:// parsing
src/crypto/    Argon2id KDF, XChaCha20-Poly1305 seal/open, key wrap
src/vault/     Encrypted at-rest vault file format
src/auth/      AuthFactor trait, passcode, biometric (per-OS), passkey, voice
src/session.rs Auto-lock state machine (90s / 5min)
src/pin_session.rs  PIN-sealed Supabase session + entry throttle (PinGuard)
src/sync/      Zero-knowledge sync client + Supabase auth client
src/protocol.rs  Legacy adapters + canonical Signal type re-exports
ui/            Slint UI markup
scripts/release/ Package binaries into per-OS zips + publish to S3
```

## Build, test, run

Release client configuration is stored as SOPS ciphertext and passed to Cargo
only after an exact public-value allowlist check. See
[`docs/env-secrets.md`](docs/env-secrets.md); use `nix develop`, `just verify`,
`just run dev`, or `just build-release prod`. Never compile backend secrets or
collector private keys into the desktop binary.

```bash
cargo test --workspace                 # or: cargo test
cargo test --no-default-features       # headless core only (CI, no display)
cargo run                              # launch the desktop app
```

### Supabase configuration

The Sign in with Supabase controls need the project's (non-secret) URL and anon
key. Either bake them into release builds at compile time:

```bash
THREEFA_SUPABASE_URL=https://<ref>.supabase.co \
THREEFA_SUPABASE_ANON_KEY=<anon-key> cargo build --release
```

…or set them per-install in `config.json` beside the vault (these override the
build-time defaults):

```json
{ "supabase_url": "https://<ref>.supabase.co", "supabase_anon_key": "<anon-key>" }
```

The Settings screen then offers **Sign in** (email/password → device enrollment,
optionally sealing a 6-digit PIN session), **Unlock with PIN** (refresh the
session without re-entering the password), and **Sync now**.

The legacy **Log in** / **Register** controls below them are **non-functional**:
they call `/v1/register` and `/v1/login`, which the backend has retired and no
longer mounts (it asserts they return 404 — see `3fa-backend.rs/src/app.rs`).
They are pending removal; use the Supabase sign-in above.

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
