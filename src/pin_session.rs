//! PIN-unlocked Supabase session.
//!
//! Supabase mints a short-lived access JWT (~1 h) plus a long-lived refresh
//! token. Rather than make the user re-enter their email/password every time the
//! JWT expires, the app keeps the **session secrets** — the Supabase refresh
//! token and the backend sync token — sealed at rest under a **6-digit PIN**.
//! When the JWT expires the user enters the PIN, the app decrypts the session,
//! and silently refreshes the Supabase access token. Full re-authentication is
//! only needed if the refresh token itself is revoked/expired.
//!
//! Sealing reuses the vault crypto: `key = Argon2id(pin, salt)` and
//! XChaCha20-Poly1305 with a per-seal nonce and a domain-separating AAD. A wrong
//! PIN fails closed (AEAD is all-or-nothing) — it never yields a partial or
//! plausible-looking session.
//!
//! **The PIN is low-entropy (10^6).** The seal alone is not a brute-force barrier
//! for an attacker who copies the file offline; it keeps the tokens out of
//! plaintext config and off the clipboard, and it is paired with [`PinGuard`]
//! attempt-throttling for the online/at-keyboard case. Treat the sealed session
//! as a convenience credential, not a root of trust: it is scoped to a refresh
//! token the server can revoke, never to vault seeds (those stay under the full
//! passcode-derived DEK).

use crate::crypto::{self, CryptoError, KEY_LEN};
use crate::protocol::KdfParams;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// AAD binding a sealed session to its purpose, so a session blob can never be
/// swapped in for a vault blob (or vice versa) even under the same PIN.
const SESSION_AAD: &[u8] = b"3fa-pin-session-v1";

/// Secrets that let the client keep syncing without a full re-login.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionSecrets {
    /// Supabase refresh token — exchanged for a fresh access JWT.
    pub refresh_token: String,
    /// Backend per-device sync token (bearer for `/v1/vault`, `/v1/devices`).
    pub sync_token: String,
}

// Never let session secrets leak through a derived `Debug`.
impl std::fmt::Debug for SessionSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSecrets")
            .field("refresh_token", &"<redacted>")
            .field("sync_token", &"<redacted>")
            .finish()
    }
}

/// A [`SessionSecrets`] sealed under a PIN. Safe to persist to disk (via
/// [`crate::write_private_atomic`]); reveals nothing without the PIN.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedSession {
    #[serde(with = "hex_bytes")]
    kdf_salt: Vec<u8>,
    kdf_params: KdfParams,
    #[serde(with = "hex_bytes")]
    nonce: Vec<u8>,
    #[serde(with = "hex_bytes")]
    ciphertext: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum PinError {
    #[error("PIN must be exactly 6 digits")]
    Format,
    #[error("PIN is too weak (avoid sequences and repeated digits)")]
    Weak,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("serialization error: {0}")]
    Serde(String),
}

/// Validate that a PIN is exactly 6 ASCII digits (same contract as the vault
/// passcode).
pub fn is_valid_format(pin: &[u8]) -> bool {
    pin.len() == 6 && pin.iter().all(|b| b.is_ascii_digit())
}

/// Reject the handful of PINs that dominate real-world guessing: all-same
/// (`000000`), simple ascending/descending runs (`123456`, `654321`), and the
/// most common leaked codes. Not a substitute for throttling — it only removes
/// the cheapest guesses so the 10^6 space isn't a 10-guess space.
pub fn is_weak(pin: &[u8]) -> bool {
    if pin.len() != 6 {
        return true;
    }
    // All identical digits.
    if pin.iter().all(|&b| b == pin[0]) {
        return true;
    }
    // Strictly ascending or descending run of consecutive digits.
    let ascending = pin.windows(2).all(|w| w[1] == w[0] + 1);
    let descending = pin.windows(2).all(|w| w[0] == w[1] + 1);
    if ascending || descending {
        return true;
    }
    // A small denylist of notoriously common codes.
    const COMMON: [&[u8]; 6] = [b"123456", b"111111", b"000000", b"121212", b"112233", b"696969"];
    COMMON.contains(&pin)
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Seal session secrets under a PIN. Enforces the 6-digit format and rejects the
/// weakest PINs — this is the enrollment path, so a weak PIN is refused here
/// rather than silently accepted.
pub fn seal(secrets: &SessionSecrets, pin: &[u8]) -> Result<SealedSession, PinError> {
    if !is_valid_format(pin) {
        return Err(PinError::Format);
    }
    if is_weak(pin) {
        return Err(PinError::Weak);
    }
    let kdf_params = KdfParams::default();
    let salt = crypto::random_salt();
    let key = crypto::derive_key(pin, &salt, kdf_params)?;

    let json = Zeroizing::new(
        serde_json::to_vec(secrets).map_err(|e| PinError::Serde(e.to_string()))?,
    );
    let sealed = crypto::seal(&key, &json, SESSION_AAD)?;

    Ok(SealedSession {
        kdf_salt: salt.to_vec(),
        kdf_params,
        nonce: sealed.nonce.to_vec(),
        ciphertext: sealed.ciphertext,
    })
}

/// Unseal session secrets with a PIN. A wrong PIN (or any tampering) returns
/// [`CryptoError::Decrypt`] — fail-closed, no partial output. Does not enforce
/// the weak-PIN policy: an already-sealed session may predate the policy, and the
/// AEAD is the real gate.
pub fn open(sealed: &SealedSession, pin: &[u8]) -> Result<SessionSecrets, PinError> {
    if !is_valid_format(pin) {
        return Err(PinError::Format);
    }
    // Clamp KDF cost before deriving, so a tampered file can't force a huge Argon2.
    if !sealed.kdf_params.is_sane()
        || sealed.nonce.len() != crypto::NONCE_LEN
        || !(crate::protocol::MIN_KDF_SALT_LEN..=crate::protocol::MAX_KDF_SALT_LEN)
            .contains(&sealed.kdf_salt.len())
    {
        return Err(PinError::Crypto(CryptoError::Decrypt));
    }
    let key = crypto::derive_key(pin, &sealed.kdf_salt, sealed.kdf_params)?;
    let nonce: [u8; crypto::NONCE_LEN] = sealed
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Decrypt)?;
    let bundle = crypto::Sealed {
        nonce,
        ciphertext: sealed.ciphertext.clone(),
    };
    let plain = crypto::open(&key, &bundle, SESSION_AAD)?;
    let _ = KEY_LEN; // key length asserted by crypto layer
    serde_json::from_slice(&plain).map_err(|e| PinError::Serde(e.to_string()))
}

/// Attempt throttle + lockout for PIN entry. A 6-digit PIN is only 10^6 codes, so
/// unthrottled entry is guessable; this enforces escalating backoff and an
/// optional wipe-after-N so a lost/stolen laptop can't be PIN-brute-forced at the
/// keyboard. Time is injected so it is unit-testable without sleeps (mirrors
/// [`crate::session::Session`]).
#[derive(Debug, Clone)]
pub struct PinGuard {
    failures: u32,
    max_failures: u32,
}

/// Outcome of consulting the guard before accepting a PIN attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinGate {
    /// Attempt allowed now.
    Allow,
    /// Locked out for at least this many seconds (escalating backoff).
    Backoff { seconds: u64 },
    /// Too many failures: the caller should wipe the sealed session and force a
    /// full re-login.
    Wipe,
}

impl PinGuard {
    /// `max_failures` is the count at which [`PinGate::Wipe`] is returned. A
    /// common choice is 10 (so the ~10^6 space is never meaningfully explored).
    pub fn new(max_failures: u32) -> Self {
        Self {
            failures: 0,
            max_failures,
        }
    }

    /// Restore a guard from a persisted failure count (kept alongside the sealed
    /// session so backoff survives a restart — otherwise a guesser just relaunches).
    pub fn from_failures(failures: u32, max_failures: u32) -> Self {
        Self {
            failures,
            max_failures,
        }
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Required backoff after `n` consecutive failures: 0 for the first few, then
    /// escalating. Caps at 5 minutes so it never wedges forever before the wipe
    /// threshold.
    fn backoff_secs(n: u32) -> u64 {
        match n {
            0..=2 => 0,
            3 => 5,
            4 => 30,
            5 => 60,
            _ => 300,
        }
    }

    /// Decide whether a PIN attempt may proceed now. `elapsed_since_last_failure`
    /// is how long since the most recent failure (caller-tracked, monotonic).
    pub fn gate(&self, elapsed_since_last_failure: std::time::Duration) -> PinGate {
        if self.failures >= self.max_failures {
            return PinGate::Wipe;
        }
        let need = Self::backoff_secs(self.failures);
        if need > 0 && elapsed_since_last_failure.as_secs() < need {
            return PinGate::Backoff {
                seconds: need - elapsed_since_last_failure.as_secs(),
            };
        }
        PinGate::Allow
    }

    /// Record a failed attempt (advances backoff / toward wipe).
    pub fn record_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
    }

    /// Record a success (clears the failure count).
    pub fn record_success(&mut self) {
        self.failures = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn secrets() -> SessionSecrets {
        SessionSecrets {
            refresh_token: "rt-abc123".into(),
            sync_token: "st-def456".into(),
        }
    }

    #[test]
    fn seal_open_round_trips() {
        let sealed = seal(&secrets(), b"314159").unwrap();
        let back = open(&sealed, b"314159").unwrap();
        assert_eq!(back.refresh_token, "rt-abc123");
        assert_eq!(back.sync_token, "st-def456");
    }

    #[test]
    fn wrong_pin_fails_closed() {
        let sealed = seal(&secrets(), b"314159").unwrap();
        let err = open(&sealed, b"271828").unwrap_err();
        assert!(matches!(err, PinError::Crypto(CryptoError::Decrypt)));
    }

    #[test]
    fn sealed_session_contains_no_plaintext_token() {
        let sealed = seal(&secrets(), b"314159").unwrap();
        let blob = serde_json::to_vec(&sealed).unwrap();
        for needle in [b"rt-abc123".as_slice(), b"st-def456".as_slice()] {
            assert!(
                !blob.windows(needle.len()).any(|w| w == needle),
                "token leaked into sealed session"
            );
        }
    }

    #[test]
    fn weak_pins_are_rejected_on_seal() {
        for weak in [b"000000", b"111111", b"123456", b"654321", b"121212"] {
            assert!(matches!(seal(&secrets(), weak), Err(PinError::Weak)), "{weak:?}");
        }
    }

    #[test]
    fn malformed_pin_rejected() {
        assert!(matches!(seal(&secrets(), b"12345"), Err(PinError::Format)));
        assert!(matches!(seal(&secrets(), b"12a456"), Err(PinError::Format)));
    }

    #[test]
    fn is_weak_allows_reasonable_pins() {
        assert!(!is_weak(b"314159"));
        assert!(!is_weak(b"271828"));
        assert!(!is_weak(b"837465"));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut sealed = seal(&secrets(), b"314159").unwrap();
        sealed.ciphertext[0] ^= 0xff;
        assert!(open(&sealed, b"314159").is_err());
    }

    #[test]
    fn guard_allows_then_backs_off_then_wipes() {
        let mut g = PinGuard::new(6);
        // First three attempts: no backoff.
        assert_eq!(g.gate(Duration::ZERO), PinGate::Allow);
        g.record_failure();
        g.record_failure();
        g.record_failure();
        // Now backoff kicks in and counts down with elapsed time.
        assert_eq!(g.gate(Duration::ZERO), PinGate::Backoff { seconds: 5 });
        assert_eq!(g.gate(Duration::from_secs(2)), PinGate::Backoff { seconds: 3 });
        assert_eq!(g.gate(Duration::from_secs(5)), PinGate::Allow);
        // Keep failing to the threshold -> wipe.
        g.record_failure(); // 4
        g.record_failure(); // 5
        g.record_failure(); // 6 == max
        assert_eq!(g.gate(Duration::from_secs(999)), PinGate::Wipe);
    }

    #[test]
    fn guard_success_resets() {
        let mut g = PinGuard::new(6);
        g.record_failure();
        g.record_failure();
        g.record_success();
        assert_eq!(g.failures(), 0);
        assert_eq!(g.gate(Duration::ZERO), PinGate::Allow);
    }
}
