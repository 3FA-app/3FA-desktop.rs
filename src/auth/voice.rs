//! Voice factor — the user speaks a 4-digit PIN; we verify **both** halves:
//!
//!   1. *What was said* — speech-to-text must transcribe the expected digits
//!      (knowledge / liveness). In **challenge mode** the digits are a fresh
//!      random sequence each time, which defeats replay of a recorded clip.
//!   2. *Who said it* — a speaker-embedding model produces a voiceprint whose
//!      cosine similarity to the enrolled voiceprint must exceed a threshold
//!      (biometric).
//!
//! Both halves run **on-device**. Raw audio is never persisted or uploaded.
//! Voice is a *secondary* factor only (see plan): the policy engine never lets
//! it be the sole gate when the user has configured 2FA/3FA.
//!
//! The heavy ML (whisper-rs for STT, ONNX speaker model via `ort`) lives behind
//! the [`VoiceBackend`] trait so the core builds and tests without those deps; a
//! `NullBackend` reports the factor unavailable until a real backend is plugged
//! in (feature `voice-ml`, added in a follow-up).

use super::passcode::ct_eq;
use super::{AuthFactor, Challenge, FactorError, FactorKind, FactorProof};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::OsRng;

/// Cosine-similarity threshold above which two voiceprints are deemed the same
/// speaker. Conservative default; tuned during enrollment QA.
pub const SPEAKER_MATCH_THRESHOLD: f32 = 0.75;

/// Result of running the on-device models over a captured utterance.
#[derive(Debug, Clone)]
pub struct VoiceObservation {
    /// Digits the STT model heard, as ASCII bytes (e.g. b"4821").
    pub spoken_digits: Vec<u8>,
    /// Speaker embedding for this utterance.
    pub embedding: Vec<f32>,
}

/// Pluggable inference backend. Real implementation wraps whisper-rs + an ONNX
/// speaker model; the default [`NullBackend`] makes the factor inert.
pub trait VoiceBackend {
    fn is_ready(&self) -> bool;
    /// Capture from the mic and run both models. `expected_len` lets the STT
    /// step know how many digits to expect.
    fn observe(&mut self, expected_len: usize) -> Result<VoiceObservation, FactorError>;
}

/// No-op backend: voice factor reports unavailable. Used until `voice-ml` lands.
#[derive(Default)]
pub struct NullBackend;

impl VoiceBackend for NullBackend {
    fn is_ready(&self) -> bool {
        false
    }
    fn observe(&mut self, _expected_len: usize) -> Result<VoiceObservation, FactorError> {
        Err(FactorError::Unavailable)
    }
}

/// Enrollment data persisted in the (encrypted) vault payload.
#[derive(Debug, Clone)]
pub struct VoiceEnrollment {
    /// Argon2id PHC hash of the user's fixed 4-digit PIN (fixed-PIN mode only).
    pub pin_hash: String,
    /// Enrolled speaker voiceprint.
    pub voiceprint: Vec<f32>,
}

/// Whether to read a fixed PIN (convenient, replay-weak) or a fresh random
/// challenge each time (replay-resistant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoiceMode {
    FixedPin,
    Challenge,
}

/// Hash a 4-digit voice PIN for storage.
pub fn hash_pin(pin: &[u8]) -> Result<String, FactorError> {
    let salt = SaltString::generate(&mut OsRng);
    pin_hasher()
        .hash_password(pin, &salt)
        .map(|h| h.to_string())
        .map_err(|e| FactorError::Backend(e.to_string()))
}

fn pin_hasher() -> Argon2<'static> {
    let params = Params::new(64 * 1024, 2, 1, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Cosine similarity between two equal-length embeddings. Returns 0.0 on length
/// mismatch or zero vectors (fails closed).
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut na = 0.0f32;
    let mut nb = 0.0f32;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    if na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    dot / (na.sqrt() * nb.sqrt())
}

/// The voice factor.
pub struct VoiceFactor<B: VoiceBackend> {
    backend: B,
    enrollment: Option<VoiceEnrollment>,
    mode: VoiceMode,
    /// In challenge mode, the digits the UI just asked the user to read.
    expected_challenge: Option<Vec<u8>>,
}

impl<B: VoiceBackend> VoiceFactor<B> {
    pub fn new(backend: B, enrollment: Option<VoiceEnrollment>, mode: VoiceMode) -> Self {
        Self {
            backend,
            enrollment,
            mode,
            expected_challenge: None,
        }
    }

    /// Set the random digits the user is being prompted to read (challenge mode).
    pub fn set_challenge_digits(&mut self, digits: Vec<u8>) {
        self.expected_challenge = Some(digits);
    }

    fn check_digits(&self, obs: &VoiceObservation) -> Result<(), FactorError> {
        match self.mode {
            VoiceMode::Challenge => {
                let expected = self
                    .expected_challenge
                    .as_deref()
                    .ok_or(FactorError::Rejected)?;
                if ct_eq(&obs.spoken_digits, expected) {
                    Ok(())
                } else {
                    Err(FactorError::Rejected)
                }
            }
            VoiceMode::FixedPin => {
                let enr = self.enrollment.as_ref().ok_or(FactorError::Unavailable)?;
                let parsed = PasswordHash::new(&enr.pin_hash)
                    .map_err(|e| FactorError::Backend(e.to_string()))?;
                pin_hasher()
                    .verify_password(&obs.spoken_digits, &parsed)
                    .map_err(|_| FactorError::Rejected)
            }
        }
    }

    fn check_speaker(&self, obs: &VoiceObservation) -> Result<(), FactorError> {
        let enr = self.enrollment.as_ref().ok_or(FactorError::Unavailable)?;
        let sim = cosine_similarity(&obs.embedding, &enr.voiceprint);
        if sim >= SPEAKER_MATCH_THRESHOLD {
            Ok(())
        } else {
            Err(FactorError::Rejected)
        }
    }
}

impl<B: VoiceBackend> AuthFactor for VoiceFactor<B> {
    fn kind(&self) -> FactorKind {
        FactorKind::Voice
    }

    fn is_available(&self) -> bool {
        self.enrollment.is_some() && self.backend.is_ready()
    }

    fn verify(&mut self, _challenge: &Challenge) -> Result<FactorProof, FactorError> {
        let expected_len = 4;
        let obs = self.backend.observe(expected_len)?;
        // Both halves must pass: spoken digits AND speaker identity.
        self.check_digits(&obs)?;
        self.check_speaker(&obs)?;
        Ok(FactorProof {
            kind: FactorKind::Voice,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scripted backend for tests: returns a fixed observation.
    struct ScriptedBackend(VoiceObservation);
    impl VoiceBackend for ScriptedBackend {
        fn is_ready(&self) -> bool {
            true
        }
        fn observe(&mut self, _len: usize) -> Result<VoiceObservation, FactorError> {
            Ok(self.0.clone())
        }
    }

    fn enrolled(pin: &[u8], print: Vec<f32>) -> VoiceEnrollment {
        VoiceEnrollment {
            pin_hash: hash_pin(pin).unwrap(),
            voiceprint: print,
        }
    }

    #[test]
    fn cosine_basics() {
        assert!((cosine_similarity(&[1.0, 0.0], &[1.0, 0.0]) - 1.0).abs() < 1e-6);
        assert!(cosine_similarity(&[1.0, 0.0], &[0.0, 1.0]).abs() < 1e-6);
        assert_eq!(cosine_similarity(&[1.0], &[1.0, 2.0]), 0.0); // length mismatch
    }

    #[test]
    fn fixed_pin_correct_speaker_and_digits_passes() {
        let print = vec![0.2, 0.4, 0.4, 0.8];
        let enr = enrolled(b"4821", print.clone());
        let backend = ScriptedBackend(VoiceObservation {
            spoken_digits: b"4821".to_vec(),
            embedding: print,
        });
        let mut f = VoiceFactor::new(backend, Some(enr), VoiceMode::FixedPin);
        assert!(f.verify(&Challenge::default()).is_ok());
    }

    #[test]
    fn wrong_digits_rejected_even_with_right_voice() {
        let print = vec![0.2, 0.4, 0.4, 0.8];
        let enr = enrolled(b"4821", print.clone());
        let backend = ScriptedBackend(VoiceObservation {
            spoken_digits: b"0000".to_vec(),
            embedding: print,
        });
        let mut f = VoiceFactor::new(backend, Some(enr), VoiceMode::FixedPin);
        assert!(matches!(
            f.verify(&Challenge::default()),
            Err(FactorError::Rejected)
        ));
    }

    #[test]
    fn wrong_speaker_rejected_even_with_right_digits() {
        let enrolled_print = vec![1.0, 0.0, 0.0, 0.0];
        let impostor_print = vec![0.0, 1.0, 0.0, 0.0];
        let enr = enrolled(b"4821", enrolled_print);
        let backend = ScriptedBackend(VoiceObservation {
            spoken_digits: b"4821".to_vec(),
            embedding: impostor_print,
        });
        let mut f = VoiceFactor::new(backend, Some(enr), VoiceMode::FixedPin);
        assert!(matches!(
            f.verify(&Challenge::default()),
            Err(FactorError::Rejected)
        ));
    }

    #[test]
    fn challenge_mode_rejects_replayed_wrong_sequence() {
        let print = vec![0.2, 0.4, 0.4, 0.8];
        let enr = enrolled(b"0000", print.clone());
        let backend = ScriptedBackend(VoiceObservation {
            spoken_digits: b"1357".to_vec(), // replay of an old challenge
            embedding: print,
        });
        let mut f = VoiceFactor::new(backend, Some(enr), VoiceMode::Challenge);
        f.set_challenge_digits(b"4862".to_vec()); // today's challenge
        assert!(matches!(
            f.verify(&Challenge::default()),
            Err(FactorError::Rejected)
        ));
    }

    #[test]
    fn null_backend_is_unavailable() {
        let f = VoiceFactor::new(NullBackend, None, VoiceMode::FixedPin);
        assert!(!f.is_available());
    }
}
