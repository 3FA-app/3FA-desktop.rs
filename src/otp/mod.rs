//! Standard OTP generation: HOTP (RFC 4226) and TOTP (RFC 6238).
//!
//! Hand-rolled over the RustCrypto `hmac`/`sha1`/`sha2` primitives rather than a
//! third-party OTP crate, so the entire security-critical code path is auditable
//! in-tree. Verified against the published RFC test vectors (see `tests` below).

pub mod uri;

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroize;

/// Hash algorithm backing the HMAC. Matches the `algorithm` field of an
/// `otpauth://` URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OtpError {
    #[error("digit count must be between 6 and 8")]
    InvalidDigits,
    #[error("secret key is empty")]
    EmptySecret,
}

/// Compute an HOTP value (RFC 4226) for the given counter.
///
/// `secret` is the raw (already base32-decoded) key bytes. `digits` is 6–8.
pub fn hotp(
    algorithm: Algorithm,
    secret: &[u8],
    counter: u64,
    digits: u32,
) -> Result<u32, OtpError> {
    if secret.is_empty() {
        return Err(OtpError::EmptySecret);
    }
    if !(6..=8).contains(&digits) {
        return Err(OtpError::InvalidDigits);
    }

    let msg = counter.to_be_bytes();
    let mut hs = hmac_digest(algorithm, secret, &msg);

    // Dynamic truncation (RFC 4226 §5.3).
    let offset = (hs[hs.len() - 1] & 0x0f) as usize;
    let bin_code = ((u32::from(hs[offset]) & 0x7f) << 24)
        | ((u32::from(hs[offset + 1]) & 0xff) << 16)
        | ((u32::from(hs[offset + 2]) & 0xff) << 8)
        | (u32::from(hs[offset + 3]) & 0xff);
    hs.zeroize();

    let modulo = 10u32.pow(digits);
    Ok(bin_code % modulo)
}

/// Compute a TOTP value (RFC 6238) for a given unix timestamp.
///
/// `period` is the time step in seconds (default 30). `t0` is the epoch offset
/// (almost always 0).
pub fn totp_at(
    algorithm: Algorithm,
    secret: &[u8],
    unix_time: u64,
    period: u64,
    t0: u64,
    digits: u32,
) -> Result<u32, OtpError> {
    let counter = (unix_time.saturating_sub(t0)) / period;
    hotp(algorithm, secret, counter, digits)
}

/// Seconds remaining in the current TOTP window — drives the countdown ring.
pub fn seconds_remaining(unix_time: u64, period: u64) -> u64 {
    period - (unix_time % period)
}

/// Format an OTP value as a zero-padded string of `digits` length.
pub fn format_code(code: u32, digits: u32) -> String {
    format!("{:0width$}", code, width = digits as usize)
}

fn hmac_digest(algorithm: Algorithm, key: &[u8], msg: &[u8]) -> Vec<u8> {
    match algorithm {
        Algorithm::Sha1 => {
            let mut mac = <Hmac<Sha1>>::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(msg);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha256 => {
            let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(msg);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha512 => {
            let mut mac = <Hmac<Sha512>>::new_from_slice(key).expect("HMAC accepts any key length");
            mac.update(msg);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4226 Appendix D — HOTP test vectors. Secret is the ASCII string
    /// "12345678901234567890", counters 0..=9, 6 digits, SHA1.
    #[test]
    fn rfc4226_hotp_vectors() {
        let secret = b"12345678901234567890";
        let expected = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (counter, want) in expected.iter().enumerate() {
            let got = hotp(Algorithm::Sha1, secret, counter as u64, 6).unwrap();
            assert_eq!(got, *want, "HOTP counter {counter}");
        }
    }

    /// RFC 6238 Appendix B — TOTP test vectors, 8 digits.
    ///
    /// The RFC uses a distinct ASCII seed per algorithm (the 20/32/64-byte
    /// repeating "1234567890" pattern keyed to the hash's block size).
    #[test]
    fn rfc6238_totp_vectors() {
        let seed_sha1 = b"12345678901234567890".to_vec();
        let seed_sha256 = b"12345678901234567890123456789012".to_vec();
        let seed_sha512 =
            b"1234567890123456789012345678901234567890123456789012345678901234".to_vec();

        // (unix_time, sha1, sha256, sha512)
        let cases: [(u64, u32, u32, u32); 6] = [
            (59, 94287082, 46119246, 90693936),
            (1111111109, 7081804, 68084774, 25091201),
            (1111111111, 14050471, 67062674, 99943326),
            (1234567890, 89005924, 91819424, 93441116),
            (2000000000, 69279037, 90698825, 38618901),
            (20000000000, 65353130, 77737706, 47863826),
        ];

        for (t, s1, s256, s512) in cases {
            assert_eq!(
                totp_at(Algorithm::Sha1, &seed_sha1, t, 30, 0, 8).unwrap(),
                s1,
                "SHA1 @ {t}"
            );
            assert_eq!(
                totp_at(Algorithm::Sha256, &seed_sha256, t, 30, 0, 8).unwrap(),
                s256,
                "SHA256 @ {t}"
            );
            assert_eq!(
                totp_at(Algorithm::Sha512, &seed_sha512, t, 30, 0, 8).unwrap(),
                s512,
                "SHA512 @ {t}"
            );
        }
    }

    #[test]
    fn rejects_bad_digits_and_empty_secret() {
        assert!(matches!(
            hotp(Algorithm::Sha1, b"x", 0, 5),
            Err(OtpError::InvalidDigits)
        ));
        assert!(matches!(
            hotp(Algorithm::Sha1, b"", 0, 6),
            Err(OtpError::EmptySecret)
        ));
    }

    #[test]
    fn format_pads_to_width() {
        assert_eq!(format_code(1234, 6), "001234");
        assert_eq!(format_code(755224, 6), "755224");
    }

    #[test]
    fn countdown_wraps_within_period() {
        assert_eq!(seconds_remaining(0, 30), 30);
        assert_eq!(seconds_remaining(29, 30), 1);
        assert_eq!(seconds_remaining(30, 30), 30);
    }

    /// Digit truncation is a suffix relationship: the 6-digit code is the low
    /// six digits of the 8-digit code for the same HMAC output (RFC 4226 §5.3
    /// takes `bin_code mod 10^digits`). Pinned against the RFC 6238 vector at
    /// T=59 (8-digit SHA1 = 94287082).
    #[test]
    fn digit_count_truncates_the_same_bin_code() {
        let secret = b"12345678901234567890";
        assert_eq!(
            totp_at(Algorithm::Sha1, secret, 59, 30, 0, 8).unwrap(),
            94287082
        );
        assert_eq!(
            totp_at(Algorithm::Sha1, secret, 59, 30, 0, 7).unwrap(),
            4287082
        );
        assert_eq!(
            totp_at(Algorithm::Sha1, secret, 59, 30, 0, 6).unwrap(),
            287082
        );
    }

    /// All timestamps inside one period share a counter (identical code), and a
    /// nonzero `t0` shifts the window: T=89 with t0=30 is the same counter as
    /// T=59 with t0=0.
    #[test]
    fn totp_window_and_t0_offset_semantics() {
        let secret = b"12345678901234567890";
        let at_59 = totp_at(Algorithm::Sha1, secret, 59, 30, 0, 8).unwrap();
        assert_eq!(
            totp_at(Algorithm::Sha1, secret, 30, 30, 0, 8).unwrap(),
            at_59
        );
        assert_eq!(
            totp_at(Algorithm::Sha1, secret, 89, 30, 30, 8).unwrap(),
            at_59
        );
        // A time before t0 saturates to counter 0 rather than underflowing.
        let at_0 = totp_at(Algorithm::Sha1, secret, 0, 30, 0, 8).unwrap();
        assert_eq!(
            totp_at(Algorithm::Sha1, secret, 5, 30, 100, 8).unwrap(),
            at_0
        );
    }

    #[test]
    fn eight_digit_codes_format_full_width() {
        assert_eq!(format_code(94287082, 8), "94287082");
        assert_eq!(format_code(7081804, 8), "07081804");
        assert_eq!(format_code(0, 8), "00000000");
    }
}
