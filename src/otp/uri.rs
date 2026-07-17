//! Parsing of `otpauth://` URIs (the de-facto standard emitted by QR codes from
//! Google, GitHub, AWS, etc.) into a structured [`OtpAccount`].
//!
//! Spec reference: <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>

use super::Algorithm;
use url::Url;
use zeroize::ZeroizeOnDrop;

/// One enrolled OTP account. The `secret` is the raw decoded key bytes and is
/// zeroized on drop so it never lingers in freed memory.
#[derive(Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct OtpAccount {
    #[zeroize(skip)]
    pub kind: OtpKind,
    #[zeroize(skip)]
    pub issuer: String,
    #[zeroize(skip)]
    pub label: String,
    pub secret: Vec<u8>,
    #[zeroize(skip)]
    pub algorithm: Algorithm,
    #[zeroize(skip)]
    pub digits: u32,
    /// TOTP step in seconds, or HOTP initial counter, depending on `kind`.
    #[zeroize(skip)]
    pub period: u64,
    #[zeroize(skip)]
    pub counter: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpKind {
    Totp,
    Hotp,
}

#[derive(Debug, thiserror::Error)]
pub enum UriError {
    #[error("not an otpauth:// URI")]
    WrongScheme,
    #[error("unsupported otp type (expected totp or hotp)")]
    UnsupportedType,
    #[error("missing or invalid secret")]
    BadSecret,
    #[error("missing required HOTP counter")]
    MissingCounter,
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("malformed URI: {0}")]
    Malformed(String),
}

impl OtpAccount {
    /// Parse an `otpauth://TYPE/LABEL?secret=...&issuer=...` URI.
    pub fn from_uri(uri: &str) -> Result<Self, UriError> {
        let url = Url::parse(uri).map_err(|e| UriError::Malformed(e.to_string()))?;
        if url.scheme() != "otpauth" {
            return Err(UriError::WrongScheme);
        }

        let kind = match url.host_str() {
            Some("totp") => OtpKind::Totp,
            Some("hotp") => OtpKind::Hotp,
            _ => return Err(UriError::UnsupportedType),
        };

        // Label is the path, percent-decoded, with an optional "Issuer:Account".
        let raw_label = url.path().trim_start_matches('/');
        let label = percent_decode(raw_label);

        let mut secret_b32 = None;
        let mut issuer_param = None;
        let mut algorithm = Algorithm::Sha1;
        let mut digits = 6u32;
        let mut period = 30u64;
        let mut counter = 0u64;

        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "secret" => secret_b32 = Some(v.into_owned()),
                "issuer" => issuer_param = Some(v.into_owned()),
                // Reject unrecognized parameter values rather than silently
                // defaulting: a malicious QR/URI must not be able to downgrade the
                // hash to SHA-1 or coerce a digit count that makes this client
                // generate codes the real service won't accept (a silent lockout).
                "algorithm" => {
                    algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        other => return Err(UriError::UnsupportedAlgorithm(other.to_string())),
                    }
                }
                "digits" => {
                    digits = v
                        .parse::<u32>()
                        .ok()
                        .filter(|d| (6..=8).contains(d))
                        .ok_or_else(|| UriError::Malformed(format!("invalid digits: {v}")))?;
                }
                "period" => {
                    period = v
                        .parse::<u64>()
                        .ok()
                        .filter(|p| *p > 0)
                        .ok_or_else(|| UriError::Malformed(format!("invalid period: {v}")))?;
                }
                "counter" => {
                    counter = v
                        .parse::<u64>()
                        .map_err(|_| UriError::Malformed(format!("invalid counter: {v}")))?;
                }
                _ => {}
            }
        }

        let secret_b32 = secret_b32.ok_or(UriError::BadSecret)?;
        let secret = base32::decode(
            base32::Alphabet::Rfc4648 { padding: false },
            secret_b32.trim_end_matches('='),
        )
        .ok_or(UriError::BadSecret)?;
        if secret.is_empty() {
            return Err(UriError::BadSecret);
        }

        if kind == OtpKind::Hotp && !url.query_pairs().any(|(k, _)| k == "counter") {
            return Err(UriError::MissingCounter);
        }

        // Prefer the explicit issuer parameter; fall back to the "Issuer:" prefix
        // in the label.
        let issuer = issuer_param.unwrap_or_else(|| {
            label
                .split_once(':')
                .map(|(i, _)| i.trim().to_string())
                .unwrap_or_default()
        });

        Ok(OtpAccount {
            kind,
            issuer,
            label,
            secret,
            algorithm,
            digits,
            period,
            counter,
        })
    }
}

/// Minimal percent-decoding for the label path segment.
fn percent_decode(s: &str) -> String {
    // `url` already decodes query values; the path we decode ourselves to keep
    // the human label readable (e.g. "ACME%20Co" -> "ACME Co").
    percent_encoding_decode(s)
}

fn percent_encoding_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_totp_uri() {
        // "JBSWY3DPEHPK3PXP" base32-decodes to "Hello!\xde\xad\xbe\xef".
        let uri = "otpauth://totp/ACME%20Co:alice@acme.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30";
        let acct = OtpAccount::from_uri(uri).unwrap();
        assert_eq!(acct.kind, OtpKind::Totp);
        assert_eq!(acct.issuer, "ACME Co");
        assert_eq!(acct.label, "ACME Co:alice@acme.com");
        assert_eq!(acct.algorithm, Algorithm::Sha1);
        assert_eq!(acct.digits, 6);
        assert_eq!(acct.period, 30);
        assert!(!acct.secret.is_empty());
    }

    #[test]
    fn hotp_requires_counter() {
        let uri = "otpauth://hotp/acct?secret=JBSWY3DPEHPK3PXP";
        assert!(matches!(
            OtpAccount::from_uri(uri),
            Err(UriError::MissingCounter)
        ));
        let ok = "otpauth://hotp/acct?secret=JBSWY3DPEHPK3PXP&counter=5";
        assert_eq!(OtpAccount::from_uri(ok).unwrap().counter, 5);
    }

    #[test]
    fn rejects_wrong_scheme_and_bad_secret() {
        assert!(matches!(
            OtpAccount::from_uri("https://totp/x?secret=AAAA"),
            Err(UriError::WrongScheme)
        ));
        assert!(matches!(
            OtpAccount::from_uri("otpauth://totp/x?secret=!!!notbase32!!!"),
            Err(UriError::BadSecret)
        ));
    }

    #[test]
    fn infers_issuer_from_label_prefix() {
        let uri = "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP";
        let acct = OtpAccount::from_uri(uri).unwrap();
        assert_eq!(acct.issuer, "GitHub");
    }

    #[test]
    fn rejects_unknown_algorithm_instead_of_downgrading() {
        let uri = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA999";
        assert!(matches!(
            OtpAccount::from_uri(uri),
            Err(UriError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn rejects_out_of_range_digits_and_bad_period() {
        assert!(matches!(
            OtpAccount::from_uri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4"),
            Err(UriError::Malformed(_))
        ));
        assert!(matches!(
            OtpAccount::from_uri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0"),
            Err(UriError::Malformed(_))
        ));
    }

    /// Base32 decode edges: padded secrets (QR generators differ on emitting
    /// `=`) must decode to the same key bytes as the canonical unpadded form.
    /// "JBSWY3DP" -> "Hello" is a fixed RFC 4648 decode.
    #[test]
    fn base32_padding_is_tolerated() {
        let unpadded = OtpAccount::from_uri("otpauth://totp/x?secret=JBSWY3DP").unwrap();
        assert_eq!(unpadded.secret, b"Hello");
        let padded = OtpAccount::from_uri("otpauth://totp/x?secret=JBSWY3DP%3D%3D%3D%3D").unwrap();
        assert_eq!(padded.secret, unpadded.secret);
    }

    #[test]
    fn missing_or_empty_secret_is_rejected() {
        assert!(matches!(
            OtpAccount::from_uri("otpauth://totp/x?issuer=NoSecret"),
            Err(UriError::BadSecret)
        ));
        assert!(matches!(
            OtpAccount::from_uri("otpauth://totp/x?secret="),
            Err(UriError::BadSecret)
        ));
        // Padding-only decodes to zero bytes and must also be rejected.
        assert!(matches!(
            OtpAccount::from_uri("otpauth://totp/x?secret=%3D%3D%3D"),
            Err(UriError::BadSecret)
        ));
    }

    #[test]
    fn unknown_query_params_are_ignored() {
        let acct = OtpAccount::from_uri(
            "otpauth://totp/x?secret=JBSWY3DP&image=https%3A%2F%2Fx.example&foo=bar",
        )
        .unwrap();
        assert_eq!(acct.secret, b"Hello");
        assert_eq!(acct.digits, 6);
        assert_eq!(acct.period, 30);
    }
}
