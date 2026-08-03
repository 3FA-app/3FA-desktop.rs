use threefa_core::otp::{
    uri::{OtpAccount, OtpKind, UriError},
    Algorithm,
};

const SECRET: &str = "JBSWY3DPEHPK3PXP";

#[test]
fn debug_output_never_contains_raw_seed_material() {
    let account = OtpAccount::from_uri(&format!(
        "otpauth://totp/3FA:alex@example.com?secret={SECRET}&issuer=3FA"
    ))
    .expect("valid account");

    let debug = format!("{account:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(SECRET));
    assert!(!debug.contains("Hello"));
}

#[test]
fn explicit_issuer_wins_over_the_label_prefix() {
    let account = OtpAccount::from_uri(&format!(
        "otpauth://totp/Legacy:alex@example.com?secret={SECRET}&issuer=Current"
    ))
    .expect("valid account");

    assert_eq!(account.issuer, "Current");
    assert_eq!(account.label, "Legacy:alex@example.com");
}

#[test]
fn algorithm_names_are_case_insensitive_but_unknown_values_fail_closed() {
    for (value, expected) in [
        ("sha1", Algorithm::Sha1),
        ("Sha256", Algorithm::Sha256),
        ("sHa512", Algorithm::Sha512),
    ] {
        let account = OtpAccount::from_uri(&format!(
            "otpauth://totp/account?secret={SECRET}&algorithm={value}"
        ))
        .expect("supported algorithm");
        assert_eq!(account.algorithm, expected);
    }

    assert!(matches!(
        OtpAccount::from_uri(&format!(
            "otpauth://totp/account?secret={SECRET}&algorithm=md5"
        )),
        Err(UriError::UnsupportedAlgorithm(_))
    ));
}

#[test]
fn hotp_preserves_large_counters_and_totp_preserves_custom_periods() {
    let hotp = OtpAccount::from_uri(&format!(
        "otpauth://hotp/account?secret={SECRET}&counter={}",
        u64::MAX
    ))
    .expect("valid HOTP account");
    assert_eq!(hotp.kind, OtpKind::Hotp);
    assert_eq!(hotp.counter, u64::MAX);

    let totp = OtpAccount::from_uri(&format!(
        "otpauth://totp/account?secret={SECRET}&period=45&digits=8"
    ))
    .expect("valid TOTP account");
    assert_eq!(totp.kind, OtpKind::Totp);
    assert_eq!(totp.period, 45);
    assert_eq!(totp.digits, 8);
}

#[test]
fn unsupported_otp_hosts_do_not_fall_back_to_totp() {
    for kind in ["steam", "ocra", "totp-extra"] {
        assert!(matches!(
            OtpAccount::from_uri(&format!("otpauth://{kind}/account?secret={SECRET}")),
            Err(UriError::UnsupportedType)
        ));
    }
}
