//! TOTP MFA (Google Authenticator / Authy compatible).

use totp_rs::{Algorithm, Secret, TOTP};

const ISSUER: &str = "Weissman-Cybersecurity";

pub fn generate_secret() -> String {
    // Return a base32 (Encoded) secret: `otpauth_uri` / `verify_code` treat the
    // stored value as base32 (`Secret::Encoded`), but `Secret::generate_secret()`
    // yields a `Secret::Raw` whose `Display` is hex — base32-decoding that hex
    // fails (it contains 0/1/8/9), so the seed could never verify. `.to_encoded()`
    // makes the generated seed consistent with how it is later consumed.
    Secret::generate_secret().to_encoded().to_string()
}

pub fn otpauth_uri(secret_b32: &str, email: &str) -> Result<String, String> {
    let secret = Secret::Encoded(secret_b32.trim().to_string());
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().map_err(|e| e.to_string())?,
        Some(ISSUER.to_string()),
        email.trim().to_string(),
    )
    .map_err(|e| e.to_string())?;
    Ok(totp.get_url())
}

pub fn verify_code(secret_b32: &str, code: &str) -> bool {
    let secret_b32 = secret_b32.trim();
    if secret_b32.is_empty() {
        return false;
    }
    let code = code.trim();
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let secret = match Secret::Encoded(secret_b32.to_string()).to_bytes() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let totp = match TOTP::new(Algorithm::SHA1, 6, 1, 30, secret, None, "".to_string()) {
        Ok(t) => t,
        Err(_) => return false,
    };
    totp.check_current(code).unwrap_or(false)
}

/// Normalize user-provided base32 (strip whitespace, uppercase).
pub fn normalize_secret_input(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase()
}

// --- At-rest encryption of the TOTP seed -----------------------------------
// The TOTP seed is a long-lived credential and must not sit in `users.mfa_secret`
// as plaintext. We reuse the shared AES-256-GCM envelope from
// `soar::integrations_vault` (single audited crypto implementation) rather than
// rolling a second one here.

/// Encrypt a TOTP seed for storage at rest. Returns an opaque `wzi1:`-prefixed
/// envelope when key material is configured; without a key it returns the input
/// unchanged (dev fallback — production is fail-closed at the vault layer).
#[must_use]
pub fn encrypt_secret_at_rest(secret_b32: &str) -> String {
    crate::soar::integrations_vault::encrypt_secret(secret_b32)
}

/// Decrypt a stored TOTP seed. Legacy plaintext (no envelope prefix) is returned
/// unchanged, so accounts enrolled before at-rest encryption keep verifying
/// (lazy migration; the login path re-encrypts them on next successful verify).
#[must_use]
pub fn decrypt_secret_at_rest(stored: &str) -> String {
    crate::soar::integrations_vault::decrypt_secret(stored)
}

/// True if the stored seed is an encrypted envelope (not legacy plaintext).
#[must_use]
pub fn is_secret_encrypted(stored: &str) -> bool {
    crate::soar::integrations_vault::is_encrypted(stored)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_plaintext_seed_passes_through_decrypt() {
        // A bare base32 seed has no envelope prefix and must be returned as-is,
        // so pre-encryption rows still verify.
        let s = "JBSWY3DPEHPK3PXP";
        assert!(!is_secret_encrypted(s));
        assert_eq!(decrypt_secret_at_rest(s), s);
    }

    #[test]
    fn envelope_prefix_is_classified_as_encrypted() {
        assert!(is_secret_encrypted("wzi1:c29tZS1jaXBoZXJ0ZXh0"));
        assert!(!is_secret_encrypted(&generate_secret()));
    }

    #[test]
    fn generated_secret_is_base32_encoded() {
        // Regression: the generated seed must be base32 (Encoded), not hex (the
        // Raw `Display`), otherwise otpauth_uri()/verify_code() cannot decode it.
        let s = generate_secret();
        assert!(
            Secret::Encoded(s.clone()).to_bytes().is_ok(),
            "generated seed must be valid base32, got: {s}"
        );
    }

    #[test]
    fn verify_code_accepts_current_totp_via_decrypt_path() {
        // Generate a seed, decrypt-passthrough it (legacy plaintext), and confirm
        // the current code verifies — exercising the decrypt-then-verify seam the
        // login path uses.
        let secret = generate_secret();
        let recovered = decrypt_secret_at_rest(&secret);
        assert_eq!(recovered, secret);
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(recovered.clone())
                .to_bytes()
                .expect("generated seed must be base32-decodable"),
            None,
            String::new(),
        )
        .unwrap();
        let code = totp.generate_current().unwrap();
        assert!(verify_code(&recovered, &code));
    }

    #[test]
    fn normalize_strips_whitespace_and_uppercases() {
        assert_eq!(normalize_secret_input("jbsw y3dp"), "JBSWY3DP");
        assert_eq!(normalize_secret_input("  a b\tc\nd "), "ABCD");
        assert_eq!(normalize_secret_input(""), "");
    }

    #[test]
    fn verify_code_rejects_empty_secret() {
        assert!(!verify_code("", "123456"));
        assert!(!verify_code("   ", "123456")); // trims to empty
    }

    #[test]
    fn verify_code_rejects_bad_format() {
        // These fail the length/charset gate before any TOTP/time computation.
        assert!(!verify_code("JBSWY3DPEHPK3PXP", "12345")); // too short
        assert!(!verify_code("JBSWY3DPEHPK3PXP", "1234567")); // too long
        assert!(!verify_code("JBSWY3DPEHPK3PXP", "12ab56")); // non-digit
    }

    #[test]
    fn verify_code_rejects_invalid_base32_secret() {
        // '1' is not in the RFC4648 base32 alphabet; decode fails -> false.
        assert!(!verify_code("1", "123456"));
    }

    #[test]
    fn otpauth_uri_builds_for_valid_secret() {
        // totp-rs enforces a >= 16-byte (128-bit) secret; 32 base32 chars decode to 20 bytes.
        let uri = otpauth_uri("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "user@example.com").unwrap();
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("Weissman-Cybersecurity"));
        assert!(uri.contains("secret="));
    }

    #[test]
    fn otpauth_uri_errors_on_invalid_secret() {
        assert!(otpauth_uri("1", "user@example.com").is_err());
    }

    #[test]
    fn generate_secret_is_non_empty() {
        assert!(!generate_secret().is_empty());
    }
}
