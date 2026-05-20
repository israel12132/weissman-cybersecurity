//! TOTP MFA (Google Authenticator / Authy compatible).

use totp_rs::{Algorithm, Secret, TOTP};

const ISSUER: &str = "Weissman-Cybersecurity";

pub fn generate_secret() -> String {
    Secret::generate_secret().to_string()
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
