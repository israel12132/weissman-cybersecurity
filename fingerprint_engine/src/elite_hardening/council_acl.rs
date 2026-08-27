//! Supreme Council memory write ACL (control 89).
//!
//! Vector-table inserts are app-role only at the SQL GRANT layer; this helper
//! additionally rejects untrusted *logical* sources so a prompt, a raw RAG
//! chunk, or an unconfirmed model dump cannot poison `supreme_council_memory`.

pub const TRUSTED_SOURCES: &[&str] = &[
    "oast_success",
    "analyst_confirmed",
    "winning_path",
    "pentest_memory_win",
];

pub fn council_write_allowed(source: &str) -> bool {
    let s = source.trim();
    if s.is_empty() {
        return false;
    }
    TRUSTED_SOURCES.iter().any(|t| *t == s)
}

/// `oast_success` requires a real OAST token (≥8 chars). Probe-confirmed wins
/// without a token persist as `winning_path` — still a trusted source, but the
/// DB trigger will reject a forged `oast_success` with an empty token.
pub const OAST_TOKEN_MIN_LEN: usize = 8;

pub fn council_persist_source(oast_token: &str) -> &'static str {
    if oast_token.trim().len() >= OAST_TOKEN_MIN_LEN {
        "oast_success"
    } else {
        "winning_path"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oast_success_is_trusted() {
        assert!(council_write_allowed("oast_success"));
        assert!(council_write_allowed("winning_path"));
    }

    #[test]
    fn prompt_and_rag_are_rejected() {
        assert!(!council_write_allowed("user_prompt"));
        assert!(!council_write_allowed("untrusted_rag"));
        assert!(!council_write_allowed(""));
        assert!(!council_write_allowed("llm_raw"));
    }

    #[test]
    fn oast_success_requires_token() {
        assert_eq!(council_persist_source(""), "winning_path");
        assert_eq!(council_persist_source("short"), "winning_path");
        assert_eq!(council_persist_source("oob-token-ok"), "oast_success");
    }
}
