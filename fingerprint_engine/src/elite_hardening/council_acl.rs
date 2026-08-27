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
}
