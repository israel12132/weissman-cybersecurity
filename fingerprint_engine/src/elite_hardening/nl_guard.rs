//! Ask Weissman compile-time guards: DDL kill, required LIMIT, fail-closed.

/// Spec §10: Ask Weissman allow-list (weissman_ro GRANT set, including OT/ICS tables).
pub const ASK_WEISSMAN_TABLE_COUNT: usize = 17;

const DDL_TOKENS: &[&str] = &[
    " DROP ",
    " TRUNCATE ",
    " ALTER ",
    " INSERT ",
    " UPDATE ",
    " DELETE ",
    " GRANT ",
    " REVOKE ",
    " COPY ",
    " EXECUTE ",
    " CREATE ",
    " COMMENT ",
    " VACUUM ",
    " CALL ",
    " DO ",
    ";",
    "--",
    "/*",
];

pub fn reject_unsafe_sql(sql: &str) -> Result<(), String> {
    let padded = format!(" {} ", sql);
    let upper = padded.to_ascii_uppercase();
    if !upper.trim_start().starts_with("SELECT ") && !upper.trim_start().starts_with("WITH ") {
        return Err("fail-closed: compiled plan is not SELECT/WITH".into());
    }
    for tok in DDL_TOKENS {
        if *tok == ";" {
            // trailing semicolon is unused (we never emit it); reject any semicolon.
            if sql.contains(';') {
                return Err("fail-closed: semicolon is not allowed in compiled SQL".into());
            }
            continue;
        }
        if upper.contains(tok) {
            return Err(format!(
                "fail-closed: forbidden token {} in compiled SQL",
                tok.trim()
            ));
        }
    }
    Ok(())
}

pub fn require_limit(limit: Option<i64>, max: i64) -> Result<i64, String> {
    let Some(n) = limit else {
        return Err("fail-closed: QueryPlan.limit is required".into());
    };
    if n < 1 {
        return Err("fail-closed: LIMIT must be ≥ 1".into());
    }
    Ok(n.min(max))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_ok() {
        assert!(
            reject_unsafe_sql("SELECT id FROM vulnerabilities WHERE tenant_id = $1 LIMIT 50")
                .is_ok()
        );
    }

    #[test]
    fn drop_rejected() {
        assert!(reject_unsafe_sql("SELECT 1; DROP TABLE vulnerabilities").is_err());
    }

    #[test]
    fn limit_required() {
        assert!(require_limit(None, 200).is_err());
        assert_eq!(require_limit(Some(9999), 200).unwrap(), 200);
    }
}
