//! Platform self-security posture score — measures Weissman deployment health, not tenant clients.

use serde::Serialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use weissman_core::tls_policy::is_production_environment;

#[derive(Debug, Clone, Serialize)]
pub struct SecurityPostureScore {
    pub score: u8,
    pub grade: char,
    pub checks: Vec<PostureCheck>,
    pub generated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PostureCheck {
    pub id: &'static str,
    pub passed: bool,
    pub weight: u8,
    pub detail: String,
}

/// Compute live platform posture from env + DB signals (no fabricated metrics).
pub async fn compute_platform_posture(pool: &PgPool) -> SecurityPostureScore {
    let mut checks = Vec::new();

    let jwt_ok = std::env::var("WEISSMAN_JWT_SECRET")
        .map(|s| s.trim().len() >= 48)
        .unwrap_or(false);
    checks.push(PostureCheck {
        id: "jwt_secret_strength",
        passed: jwt_ok,
        weight: 15,
        detail: if jwt_ok {
            "JWT secret >= 48 bytes".into()
        } else {
            "WEISSMAN_JWT_SECRET missing or too short".into()
        },
    });

    let metrics_ok = std::env::var("WEISSMAN_METRICS_TOKEN")
        .map(|s| s.trim().len() >= 32)
        .unwrap_or(false);
    checks.push(PostureCheck {
        id: "metrics_token",
        passed: metrics_ok,
        weight: 10,
        detail: if metrics_ok {
            "Metrics endpoint token configured".into()
        } else {
            "WEISSMAN_METRICS_TOKEN not set (metrics would be blocked)".into()
        },
    });

    let redis_ok = std::env::var("REDIS_URL")
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
        || is_production_environment()
            && crate::security_startup::env_truthy_pub("WEISSMAN_ALLOW_SINGLE_NODE");
    checks.push(PostureCheck {
        id: "redis_distributed",
        passed: redis_ok,
        weight: 12,
        detail: if redis_ok {
            "Redis or explicit single-node ack".into()
        } else {
            "REDIS_URL unset — rate limits degrade per-replica".into()
        },
    });

    let cookie_ok = !is_production_environment() || crate::auth_jwt::cookie_use_secure();
    checks.push(PostureCheck {
        id: "secure_cookies",
        passed: cookie_ok,
        weight: 10,
        detail: if cookie_ok {
            "Cookie secure policy OK for environment".into()
        } else {
            "WEISSMAN_COOKIE_SECURE must be 1 in production".into()
        },
    });

    let destructive_ok = std::env::var("WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET")
        .map(|s| s.trim().len() >= 32)
        .unwrap_or(!is_production_environment());
    checks.push(PostureCheck {
        id: "destructive_hmac",
        passed: destructive_ok,
        weight: 8,
        detail: if destructive_ok {
            "Destructive action HMAC secret configured".into()
        } else {
            "WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET required in production".into()
        },
    });

    let revoked_table_ok = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'weissman_revoked_tokens')",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(false);
    checks.push(PostureCheck {
        id: "jwt_revocation_table",
        passed: revoked_table_ok,
        weight: 10,
        detail: if revoked_table_ok {
            "Token revocation table present".into()
        } else {
            "weissman_revoked_tokens missing".into()
        },
    });

    let rls_ok = sqlx::query_scalar::<_, bool>(
        r#"SELECT EXISTS (
            SELECT 1 FROM pg_tables t
            JOIN pg_class c ON c.relname = t.tablename
            WHERE t.tablename = 'vulnerabilities' AND c.relrowsecurity = true
        )"#,
    )
    .fetch_one(pool)
    .await
    .unwrap_or(false);
    checks.push(PostureCheck {
        id: "findings_rls",
        passed: rls_ok,
        weight: 15,
        detail: if rls_ok {
            "vulnerabilities table has RLS enabled".into()
        } else {
            "RLS not enabled on vulnerabilities".into()
        },
    });

    let enrollment_hashed = sqlx::query_scalar::<_, bool>(
        r#"SELECT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name = 'endpoint_agent_enrollment_tokens'
              AND column_name = 'token_hash'
        )"#,
    )
    .fetch_one(pool)
    .await
    .unwrap_or(false);
    checks.push(PostureCheck {
        id: "agent_enrollment_hardening",
        passed: enrollment_hashed,
        weight: 10,
        detail: if enrollment_hashed {
            "Enrollment tokens stored hashed".into()
        } else {
            "token_hash column missing on enrollment tokens".into()
        },
    });

    let openapi_blocked = is_production_environment();
    checks.push(PostureCheck {
        id: "openapi_prod_blocked",
        passed: openapi_blocked,
        weight: 5,
        detail: "OpenAPI disabled in production by policy".into(),
    });

    let total_weight: u32 = checks.iter().map(|c| c.weight as u32).sum();
    let earned: u32 = checks
        .iter()
        .filter(|c| c.passed)
        .map(|c| c.weight as u32)
        .sum();
    let score = if total_weight == 0 {
        0
    } else {
        ((earned * 100) / total_weight).min(100) as u8
    };
    let grade = match score {
        90..=100 => 'A',
        80..=89 => 'B',
        70..=79 => 'C',
        60..=69 => 'D',
        _ => 'F',
    };

    SecurityPostureScore {
        score,
        grade,
        checks,
        generated_at: chrono::Utc::now().to_rfc3339(),
    }
}

#[must_use]
pub fn posture_to_json(p: &SecurityPostureScore) -> Value {
    serde_json::to_value(p).unwrap_or_else(|_| json!({ "error": "posture serialize failed" }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SecurityPostureScore {
        SecurityPostureScore {
            score: 85,
            grade: 'B',
            checks: vec![
                PostureCheck {
                    id: "jwt_secret_strength",
                    passed: true,
                    weight: 15,
                    detail: "ok".into(),
                },
                PostureCheck {
                    id: "metrics_token",
                    passed: false,
                    weight: 10,
                    detail: "missing".into(),
                },
            ],
            generated_at: "2026-01-01T00:00:00+00:00".into(),
        }
    }

    #[test]
    fn posture_to_json_preserves_fields() {
        let v = posture_to_json(&sample());
        assert_eq!(v["score"], 85);
        assert_eq!(v["grade"], "B");
        assert_eq!(v["checks"].as_array().unwrap().len(), 2);
        assert_eq!(v["checks"][0]["id"], "jwt_secret_strength");
        assert_eq!(v["checks"][0]["passed"], true);
        assert_eq!(v["checks"][1]["weight"], 10);
    }

    #[test]
    fn posture_check_serializes_all_fields() {
        let c = PostureCheck {
            id: "redis_distributed",
            passed: true,
            weight: 12,
            detail: "Redis configured".into(),
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["id"], "redis_distributed");
        assert_eq!(v["passed"], true);
        assert_eq!(v["weight"], 12);
        assert_eq!(v["detail"], "Redis configured");
    }
}
