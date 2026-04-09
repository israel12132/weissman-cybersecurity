//! B2B SaaS billing: Paddle Billing (checkout transactions), signed webhooks, per-tenant usage limits.
//! Enforcement is applied at API boundaries (`clients` create, `scan/run-all`).

mod webhook;

use chrono::{Datelike, Utc};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use weissman_db::auth_access;

pub use webhook::{handle_paddle_webhook, PaddleWebhookError};

/// When `true`, tenants must have an active or trialing Paddle subscription to add clients or run scans.
/// Default: `true` if `PADDLE_API_KEY` is non-empty, else `false` (local dev without billing).
pub fn billing_strict_enabled() -> bool {
    if let Ok(v) = std::env::var("WEISSMAN_BILLING_STRICT") {
        let s = v.trim();
        if s == "1" || s.eq_ignore_ascii_case("true") {
            return true;
        }
        if s == "0" || s.eq_ignore_ascii_case("false") {
            return false;
        }
    }
    std::env::var("PADDLE_API_KEY")
        .map(|k| !k.trim().is_empty())
        .unwrap_or(false)
}

pub fn paddle_api_base() -> Result<String, String> {
    let raw = std::env::var("PADDLE_ENVIRONMENT").unwrap_or_else(|_| "sandbox".to_string());
    match raw.trim().to_lowercase().as_str() {
        "sandbox" => Ok("https://sandbox-api.paddle.com".to_string()),
        "production" => Ok("https://api.paddle.com".to_string()),
        _ => Err(format!(
            "PADDLE_ENVIRONMENT must be 'sandbox' or 'production', got: {}",
            raw.trim()
        )),
    }
}

fn paddle_api_key() -> Result<String, String> {
    std::env::var("PADDLE_API_KEY")
        .map_err(|_| "PADDLE_API_KEY not configured".to_string())
        .and_then(|s| {
            let t = s.trim().to_string();
            if t.is_empty() {
                Err("PADDLE_API_KEY not configured".to_string())
            } else {
                Ok(t)
            }
        })
}

fn period_ym_now() -> String {
    let n = Utc::now().naive_utc().date();
    format!("{:04}-{:02}", n.year(), n.month())
}

pub async fn enforce_client_create(pool: &PgPool, tenant_id: i64) -> Result<(), String> {
    if !billing_strict_enabled() {
        return Ok(());
    }
    let row = sqlx::query(
        r#"SELECT ts.status, ts.plan_slug, bp.max_clients
           FROM tenant_subscriptions ts
           INNER JOIN billing_plans bp ON bp.slug = ts.plan_slug
           WHERE ts.tenant_id = $1"#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;
    let Some(r) = row else {
        return Err("Subscription not provisioned for tenant".to_string());
    };
    let status: String = r.try_get("status").map_err(|e| e.to_string())?;
    if !subscription_allows_usage(&status) {
        return Err(format!(
            "Subscription not active (status={}). Complete Paddle checkout or update payment method.",
            status
        ));
    }
    let max_c: i32 = r.try_get("max_clients").map_err(|e| e.to_string())?;
    let count: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM clients WHERE tenant_id = $1")
        .bind(tenant_id)
        .fetch_one(pool)
        .await
        .map_err(|e| e.to_string())?;
    if count >= max_c as i64 {
        return Err(format!(
            "Client limit reached ({}/{}). Upgrade your plan.",
            count, max_c
        ));
    }
    Ok(())
}

pub async fn enforce_scan_start(pool: &PgPool, tenant_id: i64) -> Result<(), String> {
    if !billing_strict_enabled() {
        return Ok(());
    }
    let row = sqlx::query(
        r#"SELECT ts.status, ts.plan_slug, bp.max_scans_month
           FROM tenant_subscriptions ts
           INNER JOIN billing_plans bp ON bp.slug = ts.plan_slug
           WHERE ts.tenant_id = $1"#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;
    let Some(r) = row else {
        return Err("Subscription not provisioned for tenant".to_string());
    };
    let status: String = r.try_get("status").map_err(|e| e.to_string())?;
    if !subscription_allows_usage(&status) {
        return Err(format!(
            "Subscription not active (status={}). Complete Paddle checkout or update payment method.",
            status
        ));
    }
    let max_s: i32 = r.try_get("max_scans_month").map_err(|e| e.to_string())?;
    let period = period_ym_now();
    let used: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(scans_started,0)::bigint FROM tenant_usage_counters WHERE tenant_id = $1 AND period_ym = $2",
    )
    .bind(tenant_id)
    .bind(&period)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?
    .unwrap_or(0);
    if used >= max_s as i64 {
        return Err(format!(
            "Monthly scan limit reached ({}/{}). Upgrade or wait for the next billing period.",
            used, max_s
        ));
    }
    Ok(())
}

pub async fn record_scan_started(pool: &PgPool, tenant_id: i64) -> Result<(), sqlx::Error> {
    let period = period_ym_now();
    sqlx::query(
        r#"INSERT INTO tenant_usage_counters (tenant_id, period_ym, scans_started)
           VALUES ($1, $2, 1)
           ON CONFLICT (tenant_id, period_ym)
           DO UPDATE SET scans_started = tenant_usage_counters.scans_started + 1"#,
    )
    .bind(tenant_id)
    .bind(&period)
    .execute(pool)
    .await?;
    Ok(())
}

fn subscription_allows_usage(status: &str) -> bool {
    matches!(
        status.to_lowercase().as_str(),
        "active" | "trialing"
    )
}

pub async fn usage_dashboard_json(pool: &PgPool, tenant_id: i64) -> Result<Value, String> {
    let row = sqlx::query(
        r#"SELECT ts.status, ts.plan_slug, ts.paddle_subscription_id, ts.current_period_end,
                  bp.display_name, bp.max_clients, bp.max_scans_month
           FROM tenant_subscriptions ts
           INNER JOIN billing_plans bp ON bp.slug = ts.plan_slug
           WHERE ts.tenant_id = $1"#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;
    let Some(r) = row else {
        return Ok(json!({
            "billing_strict": billing_strict_enabled(),
            "subscription": null,
            "usage": null,
        }));
    };
    let status: String = r.try_get("status").unwrap_or_default();
    let plan_slug: String = r.try_get("plan_slug").unwrap_or_default();
    let display_name: String = r.try_get("display_name").unwrap_or_default();
    let max_clients: i32 = r.try_get("max_clients").unwrap_or(0);
    let max_scans_month: i32 = r.try_get("max_scans_month").unwrap_or(0);
    let paddle_sub: Option<String> = r.try_get("paddle_subscription_id").ok();
    let period_end: Option<chrono::DateTime<Utc>> = r.try_get("current_period_end").ok();

    let client_count: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM clients WHERE tenant_id = $1")
        .bind(tenant_id)
        .fetch_one(pool)
        .await
        .map_err(|e| e.to_string())?;
    let period = period_ym_now();
    let scans_used: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(scans_started,0)::bigint FROM tenant_usage_counters WHERE tenant_id = $1 AND period_ym = $2",
    )
    .bind(tenant_id)
    .bind(&period)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?
    .unwrap_or(0);

    Ok(json!({
        "billing_strict": billing_strict_enabled(),
        "subscription": {
            "status": status,
            "plan_slug": plan_slug,
            "plan_name": display_name,
            "paddle_subscription_id": paddle_sub,
            "current_period_end": period_end.map(|d| d.to_rfc3339()),
        },
        "limits": {
            "max_clients": max_clients,
            "max_scans_per_month": max_scans_month,
        },
        "usage": {
            "clients": client_count,
            "scans_this_month": scans_used,
            "period": period,
        },
    }))
}

pub async fn resolve_paddle_price_id(pool: &PgPool, plan_slug: &str) -> Result<String, String> {
    let cell = sqlx::query_scalar::<_, Option<String>>(
        "SELECT paddle_price_id FROM billing_plans WHERE slug = $1 AND active = true",
    )
    .bind(plan_slug)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;
    if let Some(Some(ref pid)) = cell {
        let t = pid.trim();
        if !t.is_empty() {
            return Ok(t.to_string());
        }
    }
    let key = match plan_slug {
        "starter" => "WEISSMAN_PADDLE_PRICE_STARTER",
        "professional" => "WEISSMAN_PADDLE_PRICE_PROFESSIONAL",
        "enterprise" => "WEISSMAN_PADDLE_PRICE_ENTERPRISE",
        _ => return Err("Invalid plan_slug".to_string()),
    };
    std::env::var(key)
        .map_err(|_| format!("Set billing_plans.paddle_price_id or environment variable {}", key))
        .and_then(|s| {
            let t = s.trim().to_string();
            if t.is_empty() {
                Err(format!("{} is empty", key))
            } else {
                Ok(t)
            }
        })
}

pub async fn plan_slug_for_paddle_price_id(pool: &PgPool, price_id: &str) -> Option<String> {
    let pid = price_id.trim();
    if let Ok(Some(s)) = sqlx::query_scalar::<_, String>(
        "SELECT slug FROM billing_plans WHERE paddle_price_id = $1 AND active = true",
    )
    .bind(pid)
    .fetch_optional(pool)
    .await
    {
        return Some(s);
    }
    if let Ok(p) = std::env::var("WEISSMAN_PADDLE_PRICE_ENTERPRISE") {
        if p.trim() == pid {
            return Some("enterprise".to_string());
        }
    }
    if let Ok(p) = std::env::var("WEISSMAN_PADDLE_PRICE_PROFESSIONAL") {
        if p.trim() == pid {
            return Some("professional".to_string());
        }
    }
    if let Ok(p) = std::env::var("WEISSMAN_PADDLE_PRICE_STARTER") {
        if p.trim() == pid {
            return Some("starter".to_string());
        }
    }
    None
}

pub(crate) fn first_subscription_item_paddle_price_id(sub: &Value) -> Option<String> {
    let items = sub.get("items")?.as_array()?;
    let first = items.first()?;
    first
        .get("price")
        .and_then(|p| p.get("id"))
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            first
                .get("price_id")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string())
        })
}

pub async fn paddle_http_get_json(path: &str, base_override: &str) -> Result<Value, String> {
    let key = paddle_api_key()?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(45))
        .build()
        .map_err(|e| e.to_string())?;
    let url = format!(
        "{}{}",
        base_override.trim_end_matches('/'),
        path
    );
    let res = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", key))
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!(
            "Paddle API GET {} failed: {}",
            path,
            res.text().await.unwrap_or_default()
        ));
    }
    res.json().await.map_err(|e| e.to_string())
}

async fn paddle_list_customers_by_email(email: &str) -> Result<Vec<Value>, String> {
    let base = paddle_api_base()?;
    let key = paddle_api_key()?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(45))
        .build()
        .map_err(|e| e.to_string())?;
    let url = format!("{}/customers", base.trim_end_matches('/'));
    let res = client
        .get(&url)
        .query(&[("email", email)])
        .header("Authorization", format!("Bearer {}", key))
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!(
            "Paddle list customers failed: {}",
            res.text().await.unwrap_or_default()
        ));
    }
    let v: Value = res.json().await.map_err(|e| e.to_string())?;
    Ok(v.get("data")
        .and_then(|d| d.as_array())
        .cloned()
        .unwrap_or_default())
}

async fn paddle_create_customer(email: &str, tenant_id: i64) -> Result<String, String> {
    let base = paddle_api_base()?;
    let key = paddle_api_key()?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(45))
        .build()
        .map_err(|e| e.to_string())?;
    let body = json!({
        "email": email,
        "custom_data": { "tenant_id": tenant_id.to_string() }
    });
    let url = format!("{}/customers", base.trim_end_matches('/'));
    let res = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", key))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::ACCEPT, "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!(
            "Paddle create customer failed: {}",
            res.text().await.unwrap_or_default()
        ));
    }
    let v: Value = res.json().await.map_err(|e| e.to_string())?;
    v.pointer("/data/id")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "Paddle create customer response missing data.id".to_string())
}

fn transaction_checkout_url(v: &Value) -> Option<String> {
    v.pointer("/data/checkout/url")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
}

async fn paddle_create_transaction_checkout(
    customer_id: &str,
    price_id: &str,
    tenant_id: i64,
) -> Result<String, String> {
    let base = paddle_api_base()?;
    let key = paddle_api_key()?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(45))
        .build()
        .map_err(|e| e.to_string())?;
    let body = json!({
        "customer_id": customer_id,
        "items": [{ "price_id": price_id, "quantity": 1 }],
        "collection_mode": "automatic",
        "custom_data": { "tenant_id": tenant_id.to_string() }
    });
    let url = format!("{}/transactions", base.trim_end_matches('/'));
    let res = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", key))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::ACCEPT, "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!(
            "Paddle create transaction failed: {}",
            res.text().await.unwrap_or_default()
        ));
    }
    let v: Value = res.json().await.map_err(|e| e.to_string())?;
    if let Some(u) = transaction_checkout_url(&v) {
        return Ok(u);
    }
    if let Some(tid) = v.pointer("/data/id").and_then(|x| x.as_str()) {
        let path = format!("/transactions/{}", urlencoding::encode(tid));
        let v2 = paddle_http_get_json(&path, &base).await?;
        if let Some(u) = transaction_checkout_url(&v2) {
            return Ok(u);
        }
    }
    Err(format!(
        "Paddle response missing data.checkout.url: {}",
        serde_json::to_string(&v).unwrap_or_default()
    ))
}

/// Returns a Paddle Checkout URL for an automatically collected subscription transaction.
pub async fn create_checkout_session_url(
    pool: &PgPool,
    tenant_id: i64,
    user_id: i64,
    plan_slug: &str,
) -> Result<String, String> {
    let _ = paddle_api_key()?;
    let price_id = resolve_paddle_price_id(pool, plan_slug).await?;
    let row = sqlx::query("SELECT lower(trim(email)) AS email FROM users WHERE id = $1 AND tenant_id = $2")
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?;
    let email: String = row
        .and_then(|r| r.try_get::<String, _>("email").ok())
        .filter(|e| !e.is_empty())
        .ok_or_else(|| "User email not found".to_string())?;

    let customers = paddle_list_customers_by_email(&email).await?;
    let customer_id = if let Some(first) = customers.first() {
        first
            .get("id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string()
    } else {
        paddle_create_customer(&email, tenant_id).await?
    };
    if customer_id.is_empty() {
        return Err("Paddle customer id empty".to_string());
    }

    upsert_paddle_customer(pool, tenant_id, &customer_id)
        .await
        .map_err(|e| e.to_string())?;

    paddle_create_transaction_checkout(&customer_id, &price_id, tenant_id).await
}

pub(crate) async fn upsert_paddle_customer(
    pool: &PgPool,
    tenant_id: i64,
    customer_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO tenant_paddle_customers (tenant_id, paddle_customer_id)
           VALUES ($1, $2)
           ON CONFLICT (tenant_id) DO UPDATE SET paddle_customer_id = EXCLUDED.paddle_customer_id"#,
    )
    .bind(tenant_id)
    .bind(customer_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub(crate) async fn update_subscription_from_paddle_object(
    pool: &PgPool,
    tenant_id: i64,
    sub_id: &str,
    status: &str,
    price_id: Option<&str>,
    plan_slug_override: Option<&str>,
    period_start: Option<chrono::DateTime<Utc>>,
    period_end: Option<chrono::DateTime<Utc>>,
    cancel_at_period_end: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"UPDATE tenant_subscriptions SET
            paddle_subscription_id = $2,
            paddle_price_id = COALESCE($3, paddle_price_id),
            plan_slug = COALESCE($4, plan_slug),
            status = $5,
            current_period_start = COALESCE($6, current_period_start),
            current_period_end = COALESCE($7, current_period_end),
            cancel_at_period_end = $8,
            updated_at = now()
           WHERE tenant_id = $1"#,
    )
    .bind(tenant_id)
    .bind(sub_id)
    .bind(price_id)
    .bind(plan_slug_override)
    .bind(status)
    .bind(period_start)
    .bind(period_end)
    .bind(cancel_at_period_end)
    .execute(pool)
    .await?;
    Ok(())
}

pub(crate) async fn update_subscription_status_by_paddle_id(
    pool: &PgPool,
    paddle_sub_id: &str,
    status: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE tenant_subscriptions SET status = $2, updated_at = now() WHERE paddle_subscription_id = $1",
    )
    .bind(paddle_sub_id)
    .bind(status)
    .execute(pool)
    .await?;
    Ok(())
}

pub(crate) fn period_bounds_paddle(
    sub: &Value,
) -> (
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::DateTime<chrono::Utc>>,
) {
    use chrono::{DateTime, Utc};
    let period = sub.get("current_billing_period");
    let starts = period
        .and_then(|p| p.get("starts_at"))
        .and_then(|x| x.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc)));
    let ends = period
        .and_then(|p| p.get("ends_at"))
        .and_then(|x| x.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc)));
    (starts, ends)
}

/// Applies a Paddle subscription JSON entity (`data` object from API) to the tenant row.
pub(crate) async fn apply_paddle_subscription_to_tenant(
    pool: &PgPool,
    tenant_id: i64,
    sub: &Value,
) -> Result<(), String> {
    let sub_id = sub
        .get("id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| "subscription id missing".to_string())?;
    let status = sub
        .get("status")
        .and_then(|x| x.as_str())
        .unwrap_or("inactive")
        .to_lowercase();
    let price_id = first_subscription_item_paddle_price_id(sub);
    let plan_slug = if let Some(ref pid) = price_id {
        plan_slug_for_paddle_price_id(pool, pid).await
    } else {
        None
    };
    let (ps, pe) = period_bounds_paddle(sub);
    let cancel_at = sub
        .get("scheduled_change")
        .and_then(|s| s.get("action"))
        .and_then(|x| x.as_str())
        .map(|a| a == "cancel")
        .unwrap_or(false);

    update_subscription_from_paddle_object(
        pool,
        tenant_id,
        sub_id,
        &status,
        price_id.as_deref(),
        plan_slug.as_deref(),
        ps,
        pe,
        cancel_at,
    )
    .await
    .map_err(|e| e.to_string())?;

    if let Some(cust) = sub.get("customer_id").and_then(|x| x.as_str()) {
        upsert_paddle_customer(pool, tenant_id, cust)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Pull the latest subscription state from Paddle Billing into Postgres (dashboard / live demo).
pub async fn refresh_subscription_from_paddle_api(
    pool: &PgPool,
    tenant_id: i64,
) -> Result<String, String> {
    let row = sqlx::query(
        "SELECT paddle_subscription_id FROM tenant_subscriptions WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;
    let Some(r) = row else {
        return Err("No subscription row for tenant.".to_string());
    };
    let sid: Option<String> = r.try_get("paddle_subscription_id").ok();
    let Some(sub_id) = sid.filter(|s| !s.trim().is_empty()) else {
        return Err(
            "No paddle_subscription_id on file; complete Paddle checkout or wait for webhooks."
                .to_string(),
        );
    };
    let base = paddle_api_base()?;
    let path = format!(
        "/subscriptions/{}",
        urlencoding::encode(sub_id.trim())
    );
    let v = paddle_http_get_json(&path, &base).await?;
    let data = v
        .get("data")
        .ok_or_else(|| "Paddle subscription response missing data".to_string())?;
    apply_paddle_subscription_to_tenant(pool, tenant_id, data).await?;
    Ok(format!(
        "Subscription {} refreshed from Paddle Billing.",
        sub_id.trim()
    ))
}

/// Validates and normalizes a tenant slug (DNS-like label).
pub fn normalize_tenant_slug(raw: &str) -> Result<String, String> {
    let s = raw.trim().to_lowercase();
    if s.is_empty() {
        return Err("tenant_slug required".to_string());
    }
    if s == "default" {
        return Err("tenant_slug 'default' is reserved".to_string());
    }
    if s.len() < 3 || s.len() > 48 {
        return Err("tenant_slug must be 3–48 characters".to_string());
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err("tenant_slug may contain only a-z, 0-9, hyphen".to_string());
    }
    Ok(s)
}

/// Self-serve B2B onboarding: new tenant, admin user, subscription row, usage counter (auth pool / BYPASSRLS).
pub async fn register_tenant_and_admin(
    auth_pool: &PgPool,
    organization_name: &str,
    tenant_slug: &str,
    email: &str,
    password: &str,
    plan_slug: &str,
) -> Result<(i64, i64), String> {
    let org = organization_name.trim();
    if org.is_empty() {
        return Err("organization_name required".to_string());
    }
    let slug = normalize_tenant_slug(tenant_slug)?;
    let em = email.trim();
    if em.is_empty() || !em.contains('@') {
        return Err("valid email required".to_string());
    }
    if password.len() < 10 {
        return Err("password must be at least 10 characters".to_string());
    }
    let plan_ok: bool = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM billing_plans WHERE slug = $1 AND active = true)",
    )
    .bind(plan_slug)
    .fetch_one(auth_pool)
    .await
    .map_err(|e| e.to_string())?;
    if !plan_ok {
        return Err("invalid or inactive plan_slug".to_string());
    }
    let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|e| e.to_string())?;
    let mut tx = auth_pool.begin().await.map_err(|e| e.to_string())?;
    let tid: i64 = sqlx::query_scalar(
        "INSERT INTO tenants (slug, name, active) VALUES ($1, $2, true) RETURNING id",
    )
    .bind(&slug)
    .bind(org)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(ref dbe) = e {
            if dbe.code().map(|c| c.as_ref() == "23505").unwrap_or(false) {
                return "tenant_slug already registered".to_string();
            }
        }
        e.to_string()
    })?;
    let uid: i64 = auth_access::insert_user_auth(&mut *tx, tid, em, Some(hash.as_str()), "admin")
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref dbe) = e {
                if dbe.code().map(|c| c.as_ref() == "23505").unwrap_or(false) {
                    return "email already registered for this tenant".to_string();
                }
            }
            e.to_string()
        })?;
    let sub_status = if billing_strict_enabled() {
        "incomplete"
    } else {
        "active"
    };
    sqlx::query(
        "INSERT INTO tenant_subscriptions (tenant_id, plan_slug, status) VALUES ($1, $2, $3)",
    )
    .bind(tid)
    .bind(plan_slug)
    .bind(sub_status)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let period = period_ym_now();
    sqlx::query(
        "INSERT INTO tenant_usage_counters (tenant_id, period_ym, scans_started) VALUES ($1, $2, 0)",
    )
    .bind(tid)
    .bind(&period)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok((tid, uid))
}
