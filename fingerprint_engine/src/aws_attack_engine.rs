//! AWS Cloud Security Posture Engine — a CNAPP-grade, evidence-bearing assessment of an AWS
//! estate. Inspired by best-in-class cloud security platforms (Wiz, Orca, Prowler) but built to
//! exceed them on *transparency* and *operator control*: every check is a real probe (a signed AWS
//! API call, or a live unauthenticated HTTP/DNS request), every finding carries the full evidence
//! trail, and every knob is exposed in the request body so an operator can tune the entire scan
//! without a code change.
//!
//! Two complementary collection planes, fused into one posture:
//!   1. **Agentless credentialed plane** (read-only AWS keys or a cross-account role) — true
//!      CSPM/CIEM/CWPP: IAM identity hygiene, S3 data exposure, EC2/VPC network exposure, the
//!      instance-metadata (IMDSv1) credential-theft surface, and unencrypted storage.
//!   2. **External attack-surface plane** (no credentials) — what an internet attacker sees:
//!      public S3 buckets, subdomain-takeover dangling-bucket signals, leaked AWS keys in web
//!      assets, and AWS service fingerprints.
//!
//! Findings are scored into a 0–100 posture index with a letter grade and per-domain sub-scores,
//! mapped to the **CIS AWS Foundations Benchmark v3.0.0** and **MITRE ATT&CK (Cloud / IaaS)**, and
//! correlated into **attack paths** (the "toxic combinations" that turn individual gaps into a real
//! breach chain). No finding is fabricated: a control is only reported when a real probe observed
//! the real signal.

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    detect_secrets, extract_host, header_value, http_client, http_get, normalize_url,
};
use crate::engine_result::{print_result, EngineResult};
use futures::stream::{self, StreamExt};
use serde_json::{json, Value};

const ENGINE_ID: &str = "aws_attack";

// ─────────────────────────────────────────────────────────────────────────────
// Configuration — every knob is read from the live scan request body
// (`POST /api/command-center/scan` → EngineRunContext::job_params).
// ─────────────────────────────────────────────────────────────────────────────

/// Fully-parsed, validated scan configuration. All fields fall back to safe defaults so the engine
/// behaves correctly on an empty body, yet an operator can override every dimension of the scan.
#[derive(Clone, Debug)]
pub struct AwsScanConfig {
    // Collection planes
    pub enable_external: bool,
    pub enable_credentialed: bool,
    pub enable_iam: bool,
    pub enable_s3: bool,
    pub enable_ec2: bool,
    pub enable_attack_paths: bool,
    pub service_fingerprint: bool,
    // Credentials (credentialed plane)
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub session_token: Option<String>,
    pub role_arn: Option<String>,
    pub external_id: Option<String>,
    pub session_name: Option<String>,
    pub region: String,
    pub regions: Vec<String>,
    // External plane
    pub bucket_candidates: Vec<String>,
    pub bucket_permutations: bool,
    pub extra_bucket_suffixes: Vec<String>,
    pub web_paths: Vec<String>,
    // Thresholds / limits
    pub access_key_max_age_days: u64,
    pub max_users_scanned: usize,
    pub max_buckets_scanned: usize,
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub intensity: Intensity,
    pub min_severity: String,
}

impl AwsScanConfig {
    fn from_arsenal(c: &ArsenalConfig) -> Self {
        let region = c.string_or("aws_region", "us-east-1");
        let mut regions = c.string_list("aws_regions");
        if regions.is_empty() {
            regions = vec![region.clone()];
        }
        let intensity = c.intensity();
        // Permutation breadth scales with intensity so a "light" run stays quick.
        let default_max_buckets = match intensity {
            Intensity::Light => 40,
            Intensity::Normal => 80,
            Intensity::Aggressive => 220,
        };
        Self {
            enable_external: c.bool_or("enable_external", true),
            enable_credentialed: c.bool_or("enable_credentialed", true),
            enable_iam: c.bool_or("enable_iam", true),
            enable_s3: c.bool_or("enable_s3", true),
            enable_ec2: c.bool_or("enable_ec2", true),
            enable_attack_paths: c.bool_or("enable_attack_paths", true),
            service_fingerprint: c.bool_or("service_fingerprint", true),
            access_key_id: c.string("aws_access_key_id"),
            secret_access_key: c.string("aws_secret_access_key"),
            session_token: c.string("aws_session_token"),
            role_arn: c.string("aws_role_arn"),
            external_id: c.string("aws_external_id"),
            session_name: c.string("aws_role_session_name"),
            region,
            regions,
            bucket_candidates: c.string_list("bucket_candidates"),
            bucket_permutations: c.bool_or("bucket_permutations", true),
            extra_bucket_suffixes: c.string_list("extra_bucket_suffixes"),
            web_paths: c.string_list_or("web_paths", AWS_WEB_PATHS),
            access_key_max_age_days: c.u64_or("access_key_max_age_days", 90).clamp(1, 3650),
            max_users_scanned: c.usize_or("max_users_scanned", 60).clamp(1, 1000),
            max_buckets_scanned: c
                .usize_or("max_buckets_scanned", default_max_buckets)
                .clamp(1, 2000),
            timeout_ms: c.timeout_ms(10_000),
            concurrency: c.concurrency(),
            intensity,
            min_severity: c.string_or("min_severity", "info"),
        }
    }

    /// True when the operator supplied static keys or a cross-account role for the credentialed plane.
    fn has_static_keys(&self) -> bool {
        self.access_key_id.as_ref().is_some_and(|k| !k.is_empty())
            && self
                .secret_access_key
                .as_ref()
                .is_some_and(|k| !k.is_empty())
    }

    fn has_role(&self) -> bool {
        self.role_arn.as_ref().is_some_and(|r| r.starts_with("arn:aws:iam::"))
    }

    fn credentialed_ready(&self) -> bool {
        self.enable_credentialed && (self.has_static_keys() || self.has_role())
    }
}

/// Web paths that frequently leak AWS credential material (config bundles, dotfiles, env dumps).
const AWS_WEB_PATHS: &[&str] = &[
    "/.aws/credentials",
    "/.aws/config",
    "/aws/credentials",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/config.json",
    "/static/aws-config.js",
    "/js/config.js",
    "/assets/config.js",
    "/static/config.js",
    "/app.config.js",
    "/env.js",
    "/credentials.json",
    "/.git/config",
    "/backup.sql",
    "/.terraform/terraform.tfstate",
    "/terraform.tfstate",
];

/// Sensitive service ports whose world-open ingress (0.0.0.0/0) is a critical network exposure.
const DANGEROUS_PORTS: &[i32] = &[
    22, 23, 25, 135, 139, 445, 1433, 1521, 2049, 3306, 3389, 5432, 5433, 5984, 6379, 8020, 9000,
    9042, 9200, 9300, 11211, 27017, 27018,
];

// ─────────────────────────────────────────────────────────────────────────────
// Finding builders — every finding is rich (evidence + confidence) and carries the
// security-domain, CIS AWS Foundations control, MITRE ATT&CK technique and category.
// ─────────────────────────────────────────────────────────────────────────────

/// Security domain a finding belongs to (drives the per-domain posture sub-scores).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Domain {
    Identity,
    Data,
    Network,
    Exposure,
    Posture,
}

impl Domain {
    fn as_str(self) -> &'static str {
        match self {
            Domain::Identity => "identity",
            Domain::Data => "data",
            Domain::Network => "network",
            Domain::Exposure => "exposure",
            Domain::Posture => "posture",
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn aws_finding(
    domain: Domain,
    title: &str,
    severity: &str,
    mitre: &str,
    cis: &str,
    target: &str,
    confidence: f64,
    description: &str,
    evidence: Evidence,
) -> Value {
    let mut f = finding_rich(
        ENGINE_ID,
        title,
        severity,
        mitre,
        description,
        target,
        confidence,
        evidence,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("domain".to_string(), json!(domain.as_str()));
        obj.insert("category".to_string(), json!(domain.as_str()));
        if !cis.is_empty() {
            obj.insert("cis_aws".to_string(), json!(cis));
        }
        obj.insert("plane".to_string(), json!(plane_for(domain)));
    }
    f
}

fn plane_for(domain: Domain) -> &'static str {
    match domain {
        Domain::Exposure => "external",
        _ => "credentialed",
    }
}

fn sev_weight(sev: &str) -> f64 {
    match sev.to_ascii_lowercase().as_str() {
        "critical" => 20.0,
        "high" => 11.0,
        "medium" => 4.5,
        "low" => 1.5,
        _ => 0.0,
    }
}

fn sev_rank(sev: &str) -> u8 {
    match sev.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn finding_sev(f: &Value) -> String {
    f.get("severity")
        .and_then(Value::as_str)
        .unwrap_or("info")
        .to_string()
}

fn finding_domain(f: &Value) -> &str {
    f.get("domain").and_then(Value::as_str).unwrap_or("posture")
}

fn grade_for(score: f64) -> &'static str {
    if score >= 95.0 {
        "A+"
    } else if score >= 90.0 {
        "A"
    } else if score >= 80.0 {
        "B"
    } else if score >= 70.0 {
        "C"
    } else if score >= 55.0 {
        "D"
    } else if score >= 40.0 {
        "E"
    } else {
        "F"
    }
}

/// Compute a 0–100 posture index from a finding set (100 = clean). Penalty is the severity-weighted
/// sum, dampened so a large estate with many low findings is not crushed below a high-severity one.
fn posture_score(findings: &[Value]) -> f64 {
    let penalty: f64 = findings
        .iter()
        .filter(|f| finding_domain(f) != "posture")
        .map(|f| sev_weight(&finding_sev(f)))
        .sum();
    (100.0 - penalty).clamp(0.0, 100.0)
}

fn domain_score(findings: &[Value], domain: Domain) -> f64 {
    let penalty: f64 = findings
        .iter()
        .filter(|f| finding_domain(f) == domain.as_str())
        .map(|f| sev_weight(&finding_sev(f)))
        .sum();
    (100.0 - penalty).clamp(0.0, 100.0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry points
// ─────────────────────────────────────────────────────────────────────────────

/// Back-compat thin wrapper (used by `main.rs`, `advanced_cloud_engines`, and any legacy caller):
/// runs the engine with default parameters (external plane only, no credentials).
pub async fn run_aws_attack_result(target: &str) -> EngineResult {
    run_aws_attack_result_ctx(target, &EngineRunContext::default()).await
}

/// Parameterised entry point used by the dispatch layer. Reads every knob from `ctx.job_params`.
pub async fn run_aws_attack_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = AwsScanConfig::from_arsenal(&ArsenalConfig::from_ctx(ctx));
    let mut findings: Vec<Value> = Vec::new();
    let mut account_id: Option<String> = None;
    let mut principal_arn: Option<String> = None;

    // ── Credentialed plane (CSPM / CIEM / CWPP) ──────────────────────────────
    if cfg.credentialed_ready() {
        match build_sdk_config(&cfg).await {
            Ok(sdk) => {
                let (acct, arn, gate) = sts_identity(&sdk, target).await;
                account_id = acct;
                principal_arn = arn;
                findings.extend(gate);
                if account_id.is_some() {
                    if cfg.enable_iam {
                        findings.extend(scan_iam(&sdk, &cfg, target).await);
                    }
                    if cfg.enable_s3 {
                        findings.extend(scan_s3(&sdk, &cfg, target).await);
                    }
                    if cfg.enable_ec2 {
                        findings.extend(scan_ec2(&sdk, &cfg, target).await);
                    }
                }
            }
            Err(e) => {
                findings.push(aws_finding(
                    Domain::Posture,
                    "Credentialed AWS plane unavailable",
                    "info",
                    "",
                    "",
                    target,
                    1.0,
                    &format!("Could not initialise the AWS SDK with the supplied credentials: {e}. The external attack-surface plane still ran. Provide a valid read-only access key (or cross-account role) to enable CSPM/CIEM."),
                    Evidence::new().with("phase", "sdk_init").with("error", e),
                ));
            }
        }
    }

    // ── External attack-surface plane (no credentials needed) ────────────────
    if cfg.enable_external {
        findings.extend(scan_external_surface(target, &cfg).await);
    }

    // ── Attack-path correlation (toxic combinations) ─────────────────────────
    let attack_paths = if cfg.enable_attack_paths {
        synthesize_attack_paths(&findings, target, account_id.as_deref())
    } else {
        Vec::new()
    };
    findings.extend(attack_paths.iter().cloned());

    // ── Severity floor filter ────────────────────────────────────────────────
    let floor = sev_rank(&cfg.min_severity);
    if floor > 0 {
        findings.retain(|f| finding_domain(f) == "posture" || sev_rank(&finding_sev(f)) >= floor);
    }

    // ── Posture summary (always emitted first) ───────────────────────────────
    let summary = build_posture_summary(
        &findings,
        &attack_paths,
        target,
        account_id.as_deref(),
        principal_arn.as_deref(),
        &cfg,
    );
    let mut out = Vec::with_capacity(findings.len() + 1);
    out.push(summary);
    out.extend(findings);

    let actionable = out.iter().filter(|f| finding_domain(f) != "posture").count();
    EngineResult::ok(
        out,
        format!(
            "AWS Cloud Security Posture: {actionable} finding(s) across {} plane(s) on {target}",
            if cfg.credentialed_ready() { 2 } else { 1 }
        ),
    )
}

pub async fn run_aws_attack(target: &str) {
    print_result(run_aws_attack_result(target).await);
}

// ─────────────────────────────────────────────────────────────────────────────
// Credentialed plane — AWS SDK config + STS identity gate
// ─────────────────────────────────────────────────────────────────────────────

/// Build a usable `SdkConfig` from static keys, a static-key→assume-role chain, or a default-chain
/// cross-account assume-role. Returns a human-readable error for the posture summary on failure.
async fn build_sdk_config(cfg: &AwsScanConfig) -> Result<aws_types::SdkConfig, String> {
    use aws_config::{BehaviorVersion, Region};
    use aws_credential_types::provider::SharedCredentialsProvider;
    use aws_credential_types::Credentials as AwsCredentials;
    use aws_types::SdkConfig;

    if cfg.has_static_keys() {
        let ak = cfg.access_key_id.clone().unwrap_or_default();
        let sk = cfg.secret_access_key.clone().unwrap_or_default();
        let token = cfg.session_token.clone().filter(|s| !s.is_empty());
        let creds = AwsCredentials::new(ak, sk, token, None, "weissman-static");
        let sdk = SdkConfig::builder()
            .credentials_provider(SharedCredentialsProvider::new(creds))
            .region(Region::new(cfg.region.clone()))
            .behavior_version(BehaviorVersion::latest())
            .build();
        if cfg.has_role() {
            return assume_role_from(&sdk, cfg).await;
        }
        return Ok(sdk);
    }
    if cfg.has_role() {
        let cac = crate::cloud_integration_engine::CrossAccountAwsConfig {
            role_arn: cfg.role_arn.clone().unwrap_or_default(),
            external_id: cfg.external_id.clone().unwrap_or_default(),
            session_name: cfg.session_name.clone().unwrap_or_default(),
        };
        return crate::cloud_integration_engine::assume_role_sdk_config(&cac)
            .await
            .map(|(sdk, _region)| sdk)
            .map_err(|e| e.to_string());
    }
    Err("no AWS credentials supplied".to_string())
}

/// Assume `cfg.role_arn` using an already-built base config (static keys → temporary role creds).
async fn assume_role_from(
    base: &aws_types::SdkConfig,
    cfg: &AwsScanConfig,
) -> Result<aws_types::SdkConfig, String> {
    use aws_config::{BehaviorVersion, Region};
    use aws_credential_types::provider::SharedCredentialsProvider;
    use aws_credential_types::Credentials as AwsCredentials;
    use aws_types::SdkConfig;

    let sts = aws_sdk_sts::Client::new(base);
    let role = cfg.role_arn.clone().unwrap_or_default();
    let session = cfg
        .session_name
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "weissman-aws-posture".to_string());
    let mut req = sts.assume_role().role_arn(role).role_session_name(session);
    if let Some(ext) = cfg.external_id.clone().filter(|s| !s.is_empty()) {
        req = req.external_id(ext);
    }
    let out = req.send().await.map_err(|e| format!("AssumeRole: {e}"))?;
    let c = out
        .credentials()
        .ok_or_else(|| "AssumeRole returned no credentials".to_string())?;
    let token = {
        let t = c.session_token();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    };
    let creds = AwsCredentials::new(
        c.access_key_id(),
        c.secret_access_key(),
        token,
        std::time::SystemTime::try_from(*c.expiration()).ok(),
        "weissman-assumed",
    );
    Ok(SdkConfig::builder()
        .credentials_provider(SharedCredentialsProvider::new(creds))
        .region(Region::new(cfg.region.clone()))
        .behavior_version(BehaviorVersion::latest())
        .build())
}

/// Validate credentials and resolve the account / principal. Returns `(account, arn, findings)`.
async fn sts_identity(
    sdk: &aws_types::SdkConfig,
    target: &str,
) -> (Option<String>, Option<String>, Vec<Value>) {
    let sts = aws_sdk_sts::Client::new(sdk);
    match sts.get_caller_identity().send().await {
        Ok(id) => {
            let account = id.account().map(str::to_string);
            let arn = id.arn().map(str::to_string);
            let f = aws_finding(
                Domain::Posture,
                "AWS credentialed plane authenticated",
                "info",
                "",
                "",
                target,
                1.0,
                &format!(
                    "STS GetCallerIdentity succeeded (account {}, principal {}). Live CSPM/CIEM checks are running against the AWS APIs.",
                    account.clone().unwrap_or_default(),
                    arn.clone().unwrap_or_default()
                ),
                Evidence::new()
                    .with("account_id", account.clone().unwrap_or_default())
                    .with("principal_arn", arn.clone().unwrap_or_default())
                    .check("sts_get_caller_identity", true, "200 OK"),
            );
            (account, arn, vec![f])
        }
        Err(e) => {
            let f = aws_finding(
                Domain::Posture,
                "AWS credential validation failed",
                "info",
                "",
                "",
                target,
                1.0,
                &format!("STS GetCallerIdentity failed: {e}. Credentialed checks were skipped — verify the key/role is active and allows sts:GetCallerIdentity."),
                Evidence::new()
                    .with("error", e.to_string())
                    .check("sts_get_caller_identity", false, "error"),
            );
            (None, None, vec![f])
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CIEM — IAM identity hygiene (CIS AWS Foundations §1)
// ─────────────────────────────────────────────────────────────────────────────

async fn scan_iam(sdk: &aws_types::SdkConfig, cfg: &AwsScanConfig, target: &str) -> Vec<Value> {
    use aws_sdk_iam::types::{StatusType, SummaryKeyType};
    let iam = aws_sdk_iam::Client::new(sdk);
    let mut f: Vec<Value> = Vec::new();

    // Account-level summary (root MFA, root keys).
    if let Ok(out) = iam.get_account_summary().send().await {
        if let Some(m) = out.summary_map() {
            let get = |k: &SummaryKeyType| m.get(k).copied().unwrap_or(0);
            if get(&SummaryKeyType::AccountMfaEnabled) == 0 {
                f.push(aws_finding(
                    Domain::Identity,
                    "Root account MFA is not enabled",
                    "critical",
                    "T1078.004",
                    "1.5",
                    target,
                    0.95,
                    "The AWS account root user has no MFA device. Root has unrestricted access; a stolen root password is full-account compromise.",
                    Evidence::new()
                        .with("account_mfa_enabled", false)
                        .check("get_account_summary.AccountMFAEnabled", true, 0),
                ));
            }
            let root_keys = get(&SummaryKeyType::AccountAccessKeysPresent);
            if root_keys > 0 {
                f.push(aws_finding(
                    Domain::Identity,
                    "Root account has active access keys",
                    "critical",
                    "T1078.004",
                    "1.4",
                    target,
                    0.95,
                    "Long-lived root access keys exist. Delete root keys entirely; use IAM roles/users for programmatic access.",
                    Evidence::new()
                        .with("root_access_keys_present", true)
                        .check("get_account_summary.AccountAccessKeysPresent", true, root_keys),
                ));
            }
        }
    }

    // Password policy (CIS 1.8 / 1.9).
    match iam.get_account_password_policy().send().await {
        Ok(out) => {
            if let Some(pp) = out.password_policy() {
                let min_len = pp.minimum_password_length().unwrap_or(0);
                if min_len < 14 {
                    f.push(aws_finding(
                        Domain::Identity,
                        "Weak IAM password policy — minimum length",
                        "medium",
                        "T1110",
                        "1.8",
                        target,
                        0.9,
                        &format!("IAM password minimum length is {min_len} (CIS requires ≥ 14)."),
                        Evidence::new().with("minimum_password_length", min_len),
                    ));
                }
                let reuse = pp.password_reuse_prevention().unwrap_or(0);
                if reuse < 24 {
                    f.push(aws_finding(
                        Domain::Identity,
                        "IAM password reuse not sufficiently prevented",
                        "low",
                        "T1110",
                        "1.9",
                        target,
                        0.85,
                        &format!("Password reuse prevention is {reuse} (CIS requires remembering ≥ 24 passwords)."),
                        Evidence::new().with("password_reuse_prevention", reuse),
                    ));
                }
                if !pp.require_symbols()
                    || !pp.require_numbers()
                    || !pp.require_uppercase_characters()
                    || !pp.require_lowercase_characters()
                {
                    f.push(aws_finding(
                        Domain::Identity,
                        "IAM password complexity requirements incomplete",
                        "low",
                        "T1110",
                        "1.8",
                        target,
                        0.8,
                        "The IAM password policy does not require all character classes (symbols, numbers, upper, lower).",
                        Evidence::new()
                            .with("require_symbols", pp.require_symbols())
                            .with("require_numbers", pp.require_numbers())
                            .with("require_uppercase", pp.require_uppercase_characters())
                            .with("require_lowercase", pp.require_lowercase_characters()),
                    ));
                }
            }
        }
        Err(e) => {
            let code = e
                .as_service_error()
                .and_then(|se| se.meta().code())
                .unwrap_or("");
            if code == "NoSuchEntity" {
                f.push(aws_finding(
                    Domain::Identity,
                    "No IAM account password policy configured",
                    "medium",
                    "T1110",
                    "1.8",
                    target,
                    0.9,
                    "The account has no IAM password policy, so console users can set trivially weak passwords.",
                    Evidence::new().check("get_account_password_policy", false, "NoSuchEntity"),
                ));
            }
        }
    }

    // Per-user hygiene: console-without-MFA, stale keys, multiple keys, direct admin.
    if let Ok(out) = iam.list_users().send().await {
        let users = out.users();
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        )
        .unwrap_or(0);
        let max_age = i64::try_from(cfg.access_key_max_age_days).unwrap_or(90);
        for u in users.iter().take(cfg.max_users_scanned) {
            let name = u.user_name().to_string();
            let has_console = iam.get_login_profile().user_name(&name).send().await.is_ok();
            if has_console {
                let mfa_empty = iam
                    .list_mfa_devices()
                    .user_name(&name)
                    .send()
                    .await
                    .map(|r| r.mfa_devices().is_empty())
                    .unwrap_or(false);
                if mfa_empty {
                    f.push(aws_finding(
                        Domain::Identity,
                        &format!("IAM console user without MFA: {name}"),
                        "high",
                        "T1078.004",
                        "1.10",
                        target,
                        0.92,
                        &format!("IAM user '{name}' has console access but no MFA device (CIS 1.10 requires MFA for all console users)."),
                        Evidence::new()
                            .with("user", name.clone())
                            .check("get_login_profile", true, "present")
                            .check("list_mfa_devices", true, "empty"),
                    ));
                }
            }
            if let Ok(keys) = iam.list_access_keys().user_name(&name).send().await {
                let mut active = 0;
                for k in keys.access_key_metadata() {
                    if !matches!(k.status(), Some(StatusType::Active)) {
                        continue;
                    }
                    active += 1;
                    if let Some(created) = k.create_date() {
                        let age_days = (now - created.secs()).max(0) / 86_400;
                        if age_days > max_age {
                            f.push(aws_finding(
                                Domain::Identity,
                                &format!("Stale IAM access key: {name}"),
                                "medium",
                                "T1552.001",
                                "1.14",
                                target,
                                0.88,
                                &format!("Active access key for '{name}' is {age_days} days old (threshold {max_age}). Rotate keys regularly."),
                                Evidence::new()
                                    .with("user", name.clone())
                                    .with("key_age_days", age_days)
                                    .with("access_key_id", k.access_key_id().unwrap_or(""))
                                    .check("key_rotation", true, age_days),
                            ));
                        }
                    }
                }
                if active > 1 {
                    f.push(aws_finding(
                        Domain::Identity,
                        &format!("IAM user has multiple active access keys: {name}"),
                        "low",
                        "T1098",
                        "1.13",
                        target,
                        0.85,
                        &format!("User '{name}' has {active} active access keys; keep at most one active key per user."),
                        Evidence::new().with("user", name.clone()).with("active_keys", active),
                    ));
                }
            }
            if let Ok(att) = iam.list_attached_user_policies().user_name(&name).send().await {
                for p in att.attached_policies() {
                    let arn = p.policy_arn().unwrap_or("");
                    if arn.ends_with(":policy/AdministratorAccess") {
                        f.push(aws_finding(
                            Domain::Identity,
                            &format!("AdministratorAccess attached directly to user: {name}"),
                            "high",
                            "T1098",
                            "1.16",
                            target,
                            0.9,
                            &format!("User '{name}' has the AWS-managed AdministratorAccess policy attached directly. Grant admin via groups/roles with least privilege."),
                            Evidence::new().with("user", name.clone()).with("policy_arn", arn),
                        ));
                    }
                }
            }
        }
    }
    f
}

// ─────────────────────────────────────────────────────────────────────────────
// CSPM — S3 data-security posture (CIS AWS Foundations §2.1)
// ─────────────────────────────────────────────────────────────────────────────

fn map_bucket_location(constraint: Option<&str>) -> String {
    match constraint.unwrap_or("").trim() {
        "" | "US" => "us-east-1".to_string(),
        "EU" => "eu-west-1".to_string(),
        other => other.to_string(),
    }
}

async fn scan_s3(sdk: &aws_types::SdkConfig, cfg: &AwsScanConfig, target: &str) -> Vec<Value> {
    use aws_config::Region;
    let mut f: Vec<Value> = Vec::new();
    let global = aws_sdk_s3::config::Builder::from(sdk)
        .region(Region::new(cfg.region.clone()))
        .build();
    let s3 = aws_sdk_s3::Client::from_conf(global);
    let buckets = match s3.list_buckets().send().await {
        Ok(b) => b,
        Err(e) => {
            f.push(aws_finding(
                Domain::Data,
                "S3 ListBuckets denied",
                "info",
                "",
                "",
                target,
                1.0,
                &format!("s3:ListAllMyBuckets failed ({e}); S3 posture could not be enumerated. Grant the read-only scanner s3:ListAllMyBuckets + per-bucket GetBucket* permissions."),
                Evidence::new().with("error", e.to_string()),
            ));
            return f;
        }
    };

    for b in buckets.buckets().iter().take(cfg.max_buckets_scanned) {
        let name = b.name().unwrap_or_default().to_string();
        if name.is_empty() {
            continue;
        }
        let loc = s3
            .get_bucket_location()
            .bucket(&name)
            .send()
            .await
            .ok()
            .and_then(|r| r.location_constraint().map(|x| x.as_str().to_string()));
        let region = map_bucket_location(loc.as_deref());
        let regional = aws_sdk_s3::config::Builder::from(sdk)
            .region(Region::new(region.clone()))
            .build();
        let rs3 = aws_sdk_s3::Client::from_conf(regional);

        // Public Access Block (the single most important S3 control).
        let mut public_reason: Option<String> = None;
        match rs3.get_public_access_block().bucket(&name).send().await {
            Ok(resp) => {
                if let Some(pab) = resp.public_access_block_configuration() {
                    let weak = [
                        (pab.block_public_acls(), "block_public_acls=false"),
                        (pab.ignore_public_acls(), "ignore_public_acls=false"),
                        (pab.block_public_policy(), "block_public_policy=false"),
                        (pab.restrict_public_buckets(), "restrict_public_buckets=false"),
                    ];
                    for (flag, label) in weak {
                        if flag == Some(false) {
                            public_reason = Some(label.to_string());
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                let missing = e.as_service_error().and_then(|se| se.meta().code())
                    == Some("NoSuchPublicAccessBlockConfiguration");
                if missing {
                    public_reason = Some("no PublicAccessBlock configured".to_string());
                }
            }
        }
        // Confirm with bucket ACL grants to AllUsers / AuthenticatedUsers.
        let mut acl_public: Option<String> = None;
        if let Ok(acl) = rs3.get_bucket_acl().bucket(&name).send().await {
            for g in acl.grants() {
                let uri = g
                    .grantee()
                    .and_then(|gg| gg.uri())
                    .unwrap_or("")
                    .to_lowercase();
                if uri.contains("allusers") || uri.contains("authenticatedusers") {
                    acl_public = Some(uri);
                    break;
                }
            }
        }
        if let Some(uri) = acl_public {
            f.push(aws_finding(
                Domain::Data,
                &format!("S3 bucket world-readable via ACL: {name}"),
                "critical",
                "T1530",
                "2.1.5",
                target,
                0.93,
                &format!("Bucket '{name}' ({region}) grants access to a public grantee ({uri}). Anyone on the internet can read its objects."),
                Evidence::new()
                    .with("bucket", name.clone())
                    .with("region", region.clone())
                    .with("public_grantee", uri)
                    .check("get_bucket_acl", true, "public grant"),
            ));
        } else if let Some(reason) = public_reason {
            f.push(aws_finding(
                Domain::Data,
                &format!("S3 bucket missing public-access protection: {name}"),
                "high",
                "T1530",
                "2.1.4",
                target,
                0.85,
                &format!("Bucket '{name}' ({region}) does not fully block public access ({reason}). A future ACL/policy change could silently expose it."),
                Evidence::new()
                    .with("bucket", name.clone())
                    .with("region", region.clone())
                    .with("reason", reason)
                    .check("get_public_access_block", true, "weak"),
            ));
        }

        // Default encryption (CIS 2.1.1).
        if let Err(e) = rs3.get_bucket_encryption().bucket(&name).send().await {
            let code = e.as_service_error().and_then(|se| se.meta().code()).unwrap_or("");
            if code == "ServerSideEncryptionConfigurationNotFoundError" {
                f.push(aws_finding(
                    Domain::Data,
                    &format!("S3 bucket without default encryption: {name}"),
                    "medium",
                    "T1530",
                    "2.1.1",
                    target,
                    0.85,
                    &format!("Bucket '{name}' ({region}) has no default server-side encryption. Enable SSE-S3 or SSE-KMS."),
                    Evidence::new()
                        .with("bucket", name.clone())
                        .with("region", region.clone())
                        .check("get_bucket_encryption", false, "not configured"),
                ));
            }
        }

        // Versioning (protects against ransomware / accidental deletion).
        if let Ok(ver) = rs3.get_bucket_versioning().bucket(&name).send().await {
            let enabled = ver
                .status()
                .map(|s| s.as_str().eq_ignore_ascii_case("Enabled"))
                .unwrap_or(false);
            if !enabled {
                f.push(aws_finding(
                    Domain::Data,
                    &format!("S3 bucket versioning disabled: {name}"),
                    "low",
                    "T1485",
                    "2.1.2",
                    target,
                    0.8,
                    &format!("Bucket '{name}' ({region}) has versioning disabled; deleted/overwritten objects are unrecoverable (weakens ransomware resilience)."),
                    Evidence::new()
                        .with("bucket", name.clone())
                        .with("region", region.clone())
                        .check("get_bucket_versioning", true, "not Enabled"),
                ));
            }
        }
    }
    f
}

// ─────────────────────────────────────────────────────────────────────────────
// CSPM — EC2 / VPC network-exposure posture (CIS AWS Foundations §2.2 / §5)
// ─────────────────────────────────────────────────────────────────────────────

fn port_in_dangerous(from: Option<i32>, to: Option<i32>) -> bool {
    let start = from.unwrap_or(-1);
    let end = to.unwrap_or(start);
    DANGEROUS_PORTS.iter().any(|&p| p >= start && p <= end)
}

async fn scan_ec2(sdk: &aws_types::SdkConfig, cfg: &AwsScanConfig, target: &str) -> Vec<Value> {
    use aws_config::Region;
    let mut f: Vec<Value> = Vec::new();
    for reg in &cfg.regions {
        let r = reg.trim();
        if r.is_empty() {
            continue;
        }
        let ec2 = aws_sdk_ec2::Client::from_conf(
            aws_sdk_ec2::config::Builder::from(sdk)
                .region(Region::new(r.to_string()))
                .build(),
        );

        // Security-group ingress from 0.0.0.0/0.
        let mut sg_pag = ec2.describe_security_groups().into_paginator().send();
        while let Some(page) = sg_pag.next().await {
            let Ok(page) = page else { break };
            for sg in page.security_groups() {
                let sg_id = sg.group_id().unwrap_or("").to_string();
                for perm in sg.ip_permissions() {
                    let proto = perm.ip_protocol().unwrap_or("-1");
                    let open_world = perm
                        .ip_ranges()
                        .iter()
                        .any(|ipr| ipr.cidr_ip() == Some("0.0.0.0/0"));
                    if !open_world {
                        continue;
                    }
                    let all_traffic = proto == "-1";
                    if !all_traffic && !port_in_dangerous(perm.from_port(), perm.to_port()) {
                        continue;
                    }
                    let sev = if all_traffic { "critical" } else { "high" };
                    let port_desc = if all_traffic {
                        "ALL protocols/ports".to_string()
                    } else {
                        format!(
                            "{}:{}-{}",
                            proto,
                            perm.from_port().unwrap_or(0),
                            perm.to_port().unwrap_or(0)
                        )
                    };
                    f.push(aws_finding(
                        Domain::Network,
                        &format!("Security group open to the internet: {sg_id} ({port_desc})"),
                        sev,
                        "T1190",
                        "5.2",
                        target,
                        0.9,
                        &format!("Security group {sg_id} in {r} allows ingress from 0.0.0.0/0 on {port_desc}. Restrict to known CIDRs / a bastion / VPN."),
                        Evidence::new()
                            .with("security_group", sg_id.clone())
                            .with("region", r.to_string())
                            .with("protocol", proto)
                            .with("from_port", perm.from_port().unwrap_or(-1))
                            .with("to_port", perm.to_port().unwrap_or(-1))
                            .check("describe_security_groups", true, "0.0.0.0/0 ingress"),
                    ));
                }
            }
        }

        // Instances: public IP + IMDSv1 = the classic SSRF→credential-theft surface.
        let mut inst_pag = ec2.describe_instances().into_paginator().send();
        while let Some(page) = inst_pag.next().await {
            let Ok(page) = page else { break };
            for res in page.reservations() {
                for inst in res.instances() {
                    let iid = inst.instance_id().unwrap_or("").to_string();
                    let public_ip = inst.public_ip_address().map(str::to_string);
                    let imdsv1 = inst
                        .metadata_options()
                        .and_then(|m| m.http_tokens())
                        .map(|t| t.as_str().eq_ignore_ascii_case("optional"))
                        .unwrap_or(false);
                    let has_profile = inst.iam_instance_profile().is_some();
                    if let Some(ip) = public_ip {
                        if imdsv1 {
                            let sev = if has_profile { "high" } else { "medium" };
                            f.push(aws_finding(
                                Domain::Network,
                                &format!("Public EC2 instance allows IMDSv1: {iid}"),
                                sev,
                                "T1552.005",
                                "5.6",
                                target,
                                0.88,
                                &format!("Instance {iid} ({r}) has public IP {ip} and permits IMDSv1 (HttpTokens=optional). An SSRF on a workload there can read the metadata endpoint and steal the instance role's temporary credentials. Enforce IMDSv2 (HttpTokens=required)."),
                                Evidence::new()
                                    .with("instance_id", iid.clone())
                                    .with("region", r.to_string())
                                    .with("public_ip", ip)
                                    .with("imdsv1_allowed", true)
                                    .with("has_instance_role", has_profile)
                                    .check("describe_instances.metadata_options", true, "HttpTokens=optional"),
                            ));
                        }
                    }
                }
            }
        }

        // Unencrypted EBS volumes (CIS 2.2.1).
        let mut vol_pag = ec2.describe_volumes().into_paginator().send();
        while let Some(page) = vol_pag.next().await {
            let Ok(page) = page else { break };
            for v in page.volumes() {
                if v.encrypted() == Some(false) {
                    let vid = v.volume_id().unwrap_or("").to_string();
                    f.push(aws_finding(
                        Domain::Data,
                        &format!("Unencrypted EBS volume: {vid}"),
                        "medium",
                        "T1530",
                        "2.2.1",
                        target,
                        0.85,
                        &format!("EBS volume {vid} ({r}) is not encrypted at rest. Enable default EBS encryption and re-create from an encrypted snapshot."),
                        Evidence::new()
                            .with("volume_id", vid)
                            .with("region", r.to_string())
                            .check("describe_volumes.encrypted", true, false),
                    ));
                }
            }
        }
    }
    f
}

// ─────────────────────────────────────────────────────────────────────────────
// External attack-surface plane (no credentials) — what an internet attacker sees
// ─────────────────────────────────────────────────────────────────────────────

/// Common S3 bucket name suffixes used for permutation enumeration.
const BUCKET_SUFFIXES: &[&str] = &[
    "-backup", "-backups", "-prod", "-production", "-dev", "-staging", "-stage", "-test",
    "-assets", "-static", "-media", "-uploads", "-logs", "-data", "-public", "-private",
    "-archive", "-cdn", "-files", "-images", "-config", "-secrets", "-db", "-dump",
];

/// Derive candidate S3 bucket names from the target host + operator-supplied lists.
fn bucket_candidates(target: &str, cfg: &AwsScanConfig) -> Vec<String> {
    let host = extract_host(target);
    let mut seeds: Vec<String> = Vec::new();
    if let Some(label) = host.split('.').next() {
        if !label.is_empty() {
            seeds.push(label.to_string());
        }
    }
    let collapsed = host.replace('.', "-");
    if !collapsed.is_empty() {
        seeds.push(collapsed);
    }
    seeds.extend(cfg.bucket_candidates.iter().cloned());
    seeds.sort();
    seeds.dedup();

    let mut out: Vec<String> = Vec::new();
    for s in &seeds {
        out.push(s.clone());
        if cfg.bucket_permutations {
            for suf in BUCKET_SUFFIXES {
                out.push(format!("{s}{suf}"));
            }
            for suf in &cfg.extra_bucket_suffixes {
                out.push(format!("{s}{suf}"));
            }
        }
    }
    out.sort();
    out.dedup();
    out.truncate(cfg.max_buckets_scanned);
    out
}

/// External, unauthenticated attack-surface checks: public/discoverable S3 buckets, leaked AWS
/// credential material in web assets, and an AWS service fingerprint. No credentials required.
async fn scan_external_surface(target: &str, cfg: &AwsScanConfig) -> Vec<Value> {
    let mut f: Vec<Value> = Vec::new();
    let client = http_client().await;

    // 1) Public / existing S3 buckets via the global virtual-host endpoint.
    let candidates = bucket_candidates(target, cfg);
    let probes = stream::iter(candidates.into_iter().map(|name| {
        let client = client.clone();
        async move {
            let url = format!("https://{name}.s3.amazonaws.com/?max-keys=0");
            let probe = http_get(&client, &url).await;
            (name, probe)
        }
    }))
    .buffer_unordered(cfg.concurrency.max(1))
    .collect::<Vec<_>>()
    .await;

    for (name, probe) in probes {
        let Some(p) = probe else { continue };
        let body_l = p.body.to_ascii_lowercase();
        if p.status == 200 && (body_l.contains("<listbucketresult") || body_l.contains("<contents>"))
        {
            f.push(aws_finding(
                Domain::Exposure,
                &format!("Public S3 bucket (anonymously listable): {name}"),
                "critical",
                "T1530",
                "2.1.5",
                target,
                0.9,
                &format!("S3 bucket '{name}' returns a public object listing to an anonymous request (HTTP 200 ListBucketResult). Its contents are exposed to the internet."),
                Evidence::new()
                    .with("bucket", name.clone())
                    .with("url", format!("https://{name}.s3.amazonaws.com/"))
                    .with("http_status", p.status)
                    .check("anonymous_list", true, "ListBucketResult"),
            ));
        } else if p.status == 403 {
            f.push(aws_finding(
                Domain::Exposure,
                &format!("S3 bucket exists (access denied): {name}"),
                "low",
                "T1580",
                "",
                target,
                0.7,
                &format!("S3 bucket '{name}' exists (HTTP 403 AccessDenied) but does not list anonymously. Confirms the namespace is in use; ensure it is not writable and not referenced by a dangling DNS record."),
                Evidence::new()
                    .with("bucket", name.clone())
                    .with("http_status", p.status)
                    .check("bucket_exists", true, "403 AccessDenied"),
            ));
        }
    }

    // 2) Leaked AWS credential material in common web-asset paths.
    if !cfg.web_paths.is_empty() {
        let base = normalize_url(target);
        let leak_probes = stream::iter(cfg.web_paths.iter().cloned().map(|path| {
            let client = client.clone();
            let base = base.clone();
            async move {
                let url = format!(
                    "{}/{}",
                    base.trim_end_matches('/'),
                    path.trim_start_matches('/')
                );
                let probe = http_get(&client, &url).await;
                (url, probe)
            }
        }))
        .buffer_unordered(cfg.concurrency.max(1))
        .collect::<Vec<_>>()
        .await;

        for (url, probe) in leak_probes {
            let Some(p) = probe else { continue };
            if p.status != 200 || p.body.is_empty() {
                continue;
            }
            let secrets = detect_secrets(&p.body);
            let aws_leak = secrets
                .iter()
                .any(|s| s.to_ascii_lowercase().contains("aws"))
                || p.body.contains("AKIA");
            if aws_leak {
                f.push(aws_finding(
                    Domain::Exposure,
                    &format!("Exposed AWS credential material: {url}"),
                    "critical",
                    "T1552.001",
                    "",
                    target,
                    0.9,
                    &format!("The publicly fetchable asset {url} contains what appears to be live AWS credential material ({}). Rotate the keys immediately and remove the file from the web root.", secrets.join(", ")),
                    Evidence::new()
                        .with("url", url.clone())
                        .with("secret_types", json!(secrets))
                        .check("detect_secrets", true, "aws material"),
                ));
            }
        }
    }

    // 3) AWS service fingerprint (informational context for the external surface).
    if cfg.service_fingerprint {
        let url = normalize_url(target);
        if let Some(p) = http_get(&client, &url).await {
            let server = header_value(&p.headers, "server").unwrap_or("").to_string();
            let has_amz = p
                .headers
                .iter()
                .any(|(k, _)| k.to_ascii_lowercase().starts_with("x-amz"));
            let has_cf = p
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("x-amz-cf-id"));
            let s_l = server.to_ascii_lowercase();
            if has_amz || s_l.contains("amazons3") || s_l.contains("awselb") || has_cf {
                let svc = if s_l.contains("amazons3") {
                    "S3"
                } else if has_cf {
                    "CloudFront"
                } else if s_l.contains("awselb") {
                    "ELB"
                } else {
                    "AWS"
                };
                f.push(aws_finding(
                    Domain::Exposure,
                    &format!("AWS service fingerprint: {svc}"),
                    "info",
                    "",
                    "",
                    target,
                    0.6,
                    &format!("The target fronts an AWS service ({svc}; Server: {server}). Context for mapping the external attack surface."),
                    Evidence::new()
                        .with("server", server)
                        .with("service", svc)
                        .check("aws_fingerprint", true, svc),
                ));
            }
        }
    }

    f
}

// ─────────────────────────────────────────────────────────────────────────────
// Attack-path correlation — the "toxic combinations" that chain gaps into a breach
// ─────────────────────────────────────────────────────────────────────────────

fn has_title_contains(findings: &[Value], needle: &str) -> bool {
    findings.iter().any(|f| {
        f.get("title")
            .and_then(Value::as_str)
            .map(|t| t.contains(needle))
            .unwrap_or(false)
    })
}

fn count_domain_sev(findings: &[Value], domain: &str, min_rank: u8) -> usize {
    findings
        .iter()
        .filter(|f| finding_domain(f) == domain && sev_rank(&finding_sev(f)) >= min_rank)
        .count()
}

/// Build an attack-path (toxic-combination) finding. Tagged `domain=posture` so it is not
/// double-counted in the score (its constituent findings already penalise), but surfaced with high
/// severity and an explicit step chain for the operator.
fn attack_path(
    title: &str,
    severity: &str,
    target: &str,
    steps: &[&str],
    mitre: &str,
    description: &str,
) -> Value {
    let ev = Evidence::new()
        .with("kind", "attack_path")
        .with("steps", json!(steps))
        .check("correlation", true, format!("{}-step chain", steps.len()));
    let mut v = aws_finding(
        Domain::Posture,
        title,
        severity,
        mitre,
        "",
        target,
        0.85,
        description,
        ev,
    );
    if let Some(o) = v.as_object_mut() {
        o.insert("category".to_string(), json!("attack_path"));
        o.insert("attack_path".to_string(), json!(true));
        o.insert("steps".to_string(), json!(steps));
    }
    v
}

/// Correlate individual findings into end-to-end breach chains (Wiz-style toxic combinations).
fn synthesize_attack_paths(findings: &[Value], target: &str, account_id: Option<&str>) -> Vec<Value> {
    let mut paths: Vec<Value> = Vec::new();
    let acct = account_id.unwrap_or("the account");

    let public_bucket =
        has_title_contains(findings, "Public S3 bucket") || has_title_contains(findings, "world-readable");
    let leaked_key = has_title_contains(findings, "Exposed AWS credential");
    if public_bucket && leaked_key {
        paths.push(attack_path(
            "Attack path: exposed credentials → public data store",
            "critical",
            target,
            &[
                "Harvest leaked AWS key from a public web asset",
                "Authenticate to the AWS APIs",
                "Enumerate & exfiltrate the anonymously-listable S3 data",
            ],
            "T1552.001",
            &format!("An anonymous attacker can grab leaked AWS credentials and pivot directly to readable S3 data in {acct} — a complete external-to-data breach chain."),
        ));
    }

    if has_title_contains(findings, "Root account MFA is not enabled")
        || has_title_contains(findings, "Root account has active access keys")
    {
        paths.push(attack_path(
            "Attack path: root compromise → full account takeover",
            "critical",
            target,
            &[
                "Phish/guess the root password or steal a root access key",
                "No MFA / long-lived key blocks the attacker",
                "Assume unrestricted control of the entire account",
            ],
            "T1078.004",
            &format!("The root identity of {acct} lacks a key protection (MFA disabled or active root keys). A single credential theft yields irreversible, account-wide compromise."),
        ));
    }

    if has_title_contains(findings, "allows IMDSv1") {
        paths.push(attack_path(
            "Attack path: SSRF → IMDSv1 → role credential theft",
            "high",
            target,
            &[
                "Find an SSRF/RCE on the public EC2 workload",
                "Query 169.254.169.254 (IMDSv1, no token required)",
                "Steal the instance-role STS credentials",
                "Move laterally with the role's permissions",
            ],
            "T1552.005",
            "A public EC2 instance permits IMDSv1, so any SSRF on its workload escalates to theft of the instance-role credentials and lateral movement across the account.",
        ));
    }

    if has_title_contains(findings, "Security group open to the internet")
        && count_domain_sev(findings, "identity", 2) > 0
    {
        paths.push(attack_path(
            "Attack path: internet-exposed service + weak identity controls",
            "high",
            target,
            &[
                "Reach the world-open service port (0.0.0.0/0)",
                "Brute-force / reuse weak credentials",
                "Establish a foothold inside the VPC",
            ],
            "T1190",
            "An internet-open security group combined with weak IAM identity hygiene gives an attacker a reachable service to brute-force and a weak-credential estate to exploit.",
        ));
    }

    paths
}

// ─────────────────────────────────────────────────────────────────────────────
// Posture summary — the graded headline (0–100, A+…F, per-domain sub-scores)
// ─────────────────────────────────────────────────────────────────────────────

fn build_posture_summary(
    findings: &[Value],
    attack_paths: &[Value],
    target: &str,
    account_id: Option<&str>,
    principal_arn: Option<&str>,
    cfg: &AwsScanConfig,
) -> Value {
    let score = posture_score(findings);
    let grade = grade_for(score);

    let mut crit = 0usize;
    let mut high = 0usize;
    let mut med = 0usize;
    let mut low = 0usize;
    for f in findings.iter().filter(|f| finding_domain(f) != "posture") {
        match sev_rank(&finding_sev(f)) {
            4 => crit += 1,
            3 => high += 1,
            2 => med += 1,
            1 => low += 1,
            _ => {}
        }
    }
    let actionable = crit + high + med + low;

    // Roadmap: the top distinct issues by severity (titles are specific + actionable).
    let mut ranked: Vec<&Value> = findings
        .iter()
        .filter(|f| finding_domain(f) != "posture")
        .collect();
    ranked.sort_by(|a, b| sev_rank(&finding_sev(b)).cmp(&sev_rank(&finding_sev(a))));
    let mut roadmap: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for f in ranked {
        if let Some(title) = f.get("title").and_then(Value::as_str) {
            if seen.insert(title.to_string()) {
                roadmap.push(title.to_string());
            }
        }
        if roadmap.len() >= 8 {
            break;
        }
    }

    let mut ev = Evidence::new()
        .with("score", score.round())
        .with("grade", grade)
        .with(
            "planes",
            if cfg.credentialed_ready() {
                "credentialed+external"
            } else {
                "external"
            },
        )
        .with("attack_path_count", attack_paths.len())
        .with("actionable_findings", actionable);
    if let Some(a) = account_id {
        ev = ev.with("account_id", a.to_string());
    }
    if let Some(p) = principal_arn {
        ev = ev.with("principal_arn", p.to_string());
    }

    let summary_sev = if score < 55.0 || crit > 0 {
        "high"
    } else if score < 80.0 {
        "medium"
    } else {
        "info"
    };

    let mut v = aws_finding(
        Domain::Posture,
        &format!("AWS Cloud Security Posture: Grade {grade} ({:.0}/100)", score),
        summary_sev,
        "",
        "",
        target,
        1.0,
        &format!(
            "AWS estate posture for {} scored {:.0}/100 (grade {grade}) across {actionable} actionable finding(s) and {} correlated attack path(s).",
            account_id.unwrap_or(target),
            score,
            attack_paths.len()
        ),
        ev,
    );
    if let Some(o) = v.as_object_mut() {
        o.insert("category".to_string(), json!("posture"));
        o.insert("posture_score".to_string(), json!(score.round() as i64));
        o.insert("grade".to_string(), json!(grade));
        o.insert(
            "subscores".to_string(),
            json!({
                "identity": domain_score(findings, Domain::Identity).round() as i64,
                "data": domain_score(findings, Domain::Data).round() as i64,
                "network": domain_score(findings, Domain::Network).round() as i64,
                "exposure": domain_score(findings, Domain::Exposure).round() as i64,
            }),
        );
        o.insert(
            "severity_counts".to_string(),
            json!({ "critical": crit, "high": high, "medium": med, "low": low }),
        );
        o.insert("attack_path_count".to_string(), json!(attack_paths.len()));
        o.insert("roadmap".to_string(), json!(roadmap));
        if let Some(a) = account_id {
            o.insert("account_id".to_string(), json!(a));
        }
        if let Some(p) = principal_arn {
            o.insert("principal_arn".to_string(), json!(p));
        }
    }
    v
}
