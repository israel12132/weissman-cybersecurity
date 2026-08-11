//! GCP Cloud Security Posture Engine — a CNAPP-grade, evidence-bearing assessment of a Google
//! Cloud estate. Built to match (and exceed) best-in-class cloud security platforms (Wiz, Orca,
//! Prowler, Google SCC) on *transparency* and *operator control*: every check is a real probe (a
//! signed Google REST API call, or a live unauthenticated HTTP request), every finding carries its
//! full evidence trail, and every knob is exposed in the scan request body so an operator can tune
//! the entire assessment without a code change.
//!
//! Two complementary collection planes, fused into one posture:
//!   1. **Agentless credentialed plane** (a read-only OAuth2 access token *or* a service-account
//!      JSON key, exchanged for a read-only `cloud-platform.read-only` token) — true CSPM / CIEM /
//!      CWPP / DSPM:
//!        - **CIEM**: project IAM-policy analysis, public (`allUsers` / `allAuthenticatedUsers`)
//!          bindings, primitive-role sprawl, and the full GCP privilege-escalation primitive set
//!          (service-account impersonation / `actAs`, key creation, `setIamPolicy`, deployment /
//!          build / function / run / compute `actAs` chains).
//!        - **CWPP**: Compute Engine instances (public IP, default SA + `cloud-platform` scope, OS
//!          Login, Shielded VM, serial-port, IP-forwarding, legacy metadata) and VPC firewalls
//!          (0.0.0.0/0 ingress on sensitive ports).
//!        - **DSPM**: Cloud Storage (public IAM, uniform bucket-level access, public-access
//!          prevention, versioning), BigQuery dataset exposure, Cloud SQL exposure.
//!        - **GKE**: legacy ABAC, basic-auth / client-cert master auth, public endpoint, master
//!          authorized networks, network policy, Workload Identity, Shielded GKE nodes, legacy
//!          metadata endpoints, release channel.
//!        - **Network/DNS**: Cloud DNS DNSSEC, Cloud Functions / Cloud Run public invokers.
//!   2. **External attack-surface plane** (no credentials) — what an internet attacker sees: the
//!      GCE metadata SSRF surface, public / dangling GCS buckets, leaked service-account keys and
//!      GCP API keys in web assets, and Firebase exposure.
//!
//! Findings are scored into a 0–100 posture index with a letter grade and per-domain sub-scores,
//! mapped to the **CIS Google Cloud Foundations Benchmark v2.0** and **MITRE ATT&CK (Cloud / IaaS)**,
//! and correlated into **attack paths** (the "toxic combinations" that turn individual gaps into a
//! real breach chain). No finding is fabricated: a control is only reported when a real probe
//! observed the real signal.

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{detect_secrets, extract_host, http_client, http_get};
use crate::engine_result::{print_result, EngineResult};
use futures::stream::{self, StreamExt};
use serde::Serialize;
use serde_json::{json, Value};
use std::time::Duration;

const ENGINE_ID: &str = "gcp_attack";

/// Read-only OAuth2 scope — the scanner never needs write access. A service-account key is exchanged
/// for a token restricted to this scope so a leaked scan token cannot mutate the estate.
const GCP_READONLY_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform.read-only";
const GCE_CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

// ─────────────────────────────────────────────────────────────────────────────
// Configuration — every knob is read from the live scan request body
// (`POST /api/command-center/scan` → EngineRunContext::job_params).
// ─────────────────────────────────────────────────────────────────────────────

/// Fully-parsed, validated scan configuration. All fields fall back to safe defaults so the engine
/// behaves correctly on an empty body, yet an operator can override every dimension of the scan.
#[derive(Clone, Debug)]
pub struct GcpScanConfig {
    // Collection planes
    pub enable_external: bool,
    pub enable_credentialed: bool,
    // Credentialed check toggles
    pub check_iam: bool,
    pub check_sa_keys: bool,
    pub check_compute: bool,
    pub check_firewall: bool,
    pub check_storage: bool,
    pub check_gke: bool,
    pub check_sql: bool,
    pub check_bigquery: bool,
    pub check_functions: bool,
    pub check_run: bool,
    pub check_dns: bool,
    pub enable_attack_paths: bool,
    pub enable_privesc: bool,
    // Credentials (credentialed plane)
    pub access_token: Option<String>,
    pub service_account_key: Option<Value>,
    pub project_ids: Vec<String>,
    // External plane
    pub bucket_candidates: Vec<String>,
    pub bucket_permutations: bool,
    pub extra_bucket_suffixes: Vec<String>,
    pub web_paths: Vec<String>,
    pub check_metadata: bool,
    // Thresholds / limits
    pub sa_key_max_age_days: i64,
    pub max_projects: usize,
    pub max_resources: usize,
    pub max_buckets: usize,
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub intensity: Intensity,
    pub min_severity: String,
    pub min_confidence: f64,
    pub include_posture_summary: bool,
}

impl GcpScanConfig {
    fn from_arsenal(c: &ArsenalConfig) -> Self {
        let intensity = c.intensity();
        let default_max_buckets = match intensity {
            Intensity::Light => 30,
            Intensity::Normal => 70,
            Intensity::Aggressive => 200,
        };
        let default_max_resources = match intensity {
            Intensity::Light => 50,
            Intensity::Normal => 150,
            Intensity::Aggressive => 600,
        };
        // Accept the service-account key as a JSON object or a JSON string (the UI sends a pasted
        // blob). Either way we end up with a parsed object, or None.
        let service_account_key = c
            .raw()
            .get("gcp_service_account_key")
            .or_else(|| c.raw().get("service_account_key"))
            .and_then(|v| match v {
                Value::Object(_) => Some(v.clone()),
                Value::String(s) if !s.trim().is_empty() => serde_json::from_str::<Value>(s).ok(),
                _ => None,
            });
        Self {
            enable_external: c.bool_or("enable_external", true),
            enable_credentialed: c.bool_or("enable_credentialed", true),
            check_iam: c.bool_or("check_iam", true),
            check_sa_keys: c.bool_or("check_sa_keys", true),
            check_compute: c.bool_or("check_compute", true),
            check_firewall: c.bool_or("check_firewall", true),
            check_storage: c.bool_or("check_storage", true),
            check_gke: c.bool_or("check_gke", true),
            check_sql: c.bool_or("check_sql", true),
            check_bigquery: c.bool_or("check_bigquery", true),
            check_functions: c.bool_or("check_functions", true),
            check_run: c.bool_or("check_run", true),
            check_dns: c.bool_or("check_dns", true),
            enable_attack_paths: c.bool_or("synthesize_attack_paths", true),
            enable_privesc: c.bool_or("enable_privesc", true),
            access_token: c
                .string("gcp_access_token")
                .or_else(|| c.string("access_token")),
            service_account_key,
            project_ids: {
                let mut p = c.string_list("gcp_project_ids");
                if let Some(single) = c.string("gcp_project_id") {
                    if !p.contains(&single) {
                        p.push(single);
                    }
                }
                p
            },
            bucket_candidates: c.string_list("bucket_candidates"),
            bucket_permutations: c.bool_or("bucket_permutations", true),
            extra_bucket_suffixes: c.string_list("extra_bucket_suffixes"),
            web_paths: c.string_list_or("web_paths", GCP_WEB_PATHS),
            check_metadata: c.bool_or("check_metadata", true),
            sa_key_max_age_days: i64::try_from(c.u64_or("sa_key_max_age_days", 90).clamp(1, 3650))
                .unwrap_or(90),
            max_projects: c.usize_or("max_projects", 25).clamp(1, 200),
            max_resources: c
                .usize_or("max_resources", default_max_resources)
                .clamp(1, 5000),
            max_buckets: c
                .usize_or("max_buckets", default_max_buckets)
                .clamp(1, 2000),
            timeout_ms: c.timeout_ms(12_000),
            concurrency: c.concurrency(),
            intensity,
            min_severity: c.string_or("min_severity", "info"),
            min_confidence: {
                let v = c.raw();
                v.get("min_confidence")
                    .and_then(|x| {
                        x.as_f64()
                            .or_else(|| x.as_str().and_then(|s| s.parse().ok()))
                    })
                    .unwrap_or(0.0)
                    .clamp(0.0, 1.0)
            },
            include_posture_summary: c.bool_or("include_posture_summary", true),
        }
    }

    /// True when the operator supplied any credential for the credentialed plane.
    fn credentialed_ready(&self) -> bool {
        self.enable_credentialed
            && (self.access_token.as_ref().is_some_and(|t| !t.is_empty())
                || self.service_account_key.is_some())
    }
}

/// Web paths that frequently leak GCP credential material (SA keys, gcloud configs, env dumps).
const GCP_WEB_PATHS: &[&str] = &[
    "/.gcp/credentials.json",
    "/gcp.json",
    "/service-account.json",
    "/service_account.json",
    "/google-credentials.json",
    "/credentials.json",
    "/gcloud.json",
    "/sa-key.json",
    "/key.json",
    "/firebase.json",
    "/google-services.json",
    "/.config/gcloud/credentials.db",
    "/.config/gcloud/application_default_credentials.json",
    "/app.yaml",
    "/.env",
    "/static/firebase-config.js",
    "/assets/config.js",
    "/__/firebase/init.json",
];

/// Indicators that a fetched body is a real GCP service-account key.
const SA_KEY_INDICATORS: &[&str] = &[
    "\"type\": \"service_account\"",
    "\"type\":\"service_account\"",
    "private_key_id",
    "client_email",
    "-----BEGIN PRIVATE KEY-----",
    "oauth2.googleapis.com/token",
];

/// Sensitive service ports whose world-open ingress (0.0.0.0/0) is a critical network exposure.
/// `(port, label, cis_control, severity)`.
const DANGEROUS_PORTS: &[(u32, &str, &str, &str)] = &[
    (22, "SSH", "3.6", "high"),
    (3389, "RDP", "3.7", "high"),
    (3306, "MySQL", "3.6", "high"),
    (5432, "PostgreSQL", "3.6", "high"),
    (1433, "MSSQL", "3.6", "high"),
    (27017, "MongoDB", "3.6", "high"),
    (6379, "Redis", "3.6", "high"),
    (9200, "Elasticsearch", "3.6", "high"),
    (2375, "Docker API", "3.6", "critical"),
    (2379, "etcd", "3.6", "critical"),
    (11211, "Memcached", "3.6", "high"),
    (5984, "CouchDB", "3.6", "high"),
    (23, "Telnet", "3.6", "high"),
    (445, "SMB", "3.6", "high"),
    (135, "RPC", "3.6", "medium"),
    (10250, "kubelet", "3.6", "high"),
];

// ─────────────────────────────────────────────────────────────────────────────
// GCP privilege-escalation primitive catalog (CIEM). Each dangerous role, when held by a principal
// an attacker can reach, enables a documented escalation to a higher-privileged identity. Mirrors
// the well-known GCP privilege-escalation research (Rhino Security Labs / GCP-IAM-Privilege-
// Escalation) at the role granularity we can observe from a read-only IAM-policy read.
// `(role, technique, severity)`.
// ─────────────────────────────────────────────────────────────────────────────
const PRIVESC_ROLES: &[(&str, &str, &str)] = &[
    ("roles/owner", "Primitive Owner role — full control of the project including IAM (setIamPolicy). Any holder can grant themselves or others any role.", "critical"),
    ("roles/editor", "Primitive Editor role — broad write access across nearly all services; can create resources (functions, instances, builds) that run as service accounts to pivot.", "high"),
    ("roles/iam.serviceAccountTokenCreator", "Can mint OAuth2 access tokens / sign JWTs for ANY service account it can target (generateAccessToken) — direct impersonation of higher-privileged identities.", "critical"),
    ("roles/iam.serviceAccountUser", "Holds the actAs permission — can attach (run as) service accounts when creating compute/functions/run/dataflow workloads, inheriting that SA's privileges.", "high"),
    ("roles/iam.serviceAccountKeyAdmin", "Can create long-lived user-managed keys for any service account — exfiltratable, persistent credentials for a higher-privileged identity.", "critical"),
    ("roles/iam.serviceAccountAdmin", "Manages service accounts and their IAM policy — can grant itself impersonation rights over privileged SAs.", "high"),
    ("roles/iam.securityAdmin", "Can read and SET IAM policy across the project (setIamPolicy) — direct privilege escalation to any role.", "critical"),
    ("roles/iam.roleAdmin", "Can create/update custom roles and add arbitrary permissions to a role it is granted — privilege escalation by role mutation.", "high"),
    ("roles/resourcemanager.projectIamAdmin", "Can set the project IAM policy — grant any principal any role, including Owner.", "critical"),
    ("roles/iam.workloadIdentityPoolAdmin", "Manages Workload Identity Federation pools — can configure external identities to impersonate service accounts.", "high"),
    ("roles/deploymentmanager.editor", "Deployment Manager runs as the Google APIs service agent (often Editor) — can deploy resources with elevated privileges (actAs bypass).", "high"),
    ("roles/cloudbuild.builds.editor", "Cloud Build runs as the powerful Cloud Build SA — can execute arbitrary build steps to read secrets / mint tokens of that SA.", "high"),
    ("roles/cloudfunctions.admin", "Can deploy Cloud Functions; combined with actAs lets an attacker run code as a privileged runtime service account.", "high"),
    ("roles/cloudfunctions.developer", "Can deploy/update Cloud Functions code that executes as the function's runtime service account.", "high"),
    ("roles/run.admin", "Can deploy Cloud Run services; combined with actAs runs attacker code as a privileged service account.", "high"),
    ("roles/compute.admin", "Full Compute control — can launch instances (with actAs) whose startup scripts read the attached SA's tokens from the metadata server.", "high"),
    ("roles/compute.instanceAdmin.v1", "Can create/modify instances and set their service account / startup scripts — pivot to the instance SA via the metadata server.", "high"),
    ("roles/container.admin", "Full GKE control — can deploy privileged workloads that read node/workload SA tokens.", "high"),
    ("roles/dataflow.developer", "Dataflow jobs run as a service account — can execute code as that SA.", "medium"),
    ("roles/composer.admin", "Cloud Composer (Airflow) DAGs run as a service account — arbitrary code execution as that SA.", "high"),
    ("roles/dataproc.editor", "Dataproc cluster initialization actions run as a service account — code execution as that SA.", "medium"),
    ("roles/serviceusage.serviceUsageAdmin", "Can enable additional APIs, broadening the attack surface available for further escalation.", "medium"),
    ("roles/storage.admin", "Full control of Cloud Storage — can read every object (including SA keys / Terraform state) and make buckets public.", "high"),
    ("roles/secretmanager.admin", "Full control of Secret Manager — can read every stored secret in the project.", "critical"),
    ("roles/secretmanager.secretAccessor", "Can read the payload of secrets — direct access to stored credentials.", "high"),
    ("roles/cloudkms.admin", "Full KMS control — can grant decrypt rights and read protected data.", "high"),
];

// ─────────────────────────────────────────────────────────────────────────────
// Finding domains + scoring (mirrors the AWS engine so cross-cloud posture is comparable).
// ─────────────────────────────────────────────────────────────────────────────

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
    } else if score >= 65.0 {
        "C"
    } else if score >= 55.0 {
        "D"
    } else if score >= 40.0 {
        "E"
    } else {
        "F"
    }
}

fn posture_score(findings: &[Value]) -> f64 {
    let penalty: f64 = findings
        .iter()
        .filter(|f| {
            finding_domain(f) != "posture"
                && !f
                    .get("attack_path")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
        })
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
// GCP REST client (read-only) + auth.
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a single GCP REST call: a parsed body, or a classified failure.
enum GcpErr {
    Network(String),
    /// (status, classified reason, raw body excerpt)
    Http(u16, &'static str, String),
    Parse(String),
}

impl GcpErr {
    fn classify(status: u16, body: &str) -> &'static str {
        let b = body.to_ascii_lowercase();
        if b.contains("service_disabled")
            || b.contains("has not been used")
            || b.contains("it is disabled")
        {
            "api_disabled"
        } else if status == 401 {
            "unauthenticated"
        } else if status == 403 {
            "permission_denied"
        } else if status == 404 {
            "not_found"
        } else {
            "error"
        }
    }
}

struct GcpClient {
    http: reqwest::Client,
    token: String,
}

impl GcpClient {
    async fn get(&self, url: &str) -> Result<Value, GcpErr> {
        let resp = self
            .http
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| GcpErr::Network(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        if status == 200 {
            serde_json::from_str(&body).map_err(|e| GcpErr::Parse(e.to_string()))
        } else {
            let reason = GcpErr::classify(status, &body);
            Err(GcpErr::Http(
                status,
                reason,
                body.chars().take(240).collect(),
            ))
        }
    }

    /// Follow `nextPageToken` across pages, collecting items from `item_field`, up to `max_items`.
    async fn list_all(
        &self,
        base_url: &str,
        item_field: &str,
        max_items: usize,
    ) -> Result<Vec<Value>, GcpErr> {
        let mut out: Vec<Value> = Vec::new();
        let mut page_token: Option<String> = None;
        for _ in 0..25 {
            let url = match &page_token {
                Some(t) => {
                    let sep = if base_url.contains('?') { '&' } else { '?' };
                    format!("{base_url}{sep}pageToken={t}")
                }
                None => base_url.to_string(),
            };
            let v = self.get(&url).await?;
            if let Some(items) = v.get(item_field).and_then(Value::as_array) {
                out.extend(items.iter().cloned());
            }
            if out.len() >= max_items {
                out.truncate(max_items);
                break;
            }
            match v.get("nextPageToken").and_then(Value::as_str) {
                Some(t) if !t.is_empty() => page_token = Some(t.to_string()),
                _ => break,
            }
        }
        Ok(out)
    }
}

#[derive(Serialize)]
struct JwtClaims {
    iss: String,
    scope: String,
    aud: String,
    iat: u64,
    exp: u64,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Exchange a service-account JSON key for a read-only access token (signed RS256 JWT bearer grant).
async fn token_from_sa_key(key: &Value, http: &reqwest::Client) -> Result<String, String> {
    let client_email = key
        .get("client_email")
        .and_then(Value::as_str)
        .ok_or("service-account key missing client_email")?;
    let private_key = key
        .get("private_key")
        .and_then(Value::as_str)
        .ok_or("service-account key missing private_key")?;
    let token_uri = key
        .get("token_uri")
        .and_then(Value::as_str)
        .unwrap_or("https://oauth2.googleapis.com/token");
    let kid = key
        .get("private_key_id")
        .and_then(Value::as_str)
        .unwrap_or("");

    let now = now_secs();
    let claims = JwtClaims {
        iss: client_email.to_string(),
        scope: GCP_READONLY_SCOPE.to_string(),
        aud: token_uri.to_string(),
        iat: now,
        exp: now + 3600,
    };
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    if !kid.is_empty() {
        header.kid = Some(kid.to_string());
    }
    let enc = jsonwebtoken::EncodingKey::from_rsa_pem(private_key.as_bytes())
        .map_err(|e| format!("invalid service-account private_key: {e}"))?;
    let assertion = jsonwebtoken::encode(&header, &claims, &enc)
        .map_err(|e| format!("failed to sign JWT assertion: {e}"))?;

    let resp = http
        .post(token_uri)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &assertion),
        ])
        .send()
        .await
        .map_err(|e| format!("token endpoint request failed: {e}"))?;
    let status = resp.status();
    let body: Value = resp
        .json()
        .await
        .map_err(|e| format!("token endpoint returned non-JSON: {e}"))?;
    if !status.is_success() {
        return Err(format!(
            "token endpoint {} — {}",
            status.as_u16(),
            body.get("error_description")
                .or_else(|| body.get("error"))
                .and_then(Value::as_str)
                .unwrap_or("unknown error")
        ));
    }
    body.get("access_token")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "token endpoint response had no access_token".to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Collector — accumulates findings, the security graph, and toxic-combination signals.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Signals {
    public_instance: bool,
    instance_token_theft: bool, // public instance + broad-scope SA reachable from metadata
    open_admin_port: bool,
    public_bucket: bool,
    leaked_sa_key: bool,
    public_gke_endpoint: bool,
    gke_weak_auth: bool,
    public_sql: bool,
    sql_no_ssl: bool,
    project_public_iam: bool,
    sa_impersonation: bool,
    public_function: bool,
    public_run: bool,
    public_dataset: bool,
}

struct Collector<'a> {
    #[allow(dead_code)] // held for lifetime/config context; not read after refactor
    cfg: &'a GcpScanConfig,
    findings: Vec<Value>,
    nodes: Vec<Value>,
    edges: Vec<Value>,
    sig: Signals,
    /// Project-level `enable-oslogin` (from `commonInstanceMetadata`). Instances inherit it, so
    /// an instance with no per-instance key is only non-compliant when the project is also off.
    project_oslogin: bool,
}

impl<'a> Collector<'a> {
    fn new(cfg: &'a GcpScanConfig) -> Self {
        Self {
            cfg,
            findings: Vec::new(),
            nodes: Vec::new(),
            edges: Vec::new(),
            sig: Signals::default(),
            project_oslogin: false,
        }
    }

    fn add_node(&mut self, id: &str, label: &str, kind: &str, status: &str) {
        if self
            .nodes
            .iter()
            .any(|n| n.get("id").and_then(Value::as_str) == Some(id))
        {
            return;
        }
        self.nodes
            .push(json!({ "id": id, "label": label, "type": kind, "status": status }));
    }

    fn add_edge(&mut self, from: &str, to: &str) {
        self.edges.push(json!({ "from": from, "to": to }));
    }

    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        domain: Domain,
        title: &str,
        severity: &str,
        mitre: &str,
        cis: &str,
        target: &str,
        confidence: f64,
        description: &str,
        evidence: Evidence,
    ) {
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
                obj.insert("cis_gcp".to_string(), json!(cis));
            }
        }
        self.findings.push(f);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry points
// ─────────────────────────────────────────────────────────────────────────────

/// Back-compat thin wrapper (used by `main.rs` and legacy callers): runs the engine with default
/// parameters (external attack-surface plane only, no credentials).
pub async fn run_gcp_attack_result(target: &str) -> EngineResult {
    run_gcp_attack_result_ctx(target, &EngineRunContext::default()).await
}

/// Parameterised entry point used by the dispatch layer. Reads every knob from `ctx.job_params`.
pub async fn run_gcp_attack_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = GcpScanConfig::from_arsenal(&ArsenalConfig::from_ctx(ctx));
    let mut col = Collector::new(&cfg);

    let mut scanned_projects: Vec<String> = Vec::new();
    let mut authed = false;

    // ── Credentialed plane (CSPM / CIEM / DSPM / CWPP) ───────────────────────
    if cfg.credentialed_ready() {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms.max(3_000)))
            .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
            .user_agent("Weissman-GCP-Probe/1.0")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        let token = if let Some(tok) = cfg.access_token.clone().filter(|t| !t.is_empty()) {
            Ok(tok)
        } else if let Some(key) = cfg.service_account_key.clone() {
            token_from_sa_key(&key, &http).await
        } else {
            Err("no credential available".to_string())
        };

        match token {
            Ok(token) => {
                authed = true;
                let client = GcpClient { http, token };
                scanned_projects = resolve_projects(&client, &cfg, &mut col, target).await;
                for project in scanned_projects.iter().take(cfg.max_projects) {
                    scan_project(&client, &cfg, &mut col, project, target).await;
                }
            }
            Err(e) => {
                col.push(
                    Domain::Posture,
                    "Credentialed GCP plane unavailable",
                    "info",
                    "",
                    "",
                    target,
                    1.0,
                    &format!("Could not obtain a GCP access token from the supplied credentials: {e}. The external attack-surface plane still ran. Provide a valid read-only OAuth2 access token (gcloud auth print-access-token) or a read-only service-account JSON key to enable CSPM/CIEM."),
                    Evidence::new().with("phase", "auth").with("error", e),
                );
            }
        }
    }

    // ── External attack-surface plane (no credentials needed) ────────────────
    if cfg.enable_external {
        scan_external_surface(&cfg, &mut col, target).await;
    }

    // ── Attack-path correlation (toxic combinations) ─────────────────────────
    if cfg.enable_attack_paths {
        synthesize_attack_paths(&mut col, target);
    }

    // ── Severity floor + confidence filter ───────────────────────────────────
    let floor = sev_rank(&cfg.min_severity);
    let min_conf = cfg.min_confidence;
    col.findings.retain(|f| {
        if finding_domain(f) == "posture" {
            return true;
        }
        let sev_ok = floor == 0 || sev_rank(&finding_sev(f)) >= floor;
        let conf_ok = f
            .get("confidence")
            .and_then(Value::as_f64)
            .map(|c| c >= min_conf)
            .unwrap_or(true);
        sev_ok && conf_ok
    });

    // ── Posture summary (always emitted first when enabled) ──────────────────
    let mut out: Vec<Value> = Vec::with_capacity(col.findings.len() + 1);
    if cfg.include_posture_summary {
        out.push(build_posture_summary(
            &col,
            target,
            &scanned_projects,
            authed,
        ));
    }
    out.append(&mut col.findings);

    let actionable = out
        .iter()
        .filter(|f| finding_domain(f) != "posture")
        .count();
    EngineResult::ok(
        out,
        format!(
            "GCP Cloud Security Posture: {actionable} finding(s) across {} plane(s) on {target}",
            if authed { 2 } else { 1 }
        ),
    )
}

pub async fn run_gcp_attack(target: &str) {
    print_result(run_gcp_attack_result(target).await);
}

// ─────────────────────────────────────────────────────────────────────────────
// Project resolution
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve the set of projects to scan: explicit config first, else auto-discover accessible
/// projects via Cloud Resource Manager.
async fn resolve_projects(
    client: &GcpClient,
    cfg: &GcpScanConfig,
    col: &mut Collector<'_>,
    target: &str,
) -> Vec<String> {
    if !cfg.project_ids.is_empty() {
        return cfg.project_ids.clone();
    }
    match client
        .list_all(
            "https://cloudresourcemanager.googleapis.com/v1/projects",
            "projects",
            cfg.max_projects,
        )
        .await
    {
        Ok(items) => {
            let ids: Vec<String> = items
                .iter()
                .filter_map(|p| {
                    p.get("projectId")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .collect();
            if ids.is_empty() {
                col.push(
                    Domain::Posture,
                    "No GCP projects visible to the scanner identity",
                    "info",
                    "",
                    "",
                    target,
                    1.0,
                    "The credential authenticated, but Cloud Resource Manager returned no projects. Supply gcp_project_id explicitly, or grant the scanner resourcemanager.projects.list / a project-level read role.",
                    Evidence::new().check("cloudresourcemanager.projects.list", true, "empty"),
                );
            } else {
                col.push(
                    Domain::Posture,
                    &format!("GCP credentialed plane authenticated — {} project(s) in scope", ids.len()),
                    "info",
                    "",
                    "",
                    target,
                    1.0,
                    &format!("Read-only token validated. Live CSPM/CIEM checks are running against project(s): {}.", ids.join(", ")),
                    Evidence::new()
                        .with("projects", json!(ids))
                        .check("cloudresourcemanager.projects.list", true, ids.len() as i64),
                );
            }
            ids
        }
        Err(e) => {
            col.push(
                Domain::Posture,
                "GCP project discovery failed",
                "info",
                "",
                "",
                target,
                1.0,
                &format!("Could not list projects ({}). Supply gcp_project_id explicitly to scan a known project.", describe_err(&e)),
                Evidence::new().check("cloudresourcemanager.projects.list", false, describe_err(&e)),
            );
            Vec::new()
        }
    }
}

fn describe_err(e: &GcpErr) -> String {
    match e {
        GcpErr::Network(s) => format!("network error: {s}"),
        GcpErr::Http(code, reason, body) => format!("HTTP {code} ({reason}): {body}"),
        GcpErr::Parse(s) => format!("parse error: {s}"),
    }
}

/// Emit a graceful info finding when an API call fails for a recoverable reason (permission / API
/// disabled), so the operator sees coverage gaps instead of silent emptiness.
fn note_api_gap(col: &mut Collector<'_>, target: &str, service: &str, project: &str, e: &GcpErr) {
    // Only annotate the meaningful, recoverable cases (don't spam on transient network blips).
    if let GcpErr::Http(_code, reason, _body) = e {
        let detail = match *reason {
            "api_disabled" => format!("The {service} API is not enabled on project {project}; nothing to assess there."),
            "permission_denied" => format!("The scanner identity lacks read permission for {service} on project {project}; grant a read-only role to assess it."),
            _ => return,
        };
        col.push(
            Domain::Posture,
            &format!("{service} not assessable on {project}"),
            "info",
            "",
            "",
            target,
            1.0,
            &detail,
            Evidence::new()
                .with("service", service)
                .with("project", project)
                .check(reason, false, "skipped"),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-project credentialed scan
// ─────────────────────────────────────────────────────────────────────────────

async fn scan_project(
    client: &GcpClient,
    cfg: &GcpScanConfig,
    col: &mut Collector<'_>,
    project: &str,
    target: &str,
) {
    let root = format!("project:{project}");
    col.add_node(&root, project, "root", "root");

    if cfg.check_iam {
        scan_project_iam(client, cfg, col, project, target, &root).await;
    }
    if cfg.check_sa_keys {
        scan_service_account_keys(client, cfg, col, project, target, &root).await;
    }
    if cfg.check_compute {
        // Project metadata first: it sets `col.project_oslogin`, which per-instance assessment
        // uses to avoid flagging every VM in a project that enforces OS Login at project scope.
        scan_project_metadata(client, col, project, target).await;
        scan_compute_instances(client, cfg, col, project, target, &root).await;
    }
    if cfg.check_firewall {
        scan_firewalls(client, cfg, col, project, target, &root).await;
    }
    if cfg.check_storage {
        scan_storage(client, cfg, col, project, target, &root).await;
    }
    if cfg.check_gke {
        scan_gke(client, col, project, target, &root).await;
    }
    if cfg.check_sql {
        scan_cloudsql(client, cfg, col, project, target, &root).await;
    }
    if cfg.check_bigquery {
        scan_bigquery(client, cfg, col, project, target, &root).await;
    }
    if cfg.check_functions {
        scan_functions(client, cfg, col, project, target, &root).await;
    }
    if cfg.check_run {
        scan_cloud_run(client, cfg, col, project, target, &root).await;
    }
    if cfg.check_dns {
        scan_dns(client, cfg, col, project, target).await;
    }
}

// ── CIEM — project IAM policy: public bindings, primitive sprawl, privesc primitives ─────────────

async fn scan_project_iam(
    client: &GcpClient,
    cfg: &GcpScanConfig,
    col: &mut Collector<'_>,
    project: &str,
    target: &str,
    root: &str,
) {
    let url =
        format!("https://cloudresourcemanager.googleapis.com/v1/projects/{project}:getIamPolicy");
    let policy = match client
        .http
        .post(&url)
        .bearer_auth(&client.token)
        .json(&json!({"options": {"requestedPolicyVersion": 3}}))
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if status == 200 {
                serde_json::from_str::<Value>(&body).unwrap_or(json!({}))
            } else {
                let reason = GcpErr::classify(status, &body);
                note_api_gap(
                    col,
                    target,
                    "Cloud Resource Manager (IAM policy)",
                    project,
                    &GcpErr::Http(status, reason, body.chars().take(200).collect()),
                );
                return;
            }
        }
        Err(e) => {
            col.push(
                Domain::Posture,
                "IAM policy read failed",
                "info",
                "",
                "",
                target,
                1.0,
                &format!("getIamPolicy network error on {project}: {e}"),
                Evidence::new().check("projects.getIamPolicy", false, "network"),
            );
            return;
        }
    };

    let bindings = policy
        .get("bindings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut primitive_members = 0usize;
    for b in &bindings {
        let role = b.get("role").and_then(Value::as_str).unwrap_or("");
        let members: Vec<String> = b
            .get("members")
            .and_then(Value::as_array)
            .map(|m| {
                m.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        // 1) Public principals on a project binding — the worst-case CIEM failure.
        let public_members: Vec<&String> = members
            .iter()
            .filter(|m| m.as_str() == "allUsers" || m.as_str() == "allAuthenticatedUsers")
            .collect();
        if !public_members.is_empty() {
            col.sig.project_public_iam = true;
            let node = format!("iam-public:{project}:{role}");
            col.add_node(&node, &format!("public {role}"), "iam", "takeover");
            col.add_edge(root, &node);
            col.push(
                Domain::Identity,
                &format!("Project IAM grants {role} to the public", ),
                "critical",
                "T1078.004",
                "1.x",
                target,
                0.97,
                &format!(
                    "Project '{project}' has an IAM binding granting '{role}' to {}. Anyone on the internet (or any Google account) can act with this role on the project. Remove the public member immediately.",
                    public_members.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                ),
                Evidence::new()
                    .with("project", project)
                    .with("role", role)
                    .with("public_members", json!(public_members))
                    .check("projects.getIamPolicy", true, "public binding"),
            );
        }

        // 2) Primitive-role sprawl (owner/editor).
        if role == "roles/owner" || role == "roles/editor" {
            let human = members
                .iter()
                .filter(|m| m.starts_with("user:") || m.starts_with("group:"))
                .count();
            primitive_members += human;
        }

        // 3) Privilege-escalation primitives.
        if cfg.enable_privesc {
            if let Some((_, technique, severity)) =
                PRIVESC_ROLES.iter().find(|(r, _, _)| *r == role)
            {
                // Only the principals an attacker might plausibly pivot through: exclude
                // Google-managed service agents (expected). The previous first predicate was a
                // tautology (`A || (B && C) || D` is true for every well-formed member string),
                // so it narrowed nothing — `is_google_managed_agent` is the only real filter.
                let risky: Vec<&String> = members
                    .iter()
                    .filter(|m| !is_google_managed_agent(m))
                    .collect();
                if !risky.is_empty() {
                    let node = format!("privesc:{project}:{role}");
                    col.add_node(&node, role, "iam", "exposed");
                    col.add_edge(root, &node);
                    if role == "roles/iam.serviceAccountTokenCreator"
                        || role == "roles/iam.serviceAccountUser"
                    {
                        col.sig.sa_impersonation = true;
                    }
                    col.push(
                        Domain::Identity,
                        &format!("CIEM privilege-escalation role granted: {role}"),
                        severity,
                        "T1548",
                        "1.x",
                        target,
                        0.8,
                        &format!(
                            "Project '{project}' grants '{role}' to {}. {technique}",
                            risky
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        Evidence::new()
                            .with("project", project)
                            .with("role", role)
                            .with("members", json!(risky))
                            .with("escalation_technique", *technique)
                            .check("privilege_escalation_primitive", true, role),
                    );
                }
            }
        }
    }

    if primitive_members > 0 {
        col.push(
            Domain::Identity,
            "Primitive roles (Owner/Editor) granted to human identities",
            "medium",
            "T1098",
            "1.5",
            target,
            0.75,
            &format!(
                "Project '{project}' assigns the primitive roles Owner/Editor to {primitive_members} user/group principal(s). Primitive roles violate least privilege (CIS 1.5); replace them with predefined or custom roles scoped to the minimum required permissions."
            ),
            Evidence::new()
                .with("project", project)
                .with("primitive_human_members", primitive_members as i64)
                .check("primitive_role_sprawl", true, primitive_members as i64),
        );
    }
}

fn is_google_managed_agent(member: &str) -> bool {
    member.contains("@cloudservices.gserviceaccount.com")
        || member.contains(".gserviceaccount.com")
            && (member.contains("@gcp-sa-")
                || member.contains("@cloud-")
                || member.contains("@compute-system")
                || member.contains("@container-engine-robot")
                || member.contains("@cloudbuild.gserviceaccount.com")
                || member.contains("@system.gserviceaccount.com"))
}

// ── CIEM — service-account user-managed keys (long-lived, exfiltratable credentials) ─────────────

async fn scan_service_account_keys(
    client: &GcpClient,
    cfg: &GcpScanConfig,
    col: &mut Collector<'_>,
    project: &str,
    target: &str,
    root: &str,
) {
    let url = format!("https://iam.googleapis.com/v1/projects/{project}/serviceAccounts");
    let accounts = match client.list_all(&url, "accounts", cfg.max_resources).await {
        Ok(a) => a,
        Err(e) => {
            note_api_gap(col, target, "IAM (service accounts)", project, &e);
            return;
        }
    };

    for sa in accounts.iter().take(cfg.max_resources) {
        let email = sa.get("email").and_then(Value::as_str).unwrap_or("");
        if email.is_empty() {
            continue;
        }
        let keys_url = format!(
            "https://iam.googleapis.com/v1/projects/{project}/serviceAccounts/{email}/keys?keyTypes=USER_MANAGED"
        );
        let keys = match client.get(&keys_url).await {
            Ok(v) => v
                .get("keys")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            Err(_) => continue,
        };
        for k in &keys {
            let name = k.get("name").and_then(Value::as_str).unwrap_or("");
            let valid_after = k
                .get("validAfterTime")
                .and_then(Value::as_str)
                .unwrap_or("");
            let age_days = key_age_days(valid_after);
            // Any user-managed key is a finding (CIS 1.4); aged keys escalate (CIS 1.7).
            let (sev, conf, extra) = if age_days > cfg.sa_key_max_age_days {
                ("high", 0.85, format!(" The key is {age_days} days old (threshold {} days) — rotate or, better, eliminate it.", cfg.sa_key_max_age_days))
            } else {
                ("medium", 0.8, String::new())
            };
            let node = format!("sakey:{email}");
            col.add_node(&node, email, "identity", "exposed");
            col.add_edge(root, &node);
            col.push(
                Domain::Identity,
                &format!("User-managed service-account key: {email}"),
                sev,
                "T1552.001",
                "1.4",
                target,
                conf,
                &format!(
                    "Service account '{email}' in project '{project}' has a user-managed key. User-managed keys are long-lived, downloadable credentials that are a leading cause of GCP breaches when committed to code or leaked.{extra} Prefer Workload Identity / short-lived impersonation and delete static keys."
                ),
                Evidence::new()
                    .with("project", project)
                    .with("service_account", email)
                    .with("key_name", name)
                    .with("key_age_days", age_days)
                    .with("valid_after", valid_after)
                    .check("serviceAccounts.keys.list[USER_MANAGED]", true, age_days),
            );
        }
    }
}

fn key_age_days(valid_after: &str) -> i64 {
    if valid_after.is_empty() {
        return 0;
    }
    match chrono::DateTime::parse_from_rfc3339(valid_after) {
        Ok(dt) => {
            let now = chrono::Utc::now();
            (now.timestamp() - dt.timestamp()).max(0) / 86_400
        }
        Err(_) => 0,
    }
}

// ── CWPP — Compute Engine instances ──────────────────────────────────────────────────────────────

async fn scan_compute_instances(
    client: &GcpClient,
    cfg: &GcpScanConfig,
    col: &mut Collector<'_>,
    project: &str,
    target: &str,
    root: &str,
) {
    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/instances?maxResults=500"
    );
    let agg = match client.get(&url).await {
        Ok(v) => v,
        Err(e) => {
            note_api_gap(col, target, "Compute Engine (instances)", project, &e);
            return;
        }
    };

    let mut count = 0usize;
    if let Some(items) = agg.get("items").and_then(Value::as_object) {
        for (_zone, scope) in items {
            let instances = scope.get("instances").and_then(Value::as_array);
            let Some(instances) = instances else { continue };
            for inst in instances {
                if count >= cfg.max_resources {
                    return;
                }
                count += 1;
                assess_instance(col, project, target, root, inst);
            }
        }
    }
}

fn assess_instance(col: &mut Collector<'_>, project: &str, target: &str, root: &str, inst: &Value) {
    let name = inst
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("instance");
    let zone = inst
        .get("zone")
        .and_then(Value::as_str)
        .and_then(|z| z.rsplit('/').next())
        .unwrap_or("");

    // Public IP via accessConfigs.natIP
    let mut public_ip: Option<String> = None;
    if let Some(nics) = inst.get("networkInterfaces").and_then(Value::as_array) {
        for nic in nics {
            if let Some(acs) = nic.get("accessConfigs").and_then(Value::as_array) {
                for ac in acs {
                    if let Some(ip) = ac.get("natIP").and_then(Value::as_str) {
                        public_ip = Some(ip.to_string());
                    }
                }
            }
        }
    }

    // Attached service account + scopes
    let mut default_sa = false;
    let mut broad_scope = false;
    let mut sa_email = String::new();
    if let Some(sas) = inst.get("serviceAccounts").and_then(Value::as_array) {
        for sa in sas {
            let email = sa.get("email").and_then(Value::as_str).unwrap_or("");
            sa_email = email.to_string();
            if email.ends_with("-compute@developer.gserviceaccount.com") {
                default_sa = true;
            }
            if let Some(scopes) = sa.get("scopes").and_then(Value::as_array) {
                if scopes
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|s| s == GCE_CLOUD_PLATFORM_SCOPE)
                {
                    broad_scope = true;
                }
            }
        }
    }

    // Metadata flags
    let meta = instance_metadata_map(inst);
    // Fall back to the project-level flag when the instance carries no explicit key: GCP's
    // recommended pattern is to set enable-oslogin once in project metadata and let instances
    // inherit it, so an absent per-instance key on such a project is compliant, not a finding.
    let oslogin = meta
        .get("enable-oslogin")
        .map(|v| is_truthy(v))
        .unwrap_or(col.project_oslogin);
    let serial_enabled = meta
        .get("serial-port-enable")
        .map(|v| is_truthy(v))
        .unwrap_or(false);
    let legacy_endpoints_disabled = meta
        .get("disable-legacy-endpoints")
        .map(|v| is_truthy(v))
        .unwrap_or(false);
    let can_ip_forward = inst
        .get("canIpForward")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let shielded = inst
        .get("shieldedInstanceConfig")
        .map(|s| {
            s.get("enableVtpm")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                && s.get("enableIntegrityMonitoring")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
        })
        .unwrap_or(false);

    let inode = format!("gce:{project}:{name}");
    let exposed = public_ip.is_some();
    col.add_node(
        &inode,
        name,
        "compute",
        if exposed { "exposed" } else { "secure" },
    );
    col.add_edge(root, &inode);

    if let Some(ip) = &public_ip {
        col.sig.public_instance = true;
        // The classic GCP token-theft surface: public instance + default SA + cloud-platform scope.
        if default_sa && broad_scope {
            col.sig.instance_token_theft = true;
            col.push(
                Domain::Network,
                &format!("Public instance runs default SA with cloud-platform scope: {name}"),
                "critical",
                "T1552.005",
                "4.1",
                target,
                0.9,
                &format!(
                    "Instance '{name}' ({zone}) has public IP {ip} and runs as the default Compute service account '{sa_email}' with the full cloud-platform scope. An SSRF/RCE on a workload there can read the metadata server and obtain a token with project-wide access — a direct path to full project compromise. Use a dedicated least-privilege SA and restrict access scopes."
                ),
                Evidence::new()
                    .with("project", project)
                    .with("instance", name)
                    .with("zone", zone)
                    .with("public_ip", ip.clone())
                    .with("service_account", sa_email.clone())
                    .with("default_sa", true)
                    .with("cloud_platform_scope", true)
                    .check("aggregated.instances.serviceAccounts.scopes", true, "cloud-platform"),
            );
        } else if broad_scope {
            col.push(
                Domain::Network,
                &format!("Public instance has an over-broad access scope: {name}"),
                "high",
                "T1552.005",
                "4.2",
                target,
                0.82,
                &format!("Instance '{name}' ({zone}, public IP {ip}) grants its service account '{sa_email}' the cloud-platform scope. Restrict scopes to the minimum the workload needs."),
                Evidence::new()
                    .with("instance", name)
                    .with("public_ip", ip.clone())
                    .with("service_account", sa_email.clone())
                    .check("access_scopes", true, "cloud-platform"),
            );
        }
    }

    if !oslogin {
        col.push(
            Domain::Identity,
            &format!("OS Login not enabled on instance: {name}"),
            "medium",
            "T1078",
            "4.4",
            target,
            0.7,
            &format!("Instance '{name}' ({zone}) does not enforce OS Login (enable-oslogin). OS Login centralises SSH access on IAM and supports MFA; without it, instance/project SSH keys grant standing access that is hard to audit."),
            Evidence::new().with("instance", name).check("enable-oslogin", false, "absent"),
        );
    }
    if serial_enabled {
        col.push(
            Domain::Network,
            &format!("Serial-port access enabled on instance: {name}"),
            "medium",
            "T1021",
            "4.5",
            target,
            0.8,
            &format!("Instance '{name}' ({zone}) has the interactive serial console enabled (serial-port-enable). The serial port has no IP/firewall restriction and is a common backdoor for credential-based access. Disable it unless actively debugging."),
            Evidence::new().with("instance", name).check("serial-port-enable", true, "enabled"),
        );
    }
    if public_ip.is_some() && !legacy_endpoints_disabled {
        col.push(
            Domain::Network,
            &format!("Legacy metadata endpoints not disabled: {name}"),
            "medium",
            "T1552.005",
            "4.x",
            target,
            0.7,
            &format!("Instance '{name}' ({zone}) does not set disable-legacy-endpoints=true. Legacy (v1beta1) metadata endpoints don't require the Metadata-Flavor header, widening SSRF-to-token-theft. Disable legacy endpoints."),
            Evidence::new().with("instance", name).check("disable-legacy-endpoints", false, "absent"),
        );
    }
    if can_ip_forward {
        col.push(
            Domain::Network,
            &format!("IP forwarding enabled on instance: {name}"),
            "low",
            "T1090",
            "4.6",
            target,
            0.7,
            &format!("Instance '{name}' ({zone}) can forward IP packets (canIpForward). A compromised host can act as a router/pivot to bypass network segmentation. Disable unless it is an intentional NAT/VPN appliance."),
            Evidence::new().with("instance", name).check("canIpForward", true, "true"),
        );
    }
    if !shielded {
        col.push(
            Domain::Posture,
            &format!("Shielded VM not fully enabled: {name}"),
            "low",
            "T1542",
            "4.8",
            target,
            0.65,
            &format!("Instance '{name}' ({zone}) does not have vTPM + integrity monitoring (Shielded VM). Shielded VM defends against boot-/kernel-level rootkits and verifies instance integrity."),
            Evidence::new().with("instance", name).check("shieldedInstanceConfig", false, "partial/absent"),
        );
    }
}

fn instance_metadata_map(inst: &Value) -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    if let Some(items) = inst
        .get("metadata")
        .and_then(|md| md.get("items"))
        .and_then(Value::as_array)
    {
        for it in items {
            if let (Some(k), Some(v)) = (
                it.get("key").and_then(Value::as_str),
                it.get("value").and_then(Value::as_str),
            ) {
                m.insert(k.to_string(), v.to_string());
            }
        }
    }
    m
}

fn is_truthy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "on" | "enabled"
    )
}

// ── CWPP — VPC firewalls (0.0.0.0/0 ingress on sensitive ports) ──────────────────────────────────

async fn scan_firewalls(
    client: &GcpClient,
    cfg: &GcpScanConfig,
    col: &mut Collector<'_>,
    project: &str,
    target: &str,
    root: &str,
) {
    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{project}/global/firewalls?maxResults=500"
    );
    let rules = match client.list_all(&url, "items", cfg.max_resources).await {
        Ok(r) => r,
        Err(e) => {
            note_api_gap(col, target, "Compute Engine (firewalls)", project, &e);
            return;
        }
    };

    for fw in &rules {
        let name = fw.get("name").and_then(Value::as_str).unwrap_or("firewall");
        let disabled = fw.get("disabled").and_then(Value::as_bool).unwrap_or(false);
        let direction = fw
            .get("direction")
            .and_then(Value::as_str)
            .unwrap_or("INGRESS");
        if disabled || direction != "INGRESS" {
            continue;
        }
        let world_open = fw
            .get("sourceRanges")
            .and_then(Value::as_array)
            .map(|r| r.iter().filter_map(Value::as_str).any(|c| c == "0.0.0.0/0"))
            .unwrap_or(false);
        if !world_open {
            continue;
        }
        let Some(allowed) = fw.get("allowed").and_then(Value::as_array) else {
            continue;
        };
        for rule in allowed {
            let proto = rule.get("IPProtocol").and_then(Value::as_str).unwrap_or("");
            let ports_all = rule.get("ports").is_none(); // absence = all ports
                                                         // Ports are only meaningful for tcp/udp. GCP omits the `ports` key for
                                                         // icmp/esp/ah/sctp/etc., so a missing key does NOT mean "all TCP ports" there —
                                                         // treating it that way fabricated 16 port findings for a benign `allow icmp` rule.
            let proto_l = proto.to_ascii_lowercase();
            let port_bearing = matches!(proto_l.as_str(), "tcp" | "udp" | "6" | "17");
            let ports: Vec<u32> = rule
                .get("ports")
                .and_then(Value::as_array)
                .map(|p| {
                    p.iter()
                        .filter_map(Value::as_str)
                        .flat_map(parse_port_spec)
                        .collect()
                })
                .unwrap_or_default();

            if (proto == "all" || proto.is_empty() || proto == "0") && ports_all {
                col.sig.open_admin_port = true;
                let node = format!("fw:{project}:{name}");
                col.add_node(&node, name, "firewall", "takeover");
                col.add_edge(root, &node);
                col.push(
                    Domain::Network,
                    &format!("Firewall allows ALL traffic from the internet: {name}"),
                    "critical",
                    "T1190",
                    "3.x",
                    target,
                    0.92,
                    &format!("Firewall rule '{name}' in project '{project}' permits ALL protocols/ports from 0.0.0.0/0. Every VM the rule targets is fully internet-exposed. Restrict source ranges and protocols/ports to the minimum required."),
                    Evidence::new().with("firewall", name).with("source", "0.0.0.0/0").check("allowed.all", true, "all"),
                );
                continue;
            }
            for (port, label, cis, sev) in DANGEROUS_PORTS {
                let hit = (ports_all && port_bearing) || ports.contains(port);
                if hit {
                    if matches!(*sev, "critical" | "high") {
                        col.sig.open_admin_port = true;
                    }
                    let node = format!("fw:{project}:{name}:{port}");
                    col.add_node(&node, &format!("{name}:{port}"), "firewall", "exposed");
                    col.add_edge(root, &node);
                    col.push(
                        Domain::Network,
                        &format!("Firewall exposes {label} ({port}) to the internet: {name}"),
                        sev,
                        "T1190",
                        cis,
                        target,
                        0.9,
                        &format!("Firewall rule '{name}' allows {proto}/{port} ({label}) from 0.0.0.0/0. Expose administrative/database ports only to known CIDRs, an IAP tunnel, or a bastion."),
                        Evidence::new()
                            .with("firewall", name)
                            .with("port", *port as i64)
                            .with("service", *label)
                            .with("source", "0.0.0.0/0")
                            .check("ingress_0.0.0.0/0", true, *port as i64),
                    );
                }
            }
        }
    }
}

fn parse_port_spec(spec: &str) -> Vec<u32> {
    let s = spec.trim();
    if let Some((a, b)) = s.split_once('-') {
        if let (Ok(a), Ok(b)) = (a.trim().parse::<u32>(), b.trim().parse::<u32>()) {
            // Bound range expansion so a 0-65535 rule doesn't allocate absurdly.
            if b >= a && b - a <= 65_535 {
                return (a..=b).collect();
            }
        }
        Vec::new()
    } else if let Ok(p) = s.parse::<u32>() {
        vec![p]
    } else {
        Vec::new()
    }
}

// ── Project-wide metadata (OS Login at project, project SSH keys) ─────────────────────────────────

async fn scan_project_metadata(
    client: &GcpClient,
    col: &mut Collector<'_>,
    project: &str,
    target: &str,
) {
    let url = format!("https://compute.googleapis.com/compute/v1/projects/{project}");
    let proj = match client.get(&url).await {
        Ok(v) => v,
        Err(_) => return,
    };
    let mut oslogin = false;
    let mut project_ssh_keys = false;
    if let Some(items) = proj
        .get("commonInstanceMetadata")
        .and_then(|m| m.get("items"))
        .and_then(Value::as_array)
    {
        for it in items {
            match it.get("key").and_then(Value::as_str) {
                Some("enable-oslogin") => {
                    oslogin = it
                        .get("value")
                        .and_then(Value::as_str)
                        .map(is_truthy)
                        .unwrap_or(false);
                }
                Some("ssh-keys") | Some("sshKeys") => project_ssh_keys = true,
                _ => {}
            }
        }
    }
    // Instances inherit the project-level flag; record it so assess_instance can treat an
    // instance with no per-instance key as compliant when the project enforces OS Login.
    col.project_oslogin = oslogin;
    if !oslogin {
        col.push(
            Domain::Identity,
            "OS Login not enforced at the project level",
            "medium",
            "T1078",
            "4.4",
            target,
            0.75,
            &format!("Project '{project}' does not set enable-oslogin=true in project metadata, so OS Login is not enforced cluster-wide. Enable it to centralise SSH access on IAM with auditing and optional 2FA."),
            Evidence::new().with("project", project).check("project.enable-oslogin", false, "absent"),
        );
    }
    if project_ssh_keys && !oslogin {
        col.push(
            Domain::Identity,
            "Project-wide SSH keys present without OS Login",
            "medium",
            "T1098.004",
            "4.3",
            target,
            0.7,
            &format!("Project '{project}' defines project-wide SSH keys while OS Login is disabled. Project-wide keys grant standing SSH access to every instance that doesn't block them. Migrate to OS Login and remove the project-level keys."),
            Evidence::new().with("project", project).check("project.ssh-keys", true, "present"),
        );
    }
}

// ── DSPM — Cloud Storage ─────────────────────────────────────────────────────────────────────────

async fn scan_storage(
    client: &GcpClient,
    cfg: &GcpScanConfig,
    col: &mut Collector<'_>,
    project: &str,
    target: &str,
    root: &str,
) {
    let url =
        format!("https://storage.googleapis.com/storage/v1/b?project={project}&maxResults=200");
    let buckets = match client.list_all(&url, "items", cfg.max_buckets).await {
        Ok(b) => b,
        Err(e) => {
            note_api_gap(col, target, "Cloud Storage", project, &e);
            return;
        }
    };

    for b in buckets.iter().take(cfg.max_buckets) {
        let name = b.get("name").and_then(Value::as_str).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let ubla = b
            .get("iamConfiguration")
            .and_then(|c| c.get("uniformBucketLevelAccess"))
            .and_then(|u| u.get("enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let pap = b
            .get("iamConfiguration")
            .and_then(|c| c.get("publicAccessPrevention"))
            .and_then(Value::as_str)
            .unwrap_or("inherited");
        let versioning = b
            .get("versioning")
            .and_then(|v| v.get("enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false);

        // Bucket IAM — public members (CIS 5.1).
        let iam_url = format!("https://storage.googleapis.com/storage/v1/b/{name}/iam");
        if let Ok(iam) = client.get(&iam_url).await {
            let public: Vec<String> = iam
                .get("bindings")
                .and_then(Value::as_array)
                .map(|bs| {
                    bs.iter()
                        .filter_map(|bd| bd.get("members").and_then(Value::as_array))
                        .flatten()
                        .filter_map(Value::as_str)
                        .filter(|m| *m == "allUsers" || *m == "allAuthenticatedUsers")
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !public.is_empty() {
                col.sig.public_bucket = true;
                let node = format!("gcs:{name}");
                col.add_node(&node, name, "storage", "takeover");
                col.add_edge(root, &node);
                col.push(
                    Domain::Data,
                    &format!("Cloud Storage bucket is public: {name}"),
                    "critical",
                    "T1530",
                    "5.1",
                    target,
                    0.95,
                    &format!("Bucket '{name}' grants access to {} via IAM. Its objects are readable by anyone (or any Google account). Remove allUsers/allAuthenticatedUsers and enable public-access prevention.", public.join(", ")),
                    Evidence::new()
                        .with("bucket", name)
                        .with("public_members", json!(public))
                        .check("b.iam.bindings.public", true, "present"),
                );
            }
        }

        if pap != "enforced" {
            col.push(
                Domain::Data,
                &format!("Public-access prevention not enforced: {name}"),
                "medium",
                "T1530",
                "5.2",
                target,
                0.75,
                &format!("Bucket '{name}' has publicAccessPrevention='{pap}'. Set it to 'enforced' so the bucket can never be made public by a future ACL/IAM change."),
                Evidence::new().with("bucket", name).with("public_access_prevention", pap).check("publicAccessPrevention", true, pap),
            );
        }
        if !ubla {
            col.push(
                Domain::Data,
                &format!("Uniform bucket-level access disabled: {name}"),
                "low",
                "T1530",
                "5.2",
                target,
                0.7,
                &format!("Bucket '{name}' still allows fine-grained object ACLs (uniform bucket-level access disabled). Object ACLs are easy to misconfigure into public exposure; enable uniform bucket-level access to manage permissions solely via IAM."),
                Evidence::new().with("bucket", name).check("uniformBucketLevelAccess", false, "disabled"),
            );
        }
        if !versioning {
            col.push(
                Domain::Data,
                &format!("Object versioning disabled: {name}"),
                "low",
                "T1485",
                "5.x",
                target,
                0.6,
                &format!("Bucket '{name}' has object versioning disabled; overwritten/deleted objects are unrecoverable, weakening ransomware and accidental-deletion resilience."),
                Evidence::new().with("bucket", name).check("versioning.enabled", false, "disabled"),
            );
        }
    }
}

// ── GKE — cluster control-plane / data-plane posture ─────────────────────────────────────────────

async fn scan_gke(
    client: &GcpClient,
    col: &mut Collector<'_>,
    project: &str,
    target: &str,
    root: &str,
) {
    let url =
        format!("https://container.googleapis.com/v1/projects/{project}/locations/-/clusters");
    let clusters = match client.get(&url).await {
        Ok(v) => v
            .get("clusters")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        Err(e) => {
            note_api_gap(col, target, "Kubernetes Engine (GKE)", project, &e);
            return;
        }
    };

    for c in &clusters {
        let name = c.get("name").and_then(Value::as_str).unwrap_or("cluster");
        let location = c.get("location").and_then(Value::as_str).unwrap_or("");
        let node = format!("gke:{project}:{name}");

        let legacy_abac = c
            .get("legacyAbac")
            .and_then(|a| a.get("enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let master_auth = c.get("masterAuth");
        let basic_auth = master_auth
            .and_then(|m| m.get("username"))
            .and_then(Value::as_str)
            .map(|u| !u.is_empty())
            .unwrap_or(false);
        let client_cert = master_auth
            .and_then(|m| m.get("clientCertificate"))
            .and_then(Value::as_str)
            .map(|x| !x.is_empty())
            .unwrap_or(false);
        let private_nodes = c
            .get("privateClusterConfig")
            .and_then(|p| p.get("enablePrivateNodes"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let private_endpoint = c
            .get("privateClusterConfig")
            .and_then(|p| p.get("enablePrivateEndpoint"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let authorized_networks = c
            .get("masterAuthorizedNetworksConfig")
            .and_then(|m| m.get("enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let network_policy = c
            .get("networkPolicy")
            .and_then(|n| n.get("enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let shielded_nodes = c
            .get("shieldedNodes")
            .and_then(|s| s.get("enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let workload_identity = c
            .get("workloadIdentityConfig")
            .and_then(|w| w.get("workloadPool"))
            .and_then(Value::as_str)
            .map(|p| !p.is_empty())
            .unwrap_or(false);
        let public_endpoint = c
            .get("endpoint")
            .and_then(Value::as_str)
            .map(|e| !e.is_empty())
            .unwrap_or(false)
            && !private_endpoint;

        let weak = legacy_abac || basic_auth || client_cert;
        if weak {
            col.sig.gke_weak_auth = true;
        }
        let exposed = public_endpoint && (weak || !authorized_networks);
        col.add_node(
            &node,
            name,
            "gke",
            if exposed { "takeover" } else { "secure" },
        );
        col.add_edge(root, &node);

        if legacy_abac {
            col.push(Domain::Identity, &format!("GKE legacy ABAC enabled: {name}"), "high", "T1078", "7.3", target, 0.9,
                &format!("Cluster '{name}' ({location}) has legacy ABAC enabled, which grants broad, hard-to-audit authorization that bypasses RBAC. Disable legacy authorization."),
                Evidence::new().with("cluster", name).check("legacyAbac.enabled", true, "enabled"));
        }
        if basic_auth {
            col.push(Domain::Identity, &format!("GKE basic authentication enabled: {name}"), "critical", "T1078", "7.x", target, 0.9,
                &format!("Cluster '{name}' ({location}) has master basic authentication (static username/password) enabled — a credential-stuffing target that grants control-plane access. Disable basic auth and use IAM/OIDC."),
                Evidence::new().with("cluster", name).check("masterAuth.username", true, "set"));
        }
        if client_cert {
            col.push(Domain::Identity, &format!("GKE client certificate issued: {name}"), "medium", "T1078", "7.x", target, 0.8,
                &format!("Cluster '{name}' ({location}) issues a client certificate for the control plane. Client certs cannot be revoked without rotating the cluster CA; disable client-cert auth and rely on IAM."),
                Evidence::new().with("cluster", name).check("masterAuth.clientCertificate", true, "issued"));
        }
        if public_endpoint && !authorized_networks {
            col.sig.public_gke_endpoint = true;
            col.push(Domain::Network, &format!("GKE public endpoint without master authorized networks: {name}"), "high", "T1190", "7.13", target, 0.88,
                &format!("Cluster '{name}' ({location}) exposes a public control-plane endpoint with no master authorized-networks allow-list. The Kubernetes API is reachable from the entire internet. Enable master authorized networks or a private endpoint."),
                Evidence::new().with("cluster", name).check("masterAuthorizedNetworksConfig.enabled", false, "disabled"));
        }
        if !private_nodes {
            col.push(Domain::Network, &format!("GKE nodes have public IPs (not a private cluster): {name}"), "medium", "T1190", "7.15", target, 0.75,
                &format!("Cluster '{name}' ({location}) is not a private cluster (enablePrivateNodes=false); nodes get public IPs, widening the attack surface. Convert to a private cluster."),
                Evidence::new().with("cluster", name).check("privateClusterConfig.enablePrivateNodes", false, "disabled"));
        }
        if !network_policy {
            col.push(Domain::Network, &format!("GKE network policy disabled: {name}"), "low", "T1046", "7.10", target, 0.7,
                &format!("Cluster '{name}' ({location}) has no network policy enforcement, so pods can communicate without restriction (flat lateral movement). Enable a network policy provider."),
                Evidence::new().with("cluster", name).check("networkPolicy.enabled", false, "disabled"));
        }
        if !workload_identity {
            col.push(Domain::Identity, &format!("GKE Workload Identity not configured: {name}"), "medium", "T1552.005", "7.12", target, 0.78,
                &format!("Cluster '{name}' ({location}) does not use Workload Identity. Without it, pods reach the node's service account through the metadata server (node-SA token theft). Enable Workload Identity and metadata concealment."),
                Evidence::new().with("cluster", name).check("workloadIdentityConfig.workloadPool", false, "absent"));
        }
        if !shielded_nodes {
            col.push(Domain::Posture, &format!("GKE Shielded Nodes disabled: {name}"), "low", "T1542", "7.17", target, 0.65,
                &format!("Cluster '{name}' ({location}) does not enable Shielded GKE Nodes (secure boot + integrity monitoring). Enable Shielded Nodes to harden the data plane against boot/kernel tampering."),
                Evidence::new().with("cluster", name).check("shieldedNodes.enabled", false, "disabled"));
        }
    }
}

// ── DSPM — Cloud SQL ─────────────────────────────────────────────────────────────────────────────

async fn scan_cloudsql(
    client: &GcpClient,
    cfg: &GcpScanConfig,
    col: &mut Collector<'_>,
    project: &str,
    target: &str,
    root: &str,
) {
    let url = format!("https://sqladmin.googleapis.com/v1/projects/{project}/instances");
    let instances = match client.list_all(&url, "items", cfg.max_resources).await {
        Ok(i) => i,
        Err(e) => {
            note_api_gap(col, target, "Cloud SQL", project, &e);
            return;
        }
    };

    for inst in &instances {
        let name = inst
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("instance");
        let ipcfg = inst.get("settings").and_then(|s| s.get("ipConfiguration"));
        let ipv4 = ipcfg
            .and_then(|c| c.get("ipv4Enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let require_ssl = ipcfg
            .and_then(|c| c.get("requireSsl"))
            .and_then(Value::as_bool)
            .or_else(|| {
                ipcfg
                    .and_then(|c| c.get("sslMode"))
                    .and_then(Value::as_str)
                    .map(|m| m != "ALLOW_UNENCRYPTED_AND_ENCRYPTED")
            })
            .unwrap_or(false);
        let world_authorized = ipcfg
            .and_then(|c| c.get("authorizedNetworks"))
            .and_then(Value::as_array)
            .map(|ns| {
                ns.iter()
                    .filter_map(|n| n.get("value").and_then(Value::as_str))
                    .any(|v| v == "0.0.0.0/0")
            })
            .unwrap_or(false);
        let backups = inst
            .get("settings")
            .and_then(|s| s.get("backupConfiguration"))
            .and_then(|b| b.get("enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let node = format!("sql:{project}:{name}");
        let exposed = ipv4 && world_authorized;
        col.add_node(
            &node,
            name,
            "sql",
            if exposed {
                "takeover"
            } else if ipv4 {
                "exposed"
            } else {
                "secure"
            },
        );
        col.add_edge(root, &node);

        if ipv4 && world_authorized {
            col.sig.public_sql = true;
            col.push(Domain::Data, &format!("Cloud SQL instance is internet-exposed: {name}"), "critical", "T1190", "6.5", target, 0.92,
                &format!("Cloud SQL '{name}' has a public IPv4 and an authorized network of 0.0.0.0/0 — the database is reachable from the entire internet. Remove the 0.0.0.0/0 authorized network and prefer Private IP / the Cloud SQL Auth Proxy."),
                Evidence::new().with("instance", name).with("public_ip", true).with("authorized_0.0.0.0/0", true).check("authorizedNetworks", true, "0.0.0.0/0"));
        } else if ipv4 {
            col.push(Domain::Network, &format!("Cloud SQL instance has a public IP: {name}"), "medium", "T1190", "6.x", target, 0.78,
                &format!("Cloud SQL '{name}' exposes a public IPv4 address. Prefer Private IP and the Cloud SQL Auth Proxy to remove the instance from the public internet."),
                Evidence::new().with("instance", name).check("ipv4Enabled", true, "true"));
        }
        if ipv4 && !require_ssl {
            col.sig.sql_no_ssl = true;
            col.push(Domain::Data, &format!("Cloud SQL does not require SSL/TLS: {name}"), "high", "T1040", "6.4", target, 0.85,
                &format!("Cloud SQL '{name}' accepts unencrypted connections (requireSsl/SSL mode not enforced). Database traffic — including credentials — can be intercepted. Require SSL (or ENCRYPTED_ONLY sslMode)."),
                Evidence::new().with("instance", name).check("requireSsl", false, "not enforced"));
        }
        if !backups {
            col.push(Domain::Posture, &format!("Cloud SQL automated backups disabled: {name}"), "low", "T1485", "6.7", target, 0.65,
                &format!("Cloud SQL '{name}' has automated backups disabled, weakening recovery from ransomware or accidental deletion. Enable automated backups and point-in-time recovery."),
                Evidence::new().with("instance", name).check("backupConfiguration.enabled", false, "disabled"));
        }
    }
}

// ── DSPM — BigQuery dataset exposure ─────────────────────────────────────────────────────────────

async fn scan_bigquery(
    client: &GcpClient,
    cfg: &GcpScanConfig,
    col: &mut Collector<'_>,
    project: &str,
    target: &str,
    root: &str,
) {
    let url = format!(
        "https://bigquery.googleapis.com/bigquery/v2/projects/{project}/datasets?maxResults=200"
    );
    let datasets = match client.list_all(&url, "datasets", cfg.max_resources).await {
        Ok(d) => d,
        Err(e) => {
            note_api_gap(col, target, "BigQuery", project, &e);
            return;
        }
    };

    for ds in datasets.iter().take(cfg.max_resources) {
        let id = ds
            .get("datasetReference")
            .and_then(|r| r.get("datasetId"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if id.is_empty() {
            continue;
        }
        let detail_url =
            format!("https://bigquery.googleapis.com/bigquery/v2/projects/{project}/datasets/{id}");
        let Ok(detail) = client.get(&detail_url).await else {
            continue;
        };
        let public: Vec<String> = detail
            .get("access")
            .and_then(Value::as_array)
            .map(|acl| {
                acl.iter()
                    .filter_map(|a| {
                        let special = a.get("specialGroup").and_then(Value::as_str);
                        let iam = a.get("iamMember").and_then(Value::as_str);
                        if special == Some("allAuthenticatedUsers")
                            || iam == Some("allUsers")
                            || iam == Some("allAuthenticatedUsers")
                        {
                            Some(special.or(iam).unwrap_or("public").to_string())
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        if !public.is_empty() {
            col.sig.public_dataset = true;
            let node = format!("bq:{project}:{id}");
            col.add_node(&node, id, "bigquery", "takeover");
            col.add_edge(root, &node);
            col.push(Domain::Data, &format!("BigQuery dataset is public: {id}"), "critical", "T1530", "7.1", target, 0.93,
                &format!("Dataset '{id}' in project '{project}' grants access to {} — its tables are queryable by anyone (or any Google account). Remove the public access entry.", public.join(", ")),
                Evidence::new().with("dataset", id).with("public_members", json!(public)).check("datasets.access.public", true, "present"));
        }
    }
}

// ── Cloud Functions / Cloud Run — public (allUsers) invokers ─────────────────────────────────────

async fn scan_functions(
    client: &GcpClient,
    cfg: &GcpScanConfig,
    col: &mut Collector<'_>,
    project: &str,
    target: &str,
    root: &str,
) {
    let url = format!(
        "https://cloudfunctions.googleapis.com/v1/projects/{project}/locations/-/functions"
    );
    let functions = match client.list_all(&url, "functions", cfg.max_resources).await {
        Ok(f) => f,
        Err(e) => {
            note_api_gap(col, target, "Cloud Functions", project, &e);
            return;
        }
    };
    for func in functions.iter().take(cfg.max_resources) {
        let name = func.get("name").and_then(Value::as_str).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let iam_url = format!("https://cloudfunctions.googleapis.com/v1/{name}:getIamPolicy");
        let Ok(iam) = client.get(&iam_url).await else {
            continue;
        };
        if iam_has_public_member(&iam) {
            col.sig.public_function = true;
            let short = name.rsplit('/').next().unwrap_or(name);
            let node = format!("fn:{project}:{short}");
            col.add_node(&node, short, "function", "exposed");
            col.add_edge(root, &node);
            col.push(Domain::Exposure, &format!("Cloud Function allows unauthenticated invocation: {short}"), "high", "T1190", "1.x", target, 0.85,
                &format!("Function '{short}' in project '{project}' grants the invoker role to allUsers/allAuthenticatedUsers — anyone can trigger it. If it runs as a privileged runtime service account, this is a pivot into the project. Require authenticated invocation."),
                Evidence::new().with("function", short).check("getIamPolicy.public_invoker", true, "present"));
        }
    }
}

async fn scan_cloud_run(
    client: &GcpClient,
    cfg: &GcpScanConfig,
    col: &mut Collector<'_>,
    project: &str,
    target: &str,
    root: &str,
) {
    let url = format!("https://run.googleapis.com/v2/projects/{project}/locations/-/services");
    let services = match client.list_all(&url, "services", cfg.max_resources).await {
        Ok(s) => s,
        Err(e) => {
            note_api_gap(col, target, "Cloud Run", project, &e);
            return;
        }
    };
    for svc in services.iter().take(cfg.max_resources) {
        let name = svc.get("name").and_then(Value::as_str).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let iam_url = format!("https://run.googleapis.com/v2/{name}:getIamPolicy");
        let Ok(iam) = client.get(&iam_url).await else {
            continue;
        };
        if iam_has_public_member(&iam) {
            col.sig.public_run = true;
            let short = name.rsplit('/').next().unwrap_or(name);
            let node = format!("run:{project}:{short}");
            col.add_node(&node, short, "run", "exposed");
            col.add_edge(root, &node);
            col.push(Domain::Exposure, &format!("Cloud Run service allows unauthenticated access: {short}"), "high", "T1190", "1.x", target, 0.85,
                &format!("Cloud Run service '{short}' in project '{project}' grants run.invoker to allUsers/allAuthenticatedUsers — it is publicly reachable. Confirm this is intended; if it runs as a privileged service account, restrict invocation to authenticated callers."),
                Evidence::new().with("service", short).check("getIamPolicy.public_invoker", true, "present"));
        }
    }
}

fn iam_has_public_member(iam: &Value) -> bool {
    iam.get("bindings")
        .and_then(Value::as_array)
        .map(|bs| {
            bs.iter()
                .filter_map(|b| b.get("members").and_then(Value::as_array))
                .flatten()
                .filter_map(Value::as_str)
                .any(|m| m == "allUsers" || m == "allAuthenticatedUsers")
        })
        .unwrap_or(false)
}

// ── Cloud DNS — DNSSEC ───────────────────────────────────────────────────────────────────────────

async fn scan_dns(
    client: &GcpClient,
    cfg: &GcpScanConfig,
    col: &mut Collector<'_>,
    project: &str,
    target: &str,
) {
    let url = format!("https://dns.googleapis.com/dns/v1/projects/{project}/managedZones");
    let zones = match client
        .list_all(&url, "managedZones", cfg.max_resources)
        .await
    {
        Ok(z) => z,
        Err(e) => {
            note_api_gap(col, target, "Cloud DNS", project, &e);
            return;
        }
    };
    for z in zones.iter().take(cfg.max_resources) {
        let name = z.get("name").and_then(Value::as_str).unwrap_or("zone");
        let visibility = z
            .get("visibility")
            .and_then(Value::as_str)
            .unwrap_or("public");
        if visibility != "public" {
            continue;
        }
        let dnssec = z
            .get("dnssecConfig")
            .and_then(|d| d.get("state"))
            .and_then(Value::as_str)
            .unwrap_or("off");
        if dnssec != "on" {
            col.push(Domain::Network, &format!("Public DNS zone without DNSSEC: {name}"), "medium", "T1565.002", "3.3", target, 0.8,
                &format!("Public managed zone '{name}' in project '{project}' has DNSSEC '{dnssec}'. Without DNSSEC, responses can be spoofed (cache poisoning). Enable DNSSEC and publish DS records at the registrar."),
                Evidence::new().with("zone", name).with("dnssec_state", dnssec).check("dnssecConfig.state", true, dnssec));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// External attack-surface plane (no credentials)
// ─────────────────────────────────────────────────────────────────────────────

async fn scan_external_surface(cfg: &GcpScanConfig, col: &mut Collector<'_>, target: &str) {
    let client = http_client().await;
    let host = extract_host(target);
    let base = if target.starts_with("http") {
        target.trim_end_matches('/').to_string()
    } else {
        format!("https://{}", host.trim_end_matches('/'))
    };

    // 1) GCE metadata reachability is a property of the SCAN ORIGIN (the worker's own
    //    link-local 169.254.x metadata server), never of the customer `target`. Emitting it
    //    as a finding bound to `target` fabricates a critical finding about a resource the
    //    customer does not own and leaks the platform's own project metadata cross-tenant, so
    //    it is recorded only as an internal debug signal — never as a finding, never with body.
    if cfg.check_metadata {
        let metadata_url = "http://metadata.google.internal/computeMetadata/v1/?recursive=true";
        if let Ok(resp) = client
            .get(metadata_url)
            .header("Metadata-Flavor", "Google")
            .timeout(Duration::from_secs(3))
            .send()
            .await
        {
            if resp.status().as_u16() == 200 {
                tracing::debug!(
                    target: "gcp_engine",
                    "scan origin can reach the GCE metadata server (self-host signal, not attributed to target)"
                );
            }
        }
    }

    // 2) Public / dangling GCS buckets (permutation enumeration).
    let candidates = gcs_bucket_candidates(cfg, &host);
    let conc = cfg.concurrency.min(24).max(1);
    let probed: Vec<(String, u16, bool)> = stream::iter(candidates)
        .map(|bucket| {
            let c = client.clone();
            async move {
                let url =
                    format!("https://storage.googleapis.com/storage/v1/b/{bucket}/o?maxResults=1");
                match c.get(&url).send().await {
                    Ok(r) => {
                        let status = r.status().as_u16();
                        let listable = status == 200;
                        Some((bucket, status, listable))
                    }
                    Err(_) => None,
                }
            }
        })
        .buffer_unordered(conc)
        .filter_map(|x| async move { x })
        .collect()
        .await;

    for (bucket, status, listable) in probed {
        if listable {
            col.sig.public_bucket = true;
            col.push(Domain::Data, &format!("Publicly-listable GCS bucket: {bucket}"), "critical", "T1530", "5.1", target, 0.85,
                &format!("Bucket '{bucket}' allows anonymous object listing (HTTP 200 on the JSON list API). Its contents are exposed to the internet. Remove allUsers access and enable public-access prevention."),
                Evidence::new().with("bucket", bucket.clone()).with("status", status as i64).check("storage.objects.list[anon]", true, status as i64));
        } else if status == 401 || status == 403 {
            col.push(Domain::Exposure, &format!("GCS bucket exists (name confirmed): {bucket}"), "low", "T1580", "5.x", target, 0.6,
                &format!("Bucket '{bucket}' exists but denies anonymous listing (HTTP {status}). The name is confirmed, useful for targeted access attempts or subdomain-takeover checks; verify it is owned by you."),
                Evidence::new().with("bucket", bucket).with("status", status as i64).check("bucket_exists", true, status as i64));
        }
    }

    // 3) Leaked SA keys / GCP API keys / credentials in web assets.
    for path in &cfg.web_paths {
        let url = format!("{base}{path}");
        if let Some(probe) = http_get(&client, &url).await {
            if probe.status != 200 || probe.body.len() < 16 {
                continue;
            }
            let is_sa_key = SA_KEY_INDICATORS.iter().any(|ind| probe.body.contains(ind));
            let secrets = detect_secrets(&probe.body);
            if is_sa_key {
                col.sig.leaked_sa_key = true;
                col.push(Domain::Exposure, &format!("Service-account key exposed on the web: {path}"), "critical", "T1552.001", "1.4", target, 0.9,
                    &format!("The file {url} (HTTP 200) contains GCP service-account key material (private_key / client_email / token_uri). This is a directly-usable cloud credential. Revoke the key immediately and remove the file."),
                    Evidence::new().with("url", url.clone()).with("secret_types", json!(secrets)).check("sa_key_indicators", true, "present"));
            } else if !secrets.is_empty() {
                col.push(Domain::Exposure, &format!("Secrets leaked in web asset: {path}"), "high", "T1552", "1.x", target, 0.8,
                    &format!("The file {url} (HTTP 200) leaks credential material: {}. Rotate the affected secrets and remove the exposure.", secrets.join(", ")),
                    Evidence::new().with("url", url).with("secret_types", json!(secrets)).check("detect_secrets", true, secrets.len() as i64));
            }
        }
    }
}

/// Build the GCS bucket-name candidate list from the target host + common suffixes, intensity-scaled.
fn gcs_bucket_candidates(cfg: &GcpScanConfig, host: &str) -> Vec<String> {
    if !cfg.bucket_candidates.is_empty() {
        return cfg.bucket_candidates.clone();
    }
    let labels: Vec<&str> = host.split('.').filter(|p| !p.is_empty()).collect();
    let mut bases: Vec<String> = Vec::new();
    if let Some(first) = labels.first() {
        bases.push((*first).to_string());
    }
    if labels.len() >= 2 {
        bases.push(labels[..labels.len() - 1].join("-"));
        bases.push(labels[..labels.len() - 1].join("."));
        bases.push(labels.join("-"));
    }
    bases.push(host.to_string());
    bases.sort();
    bases.dedup();

    if !cfg.bucket_permutations {
        return bases;
    }

    let mut suffixes: Vec<String> = [
        "",
        "-prod",
        "-dev",
        "-staging",
        "-stage",
        "-test",
        "-backup",
        "-backups",
        "-data",
        "-assets",
        "-static",
        "-public",
        "-private",
        "-uploads",
        "-media",
        "-logs",
        "-bucket",
        "-storage",
        "-files",
        "-images",
        "-config",
        "-secret",
        "-secrets",
        "-tf",
        "-terraform",
        "-artifacts",
        "-build",
        "-cdn",
        "-www",
        "-app",
        "-internal",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    suffixes.extend(cfg.extra_bucket_suffixes.iter().cloned());

    let cap = match cfg.intensity {
        Intensity::Light => 20,
        Intensity::Normal => 70,
        Intensity::Aggressive => cfg.max_buckets,
    };

    let mut out: Vec<String> = Vec::new();
    for base in &bases {
        for suf in &suffixes {
            let name = format!("{base}{suf}");
            // GCS bucket names are 3–63 chars, lowercase, no consecutive dots.
            if name.len() >= 3 && name.len() <= 63 && !out.contains(&name) {
                out.push(name);
            }
            if out.len() >= cap {
                return out;
            }
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Attack-path correlation (toxic combinations)
// ─────────────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn push_attack_path(
    col: &mut Collector<'_>,
    target: &str,
    path_id: &str,
    title: &str,
    mitre: &str,
    confidence: f64,
    steps: &[(&str, String)],
    kill_chain: &[&str],
) {
    let steps_json: Vec<Value> = steps
        .iter()
        .enumerate()
        .map(|(i, (stage, detail))| json!({ "order": i + 1, "stage": stage, "detail": detail }))
        .collect();
    let ev = Evidence::new()
        .with("path_id", path_id)
        .with("kill_chain", json!(kill_chain))
        .with("steps", json!(steps_json));
    let mut f = finding_rich(
        ENGINE_ID,
        title,
        "critical",
        mitre,
        &format!("Attack path (toxic combination of real, observed exposures): {title}"),
        target,
        confidence,
        ev,
    );
    if let Some(o) = f.as_object_mut() {
        o.insert("category".to_string(), json!("attack_path"));
        o.insert("attack_path".to_string(), json!(true));
        o.insert("domain".to_string(), json!("posture"));
        o.insert("path_id".to_string(), json!(path_id));
    }
    col.findings.push(f);
}

fn synthesize_attack_paths(col: &mut Collector<'_>, target: &str) {
    let s = &col.sig;
    let (
        public_instance,
        token_theft,
        open_admin,
        public_bucket,
        leaked_key,
        public_gke,
        gke_weak,
        public_sql,
        sql_no_ssl,
        project_public,
        impersonation,
        public_fn,
        public_run,
        public_ds,
    ) = (
        s.public_instance,
        s.instance_token_theft,
        s.open_admin_port,
        s.public_bucket,
        s.leaked_sa_key,
        s.public_gke_endpoint,
        s.gke_weak_auth,
        s.public_sql,
        s.sql_no_ssl,
        s.project_public_iam,
        s.sa_impersonation,
        s.public_function,
        s.public_run,
        s.public_dataset,
    );

    if token_theft || (public_instance && open_admin) {
        push_attack_path(col, target, "gce_token_theft",
            "Public VM → metadata SSRF → service-account token → project takeover", "T1552.005", 0.9,
            &[
                ("Initial Access", "Reach the internet-exposed Compute Engine instance (public IP / open admin port)".to_string()),
                ("Execution", "Trigger SSRF or RCE on the workload running on the instance".to_string()),
                ("Credential Access", "Read http://metadata.google.internal/.../token to steal the attached service account's OAuth2 token".to_string()),
                ("Privilege Escalation", "Use the cloud-platform-scoped token to act across the project".to_string()),
                ("Impact", "Read every bucket, secret and database the service account can reach — full project compromise".to_string()),
            ],
            &["Initial Access", "Execution", "Credential Access", "Privilege Escalation", "Impact"]);
    }
    if public_bucket && leaked_key {
        push_attack_path(
            col,
            target,
            "public_bucket_key_chain",
            "Public storage → leaked service-account key → authenticated project access",
            "T1530",
            0.88,
            &[
                (
                    "Collection",
                    "Enumerate the publicly-listable Cloud Storage bucket".to_string(),
                ),
                (
                    "Credential Access",
                    "Download the service-account JSON key found in the public bucket / web asset"
                        .to_string(),
                ),
                (
                    "Privilege Escalation",
                    "Authenticate with the key to obtain the SA's project permissions".to_string(),
                ),
                (
                    "Impact",
                    "Pivot from anonymous read to authenticated control of the SA's resources"
                        .to_string(),
                ),
            ],
            &[
                "Collection",
                "Credential Access",
                "Privilege Escalation",
                "Impact",
            ],
        );
    }
    if public_gke && gke_weak {
        push_attack_path(col, target, "gke_public_takeover",
            "Public GKE endpoint + weak control-plane auth → cluster & node-SA takeover", "T1190", 0.87,
            &[
                ("Initial Access", "Reach the public GKE API endpoint (no master authorized networks)".to_string()),
                ("Privilege Escalation", "Abuse legacy ABAC / basic-auth / client-cert to gain cluster-admin".to_string()),
                ("Credential Access", "Deploy a pod that reads the node service account token from the metadata server".to_string()),
                ("Impact", "Control every workload, secret and node — and pivot into the project via the node SA".to_string()),
            ],
            &["Initial Access", "Privilege Escalation", "Credential Access", "Impact"]);
    }
    if public_sql {
        let extra = if sql_no_ssl {
            " over an unencrypted channel (credentials sniffable)"
        } else {
            ""
        };
        push_attack_path(col, target, "public_sql_breach",
            "Internet-exposed Cloud SQL → direct database breach", "T1190", 0.86,
            &[
                ("Initial Access", format!("Connect to the Cloud SQL instance reachable from 0.0.0.0/0{extra}")),
                ("Credential Access", "Brute-force / reuse database credentials, or sniff them if SSL is not required".to_string()),
                ("Collection", "Exfiltrate the database contents".to_string()),
                ("Impact", "Confidential data breach".to_string()),
            ],
            &["Initial Access", "Credential Access", "Collection", "Impact"]);
    }
    if project_public {
        push_attack_path(
            col,
            target,
            "project_public_iam_takeover",
            "Public IAM binding → anyone obtains project-level access",
            "T1078.004",
            0.95,
            &[
                (
                    "Initial Access",
                    "Authenticate as any (or any Google) account".to_string(),
                ),
                (
                    "Privilege Escalation",
                    "Inherit the role granted to allUsers/allAuthenticatedUsers on the project"
                        .to_string(),
                ),
                (
                    "Impact",
                    "Operate within the project at the granted role with no targeting required"
                        .to_string(),
                ),
            ],
            &["Initial Access", "Privilege Escalation", "Impact"],
        );
    }
    if impersonation {
        push_attack_path(col, target, "sa_impersonation_chain",
            "Service-account impersonation rights → privilege-escalation chain", "T1548", 0.82,
            &[
                ("Discovery", "Identify the principal holding serviceAccountTokenCreator / serviceAccountUser".to_string()),
                ("Privilege Escalation", "Mint tokens for / actAs a higher-privileged service account".to_string()),
                ("Impact", "Operate with the target SA's elevated permissions".to_string()),
            ],
            &["Discovery", "Privilege Escalation", "Impact"]);
    }
    if (public_fn || public_run) && impersonation {
        push_attack_path(
            col,
            target,
            "public_serverless_pivot",
            "Public serverless endpoint + impersonation → run code as a privileged SA",
            "T1190",
            0.8,
            &[
                (
                    "Initial Access",
                    "Invoke the unauthenticated Cloud Function / Cloud Run service".to_string(),
                ),
                (
                    "Execution",
                    "Abuse the endpoint (SSRF/injection) to act from inside the project network"
                        .to_string(),
                ),
                (
                    "Privilege Escalation",
                    "Leverage actAs / token-creator rights to assume a privileged service account"
                        .to_string(),
                ),
                (
                    "Impact",
                    "Broad project access from an initially-anonymous entry point".to_string(),
                ),
            ],
            &[
                "Initial Access",
                "Execution",
                "Privilege Escalation",
                "Impact",
            ],
        );
    }
    if public_ds {
        push_attack_path(
            col,
            target,
            "public_bigquery_exfil",
            "Public BigQuery dataset → analytics data exfiltration",
            "T1530",
            0.8,
            &[
                (
                    "Discovery",
                    "Query the publicly-accessible BigQuery dataset".to_string(),
                ),
                (
                    "Collection",
                    "Export tables containing potentially sensitive analytics / PII".to_string(),
                ),
                ("Impact", "Confidential data exposure".to_string()),
            ],
            &["Discovery", "Collection", "Impact"],
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Posture summary (security graph + scores)
// ─────────────────────────────────────────────────────────────────────────────

fn build_posture_summary(
    col: &Collector<'_>,
    target: &str,
    projects: &[String],
    authed: bool,
) -> Value {
    let findings = &col.findings;
    let mut crit = 0u32;
    let mut high = 0u32;
    let mut med = 0u32;
    let mut low = 0u32;
    let mut attack_paths = 0u32;
    for f in findings {
        if f.get("attack_path")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            attack_paths += 1;
            continue;
        }
        match finding_sev(f).as_str() {
            "critical" => crit += 1,
            "high" => high += 1,
            "medium" => med += 1,
            "low" => low += 1,
            _ => {}
        }
    }

    let score = posture_score(findings);
    let grade = grade_for(score);

    let mut surfaces: Vec<&str> = Vec::new();
    for n in &col.nodes {
        if let Some(kind) = n.get("type").and_then(Value::as_str) {
            if kind != "root" && !surfaces.contains(&kind) {
                surfaces.push(kind);
            }
        }
    }

    let domain_scores = json!({
        "identity": domain_score(findings, Domain::Identity),
        "data": domain_score(findings, Domain::Data),
        "network": domain_score(findings, Domain::Network),
        "exposure": domain_score(findings, Domain::Exposure),
    });

    let planes = if authed { 2 } else { 1 };
    let ev = Evidence::new()
        .with("exposure_score", (100.0 - score).round())
        .with("posture_score", score.round())
        .with("posture_grade", grade)
        .with("domain_scores", domain_scores)
        .with(
            "severity_counts",
            json!({ "critical": crit, "high": high, "medium": med, "low": low }),
        )
        .with("attack_paths", attack_paths)
        .with("projects_scanned", json!(projects))
        .with("planes", planes)
        .with("surfaces_detected", json!(surfaces))
        .with("graph", json!({ "nodes": col.nodes, "edges": col.edges }));

    let mut f = finding_rich(
        ENGINE_ID,
        &format!(
            "GCP cloud posture: grade {grade} ({}/100), {attack_paths} attack path(s)",
            score.round()
        ),
        "info",
        "",
        "Aggregated GCP cloud-security posture for the target, derived entirely from the real services observed during this scan. The security graph and attack paths summarise how the individual exposures chain together. Mapped to the CIS Google Cloud Foundations Benchmark and MITRE ATT&CK.",
        target,
        1.0,
        ev,
    );
    if let Some(o) = f.as_object_mut() {
        o.insert("category".to_string(), json!("posture_summary"));
        o.insert("domain".to_string(), json!("posture"));
    }
    f
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_from(v: Value) -> GcpScanConfig {
        GcpScanConfig::from_arsenal(&ArsenalConfig::from_value(v))
    }

    #[test]
    fn config_defaults_run_external_only() {
        let c = cfg_from(json!({}));
        assert!(c.enable_external);
        assert!(!c.credentialed_ready());
        assert!(c.check_iam && c.check_storage && c.check_gke);
        assert_eq!(c.min_severity, "info");
    }

    #[test]
    fn config_reads_credentials_and_toggles() {
        let c = cfg_from(json!({
            "gcp_access_token": "ya29.test", // nosemgrep
            "gcp_project_id": "demo-proj",
            "check_gke": false,
            "intensity": "aggressive",
            "min_confidence": 0.5
        }));
        assert!(c.credentialed_ready());
        assert!(c.project_ids.contains(&"demo-proj".to_string()));
        assert!(!c.check_gke);
        assert_eq!(c.intensity, Intensity::Aggressive);
        assert!((c.min_confidence - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn service_account_key_parsed_from_string() {
        let key = json!({"type":"service_account","client_email":"x@y.iam.gserviceaccount.com","private_key":"PEM"}); // nosemgrep
        let c = cfg_from(json!({ "gcp_service_account_key": key.to_string() }));
        assert!(c.service_account_key.is_some());
        assert!(c.credentialed_ready());
    }

    #[test]
    fn privesc_role_table_covers_impersonation_and_owner() {
        assert!(PRIVESC_ROLES
            .iter()
            .any(|(r, _, s)| *r == "roles/owner" && *s == "critical"));
        assert!(PRIVESC_ROLES
            .iter()
            .any(|(r, _, _)| *r == "roles/iam.serviceAccountTokenCreator"));
    }

    #[test]
    fn google_managed_agents_are_excluded() {
        assert!(is_google_managed_agent(
            "serviceAccount:service-123@gcp-sa-pubsub.iam.gserviceaccount.com"
        ));
        assert!(is_google_managed_agent(
            "serviceAccount:123@cloudservices.gserviceaccount.com"
        ));
        assert!(!is_google_managed_agent("user:alice@example.com"));
    }

    #[test]
    fn dangerous_port_parsing() {
        assert_eq!(parse_port_spec("22"), vec![22]);
        assert_eq!(parse_port_spec("80-82"), vec![80, 81, 82]);
        assert!(parse_port_spec("not-a-port").is_empty());
    }

    #[test]
    fn scoring_and_grade() {
        let findings = vec![
            json!({"severity":"critical","domain":"identity"}),
            json!({"severity":"high","domain":"network"}),
        ];
        let s = posture_score(&findings);
        assert!(s < 70.0 && s > 60.0); // 100 - 20 - 11 = 69
        assert_eq!(grade_for(s), "C");
        assert_eq!(grade_for(100.0), "A+");
        assert_eq!(grade_for(0.0), "F");
    }

    #[test]
    fn attack_paths_require_real_signals() {
        let cfg = cfg_from(json!({}));
        let mut col = Collector::new(&cfg);
        col.sig.public_instance = true;
        col.sig.open_admin_port = true;
        synthesize_attack_paths(&mut col, "t");
        assert!(col
            .findings
            .iter()
            .any(|f| f.get("category").and_then(Value::as_str) == Some("attack_path")));

        let cfg2 = cfg_from(json!({}));
        let mut clean = Collector::new(&cfg2);
        synthesize_attack_paths(&mut clean, "t");
        assert!(clean.findings.is_empty());
    }

    #[test]
    fn iam_public_member_detection() {
        let iam =
            json!({"bindings":[{"role":"roles/cloudfunctions.invoker","members":["allUsers"]}]});
        assert!(iam_has_public_member(&iam));
        let priv_iam = json!({"bindings":[{"role":"roles/x","members":["user:a@b.com"]}]});
        assert!(!iam_has_public_member(&priv_iam));
    }

    #[test]
    fn bucket_candidates_respect_overrides_and_bounds() {
        let c = cfg_from(json!({ "bucket_candidates": ["only-this-one"] }));
        assert_eq!(
            gcs_bucket_candidates(&c, "example.com"),
            vec!["only-this-one".to_string()]
        );

        let c2 = cfg_from(json!({ "intensity": "light" }));
        let cands = gcs_bucket_candidates(&c2, "example.com");
        assert!(!cands.is_empty() && cands.len() <= 20);
        assert!(cands.iter().all(|b| b.len() >= 3 && b.len() <= 63));
    }
}
