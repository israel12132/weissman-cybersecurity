//! Azure Attack Engine — world-class **agentless Azure Cloud Security Posture (CSPM)** engine.
//!
//! The Microsoft-Azure counterpart to the platform's AWS CSPM module, modelled on the agentless
//! cloud-scanning approach pioneered by Wiz / the top-tier CNAPP vendors and pushed further: every
//! finding is backed by a **real API call** (no simulated posture), carries a granular [`Evidence`]
//! trail, and the engine performs **attack-path / toxic-combination correlation** (the "security
//! graph" differentiator) so the operator sees the chains that lead from the internet to a full
//! subscription compromise — not just isolated misconfigurations.
//!
//! ## Two operating modes (auto-selected from the scan request)
//!
//! * **Agentless authenticated posture scan** — when the operator supplies an Azure AD service
//!   principal (`tenant_id` + `client_id` + `client_secret`), the engine performs the OAuth2
//!   client-credentials flow and queries the live **Azure Resource Manager** REST API across the
//!   accessible subscriptions:
//!     - **Identity / RBAC** — subscription-scope `Owner` / `User Access Administrator` sprawl.
//!     - **Storage** — anonymous blob public-access, HTTP (non-TLS) traffic allowed, weak minimum
//!       TLS, and `networkAcls.defaultAction = Allow` (open to every network).
//!     - **Network** — NSG inbound rules opening sensitive management / data ports to `Internet` /
//!       `*` / `0.0.0.0/0`, correlated with allocated public IPs.
//!     - **SQL** — servers with public network access enabled and `0.0.0.0` firewall rules.
//!     - **Key Vault** — public network access, missing soft-delete / purge-protection.
//!     - **Defender for Cloud** — subscriptions left on the Free tier (no workload protection).
//!     - **Azure Resource Graph (ARG)** — cross-subscription KQL discovery of public storage, ACR
//!       admin users, public AKS API servers, and public Cosmos DB accounts in one shot.
//!     - **ACR / AKS / App Service / Cosmos / Compute** — container registry admin user, public
//!       Kubernetes API, remote debugging / FTPS / HTTP-only web apps, public Cosmos DB, and disks
//!       without encryption at rest.
//!   Then it **correlates** these facts into ranked attack paths and optionally emits a **security
//!   graph** + **0–100 posture score** (Wiz-class CNAPP output).
//!
//! * **Unauthenticated external surface scan** — when no credentials are supplied, the engine falls
//!   back to honest remote-only probing of the target: Azure AD tenant discovery, public Blob
//!   container enumeration (`*.blob.core.windows.net`), **Azure subdomain takeover** (dangling CNAME
//!   to azurewebsites.net / blob / Front Door / Traffic Manager), and leaked Azure key material /
//!   SAS tokens in web assets. It never probes the scanner host's own IMDS.
//!
//! **Every knob is operator-controllable from the GUI** (`POST /api/command-center/scan` →
//! `job_params`): credentials, subscription scope, which service checks to run, sensitive-port set,
//! intensity, sovereign-cloud endpoints, and per-resource caps. Nothing is hidden or fabricated.
//!
//! MITRE: T1078.004 (Valid Cloud Accounts), T1530 (Data from Cloud Storage), T1580 (Cloud Infra
//! Discovery), T1552 (Unsecured Credentials), T1190 (Exploit Public-Facing Application).

use crate::arsenal_config::{finding_rich, severity_for_score, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{
    detect_secrets, dns_a, extract_host, header_value, http_client, http_get, join_url,
    normalize_url,
};
use crate::engine_result::{print_result, EngineResult};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::Duration;

const ENGINE_ID: &str = "azure_attack";
const DEFAULT_ARM: &str = "https://management.azure.com";
const DEFAULT_LOGIN: &str = "https://login.microsoftonline.com";

/// Well-known privileged Azure RBAC role-definition GUIDs.
const ROLE_OWNER: &str = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635";
const ROLE_USER_ACCESS_ADMIN: &str = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9";
const ROLE_CONTRIBUTOR: &str = "b24988ac-6180-42a0-ab88-20f7382dd24c";

/// Sensitive service ports — exposure to the internet on any of these is a real risk.
/// `(port, service label, MITRE technique)`.
const SENSITIVE_PORTS: &[(u16, &str, &str)] = &[
    (22, "SSH", "T1021.004"),
    (3389, "RDP", "T1021.001"),
    (23, "Telnet", "T1021"),
    (445, "SMB", "T1021.002"),
    (135, "WinRM/MSRPC", "T1021"),
    (5985, "WinRM HTTP", "T1021.006"),
    (5986, "WinRM HTTPS", "T1021.006"),
    (3306, "MySQL", "T1210"),
    (5432, "PostgreSQL", "T1210"),
    (1433, "Azure SQL / MSSQL", "T1210"),
    (1521, "Oracle DB", "T1210"),
    (27017, "MongoDB / Cosmos Mongo", "T1210"),
    (6379, "Redis", "T1210"),
    (9200, "Elasticsearch", "T1210"),
    (5601, "Kibana", "T1210"),
    (2375, "Docker API (unauth)", "T1610"),
    (6443, "Kubernetes API", "T1610"),
];

const AZURE_WEB_PATHS: &[&str] = &[
    "/.azure/credentials",
    "/azure-credentials.json",
    "/.env",
    "/.env.azure",
    "/appsettings.json",
    "/appsettings.Production.json",
    "/web.config",
    "/azure-pipelines.yml",
    "/.publishsettings",
    "/local.settings.json",
];

/// Azure storage connection-string / SAS indicators (high-precision, not generic `=`).
const SAS_INDICATORS: &[&str] = &[
    "blob.core.windows.net",
    "AccountKey=",
    "SharedAccessSignature",
    "DefaultEndpointsProtocol=",
    "?sv=20",
];

/// Common blob container names to test for public anonymous listing.
const COMMON_CONTAINERS: &[&str] = &[
    "backup",
    "backups",
    "data",
    "public",
    "files",
    "uploads",
    "images",
    "media",
    "logs",
    "$web",
    "documents",
    "config",
    "assets",
    "static",
    "db",
    "dump",
];

/// Azure-specific dangling-CNAME takeover fingerprints (external scan).
const AZURE_TAKEOVER_SUFFIXES: &[(&str, &str)] = &[
    (".azurewebsites.net", "Azure App Service"),
    (".cloudapp.net", "Azure Cloud Service"),
    (".trafficmanager.net", "Azure Traffic Manager"),
    (".blob.core.windows.net", "Azure Blob Storage"),
    (".azurefd.net", "Azure Front Door"),
    (".database.windows.net", "Azure SQL"),
    (".redis.cache.windows.net", "Azure Cache for Redis"),
];

const DEFAULT_TAKEOVER_SUBDOMAINS: &[&str] = &[
    "www", "api", "app", "dev", "staging", "test", "portal", "cdn", "assets", "static", "mail",
    "blog", "shop", "admin",
];

// ─────────────────────────────────────────────────────────────────────────────
// Pure helpers (unit-tested; no network)
// ─────────────────────────────────────────────────────────────────────────────

/// True when an NSG/SQL source prefix means "the whole internet".
#[must_use]
pub fn is_internet_source(prefix: &str) -> bool {
    matches!(
        prefix.trim().to_ascii_lowercase().as_str(),
        "*" | "0.0.0.0/0" | "internet" | "::/0" | "any"
    )
}

/// Human label + MITRE technique for a sensitive port, if it is one.
#[must_use]
pub fn sensitive_port_meta(port: u16) -> Option<(&'static str, &'static str)> {
    SENSITIVE_PORTS
        .iter()
        .find(|(p, _, _)| *p == port)
        .map(|(_, label, mitre)| (*label, *mitre))
}

/// Parse a single NSG port token (`"22"`, `"1000-2000"`, `"*"`) into an inclusive range.
#[must_use]
pub fn parse_port_token(tok: &str) -> Option<(u32, u32)> {
    let t = tok.trim();
    if t == "*" {
        return Some((0, 65_535));
    }
    if let Some((lo, hi)) = t.split_once('-') {
        let lo = lo.trim().parse::<u32>().ok()?;
        let hi = hi.trim().parse::<u32>().ok()?;
        return Some((lo.min(hi), lo.max(hi)));
    }
    let p = t.parse::<u32>().ok()?;
    Some((p, p))
}

/// Given the destination port tokens + protocol of an inbound Allow rule, return the sensitive
/// ports it exposes. Protocol `*`/`tcp` can expose TCP services; `udp` cannot.
#[must_use]
pub fn sensitive_ports_for_rule(tokens: &[String], protocol: &str, sensitive: &[u16]) -> Vec<u16> {
    let proto = protocol.trim().to_ascii_lowercase();
    if proto != "*" && proto != "tcp" && !proto.is_empty() {
        return Vec::new();
    }
    let ranges: Vec<(u32, u32)> = tokens.iter().filter_map(|t| parse_port_token(t)).collect();
    sensitive
        .iter()
        .copied()
        .filter(|p| {
            let pp = u32::from(*p);
            ranges.iter().any(|(lo, hi)| pp >= *lo && pp <= *hi)
        })
        .collect()
}

/// True when an ARM role-definition id is a high-privilege (Owner / User-Access-Admin) role.
#[must_use]
pub fn is_high_priv_role(role_def_id: &str) -> bool {
    let id = role_def_id.to_ascii_lowercase();
    id.ends_with(ROLE_OWNER) || id.ends_with(ROLE_USER_ACCESS_ADMIN)
}

/// Extract the destination-port tokens of an NSG security rule (single + plural forms).
fn rule_port_tokens(props: &Value) -> Vec<String> {
    let mut toks = Vec::new();
    if let Some(s) = props.get("destinationPortRange").and_then(Value::as_str) {
        if !s.is_empty() {
            toks.push(s.to_string());
        }
    }
    if let Some(arr) = props.get("destinationPortRanges").and_then(Value::as_array) {
        for v in arr {
            if let Some(s) = v.as_str() {
                toks.push(s.to_string());
            }
        }
    }
    toks
}

/// Collect the source address prefixes of a rule (single + plural).
fn rule_source_prefixes(props: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(s) = props.get("sourceAddressPrefix").and_then(Value::as_str) {
        out.push(s.to_string());
    }
    if let Some(arr) = props.get("sourceAddressPrefixes").and_then(Value::as_array) {
        for v in arr {
            if let Some(s) = v.as_str() {
                out.push(s.to_string());
            }
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Collected facts → attack-path correlation
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct AzureFacts {
    tenant_id: Option<String>,
    subscriptions: Vec<String>,
    public_storage: Vec<String>,
    insecure_transport_storage: Vec<String>,
    open_storage_networks: Vec<String>,
    world_open_admin_nsgs: Vec<String>,
    public_ips: usize,
    public_sql: Vec<String>,
    public_keyvaults: Vec<String>,
    owner_assignments: usize,
    defender_free_subs: Vec<String>,
    acr_admin_enabled: Vec<String>,
    public_aks: Vec<String>,
    risky_appservice: Vec<String>,
    public_cosmos: Vec<String>,
    unencrypted_disks: Vec<String>,
}

fn attack_path_finding(
    title: &str,
    severity: &str,
    target: &str,
    steps: &[&str],
    mitre: &str,
    description: &str,
    toxic_combo: &str,
    confidence: f64,
    ev_extra: Evidence,
) -> Value {
    let ev = ev_extra
        .with("kind", "attack_path")
        .with("toxic_combination", toxic_combo)
        .with("steps", json!(steps))
        .check("correlation", true, format!("{}-step chain", steps.len()));
    let mut f = finding_rich(
        ENGINE_ID,
        title,
        severity,
        mitre,
        description,
        target,
        confidence,
        ev,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("category".to_string(), json!("attack_path"));
        obj.insert("attack_path".to_string(), json!(true));
        obj.insert("steps".to_string(), json!(steps));
        obj.insert("toxic_combination".to_string(), json!(toxic_combo));
        obj.insert("domain".to_string(), json!("azure_posture"));
    }
    f
}

fn sev_weight(sev: &str) -> f64 {
    match sev.to_ascii_lowercase().as_str() {
        "critical" => 22.0,
        "high" => 12.0,
        "medium" => 5.0,
        "low" => 1.5,
        _ => 0.0,
    }
}

fn finding_sev(f: &Value) -> String {
    f.get("severity")
        .and_then(Value::as_str)
        .unwrap_or("info")
        .to_string()
}

fn posture_score(findings: &[Value]) -> f64 {
    let penalty: f64 = findings
        .iter()
        .filter(|f| f.get("attack_path").and_then(Value::as_bool) != Some(true))
        .filter(|f| {
            !f.get("title")
                .and_then(Value::as_str)
                .is_some_and(|t| t.contains("posture summary"))
        })
        .map(|f| sev_weight(&finding_sev(f)))
        .sum();
    (100.0 - penalty).clamp(0.0, 100.0)
}

fn letter_grade(score: f64) -> &'static str {
    match score.round() as i64 {
        95..=100 => "A+",
        90..=94 => "A",
        85..=89 => "A-",
        75..=84 => "B",
        65..=74 => "C",
        50..=64 => "D",
        _ => "F",
    }
}

#[derive(Clone, Debug)]
struct GraphNode {
    id: String,
    kind: String,
    region: String,
    exposure: String,
    risk_tags: Vec<String>,
}

#[derive(Clone, Debug)]
struct GraphEdge {
    from: String,
    to: String,
    rel: String,
}

#[derive(Default)]
struct SecurityGraph {
    nodes: BTreeMap<String, GraphNode>,
    edges: Vec<GraphEdge>,
}

impl SecurityGraph {
    fn upsert(&mut self, id: &str, kind: &str, scope: &str, exposure: &str, tags: &[&str]) {
        let node = self
            .nodes
            .entry(id.to_string())
            .or_insert_with(|| GraphNode {
                id: id.to_string(),
                kind: kind.to_string(),
                region: scope.to_string(),
                exposure: exposure.to_string(),
                risk_tags: Vec::new(),
            });
        for t in tags {
            if !node.risk_tags.iter().any(|x| x == t) {
                node.risk_tags.push((*t).to_string());
            }
        }
        if exposure == "internet" {
            node.exposure = "internet".to_string();
        }
    }

    fn link(&mut self, from: &str, to: &str, rel: &str) {
        self.edges.push(GraphEdge {
            from: from.to_string(),
            to: to.to_string(),
            rel: rel.to_string(),
        });
    }

    fn to_json(&self) -> Value {
        json!({
            "node_count": self.nodes.len(),
            "edge_count": self.edges.len(),
            "nodes": self.nodes.values().map(|n| json!({
                "id": n.id,
                "kind": n.kind,
                "scope": n.region,
                "exposure": n.exposure,
                "risk_tags": n.risk_tags,
            })).collect::<Vec<_>>(),
            "edges": self.edges.iter().map(|e| json!({
                "from": e.from,
                "to": e.to,
                "relationship": e.rel,
            })).collect::<Vec<_>>(),
        })
    }
}

fn correlate_attack_paths(f: &AzureFacts, target: &str) -> Vec<Value> {
    let mut out = Vec::new();

    // 1. Internet-reachable management/data port + public IPs in the subscription.
    if !f.world_open_admin_nsgs.is_empty() && f.public_ips > 0 {
        let ev = Evidence::new()
            .with("world_open_nsgs", json!(f.world_open_admin_nsgs))
            .with("public_ip_count", f.public_ips as u64);
        out.push(attack_path_finding(
            "Attack path: internet → exposed SSH/RDP/DB port → host compromise",
            "high",
            target,
            &[
                "Attacker scans public IPs in the subscription",
                "NSG allows Internet/* to SSH/RDP/DB ports",
                "Brute-force or exploit yields shell / DB access",
                "Lateral movement toward Key Vault, storage and AKS",
            ],
            "T1190",
            "Network Security Group rules allow the whole internet (Internet / * / 0.0.0.0/0) to \
             reach management or database ports, and the subscription has public IPs allocated. This \
             is a direct brute-force / exploit ingress and lateral-movement launch point. Scope NSG \
             source to a bastion / VPN prefix and place data services behind Private Endpoints.",
            "internet_nsg_plus_public_ip",
            0.82,
            ev,
        ));
    }

    // 2. Publicly exposed storage, worse without HTTPS-only.
    if !f.public_storage.is_empty() {
        let unprotected: Vec<String> = f
            .public_storage
            .iter()
            .filter(|s| f.insecure_transport_storage.contains(*s))
            .cloned()
            .collect();
        let sev = if unprotected.is_empty() {
            "high"
        } else {
            "critical"
        };
        let ev = Evidence::new()
            .with("public_storage_accounts", json!(f.public_storage))
            .with("public_and_cleartext", json!(unprotected));
        let mut steps = vec![
            "Attacker enumerates public blob containers (no auth)",
            "Sensitive backups / configs / keys downloaded",
        ];
        if !unprotected.is_empty() {
            steps.push("Cleartext HTTP enables SAS / credential interception");
        }
        out.push(attack_path_finding(
            "Attack path: anonymous internet → public Azure Blob storage",
            sev,
            target,
            &steps,
            "T1530",
            "Storage accounts allow anonymous blob access or accept traffic from every network. \
             Combined with non-TLS (HTTP) access this is a turnkey data-breach and tampering target. \
             Set allowBlobPublicAccess=false, networkAcls.defaultAction=Deny + Private Endpoints, and \
             supportsHttpsTrafficOnly=true with TLS 1.2 minimum.",
            "public_storage_cleartext",
            0.88,
            ev,
        ));
    }

    // 3. Subscription privilege sprawl.
    if f.owner_assignments >= 5 {
        let ev = Evidence::new().with("owner_or_uaa_assignments", f.owner_assignments as u64);
        out.push(attack_path_finding(
            "Attack path: Owner-role sprawl → one phished principal = subscription takeover",
            "high",
            target,
            &[
                "Attacker phishes / steals credentials for any Owner principal",
                "Owner grants themselves persistent access and disables logging",
                "Full subscription compromise including Key Vault and storage",
            ],
            "T1078.004",
            "An unusually large number of principals hold Owner / User Access Administrator at \
             subscription scope. Each is a single-compromise path to full control (including \
             granting themselves more access and disabling logging). Apply PIM just-in-time \
             elevation, remove standing Owner rights, and enforce phishing-resistant MFA.",
            "owner_sprawl",
            0.75,
            ev,
        ));
    }

    // 4. SQL public exposure.
    if !f.public_sql.is_empty() {
        let ev = Evidence::new().with("public_sql_servers", json!(f.public_sql));
        out.push(attack_path_finding(
            "Attack path: internet → public Azure SQL server",
            "critical",
            target,
            &[
                "Attacker discovers public SQL endpoint",
                "Credential spray / SQL injection against exposed server",
                "Database dump → lateral movement via stored secrets",
            ],
            "T1190",
            "Azure SQL servers permit public network access (and in some cases a 0.0.0.0 'allow Azure \
             services' / open firewall rule). This exposes the database directly to credential \
             attacks and SQL exploitation from the internet. Disable public network access and use \
             Private Endpoints; never use 0.0.0.0–255.255.255.255 firewall rules.",
            "public_sql",
            0.85,
            ev,
        ));
    }

    // 5. Key Vault public exposure.
    if !f.public_keyvaults.is_empty() {
        let ev = Evidence::new().with("public_key_vaults", json!(f.public_keyvaults));
        out.push(attack_path_finding(
            "Attack path: internet → Key Vault (secret theft / irreversible destruction)",
            "high",
            target,
            &[
                "Attacker compromises any identity with Key Vault access",
                "Public network path reaches the vault without Private Endpoint friction",
                "Secrets exfiltrated; without purge protection, permanent destruction possible",
            ],
            "T1552",
            "Key Vaults allow public network access and/or lack purge protection. A compromised \
             identity can exfiltrate every secret/key/certificate, and without purge protection an \
             attacker can permanently destroy them. Restrict network access to Private Endpoints and \
             enable soft-delete + purge protection.",
            "public_keyvault",
            0.72,
            ev,
        ));
    }

    // 6. Public AKS API + ACR admin user (container supply-chain takeover).
    if !f.public_aks.is_empty() && !f.acr_admin_enabled.is_empty() {
        let ev = Evidence::new()
            .with("public_aks_clusters", json!(f.public_aks))
            .with("acr_admin_registries", json!(f.acr_admin_enabled));
        out.push(attack_path_finding(
            "Attack path: public AKS API + ACR admin → cluster / supply-chain takeover",
            "critical",
            target,
            &[
                "Attacker reaches a public Kubernetes API server (no private cluster / no IP allow-list)",
                "ACR admin credentials push a malicious container image",
                "Workloads pull poisoned image → cluster-wide compromise",
            ],
            "T1610",
            "A Kubernetes cluster exposes its API server to the internet while at least one Container \
             Registry has the legacy admin user enabled. This is the classic CNAPP toxic combination: \
             push malicious images and execute in-cluster. Disable ACR admin user, enable private AKS \
             clusters + authorized IP ranges, and use workload identity / ACR token auth.",
            "public_aks_acr_admin",
            0.9,
            ev,
        ));
    }

    // 7. Risky App Service (remote debug / FTPS) + public storage.
    if !f.risky_appservice.is_empty() && !f.public_storage.is_empty() {
        let ev = Evidence::new()
            .with("risky_app_services", json!(f.risky_appservice))
            .with("public_storage_accounts", json!(f.public_storage));
        out.push(attack_path_finding(
            "Attack path: App Service remote debug / FTPS → storage data theft",
            "high",
            target,
            &[
                "Attacker exploits FTPS-all-allowed or enabled remote debugging on App Service",
                "Gains code / connection-string access from the web app slot",
                "Pivot to publicly exposed blob storage for mass exfiltration",
            ],
            "T1190",
            "An internet-facing App Service permits remote debugging or unrestricted FTPS while blob \
             storage is publicly accessible. Application connection strings and SAS tokens in the app \
             become a direct path to data theft. Disable remote debugging, restrict FTPS, and lock down \
             storage network ACLs.",
            "appservice_debug_public_storage",
            0.78,
            ev,
        ));
    }

    // 8. Public Cosmos DB (NoSQL data plane from internet).
    if !f.public_cosmos.is_empty() && f.public_ips > 0 {
        let ev = Evidence::new()
            .with("public_cosmos_accounts", json!(f.public_cosmos))
            .with("public_ip_count", f.public_ips as u64);
        out.push(attack_path_finding(
            "Attack path: internet → public Cosmos DB account",
            "critical",
            target,
            &[
                "Cosmos DB account accepts public network connections",
                "Attacker brute-forces keys or exploits misconfigured RBAC",
                "Full document/SQL API data exfiltration",
            ],
            "T1530",
            "Azure Cosmos DB accounts with public network access are directly reachable from the \
             internet. Combined with allocated public IPs in the same subscription this indicates \
             an active external attack surface. Disable public network access and use Private \
             Endpoints + Azure AD RBAC.",
            "public_cosmos",
            0.86,
            ev,
        ));
    }

    out
}

fn posture_summary(
    f: &AzureFacts,
    findings_so_far: &[Value],
    target: &str,
    graph: &SecurityGraph,
    include_score: bool,
    include_graph: bool,
) -> Value {
    let mut sev_counts = BTreeMap::<String, u64>::new();
    for fnd in findings_so_far {
        let s = finding_sev(fnd);
        *sev_counts.entry(s).or_insert(0) += 1;
    }
    let attack_path_count = findings_so_far
        .iter()
        .filter(|f| f.get("attack_path").and_then(Value::as_bool) == Some(true))
        .count();
    let score = posture_score(findings_so_far);
    let grade = letter_grade(score);
    let crit = findings_so_far
        .iter()
        .filter(|f| finding_sev(f) == "critical")
        .count();

    let mut ev = Evidence::new()
        .with("tenant_id", f.tenant_id.clone().unwrap_or_default())
        .with("subscriptions_scanned", json!(f.subscriptions))
        .with("public_storage_accounts", f.public_storage.len() as u64)
        .with(
            "insecure_transport_storage",
            f.insecure_transport_storage.len() as u64,
        )
        .with("open_network_storage", f.open_storage_networks.len() as u64)
        .with("world_open_nsgs", f.world_open_admin_nsgs.len() as u64)
        .with("public_ips", f.public_ips as u64)
        .with("public_sql_servers", f.public_sql.len() as u64)
        .with("public_key_vaults", f.public_keyvaults.len() as u64)
        .with("owner_assignments", f.owner_assignments as u64)
        .with("acr_admin_registries", f.acr_admin_enabled.len() as u64)
        .with("public_aks_clusters", f.public_aks.len() as u64)
        .with("risky_app_services", f.risky_appservice.len() as u64)
        .with("public_cosmos_accounts", f.public_cosmos.len() as u64)
        .with("unencrypted_disks", f.unencrypted_disks.len() as u64)
        .with("defender_free_subscriptions", json!(f.defender_free_subs))
        .with("attack_path_count", attack_path_count as u64)
        .with("findings_by_severity", json!(sev_counts));
    if include_score {
        ev = ev.check("posture_score", true, score.round() as i64);
    }
    if include_graph {
        ev = ev.with("security_graph", graph.to_json());
    }

    let title = if include_score {
        format!(
            "Azure posture summary — grade {grade} ({score:.0}/100) — tenant {}",
            f.tenant_id.clone().unwrap_or_else(|| "unknown".to_string())
        )
    } else {
        format!(
            "Azure posture summary — tenant {}",
            f.tenant_id.clone().unwrap_or_else(|| "unknown".to_string())
        )
    };
    let desc = if include_score {
        format!(
            "Agentless Azure CSPM assessment scored {score:.0}/100 (grade {grade}) with {crit} critical \
             finding(s) and {attack_path_count} correlated attack path(s). Counts roll up live Storage / \
             Network / SQL / Key Vault / RBAC / ACR / AKS / App Service / Cosmos / Compute findings."
        )
    } else {
        "Agentless CSPM assessment summary for the connected Azure tenant. Counts roll up the live \
         Storage / Network / SQL / Key Vault / RBAC / ACR / AKS / App Service / Cosmos findings and \
         the correlated attack paths below."
            .to_string()
    };

    let sev = if include_score && score < 65.0 {
        "high"
    } else if include_score && score < 85.0 {
        "medium"
    } else {
        "info"
    };

    let mut v = finding_rich(ENGINE_ID, &title, sev, "", &desc, target, 1.0, ev);
    if include_score {
        if let Some(obj) = v.as_object_mut() {
            obj.insert("posture_score".to_string(), json!(score.round() as i64));
            obj.insert("grade".to_string(), json!(grade));
        }
    }
    if include_graph {
        if let Some(obj) = v.as_object_mut() {
            obj.insert("security_graph".to_string(), graph.to_json());
        }
    }
    v
}

// ─────────────────────────────────────────────────────────────────────────────
// Azure Resource Manager REST client
// ─────────────────────────────────────────────────────────────────────────────

struct ArmClient {
    http: reqwest::Client,
    token: String,
    arm: String,
}

impl ArmClient {
    /// Paginated GET that follows `nextLink` (bounded) and returns the merged `value` array.
    async fn get_all(&self, url: &str, max_pages: usize) -> Result<Vec<Value>, (u16, String)> {
        let mut out = Vec::new();
        let mut next = Some(url.to_string());
        let mut pages = 0usize;
        while let Some(u) = next.take() {
            if pages >= max_pages {
                break;
            }
            pages += 1;
            let resp = self
                .http
                .get(&u)
                .bearer_auth(&self.token)
                .send()
                .await
                .map_err(|e| (0u16, e.to_string()))?;
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if !(200..300).contains(&status) {
                return Err((status, body));
            }
            let v: Value = serde_json::from_str(&body).map_err(|e| (status, e.to_string()))?;
            if let Some(arr) = v.get("value").and_then(Value::as_array) {
                out.extend(arr.iter().cloned());
            } else {
                out.push(v.clone());
            }
            next = v
                .get("nextLink")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        Ok(out)
    }

    /// POST JSON to ARM (used by Azure Resource Graph).
    async fn post_json(&self, url: &str, body: &Value) -> Result<Value, (u16, String)> {
        let resp = self
            .http
            .post(url)
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .map_err(|e| (0u16, e.to_string()))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        if !(200..300).contains(&status) {
            return Err((status, text));
        }
        serde_json::from_str(&text).map_err(|e| (status, e.to_string()))
    }

    /// Run a KQL query across subscriptions via Azure Resource Graph (paginated).
    async fn arg_query(
        &self,
        subs: &[String],
        query: &str,
        max_rows: usize,
    ) -> Result<Vec<Value>, (u16, String)> {
        let url = format!(
            "{}/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01",
            self.arm
        );
        let mut out = Vec::new();
        let mut skip: Option<String> = None;
        while out.len() < max_rows {
            let page = (100usize).min(max_rows - out.len());
            let mut options = json!({ "resultFormat": "objectArray", "$top": page });
            if let Some(s) = &skip {
                options["$skipToken"] = json!(s);
            }
            let body = json!({
                "subscriptions": subs,
                "query": query,
                "options": options,
            });
            let v = self.post_json(&url, &body).await?;
            if let Some(data) = v.get("data").and_then(Value::as_array) {
                out.extend(data.iter().cloned());
            }
            skip = v
                .get("$skipToken")
                .and_then(Value::as_str)
                .map(str::to_string);
            if skip.is_none() {
                break;
            }
        }
        Ok(out)
    }
}

/// OAuth2 client-credentials token for ARM.
async fn acquire_token(
    http: &reqwest::Client,
    login: &str,
    tenant: &str,
    client_id: &str,
    client_secret: &str,
    scope: &str,
) -> Result<String, String> {
    let url = format!(
        "{}/{}/oauth2/v2.0/token",
        login.trim_end_matches('/'),
        tenant
    );
    let resp = http
        .post(&url)
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("grant_type", "client_credentials"),
            ("scope", scope),
        ])
        .send()
        .await
        .map_err(|e| format!("token request transport error: {e}"))?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    if status != 200 {
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let code = v
            .get("error")
            .and_then(Value::as_str)
            .or_else(|| {
                v.get("error")
                    .and_then(|e| e.get("code"))
                    .and_then(Value::as_str)
            })
            .unwrap_or("token_error");
        let desc = v
            .get("error_description")
            .and_then(Value::as_str)
            .unwrap_or("(no description)");
        let desc_short: String = desc.chars().take(180).collect();
        return Err(format!("token endpoint {status} {code}: {desc_short}"));
    }
    let v: Value =
        serde_json::from_str(&body).map_err(|e| format!("token response parse error: {e}"))?;
    v.get("access_token")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "token response missing access_token".to_string())
}

fn arm_err_finding(target: &str, op: &str, status: u16, body: &str) -> Value {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let code = v
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let (sev, title, desc) = match status {
        401 => (
            "info",
            format!("{op}: unauthorized"),
            "The service principal's token was rejected (401). Verify the client secret and that the \
             app has not had its credentials rotated/expired.".to_string(),
        ),
        403 => (
            "info",
            format!("{op}: insufficient RBAC (coverage gap)"),
            "The service principal lacks permission for this call (403). Grant the built-in `Reader` \
             role (and `Security Reader`) at subscription scope for complete read-only coverage."
                .to_string(),
        ),
        429 => (
            "info",
            format!("{op}: throttled by ARM"),
            "Azure Resource Manager rate-limited this call (429). Re-run with lower intensity or a \
             narrower subscription scope.".to_string(),
        ),
        _ => (
            "low",
            format!("{op}: call failed (HTTP {status})"),
            "An Azure Resource Manager call failed; the affected area may be incomplete.".to_string(),
        ),
    };
    let ev = Evidence::new()
        .with("operation", op.to_string())
        .with("http_status", u64::from(status))
        .with("error_code", code.to_string())
        .check("api_call_succeeded", false, format!("HTTP {status} {code}"));
    finding_rich(ENGINE_ID, &title, sev, "", &desc, target, 0.3, ev)
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-subscription scanners
// ─────────────────────────────────────────────────────────────────────────────

async fn scan_storage(
    arm: &ArmClient,
    sub: &str,
    target: &str,
    f: &mut AzureFacts,
    out: &mut Vec<Value>,
) {
    let url = format!(
        "{}/subscriptions/{}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01",
        arm.arm, sub
    );
    match arm.get_all(&url, 10).await {
        Ok(accounts) => {
            for a in accounts {
                let name = a
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let props = a.get("properties").cloned().unwrap_or(Value::Null);
                let allow_public = props
                    .get("allowBlobPublicAccess")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                let https_only = props
                    .get("supportsHttpsTrafficOnly")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let min_tls = props
                    .get("minimumTlsVersion")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let net_default = props
                    .get("networkAcls")
                    .and_then(|n| n.get("defaultAction"))
                    .and_then(Value::as_str)
                    .unwrap_or("Allow");
                let qualified = format!("{sub}:{name}");

                if allow_public {
                    f.public_storage.push(qualified.clone());
                    let ev = Evidence::new()
                        .with("subscription", sub.to_string())
                        .with("storage_account", name.clone())
                        .check(
                            "allow_blob_public_access",
                            true,
                            "allowBlobPublicAccess = true",
                        );
                    out.push(finding_rich(
                        ENGINE_ID,
                        &format!("Storage account '{name}' allows anonymous blob public access"),
                        "high",
                        "T1530",
                        "The storage account permits anonymous (public) blob access. Any container set \
                         to public becomes internet-readable. Set allowBlobPublicAccess=false at the \
                         account level.",
                        target,
                        0.7,
                        ev,
                    ));
                }
                if net_default.eq_ignore_ascii_case("Allow") {
                    f.open_storage_networks.push(qualified.clone());
                    let ev = Evidence::new()
                        .with("subscription", sub.to_string())
                        .with("storage_account", name.clone())
                        .check(
                            "network_default_action",
                            false,
                            "networkAcls.defaultAction = Allow",
                        );
                    out.push(finding_rich(
                        ENGINE_ID,
                        &format!("Storage account '{name}' accepts traffic from all networks"),
                        "medium",
                        "T1530",
                        "networkAcls.defaultAction is 'Allow', so the account is reachable from any \
                         network. Set defaultAction=Deny and use Private Endpoints / a service-network \
                         allow-list.",
                        target,
                        0.55,
                        ev,
                    ));
                }
                if !https_only {
                    f.insecure_transport_storage.push(qualified.clone());
                    let ev = Evidence::new()
                        .with("subscription", sub.to_string())
                        .with("storage_account", name.clone())
                        .check("https_only", false, "supportsHttpsTrafficOnly = false");
                    out.push(finding_rich(
                        ENGINE_ID,
                        &format!("Storage account '{name}' permits cleartext HTTP"),
                        "medium",
                        "T1040",
                        "supportsHttpsTrafficOnly is false, so blobs/files can be accessed over \
                         cleartext HTTP — exposing SAS tokens and data to interception. Enforce \
                         HTTPS-only.",
                        target,
                        0.5,
                        ev,
                    ));
                }
                if !min_tls.is_empty() && min_tls != "TLS1_2" {
                    let ev = Evidence::new()
                        .with("subscription", sub.to_string())
                        .with("storage_account", name.clone())
                        .with("minimum_tls", min_tls.to_string())
                        .check(
                            "min_tls_1_2",
                            false,
                            format!("minimumTlsVersion = {min_tls}"),
                        );
                    out.push(finding_rich(
                        ENGINE_ID,
                        &format!("Storage account '{name}' allows TLS below 1.2"),
                        "low",
                        "T1040",
                        "The storage account accepts a TLS version below 1.2. Set minimumTlsVersion to \
                         TLS1_2.",
                        target,
                        0.4,
                        ev,
                    ));
                }
            }
        }
        Err((status, body)) => out.push(arm_err_finding(target, "Storage list", status, &body)),
    }
}

async fn scan_network(
    arm: &ArmClient,
    sub: &str,
    sensitive: &[u16],
    target: &str,
    f: &mut AzureFacts,
    out: &mut Vec<Value>,
) {
    // Public IPs (allocated).
    let pip_url = format!(
        "{}/subscriptions/{}/providers/Microsoft.Network/publicIPAddresses?api-version=2023-09-01",
        arm.arm, sub
    );
    if let Ok(pips) = arm.get_all(&pip_url, 10).await {
        let allocated = pips
            .iter()
            .filter(|p| {
                p.get("properties")
                    .and_then(|x| x.get("ipAddress"))
                    .and_then(Value::as_str)
                    .is_some()
            })
            .count();
        f.public_ips += allocated;
    }

    // NSGs.
    let nsg_url = format!(
        "{}/subscriptions/{}/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-09-01",
        arm.arm, sub
    );
    match arm.get_all(&nsg_url, 10).await {
        Ok(nsgs) => {
            for nsg in nsgs {
                let nsg_name = nsg
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let rules = nsg
                    .get("properties")
                    .and_then(|p| p.get("securityRules"))
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let mut exposed: Vec<Value> = Vec::new();
                let mut admin_exposed = false;
                for rule in &rules {
                    let rp = rule.get("properties").cloned().unwrap_or(Value::Null);
                    let inbound = rp.get("direction").and_then(Value::as_str) == Some("Inbound");
                    let allow = rp.get("access").and_then(Value::as_str) == Some("Allow");
                    if !inbound || !allow {
                        continue;
                    }
                    let public = rule_source_prefixes(&rp)
                        .iter()
                        .any(|p| is_internet_source(p));
                    if !public {
                        continue;
                    }
                    let protocol = rp.get("protocol").and_then(Value::as_str).unwrap_or("*");
                    let tokens = rule_port_tokens(&rp);
                    let ports = sensitive_ports_for_rule(&tokens, protocol, sensitive);
                    for p in ports {
                        if let Some((label, mitre)) = sensitive_port_meta(p) {
                            if p == 22 || p == 3389 || p == 5985 || p == 5986 {
                                admin_exposed = true;
                            }
                            exposed.push(json!({"port": p, "service": label, "mitre": mitre,
                                "rule": rule.get("name").and_then(Value::as_str).unwrap_or("")}));
                        }
                    }
                }
                if !exposed.is_empty() {
                    if admin_exposed {
                        f.world_open_admin_nsgs.push(format!("{sub}:{nsg_name}"));
                    }
                    let score = if admin_exposed { 0.85 } else { 0.7 };
                    let ev = Evidence::new()
                        .with("subscription", sub.to_string())
                        .with("network_security_group", nsg_name.clone())
                        .with("exposed_ports", json!(exposed))
                        .check(
                            "ingress_restricted",
                            false,
                            "Internet/* source on sensitive port(s)",
                        );
                    out.push(finding_rich(
                        ENGINE_ID,
                        &format!(
                            "NSG '{nsg_name}' exposes {} sensitive port(s) to the internet",
                            exposed.len()
                        ),
                        severity_for_score(score),
                        "T1190",
                        "A Network Security Group allows the internet (Internet / * / 0.0.0.0/0) to \
                         reach management or database ports. Scope the source to a bastion / VPN \
                         prefix; expose nothing sensitive directly.",
                        target,
                        score,
                        ev,
                    ));
                }
            }
        }
        Err((status, body)) => out.push(arm_err_finding(target, "NSG list", status, &body)),
    }
}

async fn scan_sql(
    arm: &ArmClient,
    sub: &str,
    aggressive: bool,
    target: &str,
    f: &mut AzureFacts,
    out: &mut Vec<Value>,
) {
    let url = format!(
        "{}/subscriptions/{}/providers/Microsoft.Sql/servers?api-version=2021-11-01",
        arm.arm, sub
    );
    let servers = match arm.get_all(&url, 10).await {
        Ok(s) => s,
        Err((status, body)) => {
            out.push(arm_err_finding(target, "SQL server list", status, &body));
            return;
        }
    };
    for s in servers.iter().take(50) {
        let name = s
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let id = s
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let public = s
            .get("properties")
            .and_then(|p| p.get("publicNetworkAccess"))
            .and_then(Value::as_str)
            .map(|v| v.eq_ignore_ascii_case("Enabled"))
            .unwrap_or(false);
        let mut open_firewall = false;
        if aggressive && !id.is_empty() {
            let fw_url = format!("{}{}/firewallRules?api-version=2021-11-01", arm.arm, id);
            if let Ok(rules) = arm.get_all(&fw_url, 5).await {
                open_firewall = rules.iter().any(|r| {
                    let p = r.get("properties").cloned().unwrap_or(Value::Null);
                    p.get("startIpAddress").and_then(Value::as_str) == Some("0.0.0.0")
                        && p.get("endIpAddress").and_then(Value::as_str) == Some("255.255.255.255")
                });
            }
        }
        if public || open_firewall {
            f.public_sql.push(format!("{sub}:{name}"));
            let ev = Evidence::new()
                .with("subscription", sub.to_string())
                .with("sql_server", name.clone())
                .check(
                    "public_network_access",
                    public,
                    "publicNetworkAccess = Enabled",
                )
                .check(
                    "open_firewall_0_0_0_0",
                    open_firewall,
                    "0.0.0.0–255.255.255.255 firewall rule",
                );
            out.push(finding_rich(
                ENGINE_ID,
                &format!("Azure SQL server '{name}' is reachable from the public internet"),
                "high",
                "T1190",
                "The SQL server allows public network access (and/or has an all-internet firewall \
                 rule). Disable public network access and use Private Endpoints; never allow \
                 0.0.0.0–255.255.255.255.",
                target,
                0.75,
                ev,
            ));
        }
    }
}

async fn scan_keyvault(
    arm: &ArmClient,
    sub: &str,
    target: &str,
    f: &mut AzureFacts,
    out: &mut Vec<Value>,
) {
    let url = format!(
        "{}/subscriptions/{}/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01",
        arm.arm, sub
    );
    let vaults = match arm.get_all(&url, 10).await {
        Ok(v) => v,
        Err((status, body)) => {
            out.push(arm_err_finding(target, "Key Vault list", status, &body));
            return;
        }
    };
    for v in vaults {
        let name = v
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let props = v.get("properties").cloned().unwrap_or(Value::Null);
        let public = props
            .get("publicNetworkAccess")
            .and_then(Value::as_str)
            .map(|x| x.eq_ignore_ascii_case("Enabled"))
            .unwrap_or_else(|| {
                // Older API shape: networkAcls.defaultAction.
                props
                    .get("networkAcls")
                    .and_then(|n| n.get("defaultAction"))
                    .and_then(Value::as_str)
                    .map(|d| d.eq_ignore_ascii_case("Allow"))
                    .unwrap_or(true)
            });
        let purge = props
            .get("enablePurgeProtection")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let soft_delete = props
            .get("enableSoftDelete")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if public || !purge || !soft_delete {
            if public {
                f.public_keyvaults.push(format!("{sub}:{name}"));
            }
            let sev = if public { "high" } else { "medium" };
            let ev = Evidence::new()
                .with("subscription", sub.to_string())
                .with("key_vault", name.clone())
                .check(
                    "public_network_access",
                    public,
                    "reachable from all networks",
                )
                .check("purge_protection", purge, "enablePurgeProtection")
                .check("soft_delete", soft_delete, "enableSoftDelete");
            out.push(finding_rich(
                ENGINE_ID,
                &format!("Key Vault '{name}' weak network / data-protection posture"),
                sev,
                "T1552",
                "The Key Vault is publicly reachable and/or lacks soft-delete + purge protection. \
                 Restrict to Private Endpoints and enable soft-delete + purge protection so secrets \
                 cannot be exfiltrated or irreversibly destroyed.",
                target,
                0.6,
                ev,
            ));
        }
    }
}

async fn scan_rbac(
    arm: &ArmClient,
    sub: &str,
    target: &str,
    f: &mut AzureFacts,
    out: &mut Vec<Value>,
) {
    let url = format!(
        "{}/subscriptions/{}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01",
        arm.arm, sub
    );
    if let Ok(assignments) = arm.get_all(&url, 20).await {
        let high_priv = assignments
            .iter()
            .filter(|a| {
                a.get("properties")
                    .and_then(|p| p.get("roleDefinitionId"))
                    .and_then(Value::as_str)
                    .is_some_and(is_high_priv_role)
            })
            .count();
        f.owner_assignments += high_priv;
        if high_priv > 0 {
            let ev = Evidence::new()
                .with("subscription", sub.to_string())
                .with("owner_or_uaa_assignments", high_priv as u64)
                .check(
                    "standing_high_privilege",
                    true,
                    format!("{high_priv} Owner/UAA assignments"),
                );
            let sev = if high_priv >= 5 { "high" } else { "medium" };
            out.push(finding_rich(
                ENGINE_ID,
                &format!("{high_priv} Owner / User-Access-Admin assignment(s) at subscription scope"),
                sev,
                "T1098",
                "Standing Owner / User Access Administrator assignments at subscription scope are a \
                 large privilege surface. Move to PIM just-in-time elevation, remove unused standing \
                 grants, and require MFA + approval for activation.",
                target,
                0.6,
                ev,
            ));
        }
    }
}

async fn scan_defender(
    arm: &ArmClient,
    sub: &str,
    target: &str,
    f: &mut AzureFacts,
    out: &mut Vec<Value>,
) {
    let url = format!(
        "{}/subscriptions/{}/providers/Microsoft.Security/pricings?api-version=2023-01-01",
        arm.arm, sub
    );
    if let Ok(pricings) = arm.get_all(&url, 5).await {
        let free: Vec<String> = pricings
            .iter()
            .filter(|p| {
                p.get("properties")
                    .and_then(|x| x.get("pricingTier"))
                    .and_then(Value::as_str)
                    == Some("Free")
            })
            .filter_map(|p| p.get("name").and_then(Value::as_str).map(str::to_string))
            .collect();
        if !free.is_empty() {
            f.defender_free_subs.push(sub.to_string());
            let shown: Vec<String> = free.iter().take(30).cloned().collect();
            let ev = Evidence::new()
                .with("subscription", sub.to_string())
                .with("free_tier_plans", json!(shown))
                .check(
                    "defender_enabled",
                    false,
                    format!("{} plan(s) on Free tier", free.len()),
                );
            out.push(finding_rich(
                ENGINE_ID,
                &format!("Microsoft Defender for Cloud is not fully enabled in subscription {sub}"),
                "medium",
                "T1562.001",
                "One or more Defender for Cloud plans are on the Free tier, so workload threat \
                 protection, agentless scanning and just-in-time access are not active. Enable the \
                 Standard tier for servers, storage, SQL, containers and Key Vault.",
                target,
                0.55,
                ev,
            ));
        }
    }
}

async fn scan_arg_bulk(
    arm: &ArmClient,
    subs: &[String],
    target: &str,
    f: &mut AzureFacts,
    out: &mut Vec<Value>,
    graph: &mut SecurityGraph,
    max_rows: usize,
) {
    if subs.is_empty() {
        return;
    }
    let queries: &[(&str, &str, &str)] = &[
        (
            "public_storage",
            "Resources | where type =~ 'microsoft.storage/storageaccounts' | where properties.allowBlobPublicAccess == true | project name, subscriptionId",
            "Storage accounts with anonymous blob access enabled (ARG)",
        ),
        (
            "acr_admin",
            "Resources | where type =~ 'microsoft.containerregistry/registries' | where properties.adminUserEnabled == true | project name, subscriptionId",
            "Container registries with legacy admin user enabled (ARG)",
        ),
        (
            "public_aks",
            "Resources | where type =~ 'microsoft.containerservice/managedclusters' | extend priv = tobool(properties.apiServerAccessProfile.enablePrivateCluster) | where priv == false | project name, subscriptionId",
            "AKS clusters without private API server (ARG)",
        ),
        (
            "public_cosmos",
            "Resources | where type =~ 'microsoft.documentdb/databaseaccounts' | where properties.publicNetworkAccess =~ 'Enabled' | project name, subscriptionId",
            "Cosmos DB accounts with public network access (ARG)",
        ),
    ];
    for (kind, kql, title_prefix) in queries {
        match arm.arg_query(subs, kql, max_rows).await {
            Ok(rows) => {
                if rows.is_empty() {
                    continue;
                }
                let sample: Vec<Value> = rows.iter().take(15).cloned().collect();
                let count = rows.len();
                for row in &rows {
                    let sub = row
                        .get("subscriptionId")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let name = row.get("name").and_then(Value::as_str).unwrap_or("");
                    if name.is_empty() {
                        continue;
                    }
                    let qualified = format!("{sub}:{name}");
                    graph.upsert(
                        &format!("{kind}:{name}"),
                        kind,
                        sub,
                        "internet",
                        &["arg_discovery"],
                    );
                    graph.link("internet", &format!("{kind}:{name}"), "arg_exposed");
                    match *kind {
                        "public_storage" if !f.public_storage.contains(&qualified) => {
                            f.public_storage.push(qualified);
                        }
                        "acr_admin" if !f.acr_admin_enabled.contains(&qualified) => {
                            f.acr_admin_enabled.push(qualified);
                        }
                        "public_aks" if !f.public_aks.contains(&qualified) => {
                            f.public_aks.push(qualified);
                        }
                        "public_cosmos" if !f.public_cosmos.contains(&qualified) => {
                            f.public_cosmos.push(qualified);
                        }
                        _ => {}
                    }
                }
                let ev = Evidence::new()
                    .with("query_kind", (*kind).to_string())
                    .with("kql", (*kql).to_string())
                    .with("match_count", count as u64)
                    .with("sample", json!(sample))
                    .check("arg_query", true, format!("{count} resource(s) matched"));
                out.push(finding_rich(
                    ENGINE_ID,
                    &format!("{title_prefix}: {count} match(es)"),
                    if count >= 5 { "high" } else { "medium" },
                    "T1580",
                    "Azure Resource Graph cross-subscription query identified resources matching a \
                     high-risk posture pattern. These are live inventory facts from ARM — use them to \
                     prioritise remediation across the estate.",
                    target,
                    0.8,
                    ev,
                ));
            }
            Err((status, body)) => out.push(arm_err_finding(
                target,
                &format!("Resource Graph ({kind})"),
                status,
                &body,
            )),
        }
    }
}

async fn scan_acr(
    arm: &ArmClient,
    sub: &str,
    target: &str,
    f: &mut AzureFacts,
    out: &mut Vec<Value>,
    graph: &mut SecurityGraph,
) {
    let url = format!(
        "{}/subscriptions/{}/providers/Microsoft.ContainerRegistry/registries?api-version=2023-07-01",
        arm.arm, sub
    );
    if let Ok(registries) = arm.get_all(&url, 10).await {
        for r in registries {
            let name = r
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let props = r.get("properties").cloned().unwrap_or(Value::Null);
            let admin = props
                .get("adminUserEnabled")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let public_net = props
                .get("publicNetworkAccess")
                .and_then(Value::as_str)
                .map(|v| v.eq_ignore_ascii_case("Enabled"))
                .unwrap_or(true);
            let qualified = format!("{sub}:{name}");
            if admin {
                f.acr_admin_enabled.push(qualified.clone());
                graph.upsert(
                    &format!("acr:{name}"),
                    "container_registry",
                    sub,
                    "internal",
                    &["admin_user"],
                );
                let ev = Evidence::new()
                    .with("subscription", sub.to_string())
                    .with("registry", name.clone())
                    .check("admin_user_enabled", true, "adminUserEnabled = true");
                out.push(finding_rich(
                    ENGINE_ID,
                    &format!("ACR '{name}' has the legacy admin user enabled"),
                    "high",
                    "T1552",
                    "Azure Container Registry admin credentials are a long-lived shared secret that \
                     bypass RBAC. Disable admin user and use managed identity / ACR tokens / Azure AD.",
                    target,
                    0.75,
                    ev,
                ));
            }
            if public_net {
                graph.upsert(
                    &format!("acr:{name}"),
                    "container_registry",
                    sub,
                    "internet",
                    &["public_network"],
                );
                let ev = Evidence::new()
                    .with("subscription", sub.to_string())
                    .with("registry", name.clone())
                    .check(
                        "public_network_access",
                        true,
                        "publicNetworkAccess = Enabled",
                    );
                out.push(finding_rich(
                    ENGINE_ID,
                    &format!("ACR '{name}' accepts traffic from public networks"),
                    "medium",
                    "T1190",
                    "The container registry is reachable from public networks. Restrict to Private \
                     Endpoints or trusted networks to prevent anonymous image pulls / pushes.",
                    target,
                    0.55,
                    ev,
                ));
            }
        }
    }
}

async fn scan_aks(
    arm: &ArmClient,
    sub: &str,
    target: &str,
    f: &mut AzureFacts,
    out: &mut Vec<Value>,
    graph: &mut SecurityGraph,
) {
    let url = format!(
        "{}/subscriptions/{}/providers/Microsoft.ContainerService/managedClusters?api-version=2024-01-01",
        arm.arm, sub
    );
    if let Ok(clusters) = arm.get_all(&url, 10).await {
        for c in clusters {
            let name = c
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let props = c.get("properties").cloned().unwrap_or(Value::Null);
            let api = props
                .get("apiServerAccessProfile")
                .cloned()
                .unwrap_or(Value::Null);
            let private = api
                .get("enablePrivateCluster")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let authorized = api
                .get("authorizedIPRanges")
                .and_then(Value::as_array)
                .map(|a| !a.is_empty())
                .unwrap_or(false);
            if !private && !authorized {
                let qualified = format!("{sub}:{name}");
                f.public_aks.push(qualified);
                graph.upsert(
                    &format!("aks:{name}"),
                    "kubernetes",
                    sub,
                    "internet",
                    &["public_api"],
                );
                graph.link("internet", &format!("aks:{name}"), "k8s_api_access");
                let ev = Evidence::new()
                    .with("subscription", sub.to_string())
                    .with("cluster", name.clone())
                    .check("private_cluster", false, "enablePrivateCluster = false")
                    .check(
                        "authorized_ip_ranges",
                        false,
                        "no authorizedIPRanges configured",
                    );
                out.push(finding_rich(
                    ENGINE_ID,
                    &format!("AKS cluster '{name}' exposes a public Kubernetes API server"),
                    "critical",
                    "T1610",
                    "The cluster API server is reachable from the internet (no private cluster and no \
                     authorized IP ranges). This is one of the highest-impact Kubernetes misconfigurations. \
                     Enable private cluster + authorized IP ranges and enforce Azure AD + RBAC.",
                    target,
                    0.9,
                    ev,
                ));
            }
        }
    }
}

async fn scan_appservice(
    arm: &ArmClient,
    sub: &str,
    target: &str,
    f: &mut AzureFacts,
    out: &mut Vec<Value>,
    graph: &mut SecurityGraph,
) {
    let url = format!(
        "{}/subscriptions/{}/providers/Microsoft.Web/sites?api-version=2023-01-01",
        arm.arm, sub
    );
    if let Ok(sites) = arm.get_all(&url, 10).await {
        for s in sites.iter().take(80) {
            let name = s
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let props = s.get("properties").cloned().unwrap_or(Value::Null);
            let cfg = props.get("siteConfig").cloned().unwrap_or(Value::Null);
            let ftps = cfg.get("ftpsState").and_then(Value::as_str).unwrap_or("");
            let remote_dbg = cfg
                .get("remoteDebuggingEnabled")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let https_only = props
                .get("httpsOnly")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let min_tls = cfg
                .get("minTlsVersion")
                .and_then(Value::as_str)
                .unwrap_or("");
            let risky_ftps = ftps.eq_ignore_ascii_case("AllAllowed");
            if risky_ftps || remote_dbg || !https_only {
                let qualified = format!("{sub}:{name}");
                f.risky_appservice.push(qualified);
                graph.upsert(
                    &format!("app:{name}"),
                    "app_service",
                    sub,
                    "internet",
                    &["web_app"],
                );
                let mut ev = Evidence::new()
                    .with("subscription", sub.to_string())
                    .with("app_service", name.clone());
                let mut issues = Vec::new();
                if risky_ftps {
                    ev = ev.check("ftps_all_allowed", true, "ftpsState = AllAllowed");
                    issues.push("FTPS allows all connections");
                }
                if remote_dbg {
                    ev = ev.check("remote_debugging", true, "remoteDebuggingEnabled = true");
                    issues.push("remote debugging enabled");
                }
                if !https_only {
                    ev = ev.check("https_only", false, "httpsOnly = false");
                    issues.push("HTTP allowed");
                }
                let sev = if remote_dbg { "high" } else { "medium" };
                out.push(finding_rich(
                    ENGINE_ID,
                    &format!("App Service '{name}' weak hardening ({})", issues.join(", ")),
                    sev,
                    "T1190",
                    "An internet-facing App Service permits remote debugging, unrestricted FTPS, or \
                     cleartext HTTP. Attackers can intercept credentials, deploy webshells, or pivot to \
                     linked storage / Key Vault via app settings. Enforce HTTPS-only, disable remote \
                     debugging, and set ftpsState=Disabled or FtpsOnly.",
                    target,
                    if remote_dbg { 0.78 } else { 0.55 },
                    ev,
                ));
            }
            if !min_tls.is_empty() && min_tls != "1.2" && min_tls != "1.3" {
                let ev = Evidence::new()
                    .with("subscription", sub.to_string())
                    .with("app_service", name.clone())
                    .with("min_tls", min_tls.to_string())
                    .check("min_tls_1_2", false, format!("minTlsVersion = {min_tls}"));
                out.push(finding_rich(
                    ENGINE_ID,
                    &format!("App Service '{name}' allows TLS below 1.2"),
                    "low",
                    "T1040",
                    "The App Service accepts legacy TLS versions. Set minTlsVersion to 1.2 or higher.",
                    target,
                    0.4,
                    ev,
                ));
            }
        }
    }
}

async fn scan_cosmos(
    arm: &ArmClient,
    sub: &str,
    target: &str,
    f: &mut AzureFacts,
    out: &mut Vec<Value>,
    graph: &mut SecurityGraph,
) {
    let url = format!(
        "{}/subscriptions/{}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2023-04-15",
        arm.arm, sub
    );
    if let Ok(accounts) = arm.get_all(&url, 10).await {
        for a in accounts {
            let name = a
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let props = a.get("properties").cloned().unwrap_or(Value::Null);
            let public = props
                .get("publicNetworkAccess")
                .and_then(Value::as_str)
                .map(|v| v.eq_ignore_ascii_case("Enabled"))
                .unwrap_or(false);
            if public {
                let qualified = format!("{sub}:{name}");
                f.public_cosmos.push(qualified);
                graph.upsert(
                    &format!("cosmos:{name}"),
                    "cosmos_db",
                    sub,
                    "internet",
                    &["public_network"],
                );
                graph.link("internet", &format!("cosmos:{name}"), "nosql_access");
                let ev = Evidence::new()
                    .with("subscription", sub.to_string())
                    .with("cosmos_account", name.clone())
                    .check(
                        "public_network_access",
                        true,
                        "publicNetworkAccess = Enabled",
                    );
                out.push(finding_rich(
                    ENGINE_ID,
                    &format!("Cosmos DB '{name}' allows public network access"),
                    "high",
                    "T1530",
                    "The Cosmos DB account is reachable from the public internet. Disable public \
                     network access and use Private Endpoints with Azure AD RBAC.",
                    target,
                    0.72,
                    ev,
                ));
            }
        }
    }
}

async fn scan_compute(
    arm: &ArmClient,
    sub: &str,
    target: &str,
    f: &mut AzureFacts,
    out: &mut Vec<Value>,
    graph: &mut SecurityGraph,
) {
    let url = format!(
        "{}/subscriptions/{}/providers/Microsoft.Compute/disks?api-version=2023-04-02",
        arm.arm, sub
    );
    if let Ok(disks) = arm.get_all(&url, 10).await {
        for d in disks.iter().take(100) {
            let name = d
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let props = d.get("properties").cloned().unwrap_or(Value::Null);
            let enc = props.get("encryption").cloned().unwrap_or(Value::Null);
            let enc_type = enc.get("type").and_then(Value::as_str).unwrap_or("");
            let encrypted = enc_type.contains("EncryptionAtRest");
            if !encrypted {
                let qualified = format!("{sub}:{name}");
                f.unencrypted_disks.push(qualified);
                graph.upsert(
                    &format!("disk:{name}"),
                    "managed_disk",
                    sub,
                    "internal",
                    &["no_encryption"],
                );
                let ev = Evidence::new()
                    .with("subscription", sub.to_string())
                    .with("disk", name.clone())
                    .check(
                        "encryption_at_rest",
                        false,
                        format!("encryption.type = {enc_type}"),
                    );
                out.push(finding_rich(
                    ENGINE_ID,
                    &format!("Managed disk '{name}' lacks encryption at rest"),
                    "medium",
                    "T1530",
                    "The managed disk does not have platform or customer-managed encryption at rest \
                     configured. Enable encryption (default for new disks) and use CMK for regulated \
                     workloads.",
                    target,
                    0.5,
                    ev,
                ));
            }
        }
    }
}

/// Full agentless authenticated posture scan against the connected tenant.
async fn run_posture_scan(
    http: reqwest::Client,
    token: String,
    arm_endpoint: String,
    tenant: String,
    cfg: &ArsenalConfig,
    target: &str,
) -> EngineResult {
    let arm = ArmClient {
        http,
        token,
        arm: arm_endpoint,
    };
    let mut facts = AzureFacts {
        tenant_id: Some(tenant),
        ..AzureFacts::default()
    };
    let mut findings: Vec<Value> = Vec::new();

    // Resolve subscription scope.
    let mut subs: Vec<String> = cfg.string_list("subscriptions");
    if let Some(one) = cfg.string("subscription_id") {
        if !subs.contains(&one) {
            subs.push(one);
        }
    }
    if subs.is_empty() {
        let url = format!("{}/subscriptions?api-version=2020-01-01", arm.arm);
        match arm.get_all(&url, 10).await {
            Ok(list) => {
                for s in list {
                    if let Some(id) = s.get("subscriptionId").and_then(Value::as_str) {
                        subs.push(id.to_string());
                    }
                }
            }
            Err((status, body)) => {
                let mut result = EngineResult::ok(
                    vec![arm_err_finding(target, "List subscriptions", status, &body)],
                    format!("azure_attack: could not list subscriptions (HTTP {status})"),
                );
                result.findings.push(finding_rich(
                    ENGINE_ID,
                    "Grant the service principal Reader at subscription scope",
                    "info",
                    "",
                    "The connector authenticated but cannot enumerate subscriptions. Assign the \
                     built-in `Reader` (and `Security Reader`) role to the app at the subscription \
                     (or management-group) scope, then re-run.",
                    target,
                    1.0,
                    Evidence::new().check(
                        "subscription_enumeration",
                        false,
                        "no subscriptions visible",
                    ),
                ));
                return result;
            }
        }
    }
    let max_subs = cfg.usize_or("max_subscriptions", 5).clamp(1, 50);
    subs.truncate(max_subs);
    facts.subscriptions = subs.clone();

    let checks = cfg.string_list("checks");
    let run = |name: &str| checks.is_empty() || checks.iter().any(|c| c.eq_ignore_ascii_case(name));
    let aggressive = cfg.intensity() != Intensity::Light;
    let include_graph = cfg.bool_or("include_security_graph", true);
    let include_attack_paths = cfg.bool_or("include_attack_paths", true);
    let posture_scoring = cfg.bool_or("posture_scoring", true);
    let arg_max_rows = cfg.usize_or("arg_max_rows", 200).clamp(10, 2000);
    let mut graph = SecurityGraph::default();
    graph.upsert(
        "internet",
        "attack_surface",
        "global",
        "internet",
        &["ingress"],
    );
    let mut sensitive = cfg.ports("sensitive_ports");
    if sensitive.is_empty() {
        sensitive = SENSITIVE_PORTS.iter().map(|(p, _, _)| *p).collect();
    }
    let budget = Duration::from_secs(cfg.u64_or("section_timeout_secs", 75).clamp(15, 300));

    if run("arg") {
        let _ = tokio::time::timeout(
            budget,
            scan_arg_bulk(
                &arm,
                &subs,
                target,
                &mut facts,
                &mut findings,
                &mut graph,
                arg_max_rows,
            ),
        )
        .await;
    }

    for sub in &subs {
        if run("storage") {
            let _ = tokio::time::timeout(
                budget,
                scan_storage(&arm, sub, target, &mut facts, &mut findings),
            )
            .await;
        }
        if run("network") {
            let _ = tokio::time::timeout(
                budget,
                scan_network(&arm, sub, &sensitive, target, &mut facts, &mut findings),
            )
            .await;
        }
        if run("sql") {
            let _ = tokio::time::timeout(
                budget,
                scan_sql(&arm, sub, aggressive, target, &mut facts, &mut findings),
            )
            .await;
        }
        if run("keyvault") {
            let _ = tokio::time::timeout(
                budget,
                scan_keyvault(&arm, sub, target, &mut facts, &mut findings),
            )
            .await;
        }
        if run("rbac") {
            let _ = tokio::time::timeout(
                budget,
                scan_rbac(&arm, sub, target, &mut facts, &mut findings),
            )
            .await;
        }
        if run("defender") && aggressive {
            let _ = tokio::time::timeout(
                budget,
                scan_defender(&arm, sub, target, &mut facts, &mut findings),
            )
            .await;
        }
        if run("acr") {
            let _ = tokio::time::timeout(
                budget,
                scan_acr(&arm, sub, target, &mut facts, &mut findings, &mut graph),
            )
            .await;
        }
        if run("aks") {
            let _ = tokio::time::timeout(
                budget,
                scan_aks(&arm, sub, target, &mut facts, &mut findings, &mut graph),
            )
            .await;
        }
        if run("appservice") {
            let _ = tokio::time::timeout(
                budget,
                scan_appservice(&arm, sub, target, &mut facts, &mut findings, &mut graph),
            )
            .await;
        }
        if run("cosmos") {
            let _ = tokio::time::timeout(
                budget,
                scan_cosmos(&arm, sub, target, &mut facts, &mut findings, &mut graph),
            )
            .await;
        }
        if run("compute") && aggressive {
            let _ = tokio::time::timeout(
                budget,
                scan_compute(&arm, sub, target, &mut facts, &mut findings, &mut graph),
            )
            .await;
        }
    }

    if include_attack_paths {
        let mut paths = correlate_attack_paths(&facts, target);
        findings.append(&mut paths);
    }
    findings.insert(
        0,
        posture_summary(
            &facts,
            &findings,
            target,
            &graph,
            posture_scoring,
            include_graph,
        ),
    );

    let crit = findings
        .iter()
        .filter(|f| f.get("severity").and_then(Value::as_str) == Some("critical"))
        .count();
    EngineResult::ok(
        findings,
        format!(
            "azure_attack: agentless CSPM across {} subscription(s) — {} critical finding(s)",
            facts.subscriptions.len(),
            crit
        ),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Unauthenticated external surface scan
// ─────────────────────────────────────────────────────────────────────────────

fn blob_listing_exposed(body: &str) -> bool {
    body.contains("<EnumerationResults") && (body.contains("<Blob>") || body.contains("<Blobs"))
}

async fn dns_cname(host: &str) -> Vec<String> {
    use hickory_resolver::proto::rr::RecordType;
    use hickory_resolver::TokioResolver;
    let resolver = match TokioResolver::builder_tokio().and_then(|b| b.build()) {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    let Ok(lookup) = resolver.lookup(host, RecordType::CNAME).await else {
        return vec![];
    };
    let mut out = Vec::new();
    for record in lookup.answers() {
        let s = record
            .data
            .to_string()
            .trim()
            .trim_end_matches('.')
            .to_string();
        if !s.is_empty() {
            out.push(s);
        }
    }
    out
}

fn apex_domain(host: &str) -> String {
    let h = host.trim().trim_end_matches('.');
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        h.to_string()
    }
}

async fn scan_azure_subdomain_takeover(
    cfg: &ArsenalConfig,
    target: &str,
    domain: &str,
    findings: &mut Vec<Value>,
) {
    if !cfg.bool_or("check_takeover", true) {
        return;
    }
    let mut names: Vec<String> = vec![domain.to_string()];
    names.extend(cfg.string_list("subdomains"));
    if names.len() == 1 {
        for sub in DEFAULT_TAKEOVER_SUBDOMAINS {
            names.push(format!("{sub}.{domain}"));
        }
    } else {
        let apex = domain.to_string();
        names = names
            .into_iter()
            .map(|n| {
                let n = n.trim().trim_end_matches('.').to_string();
                if n.is_empty() {
                    return String::new();
                }
                if n.contains('.') {
                    n
                } else {
                    format!("{n}.{apex}")
                }
            })
            .filter(|n| !n.is_empty())
            .collect();
    }
    names.sort();
    names.dedup();
    let max_names = cfg.usize_or("max_takeover_hosts", 25).clamp(1, 100);
    for name in names.into_iter().take(max_names) {
        let cnames = dns_cname(&name).await;
        for cn in cnames {
            let cl = cn.trim_end_matches('.').to_ascii_lowercase();
            if let Some((suffix, service)) = AZURE_TAKEOVER_SUFFIXES
                .iter()
                .find(|(suf, _)| cl.ends_with(*suf))
            {
                let target_host = cn.trim_end_matches('.');
                let resolves = !dns_a(target_host).await.is_empty();
                let sev = if resolves { "low" } else { "high" };
                let ev = Evidence::new()
                    .with("hostname", name.clone())
                    .with("cname", cn.clone())
                    .with("azure_service", *service)
                    .with("target_suffix", *suffix)
                    .check("cname_target_resolves", resolves, target_host);
                findings.push(finding_rich(
                    ENGINE_ID,
                    &format!(
                        "{} Azure dangling CNAME — {name} → {service}",
                        if resolves { "Third-party" } else { "Dangling" }
                    ),
                    sev,
                    "T1584.001",
                    &format!(
                        "{name} is a CNAME to {cn} ({service}). {}",
                        if resolves {
                            "The Azure target currently resolves; confirm the resource is still owned \
                             by you to prevent future subdomain takeover."
                        } else {
                            "The CNAME target does NOT resolve — an attacker can claim the Azure \
                             resource (App Service / Blob / Front Door / etc.) and take over this \
                             hostname for phishing, cookie theft, or OAuth redirect abuse."
                        }
                    ),
                    target,
                    if resolves { 0.55 } else { 0.88 },
                    ev,
                ));
            }
        }
    }
}

async fn run_external_surface(cfg: &ArsenalConfig, target: &str) -> EngineResult {
    let client = http_client().await;
    let base = normalize_url(target);
    let host = extract_host(target);
    let domain = apex_domain(&host);
    let domain_label = host.split('.').next().unwrap_or(&host).to_string();
    let mut findings: Vec<Value> = Vec::new();

    // 0. Azure subdomain takeover (dangling CNAME → azurewebsites.net / blob / Front Door …).
    scan_azure_subdomain_takeover(cfg, target, &domain, &mut findings).await;

    // 1. Azure AD tenant discovery (federation realm).
    let oidc = format!(
        "{}/{}/.well-known/openid-configuration",
        DEFAULT_LOGIN, host
    );
    if let Some(p) = http_get(&client, &oidc).await {
        if p.status == 200
            && (p.body.contains("authorization_endpoint") || p.body.contains("issuer"))
        {
            let tenant = serde_json::from_str::<Value>(&p.body).ok().and_then(|v| {
                v.get("issuer")
                    .and_then(Value::as_str)
                    .and_then(|iss| iss.split('/').nth(3).map(str::to_string))
            });
            let ev = Evidence::new()
                .with("domain", host.clone())
                .with("tenant_id", tenant.clone().unwrap_or_default())
                .check("aad_tenant_discoverable", true, json!({ "status": 200 }));
            findings.push(finding_rich(
                ENGINE_ID,
                "Azure AD (Entra ID) tenant is discoverable for this domain",
                "info",
                "T1590",
                "The domain is federated to an Azure AD tenant whose OpenID configuration is public \
                 (this is by design). The tenant id and login endpoints aid targeted phishing and \
                 password-spray; ensure Conditional Access + MFA and smart-lockout are enforced.",
                target,
                0.6,
                ev,
            ));
        }
    }

    // 2. Public Blob container enumeration.
    let mut accounts: Vec<String> = vec![domain_label.clone(), host.replace('.', "")];
    accounts.extend(cfg.string_list("storage_accounts"));
    let suffixes = cfg.string_list_or(
        "account_suffixes",
        &["", "prod", "dev", "backup", "data", "storage", "assets"],
    );
    let mut candidates: Vec<String> = Vec::new();
    for a in &accounts {
        let a = a.to_ascii_lowercase();
        let a: String = a.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        if a.len() < 3 || a.len() > 24 {
            continue;
        }
        for s in &suffixes {
            candidates.push(format!("{a}{s}"));
        }
    }
    candidates.sort();
    candidates.dedup();
    let max_accounts = cfg.usize_or("max_account_candidates", 12).clamp(1, 100);
    let containers = cfg.string_list_or("containers", COMMON_CONTAINERS);

    for acct in candidates.into_iter().take(max_accounts) {
        let blob_host = format!("{acct}.blob.core.windows.net");
        // Only probe containers if the account DNS actually resolves (account exists).
        if dns_a(&blob_host).await.is_empty() {
            continue;
        }
        let ev_exists = Evidence::new()
            .with("storage_account", acct.clone())
            .with("blob_endpoint", blob_host.clone())
            .check("account_dns_resolves", true, "the storage account exists");
        findings.push(finding_rich(
            ENGINE_ID,
            &format!("Azure Storage account exists: {acct}"),
            "info",
            "T1580",
            "A storage account associated with this target exists (its blob endpoint resolves). \
             Verify ownership and that its containers are not public.",
            target,
            0.35,
            ev_exists,
        ));
        for c in containers.iter().take(20) {
            let u = format!("https://{blob_host}/{c}?restype=container&comp=list");
            if let Some(p) = http_get(&client, &u).await {
                if p.status == 200 && blob_listing_exposed(&p.body) {
                    let ev = Evidence::new()
                        .with("storage_account", acct.clone())
                        .with("container", c.clone())
                        .with("url", u.clone())
                        .check(
                            "public_container_listing",
                            true,
                            "EnumerationResults returned (HTTP 200)",
                        );
                    findings.push(finding_rich(
                        ENGINE_ID,
                        &format!("Public Azure Blob container '{c}' on account '{acct}'"),
                        "critical",
                        "T1530",
                        "An Azure Blob container is anonymously listable, exposing its objects to the \
                         internet. Set the container access level to Private and disable \
                         allowBlobPublicAccess on the account.",
                        target,
                        0.85,
                        ev,
                    ));
                }
            }
        }
    }

    // 3. Leaked Azure credentials / SAS tokens in web assets.
    for path in AZURE_WEB_PATHS {
        let url = join_url(&base, path);
        if let Some(p) = http_get(&client, &url).await {
            if p.status == 200 {
                let secrets = detect_secrets(&p.body);
                let sas = SAS_INDICATORS.iter().any(|ind| p.body.contains(ind));
                if sas || !secrets.is_empty() {
                    let ev = Evidence::new()
                        .with("url", p.final_url.clone())
                        .with("sas_or_connection_string", sas)
                        .with("secret_types", json!(secrets))
                        .check(
                            "azure_secret_material",
                            true,
                            json!({ "sas": sas, "secrets": secrets }),
                        );
                    findings.push(finding_rich(
                        ENGINE_ID,
                        &format!("Azure credential / SAS material exposed at {path}"),
                        "critical",
                        "T1552.001",
                        "A web-reachable asset contains an Azure storage connection string / SAS token \
                         or other secret material. Rotate the affected keys immediately and remove the \
                         file from the web root / deployment output.",
                        target,
                        0.88,
                        ev,
                    ));
                }
            }
        }
    }

    // 4. Azure edge / service fingerprint.
    if let Some(p) = http_get(&client, &base).await {
        let server = header_value(&p.headers, "server")
            .unwrap_or("")
            .to_ascii_lowercase();
        let xpb = header_value(&p.headers, "x-powered-by")
            .unwrap_or("")
            .to_ascii_lowercase();
        if server.contains("microsoft-iis")
            || server.contains("windows-azure")
            || header_value(&p.headers, "x-azure-ref").is_some()
            || xpb.contains("asp.net")
        {
            let ev = Evidence::new()
                .with("url", p.final_url.clone())
                .with("server", server.clone())
                .check(
                    "azure_edge_headers",
                    true,
                    "Azure / IIS / Front Door fingerprint",
                );
            findings.push(finding_rich(
                ENGINE_ID,
                "Azure-hosted surface detected",
                "info",
                "T1590",
                "Response headers indicate the target is hosted on Azure (App Service / Front Door / \
                 IIS). Review WAF coverage, TLS configuration and that staging slots / Kudu (SCM) are \
                 not internet-exposed.",
                target,
                0.4,
                ev,
            ));
        }
    }

    if cfg.emit_agent_guidance() {
        let ev = Evidence::new().check(
            "credentialed_scan_available",
            false,
            "no Azure service-principal supplied — only external surface was assessed",
        );
        findings.push(finding_rich(
            ENGINE_ID,
            "Connect an Azure service principal for a full CSPM posture scan",
            "info",
            "",
            "This run assessed only the externally observable Azure surface. Provide an Azure AD \
             service principal (tenant_id + client_id + client_secret) with the built-in `Reader` / \
             `Security Reader` roles in the engine parameters to unlock the full agentless posture \
             assessment: storage public-access, NSG internet exposure, SQL / Key Vault posture, RBAC \
             sprawl, Defender coverage and attack-path correlation.",
            target,
            1.0,
            ev,
        ));
    }

    EngineResult::ok(
        findings.clone(),
        format!(
            "azure_attack: external surface scan of {host} — {} signal(s)",
            findings.len()
        ),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry points
// ─────────────────────────────────────────────────────────────────────────────

/// Context-aware entry point: credentialed agentless CSPM when a service principal is supplied,
/// otherwise an honest external-surface scan.
pub async fn run_azure_attack_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);

    let tenant = cfg
        .string("tenant_id")
        .or_else(|| cfg.string("azure_tenant_id"));
    let client_id = cfg
        .string("client_id")
        .or_else(|| cfg.string("azure_client_id"));
    let secret = cfg
        .string("client_secret")
        .or_else(|| cfg.string("azure_client_secret"));

    if let (Some(tenant), Some(client_id), Some(secret)) = (tenant, client_id, secret) {
        let login = cfg.string_or("login_endpoint", DEFAULT_LOGIN);
        let arm_endpoint = cfg.string_or("arm_endpoint", DEFAULT_ARM);
        let scope = cfg.string_or(
            "scope",
            &format!("{}/.default", arm_endpoint.trim_end_matches('/')),
        );
        let http = http_client().await;
        match acquire_token(&http, &login, &tenant, &client_id, &secret, &scope).await {
            Ok(token) => {
                let mut result =
                    run_posture_scan(http, token, arm_endpoint, tenant, &cfg, target).await;
                if cfg.bool_or("also_external_scan", false) {
                    let mut ext = run_external_surface(&cfg, target).await;
                    result.findings.append(&mut ext.findings);
                }
                return result;
            }
            Err(e) => {
                let mut result = run_external_surface(&cfg, target).await;
                result.findings.insert(
                    0,
                    finding_rich(
                        ENGINE_ID,
                        "Azure credential resolution failed",
                        "info",
                        "",
                        &format!(
                            "Could not obtain an Azure access token ({e}). Verify tenant_id / \
                             client_id / client_secret and that the app registration is valid. \
                             Falling back to an external-only surface scan."
                        ),
                        target,
                        1.0,
                        Evidence::new().check("token_acquisition", false, e),
                    ),
                );
                return result;
            }
        }
    }

    run_external_surface(&cfg, target).await
}

/// Back-compat 1-arg entry (used by catalog aliases / older callers). Runs in external mode.
pub async fn run_azure_attack_result(target: &str) -> EngineResult {
    run_azure_attack_result_ctx(target, &EngineRunContext::default()).await
}

/// CLI wrapper (`cargo run -- azure_attack <target>`).
pub async fn run_azure_attack(target: &str) {
    print_result(run_azure_attack_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internet_source_detection() {
        assert!(is_internet_source("*"));
        assert!(is_internet_source("0.0.0.0/0"));
        assert!(is_internet_source("Internet"));
        assert!(is_internet_source("internet"));
        assert!(!is_internet_source("10.0.0.0/8"));
        assert!(!is_internet_source("VirtualNetwork"));
    }

    #[test]
    fn port_token_parsing() {
        assert_eq!(parse_port_token("22"), Some((22, 22)));
        assert_eq!(parse_port_token("*"), Some((0, 65_535)));
        assert_eq!(parse_port_token("1000-2000"), Some((1000, 2000)));
        assert_eq!(parse_port_token("2000-1000"), Some((1000, 2000)));
        assert_eq!(parse_port_token("bad"), None);
    }

    #[test]
    fn sensitive_ports_rule_matching() {
        let sens = [22, 3389, 1433];
        assert_eq!(
            sensitive_ports_for_rule(&["22".to_string()], "Tcp", &sens),
            vec![22]
        );
        // Wildcard port + wildcard protocol exposes everything.
        let mut got = sensitive_ports_for_rule(&["*".to_string()], "*", &sens);
        got.sort_unstable();
        assert_eq!(got, vec![22, 1433, 3389]);
        // UDP cannot expose these TCP services.
        assert!(sensitive_ports_for_rule(&["3389".to_string()], "Udp", &sens).is_empty());
        // Range covering RDP+SQL.
        let mut r = sensitive_ports_for_rule(&["1000-4000".to_string()], "Tcp", &sens);
        r.sort_unstable();
        assert_eq!(r, vec![1433, 3389]);
    }

    #[test]
    fn high_priv_role_detection() {
        let owner = format!(
            "/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/{ROLE_OWNER}"
        );
        let contributor = format!(
            "/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/{ROLE_CONTRIBUTOR}"
        );
        assert!(is_high_priv_role(&owner));
        assert!(!is_high_priv_role(&contributor));
    }

    #[test]
    fn nsg_rule_field_extraction() {
        let rule = json!({
            "properties": {
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "sourceAddressPrefix": "Internet",
                "destinationPortRanges": ["22", "3389"]
            }
        });
        let props = rule.get("properties").unwrap();
        assert!(rule_source_prefixes(props)
            .iter()
            .any(|p| is_internet_source(p)));
        let toks = rule_port_tokens(props);
        let mut ports = sensitive_ports_for_rule(&toks, "Tcp", &[22, 3389, 1433]);
        ports.sort_unstable();
        assert_eq!(ports, vec![22, 3389]);
    }

    #[test]
    fn letter_grade_boundaries() {
        assert_eq!(letter_grade(96.0), "A+");
        assert_eq!(letter_grade(50.0), "D");
        assert_eq!(letter_grade(30.0), "F");
    }

    #[test]
    fn posture_score_penalizes_critical() {
        let findings = vec![finding_rich(
            ENGINE_ID,
            "test critical",
            "critical",
            "",
            "desc",
            "https://example.com",
            1.0,
            Evidence::new(),
        )];
        assert!(posture_score(&findings) < 80.0);
    }

    #[test]
    fn apex_domain_extraction() {
        assert_eq!(apex_domain("api.contoso.com"), "contoso.com");
        assert_eq!(apex_domain("contoso.com"), "contoso.com");
    }

    #[test]
    fn correlation_flags_public_sql() {
        let facts = AzureFacts {
            public_sql: vec!["sub:sql1".to_string()],
            ..AzureFacts::default()
        };
        let paths = correlate_attack_paths(&facts, "https://example.com");
        assert!(paths.iter().any(|p| finding_sev(p) == "critical"));
    }

    #[test]
    fn correlation_flags_public_aks_acr() {
        let facts = AzureFacts {
            public_aks: vec!["sub:aks1".to_string()],
            acr_admin_enabled: vec!["sub:acr1".to_string()],
            ..AzureFacts::default()
        };
        let paths = correlate_attack_paths(&facts, "https://example.com");
        assert!(paths
            .iter()
            .any(|p| p.get("toxic_combination").and_then(Value::as_str)
                == Some("public_aks_acr_admin")));
    }

    #[tokio::test]
    async fn empty_target_errors() {
        let r = run_azure_attack_result("").await;
        assert!(!r.success);
    }
}
