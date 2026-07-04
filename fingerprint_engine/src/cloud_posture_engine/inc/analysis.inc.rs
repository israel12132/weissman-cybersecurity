fn finding_title(f: &Value) -> &str {
    f.get("title").and_then(Value::as_str).unwrap_or("")
}

fn finding_sev(f: &Value) -> String {
    f.get("severity")
        .and_then(Value::as_str)
        .unwrap_or("info")
        .to_ascii_lowercase()
}

fn has_title_contains(findings: &[Value], needle: &str) -> bool {
    findings.iter().any(|f| finding_title(f).contains(needle))
}

fn attack_path_finding(
    title: &str,
    severity: &str,
    target: &str,
    steps: &[&str],
    mitre: &str,
    description: &str,
    toxic_combo: &str,
) -> Value {
    let ev = Evidence::new()
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
        0.88,
        ev,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("category".to_string(), json!("attack_path"));
        obj.insert("attack_path".to_string(), json!(true));
        obj.insert("steps".to_string(), json!(steps));
        obj.insert("toxic_combination".to_string(), json!(toxic_combo));
        obj.insert("domain".to_string(), json!("posture"));
    }
    f
}

fn synthesize_attack_paths(findings: &[Value], target: &str, account_id: Option<&str>) -> Vec<Value> {
    let mut paths = Vec::new();
    let acct = account_id.unwrap_or("the account");

    if has_title_contains(findings, "Root account MFA is not enabled")
        || has_title_contains(findings, "Root account has active access keys")
    {
        paths.push(attack_path_finding(
            "Toxic combination: root identity unprotected → full account takeover",
            "critical",
            target,
            &[
                "Phish or brute-force the root password / steal a root access key",
                "No MFA or long-lived root key blocks the attacker",
                "Assume unrestricted control of the entire AWS organisation",
            ],
            "T1078.004",
            &format!("The root identity of {acct} lacks MFA or has active access keys — a single credential theft yields irreversible account-wide compromise (Wiz-class toxic combination)."),
            "unprotected_root",
        ));
    }

    if has_title_contains(findings, "Public EC2 instance allows IMDSv1")
        && has_title_contains(findings, "AdministratorAccess")
    {
        paths.push(attack_path_finding(
            "Toxic combination: public IMDSv1 + over-privileged instance role → cloud admin",
            "critical",
            target,
            &[
                "Exploit SSRF/RCE on a public-facing workload",
                "Query 169.254.169.254 (IMDSv1, no session token)",
                "Steal instance-role credentials with AdministratorAccess",
                "Full cloud control from an unauthenticated internet attacker",
            ],
            "T1552.005",
            "Internet-exposed compute with IMDSv1 and an admin-capable instance role creates a direct external-to-admin breach chain.",
            "imdsv1_admin_role",
        ));
    }

    if has_title_contains(findings, "S3 bucket world-readable")
        && has_title_contains(findings, "Stale IAM access key")
    {
        paths.push(attack_path_finding(
            "Toxic combination: stale long-lived keys + public data store",
            "high",
            target,
            &[
                "Discover or leak a stale IAM access key (no rotation)",
                "Enumerate publicly readable S3 buckets",
                "Exfiltrate sensitive data at scale",
            ],
            "T1530",
            &format!("Stale IAM keys combined with public S3 exposure in {acct} enables persistent, undetected data exfiltration."),
            "stale_keys_public_s3",
        ));
    }

    if has_title_contains(findings, "Security group open to the internet")
        && has_title_contains(findings, "Unencrypted EBS volume")
    {
        paths.push(attack_path_finding(
            "Toxic combination: internet-open management port + unencrypted disk",
            "high",
            target,
            &[
                "Scan for world-open SSH/RDP/database ports",
                "Compromise the instance via credential spray or known CVE",
                "Attach/detach unencrypted EBS snapshot for offline data theft",
            ],
            "T1190",
            "Wide-open security groups on sensitive ports paired with unencrypted EBS volumes amplify blast radius after initial access.",
            "open_sg_unencrypted_ebs",
        ));
    }

    if has_title_contains(findings, "Lambda function publicly invokable")
        && has_title_contains(findings, "AdministratorAccess")
    {
        paths.push(attack_path_finding(
            "Toxic combination: public Lambda + admin execution role",
            "critical",
            target,
            &[
                "Invoke the publicly accessible Lambda function without authentication",
                "Abuse the over-privileged execution role via SSRF or code injection",
                "Pivot to full AWS account control",
            ],
            "T1190",
            &format!("Public Lambda with AdministratorAccess execution role in {acct} enables unauthenticated cloud takeover."),
            "public_lambda_admin_role",
        ));
    }

    if has_title_contains(findings, "RDS instance publicly accessible")
        && has_title_contains(findings, "RDS storage not encrypted")
    {
        paths.push(attack_path_finding(
            "Toxic combination: internet-exposed unencrypted database",
            "critical",
            target,
            &[
                "Discover publicly accessible RDS endpoint via port scan",
                "Brute-force or spray database credentials",
                "Exfiltrate plaintext data at rest and in transit",
            ],
            "T1190",
            &format!("Public RDS without encryption in {acct} — direct internet path to sensitive data."),
            "public_rds_unencrypted",
        ));
    }

    if has_title_contains(findings, "No CloudTrail trail configured")
        || has_title_contains(findings, "CloudTrail trail not actively logging")
    {
        paths.push(attack_path_finding(
            "Toxic combination: blind audit plane + any identity gap",
            "high",
            target,
            &[
                "Exploit any IAM/network misconfiguration for initial access",
                "Operate without CloudTrail visibility — defenders cannot correlate API abuse",
                "Maintain persistence while evading SIEM detection",
            ],
            "T1562.008",
            &format!("Missing or disabled CloudTrail in {acct} means toxic identity/network combinations may go undetected for weeks."),
            "blind_audit_plane",
        ));
    }

    if has_title_contains(findings, "Public EBS snapshot")
        && has_title_contains(findings, "Unencrypted EBS volume")
    {
        paths.push(attack_path_finding(
            "Toxic combination: public snapshot + unencrypted volumes",
            "critical",
            target,
            &[
                "Locate a publicly shared EBS snapshot (group: all)",
                "Create a volume in an attacker account from the snapshot",
                "Mount offline and extract sensitive data without touching production",
            ],
            "T1530",
            &format!("Public EBS snapshots combined with unencrypted volumes in {acct} enable cross-account data theft."),
            "public_snapshot_unencrypted",
        ));
    }

    if has_title_contains(findings, "Access Analyzer")
        && (has_title_contains(findings, "GuardDuty not enabled")
            || has_title_contains(findings, "CloudTrail trail not actively logging"))
    {
        paths.push(attack_path_finding(
            "Toxic combination: proven external access + no runtime/audit detection",
            "critical",
            target,
            &[
                "Access Analyzer confirms an externally reachable resource",
                "GuardDuty/CloudTrail blind spots prevent detection of exploitation",
                "Attacker exfiltrates or pivots while SOC has no correlated signal",
            ],
            "T1562.008",
            &format!("Confirmed external-access findings in {acct} without GuardDuty/CloudTrail coverage — high-confidence breach with low detection probability."),
            "external_access_blind_detection",
        ));
    }

    if has_title_contains(findings, "EKS cluster public API endpoint")
        && has_title_contains(findings, "AdministratorAccess")
    {
        paths.push(attack_path_finding(
            "Toxic combination: public Kubernetes API + cluster-admin-equivalent IAM",
            "critical",
            target,
            &[
                "Reach the public EKS API endpoint from the internet",
                "Authenticate with stolen/over-permissive IAM or leaked kubeconfig",
                "Deploy privileged workloads or steal cluster secrets",
            ],
            "T1190",
            &format!("Public EKS control plane in {acct} combined with admin-capable IAM enables full cluster takeover."),
            "public_eks_admin_iam",
        ));
    }

    if has_title_contains(findings, "Lambda Function URL without auth")
        && has_title_contains(findings, "Secrets Manager secret")
    {
        paths.push(attack_path_finding(
            "Toxic combination: unauthenticated Lambda URL + long-lived secrets",
            "high",
            target,
            &[
                "Invoke the public Lambda Function URL without credentials",
                "Abuse application logic to read environment or call Secrets Manager",
                "Harvest database/API credentials at scale",
            ],
            "T1552.001",
            "Public Lambda URLs in the same account as rotatable-but-exposed secrets amplify credential theft blast radius.",
            "public_lambda_url_secrets",
        ));
    }

    if has_title_contains(findings, "OpenSearch domain without VPC isolation")
        && has_title_contains(findings, "OpenSearch domain access policy is public")
    {
        paths.push(attack_path_finding(
            "Toxic combination: internet OpenSearch + wildcard access policy → full index exfiltration",
            "critical",
            target,
            &[
                "Reach the public OpenSearch endpoint from the internet",
                "Authenticate with anonymous/wildcard policy (no fine-grained control)",
                "Dump all indices — PII, logs, secrets indexed in Elasticsearch",
            ],
            "T1530",
            &format!("Public OpenSearch domain with wildcard access policy in {acct} — direct data warehouse breach."),
            "public_opensearch_wildcard",
        ));
    }

    if has_title_contains(findings, "API Gateway HTTP API has unauthenticated routes")
        && has_title_contains(findings, "Lambda function publicly invokable")
    {
        paths.push(attack_path_finding(
            "Toxic combination: open API Gateway routes → serverless entry chain",
            "critical",
            target,
            &[
                "Hit unauthenticated HTTP API routes (AuthorizationType=NONE)",
                "Chain to publicly invokable Lambda backends",
                "Abuse execution roles for lateral movement",
            ],
            "T1190",
            &format!("Unauthenticated API Gateway surface combined with public Lambda in {acct} creates a layered serverless attack chain."),
            "apigw_lambda_chain",
        ));
    }

    if has_title_contains(findings, "DynamoDB table resource policy is public")
        && has_title_contains(findings, "GuardDuty not enabled")
    {
        paths.push(attack_path_finding(
            "Toxic combination: public DynamoDB + no threat detection",
            "critical",
            target,
            &[
                "Scan/exfiltrate a publicly policy-accessible DynamoDB table",
                "No GuardDuty anomaly detection on API abuse patterns",
                "Maintain persistent data theft without SOC alert",
            ],
            "T1530",
            &format!("Public DynamoDB resource policy in {acct} without GuardDuty — high-impact exfil with low detection."),
            "public_dynamodb_blind",
        ));
    }

    if has_title_contains(findings, "CloudFront S3 origin without OAC")
        && has_title_contains(findings, "S3 bucket world-readable")
    {
        paths.push(attack_path_finding(
            "Toxic combination: CloudFront origin bypass + public S3 bucket",
            "critical",
            target,
            &[
                "Bypass CloudFront and request the S3 origin directly (no OAC/OAI)",
                "Hit a world-readable bucket confirmed by S3 posture checks",
                "Exfiltrate objects without touching the CDN edge logs",
            ],
            "T1530",
            &format!("CloudFront distribution with unprotected S3 origin plus public bucket in {acct} — dual-path data exfiltration."),
            "cloudfront_s3_bypass",
        ));
    }

    if has_title_contains(findings, "CloudFront distribution allows cleartext HTTP")
        && has_title_contains(findings, "CloudFront distribution without WAF")
    {
        paths.push(attack_path_finding(
            "Toxic combination: HTTP-only CloudFront edge + no WAF",
            "high",
            target,
            &[
                "Intercept session tokens on cleartext HTTP cache behaviors",
                "No WAF to block credential stuffing, SSRF probes, or bot abuse",
                "Pivot into origin via stolen cookies or forged headers",
            ],
            "T1040",
            &format!("CloudFront edge in {acct} accepts HTTP and lacks WAF — classic session hijack + unfiltered attack surface."),
            "cloudfront_http_no_waf",
        ));
    }

    if has_title_contains(findings, "Public Route53 zone without DNSSEC")
        && has_title_contains(findings, "Access Analyzer")
    {
        paths.push(attack_path_finding(
            "Toxic combination: DNSSEC gap + proven external AWS access",
            "critical",
            target,
            &[
                "Poison or hijack DNS for a zone without DNSSEC validation",
                "Redirect users to attacker-controlled endpoints",
                "Leverage Access Analyzer–confirmed external resources for payload delivery",
            ],
            "T1557",
            &format!("Unsigned public DNS zone in {acct} combined with external-access findings — supply-chain grade redirect attack."),
            "dnssec_external_access",
        ));
    }

    if has_title_contains(findings, "EventBridge bus allows wildcard principal")
        && has_title_contains(findings, "Lambda function publicly invokable")
    {
        paths.push(attack_path_finding(
            "Toxic combination: open EventBridge bus → inject events → public Lambda",
            "critical",
            target,
            &[
                "PutEvents from any principal allowed by the bus policy",
                "Trigger rules targeting publicly invokable Lambda functions",
                "Execute arbitrary serverless code without authentication",
            ],
            "T1190",
            &format!("Wildcard EventBridge bus policy chained to public Lambda in {acct} — event-driven serverless takeover."),
            "eventbridge_lambda_injection",
        ));
    }

    if has_title_contains(findings, "Redshift cluster publicly accessible")
        && has_title_contains(findings, "GuardDuty not enabled")
    {
        paths.push(attack_path_finding(
            "Toxic combination: public Redshift warehouse + no threat detection",
            "critical",
            target,
            &[
                "Connect to the internet-exposed Redshift endpoint",
                "Dump analytics/PII tables via SQL",
                "No GuardDuty to correlate anomalous data-plane API activity",
            ],
            "T1530",
            &format!("Public Redshift in {acct} without GuardDuty — high-value warehouse exfil with minimal SOC signal."),
            "public_redshift_blind",
        ));
    }

    if has_title_contains(findings, "WAFv2 web ACL has zero rules")
        && has_title_contains(findings, "Internet-facing ALB cleartext HTTP")
    {
        paths.push(attack_path_finding(
            "Toxic combination: pass-through WAF + cleartext internet ALB",
            "critical",
            target,
            &[
                "Hit the internet-facing ALB over unencrypted HTTP",
                "WAF ACL attached (if any) has zero rules — no OWASP/bot filtering",
                "Reach backend workloads without meaningful edge or transport protection",
            ],
            "T1190",
            &format!("Empty WAF rules combined with cleartext ALB in {acct} — layered edge controls are effectively absent."),
            "empty_waf_cleartext_alb",
        ));
    }

    if has_title_contains(findings, "CloudWatch Logs resource policy allows wildcard")
        && has_title_contains(findings, "Secrets Manager secret")
    {
        paths.push(attack_path_finding(
            "Toxic combination: open log policy + rotatable secrets plane",
            "high",
            target,
            &[
                "Inject or read logs via wildcard CloudWatch Logs resource policy",
                "Harvest secret access patterns from application log streams",
                "Target Secrets Manager entries flagged without rotation",
            ],
            "T1552.001",
            &format!("Permissive CloudWatch Logs policy plus Secrets Manager exposure in {acct} — credential harvesting via telemetry."),
            "logs_policy_secrets",
        ));
    }

    if has_title_contains(findings, "DocumentDB instance publicly accessible")
        && has_title_contains(findings, "DocumentDB cluster without encryption")
    {
        paths.push(attack_path_finding(
            "Toxic combination: public unencrypted DocumentDB → full database dump",
            "critical",
            target,
            &[
                "Connect to the public DocumentDB endpoint from anywhere",
                "No encryption at rest — snapshots and storage are plaintext-equivalent",
                "Exfiltrate entire Mongo-compatible collections",
            ],
            "T1530",
            &format!("Public, unencrypted DocumentDB in {acct} — worst-case NoSQL data breach chain."),
            "public_docdb_unencrypted",
        ));
    }

    if (has_title_contains(findings, "Neptune instance publicly accessible")
        || has_title_contains(findings, "Neptune cluster publicly accessible"))
        && (has_title_contains(findings, "Neptune cluster without encryption")
            || has_title_contains(findings, "GuardDuty not enabled"))
    {
        paths.push(attack_path_finding(
            "Toxic combination: internet-exposed graph DB + weak detection/encryption",
            "critical",
            target,
            &[
                "Reach the public Neptune endpoint from the internet",
                "Query or dump the property graph without VPC isolation",
                "Exfiltrate relationship data while GuardDuty/encryption gaps reduce detection",
            ],
            "T1190",
            &format!("Public Neptune cluster in {acct} with encryption or GuardDuty gaps — graph-native data breach."),
            "public_neptune_blind",
        ));
    }

    if has_title_contains(findings, "MemoryDB cluster uses open-access ACL")
        && has_title_contains(findings, "MemoryDB cluster without TLS")
    {
        paths.push(attack_path_finding(
            "Toxic combination: open MemoryDB ACL + cleartext in transit",
            "critical",
            target,
            &[
                "Connect to MemoryDB from any principal allowed by open-access ACL",
                "Intercept or replay Redis-compatible commands without TLS",
                "Harvest session tokens and cache secrets in plaintext",
            ],
            "T1040",
            &format!("Open-access MemoryDB without TLS in {acct} — cache plane becomes a credential vault for attackers."),
            "memorydb_open_no_tls",
        ));
    }

    if has_title_contains(findings, "AWS Backup vault allows wildcard principal")
        && has_title_contains(findings, "S3 bucket")
    {
        paths.push(attack_path_finding(
            "Toxic combination: cross-account backup vault + exposed object store",
            "critical",
            target,
            &[
                "Use wildcard backup vault policy to copy recovery points cross-account",
                "Restore backups into attacker-controlled account",
                "Combine with any S3 exposure finding for staged exfiltration",
            ],
            "T1530",
            &format!("Public backup vault policy in {acct} chained with S3 data exposure — ransomware recovery becomes attacker asset."),
            "backup_vault_s3_chain",
        ));
    }

    if has_title_contains(findings, "Organization SCP allows wildcard actions")
        && has_title_contains(findings, "AdministratorAccess")
    {
        paths.push(attack_path_finding(
            "Toxic combination: permissive org SCP + account admin plane",
            "high",
            target,
            &[
                "Org SCP allows wildcard actions — weak guardrail at the management account",
                "Compromised admin IAM in member account bypasses intended org denies",
                "Lateral movement across OU boundaries via over-privileged roles",
            ],
            "T1078.004",
            &format!("Wildcard org SCP plus admin attachments in {acct} — governance plane fails to contain blast radius."),
            "org_scp_admin_combo",
        ));
    }

    if has_title_contains(findings, "Step Functions state machine logging disabled")
        && has_title_contains(findings, "Lambda Function URL without auth")
    {
        paths.push(attack_path_finding(
            "Toxic combination: blind serverless workflow + public Lambda entry",
            "high",
            target,
            &[
                "Invoke unauthenticated Lambda Function URL for initial access",
                "Trigger Step Functions workflows with logging disabled",
                "Operate orchestration abuse without CloudWatch audit trail",
            ],
            "T1562.002",
            &format!("Public Lambda URL plus unlogged Step Functions in {acct} — invisible serverless attack chain."),
            "sfn_blind_lambda_url",
        ));
    }

    if has_title_contains(findings, "IAM Identity Center (SSO) not enabled")
        && has_title_contains(findings, "IAM access key")
    {
        paths.push(attack_path_finding(
            "Toxic combination: no SSO federation + long-lived access keys",
            "high",
            target,
            &[
                "Human operators rely on long-lived IAM access keys without centralized IdP",
                "No IAM Identity Center means no session-bound federation or permission-set governance",
                "Stolen keys provide persistent account access outside SOC visibility",
            ],
            "T1078.004",
            &format!("Missing IAM Identity Center with stale access keys in {acct} — identity sprawl without federation guardrails."),
            "no_sso_long_lived_keys",
        ));
    }

    paths
}

/// Graph-native toxic paths — correlates live SecurityGraph edges (not just title matching).
fn synthesize_graph_attack_paths(
    graph: &SecurityGraph,
    target: &str,
    account_id: Option<&str>,
) -> Vec<Value> {
    let mut paths = Vec::new();
    let acct = account_id.unwrap_or("the account");

    for node in graph.internet_exposed_nodes() {
        let peers = graph.privileged_identity_peers(node.id.as_str());
        for peer in peers {
            let combo = format!("graph_{}_{}", node.kind, peer.kind);
            if paths.iter().any(|p: &Value| {
                p.get("toxic_combination")
                    .and_then(Value::as_str)
                    == Some(combo.as_str())
            }) {
                continue;
            }
            let title = format!(
                "Graph path: internet-exposed {} → privileged {} ({})",
                node.kind, peer.kind, peer.id
            );
            paths.push(attack_path_finding(
                &title,
                "critical",
                target,
                &[
                    "Reach the internet-exposed asset from an unauthenticated attacker",
                    "Abuse execution_role or instance profile to obtain cloud credentials",
                    "Pivot with over-privileged IAM permissions across the account",
                ],
                "T1078.004",
                &format!(
                    "Security graph in {acct} links internet-exposed `{}` ({}) to privileged identity `{}` — a Wiz-class lateral movement chain validated by live asset relationships.",
                    node.id, node.region, peer.id
                ),
                &combo,
            ));
        }
    }

    paths
}

fn detective_coverage_score(findings: &[Value]) -> i64 {
    let planes = [
        !has_title_contains(findings, "No CloudTrail trail configured"),
        !has_title_contains(findings, "CloudTrail trail not actively logging"),
        !has_title_contains(findings, "GuardDuty not enabled"),
        !has_title_contains(findings, "AWS Config recorder not configured")
            && !has_title_contains(findings, "AWS Config recorder not recording"),
        !has_title_contains(findings, "Access Analyzer not enabled"),
    ];
    let active = planes.iter().filter(|&&p| p).count();
    (active * 100 / planes.len().max(1)) as i64
}

fn domain_score(findings: &[Value], domain: &str) -> f64 {
    let penalty: f64 = findings
        .iter()
        .filter(|f| {
            f.get("domain").and_then(Value::as_str) == Some(domain)
                && f.get("attack_path").and_then(Value::as_bool) != Some(true)
        })
        .map(|f| sev_weight(&finding_sev(f)))
        .sum();
    (100.0 - penalty).clamp(0.0, 100.0)
}

fn posture_score(findings: &[Value]) -> f64 {
    let penalty: f64 = findings
        .iter()
        .filter(|f| f.get("attack_path").and_then(Value::as_bool) != Some(true))
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

fn compliance_scores(findings: &[Value], frameworks: &[String]) -> Map<String, Value> {
    let mut out = Map::new();
    let actionable: Vec<&Value> = findings
        .iter()
        .filter(|f| f.get("attack_path").and_then(Value::as_bool) != Some(true))
        .filter(|f| severity_rank(&finding_sev(f)) >= severity_rank("low"))
        .collect();

    for fw in frameworks {
        let fw_upper = fw.to_ascii_uppercase();
        let key = match fw_upper.as_str() {
            "CIS" => "cis_aws",
            "SOC2" => "soc2",
            "ISO27001" | "ISO" => "iso27001",
            "PCI" => "pci_dss",
            "NIST" => "nist_csf",
            "GDPR" => "gdpr",
            other => other,
        };
        let failed: BTreeSet<String> = actionable
            .iter()
            .filter_map(|f| {
                f.get("compliance")
                    .and_then(|c| c.get(key))
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
            })
            .collect();
        let score = (100.0 - (failed.len() as f64 * 4.5)).clamp(0.0, 100.0);
        out.insert(
            fw.clone(),
            json!({
                "score": score.round() as i64,
                "grade": letter_grade(score),
                "failed_controls": failed.len(),
                "sample_controls": failed.iter().take(8).collect::<Vec<_>>(),
            }),
        );
    }
    out
}

fn remediation_roadmap(findings: &[Value]) -> Vec<Value> {
    let mut ranked: Vec<&Value> = findings
        .iter()
        .filter(|f| f.get("attack_path").and_then(Value::as_bool) != Some(true))
        .filter(|f| f.get("category").and_then(Value::as_str) != Some("summary"))
        .filter(|f| !f.get("remediation").and_then(Value::as_str).unwrap_or("").is_empty())
        .filter(|f| severity_rank(&finding_sev(f)) >= severity_rank("medium"))
        .collect();
    ranked.sort_by_key(|f| std::cmp::Reverse(severity_rank(&finding_sev(f))));
    ranked
        .into_iter()
        .take(12)
        .map(|f| {
            json!({
                "title": f.get("title").and_then(Value::as_str).unwrap_or(""),
                "severity": finding_sev(f),
                "domain": f.get("domain").and_then(Value::as_str).unwrap_or(""),
                "rule_id": f.get("rule_id").and_then(Value::as_str).unwrap_or(""),
                "remediation": f.get("remediation").and_then(Value::as_str).unwrap_or(""),
                "resource_id": f.get("resource_id").and_then(Value::as_str).unwrap_or(""),
                "region": f.get("region").and_then(Value::as_str).unwrap_or(""),
            })
        })
        .collect()
}

fn cnapp_risk_register(findings: &[Value]) -> Vec<Value> {
    use std::collections::HashMap;
    let mut scores: HashMap<String, (f64, String, String, String, String)> = HashMap::new();
    for f in findings {
        if f.get("category").and_then(Value::as_str) == Some("summary")
            || f.get("attack_path").and_then(Value::as_bool) == Some(true)
        {
            continue;
        }
        let rid = f.get("resource_id").and_then(Value::as_str).unwrap_or("");
        if rid.is_empty() {
            continue;
        }
        let sev = finding_sev(f);
        let entry = scores.entry(rid.to_string()).or_insert((
            0.0,
            f.get("resource_type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            f.get("domain").and_then(Value::as_str).unwrap_or("").to_string(),
            f.get("region").and_then(Value::as_str).unwrap_or("").to_string(),
            sev.clone(),
        ));
        entry.0 += sev_weight(&sev);
        if severity_rank(&sev) > severity_rank(&entry.4) {
            entry.4 = sev;
        }
    }
    let mut ranked: Vec<_> = scores.into_iter().collect();
    ranked.sort_by(|a, b| b.1.0.partial_cmp(&a.1.0).unwrap_or(std::cmp::Ordering::Equal));
    ranked
        .into_iter()
        .take(15)
        .map(|(resource_id, (score, resource_type, domain, region, peak_sev))| {
            json!({
                "resource_id": resource_id,
                "resource_type": resource_type,
                "domain": domain,
                "region": region,
                "risk_score": score.round() as i64,
                "peak_severity": peak_sev,
            })
        })
        .collect()
}

fn count_rule(findings: &[Value], rule_id: &str) -> usize {
    findings
        .iter()
        .filter(|f| f.get("rule_id").and_then(Value::as_str) == Some(rule_id))
        .count()
}

fn observability_posture(findings: &[Value]) -> Value {
    json!({
        "logs_no_retention": count_rule(findings, "logs_no_retention"),
        "logs_public_policy": count_rule(findings, "logs_public_resource_policy"),
        "waf_no_logging": count_rule(findings, "wafv2_no_logging"),
        "waf_no_rules": count_rule(findings, "wafv2_no_rules"),
        "redshift_audit_off": count_rule(findings, "redshift_audit_logging_disabled"),
    })
}

fn warehouse_exposure(findings: &[Value]) -> Value {
    json!({
        "public_redshift": count_rule(findings, "redshift_publicly_accessible"),
        "public_rds": count_rule(findings, "rds_publicly_accessible"),
        "public_documentdb": count_rule(findings, "documentdb_publicly_accessible"),
        "public_opensearch": count_rule(findings, "opensearch_public_domain"),
        "public_neptune": count_rule(findings, "neptune_publicly_accessible"),
        "memorydb_open_acl": count_rule(findings, "memorydb_open_acl"),
        "unencrypted_warehouses": count_rule(findings, "redshift_unencrypted")
            + count_rule(findings, "documentdb_unencrypted")
            + count_rule(findings, "rds_unencrypted_storage"),
    })
}

fn cnapp_catalog_status(opts: &CloudScanOptions) -> Value {
    let enabled: Vec<String> = if opts.services.is_empty() {
        CNAPP_SERVICE_PLANES.iter().map(|s| (*s).to_string()).collect()
    } else {
        opts.services.iter().cloned().collect()
    };
    json!({
        "plane_count": CNAPP_PLANE_COUNT,
        "catalog_status": "complete",
        "verification": {
            "live_api_only": true,
            "requires_cross_account_role": true,
            "dispatch_planes_wired": CNAPP_PLANE_COUNT,
            "intelligence_layers": [
                "security_graph",
                "toxic_combination_paths",
                "graph_native_2hop_paths",
                "cnapp_risk_register",
                "data_perimeter",
                "warehouse_exposure",
                "observability_posture",
                "detective_coverage",
                "compliance_scoring",
                "remediation_roadmap",
                "blast_radius_index",
            ],
            "frameworks": opts.frameworks,
        },
        "planes": CNAPP_SERVICE_PLANES,
        "services_enabled": enabled,
        "all_planes_by_default": opts.services.is_empty(),
    })
}

fn data_perimeter_status(findings: &[Value]) -> Value {
    let external = findings
        .iter()
        .filter(|f| f.get("rule_id").and_then(Value::as_str) == Some("access_analyzer_external_access"))
        .count();
    let public_data = findings
        .iter()
        .filter(|f| {
            f.get("domain").and_then(Value::as_str) == Some("data")
                && severity_rank(&finding_sev(f)) >= severity_rank("high")
        })
        .count();
    json!({
        "access_analyzer_external": external,
        "high_severity_data_findings": public_data,
        "perimeter_status": if external == 0 && public_data == 0 { "contained" } else if external > 3 { "breached" } else { "degraded" },
    })
}

fn exposure_metrics(graph: &SecurityGraph) -> Value {
    let internet = graph
        .nodes
        .values()
        .filter(|n| n.exposure == "internet")
        .count();
    let privileged = graph
        .nodes
        .values()
        .filter(|n| {
            n.risk_tags.iter().any(|t| {
                t.contains("admin")
                    || t.contains("privileged")
                    || t.contains("wildcard")
            })
        })
        .count();
    let blast = (internet.saturating_mul(4) + privileged.saturating_mul(6)).min(100);
    json!({
        "total_assets": graph.nodes.len(),
        "relationships": graph.edges.len(),
        "internet_exposed": internet,
        "privileged_assets": privileged,
        "blast_radius_index": blast,
    })
}

fn build_summary(
    target: &str,
    account_id: Option<&str>,
    principal_arn: Option<&str>,
    findings: &[Value],
    attack_paths: &[Value],
    graph: &SecurityGraph,
    opts: &CloudScanOptions,
) -> Value {
    let score = posture_score(findings);
    let grade = letter_grade(score);
    let crit = findings.iter().filter(|f| finding_sev(f) == "critical").count();
    let high = findings.iter().filter(|f| finding_sev(f) == "high").count();
    let med = findings.iter().filter(|f| finding_sev(f) == "medium").count();
    let low = findings.iter().filter(|f| finding_sev(f) == "low").count();
    let compliance = compliance_scores(findings, &opts.frameworks);

    let mut ev = Evidence::new()
        .with("engine", ENGINE_ID)
        .with("scan_mode", "agentless_cross_account")
        .with("regions", json!(opts.effective_regions()))
        .with("services", json!(opts.services.iter().collect::<Vec<_>>()))
        .check("posture_score", true, score.round() as i64);

    if opts.include_security_graph {
        ev = ev.with("security_graph", graph.to_json());
    }

    let mut v = finding_rich(
        ENGINE_ID,
        &format!("AWS Cloud Posture Summary — grade {grade} ({score:.0}/100)"),
        if score >= 85.0 { "info" } else if score >= 65.0 { "medium" } else { "high" },
        "",
        &format!(
            "Agentless CSPM/CNAPP scan of {} scored {:.0}/100 (grade {grade}) with {crit} critical, {high} high, {med} medium findings and {} toxic-combination attack path(s).",
            account_id.unwrap_or(target),
            score,
            attack_paths.len()
        ),
        target,
        1.0,
        ev,
    );

    if let Some(obj) = v.as_object_mut() {
        obj.insert("category".to_string(), json!("summary"));
        obj.insert("posture_score".to_string(), json!(score.round() as i64));
        obj.insert("grade".to_string(), json!(grade));
        obj.insert(
            "subscores".to_string(),
            json!({
                "identity": domain_score(findings, "identity").round() as i64,
                "data": domain_score(findings, "data").round() as i64,
                "network": domain_score(findings, "network").round() as i64,
                "compute": domain_score(findings, "compute").round() as i64,
                "governance": domain_score(findings, "governance").round() as i64,
            }),
        );
        obj.insert(
            "severity_counts".to_string(),
            json!({ "critical": crit, "high": high, "medium": med, "low": low }),
        );
        obj.insert("attack_path_count".to_string(), json!(attack_paths.len()));
        obj.insert("compliance_scores".to_string(), Value::Object(compliance));
        obj.insert("exposure_metrics".to_string(), exposure_metrics(graph));
        obj.insert(
            "detective_coverage".to_string(),
            json!({
                "score": detective_coverage_score(findings),
                "planes": ["cloudtrail", "guardduty", "config", "access_analyzer", "waf_logging", "log_retention"],
            }),
        );
        obj.insert("remediation_roadmap".to_string(), json!(remediation_roadmap(findings)));
        obj.insert("cnapp_risk_register".to_string(), json!(cnapp_risk_register(findings)));
        obj.insert("data_perimeter".to_string(), data_perimeter_status(findings));
        obj.insert("observability_posture".to_string(), observability_posture(findings));
        obj.insert("warehouse_exposure".to_string(), warehouse_exposure(findings));
        obj.insert("cnapp_catalog".to_string(), cnapp_catalog_status(opts));
        obj.insert(
            "rules_triggered".to_string(),
            json!(findings.iter().filter(|f| {
                f.get("category").and_then(Value::as_str) != Some("summary")
                    && f.get("attack_path").and_then(Value::as_bool) != Some(true)
                    && f.get("rule_id").is_some()
            }).count()),
        );
        if opts.include_security_graph {
            obj.insert("security_graph".to_string(), graph.to_json());
        }
        if let Some(a) = account_id {
            obj.insert("account_id".to_string(), json!(a));
        }
        if let Some(p) = principal_arn {
            obj.insert("principal_arn".to_string(), json!(p));
        }
        obj.insert("frameworks".to_string(), json!(opts.frameworks));
    }
    v
}
