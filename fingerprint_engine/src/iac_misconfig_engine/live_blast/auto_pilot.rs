//! Auto-Pilot Remediation — deterministic code patches from proven attack paths + optional GitHub PR.

use super::graph_model::{InfraGraph, NodeKind, ProvenAttackPath};
use super::policies::AUTOPILOT_FIX;
use crate::iac_misconfig_engine::model::{Finding, IacFile};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub struct AutoPilotConfig {
    pub enabled: bool,
    pub create_pr: bool,
    pub repo_url: String,
    pub base_branch: String,
    pub github_token: String,
}

#[derive(Debug, Clone)]
pub struct CodePatch {
    pub file: String,
    pub policy_id: String,
    pub path_id: String,
    pub toxic_class: String,
    pub patch: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Default)]
pub struct AutoPilotResult {
    pub patches: Vec<CodePatch>,
    pub pr_url: Option<String>,
    pub pr_branch: Option<String>,
    pub notes: Vec<String>,
}

/// Generate apply-ready patches from proven paths; optionally open a real GitHub PR.
pub async fn run(
    files: &[IacFile],
    graph: &InfraGraph,
    paths: &[ProvenAttackPath],
    cfg: &AutoPilotConfig,
) -> AutoPilotResult {
    let mut result = AutoPilotResult::default();
    if !cfg.enabled || paths.is_empty() {
        return result;
    }

    let file_map: BTreeMap<String, &IacFile> = files.iter().map(|f| (f.name.clone(), f)).collect();
    let mut seen: BTreeMap<String, CodePatch> = BTreeMap::new();

    for path in paths {
        if path.hops.len() < 2 {
            continue;
        }
        for patch in patches_for_path(path, graph, &file_map) {
            let key = format!("{}|{}", patch.file, patch.toxic_class);
            seen.entry(key).or_insert(patch);
        }
    }
    result.patches = seen.into_values().collect();
    result.notes.push(format!(
        "autopilot: {} patches generated",
        result.patches.len()
    ));

    if cfg.create_pr && !cfg.github_token.trim().is_empty() && !cfg.repo_url.trim().is_empty() {
        match create_github_pr(cfg, &result.patches).await {
            Ok(pr) => {
                result.notes.push(format!("GitHub PR created: {}", pr.url));
                result.pr_url = Some(pr.url);
                result.pr_branch = Some(pr.branch);
            }
            Err(e) => result.notes.push(format!("GitHub PR failed: {e}")),
        }
    } else if cfg.create_pr {
        result
            .notes
            .push("autopilot PR skipped: need github_token + git_repo_url".to_string());
    }

    result
}

#[must_use]
pub fn findings_from_autopilot(patches: &[CodePatch]) -> Vec<Finding> {
    patches
        .iter()
        .map(|p| {
            Finding::new(AUTOPILOT_FIX, &p.path_id, &p.file)
                .observed(p.rationale.clone())
                .fix(p.patch.clone())
        })
        .collect()
}

#[must_use]
pub fn bundle_json(result: &AutoPilotResult) -> Value {
    json!({
        "format": "weissman-autopilot-v1",
        "patch_count": result.patches.len(),
        "pr_url": result.pr_url,
        "pr_branch": result.pr_branch,
        "patches": result.patches.iter().map(|p| json!({
            "file": p.file,
            "policy_id": p.policy_id,
            "path_id": p.path_id,
            "toxic_class": p.toxic_class,
            "patch": p.patch,
            "rationale": p.rationale,
        })).collect::<Vec<_>>(),
        "notes": result.notes,
    })
}

struct PrCreated {
    url: String,
    branch: String,
}

fn patches_for_path(
    path: &ProvenAttackPath,
    graph: &InfraGraph,
    files: &BTreeMap<String, &IacFile>,
) -> Vec<CodePatch> {
    let mut out = Vec::new();
    let end = path.hops.last().map(|h| h.node_id.as_str()).unwrap_or("");
    let Some(node) = graph.nodes.get(end) else {
        return out;
    };
    let file = node.file.clone();
    if !files.contains_key(&file) {
        return out;
    }

    match path.toxic_class.as_str() {
        "CROSS_PLANE_EXFIL" | "IAM_PROVEN_EXFIL" => {
            if node.kind == NodeKind::S3Bucket
                || path.narrative.contains("S3")
                || path.narrative.contains("s3")
            {
                out.push(CodePatch {
                    file: file.clone(),
                    policy_id: "WZ-LIVE-AUTO-001".into(),
                    path_id: path.id.clone(),
                    toxic_class: path.toxic_class.clone(),
                    patch: s3_public_access_block_patch(&node.label),
                    rationale: format!(
                        "Break exfil path {} — block public S3 access",
                        path.narrative
                    ),
                });
            }
            if path.toxic_class == "CROSS_PLANE_EXFIL" {
                if let Some(tf) = files.values().find(|f| f.name.ends_with(".tf")) {
                    out.push(CodePatch {
                        file: tf.name.clone(),
                        policy_id: "WZ-LIVE-AUTO-001".into(),
                        path_id: path.id.clone(),
                        toxic_class: path.toxic_class.clone(),
                        patch: irsa_scope_patch(),
                        rationale: "Scope IRSA role — remove wildcard S3 actions".to_string(),
                    });
                }
            }
        }
        "DATA_BREACH" | "RBAC_PROVEN_SECRET" | "SECRET_EXPOSURE" => {
            if node.kind == NodeKind::RdsInstance {
                out.push(CodePatch {
                    file: file.clone(),
                    policy_id: "WZ-LIVE-AUTO-001".into(),
                    path_id: path.id.clone(),
                    toxic_class: path.toxic_class.clone(),
                    patch: "  publicly_accessible = false".into(),
                    rationale: format!("Close RDS exposure on path {}", path.narrative),
                });
            }
            if path.toxic_class.contains("SECRET") || path.toxic_class.contains("RBAC") {
                if let Some(yaml) = files
                    .values()
                    .find(|f| f.name.ends_with(".yaml") || f.name.ends_with(".yml"))
                {
                    out.push(CodePatch {
                        file: yaml.name.clone(),
                        policy_id: "WZ-LIVE-AUTO-001".into(),
                        path_id: path.id.clone(),
                        toxic_class: path.toxic_class.clone(),
                        patch: ingress_tls_patch(),
                        rationale: "Add TLS + restrict Ingress exposure".to_string(),
                    });
                    out.push(CodePatch {
                        file: "network-policy-autopilot.yaml".into(),
                        policy_id: "WZ-LIVE-AUTO-001".into(),
                        path_id: path.id.clone(),
                        toxic_class: path.toxic_class.clone(),
                        patch: default_deny_netpol(),
                        rationale: "Default-deny NetworkPolicy breaks ingress→secret path"
                            .to_string(),
                    });
                }
            }
        }
        "LATERAL_COMPUTE" | "GENERIC_REACHABILITY" => {
            if node.kind == NodeKind::S3Bucket {
                out.push(CodePatch {
                    file: file.clone(),
                    policy_id: "WZ-LIVE-AUTO-001".into(),
                    path_id: path.id.clone(),
                    toxic_class: path.toxic_class.clone(),
                    patch: s3_public_access_block_patch(&node.label),
                    rationale: format!("Block public S3 on path {}", path.narrative),
                });
            }
            if node.kind == NodeKind::SecurityGroup
                || path.hops.iter().any(|h| h.kind == "security_group")
            {
                out.push(CodePatch {
                    file: file.clone(),
                    policy_id: "WZ-LIVE-AUTO-001".into(),
                    path_id: path.id.clone(),
                    toxic_class: path.toxic_class.clone(),
                    patch: "    cidr_blocks = [\"10.0.0.0/8\"]  # was 0.0.0.0/0 — autopilot".into(),
                    rationale: format!("Restrict SG ingress on path {}", path.narrative),
                });
            }
        }
        _ => {
            if path.hops.len() >= 3 {
                if let Some(h) = path.hops.iter().find(|h| h.kind == "security_group") {
                    if let Some(node) = graph.nodes.get(&h.node_id) {
                        out.push(CodePatch {
                            file: node.file.clone(),
                            policy_id: "WZ-LIVE-AUTO-001".into(),
                            path_id: path.id.clone(),
                            toxic_class: path.toxic_class.clone(),
                            patch:
                                "    cidr_blocks = [\"10.0.0.0/8\"]  # autopilot: restrict open SG"
                                    .into(),
                            rationale: format!("Restrict exposure on path {}", path.narrative),
                        });
                    }
                }
            }
        }
    }
    out
}

fn s3_public_access_block_patch(bucket_label: &str) -> String {
    format!(
        r#"
resource "aws_s3_bucket_public_access_block" "{bucket_label}_block" {{
  bucket = aws_s3_bucket.{bucket_label}.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}
"#
    )
}

fn irsa_scope_patch() -> String {
    r#"
# Autopilot: replace wildcard IAM with least-privilege (review ARNs)
# Action = ["s3:GetObject"]  Resource = ["arn:aws:s3:::SPECIFIC-BUCKET/*"]
"#
    .trim()
    .to_string()
}

fn ingress_tls_patch() -> String {
    r#"
  tls:
  - hosts:
    - REPLACE_ME.example.com
    secretName: autopilot-tls
"#
    .trim()
    .to_string()
}

fn default_deny_netpol() -> String {
    r#"apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: autopilot-default-deny
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
"#
    .to_string()
}

fn parse_github(url: &str) -> Option<(String, String)> {
    let u = url.trim().trim_end_matches(".git");
    let rest = u
        .strip_prefix("https://github.com/")
        .or_else(|| u.strip_prefix("http://github.com/"))
        .or_else(|| u.strip_prefix("git@github.com:"))
        .or_else(|| u.strip_prefix("github.com/"))?;
    let mut parts = rest.split('/');
    let owner = parts.next()?.to_string();
    let repo = parts.next()?.to_string();
    Some((owner, repo))
}

async fn create_github_pr(
    cfg: &AutoPilotConfig,
    patches: &[CodePatch],
) -> Result<PrCreated, String> {
    if patches.is_empty() {
        return Err("no patches".into());
    }
    let (owner, repo) = parse_github(&cfg.repo_url).ok_or("invalid git_repo_url")?;
    let token = cfg.github_token.trim();
    let base = if cfg.base_branch.trim().is_empty() {
        "main"
    } else {
        cfg.base_branch.trim()
    };
    let branch = format!("weissman-autopilot-{}", chrono_lite_ts());
    let client = reqwest::Client::builder()
        .user_agent("Weissman-AutoPilot/1.0")
        .build()
        .map_err(|e| e.to_string())?;

    let ref_url = format!("https://api.github.com/repos/{owner}/{repo}/git/ref/heads/{base}");
    let ref_resp = client
        .get(&ref_url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !ref_resp.status().is_success() {
        return Err(format!("GET ref failed: {}", ref_resp.status()));
    }
    let ref_json: Value = ref_resp.json().await.map_err(|e| e.to_string())?;
    let sha = ref_json
        .get("object")
        .and_then(|o| o.get("sha"))
        .and_then(Value::as_str)
        .ok_or("missing base sha")?;

    let create_ref = json!({ "ref": format!("refs/heads/{branch}"), "sha": sha });
    let cr = client
        .post(format!(
            "https://api.github.com/repos/{owner}/{repo}/git/refs"
        ))
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/vnd.github+json")
        .json(&create_ref)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !cr.status().is_success() && cr.status().as_u16() != 422 {
        return Err(format!("create ref failed: {}", cr.status()));
    }

    for patch in patches.iter().take(20) {
        let path = patch.file.replace('\\', "/");
        let get_url =
            format!("https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={branch}");
        let existing = match client
            .get(&get_url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => r.json::<Value>().await.ok(),
            _ => None,
        };
        let existing_sha = existing
            .as_ref()
            .and_then(|v| v.get("sha").and_then(Value::as_str).map(str::to_string));
        let merged_content = if let Some(v) = existing.as_ref() {
            v.get("content")
                .and_then(Value::as_str)
                .map(str::to_string)
                .and_then(|b64| base64_decode(&b64))
                .map(|existing_text| merge_patch(&existing_text, &patch.patch))
                .unwrap_or_else(|| patch.patch.clone())
        } else {
            patch.patch.clone()
        };
        let content_b64 = base64_encode(merged_content.as_bytes());

        let mut body = json!({
            "message": format!("[Weissman AutoPilot] {} — {}", patch.toxic_class, patch.path_id),
            "content": content_b64,
            "branch": branch,
        });
        if let Some(sha) = existing_sha {
            body["sha"] = json!(sha);
        }
        let put_url = format!("https://api.github.com/repos/{owner}/{repo}/contents/{path}");
        let put = client
            .put(&put_url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/vnd.github+json")
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !put.status().is_success() {
            return Err(format!("PUT contents {path} failed: {}", put.status()));
        }
    }

    let pr_body = json!({
        "title": "[Weissman AutoPilot] IaC security remediation",
        "head": branch,
        "base": base,
        "body": "Automated remediation from deterministic attack-path analysis. Review before merge.",
    });
    let pr_resp = client
        .post(format!("https://api.github.com/repos/{owner}/{repo}/pulls"))
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/vnd.github+json")
        .json(&pr_body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !pr_resp.status().is_success() {
        return Err(format!("create PR failed: {}", pr_resp.status()));
    }
    let pr_json: Value = pr_resp.json().await.map_err(|e| e.to_string())?;
    let url = pr_json
        .get("html_url")
        .and_then(Value::as_str)
        .ok_or("missing pr url")?
        .to_string();
    Ok(PrCreated { url, branch })
}

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn base64_decode(input: &str) -> Option<String> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = cleaned.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let a = decode_b64_char(*bytes.get(i)?)?;
        let b = decode_b64_char(*bytes.get(i + 1)?)?;
        let c = bytes
            .get(i + 2)
            .filter(|&&x| x != b'=')
            .and_then(|&x| decode_b64_char(x));
        let d = bytes
            .get(i + 3)
            .filter(|&&x| x != b'=')
            .and_then(|&x| decode_b64_char(x));
        out.push(((a << 2) | (b >> 4)) as u8);
        if let Some(c) = c {
            out.push((((b & 0xf) << 4) | (c >> 2)) as u8);
            if let Some(d) = d {
                out.push((((c & 0x3) << 6) | d) as u8);
            }
        }
        i += 4;
    }
    String::from_utf8(out).ok()
}

fn decode_b64_char(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn merge_patch(existing: &str, patch: &str) -> String {
    if existing.contains("# Weissman AutoPilot") {
        return existing.to_string();
    }
    format!("{existing}\n\n# Weissman AutoPilot remediation\n{patch}")
}

fn chrono_lite_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_s3_patch() {
        let path = ProvenAttackPath {
            id: "WZ-PATH-1".into(),
            title: "t".into(),
            hops: vec![super::super::graph_model::PathHop {
                node_id: "s3:assets".into(),
                kind: "s3_bucket".into(),
                label: "assets".into(),
                edge_kind: None,
                evidence: None,
                live_status: "not_checked".into(),
            }],
            target_sensitive: true,
            live_confirmed_hops: 0,
            permission_proven_hops: 1,
            toxic_class: "GENERIC_REACHABILITY".into(),
            narrative: "Internet → assets".into(),
        };
        let mut g = InfraGraph::default();
        g.add_node(super::super::graph_model::GraphNode {
            id: "s3:assets".into(),
            kind: NodeKind::S3Bucket,
            label: "assets".into(),
            file: "main.tf".into(),
            provider: "aws".into(),
            sensitive: true,
            internet_facing: true,
            live_status: super::super::graph_model::LiveStatus::NotChecked,
            live_evidence: None,
            iac_address: Some("aws_s3_bucket.assets".into()),
            cloud_arn: None,
        });
        let mut files_map = BTreeMap::new();
        let f = IacFile {
            name: "main.tf".into(),
            content: "".into(),
            forced: None,
            origin: "inline".into(),
        };
        files_map.insert("main.tf".into(), &f);
        let patches = patches_for_path(&path, &g, &files_map);
        assert!(!patches.is_empty());
    }
}
