//! Azure ARM template analyzer (JSON): walks the resource tree (including nested resources) and
//! enforces core CIS Azure controls for storage, network, SQL, Key Vault and AKS.

use super::model::{line_of, Finding, PolicyMeta, Severity};
use serde_yaml::Value;

use Severity::{High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "arm",
            provider: "azure",
            description: $desc,
            remediation: $rem,
            mitre: $mitre,
            cwe: $cwe,
            references: $refs,
            compliance: $comp,
        }
    };
}

pub const STORAGE_HTTPS: PolicyMeta = pol!(
    "WZ-ARM-ST-001",
    "Storage account allows HTTP traffic",
    High,
    "supportsHttpsTrafficOnly is false on a Microsoft.Storage/storageAccounts resource.",
    "Set properties.supportsHttpsTrafficOnly = true.",
    "T1040",
    "CWE-319",
    &["CIS-Azure-3.1"],
    &["CIS-Azure-3.1", "NIST-SC-8", "PCI-DSS-4.1"]
);
pub const STORAGE_TLS: PolicyMeta = pol!(
    "WZ-ARM-ST-002",
    "Storage account min TLS below 1.2",
    Medium,
    "minimumTlsVersion is below TLS1_2.",
    "Set properties.minimumTlsVersion = TLS1_2.",
    "T1040",
    "CWE-326",
    &["CIS-Azure-3.12"],
    &["CIS-Azure-3.12", "NIST-SC-8"]
);
pub const STORAGE_PUBLIC: PolicyMeta = pol!(
    "WZ-ARM-ST-003",
    "Storage account allows public blob access",
    High,
    "allowBlobPublicAccess is true on a storage account.",
    "Set properties.allowBlobPublicAccess = false.",
    "T1530",
    "CWE-732",
    &["CIS-Azure-3.7"],
    &["CIS-Azure-3.7", "NIST-AC-3", "PCI-DSS-1.2"]
);
pub const NSG_OPEN: PolicyMeta = pol!(
    "WZ-ARM-NSG-001",
    "NSG rule allows inbound from any source",
    High,
    "A network security rule allows inbound from '*'/'Internet'/0.0.0.0/0.",
    "Restrict sourceAddressPrefix; never expose management ports publicly.",
    "T1190",
    "CWE-284",
    &["CIS-Azure-6.1", "CIS-Azure-6.2"],
    &["CIS-Azure-6.1", "CIS-Azure-6.2", "NIST-SC-7"]
);
pub const SQL_PUBLIC: PolicyMeta = pol!("WZ-ARM-SQL-001", "SQL server public network access / weak TLS", High, "A Microsoft.Sql/servers resource enables public network access or sets minimalTlsVersion below 1.2.", "Set publicNetworkAccess = Disabled and minimalTlsVersion = 1.2; use private endpoints.", "T1190", "CWE-319", &["CIS-Azure-4.x"], &["NIST-SC-7", "PCI-DSS-1.3.6", "HIPAA-164.312(e)(1)"]);
pub const KV_PROTECTION: PolicyMeta = pol!(
    "WZ-ARM-KV-001",
    "Key Vault soft-delete / purge protection disabled",
    Medium,
    "enableSoftDelete or enablePurgeProtection is not true on a Key Vault.",
    "Set properties.enableSoftDelete = true and enablePurgeProtection = true.",
    "T1485",
    "CWE-693",
    &["CIS-Azure-8.x"],
    &["NIST-CP-9", "SOC2-A1.2"]
);
pub const AKS_RBAC: PolicyMeta = pol!(
    "WZ-ARM-AKS-001",
    "AKS cluster has RBAC disabled",
    High,
    "enableRBAC is false on a Microsoft.ContainerService/managedClusters resource.",
    "Set properties.enableRBAC = true and integrate Entra ID.",
    "T1078",
    "CWE-284",
    &["CIS-Azure-8.x"],
    &["NIST-AC-3", "SOC2-CC6.3"]
);
pub const AKS_PUBLIC_API: PolicyMeta = pol!(
    "WZ-ARM-AKS-002",
    "AKS API server is publicly reachable",
    Medium,
    "The cluster does not restrict the API server (no authorized IP ranges / private cluster).",
    "Enable a private cluster or apiServerAccessProfile authorizedIPRanges.",
    "T1190",
    "CWE-668",
    &["CIS-Azure-8.x"],
    &["NIST-SC-7"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![
        STORAGE_HTTPS,
        STORAGE_TLS,
        STORAGE_PUBLIC,
        NSG_OPEN,
        SQL_PUBLIC,
        KV_PROTECTION,
        AKS_RBAC,
        AKS_PUBLIC_API,
    ]
}

fn bool_like(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Collect every object that looks like an ARM resource (`type` + usually `properties`).
fn collect_resources<'a>(v: &'a Value, acc: &mut Vec<&'a Value>) {
    match v {
        Value::Mapping(m) => {
            if v.get("type").and_then(Value::as_str).is_some() {
                acc.push(v);
            }
            for (_, val) in m {
                collect_resources(val, acc);
            }
        }
        Value::Sequence(seq) => {
            for x in seq {
                collect_resources(x, acc);
            }
        }
        _ => {}
    }
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(doc): Result<Value, _> = serde_yaml::from_str(content) else {
        return out;
    };
    let mut resources = Vec::new();
    collect_resources(&doc, &mut resources);

    for res in resources {
        let rtype = res
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let tlow = rtype.to_ascii_lowercase();
        let name = res
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("resource")
            .to_string();
        let props = res.get("properties").cloned().unwrap_or(Value::Null);
        let line = line_of(content, &rtype).max(1);
        let id = format!("{} ({})", rtype, name);

        if tlow.contains("microsoft.storage/storageaccounts") {
            if props.get("supportsHttpsTrafficOnly").and_then(bool_like) == Some(false) {
                out.push(
                    Finding::new(STORAGE_HTTPS, &id, file)
                        .at(line)
                        .observed("supportsHttpsTrafficOnly: false")
                        .fix("\"supportsHttpsTrafficOnly\": true"),
                );
            }
            if let Some(tls) = props.get("minimumTlsVersion").and_then(Value::as_str) {
                if !tls.contains("1_2") && !tls.contains("1.2") && !tls.contains("1_3") {
                    out.push(
                        Finding::new(STORAGE_TLS, &id, file)
                            .at(line)
                            .observed(format!("minimumTlsVersion: {}", tls))
                            .fix("\"minimumTlsVersion\": \"TLS1_2\""),
                    );
                }
            }
            if props.get("allowBlobPublicAccess").and_then(bool_like) == Some(true) {
                out.push(
                    Finding::new(STORAGE_PUBLIC, &id, file)
                        .at(line)
                        .observed("allowBlobPublicAccess: true")
                        .fix("\"allowBlobPublicAccess\": false"),
                );
            }
        } else if tlow.contains("networksecuritygroups/securityrules")
            || (tlow.contains("networksecuritygroups") && props.get("securityRules").is_some())
        {
            // direct rule resource
            check_nsg_rule(file, &id, line, &props, &mut out);
            if let Some(rules) = props.get("securityRules").and_then(Value::as_sequence) {
                for r in rules {
                    let rp = r.get("properties").cloned().unwrap_or_else(|| r.clone());
                    check_nsg_rule(file, &id, line, &rp, &mut out);
                }
            }
        } else if tlow.contains("microsoft.sql/servers") {
            let public = props
                .get("publicNetworkAccess")
                .and_then(Value::as_str)
                .map(|s| s.eq_ignore_ascii_case("enabled"))
                .unwrap_or(false);
            let weak_tls = props
                .get("minimalTlsVersion")
                .and_then(Value::as_str)
                .map(|s| !s.contains("1.2") && !s.contains("1.3"))
                .unwrap_or(false);
            if public || weak_tls {
                out.push(
                    Finding::new(SQL_PUBLIC, &id, file)
                        .at(line)
                        .observed("publicNetworkAccess Enabled or minimalTlsVersion < 1.2")
                        .fix(
                            "\"publicNetworkAccess\": \"Disabled\", \"minimalTlsVersion\": \"1.2\"",
                        ),
                );
            }
        } else if tlow.contains("microsoft.keyvault/vaults") {
            let soft = props.get("enableSoftDelete").and_then(bool_like) == Some(true);
            let purge = props.get("enablePurgeProtection").and_then(bool_like) == Some(true);
            if !soft || !purge {
                out.push(
                    Finding::new(KV_PROTECTION, &id, file)
                        .at(line)
                        .observed("enableSoftDelete/enablePurgeProtection not both true")
                        .fix("\"enableSoftDelete\": true, \"enablePurgeProtection\": true"),
                );
            }
        } else if tlow.contains("microsoft.containerservice/managedclusters") {
            if props.get("enableRBAC").and_then(bool_like) == Some(false) {
                out.push(
                    Finding::new(AKS_RBAC, &id, file)
                        .at(line)
                        .observed("enableRBAC: false")
                        .fix("\"enableRBAC\": true"),
                );
            }
            let restricted = props
                .get("apiServerAccessProfile")
                .map(|p| {
                    p.get("enablePrivateCluster").and_then(bool_like) == Some(true)
                        || p.get("authorizedIPRanges")
                            .and_then(Value::as_sequence)
                            .map(|s| !s.is_empty())
                            .unwrap_or(false)
                })
                .unwrap_or(false);
            if !restricted {
                out.push(
                    Finding::new(AKS_PUBLIC_API, &id, file)
                        .at(line)
                        .observed("no private cluster / authorizedIPRanges")
                        .fix("\"apiServerAccessProfile\": { \"enablePrivateCluster\": true }"),
                );
            }
        }
    }
    out
}

fn check_nsg_rule(file: &str, id: &str, line: usize, p: &Value, out: &mut Vec<Finding>) {
    let dir = p.get("direction").and_then(Value::as_str).unwrap_or("");
    let access = p.get("access").and_then(Value::as_str).unwrap_or("");
    let src = p
        .get("sourceAddressPrefix")
        .and_then(Value::as_str)
        .unwrap_or("");
    let open =
        src == "*" || src == "0.0.0.0/0" || src.eq_ignore_ascii_case("internet") || src == "::/0";
    if dir.eq_ignore_ascii_case("Inbound") && access.eq_ignore_ascii_case("Allow") && open {
        out.push(
            Finding::new(NSG_OPEN, id, file)
                .at(line)
                .observed(format!("sourceAddressPrefix: {}", src))
                .fix("\"sourceAddressPrefix\": \"10.0.0.0/8\""),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_storage_http_and_public() {
        let j = r#"{"resources":[{"type":"Microsoft.Storage/storageAccounts","name":"sa","properties":{"supportsHttpsTrafficOnly":false,"allowBlobPublicAccess":true,"minimumTlsVersion":"TLS1_0"}}]}"#;
        let f = evaluate("azuredeploy.json", j);
        assert!(f.iter().any(|x| x.policy.id == STORAGE_HTTPS.id));
        assert!(f.iter().any(|x| x.policy.id == STORAGE_PUBLIC.id));
        assert!(f.iter().any(|x| x.policy.id == STORAGE_TLS.id));
    }
}
