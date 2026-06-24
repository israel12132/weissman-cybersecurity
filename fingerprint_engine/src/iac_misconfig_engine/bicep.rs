//! Native Azure Bicep analyzer — storage public access, open NSG rules, Key Vault soft-delete off,
//! SQL public endpoints. Deterministic pattern matching on Bicep DSL (not ARM JSON).

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id, title: $title, severity: $sev, framework: "bicep", provider: "azure",
            description: $desc, remediation: $rem, mitre: $mitre, cwe: $cwe, references: $refs, compliance: $comp,
        }
    };
}

pub const ST_PUBLIC: PolicyMeta = pol!("WZ-BCP-001", "Bicep Storage Account allows public blob access", High, "allowBlobPublicAccess / publicNetworkAccess enables anonymous blob enumeration.", "Set allowBlobPublicAccess: false and publicNetworkAccess: Disabled.", "T1530", "CWE-732", &["CIS-Azure-3.7"], &["CIS-Azure-3.7", "NIST-AC-3", "PCI-DSS-1.2"]);
pub const NSG_OPEN: PolicyMeta = pol!("WZ-BCP-002", "Bicep NSG allows inbound from *", High, "securityRules with sourceAddressPrefix '*' or 'Internet' expose workloads.", "Restrict sourceAddressPrefix to known CIDR ranges.", "T1190", "CWE-284", &["CIS-Azure-6.1"], &["CIS-Azure-6.1", "NIST-SC-7"]);
pub const KV_NO_SOFT: PolicyMeta = pol!("WZ-BCP-003", "Bicep Key Vault soft-delete disabled", Medium, "enableSoftDelete: false risks permanent secret loss and complicates recovery.", "Set enableSoftDelete: true and enablePurgeProtection: true.", "T1485", "CWE-404", &["CIS-Azure-9.x"], &["NIST-CP-9", "SOC2-A1.2"]);
pub const SQL_PUBLIC: PolicyMeta = pol!("WZ-BCP-004", "Bicep SQL Server allows public network access", High, "publicNetworkAccess: 'Enabled' exposes the database endpoint to the internet.", "Set publicNetworkAccess: 'Disabled' and use private endpoints.", "T1190", "CWE-668", &["CIS-Azure-4.x"], &["NIST-SC-7", "PCI-DSS-1.3.6"]);
pub const HTTPS_OFF: PolicyMeta = pol!("WZ-BCP-005", "Bicep Storage allows HTTP traffic", High, "supportsHttpsTrafficOnly: false permits cleartext blob access.", "Set supportsHttpsTrafficOnly: true and minimumTlsVersion: 'TLS1_2'.", "T1040", "CWE-319", &["CIS-Azure-3.1"], &["NIST-SC-8", "PCI-DSS-4.1"]);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![ST_PUBLIC, NSG_OPEN, KV_NO_SOFT, SQL_PUBLIC, HTTPS_OFF]
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let lc = content.to_ascii_lowercase();
    if !file.to_ascii_lowercase().ends_with(".bicep") && !lc.contains("resource ") {
        return out;
    }

    if lc.contains("allowblobpublicaccess: true") || lc.contains("publicnetworkaccess: 'enabled'") && lc.contains("microsoft.storage/storageaccounts") {
        out.push(Finding::new(ST_PUBLIC, file, file).observed("public blob/network access enabled on storage"));
    }
    if (lc.contains("sourceaddressprefix: '*'") || lc.contains("sourceaddressprefix: 'internet'"))
        && lc.contains("microsoft.network/networksecuritygroups")
    {
        out.push(Finding::new(NSG_OPEN, file, file).observed("NSG rule sourceAddressPrefix *"));
    }
    if lc.contains("enablesoftdelete: false") && lc.contains("microsoft.keyvault/vaults") {
        out.push(Finding::new(KV_NO_SOFT, file, file).observed("enableSoftDelete: false"));
    }
    if lc.contains("publicnetworkaccess: 'enabled'") && lc.contains("microsoft.sql/servers") {
        out.push(Finding::new(SQL_PUBLIC, file, file).observed("SQL publicNetworkAccess Enabled"));
    }
    if lc.contains("supportshttpstrafficonly: false") {
        out.push(Finding::new(HTTPS_OFF, file, file).observed("supportsHttpsTrafficOnly: false"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_storage_public() {
        let b = "resource st 'Microsoft.Storage/storageAccounts@2021-09-01' = {\n  properties: { allowBlobPublicAccess: true }\n}\n";
        assert!(evaluate("main.bicep", b).iter().any(|f| f.policy.id == ST_PUBLIC.id));
    }
}
