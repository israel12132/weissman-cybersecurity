//! KEDA autoscaling analyzer — insecure scalers, plaintext trigger auth, and dangerous minReplica=0
//! on production workloads without safeguards.

use super::model::{Finding, PolicyMeta, Severity};

use Severity::{Critical, High, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "keda",
            provider: "kubernetes",
            description: $desc,
            remediation: $rem,
            mitre: $mitre,
            cwe: $cwe,
            references: $refs,
            compliance: $comp,
        }
    };
}

pub const TRIGGER_SECRET: PolicyMeta = pol!(
    "WZ-KEDA-001",
    "KEDA TriggerAuthentication embeds secret literal",
    Critical,
    "TriggerAuthentication parameter contains password/token literal instead of secretKeyRef.",
    "Use secretTargetRef / env / podIdentity only; never embed literals.",
    "T1552.001",
    "CWE-798",
    &["CIS-K8S-5.x"],
    &["NIST-IA-5", "PCI-DSS-8.2.1"]
);
pub const INSECURE_PROM: PolicyMeta = pol!(
    "WZ-KEDA-002",
    "KEDA Prometheus scaler uses HTTP without TLS",
    High,
    "prometheus serverAddress uses http:// — metrics and auth tokens exposed.",
    "Use https:// with mTLS or service mesh; scope queries.",
    "T1040",
    "CWE-319",
    &["CIS-K8S-5.x"],
    &["NIST-SC-8", "PCI-DSS-4.1"]
);
pub const KAFKA_NO_TLS: PolicyMeta = pol!(
    "WZ-KEDA-003",
    "KEDA Kafka scaler disables TLS",
    High,
    "tls: disable or enable: false on kafka trigger metadata.",
    "Enable TLS and SASL for Kafka scalers; use TriggerAuthentication.",
    "T1040",
    "CWE-319",
    &["CIS-K8S-5.x"],
    &["NIST-SC-8", "SOC2-CC6.6"]
);
pub const SCALE_TO_ZERO_PROD: PolicyMeta = pol!(
    "WZ-KEDA-004",
    "KEDA ScaledObject minReplicaCount 0 on production workload",
    Medium,
    "minReplicaCount: 0 on prod-named ScaledObject — cold-start bypass and availability risk.",
    "Set minReplicaCount >= 1 for production; use separate dev profiles.",
    "T1499",
    "CWE-693",
    &["CIS-K8S-5.x"],
    &["NIST-CP-10", "SOC2-A1.2"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![
        TRIGGER_SECRET,
        INSECURE_PROM,
        KAFKA_NO_TLS,
        SCALE_TO_ZERO_PROD,
    ]
}

fn is_keda(content: &str) -> bool {
    let lc = content.to_ascii_lowercase();
    lc.contains("keda.sh")
        || lc.contains("kind: scaledobject")
        || lc.contains("kind: triggerauthentication")
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_keda(content) {
        return out;
    }
    let lc = content.to_ascii_lowercase();

    if (lc.contains("triggerauthentication") || lc.contains("parameter:"))
        && (lc.contains("password:") || lc.contains("token:") || lc.contains("apikey:"))
        && !lc.contains("secretkeyref")
    {
        out.push(
            Finding::new(TRIGGER_SECRET, file, file).observed("literal in TriggerAuthentication"),
        );
    }
    if lc.contains("serveraddress: http://") || lc.contains("serveraddress: \"http://") {
        out.push(Finding::new(INSECURE_PROM, file, file).observed("Prometheus http://"));
    }
    if lc.contains("tls: disable")
        || lc.contains("tls: \"disable\"")
        || lc.contains("enable: false") && lc.contains("kafka")
    {
        out.push(Finding::new(KAFKA_NO_TLS, file, file).observed("Kafka TLS disabled"));
    }
    if lc.contains("minreplicacount: 0") && (lc.contains("prod") || lc.contains("production")) {
        out.push(Finding::new(SCALE_TO_ZERO_PROD, file, file).observed("scale-to-zero prod"));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_http_prometheus() {
        let y = "apiVersion: keda.sh/v1alpha1\nkind: ScaledObject\nspec:\n  triggers:\n    - type: prometheus\n      metadata:\n        serverAddress: http://prometheus:9090";
        let f = evaluate("keda/so.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == INSECURE_PROM.id));
    }
}
