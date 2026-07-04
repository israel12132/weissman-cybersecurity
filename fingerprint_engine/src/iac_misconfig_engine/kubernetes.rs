//! Kubernetes analyzer: parses multi-document YAML manifests and enforces the Pod Security
//! Standards (restricted profile) plus CIS Kubernetes Benchmark workload + RBAC controls.

use super::model::{line_of, Finding, PolicyMeta, Severity};
use serde::Deserialize;
use serde_yaml::Value;

use Severity::{Critical, High, Info, Low, Medium};

macro_rules! pol {
    ($id:expr, $title:expr, $sev:expr, $desc:expr, $rem:expr, $mitre:expr, $cwe:expr, $refs:expr, $comp:expr) => {
        PolicyMeta {
            id: $id,
            title: $title,
            severity: $sev,
            framework: "kubernetes",
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

pub const PRIVILEGED: PolicyMeta = pol!("WZ-K8S-001", "Container runs in privileged mode", Critical, "A container sets securityContext.privileged = true, granting host-level access equivalent to root on the node.", "Set privileged = false and grant only the specific Linux capabilities the workload needs.", "T1610", "CWE-250", &["CIS-K8S-5.2.1", "https://kubernetes.io/docs/concepts/security/pod-security-standards/"], &["CIS-K8S-5.2.1", "NIST-AC-6", "SOC2-CC6.3", "PCI-DSS-2.2.4", "MITRE-T1610"]);
pub const ALLOW_PRIV_ESC: PolicyMeta = pol!("WZ-K8S-002", "Privilege escalation is allowed", High, "allowPrivilegeEscalation is not set to false, letting a process gain more privileges than its parent (e.g. via setuid).", "Set securityContext.allowPrivilegeEscalation = false.", "T1068", "CWE-269", &["CIS-K8S-5.2.5"], &["CIS-K8S-5.2.5", "NIST-AC-6", "SOC2-CC6.3"]);
pub const RUN_AS_ROOT: PolicyMeta = pol!(
    "WZ-K8S-003",
    "Container may run as root",
    High,
    "runAsNonRoot is not true at pod or container level, so the workload can run as UID 0.",
    "Set securityContext.runAsNonRoot = true and runAsUser to a non-zero UID.",
    "T1611",
    "CWE-250",
    &["CIS-K8S-5.2.6"],
    &["CIS-K8S-5.2.6", "NIST-AC-6", "PCI-DSS-2.2.4"]
);
pub const RO_ROOT_FS: PolicyMeta = pol!("WZ-K8S-004", "Root filesystem is writable", Medium, "readOnlyRootFilesystem is not true, allowing an attacker to tamper with the container filesystem and persist.", "Set securityContext.readOnlyRootFilesystem = true and mount writable emptyDir volumes where needed.", "T1222", "CWE-732", &["CIS-K8S-5.2.x"], &["NIST-CM-5", "SOC2-CC6.8"]);
pub const HOST_NETWORK: PolicyMeta = pol!("WZ-K8S-005", "Pod uses the host network namespace", High, "hostNetwork = true shares the node's network stack, bypassing network policies and exposing host interfaces.", "Set hostNetwork = false; use a Service for connectivity.", "T1610", "CWE-668", &["CIS-K8S-5.2.4"], &["CIS-K8S-5.2.4", "NIST-SC-7", "SOC2-CC6.6"]);
pub const HOST_PID: PolicyMeta = pol!("WZ-K8S-006", "Pod uses the host PID namespace", High, "hostPID = true lets the container see and signal host processes, aiding escape and credential theft.", "Set hostPID = false.", "T1610", "CWE-668", &["CIS-K8S-5.2.2"], &["CIS-K8S-5.2.2", "NIST-AC-6"]);
pub const HOST_IPC: PolicyMeta = pol!(
    "WZ-K8S-007",
    "Pod uses the host IPC namespace",
    High,
    "hostIPC = true shares host inter-process communication, enabling cross-workload data access.",
    "Set hostIPC = false.",
    "T1610",
    "CWE-668",
    &["CIS-K8S-5.2.3"],
    &["CIS-K8S-5.2.3", "NIST-AC-6"]
);
pub const DANGEROUS_CAPS: PolicyMeta = pol!("WZ-K8S-008", "Container adds dangerous Linux capabilities", High, "capabilities.add grants powerful capabilities (e.g. SYS_ADMIN, NET_ADMIN, NET_RAW, ALL) that enable container escape.", "Drop ALL capabilities and add back only the minimal set strictly required.", "T1610", "CWE-250", &["CIS-K8S-5.2.8", "CIS-K8S-5.2.9"], &["CIS-K8S-5.2.8", "NIST-AC-6", "MITRE-T1610"]);
pub const CAPS_NOT_DROPPED: PolicyMeta = pol!(
    "WZ-K8S-009",
    "Container does not drop ALL capabilities",
    Low,
    "capabilities.drop does not include ALL, leaving default capabilities available.",
    "Set capabilities.drop = [\"ALL\"] and add back only what is needed.",
    "T1610",
    "CWE-250",
    &["CIS-K8S-5.2.x"],
    &["NIST-AC-6"]
);
pub const HOSTPATH: PolicyMeta = pol!("WZ-K8S-010", "Pod mounts a sensitive hostPath volume", High, "A hostPath volume mounts a node directory into the pod; mounting /, /var/run/docker.sock or /etc enables escape.", "Avoid hostPath; use PersistentVolumes/CSI. If unavoidable, mount a minimal read-only sub-path.", "T1610", "CWE-668", &["CIS-K8S-5.2.x"], &["NIST-AC-6", "SOC2-CC6.3", "MITRE-T1610"]);
pub const IMAGE_LATEST: PolicyMeta = pol!("WZ-K8S-011", "Container image uses a mutable tag", Low, "An image uses the 'latest' tag or no tag, making deployments non-reproducible and bypassing pinning.", "Pin images to an immutable digest (image@sha256:…) or a fixed version tag.", "T1525", "CWE-494", &["CIS-K8S-5.x"], &["NIST-CM-2", "SOC2-CC8.1"]);
pub const NO_LIMITS: PolicyMeta = pol!("WZ-K8S-012", "Container has no CPU/memory limits", Low, "No resources.limits are set, enabling noisy-neighbour and denial-of-service via resource exhaustion.", "Set resources.limits.cpu and resources.limits.memory (and matching requests).", "T1499", "CWE-770", &["CIS-K8S-5.x"], &["NIST-SC-6", "SOC2-A1.1"]);
pub const SA_TOKEN: PolicyMeta = pol!("WZ-K8S-013", "Service account token is auto-mounted", Medium, "automountServiceAccountToken is not false, exposing API credentials to a compromised container.", "Set automountServiceAccountToken = false unless the workload calls the Kubernetes API.", "T1528", "CWE-522", &["CIS-K8S-5.1.6"], &["CIS-K8S-5.1.6", "NIST-AC-6", "MITRE-T1528"]);
pub const RBAC_WILDCARD: PolicyMeta = pol!(
    "WZ-K8S-014",
    "RBAC role grants wildcard permissions",
    High,
    "A Role/ClusterRole rule grants verbs '*' on resources '*', equivalent to cluster admin.",
    "Scope RBAC rules to specific verbs and resources following least privilege.",
    "T1098",
    "CWE-269",
    &["CIS-K8S-5.1.1", "CIS-K8S-5.1.3"],
    &["CIS-K8S-5.1.1", "CIS-K8S-5.1.3", "NIST-AC-6", "SOC2-CC6.3"]
);
pub const DEFAULT_NS: PolicyMeta = pol!("WZ-K8S-015", "Workload deployed to the default namespace", Info, "Running in the default namespace makes scoping, RBAC and network policy harder and is discouraged by CIS.", "Deploy workloads into dedicated, labelled namespaces.", "T1610", "CWE-1188", &["CIS-K8S-5.7.1"], &["CIS-K8S-5.7.1"]);
pub const LB_EXPOSED: PolicyMeta = pol!(
    "WZ-K8S-016",
    "Service type LoadBalancer exposes workload externally",
    High,
    "A Service of type LoadBalancer provisions a cloud load balancer with a public endpoint.",
    "Prefer ClusterIP + Ingress with TLS/WAF, or internal LoadBalancer annotations.",
    "T1190",
    "CWE-668",
    &["CIS-K8S-5.4.x"],
    &["NIST-SC-7", "SOC2-CC6.6", "PCI-DSS-1.2.1"]
);
pub const CLUSTER_ADMIN_BIND: PolicyMeta = pol!("WZ-K8S-017", "ClusterRoleBinding grants cluster-admin", Critical, "A ClusterRoleBinding references the built-in cluster-admin ClusterRole, granting full cluster control.", "Replace with a least-privilege ClusterRole scoped to required resources.", "T1098", "CWE-269", &["CIS-K8S-5.1.3"], &["CIS-K8S-5.1.3", "NIST-AC-6", "MITRE-T1098"]);
pub const INGRESS_NO_TLS: PolicyMeta = pol!(
    "WZ-K8S-018",
    "Ingress routes traffic without TLS",
    High,
    "An Ingress spec has no tls section, terminating HTTP only at the edge.",
    "Add spec.tls with a valid certificate (cert-manager / ACM) and redirect HTTP→HTTPS.",
    "T1040",
    "CWE-319",
    &["CIS-K8S-5.4.x"],
    &["NIST-SC-8", "PCI-DSS-4.1"]
);
pub const SECRET_ENV: PolicyMeta = pol!(
    "WZ-K8S-019",
    "Container env embeds secret literal",
    Critical,
    "An env var named like a secret contains a plaintext value instead of secretKeyRef.",
    "Use env.valueFrom.secretKeyRef; never embed credentials in manifests.",
    "T1552.001",
    "CWE-798",
    &["CIS-K8S-5.x"],
    &["NIST-IA-5", "PCI-DSS-8.2.1"]
);
pub const NETPOL_OPEN: PolicyMeta = pol!(
    "WZ-K8S-020",
    "NetworkPolicy allows overly broad ingress",
    High,
    "NetworkPolicy ingress has no podSelector/from restrictions or allows all namespaces.",
    "Use default-deny and explicit namespace/pod selectors.",
    "T1021",
    "CWE-284",
    &["CIS-K8S-5.3.2"],
    &["NIST-SC-7", "SOC2-CC6.6"]
);
pub const SECCOMP_UNCONFINED: PolicyMeta = pol!(
    "WZ-K8S-021",
    "Pod seccomp profile Unconfined or unset on risky workload",
    Medium,
    "securityContext seccompProfile type Unconfined or missing while privileged/hostPath is set.",
    "Set seccompProfile: { type: RuntimeDefault } or Localhost profile.",
    "T1610",
    "CWE-250",
    &["CIS-K8S-5.2.x"],
    &["NIST-AC-6"]
);

#[must_use]
pub fn policies() -> Vec<PolicyMeta> {
    vec![
        PRIVILEGED,
        ALLOW_PRIV_ESC,
        RUN_AS_ROOT,
        RO_ROOT_FS,
        HOST_NETWORK,
        HOST_PID,
        HOST_IPC,
        DANGEROUS_CAPS,
        CAPS_NOT_DROPPED,
        HOSTPATH,
        IMAGE_LATEST,
        NO_LIMITS,
        SA_TOKEN,
        RBAC_WILDCARD,
        DEFAULT_NS,
        LB_EXPOSED,
        CLUSTER_ADMIN_BIND,
        INGRESS_NO_TLS,
        SECRET_ENV,
        NETPOL_OPEN,
        SECCOMP_UNCONFINED,
    ]
}

fn vget<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.get(k)
}
fn vstr<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}
fn vbool(v: &Value, k: &str) -> Option<bool> {
    v.get(k).and_then(Value::as_bool)
}

/// Resolve the pod spec for any common workload kind.
fn pod_spec<'a>(doc: &'a Value, kind: &str) -> Option<&'a Value> {
    match kind {
        "Pod" => vget(doc, "spec"),
        "CronJob" => doc
            .get("spec")
            .and_then(|s| s.get("jobTemplate"))
            .and_then(|j| j.get("spec"))
            .and_then(|s| s.get("template"))
            .and_then(|t| t.get("spec")),
        "Deployment"
        | "StatefulSet"
        | "DaemonSet"
        | "ReplicaSet"
        | "Job"
        | "ReplicationController" => doc
            .get("spec")
            .and_then(|s| s.get("template"))
            .and_then(|t| t.get("spec")),
        _ => None,
    }
}

#[must_use]
pub fn evaluate(file: &str, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for de in serde_yaml::Deserializer::from_str(content) {
        let Ok(doc) = Value::deserialize(de) else {
            continue;
        };
        if doc.is_null() {
            continue;
        }
        let kind = vstr(&doc, "kind").unwrap_or("").to_string();
        let name = doc
            .get("metadata")
            .and_then(|m| vstr(m, "name"))
            .unwrap_or("unnamed")
            .to_string();
        let ns = doc
            .get("metadata")
            .and_then(|m| vstr(m, "namespace"))
            .unwrap_or("default")
            .to_string();
        let res = format!("{}/{}", kind, name);
        let base_line = line_of(content, &format!("name: {}", name))
            .max(line_of(content, &format!("kind: {}", kind)));

        if kind == "Role" || kind == "ClusterRole" {
            check_rbac(file, content, &doc, &res, base_line, &mut out);
            continue;
        }

        if kind == "Service" {
            if doc
                .get("spec")
                .and_then(|s| s.get("type"))
                .and_then(Value::as_str)
                == Some("LoadBalancer")
            {
                out.push(
                    Finding::new(LB_EXPOSED, &res, file)
                        .at(base_line)
                        .observed("spec.type = LoadBalancer")
                        .fix("type: ClusterIP  # or internal LB annotation"),
                );
            }
            continue;
        }

        if kind == "ClusterRoleBinding" || kind == "RoleBinding" {
            let role_ref = doc
                .get("roleRef")
                .and_then(|r| r.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if role_ref == "cluster-admin" {
                out.push(
                    Finding::new(CLUSTER_ADMIN_BIND, &res, file)
                        .at(base_line)
                        .observed("roleRef.name = cluster-admin"),
                );
            }
            continue;
        }

        if kind == "Ingress" {
            let has_tls = doc
                .get("spec")
                .and_then(|s| s.get("tls"))
                .and_then(Value::as_sequence)
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            if !has_tls {
                out.push(Finding::new(INGRESS_NO_TLS, &res, file).at(base_line).observed("spec.tls missing").fix("spec:\n  tls:\n    - hosts: [app.example.com]\n      secretName: app-tls"));
            }
            continue;
        }

        if kind == "NetworkPolicy" {
            check_netpol(file, &doc, &res, base_line, &mut out);
            continue;
        }

        let Some(spec) = pod_spec(&doc, &kind) else {
            continue;
        };

        if ns == "default"
            && matches!(
                kind.as_str(),
                "Deployment" | "StatefulSet" | "DaemonSet" | "Pod" | "Job" | "CronJob"
            )
        {
            out.push(
                Finding::new(DEFAULT_NS, &res, file)
                    .at(base_line)
                    .observed("metadata.namespace = default"),
            );
        }

        for (flag, pol) in [
            ("hostNetwork", HOST_NETWORK),
            ("hostPID", HOST_PID),
            ("hostIPC", HOST_IPC),
        ] {
            if vbool(spec, flag) == Some(true) {
                out.push(
                    Finding::new(pol, &res, file)
                        .at(base_line)
                        .observed(format!("{} = true", flag))
                        .fix(format!("{}: false", flag)),
                );
            }
        }

        // hostPath volumes
        if let Some(vols) = vget(spec, "volumes").and_then(Value::as_sequence) {
            for vol in vols {
                if let Some(hp) = vol.get("hostPath") {
                    let path = vstr(hp, "path").unwrap_or("/");
                    out.push(
                        Finding::new(HOSTPATH, &res, file)
                            .at(line_of(content, "hostPath").max(base_line))
                            .observed(format!("hostPath.path = {}", path))
                            .fix("# replace hostPath with a PersistentVolumeClaim / CSI volume"),
                    );
                }
            }
        }

        let pod_run_as_non_root = spec
            .get("securityContext")
            .and_then(|sc| vbool(sc, "runAsNonRoot"));

        let containers = collect_containers(spec);
        for c in &containers {
            let cname = vstr(c, "name").unwrap_or("container").to_string();
            let cres = format!("{} [{}]", res, cname);
            let cline = line_of(content, &format!("name: {}", cname)).max(base_line);
            let sc = c.get("securityContext");

            if let Some(image) = vstr(c, "image") {
                let tag = image.rsplit(':').next().unwrap_or("");
                if !image.contains('@') && (!image.contains(':') || tag == "latest") {
                    out.push(
                        Finding::new(IMAGE_LATEST, &cres, file)
                            .at(cline)
                            .observed(format!("image = {}", image))
                            .fix("# pin to image@sha256:<digest>"),
                    );
                }
            }

            if let Some(envs) = c.get("env").and_then(Value::as_sequence) {
                for e in envs {
                    let key = e.get("name").and_then(Value::as_str).unwrap_or("");
                    let up = key.to_ascii_uppercase();
                    if ["PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY"]
                        .iter()
                        .any(|k| up.contains(k))
                    {
                        if let Some(val) = e.get("value").and_then(Value::as_str) {
                            if !val.is_empty() && !val.starts_with('$') {
                                out.push(
                                    Finding::new(SECRET_ENV, &cres, file)
                                        .at(cline)
                                        .observed(format!("env {key} plaintext value"))
                                        .fix("valueFrom:\n  secretKeyRef: …"),
                                );
                            }
                        }
                    }
                }
            }

            if c.get("resources").and_then(|r| r.get("limits")).is_none() {
                out.push(
                    Finding::new(NO_LIMITS, &cres, file)
                        .at(cline)
                        .observed("resources.limits not set"),
                );
            }

            if let Some(sc) = sc {
                if vbool(sc, "privileged") == Some(true) {
                    out.push(
                        Finding::new(PRIVILEGED, &cres, file)
                            .at(cline)
                            .observed("privileged = true")
                            .fix("privileged: false"),
                    );
                }
                let seccomp = sc
                    .get("seccompProfile")
                    .and_then(|s| vstr(s, "type"))
                    .unwrap_or("");
                if (vbool(sc, "privileged") == Some(true) || lc_content_has_hostpath(content))
                    && (seccomp.is_empty() || seccomp.eq_ignore_ascii_case("Unconfined"))
                {
                    out.push(
                        Finding::new(SECCOMP_UNCONFINED, &cres, file)
                            .at(cline)
                            .observed(format!("seccompProfile.type = {seccomp}")),
                    );
                }
                if vbool(sc, "allowPrivilegeEscalation") != Some(false) {
                    out.push(
                        Finding::new(ALLOW_PRIV_ESC, &cres, file)
                            .at(cline)
                            .observed("allowPrivilegeEscalation != false")
                            .fix("allowPrivilegeEscalation: false"),
                    );
                }
                if vbool(sc, "readOnlyRootFilesystem") != Some(true) {
                    out.push(
                        Finding::new(RO_ROOT_FS, &cres, file)
                            .at(cline)
                            .observed("readOnlyRootFilesystem != true")
                            .fix("readOnlyRootFilesystem: true"),
                    );
                }
                let c_run_as_non_root = vbool(sc, "runAsNonRoot");
                if c_run_as_non_root != Some(true) && pod_run_as_non_root != Some(true) {
                    out.push(
                        Finding::new(RUN_AS_ROOT, &cres, file)
                            .at(cline)
                            .observed("runAsNonRoot != true")
                            .fix("runAsNonRoot: true"),
                    );
                }
                if let Some(caps) = sc.get("capabilities") {
                    let add: Vec<String> = caps
                        .get("add")
                        .and_then(Value::as_sequence)
                        .map(|s| {
                            s.iter()
                                .filter_map(|x| x.as_str().map(|v| v.to_ascii_uppercase()))
                                .collect()
                        })
                        .unwrap_or_default();
                    const DANGER: &[&str] = &[
                        "ALL",
                        "SYS_ADMIN",
                        "NET_ADMIN",
                        "NET_RAW",
                        "SYS_PTRACE",
                        "SYS_MODULE",
                        "DAC_OVERRIDE",
                        "SETUID",
                        "SETGID",
                    ];
                    if add.iter().any(|a| DANGER.contains(&a.as_str())) {
                        out.push(
                            Finding::new(DANGEROUS_CAPS, &cres, file)
                                .at(cline)
                                .observed(format!("capabilities.add = {:?}", add))
                                .fix("capabilities:\n  drop: [\"ALL\"]"),
                        );
                    }
                    let drops: Vec<String> = caps
                        .get("drop")
                        .and_then(Value::as_sequence)
                        .map(|s| {
                            s.iter()
                                .filter_map(|x| x.as_str().map(|v| v.to_ascii_uppercase()))
                                .collect()
                        })
                        .unwrap_or_default();
                    if !drops.iter().any(|d| d == "ALL") {
                        out.push(
                            Finding::new(CAPS_NOT_DROPPED, &cres, file)
                                .at(cline)
                                .observed("capabilities.drop does not include ALL")
                                .fix("capabilities:\n  drop: [\"ALL\"]"),
                        );
                    }
                } else {
                    out.push(
                        Finding::new(CAPS_NOT_DROPPED, &cres, file)
                            .at(cline)
                            .observed("no capabilities.drop")
                            .fix("capabilities:\n  drop: [\"ALL\"]"),
                    );
                }
            } else {
                // No securityContext at all → multiple defaults are insecure.
                out.push(
                    Finding::new(ALLOW_PRIV_ESC, &cres, file)
                        .at(cline)
                        .observed("no securityContext (allowPrivilegeEscalation defaults true)")
                        .fix("securityContext:\n  allowPrivilegeEscalation: false"),
                );
                if pod_run_as_non_root != Some(true) {
                    out.push(
                        Finding::new(RUN_AS_ROOT, &cres, file)
                            .at(cline)
                            .observed("no securityContext (may run as root)")
                            .fix("securityContext:\n  runAsNonRoot: true"),
                    );
                }
                out.push(
                    Finding::new(RO_ROOT_FS, &cres, file)
                        .at(cline)
                        .observed("no securityContext (root fs writable)")
                        .fix("securityContext:\n  readOnlyRootFilesystem: true"),
                );
            }
        }

        // automountServiceAccountToken
        let pod_amt = vbool(spec, "automountServiceAccountToken");
        if pod_amt != Some(false) {
            out.push(
                Finding::new(SA_TOKEN, &res, file)
                    .at(base_line)
                    .observed("automountServiceAccountToken != false")
                    .fix("automountServiceAccountToken: false"),
            );
        }
    }
    out
}

fn collect_containers(spec: &Value) -> Vec<Value> {
    let mut v = Vec::new();
    for key in ["containers", "initContainers", "ephemeralContainers"] {
        if let Some(seq) = vget(spec, key).and_then(Value::as_sequence) {
            v.extend(seq.iter().cloned());
        }
    }
    v
}

fn lc_content_has_hostpath(content: &str) -> bool {
    content.to_ascii_lowercase().contains("hostpath:")
}

fn check_netpol(file: &str, doc: &Value, res: &str, line: usize, out: &mut Vec<Finding>) {
    let Some(ingress) = doc
        .get("spec")
        .and_then(|s| s.get("ingress"))
        .and_then(Value::as_sequence)
    else {
        return;
    };
    for ing in ingress {
        let empty_from = ing
            .get("from")
            .and_then(Value::as_sequence)
            .map(|s| s.is_empty())
            .unwrap_or(true);
        let pod_sel = doc.get("spec").and_then(|s| s.get("podSelector"));
        let empty_pod = pod_sel
            .map(|p| p.as_mapping().map(|m| m.is_empty()).unwrap_or(false))
            .unwrap_or(true);
        if empty_from && empty_pod {
            out.push(
                Finding::new(NETPOL_OPEN, res, file)
                    .at(line)
                    .observed("NetworkPolicy allows broad ingress (empty from/podSelector)"),
            );
        }
    }
}

fn check_rbac(
    file: &str,
    content: &str,
    doc: &Value,
    res: &str,
    line: usize,
    out: &mut Vec<Finding>,
) {
    let Some(rules) = doc.get("rules").and_then(Value::as_sequence) else {
        return;
    };
    for rule in rules {
        let verbs: Vec<String> = rule
            .get("verbs")
            .and_then(Value::as_sequence)
            .map(|s| {
                s.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let resources: Vec<String> = rule
            .get("resources")
            .and_then(Value::as_sequence)
            .map(|s| {
                s.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let star_verb = verbs.iter().any(|v| v == "*");
        let star_res = resources.iter().any(|r| r == "*");
        if star_verb && star_res {
            out.push(
                Finding::new(RBAC_WILDCARD, res, file)
                    .at(line_of(content, "verbs").max(line))
                    .observed("verbs: [\"*\"], resources: [\"*\"]")
                    .fix("verbs: [\"get\", \"list\"]\nresources: [\"pods\"]"),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_privileged_and_hostpath() {
        let y = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: app
          image: nginx:latest
          securityContext:
            privileged: true
      volumes:
        - name: docker
          hostPath:
            path: /var/run/docker.sock
"#;
        let f = evaluate("deploy.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == PRIVILEGED.id));
        assert!(f.iter().any(|x| x.policy.id == HOST_NETWORK.id));
        assert!(f.iter().any(|x| x.policy.id == HOSTPATH.id));
        assert!(f.iter().any(|x| x.policy.id == IMAGE_LATEST.id));
    }

    #[test]
    fn flags_rbac_wildcard() {
        let y = r#"
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: admin
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
"#;
        let f = evaluate("rbac.yaml", y);
        assert!(f.iter().any(|x| x.policy.id == RBAC_WILDCARD.id));
    }
}
