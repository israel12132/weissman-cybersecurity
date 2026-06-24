//! Attack-path synthesis — correlates **real** policy violations observed in the same scan into
//! multi-step breach chains (Wiz-style toxic combinations). A chain is emitted only when every
//! required policy id was actually triggered by an analyzer; nothing is invented.

use super::model::{Finding, Severity};
use serde_json::{json, Value};
use std::collections::HashSet;

/// One known toxic combination: all `required` policy ids must appear in the scan; if `any_of` is
/// non-empty, at least one of those ids must also appear.
#[derive(Debug)]
struct ChainDef {
    id: &'static str,
    title: &'static str,
    severity: Severity,
    description: &'static str,
    remediation: &'static str,
    mitre_path: &'static [&'static str],
    required: &'static [&'static str],
    any_of: &'static [&'static str],
}

const CHAINS: &[ChainDef] = &[
    ChainDef {
        id: "WZ-CHAIN-EXFIL-001",
        title: "Public storage + IAM over-privilege → cloud data exfiltration",
        severity: Severity::Critical,
        description: "Publicly readable object storage combined with IAM wildcard permissions enables an attacker to list, read and exfiltrate all cloud data without authentication escalation.",
        remediation: "Remove public ACLs/policies on storage, enforce Public Access Block, and replace wildcard IAM with least-privilege scoped to specific buckets and prefixes.",
        mitre_path: &["T1190", "T1530", "T1078"],
        required: &["WZ-TF-AWS-IAM-001"],
        any_of: &["WZ-TF-AWS-S3-001", "WZ-TF-AWS-S3-002", "WZ-TF-GCP-GCS-001", "WZ-CFN-S3-001", "WZ-EXP-001"],
    },
    ChainDef {
        id: "WZ-CHAIN-DB-001",
        title: "Public database + open network path → direct data breach",
        severity: Severity::Critical,
        description: "A publicly accessible database reachable through an internet-open security group creates a direct path to credential brute-force and data theft without lateral movement.",
        remediation: "Set publicly_accessible = false, place the database in private subnets, and restrict security groups to application-tier CIDRs only.",
        mitre_path: &["T1190", "T1110", "T1530"],
        required: &["WZ-TF-AWS-RDS-001"],
        any_of: &["WZ-TF-AWS-SG-001", "WZ-TF-AWS-SG-002", "WZ-CFN-SG-001", "WZ-CFN-SG-002", "WZ-CFN-RDS-001"],
    },
    ChainDef {
        id: "WZ-CHAIN-K8S-ESCAPE-001",
        title: "Privileged pod + Docker socket mount → cluster/node escape",
        severity: Severity::Critical,
        description: "A privileged container with the host Docker socket mounted can spawn arbitrary privileged containers on the node, effectively granting host root and cluster-wide compromise.",
        remediation: "Set privileged = false, remove hostPath mounts to /var/run/docker.sock, enforce Pod Security Standards restricted profile, and use a read-only root filesystem.",
        mitre_path: &["T1610", "T1611", "T1068"],
        required: &["WZ-K8S-001", "WZ-K8S-010"],
        any_of: &[],
    },
    ChainDef {
        id: "WZ-CHAIN-K8S-RBAC-001",
        title: "Wildcard RBAC + auto-mounted SA token → cluster admin takeover",
        severity: Severity::Critical,
        description: "A workload with cluster-admin-equivalent RBAC and an auto-mounted service account token lets any container compromise escalate to full cluster control via the Kubernetes API.",
        remediation: "Scope RBAC to minimal verbs/resources, set automountServiceAccountToken = false, and use bound service account tokens with short TTL.",
        mitre_path: &["T1098", "T1528", "T1610"],
        required: &["WZ-K8S-014", "WZ-K8S-013"],
        any_of: &[],
    },
    ChainDef {
        id: "WZ-CHAIN-CI-001",
        title: "pull_request_target + checkout head + secrets → CI/CD supply-chain takeover",
        severity: Severity::Critical,
        description: "The classic GitHub Actions pwn-request: untrusted PR code runs with repository secrets during pull_request_target, enabling secret exfiltration and arbitrary code execution in the pipeline.",
        remediation: "Never checkout PR head refs under pull_request_target. Use pull_request for untrusted code, pin actions to commit SHAs, and scope GITHUB_TOKEN to contents:read.",
        mitre_path: &["T1195.002", "T1552.001", "T1078"],
        required: &["WZ-GHA-001"],
        any_of: &["WZ-GHA-002", "WZ-GHA-006", "WZ-SEC-GH-001", "WZ-SEC-GEN-001", "WZ-SEC-AWS-001"],
    },
    ChainDef {
        id: "WZ-CHAIN-STATE-001",
        title: "Exposed Terraform state + embedded secrets → full infrastructure credential theft",
        severity: Severity::Critical,
        description: "A publicly reachable Terraform state file often contains database passwords, API keys and resource attributes. Combined with hard-coded secrets in source, an attacker gains immediate cloud admin access.",
        remediation: "Remove state from web roots, migrate to an encrypted remote backend (S3+DynamoDB/TFC) with tight IAM, rotate all secrets found in state, and eliminate hard-coded credentials.",
        mitre_path: &["T1552", "T1552.001", "T1078"],
        required: &["WZ-EXP-001"],
        any_of: &["WZ-SEC-AWS-001", "WZ-SEC-GEN-001", "WZ-SEC-GH-001", "WZ-SEC-GCP-001", "WZ-TF-GEN-001", "WZ-DKR-005"],
    },
    ChainDef {
        id: "WZ-CHAIN-ADMIN-001",
        title: "SSH/RDP open to internet + IAM admin → instant cloud takeover",
        severity: Severity::Critical,
        description: "Internet-exposed management ports combined with IAM wildcard admin means any successful brute-force or stolen key immediately grants full cloud account control.",
        remediation: "Close 22/3389 to 0.0.0.0/0, use SSM Session Manager or VPN, and replace IAM Action */Resource * with least-privilege roles.",
        mitre_path: &["T1190", "T1110", "T1098"],
        required: &["WZ-TF-AWS-SG-002", "WZ-TF-AWS-IAM-001"],
        any_of: &[],
    },
    ChainDef {
        id: "WZ-CHAIN-IMDS-001",
        title: "IMDSv1 + open ingress → SSRF credential theft chain",
        severity: Severity::High,
        description: "EC2 instances allowing IMDSv1 behind an internet-open security group are vulnerable to SSRF attacks that steal instance role credentials and pivot across the account.",
        remediation: "Enforce IMDSv2 (http_tokens = required) and restrict security group ingress to known ranges; add WAF/rate-limiting on public endpoints.",
        mitre_path: &["T1190", "T1552.005", "T1078"],
        required: &["WZ-TF-AWS-EC2-001", "WZ-TF-AWS-SG-001"],
        any_of: &[],
    },
    ChainDef {
        id: "WZ-CHAIN-COMPOSE-001",
        title: "Docker socket in compose + privileged service → host root",
        severity: Severity::Critical,
        description: "docker-compose mounting /var/run/docker.sock with privileged: true gives any container escape to full host root — equivalent to giving attackers your entire machine.",
        remediation: "Remove the Docker socket mount and privileged flag; run rootless Docker or use Kubernetes with Pod Security Standards.",
        mitre_path: &["T1610", "T1611"],
        required: &["WZ-CMP-001", "WZ-CMP-002"],
        any_of: &[],
    },
    ChainDef {
        id: "WZ-CHAIN-AUDIT-001",
        title: "Disabled CloudTrail + IAM wildcard → undetected persistence",
        severity: Severity::High,
        description: "With logging disabled and IAM admin permissions, an attacker can create backdoor users and roles without leaving forensic traces in CloudTrail.",
        remediation: "Enable multi-region CloudTrail with log file validation and S3 Object Lock; apply least-privilege IAM and alert on CreateUser/AttachUserPolicy events.",
        mitre_path: &["T1562.008", "T1098", "T1078"],
        required: &["WZ-TF-AWS-CT-001", "WZ-TF-AWS-IAM-001"],
        any_of: &["WZ-CFN-CT-001"],
    },
    ChainDef {
        id: "WZ-CHAIN-MODULE-001",
        title: "Unpinned Terraform module + secret in repo → supply-chain implant risk",
        severity: Severity::High,
        description: "Terraform modules fetched from mutable git refs (no version pin) combined with committed secrets let a compromised module source or typosquat inject malicious resources using stolen credentials.",
        remediation: "Pin every module source to an immutable ref (semver tag or commit SHA), use a private module registry, and remove all secrets from VCS.",
        mitre_path: &["T1195.001", "T1552.001"],
        required: &["WZ-TF-SUPPLY-001"],
        any_of: &["WZ-SEC-AWS-001", "WZ-SEC-GEN-001", "WZ-SEC-GH-001", "WZ-TF-GEN-001"],
    },
    ChainDef {
        id: "WZ-CHAIN-LAMBDA-001",
        title: "Unauthenticated Lambda URL + IAM admin → serverless backdoor",
        severity: Severity::Critical,
        description: "A publicly invocable Lambda function URL combined with IAM wildcard allows arbitrary code execution path to full account takeover via role chaining.",
        remediation: "Set authorization_type = AWS_IAM on function URLs and replace wildcard IAM with scoped roles.",
        mitre_path: &["T1190", "T1098", "T1078"],
        required: &["WZ-TF-AWS-LMB-001", "WZ-TF-AWS-IAM-001"],
        any_of: &[],
    },
    ChainDef {
        id: "WZ-CHAIN-K8S-LB-001",
        title: "LoadBalancer exposure + no NetworkPolicy → internet-wide workload access",
        severity: Severity::High,
        description: "A publicly provisioned LoadBalancer Service in a namespace with no NetworkPolicy means any internet host can reach pod ports without east-west segmentation.",
        remediation: "Switch to internal ingress, add default-deny NetworkPolicy, and restrict LoadBalancer with cloud annotations.",
        mitre_path: &["T1190", "T1021"],
        required: &["WZ-K8S-016", "WZ-CORR-K8S-001"],
        any_of: &[],
    },
    ChainDef {
        id: "WZ-CHAIN-API-001",
        title: "OpenAPI admin path without security + HTTP server → credential-less API takeover",
        severity: Severity::Critical,
        description: "Sensitive API operations documented without security on a cleartext HTTP server enable drive-by admin access and credential interception.",
        remediation: "Require OAuth2/JWT on all sensitive operations and enforce HTTPS-only servers.",
        mitre_path: &["T1190", "T1040", "T1530"],
        required: &["WZ-OAS-004", "WZ-OAS-002"],
        any_of: &["WZ-OAS-001"],
    },
    ChainDef {
        id: "WZ-CHAIN-SLS-001",
        title: "Serverless public HTTP + IAM wildcard → account-wide Lambda pivot",
        severity: Severity::Critical,
        description: "Public Serverless HTTP endpoints combined with wildcard IAM let attackers invoke functions and pivot with Lambda's attached role permissions.",
        remediation: "Add API Gateway authorizers and scope iamRoleStatements per function.",
        mitre_path: &["T1190", "T1098"],
        required: &["WZ-SLS-002", "WZ-SLS-001"],
        any_of: &[],
    },
    ChainDef {
        id: "WZ-CHAIN-GRAPH-001",
        title: "Public exposure graph + sensitive datastore → direct breach path",
        severity: Severity::Critical,
        description: "Resource graph analysis found public ingress and a sensitive datastore in the same infrastructure codebase.",
        remediation: "Segment networks; remove public exposure; encrypt and privatize datastores.",
        mitre_path: &["T1190", "T1530"],
        required: &["WZ-GRAPH-001"],
        any_of: &[],
    },
    ChainDef {
        id: "WZ-CHAIN-PLM-001",
        title: "Pulumi public S3 + IAM admin → programmatic exfiltration",
        severity: Severity::Critical,
        description: "Pulumi program defines both public object storage and IAM admin wildcard.",
        remediation: "Fix Pulumi program: private buckets + least-privilege IAM.",
        mitre_path: &["T1530", "T1098"],
        required: &["WZ-PLM-001", "WZ-PLM-004"],
        any_of: &[],
    },
    ChainDef {
        id: "WZ-CHAIN-XP-001",
        title: "Crossplane public S3 XR + inline ProviderConfig creds → control-plane to cloud takeover",
        severity: Severity::Critical,
        description: "Crossplane provisions public object storage while ProviderConfig embeds cloud credentials in plaintext — compromising the Kubernetes control plane yields immediate cloud admin.",
        remediation: "Move ProviderConfig credentials to Secret refs; set S3 XR blockPublicAccess BLOCK_ALL.",
        mitre_path: &["T1552.001", "T1530", "T1098"],
        required: &["WZ-XP-001", "WZ-XP-004"],
        any_of: &["WZ-XP-002"],
    },
    ChainDef {
        id: "WZ-CHAIN-DRIFT-001",
        title: "Security posture drift + public exposure → partial-fix bypass",
        severity: Severity::High,
        description: "Conflicting security settings across files in the same repo indicate incomplete remediation — attackers target the still-vulnerable artifact.",
        remediation: "Reconcile drift: single module source of truth, CI gate on all environments, remove legacy public configs.",
        mitre_path: &["T1190", "T1530"],
        required: &["WZ-DRIFT-001"],
        any_of: &["WZ-DRIFT-002", "WZ-DRIFT-003", "WZ-DRIFT-004", "WZ-DRIFT-005", "WZ-TF-AWS-S3-001", "WZ-TF-AWS-SG-001"],
    },
    ChainDef {
        id: "WZ-CHAIN-TG-001",
        title: "Terragrunt HTTP state + cleartext inputs → full infrastructure credential theft",
        severity: Severity::Critical,
        description: "Unencrypted Terragrunt remote state combined with secrets in inputs lets attackers reconstruct entire cloud topology and credentials.",
        remediation: "Migrate to encrypted S3/GCS backend with DynamoDB locking; remove secrets from inputs; use SOPS/Vault.",
        mitre_path: &["T1552", "T1530", "T1078"],
        required: &["WZ-TG-001"],
        any_of: &["WZ-TG-004", "WZ-EXP-001"],
    },
    ChainDef {
        id: "WZ-CHAIN-XP-002",
        title: "Crossplane Claim without selector + public XR → unintended prod exposure",
        severity: Severity::Critical,
        description: "Unpinned Composition binding plus public cloud XR provisioning can push dev templates into production paths.",
        remediation: "Add compositionSelector.matchLabels; enforce private forProvider defaults in all Compositions.",
        mitre_path: &["T1190", "T1530"],
        required: &["WZ-XP-008", "WZ-XP-001"],
        any_of: &[],
    },
    ChainDef {
        id: "WZ-CHAIN-GITOPS-001",
        title: "Argo CD mutable ref + Flux prune-off → unreviewed cluster mutation",
        severity: Severity::Critical,
        description: "GitOps pipelines tracking HEAD with prune disabled let any repo commit instantly change cluster state while orphaned backdoors persist.",
        remediation: "Pin revisions; enable prune; require signed commits and policy checks before sync.",
        mitre_path: &["T1195.002", "T1098", "T1528"],
        required: &["WZ-ARGO-001"],
        any_of: &["WZ-FLX-001", "WZ-FLX-003", "WZ-ARGO-004"],
    },
    ChainDef {
        id: "WZ-CHAIN-MESH-001",
        title: "Istio permissive mTLS + allow-all authz → lateral movement highway",
        severity: Severity::Critical,
        description: "Service mesh configured for PERMISSIVE mTLS with AuthorizationPolicy allowing all principals — east-west traffic is plaintext and unauthenticated.",
        remediation: "Enforce STRICT mTLS; default-deny AuthorizationPolicy with explicit service account allows.",
        mitre_path: &["T1040", "T1021", "T1071"],
        required: &["WZ-IST-001", "WZ-IST-002"],
        any_of: &["WZ-IST-003"],
    },
    ChainDef {
        id: "WZ-CHAIN-VAULT-001",
        title: "Vault sudo path wildcard + disabled audit → secret exfiltration without trace",
        severity: Severity::Critical,
        description: "Vault policy grants sudo on broad paths while audit is weak — attackers extract all secrets with minimal forensic trail.",
        remediation: "Remove sudo; scope paths; enable tamper-evident audit to SIEM.",
        mitre_path: &["T1552.001", "T1562.008", "T1078"],
        required: &["WZ-VLT-001", "WZ-VLT-002"],
        any_of: &["WZ-VLT-004"],
    },
    ChainDef {
        id: "WZ-CHAIN-PLAN-001",
        title: "Terraform plan deploys public S3 + open SG → imminent breach on apply",
        severity: Severity::Critical,
        description: "CI plan output shows combined public storage and internet-open security group about to be applied.",
        remediation: "Block the pipeline; fix HCL and re-plan before apply.",
        mitre_path: &["T1190", "T1530"],
        required: &["WZ-PLAN-001", "WZ-PLAN-002"],
        any_of: &[],
    },
    ChainDef {
        id: "WZ-CHAIN-KYV-001",
        title: "Kyverno audit-only + privileged workload → policy theater bypass",
        severity: Severity::Critical,
        description: "Kyverno policies set to audit while workloads run privileged — violations are logged but never blocked, enabling cluster escape.",
        remediation: "Set validationFailureAction: Enforce; remove privileged mutations; enable background scanning.",
        mitre_path: &["T1610", "T1562", "T1098"],
        required: &["WZ-KYV-001"],
        any_of: &["WZ-KYV-002", "WZ-K8S-001"],
    },
    ChainDef {
        id: "WZ-CHAIN-CI-002",
        title: "Atlantis ungated apply + IAM admin → one-click cloud takeover",
        severity: Severity::Critical,
        description: "Terraform automation allows apply without approval while HCL defines IAM wildcard admin — any merged PR becomes full account compromise.",
        remediation: "Require approved + mergeable apply_requirements; replace IAM Action */Resource * with least privilege.",
        mitre_path: &["T1195.002", "T1098", "T1078"],
        required: &["WZ-CI-001", "WZ-TF-AWS-IAM-001"],
        any_of: &["WZ-CI-002"],
    },
    ChainDef {
        id: "WZ-CHAIN-SOPS-001",
        title: "SOPS without KMS + committed secret literals → decryptable credential leak",
        severity: Severity::Critical,
        description: "SOPS creation rules lack cloud KMS while secret literals remain in VCS — attackers with repo access recover credentials offline.",
        remediation: "Add KMS/age recipients to all creation_rules; encrypt every secrets file; rotate exposed values.",
        mitre_path: &["T1552.001", "T1552", "T1078"],
        required: &["WZ-SOPS-001"],
        any_of: &["WZ-SOPS-004", "WZ-SEC-GEN-001", "WZ-CUE-002"],
    },
    ChainDef {
        id: "WZ-CHAIN-RECON-002",
        title: "Plan/static reconciliation gap + tfplan public exposure → blind apply",
        severity: Severity::Critical,
        description: "Static HCL scan misses risks visible only in the plan JSON — CI may green-light an apply that deploys public storage.",
        remediation: "Fail pipeline on WZ-RECON-* findings; scan full module tree; require plan+code reconciliation gate.",
        mitre_path: &["T1190", "T1530", "T1195"],
        required: &["WZ-RECON-001"],
        any_of: &["WZ-PLAN-001", "WZ-RECON-003", "WZ-PLAN-002"],
    },
    ChainDef {
        id: "WZ-CHAIN-LDR-001",
        title: "Linkerd allow-all + privileged pod → mesh bypass cluster escape",
        severity: Severity::Critical,
        description: "Unauthenticated ServerAuthorization combined with privileged workloads lets attackers bypass zero-trust mesh controls and escalate on nodes.",
        remediation: "Require meshTLS authentication; remove privileged; enforce ServerAuthorization per service.",
        mitre_path: &["T1021", "T1610", "T1068"],
        required: &["WZ-LDR-001"],
        any_of: &["WZ-K8S-001", "WZ-LDR-002"],
    },
    ChainDef {
        id: "WZ-CHAIN-PKR-001",
        title: "Packer hardcoded creds + public AMI → golden image supply-chain breach",
        severity: Severity::Critical,
        description: "Image pipeline embeds cloud keys and publishes AMIs broadly — compromised build becomes org-wide backdoor.",
        remediation: "Remove keys from Packer; use OIDC; keep AMIs private; encrypt all volumes.",
        mitre_path: &["T1552.001", "T1195.002", "T1530"],
        required: &["WZ-PKR-001"],
        any_of: &["WZ-PKR-005", "WZ-PKR-002"],
    },
    ChainDef {
        id: "WZ-CHAIN-HLF-001",
        title: "Helmfile secret values + HTTP chart repo → cluster credential theft",
        severity: Severity::Critical,
        description: "Helmfile commits secret literals and pulls charts over HTTP — MITM can substitute charts and harvest credentials at deploy time.",
        remediation: "Encrypt values with SOPS; pin chart versions; use HTTPS/OCI with signatures.",
        mitre_path: &["T1552.001", "T1195.002", "T1610"],
        required: &["WZ-HLF-001", "WZ-HLF-005"],
        any_of: &["WZ-HLF-002"],
    },
    ChainDef {
        id: "WZ-CHAIN-CERT-001",
        title: "cert-manager weak keys + long-lived CA cert → persistent MITM",
        severity: Severity::High,
        description: "Weak private keys with isCA certificates and no rotation creates long-lived trust anchor compromise.",
        remediation: "Use short-lived certs; rotationPolicy Always; never isCA in app namespaces.",
        mitre_path: &["T1557", "T1588"],
        required: &["WZ-CERT-003"],
        any_of: &["WZ-CERT-001", "WZ-CERT-004"],
    },
    ChainDef {
        id: "WZ-CHAIN-ESO-001",
        title: "External Secrets inline creds + wildcard store → cluster-wide secret exfiltration",
        severity: Severity::Critical,
        description: "ClusterSecretStore with embedded cloud keys and wildcard paths lets any namespace pull all secrets after control-plane compromise.",
        remediation: "Use workload identity; scope paths; namespace-scoped SecretStore.",
        mitre_path: &["T1552.001", "T1098", "T1078"],
        required: &["WZ-ESO-001"],
        any_of: &["WZ-ESO-004"],
    },
    ChainDef {
        id: "WZ-CHAIN-GW-001",
        title: "Gateway API HTTP listener + admin HTTPRoute → credential-less takeover",
        severity: Severity::Critical,
        description: "Cleartext Gateway listener combined with admin/debug HTTPRoute exposes management endpoints to the internet.",
        remediation: "HTTPS with certificateRefs; remove admin paths; add auth filters.",
        mitre_path: &["T1190", "T1040", "T1530"],
        required: &["WZ-GW-001", "WZ-GW-004"],
        any_of: &[],
    },
    ChainDef {
        id: "WZ-CHAIN-SKF-001",
        title: "Skaffold latest tag + build secret → dev pipeline to prod breach",
        severity: Severity::Critical,
        description: "Skaffold deploys mutable images with secrets in buildArgs — CI compromise yields both credentials and uncontrolled prod deploy.",
        remediation: "Pin digests; remove build secrets from YAML; separate dev/prod profiles.",
        mitre_path: &["T1195.001", "T1552.001", "T1078"],
        required: &["WZ-SKF-001", "WZ-SKF-002"],
        any_of: &["WZ-SKF-003"],
    },
    ChainDef {
        id: "WZ-CHAIN-SC-001",
        title: "Supply-chain correlation: unpinned module + repo secret → implant ready",
        severity: Severity::Critical,
        description: "Cross-file analysis found mutable Terraform module source and committed secrets — attacker can substitute module and use credentials immediately.",
        remediation: "Pin modules; rotate secrets; enable private module registry.",
        mitre_path: &["T1195.001", "T1552.001"],
        required: &["WZ-SC-001"],
        any_of: &["WZ-SC-002", "WZ-SC-003"],
    },
    ChainDef {
        id: "WZ-CHAIN-VEL-001",
        title: "Velero public backup + inline creds → full cluster secret archive leak",
        severity: Severity::Critical,
        description: "Backup target is public/readable with credentials in BSL — attacker restores entire etcd secrets offline.",
        remediation: "Private encrypted bucket; IRSA; exclude secrets from schedules.",
        mitre_path: &["T1530", "T1552.001", "T1078"],
        required: &["WZ-VEL-001", "WZ-VEL-002"],
        any_of: &["WZ-VEL-004"],
    },
    ChainDef {
        id: "WZ-CHAIN-KEDA-001",
        title: "KEDA trigger secret + scale-to-zero prod → cold-start credential theft",
        severity: Severity::High,
        description: "KEDA TriggerAuthentication with embedded secrets on production scale-to-zero workload — scaler events leak credentials on wake.",
        remediation: "secretKeyRef only; minReplicaCount >= 1 for prod; TLS on scalers.",
        mitre_path: &["T1552.001", "T1499"],
        required: &["WZ-KEDA-001"],
        any_of: &["WZ-KEDA-004", "WZ-KEDA-002"],
    },
    ChainDef {
        id: "WZ-CHAIN-TKN-001",
        title: "Tekton privileged task + secret params → CI pipeline takeover",
        severity: Severity::Critical,
        description: "Privileged Tekton step with secret literals in params — compromised pipeline runs arbitrary code with node access.",
        remediation: "Non-privileged steps; Tekton secrets; pin images; scoped SA.",
        mitre_path: &["T1610", "T1552.001", "T1195.002"],
        required: &["WZ-TKN-001", "WZ-TKN-002"],
        any_of: &["WZ-TKN-003"],
    },
    ChainDef {
        id: "WZ-CHAIN-FLC-001",
        title: "Falco rules disabled + file-only output → blind runtime",
        severity: Severity::High,
        description: "Critical Falco rules disabled while output stays local — attacks execute without SIEM detection.",
        remediation: "Enable rules; forward via falcosidekick; remove catch-all exclusions.",
        mitre_path: &["T1562", "T1562.008"],
        required: &["WZ-FLC-001", "WZ-FLC-003"],
        any_of: &["WZ-FLC-004"],
    },
    ChainDef {
        id: "WZ-CHAIN-BS-001",
        title: "Backstage guest auth + inline SCM token → developer portal takeover",
        severity: Severity::Critical,
        description: "Unauthenticated Backstage with embedded GitHub/GitLab tokens lets any visitor enumerate repos and trigger integrations.",
        remediation: "Enable OAuth; remove guest access; externalize tokens via ESO.",
        mitre_path: &["T1078", "T1552.001", "T1190"],
        required: &["WZ-BS-001", "WZ-BS-002"],
        any_of: &["WZ-BS-004"],
    },
    ChainDef {
        id: "WZ-CHAIN-EGW-001",
        title: "Envoy Gateway cleartext + JWT disabled → credential-less API abuse",
        severity: Severity::Critical,
        description: "Public HTTP listener without JWT/ext_authz exposes backend APIs to unauthenticated callers.",
        remediation: "HTTPS termination; enable JWT; add ext_authz.",
        mitre_path: &["T1190", "T1040", "T1078"],
        required: &["WZ-EGW-001", "WZ-EGW-002"],
        any_of: &["WZ-EGW-003"],
    },
    ChainDef {
        id: "WZ-CHAIN-KUS-001",
        title: "Kustomize privileged patch + secret literal → committed cluster compromise",
        severity: Severity::Critical,
        description: "Overlay enables privileged containers and commits secretGenerator passwords — attacker gets node escape material from Git.",
        remediation: "Remove privileged patch; use External Secrets; enforce PSS restricted.",
        mitre_path: &["T1610", "T1552.001", "T1195.001"],
        required: &["WZ-KUS-001", "WZ-KUS-007"],
        any_of: &["WZ-KUS-004", "WZ-KUS-006"],
    },
    ChainDef {
        id: "WZ-CHAIN-SS-001",
        title: "SealedSecret cluster-wide + plaintext template → Git-leaked secret recovery",
        severity: Severity::Critical,
        description: "Cluster-wide sealing scope with plaintext template data lets anyone with repo access recover secrets after controller compromise.",
        remediation: "Namespace-scope SealedSecrets; encryptedData only; rotate sealing keys.",
        mitre_path: &["T1552.001", "T1098", "T1530"],
        required: &["WZ-SS-001", "WZ-SS-003"],
        any_of: &["WZ-SS-002"],
    },
    ChainDef {
        id: "WZ-CHAIN-PRM-001",
        title: "Prometheus TLS skip + Grafana admin password → metrics-to-dashboard takeover",
        severity: Severity::Critical,
        description: "Insecure metric scrape combined with embedded Grafana admin creds enables MITM and full observability stack control.",
        remediation: "Verify scrape TLS; externalize Grafana admin via Secret + SSO.",
        mitre_path: &["T1557", "T1552.001", "T1078"],
        required: &["WZ-PRM-001", "WZ-PRM-002"],
        any_of: &["WZ-PRM-004"],
    },
    ChainDef {
        id: "WZ-CHAIN-ARO-001",
        title: "Argo Rollout blind canary + privileged analysis → prod implant",
        severity: Severity::Critical,
        description: "Progressive delivery without analysis gates and privileged analysis pods ships bad code to production with node-level execution.",
        remediation: "Add AnalysisTemplates; non-privileged analysis; enable auto-rollback.",
        mitre_path: &["T1195.002", "T1610", "T1078"],
        required: &["WZ-ARO-001", "WZ-ARO-003"],
        any_of: &["WZ-ARO-004"],
    },
];

#[derive(Debug, Clone)]
pub struct SynthesizedChain {
    pub def: &'static ChainDef,
    pub matched_policies: Vec<String>,
    pub linked_findings: Vec<String>,
}

impl SynthesizedChain {
    #[must_use]
    pub fn summary_json(&self) -> Value {
        json!({
            "id": self.def.id,
            "title": self.def.title,
            "severity": self.def.severity.as_str(),
            "mitre_path": self.def.mitre_path,
            "matched_policies": self.matched_policies,
            "linked_findings": self.linked_findings,
            "remediation": self.def.remediation,
        })
    }

    #[must_use]
    pub fn severity(&self) -> Severity {
        self.def.severity
    }

    #[must_use]
    pub fn mitre_path(&self) -> &'static [&'static str] {
        self.def.mitre_path
    }
}

/// Evaluate which attack chains are activated by the observed findings.
#[must_use]
pub fn synthesize(findings: &[Finding]) -> Vec<SynthesizedChain> {
    let triggered: HashSet<&str> = findings.iter().map(|f| f.policy.id).collect();
    let mut out = Vec::new();

    for chain in CHAINS {
        let all_required = chain.required.iter().all(|p| triggered.contains(p));
        if !all_required {
            continue;
        }
        if !chain.any_of.is_empty() && !chain.any_of.iter().any(|p| triggered.contains(p)) {
            continue;
        }
        let mut matched: Vec<String> = chain
            .required
            .iter()
            .chain(chain.any_of.iter().filter(|p| triggered.contains(**p)))
            .map(|s| (*s).to_string())
            .collect();
        matched.sort();
        matched.dedup();

        let linked: Vec<String> = findings
            .iter()
            .filter(|f| matched.contains(&f.policy.id.to_string()))
            .map(|f| format!("{}:{}:{}", f.policy.id, f.file, f.resource))
            .collect();

        out.push(SynthesizedChain {
            def: chain,
            matched_policies: matched,
            linked_findings: linked,
        });
    }
    out.sort_by(|a, b| b.severity().cmp(&a.severity()));
    out
}

/// Blast-radius multiplier when toxic chains are present (capped).
#[must_use]
pub fn blast_radius_multiplier(chains: &[SynthesizedChain]) -> f64 {
    if chains.is_empty() {
        return 1.0;
    }
    let crit = chains.iter().filter(|c| c.severity() == Severity::Critical).count();
    let high = chains.iter().filter(|c| c.severity() == Severity::High).count();
    (1.0 + crit as f64 * 0.35 + high as f64 * 0.15).min(3.0)
}

#[must_use]
pub fn chain_to_finding(chain: &SynthesizedChain, target: &str) -> Value {
    let c = chain.def;
    json!({
        "type": "iac_misconfig",
        "engine_id": "iac_misconfig",
        "category": "iac_attack_chain",
        "policy_id": c.id,
        "title": format!("[ATTACK PATH] {}", c.title),
        "severity": c.severity.as_str(),
        "framework": "attack_path",
        "provider": "correlation",
        "mitre_attack": c.mitre_path.join(" → "),
        "description": format!("{} Policies correlated: {}.", c.description, chain.matched_policies.join(", ")),
        "remediation": c.remediation,
        "target": target,
        "attack_chain": {
            "id": c.id,
            "mitre_path": c.mitre_path,
            "matched_policies": chain.matched_policies,
            "linked_findings": chain.linked_findings,
            "blast_radius": "elevated",
        },
        "confidence": 0.98,
        "verification_method": "iac_finding_correlation",
    })
}

/// Render activated attack chains as a Mermaid flowchart for executive / SOC visualization.
#[must_use]
pub fn mermaid_graph(chains: &[SynthesizedChain]) -> String {
    if chains.is_empty() {
        return "flowchart LR\n  A[No attack paths detected]".to_string();
    }
    let mut lines = vec!["flowchart LR".to_string()];
    for (i, chain) in chains.iter().enumerate() {
        let sev = chain.severity().as_str();
        let chain_id = format!("C{i}");
        let title = chain.def.title.replace('"', "'");
        lines.push(format!("  subgraph {chain_id}[\"{title}\"]"));
        lines.push(format!("    direction LR"));
        lines.push(format!("    style {chain_id} fill:#1e293b,stroke:#38bdf8"));
        let mitre = chain.mitre_path();
        for (j, tech) in mitre.iter().enumerate() {
            let node = format!("{chain_id}T{j}");
            lines.push(format!("    {node}[\"{tech}\"]"));
            if j > 0 {
                let prev = format!("{chain_id}T{}", j - 1);
                lines.push(format!("    {prev} --> {node}"));
            }
        }
        lines.push(format!("    {chain_id}S[\"{sev}\"]"));
        if !mitre.is_empty() {
            let last = format!("{chain_id}T{}", mitre.len() - 1);
            lines.push(format!("    {last} --> {chain_id}S"));
        }
        lines.push("  end".to_string());
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iac_misconfig_engine::terraform::{IAM_WILDCARD, S3_PUBLIC_ACL, SG_OPEN_ADMIN};

    #[test]
    fn detects_exfil_chain() {
        let findings = vec![
            Finding::new(IAM_WILDCARD, "aws_iam_policy.admin", "main.tf"),
            Finding::new(S3_PUBLIC_ACL, "aws_s3_bucket.assets", "main.tf"),
        ];
        let chains = synthesize(&findings);
        assert!(chains.iter().any(|c| c.def.id == "WZ-CHAIN-EXFIL-001"));
    }

    #[test]
    fn detects_admin_internet_chain() {
        let findings = vec![
            Finding::new(SG_OPEN_ADMIN, "aws_security_group.web", "main.tf"),
            Finding::new(IAM_WILDCARD, "aws_iam_policy.admin", "main.tf"),
        ];
        let chains = synthesize(&findings);
        assert!(chains.iter().any(|c| c.def.id == "WZ-CHAIN-ADMIN-001"));
    }

    #[test]
    fn mermaid_includes_chains() {
        let findings = vec![
            Finding::new(IAM_WILDCARD, "aws_iam_policy.admin", "main.tf"),
            Finding::new(S3_PUBLIC_ACL, "aws_s3_bucket.assets", "main.tf"),
        ];
        let chains = synthesize(&findings);
        let m = mermaid_graph(&chains);
        assert!(m.contains("flowchart LR"));
        assert!(m.contains("T1530"));
    }

    #[test]
    fn no_chain_without_required() {
        let findings = vec![Finding::new(S3_PUBLIC_ACL, "b", "main.tf")];
        assert!(synthesize(&findings).is_empty());
    }
}
