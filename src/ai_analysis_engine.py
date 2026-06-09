"""
Weissman-cybersecurity: AI Analysis Engine.
Pattern recognition, attack path simulation, false positive reduction, and threat correlation.
"""
from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Attack pattern library
# ---------------------------------------------------------------------------

ATTACK_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "AP-001",
        "name": "Cloud-to-AD Lateral Movement",
        "description": "Attacker compromises cloud credentials, pivots via VPN/DirectConnect into on-premises AD, escalates privileges to Domain Admin.",
        "affected_systems": ["aws", "azure", "active_directory", "vpn"],
        "attack_chain": ["cloud_credential_theft", "vpn_pivot", "ad_enumeration", "privilege_escalation", "domain_admin"],
        "confidence_base": 0.78,
        "mitre_techniques": ["T1078", "T1021", "T1484", "T1087", "T1003"],
        "category": "cloud_attacks",
    },
    {
        "id": "AP-002",
        "name": "Supply Chain → RCE Chain",
        "description": "Malicious dependency injected into CI/CD pipeline executes arbitrary code on build servers and propagates to production.",
        "affected_systems": ["ci_cd", "npm", "pypi", "maven", "build_server"],
        "attack_chain": ["dependency_confusion", "malicious_package", "build_server_compromise", "artifact_tampering", "production_rce"],
        "confidence_base": 0.71,
        "mitre_techniques": ["T1195", "T1059", "T1543", "T1036", "T1041"],
        "category": "supply_chain",
    },
    {
        "id": "AP-003",
        "name": "SSRF→IMDS→IAM Escalation",
        "description": "SSRF vulnerability in web application used to reach cloud IMDS endpoint, stealing IAM credentials for privilege escalation.",
        "affected_systems": ["web_application", "aws_ec2", "iam", "s3"],
        "attack_chain": ["ssrf_discovery", "imds_access", "iam_key_theft", "privilege_escalation", "data_exfiltration"],
        "confidence_base": 0.88,
        "mitre_techniques": ["T1190", "T1552", "T1078", "T1537", "T1041"],
        "category": "cloud_attacks",
    },
    {
        "id": "AP-004",
        "name": "Web→DB→AD Pivot",
        "description": "SQL injection exploited to read DB credentials, pivot to database server, then use DB server's AD account for further compromise.",
        "affected_systems": ["web_application", "database", "active_directory"],
        "attack_chain": ["sqli_exploitation", "db_credential_dump", "db_server_access", "ad_service_account", "lateral_movement"],
        "confidence_base": 0.82,
        "mitre_techniques": ["T1190", "T1005", "T1021", "T1078", "T1087"],
        "category": "web_exploitation",
    },
    {
        "id": "AP-005",
        "name": "Kerberoasting→DCSync→Domain Takeover",
        "description": "Service account TGS tickets cracked offline, account used to obtain DCSync rights, all domain hashes extracted.",
        "affected_systems": ["active_directory", "kerberos", "domain_controller"],
        "attack_chain": ["spn_enumeration", "tgs_request", "offline_cracking", "privilege_escalation", "dcsync", "domain_takeover"],
        "confidence_base": 0.86,
        "mitre_techniques": ["T1558", "T1003", "T1078", "T1484", "T1207"],
        "category": "ad_attacks",
    },
    {
        "id": "AP-006",
        "name": "Container Escape→Node Compromise→Cluster Takeover",
        "description": "Privileged container escapes to host node, extracts kubelet credentials, gains cluster-admin access via Kubernetes API.",
        "affected_systems": ["kubernetes", "docker", "linux_host"],
        "attack_chain": ["privileged_container", "container_escape", "node_credential_theft", "kubernetes_api_access", "cluster_admin"],
        "confidence_base": 0.79,
        "mitre_techniques": ["T1611", "T1552", "T1098", "T1543", "T1078"],
        "category": "cloud_attacks",
    },
    {
        "id": "AP-007",
        "name": "Phishing→Credential→Lateral→Ransomware",
        "description": "Phishing email delivers credential stealer, harvested credentials used for lateral movement, ransomware deployed domain-wide via GPO.",
        "affected_systems": ["email", "endpoints", "active_directory", "file_servers"],
        "attack_chain": ["spear_phishing", "credential_theft", "lateral_movement", "ad_compromise", "gpo_deployment", "ransomware_execution"],
        "confidence_base": 0.83,
        "mitre_techniques": ["T1566", "T1056", "T1021", "T1484", "T1486", "T1490"],
        "category": "ransomware_chain",
    },
    {
        "id": "AP-008",
        "name": "OAuth2 Misconfiguration→Account Takeover",
        "description": "Open redirect in OAuth2 flow used to steal authorization codes, victim accounts fully compromised.",
        "affected_systems": ["web_application", "oauth2", "identity_provider"],
        "attack_chain": ["oauth_redirect_bypass", "authorization_code_theft", "token_exchange", "account_takeover", "data_access"],
        "confidence_base": 0.75,
        "mitre_techniques": ["T1550", "T1539", "T1078", "T1485"],
        "category": "web_exploitation",
    },
    {
        "id": "AP-009",
        "name": "Log4Shell→JNDI→RCE→Persistence",
        "description": "Log4j2 JNDI injection triggers LDAP callback loading malicious Java class, achieving RCE and establishing persistence.",
        "affected_systems": ["java_applications", "web_servers", "log4j"],
        "attack_chain": ["log4shell_injection", "jndi_ldap_callback", "malicious_class_load", "rce_execution", "reverse_shell", "persistence"],
        "confidence_base": 0.93,
        "mitre_techniques": ["T1190", "T1059", "T1543", "T1071", "T1027"],
        "category": "web_exploitation",
    },
    {
        "id": "AP-010",
        "name": "S3 Public Bucket→Credential Discovery→Full AWS Compromise",
        "description": "Public S3 bucket contains application config files with AWS keys; keys used to escalate to AdministratorAccess.",
        "affected_systems": ["aws_s3", "iam", "aws_account"],
        "attack_chain": ["s3_enumeration", "config_file_discovery", "key_extraction", "iam_enumeration", "privilege_escalation", "account_takeover"],
        "confidence_base": 0.88,
        "mitre_techniques": ["T1530", "T1552", "T1078", "T1580", "T1537"],
        "category": "cloud_attacks",
    },
    {
        "id": "AP-011",
        "name": "XXE→SSRF→Internal Network Scan",
        "description": "XXE allows external entity resolution, pivoted to SSRF to scan internal network and access internal APIs.",
        "affected_systems": ["web_application", "xml_parser", "internal_network"],
        "attack_chain": ["xxe_injection", "file_read", "ssrf_pivot", "internal_network_scan", "internal_api_access"],
        "confidence_base": 0.77,
        "mitre_techniques": ["T1190", "T1046", "T1005", "T1041"],
        "category": "web_exploitation",
    },
    {
        "id": "AP-012",
        "name": "GraphQL Introspection→Mutation Abuse→Data Breach",
        "description": "Introspection reveals admin mutations; unauthenticated admin mutation grants full data access.",
        "affected_systems": ["graphql_api", "web_application", "database"],
        "attack_chain": ["introspection_query", "schema_enumeration", "mutation_discovery", "auth_bypass", "data_exfiltration"],
        "confidence_base": 0.72,
        "mitre_techniques": ["T1190", "T1078", "T1005", "T1041"],
        "category": "web_exploitation",
    },
    {
        "id": "AP-013",
        "name": "Insecure Deserialization→RCE→Pivot",
        "description": "Java deserialization gadget chain in REST API achieves RCE, used to pivot to internal systems.",
        "affected_systems": ["java_application", "rest_api", "internal_network"],
        "attack_chain": ["deserialization_payload", "rce_via_gadget_chain", "shell_execution", "internal_pivot", "data_exfiltration"],
        "confidence_base": 0.81,
        "mitre_techniques": ["T1059", "T1190", "T1021", "T1041"],
        "category": "web_exploitation",
    },
    {
        "id": "AP-014",
        "name": "Subdomain Takeover→Phishing→Credential Harvest",
        "description": "Dangling DNS CNAME claimed on third-party platform, used to serve phishing pages for legitimate-looking subdomain.",
        "affected_systems": ["dns", "web_application", "email"],
        "attack_chain": ["dns_enumeration", "cname_discovery", "subdomain_claim", "phishing_page_deploy", "credential_harvest"],
        "confidence_base": 0.76,
        "mitre_techniques": ["T1584", "T1566", "T1056", "T1078"],
        "category": "web_exploitation",
    },
    {
        "id": "AP-015",
        "name": "JWT None Algorithm→Admin Impersonation",
        "description": "API accepts JWTs with alg:none, attacker forges admin token without knowledge of signing key.",
        "affected_systems": ["rest_api", "jwt_auth", "web_application"],
        "attack_chain": ["jwt_alg_none_bypass", "admin_token_forge", "api_full_access", "data_exfiltration"],
        "confidence_base": 0.94,
        "mitre_techniques": ["T1550", "T1078", "T1005"],
        "category": "web_exploitation",
    },
    {
        "id": "AP-016",
        "name": "Silver Ticket Attack",
        "description": "Service hash obtained via Kerberoasting used to forge service tickets bypassing the KDC.",
        "affected_systems": ["active_directory", "kerberos", "services"],
        "attack_chain": ["kerberoasting", "hash_crack", "silver_ticket_forge", "service_impersonation", "data_access"],
        "confidence_base": 0.80,
        "mitre_techniques": ["T1558", "T1550", "T1078", "T1005"],
        "category": "ad_attacks",
    },
    {
        "id": "AP-017",
        "name": "NTLM Relay→SMB Signing Disabled→Lateral Movement",
        "description": "LLMNR poisoning captures NTLM hashes, relayed to hosts without SMB signing for code execution.",
        "affected_systems": ["windows_network", "smb", "active_directory"],
        "attack_chain": ["llmnr_poisoning", "ntlm_capture", "smb_relay", "remote_code_execution", "lateral_movement"],
        "confidence_base": 0.85,
        "mitre_techniques": ["T1557", "T1021", "T1059", "T1078"],
        "category": "ad_attacks",
    },
    {
        "id": "AP-018",
        "name": "GKE Metadata Server→SA Key Theft→GCP Takeover",
        "description": "Pod accesses GKE metadata server to steal service account tokens with Editor role, used for full GCP project takeover.",
        "affected_systems": ["gke", "gcp", "metadata_server"],
        "attack_chain": ["metadata_server_access", "sa_token_theft", "gcp_iam_escalation", "resource_access", "data_exfiltration"],
        "confidence_base": 0.82,
        "mitre_techniques": ["T1552", "T1078", "T1580", "T1537"],
        "category": "cloud_attacks",
    },
    {
        "id": "AP-019",
        "name": "Dependency Confusion→Build Server→Production Backdoor",
        "description": "Internal package name registered on public registry with higher version, pulled by build server, executing malicious code in production.",
        "affected_systems": ["npm", "pypi", "ci_cd", "production"],
        "attack_chain": ["package_registration", "version_confusion", "build_execution", "malicious_code_run", "production_compromise"],
        "confidence_base": 0.74,
        "mitre_techniques": ["T1195", "T1059", "T1543", "T1041"],
        "category": "supply_chain",
    },
    {
        "id": "AP-020",
        "name": "Spring4Shell→RCE→Cryptominer Deployment",
        "description": "CVE-2022-22965 exploited against Spring MVC endpoint, remote shell achieved, cryptominer deployed for persistent monetisation.",
        "affected_systems": ["spring_boot", "java_application", "web_server"],
        "attack_chain": ["spring4shell_exploit", "classloader_manipulation", "webshell_upload", "rce_execution", "cryptominer_install"],
        "confidence_base": 0.87,
        "mitre_techniques": ["T1190", "T1059", "T1543", "T1496"],
        "category": "web_exploitation",
    },
    {
        "id": "AP-021",
        "name": "Exposed etcd→Kubernetes Secret Dump→Cluster Admin",
        "description": "Unauthenticated etcd access allows reading all Kubernetes secrets including service account tokens with cluster-admin rights.",
        "affected_systems": ["kubernetes", "etcd"],
        "attack_chain": ["etcd_enumeration", "secret_extraction", "sa_token_use", "cluster_admin_access"],
        "confidence_base": 0.91,
        "mitre_techniques": ["T1552", "T1078", "T1611"],
        "category": "cloud_attacks",
    },
    {
        "id": "AP-022",
        "name": "Mass Assignment→Role Escalation→Data Access",
        "description": "REST API mass assignment sets role=admin, full administrative access granted to attacker-controlled account.",
        "affected_systems": ["rest_api", "web_application", "database"],
        "attack_chain": ["api_enumeration", "mass_assignment_exploit", "role_escalation", "admin_access", "data_exfiltration"],
        "confidence_base": 0.78,
        "mitre_techniques": ["T1078", "T1190", "T1005"],
        "category": "web_exploitation",
    },
    {
        "id": "AP-023",
        "name": "DNS C2 Tunneling→Long-Term Persistence",
        "description": "Malware communicates via DNS TXT records to C2 server, bypassing network egress controls for long-term persistence.",
        "affected_systems": ["dns", "endpoints", "network"],
        "attack_chain": ["dns_c2_setup", "malware_install", "dns_tunnel_comms", "c2_control", "long_term_persistence"],
        "confidence_base": 0.69,
        "mitre_techniques": ["T1071", "T1132", "T1095", "T1573"],
        "category": "multi_vector",
    },
    {
        "id": "AP-024",
        "name": "Azure AD Consent Phishing→OAuth Token→M365 Data Access",
        "description": "Malicious OAuth app granted user consent via phishing, persistent access to Microsoft 365 email and OneDrive without credentials.",
        "affected_systems": ["azure_ad", "microsoft_365", "oauth2"],
        "attack_chain": ["malicious_app_registration", "consent_phishing", "oauth_grant", "token_acquisition", "m365_data_access"],
        "confidence_base": 0.81,
        "mitre_techniques": ["T1566", "T1550", "T1114", "T1530"],
        "category": "cloud_attacks",
    },
    {
        "id": "AP-025",
        "name": "LFI→Log Poisoning→RCE",
        "description": "Local file inclusion used to read access logs containing injected PHP code, triggering server-side code execution.",
        "affected_systems": ["php_application", "web_server", "linux"],
        "attack_chain": ["lfi_discovery", "log_injection", "log_file_inclusion", "php_rce", "webshell_install"],
        "confidence_base": 0.83,
        "mitre_techniques": ["T1190", "T1059", "T1505", "T1543"],
        "category": "web_exploitation",
    },
    {
        "id": "AP-026",
        "name": "BloodHound Shortest Path→Domain Admin in 3 Hops",
        "description": "BloodHound identifies 3-hop attack path from low-privileged user to Domain Admin via group membership and delegation abuse.",
        "affected_systems": ["active_directory", "windows"],
        "attack_chain": ["bloodhound_analysis", "group_membership_abuse", "delegation_abuse", "domain_admin_access"],
        "confidence_base": 0.87,
        "mitre_techniques": ["T1087", "T1078", "T1484", "T1003"],
        "category": "ad_attacks",
    },
    {
        "id": "AP-027",
        "name": "Stored XSS→Session Hijack→Account Takeover",
        "description": "Stored XSS in user profile page exfiltrates admin session cookies, full account takeover achieved.",
        "affected_systems": ["web_application", "browser"],
        "attack_chain": ["xss_injection", "payload_storage", "victim_session_steal", "cookie_exfiltration", "account_takeover"],
        "confidence_base": 0.80,
        "mitre_techniques": ["T1059", "T1539", "T1078"],
        "category": "web_exploitation",
    },
    {
        "id": "AP-028",
        "name": "Ransomware Kill Chain (Full)",
        "description": "Complete ransomware deployment: initial access via phishing, credential theft, lateral movement, backup deletion, domain-wide encryption.",
        "affected_systems": ["endpoints", "file_servers", "backup_systems", "active_directory"],
        "attack_chain": ["phishing_delivery", "payload_execution", "credential_harvest", "lateral_movement", "backup_deletion", "encryption_deployment"],
        "confidence_base": 0.76,
        "mitre_techniques": ["T1566", "T1059", "T1021", "T1490", "T1486"],
        "category": "ransomware_chain",
    },
    {
        "id": "AP-029",
        "name": "Exposed Docker Socket→Host Escape→Full Server Compromise",
        "description": "Docker socket mounted in container used to launch privileged container with host filesystem mount, achieving root on host.",
        "affected_systems": ["docker", "linux_host", "kubernetes"],
        "attack_chain": ["docker_socket_access", "privileged_container_launch", "host_mount", "chroot_escape", "root_access"],
        "confidence_base": 0.92,
        "mitre_techniques": ["T1611", "T1059", "T1543", "T1078"],
        "category": "cloud_attacks",
    },
    {
        "id": "AP-030",
        "name": "CI/CD Pipeline Injection→Secrets Exfiltration",
        "description": "Attacker with write access to a feature branch injects malicious CI/CD steps to exfiltrate build secrets and deploy keys.",
        "affected_systems": ["ci_cd", "github_actions", "gitlab_ci", "secrets"],
        "attack_chain": ["branch_write_access", "pipeline_yaml_injection", "secret_env_exfiltration", "deploy_key_theft", "production_access"],
        "confidence_base": 0.78,
        "mitre_techniques": ["T1195", "T1552", "T1041", "T1078"],
        "category": "supply_chain",
    },
    {
        "id": "AP-031",
        "name": "BOLA→PII Mass Harvest",
        "description": "Broken object-level authorisation in REST API allows enumeration of all user IDs to harvest full PII database.",
        "affected_systems": ["rest_api", "web_application", "database"],
        "attack_chain": ["api_enumeration", "bola_exploitation", "id_iteration", "pii_extraction", "data_sale"],
        "confidence_base": 0.85,
        "mitre_techniques": ["T1190", "T1005", "T1041"],
        "category": "web_exploitation",
    },
    {
        "id": "AP-032",
        "name": "Pass-the-Hash→Lateral Movement→Data Exfiltration",
        "description": "NTLM hash captured via Mimikatz used to authenticate to all Windows hosts sharing the same local admin account.",
        "affected_systems": ["windows_hosts", "smb", "active_directory"],
        "attack_chain": ["hash_capture", "pth_authentication", "lateral_movement", "data_discovery", "exfiltration"],
        "confidence_base": 0.84,
        "mitre_techniques": ["T1550", "T1021", "T1005", "T1041"],
        "category": "ad_attacks",
    },
]

# Maps vuln_type keywords to attack pattern IDs
_VULN_PATTERN_AFFINITY: dict[str, list[str]] = {
    "ssrf": ["AP-003", "AP-011"],
    "sqli": ["AP-004"],
    "xss": ["AP-027"],
    "xxe": ["AP-011"],
    "rce": ["AP-009", "AP-013", "AP-020"],
    "lfi": ["AP-025"],
    "bola": ["AP-031"],
    "idor": ["AP-031"],
    "jwt": ["AP-015"],
    "oauth": ["AP-008", "AP-024"],
    "mass_assignment": ["AP-022"],
    "kerberoast": ["AP-005", "AP-016"],
    "dcsync": ["AP-005"],
    "ntlm": ["AP-017", "AP-032"],
    "pth": ["AP-032"],
    "s3": ["AP-010"],
    "iam": ["AP-001", "AP-010"],
    "container": ["AP-006", "AP-021", "AP-029"],
    "docker": ["AP-029"],
    "kubernetes": ["AP-006", "AP-021"],
    "graphql": ["AP-012"],
    "deserialization": ["AP-013"],
    "phishing": ["AP-007", "AP-014"],
    "subdomain": ["AP-014"],
    "supply_chain": ["AP-002", "AP-019", "AP-030"],
    "cloud": ["AP-001", "AP-003", "AP-010", "AP-018"],
}

# Known threat actors and their associated campaigns
_THREAT_ACTOR_DB: list[dict[str, Any]] = [
    {
        "threat_actor": "APT29 (Cozy Bear)",
        "campaign": "SolarWinds Supply Chain",
        "categories": ["supply_chain", "cloud_attacks"],
        "active_exploitation": True,
        "related_cves": ["CVE-2020-10148", "CVE-2021-27562"],
    },
    {
        "threat_actor": "Lazarus Group",
        "campaign": "Operation Dream Job",
        "categories": ["web_exploitation", "ransomware_chain"],
        "active_exploitation": True,
        "related_cves": ["CVE-2021-44228", "CVE-2022-22965"],
    },
    {
        "threat_actor": "FIN7",
        "campaign": "Carbon Spider",
        "categories": ["ransomware_chain", "web_exploitation"],
        "active_exploitation": True,
        "related_cves": ["CVE-2019-0708", "CVE-2021-34527"],
    },
    {
        "threat_actor": "Sandworm",
        "campaign": "Industroyer2",
        "categories": ["ad_attacks", "multi_vector"],
        "active_exploitation": True,
        "related_cves": ["CVE-2017-0144", "CVE-2020-17049"],
    },
    {
        "threat_actor": "ALPHV/BlackCat",
        "campaign": "Ransomware-as-a-Service",
        "categories": ["ransomware_chain", "ad_attacks"],
        "active_exploitation": True,
        "related_cves": ["CVE-2021-1675", "CVE-2022-33679"],
    },
    {
        "threat_actor": "UNC3944 (Scattered Spider)",
        "campaign": "Social Engineering → Cloud",
        "categories": ["cloud_attacks", "multi_vector"],
        "active_exploitation": True,
        "related_cves": ["CVE-2023-25690"],
    },
]


# ---------------------------------------------------------------------------
# Pattern Recognizer
# ---------------------------------------------------------------------------

@dataclass
class PatternRecognizer:
    """Identifies attack patterns and chains in collections of findings."""

    patterns: list[dict[str, Any]] = field(default_factory=lambda: list(ATTACK_PATTERNS))

    def analyze_finding_patterns(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Analyse findings to identify matching attack patterns and overall threat posture.

        Returns a dict with matched_patterns, overall_threat_score,
        attack_surface_breadth, dominant_category, and recommendations.
        """
        if not findings:
            return {
                "matched_patterns": [],
                "overall_threat_score": 0.0,
                "attack_surface_breadth": 0,
                "dominant_category": "none",
                "recommendations": ["No findings to analyse."],
            }

        matched_pattern_ids: set[str] = set()
        category_counts: dict[str, int] = {}

        for finding in findings:
            vtype = finding.get("vuln_type", "").lower()
            for keyword, pattern_ids in _VULN_PATTERN_AFFINITY.items():
                if keyword in vtype:
                    matched_pattern_ids.update(pattern_ids)

        matched_patterns: list[dict[str, Any]] = []
        for p in self.patterns:
            if p["id"] in matched_pattern_ids:
                cat = p["category"]
                category_counts[cat] = category_counts.get(cat, 0) + 1

                # Adjust confidence based on severity of triggering findings
                sev_boost = sum(
                    0.05 if f.get("severity", "").lower() == "critical" else
                    0.02 if f.get("severity", "").lower() == "high" else 0
                    for f in findings
                )
                adjusted_confidence = min(0.99, p["confidence_base"] + sev_boost)

                matched_patterns.append({
                    "pattern_id": p["id"],
                    "name": p["name"],
                    "category": cat,
                    "confidence": round(adjusted_confidence, 3),
                    "mitre_techniques": p["mitre_techniques"],
                    "attack_chain": p["attack_chain"],
                })

        dominant_category = max(category_counts, key=lambda k: category_counts[k]) if category_counts else "none"

        # Score: base on number of patterns matched and their confidence
        if matched_patterns:
            avg_confidence = sum(p["confidence"] for p in matched_patterns) / len(matched_patterns)
            pattern_factor = min(1.0, len(matched_patterns) / 10)
            overall_threat_score = round(avg_confidence * 70 + pattern_factor * 30, 2)
        else:
            overall_threat_score = 0.0

        critical_count = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
        recommendations = self._build_recommendations(matched_patterns, critical_count)

        return {
            "matched_patterns": matched_patterns,
            "overall_threat_score": overall_threat_score,
            "attack_surface_breadth": len(set(p["category"] for p in matched_patterns)),
            "dominant_category": dominant_category,
            "recommendations": recommendations,
        }

    def detect_attack_clusters(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Cluster related findings by vulnerability type and affected system.

        Returns a list of cluster dicts, each describing a related group
        of vulnerabilities that form a cohesive attack surface.
        """
        clusters: dict[str, list[dict[str, Any]]] = {}

        for finding in findings:
            vtype = finding.get("vuln_type", "unknown")
            cluster_key = self._vuln_to_cluster_key(vtype)
            clusters.setdefault(cluster_key, []).append(finding)

        result: list[dict[str, Any]] = []
        for cluster_name, cluster_findings in clusters.items():
            severities = [f.get("severity", "medium").lower() for f in cluster_findings]
            max_sev = (
                "critical" if "critical" in severities else
                "high" if "high" in severities else
                "medium" if "medium" in severities else "low"
            )
            cvss_scores = [float(f.get("cvss_score", 5.0)) for f in cluster_findings]
            avg_cvss = sum(cvss_scores) / len(cvss_scores)
            endpoints = list({f.get("endpoint", "") for f in cluster_findings})

            result.append({
                "cluster_name": cluster_name,
                "finding_count": len(cluster_findings),
                "max_severity": max_sev,
                "avg_cvss": round(avg_cvss, 2),
                "affected_endpoints": endpoints[:5],
                "vuln_types": list({f.get("vuln_type", "") for f in cluster_findings}),
                "combined_risk": round(avg_cvss * len(cluster_findings) * 0.5, 2),
            })

        return sorted(result, key=lambda c: c["combined_risk"], reverse=True)

    def predict_next_attack_vector(
        self, current_findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """
        Predict likely next attacker moves based on current findings.

        Returns a list of predicted next vectors with probability scores,
        MITRE technique IDs, and descriptions.
        """
        predictions: list[dict[str, Any]] = []
        seen_vtypes = {f.get("vuln_type", "").lower() for f in current_findings}

        # Prediction rules: if we see X, attacker will likely try Y next
        prediction_rules: list[tuple[str, dict[str, Any]]] = [
            ("ssrf", {
                "vector": "Cloud Metadata (IMDS) Access",
                "probability": 0.88,
                "technique": "T1552.005",
                "description": "SSRF will be used to access cloud metadata endpoint for IAM credential theft.",
            }),
            ("sqli", {
                "vector": "Database Credential Dump",
                "probability": 0.82,
                "technique": "T1005",
                "description": "SQL injection exploited to extract user credentials and database contents.",
            }),
            ("xss", {
                "vector": "Session Cookie Theft",
                "probability": 0.79,
                "technique": "T1539",
                "description": "XSS used to exfiltrate session tokens for account takeover.",
            }),
            ("rce", {
                "vector": "Reverse Shell Establishment",
                "probability": 0.91,
                "technique": "T1059",
                "description": "RCE used to establish persistent reverse shell for interactive access.",
            }),
            ("kerberoast", {
                "vector": "Offline Password Cracking",
                "probability": 0.87,
                "technique": "T1110",
                "description": "Kerberos TGS tickets cracked offline to obtain plaintext service account passwords.",
            }),
            ("iam", {
                "vector": "Cloud Privilege Escalation",
                "probability": 0.84,
                "technique": "T1078.004",
                "description": "Stolen IAM credentials used to escalate to administrator-level cloud access.",
            }),
            ("container", {
                "vector": "Container Escape to Host",
                "probability": 0.76,
                "technique": "T1611",
                "description": "Container misconfiguration exploited to escape to the underlying host node.",
            }),
            ("bola", {
                "vector": "Mass PII Enumeration",
                "probability": 0.85,
                "technique": "T1005",
                "description": "BOLA/IDOR used to iterate all object IDs and harvest user PII at scale.",
            }),
            ("phishing", {
                "vector": "Credential Harvesting Campaign",
                "probability": 0.78,
                "technique": "T1056",
                "description": "Phishing infrastructure used to harvest credentials from targeted users.",
            }),
            ("lfi", {
                "vector": "Log Poisoning for RCE",
                "probability": 0.71,
                "technique": "T1059",
                "description": "LFI used to include poisoned log files containing PHP/server-side code.",
            }),
        ]

        for trigger_keyword, pred in prediction_rules:
            if any(trigger_keyword in vtype for vtype in seen_vtypes):
                predictions.append(pred)

        # Always add lateral movement if critical findings exist
        has_critical = any(f.get("severity", "").lower() == "critical" for f in current_findings)
        if has_critical and not any(p["vector"] == "Lateral Movement" for p in predictions):
            predictions.append({
                "vector": "Lateral Movement via Credential Reuse",
                "probability": 0.73,
                "technique": "T1021",
                "description": "Compromised credentials reused for lateral movement to adjacent systems.",
            })

        return sorted(predictions, key=lambda p: p["probability"], reverse=True)

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _vuln_to_cluster_key(vuln_type: str) -> str:
        vtype = vuln_type.lower()
        if any(k in vtype for k in ("sqli", "sql", "injection")):
            return "injection_attacks"
        if any(k in vtype for k in ("xss", "cross_site")):
            return "xss_attacks"
        if any(k in vtype for k in ("ssrf", "xxe", "request_forgery")):
            return "server_side_attacks"
        if any(k in vtype for k in ("iam", "s3", "cloud", "azure", "gcp", "aws", "lambda")):
            return "cloud_misconfigurations"
        if any(k in vtype for k in ("kerberos", "dcsync", "ntlm", "ad", "ldap", "gpo")):
            return "active_directory_attacks"
        if any(k in vtype for k in ("container", "docker", "kubernetes", "k8s", "pod")):
            return "container_security"
        if any(k in vtype for k in ("jwt", "oauth", "auth", "session")):
            return "authentication_issues"
        if any(k in vtype for k in ("rce", "lfi", "rfi", "deserialization")):
            return "code_execution"
        return "miscellaneous"

    @staticmethod
    def _build_recommendations(
        matched_patterns: list[dict[str, Any]], critical_count: int
    ) -> list[str]:
        recs: list[str] = []
        categories = {p["category"] for p in matched_patterns}

        if "web_exploitation" in categories:
            recs.append("Deploy a WAF with OWASP Core Rule Set. Conduct urgent code review of injection points.")
        if "cloud_attacks" in categories:
            recs.append("Audit IAM permissions with least-privilege tools (IAM Access Analyzer, ScoutSuite). Enable CloudTrail/GCP Audit Logs.")
        if "ad_attacks" in categories:
            recs.append("Run BloodHound to map attack paths. Implement tiered administration and LAPS immediately.")
        if "ransomware_chain" in categories:
            recs.append("Test backup restoration procedures. Segment network to limit lateral movement. Deploy EDR on all endpoints.")
        if "supply_chain" in categories:
            recs.append("Implement dependency pinning and integrity verification (SRI/sigstore). Audit CI/CD pipeline permissions.")
        if critical_count >= 3:
            recs.append("URGENT: Initiate incident response process. Multiple critical findings indicate likely active or imminent compromise.")

        if not recs:
            recs.append("Continue regular security assessments and patch management.")
        return recs


# ---------------------------------------------------------------------------
# Attack Path Simulator
# ---------------------------------------------------------------------------

# Pre-built attack graphs: source → list of (target, technique, base_prob)
_ATTACK_GRAPHS: dict[str, list[tuple[str, str, float]]] = {
    "Internet": [
        ("Web Application", "T1190", 0.85),
        ("Email Gateway", "T1566", 0.75),
        ("VPN Endpoint", "T1078", 0.60),
    ],
    "Web Application": [
        ("Application DB", "T1190", 0.70),
        ("Internal API", "T1021", 0.65),
        ("Cloud IMDS", "T1552", 0.80),
    ],
    "Cloud IMDS": [
        ("IAM Role", "T1078", 0.90),
        ("S3 Bucket", "T1530", 0.85),
    ],
    "IAM Role": [
        ("Cloud Storage", "T1537", 0.80),
        ("Compute Instance", "T1578", 0.75),
    ],
    "Application DB": [
        ("DB Server OS", "T1059", 0.65),
        ("Domain Service Account", "T1078", 0.70),
    ],
    "Domain Service Account": [
        ("Active Directory", "T1087", 0.75),
        ("File Server", "T1021", 0.70),
    ],
    "Active Directory": [
        ("Domain Controller", "T1484", 0.80),
        ("All Domain Hosts", "T1550", 0.85),
    ],
    "Domain Controller": [
        ("All AD Credentials", "T1003", 0.95),
        ("Enterprise CA", "T1649", 0.70),
    ],
    "Email Gateway": [
        ("User Endpoint", "T1204", 0.70),
    ],
    "User Endpoint": [
        ("Domain Service Account", "T1056", 0.65),
        ("Active Directory", "T1087", 0.55),
    ],
}


@dataclass
class AttackPathSimulator:
    """Simulates realistic attack paths through an organisation's infrastructure."""

    attack_graph: dict[str, list[tuple[str, str, float]]] = field(
        default_factory=lambda: dict(_ATTACK_GRAPHS)
    )

    def simulate_path(
        self, entry_findings: list[dict[str, Any]], target_asset: str
    ) -> dict[str, Any]:
        """
        Simulate an attack path from the vulnerabilities in *entry_findings*
        towards *target_asset*.

        Returns path_nodes, total_probability, estimated_time_hours,
        blast_radius, and recommended_detections.
        """
        entry_point = self._infer_entry_point(entry_findings)
        path_nodes: list[dict[str, Any]] = []
        current = entry_point
        total_probability = 1.0
        total_hours = 0.0

        visited: set[str] = set()
        max_hops = 6

        for _ in range(max_hops):
            if current in visited:
                break
            visited.add(current)
            neighbors = self.attack_graph.get(current, [])
            if not neighbors:
                break

            # Pick the highest-probability neighbor
            best = max(neighbors, key=lambda x: x[2])
            asset, technique, prob = best

            # Adjust probability based on finding severities
            sev_multiplier = 1.0 + sum(
                0.05 if f.get("severity", "").lower() == "critical" else 0.02
                for f in entry_findings
            )
            adjusted_prob = min(0.99, prob * sev_multiplier)
            total_probability *= adjusted_prob

            hop_hours = random.uniform(1.0, 8.0)
            total_hours += hop_hours

            path_nodes.append({
                "asset": current,
                "next_asset": asset,
                "technique": technique,
                "probability": round(adjusted_prob, 3),
                "estimated_hours": round(hop_hours, 1),
            })

            if asset == target_asset or current == target_asset:
                path_nodes.append({
                    "asset": asset,
                    "next_asset": None,
                    "technique": "TARGET_REACHED",
                    "probability": round(total_probability, 4),
                    "estimated_hours": 0,
                })
                break
            current = asset

        blast = self.compute_blast_radius(
            entry_findings[0] if entry_findings else {}, None
        )

        return {
            "path_nodes": path_nodes,
            "total_probability": round(total_probability, 4),
            "estimated_time_hours": round(total_hours, 1),
            "blast_radius": blast,
            "recommended_detections": self._detection_recommendations(path_nodes),
        }

    def compute_blast_radius(
        self,
        finding: dict[str, Any],
        asset_map: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Estimate the blast radius of a single finding.

        Returns affected_assets, data_exposure_risk, business_impact_score,
        and lateral_movement_paths.
        """
        sev = finding.get("severity", "medium").lower()
        cvss = float(finding.get("cvss_score", 5.0))
        vtype = finding.get("vuln_type", "").lower()

        # Determine affected assets from asset_map or infer from vuln type
        if asset_map:
            affected = list(asset_map.keys())[:5]
        else:
            affected = self._infer_affected_assets(vtype)

        data_risk = (
            "critical" if cvss >= 9.0 else
            "high" if cvss >= 7.0 else
            "medium" if cvss >= 4.0 else "low"
        )

        business_impact = min(100.0, cvss * 10 * (1.5 if sev == "critical" else 1.0))

        lateral_paths: list[str] = []
        if "rce" in vtype or "sqli" in vtype:
            lateral_paths = ["DB Server → AD Service Account → Domain Controller", "Web Server → Internal API → Cloud Credentials"]
        elif "ssrf" in vtype:
            lateral_paths = ["Web App → Cloud IMDS → IAM Role → All Cloud Resources"]
        elif "iam" in vtype or "cloud" in vtype:
            lateral_paths = ["Cloud Credentials → All Cloud Resources → Data Stores"]

        return {
            "affected_assets": affected,
            "data_exposure_risk": data_risk,
            "business_impact_score": round(business_impact, 1),
            "lateral_movement_paths": lateral_paths,
        }

    def find_shortest_attack_path(
        self,
        source: str,
        target: str,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        BFS-based shortest path finder through the attack graph from
        *source* to *target*, weighted by finding severities.

        Returns a list of step dicts.
        """
        from collections import deque

        # Build adjacency from attack_graph
        graph = self.attack_graph
        queue: deque[tuple[str, list[tuple[str, str, str, float]]]] = deque()
        queue.append((source, []))
        visited: set[str] = set()

        sev_boost = sum(
            0.05 if f.get("severity", "").lower() == "critical" else 0.02
            for f in findings
        )

        while queue:
            current, path = queue.popleft()
            if current in visited:
                continue
            visited.add(current)

            if current == target:
                steps: list[dict[str, Any]] = []
                for src, tgt, tech, prob in path:
                    steps.append({
                        "source": src,
                        "target": tgt,
                        "technique": tech,
                        "probability": round(min(0.99, prob + sev_boost), 3),
                        "estimated_time": f"{random.randint(1, 8)}h",
                    })
                return steps

            for neighbor, technique, base_prob in graph.get(current, []):
                if neighbor not in visited:
                    queue.append((neighbor, path + [(current, neighbor, technique, base_prob)]))

        return []  # No path found

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _infer_entry_point(findings: list[dict[str, Any]]) -> str:
        if not findings:
            return "Internet"
        vtype = findings[0].get("vuln_type", "").lower()
        if any(k in vtype for k in ("sqli", "xss", "ssrf", "rce", "lfi")):
            return "Web Application"
        if any(k in vtype for k in ("phishing",)):
            return "Email Gateway"
        if any(k in vtype for k in ("s3", "iam", "cloud")):
            return "Cloud IMDS"
        return "Internet"

    @staticmethod
    def _infer_affected_assets(vtype: str) -> list[str]:
        if "sqli" in vtype:
            return ["Application DB", "DB Server OS", "Domain Service Account"]
        if "ssrf" in vtype:
            return ["Cloud IMDS", "IAM Role", "Internal API", "Cloud Storage"]
        if "rce" in vtype:
            return ["Web Server", "Application DB", "Internal Network"]
        if "iam" in vtype or "cloud" in vtype:
            return ["All Cloud Resources", "S3 Buckets", "Compute Instances"]
        if "kerberos" in vtype or "ad" in vtype or "dcsync" in vtype:
            return ["Domain Controller", "All AD Accounts", "File Servers"]
        return ["Web Application", "Internal API"]

    @staticmethod
    def _detection_recommendations(path_nodes: list[dict[str, Any]]) -> list[str]:
        techniques = {n["technique"] for n in path_nodes}
        recs: list[str] = []
        if "T1190" in techniques:
            recs.append("Enable WAF with OWASP rules; monitor for anomalous HTTP error rates.")
        if "T1552" in techniques or "T1078" in techniques:
            recs.append("Enable CloudTrail/Audit Logging; alert on unusual IAM API calls.")
        if "T1087" in techniques or "T1484" in techniques:
            recs.append("Deploy BloodHound Enterprise for continuous AD path monitoring.")
        if "T1003" in techniques:
            recs.append("Alert on DCSync events (Event ID 4662 with replication rights).")
        if "T1059" in techniques:
            recs.append("Deploy EDR with behaviour-based detection for shell execution.")
        if not recs:
            recs.append("Enable comprehensive SIEM logging across all detected attack path nodes.")
        return recs


# ---------------------------------------------------------------------------
# False Positive Reducer
# ---------------------------------------------------------------------------

# Exploit reliability scores for common vuln types (higher = more reliable)
_EXPLOIT_RELIABILITY: dict[str, float] = {
    "sqli_error_based": 0.95,
    "sqli_time_based": 0.85,
    "sqli_blind": 0.80,
    "xss_reflected": 0.88,
    "xss_stored": 0.90,
    "xss_dom": 0.75,
    "rce": 0.93,
    "ssrf": 0.87,
    "xxe": 0.82,
    "lfi": 0.80,
    "rfi": 0.75,
    "bola": 0.88,
    "idor": 0.88,
    "deserialization": 0.78,
    "jwt_alg_none": 0.97,
    "jwt_weak_secret": 0.90,
    "mass_assignment": 0.82,
    "open_redirect": 0.70,
    "graphql_introspection": 0.99,
    "misconfiguration": 0.92,
    "s3_public": 0.99,
    "cloudtrail_disabled": 0.99,
    "security_misconfiguration": 0.91,
    "cors_misconfiguration": 0.85,
    "rate_limit_bypass": 0.90,
}


@dataclass
class FalsePositiveReducer:
    """Reduces false positives in scanner findings using multi-factor heuristics."""

    def score_finding(
        self,
        finding: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> float:
        """
        Compute a false-positive confidence score (0-1) for a finding.

        Higher values indicate the finding is more likely to be genuine.
        Uses: exploit reliability, severity/CVSS alignment, CVE references,
        scanner confidence, and optional context (service banner, port).
        """
        vtype = finding.get("vuln_type", "").lower()
        severity = finding.get("severity", "medium").lower()
        cvss = float(finding.get("cvss_score", 5.0))
        cve_refs = finding.get("cve_refs", [])
        scanner_confidence = float(finding.get("confidence", 0.5))

        # 1. Exploit reliability component
        reliability = _EXPLOIT_RELIABILITY.get(vtype, 0.60)
        for key, val in _EXPLOIT_RELIABILITY.items():
            if key in vtype:
                reliability = max(reliability, val)

        # 2. Severity ↔ CVSS alignment (mismatches reduce score)
        sev_expected_cvss = {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0}
        expected = sev_expected_cvss.get(severity, 5.0)
        alignment = 1.0 - min(1.0, abs(cvss - expected) / 10.0)

        # 3. CVE reference bonus (known CVEs are more reliable)
        cve_bonus = min(0.15, len(cve_refs) * 0.05)

        # 4. Context enrichment (optional)
        context_score = 0.0
        if context:
            if context.get("service_banner_match"):
                context_score += 0.10
            if context.get("port_expected"):
                context_score += 0.05
            if context.get("previous_confirmed"):
                context_score += 0.20

        # Weighted combination
        fp_score = (
            reliability * 0.35
            + alignment * 0.25
            + scanner_confidence * 0.25
            + cve_bonus
            + context_score
        )

        return round(min(0.99, max(0.01, fp_score)), 3)

    def batch_reduce(
        self,
        findings: list[dict[str, Any]],
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Enrich each finding with fp_score, fp_likely (bool), and fp_reason.
        Returns a copy of the findings list with these fields added.
        """
        enriched: list[dict[str, Any]] = []
        for finding in findings:
            score = self.score_finding(finding, context)
            fp_likely = score < 0.55
            enriched.append({
                **finding,
                "fp_score": score,
                "fp_likely": fp_likely,
                "fp_reason": self._explain_reduction(finding, score),
            })
        return enriched

    def explain_reduction(self, finding: dict[str, Any]) -> str:
        """Return a human-readable explanation of the FP assessment."""
        score = self.score_finding(finding)
        return self._explain_reduction(finding, score)

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _explain_reduction(finding: dict[str, Any], score: float) -> str:
        reasons: list[str] = []
        cvss = float(finding.get("cvss_score", 5.0))
        severity = finding.get("severity", "medium").lower()
        cve_refs = finding.get("cve_refs", [])

        if score >= 0.85:
            reasons.append("High confidence: finding type has strong exploit reliability")
        elif score >= 0.65:
            reasons.append("Medium confidence: finding is plausible but requires manual verification")
        else:
            reasons.append("Low confidence: finding may be a false positive")

        if cve_refs:
            reasons.append(f"Known CVE(s) referenced: {', '.join(cve_refs[:2])}")
        else:
            reasons.append("No CVE references reduce specificity")

        if severity == "critical" and cvss < 7.0:
            reasons.append(f"Severity/CVSS mismatch: marked critical but CVSS {cvss} is low")
        elif severity == "low" and cvss > 7.0:
            reasons.append(f"Severity/CVSS mismatch: marked low but CVSS {cvss} is high")

        return "; ".join(reasons) + f" (fp_score={score:.3f})"


# ---------------------------------------------------------------------------
# Threat Correlator
# ---------------------------------------------------------------------------

@dataclass
class ThreatCorrelator:
    """Correlates findings with threat intelligence and computes composite risk."""

    threat_actor_db: list[dict[str, Any]] = field(
        default_factory=lambda: list(_THREAT_ACTOR_DB)
    )

    def correlate_with_threat_intel(
        self,
        findings: list[dict[str, Any]],
        intel_feeds: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Enrich each finding with threat actor attribution and campaign data.

        Each finding is augmented with: threat_actor, campaign, confidence,
        active_exploitation (bool), and related_cves.
        """
        enriched: list[dict[str, Any]] = []
        feeds = intel_feeds or self.threat_actor_db

        for finding in findings:
            vtype = finding.get("vuln_type", "").lower()
            sev = finding.get("severity", "medium").lower()
            cves = finding.get("cve_refs", [])

            best_match: dict[str, Any] | None = None
            best_score = 0

            for actor_entry in feeds:
                score = 0
                actor_cats = actor_entry.get("categories", [])

                # Match by category affinity
                for keyword, pattern_ids in _VULN_PATTERN_AFFINITY.items():
                    if keyword in vtype:
                        for p in ATTACK_PATTERNS:
                            if p["id"] in pattern_ids and p["category"] in actor_cats:
                                score += 2

                # Match by CVE overlap
                actor_cves = actor_entry.get("related_cves", [])
                score += sum(1 for c in cves if c in actor_cves)

                # Severity boost
                if sev == "critical":
                    score += 1

                if score > best_score:
                    best_score = score
                    best_match = actor_entry

            if best_match and best_score > 0:
                actor_confidence = min(0.95, 0.50 + best_score * 0.10)
            else:
                actor_confidence = 0.20
                best_match = {
                    "threat_actor": "Unknown",
                    "campaign": "Opportunistic",
                    "active_exploitation": False,
                    "related_cves": [],
                }

            enriched.append({
                **finding,
                "threat_actor": best_match.get("threat_actor", "Unknown"),
                "campaign": best_match.get("campaign", "Opportunistic"),
                "actor_confidence": round(actor_confidence, 2),
                "active_exploitation": best_match.get("active_exploitation", False),
                "related_cves": best_match.get("related_cves", []),
            })

        return enriched

    def compute_composite_risk(
        self,
        findings: list[dict[str, Any]],
        business_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Compute a composite risk score from all findings, incorporating
        optional business context (e.g., regulated industry, public-facing).

        Returns composite_score, risk_level, critical_findings_count,
        business_impact, regulatory_exposure, and recommended_priorities.
        """
        if not findings:
            return {
                "composite_score": 0.0,
                "risk_level": "low",
                "critical_findings_count": 0,
                "business_impact": "minimal",
                "regulatory_exposure": [],
                "recommended_priorities": [],
            }

        ctx = business_context or {}
        industry = ctx.get("industry", "generic").lower()
        public_facing = ctx.get("public_facing", True)
        stores_pii = ctx.get("stores_pii", False)

        critical_count = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
        high_count = sum(1 for f in findings if f.get("severity", "").lower() == "high")
        cvss_scores = [float(f.get("cvss_score", 0)) for f in findings]
        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0

        # Active exploitation findings increase risk significantly
        active_exploit_count = sum(1 for f in findings if f.get("active_exploitation", False))

        base_score = (
            critical_count * 18
            + high_count * 7
            + avg_cvss * 3
            + active_exploit_count * 10
        )
        base_score = min(100.0, base_score)

        # Business context multipliers
        if public_facing:
            base_score = min(100.0, base_score * 1.15)
        if stores_pii:
            base_score = min(100.0, base_score * 1.10)
        if industry in ("healthcare", "finance", "government"):
            base_score = min(100.0, base_score * 1.20)

        risk_level = (
            "critical" if base_score >= 75 else
            "high" if base_score >= 50 else
            "medium" if base_score >= 25 else "low"
        )

        business_impact = (
            "severe – operational disruption likely" if base_score >= 75 else
            "significant – data breach or downtime risk" if base_score >= 50 else
            "moderate – limited exposure" if base_score >= 25 else
            "minimal – low likelihood of exploitation"
        )

        regulatory_exposure: list[str] = []
        if stores_pii:
            regulatory_exposure.extend(["GDPR Article 32", "CCPA"])
        if industry == "healthcare":
            regulatory_exposure.append("HIPAA Security Rule")
        if industry == "finance":
            regulatory_exposure.extend(["PCI DSS v4.0", "SOX"])

        priorities = self._build_priority_list(findings, critical_count, active_exploit_count)

        return {
            "composite_score": round(base_score, 2),
            "risk_level": risk_level,
            "critical_findings_count": critical_count,
            "active_exploitation_count": active_exploit_count,
            "business_impact": business_impact,
            "regulatory_exposure": regulatory_exposure,
            "recommended_priorities": priorities,
        }

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _build_priority_list(
        findings: list[dict[str, Any]],
        critical_count: int,
        active_exploit_count: int,
    ) -> list[str]:
        priorities: list[str] = []
        if active_exploit_count > 0:
            priorities.append("IMMEDIATE: Patch findings with active known exploitation (0-24 hours).")
        if critical_count > 0:
            priorities.append(f"Remediate all {critical_count} critical findings within 7 days.")
        high_findings = [f for f in findings if f.get("severity", "").lower() == "high"]
        if high_findings:
            priorities.append(f"Address {len(high_findings)} high-severity findings within 30 days.")
        vuln_types = {f.get("vuln_type", "") for f in findings}
        if any("cloud" in v or "iam" in v or "s3" in v for v in vuln_types):
            priorities.append("Conduct urgent cloud configuration review and IAM audit.")
        if any("ad" in v or "kerberos" in v or "dcsync" in v for v in vuln_types):
            priorities.append("Engage AD hardening project: LAPS, tiered admin, BloodHound remediation.")
        return priorities
