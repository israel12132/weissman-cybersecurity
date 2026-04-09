"""
Weissman-cybersecurity: One-Click Remediation — AI-driven fix generator.
Produces exact patch, config snippets, and Enterprise IaC (Terraform, Kubernetes, Ansible).
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Infrastructure as Code: ready-to-use Terraform, Kubernetes YAML, Ansible (per tech + finding).
REMEDIATION_IAC: dict[str, dict[str, dict[str, str]]] = {
    "nginx": {
        "lfi": {
            "terraform": """
# Terraform: Harden nginx (LFI/path traversal)
resource "aws_security_group_rule" "nginx_ingress" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = var.nginx_sg_id
}
# Enforce WAF / path normalization in ALB or nginx config
""",
            "kubernetes": """
# Kubernetes: nginx configmap (block path traversal)
apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-hardening
data:
  default.conf: |
    server {
      if ($request_uri ~*\\.\\.) { return 403; }
      add_header X-Content-Type-Options "nosniff" always;
      add_header X-Frame-Options "SAMEORIGIN" always;
    }
""",
            "ansible": """
# Ansible: Harden nginx (LFI)
- name: Harden nginx path traversal
  lineinfile:
    path: /etc/nginx/nginx.conf
    insertafter: 'server {'
    line: '    if ($request_uri ~*\\.\\.) { return 403; }'
  notify: reload nginx
""",
        },
        "default": {
            "terraform": "# Terraform: Restrict nginx SG; enable WAF\n",
            "kubernetes": "# Kubernetes: nginx ConfigMap — server_tokens off; security headers\n",
            "ansible": "# Ansible: apt upgrade nginx; server_tokens off\n",
        },
    },
    "apache": {
        "lfi": {
            "terraform": "# Terraform: Harden Apache (WAF / ALB rules)\n",
            "kubernetes": "# Kubernetes: Apache config — Options -Indexes; AllowOverride None\n",
            "ansible": """
# Ansible: Apache LFI hardening
- name: Disable directory listing
  lineinfile:
    path: "{{ apache_conf }}"
    regexp: '^\\s*Options'
    line: '    Options -Indexes -Includes'
  notify: restart apache
""",
        },
        "default": {
            "terraform": "# Terraform: Apache security group + WAF\n",
            "kubernetes": "# Kubernetes: Apache deployment — readOnlyRootFilesystem: true\n",
            "ansible": "# Ansible: yum update httpd; ServerTokens Prod\n",
        },
    },
    "docker": {
        "default": {
            "terraform": """
# Terraform: Harden ECS / Docker
resource "aws_ecs_task_definition" "hardened" {
  container_definitions = jsonencode([{
    readOnlyRootFilesystem = true
    user                   = "1000"
    logConfiguration = { ... }
  }])
}
""",
            "kubernetes": """
# Kubernetes: Pod security (no root, read-only root)
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    readOnlyRootFilesystem: true
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
""",
            "ansible": """
# Ansible: Docker hardened
- name: Run container as non-root
  docker_container:
    name: "{{ app_name }}"
    image: "{{ image }}"
    user: "1000"
  register: c
""",
        },
    },
    "default": {
        "default": {
            "terraform": "# Terraform: Restrict ingress; enable logging and WAF where applicable\n",
            "kubernetes": "# Kubernetes: securityContext runAsNonRoot; readOnlyRootFilesystem: true\n",
            "ansible": "# Ansible: Apply vendor patch; restrict services; least privilege\n",
        },
    },
}

# Template fixes per tech and finding type. Placeholders: {cve_id}, {component}, {version}
REMEDIATION_TEMPLATES: dict[str, dict[str, str]] = {
    "nginx": {
        "lfi": """
# Nginx: Prevent path traversal (LFI)
location / {
    # Disable script execution in uploads
    location ~* ^/uploads/ {
        add_header X-Content-Type-Options "nosniff";
        default_type application/octet-stream;
    }
    # Normalize path - reject ..
    if ($request_uri ~*\\.\\.) { return 403; }
}
""",
        "header_injection": """
# Nginx: Harden headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
""",
        "default": """
# Nginx: General hardening for {cve_id}
# 1. Update to latest stable: apt upgrade nginx
# 2. Disable server_tokens: server_tokens off;
# 3. Restrict methods: if ($request_method !~ ^(GET|POST|HEAD)$) { return 405; }
""",
    },
    "apache": {
        "lfi": """
# Apache: Prevent LFI (.htaccess or vhost)
<Directory "/var/www">
    Options -Indexes -Includes
    AllowOverride None
    Require all denied
</Directory>
<FilesMatch "\\.(bak|env|old)$">
    Require all denied
</FilesMatch>
""",
        "default": """
# Apache: Remediation for {cve_id}
# 1. Update: yum update httpd  or  apt upgrade apache2
# 2. Disable server signature: ServerTokens Prod
# 3. Remove default docs: rm -rf /var/www/html/*
""",
    },
    "php": {
        "sql_injection": """
# PHP: Parameterized query (remediation)
// BAD: $q = "SELECT * FROM users WHERE id = " . $_GET['id'];
// GOOD:
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
""",
        "xss": """
# PHP: Output encoding
// BAD: echo $_GET['name'];
// GOOD:
echo htmlspecialchars($_GET['name'] ?? '', ENT_QUOTES, 'UTF-8');
""",
        "default": """
# PHP: General fix for {cve_id}
# 1. Update PHP: apt upgrade php (or use supported version)
# 2. Set open_basedir and disable_functions in php.ini
# 3. Use prepared statements for all DB queries
""",
    },
    "node": {
        "injection": """
// Node: Sanitize input (e.g. for {cve_id})
const validator = require('validator');
const userInput = validator.escape(req.body.input);
// Or use parameterized queries for DB
""",
        "default": """
// Node: Remediation for {cve_id}
// 1. Update dependency: npm update <package>
// 2. Use helmet(): app.use(helmet());
// 3. Validate/sanitize all user input (validator, joi)
""",
    },
    "java": {
        "deserialization": """
// Java: Avoid deserializing untrusted data
// Use safe formats (JSON with trusted libs) or validate/sanitize
ObjectInputStream ois = new ObjectInputStream(...);
// Prefer: JsonNode node = objectMapper.readTree(input);
""",
        "default": """
// Java: Fix for {cve_id}
// 1. Upgrade affected library (Maven/Gradle)
// 2. Avoid ObjectInputStream on network data
// 3. Use SecurityManager and least privilege
""",
    },
    "docker": {
        "default": """
# Docker: Harden for {cve_id}
# 1. Update base image: FROM alpine:3.19 (or latest)
# 2. Run as non-root: USER 1000
# 3. No secrets in image: use secrets mount or env at runtime
""",
    },
    "default": {
        "default": """
# Remediation for {cve_id}
# 1. Update {component} to a patched version (check vendor advisory)
# 2. Apply vendor patch or workaround
# 3. Restrict network access and principle of least privilege
""",
    },
}


def get_remediation_snippet(
    finding_type: str | None = None,
    tech_stack: list[str] | None = None,
    severity: str | None = None,
    cve_id: str | None = None,
    component: str | None = None,
) -> str:
    """
    One-Click Remediation: return exact patch / config / code snippet for the finding.
    finding_type: e.g. lfi, sql_injection, xss, deserialization, default.
    tech_stack: e.g. ["nginx", "php"] — first match wins.
    """
    finding_type = (finding_type or "default").strip().lower()
    cve_id = cve_id or "CVE-XXXX"
    component = component or "affected component"
    tech_keys = [t.strip().lower() for t in (tech_stack or []) if t]
    if not tech_keys:
        tech_keys = ["default"]
    for tech in tech_keys:
        templates = REMEDIATION_TEMPLATES.get(tech) or REMEDIATION_TEMPLATES.get("default") or {}
        snippet = templates.get(finding_type) or templates.get("default")
        if snippet:
            return snippet.strip().format(
                cve_id=cve_id,
                component=component,
                version="latest",
            )
    snippet = (REMEDIATION_TEMPLATES.get("default") or {}).get("default") or REMEDIATION_TEMPLATES["default"]["default"]
    return snippet.strip().format(cve_id=cve_id, component=component, version="latest")


def get_remediation_iac(
    finding_type: str | None = None,
    tech_stack: list[str] | None = None,
    severity: str | None = None,
    cve_id: str | None = None,
    component: str | None = None,
) -> dict[str, str]:
    """
    Enterprise DevOps: return IaC snippets (Terraform, Kubernetes, Ansible) for the finding.
    Keys: terraform, kubernetes, ansible. Empty string if no snippet for that format.
    """
    finding_type = (finding_type or "default").strip().lower()
    tech_keys = [t.strip().lower() for t in (tech_stack or []) if t]
    if not tech_keys:
        tech_keys = ["default"]
    out: dict[str, str] = {"terraform": "", "kubernetes": "", "ansible": ""}
    for tech in tech_keys:
        iac_tech = REMEDIATION_IAC.get(tech) or REMEDIATION_IAC.get("default") or {}
        block = iac_tech.get(finding_type) or iac_tech.get("default")
        if block:
            cve = cve_id or "CVE-XXXX"
            comp = component or "component"
            for k in out:
                s = (block.get(k) or "").strip()
                out[k] = s.replace("{cve_id}", cve).replace("{component}", comp)
            return out
    default_block = (REMEDIATION_IAC.get("default") or {}).get("default") or {}
    cve = cve_id or "CVE-XXXX"
    comp = component or "component"
    for k in out:
        s = (default_block.get(k) or "").strip()
        out[k] = s.replace("{cve_id}", cve).replace("{component}", comp)
    return out
