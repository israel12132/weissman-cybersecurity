import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import { Search, Download, RefreshCw } from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { SkeletonBar, SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { apiFetch } from '../lib/apiBase'
import { openSseStream } from '../lib/sseStream'
import { ENGINES_BY_ID } from '../lib/enginesRegistry'
import { useClientIntegrations } from '../hooks/useClientIntegrations'
import { prefillParamsForEngine } from '../lib/engineClientPrefill'

const ENGINE_ID = 'iac_misconfig'

const MODES = [
  { id: 'static', label: 'Static (inline)', icon: '📝', desc: 'Analyze pasted IaC — fully offline, deterministic' },
  { id: 'repo', label: 'Repository', icon: '🐙', desc: 'Fetch a GitHub repo tree and scan every IaC file' },
  { id: 'exposure', label: 'Exposure', icon: '🌐', desc: 'Probe a host for publicly leaked IaC (state, .env…)' },
]

const FRAMEWORKS = [
  { id: 'terraform', label: 'Terraform', icon: '🟣' },
  { id: 'kubernetes', label: 'Kubernetes', icon: '☸️' },
  { id: 'dockerfile', label: 'Dockerfile', icon: '🐳' },
  { id: 'cloudformation', label: 'CloudFormation', icon: '🟠' },
  { id: 'docker_compose', label: 'Compose', icon: '🧩' },
  { id: 'github_actions', label: 'GH Actions', icon: '⚙️' },
  { id: 'arm', label: 'Azure ARM', icon: '🔷' },
  { id: 'helm', label: 'Helm', icon: '⎈' },
  { id: 'openapi', label: 'OpenAPI', icon: '📡' },
  { id: 'serverless', label: 'Serverless', icon: 'λ' },
  { id: 'kustomize', label: 'Kustomize', icon: '🎨' },
  { id: 'bicep', label: 'Bicep', icon: '🔷' },
  { id: 'pulumi', label: 'Pulumi', icon: '🟧' },
  { id: 'cdk', label: 'AWS CDK', icon: '📦' },
  { id: 'ansible', label: 'Ansible', icon: '📋' },
  { id: 'nginx', label: 'Nginx', icon: '🌐' },
  { id: 'crossplane', label: 'Crossplane', icon: '✈️' },
  { id: 'terragrunt', label: 'Terragrunt', icon: '🏗️' },
  { id: 'argocd', label: 'Argo CD', icon: '🔄' },
  { id: 'flux', label: 'Flux CD', icon: '🔁' },
  { id: 'opa', label: 'OPA/GK', icon: '🛡️' },
  { id: 'vault', label: 'Vault HCL', icon: '🔐' },
  { id: 'istio', label: 'Istio', icon: '🕸️' },
  { id: 'kyverno', label: 'Kyverno', icon: '🔒' },
  { id: 'sops', label: 'SOPS', icon: '🔑' },
  { id: 'cue', label: 'CUE', icon: '📐' },
  { id: 'ci_platform', label: 'CI Platform', icon: '🚀' },
  { id: 'reconcile', label: 'Plan Reconcile', icon: '⚖️' },
  { id: 'linkerd', label: 'Linkerd', icon: '🔗' },
  { id: 'packer', label: 'Packer', icon: '📀' },
  { id: 'helmfile', label: 'Helmfile', icon: '⎈' },
  { id: 'cert_manager', label: 'cert-manager', icon: '📜' },
  { id: 'external_secrets', label: 'External Secrets', icon: '🔐' },
  { id: 'gateway_api', label: 'Gateway API', icon: '🚪' },
  { id: 'skaffold', label: 'Skaffold', icon: '⚡' },
  { id: 'supply_chain', label: 'Supply Chain', icon: '⛓️' },
  { id: 'velero', label: 'Velero', icon: '💾' },
  { id: 'keda', label: 'KEDA', icon: '📈' },
  { id: 'tekton', label: 'Tekton', icon: '🔧' },
  { id: 'falco', label: 'Falco', icon: '🦅' },
  { id: 'backstage', label: 'Backstage', icon: '🎭' },
  { id: 'envoy_gateway', label: 'Envoy Gateway', icon: '🛡️' },
  { id: 'sealed_secrets', label: 'Sealed Secrets', icon: '🔏' },
  { id: 'prometheus_operator', label: 'Prometheus Op', icon: '📊' },
  { id: 'argo_rollouts', label: 'Argo Rollouts', icon: '🎯' },
]

const GATE_PROFILES = ['', 'development', 'ci', 'production', 'pci', 'fedramp']
const ASSET_TIERS = ['tier3', 'tier2', 'tier1']

const PROVIDERS = ['aws', 'azure', 'gcp', 'kubernetes', 'docker', 'github', 'generic']
const PACKS = ['CIS', 'PCI-DSS', 'HIPAA', 'NIST', 'SOC2', 'ISO27001', 'MITRE']
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']
const IAC_TYPES = ['auto', 'terraform', 'kubernetes', 'dockerfile', 'cloudformation', 'docker_compose', 'github_actions', 'arm', 'helm', 'openapi', 'serverless', 'kustomize', 'bicep', 'pulumi', 'cdk', 'ansible', 'nginx', 'crossplane', 'terragrunt', 'argocd', 'flux', 'opa', 'vault', 'istio', 'kyverno', 'sops', 'cue', 'ci_platform', 'linkerd', 'packer', 'helmfile', 'cert_manager', 'external_secrets', 'gateway_api', 'skaffold', 'velero', 'keda', 'tekton', 'falco', 'backstage', 'envoy_gateway', 'sealed_secrets', 'prometheus_operator', 'argo_rollouts']

const SEV_COLOR = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22d3ee',
  info: '#64748b',
}

// Demo artifacts that deliberately trip multiple high-value policies (Wiz-style "try it").
const SAMPLES = {
  terraform: {
    name: 'main.tf',
    type: 'terraform',
    content: `resource "aws_s3_bucket" "assets" {
  bucket = "company-public-assets"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" {
  engine               = "postgres"
  publicly_accessible  = true
  storage_encrypted    = false
}

resource "aws_iam_policy" "admin" {
  policy = <<EOF
{ "Version": "2012-10-17", "Statement": [ { "Effect": "Allow", "Action": "*", "Resource": "*" } ] }
EOF
}`,
  },
  kubernetes: {
    name: 'deployment.yaml',
    type: 'kubernetes',
    content: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-api
  namespace: default
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: api
          image: payments/api:latest
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
      volumes:
        - name: dockersock
          hostPath:
            path: /var/run/docker.sock`,
  },
  dockerfile: {
    name: 'Dockerfile',
    type: 'dockerfile',
    content: `FROM ubuntu:latest
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY
RUN curl https://get.example.com/install.sh | bash
COPY id_rsa /root/.ssh/id_rsa
RUN chmod 777 /app
# no USER -> runs as root`,
  },
  github_actions: {
    name: '.github/workflows/ci.yml',
    type: 'github_actions',
    content: `on: pull_request_target
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
        with:
          ref: \${{ github.event.pull_request.head.ref }}
      - run: echo "Title: \${{ github.event.issue.title }}"`,
  },
  openapi: {
    name: 'openapi.json',
    type: 'openapi',
    content: `{
  "openapi": "3.0.0",
  "servers": [{ "url": "http://api.example.com" }],
  "paths": {
    "/admin/export": {
      "get": { "responses": { "200": { "description": "dump" } } }
    }
  }
}`,
  },
  serverless: {
    name: 'serverless.yml',
    type: 'serverless',
    content: `service: payments-api
provider:
  name: aws
  iamRoleStatements:
    - Effect: Allow
      Action: '*'
      Resource: '*'
functions:
  pay:
    handler: src/handler.main
    events:
      - http: { path: pay, method: post }`,
  },
  kustomize: {
    name: 'kustomization.yaml',
    type: 'kustomize',
    content: `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml
patches:
  - patch: |-
      spec:
        template:
          spec:
            containers:
              - name: api
                securityContext:
                  privileged: true
images:
  - name: payments/api
    newTag: latest`,
  },
  pulumi: {
    name: 'index.ts',
    type: 'pulumi',
    content: `import * as aws from "@pulumi/aws";
new aws.s3.Bucket("assets", { acl: "public-read" });
new aws.iam.Policy("admin", {
  policy: JSON.stringify({ Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] }),
});`,
  },
  cdk: {
    name: 'stack.ts',
    type: 'cdk',
    content: `import * as s3 from 'aws-cdk-lib/aws-s3';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
new s3.Bucket(this, 'B', { blockPublicAccess: s3.BlockPublicAccess.BLOCK_NONE });
new ec2.SecurityGroup(this, 'SG', {}).addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22));`,
  },
  bicep: {
    name: 'main.bicep',
    type: 'bicep',
    content: `resource st 'Microsoft.Storage/storageAccounts@2021-09-01' = {
  properties: { allowBlobPublicAccess: true, supportsHttpsTrafficOnly: false }
}`,
  },
  ansible: {
    name: 'playbook.yml',
    type: 'ansible',
    content: `- hosts: all
  become: true
  vars:
    db_password: SuperSecret123!
  tasks:
    - name: deploy
      ansible.builtin.shell: curl https://setup.example | bash
    - copy:
        dest: /opt/app
        mode: '0777'`,
  },
  nginx: {
    name: 'nginx.conf',
    type: 'nginx',
    content: `server_tokens on;
server {
  listen 443 ssl;
  ssl_protocols TLSv1 TLSv1.1;
  location / { autoindex on; proxy_pass http://backend; }
}`,
  },
  crossplane: {
    name: 'crossplane/bucket-xr.yaml',
    type: 'crossplane',
    content: `apiVersion: s3.aws.upbound.io/v1beta1
kind: Bucket
metadata:
  name: public-assets
spec:
  forProvider:
    acl: public-read
    region: us-east-1
---
apiVersion: aws.upbound.io/v1beta1
kind: ProviderConfig
metadata:
  name: default
spec:
  credentials:
    source: Secret
    secretRef:
      name: aws-creds
      namespace: crossplane-system`,
  },
  terragrunt: {
    name: 'terragrunt.hcl',
    type: 'terragrunt',
    content: `remote_state {
  backend = "s3"
  config = {
    bucket   = "tf-state"
    endpoint = "http://state.internal:9000"
    key      = "prod/terraform.tfstate"
  }
}

inputs = {
  db_password = "SuperSecret123!"
}

dependency "vpc" {
  config_path = "../vpc"
}`,
  },
  drift: {
    multi: true,
    files: [
      { name: 'prod/main.tf', type: 'terraform', content: 'resource "aws_s3_bucket" "assets" { acl = "public-read" }' },
      { name: 'staging/main.tf', type: 'terraform', content: 'resource "aws_s3_bucket" "assets" { acl = "private" }' },
    ],
  },
  argocd: {
    name: 'argocd/app.yaml',
    type: 'argocd',
    content: `apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: payments
spec:
  source:
    repoURL: http://git.internal/repos/payments
    targetRevision: HEAD
  syncPolicy:
    automated:
      selfHeal: true`,
  },
  flux: {
    name: 'flux/kustomization.yaml',
    type: 'flux',
    content: `apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: prod-apps
  namespace: flux-system
spec:
  prune: false
  sourceRef:
    kind: GitRepository
    name: prod-repo`,
  },
  istio: {
    name: 'istio/authz.yaml',
    type: 'istio',
    content: `apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
spec:
  mtls:
    mode: PERMISSIVE
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-all
spec:
  action: ALLOW
  rules:
    - {}`,
  },
  vault: {
    name: 'vault/admin-policy.hcl',
    type: 'vault',
    content: `path "*" {
  capabilities = ["create", "read", "update", "delete", "sudo"]
}`,
  },
  tfplan: {
    name: 'plan.json',
    type: 'terraform',
    plan: '{"resource_changes":[{"address":"aws_s3_bucket.b","type":"aws_s3_bucket","change":{"actions":["create"],"after":{"acl":"public-read"}}},{"address":"aws_security_group.sg","type":"aws_security_group","change":{"actions":["create"],"after":{"ingress":[{"cidr_blocks":["0.0.0.0/0"]}]}}}]}',
  },
  reconcile: {
    reconcile: true,
    name: 'main.tf',
    type: 'terraform',
    content: 'resource "aws_s3_bucket" "b" { bucket = "looks-private" }',
    plan: '{"resource_changes":[{"address":"aws_s3_bucket.b","type":"aws_s3_bucket","change":{"actions":["create"],"after":{"acl":"public-read"}}}]}',
  },
  kyverno: {
    name: 'kyverno/cluster-policy.yaml',
    type: 'kyverno',
    content: `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: audit-only
spec:
  validationFailureAction: audit
  background: false
  rules:
    - name: mutate-priv
      mutate:
        patchStrategicMerge:
          spec:
            containers:
              - securityContext:
                  privileged: true`,
  },
  sops: {
    name: '.sops.yaml',
    type: 'sops',
    content: `creation_rules:
  - encrypted_regex: .*
    shamir_threshold: 1`,
  },
  cue: {
    name: 'config.cue',
    type: 'cue',
    content: `package config

#Config: {
  cidr: "0.0.0.0/0"
  password: "SuperSecret123!"
}

config: #Config`,
  },
  atlantis: {
    name: 'atlantis.yaml',
    type: 'ci_platform',
    content: `repos:
  - id: /.*/
    automerge: true
    apply_requirements: []`,
  },
  linkerd: {
    name: 'linkerd/sa.yaml',
    type: 'linkerd',
    content: `apiVersion: policy.linkerd.io/v1beta1
kind: ServerAuthorization
metadata:
  name: all-clients
spec:
  server:
    name: payments-api
  client:
    unauthenticated: true`,
  },
  packer: {
    name: 'packer.pkr.hcl',
    type: 'packer',
    content: `source "amazon-ebs" "golden" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  ami_groups = ["all"]
  encrypted = false
}`,
  },
  helmfile: {
    name: 'helmfile.yaml',
    type: 'helmfile',
    content: `releases:
  - name: payments
    chart: http://charts.internal/payments
    wait: false
    setValues:
      - name: db.password
        value: SuperSecret123!`,
  },
  cert_manager: {
    name: 'certs/api-cert.yaml',
    type: 'cert_manager',
    content: `apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: api-prod
spec:
  isCA: true
  privateKey:
    size: 1024
    rotationPolicy: Never
  solvers:
    - http01:
        ingress:
          class: nginx`,
  },
  eso: {
    name: 'eso/cluster-store.yaml',
    type: 'external_secrets',
    content: `apiVersion: external-secrets.io/v1beta1
kind: ClusterSecretStore
metadata:
  name: aws-store
spec:
  provider:
    aws:
      service: SecretsManager
      accessKeyID: AKIAIOSFODNN7EXAMPLE
      secretAccessKey: wJalrXUtnFEMI
      role: "*"`,
  },
  gateway: {
    name: 'gateway/api-gw.yaml',
    type: 'gateway_api',
    content: `apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: public-gw
spec:
  listeners:
    - protocol: HTTP
      port: 80
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: admin-route
spec:
  rules:
    - matches:
        - path:
            value: /admin`,
  },
  skaffold: {
    name: 'skaffold.yaml',
    type: 'skaffold',
    content: `apiVersion: skaffold/v4beta7
kind: Config
profiles:
  - name: production
    portForward:
      - resourceType: service
        resourceName: payments-api
build:
  artifacts:
    - image: payments/api:latest
      docker:
        buildArgs:
          API_KEY: SuperSecret123!`,
  },
  supply_chain: {
    multi: true,
    files: [
      { name: 'main.tf', type: 'terraform', content: 'module "vpc" { source = "git::https://github.com/org/vpc.git" }' },
      { name: 'Dockerfile', type: 'dockerfile', content: 'FROM ubuntu:latest\nENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE' },
      { name: 'deploy.yaml', type: 'kubernetes', content: 'apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: api\n          image: payments/api:latest' },
    ],
  },
  velero: {
    name: 'velero/bsl.yaml',
    type: 'velero',
    content: `apiVersion: velero.io/v1
kind: BackupStorageLocation
metadata:
  name: default
spec:
  config:
    s3Url: http://minio:9000/backups
    publicAccess: true
  credential:
    name: velero-creds
    accessKey: AKIAIOSFODNN7EXAMPLE
    secretKey: wJalrXUtnFEMI`,
  },
  keda: {
    name: 'keda/scaledobject.yaml',
    type: 'keda',
    content: `apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: payments-prod
spec:
  minReplicaCount: 0
  triggers:
    - type: prometheus
      metadata:
        serverAddress: http://prometheus:9090`,
  },
  tekton: {
    name: 'tekton/pipeline.yaml',
    type: 'tekton',
    content: `apiVersion: tekton.dev/v1
kind: PipelineRun
metadata:
  name: build-prod
spec:
  serviceAccountName: default
  params:
    - name: db.password
      value: SuperSecret123!
  pipelineSpec:
    tasks:
      - name: build
        taskSpec:
          steps:
            - image: ubuntu:latest
              securityContext:
                privileged: true`,
  },
  falco: {
    name: 'falco/custom-rules.yaml',
    type: 'falco',
    content: `- rule: Terminal shell in container
  enabled: false
  condition: spawned_process
- macro: sensitive_paths
  condition: not fd.name in (/etc/shadow, /var/run/docker.sock)`,
  },
  backstage: {
    name: 'app-config.yaml',
    type: 'backstage',
    content: `app:
  title: Dev Portal
auth:
  environment: development
  dangerouslyAllowGuestAccess: true
backend:
  cors:
    origin: '*'
integrations:
  github:
    token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
techdocs:
  publisher:
    type: awsS3
    awsS3:
      bucketName: docs-public
      publicRead: true`,
  },
  envoy_gateway: {
    name: 'envoy-gateway/gateway.yaml',
    type: 'envoy_gateway',
    content: `apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyProxy
metadata:
  name: edge
spec:
  admin:
    address: 0.0.0.0:9901
  jwt:
    disabled: true
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: api
spec:
  hostnames:
    - '*'
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - name: payments-api`,
  },
  kustomize_deep: {
    name: 'overlays/prod/kustomization.yaml',
    type: 'kustomize',
    content: `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: kube-system
resources:
  - ../../base
patches:
  - patch: |-
      spec:
        template:
          spec:
            hostNetwork: true
            containers:
              - name: api
                securityContext:
                  privileged: true
                  seccompProfile:
                    type: Unconfined
secretGenerator:
  - name: db-creds
    literals:
      - password=prod-db-secret-2024`,
  },
  sealed_secrets: {
    name: 'sealed/db.yaml',
    type: 'sealed_secrets',
    content: `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: db-creds
  annotations:
    sealedsecrets.bitnami.com/cluster-wide: 'true'
    sealedsecrets.bitnami.com/strict-validation: 'false'
spec:
  encryptedData:
    password: AgBxExample
  template:
    stringData:
      password: plaintext-leak`,
  },
  prometheus: {
    name: 'monitoring/stack.yaml',
    type: 'prometheus_operator',
    content: `apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: payments
spec:
  endpoints:
    - tlsConfig:
        insecureSkipVerify: true
---
apiVersion: v1
kind: Secret
metadata:
  name: grafana-admin
stringData:
  adminPassword: SuperSecret123!`,
  },
  argo_rollouts: {
    name: 'rollouts/api.yaml',
    type: 'argo_rollouts',
    content: `apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: payments-api
spec:
  strategy:
    canary:
      trafficRouting:
        header:
          name: X-Canary
      steps:
        - setWeight: 30
        - pause: {}
  template:
    spec:
      containers:
        - name: analysis
          securityContext:
            privileged: true`,
  },
}

const splitCsv = (s) => String(s || '').split(/[\n,]/).map((x) => x.trim()).filter(Boolean)

function exportPolicyFindingsCsv(rows, filenamePrefix) {
  const header = ['severity', 'policy_id', 'title', 'file', 'resource', 'framework', 'description']
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const lines = [
    header.join(','),
    ...rows.map((f) =>
      [f.severity, f.policy_id, f.title, f.file, f.resource, f.framework, f.description].map(esc).join(','),
    ),
  ]
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${filenamePrefix}-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}
const numOr = (v, d) => {
  const n = Number(v)
  return Number.isFinite(n) ? n : d
}

const DEFAULT_PARAMS = {
  scan_modes: ['static'],
  // static
  iac_content: '',
  iac_filename: 'main.tf',
  iac_type: 'auto',
  iac_files_json: '',
  terraform_plan_json: '',
  // repo
  repo_url: '',
  repo_ref: '',
  repo_subdir: '',
  max_files: '300',
  // filters
  frameworks: [...FRAMEWORKS.map((f) => f.id)],
  providers: [...PROVIDERS],
  compliance_packs: [...PACKS],
  // detection
  secret_scan: true,
  dedupe: true,
  attack_path_synthesis: true,
  cross_file_correlation: true,
  include_policy_catalog: true,
  resource_graph: true,
  drift_analysis: true,
  live_blast: true,
  aws_cross_account_role_arn: '',
  aws_external_id: '',
  aws_regions: '',
  k8s_api_server: '',
  k8s_token: '',
  k8s_namespace: 'default',
  iam_simulate: true,
  k8s_rbac_prove: true,
  autopilot: true,
  autopilot_create_pr: false,
  git_repo_url: '',
  git_base_branch: 'main',
  github_token: '',
  gate_profile: '',
  asset_tier: 'tier3',
  min_severity: 'info',
  fail_severity: 'high',
  // advanced
  skip_policies: '',
  only_policies: '',
  policy_waivers: '',
  exposure_paths: '',
  timeout_ms: '8000',
  verify_tls: true,
}

function buildScanBody(params, clientId, target) {
  const body = {
    engine: ENGINE_ID,
    client_id: Number(clientId),
    target,
    timeout: 300,
    scan_modes: params.scan_modes,
    min_severity: params.min_severity,
    fail_severity: params.fail_severity,
    secret_scan: !!params.secret_scan,
    dedupe: !!params.dedupe,
    attack_path_synthesis: !!params.attack_path_synthesis,
    cross_file_correlation: !!params.cross_file_correlation,
    include_policy_catalog: !!params.include_policy_catalog,
    resource_graph: !!params.resource_graph,
    drift_analysis: !!params.drift_analysis,
    live_blast: !!params.live_blast,
    iam_simulate: !!params.iam_simulate,
    k8s_rbac_prove: !!params.k8s_rbac_prove,
    autopilot: !!params.autopilot,
    compliance_packs: params.compliance_packs,
    timeout_ms: numOr(params.timeout_ms, 8000),
    verify_tls: !!params.verify_tls,
  }
  if (params.scan_modes.includes('static')) {
    let iacFiles = null
    if (params.iac_files_json?.trim()) {
      try {
        const parsed = JSON.parse(params.iac_files_json)
        if (Array.isArray(parsed) && parsed.length) iacFiles = parsed
      } catch { /* ignore invalid JSON */ }
    }
    if (iacFiles) body.iac_files = iacFiles
    if (params.iac_content.trim()) {
      body.iac_content = params.iac_content
      body.iac_filename = params.iac_filename.trim() || 'input.tf'
      if (params.iac_type !== 'auto') body.iac_type = params.iac_type
    }
  }
  if (params.scan_modes.includes('repo') && params.repo_url.trim()) {
    body.repo_url = params.repo_url.trim()
    if (params.repo_ref.trim()) body.repo_ref = params.repo_ref.trim()
    if (params.repo_subdir.trim()) body.repo_subdir = params.repo_subdir.trim()
    body.max_files = numOr(params.max_files, 300)
  }
  // Only send framework/provider filters when narrowed (empty server-side = all).
  if (params.frameworks.length && params.frameworks.length < FRAMEWORKS.length) body.frameworks = params.frameworks
  if (params.providers.length && params.providers.length < PROVIDERS.length) body.providers = params.providers
  const skip = splitCsv(params.skip_policies)
  if (skip.length) body.skip_policies = skip
  const only = splitCsv(params.only_policies)
  if (only.length) body.only_policies = only
  const waivers = splitCsv(params.policy_waivers)
  if (waivers.length) body.policy_waivers = waivers
  const exp = splitCsv(params.exposure_paths)
  if (exp.length) body.exposure_paths = exp
  if (params.terraform_plan_json?.trim()) body.terraform_plan_json = params.terraform_plan_json.trim()
  if (params.gate_profile) body.gate_profile = params.gate_profile
  if (params.asset_tier && params.asset_tier !== 'tier3') body.asset_tier = params.asset_tier
  if (params.aws_cross_account_role_arn?.trim()) {
    body.aws_cross_account_role_arn = params.aws_cross_account_role_arn.trim()
    body.live_cloud_reconcile = true
  }
  if (params.aws_external_id?.trim()) body.aws_external_id = params.aws_external_id.trim()
  const regions = splitCsv(params.aws_regions)
  if (regions.length) body.aws_regions = regions
  if (params.k8s_api_server?.trim()) {
    body.k8s_api_server = params.k8s_api_server.trim()
    body.live_cloud_reconcile = true
  }
  if (params.k8s_token?.trim()) body.k8s_token = params.k8s_token.trim()
  if (params.k8s_namespace?.trim() && params.k8s_namespace !== 'default') {
    body.k8s_namespace = params.k8s_namespace.trim()
  }
  if (params.autopilot_create_pr) body.autopilot_create_pr = true
  if (params.git_repo_url?.trim()) body.git_repo_url = params.git_repo_url.trim()
  if (params.github_token?.trim()) body.github_token = params.github_token.trim()
  if (params.git_base_branch?.trim() && params.git_base_branch !== 'main') {
    body.git_base_branch = params.git_base_branch.trim()
  }
  return body
}

// ─── Control primitives ──────────────────────────────────────────────────────

function Section({ title, icon, accent = '#22d3ee', count, defaultOpen = true, children }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="rounded-xl border bg-[var(--table-surface)] overflow-hidden" style={{ borderColor: `${accent}22` }}>
      <button type="button" onClick={() => setOpen((o) => !o)} className="w-full flex items-center justify-between px-3 py-2.5 hover:bg-[var(--row-hover-bg)] transition-colors">
        <span className="flex items-center gap-2 text-[11px] font-mono uppercase tracking-[0.18em] font-semibold" style={{ color: accent }}>
          <span>{icon}</span>
          {title}
          {count != null && <span className="text-[var(--text-disabled)] normal-case tracking-normal">· {count}</span>}
        </span>
        <span className={`text-[var(--text-muted)] text-xs transition-transform ${open ? 'rotate-90' : ''}`}>▶</span>
      </button>
      {open && <div className="px-3 pb-3 pt-1 space-y-3 border-t border-[var(--border-subtle)]">{children}</div>}
    </div>
  )
}
function Hint({ children }) {
  if (!children) return null
  return <span className="block text-[9px] font-mono text-[var(--text-disabled)] mt-0.5 leading-snug">{children}</span>
}
function Num({ label, value, onChange, min, max, step, hint }) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{label}</span>
      <input type="number" min={min} max={max} step={step} value={value} onChange={(e) => onChange(e.target.value)} className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-sm text-white font-mono focus:outline-none focus:border-cyan-400/40" />
      <Hint>{hint}</Hint>
    </label>
  )
}
function Sel({ label, value, onChange, options, hint }) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)} className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-sm text-white focus:outline-none focus:border-cyan-400/40">
        {options.map((o) => <option key={o} value={o}>{o}</option>)}
      </select>
      <Hint>{hint}</Hint>
    </label>
  )
}
function Txt({ label, value, onChange, placeholder, hint, type = 'text' }) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{label}</span>
      <input type={type} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-sm text-white font-mono placeholder-white/20 focus:outline-none focus:border-cyan-400/40" />
      <Hint>{hint}</Hint>
    </label>
  )
}
function Area({ label, value, onChange, placeholder, rows = 3, hint, mono = true }) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{label}</span>
      <textarea rows={rows} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} className={`w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-xs text-white ${mono ? 'font-mono' : ''} placeholder-white/20 focus:outline-none focus:border-cyan-400/40 resize-y`} />
      <Hint>{hint}</Hint>
    </label>
  )
}
function Toggle({ label, value, onChange, hint }) {
  return (
    <div className="flex items-start justify-between gap-3 py-0.5">
      <div className="min-w-0">
        <span className="text-[11px] font-mono text-[var(--text-secondary)]">{label}</span>
        <Hint>{hint}</Hint>
      </div>
      <button type="button" role="switch" aria-checked={value} onClick={() => onChange(!value)} className={`relative shrink-0 mt-0.5 w-9 h-5 rounded-full transition-all ${value ? 'bg-cyan-500/40' : 'bg-[var(--scrim)] border border-[var(--border-default)]'}`}>
        <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all ${value ? 'left-[18px]' : 'left-0.5'}`} />
      </button>
    </div>
  )
}
function Chips({ options, selected, onToggle, render }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {options.map((o) => {
        const id = typeof o === 'string' ? o : o.id
        const on = selected.includes(id)
        return (
          <button key={id} type="button" onClick={() => onToggle(id)} className={`text-[10px] font-mono px-2 py-1 rounded-md border transition-all ${on ? 'bg-cyan-500/15 border-cyan-400/50 text-cyan-200' : 'border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-secondary)]'}`}>
            {render ? render(o) : id}
          </button>
        )
      })}
    </div>
  )
}

// ─── Result visualization ────────────────────────────────────────────────────

function ScoreGauge({ score, grade, blast }) {
  const pct = Math.min(100, Math.max(0, score ?? 0))
  const color = pct >= 75 ? '#ef4444' : pct >= 50 ? '#f97316' : pct >= 25 ? '#f59e0b' : '#10b981'
  return (
    <div className="relative w-36 h-36 mx-auto">
      <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
        <circle cx="50" cy="50" r="42" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8" />
        <circle cx="50" cy="50" r="42" fill="none" stroke={color} strokeWidth="8" strokeDasharray={`${pct * 2.64} 264`} strokeLinecap="round" style={{ filter: `drop-shadow(0 0 8px ${color}80)` }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold text-white">{grade ?? '—'}</span>
        <span className="text-[9px] font-mono text-[var(--text-muted)] uppercase tracking-widest">risk {pct}</span>
        {blast > 1 && <span className="text-[8px] font-mono text-rose-300/80 mt-0.5">×{blast.toFixed(2)} blast</span>}
      </div>
    </div>
  )
}
function MetricTile({ label, value, accent = '#22d3ee' }) {
  return (
    <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4" style={{ boxShadow: `inset 0 1px 0 ${accent}20` }}>
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)] mb-1">{label}</p>
      <p className="text-2xl font-bold text-white">{value ?? '—'}</p>
    </div>
  )
}
function AttackPathCard({ chain }) {
  const sev = chain.severity || 'critical'
  const mitre = Array.isArray(chain.mitre_path) ? chain.mitre_path : []
  return (
    <div className="rounded-xl border p-4 space-y-2" style={{ borderColor: `${SEV_COLOR[sev]}44`, background: `${SEV_COLOR[sev]}08` }}>
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="text-[9px] font-mono uppercase tracking-widest" style={{ color: SEV_COLOR[sev] }}>{chain.id}</p>
          <p className="text-sm font-semibold text-white mt-0.5 leading-snug">{chain.title}</p>
        </div>
        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded uppercase shrink-0" style={{ color: SEV_COLOR[sev], background: `${SEV_COLOR[sev]}1a` }}>{sev}</span>
      </div>
      {mitre.length > 0 && (
        <div className="flex flex-wrap items-center gap-1">
          {mitre.map((m, i) => (
            <React.Fragment key={m}>
              {i > 0 && <span className="text-[var(--text-disabled)] text-[10px]">→</span>}
              <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[var(--row-hover-bg)] text-cyan-200/80">{m}</span>
            </React.Fragment>
          ))}
        </div>
      )}
      {Array.isArray(chain.matched_policies) && chain.matched_policies.length > 0 && (
        <p className="text-[10px] font-mono text-[var(--text-muted)] leading-relaxed">
          <span className="text-[var(--text-disabled)]">Correlated: </span>{chain.matched_policies.join(' · ')}
        </p>
      )}
      {chain.remediation && <p className="text-[11px] text-emerald-200/70 leading-relaxed">{chain.remediation}</p>}
    </div>
  )
}
function SeverityBars({ bySeverity }) {
  const total = SEVERITIES.reduce((a, s) => a + (bySeverity?.[s] || 0), 0) || 1
  return (
    <div className="space-y-1.5">
      {['critical', 'high', 'medium', 'low', 'info'].map((s) => {
        const n = bySeverity?.[s] || 0
        return (
          <div key={s} className="flex items-center gap-2">
            <span className="w-16 text-[10px] font-mono uppercase" style={{ color: SEV_COLOR[s] }}>{s}</span>
            <div className="flex-1 h-2 rounded-full bg-[var(--row-hover-bg)] overflow-hidden">
              <div className="h-full rounded-full" style={{ width: `${(n / total) * 100}%`, background: SEV_COLOR[s] }} />
            </div>
            <span className="w-8 text-right text-[11px] font-mono text-[var(--text-secondary)]">{n}</span>
          </div>
        )
      })}
    </div>
  )
}
function ComplianceCard({ pack }) {
  const failed = pack.controls_failed ?? 0
  const ok = pack.status === 'pass'
  return (
    <div className="rounded-lg border bg-[var(--table-surface)] p-3" style={{ borderColor: ok ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)' }}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-bold text-white">{pack.pack}</span>
        <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded ${ok ? 'text-emerald-300 bg-emerald-500/10' : 'text-rose-300 bg-rose-500/10'}`}>{ok ? 'PASS' : 'FAIL'}</span>
      </div>
      <p className="text-[10px] font-mono text-[var(--text-muted)] mt-1">{failed} failed · {pack.controls_covered ?? 0} covered</p>
      {Array.isArray(pack.failed_controls) && pack.failed_controls.length > 0 && (
        <p className="text-[9px] font-mono text-[var(--text-disabled)] mt-1 leading-snug break-words">{pack.failed_controls.slice(0, 6).join(', ')}{pack.failed_controls.length > 6 ? '…' : ''}</p>
      )}
    </div>
  )
}
function FrameworkCoverage({ coverage }) {
  const rows = coverage?.frameworks || []
  if (!rows.length) return null
  return (
    <div className="space-y-1.5">
      {rows.map((r) => (
        <div key={r.framework} className="flex items-center gap-2">
          <span className="w-24 text-[10px] font-mono text-[var(--text-tertiary)] truncate">{r.framework}</span>
          <div className="flex-1 h-2 rounded-full bg-[var(--row-hover-bg)] overflow-hidden">
            <div className="h-full rounded-full bg-violet-500/70" style={{ width: `${r.hit_rate_pct || 0}%` }} />
          </div>
          <span className="text-[10px] font-mono text-[var(--text-muted)] w-20 text-right">{r.policies_triggered}/{r.policies_total}</span>
        </div>
      ))}
    </div>
  )
}
function PolicyCatalog({ catalog, query, onQuery }) {
  const list = Array.isArray(catalog) ? catalog : []
  const q = query.trim().toLowerCase()
  const filtered = q ? list.filter((p) => `${p.id} ${p.title} ${p.framework}`.toLowerCase().includes(q)) : list
  const triggered = filtered.filter((p) => p.triggered)
  return (
    <div className="space-y-2">
      <input value={query} onChange={(e) => onQuery(e.target.value)} placeholder="Search policy id, title, framework…" className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-xs text-white font-mono placeholder-white/25" />
      <p className="text-[9px] font-mono text-[var(--text-muted)]">{triggered.length} triggered · {filtered.length} shown · {list.length} total</p>
      <div className="max-h-52 overflow-auto space-y-1 pr-1">
        {filtered.slice(0, 120).map((p) => (
          <div key={p.id} className={`flex items-center justify-between gap-2 rounded px-2 py-1 text-[10px] font-mono ${p.triggered ? 'bg-rose-500/10 border border-rose-500/20' : 'bg-[var(--row-hover-bg)] border border-[var(--border-subtle)]'}`}>
            <span className="text-[var(--text-secondary)] truncate">{p.id}</span>
            <span className="shrink-0 uppercase" style={{ color: SEV_COLOR[p.severity] || '#94a3b8' }}>{p.severity}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
function FindingCard({ f }) {
  const [open, setOpen] = useState(false)
  const sev = f.severity || 'info'
  return (
    <div className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] overflow-hidden">
      <button type="button" onClick={() => setOpen((o) => !o)} className="w-full text-left px-3 py-2 hover:bg-[var(--row-hover-bg)] transition-colors">
        <div className="flex items-start gap-2">
          <span className="font-mono text-[10px] px-1.5 py-0.5 rounded shrink-0 uppercase" style={{ color: SEV_COLOR[sev], background: `${SEV_COLOR[sev]}1a` }}>{sev}</span>
          <span className="min-w-0 flex-1">
            <span className="text-[12px] text-[var(--text-primary)] block leading-snug">{f.title}</span>
            <span className="text-[10px] font-mono text-[var(--text-muted)] block truncate">{f.location || f.file} {f.resource ? `· ${f.resource}` : ''}</span>
          </span>
          <span className="text-[var(--text-disabled)] text-xs">{open ? '−' : '+'}</span>
        </div>
      </button>
      {open && (
        <div className="px-3 pb-3 space-y-2 border-t border-[var(--border-subtle)] text-[11px]">
          <p className="text-[var(--text-tertiary)] leading-relaxed mt-2">{f.description}</p>
          <div className="flex flex-wrap gap-1.5">
            {f.framework && <Badge>{f.framework}</Badge>}
            {f.provider && <Badge>{f.provider}</Badge>}
            {f.mitre_attack && <Badge>{f.mitre_attack}</Badge>}
            {f.cwe && <Badge>{f.cwe}</Badge>}
          </div>
          {f.remediation && (
            <div>
              <p className="text-[9px] font-mono uppercase text-emerald-400/70">Remediation</p>
              <p className="text-[var(--text-tertiary)] leading-relaxed">{f.remediation}</p>
            </div>
          )}
          {f.code_fix && (
            <pre className="rounded-lg bg-[var(--scrim)] border border-emerald-500/20 p-2 text-[10px] font-mono text-emerald-300/80 overflow-auto whitespace-pre-wrap">{f.code_fix}</pre>
          )}
          {Array.isArray(f.compliance) && f.compliance.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {f.compliance.map((c) => <span key={c} className="text-[8px] font-mono px-1 py-0.5 rounded bg-[var(--row-hover-bg)] text-[var(--text-muted)]">{c}</span>)}
            </div>
          )}
          {Array.isArray(f.references) && f.references.length > 0 && (
            <div className="flex flex-col gap-0.5">
              {f.references.filter((r) => r.startsWith('http')).slice(0, 3).map((r) => (
                <a key={r} href={r} target="_blank" rel="noreferrer" className="text-[9px] font-mono text-cyan-400/60 hover:text-cyan-300 truncate">{r}</a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
function MitreRollup({ rows }) {
  if (!Array.isArray(rows) || !rows.length) return null
  return (
    <div className="flex flex-wrap gap-1.5">
      {rows.slice(0, 12).map((r) => (
        <span key={r.technique} className="text-[9px] font-mono px-2 py-1 rounded border border-[var(--border-default)] bg-[var(--table-surface)]" style={{ color: SEV_COLOR[r.max_severity] || '#94a3b8' }}>
          {r.technique} · {r.findings}
        </span>
      ))}
    </div>
  )
}
function ExecutiveBanner({ summary }) {
  const ex = summary?.executive_summary
  if (!ex?.narrative) return null
  return (
    <div className="rounded-2xl border border-cyan-500/25 bg-cyan-950/20 px-4 py-3">
      <p className="text-[10px] font-mono uppercase tracking-widest text-cyan-300/70 mb-1">{summary?.gate_profile ? `Gate: ${summary.gate_profile}` : 'Executive Posture'}</p>
      <p className="text-sm text-[var(--text-secondary)] leading-relaxed">{ex.narrative}</p>
    </div>
  )
}
function RiskHeatmap({ heatmap }) {
  const rows = heatmap?.rows
  if (!Array.isArray(rows) || !rows.length) return null
  return (
    <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4 overflow-x-auto">
      <p className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-3">Risk Heatmap (framework × severity)</p>
      <table className="w-full text-[10px] font-mono">
        <thead>
          <tr className="text-[var(--text-muted)]">
            <th className="text-left py-1 pr-2">Framework</th>
            {['critical', 'high', 'medium', 'low'].map((s) => <th key={s} className="px-2 py-1 uppercase" style={{ color: SEV_COLOR[s] }}>{s}</th>)}
            <th className="px-2 py-1">Σ</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.framework} className="border-t border-[var(--border-subtle)]">
              <td className="py-1 pr-2 text-[var(--text-secondary)]">{r.framework}</td>
              {['critical', 'high', 'medium', 'low'].map((s) => (
                <td key={s} className="px-2 py-1 text-center" style={{ background: r[s] ? `${SEV_COLOR[s]}18` : 'transparent', color: SEV_COLOR[s] }}>{r[s] || 0}</td>
              ))}
              <td className="px-2 py-1 text-[var(--text-tertiary)] text-center">{r.total}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
function CompliancePlaybooks({ playbooks }) {
  if (!Array.isArray(playbooks) || !playbooks.length) return null
  return (
    <div className="rounded-2xl border border-emerald-500/20 bg-emerald-950/10 p-4 space-y-2">
      <p className="text-[10px] font-mono uppercase tracking-widest text-emerald-300/80">Compliance Remediation Playbooks</p>
      <div className="max-h-52 overflow-auto space-y-2 pr-1">
        {playbooks.slice(0, 15).map((pb, i) => (
          <div key={`${pb.control}-${i}`} className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] p-2">
            <p className="text-[10px] font-mono text-emerald-200/90">{pb.pack} · {pb.control} <span className="text-[var(--text-muted)]">({pb.findings_linked} linked)</span></p>
            <ul className="mt-1 space-y-0.5">
              {(pb.steps || []).slice(0, 3).map((step, j) => (
                <li key={j} className="text-[9px] font-mono text-[var(--text-muted)] leading-snug">• {step}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  )
}
function InteractiveAttackGraph({ chains }) {
  if (!Array.isArray(chains) || !chains.length) return null
  const w = Math.min(720, chains.length * 200 + 80)
  const h = chains.length * 72 + 40
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full max-h-48 rounded-lg border border-[var(--border-default)] bg-[var(--bg-3)]" role="img" aria-label="Attack path graph">
      {chains.map((c, ci) => {
        const y = 24 + ci * 72
        const sev = c.severity || 'critical'
        const color = SEV_COLOR[sev] || '#ef4444'
        const mitre = c.mitre_path || []
        return (
          <g key={c.id}>
            <text x="8" y={y - 6} fill={color} fontSize="8" fontFamily="monospace">{c.id}</text>
            {mitre.map((m, mi) => {
              const x = 12 + mi * 88
              return (
                <g key={`${c.id}-${m}`}>
                  <rect x={x} y={y} width="72" height="22" rx="4" fill={`${color}22`} stroke={color} strokeWidth="0.5" />
                  <text x={x + 36} y={y + 14} fill="#e2e8f0" fontSize="7" fontFamily="monospace" textAnchor="middle">{m}</text>
                  {mi > 0 && <line x1={x - 14} y1={y + 11} x2={x} y2={y + 11} stroke="#64748b" strokeWidth="1" markerEnd="url(#arrow)" />}
                </g>
              )
            })}
          </g>
        )
      })}
      <defs>
        <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
          <path d="M0,0 L6,3 L0,6 Z" fill="#64748b" />
        </marker>
      </defs>
    </svg>
  )
}
function ReadinessPanel({ readiness }) {
  if (!readiness) return null
  const score = readiness.readiness_score ?? 0
  const color = score >= 70 ? '#10b981' : score >= 40 ? '#f59e0b' : '#ef4444'
  return (
    <div className="rounded-2xl border border-violet-500/25 bg-violet-950/15 p-4">
      <p className="text-[10px] font-mono uppercase tracking-widest text-violet-300/80 mb-3">Operational Readiness</p>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <MetricTile label="Readiness" value={`${score}/100`} accent={color} />
        <MetricTile label="Fixability" value={`${readiness.fixability_pct ?? 0}%`} accent="#22d3ee" />
        <MetricTile label="Auto-fixes" value={readiness.automated_fixes_available ?? 0} accent="#a855f7" />
        <MetricTile label="Est. hours" value={readiness.estimated_remediation_hours ?? '—'} accent="#f97316" />
      </div>
    </div>
  )
}
function CisScorecard({ scorecard }) {
  const packs = scorecard?.packs
  if (!Array.isArray(packs) || !packs.length) return null
  return (
    <div className="rounded-2xl border border-emerald-500/20 bg-emerald-950/10 p-4 space-y-2">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[10px] font-mono uppercase tracking-widest text-emerald-300/80">CIS / Compliance Scorecard</p>
        <span className="text-sm font-bold text-emerald-200">{scorecard.overall_pass_pct ?? 0}% · {scorecard.maturity ?? '—'}</span>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        {packs.map((p) => (
          <div key={p.pack} className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] p-2">
            <p className="text-[10px] font-bold text-white">{p.pack}</p>
            <p className="text-[9px] font-mono text-[var(--text-muted)]">{p.pass_pct}% pass · {p.controls_failed} failed</p>
          </div>
        ))}
      </div>
    </div>
  )
}
function HipaaReportPanel({ report }) {
  if (!report?.safeguard_families) return null
  return (
    <div className="rounded-2xl border border-teal-500/25 bg-teal-950/15 p-4 space-y-2">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <p className="text-[10px] font-mono uppercase tracking-widest text-teal-300/80">HIPAA 164.312 Safeguards</p>
        <span className={`text-[9px] font-mono px-2 py-0.5 rounded-full border ${report.baa_ready ? 'border-emerald-400/40 text-emerald-300' : 'border-rose-400/40 text-rose-300'}`}>
          {report.phi_risk ? 'ePHI-risk' : 'BAA-ready'} · {report.pass_pct ?? 0}%
        </span>
      </div>
      {report.narrative && <p className="text-[11px] text-[var(--text-tertiary)] leading-relaxed">{report.narrative}</p>}
    </div>
  )
}
function NistReportPanel({ report }) {
  if (!report?.control_families) return null
  return (
    <div className="rounded-2xl border border-sky-500/25 bg-sky-950/15 p-4 space-y-2">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <p className="text-[10px] font-mono uppercase tracking-widest text-sky-300/80">NIST 800-53 Control Families</p>
        <span className={`text-[9px] font-mono px-2 py-0.5 rounded-full border ${report.fedramp_ready ? 'border-emerald-400/40 text-emerald-300' : 'border-amber-400/40 text-amber-300'}`}>
          {report.fedramp_ready ? 'FedRAMP-ready' : 'gaps'} · {report.pass_pct ?? 0}%
        </span>
      </div>
      {report.narrative && <p className="text-[11px] text-[var(--text-tertiary)] leading-relaxed">{report.narrative}</p>}
    </div>
  )
}
function Iso27001ReportPanel({ report }) {
  if (!report?.annex_a_themes) return null
  return (
    <div className="rounded-2xl border border-indigo-500/25 bg-indigo-950/15 p-4 space-y-2">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <p className="text-[10px] font-mono uppercase tracking-widest text-indigo-300/80">ISO 27001 Annex A</p>
        <span className={`text-[9px] font-mono px-2 py-0.5 rounded-full border ${report.certification_ready ? 'border-emerald-400/40 text-emerald-300' : 'border-amber-400/40 text-amber-300'}`}>
          {report.certification_ready ? 'cert-ready' : 'gaps'} · {report.pass_pct ?? 0}%
        </span>
      </div>
      {report.narrative && <p className="text-[11px] text-[var(--text-tertiary)] leading-relaxed">{report.narrative}</p>}
    </div>
  )
}
function FedRampReportPanel({ report }) {
  if (!report?.families) return null
  return (
    <div className="rounded-2xl border border-amber-500/25 bg-amber-950/15 p-4 space-y-2">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <p className="text-[10px] font-mono uppercase tracking-widest text-amber-300/80">FedRAMP Moderate</p>
        <span className={`text-[9px] font-mono px-2 py-0.5 rounded-full border ${report.ato_ready ? 'border-emerald-400/40 text-emerald-300' : 'border-rose-400/40 text-rose-300'}`}>
          {report.ato_ready ? 'ATO-ready' : 'ATO-risk'} · {report.pass_pct ?? 0}%
        </span>
      </div>
      {report.narrative && <p className="text-[11px] text-[var(--text-tertiary)] leading-relaxed">{report.narrative}</p>}
    </div>
  )
}
function LiveBlastPanel({ liveBlast, realLiveRisk, staticRisk }) {
  const { t } = useTranslation()
  const [showMermaid, setShowMermaid] = useState(false)
  if (!liveBlast?.engine) return null
  const paths = liveBlast.proven_attack_paths || []
  const graph = liveBlast.graph || {}
  const blast = liveBlast.blast_radius || {}
  const proofs = liveBlast.permission_proofs || []
  const rbac = liveBlast.k8s_rbac_proofs || []
  const matches = liveBlast.live_reconcile_matches || []
  const status = liveBlast.live_status_counts || {}
  const mermaid = liveBlast.attack_path_mermaid || []
  const elevation = liveBlast.risk_elevation ?? 0
  const verification = liveBlast.verification_status || 'static_graph'
  return (
    <div className="rounded-2xl border border-rose-500/30 bg-rose-950/20 p-4 space-y-3">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <p className="text-[10px] font-mono uppercase tracking-widest text-rose-300/90">
          {t('iacSecurity.live_blast_panel_title', 'Sovereign Live Blast Engine')}
        </p>
        <span className="text-[9px] font-mono px-2 py-0.5 rounded-full border border-rose-400/40 text-rose-200">
          {t('iacSecurity.live_blast_risk', 'Live {{live}} / Static {{static}} (+{{elev}})', { live: realLiveRisk ?? '—', static: staticRisk ?? '—', elev: elevation })}
        </span>
      </div>
      <p className="text-[9px] font-mono text-[var(--text-muted)]">
        {t('iacSecurity.live_blast_verification', 'Verification')}: <span className="text-cyan-300/80">{verification}</span>
        {liveBlast.k8s_auth_source && <> · K8s: {liveBlast.k8s_auth_source}</>}
      </p>
      <div className="grid grid-cols-2 md:grid-cols-6 gap-2 text-[10px] font-mono">
        <div className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] p-2"><span className="text-[var(--text-muted)]">{t('iacSecurity.live_blast_nodes', 'Graph nodes')}</span><p className="text-white font-bold">{graph.node_count ?? 0}</p></div>
        <div className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] p-2"><span className="text-[var(--text-muted)]">{t('iacSecurity.live_blast_paths', 'Proven paths')}</span><p className="text-rose-300 font-bold">{liveBlast.proven_path_count ?? 0}</p></div>
        <div className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] p-2"><span className="text-[var(--text-muted)]">{t('iacSecurity.live_blast_score', 'Blast score')}</span><p className="text-amber-300 font-bold">{blast.blast_score ?? 0}</p></div>
        <div className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] p-2"><span className="text-[var(--text-muted)]">{t('iacSecurity.live_blast_live', 'Live confirmed')}</span><p className="text-emerald-300 font-bold">{liveBlast.live_confirmed_resources ?? status.confirmed ?? 0}</p></div>
        <div className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] p-2"><span className="text-[var(--text-muted)]">{t('iacSecurity.live_blast_irsa', 'IRSA bridges')}</span><p className="text-violet-300 font-bold">{liveBlast.cross_plane_bridges ?? 0}</p></div>
        <div className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] p-2"><span className="text-[var(--text-muted)]">{t('iacSecurity.live_blast_iam', 'IAM proofs')}</span><p className="text-cyan-300 font-bold">{proofs.length}</p></div>
      </div>
      {(status.not_deployed > 0 || status.contradicts_iac > 0) && (
        <div className="rounded-lg border border-orange-500/25 bg-orange-950/20 px-3 py-2 text-[10px] font-mono text-orange-200/90">
          {t('iacSecurity.live_blast_drift', 'Drift')}: {status.not_deployed ?? 0} not deployed · {status.contradicts_iac ?? 0} contradicts IaC
        </div>
      )}
      {rbac.length > 0 && (
        <div className="space-y-1 max-h-28 overflow-auto">
          <p className="text-[9px] font-mono text-violet-300/80 uppercase">{t('iacSecurity.k8s_rbac_prove', 'K8s SubjectAccessReview')} ({rbac.length})</p>
          {rbac.slice(0, 5).map((p, i) => (
            <p key={i} className="text-[9px] font-mono text-[var(--text-muted)] truncate">{p.subject} → {p.verb} {p.resource} ({p.allowed ? 'ALLOW' : 'DENY'})</p>
          ))}
        </div>
      )}
      {matches.length > 0 && (
        <div className="space-y-1 max-h-28 overflow-auto">
          <p className="text-[9px] font-mono text-emerald-300/80 uppercase">{t('iacSecurity.live_blast_reconcile', 'Live reconcile')} ({matches.length})</p>
          {matches.slice(0, 6).map((m, i) => (
            <p key={i} className="text-[9px] font-mono text-[var(--text-muted)] truncate">{m.live_status}: {m.evidence}</p>
          ))}
        </div>
      )}
      {liveBlast.autopilot?.patch_count > 0 && (
        <div className="rounded-lg border border-emerald-500/25 bg-emerald-950/20 px-3 py-2 space-y-1">
          <p className="text-[10px] font-mono text-emerald-300/90">{t('iacSecurity.autopilot', 'Auto-Pilot remediation')}: {liveBlast.autopilot.patch_count} patches</p>
          {(liveBlast.autopilot.patches || []).slice(0, 3).map((p, i) => (
            <p key={i} className="text-[9px] font-mono text-[var(--text-muted)] truncate">{p.toxic_class}: {p.file}</p>
          ))}
          {liveBlast.autopilot.pr_url && (
            <a href={liveBlast.autopilot.pr_url} target="_blank" rel="noreferrer" className="text-[9px] font-mono text-cyan-300 underline">
              {liveBlast.autopilot.pr_url}
            </a>
          )}
        </div>
      )}
      {paths.slice(0, 3).map((p) => (
        <div key={p.id} className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] px-3 py-2">
          <p className="text-[10px] font-bold text-[var(--text-secondary)]">{p.title}</p>
          <p className="text-[9px] font-mono text-amber-300/70">{p.toxic_class}</p>
          <p className="text-[9px] font-mono text-[var(--text-muted)] mt-1">{p.narrative}</p>
        </div>
      ))}
      {mermaid.length > 0 && (
        <div className="rounded-lg border border-cyan-500/20 bg-cyan-950/10 px-3 py-2">
          <button type="button" onClick={() => setShowMermaid((s) => !s)} className="text-[9px] font-mono text-cyan-300/80 hover:text-cyan-200">
            {showMermaid ? t('iacSecurity.live_blast_hide_mermaid', 'Hide mermaid') : t('iacSecurity.live_blast_show_mermaid', 'Show live path mermaid')}
          </button>
          {showMermaid && (
            <pre className="text-[8px] font-mono text-[var(--text-tertiary)] mt-2 whitespace-pre-wrap max-h-32 overflow-auto">{mermaid.join('\n\n')}</pre>
          )}
        </div>
      )}
    </div>
  )
}
function AuditPacketPanel({ packet }) {
  if (!packet?.packet_type) return null
  return (
    <div className="rounded-2xl border border-violet-500/30 bg-violet-950/20 p-4 space-y-2">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <p className="text-[10px] font-mono uppercase tracking-widest text-violet-300/80">Master Audit Packet</p>
        <span className={`text-[9px] font-mono px-2 py-0.5 rounded-full border ${packet.audit_ready ? 'border-emerald-400/40 text-emerald-300' : 'border-amber-400/40 text-amber-300'}`}>
          {packet.audit_ready ? 'AUDIT-READY' : 'GAPS'} · {packet.findings_total ?? 0} findings
        </span>
      </div>
      {packet.narrative && <p className="text-[11px] text-[var(--text-tertiary)] leading-relaxed">{packet.narrative}</p>}
      <p className="text-[9px] font-mono text-[var(--text-muted)]">SOC2 + PCI + HIPAA + NIST + ISO 27001 + FedRAMP + gate evidence — export below.</p>
    </div>
  )
}
function GateEvidencePanel({ evidence }) {
  if (!evidence?.evidence_type) return null
  return (
    <div className="rounded-2xl border border-cyan-500/25 bg-cyan-950/15 p-4 space-y-2">
      <p className="text-[10px] font-mono uppercase tracking-widest text-cyan-300/80">Gate Audit Evidence</p>
      <p className="text-[11px] text-[var(--text-tertiary)]">
        {evidence.gate_passed ? 'PASS' : 'FAIL'} · {evidence.blocking_findings_count ?? 0} blocking findings · {evidence.blocking_chains_count ?? 0} blocking chains · {evidence.waivers_applied ?? 0} waivers
      </p>
      <p className="text-[9px] font-mono text-[var(--text-muted)]">Deterministic CC8/PCI evidence packet for auditors — export JSON below.</p>
    </div>
  )
}
function PciReportPanel({ report }) {
  if (!report?.requirements) return null
  return (
    <div className="rounded-2xl border border-rose-500/25 bg-rose-950/15 p-4 space-y-3">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <p className="text-[10px] font-mono uppercase tracking-widest text-rose-300/80">PCI-DSS CDE Report</p>
        <span className={`text-[9px] font-mono px-2 py-0.5 rounded-full border ${report.cde_ready ? 'border-emerald-400/40 text-emerald-300' : 'border-rose-400/40 text-rose-300'}`}>
          {report.cde_ready ? 'CDE-ready' : 'CDE-risk'} · {report.pass_pct ?? 0}%
        </span>
      </div>
      {report.narrative && <p className="text-[11px] text-[var(--text-tertiary)] leading-relaxed">{report.narrative}</p>}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 max-h-40 overflow-auto pr-1">
        {report.requirements.slice(0, 10).map((r) => (
          <div key={r.requirement} className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] px-2 py-1.5">
            <p className="text-[9px] font-mono text-rose-200/90">Req {r.requirement}</p>
            <p className={`text-[10px] font-mono mt-0.5 ${status === 'pass' ? 'text-emerald-400/80' : 'text-rose-400/80'}`}>
              {r.findings_linked ?? 0} · {status}
            </p>
          </div>
        ))}
      </div>
    </div>
  )
}
function SupplyChainPanel({ findings, count }) {
  const rows = findings.filter((f) => f.framework === 'supply_chain' || String(f.policy_id || '').startsWith('WZ-SC-'))
  if (!rows.length && !count) return null
  return (
    <div className="rounded-2xl border border-amber-500/25 bg-amber-950/15 p-4 space-y-2">
      <p className="text-[10px] font-mono uppercase tracking-widest text-amber-300/80">Supply-Chain Correlation ({count ?? rows.length})</p>
      <p className="text-[9px] font-mono text-[var(--text-muted)]">Cross-file toxic combos: unpinned deps + secrets, mutable images across stack.</p>
      <div className="space-y-1 max-h-36 overflow-auto pr-1">
        {rows.slice(0, 10).map((f, i) => (
          <div key={`${f.policy_id}-${i}`} className="text-[10px] font-mono rounded px-2 py-1 bg-[var(--table-surface)] border border-amber-500/15">
            <span className="text-amber-200/90">{f.policy_id || f.title}</span>
            <span className="text-[var(--text-muted)] block truncate">{f.observed || f.description}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
function Soc2ReportPanel({ report }) {
  if (!report?.cc_families) return null
  const families = report.cc_families
  return (
    <div className="rounded-2xl border border-indigo-500/25 bg-indigo-950/15 p-4 space-y-3">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <p className="text-[10px] font-mono uppercase tracking-widest text-indigo-300/80">SOC2 Trust Services Report</p>
        <span className={`text-[9px] font-mono px-2 py-0.5 rounded-full border ${report.audit_ready ? 'border-emerald-400/40 text-emerald-300' : 'border-rose-400/40 text-rose-300'}`}>
          {report.audit_ready ? 'audit-ready' : 'audit-risk'} · {report.pass_pct ?? 0}%
        </span>
      </div>
      {report.narrative && <p className="text-[11px] text-[var(--text-tertiary)] leading-relaxed">{report.narrative}</p>}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
        {families.slice(0, 9).map((f) => (
          <div key={f.cc_family} className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] px-2 py-1.5">
            <p className="text-[9px] font-mono text-indigo-200/90">{f.cc_family} <span className="text-[var(--text-muted)]">{f.title}</span></p>
            <p className={`text-[10px] font-mono mt-0.5 ${f.status === 'pass' ? 'text-emerald-400/80' : 'text-rose-400/80'}`}>
              {f.findings_linked ?? 0} findings · {f.status}
            </p>
          </div>
        ))}
      </div>
    </div>
  )
}
function ReconcilePanel({ findings, count }) {
  const rows = findings.filter((f) => f.framework === 'reconcile' || String(f.policy_id || '').startsWith('WZ-RECON'))
  if (!rows.length && !count) return null
  return (
    <div className="rounded-2xl border border-violet-500/25 bg-violet-950/15 p-4 space-y-2">
      <p className="text-[10px] font-mono uppercase tracking-widest text-violet-300/80">Plan ↔ Static Reconciliation ({count ?? rows.length})</p>
      <p className="text-[9px] font-mono text-[var(--text-muted)] leading-snug">Detects when Terraform plan JSON and static HCL disagree — stale plans, module-expanded risk, or partial workspace scans.</p>
      <div className="space-y-1 max-h-36 overflow-auto pr-1">
        {rows.slice(0, 12).map((f, i) => (
          <div key={`${f.policy_id}-${i}`} className="text-[10px] font-mono rounded px-2 py-1 bg-[var(--table-surface)] border border-violet-500/15">
            <span className="text-violet-200/90">{f.policy_id || f.title}</span>
            <span className="text-[var(--text-muted)] block truncate">{f.observed || f.description}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
function DriftPanel({ findings, count }) {
  const drift = findings.filter((f) => f.framework === 'drift' || String(f.policy_id || '').startsWith('WZ-DRIFT'))
  if (!drift.length && !count) return null
  return (
    <div className="rounded-2xl border border-orange-500/25 bg-orange-950/15 p-4 space-y-2">
      <p className="text-[10px] font-mono uppercase tracking-widest text-orange-300/80">Posture Drift ({count ?? drift.length})</p>
      <div className="space-y-1 max-h-36 overflow-auto pr-1">
        {drift.slice(0, 12).map((f, i) => (
          <div key={`${f.policy_id}-${i}`} className="text-[10px] font-mono rounded px-2 py-1 bg-[var(--table-surface)] border border-orange-500/15">
            <span className="text-orange-200/90">{f.policy_id || f.title}</span>
            <span className="text-[var(--text-muted)] block truncate">{f.observed || f.description}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
function AttackPathMermaid({ source, chains }) {
  const [showSrc, setShowSrc] = useState(false)
  if (!source && !chains?.length) return null
  return (
    <div className="rounded-xl border border-cyan-500/20 bg-cyan-950/10 p-3 space-y-2">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[10px] font-mono uppercase tracking-widest text-cyan-300/70">Attack Path Graph (Mermaid)</p>
        <button type="button" onClick={() => setShowSrc((s) => !s)} className="text-[9px] font-mono text-[var(--text-muted)] hover:text-[var(--text-secondary)]">{showSrc ? 'hide source' : 'show mermaid'}</button>
      </div>
      <div className="flex flex-wrap gap-2">
        {(chains || []).map((c) => (
          <div key={c.id} className="rounded-lg border border-[var(--border-default)] bg-[var(--bg-2)] px-2 py-1.5 text-[9px] font-mono">
            <span className="text-rose-300/90 block">{c.id}</span>
            <span className="text-[var(--text-tertiary)] flex flex-wrap items-center gap-0.5 mt-0.5">
              {(c.mitre_path || []).map((m, i) => (
                <React.Fragment key={m}>
                  {i > 0 && <span className="text-[var(--text-disabled)]">→</span>}
                  <span className="text-cyan-200/80">{m}</span>
                </React.Fragment>
              ))}
            </span>
          </div>
        ))}
      </div>
      {showSrc && source && (
        <pre className="rounded-lg bg-[var(--scrim)] border border-[var(--border-default)] p-2 text-[9px] font-mono text-emerald-300/70 overflow-auto whitespace-pre-wrap max-h-40">{source}</pre>
      )}
    </div>
  )
}
function WaiversPanel({ waivers }) {
  if (!Array.isArray(waivers) || !waivers.length) return null
  return (
    <div className="rounded-2xl border border-amber-500/25 bg-amber-950/15 p-4 space-y-2">
      <p className="text-[10px] font-mono uppercase tracking-widest text-amber-300/80">Policy Waivers Applied ({waivers.length})</p>
      <div className="space-y-1 max-h-36 overflow-auto pr-1">
        {waivers.map((w, i) => (
          <div key={`${w.policy_id}-${i}`} className="text-[10px] font-mono rounded px-2 py-1 bg-[var(--table-surface)] border border-[var(--border-subtle)]">
            <span className="text-amber-200/90">{w.policy_id}</span>
            <span className="text-[var(--text-muted)]"> · {w.file || w.resource}</span>
            {w.reason && <span className="text-[var(--text-disabled)] block">{w.reason}</span>}
          </div>
        ))}
      </div>
    </div>
  )
}
function Badge({ children }) {
  return <span className="text-[8px] font-mono px-1.5 py-0.5 rounded bg-[var(--row-hover-bg)] text-[var(--text-muted)] uppercase tracking-wide">{children}</span>
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function IacSecurityCenter() {
  const { t } = useTranslation()
  const engine = ENGINES_BY_ID[ENGINE_ID]
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState('')
  const { postScan } = useCommandCenterScan(selectedClientId)
  const { integrations } = useClientIntegrations(selectedClientId)
  const [target, setTarget] = useState('')
  const [params, setParams] = useState(DEFAULT_PARAMS)
  useSyncHubScanParams(ENGINE_ID, params)

  useEffect(() => {
    if (!integrations) return
    setParams((prev) => prefillParamsForEngine(ENGINE_ID, integrations, prev))
  }, [integrations])
  const [running, setRunning] = useState(false)
  const [lines, setLines] = useState([])
  const [summary, setSummary] = useState(null)
  const [findings, setFindings] = useState([])
  const [sevFilter, setSevFilter] = useState('all')
  const [findingSearch, setFindingSearch] = useState('')
  const [lastScanAt, setLastScanAt] = useState(null)
  const [showPreview, setShowPreview] = useState(false)
  const [policyQuery, setPolicyQuery] = useState('')
  const esRef = useRef(null)

  const setField = useCallback((k, v) => setParams((p) => ({ ...p, [k]: v })), [])
  const toggleIn = useCallback((key, id) => setParams((p) => {
    const has = p[key].includes(id)
    return { ...p, [key]: has ? p[key].filter((x) => x !== id) : [...p[key], id] }
  }), [])

  const resetParams = useCallback(() => setParams({ ...DEFAULT_PARAMS, frameworks: [...FRAMEWORKS.map((f) => f.id)], providers: [...PROVIDERS], compliance_packs: [...PACKS], scan_modes: ['static'] }), [])

  const loadSample = useCallback((key) => {
    const s = SAMPLES[key]
    if (!s) return
    if (s.multi && Array.isArray(s.files)) {
      setParams((p) => ({
        ...p,
        scan_modes: Array.from(new Set([...p.scan_modes, 'static'])),
        iac_files_json: JSON.stringify(s.files, null, 2),
        iac_content: '',
        drift_analysis: true,
        cross_file_correlation: true,
      }))
      return
    }
    if (s.reconcile) {
      setParams((p) => ({
        ...p,
        scan_modes: Array.from(new Set([...p.scan_modes, 'static'])),
        iac_content: s.content,
        iac_filename: s.name,
        iac_type: s.type,
        terraform_plan_json: s.plan,
        iac_files_json: '',
      }))
      return
    }
    if (s.plan) {
      setParams((p) => ({
        ...p,
        scan_modes: Array.from(new Set([...p.scan_modes, 'static'])),
        terraform_plan_json: s.plan,
        iac_content: '',
        iac_files_json: '',
      }))
      return
    }
    setParams((p) => ({ ...p, scan_modes: Array.from(new Set([...p.scan_modes, 'static'])).filter((m) => m !== 'exposure' || p.scan_modes.includes('exposure')), iac_content: s.content, iac_filename: s.name, iac_type: s.type, iac_files_json: '' }))
  }, [])

  const effectiveTarget = useCallback(() => {
    if (params.scan_modes.includes('exposure') && target.trim()) return target.trim()
    if (params.scan_modes.includes('repo') && params.repo_url.trim()) return params.repo_url.trim()
    if (target.trim()) return target.trim()
    return 'inline-iac'
  }, [params.scan_modes, params.repo_url, target])

  const previewBody = useMemo(() => buildScanBody(params, selectedClientId || 0, effectiveTarget()), [params, selectedClientId, effectiveTarget])
  const paramCount = useMemo(() => {
    let c = 0
    const walk = (o) => { for (const v of Object.values(o)) { c += 1; if (Array.isArray(v)) c += v.length } }
    walk(previewBody)
    return c
  }, [previewBody])

  useEffect(() => {
    apiFetch('/api/clients').then((r) => (r.ok ? r.json() : [])).then((d) => { if (Array.isArray(d)) setClients(d) }).catch(() => {})
  }, [])

  useEffect(() => {
    if (!selectedClientId) return
    const c = clients.find((x) => String(x.id) === String(selectedClientId))
    if (!c) return
    let domains = c.domains
    if (typeof domains === 'string') { try { domains = JSON.parse(domains) } catch { domains = [] } }
    const first = Array.isArray(domains) ? (domains[0] || '') : ''
    if (first) setTarget(first.startsWith('http') ? first : `https://${first}`)
  }, [selectedClientId, clients])

  useEffect(() => () => { if (esRef.current) esRef.current.close() }, [])

  const appendLine = useCallback((m) => setLines((prev) => [...prev.slice(-400), m]), [])

  const canRun = useMemo(() => {
    if (!selectedClientId) return false
    if (params.scan_modes.length === 0) return false
    if (params.scan_modes.includes('static') && !params.iac_content.trim() && !params.iac_files_json.trim()) return params.scan_modes.length > 1
    if (params.scan_modes.includes('repo') && !params.repo_url.trim()) return params.scan_modes.length > 1
    if (params.scan_modes.includes('exposure') && !target.trim()) return params.scan_modes.length > 1
    return true
  }, [selectedClientId, params.scan_modes, params.iac_content, params.repo_url, target])

  const handleRun = useCallback(async () => {
    if (!canRun) return
    setRunning(true)
    setLines([])
    setSummary(null)
    setFindings([])
    appendLine(`[IaC] Launching scan — modes: ${params.scan_modes.join(', ')} (${paramCount} params)…`)
    const body = buildScanBody(params, selectedClientId, effectiveTarget())
    try {
      const { ok, data } = await postScan(body)
      if (!ok) { appendLine(`[ERROR] ${data.detail || 'scan failed'}`); setRunning(false); return }
      const jobId = data.job_id
      appendLine(`[IaC] Job queued: ${jobId}`)
      if (esRef.current) esRef.current.close()
      const es = openSseStream(`/api/telemetry/stream?job_id=${jobId}`)
      esRef.current = es
      es.onmessage = (ev) => {
        try {
          const p = JSON.parse(ev.data)
          if (p.message) appendLine(p.message)
          if (p.status === 'completed' || p.status === 'failed') {
            es.close()
            apiFetch(`/api/jobs/${jobId}`).then((jr) => (jr.ok ? jr.json() : null)).then((job) => {
              const res = job?.result_json || job?.result
              const all = res?.findings || []
              const sum = all.find((x) => x.category === 'iac_summary')
              const viol = all.filter((x) => x.category !== 'iac_summary')
              setSummary(sum?.iac_summary || null)
              setFindings(viol)
              setLastScanAt(new Date().toISOString())
              appendLine(`[IaC] Complete — ${viol.length} findings, risk ${sum?.iac_summary?.risk_score ?? '?'}/100 (grade ${sum?.iac_summary?.grade ?? '?'})`)
              setRunning(false)
            }).catch(() => setRunning(false))
          }
        } catch { /* ignore */ }
      }
      es.onerror = () => { es.close(); setRunning(false) }
    } catch (e) { appendLine(`[ERROR] ${e.message}`); setRunning(false) }
  }, [canRun, params, selectedClientId, effectiveTarget, paramCount, appendLine])

  const remediationQueue = useMemo(() => summary?.remediation_queue || [], [summary])
  const policyCatalog = useMemo(() => (Array.isArray(summary?.policy_catalog) ? summary.policy_catalog : []), [summary])
  const attackChains = useMemo(() => summary?.attack_chains || [], [summary])
  const policyFindings = useMemo(() => findings.filter((f) => f.category !== 'iac_attack_chain'), [findings])
  const shownFindings = useMemo(() => {
    let list = policyFindings
    if (sevFilter !== 'all') list = list.filter((f) => f.severity === sevFilter)
    const q = findingSearch.trim().toLowerCase()
    if (q) {
      list = list.filter((f) =>
        `${f.policy_id || ''} ${f.title || ''} ${f.file || ''} ${f.resource || ''} ${f.description || ''} ${f.framework || ''}`.toLowerCase().includes(q),
      )
    }
    return list
  }, [policyFindings, sevFilter, findingSearch])

  const exportFixBundle = useCallback(() => {
    const bundle = summary?.fix_bundle
    if (!bundle) return
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `iac-fixes-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }, [summary])

  const exportShellScript = useCallback(() => {
    const script = summary?.fix_bundle?.shell_script
    if (!script) return
    const blob = new Blob([script], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `iac-fixes-${Date.now()}.sh`
    a.click()
    URL.revokeObjectURL(url)
  }, [summary])

  const exportGateEvidence = useCallback(() => {
    const ev = summary?.gate_evidence
    if (!ev) return
    const blob = new Blob([JSON.stringify(ev, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `iac-gate-evidence-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }, [summary])

  const exportAuditPacket = useCallback(() => {
    const pkt = summary?.audit_packet
    if (!pkt) return
    const blob = new Blob([JSON.stringify(pkt, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `iac-audit-packet-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }, [summary])

  const exportBundle = useCallback(() => {
    const bundle = {
      engine: ENGINE_ID,
      summary,
      findings: policyFindings,
      attack_chains: attackChains,
      audit_packet: summary?.audit_packet || null,
      exported_at: new Date().toISOString(),
    }
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `iac-security-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }, [summary, policyFindings, attackChains])

  const loadLastScan = useCallback(async () => {
    try {
      const r = await apiFetch('/api/engines/history/iac_misconfig?limit=1')
      if (!r.ok) return
      const d = await r.json()
      const runs = Array.isArray(d) ? d : Array.isArray(d?.runs) ? d.runs : []
      const last = runs[0]
      if (!last) return
      const all = Array.isArray(last.findings) ? last.findings : []
      const sum = all.find((x) => x.category === 'iac_summary')
      const viol = all.filter((x) => x.category !== 'iac_summary')
      if (sum?.iac_summary || viol.length) {
        setSummary(sum?.iac_summary || null)
        setFindings(viol)
        setLastScanAt(last.completed_at || last.updated_at || last.created_at || null)
        appendLine(`[IaC] Loaded last run — ${viol.length} findings`)
      }
    } catch {
      /* no fabricated history */
    }
  }, [appendLine])

  const exportFindingsCsv = useCallback(() => {
    if (!shownFindings.length) return
    exportPolicyFindingsCsv(shownFindings, 'weissman-iac-findings')
  }, [shownFindings])

  const shellActions = (
    <ShellScanActions
      onRefresh={loadLastScan}
      onExport={exportFindingsCsv}
      refreshLoading={running}
      exportDisabled={!shownFindings.length}
    />
  )

  useEffect(() => {
    loadLastScan()
  }, [loadLastScan])

  return (
    <PageShell
      hideHubParams
      title={t('iacSecurity.title', 'IaC Security Center')}
      subtitle={t('iacSecurity.subtitle', '45-framework CNAPP IaC — complete compliance: SOC2/PCI/HIPAA/NIST/ISO/FedRAMP audit packet')}
      actions={shellActions}
    >
      <div className="space-y-6">
        {/* Hero */}
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="relative overflow-hidden rounded-2xl border border-cyan-500/30 bg-gradient-to-br from-cyan-950/40 via-black/60 to-sky-950/30 p-6">
          <div className="absolute inset-0 opacity-30" style={{ background: 'radial-gradient(circle at 20% 50%, rgba(34,211,238,0.35), transparent 50%), radial-gradient(circle at 85% 30%, rgba(56,189,248,0.2), transparent 50%)' }} />
          <div className="relative flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-2 flex-wrap">
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-cyan-400/40 text-cyan-300 bg-cyan-500/10 uppercase tracking-widest">CNAPP · IaC Scanning</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-emerald-400/30 text-emerald-300 bg-emerald-500/10 uppercase tracking-widest">{paramCount} {t('iacSecurity.live_params', 'live parameters')}</span>
                {summary && <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-[var(--border-strong)] text-[var(--text-tertiary)]">{summary.policies_available} policies</span>}
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">{engine?.label ? `${engine.label} — Security Center` : 'IaC Security Center'}</h1>
              <p className="text-sm text-[var(--text-tertiary)] mt-1 max-w-2xl leading-relaxed">{t('iacSecurity.hero_desc', 'Deterministic, agentless static analysis of your infrastructure code with deep policy coverage, secret detection, compliance posture and code-level remediation — inspired by Wiz, Checkov & tfsec.')}</p>
            </div>
            <Link to={`/engines/${ENGINE_ID}`} className="text-[11px] font-mono px-3 py-1.5 rounded-lg border border-[var(--border-strong)] text-[var(--text-tertiary)] hover:text-white hover:border-[var(--border-strong)] transition-colors">Engine Detail →</Link>
          </div>
        </motion.div>

        <div className="grid grid-cols-1 xl:grid-cols-[400px_1fr] gap-6 items-start">
          {/* ── Control column ── */}
          <div className="xl:sticky xl:top-4 space-y-3 xl:max-h-[calc(100dvh-2rem)] xl:overflow-y-auto pr-1">
            <div className="rounded-2xl border border-cyan-500/25 bg-gradient-to-b from-cyan-950/30 to-black/50 p-3">
              <div className="flex items-center justify-between mb-2 px-1">
                <h2 className="text-sm font-bold text-white tracking-tight flex items-center gap-2"><span>🎛️</span> {t('iacSecurity.control', 'Scan Control')}</h2>
                <button type="button" onClick={resetParams} className="text-[9px] font-mono uppercase tracking-wide px-2 py-1 rounded-md border border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-secondary)]">{t('common.reset', 'Reset')}</button>
              </div>

              <Section title={t('iacSecurity.sec_target', 'Target Binding')} icon="🎯" accent="#22d3ee" count={2}>
                <label className="block space-y-1">
                  <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{t('common.client', 'Client')}</span>
                  <select value={selectedClientId} onChange={(e) => setSelectedClientId(e.target.value)} className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-sm text-white focus:outline-none focus:border-cyan-400/40">
                    <option value="">—</option>
                    {clients.map((c) => <option key={c.id} value={c.id}>{c.name || c.id}</option>)}
                  </select>
                </label>
                <Txt label={t('iacSecurity.host_target', 'Host (exposure mode)')} value={target} onChange={setTarget} placeholder="https://target.example" hint="Probed for publicly leaked IaC files" />
              </Section>

              <Section title={t('iacSecurity.sec_mode', 'Scan Modes')} icon="🧭" accent="#38bdf8" count={params.scan_modes.length}>
                <div className="space-y-1.5">
                  {MODES.map((m) => {
                    const on = params.scan_modes.includes(m.id)
                    return (
                      <button key={m.id} type="button" onClick={() => toggleIn('scan_modes', m.id)} className={`flex items-center gap-2 text-left w-full rounded-lg border px-2.5 py-1.5 transition-all ${on ? 'bg-[var(--row-hover-bg)] border-cyan-400/50' : 'opacity-50 border-[var(--border-default)] hover:opacity-90'}`}>
                        <span>{m.icon}</span>
                        <span className="min-w-0 flex-1">
                          <span className="text-xs font-semibold text-white block">{m.label}</span>
                          <span className="text-[9px] text-[var(--text-muted)] block leading-tight">{m.desc}</span>
                        </span>
                        <span className={`text-[9px] font-mono ${on ? 'text-emerald-400' : 'text-[var(--text-disabled)]'}`}>{on ? 'ON' : 'OFF'}</span>
                      </button>
                    )
                  })}
                </div>
              </Section>

              {params.scan_modes.includes('static') && (
                <Section title={t('iacSecurity.sec_static', 'Inline IaC')} icon="📝" accent="#a855f7" count={3}>
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <span className="text-[9px] font-mono text-[var(--text-disabled)] uppercase">{t('iacSecurity.load_sample', 'Load sample')}:</span>
                    {Object.keys(SAMPLES).map((k) => (
                      <button key={k} type="button" onClick={() => loadSample(k)} className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-[var(--border-default)] text-cyan-300/70 hover:text-cyan-200 hover:border-cyan-400/40">{k}</button>
                    ))}
                  </div>
                  <Area label={t('iacSecurity.iac_content', 'IaC content')} value={params.iac_content} onChange={(v) => setField('iac_content', v)} rows={10} placeholder={'Paste Terraform / K8s / Dockerfile / CloudFormation / Compose / GH Actions / ARM…'} />
                  <Area label="Multi-file bundle (JSON)" value={params.iac_files_json} onChange={(v) => setField('iac_files_json', v)} rows={5} mono placeholder={'[{"name":"prod.tf","content":"..."},{"name":"staging.tf","content":"..."}]'} hint="Enables drift & cross-file correlation in static mode" />
                  <div className="grid grid-cols-2 gap-2">
                    <Txt label={t('iacSecurity.filename', 'Filename')} value={params.iac_filename} onChange={(v) => setField('iac_filename', v)} placeholder="main.tf" />
                    <Sel label={t('iacSecurity.iac_type', 'Type')} value={params.iac_type} onChange={(v) => setField('iac_type', v)} options={IAC_TYPES} hint="auto = detect" />
                  </div>
                </Section>
              )}

              {params.scan_modes.includes('repo') && (
                <Section title={t('iacSecurity.sec_repo', 'Repository')} icon="🐙" accent="#818cf8" count={4}>
                  <Txt label="GitHub URL" value={params.repo_url} onChange={(v) => setField('repo_url', v)} placeholder="https://github.com/org/repo" />
                  <div className="grid grid-cols-2 gap-2">
                    <Txt label="Ref / branch" value={params.repo_ref} onChange={(v) => setField('repo_ref', v)} placeholder="(default)" />
                    <Txt label="Subdir" value={params.repo_subdir} onChange={(v) => setField('repo_subdir', v)} placeholder="infra/" />
                  </div>
                  <Num label="Max files" value={params.max_files} onChange={(v) => setField('max_files', v)} min={1} max={2000} hint="Cap files fetched per scan" />
                </Section>
              )}

              <Section title={t('iacSecurity.sec_frameworks', 'Frameworks')} icon="🧱" accent="#34d399" count={params.frameworks.length} defaultOpen={false}>
                <Chips options={FRAMEWORKS} selected={params.frameworks} onToggle={(id) => toggleIn('frameworks', id)} render={(o) => `${o.icon} ${o.label}`} />
                <Hint>{t('iacSecurity.frameworks_hint', 'Secrets & exposure findings always included.')}</Hint>
              </Section>

              <Section title={t('iacSecurity.sec_providers', 'Cloud Providers')} icon="☁️" accent="#60a5fa" count={params.providers.length} defaultOpen={false}>
                <Chips options={PROVIDERS} selected={params.providers} onToggle={(id) => toggleIn('providers', id)} />
              </Section>

              <Section title={t('iacSecurity.sec_compliance', 'Compliance Packs')} icon="🛡️" accent="#f59e0b" count={params.compliance_packs.length} defaultOpen={false}>
                <Chips options={PACKS} selected={params.compliance_packs} onToggle={(id) => toggleIn('compliance_packs', id)} />
              </Section>

              <Section title={t('iacSecurity.sec_detection', 'Detection & Gate')} icon="🎚️" accent="#94a3b8" count={7} defaultOpen={false}>
                <Sel label="Gate profile" value={params.gate_profile} onChange={(v) => setField('gate_profile', v)} options={GATE_PROFILES} hint="Preset strictness (dev/ci/prod/pci)" />
                <Sel label="Asset tier" value={params.asset_tier} onChange={(v) => setField('asset_tier', v)} options={ASSET_TIERS} hint="tier1 = production-critical risk multiplier" />
                <div className="grid grid-cols-2 gap-2">
                  <Sel label="Min severity" value={params.min_severity} onChange={(v) => setField('min_severity', v)} options={SEVERITIES} hint="Drop below this rank" />
                  <Sel label="Fail (gate) at" value={params.fail_severity} onChange={(v) => setField('fail_severity', v)} options={SEVERITIES} hint="CI gate threshold" />
                </div>
                <Toggle label="Secret scanning" value={params.secret_scan} onChange={(v) => setField('secret_scan', v)} hint="AWS keys, private keys, tokens, high-entropy" />
                <Toggle label="Attack path synthesis" value={params.attack_path_synthesis} onChange={(v) => setField('attack_path_synthesis', v)} hint="Correlate real findings into multi-step breach chains (Wiz-class)" />
                <Toggle label="Resource graph" value={params.resource_graph} onChange={(v) => setField('resource_graph', v)} hint="Multi-file exposure↔datastore graph findings" />
                <Toggle label="Cross-file correlation" value={params.cross_file_correlation} onChange={(v) => setField('cross_file_correlation', v)} hint="Namespace↔NetworkPolicy gaps, secret+public combos across repo" />
                <Toggle label="Drift analysis" value={params.drift_analysis} onChange={(v) => setField('drift_analysis', v)} hint="Detect conflicting security settings for same resource across files" />
                <Toggle label="Live blast radius" value={params.live_blast} onChange={(v) => setField('live_blast', v)} hint="Graph + live AWS/K8s + IRSA cross-plane + blast quantification" />
                <Toggle label="IAM SimulatePrincipalPolicy" value={params.iam_simulate} onChange={(v) => setField('iam_simulate', v)} hint="S3 + RDS + SecretsManager + KMS via IAM Policy Simulator" />
                <Toggle label="K8s SubjectAccessReview" value={params.k8s_rbac_prove} onChange={(v) => setField('k8s_rbac_prove', v)} hint="Live SAR proves ServiceAccount can get/list secrets" />
                <Toggle label="Auto-Pilot remediation" value={params.autopilot} onChange={(v) => setField('autopilot', v)} hint="Generate code_fix patches from proven attack paths" />
                <Toggle label="Auto-Pilot create GitHub PR" value={params.autopilot_create_pr} onChange={(v) => setField('autopilot_create_pr', v)} hint="Requires github_token + git_repo_url — real GitHub API" />
                <Area label="Git repo URL (PR target)" value={params.git_repo_url} onChange={(v) => setField('git_repo_url', v)} rows={1} placeholder="https://github.com/org/infra-repo" />
                <Txt label="GitHub token (PR)" value={params.github_token} onChange={(v) => setField('github_token', v)} placeholder="ghp_…" hint="Used only for Auto-Pilot PR — never logged" type="password" />
                <Area label="Git base branch" value={params.git_base_branch} onChange={(v) => setField('git_base_branch', v)} rows={1} placeholder="main" />
                <Area label="AWS cross-account role ARN" value={params.aws_cross_account_role_arn} onChange={(v) => setField('aws_cross_account_role_arn', v)} rows={1} placeholder="arn:aws:iam::123456789012:role/WeissmanReadOnly" hint="Real STS AssumeRole for live cloud verification" />
                <Area label="AWS external ID" value={params.aws_external_id} onChange={(v) => setField('aws_external_id', v)} rows={1} placeholder="optional external ID" />
                <Area label="AWS regions" value={params.aws_regions} onChange={(v) => setField('aws_regions', v)} rows={1} placeholder="us-east-1, eu-west-1" hint="Comma-separated EC2/RDS regions" />
                <Area label="K8s API server" value={params.k8s_api_server} onChange={(v) => setField('k8s_api_server', v)} rows={1} placeholder="https://kubernetes.default.svc:443" hint="Live GET against Ingress/Service/SA/Secret/Workload" />
                <Area label="K8s bearer token" value={params.k8s_token} onChange={(v) => setField('k8s_token', v)} rows={1} placeholder="eyJhbGci..." hint="Service account or kubeconfig token — never logged" />
                <Area label="K8s default namespace" value={params.k8s_namespace} onChange={(v) => setField('k8s_namespace', v)} rows={1} placeholder="default" />
                <Toggle label="Include policy catalog" value={params.include_policy_catalog} onChange={(v) => setField('include_policy_catalog', v)} hint="Full policy browser payload in summary" />
                <Toggle label="Dedupe findings" value={params.dedupe} onChange={(v) => setField('dedupe', v)} />
                <Toggle label="Verify TLS" value={params.verify_tls} onChange={(v) => setField('verify_tls', v)} hint="Exposure/repo fetch" />
              </Section>

              <Section title={t('iacSecurity.sec_advanced', 'Advanced')} icon="⚗️" accent="#64748b" count={5} defaultOpen={false}>
                <Area label="Skip policy IDs" value={params.skip_policies} onChange={(v) => setField('skip_policies', v)} rows={2} placeholder="WZ-TF-AWS-KMS-001, …" />
                <Area label="Policy waivers" value={params.policy_waivers} onChange={(v) => setField('policy_waivers', v)} rows={2} placeholder="WZ-TF-AWS-S3-001, WZ-EXP-002" hint="Approved exceptions — excluded from gate, audited in summary" />
                <Area label="Only policy IDs" value={params.only_policies} onChange={(v) => setField('only_policies', v)} rows={2} placeholder="(empty = all)" />
                <Area label={t('iacSecurity.terraform_plan', 'Terraform plan JSON')} value={params.terraform_plan_json} onChange={(v) => setField('terraform_plan_json', v)} rows={4} mono placeholder={'Paste output of: terraform show -json plan.out'} hint={t('iacSecurity.plan_reconcile_hint', 'Detects gaps between HCL scan and plan JSON — block blind applies')} />
                <Area label="Extra exposure paths" value={params.exposure_paths} onChange={(v) => setField('exposure_paths', v)} rows={2} placeholder="/secret.tfstate" />
                <Num label="Timeout (ms)" value={params.timeout_ms} onChange={(v) => setField('timeout_ms', v)} min={500} max={30000} />
              </Section>

              <Section title={t('iacSecurity.sec_payload', 'Live Payload Preview')} icon="📦" accent="#64748b" count={paramCount} defaultOpen={false}>
                <button type="button" onClick={() => setShowPreview((s) => !s)} className="text-[10px] font-mono text-cyan-300/70 hover:text-cyan-200">{showPreview ? t('iacSecurity.hide_json', 'hide JSON') : t('iacSecurity.show_json', 'show exact request JSON')}</button>
                {showPreview && <pre className="max-h-60 overflow-auto rounded-lg bg-[var(--scrim)] border border-[var(--border-default)] p-2.5 text-[10px] font-mono text-emerald-300/80 leading-relaxed">{JSON.stringify(previewBody, null, 2)}</pre>}
              </Section>

              <button type="button" onClick={handleRun} disabled={running || !canRun} className="mt-3 w-full py-3 rounded-xl font-mono text-sm uppercase tracking-widest border transition-all disabled:opacity-40 disabled:cursor-not-allowed" style={{ borderColor: running ? 'rgba(34,211,238,0.5)' : 'rgba(34,211,238,0.6)', background: running ? 'rgba(34,211,238,0.12)' : 'rgba(34,211,238,0.22)', color: '#cffafe', boxShadow: running ? 'none' : '0 0 24px rgba(34,211,238,0.18)' }}>
                {running ? t('iacSecurity.scanning', 'Scanning…') : t('iacSecurity.scan', 'Run IaC Scan')}
              </button>
            </div>
          </div>

          {/* ── Results theatre ── */}
          <div className="space-y-6 min-w-0">
            {running && !summary && (
              <div className="rounded-2xl border border-cyan-500/20 bg-[var(--bg-2)] p-6 space-y-4">
                <p className="text-[11px] font-mono text-cyan-300/80 animate-pulse">{t('iacSecurity.running_note', 'Analyzing infrastructure code…')}</p>
                <SkeletonWidgetGrid count={4} />
                <SkeletonBar className="h-24 w-full" />
              </div>
            )}
            {lastScanAt && (
              <p className="text-[10px] font-mono text-[var(--text-muted)]">
                {t('iacSecurity.last_scan', 'Last scan')}: {new Date(lastScanAt).toLocaleString()}
              </p>
            )}
            <ExecutiveBanner summary={summary} />
            {summary?.readiness && <ReadinessPanel readiness={summary.readiness} />}
            {summary?.cis_scorecard && <CisScorecard scorecard={summary.cis_scorecard} />}
            {summary?.risk_heatmap && <RiskHeatmap heatmap={summary.risk_heatmap} />}
            {attackChains.length > 0 && (
              <div className="rounded-2xl border border-rose-500/40 bg-gradient-to-r from-rose-950/40 to-orange-950/20 px-4 py-3 flex items-center justify-between gap-3 flex-wrap">
                <p className="text-sm font-semibold text-rose-200">{t('iacSecurity.toxic_alert', 'Toxic combination detected')} — {attackChains.length} {t('iacSecurity.attack_paths', 'attack paths')}</p>
                <span className="text-[10px] font-mono text-rose-300/70">{t('iacSecurity.toxic_hint', 'Correlated policies indicate exploitable breach chains — prioritize remediation queue')}</span>
              </div>
            )}
            <div className="grid grid-cols-1 2xl:grid-cols-3 gap-6">
              <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] p-5 text-center">
                <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)] mb-3">{t('iacSecurity.posture', 'Security Posture')}</p>
                <ScoreGauge score={summary?.risk_score} grade={summary?.grade} blast={summary?.blast_radius_multiplier ?? 1} />
                {summary && (
                  <div className={`mt-3 inline-block text-[10px] font-mono px-2 py-1 rounded ${summary.gate?.passed ? 'text-emerald-300 bg-emerald-500/10' : 'text-rose-300 bg-rose-500/10'}`}>
                    {t('iacSecurity.gate', 'Gate')}: {summary.gate?.passed ? 'PASS' : `FAIL (${summary.gate?.blocking_findings} ≥ ${summary.gate?.fail_severity})`}
                  </div>
                )}
              </div>
              <div className="2xl:col-span-2 rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] p-5">
                <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)] mb-3">{t('iacSecurity.severity_breakdown', 'Severity Breakdown')}</p>
                <SeverityBars bySeverity={summary?.by_severity} />
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mt-4">
                  <MetricTile label="Findings" value={summary?.findings_total} accent="#ef4444" />
                  <MetricTile label="Files" value={summary?.files_scanned} accent="#22d3ee" />
                  <MetricTile label="Policies hit" value={summary ? `${summary.policies_triggered}/${summary.policies_available}` : '—'} accent="#a855f7" />
                  <MetricTile label="Attack paths" value={attackChains.length || '—'} accent="#f43f5e" />
                  <MetricTile label="Readiness" value={summary?.readiness?.readiness_score != null ? `${summary.readiness.readiness_score}` : '—'} accent="#8b5cf6" />
                  <MetricTile label="Drift" value={summary?.drift_findings ?? '—'} accent="#f97316" />
                  <MetricTile label="Reconcile" value={summary?.plan_reconcile_findings ?? '—'} accent="#8b5cf6" />
                  <MetricTile label="Supply" value={summary?.supply_chain_findings ?? '—'} accent="#f59e0b" />
                </div>
              </div>
            </div>

            {attackChains.length > 0 && (
              <div className="rounded-2xl border border-rose-500/25 bg-rose-950/20 p-4 space-y-3">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-rose-300/80">{t('iacSecurity.attack_paths', 'Attack Paths (toxic combinations)')}</p>
                  <span className="text-[9px] font-mono text-[var(--text-muted)]">{attackChains.length} {t('iacSecurity.chains_detected', 'chains from correlated policies')}</span>
                </div>
                <InteractiveAttackGraph chains={attackChains} />
                <AttackPathMermaid source={summary?.attack_path_mermaid} chains={attackChains} />
                <div className="grid gap-2">
                  {attackChains.map((c) => <AttackPathCard key={c.id} chain={c} />)}
                </div>
              </div>
            )}

            <WaiversPanel waivers={summary?.policy_waivers_applied} />
            <DriftPanel findings={policyFindings} count={summary?.drift_findings} />
            <ReconcilePanel findings={policyFindings} count={summary?.plan_reconcile_findings} />
            {summary?.soc2_report && <Soc2ReportPanel report={summary.soc2_report} />}
            {summary?.pci_report && <PciReportPanel report={summary.pci_report} />}
            {summary?.hipaa_report && <HipaaReportPanel report={summary.hipaa_report} />}
            {summary?.nist_report && <NistReportPanel report={summary.nist_report} />}
            {summary?.iso27001_report && <Iso27001ReportPanel report={summary.iso27001_report} />}
            {summary?.fedramp_report && <FedRampReportPanel report={summary.fedramp_report} />}
            {summary?.live_blast && (
              <LiveBlastPanel
                liveBlast={summary.live_blast}
                realLiveRisk={summary.real_live_risk_score}
                staticRisk={summary.static_risk_score}
              />
            )}
            {summary?.audit_packet && <AuditPacketPanel packet={summary.audit_packet} />}
            {summary?.gate_evidence && <GateEvidencePanel evidence={summary.gate_evidence} />}
            <SupplyChainPanel findings={policyFindings} count={summary?.supply_chain_findings} />
            {summary?.compliance_playbooks?.length > 0 && <CompliancePlaybooks playbooks={summary.compliance_playbooks} />}

            {summary?.framework_coverage && (
              <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
                <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)] mb-3">{t('iacSecurity.framework_coverage', 'Framework Policy Coverage')}</p>
                <FrameworkCoverage coverage={summary.framework_coverage} />
              </div>
            )}

            {remediationQueue.length > 0 && (
              <div className="rounded-2xl border border-emerald-500/20 bg-emerald-950/10 p-4 space-y-2">
                <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-emerald-300/80">{t('iacSecurity.remediation_queue', 'Prioritized Remediation Queue')}</p>
                <div className="max-h-48 overflow-auto space-y-1 pr-1">
                  {remediationQueue.slice(0, 20).map((r, i) => (
                    <div key={`${r.policy_id}-${i}`} className="flex items-start gap-2 text-[10px] font-mono rounded px-2 py-1 bg-[var(--table-surface)] border border-[var(--border-subtle)]">
                      <span className="text-[var(--text-disabled)] w-4">{i + 1}.</span>
                      <span className="min-w-0 flex-1">
                        <span className="text-[var(--text-secondary)] block">{r.policy_id} {r.in_attack_chain ? '⚡' : ''}</span>
                        <span className="text-[var(--text-muted)] truncate block">{r.file} · {r.resource}</span>
                      </span>
                      <span className="uppercase shrink-0" style={{ color: SEV_COLOR[r.severity] }}>{r.severity}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {policyCatalog.length > 0 && (
              <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
                <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)] mb-3">{t('iacSecurity.policy_catalog', 'Policy Catalog')}</p>
                <PolicyCatalog catalog={policyCatalog} query={policyQuery} onQuery={setPolicyQuery} />
              </div>
            )}

            {summary?.mitre_rollup?.length > 0 && (
              <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
                <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)] mb-3">{t('iacSecurity.mitre_rollup', 'MITRE ATT&CK Rollup')}</p>
                <MitreRollup rows={summary.mitre_rollup} />
              </div>
            )}

            {summary?.compliance && summary.compliance.length > 0 && (
              <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
                <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)] mb-3">{t('iacSecurity.compliance_posture', 'Compliance Posture')}</p>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                  {summary.compliance.map((p) => <ComplianceCard key={p.pack} pack={p} />)}
                </div>
              </div>
            )}

            {/* Telemetry */}
            <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--scrim)] overflow-hidden">
              <div className="px-4 py-2 border-b border-[var(--border-subtle)] text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest">{t('iacSecurity.telemetry', 'Scan Telemetry')}</div>
              <pre className="h-32 overflow-auto p-3 text-[10px] font-mono text-emerald-400/80 leading-relaxed">{lines.length ? lines.join('\n') : t('iacSecurity.awaiting', 'Awaiting scan…')}</pre>
            </div>

            {/* Findings */}
            <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4 space-y-3">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">
                  {shownFindings.length}/{policyFindings.length} {t('iacSecurity.findings', 'Findings')}
                </p>
                <div className="relative min-w-[200px] flex-1 max-w-xs">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-disabled)]" />
                  <input
                    type="search"
                    value={findingSearch}
                    onChange={(e) => setFindingSearch(e.target.value)}
                    placeholder={t('iacSecurity.findings_search', 'Search policy, file, resource…')}
                    className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] text-[11px] font-mono text-[var(--text-secondary)] placeholder-white/25 focus:outline-none focus:border-cyan-500/40"
                  />
                </div>
                <div className="flex gap-1 items-center flex-wrap">
                  {summary && (
                    <>
                      <button type="button" onClick={exportBundle} className="text-[9px] font-mono px-2 py-0.5 rounded border border-emerald-400/30 text-emerald-300/80 hover:bg-emerald-500/10">
                        {t('iacSecurity.export_bundle', 'Export remediation bundle')}
                      </button>
                      {summary.audit_packet && (
                        <button type="button" onClick={exportAuditPacket} className="text-[9px] font-mono px-2 py-0.5 rounded border border-violet-400/30 text-violet-300/80 hover:bg-violet-500/10">
                          {t('iacSecurity.export_audit_packet', 'Export audit packet')}
                        </button>
                      )}
                      {summary.gate_evidence && (
                        <button type="button" onClick={exportGateEvidence} className="text-[9px] font-mono px-2 py-0.5 rounded border border-cyan-400/30 text-cyan-300/80 hover:bg-cyan-500/10">
                          {t('iacSecurity.export_gate_evidence', 'Export gate evidence')}
                        </button>
                      )}
                      {summary.fix_bundle?.fix_count > 0 && (
                        <>
                          <button type="button" onClick={exportFixBundle} className="text-[9px] font-mono px-2 py-0.5 rounded border border-violet-400/30 text-violet-300/80 hover:bg-violet-500/10">
                            {t('iacSecurity.export_fixes', 'Export fix bundle')} ({summary.fix_bundle.fix_count})
                          </button>
                          {summary.fix_bundle?.shell_script && (
                            <button type="button" onClick={exportShellScript} className="text-[9px] font-mono px-2 py-0.5 rounded border border-cyan-400/30 text-cyan-300/80 hover:bg-cyan-500/10">
                              Export .sh script
                            </button>
                          )}
                        </>
                      )}
                    </>
                  )}
                  {['all', ...SEVERITIES].map((s) => (
                    <button key={s} type="button" onClick={() => setSevFilter(s)} className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase ${sevFilter === s ? 'border-cyan-400/50 text-cyan-200 bg-cyan-500/10' : 'border-[var(--border-default)] text-[var(--text-muted)]'}`}>{s}</button>
                  ))}
                </div>
              </div>
              <AnimatePresence>
                {shownFindings.length > 0 ? (
                  <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-1.5 max-h-[600px] overflow-auto pr-1">
                    {shownFindings.slice(0, 300).map((f, i) => <FindingCard key={`${f.policy_id}-${i}`} f={f} />)}
                  </motion.div>
                ) : (
                  <p className="text-[11px] text-[var(--text-disabled)] font-mono py-6 text-center">
                    {running
                      ? t('iacSecurity.running_note', 'Analyzing infrastructure code…')
                      : findingSearch.trim()
                        ? t('iacSecurity.no_findings_filtered', 'No findings match the current search and severity filters.')
                        : t('iacSecurity.no_findings', 'No findings yet — configure a scan and run.')}
                  </p>
                )}
              </AnimatePresence>
            </div>
          </div>
        </div>
      </div>
    </PageShell>
  )
}
