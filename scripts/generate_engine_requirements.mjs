#!/usr/bin/env node
/**
 * Derives per-engine + per-module onboarding requirements from live source (no hand-waving).
 * Outputs shared JSON consumed by Rust API and React onboarding wizard.
 */
import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')

function extractArray(name, text) {
  const m = text.match(new RegExp(`pub const ${name}: &\\[&str\\] = &\\[(.*?)\\];`, 's'))
  if (!m) throw new Error(`Missing array: ${name}`)
  return [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1])
}

const engineRs = fs.readFileSync(path.join(root, 'backend/weissman-core/src/models/engine.rs'), 'utf8')
const dispatchRs = fs.readFileSync(path.join(root, 'fingerprint_engine/src/engine_dispatch.rs'), 'utf8')
const scanRs = fs.readFileSync(path.join(root, 'fingerprint_engine/src/scan_routing.rs'), 'utf8')
const { ENGINES_REGISTRY } = await import(pathToFileURL(path.join(root, 'frontend/src/lib/enginesRegistry.js')).href)

const productionIds = extractArray('PRODUCTION_ENGINE_IDS', engineRs)
const agentRequired = new Set(extractArray('AGENT_REQUIRED_ENGINES', dispatchRs))

const AI_HEAVY = new Set([
  'semantic_ai_fuzz', 'ai_adversarial_redteam', 'llm_path_fuzz', 'ollama_fuzz',
  'http_feedback_fuzz', 'poe_synthesis', 'nexus_sovereign_swarm', 'llm_redteam',
  'llm_fuzzer', 'council_debate', 'feedback_fuzz', 'deep_fuzz',
])

const OAST_ENGINES = new Set(
  [...scanRs.matchAll(/engines:\s*&\["([^"]+)"\][\s\S]*?inject_oast:\s*true/g)].map((m) => m[1]),
)

const IAC_PATTERN = /^(iac_|pipeline$|terraform|terragrunt|helm_|k8s_container|container_registry|cicd_|sbom_|supply_chain)/

const AWS_PATTERN = /^(aws_|s3_|iam_|ec2_|lambda_|cloudformation|eks_|rds_|kms_|secrets_manager)/i
const GCP_PATTERN = /^(gcp_|gke_|cloud_sql|bigquery|gcs_)/i
const AZURE_PATTERN = /^(azure_|entra_|arm_|aad_)/i

const IDENTITY_PATTERN = /^(kerberos|saml|oauth|oidc|ldap|password_spray|ntlm|ad_|identity_|jwt_|mtls_)/i

const registryById = Object.fromEntries(ENGINES_REGISTRY.map((e) => [e.id, e]))

const REQUIREMENTS = {
  msa_acknowledged: {
    id: 'msa_acknowledged',
    scope: 'client',
    field: 'onboarding.msa_acknowledged',
    type: 'boolean',
    required: true,
    label_en: 'Written authorization (MSA/SOW) acknowledged',
    label_he: 'אישור הרשאה כתובה (MSA/SOW)',
    hint_en: 'Only onboard clients with explicit written authorization for security testing.',
    hint_he: 'קליטה רק עם הרשאה כתובה מפורשת לבדיקות אבטחה.',
  },
  emergency_contact: {
    id: 'emergency_contact',
    scope: 'client',
    field: 'onboarding.emergency_contact_phone',
    type: 'string',
    required: true,
    label_en: 'Emergency stop contact (phone)',
    label_he: 'איש קשר חירום לעצירת סריקה (טלפון)',
    hint_en: '24/7 number to halt scans immediately if needed.',
    hint_he: 'מספר זמין לעצירת סריקות מיידית.',
  },
  scope_domains: {
    id: 'scope_domains',
    scope: 'client',
    field: 'domains',
    type: 'string_list',
    required: true,
    label_en: 'Authorized domains',
    label_he: 'דומיינים מורשים',
    hint_en: 'Only assets in scope will be scanned.',
    hint_he: 'רק נכסים בהיקף ייסרקו.',
  },
  scope_ips: {
    id: 'scope_ips',
    scope: 'client',
    field: 'ip_ranges',
    type: 'string_list',
    required: false,
    label_en: 'Authorized IP ranges (CIDR)',
    label_he: 'טווחי IP מורשים (CIDR)',
    hint_en: 'Required for IP/OT/network segment engines.',
    hint_he: 'נדרש למנועי IP/OT/רשת.',
  },
  scope_exclusions: {
    id: 'scope_exclusions',
    scope: 'client',
    field: 'onboarding.exclusions',
    type: 'string_list',
    required: false,
    label_en: 'Exclusions (never scan)',
    label_he: 'חריגים (לעולם לא לסרוק)',
    hint_en: 'Payment gateways, prod DBs, third-party SaaS, etc.',
    hint_he: 'שערי תשלום, DB production, SaaS צד-ג׳.',
  },
  contact_email: {
    id: 'contact_email',
    scope: 'client',
    field: 'contact_email',
    type: 'email',
    required: true,
    label_en: 'Primary security contact email',
    label_he: 'אימייל איש קשר אבטחה',
  },
  aws_cross_account: {
    id: 'aws_cross_account',
    scope: 'client',
    fields: ['aws_cross_account_role_arn', 'aws_external_id'],
    type: 'cloud_aws',
    required: true,
    label_en: 'AWS cross-account role ARN + external ID',
    label_he: 'AWS cross-account role ARN + external ID',
    hint_en: 'AssumeRole for agentless AWS posture engines.',
    hint_he: 'AssumeRole למנועי AWS agentless.',
  },
  gcp_project: {
    id: 'gcp_project',
    scope: 'client',
    field: 'gcp_project_id',
    type: 'string',
    required: true,
    label_en: 'GCP project ID',
    label_he: 'מזהה פרויקט GCP',
  },
  azure_subscription: {
    id: 'azure_subscription',
    scope: 'client',
    fields: ['onboarding.azure_subscription_id', 'onboarding.azure_tenant_id'],
    type: 'cloud_azure',
    required: true,
    label_en: 'Azure subscription + tenant ID',
    label_he: 'Azure subscription + tenant ID',
  },
  ad_domain: {
    id: 'ad_domain',
    scope: 'client',
    field: 'onboarding.ad_domain',
    type: 'string',
    required: true,
    label_en: 'Active Directory domain (FQDN)',
    label_he: 'דומיין Active Directory (FQDN)',
    hint_en: 'For Kerberos, LDAP, password spray, identity engines.',
    hint_he: 'למנועי Kerberos, LDAP, identity.',
  },
  iac_repos: {
    id: 'iac_repos',
    scope: 'client',
    field: 'onboarding.repo_urls',
    type: 'url_list',
    required: true,
    label_en: 'IaC / pipeline repository URLs',
    label_he: 'כתובות repo ל-IaC / pipeline',
    hint_en: 'Git URLs for Terraform, Helm, K8s manifests, CI configs.',
    hint_he: 'Git ל-Terraform, Helm, K8s, CI.',
  },
  endpoint_agent: {
    id: 'endpoint_agent',
    scope: 'client',
    field: 'onboarding.agent_platforms',
    type: 'platform_list',
    required: true,
    label_en: 'Endpoint agent target platforms',
    label_he: 'פלטפורמות ל-Agent endpoint',
    hint_en: 'Install Weissman agent on each platform in scope after create.',
    hint_he: 'התקנת Agent Weissman על כל פלטפורמה בהיקף.',
  },
  industrial_ot: {
    id: 'industrial_ot',
    scope: 'client',
    fields: ['client_configs.industrial_ot_enabled', 'ip_ranges'],
    type: 'boolean',
    required: true,
    label_en: 'Industrial OT/ICS enabled + IP ranges',
    label_he: 'OT/ICS מופעל + טווחי IP',
    hint_en: 'Enable OT engines and provide OT network CIDRs.',
    hint_he: 'הפעלת מנועי OT ו-CIDR של רשת OT.',
  },
  llm_secops_endpoints: {
    id: 'llm_secops_endpoints',
    scope: 'client',
    field: 'onboarding.llm_secops.endpoints',
    type: 'url_list',
    required: false,
    label_en: 'Client LLM/chat API endpoints (optional)',
    label_he: 'נקודות קצה LLM/chat של הלקוח (אופציונלי)',
    hint_en: 'For llm_secops fuzz against customer RAG/chat APIs.',
    hint_he: 'ל-fuzz על RAG/chat APIs של הלקוח.',
  },
  tenant_llm: {
    id: 'tenant_llm',
    scope: 'tenant',
    config_key: 'llm_base_url',
    env: 'WEISSMAN_LLM_BASE_URL',
    type: 'tenant_config',
    required: true,
    label_en: 'Platform LLM endpoint (tenant)',
    label_he: 'LLM של הפלטפורמה (tenant)',
    hint_en: 'Required for AI red team, Council, semantic fuzz.',
    hint_he: 'נדרש ל-AI red team, Council, semantic fuzz.',
  },
  tenant_oast: {
    id: 'tenant_oast',
    scope: 'tenant',
    env: 'WEISSMAN_OAST_LISTENER_URL',
    type: 'tenant_env',
    required: true,
    label_en: 'OAST callback listener (tenant)',
    label_he: 'OAST callback listener (tenant)',
    hint_en: 'Out-of-band verification for blind SSRF/XSS/OAST engines.',
    hint_he: 'אימות OOB ל-SSRF/XSS blind.',
  },
  tenant_ai_entitlement: {
    id: 'tenant_ai_entitlement',
    scope: 'tenant',
    config_key: 'ai_heavy_entitled',
    type: 'tenant_config',
    required: true,
    label_en: 'AI-heavy entitlement enabled',
    label_he: 'Entitlement למנועי AI-heavy',
  },
}

const MODULES = {
  baseline_asm: {
    id: 'baseline_asm',
    label_en: 'Baseline ASM & Web (remote probes)',
    label_he: 'ASM + Web בסיס (remote probes)',
    requirements: ['msa_acknowledged', 'emergency_contact', 'contact_email', 'scope_domains', 'scope_exclusions'],
    engine_filter: (id, group, kind) => kind === 'real_probe' && !['cloud', 'ai'].includes(group) && !agentRequired.has(id),
  },
  cloud_aws: {
    id: 'cloud_aws',
    label_en: 'AWS cloud posture',
    label_he: 'AWS cloud posture',
    requirements: ['aws_cross_account', 'scope_domains'],
    engine_filter: (id) => AWS_PATTERN.test(id) || id.includes('aws'),
  },
  cloud_gcp: {
    id: 'cloud_gcp',
    label_en: 'GCP cloud posture',
    label_he: 'GCP cloud posture',
    requirements: ['gcp_project', 'scope_domains'],
    engine_filter: (id) => GCP_PATTERN.test(id) || id.includes('gcp'),
  },
  cloud_azure: {
    id: 'cloud_azure',
    label_en: 'Azure / Entra posture',
    label_he: 'Azure / Entra posture',
    requirements: ['azure_subscription', 'scope_domains'],
    engine_filter: (id) => AZURE_PATTERN.test(id) || id.includes('azure'),
  },
  identity_ad: {
    id: 'identity_ad',
    label_en: 'Identity & AD (Kerberos, SAML, OAuth)',
    label_he: 'Identity & AD',
    requirements: ['ad_domain', 'scope_domains'],
    engine_filter: (id, group) => group === 'crypto' || IDENTITY_PATTERN.test(id),
  },
  endpoint_agent: {
    id: 'endpoint_agent',
    label_en: 'Endpoint agent detections',
    label_he: 'Endpoint agent detections',
    requirements: ['endpoint_agent', 'scope_domains'],
    engine_filter: (id) => agentRequired.has(id),
  },
  iac_supply_chain: {
    id: 'iac_supply_chain',
    label_en: 'IaC, CI/CD & supply chain',
    label_he: 'IaC, CI/CD & supply chain',
    requirements: ['iac_repos', 'scope_domains'],
    engine_filter: (id, group) => IAC_PATTERN.test(id) || group === 'supply_chain',
  },
  industrial_ot: {
    id: 'industrial_ot',
    label_en: 'Industrial OT / ICS',
    label_he: 'Industrial OT / ICS',
    requirements: ['industrial_ot', 'scope_ips'],
    engine_filter: (id, group) => group === 'ot',
  },
  ai_redteam: {
    id: 'ai_redteam',
    label_en: 'AI / LLM red team',
    label_he: 'AI / LLM red team',
    requirements: ['tenant_llm', 'tenant_ai_entitlement', 'llm_secops_endpoints'],
    engine_filter: (id, group) => group === 'ai' || AI_HEAVY.has(id),
  },
  oast_blind: {
    id: 'oast_blind',
    label_en: 'Blind / OOB verification',
    label_he: 'Blind / OOB verification',
    requirements: ['tenant_oast'],
    engine_filter: (id) => OAST_ENGINES.has(id),
  },
}

function classifyKind(id) {
  if (agentRequired.has(id)) return 'agent_required'
  if (id === 'poe_synthesis') return 'special'
  return 'real_probe'
}

function requirementsForEngine(id) {
  const reg = registryById[id]
  const group = reg?.group || 'apt'
  const kind = classifyKind(id)
  const reqs = new Set(['scope_domains', 'contact_email'])

  if (kind === 'agent_required') reqs.add('endpoint_agent')
  if (AWS_PATTERN.test(id) || (group === 'cloud' && id.includes('aws'))) reqs.add('aws_cross_account')
  if (GCP_PATTERN.test(id) || (group === 'cloud' && id.includes('gcp'))) reqs.add('gcp_project')
  if (AZURE_PATTERN.test(id) || (group === 'cloud' && id.includes('azure'))) reqs.add('azure_subscription')
  if (IAC_PATTERN.test(id) || id === 'pipeline') reqs.add('iac_repos')
  if (IDENTITY_PATTERN.test(id) || group === 'crypto') reqs.add('ad_domain')
  if (group === 'ot') {
    reqs.add('scope_ips')
    if (!agentRequired.has(id)) reqs.add('industrial_ot')
  }
  if (group === 'ai' || AI_HEAVY.has(id)) {
    reqs.add('tenant_llm')
    reqs.add('tenant_ai_entitlement')
    reqs.add('llm_secops_endpoints')
  }
  if (OAST_ENGINES.has(id)) reqs.add('tenant_oast')
  if (group === 'network' && !agentRequired.has(id)) reqs.add('scope_ips')

  return [...reqs].sort()
}

const engines = {}
for (const id of productionIds) {
  const reg = registryById[id]
  engines[id] = {
    id,
    group: reg?.group || 'unknown',
    kind: classifyKind(id),
    label: reg?.label || id,
    requirements: requirementsForEngine(id),
  }
}

const moduleEngines = {}
for (const [modId, mod] of Object.entries(MODULES)) {
  moduleEngines[modId] = productionIds.filter((id) => {
    const reg = registryById[id]
    const group = reg?.group || 'apt'
    return mod.engine_filter(id, group, classifyKind(id))
  })
}

const out = {
  version: 1,
  generated_at: new Date().toISOString(),
  production_engine_count: productionIds.length,
  requirements: REQUIREMENTS,
  modules: Object.fromEntries(
    Object.entries(MODULES).map(([k, v]) => [
      k,
      {
        id: v.id,
        label_en: v.label_en,
        label_he: v.label_he,
        requirements: v.requirements,
        engine_count: moduleEngines[k]?.length || 0,
      },
    ]),
  ),
  engines,
}

const outPath = path.join(root, 'shared/engine_requirements.json')
fs.mkdirSync(path.dirname(outPath), { recursive: true })
fs.writeFileSync(outPath, `${JSON.stringify(out, null, 2)}\n`)
console.log(`Wrote ${outPath} (${productionIds.length} engines, ${Object.keys(MODULES).length} modules)`)
