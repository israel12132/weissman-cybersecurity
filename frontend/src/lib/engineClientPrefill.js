/**
 * Maps engine PARAM_DEFS keys → client integration fields for auto-prefill on EngineDetail.
 */
import { getEngineParams, ENGINE_COMMAND_CENTER_ROUTES } from './engineParamDefs.js'

function parseJsonList(raw) {
  if (Array.isArray(raw)) return raw
  if (typeof raw !== 'string' || !raw.trim()) return []
  try {
    const p = JSON.parse(raw)
    return Array.isArray(p) ? p : []
  } catch {
    return raw.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean)
  }
}

export function normalizeIntegrations(data) {
  if (!data) return null
  const ext = data.aws_external_id
  const gh = data.github_token
  const oastKey = data.oast_api_key
  return {
    ...data,
    aws_external_id: typeof ext === 'object' && ext?.masked ? ext.masked : (ext || ''),
    aws_external_id_configured: typeof ext === 'object' ? !!ext?.configured : !!ext,
    github_token: typeof gh === 'object' && gh?.masked ? gh.masked : (gh || ''),
    github_token_configured: typeof gh === 'object' ? !!gh?.configured : !!gh,
    oast_api_key: typeof oastKey === 'object' && oastKey?.masked ? oastKey.masked : (oastKey || ''),
    oast_api_key_configured: typeof oastKey === 'object' ? !!oastKey?.configured : !!oastKey,
    repo_urls: parseJsonList(data.repo_urls),
    domains: parseJsonList(data.domains),
    agent_platforms: parseJsonList(data.agent_platforms),
    llm_secops_endpoints: Array.isArray(data.llm_secops_endpoints) ? data.llm_secops_endpoints : [],
  }
}

const AWS_PATTERN = /^(aws_|s3_|iam_|ec2_|lambda_|eks_|rds_|kms_|secrets_manager|cloudformation|multi_cloud|cloud_posture)/i
const GCP_PATTERN = /^(gcp_|gke_|cloud_sql|bigquery|gcs_)/i
const AZURE_PATTERN = /^(azure_|entra_|arm_|aad_)/i
const IDENTITY_PATTERN = /^(kerberos|saml|oauth|oidc|ldap|password_spray|ntlm|ad_|identity_|jwt_|kerberoast)/i
const IAC_PATTERN = /^(iac_|pipeline$|terraform|terragrunt|helm_|k8s_container|container_registry|cicd_|sbom_|supply_chain|github_actions|devsecops)/i

const OAST_PATTERN = /^(ssrf|oast|xxe|ssti|http_feedback|prototype_pollution|websocket)/i
const LLM_PATTERN = /^(llm_|semantic_ai|ai_adversarial|poe_synthesis|nexus_sovereign|rag_poison|prompt_injection|council_|feedback_fuzz|deep_fuzz|ollama)/i
const SOVEREIGN_PATTERN = /^(chronos|liquid_matrix|cognitive_starvation)/i

/** @type {Record<string, (c: object) => Record<string, string>>} */
const EXPLICIT_PREFILL = {
  cloud_posture: (c) => ({
    aws_cross_account_role_arn: c.aws_cross_account_role_arn || '',
    aws_external_id: c.aws_external_id_configured ? '••••••••' : '',
  }),
  aws_attack: (c) => ({ aws_cross_account_role_arn: c.aws_cross_account_role_arn || '' }),
  gcp_attack: (c) => ({ gcp_project: c.gcp_project_id || '' }),
  azure_attack: (c) => ({
    azure_subscription_id: c.azure_subscription_id || '',
    azure_tenant_id: c.azure_tenant_id || '',
  }),
  iac_misconfig: (c) => ({ repo_url: (c.repo_urls || [])[0] || '' }),
  supply_chain: (c) => ({
    repo_url: (c.repo_urls || [])[0] || '',
    github_token: c.github_token_configured ? '••••••••' : '',
  }),
  cicd_pipeline: (c) => ({
    repo_url: (c.repo_urls || [])[0] || '',
    github_token: c.github_token_configured ? '••••••••' : '',
  }),
  container_registry: (c) => ({ repo_url: (c.repo_urls || [])[0] || '' }),
  sbom_analyzer: (c) => ({ repo_url: (c.repo_urls || [])[0] || '' }),
  typosquatting_monitor: (c) => ({ domain: c.ad_domain || '' }),
  threat_emulation: (c) => {
    const patch = {}
    const domains = parseJsonList(c.domains)
    if (domains[0]) patch.target = domains[0].startsWith('http') ? domains[0] : `https://${domains[0]}`
    return patch
  },
  mobile_attack: (c) => {
    const domains = parseJsonList(c.domains)
    if (!domains[0]) return {}
    return { target: domains[0].startsWith('http') ? domains[0] : `https://${domains[0]}` }
  },
  digital_twin: (c) => {
    const domains = parseJsonList(c.domains)
    if (!domains[0]) return {}
    return { target: domains[0].startsWith('http') ? domains[0] : `https://${domains[0]}` }
  },
  kerberoasting: (c) => ({ domain: c.ad_domain || '' }),
  password_spray: (c) => ({ domain: c.ad_domain || '' }),
  saml_attack: (c) => ({ domain: c.ad_domain || '' }),
  leak_hunter: (c) => ({
    github_token: c.github_token_configured ? '••••••••' : '',
  }),
  oast_oob: (c) => ({
    oast_domain: c.oast_domain || '',
    oast_api_key: c.oast_api_key_configured ? '••••••••' : '',
  }),
  osint: (c) => ({
    github_token: c.github_token_configured ? '••••••••' : '',
  }),
  semantic_ai_fuzz: (c) => prefillLlm(c),
  llm_redteam: (c) => prefillLlm(c),
  ai_adversarial_redteam: (c) => prefillLlm(c),
}

function prefillLlm(c) {
  const ep = (c.llm_secops_endpoints || [])[0]
  if (!ep) return {}
  return {
    llm_base_url: ep.base_url || ep.url || '',
    llm_model: ep.model || '',
  }
}

function patternPrefill(engineId, c) {
  const patch = {}
  const firstRepo = (c.repo_urls || [])[0] || ''
  if (AWS_PATTERN.test(engineId)) {
    patch.aws_cross_account_role_arn = c.aws_cross_account_role_arn || ''
    if (c.aws_external_id_configured) patch.aws_external_id = '••••••••'
  }
  if (GCP_PATTERN.test(engineId)) patch.gcp_project = c.gcp_project_id || ''
  if (AZURE_PATTERN.test(engineId)) {
    patch.azure_subscription_id = c.azure_subscription_id || ''
    patch.azure_tenant_id = c.azure_tenant_id || ''
  }
  if (IDENTITY_PATTERN.test(engineId)) patch.domain = c.ad_domain || ''
  if (IAC_PATTERN.test(engineId) && firstRepo) patch.repo_url = firstRepo
  if (OAST_PATTERN.test(engineId)) {
    patch.oast_domain = c.oast_domain || ''
    if (c.oast_api_key_configured) patch.oast_api_key = '••••••••'
  }
  if (LLM_PATTERN.test(engineId)) Object.assign(patch, prefillLlm(c))
  if (SOVEREIGN_PATTERN.test(engineId)) {
    if (c.ebpf_ssh_host) patch.ebpf_ssh_host = c.ebpf_ssh_host
    if (c.ebpf_ssh_user) patch.ebpf_ssh_user = c.ebpf_ssh_user
  }
  if (/github|leak_hunter|osint/i.test(engineId) && c.github_token_configured) {
    patch.github_token = '••••••••'
  }
  return patch
}

export function prefillParamsForEngine(engineId, integrations, currentParams = {}) {
  if (!integrations) return currentParams
  const explicit = EXPLICIT_PREFILL[engineId]
  const patch = {
    ...patternPrefill(engineId, integrations),
    ...(explicit ? explicit(integrations) : {}),
  }
  const next = { ...currentParams }
  for (const [k, v] of Object.entries(patch)) {
    if (v && (!next[k] || next[k] === '')) next[k] = v
  }
  return next
}

/** Build default param object from schema + integrations prefill */
export function buildDefaultEngineParams(engineId, integrations = null) {
  const schema = getEngineParams({ id: engineId })
  const base = Object.fromEntries(schema.map((d) => [d.key, d.defaultVal ?? '']))
  return integrations ? prefillParamsForEngine(engineId, integrations, base) : base
}

/** Merge integration defaults into a hub-built scan body (hub fields win when set). */
export function mergeScanBody(engineId, customBody, integrations = null) {
  if (!customBody || typeof customBody !== 'object') return customBody
  const defaults = buildDefaultEngineParams(engineId, integrations)
  const out = { ...customBody }
  for (const [k, v] of Object.entries(defaults)) {
    if (out[k] === '' || out[k] == null) {
      if (v !== '' && v != null) out[k] = v
    }
  }
  for (const [k, v] of Object.entries(out)) {
    if (v === '' || v == null || v === '••••••••') delete out[k]
  }
  return out
}

/** Merge schema defaults, sample payload, and runtime fields for POST /api/command-center/scan */
export function buildScanPayload(engineId, {
  clientId,
  target,
  integrations = null,
  samplePayload = {},
  extraParams = {},
} = {}) {
  const body = {
    engine: engineId,
    ...buildDefaultEngineParams(engineId, integrations),
    ...samplePayload,
    ...extraParams,
  }
  if (clientId != null && clientId !== '') body.client_id = Number(clientId)
  if (typeof target === 'string' && target.trim()) body.target = target.trim()
  for (const [k, v] of Object.entries(body)) {
    if (v === '' || v == null) delete body[k]
    if (v === '••••••••') delete body[k]
  }
  return body
}

/** Command center routes for top-tier / hub navigation */
export const TOP_TIER_PARAM_ROUTES = ENGINE_COMMAND_CENTER_ROUTES
