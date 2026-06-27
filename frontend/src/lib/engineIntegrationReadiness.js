/**
 * Engine → required client/tenant integration chips for readiness UI.
 */

const AWS_PATTERN = /^(aws_|s3_|iam_|ec2_|lambda_|eks_|rds_|kms_|secrets_manager|cloudformation|multi_cloud|cloud_posture|serverless)/i
const GCP_PATTERN = /^(gcp_|gke_|cloud_sql|bigquery|gcs_)/i
const AZURE_PATTERN = /^(azure_|entra_|arm_|aad_)/i
const IDENTITY_PATTERN = /^(kerberos|saml|oauth|oidc|ldap|password_spray|ntlm|ad_|identity_|jwt_|kerberoast)/i
const IAC_PATTERN = /^(iac_|pipeline$|terraform|terragrunt|helm_|k8s_container|container_registry|cicd_|sbom_|supply_chain|github_actions|devsecops)/i
const OAST_PATTERN = /^(ssrf|oast|xxe|ssti|http_feedback|prototype_pollution|websocket)/i
const LLM_PATTERN = /^(llm_|semantic_ai|ai_adversarial|poe_synthesis|nexus_sovereign|rag_poison|prompt_injection|council_|feedback_fuzz|deep_fuzz|ollama)/i
const AGENT_PATTERN = /^(edr_evasion|endpoint_|memory_forensics|scada_ics|digital_twin)/i
const GITHUB_PATTERN = /^(leak_hunter|osint|github_secret)/i
const SCOPE_PATTERN = /^(asm|attack_surface|threat_emulation|mobile_attack|digital_twin|spear_phishing|risk_superposition|exploit_lab|pqc_scanner|bgp_dns|chronos|liquid_matrix|cognitive)/i

const EXPLICIT = {
  cloud_posture: ['aws', 'aws_ext'],
  aws_attack: ['aws'],
  gcp_attack: ['gcp'],
  azure_attack: ['azure'],
  iac_misconfig: ['iac'],
  cicd_pipeline: ['iac', 'github'],
  supply_chain: ['iac', 'github'],
  container_registry: ['iac'],
  sbom_analyzer: ['iac'],
  kerberoasting: ['ad'],
  password_spray: ['ad'],
  saml_attack: ['ad'],
  leak_hunter: ['github'],
  oast_oob: ['oast'],
  osint: ['github'],
  semantic_ai_fuzz: ['llm'],
  llm_redteam: ['llm'],
  ai_adversarial_redteam: ['llm'],
  feedback_fuzz: ['llm'],
  http_feedback_fuzz: ['llm'],
  threat_emulation: ['scope'],
  mobile_attack: ['scope'],
  digital_twin: ['scope', 'agent'],
  spear_phishing: ['scope'],
  risk_superposition_collapse: ['scope'],
  chronos: ['scope', 'agent'],
  liquid_matrix: ['scope'],
  cognitive_starvation: ['scope'],
  scada_ics: ['agent'],
  modbus_attack: ['agent'],
  bacnet_attack: ['agent'],
  opcua_attack: ['agent'],
  exploit_lab: ['scope'],
  pqc_scanner: ['scope'],
  nexus_sovereign_swarm: ['llm', 'agent'],
}

function collectKeys(engineId) {
  const keys = new Set(EXPLICIT[engineId] || [])
  if (AWS_PATTERN.test(engineId)) keys.add('aws')
  if (/cloud_posture|aws_attack/i.test(engineId)) keys.add('aws_ext')
  if (GCP_PATTERN.test(engineId)) keys.add('gcp')
  if (AZURE_PATTERN.test(engineId)) keys.add('azure')
  if (IDENTITY_PATTERN.test(engineId)) keys.add('ad')
  if (IAC_PATTERN.test(engineId)) keys.add('iac')
  if (OAST_PATTERN.test(engineId)) keys.add('oast')
  if (LLM_PATTERN.test(engineId)) keys.add('llm')
  if (AGENT_PATTERN.test(engineId)) keys.add('agent')
  if (GITHUB_PATTERN.test(engineId)) keys.add('github')
  if (SCOPE_PATTERN.test(engineId)) keys.add('scope')
  return [...keys]
}

const CHIP_DEFS = {
  aws: { label: 'AWS', color: '#f97316' },
  aws_ext: { label: 'AWS Ext ID', color: '#fb923c' },
  gcp: { label: 'GCP', color: '#4285f4' },
  azure: { label: 'Azure', color: '#0078d4' },
  ad: { label: 'AD', color: '#a855f7' },
  iac: { label: 'IaC Repo', color: '#22d3ee' },
  oast: { label: 'OAST', color: '#f43f5e' },
  llm: { label: 'LLM', color: '#8b5cf6' },
  agent: { label: 'Agent', color: '#34d399' },
  github: { label: 'GitHub', color: '#e2e8f0' },
  scope: { label: 'Scope', color: '#38bdf8' },
}

function statusForKey(key, c) {
  if (!c) return false
  switch (key) {
    case 'aws':
      return !!String(c.aws_cross_account_role_arn || '').trim()
    case 'aws_ext':
      return !!c.aws_external_id_configured
    case 'gcp':
      return !!String(c.gcp_project_id || '').trim()
    case 'azure':
      return !!String(c.azure_subscription_id || '').trim() && !!String(c.azure_tenant_id || '').trim()
    case 'ad':
      return !!String(c.ad_domain || '').trim()
    case 'iac':
      return Array.isArray(c.repo_urls) && c.repo_urls.length > 0
    case 'oast':
      return !!String(c.oast_domain || '').trim() || !!c.oast_api_key_configured
    case 'llm':
      return Array.isArray(c.llm_secops_endpoints) && c.llm_secops_endpoints.length > 0
    case 'agent':
      return Array.isArray(c.agent_platforms) && c.agent_platforms.length > 0
    case 'github':
      return !!c.github_token_configured
    case 'scope': {
      const domains = Array.isArray(c.domains) ? c.domains : []
      return domains.some((d) => String(d || '').trim())
    }
    default:
      return false
  }
}

/** @returns {{ percent: number, ready: boolean, chips: Array<{ key: string, label: string, color: string, ok: boolean, required: boolean }> }} */
export function computeEngineIntegrationReadiness(engineId, integrations) {
  const keys = collectKeys(engineId)
  if (!keys.length) {
    return { percent: 100, ready: true, chips: [] }
  }
  const chips = keys.map((key) => ({
    key,
    label: CHIP_DEFS[key]?.label || key,
    color: CHIP_DEFS[key]?.color || '#94a3b8',
    ok: statusForKey(key, integrations),
    required: true,
  }))
  const okCount = chips.filter((c) => c.ok).length
  return {
    percent: Math.round((okCount * 100) / chips.length),
    ready: okCount === chips.length,
    chips,
  }
}
