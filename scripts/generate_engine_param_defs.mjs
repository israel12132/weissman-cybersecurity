#!/usr/bin/env node
/**
 * Generates supplemental PARAM_DEFS for every production engine without hand-tuned UI.
 * Run: node scripts/generate_engine_param_defs.mjs
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
const scanRs = fs.readFileSync(path.join(root, 'fingerprint_engine/src/scan_routing.rs'), 'utf8')
const { ENGINES_REGISTRY } = await import(pathToFileURL(path.join(root, 'frontend/src/lib/enginesRegistry.js')).href)
const { EXPLICIT_PARAM_DEFS } = await import(pathToFileURL(path.join(root, 'frontend/src/lib/engineParamDefsExplicit.js')).href)

const productionIds = extractArray('PRODUCTION_ENGINE_IDS', engineRs)
const registryById = Object.fromEntries(ENGINES_REGISTRY.map((e) => [e.id, e]))

const OAST_ENGINES = new Set(
  [...scanRs.matchAll(/engines:\s*&\["([^"]+)"\][\s\S]*?inject_oast:\s*true/g)].map((m) => m[1]),
)

const AI_HEAVY = new Set([
  'semantic_ai_fuzz', 'ai_adversarial_redteam', 'llm_path_fuzz', 'ollama_fuzz',
  'http_feedback_fuzz', 'poe_synthesis', 'nexus_sovereign_swarm', 'llm_redteam',
  'llm_fuzzer', 'council_debate', 'feedback_fuzz', 'deep_fuzz', 'llm_jailbreak',
  'prompt_injection_chain', 'rag_poisoning_engine', 'prompt_injection_brake',
  'jailbreak_cognitive_engine', 'rag_poisoning_guard', 'autonomous_pentest',
])

const P = (key, label, type, extra = {}) => ({ key, label, type, defaultVal: '', ...extra })

const SHARED = {
  intensity: P('intensity', 'Scan Intensity', 'select', { options: ['light', 'normal', 'aggressive'], defaultVal: 'normal' }),
  maxFindings: P('max_findings', 'Max Findings', 'number', { defaultVal: '200', min: 1, max: 5000 }),
  timeout: P('timeout_ms', 'Probe Timeout (ms)', 'number', { defaultVal: '8000', min: 500, max: 60000 }),
  evidence: P('evidence_mode', 'Evidence Mode', 'select', { options: ['standard', 'strict', 'forensic'], defaultVal: 'standard' }),
  stealth: P('stealth_mode', 'Stealth Mode', 'select', { options: ['off', 'low', 'high'], defaultVal: 'low' }),
  depth: P('depth', 'Probe Depth', 'select', { options: ['1', '2', '3', '4', '5'], defaultVal: '3' }),
  ports: P('ports', 'Ports / Port Range', 'text', { placeholder: 'top | 80,443,8080', defaultVal: 'top' }),
  domain: P('domain', 'Target Domain (AD/DNS)', 'text', { placeholder: 'corp.example.com', defaultVal: '' }),
  repo: P('repo_url', 'Repository URL', 'text', { placeholder: 'https://github.com/org/infra', defaultVal: '' }),
  awsRole: P('aws_cross_account_role_arn', 'AWS Cross-Account Role ARN', 'text', { placeholder: 'arn:aws:iam::123:role/WeissmanReadOnly', defaultVal: '' }),
  awsExt: P('aws_external_id', 'AWS External ID', 'password', { placeholder: 'external-id', defaultVal: '' }),
  gcp: P('gcp_project', 'GCP Project ID', 'text', { placeholder: 'my-project', defaultVal: '' }),
  azureSub: P('azure_subscription_id', 'Azure Subscription ID', 'text', { defaultVal: '' }),
  azureTenant: P('azure_tenant_id', 'Azure Tenant ID', 'text', { defaultVal: '' }),
  llmUrl: P('llm_base_url', 'LLM Base URL', 'text', { placeholder: 'http://127.0.0.1:11434/v1', defaultVal: '' }),
  llmModel: P('llm_model', 'LLM Model', 'text', { placeholder: 'gpt-4o', defaultVal: '' }),
  oast: P('oast_domain', 'OAST Callback Domain', 'text', { placeholder: 'token.oast.example.com', defaultVal: '' }),
  auth: P('auth_header', 'Authorization Header', 'password', { placeholder: 'Bearer eyJ...', defaultVal: '' }),
  cookies: P('cookies', 'Session Cookies', 'password', { placeholder: 'session=...', defaultVal: '' }),
  github: P('github_token', 'GitHub Token (optional)', 'password', { placeholder: 'ghp_...', defaultVal: '' }),
  safe: P('safe_mode', 'Safe Mode (no destructive exec)', 'select', { options: ['true', 'false'], defaultVal: 'true' }),
  otStrict: P('protocol_strict', 'OT Protocol Strict', 'select', { options: ['true', 'false'], defaultVal: 'true' }),
  campaign: P('campaign_name', 'Campaign Name', 'text', { placeholder: 'Red Team Q2', defaultVal: '' }),
  platform: P('platform', 'Platform', 'select', { options: ['both', 'android', 'ios'], defaultVal: 'both' }),
}

function uniqParams(list) {
  const seen = new Set()
  return list.filter((p) => {
    if (seen.has(p.key)) return false
    seen.add(p.key)
    return true
  })
}

function byGroup(group) {
  switch (group) {
    case 'recon':
      return [SHARED.depth, SHARED.ports, SHARED.github, SHARED.stealth, SHARED.maxFindings]
    case 'web':
      return [SHARED.intensity, SHARED.cookies, SHARED.auth, SHARED.timeout, SHARED.maxFindings, SHARED.stealth]
    case 'ai':
      return [SHARED.llmUrl, SHARED.llmModel, SHARED.intensity, SHARED.maxFindings, SHARED.safe]
    case 'cloud':
      return [SHARED.awsRole, SHARED.awsExt, SHARED.gcp, SHARED.azureSub, SHARED.azureTenant, SHARED.intensity, SHARED.stealth]
    case 'ot':
      return [SHARED.ports, SHARED.otStrict, SHARED.depth, SHARED.timeout, SHARED.maxFindings]
    case 'crypto':
      return [SHARED.domain, SHARED.intensity, SHARED.ports, SHARED.stealth, SHARED.maxFindings]
    case 'network':
      return [SHARED.ports, SHARED.intensity, SHARED.timeout, SHARED.stealth, SHARED.maxFindings]
    case 'supply_chain':
      return [SHARED.repo, SHARED.github, SHARED.intensity, SHARED.maxFindings]
    case 'apt':
      return [SHARED.intensity, SHARED.campaign, SHARED.stealth, SHARED.maxFindings, SHARED.evidence]
    case 'malware':
      return [SHARED.safe, SHARED.intensity, SHARED.stealth, SHARED.maxFindings]
    case 'social':
      return [SHARED.campaign, SHARED.intensity, SHARED.maxFindings]
    case 'mobile':
      return [SHARED.platform, SHARED.intensity, SHARED.auth, SHARED.maxFindings]
    case 'data':
      return [SHARED.intensity, SHARED.stealth, SHARED.maxFindings, SHARED.evidence]
    case 'stealth':
      return [SHARED.stealth, P('stealth_level', 'Stealth Level (1-5)', 'number', { defaultVal: '3', min: 1, max: 5 }), SHARED.maxFindings]
    case 'defense':
      return [SHARED.intensity, SHARED.evidence, SHARED.maxFindings]
    default:
      return [SHARED.intensity, SHARED.timeout, SHARED.maxFindings, SHARED.evidence]
  }
}

const IAC_PATTERN = /^(iac_|pipeline$|terraform|terragrunt|helm_|k8s_container|container_registry|cicd_|sbom_|supply_chain|github_actions)/

function byPattern(id) {
  const extra = []
  if (/^(aws_|s3_|iam_|ec2_|lambda_|eks_|rds_|kms_|secrets_manager|cloudformation|multi_cloud)/i.test(id)) {
    extra.push(SHARED.awsRole, SHARED.awsExt)
  }
  if (/^(gcp_|gke_|cloud_sql|bigquery|gcs_)/i.test(id)) extra.push(SHARED.gcp)
  if (/^(azure_|entra_|arm_|aad_)/i.test(id)) extra.push(SHARED.azureSub, SHARED.azureTenant)
  if (/^(kerberos|saml|oauth|oidc|ldap|password_spray|ntlm|ad_|identity_|jwt_|kerberoast)/i.test(id)) {
    extra.push(SHARED.domain)
  }
  if (IAC_PATTERN.test(id)) extra.push(SHARED.repo, SHARED.github)
  if (AI_HEAVY.has(id) || /^llm_|^ai_|semantic_|adversarial_|rag_|prompt_/.test(id)) {
    extra.push(SHARED.llmUrl, SHARED.llmModel)
  }
  if (OAST_ENGINES.has(id) || /oast|oob|blind_ssrf|xxe|log4shell|callback/i.test(id)) {
    extra.push(SHARED.oast)
  }
  if (/^github_|gitlab_|cicd_|pipeline|terraform|helm_|sbom_|devsecops/.test(id)) {
    extra.push(SHARED.repo, SHARED.github)
  }
  if (/^scada_|^iot_|^modbus|^dnp3|^bacnet|^iec61850|^ics_|^plc_|^hmi_/.test(id)) {
    extra.push(SHARED.otStrict, SHARED.ports)
  }
  if (/mobile|android|ios|apk_/.test(id)) extra.push(SHARED.platform)
  if (/phish|spear_|vishing|smish|bec_|pretext/.test(id)) extra.push(SHARED.campaign)
  if (/malware|ransom|trojan|worm_|bootkit|keylogger|spyware/.test(id)) extra.push(SHARED.safe)
  return extra
}

const generated = {}

for (const id of productionIds) {
  if (EXPLICIT_PARAM_DEFS[id]) continue
  const group = registryById[id]?.group || 'web'
  const params = uniqParams([...byPattern(id), ...byGroup(group)])
  generated[id] = params
}

const outPath = path.join(root, 'frontend/src/lib/engineParamDefs.generated.js')
const body = `/**
 * AUTO-GENERATED — node scripts/generate_engine_param_defs.mjs
 * Supplemental scan parameters for production engines without explicit PARAM_DEFS.
 * Do not edit by hand; regenerate after registry changes.
 */
export const GENERATED_PARAM_DEFS = ${JSON.stringify(generated, null, 2)}
`

// --check: verify the committed file matches what we'd generate, without writing.
// Lets the wiring gate FAIL on drift instead of silently rewriting a tracked
// source file inside the runner (leaving the shipped bundle built from a stale copy).
if (process.argv.includes('--check')) {
  const existing = fs.existsSync(outPath) ? fs.readFileSync(outPath, 'utf8') : ''
  if (existing !== body) {
    console.error(
      `✖ ${path.relative(root, outPath)} is out of date vs the engine registry.\n` +
        '  Run: node scripts/generate_engine_param_defs.mjs  (and commit the result).',
    )
    process.exit(1)
  }
  console.log(`✓ ${path.relative(root, outPath)} is up to date (${Object.keys(generated).length} profiles)`)
  process.exit(0)
}

fs.writeFileSync(outPath, body)
console.log(`Generated ${Object.keys(generated).length} engine param profiles → ${outPath}`)
console.log(`Explicit hand-tuned: ${Object.keys(EXPLICIT_PARAM_DEFS).length}`)
