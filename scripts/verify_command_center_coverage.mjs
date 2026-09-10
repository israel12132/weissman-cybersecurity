#!/usr/bin/env node
/**
 * Supreme coverage gate — command-center scan wiring, params, routes, integrations.
 * Run: node scripts/verify_command_center_coverage.mjs
 */
import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { spawnSync } from 'node:child_process'

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')
const pagesDir = path.join(root, 'frontend/src/pages')
const violations = []
const warnings = []

function readPages() {
  return fs.readdirSync(pagesDir).filter((f) => f.endsWith('.jsx'))
}

// Delegate to existing gates
for (const script of [
  'verify_engine_scan_wiring.mjs',
  'verify_hub_local_params.mjs',
]) {
  const r = spawnSync('node', [`scripts/${script}`], { cwd: root, encoding: 'utf8' })
  if (r.status !== 0) {
    console.error(r.stdout || r.stderr)
    process.exit(r.status ?? 1)
  }
}

const { ROUTE_ENGINE_ID, ROUTE_ENGINE_ID_PARAM_PREFIX, resolveRouteEngineId } = await import(
  pathToFileURL(path.join(root, 'frontend/src/lib/routeEngineId.js')).href,
)
const { getEngineParams } = await import(
  pathToFileURL(path.join(root, 'frontend/src/lib/engineParamDefs.js')).href,
)

const { computeEngineIntegrationReadiness } = await import(
  pathToFileURL(path.join(root, 'frontend/src/lib/engineIntegrationReadiness.js')).href,
)

const main = fs.readFileSync(path.join(root, 'frontend/src/main.jsx'), 'utf8')
const routedComponents = new Set()
for (const m of main.matchAll(/path="([^"]+)"[^>]*element=\{<(\w+)/g)) {
  routedComponents.add(m[2])
}

const hubPages = []
for (const file of readPages()) {
  const text = fs.readFileSync(path.join(pagesDir, file), 'utf8')
  const scans = /\bpostScan\(/.test(text)
    || /\blaunchEngineScan\(/.test(text)
    || /useLaunchEngineScan\(/.test(text)
  const hasCC = text.includes('useCommandCenterScan')
  const hasLaunch = text.includes('useLaunchEngineScan')
  const isHub = text.includes('<PageShell') && (hasCC || hasLaunch)

  if (text.includes('function firstClientTarget(')) {
    violations.push(`${file}: local firstClientTarget — use lib/clientTarget.js`)
  }
  if (scans && !hasCC && !hasLaunch) {
    violations.push(`${file}: scan dispatch without useCommandCenterScan / useLaunchEngineScan`)
  }
  if (hasCC && scans && text.includes('useCommandCenterScan(')) {
    hubPages.push(file)
  }
  if (isHub && hasCC) {
    const comp = file.replace('.jsx', '')
    if (!routedComponents.has(comp)) continue
    const routeMatch = main.match(new RegExp(`path="([^"]+)"[^>]*element=\\{<${comp}`))
    const route = routeMatch?.[1]
    const hasEngineProp = /engineId=\{/.test(text)
    const isMulti = text.includes('useHubEngineFocus') || text.includes('focusedEngineId')
    const routeKey = route ? (route.startsWith('/') ? route : `/${route}`) : null
    const routeEngine = routeKey ? resolveRouteEngineId(routeKey) : null
    if (!hasEngineProp && !routeEngine && !isMulti) {
      violations.push(`${file}: PageShell hub without engineId or ROUTE_ENGINE_ID mapping`)
    }
  }
  if (isHub && !text.includes('EngineIntegrationsBar') && !text.includes('PageShell')) {
    // PageShell auto-injects bar — OK
  }
}

// Route map sanity: every ROUTE_ENGINE_ID value must have param schema
for (const [route, engineId] of Object.entries(ROUTE_ENGINE_ID)) {
  const schema = getEngineParams({ id: engineId })
  if (!schema?.length) {
    violations.push(`route ${route} → ${engineId}: missing param schema`)
  }
  const readiness = computeEngineIntegrationReadiness(engineId, {})
  if (!readiness) {
    warnings.push(`route ${route}: readiness compute failed`)
  }
}

// Parametric prefixes must resolve
for (const rule of ROUTE_ENGINE_ID_PARAM_PREFIX) {
  const sample = `${rule.prefix}42`
  const resolved = resolveRouteEngineId(sample)
  if (resolved !== rule.engine) {
    violations.push(`param route ${sample} expected ${rule.engine}, got ${resolved}`)
  }
  if (!getEngineParams({ id: rule.engine })?.length) {
    violations.push(`param route engine ${rule.engine}: missing param schema`)
  }
}

// ProtectedOutlet providers (TacticalApp + ProtectedProviders bundle)
const tacticalApp = fs.readFileSync(path.join(root, 'frontend/src/TacticalApp.jsx'), 'utf8')
const protectedProviders = fs.readFileSync(path.join(root, 'frontend/src/providers/ProtectedProviders.jsx'), 'utf8')
if (
  !tacticalApp.includes('ProtectedOutlet')
  || !protectedProviders.includes('ClientProvider')
  || !protectedProviders.includes('EngineHubProvider')
) {
  violations.push('TacticalApp/ProtectedProviders: missing ClientProvider / EngineHubProvider shell')
}

// launchEngineScan must be engine-aware (hub merge guard)
const launchSrc = fs.readFileSync(path.join(root, 'frontend/src/hooks/useLaunchEngineScan.js'), 'utf8')
if (!launchSrc.includes('hubEngineId')) {
  violations.push('useLaunchEngineScan: missing engine-aware hubEngineId merge')
}
const ccSrc = fs.readFileSync(path.join(root, 'frontend/src/hooks/useCommandCenterScan.js'), 'utf8')
if (!ccSrc.includes('hubEngineId')) {
  violations.push('useCommandCenterScan: missing engine-aware hubEngineId merge')
}

// scan_routing server hydration
const scanRouting = fs.readFileSync(path.join(root, 'fingerprint_engine/src/scan_routing.rs'), 'utf8')
for (const needle of ['hydrate_extras_from_client', 'hydrate_extras_from_tenant', 'MASKED_SECRET']) {
  if (!scanRouting.includes(needle)) {
    violations.push(`scan_routing.rs: missing ${needle}`)
  }
}

// Job payload secret redaction for GET /api/jobs/:id
const redactMod = path.join(root, 'fingerprint_engine/src/scan_payload_redaction.rs')
const jobsInc = fs.readFileSync(path.join(root, 'fingerprint_engine/src/server_handlers_jobs.inc'), 'utf8')
if (!fs.existsSync(redactMod)) {
  violations.push('scan_payload_redaction.rs: missing')
} else if (!jobsInc.includes('scan_payload_redaction::redact_for_api')) {
  violations.push('server_handlers_jobs.inc: job GET must redact payload secrets')
} else if (!jobsInc.includes('reveal_job_payload_for_tenant')) {
  violations.push('server_handlers_jobs.inc: job GET must decrypt the tenant envelope before redact')
}
const asyncExec = fs.readFileSync(path.join(root, 'fingerprint_engine/src/async_job_executor.rs'), 'utf8')
if (!asyncExec.includes('engine_stack_runtime::run_on_large_stack')) {
  violations.push('async_job_executor: command_center_engine must use large-stack runtime')
}
if (!scanRouting.includes('seal_payload_for_queue') || !scanRouting.includes('hydrate_stored_job_payload')) {
  violations.push('scan_routing: missing queue seal / worker hydration')
}
const redactSrc = fs.readFileSync(path.join(root, 'fingerprint_engine/src/scan_payload_redaction.rs'), 'utf8')
if (!redactSrc.includes('strip_secrets_for_storage')) {
  violations.push('scan_payload_redaction: missing strip_secrets_for_storage')
}
for (const script of [
  'verify_fp_tp_confidence_e2e.mjs',
  'verify_supreme_e2e_stack.mjs',
]) {
  if (!fs.existsSync(path.join(root, 'scripts', script))) {
    violations.push(`scripts/${script}: missing`)
  }
}

// integrations API exposes tenant secrets (masked)
const phase3 = fs.readFileSync(path.join(root, 'fingerprint_engine/src/server_handlers_phase3.inc'), 'utf8')
for (const needle of ['"github_token": mask_secret_field', '"oast_domain"', '"oast_api_key": mask_secret_field']) {
  if (!phase3.includes(needle)) {
    violations.push(`integrations GET: missing ${needle}`)
  }
}

// Live E2E stack scripts present
for (const script of ['run_e2e_stack.sh', 'verify_scan_pipeline_e2e.mjs', 'verify_engine_groups_findings_e2e.mjs']) {
  if (!fs.existsSync(path.join(root, 'scripts', script))) {
    violations.push(`scripts/${script}: missing (runtime E2E gate)`)
  }
}

// retryShed is a runtime binding. node --check does not catch a missing import;
// CI then dies at pollJob after the live stack (login + enqueue already succeeded).
{
  const findingsE2ePath = path.join(root, 'scripts', 'verify_engine_groups_findings_e2e.mjs')
  if (fs.existsSync(findingsE2ePath)) {
    const findingsE2e = fs.readFileSync(findingsE2ePath, 'utf8')
    if (!/import\s*\{[^}]*\bretryShed\b[^}]*\}\s*from\s*['\"]\.\/lib\/scan_intake\.mjs['\"]/.test(findingsE2e)) {
      violations.push(
        'verify_engine_groups_findings_e2e.mjs: pollJob uses retryShed but does not import it from scan_intake.mjs',
      )
    }
  }
}

if (warnings.length) {
  console.warn('verify_command_center_coverage: warnings')
  for (const w of warnings) console.warn(`  - ${w}`)
}

if (violations.length) {
  console.error('verify_command_center_coverage: FAIL')
  for (const v of violations) console.error(`  - ${v}`)
  process.exit(1)
}

console.log(
  `verify_command_center_coverage: OK (${hubPages.length} hub scan pages, ${Object.keys(ROUTE_ENGINE_ID).length} route engines, ${ROUTE_ENGINE_ID_PARAM_PREFIX.length} parametric routes)`,
)
