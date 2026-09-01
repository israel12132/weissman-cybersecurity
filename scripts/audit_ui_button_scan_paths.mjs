import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { retryScanIntake, retryLogin } from './lib/scan_intake.mjs'

const BASE_URL = process.env.WEISSMAN_SMOKE_BASE_URL || 'http://127.0.0.1'
const LOGIN_EMAIL = process.env.WEISSMAN_SMOKE_LOGIN_EMAIL || process.env.WEISSMAN_ADMIN_EMAIL || 'admin@localhost'
const LOGIN_PASSWORD = process.env.WEISSMAN_SMOKE_LOGIN_PASSWORD || process.env.WEISSMAN_ADMIN_PASSWORD || 'changeme'
const TENANT_SLUG = process.env.WEISSMAN_TENANT_SLUG || 'default'
const CLIENT_NAME = process.env.WEISSMAN_SMOKE_CLIENT_NAME || 'CI Smoke Client'
const POLL_TIMEOUT_MS = Number(process.env.WEISSMAN_UI_AUDIT_POLL_TIMEOUT_MS || 180000)

const UI_BUTTON_SCENARIOS_BASE = [
  {
    source: 'frontend/src/components/CommandBar.jsx',
    kind: 'command-center-scan',
    payload: { engine: 'recon', target: 'https://example.com' },
  },
  {
    source: 'frontend/src/components/cockpit/EngineCard.jsx',
    kind: 'command-center-scan',
    payload: { engine: 'recon', target: 'https://example.com' },
  },
  {
    source: 'frontend/src/pages/BusinessEngineProfile.jsx',
    kind: 'command-center-scan',
    payload: { engine: 'osint', target: 'https://example.com' },
  },
  {
    source: 'frontend/src/pages/CloudControlTower.jsx',
    kind: 'command-center-scan',
    payload: { engine: 'cloud_audit_evasion', target: 'https://example.com' },
  },
  {
    source: 'frontend/src/pages/DigitalTwinSimulator.jsx',
    kind: 'command-center-scan',
    payload: { engine: 'digital_twin', scenario: 'xss_stored', target: 'https://example.com' },
  },
  {
    source: 'frontend/src/pages/EngineClientCatalog.jsx',
    kind: 'command-center-scan',
    payload: { engine: 'recon', target: 'https://example.com' },
  },
  {
    source: 'frontend/src/pages/EngineDetail.jsx',
    kind: 'command-center-scan',
    payload: { engine: 'llm_jailbreak', target: 'https://example.com', timeout: 45 },
  },
  {
    source: 'frontend/src/pages/EngineMatrix.jsx',
    kind: 'command-center-scan',
    payload: { engine: 'recon', target: 'https://example.com' },
  },
  {
    source: 'frontend/src/pages/NetworkIntelligence.jsx',
    kind: 'command-center-scan',
    payload: { engine: 'bgp_dns_hijacking', target: 'example.com' },
  },
  {
    source: 'frontend/src/pages/OastDashboard.jsx',
    kind: 'command-center-scan',
    payload: { engine: 'oast_oob', probe_type: 'dns', target: 'https://example.com' },
  },
  {
    source: 'frontend/src/pages/PqcRadar.jsx',
    kind: 'command-center-scan',
    payload: { engine: 'pqc_scanner', target: 'https://example.com' },
  },
  {
    source: 'frontend/src/pages/SupplyChainHub.jsx',
    kind: 'command-center-scan',
    payload: { engine: 'supply_chain', target: 'https://github.com/octocat/Hello-World' },
  },
  {
    source: 'frontend/src/pages/ThreatEmulation.jsx',
    kind: 'command-center-scan',
    payload: { engine: 'threat_emulation', apt_group: 'apt28', target: 'https://example.com' },
  },
  {
    source: 'frontend/src/pages/TopTierEngineProfile.jsx',
    kind: 'command-center-scan',
    payload: { engine: 'kill_chain', target: 'https://example.com' },
  },
  {
    source: 'frontend/src/pages/TopTierEngineHub.jsx',
    kind: 'top-tier-health-probe',
    payload: { target: 'https://example.com' },
  },
]

/**
 * Known scan-engine IDs, loaded from the generated catalog. Used to reject engine
 * strings the discovery heuristic scrapes out of demo/config text (e.g. a Terraform
 * `engine = "postgres"` snippet rendered in the IaC page, or an `EXPLOIT_LAB_ENGINE`
 * namespace constant) rather than fabricating a scan the API rejects with 400. If the
 * catalog can't be read, fall back to accepting any derived engine (old behaviour).
 */
function loadKnownEngineIds() {
  try {
    const catalog = JSON.parse(readFileSync(join(process.cwd(), 'shared/engine_requirements.json'), 'utf8'))
    const ids = Object.keys(catalog?.engines || {})
    return ids.length ? new Set(ids) : null
  } catch {
    return null
  }
}

/** Auto-discover scan-wired hub pages not listed explicitly above. */
function discoverScanHubScenarios() {
  const pagesDir = join(process.cwd(), 'frontend/src/pages')
  const existing = new Set(UI_BUTTON_SCENARIOS_BASE.map((s) => s.source))
  const knownEngines = loadKnownEngineIds()
  const extra = []
  for (const file of readdirSync(pagesDir)) {
    if (!file.endsWith('.jsx') || file === 'PageShell.jsx') continue
    const source = `frontend/src/pages/${file}`
    if (existing.has(source)) continue
    const src = readFileSync(join(pagesDir, file), 'utf8')
    if (!/useCommandCenterScan|useLaunchEngineScan|launchEngineScan|postEngineScan/.test(src)) continue
    // Prefer the page's canonical `ENGINE_ID = '...'` declaration over any inline
    // `engine: '...'` / `engine = '...'` occurrence — the latter also matches demo
    // config text (e.g. a rendered Terraform `engine = "postgres"` block), which is
    // not the page's real scan engine.
    const engineMatch = src.match(/ENGINE_ID\s*=\s*['"]([a-z0-9_]+)['"]/)
      || src.match(/engine(?:Id)?\s*[:=]\s*['"]([a-z0-9_]+)['"]/i)
    // A scan-wired page with NO derivable engine cannot be verified against its own
    // engine — substituting a 'recon' default (the previous behaviour) proves only
    // that the shared recon engine works and would green-light a broken engine behind
    // this page's Run button. Surface it as a discovery skip instead.
    if (!engineMatch) {
      console.warn(
        `[audit] skipping ${source}: no ENGINE_ID/engine declaration — cannot verify this page's real scan engine`,
      )
      continue
    }
    const engine = engineMatch[1]
    // A page that declares an engine string which isn't a real catalog engine is a
    // discovery false-positive (scraped text / namespace constant), not a scan target —
    // skip it rather than submitting a fabricated engine that 400s.
    if (knownEngines && !knownEngines.has(engine)) {
      console.warn(
        `[audit] skipping ${source}: derived engine '${engine}' is not a known scan engine `
          + '(likely demo/config text or a namespace constant, not the page\'s scan target)',
      )
      continue
    }
    extra.push({
      source,
      kind: 'command-center-scan',
      autoDiscovered: true,
      payload: { engine, target: 'https://example.com' },
    })
  }
  return extra
}

const UI_BUTTON_SCENARIOS = [...UI_BUTTON_SCENARIOS_BASE, ...discoverScanHubScenarios()]

/**
 * Per-engine CI bounding params, same contract as `scripts/lib/group_smoke_plan.mjs`:
 * job_params are read live from the scan body. Auto-discovered hub pages (e.g.
 * AttackSurfaceManagement → `asm`) otherwise POST `{engine, target, timeout:45}`
 * with every ASM module on — crt.sh CT for example.com + 23k-prefix brute + 63
 * ports. That misses the 45s attempt budget; resilience then widens 45→90→180s
 * and the 180s poller gives up while the job is still `running`.
 *
 * Keep a real live probe (DNS + HTTP + well-known) and cut the unbounded fan-out.
 */
const ENGINE_CI_PARAMS = {
  asm: {
    ports: '80,443',
    port_scan: true,
    subdomain_enum: false,
    subdomain_sources: 'passive',
    max_subdomains: 8,
    live_ai_discovery: false,
    dns_intel: true,
    dns_hardening: false,
    dkim_probe: false,
    rdap_intel: false,
    ip_asn_enrichment: false,
    http_posture: true,
    tls_posture: false,
    cloud_hunter: false,
    tech_fingerprint: false,
    shadow_it_scan: false,
    wellknown_probe: true,
    cleartext_http_probe: false,
    banner_grab: false,
    cors_probe: false,
    sensitive_path_probe: false,
    robots_harvest: false,
    attack_path_correlation: true,
    port_timeout_ms: 400,
    http_timeout_ms: 2500,
    max_findings: 80,
  },
}

const UI_PLACEHOLDER_NOTES = [
  {
    source: 'frontend/src/pages/ThreatEmulation.jsx',
    note: 'After queueing, UI sets optimistic placeholder metrics (`pending: true`) until real results are fetched.',
  },
  {
    source: 'frontend/src/pages/DigitalTwinSimulator.jsx',
    note: 'After queueing, UI inserts placeholder scenario status text while job runs.',
  },
]

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function extractHost(target) {
  if (!target || typeof target !== 'string') return null
  try {
    return new URL(target).hostname
  } catch {
    return target
      .replace(/^https?:\/\//, '')
      .split('/')[0]
      .trim()
  }
}

function terminalStatus(status) {
  return ['completed', 'failed', 'error', 'cancelled', 'dead'].includes(String(status || '').toLowerCase())
}

function terminalErrorText(payload) {
  return [payload?.error, payload?.last_error, payload?.detail, payload?.message]
    .filter((value) => typeof value === 'string' && value.trim())
    .join(' | ')
}

function isCatalogOnlyError(payload) {
  return /catalog-only|no runner|unknown/i.test(terminalErrorText(payload))
}

async function api(path, options = {}) {
  const response = await fetch(`${BASE_URL}${path}`, options)
  const rawText = await response.text()
  let body = rawText
  try {
    body = rawText ? JSON.parse(rawText) : null
  } catch {}
  return { response, body }
}

async function login() {
  const { response, body } = await retryLogin(
    () => api('/api/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: LOGIN_EMAIL, password: LOGIN_PASSWORD, tenant_slug: TENANT_SLUG }),
    }),
    { statusOf: (r) => r?.response?.status, retryAfterOf: (r) => r?.body?.retry_after_seconds },
  )
  if (!response.ok || !body?.access_token) {
    throw new Error(`login failed (${response.status}): ${JSON.stringify(body)}`)
  }
  return body.access_token
}

// This audit runs ~40+ scan scenarios sequentially and can run well past the access
// token's TTL (WEISSMAN_ACCESS_TOKEN_MINUTES, default 15). Without refreshing, late
// scenarios 401 on job polling and time out. Refresh the bearer proactively before it
// can expire, and reactively on any 401, mutating the shared `headers` object in place
// so every in-flight caller (queue POST + waitForJob poll) picks up the new token.
let lastAuthMs = 0
async function reauth(headers) {
  headers.authorization = `Bearer ${await login()}`
  lastAuthMs = Date.now()
}
async function ensureFreshAuth(headers) {
  if (Date.now() - lastAuthMs > 10 * 60 * 1000) await reauth(headers)
}

async function ensureClient(headers) {
  const neededDomains = [...new Set(UI_BUTTON_SCENARIOS
    .map((scenario) => extractHost(scenario.payload?.target))
    .filter(Boolean))]
    .sort()
  const payload = {
    name: CLIENT_NAME,
    domains: JSON.stringify(neededDomains),
    tech_stack: JSON.stringify(['nginx', 'github-actions']),
    ip_ranges: JSON.stringify([]),
  }
  const list = await api('/api/clients', { headers })
  if (!list.response.ok || !Array.isArray(list.body)) {
    throw new Error(`clients list failed (${list.response.status}): ${JSON.stringify(list.body)}`)
  }
  const existing = list.body.find((client) => client.name === CLIENT_NAME)

  if (existing?.id) {
    const updated = await api(`/api/clients/${existing.id}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    })
    if (!updated.response.ok) {
      throw new Error(`client update failed (${updated.response.status}): ${JSON.stringify(updated.body)}`)
    }
    return existing.id
  }

  const created = await api('/api/clients', {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  })
  if (!created.response.ok) {
    throw new Error(`client create failed (${created.response.status}): ${JSON.stringify(created.body)}`)
  }

  const listAgain = await api('/api/clients', { headers })
  if (!listAgain.response.ok || !Array.isArray(listAgain.body)) {
    throw new Error(`clients list-after-create failed (${listAgain.response.status})`)
  }
  const createdClient = listAgain.body.find((client) => client.name === CLIENT_NAME)
  if (!createdClient?.id) throw new Error('smoke client not found after create')
  return createdClient.id
}

async function waitForJob(headers, jobId) {
  const startedAt = Date.now()
  let last = null
  while (Date.now() - startedAt < POLL_TIMEOUT_MS) {
    await sleep(1000)
    const { response, body } = await api(`/api/jobs/${jobId}`, { headers })
    if (!response.ok) {
      last = { status: `http_${response.status}`, error: JSON.stringify(body) }
      // Token likely expired mid-run — refresh and keep polling with the new bearer.
      if (response.status === 401) await reauth(headers)
      continue
    }
    last = body
    if (terminalStatus(body?.status)) return body
  }
  throw new Error(`job ${jobId} timed out; last=${JSON.stringify(last)}`)
}

function summarize(scenario, jobId, job) {
  return {
    source: scenario.source,
    kind: scenario.kind,
    engine: scenario.payload?.engine || null,
    target: scenario.payload?.target || null,
    jobId,
    status: job?.status || 'unknown',
    error: terminalErrorText(job) || null,
    findingsCount: job?.findings_count ?? job?.result_json?.findings?.length ?? null,
  }
}

async function runScenario(headers, clientId, scenario) {
  if (scenario.kind === 'top-tier-health-probe') {
    const body = { ...scenario.payload, client_id: clientId }
    const queued = await retryScanIntake(
      () => api('/api/engines/top-tier/health-probe', {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
      }),
      {
        label: `${scenario.source} (top-tier-health-probe)`,
        statusOf: (r) => r.response.status,
        retryAfterOf: (r) => r.body?.retry_after_seconds,
      },
    )
    if (!queued.response.ok) {
      throw new Error(`top-tier health probe queue failed (${queued.response.status}): ${JSON.stringify(queued.body)}`)
    }
    const jobId = queued.body?.job_id
    if (!jobId) throw new Error('top-tier health probe missing job_id')
    const job = await waitForJob(headers, jobId)
    return summarize(scenario, jobId, job)
  }

  const ciParams = ENGINE_CI_PARAMS[scenario.payload?.engine] || {}
  const body = { ...ciParams, ...scenario.payload, client_id: clientId, timeout: 45 }
  const queued = await retryScanIntake(
    () => api('/api/command-center/scan', {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    }),
    {
      label: scenario.source || scenario.payload?.engine || 'ui-scan',
      statusOf: (r) => r.response.status,
      retryAfterOf: (r) => r.body?.retry_after_seconds,
    },
  )
  if (!queued.response.ok) {
    throw new Error(`scan queue failed (${queued.response.status}): ${JSON.stringify(queued.body)}`)
  }
  const jobId = queued.body?.job_id
  if (!jobId) throw new Error('scan queue missing job_id')
  const job = await waitForJob(headers, jobId)
  return summarize(scenario, jobId, job)
}

/** Authoritative production engine ids from GET /api/engines/production (empty Set = fail-open). */
async function fetchProductionEngineIds(headers) {
  try {
    const { response, body } = await api('/api/engines/production', { headers })
    if (!response.ok || !Array.isArray(body?.production)) return new Set()
    return new Set(body.production.filter((id) => typeof id === 'string'))
  } catch {
    return new Set()
  }
}

async function main() {
  const headers = {
    'content-type': 'application/json',
    authorization: '',
  }
  await reauth(headers)
  const clientId = await ensureClient(headers)

  // Validate auto-discovered scenarios against the authoritative production engine roster. The
  // hub-page heuristic can extract a string that is not a real scan engine (e.g. a DB engine name
  // or a module label); submitting it yields a 400 "unknown engine" that is a false negative, not a
  // real wiring gap (those pages' true buttons use real, separately-covered engines). Skip any
  // auto-discovered scenario whose engine is not in `GET /api/engines/production`. Curated base
  // scenarios are always kept.
  const roster = await fetchProductionEngineIds(headers)
  const skipped = []
  const scenarios = UI_BUTTON_SCENARIOS.filter((s) => {
    if (!s.autoDiscovered || s.kind !== 'command-center-scan') return true
    if (roster.size === 0 || roster.has(s.payload?.engine)) return true
    skipped.push({ source: s.source, engine: s.payload?.engine, reason: 'engine not in production roster (heuristic mis-extraction)' })
    return false
  })
  for (const s of skipped) console.log(JSON.stringify({ skipped: true, ...s }))

  const results = []
  const failures = []

  for (const scenario of scenarios) {
    await ensureFreshAuth(headers)
    try {
      const summary = await runScenario(headers, clientId, scenario)
      results.push(summary)
      const failed = String(summary.status).toLowerCase() !== 'completed' || isCatalogOnlyError(summary)
      if (failed) failures.push(summary)
      console.log(JSON.stringify(summary))
    } catch (error) {
      const summary = {
        source: scenario.source,
        kind: scenario.kind,
        engine: scenario.payload?.engine || null,
        target: scenario.payload?.target || null,
        jobId: null,
        status: 'failed_to_execute',
        error: error instanceof Error ? error.message : String(error),
        findingsCount: null,
      }
      results.push(summary)
      failures.push(summary)
      console.log(JSON.stringify(summary))
    }
    await sleep(1200)
  }

  const output = {
    baseUrl: BASE_URL,
    loginEmail: LOGIN_EMAIL,
    clientId,
    totalScenarios: results.length,
    failures: failures.length,
    placeholderDisplayNotes: UI_PLACEHOLDER_NOTES,
    results,
  }

  if (failures.length > 0) {
    console.error(JSON.stringify(output, null, 2))
    process.exit(1)
  }

  console.log(JSON.stringify(output, null, 2))
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error))
  process.exit(1)
})