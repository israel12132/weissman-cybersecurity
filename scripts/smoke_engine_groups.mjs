import { GROUP_SMOKE_PLAN, collectApprovedDomains } from './lib/group_smoke_plan.mjs'
import { retryScanIntake, retryLogin } from './lib/scan_intake.mjs'

const BASE_URL = process.env.WEISSMAN_SMOKE_BASE_URL || 'http://127.0.0.1:18000'
const LOGIN_EMAIL = process.env.WEISSMAN_SMOKE_LOGIN_EMAIL || process.env.WEISSMAN_ADMIN_EMAIL || 'admin@localhost'
const LOGIN_PASSWORD = process.env.WEISSMAN_SMOKE_LOGIN_PASSWORD || process.env.WEISSMAN_ADMIN_PASSWORD || 'changeme'
const TENANT_SLUG = process.env.WEISSMAN_TENANT_SLUG || 'default'
const CLIENT_NAME = process.env.WEISSMAN_SMOKE_CLIENT_NAME || 'CI Smoke Client'
const POLL_TIMEOUT_MS = Number(process.env.WEISSMAN_SMOKE_POLL_TIMEOUT_MS || 180000)
const BETWEEN_RUN_DELAY_MS = Number(process.env.WEISSMAN_SMOKE_DELAY_MS || 1200)

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function collectApprovedDomainsFromPlan(plan) {
  return collectApprovedDomains(plan)
}

function terminalStatus(status) {
  // `dead` = dead-letter queue (permanent failure); treat it as terminal so a dead-lettered job
  // surfaces its real error immediately instead of being polled until the client timeout.
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
  const { timeoutMs = 30_000, ...fetchOptions } = options
  const response = await fetch(`${BASE_URL}${path}`, {
    ...fetchOptions,
    signal: AbortSignal.timeout(timeoutMs),
  })
  const rawText = await response.text()
  let body = rawText
  try {
    body = rawText ? JSON.parse(rawText) : null
  } catch {}
  return { response, body, rawText }
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

async function requireOwner(headers) {
  const { response, body } = await api('/api/auth/me', { headers })
  if (!response.ok) {
    throw new Error(`auth/me failed (${response.status}): ${JSON.stringify(body)}`)
  }
  if (body?.can_create_clients !== true) {
    throw new Error(
      `smoke login ${LOGIN_EMAIL} cannot create clients ` +
        `(can_create_clients=${body?.can_create_clients}, is_owner=${body?.is_owner}, ` +
        `is_superadmin=${body?.is_superadmin}, role=${body?.role}). ` +
        'Client lifecycle is owner-only; use WEISSMAN_ADMIN_EMAIL (promoted is_superadmin), ' +
        'not a staff bootstrap user.',
    )
  }
}

async function listClients(headers) {
  const { response, body } = await api('/api/clients', { headers })
  if (!response.ok || !Array.isArray(body)) {
    throw new Error(`clients list failed (${response.status}): ${JSON.stringify(body)}`)
  }
  return body
}

async function ensureClient(headers) {
  const approvedDomains = collectApprovedDomainsFromPlan(GROUP_SMOKE_PLAN)
  let clients = await listClients(headers)
  let client = clients.find((entry) => entry.name === CLIENT_NAME)

  const payload = {
    name: CLIENT_NAME,
    domains: JSON.stringify(approvedDomains),
    tech_stack: JSON.stringify(['nginx', 'github-actions']),
    ip_ranges: JSON.stringify([]),
  }

  if (!client) {
    const created = await api('/api/clients', {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    })
    if (!created.response.ok) {
      throw new Error(
        `client create failed (${created.response.status}): ${JSON.stringify(created.body)}` +
          (created.response.status === 403
            ? ' Log in as the platform owner (WEISSMAN_ADMIN_EMAIL), not a staff user.'
            : ''),
      )
    }
    clients = await listClients(headers)
    client = clients.find((entry) => entry.name === CLIENT_NAME)
  } else {
    const updated = await api(`/api/clients/${client.id}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    })
    if (!updated.response.ok) {
      throw new Error(`client update failed (${updated.response.status}): ${JSON.stringify(updated.body)}`)
    }
    clients = await listClients(headers)
    client = clients.find((entry) => entry.name === CLIENT_NAME)
  }

  if (!client?.id) {
    throw new Error('smoke client missing after create/update')
  }
  return client
}

async function submitScan(headers, clientId, entry) {
  // Ride out transient scan-intake shedding (429 rate_limited / 503 load_shed), honoring the
  // server's Retry-After hint. See scripts/lib/scan_intake.mjs for the contract.
  const result = await retryScanIntake(
    () => api('/api/command-center/scan', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        // Forward the per-engine CI bounding params the plan carries (e.g.
        // PKI_TLS_CI_PARAMS / BGP_DNS_CI_PARAMS disable the unbounded live-network
        // fan-out that otherwise runs for minutes). These are read live from the
        // scan body as job_params; without them the slow engines blow the 180s
        // poll window. Spread first so the identity/timeout fields below always win.
        ...(entry.params && typeof entry.params === 'object' ? entry.params : {}),
        engine: entry.engine,
        client_id: clientId,
        target: entry.target,
        timeout: 45,
      }),
    }),
    {
      label: `${entry.group}/${entry.engine}`,
      statusOf: (r) => r.response.status,
      retryAfterOf: (r) => r.body?.retry_after_seconds,
    },
  )
  if (result.response.ok) {
    return result.body
  }
  throw new Error(`scan submit failed for ${entry.group}/${entry.engine} (${result.response.status}): ${JSON.stringify(result.body)}`)
}

async function waitForJob(headers, jobId) {
  const startedAt = Date.now()
  let latest = null
  while (Date.now() - startedAt < POLL_TIMEOUT_MS) {
    await sleep(1000)
    const { response, body } = await api(`/api/jobs/${jobId}`, { headers })
    if (response.status === 401) {
      headers.authorization = `Bearer ${await login()}`
      continue
    }
    if (!response.ok) {
      latest = { status: `http_${response.status}`, error: JSON.stringify(body) }
      continue
    }
    latest = body
    if (terminalStatus(body?.status)) {
      return body
    }
  }
  throw new Error(`job ${jobId} timed out after ${POLL_TIMEOUT_MS}ms; last=${JSON.stringify(latest)}`)
}

function summariseJob(entry, jobId, job) {
  return {
    group: entry.group,
    engine: entry.engine,
    target: entry.target,
    jobId,
    status: job?.status || 'unknown',
    findingsCount: job?.findings_count ?? job?.result_json?.findings?.length ?? null,
    error: terminalErrorText(job) || null,
  }
}

function record(results, failures, summary) {
  results.push(summary)
  if (String(summary?.status).toLowerCase() !== 'completed' || isCatalogOnlyError(summary)) {
    failures.push(summary)
  }
  console.log(JSON.stringify(summary))
}

async function runEngine(headers, clientId, entry) {
  const queued = await submitScan(headers, clientId, entry)
  const jobId = queued?.job_id
  if (!jobId) {
    throw new Error(`missing job_id in response: ${JSON.stringify(queued)}`)
  }
  const job = await waitForJob(headers, jobId)
  return summariseJob(entry, jobId, job)
}

async function main() {
  const token = await login()
  const headers = {
    'content-type': 'application/json',
    authorization: `Bearer ${token}`,
  }
  await requireOwner(headers)
  const client = await ensureClient(headers)
  const results = []
  const failures = []

  for (const entry of GROUP_SMOKE_PLAN) {
    // One login for the whole sweep. CI sets WEISSMAN_ACCESS_TOKEN_MINUTES=120 so
    // the bearer outlives 14 engines. Re-login-per-engine hits the production
    // per-IP login limiter (8/min, Redis token-bucket) and 429s the rest of the
    // run; re-auth only on 401 if a token ever does expire.
    try {
      record(results, failures, await runEngine(headers, client.id, entry))
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error)
      if (/\(401\)/.test(msg)) {
        try {
          headers.authorization = `Bearer ${await login()}`
          record(results, failures, await runEngine(headers, client.id, entry))
        } catch (retryErr) {
          record(results, failures, {
            group: entry.group,
            engine: entry.engine,
            target: entry.target,
            jobId: null,
            status: 'failed_to_execute',
            findingsCount: null,
            error: retryErr instanceof Error ? retryErr.message : String(retryErr),
          })
        }
      } else {
        record(results, failures, {
          group: entry.group,
          engine: entry.engine,
          target: entry.target,
          jobId: null,
          status: 'failed_to_execute',
          findingsCount: null,
          error: msg,
        })
      }
    }
    await sleep(BETWEEN_RUN_DELAY_MS)
  }

  const output = {
    baseUrl: BASE_URL,
    loginEmail: LOGIN_EMAIL,
    clientId: client.id,
    total: results.length,
    failures: failures.length,
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