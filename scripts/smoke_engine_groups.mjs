import { GROUP_SMOKE_PLAN, collectApprovedDomains } from './lib/group_smoke_plan.mjs'

const BASE_URL = process.env.WEISSMAN_SMOKE_BASE_URL || 'http://127.0.0.1:18000'
const LOGIN_EMAIL = process.env.WEISSMAN_SMOKE_LOGIN_EMAIL || process.env.WEISSMAN_ADMIN_EMAIL || 'admin@localhost'
const LOGIN_PASSWORD = process.env.WEISSMAN_SMOKE_LOGIN_PASSWORD || process.env.WEISSMAN_ADMIN_PASSWORD || 'changeme'
const TENANT_SLUG = process.env.WEISSMAN_TENANT_SLUG || 'default'
const CLIENT_NAME = process.env.WEISSMAN_SMOKE_CLIENT_NAME || 'CI Smoke Client'
const POLL_TIMEOUT_MS = Number(process.env.WEISSMAN_SMOKE_POLL_TIMEOUT_MS || 180000)
const SUBMIT_RETRIES = Number(process.env.WEISSMAN_SMOKE_SUBMIT_RETRIES || 3)
const BETWEEN_RUN_DELAY_MS = Number(process.env.WEISSMAN_SMOKE_DELAY_MS || 1200)

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function collectApprovedDomainsFromPlan(plan) {
  return collectApprovedDomains(plan)
}

function terminalStatus(status) {
  return ['completed', 'failed', 'error', 'cancelled'].includes(String(status || '').toLowerCase())
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
  return { response, body, rawText }
}

async function login() {
  const { response, body } = await api('/api/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: LOGIN_EMAIL, password: LOGIN_PASSWORD, tenant_slug: TENANT_SLUG }),
  })
  if (!response.ok || !body?.access_token) {
    throw new Error(`login failed (${response.status}): ${JSON.stringify(body)}`)
  }
  return body.access_token
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
      throw new Error(`client create failed (${created.response.status}): ${JSON.stringify(created.body)}`)
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
  let attempt = 0
  while (attempt < SUBMIT_RETRIES) {
    attempt += 1
    const result = await api('/api/command-center/scan', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        engine: entry.engine,
        client_id: clientId,
        target: entry.target,
        timeout: 45,
      }),
    })
    if (result.response.ok) {
      return result.body
    }
    if (result.response.status !== 429) {
      throw new Error(`scan submit failed for ${entry.group}/${entry.engine} (${result.response.status}): ${JSON.stringify(result.body)}`)
    }
    await sleep(1500 * attempt)
  }
  throw new Error(`scan submit rate-limited for ${entry.group}/${entry.engine} after ${SUBMIT_RETRIES} attempts`)
}

async function waitForJob(headers, jobId) {
  const startedAt = Date.now()
  let latest = null
  while (Date.now() - startedAt < POLL_TIMEOUT_MS) {
    await sleep(1000)
    const { response, body } = await api(`/api/jobs/${jobId}`, { headers })
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

async function main() {
  const token = await login()
  const headers = {
    'content-type': 'application/json',
    authorization: `Bearer ${token}`,
  }
  const client = await ensureClient(headers)
  const results = []
  const failures = []

  for (const entry of GROUP_SMOKE_PLAN) {
    try {
      const queued = await submitScan(headers, client.id, entry)
      const jobId = queued?.job_id
      if (!jobId) {
        throw new Error(`missing job_id in response: ${JSON.stringify(queued)}`)
      }
      const job = await waitForJob(headers, jobId)
      const summary = summariseJob(entry, jobId, job)
      results.push(summary)
      if (String(job?.status).toLowerCase() !== 'completed' || isCatalogOnlyError(job)) {
        failures.push(summary)
      }
      console.log(JSON.stringify(summary))
    } catch (error) {
      const summary = {
        group: entry.group,
        engine: entry.engine,
        target: entry.target,
        jobId: null,
        status: 'failed_to_execute',
        findingsCount: null,
        error: error instanceof Error ? error.message : String(error),
      }
      results.push(summary)
      failures.push(summary)
      console.log(JSON.stringify(summary))
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