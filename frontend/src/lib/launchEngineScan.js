import { apiFetch } from './apiBase'
import { apiFetchScanIntake } from './scanIntakeRetry'
import { buildScanPayload, mergeScanBody, normalizeIntegrations } from './engineClientPrefill'

/** Fetch normalized client integrations (credentials, OAST, LLM, etc.). */
export async function fetchClientIntegrations(clientId) {
  if (clientId == null || clientId === '') return null
  const r = await apiFetch(`/api/clients/${clientId}/integrations`)
  if (!r.ok) return null
  return normalizeIntegrations(await r.json().catch(() => null))
}

/**
 * Build scan body and POST /api/command-center/scan.
 * Integrations are fetched automatically when clientId is set and integrations omitted.
 */
export async function launchEngineScan({
  engineId,
  clientId,
  target,
  extraParams = {},
  samplePayload = {},
  integrations = undefined,
  timeout,
} = {}) {
  let ints = integrations
  if (ints === undefined && clientId != null && clientId !== '') {
    ints = await fetchClientIntegrations(clientId)
  }
  const body = buildScanPayload(engineId, {
    clientId,
    target,
    integrations: ints,
    samplePayload,
    extraParams,
  })
  if (timeout != null) body.timeout = timeout

  const r = await apiFetchScanIntake('/api/command-center/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const data = await r.json().catch(() => ({}))
  return { ok: r.ok, status: r.status, data, body }
}

/**
 * POST a hub-built scan body with integration defaults merged in.
 * Use in Command Center pages that already have buildScanBody / buildBody.
 */
export async function postEngineScan(customBody, integrations = undefined) {
  const engineId = customBody?.engine
  if (!engineId) throw new Error('postEngineScan: body.engine is required')
  let ints = integrations
  if (ints === undefined && customBody.client_id != null) {
    ints = await fetchClientIntegrations(customBody.client_id)
  }
  const body = mergeScanBody(engineId, customBody, ints)
  const r = await apiFetchScanIntake('/api/command-center/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const data = await r.json().catch(() => ({}))
  return { ok: r.ok, status: r.status, data, body }
}
