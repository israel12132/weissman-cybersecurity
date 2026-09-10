import { apiUrl } from '@cc/lib/apiBase'

async function getJson(path) {
  const r = await fetch(apiUrl(path), { credentials: 'omit', signal: AbortSignal.timeout(8000) })
  if (!r.ok) {
    const err = new Error(`${path} ${r.status}`)
    err.status = r.status
    throw err
  }
  return r.json()
}

export async function fetchPlatformPulse() {
  return getJson('/api/public/platform-pulse')
}

export async function fetchEngineCatalog() {
  return getJson('/api/public/engine-catalog')
}
