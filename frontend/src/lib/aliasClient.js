import { useEffect, useState } from 'react'
import { apiFetch } from '../utils/apiFetch'

/** Append `client_id` query param for tenant-scoped API aliases. */
export function withClientId(path, clientId) {
  if (clientId == null || clientId === '') return path
  const sep = path.includes('?') ? '&' : '?'
  return `${path}${sep}client_id=${encodeURIComponent(String(clientId))}`
}

function clientsUnavailableError(detail) {
  const err = new Error(detail || 'clients unavailable')
  err.code = 'clients_unavailable'
  return err
}

/** First client in tenant (ORDER BY id), matching backend alias resolution. */
export async function fetchFirstTenantClientId({ signal } = {}) {
  const data = await apiFetch('/api/clients?limit=1', { signal })
  if (data?.ok === false || data?.unavailable) {
    throw clientsUnavailableError(data.detail)
  }
  const list = Array.isArray(data) ? data : data?.clients || []
  if (list.length === 0) return null
  const id = Number(list[0]?.id)
  return Number.isFinite(id) && id > 0 ? id : null
}

/** React hook: resolves first tenant client id for alias API routes. */
export function useFirstTenantClientId() {
  const [clientId, setClientId] = useState(null)
  const [loading, setLoading] = useState(true)
  const [unavailable, setUnavailable] = useState(false)

  useEffect(() => {
    let cancelled = false
    const ac = new AbortController()
    fetchFirstTenantClientId({ signal: ac.signal })
      .then((id) => {
        if (!cancelled) {
          setClientId(id)
          setUnavailable(false)
          setLoading(false)
        }
      })
      .catch((e) => {
        if (e?.name === 'AbortError' || ac.signal.aborted || cancelled) return
        setClientId(null)
        setUnavailable(true)
        setLoading(false)
      })
    return () => {
      cancelled = true
      ac.abort()
    }
  }, [])

  return { clientId, loading, unavailable }
}
