import { useEffect, useState } from 'react'
import { apiFetch } from './apiBase'

/** Append `client_id` query param for tenant-scoped API aliases. */
export function withClientId(path, clientId) {
  if (clientId == null || clientId === '') return path
  const sep = path.includes('?') ? '&' : '?'
  return `${path}${sep}client_id=${encodeURIComponent(String(clientId))}`
}

/** First client in tenant (ORDER BY id), matching backend alias resolution. */
export async function fetchFirstTenantClientId() {
  const r = await apiFetch('/api/clients')
  if (!r.ok) return null
  const data = await r.json().catch(() => [])
  const list = Array.isArray(data) ? data : data?.clients || []
  if (list.length === 0) return null
  const id = Number(list[0]?.id)
  return Number.isFinite(id) && id > 0 ? id : null
}

/** React hook: resolves first tenant client id for alias API routes. */
export function useFirstTenantClientId() {
  const [clientId, setClientId] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    fetchFirstTenantClientId()
      .then((id) => {
        if (!cancelled) {
          setClientId(id)
          setLoading(false)
        }
      })
      .catch(() => {
        if (!cancelled) {
          setClientId(null)
          setLoading(false)
        }
      })
    return () => {
      cancelled = true
    }
  }, [])

  return { clientId, loading }
}
