import { useEffect, useState } from 'react'
import { apiFetch } from './apiBase'
import { useAuthOptional } from '../context/AuthContext'
import { assignedClientId } from './clientScope'

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

/** React hook: resolves bound / first tenant client id for alias API routes. */
export function useFirstTenantClientId() {
  const auth = useAuthOptional()
  const assigned = assignedClientId(auth?.session)
  const [clientId, setClientId] = useState(assigned)
  const [loading, setLoading] = useState(assigned == null)

  useEffect(() => {
    if (assigned != null) {
      setClientId(assigned)
      setLoading(false)
      return undefined
    }
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
  }, [assigned])

  return { clientId, loading }
}
