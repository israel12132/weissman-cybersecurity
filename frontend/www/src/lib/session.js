import { apiUrl } from '@cc/lib/apiBase'

/** Session payload when a Command Center cookie/token is already valid; otherwise null. */
export async function probeExistingSession() {
  try {
    const r = await fetch(apiUrl('/api/auth/me'), { credentials: 'include' })
    if (!r.ok) return null
    const d = await r.json().catch(() => null)
    if (!d || d.ok !== true) return null
    return d
  } catch {
    return null
  }
}
