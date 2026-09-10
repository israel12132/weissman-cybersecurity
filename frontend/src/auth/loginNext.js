/**
 * Safe post-login destination. Only same-origin Command Center paths.
 * Rejects protocol-relative, absolute, and API/login loops.
 */
export function sanitizeNextPath(raw) {
  if (raw == null) return null
  let next = String(raw).trim()
  if (!next) return null
  try {
    next = decodeURIComponent(next)
  } catch {
    return null
  }
  next = next.trim()
  if (!next.startsWith('/') || next.startsWith('//') || next.includes('://')) return null
  if (next.startsWith('/api') || next.startsWith('/ws') || next.startsWith('/login')) return null
  if (next.startsWith('/signup') || next.startsWith('/install')) return null
  if (next.startsWith('/command-center')) {
    return next
  }
  // CC-relative paths from React Router (basename stripped).
  if (next === '/' || next.startsWith('/')) {
    return `/command-center${next === '/' ? '/' : next}`
  }
  return null
}

export function commandCenterHomeForRole(result) {
  if (result?.is_superadmin === true) return '/command-center/'
  const role = String(result?.role || '').trim().toLowerCase()
  return role === 'ceo' ? '/command-center/' : '/command-center/operations'
}

export function resolvePostLoginHref(result, nextRaw) {
  return sanitizeNextPath(nextRaw) || commandCenterHomeForRole(result)
}

export function flagshipLoginHref(fromPathname = '') {
  const next = sanitizeNextPath(fromPathname.startsWith('/command-center')
    ? fromPathname
    : `/command-center${fromPathname || '/'}`)
  if (!next || next === '/command-center/' || next === '/command-center') return '/login'
  return `/login?next=${encodeURIComponent(next)}`
}

export const WORKSPACE_SLUG_KEY = 'weissman_workspace_slug'

export function readStoredWorkspaceSlug() {
  if (typeof localStorage === 'undefined') return 'default'
  try {
    const v = localStorage.getItem(WORKSPACE_SLUG_KEY)
    const slug = String(v || '').trim()
    return slug || 'default'
  } catch {
    return 'default'
  }
}

export function writeStoredWorkspaceSlug(slug) {
  if (typeof localStorage === 'undefined') return
  try {
    const v = String(slug || '').trim() || 'default'
    localStorage.setItem(WORKSPACE_SLUG_KEY, v)
  } catch {
    /* privacy mode */
  }
}

export function normalizeMfaCode(raw) {
  return String(raw || '').replace(/\D/g, '').slice(0, 6)
}
