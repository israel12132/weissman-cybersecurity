import { createContext, useContext, useState, useCallback, useEffect } from 'react'
import {
  apiUrl,
  setStoredAccessToken,
  clearStoredAccessToken,
} from '../lib/apiBase'
import { apiFetch } from '../utils/apiFetch'
import { effectiveRole, sessionRoleRank, sessionHasRole } from '../lib/roles'
import {
  assignedClientId,
  canCreateClients,
  canDeleteClients,
  isClientUser,
  isPlatformOwner,
  isStaffUser,
} from '../lib/clientScope'
import { queryClient } from '../lib/queryClient'
import { invalidateAgentFleetCache } from '../hooks/useAgentFleetStatus'
import { invalidateEngineCapabilitiesCache } from '../lib/useEngineCapabilities'
import { invalidateEngineHistorySummary } from '../lib/engineHistorySummary'

const AuthContext = createContext(null)

function computeIsCeo(session) {
  return sessionHasRole(session, 'ceo')
}

export function AuthProvider({ children }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [session, setSession] = useState(null)

  const refreshSession = useCallback(async () => {
    // A throttled (429) or hiccuping (5xx / network) session probe says NOTHING about
    // whether the user is actually logged out — only a definitive 401/403 does.
    // utils/apiFetch throws on any non-2xx (429 surfaced immediately with err.status /
    // err.retryAfter; a 401 only after lib/apiBase's single token-refresh retry has already
    // failed underneath). So retry transient failures here, honor Retry-After, and clear the
    // session ONLY on a real 401/403. Dropping a live session on a transient 429 bounces the
    // user to /login, whose own boot requests then re-burst the API — a self-amplifying
    // throttle storm. Never log a valid user out on a throttle.
    for (let attempt = 0; attempt < 4; attempt += 1) {
      let data
      try {
        data = await apiFetch('/api/auth/me', { method: 'GET' })
      } catch (err) {
        const status = err?.status
        if (status === 401 || status === 403) {
          setSession(null)
          setIsAuthenticated(false)
          return null
        }
        if (status === 429 || status === undefined || status >= 500) {
          // Throttled / server hiccup / network blip — transient. Honor Retry-After, else back off.
          const ra = Number(err?.retryAfter)
          const waitMs = Number.isFinite(ra) && ra > 0 ? Math.min(ra * 1000, 3000) : 300 * (attempt + 1)
          await new Promise((res) => setTimeout(res, waitMs))
          continue
        }
        // Any other 4xx is not an auth signal we understand — don't nuke a live session.
        return null
      }
      // On success utils/apiFetch returns the parsed JSON. The instanceof Response guard
      // covers the (contract-impossible) non-JSON 200 so a Response is never mistaken for
      // a session payload.
      if (!data || data instanceof Response || data.ok !== true) {
        setSession(null)
        setIsAuthenticated(false)
        return null
      }
      setSession(data)
      setIsAuthenticated(true)
      return data
    }
    // Exhausted transient retries: do NOT forcibly clear an existing session — leave auth
    // state untouched so a throttled probe never logs a valid user out.
    return null
  }, [])

  const checkAuth = useCallback(async () => {
    setIsLoading(true)
    await refreshSession()
    setIsLoading(false)
  }, [refreshSession])

  useEffect(() => {
    checkAuth()
  }, [checkAuth])

  const login = useCallback(
    async (email, password, tenantSlug) => {
      try {
        const payload = {
          email: email.trim(),
          password,
        }
        const slug = typeof tenantSlug === 'string' ? tenantSlug.trim() : ''
        if (slug) payload.tenant_slug = slug
        const r = await fetch(apiUrl('/api/login'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify(payload),
        })
        const data = await r.json().catch(() => ({}))
        if (r.ok && data.mfa_required && data.mfa_token) {
          return { ok: false, mfa_required: true, mfa_token: data.mfa_token, detail: data.detail }
        }
        if (r.ok && data.ok) {
          if (data.access_token) setStoredAccessToken(data.access_token)
          setSession({
            ok: true,
            user_id: data.user_id,
            tenant_id: data.tenant_id,
            role: data.role,
            is_superadmin: data.is_superadmin === true,
            assigned_client_id: data.assigned_client_id ?? null,
          })
          setIsAuthenticated(true)
          await refreshSession()
          return {
            ok: true,
            role: data.role,
            is_superadmin: data.is_superadmin === true,
            is_owner: data.is_superadmin === true || String(data.role || '').toLowerCase() === 'ceo',
          }
        }
        // BLOCKER #3 — server returns 403 + code=mfa_enrollment_required when tenant
        // policy demands MFA but user hasn't enrolled.
        if (r.status === 403 && data.code === 'mfa_enrollment_required') {
          clearStoredAccessToken()
          return {
            ok: false,
            code: 'mfa_enrollment_required',
            detail: data.detail || 'MFA enrollment required by tenant policy.',
          }
        }
        clearStoredAccessToken()
        return {
          ok: false,
          detail: data.detail || data.error || `Login failed (HTTP ${r.status})`,
        }
      } catch (_) {
        return { ok: false, detail: 'Network error' }
      }
    },
    [refreshSession],
  )

  const verifyMfa = useCallback(
    async (mfaToken, code) => {
      try {
        const r = await fetch(apiUrl('/api/auth/mfa/verify'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ mfa_token: mfaToken, code: code.trim() }),
        })
        const data = await r.json().catch(() => ({}))
        if (r.ok && data.ok) {
          if (data.access_token) setStoredAccessToken(data.access_token)
          setSession({
            ok: true,
            user_id: data.user_id,
            tenant_id: data.tenant_id,
            role: data.role,
            is_superadmin: data.is_superadmin === true,
            assigned_client_id: data.assigned_client_id ?? null,
          })
          setIsAuthenticated(true)
          await refreshSession()
          return {
            ok: true,
            role: data.role,
            is_superadmin: data.is_superadmin === true,
            is_owner: data.is_superadmin === true || String(data.role || '').toLowerCase() === 'ceo',
          }
        }
        return { ok: false, detail: data.detail || 'Invalid code' }
      } catch (_) {
        return { ok: false, detail: 'Network error' }
      }
    },
    [refreshSession],
  )

  const logout = useCallback(async () => {
    try {
      await fetch(apiUrl('/api/logout'), { method: 'POST', credentials: 'include' })
    } catch (_) {
      /* still clear local state */
    }
    clearStoredAccessToken()
    // Tear down every cross-request cache so the next login in this same tab
    // (shared/kiosk workstation) can never be served the previous tenant's data:
    //  - the react-query cache (tenant-agnostic keys, up to gcTime),
    //  - the hand-rolled module singletons (agent fleet, engine capabilities,
    //    engine history summary) which otherwise live for the tab's lifetime.
    try {
      queryClient.clear()
    } catch (_) {
      /* query cache teardown is best-effort — non-fatal */
    }
    invalidateAgentFleetCache()
    invalidateEngineCapabilitiesCache()
    invalidateEngineHistorySummary()
    // Clear tab-scoped app state that can carry tenant data across a re-login on
    // a shared/kiosk workstation (the notification inbox persists findings).
    try {
      sessionStorage.removeItem('weissman_notifications')
    } catch (_) {
      /* sessionStorage may be unavailable — non-fatal */
    }
    setIsAuthenticated(false)
    setSession(null)
  }, [])

  const isCeo = computeIsCeo(session)
  const role = effectiveRole(session)
  const roleRank = sessionRoleRank(session)
  const hasRole = useCallback((minRole) => sessionHasRole(session, minRole), [session])
  const isOwner = isPlatformOwner(session)
  const isClientPortal = isClientUser(session)
  const isStaff = isStaffUser(session)
  const assignedClient = assignedClientId(session)
  const allowCreateClients = canCreateClients(session)
  const allowDeleteClients = canDeleteClients(session)

  const value = {
    isAuthenticated,
    isLoading,
    session,
    isCeo,
    isOwner,
    isStaff,
    isClientUser: isClientPortal,
    assignedClientId: assignedClient,
    canCreateClients: allowCreateClients,
    canDeleteClients: allowDeleteClients,
    role,
    roleRank,
    hasRole,
    login,
    verifyMfa,
    logout,
    checkAuth,
    refreshSession,
  }
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}

/** Safe when ClientProvider is mounted without AuthProvider (unit tests). */
export function useAuthOptional() {
  return useContext(AuthContext)
}

/**
 * Convenience hook for role checks in pages/components.
 * `usePermissions().hasRole('admin')` → boolean.
 */
export function usePermissions() {
  const {
    role,
    roleRank,
    hasRole,
    isCeo,
    isOwner,
    isStaff,
    isClientUser: isClientPortal,
    canCreateClients: allowCreate,
    canDeleteClients: allowDelete,
    assignedClientId: assigned,
    session,
  } = useAuth()
  return {
    role,
    roleRank,
    hasRole,
    isCeo,
    isOwner,
    isStaff,
    isClientUser: isClientPortal,
    canCreateClients: allowCreate,
    canDeleteClients: allowDelete,
    assignedClientId: assigned,
    isSuperadmin: session?.is_superadmin === true,
  }
}
