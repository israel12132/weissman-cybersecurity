import React, { createContext, useContext, useState, useCallback, useEffect } from 'react'
import {
  apiUrl,
  apiFetch,
  setStoredAccessToken,
  clearStoredAccessToken,
} from '../lib/apiBase'

const AuthContext = createContext(null)

function computeIsCeo(session) {
  if (!session || session.ok === false) return false
  if (session.is_superadmin === true) return true
  const r = (session.role || '').toString().trim().toLowerCase()
  return r === 'ceo'
}

export function AuthProvider({ children }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [session, setSession] = useState(null)

  const refreshSession = useCallback(async () => {
    try {
      const r = await apiFetch('/api/auth/me', { method: 'GET' })
      if (!r.ok) {
        setSession(null)
        setIsAuthenticated(false)
        return null
      }
      const data = await r.json().catch(() => ({}))
      if (data.ok !== true) {
        setSession(null)
        setIsAuthenticated(false)
        return null
      }
      setSession(data)
      setIsAuthenticated(true)
      return data
    } catch (_) {
      setSession(null)
      setIsAuthenticated(false)
      return null
    }
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
    async (email, password, tenantSlug = 'default') => {
      try {
        const r = await fetch(apiUrl('/api/login'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({
            email: email.trim(),
            password,
            tenant_slug: (tenantSlug || 'default').trim() || 'default',
          }),
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
          })
          setIsAuthenticated(true)
          await refreshSession()
          return { ok: true }
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
          })
          setIsAuthenticated(true)
          await refreshSession()
          return { ok: true }
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
    setIsAuthenticated(false)
    setSession(null)
  }, [])

  const isCeo = computeIsCeo(session)

  const value = {
    isAuthenticated,
    isLoading,
    session,
    isCeo,
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
