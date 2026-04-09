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
        clearStoredAccessToken()
        return { ok: false, detail: data.detail || 'Invalid email or password' }
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
