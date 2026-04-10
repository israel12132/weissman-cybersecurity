import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../../context/AuthContext'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [tenantSlug, setTenantSlug] = useState('default')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const { login, isAuthenticated } = useAuth()
  const navigate = useNavigate()

  useEffect(() => {
    if (isAuthenticated) navigate('/', { replace: true })
  }, [isAuthenticated, navigate])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setSubmitting(true)
    try {
      const result = await login(email, password, tenantSlug)
      if (result.ok) {
        navigate('/', { replace: true })
        return
      }
      setError(result.detail || 'Access Denied')
    } catch (_) {
      setError('Access Denied')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div
      className="min-h-screen flex flex-col items-center justify-center bg-[#050505] relative overflow-hidden"
      style={{ background: '#050505' }}
    >
      {/* Pulsing neon cyan line */}
      <div
        className="absolute bottom-0 left-0 right-0 h-0.5 animate-pulse"
        style={{
          background: 'linear-gradient(90deg, transparent, #22d3ee, transparent)',
          boxShadow: '0 0 20px #22d3ee, 0 0 40px rgba(34, 211, 238, 0.3)',
        }}
      />

      <div className="w-full max-w-sm px-6">
        <h1 className="text-center text-xl font-light tracking-[0.35em] text-white/90 mb-12 uppercase">
          Weissman Cybersecurity
        </h1>

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label htmlFor="tenant" className="block text-[10px] uppercase tracking-widest text-[#6b7280] mb-2 font-mono">
              Tenant slug
            </label>
            <input
              id="tenant"
              type="text"
              autoComplete="organization"
              value={tenantSlug}
              onChange={(e) => setTenantSlug(e.target.value)}
              className="w-full px-4 py-3 rounded bg-[#0a0a0a] border border-[#222] text-white placeholder-[#4b5563] focus:outline-none focus:border-[#22d3ee] focus:ring-1 focus:ring-[#22d3ee]/50 transition-colors font-mono text-sm"
              placeholder="default"
            />
          </div>
          <div>
            <label htmlFor="email" className="block text-[10px] uppercase tracking-widest text-[#6b7280] mb-2 font-mono">
              Email
            </label>
            <input
              id="email"
              type="email"
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="w-full px-4 py-3 rounded bg-[#0a0a0a] border border-[#222] text-white placeholder-[#4b5563] focus:outline-none focus:border-[#22d3ee] focus:ring-1 focus:ring-[#22d3ee]/50 transition-colors font-mono text-sm"
              placeholder="admin@weissman.local"
            />
          </div>
          <div>
            <label htmlFor="password" className="block text-[10px] uppercase tracking-widest text-[#6b7280] mb-2 font-mono">
              Password
            </label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full px-4 py-3 rounded bg-[#0a0a0a] border border-[#222] text-white placeholder-[#4b5563] focus:outline-none focus:border-[#22d3ee] focus:ring-1 focus:ring-[#22d3ee]/50 transition-colors font-mono text-sm"
              placeholder="••••••••"
            />
          </div>

          {error && (
            <p id="login-error-message" className="text-sm font-mono text-red-500 text-center py-2 border border-red-500/30 bg-red-500/5 rounded">
              {error}
            </p>
          )}

          <button
            id="login-submit-btn"
            type="submit"
            disabled={submitting}
            className="w-full py-3.5 rounded font-semibold text-sm tracking-widest uppercase transition-all border-2 border-[#22d3ee] bg-[#22d3ee]/10 text-[#22d3ee] hover:bg-[#22d3ee]/20 focus:outline-none focus:ring-2 focus:ring-[#22d3ee] focus:ring-offset-2 focus:ring-offset-[#050505] disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {submitting ? 'Authenticating…' : 'Authenticate'}
          </button>
        </form>

        <div className="mt-8 space-y-3">
          <p className="text-center text-[10px] uppercase tracking-widest text-[#6b7280] font-mono">Enterprise SSO</p>
          <button
            id="login-oidc-btn"
            type="button"
            className="w-full py-3 rounded text-sm font-mono border border-[#374151] text-[#9ca3af] hover:border-[#22d3ee]/50 hover:text-[#22d3ee] transition-colors"
            onClick={() => {
              const t = encodeURIComponent((tenantSlug || 'default').trim() || 'default')
              window.location.href = `${window.location.origin}/api/auth/oidc/begin?tenant_slug=${t}&idp_name=enterprise`
            }}
          >
            Login with OIDC (IdP name: enterprise)
          </button>
          <button
            id="login-saml-btn"
            type="button"
            className="w-full py-3 rounded text-sm font-mono border border-[#374151] text-[#9ca3af] hover:border-[#22d3ee]/50 hover:text-[#22d3ee] transition-colors"
            onClick={() => {
              const t = encodeURIComponent((tenantSlug || 'default').trim() || 'default')
              window.location.href = `${window.location.origin}/api/auth/saml/begin?tenant_slug=${t}&idp_name=enterprise_saml`
            }}
          >
            Login with SAML (IdP name: enterprise_saml)
          </button>
        </div>
      </div>
    </div>
  )
}
