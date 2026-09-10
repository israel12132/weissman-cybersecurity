import { useCallback, useEffect } from 'react'
import { useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { apiUrl, setStoredAccessToken } from '@cc/lib/apiBase'
import LoginGate from '@cc/auth/LoginGate'
import { resolvePostLoginHref } from '@cc/auth/loginNext'
import { probeExistingSession } from '../lib/session'

async function login(email, password, tenantSlug = 'default') {
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
    return { ok: true, role: data.role, is_superadmin: data.is_superadmin === true }
  }
  if (r.status === 403 && data.code === 'mfa_enrollment_required') {
    return { ok: false, code: 'mfa_enrollment_required', detail: data.detail }
  }
  if (r.status === 429 && data.code === 'login_locked') {
    return { ok: false, code: 'login_locked', retry_after_seconds: data.retry_after_seconds, detail: data.detail }
  }
  return { ok: false, detail: data.detail || data.error || `Login failed (HTTP ${r.status})` }
}

async function verifyMfa(mfaToken, code) {
  const r = await fetch(apiUrl('/api/auth/mfa/verify'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ mfa_token: mfaToken, code: String(code).trim() }),
  })
  const data = await r.json().catch(() => ({}))
  if (r.ok && data.ok) {
    if (data.access_token) setStoredAccessToken(data.access_token)
    return { ok: true, role: data.role, is_superadmin: data.is_superadmin === true }
  }
  return { ok: false, detail: data.detail || 'Invalid code' }
}

export default function Login() {
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const next = params.get('next')

  useEffect(() => {
    document.title = t('meta.login')
  }, [t])

  useEffect(() => {
    let cancelled = false
    probeExistingSession().then((session) => {
      if (!cancelled && session?.ok) {
        window.location.replace(resolvePostLoginHref(session, next))
      }
    })
    return () => {
      cancelled = true
    }
  }, [next])

  const onSuccess = useCallback(
    (result) => {
      window.location.assign(resolvePostLoginHref(result, next))
    },
    [next],
  )

  return (
    <LoginGate
      login={login}
      verifyMfa={verifyMfa}
      isAuthenticated={false}
      onSuccess={onSuccess}
      homeHref="/"
      signupHref="/signup"
      statusHref="/status"
    />
  )
}
