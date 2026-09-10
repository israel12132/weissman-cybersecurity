import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { apiUrl } from '@cc/lib/apiBase'

export default function Signup() {
  const { t } = useTranslation()
  const [status, setStatus] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const onSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setStatus('')
    const fd = new FormData(e.target)
    if (!fd.get('accept_terms')) {
      setError(t('signup.terms'))
      return
    }
    setBusy(true)
    try {
      const r = await fetch(apiUrl('/api/auth/signup'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          workspace_name: fd.get('workspace_name'),
          email: fd.get('email'),
          password: fd.get('password'),
          accept_terms: true,
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (r.status === 202 || r.ok) {
        setStatus(d.detail || t('contact.success'))
        e.target.reset()
      } else {
        setError(d.detail || t('contact.error'))
      }
    } catch {
      setError(t('contact.error'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mx-auto max-w-md px-5 py-16">
      <p className="text-[11px] uppercase tracking-[0.2em] text-cyan-300/80">{t('signup.kicker')}</p>
      <h1 className="mt-3 font-display text-3xl font-semibold">{t('signup.title')}</h1>
      <p className="mt-3 text-sm text-white/55">{t('signup.lead')}</p>
      <form onSubmit={onSubmit} className="mt-8 space-y-4">
        <label className="block text-xs uppercase tracking-wide text-white/40">
          {t('signup.workspace')}
          <input name="workspace_name" required minLength={2} className="mt-2 w-full rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3 text-sm text-white outline-none focus:border-cyan-400/40" />
        </label>
        <label className="block text-xs uppercase tracking-wide text-white/40">
          {t('signup.email')}
          <input name="email" type="email" required className="mt-2 w-full rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3 text-sm text-white outline-none focus:border-cyan-400/40" />
        </label>
        <label className="block text-xs uppercase tracking-wide text-white/40">
          {t('signup.password')}
          <input name="password" type="password" required minLength={12} autoComplete="new-password" className="mt-2 w-full rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3 text-sm text-white outline-none focus:border-cyan-400/40" />
        </label>
        <label className="flex items-start gap-2 text-sm text-white/60">
          <input type="checkbox" name="accept_terms" className="mt-1" />
          <span>
            {t('signup.terms')}{' '}
            <a href="/terms.html" className="text-cyan-300">{t('auth.terms')}</a>
            {' · '}
            <a href="/privacy.html" className="text-cyan-300">{t('auth.privacy')}</a>
          </span>
        </label>
        <button type="submit" disabled={busy} className="w-full rounded-xl bg-cyan-400 py-3 text-sm font-semibold text-[#041018] disabled:opacity-50">
          {busy ? t('signup.creating') : t('signup.submit')}
        </button>
        {status && <p className="text-sm text-cyan-200" role="status">{status}</p>}
        {error && <p className="text-sm text-rose-300" role="alert">{error}</p>}
      </form>
      <p className="mt-8 text-center text-sm text-white/45">
        <Link to="/login" className="text-cyan-300">{t('signup.signin')}</Link>
      </p>
    </div>
  )
}
