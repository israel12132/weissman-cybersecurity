import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { apiUrl } from '@cc/lib/apiBase'

export default function Contact() {
  const { t } = useTranslation()
  const [status, setStatus] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const onSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setStatus('')
    setBusy(true)
    const fd = new FormData(e.target)
    try {
      const r = await fetch(apiUrl('/api/public/contact'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: fd.get('name'),
          email: fd.get('email'),
          company: fd.get('company'),
          message: fd.get('message'),
          source: 'flagship',
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
    <div className="mx-auto max-w-xl px-5 py-16">
      <p className="text-[11px] uppercase tracking-[0.2em] text-cyan-300/80">{t('contact.kicker')}</p>
      <h1 className="mt-3 font-display text-4xl font-semibold">{t('contact.title')}</h1>
      <p className="mt-4 text-white/55">{t('contact.lead')}</p>
      <form onSubmit={onSubmit} className="mt-10 space-y-4">
        <Field name="name" label={t('contact.name')} required />
        <Field name="email" label={t('contact.email')} type="email" required />
        <Field name="company" label={t('contact.company')} />
        <label className="block text-xs uppercase tracking-wide text-white/40">
          {t('contact.message')}
          <textarea name="message" required rows={5} className="mt-2 w-full rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3 text-sm text-white outline-none focus:border-cyan-400/40" />
        </label>
        <button type="submit" disabled={busy} className="w-full rounded-xl bg-cyan-400 py-3 text-sm font-semibold text-[#041018] disabled:opacity-50">
          {busy ? t('contact.sending') : t('contact.submit')}
        </button>
        {status && <p className="text-sm text-cyan-200" role="status">{status}</p>}
        {error && <p className="text-sm text-rose-300" role="alert">{error}</p>}
      </form>
    </div>
  )
}

function Field({ name, label, type = 'text', required }) {
  return (
    <label className="block text-xs uppercase tracking-wide text-white/40">
      {label}
      <input name={name} type={type} required={required} className="mt-2 w-full rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3 text-sm text-white outline-none focus:border-cyan-400/40" />
    </label>
  )
}
