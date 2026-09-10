import { useState, type FormEvent } from 'react'
import { submitSignup } from '../lib/submitSignup'
import { company } from '../content/site'
import { useI18n } from '../i18n'
import { A } from './A'
import { Button } from './Button'
import { TextWithLtr } from './Ltr'

export function SignupForm() {
  const { t } = useI18n()
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle')
  const [detail, setDetail] = useState('')
  const [verifyUrl, setVerifyUrl] = useState<string>()
  const [errors, setErrors] = useState<Record<string, string>>({})

  async function onSubmit(ev: FormEvent<HTMLFormElement>) {
    ev.preventDefault()
    const fd = new FormData(ev.currentTarget)
    const workspace_name = String(fd.get('workspace_name') || '').trim()
    const email = String(fd.get('email') || '').trim()
    const password = String(fd.get('password') || '')
    const accept = Boolean(fd.get('accept_terms'))
    const next: Record<string, string> = {}
    if (workspace_name.length < 2) next.workspace_name = t('signupForm.errWorkspace')
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) next.email = t('signupForm.errEmail')
    if (password.length < 12) next.password = t('signupForm.errPasswordLen')
    else if (!/[A-Za-z]/.test(password) || !/[^A-Za-z]/.test(password)) {
      next.password = t('signupForm.errPasswordMix')
    }
    if (!accept) next.accept_terms = t('signupForm.errTerms')
    setErrors(next)
    if (Object.keys(next).length) return

    setStatus('loading')
    setDetail('')
    setVerifyUrl(undefined)
    const result = await submitSignup({ workspace_name, email, password, accept_terms: true })
    if (result.ok) {
      setStatus('success')
      setDetail(t('signupForm.success'))
      setVerifyUrl(result.verifyUrl)
      ev.currentTarget.reset()
    } else {
      setStatus('error')
      setDetail(result.status === 503 ? t('signupForm.gated') : result.status === 0 ? t('signupForm.network') : t('signupForm.fail'))
    }
  }

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-4">
      <Field id="workspace_name" label={t('signupForm.workspace')} error={errors.workspace_name} />
      <Field id="email" label={t('signupForm.email')} type="email" error={errors.email} />
      <Field id="password" label={t('signupForm.password')} type="password" error={errors.password} hint={t('signupForm.hint')} />
      <label className="flex items-start gap-3 text-sm text-muted">
        <input id="accept_terms" name="accept_terms" type="checkbox" className="mt-1" />
        <span>
          {t('signupForm.agreeBefore')}{' '}
          <A className="text-accent underline" href="/terms.html" target="_blank" rel="noopener noreferrer">
            {t('signupForm.terms')}
          </A>{' '}
          {t('signupForm.and')}{' '}
          <A className="text-accent underline" href="/privacy.html" target="_blank" rel="noopener noreferrer">
            {t('signupForm.privacy')}
          </A>
          .
        </span>
      </label>
      {errors.accept_terms && <p className="text-sm text-danger">{errors.accept_terms}</p>}
      <Button type="submit" className="w-full" disabled={status === 'loading'}>
        {status === 'loading' ? t('signupForm.creating') : t('signupForm.submit')}
      </Button>
      <p role="status" aria-live="polite" className={`text-center text-sm ${status === 'success' ? 'text-ops' : status === 'error' ? 'text-danger' : ''}`}>
        {detail ? <TextWithLtr template={detail} value={company.emails.sales} /> : null}
        {verifyUrl && (
          <>
            {' '}
            <a className="block text-xs text-accent" href={verifyUrl} dir="ltr">
              {t('signupForm.verify')}
            </a>
          </>
        )}
      </p>
    </form>
  )
}

function Field({
  id,
  label,
  type = 'text',
  error,
  hint,
}: {
  id: string
  label: string
  type?: string
  error?: string
  hint?: string
}) {
  return (
    <div>
      <label className="mb-1 block text-xs uppercase tracking-[0.14em] text-dim" htmlFor={id}>
        {label}
      </label>
      <input
        id={id}
        name={id}
        type={type}
        className="min-h-11 w-full rounded-[12px] border border-[var(--line)] bg-deep px-3 text-ink"
        aria-invalid={Boolean(error)}
      />
      {hint && <p className="mt-1 text-xs text-dim">{hint}</p>}
      {error && <p className="mt-1 text-sm text-danger">{error}</p>}
    </div>
  )
}
