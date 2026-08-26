import { useState, type FormEvent } from 'react'
import { submitSignup } from '../lib/submitSignup'
import { Button } from './Button'

export function SignupForm() {
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
    if (workspace_name.length < 2) next.workspace_name = 'Workspace name must be 2–80 characters.'
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) next.email = 'Enter a valid work email.'
    if (password.length < 12) next.password = 'Use at least 12 characters with letters and numbers or symbols.'
    else if (!/[A-Za-z]/.test(password) || !/[^A-Za-z]/.test(password)) {
      next.password = 'Mix letters with numbers or symbols.'
    }
    if (!accept) next.accept_terms = 'You must accept the Terms of Service and Privacy Policy.'
    setErrors(next)
    if (Object.keys(next).length) return

    setStatus('loading')
    setDetail('')
    setVerifyUrl(undefined)
    const result = await submitSignup({ workspace_name, email, password, accept_terms: true })
    if (result.ok) {
      setStatus('success')
      setDetail(result.detail)
      setVerifyUrl(result.verifyUrl)
      ev.currentTarget.reset()
    } else {
      setStatus('error')
      setDetail(result.detail)
    }
  }

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-4">
      <Field id="workspace_name" label="Workspace name" error={errors.workspace_name} />
      <Field id="email" label="Work email" type="email" error={errors.email} />
      <Field id="password" label="Password" type="password" error={errors.password} hint="Min 12 characters · mix letters and numbers/symbols" />
      <label className="flex items-start gap-3 text-sm text-muted">
        <input id="accept_terms" name="accept_terms" type="checkbox" className="mt-1" />
        <span>
          I agree to the{' '}
          <a className="text-accent underline" href="/terms.html" target="_blank" rel="noopener noreferrer">
            Terms of Service
          </a>{' '}
          and{' '}
          <a className="text-accent underline" href="/privacy.html" target="_blank" rel="noopener noreferrer">
            Privacy Policy
          </a>
          .
        </span>
      </label>
      {errors.accept_terms && <p className="text-sm text-danger">{errors.accept_terms}</p>}
      <Button type="submit" className="w-full" disabled={status === 'loading'}>
        {status === 'loading' ? 'Creating…' : 'Create workspace'}
      </Button>
      <p role="status" aria-live="polite" className={`text-center text-sm ${status === 'success' ? 'text-ops' : status === 'error' ? 'text-danger' : ''}`}>
        {detail}
        {verifyUrl && (
          <>
            {' '}
            <a className="block text-xs text-accent" href={verifyUrl}>
              Dev verify link →
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
