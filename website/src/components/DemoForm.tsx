import { useState, type FormEvent } from 'react'
import { submitDemoRequest } from '../lib/submitDemoRequest'
import { Button } from './Button'
import { company } from '../content/site'

type FieldErr = Partial<Record<'name' | 'email' | 'company' | 'message', string>>

export function DemoForm() {
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle')
  const [detail, setDetail] = useState('')
  const [mailto, setMailto] = useState<string | undefined>()
  const [errors, setErrors] = useState<FieldErr>({})

  function validate(fd: FormData): FieldErr {
    const e: FieldErr = {}
    const name = String(fd.get('name') || '').trim()
    const email = String(fd.get('email') || '').trim()
    const companyName = String(fd.get('company') || '').trim()
    const message = String(fd.get('message') || '').trim()
    if (name.length < 2) e.name = 'Enter your name.'
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) e.email = 'Enter a valid work email.'
    if (companyName.length < 2) e.company = 'Enter an organisation name.'
    if (message.length < 10) e.message = 'Tell us briefly what you want to see (10+ characters).'
    return e
  }

  async function onSubmit(ev: FormEvent<HTMLFormElement>) {
    ev.preventDefault()
    const fd = new FormData(ev.currentTarget)
    const next = validate(fd)
    setErrors(next)
    if (Object.keys(next).length) return
    setStatus('loading')
    setDetail('')
    setMailto(undefined)
    const result = await submitDemoRequest({
      name: String(fd.get('name')),
      email: String(fd.get('email')),
      company: String(fd.get('company')),
      role: String(fd.get('role') || ''),
      message: String(fd.get('message')),
    })
    if (result.ok) {
      setStatus('success')
      setDetail(result.detail)
      ev.currentTarget.reset()
    } else {
      setStatus('error')
      setDetail(result.detail)
      setMailto(result.mailto)
    }
  }

  return (
    <form onSubmit={onSubmit} noValidate className="surface space-y-4 p-6">
      <Field id="name" label="Name" error={errors.name} required />
      <Field id="email" label="Work email" type="email" error={errors.email} required />
      <Field id="company" label="Organisation" error={errors.company} required />
      <Field id="role" label="Role" />
      <Field id="message" label="What should we cover?" textarea error={errors.message} required />
      <Button type="submit" disabled={status === 'loading'}>
        {status === 'loading' ? 'Sending…' : 'Request a demo'}
      </Button>
      <p role="status" aria-live="polite" className={`text-sm ${status === 'success' ? 'text-ops' : status === 'error' ? 'text-danger' : 'text-dim'}`}>
        {detail}
        {mailto && (
          <>
            {' '}
            <a className="underline" href={mailto}>
              Email {company.emails.sales}
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
  textarea,
  error,
  required,
}: {
  id: string
  label: string
  type?: string
  textarea?: boolean
  error?: string
  required?: boolean
}) {
  const cls =
    'w-full rounded-[12px] border border-[var(--line)] bg-deep px-3 py-2.5 text-ink placeholder:text-dim'
  return (
    <div>
      <label className="mb-1 block text-xs uppercase tracking-[0.14em] text-dim" htmlFor={id}>
        {label}
      </label>
      {textarea ? (
        <textarea id={id} name={id} rows={4} required={required} className={cls} aria-invalid={Boolean(error)} />
      ) : (
        <input id={id} name={id} type={type} required={required} className={`${cls} min-h-11`} aria-invalid={Boolean(error)} />
      )}
      {error && <p className="mt-1 text-sm text-danger">{error}</p>}
    </div>
  )
}
