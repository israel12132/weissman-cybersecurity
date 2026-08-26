import { useState, type FormEvent } from 'react'
import { submitDemoRequest } from '../lib/submitDemoRequest'
import { company } from '../content/site'
import { useI18n } from '../i18n'
import { Button } from './Button'
import { TextWithLtr } from './Ltr'

type FieldErr = Partial<Record<'name' | 'email' | 'company' | 'message', string>>

export function DemoForm() {
  const { t } = useI18n()
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
    if (name.length < 2) e.name = t('demoForm.errName')
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) e.email = t('demoForm.errEmail')
    if (companyName.length < 2) e.company = t('demoForm.errOrg')
    if (message.length < 10) e.message = t('demoForm.errMessage')
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
      setDetail(t('demoForm.success'))
      ev.currentTarget.reset()
    } else {
      setStatus('error')
      setDetail(result.status === 503 ? t('demoForm.smtpOff') : result.status === 0 ? t('demoForm.network') : t('demoForm.fail'))
      setMailto(result.mailto)
    }
  }

  return (
    <form onSubmit={onSubmit} noValidate className="surface space-y-4 p-6">
      <Field id="name" label={t('demoForm.name')} error={errors.name} required />
      <Field id="email" label={t('demoForm.email')} type="email" error={errors.email} required />
      <Field id="company" label={t('demoForm.organisation')} error={errors.company} required />
      <Field id="role" label={t('demoForm.role')} />
      <Field id="message" label={t('demoForm.message')} textarea error={errors.message} required />
      <Button type="submit" disabled={status === 'loading'}>
        {status === 'loading' ? t('demoForm.sending') : t('demoForm.submit')}
      </Button>
      <p role="status" aria-live="polite" className={`text-sm ${status === 'success' ? 'text-ops' : status === 'error' ? 'text-danger' : 'text-dim'}`}>
        {detail ? <TextWithLtr template={detail} value={company.emails.sales} /> : null}
        {mailto && (
          <>
            {' '}
            <a className="underline" href={mailto}>
              <TextWithLtr template={t('demoForm.emailSales')} value={company.emails.sales} />
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
  const cls = 'w-full rounded-[12px] border border-[var(--line)] bg-deep px-3 py-2.5 text-ink placeholder:text-dim'
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

