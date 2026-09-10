import React, { useCallback, useEffect, useId, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Eye, EyeOff, Loader2, AlertCircle, Shield, CheckCircle2, Globe2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import Logo from '../components/Logo'
import Button from '../components/ui/Button'
import { apiUrl } from '../lib/apiBase'
import {
  normalizeMfaCode,
  readStoredWorkspaceSlug,
  writeStoredWorkspaceSlug,
} from './loginNext.js'

const formVariants = {
  initial: { opacity: 0, x: 16 },
  animate: { opacity: 1, x: 0, transition: { duration: 0.32, ease: [0.22, 1, 0.36, 1] } },
  exit: { opacity: 0, x: -16, transition: { duration: 0.2, ease: [0.22, 1, 0.36, 1] } },
}

function AuthSpinner({ className = '' }) {
  return <Loader2 className={`h-4 w-4 animate-spin ${className}`} aria-hidden />
}

function StepIndicator({ step, t }) {
  const steps = [
    { key: 'credentials', label: t('auth.step_credentials') },
    { key: 'mfa', label: t('auth.step_mfa') },
  ]
  const current = step === 'mfa' ? 2 : 1
  return (
    <nav aria-label={t('auth.step_indicator', { current, total: 2 })} className="mb-8">
      <ol className="flex items-center gap-2">
        {steps.map((s, i) => {
          const num = i + 1
          const active = num === current
          const done = num < current
          return (
            <li key={s.key} className="flex flex-1 items-center gap-2">
              <div className="flex items-center gap-2 min-w-0">
                <span
                  className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-xs font-medium transition-colors ${
                    active
                      ? 'bg-cyan-400/15 text-cyan-300 ring-1 ring-cyan-400/40'
                      : done
                        ? 'bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/30'
                        : 'bg-white/5 text-white/35 ring-1 ring-white/10'
                  }`}
                  aria-current={active ? 'step' : undefined}
                >
                  {done ? <CheckCircle2 className="h-3.5 w-3.5" aria-hidden /> : num}
                </span>
                <span className={`hidden sm:block truncate text-xs tracking-wide ${active ? 'text-white/90' : 'text-white/40'}`}>
                  {s.label}
                </span>
              </div>
              {i < steps.length - 1 && (
                <div className={`mx-1 h-px flex-1 ${done ? 'bg-cyan-400/30' : 'bg-white/10'}`} aria-hidden />
              )}
            </li>
          )
        })}
      </ol>
    </nav>
  )
}

function AuthAlert({ variant = 'error', children }) {
  const styles =
    variant === 'warning'
      ? 'border-amber-500/25 bg-amber-500/[0.07] text-amber-100/90'
      : variant === 'success'
        ? 'border-emerald-500/25 bg-emerald-500/[0.07] text-emerald-100/90'
        : 'border-rose-400/20 bg-rose-500/[0.06] text-rose-100/90'
  return (
    <div role="alert" aria-live="polite" className={`flex items-start gap-3 rounded-xl border px-4 py-3 backdrop-blur-sm ${styles}`}>
      <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 opacity-80" aria-hidden />
      <div className="text-sm leading-relaxed">{children}</div>
    </div>
  )
}

const FloatingInput = React.forwardRef(function FloatingInput(
  {
    id, label, type = 'text', value, onChange, required, autoComplete, inputMode,
    placeholder, disabled, endAdornment, className = '', inputClassName = '', onFocus, onBlur,
    onKeyDown, onKeyUp,
  },
  ref,
) {
  const [focused, setFocused] = useState(false)
  const floated = focused || (value != null && String(value).length > 0)
  return (
    <div className={`relative ${className}`}>
      <label
        htmlFor={id}
        className={`pointer-events-none absolute start-4 z-10 origin-start transition-all duration-200 ${
          floated
            ? 'top-2.5 text-[10px] font-medium uppercase tracking-[0.14em] text-cyan-400/80'
            : 'top-1/2 -translate-y-1/2 text-sm text-white/45'
        }`}
      >
        {label}
      </label>
      <input
        ref={ref}
        id={id}
        type={type}
        value={value}
        onChange={onChange}
        required={required}
        autoComplete={autoComplete}
        inputMode={inputMode}
        placeholder={floated ? placeholder : undefined}
        disabled={disabled}
        onFocus={(e) => { setFocused(true); onFocus?.(e) }}
        onBlur={(e) => { setFocused(false); onBlur?.(e) }}
        onKeyDown={onKeyDown}
        onKeyUp={onKeyUp}
        className={`peer w-full rounded-xl border bg-white/[0.03] px-4 pb-3 pt-7 text-sm text-white outline-none transition-all duration-200 placeholder:text-white/25 disabled:cursor-not-allowed disabled:opacity-50 ${
          endAdornment ? 'pe-12' : ''
        } ${
          focused
            ? 'border-cyan-400/50 shadow-[0_0_0_3px_rgba(34,211,238,0.12),0_0_24px_rgba(34,211,238,0.08)]'
            : 'border-white/10 hover:border-white/20'
        } ${inputClassName}`}
      />
      {endAdornment}
    </div>
  )
})

function MfaBoxes({ value, onChange, disabled, inputRef, id, label }) {
  const digits = (value + '      ').slice(0, 6).split('')
  return (
    <label htmlFor={id} className="flex cursor-text justify-center gap-2" dir="ltr">
      {digits.map((d, i) => (
        <span
          key={i}
          className={`flex h-12 w-10 items-center justify-center rounded-lg border font-mono text-lg ${
            d.trim()
              ? 'border-cyan-400/40 bg-cyan-400/10 text-white'
              : 'border-white/10 bg-white/[0.03] text-white/30'
          }`}
          aria-hidden
        >
          {d.trim() || '·'}
        </span>
      ))}
      <input
        ref={inputRef}
        id={id}
        type="text"
        inputMode="numeric"
        autoComplete="one-time-code"
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(normalizeMfaCode(e.target.value))}
        onPaste={(e) => {
          e.preventDefault()
          onChange(normalizeMfaCode(e.clipboardData.getData('text')))
        }}
        aria-label={label || 'Authentication code'}
        className="sr-only"
      />
    </label>
  )
}

function BrandPanel({ t, pulse }) {
  const engineLabel = pulse?.production_engines
    ? t('auth.trust_engines_live', { count: pulse.production_engines })
    : t('auth.trust_engines_checking')
  const trustItems = [
    { icon: Shield, label: engineLabel },
    { icon: CheckCircle2, label: t('auth.trust_soc2') },
    { icon: Globe2, label: t('auth.trust_region') },
  ]
  return (
    <aside className="relative hidden min-h-[100dvh] flex-col justify-between overflow-hidden lg:flex lg:w-[52%] xl:w-[55%]">
      <div className="pointer-events-none absolute inset-0 bg-[#030712]" aria-hidden>
        <div
          className="absolute -left-1/4 top-0 h-[70%] w-[70%] rounded-full opacity-40 blur-3xl"
          style={{ background: 'radial-gradient(circle, rgba(34,211,238,0.22) 0%, transparent 70%)', animation: 'auth-mesh-drift 18s ease-in-out infinite' }}
        />
        <div
          className="absolute -bottom-1/4 -right-1/4 h-[80%] w-[80%] rounded-full opacity-30 blur-3xl"
          style={{ background: 'radial-gradient(circle, rgba(14,165,233,0.18) 0%, transparent 65%)', animation: 'auth-mesh-drift 22s ease-in-out infinite reverse' }}
        />
        <div
          className="absolute inset-0 opacity-[0.035]"
          style={{
            backgroundImage: 'linear-gradient(rgba(255,255,255,0.8) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.8) 1px, transparent 1px)',
            backgroundSize: '48px 48px',
          }}
        />
      </div>
      <div className="relative z-10 flex flex-1 flex-col justify-center px-12 xl:px-16 py-16">
        <a href="/" className="mb-10 inline-flex w-fit" aria-label={t('auth.back_to_site')}>
          <Logo size={48} glow />
        </a>
        <h1 className="max-w-md font-display text-3xl font-semibold leading-tight tracking-tight text-white xl:text-4xl">
          {t('auth.brand_tagline')}
        </h1>
        <p className="mt-5 max-w-lg text-base leading-relaxed text-white/55">
          {t('auth.brand_story')}
        </p>
        <ul className="mt-10 flex flex-wrap gap-3" aria-label={t('auth.trust_label')}>
          {trustItems.map(({ icon: Icon, label }) => (
            <li key={label} className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.04] px-4 py-2 text-xs font-medium tracking-wide text-white/70 backdrop-blur-sm">
              <Icon className="h-3.5 w-3.5 text-cyan-400/80" aria-hidden />
              {label}
            </li>
          ))}
        </ul>
      </div>
      <p className="relative z-10 px-12 xl:px-16 pb-10 text-[11px] tracking-wide text-white/30">
        {t('auth.secure_connection')}
      </p>
    </aside>
  )
}

/**
 * Shared cinematic login gate used by the flagship `/login` site and `/command-center/login`.
 */
export default function LoginGate({
  login,
  verifyMfa,
  isAuthenticated,
  onSuccess,
  languageSwitcher,
  homeHref = '/',
  signupHref = '/signup',
  statusHref = '/status',
}) {
  const { t, i18n } = useTranslation()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [showWorkspace, setShowWorkspace] = useState(false)
  const [tenantSlug, setTenantSlug] = useState(readStoredWorkspaceSlug)
  const [showSso, setShowSso] = useState(false)
  const [error, setError] = useState('')
  const [errorCode, setErrorCode] = useState('')
  const [lockSeconds, setLockSeconds] = useState(0)
  const [submitting, setSubmitting] = useState(false)
  const [mfaToken, setMfaToken] = useState(null)
  const [mfaCode, setMfaCode] = useState('')
  const [capsLock, setCapsLock] = useState(false)
  const [pulse, setPulse] = useState(null)
  const [verifiedSignup, setVerifiedSignup] = useState(false)
  const mfaInputRef = useRef(null)
  const emailInputRef = useRef(null)
  const errorRegionId = useId()

  useEffect(() => {
    if (typeof window === 'undefined') return undefined
    const q = new URLSearchParams(window.location.search)
    const tenant = String(q.get('tenant') || '').trim()
    if (tenant) {
      setTenantSlug(tenant)
      setShowWorkspace(true)
    }
    if (q.get('verified') === '1') setVerifiedSignup(true)
    return undefined
  }, [])

  useEffect(() => {
    let cancelled = false
    fetch(apiUrl('/api/public/platform-pulse'), { credentials: 'omit', signal: AbortSignal.timeout(8000) })
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => { if (!cancelled && d?.ok) setPulse(d) })
      .catch(() => { if (!cancelled) setPulse(null) })
    return () => { cancelled = true }
  }, [])

  useEffect(() => {
    if (!lockSeconds) return undefined
    const id = window.setInterval(() => {
      setLockSeconds((s) => (s <= 1 ? 0 : s - 1))
    }, 1000)
    return () => window.clearInterval(id)
  }, [lockSeconds])

  useEffect(() => {
    if (mfaToken && mfaInputRef.current) mfaInputRef.current.focus()
    else if (!mfaToken && emailInputRef.current) emailInputRef.current.focus()
  }, [mfaToken])

  useEffect(() => {
    const onKey = (e) => setCapsLock(Boolean(e.getModifierState?.('CapsLock')))
    window.addEventListener('keydown', onKey)
    window.addEventListener('keyup', onKey)
    return () => {
      window.removeEventListener('keydown', onKey)
      window.removeEventListener('keyup', onKey)
    }
  }, [])

  const onCaps = useCallback((e) => {
    setCapsLock(Boolean(e.getModifierState?.('CapsLock')))
  }, [])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setErrorCode('')
    setSubmitting(true)
    try {
      const result = await login(email, password, tenantSlug)
      if (result.ok) {
        writeStoredWorkspaceSlug(tenantSlug)
        onSuccess(result)
        return
      }
      if (result.mfa_required && result.mfa_token) {
        setMfaToken(result.mfa_token)
        setError('')
        return
      }
      if (result.code === 'mfa_enrollment_required') {
        setErrorCode('mfa_enrollment_required')
        setError(result.detail || t('auth.mfa_enrollment_required'))
        return
      }
      if (result.code === 'login_locked') {
        const secs = Number(result.retry_after_seconds) || 60
        setLockSeconds(secs)
        setErrorCode('login_locked')
        setError(t('auth.login_locked', { seconds: secs }))
        return
      }
      setError(result.detail || t('auth.access_denied'))
    } catch (_) {
      setError(t('auth.network_error'))
    } finally {
      setSubmitting(false)
    }
  }

  const handleMfaSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setSubmitting(true)
    try {
      const result = await verifyMfa(mfaToken, mfaCode)
      if (result.ok) {
        writeStoredWorkspaceSlug(tenantSlug)
        onSuccess(result)
        return
      }
      setError(result.detail || t('auth.mfa_invalid_code'))
    } catch (_) {
      setError(t('auth.mfa_invalid_code'))
    } finally {
      setSubmitting(false)
    }
  }

  const beginSso = (path) => {
    const slug = encodeURIComponent((tenantSlug || 'default').trim() || 'default')
    window.location.href = apiUrl(`${path}?tenant_slug=${slug}&idp_name=${path.includes('saml') ? 'enterprise_saml' : 'enterprise'}`)
  }

  const step = mfaToken ? 'mfa' : 'credentials'
  const currentLang = (i18n.resolvedLanguage || i18n.language || 'en').slice(0, 2)

  if (isAuthenticated) {
    return (
      <div className="flex min-h-[100dvh] items-center justify-center bg-[#030712] px-6 text-white">
        <div className="text-center">
          <AuthSpinner className="mx-auto mb-4 text-cyan-300" />
          <p className="text-sm text-white/60">{t('auth.entering_command_center')}</p>
        </div>
      </div>
    )
  }

  return (
    <div className="relative min-h-[100dvh] bg-[#030712] text-white">
      <style>{`
        @keyframes auth-mesh-drift {
          0%, 100% { transform: translate(0, 0) scale(1); }
          33% { transform: translate(4%, -3%) scale(1.04); }
          66% { transform: translate(-3%, 2%) scale(0.97); }
        }
      `}</style>
      <div className="flex min-h-[100dvh] flex-col lg:flex-row">
        <BrandPanel t={t} pulse={pulse} />
        <main className="relative flex flex-1 flex-col">
          <div className="pointer-events-none absolute inset-x-0 top-0 h-64 bg-gradient-to-b from-cyan-500/[0.06] to-transparent lg:hidden" aria-hidden />
          <header className="relative z-10 flex items-center justify-between px-6 pt-6 lg:justify-end lg:px-10 lg:pt-8">
            <a href={homeHref} className="lg:hidden" aria-label={t('auth.back_to_site')}>
              <Logo compact size={36} glow />
            </a>
            {languageSwitcher || (
              <div className="inline-flex items-center gap-1 rounded-lg border border-white/10 bg-black/30 p-1" role="group" aria-label={t('auth.language')}>
                {['en', 'he'].map((code) => (
                  <Button
                    key={code}
                    variant="unstyled"
                    type="button"
                    onClick={() => i18n.changeLanguage(code)}
                    className={`px-2 py-1 rounded-md text-[11px] font-mono ${
                      currentLang === code
                        ? 'bg-cyan-500/20 text-cyan-200 border border-cyan-500/40'
                        : 'text-white/55 hover:text-white/85 border border-transparent'
                    }`}
                    aria-pressed={currentLang === code}
                  >
                    {code === 'he' ? 'עברית' : 'English'}
                  </Button>
                ))}
              </div>
            )}
          </header>

          <div className="relative z-10 flex flex-1 flex-col justify-center px-6 py-8 sm:px-10 lg:px-14 xl:px-20">
            <div className="mx-auto w-full max-w-md">
              <div className="mb-8 lg:mb-10">
                <h2 className="font-display text-2xl font-semibold tracking-tight text-white sm:text-[1.65rem]">
                  {mfaToken ? t('auth.mfa_required') : t('auth.welcome_back')}
                </h2>
                <p className="mt-2 text-sm text-white/45">
                  {mfaToken ? t('auth.mfa_enter_code') : t('auth.sign_in_subtitle')}
                </p>
              </div>

              <StepIndicator step={step} t={t} />

              <div id={errorRegionId} aria-live="polite" aria-atomic="true">
                <AnimatePresence mode="wait">
                  {verifiedSignup && !error && (
                    <motion.div key="verified" initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="mb-6">
                      <AuthAlert variant="success">
                        <p>{t('auth.signup_verified')}</p>
                      </AuthAlert>
                    </motion.div>
                  )}
                  {error && (
                    <motion.div key="error" initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="mb-6">
                      <AuthAlert variant={errorCode === 'mfa_enrollment_required' ? 'warning' : 'error'}>
                        <p>{errorCode === 'login_locked' && lockSeconds > 0 ? t('auth.login_locked', { seconds: lockSeconds }) : error}</p>
                        {errorCode === 'mfa_enrollment_required' && (
                          <p className="mt-2 text-xs opacity-75">{t('auth.mfa_enrollment_hint')}</p>
                        )}
                      </AuthAlert>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

              <AnimatePresence mode="wait">
                {mfaToken ? (
                  <motion.form key="mfa-form" variants={formVariants} initial="initial" animate="animate" exit="exit" onSubmit={handleMfaSubmit} className="space-y-5">
                    <MfaBoxes
                      id="mfa-code"
                      value={mfaCode}
                      onChange={setMfaCode}
                      disabled={submitting}
                      inputRef={mfaInputRef}
                      label={t('auth.mfa_code_label')}
                    />
                    <Button
                      variant="unstyled"
                      type="submit"
                      disabled={submitting || mfaCode.length !== 6}
                      className="group relative flex w-full items-center justify-center gap-2 overflow-hidden rounded-xl border border-cyan-400/40 bg-gradient-to-b from-cyan-400/15 to-cyan-500/10 py-3.5 text-sm font-semibold tracking-wide text-cyan-100 transition-all hover:border-cyan-400/60 disabled:cursor-not-allowed disabled:opacity-45"
                    >
                      {submitting ? <><AuthSpinner />{t('auth.mfa_verifying')}</> : t('auth.mfa_verify')}
                    </Button>
                    <Button
                      variant="unstyled"
                      type="button"
                      onClick={() => { setMfaToken(null); setMfaCode(''); setError('') }}
                      className="w-full py-2 text-xs text-white/40 hover:text-white/70"
                    >
                      {t('auth.mfa_back_to_password')}
                    </Button>
                  </motion.form>
                ) : (
                  <motion.form key="credentials-form" variants={formVariants} initial="initial" animate="animate" exit="exit" onSubmit={handleSubmit} className="space-y-4">
                    {showWorkspace && (
                      <FloatingInput
                        id="tenant"
                        label={t('auth.workspace')}
                        type="text"
                        autoComplete="organization"
                        value={tenantSlug}
                        onChange={(e) => setTenantSlug(e.target.value)}
                        disabled={submitting}
                      />
                    )}
                    <FloatingInput
                      id="email"
                      label={t('auth.email')}
                      type="email"
                      autoComplete="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                      disabled={submitting}
                      ref={emailInputRef}
                    />
                    <FloatingInput
                      id="password"
                      label={t('auth.password')}
                      type={showPassword ? 'text' : 'password'}
                      autoComplete="current-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      disabled={submitting}
                      onFocus={onCaps}
                      onBlur={onCaps}
                      onKeyDown={onCaps}
                      onKeyUp={onCaps}
                      endAdornment={
                        <Button
                          variant="unstyled"
                          type="button"
                          onClick={() => setShowPassword((v) => !v)}
                          className="absolute end-3 top-1/2 z-10 -translate-y-1/2 rounded-lg p-1.5 text-white/40 hover:bg-white/5 hover:text-white/70"
                          aria-label={showPassword ? t('auth.hide_password') : t('auth.show_password')}
                          aria-pressed={showPassword}
                          tabIndex={-1}
                        >
                          {showPassword ? <EyeOff className="h-4 w-4" aria-hidden /> : <Eye className="h-4 w-4" aria-hidden />}
                        </Button>
                      }
                    />
                    {capsLock && <p className="text-xs text-amber-200/80">{t('auth.caps_lock')}</p>}
                    <Button
                      variant="unstyled"
                      type="submit"
                      disabled={submitting || lockSeconds > 0}
                      className="group relative mt-2 flex w-full items-center justify-center gap-2 overflow-hidden rounded-xl border border-cyan-400/40 bg-gradient-to-b from-cyan-400/15 to-cyan-500/10 py-3.5 text-sm font-semibold tracking-wide text-cyan-100 transition-all hover:border-cyan-400/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50 disabled:cursor-not-allowed disabled:opacity-45"
                    >
                      {submitting ? <><AuthSpinner />{t('auth.authenticating')}</> : t('auth.authenticate')}
                    </Button>
                    <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                      <button
                        type="button"
                        className="text-xs text-white/40 hover:text-white/70"
                        onClick={() => setShowWorkspace((v) => !v)}
                      >
                        {showWorkspace ? t('auth.hide_workspace') : t('auth.different_workspace')}
                      </button>
                      <button
                        type="button"
                        className="text-xs text-white/40 hover:text-white/70"
                        onClick={() => setShowSso((v) => !v)}
                      >
                        {t('auth.use_company_sso')}
                      </button>
                    </div>
                  </motion.form>
                )}
              </AnimatePresence>

              {!mfaToken && showSso && (
                <div className="mt-8 space-y-3">
                  <div className="relative flex items-center gap-3">
                    <div className="h-px flex-1 bg-white/10" aria-hidden />
                    <span className="text-[10px] font-medium uppercase tracking-[0.2em] text-white/35">{t('auth.enterprise_sso')}</span>
                    <div className="h-px flex-1 bg-white/10" aria-hidden />
                  </div>
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                    <Button variant="unstyled" type="button" className="rounded-xl border border-white/10 bg-white/[0.02] px-4 py-3 text-sm text-white/60 hover:border-cyan-400/30 hover:text-cyan-200/90" onClick={() => beginSso('/api/auth/oidc/begin')}>
                      {t('auth.sso_oidc')}
                    </Button>
                    <Button variant="unstyled" type="button" className="rounded-xl border border-white/10 bg-white/[0.02] px-4 py-3 text-sm text-white/60 hover:border-cyan-400/30 hover:text-cyan-200/90" onClick={() => beginSso('/api/auth/saml/begin')}>
                      {t('auth.sso_saml')}
                    </Button>
                  </div>
                </div>
              )}

              <footer className="mt-10 border-t border-white/10 pt-8 text-center space-y-3">
                <p className="text-sm text-white/45">
                  {t('auth.new_here')}{' '}
                  <a href={signupHref} className="font-medium text-cyan-400/90 hover:text-cyan-300 hover:underline underline-offset-4">
                    {t('auth.create_workspace')}
                  </a>
                </p>
                <p className="text-[11px] text-white/30">
                  <a href="/terms.html" className="hover:text-white/55">{t('auth.terms')}</a>
                  {' · '}
                  <a href="/privacy.html" className="hover:text-white/55">{t('auth.privacy')}</a>
                  {' · '}
                  <a href={statusHref} className="hover:text-white/55">{t('auth.status_link')}</a>
                </p>
              </footer>
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}
