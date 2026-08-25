import { useState, useEffect, useRef, useId, useCallback } from 'react'
import { Link, useNavigate } from 'react-router'
import { motion, AnimatePresence } from 'framer-motion'
import { Eye, EyeOff, Loader2, AlertCircle, Shield, CheckCircle2, Globe2 } from 'lucide-react'
import { useAuth } from '../../context/AuthContext'
import { apiUrl } from '../../lib/apiBase'
import { useTranslation } from 'react-i18next'
import LanguageSwitcher from '../LanguageSwitcher'
import Logo from '../Logo'
import Button from '../ui/Button'
import CyberLiveBackdrop from '../CyberLiveBackdrop'
import { FloatingInput } from '../auth/AuthFields'
import TenantSlugField from '../auth/TenantSlugField'
import { PRODUCTION_ENGINE_COUNT } from '../../lib/platformScale'

const formVariants = {
  initial: { opacity: 0, x: 24 },
  animate: { opacity: 1, x: 0, transition: { duration: 0.35, ease: [0.22, 1, 0.36, 1] } },
  exit: { opacity: 0, x: -24, transition: { duration: 0.25, ease: [0.22, 1, 0.36, 1] } },
}

function AuthSpinner({ className = '' }) {
  return (
    <Loader2
      className={`h-4 w-4 animate-spin ${className}`}
      aria-hidden
    />
  )
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
                <span
                  className={`hidden sm:block truncate text-xs tracking-wide ${
                    active ? 'text-white/90' : 'text-white/40'
                  }`}
                >
                  {s.label}
                </span>
              </div>
              {i < steps.length - 1 && (
                <div
                  className={`mx-1 h-px flex-1 transition-colors ${
                    done ? 'bg-cyan-400/30' : 'bg-white/10'
                  }`}
                  aria-hidden
                />
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
      : 'border-rose-400/20 bg-rose-500/[0.06] text-rose-100/90'

  return (
    <div
      role="alert"
      aria-live="polite"
      className={`flex items-start gap-3 rounded-xl border px-4 py-3 backdrop-blur-sm ${styles}`}
    >
      <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 opacity-80" aria-hidden />
      <div className="text-sm leading-relaxed">{children}</div>
    </div>
  )
}

function BrandPanel({ t }) {
  const trustItems = [
    { icon: Shield, label: t('auth.trust_engines', { engines: PRODUCTION_ENGINE_COUNT }) },
    { icon: CheckCircle2, label: t('auth.trust_soc2') },
    { icon: Globe2, label: t('auth.trust_region') },
  ]

  return (
    <aside className="relative hidden min-h-screen flex-col justify-between overflow-hidden lg:flex lg:w-[52%] xl:w-[55%]">
      {/* Readability scrim: the live backdrop keeps moving underneath the headline. */}
      <div
        className="pointer-events-none absolute inset-0 bg-gradient-to-r from-[#030712]/82 via-[#030712]/28 to-transparent"
        aria-hidden
      />

      <div className="relative z-10 flex flex-1 flex-col justify-center px-12 xl:px-16 py-16">
        <Logo size={48} glow className="mb-10" />
        <h1 className="max-w-md font-holo text-3xl font-semibold leading-tight tracking-tight text-white xl:text-4xl">
          {t('auth.brand_tagline')}
        </h1>
        <p className="mt-5 max-w-lg text-base leading-relaxed text-white/55">
          {t('auth.brand_story', { engines: PRODUCTION_ENGINE_COUNT })}
        </p>

        <ul className="mt-10 flex flex-wrap gap-3" aria-label={t('auth.trust_label')}>
          {trustItems.map(({ icon: Icon, label }) => (
            <li
              key={label}
              className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.04] px-4 py-2 text-xs font-medium tracking-wide text-white/70 backdrop-blur-sm"
            >
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

export default function Login() {
  const { t } = useTranslation()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [tenantSlug, setTenantSlug] = useState('default')
  const [error, setError] = useState('')
  const [errorCode, setErrorCode] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [mfaToken, setMfaToken] = useState(null)
  const [mfaCode, setMfaCode] = useState('')
  const { login, verifyMfa, isAuthenticated, isCeo } = useAuth()
  const navigate = useNavigate()
  const mfaInputRef = useRef(null)
  const emailInputRef = useRef(null)
  const errorRegionId = useId()

  const postLoginPath = useCallback((result) => {
    if (result?.is_superadmin === true) return '/'
    const role = String(result?.role || '').trim().toLowerCase()
    return role === 'ceo' ? '/' : '/operations'
  }, [])

  useEffect(() => {
    if (isAuthenticated) navigate(isCeo ? '/' : '/operations', { replace: true })
  }, [isAuthenticated, isCeo, navigate])

  useEffect(() => {
    if (mfaToken && mfaInputRef.current) {
      mfaInputRef.current.focus()
    } else if (!mfaToken && emailInputRef.current) {
      emailInputRef.current.focus()
    }
  }, [mfaToken])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setErrorCode('')
    setSubmitting(true)
    try {
      const result = await login(email, password, tenantSlug)
      if (result.ok) {
        navigate(postLoginPath(result), { replace: true })
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
        navigate(postLoginPath(result), { replace: true })
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

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#030712] text-white">
      <CyberLiveBackdrop />

      <div className="relative z-10 flex min-h-screen flex-col lg:flex-row">
        <BrandPanel t={t} />

        <main className="relative flex flex-1 flex-col bg-[#030712]/80 backdrop-blur-md lg:border-s lg:border-white/[0.07] lg:bg-[#030712]/65 lg:shadow-[-24px_0_60px_-30px_rgba(34,211,238,0.25)]">
          <header className="relative z-10 flex items-center justify-between px-6 pt-6 lg:justify-end lg:px-10 lg:pt-8">
            <div className="lg:hidden">
              <Logo compact size={36} glow />
            </div>
            <LanguageSwitcher className="opacity-80 hover:opacity-100 transition-opacity" />
          </header>

          <div className="relative z-10 flex flex-1 flex-col justify-center px-6 py-8 sm:px-10 lg:px-14 xl:px-20">
            <div className="mx-auto w-full max-w-md">
              {/* Mobile trust strip */}
              <ul className="mb-6 flex flex-wrap justify-center gap-2 lg:hidden" aria-label={t('auth.trust_label')}>
                {[
                  t('auth.trust_engines', { engines: PRODUCTION_ENGINE_COUNT }),
                  t('auth.trust_soc2'),
                  t('auth.trust_region'),
                ].map((label) => (
                  <li
                    key={label}
                    className="rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 text-[10px] tracking-wide text-white/50"
                  >
                    {label}
                  </li>
                ))}
              </ul>

              <div className="mb-8 lg:mb-10">
                <h2 className="font-holo text-2xl font-semibold tracking-tight text-white sm:text-[1.65rem]">
                  {mfaToken ? t('auth.mfa_required') : t('auth.welcome_back')}
                </h2>
                <p className="mt-2 text-sm text-white/45">
                  {mfaToken ? t('auth.mfa_enter_code') : t('auth.sign_in_subtitle')}
                </p>
              </div>

              <StepIndicator step={step} t={t} />

              <div id={errorRegionId} aria-live="polite" aria-atomic="true">
                <AnimatePresence mode="wait">
                  {error && (
                    <motion.div
                      key="error"
                      initial={{ opacity: 0, y: -8, height: 0 }}
                      animate={{ opacity: 1, y: 0, height: 'auto' }}
                      exit={{ opacity: 0, y: -8, height: 0 }}
                      className="mb-6 overflow-hidden"
                    >
                      <AuthAlert variant={errorCode === 'mfa_enrollment_required' ? 'warning' : 'error'}>
                        <p>{error}</p>
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
                  <motion.form
                    key="mfa-form"
                    variants={formVariants}
                    initial="initial"
                    animate="animate"
                    exit="exit"
                    onSubmit={handleMfaSubmit}
                    className="space-y-5"
                  >
                    <FloatingInput
                      id="mfa-code"
                      label={t('auth.mfa_code_label')}
                      type="text"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      value={mfaCode}
                      onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      required
                      placeholder="000000"
                      disabled={submitting}
                      inputClassName="text-center font-mono text-lg tracking-[0.45em]"
                      ref={mfaInputRef}
                    />

                    <Button variant="unstyled"
                      type="submit"
                      disabled={submitting || mfaCode.length !== 6}
                      className="group relative flex w-full items-center justify-center gap-2 overflow-hidden rounded-xl border border-cyan-400/40 bg-gradient-to-b from-cyan-400/15 to-cyan-500/10 py-3.5 text-sm font-semibold tracking-wide text-cyan-100 transition-all hover:border-cyan-400/60 hover:from-cyan-400/20 disabled:cursor-not-allowed disabled:opacity-45"
                    >
                      {submitting ? (
                        <>
                          <AuthSpinner />
                          {t('auth.mfa_verifying')}
                        </>
                      ) : (
                        t('auth.mfa_verify')
                      )}
                    </Button>

                    <Button variant="unstyled"
                      type="button"
                      onClick={() => {
                        setMfaToken(null)
                        setMfaCode('')
                        setError('')
                      }}
                      className="w-full py-2 text-xs text-white/40 transition-colors hover:text-white/70"
                    >
                      {t('auth.mfa_back_to_password')}
                    </Button>
                  </motion.form>
                ) : (
                  <motion.form
                    key="credentials-form"
                    variants={formVariants}
                    initial="initial"
                    animate="animate"
                    exit="exit"
                    onSubmit={handleSubmit}
                    className="space-y-4"
                  >
                    <TenantSlugField
                      id="tenant"
                      value={tenantSlug}
                      onChange={setTenantSlug}
                      disabled={submitting}
                    />
                    <FloatingInput
                      id="email"
                      label={t('common.email')}
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
                      label={t('common.password')}
                      type={showPassword ? 'text' : 'password'}
                      autoComplete="current-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      disabled={submitting}
                      endAdornment={
                        <Button variant="unstyled"
                          type="button"
                          onClick={() => setShowPassword((v) => !v)}
                          className="absolute end-3 top-1/2 z-10 -translate-y-1/2 rounded-lg p-1.5 text-white/40 transition-colors hover:bg-white/5 hover:text-white/70 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50"
                          aria-label={showPassword ? t('auth.hide_password') : t('auth.show_password')}
                          aria-pressed={showPassword}
                          tabIndex={-1}
                        >
                          {showPassword ? (
                            <EyeOff className="h-4 w-4" aria-hidden />
                          ) : (
                            <Eye className="h-4 w-4" aria-hidden />
                          )}
                        </Button>
                      }
                    />

                    <Button variant="unstyled"
                      type="submit"
                      disabled={submitting}
                      className="group relative mt-2 flex w-full items-center justify-center gap-2 overflow-hidden rounded-xl border border-cyan-400/40 bg-gradient-to-b from-cyan-400/15 to-cyan-500/10 py-3.5 text-sm font-semibold tracking-wide text-cyan-100 transition-all hover:border-cyan-400/60 hover:from-cyan-400/20 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50 focus-visible:ring-offset-2 focus-visible:ring-offset-[#030712] disabled:cursor-not-allowed disabled:opacity-45"
                    >
                      {submitting ? (
                        <>
                          <AuthSpinner />
                          {t('auth.authenticating')}
                        </>
                      ) : (
                        t('auth.authenticate')
                      )}
                    </Button>
                  </motion.form>
                )}
              </AnimatePresence>

              {!mfaToken && (
                <div className="mt-10 space-y-3">
                  <div className="relative flex items-center gap-3">
                    <div className="h-px flex-1 bg-white/10" aria-hidden />
                    <span className="text-[10px] font-medium uppercase tracking-[0.2em] text-white/35">
                      {t('auth.enterprise_sso')}
                    </span>
                    <div className="h-px flex-1 bg-white/10" aria-hidden />
                  </div>
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                    <Button variant="unstyled"
                      type="button"
                      className="rounded-xl border border-white/10 bg-white/[0.02] px-4 py-3 text-sm text-white/60 transition-all hover:border-cyan-400/30 hover:bg-cyan-400/[0.04] hover:text-cyan-200/90"
                      onClick={() => beginSso('/api/auth/oidc/begin')}
                    >
                      {t('auth.sso_oidc')}
                    </Button>
                    <Button variant="unstyled"
                      type="button"
                      className="rounded-xl border border-white/10 bg-white/[0.02] px-4 py-3 text-sm text-white/60 transition-all hover:border-cyan-400/30 hover:bg-cyan-400/[0.04] hover:text-cyan-200/90"
                      onClick={() => beginSso('/api/auth/saml/begin')}
                    >
                      {t('auth.sso_saml')}
                    </Button>
                  </div>
                </div>
              )}

              <footer className="mt-10 border-t border-white/10 pt-8 text-center space-y-3">
                <p className="text-sm text-white/45">
                  {t('auth.new_here')}{' '}
                  <a
                    href="/signup.html"
                    className="font-medium text-cyan-400/90 transition-colors hover:text-cyan-300 hover:underline underline-offset-4"
                  >
                    {t('auth.create_workspace')}
                  </a>
                </p>
                <p className="text-[11px] text-white/30">
                  <a href="/terms.html" className="transition-colors hover:text-white/55">
                    {t('auth.terms')}
                  </a>
                  {' · '}
                  <a href="/privacy.html" className="transition-colors hover:text-white/55">
                    {t('auth.privacy')}
                  </a>
                  {' · '}
                  <Link to="/status" className="transition-colors hover:text-white/55">
                    {t('auth.status_link')}
                  </Link>
                  {' · '}
                  <a href={apiUrl('/api/docs/')} className="transition-colors hover:text-white/55">
                    {t('auth.api_docs')}
                  </a>
                </p>
              </footer>
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}
