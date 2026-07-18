import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useTranslation, Trans } from 'react-i18next'
import {
  Building2,
  CheckCircle2,
  ChevronRight,
  Globe,
  Loader2,
  Radar,
  Shield,
  Sparkles,
} from 'lucide-react'
import { apiFetch } from '../../utils/apiFetch'
import { formatApiErrorFromBody } from '../../lib/apiError'
import Button from '../ui/Button'

const STEPS = [
  { id: 1, labelKey: 'client', icon: Building2 },
  { id: 2, labelKey: 'scope', icon: Shield },
  { id: 3, labelKey: 'launch', icon: Radar },
]

function parseDomains(raw) {
  return raw
    .split(/[\n,]+/)
    .map((d) => d.trim())
    .filter(Boolean)
}

function domainsToJson(raw) {
  const list = parseDomains(raw)
  return JSON.stringify(list)
}

export default function OnboardingWizard({ open, onComplete }) {
  const { t } = useTranslation()
  const [step, setStep] = useState(1)
  const [name, setName] = useState('')
  const [domain, setDomain] = useState('')
  const [clientId, setClientId] = useState(null)
  const [scopeConfirmed, setScopeConfirmed] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const [scanResult, setScanResult] = useState(null)

  if (!open) return null

  const domains = parseDomains(domain)

  const handleCreateClient = async (e) => {
    e.preventDefault()
    setError('')
    const trimmedName = name.trim()
    if (!trimmedName) {
      setError(t('components.onboarding.name_required'))
      return
    }
    if (domains.length === 0) {
      setError(t('components.onboarding.domain_required'))
      return
    }
    setSubmitting(true)
    try {
      const payload = {
        name: trimmedName,
        domains: domainsToJson(domain),
        ip_ranges: '[]',
        tech_stack: '[]',
        contact_email: '',
        auto_detect_tech_stack: true,
      }
      const d = await apiFetch('/api/clients', {
        method: 'POST',
        body: payload,
      })
      if (d.id == null) {
        setError(formatApiErrorFromBody(d, 200))
        setSubmitting(false)
        return
      }
      setClientId(String(d.id))
      setStep(2)
    } catch (err) {
      if (err?.response) {
        const b = await err.response.json().catch(() => ({}))
        setError(formatApiErrorFromBody(b, err.status))
      } else {
        setError(err?.message || t('components.onboarding.network_error'))
      }
    }
    setSubmitting(false)
  }

  const handleLaunchScan = async () => {
    if (!clientId) return
    setError('')
    setSubmitting(true)
    try {
      const d = await apiFetch(`/api/clients/${clientId}/scan/run-all`, { method: 'POST' })
      setScanResult({
        message: d.message || t('components.onboarding.scan_queued_default'),
        jobs_queued: d.jobs_queued ?? 0,
      })
      setTimeout(() => {
        onComplete?.({ clientId, scan: d })
      }, 1800)
    } catch (err) {
      if (err?.response) {
        const b = await err.response.json().catch(() => ({}))
        setError(b.detail || b.message || t('components.onboarding.scan_failed', { status: err.status }))
      } else {
        setError(err?.message || t('components.onboarding.scan_network_error'))
      }
      setSubmitting(false)
    }
  }

  return (
    <div
      className="fixed inset-0 z-[200] flex items-center justify-center p-4 sm:p-6"
      role="dialog"
      aria-modal="true"
      aria-labelledby="onboarding-wizard-title"
    >
      <div
        className="absolute inset-0 bg-[#030508]/92 backdrop-blur-xl"
        aria-hidden
        style={{
          backgroundImage: [
            'radial-gradient(ellipse 80% 60% at 50% 0%, rgba(34,211,238,0.08) 0%, transparent 55%)',
            'radial-gradient(ellipse 60% 50% at 80% 100%, rgba(139,92,246,0.06) 0%, transparent 50%)',
          ].join(', '),
        }}
      />

      <motion.div
        initial={{ opacity: 0, y: 24, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.35, ease: [0.4, 0, 0.2, 1] }}
        className="relative w-full max-w-xl rounded-2xl border border-[var(--border-default)] bg-[#0a0f18]/95 shadow-[0_24px_80px_rgba(0,0,0,0.65),0_0_0_1px_rgba(34,211,238,0.06)] overflow-hidden"
      >
        <div
          className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent"
          aria-hidden
        />

        <div className="px-6 sm:px-8 pt-7 pb-5 border-b border-[var(--border-subtle)]">
          <div className="flex items-start gap-3 mb-6">
            <div className="shrink-0 w-10 h-10 rounded-xl border border-cyan-500/30 bg-cyan-500/10 flex items-center justify-center">
              <Sparkles className="w-5 h-5 text-cyan-400" strokeWidth={1.75} />
            </div>
            <div>
              <p className="text-[9px] font-mono uppercase tracking-[0.28em] text-cyan-400/70 mb-1">
                {t('components.onboarding.badge')}
              </p>
              <h2 id="onboarding-wizard-title" className="text-lg font-semibold text-white tracking-tight">
                {t('components.onboarding.title')}
              </h2>
              <p className="text-[13px] text-[var(--text-muted)] mt-1 leading-relaxed">
                {t('components.onboarding.subtitle')}
              </p>
            </div>
          </div>

          <nav className="flex items-center gap-2" aria-label="Onboarding progress">
            {STEPS.map((s, i) => {
              const Icon = s.icon
              const active = step === s.id
              const done = step > s.id
              return (
                <React.Fragment key={s.id}>
                  <div
                    className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-[10px] font-mono uppercase tracking-[0.15em] transition-all ${
                      active
                        ? 'bg-cyan-500/15 border border-cyan-500/35 text-cyan-200'
                        : done
                          ? 'bg-emerald-500/10 border border-emerald-500/25 text-emerald-300/80'
                          : 'bg-[var(--row-hover-bg)] border border-[var(--border-subtle)] text-[var(--text-disabled)]'
                    }`}
                  >
                    {done ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Icon className="w-3.5 h-3.5" strokeWidth={1.75} />
                    )}
                    <span>{t(`components.onboarding.steps.${s.labelKey}`)}</span>
                  </div>
                  {i < STEPS.length - 1 && (
                    <ChevronRight className="w-3.5 h-3.5 text-[var(--text-disabled)] shrink-0" aria-hidden />
                  )}
                </React.Fragment>
              )
            })}
          </nav>
        </div>

        <div className="px-6 sm:px-8 py-6 min-h-[280px]">
          <AnimatePresence mode="wait">
            {step === 1 && (
              <motion.form
                key="step-1"
                initial={{ opacity: 0, x: 12 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -12 }}
                transition={{ duration: 0.25 }}
                onSubmit={handleCreateClient}
                className="space-y-5"
              >
                <div>
                  <label htmlFor="onboarding-name" className="block text-[11px] font-mono uppercase tracking-[0.18em] text-[var(--text-muted)] mb-2">
                    {t('components.onboarding.client_name')}
                  </label>
                  <input
                    id="onboarding-name"
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder={t('components.onboarding.client_placeholder')}
                    autoFocus
                    className="w-full px-4 py-3 rounded-xl bg-[var(--bg-2)] border border-[var(--border-default)] text-white placeholder-white/25 focus:outline-none focus:ring-2 focus:ring-cyan-500/40 focus:border-cyan-500/40 transition-all"
                  />
                </div>
                <div>
                  <label htmlFor="onboarding-domain" className="block text-[11px] font-mono uppercase tracking-[0.18em] text-[var(--text-muted)] mb-2">
                    {t('components.onboarding.authorized_domain')}
                  </label>
                  <div className="relative">
                    <Globe className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-disabled)] pointer-events-none" />
                    <input
                      id="onboarding-domain"
                      type="text"
                      value={domain}
                      onChange={(e) => setDomain(e.target.value)}
                      placeholder={t('components.onboarding.domain_placeholder')}
                      className="w-full pl-11 pr-4 py-3 rounded-xl bg-[var(--bg-2)] border border-[var(--border-default)] text-white placeholder-white/25 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500/40 focus:border-cyan-500/40 transition-all"
                    />
                  </div>
                  <p className="mt-2 text-[11px] text-[var(--text-disabled)]">
                    {t('components.onboarding.domain_hint')}
                  </p>
                </div>
                {error && (
                  <div className="px-4 py-3 rounded-xl border border-red-500/30 bg-red-950/30 text-red-300 text-sm">
                    {error}
                  </div>
                )}
                <Button variant="unstyled"
                  type="submit"
                  disabled={submitting}
                  className="w-full flex items-center justify-center gap-2 px-5 py-3 rounded-xl font-semibold text-sm tracking-wide border border-cyan-500/50 bg-gradient-to-r from-cyan-500/15 to-violet-500/10 text-cyan-100 hover:from-cyan-500/25 hover:to-violet-500/15 hover:shadow-[0_0_24px_rgba(34,211,238,0.15)] disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                >
                  {submitting ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      {t('components.onboarding.creating')}
                    </>
                  ) : (
                    <>
                      {t('components.onboarding.continue')}
                      <ChevronRight className="w-4 h-4" />
                    </>
                  )}
                </Button>
              </motion.form>
            )}

            {step === 2 && (
              <motion.div
                key="step-2"
                initial={{ opacity: 0, x: 12 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -12 }}
                transition={{ duration: 0.25 }}
                className="space-y-5"
              >
                <div className="rounded-xl border border-[var(--border-default)] bg-[var(--row-hover-bg)] p-5 space-y-4">
                  <div>
                    <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)] mb-1">{t('components.onboarding.client_label')}</p>
                    <p className="text-base font-semibold text-white">{name.trim()}</p>
                  </div>
                  <div>
                    <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)] mb-2">{t('components.onboarding.domains_label')}</p>
                    <ul className="space-y-1.5">
                      {domains.map((d) => (
                        <li
                          key={d}
                          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-cyan-500/5 border border-cyan-500/15 font-mono text-sm text-cyan-200/90"
                        >
                          <Globe className="w-3.5 h-3.5 text-cyan-400/70 shrink-0" />
                          {d}
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div className="pt-2 border-t border-[var(--border-subtle)]">
                    <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">
                      <Trans
                        i18nKey="components.onboarding.scope_hint"
                        components={{ 1: <span className="text-emerald-400/90 font-medium" /> }}
                      />
                    </p>
                  </div>
                </div>

                <label className="flex items-start gap-3 cursor-pointer group">
                  <input
                    type="checkbox"
                    checked={scopeConfirmed}
                    onChange={(e) => setScopeConfirmed(e.target.checked)}
                    className="mt-0.5 w-4 h-4 rounded border-[var(--border-strong)] bg-[var(--bg-2)] text-cyan-500 focus:ring-cyan-500/40"
                  />
                  <span className="text-sm text-[var(--text-tertiary)] group-hover:text-[var(--text-secondary)] transition-colors leading-relaxed">
                    {t('components.onboarding.scope_confirm')}
                  </span>
                </label>

                {error && (
                  <div className="px-4 py-3 rounded-xl border border-red-500/30 bg-red-950/30 text-red-300 text-sm">
                    {error}
                  </div>
                )}

                <div className="flex gap-3">
                  <Button variant="unstyled"
                    type="button"
                    onClick={() => { setStep(1); setError('') }}
                    className="px-4 py-3 rounded-xl text-sm font-medium border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] transition-colors"
                  >
                    {t('components.onboarding.back')}
                  </Button>
                  <Button variant="unstyled"
                    type="button"
                    disabled={!scopeConfirmed}
                    onClick={() => { setError(''); setStep(3) }}
                    className="flex-1 flex items-center justify-center gap-2 px-5 py-3 rounded-xl font-semibold text-sm tracking-wide border border-cyan-500/50 bg-cyan-500/10 text-cyan-100 hover:bg-cyan-500/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                  >
                    {t('components.onboarding.confirm_scope')}
                    <ChevronRight className="w-4 h-4" />
                  </Button>
                </div>
              </motion.div>
            )}

            {step === 3 && (
              <motion.div
                key="step-3"
                initial={{ opacity: 0, x: 12 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -12 }}
                transition={{ duration: 0.25 }}
                className="space-y-5"
              >
                {scanResult ? (
                  <div className="flex flex-col items-center text-center py-6">
                    <motion.div
                      initial={{ scale: 0.8, opacity: 0 }}
                      animate={{ scale: 1, opacity: 1 }}
                      className="w-16 h-16 rounded-2xl border border-emerald-500/40 bg-emerald-500/10 flex items-center justify-center mb-4"
                    >
                      <CheckCircle2 className="w-8 h-8 text-emerald-400" />
                    </motion.div>
                    <h3 className="text-lg font-semibold text-white mb-1">{t('components.onboarding.scan_launched')}</h3>
                    <p className="text-sm text-[var(--text-tertiary)] max-w-sm">{scanResult.message}</p>
                    {scanResult.jobs_queued > 0 && (
                      <p className="mt-2 text-[11px] font-mono text-cyan-400/80">
                        {scanResult.jobs_queued === 1
                          ? t('components.onboarding.jobs_queued', { count: scanResult.jobs_queued })
                          : t('components.onboarding.jobs_queued_plural', { count: scanResult.jobs_queued })}
                      </p>
                    )}
                    <p className="mt-4 text-[11px] text-[var(--text-disabled)] font-mono uppercase tracking-[0.15em]">
                      {t('components.onboarding.opening_cockpit')}
                    </p>
                  </div>
                ) : (
                  <>
                    <div className="rounded-xl border border-violet-500/20 bg-violet-500/5 p-5 text-center">
                      <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl border border-violet-500/30 bg-violet-500/10 mb-4">
                        <Radar className="w-7 h-7 text-violet-400" strokeWidth={1.5} />
                      </div>
                      <h3 className="text-base font-semibold text-white mb-2">{t('components.onboarding.ready_title')}</h3>
                      <p className="text-sm text-[var(--text-muted)] leading-relaxed max-w-sm mx-auto">
                        <Trans
                          i18nKey="components.onboarding.ready_body"
                          values={{ name: name.trim() }}
                          components={{ 1: <span className="text-[var(--text-secondary)] font-medium" /> }}
                        />
                      </p>
                    </div>

                    {error && (
                      <div className="px-4 py-3 rounded-xl border border-red-500/30 bg-red-950/30 text-red-300 text-sm">
                        {error}
                      </div>
                    )}

                    <div className="flex gap-3">
                      <Button variant="unstyled"
                        type="button"
                        onClick={() => { setStep(2); setError('') }}
                        disabled={submitting}
                        className="px-4 py-3 rounded-xl text-sm font-medium border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] transition-colors disabled:opacity-50"
                      >
                        {t('components.onboarding.back')}
                      </Button>
                      <Button variant="unstyled"
                        type="button"
                        onClick={handleLaunchScan}
                        disabled={submitting}
                        className="flex-1 flex items-center justify-center gap-2 px-5 py-3 rounded-xl font-semibold text-sm tracking-wide border border-violet-500/50 bg-gradient-to-r from-violet-500/20 to-cyan-500/15 text-white hover:shadow-[0_0_28px_rgba(139,92,246,0.2)] disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                      >
                        {submitting ? (
                          <>
                            <Loader2 className="w-4 h-4 animate-spin" />
                            {t('components.onboarding.launching')}
                          </>
                        ) : (
                          <>
                            <Radar className="w-4 h-4" />
                            {t('components.onboarding.launch_full_scan')}
                          </>
                        )}
                      </Button>
                    </div>
                  </>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </motion.div>
    </div>
  )
}
