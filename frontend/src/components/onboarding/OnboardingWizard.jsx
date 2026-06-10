import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
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
import { apiFetch } from '../../lib/apiBase'
import { formatApiErrorFromBody } from '../../lib/apiError'

const STEPS = [
  { id: 1, label: 'Client', icon: Building2 },
  { id: 2, label: 'Scope', icon: Shield },
  { id: 3, label: 'Launch', icon: Radar },
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
      setError('Client name is required')
      return
    }
    if (domains.length === 0) {
      setError('Enter at least one authorized domain')
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
      const r = await apiFetch('/api/clients', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok || d.id == null) {
        setError(formatApiErrorFromBody(d, r.status))
        setSubmitting(false)
        return
      }
      setClientId(String(d.id))
      setStep(2)
    } catch (err) {
      setError(err?.message || 'Network error — could not reach API')
    }
    setSubmitting(false)
  }

  const handleLaunchScan = async () => {
    if (!clientId) return
    setError('')
    setSubmitting(true)
    try {
      const r = await apiFetch(`/api/clients/${clientId}/scan/run-all`, { method: 'POST' })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        setError(d.detail || d.message || `Scan launch failed (HTTP ${r.status})`)
        setSubmitting(false)
        return
      }
      setScanResult({
        message: d.message || 'Scan queued successfully',
        jobs_queued: d.jobs_queued ?? 0,
      })
      setTimeout(() => {
        onComplete?.({ clientId, scan: d })
      }, 1800)
    } catch (err) {
      setError(err?.message || 'Network error launching scan')
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
        className="relative w-full max-w-xl rounded-2xl border border-white/10 bg-[#0a0f18]/95 shadow-[0_24px_80px_rgba(0,0,0,0.65),0_0_0_1px_rgba(34,211,238,0.06)] overflow-hidden"
      >
        <div
          className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-400/50 to-transparent"
          aria-hidden
        />

        <div className="px-6 sm:px-8 pt-7 pb-5 border-b border-white/[0.06]">
          <div className="flex items-start gap-3 mb-6">
            <div className="shrink-0 w-10 h-10 rounded-xl border border-cyan-500/30 bg-cyan-500/10 flex items-center justify-center">
              <Sparkles className="w-5 h-5 text-cyan-400" strokeWidth={1.75} />
            </div>
            <div>
              <p className="text-[9px] font-mono uppercase tracking-[0.28em] text-cyan-400/70 mb-1">
                First-time setup
              </p>
              <h2 id="onboarding-wizard-title" className="text-lg font-semibold text-white tracking-tight">
                Welcome to Weissman Command Center
              </h2>
              <p className="text-[13px] text-white/45 mt-1 leading-relaxed">
                Add your first client, confirm authorized scope, and launch your inaugural scan.
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
                          : 'bg-white/[0.03] border border-white/[0.06] text-white/30'
                    }`}
                  >
                    {done ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Icon className="w-3.5 h-3.5" strokeWidth={1.75} />
                    )}
                    <span>{s.label}</span>
                  </div>
                  {i < STEPS.length - 1 && (
                    <ChevronRight className="w-3.5 h-3.5 text-white/15 shrink-0" aria-hidden />
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
                  <label htmlFor="onboarding-name" className="block text-[11px] font-mono uppercase tracking-[0.18em] text-white/45 mb-2">
                    Client name
                  </label>
                  <input
                    id="onboarding-name"
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Acme Corporation"
                    autoFocus
                    className="w-full px-4 py-3 rounded-xl bg-black/40 border border-white/10 text-white placeholder-white/25 focus:outline-none focus:ring-2 focus:ring-cyan-500/40 focus:border-cyan-500/40 transition-all"
                  />
                </div>
                <div>
                  <label htmlFor="onboarding-domain" className="block text-[11px] font-mono uppercase tracking-[0.18em] text-white/45 mb-2">
                    Authorized domain
                  </label>
                  <div className="relative">
                    <Globe className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-white/25 pointer-events-none" />
                    <input
                      id="onboarding-domain"
                      type="text"
                      value={domain}
                      onChange={(e) => setDomain(e.target.value)}
                      placeholder="example.com"
                      className="w-full pl-11 pr-4 py-3 rounded-xl bg-black/40 border border-white/10 text-white placeholder-white/25 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500/40 focus:border-cyan-500/40 transition-all"
                    />
                  </div>
                  <p className="mt-2 text-[11px] text-white/30">
                    Comma or newline separated. Wildcards supported (e.g. *.example.com).
                  </p>
                </div>
                {error && (
                  <div className="px-4 py-3 rounded-xl border border-red-500/30 bg-red-950/30 text-red-300 text-sm">
                    {error}
                  </div>
                )}
                <button
                  type="submit"
                  disabled={submitting}
                  className="w-full flex items-center justify-center gap-2 px-5 py-3 rounded-xl font-semibold text-sm tracking-wide border border-cyan-500/50 bg-gradient-to-r from-cyan-500/15 to-violet-500/10 text-cyan-100 hover:from-cyan-500/25 hover:to-violet-500/15 hover:shadow-[0_0_24px_rgba(34,211,238,0.15)] disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                >
                  {submitting ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Creating client…
                    </>
                  ) : (
                    <>
                      Continue
                      <ChevronRight className="w-4 h-4" />
                    </>
                  )}
                </button>
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
                <div className="rounded-xl border border-white/[0.08] bg-white/[0.02] p-5 space-y-4">
                  <div>
                    <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-white/35 mb-1">Client</p>
                    <p className="text-base font-semibold text-white">{name.trim()}</p>
                  </div>
                  <div>
                    <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-white/35 mb-2">Authorized domains</p>
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
                  <div className="pt-2 border-t border-white/[0.06]">
                    <p className="text-[11px] text-white/40 leading-relaxed">
                      Scans run in <span className="text-emerald-400/90 font-medium">safe proofs</span> mode by default.
                      Only assets within the declared scope will be assessed.
                    </p>
                  </div>
                </div>

                <label className="flex items-start gap-3 cursor-pointer group">
                  <input
                    type="checkbox"
                    checked={scopeConfirmed}
                    onChange={(e) => setScopeConfirmed(e.target.checked)}
                    className="mt-0.5 w-4 h-4 rounded border-white/20 bg-black/40 text-cyan-500 focus:ring-cyan-500/40"
                  />
                  <span className="text-sm text-white/60 group-hover:text-white/80 transition-colors leading-relaxed">
                    I confirm these domains are authorized for security assessment under my organization&apos;s rules of engagement.
                  </span>
                </label>

                {error && (
                  <div className="px-4 py-3 rounded-xl border border-red-500/30 bg-red-950/30 text-red-300 text-sm">
                    {error}
                  </div>
                )}

                <div className="flex gap-3">
                  <button
                    type="button"
                    onClick={() => { setStep(1); setError('') }}
                    className="px-4 py-3 rounded-xl text-sm font-medium border border-white/10 text-white/50 hover:text-white/80 hover:border-white/20 transition-colors"
                  >
                    Back
                  </button>
                  <button
                    type="button"
                    disabled={!scopeConfirmed}
                    onClick={() => { setError(''); setStep(3) }}
                    className="flex-1 flex items-center justify-center gap-2 px-5 py-3 rounded-xl font-semibold text-sm tracking-wide border border-cyan-500/50 bg-cyan-500/10 text-cyan-100 hover:bg-cyan-500/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                  >
                    Confirm scope
                    <ChevronRight className="w-4 h-4" />
                  </button>
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
                    <h3 className="text-lg font-semibold text-white mb-1">Scan launched</h3>
                    <p className="text-sm text-white/50 max-w-sm">{scanResult.message}</p>
                    {scanResult.jobs_queued > 0 && (
                      <p className="mt-2 text-[11px] font-mono text-cyan-400/80">
                        {scanResult.jobs_queued} job{scanResult.jobs_queued !== 1 ? 's' : ''} queued
                      </p>
                    )}
                    <p className="mt-4 text-[11px] text-white/30 font-mono uppercase tracking-[0.15em]">
                      Opening cockpit…
                    </p>
                  </div>
                ) : (
                  <>
                    <div className="rounded-xl border border-violet-500/20 bg-violet-500/5 p-5 text-center">
                      <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl border border-violet-500/30 bg-violet-500/10 mb-4">
                        <Radar className="w-7 h-7 text-violet-400" strokeWidth={1.5} />
                      </div>
                      <h3 className="text-base font-semibold text-white mb-2">Ready to scan</h3>
                      <p className="text-sm text-white/45 leading-relaxed max-w-sm mx-auto">
                        Launch a full assessment across all enabled engines for{' '}
                        <span className="text-white/80 font-medium">{name.trim()}</span>.
                      </p>
                    </div>

                    {error && (
                      <div className="px-4 py-3 rounded-xl border border-red-500/30 bg-red-950/30 text-red-300 text-sm">
                        {error}
                      </div>
                    )}

                    <div className="flex gap-3">
                      <button
                        type="button"
                        onClick={() => { setStep(2); setError('') }}
                        disabled={submitting}
                        className="px-4 py-3 rounded-xl text-sm font-medium border border-white/10 text-white/50 hover:text-white/80 hover:border-white/20 transition-colors disabled:opacity-50"
                      >
                        Back
                      </button>
                      <button
                        type="button"
                        onClick={handleLaunchScan}
                        disabled={submitting}
                        className="flex-1 flex items-center justify-center gap-2 px-5 py-3 rounded-xl font-semibold text-sm tracking-wide border border-violet-500/50 bg-gradient-to-r from-violet-500/20 to-cyan-500/15 text-white hover:shadow-[0_0_28px_rgba(139,92,246,0.2)] disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                      >
                        {submitting ? (
                          <>
                            <Loader2 className="w-4 h-4 animate-spin" />
                            Launching…
                          </>
                        ) : (
                          <>
                            <Radar className="w-4 h-4" />
                            Launch full scan
                          </>
                        )}
                      </button>
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
