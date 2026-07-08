import React, { useCallback, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Loader2, ShieldCheck, ShieldAlert, ShieldQuestion, ShieldX } from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'

const VERDICT_META = {
  CONFIRMED: { color: '#22c55e', icon: ShieldCheck },
  LIKELY_VALID: { color: '#38bdf8', icon: ShieldCheck },
  INCONCLUSIVE: { color: '#fbbf24', icon: ShieldQuestion },
  NOISE: { color: '#94a3b8', icon: ShieldX },
  FALSE_POSITIVE: { color: '#f87171', icon: ShieldAlert },
}

export function liveVerdictFromFinding(finding) {
  return (
    finding?.live_verdict
    || finding?.live_verification?.verdict
    || finding?.raw?.live_verification?.verdict
    || ''
  )
}

export function LiveVerdictBadge({ verification, verdict: verdictProp, compact = false }) {
  const { t } = useTranslation()
  const verdict = verdictProp || verification?.verdict
  if (!verdict) return null
  const meta = VERDICT_META[verdict] || VERDICT_META.INCONCLUSIVE
  const Icon = meta.icon
  const conf = verification?.confidence
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border font-mono uppercase tracking-wide ${
        compact ? 'text-[9px] px-1.5 py-0.5' : 'text-[10px] px-2 py-0.5'
      }`}
      style={{ color: meta.color, borderColor: `${meta.color}55`, background: `${meta.color}12` }}
      title={conf != null ? t('findings.liveVerify.confidence_pct', { pct: Math.round(conf * 100) }) : verdict}
    >
      <Icon className={compact ? 'w-3 h-3' : 'w-3.5 h-3.5'} />
      {t(`findings.liveVerify.verdict_${verdict}`, { defaultValue: verdict })}
    </span>
  )
}

export function FindingVerifyChecks({ checks }) {
  const { t } = useTranslation()
  const list = Array.isArray(checks) ? checks : []
  if (!list.length) return null
  return (
    <ul className="space-y-2">
      {list.map((c) => (
        <li
          key={c.id}
          className={`rounded-lg border px-3 py-2 text-[11px] font-mono ${
            c.passed
              ? 'border-emerald-500/25 bg-emerald-950/20 text-emerald-200/90'
              : 'border-rose-500/20 bg-rose-950/15 text-rose-200/80'
          }`}
        >
          <div className="flex items-center justify-between gap-2 mb-0.5">
            <span className="font-semibold">{c.label}</span>
            <span className="text-[9px] uppercase opacity-70">
              {c.passed ? t('findings.liveVerify.pass') : t('findings.liveVerify.fail')}
            </span>
          </div>
          <p className="text-[var(--text-tertiary)] leading-relaxed break-words">{c.detail}</p>
        </li>
      ))}
    </ul>
  )
}

export function FindingVerifyPanel({ verification }) {
  const { t } = useTranslation()
  if (!verification?.verdict) return null
  return (
    <div className="rounded-xl border border-cyan-500/20 bg-cyan-950/15 p-4 space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <LiveVerdictBadge verification={verification} />
        {verification.confidence != null && (
          <span className="text-[10px] font-mono text-[var(--text-muted)]">
            {t('findings.liveVerify.confidence_pct', { pct: Math.round(verification.confidence * 100) })}
          </span>
        )}
        {verification.verified_at && (
          <span className="text-[10px] font-mono text-[var(--text-disabled)] ltr-only">
            {new Date(verification.verified_at).toLocaleString()}
          </span>
        )}
      </div>
      {verification.reproducible && (
        <p className="text-[11px] text-emerald-300/80 font-mono">{t('findings.liveVerify.reproduced')}</p>
      )}
      <FindingVerifyChecks checks={verification.checks} />
    </div>
  )
}

export default function FindingVerifyButton({
  finding,
  onVerified,
  deep = false,
  compact = false,
  variant = 'secondary',
}) {
  const { t } = useTranslation()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)

  const rawId = finding?.raw_id ?? finding?.id
  const existing = useMemo(
    () => finding?.live_verification || finding?.raw?.live_verification,
    [finding],
  )

  const runVerify = useCallback(async (e) => {
    e?.stopPropagation?.()
    if (!rawId || loading) return
    setLoading(true)
    setError('')
    try {
      const r = await apiFetch(`/api/findings/${encodeURIComponent(rawId)}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ deep }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok || !d.ok) throw new Error(d.detail || d.error || `HTTP ${r.status}`)
      const verification = {
        verdict: d.verdict,
        confidence: d.confidence,
        reproducible: d.reproducible,
        checks: d.checks,
        verified_at: d.verified_at,
        recommended_status: d.recommended_status,
      }
      setResult(verification)
      onVerified?.(rawId, verification, d)
    } catch (err) {
      setError(err?.message || t('findings.liveVerify.failed'))
    } finally {
      setLoading(false)
    }
  }, [rawId, loading, deep, onVerified, t])

  const active = result || existing

  if (compact) {
    return (
      <button
        type="button"
        onClick={runVerify}
        disabled={loading || !rawId}
        className="inline-flex items-center gap-1 px-2 py-1 rounded-lg text-[10px] font-mono border border-violet-500/35 text-violet-200/90 hover:bg-violet-500/10 disabled:opacity-40"
        title={t('findings.liveVerify.button')}
      >
        {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : <ShieldCheck className="w-3 h-3" />}
        {t('findings.liveVerify.button_short')}
      </button>
    )
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={runVerify}
          disabled={loading || !rawId}
          className={
            variant === 'primary'
              ? 'inline-flex items-center gap-1.5 px-4 py-2 rounded-xl border border-violet-500/40 bg-violet-500/15 text-violet-100 text-[12px] font-mono uppercase hover:bg-violet-500/25 disabled:opacity-40'
              : 'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-mono border border-violet-500/35 text-violet-200 hover:bg-violet-500/10 disabled:opacity-40'
          }
        >
          {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
          {deep ? t('findings.liveVerify.button_deep') : t('findings.liveVerify.button')}
        </button>
        {!compact && !deep && (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation()
              if (loading || !rawId) return
              setLoading(true)
              setError('')
              apiFetch(`/api/findings/${encodeURIComponent(rawId)}/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ deep: true }),
              })
                .then(async (r) => {
                  const d = await r.json().catch(() => ({}))
                  if (!r.ok || !d.ok) throw new Error(d.detail || `HTTP ${r.status}`)
                  const verification = {
                    verdict: d.verdict,
                    confidence: d.confidence,
                    reproducible: d.reproducible,
                    checks: d.checks,
                    verified_at: d.verified_at,
                  }
                  setResult(verification)
                  onVerified?.(rawId, verification, d)
                })
                .catch((err) => setError(err?.message || t('findings.liveVerify.failed')))
                .finally(() => setLoading(false))
            }}
            disabled={loading || !rawId}
            className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-[10px] font-mono border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] disabled:opacity-40"
          >
            {t('findings.liveVerify.button_deep')}
          </button>
        )}
        {active?.verdict && <LiveVerdictBadge verification={active} />}
      </div>
      {error && (
        <div className="text-[11px] font-mono text-rose-300/90 border border-rose-500/30 rounded-lg px-3 py-2">
          {error}
        </div>
      )}
      {active && <FindingVerifyPanel verification={active} />}
    </div>
  )
}
