import { useCallback, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Loader2, ShieldCheck, ShieldAlert, ShieldQuestion, ShieldX } from 'lucide-react'
import { apiFetch } from '../../utils/apiFetch'
import Button from '../ui/Button'

const VERDICT_META = {
  CONFIRMED: { color: '#22c55e', icon: ShieldCheck },
  LIKELY_VALID: { color: '#38bdf8', icon: ShieldCheck },
  INCONCLUSIVE: { color: '#fbbf24', icon: ShieldQuestion },
  NOISE: { color: '#94a3b8', icon: ShieldX },
  FALSE_POSITIVE: { color: '#f87171', icon: ShieldAlert },
}

/** Numeric row id / VLN- token / finding_id accepted by POST /api/findings/:id/verify */
export function findingVerifyId(finding) {
  if (!finding || typeof finding !== 'object') return ''
  const candidates = [finding.raw_id, finding.id, finding.finding_id]
  for (const c of candidates) {
    if (c == null || c === '') continue
    const s = String(c).trim()
    const m = s.match(/^(?:VLN-)?(\d+)$/i)
    if (m && Number(m[1]) > 0) return m[1]
  }
  if (finding.finding_id) return String(finding.finding_id).trim()
  if (finding.raw_id != null && finding.raw_id !== '') return String(finding.raw_id).trim()
  if (finding.id != null && finding.id !== '') return String(finding.id).trim()
  return ''
}

export function liveVerdictFromFinding(finding) {
  return (
    finding?.live_verdict
    || finding?.live_verification?.verdict
    || finding?.raw?.live_verification?.verdict
    || ''
  )
}

function verificationFromPayload(d) {
  if (!d) return null
  return {
    verdict: d.verdict,
    confidence: d.confidence,
    reproducible: d.reproducible,
    checks: d.checks,
    verified_at: d.verified_at,
    recommended_status: d.recommended_status,
    rescan_message: d.rescan_message,
    rescan_finding_count: d.rescan_finding_count,
    deep: d.deep,
  }
}

function isAbortError(err) {
  return err?.name === 'AbortError' || /aborted|abort|timeout/i.test(String(err?.message || ''))
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
      {list.map((c, idx) => (
        <li
          key={c.id || `${c.label || 'check'}-${idx}`}
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
  if (!verification?.verdict && !verification?.checks?.length) return null
  return (
    <div className="rounded-xl border border-cyan-500/20 bg-cyan-950/15 p-4 space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        {verification.verdict && <LiveVerdictBadge verification={verification} />}
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
      {verification.rescan_message && (
        <p className="text-[11px] text-[var(--text-secondary)] font-mono leading-relaxed break-words">
          {t('findings.liveVerify.rescan_note', { message: verification.rescan_message })}
          {verification.rescan_finding_count != null
            ? ` (${t('findings.liveVerify.rescan_count', { count: verification.rescan_finding_count })})`
            : ''}
        </p>
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
  const [loadingMode, setLoadingMode] = useState('')
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)

  const rawId = useMemo(() => findingVerifyId(finding), [finding])
  const existing = useMemo(
    () => finding?.live_verification || finding?.raw?.live_verification,
    [finding],
  )
  const loading = Boolean(loadingMode)

  const runVerify = useCallback(async (e, { deep: deepRun } = {}) => {
    e?.stopPropagation?.()
    e?.preventDefault?.()
    const useDeep = deepRun ?? deep
    if (loading) return
    if (!rawId) {
      setError(t('findings.liveVerify.missing_id'))
      return
    }
    setLoadingMode(useDeep ? 'deep' : 'verify')
    setError('')
    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null
    const timeoutMs = useDeep ? 120_000 : 45_000
    const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null
    try {
      const d = await apiFetch(`/api/findings/${encodeURIComponent(rawId)}/verify`, {
        method: 'POST',
        body: { deep: useDeep },
        signal: controller?.signal,
        breaker: false,
      })
      if (!d || d.ok === false) {
        throw new Error(d?.detail || d?.error || t('findings.liveVerify.failed'))
      }
      const verification = verificationFromPayload(d)
      if (!verification?.verdict && !verification?.checks?.length) {
        throw new Error(t('findings.liveVerify.empty_result'))
      }
      setResult(verification)
      onVerified?.(rawId, verification, d)
    } catch (err) {
      if (isAbortError(err)) {
        setError(t('findings.liveVerify.timeout'))
      } else {
        setError(err?.message || t('findings.liveVerify.failed'))
      }
    } finally {
      if (timer) clearTimeout(timer)
      setLoadingMode('')
    }
  }, [rawId, loading, deep, onVerified, t])

  const active = result || existing

  if (compact) {
    return (
      <span className="inline-flex flex-col items-start gap-1">
        <Button variant="unstyled"
          type="button"
          onClick={(e) => runVerify(e, { deep: false })}
          disabled={loading || !rawId}
          className={`inline-flex items-center gap-1 px-2 py-1 rounded-lg text-[10px] font-mono border ${
            error
              ? 'border-rose-500/50 text-rose-200 hover:bg-rose-500/10'
              : 'border-violet-500/35 text-violet-200/90 hover:bg-violet-500/10'
          } disabled:opacity-40`}
          title={error || t('findings.liveVerify.button')}
        >
          {loadingMode === 'verify' ? <Loader2 className="w-3 h-3 animate-spin" /> : <ShieldCheck className="w-3 h-3" />}
          {t('findings.liveVerify.button_short')}
        </Button>
        {error && (
          <span className="text-[9px] font-mono text-rose-300/90 max-w-[12rem] leading-snug">{error}</span>
        )}
      </span>
    )
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="unstyled"
          type="button"
          onClick={(e) => runVerify(e, { deep: false })}
          disabled={loading || !rawId}
          className={
            variant === 'primary'
              ? 'inline-flex items-center gap-1.5 px-4 py-2 rounded-xl border border-violet-500/40 bg-violet-500/15 text-violet-100 text-[12px] font-mono uppercase hover:bg-violet-500/25 disabled:opacity-40'
              : 'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-mono border border-violet-500/35 text-violet-200 hover:bg-violet-500/10 disabled:opacity-40'
          }
        >
          {loadingMode === 'verify' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
          {deep ? t('findings.liveVerify.button_deep') : t('findings.liveVerify.button')}
        </Button>
        {!compact && !deep && (
          <Button variant="unstyled"
            type="button"
            onClick={(e) => runVerify(e, { deep: true })}
            disabled={loading || !rawId}
            className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-[10px] font-mono border border-cyan-500/35 text-cyan-200/90 hover:bg-cyan-500/10 disabled:opacity-40"
            title={t('findings.liveVerify.button_deep_hint')}
          >
            {loadingMode === 'deep' ? <Loader2 className="w-3 h-3 animate-spin" /> : null}
            {loadingMode === 'deep'
              ? t('findings.liveVerify.button_deep_running')
              : t('findings.liveVerify.button_deep')}
          </Button>
        )}
        {active?.verdict && <LiveVerdictBadge verification={active} />}
      </div>
      {loadingMode === 'deep' && (
        <p className="text-[11px] font-mono text-cyan-200/80">{t('findings.liveVerify.deep_running')}</p>
      )}
      {error && (
        <div className="text-[11px] font-mono text-rose-300/90 border border-rose-500/30 rounded-lg px-3 py-2">
          {error}
        </div>
      )}
      {active && <FindingVerifyPanel verification={active} />}
    </div>
  )
}
