/**
 * Platform Security Posture — self-audit score + weighted checks.
 *
 * Wired to the live GET /api/security/posture-score endpoint, which scores the
 * platform's own hardening (0–100 + letter grade) from a set of weighted
 * checks. Platform-wide — no client selection. Route: /security-posture
 */
import React, { useState, useCallback, useEffect, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { ShieldCheck, Check, X, Search } from 'lucide-react'
import PageShell from './PageShell'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import { SkeletonWidgetGrid, SkeletonCard } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { apiFetch } from '../lib/apiBase'
import { postureGradeColor as gradeColor, postureScoreColor as scoreColor } from '../lib/riskFormat'

const NS = 'pages.securityPosture'

/** Circular score gauge. */
function ScoreRing({ score, grade }) {
  const s = Math.max(0, Math.min(100, Number(score) || 0))
  const color = scoreColor(s)
  const R = 54
  const C = 2 * Math.PI * R
  const dash = (s / 100) * C
  return (
    <div className="relative w-40 h-40 shrink-0">
      <svg viewBox="0 0 128 128" className="w-full h-full -rotate-90">
        <circle cx="64" cy="64" r={R} fill="none" stroke="var(--border-strong)" strokeWidth="10" />
        <circle
          cx="64"
          cy="64"
          r={R}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${C}`}
          style={{ transition: 'stroke-dasharray 0.6s ease' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-bold tabular-nums" style={{ color }}>{s}</span>
        <span className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">/ 100</span>
        {grade && (
          <span className="mt-1 text-lg font-black" style={{ color: gradeColor(grade) }}>{String(grade).toUpperCase()}</span>
        )}
      </div>
    </div>
  )
}

export default function SecurityPosture() {
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState('all') // all | failed | passed

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const r = await apiFetch('/api/security/posture-score')
      const d = await r.json().catch(() => ({}))
      if (!r.ok || d.error) throw new Error(d.error || d.detail || `HTTP ${r.status}`)
      setData(d)
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    load()
  }, [load])

  const checks = useMemo(() => (Array.isArray(data?.checks) ? data.checks : []), [data])
  const summary = useMemo(() => {
    const passed = checks.filter((c) => c.passed)
    const passedWeight = passed.reduce((s, c) => s + (Number(c.weight) || 0), 0)
    const totalWeight = checks.reduce((s, c) => s + (Number(c.weight) || 0), 0)
    return { passed: passed.length, total: checks.length, passedWeight, totalWeight }
  }, [checks])

  // Failed first, then by descending weight — the remediation worklist.
  const orderedChecks = useMemo(
    () => [...checks].sort((a, b) => (a.passed === b.passed ? (b.weight || 0) - (a.weight || 0) : a.passed ? 1 : -1)),
    [checks],
  )

  // Live filter over the worklist: free-text (id/detail) + pass/fail status.
  const visibleChecks = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    return orderedChecks.filter((c) => {
      if (statusFilter === 'failed' && c.passed) return false
      if (statusFilter === 'passed' && !c.passed) return false
      if (!q) return true
      return (
        String(c.id || '').toLowerCase().includes(q) ||
        String(c.detail || '').toLowerCase().includes(q)
      )
    })
  }, [orderedChecks, searchQuery, statusFilter])

  const generatedAt = data?.generated_at ? new Date(data.generated_at).toLocaleString() : null

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={data?.grade ? `${t(`${NS}.grade`)} ${String(data.grade).toUpperCase()}` : t(`${NS}.badge`)}
      badgeColor={gradeColor(data?.grade)}
      icon={<ShieldCheck className="w-5 h-5" />}
      actions={<ShellScanActions onRefresh={load} refreshLoading={loading} exportDisabled />}
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        {loading && (
          <>
            <SkeletonWidgetGrid count={2} />
            <SkeletonCard lines={8} />
          </>
        )}

        {error && (
          <div className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        {!loading && !error && data && (
          <>
            <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--table-surface)] backdrop-blur-md p-6 flex flex-col sm:flex-row items-center gap-6">
              <ScoreRing score={data.score} grade={data.grade} />
              <div className="flex-1 min-w-0 space-y-3 w-full">
                <div className="grid grid-cols-2 gap-3">
                  <div className="rounded-xl bg-[var(--table-surface)] border border-[var(--border-subtle)] p-3">
                    <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-1">
                      {t(`${NS}.checks_passed`)}
                    </div>
                    <div className="text-xl font-bold text-emerald-300 tabular-nums">
                      {summary.passed}/{summary.total}
                    </div>
                  </div>
                  <div className="rounded-xl bg-[var(--table-surface)] border border-[var(--border-subtle)] p-3">
                    <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-1">
                      {t(`${NS}.weight_passed`)}
                    </div>
                    <div className="text-xl font-bold text-cyan-300 tabular-nums">
                      {summary.passedWeight}/{summary.totalWeight}
                    </div>
                  </div>
                </div>
                {generatedAt && (
                  <div className="text-[11px] font-mono text-[var(--text-muted)]">
                    {t(`${NS}.generated_at`, { time: generatedAt })}
                  </div>
                )}
              </div>
            </div>

            <div>
              <h2 className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-1">
                {t(`${NS}.checks_heading`)}
              </h2>
              <p className="text-[11px] text-[var(--text-muted)] mb-3">{t(`${NS}.checks_hint`)}</p>

              {/* Live worklist filter — free-text over id/detail + pass/fail status */}
              <div className="flex flex-col sm:flex-row sm:items-center gap-2 mb-3">
                <div className="relative flex-1 min-w-0">
                  <Search className="absolute top-1/2 -translate-y-1/2 left-2.5 w-3.5 h-3.5 text-[var(--text-muted)] pointer-events-none" aria-hidden />
                  <input
                    type="search"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder={t(`${NS}.search_placeholder`)}
                    aria-label={t(`${NS}.search_placeholder`)}
                    className="w-full bg-[var(--table-surface)] border border-[var(--border-default)] rounded-lg pl-8 pr-2.5 py-1.5 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-cyan-500/40"
                  />
                </div>
                <div className="flex items-center gap-1 shrink-0" role="group" aria-label={t(`${NS}.filter_status`)}>
                  {['all', 'failed', 'passed'].map((f) => (
                    <button
                      key={f}
                      type="button"
                      onClick={() => setStatusFilter(f)}
                      aria-pressed={statusFilter === f}
                      className={[
                        'px-2.5 py-1.5 rounded-lg text-[10px] font-mono uppercase tracking-wider border transition-colors',
                        statusFilter === f
                          ? 'bg-cyan-500/15 text-cyan-200 border-cyan-500/30'
                          : 'text-[var(--text-muted)] border-[var(--border-default)] hover:text-[var(--text-secondary)]',
                      ].join(' ')}
                    >
                      {t(`${NS}.filter_${f}`)}
                    </button>
                  ))}
                </div>
              </div>
              <div className="text-[10px] font-mono text-[var(--text-muted)] mb-2" aria-live="polite">
                {t(`${NS}.showing_count`, { shown: visibleChecks.length, total: orderedChecks.length })}
              </div>

              {visibleChecks.length === 0 ? (
                <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--table-surface)] px-4 py-6 text-center text-[12px] font-mono text-[var(--text-muted)]">
                  {t(`${NS}.no_matches`)}
                </div>
              ) : (
              <ul className="space-y-2">
                {visibleChecks.map((c) => (
                  <li
                    key={c.id}
                    className="flex items-start gap-3 rounded-xl border bg-[var(--table-surface)] p-3"
                    style={{ borderColor: c.passed ? 'rgba(74,222,128,0.2)' : 'rgba(239,68,68,0.28)' }}
                  >
                    <span
                      className="mt-0.5 w-5 h-5 rounded-full flex items-center justify-center shrink-0"
                      style={{ background: c.passed ? 'rgba(74,222,128,0.15)' : 'rgba(239,68,68,0.15)' }}
                    >
                      {c.passed ? (
                        <Check className="w-3 h-3 text-emerald-400" aria-hidden />
                      ) : (
                        <X className="w-3 h-3 text-rose-400" aria-hidden />
                      )}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-[12px] font-mono text-[var(--text-secondary)]">{c.id}</span>
                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-[var(--border-default)] bg-[var(--row-hover-bg)] text-[var(--text-muted)]">
                          {t(`${NS}.weight`, { weight: c.weight })}
                        </span>
                        <span
                          className="text-[9px] font-mono px-1.5 py-0.5 rounded uppercase tracking-wider"
                          style={{
                            color: c.passed ? '#4ade80' : '#f87171',
                            background: c.passed ? 'rgba(74,222,128,0.1)' : 'rgba(239,68,68,0.1)',
                          }}
                        >
                          {c.passed ? t(`${NS}.pass`) : t(`${NS}.fail`)}
                        </span>
                      </div>
                      {c.detail && <p className="text-[12px] text-[var(--text-tertiary)] mt-1 leading-relaxed">{c.detail}</p>}
                    </div>
                  </li>
                ))}
              </ul>
              )}
            </div>
          </>
        )}
      </div>
    </PageShell>
  )
}
