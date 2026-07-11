import { useEffect, useMemo, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Activity, GitPullRequest, AlertTriangle } from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import EmptyState from '../components/ui/EmptyState'
import { SkeletonTable } from '../components/ui/Skeleton'
import { apiFetch } from '../lib/apiBase'
import RemediationAnalyticsPanel from '../components/remediation/RemediationAnalyticsPanel'
import HealReadinessPanel from '../components/remediation/HealReadinessPanel'
import HealTrendSparkline from '../components/remediation/HealTrendSparkline'

/**
 * RemediationAnalytics — aggregates auto-heal telemetry across every client that
 * appears in /api/findings, reusing the exact heal-stats shape RemediationHub builds,
 * plus a merged "recent heals" activity feed from /api/clients/:id/heal-requests.
 */

// mirrors VERDICT_META in components/remediation/RemediationDetail.jsx
const VERDICT_META = {
  fixed: { color: '#22c55e', key: 'verdict_fixed' },
  broke_app: { color: '#f43f5e', key: 'verdict_broke_app' },
  still_vulnerable: { color: '#fb923c', key: 'verdict_still_vulnerable' },
  inconclusive: { color: '#94a3b8', key: 'verdict_inconclusive' },
}

export default function RemediationAnalytics() {
  const { t } = useTranslation()
  const [findings, setFindings] = useState([])
  const [healStats, setHealStats] = useState(null)
  const [heals, setHeals] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const r = await apiFetch('/api/findings?limit=2000')
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const d = await r.json()
      setFindings(Array.isArray(d) ? d : Array.isArray(d?.findings) ? d.findings : [])
    } catch (e) {
      setError(e.message || 'Failed to load findings')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  // Distinct client_ids — same derivation as RemediationHub
  const clientIds = useMemo(
    () => [...new Set(findings.map((f) => f.client_id).filter(Boolean))].slice(0, 25),
    [findings],
  )

  // Aggregate heal-stats — identical reducer to RemediationHub
  useEffect(() => {
    if (!clientIds.length) { setHealStats(null); return undefined }
    let cancelled = false
    Promise.all(
      clientIds.map((id) =>
        apiFetch(`/api/clients/${id}/heal-stats`).then((r) => (r.ok ? r.json() : null)).catch(() => null)),
    ).then((list) => {
      if (cancelled) return
      const channelMap = {}
      const agg = list.filter(Boolean).reduce(
        (a, s) => {
          for (const c of s.by_channel || []) channelMap[c.channel] = (channelMap[c.channel] || 0) + (c.count || 0)
          return {
            total: a.total + (s.total || 0),
            fixed: a.fixed + (s.fixed || 0),
            broke_app: a.broke_app + (s.broke_app || 0),
            still_vulnerable: a.still_vulnerable + (s.still_vulnerable || 0),
            attested: a.attested + (s.attested || 0),
            attemptsSum: a.attemptsSum + (s.avg_attempts || 1) * (s.total || 0),
            maxAttempts: Math.max(a.maxAttempts, s.max_attempts || 1),
          }
        },
        { total: 0, fixed: 0, broke_app: 0, still_vulnerable: 0, attested: 0, attemptsSum: 0, maxAttempts: 1 },
      )
      agg.by_channel = Object.entries(channelMap)
        .map(([channel, count]) => ({ channel, count }))
        .sort((x, y) => y.count - x.count)
      setHealStats(agg.total > 0 ? agg : null)
    })
    return () => { cancelled = true }
  }, [clientIds])

  // Recent heals feed — merge /heal-requests across clients, newest first
  useEffect(() => {
    if (!clientIds.length) { setHeals([]); return undefined }
    let cancelled = false
    Promise.all(
      clientIds.map((id) =>
        apiFetch(`/api/clients/${id}/heal-requests`)
          .then((r) => (r.ok ? r.json() : null)).catch(() => null)
          .then((d) => {
            const list = Array.isArray(d) ? d : Array.isArray(d?.requests) ? d.requests : []
            return list.map((x) => ({ ...x, client_id: id }))
          })),
    ).then((lists) => {
      if (cancelled) return
      const merged = lists.flat().filter(Boolean)
      merged.sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')))
      setHeals(merged.slice(0, 50))
    })
    return () => { cancelled = true }
  }, [clientIds])

  return (
    <PageShell
      title={t('pages.remediationAnalytics.title', { defaultValue: 'Remediation Analytics' })}
      subtitle={t('pages.remediationAnalytics.subtitle', { defaultValue: 'Auto-heal outcomes aggregated across every active client' })}
      badge={t('pages.remediationAnalytics.badge', { defaultValue: 'ANALYTICS' })}
      badgeColor="#22d3ee"
      icon={<Activity />}
      actions={<ShellScanActions onRefresh={load} refreshLoading={loading} exportDisabled />}
    >
      <div className="space-y-6">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <p className="text-xs text-white/45 font-mono">
            {t('pages.remediationAnalytics.intro', { defaultValue: 'Live auto-heal telemetry from GET /api/clients/:id/heal-stats and /heal-requests.' })}
          </p>
          <Link to="/remediation" className="text-xs text-cyan-300 hover:text-cyan-200">
            {t('pages.remediationAnalytics.open_hub', { defaultValue: 'Remediation Hub →' })}
          </Link>
        </div>

        <HealReadinessPanel />

        <HealTrendSparkline clientIds={clientIds} days={30} />

        {error && (
          <div className="p-4 rounded-xl border border-red-500/30 bg-red-900/20 text-red-300 text-sm flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            {t('pages.remediationHub.load_error', { error })}
          </div>
        )}

        {loading ? (
          <SkeletonTable rows={4} cols={3} />
        ) : healStats ? (
          <RemediationAnalyticsPanel stats={healStats} />
        ) : (
          <EmptyState
            compact
            icon="shield"
            title={t('pages.remediationAnalytics.empty_title', { defaultValue: 'No auto-heal runs yet.' })}
            body={t('pages.remediationAnalytics.empty_hint', { defaultValue: 'Trigger a heal from the Remediation Hub to populate analytics.' })}
          />
        )}

        {/* Recent heals feed */}
        <section className="space-y-2">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <GitPullRequest className="w-4 h-4 text-cyan-400" />
            {t('pages.remediationAnalytics.recent_heals', { defaultValue: 'Recent heals' })}
          </h3>
          {loading ? (
            <SkeletonTable rows={5} cols={4} />
          ) : heals.length === 0 ? (
            <div className="text-xs text-white/30 font-mono">—</div>
          ) : (
            <div className="divide-y divide-white/5 rounded-xl border border-white/10 overflow-hidden bg-black/40">
              {heals.map((h) => {
                const vm = h.verdict ? VERDICT_META[h.verdict] : null
                return (
                  <div
                    key={h.id || `${h.client_id}-${h.finding_id}-${h.created_at}`}
                    className="flex items-center justify-between gap-3 px-4 py-2.5 text-xs hover:bg-white/[0.03]"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span style={{ color: vm ? vm.color : 'rgba(255,255,255,0.3)' }}>●</span>
                      <span className="text-white/70 font-mono truncate max-w-[220px]">{h.finding_id || '—'}</span>
                      <span className="text-white/60 truncate">
                        {vm ? t(`pages.remediationHub.${vm.key}`, { defaultValue: h.verdict }) : (h.verification_status || h.status || '—')}
                      </span>
                      {h.channel && <span className="text-[10px] text-white/35 font-mono">{h.channel}</span>}
                      {h.attempts > 1 && <span className="text-[10px] text-amber-300/70 font-mono">×{h.attempts}</span>}
                      {h.attested && <span className="text-[10px] text-emerald-300/70">🔏</span>}
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      {h.pr_url && (
                        <a href={h.pr_url} target="_blank" rel="noreferrer" className="text-cyan-300/80 hover:text-cyan-200">
                          <GitPullRequest className="w-3.5 h-3.5" />
                        </a>
                      )}
                      <span className="text-[10px] text-white/30 font-mono whitespace-nowrap">{(h.created_at || '').slice(0, 10)}</span>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </section>
      </div>
    </PageShell>
  )
}
