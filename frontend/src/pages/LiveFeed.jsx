/**
 * Live Findings Feed — the command-center ticker.
 *
 * Wired to the live GET /api/command-center/ticker endpoint, which streams the
 * 100 most recent findings as an event feed (time, target, severity, message).
 * Auto-refreshes on an interval for a live "wall display" surface. Route: /live-feed
 */
import { useState, useCallback, useEffect, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Radio, Search, Pause, Play } from 'lucide-react'
import { useVisiblePolling } from '../hooks/useVisiblePolling'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import FilterPills from '../components/ui/FilterPills'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useClient } from '../context/ClientContext'
import { apiFetch } from '../lib/apiBase'
import { SEV_ORDER, SEV_COLOR } from '../lib/severity'

const NS = 'pages.liveFeed'
const REFRESH_MS = 15000

export default function LiveFeed() {
  const { t } = useTranslation()
  const { clients } = useClient()
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [sevFilter, setSevFilter] = useState('all')
  const [paused, setPaused] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)

  const load = useCallback(async (opts = {}) => {
    setError('')
    // Manual refresh shows the spinner; the 15s poll refreshes silently.
    if (!opts.silent) setLoading(true)
    try {
      const r = await apiFetch('/api/command-center/ticker')
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`)
      setEvents(Array.isArray(d.events) ? d.events : [])
      setLastUpdated(new Date())
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    load()
  }, [load])

  // Live polling — suspended while paused; skips ticks while the tab is hidden.
  useVisiblePolling(() => load({ silent: true }), REFRESH_MS, { paused })

  const severities = useMemo(
    () => [...new Set(events.map((e) => (e.severity || '').toLowerCase()).filter(Boolean))].sort(
      (a, b) => (SEV_ORDER[b] || 0) - (SEV_ORDER[a] || 0),
    ),
    [events],
  )

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return events.filter((e) => {
      if (sevFilter !== 'all' && (e.severity || '').toLowerCase() !== sevFilter) return false
      if (!q) return true
      return `${e.message} ${e.target} ${e.agentId}`.toLowerCase().includes(q)
    })
  }, [events, search, sevFilter])

  const stats = useMemo(() => {
    let critHigh = 0
    for (const e of events) {
      const s = (e.severity || '').toLowerCase()
      if (s === 'critical' || s === 'high') critHigh += 1
    }
    return { total: events.length, critHigh, severities: severities.length }
  }, [events, severities])

  const sevPills = useMemo(
    () => [
      { id: 'all', label: t(`${NS}.all_severities`), active: sevFilter === 'all', onClick: () => setSevFilter('all') },
      ...severities.map((s) => ({ id: s, label: s, active: sevFilter === s, onClick: () => setSevFilter(s) })),
    ],
    [severities, sevFilter, t],
  )

  // Resolve the event's client id → a human name (falls back to "client N").
  const clientName = useMemo(() => {
    const byId = new Map((clients || []).map((c) => [String(c.id), c.name || c.domain]))
    return (id) => byId.get(String(id)) || t(`${NS}.client`, { id })
  }, [clients, t])

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={paused ? t(`${NS}.badge_paused`) : t(`${NS}.badge_live`)}
      badgeColor={paused ? '#94a3b8' : '#4ade80'}
      icon={<Radio className="w-5 h-5" />}
      actions={
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setPaused((p) => !p)}
            aria-pressed={paused}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-[var(--border-default)] text-[var(--text-tertiary)] text-xs font-mono hover:text-[var(--text-primary)] hover:border-[var(--border-strong)] transition-colors"
          >
            {paused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            {paused ? t(`${NS}.resume`) : t(`${NS}.pause`)}
          </button>
          <ShellScanActions onRefresh={load} refreshLoading={loading} exportDisabled />
        </div>
      }
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        {loading && events.length === 0 && <SkeletonWidgetGrid count={3} />}

        {error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        {(events.length > 0 || !loading) && !error && (
          <>
            <div className="grid grid-cols-3 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_total`)} value={stats.total} accent="#22d3ee" />
              <ExecutiveWidget label={t(`${NS}.kpi_crit_high`)} value={stats.critHigh} accent="#f43f5e" />
              <ExecutiveWidget label={t(`${NS}.kpi_severities`)} value={stats.severities} accent="#a78bfa" />
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <div className="relative flex-1 min-w-[220px] max-w-md">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-disabled)] pointer-events-none" />
                <input
                  type="search"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  aria-label={t(`${NS}.search_placeholder`)}
                  placeholder={t(`${NS}.search_placeholder`)}
                  className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-xl pl-10 pr-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-emerald-500/40"
                />
              </div>
              {severities.length > 0 && <FilterPills pills={sevPills} />}
              {lastUpdated && (
                <span className="text-[10px] font-mono text-[var(--text-muted)] ml-auto flex items-center gap-1.5">
                  <span className={`w-1.5 h-1.5 rounded-full ${paused ? 'bg-gray-500' : 'bg-emerald-400 animate-pulse'}`} />
                  {t(`${NS}.updated`, { time: lastUpdated.toLocaleTimeString() })}
                </span>
              )}
            </div>

            {events.length === 0 ? (
              <EmptyState icon="📡" title={t(`${NS}.empty_title`)} body={t(`${NS}.empty_body`)} />
            ) : filtered.length === 0 ? (
              <EmptyState icon="🔍" title={t(`${NS}.no_match_title`)} body={t(`${NS}.no_match_body`)} />
            ) : (
              <ul className="space-y-1.5">
                {filtered.map((e) => {
                  const sev = (e.severity || 'info').toLowerCase()
                  const c = SEV_COLOR[sev] || SEV_COLOR.info
                  return (
                    <li
                      key={e.id}
                      className="flex items-center gap-3 rounded-lg border bg-[var(--table-surface)] px-3 py-2"
                      style={{ borderColor: `${c}30` }}
                    >
                      <span className="w-1 h-8 rounded-full shrink-0" style={{ background: c }} aria-hidden />
                      <code className="text-[11px] font-mono text-[var(--text-muted)] shrink-0 tabular-nums">{e.time || '—'}</code>
                      <span
                        className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-wider shrink-0"
                        style={{ color: c, borderColor: `${c}40`, background: `${c}10` }}
                      >
                        {sev}
                      </span>
                      <span className="text-[12px] text-[var(--text-secondary)] truncate flex-1 min-w-0" title={e.message}>
                        {e.message || '—'}
                      </span>
                      <span className="text-[10px] font-mono text-[var(--text-muted)] shrink-0 hidden sm:inline max-w-[10rem] truncate" title={clientName(e.target)}>
                        {clientName(e.target)}
                      </span>
                    </li>
                  )
                })}
              </ul>
            )}
          </>
        )}
      </div>
    </PageShell>
  )
}
