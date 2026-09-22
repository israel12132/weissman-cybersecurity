/**
 * ITDR — IdP connectors (Entra/Okta/Google) + live auth events.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Fingerprint } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import FilterPills from '../components/ui/FilterPills'
import ShellScanActions from '../components/engine/ShellScanActions'
import Button from '../components/ui/Button'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { apiFetch } from '../utils/apiFetch'
import { downloadCsv } from '../lib/exportFindingsCsv'
import { useToast } from '../components/ui/Toaster'
import { useClient } from '../context/ClientContext'
import { configuredItdrProviders, ITDR_PROVIDERS } from '../lib/itdrConnectors'

const NS = 'pages.itdrCommandCenter'

export default function ItdrCommandCenter() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const { selectedClientId } = useClient()
  const [connectors, setConnectors] = useState({})
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [outcomeFilter, setOutcomeFilter] = useState('all')
  const [pulling, setPulling] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [c, e] = await Promise.all([
        apiFetch('/api/itdr/connectors'),
        apiFetch('/api/itdr/auth-events?limit=500'),
      ])
      if (c?.ok === false || c?.unavailable) throw new Error(c.detail || t(`${NS}.load_failed`))
      if (e?.ok === false || e?.unavailable) throw new Error(e.detail || t(`${NS}.load_failed`))
      setConnectors(c.connectors && typeof c.connectors === 'object' ? c.connectors : {})
      setEvents(Array.isArray(e.events) ? e.events : [])
    } catch (err) {
      setError(err.message || t(`${NS}.load_failed`))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => { load() }, [load])

  const outcomeCounts = useMemo(() => {
    let fail = 0
    let success = 0
    let mfa = 0
    for (const ev of events) {
      if (ev.success === false) fail += 1
      else if (ev.success) success += 1
      if (ev.mfa_prompted) mfa += 1
    }
    return { all: events.length, fail, success, mfa }
  }, [events])

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    return events.filter((ev) => {
      if (outcomeFilter === 'fail' && ev.success !== false) return false
      if (outcomeFilter === 'success' && !ev.success) return false
      if (outcomeFilter === 'mfa' && !ev.mfa_prompted) return false
      if (!q) return true
      return `${ev.username} ${ev.ip} ${ev.country} ${ev.provider}`.toLowerCase().includes(q)
    })
  }, [events, searchQuery, outcomeFilter])

  const outcomePills = useMemo(
    () =>
      [
        { id: 'all', label: t('common.all'), count: outcomeCounts.all, color: '#22d3ee' },
        { id: 'fail', label: t(`${NS}.filter_failed`), count: outcomeCounts.fail, color: '#fb7185' },
        { id: 'success', label: t(`${NS}.filter_success`), count: outcomeCounts.success, color: '#34d399' },
        { id: 'mfa', label: t(`${NS}.filter_mfa`), count: outcomeCounts.mfa, color: '#a78bfa' },
      ].map((p) => ({ ...p, active: outcomeFilter === p.id, onClick: () => setOutcomeFilter(p.id) })),
    [outcomeCounts, outcomeFilter, t],
  )

  const exportCsv = useCallback(() => {
    if (error) return
    downloadCsv(
      filtered.map((ev) => [ev.ts, ev.username, ev.ip, ev.country, ev.success, ev.mfa_prompted]),
      ['ts', 'user', 'ip', 'country', 'success', 'mfa'],
      'weissman-itdr-events',
    )
  }, [error, filtered])

  const fails = events.filter((ev) => ev.success === false).length
  const armedProviders = useMemo(() => configuredItdrProviders(connectors), [connectors])
  const unconfigured = armedProviders.length === 0

  const pull = async (provider) => {
    if (!armedProviders.includes(provider)) {
      toast.error(t(`${NS}.pull_unconfigured`, { provider }))
      return
    }
    setPulling(provider)
    try {
      const d = await apiFetch('/api/itdr/connectors/pull', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider, client_id: selectedClientId || undefined }),
      })
      if (d?.ok === false || d?.unavailable) throw new Error(d.detail || 'pull failed')
      if (d.ingested == null) throw new Error('pull ingested unconfirmed')
      toast.success(t(`${NS}.pulled`, { provider, n: d.ingested }))
      await load()
    } catch (err) {
      toast.error(err.message || t(`${NS}.pull_failed`))
    } finally {
      setPulling('')
    }
  }

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      icon={<Fingerprint />}
      actions={(
        <ShellScanActions onRefresh={load} onExport={error ? undefined : exportCsv} refreshLoading={loading} exportDisabled={!!error || !filtered.length} />
      )}
    >
      <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>
      {loading ? <SkeletonWidgetGrid count={3} /> : error ? (
        <EmptyState title={t(`${NS}.load_failed`)} body={error} />
      ) : (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            <ExecutiveWidget label={t(`${NS}.kpi_events`)} value={events.length} />
            <ExecutiveWidget label={t(`${NS}.kpi_fails`)} value={fails} />
            <div
              data-testid="itdr-armed-providers"
              data-live={unconfigured ? 'false' : 'true'}
              data-armed={String(armedProviders.length)}
            >
              <ExecutiveWidget label={t(`${NS}.kpi_providers`)} value={armedProviders.length} />
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {ITDR_PROVIDERS.map((p) => (
              <Button
                key={p}
                type="button"
                variant="ghost"
                disabled={!!pulling || !armedProviders.includes(p)}
                onClick={() => pull(p)}
              >
                {pulling === p ? t(`${NS}.pulling`) : t(`${NS}.pull`, { provider: p })}
              </Button>
            ))}
          </div>
          <p className="text-xs text-[var(--text-muted)] font-mono">{t(`${NS}.connector_hint`)} {armedProviders.join(', ') || t(`${NS}.none_armed`)}</p>
          <div className="flex flex-wrap items-end gap-4">
            <input
              type="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={t(`${NS}.search_placeholder`)}
              aria-label={t(`${NS}.search_placeholder`)}
              className="w-full max-w-sm px-3 py-2 rounded-lg text-sm bg-[var(--bg-3)] border border-[var(--border-default)] text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500/40"
            />
            {events.length > 0 && <FilterPills pills={outcomePills} />}
          </div>
          {!filtered.length ? (
            <EmptyState
              title={t(unconfigured ? `${NS}.empty_unconfigured_title` : `${NS}.empty_title`)}
              body={t(unconfigured ? `${NS}.empty_unconfigured_body` : `${NS}.empty_body`)}
            />
          ) : (
            <ul className="space-y-1.5 font-mono text-xs">
              {filtered.slice(0, 200).map((ev, i) => (
                <li key={`${ev.ts}-${ev.ip}-${i}`} className="border border-[var(--border-default)] bg-[var(--table-surface)] rounded px-3 py-2 flex justify-between gap-3">
                  <span className="text-[var(--text-primary)]">{ev.username} @ {ev.ip}</span>
                  <span className={ev.success ? 'text-emerald-300' : 'text-rose-300'}>
                    {ev.success ? t(`${NS}.ok`) : t(`${NS}.fail`)} {ev.mfa_prompted ? 'MFA' : ''}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </PageShell>
  )
}
