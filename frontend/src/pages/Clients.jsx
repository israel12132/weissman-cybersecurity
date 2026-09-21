import { useEffect, useState, useMemo, useRef, useCallback } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import PremiumPageHeader from '../components/ui/PremiumPageHeader'
import PortfolioPosturePanel from './PortfolioPosturePanel'
import PortfolioAttackPanel from './PortfolioAttackPanel'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import EmptyState from '../components/ui/EmptyState'
import { SkeletonCardGrid, SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { apiFetch } from '../utils/apiFetch'
import { confirmDialog } from '../utils/confirmDialog'
import { useToast } from '../components/ui/Toaster'
import Button from '../components/ui/Button'
import { useAuth } from '../context/AuthContext'

function fmtUsd(n) {
  if (n == null) return '$—'
  const abs = Math.abs(n)
  if (abs >= 1_000_000_000) return `$${(n / 1_000_000_000).toFixed(2)}B`
  if (abs >= 1_000_000) return `$${(n / 1_000_000).toFixed(2)}M`
  if (abs >= 1_000) return `$${(n / 1_000).toFixed(1)}k`
  return `$${Math.round(n).toLocaleString()}`
}

// Portfolio triage colours, keyed to worst-case single-loss exposure ($SLE).
const SEV = {
  critical: { color: '#f43f5e', bg: 'rgba(244,63,94,0.14)', border: 'rgba(244,63,94,0.38)' },
  high: { color: '#fb923c', bg: 'rgba(251,146,60,0.14)', border: 'rgba(251,146,60,0.34)' },
  medium: { color: '#fbbf24', bg: 'rgba(251,191,36,0.13)', border: 'rgba(251,191,36,0.32)' },
  low: { color: '#34d399', bg: 'rgba(52,211,153,0.13)', border: 'rgba(52,211,153,0.32)' },
  none: { color: '#94a3b8', bg: 'rgba(148,163,184,0.1)', border: 'rgba(148,163,184,0.26)' },
}

function severityKey(snap) {
  if (!snap) return 'none'
  const v = snap.sle_worst_usd || 0
  if (v > 1_000_000) return 'critical'
  if (v > 250_000) return 'high'
  if (v > 50_000) return 'medium'
  if (v > 0) return 'low'
  return 'none'
}

export default function Clients() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const { canCreateClients, canDeleteClients, isClientUser } = useAuth()
  const [clients, setClients] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [scanningId, setScanningId] = useState(null)
  const [scanToast, setScanToast] = useState(null)
  const [lastUpdated, setLastUpdated] = useState(null)
  const [risk, setRisk] = useState({})
  // Latest risk map, read inside the fetch effect without making it a dependency
  // (which would refire the whole batch on every incremental setRisk).
  const riskRef = useRef(risk)
  useEffect(() => { riskRef.current = risk }, [risk])

  useEffect(() => {
    loadClients()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    let cancelled = false
    if (clients.length === 0) return undefined
    // Only fetch clients whose risk we haven't loaded yet (skips a full refetch
    // on every refresh/delete), and cap concurrency so a large tenant doesn't
    // fire one burst that trips the API rate limiter / circuit breaker.
    const pending = clients.filter((c) => riskRef.current[c.id] === undefined)
    if (pending.length === 0) return undefined
    const CONCURRENCY = 5
    let idx = 0
    async function worker() {
      while (!cancelled && idx < pending.length) {
        const c = pending[idx]
        idx += 1
        let snap = null
        try {
          const d = await apiFetch(`/api/financial-risk/${c.id}`)
          snap = d?.snapshot || null
        } catch (_) {
          snap = null
        }
        if (cancelled) return
        setRisk((m) => ({ ...m, [c.id]: snap }))
      }
    }
    Promise.all(Array.from({ length: Math.min(CONCURRENCY, pending.length) }, () => worker()))
    return () => { cancelled = true }
  }, [clients])

  async function loadClients() {
    setLoading(true)
    setError('')
    try {
      const data = await apiFetch('/api/clients')
      const clientList = Array.isArray(data) ? data : (data.clients || [])
      setClients(clientList)
      setLastUpdated(new Date())
    } catch (err) {
      if (err?.status) {
        const text = err.response
          ? await err.response.text().catch(() => 'Failed to load clients')
          : (err.message || 'Failed to load clients')
        setError(t('clients_page.load_failed', { detail: text }))
      } else {
        setError(t('clients_page.load_error', { detail: err.message }))
      }
    } finally {
      setLoading(false)
    }
  }

  async function recomputeRisk(clientId) {
    try {
      const d = await apiFetch(`/api/financial-risk/${clientId}?recompute=1`)
      if (d?.snapshot) {
        setRisk((m) => ({ ...m, [clientId]: d.snapshot }))
      }
    } catch (_) { /* surfaced via the empty $— card */ }
  }

  const totals = clients.reduce(
    (acc, c) => {
      const s = risk[c.id]
      if (!s) return acc
      acc.assets += s.total_asset_value_usd || 0
      acc.crown += s.crown_jewel_value_usd || 0
      acc.sle += s.sle_worst_usd || 0
      acc.ale += s.ale_annualised_usd || 0
      acc.have += 1
      return acc
    },
    { assets: 0, crown: 0, sle: 0, ale: 0, have: 0 },
  )

  async function runScan(clientId, clientName) {
    const ok = await confirmDialog({
      title: t('clients_page.scan_title'),
      message: t('clients_page.scan_confirm', { name: clientName }),
      confirmLabel: t('clients_page.scan_action'),
      cancelLabel: t('common.cancel'),
      variant: 'primary',
    })
    if (!ok) return
    setScanningId(clientId)
    setScanToast(null)
    try {
      const data = await apiFetch(`/api/clients/${clientId}/scan/run-all`, { method: 'POST' })
      setScanToast({
        kind: 'ok',
        message: data.message || t('clients_page.scan_queued', { count: data.jobs_queued ?? 0 }),
        jobs_queued: data.jobs_queued ?? 0,
      })
    } catch (err) {
      if (err?.status) {
        const b = err.response ? await err.response.json().catch(() => ({})) : {}
        setScanToast({
          kind: 'error',
          message: b.detail || t('clients_page.scan_failed', { status: err.status }),
        })
      } else {
        setScanToast({ kind: 'error', message: err.message || t('clients_page.scan_error') })
      }
    } finally {
      setScanningId(null)
    }
  }

  async function deleteClient(clientId, clientName) {
    const ok = await confirmDialog({
      title: t('clients_page.delete_title'),
      message: t('clients_page.delete_confirm', { name: clientName }),
      confirmLabel: t('common.delete'),
      cancelLabel: t('common.cancel'),
      variant: 'danger',
    })
    if (!ok) return
    try {
      await apiFetch(`/api/clients/${clientId}`, { method: 'DELETE' })
      loadClients()
      toast.success(t('clients_page.delete_success', { name: clientName }))
    } catch (err) {
      if (err?.status) {
        const text = err.response
          ? await err.response.text().catch(() => 'Failed to delete client')
          : (err.message || 'Failed to delete client')
        toast.error(t('clients_page.delete_failed', { detail: text }))
      } else {
        toast.error(t('clients_page.delete_error', { detail: err.message }))
      }
    }
  }

  const countLabel = clients.length === 1
    ? t('clients_page.clients_count', { count: 1 })
    : t('clients_page.clients_count_plural', { count: clients.length })

  const listFindings = useMemo(() => clients.map((c) => ({
    id: c.id,
    severity: risk[c.id]?.sle_worst_usd > 1_000_000 ? 'critical' : risk[c.id] ? 'medium' : 'info',
    title: c.name,
    type: 'client',
    description: c.contact_email || '',
    resource: String(c.id),
  })), [clients, risk])

  const {
    exportCsv,
    filteredFindings,
    searchQuery,
    setSearchQuery,
  } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-clients',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const handleExportCsv = useCallback(() => {
    if (error) return
    exportCsv()
  }, [error, exportCsv])

  const visibleClients = useMemo(() => {
    if (!searchQuery.trim()) return clients
    const ids = new Set(filteredFindings.map((f) => String(f.id)))
    return clients.filter((c) => ids.has(String(c.id)))
  }, [clients, filteredFindings, searchQuery])

  const [filterMode, setFilterMode] = useState('all')
  const [sortMode, setSortMode] = useState('worst')

  // Largest worst-case exposure in the portfolio — the risk bars scale against it.
  const portfolioMax = useMemo(
    () => Math.max(1, ...clients.map((c) => risk[c.id]?.sle_worst_usd || 0)),
    [clients, risk],
  )

  const filterCounts = useMemo(() => ({
    all: visibleClients.length,
    at_risk: visibleClients.filter((c) => (risk[c.id]?.sle_worst_usd || 0) > 0).length,
    unscanned: visibleClients.filter((c) => !risk[c.id]).length,
  }), [visibleClients, risk])

  const displayClients = useMemo(() => {
    let list = visibleClients.slice()
    if (filterMode === 'at_risk') list = list.filter((c) => (risk[c.id]?.sle_worst_usd || 0) > 0)
    else if (filterMode === 'unscanned') list = list.filter((c) => !risk[c.id])
    list.sort((a, b) => {
      if (sortMode === 'name') return String(a.name || '').localeCompare(String(b.name || ''))
      if (sortMode === 'newest') return new Date(b.created_at || 0) - new Date(a.created_at || 0)
      return (risk[b.id]?.sle_worst_usd || 0) - (risk[a.id]?.sle_worst_usd || 0)
    })
    return list
  }, [visibleClients, filterMode, sortMode, risk])

  return (
    <PageShell
      title={t('clients_page.title')}
      subtitle={t('clients_page.subtitle')}
      actions={(
        <ShellScanActions
          onRefresh={loadClients}
          onExport={error ? undefined : handleExportCsv}
          refreshLoading={loading}
          exportDisabled={!!error || !filteredFindings.length}
        />
      )}
    >
      <div className="space-y-6">
        <PremiumPageHeader
          title={t('clients_page.clients_heading')}
          subtitle={error ? undefined : countLabel}
          badge={t('findings.live_badge')}
          badgeColor="#8b5cf6"
          count={error ? null : clients.length}
          countLabel={t('clients.title')}
          lastUpdated={error ? null : lastUpdated}
          loading={loading}
          onRefresh={loadClients}
          refreshLabel={t('common.refresh')}
        >
          {canCreateClients && (
          <Link
            to="/clients/new"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-[11px] font-mono border border-violet-500/35 bg-violet-500/12 text-violet-200 hover:bg-violet-500/20 transition-all"
          >
            {t('clients_page.add_new')}
          </Link>
          )}
        </PremiumPageHeader>

        {!isClientUser && (
          <>
            <PortfolioPosturePanel />
            <PortfolioAttackPanel />
          </>
        )}

        {loading && clients.length === 0 ? (
          <SkeletonWidgetGrid count={4} />
        ) : !error && clients.length > 0 ? (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <ExecutiveWidget
              label={t('clients_page.worst_case_loss')}
              value={fmtUsd(totals.sle)}
              hint={t('clients_page.worst_case_hint')}
              accent="#f43f5e"
            />
            <ExecutiveWidget
              label={t('clients_page.annualised_loss')}
              value={fmtUsd(totals.ale)}
              hint={t('clients_page.annualised_hint')}
              accent="#f59e0b"
            />
            <ExecutiveWidget
              label={t('clients_page.crown_jewels')}
              value={fmtUsd(totals.crown)}
              hint={t('clients_page.crown_hint')}
              accent="#a78bfa"
            />
            <ExecutiveWidget
              label={t('clients_page.total_asset_value')}
              value={fmtUsd(totals.assets)}
              footer={t('clients_page.scored_clients', { scored: totals.have, total: clients.length })}
              accent="#22d3ee"
            />
          </div>
        ) : null}

        {error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        {scanToast && (
          <div className={`rounded-xl border px-4 py-3 ${
            scanToast.kind === 'ok'
              ? 'bg-emerald-950/25 border-emerald-500/30 text-emerald-200'
              : 'bg-rose-950/25 border-rose-500/30 text-rose-300'
          }`}>
            <div className="font-medium text-sm">{scanToast.message}</div>
            {scanToast.kind === 'ok' && (
              <div className="mt-1.5 text-xs text-[var(--text-muted)] font-mono">
                {t('clients_page.track_jobs')}{' '}
                <Link to="/jobs" className="underline hover:text-emerald-200">{t('nav.jobs')}</Link>
                {' · '}
                <Link to="/findings" className="underline hover:text-emerald-200">{t('clients_page.track_findings')}</Link>
              </div>
            )}
          </div>
        )}

        {loading && clients.length === 0 && (
          <SkeletonCardGrid count={3} />
        )}

        {!loading && !error && clients.length === 0 && (
          <EmptyState
            icon="shield"
            title={t('clients_page.no_clients_title')}
            body={t('clients_page.no_clients_body')}
            cta={canCreateClients ? { label: t('clients_page.add_first'), to: '/clients/new' } : undefined}
          />
        )}

        {!loading && !error && clients.length > 0 && (
          <>
            <WeissmanListToolbar
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              searchPlaceholder={t('clients_page.search_placeholder')}
              lastUpdated={lastUpdated}
              resultCount={displayClients.length}
              totalCount={clients.length}
            />

            <div className="flex flex-wrap items-center justify-between gap-3">
              <div
                className="inline-flex items-center gap-1 rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] p-1"
                role="tablist"
                aria-label={t('clients_page.filter_all')}
              >
                {[['all', 'filter_all'], ['at_risk', 'filter_at_risk'], ['unscanned', 'filter_unscanned']].map(
                  ([mode, key]) => (
                    <Button
                      key={mode}
                      variant="unstyled"
                      type="button"
                      role="tab"
                      aria-selected={filterMode === mode}
                      onClick={() => setFilterMode(mode)}
                      className={[
                        'px-3 py-1.5 rounded-lg text-[11px] font-mono transition-colors border',
                        filterMode === mode
                          ? 'bg-violet-500/20 text-violet-100 border-violet-500/30'
                          : 'text-[var(--text-muted)] hover:text-[var(--text-secondary)] border-transparent',
                      ].join(' ')}
                    >
                      {t(`clients_page.${key}`)}{' '}
                      <span className="opacity-60 tabular-nums">{filterCounts[mode]}</span>
                    </Button>
                  ),
                )}
              </div>
              <label className="inline-flex items-center gap-2 text-[11px] font-mono text-[var(--text-muted)]">
                {t('clients_page.sort_by')}
                <select
                  value={sortMode}
                  onChange={(e) => setSortMode(e.target.value)}
                  className="bg-[var(--table-surface)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-[var(--text-secondary)] outline-none focus-visible:border-violet-500/40 cursor-pointer"
                >
                  <option value="worst">{t('clients_page.sort_worst')}</option>
                  <option value="name">{t('clients_page.sort_name')}</option>
                  <option value="newest">{t('clients_page.sort_newest')}</option>
                </select>
              </label>
            </div>

            {displayClients.length === 0 ? (
              <EmptyState
                icon="search"
                title={t('weissmanFindings.filtered_title')}
                body={t('weissmanFindings.filtered_body')}
              />
            ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
            {displayClients.map((client) => {
              const domains = (() => {
                try {
                  const parsed = typeof client.domains === 'string' ? JSON.parse(client.domains) : client.domains
                  return Array.isArray(parsed) ? parsed : []
                } catch {
                  return []
                }
              })()

              const ipRanges = (() => {
                try {
                  const parsed = typeof client.ip_ranges === 'string' ? JSON.parse(client.ip_ranges) : client.ip_ranges
                  return Array.isArray(parsed) ? parsed : []
                } catch {
                  return []
                }
              })()

              const snap = risk[client.id]
              const sev = severityKey(snap)
              const sc = SEV[sev]
              const barPct = snap ? Math.max(3, Math.round(((snap.sle_worst_usd || 0) / portfolioMax) * 100)) : 0

              return (
                <article
                  key={client.id}
                  className="group relative overflow-hidden rounded-2xl border border-[var(--border-default)] bg-[var(--table-surface)] backdrop-blur-md p-5 transition-all hover:border-violet-500/35 hover:shadow-[0_8px_32px_rgba(139,92,246,0.12)]"
                >
                  <div
                    className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-violet-500/40 to-transparent opacity-0 group-hover:opacity-100 transition-opacity"
                    aria-hidden="true"
                  />

                  <div className="flex items-start justify-between gap-3 mb-4">
                    <div className="min-w-0 flex-1">
                      <h3 className="text-lg font-semibold text-[var(--text-primary)] truncate group-hover:text-violet-200 transition-colors">
                        {client.name}
                      </h3>
                      {client.contact_email && (
                        <p className="text-sm text-[var(--text-muted)] mt-1 truncate font-mono">{client.contact_email}</p>
                      )}
                    </div>
                    <div className="shrink-0 flex flex-col items-end gap-1.5">
                      <span
                        className="px-2 py-0.5 rounded-md text-[9px] font-mono uppercase tracking-wider border"
                        style={{ color: sc.color, borderColor: sc.border, background: sc.bg }}
                        title={t('clients_page.worst_case_hint')}
                      >
                        {t(`clients_page.sev_${sev}`)}
                      </span>
                      <Link
                        to={`/clients/${client.id}`}
                        className="px-3 py-1 text-[10px] font-mono uppercase tracking-wider border border-violet-500/30 rounded-lg text-violet-300 hover:bg-violet-500/10 transition-colors"
                      >
                        {t('clients_page.view')}
                      </Link>
                    </div>
                  </div>

                  <div
                    className="mb-4 p-4 rounded-xl border"
                    style={{
                      borderColor: 'rgba(244, 63, 94, 0.25)',
                      background: 'linear-gradient(145deg, rgba(244,63,94,0.06) 0%, rgba(0,0,0,0.2) 100%)',
                    }}
                  >
                    <div className="flex items-baseline justify-between gap-2">
                      <span className="text-[10px] font-mono uppercase tracking-[0.14em] text-rose-300/80">
                        {t('clients_page.at_risk')}
                      </span>
                      {!risk[client.id] && (
                        <Button variant="unstyled"
                          type="button"
                          onClick={() => recomputeRisk(client.id)}
                          className="text-[10px] font-mono text-cyan-300/70 hover:text-cyan-200"
                          title={t('clients_page.compute_title')}
                        >
                          {t('clients_page.compute_risk')}
                        </Button>
                      )}
                    </div>
                    <div className="text-2xl font-bold text-rose-200 tabular-nums mt-1 tracking-tight">
                      {risk[client.id]
                        ? fmtUsd(risk[client.id].sle_worst_usd)
                        : <span className="text-[var(--text-muted)] text-sm font-normal">{t('clients_page.no_snapshot')}</span>}
                    </div>
                    {snap && (
                      <div
                        className="mt-2 h-1 rounded-full bg-[var(--border-subtle)] overflow-hidden"
                        role="img"
                        aria-label={`${t(`clients_page.sev_${sev}`)} · ${fmtUsd(snap.sle_worst_usd)}`}
                      >
                        <div className="h-full rounded-full transition-all" style={{ width: `${barPct}%`, background: sc.color }} />
                      </div>
                    )}
                    {risk[client.id] && (
                      <div className="text-[10px] font-mono text-[var(--text-muted)] mt-1.5">
                        {t('clients_page.ale_crown', {
                          ale: fmtUsd(risk[client.id].ale_annualised_usd),
                          crown: fmtUsd(risk[client.id].crown_jewel_value_usd),
                        })}
                      </div>
                    )}
                  </div>

                  <dl className="space-y-2 text-sm border-t border-[var(--border-subtle)] pt-3">
                    <div className="flex items-center justify-between">
                      <dt className="text-[var(--text-muted)] font-mono text-[11px]">{t('clients_page.domains_label')}</dt>
                      <dd className="text-[var(--text-primary)] font-semibold tabular-nums">{domains.length}</dd>
                    </div>
                    <div className="flex items-center justify-between">
                      <dt className="text-[var(--text-muted)] font-mono text-[11px]">{t('clients_page.ip_ranges_label')}</dt>
                      <dd className="text-[var(--text-primary)] font-semibold tabular-nums">{ipRanges.length}</dd>
                    </div>
                    {client.created_at && (
                      <div className="flex items-center justify-between pt-2 border-t border-[var(--border-subtle)]">
                        <dt className="text-[var(--text-muted)] font-mono text-[10px]">{t('clients_page.created_label')}</dt>
                        <dd className="text-[var(--text-tertiary)] font-mono text-[10px]">
                          {new Date(client.created_at).toLocaleDateString()}
                        </dd>
                      </div>
                    )}
                  </dl>

                  <div className="mt-4 pt-4 border-t border-[var(--border-subtle)] flex items-center justify-between gap-2">
                    <Link
                      to={`/clients/${client.id}`}
                      className="text-sm text-violet-300 hover:text-violet-200 font-mono transition-colors"
                    >
                      {t('clients_page.manage')}
                    </Link>
                    <div className="flex items-center gap-3">
                      <Button variant="unstyled"
                        type="button"
                        onClick={() => runScan(client.id, client.name)}
                        disabled={scanningId === client.id || domains.length === 0}
                        className="text-sm text-emerald-300 hover:text-emerald-200 disabled:text-[var(--text-disabled)] disabled:cursor-not-allowed transition-colors font-mono"
                        title={domains.length === 0 ? t('clients_page.scan_no_domain') : t('clients_page.scan_title')}
                      >
                        {scanningId === client.id ? t('clients_page.queuing') : t('clients_page.scan_now')}
                      </Button>
                      {canDeleteClients && (
                      <Button variant="unstyled"
                        type="button"
                        onClick={() => deleteClient(client.id, client.name)}
                        className="text-sm text-rose-400/80 hover:text-rose-300 transition-colors font-mono"
                        title={t('clients_page.delete_title')}
                      >
                        {t('clients_page.delete_client')}
                      </Button>
                      )}
                    </div>
                  </div>
                </article>
              )
            })}
          </div>
            )}
          </>
        )}
      </div>
    </PageShell>
  )
}
