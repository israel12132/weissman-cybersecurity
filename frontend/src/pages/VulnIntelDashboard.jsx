import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Download } from 'lucide-react'
import { createColumnHelper } from '@tanstack/react-table'
import { apiFetch } from '../lib/apiBase'
import FindingDrawer from '../components/ui/FindingDrawer'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import PremiumPageHeader from '../components/ui/PremiumPageHeader'
import FilterPills from '../components/ui/FilterPills'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import DataTable from '../components/ui/DataTable'
import { useSavedViews } from '../hooks/useSavedViews'
import SeverityBadge, { SEVERITY_META, getSeverityMeta } from '../components/ui/SeverityBadge'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'

const STATUS_COLORS = {
  OPEN: '#ef4444',
  ACKNOWLEDGED: '#f59e0b',
  IN_PROGRESS: '#3b82f6',
  FIXED: '#22c55e',
  FALSE_POSITIVE: '#6b7280',
}

function isKevListed(f) {
  return !!(f?.kev_listed || f?.kev || f?.raw?.kev)
}

function formatDate(val) {
  if (!val) return '—'
  try {
    return new Date(val).toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  } catch {
    return '—'
  }
}

const columnHelper = createColumnHelper()

function buildColumns(t) {
  return [
    columnHelper.accessor('severity', {
      id: 'severity',
      header: t('common.severity'),
      size: 110,
      cell: ({ getValue }) => <SeverityBadge severity={getValue()} showDot />,
    }),
    columnHelper.accessor((row) => row.cve || row.cve_id || '—', {
      id: 'cve',
      header: t('findings.cve'),
      size: 140,
      cell: ({ getValue }) => (
        <span className="text-cyan-300/90 font-mono text-[11px]">{getValue()}</span>
      ),
    }),
    columnHelper.accessor((row) => row.title || row.summary || '—', {
      id: 'title',
      header: t('common.name'),
      size: 320,
      cell: ({ getValue }) => (
        <span className="text-[var(--text-primary)] text-[12px] line-clamp-2 leading-snug">{getValue()}</span>
      ),
    }),
    columnHelper.accessor((row) => row.source || row.engine || '—', {
      id: 'source',
      header: t('findings.source'),
      size: 140,
      cell: ({ getValue }) => (
        <span className="text-[var(--text-tertiary)] font-mono text-[11px] truncate">{getValue()}</span>
      ),
    }),
    columnHelper.accessor((row) => (row.status || 'OPEN').toUpperCase(), {
      id: 'status',
      header: t('common.status'),
      size: 120,
      cell: ({ getValue }) => {
        const v = getValue()
        const color = STATUS_COLORS[v] || '#6b7280'
        return (
          <span
            className="inline-flex px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider font-mono border"
            style={{ color, backgroundColor: `${color}18`, borderColor: `${color}40` }}
          >
            {v}
          </span>
        )
      },
    }),
    columnHelper.accessor('discovered_at', {
      id: 'discovered',
      header: t('findings.discovered'),
      size: 160,
      cell: ({ getValue }) => (
        <span className="text-[var(--text-muted)] font-mono text-[11px] whitespace-nowrap">
          {formatDate(getValue())}
        </span>
      ),
    }),
  ]
}

export default function VulnIntelDashboard() {
  const { t } = useTranslation()
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('')
  const [kevFilter, setKevFilter] = useState(false)
  const [filtersExpanded, setFiltersExpanded] = useState(true)
  const [total, setTotal] = useState(0)
  const [lastUpdated, setLastUpdated] = useState(null)
  const [selected, setSelected] = useState(null)

  // Saved views (named filter snapshots, per-user, localStorage)
  const { views: savedViews, saveView, deleteView } = useSavedViews('weissman_vuln_views')
  const [viewName, setViewName] = useState('')
  const saveCurrentView = useCallback(() => {
    const name = viewName.trim()
    if (!name) return
    saveView(name, { filter, severityFilter, statusFilter, kevFilter })
    setViewName('')
  }, [viewName, saveView, filter, severityFilter, statusFilter, kevFilter])
  const applyView = useCallback((state) => {
    if (!state) return
    setFilter(state.filter ?? '')
    setSeverityFilter(state.severityFilter ?? 'all')
    setStatusFilter(state.statusFilter ?? '')
    setKevFilter(Boolean(state.kevFilter))
  }, [])

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    const qs = new URLSearchParams({ limit: '1000' })
    if (severityFilter !== 'all') qs.set('severity', severityFilter)
    try {
      const r = await apiFetch(`/api/findings?${qs.toString()}`)
      if (!r.ok) {
        const data = await r.json().catch(() => ({}))
        throw new Error(data.detail || data.error || `HTTP ${r.status}`)
      }
      const data = await r.json()
      const arr = Array.isArray(data) ? data : Array.isArray(data?.findings) ? data.findings : []
      setFindings(arr)
      setTotal(Number(data?.total ?? arr.length))
      setLastUpdated(new Date())
    } catch (e) {
      setError(e.message || 'Failed to load findings')
    } finally {
      setLoading(false)
    }
  }, [severityFilter])

  useEffect(() => {
    load().catch(() => {})
  }, [load])

  const summary = useMemo(() => {
    const by = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of findings) {
      const s = (f.severity || 'info').toLowerCase()
      if (by[s] !== undefined) by[s] += 1
    }
    const cves = new Set(findings.map((f) => f.cve || f.cve_id).filter(Boolean))
    return { by, cves: cves.size }
  }, [findings])

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase()
    return findings.filter((f) => {
      const sev = (f.severity || '').toLowerCase()
      if (severityFilter !== 'all' && sev !== severityFilter) return false
      if (statusFilter && (f.status || 'OPEN').toUpperCase() !== statusFilter) return false
      if (kevFilter && !isKevListed(f)) return false
      if (!q) return true
      const hay = `${f.title || ''} ${f.description || ''} ${f.cve || ''} ${f.source || ''}`.toLowerCase()
      return hay.includes(q)
    })
  }, [findings, filter, severityFilter, statusFilter, kevFilter])

  const tableData = useMemo(() => filtered.slice(0, 200), [filtered])

  const columns = useMemo(() => buildColumns(t), [t])

  const statusCounts = useMemo(() => {
    const c = {}
    for (const f of findings) {
      const s = (f.status || 'OPEN').toUpperCase()
      c[s] = (c[s] || 0) + 1
    }
    return c
  }, [findings])

  const kevCount = useMemo(() => findings.filter(isKevListed).length, [findings])

  const exportCsv = useCallback(() => {
    const header = ['severity', 'cve', 'title', 'source', 'status', 'discovered_at', 'id']
    const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`
    const lines = [
      header.join(','),
      ...filtered.map((f) => [
        f.severity || '',
        f.cve || f.cve_id || '',
        f.title || f.summary || '',
        f.source || f.engine || '',
        (f.status || 'OPEN').toUpperCase(),
        f.discovered_at || '',
        f.id || f.raw_id || f.finding_id || '',
      ].map(esc).join(',')),
    ]
    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `vuln-intel-findings-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }, [filtered])

  const selectedRowId = selected?.raw_id ?? selected?.id

  useFindingsWorkbench(filtered, { csvPrefix: 'vuln-intel-findings' })

  return (
    <PageShell
      title={t('vuln_intel.title')}
      badge="CVE"
      badgeColor="#f97316"
      subtitle={t('vuln_intel.subtitle')}
      actions={(
        <ShellScanActions
          onRefresh={() => load()}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!filtered.length}
        />
      )}
    >
      <div className="space-y-5">
        <EvidenceNotice>{t('vuln_intel.evidence_notice')}</EvidenceNotice>

        <PremiumPageHeader
          title={t('vuln_intel.title')}
          subtitle={t('vuln_intel.subtitle')}
          badge={t('vuln_intel.live_badge')}
          badgeColor="#f97316"
          count={filtered.length}
          countLabel={t('findings.title')}
          lastUpdated={lastUpdated}
          loading={loading}
          onRefresh={() => load()}
          refreshLabel={t('common.refresh')}
        >
          <button
            type="button"
            onClick={exportCsv}
            disabled={filtered.length === 0}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-[11px] font-mono border border-emerald-500/30 bg-emerald-500/10 text-emerald-200 hover:bg-emerald-500/20 disabled:opacity-40 transition-all"
          >
            <Download className="h-3.5 w-3.5" />
            {t('vuln_intel.export_csv')}
          </button>
          <button
            type="button"
            onClick={() => setFiltersExpanded((v) => !v)}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-[11px] font-mono border border-[var(--border-default)] bg-[var(--row-hover-bg)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:border-[var(--border-strong)] transition-all"
          >
            {filtersExpanded ? t('common.hide_filters') : t('common.show_filters')}
          </button>
        </PremiumPageHeader>

        <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
          <ExecutiveWidget
            label={t('vuln_intel.critical')}
            value={loading ? '—' : summary.by.critical.toLocaleString()}
            accent="#ef4444"
          />
          <ExecutiveWidget
            label={t('vuln_intel.high')}
            value={loading ? '—' : summary.by.high.toLocaleString()}
            accent="#f97316"
          />
          <ExecutiveWidget
            label={t('vuln_intel.medium')}
            value={loading ? '—' : summary.by.medium.toLocaleString()}
            accent="#f59e0b"
          />
          <ExecutiveWidget
            label={t('vuln_intel.low')}
            value={loading ? '—' : summary.by.low.toLocaleString()}
            accent="#22d3ee"
          />
          <ExecutiveWidget
            label={t('vuln_intel.distinct_cves')}
            value={loading ? '—' : summary.cves.toLocaleString()}
            hint={t('vuln_intel.distinct_cves_hint')}
            accent="#a78bfa"
            className="col-span-2 lg:col-span-1"
          />
        </div>

        {filtersExpanded && (
          <div className="glass-panel rounded-2xl p-4 sm:p-5 space-y-4">
            <FilterPills
              label={t('findings.filter_severity')}
              pills={[
                {
                  id: 'vuln-sev-all',
                  label: t('vuln_intel.all_severities'),
                  count: findings.length,
                  active: severityFilter === 'all',
                  color: '#94a3b8',
                  onClick: () => setSeverityFilter('all'),
                },
                ...Object.entries(SEVERITY_META).map(([key, meta]) => ({
                  id: `vuln-sev-${key}`,
                  label: meta.label,
                  count: summary.by[key] || 0,
                  active: severityFilter === key,
                  color: meta.color,
                  onClick: () => setSeverityFilter(key),
                })),
              ]}
            />

            <FilterPills
              label={t('findings.filter_status')}
              pills={[
                {
                  id: 'vuln-status-all',
                  label: t('vuln_intel.all_statuses'),
                  count: findings.length,
                  active: !statusFilter,
                  color: '#94a3b8',
                  onClick: () => setStatusFilter(''),
                },
                ...Object.entries(STATUS_COLORS).map(([value, color]) => ({
                  id: `vuln-status-${value}`,
                  label: value.replace('_', ' '),
                  count: statusCounts[value] || 0,
                  active: statusFilter === value,
                  color,
                  onClick: () => setStatusFilter(statusFilter === value ? '' : value),
                })),
                {
                  id: 'vuln-kev',
                  label: t('vuln_intel.kev_only'),
                  count: kevCount,
                  active: kevFilter,
                  color: '#f59e0b',
                  onClick: () => setKevFilter((v) => !v),
                },
              ]}
            />

            <div className="relative max-w-xl">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-disabled)] text-xs pointer-events-none">
                ⌕
              </span>
              <input
                type="search"
                aria-label={t('findings.search_placeholder')}
                placeholder={t('findings.search_placeholder')}
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-xl pl-8 pr-3 py-2.5 text-sm font-mono text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500/40"
              />
            </div>

            {/* Saved views — named filter snapshots (per-user, local). */}
            <div className="flex flex-wrap items-center gap-2 pt-3 border-t border-[var(--border-subtle)]">
              <span className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{t('findings.views_label')}</span>
              {savedViews.map((v) => (
                <span key={v.id} className="inline-flex items-center gap-1 rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] pl-2.5 pr-1 py-1 text-[11px] font-mono text-[var(--text-secondary)]">
                  <button type="button" onClick={() => applyView(v.state)} className="hover:text-cyan-300 transition-colors" title={t('findings.view_apply')}>{v.name}</button>
                  <button type="button" onClick={() => deleteView(v.id)} aria-label={t('findings.view_delete', { name: v.name })} className="w-4 h-4 flex items-center justify-center rounded text-[var(--text-muted)] hover:text-rose-300 transition-colors">×</button>
                </span>
              ))}
              {savedViews.length === 0 && (
                <span className="text-[11px] font-mono text-[var(--text-disabled)]">{t('findings.views_empty')}</span>
              )}
              <form className="inline-flex items-center gap-1.5 ms-auto" onSubmit={(e) => { e.preventDefault(); saveCurrentView() }}>
                <input
                  type="text"
                  value={viewName}
                  onChange={(e) => setViewName(e.target.value)}
                  placeholder={t('findings.view_name_placeholder')}
                  aria-label={t('findings.view_name_placeholder')}
                  className="w-40 bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-[11px] text-[var(--text-secondary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500/40"
                />
                <button type="submit" disabled={!viewName.trim()} className="rounded-lg border border-cyan-500/30 bg-cyan-500/5 px-2.5 py-1.5 text-[11px] font-mono text-cyan-300 hover:bg-cyan-500/15 disabled:opacity-40 disabled:cursor-not-allowed transition-colors">{t('findings.view_save')}</button>
              </form>
            </div>
          </div>
        )}

        {error ? (
          <EmptyState
            icon="alert"
            title={t('vuln_intel.failed_title')}
            body={error}
            cta={{ label: t('common.retry'), onClick: load }}
          />
        ) : !loading && findings.length === 0 ? (
          <EmptyState
            icon="shield"
            title={t('findings.no_findings_yet')}
            body={t('findings.no_findings_body')}
            cta={{ label: t('vuln_intel.empty_cta'), to: '/clients' }}
          />
        ) : !loading && filtered.length === 0 ? (
          <EmptyState
            icon="search-x"
            title={t('vuln_intel.no_match_title')}
            body={t('vuln_intel.no_match_body')}
            cta={{ label: t('vuln_intel.empty_cta'), to: '/clients' }}
          />
        ) : (
          <>
            <DataTable
              id="vuln-intel-table"
              columns={columns}
              data={tableData}
              loading={loading}
              onRowClick={(row) => setSelected(row.original)}
              selectedRowId={selectedRowId}
              getRowAccentColor={(row) => getSeverityMeta(row.severity).border}
              emptyFilteredMessage={t('vuln_intel.no_match_title')}
              zebra
              stickyHeader
            />
            {!loading && filtered.length > 200 && (
              <p className="text-[11px] font-mono text-[var(--text-muted)] text-center">
                {t('vuln_intel.showing_first', { count: filtered.length })}
              </p>
            )}
          </>
        )}

        <p className="text-[10px] font-mono text-[var(--text-disabled)] text-center">
          {t('findings.shown_of_total', { shown: filtered.length, total })}
        </p>
      </div>

      <FindingDrawer finding={selected} onClose={() => setSelected(null)} />
    </PageShell>
  )
}
