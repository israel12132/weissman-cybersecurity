/**
 * Board Evidence Pack — /board-pack
 *
 * Live tenant findings only (GET /api/board-pack). KPIs and the table share
 * that response: totals cover the export set (≤50k); `grid` is the same
 * ordered preview (≤5k). Downloads a true OOXML workbook plus PDF/CSV.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { FileSpreadsheet, Radio, Search, ShieldAlert } from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import EmptyState from '../components/ui/EmptyState'
import DataTable from '../components/ui/DataTable'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import { SkeletonTable, SkeletonWidgetGrid } from '../components/ui/Skeleton'
import Button from '../components/ui/Button'
import { apiFetch } from '../utils/apiFetch'
import { downloadApiFile } from '../lib/downloadApiFile'
import { useClient } from '../context/ClientContext'
import { useVisiblePolling } from '../hooks/useVisiblePolling'

const NS = 'pages.boardEvidencePack'
const columnHelper = createColumnHelper()
const ADVERSARY_SOURCES = new Set([
  'leak_hunter',
  'darkweb_intel',
  'dark_web_monitor',
  'typosquatting_monitor',
  'adversary_exposure_delta',
  'threat_intel_fusion',
])

function sevColor(sev) {
  const s = (sev || '').toLowerCase()
  if (s === 'critical') return '#f43f5e'
  if (s === 'high') return '#fb923c'
  if (s === 'medium') return '#fbbf24'
  if (s === 'low') return '#38bdf8'
  return '#94a3b8'
}

export default function BoardEvidencePack() {
  const { t } = useTranslation()
  const { selectedClientId, selectedClient, clients } = useClient()
  const [pack, setPack] = useState(null)
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [busy, setBusy] = useState('')
  const loadGen = useRef(0)

  const qs = selectedClientId ? `?client_id=${encodeURIComponent(selectedClientId)}` : ''

  const load = useCallback(async () => {
    const gen = ++loadGen.current
    setError('')
    try {
      const summary = await apiFetch(`/api/board-pack${qs}`)
      if (gen !== loadGen.current) return
      setPack(summary && typeof summary === 'object' ? summary : null)
      const arr = Array.isArray(summary?.grid) ? summary.grid : []
      setFindings(arr)
    } catch (e) {
      if (gen !== loadGen.current) return
      setError(e.message || t(`${NS}.load_error`))
      setPack(null)
      setFindings([])
    } finally {
      if (gen === loadGen.current) setLoading(false)
    }
  }, [qs, t])

  useEffect(() => {
    setPack(null)
    setFindings([])
    setLoading(true)
    load()
  }, [load, selectedClientId])

  useVisiblePolling(load, 60000, { paused: !autoRefresh })

  const totals = pack?.totals || {}
  const scope = pack?.scope || {}
  const critical = Number(totals.critical) || 0
  const exportTotal = Number(totals.findings) || findings.length
  const truncated = Boolean(scope.truncated) || exportTotal > findings.length

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return findings
    return findings.filter((f) =>
      `${f.title || ''} ${f.source || f.engine || ''} ${f.severity || ''} ${f.mitre || ''}`.toLowerCase().includes(q),
    )
  }, [findings, search])

  const xlsxPath = pack?.exports?.xlsx || (selectedClientId
    ? `/api/clients/${selectedClientId}/export/xlsx`
    : '/api/findings/export/xlsx')
  const csvPath = pack?.exports?.csv || (selectedClientId
    ? `/api/clients/${selectedClientId}/export/csv`
    : '/api/findings/export/csv')
  const pdfPath = pack?.exports?.pdf || (selectedClientId ? `/api/clients/${selectedClientId}/report/pdf` : null)

  const download = useCallback(
    async (path, fallback, kind) => {
      setBusy(kind)
      try {
        await downloadApiFile(path, fallback)
      } catch (e) {
        setError(e.message || t(`${NS}.download_failed`))
      } finally {
        setBusy('')
      }
    },
    [t],
  )

  const columns = useMemo(
    () => [
      columnHelper.accessor((f) => (f.severity || 'info').toLowerCase(), {
        id: 'severity',
        header: t(`${NS}.col_severity`),
        cell: (ctx) => (
          <span
            className="inline-block px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider border"
            style={{ color: sevColor(ctx.getValue()), borderColor: `${sevColor(ctx.getValue())}55` }}
          >
            {ctx.getValue()}
          </span>
        ),
      }),
      columnHelper.accessor((f) => f.title || '', {
        id: 'title',
        header: t(`${NS}.col_title`),
        cell: (ctx) => (
          <span className="text-[var(--text-primary)] max-w-md truncate block" title={ctx.getValue()}>
            {ctx.getValue() || '—'}
          </span>
        ),
      }),
      columnHelper.accessor((f) => f.source || f.engine || '', {
        id: 'source',
        header: t(`${NS}.col_source`),
        cell: (ctx) => {
          const src = ctx.getValue()
          const hot = ADVERSARY_SOURCES.has(String(src).toLowerCase())
          return (
            <span className={hot ? 'text-violet-300' : 'text-[var(--text-tertiary)]'}>
              {src || '—'}
            </span>
          )
        },
      }),
      columnHelper.accessor((f) => f.mitre || '', {
        id: 'mitre',
        header: t(`${NS}.col_mitre`),
        cell: (ctx) => (
          <span className="text-[var(--text-tertiary)] font-mono text-[11px]">{ctx.getValue() || '—'}</span>
        ),
      }),
    ],
    [t],
  )

  const clientLabel = selectedClient?.name || t(`${NS}.all_clients`)

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#10b981"
      icon={<FileSpreadsheet />}
      actions={(
        <div className="flex items-center gap-2 flex-wrap">
          <Button
            variant="unstyled"
            type="button"
            onClick={() => setAutoRefresh((v) => !v)}
            className={`px-3 py-1.5 rounded-lg border text-xs font-mono ${
              autoRefresh
                ? 'border-emerald-500/40 text-emerald-300 bg-emerald-500/10'
                : 'border-[var(--border-default)] text-[var(--text-tertiary)]'
            }`}
          >
            <Radio className={`w-3 h-3 inline mr-1 ${autoRefresh ? 'animate-pulse' : ''}`} />
            {autoRefresh ? t(`${NS}.auto_on`) : t(`${NS}.auto_off`)}
          </Button>
          <ShellScanActions
            onRefresh={load}
            onExport={() => download(csvPath, 'Weissman_findings.csv', 'csv')}
            onExportXlsx={() => download(xlsxPath, 'Weissman_Board.xlsx', 'xlsx')}
            refreshLoading={loading}
            exportDisabled={busy === 'csv'}
            exportXlsxDisabled={busy === 'xlsx'}
            exportLabel={t('common.export_csv')}
            xlsxLabel={t('common.export_xlsx')}
          />
          {pdfPath && (
            <Button
              variant="unstyled"
              type="button"
              onClick={() => download(pdfPath, 'Weissman_Report.pdf', 'pdf')}
              disabled={busy === 'pdf'}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyan-500/35 text-[11px] font-mono text-cyan-300 hover:bg-cyan-500/10 disabled:opacity-40"
            >
              {t('common.export_pdf')}
            </Button>
          )}
        </div>
      )}
    >
      <div className="space-y-6">
        <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/20 px-4 py-3 flex items-start gap-3">
          <ShieldAlert className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
          <p className="text-xs text-emerald-100/80 leading-relaxed">{t(`${NS}.evidence_notice`)}</p>
        </div>

        {error && (
          <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">{error}</div>
        )}

        {clients?.length > 0 && (
          <p className="text-[11px] font-mono text-[var(--text-muted)]">
            {t(`${NS}.scoped_to`, { name: clientLabel })}
          </p>
        )}

        {loading ? (
          <SkeletonWidgetGrid />
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
            <ExecutiveWidget label={t(`${NS}.kpi_total`)} value={totals.findings ?? findings.length} accent="#22d3ee" />
            <ExecutiveWidget
              label={t(`${NS}.kpi_critical`)}
              value={critical}
              accent="#f43f5e"
              className={critical > 0 ? 'animate-pulse' : ''}
            />
            <ExecutiveWidget label={t(`${NS}.kpi_high`)} value={totals.high ?? 0} accent="#fb923c" />
            <ExecutiveWidget label={t(`${NS}.kpi_verified`)} value={totals.verified ?? 0} accent="#34d399" />
            <ExecutiveWidget label={t(`${NS}.kpi_adversary`)} value={totals.adversary_indexed ?? 0} accent="#a78bfa" />
            <ExecutiveWidget label={t(`${NS}.kpi_remediation`)} value={totals.remediation_ready ?? 0} accent="#fbbf24" />
          </div>
        )}

        <p className="text-[11px] font-mono text-[var(--text-muted)] leading-relaxed">
          {t(`${NS}.legal_note`)}
        </p>

        {truncated && !loading && (
          <p className="text-[11px] font-mono text-amber-200/90 leading-relaxed rounded-lg border border-amber-500/25 bg-amber-500/10 px-3 py-2">
            {t(`${NS}.grid_capped`, {
              shown: findings.length,
              total: exportTotal,
              exportCap: scope.export_limit ?? 50000,
            })}
          </p>
        )}

        <div className="flex flex-wrap gap-3 text-[11px] font-mono">
          <Link to="/dark-web" className="text-violet-300 hover:underline">{t(`${NS}.link_dark_web`)}</Link>
          <Link to="/findings" className="text-cyan-300 hover:underline">{t(`${NS}.link_findings`)}</Link>
          <Link to="/reports" className="text-[var(--text-tertiary)] hover:underline">{t(`${NS}.link_reports`)}</Link>
        </div>

        <div className="relative">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)]" />
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t(`${NS}.search_placeholder`)}
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] text-sm text-[var(--text-primary)]"
          />
        </div>

        {loading ? (
          <SkeletonTable />
        ) : filtered.length === 0 ? (
          <EmptyState
            icon="file"
            title={t(`${NS}.empty_title`)}
            body={t(`${NS}.empty_body`)}
            secondary={{ label: t(`${NS}.empty_scan`), href: '/engines' }}
          />
        ) : (
          <DataTable data={filtered} columns={columns} />
        )}
      </div>
    </PageShell>
  )
}
