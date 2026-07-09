/**
 * Report History — generated report-run ledger.
 *
 * Wired to the live GET /api/reports endpoint, which returns the 100 most
 * recent report_runs (id, generation time, artifact path). This is the audit
 * trail of report generation — when reports were produced and where the
 * artifact was written. Route: /reports
 */
import React, { useState, useCallback, useEffect, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { FileClock, Search } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import DataTable from '../components/ui/DataTable'
import CopyButton from '../components/ui/CopyButton'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { apiFetch } from '../lib/apiBase'

const NS = 'pages.reportHistory'
const columnHelper = createColumnHelper()

export default function ReportHistory() {
  const { t } = useTranslation()
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const r = await apiFetch('/api/reports')
      const d = await r.json().catch(() => [])
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      setRows(Array.isArray(d) ? d : Array.isArray(d?.reports) ? d.reports : [])
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    load()
  }, [load])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return rows
    return rows.filter((r) => `${r.id} ${r.pdf_path} ${r.created_at}`.toLowerCase().includes(q))
  }, [rows, search])

  const stats = useMemo(() => {
    const withArtifact = rows.filter((r) => r.pdf_path).length
    const latest = rows[0]?.created_at ? new Date(rows[0].created_at).toLocaleDateString() : '—'
    return { total: rows.length, withArtifact, latest }
  }, [rows])

  const columns = useMemo(
    () => [
      columnHelper.accessor((r) => Number(r.id) || 0, {
        id: 'id',
        header: t(`${NS}.col_run`),
        cell: (ctx) => <span className="font-mono text-[12px] text-[var(--text-primary)] tabular-nums">#{ctx.getValue()}</span>,
      }),
      columnHelper.accessor((r) => r.created_at || '', {
        id: 'created_at',
        header: t(`${NS}.col_generated`),
        cell: (ctx) => (
          <span className="text-[var(--text-tertiary)] whitespace-nowrap text-[12px]">
            {ctx.getValue() ? new Date(ctx.getValue()).toLocaleString() : '—'}
          </span>
        ),
      }),
      columnHelper.accessor((r) => r.pdf_path || '', {
        id: 'pdf_path',
        header: t(`${NS}.col_artifact`),
        enableSorting: false,
        cell: (ctx) =>
          ctx.getValue() ? (
            <span className="flex items-center gap-1.5 min-w-0">
              <code className="text-[11px] font-mono text-[var(--text-muted)] truncate max-w-[26rem]" title={ctx.getValue()}>
                {ctx.getValue()}
              </code>
              <CopyButton value={ctx.getValue()} />
            </span>
          ) : (
            <span className="text-[10px] font-mono text-[var(--text-disabled)] uppercase tracking-wider">
              {t(`${NS}.no_artifact`)}
            </span>
          ),
      }),
    ],
    [t],
  )

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#22d3ee"
      icon={<FileClock className="w-5 h-5" />}
      actions={<ShellScanActions onRefresh={load} refreshLoading={loading} exportDisabled />}
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        {loading && <SkeletonWidgetGrid count={3} />}

        {error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        {!loading && !error && (
          <>
            <div className="grid grid-cols-3 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_total`)} value={stats.total} accent="#22d3ee" />
              <ExecutiveWidget label={t(`${NS}.kpi_artifacts`)} value={stats.withArtifact} accent="#4ade80" />
              <ExecutiveWidget label={t(`${NS}.kpi_latest`)} value={stats.latest} accent="#a78bfa" />
            </div>

            <div className="relative flex-1 min-w-[220px] max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-disabled)] pointer-events-none" />
              <input
                type="search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={t(`${NS}.search_placeholder`)}
                className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-xl pl-10 pr-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500/40"
              />
            </div>

            {rows.length === 0 ? (
              <EmptyState icon="🧾" title={t(`${NS}.empty_title`)} body={t(`${NS}.empty_body`)} />
            ) : filtered.length === 0 ? (
              <EmptyState icon="🔍" title={t(`${NS}.no_match_title`)} body={t(`${NS}.no_match_body`)} />
            ) : (
              <DataTable id="report-history-table" columns={columns} data={filtered} animateRows={false} getRowId={(r) => r.id} />
            )}
          </>
        )}
      </div>
    </PageShell>
  )
}
