/**
 * Financial Blast-Radius (FAIR) — executive money-view.
 *
 * Translates the risk graph into dollars per client via the live
 * GET /api/financial-risk/:client_id endpoint (FAIR-aligned SLE/ALE computed
 * server-side from asset values × CVSS/EPSS/KEV). `?recompute=1` forces a fresh
 * snapshot. Route: /financial-risk
 */
import { useState, useCallback, useEffect, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { DollarSign, RefreshCw } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import DataTable from '../components/ui/DataTable'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useClient } from '../context/ClientContext'
import { apiFetch } from '../lib/apiBase'
import { fmtUsd } from '../lib/riskFormat'
import { useToast } from '../components/ui/Toaster'
import Button from '../components/ui/Button'

const NS = 'pages.financialRisk'
const columnHelper = createColumnHelper()

function fmtUsdFull(n) {
  return `$${(Number(n) || 0).toLocaleString()}`
}

function contributorsCsv(rows) {
  const header = ['label', 'node_type', 'business_value_usd', 'crown_jewel', 'kev_present', 'max_cvss', 'max_epss', 'sle_usd', 'ale_usd']
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const lines = [
    header.join(','),
    ...rows.map((r) =>
      [
        r.label,
        r.node_type,
        r.business_value_usd,
        r.crown_jewel,
        r.kev_present,
        r.max_cvss,
        r.max_epss,
        r.sle_usd,
        r.ale_usd,
      ].map(esc).join(','),
    ),
  ]
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `weissman-financial-risk-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

export default function FinancialRisk() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const { clients, selectedClientId, setSelectedClientId } = useClient()

  const [snapshot, setSnapshot] = useState(null)
  const [loading, setLoading] = useState(false)
  const [recomputing, setRecomputing] = useState(false)
  const [error, setError] = useState('')
  const [hasSnapshot, setHasSnapshot] = useState(true)

  const load = useCallback(
    async (recompute = false) => {
      if (selectedClientId == null) return
      if (recompute) setRecomputing(true)
      else setLoading(true)
      setError('')
      try {
        const qs = recompute ? '?recompute=1' : ''
        const r = await apiFetch(`/api/financial-risk/${encodeURIComponent(selectedClientId)}${qs}`)
        const data = await r.json().catch(() => ({}))
        if (!r.ok || data.ok === false) {
          throw new Error(data.detail || `HTTP ${r.status}`)
        }
        setSnapshot(data.snapshot || null)
        setHasSnapshot(Boolean(data.snapshot))
        if (recompute && data.snapshot) toast.success(t(`${NS}.recompute_done`))
      } catch (e) {
        setError(e.message || t(`${NS}.load_failed`))
      } finally {
        setLoading(false)
        setRecomputing(false)
      }
    },
    [selectedClientId, t, toast],
  )

  useEffect(() => {
    setSnapshot(null)
    if (selectedClientId != null) load(false)
  }, [selectedClientId, load])

  const contributors = useMemo(
    () => (Array.isArray(snapshot?.top_contributors) ? snapshot.top_contributors : []),
    [snapshot],
  )

  const columns = useMemo(
    () => [
      columnHelper.accessor('label', {
        header: t(`${NS}.col_asset`),
        cell: (ctx) => (
          <span className="flex items-center gap-2">
            {ctx.row.original.crown_jewel && <span title={t(`${NS}.crown_jewel`)}>👑</span>}
            <span className="text-[var(--text-primary)] truncate max-w-[16rem]" title={ctx.getValue()}>
              {ctx.getValue() || '—'}
            </span>
          </span>
        ),
      }),
      columnHelper.accessor('node_type', {
        header: t(`${NS}.col_type`),
        cell: (ctx) => <span className="text-[var(--text-tertiary)] font-mono text-[11px]">{ctx.getValue() || '—'}</span>,
      }),
      columnHelper.accessor('business_value_usd', {
        header: t(`${NS}.col_value`),
        cell: (ctx) => <span className="tabular-nums text-[var(--text-secondary)]">{fmtUsd(ctx.getValue())}</span>,
      }),
      columnHelper.accessor('max_cvss', {
        header: 'CVSS',
        cell: (ctx) => <span className="tabular-nums text-[var(--text-secondary)]">{(Number(ctx.getValue()) || 0).toFixed(1)}</span>,
      }),
      columnHelper.accessor('max_epss', {
        header: 'EPSS',
        cell: (ctx) => (
          <span className="tabular-nums text-[var(--text-secondary)]">{`${((Number(ctx.getValue()) || 0) * 100).toFixed(1)}%`}</span>
        ),
      }),
      columnHelper.accessor('kev_present', {
        header: 'KEV',
        cell: (ctx) =>
          ctx.getValue() ? (
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-rose-500/40 bg-rose-500/10 text-rose-300">
              KEV
            </span>
          ) : (
            <span className="text-[var(--text-disabled)]">—</span>
          ),
      }),
      columnHelper.accessor('sle_usd', {
        header: t(`${NS}.col_sle`),
        cell: (ctx) => <span className="tabular-nums text-amber-300/90">{fmtUsd(ctx.getValue())}</span>,
      }),
      columnHelper.accessor('ale_usd', {
        header: t(`${NS}.col_ale`),
        cell: (ctx) => <span className="tabular-nums text-rose-300/90 font-semibold">{fmtUsd(ctx.getValue())}</span>,
      }),
    ],
    [t],
  )

  const computedAt = snapshot?.computed_at_unix
    ? new Date(snapshot.computed_at_unix * 1000).toLocaleString()
    : null

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#4ade80"
      icon={<DollarSign className="w-5 h-5" />}
      actions={
        <div className="flex items-center gap-2">
          <select
            value={selectedClientId ?? ''}
            onChange={(e) => setSelectedClientId(e.target.value ? Number(e.target.value) : null)}
            className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-secondary)] focus:outline-none focus:border-emerald-500/40"
            aria-label={t(`${NS}.select_client`)}
          >
            <option value="">{t(`${NS}.select_client`)}</option>
            {clients.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name || c.domain || `#${c.id}`}
              </option>
            ))}
          </select>
          <Button variant="unstyled"
            type="button"
            onClick={() => load(true)}
            disabled={selectedClientId == null || recomputing}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-200 text-xs font-medium hover:bg-emerald-500/20 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${recomputing ? 'animate-spin' : ''}`} />
            {t(`${NS}.recompute`)}
          </Button>
          <ShellScanActions
            onRefresh={() => load(false)}
            onExport={() => contributorsCsv(contributors)}
            refreshLoading={loading}
            exportDisabled={!contributors.length}
          />
        </div>
      }
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        {selectedClientId == null && (
          <EmptyState icon="building" title={t(`${NS}.pick_client_title`)} body={t(`${NS}.pick_client_body`)} />
        )}

        {selectedClientId != null && loading && <SkeletonWidgetGrid count={4} />}

        {error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        {selectedClientId != null && !loading && !error && !hasSnapshot && (
          <EmptyState
            icon="dollar"
            title={t(`${NS}.no_snapshot_title`)}
            body={t(`${NS}.no_snapshot_body`)}
            action={
              <Button variant="unstyled"
                type="button"
                onClick={() => load(true)}
                disabled={recomputing}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 text-white text-sm font-medium hover:bg-emerald-700 disabled:opacity-50"
              >
                <RefreshCw className={`w-4 h-4 ${recomputing ? 'animate-spin' : ''}`} />
                {t(`${NS}.compute_now`)}
              </Button>
            }
          />
        )}

        {selectedClientId != null && !loading && !error && hasSnapshot && snapshot && (
          <>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              <ExecutiveWidget
                label={t(`${NS}.kpi_ale`)}
                value={fmtUsd(snapshot.ale_annualised_usd)}
                hint={t(`${NS}.kpi_ale_hint`)}
                accent="#ef4444"
              />
              <ExecutiveWidget
                label={t(`${NS}.kpi_sle`)}
                value={fmtUsd(snapshot.sle_worst_usd)}
                hint={t(`${NS}.kpi_sle_hint`)}
                accent="#f59e0b"
              />
              <ExecutiveWidget
                label={t(`${NS}.kpi_crown`)}
                value={fmtUsd(snapshot.crown_jewel_value_usd)}
                hint={t(`${NS}.kpi_crown_hint`)}
                accent="#a78bfa"
              />
              <ExecutiveWidget
                label={t(`${NS}.kpi_total`)}
                value={fmtUsd(snapshot.total_asset_value_usd)}
                hint={t(`${NS}.kpi_total_hint`)}
                accent="#22d3ee"
              />
            </div>

            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] font-mono text-[var(--text-muted)]">
              {computedAt && <span>{t(`${NS}.computed_at`, { time: computedAt })}</span>}
              <span>
                {t(`${NS}.ale_full`, { value: fmtUsdFull(snapshot.ale_annualised_usd) })}
              </span>
              <span>{t(`${NS}.discount`, { pct: Math.round((snapshot.risk_loss_discount ?? 1) * 100) })}</span>
            </div>

            <div>
              <h2 className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-3">
                {t(`${NS}.top_contributors`)}
              </h2>
              {contributors.length === 0 ? (
                <EmptyState icon="chart" title={t(`${NS}.no_contributors_title`)} body={t(`${NS}.no_contributors_body`)} />
              ) : (
                <DataTable
                  id="financial-risk-contributors"
                  columns={columns}
                  data={contributors}
                  animateRows={false}
                  searchable
                  getRowId={(r) => r.node_id}
                  getRowAccentColor={(r) => (r.kev_present ? '#ef4444' : r.crown_jewel ? '#a78bfa' : undefined)}
                />
              )}
            </div>
          </>
        )}
      </div>
    </PageShell>
  )
}
