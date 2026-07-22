/**
 * Attack-Path Inference — choke-points + ranked internet→crown-jewel paths.
 *
 * Wired to the live GET /api/attack-paths/:client_id endpoint (BFS over the
 * risk graph weighted by CVSS+EPSS+KEV, server-side). `?recompute=1&top_k=N`
 * regenerates the snapshot. Route: /attack-paths
 */
import React, { useState, useCallback, useEffect, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { GitBranch, RefreshCw, ChevronRight } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import DataTable from '../components/ui/DataTable'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useClient } from '../context/ClientContext'
import { apiFetch } from '../utils/apiFetch'
import { useToast } from '../components/ui/Toaster'
import Button from '../components/ui/Button'

const NS = 'pages.attackPaths'
const columnHelper = createColumnHelper()

function riskColor(risk) {
  const r = Number(risk) || 0
  if (r >= 8) return '#ef4444'
  if (r >= 6) return '#f97316'
  if (r >= 4) return '#f59e0b'
  return '#22d3ee'
}

function chokeCsv(rows) {
  const header = ['label', 'node_type', 'coverage', 'coverage_pct', 'max_finding_cvss', 'max_finding_epss', 'kev_present']
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const lines = [
    header.join(','),
    ...rows.map((r) =>
      [r.label, r.node_type, r.coverage, r.coverage_pct, r.max_finding_cvss, r.max_finding_epss, r.kev_present]
        .map(esc)
        .join(','),
    ),
  ]
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `weissman-attack-paths-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

function PathCard({ path, t }) {
  const color = riskColor(path.risk)
  return (
    <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--table-surface)] p-4">
      <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <span
            className="text-[10px] font-mono px-2 py-0.5 rounded border uppercase tracking-wider"
            style={{ color, borderColor: `${color}40`, background: `${color}10` }}
          >
            {t(`${NS}.risk`)} {(Number(path.risk) || 0).toFixed(1)}
          </span>
          <span className="text-[10px] font-mono text-[var(--text-muted)]">{t(`${NS}.hops`, { count: path.hops })}</span>
          {path.kev_hops > 0 && (
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-rose-500/40 bg-rose-500/10 text-rose-300">
              {t(`${NS}.kev_hops`, { count: path.kev_hops })}
            </span>
          )}
        </div>
        <span className="text-[10px] font-mono text-[var(--text-disabled)]">{t(`${NS}.cost`, { cost: (Number(path.cost) || 0).toFixed(1) })}</span>
      </div>
      <div className="flex items-center gap-1 flex-wrap">
        {(path.steps || []).map((step, i) => (
          <React.Fragment key={`${step.node_id}-${i}`}>
            {i > 0 && <ChevronRight className="w-3 h-3 text-[var(--text-disabled)] shrink-0" aria-hidden />}
            <span
              className="text-[11px] font-mono px-2 py-1 rounded border border-[var(--border-default)] bg-[var(--row-hover-bg)] text-[var(--text-secondary)] truncate max-w-[12rem]"
              title={`${step.label} (${step.node_type})`}
            >
              {i === 0 ? '🌐 ' : ''}
              {i === (path.steps.length - 1) ? '👑 ' : ''}
              {step.label || step.graph_key}
            </span>
          </React.Fragment>
        ))}
      </div>
    </div>
  )
}

export default function AttackPaths() {
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
        const qs = recompute ? '?recompute=1&top_k=15' : ''
        const data = await apiFetch(`/api/attack-paths/${encodeURIComponent(selectedClientId)}${qs}`)
        if (data?.ok === false) throw new Error(data.detail || 'load failed')
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

  const chokePoints = useMemo(
    () => (Array.isArray(snapshot?.choke_points) ? snapshot.choke_points : []),
    [snapshot],
  )
  const paths = useMemo(
    () => (Array.isArray(snapshot?.paths) ? snapshot.paths : []),
    [snapshot],
  )
  const topRisk = useMemo(
    () => (paths.length ? Math.max(...paths.map((p) => Number(p.risk) || 0)) : 0),
    [paths],
  )

  const columns = useMemo(
    () => [
      columnHelper.accessor('label', {
        header: t(`${NS}.col_node`),
        cell: (ctx) => (
          <span className="text-[var(--text-primary)] truncate max-w-[16rem] block" title={ctx.getValue()}>
            {ctx.getValue() || ctx.row.original.graph_key || '—'}
          </span>
        ),
      }),
      columnHelper.accessor('node_type', {
        header: t(`${NS}.col_type`),
        cell: (ctx) => <span className="text-[var(--text-tertiary)] font-mono text-[11px]">{ctx.getValue() || '—'}</span>,
      }),
      columnHelper.accessor('coverage_pct', {
        header: t(`${NS}.col_coverage`),
        cell: (ctx) => {
          const pct = Number(ctx.getValue()) || 0
          const color = pct >= 66 ? '#ef4444' : pct >= 33 ? '#f59e0b' : '#22d3ee'
          return (
            <div className="flex items-center gap-2 min-w-[120px]">
              <div className="h-1.5 flex-1 rounded-full bg-[var(--row-hover-bg)] overflow-hidden">
                <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
              </div>
              <span className="tabular-nums text-[11px]" style={{ color }}>{pct}%</span>
            </div>
          )
        },
      }),
      columnHelper.accessor('coverage', {
        header: t(`${NS}.col_paths`),
        cell: (ctx) => <span className="tabular-nums text-[var(--text-secondary)]">{ctx.getValue()}</span>,
      }),
      columnHelper.accessor('max_finding_cvss', {
        header: 'CVSS',
        cell: (ctx) => <span className="tabular-nums text-[var(--text-secondary)]">{(Number(ctx.getValue()) || 0).toFixed(1)}</span>,
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
      badgeColor="#f97316"
      icon={<GitBranch className="w-5 h-5" />}
      actions={
        <div className="flex items-center gap-2">
          <select
            value={selectedClientId ?? ''}
            onChange={(e) => setSelectedClientId(e.target.value ? Number(e.target.value) : null)}
            className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-secondary)] focus:outline-none focus:border-orange-500/40"
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
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-orange-500/30 bg-orange-500/10 text-orange-200 text-xs font-medium hover:bg-orange-500/20 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${recomputing ? 'animate-spin' : ''}`} />
            {t(`${NS}.recompute`)}
          </Button>
          <ShellScanActions
            onRefresh={() => load(false)}
            onExport={() => chokeCsv(chokePoints)}
            refreshLoading={loading}
            exportDisabled={!chokePoints.length}
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
            icon="network"
            title={t(`${NS}.no_snapshot_title`)}
            body={t(`${NS}.no_snapshot_body`)}
            action={
              <Button variant="unstyled"
                type="button"
                onClick={() => load(true)}
                disabled={recomputing}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-orange-600 text-white text-sm font-medium hover:bg-orange-700 disabled:opacity-50"
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
              <ExecutiveWidget label={t(`${NS}.kpi_entries`)} value={snapshot.entry_count ?? 0} hint={t(`${NS}.kpi_entries_hint`)} accent="#22d3ee" />
              <ExecutiveWidget label={t(`${NS}.kpi_jewels`)} value={snapshot.jewel_count ?? 0} hint={t(`${NS}.kpi_jewels_hint`)} accent="#a78bfa" />
              <ExecutiveWidget label={t(`${NS}.kpi_paths`)} value={paths.length} hint={t(`${NS}.kpi_paths_hint`)} accent="#f97316" />
              <ExecutiveWidget label={t(`${NS}.kpi_top_risk`)} value={topRisk.toFixed(1)} hint={t(`${NS}.kpi_top_risk_hint`)} accent={riskColor(topRisk)} />
            </div>

            {computedAt && (
              <div className="text-[11px] font-mono text-[var(--text-muted)]">{t(`${NS}.computed_at`, { time: computedAt })}</div>
            )}

            <div>
              <h2 className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-1">
                {t(`${NS}.choke_points`)}
              </h2>
              <p className="text-[11px] text-[var(--text-muted)] mb-3">{t(`${NS}.choke_points_hint`)}</p>
              {chokePoints.length === 0 ? (
                <EmptyState icon="chart" title={t(`${NS}.no_choke_title`)} body={t(`${NS}.no_choke_body`)} />
              ) : (
                <DataTable
                  id="attack-choke-points"
                  columns={columns}
                  data={chokePoints}
                  animateRows={false}
                  searchable
                  getRowId={(r) => r.node_id}
                  getRowAccentColor={(r) => (r.kev_present ? '#ef4444' : r.coverage_pct >= 66 ? '#f97316' : undefined)}
                />
              )}
            </div>

            <div>
              <h2 className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-3">
                {t(`${NS}.top_paths`)}
              </h2>
              {paths.length === 0 ? (
                <EmptyState icon="shield" title={t(`${NS}.no_paths_title`)} body={t(`${NS}.no_paths_body`)} />
              ) : (
                <div className="space-y-3">
                  {paths.slice(0, 15).map((p, i) => (
                    <PathCard key={`${p.entry}-${p.jewel}-${i}`} path={p} t={t} />
                  ))}
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </PageShell>
  )
}
