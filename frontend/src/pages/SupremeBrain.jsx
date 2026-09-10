/**
 * Supreme Brain — attack-path inference × FAIR blast radius × pentest RAG memory.
 *
 * Live GET /api/supreme-brain/:client_id. `?recompute=1` regenerates Dijkstra
 * and FAIR snapshots from the current risk graph. Route: /supreme-brain
 */
import { useState, useCallback, useEffect, useMemo, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { Brain, RefreshCw } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import DataTable from '../components/ui/DataTable'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useClient } from '../context/ClientContext'
import { apiFetch } from '../utils/apiFetch'
import { fmtUsd } from '../lib/riskFormat'
import { useToast } from '../components/ui/Toaster'
import Button from '../components/ui/Button'

const NS = 'pages.supremeBrain'
const columnHelper = createColumnHelper()

function pathFrom(path) {
  const steps = Array.isArray(path?.steps) ? path.steps : []
  return steps[0]?.label || steps[0]?.graph_key || path?.entry || '—'
}

function pathTo(path) {
  const steps = Array.isArray(path?.steps) ? path.steps : []
  const last = steps[steps.length - 1]
  return last?.label || last?.graph_key || path?.jewel || '—'
}

function exportBrain(payload) {
  const blob = new Blob([JSON.stringify(payload || {}, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `weissman-supreme-brain-${new Date().toISOString().slice(0, 10)}.json`
  a.click()
  URL.revokeObjectURL(url)
}

export default function SupremeBrain() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const toastRef = useRef(toast)
  useEffect(() => { toastRef.current = toast }, [toast])
  const { clients, selectedClientId, setSelectedClientId } = useClient()

  const [payload, setPayload] = useState(null)
  const [loading, setLoading] = useState(false)
  const [recomputing, setRecomputing] = useState(false)
  const [error, setError] = useState('')

  const load = useCallback(
    async (recompute = false) => {
      if (selectedClientId == null) return
      if (recompute) setRecomputing(true)
      else setLoading(true)
      setError('')
      try {
        const qs = recompute ? '?recompute=1' : ''
        const data = await apiFetch(`/api/supreme-brain/${encodeURIComponent(selectedClientId)}${qs}`)
        if (data?.ok === false) throw new Error(data.detail || 'load failed')
        setPayload(data)
        if (recompute) toastRef.current.success(t(`${NS}.recompute_done`))
      } catch (e) {
        setError(e.message || t(`${NS}.load_failed`))
      } finally {
        setLoading(false)
        setRecomputing(false)
      }
    },
    [selectedClientId, t],
  )

  useEffect(() => {
    setPayload(null)
    if (selectedClientId != null) load(false)
  }, [selectedClientId, load])

  const pathsSnap = payload?.paths || null
  const financial = payload?.financial || null
  const memory = payload?.pentest_memory || null
  const paths = useMemo(
    () => (Array.isArray(pathsSnap?.paths) ? pathsSnap.paths : []),
    [pathsSnap],
  )
  const hasAny = Boolean(pathsSnap || financial || memory)

  const columns = useMemo(
    () => [
      columnHelper.display({
        id: 'from',
        header: t(`${NS}.col_from`),
        cell: (ctx) => (
          <span className="text-[var(--text-primary)] truncate max-w-[14rem] block" title={pathFrom(ctx.row.original)}>
            {pathFrom(ctx.row.original)}
          </span>
        ),
      }),
      columnHelper.display({
        id: 'to',
        header: t(`${NS}.col_to`),
        cell: (ctx) => (
          <span className="text-[var(--text-primary)] truncate max-w-[14rem] block" title={pathTo(ctx.row.original)}>
            {pathTo(ctx.row.original)}
          </span>
        ),
      }),
      columnHelper.accessor('hops', {
        header: t(`${NS}.col_hops`),
        cell: (ctx) => <span className="tabular-nums text-[var(--text-secondary)]">{ctx.getValue() ?? 0}</span>,
      }),
      columnHelper.accessor('path_score', {
        header: t(`${NS}.col_score`),
        cell: (ctx) => {
          const score = Number(ctx.getValue()) || 0
          const color = score >= 80 ? '#ef4444' : score >= 50 ? '#f59e0b' : '#22d3ee'
          return <span className="tabular-nums font-semibold" style={{ color }}>{score}</span>
        },
      }),
      columnHelper.accessor('ale_usd', {
        header: t(`${NS}.col_ale`),
        cell: (ctx) => <span className="tabular-nums text-amber-300/90">{fmtUsd(ctx.getValue())}</span>,
      }),
      columnHelper.accessor('root_cause', {
        header: t(`${NS}.col_root`),
        cell: (ctx) => (
          <span className="text-[11px] font-mono text-[var(--text-muted)] truncate max-w-[18rem] block" title={ctx.getValue()}>
            {ctx.getValue() || '—'}
          </span>
        ),
      }),
    ],
    [t],
  )

  const computedAt = pathsSnap?.computed_at_unix
    ? new Date(pathsSnap.computed_at_unix * 1000).toLocaleString()
    : financial?.computed_at_unix
      ? new Date(financial.computed_at_unix * 1000).toLocaleString()
      : null

  const hitPct = Math.round((Number(memory?.avg_replay_hit_rate) || 0) * 100)

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#a78bfa"
      icon={<Brain className="w-5 h-5" />}
      actions={
        <div className="flex items-center gap-2">
          <select
            value={selectedClientId ?? ''}
            onChange={(e) => setSelectedClientId(e.target.value ? Number(e.target.value) : null)}
            className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-secondary)] focus:outline-none focus:border-violet-500/40"
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
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-violet-500/30 bg-violet-500/10 text-violet-200 text-xs font-medium hover:bg-violet-500/20 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${recomputing ? 'animate-spin' : ''}`} />
            {t(`${NS}.recompute`)}
          </Button>
          <ShellScanActions
            onRefresh={() => load(false)}
            onExport={() => exportBrain(payload)}
            refreshLoading={loading}
            exportDisabled={!payload}
          />
        </div>
      }
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        {selectedClientId == null && (
          <EmptyState icon="building" title={t(`${NS}.pick_client_title`)} body={t(`${NS}.pick_client_body`)} />
        )}

        {selectedClientId != null && loading && <SkeletonWidgetGrid count={8} />}

        {error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        {selectedClientId != null && !loading && !error && !hasAny && (
          <EmptyState
            icon="network"
            title={t(`${NS}.no_data_title`)}
            body={t(`${NS}.no_data_body`)}
            action={
              <Button variant="unstyled"
                type="button"
                onClick={() => load(true)}
                disabled={recomputing}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-violet-600 text-white text-sm font-medium hover:bg-violet-700 disabled:opacity-50"
              >
                <RefreshCw className={`w-4 h-4 ${recomputing ? 'animate-spin' : ''}`} />
                {t(`${NS}.compute_now`)}
              </Button>
            }
          />
        )}

        {selectedClientId != null && !loading && !error && hasAny && (
          <>
            {payload?.graph_dirty && (
              <div className="rounded-xl border border-amber-500/30 bg-amber-950/20 px-4 py-2 text-[12px] font-mono text-amber-200">
                {t(`${NS}.graph_dirty`)}
              </div>
            )}

            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_paths`)} value={paths.length} hint={t(`${NS}.kpi_paths_hint`)} accent="#f97316" />
              <ExecutiveWidget label={t(`${NS}.kpi_score`)} value={pathsSnap?.max_path_score ?? 0} hint={t(`${NS}.kpi_score_hint`)} accent="#ef4444" />
              <ExecutiveWidget label={t(`${NS}.kpi_path_ale`)} value={fmtUsd(pathsSnap?.total_path_ale_usd)} hint={t(`${NS}.kpi_path_ale_hint`)} accent="#f59e0b" />
              <ExecutiveWidget label={t(`${NS}.kpi_chokes`)} value={(pathsSnap?.choke_points || []).length} hint={t(`${NS}.kpi_chokes_hint`)} accent="#22d3ee" />
            </div>

            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_ale`)} value={fmtUsd(financial?.ale_annualised_usd)} hint={t(`${NS}.kpi_ale_hint`)} accent="#ef4444" />
              <ExecutiveWidget label={t(`${NS}.kpi_concentration`)} value={`${financial?.concentration_pct ?? 0}%`} hint={t(`${NS}.kpi_concentration_hint`)} accent="#a78bfa" />
              <ExecutiveWidget label={t(`${NS}.kpi_delay`)} value={fmtUsd(financial?.delay_cost_usd_per_day)} hint={t(`${NS}.kpi_delay_hint`)} accent="#f97316" />
              <ExecutiveWidget label={t(`${NS}.kpi_memory`)} value={memory?.winning_paths ?? 0} hint={t(`${NS}.kpi_memory_hint`)} accent="#22d3ee" />
            </div>

            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_hit_rate`)} value={`${hitPct}%`} hint={t(`${NS}.kpi_hit_rate_hint`)} accent="#4ade80" />
              <ExecutiveWidget label={t(`${NS}.kpi_engines`)} value={memory?.engines ?? 0} hint={t(`${NS}.kpi_engines_hint`)} accent="#38bdf8" />
            </div>

            {computedAt && (
              <div className="text-[11px] font-mono text-[var(--text-muted)]">{t(`${NS}.computed_at`, { time: computedAt })}</div>
            )}

            <div>
              <h2 className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-3">
                {t(`${NS}.paths_title`)}
              </h2>
              {paths.length === 0 ? (
                <EmptyState icon="shield" title={t(`${NS}.empty_paths_title`)} body={t(`${NS}.empty_paths_body`)} />
              ) : (
                <DataTable
                  id="supreme-brain-paths"
                  columns={columns}
                  data={paths}
                  animateRows={false}
                  searchable
                  getRowId={(r, i) => `${r.entry}-${r.jewel}-${i}`}
                  getRowAccentColor={(r) => (r.kev_hops > 0 ? '#ef4444' : Number(r.path_score) >= 80 ? '#f97316' : undefined)}
                />
              )}
            </div>
          </>
        )}
      </div>
    </PageShell>
  )
}
