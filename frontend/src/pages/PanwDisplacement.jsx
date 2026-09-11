/**
 * PANW displacement win-room — live SKU map vs Palo Alto, not marketing scores.
 *
 * Wired to GET /api/competitive/panw-displacement?client_id=
 * and POST /api/command-center/scan (exposure_schism_fusion).
 * Verdicts are computed from live connectors, surface snapshots, and engine kinds.
 * Route: /panw-displacement
 */
import { useState, useCallback, useEffect, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { Swords, RefreshCw } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import DataTable from '../components/ui/DataTable'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useClient } from '../context/ClientContext'
import { apiFetch } from '../utils/apiFetch'
import { downloadCsv } from '../lib/exportFindingsCsv'
import { launchEngineScan } from '../lib/launchEngineScan'
import { firstClientTarget, resolveClient } from '../lib/clientTarget'
import Button from '../components/ui/Button'

const NS = 'pages.panwDisplacement'
const SCHISM_ENGINE = 'exposure_schism_fusion'
const columnHelper = createColumnHelper()

const VERDICT_ACCENT = {
  live_win: '#34d399',
  live_partial: '#22d3ee',
  live_gap_sensor: '#fb7185',
  live_gap_sensor_offline: '#fb7185',
  unproven: '#fbbf24',
  unproven_connector: '#fbbf24',
  unproven_baseline: '#fbbf24',
  unproven_no_client: '#94a3b8',
  unavailable: '#64748b',
  non_goal: '#64748b',
  overlap_probe: '#a78bfa',
}

function skuCsv(rows) {
  const header = ['id', 'panw_sku', 'role', 'verdict', 'engines', 'honest_gap']
  const data = rows.map((r) => [
    r.id,
    r.panw_sku,
    r.role,
    r.verdict,
    (r.weissman_engines || []).map((e) => e.id).join(' '),
    r.honest_gap,
  ])
  downloadCsv(data, header, 'weissman-panw-displacement')
}

export default function PanwDisplacement() {
  const { t } = useTranslation()
  const { clients, selectedClientId, setSelectedClientId } = useClient()

  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [searchTerm, setSearchTerm] = useState('')
  const [hunting, setHunting] = useState(false)
  const [huntMsg, setHuntMsg] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const q = selectedClientId != null ? `?client_id=${encodeURIComponent(selectedClientId)}` : ''
      const body = await apiFetch(`/api/competitive/panw-displacement${q}`)
      setReport(body)
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
    } finally {
      setLoading(false)
    }
  }, [selectedClientId, t])

  useEffect(() => {
    load()
  }, [load])

  const skus = useMemo(
    () => (Array.isArray(report?.skus) ? report.skus : []),
    [report],
  )

  const filtered = useMemo(() => {
    const q = searchTerm.trim().toLowerCase()
    if (!q) return skus
    return skus.filter((s) => {
      const engines = (s.weissman_engines || []).map((e) => e.id).join(' ')
      const hay = `${s.id} ${s.panw_sku} ${s.panw_label} ${s.role} ${s.verdict} ${engines} ${s.honest_gap}`.toLowerCase()
      return hay.includes(q)
    })
  }, [skus, searchTerm])

  const selected = resolveClient(selectedClientId, clients)
  const target = firstClientTarget(selected)

  const huntSchism = useCallback(async () => {
    if (!selectedClientId || !target) {
      setHuntMsg(t(`${NS}.hunt_need_target`))
      return
    }
    setHunting(true)
    setHuntMsg('')
    try {
      const r = await launchEngineScan({
        engineId: SCHISM_ENGINE,
        clientId: selectedClientId,
        target,
      })
      if (r?.ok) {
        setHuntMsg(t(`${NS}.hunt_queued`))
      } else {
        setHuntMsg(r?.data?.error || t(`${NS}.hunt_failed`))
      }
    } catch (e) {
      setHuntMsg(e.message || t(`${NS}.hunt_failed`))
    } finally {
      setHunting(false)
    }
  }, [selectedClientId, target, t])

  const columns = useMemo(
    () => [
      columnHelper.accessor('panw_sku', {
        header: t(`${NS}.col_sku`),
        cell: (ctx) => (
          <div>
            <div className="font-medium text-[var(--text-primary)] text-[12px]">{ctx.getValue()}</div>
            <div className="font-mono text-[10px] text-[var(--text-muted)]">{ctx.row.original.id}</div>
          </div>
        ),
      }),
      columnHelper.accessor('role', {
        header: t(`${NS}.col_role`),
        cell: (ctx) => <span className="text-[11px] text-[var(--text-tertiary)]">{t(`${NS}.role_${ctx.getValue()}`, ctx.getValue())}</span>,
      }),
      columnHelper.accessor('verdict', {
        header: t(`${NS}.col_verdict`),
        cell: (ctx) => {
          const v = ctx.getValue()
          const color = VERDICT_ACCENT[v] || '#94a3b8'
          return (
            <span className="font-mono text-[11px] font-semibold" style={{ color }}>
              {t(`${NS}.verdict_${v}`, v)}
            </span>
          )
        },
      }),
      columnHelper.accessor('weissman_engines', {
        header: t(`${NS}.col_engines`),
        cell: (ctx) => (
          <span className="font-mono text-[10px] text-cyan-300/80">
            {(ctx.getValue() || []).map((e) => e.id).join(' · ') || '—'}
          </span>
        ),
      }),
      columnHelper.accessor('honest_gap', {
        header: t(`${NS}.col_gap`),
        cell: (ctx) => (
          <span className="text-[11px] text-[var(--text-tertiary)] leading-snug block max-w-[36rem]">
            {ctx.getValue()}
          </span>
        ),
      }),
    ],
    [t],
  )

  const c = report?.live_connectors || {}
  const counts = report?.counts || {}
  const nerve = c.first_mover_nerve || {}
  const surface = c.surface || {}

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#f43f5e"
      icon={<Swords className="w-5 h-5" />}
      engineId={SCHISM_ENGINE}
      hideEvidence
      actions={
        <div className="flex items-center gap-2 flex-wrap">
          <select
            value={selectedClientId ?? ''}
            onChange={(e) => setSelectedClientId(e.target.value ? Number(e.target.value) : null)}
            className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-secondary)] focus:outline-none focus:border-rose-500/40"
            aria-label={t(`${NS}.select_client`)}
          >
            <option value="">{t(`${NS}.select_client`)}</option>
            {clients.map((cl) => (
              <option key={cl.id} value={cl.id}>
                {cl.name || cl.domain || `#${cl.id}`}
              </option>
            ))}
          </select>
          <Button
            variant="unstyled"
            type="button"
            onClick={huntSchism}
            disabled={hunting || !selectedClientId}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-rose-500/30 bg-rose-500/10 text-rose-100 text-xs font-medium hover:bg-rose-500/20 disabled:opacity-40"
          >
            {hunting ? `⟳ ${t(`${NS}.hunting`)}` : `⚡ ${t(`${NS}.hunt`)}`}
          </Button>
          <Button
            variant="unstyled"
            type="button"
            onClick={load}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-200 text-xs font-medium hover:bg-cyan-500/20 disabled:opacity-40"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            {t(`${NS}.reload`)}
          </Button>
          <ShellScanActions
            onRefresh={load}
            onExport={() => skuCsv(filtered)}
            refreshLoading={loading}
            exportDisabled={!filtered.length}
          />
        </div>
      }
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        {error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}
        {huntMsg && (
          <p className="text-[12px] font-mono text-amber-200/80">{huntMsg}</p>
        )}

        {loading && !report && <SkeletonWidgetGrid count={4} />}

        {report && (
          <>
            <p className="text-[13px] leading-relaxed text-[var(--text-secondary)] max-w-4xl">
              {report.category_truth}
            </p>

            <div className="grid grid-cols-2 lg:grid-cols-4 xl:grid-cols-8 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_win`)} value={counts.live_win ?? 0} hint={t(`${NS}.kpi_win_hint`)} accent="#34d399" />
              <ExecutiveWidget label={t(`${NS}.kpi_partial`)} value={counts.live_partial ?? 0} hint={t(`${NS}.kpi_partial_hint`)} accent="#22d3ee" />
              <ExecutiveWidget label={t(`${NS}.kpi_gap`)} value={counts.live_gap ?? 0} hint={t(`${NS}.kpi_gap_hint`)} accent="#fb7185" />
              <ExecutiveWidget label={t(`${NS}.kpi_unproven`)} value={counts.unproven ?? 0} hint={t(`${NS}.kpi_unproven_hint`)} accent="#fbbf24" />
              <ExecutiveWidget
                label={t(`${NS}.kpi_aws`)}
                value={c.aws_role_configured ? t(`${NS}.on`) : t(`${NS}.off`)}
                hint={t(`${NS}.kpi_aws_hint`)}
                accent="#f59e0b"
              />
              <ExecutiveWidget
                label={t(`${NS}.kpi_agents`)}
                value={`${c.enrolled_agents_online ?? 0}/${c.enrolled_agents_total ?? 0}`}
                hint={t(`${NS}.kpi_agents_hint`)}
                accent="#a78bfa"
              />
              <ExecutiveWidget
                label={t(`${NS}.kpi_sso`)}
                value={c.sso_idp_count ?? 0}
                hint={t(`${NS}.kpi_sso_hint`)}
                accent="#818cf8"
              />
              <ExecutiveWidget
                label={t(`${NS}.kpi_oast`)}
                value={nerve.oast_configured ? t(`${NS}.on`) : t(`${NS}.off`)}
                hint={t(`${NS}.kpi_oast_hint`)}
                accent="#22d3ee"
              />
            </div>

            <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] px-4 py-3 text-[12px] font-mono text-[var(--text-tertiary)] flex flex-wrap gap-x-4 gap-y-1">
              <span>certstream {nerve.certstream_connected ? 'live' : nerve.certstream_enabled ? 'idle' : 'off'}</span>
              <span>azure {c.azure_configured ? 'on' : 'off'}</span>
              <span>gcp {c.gcp_project_configured ? 'on' : 'off'}</span>
              <span>snapshots {surface.snapshot_count ?? 0}{surface.baseline_only ? ' · baseline' : ''}</span>
              <span>added {surface.added ?? 0}</span>
              <span>soar {(c.soar_providers || []).join(',') || 'none'}</span>
            </div>

            <div>
              <h2 className="text-sm font-semibold text-[var(--text-primary)] mb-2">{t(`${NS}.moat_title`)}</h2>
              <p className="text-[13px] text-[var(--text-secondary)] max-w-4xl leading-relaxed">
                {report.unique_moat?.why_panw_cannot_copy}
              </p>
              <p className="font-mono text-[11px] text-cyan-300/80 mt-1">{report.unique_moat?.engine_id}</p>
            </div>

            <div>
              <h2 className="text-sm font-semibold text-[var(--text-primary)] mb-2">{t(`${NS}.absences_title`)}</h2>
              <ul className="flex flex-wrap gap-2">
                {(report.code_absences || []).map((a) => (
                  <li key={a} className="font-mono text-[11px] px-2 py-1 rounded-md border border-amber-500/30 bg-amber-500/10 text-amber-100">
                    {a}
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <label htmlFor="panw-displacement-search" className="sr-only">{t(`${NS}.search_placeholder`)}</label>
              <input
                id="panw-displacement-search"
                data-testid="sku-search"
                type="search"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder={t(`${NS}.search_placeholder`)}
                className="w-full max-w-md bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-primary)] mb-3"
              />
              {filtered.length === 0 ? (
                <EmptyState title={t(`${NS}.empty_title`)} body={t(`${NS}.empty_body`)} />
              ) : (
                <div data-testid="sku-table">
                  <DataTable data={filtered} columns={columns} getRowId={(row) => row.id} />
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </PageShell>
  )
}
