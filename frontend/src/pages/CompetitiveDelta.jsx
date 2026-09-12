/**
 * Competitive Delta — live bake-off board vs public market clusters.
 * Route: /competitive-delta
 *
 * GET /api/competitive-delta only. Engine counts, OT catalog membership, SSO/agent
 * facts, and env booleans are live. Vendor clusters are labelled market research
 * (not live scans of those products). Weissman is not a PAN-OS replacement.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Swords, Search } from 'lucide-react'
import { createColumnHelper } from '@tanstack/react-table'
import PageShell from './PageShell'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import FilterPills from '../components/ui/FilterPills'
import DataTable from '../components/ui/DataTable'
import Button from '../components/ui/Button'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { apiFetch } from '../utils/apiFetch'
import { exportRowsCsv, exportRowsPdf, rowMatchesQuery } from '../lib/pageExport'

const NS = 'pages.competitiveDelta'
const columnHelper = createColumnHelper()

export const DELTA_CSV_HEADER = ['id', 'title', 'live_engine_count', 'covered', 'beats', 'sample_ids']

export function deltaLaneRows(lanes) {
  return (Array.isArray(lanes) ? lanes : []).map((l) => [
    l?.id ?? '',
    l?.title ?? '',
    l?.live_engine_count ?? 0,
    l?.covered ? 'live' : 'gap',
    l?.beats ?? '',
    Array.isArray(l?.sample_ids) ? l.sample_ids.join(' ') : '',
  ])
}

function downloadJson(payload, prefix) {
  const blob = new Blob([JSON.stringify(payload ?? {}, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${prefix}-${new Date().toISOString().slice(0, 10)}.json`
  a.click()
  URL.revokeObjectURL(url)
}

function statusLabel(fact, t) {
  if (!fact || typeof fact !== 'object') return t(`${NS}.unknown`)
  if (fact.on_this_revision) return t(`${NS}.present`)
  return t(`${NS}.not_on_revision`)
}

export default function CompetitiveDelta() {
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [coverageFilter, setCoverageFilter] = useState('all')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const d = await apiFetch('/api/competitive-delta')
      if (d?.ok === false) throw new Error(d.detail || 'load failed')
      setData(d)
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    load()
  }, [load])

  const lanes = Array.isArray(data?.moat?.lanes) ? data.moat.lanes : []
  const clusters = Array.isArray(data?.moat?.market_research?.clusters)
    ? data.moat.market_research.clusters
    : []

  const filtered = useMemo(() => {
    return lanes.filter((l) => {
      if (coverageFilter === 'live' && !l.covered) return false
      if (coverageFilter === 'gap' && l.covered) return false
      return rowMatchesQuery(searchQuery, [
        l.id,
        l.title,
        l.beats,
        l.covered ? 'live' : 'gap',
        ...(Array.isArray(l.sample_ids) ? l.sample_ids : []),
      ])
    })
  }, [lanes, searchQuery, coverageFilter])

  const pills = useMemo(
    () => [
      { id: 'all', label: t(`${NS}.all_lanes`), active: coverageFilter === 'all', onClick: () => setCoverageFilter('all') },
      { id: 'live', label: t(`${NS}.live`), active: coverageFilter === 'live', onClick: () => setCoverageFilter('live') },
      { id: 'gap', label: t(`${NS}.gap`), active: coverageFilter === 'gap', onClick: () => setCoverageFilter('gap') },
    ],
    [coverageFilter, t],
  )

  const columns = useMemo(
    () => [
      columnHelper.accessor('id', {
        header: () => t(`${NS}.col_id`),
        cell: (ctx) => <span className="font-mono text-cyan-300 text-[11px]">{ctx.getValue()}</span>,
      }),
      columnHelper.accessor('title', {
        header: () => t(`${NS}.col_lane`),
        cell: (ctx) => <span className="text-white">{ctx.getValue()}</span>,
      }),
      columnHelper.accessor('live_engine_count', {
        header: () => t(`${NS}.col_engines`),
        cell: (ctx) => (
          <span className="font-mono text-cyan-200 tabular-nums">{ctx.getValue()}</span>
        ),
      }),
      columnHelper.accessor('covered', {
        header: () => t(`${NS}.col_status`),
        cell: (ctx) => {
          const live = Boolean(ctx.getValue())
          return (
            <span
              className={`inline-flex rounded-full px-2 py-0.5 text-[10px] uppercase tracking-wider ${
                live ? 'bg-emerald-500/15 text-emerald-300' : 'bg-rose-500/15 text-rose-300'
              }`}
            >
              {live ? t(`${NS}.live`) : t(`${NS}.gap`)}
            </span>
          )
        },
      }),
      columnHelper.accessor('beats', {
        header: () => t(`${NS}.col_beats`),
        cell: (ctx) => (
          <span className="text-[var(--text-muted)] text-[11px] leading-snug">{ctx.getValue()}</span>
        ),
      }),
    ],
    [t],
  )

  const doExport = (kind) => {
    const rows = deltaLaneRows(filtered)
    if (kind === 'json') {
      downloadJson(data, 'weissman-competitive-delta')
    } else if (kind === 'pdf') {
      exportRowsPdf(t(`${NS}.title`), DELTA_CSV_HEADER, rows, 'weissman-competitive-delta')
    } else {
      exportRowsCsv(DELTA_CSV_HEADER, rows, 'weissman-competitive-delta')
    }
  }

  const enginesTotal = data?.engines?.total_ids ?? data?.moat?.engines_total ?? '—'
  const lanesCovered = data?.moat ? `${data.moat.lanes_covered}/${data.moat.lanes_total}` : '—'
  const otOk = Boolean(data?.ot_safety?.in_production_catalog)
  const campaign = data?.revision?.campaign_fabric
  const proof = data?.revision?.proof_artifacts

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#f97316"
      hideEvidence
      icon={<Swords className="w-5 h-5" />}
      actions={
        <ShellScanActions
          onRefresh={load}
          onExport={() => doExport('csv')}
          refreshLoading={loading}
          exportDisabled={!filtered.length}
        />
      }
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        {loading && <SkeletonWidgetGrid count={4} />}

        {error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        {!loading && !error && (
          <>
            <section
              data-testid="panos-posture"
              className="rounded-xl border border-amber-500/25 bg-amber-950/15 p-4 space-y-1"
            >
              <h2 className="text-sm font-semibold uppercase tracking-wider text-amber-200">
                {t(`${NS}.panos_title`)}
              </h2>
              <p className="text-xs text-[var(--text-muted)]">{t(`${NS}.panos_body`)}</p>
              <p className="text-[11px] font-mono text-amber-200/90">{data?.panos_posture}</p>
            </section>

            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-8 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_engines`)} value={enginesTotal} accent="#38bdf8" />
              <ExecutiveWidget
                label={t(`${NS}.kpi_lanes`)}
                value={lanesCovered}
                accent={data?.moat?.unmatched_stack ? '#34d399' : '#f59e0b'}
              />
              <ExecutiveWidget label={t(`${NS}.kpi_fusion`)} value={data?.fusion_engines ?? '—'} accent="#a78bfa" />
              <ExecutiveWidget
                label={t(`${NS}.kpi_ot`)}
                value={otOk ? t(`${NS}.ot_catalogued`) : t(`${NS}.ot_gap`)}
                accent={otOk ? '#34d399' : '#f43f5e'}
              />
              <ExecutiveWidget
                label={t(`${NS}.kpi_agents`)}
                value={data?.tenant?.endpoint_agents_enrolled ?? '—'}
                accent="#22d3ee"
              />
              <ExecutiveWidget
                label={t(`${NS}.kpi_sso`)}
                value={data?.tenant?.sso_idps_active ?? '—'}
                accent={data?.tenant?.sso_configured ? '#34d399' : '#f59e0b'}
              />
              <ExecutiveWidget
                label={t(`${NS}.kpi_oast`)}
                value={data?.ops_env?.oast_configured ? t(`${NS}.configured`) : t(`${NS}.unset`)}
                accent={data?.ops_env?.oast_configured ? '#34d399' : '#f59e0b'}
              />
              <ExecutiveWidget
                label={t(`${NS}.kpi_nvd`)}
                value={data?.ops_env?.nvd_api_key_present ? t(`${NS}.configured`) : t(`${NS}.unset`)}
                accent={data?.ops_env?.nvd_api_key_present ? '#34d399' : '#f59e0b'}
              />
            </div>

            <section data-testid="revision-facts" className="rounded-xl border border-white/10 bg-black/20 p-4 space-y-2">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-cyan-200">
                {t(`${NS}.revision_title`)}
              </h2>
              <p className="text-xs text-[var(--text-muted)]">{t(`${NS}.revision_notice`)}</p>
              <ul className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono">
                <li data-testid="campaign-fabric">
                  {t(`${NS}.campaign_fabric`)}: {statusLabel(campaign, t)}
                  {campaign?.detail ? ` — ${campaign.detail}` : ''}
                </li>
                <li data-testid="proof-artifacts">
                  {t(`${NS}.proof_artifacts`)}: {statusLabel(proof, t)}
                  {proof?.detail ? ` — ${proof.detail}` : ''}
                </li>
              </ul>
            </section>

            <div className="flex flex-col sm:flex-row gap-3 sm:items-center">
              <label className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-muted)]" />
                <input
                  type="search"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder={t(`${NS}.search_placeholder`)}
                  className="w-full rounded-lg border border-white/10 bg-black/30 pl-9 pr-3 py-2 text-sm text-white placeholder:text-[var(--text-muted)]"
                />
              </label>
              <Button type="button" variant="ghost" size="xs" onClick={() => doExport('json')}>
                {t(`${NS}.export_json`)}
              </Button>
              <Button type="button" variant="ghost" size="xs" onClick={() => doExport('pdf')}>
                {t(`${NS}.export_pdf`)}
              </Button>
            </div>

            <FilterPills pills={pills} />

            <DataTable
              columns={columns}
              data={filtered}
              animateRows={false}
              getRowId={(row) => String(row.id)}
              emptyState={{
                title: lanes.length ? t(`${NS}.no_match_title`) : t(`${NS}.empty_title`),
                body: lanes.length ? t(`${NS}.no_match_body`) : t(`${NS}.empty_body`),
              }}
            />

            {clusters.length > 0 && (
              <section data-testid="market-research" className="rounded-xl border border-white/10 bg-black/20 p-4 space-y-3">
                <h2 className="text-sm font-semibold uppercase tracking-wider text-violet-200">
                  {t(`${NS}.research_title`)}
                </h2>
                <p className="text-xs text-[var(--text-muted)]">{t(`${NS}.research_notice`)}</p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {clusters.map((c) => (
                    <article key={c.cluster} className="rounded-lg border border-white/10 bg-black/30 px-3 py-2 space-y-1">
                      <h3 className="text-xs text-white font-medium">{c.cluster}</h3>
                      <p className="text-[10px] text-cyan-200/80 font-mono">
                        {(Array.isArray(c.vendors) ? c.vendors : []).join(' · ')}
                      </p>
                      <p className="text-[10px] text-[var(--text-muted)]">{c.owns}</p>
                      <p className="text-[10px] text-amber-200/80">{c.lacks}</p>
                      {c.weissman_posture ? (
                        <p className="text-[10px] text-emerald-300/90">{c.weissman_posture}</p>
                      ) : null}
                    </article>
                  ))}
                </div>
              </section>
            )}
          </>
        )}
      </div>
    </PageShell>
  )
}
