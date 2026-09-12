/**
 * Competitive Win Room — live market-readiness vs prevention-fabric bake-off.
 * Route: /win-room
 *
 * Data from GET /api/market-readiness (authenticated). Catalog counts come from
 * PRODUCTION_ENGINE_IDS. Finding counts come from the tenant DB. Nothing is a
 * simulated Palo Alto score.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Swords, Search } from 'lucide-react'
import { createColumnHelper } from '@tanstack/react-table'
import PageShell from './PageShell'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import DataTable from '../components/ui/DataTable'
import EmptyState from '../components/ui/EmptyState'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { apiFetch } from '../utils/apiFetch'
import { exportRowsCsv, rowMatchesQuery } from '../lib/pageExport'

const NS = 'pages.competitiveWinRoom'
const columnHelper = createColumnHelper()

export const WIN_ROOM_CSV_HEADER = ['kind', 'id', 'title', 'detail', 'count']

export function winRoomRows(data) {
  const rows = []
  for (const g of Array.isArray(data?.honest_gaps) ? data.honest_gaps : []) {
    rows.push(['gap', g.id ?? '', g.severity ?? '', g.detail ?? '', ''])
  }
  for (const lane of Array.isArray(data?.moat?.lanes) ? data.moat.lanes : []) {
    rows.push([
      'lane',
      lane.id ?? '',
      lane.title ?? '',
      lane.beats ?? '',
      String(lane.live_engine_count ?? 0),
    ])
  }
  for (const f of Array.isArray(data?.live_findings) ? data.live_findings : []) {
    rows.push(['finding', f.source ?? '', '', '', String(f.count ?? 0)])
  }
  return rows
}

export default function CompetitiveWinRoom() {
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [searchQuery, setSearchQuery] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const d = await apiFetch('/api/market-readiness')
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

  const gaps = Array.isArray(data?.honest_gaps) ? data.honest_gaps : []
  const lanes = Array.isArray(data?.moat?.lanes) ? data.moat.lanes : []
  const findings = Array.isArray(data?.live_findings) ? data.live_findings : []
  const fabric = Array.isArray(data?.prevention_fabric_engines) ? data.prevention_fabric_engines : []

  const filteredLanes = useMemo(() => {
    return lanes.filter((lane) =>
      rowMatchesQuery(searchQuery, [
        lane.id,
        lane.title,
        lane.beats,
        lane.live_engine_count,
        lane.covered ? 'live' : 'gap',
      ]),
    )
  }, [lanes, searchQuery])

  const exportCsv = useCallback(() => {
    exportRowsCsv(WIN_ROOM_CSV_HEADER, winRoomRows(data), 'weissman-win-room')
  }, [data])

  const columns = useMemo(
    () => [
      columnHelper.accessor('id', { header: t(`${NS}.col_id`) }),
      columnHelper.accessor('title', { header: t(`${NS}.col_title`) }),
      columnHelper.accessor('live_engine_count', { header: t(`${NS}.col_engines`) }),
      columnHelper.accessor('beats', { header: t(`${NS}.col_beats`) }),
    ],
    [t],
  )

  const findingsKnown = Array.isArray(data?.live_findings)
  const liveFindingTotal = findingsKnown
    ? findings.reduce((n, f) => n + Number(f.count || 0), 0)
    : null

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      icon={<Swords />}
      actions={(
        <ShellScanActions
          onRefresh={load}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!data}
        />
      )}
    >
      <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>
      {loading ? (
        <SkeletonWidgetGrid count={4} />
      ) : error ? (
        <EmptyState title={t(`${NS}.load_failed`)} body={error} />
      ) : (
        <div className="space-y-4">
          <p className="text-sm text-white/80 leading-relaxed" data-testid="win-room-thesis">
            {data?.thesis}
          </p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <ExecutiveWidget label={t(`${NS}.kpi_engines`)} value={data?.engines_total ?? '—'} />
            <ExecutiveWidget label={t(`${NS}.kpi_fabric`)} value={fabric.length} />
            <ExecutiveWidget label={t(`${NS}.kpi_lanes`)} value={`${data?.moat?.lanes_covered ?? 0}/${data?.moat?.lanes_total ?? 0}`} />
            <ExecutiveWidget
              label={t(`${NS}.kpi_findings`)}
              value={findingsKnown ? liveFindingTotal : t(`${NS}.findings_unknown`)}
            />
          </div>
          {data?.live_findings_error ? (
            <EmptyState
              title={t(`${NS}.findings_unavailable`)}
              body={String(data.live_findings_error)}
            />
          ) : null}
          <div className="rounded-lg border border-amber-500/30 bg-amber-950/20 p-3 text-xs text-amber-100/90" data-testid="win-room-category">
            {t(`${NS}.not_ngfw`)}
          </div>
          <div>
            <h2 className="text-sm font-semibold text-white mb-2">{t(`${NS}.gaps_heading`)}</h2>
            {!gaps.length ? (
              <EmptyState title={t(`${NS}.empty_gaps`)} body={t(`${NS}.empty_gaps_body`)} />
            ) : (
              <ul className="space-y-2">
                {gaps.map((g) => (
                  <li key={g.id} className="rounded-lg border border-white/10 p-3" data-testid="win-room-gap">
                    <div className="text-[10px] font-mono uppercase text-amber-300">{g.id} · {g.severity}</div>
                    <div className="text-sm text-white mt-1">{g.detail}</div>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <div className="relative max-w-sm">
            <Search className="w-3.5 h-3.5 text-white/30 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={t(`${NS}.search_placeholder`)}
              aria-label={t(`${NS}.search_placeholder`)}
              className="w-full pl-8 pr-3 py-2 rounded-lg text-sm bg-black/40 border border-white/10 text-white"
            />
          </div>
          <h2 className="text-sm font-semibold text-white">{t(`${NS}.lanes_heading`)}</h2>
          {!filteredLanes.length ? (
            <EmptyState title={t(`${NS}.empty_lanes`)} body={t(`${NS}.empty_lanes_body`)} />
          ) : (
            <DataTable columns={columns} data={filteredLanes} />
          )}
        </div>
      )}
    </PageShell>
  )
}
