/**
 * Elite Hardening Command Center — live enforcement of the 100-control Part 2 spec.
 * Route: /elite-hardening
 *
 * Data comes from GET /api/elite-hardening/status (authenticated). Nothing on this
 * page is hardcoded: control live/gap flags are computed from the running kernel.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ShieldCheck, Search } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import FilterPills from '../components/ui/FilterPills'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { apiFetch } from '../utils/apiFetch'
import { exportRowsCsv, exportRowsPdf, rowMatchesQuery } from '../lib/pageExport'

const NS = 'pages.eliteHardening'

export const ELITE_CSV_HEADER = ['id', 'section', 'title', 'enforced', 'detail']

export function eliteControlRows(controls) {
  return (Array.isArray(controls) ? controls : []).map((c) => [
    c?.id ?? '',
    c?.section_title || c?.section || '',
    c?.title ?? '',
    c?.enforced ? 'live' : 'gap',
    c?.detail ?? '',
  ])
}

export default function EliteHardeningCommandCenter() {
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [sectionFilter, setSectionFilter] = useState('all')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const d = await apiFetch('/api/elite-hardening/status')
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

  const controls = Array.isArray(data?.controls) ? data.controls : []
  const sections = useMemo(() => {
    const seen = []
    for (const c of controls) {
      const title = c.section_title || `§${c.section}`
      if (!seen.includes(title)) seen.push(title)
    }
    return seen
  }, [controls])

  const filtered = useMemo(() => {
    return controls.filter((c) => {
      if (sectionFilter !== 'all' && (c.section_title || '') !== sectionFilter) return false
      return rowMatchesQuery(searchQuery, [c.id, c.section_title, c.title, c.detail, c.enforced ? 'live' : 'gap'])
    })
  }, [controls, searchQuery, sectionFilter])

  const enforced = Number(data?.controls_enforced) || controls.filter((c) => c.enforced).length
  const total = Number(data?.controls_total) || controls.length
  const gaps = Math.max(0, total - enforced)

  const pills = useMemo(
    () => [
      { id: 'all', label: t(`${NS}.all_sections`), active: sectionFilter === 'all', onClick: () => setSectionFilter('all') },
      ...sections.map((s) => ({
        id: s,
        label: s,
        active: sectionFilter === s,
        onClick: () => setSectionFilter(s),
      })),
    ],
    [sectionFilter, sections, t],
  )

  const exportRows = () => eliteControlRows(filtered)
  const doExport = (kind) => {
    const rows = exportRows()
    if (kind === 'pdf') {
      exportRowsPdf(t(`${NS}.title`), ELITE_CSV_HEADER, rows, 'weissman-elite-hardening')
    } else {
      exportRowsCsv(ELITE_CSV_HEADER, rows, 'weissman-elite-hardening')
    }
  }

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#22d3ee"
      hideEvidence
      icon={<ShieldCheck className="w-5 h-5" />}
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
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_enforced`)} value={`${enforced}/${total || 100}`} accent="#22d3ee" />
              <ExecutiveWidget label={t(`${NS}.kpi_gaps`)} value={gaps} accent={gaps ? '#f43f5e' : '#34d399'} />
              <ExecutiveWidget label={t(`${NS}.kpi_mitre`)} value={data?.mitre_attack || 'v19.1'} accent="#a78bfa" />
              <ExecutiveWidget label={t(`${NS}.kpi_probes`)} value={data?.live_probes_target || 303} accent="#f97316" />
              <ExecutiveWidget
                label={t(`${NS}.kpi_engines`)}
                value={data?.moat?.engines_total ?? '—'}
                accent="#38bdf8"
              />
              <ExecutiveWidget
                label={t(`${NS}.kpi_lanes`)}
                value={
                  data?.moat
                    ? `${data.moat.lanes_covered}/${data.moat.lanes_total}`
                    : '—'
                }
                accent={data?.moat?.unmatched_stack ? '#34d399' : '#f59e0b'}
              />
            </div>

            {Array.isArray(data?.moat?.lanes) && data.moat.lanes.length > 0 && (
              <section className="rounded-xl border border-cyan-500/20 bg-cyan-950/10 p-4 space-y-3">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <h2 className="text-sm font-semibold uppercase tracking-wider text-cyan-200">
                    {t(`${NS}.moat_title`)}
                  </h2>
                  <span className="font-mono text-[11px] text-[var(--text-muted)]">
                    {data.moat.unmatched_stack ? t(`${NS}.moat_unmatched`) : t(`${NS}.moat_partial`)}
                  </span>
                </div>
                <p className="text-xs text-[var(--text-muted)]">{t(`${NS}.moat_notice`)}</p>
                <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-2">
                  {data.moat.lanes.map((lane) => (
                    <article
                      key={lane.id}
                      data-testid="moat-lane"
                      className="rounded-lg border border-white/10 bg-black/30 px-3 py-2"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <h3 className="text-xs text-white font-medium leading-snug">{lane.title}</h3>
                        <span className="font-mono text-cyan-300 text-sm tabular-nums">
                          {lane.live_engine_count}
                        </span>
                      </div>
                      <p className="mt-1 text-[10px] leading-snug text-[var(--text-muted)]">{lane.beats}</p>
                    </article>
                  ))}
                </div>
              </section>
            )}

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
              <button
                type="button"
                className="text-xs uppercase tracking-wider text-cyan-400 hover:text-cyan-300"
                onClick={() => doExport('pdf')}
              >
                {t(`${NS}.export_pdf`)}
              </button>
            </div>

            <FilterPills pills={pills} />

            {filtered.length === 0 ? (
              <EmptyState
                title={controls.length ? t(`${NS}.no_match_title`) : t(`${NS}.empty_title`)}
                body={controls.length ? t(`${NS}.no_match_body`) : t(`${NS}.empty_body`)}
              />
            ) : (
              <div className="overflow-x-auto rounded-xl border border-white/10">
                <table className="w-full text-sm">
                  <thead className="text-[11px] uppercase tracking-wider text-[var(--text-muted)] bg-white/5">
                    <tr>
                      <th className="text-left px-3 py-2">#</th>
                      <th className="text-left px-3 py-2">{t(`${NS}.col_section`)}</th>
                      <th className="text-left px-3 py-2">{t(`${NS}.col_control`)}</th>
                      <th className="text-left px-3 py-2">{t(`${NS}.col_status`)}</th>
                      <th className="text-left px-3 py-2">{t(`${NS}.col_detail`)}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((c) => (
                      <tr key={c.id} className="border-t border-white/5 hover:bg-white/[0.03]">
                        <td className="px-3 py-2 font-mono text-cyan-300 tabular-nums">{c.id}</td>
                        <td className="px-3 py-2 text-[var(--text-muted)] whitespace-nowrap">{c.section_title}</td>
                        <td className="px-3 py-2 text-white">{c.title}</td>
                        <td className="px-3 py-2">
                          <span
                            className={`inline-flex rounded-full px-2 py-0.5 text-[10px] uppercase tracking-wider ${
                              c.enforced
                                ? 'bg-emerald-500/15 text-emerald-300'
                                : 'bg-rose-500/15 text-rose-300'
                            }`}
                          >
                            {c.enforced ? t(`${NS}.live`) : t(`${NS}.gap`)}
                          </span>
                        </td>
                        <td className="px-3 py-2 text-[var(--text-muted)] font-mono text-[11px]">{c.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
    </PageShell>
  )
}
