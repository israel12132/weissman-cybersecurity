/**
 * Scan → Finding Truth Spine
 *
 * Live GET /api/scan-finding-spine joins tenant scan jobs with persisted
 * vulnerabilities so operators see whether attack/scan/finding work is
 * evidence-backed, live-verified, MITRE-mapped, or stuck. No fabricated rows.
 * Route: /scan-finding-spine
 */
import { useState, useCallback, useEffect, useMemo } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { Activity, Search } from 'lucide-react'
import PageShell from './PageShell'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import DataTable from '../components/ui/DataTable'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { apiFetch } from '../utils/apiFetch'
import { downloadCsv } from '../lib/exportFindingsCsv'
import { filterEngines, filterGaps, spineCsvRows, SPINE_CSV_HEADER } from '../lib/scanFindingSpine'

const NS = 'pages.scanFindingSpine'
const columnHelper = createColumnHelper()

function gapColor(severity) {
  if (severity === 'critical') return '#f43f5e'
  if (severity === 'high') return '#f97316'
  return '#94a3b8'
}

export default function ScanFindingSpine() {
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const d = await apiFetch('/api/scan-finding-spine')
      if (d?.ok === false) throw new Error(d.detail || t(`${NS}.load_failed`))
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

  const kpis = data?.kpis || {}
  const engines = useMemo(() => filterEngines(data?.engines || [], search), [data, search])
  const gaps = useMemo(() => filterGaps(data?.gaps || [], search), [data, search])
  const scans = data?.scans || []

  const columns = useMemo(
    () => [
      columnHelper.accessor((r) => r.source || '', {
        id: 'source',
        header: t(`${NS}.col_engine`),
        cell: (ctx) => (
          <span className="font-mono text-[11px] text-cyan-200/90">{ctx.getValue() || '—'}</span>
        ),
      }),
      columnHelper.accessor((r) => r.reality_kind || '', {
        id: 'kind',
        header: t(`${NS}.col_reality`),
        cell: (ctx) => (
          <span className="text-[10px] font-mono uppercase text-[var(--text-muted)]">{ctx.getValue()}</span>
        ),
      }),
      columnHelper.accessor((r) => r.findings || 0, {
        id: 'findings',
        header: t(`${NS}.col_findings`),
      }),
      columnHelper.accessor((r) => r.evidence || 0, {
        id: 'evidence',
        header: t(`${NS}.col_evidence`),
      }),
      columnHelper.accessor((r) => r.proven || 0, {
        id: 'proven',
        header: t(`${NS}.col_proven`),
      }),
      columnHelper.accessor((r) => r.unverified_critical || 0, {
        id: 'unverified',
        header: t(`${NS}.col_unverified`),
        cell: (ctx) => (
          <span className={ctx.getValue() > 0 ? 'text-rose-300 font-mono' : 'text-[var(--text-muted)] font-mono'}>
            {ctx.getValue()}
          </span>
        ),
      }),
      columnHelper.accessor((r) => r.mitre || 0, {
        id: 'mitre',
        header: t(`${NS}.col_mitre`),
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
      icon={<Activity className="w-5 h-5" />}
      actions={
        <ShellScanActions
          onRefresh={load}
          onExport={() => downloadCsv(spineCsvRows(data || {}), SPINE_CSV_HEADER, 'weissman-scan-finding-spine')}
          refreshLoading={loading}
          exportDisabled={!data}
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
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_findings`)} value={kpis.findings_total || 0} accent="#22d3ee" />
              <ExecutiveWidget label={t(`${NS}.kpi_evidence`)} value={kpis.evidence || 0} accent="#4ade80" />
              <ExecutiveWidget label={t(`${NS}.kpi_unverified`)} value={kpis.unverified_critical || 0} accent="#f43f5e" />
              <ExecutiveWidget label={t(`${NS}.kpi_scans`)} value={kpis.scans_running || 0} accent="#facc15" />
            </div>

            <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono">
              <Link to="/findings" className="text-cyan-400/80 hover:text-cyan-300">{t(`${NS}.link_findings`)}</Link>
              <span className="text-[var(--text-disabled)]">·</span>
              <Link to="/jobs" className="text-cyan-400/80 hover:text-cyan-300">{t(`${NS}.link_jobs`)}</Link>
              <span className="text-[var(--text-disabled)]">·</span>
              <Link to="/attack-paths" className="text-cyan-400/80 hover:text-cyan-300">{t(`${NS}.link_attack_paths`)}</Link>
              <span className="text-[var(--text-disabled)]">·</span>
              <Link to="/kill-chain" className="text-cyan-400/80 hover:text-cyan-300">{t(`${NS}.link_kill_chain`)}</Link>
            </div>

            <div className="relative max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-disabled)] pointer-events-none" />
              <input
                type="search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                aria-label={t(`${NS}.search_placeholder`)}
                placeholder={t(`${NS}.search_placeholder`)}
                className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-xl pl-10 pr-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500/40"
              />
            </div>

            <section className="space-y-3">
              <h2 className="text-sm font-semibold tracking-wide text-[var(--text-secondary)]">{t(`${NS}.gaps_heading`)}</h2>
              {gaps.length === 0 ? (
                <EmptyState icon="shield" title={t(`${NS}.no_gaps_title`)} body={t(`${NS}.no_gaps_body`)} />
              ) : (
                <ul className="space-y-2">
                  {gaps.map((g) => (
                    <li
                      key={g.id}
                      className="rounded-xl border px-4 py-3 text-sm"
                      style={{ borderColor: `${gapColor(g.severity)}40`, background: `${gapColor(g.severity)}12` }}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <span className="font-mono text-[11px] uppercase tracking-wider" style={{ color: gapColor(g.severity) }}>
                          {g.id} · {g.severity}
                        </span>
                        <span className="font-mono text-[var(--text-primary)]">{g.count}</span>
                      </div>
                      <p className="mt-1 text-[var(--text-tertiary)]">{g.detail}</p>
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <section className="space-y-3">
              <h2 className="text-sm font-semibold tracking-wide text-[var(--text-secondary)]">{t(`${NS}.engines_heading`)}</h2>
              {engines.length === 0 ? (
                <EmptyState icon="inbox" title={t(`${NS}.empty_engines_title`)} body={t(`${NS}.empty_engines_body`)} />
              ) : (
                <DataTable id="scan-finding-spine-engines" columns={columns} data={engines} />
              )}
            </section>

            <section className="space-y-3">
              <h2 className="text-sm font-semibold tracking-wide text-[var(--text-secondary)]">{t(`${NS}.scans_heading`)}</h2>
              {scans.length === 0 ? (
                <EmptyState icon="radar" title={t(`${NS}.empty_scans_title`)} body={t(`${NS}.empty_scans_body`)} />
              ) : (
                <ul className="space-y-2 font-mono text-[11px]">
                  {scans.slice(0, 12).map((j) => (
                    <li key={j.id} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-[var(--border-default)] bg-[var(--bg-3)] px-3 py-2">
                      <span className="text-cyan-200/90">{j.kind}</span>
                      <span className={j.stuck ? 'text-rose-300' : 'text-[var(--text-muted)]'}>{j.status}{j.stuck ? ` · ${t(`${NS}.stuck`)}` : ''}</span>
                      <span className="text-[var(--text-disabled)] truncate max-w-[240px]">{j.target || j.id}</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </>
        )}
      </div>
    </PageShell>
  )
}
