import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Search, Map, Rocket, Layers } from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { SkeletonTable } from '../components/ui/Skeleton'
import { strategicEnginesNeedingDedicatedPage } from '../lib/strategicEngineProgram'
import { ENGINES_BY_ID } from '../lib/enginesRegistry'
import { useProductionEngines } from '../lib/useProductionEngines'

const STATUS_KEY = {
  planned_wave_1: 'pages.strategicEngineProgram.status_planned_wave_1',
  planned_wave_2: 'pages.strategicEngineProgram.status_planned_wave_2',
  implemented_top_tier: 'pages.strategicEngineProgram.status_implemented_top_tier',
}

const STATUS_COLOR = {
  planned_wave_1: 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10',
  planned_wave_2: 'text-amber-300 border-amber-500/40 bg-amber-500/10',
  implemented_top_tier: 'text-cyan-300 border-cyan-500/40 bg-cyan-500/10',
}

export default function StrategicEngineProgram() {
  const { t } = useTranslation()
  const rows = useMemo(() => strategicEnginesNeedingDedicatedPage(), [])
  const { isProduction, loading: productionLoading, productionCount } = useProductionEngines()
  const [search, setSearch] = useState('')
  const [priorityFilter, setPriorityFilter] = useState('all')

  const byPriority = useMemo(() => {
    const p0 = rows.filter((r) => r.priority === 'P0')
    const p1 = rows.filter((r) => r.priority === 'P1')
    return { p0, p1 }
  }, [rows])

  const liveInProgram = useMemo(
    () => rows.filter((r) => isProduction(r.id)).length,
    [rows, isProduction],
  )

  const filteredRows = useMemo(() => {
    const term = search.trim().toLowerCase()
    return rows.filter((row) => {
      if (priorityFilter !== 'all' && row.priority !== priorityFilter) return false
      if (!term) return true
      const reg = ENGINES_BY_ID[row.id]
      const label = (reg?.label || row.id).toLowerCase()
      return (
        label.includes(term)
        || row.id.toLowerCase().includes(term)
        || String(row.reason || '').toLowerCase().includes(term)
      )
    })
  }, [rows, search, priorityFilter])

  const listFindings = useMemo(() => filteredRows.map((row) => {
    const reg = ENGINES_BY_ID[row.id]
    return {
      id: row.id,
      severity: 'info',
      category: 'roadmap',
      roadmap: true,
      title: reg?.label || row.id,
      type: row.priority || 'engine',
      description: row.reason || '',
    }
  }), [filteredRows])

  const { exportCsv, filteredFindings } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-strategic-engines',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description}`,
  })

  return (
    <PageShell
      title={t('pages.strategicEngineProgram.title')}
      subtitle={t('pages.strategicEngineProgram.subtitle')}
      badge={t('pages.strategicEngineProgram.badge')}
      badgeColor="#34d399"
      actions={(
        <div className="flex items-center gap-2 flex-wrap">
          <Link
            to="/engines"
            className="px-3 py-1.5 rounded-lg border border-[var(--border-default)] text-xs font-mono text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] hover:bg-[var(--row-hover-bg)] transition-colors"
          >
            {t('pages.strategicEngineProgram.back_matrix')}
          </Link>
          <Link
            to="/engines/top-tier"
            className="px-3 py-1.5 rounded-lg border border-cyan-500/30 text-xs font-mono text-cyan-300/80 hover:bg-cyan-500/10 transition-colors"
          >
            {t('pages.strategicEngineProgram.top_tier_hub')}
          </Link>
          <ShellScanActions
            onRefresh={() => window.location.reload()}
            onExport={exportCsv}
            refreshLoading={productionLoading}
            exportDisabled={!filteredFindings.length}
          />
        </div>
      )}
    >
      <div className="space-y-6">
        <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/20 px-4 py-3 flex items-start gap-3">
          <Map className="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
          <p className="text-xs text-emerald-100/70 leading-relaxed">
            {t('pages.strategicEngineProgram.roadmap_notice')}
          </p>
        </div>

        <section className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <article className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
            <div className="text-[11px] text-[var(--text-tertiary)]">{t('pages.strategicEngineProgram.prioritized_label')}</div>
            <div className="text-2xl font-semibold text-white">{rows.length}</div>
            <p className="text-xs text-[var(--text-tertiary)]">{t('pages.strategicEngineProgram.prioritized_count', { count: rows.length })}</p>
          </article>
          <article className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4">
            <div className="text-[11px] text-emerald-300/70">{t('pages.strategicEngineProgram.p0_label')}</div>
            <div className="text-2xl font-semibold text-emerald-300">{byPriority.p0.length}</div>
            <p className="text-xs text-[var(--text-tertiary)]">{t('pages.strategicEngineProgram.p0_desc')}</p>
          </article>
          <article className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4">
            <div className="text-[11px] text-amber-300/70">{t('pages.strategicEngineProgram.p1_label')}</div>
            <div className="text-2xl font-semibold text-amber-300">{byPriority.p1.length}</div>
            <p className="text-xs text-[var(--text-tertiary)]">{t('pages.strategicEngineProgram.p1_desc')}</p>
          </article>
          <article className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4">
            <div className="flex items-center gap-2 text-[11px] text-cyan-300/70">
              <Rocket className="w-3.5 h-3.5" />
              {t('pages.strategicEngineProgram.live_production')}
            </div>
            <div className="text-2xl font-semibold text-cyan-300">
              {productionLoading ? '—' : liveInProgram}
            </div>
            <p className="text-xs text-[var(--text-tertiary)]">
              {productionLoading
                ? t('pages.strategicEngineProgram.loading_production')
                : t('pages.strategicEngineProgram.live_production_desc', { total: productionCount, program: rows.length })}
            </p>
          </article>
        </section>

        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-disabled)]" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={t('pages.strategicEngineProgram.search_placeholder')}
              className="w-full pl-10 pr-4 py-2 rounded-xl bg-[var(--bg-2)] border border-[var(--border-default)] text-sm text-white placeholder-white/25 focus:outline-none focus:border-cyan-500/40"
            />
          </div>
          <div className="flex items-center gap-1 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg p-1">
            {['all', 'P0', 'P1'].map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => setPriorityFilter(p)}
                className={`px-3 py-1.5 rounded-md text-xs font-mono transition-all ${
                  priorityFilter === p
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                    : 'text-[var(--text-muted)] hover:text-[var(--text-secondary)] hover:bg-[var(--row-hover-bg)]'
                }`}
              >
                {p === 'all' ? t('pages.strategicEngineProgram.filter_all') : p}
              </button>
            ))}
          </div>
        </div>

        <section className="rounded-2xl border border-[var(--border-default)] bg-[var(--table-surface)] p-5">
          <div className="flex items-center gap-2 mb-4">
            <Layers className="w-4 h-4 text-[var(--text-muted)]" />
            <h2 className="text-sm font-semibold text-white">{t('pages.strategicEngineProgram.priority_matrix')}</h2>
            <span className="text-[10px] font-mono text-[var(--text-muted)] ml-auto">
              {t('pages.strategicEngineProgram.showing_count', { count: filteredRows.length, total: rows.length })}
            </span>
          </div>

          {productionLoading ? (
            <SkeletonTable rows={6} cols={5} />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-[var(--text-tertiary)] border-b border-[var(--border-default)]">
                    <th className="py-2 pr-3">{t('pages.strategicEngineProgram.col_engine')}</th>
                    <th className="py-2 pr-3">{t('pages.strategicEngineProgram.col_priority')}</th>
                    <th className="py-2 pr-3">{t('pages.strategicEngineProgram.col_status')}</th>
                    <th className="py-2 pr-3">{t('pages.strategicEngineProgram.col_reason')}</th>
                    <th className="py-2">{t('pages.strategicEngineProgram.col_action')}</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRows.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-8 text-center text-[var(--text-muted)] text-xs font-mono">
                        {t('pages.strategicEngineProgram.no_results')}
                      </td>
                    </tr>
                  ) : (
                    filteredRows.map((row) => {
                      const reg = ENGINES_BY_ID[row.id]
                      const label = reg?.label || row.id
                      const live = isProduction(row.id)
                      return (
                        <tr key={row.id} className="border-b border-[var(--border-subtle)]">
                          <td className="py-3 pr-3">
                            <div className="flex items-center gap-2 flex-wrap">
                              <Link to={`/engines/${row.id}`} className="text-white font-medium hover:text-cyan-300 transition-colors">
                                {label}
                              </Link>
                              <span className={`px-2 py-0.5 rounded border text-[10px] font-mono uppercase tracking-wider ${
                                live
                                  ? 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10'
                                  : 'text-[var(--text-muted)] border-[var(--border-strong)] bg-[var(--row-hover-bg)]'
                              }`}>
                                {live ? t('pages.strategicEngineProgram.production') : t('pages.strategicEngineProgram.catalog')}
                              </span>
                            </div>
                            <div className="text-[11px] font-mono text-[var(--text-muted)]">{row.id}</div>
                          </td>
                          <td className="py-3 pr-3">
                            <span className="px-2 py-0.5 rounded border border-[var(--border-strong)] text-[11px] font-mono text-[var(--text-secondary)]">{row.priority}</span>
                          </td>
                          <td className="py-3 pr-3">
                            <span className={`px-2 py-0.5 rounded border text-[11px] font-mono ${STATUS_COLOR[row.status] || 'text-[var(--text-secondary)] border-[var(--border-strong)] bg-[var(--row-hover-bg)]'}`}>
                              {STATUS_KEY[row.status] ? t(STATUS_KEY[row.status]) : row.status}
                            </span>
                          </td>
                          <td className="py-3 pr-3 text-[var(--text-tertiary)] text-xs max-w-xs">{row.reason}</td>
                          <td className="py-3">
                            <Link
                              to={row.route}
                              className="px-2 py-1 rounded border border-cyan-500/40 text-cyan-300 text-xs font-mono hover:bg-cyan-500/10"
                            >
                              {t('pages.strategicEngineProgram.open_page')}
                            </Link>
                          </td>
                        </tr>
                      )
                    })
                  )}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
          <div className="text-[11px] text-[var(--text-tertiary)]">{t('pages.strategicEngineProgram.execution_rule')}</div>
          <div className="text-sm font-semibold text-white mt-1">{t('pages.strategicEngineProgram.execution_title')}</div>
          <p className="text-xs text-[var(--text-tertiary)] mt-1">{t('pages.strategicEngineProgram.execution_desc')}</p>
        </section>
      </div>
    </PageShell>
  )
}
