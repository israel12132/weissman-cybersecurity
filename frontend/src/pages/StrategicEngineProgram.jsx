import React, { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
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
  const { isProduction, loading: productionLoading } = useProductionEngines()

  const byPriority = useMemo(() => {
    const p0 = rows.filter((r) => r.priority === 'P0')
    const p1 = rows.filter((r) => r.priority === 'P1')
    return { p0, p1 }
  }, [rows])

  return (
    <div
      className="min-h-[100dvh] text-slate-100"
      style={{ background: 'radial-gradient(ellipse 120% 80% at 50% 0%, #10201a 0%, #04110f 55%, #000 100%)' }}
    >
      <header className="sticky top-0 z-20 border-b border-white/10 bg-black/50 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 py-3 flex flex-wrap items-center gap-3">
          <Link to="/engines" className="text-white/40 hover:text-white/70 text-xs font-mono">{t('pages.strategicEngineProgram.back_matrix')}</Link>
          <span className="text-white/20 text-xs">|</span>
          <Link to="/engines/top-tier" className="text-cyan-400/70 hover:text-cyan-300 text-xs font-mono">{t('pages.strategicEngineProgram.top_tier_hub')}</Link>
          <span className="text-white/20 text-xs">|</span>
          <h1 className="text-sm font-bold tracking-tight text-white">{t('pages.strategicEngineProgram.title')}</h1>
          <span className="text-[10px] font-mono text-white/35 uppercase tracking-widest">{t('pages.strategicEngineProgram.prioritized_count', { count: rows.length })}</span>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <article className="rounded-xl border border-white/10 bg-black/40 p-4">
            <div className="text-[11px] text-white/60">{t('pages.strategicEngineProgram.p0_label')}</div>
            <div className="text-2xl font-semibold text-emerald-300">{byPriority.p0.length}</div>
            <p className="text-xs text-white/50">{t('pages.strategicEngineProgram.p0_desc')}</p>
          </article>
          <article className="rounded-xl border border-white/10 bg-black/40 p-4">
            <div className="text-[11px] text-white/60">{t('pages.strategicEngineProgram.p1_label')}</div>
            <div className="text-2xl font-semibold text-amber-300">{byPriority.p1.length}</div>
            <p className="text-xs text-white/50">{t('pages.strategicEngineProgram.p1_desc')}</p>
          </article>
          <article className="rounded-xl border border-white/10 bg-black/40 p-4">
            <div className="text-[11px] text-white/60">{t('pages.strategicEngineProgram.execution_rule')}</div>
            <div className="text-sm font-semibold text-white">{t('pages.strategicEngineProgram.execution_title')}</div>
            <p className="text-xs text-white/50">{t('pages.strategicEngineProgram.execution_desc')}</p>
          </article>
        </section>

        <section className="rounded-2xl border border-white/10 bg-black/45 p-5">
          <h2 className="text-sm font-semibold text-white mb-4">{t('pages.strategicEngineProgram.priority_matrix')}</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-white/50 border-b border-white/10">
                  <th className="py-2 pr-3">{t('pages.strategicEngineProgram.col_engine')}</th>
                  <th className="py-2 pr-3">{t('pages.strategicEngineProgram.col_priority')}</th>
                  <th className="py-2 pr-3">{t('pages.strategicEngineProgram.col_status')}</th>
                  <th className="py-2 pr-3">{t('pages.strategicEngineProgram.col_reason')}</th>
                  <th className="py-2">{t('pages.strategicEngineProgram.col_action')}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const reg = ENGINES_BY_ID[row.id]
                  const label = reg?.label || row.id
                  const live = isProduction(row.id)
                  return (
                    <tr key={row.id} className="border-b border-white/5">
                      <td className="py-3 pr-3">
                        <div className="flex items-center gap-2 flex-wrap">
                          <Link to={`/engines/${row.id}`} className="text-white font-medium hover:text-cyan-300 transition-colors">
                            {label}
                          </Link>
                          {!productionLoading && (
                            <span className={`px-2 py-0.5 rounded border text-[10px] font-mono uppercase tracking-wider ${
                              live
                                ? 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10'
                                : 'text-white/45 border-white/15 bg-white/5'
                            }`}>
                              {live ? t('pages.strategicEngineProgram.production') : t('pages.strategicEngineProgram.catalog')}
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] font-mono text-white/40">{row.id}</div>
                      </td>
                      <td className="py-3 pr-3">
                        <span className="px-2 py-0.5 rounded border border-white/20 text-[11px] font-mono text-white/70">{row.priority}</span>
                      </td>
                      <td className="py-3 pr-3">
                        <span className={`px-2 py-0.5 rounded border text-[11px] font-mono ${STATUS_COLOR[row.status] || 'text-white/70 border-white/20 bg-white/10'}`}>
                          {STATUS_KEY[row.status] ? t(STATUS_KEY[row.status]) : row.status}
                        </span>
                      </td>
                      <td className="py-3 pr-3 text-white/60 text-xs">{row.reason}</td>
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
                })}
              </tbody>
            </table>
          </div>
        </section>
      </main>
    </div>
  )
}
