import React, { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { strategicEnginesNeedingDedicatedPage } from '../lib/strategicEngineProgram'
import { ENGINES_BY_ID } from '../lib/enginesRegistry'

const STATUS_LABELS = {
  planned_wave_1: 'Planned Wave 1',
  planned_wave_2: 'Planned Wave 2',
  implemented_top_tier: 'Implemented (Top-Tier)',
}

const STATUS_COLOR = {
  planned_wave_1: 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10',
  planned_wave_2: 'text-amber-300 border-amber-500/40 bg-amber-500/10',
  implemented_top_tier: 'text-cyan-300 border-cyan-500/40 bg-cyan-500/10',
}

export default function StrategicEngineProgram() {
  const rows = useMemo(() => strategicEnginesNeedingDedicatedPage(), [])

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
          <Link to="/engines" className="text-white/40 hover:text-white/70 text-xs font-mono">Back to Engine Matrix</Link>
          <span className="text-white/20 text-xs">|</span>
          <Link to="/engines/top-tier" className="text-cyan-400/70 hover:text-cyan-300 text-xs font-mono">Top-Tier Hub</Link>
          <span className="text-white/20 text-xs">|</span>
          <h1 className="text-sm font-bold tracking-tight text-white">Strategic Dedicated Engine Program</h1>
          <span className="text-[10px] font-mono text-white/35 uppercase tracking-widest">{rows.length} prioritized engines</span>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <article className="rounded-xl border border-white/10 bg-black/40 p-4">
            <div className="text-[11px] text-white/60">P0 Critical</div>
            <div className="text-2xl font-semibold text-emerald-300">{byPriority.p0.length}</div>
            <p className="text-xs text-white/50">Immediate business workflows, executive visibility, and operational SLAs.</p>
          </article>
          <article className="rounded-xl border border-white/10 bg-black/40 p-4">
            <div className="text-[11px] text-white/60">P1 Strategic</div>
            <div className="text-2xl font-semibold text-amber-300">{byPriority.p1.length}</div>
            <p className="text-xs text-white/50">Important specialist programs that follow once P0 standardizes delivery.</p>
          </article>
          <article className="rounded-xl border border-white/10 bg-black/40 p-4">
            <div className="text-[11px] text-white/60">Execution Rule</div>
            <div className="text-sm font-semibold text-white">Engine-by-engine rollout</div>
            <p className="text-xs text-white/50">Each engine gets dedicated run controls, history, live evidence, and exports before moving to the next one.</p>
          </article>
        </section>

        <section className="rounded-2xl border border-white/10 bg-black/45 p-5">
          <h2 className="text-sm font-semibold text-white mb-4">Priority Matrix</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-white/50 border-b border-white/10">
                  <th className="py-2 pr-3">Engine</th>
                  <th className="py-2 pr-3">Priority</th>
                  <th className="py-2 pr-3">Status</th>
                  <th className="py-2 pr-3">Business Reason</th>
                  <th className="py-2">Action</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const reg = ENGINES_BY_ID[row.id]
                  const label = reg?.label || row.id
                  return (
                    <tr key={row.id} className="border-b border-white/5">
                      <td className="py-3 pr-3">
                        <div className="text-white font-medium">{label}</div>
                        <div className="text-[11px] font-mono text-white/40">{row.id}</div>
                      </td>
                      <td className="py-3 pr-3">
                        <span className="px-2 py-0.5 rounded border border-white/20 text-[11px] font-mono text-white/70">{row.priority}</span>
                      </td>
                      <td className="py-3 pr-3">
                        <span className={`px-2 py-0.5 rounded border text-[11px] font-mono ${STATUS_COLOR[row.status] || 'text-white/70 border-white/20 bg-white/10'}`}>
                          {STATUS_LABELS[row.status] || row.status}
                        </span>
                      </td>
                      <td className="py-3 pr-3 text-white/60 text-xs">{row.reason}</td>
                      <td className="py-3">
                        <Link
                          to={row.route}
                          className="px-2 py-1 rounded border border-cyan-500/40 text-cyan-300 text-xs font-mono hover:bg-cyan-500/10"
                        >
                          Open Page
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
