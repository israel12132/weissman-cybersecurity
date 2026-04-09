import React from 'react'

export default function GodModeDiscoveryStrip({ discovery, godErr }) {
  if (godErr) {
    return (
      <div className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-[11px] font-mono text-rose-200">
        Discovery snapshot: {godErr}
      </div>
    )
  }
  if (!discovery || typeof discovery !== 'object') {
    return (
      <div className="rounded-xl border border-white/10 bg-slate-950/60 px-4 py-3 text-[11px] font-mono text-slate-500">
        No discovery phase snapshot yet — runs when orchestrator completes ASM-path discovery for a client.
      </div>
    )
  }
  const name = discovery.client_name || '—'
  const target = discovery.primary_target || '—'
  const tl = discovery.target_list_count
  const dp = discovery.discovered_paths_count
  const at = discovery.updated_at || '—'

  return (
    <div
      className="rounded-xl border border-cyan-500/25 bg-gradient-to-r from-cyan-950/40 via-slate-950/80 to-violet-950/30 px-5 py-4 shadow-[inset_0_1px_0_rgba(34,211,238,0.12)]"
      style={{
        boxShadow: '0 0 48px rgba(34, 211, 238, 0.06), inset 0 1px 0 rgba(255,255,255,0.04)',
      }}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-[9px] font-mono uppercase tracking-[0.35em] text-cyan-400/90 mb-1">
            Tenant discovery · last ASM merge
          </p>
          <p className="text-sm font-semibold text-white tracking-tight">
            <span className="text-cyan-200/90">{name}</span>
            <span className="text-slate-600 mx-2">·</span>
            <span className="font-mono text-amber-200/90 break-all">{target}</span>
          </p>
        </div>
        <div className="flex flex-wrap gap-4 text-right">
          <div>
            <p className="text-[9px] uppercase text-slate-500 font-mono">target_list</p>
            <p className="text-xl font-mono text-white tabular-nums">{tl != null ? tl : '—'}</p>
          </div>
          <div>
            <p className="text-[9px] uppercase text-slate-500 font-mono">discovered_paths</p>
            <p className="text-xl font-mono text-emerald-300/90 tabular-nums">{dp != null ? dp : '—'}</p>
          </div>
          <div className="text-left min-w-[140px]">
            <p className="text-[9px] uppercase text-slate-500 font-mono">updated</p>
            <p className="text-[10px] font-mono text-slate-400">{at}</p>
          </div>
        </div>
      </div>
    </div>
  )
}
