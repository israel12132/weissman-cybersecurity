import React from 'react'

function SpinnerTiny() {
  return (
    <svg
      className="w-3.5 h-3.5 animate-spin text-emerald-300/90"
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
      aria-hidden
    >
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path
        className="opacity-90"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
      />
    </svg>
  )
}

function Cell({ engine, scanning, onTenantEngineToggle, engineToggleBusy }) {
  const tenantOn = !!engine.tenant_policy_includes
  const n = engine.clients_enabled_count ?? 0
  const tot = engine.clients_total ?? 0
  const busy = engineToggleBusy === engine.id
  const canToggle = !!onTenantEngineToggle && !busy

  return (
    <div
      className={`relative rounded-lg border px-2 py-2.5 transition-all duration-200 ${
        tenantOn
          ? 'border-emerald-500/40 bg-emerald-950/30 shadow-[inset_0_1px_0_rgba(52,211,153,0.12)]'
          : 'border-white/10 bg-black/45 hover:border-white/20'
      } ${scanning ? 'ring-1 ring-cyan-500/25' : ''}`}
    >
      {scanning && (
        <span
          className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-orange-400 animate-pulse shadow-[0_0_8px_rgba(251,146,60,0.8)]"
          title="Orchestrator scanning flag active"
        />
      )}
      <p className="text-[9px] font-mono uppercase tracking-wider text-slate-500 truncate" title={engine.id}>
        {engine.label}
      </p>
      <p className="text-[10px] font-mono text-slate-400 mt-0.5 truncate">{engine.id}</p>
      <div className="mt-2.5 flex items-center justify-between gap-2">
        <div className="flex flex-col gap-1 min-w-0">
          <span className="text-[8px] font-mono uppercase tracking-wide text-slate-600">Orchestrator policy</span>
          <button
            type="button"
            role="switch"
            aria-checked={tenantOn}
            aria-busy={busy}
            disabled={!canToggle}
            onClick={(e) => {
              e.preventDefault()
              e.stopPropagation()
              if (!canToggle) return
              onTenantEngineToggle(engine.id, !tenantOn)
            }}
            title={
              busy
                ? 'Updating system_configs.active_engines…'
                : 'Toggle engine in default-tenant active_engines (PUT /api/ceo/tenant/engines)'
            }
            className={`
              group relative flex items-center gap-2 rounded-full pl-0.5 pr-2 py-0.5 transition-all duration-200
              focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400/50 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-950
              ${tenantOn ? 'bg-emerald-500/15' : 'bg-slate-800/80'}
              ${canToggle ? 'cursor-pointer hover:bg-emerald-500/10' : 'opacity-50 cursor-not-allowed'}
            `}
          >
            <span
              className={`
                relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border transition-colors duration-200
                ${tenantOn ? 'border-emerald-400/50 bg-emerald-600/35' : 'border-white/15 bg-slate-900'}
                ${canToggle ? 'group-hover:border-emerald-300/40' : ''}
              `}
            >
              <span
                className={`
                  inline-block h-4 w-4 transform rounded-full shadow-md transition-transform duration-200
                  ${tenantOn ? 'translate-x-4 bg-emerald-200' : 'translate-x-0.5 bg-slate-500'}
                `}
              />
            </span>
            <span
              className={`text-[9px] font-bold font-mono uppercase tracking-tight whitespace-nowrap ${
                tenantOn ? 'text-emerald-200' : 'text-slate-500'
              }`}
            >
              {busy ? (
                <span className="inline-flex items-center gap-1">
                  <SpinnerTiny />
                  sync
                </span>
              ) : tenantOn ? (
                'on'
              ) : (
                'off'
              )}
            </span>
          </button>
        </div>
        <span className="text-[10px] font-mono text-cyan-200/85 tabular-nums shrink-0 pt-3">
          {n}/{tot}
        </span>
      </div>
      <p className="text-[8px] text-slate-600 font-mono mt-1.5 uppercase">clients w/ engine</p>
    </div>
  )
}

export default function GodModeEngineMatrix({
  matrix,
  scanningActive,
  godErr,
  onTenantEngineToggle,
  engineToggleBusy,
}) {
  if (godErr) {
    return (
      <div className="rounded-2xl border border-rose-500/25 bg-rose-950/15 p-4 text-[11px] font-mono text-rose-200">
        Engine matrix: {godErr}
      </div>
    )
  }
  if (!matrix) return null

  const core = matrix.core_engines || []
  const zd = matrix.zero_day_radar || {}
  const ot = matrix.ot_ics || {}

  return (
    <div
      className="rounded-2xl border border-slate-700/50 bg-gradient-to-b from-slate-950/95 to-black p-5"
      style={{ boxShadow: '0 0 80px rgba(59, 130, 246, 0.05)' }}
    >
      <div className="flex flex-wrap items-end justify-between gap-3 mb-4">
        <div>
          <h3 className="text-[10px] font-mono uppercase tracking-[0.3em] text-slate-400">
            Engine matrix
          </h3>
          <p className="text-xs text-slate-500 mt-1 font-mono">
            KNOWN_ENGINE_IDS · tenant <span className="text-slate-400">active_engines</span> · per-client{' '}
            <span className="text-slate-400">enabled_engines</span>
          </p>
          <p className="text-[10px] text-slate-600 mt-2 max-w-2xl leading-relaxed">
            Use the <span className="text-slate-500">orchestrator policy</span> switch to update{' '}
            <span className="text-slate-500">system_configs.active_engines</span> for the{' '}
            <span className="text-emerald-600/90">default</span> tenant via{' '}
            <span className="text-slate-500">PUT /api/ceo/tenant/engines</span>. Client-level allow-lists still use{' '}
            <span className="text-slate-500">enabled_engines</span> in Engine Room.
          </p>
        </div>
        <div
          className={`text-[10px] font-mono uppercase px-3 py-1 rounded-lg border ${
            scanningActive
              ? 'border-orange-500/50 text-orange-300 bg-orange-950/40'
              : 'border-white/15 text-slate-500 bg-white/5'
          }`}
        >
          orchestrator {scanningActive ? 'scanning' : 'idle'}
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-9 gap-2 mb-5">
        {core.map((e) => (
          <Cell
            key={e.id}
            engine={e}
            scanning={!!scanningActive}
            onTenantEngineToggle={onTenantEngineToggle}
            engineToggleBusy={engineToggleBusy}
          />
        ))}
      </div>

      <div className="grid sm:grid-cols-2 gap-3">
        <div className="rounded-xl border border-amber-500/25 bg-amber-950/15 px-4 py-3">
          <p className="text-[9px] font-mono uppercase tracking-widest text-amber-200/90 mb-2">
            Zero-Day radar
          </p>
          <div className="flex flex-wrap gap-3 text-[11px] font-mono">
            <span className={zd.tenant_threat_intel_probing_enabled ? 'text-amber-300' : 'text-slate-500'}>
              threat_intel probing: {zd.tenant_threat_intel_probing_enabled ? 'ON' : 'off'}
            </span>
            <span className="text-slate-400">
              clients w/ <code className="text-cyan-400/90">zero_day_radar</code>: {zd.clients_with_zero_day_radar_engine ?? 0} /{' '}
              {zd.clients_total ?? 0}
            </span>
          </div>
        </div>
        <div className="rounded-xl border border-violet-500/25 bg-violet-950/15 px-4 py-3">
          <p className="text-[9px] font-mono uppercase tracking-widest text-violet-200/90 mb-2">
            OT / ICS passive
          </p>
          <p className="text-[11px] font-mono text-slate-400">
            clients w/ <code className="text-violet-300/90">industrial_ot_enabled</code>:{' '}
            <span className="text-white tabular-nums">{ot.clients_with_industrial_ot_enabled ?? 0}</span> /{' '}
            {ot.clients_total ?? 0}
          </p>
        </div>
      </div>
    </div>
  )
}
