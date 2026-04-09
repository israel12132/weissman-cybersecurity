import React, { useCallback } from 'react'
import { useClient } from '../../context/ClientContext'
import { useWarRoom } from '../../context/WarRoomContext'
import RoEPanel from './RoEPanel'
import EngineCard from './EngineCard'
import RedTeamSkullSwitch from '../warroom/RedTeamSkullSwitch'

const ENGINES = [
  { id: 'osint', label: 'OSINT' },
  { id: 'asm', label: 'ASM' },
  { id: 'supply_chain', label: 'Supply Chain' },
  { id: 'leak_hunter', label: 'Leak Hunter' },
  { id: 'bola_idor', label: 'BOLA/IDOR' },
  { id: 'llm_path_fuzz', label: 'LLM Path Fuzz' },
  { id: 'semantic_ai_fuzz', label: 'Semantic AI Fuzz' },
  { id: 'microsecond_timing', label: 'Microsecond Timing' },
  { id: 'ai_adversarial_redteam', label: 'AI Adversarial Red Team' },
  { id: 'poe_synthesis', label: 'PoE Synthesis' },
  { id: 'zero_day_radar', label: 'Zero-Day Radar' },
  { id: 'pipeline', label: 'Phantom Pipeline' },
]

const defaultEngines = []

export default function EngineRoomTab() {
  const {
    selectedClient,
    selectedClientId,
    clientConfig,
    patchConfig,
    configLoading,
    configError,
    dismissConfigError,
    poeJobId,
  } = useClient()
  const { confirmCommand, refuseCommand } = useWarRoom()

  if (clientConfig == null || clientConfig === undefined) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[280px]">
        <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 px-8 py-10 text-center">
          <p className="text-sm text-white/70">Connecting to Submarine...</p>
        </div>
      </div>
    )
  }

  const enabledList = Array.isArray(clientConfig.enabled_engines) ? clientConfig.enabled_engines : defaultEngines
  const enabledSet = new Set(enabledList)

  const handleEngineToggle = useCallback(
    async (engineId, nextEnabled) => {
      const current = Array.isArray(clientConfig?.enabled_engines) ? clientConfig.enabled_engines : defaultEngines
      const next = nextEnabled
        ? [...current.filter((e) => e !== engineId), engineId]
        : current.filter((e) => e !== engineId)
      const ok = await patchConfig(selectedClientId, { enabled_engines: next })
      if (ok && confirmCommand) confirmCommand('engine', engineId)
      else if (!ok && refuseCommand) refuseCommand()
    },
    [clientConfig?.enabled_engines, patchConfig, selectedClientId, confirmCommand, refuseCommand],
  )

  if (!selectedClient) {
    return (
      <div className="p-8">
        <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-8 text-center">
          <p className="text-sm text-white/70">Select a client from the sidebar to configure the Engine Room.</p>
        </div>
      </div>
    )
  }

  if (configLoading) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[280px]">
        <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 px-8 py-10 text-center">
          <div className="inline-block h-8 w-8 animate-spin rounded-full border-2 border-[#22d3ee]/50 border-t-[#22d3ee] mb-4" />
          <p className="text-sm text-white/70">Loading Data from Submarine...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 md:p-8 space-y-8">
      {configError && (
        <div
          className="rounded-xl border border-rose-500/40 bg-rose-950/30 px-4 py-3 text-sm text-rose-200 flex justify-between gap-4 items-start"
          role="alert"
        >
          <span className="min-w-0 break-words">{configError}</span>
          <button
            type="button"
            className="text-rose-400 text-xs underline shrink-0"
            onClick={dismissConfigError}
          >
            Dismiss
          </button>
        </div>
      )}
      <div className="flex flex-wrap items-start gap-6">
        <RoEPanel />
        <RedTeamSkullSwitch />
      </div>

      {/* Engine Grid */}
      <div>
        <h3 className="text-xs font-semibold text-white/50 uppercase tracking-[0.2em] mb-1">
          Engine Grid
        </h3>
        <p className="text-[11px] text-white/45 mb-4 max-w-3xl leading-relaxed">
          <span className="text-white/60">Toggle</span> enables the engine for this client in the orchestrator allow-list.
          Use <span className="text-cyan-400/90">Run</span> to queue an immediate async job (worker); live lines appear
          here when the backend streams telemetry for this client.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
          {ENGINES.map(({ id, label }) => (
            <EngineCard
              key={id}
              engineId={id}
              label={label}
              enabled={enabledSet.has(id)}
              onToggle={(next) => handleEngineToggle(id, next)}
              disabled={configLoading}
              sseJobId={id === 'poe_synthesis' ? poeJobId : null}
              showCommandConfirmed={id}
            />
          ))}
        </div>
      </div>
    </div>
  )
}
