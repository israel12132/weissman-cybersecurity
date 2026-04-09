import React, { useCallback, useState } from 'react'
import { useClient } from '../../context/ClientContext'
import { useWarRoom } from '../../context/WarRoomContext'
import RoEPanel from './RoEPanel'
import EngineCard from './EngineCard'
import RedTeamSkullSwitch from '../warroom/RedTeamSkullSwitch'
import { ENGINES_REGISTRY, ENGINE_GROUP_DEFS, getEnginesByGroup } from '../../lib/enginesRegistry'

const defaultEngines = []

function GroupSection({ groupDef, engines, enabledSet, configLoading, poeJobId, onToggle, onEnableAll, onDisableAll }) {
  const enabledCount = engines.filter((e) => enabledSet.has(e.id)).length

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span
            className="w-2 h-2 rounded-full shrink-0"
            style={{ backgroundColor: groupDef.color, boxShadow: `0 0 6px ${groupDef.color}80` }}
          />
          <h3
            className="text-xs font-semibold uppercase tracking-[0.18em]"
            style={{ color: groupDef.color }}
          >
            {groupDef.label}
          </h3>
          <span className="text-[10px] font-mono text-white/40">
            {enabledCount}/{engines.length} enabled
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => onEnableAll(engines.map((e) => e.id))}
            disabled={configLoading}
            className="px-2 py-0.5 rounded text-[10px] font-mono border border-white/10 text-white/50 hover:text-white/80 hover:border-white/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            Enable All
          </button>
          <button
            type="button"
            onClick={() => onDisableAll(engines.map((e) => e.id))}
            disabled={configLoading}
            className="px-2 py-0.5 rounded text-[10px] font-mono border border-white/10 text-white/50 hover:text-white/80 hover:border-white/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            Disable All
          </button>
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {engines.map(({ id, label }) => (
          <EngineCard
            key={id}
            engineId={id}
            label={label}
            enabled={enabledSet.has(id)}
            onToggle={(next) => onToggle(id, next)}
            disabled={configLoading}
            sseJobId={id === 'poe_synthesis' ? poeJobId : null}
            showCommandConfirmed={id}
          />
        ))}
      </div>
    </div>
  )
}

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
  const [activeGroup, setActiveGroup] = useState('all')

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

  const handleEnableAll = useCallback(
    async (engineIds) => {
      const current = Array.isArray(clientConfig?.enabled_engines) ? clientConfig.enabled_engines : defaultEngines
      const currentSet = new Set(current)
      engineIds.forEach((id) => currentSet.add(id))
      const ok = await patchConfig(selectedClientId, { enabled_engines: [...currentSet] })
      if (!ok && refuseCommand) refuseCommand()
    },
    [clientConfig?.enabled_engines, patchConfig, selectedClientId, refuseCommand],
  )

  const handleDisableAll = useCallback(
    async (engineIds) => {
      const current = Array.isArray(clientConfig?.enabled_engines) ? clientConfig.enabled_engines : defaultEngines
      const disableSet = new Set(engineIds)
      const next = current.filter((e) => !disableSet.has(e))
      const ok = await patchConfig(selectedClientId, { enabled_engines: next })
      if (!ok && refuseCommand) refuseCommand()
    },
    [clientConfig?.enabled_engines, patchConfig, selectedClientId, refuseCommand],
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

  const visibleGroups = activeGroup === 'all'
    ? ENGINE_GROUP_DEFS
    : ENGINE_GROUP_DEFS.filter((g) => g.id === activeGroup)

  const totalEnabled = enabledList.length
  const totalEngines = ENGINES_REGISTRY.length

  return (
    <div className="p-6 md:p-8 space-y-6">
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

      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-xs font-semibold text-white/50 uppercase tracking-[0.2em]">
            Engine Grid — All {totalEngines} Engines
          </h3>
          <p className="text-[11px] text-white/40 mt-0.5">
            {totalEnabled} enabled · {totalEngines - totalEnabled} disabled ·{' '}
            <span className="text-white/50">Toggle to add to orchestrator allow-list. Run to queue immediate async job.</span>
          </p>
        </div>
      </div>

      {/* Group filter tabs */}
      <div className="flex flex-wrap gap-1.5">
        <button
          type="button"
          onClick={() => setActiveGroup('all')}
          className={`px-3 py-1 rounded-lg text-[11px] font-mono transition-all ${
            activeGroup === 'all'
              ? 'bg-white/15 text-white border border-white/30'
              : 'text-white/50 border border-white/10 hover:border-white/20 hover:text-white/70'
          }`}
        >
          All ({totalEngines})
        </button>
        {ENGINE_GROUP_DEFS.map((g) => {
          const groupEngines = getEnginesByGroup(g.id)
          return (
            <button
              key={g.id}
              type="button"
              onClick={() => setActiveGroup(g.id)}
              className={`px-3 py-1 rounded-lg text-[11px] font-mono transition-all ${
                activeGroup === g.id
                  ? 'text-white border'
                  : 'text-white/50 border border-white/10 hover:border-white/20 hover:text-white/70'
              }`}
              style={
                activeGroup === g.id
                  ? { backgroundColor: `${g.color}25`, borderColor: `${g.color}60`, color: g.color }
                  : {}
              }
            >
              {g.label} ({groupEngines.length})
            </button>
          )
        })}
      </div>

      {/* Group sections */}
      <div className="space-y-10">
        {visibleGroups.map((groupDef) => {
          const engines = getEnginesByGroup(groupDef.id)
          if (engines.length === 0) return null
          return (
            <GroupSection
              key={groupDef.id}
              groupDef={groupDef}
              engines={engines}
              enabledSet={enabledSet}
              configLoading={configLoading}
              poeJobId={poeJobId}
              onToggle={handleEngineToggle}
              onEnableAll={handleEnableAll}
              onDisableAll={handleDisableAll}
            />
          )
        })}
      </div>
    </div>
  )
}
