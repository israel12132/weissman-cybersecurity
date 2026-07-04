import React, { useCallback, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useClient } from '../../context/ClientContext'
import { useWarRoom } from '../../context/WarRoomContext'
import RoEPanel from './RoEPanel'
import EngineCard from './EngineCard'
import RedTeamSkullSwitch from '../warroom/RedTeamSkullSwitch'
import { ENGINE_GROUP_DEFS } from '../../lib/engineGroupDefs'
import { useProductionEngines } from '../../lib/useProductionEngines'

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
  const { t } = useTranslation()
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
  const [search, setSearch] = useState('')
  const [onlyEnabled, setOnlyEnabled] = useState(false)
  const { engines: productionRegistry, productionCount, catalogCount, loading: productionLoading } =
    useProductionEngines()

  // All hooks must run unconditionally and in a stable order on every render, so they
  // are declared BEFORE any early return below (React Rules of Hooks — calling a hook
  // after a conditional `return` desyncs the hook list and crashes the component).
  // enabledList is null-safe because clientConfig may still be loading here.
  const enabledList = Array.isArray(clientConfig?.enabled_engines)
    ? clientConfig.enabled_engines
    : defaultEngines
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

  const filteredRegistry = useMemo(() => {
    const q = search.trim().toLowerCase()
    return productionRegistry.filter((e) => {
      if (onlyEnabled && !enabledSet.has(e.id)) return false
      if (!q) return true
      const hay = `${e.id} ${e.label || ''} ${e.description || ''} ${e.mitre || ''}`.toLowerCase()
      return hay.includes(q)
    })
  }, [productionRegistry, search, onlyEnabled, enabledSet])

  // ── Early returns (after all hooks) ──────────────────────────────────────
  if (clientConfig == null || clientConfig === undefined) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[280px]">
        <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 px-8 py-10 text-center">
          <p className="text-sm text-white/70">{t('components.cockpitWidgets.engineRoomTab.connecting')}</p>
        </div>
      </div>
    )
  }

  if (!selectedClient) {
    return (
      <div className="p-8">
        <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-8 text-center">
          <p className="text-sm text-white/70">{t('components.cockpitWidgets.engineRoomTab.select_client')}</p>
        </div>
      </div>
    )
  }

  if (configLoading || productionLoading) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[280px]">
        <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 px-8 py-10 text-center">
          <div className="inline-block h-8 w-8 animate-spin rounded-full border-2 border-[#22d3ee]/50 border-t-[#22d3ee] mb-4" />
          <p className="text-sm text-white/70">{t('components.cockpitWidgets.engineRoomTab.loading')}</p>
        </div>
      </div>
    )
  }

  const enginesByGroup = (groupId) =>
    filteredRegistry.filter((e) => e.group === groupId)

  const visibleGroups = activeGroup === 'all'
    ? ENGINE_GROUP_DEFS
    : ENGINE_GROUP_DEFS.filter((g) => g.id === activeGroup)

  const totalEnabled = enabledList.filter((id) =>
    productionRegistry.some((e) => e.id === id),
  ).length
  const totalEngines = productionCount || productionRegistry.length

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
            {t('engines.title')} — {t('engines.live_engines', { count: totalEngines })}
            {catalogCount > totalEngines ? (
              <span className="text-white/35 font-normal normal-case tracking-normal ms-2">
                {t('engines.catalog_hidden', { count: catalogCount })}
              </span>
            ) : null}
          </h3>
          <p className="text-[11px] text-white/40 mt-0.5">
            {t('engines.enabled_count', { enabled: totalEnabled, disabled: totalEngines - totalEnabled })} ·{' '}
            <span className="text-white/50">{t('engines.toggle_hint')}</span>
          </p>
        </div>
      </div>

      {/* Search + filter row */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[260px]">
          <input
            type="search"
            placeholder={t('engines.search_placeholder')}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-black/50 border border-white/10 rounded-lg px-3 py-2 text-sm font-mono text-white/85 placeholder-white/30 focus:outline-none focus:border-cyan-500/40"
          />
          {search && (
            <button
              type="button"
              onClick={() => setSearch('')}
              aria-label={t('common.close')}
              className="absolute end-2 top-1/2 -translate-y-1/2 text-white/40 hover:text-white text-xs"
            >
              ✕
            </button>
          )}
        </div>
        <label className="text-[11px] font-mono text-white/55 inline-flex items-center gap-2 select-none">
          <input
            type="checkbox"
            checked={onlyEnabled}
            onChange={(e) => setOnlyEnabled(e.target.checked)}
            className="accent-cyan-500"
          />
          {t('engines.show_only_enabled')}
        </label>
        <span className="text-[11px] font-mono text-white/35">
          {t('engines.matches', { count: filteredRegistry.length })}
        </span>
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
          {t('engines.all_engines', { count: totalEngines })}
        </button>
        {ENGINE_GROUP_DEFS.map((g) => {
          const groupEngines = enginesByGroup(g.id)
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
          const engines = enginesByGroup(groupDef.id)
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
