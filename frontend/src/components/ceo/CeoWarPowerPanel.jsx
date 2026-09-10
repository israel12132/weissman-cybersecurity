import { Link } from 'react-router-dom'
import { useState } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { useClient } from '../../context/ClientContext'
import { formatHttpApiError } from '../../lib/apiBase'
import { intensityFromDepth, productionEngineIds, resolveClientScanTarget } from '../../lib/warPower'
import { apiFetch } from '../../utils/apiFetch'
import { useToast } from '../ui/Toaster'
import Button from '../ui/Button'

async function safeApi(path, init) {
  try {
    return { ok: true, data: await apiFetch(path, init) }
  } catch (e) {
    return {
      ok: false,
      status: e?.status,
      message: e?.response ? formatHttpApiError(e.response, e.message) : e?.message || String(e),
      error: e,
    }
  }
}

export default function CeoWarPowerPanel({ onFlagsChanged }) {
  const { t } = useTranslation()
  const { toast } = useToast()
  const { selectedClientId, selectedClient, patchConfig, roePending, submitRoeApproval } = useClient()
  const [depth, setDepth] = useState(3)
  const [unleashBusy, setUnleashBusy] = useState(false)
  const [aggressiveBusy, setAggressiveBusy] = useState(false)
  const [log, setLog] = useState([])

  const pushLog = (line) => setLog((prev) => [...prev.slice(-11), line])

  const runUnleashCore = async () => {
    const safe = await safeApi('/api/ceo/global-safe-mode', {
      method: 'PATCH',
      body: { global_safe_mode: false },
    })
    pushLog(safe.ok ? t('components.ceo.integratedCommandDeck.warSafeOff') : `safe-mode: ${safe.message}`)
    const kill = await safeApi('/api/ceo/strategy', {
      method: 'PATCH',
      body: { configs: { genesis_kill_switch: 'false' } },
    })
    pushLog(kill.ok ? t('components.ceo.integratedCommandDeck.warKillDisarmed') : `genesis: ${kill.message}`)
    const interval = await safeApi('/api/ceo/god-mode/scan-interval', {
      method: 'PATCH',
      body: { scan_interval_secs: 10 },
    })
    pushLog(
      interval.ok
        ? t('components.ceo.integratedCommandDeck.warIntervalMin')
        : `interval: ${interval.message}`,
    )
    if (onFlagsChanged) await onFlagsChanged()
    const enginesPayload = await safeApi('/api/engines/production')
    const ids = productionEngineIds(enginesPayload.ok ? enginesPayload.data : null)
    const armed = await armClientConfig(ids)
    if (!armed.ok) {
      pushLog(armed.detail || t('components.ceo.integratedCommandDeck.warConfigFailed'))
      toast.error(armed.detail || t('components.ceo.integratedCommandDeck.warConfigFailed'))
      return { ok: false }
    }
    pushLog(t('components.ceo.integratedCommandDeck.warEnginesArmed', { n: armed.engineN || ids.length }))
    if (!armed.roeOk) {
      pushLog(t('components.ceo.integratedCommandDeck.warRoePending'))
      toast.warning(t('components.ceo.integratedCommandDeck.warRoePending'))
    } else {
      pushLog(t('components.ceo.integratedCommandDeck.warRoeArmed'))
    }
    return { ok: true }
  }

  const armClientConfig = async (engineIds) => {
    if (selectedClientId == null) {
      return { ok: false, detail: t('components.ceo.integratedCommandDeck.warNeedClient') }
    }
    const base = {
      stealth_level: 0,
      industrial_ot_enabled: true,
      auto_harvest: true,
    }
    if (engineIds.length) base.enabled_engines = engineIds
    const flagsOk = await patchConfig(selectedClientId, base)
    const roeOk = await patchConfig(selectedClientId, { roe_mode: 'weaponized_god_mode' })
    return { ok: flagsOk, roeOk, engineN: engineIds.length }
  }

  const handleUnleash = async () => {
    setUnleashBusy(true)
    setLog([])
    try {
      const { ok } = await runUnleashCore()
      if (ok) toast.success(t('components.ceo.integratedCommandDeck.warUnleashDone'))
    } finally {
      setUnleashBusy(false)
    }
  }

  const handleMaxAggressive = async () => {
    if (selectedClientId == null) {
      toast.warning(t('components.ceo.integratedCommandDeck.warNeedClient'))
      return
    }
    const target = resolveClientScanTarget(selectedClient)
    if (!target) {
      toast.error(t('components.ceo.integratedCommandDeck.warNeedDomain'))
      return
    }
    setAggressiveBusy(true)
    setLog([])
    try {
      await runUnleashCore()
      const intensity = intensityFromDepth(depth)
      const queued = await safeApi('/api/scan/all-engines', {
        method: 'POST',
        body: {
          client_id: Number(selectedClientId),
          target,
          intensity,
          deep: depth >= 3,
        },
      })
      if (!queued.ok) {
        pushLog(`all-engines: ${queued.message}`)
        toast.error(queued.message)
        return
      }
      const jobId = queued.data?.job_id || queued.data?.id || '—'
      const n = queued.data?.engines_queued ?? queued.data?.engine_count ?? 'all'
      pushLog(t('components.ceo.integratedCommandDeck.warQueued', { n, jobId, intensity }))
      toast.success(t('components.ceo.integratedCommandDeck.warQueued', { n, jobId, intensity }))
    } finally {
      setAggressiveBusy(false)
    }
  }

  return (
    <div
      id="ceo-war-power-panel"
      className="rounded-2xl border border-orange-500/40 bg-gradient-to-br from-orange-950/40 via-black to-red-950/30 p-5"
    >
      <p className="text-[10px] font-mono uppercase tracking-[0.35em] text-orange-300/90 mb-1">
        {t('components.ceo.integratedCommandDeck.warBrand')}
      </p>
      <h3 className="text-lg font-bold text-white tracking-tight mb-1">
        {t('components.ceo.integratedCommandDeck.warTitle')}
      </h3>
      <p className="text-[11px] font-mono text-[var(--text-muted)] mb-4 max-w-3xl leading-relaxed">
        <Trans
          i18nKey="components.ceo.integratedCommandDeck.warHint"
          values={{ client: selectedClient?.name || '—' }}
          components={{ 1: <span className="text-orange-200/90" /> }}
        />
      </p>

      <label className="block mb-4">
        <span className="text-[10px] font-mono uppercase tracking-widest text-orange-200/80">
          {t('components.ceo.integratedCommandDeck.warDepth', { intensity: intensityFromDepth(depth) })}
        </span>
        <input
          id="ceo-war-depth-slider"
          type="range"
          min={1}
          max={3}
          step={1}
          value={depth}
          onChange={(e) => setDepth(Number(e.target.value))}
          className="mt-2 w-full accent-orange-400"
        />
      </label>

      <div className="grid gap-3 sm:grid-cols-2">
        <Button
          variant="unstyled"
          type="button"
          id="ceo-war-unleash-compute-btn"
          disabled={unleashBusy || aggressiveBusy}
          onClick={handleUnleash}
          className="py-3 rounded-xl text-xs font-bold uppercase tracking-widest border border-amber-400/50 bg-amber-950/50 text-amber-100 hover:bg-amber-900/50 disabled:opacity-40"
        >
          {unleashBusy ? '…' : t('components.ceo.integratedCommandDeck.warUnleashBtn')}
        </Button>
        <Button
          variant="unstyled"
          type="button"
          id="ceo-war-max-aggressive-btn"
          disabled={aggressiveBusy || unleashBusy || selectedClientId == null}
          onClick={handleMaxAggressive}
          className="py-3 rounded-xl text-xs font-bold uppercase tracking-widest border border-red-400/60 bg-red-950/60 text-red-100 hover:bg-red-900/50 disabled:opacity-40"
        >
          {aggressiveBusy ? '…' : t('components.ceo.integratedCommandDeck.warAggressiveBtn')}
        </Button>
      </div>

      {roePending ? (
        <div
          id="ceo-war-roe-approval"
          className="mt-4 rounded-xl border border-amber-400/50 bg-amber-950/40 p-3 space-y-2"
          role="status"
        >
          <p className="text-[11px] font-mono text-amber-100 leading-relaxed">
            {t('components.ceo.integratedCommandDeck.warRoePending')}
          </p>
          <p className="text-[10px] font-mono text-amber-200/80">
            {t('components.ceo.integratedCommandDeck.warRoeProgress', {
              have: roePending.approvalsHave ?? 0,
              need: roePending.approvalsNeeded || 2,
              id: roePending.requestId || '—',
            })}
          </p>
          <div className="flex flex-wrap gap-2">
            <Button
              variant="unstyled"
              type="button"
              id="ceo-war-roe-approve-btn"
              onClick={async () => {
                const ok = await submitRoeApproval()
                if (ok) toast.success(t('components.ceo.integratedCommandDeck.warRoeApproveMine'))
              }}
              className="px-3 py-2 rounded-lg text-[10px] font-bold uppercase tracking-widest border border-amber-300/50 bg-amber-900/50 text-amber-50"
            >
              {t('components.ceo.integratedCommandDeck.warRoeApproveMine')}
            </Button>
            <Link
              id="ceo-war-roe-queue-link"
              to="/roe-approvals"
              className="inline-flex items-center px-3 py-2 rounded-lg text-[10px] font-bold uppercase tracking-widest border border-amber-400/40 text-amber-100 hover:bg-amber-900/40"
            >
              {t('components.ceo.integratedCommandDeck.warRoeOpenQueue')}
            </Link>
          </div>
        </div>
      ) : null}

      {log.length > 0 && (
        <ul className="mt-4 space-y-1 font-mono text-[10px] text-orange-100/80" aria-live="polite">
          {log.map((line, i) => (
            <li key={`${i}-${line.slice(0, 24)}`}>{line}</li>
          ))}
        </ul>
      )}
    </div>
  )
}
