/**
 * SOC Command Bar: Launch scans from dashboard clients (no manual target) or single-engine on selected target.
 * "Scan all clients" runs all 5 engines on all clients from DB.
 */
import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { formatApiErrorFromBody, formatApiErrorResponse } from '../lib/apiError.js'
import { apiFetch } from '../utils/apiFetch'
import { launchEngineScan } from '../lib/launchEngineScan'
import { firstClientTarget, engineRequiresTarget, resolveEnqueueTarget } from '../lib/clientTarget'
import { useClientOptional } from '../context/ClientContext'
import Button from './ui/Button'

const ENGINE_IDS = [
  { id: 'supply_chain', color: 'emerald' },
  { id: 'llm_path_fuzz', color: 'cyan' },
  { id: 'bola_idor', color: 'crimson' },
  { id: 'osint', color: 'amber' },
  { id: 'asm', color: 'violet' },
]

const COLOR_CLASSES = {
  emerald: 'bg-emerald-500/20 border-emerald-400/50 text-emerald-300 hover:bg-emerald-500/30 hover:border-emerald-400',
  cyan: 'bg-cyan-500/20 border-cyan-400/50 text-cyan-300 hover:bg-cyan-500/30 hover:border-cyan-400',
  crimson: 'bg-rose-500/20 border-rose-400/50 text-rose-300 hover:bg-rose-500/30 hover:border-rose-400',
  amber: 'bg-amber-500/20 border-amber-400/50 text-amber-300 hover:bg-amber-500/30 hover:border-amber-400',
  violet: 'bg-violet-500/20 border-violet-400/50 text-violet-300 hover:bg-violet-500/30 hover:border-violet-400',
}

function getFirstTarget(client) {
  return firstClientTarget(client)
}

export default function CommandBar({ onScanLaunched, onError }) {
  const { t } = useTranslation()
  const clientCtx = useClientOptional()
  const clientScopeLocked = clientCtx?.clientScopeLocked === true
  const [target, setTarget] = useState('')
  const [localClients, setLocalClients] = useState([])
  const [clientsError, setClientsError] = useState(null)
  const [localSelectedId, setLocalSelectedId] = useState('')
  const [loading, setLoading] = useState(null)
  const [lastResult, setLastResult] = useState(null)

  const clients = clientCtx?.clients?.length ? clientCtx.clients : localClients
  const selectedClientId = clientScopeLocked
    ? String(clientCtx?.selectedClientId ?? '')
    : (clientCtx?.selectedClientId != null ? String(clientCtx.selectedClientId) : localSelectedId)
  const selectedClient = clients.find((c) => String(c?.id) === String(selectedClientId))

  const setSelectedClientId = (id) => {
    if (clientScopeLocked) return
    if (clientCtx?.setSelectedClientId) clientCtx.setSelectedClientId(id || null)
    setLocalSelectedId(id)
  }

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const list = await apiFetch('/api/clients')
        if (cancelled) return
        setLocalClients(Array.isArray(list) ? list : [])
        setClientsError(Array.isArray(list) ? null : t('components.commandBar.clients_error'))
      } catch (e) {
        if (!cancelled) {
          setLocalClients([])
          setClientsError(e?.response ? await formatApiErrorResponse(e.response) : (e?.message || t('components.commandBar.network_error')))
        }
      }
    })()
    return () => {
      cancelled = true
    }
  }, [t])

  useEffect(() => {
    if (!selectedClientId) return
    const c = clients.find((x) => String(x?.id) === String(selectedClientId))
    setTarget(getFirstTarget(c))
  }, [selectedClientId, clients])

  async function runFullScanAllClients() {
    setLoading('run-all')
    setLastResult(null)
    try {
      const data = await apiFetch('/api/scan/run-all', { method: 'POST' })
      setLastResult({ engine: 'run-all', job_id: 'all', status: 'started' })
      if (onScanLaunched) onScanLaunched('run-all', data)
    } catch (e) {
      const b = e?.response ? await e.response.json().catch(() => null) : null
      const msg = formatApiErrorFromBody(b, e?.status)
      if (onError) onError(msg)
      setLastResult({ engine: 'run-all', error: msg })
    } finally {
      setLoading(null)
    }
  }

  async function launchScan(engineId) {
    const resolved = resolveEnqueueTarget({
      engineId,
      target,
      client: selectedClient,
      clientScopeLocked,
    })
    if (engineRequiresTarget(engineId) && !resolved) {
      if (onError) onError(t('components.commandBar.no_target_error'))
      return
    }
    setLoading(engineId)
    setLastResult(null)
    try {
      const { ok, data, status } = await launchEngineScan({
        engineId,
        clientId: selectedClientId || undefined,
        target: resolved,
        client: selectedClient,
        clientScopeLocked,
      })
      if (!ok) {
        const msg = formatApiErrorFromBody(data, status)
        if (onError) onError(msg)
        setLastResult({ engine: engineId, error: msg })
        return
      }
      setLastResult({ engine: engineId, job_id: data?.job_id, status: data?.status })
      if (onScanLaunched) onScanLaunched(engineId, data)
    } catch (e) {
      const msg = e?.message || t('components.commandBar.network_error')
      if (onError) onError(msg)
      setLastResult({ engine: engineId, error: msg })
    } finally {
      setLoading(null)
    }
  }

  return (
    <div className="soc-command-bar">
      {clientsError && (
        <div className="px-3 py-2 text-xs text-rose-300 bg-rose-950/40 border-b border-rose-500/30" role="alert">
          {t('components.commandBar.clients_prefix')} {clientsError}
        </div>
      )}
      <div className="soc-command-bar-inner">
        <label className="soc-command-bar-label">{t('components.commandBar.target_label')}</label>
        {clientScopeLocked ? (
          <div className="soc-command-bar-select" data-testid="command-bar-client-locked">
            {(selectedClient?.name || t('engines.workspace_locked'))}
            {getFirstTarget(selectedClient) ? ` · ${getFirstTarget(selectedClient)}` : ''}
          </div>
        ) : (
          <select
            className="soc-command-bar-select"
            value={selectedClientId}
            onChange={(e) => setSelectedClientId(e.target.value)}
            aria-label={t('components.commandBar.client_aria')}
          >
            <option value="">{t('components.commandBar.select_client')}</option>
            {clients.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name || c.id} {getFirstTarget(c) ? `(${getFirstTarget(c)})` : ''}
              </option>
            ))}
          </select>
        )}
        <input
          type="text"
          placeholder={t('components.commandBar.target_url_placeholder')}
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          className="soc-command-bar-input"
          aria-label={t('components.commandBar.target_placeholder')}
        />
        <Button variant="unstyled"
          type="button"
          disabled={loading != null}
          onClick={runFullScanAllClients}
          className="soc-command-bar-btn bg-violet-500/20 border-violet-400/50 text-violet-300 hover:bg-violet-500/30 hover:border-violet-400 font-semibold"
          title={t('components.commandBar.scan_all_hint')}
        >
          {loading === 'run-all' ? '…' : t('components.commandBar.scan_all')}
        </Button>
        <div className="soc-command-bar-engines">
          {ENGINE_IDS.map(({ id, color }) => {
            const label = t(`components.commandBar.engines.${id}.label`)
            const short = t(`components.commandBar.engines.${id}.short`)
            return (
              <Button variant="unstyled"
                key={id}
                type="button"
                disabled={loading != null}
                onClick={() => launchScan(id)}
                className={`soc-command-bar-btn ${COLOR_CLASSES[color]}`}
                title={label}
              >
                {loading === id ? '…' : short}
              </Button>
            )
          })}
        </div>
      </div>
      {lastResult?.error && (
        <div className="soc-command-bar-error" role="alert">
          {lastResult.engine}: {lastResult.error}
        </div>
      )}
      {lastResult?.job_id && (
        <div className="soc-command-bar-success">
          {lastResult.engine} → {lastResult.status} (job: {lastResult.job_id})
        </div>
      )}
    </div>
  )
}
