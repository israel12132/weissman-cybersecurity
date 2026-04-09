/**
 * SOC Command Bar: Launch scans from dashboard clients (no manual target) or single-engine on selected target.
 * "Scan all clients" runs all 5 engines on all clients from DB.
 */
import { useState, useEffect } from 'react'
import { formatApiErrorFromBody, formatApiErrorResponse } from '../lib/apiError.js'
import { apiFetch } from '../lib/apiBase'

const ENGINES = [
  { id: 'supply_chain', label: 'Supply Chain', short: 'SC', color: 'emerald' },
  { id: 'llm_path_fuzz', label: 'AI Fuzz (vLLM)', short: 'AI', color: 'cyan' },
  { id: 'bola_idor', label: 'BOLA/IDOR', short: 'IDOR', color: 'crimson' },
  { id: 'osint', label: 'OSINT / Dark Web', short: 'OSINT', color: 'amber' },
  { id: 'asm', label: 'Attack Surface', short: 'ASM', color: 'violet' },
]

const COLOR_CLASSES = {
  emerald: 'bg-emerald-500/20 border-emerald-400/50 text-emerald-300 hover:bg-emerald-500/30 hover:border-emerald-400',
  cyan: 'bg-cyan-500/20 border-cyan-400/50 text-cyan-300 hover:bg-cyan-500/30 hover:border-cyan-400',
  crimson: 'bg-rose-500/20 border-rose-400/50 text-rose-300 hover:bg-rose-500/30 hover:border-rose-400',
  amber: 'bg-amber-500/20 border-amber-400/50 text-amber-300 hover:bg-amber-500/30 hover:border-amber-400',
  violet: 'bg-violet-500/20 border-violet-400/50 text-violet-300 hover:bg-violet-500/30 hover:border-violet-400',
}

function getFirstTarget(client) {
  if (!client?.domains) return ''
  try {
    const arr = typeof client.domains === 'string' ? JSON.parse(client.domains) : client.domains
    if (Array.isArray(arr) && arr.length) return arr[0]
  } catch (_) {}
  return client?.name || ''
}

export default function CommandBar({ onScanLaunched, onError }) {
  const [target, setTarget] = useState('')
  const [clients, setClients] = useState([])
  const [clientsError, setClientsError] = useState(null)
  const [selectedClientId, setSelectedClientId] = useState('')
  const [loading, setLoading] = useState(null)
  const [lastResult, setLastResult] = useState(null)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const r = await apiFetch('/api/clients')
        if (cancelled) return
        if (r.ok) {
          const list = await r.json()
          setClients(Array.isArray(list) ? list : [])
          setClientsError(Array.isArray(list) ? null : 'Unexpected /api/clients response.')
        } else {
          setClients([])
          setClientsError(await formatApiErrorResponse(r))
        }
      } catch (e) {
        if (!cancelled) {
          setClients([])
          setClientsError(e?.message || 'Network error')
        }
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    if (!selectedClientId) return
    const c = clients.find((x) => String(x?.id) === String(selectedClientId))
    setTarget(getFirstTarget(c))
  }, [selectedClientId, clients])

  async function runFullScanAllClients() {
    setLoading('run-all')
    setLastResult(null)
    try {
      const r = await apiFetch('/api/scan/run-all', { method: 'POST' })
      let data = null
      try {
        data = await r.json()
      } catch {
        data = null
      }
      if (!r.ok) {
        const msg = formatApiErrorFromBody(data, r.status)
        if (onError) onError(msg)
        setLastResult({ engine: 'run-all', error: msg })
        return
      }
      setLastResult({ engine: 'run-all', job_id: 'all', status: 'started' })
      if (onScanLaunched) onScanLaunched('run-all', data)
    } catch (e) {
      const msg = e?.message || 'Network error'
      if (onError) onError(msg)
      setLastResult({ engine: 'run-all', error: msg })
    } finally {
      setLoading(null)
    }
  }

  async function launchScan(engineId) {
    const t = (target || '').trim()
    if (!t) {
      if (onError) onError('Select a client above or enter a target URL.')
      return
    }
    setLoading(engineId)
    setLastResult(null)
    try {
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ engine: engineId, target: t }),
      })
      let data = null
      try {
        data = await r.json()
      } catch {
        data = null
      }
      if (!r.ok) {
        const msg = formatApiErrorFromBody(data, r.status)
        if (onError) onError(msg)
        setLastResult({ engine: engineId, error: msg })
        return
      }
      setLastResult({ engine: engineId, job_id: data?.job_id, status: data?.status })
      if (onScanLaunched) onScanLaunched(engineId, data)
    } catch (e) {
      const msg = e?.message || 'Network error'
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
          Clients: {clientsError}
        </div>
      )}
      <div className="soc-command-bar-inner">
        <label className="soc-command-bar-label">TARGET</label>
        <select
          className="soc-command-bar-select"
          value={selectedClientId}
          onChange={(e) => setSelectedClientId(e.target.value)}
          aria-label="Client from dashboard"
        >
          <option value="">— Select client (from dashboard) —</option>
          {clients.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name || c.id} {getFirstTarget(c) ? `(${getFirstTarget(c)})` : ''}
            </option>
          ))}
        </select>
        <input
          type="text"
          placeholder="Or enter URL / scope"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          className="soc-command-bar-input"
          aria-label="Target URL or scope"
        />
        <button
          type="button"
          disabled={loading != null}
          onClick={runFullScanAllClients}
          className="soc-command-bar-btn bg-violet-500/20 border-violet-400/50 text-violet-300 hover:bg-violet-500/30 hover:border-violet-400 font-semibold"
          title="Run all 5 engines on all clients from DB"
        >
          {loading === 'run-all' ? '…' : 'Scan all clients'}
        </button>
        <div className="soc-command-bar-engines">
          {ENGINES.map(({ id, label, short, color }) => (
            <button
              key={id}
              type="button"
              disabled={loading != null}
              onClick={() => launchScan(id)}
              className={`soc-command-bar-btn ${COLOR_CLASSES[color]}`}
              title={label}
            >
              {loading === id ? '…' : short}
            </button>
          ))}
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
