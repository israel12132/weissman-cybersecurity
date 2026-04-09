import React, { useState, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useClient } from '../../context/ClientContext'
import { useTelemetry } from '../../context/TelemetryContext'
import { useWarRoom } from '../../context/WarRoomContext'
import { apiFetch, apiEventSourceUrl } from '../../lib/apiBase'
import { clientPrimaryTargetUrl, engineRunsWithoutTarget } from '../../lib/clientTarget'
import { ENGINES_BY_ID } from '../../lib/enginesRegistry'

const MAX_TERMINAL_LINES = 80

function formatSseLine(data) {
  if (typeof data !== 'object' || data === null) return null
  if (data.error) return `[ERROR] ${data.error}`
  if (data.message) return data.message
  const b = data.bytes_ingested
  const c = data.chunks_ingested
  if (b != null && c != null) return `Live: ${b} bytes, ${c} chunks`
  if (data.status === 'running' && data.message) return data.message
  if (data.status === 'completed') return `Completed. ${data.message || ''}`.trim()
  if (data.status === 'failed') return data.error ? `[ERROR] ${data.error}` : 'Failed.'
  return null
}

export default function EngineCard({ engineId, label, enabled, onToggle, disabled, sseJobId, showCommandConfirmed }) {
  const [poeJobLines, setPoeJobLines] = useState([])
  const [hasError, setHasError] = useState(false)
  const [runBusy, setRunBusy] = useState(false)
  const terminalRef = useRef(null)
  const { selectedClientId, selectedClient } = useClient()
  const { addToast, progressByEngine, addProgress } = useTelemetry()
  const { commandConfirmed } = useWarRoom()
  const progress = progressByEngine ?? {}
  const showConfirmed = commandConfirmed?.source === 'engine' && commandConfirmed?.meta === showCommandConfirmed

  const clientKey = selectedClientId ? `${selectedClientId}_${engineId}` : null
  const globalKey = `_global_${engineId}`
  const globalLines = clientKey ? progress[clientKey] || [] : progress[globalKey] || []

  const primaryTarget = clientPrimaryTargetUrl(selectedClient)
  const canRunTargeted = engineRunsWithoutTarget(engineId) || Boolean(primaryTarget)
  const cidNum = selectedClientId != null && selectedClientId !== '' ? Number(selectedClientId) : null

  const runScanNow = useCallback(async () => {
    if (!enabled || runBusy || cidNum == null || Number.isNaN(cidNum)) {
      addToast('error', 'Select a client and enable the engine first', engineId)
      return
    }
    if (!canRunTargeted) {
      addToast('error', 'Add at least one domain for this client', engineId)
      return
    }
    setRunBusy(true)
    try {
      const body = { engine: engineId, client_id: cidNum }
      if (!engineRunsWithoutTarget(engineId)) {
        body.target = primaryTarget
      }
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        const msg = d.detail || d.error || r.statusText || 'Scan request failed'
        addToast('error', String(msg), engineId)
        addProgress(String(cidNum), engineId, `[queue failed] ${msg}`)
        return
      }
      const jid = d.job_id || d.jobId || ''
      const line = jid ? `Queued job ${jid} (${d.job_kind || engineId})` : (d.message || 'Scan queued')
      addToast('info', line, engineId)
      addProgress(String(cidNum), engineId, line)
    } catch (e) {
      addToast('error', e?.message || 'Network error', engineId)
    } finally {
      setRunBusy(false)
    }
  }, [
    enabled,
    runBusy,
    cidNum,
    canRunTargeted,
    primaryTarget,
    engineId,
    addToast,
    addProgress,
  ])

  useEffect(() => {
    if (!sseJobId || engineId !== 'poe_synthesis') return
    setPoeJobLines([])
    setHasError(false)
    const path = `/api/poe-scan/stream/${encodeURIComponent(sseJobId)}`
    const url = apiEventSourceUrl(path)
    const es = new EventSource(url, { withCredentials: true })
    setPoeJobLines((prev) => [...prev, '> Connecting to stream...'])
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data || '{}')
        const line = formatSseLine(data)
        if (line) {
          setPoeJobLines((prev) => {
            const next = [...prev, `> ${line}`].slice(-MAX_TERMINAL_LINES)
            return next
          })
          if (data.error) {
            setHasError(true)
            addToast('error', data.error, 'poe_synthesis')
          }
        }
      } catch (_) {
        setPoeJobLines((prev) => [...prev.slice(-MAX_TERMINAL_LINES), '> [parse error]'])
      }
    }
    es.onerror = () => {
      es.close()
    }
    return () => {
      es.close()
    }
  }, [sseJobId, engineId, addToast])

  const linesToScroll = engineId === 'poe_synthesis' && poeJobLines.length > 0 ? poeJobLines : globalLines
  useEffect(() => {
    if (!terminalRef.current) return
    terminalRef.current.scrollTop = terminalRef.current.scrollHeight
  }, [linesToScroll])

  const terminalContent = (() => {
    let base = ''
    if (engineId === 'poe_synthesis' && poeJobLines.length > 0) base = poeJobLines.join('\n')
    else if (globalLines.length > 0) base = globalLines.join('\n')
    else base = enabled ? '> System idle...' : '> Engine offline'
    if (showConfirmed) base += '\n> Command Confirmed'
    return base
  })()

  // MITRE badge from engine registry
  const registryEntry = ENGINES_BY_ID[engineId]
  const mitreId = registryEntry?.mitre ?? null

  return (
    <div
      className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-4 transition-all duration-300 hover:border-white/20 hover:shadow-[0_0_30px_rgba(0,0,0,0.25)]"
    >
      <div className="flex items-center justify-between gap-3 mb-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-sm font-semibold text-white truncate">{label}</span>
          <span
            className={`shrink-0 w-2 h-2 rounded-full transition-all duration-200 ${
              enabled ? 'bg-[#4ade80] shadow-[0_0_6px_rgba(74,222,128,0.6)]' : 'bg-white/20'
            } ${hasError ? '!bg-[#ef4444] shadow-[0_0_6px_rgba(239,68,68,0.6)]' : ''}`}
          />
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            title={
              !enabled
                ? 'Enable engine first'
                : !canRunTargeted
                  ? 'Add a domain to run URL-based engines'
                  : 'Queue this engine on the worker (async job)'
            }
            disabled={disabled || !enabled || runBusy || !canRunTargeted}
            onClick={() => runScanNow()}
            className="px-2 py-1 rounded-lg text-[10px] font-mono uppercase tracking-wide border border-cyan-500/40 text-cyan-200/90 hover:bg-cyan-950/50 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {runBusy ? '…' : 'Run'}
          </button>
          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            disabled={disabled}
            onClick={() => onToggle(!enabled)}
            className={`
            relative shrink-0 w-11 h-6 rounded-full transition-all duration-300 ease-out
            focus:outline-none focus:ring-2 focus:ring-[#22d3ee]/50 focus:ring-offset-2 focus:ring-offset-black/40
            disabled:opacity-50 disabled:cursor-not-allowed
            ${enabled
              ? 'bg-[#22d3ee]/40 shadow-inner'
              : 'bg-black/60 border border-white/10'
            }
          `}
          >
            <span
              className={`absolute top-0.5 w-5 h-5 rounded-full bg-white shadow-lg transition-all duration-300 ease-out ${
                enabled ? 'left-[22px]' : 'left-0.5'
              }`}
              style={enabled ? { boxShadow: '0 1px 3px rgba(0,0,0,0.2)' } : {}}
            />
          </button>
        </div>
      </div>

      {/* MITRE badge */}
      {mitreId && (
        <div className="mb-2">
          <span className="inline-block px-1.5 py-0.5 rounded text-[9px] font-mono bg-white/5 border border-white/10 text-white/40 tracking-wider">
            {mitreId}
          </span>
        </div>
      )}

      <div
        ref={terminalRef}
        className="relative rounded-xl bg-black/80 shadow-inner border border-white/5 p-3 min-h-[72px] font-mono text-[11px] leading-relaxed overflow-auto"
      >
        <pre
          className={`m-0 whitespace-pre-wrap break-all ${
            hasError ? 'text-red-400' : 'text-[#4ade80]/90'
          }`}
        >
          {terminalContent}
        </pre>
        <AnimatePresence>
          {showConfirmed && (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0 }}
              className="absolute bottom-2 right-2 text-[10px] font-mono text-[#22d3ee]"
              style={{ textShadow: '0 0 8px rgba(34,211,238,0.8)' }}
            >
              Command Confirmed
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  )
}
