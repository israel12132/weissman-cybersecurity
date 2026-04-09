/**
 * Module 9: Exploit Synthesis & Memory Forensics Lab.
 * Entropy Gauge (Richter scale), Deception Badge, Hex Heatmap (Memory X-Ray).
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { FixedSizeList as List } from 'react-window'
import { apiFetch, apiEventSourceUrl } from '../lib/apiBase'

const ENTROPY_MAX = 8
const ENTROPY_SAFE = 4
const ENTROPY_WARN = 7

/** Semi-circle Entropy Gauge (0–8). 0–4 blue, 4–6.9 yellow, 7–8 crimson. */
function EntropyGauge({ value, isLeak }) {
  const v = Math.min(ENTROPY_MAX, Math.max(0, Number(value) ?? 0))
  const rotation = -90 + (v / ENTROPY_MAX) * 180
  const zone = v >= ENTROPY_WARN ? 'critical' : v >= ENTROPY_SAFE ? 'warning' : 'safe'
  const colors = { safe: { stroke: '#3b82f6', label: 'Safe' }, warning: { stroke: '#eab308', label: 'Warning' }, critical: { stroke: '#dc2626', label: 'Critical' } }
  const c = colors[zone]
  return (
    <div className="relative flex flex-col items-center">
      <svg viewBox="0 0 120 80" className="w-full max-w-[200px] h-24 text-slate-700" aria-label={`Entropy ${v.toFixed(1)}`}>
        <defs>
          <linearGradient id="gaugeSafe" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stopColor="#1e3a5f" /><stop offset="100%" stopColor="#3b82f6" /></linearGradient>
          <linearGradient id="gaugeWarn" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stopColor="#713f12" /><stop offset="100%" stopColor="#eab308" /></linearGradient>
          <linearGradient id="gaugeCrit" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stopColor="#7f1d1d" /><stop offset="100%" stopColor="#dc2626" /></linearGradient>
        </defs>
        <path d="M 10 70 A 50 50 0 0 1 110 70" fill="none" stroke="currentColor" strokeWidth="12" className="text-slate-700" />
        <path d="M 10 70 A 50 50 0 0 1 60 22" fill="none" stroke="url(#gaugeSafe)" strokeWidth="12" strokeLinecap="round" />
        <path d="M 60 22 A 50 50 0 0 1 95 52" fill="none" stroke="url(#gaugeWarn)" strokeWidth="12" strokeLinecap="round" />
        <path d="M 95 52 A 50 50 0 0 1 110 70" fill="none" stroke="url(#gaugeCrit)" strokeWidth="12" strokeLinecap="round" />
        <line
          x1="60"
          y1="70"
          x2="60"
          y2="35"
          stroke={c.stroke}
          strokeWidth="3"
          strokeLinecap="round"
          transform={`rotate(${rotation}, 60, 70)`}
          className={isLeak ? 'animate-pulse' : ''}
          style={isLeak ? { filter: 'drop-shadow(0 0 4px rgba(220,38,38,0.8))' } : undefined}
        />
        <circle cx="60" cy="70" r="4" fill={c.stroke} className={isLeak ? 'animate-pulse' : ''} />
      </svg>
      <div className="text-center mt-0">
        <span className="font-mono font-bold text-lg" style={{ color: c.stroke }}>{v.toFixed(1)}</span>
        <span className="text-slate-500 text-xs ml-1">/ {ENTROPY_MAX}</span>
      </div>
      {isLeak && (
        <div className="mt-2 px-3 py-1.5 rounded bg-red-500/20 border border-red-500/60 animate-pulse">
          <span className="text-red-400 font-bold text-xs uppercase tracking-wider">Silent Memory Leak Detected</span>
        </div>
      )}
    </div>
  )
}

/** Deception Badge: HTTP 200 (green) + TRUE STATE DATA BLEED (red). */
function DeceptionBadge() {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="px-3 py-1.5 rounded-full bg-emerald-500/20 text-emerald-400 text-sm font-medium border border-emerald-500/50">
        HTTP 200 OK
      </span>
      <span className="text-slate-500 text-sm">→</span>
      <span className="px-3 py-1.5 rounded-full bg-red-500/25 text-red-400 text-sm font-semibold border-2 border-red-500/70 flex items-center gap-1.5">
        <span className="text-red-400">⚠</span>
        TRUE STATE: DATA BLEED (High Entropy Bypass)
      </span>
    </div>
  )
}

// x86_64 only: 8-byte alignment. Buffer → Padding → RBP (8B) → RIP (8B) → Shellcode. No 32-bit (EBP/EIP) references.
const STACK_LAYOUT_64 = [
  { name: 'Shellcode', reg: 'Shellcode', color: 'from-emerald-500/80 to-emerald-700/80', size: 'variable' },
  { name: 'RIP (Return, 8B)', reg: 'RIP', color: 'from-rose-500/80 to-rose-700/80', size: 8 },
  { name: 'RBP (Frame, 8B)', reg: 'RBP', color: 'from-amber-500/80 to-amber-700/80', size: 8 },
  { name: 'Padding', reg: 'Padding', color: 'from-slate-600/80 to-slate-700/80', size: 'variable' },
  { name: 'Buffer', reg: 'Buffer', color: 'from-cyan-600/80 to-cyan-700/80', size: 'variable' },
]

export default function MemoryForensicsLab() {
  const { clientId } = useParams()
  const [findings, setFindings] = useState([])
  const [selected, setSelected] = useState(null)
  const [loading, setLoading] = useState(true)
  const [targetUrl, setTargetUrl] = useState('')
  const [running, setRunning] = useState(false)
  const [jobId, setJobId] = useState(null)
  const [jobStatus, setJobStatus] = useState(null)
  const [client, setClient] = useState(null)
  const [hoveredSlot, setHoveredSlot] = useState(null) // 'Buffer' | 'Padding' | 'RBP' | 'RIP' | 'Shellcode' for hex hover

  const fetchFindings = useCallback(() => {
    if (!clientId) return
    setLoading(true)
    apiFetch(`/api/clients/${clientId}/poe-findings`)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((data) => setFindings(data?.findings ?? []))
      .catch(() => setFindings([]))
      .finally(() => setLoading(false))
  }, [clientId])

  useEffect(() => {
    fetchFindings()
  }, [fetchFindings])

  useEffect(() => {
    if (!clientId) return
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((list) => {
        const c = Array.isArray(list) ? list.find((x) => String(x.id) === String(clientId)) : null
        setClient(c || null)
        if (c?.domains) {
          try {
            const doms = typeof c.domains === 'string' ? JSON.parse(c.domains) : c.domains
            const first = Array.isArray(doms) ? doms[0] : null
            if (first && !targetUrl) setTargetUrl(first.startsWith('http') ? first : `https://${first}`)
          } catch (_) {}
        }
      })
      .catch(() => setClient(null))
  }, [clientId])

  const runScan = () => {
    if (!clientId || !targetUrl.trim()) return
    setRunning(true)
    setJobId(null)
    setJobStatus(null)
    apiFetch('/api/poe-scan/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: clientId, target_url: targetUrl.trim() }),
    })
      .then((r) => {
        if (r.status !== 202) return r.json().then((d) => Promise.reject(new Error(d?.detail || 'Start failed')))
        return r.json()
      })
      .then((data) => {
        const id = data?.job_id
        if (!id) {
          setRunning(false)
          return
        }
        setJobId(id)
        setJobStatus({ status: 'running', message: data?.message || 'Queued.' })
        // Zero-latency SSE (Bearer via query when cookies are blocked)
        const path = `/api/poe-scan/stream/${encodeURIComponent(id)}`
        const es = new EventSource(apiEventSourceUrl(path), { withCredentials: true })
        es.onmessage = (e) => {
          try {
            const s = JSON.parse(e.data)
            setJobStatus(s)
            if (s.status === 'completed') {
              fetchFindings()
              setRunning(false)
              setJobId(null)
              es.close()
            } else if (s.status === 'failed') {
              setRunning(false)
              setJobId(null)
              es.close()
            }
          } catch (_) {}
        }
        es.onerror = () => {
          es.close()
          setRunning(false)
          setJobId(null)
        }
      })
      .catch(() => setRunning(false))
  }

  // 64-bit stack byte ranges (IDA-style): Buffer 0-64, RBP 64-72, RIP 72-80, Shellcode 80+
  const getSlotAtOffset = (offset) => {
    if (offset < 64) return 'Buffer'
    if (offset < 72) return 'RBP'
    if (offset < 80) return 'RIP'
    return 'Shellcode'
  }

  const payloadToHex = (str) => {
    if (!str || typeof str !== 'string') return ''
    return Array.from(str)
      .map((c) => c.charCodeAt(0).toString(16).padStart(2, '0').toUpperCase())
      .join(' ')
  }

  const ENTROPY_BLOCK = 256
  const hasEntropyMap = selected?.entropy_map && Array.isArray(selected.entropy_map) && selected.entropy_map.length > 0
  const responseBytes = useMemo(() => {
    if (!selected?.response_bleed_preview || !hasEntropyMap) return null
    try {
      const bin = atob(selected.response_bleed_preview)
      return Array.from(bin, (c) => c.charCodeAt(0))
    } catch {
      return null
    }
  }, [selected?.response_bleed_preview, hasEntropyMap])
  const payloadBytes = useMemo(() => {
    if (responseBytes && responseBytes.length > 0) return responseBytes
    return selected?.poc_exploit ? Array.from(selected.poc_exploit, (c) => c.charCodeAt(0)) : []
  }, [responseBytes, selected?.poc_exploit])
  const BYTES_PER_ROW = 16
  const hexRowCount = Math.ceil(payloadBytes.length / BYTES_PER_ROW)
  const HEX_ROW_HEIGHT = 22
  const HEX_VIEWER_HEIGHT = 384

  const isMemoryLeakFinding = selected && (
    selected.entropy_score != null ||
    hasEntropyMap ||
    (selected.trigger_reason && /entropy|memory leak|silent.*(memory|200)/i.test(selected.trigger_reason))
  )
  const maxLocalEntropy = useMemo(() => {
    if (!hasEntropyMap) return null
    return Math.max(...selected.entropy_map.map((e) => (e && typeof e.entropy === 'number' ? e.entropy : 0)))
  }, [hasEntropyMap, selected?.entropy_map])
  const entropyDisplay = selected?.entropy_score ?? maxLocalEntropy ?? (isMemoryLeakFinding ? 7.5 : null)
  const isEntropyCritical = entropyDisplay != null && entropyDisplay >= ENTROPY_WARN
  const bleedStartOffset = selected?.bleed_start_offset != null ? Number(selected.bleed_start_offset) : null

  const getEntropyAtByte = useCallback(
    (byteOffset) => {
      if (!hasEntropyMap || !selected.entropy_map) return null
      const blockIndex = Math.floor(byteOffset / ENTROPY_BLOCK)
      const entry = selected.entropy_map[blockIndex]
      return entry && typeof entry.entropy === 'number' ? entry.entropy : null
    },
    [hasEntropyMap, selected?.entropy_map]
  )

  const rawChunkSize = 500

  const rawChunks = useMemo(() => {
    const str = selected?.poc_exploit || ''
    if (!str) return []
    const chunks = []
    for (let i = 0; i < str.length; i += rawChunkSize) {
      chunks.push(str.slice(i, i + rawChunkSize))
    }
    return chunks
  }, [selected?.poc_exploit])
  const RAW_ROW_HEIGHT = 20

  const HexRow = useCallback(
    ({ index, style }) => {
      const start = index * BYTES_PER_ROW
      const rowBytes = payloadBytes.slice(start, start + BYTES_PER_ROW)
      const offset = start
      const inBleedZone = (byteOffset) => bleedStartOffset != null && byteOffset >= bleedStartOffset
      return (
        <div style={style} className="flex flex-nowrap gap-0.5 leading-relaxed font-mono text-sm">
          <span className="text-slate-500 w-16 shrink-0">
            {offset < 0x10000
              ? '0x' + offset.toString(16).toUpperCase().padStart(4, '0')
              : '0x' + offset.toString(16).toUpperCase()}
          </span>
          <span className="flex flex-wrap gap-0.5">
            {rowBytes.map((byte, col) => {
              const byteOffset = start + col
              const slot = getSlotAtOffset(byteOffset)
              const isHovered = hoveredSlot === slot
              const isBleed = inBleedZone(byteOffset)
              const blockEntropy = getEntropyAtByte(byteOffset)
              const severityClass =
                blockEntropy != null && blockEntropy >= ENTROPY_WARN
                  ? 'text-red-400 font-semibold'
                  : blockEntropy != null && blockEntropy >= ENTROPY_SAFE
                    ? 'text-amber-400'
                    : isBleed
                      ? 'text-red-400 font-semibold'
                      : 'text-slate-400'
              return (
                <span
                  key={byteOffset}
                  onMouseEnter={() => setHoveredSlot(slot)}
                  onMouseLeave={() => setHoveredSlot(null)}
                  className={`cursor-default px-0.5 rounded ${severityClass} ${isHovered ? 'bg-cyan-500/40 text-white' : isBleed || (blockEntropy != null && blockEntropy >= ENTROPY_SAFE) ? 'hover:bg-red-500/20' : 'hover:bg-slate-700/50'}`}
                  title={
                    blockEntropy != null
                      ? `Offset ${byteOffset} → ${slot} (entropy ${blockEntropy.toFixed(2)})`
                      : isBleed
                        ? `Offset ${byteOffset} → ${slot} (bleed start)` : `Offset ${byteOffset} → ${slot}`
                  }
                >
                  {byte.toString(16).toUpperCase().padStart(2, '0')}
                </span>
              )
            })}
          </span>
        </div>
      )
    },
    [payloadBytes, hoveredSlot, bleedStartOffset, getEntropyAtByte]
  )

  const RawChunkRow = useCallback(
    ({ index, style }) => {
      const chunk = rawChunks[index] || ''
      const chunkStart = index * rawChunkSize
      const isBleedChunk = !responseBytes && bleedStartOffset != null && chunkStart >= bleedStartOffset
      return (
        <div
          style={style}
          className={`font-mono text-sm whitespace-pre-wrap break-all ${isBleedChunk ? 'text-red-400 font-semibold' : 'text-slate-400'}`}
        >
          {chunk}
        </div>
      )
    },
    [rawChunks, rawChunkSize, bleedStartOffset, responseBytes]
  )

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 p-6">
      <div className="max-w-6xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-4">
            <Link to="/" className="text-cyan-400 hover:text-cyan-300 text-sm font-medium">← War Room</Link>
            <h1 className="text-2xl font-bold text-white tracking-tight">Exploit Synthesis &amp; Memory Lab</h1>
          </div>
          {clientId && client && <span className="text-slate-500 text-sm">{client.name} (ID: {clientId})</span>}
        </div>

        <div className="mb-6 flex flex-wrap gap-2 items-center">
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://target.example.com"
            className="rounded-lg bg-slate-800 border border-slate-600 px-3 py-2 text-sm text-white placeholder-slate-500 w-80"
          />
          <button
            onClick={runScan}
            disabled={running || !clientId}
            className="px-4 py-2 rounded-lg bg-violet-600 hover:bg-violet-500 disabled:bg-slate-600 text-white text-sm font-medium"
          >
            {running ? 'PoE scan running…' : 'Run PoE scan'}
          </button>
          {jobId && (
            <span className="text-slate-400 text-sm font-mono">
              Job: {jobId}
              {jobStatus?.status === 'running' && (
                <>
                  {' (live stream…)'}
                  {(jobStatus?.bytes_ingested != null || jobStatus?.chunks_ingested != null) && (
                    <span className="text-cyan-400 ml-2">
                      Live Data Ingestion: {Number(jobStatus.bytes_ingested ?? 0).toLocaleString()} bytes, {Number(jobStatus.chunks_ingested ?? 0).toLocaleString()} chunks
                    </span>
                  )}
                </>
              )}
              {jobStatus?.status === 'completed' && ` — ${jobStatus?.findings_count ?? 0} findings.`}
              {jobStatus?.status === 'failed' && ` — Failed: ${jobStatus?.error || 'unknown'}`}
            </span>
          )}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          <div className="rounded-xl bg-slate-900/80 border border-slate-700/60 p-6">
            <h2 className="text-lg font-semibold text-slate-200 mb-2">64-bit Stack Frame (x86_64)</h2>
            <p className="text-xs text-slate-500 mb-4">Buffer → Padding → RBP (8B) → RIP (8B) → Shellcode. Hover hex bytes to highlight.</p>
            <div className="space-y-2 font-mono text-sm">
              {STACK_LAYOUT_64.map((slot) => (
                <div
                  key={slot.reg}
                  className={`rounded-lg bg-gradient-to-r ${slot.color} px-4 py-2 flex justify-between items-center transition-all ${
                    hoveredSlot === slot.reg ? 'ring-2 ring-cyan-400 scale-[1.02]' : ''
                  }`}
                >
                  <span className="text-slate-100 font-semibold">{slot.reg}</span>
                  <span className="text-slate-200/90 text-xs">{slot.name}</span>
                </div>
              ))}
            </div>
            {selected && (
              <div className="mt-4 p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-200 text-xs">
                Payload overwrite: fills Buffer, then RBP/RIP (8 bytes each). 64-bit addresses. Safe PoE only.
              </div>
            )}
          </div>

          <div className="rounded-xl bg-slate-900/80 border border-slate-700/60 p-6 flex flex-col">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-slate-200">Weaponization Status</h2>
              <span className="px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-400 text-sm font-medium border border-emerald-500/40">
                SAFE (Proof of Exploitability Only)
              </span>
            </div>
            <p className="text-sm text-slate-400 mb-4">
              All synthesized payloads are read-only PoC. No reverse shells, no malware. Verified exploitability only.
            </p>
            {selected ? (
              <div className="space-y-4 text-sm">
                {isMemoryLeakFinding && (
                  <>
                    <div className="border border-slate-600 rounded-lg p-4 bg-slate-950/80">
                      <p className="text-slate-500 text-xs uppercase tracking-wider mb-2">Entropy Gauge (Richter scale)</p>
                      <EntropyGauge value={entropyDisplay} isLeak={isEntropyCritical} />
                    </div>
                    <div>
                      <p className="text-slate-500 text-xs uppercase tracking-wider mb-2">Deception — WAF bypass</p>
                      <DeceptionBadge />
                    </div>
                  </>
                )}
                {selected.trigger_reason && (
                  <p>
                    <span className="text-slate-500">Triggered by:</span>{' '}
                    <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/40 font-medium">
                      {selected.trigger_reason}
                    </span>
                  </p>
                )}
                <p><span className="text-slate-500">Title:</span> <span className="text-slate-200">{selected.title}</span></p>
                <p><span className="text-slate-500">Severity:</span> <span className={selected.severity === 'critical' ? 'text-red-400' : 'text-amber-400'}>{selected.severity}</span></p>
                <p><span className="text-slate-500">Verified:</span> {selected.verified ? <span className="text-emerald-400">Yes</span> : <span className="text-slate-500">No</span>}
                </p>
                <p><span className="text-slate-500">Status:</span> {selected.weaponization_status || 'SAFE (Proof of Exploitability Only)'}</p>
              </div>
            ) : (
              <p className="text-slate-500 text-sm">Select a finding to see details.</p>
            )}
          </div>
        </div>

        <div className="rounded-xl bg-slate-900/80 border border-slate-700/60 p-6 mb-6">
          <h2 className="text-lg font-semibold text-slate-200 mb-4">PoE Findings</h2>
          {loading && <p className="text-slate-500">Loading…</p>}
          {!loading && findings.length === 0 && (
            <p className="text-slate-500">No PoE findings. Run a PoE scan with a target URL.</p>
          )}
          {!loading && findings.length > 0 && (
            <ul className="space-y-2">
              {findings.map((f) => (
                <li key={f.id}>
                    <button
                    type="button"
                    onClick={() => setSelected(f)}
                    className={`w-full text-left rounded-lg px-4 py-3 border transition-colors ${
                      selected?.id === f.id
                        ? 'bg-violet-500/20 border-violet-500/50 text-white'
                        : 'bg-slate-800/60 border-slate-600 hover:border-slate-500 text-slate-200'
                    }`}
                  >
                    <span className="font-medium">{f.title}</span>
                    <span className={`ml-2 text-xs ${f.severity === 'critical' ? 'text-red-400' : 'text-amber-400'}`}>
                      {f.severity}
                    </span>
                    {f.verified && <span className="ml-2 text-xs text-emerald-400">Verified</span>}
                    {f.trigger_reason && (
                      <span className="ml-2 text-xs px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/40" title={f.trigger_reason}>
                        {f.trigger_reason.length > 28 ? f.trigger_reason.slice(0, 28) + '…' : f.trigger_reason}
                      </span>
                    )}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        {selected && (
          <div className="rounded-xl bg-slate-900/80 border border-slate-700/60 p-6">
            <h2 className="text-lg font-semibold text-slate-200 mb-2">
              {hasEntropyMap || bleedStartOffset != null ? 'Hex Heatmap (Memory X-Ray)' : 'Hex Viewer (IDA-style)'} — hover to highlight 64-bit stack (RBP/RIP)
            </h2>
            <p className="text-xs text-slate-500 mb-4">
              {hasEntropyMap || bleedStartOffset != null
                ? (bleedStartOffset != null
                  ? `Bleed start at offset ${bleedStartOffset} (sliding-window entropy). Color by block entropy.`
                  : 'Color by per-block entropy (256-byte windows).')
                : 'Offset 0-63: Buffer | 64-71: RBP | 72-79: RIP | 80+: Shellcode. Scroll for full payload.'}
            </p>
            <div className="rounded-lg bg-slate-950 border border-slate-700 overflow-hidden">
              <div className="px-3 py-2 border-b border-slate-700 text-slate-500 text-xs font-mono flex flex-wrap items-center gap-2">
                <span>VLN-{selected.id}</span>
                <span>{selected.weaponization_status || 'SAFE'}</span>
                {selected.trigger_reason && (
                  <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/40">Triggered by: {selected.trigger_reason}</span>
                )}
                {selected.expected_verification && (
                  <span className="text-emerald-400">Expected: &quot;{selected.expected_verification}&quot;</span>
                )}
                {hoveredSlot && <span className="text-cyan-400">→ {hoveredSlot}</span>}
              </div>
              <div className="p-4 overflow-x-auto" onMouseLeave={() => setHoveredSlot(null)}>
                {payloadBytes.length === 0 ? (
                  <span className="text-slate-500">(empty)</span>
                ) : (
                  <List
                    height={HEX_VIEWER_HEIGHT}
                    itemCount={hexRowCount}
                    itemSize={HEX_ROW_HEIGHT}
                    width="100%"
                    overscanCount={10}
                  >
                    {HexRow}
                  </List>
                )}
              </div>
              <div className="px-3 py-2 border-t border-slate-700 text-slate-500 text-xs">
                {hasEntropyMap || bleedStartOffset != null
                  ? 'Raw payload (Memory X-Ray: color by entropy map; red = bleed zone from backend)'
                  : 'Raw payload (virtualized, full length)'}:
              </div>
              <div className="p-4 overflow-x-auto max-h-96 overflow-y-auto" onMouseLeave={() => setHoveredSlot(null)}>
                {rawChunks.length === 0 ? (
                  <span className="text-slate-500">(none)</span>
                ) : (
                  <List
                    height={HEX_VIEWER_HEIGHT}
                    itemCount={rawChunks.length}
                    itemSize={RAW_ROW_HEIGHT}
                    width="100%"
                    overscanCount={15}
                  >
                    {RawChunkRow}
                  </List>
                )}
              </div>
            </div>
            {selected.footprint && (
              <div className="mt-4 p-3 rounded-lg bg-slate-800/60 border border-slate-600 text-slate-400 text-xs font-mono">
                <strong className="text-slate-300">Crash footprint:</strong> {selected.footprint}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
