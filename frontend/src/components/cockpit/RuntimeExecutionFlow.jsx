/**
 * CNAPP Layer 2: Runtime Execution Flow — eBPF/IAST traces for a finding (file, line, function).
 * Shows exact code/memory path when exploit is proven. Data from live runtime-traces API.
 */
import React, { useEffect, useState } from 'react'
import { Cpu, FileCode, MapPin } from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'

export default function RuntimeExecutionFlow({ clientId, findingId }) {
  const [traces, setTraces] = useState([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!clientId) {
      setTraces([])
      return
    }
    setLoading(true)
    const url = findingId
      ? `/api/clients/${clientId}/runtime-traces?finding_id=${encodeURIComponent(findingId)}`
      : `/api/clients/${clientId}/runtime-traces`
    apiFetch(url)
      .then(r => (r.ok ? r.json() : { traces: [] }))
      .then(d => {
        setTraces(d.traces || [])
      })
      .catch(() => setTraces([]))
      .finally(() => setLoading(false))
  }, [clientId, findingId])

  if (!clientId) return null

  return (
    <div className="rounded-xl border border-white/10 bg-black/40 backdrop-blur-sm overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-white/10 bg-black/30">
        <Cpu className="w-4 h-4 text-[#22d3ee]" />
        <span className="text-xs font-semibold text-white uppercase tracking-wider">Runtime Execution Flow (eBPF / IAST)</span>
      </div>
      <div className="p-3 max-h-48 overflow-y-auto">
        {loading ? (
          <p className="text-xs text-white/50">Loading traces…</p>
        ) : traces.length === 0 ? (
          <p className="text-xs text-white/50">
            {findingId
              ? 'No runtime traces linked to this finding. Deploy the IAST agent or enable eBPF ingestion to see execution flow.'
              : 'No runtime traces for this client yet.'}
          </p>
        ) : (
          <ul className="space-y-2">
            {traces.map((t, i) => (
              <li key={t.id || i} className="flex items-start gap-2 text-xs font-mono">
                <MapPin className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                <div className="min-w-0">
                  {t.source_file && (
                    <span className="text-[#22d3ee] flex items-center gap-1">
                      <FileCode className="w-3 h-3" />
                      {t.source_file}
                      {t.line_number != null && <span className="text-white/70">:{t.line_number}</span>}
                    </span>
                  )}
                  {t.function_name && <span className="text-white/80 block">{t.function_name}</span>}
                  {t.payload_hash && <span className="text-white/50 block truncate">payload_hash: {t.payload_hash}</span>}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
