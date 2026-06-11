import React, { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Cpu, FileCode, MapPin } from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'

const NS = 'components.cockpitWidgets.runtimeExecutionFlow'

export default function RuntimeExecutionFlow({ clientId, findingId }) {
  const { t } = useTranslation()
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
        <span className="text-xs font-semibold text-white uppercase tracking-wider">{t(`${NS}.title`)}</span>
      </div>
      <div className="p-3 max-h-48 overflow-y-auto">
        {loading ? (
          <p className="text-xs text-white/50">{t(`${NS}.loading`)}</p>
        ) : traces.length === 0 ? (
          <p className="text-xs text-white/50">
            {findingId
              ? t(`${NS}.noTracesFinding`)
              : t(`${NS}.noTracesClient`)}
          </p>
        ) : (
          <ul className="space-y-2">
            {traces.map((trace, i) => (
              <li key={trace.id || i} className="flex items-start gap-2 text-xs font-mono">
                <MapPin className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                <div className="min-w-0">
                  {trace.source_file && (
                    <span className="text-[#22d3ee] flex items-center gap-1">
                      <FileCode className="w-3 h-3" />
                      {trace.source_file}
                      {trace.line_number != null && <span className="text-white/70">:{trace.line_number}</span>}
                    </span>
                  )}
                  {trace.function_name && <span className="text-white/80 block">{trace.function_name}</span>}
                  {trace.payload_hash && (
                    <span className="text-white/50 block truncate">
                      {t(`${NS}.payloadHash`, { hash: trace.payload_hash })}
                    </span>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
