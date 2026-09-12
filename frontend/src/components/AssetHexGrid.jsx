import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../utils/apiFetch'

const NS = 'components.intelWidgets.assetHexGrid'

const STATUS_COLOR = {
  vulnerable: '#ef4444',
  exposed: '#f97316',
  unknown: '#64748b',
  ok: '#22d3ee',
  clean: '#4ade80',
}

function statusColor(status) {
  const s = (status || 'unknown').toLowerCase()
  return STATUS_COLOR[s] || STATUS_COLOR.unknown
}

export default function AssetHexGrid({ clientId: clientIdProp = null }) {
  const { t } = useTranslation()
  const [clientId, setClientId] = useState(clientIdProp)
  const [nodes, setNodes] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [clientsUnavailable, setClientsUnavailable] = useState(false)
  const [truncated, setTruncated] = useState(false)

  useEffect(() => {
    if (clientIdProp) {
      setClientId(clientIdProp)
      setClientsUnavailable(false)
      return
    }
    const ac = new AbortController()
    apiFetch('/api/clients', { signal: ac.signal })
      .then((data) => {
        if (data?.ok === false || data?.unavailable) {
          setClientsUnavailable(true)
          setClientId(null)
          return
        }
        const list = Array.isArray(data) ? data : (data?.clients ?? [])
        const first = list[0]
        setClientsUnavailable(false)
        setClientId(first?.id ?? null)
      })
      .catch((e) => {
        if (e?.name === 'AbortError') return
        setClientsUnavailable(true)
        setClientId(null)
      })
    return () => ac.abort()
  }, [clientIdProp])

  useEffect(() => {
    if (!clientId) {
      setNodes([])
      setTruncated(false)
      return
    }
    const ac = new AbortController()
    setLoading(true)
    setError(null)
    setTruncated(false)
    apiFetch(`/api/clients/${clientId}/attack-surface-graph`, { signal: ac.signal })
      .then((data) => {
        if (data?.ok === false || data?.unavailable) {
          throw new Error(data.detail || t(`${NS}.error`))
        }
        setNodes(Array.isArray(data?.nodes) ? data.nodes : [])
        setTruncated(Boolean(data?.truncated) || (Array.isArray(data?.nodes) && data.nodes.length > 24))
      })
      .catch((e) => {
        if (e?.name === 'AbortError') return
        setNodes([])
        setTruncated(false)
        setError(e.message || t(`${NS}.error`))
      })
      .finally(() => {
        if (!ac.signal.aborted) setLoading(false)
      })
    return () => ac.abort()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clientId])

  return (
    <div className="asset-hex-grid">
      <div className="text-cyber-cyan font-semibold text-xs tracking-widest mb-2 uppercase">
        {t(`${NS}.title`)}
      </div>

      {clientsUnavailable && (
        <p
          className="text-[10px] text-rose-400/80 font-mono"
          data-testid="asset-hex-clients-unavailable"
          role="alert"
        >
          {t(`${NS}.unavailable`)}
        </p>
      )}

      {!clientId && !loading && !clientsUnavailable && (
        <p className="text-[10px] text-white/40 font-mono">{t(`${NS}.select_client`)}</p>
      )}

      {clientId && loading && (
        <p className="text-[10px] text-white/40 font-mono animate-pulse">{t(`${NS}.loading`)}</p>
      )}

      {clientId && !loading && error && (
        <p className="text-[10px] text-rose-400/80 font-mono">{t(`${NS}.error`)}</p>
      )}

      {clientId && !loading && !error && truncated && (
        <p
          className="text-[10px] text-amber-300/80 font-mono"
          data-testid="asset-hex-truncated"
          role="status"
        >
          {t(`${NS}.truncated`)}
        </p>
      )}

      {clientId && !loading && !error && nodes.length === 0 && (
        <p className="text-[10px] text-white/40 font-mono">{t(`${NS}.empty`)}</p>
      )}

      {nodes.length > 0 && (
        <div
          className="grid gap-1.5 justify-items-center max-h-40 overflow-y-auto"
          style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}
        >
          {nodes.slice(0, 24).map((node) => {
            const color = statusColor(node.status)
            const label = (node.label || node.id || '?').toString()
            const short = label.length > 8 ? `${label.slice(0, 7)}…` : label
            return (
              <div
                key={node.id || label}
                title={`${label} (${node.node_type || 'asset'}) — ${node.status || 'unknown'}`}
                className="hex-cell w-8 h-9 flex items-center justify-center rounded-sm border font-mono text-[9px] transition-all duration-300"
                style={{
                  borderColor: `${color}66`,
                  background: `${color}14`,
                  color,
                }}
              >
                {short}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
