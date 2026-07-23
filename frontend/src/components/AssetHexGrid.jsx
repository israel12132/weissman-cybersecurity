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

  useEffect(() => {
    if (clientIdProp) {
      setClientId(clientIdProp)
      return
    }
    let cancelled = false
    apiFetch('/api/clients')
      .then((data) => {
        if (cancelled) return
        const first = (data?.clients ?? [])[0]
        setClientId(first?.id ?? null)
      })
      .catch(() => {
        if (!cancelled) setClientId(null)
      })
    return () => { cancelled = true }
  }, [clientIdProp])

  useEffect(() => {
    if (!clientId) {
      setNodes([])
      return
    }
    let cancelled = false
    setLoading(true)
    setError(null)
    apiFetch(`/api/clients/${clientId}/attack-surface-graph`)
      .then((data) => {
        if (cancelled) return
        setNodes(Array.isArray(data?.nodes) ? data.nodes : [])
      })
      .catch((e) => {
        if (!cancelled) {
          setNodes([])
          setError(e.message || 'load failed')
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => { cancelled = true }
  }, [clientId])

  return (
    <div className="asset-hex-grid">
      <div className="text-cyber-cyan font-semibold text-xs tracking-widest mb-2 uppercase">
        {t(`${NS}.title`)}
      </div>

      {!clientId && !loading && (
        <p className="text-[10px] text-white/40 font-mono">{t(`${NS}.select_client`)}</p>
      )}

      {clientId && loading && (
        <p className="text-[10px] text-white/40 font-mono animate-pulse">{t(`${NS}.loading`)}</p>
      )}

      {clientId && !loading && error && (
        <p className="text-[10px] text-rose-400/80 font-mono">{t(`${NS}.error`)}</p>
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
