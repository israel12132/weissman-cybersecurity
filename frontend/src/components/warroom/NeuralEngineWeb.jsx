import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import { useClient } from '../../context/ClientContext'
import { useWarRoom } from '../../context/WarRoomContext'

const ENGINE_COLORS = {
  osint: '#22d3ee',
  asm: '#a855f7',
  ollama_fuzz: '#f97316',
  llm_path_fuzz: '#f97316',
  semantic_ai_fuzz: '#f97316',
  bola_idor: '#e879f9',
  microsecond_timing: '#38bdf8',
  ai_adversarial_redteam: '#ef4444',
  leak_hunter: '#f59e0b',
  supply_chain: '#6b7280',
}

/** Deterministic ring layout from client id — topology view, not geolocation. */
function nodePosition(index, total, width, height) {
  const cx = width / 2
  const cy = height / 2
  if (total <= 0) return [cx, cy]
  const radius = Math.min(width, height) * 0.38
  const angle = (index / total) * Math.PI * 2 - Math.PI / 2
  return [cx + radius * Math.cos(angle), cy + radius * Math.sin(angle)]
}

export default function NeuralEngineWeb({ width = 400, height = 300 }) {
  const { t } = useTranslation()
  const { clients, selectedClientId, clientConfig } = useClient()
  const { engineActivityCount } = useWarRoom()
  const enabledEngines = Array.isArray(clientConfig?.enabled_engines) ? clientConfig.enabled_engines : []
  const activity = engineActivityCount || {}

  const paths = useMemo(() => {
    const hub = [width / 2, height / 2]
    const out = []
    const list = selectedClientId
      ? clients.filter((c) => String(c.id) === String(selectedClientId))
      : clients
    const targets = list.slice(0, 8)
    targets.forEach((client, idx) => {
      const to = nodePosition(idx, targets.length, width, height)
      enabledEngines.forEach((engineId) => {
        const color = ENGINE_COLORS[engineId] || '#64748b'
        const activityKey = selectedClientId ? `${selectedClientId}_${engineId}` : `_${engineId}`
        const rate = activity[activityKey] || 0
        if (rate <= 0 && !selectedClientId) return
        out.push({
          id: `${client.id}-${engineId}`,
          engineId,
          clientName: client.name || `Client ${client.id}`,
          color,
          from: hub,
          to,
          isRedTeam: engineId === 'ai_adversarial_redteam',
          activityKey,
          rate,
        })
      })
    })
    return out
  }, [clients, selectedClientId, enabledEngines, width, height, activity])

  const hasClients = (selectedClientId ? clients.filter((c) => String(c.id) === String(selectedClientId)) : clients).length > 0
  const showEmpty = !hasClients || enabledEngines.length === 0
  const showIdle = !showEmpty && paths.length === 0

  return (
    <div className="relative" style={{ width, height }}>
      {showEmpty && (
        <div className="absolute inset-0 flex items-center justify-center text-center px-4">
          <p className="text-[10px] font-mono text-white/40 uppercase tracking-widest">
            {!hasClients
              ? t('components.neuralEngineWeb.no_clients')
              : t('components.neuralEngineWeb.no_engines')}
          </p>
        </div>
      )}
      {showIdle && (
        <div className="absolute inset-0 flex items-center justify-center text-center px-4">
          <p className="text-[10px] font-mono text-white/35 uppercase tracking-widest">
            {t('components.neuralEngineWeb.idle')}
          </p>
        </div>
      )}
      <svg
        width={width}
        height={height}
        className="max-w-full block overflow-hidden"
        style={{ verticalAlign: 'middle' }}
      >
        <defs>
          <linearGradient id="neuralGradBlue" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.9" />
            <stop offset="100%" stopColor="#22d3ee" stopOpacity="0.2" />
          </linearGradient>
          <linearGradient id="neuralGradRed" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#ef4444" stopOpacity="1" />
            <stop offset="100%" stopColor="#ef4444" stopOpacity="0.3" />
          </linearGradient>
          <filter id="neuralGlow">
            <feGaussianBlur stdDeviation="1" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <circle cx={width / 2} cy={height / 2} r="4" fill="#22d3ee" opacity="0.8" />
        <AnimatePresence>
          {paths.map((p) => {
            const rate = p.rate || activity[p.activityKey] || 0
            const duration = Math.max(0.4, 1.6 - rate * 0.15)
            const pulseDuration = Math.max(0.6, 1.4 - rate * 0.12)
            return (
              <motion.g
                key={p.id}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.4 }}
              >
                <motion.line
                  x1={p.from[0]}
                  y1={p.from[1]}
                  x2={p.to[0]}
                  y2={p.to[1]}
                  stroke={p.isRedTeam ? 'url(#neuralGradRed)' : p.color}
                  strokeWidth={p.isRedTeam ? 2.5 : 1.2}
                  strokeDasharray="6 4"
                  strokeLinecap="round"
                  fill="none"
                  opacity={0.85}
                  style={{
                    filter: p.isRedTeam ? 'url(#neuralGlow)' : 'none',
                    animation: p.isRedTeam
                      ? `neuralPulse ${pulseDuration}s ease-in-out infinite`
                      : rate > 0
                        ? `neuralFlow ${duration}s linear infinite`
                        : 'none',
                  }}
                />
                <title>{`${p.clientName} · ${p.engineId}`}</title>
              </motion.g>
            )
          })}
        </AnimatePresence>
        <style>{`
          @keyframes neuralPulse {
            0%, 100% { opacity: 0.85; stroke-width: 2.5; }
            50% { opacity: 1; stroke-width: 3; }
          }
          @keyframes neuralFlow {
            0% { stroke-dashoffset: 10; }
            100% { stroke-dashoffset: 0; }
          }
        `}</style>
      </svg>
    </div>
  )
}
