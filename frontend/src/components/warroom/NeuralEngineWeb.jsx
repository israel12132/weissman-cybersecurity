import React, { useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useClient } from '../../context/ClientContext'
import { useWarRoom } from '../../context/WarRoomContext'
import { stableGeoFromLabel } from '../../lib/stableGeoFromLabel'

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

function geoForTarget(domainOrName) {
  return stableGeoFromLabel(domainOrName)
}

function project(lat, lng, width, height) {
  const x = (lng + 180) / 360 * width
  const y = (1 - (lat + 90) / 180) * height * 0.5 + height * 0.25
  return [x, y]
}

export default function NeuralEngineWeb({ width = 400, height = 300 }) {
  const { clients, selectedClientId, clientConfig } = useClient()
  const { US_CENTER, engineActivityCount } = useWarRoom()
  const enabledEngines = Array.isArray(clientConfig?.enabled_engines) ? clientConfig.enabled_engines : []
  const activity = engineActivityCount || {}

  const paths = useMemo(() => {
    const [usLng, usLat] = US_CENTER
    const us = project(usLat, usLng, width, height)
    const out = []
    const list = selectedClientId ? clients.filter((c) => String(c.id) === String(selectedClientId)) : clients
    list.slice(0, 8).forEach((client) => {
      const name = client.name || client.domains
      let dom = name
      if (typeof client.domains === 'string') {
        try {
          const arr = JSON.parse(client.domains)
          dom = Array.isArray(arr) && arr[0] ? arr[0] : name
        } catch (_) {}
      }
      const [lat, lng] = geoForTarget(dom)
      const t = project(lat, lng, width, height)
      enabledEngines.forEach((engineId) => {
        const color = ENGINE_COLORS[engineId] || '#64748b'
        const activityKey = selectedClientId ? `${selectedClientId}_${engineId}` : `_${engineId}`
        out.push({
          id: `${client.id}-${engineId}`,
          engineId,
          color,
          from: us,
          to: t,
          isRedTeam: engineId === 'ai_adversarial_redteam',
          activityKey,
        })
      })
    })
    return out
  }, [clients, selectedClientId, enabledEngines, width, height, US_CENTER])

  return (
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
      <AnimatePresence>
        {paths.map((p) => {
          const rate = activity[p.activityKey] || 0
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
                  animation: p.isRedTeam ? `neuralPulse ${pulseDuration}s ease-in-out infinite` : rate > 0 ? `neuralFlow ${duration}s linear infinite` : 'none',
                }}
              />
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
  )
}
