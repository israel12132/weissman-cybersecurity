import React, { useState, useEffect, useCallback, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ComposableMap, Geographies, Geography, ZoomableGroup, Marker, Line } from 'react-simple-maps'
import { useClient } from '../../context/ClientContext'
import { useWarRoom } from '../../context/WarRoomContext'
import { useWarRoomSound } from '../../hooks/useWarRoomSound'
import { stableGeoFromLabel } from '../../lib/stableGeoFromLabel'
import { apiFetch } from '../../lib/apiBase'

const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json'
const US_CENTER = [37.09, -95.71]
const PATROL_IDLE_MS = 30000
const PATROL_PAN_SPEED = 0.08

function geoForTarget(domainOrName) {
  return stableGeoFromLabel(domainOrName)
}

export default function SatelliteDroneMap() {
  const { selectedClient, selectedClientId } = useClient()
  const { vulnMarkers, setVulnMarkers, mapZoomComplete, setMapZoomComplete, lastNewTarget, setLastNewTarget, discoveredTargets, lastLatencyMs, US_CENTER: usCenter } = useWarRoom()
  const { playZoom } = useWarRoomSound()
  const [center, setCenter] = useState(US_CENTER)
  const [zoom, setZoom] = useState(1)
  const [targetCoord, setTargetCoord] = useState(null)
  const [zoomPhase, setZoomPhase] = useState('idle')
  const [patrolMode, setPatrolMode] = useState(false)
  const [targetCoordsList, setTargetCoordsList] = useState([])
  const lastTargetTimeRef = useRef(0)
  const patrolOffsetRef = useRef(0)

  useEffect(() => {
    setTargetCoordsList([])
  }, [selectedClientId])

  useEffect(() => {
    if (!lastNewTarget || !selectedClientId || String(lastNewTarget.client_id) !== String(selectedClientId)) return
    const host = lastNewTarget.host || ''
    const coord = geoForTarget(host)
    setTargetCoord(coord)
    setVulnMarkers([])
    setMapZoomComplete(false)
    setZoomPhase('zooming')
    setCenter(coord)
    setZoom(3)
    lastTargetTimeRef.current = Date.now()
    setPatrolMode(false)
    setTargetCoordsList((prev) => {
      const next = [...prev, coord]
      return next.slice(-16)
    })
    playZoom()
    setLastNewTarget(null)
  }, [lastNewTarget, selectedClientId, setVulnMarkers, setMapZoomComplete, setLastNewTarget, playZoom])

  useEffect(() => {
    if (zoomPhase !== 'zooming') return
    const t = setTimeout(() => {
      setZoomPhase('done')
      setMapZoomComplete(true)
    }, 1200)
    return () => clearTimeout(t)
  }, [zoomPhase, setMapZoomComplete])

  useEffect(() => {
    if (!selectedClientId) return
    const tid = setTimeout(() => {
      if (zoomPhase === 'idle' && Date.now() - lastTargetTimeRef.current > PATROL_IDLE_MS) {
        setPatrolMode(true)
      }
    }, PATROL_IDLE_MS)
    return () => clearTimeout(tid)
  }, [zoomPhase, selectedClientId])

  useEffect(() => {
    if (!patrolMode) return
    const id = setInterval(() => {
      patrolOffsetRef.current += PATROL_PAN_SPEED
      const angle = patrolOffsetRef.current
      setCenter([37.09 + Math.sin(angle) * 25, -95.71 + Math.cos(angle * 0.7) * 15])
      setZoom(1.2)
    }, 200)
    return () => clearInterval(id)
  }, [patrolMode])

  useEffect(() => {
    if (lastNewTarget && String(lastNewTarget.client_id) === String(selectedClientId)) setPatrolMode(false)
  }, [lastNewTarget, selectedClientId])

  useEffect(() => {
    if (zoomPhase !== 'done' || !selectedClientId || !targetCoord) return
    apiFetch(`/api/clients/${selectedClientId}/findings`)
      .then((r) => (r.ok ? r.json() : []))
      .then((data) => {
        const list = data?.findings ?? (Array.isArray(data) ? data : [])
        const arr = Array.isArray(list) ? list : []
        const count = Math.min(arr.length, 8)
        setVulnMarkers(Array.from({ length: count }, (_, i) => ({
          coord: [targetCoord[0] + (i - count / 2) * 0.08, targetCoord[1]],
        })))
      })
      .catch(() => {})
  }, [zoomPhase, selectedClientId, targetCoord, setVulnMarkers])

  return (
    <motion.div
      className="absolute inset-0 rounded-2xl overflow-hidden bg-slate-950/90 border border-white/10"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.4 }}
    >
      <div className="absolute inset-0">
        <ComposableMap
          projection="geoMercator"
          projectionConfig={{ scale: 147 }}
          style={{ width: '100%', height: '100%' }}
        >
          <ZoomableGroup center={center} zoom={zoom}>
            <Geographies geography={GEO_URL}>
              {({ geographies }) =>
                geographies.map((geo) => (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    fill="#0f172a"
                    stroke="rgba(71, 85, 105, 0.4)"
                    strokeWidth={0.4}
                    style={{ outline: 'none' }}
                  />
                ))
              }
            </Geographies>
            {targetCoordsList.length > 1 && (
              <Line
                coordinates={[
                  [(usCenter || US_CENTER)[1], (usCenter || US_CENTER)[0]],
                  ...targetCoordsList.map(([lat, lng]) => [lng, lat]),
                ]}
                stroke="#22d3ee"
                strokeWidth={1}
                strokeDasharray="4 3"
                strokeOpacity={0.6}
                fill="none"
              />
            )}
            <Marker coordinates={usCenter || US_CENTER}>
              <motion.circle
                r={4}
                fill="#22d3ee"
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ delay: 0.2, type: 'spring', stiffness: 200 }}
              />
              <circle r={6} fill="none" stroke="#22d3ee" strokeWidth={1} opacity={0.6} />
            </Marker>
            {targetCoordsList.map((coord, idx) => (
              <Marker key={`t-${idx}`} coordinates={coord}>
                <circle r={3} fill="#f97316" fillOpacity={0.9} stroke="#f97316" strokeWidth={1} />
              </Marker>
            ))}
            <AnimatePresence>
              {targetCoord && (
                <Marker key="target" coordinates={targetCoord}>
                  <motion.circle
                    r={5}
                    fill="#f97316"
                    initial={{ scale: 0, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    transition={{ delay: 0.5, type: 'spring' }}
                  />
                  <circle r={8} fill="none" stroke="#f97316" strokeWidth={1.5} opacity={0.5} />
                </Marker>
              )}
            </AnimatePresence>
            {mapZoomComplete && vulnMarkers.length > 0 && (
              <>
                {vulnMarkers.map((m, i) => {
                  const dataGlitch = lastLatencyMs != null && lastLatencyMs > 500
                  return (
                    <Marker key={i} coordinates={m.coord}>
                      <motion.g
                        initial={{ scale: 0, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        transition={{ delay: i * 0.05 }}
                        className={dataGlitch ? 'animate-glitch' : ''}
                      >
                        <circle r={6} fill="#ef4444" className="animate-pulse" />
                        <circle
                          r={10}
                          fill="none"
                          stroke="#ef4444"
                          strokeWidth={2}
                          opacity={0.6}
                          style={{ filter: dataGlitch ? 'drop-shadow(0 0 12px #ef4444)' : 'drop-shadow(0 0 6px #ef4444)' }}
                        />
                      </motion.g>
                    </Marker>
                  )
                })}
              </>
            )}
          </ZoomableGroup>
        </ComposableMap>
      </div>
      <div className="absolute bottom-2 left-2 text-[10px] font-mono text-white/50 uppercase tracking-wider">
        {patrolMode ? 'Patrol mode' : zoomPhase === 'zooming' ? 'Drone zooming…' : mapZoomComplete ? 'Markers active' : 'Satellite'}
      </div>
    </motion.div>
  )
}
