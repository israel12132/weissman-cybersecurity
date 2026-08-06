import { useState, useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import { useClient } from '../../context/ClientContext'
import { useWarRoom } from '../../context/WarRoomContext'
import { useWarRoomSound } from '../../hooks/useWarRoomSound'
import { stableGeoFromLabel } from '../../lib/stableGeoFromLabel'
import { apiFetch } from '../../utils/apiFetch'
import GeoWorldMap, { GeoMarker, GeoLine } from '../ui/GeoWorldMap'

const NS = 'components.cockpitWidgets.satelliteDroneMap'
const US_CENTER = [37.09, -95.71]
const PATROL_IDLE_MS = 30000
const PATROL_PAN_SPEED = 0.08

/** stableGeoFromLabel returns [lat, lng]; the map expects [lng, lat]. */
function geoForTarget(domainOrName) {
  const [lat, lng] = stableGeoFromLabel(domainOrName)
  return [lng, lat]
}

function mapCenterFromLatLng([lat, lng]) {
  return [lng, lat]
}

export default function SatelliteDroneMap() {
  const { t } = useTranslation()
  const { selectedClientId } = useClient()
  const { vulnMarkers, setVulnMarkers, mapZoomComplete, setMapZoomComplete, lastNewTarget, setLastNewTarget, discoveredTargets, lastLatencyMs, US_CENTER: usCenter } = useWarRoom()
  const { playZoom } = useWarRoomSound()
  const usMapCenter = mapCenterFromLatLng(usCenter || US_CENTER)
  const [center, setCenter] = useState(usMapCenter)
  const [zoom, setZoom] = useState(1)
  const [targetCoord, setTargetCoord] = useState(null)
  const [zoomPhase, setZoomPhase] = useState('idle')
  const [patrolMode, setPatrolMode] = useState(false)
  const [targetCoordsList, setTargetCoordsList] = useState([])
  const lastTargetTimeRef = useRef(0)
  const patrolOffsetRef = useRef(0)

  // Seed the map with targets already discovered for this client (live telemetry
  // accumulated in WarRoom context) so the flight path isn't empty on mount — new
  // targets still animate in on top via the lastNewTarget effect below.
  useEffect(() => {
    const seeded = (discoveredTargets || [])
      .filter((tgt) => String(tgt.client_id) === String(selectedClientId) && tgt.host)
      .map((tgt) => geoForTarget(tgt.host))
      .slice(-16)
    setTargetCoordsList(seeded)
  }, [selectedClientId, discoveredTargets])

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
    const timer = setTimeout(() => {
      setZoomPhase('done')
      setMapZoomComplete(true)
    }, 1200)
    return () => clearTimeout(timer)
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
      setCenter([-95.71 + Math.cos(angle * 0.7) * 15, 37.09 + Math.sin(angle) * 25])
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
      .then((data) => {
        const list = data?.findings ?? (Array.isArray(data) ? data : [])
        const arr = Array.isArray(list) ? list : []
        const count = Math.min(arr.length, 8)
        setVulnMarkers(Array.from({ length: count }, (_, i) => ({
          coord: [targetCoord[0] + (i - count / 2) * 0.08, targetCoord[1]], // [lng, lat]
        })))
      })
      // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
      .catch(() => {})
  }, [zoomPhase, selectedClientId, targetCoord, setVulnMarkers])

  const statusLabel = patrolMode
    ? t(`${NS}.patrolMode`)
    : zoomPhase === 'zooming'
      ? t(`${NS}.zooming`)
      : mapZoomComplete
        ? t(`${NS}.markersActive`)
        : t(`${NS}.satellite`)

  return (
    <motion.div
      className="absolute inset-0 rounded-2xl overflow-hidden bg-[var(--bg-0)]/90 border border-white/10"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.4 }}
    >
      <div className="absolute inset-0">
        <GeoWorldMap
          projection="geoMercator"
          projectionScale={147}
          center={center}
          zoom={zoom}
          geographyFill="#0f172a"
          geographyStroke="rgba(71, 85, 105, 0.4)"
          geographyStrokeWidth={0.4}
          geographyStyle={{ outline: 'none' }}
          style={{ width: '100%', height: '100%' }}
        >
          {targetCoordsList.length > 1 && (
            <GeoLine
              coordinates={[
                [(usCenter || US_CENTER)[1], (usCenter || US_CENTER)[0]],
                // targetCoordsList already holds [lng, lat] (from geoForTarget),
                // the order the map expects — same as the markers below.
                ...targetCoordsList,
              ]}
              stroke="#22d3ee"
              strokeWidth={1}
              strokeDasharray="4 3"
              strokeOpacity={0.6}
            />
          )}
          <GeoMarker coordinates={usMapCenter}>
            <motion.circle
              r={4}
              fill="#22d3ee"
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ delay: 0.2, type: 'spring', stiffness: 200 }}
            />
            <circle r={6} fill="none" stroke="#22d3ee" strokeWidth={1} opacity={0.6} />
          </GeoMarker>
          {targetCoordsList.map((coord, idx) => (
            <GeoMarker key={`t-${idx}`} coordinates={coord}>
              <circle r={3} fill="#f97316" fillOpacity={0.9} stroke="#f97316" strokeWidth={1} />
            </GeoMarker>
          ))}
          <AnimatePresence>
            {targetCoord && (
              <GeoMarker key="target" coordinates={targetCoord}>
                <motion.circle
                  r={5}
                  fill="#f97316"
                  initial={{ scale: 0, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  transition={{ delay: 0.5, type: 'spring' }}
                />
                <circle r={8} fill="none" stroke="#f97316" strokeWidth={1.5} opacity={0.5} />
              </GeoMarker>
            )}
          </AnimatePresence>
          {mapZoomComplete && vulnMarkers.length > 0 && (
            <>
              {vulnMarkers.map((m, i) => {
                const dataGlitch = lastLatencyMs != null && lastLatencyMs > 500
                return (
                  <GeoMarker key={i} coordinates={m.coord}>
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
                  </GeoMarker>
                )
              })}
            </>
          )}
        </GeoWorldMap>
      </div>
      <div className="absolute bottom-2 left-2 text-[10px] font-mono text-white/50 uppercase tracking-wider">
        {statusLabel}
      </div>
    </motion.div>
  )
}
