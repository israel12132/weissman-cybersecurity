import { useEffect, useRef } from 'react'
import * as THREE from 'three'
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js'

const CYAN = 0x00f3ff
const MAGENTA = 0xff00ff
const emptyGlobeData = { scanPulses: [], threatStreams: [], criticalVulns: [], intelNodes: [] }
const ARC_MAX_AGE = 4
const PULSE_MAX_AGE = 3

function latLonToVector3(lat, lon, radius = 1) {
  const phi = (90 - lat) * (Math.PI / 180)
  const theta = (lon + 180) * (Math.PI / 180)
  return new THREE.Vector3(
    -radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta)
  )
}

function createTextSprite(text, color = 0x00f3ff, options = {}) {
  const { scale: scaleMul = 1, badge } = options
  const canvas = document.createElement('canvas')
  canvas.width = 320
  canvas.height = badge ? 80 : 64
  const ctx = canvas.getContext('2d')
  ctx.fillStyle = 'rgba(0,0,0,0.75)'
  ctx.fillRect(0, 0, canvas.width, canvas.height)
  ctx.font = 'bold 13px JetBrains Mono, monospace'
  ctx.fillStyle = color === 0xff3366 ? '#ff3366' : '#00f3ff'
  ctx.textAlign = 'center'
  ctx.fillText(text, 160, badge ? 36 : 38)
  if (badge) {
    ctx.font = 'bold 10px JetBrains Mono, monospace'
    ctx.fillStyle = '#ff3366'
    ctx.fillText('VERIFIED', 160, 58)
  }
  const tex = new THREE.CanvasTexture(canvas)
  tex.needsUpdate = true
  const mat = new THREE.SpriteMaterial({
    map: tex,
    transparent: true,
    depthWrite: false,
  })
  const sprite = new THREE.Sprite(mat)
  const sy = badge ? 0.08 : 0.06
  sprite.scale.set(0.32 * scaleMul, sy * scaleMul, 1)
  return sprite
}

function bezierArc(from, to, segments = 24) {
  const mid = new THREE.Vector3().addVectors(from, to).multiplyScalar(0.5)
  mid.normalize().multiplyScalar(1.25)
  const points = []
  for (let i = 0; i <= segments; i++) {
    const t = i / segments
    const t1 = 1 - t
    const b = new THREE.Vector3()
      .addScaledVector(from, t1 * t1)
      .addScaledVector(mid, 2 * t1 * t)
      .addScaledVector(to, t * t)
    points.push(b)
  }
  return points
}

export default function Globe({ data, realtimeArcs = [], realtimePulses = [], connectionStatus = 'online' }) {
  const containerRef = useRef(null)
  const rendererRef = useRef(null)
  const controlsRef = useRef(null)
  const sceneRef = useRef(null)
  const arcsRef = useRef([])
  const pulsesRef = useRef([])
  const clockRef = useRef(null)
  const isOffline = connectionStatus !== 'online'
  const safeData = isOffline ? emptyGlobeData : (data || emptyGlobeData)

  useEffect(() => {
    if (!containerRef.current) return

    const width = containerRef.current.clientWidth
    const height = containerRef.current.clientHeight
    const scene = new THREE.Scene()
    scene.background = new THREE.Color(0x000000)
    sceneRef.current = scene

    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000)
    camera.position.set(0, 0, 2.8)
    camera.lookAt(0, 0, 0)

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false })
    renderer.setSize(width, height)
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    containerRef.current.appendChild(renderer.domElement)
    rendererRef.current = renderer

    const controls = new OrbitControls(camera, renderer.domElement)
    controls.enableDamping = true
    controls.dampingFactor = 0.05
    controls.autoRotate = true
    controls.autoRotateSpeed = 0.35
    controls.minDistance = 1.2
    controls.maxDistance = 5
    controlsRef.current = controls

    const particleCount = 12000
    const positions = new Float32Array(particleCount * 3)
    const colors = new Float32Array(particleCount * 3)
    const c1 = new THREE.Color(CYAN)
    const c2 = new THREE.Color(MAGENTA)
    for (let i = 0; i < particleCount; i++) {
      const theta = (i / particleCount) * Math.PI * 2
      const phi = Math.acos(2 * (i % 97) / 97 - 1)
      const r = 1.002 + (i % 11) * 0.0009
      positions[i * 3] = r * Math.sin(phi) * Math.cos(theta)
      positions[i * 3 + 1] = r * Math.cos(phi)
      positions[i * 3 + 2] = r * Math.sin(phi) * Math.sin(theta)
      const col = i % 3 === 0 ? c2 : c1
      colors[i * 3] = col.r
      colors[i * 3 + 1] = col.g
      colors[i * 3 + 2] = col.b
    }
    const particleGeo = new THREE.BufferGeometry()
    particleGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3))
    particleGeo.setAttribute('color', new THREE.BufferAttribute(colors, 3))
    const particleMat = new THREE.PointsMaterial({
      size: 0.006,
      vertexColors: true,
      transparent: true,
      opacity: isOffline ? 0.25 : 0.75,
      sizeAttenuation: true,
    })
    const particles = new THREE.Points(particleGeo, particleMat)
    scene.add(particles)

    const ringGeo = new THREE.RingGeometry(1.28, 1.35, 64)
    const ringMat = new THREE.MeshBasicMaterial({
      color: CYAN,
      transparent: true,
      opacity: isOffline ? 0.04 : 0.12,
      side: THREE.DoubleSide,
    })
    const ring = new THREE.Mesh(ringGeo, ringMat)
    ring.rotation.x = Math.PI / 2
    scene.add(ring)

    scene.add(new THREE.AmbientLight(0x111111))
    const light = new THREE.PointLight(0x00f5ff, isOffline ? 0.1 : 0.35, 50)
    light.position.set(5, 5, 5)
    scene.add(light)

    const pulses = safeData.scanPulses || []
    const vulns = safeData.criticalVulns || []
    const streams = safeData.threatStreams || []
    const tagSpritesRef = { current: [] }

    if (pulses.length > 0) {
      const pulseGeo = new THREE.BufferGeometry()
      const pulsePos = new Float32Array(pulses.length * 3)
      const R = 1.02
      pulses.forEach((p, i) => {
        const v = latLonToVector3(p.lat, p.lon, R)
        pulsePos[i * 3] = v.x
        pulsePos[i * 3 + 1] = v.y
        pulsePos[i * 3 + 2] = v.z
        const label = (p.name || `Client ${p.client_id || i}`).toString().toUpperCase().slice(0, 12)
        const tag = createTextSprite(label, CYAN)
        tag.position.copy(v).multiplyScalar(1.08)
        scene.add(tag)
        tagSpritesRef.current.push({ sprite: tag, pulse: true })
      })
      pulseGeo.setAttribute('position', new THREE.BufferAttribute(pulsePos, 3))
      const pulseMat = new THREE.PointsMaterial({
        color: CYAN,
        size: 0.035,
        transparent: true,
        opacity: 0.9,
        sizeAttenuation: true,
      })
      scene.add(new THREE.Points(pulseGeo, pulseMat))
    }

    if (vulns.length > 0) {
      const vulnGeo = new THREE.BufferGeometry()
      const vulnPos = new Float32Array(vulns.length * 3)
      vulns.forEach((v, i) => {
        const vec = latLonToVector3(v.lat, v.lon, 1.03)
        vulnPos[i * 3] = vec.x
        vulnPos[i * 3 + 1] = vec.y
        vulnPos[i * 3 + 2] = vec.z
        const label = (v.client_name || 'TARGET').toString().toUpperCase().slice(0, 10)
        const tag = createTextSprite(label, 0xff3366, { badge: true })
        tag.position.copy(vec).multiplyScalar(1.12)
        scene.add(tag)
        tagSpritesRef.current.push({ sprite: tag, pulse: false, verified: true })
      })
      vulnGeo.setAttribute('position', new THREE.BufferAttribute(vulnPos, 3))
      scene.add(
        new THREE.Points(
          vulnGeo,
          new THREE.PointsMaterial({
            color: 0xff3366,
            size: 0.05,
            transparent: true,
            opacity: 0.95,
            sizeAttenuation: true,
          })
        )
      )
    }

    if (streams.length >= 2) {
      const linePoints = []
      streams.forEach((s) => {
        const from = latLonToVector3(s.from?.lat ?? 0, s.from?.lon ?? 0, 1.12)
        const to = latLonToVector3(s.to?.lat ?? 0, s.to?.lon ?? 0, 1.12)
        linePoints.push(from, to)
      })
      const lineGeo = new THREE.BufferGeometry().setFromPoints(linePoints)
      scene.add(
        new THREE.LineSegments(
          lineGeo,
          new THREE.LineBasicMaterial({
            color: 0xffb800,
            transparent: true,
            opacity: 0.3,
          })
        )
      )
    }

    const clock = new THREE.Clock()
    clockRef.current = clock
    let frameId = 0

    function animate() {
      frameId = requestAnimationFrame(animate)
      const elapsed = clock.getElapsedTime()
      controls.update()

      if (!isOffline) {
        tagSpritesRef.current.forEach(({ sprite, verified }) => {
          if (verified && sprite.material) {
            const pulse = 0.85 + 0.2 * Math.sin(elapsed * 2.5)
            sprite.material.opacity = pulse
          }
        })
      }

      arcsRef.current = arcsRef.current.filter((a) => {
        if (elapsed - a.birth > ARC_MAX_AGE) {
          scene.remove(a.line)
          a.line.geometry.dispose()
          a.line.material.dispose()
          if (a.sprite) {
            scene.remove(a.sprite)
            a.sprite.material?.map?.dispose()
            a.sprite.material?.dispose()
          }
          if (a.id) addedArcIdsRef.current.delete(a.id)
          return false
        }
        a.line.material.opacity = Math.max(0, 0.7 * (1 - (elapsed - a.birth) / ARC_MAX_AGE))
        if (a.sprite && a.sprite.material)
          a.sprite.material.opacity = Math.max(0, 1 - (elapsed - a.birth) / ARC_MAX_AGE)
        return true
      })

      pulsesRef.current = pulsesRef.current.filter((p) => {
        if (elapsed - p.birth > PULSE_MAX_AGE) {
          scene.remove(p.mesh)
          p.mesh.geometry.dispose()
          p.mesh.material.dispose()
          if (p.id) addedPulseIdsRef.current.delete(p.id)
          return false
        }
        const t = (elapsed - p.birth) / PULSE_MAX_AGE
        const scale = 1 + t * 2
        p.mesh.scale.setScalar(scale)
        p.mesh.material.opacity = Math.max(0, 1 - t)
        return true
      })

      renderer.render(scene, camera)
    }
    animate()

    const onResize = () => {
      if (!containerRef.current || !rendererRef.current) return
      const w = containerRef.current.clientWidth
      const h = containerRef.current.clientHeight
      camera.aspect = w / h
      camera.updateProjectionMatrix()
      rendererRef.current.setSize(w, h)
    }
    window.addEventListener('resize', onResize)

    return () => {
      window.removeEventListener('resize', onResize)
      cancelAnimationFrame(frameId)
      tagSpritesRef.current.forEach(({ sprite }) => {
        scene.remove(sprite)
        sprite.material?.map?.dispose()
        sprite.material?.dispose()
      })
      tagSpritesRef.current = []
      arcsRef.current.forEach((a) => {
        scene.remove(a.line)
        a.line.geometry.dispose()
        a.line.material.dispose()
        if (a.sprite) {
          scene.remove(a.sprite)
          a.sprite.material?.map?.dispose()
          a.sprite.material?.dispose()
        }
      })
      arcsRef.current = []
      pulsesRef.current.forEach((p) => {
        scene.remove(p.mesh)
        p.mesh.geometry.dispose()
        p.mesh.material.dispose()
      })
      pulsesRef.current = []
      if (containerRef.current && rendererRef.current?.domElement) {
        containerRef.current.removeChild(rendererRef.current.domElement)
      }
      rendererRef.current?.dispose()
      controlsRef.current = null
      sceneRef.current = null
      clockRef.current = null
    }
  }, [safeData, isOffline])

  const addedArcIdsRef = useRef(new Set())
  const addedPulseIdsRef = useRef(new Set())

  // Real-time arcs: only from WebSocket events (no simulation)
  useEffect(() => {
    if (!sceneRef.current || !clockRef.current || isOffline || !realtimeArcs.length) return
    const scene = sceneRef.current
    const elapsed = clockRef.current.getElapsedTime()
    realtimeArcs.forEach((arc) => {
      if (!arc.id || addedArcIdsRef.current.has(arc.id) || !arc.from || !arc.to) return
      addedArcIdsRef.current.add(arc.id)
      const from = latLonToVector3(arc.from.lat, arc.from.lon, 1.15)
      const to = latLonToVector3(arc.to.lat, arc.to.lon, 1.08)
      const arcPoints = bezierArc(from, to)
      const arcGeo = new THREE.BufferGeometry().setFromPoints(arcPoints)
      const arcMat = new THREE.LineBasicMaterial({
        color: arc.severity === 'critical' ? 0xff3366 : 0x00f3ff,
        transparent: true,
        opacity: 0.7,
      })
      const arcLine = new THREE.Line(arcGeo, arcMat)
      scene.add(arcLine)
      const label = (arc.label || 'INTEL').toString().slice(0, 14)
      const sprite = createTextSprite(label, arc.severity === 'critical' ? 0xff3366 : CYAN)
      sprite.position.copy(to).multiplyScalar(1.12)
      scene.add(sprite)
      arcsRef.current.push({ id: arc.id, line: arcLine, birth: elapsed, sprite })
    })
  }, [realtimeArcs, isOffline])

  useEffect(() => {
    if (isOffline) {
      addedArcIdsRef.current.clear()
      addedPulseIdsRef.current.clear()
    }
  }, [isOffline])

  // Red pulses at target location (emergency alerts)
  useEffect(() => {
    if (!sceneRef.current || !clockRef.current || isOffline || !realtimePulses.length) return
    const scene = sceneRef.current
    const elapsed = clockRef.current.getElapsedTime()
    realtimePulses.forEach((p) => {
      if (!p.id || addedPulseIdsRef.current.has(p.id) || p.lat == null || p.lon == null) return
      addedPulseIdsRef.current.add(p.id)
      const pos = latLonToVector3(p.lat, p.lon, 1.04)
      const geo = new THREE.RingGeometry(0.02, 0.06, 32)
      const mat = new THREE.MeshBasicMaterial({
        color: 0xff3366,
        transparent: true,
        opacity: 0.9,
        side: THREE.DoubleSide,
      })
      const mesh = new THREE.Mesh(geo, mat)
      mesh.position.copy(pos)
      mesh.rotation.x = -Math.PI / 2
      scene.add(mesh)
      pulsesRef.current.push({ id: p.id, mesh, birth: elapsed })
    })
  }, [realtimePulses, isOffline])

  return (
    <div
      className="w-full h-full min-h-0 rounded-lg overflow-hidden globe-container relative"
      data-offline={isOffline}
      style={isOffline ? { opacity: 0.4, filter: 'grayscale(0.5)' } : {}}
    >
      <div ref={containerRef} className="w-full h-full min-h-0" />
      {isOffline && (
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none connection-lost-overlay">
          <span className="connection-lost-text">CONNECTION LOST</span>
        </div>
      )}
    </div>
  )
}
