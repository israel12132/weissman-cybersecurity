import { useEffect, useRef, useState } from 'react'
import * as THREE from 'three'
import { cn } from '../../lib/cn'

const SEVERITY_HEX = {
  critical: 0xf87171,
  high: 0xfb923c,
  medium: 0xfbbf24,
  low: 0x4ade80,
  info: 0x38bdf8,
  default: 0x22d3ee,
}
const SEVERITY_CSS = {
  critical: 'bg-severity-critical',
  high: 'bg-severity-high',
  medium: 'bg-severity-medium',
  low: 'bg-severity-low',
  info: 'bg-severity-info',
  default: 'bg-accent-cyan',
}

/** Deterministic Fibonacci-sphere position for node `i` of `n` (no RNG). */
function spherePos(i, n, radius) {
  if (n <= 1) return [0, 0, 0]
  const y = 1 - (i / (n - 1)) * 2
  const r = Math.sqrt(Math.max(0, 1 - y * y))
  const theta = Math.PI * (3 - Math.sqrt(5)) * i // golden angle
  return [Math.cos(theta) * r * radius, y * radius, Math.sin(theta) * r * radius]
}

/**
 * Topology3D — a real-time 3D network topology (Three.js). Nodes are placed on a
 * deterministic sphere, coloured by severity, and connected by links; the graph
 * auto-rotates. WebGL is guarded — in headless/unsupported environments it
 * degrades to an accessible node list. A keyboard-navigable node list is always
 * rendered alongside the canvas for a11y and selection.
 *
 * @param {Array<{id:string,label?:string,severity?:string}>} nodes
 * @param {Array<{source:string,target:string}>} [links]
 * @param {number} [height=360] @param {boolean} [autoRotate=true]
 * @param {(node:object)=>void} [onNodeClick]
 */
export default function Topology3D({
  nodes = [],
  links = [],
  height = 360,
  autoRotate = true,
  onNodeClick,
  className,
  ...props
}) {
  const mountRef = useRef(null)
  const [webglFailed, setWebglFailed] = useState(false)

  useEffect(() => {
    const mount = mountRef.current
    if (!mount || nodes.length === 0) return undefined

    let renderer
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    } catch {
      setWebglFailed(true)
      return undefined
    }
    if (!renderer || typeof renderer.render !== 'function') {
      setWebglFailed(true)
      return undefined
    }

    const width = mount.clientWidth || 480
    renderer.setSize(width, height)
    renderer.setPixelRatio(Math.min(2, typeof window !== 'undefined' ? window.devicePixelRatio || 1 : 1))
    mount.appendChild(renderer.domElement)

    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(55, width / height, 0.1, 1000)
    camera.position.z = 60

    const group = new THREE.Group()
    scene.add(group)

    const radius = 22
    const posById = new Map()
    const sphereGeo = new THREE.SphereGeometry(1.1, 16, 16)
    nodes.forEach((n, i) => {
      const [x, y, z] = spherePos(i, nodes.length, radius)
      posById.set(n.id, [x, y, z])
      const color = SEVERITY_HEX[n.severity] ?? SEVERITY_HEX.default
      const mesh = new THREE.Mesh(sphereGeo, new THREE.MeshBasicMaterial({ color }))
      mesh.position.set(x, y, z)
      group.add(mesh)
    })

    if (links.length) {
      const linkMat = new THREE.LineBasicMaterial({ color: 0x334155, transparent: true, opacity: 0.5 })
      const points = []
      links.forEach((l) => {
        const a = posById.get(l.source)
        const b = posById.get(l.target)
        if (a && b) {
          points.push(new THREE.Vector3(...a), new THREE.Vector3(...b))
        }
      })
      if (points.length) {
        const geo = new THREE.BufferGeometry().setFromPoints(points)
        scene.add(new THREE.LineSegments(geo, linkMat))
      }
    }

    let frame
    const animate = () => {
      if (autoRotate) {
        group.rotation.y += 0.0025
        group.rotation.x += 0.0008
      }
      renderer.render(scene, camera)
      frame =
        typeof requestAnimationFrame === 'function' ? requestAnimationFrame(animate) : undefined
    }
    animate()

    const onResize = () => {
      const w = mount.clientWidth || width
      camera.aspect = w / height
      camera.updateProjectionMatrix()
      renderer.setSize(w, height)
    }
    if (typeof window !== 'undefined') window.addEventListener('resize', onResize)

    return () => {
      if (frame && typeof cancelAnimationFrame === 'function') cancelAnimationFrame(frame)
      if (typeof window !== 'undefined') window.removeEventListener('resize', onResize)
      sphereGeo.dispose()
      try {
        renderer.dispose()
      } catch {
        /* ignore */
      }
      if (renderer.domElement && renderer.domElement.parentNode === mount) {
        mount.removeChild(renderer.domElement)
      }
    }
  }, [nodes, links, height, autoRotate])

  return (
    <div className={cn('flex flex-col gap-2', className)} {...props}>
      <div
        ref={mountRef}
        role="img"
        aria-label="3D network topology"
        className={cn(
          'relative overflow-hidden rounded-xl border border-border-default bg-bg-1',
          webglFailed && 'flex items-center justify-center',
        )}
        style={{ height }}
      >
        {webglFailed && (
          <span className="text-xs text-text-muted">
            3D rendering unavailable — see the node list below.
          </span>
        )}
      </div>

      {/* Accessible + keyboard-selectable node list (also the WebGL fallback). */}
      <ul className="flex flex-wrap gap-1.5" aria-label="Topology nodes">
        {nodes.map((n) => {
          const sev = SEVERITY_CSS[n.severity] ?? SEVERITY_CSS.default
          const label = n.label || n.id
          const inner = (
            <>
              <span className={cn('size-2 rounded-full', sev)} aria-hidden="true" />
              {label}
            </>
          )
          return (
            <li key={n.id}>
              {onNodeClick ? (
                <button
                  type="button"
                  onClick={() => onNodeClick(n)}
                  className="inline-flex items-center gap-1.5 rounded-full border border-border-default bg-bg-2 px-2 py-0.5 text-[11px] text-text-tertiary hover:border-border-strong hover:text-text-secondary focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]"
                >
                  {inner}
                </button>
              ) : (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-border-default bg-bg-2 px-2 py-0.5 text-[11px] text-text-tertiary">
                  {inner}
                </span>
              )}
            </li>
          )
        })}
      </ul>
    </div>
  )
}

export { Topology3D }
