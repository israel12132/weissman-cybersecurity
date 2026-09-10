import { useEffect, useRef } from 'react'

/**
 * Lightweight constellation of live engine IDs. Not a tenant graph.
 */
export default function EngineConstellation({ ids = [], className = '' }) {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return undefined
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches
    const ctx = canvas.getContext('2d')
    if (!ctx) return undefined
    if (!ids.length) {
      ctx.clearRect(0, 0, canvas.width, canvas.height)
      return undefined
    }

    const nodes = ids.slice(0, 90).map((id, i) => {
      const a = (i / 90) * Math.PI * 2
      const r = 0.18 + (i % 7) * 0.09
      return { id, a, r, x: 0, y: 0 }
    })

    let raf = 0
    let t = 0
    const draw = () => {
      const dpr = window.devicePixelRatio || 1
      const w = canvas.clientWidth
      const h = canvas.clientHeight
      if (canvas.width !== Math.floor(w * dpr) || canvas.height !== Math.floor(h * dpr)) {
        canvas.width = Math.floor(w * dpr)
        canvas.height = Math.floor(h * dpr)
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      ctx.clearRect(0, 0, w, h)
      const cx = w * 0.55
      const cy = h * 0.48
      const spin = reduce ? 0 : t * 0.00012
      nodes.forEach((n) => {
        n.x = cx + Math.cos(n.a + spin) * n.r * Math.min(w, h)
        n.y = cy + Math.sin(n.a + spin * 0.85) * n.r * Math.min(w, h) * 0.72
      })
      ctx.strokeStyle = 'rgba(34,211,238,0.08)'
      ctx.lineWidth = 1
      for (let i = 0; i < nodes.length; i += 3) {
        const a = nodes[i]
        const b = nodes[(i + 11) % nodes.length]
        ctx.beginPath()
        ctx.moveTo(a.x, a.y)
        ctx.lineTo(b.x, b.y)
        ctx.stroke()
      }
      nodes.forEach((n, i) => {
        ctx.beginPath()
        ctx.fillStyle = i % 5 === 0 ? 'rgba(34,211,238,0.85)' : 'rgba(148,163,184,0.45)'
        ctx.arc(n.x, n.y, i % 5 === 0 ? 2.4 : 1.4, 0, Math.PI * 2)
        ctx.fill()
      })
      t += 16
      if (!reduce) raf = window.requestAnimationFrame(draw)
    }
    draw()
    return () => window.cancelAnimationFrame(raf)
  }, [ids])

  return <canvas ref={canvasRef} className={className} aria-hidden />
}
