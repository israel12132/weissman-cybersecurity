import { useEffect, useRef } from 'react'

/**
 * War Room cinematic background: deep-space blurred data streams + reactive 3D grid.
 * Pure CSS/Canvas, no external images.
 */
export default function CinematicBackground() {
  const canvasRef = useRef(null)

  useEffect(() => {
    if (!canvasRef.current) return
    const canvas = canvasRef.current
    const ctx = canvas.getContext('2d')
    let frameId
    let t = 0

    function resize() {
      canvas.width = window.innerWidth
      canvas.height = window.innerHeight
    }
    resize()
    window.addEventListener('resize', resize)

    function draw() {
      const w = canvas.width
      const h = canvas.height
      t += 0.008

      // Deep space gradient (dark blue-black)
      const g = ctx.createRadialGradient(w / 2, h / 2, 0, w / 2, h / 2, w * 0.8)
      g.addColorStop(0, 'rgba(5, 5, 20, 0.97)')
      g.addColorStop(0.5, 'rgba(2, 2, 12, 0.98)')
      g.addColorStop(1, 'rgba(0, 0, 5, 0.99)')
      ctx.fillStyle = g
      ctx.fillRect(0, 0, w, h)

      // Subtle reactive 3D grid (perspective)
      ctx.strokeStyle = 'rgba(0, 243, 255, 0.06)'
      ctx.lineWidth = 1
      const gridStep = 48
      const vanishY = h * 0.4
      for (let i = -Math.floor(w / gridStep); i <= Math.floor(w / gridStep) + 1; i++) {
        const x = w / 2 + i * gridStep + (Math.sin(t + i * 0.1) * 2)
        ctx.beginPath()
        ctx.moveTo(x, h + 20)
        ctx.lineTo(w / 2 + (x - w / 2) * 0.3, vanishY)
        ctx.stroke()
      }
      for (let j = 0; j <= 12; j++) {
        const y = vanishY + (h - vanishY) * (j / 12) + Math.sin(t + j * 0.2) * 3
        ctx.beginPath()
        ctx.moveTo(0, y)
        ctx.lineTo(w, y)
        ctx.stroke()
      }

      // Blurred Data Stream background (depth + high-tech atmosphere)
      ctx.globalAlpha = 0.09
      for (let s = 0; s < 4; s++) {
        const offset = (t * 50 + s * 220) % (h + 100) - 50
        const grad = ctx.createLinearGradient(0, offset, w, offset + 50)
        grad.addColorStop(0, 'transparent')
        grad.addColorStop(0.35, 'rgba(0, 243, 255, 0.35)')
        grad.addColorStop(0.65, 'rgba(0, 243, 255, 0.35)')
        grad.addColorStop(1, 'transparent')
        ctx.strokeStyle = grad
        ctx.lineWidth = 22
        ctx.beginPath()
        ctx.moveTo(0, offset)
        ctx.lineTo(w, offset + 25)
        ctx.stroke()
      }
      ctx.globalAlpha = 1

      frameId = requestAnimationFrame(draw)
    }
    draw()
    return () => {
      window.removeEventListener('resize', resize)
      cancelAnimationFrame(frameId)
    }
  }, [])

  return (
    <div className="absolute inset-0 overflow-hidden" aria-hidden>
      <canvas ref={canvasRef} className="absolute inset-0 w-full h-full" />
      <div
        className="absolute inset-0 pointer-events-none"
        style={{ background: 'rgba(0,2,8,0.86)' }}
        aria-hidden
      />
    </div>
  )
}
