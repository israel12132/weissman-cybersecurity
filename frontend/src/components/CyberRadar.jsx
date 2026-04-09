import { useEffect, useRef } from 'react'

export default function CyberRadar() {
  const canvasRef = useRef(null)
  useEffect(() => {
    if (!canvasRef.current) return
    const canvas = canvasRef.current
    const ctx = canvas.getContext('2d')
    const size = 140
    canvas.width = size
    canvas.height = size
    let angle = 0
    let frameId
    function draw() {
      ctx.clearRect(0, 0, size, size)
      const cx = size / 2
      const cy = size / 2
      const r = size / 2 - 4
      ctx.strokeStyle = 'rgba(0, 243, 255, 0.25)'
      ctx.lineWidth = 1
      for (let i = 1; i <= 4; i++) {
        ctx.beginPath()
        ctx.arc(cx, cy, r * (i / 4), 0, Math.PI * 2)
        ctx.stroke()
      }
      ctx.beginPath()
      ctx.moveTo(cx, cy)
      ctx.lineTo(cx + r * Math.cos(angle), cy + r * Math.sin(angle))
      ctx.strokeStyle = 'rgba(0, 243, 255, 0.7)'
      ctx.lineWidth = 2
      ctx.stroke()
      angle += 0.03
      if (angle >= Math.PI * 2) angle = 0
      frameId = requestAnimationFrame(draw)
    }
    draw()
    return () => cancelAnimationFrame(frameId)
  }, [])
  return (
    <div className="cyber-radar">
      <div className="text-cyber-cyan font-semibold text-xs tracking-widest mb-2 uppercase">
        Cyber Radar
      </div>
      <div className="relative inline-block">
        <canvas ref={canvasRef} className="block rounded-full border border-cyber-cyan/30" />
      </div>
      <p className="text-[10px] text-slate-500 mt-1 font-mono">Dark Web intel</p>
    </div>
  )
}
