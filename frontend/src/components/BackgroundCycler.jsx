import { useEffect, useRef, useState } from 'react'

const THEME_DURATION_MS = 120 * 1000

// Theme 1: Matrix Rain (canvas)
function MatrixRainCanvas({ active }) {
  const canvasRef = useRef(null)
  useEffect(() => {
    if (!active || !canvasRef.current) return
    const canvas = canvasRef.current
    const ctx = canvas.getContext('2d')
    let frameId
    const cols = Math.floor(canvas.width / 14)
    const drops = Array(cols).fill(0)
    function resize() {
      canvas.width = window.innerWidth
      canvas.height = window.innerHeight
    }
    resize()
    window.addEventListener('resize', resize)
    function draw() {
      ctx.fillStyle = 'rgba(0, 8, 4, 0.08)'
      ctx.fillRect(0, 0, canvas.width, canvas.height)
      ctx.fillStyle = '#0a3d2a'
      ctx.font = '12px JetBrains Mono'
      for (let i = 0; i < drops.length; i++) {
        const char = String.fromCharCode(0x30a0 + ((i + Math.floor(drops[i] / 10)) % 96))
        ctx.fillText(char, i * 14, drops[i] * 14)
        if (drops[i] * 14 > canvas.height && (i + drops[i]) % 41 === 0) drops[i] = 0
        drops[i]++
      }
      frameId = requestAnimationFrame(draw)
    }
    draw()
    return () => {
      window.removeEventListener('resize', resize)
      cancelAnimationFrame(frameId)
    }
  }, [active])
  return <canvas ref={canvasRef} className="absolute inset-0 w-full h-full" aria-hidden />
}

// Theme 2: Hex grid (CSS)
function HexGridBg({ active }) {
  if (!active) return null
  return (
    <div className="absolute inset-0 overflow-hidden" aria-hidden>
      <div
        className="absolute inset-0 opacity-30"
        style={{
          backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='28' height='32' viewBox='0 0 28 32'%3E%3Cpath fill='none' stroke='%2300f3ff' stroke-width='0.4' d='M14 0l14 8v16l-14 8L0 24V8z'/%3E%3Cpath fill='none' stroke='%2300f3ff' stroke-width='0.2' opacity='0.5' d='M14 0l14 8v16l-14 8L0 24V8z'/%3E%3C/svg%3E")`,
          backgroundSize: '28px 32px',
          animation: 'hex-drift 30s linear infinite',
        }}
      />
    </div>
  )
}

// Theme 3: Radar sweep (canvas)
function RadarSweepCanvas({ active }) {
  const canvasRef = useRef(null)
  useEffect(() => {
    if (!active || !canvasRef.current) return
    const canvas = canvasRef.current
    const ctx = canvas.getContext('2d')
    let frameId
    let angle = 0
    function resize() {
      canvas.width = window.innerWidth
      canvas.height = window.innerHeight
    }
    resize()
    window.addEventListener('resize', resize)
    function draw() {
      ctx.fillStyle = 'rgba(0, 2, 4, 0.12)'
      ctx.fillRect(0, 0, canvas.width, canvas.height)
      const cx = canvas.width / 2
      const cy = canvas.height / 2
      const r = Math.max(canvas.width, canvas.height) * 0.6
      ctx.strokeStyle = 'rgba(0, 200, 180, 0.08)'
      ctx.lineWidth = 1
      for (let i = 1; i <= 6; i++) {
        ctx.beginPath()
        ctx.arc(cx, cy, r * (i / 6), 0, Math.PI * 2)
        ctx.stroke()
      }
      ctx.strokeStyle = 'rgba(0, 243, 255, 0.2)'
      ctx.lineWidth = 2
      ctx.beginPath()
      ctx.moveTo(cx, cy)
      ctx.lineTo(cx + r * Math.cos(angle), cy + r * Math.sin(angle))
      ctx.stroke()
      angle += 0.004
      if (angle > Math.PI * 2) angle = 0
      frameId = requestAnimationFrame(draw)
    }
    draw()
    return () => {
      window.removeEventListener('resize', resize)
      cancelAnimationFrame(frameId)
    }
  }, [active])
  return <canvas ref={canvasRef} className="absolute inset-0 w-full h-full" aria-hidden />
}

// Theme 4: Neon dust (CSS particles) — deterministic positions, no Math.random
function NeonDustBg({ active }) {
  if (!active) return null
  const dots = Array.from({ length: 60 }, (_, i) => ({
    id: i,
    left: `${((i * 17) % 100)}%`,
    top: `${((i * 23 + 31) % 100)}%`,
    delay: (i % 5) * 0.8,
    duration: 3 + (i % 4),
  }))
  return (
    <div className="absolute inset-0 overflow-hidden" aria-hidden>
      {dots.map((d) => (
        <div
          key={d.id}
          className="absolute w-1 h-1 rounded-full bg-cyan-400/40"
          style={{
            left: d.left,
            top: d.top,
            boxShadow: '0 0 8px rgba(0,243,255,0.5)',
            animation: `neon-dust ${d.duration}s ease-in-out ${d.delay}s infinite`,
          }}
        />
      ))}
    </div>
  )
}

export default function BackgroundCycler() {
  const [themeIndex, setThemeIndex] = useState(0)
  useEffect(() => {
    const t = setInterval(() => {
      setThemeIndex((i) => (i + 1) % 4)
    }, THEME_DURATION_MS)
    return () => clearInterval(t)
  }, [])
  return (
    <div className="absolute inset-0 overflow-hidden">
      <MatrixRainCanvas active={themeIndex === 0} />
      <HexGridBg active={themeIndex === 1} />
      <RadarSweepCanvas active={themeIndex === 2} />
      <NeonDustBg active={themeIndex === 3} />
      <div
        className="absolute inset-0 pointer-events-none"
        style={{ background: 'rgba(0,0,0,0.85)' }}
        aria-hidden
      />
    </div>
  )
}
