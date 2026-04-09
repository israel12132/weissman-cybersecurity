import { useEffect, useRef, useState } from 'react'

const DURATION_MS = 600

export default function LiveCounter({ value = 0, label, className = '' }) {
  const [display, setDisplay] = useState(value)
  const prevRef = useRef(value)
  const rafRef = useRef(null)
  const startRef = useRef(null)

  useEffect(() => {
    const target = Number(value) || 0
    if (target === prevRef.current) return
    const start = prevRef.current
    prevRef.current = target

    const step = (ts) => {
      if (!startRef.current) startRef.current = ts
      const elapsed = ts - startRef.current
      const t = Math.min(1, elapsed / DURATION_MS)
      const ease = 1 - (1 - t) * (1 - t)
      setDisplay(Math.round(start + (target - start) * ease))
      if (t < 1) rafRef.current = requestAnimationFrame(step)
      else startRef.current = null
    }
    rafRef.current = requestAnimationFrame(step)
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current)
    }
  }, [value])

  return (
    <span className={className}>
      <span className="tabular-nums">{display}</span>
      {label != null && <span className="opacity-80 ml-0.5">{label}</span>}
    </span>
  )
}
