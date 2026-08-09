import { useEffect, useRef, useState } from 'react'

const DURATION_MS = 600

export default function LiveCounter({ value = 0, label, className = '' }) {
  const [display, setDisplay] = useState(value)
  // Track the currently-displayed value so a value change mid-animation interpolates
  // from what is actually on screen, not from the previous (possibly unreached) target.
  const displayRef = useRef(value)
  const rafRef = useRef(null)
  const startRef = useRef(null)

  useEffect(() => {
    const target = Number(value) || 0
    if (target === displayRef.current) return
    const start = displayRef.current
    // Re-anchor the animation clock for this run; the previous run may have left a stale ts.
    startRef.current = null

    const step = (ts) => {
      if (!startRef.current) startRef.current = ts
      const elapsed = ts - startRef.current
      const t = Math.min(1, elapsed / DURATION_MS)
      const ease = 1 - (1 - t) * (1 - t)
      const next = Math.round(start + (target - start) * ease)
      displayRef.current = next
      setDisplay(next)
      if (t < 1) rafRef.current = requestAnimationFrame(step)
      else startRef.current = null
    }
    rafRef.current = requestAnimationFrame(step)
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current)
      startRef.current = null
    }
  }, [value])

  return (
    <span className={className}>
      <span className="tabular-nums">{display}</span>
      {label != null && <span className="opacity-80 ml-0.5">{label}</span>}
    </span>
  )
}
