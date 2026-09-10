import { useEffect, useRef, useState } from 'react'
import { useI18n } from '../i18n'

type Props = {
  value: number
  suffix?: string
  className?: string
}

export function MetricCounter({ value, suffix = '', className = '' }: Props) {
  const { n } = useI18n()
  const ref = useRef<HTMLSpanElement>(null)
  const [shown, setShown] = useState(0)

  useEffect(() => {
    const el = ref.current
    if (!el) return
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    const io = new IntersectionObserver(
      ([e]) => {
        if (!e?.isIntersecting) return
        io.disconnect()
        if (reduce) {
          setShown(value)
          return
        }
        const start = performance.now()
        const dur = 700
        const tick = (now: number) => {
          const t = Math.min(1, (now - start) / dur)
          const eased = 1 - (1 - t) * (1 - t)
          setShown(Math.round(value * eased))
          if (t < 1) requestAnimationFrame(tick)
        }
        requestAnimationFrame(tick)
      },
      { threshold: 0.4 },
    )
    io.observe(el)
    return () => io.disconnect()
  }, [value])

  return (
    <span ref={ref} className={className} dir="ltr">
      {n(shown)}
      {suffix}
    </span>
  )
}
