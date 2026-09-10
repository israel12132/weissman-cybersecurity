import { useEffect, useRef, type ReactNode } from 'react'

export function Reveal({ children, className = '' }: { children: ReactNode; className?: string }) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const el = ref.current
    if (!el) return
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      el.dataset.visible = '1'
      return
    }
    const io = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            el.dataset.visible = '1'
            io.disconnect()
          }
        }
      },
      { threshold: 0.12 },
    )
    io.observe(el)
    return () => io.disconnect()
  }, [])

  return (
    <div
      ref={ref}
      className={`translate-y-4 opacity-0 transition duration-slow ease-[var(--ease)] data-[visible]:translate-y-0 data-[visible]:opacity-100 ${className}`}
    >
      {children}
    </div>
  )
}
