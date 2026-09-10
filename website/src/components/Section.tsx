import type { ReactNode } from 'react'

export function Section({
  id,
  eyebrow,
  title,
  sub,
  children,
  className = '',
}: {
  id?: string
  eyebrow?: string
  title?: string
  sub?: string
  children: ReactNode
  className?: string
}) {
  return (
    <section id={id} className={`border-t border-[var(--line)] py-20 md:py-24 ${className}`}>
      <div className="site-wrap">
        {(eyebrow || title) && (
          <header className="mb-10 max-w-3xl">
            {eyebrow && <p className="eyebrow mb-3">{eyebrow}</p>}
            {title && <h2 className="display text-3xl text-ink md:text-4xl">{title}</h2>}
            {sub && <p className="mt-4 text-lg text-muted">{sub}</p>}
          </header>
        )}
        {children}
      </div>
    </section>
  )
}
