import { useEffect, useState } from 'react'
import { homeSectionNav } from '../content/nav'

export function StickySectionNav() {
  const [active, setActive] = useState<string>(homeSectionNav[0].id)

  useEffect(() => {
    const els = homeSectionNav
      .map((s) => document.getElementById(s.id))
      .filter((n): n is HTMLElement => Boolean(n))
    if (!els.length) return
    const io = new IntersectionObserver(
      (entries) => {
        const vis = entries.filter((e) => e.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0]
        if (vis?.target.id) setActive(vis.target.id)
      },
      { rootMargin: '-30% 0px -55% 0px', threshold: [0.15, 0.4, 0.7] },
    )
    els.forEach((el) => io.observe(el))
    return () => io.disconnect()
  }, [])

  return (
    <nav
      aria-label="On this page"
      className="sticky top-[var(--nav-h)] z-30 hidden border-b border-[var(--line)] bg-[rgba(7,9,12,0.88)] backdrop-blur md:block"
    >
      <ul className="site-wrap flex gap-1 overflow-x-auto py-2">
        {homeSectionNav.map((s) => (
          <li key={s.id}>
            <a
              href={`#${s.id}`}
              className={`inline-flex min-h-11 items-center px-3 text-sm ${active === s.id ? 'text-accent' : 'text-muted hover:text-ink'}`}
              aria-current={active === s.id ? 'location' : undefined}
            >
              {s.label}
            </a>
          </li>
        ))}
      </ul>
    </nav>
  )
}
