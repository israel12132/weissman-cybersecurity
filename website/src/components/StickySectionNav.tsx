import { useEffect, useState } from 'react'
import { homeSectionNav } from '../content/nav'
import { useI18n } from '../i18n'

export function StickySectionNav() {
  const { t } = useI18n()
  const [active, setActive] = useState<string>(homeSectionNav[0])

  useEffect(() => {
    const els = homeSectionNav
      .map((id) => document.getElementById(id))
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
      aria-label={t('a11y.onThisPage')}
      className="sticky top-[var(--nav-h)] z-30 hidden border-b border-[var(--line)] bg-[rgba(7,9,12,0.88)] backdrop-blur md:block"
    >
      <ul className="site-wrap flex gap-1 overflow-x-auto py-2">
        {homeSectionNav.map((id) => (
          <li key={id}>
            <a
              href={`#${id}`}
              className={`inline-flex min-h-11 items-center px-3 text-sm ${active === id ? 'text-accent' : 'text-muted hover:text-ink'}`}
              aria-current={active === id ? 'location' : undefined}
            >
              {t(`nav.sections.${id}`)}
            </a>
          </li>
        ))}
      </ul>
    </nav>
  )
}
