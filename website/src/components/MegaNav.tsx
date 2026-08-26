import { useEffect, useId, useRef, useState, type MutableRefObject } from 'react'
import { createPortal } from 'react-dom'
import { cta } from '../content/site'
import { mainNav, type NavItem } from '../content/nav'
import { ButtonLink } from './Button'
import { Logo } from './Logo'

export function MegaNav() {
  const [openId, setOpenId] = useState<string | null>(null)
  const [mobile, setMobile] = useState(false)
  const [mobileOpen, setMobileOpen] = useState<string | null>(null)
  const barRef = useRef<HTMLElement>(null)
  const firstLink = useRef<HTMLAnchorElement | null>(null)

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        setOpenId(null)
        setMobile(false)
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])

  useEffect(() => {
    document.body.style.overflow = mobile ? 'hidden' : ''
    return () => {
      document.body.style.overflow = ''
    }
  }, [mobile])

  useEffect(() => {
    if (openId && firstLink.current) firstLink.current.focus()
  }, [openId])

  return (
    <header ref={barRef} className="sticky top-0 z-50 border-b border-[var(--line)] bg-[rgba(7,9,12,0.78)] backdrop-blur-xl">
      <div className="site-wrap flex h-[var(--nav-h)] items-center justify-between gap-4">
        <a href="/" className="shrink-0" aria-label="Weissman home">
          <Logo size={34} />
        </a>

        <nav className="hidden items-center gap-1 lg:flex" aria-label="Primary">
          {mainNav.map((item) => (
            <DesktopItem
              key={item.id}
              item={item}
              open={openId === item.id}
              onOpen={() => setOpenId(item.id)}
              onClose={() => setOpenId(null)}
              firstLinkRef={openId === item.id ? firstLink : undefined}
            />
          ))}
        </nav>

        <div className="hidden items-center gap-2 lg:flex">
          <ButtonLink variant="ghost" href={cta.signIn.href}>
            {cta.signIn.label}
          </ButtonLink>
          <ButtonLink href={cta.primary.href}>{cta.primary.label}</ButtonLink>
        </div>

        <button
          type="button"
          className="inline-flex min-h-11 min-w-11 items-center justify-center rounded-[12px] border border-[var(--line)] lg:hidden"
          aria-expanded={mobile}
          aria-controls="mobile-nav"
          onClick={() => setMobile((v) => !v)}
        >
          <span className="sr-only">{mobile ? 'Close menu' : 'Open menu'}</span>
          <span aria-hidden className="text-lg">
            {mobile ? '×' : '☰'}
          </span>
        </button>
      </div>

      {openId && (
        <button
          type="button"
          aria-label="Close menu overlay"
          className="fixed inset-0 top-[calc(var(--nav-h)+2.6rem)] z-40 bg-black/45"
          onClick={() => setOpenId(null)}
        />
      )}

      {mobile &&
        createPortal(
        <div
          id="mobile-nav"
          role="dialog"
          aria-modal="true"
          aria-label="Mobile navigation"
          className="fixed inset-0 z-[80] flex flex-col bg-deep lg:hidden"
        >
          <div className="flex h-[var(--nav-h)] items-center justify-between border-b border-[var(--line)] px-4">
            <Logo size={30} />
            <button type="button" className="min-h-11 min-w-11" onClick={() => setMobile(false)} aria-label="Close menu">
              ×
            </button>
          </div>
          <div className="flex-1 overflow-y-auto px-4 py-4">
            {mainNav.map((item) => (
              <div key={item.id} className="border-b border-[var(--line)]">
                <button
                  type="button"
                  className="flex min-h-11 w-full items-center justify-between py-3 text-left text-lg"
                  aria-expanded={mobileOpen === item.id}
                  onClick={() => setMobileOpen((cur) => (cur === item.id ? null : item.id))}
                >
                  {item.label}
                  <span aria-hidden>{mobileOpen === item.id ? '–' : '+'}</span>
                </button>
                {mobileOpen === item.id && (
                  <ul className="space-y-1 pb-4">
                    {(item.mega ?? []).flatMap((col) => col.links).map((link) => (
                      <li key={link.href}>
                        <a className="block min-h-11 rounded-[12px] px-2 py-2 text-muted hover:bg-elevated hover:text-ink" href={link.href}>
                          <span className="block text-ink">{link.label}</span>
                          {link.description && <span className="text-sm text-dim">{link.description}</span>}
                        </a>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            ))}
            <div className="mt-6 flex flex-col gap-3">
              <ButtonLink href={cta.primary.href}>{cta.primary.label}</ButtonLink>
              <ButtonLink variant="ghost" href={cta.signIn.href}>
                {cta.signIn.label}
              </ButtonLink>
            </div>
          </div>
        </div>,
        document.body,
      )}
    </header>
  )
}

function DesktopItem({
  item,
  open,
  onOpen,
  onClose,
  firstLinkRef,
}: {
  item: NavItem
  open: boolean
  onOpen: () => void
  onClose: () => void
  firstLinkRef?: MutableRefObject<HTMLAnchorElement | null>
}) {
  const panelId = useId()
  const hasMega = Boolean(item.mega?.length)

  return (
    <div className="relative" onMouseEnter={hasMega ? onOpen : undefined} onMouseLeave={hasMega ? onClose : undefined}>
      {hasMega ? (
        <button
          type="button"
          className="inline-flex min-h-11 items-center gap-1 px-3 text-sm text-muted hover:text-ink"
          aria-expanded={open}
          aria-controls={panelId}
          onClick={() => (open ? onClose() : onOpen())}
          onKeyDown={(e) => {
            if (e.key === 'ArrowDown') {
              e.preventDefault()
              onOpen()
            }
          }}
        >
          {item.label}
        </button>
      ) : (
        <a className="inline-flex min-h-11 items-center px-3 text-sm text-muted hover:text-ink" href={item.href}>
          {item.label}
        </a>
      )}

      {hasMega && open && (
        <div
          id={panelId}
          role="menu"
          className="absolute left-1/2 top-full z-50 w-[min(52rem,calc(100vw-2rem))] -translate-x-1/2 pt-3"
        >
          <div className="surface grid gap-6 p-6 shadow-[var(--shadow)] md:grid-cols-2">
            {item.mega!.map((col, ci) => (
              <div key={col.heading}>
                <p className="eyebrow mb-3">{col.heading}</p>
                <ul className="space-y-1">
                  {col.links.map((link, li) => (
                    <li key={link.href}>
                      <a
                        role="menuitem"
                        ref={ci === 0 && li === 0 ? firstLinkRef : undefined}
                        className="block rounded-[12px] px-3 py-2 hover:bg-white/5"
                        href={link.href}
                      >
                        <span className="block text-sm font-medium text-ink">{link.label}</span>
                        {link.description && <span className="text-xs text-dim">{link.description}</span>}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
