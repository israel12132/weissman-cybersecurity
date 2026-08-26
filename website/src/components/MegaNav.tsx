import { useEffect, useId, useRef, useState, type MutableRefObject } from 'react'
import { createPortal } from 'react-dom'
import { useI18n } from '../i18n'
import { mainNav, type NavItem } from '../content/nav'
import { A } from './A'
import { ButtonLink } from './Button'
import { LanguageSwitcher } from './LanguageSwitcher'
import { Logo } from './Logo'

export function MegaNav() {
  const { t } = useI18n()
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

  function megaLabel(itemId: string, linkId: string, field: 'label' | 'description') {
    return t(`nav.mega.${itemId}.${linkId}.${field}`)
  }

  return (
    <header ref={barRef} className="sticky top-0 z-50 overflow-visible border-b border-[var(--line)] bg-[rgba(7,9,12,0.92)] backdrop-blur-xl">
      <div className="site-wrap flex h-[var(--nav-h)] items-center justify-between gap-3">
        <A href="/" className="shrink-0" aria-label={t('a11y.home')}>
          <Logo size={34} />
        </A>

        <nav className="hidden items-center gap-1 lg:flex" aria-label={t('a11y.primaryNav')}>
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
          <LanguageSwitcher variant="bar" />
          <ButtonLink variant="ghost" href="/command-center/login">
            {t('cta.signIn')}
          </ButtonLink>
          <ButtonLink href="/contact/">{t('cta.bookDemo')}</ButtonLink>
        </div>

        <div className="flex items-center gap-2 lg:hidden">
          <LanguageSwitcher variant="bar" />
          <button
            type="button"
            className="inline-flex min-h-11 min-w-11 items-center justify-center rounded-[12px] border border-[var(--line)]"
            aria-expanded={mobile}
            aria-controls="mobile-nav"
            onClick={() => setMobile((v) => !v)}
          >
            <span className="sr-only">{mobile ? t('a11y.closeMenu') : t('a11y.openMenu')}</span>
            <span aria-hidden className="text-lg">
              {mobile ? '×' : '☰'}
            </span>
          </button>
        </div>
      </div>

      {openId && (
        <button
          type="button"
          aria-label={t('a11y.closeOverlay')}
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
            aria-label={t('a11y.mobileNav')}
            className="fixed inset-0 z-[80] flex flex-col bg-deep lg:hidden"
          >
            <div className="flex h-[var(--nav-h)] items-center justify-between border-b border-[var(--line)] px-4">
              <Logo size={30} />
              <button type="button" className="min-h-11 min-w-11" onClick={() => setMobile(false)} aria-label={t('a11y.closeMenu')}>
                ×
              </button>
            </div>
            <div className="flex-1 overflow-y-auto px-4 py-4">
              {mainNav.map((item) => (
                <div key={item.id} className="border-b border-[var(--line)]">
                  <button
                    type="button"
                    className="flex min-h-11 w-full items-center justify-between py-3 text-start text-lg"
                    aria-expanded={mobileOpen === item.id}
                    onClick={() => setMobileOpen((cur) => (cur === item.id ? null : item.id))}
                  >
                    {t(`nav.${item.id}`)}
                    <span aria-hidden>{mobileOpen === item.id ? '–' : '+'}</span>
                  </button>
                  {mobileOpen === item.id && (
                    <ul className="space-y-1 pb-4">
                      {(item.mega ?? []).flatMap((col) =>
                        col.links.map((link) => (
                          <li key={link.id}>
                            <A
                              className="block min-h-11 rounded-[12px] px-2 py-2 text-muted hover:bg-elevated hover:text-ink"
                              href={link.href}
                            >
                              <span className="block text-ink">{megaLabel(item.id, link.id, 'label')}</span>
                              <span className="text-sm text-dim">{megaLabel(item.id, link.id, 'description')}</span>
                            </A>
                          </li>
                        )),
                      )}
                    </ul>
                  )}
                </div>
              ))}
              <div className="mt-6 flex flex-col gap-3">
                <LanguageSwitcher variant="drawer" />
                <ButtonLink href="/contact/">{t('cta.bookDemo')}</ButtonLink>
                <ButtonLink variant="ghost" href="/command-center/login">
                  {t('cta.signIn')}
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
  const { t, href } = useI18n()
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
          {t(`nav.${item.id}`)}
        </button>
      ) : (
        <A className="inline-flex min-h-11 items-center px-3 text-sm text-muted hover:text-ink" href={item.href}>
          {t(`nav.${item.id}`)}
        </A>
      )}

      {hasMega && open && (
        <div
          id={panelId}
          role="menu"
          className="absolute left-1/2 top-full z-[80] w-[min(52rem,calc(100vw-2rem))] -translate-x-1/2 pt-3"
        >
          <div className="grid gap-6 rounded-[14px] border border-[var(--line-strong)] bg-[#10141b] p-6 shadow-[var(--shadow)] md:grid-cols-2">
            {item.mega!.map((col, ci) => (
              <div key={col.id}>
                <p className="eyebrow mb-3">{t(`nav.mega.${item.id}.${col.id}`)}</p>
                <ul className="space-y-1">
                  {col.links.map((link, li) => (
                    <li key={link.id}>
                      <a
                        role="menuitem"
                        ref={ci === 0 && li === 0 ? firstLinkRef : undefined}
                        className="block rounded-[12px] px-3 py-2 hover:bg-white/5"
                        href={href(link.href)}
                      >
                        <span className="block text-sm font-medium text-ink">
                          {t(`nav.mega.${item.id}.${link.id}.label`)}
                        </span>
                        <span className="text-xs text-dim">{t(`nav.mega.${item.id}.${link.id}.description`)}</span>
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
