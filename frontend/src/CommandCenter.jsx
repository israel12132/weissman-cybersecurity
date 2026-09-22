/* @weissman-forensic-page
 * Immersive full-screen Nebula Command Center — the post-login landing that
 * replaces the legacy cockpit at "/". Evidence-only theater surface (like
 * /operations and /intel-map): a live-data command deck + war room fused on
 * the Weissman brand backdrop, three.js glass globe, bilingual (EN/HE), with
 * an in-surface command menu (search · favorites · recents) and back navigation.
 *
 * The in-surface menu is fed the REAL application navigation (the same
 * appNav source the sidebar uses), role-filtered and resolved into both
 * languages, and its items drive real router navigation — so the cockpit menu
 * is the whole product, not a decorative copy.
 *
 * The animated engine, markup and styles are ported verbatim from the verified
 * prototype and live in ./commandCenterEngine.js (regenerated, not hand-edited).
 */
import { useEffect, useRef } from 'react'
import * as THREE from 'three'
import { useTranslation } from 'react-i18next'
import { useNavigate, useLocation } from 'react-router'
import { CC_CSS, CC_HTML, mountCommandCenter } from './commandCenterEngine'
import { PRIMARY_NAV_GROUP, NAV_GROUPS, canAccessNavItem } from './lib/appNav'
import { useAuthOptional } from './context/AuthContext'
import { loadLocale } from './i18n/localeLoader'

const STYLE_ID = 'wm-command-center-style'

export default function CommandCenter({ initialView = 'cockpit' }) {
  const hostRef = useRef(null)
  const { i18n } = useTranslation()
  const navigate = useNavigate()
  const { pathname } = useLocation()
  const auth = useAuthOptional()
  const session = auth?.session || null

  // Live refs so the engine (mounted once) always reads the latest values
  // without needing a remount when the router/session/nav model change.
  const navModelRef = useRef(null)
  const navigateRef = useRef(navigate)
  navigateRef.current = navigate
  const pathRef = useRef(pathname)
  pathRef.current = pathname

  // Build the real, role-filtered, bilingual navigation model. Both locale
  // bundles are ensured first so every label resolves in EN and HE at once.
  useEffect(() => {
    let cancelled = false
    const build = async () => {
      try {
        // Ensure both locale bundles are present so every label resolves in EN and HE.
        await Promise.all([loadLocale('en'), loadLocale('he')])
      } catch {
        /* Locale bundles are best-effort; build from whatever is loaded. */
      }
      if (cancelled) return
      try {
        const ten = i18n.getFixedT('en')
        const the = i18n.getFixedT('he')
        const groups = [PRIMARY_NAV_GROUP, ...NAV_GROUPS]
        const seen = new Set()
        const model = []
        for (const g of groups) {
          const items = []
          for (const it of g.items) {
            if (!canAccessNavItem(it, session)) continue
            if (seen.has(it.to)) continue // dedupe any route shared across groups
            seen.add(it.to)
            items.push({ t: it.to, e: ten(it.labelKey), h: the(it.labelKey), i: it.icon || '' })
          }
          if (items.length) model.push({ id: g.id, e: ten(g.labelKey), h: the(g.labelKey), items })
        }
        navModelRef.current = model
      } catch {
        /* Keep the engine's embedded fallback navigation model. */
      }
    }
    build()
    return () => {
      cancelled = true
    }
  }, [session, i18n])

  useEffect(() => {
    const host = hostRef.current
    if (!host) return undefined

    // Scoped styles: injected while the surface is mounted, removed on unmount
    // so its generic class names never leak onto other pages.
    let styleEl = document.getElementById(STYLE_ID)
    if (!styleEl) {
      styleEl = document.createElement('style')
      styleEl.id = STYLE_ID
      styleEl.textContent = CC_CSS
      document.head.appendChild(styleEl)
    }

    host.innerHTML = CC_HTML
    const initialLang = String(i18n.language || 'en').startsWith('he') ? 'he' : 'en'
    let cleanup = null
    try {
      cleanup = mountCommandCenter(host, THREE, {
        initialView,
        initialLang,
        currentPath: pathRef.current,
        // The cockpit menu renders the real app navigation and drives the router.
        getNav: () => navModelRef.current,
        onNavigate: (to) => {
          try {
            if (to) navigateRef.current(to)
          } catch {
            /* navigation is best-effort; never throw out of the engine */
          }
        },
        onLangChange: (lang) => {
          try {
            i18n.changeLanguage(lang)
          } catch {
            /* best-effort; the surface keeps its own language regardless */
          }
        },
      })
    } catch {
      /* engine boot is best-effort; a failed WebGL init must not crash the route */
    }

    return () => {
      try {
        if (cleanup) cleanup()
      } catch {
        /* noop */
      }
      if (host) host.innerHTML = ''
      const existing = document.getElementById(STYLE_ID)
      if (existing) existing.remove()
    }
    // Re-mount only when the entry view changes (cockpit vs war room).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialView])

  return <div ref={hostRef} className="wm-command-center-host" data-testid="command-center" />
}
