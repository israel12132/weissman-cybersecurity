/* @weissman-forensic-page
 * Immersive full-screen Nebula Command Center — the post-login landing that
 * replaces the legacy cockpit at "/". Evidence-only theater surface (like
 * /operations and /intel-map): a live-data command deck + war room fused on
 * the Weissman brand backdrop, three.js glass globe, bilingual (EN/HE), with
 * an in-surface menu drawer and back navigation.
 *
 * The animated engine, markup and styles are ported verbatim from the verified
 * prototype and live in ./commandCenterEngine.js (regenerated, not hand-edited).
 */
import { useEffect, useRef } from 'react'
import * as THREE from 'three'
import { useTranslation } from 'react-i18next'
import { CC_CSS, CC_HTML, mountCommandCenter } from './commandCenterEngine'

const STYLE_ID = 'wm-command-center-style'

export default function CommandCenter({ initialView = 'cockpit' }) {
  const hostRef = useRef(null)
  const { i18n } = useTranslation()

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
