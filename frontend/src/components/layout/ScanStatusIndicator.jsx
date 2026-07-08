import React, { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Radar } from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'

const POLL_MS = 15000

/**
 * Global "scan in progress" indicator for the app header.
 *
 * Polls the live GET /api/scan/status ({ scanning_active }) and shows a subtle
 * pulsing pill only while a scan is running — an at-a-glance signal that the
 * platform is actively working, without adding clutter when idle.
 */
export default function ScanStatusIndicator() {
  const { t } = useTranslation()
  const [active, setActive] = useState(false)
  const timerRef = useRef(null)

  useEffect(() => {
    let cancelled = false
    const poll = async () => {
      // Skip work when the tab is hidden — saves needless requests.
      if (typeof document !== 'undefined' && document.hidden) return
      try {
        const r = await apiFetch('/api/scan/status')
        const d = await r.json().catch(() => ({}))
        if (!cancelled) setActive(r.ok && d.scanning_active === true)
      } catch {
        if (!cancelled) setActive(false)
      }
    }
    poll()
    timerRef.current = setInterval(poll, POLL_MS)
    return () => {
      cancelled = true
      clearInterval(timerRef.current)
    }
  }, [])

  if (!active) return null

  return (
    <span
      className="hidden sm:flex items-center gap-1.5 px-2 py-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 text-emerald-300 text-[10px] font-mono uppercase tracking-wider"
      role="status"
      aria-live="polite"
      title={t('scanStatus.active_hint')}
    >
      <Radar className="w-3 h-3 animate-spin" style={{ animationDuration: '3s' }} aria-hidden />
      {t('scanStatus.active')}
    </span>
  )
}
