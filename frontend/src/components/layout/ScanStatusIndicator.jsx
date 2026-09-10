import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Radar } from 'lucide-react'
import { apiFetch } from '../../utils/apiFetch'
import { useVisiblePolling } from '../../hooks/useVisiblePolling'

const POLL_MS = 15000

/**
 * Global "scan in progress" indicator for the app header.
 *
 * Polls GET /api/scan/status (`scan_in_progress`, `running_async_jobs`, `scanning_active`)
 * and shows a pulsing pill while a worker job or operator scan is actually running.
 */
export default function ScanStatusIndicator() {
  const { t } = useTranslation()
  const [active, setActive] = useState(false)

  const poll = useCallback(async () => {
    try {
      const d = await apiFetch('/api/scan/status')
      const jobs = Number(d.running_async_jobs) || 0
      setActive(
        d.scan_in_progress === true
          || d.scanning_active === true
          || jobs > 0,
      )
    } catch {
      setActive(false)
    }
  }, [])

  useEffect(() => {
    poll()
  }, [poll])

  useVisiblePolling(poll, POLL_MS)

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
