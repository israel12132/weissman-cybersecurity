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
 * Store-down / 503 is unknown — never painted as idle.
 */
export default function ScanStatusIndicator() {
  const { t } = useTranslation()
  const [mode, setMode] = useState(null)

  const poll = useCallback(async () => {
    try {
      const d = await apiFetch('/api/scan/status')
      if (d == null || d.ok === false || d.unavailable || d.running_async_jobs == null) {
        setMode('unknown')
        return
      }
      const jobs = Number(d.running_async_jobs) || 0
      setMode(
        d.scan_in_progress === true
          || d.scanning_active === true
          || jobs > 0
          ? 'active'
          : 'idle',
      )
    } catch {
      setMode('unknown')
    }
  }, [])

  useEffect(() => {
    poll()
  }, [poll])

  useVisiblePolling(poll, POLL_MS)

  if (mode == null || mode === 'idle') return null

  if (mode === 'unknown') {
    return (
      <span
        className="hidden sm:flex items-center gap-1.5 px-2 py-1 rounded-full border border-amber-500/30 bg-amber-500/10 text-[var(--severity-medium)] text-[10px] font-mono uppercase tracking-wider"
        role="status"
        aria-live="polite"
        data-testid="scan-status-unavailable"
        title={t('scanStatus.unknown_hint')}
      >
        <Radar className="w-3 h-3" aria-hidden />
        {t('scanStatus.unknown')}
      </span>
    )
  }

  return (
    <span
      className="hidden sm:flex items-center gap-1.5 px-2 py-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 text-[var(--severity-low)] text-[10px] font-mono uppercase tracking-wider"
      role="status"
      aria-live="polite"
      title={t('scanStatus.active_hint')}
    >
      <Radar className="w-3 h-3 animate-spin" style={{ animationDuration: '3s' }} aria-hidden />
      {t('scanStatus.active')}
    </span>
  )
}
