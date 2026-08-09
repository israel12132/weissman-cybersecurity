import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { useTelemetry } from '../../context/TelemetryContext'

/**
 * Live telemetry strip filtered to the active engine (manifest-driven).
 */
export default function TelemetryStrip({ engineId, live = true, memory = false }) {
  const { t } = useTranslation()
  const { progressByEngine, activity } = useTelemetry()

  const engineEvents = useMemo(() => {
    if (!engineId) return []
    const msgs = progressByEngine?.[engineId]
    if (Array.isArray(msgs) && msgs.length) {
      return msgs.slice(-5)
    }
    return (activity || [])
      .filter((e) => e?.engine === engineId)
      .slice(0, 5)
  }, [engineId, progressByEngine, activity])

  if (!live && !memory) return null
  if (!engineEvents.length) return null

  return (
    <div
      className="mb-4 rounded-xl border border-cyan-500/20 bg-cyan-950/15 px-4 py-3"
      role="log"
      aria-live="polite"
      aria-label={t('engineC2.telemetry_strip')}
    >
      <div className="text-[9px] font-mono uppercase tracking-widest text-cyan-300/60 mb-2">
        {memory ? t('engineC2.memory_telemetry') : t('engineC2.live_telemetry')}
      </div>
      <ul className="space-y-1 max-h-24 overflow-y-auto">
        {engineEvents.map((ev, i) => (
          <li key={i} className="text-[10px] font-mono text-white/55 truncate">
            {ev?.message || JSON.stringify(ev)}
          </li>
        ))}
      </ul>
    </div>
  )
}
