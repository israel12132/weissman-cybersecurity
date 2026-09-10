import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { fetchPlatformPulse } from '../lib/liveApi'

export default function LivePulse({ className = '' }) {
  const { t } = useTranslation()
  const [pulse, setPulse] = useState(null)
  const [error, setError] = useState(false)

  useEffect(() => {
    let cancelled = false
    fetchPlatformPulse()
      .then((d) => {
        if (!cancelled) setPulse(d)
      })
      .catch(() => {
        if (!cancelled) setError(true)
      })
    return () => {
      cancelled = true
    }
  }, [])

  if (error) {
    return (
      <p className={`text-sm text-amber-200/80 ${className}`} role="status">
        {t('home.pulse_unavailable')}
      </p>
    )
  }

  const items = [
    { label: t('home.stat_canonical'), value: pulse?.distinct_canonical },
    { label: t('home.stat_probes'), value: pulse?.real_probes },
    { label: t('home.stat_engines'), value: pulse?.production_engines },
    { label: t('home.stat_aliases'), value: pulse?.alias_ids },
    { label: t('home.stat_agent'), value: pulse?.agent_required },
    { label: t('home.stat_health'), value: pulse?.health },
  ]

  return (
    <dl className={`grid grid-cols-2 gap-4 sm:grid-cols-3 ${className}`}>
      {items.map((item) => (
        <div key={item.label} className="rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-4">
          <dt className="text-[10px] uppercase tracking-[0.16em] text-white/40">{item.label}</dt>
          <dd className="mt-2 font-display text-2xl font-semibold text-cyan-200">
            {pulse ? String(item.value ?? '—') : '…'}
          </dd>
        </div>
      ))}
    </dl>
  )
}
