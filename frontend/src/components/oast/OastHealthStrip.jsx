import { useTranslation } from 'react-i18next'

export default function OastHealthStrip({ health, fallbackCount = 0 }) {
  const { t } = useTranslation()
  if (!health) return null
  const observed = Boolean(health.last_callback_at)
  const unavailable = Boolean(health.unavailable)
  const live = !unavailable && Boolean(health.configured) && observed
  return (
    <div
      data-testid="oast-health-strip"
      data-live={live ? 'true' : 'false'}
      data-unavailable={unavailable ? 'true' : 'false'}
      className={`mb-6 rounded-xl border px-4 py-3 text-[11px] font-mono flex flex-wrap gap-3 ${
        live
          ? 'border-emerald-500/30 bg-emerald-950/20 text-emerald-200'
          : 'border-amber-500/30 bg-amber-950/20 text-amber-100'
      }`}
    >
      <span>
        {t('pages.oastDashboard.health_listener')}: {unavailable
          ? t('pages.oastDashboard.health_unavailable')
          : health.configured
            ? (observed
              ? t('pages.oastDashboard.health_configured')
              : t('pages.oastDashboard.health_idle'))
            : t('pages.oastDashboard.health_missing')}
      </span>
      <span>
        {t('pages.oastDashboard.health_domain')}: {health.domain || '—'}
      </span>
      <span>
        {t('pages.oastDashboard.health_last')}: {unavailable
          ? '—'
          : (health.last_callback_at || t('pages.oastDashboard.health_none'))}
      </span>
      {!unavailable && (
      <span>
        {t('pages.oastDashboard.health_count', { count: health.callback_count ?? fallbackCount })}
      </span>
      )}
    </div>
  )
}
