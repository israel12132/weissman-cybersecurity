import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { CalendarClock, AlertTriangle } from 'lucide-react'
import { useClient } from '../context/ClientContext'
import { apiFetch } from '../utils/apiFetch'

/**
 * SlaForecastStrip — proactive view of upcoming SLA breaches for the selected client.
 *
 * Renders GET /api/remediation/sla-forecast/:client_id: cumulative breach counts by 7/14/30/60/90-
 * day horizons (KEV subset called out), plus what is already overdue. Lets a team get ahead of the
 * curve instead of only reacting to breaches after the fact.
 */

/** Pure: largest cumulative breach count across buckets; >=1 to avoid a zero bar denominator. */
export function maxBreached(forecast) {
  if (!Array.isArray(forecast) || forecast.length === 0) return 1
  return Math.max(1, ...forecast.map((b) => Number(b?.breached) || 0))
}

export default function SlaForecastStrip() {
  const { t } = useTranslation()
  const { selectedClientId, clients } = useClient()
  const clientId = useMemo(() => {
    if (selectedClientId != null && selectedClientId !== '') return selectedClientId
    const first = Array.isArray(clients) && clients.length ? Number(clients[0]?.id) : null
    return Number.isFinite(first) && first > 0 ? first : null
  }, [selectedClientId, clients])

  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const load = useCallback(async (id) => {
    if (id == null) { setData(null); return }
    setLoading(true)
    setError(null)
    try {
      const d = await apiFetch(`/api/remediation/sla-forecast/${encodeURIComponent(id)}`)
      setData(d && typeof d === 'object' ? d : null)
    } catch (e) {
      setError(e?.message || 'load failed')
      setData(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load(clientId) }, [clientId, load])

  const forecast = Array.isArray(data?.forecast) ? data.forecast : []
  const barMax = maxBreached(forecast)

  if (clientId == null || loading) return null
  if (error) return null
  if (forecast.length === 0 || forecast.every((b) => (Number(b.breached) || 0) === 0)) return null

  return (
    <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
      <div className="p-4 border-b border-white/10 flex items-center justify-between gap-3 flex-wrap">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <CalendarClock className="w-4 h-4 text-amber-400" />
          {t('pages.remediationHub.forecast_heading', { defaultValue: 'SLA Breach Forecast' })}
        </h3>
        {Number(data?.overdue_now) > 0 && (
          <span className="inline-flex items-center gap-1 text-[11px] text-rose-300 font-medium">
            <AlertTriangle className="w-3.5 h-3.5" />
            {t('pages.remediationHub.forecast_overdue_now', { count: data.overdue_now, defaultValue: '{{count}} already overdue' })}
          </span>
        )}
      </div>

      <div className="p-4 grid grid-cols-5 gap-3">
        {forecast.map((b) => {
          const breached = Number(b.breached) || 0
          const kev = Number(b.kev_breached) || 0
          return (
            <div key={b.within_days} className="flex flex-col items-center gap-1.5">
              <div className="text-lg font-bold tabular-nums text-white">{breached}</div>
              {kev > 0 && (
                <div className="text-[10px] font-mono text-orange-300">{t('pages.remediationHub.forecast_kev', { count: kev, defaultValue: '{{count}} KEV' })}</div>
              )}
              <div className="w-full h-16 flex items-end">
                <div
                  className="w-full rounded-t bg-gradient-to-t from-amber-500/40 to-rose-500/70"
                  style={{ height: `${(breached / barMax) * 100}%` }}
                />
              </div>
              <div className="text-[10px] text-white/40 font-mono">
                {t('pages.remediationHub.forecast_within', { days: b.within_days, defaultValue: '≤{{days}}d' })}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
