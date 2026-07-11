import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { TrendingUp } from 'lucide-react'
import { apiFetch } from '../../lib/apiBase'

/**
 * HealTrendSparkline — daily auto-heal volume + success-rate trend, merged across the given clients
 * from GET /api/clients/:id/heal-trends. Inline SVG (no charting dep): an accent area for daily heal
 * volume with an emphasized latest point, a green success-rate line, and rollup stats. Theme-aware.
 */
export default function HealTrendSparkline({ clientIds = [], days = 30 }) {
  const { t } = useTranslation()
  const [data, setData] = useState(null)

  const key = clientIds.join(',')
  useEffect(() => {
    if (!clientIds.length) { setData(null); return undefined }
    let cancelled = false
    Promise.all(
      clientIds.map((id) =>
        apiFetch(`/api/clients/${id}/heal-trends?days=${days}`)
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null)),
    ).then((list) => {
      if (cancelled) return
      const dayMap = {}
      let total = 0
      let fixed = 0
      let attemptsWeighted = 0
      for (const res of list) {
        const tr = res?.trend
        if (!tr) continue
        for (const d of tr.days || []) {
          const e = dayMap[d.day] || (dayMap[d.day] = { total: 0, fixed: 0 })
          e.total += d.total || 0
          e.fixed += d.fixed || 0
        }
        total += tr.total || 0
        fixed += tr.fixed || 0
        attemptsWeighted += (tr.avg_attempts || 1) * (tr.total || 0)
      }
      const daysArr = Object.entries(dayMap)
        .map(([day, v]) => ({ day, total: v.total, fixed: v.fixed, rate: v.total ? v.fixed / v.total : 0 }))
        .sort((a, b) => a.day.localeCompare(b.day))
      setData({
        days: daysArr,
        total,
        fixed,
        rate: total ? fixed / total : 0,
        avgAttempts: total ? attemptsWeighted / total : 0,
      })
    })
    return () => { cancelled = true }
  }, [key, days])

  if (!data || data.total === 0) return null

  const W = 560
  const H = 96
  const pad = 6
  const ds = data.days
  const n = ds.length
  const maxT = Math.max(1, ...ds.map((d) => d.total))
  const x = (i) => (n <= 1 ? W / 2 : pad + (i * (W - 2 * pad)) / (n - 1))
  const yT = (v) => H - pad - (v / maxT) * (H - 2 * pad)
  const yR = (v) => H - pad - v * (H - 2 * pad)
  const volLine = ds.map((d, i) => `${x(i)},${yT(d.total)}`).join(' ')
  const area = `${pad},${H - pad} ${volLine} ${x(n - 1)},${H - pad}`
  const rateLine = ds.map((d, i) => `${x(i)},${yR(d.rate)}`).join(' ')
  const last = ds[n - 1]

  const pct = (v) => `${Math.round(v * 100)}%`

  return (
    <section className="rounded-2xl border border-white/10 bg-black/40 p-4 sm:p-5">
      <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <TrendingUp className="w-4 h-4 text-cyan-400" />
          {t('pages.healTrends.title', { defaultValue: 'Heal trends' })}
          <span className="text-[11px] text-white/35 font-mono">· {days}d</span>
        </h3>
        <div className="flex items-center gap-4 text-xs">
          <span className="text-white/60">{t('pages.healTrends.total', { defaultValue: 'Heals' })} <b className="text-white tabular-nums">{data.total}</b></span>
          <span className="text-emerald-300/90">{t('pages.healTrends.success', { defaultValue: 'Success' })} <b className="tabular-nums">{pct(data.rate)}</b></span>
          <span className="text-amber-300/80">{t('pages.healTrends.avg_attempts', { defaultValue: 'Avg attempts' })} <b className="tabular-nums">{data.avgAttempts.toFixed(1)}</b></span>
        </div>
      </div>
      <div className="overflow-x-auto">
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ minWidth: 320, height: 96 }} role="img" aria-label="daily heal volume and success rate">
          <defs>
            <linearGradient id="htg" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.35" />
              <stop offset="100%" stopColor="#22d3ee" stopOpacity="0.02" />
            </linearGradient>
          </defs>
          {[0.25, 0.5, 0.75].map((g) => (
            <line key={g} x1={pad} x2={W - pad} y1={H - pad - g * (H - 2 * pad)} y2={H - pad - g * (H - 2 * pad)} stroke="rgba(255,255,255,0.06)" strokeWidth="1" />
          ))}
          <polygon points={area} fill="url(#htg)" />
          <polyline points={volLine} fill="none" stroke="#22d3ee" strokeWidth="1.75" strokeLinejoin="round" />
          <polyline points={rateLine} fill="none" stroke="#34d399" strokeWidth="1.5" strokeDasharray="3 3" opacity="0.9" />
          <circle cx={x(n - 1)} cy={yT(last.total)} r="3.2" fill="#22d3ee" />
        </svg>
      </div>
      <div className="flex items-center gap-4 mt-1.5 text-[10px] text-white/40">
        <span className="inline-flex items-center gap-1.5"><span className="inline-block w-3 h-0.5 bg-cyan-400" /> {t('pages.healTrends.volume', { defaultValue: 'Daily volume' })}</span>
        <span className="inline-flex items-center gap-1.5"><span className="inline-block w-3 h-0.5 bg-emerald-400" /> {t('pages.healTrends.success_rate', { defaultValue: 'Success rate' })}</span>
      </div>
    </section>
  )
}
