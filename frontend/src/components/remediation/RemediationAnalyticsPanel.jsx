import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { ShieldCheck, CheckCircle, AlertTriangle, GitPullRequest, Repeat } from 'lucide-react'

/**
 * RemediationAnalyticsPanel — a self-contained visual dashboard for auto-heal outcomes, built from
 * the aggregated heal-stats (no charting dependency; inline SVG donut + CSS bars). Theme-aware dark.
 */

const VERDICT_SEGMENTS = [
  { key: 'fixed', color: '#22c55e', labelKey: 'verdict_fixed', label: 'Fixed' },
  { key: 'still_vulnerable', color: '#fb923c', labelKey: 'verdict_still_vulnerable', label: 'Still vulnerable' },
  { key: 'broke_app', color: '#f43f5e', labelKey: 'verdict_broke_app', label: 'Broke app' },
  { key: 'other', color: '#64748b', labelKey: 'heal_other', label: 'Other' },
]

function Donut({ segments, total }) {
  const R = 52
  const C = 2 * Math.PI * R
  let offset = 0
  return (
    <svg viewBox="0 0 130 130" className="w-36 h-36 shrink-0" role="img" aria-label="verdict distribution">
      <circle cx="65" cy="65" r={R} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="16" />
      {total > 0 && segments.map((s) => {
        if (!s.value) return null
        const frac = s.value / total
        const dash = frac * C
        const el = (
          <circle
            key={s.key}
            cx="65" cy="65" r={R} fill="none"
            stroke={s.color} strokeWidth="16"
            strokeDasharray={`${dash} ${C - dash}`}
            strokeDashoffset={-offset}
            transform="rotate(-90 65 65)"
          />
        )
        offset += dash
        return el
      })}
      <text x="65" y="61" textAnchor="middle" className="fill-white" style={{ fontSize: 20, fontWeight: 700 }}>{total}</text>
      <text x="65" y="78" textAnchor="middle" style={{ fontSize: 9, fill: 'rgba(255,255,255,0.4)' }}>runs</text>
    </svg>
  )
}

function Kpi({ icon, label, value, color }) {
  return (
    <div className="bg-black/30 border border-white/10 rounded-xl p-3">
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-[11px] text-white/45">{label}</span>
        {icon}
      </div>
      <div className="text-xl font-bold tabular-nums" style={color ? { color } : { color: '#fff' }}>{value}</div>
    </div>
  )
}

export default function RemediationAnalyticsPanel({ stats }) {
  const { t } = useTranslation()
  const total = stats?.total || 0

  const segments = useMemo(() => {
    const fixed = stats?.fixed || 0
    const still = stats?.still_vulnerable || 0
    const broke = stats?.broke_app || 0
    const other = Math.max(0, total - fixed - still - broke)
    const map = { fixed, still_vulnerable: still, broke_app: broke, other }
    return VERDICT_SEGMENTS.map((s) => ({ ...s, value: map[s.key] || 0 }))
  }, [stats, total])

  const channels = stats?.by_channel || []
  const maxChan = Math.max(1, ...channels.map((c) => c.count || 0))
  const successPct = total > 0 ? Math.round(((stats?.fixed || 0) / total) * 100) : 0
  const avgAttempts = total > 0 ? ((stats?.attemptsSum || 0) / total).toFixed(1) : '1.0'

  return (
    <div className="p-4 rounded-xl border border-white/10 bg-black/40 space-y-5">
      {/* KPI row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Kpi icon={<CheckCircle className="w-4 h-4 text-green-400" />} label={t('pages.remediationHub.heal_fix_rate', { defaultValue: 'fix rate' })} value={`${successPct}%`} color="#22c55e" />
        <Kpi icon={<Repeat className="w-4 h-4 text-amber-400" />} label={t('pages.remediationHub.heal_avg_attempts', { defaultValue: 'avg attempts' })} value={avgAttempts} />
        <Kpi icon={<ShieldCheck className="w-4 h-4 text-emerald-400" />} label={t('pages.remediationHub.heal_attested', { defaultValue: 'attested' })} value={stats?.attested || 0} color="#34d399" />
        <Kpi icon={<AlertTriangle className="w-4 h-4 text-rose-400" />} label={t('pages.remediationHub.verdict_broke_app', { defaultValue: 'broke app' })} value={stats?.broke_app || 0} color="#f43f5e" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Verdict donut */}
        <div className="flex items-center gap-4">
          <Donut segments={segments} total={total} />
          <div className="space-y-1.5">
            {segments.map((s) => (
              <div key={s.key} className="flex items-center gap-2 text-xs">
                <span className="w-2.5 h-2.5 rounded-sm" style={{ background: s.color }} />
                <span className="text-white/70">{t(`pages.remediationHub.${s.labelKey}`, { defaultValue: s.label })}</span>
                <span className="text-white/40 tabular-nums ml-auto">{s.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Channel bars */}
        <div className="space-y-2">
          <div className="text-xs font-semibold text-white/70 flex items-center gap-1.5">
            <GitPullRequest className="w-3.5 h-3.5 text-cyan-400" /> {t('pages.remediationHub.channel_label', { defaultValue: 'Delivery channel' })}
          </div>
          {channels.length === 0 ? (
            <div className="text-xs text-white/30">—</div>
          ) : (
            channels.map((c) => (
              <div key={c.channel} className="flex items-center gap-2">
                <span className="text-[10px] font-mono text-white/45 w-32 truncate">{c.channel}</span>
                <div className="flex-1 h-2 rounded-full bg-white/5 overflow-hidden">
                  <div className="h-full rounded-full bg-cyan-400/70" style={{ width: `${(c.count / maxChan) * 100}%` }} />
                </div>
                <span className="text-[10px] tabular-nums text-white/50 w-8 text-right">{c.count}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
