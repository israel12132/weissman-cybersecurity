import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Gauge, AlertTriangle } from 'lucide-react'
import { useClient } from '../context/ClientContext'
import { apiFetch } from '../lib/apiBase'
import { SkeletonTable } from '../components/ui/Skeleton'

/**
 * PostureScoreCard — board-level security posture at a glance.
 *
 * Renders GET /api/posture/score/:client_id: the 0..100 score + A–F grade, the four sub-scores,
 * and the ranked drivers. The score is computed server-side from the same fix-first program the
 * rest of the hub shows, so this card never disagrees with the queue below it.
 */

/** Pure: brand colour for an A–F grade. Exported for tests. */
export function gradeColor(grade) {
  switch (String(grade || '').toUpperCase()) {
    case 'A': return '#34d399'
    case 'B': return '#a3e635'
    case 'C': return '#fbbf24'
    case 'D': return '#fb923c'
    case 'F': return '#f43f5e'
    default: return '#94a3b8'
  }
}

/**
 * Pure: pick the projection steps that first reach each distinct grade along the fix path — the
 * natural "fix N → reach grade" milestones. Returns up to 3. Exported for tests.
 */
export function gradeMilestones(projection) {
  if (!Array.isArray(projection)) return []
  const out = []
  const seen = new Set()
  for (const s of projection) {
    const g = String(s?.projected_grade || '')
    if (g && !seen.has(g)) {
      seen.add(g)
      out.push(s)
    }
    if (out.length >= 3) break
  }
  return out
}

/** Pure: colour a 0..100 sub-score on the same scale as grades. Exported for tests. */
export function scoreColor(value) {
  const n = Number(value)
  if (!Number.isFinite(n)) return '#94a3b8'
  if (n >= 90) return '#34d399'
  if (n >= 80) return '#a3e635'
  if (n >= 70) return '#fbbf24'
  if (n >= 60) return '#fb923c'
  return '#f43f5e'
}

function SubScore({ label, value }) {
  const v = Number(value) || 0
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-[10px] uppercase tracking-wider text-white/40">{label}</span>
        <span className="text-[11px] font-mono tabular-nums" style={{ color: scoreColor(v) }}>{v.toFixed(0)}</span>
      </div>
      <div className="h-1.5 rounded-full bg-white/5 overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${Math.max(0, Math.min(100, v))}%`, background: scoreColor(v) }} />
      </div>
    </div>
  )
}

export default function PostureScoreCard() {
  const { t } = useTranslation()
  const { selectedClientId, clients } = useClient()
  const clientId = useMemo(() => {
    if (selectedClientId != null && selectedClientId !== '') return selectedClientId
    const first = Array.isArray(clients) && clients.length ? Number(clients[0]?.id) : null
    return Number.isFinite(first) && first > 0 ? first : null
  }, [selectedClientId, clients])

  const [data, setData] = useState(null)
  const [projection, setProjection] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const load = useCallback(async (id) => {
    if (id == null) { setData(null); setProjection([]); return }
    setLoading(true)
    setError(null)
    try {
      const r = await apiFetch(`/api/posture/score/${encodeURIComponent(id)}`)
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const d = await r.json()
      setData(d?.posture && typeof d.posture === 'object' ? d.posture : null)
      setProjection(Array.isArray(d?.projection) ? d.projection : [])
    } catch (e) {
      setError(e?.message || 'load failed')
      setData(null)
      setProjection([])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load(clientId) }, [clientId, load])

  if (clientId == null) return null

  return (
    <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
      <div className="p-4 border-b border-white/10 flex items-center gap-2">
        <Gauge className="w-4 h-4 text-cyan-400" />
        <h3 className="text-sm font-semibold text-white">{t('pages.remediationHub.posture_heading', { defaultValue: 'Security Posture' })}</h3>
      </div>

      {error ? (
        <div className="p-4 text-sm text-rose-300 flex items-center gap-2"><AlertTriangle className="w-4 h-4 shrink-0" />{t('pages.remediationHub.posture_error', { error, defaultValue: "Couldn't load posture: {{error}}." })}</div>
      ) : loading ? (
        <div className="p-4"><SkeletonTable rows={3} cols={2} /></div>
      ) : !data ? (
        <div className="p-4 text-sm text-white/40">{t('pages.remediationHub.posture_empty', { defaultValue: 'No posture data yet.' })}</div>
      ) : (
        <div className="p-4 grid grid-cols-1 md:grid-cols-[auto,1fr,1fr] gap-6 items-center">
          {/* Score + grade */}
          <div className="flex flex-col items-center justify-center px-2">
            <div className="text-5xl font-black tabular-nums leading-none" style={{ color: gradeColor(data.grade) }}>
              {Number(data.score).toFixed(0)}
            </div>
            <div className="mt-1 flex items-center gap-2">
              <span className="text-2xl font-black" style={{ color: gradeColor(data.grade) }}>{data.grade}</span>
              <span className="text-[10px] text-white/40 uppercase tracking-wider">{t('pages.remediationHub.posture_of_100', { defaultValue: '/ 100' })}</span>
            </div>
          </div>

          {/* Sub-scores */}
          <div className="space-y-2.5">
            <SubScore label={t('pages.remediationHub.posture_sub_exploit', { defaultValue: 'Exploitability control' })} value={data.sub_scores?.exploitability_control} />
            <SubScore label={t('pages.remediationHub.posture_sub_timeliness', { defaultValue: 'Remediation timeliness' })} value={data.sub_scores?.remediation_timeliness} />
            <SubScore label={t('pages.remediationHub.posture_sub_business', { defaultValue: 'Business exposure' })} value={data.sub_scores?.business_exposure} />
            <SubScore label={t('pages.remediationHub.posture_sub_severity', { defaultValue: 'Severity load' })} value={data.sub_scores?.severity_load} />
          </div>

          {/* Drivers */}
          <div>
            <div className="text-[10px] uppercase tracking-wider text-white/40 mb-2">{t('pages.remediationHub.posture_drivers', { defaultValue: 'Top drivers' })}</div>
            {Array.isArray(data.drivers) && data.drivers.length > 0 ? (
              <ul className="space-y-1.5">
                {data.drivers.map((d, i) => (
                  <li key={i} className="flex items-start gap-1.5 text-[11px] text-white/70">
                    <span className="mt-1 w-1 h-1 rounded-full bg-rose-400 shrink-0" />
                    <span>{d}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="text-[11px] text-emerald-300/80">{t('pages.remediationHub.posture_clean', { defaultValue: 'No significant risk drivers — posture is healthy.' })}</div>
            )}
          </div>
        </div>
      )}

      {/* Remediation impact projection: fix the top N actions → reach this grade. */}
      {!loading && !error && data && gradeMilestones(projection).length > 0 && (
        <div className="px-4 pb-4 -mt-1">
          <div className="text-[10px] uppercase tracking-wider text-white/40 mb-2">
            {t('pages.remediationHub.posture_projection', { defaultValue: 'Impact projection' })}
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {gradeMilestones(projection).map((s) => (
              <div key={s.after_fixing_rank} className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg border border-white/10 bg-white/[0.03]">
                <span className="text-[11px] text-white/60">
                  {t('pages.remediationHub.posture_fix_n', { count: s.actions_fixed, defaultValue: 'Fix top {{count}}' })}
                </span>
                <span className="text-[11px] text-white/30">→</span>
                <span className="text-sm font-bold tabular-nums" style={{ color: gradeColor(s.projected_grade) }}>
                  {Number(s.projected_score).toFixed(0)} {s.projected_grade}
                </span>
                {Number(s.delta) > 0 && (
                  <span className="text-[10px] font-mono text-emerald-300/80">+{Number(s.delta).toFixed(0)}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
