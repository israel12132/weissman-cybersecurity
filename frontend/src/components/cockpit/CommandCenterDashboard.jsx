/**
 * Command Center — the enterprise landing dashboard.
 *
 * A single, real-data command surface (CrowdStrike / Palo Alto class): board-level posture, the
 * cross-domain attack-vector synthesis, live telemetry, MITRE coverage, prioritized remediation, and
 * the freshest critical findings. Every panel is backed by a live API — no placeholder data:
 *   - GET /api/executive-summary/:id     posture grade, SLA exposure, ranked remediation actions
 *   - GET /api/analytics/attack-vectors  composite multi-stage attack vectors
 *   - GET /api/clients/:id/findings      real findings feed
 *   - GET /api/dashboard/exec-kpis       executive KPI strip
 * plus the shared LiveActivityFeed (WebSocket telemetry) and MitreCoverageHeatmap.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { ShieldAlert, Activity, Crosshair, Clock, ArrowRight } from 'lucide-react'
import { useClient } from '../../context/ClientContext'
import { apiFetch } from '../../utils/apiFetch'
import LiveActivityFeed from './LiveActivityFeed'
import MitreCoverageHeatmap from './MitreCoverageHeatmap'

const GLASS =
  'rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 transition-all duration-300 hover:border-white/20'

const SEV_COLOR = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22d3ee',
  info: '#6b7280',
}

function sevColor(s) {
  return SEV_COLOR[(s || 'info').toLowerCase()] || SEV_COLOR.info
}

function gradeColor(grade) {
  const g = (grade || 'F')[0]
  return { A: '#22d3ee', B: '#4ade80', C: '#fbbf24', D: '#f97316', F: '#ef4444' }[g] || '#ef4444'
}

function HeroCard({ label, value, sub, color, icon: Icon }) {
  return (
    <div className={GLASS}>
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-medium text-white/50 uppercase tracking-widest">{label}</span>
        {Icon && <Icon className="w-4 h-4" style={{ color }} />}
      </div>
      <p className="text-3xl font-bold mt-2 tabular-nums" style={{ color }}>{value}</p>
      {sub && <p className="text-[11px] text-white/40 mt-1">{sub}</p>}
    </div>
  )
}

export default function CommandCenterDashboard() {
  const { t } = useTranslation()
  const { selectedClient, selectedClientId } = useClient()
  const [summary, setSummary] = useState(null)
  const [vectors, setVectors] = useState([])
  const [findings, setFindings] = useState([])
  const [kpis, setKpis] = useState(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async (background = false) => {
    if (!selectedClientId) return
    if (!background) setLoading(true)
    const [summaryData, vectorsData, findingsData, kpiData] = await Promise.all([
      apiFetch(`/api/executive-summary/${selectedClientId}`).catch(() => null),
      apiFetch(`/api/analytics/attack-vectors?client_id=${selectedClientId}`).catch(() => null),
      apiFetch(`/api/clients/${selectedClientId}/findings`).catch(() => null),
      apiFetch('/api/dashboard/exec-kpis').catch(() => null),
    ])
    setSummary(summaryData?.ok ? summaryData : null)
    setVectors(Array.isArray(vectorsData?.vectors) ? vectorsData.vectors : [])
    setFindings(Array.isArray(findingsData?.findings) ? findingsData.findings : [])
    setKpis(kpiData || null)
    if (!background) setLoading(false)
  }, [selectedClientId])

  useEffect(() => {
    load()
    const iv = setInterval(() => load(true), 30000)
    return () => clearInterval(iv)
  }, [load])

  const posture = summary?.posture
  const remediation = summary?.remediation
  const topActions = Array.isArray(remediation?.top_actions) ? remediation.top_actions : []

  const severityCounts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of findings) {
      const s = (f.severity || 'info').toLowerCase()
      if (s.includes('critical')) c.critical += 1
      else if (s.includes('high')) c.high += 1
      else if (s.includes('med')) c.medium += 1
      else if (s.includes('low')) c.low += 1
      else c.info += 1
    }
    return c
  }, [findings])

  const topFindings = useMemo(() => {
    const rank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }
    return [...findings]
      .sort((a, b) => (rank[(b.severity || '').toLowerCase()] || 0) - (rank[(a.severity || '').toLowerCase()] || 0))
      .slice(0, 6)
  }, [findings])

  const clientLabel = selectedClient?.name || t('components.commandCenter.client_fallback', { id: selectedClientId })
  const grade = posture?.grade || '—'
  const score = posture?.score != null ? Math.round(posture.score) : (kpis?.security_score ?? 0)
  const maxSev = Math.max(severityCounts.critical, severityCounts.high, severityCounts.medium, severityCounts.low, 1)

  if (!selectedClientId) {
    return (
      <div className="p-8 flex items-center justify-center min-h-[400px]">
        <div className={`${GLASS} max-w-md text-center py-12`}>
          <p className="text-white/80 text-sm uppercase tracking-widest mb-2">{t('components.commandCenter.no_client')}</p>
          <p className="text-white/50 text-xs">{t('components.commandCenter.select_sidebar')}</p>
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 md:p-8 space-y-6">
      <div className="flex items-end justify-between gap-3 flex-wrap">
        <div>
          <h2 className="text-xs font-semibold text-white/60 uppercase tracking-[0.2em] mb-1">
            {t('components.commandCenter.title')}
          </h2>
          <p className="text-white/40 text-sm">{t('components.commandCenter.subtitle', { client: clientLabel })}</p>
        </div>
        <span className="inline-flex items-center gap-1.5 text-[10px] font-mono text-emerald-300 px-2 py-0.5 rounded border border-emerald-500/30 bg-emerald-500/10">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          {t('components.commandCenter.live')}
        </span>
      </div>

      {/* Hero posture band */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <div className={`${GLASS} flex items-center gap-4`}>
          <div
            className="w-16 h-16 rounded-2xl flex items-center justify-center text-3xl font-bold shrink-0"
            style={{ color: gradeColor(grade), border: `2px solid ${gradeColor(grade)}55`, background: `${gradeColor(grade)}12` }}
          >
            {loading ? '—' : grade}
          </div>
          <div>
            <div className="text-[11px] text-white/50 uppercase tracking-widest">{t('components.commandCenter.posture')}</div>
            <div className="text-2xl font-bold tabular-nums" style={{ color: gradeColor(grade) }}>{loading ? '—' : `${score}`}</div>
            <div className="text-[10px] text-white/40">/ 100</div>
          </div>
        </div>
        <HeroCard label={t('components.commandCenter.findings')} value={loading ? '—' : (remediation?.total_findings ?? findings.length)} color="#22d3ee" icon={ShieldAlert} />
        <HeroCard label={t('components.commandCenter.attack_vectors')} value={loading ? '—' : vectors.length} sub={t('components.commandCenter.synthesized')} color="#a78bfa" icon={Crosshair} />
        <HeroCard label={t('components.commandCenter.kev')} value={loading ? '—' : (remediation?.kev_actions ?? 0)} color="#ef4444" icon={Activity} />
        <HeroCard label={t('components.commandCenter.overdue_sla')} value={loading ? '—' : (summary?.sla?.overdue_now ?? 0)} color="#f97316" icon={Clock} />
      </div>

      {/* Attack vectors + live activity */}
      <div className="grid grid-cols-1 xl:grid-cols-[3fr_2fr] gap-4">
        <div className={GLASS}>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-semibold text-white/60 uppercase tracking-widest">{t('components.commandCenter.top_vectors')}</h3>
            <Link to="/attack-vectors" className="text-[10px] font-mono text-[#a78bfa] hover:text-[#c4b5fd] inline-flex items-center gap-1">
              {t('components.commandCenter.view_all')} <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
          {vectors.length === 0 ? (
            <p className="text-sm text-white/30 py-8 text-center">{t('components.commandCenter.no_vectors')}</p>
          ) : (
            <div className="space-y-3">
              {vectors.slice(0, 4).map((v) => (
                <div key={v.id} className="rounded-xl border border-white/10 bg-white/[0.02] p-3">
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <span className="text-sm font-semibold text-white truncate">{v.name}</span>
                    <span
                      className="text-[10px] font-mono px-2 py-0.5 rounded border shrink-0 uppercase"
                      style={{ color: sevColor(v.severity), borderColor: `${sevColor(v.severity)}40`, backgroundColor: `${sevColor(v.severity)}12` }}
                    >
                      {v.severity}
                    </span>
                  </div>
                  <div className="flex items-center flex-wrap gap-1 mb-1.5">
                    {(v.mitre_chain || []).map((m, i) => (
                      <span key={m} className="flex items-center gap-1">
                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[#6366f1]/20 text-[#a5b4fc]">{m}</span>
                        {i < v.mitre_chain.length - 1 && <span className="text-white/20 text-[9px]">→</span>}
                      </span>
                    ))}
                  </div>
                  <div className="flex items-center gap-3 text-[10px] text-white/40">
                    <span>{t('components.commandCenter.confidence')}: <span className="font-mono" style={{ color: sevColor(v.severity) }}>{Math.round((v.confidence || 0) * 100)}%</span></span>
                    <span>{t('components.commandCenter.priority')}: <span className="font-mono text-white/60">{v.priority}</span></span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
        <div className={GLASS}>
          <h3 className="text-xs font-semibold text-white/60 uppercase tracking-widest mb-4">{t('components.commandCenter.live_activity')}</h3>
          <LiveActivityFeed maxHeight={280} />
        </div>
      </div>

      {/* Severity distribution + MITRE coverage */}
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_2fr] gap-4">
        <div className={GLASS}>
          <h3 className="text-xs font-semibold text-white/60 uppercase tracking-widest mb-4">{t('components.commandCenter.severity_distribution')}</h3>
          <div className="space-y-3">
            {['critical', 'high', 'medium', 'low'].map((s) => (
              <div key={s}>
                <div className="flex justify-between text-[11px] mb-1">
                  <span className="capitalize" style={{ color: sevColor(s) }}>{t(`components.commandCenter.sev_${s}`)}</span>
                  <span className="font-mono text-white/50 tabular-nums">{severityCounts[s]}</span>
                </div>
                <div className="h-2 rounded-full bg-white/5 overflow-hidden">
                  <div className="h-full rounded-full transition-all duration-500" style={{ width: `${Math.round((severityCounts[s] / maxSev) * 100)}%`, backgroundColor: sevColor(s) }} />
                </div>
              </div>
            ))}
          </div>
        </div>
        <MitreCoverageHeatmap />
      </div>

      {/* Priority remediation + recent findings */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div className={GLASS}>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-semibold text-white/60 uppercase tracking-widest">{t('components.commandCenter.fix_first')}</h3>
            <Link to="/remediation" className="text-[10px] font-mono text-[#22d3ee] hover:text-[#67e8f9] inline-flex items-center gap-1">
              {t('components.commandCenter.view_all')} <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
          {topActions.length === 0 ? (
            <p className="text-sm text-white/30 py-6 text-center">{t('components.commandCenter.no_actions')}</p>
          ) : (
            <ol className="space-y-2">
              {topActions.slice(0, 6).map((a, i) => (
                <li key={a.finding_id || i} className="flex items-start gap-3 text-sm">
                  <span className="w-5 h-5 rounded-full bg-white/10 text-white/70 text-[10px] font-mono flex items-center justify-center shrink-0 mt-0.5">{i + 1}</span>
                  <div className="min-w-0">
                    <span className="text-white/85 block truncate">{a.title || a.finding_id}</span>
                    <span className="text-[10px] text-white/40">{a.asset}</span>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </div>
        <div className={GLASS}>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-semibold text-white/60 uppercase tracking-widest">{t('components.commandCenter.recent_findings')}</h3>
            <Link to="/findings" className="text-[10px] font-mono text-[#22d3ee] hover:text-[#67e8f9] inline-flex items-center gap-1">
              {t('components.commandCenter.view_all')} <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
          {topFindings.length === 0 ? (
            <p className="text-sm text-white/30 py-6 text-center">{t('components.commandCenter.no_findings')}</p>
          ) : (
            <ul className="space-y-2">
              {topFindings.map((f) => (
                <li key={f.id || f.finding_id} className="flex items-center gap-3 text-sm">
                  <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ backgroundColor: sevColor(f.severity) }} />
                  <span className="text-white/80 truncate flex-1">{f.title}</span>
                  <span className="text-[10px] font-mono text-white/40 shrink-0">{f.source}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  )
}
