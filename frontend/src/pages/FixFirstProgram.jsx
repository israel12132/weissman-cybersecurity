import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Target, Flame, GitBranch, ShieldAlert, Clock, CheckCircle2, AlertTriangle, Gem, FileText, Search } from 'lucide-react'
import { useClient } from '../context/ClientContext'
import { apiFetch } from '../utils/apiFetch'
import { SkeletonTable } from '../components/ui/Skeleton'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import Button from '../components/ui/Button'
import ShellScanActions from '../components/engine/ShellScanActions'
import { exportRowsCsv, exportRowsPdf, rowMatchesQuery } from '../lib/pageExport'

/**
 * FixFirstProgram — the authoritative, backend-computed remediation program.
 *
 * Unlike the family board (which derives buckets client-side from /api/findings), this panel
 * renders `GET /api/remediation/priority/:client_id`: one ranked, root-cause-deduplicated list
 * where each action already folds in EPSS/KEV effective risk, attack-graph choke points, an
 * SLA/overdue clock, and a compliance crosswalk. Nothing is recomputed in the browser — we only
 * present what the engine returned.
 */

/** Pure: reduce an SLA object to a compact view {tone, key, days}. Exported for tests. */
export function deriveSlaView(sla) {
  if (!sla || typeof sla !== 'object') return { tone: 'muted', key: 'unknown', days: null }
  const state = String(sla.state || 'unknown')
  const due = Number.isFinite(sla.due_in_days) ? sla.due_in_days : null
  switch (state) {
    case 'overdue':
      return { tone: 'danger', key: 'overdue', days: due == null ? null : Math.abs(due) }
    case 'due_soon':
      return { tone: 'warn', key: 'due_soon', days: due }
    case 'on_track':
      return { tone: 'ok', key: 'on_track', days: due }
    default:
      return { tone: 'muted', key: 'unknown', days: null }
  }
}

/** Pure: clamp a 0..100 priority score to a 0..1 bar fraction. Exported for tests. */
export function scoreFraction(score) {
  const n = Number(score)
  if (!Number.isFinite(n)) return 0
  return Math.max(0, Math.min(1, n / 100))
}

/** CSV header for the exported program. Exported so tests assert column stability. */
export const PROGRAM_CSV_HEADER = [
  'rank', 'title', 'asset', 'priority_score', 'max_effective_risk', 'closes_findings',
  'kev', 'kev_ransomware', 'on_choke_point', 'crown_jewel', 'business_value_usd',
  'sla_state', 'sla_due_in_days', 'sla_target_days', 'frameworks', 'rationale',
]

/** Pure: flatten a program array into CSV rows aligned with PROGRAM_CSV_HEADER. */
export function programToCsvRows(program) {
  if (!Array.isArray(program)) return []
  return program.map((it) => {
    const sla = it?.sla || {}
    const frameworks = Array.isArray(it?.compliance)
      ? it.compliance.map((c) => `${c.framework}:${c.control}`).join(' | ')
      : ''
    return [
      it?.rank ?? '',
      it?.title ?? '',
      it?.asset ?? '',
      it?.priority_score ?? '',
      it?.max_effective_risk ?? '',
      it?.closes_findings ?? '',
      it?.kev ? 'yes' : 'no',
      it?.kev_ransomware ? 'yes' : 'no',
      it?.on_choke_point ? 'yes' : 'no',
      it?.crown_jewel ? 'yes' : 'no',
      it?.business_value_usd ?? '',
      sla.state ?? '',
      sla.due_in_days ?? '',
      sla.target_days ?? '',
      frameworks,
      it?.rationale ?? '',
    ]
  })
}

/** Pure: compact USD formatter ($5M, $250K, $900). Returns null for non-positive/invalid. */
export function formatUsd(value) {
  const n = Number(value)
  if (!Number.isFinite(n) || n <= 0) return null
  if (n >= 1_000_000_000) return `$${(n / 1_000_000_000).toFixed(1).replace(/\.0$/, '')}B`
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1).replace(/\.0$/, '')}M`
  if (n >= 1_000) return `$${(n / 1_000).toFixed(1).replace(/\.0$/, '')}K`
  return `$${Math.round(n)}`
}

const TONE_CLASS = {
  danger: 'text-rose-300 bg-rose-500/10 border-rose-500/30',
  warn: 'text-amber-300 bg-amber-500/10 border-amber-500/30',
  ok: 'text-emerald-300 bg-emerald-500/10 border-emerald-500/30',
  muted: 'text-white/40 bg-white/5 border-white/10',
}

function SlaBadge({ sla, t }) {
  const v = deriveSlaView(sla)
  const Icon = v.key === 'overdue' ? AlertTriangle : v.key === 'on_track' ? CheckCircle2 : Clock
  const label =
    v.key === 'overdue'
      ? t('pages.remediationHub.program_sla_overdue', { days: v.days ?? '?', defaultValue: 'Overdue {{days}}d' })
      : v.key === 'unknown'
      ? t('pages.remediationHub.program_sla_unknown', { defaultValue: 'No SLA clock' })
      : t('pages.remediationHub.program_sla_due', { days: v.days ?? '?', defaultValue: 'Due in {{days}}d' })
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium border ${TONE_CLASS[v.tone]}`}>
      <Icon className="w-3 h-3" />
      {label}
    </span>
  )
}

function Chip({ color, children, title }) {
  return (
    <span
      title={title}
      className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono border"
      style={{ color, borderColor: `${color}55`, background: `${color}14` }}
    >
      {children}
    </span>
  )
}

function SummaryStat({ label, value, color }) {
  return (
    <div className="bg-black/40 border border-white/10 rounded-lg px-3 py-2">
      <div className="text-[10px] uppercase tracking-wider text-white/40">{label}</div>
      <div className="text-lg font-bold tabular-nums" style={color ? { color } : { color: '#fff' }}>{value}</div>
    </div>
  )
}

export default function FixFirstProgram() {
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
  const [searchQuery, setSearchQuery] = useState('')

  const load = useCallback(async (id) => {
    if (id == null) { setData(null); return }
    setLoading(true)
    setError(null)
    try {
      const d = await apiFetch(`/api/remediation/priority/${encodeURIComponent(id)}?limit=200`)
      setData(d && typeof d === 'object' ? d : null)
    } catch (e) {
      setError(e?.message || 'load failed')
      setData(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load(clientId) }, [clientId, load])

  const program = useMemo(() => (Array.isArray(data?.program) ? data.program : []), [data])
  const frameworks = Array.isArray(data?.compliance_frameworks) ? data.compliance_frameworks : []

  // Client-side filter over the already-loaded, tenant-scoped program (match on the human-
  // readable title and the affected asset). Export follows whatever the search narrows to.
  const filteredProgram = useMemo(
    () => program.filter((it) => rowMatchesQuery(searchQuery, [it?.title, it?.asset])),
    [program, searchQuery],
  )

  const handleRefresh = useCallback(() => load(clientId), [load, clientId])
  const exportCsv = useCallback(
    () => exportRowsCsv(PROGRAM_CSV_HEADER, programToCsvRows(filteredProgram), 'weissman-fix-first'),
    [filteredProgram],
  )
  const exportPdf = useCallback(
    () => exportRowsPdf('Weissman Fix-First Program', PROGRAM_CSV_HEADER, programToCsvRows(filteredProgram), 'weissman-fix-first'),
    [filteredProgram],
  )

  return (
    <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
      <div className="px-4 pt-4">
        <EvidenceNotice>
          Live remediation program from GET /api/remediation/priority/:clientId — backend-ranked,
          root-cause deduplicated, with EPSS/KEV effective risk, attack-graph choke points and SLA
          clocks. Nothing is recomputed in the browser; no fabricated remediation telemetry.
        </EvidenceNotice>
      </div>
      <div className="p-4 border-b border-white/10 flex items-center justify-between gap-3 flex-wrap">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <Target className="w-4 h-4 text-cyan-400" />
          {t('pages.remediationHub.program_heading', { defaultValue: 'Fix-First Program' })}
        </h3>
        <div className="flex items-center gap-3">
          <span className="text-[10px] text-white/35 font-mono hidden sm:inline">
            {t('pages.remediationHub.program_caption', { defaultValue: 'Backend-ranked · root-cause deduplicated · EPSS/KEV + choke points + SLA' })}
          </span>
          <ShellScanActions
            onRefresh={handleRefresh}
            onExport={exportCsv}
            refreshLoading={loading}
            exportDisabled={!filteredProgram.length}
          />
          <Button
            variant="unstyled"
            type="button"
            onClick={exportPdf}
            disabled={!filteredProgram.length}
            title={t('common.export_pdf', { defaultValue: 'Export PDF' })}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-[11px] font-semibold border border-white/15 text-white/70 hover:bg-white/10 disabled:opacity-40 transition-colors"
          >
            <FileText className="w-3.5 h-3.5" />
            {t('common.export_pdf', { defaultValue: 'PDF' })}
          </Button>
        </div>
      </div>

      {clientId == null ? (
        <div className="p-4">
          <EmptyState compact icon="shield" title={t('pages.remediationHub.program_no_client', { defaultValue: 'Select a client to load its prioritized remediation program.' })} />
        </div>
      ) : error ? (
        <div className="p-4 text-sm text-rose-300 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          {t('pages.remediationHub.program_error', { error, defaultValue: "Couldn't load the remediation program: {{error}}." })}
        </div>
      ) : loading ? (
        <div className="p-4"><SkeletonTable rows={5} cols={3} /></div>
      ) : program.length === 0 ? (
        <div className="p-4">
          <EmptyState compact icon="shield" title={t('pages.remediationHub.program_empty', { defaultValue: 'No open findings to prioritize for this client.' })} />
        </div>
      ) : (
        <>
          <div className="p-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 border-b border-white/5">
            <SummaryStat label={t('pages.remediationHub.program_stat_actions', { defaultValue: 'Actions' })} value={data.remediation_actions ?? program.length} />
            <SummaryStat label={t('pages.remediationHub.program_stat_overdue', { defaultValue: 'Overdue' })} value={data.overdue_actions ?? 0} color="#f43f5e" />
            <SummaryStat label={t('pages.remediationHub.program_stat_due_soon', { defaultValue: 'Due soon' })} value={data.due_soon_actions ?? 0} color="#fbbf24" />
            <SummaryStat label={t('pages.remediationHub.program_stat_kev', { defaultValue: 'KEV' })} value={data.kev_actions ?? 0} color="#fb923c" />
            <SummaryStat label={t('pages.remediationHub.program_stat_choke', { defaultValue: 'Choke points' })} value={data.choke_point_actions ?? 0} color="#a78bfa" />
            <SummaryStat label={t('pages.remediationHub.program_stat_crown', { defaultValue: 'Crown jewels' })} value={data.crown_jewel_actions ?? 0} color="#f0abfc" />
          </div>

          {frameworks.length > 0 && (
            <div className="px-4 py-2 border-b border-white/5 flex items-center gap-2 flex-wrap">
              <span className="text-[10px] uppercase tracking-wider text-white/35">{t('pages.remediationHub.program_frameworks', { defaultValue: 'Frameworks' })}</span>
              {frameworks.map((fw) => <Chip key={fw} color="#22d3ee">{fw}</Chip>)}
            </div>
          )}

          <div className="px-4 py-2 border-b border-white/5 flex items-center gap-2">
            <div className="relative flex-1 max-w-xs">
              <Search className="w-3 h-3 text-white/30 absolute left-2 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder={t('pages.remediationHub.program_search', { defaultValue: 'Search title or asset' })}
                aria-label={t('pages.remediationHub.program_search', { defaultValue: 'Search title or asset' })}
                className="w-full pl-6 pr-2 py-1 rounded-md text-[11px] bg-black/40 border border-white/10 text-white/80 placeholder-white/30 focus:outline-none focus:border-cyan-500/40"
              />
            </div>
          </div>

          {filteredProgram.length === 0 ? (
            <div className="p-4 text-[11px] text-white/35">
              {t('pages.remediationHub.program_no_match', { defaultValue: 'No remediation actions match your search.' })}
            </div>
          ) : (
          <div className="divide-y divide-white/5">
            {filteredProgram.map((item) => {
              const risk = Number(item.max_effective_risk)
              return (
                <div key={`${item.rank}-${item.title}-${item.asset}`} className="p-4 hover:bg-white/5 transition-colors">
                  <div className="flex items-start gap-3">
                    <div className="text-lg font-bold tabular-nums text-white/30 w-8 shrink-0 text-right">{item.rank}</div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <h4 className="text-sm font-semibold text-white truncate">{item.title || item.cwe || t('pages.remediationHub.program_untitled', { defaultValue: 'Untitled finding' })}</h4>
                        <SlaBadge sla={item.sla} t={t} />
                        {item.kev_ransomware ? (
                          <Chip color="#f43f5e" title="Ransomware-associated KEV"><Flame className="w-3 h-3" />{t('pages.remediationHub.program_ransomware', { defaultValue: 'Ransomware' })}</Chip>
                        ) : item.kev ? (
                          <Chip color="#fb923c" title="CISA Known Exploited Vulnerability"><ShieldAlert className="w-3 h-3" />KEV</Chip>
                        ) : null}
                        {item.on_choke_point && (
                          <Chip color="#a78bfa" title="On an attack-path choke point"><GitBranch className="w-3 h-3" />{t('pages.remediationHub.program_choke', { defaultValue: 'Choke point' })}</Chip>
                        )}
                        {item.crown_jewel && (
                          <Chip color="#f0abfc" title="Affects a business-critical crown-jewel asset"><Gem className="w-3 h-3" />{t('pages.remediationHub.program_crown', { defaultValue: 'Crown jewel' })}</Chip>
                        )}
                        {formatUsd(item.business_value_usd) && (
                          <Chip color="#f0abfc" title="Estimated financial blast radius">{formatUsd(item.business_value_usd)}</Chip>
                        )}
                      </div>
                      {item.asset && <div className="text-[11px] font-mono text-white/45 truncate mb-1.5">{item.asset}</div>}
                      <div className="flex items-center gap-2 mb-1.5">
                        <div className="h-1.5 w-full max-w-[220px] rounded-full bg-white/5 overflow-hidden">
                          <div className="h-full bg-gradient-to-r from-cyan-500 to-rose-500" style={{ width: `${scoreFraction(item.priority_score) * 100}%` }} />
                        </div>
                        <span className="text-[10px] font-mono text-white/40 whitespace-nowrap tabular-nums">
                          {t('pages.remediationHub.program_score', { defaultValue: 'score' })} {Number(item.priority_score).toFixed(1)}
                          {Number.isFinite(risk) ? ` · ${t('pages.remediationHub.program_risk', { defaultValue: 'risk' })} ${risk.toFixed(1)}` : ''}
                        </span>
                      </div>
                      {item.closes_findings > 1 && (
                        <div className="text-[11px] text-cyan-300/80 mb-1">
                          {t('pages.remediationHub.program_closes', { count: item.closes_findings, defaultValue: 'One fix closes {{count}} findings' })}
                        </div>
                      )}
                      {Array.isArray(item.compliance) && item.compliance.length > 0 && (
                        <div className="flex items-center gap-1 flex-wrap mt-1">
                          {item.compliance.map((c) => (
                            <Chip key={`${c.framework}-${c.control}`} color="#34d399" title={`${c.framework}: ${c.title}`}>{c.control}</Chip>
                          ))}
                        </div>
                      )}
                      {item.rationale && <div className="text-[11px] text-white/35 mt-1.5 italic">{item.rationale}</div>}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
          )}
        </>
      )}
    </div>
  )
}
