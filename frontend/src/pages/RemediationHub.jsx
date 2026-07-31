import { useEffect, useMemo, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Wrench, Zap, CheckCircle, Clock, AlertTriangle, ShieldCheck, Search, X, ChevronDown, ChevronRight, Sparkles } from 'lucide-react';
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EmptyState from '../components/ui/EmptyState'
import Button from '../components/ui/Button'
import { SkeletonTable } from '../components/ui/Skeleton'
import { apiFetch } from '../utils/apiFetch'
import RemediationDetail from '../components/remediation/RemediationDetail'
import BatchHealPanel from '../components/remediation/BatchHealPanel'
import RemediationAnalyticsPanel from '../components/remediation/RemediationAnalyticsPanel'
import FixFirstProgram from './FixFirstProgram'
import PostureScoreCard from './PostureScoreCard'
import SlaForecastStrip from './SlaForecastStrip'
import BacklogAgingPanel from './BacklogAgingPanel'

/**
 * RemediationHub — derives the remediation board entirely from real `/api/findings`
 * data so it reflects the customer's actual posture. Families, severity, and status
 * are all computed from live findings; there are no fabricated workflows or totals.
 */

const SEV_META = {
  critical: { color: '#f43f5e', rank: 5, weight: 5 },
  high: { color: '#fb923c', rank: 4, weight: 4 },
  medium: { color: '#fbbf24', rank: 3, weight: 3 },
  low: { color: '#38bdf8', rank: 2, weight: 2 },
  info: { color: '#94a3b8', rank: 1, weight: 1 },
}
const SEVERITY_KEYS = ['critical', 'high', 'medium', 'low', 'info']
const normSev = (s) => (SEV_META[String(s || '').toLowerCase()] ? String(s).toLowerCase() : 'info')

const STATUS_FROM_FINDING = (status) => {
  const s = (status || '').toUpperCase()
  if (s === 'FIXED') return 'completed'
  if (s === 'IN_PROGRESS') return 'running'
  if (s === 'FALSE_POSITIVE') return 'completed'
  return 'pending'
}

const FAMILY_RULES = [
  { id: 'xss', label: 'Cross-Site Scripting (XSS)', match: (f) => /xss|cross.site|script.injection/i.test(`${f.title} ${f.description} ${f.cwe ?? ''}`) },
  { id: 'sqli', label: 'SQL Injection', match: (f) => /sql.?injection|sqli/i.test(`${f.title} ${f.description} ${f.cwe ?? ''}`) },
  { id: 'ssrf', label: 'SSRF / Server-Side Forgery', match: (f) => /ssrf|server.side.request/i.test(`${f.title} ${f.description}`) },
  { id: 'idor', label: 'BOLA / IDOR', match: (f) => /idor|bola|broken.object|insecure direct/i.test(`${f.title} ${f.description}`) },
  { id: 'tls', label: 'TLS / Certificate Hygiene', match: (f) => /tls|certificate|ssl|hsts/i.test(`${f.title} ${f.description}`) },
  { id: 'deps', label: 'Vulnerable Dependencies', match: (f) => /dependency|outdated package|cve-\d/i.test(`${f.title} ${f.description}`) },
  { id: 'ports', label: 'Exposed Services / Ports', match: (f) => /exposed.+port|open port|asm/i.test(`${f.title} ${f.description} ${f.source ?? ''}`) },
  { id: 'auth', label: 'Authentication Weaknesses', match: (f) => /(auth|password|jwt|oauth|saml)/i.test(`${f.title} ${f.description}`) },
]

function summarizeFamilies(findings) {
  const buckets = new Map()
  for (const f of findings) {
    const family = FAMILY_RULES.find((r) => r.match(f))
    const key = family?.id || 'other'
    const label = family?.label || 'Other Findings'
    const status = STATUS_FROM_FINDING(f.status)
    const sev = normSev(f.severity)
    const cur = buckets.get(key) || { id: key, label, total: 0, statuses: {}, severities: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, items: [] }
    cur.total += 1
    cur.statuses[status] = (cur.statuses[status] || 0) + 1
    cur.severities[sev] += 1
    cur.items.push(f)
    buckets.set(key, cur)
  }
  return Array.from(buckets.values())
    .map((b) => ({
      ...b,
      priority: SEVERITY_KEYS.reduce((s, k) => s + b.severities[k] * SEV_META[k].weight, 0),
      status:
        (b.statuses.running || 0) > 0
          ? 'running'
          : (b.statuses.pending || 0) > 0
          ? 'pending'
          : (b.statuses.completed || 0) > 0
          ? 'completed'
          : 'pending',
    }))
    .sort((a, b) => b.priority - a.priority)
}

function StatusBadge({ status, t }) {
  const colors = {
    completed: 'text-green-400 bg-green-500/10 border-green-500/30',
    running: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
    pending: 'text-text-tertiary bg-bg-3 border-border-strong',
  }
  const Icon = status === 'completed' ? CheckCircle : status === 'running' ? Clock : AlertTriangle
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium ${colors[status] || colors.pending}`}>
      <Icon className={`w-3.5 h-3.5 ${status === 'running' ? 'animate-spin' : ''}`} />
      {t(`pages.remediationHub.status_${status}`)}
    </span>
  )
}

function SeverityBar({ severities, total }) {
  if (!total) return null
  return (
    <div className="flex h-1.5 w-full max-w-[220px] rounded-full overflow-hidden bg-white/5">
      {SEVERITY_KEYS.map((k) => {
        const v = severities[k]
        if (!v) return null
        return <div key={k} style={{ width: `${(v / total) * 100}%`, background: SEV_META[k].color }} title={`${k}: ${v}`} />
      })}
    </div>
  )
}

export default function RemediationHub() {
  const { t } = useTranslation()
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [sevFilter, setSevFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [expanded, setExpanded] = useState({})
  const [selectedFinding, setSelectedFinding] = useState(null)
  const [healStats, setHealStats] = useState(null)
  const [batchOpen, setBatchOpen] = useState(null)
  const [showAnalytics, setShowAnalytics] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const d = await apiFetch('/api/findings?limit=2000')
      const arr = Array.isArray(d) ? d : Array.isArray(d?.findings) ? d.findings : []
      setFindings(arr)
    } catch (e) {
      setError(e.message || 'Failed to load findings')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  // Aggregate auto-heal analytics across the clients present in the current findings.
  useEffect(() => {
    const ids = [...new Set(findings.map((f) => f.client_id).filter(Boolean))].slice(0, 25)
    if (!ids.length) { setHealStats(null); return undefined }
    let cancelled = false
    Promise.all(
      ids.map((id) => apiFetch(`/api/clients/${id}/heal-stats`).catch(() => null)),
    ).then((list) => {
      if (cancelled) return
      const channelMap = {}
      const agg = list.filter(Boolean).reduce(
        (a, s) => {
          for (const c of s.by_channel || []) channelMap[c.channel] = (channelMap[c.channel] || 0) + (c.count || 0)
          return {
            total: a.total + (s.total || 0),
            fixed: a.fixed + (s.fixed || 0),
            broke_app: a.broke_app + (s.broke_app || 0),
            still_vulnerable: a.still_vulnerable + (s.still_vulnerable || 0),
            attested: a.attested + (s.attested || 0),
            attemptsSum: a.attemptsSum + (s.avg_attempts || 1) * (s.total || 0),
            maxAttempts: Math.max(a.maxAttempts, s.max_attempts || 1),
          }
        },
        { total: 0, fixed: 0, broke_app: 0, still_vulnerable: 0, attested: 0, attemptsSum: 0, maxAttempts: 1 },
      )
      agg.by_channel = Object.entries(channelMap).map(([channel, count]) => ({ channel, count })).sort((x, y) => y.count - x.count)
      setHealStats(agg.total > 0 ? agg : null)
    })
    return () => { cancelled = true }
  }, [findings])

  const filteredFindings = useMemo(() => {
    let list = findings
    if (sevFilter !== 'all') list = list.filter((f) => normSev(f.severity) === sevFilter)
    if (statusFilter !== 'all') list = list.filter((f) => STATUS_FROM_FINDING(f.status) === statusFilter)
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter((f) => `${f.title ?? ''} ${f.description ?? ''}`.toLowerCase().includes(q))
    }
    return list
  }, [findings, sevFilter, statusFilter, search])

  const workflows = useMemo(() => summarizeFamilies(filteredFindings), [filteredFindings])

  const totals = useMemo(() => {
    let completed = 0, running = 0, pending = 0, critHigh = 0
    for (const f of filteredFindings) {
      const s = STATUS_FROM_FINDING(f.status)
      if (s === 'completed') completed += 1
      else if (s === 'running') running += 1
      else pending += 1
      const sev = normSev(f.severity)
      if (sev === 'critical' || sev === 'high') critHigh += 1
    }
    return { completed, running, pending, critHigh, total: filteredFindings.length }
  }, [filteredFindings])

  const { exportCsv } = useFindingsWorkbench(filteredFindings, { csvPrefix: 'weissman-remediation' })

  return (
    <PageShell
      title={t('pages.remediationHub.title')}
      subtitle={t('pages.remediationHub.subtitle')}
      badge={t('pages.remediationHub.badge')}
      badgeColor="#22d3ee"
      icon={<Wrench />}
      actions={(
        <ShellScanActions
          onRefresh={load}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="space-y-6">
        <p className="text-xs text-white/45 font-mono">{t('pages.remediationHub.intro')}</p>

        {/* Board-level posture score, distilled from the same fix-first program below. */}
        <PostureScoreCard />

        {/* Proactive SLA breach forecast over 7/14/30/60/90-day horizons. */}
        <SlaForecastStrip />

        {/* Backlog-aging health: open findings by age × severity, aged-critical flags. */}
        <BacklogAgingPanel />

        {/* Authoritative, backend-ranked program (fix-first). The family board below is the
            client-side derived view over the same findings. */}
        <FixFirstProgram />

        {error && (
          <div className="p-4 rounded-xl border border-red-500/30 bg-red-900/20 text-red-300 text-sm flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            {t('pages.remediationHub.load_error', { error })}
          </div>
        )}

        {/* Stats */}
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
          <StatCard label={t('pages.remediationHub.total_findings')} value={totals.total} icon={<ShieldCheck className="w-4 h-4 text-cyan-400" />} loading={loading} />
          <StatCard label={t('pages.remediationHub.crit_high')} value={totals.critHigh} icon={<AlertTriangle className="w-4 h-4 text-rose-400" />} color="#f43f5e" loading={loading} />
          <StatCard label={t('pages.remediationHub.pending_fix')} value={totals.pending} icon={<AlertTriangle className="w-4 h-4 text-yellow-400" />} loading={loading} />
          <StatCard label={t('pages.remediationHub.in_progress')} value={totals.running} icon={<Clock className="w-4 h-4 text-orange-400" />} loading={loading} />
          <StatCard label={t('pages.remediationHub.resolved')} value={totals.completed} icon={<CheckCircle className="w-4 h-4 text-green-400" />} loading={loading} />
        </div>

        {/* Auto-heal analytics strip */}
        {healStats && (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 px-4 py-2.5 rounded-xl border border-cyan-500/20 bg-cyan-500/[0.04]">
              <span className="text-[11px] font-mono uppercase tracking-wider text-cyan-300/80 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5" /> {t('pages.remediationHub.heal_analytics')}
              </span>
              <HealStat label={t('pages.remediationHub.heal_runs')} value={healStats.total} />
              <HealStat label={t('pages.remediationHub.heal_fix_rate')} value={`${Math.round((healStats.fixed / Math.max(1, healStats.total)) * 100)}%`} color="#22c55e" />
              <HealStat label={t('pages.remediationHub.heal_avg_attempts')} value={(healStats.attemptsSum / Math.max(1, healStats.total)).toFixed(1)} />
              <HealStat label={t('pages.remediationHub.heal_attested')} value={healStats.attested} color="#34d399" />
              <button
                type="button"
                onClick={() => setShowAnalytics((v) => !v)}
                className="ml-auto text-[10px] font-mono px-2.5 py-1 rounded-md border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10"
              >
                {showAnalytics ? t('pages.remediationHub.hide_analytics') : t('pages.remediationHub.show_analytics')}
              </button>
            </div>
            {showAnalytics && <RemediationAnalyticsPanel stats={healStats} />}
          </div>
        )}

        {/* Filters */}
        <div className="flex flex-col lg:flex-row lg:items-center gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white/25" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={t('pages.remediationHub.search_placeholder')}
              aria-label={t('pages.remediationHub.search_placeholder')}
              className="w-full bg-black/40 border border-white/10 rounded-lg pl-9 pr-8 py-2 text-xs text-white/80 placeholder-white/25 font-mono focus:outline-none focus:border-cyan-500/40"
            />
            {search && (
              <Button
                variant="unstyled"
                type="button"
                onClick={() => setSearch('')}
                aria-label={t('common.clear')}
                title={t('common.clear')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/60"
              >
                <X className="w-3.5 h-3.5" />
              </Button>
            )}
          </div>
          <div className="flex items-center gap-1 flex-wrap">
            <Pill active={sevFilter === 'all'} onClick={() => setSevFilter('all')}>{t('pages.remediationHub.filter_all')}</Pill>
            {['critical', 'high', 'medium', 'low'].map((k) => (
              <Pill key={k} active={sevFilter === k} color={SEV_META[k].color} onClick={() => setSevFilter((p) => (p === k ? 'all' : k))}>
                {t(`pages.remediationHub.sev_${k}`)}
              </Pill>
            ))}
          </div>
          <div className="flex items-center gap-1 flex-wrap">
            <Pill active={statusFilter === 'all'} onClick={() => setStatusFilter('all')}>{t('pages.remediationHub.filter_all')}</Pill>
            {['pending', 'running', 'completed'].map((k) => (
              <Pill key={k} active={statusFilter === k} onClick={() => setStatusFilter((p) => (p === k ? 'all' : k))}>
                {t(`pages.remediationHub.status_${k}`)}
              </Pill>
            ))}
          </div>
        </div>

        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/10 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Zap className="w-4 h-4 text-cyan-400" />
              {t('pages.remediationHub.families_heading', { count: workflows.length })}
            </h3>
            <Link to="/findings" className="text-xs text-cyan-300 hover:text-cyan-200">{t('pages.remediationHub.open_findings')}</Link>
          </div>

          <div className="divide-y divide-white/5">
            {loading ? (
              <div className="p-4"><SkeletonTable rows={5} cols={3} /></div>
            ) : workflows.length === 0 ? (
              <div className="p-4">
                <EmptyState
                  compact
                  icon="shield"
                  title={t('pages.remediationHub.empty_title')}
                  body={t('pages.remediationHub.empty_hint')}
                />
              </div>
            ) : (
              workflows.map((w) => {
                const isOpen = !!expanded[w.id]
                return (
                <div key={w.id} className="hover:bg-white/[0.03] transition-colors">
                  <div className="p-4 flex items-center justify-between gap-3">
                    <button
                      type="button"
                      onClick={() => setExpanded((e) => ({ ...e, [w.id]: !e[w.id] }))}
                      className="flex-1 min-w-0 text-left flex items-start gap-2"
                    >
                      {isOpen ? <ChevronDown className="w-4 h-4 text-white/40 mt-0.5 shrink-0" /> : <ChevronRight className="w-4 h-4 text-white/40 mt-0.5 shrink-0" />}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-3 mb-1.5 flex-wrap">
                          <h4 className="text-sm font-semibold text-white truncate">{w.label}</h4>
                          <StatusBadge status={w.status} t={t} />
                        </div>
                        <div className="flex items-center gap-3 mb-2">
                          <SeverityBar severities={w.severities} total={w.total} />
                          <span className="text-[10px] font-mono text-white/35 whitespace-nowrap">
                            {SEVERITY_KEYS.filter((k) => w.severities[k] > 0).map((k) => `${t(`pages.remediationHub.sev_${k}`)} ${w.severities[k]}`).join(' · ')}
                          </span>
                        </div>
                        <div className="text-xs text-text-tertiary">
                          {w.total === 1
                            ? t('pages.remediationHub.findings_count', { count: w.total })
                            : t('pages.remediationHub.findings_count_plural', { count: w.total })}{' '}
                          · {t('pages.remediationHub.status_breakdown', {
                            pending: w.statuses.pending || 0,
                            running: w.statuses.running || 0,
                            resolved: w.statuses.completed || 0,
                          })}
                        </div>
                      </div>
                    </button>
                    <Link
                      to={`/findings?q=${encodeURIComponent(w.label)}`}
                      className="px-3 py-1.5 bg-white/5 text-white/60 border border-white/10 rounded-lg text-xs font-medium hover:bg-white/10 transition-colors shrink-0"
                    >
                      {t('pages.remediationHub.view_findings')}
                    </Link>
                  </div>
                  {isOpen && (
                    <div className="px-4 pb-4 pl-10 space-y-1.5">
                      {w.items.some((f) => f.has_patch) && (
                        <div className="pb-1">
                          {batchOpen === w.id ? (
                            <BatchHealPanel findings={w.items} onClose={() => setBatchOpen(null)} />
                          ) : (
                            <button
                              type="button"
                              onClick={() => setBatchOpen(w.id)}
                              className="text-[11px] px-2.5 py-1 rounded-md border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10 flex items-center gap-1.5"
                            >
                              <Wrench className="w-3 h-3" />
                              {t('pages.remediationHub.batch_heal_open', { n: w.items.filter((f) => f.has_patch).length })}
                            </button>
                          )}
                        </div>
                      )}
                      {w.items.slice(0, 50).map((f) => (
                        <div key={f.raw_id || f.finding_id} className="flex items-center justify-between gap-3 p-2 rounded-lg border border-white/5 bg-black/20">
                          <div className="min-w-0 flex items-center gap-2">
                            <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: SEV_META[normSev(f.severity)].color }} />
                            <span className="text-xs text-white/75 truncate">{f.title || f.finding_id}</span>
                            {f.has_patch && <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 shrink-0">FIX</span>}
                          </div>
                          <button
                            type="button"
                            onClick={() => setSelectedFinding(f)}
                            className="px-2.5 py-1 bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 rounded-md text-[11px] font-medium hover:bg-cyan-500/30 transition-colors shrink-0 flex items-center gap-1"
                          >
                            <Sparkles className="w-3 h-3" />
                            {t('pages.remediationHub.view_fix')}
                          </button>
                        </div>
                      ))}
                      {w.items.length > 50 && (
                        <div className="text-[10px] text-white/30 font-mono pl-2">+{w.items.length - 50} more…</div>
                      )}
                    </div>
                  )}
                </div>
                )
              })
            )}
          </div>
        </div>
      </div>

      {selectedFinding && (
        <RemediationDetail finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
      )}
    </PageShell>
  )
}

function Pill({ active, color = '#22d3ee', onClick, children }) {
  return (
    <Button
      variant="unstyled"
      type="button"
      onClick={onClick}
      className="px-2.5 py-1 rounded-md text-[10px] font-mono uppercase tracking-wider border transition-colors"
      style={{
        color: active ? color : 'rgba(255,255,255,0.45)',
        borderColor: active ? `${color}66` : 'rgba(255,255,255,0.1)',
        background: active ? `${color}16` : 'transparent',
      }}
    >
      {children}
    </Button>
  )
}

function HealStat({ label, value, color }) {
  return (
    <span className="inline-flex items-baseline gap-1.5">
      <span className="text-sm font-bold tabular-nums" style={color ? { color } : { color: '#e2e8f0' }}>{value}</span>
      <span className="text-[10px] text-white/40 uppercase tracking-wide">{label}</span>
    </span>
  )
}

function StatCard({ label, value, icon, color, loading }) {
  return (
    <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-text-tertiary">{label}</span>
        {icon}
      </div>
      <div className="text-2xl font-bold tabular-nums" style={color ? { color } : { color: '#fff' }}>
        {loading ? '—' : value}
      </div>
    </div>
  )
}
