import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Wrench, Zap, CheckCircle, Clock, AlertTriangle, ShieldCheck } from 'lucide-react';
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

/**
 * RemediationHub — derives the workflow board entirely from real `/api/findings`
 * data so it reflects the customer's actual posture. There are no hard-coded
 * workflows or fabricated "auto-fixed" totals.
 */

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
    const cur = buckets.get(key) || { id: key, label, total: 0, statuses: {} }
    cur.total += 1
    cur.statuses[status] = (cur.statuses[status] || 0) + 1
    buckets.set(key, cur)
  }
  return Array.from(buckets.values()).map((b) => ({
    ...b,
    status:
      (b.statuses.running || 0) > 0
        ? 'running'
        : (b.statuses.pending || 0) > 0
        ? 'pending'
        : (b.statuses.completed || 0) > 0
        ? 'completed'
        : 'pending',
  })).sort((a, b) => b.total - a.total)
}

function StatusBadge({ status }) {
  const { t } = useTranslation()
  const colors = {
    completed: 'text-green-400 bg-green-500/10 border-green-500/30',
    running: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
    pending: 'text-gray-400 bg-gray-500/10 border-gray-500/30',
  }
  const Icon = status === 'completed' ? CheckCircle : status === 'running' ? Clock : AlertTriangle
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium ${colors[status] || colors.pending}`}>
      <Icon className={`w-3.5 h-3.5 ${status === 'running' ? 'animate-spin' : ''}`} />
      {t(`pages.remediationHub.status_${status}`, { defaultValue: status })}
    </span>
  )
}

export default function RemediationHub() {
  const { t } = useTranslation()
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      setLoading(true)
      setError(null)
      try {
        const r = await apiFetch('/api/findings?limit=2000')
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        const d = await r.json()
        if (cancelled) return
        const arr = Array.isArray(d) ? d : Array.isArray(d?.findings) ? d.findings : []
        setFindings(arr)
      } catch (e) {
        if (!cancelled) setError(e.message || 'Failed to load findings')
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => { cancelled = true }
  }, [])

  const workflows = useMemo(() => summarizeFamilies(findings), [findings])

  const totals = useMemo(() => {
    let completed = 0, running = 0, pending = 0
    for (const f of findings) {
      const s = STATUS_FROM_FINDING(f.status)
      if (s === 'completed') completed += 1
      else if (s === 'running') running += 1
      else pending += 1
    }
    return { completed, running, pending, total: findings.length }
  }, [findings])

  return (
    <PageShell title={t('pages.remediationHub.title')} icon={<Wrench />}>
      <div className="space-y-6">
        <p className="text-xs text-white/45 font-mono">
          {t('pages.remediationHub.intro')}
        </p>

        {error && (
          <div className="p-4 rounded-xl border border-red-500/30 bg-red-900/20 text-red-300 text-sm">
            {t('pages.remediationHub.load_error', { error })}
          </div>
        )}

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <StatCard label={t('pages.remediationHub.total_findings')} value={totals.total} icon={<ShieldCheck className="w-4 h-4 text-cyan-400" />} />
          <StatCard label={t('pages.remediationHub.pending_fix')} value={totals.pending} icon={<AlertTriangle className="w-4 h-4 text-yellow-400" />} />
          <StatCard label={t('pages.remediationHub.in_progress')} value={totals.running} icon={<Clock className="w-4 h-4 text-orange-400" />} />
          <StatCard label={t('pages.remediationHub.resolved')} value={totals.completed} icon={<CheckCircle className="w-4 h-4 text-green-400" />} />
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
              <div className="p-6 text-sm text-white/45">{t('pages.remediationHub.loading')}</div>
            ) : workflows.length === 0 ? (
              <div className="p-6 text-sm text-white/45 space-y-2">
                <div>{t('pages.remediationHub.empty_title')}</div>
                <div className="text-xs text-white/35">
                  {t('pages.remediationHub.empty_hint')}
                </div>
              </div>
            ) : (
              workflows.map((w) => (
                <div key={w.id} className="p-4 hover:bg-white/5 transition-colors">
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 mb-1">
                        <h4 className="text-sm font-semibold text-white truncate">{w.label}</h4>
                        <StatusBadge status={w.status} />
                      </div>
                      <div className="text-xs text-gray-400">
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
                    <Link
                      to={`/findings?q=${encodeURIComponent(w.label)}`}
                      className="px-3 py-1.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-medium hover:bg-cyan-500/30 transition-colors"
                    >
                      {t('pages.remediationHub.view_findings')}
                    </Link>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </PageShell>
  )
}

function StatCard({ label, value, icon }) {
  return (
    <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm text-gray-400">{label}</span>
        {icon}
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
    </div>
  )
}
