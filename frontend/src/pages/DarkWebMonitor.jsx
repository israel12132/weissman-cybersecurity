/**
 * Dark Web Monitor — real, customer-scoped intelligence only.
 *
 * Pulls credential / dark-web findings from `/api/findings` (sources: `leak_hunter`,
 * `darkweb_intel`, `dark_web_monitor`, etc.). If no rows exist we render an honest
 * empty state with the exact next steps (run a scan, set HIBP_API_KEY, etc.). No
 * fabricated `acmecorp.com` data.
 */
import React, { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
const DARK_WEB_SOURCES = new Set([
  'leak_hunter',
  'darkweb_intel',
  'dark_web_monitor',
  'typosquatting_monitor',
])

function severityBadge(sev) {
  const s = (sev || 'info').toLowerCase()
  const map = {
    critical: 'text-rose-300 bg-rose-500/10 border-rose-500/40',
    high: 'text-orange-300 bg-orange-500/10 border-orange-500/40',
    medium: 'text-yellow-300 bg-yellow-500/10 border-yellow-500/40',
    low: 'text-blue-300 bg-blue-500/10 border-blue-500/40',
    info: 'text-slate-300 bg-slate-700/10 border-slate-500/40',
  }
  return `inline-block px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider ${map[s] || map.info}`
}

export default function DarkWebMonitor() {
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
        const filtered = arr.filter((f) => DARK_WEB_SOURCES.has((f.source || f.engine || '').toLowerCase()))
        filtered.sort(
          (a, b) =>
            (SEVERITY_ORDER[(b.severity || '').toLowerCase()] || 0) -
            (SEVERITY_ORDER[(a.severity || '').toLowerCase()] || 0),
        )
        setFindings(filtered)
      } catch (e) {
        if (!cancelled) setError(e.message || 'Failed to load findings')
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => { cancelled = true }
  }, [])

  const stats = useMemo(() => {
    const by = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of findings) {
      const s = (f.severity || 'info').toLowerCase()
      if (by[s] !== undefined) by[s] += 1
    }
    return { ...by, total: findings.length }
  }, [findings])

  return (
    <PageShell title={t('pages.darkWebMonitor.title')} subtitle={t('pages.darkWebMonitor.subtitle')}>
      <div className="space-y-6">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <StatCard label={t('pages.darkWebMonitor.total_hits')} value={stats.total} />
          <StatCard label={t('pages.darkWebMonitor.critical')} value={stats.critical} accent="text-rose-300" />
          <StatCard label={t('pages.darkWebMonitor.high')} value={stats.high} accent="text-orange-300" />
          <StatCard label={t('pages.darkWebMonitor.medium')} value={stats.medium} accent="text-yellow-300" />
          <StatCard label={t('pages.darkWebMonitor.low_info')} value={stats.low + stats.info} accent="text-slate-300" />
        </div>

        {error && (
          <div className="p-4 rounded-xl border border-red-500/30 bg-red-900/20 text-red-300 text-sm">
            {t('pages.darkWebMonitor.load_error', { error })}
          </div>
        )}

        <section className="bg-black/40 border border-white/10 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-white">{t('pages.darkWebMonitor.findings_heading')}</h3>
            <Link to="/findings" className="text-xs text-cyan-300 hover:text-cyan-200">{t('pages.darkWebMonitor.open_findings')}</Link>
          </div>
          {loading ? (
            <div className="text-sm text-white/40">{t('pages.darkWebMonitor.loading')}</div>
          ) : findings.length === 0 ? (
            <EmptyState />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-[12px] font-mono">
                <thead>
                  <tr className="text-left text-white/45 border-b border-white/10">
                    <th className="py-2 pr-3">{t('pages.darkWebMonitor.col_severity')}</th>
                    <th className="py-2 pr-3">{t('pages.darkWebMonitor.col_title')}</th>
                    <th className="py-2 pr-3">{t('pages.darkWebMonitor.col_source')}</th>
                    <th className="py-2 pr-3">{t('pages.darkWebMonitor.col_target')}</th>
                    <th className="py-2 pr-3">{t('pages.darkWebMonitor.col_discovered')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {findings.slice(0, 200).map((f) => (
                    <tr key={f.id || f.finding_id} className="hover:bg-white/[0.02]">
                      <td className="py-2 pr-3"><span className={severityBadge(f.severity)}>{(f.severity || 'info').toUpperCase()}</span></td>
                      <td className="py-2 pr-3 text-white/85 max-w-md truncate" title={f.title}>{f.title || '—'}</td>
                      <td className="py-2 pr-3 text-white/55">{f.source || f.engine || '—'}</td>
                      <td className="py-2 pr-3 text-white/55 max-w-xs truncate" title={f.target}>{f.target || '—'}</td>
                      <td className="py-2 pr-3 text-white/40">{f.discovered_at ? new Date(f.discovered_at).toLocaleString() : ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </PageShell>
  )
}

function StatCard({ label, value, accent }) {
  return (
    <div className="rounded-2xl bg-black/40 border border-white/10 p-4">
      <div className="text-[10px] font-mono uppercase tracking-widest text-white/40">{label}</div>
      <div className={`text-3xl font-bold mt-1 ${accent || 'text-white'}`}>{value}</div>
    </div>
  )
}

function EmptyState() {
  const { t } = useTranslation()
  return (
    <div className="text-sm text-white/55 space-y-3">
      <div>{t('pages.darkWebMonitor.empty_title')}</div>
      <ul className="list-disc pl-5 space-y-1 text-xs text-white/45">
        <li>
          {t('pages.darkWebMonitor.empty_step_scan_before')}{' '}
          <Link to="/clients" className="underline text-cyan-300">{t('pages.darkWebMonitor.empty_step_scan_link')}</Link>{' '}
          {t('pages.darkWebMonitor.empty_step_scan_after')}
        </li>
        <li>{t('pages.darkWebMonitor.empty_step_keys')}</li>
        <li>
          {t('pages.darkWebMonitor.empty_step_engine_before')}{' '}
          <Link to="/engines" className="underline text-cyan-300">{t('pages.darkWebMonitor.empty_step_engine_link')}</Link>{' '}
          {t('pages.darkWebMonitor.empty_step_engine_after')}
        </li>
      </ul>
    </div>
  )
}
