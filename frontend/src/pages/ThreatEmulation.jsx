import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useState, useEffect, useCallback, useMemo } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { motion } from 'framer-motion'
import {
  RefreshCw, Shield, ShieldAlert, Target, History, AlertTriangle, CheckCircle2,
} from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EmptyState from '../components/ui/EmptyState'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { apiFetch } from '../utils/apiFetch'
import { clientPrimaryTargetUrl } from '../lib/clientTarget'
import { useJobPoll, resolveJobFindings } from '../lib/useJobPoll'
import Button from '../components/ui/Button'
import ScopedClientControl from '../components/clients/ScopedClientControl'


/** UI ids aligned with backend `APT_SCENARIOS` in threat_emulation_engine.rs */
const APT_GROUPS = [
  { id: 'lazarus', color: '#ef4444', techniques: ['T1595.002', 'T1059', 'T1486'] },
  { id: 'apt28', color: '#f97316', techniques: ['T1190', 'T1566.001', 'T1078'] },
  { id: 'apt29', color: '#f59e0b', techniques: ['T1195.002', 'T1550.001', 'T1021'] },
  { id: 'apt41', color: '#8b5cf6', techniques: ['T1190', 'T1525', 'T1027'] },
  { id: 'sandworm', color: '#6366f1', techniques: ['T1190', 'T1485', 'T1210'] },
  { id: 'kimsuky', color: '#10b981', techniques: ['T1566.002', 'T1078', 'T1041'] },
  { id: 'equation', color: '#22d3ee', techniques: ['T1021.002', 'T1542', 'T1014'] },
]

const GROUP_MATCHERS = {
  lazarus: /lazarus|hidden.?cobra/i,
  apt28: /apt28|fancy.?bear|sofacy/i,
  apt29: /apt29|cozy.?bear|dukes/i,
  apt41: /apt41|double.?dragon|winnti/i,
  sandworm: /sandworm|voodoo.?bear/i,
  kimsuky: /kimsuky|black.?banshee|chollima/i,
  equation: /equation.?group|nsa.?tao/i,
}

function parseFindingsList(data) {
  return Array.isArray(data) ? data : Array.isArray(data?.findings) ? data.findings : []
}

function isThreatEmulationFinding(f) {
  const src = String(f?.source || '').toLowerCase()
  const title = String(f?.title || '').toLowerCase()
  if (src.includes('threat_emulation')) return !title.includes('summary')
  return title.includes('apt emulation') || title.includes('[lazarus') || title.includes('[apt')
}

function groupIdForFinding(f) {
  const blob = [
    f?.raw_data?.apt_group,
    f?.raw?.apt_group,
    f?.title,
    f?.description,
  ].filter(Boolean).join(' ')
  for (const [id, re] of Object.entries(GROUP_MATCHERS)) {
    if (re.test(blob)) return id
  }
  return null
}

function findingBlocked(f) {
  if (f?.raw_data?.blocked === true || f?.raw?.blocked === true) return true
  return String(f?.severity || '').toLowerCase() === 'info'
}

function statsFromFindings(findings) {
  const byGroup = Object.fromEntries(APT_GROUPS.map((g) => [g.id, []]))
  for (const f of findings) {
    const gid = groupIdForFinding(f)
    if (gid && byGroup[gid]) byGroup[gid].push(f)
  }
  const results = {}
  for (const g of APT_GROUPS) {
    const rows = byGroup[g.id] || []
    const tested = rows.length
    const blocked = rows.filter(findingBlocked).length
    const gaps = rows.filter((f) => !findingBlocked(f)).length
    results[g.id] = {
      techniques_tested: tested,
      gaps,
      blocked,
      blocked_pct: tested ? Math.round((blocked / tested) * 100) : null,
      detected_pct: tested ? Math.round((gaps / tested) * 100) : null,
      findings: rows,
      has_data: tested > 0,
    }
  }
  return results
}

function severityBar(value, max = 100) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100))
  const color = pct > 75 ? '#ef4444' : pct > 50 ? '#f97316' : '#22d3ee'
  return { pct, color }
}

const SEV_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22d3ee',
  info: '#64748b',
}

function renderEmulationFinding(f, i) {
  const sev = (f.severity || 'info').toLowerCase()
  const color = SEV_COLORS[sev] || SEV_COLORS.info
  return (
    <div key={f.id || f.finding_id || i} className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] px-3 py-2.5 space-y-1">
      <div className="flex items-start gap-2">
        <span
          className="text-[9px] font-mono uppercase shrink-0 px-1.5 py-0.5 rounded border"
          style={{ color, borderColor: `${color}40` }}
        >
          {sev}
        </span>
        <span className="text-[12px] font-mono text-[var(--text-primary)] min-w-0 flex-1">{f.title || 'Finding'}</span>
      </div>
      {f.description && (
        <p className="text-[10px] font-mono text-[var(--text-muted)] leading-relaxed pl-0.5">{f.description}</p>
      )}
    </div>
  )
}

function AptCard({ group, result, t }) {
  const name = t(`pages.threatEmulation.apt_groups.${group.id}.name`)
  const alias = t(`pages.threatEmulation.apt_groups.${group.id}.alias`)
  const nation = t(`pages.threatEmulation.apt_groups.${group.id}.nation`)
  const description = t(`pages.threatEmulation.apt_groups.${group.id}.description`)
  const blockedPct = result?.blocked_pct ?? null
  const detectedPct = result?.detected_pct ?? null
  const { pct: blockPct, color: blockColor } = severityBar(blockedPct ?? 0)
  const { pct: detectPct } = severityBar(detectedPct ?? 0)

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 space-y-4 hover:border-[var(--border-strong)] transition-all"
      style={{ borderColor: `${group.color}25` }}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span
              className="w-2 h-2 rounded-full shrink-0"
              style={{ backgroundColor: group.color, boxShadow: `0 0 5px ${group.color}80` }}
            />
            <h3 className="text-sm font-bold text-white">{name}</h3>
            {!result?.has_data && (
              <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-[var(--border-default)] text-[var(--text-muted)]">
                {t('pages.threatEmulation.no_surface')}
              </span>
            )}
          </div>
          <p className="text-[10px] font-mono text-[var(--text-muted)]">{alias} · {nation}</p>
        </div>
        {result?.has_data && result.gaps > 0 && (
          <span className="shrink-0 text-[10px] font-mono px-2 py-0.5 rounded border border-red-500/30 text-red-300 bg-red-950/30">
            {t('pages.threatEmulation.gap_badge', { count: result.gaps })}
          </span>
        )}
      </div>

      <p className="text-xs text-[var(--text-tertiary)] leading-relaxed">{description}</p>

      <div className="flex flex-wrap gap-1">
        {group.techniques.map((tech) => (
          <span key={tech} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[var(--row-hover-bg)] border border-[var(--border-default)] text-[var(--text-muted)]">
            {tech}
          </span>
        ))}
      </div>

      {result?.has_data ? (
        <div className="space-y-2 pt-2 border-t border-[var(--border-subtle)]">
          <div className="flex items-center justify-between text-[11px] font-mono">
            <span className="text-[var(--text-tertiary)]">{t('pages.threatEmulation.blocked')}</span>
            <span style={{ color: blockColor }}>{blockedPct ?? 0}%</span>
          </div>
          <div className="h-1.5 rounded-full bg-[var(--row-hover-bg)] overflow-hidden">
            <div className="h-full rounded-full transition-all" style={{ width: `${blockPct}%`, backgroundColor: blockColor }} />
          </div>
          <div className="flex items-center justify-between text-[11px] font-mono">
            <span className="text-[var(--text-tertiary)]">{t('pages.threatEmulation.detected_not_blocked')}</span>
            <span className="text-amber-400">{detectedPct ?? 0}%</span>
          </div>
          <div className="h-1.5 rounded-full bg-[var(--row-hover-bg)] overflow-hidden">
            <div className="h-full rounded-full bg-amber-500/70 transition-all" style={{ width: `${detectPct}%` }} />
          </div>
          <p className="text-[10px] font-mono text-[var(--text-disabled)]">
            {t('pages.threatEmulation.results_summary', {
              tested: result.techniques_tested,
              gaps: result.gaps,
            })}
          </p>
          {result.findings?.slice(0, 2).map((f) => (
            <div key={f.id || f.finding_id || f.title} className="text-[10px] text-[var(--text-muted)] truncate font-mono">
              {findingBlocked(f) ? '✓' : '⚠'} {f.title}
            </div>
          ))}
        </div>
      ) : (
        <div className="pt-2 border-t border-[var(--border-subtle)]">
          <p className="text-[11px] font-mono text-[var(--text-disabled)]">{t('pages.threatEmulation.no_data')}</p>
        </div>
      )}
    </motion.div>
  )
}

export default function ThreatEmulation() {
  const { t } = useTranslation()
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const { postScan } = useCommandCenterScan(selectedClientId)
  const [emulationFindings, setEmulationFindings] = useState([])
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [activeJobId, setActiveJobId] = useState(null)
  const [toast, setToast] = useState(null)
  const [error, setError] = useState('')

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((cur) => (cur?.id === id ? null : cur)), 5000)
  }, [])

  const loadData = useCallback(async (clientId) => {
    setLoading(true)
    setError('')
    try {
      const q = clientId ? `?client_id=${clientId}&limit=1000` : '?limit=1000'
      const [findingsData, histData] = await Promise.all([
        apiFetch(`/api/findings${q}`).catch(() => null),
        apiFetch('/api/engines/history/threat_emulation?limit=20').catch(() => null),
      ])
      if (findingsData) {
        setEmulationFindings(parseFindingsList(findingsData).filter(isThreatEmulationFinding))
      }
      if (histData) {
        setHistory(Array.isArray(histData?.jobs) ? histData.jobs : [])
      }
    } catch (e) {
      setError(e?.message || t('pages.threatEmulation.load_failed'))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => {
    apiFetch('/api/clients')
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
      .catch(() => {})
  }, [])

  useEffect(() => {
    loadData(selectedClientId)
  }, [selectedClientId, loadData])

  const groupResults = useMemo(
    () => statsFromFindings(emulationFindings),
    [emulationFindings],
  )

  const aggregate = useMemo(() => {
    const withData = APT_GROUPS.filter((g) => groupResults[g.id]?.has_data)
    const totalTested = withData.reduce((s, g) => s + (groupResults[g.id]?.techniques_tested || 0), 0)
    const totalGaps = withData.reduce((s, g) => s + (groupResults[g.id]?.gaps || 0), 0)
    const totalBlocked = withData.reduce((s, g) => s + (groupResults[g.id]?.blocked || 0), 0)
    const coveragePct = Math.round((withData.length / APT_GROUPS.length) * 100)
    return { totalTested, totalGaps, totalBlocked, groupsWithSurface: withData.length, coveragePct }
  }, [groupResults])

  const {
    filteredFindings,
    counts,
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    exportCsv,
    total,
  } = useFindingsWorkbench(emulationFindings, {
    csvPrefix: 'threat-emulation',
    haystackFn: (f) => `${f.title || ''} ${f.description || ''} ${groupIdForFinding(f) || ''} ${f.type || ''}`,
  })

  const runEmulation = useCallback(async () => {
    if (!selectedClientId) {
      showToast('error', t('pages.threatEmulation.select_client_first'))
      return
    }
    const client = clients.find((c) => String(c.id) === String(selectedClientId))
    const target = clientPrimaryTargetUrl(client)
    if (!target) {
      showToast('error', t('pages.threatEmulation.missing_target'))
      return
    }
    setRunning(true)
    setError('')
    try {
      const { ok, data: d } = await postScan({
        engine: 'threat_emulation',
        client_id: Number(selectedClientId),
        target,
      })
      if (!ok) {
        showToast('error', d.detail || d.error || t('pages.threatEmulation.emulation_failed'))
        return
      }
      const jobId = d.job_id ?? ''
      showToast('info', t('pages.threatEmulation.emulation_queued', { jobId: jobId || '—' }))
      if (jobId) setActiveJobId(String(jobId))
    } catch (e) {
      showToast('error', e?.message ?? t('pages.threatEmulation.network_error'))
    } finally {
      setRunning(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedClientId, clients, showToast, t])

  useJobPoll(activeJobId, {
    enabled: Boolean(activeJobId),
    onComplete: async (job) => {
      setActiveJobId(null)
      const findings = await resolveJobFindings(job, 'threat_emulation', selectedClientId)
      const scenarioFindings = findings.filter(isThreatEmulationFinding)
      if (scenarioFindings.length) {
        setEmulationFindings((prev) => {
          const ids = new Set(prev.map((f) => f.id || f.finding_id))
          const merged = [...prev]
          for (const f of scenarioFindings) {
            const key = f.id || f.finding_id
            if (!key || !ids.has(key)) merged.unshift(f)
          }
          return merged
        })
      }
      await loadData(selectedClientId)
      showToast('info', t('pages.threatEmulation.run_complete', { status: job?.status || 'done' }))
    },
  })

  return (
    <PageShell
      title={t('pages.threatEmulation.title')}
      badge={t('pages.threatEmulation.badge')}
      badgeColor="#ef4444"
      subtitle={t('pages.threatEmulation.subtitle', { count: APT_GROUPS.length })}
      actions={(
        <ShellScanActions
          onRefresh={() => loadData(selectedClientId)}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="rounded-xl border border-amber-500/20 bg-amber-950/20 px-4 py-3 text-xs text-amber-100/75 mb-6 leading-relaxed">
        {t('pages.threatEmulation.engine_notice')}
      </div>

      {error && (
        <div role="alert" className="mb-4 rounded-xl border border-rose-500/30 bg-rose-950/30 px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3 mb-6">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[11px] font-mono text-[var(--text-muted)]">{t('pages.threatEmulation.target_client')}</span>
          <ScopedClientControl
              value={selectedClientId ?? ''}
              onChange={(id) => setSelectedClientId(id || null)}
              clients={clients}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-cyan-500/40"
              placeholder={t('pages.threatEmulation.select_placeholder')}
              allowEmpty
            />
        </div>
        <Button variant="unstyled"
          type="button"
          onClick={runEmulation}
          disabled={!selectedClientId || running || Boolean(activeJobId)}
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl font-mono text-sm border border-red-500/40 text-red-200 bg-red-950/30 hover:bg-red-950/50 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          {running || activeJobId ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin" />
              {t('pages.threatEmulation.running')}
            </>
          ) : (
            <>
              <Target className="w-4 h-4" />
              {t('pages.threatEmulation.run_full')}
            </>
          )}
        </Button>
      </div>

      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-[var(--bg-1)] border-cyan-500/30 text-cyan-200'}`}>
          {toast.msg}
        </div>
      )}

      {!selectedClientId && (
        <EmptyState
          icon={<Target className="w-8 h-8 text-[var(--text-disabled)]" />}
          title={t('pages.threatEmulation.select_client_warning_title')}
          description={t('pages.threatEmulation.select_client_warning')}
        />
      )}

      {loading && selectedClientId ? (
        <SkeletonWidgetGrid count={4} />
      ) : selectedClientId && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
              <div className="flex items-center gap-2 text-[11px] text-[var(--text-muted)] mb-1">
                <Shield className="w-3.5 h-3.5 text-cyan-400" />
                {t('pages.threatEmulation.kpi_scenarios')}
              </div>
              <div className="text-2xl font-bold text-white">{aggregate.totalTested}</div>
            </div>
            <div className="rounded-xl border border-green-500/20 bg-green-950/20 p-4">
              <div className="flex items-center gap-2 text-[11px] text-green-300/70 mb-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                {t('pages.threatEmulation.kpi_blocked')}
              </div>
              <div className="text-2xl font-bold text-green-300">{aggregate.totalBlocked}</div>
            </div>
            <div className="rounded-xl border border-red-500/20 bg-red-950/20 p-4">
              <div className="flex items-center gap-2 text-[11px] text-red-300/70 mb-1">
                <ShieldAlert className="w-3.5 h-3.5" />
                {t('pages.threatEmulation.kpi_gaps')}
              </div>
              <div className="text-2xl font-bold text-red-300">{aggregate.totalGaps}</div>
            </div>
            <div className="rounded-xl border border-purple-500/20 bg-purple-950/20 p-4">
              <div className="flex items-center gap-2 text-[11px] text-purple-300/70 mb-1">
                <AlertTriangle className="w-3.5 h-3.5" />
                {t('pages.threatEmulation.kpi_coverage')}
              </div>
              <div className="text-2xl font-bold text-purple-300">{aggregate.coveragePct}%</div>
              <div className="text-[10px] text-[var(--text-muted)] mt-1">
                {t('pages.threatEmulation.kpi_coverage_detail', { count: aggregate.groupsWithSurface, total: APT_GROUPS.length })}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-8">
            {APT_GROUPS.map((group) => (
              <AptCard key={group.id} group={group} result={groupResults[group.id]} t={t} />
            ))}
          </div>

          <WeissmanFindingsPanel
            findings={emulationFindings}
            filteredFindings={filteredFindings}
            counts={counts}
            total={total}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            severityFilter={severityFilter}
            onSeverityChange={setSeverityFilter}
            pending={(running || Boolean(activeJobId)) && !emulationFindings.length}
            jobId={activeJobId || undefined}
            accent="#ef4444"
            className="mb-8"
            showEmptyReady={!running && !activeJobId && !emulationFindings.length}
            emptyReadyTitle={t('pages.threatEmulation.select_client_warning_title')}
            emptyReadyBody={t('pages.threatEmulation.no_data')}
            renderFinding={renderEmulationFinding}
          />

          {history.length > 0 && (
            <section className="rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] p-5">
              <div className="flex items-center gap-2 mb-4">
                <History className="w-4 h-4 text-[var(--text-muted)]" />
                <h3 className="text-sm font-semibold text-white">{t('pages.threatEmulation.history_heading')}</h3>
              </div>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {history.slice(0, 10).map((job) => (
                  <div key={job.id || job.job_id} className="flex items-center justify-between gap-3 text-xs font-mono border border-[var(--border-subtle)] rounded-lg px-3 py-2">
                    <span className="text-[var(--text-tertiary)] truncate">{job.created_at?.slice(0, 19) || job.id}</span>
                    <span className={`px-2 py-0.5 rounded border ${
                      job.status === 'completed' ? 'text-green-400 border-green-500/30' : 'text-amber-300 border-amber-500/30'
                    }`}>
                      {job.status || '—'}
                    </span>
                    {job.id && (
                      <Link to={`/jobs?highlight=${job.id}`} className="text-cyan-400 hover:text-cyan-300 shrink-0">
                        {t('pages.threatEmulation.view_job')}
                      </Link>
                    )}
                  </div>
                ))}
              </div>
            </section>
          )}
        </>
      )}
    </PageShell>
  )
}
