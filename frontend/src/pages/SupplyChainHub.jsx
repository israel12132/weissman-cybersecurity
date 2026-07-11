import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useHubEngineFocus } from '../hooks/useLaunchEngineScan'
import { Link } from 'react-router-dom'
import { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { motion } from 'framer-motion'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import AgentRequiredGate from '../components/engine/AgentRequiredGate'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import SupplyChainGraph from '../components/ui/SupplyChainGraph'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { apiFetch } from '../lib/apiBase'
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'
import Button from '../components/ui/Button'

const ACCENT = '#84cc16'

const SUPPLY_ENGINE_IDS = [
  'supply_chain',
  'cicd_pipeline',
  'container_registry',
  'sbom_analyzer',
  'typosquatting_monitor',
]

const SEVERITY_COLORS = {
  critical: { bg: 'bg-red-950/30', border: 'border-red-500/30', text: 'text-red-300' },
  high: { bg: 'bg-orange-950/30', border: 'border-orange-500/30', text: 'text-orange-300' },
  medium: { bg: 'bg-amber-950/30', border: 'border-amber-500/30', text: 'text-amber-300' },
  low: { bg: 'bg-blue-950/30', border: 'border-blue-500/30', text: 'text-blue-300' },
  info: { bg: 'bg-[var(--row-hover-bg)]', border: 'border-[var(--border-default)]', text: 'text-[var(--text-tertiary)]' },
}

function sevClass(s) {
  return SEVERITY_COLORS[(s || '').toLowerCase()] ?? SEVERITY_COLORS.info
}

function FindingCard({ finding, t }) {
  const cls = sevClass(finding.severity)
  return (
    <div className={`rounded-xl border p-4 ${cls.bg} ${cls.border} space-y-1`}>
      <div className="flex items-center justify-between gap-2">
        <span className={`text-[10px] font-mono uppercase tracking-widest ${cls.text}`}>
          {finding.severity ?? 'info'}
        </span>
        <div className="flex items-center gap-1.5">
          {finding.reachability && (
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-[var(--border-strong)] text-[var(--text-tertiary)]">
              {finding.reachability}
            </span>
          )}
          <span className="text-[10px] font-mono text-[var(--text-disabled)]">{finding.engine ?? ''}</span>
        </div>
      </div>
      <p className="text-sm font-medium text-[var(--text-primary)]">{finding.title ?? finding.type ?? t('pages.supplyChainHub.finding_fallback')}</p>
      {finding.target && (
        <p className="text-[11px] font-mono text-[var(--text-muted)] truncate">{finding.target}</p>
      )}
    </div>
  )
}

function EngineRunPanel({ engineId, clientId, showToast, onFindingsUpdate, isFocused, onFocus, t }) {
  const { postScan } = useCommandCenterScan(clientId)
  useHubEngineFocus(engineId, { active: isFocused })
  const [running, setRunning] = useState(false)
  const [findings, setFindings] = useState([])
  const [lastRun, setLastRun] = useState(null)
  const [pendingJobId, setPendingJobId] = useState(null)

  const label = t(`pages.supplyChainHub.engines.${engineId}.label`)
  const description = t(`pages.supplyChainHub.engines.${engineId}.description`)

  useEffect(() => {
    onFindingsUpdate?.(engineId, findings)
  }, [engineId, findings, onFindingsUpdate])

  useJobPoll(pendingJobId, {
    enabled: Boolean(pendingJobId),
    onComplete: async (job) => {
      setRunning(false)
      setLastRun(new Date().toLocaleTimeString())
      setFindings(await resolveJobFindings(job, engineId, clientId))
      setPendingJobId(null)
      if (uiJobStatus(job.status) === 'error') {
        showToast('error', `${label}: ${job.status}`)
      }
    },
  })

  const handleRun = useCallback(async () => {
    if (!clientId) { showToast('error', t('pages.supplyChainHub.select_client_first')); return }
    setRunning(true)
    setFindings([])
    try {
      const { ok, data: d } = await postScan({ engine: engineId, client_id: Number(clientId) })
      if (!ok) { showToast('error', d.detail || t('pages.supplyChainHub.scan_failed')); setRunning(false); return }
      const jobId = d.job_id ?? ''
      showToast('info', t('pages.supplyChainHub.queued', { label, jobId }))
      if (jobId) setPendingJobId(jobId)
      else setRunning(false)
    } catch (e) {
      showToast('error', e?.message ?? t('common.error'))
      setRunning(false)
    }
  }, [clientId, engineId, label, showToast, t])

  return (
    <AgentRequiredGate engineId={engineId} className="rounded-2xl">
    <div
      className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 space-y-4"
      onMouseEnter={onFocus}
      onFocus={onFocus}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-white">{label}</h3>
          <p className="text-[11px] text-[var(--text-muted)] mt-0.5">{description}</p>
          {engineId === 'cicd_pipeline' && (
            <Link to="/cicd-security" className="inline-block mt-2 text-[10px] font-mono text-lime-400/80 hover:text-lime-300 border border-lime-500/25 rounded-lg px-2 py-1 transition-colors">
              {t('pages.supplyChainHub.open_command_center', 'Open CI/CD Command Center →')}
            </Link>
          )}
        </div>
        <Button variant="unstyled"
          type="button"
          onClick={handleRun}
          disabled={running || !clientId}
          className="shrink-0 px-3 py-1.5 rounded-lg text-[11px] font-mono uppercase border border-[#84cc16]/30 text-[#84cc16]/70 hover:bg-[#84cc16]/10 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          {running ? t('pages.supplyChainHub.running') : t('pages.supplyChainHub.run')}
        </Button>
      </div>
      {lastRun && (
        <p className="text-[10px] font-mono text-[var(--text-disabled)]">{t('pages.supplyChainHub.last_run', { time: lastRun })}</p>
      )}
      {findings.length > 0 && (
        <div className="space-y-2 pt-2 border-t border-[var(--border-subtle)]">
          {findings.slice(0, 5).map((f, i) => <FindingCard key={i} finding={f} t={t} />)}
        </div>
      )}
      {(() => {
        const inv = findings.find(
          (f) => Array.isArray(f.dependency_edges) || Array.isArray(f.components),
        )
        if (!inv) return null
        return (
          <div className="pt-3 border-t border-[var(--border-subtle)] space-y-2">
            <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">
              {t('components.findingDrawer.supplyChain.dependencyGraph')}
            </p>
            <SupplyChainGraph
              components={inv.components || []}
              edges={inv.dependency_edges || []}
              direct={inv.direct_dependencies || []}
              summary={inv.dependency_graph || null}
              byReach={inv.by_reachability || null}
              t={t}
            />
          </div>
        )
      })()}
    </div>
    </AgentRequiredGate>
  )
}

export default function SupplyChainHub() {
  const { t } = useTranslation()
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const [toast, setToast] = useState(null)
  const [findingsByEngine, setFindingsByEngine] = useState({})
  const [refreshLoading, setRefreshLoading] = useState(false)
  const [focusedEngineId, setFocusedEngineId] = useState(SUPPLY_ENGINE_IDS[0])

  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch(() => {})
  }, [])

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((cur) => (cur?.id === id ? null : cur)), 5000)
  }, [])

  const handleFindingsUpdate = useCallback((engineId, findings) => {
    setFindingsByEngine((prev) => ({ ...prev, [engineId]: findings }))
  }, [])

  const aggregatedFindings = useMemo(
    () => SUPPLY_ENGINE_IDS.flatMap((id) => {
      const list = findingsByEngine[id] || []
      return list.map((f) => ({ ...f, engine: f.engine || id }))
    }),
    [findingsByEngine],
  )

  const {
    filteredFindings,
    counts,
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    exportCsv,
    total,
  } = useFindingsWorkbench(aggregatedFindings, {
    csvPrefix: 'supply-chain-hub',
    haystackFn: (f) => `${f.title || ''} ${f.type || ''} ${f.target || ''} ${f.engine || ''} ${f.description || ''}`,
  })

  const handleRefresh = useCallback(async () => {
    setRefreshLoading(true)
    try {
      const r = await apiFetch('/api/engines/history/supply_chain?limit=1')
      if (!r.ok) return
      const d = await r.json()
      const runs = Array.isArray(d) ? d : Array.isArray(d?.runs) ? d.runs : []
      const last = runs[0]
      const findings = Array.isArray(last?.findings) ? last.findings : []
      setFindingsByEngine((prev) => ({ ...prev, supply_chain: findings }))
    } catch {
      // live-only: no demo fallback
    } finally {
      setRefreshLoading(false)
    }
  }, [])

  return (
    <PageShell
      engineId={focusedEngineId}
      title={t('pages.supplyChainHub.title')}
      badge={t('pages.supplyChainHub.badge')}
      badgeColor={ACCENT}
      subtitle={t('pages.supplyChainHub.subtitle', { count: SUPPLY_ENGINE_IDS.length })}
      actions={(
        <ShellScanActions
          onRefresh={handleRefresh}
          onExport={exportCsv}
          refreshLoading={refreshLoading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="flex items-center gap-2 mb-6">
        <span className="text-[11px] font-mono text-[var(--text-muted)]">{t('pages.supplyChainHub.client_label')}</span>
        <select
          value={selectedClientId ?? ''}
          onChange={(e) => setSelectedClientId(e.target.value || null)}
          className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-[#84cc16]/40"
        >
          <option value="">{t('pages.supplyChainHub.select_client')}</option>
          {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </div>

      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-[var(--bg-1)] border-[#84cc16]/30 text-[#84cc16]'}`}>
          {toast.msg}
        </div>
      )}

      {!selectedClientId && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-950/20 px-4 py-3 text-sm text-amber-200/80 font-mono mb-6">
          {t('pages.supplyChainHub.select_client_warning')}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        {SUPPLY_ENGINE_IDS.map((engineId) => (
          <motion.div
            key={engineId}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <EngineRunPanel
              engineId={engineId}
              clientId={selectedClientId}
              isFocused={focusedEngineId === engineId}
              onFocus={() => setFocusedEngineId(engineId)}
              showToast={showToast}
              onFindingsUpdate={handleFindingsUpdate}
              t={t}
            />
          </motion.div>
        ))}
      </div>

      <div className="mt-8">
        <WeissmanFindingsPanel
          findings={aggregatedFindings}
          filteredFindings={filteredFindings}
          counts={counts}
          total={total}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          severityFilter={severityFilter}
          onSeverityChange={setSeverityFilter}
          accent={ACCENT}
          title={t('pages.supplyChainHub.aggregated_findings', 'Supply Chain Findings')}
          emptyTitle={t('pages.supplyChainHub.empty_findings_title', 'No supply chain findings yet')}
          emptyBody={t('pages.supplyChainHub.empty_findings_body', 'Run any engine above to populate live findings.')}
          showEmptyReady
          emptyReadyTitle={t('pages.supplyChainHub.ready_title', 'Ready to scan')}
          emptyReadyBody={t('pages.supplyChainHub.ready_body', 'Select a client and run a supply-chain engine.')}
          renderFinding={(f, i) => <FindingCard key={i} finding={f} t={t} />}
        />
      </div>
    </PageShell>
  )
}
