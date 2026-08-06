import { firstClientTarget } from '../lib/clientTarget'
import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useState, useEffect, useCallback, useMemo } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { motion } from 'framer-motion'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { useEngineHistory } from '../hooks/useEngineHistory'
import { apiFetch } from '../utils/apiFetch'
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'
import KubernetesSecurityPanel from './KubernetesSecurityPanel'
import Button from '../components/ui/Button'

const CLOUD_TABS = [
  { id: 'aws', label: 'AWS', engine: 'aws_attack', color: '#f97316', icon: '☁' },
  { id: 'azure', label: 'Azure', engine: 'azure_attack', color: '#3b82f6', icon: '⬡' },
  { id: 'gcp', label: 'GCP', engine: 'gcp_attack', color: '#10b981', icon: '◈' },
  { id: 'k8s', label: 'Kubernetes', engine: 'k8s_container', color: '#8b5cf6', icon: '⎈' },
  { id: 'iac', label: 'IaC', engine: 'iac_misconfig', color: '#06b6d4', icon: '{}' },
  { id: 'serverless', label: 'Serverless', engine: 'serverless_attack', color: '#ec4899', icon: 'λ' },
]

const ENGINE_DESCRIPTIONS = {
  aws_attack: 'IAM privilege escalation, S3 bucket exposure, Lambda event injection, STS token abuse',
  azure_attack: 'Azure AD token abuse, Blob SAS exposure, Function App command injection, RBAC misconfig',
  gcp_attack: 'GCP service account key exposure, Cloud Run abuse, BigQuery public dataset scan',
  k8s_container: 'CNAPP-grade: 14 attack surfaces, CIS benchmark, CVE intel, attack paths, GitOps/observability, RBAC SSAR',
  iac_misconfig: 'Terraform/CloudFormation/Pulumi misconfiguration scan and drift detection',
  serverless_attack: 'Serverless event injection, function chaining exploitation, cold-start timing',
}


function CloudTab({ tab, active, onClick }) {
  return (
    <Button variant="unstyled"
      type="button"
      onClick={() => onClick(tab.id)}
      className={`flex items-center gap-1.5 px-4 py-2 rounded-xl text-sm font-mono transition-all border ${
        active
          ? 'text-white border'
          : 'text-[var(--text-muted)] border-[var(--border-default)] hover:border-[var(--border-strong)] hover:text-[var(--text-tertiary)]'
      }`}
      style={active ? { color: tab.color, borderColor: `${tab.color}50`, backgroundColor: `${tab.color}15` } : {}}
    >
      <span>{tab.icon}</span>
      <span>{tab.label}</span>
    </Button>
  )
}

function CloudEnginePanel({ tab, clientId, target, showToast, t, onFindingsUpdate, onStatusUpdate }) {
  const { postScan } = useCommandCenterScan(clientId)
  const [status, setStatus] = useState('idle')
  const [lastRun, setLastRun] = useState(null)
  const [findings, setFindings] = useState([])
  const [pendingJobId, setPendingJobId] = useState(null)

  useEffect(() => {
    onFindingsUpdate?.(tab.engine, findings)
  }, [findings, tab.engine, onFindingsUpdate])

  useEffect(() => {
    onStatusUpdate?.(tab.engine, status)
  }, [status, tab.engine, onStatusUpdate])

  useJobPoll(pendingJobId, {
    enabled: Boolean(pendingJobId),
    onComplete: async (job) => {
      setStatus(uiJobStatus(job.status))
      setLastRun(new Date().toLocaleTimeString())
      setFindings(await resolveJobFindings(job, tab.engine, clientId))
      setPendingJobId(null)
    },
  })

  const handleRun = useCallback(async () => {
    if (!clientId) { showToast('error', t('pages.cloudControlTower.select_client_first')); return }
    setStatus('running')
    setFindings([])
    try {
      const { ok, data: d } = await postScan({ engine: tab.engine, client_id: Number(clientId), ...(target ? { target } : {}) })
      if (!ok) { setStatus('error'); showToast('error', d.detail || t('pages.cloudControlTower.scan_failed')); return }
      const jobId = d.job_id ?? ''
      showToast('info', t('pages.cloudControlTower.queued', { label: tab.label, jobId }))
      if (jobId) setPendingJobId(jobId)
      else setStatus('error')
    } catch (e) {
      setStatus('error')
      showToast('error', e?.message ?? t('pages.cloudControlTower.scan_failed'))
    }
  }, [clientId, tab, target, showToast, t, postScan])

  const statusColor = { idle: '#374151', running: tab.color, completed: '#4ade80', error: '#ef4444' }[status]

  return (
    <motion.div
      key={tab.id}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-6"
    >
      <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-6">
        <div className="flex items-start justify-between gap-4 mb-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <span className="text-3xl" style={{ color: tab.color }}>{tab.icon}</span>
              <div>
                <h2 className="text-lg font-bold text-white">{t('pages.cloudControlTower.attack_surface', { label: tab.label })}</h2>
                <span className="text-[10px] font-mono text-[var(--text-disabled)] uppercase tracking-widest">{tab.engine}</span>
              </div>
            </div>
            <p className="text-sm text-[var(--text-tertiary)] leading-relaxed">
              {ENGINE_DESCRIPTIONS[tab.engine] ?? t('pages.cloudControlTower.default_description')}
            </p>
          </div>
          <div className="flex flex-col items-end gap-2 shrink-0">
            <div className="flex items-center gap-1.5">
              <span
                className="w-2 h-2 rounded-full"
                style={{ backgroundColor: statusColor, boxShadow: status === 'running' ? `0 0 6px ${tab.color}` : 'none' }}
              />
              <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{status}</span>
            </div>
            <Button variant="unstyled"
              type="button"
              onClick={handleRun}
              disabled={status === 'running' || !clientId}
              className="px-4 py-2 rounded-xl font-mono text-sm border transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ borderColor: `${tab.color}40`, color: tab.color, backgroundColor: `${tab.color}10` }}
            >
              {status === 'running' ? t('pages.cloudControlTower.scanning') : t('pages.cloudControlTower.run_scan')}
            </Button>
          </div>
        </div>

        {lastRun && (
          <p className="text-[10px] font-mono text-[var(--text-disabled)] mt-2">{t('pages.cloudControlTower.last_completed', { time: lastRun })}</p>
        )}
      </div>
    </motion.div>
  )
}

export default function CloudControlTower() {
  const { t } = useTranslation()
  const [activeTab, setActiveTab] = useState('aws')
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  // Registers this client with the engine hub (side effect); this view has no scan button.
  useCommandCenterScan(selectedClientId)
  const [toast, setToast] = useState(null)
  const [findingsByEngine, setFindingsByEngine] = useState({})
  const [engineStatus, setEngineStatus] = useState({})

  useEffect(() => {
    apiFetch('/api/clients')
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
      .catch(() => {})
  }, [])

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((cur) => (cur?.id === id ? null : cur)), 5000)
  }, [])

  const activeTabDef = CLOUD_TABS.find((tab) => tab.id === activeTab) ?? CLOUD_TABS[0]
  const selectedClient = clients.find((c) => String(c.id) === String(selectedClientId))
  const clientTarget = firstClientTarget(selectedClient)

  const handleFindingsUpdate = useCallback((engine, findings) => {
    setFindingsByEngine((prev) => ({ ...prev, [engine]: findings }))
  }, [])

  const handleStatusUpdate = useCallback((engine, status) => {
    setEngineStatus((prev) => ({ ...prev, [engine]: status }))
  }, [])

  const allFindings = useMemo(
    () => Object.values(findingsByEngine).flat(),
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
  } = useFindingsWorkbench(allFindings, {
    csvPrefix: 'cloud-control-tower',
    haystackFn: (f) => `${f.title || ''} ${f.type || ''} ${f.description || ''} ${f.engine || ''} ${f.category || ''}`,
  })

  const { loadLastRun, historyLoading, lastUpdated, lastJobId } = useEngineHistory(activeTabDef.engine)

  const handleRefresh = useCallback(async () => {
    const run = await loadLastRun()
    if (run) {
      handleFindingsUpdate(activeTabDef.engine, run.findings ?? [])
    }
  }, [loadLastRun, activeTabDef.engine, handleFindingsUpdate])

  useEffect(() => {
    handleRefresh()
  }, [handleRefresh])

  const activeRunning = engineStatus[activeTabDef.engine] === 'running'

  return (
    <PageShell
      engineId={activeTabDef.engine}
      hideHubParams={activeTab === 'k8s'}
      title={t('pages.cloudControlTower.title')}
      badge={t('pages.cloudControlTower.badge')}
      badgeColor="#3b82f6"
      subtitle={t('pages.cloudControlTower.subtitle', { count: CLOUD_TABS.length })}
      actions={(
        <ShellScanActions
          onRefresh={handleRefresh}
          onExport={exportCsv}
          refreshLoading={historyLoading}
          refreshDisabled={activeRunning}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="flex items-center gap-2 mb-6">
        <span className="text-[11px] font-mono text-[var(--text-muted)]">{t('pages.cloudControlTower.client_label')}</span>
        <select
          value={selectedClientId ?? ''}
          onChange={(e) => setSelectedClientId(e.target.value || null)}
          className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-blue-500/40"
        >
          <option value="">{t('pages.cloudControlTower.select_client')}</option>
          {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </div>

      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-[var(--bg-1)] border-blue-500/30 text-blue-200'}`}>
          {toast.msg}
        </div>
      )}

      {/* External Attack Surface Management cross-link */}
      <Link
        to="/attack-surface"
        className="group flex items-center justify-between gap-3 rounded-2xl border border-cyan-500/25 bg-gradient-to-r from-cyan-950/30 to-black/30 px-4 py-3 mb-4 hover:border-cyan-400/45 transition-all"
      >
        <div className="flex items-center gap-3">
          <span className="text-2xl">🌐</span>
          <div>
            <p className="text-sm font-semibold text-[var(--text-primary)]">Attack Surface Management (EASM)</p>
            <p className="text-[11px] font-mono text-[var(--text-muted)]">Discover internet-facing assets & score external exposure — assets, services, TLS/HTTP, cloud footprint, takeover risk.</p>
          </div>
        </div>
        <span className="text-[11px] font-mono text-cyan-300/80 group-hover:translate-x-0.5 transition-transform">Open →</span>
      </Link>

      {/* Agentless CSPM / CNAPP cross-link (Wiz-style) */}
      <Link
        to="/cloud-posture"
        className="group flex items-center justify-between gap-3 rounded-2xl border border-orange-500/25 bg-gradient-to-r from-orange-950/30 to-black/30 px-4 py-3 mb-6 hover:border-orange-400/45 transition-all"
      >
        <div className="flex items-center gap-3">
          <span className="text-2xl">◈</span>
          <div>
            <p className="text-sm font-semibold text-[var(--text-primary)]">Cloud Posture Management (CSPM)</p>
            <p className="text-[11px] font-mono text-[var(--text-muted)]">Agentless AWS inventory via cross-account role — IAM, S3, EC2, RDS, Lambda, CloudTrail, compliance grades & toxic-combination attack paths.</p>
          </div>
        </div>
        <span className="text-[11px] font-mono text-orange-300/80 group-hover:translate-x-0.5 transition-transform">Open →</span>
      </Link>

      {/* Cloud tabs */}
      <div className="flex flex-wrap gap-2 mb-8">
        {CLOUD_TABS.map((tab) => (
          <CloudTab key={tab.id} tab={tab} active={activeTab === tab.id} onClick={setActiveTab} />
        ))}
      </div>

      {!selectedClientId && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-950/20 px-4 py-3 text-sm text-amber-200/80 font-mono mb-6">
          {t('pages.cloudControlTower.select_client_warning')}
        </div>
      )}

      {activeTab === 'k8s' ? (
        <KubernetesSecurityPanel
          key="k8s"
          clientId={selectedClientId}
          target={clientTarget}
          showToast={showToast}
          onFindingsUpdate={handleFindingsUpdate}
          onStatusUpdate={handleStatusUpdate}
        />
      ) : (
        <CloudEnginePanel
          key={activeTab}
          tab={activeTabDef}
          clientId={selectedClientId}
          target={clientTarget}
          showToast={showToast}
          t={t}
          onFindingsUpdate={handleFindingsUpdate}
          onStatusUpdate={handleStatusUpdate}
        />
      )}

      <WeissmanFindingsPanel
        className="mt-6"
        findings={allFindings}
        filteredFindings={filteredFindings}
        counts={counts}
        total={total}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        severityFilter={severityFilter}
        onSeverityChange={setSeverityFilter}
        loading={historyLoading && !allFindings.length}
        pending={activeRunning && !allFindings.length}
        lastUpdated={lastUpdated}
        jobId={lastJobId}
        accent={activeTabDef.color}
        showEmptyReady={!activeRunning && !allFindings.length}
        emptyReadyTitle={t('pages.cloudControlTower.run_to_populate')}
        emptyReadyBody={t('pages.cloudControlTower.run_to_populate')}
        emptyTitle={t('pages.cloudControlTower.no_findings_clean')}
        emptyBody={t('pages.cloudControlTower.no_findings_clean')}
      />
    </PageShell>
  )
}
