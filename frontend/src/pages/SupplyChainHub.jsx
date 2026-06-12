import React, { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { motion } from 'framer-motion'
import PageShell from './PageShell'
import SupplyChainGraph from '../components/ui/SupplyChainGraph'
import { apiFetch } from '../lib/apiBase'
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'

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
  info: { bg: 'bg-white/5', border: 'border-white/10', text: 'text-white/60' },
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
            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-white/15 text-white/50">
              {finding.reachability}
            </span>
          )}
          <span className="text-[10px] font-mono text-white/30">{finding.engine ?? ''}</span>
        </div>
      </div>
      <p className="text-sm font-medium text-white/90">{finding.title ?? finding.type ?? t('pages.supplyChainHub.finding_fallback')}</p>
      {finding.target && (
        <p className="text-[11px] font-mono text-white/40 truncate">{finding.target}</p>
      )}
    </div>
  )
}

function EngineRunPanel({ engineId, clientId, showToast, t }) {
  const [running, setRunning] = useState(false)
  const [findings, setFindings] = useState([])
  const [lastRun, setLastRun] = useState(null)
  const [pendingJobId, setPendingJobId] = useState(null)

  const label = t(`pages.supplyChainHub.engines.${engineId}.label`)
  const description = t(`pages.supplyChainHub.engines.${engineId}.description`)

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
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ engine: engineId, client_id: Number(clientId) }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) { showToast('error', d.detail || t('pages.supplyChainHub.scan_failed')); setRunning(false); return }
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
    <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-white">{label}</h3>
          <p className="text-[11px] text-white/40 mt-0.5">{description}</p>
        </div>
        <button
          type="button"
          onClick={handleRun}
          disabled={running || !clientId}
          className="shrink-0 px-3 py-1.5 rounded-lg text-[11px] font-mono uppercase border border-[#84cc16]/30 text-[#84cc16]/70 hover:bg-[#84cc16]/10 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          {running ? t('pages.supplyChainHub.running') : t('pages.supplyChainHub.run')}
        </button>
      </div>
      {lastRun && (
        <p className="text-[10px] font-mono text-white/30">{t('pages.supplyChainHub.last_run', { time: lastRun })}</p>
      )}
      {findings.length > 0 && (
        <div className="space-y-2 pt-2 border-t border-white/5">
          {findings.slice(0, 5).map((f, i) => <FindingCard key={i} finding={f} t={t} />)}
        </div>
      )}
      {(() => {
        const inv = findings.find(
          (f) => Array.isArray(f.dependency_edges) || Array.isArray(f.components),
        )
        if (!inv) return null
        return (
          <div className="pt-3 border-t border-white/5 space-y-2">
            <p className="text-[10px] font-mono text-white/40 uppercase tracking-wide">
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
  )
}

export default function SupplyChainHub() {
  const { t } = useTranslation()
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const [toast, setToast] = useState(null)

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

  return (
    <PageShell title={t('pages.supplyChainHub.title')} badge={t('pages.supplyChainHub.badge')} badgeColor="#84cc16" subtitle={t('pages.supplyChainHub.subtitle', { count: SUPPLY_ENGINE_IDS.length })}>
      <div className="flex items-center gap-2 mb-6">
        <span className="text-[11px] font-mono text-white/40">{t('pages.supplyChainHub.client_label')}</span>
        <select
          value={selectedClientId ?? ''}
          onChange={(e) => setSelectedClientId(e.target.value || null)}
          className="bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white/80 font-mono focus:outline-none focus:border-[#84cc16]/40"
        >
          <option value="">{t('pages.supplyChainHub.select_client')}</option>
          {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      </div>

      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-black/80 border-[#84cc16]/30 text-[#84cc16]'}`}>
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
            <EngineRunPanel engineId={engineId} clientId={selectedClientId} showToast={showToast} t={t} />
          </motion.div>
        ))}
      </div>
    </PageShell>
  )
}
