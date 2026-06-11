import React, { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { useParams } from 'react-router-dom'
import { motion } from 'framer-motion'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'

const SIMULATION_SCENARIO_IDS = ['xss', 'sqli', 'mitm', 'cors']

const SCENARIO_META = {
  xss: { mitre: 'T1059.007', color: '#ef4444', risk: 'high' },
  sqli: { mitre: 'T1190', color: '#f97316', risk: 'critical' },
  mitm: { mitre: 'T1557', color: '#f59e0b', risk: 'high' },
  cors: { mitre: 'T1190', color: '#8b5cf6', risk: 'medium' },
}

const RISK_COLOR = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22d3ee' }

function ScenarioCard({ scenarioId, result, onRun, running, disabled, t }) {
  const meta = SCENARIO_META[scenarioId]
  const riskColor = RISK_COLOR[meta.risk] ?? '#6b7280'
  const label = t(`pages.digitalTwinSimulator.scenarios.${scenarioId}.label`)
  const description = t(`pages.digitalTwinSimulator.scenarios.${scenarioId}.description`)
  const riskLabel = t(`pages.digitalTwinSimulator.risk_${meta.risk}`)

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-4 hover:border-white/20 transition-all"
      style={result?.vulnerable ? { borderColor: `${riskColor}30` } : {}}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h3 className="text-sm font-semibold text-white">{label}</h3>
            <span
              className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest"
              style={{ color: riskColor, borderColor: `${riskColor}40`, backgroundColor: `${riskColor}10` }}
            >
              {riskLabel}
            </span>
          </div>
          <span className="text-[9px] font-mono text-white/30 bg-white/5 px-1.5 py-0.5 rounded border border-white/10">
            {meta.mitre}
          </span>
        </div>
        <button
          type="button"
          onClick={() => onRun(scenarioId)}
          disabled={disabled || running}
          className="shrink-0 px-3 py-1.5 rounded-lg text-[11px] font-mono uppercase border transition-all disabled:opacity-40 disabled:cursor-not-allowed"
          style={{
            borderColor: `${riskColor}40`,
            color: riskColor,
            backgroundColor: `${riskColor}10`,
          }}
        >
          {running ? t('pages.digitalTwinSimulator.simulating') : t('pages.digitalTwinSimulator.simulate')}
        </button>
      </div>

      <p className="text-[11px] text-white/45 leading-relaxed">{description}</p>

      {result && (
        <div className="pt-3 border-t border-white/5 space-y-2">
          <div className="flex items-center gap-2">
            <span
              className="w-2 h-2 rounded-full"
              style={{ backgroundColor: result.vulnerable ? riskColor : '#4ade80' }}
            />
            <span className="text-xs font-mono text-white/70">
              {result.vulnerable
                ? t('pages.digitalTwinSimulator.vulnerable_paths', { count: result.attack_paths ?? 0 })
                : t('pages.digitalTwinSimulator.not_vulnerable')}
            </span>
          </div>
          {result.details && (
            <p className="text-[10px] font-mono text-white/35 leading-relaxed">{result.details}</p>
          )}
        </div>
      )}
    </motion.div>
  )
}

export default function DigitalTwinSimulator() {
  const { t } = useTranslation()
  const { clientId: routeClientId } = useParams()
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(routeClientId ?? null)
  const [envProfile, setEnvProfile] = useState(null)
  const [results, setResults] = useState({})
  const [runningId, setRunningId] = useState(null)
  const [pendingJobs, setPendingJobs] = useState({})
  const [toast, setToast] = useState(null)

  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (!selectedClientId) { setEnvProfile(null); return }
    const client = clients.find((c) => String(c.id) === String(selectedClientId))
    if (client) {
      setEnvProfile({
        name: client.name,
        domains: (() => {
          let d = client.domains
          if (typeof d === 'string') { try { d = JSON.parse(d) } catch { d = [] } }
          return Array.isArray(d) ? d : []
        })(),
        tech_stack: (() => {
          let ts = client.tech_stack
          if (typeof ts === 'string') { try { ts = JSON.parse(ts) } catch { ts = [] } }
          return Array.isArray(ts) ? ts : []
        })(),
      })
    }
  }, [selectedClientId, clients])

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((cur) => (cur?.id === id ? null : cur)), 5000)
  }, [])

  const handleSimulate = useCallback(async (scenarioId) => {
    if (!selectedClientId) { showToast('error', t('pages.digitalTwinSimulator.select_client_first')); return }
    const primaryTarget = envProfile?.domains?.[0]
    if (!primaryTarget) { showToast('error', t('pages.digitalTwinSimulator.no_domain')); return }
    setRunningId(scenarioId)
    try {
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          engine: 'digital_twin',
          client_id: Number(selectedClientId),
          scenario: scenarioId,
          target: primaryTarget.startsWith('http://') || primaryTarget.startsWith('https://') ? primaryTarget : `https://${primaryTarget}`,
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) { showToast('error', d.detail || t('pages.digitalTwinSimulator.simulation_failed')); return }
      const jobId = d.job_id ?? ''
      showToast('info', t('pages.digitalTwinSimulator.simulation_queued', { jobId }))
      if (jobId) {
        setPendingJobs((prev) => ({ ...prev, [scenarioId]: jobId }))
      }
      setResults((prev) => ({
        ...prev,
        [scenarioId]: { vulnerable: false, attack_paths: 0, details: t('pages.digitalTwinSimulator.running_simulation'), pending: true },
      }))
    } catch (e) {
      showToast('error', e?.message ?? t('common.error'))
    } finally {
      setRunningId(null)
    }
  }, [selectedClientId, envProfile, showToast, t])

  const activePoll = Object.entries(pendingJobs).find(([, jobId]) => jobId)?.[0] ?? null
  const activeJobId = activePoll ? pendingJobs[activePoll] : null

  useJobPoll(activeJobId, {
    enabled: Boolean(activeJobId && activePoll),
    onComplete: async (job) => {
      const scenarioId = activePoll
      if (!scenarioId) return
      const findings = await resolveJobFindings(job, 'digital_twin', selectedClientId)
      const paths = findings.filter((f) => (f.severity || '').toLowerCase() !== 'info').length
      setResults((prev) => ({
        ...prev,
        [scenarioId]: {
          vulnerable: paths > 0,
          attack_paths: paths || findings.length,
          details: uiJobStatus(job.status) === 'completed'
            ? t('pages.digitalTwinSimulator.simulation_signals', { count: findings.length })
            : t('pages.digitalTwinSimulator.simulation_status', { status: job.status }),
          pending: false,
        },
      }))
      setPendingJobs((prev) => {
        const next = { ...prev }
        delete next[scenarioId]
        return next
      })
    },
  })

  const handleRunAll = useCallback(async () => {
    for (const id of SIMULATION_SCENARIO_IDS) {
      await handleSimulate(id)
    }
  }, [handleSimulate])

  return (
    <PageShell title={t('pages.digitalTwinSimulator.title')} badge={t('pages.digitalTwinSimulator.badge')} badgeColor="#8b5cf6" subtitle={t('pages.digitalTwinSimulator.subtitle')}>
      <div className="flex flex-wrap items-center justify-between gap-3 mb-8">
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-white/40">{t('pages.digitalTwinSimulator.client_label')}</span>
          <select
            value={selectedClientId ?? ''}
            onChange={(e) => setSelectedClientId(e.target.value || null)}
            className="bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white/80 font-mono focus:outline-none focus:border-[#8b5cf6]/40"
          >
            <option value="">{t('pages.digitalTwinSimulator.select_client')}</option>
            {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </div>
        <button
          type="button"
          onClick={handleRunAll}
          disabled={!selectedClientId || !!runningId}
          className="px-4 py-2 rounded-xl font-mono text-sm border border-[#8b5cf6]/40 text-[#8b5cf6] bg-[#8b5cf6]/10 hover:bg-[#8b5cf6]/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          {t('pages.digitalTwinSimulator.run_all')}
        </button>
      </div>

      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-black/80 border-[#8b5cf6]/30 text-[#8b5cf6]'}`}>
          {toast.msg}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="space-y-4">
          <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">{t('pages.digitalTwinSimulator.env_profile')}</h3>
          <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-4">
            {envProfile ? (
              <>
                <div>
                  <p className="text-[10px] font-mono text-white/40 uppercase tracking-widest mb-1">{t('pages.digitalTwinSimulator.client_heading')}</p>
                  <p className="text-sm font-semibold text-white">{envProfile.name}</p>
                </div>
                {envProfile.domains.length > 0 && (
                  <div>
                    <p className="text-[10px] font-mono text-white/40 uppercase tracking-widest mb-2">{t('pages.digitalTwinSimulator.domains_heading')}</p>
                    <div className="space-y-1">
                      {envProfile.domains.map((d, i) => (
                        <p key={i} className="text-[11px] font-mono text-cyan-300/80 truncate">{d}</p>
                      ))}
                    </div>
                  </div>
                )}
                {envProfile.tech_stack.length > 0 && (
                  <div>
                    <p className="text-[10px] font-mono text-white/40 uppercase tracking-widest mb-2">{t('pages.digitalTwinSimulator.tech_stack_heading')}</p>
                    <div className="flex flex-wrap gap-1">
                      {envProfile.tech_stack.map((tech, i) => (
                        <span key={i} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-white/50">
                          {tech}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </>
            ) : (
              <p className="text-[11px] font-mono text-white/25 text-center py-4">
                {t('pages.digitalTwinSimulator.env_empty')}
              </p>
            )}
          </div>
        </div>

        <div className="lg:col-span-2 space-y-4">
          <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">{t('pages.digitalTwinSimulator.attack_simulations')}</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {SIMULATION_SCENARIO_IDS.map((scenarioId) => (
              <ScenarioCard
                key={scenarioId}
                scenarioId={scenarioId}
                result={results[scenarioId] ?? null}
                onRun={handleSimulate}
                running={runningId === scenarioId}
                disabled={!selectedClientId}
                t={t}
              />
            ))}
          </div>
        </div>
      </div>
    </PageShell>
  )
}
