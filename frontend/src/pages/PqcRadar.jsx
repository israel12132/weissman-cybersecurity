import React, { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { motion } from 'framer-motion'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'
import { useJobPoll, resolveJobFindings, extractFindingsFromJob } from '../lib/useJobPoll'

const NIST_ALGORITHMS = [
  { id: 'CRYSTALS-Kyber', type: 'KEM', status: 'final', standard: 'FIPS 203', color: '#4ade80' },
  { id: 'CRYSTALS-Dilithium', type: 'Signature', status: 'final', standard: 'FIPS 204', color: '#4ade80' },
  { id: 'SPHINCS+', type: 'Signature', status: 'final', standard: 'FIPS 205', color: '#4ade80' },
  { id: 'FALCON', type: 'Signature', status: 'draft', standard: 'FIPS 206', color: '#f59e0b' },
  { id: 'RSA-2048', type: 'Legacy KEM', status: 'quantum-vulnerable', standard: 'PKCS#1', color: '#ef4444' },
  { id: 'ECDSA P-256', type: 'Legacy Sig', status: 'quantum-vulnerable', standard: 'FIPS 186', color: '#ef4444' },
]

function AlgoRow({ algo, t }) {
  const statusColor = {
    final: 'text-[#4ade80] bg-[#4ade80]/10 border-[#4ade80]/30',
    draft: 'text-amber-300 bg-amber-950/20 border-amber-500/30',
    'quantum-vulnerable': 'text-red-300 bg-red-950/20 border-red-500/30',
  }[algo.status] ?? 'text-white/40 bg-white/5 border-white/10'

  const statusKey = {
    final: 'pages.pqcRadar.status_final',
    draft: 'pages.pqcRadar.status_draft',
    'quantum-vulnerable': 'pages.pqcRadar.status_quantum_vulnerable',
  }[algo.status]

  return (
    <div className="flex items-center justify-between gap-4 px-4 py-3 rounded-xl bg-white/5 border border-white/5 hover:bg-white/10 transition-all">
      <div className="flex items-center gap-3 min-w-0">
        <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: algo.color }} />
        <div>
          <p className="text-sm font-mono text-white/90">{algo.id}</p>
          <p className="text-[10px] font-mono text-white/40">{algo.type} · {algo.standard}</p>
        </div>
      </div>
      <span className={`text-[9px] font-mono px-2 py-0.5 rounded border uppercase tracking-widest shrink-0 ${statusColor}`}>
        {statusKey ? t(statusKey) : algo.status}
      </span>
    </div>
  )
}

function ScanResultCard({ result, t }) {
  if (!result) return null
  const vuln = result.vulnerable_certs ?? 0
  const total = result.total_certs ?? 0
  const pct = total > 0 ? Math.round((vuln / total) * 100) : 0

  return (
    <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-6 space-y-4">
      <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">{t('pages.pqcRadar.scan_results')}</h3>
      <div className="grid grid-cols-3 gap-4">
        <div className="text-center">
          <p className="text-3xl font-bold font-mono text-white">{total}</p>
          <p className="text-[10px] font-mono text-white/40 mt-1">{t('pages.pqcRadar.certs_scanned')}</p>
        </div>
        <div className="text-center">
          <p className="text-3xl font-bold font-mono text-red-400">{vuln}</p>
          <p className="text-[10px] font-mono text-white/40 mt-1">{t('pages.pqcRadar.quantum_vulnerable')}</p>
        </div>
        <div className="text-center">
          <p className="text-3xl font-bold font-mono" style={{ color: pct > 50 ? '#ef4444' : pct > 20 ? '#f59e0b' : '#4ade80' }}>
            {pct}%
          </p>
          <p className="text-[10px] font-mono text-white/40 mt-1">{t('pages.pqcRadar.exposure_rate')}</p>
        </div>
      </div>
      {result.findings && result.findings.length > 0 && (
        <div className="space-y-2 pt-2 border-t border-white/5">
          {result.findings.slice(0, 5).map((f, i) => (
            <div key={i} className="text-[11px] font-mono text-white/50 bg-white/5 rounded px-2 py-1 truncate">
              {f.title ?? f}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function PqcRadar() {
  const { t } = useTranslation()
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState(null)
  const [scanResult, setScanResult] = useState(null)
  const [scanning, setScanning] = useState(false)
  const [pendingJobId, setPendingJobId] = useState(null)
  const [toast, setToast] = useState(null)

  useJobPoll(pendingJobId, {
    enabled: Boolean(pendingJobId),
    onComplete: async (job) => {
      const findings = await resolveJobFindings(job, 'pqc_scanner', selectedClientId)
      const fromJob = extractFindingsFromJob(job)
      const payload = job?.result ?? {}
      setScanResult({
        total_certs: payload.total_certs ?? findings.length,
        vulnerable_certs: payload.vulnerable_certs ?? findings.filter((f) => (f.severity || '').toLowerCase() !== 'info').length,
        findings: findings.length ? findings : fromJob,
        job_id: pendingJobId,
        status: job.status,
      })
      setScanning(false)
      setPendingJobId(null)
    },
  })

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

  const handleScan = useCallback(async () => {
    if (!selectedClientId) { showToast('error', t('pages.pqcRadar.select_client_first')); return }
    setScanning(true)
    setScanResult(null)
    try {
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ engine: 'pqc_scanner', client_id: Number(selectedClientId) }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) { showToast('error', d.detail || t('pages.pqcRadar.scan_failed')); return }
      const jobId = d.job_id ?? ''
      showToast('info', t('pages.pqcRadar.scan_queued', { jobId }))
      if (jobId) {
        setPendingJobId(jobId)
        setScanResult({ total_certs: 0, vulnerable_certs: 0, findings: [], job_id: jobId, pending: true })
      } else {
        setScanning(false)
      }
    } catch (e) {
      showToast('error', e?.message ?? t('common.error'))
      setScanning(false)
    }
  }, [selectedClientId, showToast, t])

  return (
    <PageShell title={t('pages.pqcRadar.title')} badge={t('pages.pqcRadar.badge')} badgeColor="#10b981" subtitle={t('pages.pqcRadar.subtitle')}>
      <div className="flex items-center justify-between gap-3 mb-8 flex-wrap">
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-white/40">{t('pages.pqcRadar.client_label')}</span>
          <select
            value={selectedClientId ?? ''}
            onChange={(e) => setSelectedClientId(e.target.value || null)}
            className="bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white/80 font-mono focus:outline-none focus:border-[#10b981]/40"
          >
            <option value="">{t('pages.pqcRadar.select_client')}</option>
            {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </div>
        <button
          type="button"
          onClick={handleScan}
          disabled={scanning || !selectedClientId}
          className="px-5 py-2 rounded-xl font-mono text-sm border border-[#10b981]/40 text-[#10b981] bg-[#10b981]/10 hover:bg-[#10b981]/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          {scanning ? t('pages.pqcRadar.scanning') : t('pages.pqcRadar.run_scan')}
        </button>
      </div>

      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-black/80 border-[#10b981]/30 text-[#10b981]'}`}>
          {toast.msg}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <motion.section
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-6 space-y-4"
        >
          <div>
            <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest mb-1">{t('pages.pqcRadar.nist_reference')}</h3>
            <p className="text-[11px] text-white/30">{t('pages.pqcRadar.nist_subtitle')}</p>
          </div>
          <div className="space-y-2">
            {NIST_ALGORITHMS.map((algo) => (
              <AlgoRow key={algo.id} algo={algo} t={t} />
            ))}
          </div>
        </motion.section>

        <motion.section
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="space-y-4"
        >
          <ScanResultCard result={scanResult} t={t} />

          {!scanResult && (
            <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-8 text-center">
              <p className="text-[11px] font-mono text-white/25">
                {!selectedClientId
                  ? t('pages.pqcRadar.empty_no_client')
                  : t('pages.pqcRadar.empty_ready')}
              </p>
            </div>
          )}
        </motion.section>
      </div>
    </PageShell>
  )
}
