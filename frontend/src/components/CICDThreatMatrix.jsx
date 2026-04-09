/**
 * Module 8: Phantom Pipeline / CI/CD Threat Matrix.
 * Horizontal pipeline (Commit -> Build -> Test -> Deploy), red stages, modal with Attacker's Playbook.
 */
import { useCallback, useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { apiFetch } from '../lib/apiBase'

const STAGES = ['Commit', 'Build', 'Test', 'Deploy']

export default function CICDThreatMatrix() {
  const { clientId } = useParams()
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [modalFinding, setModalFinding] = useState(null)
  const [runRepoUrl, setRunRepoUrl] = useState('')
  const [running, setRunning] = useState(false)
  const [client, setClient] = useState(null)

  const fetchFindings = useCallback(() => {
    if (!clientId) return
    setLoading(true)
    apiFetch(`/api/clients/${clientId}/cicd-findings`)
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((data) => setFindings(data?.findings ?? []))
      .catch(() => setFindings([]))
      .finally(() => setLoading(false))
  }, [clientId])

  useEffect(() => {
    fetchFindings()
  }, [fetchFindings])

  useEffect(() => {
    if (!clientId) return
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((list) => {
        const c = Array.isArray(list) ? list.find((x) => String(x.id) === String(clientId)) : null
        setClient(c || null)
      })
      .catch(() => setClient(null))
  }, [clientId])

  const findingsByStage = STAGES.reduce((acc, stage) => {
    acc[stage] = findings.filter((f) => (f.stage || 'Build') === stage)
    return acc
  }, {})

  const runScan = () => {
    if (!clientId || !runRepoUrl.trim()) return
    setRunning(true)
    apiFetch('/api/pipeline-scan/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: clientId, repo_url: runRepoUrl.trim() }),
    })
      .then((r) => r.json())
      .then(() => fetchFindings())
      .finally(() => setRunning(false))
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 p-6">
      <div className="max-w-6xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-4">
            <Link to="/" className="text-cyan-400 hover:text-cyan-300 text-sm font-medium">← War Room</Link>
            <h1 className="text-2xl font-bold text-white tracking-tight">Phantom Pipeline / CI/CD Matrix</h1>
          </div>
          {clientId && client && <span className="text-slate-500 text-sm">{client.name} (ID: {clientId})</span>}
        </div>

        <div className="mb-6 flex flex-wrap gap-2">
          <input
            type="text"
            value={runRepoUrl}
            onChange={(e) => setRunRepoUrl(e.target.value)}
            placeholder="https://github.com/owner/repo"
            className="rounded-lg bg-slate-800 border border-slate-600 px-3 py-2 text-sm text-white placeholder-slate-500 w-80"
          />
          <button
            onClick={runScan}
            disabled={running || !clientId}
            className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:bg-slate-600 text-white text-sm font-medium"
          >
            {running ? 'Scanning…' : 'Run pipeline scan'}
          </button>
        </div>

        <div className="rounded-xl bg-slate-900/80 border border-slate-700/60 p-6">
          <h2 className="text-lg font-semibold text-slate-200 mb-4">Pipeline</h2>
          <div className="flex flex-wrap items-center justify-between gap-4">
            {STAGES.map((stage) => {
              const count = (findingsByStage[stage] || []).length
              const isRed = count > 0
              return (
                <div key={stage} className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => count > 0 && setModalFinding(findingsByStage[stage][0])}
                    title={count > 0 ? `View ${count} finding(s)` : ''}
                    className={`rounded-xl px-6 py-4 font-bold text-sm transition-all ${
                      isRed
                        ? 'bg-red-500/30 border-2 border-red-500 text-red-200 hover:bg-red-500/50'
                        : 'bg-slate-800 border border-slate-600 text-slate-300 hover:border-slate-500'
                    }`}
                  >
                    {stage}
                    {count > 0 && <span className="ml-2 text-xs">({count})</span>}
                  </button>
                  {stage !== STAGES[STAGES.length - 1] && (
                    <span className="text-slate-600">→</span>
                  )}
                </div>
              )
            })}
          </div>
        </div>

        {loading && <p className="text-slate-500 mt-4">Loading findings…</p>}
        {!loading && findings.length === 0 && (
          <p className="text-slate-500 mt-4">No CI/CD findings. Run a pipeline scan with a GitHub repo URL.</p>
        )}

        {modalFinding && (
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
            onClick={() => setModalFinding(null)}
          >
            <div
              className="rounded-xl bg-slate-900 border-2 border-slate-600 max-w-4xl w-full max-h-[90vh] overflow-hidden flex flex-col"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="px-6 py-4 border-b border-slate-700 flex items-center justify-between">
                <h3 className="text-lg font-bold text-red-400">Attacker&apos;s Playbook</h3>
                <button
                  type="button"
                  onClick={() => setModalFinding(null)}
                  className="text-slate-400 hover:text-white"
                >
                  ✕
                </button>
              </div>
              <div className="p-4 text-sm text-amber-200 bg-amber-500/10 border-b border-slate-700">
                <strong>Blast radius:</strong> {modalFinding.blast_radius || '—'}
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-6 overflow-auto flex-1">
                <div>
                  <div className="text-slate-400 text-xs uppercase mb-2">Vulnerable client code ({modalFinding.file_path})</div>
                  <pre className="rounded-lg bg-slate-950 p-4 text-slate-300 text-xs overflow-x-auto whitespace-pre-wrap border border-slate-700">
                    {modalFinding.vulnerable_snippet || '—'}
                  </pre>
                </div>
                <div>
                  <div className="text-slate-400 text-xs uppercase mb-2">Ollama-generated PoC (stored only, never deployed)</div>
                  <pre className="rounded-lg bg-slate-950 p-4 text-red-200/90 text-xs overflow-x-auto whitespace-pre-wrap border border-red-900/50">
                    {modalFinding.poc_exploit || '—'}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
