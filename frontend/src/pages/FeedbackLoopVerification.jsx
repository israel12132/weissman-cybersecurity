import React, { useCallback, useEffect, useState } from 'react'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

export default function FeedbackLoopVerification() {
  const [targetUrl, setTargetUrl] = useState('')
  const [yaml, setYaml] = useState('')
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    apiFetch('/api/template-engine/templates/multi_step_state_demo')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => setYaml(String(d?.yaml || '')))
      .catch(() => {})
  }, [])

  const run = useCallback(async () => {
    if (!targetUrl.trim() || !yaml.trim()) return
    setRunning(true)
    setError('')
    setResult(null)
    try {
      const r = await apiFetch('/api/template-engine/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_url: targetUrl.trim(),
          template_yaml: yaml,
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d?.error || d?.detail || 'Run failed')
      setResult(d)
    } catch (e) {
      setError(e?.message || 'Run failed')
    } finally {
      setRunning(false)
    }
  }, [targetUrl, yaml])

  return (
    <PageShell
      title="Feedback Loop Verification"
      badge="STATE"
      badgeColor="#a78bfa"
      subtitle="Multi-step verification with state extraction and chained requests (token → proof)."
    >
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
        <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-3">
          <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">Chain Runner</h3>
          <input
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="Target URL (e.g. https://app.target.com)"
            className="w-full rounded-xl bg-white/5 border border-white/10 px-3 py-2 text-[12px] text-white/70 placeholder-white/20 focus:outline-none focus:border-violet-500/40"
          />
          <button
            type="button"
            disabled={!targetUrl.trim() || !yaml.trim() || running}
            onClick={run}
            className="w-full px-4 py-2 rounded-xl border border-violet-500/30 text-violet-300/70 text-[12px] font-mono uppercase hover:bg-violet-950/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {running ? '⟳ Running…' : '▶ Run Chain'}
          </button>
          {error && (
            <div className="rounded-xl border border-rose-500/30 bg-rose-950/40 px-3 py-2 text-[11px] text-rose-200">
              {error}
            </div>
          )}
          <div className="rounded-xl border border-white/10 bg-black/50 p-4">
            <div className="text-[10px] font-mono text-white/30 mb-2">Template (editable)</div>
            <textarea
              value={yaml}
              onChange={(e) => setYaml(e.target.value)}
              rows={14}
              className="w-full rounded-xl bg-black/60 border border-white/10 px-3 py-2 text-[11px] text-white/70 font-mono focus:outline-none focus:border-violet-500/40"
            />
          </div>
        </div>

        <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-3">
          <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">State & Evidence</h3>
          {!result ? (
            <div className="rounded-xl border border-white/10 bg-white/5 p-4">
              <p className="text-[11px] font-mono text-white/25">Run the chain to see state extraction and per-step evidence.</p>
            </div>
          ) : (
            <div className="space-y-3">
              <div className={`text-[10px] font-mono px-2 py-0.5 rounded border inline-flex ${
                result?.verification?.verified ? 'border-green-500/30 text-green-400 bg-green-900/10' : 'border-white/10 text-white/30'
              }`}>
                {result?.verification?.verified ? '✓ VERIFIED' : 'NOT VERIFIED'}
              </div>
              <pre className="rounded-xl border border-white/10 bg-black/50 p-4 text-[11px] text-white/70 font-mono whitespace-pre-wrap break-words">
                {JSON.stringify(result.steps || [], null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </PageShell>
  )
}

