import React, { useCallback, useEffect, useMemo, useState } from 'react'
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

function CodeBlock({ label, value }) {
  return (
    <div className="rounded-xl border border-white/10 bg-black/50 p-4">
      {label && <div className="text-[10px] font-mono text-white/30 mb-2">{label}</div>}
      <pre className="text-[11px] leading-relaxed text-white/70 font-mono whitespace-pre-wrap break-words">
        {value}
      </pre>
    </div>
  )
}

export default function TemplateEngineWorkbench() {
  const [templates, setTemplates] = useState([])
  const [selectedId, setSelectedId] = useState('http_baseline')
  const [targetUrl, setTargetUrl] = useState('')
  const [yaml, setYaml] = useState('')
  const [runResult, setRunResult] = useState(null)
  const [loadingYaml, setLoadingYaml] = useState(false)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')

  const canRun = useMemo(() => !!String(targetUrl || '').trim() && !!String(yaml || '').trim(), [targetUrl, yaml])

  useEffect(() => {
    apiFetch('/api/template-engine/templates')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setTemplates(d) })
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (!selectedId) return
    setLoadingYaml(true)
    setError('')
    apiFetch(`/api/template-engine/templates/${encodeURIComponent(selectedId)}`)
      .then(async (r) => {
        const d = await r.json().catch(() => ({}))
        if (!r.ok) throw new Error(d?.error || 'Failed to load template')
        setYaml(String(d?.yaml || ''))
      })
      .catch((e) => setError(e?.message || 'Failed to load template'))
      .finally(() => setLoadingYaml(false))
  }, [selectedId])

  const run = useCallback(async () => {
    if (!canRun) return
    setRunning(true)
    setError('')
    setRunResult(null)
    try {
      const r = await apiFetch('/api/template-engine/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_url: targetUrl.trim(),
          template_yaml: yaml,
          max_body_bytes: 200000,
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d?.error || d?.detail || 'Run failed')
      setRunResult(d)
    } catch (e) {
      setError(e?.message || 'Run failed')
    } finally {
      setRunning(false)
    }
  }, [canRun, targetUrl, yaml])

  return (
    <PageShell
      title="Template Engine"
      badge="YAML"
      badgeColor="#60a5fa"
      subtitle="Run request/matcher rules from YAML without changing core code."
    >
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
        <div className="space-y-4">
          <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-3">
            <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">Runner</h3>
            <input
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="Target URL (e.g. https://app.target.com)"
              className="w-full rounded-xl bg-white/5 border border-white/10 px-3 py-2 text-[12px] text-white/70 placeholder-white/20 focus:outline-none focus:border-blue-500/40"
            />
            <div className="flex items-center gap-3 flex-wrap">
              <select
                value={selectedId}
                onChange={(e) => setSelectedId(e.target.value)}
                className="rounded-xl bg-black/60 border border-white/10 px-3 py-2 text-[12px] text-white/70 focus:outline-none focus:border-blue-500/40"
              >
                {templates.map((t) => (
                  <option key={t.id} value={t.id}>{t.name}</option>
                ))}
                {templates.length === 0 && <option value="http_baseline">http_baseline</option>}
              </select>
              <button
                type="button"
                disabled={!canRun || running || loadingYaml}
                onClick={run}
                className="px-4 py-2 rounded-xl border border-blue-500/30 text-blue-300/70 text-[12px] font-mono uppercase hover:bg-blue-950/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
              >
                {running ? '⟳ Running…' : '▶ Run'}
              </button>
            </div>
            {error && (
              <div className="rounded-xl border border-rose-500/30 bg-rose-950/40 px-3 py-2 text-[11px] text-rose-200">
                {error}
              </div>
            )}
          </div>

          <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">Template YAML</h3>
              <span className="text-[10px] font-mono text-white/25">{loadingYaml ? 'Loading…' : 'Editable'}</span>
            </div>
            <textarea
              value={yaml}
              onChange={(e) => setYaml(e.target.value)}
              rows={18}
              className="w-full rounded-xl bg-black/60 border border-white/10 px-3 py-2 text-[11px] text-white/70 font-mono focus:outline-none focus:border-blue-500/40"
            />
          </div>
        </div>

        <div className="space-y-4">
          <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-3">
            <h3 className="text-xs font-mono text-white/50 uppercase tracking-widest">Result</h3>
            {!runResult ? (
              <div className="rounded-xl border border-white/10 bg-white/5 p-4">
                <p className="text-[11px] font-mono text-white/25">Run a template to see step-by-step evidence.</p>
              </div>
            ) : (
              <div className="space-y-3">
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                    runResult?.verification?.verified ? 'border-green-500/30 text-green-400 bg-green-900/10' : 'border-white/10 text-white/30'
                  }`}>
                    {runResult?.verification?.verified ? '✓ VERIFIED' : 'NOT VERIFIED'}
                  </span>
                </div>

                <CodeBlock label="Verification" value={JSON.stringify(runResult.verification || {}, null, 2)} />
                <CodeBlock label="Steps" value={JSON.stringify(runResult.steps || [], null, 2)} />
              </div>
            )}
          </div>
        </div>
      </div>
    </PageShell>
  )
}
