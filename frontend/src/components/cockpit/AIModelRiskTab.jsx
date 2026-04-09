import React, { useState, useEffect, useCallback } from 'react'
import { useClient } from '../../context/ClientContext'
import { apiFetch } from '../../lib/apiBase'

const VECTOR_LABELS = {
  jailbreak_system_override: 'Jailbreak / policy override',
  prompt_instruction_leak: 'Prompt / system leak',
  rag_poison_exfil_simulation: 'RAG / instruction poison',
}

export default function AIModelRiskTab() {
  const { selectedClientId, selectedClient } = useClient()
  const [summary, setSummary] = useState({ vectors: [] })
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(false)
  const [running, setRunning] = useState(false)
  const [msg, setMsg] = useState(null)

  const load = useCallback(async () => {
    if (!selectedClientId) return
    setLoading(true)
    setMsg(null)
    try {
      const [sRes, eRes] = await Promise.all([
        apiFetch(`/api/clients/${selectedClientId}/llm-fuzz/summary`),
        apiFetch(`/api/clients/${selectedClientId}/llm-fuzz/events`),
      ])
      if (sRes.ok) {
        const d = await sRes.json()
        setSummary({ vectors: d.vectors ?? [] })
      } else {
        setSummary({ vectors: [] })
      }
      if (eRes.ok) {
        const d = await eRes.json()
        setEvents(d.events ?? [])
      } else {
        setEvents([])
      }
    } catch (_) {
      setSummary({ vectors: [] })
      setEvents([])
    } finally {
      setLoading(false)
    }
  }, [selectedClientId])

  useEffect(() => {
    load()
  }, [load])

  const runFuzz = async () => {
    if (!selectedClientId) return
    setRunning(true)
    setMsg(null)
    try {
      const r = await apiFetch(`/api/clients/${selectedClientId}/llm-fuzz/run`, {
        method: 'POST',
      })
      const d = await r.json().catch(() => ({}))
      if (r.ok) {
        setMsg({ type: 'ok', text: `Probes completed (${d.summary?.probes?.length ?? 0} events).` })
        await load()
      } else {
        setMsg({ type: 'err', text: d.detail || d.error || 'Run failed (check client config).' })
      }
    } catch (e) {
      setMsg({ type: 'err', text: String(e.message || e) })
    } finally {
      setRunning(false)
    }
  }

  if (!selectedClient) {
    return (
      <div className="p-8">
        <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-8 text-center">
          <p className="text-sm text-white/70">Select a client to view AI model risk telemetry.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 md:p-8 space-y-8 max-w-6xl">
      <div className="rounded-2xl bg-gradient-to-br from-violet-950/40 to-black/60 border border-violet-500/30 p-6">
        <h2 className="text-lg font-semibold text-white mb-1">AI Model Risk (AI-SecOps)</h2>
        <p className="text-sm text-white/60 mb-4">
          Adversarial probes against endpoints declared in client config under{' '}
          <code className="text-violet-300 bg-black/40 px-1 rounded">llm_secops.endpoints</code>. OpenAI-style
          chat JSON is assumed; leakage and hallucination-under-duress scores are heuristic.
        </p>
        <pre className="text-[11px] font-mono text-emerald-400/90 bg-black/50 rounded-lg p-3 overflow-x-auto border border-white/10 mb-4">
          {`{
  "llm_secops": {
    "endpoints": [
      { "url": "https://api.example.com/v1/chat/completions", "authorization": "sk-...", "model": "gpt-4o-mini" }
    ]
  }
}`}
        </pre>
        <button
          type="button"
          disabled={running || !selectedClientId}
          onClick={runFuzz}
          className="px-5 py-2.5 rounded-xl font-semibold text-sm border border-violet-500/50 bg-violet-600/20 text-violet-200 hover:bg-violet-600/30 disabled:opacity-40"
        >
          {running ? 'Running probes…' : 'Run LLM adversarial suite'}
        </button>
        {msg && (
          <p className={`mt-3 text-sm ${msg.type === 'ok' ? 'text-emerald-400' : 'text-red-400'}`}>{msg.text}</p>
        )}
      </div>

      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-6">
        <h3 className="text-xs font-mono uppercase tracking-wider text-violet-400 mb-4">Attack vectors × stress metrics</h3>
        {loading && <p className="text-white/50 text-sm">Loading…</p>}
        {!loading && (!summary.vectors || summary.vectors.length === 0) && (
          <p className="text-white/50 text-sm">No telemetry yet. Configure endpoints and run the suite.</p>
        )}
        <div className="space-y-4">
          {(summary.vectors || []).map((v) => {
            const label = VECTOR_LABELS[v.attack_vector] || v.attack_vector
            const leak = Math.min(100, (v.avg_leakage || 0) * 100)
            const hall = Math.min(100, (v.avg_hallucination_under_duress || 0) * 100)
            return (
              <div key={v.attack_vector} className="space-y-1">
                <div className="flex justify-between text-xs text-white/80">
                  <span>{label}</span>
                  <span className="text-white/40">{v.sample_count} samples</span>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <div className="text-[10px] text-red-400/90 mb-0.5">Context leakage score</div>
                    <div className="h-2 rounded-full bg-white/10 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-red-600 to-orange-500 transition-all"
                        style={{ width: `${leak}%` }}
                      />
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-amber-400/90 mb-0.5">Hallucination under duress</div>
                    <div className="h-2 rounded-full bg-white/10 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-amber-600 to-yellow-400 transition-all"
                        style={{ width: `${hall}%` }}
                      />
                    </div>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 overflow-hidden">
        <div className="px-4 py-3 border-b border-white/10 bg-white/5">
          <h3 className="text-xs font-mono uppercase tracking-wider text-cyan-400">Recent probe events</h3>
        </div>
        <div className="overflow-x-auto max-h-[420px] overflow-y-auto">
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-black/90 text-[10px] uppercase text-white/40">
              <tr>
                <th className="p-2">Vector</th>
                <th className="p-2">Endpoint</th>
                <th className="p-2">Leak</th>
                <th className="p-2">Halluc.</th>
                <th className="p-2">Blocked</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 && !loading && (
                <tr>
                  <td colSpan={5} className="p-4 text-white/40">
                    No events.
                  </td>
                </tr>
              )}
              {events.map((e) => (
                <tr key={e.id} className="border-t border-white/5 hover:bg-white/5">
                  <td className="p-2 text-violet-300 font-mono max-w-[140px] truncate" title={e.attack_vector}>
                    {VECTOR_LABELS[e.attack_vector] || e.attack_vector}
                  </td>
                  <td className="p-2 text-white/70 font-mono max-w-[200px] truncate" title={e.endpoint_url}>
                    {e.endpoint_url}
                  </td>
                  <td className="p-2 text-red-300">{(e.leakage_score ?? 0).toFixed(2)}</td>
                  <td className="p-2 text-amber-300">{(e.hallucination_score ?? 0).toFixed(2)}</td>
                  <td className="p-2">{e.blocked ? 'yes' : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
