import React, { useEffect, useState, useCallback } from 'react'
import { apiFetch } from '../../lib/apiBase'

export default function CeoGenesisPanel() {
  const [strategyLoading, setStrategyLoading] = useState(true)
  const [strategyErr, setStrategyErr] = useState('')
  const [ramMb, setRamMb] = useState(4096)
  const [seedsRepos, setSeedsRepos] = useState('')
  const [seedsNpm, setSeedsNpm] = useState('')
  const [killSwitch, setKillSwitch] = useState(false)
  const [protocolOn, setProtocolOn] = useState(false)
  const [saving, setSaving] = useState(false)

  const [hpcLoading, setHpcLoading] = useState(true)
  const [hpcErr, setHpcErr] = useState('')
  const [researchPct, setResearchPct] = useState(50)
  const [researchAff, setResearchAff] = useState('0-15')
  const [clientAff, setClientAff] = useState('16-31')
  const [routingNote, setRoutingNote] = useState('')
  const [hpcSaving, setHpcSaving] = useState(false)
  const [hpcView, setHpcView] = useState(null)

  const loadStrategy = useCallback(async () => {
    setStrategyLoading(true)
    setStrategyErr('')
    try {
      const r = await apiFetch('/api/ceo/strategy')
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d.detail || r.statusText)
      const e = d.effective || {}
      setRamMb(Number(e.genesis_ram_budget_mb) || 4096)
      setSeedsRepos(e.genesis_seed_repos || '')
      setSeedsNpm(e.genesis_seed_npm || '')
      setKillSwitch(!!e.genesis_kill_switch)
      setProtocolOn(!!e.genesis_protocol_enabled)
    } catch (err) {
      setStrategyErr(err.message || 'load failed')
    } finally {
      setStrategyLoading(false)
    }
  }, [])

  const loadHpc = useCallback(async () => {
    setHpcLoading(true)
    setHpcErr('')
    try {
      const r = await apiFetch('/api/ceo/hpc/policy')
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d.detail || r.statusText)
      setHpcView(d)
      const des = d.desired || {}
      setResearchPct(Number(des.research_core_share_percent) || 50)
      setResearchAff(des.research_cpu_affinity || '0-15')
      setClientAff(des.client_scan_cpu_affinity || '16-31')
      setRoutingNote(des.routing_note || '')
    } catch (err) {
      setHpcErr(err.message || 'load failed')
    } finally {
      setHpcLoading(false)
    }
  }, [])

  useEffect(() => {
    loadStrategy()
    loadHpc()
  }, [loadStrategy, loadHpc])

  const saveStrategy = async (e) => {
    e.preventDefault()
    setSaving(true)
    setStrategyErr('')
    try {
      const body = {
        configs: {
          genesis_ram_budget_mb: String(Math.max(64, Math.floor(Number(ramMb) || 4096))),
          genesis_seed_repos: seedsRepos,
          genesis_seed_npm: seedsNpm,
          genesis_kill_switch: killSwitch ? 'true' : 'false',
          genesis_protocol_enabled: protocolOn ? 'true' : 'false',
        },
      }
      const r = await apiFetch('/api/ceo/strategy', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d.detail || r.statusText)
      await loadStrategy()
    } catch (err) {
      setStrategyErr(err.message || 'save failed')
    } finally {
      setSaving(false)
    }
  }

  const applyHpc = async (e) => {
    e.preventDefault()
    setHpcSaving(true)
    setHpcErr('')
    try {
      const r = await apiFetch('/api/ceo/hpc/policy', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          research_core_share_percent: Math.min(100, Math.max(0, Math.floor(researchPct))),
          research_cpu_affinity: researchAff,
          client_scan_cpu_affinity: clientAff,
          routing_note: routingNote,
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d.detail || r.statusText)
      await loadHpc()
    } catch (err) {
      setHpcErr(err.message || 'save failed')
    } finally {
      setHpcSaving(false)
    }
  }

  const eff = hpcView && hpcView.effective_routing

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <form onSubmit={saveStrategy} className="rounded-lg border border-white/10 bg-black/35 p-4 space-y-4">
        <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-widest">Genesis operations</h2>
        {strategyLoading && <p className="text-xs text-slate-500 font-mono">Loading strategy…</p>}
        {strategyErr && <p className="text-xs text-red-400 font-mono">{strategyErr}</p>}
        <label className="flex items-center gap-2 text-xs text-slate-300 font-mono cursor-pointer">
          <input type="checkbox" checked={protocolOn} onChange={(e) => setProtocolOn(e.target.checked)} />
          Genesis protocol enabled (DB)
        </label>
        <label className="flex items-center gap-2 text-xs text-red-300 font-mono cursor-pointer">
          <input type="checkbox" checked={killSwitch} onChange={(e) => setKillSwitch(e.target.checked)} />
          Global kill switch (hibernate workers)
        </label>
        <div>
          <label className="block text-[10px] uppercase text-slate-500 mb-1 font-mono">RAM budget (MB)</label>
          <input
            type="number"
            min={64}
            max={262144}
            value={ramMb}
            onChange={(e) => setRamMb(e.target.value)}
            className="w-full font-mono text-sm bg-slate-950 border border-white/15 rounded px-3 py-2 text-slate-100"
          />
        </div>
        <div>
          <label className="block text-[10px] uppercase text-slate-500 mb-1 font-mono">Seed repos (URLs, comma or newline)</label>
          <textarea
            value={seedsRepos}
            onChange={(e) => setSeedsRepos(e.target.value)}
            rows={4}
            className="w-full font-mono text-xs bg-slate-950 border border-white/15 rounded px-3 py-2 text-slate-100"
          />
        </div>
        <div>
          <label className="block text-[10px] uppercase text-slate-500 mb-1 font-mono">Seed NPM (comma / newline)</label>
          <textarea
            value={seedsNpm}
            onChange={(e) => setSeedsNpm(e.target.value)}
            rows={3}
            className="w-full font-mono text-xs bg-slate-950 border border-white/15 rounded px-3 py-2 text-slate-100"
          />
        </div>
        <button
          type="submit"
          disabled={saving}
          className="px-4 py-2 rounded bg-emerald-950/80 border border-emerald-500/40 text-emerald-100 text-xs font-mono uppercase disabled:opacity-50"
        >
          {saving ? 'Saving…' : 'Apply strategy'}
        </button>
      </form>

      <form onSubmit={applyHpc} className="rounded-lg border border-amber-500/20 bg-amber-950/10 p-4 space-y-4">
        <h2 className="text-sm font-semibold text-amber-100/90 uppercase tracking-widest">HPC routing policy</h2>
        <div
          role="alert"
          className="text-[11px] font-mono text-amber-200/90 bg-black/40 border border-amber-500/30 rounded p-3 leading-snug"
        >
          Changes job-routing policy for workers using <code className="text-cyan-300">WEISSMAN_WORKER_POOL</code>. Takes
          effect on the next async worker claim cycle (honest model — not live Tokio re-pinning).
        </div>
        {hpcLoading && <p className="text-xs text-slate-500 font-mono">Loading policy…</p>}
        {hpcErr && <p className="text-xs text-red-400 font-mono">{hpcErr}</p>}
        <div>
          <label className="block text-[10px] uppercase text-slate-500 mb-1 font-mono">
            Research core share: {researchPct}% (target)
          </label>
          <input
            type="range"
            min={0}
            max={100}
            value={researchPct}
            onChange={(e) => setResearchPct(Number(e.target.value))}
            className="w-full accent-amber-500"
          />
        </div>
        <div>
          <label className="block text-[10px] uppercase text-slate-500 mb-1 font-mono">Research CPU affinity</label>
          <input
            value={researchAff}
            onChange={(e) => setResearchAff(e.target.value)}
            className="w-full font-mono text-sm bg-slate-950 border border-white/15 rounded px-3 py-2 text-slate-100"
          />
        </div>
        <div>
          <label className="block text-[10px] uppercase text-slate-500 mb-1 font-mono">Client scan CPU affinity</label>
          <input
            value={clientAff}
            onChange={(e) => setClientAff(e.target.value)}
            className="w-full font-mono text-sm bg-slate-950 border border-white/15 rounded px-3 py-2 text-slate-100"
          />
        </div>
        <div>
          <label className="block text-[10px] uppercase text-slate-500 mb-1 font-mono">Routing note</label>
          <input
            value={routingNote}
            onChange={(e) => setRoutingNote(e.target.value)}
            className="w-full font-mono text-sm bg-slate-950 border border-white/15 rounded px-3 py-2 text-slate-100"
          />
        </div>
        <button
          type="submit"
          disabled={hpcSaving}
          className="px-4 py-2 rounded bg-amber-900/60 border border-amber-500/40 text-amber-50 text-xs font-mono uppercase disabled:opacity-50"
        >
          {hpcSaving ? 'Saving…' : 'Apply HPC policy'}
        </button>
        {eff && (
          <div className="text-[10px] font-mono text-slate-400 space-y-1 border-t border-white/10 pt-3 mt-2">
            <div>
              Worker pool env: <span className="text-cyan-300">{eff.worker_pool_env || '—'}</span>
            </div>
            <div>
              Running research jobs:{' '}
              <span className="text-emerald-300">{eff.running_research_jobs ?? '—'}</span> · client:{' '}
              <span className="text-sky-300">{eff.running_client_jobs ?? '—'}</span>
            </div>
            {eff.actual_research_share_percent_of_running != null && (
              <div>
                Actual research share (running):{' '}
                <span className="text-amber-200">{eff.actual_research_share_percent_of_running}%</span>
              </div>
            )}
          </div>
        )}
      </form>
    </div>
  )
}
