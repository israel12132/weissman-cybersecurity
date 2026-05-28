import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { apiFetch, apiUrl } from '../lib/apiBase'

function timeAgo(iso) {
  if (!iso) return 'never'
  const ms = Date.now() - new Date(iso).getTime()
  if (Number.isNaN(ms)) return 'unknown'
  const s = Math.max(1, Math.floor(ms / 1000))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

function StatusBadge({ online, last_seen_at }) {
  if (online) return <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-emerald-500/40 bg-emerald-500/15 text-emerald-300">ONLINE</span>
  if (!last_seen_at) return <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-white/15 text-white/45">NEVER ENROLLED</span>
  return <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-rose-500/40 bg-rose-500/10 text-rose-300">OFFLINE</span>
}

export default function AgentManagement() {
  const [agents, setAgents] = useState([])
  const [loading, setLoading] = useState(true)
  const [clients, setClients] = useState([])
  const [tokenClient, setTokenClient] = useState('')
  const [tokenValidity, setTokenValidity] = useState(60)
  const [generatedToken, setGeneratedToken] = useState(null)
  const [err, setErr] = useState(null)
  const [polled, setPolled] = useState(0)

  const refresh = useCallback(async () => {
    try {
      const r = await apiFetch('/api/agents/status')
      // 404 / 5xx → render an empty state instead of crashing the entire route. The endpoint
      // used to require a DB table that wasn't migrated and an empty response body broke the
      // error handler downstream.
      if (r.status === 404) {
        setAgents([])
        setErr(null)
        return
      }
      const txt = await r.text()
      let d = {}
      try { d = txt ? JSON.parse(txt) : {} } catch { d = {} }
      if (!r.ok) throw new Error(d.detail || `Couldn't load agents (HTTP ${r.status}).`)
      setAgents(Array.isArray(d.agents) ? d.agents : [])
      setErr(null)
    } catch (e) {
      setErr(e.message || String(e))
      setAgents([])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch(() => {})
    const t = setInterval(() => { setPolled((n) => n + 1); refresh() }, 15000)
    return () => clearInterval(t)
  }, [refresh])

  const createToken = useCallback(async () => {
    setErr(null); setGeneratedToken(null)
    const cid = Number(tokenClient)
    if (!cid) { setErr('Select a client first'); return }
    try {
      const r = await apiFetch('/api/agents/enrollment-tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_id: cid, valid_minutes: Number(tokenValidity) || 60 }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`)
      setGeneratedToken(d)
    } catch (e) { setErr(e.message) }
  }, [tokenClient, tokenValidity])

  const installLinux = useMemo(() => {
    if (!generatedToken) return ''
    const base = apiUrl('/install/agent.sh')
    return `curl -sSL ${base} | WEISSMAN_TOKEN="${generatedToken.enrollment_token}" WEISSMAN_SERVER="${apiUrl('').replace(/^http/, 'http')}" bash`
  }, [generatedToken])

  const installWindows = useMemo(() => {
    if (!generatedToken) return ''
    const base = apiUrl('/install/agent.ps1')
    return `iwr ${base} | iex; Install-WeissmanAgent -Token "${generatedToken.enrollment_token}" -Server "${apiUrl('').replace(/^http/, 'http')}"`
  }, [generatedToken])

  return (
    <div className="min-h-[100dvh] p-6 text-slate-100" style={{background: 'radial-gradient(ellipse 100% 70% at 50% 0%, #0f172a 0%, #020617 60%, #000 100%)'}}>
      <header className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">Endpoint Agents</h1>
          <p className="text-sm text-white/55 mt-1">
            Generate a single-use enrollment token, copy the install command, and run it on the target endpoint.
            Once online, the agent unlocks every engine marked "Requires Agent".
          </p>
        </div>
        <div className="text-[11px] font-mono text-white/40">
          {agents.length} registered · {agents.filter((a) => a.online).length} online · refresh #{polled}
        </div>
      </header>

      <section className="rounded-2xl bg-black/40 border border-white/10 backdrop-blur-md p-5 mb-6 space-y-4">
        <h2 className="text-xs font-mono uppercase tracking-widest text-white/55">Issue Enrollment Token</h2>
        {err && <div className="text-[12px] font-mono text-rose-400">{err}</div>}
        <div className="grid grid-cols-1 sm:grid-cols-[1fr_180px_140px] gap-3">
          <select value={tokenClient} onChange={(e) => setTokenClient(e.target.value)} className="bg-black/50 border border-white/10 rounded-lg px-3 py-2 text-sm font-mono">
            <option value="">— Select client —</option>
            {clients.map((c) => <option key={c.id} value={c.id}>{c.name} (#{c.id})</option>)}
          </select>
          <input type="number" min={5} max={1440} value={tokenValidity} onChange={(e) => setTokenValidity(e.target.value)} className="bg-black/50 border border-white/10 rounded-lg px-3 py-2 text-sm font-mono" placeholder="Validity (minutes)" />
          <button type="button" onClick={createToken} className="px-4 py-2 rounded-lg bg-cyan-500/20 border border-cyan-500/40 text-cyan-200 font-mono text-sm hover:bg-cyan-500/30">
            Generate Token
          </button>
        </div>
        {generatedToken && (
          <div className="space-y-3 border-t border-white/10 pt-4">
            <div>
              <div className="text-[10px] uppercase font-mono text-white/45 mb-1">One-time token (copy now — displayed only here)</div>
              <code className="block bg-black/70 border border-white/10 rounded-lg p-3 text-xs font-mono text-emerald-300 break-all">{generatedToken.enrollment_token}</code>
              <div className="text-[10px] text-white/40 mt-1">Valid for {generatedToken.expires_in_minutes} min. Client #{generatedToken.client_id}.</div>
            </div>
            <div>
              <div className="text-[10px] uppercase font-mono text-white/45 mb-1">Linux / macOS</div>
              <code className="block bg-black/70 border border-white/10 rounded-lg p-3 text-xs font-mono text-cyan-200 whitespace-pre-wrap break-all">{installLinux}</code>
            </div>
            <div>
              <div className="text-[10px] uppercase font-mono text-white/45 mb-1">Windows PowerShell (Admin)</div>
              <code className="block bg-black/70 border border-white/10 rounded-lg p-3 text-xs font-mono text-cyan-200 whitespace-pre-wrap break-all">{installWindows}</code>
            </div>
          </div>
        )}
      </section>

      <section className="rounded-2xl bg-black/40 border border-white/10 backdrop-blur-md p-5">
        <h2 className="text-xs font-mono uppercase tracking-widest text-white/55 mb-3">Registered Agents</h2>
        {loading ? <p className="text-sm text-white/40">Loading…</p> : agents.length === 0 ? (
          <p className="text-sm text-white/40">No agents enrolled yet. Generate a token above and run the install command on a target endpoint.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[12px] font-mono">
              <thead>
                <tr className="text-left text-white/45 border-b border-white/10">
                  <th className="py-2 pr-3">Status</th>
                  <th className="py-2 pr-3">Client</th>
                  <th className="py-2 pr-3">Hostname</th>
                  <th className="py-2 pr-3">OS / Arch</th>
                  <th className="py-2 pr-3">Version</th>
                  <th className="py-2 pr-3">Last seen</th>
                  <th className="py-2 pr-3">Caps</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {agents.map((a) => (
                  <tr key={a.agent_id} className="hover:bg-white/[0.02]">
                    <td className="py-2 pr-3"><StatusBadge online={a.online} last_seen_at={a.last_seen_at} /></td>
                    <td className="py-2 pr-3">#{a.client_id}</td>
                    <td className="py-2 pr-3 text-white/85">{a.hostname}</td>
                    <td className="py-2 pr-3 text-white/60">{a.os} / {a.arch}</td>
                    <td className="py-2 pr-3 text-white/55">{a.agent_version || '—'}</td>
                    <td className="py-2 pr-3 text-white/45">{timeAgo(a.last_seen_at)}</td>
                    <td className="py-2 pr-3 text-cyan-300/80 truncate max-w-[260px]" title={JSON.stringify(a.capabilities)}>
                      {(a.capabilities || []).length} caps
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}
