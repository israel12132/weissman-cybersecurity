import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import PageShell from './PageShell'
import { apiFetch, apiEventSourceUrl } from '../lib/apiBase'
import { ENGINES_BY_ID } from '../lib/enginesRegistry'

const ENGINE_ID = 'nexus_sovereign_swarm'
const ARCHETYPES = [
  { id: 'scout', label: 'Scout', color: '#22d3ee', icon: '🔭', desc: 'Technology fingerprinting & surface mapping' },
  { id: 'exploiter', label: 'Exploiter', color: '#ef4444', icon: '⚔️', desc: 'Sensitive endpoint & exposure vector probing' },
  { id: 'correlator', label: 'Correlator', color: '#a855f7', icon: '🧠', desc: 'Cross-agent hive-mind consensus synthesis' },
  { id: 'stealth', label: 'Stealth', color: '#64748b', icon: '👻', desc: 'Low-profile intel harvesting (robots, sitemap)' },
  { id: 'oracle', label: 'Oracle', color: '#f59e0b', icon: '🔮', desc: 'LLM strategic synthesis & next-engine routing' },
]

const DEFAULT_PARAMS = {
  agent_count: '2048',
  hive_mode: 'emergent',
  llm_strategy: 'adaptive',
  archetypes: 'scout,exploiter,correlator,stealth,oracle',
  endpoint_bridge: 'true',
  edge_distribution: 'true',
  convergence_threshold: '0.85',
  llm_base_url: '',
  llm_model: '',
}

function SwarmHiveCanvas({ agentCount, running, signals = 0 }) {
  const canvasRef = useRef(null)
  const animRef = useRef(null)
  const nodesRef = useRef([])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return undefined
    const ctx = canvas.getContext('2d')
    const dpr = window.devicePixelRatio || 1
    const w = canvas.offsetWidth
    const h = canvas.offsetHeight
    canvas.width = w * dpr
    canvas.height = h * dpr
    ctx.scale(dpr, dpr)

    const nodeCount = Math.min(Math.max(Math.floor(agentCount / 40), 24), 120)
    nodesRef.current = Array.from({ length: nodeCount }, (_, i) => ({
      x: Math.random() * w,
      y: Math.random() * h,
      vx: (Math.random() - 0.5) * (running ? 1.2 : 0.3),
      vy: (Math.random() - 0.5) * (running ? 1.2 : 0.3),
      r: 2 + Math.random() * 2.5,
      hue: [190, 280, 350, 45, 160][i % 5],
      pulse: Math.random() * Math.PI * 2,
      archetype: ARCHETYPES[i % ARCHETYPES.length],
    }))

    const draw = () => {
      ctx.fillStyle = 'rgba(0,0,0,0.12)'
      ctx.fillRect(0, 0, w, h)

      const nodes = nodesRef.current
      const cx = w / 2
      const cy = h / 2

      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x
          const dy = nodes[i].y - nodes[j].y
          const dist = Math.sqrt(dx * dx + dy * dy)
          if (dist < 90) {
            ctx.beginPath()
            ctx.moveTo(nodes[i].x, nodes[i].y)
            ctx.lineTo(nodes[j].x, nodes[j].y)
            ctx.strokeStyle = `hsla(${nodes[i].hue}, 80%, 60%, ${(1 - dist / 90) * 0.25})`
            ctx.lineWidth = 0.6
            ctx.stroke()
          }
        }
      }

      nodes.forEach((n) => {
        n.x += n.vx
        n.y += n.vy
        n.pulse += running ? 0.08 : 0.02
        if (n.x < 0 || n.x > w) n.vx *= -1
        if (n.y < 0 || n.y > h) n.vy *= -1

        const pull = running ? 0.0008 : 0.0002
        n.vx += (cx - n.x) * pull
        n.vy += (cy - n.y) * pull

        const glow = 0.5 + Math.sin(n.pulse) * 0.5
        ctx.beginPath()
        ctx.arc(n.x, n.y, n.r * (running ? 1 + glow * 0.4 : 1), 0, Math.PI * 2)
        ctx.fillStyle = `hsla(${n.hue}, 90%, 65%, ${0.6 + glow * 0.4})`
        ctx.fill()
      })

      if (running) {
        ctx.beginPath()
        ctx.arc(cx, cy, 28 + Math.sin(Date.now() / 300) * 4, 0, Math.PI * 2)
        ctx.strokeStyle = 'rgba(167, 139, 250, 0.5)'
        ctx.lineWidth = 1.5
        ctx.stroke()
        ctx.font = '10px monospace'
        ctx.fillStyle = 'rgba(255,255,255,0.7)'
        ctx.textAlign = 'center'
        ctx.fillText('HIVE CORE', cx, cy + 3)
      }

      animRef.current = requestAnimationFrame(draw)
    }
    draw()
    return () => {
      if (animRef.current) cancelAnimationFrame(animRef.current)
    }
  }, [agentCount, running, signals])

  return (
    <canvas
      ref={canvasRef}
      className="w-full h-full rounded-xl"
      style={{ background: 'radial-gradient(ellipse at center, rgba(88,28,135,0.15) 0%, rgba(0,0,0,0.6) 70%)' }}
    />
  )
}

function SiqGauge({ score }) {
  const pct = Math.min(100, Math.max(0, score ?? 0))
  const color = pct >= 80 ? '#ef4444' : pct >= 60 ? '#f59e0b' : '#22d3ee'
  return (
    <div className="relative w-36 h-36 mx-auto">
      <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
        <circle cx="50" cy="50" r="42" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8" />
        <circle
          cx="50" cy="50" r="42" fill="none"
          stroke={color} strokeWidth="8"
          strokeDasharray={`${pct * 2.64} 264`}
          strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 8px ${color}80)` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold text-white">{pct || '—'}</span>
        <span className="text-[9px] font-mono text-white/40 uppercase tracking-widest">SIQ</span>
      </div>
    </div>
  )
}

function MetricTile({ label, value, sub, accent = '#a855f7' }) {
  return (
    <div
      className="rounded-xl border border-white/10 bg-black/40 backdrop-blur-md p-4"
      style={{ boxShadow: `inset 0 1px 0 ${accent}20` }}
    >
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-white/35 mb-1">{label}</p>
      <p className="text-2xl font-bold text-white">{value ?? '—'}</p>
      {sub && <p className="text-[10px] font-mono text-white/30 mt-0.5">{sub}</p>}
    </div>
  )
}

export default function NexusSovereignSwarm() {
  const { t } = useTranslation()
  const engine = ENGINES_BY_ID[ENGINE_ID]
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState('')
  const [target, setTarget] = useState('')
  const [params, setParams] = useState(DEFAULT_PARAMS)
  const [running, setRunning] = useState(false)
  const [lines, setLines] = useState([])
  const [metrics, setMetrics] = useState(null)
  const [findings, setFindings] = useState([])
  const esRef = useRef(null)

  useEffect(() => {
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (!selectedClientId) return
    const client = clients.find((c) => String(c.id) === String(selectedClientId))
    if (!client) return
    let domains = client.domains
    if (typeof domains === 'string') {
      try { domains = JSON.parse(domains) } catch { domains = [] }
    }
    const first = Array.isArray(domains) ? (domains[0] || '') : ''
    if (first) setTarget(first.startsWith('http') ? first : `https://${first}`)
  }, [selectedClientId, clients])

  const appendLine = useCallback((msg) => {
    setLines((prev) => [...prev.slice(-400), msg])
  }, [])

  const handleRun = useCallback(async () => {
    if (!selectedClientId) return
    if (!target.trim()) return
    setRunning(true)
    setLines([])
    setMetrics(null)
    setFindings([])
    appendLine(`[NSSI] Initializing hive deployment — ${params.agent_count} agents...`)

    const body = {
      engine: ENGINE_ID,
      client_id: Number(selectedClientId),
      target: target.trim(),
      timeout: 300,
      ...params,
    }
    if (body.llm_base_url) {
      body.ai_endpoint = JSON.stringify({ base_url: body.llm_base_url, model: body.llm_model || '' })
    }

    try {
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = await r.json()
      if (!r.ok) {
        appendLine(`[ERROR] ${data.detail || 'Scan failed'}`)
        setRunning(false)
        return
      }
      const jobId = data.job_id
      appendLine(`[NSSI] Job queued: ${jobId}`)
      if (esRef.current) esRef.current.close()
      const es = new EventSource(apiEventSourceUrl(`/api/telemetry/stream?job_id=${jobId}`))
      esRef.current = es
      es.onmessage = (ev) => {
        try {
          const p = JSON.parse(ev.data)
          if (p.message) appendLine(p.message)
          if (p.status === 'completed' || p.status === 'failed') {
            es.close()
            setRunning(false)
            apiFetch(`/api/jobs/${jobId}`)
              .then((jr) => (jr.ok ? jr.json() : null))
              .then((job) => {
                const res = job?.result_json || job?.result
                const f = res?.findings || []
                setFindings(f)
                const meta = f.find((x) => x.swarm_metrics)?.swarm_metrics
                if (meta) setMetrics(meta)
                appendLine(`[NSSI] Deployment complete — ${f.length} findings`)
              })
              .catch(() => {})
          }
        } catch { /* ignore */ }
      }
      es.onerror = () => {
        es.close()
        setRunning(false)
      }
    } catch (e) {
      appendLine(`[ERROR] ${e.message}`)
      setRunning(false)
    }
  }, [selectedClientId, target, params, appendLine])

  useEffect(() => () => { if (esRef.current) esRef.current.close() }, [])

  const agentCount = parseInt(params.agent_count, 10) || 2048

  return (
    <PageShell
      title={t('nexusSwarm.title', 'Nexus Sovereign Swarm Intelligence')}
      subtitle={t('nexusSwarm.subtitle', 'Hyper-scale autonomous hive-mind — thousands of AI agents, emergent consensus, breakthrough SIQ scoring')}
    >
      <div className="space-y-6">
        {/* Hero strip */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          className="relative overflow-hidden rounded-2xl border border-violet-500/30 bg-gradient-to-br from-violet-950/40 via-black/60 to-cyan-950/30 p-6"
        >
          <div className="absolute inset-0 opacity-30" style={{ background: 'radial-gradient(circle at 20% 50%, rgba(139,92,246,0.4), transparent 50%), radial-gradient(circle at 80% 50%, rgba(34,211,238,0.2), transparent 50%)' }} />
          <div className="relative flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-violet-400/40 text-violet-300 bg-violet-500/10 uppercase tracking-widest">
                  Top-Tier · AI Swarm
                </span>
                <span className="text-[10px] font-mono text-white/30">MITRE T1595</span>
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">
                {engine?.label || 'Nexus Sovereign Swarm Intelligence'}
              </h1>
              <p className="text-sm text-white/50 mt-1 max-w-2xl leading-relaxed">
                {engine?.description}
              </p>
            </div>
            <div className="flex gap-2 flex-wrap">
              <Link to={`/engines/${ENGINE_ID}`} className="text-[11px] font-mono px-3 py-1.5 rounded-lg border border-white/15 text-white/60 hover:text-white hover:border-white/30 transition-colors">
                Engine Detail →
              </Link>
              <Link to={`/engines/top-tier/${ENGINE_ID}`} className="text-[11px] font-mono px-3 py-1.5 rounded-lg border border-rose-500/30 text-rose-300 hover:bg-rose-500/10 transition-colors">
                Top-Tier Profile →
              </Link>
            </div>
          </div>
        </motion.div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          {/* Hive visualization */}
          <div className="xl:col-span-2 rounded-2xl border border-white/10 bg-black/40 overflow-hidden">
            <div className="px-4 py-3 border-b border-white/5 flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-white/40">
                {t('nexusSwarm.hive_viz', 'Live Hive Visualization')}
              </span>
              {running && (
                <span className="flex items-center gap-1.5 text-[10px] font-mono text-violet-300">
                  <span className="w-1.5 h-1.5 rounded-full bg-violet-400 animate-pulse" />
                  DEPLOYING
                </span>
              )}
            </div>
            <div className="h-72 md:h-96">
              <SwarmHiveCanvas agentCount={agentCount} running={running} signals={metrics?.raw_signals} />
            </div>
          </div>

          {/* SIQ + metrics */}
          <div className="space-y-4">
            <div className="rounded-2xl border border-white/10 bg-black/40 p-5 text-center">
              <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-white/40 mb-3">
                {t('nexusSwarm.siq', 'Swarm Intelligence Quotient')}
              </p>
              <SiqGauge score={metrics?.swarm_iq} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <MetricTile label="Agents" value={metrics?.agents_deployed?.toLocaleString() ?? agentCount.toLocaleString()} accent="#22d3ee" />
              <MetricTile label="Signals" value={metrics?.raw_signals} accent="#ef4444" />
              <MetricTile label="Consensus" value={metrics?.consensus_findings} accent="#a855f7" />
              <MetricTile label="Endpoints" value={metrics?.endpoint_agents_bridged} accent="#f59e0b" />
            </div>
          </div>
        </div>

        {/* Archetypes */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {ARCHETYPES.map((a) => (
            <div
              key={a.id}
              className="rounded-xl border border-white/10 bg-black/30 p-3 hover:border-white/20 transition-colors"
              style={{ borderColor: `${a.color}20` }}
            >
              <div className="flex items-center gap-2 mb-1">
                <span>{a.icon}</span>
                <span className="text-xs font-semibold text-white">{a.label}</span>
              </div>
              <p className="text-[10px] text-white/40 leading-relaxed">{a.desc}</p>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Parameters */}
          <div className="rounded-2xl border border-white/10 bg-black/40 p-5 space-y-4">
            <h2 className="text-sm font-semibold text-white">{t('nexusSwarm.params', 'Deployment Parameters')}</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <label className="space-y-1">
                <span className="text-[10px] font-mono text-white/40 uppercase">{t('common.client')}</span>
                <select
                  value={selectedClientId}
                  onChange={(e) => setSelectedClientId(e.target.value)}
                  className="w-full rounded-lg bg-black/50 border border-white/10 px-3 py-2 text-sm text-white"
                >
                  <option value="">—</option>
                  {clients.map((c) => (
                    <option key={c.id} value={c.id}>{c.name || c.id}</option>
                  ))}
                </select>
              </label>
              <label className="space-y-1 sm:col-span-2">
                <span className="text-[10px] font-mono text-white/40 uppercase">{t('common.target')}</span>
                <input
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="https://target.example"
                  className="w-full rounded-lg bg-black/50 border border-white/10 px-3 py-2 text-sm text-white font-mono"
                />
              </label>
              {[
                { key: 'agent_count', label: 'Agent Count', type: 'number', min: 64, max: 10000 },
                { key: 'hive_mode', label: 'Hive Mode', type: 'select', options: ['emergent', 'parallel', 'stealth', 'blitz'] },
                { key: 'llm_strategy', label: 'Oracle Strategy', type: 'select', options: ['adaptive', 'aggressive', 'stealth', 'oracle'] },
                { key: 'convergence_threshold', label: 'Consensus Threshold', type: 'number', min: 0.5, max: 0.99, step: 0.01 },
                { key: 'endpoint_bridge', label: 'Endpoint Bridge', type: 'select', options: ['true', 'false'] },
                { key: 'edge_distribution', label: 'Edge Distribution', type: 'select', options: ['true', 'false'] },
                { key: 'archetypes', label: 'Archetypes', type: 'text', span: 2 },
                { key: 'llm_base_url', label: 'Oracle LLM URL', type: 'text', span: 2 },
                { key: 'llm_model', label: 'Oracle LLM Model', type: 'text' },
              ].map((f) => (
                <label key={f.key} className={`space-y-1 ${f.span === 2 ? 'sm:col-span-2' : ''}`}>
                  <span className="text-[10px] font-mono text-white/40 uppercase">{f.label}</span>
                  {f.type === 'select' ? (
                    <select
                      value={params[f.key]}
                      onChange={(e) => setParams((p) => ({ ...p, [f.key]: e.target.value }))}
                      className="w-full rounded-lg bg-black/50 border border-white/10 px-3 py-2 text-sm text-white"
                    >
                      {f.options.map((o) => <option key={o} value={o}>{o}</option>)}
                    </select>
                  ) : (
                    <input
                      type={f.type}
                      min={f.min}
                      max={f.max}
                      step={f.step}
                      value={params[f.key]}
                      onChange={(e) => setParams((p) => ({ ...p, [f.key]: e.target.value }))}
                      className="w-full rounded-lg bg-black/50 border border-white/10 px-3 py-2 text-sm text-white font-mono"
                    />
                  )}
                </label>
              ))}
            </div>
            <button
              type="button"
              onClick={handleRun}
              disabled={running || !selectedClientId || !target.trim()}
              className="w-full py-3 rounded-xl font-mono text-sm uppercase tracking-widest border transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              style={{
                borderColor: running ? 'rgba(167,139,250,0.5)' : 'rgba(139,92,246,0.6)',
                background: running ? 'rgba(139,92,246,0.15)' : 'rgba(139,92,246,0.25)',
                color: '#e9d5ff',
                boxShadow: running ? 'none' : '0 0 24px rgba(139,92,246,0.2)',
              }}
            >
              {running ? t('nexusSwarm.deploying', 'Deploying Swarm…') : t('nexusSwarm.deploy', 'Deploy Sovereign Swarm')}
            </button>
          </div>

          {/* Terminal + findings */}
          <div className="space-y-4">
            <div className="rounded-2xl border border-white/10 bg-black/60 overflow-hidden">
              <div className="px-4 py-2 border-b border-white/5 text-[10px] font-mono text-white/40 uppercase tracking-widest">
                Swarm Telemetry
              </div>
              <pre className="h-48 overflow-auto p-3 text-[10px] font-mono text-emerald-400/80 leading-relaxed">
                {lines.length ? lines.join('\n') : t('nexusSwarm.awaiting', 'Awaiting deployment…')}
              </pre>
            </div>
            <AnimatePresence>
              {findings.length > 0 && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="rounded-2xl border border-white/10 bg-black/40 p-4 max-h-64 overflow-auto space-y-2"
                >
                  <p className="text-[10px] font-mono text-white/40 uppercase">{findings.length} Findings</p>
                  {findings.slice(0, 12).map((f, i) => (
                    <div key={i} className="text-[11px] border-b border-white/5 pb-2 last:border-0">
                      <span className={`font-mono mr-2 ${f.severity === 'critical' ? 'text-red-400' : f.severity === 'high' ? 'text-orange-400' : 'text-cyan-400'}`}>
                        [{f.severity || 'info'}]
                      </span>
                      <span className="text-white/70">{f.title}</span>
                    </div>
                  ))}
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </PageShell>
  )
}
