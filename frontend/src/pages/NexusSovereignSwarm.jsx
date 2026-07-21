import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../utils/apiFetch'
import { apiUrl } from '../lib/apiBase'
import { openSseStream } from '../lib/sseStream'
import { ENGINES_BY_ID } from '../lib/enginesRegistry'
import { useVisiblePolling } from '../hooks/useVisiblePolling'
import { promptDialog } from '../utils/confirmDialog'
import Button from '../components/ui/Button'

const ENGINE_ID = 'nexus_sovereign_swarm'

const ARCHETYPES = [
  { id: 'scout', label: 'Scout', color: '#22d3ee', icon: '🔭', desc: 'Technology fingerprinting & surface mapping' },
  { id: 'exploiter', label: 'Exploiter', color: '#ef4444', icon: '⚔️', desc: 'Sensitive endpoint & exposure vector probing' },
  { id: 'correlator', label: 'Correlator', color: '#a855f7', icon: '🧠', desc: 'Cross-agent hive-mind consensus synthesis' },
  { id: 'stealth', label: 'Stealth', color: '#64748b', icon: '👻', desc: 'Low-profile intel harvesting (robots, sitemap)' },
  { id: 'oracle', label: 'Oracle', color: '#f59e0b', icon: '🔮', desc: 'LLM strategic synthesis & next-engine routing' },
]
const ARCHETYPE_IDS = ARCHETYPES.map((a) => a.id)

const HTTP_METHODS = ['GET', 'HEAD', 'OPTIONS']
const HIVE_MODES = ['emergent', 'parallel', 'stealth', 'blitz']
const STRATEGIES = ['adaptive', 'aggressive', 'stealth', 'oracle']
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']

/** Every backend SwarmConfig key the GUI must expose (parity contract). */
const NSSI_GUI_PARAM_KEYS = [
  'agent_count', 'max_surface_points', 'max_concurrency', 'hive_mode', 'llm_strategy', 'archetypes',
  'dry_run', 'adaptive', 'waves', 'single_wave', 'seed', 'max_rps', 'waf_detection', 'link_extraction',
  'attack_chains', 'auth_perimeter', 'body_analysis', 'body_max_bytes', 'body_surface_detection',
  'tls_cert_audit', 'cookie_audit', 'priority_scoring', 'rate_limit_detection', 'emit_live_telemetry',
  'progress_emit_interval', 'engine_recommendations', 'timeout_ms', 'connect_timeout_ms', 'follow_redirects',
  'max_redirects', 'verify_tls', 'user_agent', 'request_jitter_ms', 'extra_headers', 'wordlist_depth',
  'subdomain_depth', 'include_discovered_paths', 'sensitive_paths', 'stealth_paths', 'scout_method',
  'exploiter_method', 'convergence_threshold', 'consensus_min_agents', 'consensus_min_archetypes',
  'oracle_model', 'oracle_temperature', 'oracle_max_tokens', 'llm_base_url', 'endpoint_bridge',
  'edge_distribution', 'min_severity', 'emit_passive_signals', 'dedupe_findings', 'tags',
]

// Full, lossless default surface — mirrors every knob the backend SwarmConfig reads.
const DEFAULT_PARAMS = {
  // Deployment
  agent_count: '2048',
  max_surface_points: '2048',
  max_concurrency: '128',
  hive_mode: 'emergent',
  llm_strategy: 'adaptive',
  archetypes: [...ARCHETYPE_IDS],
  dry_run: false,
  // Adaptive intelligence
  adaptive: true,
  waves: '2',
  seed: '0',
  max_rps: '0',
  waf_detection: true,
  link_extraction: true,
  attack_chains: true,
  auth_perimeter: true,
  body_analysis: true,
  body_max_bytes: '65536',
  engine_recommendations: true,
  cookie_audit: true,
  priority_scoring: true,
  rate_limit_detection: true,
  emit_live_telemetry: true,
  tls_cert_audit: true,
  body_surface_detection: true,
  progress_emit_interval: '64',
  single_wave: '',
  // Transport / HTTP
  timeout_ms: '12000',
  connect_timeout_ms: '6000',
  follow_redirects: true,
  max_redirects: '3',
  verify_tls: true,
  user_agent: '',
  request_jitter_ms: '0',
  extra_headers: [{ name: '', value: '' }],
  // Surface mapping
  wordlist_depth: '120',
  subdomain_depth: '80',
  include_discovered_paths: true,
  sensitive_paths: '',
  stealth_paths: '',
  scout_method: 'GET',
  exploiter_method: 'GET',
  // Consensus & Oracle
  convergence_threshold: '0.85',
  consensus_min_agents: '2',
  consensus_min_archetypes: '2',
  oracle_model: '',
  oracle_temperature: '0.2',
  oracle_max_tokens: '256',
  // Bridge / Edge
  endpoint_bridge: true,
  edge_distribution: true,
  // Output
  min_severity: 'info',
  emit_passive_signals: true,
  dedupe_findings: false,
  tags: '',
  // Oracle LLM endpoint override
  llm_base_url: '',
}

const splitLines = (s) => String(s || '').split('\n').map((x) => x.trim()).filter(Boolean)
const splitCsv = (s) => String(s || '').split(',').map((x) => x.trim()).filter(Boolean)
const numOr = (v, d) => {
  const n = Number(v)
  return Number.isFinite(n) ? n : d
}

/** Build the exact `POST /api/command-center/scan` body from the control column state. */
function buildScanBody(params, clientId, target) {
  const body = {
    engine: ENGINE_ID,
    client_id: Number(clientId),
    target: (target || '').trim(),
    timeout: 300,
    // Deployment
    agent_count: numOr(params.agent_count, 2048),
    max_surface_points: numOr(params.max_surface_points, 2048),
    max_concurrency: numOr(params.max_concurrency, 128),
    hive_mode: params.hive_mode,
    llm_strategy: params.llm_strategy,
    archetypes: params.archetypes.join(','),
    dry_run: !!params.dry_run,
    // Adaptive intelligence
    adaptive: !!params.adaptive,
    waves: numOr(params.waves, 2),
    seed: numOr(params.seed, 0),
    max_rps: numOr(params.max_rps, 0),
    waf_detection: !!params.waf_detection,
    link_extraction: !!params.link_extraction,
    attack_chains: !!params.attack_chains,
    auth_perimeter: !!params.auth_perimeter,
    body_analysis: !!params.body_analysis,
    body_max_bytes: numOr(params.body_max_bytes, 65536),
    engine_recommendations: !!params.engine_recommendations,
    cookie_audit: !!params.cookie_audit,
    priority_scoring: !!params.priority_scoring,
    rate_limit_detection: !!params.rate_limit_detection,
    emit_live_telemetry: !!params.emit_live_telemetry,
    tls_cert_audit: !!params.tls_cert_audit,
    body_surface_detection: !!params.body_surface_detection,
    progress_emit_interval: numOr(params.progress_emit_interval, 64),
    // Transport
    timeout_ms: numOr(params.timeout_ms, 12000),
    connect_timeout_ms: numOr(params.connect_timeout_ms, 6000),
    follow_redirects: !!params.follow_redirects,
    max_redirects: numOr(params.max_redirects, 3),
    verify_tls: !!params.verify_tls,
    request_jitter_ms: numOr(params.request_jitter_ms, 0),
    // Surface mapping
    wordlist_depth: numOr(params.wordlist_depth, 120),
    subdomain_depth: numOr(params.subdomain_depth, 80),
    include_discovered_paths: !!params.include_discovered_paths,
    scout_method: params.scout_method,
    exploiter_method: params.exploiter_method,
    // Consensus & Oracle
    convergence_threshold: numOr(params.convergence_threshold, 0.85),
    consensus_min_agents: numOr(params.consensus_min_agents, 2),
    consensus_min_archetypes: numOr(params.consensus_min_archetypes, 2),
    oracle_temperature: numOr(params.oracle_temperature, 0.2),
    oracle_max_tokens: numOr(params.oracle_max_tokens, 256),
    // Bridge / Edge
    endpoint_bridge: !!params.endpoint_bridge,
    edge_distribution: !!params.edge_distribution,
    // Output
    min_severity: params.min_severity,
    emit_passive_signals: !!params.emit_passive_signals,
    dedupe_findings: !!params.dedupe_findings,
  }
  if (params.user_agent.trim()) body.user_agent = params.user_agent.trim()
  if (params.oracle_model.trim()) body.oracle_model = params.oracle_model.trim()
  if (params.llm_base_url.trim()) body.llm_base_url = params.llm_base_url.trim()
  const sp = splitLines(params.sensitive_paths)
  if (sp.length) body.sensitive_paths = sp
  const stp = splitLines(params.stealth_paths)
  if (stp.length) body.stealth_paths = stp
  const tags = splitCsv(params.tags)
  if (tags.length) body.tags = tags
  const sw = String(params.single_wave || '').trim()
  if (sw) body.single_wave = numOr(sw, 0)
  const hdrs = {}
  for (const h of params.extra_headers) {
    if (h.name.trim() && h.value.trim()) hdrs[h.name.trim()] = h.value.trim()
  }
  if (Object.keys(hdrs).length) body.extra_headers = hdrs
  return body
}

const PRESET_STORAGE_KEY = 'nssi-sovereign-custom-presets'

/** One-click mission profiles — every knob is real backend SwarmConfig field. */
const STRATEGY_HINTS = {
  adaptive: 'Balanced waves — refine hot surface each cycle',
  aggressive: 'Exploiter-heavy cycle, lower consensus bar, faster stagger',
  stealth: 'Stealth/scout bias, higher consensus bar, slower stagger',
  oracle: 'Extra scout sampling + LLM temperature boost for synthesis',
}

const MISSION_PRESETS = {
  enterprise_safe: {
    label: 'Enterprise Safe',
    icon: '🏢',
    desc: 'Low RPS, stealth hive, 2 waves, passive intel',
    patch: {
      agent_count: '512',
      hive_mode: 'stealth',
      llm_strategy: 'stealth',
      max_rps: '25',
      waves: '2',
      adaptive: true,
      request_jitter_ms: '120',
      emit_passive_signals: true,
      min_severity: 'low',
      cookie_audit: true,
      priority_scoring: true,
      rate_limit_detection: true,
    },
  },
  blitz_recon: {
    label: 'Blitz Recon',
    icon: '⚡',
    desc: 'Maximum parallelism, 4 waves, aggressive surface',
    patch: {
      agent_count: '4096',
      hive_mode: 'blitz',
      llm_strategy: 'aggressive',
      max_concurrency: '256',
      waves: '4',
      adaptive: true,
      max_rps: '0',
      link_extraction: true,
      body_analysis: true,
      attack_chains: true,
      priority_scoring: true,
    },
  },
  stealth_audit: {
    label: 'Stealth Audit',
    icon: '👻',
    desc: 'Stealth archetype bias, jitter, dedupe, info floor',
    patch: {
      agent_count: '1024',
      hive_mode: 'stealth',
      llm_strategy: 'stealth',
      request_jitter_ms: '250',
      max_rps: '15',
      waves: '2',
      dedupe_findings: true,
      min_severity: 'info',
      archetypes: ['scout', 'stealth', 'correlator', 'oracle'],
      cookie_audit: true,
      auth_perimeter: true,
    },
  },
  max_depth: {
    label: 'Maximum Depth',
    icon: '🔬',
    desc: 'Full surface, all intelligence layers, oracle on',
    patch: {
      agent_count: '8192',
      max_surface_points: '8192',
      waves: '4',
      adaptive: true,
      waf_detection: true,
      link_extraction: true,
      body_analysis: true,
      attack_chains: true,
      auth_perimeter: true,
      engine_recommendations: true,
      cookie_audit: true,
      priority_scoring: true,
      rate_limit_detection: true,
      body_max_bytes: '131072',
      archetypes: [...ARCHETYPE_IDS],
    },
  },
  red_team: {
    label: 'Red Team',
    icon: '🎯',
    desc: 'Exploiter-heavy, critical floor, edge bridge',
    patch: {
      agent_count: '2048',
      hive_mode: 'emergent',
      llm_strategy: 'aggressive',
      min_severity: 'medium',
      endpoint_bridge: true,
      edge_distribution: true,
      waves: '3',
      archetypes: ['scout', 'exploiter', 'stealth', 'correlator', 'oracle'],
      attack_chains: true,
      priority_scoring: true,
    },
  },
}

function loadCustomPresets() {
  try {
    const raw = localStorage.getItem(PRESET_STORAGE_KEY)
    return raw ? JSON.parse(raw) : {}
  } catch {
    return {}
  }
}

function saveCustomPreset(name, params) {
  const all = loadCustomPresets()
  all[name] = { label: name, icon: '💾', desc: 'Custom saved profile', patch: { ...params, extra_headers: params.extra_headers } }
  localStorage.setItem(PRESET_STORAGE_KEY, JSON.stringify(all))
  return all
}

// ─── Reusable control primitives ─────────────────────────────────────────────

function Section({ title, icon, accent = '#a855f7', count, defaultOpen = true, children }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] overflow-hidden" style={{ borderColor: `${accent}22` }}>
      <Button variant="unstyled"
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between px-3 py-2.5 hover:bg-[var(--row-hover-bg)] transition-colors"
      >
        <span className="flex items-center gap-2 text-[11px] font-mono uppercase tracking-[0.18em] font-semibold" style={{ color: accent }}>
          <span>{icon}</span>
          {title}
          {count != null && <span className="text-[var(--text-disabled)] normal-case tracking-normal">· {count}</span>}
        </span>
        <span className={`text-[var(--text-muted)] text-xs transition-transform ${open ? 'rotate-90' : ''}`}>▶</span>
      </Button>
      {open && <div className="px-3 pb-3 pt-1 space-y-3 border-t border-[var(--border-subtle)]">{children}</div>}
    </div>
  )
}

function Hint({ children }) {
  if (!children) return null
  return <span className="block text-[9px] font-mono text-[var(--text-disabled)] mt-0.5 leading-snug">{children}</span>
}

function Num({ label, value, onChange, min, max, step, hint }) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{label}</span>
      <input
        type="number"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-sm text-white font-mono focus:outline-none focus:border-violet-400/40"
      />
      <Hint>{hint}</Hint>
    </label>
  )
}

function Sel({ label, value, onChange, options, hint }) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-sm text-white focus:outline-none focus:border-violet-400/40"
      >
        {options.map((o) => (
          <option key={o} value={o}>{o}</option>
        ))}
      </select>
      <Hint>{hint}</Hint>
    </label>
  )
}

function Txt({ label, value, onChange, placeholder, hint }) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{label}</span>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-sm text-white font-mono placeholder-white/20 focus:outline-none focus:border-violet-400/40"
      />
      <Hint>{hint}</Hint>
    </label>
  )
}

function Area({ label, value, onChange, placeholder, rows = 3, hint }) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{label}</span>
      <textarea
        rows={rows}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-xs text-white font-mono placeholder-white/20 focus:outline-none focus:border-violet-400/40 resize-y"
      />
      <Hint>{hint}</Hint>
    </label>
  )
}

function Toggle({ label, value, onChange, hint }) {
  return (
    <div className="flex items-start justify-between gap-3 py-0.5">
      <div className="min-w-0">
        <span className="text-[11px] font-mono text-[var(--text-secondary)]">{label}</span>
        <Hint>{hint}</Hint>
      </div>
      <Button variant="unstyled"
        type="button"
        role="switch"
        aria-checked={value}
        onClick={() => onChange(!value)}
        className={`relative shrink-0 mt-0.5 w-9 h-5 rounded-full transition-all ${value ? 'bg-violet-500/40' : 'bg-[var(--scrim)] border border-[var(--border-default)]'}`}
      >
        <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all ${value ? 'left-[18px]' : 'left-0.5'}`} />
      </Button>
    </div>
  )
}

// ─── Visualization ───────────────────────────────────────────────────────────

function SwarmHiveCanvas({ agentCount, running }) {
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
  }, [agentCount, running])

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
        <span className="text-[9px] font-mono text-[var(--text-muted)] uppercase tracking-widest">SIQ</span>
      </div>
    </div>
  )
}

function MetricTile({ label, value, accent = '#a855f7' }) {
  return (
    <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] backdrop-blur-md p-4" style={{ boxShadow: `inset 0 1px 0 ${accent}20` }}>
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)] mb-1">{label}</p>
      <p className="text-2xl font-bold text-white">{value ?? '—'}</p>
    </div>
  )
}

const GRADE_COLOR = { A: '#34d399', B: '#a3e635', C: '#f59e0b', D: '#fb923c', E: '#f87171', F: '#ef4444' }

function GradeBadge({ grade }) {
  const g = (grade || '?').toUpperCase()
  const color = GRADE_COLOR[g] || '#94a3b8'
  return (
    <div
      className="flex flex-col items-center justify-center w-16 h-16 rounded-2xl border-2 font-bold"
      style={{ borderColor: color, color, background: `${color}12`, boxShadow: `0 0 18px ${color}30` }}
    >
      <span className="text-3xl leading-none">{g}</span>
      <span className="text-[7px] font-mono uppercase tracking-widest text-[var(--text-muted)] mt-0.5">grade</span>
    </div>
  )
}

function Chips({ items, color = '#22d3ee', empty }) {
  if (!items || items.length === 0) return <span className="text-[10px] font-mono text-[var(--text-disabled)]">{empty}</span>
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((it, i) => (
        <span
          key={`${it}-${i}`}
          className="text-[10px] font-mono px-2 py-0.5 rounded-md border"
          style={{ color, borderColor: `${color}40`, background: `${color}10` }}
        >
          {it}
        </span>
      ))}
    </div>
  )
}

function ThreatBar({ score = 0 }) {
  const pct = Math.min(100, Math.max(0, score))
  const color = pct >= 70 ? '#ef4444' : pct >= 40 ? '#f59e0b' : pct >= 15 ? '#eab308' : '#34d399'
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <span className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">Threat Surface</span>
        <span className="text-sm font-bold" style={{ color }}>{pct}/100</span>
      </div>
      <div className="h-2 rounded-full bg-[var(--row-hover-bg)] overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: color, boxShadow: `0 0 10px ${color}80` }} />
      </div>
    </div>
  )
}

function WaveTimeline({ waves }) {
  if (!Array.isArray(waves) || waves.length === 0) return null
  return (
    <div className="space-y-2">
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">Adaptive Wave Telemetry</p>
      <div className="flex items-stretch gap-2 overflow-x-auto pb-1">
        {waves.map((w) => (
          <div key={w.wave} className="shrink-0 rounded-lg border border-violet-500/20 bg-violet-950/20 px-3 py-2 min-w-[120px]">
            <div className="flex items-center gap-1.5 mb-1">
              <span className="w-1.5 h-1.5 rounded-full bg-violet-400" />
              <span className="text-[10px] font-mono text-violet-200">Wave {w.wave}</span>
            </div>
            <p className="text-[10px] font-mono text-[var(--text-tertiary)]">{(w.agents ?? 0).toLocaleString()} agents</p>
            <p className="text-[10px] font-mono text-[var(--text-muted)]">{w.surface_points ?? 0} surface · {w.signals ?? 0} signals</p>
            {(w.extracted_paths ?? 0) > 0 && (
              <p className="text-[10px] font-mono text-cyan-400/80">+{w.extracted_paths} live paths</p>
            )}
            {w.directive && (
              <p className="text-[9px] font-mono text-[var(--text-disabled)] mt-0.5 truncate">{w.directive}</p>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

function AttackChainsPanel({ chains, summary }) {
  const items = Array.isArray(chains) ? chains : summary?.evidence?.chains
  if (!items || items.length === 0) return null
  return (
    <div className="space-y-2">
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">Emergent Attack Chains</p>
      <div className="space-y-1.5">
        {items.map((c, i) => (
          <div key={i} className="rounded-lg border border-rose-500/25 bg-rose-950/20 px-3 py-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[10px] font-mono text-rose-200 truncate">{c.title || c.chain}</span>
              <span className={`text-[9px] font-mono uppercase shrink-0 ${c.severity === 'critical' ? 'text-red-400' : 'text-orange-400'}`}>{c.severity}</span>
            </div>
            {c.url && <p className="text-[9px] font-mono text-[var(--text-muted)] truncate mt-0.5">{c.url}</p>}
          </div>
        ))}
      </div>
    </div>
  )
}

function AuthPerimeterPanel({ perimeter }) {
  if (!perimeter) return null
  const open = perimeter.open || []
  const auth = perimeter.auth_required || []
  if (open.length + auth.length === 0) return null
  return (
    <div className="space-y-2">
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">Auth Perimeter</p>
      <div className="grid grid-cols-2 gap-2">
        <div className="rounded-lg border border-emerald-500/20 bg-emerald-950/15 p-2">
          <p className="text-[9px] font-mono text-emerald-300/70 mb-1">Open ({perimeter.open_count ?? open.length})</p>
          <Chips items={open.slice(0, 8)} color="#34d399" empty="—" />
        </div>
        <div className="rounded-lg border border-amber-500/20 bg-amber-950/15 p-2">
          <p className="text-[9px] font-mono text-amber-300/70 mb-1">Auth-gated ({perimeter.auth_required_count ?? auth.length})</p>
          <Chips items={auth.slice(0, 8)} color="#fbbf24" empty="—" />
        </div>
      </div>
    </div>
  )
}

function TlsIntelPanel({ tls }) {
  if (!tls) return null
  const days = tls.days_until_expiry ?? 0
  const color = tls.expired ? '#ef4444' : days < 30 ? '#f59e0b' : '#34d399'
  return (
    <div className="rounded-xl border border-emerald-500/20 bg-emerald-950/15 p-3 space-y-1.5">
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-emerald-300/70">TLS Certificate (live :443)</p>
      <p className="text-[10px] font-mono text-[var(--text-tertiary)] truncate">CN: {tls.subject || '—'}</p>
      <p className="text-[10px] font-mono text-[var(--text-tertiary)] truncate">Issuer: {tls.issuer || '—'}</p>
      <div className="flex gap-3 text-[10px] font-mono">
        <span style={{ color }}>{tls.expired ? 'EXPIRED' : `${days}d left`}</span>
        {tls.self_signed && <span className="text-amber-400">self-signed</span>}
        <span className="text-[var(--text-muted)]">{tls.public_key_bits ?? 0}-bit</span>
      </div>
    </div>
  )
}

function BodySurfacePanel({ surface }) {
  if (!surface?.markers?.length) return null
  return (
    <div className="space-y-1.5">
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">Body Surface Markers</p>
      <Chips items={surface.markers} color="#38bdf8" empty="—" />
    </div>
  )
}

function ConfigCompletenessBadge({ parity, completeness }) {
  if (!parity && !completeness) return null
  const verified = parity?.verified && completeness?.world_class_verified
  return (
    <span
      className={`text-[10px] font-mono px-2 py-0.5 rounded-full border uppercase tracking-widest ${
        verified
          ? 'border-emerald-400/40 text-emerald-300 bg-emerald-500/10'
          : 'border-amber-400/40 text-amber-300 bg-amber-500/10'
      }`}
      title={parity?.missing?.length ? `Missing: ${parity.missing.join(', ')}` : undefined}
    >
      {verified
        ? `✓ ${parity.matched}/${parity.expected} parity · world-class`
        : `⚠ ${parity?.matched ?? 0}/${parity?.expected ?? NSSI_GUI_PARAM_KEYS.length} parity`}
    </span>
  )
}

function ConfigSchemaPanel({ schema, onClose }) {
  if (!schema) return null
  return (
    // eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions -- modal backdrop; click closes overlay, not a control
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[var(--bg-3)]" onClick={onClose}>
      {/* eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions -- click only stops propagation so inner content does not close the modal */}
      <div className="max-w-2xl w-full max-h-[80vh] overflow-auto rounded-2xl border border-violet-500/30 bg-[var(--bg-0)] p-4" onClick={(e) => e.stopPropagation()}>
        <div className="flex justify-between items-center mb-3">
          <p className="text-sm font-bold text-white">NSSI Config Schema v{schema.version} · {schema.parameter_count} params</p>
          <Button variant="unstyled" type="button" aria-label="Close" onClick={onClose} className="text-[var(--text-muted)] hover:text-[var(--text-primary)]">✕</Button>
        </div>
        {schema.completeness && (
          <p className="text-[10px] font-mono text-emerald-400/80 mb-2">
            {schema.completeness.world_class_verified ? '✓ World-class matrix verified' : 'Completeness pending'}
          </p>
        )}
        <pre className="text-[10px] font-mono text-emerald-300/80 whitespace-pre-wrap">{JSON.stringify(schema.parameters, null, 2)}</pre>
      </div>
    </div>
  )
}

function SignalHeatmapPanel({ heatmap }) {
  const rows = Array.isArray(heatmap) ? heatmap : []
  if (!rows.length) return null
  const max = Math.max(...rows.map((r) => r.signals ?? 0), 1)
  return (
    <div className="space-y-2">
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">Signal Heatmap (path prefix)</p>
      <div className="space-y-1">
        {rows.slice(0, 12).map((r) => {
          const pct = Math.round(((r.signals ?? 0) / max) * 100)
          return (
            <div key={r.prefix} className="flex items-center gap-2">
              <span className="text-[9px] font-mono text-[var(--text-muted)] w-20 truncate shrink-0">/{r.prefix}</span>
              <div className="flex-1 h-1.5 rounded-full bg-[var(--row-hover-bg)] overflow-hidden">
                <div className="h-full rounded-full bg-violet-500/70" style={{ width: `${pct}%` }} />
              </div>
              <span className="text-[9px] font-mono text-violet-300/80 w-6 text-right">{r.signals}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function LiveWaveProgress({ events, running }) {
  if (!events?.length && !running) return null
  const latest = events[events.length - 1]
  const dryRun = events.some((e) => e.event?.startsWith('dry_run'))
  const completed = events.filter((e) => e.event === 'wave_complete').length
  const active = latest?.event === 'wave_start' ? latest.detail?.wave : completed
  const total = latest?.detail?.total_waves ?? events.find((e) => e.detail?.total_waves)?.detail?.total_waves ?? (dryRun ? 1 : '?')
  const progress = events.filter((e) => e.event === 'wave_progress').pop()
  return (
    <div className="rounded-xl border border-violet-500/25 bg-violet-950/20 p-3 space-y-2">
      <div className="flex items-center justify-between">
        <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-violet-300/70">
          {dryRun ? 'Dry-Run Telemetry' : 'Live Wave Telemetry'}
        </p>
        {running && <span className="w-1.5 h-1.5 rounded-full bg-violet-400 animate-pulse" />}
      </div>
      {!dryRun && (
        <p className="text-xs font-mono text-[var(--text-tertiary)]">
          Wave {active ?? '—'} / {total}
          {progress?.detail && (
            <span className="text-cyan-400/80"> · {progress.detail.completed}/{progress.detail.total} agents</span>
          )}
          {events.filter((e) => e.event === 'wave_complete').pop()?.detail?.partial_siq != null && (
            <span className="text-amber-400/80"> · SIQ {events.filter((e) => e.event === 'wave_complete').pop().detail.partial_siq}</span>
          )}
        </p>
      )}
      <div className="max-h-24 overflow-auto space-y-0.5">
        {events.slice(-8).map((e, i) => (
          <p key={`${e.ts}-${i}`} className="text-[9px] font-mono text-[var(--text-muted)] truncate">
            [{e.event}] {e.detail?.wave != null ? `W${e.detail.wave}` : ''}{' '}
            {e.detail?.signals != null ? `${e.detail.signals} sig` : ''}{' '}
            {e.detail?.requests_total != null ? `${e.detail.requests_total} req` : ''}
          </p>
        ))}
      </div>
    </div>
  )
}

function EngineRecsPanel({ recs, onLaunch, launching }) {
  if (!Array.isArray(recs) || recs.length === 0) return null
  return (
    <div className="space-y-2">
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">Next-Engine Routing</p>
      <div className="space-y-1.5">
        {recs.slice(0, 8).map((r) => (
          <div
            key={r.engine_id}
            className="flex items-center gap-2 rounded-lg border border-cyan-500/20 bg-cyan-950/15 px-3 py-2"
          >
            <Link
              to={`/engines/${r.engine_id}`}
              className="flex-1 min-w-0 hover:text-cyan-100 transition-colors"
            >
              <span className="text-[10px] font-mono text-cyan-200 block truncate">{r.engine_id}</span>
              {r.reason && <span className="text-[9px] font-mono text-[var(--text-muted)] block truncate">{r.reason}</span>}
            </Link>
            <span className="text-[9px] font-mono text-[var(--text-muted)] shrink-0">P{r.priority}</span>
            {onLaunch && (
              <Button variant="unstyled"
                type="button"
                disabled={launching === r.engine_id}
                onClick={() => onLaunch(r.engine_id)}
                className="text-[9px] font-mono uppercase px-2 py-1 rounded border border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-40 shrink-0"
              >
                {launching === r.engine_id ? '…' : 'Launch'}
              </Button>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

function StatusHistogramPanel({ histogram }) {
  const rows = Array.isArray(histogram) ? histogram : []
  if (!rows.length) return null
  const max = Math.max(...rows.map((r) => r.count ?? 0), 1)
  return (
    <div className="space-y-2">
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">HTTP Status Histogram (live)</p>
      <div className="space-y-1">
        {rows.slice(0, 10).map((r) => {
          const status = String(r.status ?? '')
          const pct = Math.round(((r.count ?? 0) / max) * 100)
          const color = status === '200' ? '#34d399' : status.startsWith('4') ? '#f59e0b' : status.startsWith('5') ? '#ef4444' : '#94a3b8'
          return (
            <div key={status} className="flex items-center gap-2">
              <span className="text-[9px] font-mono w-8 text-right shrink-0" style={{ color }}>{status}</span>
              <div className="flex-1 h-1.5 rounded-full bg-[var(--row-hover-bg)] overflow-hidden">
                <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: color, opacity: 0.7 }} />
              </div>
              <span className="text-[9px] font-mono text-[var(--text-muted)] w-8 text-right">{r.count}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function SurfaceLineagePanel({ lineage }) {
  if (!lineage || typeof lineage !== 'object') return null
  const rows = Object.entries(lineage).filter(([k]) => k !== 'total_unique')
  if (!rows.length) return null
  return (
    <div className="space-y-1.5">
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">
        Surface Lineage ({lineage.total_unique ?? '—'} unique points)
      </p>
      <div className="flex flex-wrap gap-1.5">
        {rows.map(([k, v]) => (
          <span key={k} className="text-[9px] font-mono px-2 py-0.5 rounded-md border border-[var(--border-default)] text-[var(--text-tertiary)]">
            {k}: <span className="text-cyan-300/80">{v}</span>
          </span>
        ))}
      </div>
    </div>
  )
}

function DeploymentFingerprintPanel({ fp }) {
  if (!fp) return null
  return (
    <div className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] px-3 py-2">
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)] mb-1">Deployment Fingerprint (SHA-256)</p>
      <p className="text-[10px] font-mono text-emerald-300/70 break-all select-all">{fp}</p>
    </div>
  )
}

function ConsensusFindingsPanel({ findings }) {
  const items = (findings || []).filter((f) => f.signal_type === 'hive_consensus' || f.signal_type === 'attack_chain')
  if (!items.length) return null
  return (
    <div className="space-y-2">
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">Hive Emergent Findings</p>
      <div className="space-y-1 max-h-32 overflow-auto">
        {items.slice(0, 8).map((f, i) => (
          <div key={i} className="rounded-lg border border-purple-500/20 bg-purple-950/15 px-2 py-1.5">
            <div className="flex justify-between gap-2">
              <span className="text-[9px] font-mono text-purple-200 truncate">{f.title}</span>
              <span className="text-[8px] font-mono uppercase text-orange-300 shrink-0">{f.severity}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function ArchetypeDistributionPanel({ distribution }) {
  if (!distribution || typeof distribution !== 'object') return null
  const rows = Object.entries(distribution).sort((a, b) => (b[1] ?? 0) - (a[1] ?? 0))
  if (!rows.length) return null
  const max = Math.max(...rows.map(([, n]) => Number(n) || 0), 1)
  return (
    <div className="space-y-2">
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">Agent Archetype Distribution</p>
      <div className="space-y-1">
        {rows.map(([arch, count]) => {
          const meta = ARCHETYPES.find((a) => a.id === arch)
          const pct = Math.round(((Number(count) || 0) / max) * 100)
          return (
            <div key={arch} className="flex items-center gap-2">
              <span className="text-[9px] font-mono w-16 shrink-0" style={{ color: meta?.color || '#a855f7' }}>
                {meta?.icon} {arch}
              </span>
              <div className="flex-1 h-1.5 rounded-full bg-[var(--row-hover-bg)] overflow-hidden">
                <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: meta?.color || '#a855f7', opacity: 0.75 }} />
              </div>
              <span className="text-[9px] font-mono text-[var(--text-tertiary)] w-10 text-right">{Number(count).toLocaleString()}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function ConsensusEmergencePanel({ count, strategy }) {
  if (!count) return null
  return (
    <div className="rounded-lg border border-purple-500/25 bg-purple-950/20 px-3 py-2">
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-purple-300/70">Hive-Mind Consensus</p>
      <p className="text-xs font-mono text-[var(--text-tertiary)] mt-1">
        {count} emergent consensus finding{count === 1 ? '' : 's'}
        {strategy && <span className="text-[var(--text-muted)]"> · strategy: {strategy}</span>}
      </p>
    </div>
  )
}

function OraclePanel({ oracle }) {
  if (!oracle || typeof oracle !== 'object') return null
  const engines = oracle.recommended_next_engines || oracle.recommended_engines
  const source = oracle.source || 'llm_oracle'
  return (
    <div className="rounded-xl border border-amber-500/25 bg-amber-950/15 p-3 space-y-2">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-amber-300/70">Oracle Strategic Synthesis</p>
        <span className={`text-[8px] font-mono uppercase px-1.5 py-0.5 rounded border ${
          source === 'llm_oracle'
            ? 'border-amber-400/30 text-amber-300'
            : 'border-cyan-400/30 text-cyan-300'
        }`}>
          {source === 'llm_oracle' ? 'LLM' : 'telemetry'}
        </span>
      </div>
      {oracle.swarm_iq != null && (
        <p className="text-xs font-mono text-[var(--text-secondary)]">Oracle SIQ estimate: <span className="text-amber-300">{oracle.swarm_iq}</span>/100</p>
      )}
      {oracle.priority_vector && (
        <p className="text-[10px] font-mono text-[var(--text-tertiary)] leading-relaxed">{oracle.priority_vector}</p>
      )}
      {oracle.operator_brief && (
        <p className="text-[10px] font-mono text-[var(--text-tertiary)] leading-relaxed italic">{oracle.operator_brief}</p>
      )}
      {Array.isArray(engines) && engines.length > 0 && (
        <Chips items={engines.map(String)} color="#f59e0b" empty="—" />
      )}
    </div>
  )
}

function ApiSurfacePanel({ map }) {
  if (!map?.api_paths?.length) return null
  return (
    <div className="space-y-1.5">
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">
        API Surface ({map.total ?? map.api_paths.length} paths)
      </p>
      <Chips items={map.api_paths.slice(0, 16)} color="#38bdf8" empty="—" />
    </div>
  )
}

function CookieIntelPanel({ intel }) {
  if (!intel?.issue_counts || !Object.keys(intel.issue_counts).length) return null
  const items = Object.entries(intel.issue_counts).map(([k, v]) => `${k} ×${v}`)
  return (
    <div className="space-y-1.5">
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">Cookie Security Audit</p>
      <Chips items={items} color="#fb923c" empty="—" />
    </div>
  )
}

function FindingRow({ finding }) {
  const [open, setOpen] = useState(false)
  const f = finding
  const evidence = f.evidence || f.swarm_metrics
  return (
    <div className="text-[11px] border-b border-[var(--border-subtle)] pb-2 last:border-0">
      <Button variant="unstyled" type="button" onClick={() => setOpen((o) => !o)} className="w-full text-left">
        <div className="flex items-start gap-2">
          <span className={`font-mono shrink-0 ${f.severity === 'critical' ? 'text-red-400' : f.severity === 'high' ? 'text-orange-400' : f.severity === 'medium' ? 'text-amber-400' : 'text-cyan-400'}`}>
            [{f.severity || 'info'}]
          </span>
          <span className="text-[var(--text-secondary)] min-w-0 flex-1">{f.title}</span>
          {evidence && <span className="text-[9px] font-mono text-[var(--text-disabled)] shrink-0">{open ? '▼' : '▶'}</span>}
        </div>
        {f.signal_type && <span className="block text-[9px] font-mono text-violet-400/60 ml-1 mt-0.5">{f.signal_type}</span>}
        {f.url && <span className="block text-[10px] font-mono text-[var(--text-disabled)] truncate ml-1 mt-0.5">{f.url}</span>}
      </Button>
      {open && evidence && (
        <pre className="mt-1.5 ml-1 max-h-40 overflow-auto rounded bg-[var(--bg-3)] border border-[var(--border-default)] p-2 text-[9px] font-mono text-emerald-300/70">
          {JSON.stringify(evidence, null, 2)}
        </pre>
      )}
    </div>
  )
}

function MissionPresetsBar({ onApply, onSave, onExport, onImport, onWaveReplay, customPresets, onShowSchema }) {
  return (
    <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-2.5 space-y-2">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">Mission Presets</p>
        <div className="flex gap-1 flex-wrap justify-end">
          <Button variant="unstyled" type="button" onClick={onShowSchema} className="text-[9px] font-mono px-2 py-0.5 rounded border border-violet-500/30 text-violet-300">Schema</Button>
          <Button variant="unstyled" type="button" onClick={onSave} className="text-[9px] font-mono px-2 py-0.5 rounded border border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-secondary)]">Save</Button>
          <Button variant="unstyled" type="button" onClick={onExport} className="text-[9px] font-mono px-2 py-0.5 rounded border border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-secondary)]">Export</Button>
          <Button variant="unstyled" type="button" onClick={onImport} className="text-[9px] font-mono px-2 py-0.5 rounded border border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-secondary)]">Import</Button>
        </div>
      </div>
      <div className="flex gap-1 flex-wrap">
        {[1, 2, 3, 4].map((n) => (
          <Button variant="unstyled" key={n} type="button" onClick={() => onWaveReplay(n)} className="text-[9px] font-mono px-2 py-1 rounded border border-cyan-500/25 text-cyan-300/80 hover:bg-cyan-500/10">
            Wave {n} only
          </Button>
        ))}
      </div>
      <div className="grid grid-cols-1 gap-1">
        {Object.entries(MISSION_PRESETS).map(([id, p]) => (
          <Button variant="unstyled"
            key={id}
            type="button"
            onClick={() => onApply(p.patch)}
            className="flex items-center gap-2 text-left rounded-lg border border-[var(--border-default)] px-2.5 py-2 hover:border-violet-400/30 hover:bg-violet-500/5 transition-colors"
          >
            <span>{p.icon}</span>
            <span className="min-w-0 flex-1">
              <span className="text-[11px] font-semibold text-white block">{p.label}</span>
              <span className="text-[9px] text-[var(--text-muted)] block truncate">{p.desc}</span>
            </span>
          </Button>
        ))}
      </div>
      {Object.keys(customPresets || {}).length > 0 && (
        <div className="space-y-1 pt-1 border-t border-[var(--border-subtle)]">
          <p className="text-[9px] font-mono text-[var(--text-disabled)] uppercase">Saved</p>
          {Object.entries(customPresets).map(([id, p]) => (
            <Button variant="unstyled" key={id} type="button" onClick={() => onApply(p.patch)} className="w-full text-left text-[10px] font-mono px-2 py-1 rounded border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]">
              💾 {p.label || id}
            </Button>
          ))}
        </div>
      )}
    </div>
  )
}

function ExposureVelocityPanel({ velocity }) {
  if (!velocity) return null
  return (
    <div className="grid grid-cols-3 gap-2">
      <div className="rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] px-2 py-1.5 text-center">
        <p className="text-[9px] font-mono text-[var(--text-muted)]">Elapsed</p>
        <p className="text-xs font-mono text-[var(--text-secondary)]">{velocity.elapsed_ms ?? 0}ms</p>
      </div>
      <div className="rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] px-2 py-1.5 text-center">
        <p className="text-[9px] font-mono text-[var(--text-muted)]">RPS</p>
        <p className="text-xs font-mono text-[var(--text-secondary)]">{velocity.requests_per_second ?? 0}</p>
      </div>
      <div className="rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] px-2 py-1.5 text-center">
        <p className="text-[9px] font-mono text-[var(--text-muted)]">TTFC</p>
        <p className="text-xs font-mono text-[var(--text-secondary)]">{velocity.time_to_first_critical_ms != null ? `${velocity.time_to_first_critical_ms}ms` : '—'}</p>
      </div>
    </div>
  )
}

function IntelligencePanel({ metrics, findings, oracle, onLaunchEngine, launchingEngine, liveEvents, running }) {
  const intel = metrics?.intelligence
  if (!metrics) return null
  const grade = intel?.security_grade?.grade
  const waf = intel?.waf_cdn
  const tech = intel?.technology_profile || {}
  const mitre = Array.isArray(intel?.mitre_coverage) ? intel.mitre_coverage : []
  const stack = [...(tech.servers || []), ...(tech.frameworks || [])]
  const chainSummary = findings?.find((f) => f.signal_type === 'attack_chain_summary')
  return (
    <div className="rounded-2xl border border-[var(--border-default)] bg-gradient-to-br from-indigo-950/30 to-black/50 p-5 space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">Hive Intelligence Synthesis</p>
        {waf && (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-md border border-amber-400/30 text-amber-300 bg-amber-500/10">
            WAF/CDN: {waf.vendor}
          </span>
        )}
      </div>
      <div className="flex items-center gap-5">
        {grade && <GradeBadge grade={grade} />}
        <div className="flex-1 min-w-0">
          <ThreatBar score={metrics?.threat_surface_score ?? intel?.threat_surface_score ?? 0} />
          {metrics?.severity_tally && (
            <div className="flex gap-3 mt-2 text-[10px] font-mono">
              <span className="text-red-400">{metrics.severity_tally.critical ?? 0} crit</span>
              <span className="text-orange-400">{metrics.severity_tally.high ?? 0} high</span>
              <span className="text-amber-400">{metrics.severity_tally.medium ?? 0} med</span>
            </div>
          )}
        </div>
      </div>
      <div className="space-y-1.5">
        <span className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">Technology Stack</span>
        <Chips items={stack} color="#22d3ee" empty="no stack fingerprinted" />
      </div>
      {mitre.length > 0 && (
        <div className="space-y-1.5">
          <span className="text-[9px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">MITRE ATT&CK Coverage</span>
          <Chips items={mitre.map((m) => `${m.technique} ×${m.count}`)} color="#f43f5e" empty="—" />
        </div>
      )}
      <ExposureVelocityPanel velocity={intel?.exposure_velocity} />
      <DeploymentFingerprintPanel fp={metrics?.deployment_fingerprint} />
      <SurfaceLineagePanel lineage={metrics?.surface_lineage} />
      <LiveWaveProgress events={liveEvents} running={running} />
      <ArchetypeDistributionPanel distribution={metrics?.archetype_distribution} />
      <ConsensusEmergencePanel count={intel?.consensus_emergence ?? metrics?.consensus_findings} strategy={intel?.strategy_resolved} />
      <StatusHistogramPanel histogram={intel?.http_status_histogram} />
      <ConsensusFindingsPanel findings={findings} />
      <TlsIntelPanel tls={intel?.tls_certificate} />
      <BodySurfacePanel surface={intel?.body_surface_markers} />
      <SignalHeatmapPanel heatmap={intel?.signal_heatmap} />
      <OraclePanel oracle={oracle} />
      <ApiSurfacePanel map={intel?.api_surface_map} />
      <CookieIntelPanel intel={intel?.cookie_security} />
      {intel?.rate_limit_intel?.likely_rate_limited && (
        <div className="rounded-lg border border-orange-500/30 bg-orange-950/20 px-3 py-2 text-[10px] font-mono text-orange-200">
          Rate-limit storm: {intel.rate_limit_intel.http_429_count ?? 0}×429 · {intel.rate_limit_intel.http_403_count ?? 0}×403
        </div>
      )}
      <AttackChainsPanel chains={intel?.attack_chain_details} summary={chainSummary} />
      <AuthPerimeterPanel perimeter={intel?.auth_perimeter} />
      <EngineRecsPanel recs={intel?.engine_recommendations} onLaunch={onLaunchEngine} launching={launchingEngine} />
      <WaveTimeline waves={metrics?.wave_breakdown} />
    </div>
  )
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function NexusSovereignSwarm() {
  const { t } = useTranslation()
  const engine = ENGINES_BY_ID[ENGINE_ID]
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState('')
  const { postScan } = useCommandCenterScan(selectedClientId)
  const [target, setTarget] = useState('')
  const [params, setParams] = useState(DEFAULT_PARAMS)
  useSyncHubScanParams(ENGINE_ID, params)
  const [running, setRunning] = useState(false)
  const [lines, setLines] = useState([])
  const [metrics, setMetrics] = useState(null)
  const [findings, setFindings] = useState([])
  const [endpointAgents, setEndpointAgents] = useState([])
  const [fleetBusy, setFleetBusy] = useState(false)
  const [swarmWsLive, setSwarmWsLive] = useState(false)
  const [showPreview, setShowPreview] = useState(false)
  const [oracleSynth, setOracleSynth] = useState(null)
  const [launchingEngine, setLaunchingEngine] = useState(null)
  const [liveEvents, setLiveEvents] = useState([])
  const [lastEventId, setLastEventId] = useState(0)
  const [customPresets, setCustomPresets] = useState(() => loadCustomPresets())
  const [configSchema, setConfigSchema] = useState(null)
  const [schemaParity, setSchemaParity] = useState(null)
  const [completeness, setCompleteness] = useState(null)
  const importRef = useRef(null)
  const esRef = useRef(null)
  const wsRef = useRef(null)

  const setField = useCallback((key, val) => setParams((p) => ({ ...p, [key]: val })), [])

  const toggleArchetype = useCallback((id) => {
    setParams((p) => {
      const has = p.archetypes.includes(id)
      const next = has ? p.archetypes.filter((a) => a !== id) : [...p.archetypes, id]
      return { ...p, archetypes: next }
    })
  }, [])

  const setHeader = useCallback((i, field, val) => {
    setParams((p) => ({ ...p, extra_headers: p.extra_headers.map((h, idx) => (idx === i ? { ...h, [field]: val } : h)) }))
  }, [])
  const addHeader = useCallback(() => setParams((p) => ({ ...p, extra_headers: [...p.extra_headers, { name: '', value: '' }] })), [])
  const removeHeader = useCallback((i) => {
    setParams((p) => {
      const next = p.extra_headers.filter((_, idx) => idx !== i)
      return { ...p, extra_headers: next.length ? next : [{ name: '', value: '' }] }
    })
  }, [])

  const resetParams = useCallback(() => setParams({ ...DEFAULT_PARAMS, archetypes: [...ARCHETYPE_IDS], extra_headers: [{ name: '', value: '' }] }), [])

  const fleetForClient = useMemo(
    () => endpointAgents.filter((a) => String(a.client_id) === String(selectedClientId)),
    [endpointAgents, selectedClientId],
  )
  const fleetOnline = useMemo(
    () => fleetForClient.filter((a) => a.status === 'online' || a.live).length,
    [fleetForClient],
  )

  const previewBody = useMemo(
    () => buildScanBody(params, selectedClientId || 0, target),
    [params, selectedClientId, target],
  )
  const paramCount = useMemo(() => Object.keys(previewBody).length, [previewBody])
  const realFindings = useMemo(
    () => findings.filter((f) => !f.swarm_metrics && f.signal_type !== 'attack_chain_summary'),
    [findings],
  )

  const {
    filteredFindings,
    counts,
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    exportCsv,
    refreshFromHistory,
    historyLoading,
    lastUpdated,
    lastJobId,
    setLastUpdated,
    setLastJobId,
  } = useWeissmanEnginePage(ENGINE_ID, realFindings)

  useEffect(() => {
    refreshFromHistory().then((run) => {
      if (run?.findings?.length) {
        applyHistoryFindings(run, setFindings, { setLastUpdated, setJobId: setLastJobId })
        const summary = run.findings.find((x) => x.swarm_metrics)
        const meta = summary?.swarm_metrics
        if (meta) setMetrics(meta)
        if (summary?.oracle_synthesis) setOracleSynth(summary.oracle_synthesis)
      }
    })
  }, [refreshFromHistory, setLastUpdated, setLastJobId])

  const handleRefresh = useCallback(async () => {
    const run = await refreshFromHistory()
    if (applyHistoryFindings(run, setFindings, { setLastUpdated, setJobId: setLastJobId })) {
      const summary = run.findings.find((x) => x.swarm_metrics)
      const meta = summary?.swarm_metrics
      if (meta) setMetrics(meta)
      if (summary?.oracle_synthesis) setOracleSynth(summary.oracle_synthesis)
    }
  }, [refreshFromHistory, setLastUpdated, setLastJobId])

  const loadAgents = useCallback(() => {
    apiFetch('/api/agents/status')
      .then((d) => { if (Array.isArray(d)) setEndpointAgents(d) })
      .catch((e) => { if (e?.status) setEndpointAgents([]) })
  }, [])

  useEffect(() => {
    loadAgents()
  }, [loadAgents])

  // Agent-roster refresh every 15s, skipping ticks while the tab is hidden.
  useVisiblePolling(loadAgents, 15000)

  const appendLine = useCallback((msg) => {
    setLines((prev) => [...prev.slice(-400), msg])
  }, [])

  const applyPreset = useCallback((patch) => {
    setParams((p) => ({
      ...p,
      ...patch,
      extra_headers: patch.extra_headers || p.extra_headers,
      archetypes: patch.archetypes ? [...patch.archetypes] : p.archetypes,
    }))
  }, [])

  const handleSavePreset = useCallback(async () => {
    const name = await promptDialog({
      title: t('nexusSwarm.save_preset_title'),
      label: t('nexusSwarm.save_preset_label'),
      placeholder: t('nexusSwarm.save_preset_label'),
      required: true,
    })
    if (!name?.trim()) return
    const all = saveCustomPreset(name.trim(), params)
    setCustomPresets(all)
    appendLine(`[NSSI] Saved preset "${name.trim()}"`)
  }, [params, appendLine, t])

  const handleWaveReplay = useCallback((waveNum) => {
    applyPreset({ single_wave: String(waveNum), adaptive: true, emit_live_telemetry: true })
    appendLine(`[NSSI] Configured single-wave replay: wave ${waveNum}`)
  }, [applyPreset, appendLine])

  useEffect(() => {
    apiFetch('/api/engines/nexus_sovereign_swarm/schema')
      .then((d) => {
        if (!d?.parameters) return
        const backendKeys = new Set(d.parameters.map((p) => p.key))
        const missing = NSSI_GUI_PARAM_KEYS.filter((k) => !backendKeys.has(k))
        const matched = NSSI_GUI_PARAM_KEYS.length - missing.length
        setSchemaParity({
          verified: missing.length === 0 && matched === d.parameter_count,
          matched,
          expected: NSSI_GUI_PARAM_KEYS.length,
          missing,
          backendCount: d.parameter_count ?? backendKeys.size,
        })
        if (d.completeness) setCompleteness(d.completeness)
      })
      // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
      .catch(() => {})
  }, [])

  const handleShowSchema = useCallback(() => {
    apiFetch('/api/engines/nexus_sovereign_swarm/schema')
      .then((d) => { if (d) setConfigSchema(d) })
      .catch(() => appendLine('[ERROR] Failed to load NSSI schema'))
  }, [appendLine])

  const handleExportConfig = useCallback(() => {
    const blob = new Blob([JSON.stringify({ params, target, exported_at: new Date().toISOString() }, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `nssi-config-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }, [params, target])

  const handleExportReport = useCallback(() => {
    if (!metrics && !findings.length) return
    const blob = new Blob([JSON.stringify({
      metrics,
      findings,
      oracle_synthesis: oracleSynth,
      deployment_fingerprint: metrics?.deployment_fingerprint,
      surface_lineage: metrics?.surface_lineage,
      exported_at: new Date().toISOString(),
    }, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `nssi-intelligence-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }, [metrics, findings, oracleSynth])

  const handleImportConfig = useCallback(() => {
    importRef.current?.click()
  }, [])

  const onImportFile = useCallback((e) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => {
      try {
        const data = JSON.parse(reader.result)
        if (data.params) setParams((p) => ({ ...p, ...data.params }))
        if (data.target) setTarget(data.target)
        appendLine('[NSSI] Configuration imported')
      } catch {
        appendLine('[ERROR] Invalid config JSON')
      }
    }
    reader.readAsText(file)
    e.target.value = ''
  }, [appendLine])

  const launchRecommendedEngine = useCallback(async (engineId) => {
    if (!selectedClientId || !target.trim()) return
    setLaunchingEngine(engineId)
    appendLine(`[NSSI] Launching follow-up engine: ${engineId}`)
    try {
      const { ok, data } = await postScan({
        engine: engineId,
        client_id: Number(selectedClientId),
        target: target.trim(),
        timeout: 300,
        source: 'nssi_engine_recommendation',
      })
      appendLine(ok ? `[NSSI] ${engineId} queued: ${data.job_id}` : `[ERROR] ${data.detail || 'launch failed'}`)
    } catch (e) {
      appendLine(`[ERROR] ${e.message}`)
    } finally {
      setLaunchingEngine(null)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedClientId, target, appendLine])

  const connectSwarmWs = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }
    const wsUrl = apiUrl('/ws/swarm').replace(/^http/, 'ws')
    try {
      const ws = new WebSocket(wsUrl)
      wsRef.current = ws
      ws.onopen = () => setSwarmWsLive(true)
      ws.onmessage = (ev) => {
        try {
          const p = JSON.parse(ev.data)
          if (p.source === 'nexus_sovereign_swarm' || p.agent === 'NSSI') {
            setLiveEvents((prev) => [...prev.slice(-48), { event: p.event, detail: p.detail, ts: p.ts }])
          }
          if (p.event) appendLine(`[${p.agent || 'Swarm'}] ${p.event}`)
        } catch { /* ignore */ }
      }
      ws.onclose = () => setSwarmWsLive(false)
      ws.onerror = () => setSwarmWsLive(false)
    } catch { /* ignore */ }
  }, [appendLine])

  const broadcastFleet = useCallback(async () => {
    if (!selectedClientId || !target.trim()) return
    setFleetBusy(true)
    appendLine('[NSSI] Broadcasting fleet to all endpoint agents…')
    try {
      const data = await apiFetch('/api/agents/dispatch', {
        method: 'POST',
        body: {
          client_id: Number(selectedClientId),
          engine: 'process_inventory',
          target: target.trim(),
          fleet_broadcast: true,
          params: { nssi_bridge: true, source: 'nexus_sovereign_swarm' },
        },
      })
      appendLine(`[NSSI] Fleet broadcast: ${data.live_dispatched ?? 0} live / ${data.engines_dispatched ?? 0} engines`)
      // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
      await apiFetch(`/api/clients/${selectedClientId}/swarm/run`, { method: 'POST' }).catch(() => {})
    } catch (e) {
      if (e?.status) {
        const b = e.response ? await e.response.json().catch(() => ({})) : {}
        appendLine(`[FLEET] ${b.detail || 'dispatch failed'}`)
      } else {
        appendLine(`[FLEET] ${e.message}`)
      }
    } finally {
      setFleetBusy(false)
      loadAgents()
    }
  }, [selectedClientId, target, appendLine, loadAgents])

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

  useEffect(() => {
    apiFetch('/api/clients')
      .then((d) => { if (Array.isArray(d)) setClients(d) })
      .catch((e) => { if (e?.status) setClients([]) })
  }, [])

  useEffect(() => () => {
    if (esRef.current) esRef.current.close()
    if (wsRef.current) wsRef.current.close()
  }, [])

  // Poll durable swarm_events when SSE/WS miss worker events (Redis fallback).
  useEffect(() => {
    if (!running || !selectedClientId || !params.emit_live_telemetry) return undefined
    const poll = () => {
      // Skip the 2.5s swarm-events poll while the tab is hidden (no background hammering).
      if (typeof document !== 'undefined' && document.hidden) return
      apiFetch(`/api/swarm/events?client_id=${selectedClientId}&since_id=${lastEventId}`)
        .then((d) => {
          if (!d?.events?.length) return
          setLiveEvents((prev) => {
            const merged = [...prev]
            for (const e of d.events) {
              if (!merged.some((x) => x.ts === e.ts && x.event === e.event)) {
                merged.push({ event: e.event, detail: e.detail, ts: e.ts, id: e.id })
              }
            }
            return merged.slice(-48)
          })
          const maxId = Math.max(...d.events.map((e) => e.id ?? 0))
          if (maxId > lastEventId) setLastEventId(maxId)
        })
        // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
        .catch(() => {})
    }
    poll()
    const id = setInterval(poll, 2500)
    return () => clearInterval(id)
  }, [running, selectedClientId, lastEventId, params.emit_live_telemetry])

  const handleRun = useCallback(async (opts = {}) => {
    const dryRun = !!opts.dryRun || !!params.dry_run
    if (!selectedClientId) return
    if (!target.trim()) return
    setRunning(true)
    setLines([])
    setMetrics(null)
    setFindings([])
    setOracleSynth(null)
    setLiveEvents([])
    setLastEventId(0)
    connectSwarmWs()
    appendLine(`[NSSI] ${dryRun ? 'Planning dry-run' : 'Initializing hive deployment'} — ${params.agent_count} agents (${paramCount} params)…`)
    if (params.endpoint_bridge && !dryRun) {
      await broadcastFleet()
    }

    const body = buildScanBody(params, selectedClientId, target)
    if (opts.dryRun) body.dry_run = true

    try {
      const { ok, data } = await postScan(body)
      if (!ok) {
        appendLine(`[ERROR] ${data.detail || 'Scan failed'}`)
        setRunning(false)
        return
      }
      const jobId = data.job_id
      appendLine(`[NSSI] Job queued: ${jobId}`)
      if (esRef.current) esRef.current.close()
      const es = openSseStream(`/api/telemetry/stream?job_id=${jobId}`)
      esRef.current = es
      es.onmessage = (ev) => {
        try {
          const p = JSON.parse(ev.data)
          if (p.source === 'nexus_sovereign_swarm' && p.event) {
            setLiveEvents((prev) => [...prev.slice(-48), { event: p.event, detail: p.detail, ts: p.ts }])
          }
          if (p.message) appendLine(p.message)
          if (p.status === 'completed' || p.status === 'failed') {
            es.close()
            setRunning(false)
            apiFetch(`/api/jobs/${jobId}`)
              .then((job) => {
                const res = job?.result_json || job?.result
                const f = res?.findings || []
                setFindings(f)
                setLastUpdated(new Date().toISOString())
                if (jobId) setLastJobId(jobId)
                const summary = f.find((x) => x.swarm_metrics)
                const meta = summary?.swarm_metrics
                if (meta) setMetrics(meta)
                if (summary?.oracle_synthesis) setOracleSynth(summary.oracle_synthesis)
                appendLine(`[NSSI] ${dryRun ? 'Dry-run complete' : 'Deployment complete'} — ${f.length} findings`)
              })
              // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedClientId, target, params, paramCount, appendLine, connectSwarmWs, broadcastFleet, setLastUpdated, setLastJobId])

  const agentCount = parseInt(params.agent_count, 10) || 2048

  return (
    <PageShell
      hideHubParams
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
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-emerald-400/30 text-emerald-300 bg-emerald-500/10 uppercase tracking-widest">
                  {paramCount} {t('nexusSwarm.params_badge', 'live parameters')}
                </span>
                <ConfigCompletenessBadge parity={schemaParity} completeness={completeness} />
                <span className="text-[10px] font-mono text-[var(--text-disabled)]">MITRE T1595</span>
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">
                {engine?.label || 'Nexus Sovereign Swarm Intelligence'}
              </h1>
              <p className="text-sm text-[var(--text-tertiary)] mt-1 max-w-2xl leading-relaxed">
                {engine?.description}
              </p>
            </div>
            <div className="flex gap-2 flex-wrap items-center">
              <ShellScanActions onRefresh={handleRefresh} onExport={exportCsv} exportDisabled={!filteredFindings.length} />
              <Link to={`/engines/${ENGINE_ID}`} className="text-[11px] font-mono px-3 py-1.5 rounded-lg border border-[var(--border-strong)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:border-[var(--border-strong)] transition-colors">
                Engine Detail →
              </Link>
              <Link to={`/engines/top-tier/${ENGINE_ID}`} className="text-[11px] font-mono px-3 py-1.5 rounded-lg border border-rose-500/30 text-rose-300 hover:bg-rose-500/10 transition-colors">
                Top-Tier Profile →
              </Link>
            </div>
          </div>
        </motion.div>

        {/* Main layout: dedicated control column (left) + live theatre (right) */}
        <div className="grid grid-cols-1 xl:grid-cols-[400px_1fr] gap-6 items-start">
          {/* ───────── Sovereign Control Column ───────── */}
          <div className="xl:sticky xl:top-4 space-y-3 xl:max-h-[calc(100dvh-2rem)] xl:overflow-y-auto pr-1">
            <div className="rounded-2xl border border-violet-500/25 bg-gradient-to-b from-violet-950/30 to-black/50 p-3">
              <div className="flex items-center justify-between mb-2 px-1">
                <h2 className="text-sm font-bold text-white tracking-tight flex items-center gap-2">
                  <span>🎛️</span> {t('nexusSwarm.control_column', 'Sovereign Control Column')}
                </h2>
                <Button variant="unstyled"
                  type="button"
                  onClick={resetParams}
                  className="text-[9px] font-mono uppercase tracking-wide px-2 py-1 rounded-md border border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] transition-colors"
                >
                  {t('nexusSwarm.reset', 'Reset')}
                </Button>
              </div>

              <MissionPresetsBar
                onApply={applyPreset}
                onSave={handleSavePreset}
                onExport={handleExportConfig}
                onImport={handleImportConfig}
                onWaveReplay={handleWaveReplay}
                customPresets={customPresets}
                onShowSchema={handleShowSchema}
              />
              <ConfigSchemaPanel schema={configSchema} onClose={() => setConfigSchema(null)} />
              <input ref={importRef} type="file" accept="application/json" className="hidden" onChange={onImportFile} />

              {/* Target binding */}
              <Section title={t('nexusSwarm.sec_target', 'Target Binding')} icon="🎯" accent="#22d3ee" count={2}>
                <label className="block space-y-1">
                  <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">{t('common.client', 'Client')}</span>
                  <select
                    value={selectedClientId}
                    onChange={(e) => setSelectedClientId(e.target.value)}
                    className="w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-sm text-white focus:outline-none focus:border-violet-400/40"
                  >
                    <option value="">—</option>
                    {clients.map((c) => (
                      <option key={c.id} value={c.id}>{c.name || c.id}</option>
                    ))}
                  </select>
                </label>
                <Txt label={t('common.target', 'Target')} value={target} onChange={setTarget} placeholder="https://target.example" />
              </Section>

              {/* Deployment */}
              <Section title={t('nexusSwarm.sec_deployment', 'Deployment')} icon="🚀" accent="#a855f7" count={6}>
                <div className="grid grid-cols-2 gap-2">
                  <Num label="Agent Count" value={params.agent_count} onChange={(v) => setField('agent_count', v)} min={1} max={50000} hint="1 – 50,000 micro-agents" />
                  <Num label="Max Surface Points" value={params.max_surface_points} onChange={(v) => setField('max_surface_points', v)} min={1} max={8192} hint="URLs in the surface" />
                  <Num label="Max Concurrency" value={params.max_concurrency} onChange={(v) => setField('max_concurrency', v)} min={1} max={1024} hint="In-flight probes" />
                  <Sel label="Hive Mode" value={params.hive_mode} onChange={(v) => setField('hive_mode', v)} options={HIVE_MODES} hint="emergent · parallel · stealth · blitz" />
                </div>
                <Sel label="Oracle Strategy" value={params.llm_strategy} onChange={(v) => setField('llm_strategy', v)} options={STRATEGIES} />
                {STRATEGY_HINTS[params.llm_strategy] && (
                  <p className="text-[9px] font-mono text-violet-300/60 leading-relaxed px-0.5">{STRATEGY_HINTS[params.llm_strategy]}</p>
                )}
              </Section>

              {/* Adaptive intelligence */}
              <Section title={t('nexusSwarm.sec_adaptive', 'Adaptive Intelligence')} icon="🧠" accent="#8b5cf6" count={17}>
                <Toggle label="Adaptive Multi-Wave" value={params.adaptive} onChange={(v) => setField('adaptive', v)} hint="Each wave's findings refine the next wave's surface" />
                <div className="grid grid-cols-2 gap-2">
                  <Num label="Waves" value={params.waves} onChange={(v) => setField('waves', v)} min={1} max={4} hint="1 – 4 adaptive cycles" />
                  <Num label="Max RPS" value={params.max_rps} onChange={(v) => setField('max_rps', v)} min={0} max={100000} hint="0 = unlimited (safety governor)" />
                  <Num label="Seed" value={params.seed} onChange={(v) => setField('seed', v)} min={0} hint="0 = random · fixed = reproducible" />
                  <Num label="Body Max Bytes" value={params.body_max_bytes} onChange={(v) => setField('body_max_bytes', v)} min={4096} max={262144} hint="HTML analysis cap" />
                </div>
                <Toggle label="WAF / CDN Detection" value={params.waf_detection} onChange={(v) => setField('waf_detection', v)} hint="Fingerprint edge security vendor" />
                <Toggle label="Live Link Extraction" value={params.link_extraction} onChange={(v) => setField('link_extraction', v)} hint="Extract href/src/action paths from HTML responses" />
                <Toggle label="Response Body Analysis" value={params.body_analysis} onChange={(v) => setField('body_analysis', v)} hint="Directory listing & body indicators" />
                <Toggle label="Attack Chain Correlation" value={params.attack_chains} onChange={(v) => setField('attack_chains', v)} hint="CORS+exposure, intel→exploit, HSTS chains" />
                <Toggle label="Auth Perimeter Mapping" value={params.auth_perimeter} onChange={(v) => setField('auth_perimeter', v)} hint="Classify open vs auth-gated paths" />
                <Toggle label="Next-Engine Recommendations" value={params.engine_recommendations} onChange={(v) => setField('engine_recommendations', v)} hint="Route to follow-up production engines" />
                <Toggle label="Cookie Security Audit" value={params.cookie_audit} onChange={(v) => setField('cookie_audit', v)} hint="HttpOnly / Secure / SameSite on Set-Cookie" />
                <Toggle label="Priority Surface Scoring" value={params.priority_scoring} onChange={(v) => setField('priority_scoring', v)} hint="Bias agents toward admin/api/.env paths" />
                <Toggle label="Rate-Limit Detection" value={params.rate_limit_detection} onChange={(v) => setField('rate_limit_detection', v)} hint="Aggregate 429/403 WAF block storms" />
                <Toggle label="Live Wave Telemetry" value={params.emit_live_telemetry} onChange={(v) => setField('emit_live_telemetry', v)} hint="Stream wave events to /ws/swarm + SSE + swarm_events" />
                <Toggle label="TLS Certificate Audit" value={params.tls_cert_audit} onChange={(v) => setField('tls_cert_audit', v)} hint="Live :443 handshake — issuer, expiry, self-signed" />
                <Toggle label="Body Surface Detection" value={params.body_surface_detection} onChange={(v) => setField('body_surface_detection', v)} hint="GraphQL/OpenAPI/Swagger markers in response bodies" />
                <Num label="Progress Emit Interval" value={params.progress_emit_interval} onChange={(v) => setField('progress_emit_interval', v)} min={0} max={4096} hint="Agents between wave_progress events (0=off)" />
                <Num label="Single Wave (replay)" value={params.single_wave} onChange={(v) => setField('single_wave', v)} min={0} max={4} hint="0=all waves · 1-4=run only that wave" />
              </Section>

              {/* Archetypes */}
              <Section title={t('nexusSwarm.sec_archetypes', 'Archetypes')} icon="🧬" accent="#f43f5e" count={params.archetypes.length}>
                <div className="grid grid-cols-1 gap-1.5">
                  {ARCHETYPES.map((a) => {
                    const on = params.archetypes.includes(a.id)
                    return (
                      <Button variant="unstyled"
                        key={a.id}
                        type="button"
                        onClick={() => toggleArchetype(a.id)}
                        className={`flex items-center gap-2 text-left rounded-lg border px-2.5 py-1.5 transition-all ${on ? 'bg-[var(--row-hover-bg)]' : 'opacity-45 hover:opacity-80'}`}
                        style={{ borderColor: on ? `${a.color}66` : 'rgba(255,255,255,0.08)' }}
                      >
                        <span>{a.icon}</span>
                        <span className="min-w-0 flex-1">
                          <span className="text-xs font-semibold text-white block">{a.label}</span>
                          <span className="text-[9px] text-[var(--text-muted)] block leading-tight truncate">{a.desc}</span>
                        </span>
                        <span className={`text-[9px] font-mono ${on ? 'text-emerald-400' : 'text-[var(--text-disabled)]'}`}>{on ? 'ON' : 'OFF'}</span>
                      </Button>
                    )
                  })}
                </div>
                <Hint>{t('nexusSwarm.archetypes_hint', 'Empty selection = all archetypes. Correlator + Oracle synthesise from collected signals.')}</Hint>
              </Section>

              {/* Transport / HTTP */}
              <Section title={t('nexusSwarm.sec_transport', 'Transport / HTTP')} icon="📡" accent="#38bdf8" count={8} defaultOpen={false}>
                <div className="grid grid-cols-2 gap-2">
                  <Num label="Timeout (ms)" value={params.timeout_ms} onChange={(v) => setField('timeout_ms', v)} min={500} max={60000} />
                  <Num label="Connect TO (ms)" value={params.connect_timeout_ms} onChange={(v) => setField('connect_timeout_ms', v)} min={200} max={30000} />
                  <Num label="Max Redirects" value={params.max_redirects} onChange={(v) => setField('max_redirects', v)} min={0} max={20} />
                  <Num label="Jitter (ms)" value={params.request_jitter_ms} onChange={(v) => setField('request_jitter_ms', v)} min={0} max={5000} hint="Per-agent stagger base" />
                </div>
                <Toggle label="Follow Redirects" value={params.follow_redirects} onChange={(v) => setField('follow_redirects', v)} />
                <Toggle label="Verify TLS" value={params.verify_tls} onChange={(v) => setField('verify_tls', v)} hint="Off = accept invalid certs" />
                <Txt label="User-Agent" value={params.user_agent} onChange={(v) => setField('user_agent', v)} placeholder="(default NSSI UA)" />
                <div className="space-y-1.5">
                  <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-wide">Custom Headers</span>
                  {params.extra_headers.map((h, i) => (
                    <div key={i} className="flex items-center gap-1.5">
                      <input
                        value={h.name}
                        onChange={(e) => setHeader(i, 'name', e.target.value)}
                        placeholder="Header"
                        className="w-2/5 rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-2 py-1 text-[11px] text-white font-mono placeholder-white/20 focus:outline-none focus:border-violet-400/40"
                      />
                      <input
                        value={h.value}
                        onChange={(e) => setHeader(i, 'value', e.target.value)}
                        placeholder="Value"
                        className="flex-1 rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-2 py-1 text-[11px] text-white font-mono placeholder-white/20 focus:outline-none focus:border-violet-400/40"
                      />
                      <Button variant="unstyled" type="button" aria-label="Remove header" onClick={() => removeHeader(i)} className="text-[var(--text-disabled)] hover:text-rose-400 text-sm px-1">✕</Button>
                    </div>
                  ))}
                  <Button variant="unstyled" type="button" onClick={addHeader} className="text-[10px] font-mono text-cyan-300/70 hover:text-cyan-200">+ {t('nexusSwarm.add_header', 'add header')}</Button>
                </div>
              </Section>

              {/* Surface mapping */}
              <Section title={t('nexusSwarm.sec_surface', 'Surface Mapping')} icon="🗺️" accent="#34d399" count={7} defaultOpen={false}>
                <div className="grid grid-cols-2 gap-2">
                  <Num label="Wordlist Depth" value={params.wordlist_depth} onChange={(v) => setField('wordlist_depth', v)} min={0} max={5000} />
                  <Num label="Subdomain Depth" value={params.subdomain_depth} onChange={(v) => setField('subdomain_depth', v)} min={0} max={2000} />
                  <Sel label="Scout Method" value={params.scout_method} onChange={(v) => setField('scout_method', v)} options={HTTP_METHODS} />
                  <Sel label="Exploiter Method" value={params.exploiter_method} onChange={(v) => setField('exploiter_method', v)} options={HTTP_METHODS} />
                </div>
                <Toggle label="Include Discovered Paths" value={params.include_discovered_paths} onChange={(v) => setField('include_discovered_paths', v)} />
                <Area label="Sensitive Paths (exploiter)" value={params.sensitive_paths} onChange={(v) => setField('sensitive_paths', v)} placeholder={'one per line — empty = built-in defaults\n/admin\n/api/keys'} />
                <Area label="Stealth Intel Paths" value={params.stealth_paths} onChange={(v) => setField('stealth_paths', v)} placeholder={'one per line — empty = robots/sitemap defaults'} />
              </Section>

              {/* Consensus & Oracle */}
              <Section title={t('nexusSwarm.sec_consensus', 'Consensus & Oracle')} icon="🔮" accent="#f59e0b" count={6} defaultOpen={false}>
                <div className="grid grid-cols-2 gap-2">
                  <Num label="Consensus Threshold" value={params.convergence_threshold} onChange={(v) => setField('convergence_threshold', v)} min={0.05} max={0.99} step={0.01} />
                  <Num label="Min Agents" value={params.consensus_min_agents} onChange={(v) => setField('consensus_min_agents', v)} min={1} max={50} />
                  <Num label="Min Archetypes" value={params.consensus_min_archetypes} onChange={(v) => setField('consensus_min_archetypes', v)} min={1} max={5} />
                  <Num label="Oracle Temp" value={params.oracle_temperature} onChange={(v) => setField('oracle_temperature', v)} min={0} max={2} step={0.05} />
                  <Num label="Oracle Max Tokens" value={params.oracle_max_tokens} onChange={(v) => setField('oracle_max_tokens', v)} min={32} max={4096} />
                </div>
                <Txt label="Oracle Model" value={params.oracle_model} onChange={(v) => setField('oracle_model', v)} placeholder="(tenant default e.g. gpt-4o)" />
                <Txt label="Oracle LLM Base URL" value={params.llm_base_url} onChange={(v) => setField('llm_base_url', v)} placeholder="(tenant default endpoint)" />
              </Section>

              {/* Bridge & Edge */}
              <Section title={t('nexusSwarm.sec_bridge', 'Bridge & Edge')} icon="🌐" accent="#818cf8" count={2} defaultOpen={false}>
                <Toggle label="Endpoint Agent Bridge" value={params.endpoint_bridge} onChange={(v) => setField('endpoint_bridge', v)} hint="Fan deployment out to enrolled host agents" />
                <Toggle label="Edge Distribution" value={params.edge_distribution} onChange={(v) => setField('edge_distribution', v)} hint="Assign nearest edge POP node" />
              </Section>

              {/* Output filtering */}
              <Section title={t('nexusSwarm.sec_output', 'Output & Filtering')} icon="🎚️" accent="#94a3b8" count={5} defaultOpen={false}>
                <Sel label="Min Severity" value={params.min_severity} onChange={(v) => setField('min_severity', v)} options={SEVERITIES} hint="Drop findings below this rank" />
                <Toggle label="Emit Passive Scout Signals" value={params.emit_passive_signals} onChange={(v) => setField('emit_passive_signals', v)} />
                <Toggle label="Dedupe Findings" value={params.dedupe_findings} onChange={(v) => setField('dedupe_findings', v)} />
                <Toggle label="Dry Run (plan only)" value={params.dry_run} onChange={(v) => setField('dry_run', v)} hint="Compute the plan without sending requests" />
                <Txt label="Tags (csv)" value={params.tags} onChange={(v) => setField('tags', v)} placeholder="redteam, q3-assessment" />
              </Section>

              {/* Payload preview */}
              <Section title={t('nexusSwarm.sec_payload', 'Live Payload Preview')} icon="📦" accent="#64748b" count={paramCount} defaultOpen={false}>
                <Button variant="unstyled"
                  type="button"
                  onClick={() => setShowPreview((s) => !s)}
                  className="text-[10px] font-mono text-cyan-300/70 hover:text-cyan-200"
                >
                  {showPreview ? t('nexusSwarm.hide_json', 'hide JSON') : t('nexusSwarm.show_json', 'show exact request JSON')}
                </Button>
                {showPreview && (
                  <pre className="max-h-60 overflow-auto rounded-lg bg-[var(--scrim)] border border-[var(--border-default)] p-2.5 text-[10px] font-mono text-emerald-300/80 leading-relaxed">
                    {JSON.stringify(previewBody, null, 2)}
                  </pre>
                )}
              </Section>

              {/* Deploy actions */}
              <div className="mt-3 space-y-2">
                <Button variant="unstyled"
                  type="button"
                  onClick={() => handleRun()}
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
                </Button>
                <Button variant="unstyled"
                  type="button"
                  onClick={() => handleRun({ dryRun: true })}
                  disabled={running || !selectedClientId || !target.trim()}
                  className="w-full py-2 rounded-xl font-mono text-[11px] uppercase tracking-widest border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                >
                  {t('nexusSwarm.dry_run', 'Dry-Run Plan (no requests)')}
                </Button>
              </div>
            </div>
          </div>

          {/* ───────── Live theatre ───────── */}
          <div className="space-y-6 min-w-0">
            <div className="grid grid-cols-1 2xl:grid-cols-3 gap-6">
              <div className="2xl:col-span-2 rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] overflow-hidden">
                <div className="px-4 py-3 border-b border-[var(--border-subtle)] flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">
                    {t('nexusSwarm.hive_viz', 'Live Hive Visualization')}
                  </span>
                  {running && (
                    <span className="flex items-center gap-1.5 text-[10px] font-mono text-violet-300">
                      <span className="w-1.5 h-1.5 rounded-full bg-violet-400 animate-pulse" />
                      {params.dry_run ? 'PLANNING' : 'DEPLOYING'}
                    </span>
                  )}
                </div>
                <div className="h-72 md:h-80">
                  <SwarmHiveCanvas agentCount={agentCount} running={running} />
                </div>
              </div>

              <div className="space-y-4">
                <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] p-5 text-center">
                  <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)] mb-3">
                    {t('nexusSwarm.siq', 'Swarm Intelligence Quotient')}
                  </p>
                  <SiqGauge score={metrics?.swarm_iq} />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <MetricTile label="Agents" value={metrics?.agents_deployed?.toLocaleString() ?? agentCount.toLocaleString()} accent="#22d3ee" />
                  <MetricTile label="Requests" value={metrics?.requests_sent?.toLocaleString()} accent="#38bdf8" />
                  <MetricTile label="Signals" value={metrics?.raw_signals} accent="#ef4444" />
                  <MetricTile label="Consensus" value={metrics?.consensus_findings} accent="#a855f7" />
                </div>
              </div>
            </div>

            {/* Hive intelligence synthesis */}
            <IntelligencePanel
              metrics={metrics}
              findings={findings}
              oracle={oracleSynth}
              onLaunchEngine={launchRecommendedEngine}
              launchingEngine={launchingEngine}
              liveEvents={liveEvents}
              running={running}
            />

            {/* Endpoint fleet */}
            <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4 space-y-3">
              <div className="flex items-center justify-between gap-2">
                <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-[var(--text-muted)]">
                  {t('nexusSwarm.endpoint_fleet', 'Endpoint Agent Fleet')}
                </p>
                <div className="flex items-center gap-3">
                  {swarmWsLive && <span className="text-[9px] font-mono text-emerald-400">{t('nexusSwarm.swarm_ws_live', 'swarm ws live')}</span>}
                  <span className="text-[10px] font-mono text-[var(--text-muted)]">
                    {metrics?.endpoint_agents_bridged ?? fleetOnline} {t('nexusSwarm.bridged', 'bridged')}
                  </span>
                </div>
              </div>
              <p className="text-[11px] text-[var(--text-tertiary)]">
                {fleetForClient.length
                  ? t('nexusSwarm.fleet_online', { online: fleetOnline, total: fleetForClient.length })
                  : t('nexusSwarm.no_agents', 'No endpoint agents enrolled for this client.')}
              </p>
              <div className="flex flex-wrap gap-2">
                {fleetForClient.slice(0, 8).map((a) => (
                  <span key={a.agent_uuid} className="flex items-center gap-1.5 text-[10px] font-mono text-[var(--text-muted)] rounded-lg border border-[var(--border-default)] px-2 py-1">
                    <span className={`w-1.5 h-1.5 rounded-full ${a.status === 'online' || a.live ? 'bg-emerald-400' : 'bg-white/20'}`} />
                    {a.hostname || a.device_name || a.agent_uuid?.slice(0, 8)}
                  </span>
                ))}
              </div>
              <div className="flex gap-2 pt-1">
                <Button variant="unstyled"
                  type="button"
                  onClick={broadcastFleet}
                  disabled={fleetBusy || !selectedClientId || !target.trim()}
                  className="py-2 px-4 rounded-lg text-[10px] font-mono uppercase border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10 disabled:opacity-40"
                >
                  {fleetBusy ? t('nexusSwarm.fleet_broadcasting', 'Broadcasting…') : t('nexusSwarm.fleet_broadcast', 'Broadcast Fleet')}
                </Button>
                <Link to="/agents" className="py-2 px-3 rounded-lg text-[10px] font-mono border border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-secondary)]">
                  Agents →
                </Link>
              </div>
            </div>

            {/* Telemetry */}
            <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--scrim)] overflow-hidden">
              <div className="px-4 py-2 border-b border-[var(--border-subtle)] text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest">
                Swarm Telemetry
              </div>
              <pre className="h-44 overflow-auto p-3 text-[10px] font-mono text-emerald-400/80 leading-relaxed">
                {lines.length ? lines.join('\n') : t('nexusSwarm.awaiting', 'Awaiting deployment…')}
              </pre>
            </div>

            {/* Findings */}
            {(metrics || realFindings.length > 0) && (
              <div className="flex justify-end">
                <Button variant="unstyled"
                  type="button"
                  onClick={handleExportReport}
                  className="text-[9px] font-mono uppercase px-2 py-1 rounded border border-violet-500/30 text-violet-300 hover:bg-violet-500/10"
                >
                  Export Intelligence Report
                </Button>
              </div>
            )}
            <WeissmanFindingsPanel
              findings={realFindings}
              filteredFindings={filteredFindings}
              counts={counts}
              total={realFindings.length}
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              severityFilter={severityFilter}
              onSeverityChange={setSeverityFilter}
              pending={running && !realFindings.length}
              loading={historyLoading && !realFindings.length}
              lastUpdated={lastUpdated}
              jobId={lastJobId}
              accent="#a855f7"
              showEmptyReady={!running && realFindings.length === 0}
              renderFinding={(f, i) => <FindingRow key={`${f.title}-${i}`} finding={f} />}
            />
          </div>
        </div>
      </div>
    </PageShell>
  )
}
