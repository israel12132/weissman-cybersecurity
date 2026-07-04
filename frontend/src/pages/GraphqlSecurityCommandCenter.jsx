import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../lib/apiBase'
import { openSseStream } from '../lib/sseStream'
import { buildSimpleTextPdf, downloadBytes } from '../lib/pdfExport'
import { ENGINES_BY_ID } from '../lib/enginesRegistry'

const ENGINE_ID = 'graphql_attack'

const HTTP_SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']

const SCAN_PROFILES = [
  { id: 'comprehensive', label: 'Comprehensive', color: '#f472b6', icon: '🌐', desc: 'All 41 probe components — Relay BOLA, pagination abuse, WAF evasion, live data leak, executive PDF' },
  { id: 'stealth', label: 'Stealth', color: '#64748b', icon: '👻', desc: 'Passive recon only — introspection, suggestions, fingerprint; no DoS bursts' },
  { id: 'dos_stress', label: 'DoS Stress', color: '#ef4444', icon: '💥', desc: 'Amplification-focused — elevated alias/batch/depth/fragment limits' },
]

const OWASP_API_LABELS = {
  API1: 'Broken Object Level Authorization',
  API2: 'Broken Authentication',
  API3: 'Broken Object Property Level Authorization',
  API4: 'Unrestricted Resource Consumption',
  API5: 'Broken Function Level Authorization',
  API6: 'Unrestricted Access to Sensitive Business Flows',
  API7: 'Server Side Request Forgery',
  API8: 'Security Misconfiguration',
  API9: 'Improper Inventory Management',
  API10: 'Unsafe Consumption of APIs',
}

// Full, lossless default surface — mirrors every knob the backend GraphqlScanConfig reads.
const DEFAULT_PARAMS = {
  // Scope — core discovery
  probe_introspection: true,
  probe_suggestions: true,
  probe_schema_recon: true,
  probe_fingerprint: true,
  probe_ide_exposure: true,
  // Scope — DoS / abuse
  probe_batching: true,
  probe_alias_overload: true,
  probe_depth: true,
  probe_field_duplication: true,
  probe_fragment_cycle: true,
  probe_directive_abuse: true,
  probe_rate_limit: true,
  // Scope — transport / CSRF / leaks
  probe_csrf_get: true,
  probe_error_verbosity: true,
  probe_content_type_graphql: true,
  probe_multi_operation: true,
  probe_tracing: true,
  // Scope — advanced GraphQL
  probe_federation: true,
  probe_apq: true,
  probe_introspection_bypass: true,
  probe_subscription_ws: true,
  probe_upload_scalar: true,
  probe_auth_differential: true,
  probe_bola: true,
  probe_defer_stream: true,
  probe_subscription_sse: true,
  probe_bola_batch: true,
  probe_cors: true,
  probe_cswsh: true,
  probe_variable_tampering: true,
  probe_query_cost: true,
  probe_get_cache: true,
  probe_field_auth_diff: true,
  probe_interface_leak: true,
  probe_bola_nested: true,
  probe_operation_allowlist: true,
  probe_hasura_surface: true,
  probe_relay_global_id: true,
  probe_pagination_abuse: true,
  probe_limit_fingerprint: true,
  probe_waf_evasion: true,
  probe_live_data_leak: true,
  // Endpoint surface
  graphql_paths: '',
  // DoS tuning
  alias_count: '100',
  batch_count: '10',
  depth_levels: '12',
  field_duplication_count: '200',
  burst_count: '15',
  fragment_spread_depth: '8',
  // Schema reconstruction (Clairvoyance)
  recon_fields: '',
  max_recon_fields: '48',
  bola_test_ids: '1\n2\n100',
  bola_id_range_start: '0',
  bola_id_range_end: '0',
  max_bola_probes: '8',
  bola_batch_size: '5',
  // Auth (for differential + authenticated probes)
  bearer_token: '',
  api_key: '',
  api_key_header: 'X-API-Key',
  cookie: '',
  // Posture
  attack_path_synthesis: true,
  // Transport
  timeout_ms: '9000',
  connect_timeout_ms: '4000',
  max_concurrency: '12',
  verify_tls: false,
  follow_redirects: false,
  user_agent: '',
  extra_headers: [{ name: 'Authorization', value: '' }],
  // Output
  min_severity: 'info',
  dedupe_findings: true,
  max_findings: '500',
  tags: '',
  dry_run: false,
  emit_metrics: true,
}

function applyScanProfile(profileId) {
  const base = { ...DEFAULT_PARAMS, extra_headers: [{ name: 'Authorization', value: '' }] }
  if (profileId === 'stealth') {
    return {
      ...base,
      probe_batching: false,
      probe_alias_overload: false,
      probe_depth: false,
      probe_field_duplication: false,
      probe_fragment_cycle: false,
      probe_directive_abuse: false,
      probe_rate_limit: false,
      probe_csrf_get: false,
      probe_federation: false,
      probe_apq: false,
      probe_subscription_ws: false,
      probe_upload_scalar: false,
      probe_auth_differential: false,
      probe_bola: false,
      probe_defer_stream: false,
      probe_subscription_sse: false,
      probe_bola_batch: false,
      probe_cors: false,
      probe_cswsh: false,
      probe_variable_tampering: false,
      probe_query_cost: false,
      probe_get_cache: false,
      probe_field_auth_diff: false,
      probe_interface_leak: false,
      probe_bola_nested: false,
      probe_operation_allowlist: false,
      probe_hasura_surface: false,
      probe_relay_global_id: false,
      probe_pagination_abuse: false,
      probe_limit_fingerprint: false,
      probe_waf_evasion: false,
      probe_live_data_leak: false,
      max_recon_fields: '32',
    }
  }
  if (profileId === 'dos_stress') {
    return {
      ...base,
      probe_batching: true,
      probe_alias_overload: true,
      probe_depth: true,
      probe_field_duplication: true,
      probe_fragment_cycle: true,
      probe_directive_abuse: true,
      probe_rate_limit: true,
      alias_count: '500',
      batch_count: '50',
      depth_levels: '24',
      field_duplication_count: '1000',
      burst_count: '30',
      fragment_spread_depth: '16',
      probe_introspection: false,
      probe_schema_recon: false,
      probe_suggestions: false,
    }
  }
  return base
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
    // Scope
    probe_introspection: !!params.probe_introspection,
    probe_suggestions: !!params.probe_suggestions,
    probe_schema_recon: !!params.probe_schema_recon,
    probe_batching: !!params.probe_batching,
    probe_alias_overload: !!params.probe_alias_overload,
    probe_depth: !!params.probe_depth,
    probe_csrf_get: !!params.probe_csrf_get,
    probe_error_verbosity: !!params.probe_error_verbosity,
    probe_ide_exposure: !!params.probe_ide_exposure,
    probe_fingerprint: !!params.probe_fingerprint,
    probe_federation: !!params.probe_federation,
    probe_apq: !!params.probe_apq,
    probe_introspection_bypass: !!params.probe_introspection_bypass,
    probe_field_duplication: !!params.probe_field_duplication,
    probe_fragment_cycle: !!params.probe_fragment_cycle,
    probe_directive_abuse: !!params.probe_directive_abuse,
    probe_content_type_graphql: !!params.probe_content_type_graphql,
    probe_multi_operation: !!params.probe_multi_operation,
    probe_tracing: !!params.probe_tracing,
    probe_rate_limit: !!params.probe_rate_limit,
    probe_auth_differential: !!params.probe_auth_differential,
    probe_bola: !!params.probe_bola,
    probe_defer_stream: !!params.probe_defer_stream,
    probe_subscription_sse: !!params.probe_subscription_sse,
    probe_bola_batch: !!params.probe_bola_batch,
    probe_cors: !!params.probe_cors,
    probe_cswsh: !!params.probe_cswsh,
    probe_variable_tampering: !!params.probe_variable_tampering,
    probe_query_cost: !!params.probe_query_cost,
    probe_get_cache: !!params.probe_get_cache,
    probe_field_auth_diff: !!params.probe_field_auth_diff,
    probe_interface_leak: !!params.probe_interface_leak,
    probe_bola_nested: !!params.probe_bola_nested,
    probe_operation_allowlist: !!params.probe_operation_allowlist,
    probe_hasura_surface: !!params.probe_hasura_surface,
    probe_relay_global_id: !!params.probe_relay_global_id,
    probe_pagination_abuse: !!params.probe_pagination_abuse,
    probe_limit_fingerprint: !!params.probe_limit_fingerprint,
    probe_waf_evasion: !!params.probe_waf_evasion,
    probe_live_data_leak: !!params.probe_live_data_leak,
    probe_subscription_ws: !!params.probe_subscription_ws,
    probe_upload_scalar: !!params.probe_upload_scalar,
    // DoS tuning
    alias_count: numOr(params.alias_count, 100),
    batch_count: numOr(params.batch_count, 10),
    depth_levels: numOr(params.depth_levels, 12),
    field_duplication_count: numOr(params.field_duplication_count, 200),
    burst_count: numOr(params.burst_count, 15),
    fragment_spread_depth: numOr(params.fragment_spread_depth, 8),
    max_bola_probes: numOr(params.max_bola_probes, 8),
    bola_batch_size: numOr(params.bola_batch_size, 5),
    bola_id_range_start: numOr(params.bola_id_range_start, 0),
    bola_id_range_end: numOr(params.bola_id_range_end, 0),
    max_recon_fields: numOr(params.max_recon_fields, 48),
    // Posture
    attack_path_synthesis: !!params.attack_path_synthesis,
    // Transport
    timeout_ms: numOr(params.timeout_ms, 9000),
    connect_timeout_ms: numOr(params.connect_timeout_ms, 4000),
    max_concurrency: numOr(params.max_concurrency, 12),
    verify_tls: !!params.verify_tls,
    follow_redirects: !!params.follow_redirects,
    // Output
    min_severity: params.min_severity,
    dedupe_findings: !!params.dedupe_findings,
    max_findings: numOr(params.max_findings, 500),
    dry_run: !!params.dry_run,
    emit_metrics: !!params.emit_metrics,
  }
  const paths = splitLines(params.graphql_paths)
  if (paths.length) body.graphql_paths = paths
  const recon = splitLines(params.recon_fields)
  if (recon.length) body.recon_fields = recon
  const bolaIds = splitLines(params.bola_test_ids)
  if (bolaIds.length) body.bola_test_ids = bolaIds
  if (params.user_agent.trim()) body.user_agent = params.user_agent.trim()
  if (params.bearer_token.trim()) body.bearer_token = params.bearer_token.trim()
  if (params.api_key.trim()) {
    body.api_key = params.api_key.trim()
    if (params.api_key_header.trim()) body.api_key_header = params.api_key_header.trim()
  }
  if (params.cookie.trim()) body.cookie = params.cookie.trim()
  const tags = splitCsv(params.tags)
  if (tags.length) body.tags = tags
  const hdrs = {}
  for (const h of params.extra_headers) {
    if (h.name.trim() && h.value.trim()) hdrs[h.name.trim()] = h.value.trim()
  }
  if (Object.keys(hdrs).length) body.extra_headers = hdrs
  return body
}

// ─── Reusable control primitives ─────────────────────────────────────────────

function Section({ title, icon, accent = '#f472b6', count, defaultOpen = true, children }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="rounded-xl border border-white/10 bg-black/30 overflow-hidden" style={{ borderColor: `${accent}22` }}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between px-3 py-2.5 hover:bg-white/[0.03] transition-colors"
      >
        <span className="flex items-center gap-2 text-[11px] font-mono uppercase tracking-[0.18em] font-semibold" style={{ color: accent }}>
          <span>{icon}</span>
          {title}
          {count != null && <span className="text-white/30 normal-case tracking-normal">· {count}</span>}
        </span>
        <span className={`text-white/40 text-xs transition-transform ${open ? 'rotate-90' : ''}`}>▶</span>
      </button>
      {open && <div className="px-3 pb-3 pt-1 space-y-3 border-t border-white/5">{children}</div>}
    </div>
  )
}

function Hint({ children }) {
  if (!children) return null
  return <span className="block text-[9px] font-mono text-white/25 mt-0.5 leading-snug">{children}</span>
}

function Num({ label, value, onChange, min, max, step, hint }) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] font-mono text-white/45 uppercase tracking-wide">{label}</span>
      <input
        type="number"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-lg bg-black/50 border border-white/10 px-3 py-1.5 text-sm text-white font-mono focus:outline-none focus:border-pink-400/40"
      />
      <Hint>{hint}</Hint>
    </label>
  )
}

function Sel({ label, value, onChange, options, hint }) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] font-mono text-white/45 uppercase tracking-wide">{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-lg bg-black/50 border border-white/10 px-3 py-1.5 text-sm text-white focus:outline-none focus:border-pink-400/40"
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
      <span className="text-[10px] font-mono text-white/45 uppercase tracking-wide">{label}</span>
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full rounded-lg bg-black/50 border border-white/10 px-3 py-1.5 text-sm text-white font-mono placeholder-white/20 focus:outline-none focus:border-pink-400/40"
      />
      <Hint>{hint}</Hint>
    </label>
  )
}

function Area({ label, value, onChange, placeholder, rows = 3, hint }) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] font-mono text-white/45 uppercase tracking-wide">{label}</span>
      <textarea
        rows={rows}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full rounded-lg bg-black/50 border border-white/10 px-3 py-1.5 text-xs text-white font-mono placeholder-white/20 focus:outline-none focus:border-pink-400/40 resize-y"
      />
      <Hint>{hint}</Hint>
    </label>
  )
}

function Toggle({ label, value, onChange, hint }) {
  return (
    <div className="flex items-start justify-between gap-3 py-0.5">
      <div className="min-w-0">
        <span className="text-[11px] font-mono text-white/70">{label}</span>
        <Hint>{hint}</Hint>
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={value}
        onClick={() => onChange(!value)}
        className={`relative shrink-0 mt-0.5 w-9 h-5 rounded-full transition-all ${value ? 'bg-pink-500/40' : 'bg-black/60 border border-white/10'}`}
      >
        <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all ${value ? 'left-[18px]' : 'left-0.5'}`} />
      </button>
    </div>
  )
}

// ─── Visualization: live GraphQL schema graph ────────────────────────────────

function SchemaGraphCanvas({ schemaGraph, running }) {
  const canvasRef = useRef(null)
  const animRef = useRef(null)

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

    const cx = w / 2
    const cy = h / 2
    const types = Array.isArray(schemaGraph) ? schemaGraph.slice(0, 36) : []
    const nodes = types.map((t, i) => {
      const ang = (i / Math.max(types.length, 1)) * Math.PI * 2
      const radius = Math.min(w, h) * 0.34
      const size = 4 + Math.min(14, (t.field_count || 1) * 1.2)
      const sensitive = (t.fields || []).some((f) =>
        /pass|secret|token|key|ssn|card|cred|hash|otp|pin/i.test(f),
      )
      return {
        x: cx + Math.cos(ang) * radius,
        y: cy + Math.sin(ang) * radius,
        size,
        label: t.type,
        kind: t.kind,
        sensitive,
        pulse: Math.random() * Math.PI * 2,
      }
    })

    const draw = () => {
      ctx.clearRect(0, 0, w, h)
      // edges to hub
      nodes.forEach((n) => {
        ctx.beginPath()
        ctx.moveTo(cx, cy)
        ctx.lineTo(n.x, n.y)
        ctx.strokeStyle = n.sensitive ? 'rgba(244,63,94,0.28)' : 'rgba(244,114,182,0.14)'
        ctx.lineWidth = 0.7
        ctx.stroke()
      })
      // nodes
      nodes.forEach((n) => {
        n.pulse += running ? 0.07 : 0.02
        const glow = 0.5 + Math.sin(n.pulse) * 0.5
        ctx.beginPath()
        ctx.arc(n.x, n.y, n.size * (running ? 1 + glow * 0.25 : 1), 0, Math.PI * 2)
        ctx.fillStyle = n.sensitive
          ? `rgba(244,63,94,${0.6 + glow * 0.4})`
          : `rgba(244,114,182,${0.5 + glow * 0.4})`
        ctx.fill()
        if (n.size > 8) {
          ctx.font = '8px monospace'
          ctx.fillStyle = 'rgba(255,255,255,0.55)'
          ctx.textAlign = 'center'
          ctx.fillText(String(n.label || '').slice(0, 14), n.x, n.y + n.size + 8)
        }
      })
      // hub
      ctx.beginPath()
      ctx.arc(cx, cy, 22 + (running ? Math.sin(Date.now() / 320) * 3 : 0), 0, Math.PI * 2)
      ctx.fillStyle = 'rgba(0,0,0,0.6)'
      ctx.fill()
      ctx.strokeStyle = 'rgba(244,114,182,0.7)'
      ctx.lineWidth = 1.5
      ctx.stroke()
      ctx.font = 'bold 9px monospace'
      ctx.fillStyle = 'rgba(255,255,255,0.85)'
      ctx.textAlign = 'center'
      ctx.fillText(nodes.length ? 'SCHEMA' : 'GraphQL', cx, cy + 3)
      animRef.current = requestAnimationFrame(draw)
    }
    draw()
    return () => {
      if (animRef.current) cancelAnimationFrame(animRef.current)
    }
  }, [schemaGraph, running])

  return (
    <canvas
      ref={canvasRef}
      className="w-full h-full rounded-xl"
      style={{ background: 'radial-gradient(ellipse at center, rgba(131,24,67,0.18) 0%, rgba(0,0,0,0.6) 70%)' }}
    />
  )
}

function ExposureGauge({ score }) {
  const pct = Math.min(100, Math.max(0, score ?? 0))
  const color = pct >= 70 ? '#ef4444' : pct >= 40 ? '#f59e0b' : '#22d3ee'
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
        <span className="text-[9px] font-mono text-white/40 uppercase tracking-widest">Exposure</span>
      </div>
    </div>
  )
}

function MetricTile({ label, value, accent = '#f472b6' }) {
  return (
    <div className="rounded-xl border border-white/10 bg-black/40 backdrop-blur-md p-4" style={{ boxShadow: `inset 0 1px 0 ${accent}20` }}>
      <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-white/35 mb-1">{label}</p>
      <p className="text-2xl font-bold text-white">{value ?? '—'}</p>
    </div>
  )
}

function OwaspBreakdownPanel({ posture, findings }) {
  const buckets = useMemo(() => {
    if (posture && typeof posture === 'object' && Object.keys(posture).length) {
      return Object.entries(posture).sort((a, b) => b[1] - a[1])
    }
    const map = {}
    for (const f of findings || []) {
      const raw = f.owasp_api
      if (!raw) continue
      const key = String(raw).split(':')[0].trim()
      map[key] = (map[key] || 0) + 1
    }
    return Object.entries(map).sort((a, b) => b[1] - a[1])
  }, [posture, findings])

  if (!buckets.length) return null

  const max = Math.max(...buckets.map(([, c]) => c), 1)

  return (
    <div className="rounded-2xl border border-pink-500/20 bg-pink-950/10 p-4 space-y-3">
      <p className="text-[10px] font-mono text-pink-300/70 uppercase tracking-widest">
        OWASP API Top-10 Posture
      </p>
      <div className="space-y-2">
        {buckets.map(([key, count]) => (
          <div key={key} className="space-y-1">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[10px] font-mono text-white/70">{key}</span>
              <span className="text-[10px] font-mono text-pink-300">{count}</span>
            </div>
            <div className="h-1.5 rounded-full bg-black/50 overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-pink-500/60 to-fuchsia-400/80"
                style={{ width: `${Math.round((count / max) * 100)}%` }}
              />
            </div>
            {OWASP_API_LABELS[key] && (
              <p className="text-[9px] text-white/35 leading-snug">{OWASP_API_LABELS[key]}</p>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

function SchemaTypeExplorer({ schemaGraph }) {
  const [selected, setSelected] = useState(null)
  const types = Array.isArray(schemaGraph) ? schemaGraph : []
  const active = types.find((t) => t.type === selected) || types[0]

  if (!types.length) return null

  return (
    <div className="rounded-2xl border border-white/10 bg-black/40 p-4 space-y-3">
      <p className="text-[10px] font-mono text-white/40 uppercase tracking-widest">Schema Type Explorer</p>
      <div className="flex flex-wrap gap-1.5 max-h-24 overflow-auto">
        {types.map((t) => {
          const sensitive = (t.fields || []).some((f) => /pass|secret|token|key|ssn|card|cred|hash|otp|pin/i.test(f))
          const isSel = (active?.type || types[0]?.type) === t.type
          return (
            <button
              key={t.type}
              type="button"
              onClick={() => setSelected(t.type)}
              className={`text-[10px] font-mono px-2 py-0.5 rounded border transition-colors ${isSel ? 'border-pink-400/50 bg-pink-500/15 text-pink-200' : 'border-white/10 text-white/50 hover:border-white/25'}`}
            >
              {sensitive ? '⚠ ' : ''}{t.type}
            </button>
          )
        })}
      </div>
      {active && (
        <div className="rounded-lg border border-white/10 bg-black/50 p-3">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-sm font-semibold text-white">{active.type}</span>
            <span className="text-[9px] font-mono text-white/40">{active.kind}</span>
            <span className="text-[9px] font-mono text-cyan-400/70">{active.field_count ?? (active.fields || []).length} fields</span>
          </div>
          <div className="flex flex-wrap gap-1">
            {(active.fields || []).map((f) => {
              const hot = /pass|secret|token|key|ssn|card|cred|hash|otp|pin|delete|admin|grant/i.test(f)
              return (
                <span
                  key={f}
                  className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${hot ? 'border-rose-500/40 text-rose-300 bg-rose-950/30' : 'border-white/10 text-white/55'}`}
                >
                  {f}
                </span>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

const gradeColor = (g) =>
  g === 'A' ? '#22d3ee' : g === 'B' ? '#34d399' : g === 'C' ? '#fbbf24' : g === 'D' ? '#f97316' : '#ef4444'

const sevColor = (s) =>
  s === 'critical' ? 'text-red-400' : s === 'high' ? 'text-orange-400' : s === 'medium' ? 'text-amber-400' : s === 'low' ? 'text-yellow-300' : 'text-cyan-400'

function ExecutiveSummaryStrip({ summary, onExportPdf, onExportJson }) {
  if (!summary || typeof summary !== 'object') return null
  const tier = summary.risk_tier || 'moderate'
  const tierColor = tier === 'critical' ? '#ef4444' : tier === 'elevated' ? '#f97316' : '#22d3ee'
  return (
    <div
      className="rounded-2xl border p-4 space-y-2"
      style={{ borderColor: `${tierColor}44`, background: `${tierColor}11` }}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-[10px] font-mono uppercase tracking-widest" style={{ color: tierColor }}>
          Executive Summary · {tier}
        </p>
        <div className="flex items-center gap-2">
          {summary.owasp_grade && (
            <span className="text-[10px] font-mono text-white/50">OWASP {summary.owasp_grade}</span>
          )}
          {onExportPdf && (
            <button type="button" onClick={onExportPdf} className="text-[9px] font-mono px-2 py-0.5 rounded border border-amber-500/40 text-amber-300 hover:bg-amber-500/10">
              PDF
            </button>
          )}
          {onExportJson && (
            <button type="button" onClick={onExportJson} className="text-[9px] font-mono px-2 py-0.5 rounded border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10">
              JSON
            </button>
          )}
        </div>
      </div>
      {summary.headline && (
        <p className="text-sm font-semibold text-white leading-snug">{summary.headline}</p>
      )}
      {summary.recommended_first_action && (
        <p className="text-[11px] text-white/55 leading-relaxed border-t border-white/10 pt-2">
          <span className="text-cyan-300/80 font-mono text-[10px] uppercase tracking-wide">First fix → </span>
          {summary.recommended_first_action}
        </p>
      )}
    </div>
  )
}

function ComplianceScorecardPanel({ scorecard }) {
  if (!scorecard || typeof scorecard !== 'object') return null
  const categories = Array.isArray(scorecard.categories) ? scorecard.categories : []
  if (!categories.length && !scorecard.overall_grade) return null

  return (
    <div className="rounded-2xl border border-emerald-500/25 bg-emerald-950/10 p-4 space-y-4">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <p className="text-[10px] font-mono text-emerald-300/80 uppercase tracking-widest">
          OWASP API Compliance Scorecard
        </p>
        <div className="flex items-center gap-3">
          <span
            className="text-3xl font-black font-mono"
            style={{ color: gradeColor(scorecard.overall_grade) }}
          >
            {scorecard.overall_grade || '—'}
          </span>
          <span className="text-[10px] font-mono text-white/40">
            {scorecard.overall_score ?? '—'}/100 overall
          </span>
        </div>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
        {categories.map((c) => (
          <div
            key={c.category}
            className="rounded-lg border border-white/10 bg-black/40 p-2.5 text-center"
            title={c.label}
          >
            <p className="text-lg font-bold font-mono" style={{ color: gradeColor(c.grade) }}>
              {c.grade}
            </p>
            <p className="text-[9px] font-mono text-white/50">{c.category}</p>
          </div>
        ))}
      </div>
    </div>
  )
}

function RemediationPanel({ items }) {
  const list = Array.isArray(items) ? items : []
  if (!list.length) return null

  return (
    <div className="rounded-2xl border border-cyan-500/20 bg-cyan-950/10 p-4 space-y-3">
      <p className="text-[10px] font-mono text-cyan-300/70 uppercase tracking-widest">
        Prioritized Remediation ({list.length})
      </p>
      {list.map((item, i) => (
        <div key={i} className="rounded-lg border border-white/10 bg-black/40 p-3 space-y-1">
          <div className="flex items-start gap-2">
            <span className={`text-[10px] font-mono shrink-0 ${sevColor(item.severity)}`}>
              [{item.severity || 'info'}]
            </span>
            <span className="text-xs font-semibold text-white">{item.title}</span>
          </div>
          {item.remediation && (
            <p className="text-[10px] text-cyan-200/70 leading-snug pl-1">{item.remediation}</p>
          )}
          {item.owasp_api && (
            <span className="text-[9px] font-mono text-white/35">{item.owasp_api}</span>
          )}
        </div>
      ))}
    </div>
  )
}

// ─── Page ────────────────────────────────────────────────────────────────────

export default function GraphqlSecurityCommandCenter() {
  const { t } = useTranslation()
  const engine = ENGINES_BY_ID[ENGINE_ID]
  const [clients, setClients] = useState([])
  const [selectedClientId, setSelectedClientId] = useState('')
  const { postScan } = useCommandCenterScan(selectedClientId)
  const [target, setTarget] = useState('')
  const [params, setParams] = useState(DEFAULT_PARAMS)
  useSyncHubScanParams(ENGINE_ID, params)
  const [activeProfile, setActiveProfile] = useState('comprehensive')
  const [running, setRunning] = useState(false)
  const [lines, setLines] = useState([])
  const [metrics, setMetrics] = useState(null)
  const [findings, setFindings] = useState([])
  const [showPreview, setShowPreview] = useState(false)
  const esRef = useRef(null)

  const setField = useCallback((key, val) => setParams((p) => ({ ...p, [key]: val })), [])
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
  const resetParams = useCallback(() => {
    setActiveProfile('comprehensive')
    setParams({ ...DEFAULT_PARAMS, extra_headers: [{ name: 'Authorization', value: '' }] })
  }, [])

  const loadProfile = useCallback((id) => {
    setActiveProfile(id)
    setParams(applyScanProfile(id))
  }, [])

  const previewBody = useMemo(() => buildScanBody(params, selectedClientId || 0, target), [params, selectedClientId, target])
  const paramCount = useMemo(() => Object.keys(previewBody).length, [previewBody])

  const attackPaths = useMemo(() => findings.filter((f) => f.category === 'attack_path'), [findings])
  const realFindings = useMemo(
    () => findings.filter((f) => f.category !== 'attack_path' && f.category !== 'graphql_metrics'),
    [findings],
  )

  const exportPostureJson = useCallback(() => {
    const payload = {
      engine: ENGINE_ID,
      target,
      generated_at: new Date().toISOString(),
      metrics,
      executive_summary: metrics?.executive_summary,
      compliance_scorecard: metrics?.compliance_scorecard,
      remediation_priorities: metrics?.remediation_priorities,
      owasp_posture: metrics?.owasp_posture,
      findings: realFindings,
      attack_paths: attackPaths,
    }
    downloadBytes(
      new TextEncoder().encode(JSON.stringify(payload, null, 2)),
      `graphql-posture-${Date.now()}.json`,
      'application/json',
    )
  }, [target, metrics, realFindings, attackPaths])

  const exportExecutivePdf = useCallback(() => {
    const ex = metrics?.executive_summary
    const card = metrics?.compliance_scorecard
    const lines = [
      'Weissman GraphQL & API Security — Executive Report',
      `Generated: ${new Date().toISOString()}`,
      `Target: ${target || '—'}`,
      '',
      ex?.headline || 'No executive summary yet',
      `Risk tier: ${ex?.risk_tier || '—'}`,
      `Exposure score: ${metrics?.exposure_score ?? '—'}/100`,
      `OWASP grade: ${card?.overall_grade || ex?.owasp_grade || '—'}`,
      `Components probed: ${ex?.components_probed ?? metrics?.components_probed ?? '—'}`,
      '',
      'Recommended first action:',
      ex?.recommended_first_action || '—',
      '',
      'Top remediations:',
    ]
    for (const r of (metrics?.remediation_priorities || []).slice(0, 8)) {
      lines.push(`- [${r.severity}] ${r.title}: ${r.remediation || ''}`)
    }
    lines.push('', 'OWASP API categories:')
    for (const c of card?.categories || []) {
      lines.push(`- ${c.category} ${c.grade} (${c.score}) — ${c.label}`)
    }
    downloadBytes(buildSimpleTextPdf(lines), `graphql-executive-${Date.now()}.pdf`, 'application/pdf')
  }, [target, metrics])

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
        const meta = run.findings.find((x) => x.graphql_metrics)?.graphql_metrics
        if (meta) setMetrics(meta)
      }
    })
  }, [refreshFromHistory, setLastUpdated, setLastJobId])

  const handleRefresh = useCallback(async () => {
    const run = await refreshFromHistory()
    if (applyHistoryFindings(run, setFindings, { setLastUpdated, setJobId: setLastJobId })) {
      const meta = run.findings.find((x) => x.graphql_metrics)?.graphql_metrics
      if (meta) setMetrics(meta)
    }
  }, [refreshFromHistory, setLastUpdated, setLastJobId])

  const appendLine = useCallback((msg) => setLines((prev) => [...prev.slice(-400), msg]), [])

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

  useEffect(() => () => { if (esRef.current) esRef.current.close() }, [])

  const handleRun = useCallback(async (opts = {}) => {
    const dryRun = !!opts.dryRun || !!params.dry_run
    if (!selectedClientId || !target.trim()) return
    setRunning(true)
    setLines([])
    setMetrics(null)
    setFindings([])
    appendLine(`[GraphQL] ${dryRun ? 'Planning dry-run' : 'Launching API security assessment'} — ${paramCount} params…`)

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
      appendLine(`[GraphQL] Job queued: ${jobId}`)
      if (esRef.current) esRef.current.close()
      const es = openSseStream(`/api/telemetry/stream?job_id=${jobId}`)
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
                setLastUpdated(new Date().toISOString())
                if (jobId) setLastJobId(jobId)
                const meta = f.find((x) => x.graphql_metrics)?.graphql_metrics
                if (meta) setMetrics(meta)
                appendLine(`[GraphQL] ${dryRun ? 'Dry-run complete' : 'Assessment complete'} — ${f.length} findings`)
              })
              .catch(() => {})
          }
        } catch { /* ignore */ }
      }
      es.onerror = () => { es.close(); setRunning(false) }
    } catch (e) {
      appendLine(`[ERROR] ${e.message}`)
      setRunning(false)
    }
  }, [selectedClientId, target, params, paramCount, appendLine])

  return (
    <PageShell
      hideHubParams
      title={t('graphqlSec.title', 'GraphQL & API Security Command Center')}
      subtitle={t('graphqlSec.subtitle', 'Agentless GraphQL attack-surface mapping — introspection, schema reconstruction, DoS & CSRF analysis, graded against OWASP API Top-10')}
      badge="API Security"
      badgeColor="#f472b6"
      icon="◈"
      actions={(
        <ShellScanActions
          onRefresh={handleRefresh}
          onExport={exportCsv}
          refreshLoading={historyLoading}
          refreshDisabled={running}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="space-y-6">
        {/* Hero strip */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          className="relative overflow-hidden rounded-2xl border border-pink-500/30 bg-gradient-to-br from-pink-950/40 via-black/60 to-fuchsia-950/30 p-6"
        >
          <div className="absolute inset-0 opacity-30" style={{ background: 'radial-gradient(circle at 20% 50%, rgba(236,72,153,0.4), transparent 50%), radial-gradient(circle at 80% 50%, rgba(217,70,239,0.2), transparent 50%)' }} />
          <div className="relative flex flex-wrap items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-pink-400/40 text-pink-300 bg-pink-500/10 uppercase tracking-widest">
                  API Security · GraphQL
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-emerald-400/30 text-emerald-300 bg-emerald-500/10 uppercase tracking-widest">
                  {paramCount} {t('graphqlSec.params_badge', 'live parameters')}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-violet-400/30 text-violet-300 bg-violet-500/10 uppercase tracking-widest">
                  41 {t('graphqlSec.probe_components', 'probe components')}
                </span>
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">
                {engine?.label || 'GraphQL & API Security'}
              </h1>
              <p className="text-sm text-white/50 mt-1 max-w-2xl leading-relaxed">
                {t('graphqlSec.hero_desc', 'Evidence-only remote assessment: every finding is backed by a real HTTP observation. No mutations are ever executed.')}
              </p>
            </div>
            <div className="flex gap-2 flex-wrap">
              <Link to={`/engines/${ENGINE_ID}`} className="text-[11px] font-mono px-3 py-1.5 rounded-lg border border-white/15 text-white/60 hover:text-white hover:border-white/30 transition-colors">
                Engine Detail →
              </Link>
            </div>
          </div>
        </motion.div>

        {/* Scan profiles */}
        <div className="flex flex-wrap gap-2">
          {SCAN_PROFILES.map((p) => (
            <button
              key={p.id}
              type="button"
              onClick={() => loadProfile(p.id)}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-xl border text-left transition-all ${activeProfile === p.id ? 'border-pink-400/50 bg-pink-500/10' : 'border-white/10 bg-black/40 hover:border-white/25'}`}
              style={activeProfile === p.id ? { boxShadow: `0 0 20px ${p.color}25` } : undefined}
            >
              <span className="text-lg">{p.icon}</span>
              <div>
                <p className="text-xs font-semibold text-white">{p.label}</p>
                <p className="text-[10px] text-white/40 max-w-xs leading-snug">{p.desc}</p>
              </div>
            </button>
          ))}
        </div>

        {/* Main layout: control column + live theatre */}
        <div className="grid grid-cols-1 xl:grid-cols-[400px_1fr] gap-6 items-start">
          {/* ───────── Control Column ───────── */}
          <div className="xl:sticky xl:top-4 space-y-3 xl:max-h-[calc(100dvh-2rem)] xl:overflow-y-auto pr-1">
            <div className="rounded-2xl border border-pink-500/25 bg-gradient-to-b from-pink-950/30 to-black/50 p-3">
              <div className="flex items-center justify-between mb-2 px-1">
                <h2 className="text-sm font-bold text-white tracking-tight flex items-center gap-2">
                  <span>🎛️</span> {t('graphqlSec.control_column', 'API Security Control Column')}
                </h2>
                <button
                  type="button"
                  onClick={resetParams}
                  className="text-[9px] font-mono uppercase tracking-wide px-2 py-1 rounded-md border border-white/10 text-white/40 hover:text-white/70 hover:border-white/25 transition-colors"
                >
                  {t('common.reset', 'Reset')}
                </button>
              </div>

              {/* Target Binding */}
              <Section title={t('graphqlSec.sec_target', 'Target Binding')} icon="🎯" accent="#22d3ee" count={2}>
                <label className="block space-y-1">
                  <span className="text-[10px] font-mono text-white/45 uppercase tracking-wide">{t('common.client', 'Client')}</span>
                  <select
                    value={selectedClientId}
                    onChange={(e) => setSelectedClientId(e.target.value)}
                    className="w-full rounded-lg bg-black/50 border border-white/10 px-3 py-1.5 text-sm text-white focus:outline-none focus:border-pink-400/40"
                  >
                    <option value="">—</option>
                    {clients.map((c) => (
                      <option key={c.id} value={c.id}>{c.name || c.id}</option>
                    ))}
                  </select>
                </label>
                <Txt label={t('common.target', 'Target')} value={target} onChange={setTarget} placeholder="https://api.example.com" />
              </Section>

              {/* Probe Scope — discovery */}
              <Section title={t('graphqlSec.sec_scope', 'Probe Scope')} icon="🧩" accent="#f472b6" count={10}>
                <Toggle label="Introspection" value={params.probe_introspection} onChange={(v) => setField('probe_introspection', v)} hint="Full __schema extraction → schema graph" />
                <Toggle label="Field Suggestions" value={params.probe_suggestions} onChange={(v) => setField('probe_suggestions', v)} hint="'Did you mean' info leak" />
                <Toggle label="Schema Reconstruction" value={params.probe_schema_recon} onChange={(v) => setField('probe_schema_recon', v)} hint="Clairvoyance-style recovery when introspection is off" />
                <Toggle label="Introspection Bypass (__type)" value={params.probe_introspection_bypass} onChange={(v) => setField('probe_introspection_bypass', v)} hint="Partial __type when __schema blocked" />
                <Toggle label="Federation SDL (_service)" value={params.probe_federation} onChange={(v) => setField('probe_federation', v)} hint="Apollo subgraph schema leak" />
                <Toggle label="Implementation Fingerprint" value={params.probe_fingerprint} onChange={(v) => setField('probe_fingerprint', v)} />
                <Toggle label="IDE Exposure" value={params.probe_ide_exposure} onChange={(v) => setField('probe_ide_exposure', v)} hint="GraphiQL / Playground / Apollo Sandbox" />
                <Toggle label="Subscription WebSocket" value={params.probe_subscription_ws} onChange={(v) => setField('probe_subscription_ws', v)} hint="graphql-ws / graphql-transport-ws upgrade" />
                <Toggle label="Upload Scalar / Multipart" value={params.probe_upload_scalar} onChange={(v) => setField('probe_upload_scalar', v)} />
                <Toggle label="Auth Differential" value={params.probe_auth_differential} onChange={(v) => setField('probe_auth_differential', v)} hint="Compare auth vs anonymous introspection" />
                <Toggle label="BOLA / IDOR Surface" value={params.probe_bola} onChange={(v) => setField('probe_bola', v)} hint="Schema-derived ID probes — read-only object fetch" />
                <Toggle label="@defer / @stream" value={params.probe_defer_stream} onChange={(v) => setField('probe_defer_stream', v)} hint="Incremental delivery abuse surface" />
                <Toggle label="Subscription SSE" value={params.probe_subscription_sse} onChange={(v) => setField('probe_subscription_sse', v)} hint="GraphQL over Server-Sent Events" />
              </Section>

              {/* Probe Scope — DoS / abuse */}
              <Section title={t('graphqlSec.sec_dos_probes', 'DoS & Abuse Probes')} icon="💥" accent="#ef4444" count={7} defaultOpen={false}>
                <Toggle label="Batching DoS" value={params.probe_batching} onChange={(v) => setField('probe_batching', v)} />
                <Toggle label="Alias Amplification" value={params.probe_alias_overload} onChange={(v) => setField('probe_alias_overload', v)} />
                <Toggle label="Depth / Cost Limit" value={params.probe_depth} onChange={(v) => setField('probe_depth', v)} />
                <Toggle label="Field Duplication" value={params.probe_field_duplication} onChange={(v) => setField('probe_field_duplication', v)} />
                <Toggle label="Fragment Cycle" value={params.probe_fragment_cycle} onChange={(v) => setField('probe_fragment_cycle', v)} />
                <Toggle label="Directive Stacking" value={params.probe_directive_abuse} onChange={(v) => setField('probe_directive_abuse', v)} />
                <Toggle label="Rate-Limit Burst" value={params.probe_rate_limit} onChange={(v) => setField('probe_rate_limit', v)} hint="Rapid identical queries → 429 check" />
              </Section>

              {/* Probe Scope — transport / CSRF */}
              <Section title={t('graphqlSec.sec_transport_probes', 'Transport & CSRF Probes')} icon="📡" accent="#38bdf8" count={6} defaultOpen={false}>
                <Toggle label="CSRF (GET / form)" value={params.probe_csrf_get} onChange={(v) => setField('probe_csrf_get', v)} />
                <Toggle label="Error Verbosity / Debug" value={params.probe_error_verbosity} onChange={(v) => setField('probe_error_verbosity', v)} />
                <Toggle label="application/graphql CT" value={params.probe_content_type_graphql} onChange={(v) => setField('probe_content_type_graphql', v)} />
                <Toggle label="Multi-Operation String" value={params.probe_multi_operation} onChange={(v) => setField('probe_multi_operation', v)} />
                <Toggle label="Apollo Tracing Leak" value={params.probe_tracing} onChange={(v) => setField('probe_tracing', v)} />
                <Toggle label="APQ / Persisted Query Bypass" value={params.probe_apq} onChange={(v) => setField('probe_apq', v)} />
              </Section>

              {/* Advanced API probes — world-class layer */}
              <Section title={t('graphqlSec.sec_advanced', 'Advanced API Probes')} icon="⚡" accent="#eab308" count={11} defaultOpen={false}>
                <Toggle label="BOLA Alias-Batch" value={params.probe_bola_batch} onChange={(v) => setField('probe_bola_batch', v)} hint="Multiple IDs in one aliased query — rate-limit bypass" />
                <Toggle label="CORS Misconfiguration" value={params.probe_cors} onChange={(v) => setField('probe_cors', v)} hint="OPTIONS/POST Origin reflection" />
                <Toggle label="CSWSH (WebSocket Origin)" value={params.probe_cswsh} onChange={(v) => setField('probe_cswsh', v)} hint="Cross-Site WebSocket Hijacking surface" />
                <Toggle label="Variable Tampering" value={params.probe_variable_tampering} onChange={(v) => setField('probe_variable_tampering', v)} hint="Type confusion / injection in variables" />
                <Toggle label="Query Cost Leak" value={params.probe_query_cost} onChange={(v) => setField('probe_query_cost', v)} hint="Complexity/cost in extensions or headers" />
                <Toggle label="GET Cache Poisoning" value={params.probe_get_cache} onChange={(v) => setField('probe_get_cache', v)} hint="Cacheable GET GraphQL responses" />
                <Toggle label="Field Auth Differential" value={params.probe_field_auth_diff} onChange={(v) => setField('probe_field_auth_diff', v)} hint="me/viewer with vs without credentials" />
                <Toggle label="Interface/Union Leak" value={params.probe_interface_leak} onChange={(v) => setField('probe_interface_leak', v)} hint="possibleTypes polymorphic metadata" />
                <Toggle label="Nested BOLA Chains" value={params.probe_bola_nested} onChange={(v) => setField('probe_bola_nested', v)} hint="Parent→child ID paths (user→orders)" />
                <Toggle label="Operation Allowlist Fuzz" value={params.probe_operation_allowlist} onChange={(v) => setField('probe_operation_allowlist', v)} hint="APQ hash-only + operationName GET" />
                <Toggle label="Hasura Hardening" value={params.probe_hasura_surface} onChange={(v) => setField('probe_hasura_surface', v)} hint="x-hasura-role spoof + mgmt paths" />
              </Section>

              <Section title={t('graphqlSec.sec_final', 'Final-Round Probes')} icon="🏆" accent="#f59e0b" count={5} defaultOpen={false}>
                <Toggle label="Relay Global-ID BOLA" value={params.probe_relay_global_id} onChange={(v) => setField('probe_relay_global_id', v)} hint="Apollo/Relay base64 type:id enumeration" />
                <Toggle label="Pagination Abuse" value={params.probe_pagination_abuse} onChange={(v) => setField('probe_pagination_abuse', v)} hint="Connection first:N bulk harvest" />
                <Toggle label="Limit Fingerprint" value={params.probe_limit_fingerprint} onChange={(v) => setField('probe_limit_fingerprint', v)} hint="Alias/depth ceiling discovery" />
                <Toggle label="WAF / Introspection Evasion" value={params.probe_waf_evasion} onChange={(v) => setField('probe_waf_evasion', v)} hint="CT/comment/operationName bypass variants" />
                <Toggle label="Live Data Leak" value={params.probe_live_data_leak} onChange={(v) => setField('probe_live_data_leak', v)} hint="Populated users/me/orders without auth gate" />
              </Section>

              {/* Endpoint surface */}
              <Section title={t('graphqlSec.sec_endpoints', 'Endpoint Surface')} icon="🛰️" accent="#34d399" count={1} defaultOpen={false}>
                <Area
                  label="GraphQL Paths"
                  value={params.graphql_paths}
                  onChange={(v) => setField('graphql_paths', v)}
                  rows={4}
                  placeholder={'one per line — empty = built-in defaults\n/graphql\n/api/graphql\n/v1/graphql'}
                  hint="Probed under the target origin"
                />
              </Section>

              {/* DoS tuning */}
              <Section title={t('graphqlSec.sec_dos', 'DoS Tuning')} icon="⚙️" accent="#ef4444" count={6} defaultOpen={false}>
                <div className="grid grid-cols-2 gap-2">
                  <Num label="Alias Count" value={params.alias_count} onChange={(v) => setField('alias_count', v)} min={2} max={5000} hint="Amount-limit test" />
                  <Num label="Batch Count" value={params.batch_count} onChange={(v) => setField('batch_count', v)} min={2} max={1000} />
                  <Num label="Depth Levels" value={params.depth_levels} onChange={(v) => setField('depth_levels', v)} min={2} max={60} hint="Nested-query depth" />
                  <Num label="Field Duplication" value={params.field_duplication_count} onChange={(v) => setField('field_duplication_count', v)} min={2} max={5000} />
                  <Num label="Burst Count" value={params.burst_count} onChange={(v) => setField('burst_count', v)} min={2} max={100} hint="Rate-limit probe" />
                  <Num label="Fragment Depth" value={params.fragment_spread_depth} onChange={(v) => setField('fragment_spread_depth', v)} min={2} max={40} />
                </div>
              </Section>

              {/* BOLA tuning */}
              <Section title={t('graphqlSec.sec_bola', 'BOLA / IDOR Tuning')} icon="🎯" accent="#fb7185" count={5} defaultOpen={false}>
                <Num label="Max BOLA Probes" value={params.max_bola_probes} onChange={(v) => setField('max_bola_probes', v)} min={1} max={32} hint="ID-gated fields to test per endpoint" />
                <Num label="BOLA Batch Size" value={params.bola_batch_size} onChange={(v) => setField('bola_batch_size', v)} min={2} max={32} hint="IDs aliased in one request" />
                <div className="grid grid-cols-2 gap-2">
                  <Num label="ID Range Start" value={params.bola_id_range_start} onChange={(v) => setField('bola_id_range_start', v)} min={0} max={999999} hint="0 = disabled" />
                  <Num label="ID Range End" value={params.bola_id_range_end} onChange={(v) => setField('bola_id_range_end', v)} min={0} max={999999} hint="Merged with test IDs (cap 32)" />
                </div>
                <Area
                  label="Test IDs"
                  value={params.bola_test_ids}
                  onChange={(v) => setField('bola_test_ids', v)}
                  rows={3}
                  placeholder={'one per line\n1\n2\n100'}
                  hint="Predictable IDs probed against schema-derived accessors"
                />
              </Section>

              {/* Schema reconstruction */}
              <Section title={t('graphqlSec.sec_recon', 'Schema Reconstruction')} icon="🧠" accent="#a855f7" count={2} defaultOpen={false}>
                <Num label="Max Recon Fields" value={params.max_recon_fields} onChange={(v) => setField('max_recon_fields', v)} min={1} max={500} hint="Suggestion probes (Clairvoyance)" />
                <Area
                  label="Recon Field Wordlist"
                  value={params.recon_fields}
                  onChange={(v) => setField('recon_fields', v)}
                  rows={3}
                  placeholder={'one per line — empty = built-in defaults\nuser\norders\nsecrets'}
                />
              </Section>

              {/* Auth credentials */}
              <Section title={t('graphqlSec.sec_auth', 'Authentication Plane')} icon="🔐" accent="#a855f7" count={4} defaultOpen={false}>
                <Txt label="Bearer Token" value={params.bearer_token} onChange={(v) => setField('bearer_token', v)} placeholder="eyJ…" hint="Sent as Authorization: Bearer …" />
                <div className="grid grid-cols-2 gap-2">
                  <Txt label="API Key" value={params.api_key} onChange={(v) => setField('api_key', v)} placeholder="sk-…" />
                  <Txt label="API Key Header" value={params.api_key_header} onChange={(v) => setField('api_key_header', v)} placeholder="X-API-Key" />
                </div>
                <Txt label="Cookie" value={params.cookie} onChange={(v) => setField('cookie', v)} placeholder="session=…" />
              </Section>

              {/* Transport / HTTP */}
              <Section title={t('graphqlSec.sec_transport', 'Transport / HTTP')} icon="📡" accent="#38bdf8" count={7} defaultOpen={false}>
                <div className="grid grid-cols-2 gap-2">
                  <Num label="Timeout (ms)" value={params.timeout_ms} onChange={(v) => setField('timeout_ms', v)} min={500} max={60000} />
                  <Num label="Connect TO (ms)" value={params.connect_timeout_ms} onChange={(v) => setField('connect_timeout_ms', v)} min={200} max={30000} />
                  <Num label="Max Concurrency" value={params.max_concurrency} onChange={(v) => setField('max_concurrency', v)} min={1} max={64} />
                </div>
                <Toggle label="Follow Redirects" value={params.follow_redirects} onChange={(v) => setField('follow_redirects', v)} />
                <Toggle label="Verify TLS" value={params.verify_tls} onChange={(v) => setField('verify_tls', v)} hint="Off = accept invalid certs" />
                <Txt label="User-Agent" value={params.user_agent} onChange={(v) => setField('user_agent', v)} placeholder="(default GraphQLSec UA)" />
                <div className="space-y-1.5">
                  <span className="text-[10px] font-mono text-white/45 uppercase tracking-wide">Auth / Custom Headers</span>
                  {params.extra_headers.map((h, i) => (
                    <div key={i} className="flex items-center gap-1.5">
                      <input
                        value={h.name}
                        onChange={(e) => setHeader(i, 'name', e.target.value)}
                        placeholder="Header"
                        className="w-2/5 rounded-lg bg-black/50 border border-white/10 px-2 py-1 text-[11px] text-white font-mono placeholder-white/20 focus:outline-none focus:border-pink-400/40"
                      />
                      <input
                        value={h.value}
                        onChange={(e) => setHeader(i, 'value', e.target.value)}
                        placeholder="Value (e.g. Bearer …)"
                        className="flex-1 rounded-lg bg-black/50 border border-white/10 px-2 py-1 text-[11px] text-white font-mono placeholder-white/20 focus:outline-none focus:border-pink-400/40"
                      />
                      <button type="button" onClick={() => removeHeader(i)} className="text-white/30 hover:text-rose-400 text-sm px-1">✕</button>
                    </div>
                  ))}
                  <button type="button" onClick={addHeader} className="text-[10px] font-mono text-pink-300/70 hover:text-pink-200">+ {t('graphqlSec.add_header', 'add header')}</button>
                </div>
              </Section>

              {/* Output & posture */}
              <Section title={t('graphqlSec.sec_output', 'Output & Posture')} icon="🎚️" accent="#94a3b8" count={6} defaultOpen={false}>
                <Sel label="Min Severity" value={params.min_severity} onChange={(v) => setField('min_severity', v)} options={HTTP_SEVERITIES} hint="Drop findings below this rank (attack paths always kept)" />
                <Num label="Max Findings" value={params.max_findings} onChange={(v) => setField('max_findings', v)} min={1} max={5000} />
                <Toggle label="Attack-Path Synthesis" value={params.attack_path_synthesis} onChange={(v) => setField('attack_path_synthesis', v)} hint="Wiz-style toxic-combination analysis" />
                <Toggle label="Dedupe Findings" value={params.dedupe_findings} onChange={(v) => setField('dedupe_findings', v)} />
                <Toggle label="Emit Metrics Summary" value={params.emit_metrics} onChange={(v) => setField('emit_metrics', v)} />
                <Toggle label="Dry Run (plan only)" value={params.dry_run} onChange={(v) => setField('dry_run', v)} hint="Compute the plan without sending requests" />
                <Txt label="Tags (csv)" value={params.tags} onChange={(v) => setField('tags', v)} placeholder="api-audit, q3" />
              </Section>

              {/* Payload preview */}
              <Section title={t('graphqlSec.sec_payload', 'Live Payload Preview')} icon="📦" accent="#64748b" count={paramCount} defaultOpen={false}>
                <button type="button" onClick={() => setShowPreview((s) => !s)} className="text-[10px] font-mono text-pink-300/70 hover:text-pink-200">
                  {showPreview ? t('graphqlSec.hide_json', 'hide JSON') : t('graphqlSec.show_json', 'show exact request JSON')}
                </button>
                {showPreview && (
                  <pre className="max-h-60 overflow-auto rounded-lg bg-black/60 border border-white/10 p-2.5 text-[10px] font-mono text-emerald-300/80 leading-relaxed">
                    {JSON.stringify(previewBody, null, 2)}
                  </pre>
                )}
              </Section>

              {/* Actions */}
              <div className="mt-3 space-y-2">
                <button
                  type="button"
                  onClick={() => handleRun()}
                  disabled={running || !selectedClientId || !target.trim()}
                  className="w-full py-3 rounded-xl font-mono text-sm uppercase tracking-widest border transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                  style={{
                    borderColor: running ? 'rgba(244,114,182,0.5)' : 'rgba(236,72,153,0.6)',
                    background: running ? 'rgba(236,72,153,0.15)' : 'rgba(236,72,153,0.25)',
                    color: '#fbcfe8',
                    boxShadow: running ? 'none' : '0 0 24px rgba(236,72,153,0.2)',
                  }}
                >
                  {running ? t('graphqlSec.running', 'Assessing API…') : t('graphqlSec.run', 'Run API Security Scan')}
                </button>
                <button
                  type="button"
                  onClick={() => handleRun({ dryRun: true })}
                  disabled={running || !selectedClientId || !target.trim()}
                  className="w-full py-2 rounded-xl font-mono text-[11px] uppercase tracking-widest border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                >
                  {t('graphqlSec.dry_run', 'Dry-Run Plan (no requests)')}
                </button>
              </div>
            </div>
          </div>

          {/* ───────── Live theatre ───────── */}
          <div className="space-y-6 min-w-0">
            <div className="grid grid-cols-1 2xl:grid-cols-3 gap-6">
              <div className="2xl:col-span-2 rounded-2xl border border-white/10 bg-black/40 overflow-hidden">
                <div className="px-4 py-3 border-b border-white/5 flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase tracking-[0.2em] text-white/40">
                    {t('graphqlSec.schema_viz', 'Live Schema Graph')}
                  </span>
                  {running && (
                    <span className="flex items-center gap-1.5 text-[10px] font-mono text-pink-300">
                      <span className="w-1.5 h-1.5 rounded-full bg-pink-400 animate-pulse" />
                      {params.dry_run ? 'PLANNING' : 'SCANNING'}
                    </span>
                  )}
                </div>
                <div className="h-72 md:h-80">
                  <SchemaGraphCanvas schemaGraph={metrics?.schema_graph} running={running} />
                </div>
              </div>

              <div className="space-y-4">
                <div className="rounded-2xl border border-white/10 bg-black/40 p-5 text-center">
                  <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-white/40 mb-3">
                    {t('graphqlSec.exposure_score', 'API Exposure Score')}
                  </p>
                  <ExposureGauge score={metrics?.exposure_score} />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <MetricTile label="Endpoints" value={metrics?.endpoints_found} accent="#22d3ee" />
                  <MetricTile label="Introspectable" value={metrics?.introspectable_endpoints} accent="#f59e0b" />
                  <MetricTile label="DoS Vectors" value={metrics?.dos_vectors} accent="#ef4444" />
                  <MetricTile label="Attack Paths" value={metrics?.attack_paths} accent="#a855f7" />
                  <MetricTile label="Components" value={metrics?.components_probed} accent="#34d399" />
                  <MetricTile label="High / Crit" value={metrics ? `${metrics.highs ?? 0} / ${metrics.criticals ?? 0}` : null} accent="#fb7185" />
                </div>
                {metrics?.implementation && (
                  <div className="rounded-xl border border-white/10 bg-black/40 p-3 text-center">
                    <p className="text-[9px] font-mono uppercase tracking-[0.2em] text-white/35 mb-1">Implementation</p>
                    <p className="text-sm font-bold text-pink-300">{metrics.implementation}</p>
                  </div>
                )}
              </div>
            </div>

            <ExecutiveSummaryStrip
              summary={metrics?.executive_summary}
              onExportPdf={metrics?.executive_summary ? exportExecutivePdf : undefined}
              onExportJson={metrics ? exportPostureJson : undefined}
            />

            <ComplianceScorecardPanel scorecard={metrics?.compliance_scorecard} />

            <OwaspBreakdownPanel posture={metrics?.owasp_posture} findings={realFindings} />

            <RemediationPanel items={metrics?.remediation_priorities} />

            <SchemaTypeExplorer schemaGraph={metrics?.schema_graph} />

            {/* Attack paths */}
            <AnimatePresence>
              {attackPaths.length > 0 && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="rounded-2xl border border-fuchsia-500/20 bg-fuchsia-950/10 p-4 space-y-3"
                >
                  <p className="text-[10px] font-mono text-fuchsia-300/70 uppercase tracking-widest">
                    {t('graphqlSec.attack_paths', 'Attack Paths (Toxic Combinations)')} · {attackPaths.length}
                  </p>
                  {attackPaths.map((p, i) => (
                    <div key={i} className="rounded-lg border border-white/10 bg-black/40 p-3">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`text-[10px] font-mono ${sevColor(p.severity)}`}>[{p.severity}]</span>
                        <span className="text-sm font-semibold text-white">{p.title}</span>
                      </div>
                      <div className="flex flex-wrap items-center gap-1.5 mt-2">
                        {(p.path_steps || []).map((step, j) => (
                          <React.Fragment key={j}>
                            <span className="text-[10px] font-mono text-white/60 rounded border border-white/10 bg-black/40 px-1.5 py-0.5">{step}</span>
                            {j < (p.path_steps.length - 1) && <span className="text-fuchsia-400/60 text-xs">→</span>}
                          </React.Fragment>
                        ))}
                      </div>
                    </div>
                  ))}
                </motion.div>
              )}
            </AnimatePresence>

            {/* Telemetry */}
            <div className="rounded-2xl border border-white/10 bg-black/60 overflow-hidden">
              <div className="px-4 py-2 border-b border-white/5 text-[10px] font-mono text-white/40 uppercase tracking-widest">
                {t('graphqlSec.telemetry', 'Scan Telemetry')}
              </div>
              <pre className="h-44 overflow-auto p-3 text-[10px] font-mono text-emerald-400/80 leading-relaxed">
                {lines.length ? lines.join('\n') : t('graphqlSec.awaiting', 'Awaiting assessment…')}
              </pre>
            </div>

            {/* Findings */}
            <WeissmanFindingsPanel
              findings={realFindings}
              filteredFindings={filteredFindings}
              counts={counts}
              total={realFindings.length}
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              severityFilter={severityFilter}
              onSeverityChange={setSeverityFilter}
              pending={running && realFindings.length === 0}
              loading={historyLoading && realFindings.length === 0}
              lastUpdated={lastUpdated}
              jobId={lastJobId}
              accent="#f472b6"
              showEmptyReady={!running && realFindings.length === 0}
              renderFinding={(f, i) => (
                <div key={i} className="text-[11px] border-b border-white/5 pb-2 last:border-0">
                  <div className="flex items-start gap-2">
                    <span className={`font-mono shrink-0 ${sevColor(f.severity)}`}>[{f.severity || 'info'}]</span>
                    <span className="text-white/80 min-w-0 font-semibold">{f.title}</span>
                  </div>
                  {f.description && <p className="text-[10px] text-white/40 ml-1 mt-0.5 leading-snug">{f.description}</p>}
                  <div className="flex flex-wrap gap-1.5 ml-1 mt-1">
                    {f.owasp_api && <span className="text-[9px] font-mono text-pink-300/70 rounded border border-pink-500/20 px-1.5 py-0.5">{f.owasp_api}</span>}
                    {f.component && <span className="text-[9px] font-mono text-white/40 rounded border border-white/10 px-1.5 py-0.5">{f.component}</span>}
                    {f.mitre_attack && <span className="text-[9px] font-mono text-white/30 rounded border border-white/10 px-1.5 py-0.5">{f.mitre_attack}</span>}
                  </div>
                </div>
              )}
            />
          </div>
        </div>
      </div>
    </PageShell>
  )
}
