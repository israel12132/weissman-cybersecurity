import { firstClientTarget } from '../lib/clientTarget'
import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import { useState, useEffect, useCallback, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../lib/apiBase'
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'
import Button from '../components/ui/Button'

const ENGINE = 'websocket_attack'
const ACCENT = '#22d3ee'

const PRESETS = {
  weissman_quick: {
    label: 'Weissman Quick',
    hint: 'Light intensity · handshake + CSWSH core',
    values: {
      intensity: 'light',
      check_message_probe: false,
      check_ws_rate_limit: false,
      check_binary_frames: false,
      check_graphql_introspection: false,
      check_auth_differential: false,
    },
  },
  cswsh_audit: {
    label: 'CSWSH Audit',
    hint: 'Origin validation + session-riding focus',
    values: {
      intensity: 'normal',
      check_cswsh: true,
      check_null_origin: true,
      check_missing_origin: true,
      check_forwarded_bypass: true,
      check_host_injection: true,
      check_foreign_origin_messages: true,
      check_auth_differential: true,
      check_message_probe: true,
    },
  },
  realtime_full: {
    label: 'Real-Time API Full',
    hint: 'SignalR · Socket.IO · GraphQL-ws · STOMP · live sessions',
    values: {
      intensity: 'aggressive',
      check_signalr_negotiate: true,
      check_socketio_polling: true,
      check_subprotocols: true,
      check_message_probe: true,
      check_graphql_subscribe: true,
      check_graphql_introspection: true,
      check_stomp_connect: true,
      check_sensitive_leak: true,
    },
  },
  weissman_full: {
    label: 'Weissman Ultra',
    hint: 'Every probe · aggressive caps · full posture',
    values: {
      intensity: 'aggressive',
      check_cswsh: true,
      check_null_origin: true,
      check_missing_origin: true,
      check_forwarded_bypass: true,
      check_host_injection: true,
      check_ws_version_downgrade: true,
      check_message_probe: true,
      check_sensitive_leak: true,
      check_graphql_subscribe: true,
      check_graphql_introspection: true,
      check_stomp_connect: true,
      check_auth_differential: true,
      check_foreign_origin_messages: true,
      check_ws_rate_limit: true,
      check_binary_frames: true,
      check_stateful_fuzz: true,
      check_binary_mutation: true,
      check_race_conditions: true,
      check_cross_protocol_chain: true,
      check_js_harvest: true,
      attack_path_synthesis: true,
      posture_scoring: true,
    },
  },
}

const TOGGLE_GROUPS = [
  {
    id: 'handshake',
    labelKey: 'pages.websocketSecurity.groups.handshake',
    defaultLabel: 'Handshake & transport',
    items: [
      { key: 'check_compression', label: 'permessage-deflate', hint: 'CRIME/BREACH side-channel surface' },
      { key: 'check_cleartext', label: 'Cleartext ws://', hint: 'Unencrypted transport on HTTP origin' },
      { key: 'check_tls_downgrade', label: 'TLS downgrade', hint: 'http:// handshake on HTTPS origin' },
      { key: 'check_ws_version_downgrade', label: 'Protocol version downgrade', hint: 'Sec-WebSocket-Version 8/7' },
      { key: 'check_host_injection', label: 'Host-header smuggling', hint: 'Evil Host on upgrade' },
    ],
  },
  {
    id: 'cswsh',
    labelKey: 'pages.websocketSecurity.groups.cswsh',
    defaultLabel: 'CSWSH & Origin',
    items: [
      { key: 'check_cswsh', label: 'Multi-origin CSWSH', hint: 'Differential foreign Origin' },
      { key: 'check_null_origin', label: 'Null-Origin', hint: 'Sandboxed iframe class' },
      { key: 'check_missing_origin', label: 'Missing Origin', hint: 'No Origin header' },
      { key: 'check_forwarded_bypass', label: 'X-Forwarded-* bypass', hint: 'Proxy Origin reconstruction' },
      { key: 'check_foreign_origin_messages', label: 'Foreign-origin live data', hint: 'Message-layer CSWSH' },
    ],
  },
  {
    id: 'stacks',
    labelKey: 'pages.websocketSecurity.groups.stacks',
    defaultLabel: 'Real-time stacks',
    items: [
      { key: 'check_subprotocols', label: 'Subprotocol smuggling', hint: 'graphql-ws / STOMP / OCPP' },
      { key: 'check_signalr_negotiate', label: 'SignalR /negotiate', hint: 'connectionToken exposure' },
      { key: 'check_socketio_polling', label: 'Socket.IO polling sid', hint: 'Engine.IO session id' },
      { key: 'check_js_harvest', label: 'JS URL harvest', hint: 'Mine page for ws:// paths' },
    ],
  },
  {
    id: 'messages',
    labelKey: 'pages.websocketSecurity.groups.messages',
    defaultLabel: 'Post-handshake sessions',
    items: [
      { key: 'check_message_probe', label: 'Live message probe', hint: 'Real WebSocket frame exchange' },
      { key: 'check_sensitive_leak', label: 'Sensitive data in frames', hint: 'JWT / keys / tokens' },
      { key: 'check_graphql_subscribe', label: 'GraphQL subscribe w/o auth', hint: 'connection_ack / next' },
      { key: 'check_graphql_introspection', label: 'GraphQL introspection', hint: '__schema over graphql-ws' },
      { key: 'check_stomp_connect', label: 'STOMP CONNECT', hint: 'Unauthenticated broker' },
      { key: 'check_auth_differential', label: 'Auth differential', hint: 'Same probes with/without creds' },
      { key: 'check_message_reflection', label: 'Message reflection', hint: 'DOM XSS surface' },
      { key: 'check_ws_rate_limit', label: 'Rate-limit burst', hint: 'Rapid frame flood' },
      { key: 'check_binary_frames', label: 'Binary frames', hint: 'protobuf/msgpack gateways' },
    ],
  },
  {
    id: 'enterprise',
    labelKey: 'pages.websocketSecurity.groups.enterprise',
    defaultLabel: 'Weissman Standard (DAST)',
    items: [
      { key: 'check_stateful_fuzz', label: 'Stateful conversational fuzz', hint: 'Live response-driven state machine' },
      { key: 'check_binary_mutation', label: 'Binary protobuf mutation', hint: 'Wire decode · field surgery · re-encode' },
      { key: 'check_race_conditions', label: 'Blind race execution', hint: 'Barrier-sync parallel connections' },
      { key: 'check_cross_protocol_chain', label: 'Cross-protocol chain', hint: 'WS artifacts → HTTP privilege replay' },
    ],
  },
  {
    id: 'intel',
    labelKey: 'pages.websocketSecurity.groups.intel',
    defaultLabel: 'Weissman intelligence',
    items: [
      { key: 'attack_path_synthesis', label: 'Attack-path synthesis', hint: 'Kill-chain from evidence' },
      { key: 'posture_scoring', label: 'Posture score', hint: '0–100 grade + weak areas' },
    ],
  },
]

const DEFAULT_TOGGLES = Object.fromEntries(
  TOGGLE_GROUPS.flatMap((g) => g.items.map((i) => [i.key, true]))
)

const CATEGORY_META = {
  posture_summary: { label: 'Posture Summary', icon: '◈', color: ACCENT, order: 0 },
  authenticated_cswsh: { label: 'Authenticated CSWSH', icon: '☠', color: '#fb7185', order: 1 },
  auth_differential: { label: 'Auth Differential', icon: '⚡', color: '#f43f5e', order: 2 },
  cswsh: { label: 'CSWSH', icon: '⛓', color: '#fb923c', order: 3 },
  null_origin_cswsh: { label: 'Null-Origin CSWSH', icon: '◻', color: '#f97316', order: 4 },
  foreign_origin_data: { label: 'Foreign-Origin Data', icon: '🌐', color: '#ea580c', order: 5 },
  ws_sensitive_leak: { label: 'Sensitive Leak', icon: '🔑', color: '#dc2626', order: 6 },
  graphql_ws_unauth: { label: 'GraphQL Subscribe', icon: '◈', color: '#e879f9', order: 7 },
  graphql_ws_introspection: { label: 'GraphQL Introspection', icon: '◇', color: '#d946ef', order: 8 },
  stomp_unauth: { label: 'STOMP CONNECT', icon: '▣', color: '#c026d3', order: 9 },
  host_injection: { label: 'Host Smuggling', icon: '⇄', color: '#a855f7', order: 10 },
  forwarded_bypass: { label: 'X-Forwarded Bypass', icon: '↪', color: '#9333ea', order: 11 },
  tls_downgrade: { label: 'TLS Downgrade', icon: '↓', color: '#7c3aed', order: 12 },
  ws_version_downgrade: { label: 'WS Version Downgrade', icon: '8', color: '#6366f1', order: 13 },
  subprotocol_abuse: { label: 'Subprotocol Abuse', icon: '⊞', color: '#818cf8', order: 14 },
  attack_path: { label: 'Attack Paths', icon: '⛓', color: '#f472b6', order: 15 },
  signalr_negotiate: { label: 'SignalR Negotiate', icon: '⚙', color: '#38bdf8', order: 16 },
  socketio_polling: { label: 'Socket.IO sid', icon: '◎', color: '#0ea5e9', order: 17 },
  ws_reflection: { label: 'Message Reflection', icon: '↩', color: '#fbbf24', order: 18 },
  ws_no_rate_limit: { label: 'No Rate Limit', icon: '∞', color: '#facc15', order: 19 },
  ws_binary_accepted: { label: 'Binary Accepted', icon: '01', color: '#a3e635', order: 20 },
  ws_stateful_fuzz: { label: 'Stateful Fuzz', icon: '⟳', color: '#f472b6', order: 21 },
  ws_binary_mutation: { label: 'Binary Mutation', icon: '⬡', color: '#e879f9', order: 22 },
  ws_race_condition: { label: 'Race Condition', icon: '⚡', color: '#fbbf24', order: 23 },
  cross_protocol_escalation: { label: 'Cross-Protocol Escalation', icon: '⇄', color: '#fb7185', order: 24 },
  missing_origin_cswsh: { label: 'Missing Origin CSWSH', icon: '∅', color: '#f97316', order: 25 },
  ws_cleartext: { label: 'Cleartext ws://', icon: '↓', color: '#eab308', order: 26 },
  ws_message_silent: { label: 'Silent Session', icon: '…', color: '#64748b', order: 28 },
  ws_verbose_error: { label: 'Verbose Errors', icon: '!', color: '#94a3b8', order: 29 },
  ws_endpoint: { label: 'Endpoints', icon: '●', color: '#94a3b8', order: 30 },
  js_ws_harvest: { label: 'JS Harvest', icon: '⌁', color: '#64748b', order: 31 },
  other: { label: 'Other', icon: '•', color: '#475569', order: 99 },
}

const SEV_STYLE = {
  critical: { text: 'text-rose-300', bd: 'border-rose-500/40', bg: 'bg-rose-500/10', dot: '#fb7185' },
  high: { text: 'text-orange-300', bd: 'border-orange-500/40', bg: 'bg-orange-500/10', dot: '#fb923c' },
  medium: { text: 'text-amber-300', bd: 'border-amber-500/40', bg: 'bg-amber-500/10', dot: '#fbbf24' },
  low: { text: 'text-sky-300', bd: 'border-sky-500/40', bg: 'bg-sky-500/10', dot: '#38bdf8' },
  info: { text: 'text-[var(--text-secondary)]', bd: 'border-[var(--border-default)]', bg: 'bg-[var(--row-hover-bg)]', dot: '#94a3b8' },
}

function gradeColor(g) { return { A: '#34d399', B: '#a3e635', C: '#fbbf24', D: '#fb923c' }[g] || '#fb7185' }
function linesToList(s) { return String(s || '').split(/[\n,]+/).map((x) => x.trim()).filter(Boolean) }


function isSummary(f) {
  return f && (f.category === 'posture_summary' || f.summary === true || typeof f.posture_score === 'number' || (f.title || '').includes('WebSocket Posture'))
}

function extractSummary(findings) {
  const s = findings.find(isSummary)
  if (!s) return null
  const ev = s.evidence || {}
  return {
    posture_score: s.posture_score ?? s.score ?? ev.posture_score ?? ev.score ?? 100,
    grade: s.grade ?? ev.grade ?? 'A',
    worst_severity: s.worst_severity ?? ev.worst_severity ?? 'info',
    weak_categories: s.weak_categories ?? ev.weak_categories ?? [],
  }
}

function EvidenceView({ evidence }) {
  if (!evidence || typeof evidence !== 'object') return null
  const checks = Array.isArray(evidence.checks) ? evidence.checks : []
  const scalars = Object.entries(evidence).filter(([k]) => k !== 'checks')
  return (
    <div className="mt-2 rounded-lg bg-[var(--bg-2)] border border-[var(--border-subtle)] p-3 space-y-2">
      {scalars.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1">
          {scalars.map(([k, v]) => (
            <div key={k} className="flex items-start gap-2 text-[11px] font-mono">
              <span className="text-[var(--text-muted)] shrink-0">{k}</span>
              <span className="text-[var(--text-secondary)] break-all">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
            </div>
          ))}
        </div>
      )}
      {checks.length > 0 && (
        <div className="space-y-1 pt-1 border-t border-[var(--border-subtle)]">
          {checks.map((c, i) => (
            <div key={i} className="flex items-center gap-2 text-[11px] font-mono">
              <span className={c.observed ? 'text-emerald-400' : 'text-[var(--text-disabled)]'}>{c.observed ? '✓' : '·'}</span>
              <span className="text-[var(--text-tertiary)]">{c.name}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function FindingCard({ f }) {
  const [open, setOpen] = useState(false)
  const sev = (f.severity || 'info').toLowerCase()
  const st = SEV_STYLE[sev] || SEV_STYLE.info
  return (
    <div className={`rounded-xl border ${st.bd} ${st.bg} p-3`}>
      <Button variant="unstyled" type="button" onClick={() => setOpen((o) => !o)} className="w-full text-left flex items-start gap-3">
        <span className="mt-1 w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: st.dot }} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-[10px] font-mono uppercase tracking-wider ${st.text}`}>{sev}</span>
            {f.mitre_attack && <span className="text-[10px] font-mono text-[var(--text-disabled)]">· {f.mitre_attack}</span>}
          </div>
          <div className="text-sm text-[var(--text-primary)] font-medium mt-0.5">{f.title || f.type}</div>
        </div>
        <span className="text-[var(--text-disabled)] text-xs mt-1">{open ? '▾' : '▸'}</span>
      </Button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
            <p className="text-xs text-[var(--text-tertiary)] leading-relaxed mt-2">{f.description}</p>
            <EvidenceView evidence={f.evidence} />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function Scorecard({ summary, t }) {
  if (!summary) return null
  const score = Number(summary.posture_score ?? 100)
  const grade = summary.grade ?? 'A'
  const color = gradeColor(grade)
  const worst = summary.worst_severity ?? 'info'
  const st = SEV_STYLE[worst] || SEV_STYLE.info
  const cats = summary.weak_categories || []
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-cyan-500/20 p-6 mb-6">
      <div className="flex flex-col md:flex-row md:items-center gap-6">
        <div className="flex items-center gap-5">
          <div className="relative w-28 h-28 shrink-0">
            <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
              <circle cx="50" cy="50" r="44" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="8" />
              <circle cx="50" cy="50" r="44" fill="none" stroke={color} strokeWidth="8" strokeLinecap="round" strokeDasharray={`${(score / 100) * 276.46} 276.46`} />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-3xl font-bold" style={{ color }}>{score}</span>
              <span className="text-[10px] font-mono text-[var(--text-muted)]">/ 100</span>
            </div>
          </div>
          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-cyan-400/60">{t('pages.websocketSecurity.posture', 'WebSocket Posture')}</div>
            <div className="text-5xl font-black leading-none" style={{ color }}>{grade}</div>
            <span className={`inline-block mt-1.5 text-[10px] font-mono px-2 py-0.5 rounded-full border ${st.bd} ${st.text}`}>
              {t('pages.websocketSecurity.worst', 'Worst: {{sev}}', { sev: worst })}
            </span>
          </div>
        </div>
      </div>
      {cats.length > 0 && (
        <div className="mt-4 pt-4 border-t border-[var(--border-subtle)] flex flex-wrap gap-2">
          <span className="text-[10px] font-mono text-[var(--text-muted)]">{t('pages.websocketSecurity.weak_areas', 'Weak areas:')}</span>
          {cats.map((c) => (
            <span key={c} className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/5 border border-cyan-500/20 text-cyan-200/70">
              {(CATEGORY_META[c] || CATEGORY_META.other).icon} {(CATEGORY_META[c] || CATEGORY_META.other).label}
            </span>
          ))}
        </div>
      )}
    </motion.div>
  )
}

export default function WebSocketSecurityCommandCenter() {
  const { t } = useTranslation()
  const [clients, setClients] = useState([])
  const [clientId, setClientId] = useState('')
  const { postScan } = useCommandCenterScan(clientId)
  const [target, setTarget] = useState('')
  const [targetTouched, setTargetTouched] = useState(false)
  const [showParams, setShowParams] = useState(true)
  const [status, setStatus] = useState('idle')
  const [findings, setFindings] = useState([])
  const [pendingJobId, setPendingJobId] = useState(null)
  const [lastRun, setLastRun] = useState(null)
  const [toast, setToast] = useState(null)

  const [toggles, setToggles] = useState(DEFAULT_TOGGLES)
  const [intensity, setIntensity] = useState('normal')
  const [paths, setPaths] = useState('/ws\n/socket.io/?EIO=4&transport=websocket\n/cable')
  const [foreignOrigin, setForeignOrigin] = useState('https://attacker.example.com')
  const [sessionCookie, setSessionCookie] = useState('')
  const [customMessages, setCustomMessages] = useState('')
  const [timeoutMs, setTimeoutMs] = useState(8000)
  const [messageReadMs, setMessageReadMs] = useState(3000)
  const [concurrency, setConcurrency] = useState(16)
  const [bearerToken, setBearerToken] = useState('')
  const [raceConnections, setRaceConnections] = useState(4)
  const [raceSyncUs, setRaceSyncUs] = useState(0)
  const [racePayload, setRacePayload] = useState('{"type":"subscribe","id":"race-1","payload":{"action":"transfer","amount":1}}')
  const [httpEscalationPaths, setHttpEscalationPaths] = useState('api/me\napi/v1/user\ngraphql\nadmin')
  const [statefulFuzzRounds, setStatefulFuzzRounds] = useState(4)

  useEffect(() => {
    apiFetch('/api/clients').then((r) => (r.ok ? r.json() : [])).then((d) => { if (Array.isArray(d)) setClients(d) }).catch(() => {})
  }, [])

  const selectedClient = useMemo(() => clients.find((c) => String(c.id) === String(clientId)), [clients, clientId])
  useEffect(() => { if (!targetTouched) setTarget(firstClientTarget(selectedClient)) }, [selectedClient, targetTouched])

  const showToast = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((x) => (x?.id === id ? null : x)), 5000)
  }, [])

  const detailFindings = useMemo(() => findings.filter((f) => !isSummary(f)), [findings])

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
  } = useWeissmanEnginePage(ENGINE, detailFindings)

  useEffect(() => {
    refreshFromHistory().then((run) => {
      if (run?.findings?.length) {
        applyHistoryFindings(run, setFindings, { setLastUpdated, setJobId: setLastJobId })
      }
    })
  }, [refreshFromHistory, setLastUpdated, setLastJobId])

  const handleRefresh = useCallback(async () => {
    const run = await refreshFromHistory()
    applyHistoryFindings(run, setFindings, { setLastUpdated, setJobId: setLastJobId })
  }, [refreshFromHistory, setLastUpdated, setLastJobId])

  useJobPoll(pendingJobId, {
    enabled: Boolean(pendingJobId),
    onComplete: async (job) => {
      setStatus(uiJobStatus(job.status))
      setLastRun(new Date().toLocaleTimeString())
      const fs = await resolveJobFindings(job, ENGINE, clientId)
      setFindings(Array.isArray(fs) ? fs : [])
      setLastUpdated(new Date().toISOString())
      if (pendingJobId) setLastJobId(pendingJobId)
      setPendingJobId(null)
    },
  })

  const applyPreset = useCallback((key) => {
    const p = PRESETS[key]
    if (!p) return
    setToggles((prev) => ({ ...prev, ...p.values }))
    if (p.values.intensity) setIntensity(p.values.intensity)
  }, [])

  const buildBody = useCallback(() => {
    const body = {
      engine: ENGINE,
      target: target.trim(),
      intensity,
      paths: linesToList(paths),
      foreign_origin: foreignOrigin.trim(),
      timeout_ms: Number(timeoutMs) || 8000,
      message_read_ms: Number(messageReadMs) || 3000,
      concurrency: Number(concurrency) || 16,
      ...Object.fromEntries(Object.entries(toggles).map(([k, v]) => [k, v ? 'true' : 'false'])),
    }
    if (sessionCookie.trim()) body.cookies = sessionCookie.trim()
    if (bearerToken.trim()) body.bearer_token = bearerToken.trim()
    if (customMessages.trim()) body.custom_messages = linesToList(customMessages)
    if (raceConnections) body.race_connections = Number(raceConnections)
    if (raceSyncUs !== '') body.race_sync_us = Number(raceSyncUs)
    if (racePayload.trim()) body.race_payload = racePayload.trim()
    if (statefulFuzzRounds) body.stateful_fuzz_rounds = Number(statefulFuzzRounds)
    if (httpEscalationPaths.trim()) body.http_escalation_paths = linesToList(httpEscalationPaths)
    if (clientId) body.client_id = Number(clientId)
    return body
  }, [target, intensity, paths, foreignOrigin, sessionCookie, bearerToken, customMessages, timeoutMs, messageReadMs, concurrency, toggles, clientId, raceConnections, raceSyncUs, racePayload, statefulFuzzRounds, httpEscalationPaths])

  const hubScanParams = useMemo(() => {
    const { engine, target, client_id, ...rest } = buildBody()
    return rest
  }, [buildBody])
  useSyncHubScanParams(ENGINE, hubScanParams)

  const handleRun = useCallback(async () => {
    if (!clientId) { showToast('error', t('pages.websocketSecurity.select_client_first', 'Select a client first')); return }
    if (!target.trim()) { showToast('error', t('pages.websocketSecurity.target_required', 'Target URL required')); return }
    setStatus('running'); setFindings([])
    try {
      const { ok, data: d, status } = await postScan(buildBody())
      if (!ok) { setStatus('error'); showToast('error', d.detail || t('pages.websocketSecurity.scan_failed', 'Scan failed')); return }
      const jobId = d.job_id ?? ''
      showToast('info', t('pages.websocketSecurity.queued', 'WebSocket scan queued ({{jobId}})', { jobId }))
      if (jobId) setPendingJobId(jobId); else setStatus('error')
    } catch (e) {
      setStatus('error'); showToast('error', e?.message ?? t('pages.websocketSecurity.scan_failed', 'Scan failed'))
    }
  }, [clientId, target, buildBody, showToast, t])

  const summary = useMemo(() => extractSummary(findings), [findings])
  const statusColor = { idle: '#475569', running: ACCENT, completed: '#4ade80', error: '#ef4444' }[status]

  return (
    <PageShell
      hideHubParams
      title={t('pages.websocketSecurity.title', 'WebSocket Security Command Center')}
      badge={t('pages.websocketSecurity.badge', 'WEISSMAN · REAL-TIME API')}
      badgeColor={ACCENT}
      subtitle={t('pages.websocketSecurity.subtitle', 'Agentless WebSocket DAST — RFC6455 verified handshake, CSWSH differential, stateful conversational fuzzing, binary protobuf mutation, barrier-sync race execution, cross-protocol Intelligence Bus, live GraphQL-ws / SignalR / Socket.IO chains, posture grade. Every control maps 1:1 to engine parameters.')}
      actions={(
        <ShellScanActions
          onRefresh={handleRefresh}
          onExport={exportCsv}
          refreshLoading={historyLoading}
          refreshDisabled={status === 'running'}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      {toast && (
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-[var(--bg-1)] border-cyan-500/30 text-cyan-200'}`}>
          {toast.msg}
        </div>
      )}

      <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 mb-6">
        <div className="flex flex-wrap items-end gap-4">
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.websocketSecurity.client', 'Client')}</label>
            <select value={clientId} onChange={(e) => { setClientId(e.target.value); setTargetTouched(false) }}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono min-w-[180px] focus:outline-none focus:border-cyan-500/40">
              <option value="">{t('pages.websocketSecurity.select_client', '— Select client —')}</option>
              {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </div>
          <div className="flex flex-col gap-1 flex-1 min-w-[220px]">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.websocketSecurity.target', 'Target URL')}</label>
            <input type="text" value={target} onChange={(e) => { setTarget(e.target.value); setTargetTouched(true) }} placeholder="https://app.example.com"
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-cyan-500/40" />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{t('pages.websocketSecurity.intensity', 'Intensity')}</label>
            <select value={intensity} onChange={(e) => setIntensity(e.target.value)}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-cyan-500/40">
              <option value="light">{t('pages.websocketSecurity.intensity_light', 'Light')}</option>
              <option value="normal">{t('pages.websocketSecurity.intensity_normal', 'Normal')}</option>
              <option value="aggressive">{t('pages.websocketSecurity.intensity_aggressive', 'Aggressive')}</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: statusColor, boxShadow: status === 'running' ? `0 0 6px ${ACCENT}` : 'none' }} />
            <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{status}</span>
          </div>
          <Button variant="unstyled" type="button" onClick={handleRun} disabled={status === 'running' || !clientId}
            className="px-5 py-2 rounded-xl font-mono text-sm border border-cyan-500/40 text-cyan-300 bg-cyan-500/10 hover:bg-cyan-500/20 transition-all disabled:opacity-40">
            {status === 'running' ? t('pages.websocketSecurity.scanning', '⟳ Scanning…') : t('pages.websocketSecurity.run_scan', '▶ Run WebSocket Scan')}
          </Button>
          <Button variant="unstyled" type="button" onClick={() => setShowParams((s) => !s)}
            className="px-3 py-2 rounded-xl font-mono text-xs border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]">
            {showParams ? '▾' : '▸'} {t('pages.websocketSecurity.params', 'Parameters')}
          </Button>
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          {Object.entries(PRESETS).map(([key, p]) => (
            <Button variant="unstyled" key={key} type="button" title={p.hint} onClick={() => applyPreset(key)}
              className="px-3 py-1.5 rounded-lg text-[11px] font-mono border border-cyan-500/25 text-cyan-200/80 bg-cyan-500/5 hover:bg-cyan-500/15 transition-all">
              {p.label}
            </Button>
          ))}
        </div>

        <AnimatePresence initial={false}>
          {showParams && (
            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
              <div className="mt-5 pt-5 border-t border-[var(--border-subtle)] grid grid-cols-1 xl:grid-cols-2 gap-6">
                {TOGGLE_GROUPS.map((group) => (
                  <div key={group.id}>
                    <div className="text-[10px] font-mono uppercase tracking-wider text-cyan-400/50 mb-2">
                      {t(group.labelKey, group.defaultLabel)}
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                      {group.items.map((tg) => (
                        <label key={tg.key} title={tg.hint} className="flex items-center gap-2 text-xs font-mono text-[var(--text-secondary)] cursor-pointer">
                          <input type="checkbox" checked={!!toggles[tg.key]} onChange={(e) => setToggles((p) => ({ ...p, [tg.key]: e.target.checked }))} className="accent-cyan-500" />
                          {tg.label}
                        </label>
                      ))}
                    </div>
                  </div>
                ))}
                <div className="space-y-3 xl:col-span-2 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  <div>
                    <label className="text-[10px] font-mono uppercase text-[var(--text-muted)] block mb-1">{t('pages.websocketSecurity.paths', 'WebSocket paths')}</label>
                    <textarea value={paths} onChange={(e) => setPaths(e.target.value)} rows={4}
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-cyan-500/40" />
                  </div>
                  <div className="space-y-3">
                    <div>
                      <label className="text-[10px] font-mono uppercase text-[var(--text-muted)] block mb-1">{t('pages.websocketSecurity.foreign_origin', 'Foreign Origin')}</label>
                      <input type="text" value={foreignOrigin} onChange={(e) => setForeignOrigin(e.target.value)}
                        className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)] focus:outline-none focus:border-cyan-500/40" />
                    </div>
                    <div>
                      <label className="text-[10px] font-mono uppercase text-[var(--text-muted)] block mb-1">{t('pages.websocketSecurity.session_cookie', 'Session cookie (CSWSH auth test)')}</label>
                      <input type="password" value={sessionCookie} onChange={(e) => setSessionCookie(e.target.value)} placeholder="session=…"
                        className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)] focus:outline-none focus:border-cyan-500/40" />
                    </div>
                  </div>
                  <div className="space-y-3">
                    <div>
                      <label className="text-[10px] font-mono uppercase text-[var(--text-muted)] block mb-1">{t('pages.websocketSecurity.timeout_ms', 'Timeout (ms)')}</label>
                      <input type="number" min={500} max={30000} value={timeoutMs} onChange={(e) => setTimeoutMs(e.target.value)}
                        className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)]" />
                    </div>
                    <div>
                      <label className="text-[10px] font-mono uppercase text-[var(--text-muted)] block mb-1">{t('pages.websocketSecurity.message_read_ms', 'Message read window (ms)')}</label>
                      <input type="number" min={500} max={15000} value={messageReadMs} onChange={(e) => setMessageReadMs(e.target.value)}
                        className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)]" />
                    </div>
                    <div>
                      <label className="text-[10px] font-mono uppercase text-[var(--text-muted)] block mb-1">{t('pages.websocketSecurity.concurrency', 'Concurrency (parallel probes)')}</label>
                      <input type="number" min={1} max={64} value={concurrency} onChange={(e) => setConcurrency(e.target.value)}
                        className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)]" />
                    </div>
                    <div>
                      <label className="text-[10px] font-mono uppercase text-[var(--text-muted)] block mb-1">{t('pages.websocketSecurity.bearer_token', 'Bearer token (optional)')}</label>
                      <input type="password" value={bearerToken} onChange={(e) => setBearerToken(e.target.value)} placeholder="eyJ…"
                        className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)] focus:outline-none focus:border-cyan-500/40" />
                    </div>
                    <div>
                      <label className="text-[10px] font-mono uppercase text-[var(--text-muted)] block mb-1">{t('pages.websocketSecurity.custom_messages', 'Custom WS messages')}</label>
                      <textarea value={customMessages} onChange={(e) => setCustomMessages(e.target.value)} rows={3} placeholder='{"type":"ping"}'
                        className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)]" />
                    </div>
                  </div>
                </div>
                <div className="xl:col-span-2 pt-2 border-t border-[var(--border-subtle)]">
                  <div className="text-[10px] font-mono uppercase tracking-wider text-cyan-400/50 mb-3">{t('pages.websocketSecurity.advanced', 'Weissman Standard (advanced)')}</div>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div>
                      <label className="text-[10px] font-mono uppercase text-[var(--text-muted)] block mb-1">stateful_fuzz_rounds</label>
                      <input type="number" min={1} max={6} value={statefulFuzzRounds} onChange={(e) => setStatefulFuzzRounds(e.target.value)}
                        className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)]" />
                    </div>
                    <div>
                      <label className="text-[10px] font-mono uppercase text-[var(--text-muted)] block mb-1">{t('pages.websocketSecurity.race_connections', 'Race parallel connections')}</label>
                      <input type="number" min={2} max={16} value={raceConnections} onChange={(e) => setRaceConnections(e.target.value)}
                        className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)]" />
                    </div>
                    <div>
                      <label className="text-[10px] font-mono uppercase text-[var(--text-muted)] block mb-1">{t('pages.websocketSecurity.race_sync_us', 'Race sync window (µs)')}</label>
                      <input type="number" min={0} max={50000} value={raceSyncUs} onChange={(e) => setRaceSyncUs(e.target.value)}
                        className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)]" />
                    </div>
                    <div className="md:col-span-2 lg:col-span-4">
                      <label className="text-[10px] font-mono uppercase text-[var(--text-muted)] block mb-1">{t('pages.websocketSecurity.race_payload', 'Race transactional frame')}</label>
                      <input type="text" value={racePayload} onChange={(e) => setRacePayload(e.target.value)}
                        className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)]" />
                    </div>
                    <div className="md:col-span-2 lg:col-span-4">
                      <label className="text-[10px] font-mono uppercase text-[var(--text-muted)] block mb-1">{t('pages.websocketSecurity.http_escalation_paths', 'HTTP escalation paths')}</label>
                      <textarea value={httpEscalationPaths} onChange={(e) => setHttpEscalationPaths(e.target.value)} rows={3}
                        className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)]" />
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
        {lastRun && <p className="text-[10px] font-mono text-[var(--text-disabled)] mt-3">{t('pages.websocketSecurity.last_run', 'Last completed: {{time}}', { time: lastRun })}</p>}
      </div>

      {!clientId && (
        <p className="text-xs font-mono text-[var(--text-muted)] mb-6">{t('pages.websocketSecurity.select_client_hint', 'Select an in-scope client — Weissman WebSocket assessment requires explicit client authorization.')}</p>
      )}

      {detailFindings.length > 0 && <Scorecard summary={summary} t={t} />}

      <WeissmanFindingsPanel
        findings={detailFindings}
        filteredFindings={filteredFindings}
        counts={counts}
        total={detailFindings.length}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        severityFilter={severityFilter}
        onSeverityChange={setSeverityFilter}
        pending={status === 'running' && detailFindings.length === 0}
        loading={historyLoading && detailFindings.length === 0}
        lastUpdated={lastUpdated}
        jobId={pendingJobId || lastJobId}
        accent={ACCENT}
        showEmptyReady={status !== 'running' && detailFindings.length === 0}
        emptyReadyTitle={t('pages.websocketSecurity.empty_hint', 'Run a scan to assess CSWSH, live message auth, real-time stack chains and WebSocket posture.')}
        emptyReadyBody={t('pages.websocketSecurity.empty_hint', 'Run a scan to assess CSWSH, live message auth, real-time stack chains and WebSocket posture.')}
        renderFinding={(f, i) => <FindingCard key={i} f={f} />}
      />
    </PageShell>
  )
}
