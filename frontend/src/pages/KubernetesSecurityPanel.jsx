// Dedicated, world-class control surface for the Cloud-Native & Kubernetes Security engine
// (engine id: k8s_container). Self-contained and bilingual (en/he) so it adds no shared-locale
// coupling. Exposes EVERY operator knob the Rust engine reads from job_params and renders the
// engine's posture score, security graph, attack paths and evidence-rich findings.
import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import { useIntegrationsPrefill } from '../hooks/useHubLocalScanParams'
import React, { useCallback, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'

import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import Button from '../components/ui/Button'

const ACCENT = '#8b5cf6'

const LABELS = {
  en: {
    title: 'Cloud-Native & Kubernetes Security',
    subtitle: 'Agentless, evidence-based assessment of the cluster control plane and data plane',
    target: 'Cluster target (host / IP / URL)',
    targetPh: 'e.g. 10.0.0.10  or  https://api.cluster.example',
    run: 'Run assessment',
    scanning: 'Assessing…',
    intensity: 'Probe intensity',
    light: 'Light', normal: 'Normal', aggressive: 'Aggressive',
    advanced: 'Advanced parameters',
    timeout: 'Per-probe timeout (ms)',
    concurrency: 'Port-scan concurrency',
    surfaces: 'Attack surfaces to probe',
    ports: 'Port overrides (comma-separated — blank = secure defaults)',
    auth: 'Authenticated checks (optional)',
    bearer: 'Bearer token — enables RBAC misconfiguration hunting',
    bearerPh: 'paste a kubeconfig / ServiceAccount token to enumerate ClusterRoleBindings',
    extraPaths: 'Extra API paths to probe (one per line)',
    analysis: 'Analysis',
    attackPaths: 'Synthesize attack paths (toxic combinations)',
    posture: 'Include posture summary + security graph',
    minConf: 'Minimum confidence',
    selectClient: 'Select a client first',
    scanFailed: 'Scan failed',
    queued: 'Assessment queued',
    noFindings: 'No remotely-observable cloud-native exposure — clean.',
    runToPopulate: 'Configure parameters and run the assessment to populate results.',
    exposure: 'Exposure score',
    grade: 'Posture grade',
    openPorts: 'Open ports',
    surfacesFound: 'Surfaces detected',
    graph: 'Security graph',
    pathsTitle: 'Attack paths',
    findingsTitle: 'Findings',
    evidence: 'Evidence',
    remediation: 'Remediation',
    confidence: 'Confidence',
    reset: 'Reset to defaults',
    selectAll: 'All', selectNone: 'None',
    profile: 'Scan profile',
    profileHint: 'Pre-configures ports for EKS / GKE / AKS / on-prem',
    cisTitle: 'CIS Kubernetes Benchmark',
    cisFailed: 'failed controls',
    provider: 'Managed provider',
    gitVersion: 'Cluster version',
    platformTools: 'Platform tools detected',
    dangerousPods: 'Escape-prone workloads',
    evidence_notice: 'K8s posture via POST /api/command-center/scan (k8s_container). RBAC, API paths, and port probes run against authorized cluster targets only — no simulated cluster graphs.',
  },
  he: {
    title: 'אבטחת ענן וקוברנטיס',
    subtitle: 'הערכה מבוססת-ראיות וללא סוכן של מישור הבקרה ומישור הנתונים של האשכול',
    target: 'יעד האשכול (כתובת / IP / URL)',
    targetPh: 'לדוגמה 10.0.0.10  או  https://api.cluster.example',
    run: 'הרץ הערכה',
    scanning: 'מעריך…',
    intensity: 'עוצמת בדיקה',
    light: 'קלה', normal: 'רגילה', aggressive: 'אגרסיבית',
    advanced: 'פרמטרים מתקדמים',
    timeout: 'פסק-זמן לכל בדיקה (מ"ש)',
    concurrency: 'מקביליות סריקת פורטים',
    surfaces: 'משטחי תקיפה לבדיקה',
    ports: 'דריסת פורטים (מופרד בפסיקים — ריק = ברירת מחדל מאובטחת)',
    auth: 'בדיקות מאומתות (אופציונלי)',
    bearer: 'אסימון Bearer — מפעיל איתור הגדרות-שגויות של RBAC',
    bearerPh: 'הדבק אסימון kubeconfig / ServiceAccount לספירת ClusterRoleBindings',
    extraPaths: 'נתיבי API נוספים לבדיקה (אחד בכל שורה)',
    analysis: 'ניתוח',
    attackPaths: 'סינתזת נתיבי תקיפה (צירופים רעילים)',
    posture: 'כלול סיכום תנוחה + גרף אבטחה',
    minConf: 'ביטחון מינימלי',
    selectClient: 'בחר לקוח תחילה',
    scanFailed: 'הסריקה נכשלה',
    queued: 'ההערכה הוכנסה לתור',
    noFindings: 'לא נצפתה חשיפת ענן מרחוק — נקי.',
    runToPopulate: 'הגדר פרמטרים והרץ את ההערכה כדי לאכלס תוצאות.',
    exposure: 'ציון חשיפה',
    grade: 'דירוג תנוחה',
    openPorts: 'פורטים פתוחים',
    surfacesFound: 'משטחים שזוהו',
    graph: 'גרף אבטחה',
    pathsTitle: 'נתיבי תקיפה',
    findingsTitle: 'ממצאים',
    evidence: 'ראיות',
    remediation: 'תיקון',
    confidence: 'ביטחון',
    reset: 'אפס לברירת מחדל',
    selectAll: 'הכל', selectNone: 'ללא',
    profile: 'פרופיל סריקה',
    profileHint: 'מגדיר מראש פורטים ל-EKS / GKE / AKS / on-prem',
    cisTitle: 'CIS Kubernetes Benchmark',
    cisFailed: 'בקרות שנכשלו',
    provider: 'ספק מנוהל',
    gitVersion: 'גרסת אשכול',
    platformTools: 'כלי פלטפורמה שזוהו',
    dangerousPods: 'עומסי עבודה מסוכנים',
    evidence_notice: 'Posture ק8s דרך POST /api/command-center/scan (k8s_container). בדיקות RBAC, נתיבי API ופורטים מול יעדי אשכול מורשים בלבד — ללא גרפים מדומים.',
  },
}

// (toggle key, port-override key, label, default ports shown as hint)
const SURFACES = [
  ['check_api_server', 'api_ports', 'Kubernetes API server', '6443,443,8443,16443,6444,8080'],
  ['check_kubelet', 'kubelet_ports', 'kubelet (exec / pods)', '10250,10255'],
  ['check_etcd', 'etcd_ports', 'etcd (secret store)', '2379,2380'],
  ['check_docker', 'docker_ports', 'Docker / CRI daemon', '2375,2376'],
  ['check_control_plane', 'control_plane_ports', 'Control-plane components', '10257,10259,10251,10252,10256,10249'],
  ['check_registry', 'registry_ports', 'Container registry', '5000,443'],
  ['check_service_mesh', 'mesh_ports', 'Service mesh (Envoy/Consul)', '15000,9901,19000,8500,15014'],
  ['check_cadvisor', 'cadvisor_ports', 'cAdvisor', '4194'],
  ['check_dashboard', null, 'Kubernetes Dashboard', '—'],
  ['check_helm', null, 'Legacy Helm Tiller', '44134'],
  ['check_gitops', null, 'GitOps (Argo CD / Flux / Rancher)', '—'],
  ['check_observability', 'obs_ports', 'Observability (Prometheus/Grafana)', '9090,9093,3000,9091'],
  ['check_ingress', null, 'Ingress controllers (NGINX/Traefik)', '—'],
]

const SCAN_PROFILES = {
  default: { label: 'Universal (all surfaces)', ports: {} },
  eks: {
    label: 'Amazon EKS',
    ports: { api_ports: '443', obs_ports: '9090,3000' },
  },
  gke: {
    label: 'Google GKE',
    ports: { api_ports: '443', obs_ports: '9090,3000' },
  },
  aks: {
    label: 'Azure AKS',
    ports: { api_ports: '443,6443', obs_ports: '9090,3000' },
  },
  onprem: {
    label: 'On-prem / bare metal',
    ports: {
      api_ports: '6443,8080,443',
      kubelet_ports: '10250,10255',
      etcd_ports: '2379,2380',
      control_plane_ports: '10257,10259,10251,10252',
    },
  },
}

const SEVERITY_META = {
  critical: { c: '#ef4444', w: 5 },
  high: { c: '#f97316', w: 4 },
  medium: { c: '#eab308', w: 3 },
  low: { c: '#38bdf8', w: 2 },
  info: { c: '#94a3b8', w: 1 },
}
const sevColor = (s) => (SEVERITY_META[s] || SEVERITY_META.info).c
const sevWeight = (s) => (SEVERITY_META[s] || SEVERITY_META.info).w

const NODE_STATUS_COLOR = { takeover: '#ef4444', exposed: '#f97316', secure: '#22c55e', root: '#8b5cf6' }

function defaultParams() {
  const toggles = {}
  SURFACES.forEach(([k]) => { toggles[k] = true })
  const portText = {}
  SURFACES.forEach(([, pk]) => { if (pk) portText[pk] = '' })
  return {
    intensity: 'normal',
    timeout_ms: 8000,
    concurrency: 24,
    bearer_token: '',
    extra_paths: '',
    synthesize_attack_paths: true,
    include_posture_summary: true,
    include_cis_benchmark: true,
    min_confidence: 0,
    scan_profile: 'default',
    ...toggles,
    ...portText,
  }
}

function Chip({ children, color = '#ffffff60' }) {
  return (
    <span
      className="inline-flex items-center rounded-md px-2 py-0.5 text-[10px] font-mono border"
      style={{ color, borderColor: `${color}40`, backgroundColor: `${color}12` }}
    >
      {children}
    </span>
  )
}

function SeverityPill({ sev }) {
  const c = sevColor(sev)
  return (
    <span
      className="inline-flex items-center rounded-md px-2 py-0.5 text-[10px] font-mono font-bold uppercase tracking-wide"
      style={{ color: c, backgroundColor: `${c}1a`, border: `1px solid ${c}40` }}
    >
      {sev || 'info'}
    </span>
  )
}

function GraphView({ graph }) {
  const nodes = Array.isArray(graph?.nodes) ? graph.nodes : []
  const edges = Array.isArray(graph?.edges) ? graph.edges : []
  if (!nodes.length) return null
  const roots = nodes.filter((n) => n.type === 'root')
  const others = nodes.filter((n) => n.type !== 'root')
  const H = Math.max(140, others.length * 44 + 24)
  const leftX = 90
  const rightX = 430
  const pos = {}
  roots.forEach((n) => { pos[n.id] = { x: leftX, y: H / 2 } })
  others.forEach((n, i) => { pos[n.id] = { x: rightX, y: 26 + i * 44 } })

  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 600 ${H}`} className="w-full" style={{ minWidth: 420, height: H }}>
        {edges.map((e, i) => {
          const a = pos[e.from]
          const b = pos[e.to]
          if (!a || !b) return null
          return (
            <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="#ffffff20" strokeWidth="1.5" strokeDasharray="4 3" />
          )
        })}
        {nodes.map((n) => {
          const p = pos[n.id]
          if (!p) return null
          const c = NODE_STATUS_COLOR[n.status] || '#94a3b8'
          const anchor = p.x === leftX ? 'end' : 'start'
          const tx = p.x === leftX ? p.x - 14 : p.x + 14
          return (
            <g key={n.id}>
              <circle cx={p.x} cy={p.y} r="7" fill={c} stroke={`${c}80`} strokeWidth="4" />
              <text x={tx} y={p.y + 4} fill="#e5e7eb" fontSize="12" fontFamily="monospace" textAnchor={anchor}>
                {String(n.label || n.id).slice(0, 34)}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}

function Gauge({ score = 0 }) {
  const pct = Math.max(0, Math.min(100, Number(score) || 0))
  const c = pct >= 70 ? '#ef4444' : pct >= 45 ? '#f97316' : pct >= 20 ? '#eab308' : '#22c55e'
  return (
    <div className="flex items-center gap-3">
      <div className="text-3xl font-bold font-mono" style={{ color: c }}>{pct}</div>
      <div className="flex-1">
        <div className="h-2 rounded-full bg-[var(--row-hover-bg)] overflow-hidden">
          <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: c }} />
        </div>
      </div>
    </div>
  )
}

function PostureCard({ finding, L }) {
  const ev = finding?.evidence || {}
  const counts = ev.severity_counts || {}
  const ports = Array.isArray(ev.open_ports) ? ev.open_ports : []
  const surfaces = Array.isArray(ev.surfaces_detected) ? ev.surfaces_detected : []
  const tools = Array.isArray(ev.platform_tools) ? ev.platform_tools : []
  const podStats = ev.dangerous_pod_stats || null
  return (
    <div className="rounded-2xl border border-[var(--border-default)] bg-gradient-to-br from-violet-950/30 to-black/40 p-5 mb-5">
      {(ev.managed_provider || ev.git_version) && (
        <div className="flex flex-wrap gap-2 mb-4 pb-3 border-b border-[var(--border-default)]">
          {ev.managed_provider && <Chip color="#22d3ee">{L.provider}: {ev.managed_provider}</Chip>}
          {ev.git_version && <Chip color={ACCENT}>{L.gitVersion}: {ev.git_version}</Chip>}
          {ev.cis_failed_controls > 0 && (
            <Chip color="#f97316">{L.cisTitle}: {ev.cis_failed_controls} {L.cisFailed}</Chip>
          )}
        </div>
      )}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-1">{L.exposure}</div>
          <Gauge score={ev.exposure_score} />
          <div className="mt-2 text-xs font-mono text-[var(--text-tertiary)]">{ev.posture_grade}</div>
        </div>
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-2">Severity</div>
          <div className="flex flex-wrap gap-1.5">
            {['critical', 'high', 'medium', 'low'].map((s) => (
              <span key={s} className="inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-mono"
                style={{ color: sevColor(s), backgroundColor: `${sevColor(s)}14` }}>
                <b>{counts[s] ?? 0}</b> {s}
              </span>
            ))}
          </div>
          <div className="mt-3 text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-1">{L.surfacesFound}</div>
          <div className="flex flex-wrap gap-1.5">
            {surfaces.length ? surfaces.map((s) => <Chip key={s} color={ACCENT}>{s}</Chip>) : <span className="text-[var(--text-disabled)] text-xs">—</span>}
          </div>
          {tools.length > 0 && (
            <>
              <div className="mt-3 text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-1">{L.platformTools}</div>
              <div className="flex flex-wrap gap-1.5">
                {tools.map((t) => <Chip key={t} color="#a78bfa">{t}</Chip>)}
              </div>
            </>
          )}
        </div>
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-1">{L.openPorts}</div>
          <div className="flex flex-wrap gap-1.5 mb-3">
            {ports.length ? ports.map((p) => <Chip key={p} color="#38bdf8">{p}</Chip>) : <span className="text-[var(--text-disabled)] text-xs">—</span>}
          </div>
          {podStats && (
            <>
              <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-1">{L.dangerousPods}</div>
              <div className="text-[11px] font-mono text-rose-300/80 space-y-0.5">
                {podStats.privileged > 0 && <div>privileged: {podStats.privileged}</div>}
                {podStats.host_pid > 0 && <div>hostPID: {podStats.host_pid}</div>}
                {podStats.host_path > 0 && <div>hostPath: {podStats.host_path}</div>}
              </div>
            </>
          )}
        </div>
      </div>
      {ev.graph && (ev.graph.nodes || []).length > 0 && (
        <div className="mt-5 border-t border-[var(--border-default)] pt-4">
          <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-2">{L.graph}</div>
          <GraphView graph={ev.graph} />
        </div>
      )}
    </div>
  )
}

function CisBenchmarkCard({ finding, L }) {
  const ev = finding?.evidence || {}
  const controls = Array.isArray(ev.controls) ? ev.controls : []
  if (!controls.length) return null
  return (
    <div className="rounded-2xl border border-amber-500/25 bg-amber-950/15 p-5 mb-5">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-bold text-amber-200">{L.cisTitle}</h3>
        <Chip color="#fbbf24">{ev.failed_controls ?? controls.length} {L.cisFailed}</Chip>
      </div>
      <p className="text-xs text-[var(--text-tertiary)] mb-3">{finding.description}</p>
      <div className="space-y-2 max-h-64 overflow-y-auto">
        {controls.map((c, i) => (
          <div key={i} className="flex items-start gap-2 rounded-lg bg-[var(--table-surface)] border border-[var(--border-subtle)] px-3 py-2 text-xs">
            <span className="shrink-0 font-mono text-amber-300">{c.id}</span>
            <div className="min-w-0">
              <div className="text-[var(--text-secondary)] font-medium">{c.title}</div>
              <div className="text-[var(--text-muted)] mt-0.5">{c.detail}</div>
            </div>
            <SeverityPill sev={c.severity} />
          </div>
        ))}
      </div>
    </div>
  )
}

function AttackPathCard({ finding }) {
  const ev = finding?.evidence || {}
  const steps = Array.isArray(ev.steps) ? ev.steps : []
  const chain = Array.isArray(ev.kill_chain) ? ev.kill_chain : []
  return (
    <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 p-4">
      <div className="flex items-start justify-between gap-3 mb-2">
        <h4 className="text-sm font-bold text-rose-200">{finding.title}</h4>
        <SeverityPill sev={finding.severity} />
      </div>
      {chain.length > 0 && (
        <div className="flex flex-wrap items-center gap-1 mb-3">
          {chain.map((k, i) => (
            <React.Fragment key={i}>
              <Chip color="#fb7185">{k}</Chip>
              {i < chain.length - 1 && <span className="text-rose-400/50 text-xs">→</span>}
            </React.Fragment>
          ))}
        </div>
      )}
      <ol className="space-y-1.5">
        {steps.map((s, i) => (
          <li key={i} className="flex gap-2 text-xs">
            <span className="shrink-0 w-5 h-5 rounded-full bg-rose-500/20 text-rose-300 flex items-center justify-center font-mono text-[10px]">{s.order ?? i + 1}</span>
            <span className="text-[var(--text-secondary)]"><b className="text-rose-200">{s.stage}:</b> {s.detail}</span>
          </li>
        ))}
      </ol>
    </div>
  )
}

function renderEvidenceValue(v) {
  if (v === null || v === undefined) return ''
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

function FindingCard({ finding, L }) {
  const [open, setOpen] = useState(false)
  const ev = finding?.evidence || {}
  const checks = Array.isArray(ev.checks) ? ev.checks : []
  const evKeys = Object.keys(ev).filter((k) => k !== 'checks' && k !== 'steps' && k !== 'kill_chain' && k !== 'graph')
  const conf = typeof finding.confidence === 'number' ? Math.round(finding.confidence * 100) : null
  return (
    <div className="rounded-xl border border-[var(--border-default)] bg-[var(--row-hover-bg)] overflow-hidden">
      <Button variant="unstyled" type="button" onClick={() => setOpen((o) => !o)} className="w-full flex items-start gap-3 p-3 text-left hover:bg-[var(--row-hover-bg)]">
        <span className="mt-0.5 w-1.5 self-stretch rounded-full" style={{ backgroundColor: sevColor(finding.severity) }} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityPill sev={finding.severity} />
            {finding.mitre_attack && <Chip color="#a78bfa">{finding.mitre_attack}</Chip>}
            {conf !== null && <Chip color="#22d3ee">{L.confidence} {conf}%</Chip>}
          </div>
          <div className="text-sm text-[var(--text-primary)] mt-1 font-medium">{finding.title}</div>
        </div>
        <span className="text-[var(--text-disabled)] text-xs mt-1">{open ? '−' : '+'}</span>
      </Button>
      <AnimatePresence>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
            <div className="px-4 pb-4 pt-1 space-y-3 text-xs">
              {finding.description && <p className="text-[var(--text-tertiary)] leading-relaxed">{finding.description}</p>}
              {evKeys.length > 0 && (
                <div className="rounded-lg bg-[var(--bg-2)] border border-[var(--border-subtle)] p-2">
                  <div className="text-[10px] uppercase tracking-widest text-[var(--text-disabled)] mb-1">{L.evidence}</div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-0.5 font-mono">
                    {evKeys.map((k) => (
                      <div key={k} className="flex gap-2 min-w-0">
                        <span className="text-[var(--text-muted)] shrink-0">{k}:</span>
                        <span className="text-[var(--text-secondary)] truncate">{renderEvidenceValue(ev[k])}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {checks.length > 0 && (
                <div className="space-y-1">
                  {checks.map((c, i) => (
                    <div key={i} className="flex items-center gap-2 font-mono">
                      <span style={{ color: c.observed ? '#22c55e' : '#64748b' }}>{c.observed ? '✓' : '○'}</span>
                      <span className="text-[var(--text-secondary)]">{c.name}</span>
                      <span className="text-[var(--text-muted)] truncate">{renderEvidenceValue(c.detail)}</span>
                    </div>
                  ))}
                </div>
              )}
              {finding.remediation && (
                <div className="rounded-lg bg-emerald-950/20 border border-emerald-500/20 p-2">
                  <div className="text-[10px] uppercase tracking-widest text-emerald-300/60 mb-1">{L.remediation}</div>
                  <p className="text-emerald-100/70 leading-relaxed">{finding.remediation}</p>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function Toggle({ on, onClick, label }) {
  return (
    <Button variant="unstyled" type="button" onClick={onClick}
      className="flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-xs font-mono transition-all w-full"
      style={{ borderColor: on ? `${ACCENT}50` : '#ffffff14', backgroundColor: on ? `${ACCENT}14` : 'transparent', color: on ? '#ddd6fe' : '#ffffff55' }}>
      <span className="w-7 h-4 rounded-full relative transition-all shrink-0" style={{ backgroundColor: on ? ACCENT : '#ffffff20' }}>
        <span className="absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all" style={{ left: on ? '14px' : '2px' }} />
      </span>
      <span className="truncate">{label}</span>
    </Button>
  )
}

function Segmented({ value, onChange, options }) {
  return (
    <div className="inline-flex rounded-lg border border-[var(--border-default)] p-0.5 bg-[var(--table-surface)]">
      {options.map((o) => (
        <Button variant="unstyled" key={o.value} type="button" onClick={() => onChange(o.value)}
          className="px-3 py-1 rounded-md text-xs font-mono transition-all"
          style={value === o.value ? { backgroundColor: `${ACCENT}25`, color: '#ddd6fe' } : { color: '#ffffff50' }}>
          {o.label}
        </Button>
      ))}
    </div>
  )
}

export default function KubernetesSecurityPanel({ clientId, target: defaultTarget, showToast, onFindingsUpdate, onStatusUpdate }) {
  const { postScan } = useCommandCenterScan(clientId)
  const { i18n } = useTranslation()
  const L = LABELS[i18n.language?.startsWith('he') ? 'he' : 'en']
  const [params, setParams] = useState(defaultParams)
  useIntegrationsPrefill('k8s_container', clientId, setParams)
  const [target, setTarget] = useState(defaultTarget || '')
  const [status, setStatus] = useState('idle')
  const [findings, setFindings] = useState([])
  const [pendingJobId, setPendingJobId] = useState(null)
  const [lastRun, setLastRun] = useState(null)
  const [showAdvanced, setShowAdvanced] = useState(false)

  React.useEffect(() => { setTarget(defaultTarget || '') }, [defaultTarget])

  React.useEffect(() => {
    onFindingsUpdate?.('k8s_container', findings)
  }, [findings, onFindingsUpdate])

  React.useEffect(() => {
    onStatusUpdate?.('k8s_container', status)
  }, [status, onStatusUpdate])

  const set = (k, v) => setParams((p) => ({ ...p, [k]: v }))
  const toggleAll = (on) => setParams((p) => { const n = { ...p }; SURFACES.forEach(([k]) => { n[k] = on }); return n })

  useJobPoll(pendingJobId, {
    enabled: Boolean(pendingJobId),
    onComplete: async (job) => {
      setStatus(uiJobStatus(job.status))
      setLastRun(new Date().toLocaleTimeString())
      setFindings(await resolveJobFindings(job, 'k8s_container', clientId))
      setPendingJobId(null)
    },
  })

  const applyProfile = (profileKey) => {
    setParams((p) => {
      const n = { ...p, scan_profile: profileKey }
      const prof = SCAN_PROFILES[profileKey]
      if (prof?.ports) {
        Object.entries(prof.ports).forEach(([pk, val]) => { n[pk] = val })
      }
      return n
    })
  }

  const buildBody = useCallback(() => {
    const body = { engine: 'k8s_container', client_id: Number(clientId) }
    if (target.trim()) body.target = target.trim()
    body.intensity = params.intensity
    body.timeout_ms = Number(params.timeout_ms) || 8000
    body.concurrency = Number(params.concurrency) || 24
    body.scan_profile = params.scan_profile
    SURFACES.forEach(([k]) => { body[k] = !!params[k] })
    SURFACES.forEach(([, pk]) => { if (pk && String(params[pk] || '').trim()) body[pk] = String(params[pk]).trim() })
    if (params.bearer_token.trim()) body.bearer_token = params.bearer_token.trim()
    if (params.extra_paths.trim()) body.extra_paths = params.extra_paths
    body.synthesize_attack_paths = !!params.synthesize_attack_paths
    body.include_posture_summary = !!params.include_posture_summary
    body.include_cis_benchmark = !!params.include_cis_benchmark
    if (Number(params.min_confidence) > 0) body.min_confidence = String(params.min_confidence)
    return body
  }, [clientId, target, params])

  const hubScanParams = React.useMemo(() => {
    const { engine, target: _t, client_id, ...rest } = buildBody()
    return rest
  }, [buildBody])
  useSyncHubScanParams('k8s_container', hubScanParams)

  const handleRun = useCallback(async () => {
    if (!clientId) { showToast?.('error', L.selectClient); return }
    setStatus('running'); setFindings([])
    try {
      const { ok, data: d, status } = await postScan(buildBody())
      if (!ok) { setStatus('error'); showToast?.('error', d.detail || L.scanFailed); return }
      const jobId = d.job_id ?? ''
      showToast?.('info', `${L.queued} · ${jobId}`)
      if (jobId) setPendingJobId(jobId); else setStatus('error')
    } catch (e) {
      setStatus('error'); showToast?.('error', e?.message ?? L.scanFailed)
    }
  }, [clientId, buildBody, showToast, L])

  const { posture, cis, paths, regular } = useMemo(() => {
    const posture = findings.find((f) => f.category === 'posture_summary') || null
    const cis = findings.find((f) => f.category === 'cis_benchmark') || null
    const paths = findings.filter((f) => f.category === 'attack_path')
    const regular = findings
      .filter((f) => !['posture_summary', 'attack_path', 'cis_benchmark'].includes(f.category))
      .sort((a, b) => sevWeight(b.severity) - sevWeight(a.severity))
    return { posture, cis, paths, regular }
  }, [findings])

  const statusColor = { idle: '#374151', running: ACCENT, completed: '#4ade80', error: '#ef4444' }[status]

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-5">
      <EvidenceNotice className="text-[10px] leading-snug">{L.evidence_notice}</EvidenceNotice>
      {/* Header + run */}
      <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-6">
        <div className="flex items-start justify-between gap-4 mb-4">
          <div className="flex items-center gap-3">
            <span className="text-3xl" style={{ color: ACCENT }}>⎈</span>
            <div>
              <h2 className="text-lg font-bold text-white">{L.title}</h2>
              <p className="text-sm text-[var(--text-tertiary)]">{L.subtitle}</p>
              <span className="text-[10px] font-mono text-[var(--text-disabled)] uppercase tracking-widest">k8s_container</span>
            </div>
          </div>
          <div className="flex flex-col items-end gap-2 shrink-0">
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: statusColor, boxShadow: status === 'running' ? `0 0 6px ${ACCENT}` : 'none' }} />
              <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{status}</span>
            </div>
            <Button variant="unstyled" type="button" onClick={handleRun} disabled={status === 'running' || !clientId}
              className="px-5 py-2 rounded-xl font-mono text-sm border transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ borderColor: `${ACCENT}50`, color: '#ddd6fe', backgroundColor: `${ACCENT}18` }}>
              {status === 'running' ? L.scanning : L.run}
            </Button>
          </div>
        </div>

        {/* Target */}
        <label className="block mb-4">
          <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.target}</span>
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder={L.targetPh}
            className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] font-mono focus:outline-none focus:border-violet-500/40" />
        </label>

        {/* Scan profile */}
        <div className="mb-4">
          <div className="text-[11px] font-mono text-[var(--text-muted)] mb-1">{L.profile}</div>
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(SCAN_PROFILES).map(([key, prof]) => (
              <Button variant="unstyled" key={key} type="button" onClick={() => applyProfile(key)}
                className="px-3 py-1 rounded-lg text-xs font-mono border transition-all"
                style={params.scan_profile === key
                  ? { borderColor: `${ACCENT}50`, color: '#ddd6fe', backgroundColor: `${ACCENT}14` }
                  : { borderColor: '#ffffff14', color: '#ffffff55' }}>
                {prof.label}
              </Button>
            ))}
          </div>
          <p className="text-[10px] text-[var(--text-disabled)] mt-1">{L.profileHint}</p>
        </div>

        {/* Intensity */}
        <div className="flex items-center justify-between gap-4 mb-4">
          <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.intensity}</span>
          <Segmented value={params.intensity} onChange={(v) => set('intensity', v)}
            options={[{ value: 'light', label: L.light }, { value: 'normal', label: L.normal }, { value: 'aggressive', label: L.aggressive }]} />
        </div>

        {/* Surfaces */}
        <div className="flex items-center justify-between mb-2">
          <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.surfaces}</span>
          <div className="flex gap-1">
            <Button variant="unstyled" type="button" onClick={() => toggleAll(true)} className="text-[10px] font-mono text-[var(--text-muted)] hover:text-[var(--text-secondary)] px-2 py-0.5 rounded border border-[var(--border-default)]">{L.selectAll}</Button>
            <Button variant="unstyled" type="button" onClick={() => toggleAll(false)} className="text-[10px] font-mono text-[var(--text-muted)] hover:text-[var(--text-secondary)] px-2 py-0.5 rounded border border-[var(--border-default)]">{L.selectNone}</Button>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mb-2">
          {SURFACES.map(([k, pk, label, defPorts]) => (
            <div key={k} className="flex items-center gap-2">
              <div className="flex-1"><Toggle on={!!params[k]} onClick={() => set(k, !params[k])} label={label} /></div>
              {pk && (
                <input value={params[pk]} onChange={(e) => set(pk, e.target.value)} placeholder={defPorts} disabled={!params[k]}
                  className="w-36 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-[11px] text-[var(--text-secondary)] font-mono focus:outline-none focus:border-violet-500/40 disabled:opacity-30" />
              )}
            </div>
          ))}
        </div>

        {/* Advanced */}
        <Button variant="unstyled" type="button" onClick={() => setShowAdvanced((s) => !s)} className="text-xs font-mono text-violet-300/70 hover:text-violet-200 mt-2">
          {showAdvanced ? '▾' : '▸'} {L.advanced}
        </Button>
        <AnimatePresence>
          {showAdvanced && (
            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
              <div className="pt-4 space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <label className="block">
                    <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.timeout}</span>
                    <input type="number" value={params.timeout_ms} onChange={(e) => set('timeout_ms', e.target.value)}
                      className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-sm text-[var(--text-primary)] font-mono focus:outline-none focus:border-violet-500/40" />
                  </label>
                  <label className="block">
                    <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.concurrency}</span>
                    <input type="number" value={params.concurrency} onChange={(e) => set('concurrency', e.target.value)}
                      className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-sm text-[var(--text-primary)] font-mono focus:outline-none focus:border-violet-500/40" />
                  </label>
                </div>
                <div>
                  <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.auth}</span>
                  <label className="block mt-1">
                    <span className="text-[10px] font-mono text-[var(--text-muted)]">{L.bearer}</span>
                    <input type="password" value={params.bearer_token} onChange={(e) => set('bearer_token', e.target.value)} placeholder={L.bearerPh} autoComplete="off"
                      className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-sm text-[var(--text-primary)] font-mono focus:outline-none focus:border-violet-500/40" />
                  </label>
                </div>
                <label className="block">
                  <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.extraPaths}</span>
                  <textarea value={params.extra_paths} onChange={(e) => set('extra_paths', e.target.value)} rows={2} placeholder={'/api/v1/namespaces/kube-system/secrets\n/apis/...'}
                    className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-sm text-[var(--text-primary)] font-mono focus:outline-none focus:border-violet-500/40" />
                </label>
                <div className="flex flex-col gap-2">
                  <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.analysis}</span>
                  <Toggle on={params.synthesize_attack_paths} onClick={() => set('synthesize_attack_paths', !params.synthesize_attack_paths)} label={L.attackPaths} />
                  <Toggle on={params.include_posture_summary} onClick={() => set('include_posture_summary', !params.include_posture_summary)} label={L.posture} />
                  <Toggle on={params.include_cis_benchmark} onClick={() => set('include_cis_benchmark', !params.include_cis_benchmark)} label={L.cisTitle} />
                </div>
                <label className="block">
                  <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.minConf}: {Math.round(Number(params.min_confidence) * 100)}%</span>
                  <input type="range" min="0" max="1" step="0.05" value={params.min_confidence} onChange={(e) => set('min_confidence', e.target.value)} className="mt-1 w-full accent-violet-500" />
                </label>
                <Button variant="unstyled" type="button" onClick={() => setParams(defaultParams())} className="text-[11px] font-mono text-[var(--text-muted)] hover:text-[var(--text-secondary)] underline">{L.reset}</Button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {lastRun && <p className="text-[10px] font-mono text-[var(--text-disabled)] mt-3">{lastRun}</p>}
      </div>

      {/* Results */}
      {findings.length === 0 && status !== 'running' && (
        <div className="rounded-2xl bg-[var(--row-hover-bg)] border border-[var(--border-subtle)] p-6 text-center">
          <p className="text-[11px] font-mono text-[var(--text-disabled)]">{status === 'completed' ? L.noFindings : L.runToPopulate}</p>
        </div>
      )}

      {posture && <PostureCard finding={posture} L={L} />}

      {cis && <CisBenchmarkCard finding={cis} L={L} />}

      {paths.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-sm font-bold text-rose-300 flex items-center gap-2">{L.pathsTitle} <Chip color="#fb7185">{paths.length}</Chip></h3>
          {paths.map((p, i) => <AttackPathCard key={i} finding={p} />)}
        </div>
      )}

      {regular.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-sm font-bold text-[var(--text-secondary)] flex items-center gap-2">{L.findingsTitle} <Chip color={ACCENT}>{regular.length}</Chip></h3>
          {regular.map((f, i) => <FindingCard key={i} finding={f} L={L} />)}
        </div>
      )}
    </motion.div>
  )
}
