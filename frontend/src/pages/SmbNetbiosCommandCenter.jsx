// SMB / NetBIOS Security Command Center — live binary-protocol assessment (engine: smb_netbios).
// Impacket / CrackMapExec / Nessus-class: SMB2/3 negotiate, signing, encryption, IPC$/RPC pipes, NTLM fingerprint, attack graph.
import { firstClientTarget } from '../lib/clientTarget'
import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import { useIntegrationsPrefill } from '../hooks/useHubLocalScanParams'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../utils/apiFetch'
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'
import { downloadBytes } from '../lib/pdfExport'
import Button from '../components/ui/Button'

const ENGINE_ID = 'smb_netbios'
const ACCENT = '#3b82f6'
const ACCENT2 = '#f97316'

const LABELS = {
  en: {
    title: 'SMB / NetBIOS Security Command Center',
    subtitle: 'Live wire-protocol SMB assessment — SMB2/3 negotiate, signing & encryption posture, SMBv1/EternalBlue & SMBGhost, anonymous IPC$ + DCE/RPC pipes (epmapper/spoolss/samr/lsarpc/svcctl), NTLM/SPNEGO fingerprint, NetBIOS DC role, attack-path synthesis & posture grade',
    badge: 'SMB LIVE PROTOCOL',
    client: 'Client',
    selectClient: 'Select client…',
    selectClientFirst: 'Select a client first',
    target: 'Target (IP or hostname)',
    targetPh: '192.168.1.10  or  fileserver.corp.local',
    run: 'Run SMB assessment',
    scanning: 'Probing…',
    queued: 'SMB scan queued',
    scanFailed: 'Scan failed',
    ports: 'SMB ports (comma-separated)',
    timeout: 'Per-probe timeout (ms)',
    layers: 'Assessment layers',
    checkSigning: 'SMB signing (NTLM relay precondition)',
    checkEncryption: 'SMB3 encryption posture',
    checkSmb1: 'SMBv1 / EternalBlue surface',
    checkSmbghost: 'SMBGhost (CVE-2020-0796)',
    checkSpnego: 'SPNEGO Kerberos/NTLM fingerprint',
    checkIpc: 'IPC$ + named-pipe / DCE/RPC probe',
    checkNtlm: 'NTLM host/domain/OS fingerprint',
    checkNetbios: 'NetBIOS node status (UDP 137)',
    checkNbnsRoles: 'NBNS DC / browser role detection',
    check139: 'Legacy NetBIOS session (TCP 139)',
    checkUptime: 'Server uptime (FILETIME disclosure)',
    checkMs17: 'MS17-010 Trans2 fingerprint (Nessus oracle)',
    checkNtlmWeak: 'NTLMv1 / LM weakness flags',
    checkImplementation: 'SMB stack fingerprint (Windows vs Samba)',
    checkCapabilities: 'SMB global capabilities (DFS/multichannel)',
    checkDialectDowngrade: 'SMB dialect downgrade detection',
    checkAdminShares: 'Hidden share probe (C$ / ADMIN$ / PRINT$)',
    checkPetitpotam: 'PetitPotam toxic-combination correlator',
    checkZerologon: 'Zerologon surface correlator (DC + Netlogon)',
    checkPrintnightmare: 'PrintNightmare correlator (spoolss + no signing)',
    checkMacVendor: 'MAC OUI vendor from NBNS',
    emitMetrics: 'Emit scan telemetry (pipe matrix + compliance)',
    scanElapsed: 'Scan duration',
    ms17Status: 'MS17-010 Trans2 NTSTATUS',
    scanAllPorts: 'Probe all configured ports',
    attackPaths: 'Synthesize attack paths',
    postureScoring: 'Executive posture score',
    reset: 'Reset defaults',
    export: 'Export JSON',
    posture: 'SMB exposure posture',
    grade: 'Grade',
    counts: 'Findings by severity',
    graphTitle: 'SMB lateral-movement graph',
    graphHint: 'Attacker → SMB :445 → IPC$ → RPC pipes → domain impact',
    pathsTitle: 'Ransomware / relay attack paths',
    findingsTitle: 'Protocol findings',
    evidence: 'Evidence trail',
    noFindings: 'No SMB/NetBIOS weaknesses observed on the wire — strong file-sharing posture.',
    runToPopulate: 'Configure target host and run the live SMB protocol assessment.',
    related: 'Related network engines',
    relatedNetwork: 'Network Intelligence',
    relatedTls: 'PKI / TLS Command Center',
    relatedKerberos: 'AD & Kerberos Security',
    relatedEngine: 'Engine detail (API)',
    filterAll: 'all',
    showParams: 'Parameters',
    hideParams: 'Hide parameters',
    lastRun: 'Last completed',
    pipeMatrix: 'RPC pipe exposure matrix',
    pipeOpen: 'OPEN',
    pipeClosed: 'closed',
    adminShares: 'Admin share oracle',
    telemetry: 'Live scan telemetry',
    probesRun: 'Probes executed',
    implementation: 'Stack',
    maxDialect: 'Max dialect',
    ransomwareReadiness: 'Ransomware readiness',
    compliance: 'Compliance gap mapping',
    noGaps: 'No mapped gaps',
    standards: 'Standards',
  },
  he: {
    title: 'מרכז פיקוד SMB / NetBIOS',
    subtitle: 'הערכת SMB חיה על ה-wire — negotiate SMB2/3, חתימה והצפנה, SMBv1/EternalBlue ו-SMBGhost, IPC$ אנונימי + צינורות DCE/RPC, טביעת NTLM/SPNEGO, זיהוי DC ב-NetBIOS, סינתזת נתיבי תקיפה וציון תנוחה',
    badge: 'SMB פרוטוקול חי',
    client: 'לקוח',
    selectClient: 'בחר לקוח…',
    selectClientFirst: 'בחר לקוח תחילה',
    target: 'יעד (IP או hostname)',
    targetPh: '192.168.1.10  או  fileserver.corp.local',
    run: 'הרץ הערכת SMB',
    scanning: 'סורק…',
    queued: 'סריקת SMB בתור',
    scanFailed: 'הסריקה נכשלה',
    ports: 'פורטים SMB (מופרדים בפסיקים)',
    timeout: 'Timeout לבדיקה (ms)',
    layers: 'שכבות הערכה',
    checkSigning: 'חתימת SMB (תנאי ל-NTLM relay)',
    checkEncryption: 'תנוחת הצפנת SMB3',
    checkSmb1: 'SMBv1 / EternalBlue',
    checkSmbghost: 'SMBGhost (CVE-2020-0796)',
    checkSpnego: 'טביעת Kerberos/NTLM ב-SPNEGO',
    checkIpc: 'IPC$ + צינורות DCE/RPC',
    checkNtlm: 'טביעת host/domain/OS ב-NTLM',
    checkNetbios: 'NetBIOS node status (UDP 137)',
    checkNbnsRoles: 'זיהוי DC / browser ב-NBNS',
    check139: 'NetBIOS session (TCP 139)',
    checkUptime: 'זמן uptime (FILETIME)',
    checkMs17: 'MS17-010 Trans2 fingerprint (Nessus oracle)',
    checkNtlmWeak: 'דגלי חולשה NTLMv1 / LM',
    checkImplementation: 'טביעת SMB stack (Windows vs Samba)',
    checkCapabilities: 'יכולות SMB גלובליות (DFS/multichannel)',
    checkDialectDowngrade: 'זיהוי dialect downgrade',
    checkAdminShares: 'בדיקת shares נסתרים (C$ / ADMIN$)',
    checkPetitpotam: 'Correlator PetitPotam',
    checkZerologon: 'Correlator Zerologon (DC + Netlogon)',
    checkPrintnightmare: 'Correlator PrintNightmare',
    checkMacVendor: 'ספק OUI מ-MAC ב-NBNS',
    emitMetrics: 'טלמטריית סריקה (pipe matrix + compliance)',
    scanElapsed: 'משך סריקה',
    ms17Status: 'MS17-010 Trans2 NTSTATUS',
    scanAllPorts: 'בדוק את כל הפורטים',
    attackPaths: 'סינתזת נתיבי תקיפה',
    postureScoring: 'ציון תנוחה מנהלי',
    reset: 'אפס ברירות מחדל',
    export: 'ייצוא JSON',
    posture: 'תנוחת חשיפת SMB',
    grade: 'דירוג',
    counts: 'ממצאים לפי חומרה',
    graphTitle: 'גרף lateral-movement ב-SMB',
    graphHint: 'תוקף → SMB :445 → IPC$ → RPC → השפעה על דומיין',
    pathsTitle: 'נתיבי ransomware / relay',
    findingsTitle: 'ממצאי פרוטוקול',
    evidence: 'שרשרת ראיות',
    noFindings: 'לא נצפו חולשות SMB/NetBIOS — תנוחת שיתוף קבצים חזקה.',
    runToPopulate: 'הגדר יעד והרץ הערכת SMB חיה.',
    related: 'מנועי רשת קשורים',
    relatedNetwork: 'Network Intelligence',
    relatedTls: 'מרכז PKI / TLS',
    relatedKerberos: 'AD & Kerberos',
    relatedEngine: 'פרטי מנוע (API)',
    filterAll: 'הכל',
    showParams: 'פרמטרים',
    hideParams: 'הסתר פרמטרים',
    lastRun: 'הושלם לאחרונה',
    pipeMatrix: 'מטריצת חשיפת צינורות RPC',
    pipeOpen: 'פתוח',
    pipeClosed: 'סגור',
    adminShares: 'בדיקת shares נסתרים',
    telemetry: 'טלמטריית סריקה חיה',
    probesRun: 'בדיקות שבוצעו',
    implementation: 'מימוש',
    maxDialect: 'דialect מקסימלי',
    ransomwareReadiness: 'מוכנות ransomware',
    compliance: 'מיפוי פערי compliance',
    noGaps: 'אין פערים',
    standards: 'תקנים',
  },
}

const CATEGORY_META = {
  posture_summary: { label: 'Posture Score', icon: '◈', color: ACCENT, order: 0 },
  attack_path: { label: 'Attack Paths', icon: '⛓', color: '#fb7185', order: 1 },
  cve_surface: { label: 'CVE Surface', icon: '☠', color: '#ef4444', order: 2 },
  signing_relay: { label: 'Signing / Relay', icon: '⇄', color: '#f97316', order: 3 },
  encryption: { label: 'Encryption', icon: '🔐', color: '#a855f7', order: 4 },
  ipc_rpc: { label: 'IPC$ / RPC Pipes', icon: '⚌', color: '#dc2626', order: 5 },
  fingerprint: { label: 'Host Fingerprint', icon: '🔍', color: '#38bdf8', order: 6 },
  auth_mechanism: { label: 'Auth Mechanisms', icon: '🏷', color: '#818cf8', order: 7 },
  netbios: { label: 'NetBIOS / NBNS', icon: '📡', color: '#fbbf24', order: 8 },
  legacy_netbios: { label: 'Legacy NetBIOS', icon: '139', color: '#94a3b8', order: 9 },
  smb_discovery: { label: 'SMB Discovery', icon: '445', color: '#64748b', order: 10 },
  other: { label: 'Other', icon: '•', color: '#475569', order: 99 },
}

const PIPE_DEFS = [
  { key: 'epmapper_rpc', label: 'epmapper RPC', critical: true },
  { key: 'spoolss', label: 'spoolss', critical: true },
  { key: 'samr', label: 'samr', critical: true },
  { key: 'lsarpc', label: 'lsarpc', critical: true },
  { key: 'svcctl', label: 'svcctl', critical: true },
  { key: 'efsrpc', label: 'efsrpc (PetitPotam)', critical: true },
  { key: 'netlogon', label: 'netlogon', critical: true },
  { key: 'winreg', label: 'winreg', critical: false },
  { key: 'atsvc', label: 'atsvc', critical: false },
  { key: 'srvsvc', label: 'srvsvc', critical: false },
  { key: 'wkssvc', label: 'wkssvc', critical: false },
]

const DEFAULT_PARAMS = {
  ports: '445',
  timeout_ms: '4000',
  netbios_udp_port: '137',
  check_signing: true,
  check_encryption: true,
  check_smb1: true,
  check_ms17_010: true,
  check_smbghost: true,
  check_spnego: true,
  check_ipc_pipes: true,
  check_admin_shares: true,
  check_ntlm: true,
  check_ntlm_weak: true,
  check_implementation: true,
  check_capabilities: true,
  check_dialect_downgrade: true,
  check_petitpotam: true,
  check_zerologon: true,
  check_printnightmare: true,
  check_netbios: true,
  check_nbns_roles: true,
  check_mac_vendor: true,
  check_139: true,
  check_uptime: true,
  scan_all_ports: false,
  synthesize_attack_path: true,
  posture_scoring: true,
  emit_metrics: true,
}

const SEV_COLOR = {
  critical: '#fb7185',
  high: '#fb923c',
  medium: '#fbbf24',
  low: '#38bdf8',
  info: '#94a3b8',
}

function gradeColor(g) {
  return { A: '#34d399', B: '#a3e635', C: '#fbbf24', D: '#fb923c', F: '#ef4444' }[g] || '#94a3b8'
}

function CategoryBreakdown({ findings }) {
  const groups = useMemo(() => {
    const counts = new Map()
    for (const f of findings) {
      const key = CATEGORY_META[f?.category] ? f.category : 'other'
      counts.set(key, (counts.get(key) || 0) + 1)
    }
    return [...counts.entries()]
      .map(([key, count]) => ({ key, count, meta: CATEGORY_META[key] || CATEGORY_META.other }))
      .sort((a, b) => a.meta.order - b.meta.order)
  }, [findings])

  if (!groups.length) return null
  return (
    <div className="flex flex-wrap gap-2">
      {groups.map(({ key, count, meta }) => (
        <span
          key={key}
          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-mono border"
          style={{ color: meta.color, borderColor: `${meta.color}33`, background: `${meta.color}0f` }}
        >
          <span aria-hidden="true">{meta.icon}</span>
          {meta.label}
          <span className="px-1.5 py-0.5 rounded bg-[var(--scrim)] text-[var(--text-secondary)]">{count}</span>
        </span>
      ))}
    </div>
  )
}

function isSummary(f) {
  return f?.category === 'posture_summary' || f?.summary === true || typeof f?.posture_score === 'number'
}

function isMetrics(f) {
  return f?.category === 'smb_metrics' || Boolean(f?.smb_metrics)
}

function PipeMatrixPanel({ matrix, L }) {
  if (!matrix || typeof matrix !== 'object' || Object.keys(matrix).length === 0) return null
  const shares = Array.isArray(matrix.admin_shares) ? matrix.admin_shares : []
  return (
    <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4 mb-6">
      <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-3">{L.pipeMatrix}</div>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
        {PIPE_DEFS.map(({ key, label, critical }) => {
          const open = Boolean(matrix[key])
          return (
            <div key={key} className={`rounded-lg border px-2 py-2 ${open ? (critical ? 'border-rose-500/40 bg-rose-500/10' : 'border-orange-500/30 bg-orange-500/10') : 'border-[var(--border-subtle)] bg-[var(--row-hover-bg)]'}`}>
              <div className="text-[10px] font-mono text-[var(--text-tertiary)] truncate">{label}</div>
              <div className={`text-xs font-mono mt-0.5 ${open ? (critical ? 'text-rose-300' : 'text-orange-300') : 'text-emerald-400/80'}`}>
                {open ? L.pipeOpen : L.pipeClosed}
              </div>
            </div>
          )
        })}
      </div>
      {shares.length > 0 && (
        <div className="mt-3 pt-3 border-t border-[var(--border-subtle)]">
          <div className="text-[10px] font-mono text-[var(--text-muted)] mb-2">{L.adminShares}</div>
          <div className="flex flex-wrap gap-2">
            {shares.map((s, i) => (
              <span key={i} className="text-[10px] font-mono px-2 py-1 rounded border border-amber-500/30 bg-amber-500/10 text-amber-200">
                {s.share} · {s.ntstatus}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function MetricsTelemetryPanel({ metrics, L }) {
  if (!metrics) return null
  const m = metrics.smb_metrics || metrics.evidence || metrics
  const rw = m.ransomware_readiness ?? 0
  const rwColor = rw >= 70 ? '#ef4444' : rw >= 40 ? '#f97316' : '#34d399'
  const elapsed = m.scan_elapsed_ms
  const ms17 = m.ms17_010_ntstatus
  return (
    <div className="rounded-2xl border border-cyan-500/20 bg-gradient-to-br from-cyan-950/20 to-black/40 p-4 mb-6">
      <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-3">{L.telemetry}</div>
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <div>
          <div className="text-[10px] font-mono text-[var(--text-muted)]">{L.probesRun}</div>
          <div className="text-2xl font-bold font-mono text-white">{m.probes_run ?? '—'}</div>
        </div>
        <div>
          <div className="text-[10px] font-mono text-[var(--text-muted)]">{L.implementation}</div>
          <div className="text-sm font-mono text-cyan-200">{m.implementation ?? '—'}</div>
        </div>
        <div>
          <div className="text-[10px] font-mono text-[var(--text-muted)]">{L.maxDialect}</div>
          <div className="text-sm font-mono text-[var(--text-secondary)]">{m.max_dialect ?? '—'}</div>
        </div>
        <div>
          <div className="text-[10px] font-mono text-[var(--text-muted)]">{L.ransomwareReadiness}</div>
          <div className="text-2xl font-black font-mono" style={{ color: rwColor }}>{rw}<span className="text-sm text-[var(--text-muted)]">/100</span></div>
        </div>
        {elapsed != null && (
          <div>
            <div className="text-[10px] font-mono text-[var(--text-muted)]">{L.scanElapsed}</div>
            <div className="text-sm font-mono text-[var(--text-secondary)]">{elapsed} ms</div>
          </div>
        )}
        {ms17 != null && ms17 !== 0 && (
          <div>
            <div className="text-[10px] font-mono text-[var(--text-muted)]">{L.ms17Status}</div>
            <div className="text-sm font-mono text-amber-200/90">{typeof ms17 === 'number' ? `0x${ms17.toString(16).padStart(8, '0').toUpperCase()}` : String(ms17)}</div>
          </div>
        )}
      </div>
    </div>
  )
}

function CompliancePanel({ metrics, L }) {
  const gaps = metrics?.smb_metrics?.compliance_gaps || metrics?.evidence?.compliance_gaps || metrics?.compliance_gaps
  if (!gaps) return null
  const sections = [
    { key: 'cis', label: 'CIS Controls', color: '#38bdf8' },
    { key: 'nist_800_53', label: 'NIST 800-53', color: '#a78bfa' },
    { key: 'pci_dss', label: 'PCI-DSS', color: '#fbbf24' },
    { key: 'iso_27001', label: 'ISO 27001', color: '#34d399' },
  ]
  const any = sections.some((s) => Array.isArray(gaps[s.key]) && gaps[s.key].length > 0)
  if (!any) return null
  return (
    <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--table-surface)] p-4 mb-6">
      <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-3">{L.compliance}</div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {sections.map(({ key, label, color }) => (
          <div key={key}>
            <div className="text-[10px] font-mono mb-2" style={{ color }}>{label}</div>
            <ul className="space-y-1">
              {(gaps[key] || []).map((item, i) => (
                <li key={i} className="text-[10px] font-mono text-[var(--text-tertiary)] leading-relaxed">• {item}</li>
              ))}
              {(!gaps[key] || gaps[key].length === 0) && <li className="text-[10px] font-mono text-emerald-400/70">{L.noGaps}</li>}
            </ul>
          </div>
        ))}
      </div>
    </div>
  )
}

function SmbExposureGraph({ graph, running }) {
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

    const nodes = Array.isArray(graph?.nodes) ? graph.nodes : []
    const edges = Array.isArray(graph?.edges) ? graph.edges : []

    const layout = nodes.map((n, i) => {
      const ang = (i / Math.max(nodes.length, 1)) * Math.PI * 2 - Math.PI / 2
      const r = n.type === 'source' ? 0 : Math.min(w, h) * 0.34
      return {
        ...n,
        x: w / 2 + Math.cos(ang) * r,
        y: h / 2 + Math.sin(ang) * r,
        pulse: Math.random() * Math.PI * 2,
        size: n.type === 'source' ? 16 : n.type === 'impact' ? 14 : n.type === 'exposure' || n.type === 'rpc' ? 11 : 9,
      }
    })

    const colorFor = (type) => ({
      source: '#64748b',
      service: ACCENT,
      share: ACCENT2,
      rpc: '#a855f7',
      exposure: '#ef4444',
      impact: '#fb7185',
    }[type] || '#94a3b8')

    const draw = () => {
      ctx.clearRect(0, 0, w, h)
      edges.forEach((e) => {
        const a = layout.find((n) => n.id === e.from)
        const b = layout.find((n) => n.id === e.to)
        if (!a || !b) return
        ctx.beginPath()
        ctx.moveTo(a.x, a.y)
        ctx.lineTo(b.x, b.y)
        ctx.strokeStyle = 'rgba(59,130,246,0.22)'
        ctx.lineWidth = 1
        ctx.stroke()
      })
      layout.forEach((n) => {
        n.pulse += running ? 0.07 : 0.02
        const glow = 0.5 + Math.sin(n.pulse) * 0.5
        const col = colorFor(n.type)
        ctx.beginPath()
        ctx.arc(n.x, n.y, n.size * (running ? 1 + glow * 0.15 : 1), 0, Math.PI * 2)
        ctx.fillStyle = col + 'cc'
        ctx.fill()
        if (n.label) {
          ctx.font = '8px monospace'
          ctx.fillStyle = 'rgba(255,255,255,0.55)'
          ctx.textAlign = 'center'
          ctx.fillText(String(n.label).slice(0, 18), n.x, n.y + n.size + 10)
        }
      })
      animRef.current = requestAnimationFrame(draw)
    }
    draw()
    return () => { if (animRef.current) cancelAnimationFrame(animRef.current) }
  }, [graph, running])

  return (
    <canvas
      ref={canvasRef}
      className="w-full h-44 rounded-xl bg-[var(--bg-3)] border border-[var(--border-subtle)]"
      aria-label="SMB exposure graph"
    />
  )
}

function Toggle({ on, onClick, label }) {
  return (
    <Button variant="unstyled" type="button" onClick={onClick} className="w-full flex items-center justify-between gap-2 px-3 py-2 rounded-lg bg-[var(--row-hover-bg)] border border-[var(--border-subtle)] hover:bg-[var(--row-hover-bg)] text-left">
      <span className="text-[11px] font-mono text-[var(--text-secondary)]">{label}</span>
      <span className={`shrink-0 w-9 h-5 rounded-full relative transition-colors ${on ? 'bg-blue-500/70' : 'bg-white/15'}`}>
        <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all ${on ? 'left-[18px]' : 'left-0.5'}`} />
      </span>
    </Button>
  )
}

function PostureCard({ summary, graph, pathCount, L, running }) {
  if (!summary) return null
  const ev = summary.evidence || {}
  const score = summary.posture_score ?? ev.posture_score ?? 0
  const grade = summary.grade ?? ev.grade ?? ev.posture_grade ?? '—'
  const counts = summary.counts ?? ev.counts ?? {}
  const exposureGraph = graph ?? summary.exposure_graph ?? ev.exposure_graph

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-2xl border border-blue-500/25 bg-gradient-to-br from-blue-950/30 via-orange-950/10 to-black/40 p-5 mb-6">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-2">{L.posture}</div>
          <div className="flex items-center gap-4">
            <div className="relative w-24 h-24 shrink-0">
              <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                <circle cx="50" cy="50" r="44" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="8" />
                <circle cx="50" cy="50" r="44" fill="none" stroke={gradeColor(grade)} strokeWidth="8" strokeLinecap="round" strokeDasharray={`${(score / 100) * 276.46} 276.46`} />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-2xl font-bold" style={{ color: gradeColor(grade) }}>{score}</span>
                <span className="text-[9px] font-mono text-[var(--text-muted)]">/100</span>
              </div>
            </div>
            <div>
              <div className="text-[10px] font-mono text-[var(--text-muted)]">{L.grade}</div>
              <div className="text-4xl font-black font-mono" style={{ color: gradeColor(grade) }}>{grade}</div>
              {pathCount > 0 && (
                <div className="text-[10px] font-mono text-rose-300/80 mt-1">{pathCount} attack path(s)</div>
              )}
            </div>
          </div>
        </div>
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-2">{L.counts}</div>
          <div className="flex flex-wrap gap-1.5">
            {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
              <span key={s} className="inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-mono"
                style={{ color: SEV_COLOR[s], backgroundColor: `${SEV_COLOR[s]}14` }}>
                <b>{counts[s] ?? 0}</b> {s}
              </span>
            ))}
          </div>
        </div>
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-1">{L.graphTitle}</div>
          <p className="text-[10px] text-[var(--text-muted)] mb-2">{L.graphHint}</p>
          <SmbExposureGraph graph={exposureGraph} running={running} />
        </div>
      </div>
    </motion.div>
  )
}

function AttackPathCard({ finding }) {
  const steps = Array.isArray(finding.attack_path)
    ? finding.attack_path
    : finding.evidence?.attack_path_steps || []
  return (
    <div className="rounded-xl border border-rose-500/35 bg-gradient-to-br from-rose-950/30 to-black/30 p-4 mb-3">
      <div className="flex items-start justify-between gap-3 mb-3">
        <h4 className="text-sm font-bold text-rose-100 leading-snug">{finding.title}</h4>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-rose-500/40 text-rose-300 uppercase">{finding.severity}</span>
      </div>
      {finding.description && <p className="text-xs text-[var(--text-tertiary)] mb-3 leading-relaxed">{finding.description}</p>}
      <ol className="space-y-2">
        {steps.map((step, i) => (
          <li key={i} className="flex gap-2.5 text-xs">
            <span className="shrink-0 w-6 h-6 rounded-full bg-rose-500/20 text-rose-200 flex items-center justify-center font-mono text-[10px] font-bold">{i + 1}</span>
            <span className="text-[var(--text-secondary)] leading-relaxed pt-0.5">{step}</span>
          </li>
        ))}
      </ol>
    </div>
  )
}

function FindingCard({ finding, L }) {
  const [open, setOpen] = useState(false)
  const sev = (finding.severity || 'info').toLowerCase()
  const ev = finding.evidence || {}
  const checks = Array.isArray(ev.checks) ? ev.checks : []
  const evKeys = Object.keys(ev).filter((k) => k !== 'checks')
  const standards = Array.isArray(finding.standards) ? finding.standards : []

  return (
    <div className="rounded-xl border border-[var(--border-default)] bg-[var(--row-hover-bg)] overflow-hidden mb-2">
      <Button variant="unstyled" type="button" onClick={() => setOpen((o) => !o)} className="w-full flex items-start gap-3 p-3 text-left hover:bg-[var(--row-hover-bg)]">
        <span className="mt-1 w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: SEV_COLOR[sev] }} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[10px] font-mono uppercase" style={{ color: SEV_COLOR[sev] }}>{sev}</span>
            {finding.mitre_attack && <span className="text-[10px] font-mono text-[var(--text-disabled)]">{finding.mitre_attack}</span>}
            {standards.slice(0, 3).map((s) => (
              <span key={s} className="text-[9px] font-mono px-1 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-300/80">{s}</span>
            ))}
          </div>
          <div className="text-sm text-[var(--text-primary)] mt-0.5 font-medium">{finding.title}</div>
        </div>
        <span className="text-[var(--text-disabled)] text-xs">{open ? '▾' : '▸'}</span>
      </Button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden px-3 pb-3">
            <p className="text-xs text-[var(--text-tertiary)] leading-relaxed">{finding.description}</p>
            {evKeys.length > 0 && (
              <div className="mt-2 rounded-lg bg-[var(--bg-2)] border border-[var(--border-subtle)] p-2">
                <div className="text-[10px] uppercase tracking-widest text-[var(--text-disabled)] mb-1">{L.evidence}</div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-3 gap-y-0.5 font-mono text-[10px]">
                  {evKeys.map((k) => (
                    <div key={k} className="flex gap-2">
                      <span className="text-[var(--text-muted)] shrink-0">{k}</span>
                      <span className="text-[var(--text-tertiary)] break-all">{typeof ev[k] === 'object' ? JSON.stringify(ev[k]) : String(ev[k])}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {checks.length > 0 && (
              <div className="mt-2 space-y-1">
                {checks.map((c, i) => (
                  <div key={i} className="flex gap-2 text-[10px] font-mono">
                    <span className={c.observed ? 'text-emerald-400' : 'text-[var(--text-disabled)]'}>{c.observed ? '✓' : '·'}</span>
                    <span className="text-[var(--text-tertiary)]">{c.name}</span>
                  </div>
                ))}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export default function SmbNetbiosCommandCenter() {
  const { i18n } = useTranslation()
  const lang = i18n.language?.startsWith('he') ? 'he' : 'en'
  const L = LABELS[lang]

  const [clients, setClients] = useState([])
  const [clientId, setClientId] = useState('')
  const { postScan } = useCommandCenterScan(clientId)
  const [target, setTarget] = useState('')
  const [targetTouched, setTargetTouched] = useState(false)
  const [params, setParams] = useState(DEFAULT_PARAMS)
  useIntegrationsPrefill(ENGINE_ID, clientId, setParams)
  const [showParams, setShowParams] = useState(true)
  const [status, setStatus] = useState('idle')
  const [findings, setFindings] = useState([])
  const [pendingJobId, setPendingJobId] = useState(null)
  const [lastRun, setLastRun] = useState(null)
  const [toast, setToast] = useState(null)

  useEffect(() => {
    // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
    apiFetch('/api/clients').then((d) => { if (Array.isArray(d)) setClients(d) }).catch(() => {})
  }, [])

  const selectedClient = useMemo(() => clients.find((c) => String(c.id) === String(clientId)), [clients, clientId])
  useEffect(() => {
    if (!targetTouched) setTarget(firstClientTarget(selectedClient))
  }, [selectedClient, targetTouched])

  const showToastMsg = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((x) => (x?.id === id ? null : x)), 5000)
  }, [])

  const set = (key, val) => setParams((p) => ({ ...p, [key]: val }))

  const buildBody = useCallback(() => {
    const body = {
      engine: ENGINE_ID,
      target: target.trim(),
      ports: params.ports,
      timeout_ms: Number(params.timeout_ms) || 4000,
      netbios_udp_port: Number(params.netbios_udp_port) || 137,
      check_signing: params.check_signing,
      check_encryption: params.check_encryption,
      check_smb1: params.check_smb1,
      check_ms17_010: params.check_ms17_010,
      check_smbghost: params.check_smbghost,
      check_spnego: params.check_spnego,
      check_ipc_pipes: params.check_ipc_pipes,
      check_admin_shares: params.check_admin_shares,
      check_ntlm: params.check_ntlm,
      check_ntlm_weak: params.check_ntlm_weak,
      check_implementation: params.check_implementation,
      check_capabilities: params.check_capabilities,
      check_dialect_downgrade: params.check_dialect_downgrade,
      check_petitpotam: params.check_petitpotam,
      check_zerologon: params.check_zerologon,
      check_printnightmare: params.check_printnightmare,
      check_netbios: params.check_netbios,
      check_nbns_roles: params.check_nbns_roles,
      check_mac_vendor: params.check_mac_vendor,
      check_139: params.check_139,
      check_uptime: params.check_uptime,
      scan_all_ports: params.scan_all_ports,
      synthesize_attack_path: params.synthesize_attack_path,
      posture_scoring: params.posture_scoring,
      emit_metrics: params.emit_metrics,
    }
    if (clientId) body.client_id = Number(clientId)
    return body
  }, [target, params, clientId])

  const hubScanParams = useMemo(() => {
    const { engine, target, client_id, ...rest } = buildBody()
    return rest
  }, [buildBody])
  useSyncHubScanParams(ENGINE_ID, hubScanParams)

  const handleRun = useCallback(async () => {
    if (!clientId) { showToastMsg('error', L.selectClientFirst); return }
    if (!target.trim()) { showToastMsg('error', L.targetPh); return }
    setStatus('running')
    setFindings([])
    try {
      const { ok, data: d, status: _status } = await postScan(buildBody())
      if (!ok) {
        setStatus('error')
        showToastMsg('error', d.detail || L.scanFailed)
        return
      }
      showToastMsg('info', `${L.queued} (${d.job_id ?? ''})`)
      if (d.job_id) setPendingJobId(d.job_id)
      else setStatus('error')
    } catch (e) {
      setStatus('error')
      showToastMsg('error', e?.message ?? L.scanFailed)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clientId, target, buildBody, showToastMsg, L])

  const handleExport = useCallback(() => {
    const blob = new Blob([JSON.stringify({ engine: ENGINE_ID, target, findings, exported_at: new Date().toISOString() }, null, 2)], { type: 'application/json' })
    downloadBytes(blob, `smb-netbios-${target.replace(/[^a-z0-9.-]/gi, '_')}.json`)
  }, [target, findings])

  const summary = useMemo(() => findings.find(isSummary), [findings])
  const metrics = useMemo(() => findings.find(isMetrics), [findings])
  const attackPaths = useMemo(() => findings.filter((f) => f.category === 'attack_path'), [findings])
  const realFindings = useMemo(
    () => findings.filter((f) => !isSummary(f) && !isMetrics(f) && f.category !== 'attack_path'),
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
      const fs = await resolveJobFindings(job, ENGINE_ID, clientId)
      setFindings(Array.isArray(fs) ? fs : [])
      setLastUpdated(new Date().toISOString())
      if (pendingJobId) setLastJobId(pendingJobId)
      setPendingJobId(null)
    },
  })

  const pipeMatrix = useMemo(
    () => metrics?.smb_metrics?.pipe_matrix ?? metrics?.evidence?.pipe_matrix ?? null,
    [metrics],
  )

  const statusColor = { idle: '#475569', running: ACCENT, completed: '#4ade80', error: '#ef4444' }[status]
  const exposureGraph = summary?.exposure_graph ?? summary?.evidence?.exposure_graph

  return (
    <PageShell
      hideHubParams
      title={L.title}
      badge={L.badge}
      badgeColor={ACCENT}
      subtitle={L.subtitle}
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
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-[var(--bg-1)] border-blue-500/30 text-blue-200'}`}>
          {toast.msg}
        </div>
      )}

      <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 mb-6">
        <div className="flex flex-wrap items-end gap-4">
          <div className="flex flex-col gap-1">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{L.client}</label>
            <select value={clientId} onChange={(e) => { setClientId(e.target.value); setTargetTouched(false) }}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono min-w-[180px] focus:outline-none focus:border-blue-500/40">
              <option value="">{L.selectClient}</option>
              {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </div>
          <div className="flex flex-col gap-1 flex-1 min-w-[200px]">
            <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">{L.target}</label>
            <input type="text" value={target} onChange={(e) => { setTarget(e.target.value); setTargetTouched(true) }} placeholder={L.targetPh}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-blue-500/40" />
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: statusColor, boxShadow: status === 'running' ? `0 0 6px ${ACCENT}` : 'none' }} />
            <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{status}</span>
          </div>
          <Button variant="unstyled" type="button" onClick={handleRun} disabled={status === 'running' || !clientId}
            className="px-5 py-2 rounded-xl font-mono text-sm border border-blue-500/40 text-blue-300 bg-blue-500/10 hover:bg-blue-500/20 transition-all disabled:opacity-40">
            {status === 'running' ? L.scanning : `▶ ${L.run}`}
          </Button>
          <Button variant="unstyled" type="button" onClick={() => setShowParams((s) => !s)} className="px-3 py-2 rounded-xl font-mono text-xs border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]">
            {showParams ? L.hideParams : L.showParams}
          </Button>
          {findings.length > 0 && (
            <Button variant="unstyled" type="button" onClick={handleExport} className="px-3 py-2 rounded-xl font-mono text-xs border border-[var(--border-default)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]">
              {L.export}
            </Button>
          )}
        </div>

        <AnimatePresence initial={false}>
          {showParams && (
            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
              <div className="mt-5 pt-5 border-t border-[var(--border-subtle)] grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-2">{L.layers}</div>
                  <div className="space-y-1.5">
                    <Toggle on={params.check_signing} onClick={() => set('check_signing', !params.check_signing)} label={L.checkSigning} />
                    <Toggle on={params.check_encryption} onClick={() => set('check_encryption', !params.check_encryption)} label={L.checkEncryption} />
                    <Toggle on={params.check_smb1} onClick={() => set('check_smb1', !params.check_smb1)} label={L.checkSmb1} />
                    <Toggle on={params.check_ms17_010} onClick={() => set('check_ms17_010', !params.check_ms17_010)} label={L.checkMs17} />
                    <Toggle on={params.check_smbghost} onClick={() => set('check_smbghost', !params.check_smbghost)} label={L.checkSmbghost} />
                    <Toggle on={params.check_spnego} onClick={() => set('check_spnego', !params.check_spnego)} label={L.checkSpnego} />
                    <Toggle on={params.check_ipc_pipes} onClick={() => set('check_ipc_pipes', !params.check_ipc_pipes)} label={L.checkIpc} />
                    <Toggle on={params.check_admin_shares} onClick={() => set('check_admin_shares', !params.check_admin_shares)} label={L.checkAdminShares} />
                    <Toggle on={params.check_ntlm} onClick={() => set('check_ntlm', !params.check_ntlm)} label={L.checkNtlm} />
                    <Toggle on={params.check_ntlm_weak} onClick={() => set('check_ntlm_weak', !params.check_ntlm_weak)} label={L.checkNtlmWeak} />
                    <Toggle on={params.check_implementation} onClick={() => set('check_implementation', !params.check_implementation)} label={L.checkImplementation} />
                    <Toggle on={params.check_capabilities} onClick={() => set('check_capabilities', !params.check_capabilities)} label={L.checkCapabilities} />
                    <Toggle on={params.check_dialect_downgrade} onClick={() => set('check_dialect_downgrade', !params.check_dialect_downgrade)} label={L.checkDialectDowngrade} />
                    <Toggle on={params.check_petitpotam} onClick={() => set('check_petitpotam', !params.check_petitpotam)} label={L.checkPetitpotam} />
                    <Toggle on={params.check_zerologon} onClick={() => set('check_zerologon', !params.check_zerologon)} label={L.checkZerologon} />
                    <Toggle on={params.check_printnightmare} onClick={() => set('check_printnightmare', !params.check_printnightmare)} label={L.checkPrintnightmare} />
                    <Toggle on={params.check_netbios} onClick={() => set('check_netbios', !params.check_netbios)} label={L.checkNetbios} />
                    <Toggle on={params.check_nbns_roles} onClick={() => set('check_nbns_roles', !params.check_nbns_roles)} label={L.checkNbnsRoles} />
                    <Toggle on={params.check_139} onClick={() => set('check_139', !params.check_139)} label={L.check139} />
                    <Toggle on={params.check_uptime} onClick={() => set('check_uptime', !params.check_uptime)} label={L.checkUptime} />
                    <Toggle on={params.check_mac_vendor} onClick={() => set('check_mac_vendor', !params.check_mac_vendor)} label={L.checkMacVendor} />
                    <Toggle on={params.scan_all_ports} onClick={() => set('scan_all_ports', !params.scan_all_ports)} label={L.scanAllPorts} />
                    <Toggle on={params.synthesize_attack_path} onClick={() => set('synthesize_attack_path', !params.synthesize_attack_path)} label={L.attackPaths} />
                    <Toggle on={params.posture_scoring} onClick={() => set('posture_scoring', !params.posture_scoring)} label={L.postureScoring} />
                    <Toggle on={params.emit_metrics} onClick={() => set('emit_metrics', !params.emit_metrics)} label={L.emitMetrics} />
                  </div>
                </div>
                <div className="space-y-3">
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{L.ports}</label>
                    <input type="text" value={params.ports} onChange={(e) => set('ports', e.target.value)}
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)] focus:outline-none focus:border-blue-500/40" />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)] block mb-1">{L.timeout}</label>
                    <input type="number" min={200} max={30000} value={params.timeout_ms} onChange={(e) => set('timeout_ms', e.target.value)}
                      className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs font-mono text-[var(--text-secondary)] focus:outline-none focus:border-blue-500/40" />
                  </div>
                </div>
                <div className="flex flex-col gap-2">
                  <Button variant="unstyled" type="button" onClick={() => setParams(DEFAULT_PARAMS)} className="text-[10px] font-mono text-[var(--text-muted)] hover:text-[var(--text-secondary)] text-left">{L.reset}</Button>
                  <div className="text-[10px] font-mono text-[var(--text-disabled)] leading-relaxed rounded-lg border border-[var(--border-subtle)] p-3 bg-[var(--table-surface)]">
                    MITRE T1021.002 · T1210 · T1187 · T1018 — every finding requires an observed SMB/NetBIOS protocol response on the wire.
                  </div>
                  <div className="text-[10px] font-mono text-[var(--text-disabled)] mt-auto">{L.related}:</div>
                  <div className="flex flex-wrap gap-2">
                    <Link to="/network" className="text-[10px] font-mono text-blue-300/70 hover:text-blue-200">{L.relatedNetwork}</Link>
                    <Link to="/tls-posture" className="text-[10px] font-mono text-blue-300/70 hover:text-blue-200">{L.relatedTls}</Link>
                    <Link to="/kerberos-security" className="text-[10px] font-mono text-blue-300/70 hover:text-blue-200">{L.relatedKerberos}</Link>
                    <Link to={`/engines/${ENGINE_ID}`} className="text-[10px] font-mono text-blue-300/70 hover:text-blue-200">{L.relatedEngine}</Link>
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
        {lastRun && <p className="text-[10px] font-mono text-[var(--text-disabled)] mt-3">{L.lastRun}: {lastRun}</p>}
      </div>

      {!clientId && <p className="text-xs font-mono text-[var(--text-muted)] mb-6">{L.runToPopulate}</p>}

      {(summary || findings.length > 0) && (
        <PostureCard summary={summary} graph={exposureGraph} pathCount={attackPaths.length} L={L} running={status === 'running'} />
      )}

      <MetricsTelemetryPanel metrics={metrics} L={L} />
      <CompliancePanel metrics={metrics} L={L} />
      <PipeMatrixPanel matrix={pipeMatrix} L={L} />

      {attackPaths.length > 0 && (
        <div className="mb-6">
          <h3 className="text-sm font-mono text-rose-300/90 uppercase tracking-wider mb-3">{L.pathsTitle} · {attackPaths.length}</h3>
          {attackPaths.map((f, i) => <AttackPathCard key={i} finding={f} />)}
        </div>
      )}

      {findings.length === 0 && status !== 'running' && (
        <p className="text-xs font-mono text-[var(--text-disabled)] text-center py-12">{status === 'completed' ? L.noFindings : L.runToPopulate}</p>
      )}

      {realFindings.length > 0 && <CategoryBreakdown findings={realFindings} />}

      <WeissmanFindingsPanel
        findings={realFindings}
        filteredFindings={filteredFindings}
        counts={counts}
        total={realFindings.length}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        severityFilter={severityFilter}
        onSeverityChange={setSeverityFilter}
        pending={status === 'running' && realFindings.length === 0}
        loading={historyLoading && realFindings.length === 0}
        lastUpdated={lastUpdated}
        jobId={pendingJobId || lastJobId}
        accent={ACCENT}
        title={L.findingsTitle}
        showEmptyReady={status !== 'running' && realFindings.length === 0 && findings.length === 0}
        emptyReadyTitle={L.runToPopulate}
        emptyReadyBody={L.runToPopulate}
        emptyTitle={L.noFindings}
        emptyBody={L.noFindings}
        renderFinding={(f, i) => <FindingCard key={i} finding={f} L={L} />}
      />
    </PageShell>
  )
}
