// Active Directory / Kerberos Security Command Center (engine: kerberoasting).
// Wiz-style agentless AD external posture — DNS SRV, LDAP enumeration, KDC probe, SPNEGO, attack paths.
import { firstClientTarget } from '../lib/clientTarget'
import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useIntegrationsPrefill } from '../hooks/useHubLocalScanParams'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../lib/apiBase'
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'
import { downloadBytes } from '../lib/pdfExport'

const ENGINE_ID = 'kerberoasting'
const ACCENT = '#f59e0b'
const ACCENT2 = '#a78bfa'

const LABELS = {
  en: {
    title: 'Active Directory & Kerberos Security Command Center',
    subtitle: 'Supreme-tier agentless AD posture — 18 live probe layers, DNS SRV auto-DC discovery, SMB2 signing parse, LDAP StartTLS, AD CS, Entra hybrid, tier-0 SPNs, toxic combinations & remediation roadmap',
    badge: 'AD Kerberos Posture',
    client: 'Client',
    selectClient: 'Select client…',
    selectClientFirst: 'Select a client first',
    target: 'Target (DC hostname, ADFS URL, or domain root)',
    targetPh: 'dc01.corp.example.com  or  https://adfs.corp.example.com  or  corp.example.com',
    domain: 'AD domain (DNS SRV + Kerberos realm)',
    domainPh: 'corp.example.com',
    run: 'Run AD/Kerberos assessment',
    scanning: 'Assessing…',
    queued: 'Assessment queued',
    scanFailed: 'Scan failed',
    intensity: 'Probe intensity',
    light: 'Light', normal: 'Normal', aggressive: 'Aggressive',
    presets: 'AD deployment presets',
    layers: 'Assessment layers',
    checkPorts: 'AD service port cartography (88/389/445/…)',
    checkSrv: 'DNS SRV DC discovery (_ldap/_kerberos/_gc)',
    checkLdapAnon: 'Live anonymous LDAP bind probe',
    checkLdapEnum: 'LDAP SPN & AS-REP enumeration',
    checkKdc: 'Kerberos KDC liveness (AS-REQ → KRB-ERROR)',
    checkSpnego: 'HTTP SPNEGO/NTLM (ADFS/OWA/WinRM)',
    checkStartTls: 'LDAP StartTLS on 389/tcp',
    checkSmbSigning: 'SMB2 signing required probe (445)',
    checkAdcs: 'AD CS web enrollment (/certsrv)',
    checkUserEnum: 'Kerberos user-enumeration oracle (AS-REQ)',
    checkDelegation: 'Unconstrained + RBCD delegation LDAP',
    checkMachineSpns: 'Machine-account SPN enumeration',
    checkMsdcs: '_msdcs DNS zone cartography',
    checkHybridEntra: 'Microsoft Entra GetUserRealm + Autodiscover',
    checkTier0: 'Tier-0 Kerberoastable SPNs (adminCount=1)',
    checkLdapsTls: 'LDAPS TLS certificate handshake',
    emitAgentGuidance: 'Show honest agent-required capability gaps',
    probeUsers: 'Kerberos probe usernames (one per line)',
    attackPaths: 'Synthesize Kerberoasting attack paths',
    advanced: 'Advanced parameters',
    adPorts: 'AD ports (comma-separated)',
    extraPaths: 'Extra HTTP paths (one per line)',
    dcHosts: 'Additional DC hosts (comma-separated)',
    ldapBase: 'LDAP base DN override',
    maxLdap: 'Max LDAP entries to report',
    resolver: 'DNS resolver',
    strictMode: 'Strict mode (escalate severities)',
    timeout: 'TCP/LDAP timeout (ms)',
    concurrency: 'Probe concurrency',
    reset: 'Reset defaults',
    export: 'Export JSON',
    posture: 'AD external posture score',
    grade: 'Grade',
    verdict: 'Roastability verdict',
    counts: 'Findings by severity',
    categories: 'Control domains assessed',
    pathsTitle: 'Kerberoasting attack paths',
    findingsTitle: 'AD/Kerberos findings',
    evidence: 'Evidence trail',
    remediation: 'Remediation',
    confidence: 'Confidence',
    standards: 'Standards',
    noFindings: 'No external AD/Kerberos weaknesses observed — strong perimeter posture.',
    runToPopulate: 'Configure the AD target/domain and run the assessment.',
    filterAll: 'all',
    related: 'Related identity engines',
    relatedIdentity: 'Identity & SSO Command Center',
    relatedSpray: 'Password Spray Posture',
    relatedSaml: 'SAML Attack Engine',
    relatedEngine: 'Engine detail (API)',
    graphTitle: 'AD exposure graph',
    graphHint: 'KDC → LDAP → SPNs → offline roast paths',
    toxicTitle: 'Toxic combination detected',
    roadmapTitle: 'Prioritized remediation roadmap',
    categoryScores: '8-domain posture breakdown',
    agentGapTitle: 'Agent-required deep coverage',
  },
  he: {
    title: 'מרכז פיקוד Active Directory ו-Kerberos',
    subtitle: 'תנוחת AD חיצונית ללא סוכן — DNS SRV, בדיקות LDAP/KDC חיות, ספירת SPN ו-AS-REP, SPNEGO, סינתזת נתיבי תקיפה',
    badge: 'תנוחת Kerberos AD',
    client: 'לקוח',
    selectClient: 'בחר לקוח…',
    selectClientFirst: 'בחר לקוח תחילה',
    target: 'יעד (DC, ADFS URL, או שורש דומיין)',
    targetPh: 'dc01.corp.example.com  או  https://adfs.corp.example.com  או  corp.example.com',
    domain: 'דומיין AD (DNS SRV + Kerberos realm)',
    domainPh: 'corp.example.com',
    run: 'הרץ הערכת AD/Kerberos',
    scanning: 'מעריך…',
    queued: 'ההערכה בתור',
    scanFailed: 'הסריקה נכשלה',
    intensity: 'עוצמת בדיקה',
    light: 'קלה', normal: 'רגילה', aggressive: 'אגרסיבית',
    presets: 'תבניות פריסת AD',
    layers: 'שכבות הערכה',
    checkPorts: 'מיפוי פורטים AD (88/389/445/…)',
    checkSrv: 'גילוי DC ב-DNS SRV (_ldap/_kerberos/_gc)',
    checkLdapAnon: 'בדיקת LDAP אנונימי חיה',
    checkLdapEnum: 'ספירת SPN ו-AS-REP ב-LDAP',
    checkKdc: 'חיות KDC (AS-REQ → KRB-ERROR)',
    checkSpnego: 'HTTP SPNEGO/NTLM (ADFS/OWA/WinRM)',
    checkStartTls: 'LDAP StartTLS על 389/tcp',
    checkSmbSigning: 'בדיקת SMB2 signing (445)',
    checkAdcs: 'AD CS web enrollment (/certsrv)',
    checkUserEnum: 'Oracle לספירת משתמשים ב-Kerberos',
    checkDelegation: 'Delegation + RBCD ב-LDAP',
    checkMachineSpns: 'SPN של חשבונות מחשב',
    checkMsdcs: 'מיפוי DNS _msdcs',
    checkHybridEntra: 'Entra GetUserRealm + Autodiscover',
    checkTier0: 'SPN Tier-0 (adminCount=1)',
    checkLdapsTls: 'TLS handshake על LDAPS',
    emitAgentGuidance: 'הצג פערים שדורשים סוכן',
    probeUsers: 'שמות משתמש לבדיקת Kerberos (שורה לכל שם)',
    attackPaths: 'סינתזת נתיבי Kerberoasting',
    advanced: 'פרמטרים מתקדמים',
    adPorts: 'פורטים AD (מופרדים בפסיקים)',
    extraPaths: 'נתיבי HTTP נוספים (שורה לכל נתיב)',
    dcHosts: 'DC נוספים (מופרדים בפסיקים)',
    ldapBase: 'דריסת LDAP base DN',
    maxLdap: 'מקסימום רשומות LDAP לדיווח',
    resolver: 'DNS resolver',
    strictMode: 'מצב קפדני (הסלמת חומרה)',
    timeout: 'Timeout TCP/LDAP (ms)',
    concurrency: 'מקביליות',
    reset: 'אפס ברירות מחדל',
    export: 'ייצוא JSON',
    posture: 'ציון תנוחת AD חיצונית',
    grade: 'דירוג',
    verdict: 'פסק דין roastability',
    counts: 'ממצאים לפי חומרה',
    categories: 'תחומי בקרה שנבדקו',
    pathsTitle: 'נתיבי Kerberoasting',
    findingsTitle: 'ממצאי AD/Kerberos',
    evidence: 'שרשרת ראיות',
    remediation: 'תיקון',
    confidence: 'ביטחון',
    standards: 'תקנים',
    noFindings: 'לא נצפו חולשות AD/Kerberos חיצוניות — תנוחת היקף חזקה.',
    runToPopulate: 'הגדר יעד/דומיין AD והרץ הערכה.',
    filterAll: 'הכל',
    related: 'מנועי זהות קשורים',
    relatedIdentity: 'מרכז זהות ו-SSO',
    relatedSpray: 'תנוחת Password Spray',
    relatedSaml: 'מנוע SAML',
    relatedEngine: 'פרטי מנוע (API)',
    graphTitle: 'גרף חשיפת AD',
    graphHint: 'KDC → LDAP → SPNs → נתיבי roast',
    toxicTitle: 'שילוב רעיל (Toxic Combination)',
    roadmapTitle: 'מפת דרכים לתיקון ממוקד',
    categoryScores: 'פירוט 8 תחומי תנוחה',
    agentGapTitle: 'כיסוי עמוק שדורש סוכן',
  },
}

const AD_PRESETS = [
  { id: 'hybrid', label: 'Hybrid AD + ADFS', hint: 'https://adfs.corp.example.com', domain: 'corp.example.com' },
  { id: 'dc', label: 'Domain Controller', hint: 'dc01.corp.example.com', domain: 'corp.example.com' },
  { id: 'entra', label: 'Entra + on-prem sync', hint: 'https://login.microsoftonline.com', domain: 'corp.onmicrosoft.com' },
  { id: 'exchange', label: 'Exchange OWA', hint: 'https://mail.corp.example.com/owa/', domain: 'corp.example.com' },
]

const RESOLVER_OPTIONS = [
  { value: 'system', label: 'System' },
  { value: 'cloudflare', label: 'Cloudflare' },
  { value: 'google', label: 'Google' },
  { value: 'quad9', label: 'Quad9' },
]

const SEVERITY_META = {
  critical: { c: '#ef4444', w: 5 },
  high: { c: '#f97316', w: 4 },
  medium: { c: '#eab308', w: 3 },
  low: { c: '#38bdf8', w: 2 },
  info: { c: '#94a3b8', w: 1 },
}
const sevColor = (s) => (SEVERITY_META[s] || SEVERITY_META.info).c
const sevWeight = (s) => (SEVERITY_META[s] || SEVERITY_META.info).w

function defaultParams() {
  return {
    intensity: 'normal',
    domain: '',
    check_ports: true,
    check_srv: true,
    check_ldap_anon: true,
    check_ldap_enum: true,
    check_kdc_probe: true,
    check_spnego_http: true,
    check_ldap_starttls: true,
    check_smb_signing: true,
    check_adcs_http: true,
    check_user_enum_krb: true,
    check_delegation: true,
    check_machine_spns: true,
    check_msdcs_dns: true,
    check_hybrid_entra: true,
    check_tier0_spns: true,
    check_ldaps_tls: true,
    attack_paths: true,
    emit_agent_guidance: true,
    ad_ports: '88,389,636,3268,3269,445,464,135,5985,5986,3389',
    extra_http_paths: '',
    dc_hosts: '',
    ldap_base_dn: '',
    probe_usernames: 'administrator\nadmin\nkrbtgt\nsvc_backup',
    max_ldap_entries: 32,
    resolver: 'system',
    strict_mode: false,
    timeout_ms: 5000,
    concurrency: 16,
  }
}

const CATEGORY_META = [
  { key: 'dns_exposure', label: 'DNS', color: '#38bdf8' },
  { key: 'ldap_hardening', label: 'LDAP', color: '#a78bfa' },
  { key: 'kerberos_hardening', label: 'Kerberos', color: ACCENT },
  { key: 'spnego_surface', label: 'SPNEGO', color: '#f97316' },
  { key: 'relay_preconditions', label: 'Relay', color: '#ef4444' },
  { key: 'delegation_risk', label: 'Delegation', color: '#fb7185' },
  { key: 'adcs_exposure', label: 'AD CS', color: '#dc2626' },
  { key: 'smb_hardening', label: 'SMB', color: '#22c55e' },
]

function CategoryScoresPanel({ scores, L }) {
  if (!scores || typeof scores !== 'object') return null
  return (
    <div className="rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] p-4 mb-5">
      <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-3">{L.categoryScores}</div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {CATEGORY_META.map(({ key, label, color }) => {
          const v = Number(scores[key] ?? 0)
          const c = v >= 85 ? '#22c55e' : v >= 60 ? '#eab308' : v >= 40 ? '#f97316' : '#ef4444'
          return (
            <div key={key} className="rounded-lg border border-[var(--border-subtle)] p-2">
              <div className="flex justify-between text-[10px] font-mono mb-1">
                <span style={{ color }}>{label}</span>
                <span className="text-[var(--text-secondary)]">{v}</span>
              </div>
              <div className="h-1.5 rounded-full bg-[var(--row-hover-bg)] overflow-hidden">
                <div className="h-full rounded-full" style={{ width: `${v}%`, backgroundColor: c }} />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function ToxicBanner({ finding, L }) {
  if (!finding) return null
  return (
    <div className="rounded-2xl border-2 border-rose-500/50 bg-gradient-to-r from-rose-950/50 via-red-950/30 to-black/40 p-4 mb-5">
      <div className="text-[10px] font-mono uppercase tracking-widest text-rose-300 mb-1">{L.toxicTitle}</div>
      <h3 className="text-sm font-bold text-rose-100 leading-snug">{finding.title}</h3>
      {finding.description && <p className="text-xs text-[var(--text-tertiary)] mt-2 leading-relaxed">{finding.description}</p>}
    </div>
  )
}

function RoadmapCard({ finding, L }) {
  const steps = finding?.evidence?.roadmap
  if (!Array.isArray(steps) || steps.length === 0) return null
  return (
    <div className="rounded-xl border border-emerald-500/25 bg-emerald-950/15 p-4 mb-5">
      <div className="text-[10px] font-mono uppercase tracking-widest text-emerald-300/70 mb-3">{L.roadmapTitle}</div>
      <ol className="space-y-2">
        {steps.map((s, i) => (
          <li key={i} className="flex gap-2 text-xs font-mono">
            <span className="shrink-0 text-emerald-400 font-bold">{s.priority ?? i + 1}.</span>
            <span className="text-[var(--text-secondary)]"><b className="text-emerald-200">{s.action}</b> — {s.detail} <span className="text-[var(--text-muted)]">({s.effort})</span></span>
          </li>
        ))}
      </ol>
    </div>
  )
}

function Chip({ children, color = '#ffffff60' }) {
  return (
    <span className="inline-flex items-center rounded-md px-2 py-0.5 text-[10px] font-mono border"
      style={{ color, borderColor: `${color}40`, backgroundColor: `${color}12` }}>
      {children}
    </span>
  )
}

function SeverityPill({ sev }) {
  const c = sevColor(sev)
  return (
    <span className="inline-flex items-center rounded-md px-2 py-0.5 text-[10px] font-mono font-bold uppercase tracking-wide"
      style={{ color: c, backgroundColor: `${c}1a`, border: `1px solid ${c}40` }}>
      {sev || 'info'}
    </span>
  )
}

function PostureGauge({ score = 0 }) {
  const pct = Math.max(0, Math.min(100, Number(score) || 0))
  const c = pct >= 85 ? '#22c55e' : pct >= 60 ? '#eab308' : pct >= 40 ? '#f97316' : '#ef4444'
  return (
    <div className="flex items-center gap-3">
      <div className="text-4xl font-bold font-mono tabular-nums" style={{ color: c }}>{pct}</div>
      <div className="flex-1">
        <div className="h-2.5 rounded-full bg-[var(--row-hover-bg)] overflow-hidden">
          <div className="h-full rounded-full transition-all duration-700" style={{ width: `${pct}%`, backgroundColor: c }} />
        </div>
        <p className="text-[10px] font-mono text-[var(--text-muted)] mt-1">100 = no observed external AD weakness</p>
      </div>
    </div>
  )
}

function AdGraph({ domain, spnCount, pathCount }) {
  const nodes = [
    { id: 'kdc', label: 'Kerberos KDC', x: 60, y: 90, c: ACCENT },
    { id: 'ldap', label: 'LDAP / GC', x: 220, y: 90, c: '#f97316' },
    { id: 'spn', label: `${spnCount} SPN(s)`, x: 380, y: 90, c: '#ef4444' },
    { id: 'paths', label: `${pathCount} roast path(s)`, x: 540, y: 90, c: '#dc2626' },
  ]
  return (
    <svg viewBox="0 0 620 180" className="w-full" style={{ minWidth: 320, height: 140 }}>
      <line x1="100" y1="90" x2="180" y2="90" stroke="#ffffff25" strokeWidth="2" strokeDasharray="5 4" />
      <line x1="260" y1="90" x2="340" y2="90" stroke="#ffffff25" strokeWidth="2" strokeDasharray="5 4" />
      <line x1="420" y1="90" x2="500" y2="90" stroke="#ffffff25" strokeWidth="2" strokeDasharray="5 4" />
      {nodes.map((n) => (
        <g key={n.id}>
          <circle cx={n.x} cy={n.y} r="10" fill={n.c} fillOpacity="0.9" />
          <text x={n.x} y={n.y + 28} fill="#e5e7eb" fontSize="10" fontFamily="monospace" textAnchor="middle">
            {String(n.label).slice(0, 22)}
          </text>
        </g>
      ))}
      {domain && (
        <text x="310" y="24" fill="#fbbf24" fontSize="10" fontFamily="monospace" textAnchor="middle">
          {domain}
        </text>
      )}
    </svg>
  )
}

function PostureCard({ finding, L, pathCount = 0 }) {
  const ev = finding?.evidence || {}
  const counts = ev.counts || {}
  const score = ev.score ?? finding?.confidence
  const grade = ev.grade ?? '—'
  const verdict = ev.verdict ?? ''
  const spnCount = ev.kerberoast_spn_count ?? 0
  return (
    <div className="rounded-2xl border border-amber-500/20 bg-gradient-to-br from-amber-950/25 via-violet-950/15 to-black/40 p-5 mb-5">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-2">{L.posture}</div>
          <PostureGauge score={score} />
          <div className="mt-3 flex items-center gap-2">
            <span className="text-[10px] font-mono text-[var(--text-muted)]">{L.grade}:</span>
            <span className="text-2xl font-bold font-mono text-white">{grade}</span>
          </div>
          {verdict && (
            <p className="text-[10px] font-mono text-amber-200/80 mt-2 leading-relaxed">{L.verdict}: {verdict}</p>
          )}
        </div>
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-2">{L.counts}</div>
          <div className="flex flex-wrap gap-1.5">
            {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
              <span key={s} className="inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-mono"
                style={{ color: sevColor(s), backgroundColor: `${sevColor(s)}14` }}>
                <b>{counts[s] ?? 0}</b> {s}
              </span>
            ))}
          </div>
          {ev.domain && (
            <div className="mt-4 text-xs font-mono">
              <span className="text-[var(--text-muted)]">{L.domain}: </span>
              <span className="text-amber-200">{ev.domain}</span>
            </div>
          )}
        </div>
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-1">{L.graphTitle}</div>
          <p className="text-[10px] text-[var(--text-muted)] mb-2">{L.graphHint}</p>
          <AdGraph domain={ev.domain} spnCount={spnCount} pathCount={pathCount} />
        </div>
      </div>
      {finding.description && <p className="text-xs text-[var(--text-tertiary)] mt-4 leading-relaxed border-t border-[var(--border-default)] pt-3">{finding.description}</p>}
    </div>
  )
}

function AttackPathCard({ finding }) {
  const steps = Array.isArray(finding.attack_path) ? finding.attack_path : []
  const conf = typeof finding.confidence === 'number' ? Math.round(finding.confidence * 100) : null
  return (
    <div className="rounded-xl border border-rose-500/35 bg-gradient-to-br from-rose-950/30 to-black/30 p-4">
      <div className="flex items-start justify-between gap-3 mb-3">
        <h4 className="text-sm font-bold text-rose-100 leading-snug">{finding.title}</h4>
        <div className="flex gap-1.5 shrink-0">
          <SeverityPill sev={finding.severity} />
          {conf !== null && <Chip color="#22d3ee">{conf}%</Chip>}
        </div>
      </div>
      {finding.mitre_attack && <Chip color="#a78bfa">{finding.mitre_attack}</Chip>}
      {finding.description && <p className="text-xs text-[var(--text-tertiary)] mt-2 mb-3 leading-relaxed">{finding.description}</p>}
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

function renderEvidenceValue(v) {
  if (v === null || v === undefined) return ''
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

function FindingCard({ finding, L }) {
  const [open, setOpen] = useState(false)
  const ev = finding?.evidence || {}
  const checks = Array.isArray(ev.checks) ? ev.checks : []
  const evKeys = Object.keys(ev).filter((k) => !['checks', 'score', 'grade', 'counts', 'domain', 'verdict', 'kerberoast_spn_count', 'asrep_account_count'].includes(k))
  const conf = typeof finding.confidence === 'number' ? Math.round(finding.confidence * 100) : null
  const standards = Array.isArray(finding.standards) ? finding.standards : []

  return (
    <div className="rounded-xl border border-[var(--border-default)] bg-[var(--row-hover-bg)] overflow-hidden">
      <button type="button" onClick={() => setOpen((o) => !o)} className="w-full flex items-start gap-3 p-3 text-left hover:bg-[var(--row-hover-bg)]">
        <span className="mt-0.5 w-1.5 self-stretch rounded-full" style={{ backgroundColor: sevColor(finding.severity) }} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityPill sev={finding.severity} />
            {finding.category && <Chip color={ACCENT2}>{finding.category}</Chip>}
            {finding.mitre_attack && <Chip color="#a78bfa">{finding.mitre_attack}</Chip>}
            {conf !== null && <Chip color="#22d3ee">{L.confidence} {conf}%</Chip>}
          </div>
          <div className="text-sm text-[var(--text-primary)] mt-1 font-medium">{finding.title}</div>
        </div>
        <span className="text-[var(--text-disabled)] text-xs mt-1">{open ? '−' : '+'}</span>
      </button>
      <AnimatePresence>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
            <div className="px-4 pb-4 pt-1 space-y-3 text-xs">
              {finding.description && <p className="text-[var(--text-tertiary)] leading-relaxed">{finding.description}</p>}
              {standards.length > 0 && (
                <div>
                  <div className="text-[10px] uppercase tracking-widest text-[var(--text-disabled)] mb-1">{L.standards}</div>
                  <div className="flex flex-wrap gap-1">{standards.map((s) => <Chip key={s} color="#38bdf8">{s}</Chip>)}</div>
                </div>
              )}
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
    <button type="button" onClick={onClick}
      className="flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-xs font-mono transition-all w-full text-left"
      style={{ borderColor: on ? `${ACCENT}50` : '#ffffff14', backgroundColor: on ? `${ACCENT}14` : 'transparent', color: on ? '#fcd34d' : '#ffffff55' }}>
      <span className="w-7 h-4 rounded-full relative transition-all shrink-0" style={{ backgroundColor: on ? ACCENT : '#ffffff20' }}>
        <span className="absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all" style={{ left: on ? '14px' : '2px' }} />
      </span>
      <span>{label}</span>
    </button>
  )
}

function Segmented({ value, onChange, options }) {
  return (
    <div className="inline-flex rounded-lg border border-[var(--border-default)] p-0.5 bg-[var(--table-surface)]">
      {options.map((o) => (
        <button key={o.value} type="button" onClick={() => onChange(o.value)}
          className="px-3 py-1 rounded-md text-xs font-mono transition-all"
          style={value === o.value ? { backgroundColor: `${ACCENT}25`, color: '#fcd34d' } : { color: '#ffffff50' }}>
          {o.label}
        </button>
      ))}
    </div>
  )
}


export default function KerberosSecurityCommandCenter() {
  const { i18n } = useTranslation()
  const L = LABELS[i18n.language?.startsWith('he') ? 'he' : 'en']

  const [clients, setClients] = useState([])
  const [clientId, setClientId] = useState(null)
  const { postScan } = useCommandCenterScan(clientId)
  const [params, setParams] = useState(defaultParams)
  useIntegrationsPrefill(ENGINE_ID, clientId, setParams)
  const [target, setTarget] = useState('')
  const [status, setStatus] = useState('idle')
  const [findings, setFindings] = useState([])
  const [pendingJobId, setPendingJobId] = useState(null)
  const [lastRun, setLastRun] = useState(null)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [toast, setToast] = useState(null)

  const set = (k, v) => setParams((p) => ({ ...p, [k]: v }))

  useEffect(() => {
    apiFetch('/api/clients').then((r) => (r.ok ? r.json() : [])).then((d) => { if (Array.isArray(d)) setClients(d) }).catch(() => {})
  }, [])

  useEffect(() => {
    if (!clientId) return
    const c = clients.find((x) => String(x.id) === String(clientId))
    const t = firstClientTarget(c)
    if (t) {
      setTarget(t)
      try {
        const u = new URL(t.startsWith('http') ? t : `https://${t}`)
        if (!params.domain) set('domain', u.hostname.split('.').slice(-2).join('.'))
      } catch { /* ignore */ }
    }
  }, [clientId, clients])

  const showToastMsg = useCallback((sev, msg) => {
    const id = Date.now()
    setToast({ id, sev, msg })
    setTimeout(() => setToast((t) => (t?.id === id ? null : t)), 5000)
  }, [])

  const buildBody = useCallback(() => {
    const body = { engine: ENGINE_ID, client_id: Number(clientId) }
    if (target.trim()) body.target = target.trim()
    body.intensity = params.intensity
    body.timeout_ms = Number(params.timeout_ms) || 5000
    body.concurrency = Number(params.concurrency) || 16
    if (params.domain.trim()) body.domain = params.domain.trim()
    const boolFields = [
      'check_ports', 'check_srv', 'check_ldap_anon', 'check_ldap_enum', 'check_kdc_probe',
      'check_spnego_http', 'check_ldap_starttls', 'check_smb_signing', 'check_adcs_http',
      'check_user_enum_krb', 'check_delegation', 'check_machine_spns', 'check_msdcs_dns',
      'check_hybrid_entra', 'check_tier0_spns', 'check_ldaps_tls', 'attack_paths',
      'emit_agent_guidance', 'strict_mode',
    ]
    boolFields.forEach((k) => { body[k] = params[k] ? 'true' : 'false' })
    const strFields = ['ad_ports', 'dc_hosts', 'ldap_base_dn', 'resolver']
    strFields.forEach((k) => { if (String(params[k] || '').trim()) body[k] = String(params[k]).trim() })
    if (params.extra_http_paths.trim()) body.extra_http_paths = params.extra_http_paths
    if (params.probe_usernames.trim()) body.probe_usernames = params.probe_usernames
    body.max_ldap_entries = Number(params.max_ldap_entries) || 32
    return body
  }, [clientId, target, params])

  const hubScanParams = useMemo(() => {
    const { engine, target, client_id, ...rest } = buildBody()
    return rest
  }, [buildBody])
  useSyncHubScanParams(ENGINE_ID, hubScanParams)

  const handleRun = useCallback(async () => {
    if (!clientId) { showToastMsg('error', L.selectClientFirst); return }
    if (!target.trim()) { showToastMsg('error', L.target); return }
    setStatus('running')
    setFindings([])
    try {
      const { ok, data: d, status } = await postScan(buildBody())
      if (!ok) { setStatus('error'); showToastMsg('error', d.detail || L.scanFailed); return }
      const jobId = d.job_id ?? ''
      showToastMsg('info', `${L.queued} · ${jobId}`)
      if (jobId) setPendingJobId(jobId)
      else setStatus('error')
    } catch (e) {
      setStatus('error')
      showToastMsg('error', e?.message ?? L.scanFailed)
    }
  }, [clientId, target, buildBody, showToastMsg, L])

  const handleExport = useCallback(() => {
    const payload = { engine: ENGINE_ID, exported_at: new Date().toISOString(), target, params, findings }
    downloadBytes(new TextEncoder().encode(JSON.stringify(payload, null, 2)), `kerberos-posture-${Date.now()}.json`, 'application/json')
  }, [target, params, findings])

  const { posture, paths, regular, categories, toxic, roadmap, agentGaps, categoryScores } = useMemo(() => {
    const postureF = findings.find((f) => f.category === 'posture_summary') || null
    const toxicF = findings.find((f) => f.category === 'toxic_combination') || null
    const roadmapF = findings.find((f) => f.category === 'remediation_roadmap') || null
    const pathsF = findings.filter((f) => f.category === 'attack_path')
    const agentF = findings.filter((f) => (f.title || '').includes('Agent-required'))
    const regularF = findings
      .filter((f) => !['posture_summary', 'attack_path', 'toxic_combination', 'remediation_roadmap'].includes(f.category)
        && !(f.title || '').includes('Agent-required'))
      .sort((a, b) => sevWeight(b.severity) - sevWeight(a.severity))
    const cats = [...new Set(regularF.map((f) => f.category).filter(Boolean))]
    const scores = postureF?.evidence?.category_scores || null
    return { posture: postureF, paths: pathsF, regular: regularF, categories: cats, toxic: toxicF, roadmap: roadmapF, agentGaps: agentF, categoryScores: scores }
  }, [findings])

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
  } = useWeissmanEnginePage(ENGINE_ID, regular)

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
      setFindings(await resolveJobFindings(job, ENGINE_ID, clientId))
      setLastUpdated(new Date().toISOString())
      if (pendingJobId) setLastJobId(pendingJobId)
      setPendingJobId(null)
    },
  })

  const statusColor = { idle: '#374151', running: ACCENT, completed: '#4ade80', error: '#ef4444' }[status]

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
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-[var(--bg-1)] border-amber-500/30 text-amber-200'}`}>
          {toast.msg}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3 mb-6">
        <label className="flex items-center gap-2 text-xs font-mono text-[var(--text-tertiary)]">
          {L.client}
          <select value={clientId ?? ''} onChange={(e) => setClientId(e.target.value || null)}
            className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[var(--text-secondary)] focus:outline-none focus:border-amber-500/40">
            <option value="">{L.selectClient}</option>
            {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </label>
        <Link to="/identity-security" className="text-[11px] font-mono text-violet-300/80 hover:text-violet-200 border border-violet-500/25 rounded-lg px-3 py-1.5">
          {L.relatedIdentity} →
        </Link>
      </div>

      <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-6 mb-6">
        <div className="flex items-start justify-between gap-4 mb-4">
          <div className="flex items-center gap-3">
            <span className="text-3xl">🏰</span>
            <div>
              <h2 className="text-lg font-bold text-white">{ENGINE_ID}</h2>
              <span className="text-[10px] font-mono text-[var(--text-disabled)] uppercase tracking-widest">MITRE T1558 · CIS 5 · NIST AC-2/IA-2</span>
            </div>
          </div>
          <div className="flex flex-col items-end gap-2 shrink-0">
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: statusColor, boxShadow: status === 'running' ? `0 0 6px ${ACCENT}` : 'none' }} />
              <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{status}</span>
              {lastRun && <span className="text-[10px] font-mono text-[var(--text-disabled)]">· {lastRun}</span>}
            </div>
            <div className="flex gap-2">
              {findings.length > 0 && (
                <button type="button" onClick={handleExport} className="px-3 py-2 rounded-xl font-mono text-xs border border-[var(--border-strong)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)]">
                  {L.export}
                </button>
              )}
              <button type="button" onClick={handleRun} disabled={status === 'running' || !clientId}
                className="px-5 py-2 rounded-xl font-mono text-sm border transition-all disabled:opacity-40"
                style={{ borderColor: `${ACCENT}50`, color: '#fcd34d', backgroundColor: `${ACCENT}18` }}>
                {status === 'running' ? L.scanning : L.run}
              </button>
            </div>
          </div>
        </div>

        <label className="block mb-3">
          <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.target}</span>
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder={L.targetPh}
            className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] font-mono focus:outline-none focus:border-amber-500/40" />
        </label>

        <label className="block mb-4">
          <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.domain}</span>
          <input value={params.domain} onChange={(e) => set('domain', e.target.value)} placeholder={L.domainPh}
            className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] font-mono focus:outline-none focus:border-amber-500/40" />
        </label>

        <div className="mb-4">
          <span className="text-[11px] font-mono text-[var(--text-muted)] block mb-2">{L.presets}</span>
          <div className="flex flex-wrap gap-1.5">
            {AD_PRESETS.map((p) => (
              <button key={p.id} type="button" title={p.hint}
                onClick={() => { set('domain', p.domain); if (!target.trim()) setTarget(p.hint) }}
                className="text-[10px] font-mono px-2.5 py-1 rounded-lg border border-[var(--border-default)] text-[var(--text-tertiary)] hover:border-amber-500/40 hover:text-amber-200 transition-colors">
                {p.label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-4 mb-4">
          <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.intensity}</span>
          <Segmented value={params.intensity} onChange={(v) => set('intensity', v)}
            options={[{ value: 'light', label: L.light }, { value: 'normal', label: L.normal }, { value: 'aggressive', label: L.aggressive }]} />
        </div>

        <div className="mb-4">
          <span className="text-[11px] font-mono text-[var(--text-muted)] block mb-2">{L.layers}</span>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            <Toggle on={params.check_ports} onClick={() => set('check_ports', !params.check_ports)} label={L.checkPorts} />
            <Toggle on={params.check_srv} onClick={() => set('check_srv', !params.check_srv)} label={L.checkSrv} />
            <Toggle on={params.check_msdcs_dns} onClick={() => set('check_msdcs_dns', !params.check_msdcs_dns)} label={L.checkMsdcs} />
            <Toggle on={params.check_hybrid_entra} onClick={() => set('check_hybrid_entra', !params.check_hybrid_entra)} label={L.checkHybridEntra} />
            <Toggle on={params.check_ldap_anon} onClick={() => set('check_ldap_anon', !params.check_ldap_anon)} label={L.checkLdapAnon} />
            <Toggle on={params.check_ldap_enum} onClick={() => set('check_ldap_enum', !params.check_ldap_enum)} label={L.checkLdapEnum} />
            <Toggle on={params.check_ldap_starttls} onClick={() => set('check_ldap_starttls', !params.check_ldap_starttls)} label={L.checkStartTls} />
            <Toggle on={params.check_ldaps_tls} onClick={() => set('check_ldaps_tls', !params.check_ldaps_tls)} label={L.checkLdapsTls} />
            <Toggle on={params.check_kdc_probe} onClick={() => set('check_kdc_probe', !params.check_kdc_probe)} label={L.checkKdc} />
            <Toggle on={params.check_user_enum_krb} onClick={() => set('check_user_enum_krb', !params.check_user_enum_krb)} label={L.checkUserEnum} />
            <Toggle on={params.check_smb_signing} onClick={() => set('check_smb_signing', !params.check_smb_signing)} label={L.checkSmbSigning} />
            <Toggle on={params.check_spnego_http} onClick={() => set('check_spnego_http', !params.check_spnego_http)} label={L.checkSpnego} />
            <Toggle on={params.check_adcs_http} onClick={() => set('check_adcs_http', !params.check_adcs_http)} label={L.checkAdcs} />
            <Toggle on={params.check_delegation} onClick={() => set('check_delegation', !params.check_delegation)} label={L.checkDelegation} />
            <Toggle on={params.check_machine_spns} onClick={() => set('check_machine_spns', !params.check_machine_spns)} label={L.checkMachineSpns} />
            <Toggle on={params.check_tier0_spns} onClick={() => set('check_tier0_spns', !params.check_tier0_spns)} label={L.checkTier0} />
            <Toggle on={params.attack_paths} onClick={() => set('attack_paths', !params.attack_paths)} label={L.attackPaths} />
            <Toggle on={params.emit_agent_guidance} onClick={() => set('emit_agent_guidance', !params.emit_agent_guidance)} label={L.emitAgentGuidance} />
          </div>
        </div>

        <button type="button" onClick={() => setShowAdvanced((s) => !s)}
          className="text-[11px] font-mono text-[var(--text-muted)] hover:text-[var(--text-secondary)] mb-3">
          {showAdvanced ? '▼' : '▶'} {L.advanced}
        </button>

        {showAdvanced && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 border-t border-[var(--border-default)]">
            <label className="block">
              <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.adPorts}</span>
              <input value={params.ad_ports} onChange={(e) => set('ad_ports', e.target.value)}
                className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono" />
            </label>
            <label className="block">
              <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.resolver}</span>
              <select value={params.resolver} onChange={(e) => set('resolver', e.target.value)}
                className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono">
                {RESOLVER_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </label>
            <label className="block md:col-span-2">
              <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.probeUsers}</span>
              <textarea value={params.probe_usernames} onChange={(e) => set('probe_usernames', e.target.value)} rows={3}
                className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono" />
            </label>
            <label className="block md:col-span-2">
              <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.extraPaths}</span>
              <textarea value={params.extra_http_paths} onChange={(e) => set('extra_http_paths', e.target.value)} rows={2}
                className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono" />
            </label>
            <label className="block">
              <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.dcHosts}</span>
              <input value={params.dc_hosts} onChange={(e) => set('dc_hosts', e.target.value)}
                className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono" />
            </label>
            <label className="block">
              <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.ldapBase}</span>
              <input value={params.ldap_base_dn} onChange={(e) => set('ldap_base_dn', e.target.value)} placeholder="DC=corp,DC=local"
                className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono" />
            </label>
            <label className="block">
              <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.maxLdap}</span>
              <input type="number" min={4} max={128} value={params.max_ldap_entries} onChange={(e) => set('max_ldap_entries', e.target.value)}
                className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono" />
            </label>
            <label className="block">
              <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.timeout}</span>
              <input type="number" min={1000} max={20000} value={params.timeout_ms} onChange={(e) => set('timeout_ms', e.target.value)}
                className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono" />
            </label>
            <label className="block">
              <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.concurrency}</span>
              <input type="number" min={1} max={64} value={params.concurrency} onChange={(e) => set('concurrency', e.target.value)}
                className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-xs text-[var(--text-secondary)] font-mono" />
            </label>
            <div className="flex items-end">
              <Toggle on={params.strict_mode} onClick={() => set('strict_mode', !params.strict_mode)} label={L.strictMode} />
            </div>
            <div className="flex items-end">
              <button type="button" onClick={() => setParams(defaultParams())} className="text-xs font-mono text-[var(--text-muted)] hover:text-[var(--text-secondary)] border border-[var(--border-default)] rounded-lg px-3 py-2">
                {L.reset}
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="flex flex-wrap gap-2 mb-6 text-[11px] font-mono">
        <span className="text-[var(--text-disabled)]">{L.related}:</span>
        <Link to="/identity-security" className="text-violet-300/80 hover:text-violet-200">{L.relatedIdentity}</Link>
        <span className="text-[var(--text-disabled)]">·</span>
        <Link to={`/engines/${ENGINE_ID}`} className="text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]">{L.relatedEngine}</Link>
        <span className="text-[var(--text-disabled)]">·</span>
        <Link to="/password-spray" className="text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]">{L.relatedSpray}</Link>
        <span className="text-[var(--text-disabled)]">·</span>
        <Link to="/saml-security" className="text-amber-300/80 hover:text-amber-200">{L.relatedSaml}</Link>
      </div>

      {findings.length === 0 && status !== 'running' && (
        <p className="text-sm font-mono text-[var(--text-muted)] text-center py-12">{L.runToPopulate}</p>
      )}

      {toxic && <ToxicBanner finding={toxic} L={L} />}

      {posture && <PostureCard finding={posture} L={L} pathCount={paths.length} />}

      {categoryScores && <CategoryScoresPanel scores={categoryScores} L={L} />}

      {roadmap && <RoadmapCard finding={roadmap} L={L} />}

      {categories.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mb-4">
          <span className="text-[10px] font-mono text-[var(--text-muted)]">{L.categories}:</span>
          {categories.map((c) => <Chip key={c} color={ACCENT}>{c}</Chip>)}
        </div>
      )}

      {agentGaps.length > 0 && (
        <div className="rounded-xl border border-cyan-500/20 bg-cyan-950/10 p-4 mb-6">
          <div className="text-[10px] font-mono uppercase tracking-widest text-cyan-300/60 mb-2">{L.agentGapTitle}</div>
          <div className="space-y-1">
            {agentGaps.map((f, i) => (
              <p key={i} className="text-[11px] font-mono text-[var(--text-tertiary)]">{f.title}</p>
            ))}
          </div>
        </div>
      )}

      {paths.length > 0 && (
        <div className="space-y-3 mb-6">
          <h3 className="text-sm font-bold text-rose-300 flex items-center gap-2">{L.pathsTitle} <Chip color="#fb7185">{paths.length}</Chip></h3>
          {paths.map((p, i) => <AttackPathCard key={i} finding={p} />)}
        </div>
      )}

      <WeissmanFindingsPanel
        findings={regular}
        filteredFindings={filteredFindings}
        counts={counts}
        total={regular.length}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        severityFilter={severityFilter}
        onSeverityChange={setSeverityFilter}
        pending={status === 'running' && regular.length === 0}
        loading={historyLoading && regular.length === 0}
        lastUpdated={lastUpdated}
        jobId={pendingJobId || lastJobId}
        accent={ACCENT}
        title={L.findingsTitle}
        showEmptyReady={status !== 'running' && regular.length === 0 && findings.length === 0}
        emptyReadyTitle={L.runToPopulate}
        emptyReadyBody={L.runToPopulate}
        emptyTitle={L.noFindings}
        emptyBody={L.noFindings}
        renderFinding={(f, i) => <FindingCard key={i} finding={f} L={L} />}
      />
    </PageShell>
  )
}
