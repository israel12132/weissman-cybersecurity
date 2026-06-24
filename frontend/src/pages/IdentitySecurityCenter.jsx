// OAuth 2.0 / OIDC / SSO Identity Security Command Center (engine: oauth_oidc).
// Self-contained bilingual UI exposing every operator knob the Rust engine reads from job_params,
// plus posture scoring, provider fingerprinting, attack-path synthesis and evidence-rich findings.
import React, { useCallback, useEffect, useMemo, useState } from 'react'
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

const ENGINE_ID = 'oauth_oidc'
const ACCENT = '#22d3ee'
const ACCENT2 = '#a78bfa'

const LABELS = {
  en: {
    title: 'Identity & SSO Security Command Center',
    subtitle: 'Supreme-tier agentless OAuth 2.0 / OpenID Connect / SSO posture — discovery, JWKS crypto, live authorization probing, PAR/DPoP/device-code/ROPC/CORS/subdomain takeover, toxic combinations, 8-domain scores, remediation roadmap, security graph & agent guidance',
    badge: 'Identity Posture',
    client: 'Client',
    selectClient: 'Select client…',
    selectClientFirst: 'Select a client first',
    target: 'Identity provider target (host / issuer URL)',
    targetPh: 'https://idp.example.com  or  https://login.microsoftonline.com/{tenant}/v2.0',
    run: 'Run identity assessment',
    scanning: 'Assessing…',
    queued: 'Assessment queued',
    scanFailed: 'Scan failed',
    intensity: 'Probe intensity',
    light: 'Light', normal: 'Normal', aggressive: 'Aggressive',
    presets: 'Provider presets (fill issuer template)',
    issuer: 'Issuer URL',
    discoveryUrl: 'Discovery document URL (override)',
    clientId: 'OAuth client_id (improves live probe fidelity)',
    probeRedirect: 'Probe redirect_uri (open-redirect test)',
    probeScope: 'Probe scope',
    layers: 'Assessment layers',
    checkDiscovery: 'Discovery + metadata posture (RFC 8414)',
    checkJwks: 'JWKS cryptographic analysis',
    probeAuth: 'Live authorization-endpoint behavior',
    probeImplicit: 'Implicit flow live probe (response_type=token)',
    probeToken: 'Token endpoint + PAR live probing',
    attackPaths: 'Synthesize account-takeover attack paths',
    advanced: 'Advanced parameters',
    extraDiscovery: 'Extra discovery paths (one per line)',
    extraSubdomains: 'Subdomains for takeover probe (comma-sep)',
    timeout: 'HTTP timeout (ms)',
    concurrency: 'Probe concurrency',
    reset: 'Reset defaults',
    export: 'Export JSON',
    posture: 'Identity posture score',
    grade: 'Grade',
    provider: 'Provider fingerprint',
    issuerLabel: 'Issuer',
    counts: 'Findings by severity',
    categories: 'Control domains assessed',
    pathsTitle: 'Account takeover attack paths',
    findingsTitle: 'Identity findings',
    evidence: 'Evidence trail',
    remediation: 'Remediation',
    confidence: 'Confidence',
    standards: 'Standards',
    noFindings: 'No OAuth/OIDC weaknesses observed — strong identity posture.',
    runToPopulate: 'Configure the IdP target and run the assessment.',
    filterAll: 'all',
    related: 'Related identity engines',
    relatedJwt: 'JWT Attack Lab',
    relatedKerberos: 'AD & Kerberos Command Center',
    relatedSaml: 'SAML Attack Engine',
    relatedEngine: 'Engine detail (API)',
    uebaLink: 'UEBA identity contexts',
    graphTitle: 'Identity risk graph',
    graphHint: 'Provider → control gaps → prioritized takeover paths',
    toxicTitle: 'Toxic combination detected',
    roadmapTitle: 'Prioritized remediation roadmap',
    categoryScores: '8-domain posture breakdown',
    agentGapTitle: 'Agent-required deep coverage',
    emitAgentGuidance: 'Show honest agent-required capability gaps',
    probeExtensions: 'OIDC extension endpoints (device-code, ROPC)',
    probeCors: 'CORS posture on metadata/JWKS',
    probeFederation: 'SAML federation metadata bridge',
    probeSubdomains: 'Identity subdomain takeover probe',
    checkControlMatrix: 'RFC 9700 control matrix',
    checkRemediation: 'Remediation playbook',
  },
  he: {
    title: 'מרכז פיקוד אבטחת זהות ו-SSO',
    subtitle: 'תנוחת OAuth 2.0 / OpenID Connect / SSO ללא סוכן — discovery, JWKS, בדיקות authorization חיות, סינתזת נתיבי תקיפה',
    badge: 'תנוחת זהות',
    client: 'לקוח',
    selectClient: 'בחר לקוח…',
    selectClientFirst: 'בחר לקוח תחילה',
    target: 'יעד ספק זהות (host / issuer URL)',
    targetPh: 'https://idp.example.com  או  https://login.microsoftonline.com/{tenant}/v2.0',
    run: 'הרץ הערכת זהות',
    scanning: 'מעריך…',
    queued: 'ההערכה בתור',
    scanFailed: 'הסריקה נכשלה',
    intensity: 'עוצמת בדיקה',
    light: 'קלה', normal: 'רגילה', aggressive: 'אגרסיבית',
    presets: 'תבניות ספק (מילוי issuer)',
    issuer: 'Issuer URL',
    discoveryUrl: 'Discovery URL (דריסה)',
    clientId: 'OAuth client_id (משפר דיוק הבדיקה)',
    probeRedirect: 'Probe redirect_uri (בדיקת open-redirect)',
    probeScope: 'Probe scope',
    layers: 'שכבות הערכה',
    checkDiscovery: 'Discovery + metadata (RFC 8414)',
    checkJwks: 'ניתוח קריפטוגרפי JWKS',
    probeAuth: 'התנהגות authorization endpoint חיה',
    probeImplicit: 'בדיקת implicit flow (response_type=token)',
    probeToken: 'בדיקת token endpoint + PAR חיה',
    attackPaths: 'סינתזת נתיבי השתלטות על חשבון',
    advanced: 'פרמטרים מתקדמים',
    extraDiscovery: 'נתיבי discovery נוספים (שורה לכל נתיב)',
    extraSubdomains: 'Subdomains לבדיקת takeover (מופרד בפסיקים)',
    timeout: 'Timeout HTTP (ms)',
    concurrency: 'מקביליות',
    reset: 'אפס ברירות מחדל',
    export: 'ייצוא JSON',
    posture: 'ציון תנוחת זהות',
    grade: 'דירוג',
    provider: 'טביעת ספק',
    issuerLabel: 'Issuer',
    counts: 'ממצאים לפי חומרה',
    categories: 'תחומי בקרה שנבדקו',
    pathsTitle: 'נתיבי השתלטות על חשבון',
    findingsTitle: 'ממצאי זהות',
    evidence: 'שרשרת ראיות',
    remediation: 'תיקון',
    confidence: 'ביטחון',
    standards: 'תקנים',
    noFindings: 'לא נצפו חולשות OAuth/OIDC — תנוחת זהות חזקה.',
    runToPopulate: 'הגדר יעד IdP והרץ הערכה.',
    filterAll: 'הכל',
    related: 'מנועי זהות קשורים',
    relatedJwt: 'מעבדת JWT',
    relatedKerberos: 'מרכז AD ו-Kerberos',
    relatedSaml: 'מנוע SAML',
    relatedEngine: 'פרטי מנוע (API)',
    uebaLink: 'הקשרי זהות UEBA',
    graphTitle: 'גרף סיכון זהות',
    graphHint: 'ספק → פערים → נתיבי takeover',
    toxicTitle: 'שילוב רעיל זוהה',
    roadmapTitle: 'מפת דרכים לתיקון מדורג',
    categoryScores: 'פירוט 8 תחומי תנוחה',
    agentGapTitle: 'כיסוי עמוק הדורש סוכן',
    emitAgentGuidance: 'הצג פערים שדורשים סוכן',
    probeExtensions: 'נקודות קצה OIDC (device-code, ROPC)',
    probeCors: 'תנוחת CORS על metadata/JWKS',
    probeFederation: 'גשר SAML federation metadata',
    probeSubdomains: 'בדיקת subdomain takeover לזהות',
    checkControlMatrix: 'מטריצת בקרה RFC 9700',
    checkRemediation: 'מדריך תיקון',
  },
}

const PROVIDER_PRESETS = [
  { id: 'okta', label: 'Okta', hint: 'https://YOUR-DOMAIN.okta.com/oauth2/default' },
  { id: 'entra', label: 'Microsoft Entra', hint: 'https://login.microsoftonline.com/TENANT-ID/v2.0' },
  { id: 'auth0', label: 'Auth0', hint: 'https://YOUR-TENANT.auth0.com' },
  { id: 'keycloak', label: 'Keycloak', hint: 'https://KEYCLOAK-HOST/realms/REALM' },
  { id: 'google', label: 'Google', hint: 'https://accounts.google.com' },
  { id: 'cognito', label: 'AWS Cognito', hint: 'https://cognito-idp.REGION.amazonaws.com/POOL-ID' },
  { id: 'ping', label: 'PingOne', hint: 'https://auth.pingone.com/ENV-ID/as' },
  { id: 'onelogin', label: 'OneLogin', hint: 'https://YOUR-SUBDOMAIN.onelogin.com/oidc/2' },
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
    issuer: '',
    discovery_url: '',
    client_id: '',
    probe_redirect_uri: 'https://oauth-validate.weissman.invalid/callback',
    probe_scope: 'openid',
    check_discovery: true,
    check_jwks: true,
    probe_authorization: true,
    probe_implicit: true,
    probe_token_endpoint: true,
    attack_paths: true,
    probe_extensions: true,
    probe_cors: true,
    probe_federation: true,
    probe_subdomains: true,
    check_control_matrix: true,
    check_remediation_playbook: true,
    emit_agent_guidance: true,
    extra_discovery_paths: '',
    takeover_subdomains: '',
    timeout_ms: 10000,
    concurrency: 16,
  }
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

function CategoryScoresPanel({ scores, L }) {
  if (!scores || typeof scores !== 'object') return null
  const axes = [
    ['flow_hygiene', 'Flow hygiene'],
    ['token_crypto', 'Token crypto'],
    ['redirect_validation', 'Redirect validation'],
    ['client_authentication', 'Client auth'],
    ['modern_hardening', 'Modern hardening'],
    ['endpoint_exposure', 'Endpoint exposure'],
    ['federation_bridge', 'Federation bridge'],
    ['token_endpoint_hygiene', 'Token endpoint'],
  ]
  return (
    <div className="rounded-xl border border-white/10 bg-black/30 p-4 mb-5">
      <p className="text-[10px] font-mono text-white/40 uppercase mb-3">{L.categoryScores}</p>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {axes.map(([k, label]) => {
          const v = Number(scores[k] ?? 0)
          const c = v >= 80 ? '#22c55e' : v >= 50 ? '#eab308' : '#ef4444'
          return (
            <div key={k}>
              <div className="flex justify-between text-[10px] font-mono text-white/45 mb-1"><span>{label}</span><span style={{ color: c }}>{v}</span></div>
              <div className="h-1.5 rounded-full bg-white/10"><div className="h-full rounded-full" style={{ width: `${v}%`, backgroundColor: c }} /></div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function PostureGauge({ score = 0 }) {
  const pct = Math.max(0, Math.min(100, Number(score) || 0))
  const c = pct >= 85 ? '#22c55e' : pct >= 60 ? '#eab308' : pct >= 40 ? '#f97316' : '#ef4444'
  return (
    <div className="flex items-center gap-3">
      <div className="text-4xl font-bold font-mono tabular-nums" style={{ color: c }}>{pct}</div>
      <div className="flex-1">
        <div className="h-2.5 rounded-full bg-white/10 overflow-hidden">
          <div className="h-full rounded-full transition-all duration-700" style={{ width: `${pct}%`, backgroundColor: c }} />
        </div>
        <p className="text-[10px] font-mono text-white/35 mt-1">100 = no observed weakness</p>
      </div>
    </div>
  )
}

function IdentityGraph({ provider, categories, pathCount }) {
  const nodes = [
    { id: 'idp', label: provider || 'Identity Provider', x: 80, y: 90, c: ACCENT },
    { id: 'gaps', label: `${categories.length} control domain(s)`, x: 300, y: 90, c: '#f97316' },
    { id: 'paths', label: `${pathCount} takeover path(s)`, x: 520, y: 90, c: '#ef4444' },
  ]
  return (
    <svg viewBox="0 0 620 180" className="w-full" style={{ minWidth: 320, height: 140 }}>
      <line x1="120" y1="90" x2="260" y2="90" stroke="#ffffff25" strokeWidth="2" strokeDasharray="5 4" />
      <line x1="340" y1="90" x2="480" y2="90" stroke="#ffffff25" strokeWidth="2" strokeDasharray="5 4" />
      {nodes.map((n) => (
        <g key={n.id}>
          <circle cx={n.x} cy={n.y} r="10" fill={n.c} fillOpacity="0.9" />
          <text x={n.x} y={n.y + 28} fill="#e5e7eb" fontSize="11" fontFamily="monospace" textAnchor="middle">
            {String(n.label).slice(0, 28)}
          </text>
        </g>
      ))}
    </svg>
  )
}

function PostureCard({ finding, L, pathCount = 0, categories = [] }) {
  const ev = finding?.evidence || {}
  const counts = ev.counts || {}
  const score = ev.score ?? finding?.confidence
  const grade = ev.grade ?? '—'
  return (
    <div className="rounded-2xl border border-cyan-500/20 bg-gradient-to-br from-cyan-950/25 via-violet-950/15 to-black/40 p-5 mb-5">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-white/40 mb-2">{L.posture}</div>
          <PostureGauge score={score} />
          <div className="mt-3 flex items-center gap-2">
            <span className="text-[10px] font-mono text-white/40">{L.grade}:</span>
            <span className="text-2xl font-bold font-mono text-white">{grade}</span>
          </div>
        </div>
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-white/40 mb-2">{L.counts}</div>
          <div className="flex flex-wrap gap-1.5">
            {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
              <span key={s} className="inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-mono"
                style={{ color: sevColor(s), backgroundColor: `${sevColor(s)}14` }}>
                <b>{counts[s] ?? 0}</b> {s}
              </span>
            ))}
          </div>
          {(ev.provider || ev.issuer) && (
            <div className="mt-4 space-y-1 text-xs font-mono">
              {ev.provider && <div><span className="text-white/40">{L.provider}: </span><span className="text-cyan-200">{ev.provider}</span></div>}
              {ev.issuer && <div className="truncate"><span className="text-white/40">{L.issuerLabel}: </span><span className="text-white/70">{ev.issuer}</span></div>}
            </div>
          )}
        </div>
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-white/40 mb-1">{L.graphTitle}</div>
          <p className="text-[10px] text-white/35 mb-2">{L.graphHint}</p>
          <IdentityGraph provider={ev.provider} categories={categories} pathCount={pathCount} />
        </div>
      </div>
      {finding.description && <p className="text-xs text-white/55 mt-4 leading-relaxed border-t border-white/10 pt-3">{finding.description}</p>}
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
      {finding.description && <p className="text-xs text-white/55 mt-2 mb-3 leading-relaxed">{finding.description}</p>}
      <ol className="space-y-2">
        {steps.map((step, i) => (
          <li key={i} className="flex gap-2.5 text-xs">
            <span className="shrink-0 w-6 h-6 rounded-full bg-rose-500/20 text-rose-200 flex items-center justify-center font-mono text-[10px] font-bold">{i + 1}</span>
            <span className="text-white/80 leading-relaxed pt-0.5">{step}</span>
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
  const evKeys = Object.keys(ev).filter((k) => !['checks', 'score', 'grade', 'counts', 'provider', 'issuer'].includes(k))
  const conf = typeof finding.confidence === 'number' ? Math.round(finding.confidence * 100) : null
  const standards = Array.isArray(finding.standards) ? finding.standards : []

  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.03] overflow-hidden">
      <button type="button" onClick={() => setOpen((o) => !o)} className="w-full flex items-start gap-3 p-3 text-left hover:bg-white/[0.04]">
        <span className="mt-0.5 w-1.5 self-stretch rounded-full" style={{ backgroundColor: sevColor(finding.severity) }} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityPill sev={finding.severity} />
            {finding.category && <Chip color={ACCENT2}>{finding.category}</Chip>}
            {finding.mitre_attack && <Chip color="#a78bfa">{finding.mitre_attack}</Chip>}
            {conf !== null && <Chip color="#22d3ee">{L.confidence} {conf}%</Chip>}
          </div>
          <div className="text-sm text-white/85 mt-1 font-medium">{finding.title}</div>
        </div>
        <span className="text-white/30 text-xs mt-1">{open ? '−' : '+'}</span>
      </button>
      <AnimatePresence>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
            <div className="px-4 pb-4 pt-1 space-y-3 text-xs">
              {finding.description && <p className="text-white/60 leading-relaxed">{finding.description}</p>}
              {standards.length > 0 && (
                <div>
                  <div className="text-[10px] uppercase tracking-widest text-white/30 mb-1">{L.standards}</div>
                  <div className="flex flex-wrap gap-1">{standards.map((s) => <Chip key={s} color="#38bdf8">{s}</Chip>)}</div>
                </div>
              )}
              {evKeys.length > 0 && (
                <div className="rounded-lg bg-black/40 border border-white/5 p-2">
                  <div className="text-[10px] uppercase tracking-widest text-white/30 mb-1">{L.evidence}</div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-0.5 font-mono">
                    {evKeys.map((k) => (
                      <div key={k} className="flex gap-2 min-w-0">
                        <span className="text-white/40 shrink-0">{k}:</span>
                        <span className="text-white/75 truncate">{renderEvidenceValue(ev[k])}</span>
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
                      <span className="text-white/70">{c.name}</span>
                      <span className="text-white/35 truncate">{renderEvidenceValue(c.detail)}</span>
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
      style={{ borderColor: on ? `${ACCENT}50` : '#ffffff14', backgroundColor: on ? `${ACCENT}14` : 'transparent', color: on ? '#a5f3fc' : '#ffffff55' }}>
      <span className="w-7 h-4 rounded-full relative transition-all shrink-0" style={{ backgroundColor: on ? ACCENT : '#ffffff20' }}>
        <span className="absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all" style={{ left: on ? '14px' : '2px' }} />
      </span>
      <span>{label}</span>
    </button>
  )
}

function Segmented({ value, onChange, options }) {
  return (
    <div className="inline-flex rounded-lg border border-white/10 p-0.5 bg-black/30">
      {options.map((o) => (
        <button key={o.value} type="button" onClick={() => onChange(o.value)}
          className="px-3 py-1 rounded-md text-xs font-mono transition-all"
          style={value === o.value ? { backgroundColor: `${ACCENT}25`, color: '#a5f3fc' } : { color: '#ffffff50' }}>
          {o.label}
        </button>
      ))}
    </div>
  )
}

function firstClientTarget(client) {
  if (!client) return ''
  let domains = client.domains
  if (typeof domains === 'string') {
    try { domains = JSON.parse(domains) } catch { domains = [] }
  }
  const first = Array.isArray(domains) ? domains.find((d) => typeof d === 'string' && d.trim()) : ''
  if (!first) return ''
  return first.startsWith('http') ? first : `https://${first}`
}

export default function IdentitySecurityCenter() {
  const { i18n } = useTranslation()
  const L = LABELS[i18n.language?.startsWith('he') ? 'he' : 'en']

  const [clients, setClients] = useState([])
  const [clientId, setClientId] = useState(null)
  const [params, setParams] = useState(defaultParams)
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
    if (t) setTarget(t)
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
    body.timeout_ms = Number(params.timeout_ms) || 10000
    body.concurrency = Number(params.concurrency) || 16
    const strFields = ['issuer', 'discovery_url', 'client_id', 'probe_redirect_uri', 'probe_scope']
    strFields.forEach((k) => { if (String(params[k] || '').trim()) body[k] = String(params[k]).trim() })
    const boolFields = [
      'check_discovery', 'check_jwks', 'probe_authorization', 'probe_implicit', 'probe_token_endpoint',
      'attack_paths', 'probe_extensions', 'probe_cors', 'probe_federation', 'probe_subdomains',
      'check_control_matrix', 'check_remediation_playbook', 'emit_agent_guidance',
    ]
    boolFields.forEach((k) => { body[k] = params[k] ? 'true' : 'false' })
    if (params.extra_discovery_paths.trim()) body.extra_discovery_paths = params.extra_discovery_paths
    if (params.takeover_subdomains.trim()) body.takeover_subdomains = params.takeover_subdomains
    return body
  }, [clientId, target, params])

  const handleRun = useCallback(async () => {
    if (!clientId) { showToastMsg('error', L.selectClientFirst); return }
    if (!target.trim()) { showToastMsg('error', L.target); return }
    setStatus('running')
    setFindings([])
    try {
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(buildBody()),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) { setStatus('error'); showToastMsg('error', d.detail || L.scanFailed); return }
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
    downloadBytes(new TextEncoder().encode(JSON.stringify(payload, null, 2)), `identity-posture-${Date.now()}.json`, 'application/json')
  }, [target, params, findings])

  const { posture, paths, regular, categories, toxic, roadmap, agentGaps, categoryScores } = useMemo(() => {
    const postureF = findings.find((f) => f.category === 'posture_summary') || null
    const toxicF = findings.find((f) => f.category === 'toxic_combination') || null
    const roadmapF = findings.find((f) => f.category === 'remediation_roadmap') || null
    const pathsF = findings.filter((f) => f.category === 'attack_path')
    const agentF = findings.filter((f) => f.category === 'agent_guidance')
    const regularF = findings
      .filter((f) => !['posture_summary', 'attack_path', 'toxic_combination', 'remediation_roadmap', 'agent_guidance'].includes(f.category))
      .sort((a, b) => sevWeight(b.severity) - sevWeight(a.severity))
    const cats = [...new Set(regularF.map((f) => f.category).filter(Boolean))]
    const scores = postureF?.evidence?.category_scores || roadmapF?.evidence?.category_scores || null
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
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-black/80 border-cyan-500/30 text-cyan-200'}`}>
          {toast.msg}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3 mb-6">
        <label className="flex items-center gap-2 text-xs font-mono text-white/50">
          {L.client}
          <select value={clientId ?? ''} onChange={(e) => setClientId(e.target.value || null)}
            className="bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-white/80 focus:outline-none focus:border-cyan-500/40">
            <option value="">{L.selectClient}</option>
            {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </label>
        <Link to="/identity-context" className="text-[11px] font-mono text-violet-300/80 hover:text-violet-200 border border-violet-500/25 rounded-lg px-3 py-1.5">
          {L.uebaLink} →
        </Link>
      </div>

      {/* Config panel */}
      <div className="rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-6 mb-6">
        <div className="flex items-start justify-between gap-4 mb-4">
          <div className="flex items-center gap-3">
            <span className="text-3xl">🔐</span>
            <div>
              <h2 className="text-lg font-bold text-white">{ENGINE_ID}</h2>
              <span className="text-[10px] font-mono text-white/30 uppercase tracking-widest">RFC 9700 · OWASP · MITRE T1550 / T1606</span>
            </div>
          </div>
          <div className="flex flex-col items-end gap-2 shrink-0">
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: statusColor, boxShadow: status === 'running' ? `0 0 6px ${ACCENT}` : 'none' }} />
              <span className="text-[10px] font-mono text-white/40 uppercase">{status}</span>
            </div>
            <div className="flex gap-2">
              {findings.length > 0 && (
                <button type="button" onClick={handleExport} className="px-3 py-2 rounded-xl font-mono text-xs border border-white/15 text-white/60 hover:text-white/90">
                  {L.export}
                </button>
              )}
              <button type="button" onClick={handleRun} disabled={status === 'running' || !clientId}
                className="px-5 py-2 rounded-xl font-mono text-sm border transition-all disabled:opacity-40"
                style={{ borderColor: `${ACCENT}50`, color: '#a5f3fc', backgroundColor: `${ACCENT}18` }}>
                {status === 'running' ? L.scanning : L.run}
              </button>
            </div>
          </div>
        </div>

        <label className="block mb-4">
          <span className="text-[11px] font-mono text-white/40">{L.target}</span>
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder={L.targetPh}
            className="mt-1 w-full bg-black/50 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/85 font-mono focus:outline-none focus:border-cyan-500/40" />
        </label>

        <div className="mb-4">
          <span className="text-[11px] font-mono text-white/40 block mb-2">{L.presets}</span>
          <div className="flex flex-wrap gap-1.5">
            {PROVIDER_PRESETS.map((p) => (
              <button key={p.id} type="button" title={p.hint}
                onClick={() => { set('issuer', p.hint); if (!target.trim()) setTarget(p.hint) }}
                className="text-[10px] font-mono px-2.5 py-1 rounded-lg border border-white/10 text-white/55 hover:border-cyan-500/40 hover:text-cyan-200 transition-colors">
                {p.label}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
          <label className="block">
            <span className="text-[11px] font-mono text-white/40">{L.issuer}</span>
            <input value={params.issuer} onChange={(e) => set('issuer', e.target.value)} placeholder="https://…"
              className="mt-1 w-full bg-black/50 border border-white/10 rounded-lg px-3 py-1.5 text-sm text-white/85 font-mono focus:outline-none focus:border-cyan-500/40" />
          </label>
          <label className="block">
            <span className="text-[11px] font-mono text-white/40">{L.discoveryUrl}</span>
            <input value={params.discovery_url} onChange={(e) => set('discovery_url', e.target.value)} placeholder="/.well-known/openid-configuration"
              className="mt-1 w-full bg-black/50 border border-white/10 rounded-lg px-3 py-1.5 text-sm text-white/85 font-mono focus:outline-none focus:border-cyan-500/40" />
          </label>
          <label className="block">
            <span className="text-[11px] font-mono text-white/40">{L.clientId}</span>
            <input value={params.client_id} onChange={(e) => set('client_id', e.target.value)} autoComplete="off"
              className="mt-1 w-full bg-black/50 border border-white/10 rounded-lg px-3 py-1.5 text-sm text-white/85 font-mono focus:outline-none focus:border-cyan-500/40" />
          </label>
          <label className="block">
            <span className="text-[11px] font-mono text-white/40">{L.probeRedirect}</span>
            <input value={params.probe_redirect_uri} onChange={(e) => set('probe_redirect_uri', e.target.value)}
              className="mt-1 w-full bg-black/50 border border-white/10 rounded-lg px-3 py-1.5 text-sm text-white/85 font-mono focus:outline-none focus:border-cyan-500/40" />
          </label>
        </div>

        <div className="flex items-center justify-between gap-4 mb-4">
          <span className="text-[11px] font-mono text-white/40">{L.intensity}</span>
          <Segmented value={params.intensity} onChange={(v) => set('intensity', v)}
            options={[{ value: 'light', label: L.light }, { value: 'normal', label: L.normal }, { value: 'aggressive', label: L.aggressive }]} />
        </div>

        <span className="text-[11px] font-mono text-white/40 block mb-2">{L.layers}</span>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mb-2">
          <Toggle on={params.check_discovery} onClick={() => set('check_discovery', !params.check_discovery)} label={L.checkDiscovery} />
          <Toggle on={params.check_jwks} onClick={() => set('check_jwks', !params.check_jwks)} label={L.checkJwks} />
          <Toggle on={params.probe_authorization} onClick={() => set('probe_authorization', !params.probe_authorization)} label={L.probeAuth} />
          <Toggle on={params.probe_implicit} onClick={() => set('probe_implicit', !params.probe_implicit)} label={L.probeImplicit} />
          <Toggle on={params.probe_token_endpoint} onClick={() => set('probe_token_endpoint', !params.probe_token_endpoint)} label={L.probeToken} />
          <Toggle on={params.attack_paths} onClick={() => set('attack_paths', !params.attack_paths)} label={L.attackPaths} />
          <Toggle on={params.probe_extensions} onClick={() => set('probe_extensions', !params.probe_extensions)} label={L.probeExtensions} />
          <Toggle on={params.probe_cors} onClick={() => set('probe_cors', !params.probe_cors)} label={L.probeCors} />
          <Toggle on={params.probe_federation} onClick={() => set('probe_federation', !params.probe_federation)} label={L.probeFederation} />
          <Toggle on={params.probe_subdomains} onClick={() => set('probe_subdomains', !params.probe_subdomains)} label={L.probeSubdomains} />
          <Toggle on={params.check_control_matrix} onClick={() => set('check_control_matrix', !params.check_control_matrix)} label={L.checkControlMatrix} />
          <Toggle on={params.check_remediation_playbook} onClick={() => set('check_remediation_playbook', !params.check_remediation_playbook)} label={L.checkRemediation} />
          <Toggle on={params.emit_agent_guidance} onClick={() => set('emit_agent_guidance', !params.emit_agent_guidance)} label={L.emitAgentGuidance} />
        </div>

        <button type="button" onClick={() => setShowAdvanced((s) => !s)} className="text-xs font-mono text-cyan-300/70 hover:text-cyan-200 mt-2">
          {showAdvanced ? '▾' : '▸'} {L.advanced}
        </button>
        <AnimatePresence>
          {showAdvanced && (
            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
              <div className="pt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                <label className="block md:col-span-2">
                  <span className="text-[11px] font-mono text-white/40">{L.extraDiscovery}</span>
                  <textarea value={params.extra_discovery_paths} onChange={(e) => set('extra_discovery_paths', e.target.value)} rows={2}
                    className="mt-1 w-full bg-black/50 border border-white/10 rounded-lg px-3 py-1.5 text-sm text-white/85 font-mono focus:outline-none focus:border-cyan-500/40" />
                </label>
                <label className="block">
                  <span className="text-[11px] font-mono text-white/40">{L.probeScope}</span>
                  <input value={params.probe_scope} onChange={(e) => set('probe_scope', e.target.value)}
                    className="mt-1 w-full bg-black/50 border border-white/10 rounded-lg px-3 py-1.5 text-sm font-mono text-white/85 focus:outline-none focus:border-cyan-500/40" />
                </label>
                <label className="block">
                  <span className="text-[11px] font-mono text-white/40">{L.extraSubdomains}</span>
                  <input value={params.takeover_subdomains} onChange={(e) => set('takeover_subdomains', e.target.value)} placeholder="auth, login, sso"
                    className="mt-1 w-full bg-black/50 border border-white/10 rounded-lg px-3 py-1.5 text-sm font-mono text-white/85 focus:outline-none focus:border-cyan-500/40" />
                </label>
                <label className="block">
                  <span className="text-[11px] font-mono text-white/40">{L.timeout}</span>
                  <input type="number" value={params.timeout_ms} onChange={(e) => set('timeout_ms', e.target.value)}
                    className="mt-1 w-full bg-black/50 border border-white/10 rounded-lg px-3 py-1.5 text-sm font-mono text-white/85 focus:outline-none focus:border-cyan-500/40" />
                </label>
                <label className="block">
                  <span className="text-[11px] font-mono text-white/40">{L.concurrency}</span>
                  <input type="number" value={params.concurrency} onChange={(e) => set('concurrency', e.target.value)}
                    className="mt-1 w-full bg-black/50 border border-white/10 rounded-lg px-3 py-1.5 text-sm font-mono text-white/85 focus:outline-none focus:border-cyan-500/40" />
                </label>
                <button type="button" onClick={() => setParams(defaultParams())} className="text-[11px] font-mono text-white/40 hover:text-white/70 underline md:col-span-2">{L.reset}</button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
        {lastRun && <p className="text-[10px] font-mono text-white/25 mt-3">{lastRun}</p>}
      </div>

      {/* Related engines */}
      <div className="flex flex-wrap gap-2 mb-6">
        <span className="text-[10px] font-mono text-white/35 self-center">{L.related}:</span>
        <Link to="/jwt-lab" className="text-[11px] font-mono px-3 py-1 rounded-lg border border-amber-500/30 text-amber-200/90 hover:bg-amber-500/10">{L.relatedJwt}</Link>
        <Link to="/kerberos-security" className="text-[11px] font-mono px-3 py-1 rounded-lg border border-amber-500/30 text-amber-200/90 hover:bg-amber-500/10">{L.relatedKerberos}</Link>
        <Link to="/saml-security" className="text-[11px] font-mono px-3 py-1 rounded-lg border border-violet-500/30 text-violet-200/90 hover:bg-violet-500/10">{L.relatedSaml}</Link>
        <Link to={`/engines/${ENGINE_ID}`} className="text-[11px] font-mono px-3 py-1 rounded-lg border border-white/15 text-white/60 hover:bg-white/5">{L.relatedEngine}</Link>
      </div>

      {/* Results */}
      {findings.length === 0 && status !== 'running' && (
        <div className="rounded-2xl bg-white/5 border border-white/5 p-8 text-center mb-6">
          <p className="text-[11px] font-mono text-white/25">{status === 'completed' ? L.noFindings : L.runToPopulate}</p>
        </div>
      )}

      {posture && (
        <>
          <PostureCard finding={posture} L={L} pathCount={paths.length} categories={categories} />
          {categoryScores && <CategoryScoresPanel scores={categoryScores} L={L} />}
          {toxic && (
            <div className="rounded-2xl border border-red-500/50 bg-red-950/25 p-5 mb-5">
              <p className="text-[10px] font-mono text-red-300/80 uppercase mb-2">{L.toxicTitle}</p>
              <p className="text-sm font-mono text-red-100 font-semibold">{toxic.title}</p>
              <p className="text-xs font-mono text-red-200/70 mt-2">{toxic.description}</p>
            </div>
          )}
          {roadmap?.evidence?.roadmap && (
            <div className="rounded-xl border border-emerald-500/25 bg-emerald-950/10 p-4 mb-5">
              <p className="text-[10px] font-mono text-emerald-300/70 uppercase mb-2">{L.roadmapTitle}</p>
              <ul className="space-y-1">
                {roadmap.evidence.roadmap.map((s, i) => (
                  <li key={i} className="text-[11px] font-mono text-white/75"><span className="text-emerald-400">{s.tier || s.priority}</span> · {s.action}: {s.detail}</li>
                ))}
              </ul>
            </div>
          )}
          {agentGaps.length > 0 && (
            <div className="rounded-xl border border-violet-500/25 bg-violet-950/10 p-4 mb-5">
              <p className="text-[10px] font-mono text-violet-300/70 uppercase mb-2">{L.agentGapTitle}</p>
              {agentGaps.map((f, i) => <p key={i} className="text-[11px] font-mono text-white/65">{f.title}</p>)}
            </div>
          )}
          {categories.length > 0 && (
            <div className="mb-5 flex flex-wrap items-center gap-2">
              <span className="text-[10px] font-mono uppercase tracking-widest text-white/40">{L.categories}</span>
              {categories.map((c) => <Chip key={c} color={ACCENT2}>{c}</Chip>)}
            </div>
          )}
        </>
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
