// Password Spray & Credential-Stuffing Posture Command Center (engine: password_spray).
// World-first agentless spray hygiene — M365 GetUserRealm, OIDC ROPC, Autodiscover, lockout curves, XFF bypass surface.
import { firstClientTarget } from '../lib/clientTarget'
import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useIntegrationsPrefill } from '../hooks/useHubLocalScanParams'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { motion } from 'framer-motion'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../utils/apiFetch'
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'
import { downloadBytes } from '../lib/pdfExport'
import Button from '../components/ui/Button'

const ENGINE_ID = 'password_spray'
const ACCENT = '#f43f5e'

const LABELS = {
  en: {
    title: 'Password Spray & Stuffing Posture Command Center',
    subtitle: 'Supreme-tier agentless credential intelligence — 22 live probe layers, Entra AADSTS, M365 GetUserRealm, subdomain login hunter, SAML/OIDC ROPC/device-code, lockout-curve + decay, timing/breach/browser-WAF oracles, HSTS/cookie/PKCE transport probes, toxic combinations, 8-domain scores, remediation roadmap & security graph',
    badge: 'Spray Posture',
    client: 'Client',
    selectClient: 'Select client…',
    selectClientFirst: 'Select a client first',
    target: 'Target (SSO URL, OWA, or domain root)',
    targetPh: 'https://login.example.com  or  owa.corp.example.com  or  corp.example.com',
    domain: 'Email / UPN domain (M365 + enumeration)',
    domainPh: 'corp.example.com',
    run: 'Run spray posture assessment',
    scanning: 'Assessing…',
    queued: 'Assessment queued',
    scanFailed: 'Scan failed',
    intensity: 'Probe intensity',
    light: 'Light', normal: 'Normal', aggressive: 'Aggressive',
    profile: 'Scan profile',
    profiles: { full: 'Full', discovery_only: 'Discovery only', spray_test: 'Spray test', federation: 'Federation / SSO' },
    layers: 'Assessment layers',
    checkRateLimit: 'Rate-limit detection (429/Retry-After)',
    checkLockout: 'Account lockout detection',
    checkUserEnum: 'User-enumeration oracle',
    checkMfa: 'MFA step-up surface',
    checkCaptcha: 'CAPTCHA challenge detection',
    checkFederation: 'Federated SSO exposure',
    checkM365: 'Microsoft GetUserRealm (Entra tenant)',
    checkOidcRopc: 'OIDC ROPC grant detection',
    checkAutodiscover: 'Exchange Autodiscover (OWA/EWS)',
    checkXff: 'X-Forwarded-For rate-limit bypass surface',
    checkLockoutCurve: 'Lockout-curve fingerprint',
    attackPaths: 'Synthesize attack paths',
    postureScoring: 'Posture scoring (0–100)',
    dryRun: 'Dry run (discovery only — no spray)',
    advanced: 'Advanced parameters',
    paths: 'Login paths (one per line)',
    usernames: 'Custom probe usernames',
    passwords: 'Custom probe passwords',
    wordlist: 'Wordlist size',
    delay: 'Delay between attempts (ms)',
    maxAttempts: 'Max spray attempts per surface',
    timeout: 'Per-request timeout (ms)',
    concurrency: 'Path discovery concurrency',
    authHeader: 'Auth header (Name: Value)',
    cookies: 'Session cookie',
    reset: 'Reset defaults',
    export: 'Export JSON',
    lastRun: 'Last run',
    statusIdle: 'Idle',
    statusRunning: 'Running',
    statusCompleted: 'Completed',
    statusError: 'Error',
    posture: 'Credential-stuffing posture',
    friction: 'Stuffing friction',
    grade: 'Grade',
    counts: 'Findings by severity',
    categories: 'Intelligence domains',
    pathsTitle: 'Attack paths',
    findingsTitle: 'Spray posture findings',
    lockoutTitle: 'Lockout curves',
    m365Title: 'Entra / M365 tenant',
    noFindings: 'No spray/stuffing weaknesses observed — strong identity hygiene.',
    runToPopulate: 'Configure target/domain and run the assessment.',
    filterAll: 'all',
    related: 'Related identity engines',
    relatedIdentity: 'Identity & SSO Command Center',
    relatedKerberos: 'AD & Kerberos Security',
    relatedEngine: 'Engine detail (API)',
    graphHint: 'Discover → enumerate → spray → valid account → pivot',
    radar: 'Posture radar (6 axes)',
    remediation: 'Remediation playbook',
    entra: 'Entra AADSTS signals',
    subdomains: 'Shadow login subdomains',
    toxicTitle: 'Toxic combination detected',
    roadmapTitle: 'Prioritized remediation roadmap',
    categoryScores: '8-domain posture breakdown',
    agentGapTitle: 'Agent-required deep coverage',
    emitAgentGuidance: 'Show honest agent-required capability gaps',
    checkSaml: 'SAML federation metadata',
    checkPasswordPolicy: 'Password policy oracle',
    checkDeviceCode: 'OIDC device-code grant',
    checkBasicNtlm: 'Basic/NTLM auth surface',
    checkBreach: 'Breach-password oracle',
    checkCors: 'Permissive CORS on login API',
    checkLockoutDecay: 'Lockout decay probe',
    checkHsts: 'HSTS on auth surfaces',
    checkWebauthn: 'WebAuthn / passkey surface',
    checkPkce: 'OIDC PKCE posture',
    checkCookies: 'Set-Cookie hardening',
  },
  he: {
    title: 'מרכז פיקוד Password Spray ו-Credential Stuffing',
    subtitle: 'מודיעין תקיפת זהויות ללא סוכן — מיפוי login, M365 GetUserRealm, OIDC ROPC, Autodiscover, עקומת נעילה, X-Forwarded-For, סינתזת נתיבי תקיפה',
    badge: 'תנוחת Spray',
    client: 'לקוח',
    selectClient: 'בחר לקוח…',
    selectClientFirst: 'בחר לקוח תחילה',
    target: 'יעד (SSO, OWA, או שורש דומיין)',
    targetPh: 'https://login.example.com  או  owa.corp.example.com  או  corp.example.com',
    domain: 'דומיין דוא"ל / UPN (M365 + enumeration)',
    domainPh: 'corp.example.com',
    run: 'הרץ הערכת תנוחת spray',
    scanning: 'מעריך…',
    queued: 'ההערכה בתור',
    scanFailed: 'הסריקה נכשלה',
    intensity: 'עוצמת בדיקה',
    light: 'קלה', normal: 'רגילה', aggressive: 'אגרסיבית',
    profile: 'פרופיל סריקה',
    profiles: { full: 'מלא', discovery_only: 'גילוי בלבד', spray_test: 'בדיקת spray', federation: 'פדרציה / SSO' },
    layers: 'שכבות הערכה',
    checkRateLimit: 'זיהוי rate-limit (429/Retry-After)',
    checkLockout: 'זיהוי נעילת חשבון',
    checkUserEnum: 'אורקל user enumeration',
    checkMfa: 'שטח MFA step-up',
    checkCaptcha: 'זיהוי CAPTCHA',
    checkFederation: 'חשיפת SSO מפדרט',
    checkM365: 'Microsoft GetUserRealm (Entra)',
    checkOidcRopc: 'זיהוי OIDC ROPC grant',
    checkAutodiscover: 'Exchange Autodiscover (OWA/EWS)',
    checkXff: 'X-Forwarded-For bypass surface',
    checkLockoutCurve: 'טביעת עקומת נעילה',
    attackPaths: 'סינתזת נתיבי תקיפה',
    postureScoring: 'ציון תנוחה (0–100)',
    dryRun: 'Dry run (גילוי בלבד)',
    advanced: 'פרמטרים מתקדמים',
    paths: 'נתיבי login (שורה לכל נתיב)',
    usernames: 'שמות משתמש לבדיקה',
    passwords: 'סיסמאות לבדיקה',
    wordlist: 'גודל wordlist',
    delay: 'השהיה בין ניסיונות (ms)',
    maxAttempts: 'מקסימום ניסיונות spray לכל surface',
    timeout: 'Timeout לבקשה (ms)',
    concurrency: 'מקביליות גילוי נתיבים',
    authHeader: 'Auth header (Name: Value)',
    cookies: 'עוגיית session',
    reset: 'אפס ברירות מחדל',
    export: 'ייצוא JSON',
    lastRun: 'ריצה אחרונה',
    statusIdle: 'ממתין',
    statusRunning: 'רץ',
    statusCompleted: 'הושלם',
    statusError: 'שגיאה',
    posture: 'תנוחת credential stuffing',
    friction: 'חיכוך stuffing',
    grade: 'דירוג',
    counts: 'ממצאים לפי חומרה',
    categories: 'תחומי מודיעין',
    pathsTitle: 'נתיבי תקיפה',
    findingsTitle: 'ממצאי תנוחת spray',
    lockoutTitle: 'עקומות נעילה',
    m365Title: 'דייר Entra / M365',
    noFindings: 'לא נצפו חולשות spray/stuffing — היגיינת זהויות חזקה.',
    runToPopulate: 'הגדר יעד/דומיין והרץ הערכה.',
    filterAll: 'הכל',
    related: 'מנועי זהות קשורים',
    relatedIdentity: 'מרכז Identity & SSO',
    relatedKerberos: 'AD ו-Kerberos',
    relatedEngine: 'פרטי מנוע (API)',
    graphHint: 'גילוי → enumeration → spray → חשבון תקף → pivot',
    radar: 'רדאר תנוחה (6 צירים)',
    remediation: 'מדריך תיקון',
    entra: 'אותות Entra AADSTS',
    subdomains: 'סאב-דומיינים login נסתרים',
    toxicTitle: 'שילוב רעיל זוהה',
    roadmapTitle: 'מפת דרכים לתיקון מדורג',
    categoryScores: 'פירוט תנוחה ב-8 תחומים',
    agentGapTitle: 'כיסוי עמוק הדורש סוכן',
    emitAgentGuidance: 'הצג פערי יכולות הדורשים סוכן',
    checkSaml: 'SAML federation metadata',
    checkPasswordPolicy: 'אורקל מדיניות סיסמה',
    checkDeviceCode: 'OIDC device-code grant',
    checkBasicNtlm: 'Basic/NTLM auth surface',
    checkBreach: 'אורקל סיסמאות דלופות',
    checkCors: 'CORS מתירני על login API',
    checkLockoutDecay: 'בדיקת decay של נעילה',
    checkHsts: 'HSTS על שטחי auth',
    checkWebauthn: 'WebAuthn / passkey surface',
    checkPkce: 'תנוחת OIDC PKCE',
    checkCookies: 'קשיחות Set-Cookie',
  },
}

function defaultParams() {
  return {
    scan_profile: 'full',
    intensity: 'normal',
    wordlist: 'medium',
    domain: '',
    check_rate_limit: true,
    check_lockout: true,
    check_user_enum: true,
    check_mfa_surface: true,
    check_captcha: true,
    check_oauth_federation: true,
    check_m365_realm: true,
    check_oidc_ropc: true,
    check_autodiscover: true,
    check_xff_bypass: true,
    check_lockout_curve: true,
    check_subdomain_login: true,
    check_saml_metadata: true,
    check_password_policy: true,
    check_device_code: true,
    check_basic_ntlm: true,
    check_browser_differential: true,
    check_breach_differential: true,
    check_timing_enum: true,
    check_entra_errors: true,
    check_cors_login: true,
    check_lockout_decay: false,
    check_hsts_auth: true,
    check_webauthn_surface: true,
    check_oidc_pkce: true,
    check_cookie_security: true,
    check_remediation_playbook: true,
    emit_agent_guidance: true,
    timing_samples: 8,
    lockout_decay_ms: 30000,
    subdomain_prefixes: '',
    attack_path_synthesis: true,
    posture_scoring: true,
    dry_run: false,
    paths: '',
    usernames: '',
    passwords: '',
    delay_ms: 1500,
    max_attempts: 18,
    timeout_ms: 10000,
    concurrency: 16,
    auth_header: '',
    cookies: '',
  }
}

function sevWeight(s) {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[(s || 'info').toLowerCase()] || 0
}

function Toggle({ on, onClick, label }) {
  return (
    <Button variant="unstyled" type="button" onClick={onClick}
      className="flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-xs font-mono transition-all w-full text-left"
      style={{ borderColor: on ? `${ACCENT}50` : '#ffffff14', backgroundColor: on ? `${ACCENT}14` : 'transparent', color: on ? '#fda4af' : '#ffffff55' }}>
      <span className="w-7 h-4 rounded-full relative transition-all shrink-0" style={{ backgroundColor: on ? ACCENT : '#ffffff20' }}>
        <span className="absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all" style={{ left: on ? '14px' : '2px' }} />
      </span>
      <span>{label}</span>
    </Button>
  )
}


function CategoryScoresPanel({ scores, L }) {
  if (!scores || typeof scores !== 'object') return null
  const axes = [
    ['rate_limiting', 'Rate limiting'],
    ['lockout_policy', 'Lockout policy'],
    ['mfa_captcha', 'MFA / CAPTCHA'],
    ['enumeration_resistance', 'Anti-enumeration'],
    ['federation_hygiene', 'Federation hygiene'],
    ['oidc_token_hygiene', 'OIDC token hygiene'],
    ['automation_resistance', 'Anti-automation'],
    ['transport_session', 'Transport / session'],
  ]
  return (
    <div className="rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] p-4 mb-4">
      <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest mb-3">{L.categoryScores}</p>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {axes.map(([k, label]) => {
          const v = Number(scores[k] ?? 0)
          return (
            <div key={k}>
              <div className="flex justify-between text-[10px] font-mono text-[var(--text-muted)] mb-1">
                <span>{label}</span>
                <span style={{ color: v >= 80 ? '#4ade80' : v >= 50 ? '#fbbf24' : '#f87171' }}>{v}</span>
              </div>
              <div className="h-1.5 rounded-full bg-[var(--row-hover-bg)] overflow-hidden">
                <div className="h-full rounded-full transition-all" style={{ width: `${v}%`, backgroundColor: v >= 80 ? '#4ade80' : v >= 50 ? '#fbbf24' : '#f87171' }} />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function PostureRadar({ radar, L }) {
  if (!radar || typeof radar !== 'object') return null
  const axes = [
    ['rate_limit', 'Rate limit'],
    ['lockout', 'Lockout'],
    ['mfa', 'MFA'],
    ['enumeration', 'Enumeration'],
    ['federation_hygiene', 'Federation'],
    ['automation_resistance', 'Anti-automation'],
  ]
  return (
    <div className="rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] p-4 mb-4">
      <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest mb-3">{L.radar}</p>
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        {axes.map(([k, label]) => {
          const v = Number(radar[k] ?? 0)
          return (
            <div key={k}>
              <div className="flex justify-between text-[10px] font-mono text-[var(--text-muted)] mb-1">
                <span>{label}</span>
                <span style={{ color: v >= 80 ? '#4ade80' : v >= 50 ? '#fbbf24' : '#f87171' }}>{v}</span>
              </div>
              <div className="h-1.5 rounded-full bg-[var(--row-hover-bg)] overflow-hidden">
                <div className="h-full rounded-full transition-all" style={{ width: `${v}%`, backgroundColor: v >= 80 ? '#4ade80' : v >= 50 ? '#fbbf24' : '#f87171' }} />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function PostureCard({ finding, L, pathCount }) {
  const ev = finding?.evidence || {}
  const score = ev.score ?? finding?.score ?? '—'
  const grade = ev.grade ?? finding?.grade ?? '—'
  const friction = ev.stuffing_friction != null ? Math.round(Number(ev.stuffing_friction) * 100) : null
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl border p-5 mb-6 grid md:grid-cols-4 gap-4"
      style={{ borderColor: `${ACCENT}35`, background: `linear-gradient(135deg, ${ACCENT}12, transparent)` }}>
      <div>
        <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest mb-1">{L.posture}</p>
        <p className="text-4xl font-bold font-mono" style={{ color: ACCENT }}>{score}<span className="text-lg text-[var(--text-disabled)]">/100</span></p>
        <p className="text-xs font-mono text-[var(--text-tertiary)] mt-1">{L.grade}: <span className="text-[var(--text-secondary)]">{grade}</span></p>
      </div>
      <div>
        <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest mb-1">{L.friction}</p>
        <p className="text-3xl font-bold font-mono text-sky-300">{friction != null ? `${friction}%` : '—'}</p>
        <p className="text-[10px] font-mono text-[var(--text-muted)] mt-1">{L.graphHint}</p>
      </div>
      <div>
        <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest mb-1">{L.pathsTitle}</p>
        <p className="text-3xl font-bold font-mono text-amber-300">{pathCount}</p>
      </div>
      <div className="text-[11px] font-mono text-[var(--text-muted)] leading-relaxed">{finding?.description}</div>
    </motion.div>
  )
}

function PostureRadarWrap({ finding, L }) {
  const radar = finding?.posture_radar || finding?.evidence?.posture_radar
  return <PostureRadar radar={radar} L={L} />
}

export default function PasswordSprayCommandCenter() {
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
    apiFetch('/api/clients').then((d) => { if (Array.isArray(d)) setClients(d) }).catch(() => {})
  }, [])

  useEffect(() => {
    if (!clientId) return
    const c = clients.find((x) => String(x.id) === String(clientId))
    const t = firstClientTarget(c)
    if (t) {
      setTarget(t)
      try {
        const u = new URL(t.startsWith('http') ? t : `https://${t}`)
        if (!params.domain) set('domain', u.hostname.replace(/^www\./, ''))
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
    body.scan_profile = params.scan_profile
    body.intensity = params.intensity
    body.wordlist = params.wordlist
    body.delay_ms = Number(params.delay_ms) || 1500
    body.max_attempts = Number(params.max_attempts) || 18
    body.timeout_ms = Number(params.timeout_ms) || 10000
    body.concurrency = Number(params.concurrency) || 16
    if (params.domain.trim()) body.domain = params.domain.trim()
    if (params.paths.trim()) body.paths = params.paths
    if (params.usernames.trim()) body.usernames = params.usernames
    if (params.passwords.trim()) body.passwords = params.passwords
    if (params.auth_header.trim()) body.auth_header = params.auth_header.trim()
    if (params.cookies.trim()) body.cookies = params.cookies.trim()
    const boolMap = {
      check_rate_limit: 'check_rate_limit',
      check_lockout: 'check_lockout',
      check_user_enum: 'check_user_enum',
      check_mfa_surface: 'check_mfa_surface',
      check_captcha: 'check_captcha',
      check_oauth_federation: 'check_oauth_federation',
      check_m365_realm: 'check_m365_realm',
      check_oidc_ropc: 'check_oidc_ropc',
      check_autodiscover: 'check_autodiscover',
      check_xff_bypass: 'check_xff_bypass',
      check_lockout_curve: 'check_lockout_curve',
      check_subdomain_login: 'check_subdomain_login',
      check_saml_metadata: 'check_saml_metadata',
      check_password_policy: 'check_password_policy',
      check_device_code: 'check_device_code',
      check_basic_ntlm: 'check_basic_ntlm',
      check_browser_differential: 'check_browser_differential',
      check_breach_differential: 'check_breach_differential',
      check_timing_enum: 'check_timing_enum',
      check_entra_errors: 'check_entra_errors',
      check_cors_login: 'check_cors_login',
      check_lockout_decay: 'check_lockout_decay',
      check_hsts_auth: 'check_hsts_auth',
      check_webauthn_surface: 'check_webauthn_surface',
      check_oidc_pkce: 'check_oidc_pkce',
      check_cookie_security: 'check_cookie_security',
      check_remediation_playbook: 'check_remediation_playbook',
      emit_agent_guidance: 'emit_agent_guidance',
      attack_path_synthesis: 'attack_path_synthesis',
      posture_scoring: 'posture_scoring',
      dry_run: 'dry_run',
    }
    Object.entries(boolMap).forEach(([k, apiK]) => { body[apiK] = params[k] ? 'true' : 'false' })
    body.timing_samples = Number(params.timing_samples) || 8
    body.lockout_decay_ms = Number(params.lockout_decay_ms) || 30000
    if (params.subdomain_prefixes.trim()) body.subdomain_prefixes = params.subdomain_prefixes.trim()
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
    downloadBytes(new TextEncoder().encode(JSON.stringify(payload, null, 2)), `spray-posture-${Date.now()}.json`, 'application/json')
  }, [target, params, findings])

  const { posture, paths, regular, m365, lockoutCurves, ropc, entra, remediation, subdomains, toxic, roadmap, agentGaps, categoryScores } = useMemo(() => {
    const postureF = findings.find((f) => f.category === 'posture_score') || null
    const toxicF = findings.find((f) => f.category === 'toxic_combination') || null
    const roadmapF = findings.find((f) => f.category === 'remediation_roadmap') || null
    const pathsF = findings.filter((f) => f.category === 'attack_path')
    const agentF = findings.filter((f) => f.category === 'agent_guidance' || (f.title || '').includes('Agent-required'))
    const m365F = findings.filter((f) => f.category === 'm365_realm')
    const lockoutF = findings.filter((f) => f.category === 'lockout_curve')
    const ropcF = findings.filter((f) => f.category === 'oidc_ropc')
    const entraF = findings.filter((f) => f.category === 'entra_aadsts')
    const remF = findings.find((f) => f.category === 'remediation_playbook')
    const subF = findings.filter((f) => f.category === 'subdomain_login')
    const regularF = findings
      .filter((f) => !['posture_score', 'attack_path', 'toxic_combination', 'remediation_roadmap', 'agent_guidance'].includes(f.category)
        && !(f.title || '').includes('Agent-required'))
      .sort((a, b) => sevWeight(b.severity) - sevWeight(a.severity))
    const scores = postureF?.evidence?.category_scores || roadmapF?.evidence?.category_scores || null
    return { posture: postureF, paths: pathsF, regular: regularF, m365: m365F, lockoutCurves: lockoutF, ropc: ropcF, entra: entraF, remediation: remF, subdomains: subF, toxic: toxicF, roadmap: roadmapF, agentGaps: agentF, categoryScores: scores }
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
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-[var(--bg-1)] border-rose-500/30 text-rose-200'}`}>
          {toast.msg}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3 mb-6">
        <label className="flex items-center gap-2 text-xs font-mono text-[var(--text-tertiary)]">
          {L.client}
          <select value={clientId ?? ''} onChange={(e) => setClientId(e.target.value || null)}
            className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[var(--text-secondary)] focus:outline-none focus:border-rose-500/40">
            <option value="">{L.selectClient}</option>
            {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </label>
        <Link to="/identity-security" className="text-[11px] font-mono text-violet-300/80 hover:text-violet-200 border border-violet-500/25 rounded-lg px-3 py-1.5">
          {L.relatedIdentity} →
        </Link>
        <span className="inline-flex items-center gap-2 text-[11px] font-mono text-[var(--text-tertiary)] border border-[var(--border-default)] rounded-lg px-3 py-1.5">
          <span className="w-2 h-2 rounded-full" style={{ background: statusColor, boxShadow: status === 'running' ? `0 0 8px ${statusColor}` : 'none' }} />
          {{ idle: L.statusIdle, running: L.statusRunning, completed: L.statusCompleted, error: L.statusError }[status] ?? status}
          {lastRun && <span className="text-[var(--text-disabled)]">· {L.lastRun}: {lastRun}</span>}
        </span>
      </div>

      <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-6 mb-6">
        <div className="grid lg:grid-cols-2 gap-4 mb-4">
          <label className="block text-xs font-mono text-[var(--text-tertiary)]">
            {L.target}
            <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder={L.targetPh}
              className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-[var(--text-primary)] focus:outline-none focus:border-rose-500/40" />
          </label>
          <label className="block text-xs font-mono text-[var(--text-tertiary)]">
            {L.domain}
            <input value={params.domain} onChange={(e) => set('domain', e.target.value)} placeholder={L.domainPh}
              className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-[var(--text-primary)] focus:outline-none focus:border-rose-500/40" />
          </label>
        </div>

        <div className="flex flex-wrap gap-3 mb-4 items-center">
          <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{L.profile}</span>
          {Object.entries(L.profiles).map(([k, label]) => (
            <Button variant="unstyled" key={k} type="button" onClick={() => set('scan_profile', k)}
              className="px-3 py-1 rounded-lg text-xs font-mono border transition-all"
              style={params.scan_profile === k ? { borderColor: `${ACCENT}50`, color: '#fda4af', backgroundColor: `${ACCENT}15` } : { borderColor: '#ffffff15', color: '#ffffff50' }}>
              {label}
            </Button>
          ))}
        </div>

        <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest mb-2">{L.layers}</p>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2 mb-4">
          <Toggle on={params.check_m365_realm} onClick={() => set('check_m365_realm', !params.check_m365_realm)} label={L.checkM365} />
          <Toggle on={params.check_oidc_ropc} onClick={() => set('check_oidc_ropc', !params.check_oidc_ropc)} label={L.checkOidcRopc} />
          <Toggle on={params.check_autodiscover} onClick={() => set('check_autodiscover', !params.check_autodiscover)} label={L.checkAutodiscover} />
          <Toggle on={params.check_rate_limit} onClick={() => set('check_rate_limit', !params.check_rate_limit)} label={L.checkRateLimit} />
          <Toggle on={params.check_lockout} onClick={() => set('check_lockout', !params.check_lockout)} label={L.checkLockout} />
          <Toggle on={params.check_user_enum} onClick={() => set('check_user_enum', !params.check_user_enum)} label={L.checkUserEnum} />
          <Toggle on={params.check_mfa_surface} onClick={() => set('check_mfa_surface', !params.check_mfa_surface)} label={L.checkMfa} />
          <Toggle on={params.check_captcha} onClick={() => set('check_captcha', !params.check_captcha)} label={L.checkCaptcha} />
          <Toggle on={params.check_oauth_federation} onClick={() => set('check_oauth_federation', !params.check_oauth_federation)} label={L.checkFederation} />
          <Toggle on={params.check_xff_bypass} onClick={() => set('check_xff_bypass', !params.check_xff_bypass)} label={L.checkXff} />
          <Toggle on={params.check_subdomain_login} onClick={() => set('check_subdomain_login', !params.check_subdomain_login)} label="Subdomain login hunter" />
          <Toggle on={params.check_saml_metadata} onClick={() => set('check_saml_metadata', !params.check_saml_metadata)} label={L.checkSaml} />
          <Toggle on={params.check_password_policy} onClick={() => set('check_password_policy', !params.check_password_policy)} label={L.checkPasswordPolicy} />
          <Toggle on={params.check_device_code} onClick={() => set('check_device_code', !params.check_device_code)} label={L.checkDeviceCode} />
          <Toggle on={params.check_basic_ntlm} onClick={() => set('check_basic_ntlm', !params.check_basic_ntlm)} label={L.checkBasicNtlm} />
          <Toggle on={params.check_entra_errors} onClick={() => set('check_entra_errors', !params.check_entra_errors)} label="Entra AADSTS" />
          <Toggle on={params.check_timing_enum} onClick={() => set('check_timing_enum', !params.check_timing_enum)} label="Timing enumeration" />
          <Toggle on={params.check_browser_differential} onClick={() => set('check_browser_differential', !params.check_browser_differential)} label="Browser vs script WAF" />
          <Toggle on={params.check_breach_differential} onClick={() => set('check_breach_differential', !params.check_breach_differential)} label={L.checkBreach} />
          <Toggle on={params.check_cors_login} onClick={() => set('check_cors_login', !params.check_cors_login)} label={L.checkCors} />
          <Toggle on={params.check_lockout_curve} onClick={() => set('check_lockout_curve', !params.check_lockout_curve)} label={L.checkLockoutCurve} />
          <Toggle on={params.check_lockout_decay} onClick={() => set('check_lockout_decay', !params.check_lockout_decay)} label={L.checkLockoutDecay} />
          <Toggle on={params.check_hsts_auth} onClick={() => set('check_hsts_auth', !params.check_hsts_auth)} label={L.checkHsts} />
          <Toggle on={params.check_webauthn_surface} onClick={() => set('check_webauthn_surface', !params.check_webauthn_surface)} label={L.checkWebauthn} />
          <Toggle on={params.check_oidc_pkce} onClick={() => set('check_oidc_pkce', !params.check_oidc_pkce)} label={L.checkPkce} />
          <Toggle on={params.check_cookie_security} onClick={() => set('check_cookie_security', !params.check_cookie_security)} label={L.checkCookies} />
          <Toggle on={params.attack_path_synthesis} onClick={() => set('attack_path_synthesis', !params.attack_path_synthesis)} label={L.attackPaths} />
          <Toggle on={params.posture_scoring} onClick={() => set('posture_scoring', !params.posture_scoring)} label={L.postureScoring} />
          <Toggle on={params.emit_agent_guidance} onClick={() => set('emit_agent_guidance', !params.emit_agent_guidance)} label={L.emitAgentGuidance} />
          <Toggle on={params.dry_run} onClick={() => set('dry_run', !params.dry_run)} label={L.dryRun} />
        </div>

        <div className="flex items-center justify-between gap-4 pt-2 border-t border-[var(--border-subtle)]">
          <Button variant="unstyled" type="button" onClick={() => setShowAdvanced(!showAdvanced)} className="text-xs font-mono text-[var(--text-muted)] hover:text-[var(--text-secondary)]">
            {showAdvanced ? '▾' : '▸'} {L.advanced}
          </Button>
          <div className="flex gap-2">
            {findings.length > 0 && (
              <Button variant="unstyled" type="button" onClick={handleExport} className="px-3 py-2 rounded-xl font-mono text-xs border border-[var(--border-strong)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)]">{L.export}</Button>
            )}
            <Button variant="unstyled" type="button" onClick={handleRun} disabled={status === 'running' || !clientId}
              className="px-5 py-2 rounded-xl font-mono text-sm border transition-all disabled:opacity-40"
              style={{ borderColor: `${ACCENT}50`, color: '#fda4af', backgroundColor: `${ACCENT}18` }}>
              {status === 'running' ? L.scanning : L.run}
            </Button>
          </div>
        </div>

        {showAdvanced && (
          <div className="mt-4 pt-4 border-t border-[var(--border-subtle)] grid md:grid-cols-2 gap-3">
            <label className="text-xs font-mono text-[var(--text-muted)]">{L.delay}
              <input type="number" value={params.delay_ms} onChange={(e) => set('delay_ms', e.target.value)} className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-[var(--text-secondary)]" />
            </label>
            <label className="text-xs font-mono text-[var(--text-muted)]">{L.maxAttempts}
              <input type="number" value={params.max_attempts} onChange={(e) => set('max_attempts', e.target.value)} className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-[var(--text-secondary)]" />
            </label>
            <label className="text-xs font-mono text-[var(--text-muted)] col-span-full">{L.paths}
              <textarea value={params.paths} onChange={(e) => set('paths', e.target.value)} rows={3} className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-[var(--text-secondary)] font-mono text-[11px]" />
            </label>
            <label className="text-xs font-mono text-[var(--text-muted)]">{L.usernames}
              <textarea value={params.usernames} onChange={(e) => set('usernames', e.target.value)} rows={2} className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-[var(--text-secondary)] font-mono text-[11px]" />
            </label>
            <label className="text-xs font-mono text-[var(--text-muted)]">{L.passwords}
              <textarea value={params.passwords} onChange={(e) => set('passwords', e.target.value)} rows={2} className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-[var(--text-secondary)] font-mono text-[11px]" />
            </label>
            <label className="text-xs font-mono text-[var(--text-muted)]">Timing samples
              <input type="number" value={params.timing_samples} onChange={(e) => set('timing_samples', e.target.value)} className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-[var(--text-secondary)]" />
            </label>
            <label className="text-xs font-mono text-[var(--text-muted)]">Lockout decay wait (ms)
              <input type="number" value={params.lockout_decay_ms} onChange={(e) => set('lockout_decay_ms', e.target.value)} className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-[var(--text-secondary)]" />
            </label>
            <label className="text-xs font-mono text-[var(--text-muted)] col-span-full">Subdomain prefixes (comma-sep)
              <input value={params.subdomain_prefixes} onChange={(e) => set('subdomain_prefixes', e.target.value)} placeholder="login,sso,idp,owa,auth" className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-[var(--text-secondary)] font-mono text-[11px]" />
            </label>
            <Button variant="unstyled" type="button" onClick={() => setParams(defaultParams())} className="text-xs font-mono text-[var(--text-muted)] hover:text-[var(--text-secondary)] border border-[var(--border-default)] rounded-lg px-3 py-2 md:col-span-2 justify-self-start">{L.reset}</Button>
          </div>
        )}
      </div>

      <div className="flex flex-wrap gap-2 mb-6 text-[11px] font-mono">
        <span className="text-[var(--text-disabled)]">{L.related}:</span>
        <Link to="/identity-security" className="text-violet-300/80 hover:text-violet-200">{L.relatedIdentity}</Link>
        <span className="text-[var(--text-disabled)]">·</span>
        <Link to="/kerberos-security" className="text-amber-300/80 hover:text-amber-200">{L.relatedKerberos}</Link>
        <span className="text-[var(--text-disabled)]">·</span>
        <Link to={`/engines/${ENGINE_ID}`} className="text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]">{L.relatedEngine}</Link>
      </div>

      {findings.length === 0 && status !== 'running' && (
        <p className="text-sm font-mono text-[var(--text-muted)] text-center py-12">{L.runToPopulate}</p>
      )}

      {posture && <PostureCard finding={posture} L={L} pathCount={paths.length} />}
      {posture && <PostureRadarWrap finding={posture} L={L} />}
      {categoryScores && <CategoryScoresPanel scores={categoryScores} L={L} />}

      {toxic && (
        <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
          className="rounded-2xl border border-red-500/50 bg-red-950/25 p-5 mb-6">
          <p className="text-[10px] font-mono text-red-300/80 uppercase tracking-widest mb-2">{L.toxicTitle}</p>
          <p className="text-sm font-mono text-red-100 font-semibold">{toxic.title}</p>
          <p className="text-xs font-mono text-red-200/70 mt-2">{toxic.description}</p>
          {Array.isArray(toxic.evidence?.combinations) && (
            <ul className="mt-3 space-y-1">
              {toxic.evidence.combinations.map((c, i) => (
                <li key={i} className="text-[11px] font-mono text-red-200/90">⊕ {c}</li>
              ))}
            </ul>
          )}
        </motion.div>
      )}

      {roadmap && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-950/15 p-4 mb-4">
          <p className="text-[10px] font-mono text-amber-300/70 uppercase mb-2">{L.roadmapTitle}</p>
          {Array.isArray(roadmap.evidence?.roadmap) && (
            <ul className="space-y-2">
              {roadmap.evidence.roadmap.map((step, i) => (
                <li key={i} className="text-[11px] font-mono text-[var(--text-secondary)]">
                  <span className="text-amber-400">{step.tier || `P${step.priority}`}</span>
                  {' · '}{step.action}: <span className="text-[var(--text-tertiary)]">{step.detail}</span>
                  {step.effort && <span className="text-[var(--text-muted)]"> ({step.effort})</span>}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {agentGaps.length > 0 && (
        <div className="rounded-xl border border-violet-500/25 bg-violet-950/10 p-4 mb-4">
          <p className="text-[10px] font-mono text-violet-300/70 uppercase mb-2">{L.agentGapTitle}</p>
          <ul className="space-y-1">
            {agentGaps.map((f, i) => (
              <li key={i} className="text-[11px] font-mono text-[var(--text-tertiary)]">{f.title}</li>
            ))}
          </ul>
        </div>
      )}

      {entra.length > 0 && (
        <div className="rounded-xl border border-violet-500/35 bg-violet-950/15 p-4 mb-4">
          <p className="text-[10px] font-mono text-violet-300/70 uppercase mb-2">{L.entra}</p>
          {entra.map((f, i) => (
            <p key={i} className="text-sm font-mono text-[var(--text-primary)]">{f.title}</p>
          ))}
        </div>
      )}

      {subdomains.length > 0 && (
        <div className="rounded-xl border border-sky-500/25 bg-sky-950/10 p-4 mb-4">
          <p className="text-[10px] font-mono text-sky-300/70 uppercase mb-2">{L.subdomains} ({subdomains.length})</p>
          <div className="flex flex-wrap gap-2">
            {subdomains.slice(0, 12).map((f, i) => (
              <span key={i} className="text-[10px] font-mono px-2 py-1 rounded border border-sky-500/25 text-sky-200">{f.evidence?.url || f.title}</span>
            ))}
          </div>
        </div>
      )}

      {remediation && (
        <div className="rounded-xl border border-emerald-500/25 bg-emerald-950/10 p-4 mb-4">
          <p className="text-[10px] font-mono text-emerald-300/70 uppercase mb-2">{L.remediation}</p>
          <p className="text-xs font-mono text-[var(--text-tertiary)]">{remediation.description}</p>
          {Array.isArray(remediation.evidence?.actions) && (
            <ul className="mt-2 space-y-1">
              {remediation.evidence.actions.map((a, i) => (
                <li key={i} className="text-[11px] font-mono text-[var(--text-secondary)]">
                  <span className="text-emerald-400">{a.priority}</span> · {a.control}: {a.action}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {ropc.length > 0 && (
        <div className="rounded-xl border border-red-500/40 bg-red-950/20 p-4 mb-4 text-sm font-mono text-red-200">
          <strong>ROPC:</strong> {ropc[0].title}
        </div>
      )}

      {m365.length > 0 && (
        <div className="rounded-xl border border-sky-500/30 bg-sky-950/15 p-4 mb-4">
          <p className="text-[10px] font-mono text-sky-300/70 uppercase mb-2">{L.m365Title}</p>
          <p className="text-sm font-mono text-[var(--text-secondary)]">{m365[0].title}</p>
          <p className="text-xs font-mono text-[var(--text-muted)] mt-1">{m365[0].description}</p>
        </div>
      )}

      {lockoutCurves.length > 0 && (
        <div className="rounded-xl border border-amber-500/25 bg-amber-950/10 p-4 mb-4">
          <p className="text-[10px] font-mono text-amber-300/70 uppercase mb-2">{L.lockoutTitle}</p>
          <div className="flex flex-wrap gap-2">
            {lockoutCurves.map((f, i) => (
              <span key={i} className="text-xs font-mono px-2 py-1 rounded-md border border-amber-500/30 text-amber-200">{f.title}</span>
            ))}
          </div>
        </div>
      )}

      {paths.length > 0 && (
        <div className="mb-6">
          <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase tracking-widest mb-2">{L.pathsTitle}</p>
          <div className="space-y-2">
            {paths.map((f, i) => (
              <div key={i} className="rounded-lg border border-red-500/25 bg-red-950/10 px-3 py-2 text-xs font-mono text-red-200">{f.title}</div>
            ))}
          </div>
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
        renderFinding={(f, i) => (
          <div key={i} className="rounded-xl border border-[var(--border-subtle)] bg-[var(--table-surface)] px-4 py-3">
            <div className="flex items-start justify-between gap-2">
              <p className="text-sm font-mono text-[var(--text-primary)]">{f.title}</p>
              <span className="text-[10px] font-mono uppercase shrink-0" style={{ color: { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#38bdf8', info: '#4ade80' }[(f.severity || 'info').toLowerCase()] }}>{f.severity}</span>
            </div>
            {f.description && <p className="text-xs font-mono text-[var(--text-muted)] mt-1">{f.description}</p>}
          </div>
        )}
      />
    </PageShell>
  )
}
