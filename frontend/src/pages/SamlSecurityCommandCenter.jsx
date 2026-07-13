// SAML & Enterprise SSO Federation Security Command Center (engine: saml_attack).
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
import { apiFetch } from '../lib/apiBase'
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'
import Button from '../components/ui/Button'


const ENGINE_ID = 'saml_attack'
const ACCENT = '#f59e0b'

const LABELS = {
  en: {
    title: 'SAML & SSO Federation Security Command Center',
    subtitle: 'Supreme-tier agentless SAML/WS-Fed posture — metadata X.509 parse, RelayState canary, XSW preconditions, WS-Federation, SLO exposure, toxic combinations, 8-domain scores, remediation roadmap & security graph',
    badge: 'SAML Federation Posture',
    client: 'Client', selectClient: 'Select client…', selectClientFirst: 'Select a client first',
    target: 'Target (IdP/ADFS/SSO URL or domain root)', targetPh: 'https://adfs.corp.example.com  or  https://idp.okta.com',
    run: 'Run SAML federation assessment', scanning: 'Assessing…', queued: 'Assessment queued', scanFailed: 'Scan failed',
    intensity: 'Probe intensity', light: 'Light', normal: 'Normal', aggressive: 'Aggressive',
    presets: 'IdP presets', layers: 'Assessment layers',
    checkMetadata: 'SAML metadata discovery + X.509 parse',
    checkRelaystate: 'RelayState open-redirect canary',
    checkErrors: 'Verbose SAML parser error disclosure',
    checkAttackPaths: 'Synthesize SAML attack paths',
    checkXsw: 'XML Signature Wrapping preconditions',
    checkSlo: 'Single Logout (SLO) exposure',
    checkWsFed: 'WS-Federation / ADFS metadata',
    checkExpiry: 'Metadata validUntil expiry',
    checkBindings: 'HTTP-Redirect binding posture',
    emitAgent: 'Show agent-required capability gaps',
    advanced: 'Advanced parameters', metadataUrl: 'Explicit metadata URL override',
    metadataPaths: 'Metadata paths (one per line)', ssoPaths: 'SSO/ACS paths (one per line)',
    relayCanary: 'RelayState canary URL', certWarnDays: 'Cert expiry warn (days)', minCertBits: 'Min cert key bits',
    maxPaths: 'Max paths to probe', timeout: 'HTTP timeout (ms)', concurrency: 'Concurrency',
    reset: 'Reset defaults', export: 'Export JSON',
    posture: 'Federation posture', grade: 'Grade', vendor: 'IdP vendor',
    pathsTitle: 'SAML attack paths', findingsTitle: 'Federation findings',
    toxicTitle: 'Toxic combination detected', roadmapTitle: 'Prioritized remediation roadmap',
    categoryScores: '8-domain posture breakdown', agentGapTitle: 'Agent-required deep coverage',
    runToPopulate: 'Configure the IdP/SSO target and run the assessment.',
    related: 'Related identity engines', relatedIdentity: 'Identity & SSO Command Center',
    relatedKerberos: 'AD & Kerberos Security', relatedSpray: 'Password Spray Posture', relatedEngine: 'Engine detail (API)',
  },
  he: {
    title: 'מרכז פיקוד SAML ו-SSO Federation',
    subtitle: 'תנוחת SAML/WS-Fed ללא סוכן — ניתוח metadata ו-X.509, RelayState, XSW, WS-Federation, SLO, שילובים רעילים, 8 תחומים, מפת תיקון וגרף',
    badge: 'תנוחת SAML Federation',
    client: 'לקוח', selectClient: 'בחר לקוח…', selectClientFirst: 'בחר לקוח תחילה',
    target: 'יעד (IdP/ADFS/SSO URL או שורש דומיין)', targetPh: 'https://adfs.corp.example.com  או  https://idp.okta.com',
    run: 'הרץ הערכת SAML federation', scanning: 'מעריך…', queued: 'ההערכה בתור', scanFailed: 'הסריקה נכשלה',
    intensity: 'עוצמת בדיקה', light: 'קלה', normal: 'רגילה', aggressive: 'אגרסיבית',
    presets: 'תבניות IdP', layers: 'שכבות הערכה',
    checkMetadata: 'גילוי metadata SAML + ניתוח X.509',
    checkRelaystate: 'RelayState open-redirect canary',
    checkErrors: 'חשיפת שגיאות parser SAML',
    checkAttackPaths: 'סינתזת נתיבי תקיפת SAML',
    checkXsw: 'תנאים מוקדמים ל-XML Signature Wrapping',
    checkSlo: 'חשיפת Single Logout (SLO)',
    checkWsFed: 'WS-Federation / ADFS metadata',
    checkExpiry: 'תפוגת validUntil ב-metadata',
    checkBindings: 'תנוחת HTTP-Redirect binding',
    emitAgent: 'הצג פערים שדורשים סוכן',
    advanced: 'פרמטרים מתקדמים', metadataUrl: 'URL metadata מפורש',
    metadataPaths: 'נתיבי metadata (שורה לכל נתיב)', ssoPaths: 'נתיבי SSO/ACS (שורה לכל נתיב)',
    relayCanary: 'RelayState canary URL', certWarnDays: 'אזהרת תפוגת cert (ימים)', minCertBits: 'מינימום ביטים ל-cert',
    maxPaths: 'מקסימום נתיבים', timeout: 'Timeout HTTP (ms)', concurrency: 'מקביליות',
    reset: 'אפס ברירות מחדל', export: 'ייצוא JSON',
    posture: 'תנוחת federation', grade: 'דירוג', vendor: 'ספק IdP',
    pathsTitle: 'נתיבי תקיפת SAML', findingsTitle: 'ממצאי federation',
    toxicTitle: 'שילוב רעיל זוהה', roadmapTitle: 'מפת דרכים לתיקון',
    categoryScores: 'פירוט 8 תחומי תנוחה', agentGapTitle: 'כיסוי עמוק הדורש סוכן',
    runToPopulate: 'הגדר יעד IdP/SSO והרץ הערכה.',
    related: 'מנועי זהות קשורים', relatedIdentity: 'מרכז Identity & SSO',
    relatedKerberos: 'AD ו-Kerberos', relatedSpray: 'תנוחת Password Spray', relatedEngine: 'פרטי מנוע (API)',
  },
}

const IDP_PRESETS = [
  { id: 'adfs', label: 'Microsoft ADFS', hint: 'https://adfs.corp.example.com' },
  { id: 'okta', label: 'Okta', hint: 'https://your-org.okta.com' },
  { id: 'entra', label: 'Entra / Azure AD', hint: 'https://login.microsoftonline.com' },
  { id: 'shib', label: 'Shibboleth', hint: 'https://idp.university.edu' },
]

const SCORE_AXES = [
  ['signing_trust', 'Signing trust'],
  ['assertion_policy', 'Assertion policy'],
  ['metadata_hygiene', 'Metadata hygiene'],
  ['transport_binding', 'Transport / binding'],
  ['redirect_relay', 'RelayState'],
  ['parser_disclosure', 'Parser disclosure'],
  ['slo_surface', 'SLO surface'],
  ['xsw_surface', 'XSW surface'],
]

function defaultParams() {
  return {
    intensity: 'normal',
    metadata_url: '',
    metadata_paths: '',
    sso_paths: '',
    check_metadata: true,
    check_relaystate: true,
    check_error_disclosure: true,
    check_attack_paths: true,
    check_xsw_preconditions: true,
    check_slo_exposure: true,
    check_ws_federation: true,
    check_metadata_expiry: true,
    check_binding_posture: true,
    emit_agent_guidance: true,
    relaystate_canary: 'https://weissman-canary.example.net/probe',
    cert_expiry_warn_days: 30,
    min_cert_bits: 2048,
    max_paths: 28,
    timeout_ms: 8000,
    concurrency: 16,
  }
}

function sevWeight(s) {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[(s || 'info').toLowerCase()] || 0
}

function Toggle({ on, onClick, label }) {
  return (
    <Button variant="unstyled" type="button" onClick={onClick}
      className="flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-xs font-mono transition-all w-full text-left"
      style={{ borderColor: on ? `${ACCENT}50` : '#ffffff14', backgroundColor: on ? `${ACCENT}14` : 'transparent', color: on ? '#fcd34d' : '#ffffff55' }}>
      <span className="w-7 h-4 rounded-full relative transition-all shrink-0" style={{ backgroundColor: on ? ACCENT : '#ffffff20' }}>
        <span className="absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all" style={{ left: on ? '14px' : '2px' }} />
      </span>
      <span>{label}</span>
    </Button>
  )
}


export default function SamlSecurityCommandCenter() {
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
    body.timeout_ms = Number(params.timeout_ms) || 8000
    body.concurrency = Number(params.concurrency) || 16
    body.max_paths = Number(params.max_paths) || 28
    body.cert_expiry_warn_days = Number(params.cert_expiry_warn_days) || 30
    body.min_cert_bits = Number(params.min_cert_bits) || 2048
    if (params.metadata_url.trim()) body.metadata_url = params.metadata_url.trim()
    if (params.metadata_paths.trim()) body.metadata_paths = params.metadata_paths
    if (params.sso_paths.trim()) body.sso_paths = params.sso_paths
    if (params.relaystate_canary.trim()) body.relaystate_canary = params.relaystate_canary.trim()
    const bools = [
      'check_metadata', 'check_relaystate', 'check_error_disclosure', 'check_attack_paths',
      'check_xsw_preconditions', 'check_slo_exposure', 'check_ws_federation',
      'check_metadata_expiry', 'check_binding_posture', 'emit_agent_guidance',
    ]
    bools.forEach((k) => { body[k] = params[k] ? 'true' : 'false' })
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

  const { posture, paths, regular, toxic, roadmap, agentGaps, categoryScores } = useMemo(() => {
    const postureF = findings.find((f) => f.category === 'posture') || null
    const toxicF = findings.find((f) => f.category === 'toxic_combination') || null
    const roadmapF = findings.find((f) => f.category === 'remediation_roadmap') || null
    const pathsF = findings.filter((f) => f.category === 'attack_path')
    const agentF = findings.filter((f) => f.category === 'agent_guidance')
    const regularF = findings
      .filter((f) => !['posture', 'attack_path', 'toxic_combination', 'remediation_roadmap', 'agent_guidance'].includes(f.category))
      .sort((a, b) => sevWeight(b.severity) - sevWeight(a.severity))
    const scores = postureF?.evidence?.category_scores || roadmapF?.evidence?.category_scores || null
    return { posture: postureF, paths: pathsF, regular: regularF, toxic: toxicF, roadmap: roadmapF, agentGaps: agentF, categoryScores: scores }
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
      setFindings(await resolveJobFindings(job, ENGINE_ID, clientId))
      setLastUpdated(new Date().toISOString())
      if (pendingJobId) setLastJobId(pendingJobId)
      setPendingJobId(null)
    },
  })

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
            className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-[var(--text-secondary)]">
            <option value="">{L.selectClient}</option>
            {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </label>
        <Link to="/identity-security" className="text-[11px] font-mono text-violet-300/80 hover:text-violet-200 border border-violet-500/25 rounded-lg px-3 py-1.5">{L.relatedIdentity} →</Link>
      </div>

      <div className="rounded-2xl bg-[var(--bg-2)] border border-[var(--border-default)] p-6 mb-6">
        <label className="block text-xs font-mono text-[var(--text-tertiary)] mb-3">
          {L.target}
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder={L.targetPh}
            className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-[var(--text-primary)]" />
        </label>

        <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase mb-2">{L.presets}</p>
        <div className="flex flex-wrap gap-2 mb-4">
          {IDP_PRESETS.map((p) => (
            <Button variant="unstyled" key={p.id} type="button" onClick={() => setTarget(p.hint)}
              className="px-3 py-1 rounded-lg text-xs font-mono border border-[var(--border-strong)] text-[var(--text-tertiary)] hover:text-amber-200 hover:border-amber-500/30">{p.label}</Button>
          ))}
        </div>

        <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase mb-2">{L.layers}</p>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2 mb-4">
          <Toggle on={params.check_metadata} onClick={() => set('check_metadata', !params.check_metadata)} label={L.checkMetadata} />
          <Toggle on={params.check_relaystate} onClick={() => set('check_relaystate', !params.check_relaystate)} label={L.checkRelaystate} />
          <Toggle on={params.check_error_disclosure} onClick={() => set('check_error_disclosure', !params.check_error_disclosure)} label={L.checkErrors} />
          <Toggle on={params.check_attack_paths} onClick={() => set('check_attack_paths', !params.check_attack_paths)} label={L.checkAttackPaths} />
          <Toggle on={params.check_xsw_preconditions} onClick={() => set('check_xsw_preconditions', !params.check_xsw_preconditions)} label={L.checkXsw} />
          <Toggle on={params.check_slo_exposure} onClick={() => set('check_slo_exposure', !params.check_slo_exposure)} label={L.checkSlo} />
          <Toggle on={params.check_ws_federation} onClick={() => set('check_ws_federation', !params.check_ws_federation)} label={L.checkWsFed} />
          <Toggle on={params.check_metadata_expiry} onClick={() => set('check_metadata_expiry', !params.check_metadata_expiry)} label={L.checkExpiry} />
          <Toggle on={params.check_binding_posture} onClick={() => set('check_binding_posture', !params.check_binding_posture)} label={L.checkBindings} />
          <Toggle on={params.emit_agent_guidance} onClick={() => set('emit_agent_guidance', !params.emit_agent_guidance)} label={L.emitAgent} />
        </div>

        <div className="flex justify-between items-center pt-2 border-t border-[var(--border-subtle)]">
          <Button variant="unstyled" type="button" onClick={() => setShowAdvanced(!showAdvanced)} className="text-xs font-mono text-[var(--text-muted)]">{showAdvanced ? '▾' : '▸'} {L.advanced}</Button>
          <Button variant="unstyled" type="button" onClick={handleRun} disabled={status === 'running' || !clientId}
            className="px-5 py-2 rounded-xl font-mono text-sm border border-amber-500/40 text-amber-200 bg-amber-500/15 disabled:opacity-40">
            {status === 'running' ? L.scanning : L.run}
          </Button>
        </div>

        {showAdvanced && (
          <div className="mt-4 pt-4 border-t border-[var(--border-subtle)] grid md:grid-cols-2 gap-3">
            <label className="text-xs font-mono text-[var(--text-muted)] col-span-full">{L.metadataUrl}
              <input value={params.metadata_url} onChange={(e) => set('metadata_url', e.target.value)} className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-[var(--text-secondary)]" />
            </label>
            <label className="text-xs font-mono text-[var(--text-muted)]">{L.intensity}
              <select value={params.intensity} onChange={(e) => set('intensity', e.target.value)} className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-[var(--text-secondary)]">
                <option value="light">{L.light}</option><option value="normal">{L.normal}</option><option value="aggressive">{L.aggressive}</option>
              </select>
            </label>
            <label className="text-xs font-mono text-[var(--text-muted)]">{L.relayCanary}
              <input value={params.relaystate_canary} onChange={(e) => set('relaystate_canary', e.target.value)} className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-[var(--text-secondary)] font-mono text-[11px]" />
            </label>
            <label className="text-xs font-mono text-[var(--text-muted)] col-span-full">{L.metadataPaths}
              <textarea value={params.metadata_paths} onChange={(e) => set('metadata_paths', e.target.value)} rows={2} className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-[var(--text-secondary)] font-mono text-[11px]" />
            </label>
            <label className="text-xs font-mono text-[var(--text-muted)] col-span-full">{L.ssoPaths}
              <textarea value={params.sso_paths} onChange={(e) => set('sso_paths', e.target.value)} rows={2} className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-[var(--text-secondary)] font-mono text-[11px]" />
            </label>
            <Button variant="unstyled" type="button" onClick={() => setParams(defaultParams())} className="text-xs font-mono text-[var(--text-muted)] border border-[var(--border-default)] rounded-lg px-3 py-2 md:col-span-2 justify-self-start">{L.reset}</Button>
          </div>
        )}
      </div>

      <div className="flex flex-wrap gap-2 mb-6 text-[11px] font-mono">
        <span className="text-[var(--text-disabled)]">{L.related}:</span>
        <Link to="/identity-security" className="text-violet-300/80">{L.relatedIdentity}</Link>
        <span className="text-[var(--text-disabled)]">·</span>
        <Link to="/kerberos-security" className="text-amber-300/80">{L.relatedKerberos}</Link>
        <span className="text-[var(--text-disabled)]">·</span>
        <Link to="/password-spray" className="text-rose-300/80">{L.relatedSpray}</Link>
      </div>

      {findings.length === 0 && status !== 'running' && (
        <p className="text-sm font-mono text-[var(--text-muted)] text-center py-12">{L.runToPopulate}</p>
      )}

      {posture && (
        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
          className="rounded-2xl border border-amber-500/30 bg-amber-950/15 p-5 mb-6">
          <p className="text-[10px] font-mono text-amber-300/70 uppercase mb-1">{L.posture}</p>
          <p className="text-3xl font-bold font-mono text-amber-200">{posture.posture_score ?? posture.evidence?.score ?? '—'}<span className="text-lg text-[var(--text-disabled)]">/100</span></p>
          <p className="text-xs font-mono text-[var(--text-tertiary)] mt-1">{L.grade}: {posture.grade ?? posture.evidence?.grade} · {L.vendor}: {posture.vendor ?? posture.evidence?.vendor}</p>
        </motion.div>
      )}

      {categoryScores && (
        <div className="rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] p-4 mb-4">
          <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase mb-3">{L.categoryScores}</p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {SCORE_AXES.map(([k, label]) => {
              const v = Number(categoryScores[k] ?? 0)
              return (
                <div key={k}>
                  <div className="flex justify-between text-[10px] font-mono text-[var(--text-muted)] mb-1"><span>{label}</span><span>{v}</span></div>
                  <div className="h-1.5 rounded-full bg-[var(--row-hover-bg)]"><div className="h-full rounded-full bg-amber-500/70" style={{ width: `${v}%` }} /></div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {toxic && (
        <div className="rounded-2xl border border-red-500/50 bg-red-950/25 p-5 mb-6">
          <p className="text-[10px] font-mono text-red-300/80 uppercase mb-2">{L.toxicTitle}</p>
          <p className="text-sm font-mono text-red-100 font-semibold">{toxic.title}</p>
          <p className="text-xs font-mono text-red-200/70 mt-2">{toxic.description}</p>
        </div>
      )}

      {roadmap?.evidence?.roadmap && (
        <div className="rounded-xl border border-emerald-500/25 bg-emerald-950/10 p-4 mb-4">
          <p className="text-[10px] font-mono text-emerald-300/70 uppercase mb-2">{L.roadmapTitle}</p>
          <ul className="space-y-1">
            {roadmap.evidence.roadmap.map((s, i) => (
              <li key={i} className="text-[11px] font-mono text-[var(--text-secondary)]"><span className="text-emerald-400">{s.tier || s.priority}</span> · {s.action}: {s.detail}</li>
            ))}
          </ul>
        </div>
      )}

      {agentGaps.length > 0 && (
        <div className="rounded-xl border border-violet-500/25 bg-violet-950/10 p-4 mb-4">
          <p className="text-[10px] font-mono text-violet-300/70 uppercase mb-2">{L.agentGapTitle}</p>
          {agentGaps.map((f, i) => <p key={i} className="text-[11px] font-mono text-[var(--text-tertiary)]">{f.title}</p>)}
        </div>
      )}

      {paths.length > 0 && (
        <div className="mb-6">
          <p className="text-[10px] font-mono text-[var(--text-muted)] uppercase mb-2">{L.pathsTitle}</p>
          {paths.map((f, i) => <div key={i} className="rounded-lg border border-red-500/25 bg-red-950/10 px-3 py-2 text-xs font-mono text-red-200 mb-2">{f.title}</div>)}
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
        renderFinding={(f, i) => (
          <div key={i} className="rounded-xl border border-[var(--border-subtle)] bg-[var(--table-surface)] px-4 py-3">
            <p className="text-sm font-mono text-[var(--text-primary)]">{f.title}</p>
            {f.description && <p className="text-xs font-mono text-[var(--text-muted)] mt-1">{f.description}</p>}
          </div>
        )}
      />
    </PageShell>
  )
}
