// Privilege Escalation & Credential Access Command Center
// Engine: privilege_escalation_credential_access — 500 live defensive checks.
// Read-only auditor: no LSASS dumps, no UAC bypass payloads, no Hell's Gate stubs.
import { firstClientTarget } from '../lib/clientTarget'
import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useIntegrationsPrefill } from '../hooks/useHubLocalScanParams'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import { apiFetch } from '../utils/apiFetch'
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll'
import { downloadBytes } from '../lib/pdfExport'
import Button from '../components/ui/Button'

const ENGINE_ID = 'privilege_escalation_credential_access'
const ACCENT = '#f43f5e'
const ACCENT2 = '#34d399'

const DOMAINS = [
  { key: 'check_syscall', slug: 'syscall_integrity', en: 'Syscall / W^X integrity', he: 'שלמות syscall / W^X', n: '1–50' },
  { key: 'check_lsass', slug: 'lsass_protection', en: 'LSASS / identity daemon', he: 'הגנת LSASS / זהות', n: '51–100' },
  { key: 'check_token', slug: 'token_hardening', en: 'Token & impersonation', he: 'טוקנים והתחזות', n: '101–150' },
  { key: 'check_uac', slug: 'uac_prevention', en: 'UAC bypass prevention', he: 'מניעת מעקף UAC', n: '151–200' },
  { key: 'check_service', slug: 'service_task_audit', en: 'Services & scheduled tasks', he: 'שירותים ומשימות', n: '201–250' },
  { key: 'check_kernel', slug: 'kernel_driver', en: 'Kernel / BYOVD', he: 'קרנל / BYOVD', n: '251–300' },
  { key: 'check_vault', slug: 'credential_vault', en: 'Credential vaults', he: 'כספות אישורים', n: '301–350' },
  { key: 'check_telemetry', slug: 'agent_telemetry', en: 'Agent telemetry guard', he: 'טלמטריית סוכן', n: '351–400' },
  { key: 'check_rls', slug: 'rls_partitioning', en: 'RLS / multi-tenant DB', he: 'RLS ורב-דיירות', n: '401–450' },
  { key: 'check_cicd', slug: 'zero_fabrication', en: 'Zero-fabrication CI', he: 'CI ללא זיוף', n: '451–500' },
]

const LABELS = {
  en: {
    title: 'Privilege Escalation & Credential Access',
    subtitle: '500-check live auditor — W^X, LSASS/identity-daemon, tokens, UAC prevention, service ACLs, BYOVD, credential vaults, telemetry, RLS, CI. Evidence only. Never dumps LSASS, never runs a UAC bypass, never ships Hell’s Gate stubs. Windows registry is Win32 in-process (never reg.exe).',
    badge: 'PAC-500 LIVE AUDIT',
    client: 'Client',
    selectClient: 'Select client…',
    selectClientFirst: 'Select a client first',
    target: 'Target (host / URL for remote Windows ports)',
    targetPh: 'dc01.corp.local  or  https://intranet.example',
    run: 'Run privilege & credential audit',
    scanning: 'Auditing…',
    queued: 'Audit queued',
    scanFailed: 'Audit failed',
    layers: 'Control domains (50 checks each)',
    checkRemote: 'Remote Windows privilege ports (445/135/3389/WinRM)',
    reset: 'Reset defaults',
    export: 'Export JSON',
    posture: 'Privilege / credential posture',
    grade: 'Grade',
    counts: 'Catalog coverage',
    findingsTitle: 'Failed controls',
    noFindings: 'No failed privilege/credential controls on this host — strong posture.',
    runToPopulate: 'Select a client and run the live 500-check audit.',
    related: 'Related identity engines',
    lastRun: 'Last completed',
    evaluated: 'evaluated',
    pass: 'pass',
    fail: 'fail',
    notObserved: 'not observed',
    host: 'Host',
    kernel: 'Kernel',
    notice: 'Defensive auditor — findings are configuration and memory-map evidence, not exploit output. Coverage including na/not_observed is stored under tenant RLS in one bulk UPSERT.',
  },
  he: {
    title: 'הסלמת הרשאות וגישה לאישורים',
    subtitle: 'מבקר חי של 500 בקרות. ראיות בלבד. לא דאמפ LSASS, לא מעקף UAC, לא Hell’s Gate. Registry ב-Windows נקרא ב-Win32 בתוך התהליך.',
    badge: 'PAC-500 ביקורת חיה',
    client: 'לקוח',
    selectClient: 'בחר לקוח…',
    selectClientFirst: 'בחר לקוח תחילה',
    target: 'יעד (מארח / URL לפורטי Windows מרוחקים)',
    targetPh: 'dc01.corp.local  או  https://intranet.example',
    run: 'הרץ ביקורת הרשאות ואישורים',
    scanning: 'מבקר…',
    queued: 'הביקורת בתור',
    scanFailed: 'הביקורת נכשלה',
    layers: 'תחומי בקרה (50 בדיקות לכל תחום)',
    checkRemote: 'פורטי הרשאות Windows מרוחקים',
    reset: 'איפוס',
    export: 'ייצוא JSON',
    posture: 'תנוחת הרשאות / אישורים',
    grade: 'ציון',
    counts: 'כיסוי הקטלוג',
    findingsTitle: 'בקרות שנכשלו',
    noFindings: 'לא נכשלו בקרות הרשאות/אישורים במארח זה — תנוחה חזקה.',
    runToPopulate: 'בחר לקוח והרץ את ביקורת 500 הבדיקות החיה.',
    related: 'מנועי זהות קשורים',
    lastRun: 'הושלם לאחרונה',
    evaluated: 'הוערכו',
    pass: 'עבר',
    fail: 'נכשל',
    notObserved: 'לא נצפה',
    host: 'מארח',
    kernel: 'קרנל',
    notice: 'מבקר הגנתי — הממצאים הם ראיות תצורה ומפות זיכרון, לא פלט ניצול.',
  },
}

const defaultParams = () => ({
  check_syscall: true,
  check_lsass: true,
  check_token: true,
  check_uac: true,
  check_service: true,
  check_kernel: true,
  check_vault: true,
  check_telemetry: true,
  check_rls: true,
  check_cicd: true,
  check_remote: true,
  max_findings: 200,
})

function sevWeight(s) {
  return ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 }[String(s || '').toLowerCase()] ?? 0)
}

function Toggle({ on, onClick, label, hint }) {
  return (
    <Button variant="unstyled" type="button" onClick={onClick} role="switch" aria-checked={on}
      className="flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-xs font-mono transition-all w-full text-left"
      style={{ borderColor: on ? `${ACCENT}50` : '#ffffff14', backgroundColor: on ? `${ACCENT}14` : 'transparent', color: on ? '#fecdd3' : '#ffffff55' }}>
      <span className="w-7 h-4 rounded-full relative transition-all shrink-0" style={{ backgroundColor: on ? ACCENT : '#ffffff20' }}>
        <span className="absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all" style={{ left: on ? '14px' : '2px' }} />
      </span>
      <span className="min-w-0">
        <span className="block truncate">{label}</span>
        {hint ? <span className="block text-[9px] text-[var(--text-disabled)]">{hint}</span> : null}
      </span>
    </Button>
  )
}

export default function PrivilegeEscalationCommandCenter() {
  const { i18n } = useTranslation()
  const he = i18n.language?.startsWith('he')
  const L = LABELS[he ? 'he' : 'en']

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
  const [toast, setToast] = useState(null)

  const set = (k, v) => setParams((p) => ({ ...p, [k]: v }))

  useEffect(() => {
    apiFetch('/api/clients').then((d) => { if (Array.isArray(d)) setClients(d) }).catch(() => {})
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
    body.max_findings = Number(params.max_findings) || 200
    DOMAINS.forEach((d) => { body[d.key] = params[d.key] ? 'true' : 'false' })
    body.check_remote = params.check_remote ? 'true' : 'false'
    return body
  }, [clientId, target, params])

  const hubScanParams = useMemo(() => {
    const { engine, target: _t, client_id, ...rest } = buildBody()
    return rest
  }, [buildBody])
  useSyncHubScanParams(ENGINE_ID, hubScanParams)

  const handleRun = useCallback(async () => {
    if (!clientId) { showToastMsg('error', L.selectClientFirst); return }
    if (!target.trim()) { showToastMsg('error', L.target); return }
    setStatus('running')
    setFindings([])
    try {
      const { ok, data: d } = await postScan(buildBody())
      if (!ok) { setStatus('error'); showToastMsg('error', d.detail || L.scanFailed); return }
      const jobId = d.job_id ?? ''
      showToastMsg('info', `${L.queued} · ${jobId}`)
      if (jobId) setPendingJobId(jobId)
      else setStatus('error')
    } catch (e) {
      setStatus('error')
      showToastMsg('error', e?.message ?? L.scanFailed)
    }
  }, [clientId, target, buildBody, showToastMsg, L, postScan])

  const handleExport = useCallback(() => {
    const payload = { engine: ENGINE_ID, exported_at: new Date().toISOString(), target, params, findings }
    downloadBytes(new TextEncoder().encode(JSON.stringify(payload, null, 2)), `pac500-${Date.now()}.json`, 'application/json')
  }, [target, params, findings])

  const { posture, regular } = useMemo(() => {
    const postureF = findings.find((f) => f.category === 'posture_summary') || null
    const regularF = findings
      .filter((f) => f.category !== 'posture_summary')
      .sort((a, b) => sevWeight(b.severity) - sevWeight(a.severity))
    return { posture: postureF, regular: regularF }
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

  const ev = posture?.evidence || {}
  const score = Number(ev.score ?? 0)
  const grade = ev.grade || '—'
  const covCounts = ev.counts || {}
  const domainScores = ev.domain_scores || {}
  const host = ev.host || {}
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
        <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${toast.sev === 'error' ? 'bg-rose-950/90 border-rose-500/40 text-rose-200' : 'bg-[var(--bg-1)] border-rose-500/30 text-rose-100'}`}>
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
        <Link to="/identity-security" className="text-[11px] font-mono text-rose-300/80 hover:text-rose-200 border border-rose-500/25 rounded-lg px-3 py-1.5">{L.related} →</Link>
      </div>

      <div className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-6 mb-6">
        <div className="flex items-start justify-between gap-4 mb-4">
          <div className="flex items-center gap-3">
            <span className="text-3xl">⛨</span>
            <div>
              <h2 className="text-lg font-bold text-white">{ENGINE_ID}</h2>
              <span className="text-[10px] font-mono text-[var(--text-disabled)] uppercase tracking-widest">MITRE T1068 · T1003 · T1134 · T1548.002</span>
            </div>
          </div>
          <div className="flex flex-col items-end gap-2 shrink-0">
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: statusColor, boxShadow: status === 'running' ? `0 0 6px ${ACCENT}` : 'none' }} />
              <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase">{status}</span>
            </div>
            <div className="flex gap-2">
              {findings.length > 0 && (
                <Button variant="unstyled" type="button" onClick={handleExport} className="px-3 py-2 rounded-xl font-mono text-xs border border-[var(--border-strong)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)]">
                  {L.export}
                </Button>
              )}
              <Button variant="unstyled" type="button" onClick={handleRun} disabled={status === 'running' || !clientId}
                className="px-5 py-2 rounded-xl font-mono text-sm border transition-all disabled:opacity-40"
                style={{ borderColor: `${ACCENT}50`, color: '#fecdd3', backgroundColor: `${ACCENT}18` }}>
                {status === 'running' ? L.scanning : L.run}
              </Button>
            </div>
          </div>
        </div>

        <p className="text-[11px] font-mono text-amber-200/70 mb-4 border border-amber-500/20 rounded-lg px-3 py-2 bg-amber-950/20">{L.notice}</p>

        <label className="block mb-4">
          <span className="text-[11px] font-mono text-[var(--text-muted)]">{L.target}</span>
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder={L.targetPh}
            className="mt-1 w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] font-mono focus:outline-none focus:border-rose-500/40" />
        </label>

        <span className="text-[11px] font-mono text-[var(--text-muted)] block mb-2">{L.layers}</span>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mb-3">
          {DOMAINS.map((d) => (
            <Toggle key={d.key} on={params[d.key]} onClick={() => set(d.key, !params[d.key])}
              label={he ? d.he : d.en} hint={d.n} />
          ))}
          <Toggle on={params.check_remote} onClick={() => set('check_remote', !params.check_remote)} label={L.checkRemote} hint="TCP" />
        </div>
        <div className="flex justify-end">
          <Button variant="unstyled" type="button" onClick={() => setParams(defaultParams())} className="text-[11px] font-mono text-[var(--text-muted)] hover:text-[var(--text-primary)]">{L.reset}</Button>
        </div>
      </div>

      {posture && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
          <div className="rounded-2xl border border-rose-500/25 bg-[var(--bg-2)] p-5 flex flex-col items-center justify-center">
            <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-disabled)] mb-2">{L.posture}</div>
            <div className="text-5xl font-black" style={{ color: score >= 80 ? ACCENT2 : ACCENT }}>{grade}</div>
            <div className="text-sm font-mono text-[var(--text-secondary)] mt-1">{score}/100</div>
            <div className="text-[10px] font-mono text-[var(--text-muted)] mt-2">{L.host}: {host.hostname || '—'} · {L.kernel}: {host.kernel || '—'}</div>
            {lastRun && <div className="text-[10px] font-mono text-[var(--text-disabled)] mt-1">{L.lastRun} {lastRun}</div>}
          </div>
          <div className="lg:col-span-2 rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] p-5">
            <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-disabled)] mb-3">{L.counts}</div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-4 text-center">
              {[
                [L.evaluated, covCounts.evaluated, ACCENT2],
                [L.pass, covCounts.pass, ACCENT2],
                [L.fail, covCounts.fail, ACCENT],
                [L.notObserved, covCounts.not_observed, '#64748b'],
              ].map(([lab, n, col]) => (
                <div key={lab} className="rounded-lg border border-[var(--border-subtle)] px-2 py-2">
                  <div className="text-lg font-mono font-bold" style={{ color: col }}>{n ?? 0}</div>
                  <div className="text-[10px] font-mono text-[var(--text-muted)]">{lab}</div>
                </div>
              ))}
            </div>
            <div className="space-y-1.5">
              {DOMAINS.map((d) => {
                const ds = domainScores[d.slug] || {}
                const sc = Number(ds.score ?? 0)
                return (
                  <div key={d.slug} className="flex items-center gap-2 text-[10px] font-mono">
                    <span className="w-40 truncate text-[var(--text-tertiary)]">{he ? d.he : d.en}</span>
                    <div className="flex-1 h-1.5 rounded-full bg-[var(--bg-3)] overflow-hidden">
                      <div className="h-full rounded-full" style={{ width: `${sc}%`, backgroundColor: sc >= 80 ? ACCENT2 : ACCENT }} />
                    </div>
                    <span className="w-16 text-right text-[var(--text-muted)]">{ds.fail ?? 0} fail</span>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}

      <WeissmanFindingsPanel
        title={L.findingsTitle}
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
        showEmptyReady={status !== 'running' && regular.length === 0 && findings.length === 0}
        emptyReadyTitle={L.runToPopulate}
        emptyReadyBody={L.runToPopulate}
        emptyTitle={L.noFindings}
        emptyBody={L.noFindings}
      />

      <div className="mt-6 flex flex-wrap gap-2 text-[11px] font-mono">
        <span className="text-[var(--text-disabled)]">{L.related}:</span>
        <Link to="/identity-security" className="text-rose-300/80 hover:text-rose-200">Identity & SSO</Link>
        <Link to="/kerberos-security" className="text-rose-300/80 hover:text-rose-200">Kerberos</Link>
        <Link to="/smb-netbios" className="text-rose-300/80 hover:text-rose-200">SMB / NetBIOS</Link>
        <Link to="/engines" className="text-rose-300/80 hover:text-rose-200">Engine matrix</Link>
      </div>
    </PageShell>
  )
}
