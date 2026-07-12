import { firstClientTarget } from '../lib/clientTarget'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../lib/apiBase'
import { ENGINES_BY_ID } from '../lib/enginesRegistry'
import { strategicEnginesNeedingDedicatedPage } from '../lib/strategicEngineProgram'
import { buildSimpleTextPdf, downloadBytes } from '../lib/pdfExport'
import AgentRequiredGate from '../components/engine/AgentRequiredGate'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'

import EngineHubForensicHeader from '../components/engine/EngineHubForensicHeader'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import { buildScanPayload, normalizeIntegrations } from '../lib/engineClientPrefill'
import { useEngineScanParams } from '../hooks/useEngineScanParams'
import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useSyncHubScanParams } from '../hooks/useLaunchEngineScan'
import EngineScanParamsPanel from '../components/engine/EngineScanParamsPanel'
import { BarChart, Bar, ResponsiveContainer, XAxis, YAxis, Tooltip, LineChart, Line, CartesianGrid } from 'recharts'
import Button from '../components/ui/Button'

const TARGET_REQUIRED_IDS = new Set(['osint', 'asm', 'k8s_container', 'scada_ics', 'semantic_ai_fuzz', 'ai_adversarial_redteam'])

const BUSINESS_ENGINE_DEFS = {
  osint: { requiresTarget: true, samplePayload: { engine: 'osint', max_results: 250 } },
  asm: { requiresTarget: true, samplePayload: { engine: 'asm', include_ports: true, depth: 'enterprise' } },
  leak_hunter: { requiresTarget: false, samplePayload: { engine: 'leak_hunter', mode: 'deep', include_darkweb: true } },
  supply_chain: { requiresTarget: false, samplePayload: { engine: 'supply_chain', depth: 'full', include_sbom: true } },
  semantic_ai_fuzz: { requiresTarget: true, samplePayload: { engine: 'semantic_ai_fuzz', depth: 'enterprise' } },
  ai_adversarial_redteam: { requiresTarget: true, samplePayload: { engine: 'ai_adversarial_redteam', mode: 'full' } },
  k8s_container: { requiresTarget: true, samplePayload: { engine: 'k8s_container', include_rbac: true, depth: 'enterprise' } },
  scada_ics: { requiresTarget: true, samplePayload: { engine: 'scada_ics', mode: 'passive', safety_context: true } },
}

for (const row of strategicEnginesNeedingDedicatedPage()) {
  if (!row.route.startsWith('/engines/business/') || BUSINESS_ENGINE_DEFS[row.id]) continue
  BUSINESS_ENGINE_DEFS[row.id] = {
    requiresTarget: TARGET_REQUIRED_IDS.has(row.id),
    samplePayload: { engine: row.id },
  }
}


function JsonView({ value }) {
  return (
    <pre className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-3)] p-3 text-[12px] text-emerald-300 overflow-auto font-mono">
      {JSON.stringify(value, null, 2)}
    </pre>
  )
}

function engineTitle(engineId, reg, t) {
  const key = `pages.businessEngineProfile.engines.${engineId}.title`
  const translated = t(key)
  if (translated && translated !== key) return translated
  return `${reg?.label || engineId} Page`
}

function engineMission(engineId, rowReason, t) {
  const key = `pages.businessEngineProfile.engines.${engineId}.mission`
  const translated = t(key)
  if (translated && translated !== key) return translated
  return rowReason || ''
}

export default function BusinessEngineProfile() {
  const { t } = useTranslation()
  const { engineId } = useParams()
  const def = BUSINESS_ENGINE_DEFS[engineId]
  const reg = ENGINES_BY_ID[engineId]
  const strategicRow = strategicEnginesNeedingDedicatedPage().find((r) => r.id === engineId)

  const [history, setHistory] = useState(null)
  const [profileLoading, setProfileLoading] = useState(false)
  const [clients, setClients] = useState([])
  const [clientId, setClientId] = useState('')
  const [target, setTarget] = useState('')
  const [runState, setRunState] = useState({ running: false, msg: '' })
  const [activeJobId, setActiveJobId] = useState('')
  const [liveJob, setLiveJob] = useState(null)
  const [clientIntegrations, setClientIntegrations] = useState(null)
  const { schema: paramSchema, extraParams, setParam } = useEngineScanParams(engineId, clientIntegrations)
  useSyncHubScanParams(engineId, extraParams)
  const { postScan } = useCommandCenterScan(clientId)

  const title = engineTitle(engineId, reg, t)
  const mission = engineMission(engineId, strategicRow?.reason, t)

  const jobs = Array.isArray(history?.jobs) ? history.jobs : []
  const findings = Array.isArray(history?.findings) ? history.findings : []

  const reloadProfile = useCallback(async () => {
    if (!def) return
    setProfileLoading(true)
    try {
      const r = await apiFetch(`/api/engines/history/${encodeURIComponent(engineId)}?limit=100`)
      const d = await r.json().catch(() => null)
      if (r.ok) setHistory(d)
    } finally {
      setProfileLoading(false)
    }
  }, [engineId, def])

  useEffect(() => {
    reloadProfile()
  }, [reloadProfile])

  useEffect(() => {
    let cancelled = false
    async function loadClients() {
      const r = await apiFetch('/api/clients')
      const d = await r.json().catch(() => [])
      if (!cancelled && r.ok && Array.isArray(d)) setClients(d)
    }
    loadClients()
    return () => { cancelled = true }
  }, [])

  useEffect(() => {
    if (!clientId) {
      setClientIntegrations(null)
      return
    }
    let cancelled = false
    ;(async () => {
      const r = await apiFetch(`/api/clients/${clientId}/integrations`)
      const d = r.ok ? await r.json() : null
      if (cancelled) return
      setClientIntegrations(normalizeIntegrations(d))
    })()
    return () => { cancelled = true }
  }, [clientId])

  useEffect(() => {
    if (!activeJobId) return undefined
    let cancelled = false
    const iv = setInterval(async () => {
      const r = await apiFetch(`/api/jobs/${encodeURIComponent(activeJobId)}`)
      const d = await r.json().catch(() => null)
      if (cancelled || !r.ok || !d) return
      setLiveJob(d)
      const status = String(d.status || '').toLowerCase()
      if (status === 'completed' || status === 'failed' || status === 'dead') {
        setRunState((prev) => ({ ...prev, running: false }))
      }
    }, 2000)
    return () => { cancelled = true; clearInterval(iv) }
  }, [activeJobId])

  const effectivePayload = useMemo(() => {
    const selectedClient = clients.find((c) => String(c.id) === String(clientId))
    const fallbackTarget = firstClientTarget(selectedClient)
    return buildScanPayload(engineId, {
      clientId,
      target: target.trim() || fallbackTarget,
      integrations: clientIntegrations,
      samplePayload: def?.samplePayload || {},
      extraParams,
    })
  }, [def, engineId, clientId, target, clients, clientIntegrations, extraParams])

  const statusData = useMemo(() => {
    const tally = { completed: 0, running: 0, failed: 0, pending: 0, dead: 0 }
    for (const j of jobs) {
      const key = String(j?.status || '').toLowerCase()
      if (Object.prototype.hasOwnProperty.call(tally, key)) tally[key] += 1
    }
    return Object.entries(tally).map(([name, value]) => ({ name, value }))
  }, [jobs])

  const findingsData = useMemo(() => {
    return jobs.slice(0, 12).map((j, idx) => ({
      run: `#${jobs.length - idx}`,
      findings: Number(j?.findings_count || 0),
    })).reverse()
  }, [jobs])

  const kpi = useMemo(() => {
    const completed = jobs.filter((j) => String(j?.status || '').toLowerCase() === 'completed').length
    const failed = jobs.filter((j) => {
      const s = String(j?.status || '').toLowerCase()
      return s === 'failed' || s === 'dead'
    }).length
    return { jobs: jobs.length, findings: findings.length, completed, failed }
  }, [jobs, findings])

  const listFindings = useMemo(() => [
    ...jobs.map((j) => ({
      id: j.job_id || j.id,
      severity: String(j.status || '').toLowerCase() === 'failed' ? 'high' : 'info',
      title: j.kind || j.source || 'job',
      type: 'job',
      description: String(j.status || ''),
      resource: String(j.findings_count ?? 0),
    })),
    ...findings.map((f) => ({
      id: f.id,
      severity: f.severity || 'medium',
      title: f.title || 'finding',
      type: 'finding',
      description: f.source || '',
      resource: f.discovered_at || '',
    })),
  ], [jobs, findings])

  const {
    searchQuery,
    setSearchQuery,
    filteredFindings,
  } = useFindingsWorkbench(listFindings, {
    csvPrefix: `weissman-business-${engineId}`,
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const visibleJobs = useMemo(() => {
    if (!searchQuery.trim()) return jobs.slice(0, 20)
    const jobIds = new Set(filteredFindings.filter((f) => f.type === 'job').map((f) => String(f.id)))
    return jobs.filter((j) => jobIds.has(String(j.job_id || j.id))).slice(0, 20)
  }, [jobs, filteredFindings, searchQuery])

  const visibleFindings = useMemo(() => {
    if (!searchQuery.trim()) return findings.slice(0, 20)
    const fids = new Set(filteredFindings.filter((f) => f.type === 'finding').map((f) => String(f.id)))
    return findings.filter((f) => fids.has(String(f.id))).slice(0, 20)
  }, [findings, filteredFindings, searchQuery])

  async function queueRun() {
    if (!def) return
    if (def.requiresTarget && !effectivePayload.target) {
      setRunState({ running: false, msg: t('pages.businessEngineProfile.target_required_error') })
      return
    }
    setRunState({ running: true, msg: t('pages.businessEngineProfile.queueing') })
    const { ok, data: d, status } = await postScan(effectivePayload)
    if (!ok) {
      setRunState({ running: false, msg: t('pages.businessEngineProfile.queue_failed', { status }) })
      return
    }
    setActiveJobId(d.job_id || '')
    setLiveJob(null)
    setRunState({ running: true, msg: t('pages.businessEngineProfile.queued_job', { jobId: d.job_id || 'unknown' }) })
  }

  async function exportJson() {
    const r = await apiFetch(`/api/engines/export/${encodeURIComponent(engineId)}?limit=140${activeJobId ? `&job_id=${encodeURIComponent(activeJobId)}` : ''}`)
    const d = await r.json().catch(() => null)
    if (!r.ok || !d) {
      setRunState((prev) => ({ ...prev, msg: t('pages.businessEngineProfile.export_failed', { status: r.status }) }))
      return
    }
    const bytes = new TextEncoder().encode(JSON.stringify(d, null, 2))
    downloadBytes(bytes, `${engineId}-business-export.json`, 'application/json')
  }

  function exportPdf() {
    const lines = []
    lines.push(`${t('pages.businessEngineProfile.pdf_business_engine')}: ${reg?.label || engineId} (${engineId})`)
    lines.push(`${t('pages.businessEngineProfile.pdf_generated')}: ${new Date().toISOString()}`)
    lines.push(`${t('pages.businessEngineProfile.pdf_jobs_tracked')}: ${jobs.length}`)
    lines.push(`${t('pages.businessEngineProfile.pdf_findings_tracked')}: ${findings.length}`)
    lines.push('')
    lines.push(t('pages.businessEngineProfile.pdf_mission_heading'))
    lines.push(mission)
    lines.push('')
    lines.push(t('pages.businessEngineProfile.recent_jobs'))
    for (const j of jobs.slice(0, 12)) {
      lines.push(`${j?.created_at || '-'} | ${j?.status || '-'} | findings=${j?.findings_count || 0} | source=${j?.source || '-'}`)
    }
    lines.push('')
    lines.push(t('pages.businessEngineProfile.live_findings'))
    for (const f of findings.slice(0, 20)) {
      lines.push(`${f?.discovered_at || '-'} | ${f?.severity || '-'} | ${f?.title || '-'}`)
    }
    if (liveJob?.id) {
      lines.push('')
      lines.push(`${t('pages.businessEngineProfile.pdf_active_job')}: ${liveJob.id}`)
      lines.push(`${t('common.status')}: ${liveJob.status || '-'}`)
    }
    const bytes = buildSimpleTextPdf(lines)
    downloadBytes(bytes, `${engineId}-business-export.pdf`, 'application/pdf')
  }

  if (!def) {
    return (
      <div className="min-h-[100dvh] flex flex-col items-center justify-center bg-[var(--bg-0)] text-[var(--text-tertiary)] p-8">
        <div className="text-red-400 mb-3">{t('pages.businessEngineProfile.not_configured', { engineId })}</div>
        <Link to="/engines/strategic" className="text-cyan-400 hover:underline">{t('pages.businessEngineProfile.open_strategic')}</Link>
      </div>
    )
  }

  return (
    <div className="min-h-[100dvh] text-[var(--text-secondary)]" style={{ background: 'var(--shell-bg)' }}>
      <header className="sticky top-0 z-20 border-b border-[var(--border-default)] bg-[var(--bg-3)] backdrop-blur-md">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center gap-3">
          <Link to="/engines/strategic" className="text-[var(--text-muted)] hover:text-[var(--text-secondary)] text-xs font-mono">{t('pages.businessEngineProfile.back_strategic')}</Link>
          <span className="text-[var(--text-disabled)] text-xs">|</span>
          <Link to={`/engines/${engineId}`} className="text-cyan-400/80 hover:text-cyan-300 text-xs font-mono">{t('pages.businessEngineProfile.engine_detail')}</Link>
          <span className="text-[var(--text-disabled)] text-xs">|</span>
          <h1 className="text-sm font-bold tracking-tight text-white">{title}</h1>
          <div className="ms-auto">
            <ShellScanActions
              onRefresh={reloadProfile}
              onExport={exportJson}
              refreshLoading={profileLoading}
            />
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-6 space-y-6">
        <AgentRequiredGate engineId={engineId}>
        <EngineHubForensicHeader
          evidence={t('pages.businessEngineProfile.evidence_notice')}
          engineId={engineId}
        />

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <ExecutiveWidget label={t('pages.businessEngineProfile.kpi_jobs')} value={kpi.jobs.toLocaleString()} accent="#22d3ee" />
          <ExecutiveWidget label={t('pages.businessEngineProfile.kpi_findings')} value={kpi.findings.toLocaleString()} accent="#a78bfa" />
          <ExecutiveWidget label={t('pages.businessEngineProfile.kpi_completed')} value={kpi.completed.toLocaleString()} accent="#34d399" />
          <ExecutiveWidget label={t('pages.businessEngineProfile.kpi_failed')} value={kpi.failed.toLocaleString()} accent="#f87171" />
        </div>

        <section className="rounded-2xl border border-[var(--border-default)] bg-[var(--table-surface)] p-5 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="px-2 py-0.5 rounded border border-[var(--border-strong)] text-[11px] font-mono text-[var(--text-secondary)]">{engineId}</span>
            {reg?.mitre && <span className="px-2 py-0.5 rounded border border-cyan-500/30 text-[11px] font-mono text-cyan-300">MITRE {reg.mitre}</span>}
            <span className="px-2 py-0.5 rounded border border-emerald-500/30 text-[11px] font-mono text-emerald-300">{t('pages.businessEngineProfile.dedicated_badge')}</span>
          </div>
          <p className="text-lg font-semibold text-white">{mission}</p>
          <p className="text-sm text-[var(--text-tertiary)]">{t('pages.businessEngineProfile.ops_desc')}</p>
        </section>

        <section className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4 space-y-3">
          <h2 className="text-sm font-semibold text-white">{t('pages.businessEngineProfile.run_heading')}</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <select
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)]"
            >
              <option value="">{t('pages.businessEngineProfile.select_client')}</option>
              {clients.map((c) => (
                <option key={c.id} value={c.id}>{c.name}</option>
              ))}
            </select>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={def.requiresTarget ? t('pages.businessEngineProfile.target_required_placeholder') : t('pages.businessEngineProfile.target_optional_placeholder')}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)]"
            />
            <Button variant="unstyled"
              type="button"
              onClick={queueRun}
              disabled={runState.running}
              className="rounded-lg px-3 py-2 text-sm font-mono border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10 disabled:opacity-50"
            >
              {runState.running ? t('pages.businessEngineProfile.running') : t('pages.businessEngineProfile.queue_scan')}
            </Button>
          </div>
          {paramSchema.length > 0 && (
            <EngineScanParamsPanel
              engineId={engineId}
              schema={paramSchema}
              values={extraParams}
              onChange={setParam}
              clientId={clientId}
              disabled={runState.running}
            />
          )}
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="unstyled" type="button" onClick={exportJson} className="rounded-lg px-3 py-1.5 text-xs font-mono border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/10">{t('pages.businessEngineProfile.export_json')}</Button>
            <Button variant="unstyled" type="button" onClick={exportPdf} className="rounded-lg px-3 py-1.5 text-xs font-mono border border-amber-500/40 text-amber-300 hover:bg-amber-500/10">{t('pages.businessEngineProfile.export_pdf')}</Button>
            <span className="text-xs font-mono text-[var(--text-tertiary)]">{runState.msg || t('pages.businessEngineProfile.ready')}</span>
          </div>
          {liveJob && (
            <div className="text-xs font-mono text-[var(--text-tertiary)] rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] p-2">
              {t('pages.businessEngineProfile.live_job_status', { jobId: liveJob.id || activeJobId, status: liveJob.status || '-' })}
            </div>
          )}
        </section>

        <section className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <article className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4 h-[280px]">
            <h3 className="text-sm font-semibold text-white mb-2">{t('pages.businessEngineProfile.job_status_dist')}</h3>
            <ResponsiveContainer width="100%" height="90%">
              <BarChart accessibilityLayer data={statusData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.15)" />
                <XAxis dataKey="name" stroke="#94a3b8" />
                <YAxis stroke="#94a3b8" allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#020617', border: '1px solid rgba(148,163,184,0.2)', color: '#e2e8f0' }} />
                <Bar dataKey="value" fill="#34d399" />
              </BarChart>
            </ResponsiveContainer>
          </article>
          <article className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4 h-[280px]">
            <h3 className="text-sm font-semibold text-white mb-2">{t('pages.businessEngineProfile.findings_trend')}</h3>
            <ResponsiveContainer width="100%" height="90%">
              <LineChart accessibilityLayer data={findingsData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.15)" />
                <XAxis dataKey="run" stroke="#94a3b8" />
                <YAxis stroke="#94a3b8" allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#020617', border: '1px solid rgba(148,163,184,0.2)', color: '#e2e8f0' }} />
                <Line type="monotone" dataKey="findings" stroke="#60a5fa" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </article>
        </section>

        <WeissmanListToolbar
          className="mb-2"
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          searchPlaceholder={t('pages.businessEngineProfile.search_placeholder')}
          resultCount={filteredFindings.length}
          totalCount={listFindings.length}
        />

        <section className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <article className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
            <h3 className="text-sm font-semibold text-white mb-2">{t('pages.businessEngineProfile.recent_jobs')}</h3>
            <div className="space-y-2 max-h-[280px] overflow-auto pr-1">
              {visibleJobs.map((j) => (
                <div key={`${j.job_id}-${j.created_at}`} className="text-xs rounded border border-[var(--border-default)] bg-[var(--table-surface)] p-2 text-[var(--text-secondary)] font-mono">
                  <div>{j.created_at || '-'} | {j.status || '-'} | findings={j.findings_count || 0}</div>
                  <div className="text-[var(--text-muted)]">kind={j.kind || '-'} source={j.source || '-'}</div>
                </div>
              ))}
              {!jobs.length && <div className="text-xs text-[var(--text-muted)]">{t('pages.businessEngineProfile.no_jobs')}</div>}
              {jobs.length > 0 && !visibleJobs.length && searchQuery.trim() && (
                <div className="text-xs text-[var(--text-muted)]">{t('weissmanFindings.filtered_title')}</div>
              )}
            </div>
          </article>
          <article className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
            <h3 className="text-sm font-semibold text-white mb-2">{t('pages.businessEngineProfile.live_findings')}</h3>
            <div className="space-y-2 max-h-[280px] overflow-auto pr-1">
              {visibleFindings.map((f) => (
                <div key={`${f.id}-${f.discovered_at}`} className="text-xs rounded border border-[var(--border-default)] bg-[var(--table-surface)] p-2 text-[var(--text-secondary)]">
                  <div className="font-medium text-white">{f.title || t('pages.businessEngineProfile.finding_fallback')}</div>
                  <div className="font-mono text-[var(--text-muted)]">{f.discovered_at || '-'} | {f.severity || '-'} | {f.source || '-'}</div>
                </div>
              ))}
              {!findings.length && <div className="text-xs text-[var(--text-muted)]">{t('pages.businessEngineProfile.no_findings')}</div>}
              {findings.length > 0 && !visibleFindings.length && searchQuery.trim() && (
                <div className="text-xs text-[var(--text-muted)]">{t('weissmanFindings.filtered_title')}</div>
              )}
            </div>
          </article>
        </section>

        <section className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
          <h3 className="text-sm font-semibold text-white mb-2">{t('pages.businessEngineProfile.effective_payload')}</h3>
          <JsonView value={effectivePayload} />
        </section>
        </AgentRequiredGate>
      </main>
    </div>
  )
}
