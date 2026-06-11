import React, { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../lib/apiBase'
import { ENGINES_BY_ID } from '../lib/enginesRegistry'
import { strategicEnginesNeedingDedicatedPage } from '../lib/strategicEngineProgram'
import { buildSimpleTextPdf, downloadBytes } from '../lib/pdfExport'
import { BarChart, Bar, ResponsiveContainer, XAxis, YAxis, Tooltip, LineChart, Line, CartesianGrid } from 'recharts'

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

function firstClientTarget(client) {
  if (!client) return ''
  let domains = client.domains
  if (typeof domains === 'string') {
    try { domains = JSON.parse(domains) } catch { domains = [] }
  }
  const first = Array.isArray(domains) ? domains.find((d) => typeof d === 'string' && d.trim()) : ''
  if (!first) return ''
  return first.startsWith('http://') || first.startsWith('https://') ? first : `https://${first}`
}

function JsonView({ value }) {
  return (
    <pre className="rounded-xl border border-white/10 bg-black/70 p-3 text-[12px] text-emerald-300 overflow-auto font-mono">
      {JSON.stringify(value, null, 2)}
    </pre>
  )
}

function engineTitle(engineId, reg, t) {
  const key = `pages.businessEngineProfile.engines.${engineId}.title`
  const translated = t(key, { defaultValue: '' })
  if (translated && translated !== key) return translated
  return `${reg?.label || engineId} Page`
}

function engineMission(engineId, rowReason, t) {
  const key = `pages.businessEngineProfile.engines.${engineId}.mission`
  const translated = t(key, { defaultValue: '' })
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
  const [clients, setClients] = useState([])
  const [clientId, setClientId] = useState('')
  const [target, setTarget] = useState('')
  const [runState, setRunState] = useState({ running: false, msg: '' })
  const [activeJobId, setActiveJobId] = useState('')
  const [liveJob, setLiveJob] = useState(null)

  const title = engineTitle(engineId, reg, t)
  const mission = engineMission(engineId, strategicRow?.reason, t)

  const jobs = Array.isArray(history?.jobs) ? history.jobs : []
  const findings = Array.isArray(history?.findings) ? history.findings : []

  useEffect(() => {
    let cancelled = false
    async function loadHistory() {
      const r = await apiFetch(`/api/engines/history/${encodeURIComponent(engineId)}?limit=100`)
      const d = await r.json().catch(() => null)
      if (!cancelled && r.ok) setHistory(d)
    }
    if (def) loadHistory()
    return () => { cancelled = true }
  }, [engineId, def])

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
    if (!activeJobId) return undefined
    const iv = setInterval(async () => {
      const r = await apiFetch(`/api/jobs/${encodeURIComponent(activeJobId)}`)
      const d = await r.json().catch(() => null)
      if (!r.ok || !d) return
      setLiveJob(d)
      const status = String(d.status || '').toLowerCase()
      if (status === 'completed' || status === 'failed' || status === 'dead') {
        setRunState((prev) => ({ ...prev, running: false }))
      }
    }, 2000)
    return () => clearInterval(iv)
  }, [activeJobId])

  const effectivePayload = useMemo(() => {
    const payload = { ...(def?.samplePayload || {}), engine: engineId }
    if (clientId) payload.client_id = Number(clientId)
    const selectedClient = clients.find((c) => String(c.id) === String(clientId))
    const fallbackTarget = firstClientTarget(selectedClient)
    if (target.trim()) payload.target = target.trim()
    else if (fallbackTarget) payload.target = fallbackTarget
    return payload
  }, [def, engineId, clientId, target, clients])

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

  async function queueRun() {
    if (!def) return
    if (def.requiresTarget && !target.trim()) {
      setRunState({ running: false, msg: t('pages.businessEngineProfile.target_required_error') })
      return
    }
    setRunState({ running: true, msg: t('pages.businessEngineProfile.queueing') })
    const r = await apiFetch('/api/command-center/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(effectivePayload),
    })
    const d = await r.json().catch(() => ({}))
    if (!r.ok) {
      setRunState({ running: false, msg: t('pages.businessEngineProfile.queue_failed', { status: r.status }) })
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
      <div className="min-h-[100dvh] flex flex-col items-center justify-center bg-[#030712] text-slate-300 p-8">
        <div className="text-red-400 mb-3">{t('pages.businessEngineProfile.not_configured', { engineId })}</div>
        <Link to="/engines/strategic" className="text-cyan-400 hover:underline">{t('pages.businessEngineProfile.open_strategic')}</Link>
      </div>
    )
  }

  return (
    <div className="min-h-[100dvh] text-slate-100" style={{ background: 'radial-gradient(ellipse 120% 78% at 50% 0%, #1f2937 0%, #020617 55%, #000 100%)' }}>
      <header className="sticky top-0 z-20 border-b border-white/10 bg-black/55 backdrop-blur-md">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center gap-3">
          <Link to="/engines/strategic" className="text-white/40 hover:text-white/70 text-xs font-mono">{t('pages.businessEngineProfile.back_strategic')}</Link>
          <span className="text-white/20 text-xs">|</span>
          <Link to={`/engines/${engineId}`} className="text-cyan-400/80 hover:text-cyan-300 text-xs font-mono">{t('pages.businessEngineProfile.engine_detail')}</Link>
          <span className="text-white/20 text-xs">|</span>
          <h1 className="text-sm font-bold tracking-tight text-white">{title}</h1>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-6 space-y-6">
        <section className="rounded-2xl border border-white/10 bg-black/35 p-5 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="px-2 py-0.5 rounded border border-white/20 text-[11px] font-mono text-white/70">{engineId}</span>
            {reg?.mitre && <span className="px-2 py-0.5 rounded border border-cyan-500/30 text-[11px] font-mono text-cyan-300">MITRE {reg.mitre}</span>}
            <span className="px-2 py-0.5 rounded border border-emerald-500/30 text-[11px] font-mono text-emerald-300">{t('pages.businessEngineProfile.dedicated_badge')}</span>
          </div>
          <p className="text-lg font-semibold text-white">{mission}</p>
          <p className="text-sm text-white/60">{t('pages.businessEngineProfile.ops_desc')}</p>
        </section>

        <section className="rounded-xl border border-white/10 bg-black/40 p-4 space-y-3">
          <h2 className="text-sm font-semibold text-white">{t('pages.businessEngineProfile.run_heading')}</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <select
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              className="bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90"
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
              className="bg-black/60 border border-white/10 rounded-lg px-3 py-2 text-sm text-white/90"
            />
            <button
              type="button"
              onClick={queueRun}
              disabled={runState.running}
              className="rounded-lg px-3 py-2 text-sm font-mono border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10 disabled:opacity-50"
            >
              {runState.running ? t('pages.businessEngineProfile.running') : t('pages.businessEngineProfile.queue_scan')}
            </button>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={exportJson} className="rounded-lg px-3 py-1.5 text-xs font-mono border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/10">{t('pages.businessEngineProfile.export_json')}</button>
            <button type="button" onClick={exportPdf} className="rounded-lg px-3 py-1.5 text-xs font-mono border border-amber-500/40 text-amber-300 hover:bg-amber-500/10">{t('pages.businessEngineProfile.export_pdf')}</button>
            <span className="text-xs font-mono text-white/55">{runState.msg || t('pages.businessEngineProfile.ready')}</span>
          </div>
          {liveJob && (
            <div className="text-xs font-mono text-white/65 rounded-lg border border-white/10 bg-black/45 p-2">
              {t('pages.businessEngineProfile.live_job_status', { jobId: liveJob.id || activeJobId, status: liveJob.status || '-' })}
            </div>
          )}
        </section>

        <section className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <article className="rounded-xl border border-white/10 bg-black/40 p-4 h-[280px]">
            <h3 className="text-sm font-semibold text-white mb-2">{t('pages.businessEngineProfile.job_status_dist')}</h3>
            <ResponsiveContainer width="100%" height="90%">
              <BarChart data={statusData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.15)" />
                <XAxis dataKey="name" stroke="#94a3b8" />
                <YAxis stroke="#94a3b8" allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#020617', border: '1px solid rgba(148,163,184,0.2)', color: '#e2e8f0' }} />
                <Bar dataKey="value" fill="#34d399" />
              </BarChart>
            </ResponsiveContainer>
          </article>
          <article className="rounded-xl border border-white/10 bg-black/40 p-4 h-[280px]">
            <h3 className="text-sm font-semibold text-white mb-2">{t('pages.businessEngineProfile.findings_trend')}</h3>
            <ResponsiveContainer width="100%" height="90%">
              <LineChart data={findingsData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.15)" />
                <XAxis dataKey="run" stroke="#94a3b8" />
                <YAxis stroke="#94a3b8" allowDecimals={false} />
                <Tooltip contentStyle={{ background: '#020617', border: '1px solid rgba(148,163,184,0.2)', color: '#e2e8f0' }} />
                <Line type="monotone" dataKey="findings" stroke="#60a5fa" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </article>
        </section>

        <section className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <article className="rounded-xl border border-white/10 bg-black/40 p-4">
            <h3 className="text-sm font-semibold text-white mb-2">{t('pages.businessEngineProfile.recent_jobs')}</h3>
            <div className="space-y-2 max-h-[280px] overflow-auto pr-1">
              {jobs.slice(0, 20).map((j) => (
                <div key={`${j.job_id}-${j.created_at}`} className="text-xs rounded border border-white/10 bg-black/45 p-2 text-white/70 font-mono">
                  <div>{j.created_at || '-'} | {j.status || '-'} | findings={j.findings_count || 0}</div>
                  <div className="text-white/45">kind={j.kind || '-'} source={j.source || '-'}</div>
                </div>
              ))}
              {!jobs.length && <div className="text-xs text-white/45">{t('pages.businessEngineProfile.no_jobs')}</div>}
            </div>
          </article>
          <article className="rounded-xl border border-white/10 bg-black/40 p-4">
            <h3 className="text-sm font-semibold text-white mb-2">{t('pages.businessEngineProfile.live_findings')}</h3>
            <div className="space-y-2 max-h-[280px] overflow-auto pr-1">
              {findings.slice(0, 20).map((f) => (
                <div key={`${f.id}-${f.discovered_at}`} className="text-xs rounded border border-white/10 bg-black/45 p-2 text-white/70">
                  <div className="font-medium text-white">{f.title || t('pages.businessEngineProfile.finding_fallback')}</div>
                  <div className="font-mono text-white/45">{f.discovered_at || '-'} | {f.severity || '-'} | {f.source || '-'}</div>
                </div>
              ))}
              {!findings.length && <div className="text-xs text-white/45">{t('pages.businessEngineProfile.no_findings')}</div>}
            </div>
          </article>
        </section>

        <section className="rounded-xl border border-white/10 bg-black/40 p-4">
          <h3 className="text-sm font-semibold text-white mb-2">{t('pages.businessEngineProfile.effective_payload')}</h3>
          <JsonView value={effectivePayload} />
        </section>
      </main>
    </div>
  )
}
