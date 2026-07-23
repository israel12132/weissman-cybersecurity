import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { Search } from 'lucide-react'
import { TOP_TIER_ENGINE_IDS } from '../lib/topTierEngineProfiles'
import { ENGINES_BY_ID } from '../lib/enginesRegistry'
import { apiFetch } from '../utils/apiFetch'
import { openSseStream } from '../lib/sseStream'
import ShellScanActions from '../components/engine/ShellScanActions'
import EngineHubForensicHeader from '../components/engine/EngineHubForensicHeader'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import Button from '../components/ui/Button'

function badgeClass(kind) {
  if (kind === 'command_center_engine') return 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10'
  if (kind === 'poe_synthesis_run') return 'text-cyan-300 border-cyan-500/40 bg-cyan-500/10'
  return 'text-rose-300 border-rose-500/40 bg-rose-500/10'
}

export default function TopTierEngineHub() {
  const { t } = useTranslation()
  const [audit, setAudit] = useState(null)
  const [loading, setLoading] = useState(true)
  const [clients, setClients] = useState([])
  const [clientId, setClientId] = useState('')
  const [target, setTarget] = useState('')
  const [probeJobId, setProbeJobId] = useState('')
  const [probeRunning, setProbeRunning] = useState(false)
  const [probeSummary, setProbeSummary] = useState('')
  const [probeByEngine, setProbeByEngine] = useState({})
  const [engineSearch, setEngineSearch] = useState('')

  const reloadAudit = useCallback(async () => {
    setLoading(true)
    try {
      const d = await apiFetch('/api/engines/top-tier/audit')
      setAudit(d)
    } catch {
      // audit load failed — keep prior state
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    reloadAudit()
  }, [reloadAudit])

  useEffect(() => {
    let cancelled = false
    async function loadClients() {
      try {
        const d = await apiFetch('/api/clients')
        if (!cancelled && Array.isArray(d)) setClients(d)
      } catch {
        // clients load failed — leave list unchanged
      }
    }
    loadClients()
    return () => {
      cancelled = true
    }
  }, [])

  const auditById = useMemo(() => {
    const rows = Array.isArray(audit?.engines) ? audit.engines : []
    return Object.fromEntries(rows.map((r) => [r.engine_id, r]))
  }, [audit])

  useEffect(() => {
    if (!probeJobId) return undefined
    const es = openSseStream(`/api/telemetry/stream?job_id=${encodeURIComponent(probeJobId)}`)
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data || '{}')
        if (data.job_id !== probeJobId) return
        if (data.engine_id) {
          setProbeByEngine((prev) => ({
            ...prev,
            [data.engine_id]: {
              status: data.probe_status || 'pending',
              message: data.message || '',
              duration_ms: data.duration_ms || 0,
              findings_count: data.findings_count || 0,
            },
          }))
        }
        if (typeof data.message === 'string' && data.message) setProbeSummary(data.message)
        if (data.status === 'completed' || data.status === 'failed') {
          setProbeRunning(false)
          es.close()
        }
      } catch {
        // ignore non-JSON telemetry records
      }
    }
    es.onerror = () => {
      es.close()
    }
    return () => {
      es.close()
    }
  }, [probeJobId])

  useEffect(() => {
    if (!probeRunning || !probeJobId) return undefined
    let cancelled = false
    const iv = setInterval(async () => {
      const d = await apiFetch(`/api/jobs/${encodeURIComponent(probeJobId)}`).catch(() => null)
      if (cancelled || !d) return
      if (d.status === 'completed' || d.status === 'failed' || d.status === 'dead') {
        setProbeRunning(false)
      }
      const entries = d?.result?.engines
      if (Array.isArray(entries)) {
        setProbeByEngine((prev) => {
          const next = { ...prev }
          for (const entry of entries) {
            const id = entry?.engine_id
            if (!id) continue
            next[id] = {
              status: entry?.probe_status || 'pending',
              message: entry?.message || '',
              duration_ms: entry?.duration_ms || 0,
              findings_count: entry?.findings_count || 0,
            }
          }
          return next
        })
      }
    }, 2000)
    return () => { cancelled = true; clearInterval(iv) }
  }, [probeJobId, probeRunning])

  async function startHealthProbe() {
    setProbeSummary(t('pages.topTierEngineHub.queueing'))
    setProbeByEngine({})
    const payload = {}
    if (clientId) payload.client_id = Number(clientId)
    if (target.trim()) payload.target = target.trim()
    try {
      const d = await apiFetch('/api/engines/top-tier/health-probe', {
        method: 'POST',
        body: payload,
      })
      setProbeJobId(d.job_id || '')
      setProbeRunning(true)
      setProbeSummary(t('pages.topTierEngineHub.probe_queued', { jobId: d.job_id || 'unknown' }))
    } catch (e) {
      const body = e?.response ? await e.response.json().catch(() => ({})) : {}
      setProbeSummary(body.detail || t('pages.topTierEngineHub.probe_failed', { status: e?.status ?? '' }))
      setProbeRunning(false)
    }
  }

  const filteredEngineIds = useMemo(() => {
    const q = engineSearch.trim().toLowerCase()
    if (!q) return TOP_TIER_ENGINE_IDS
    return TOP_TIER_ENGINE_IDS.filter((id) => {
      const engine = ENGINES_BY_ID[id]
      const row = auditById[id]
      const hay = `${id} ${engine?.label || ''} ${engine?.description || ''} ${row?.execution_path || ''} ${row?.canonical_engine || ''}`.toLowerCase()
      return hay.includes(q)
    })
  }, [engineSearch, auditById])

  function exportAuditCsv() {
    const rows = Array.isArray(audit?.engines) ? audit.engines : []
    const header = ['engine_id', 'label', 'execution_path', 'canonical_engine', 'is_production_runnable', 'known_in_catalog']
    const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`
    const lines = [
      header.join(','),
      ...rows.map((r) => {
        const engine = ENGINES_BY_ID[r.engine_id]
        return [
          r.engine_id,
          engine?.label || '',
          r.execution_path || '',
          r.canonical_engine || '',
          r.is_production_runnable ? 'yes' : 'no',
          r.known_in_catalog ? 'yes' : 'no',
        ].map(esc).join(',')
      }),
    ]
    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `top-tier-audit-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  function probeBadge(status) {
    if (status === 'pass') return 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10'
    if (status === 'fail') return 'text-rose-300 border-rose-500/40 bg-rose-500/10'
    if (status === 'pending') return 'text-amber-300 border-amber-500/40 bg-amber-500/10'
    return 'text-[var(--text-tertiary)] border-[var(--border-strong)] bg-[var(--row-hover-bg)]'
  }

  return (
    <div className="min-h-[100dvh] text-[var(--text-secondary)]" style={{ background: 'var(--shell-bg)' }}>
      <header className="sticky top-0 z-20 border-b border-[var(--border-default)] bg-[var(--bg-3)] backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <Link to="/engines" className="text-[var(--text-muted)] hover:text-[var(--text-secondary)] text-xs font-mono transition-colors">{t('pages.topTierEngineHub.back_matrix')}</Link>
            <span className="text-[var(--text-disabled)] text-xs">|</span>
            <h1 className="text-sm font-bold tracking-tight text-white">{t('pages.topTierEngineHub.title')}</h1>
          </div>
          <div className="flex items-center gap-3">
            <ShellScanActions
              onRefresh={reloadAudit}
              onExport={exportAuditCsv}
              refreshLoading={loading}
              exportDisabled={loading || !audit?.engines?.length}
            />
            <div className="text-[11px] font-mono text-[var(--text-tertiary)]">
            {loading
              ? t('pages.topTierEngineHub.auditing')
              : t('pages.topTierEngineHub.connected', {
                  connected: audit?.connected_count ?? 0,
                  total: audit?.top_tier_count ?? TOP_TIER_ENGINE_IDS.length,
                })}
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        <EngineHubForensicHeader evidence={t('pages.topTierEngineHub.evidence_notice')} />

        <section className="rounded-2xl border border-[var(--border-default)] bg-[var(--table-surface)] p-5">
          <h2 className="text-sm font-semibold text-white mb-2">{t('pages.topTierEngineHub.reality_heading')}</h2>
          <p className="text-sm text-[var(--text-tertiary)] leading-relaxed">
            {t('pages.topTierEngineHub.reality_body')}
          </p>
          <div className="mt-4 grid grid-cols-1 md:grid-cols-4 gap-3">
            <select
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)]"
            >
              <option value="">{t('pages.topTierEngineHub.client_optional')}</option>
              {clients.map((c) => (
                <option key={c.id} value={c.id}>{c.name}</option>
              ))}
            </select>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={t('pages.topTierEngineHub.target_placeholder')}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-sm text-[var(--text-primary)] md:col-span-2"
            />
            <Button variant="unstyled"
              type="button"
              onClick={startHealthProbe}
              disabled={probeRunning}
              className="rounded-lg px-3 py-2 text-sm font-mono border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10 disabled:opacity-50"
            >
              {probeRunning ? t('pages.topTierEngineHub.running_probe') : t('pages.topTierEngineHub.run_health_probe')}
            </Button>
          </div>
          {probeSummary && <div className="mt-3 text-xs font-mono text-[var(--text-tertiary)]">{probeSummary}</div>}
        </section>

        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[200px] max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--text-disabled)] pointer-events-none" />
            <input
              type="search"
              value={engineSearch}
              onChange={(e) => setEngineSearch(e.target.value)}
              aria-label={t('pages.topTierEngineHub.search_placeholder')}
              placeholder={t('pages.topTierEngineHub.search_placeholder')}
              className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg pl-10 pr-3 py-2 text-sm text-[var(--text-primary)] font-mono placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500/40"
            />
          </div>
          <span className="text-[11px] font-mono text-[var(--text-muted)]">
            {t('pages.topTierEngineHub.showing_count', { count: filteredEngineIds.length, total: TOP_TIER_ENGINE_IDS.length })}
          </span>
        </div>

        {loading ? (
          <SkeletonWidgetGrid count={6} />
        ) : (
        <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filteredEngineIds.length === 0 ? (
            <div className="col-span-full rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-6 text-sm text-[var(--text-tertiary)] text-center">
              {t('pages.topTierEngineHub.no_search_results')}
            </div>
          ) : filteredEngineIds.map((id, idx) => {
            const engine = ENGINES_BY_ID[id]
            const row = auditById[id]
            const path = row?.execution_path || 'unknown'
            const probe = probeByEngine[id] || null
            return (
              <article key={id} className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4 space-y-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="text-[11px] font-mono text-[var(--text-muted)]">{t('pages.topTierEngineHub.top_tier_num', { num: idx + 1 })}</div>
                    <h3 className="text-base font-semibold text-white">{engine?.label || id}</h3>
                    <div className="text-[11px] font-mono text-[var(--text-muted)]">{id}</div>
                  </div>
                  <span className={`px-2 py-1 rounded border text-[10px] font-mono uppercase tracking-wider ${badgeClass(path)}`}>
                    {path}
                  </span>
                </div>

                <p className="text-sm text-[var(--text-tertiary)] min-h-[40px]">{engine?.description || t('pages.topTierEngineHub.no_description')}</p>

                <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-[var(--text-tertiary)]">
                  <div className="rounded border border-[var(--border-default)] bg-[var(--table-surface)] p-2">
                    <div className="text-[var(--text-muted)]">{t('pages.topTierEngineHub.canonical_label')}</div>
                    <div>{row?.canonical_engine || '-'}</div>
                  </div>
                  <div className="rounded border border-[var(--border-default)] bg-[var(--table-surface)] p-2">
                    <div className="text-[var(--text-muted)]">{t('pages.topTierEngineHub.production_label')}</div>
                    <div>{row?.is_production_runnable ? t('common.yes') : t('common.no')}</div>
                  </div>
                </div>

                <div className="flex items-center gap-2 text-[11px] font-mono">
                  <span className={`px-2 py-1 rounded border uppercase tracking-wider ${probeBadge(probe?.status || 'pending')}`}>
                    {t('pages.topTierEngineHub.probe_label', { status: probe?.status || 'pending' })}
                  </span>
                  {probe && (
                    <span className="text-[var(--text-tertiary)]">
                      {t('pages.topTierEngineHub.findings_duration', {
                        count: probe.findings_count,
                        ms: probe.duration_ms,
                      })}
                    </span>
                  )}
                </div>
                {probe?.message && <div className="text-[11px] text-[var(--text-tertiary)]">{probe.message}</div>}

                <div className="flex items-center gap-2">
                  <Link
                    to={`/engines/top-tier/${id}`}
                    className="px-3 py-1.5 rounded-lg text-xs font-mono border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/10 transition-colors"
                  >
                    {t('pages.topTierEngineHub.open_dedicated')}
                  </Link>
                  <Link
                    to={`/engines/${id}`}
                    className="px-3 py-1.5 rounded-lg text-xs font-mono border border-[var(--border-strong)] text-[var(--text-secondary)] hover:bg-[var(--row-hover-bg)] transition-colors"
                  >
                    {t('pages.topTierEngineHub.open_engine_detail')}
                  </Link>
                </div>
              </article>
            )
          })}
        </section>
        )}
      </main>
    </div>
  )
}
