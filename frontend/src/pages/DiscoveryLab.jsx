/**
 * Discovery Lab — AI-assisted novel vulnerability discovery on authorized tenant
 * assets, plus a responsible-disclosure pack workflow.
 *
 * Candidates are distinct from the ordinary findings inbox. Runs dispatch
 * POST /api/discovery-lab/runs (fuzz_core + optional LLM hypotheses) and never
 * scan hosts outside the client's approved scope.
 *
 * Route: /discovery-lab
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { FlaskConical, Search } from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EmptyState from '../components/ui/EmptyState'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import FilterPills from '../components/ui/FilterPills'
import Button from '../components/ui/Button'
import { useToast } from '../components/ui/Toaster'
import { useClient } from '../context/ClientContext'
import { apiFetch } from '../utils/apiFetch'
import { firstClientTarget } from '../lib/clientTarget'
import { downloadCsv } from '../lib/exportFindingsCsv'

const NS = 'pages.discoveryLab'

const STATUS_FILTERS = [
  { id: 'all', status: '' },
  { id: 'candidate', status: 'candidate' },
  { id: 'validated', status: 'validated' },
  { id: 'remediation', status: 'customer_remediation' },
  { id: 'disclosure_ready', status: 'disclosure_ready' },
  { id: 'disclosed', status: 'disclosed' },
  { id: 'suppressed', status: 'suppressed' },
]

const RECIPIENT_KINDS = ['national_cert', 'government_cyber', 'vendor']

const IN_FLIGHT = new Set(['queued', 'running'])

function unwrapRun(payload) {
  if (!payload || typeof payload !== 'object') return null
  if (payload.run && typeof payload.run === 'object') return payload.run
  if (payload.id && (payload.status || payload.target_host || payload.target_url)) return payload
  return null
}

function unwrapCandidate(payload) {
  if (!payload || typeof payload !== 'object') return null
  if (payload.candidate && typeof payload.candidate === 'object') return payload.candidate
  if (payload.id && payload.status) return payload
  return null
}

function unwrapPack(payload) {
  if (!payload || typeof payload !== 'object') return null
  if (payload.pack && typeof payload.pack === 'object') return payload.pack
  if (payload.id && (payload.recipient_kind != null || payload.technical_summary !== undefined)) return payload
  return null
}

function pct(n) {
  if (n == null || Number.isNaN(Number(n))) return '—'
  return `${Math.round(Number(n) * 100)}%`
}

function candidateSeverity(row) {
  if (row.status === 'suppressed' || row.fp_routed) return 'info'
  const n = Number(row.novelty_score) || 0
  const c = Number(row.confidence) || 0
  if (n >= 0.7 && c >= 0.55) return 'high'
  if (n >= 0.5) return 'medium'
  return 'low'
}

function toFinding(row) {
  return {
    ...row,
    title: row.title,
    type: row.payload_class || row.anomaly_type || 'discovery_lab',
    description: row.technical_summary,
    remediation: row.recommended_fix,
    severity: candidateSeverity(row),
    resource: row.target_url,
  }
}

function exportCandidatesCsv(rows) {
  const header = [
    'id',
    'status',
    'title',
    'target_url',
    'payload_class',
    'anomaly_type',
    'novelty_score',
    'confidence',
    'fp_routed',
    'kev_listed',
  ]
  const body = rows.map((r) => [
    r.id,
    r.status,
    r.title,
    r.target_url,
    r.payload_class,
    r.anomaly_type,
    r.novelty_score,
    r.confidence,
    r.fp_routed ? 'yes' : 'no',
    r.kev_listed ? 'yes' : 'no',
  ])
  downloadCsv(body, header, 'weissman-discovery-lab-candidates')
}

function statusTone(status) {
  switch (status) {
    case 'validated':
    case 'disclosure_ready':
    case 'disclosed':
    case 'completed':
    case 'ready':
    case 'submitted':
      return 'text-emerald-300 border-emerald-500/30 bg-emerald-950/20'
    case 'candidate':
    case 'queued':
    case 'running':
    case 'draft':
      return 'text-amber-300 border-amber-400/30 bg-amber-950/15'
    case 'suppressed':
    case 'failed':
    case 'withdrawn':
      return 'text-rose-300 border-rose-500/30 bg-rose-950/20'
    default:
      return 'text-[var(--text-muted)] border-[var(--border-default)]'
  }
}

function StatusPill({ status }) {
  const { t } = useTranslation()
  if (!status) return null
  return (
    <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border ${statusTone(status)}`}>
      {t(`${NS}.status_${status}`)}
    </span>
  )
}

export default function DiscoveryLab() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const { clients, selectedClientId, setSelectedClientId, selectedClient } = useClient()

  const [clientId, setClientId] = useState(selectedClientId || selectedClient?.id || '')
  const [target, setTarget] = useState(() => firstClientTarget(selectedClient) || '')
  const [intensity, setIntensity] = useState('normal')
  const [runs, setRuns] = useState([])
  const [candidates, setCandidates] = useState([])
  const [packs, setPacks] = useState([])
  const [activeRunId, setActiveRunId] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [loading, setLoading] = useState(true)
  const [starting, setStarting] = useState(false)
  const [busyId, setBusyId] = useState('')
  const [error, setError] = useState('')
  const [selectedCandidate, setSelectedCandidate] = useState(null)
  const [selectedPack, setSelectedPack] = useState(null)
  const [events, setEvents] = useState([])
  const [packDraft, setPackDraft] = useState({
    recipient_kind: 'national_cert',
    recipient: '',
    timeline: '',
    recommended_fix: '',
    redact_payloads: true,
    redact_internal_hosts: true,
    redact_customer_ids: true,
  })

  useEffect(() => {
    if (!clientId) {
      const first = selectedClient || clients[0]
      if (first?.id) setClientId(first.id)
      return
    }
    if (target) return
    const c = clients.find((x) => String(x.id) === String(clientId)) || selectedClient
    const next = firstClientTarget(c)
    if (next) setTarget(next)
  }, [clients, selectedClient, clientId, target])

  const loadAll = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [runsRes, candRes, packRes] = await Promise.all([
        apiFetch('/api/discovery-lab/runs?limit=40'),
        apiFetch('/api/discovery-lab/candidates?limit=200'),
        apiFetch('/api/discovery-lab/disclosures?limit=80'),
      ])
      setRuns(Array.isArray(runsRes?.runs) ? runsRes.runs : [])
      setCandidates(Array.isArray(candRes?.candidates) ? candRes.candidates : [])
      setPacks(Array.isArray(packRes?.packs) ? packRes.packs : [])
    } catch (err) {
      setError(err.message || t(`${NS}.load_failed`))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadAll()
  }, [loadAll])

  const activeRun = runs.find((r) => r.id === activeRunId)
  const runStatus = activeRun?.status

  useEffect(() => {
    if (!activeRunId || !IN_FLIGHT.has(runStatus)) return undefined
    let cancelled = false
    const tick = async () => {
      try {
        const next = unwrapRun(await apiFetch(`/api/discovery-lab/runs/${encodeURIComponent(activeRunId)}`))
        if (cancelled || !next) return
        setRuns((prev) => [next, ...prev.filter((r) => r.id !== next.id)])
        if (!IN_FLIGHT.has(next.status)) {
          const candRes = await apiFetch('/api/discovery-lab/candidates?limit=200')
          if (!cancelled) {
            setCandidates(Array.isArray(candRes?.candidates) ? candRes.candidates : [])
          }
        }
      } catch {
        /* keep last known snapshot */
      }
    }
    const id = setInterval(tick, 2500)
    tick()
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [activeRunId, runStatus])

  const visibleCandidates = useMemo(() => {
    const chip = STATUS_FILTERS.find((f) => f.id === statusFilter)
    return candidates.filter((row) => {
      if (chip?.status && row.status !== chip.status) return false
      return true
    })
  }, [candidates, statusFilter])

  const findingRows = useMemo(() => visibleCandidates.map(toFinding), [visibleCandidates])

  const {
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    filteredFindings,
    exportCsv,
    counts,
    total,
  } = useFindingsWorkbench(findingRows, {
    csvPrefix: 'weissman-discovery-lab',
    haystackFn: (f) =>
      `${f.title || ''} ${f.description || ''} ${f.type || ''} ${f.resource || ''} ${f.status || ''} ${f.payload_class || ''} ${f.anomaly_type || ''}`,
  })

  const kpis = useMemo(() => {
    const novel = candidates.filter((c) => Number(c.novelty_score) >= 0.55 && c.status !== 'suppressed')
    const validated = candidates.filter((c) =>
      ['validated', 'customer_remediation', 'disclosure_ready', 'disclosed'].includes(c.status),
    )
    const fpRouted = candidates.filter((c) => c.fp_routed).length
    const ready = candidates.filter((c) => c.status === 'disclosure_ready' || c.status === 'disclosed')
    return {
      total: candidates.length,
      novel: novel.length,
      validated: validated.length,
      fpRouted,
      ready: ready.length,
    }
  }, [candidates])

  const filteredPacks = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    if (!q) return packs
    return packs.filter((p) =>
      [p.title, p.technical_summary, p.recipient, p.status, p.recipient_kind]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()
        .includes(q),
    )
  }, [packs, searchQuery])

  const startRun = async () => {
    if (!clientId || !String(target).trim()) {
      toast.error(t(`${NS}.target_required`))
      return
    }
    setStarting(true)
    try {
      const res = await apiFetch('/api/discovery-lab/runs', {
        method: 'POST',
        body: {
          client_id: Number(clientId) || clientId,
          target: String(target).trim(),
          intensity,
        },
      })
      let run = unwrapRun(res)
      if (!run && res?.run_id) {
        run = unwrapRun(await apiFetch(`/api/discovery-lab/runs/${encodeURIComponent(res.run_id)}`))
      }
      if (run?.id) {
        setActiveRunId(run.id)
        setRuns((prev) => [run, ...prev.filter((r) => r.id !== run.id)])
        toast.success(t(`${NS}.run_queued`))
      } else if (res?.run_id) {
        setActiveRunId(res.run_id)
        toast.success(t(`${NS}.run_queued`))
      }
    } catch (err) {
      toast.error(err.message || t(`${NS}.start_failed`))
    } finally {
      setStarting(false)
    }
  }

  const patchCandidate = async (id, action) => {
    setBusyId(id)
    try {
      const res = await apiFetch(`/api/discovery-lab/candidates/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: { action },
      })
      const next = unwrapCandidate(res)
      if (next) {
        setCandidates((prev) => prev.map((c) => (c.id === next.id ? next : c)))
        if (selectedCandidate?.id === next.id) setSelectedCandidate(next)
      }
      toast.success(t(`${NS}.action_${action}_ok`))
    } catch (err) {
      toast.error(err.message || t(`${NS}.action_failed`))
    } finally {
      setBusyId('')
    }
  }

  const openDisclosure = async (candidate) => {
    setBusyId(candidate.id)
    try {
      const res = await apiFetch(`/api/discovery-lab/candidates/${encodeURIComponent(candidate.id)}/disclosure`, {
        method: 'POST',
        body: {
          recipient_kind: packDraft.recipient_kind,
          recipient: packDraft.recipient || undefined,
          timeline: packDraft.timeline || undefined,
          recommended_fix: packDraft.recommended_fix || undefined,
          redact_payloads: packDraft.redact_payloads,
          redact_internal_hosts: packDraft.redact_internal_hosts,
          redact_customer_ids: packDraft.redact_customer_ids,
        },
      })
      const pack = unwrapPack(res)
      if (pack) {
        setPacks((prev) => [pack, ...prev.filter((p) => p.id !== pack.id)])
        setSelectedPack(pack)
        toast.success(t(`${NS}.pack_opened`))
      }
      const candRes = await apiFetch(`/api/discovery-lab/candidates/${encodeURIComponent(candidate.id)}`)
      const cand = unwrapCandidate(candRes)
      if (cand) {
        setCandidates((prev) => prev.map((c) => (c.id === cand.id ? cand : c)))
        setSelectedCandidate(cand)
      }
    } catch (err) {
      toast.error(err.message || t(`${NS}.pack_failed`))
    } finally {
      setBusyId('')
    }
  }

  const loadEvents = useCallback(async (packId) => {
    try {
      const res = await apiFetch(`/api/discovery-lab/disclosures/${encodeURIComponent(packId)}/events`)
      setEvents(Array.isArray(res?.events) ? res.events : [])
    } catch {
      setEvents([])
    }
  }, [])

  useEffect(() => {
    if (selectedPack?.id) loadEvents(selectedPack.id)
    else setEvents([])
  }, [selectedPack?.id, loadEvents])

  const patchPack = async (id, status) => {
    setBusyId(id)
    try {
      const res = await apiFetch(`/api/discovery-lab/disclosures/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: { status },
      })
      const pack = unwrapPack(res)
      if (pack) {
        setPacks((prev) => prev.map((p) => (p.id === pack.id ? pack : p)))
        setSelectedPack(pack)
        if (pack.candidate_id) {
          const candRes = await apiFetch(`/api/discovery-lab/candidates/${encodeURIComponent(pack.candidate_id)}`)
          const cand = unwrapCandidate(candRes)
          if (cand) setCandidates((prev) => prev.map((c) => (c.id === cand.id ? cand : c)))
        }
        await loadEvents(id)
      }
      toast.success(t(`${NS}.pack_${status}_ok`))
    } catch (err) {
      toast.error(err.message || t(`${NS}.action_failed`))
    } finally {
      setBusyId('')
    }
  }

  const exportPack = async (pack, format) => {
    try {
      const res = await apiFetch(
        `/api/discovery-lab/disclosures/${encodeURIComponent(pack.id)}/export?format=${encodeURIComponent(format)}`,
        { raw: true },
      )
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        throw new Error(err.detail || err.error || t(`${NS}.export_failed`))
      }
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const ext = format === 'markdown' ? 'md' : format
      a.download = `weissman-disclosure-${String(pack.id).slice(0, 8)}.${ext}`
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
      toast.success(t(`${NS}.export_ok`, { format }))
    } catch (err) {
      toast.error(err.message || t(`${NS}.export_failed`))
    }
  }

  const onClientChange = (id) => {
    setClientId(id)
    setSelectedClientId?.(id)
    const c = clients.find((x) => String(x.id) === String(id))
    setTarget(firstClientTarget(c) || '')
  }

  const approvedHint = selectedClient
    ? firstClientTarget(clients.find((c) => String(c.id) === String(clientId)) || selectedClient)
    : firstClientTarget(clients.find((c) => String(c.id) === String(clientId)))

  const handleExport = () => {
    if (filteredFindings.length) exportCsv()
    else exportCandidatesCsv(visibleCandidates)
  }

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#22d3ee"
      icon={<FlaskConical className="w-5 h-5 text-cyan-300" strokeWidth={1.75} />}
      evidence={t(`${NS}.evidence_notice`)}
      actions={
        <div className="flex items-center gap-2 flex-wrap">
          <Link
            to="/exploit-lab"
            className="text-[11px] font-mono px-2 py-1 rounded border border-cyan-500/35 text-cyan-300 hover:bg-cyan-500/10"
          >
            {t(`${NS}.link_exploit_lab`)}
          </Link>
          <ShellScanActions
            onRefresh={loadAll}
            onExport={handleExport}
            refreshLoading={loading}
            exportDisabled={!filteredFindings.length && !visibleCandidates.length}
          />
        </div>
      }
    >
      <div className="space-y-6" data-testid="discovery-lab-page">
        <p className="text-[11px] font-mono text-[var(--text-muted)] leading-relaxed">{t(`${NS}.scope_notice`)}</p>

        {error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
          <ExecutiveWidget label={t(`${NS}.kpi_candidates`)} value={kpis.total} accent="#22d3ee" />
          <ExecutiveWidget label={t(`${NS}.kpi_novel`)} value={kpis.novel} accent="#f59e0b" />
          <ExecutiveWidget label={t(`${NS}.kpi_validated`)} value={kpis.validated} accent="#34d399" />
          <ExecutiveWidget label={t(`${NS}.kpi_disclosure`)} value={kpis.ready} accent="#a78bfa" />
        </div>
        <p className="text-[11px] font-mono text-[var(--text-muted)]">{t(`${NS}.fp_routed_hint`, { count: kpis.fpRouted })}</p>

        <section className="rounded-2xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 space-y-4">
          <h2 className="text-[10px] font-mono uppercase tracking-widest text-cyan-300/80">{t(`${NS}.start_section`)}</h2>
          <div className="grid gap-3 md:grid-cols-3">
            <label className="text-[11px] font-mono text-[var(--text-muted)] space-y-1">
              <span>{t(`${NS}.client`)}</span>
              <select
                value={clientId}
                onChange={(e) => onClientChange(e.target.value)}
                className="w-full rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] px-2 py-2 text-sm text-[var(--text-primary)]"
              >
                {clients.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name || c.id}
                  </option>
                ))}
              </select>
            </label>
            <label className="text-[11px] font-mono text-[var(--text-muted)] space-y-1">
              <span>{t(`${NS}.target`)}</span>
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={t(`${NS}.target_placeholder`)}
                className="w-full rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] px-2 py-2 text-sm text-[var(--text-primary)]"
              />
            </label>
            <label className="text-[11px] font-mono text-[var(--text-muted)] space-y-1">
              <span>{t(`${NS}.intensity`)}</span>
              <select
                value={intensity}
                onChange={(e) => setIntensity(e.target.value)}
                className="w-full rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] px-2 py-2 text-sm text-[var(--text-primary)]"
              >
                <option value="light">{t(`${NS}.intensity_light`)}</option>
                <option value="normal">{t(`${NS}.intensity_normal`)}</option>
                <option value="aggressive">{t(`${NS}.intensity_aggressive`)}</option>
              </select>
            </label>
          </div>
          <p className="text-[11px] text-[var(--text-muted)]">
            {t(`${NS}.approved_hint`, { domains: approvedHint || t(`${NS}.no_approved_domains`) })}
          </p>
          <Button
            variant="primary"
            type="button"
            disabled={starting || !clientId}
            onClick={startRun}
            data-testid="discovery-lab-start"
          >
            {starting ? t(`${NS}.starting`) : t(`${NS}.start_run`)}
          </Button>
          {activeRun && (
            <p className="text-xs text-[var(--text-secondary)]">
              {t(`${NS}.active_run`, {
                status: activeRun.status,
                candidates: activeRun.candidates_count ?? 0,
                probes: activeRun.probes_sent ?? 0,
              })}
            </p>
          )}
        </section>

        <section className="space-y-3">
          <h2 className="text-[10px] font-mono uppercase tracking-widest text-cyan-300/80">{t(`${NS}.runs_section`)}</h2>
          {runs.length === 0 && !loading ? (
            <EmptyState icon="radar" title={t(`${NS}.no_runs`)} description={t(`${NS}.no_runs_hint`)} compact />
          ) : (
            <div className="overflow-x-auto rounded-xl border border-[var(--border-default)]">
              <table className="w-full text-xs">
                <thead className="bg-[var(--table-surface)]">
                  <tr>
                    <th className="px-3 py-2 font-mono text-start">{t(`${NS}.col_target`)}</th>
                    <th className="px-3 py-2 font-mono text-start">{t(`${NS}.col_status`)}</th>
                    <th className="px-3 py-2 font-mono text-start">{t(`${NS}.col_intensity`)}</th>
                    <th className="px-3 py-2 font-mono text-start">{t(`${NS}.col_candidates`)}</th>
                    <th className="px-3 py-2 font-mono text-start">{t(`${NS}.col_when`)}</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.map((run) => (
                    <tr
                      key={run.id}
                      className="border-t border-[var(--border-default)] cursor-pointer hover:bg-[var(--row-hover-bg)]"
                      onClick={() => setActiveRunId(run.id)}
                    >
                      <td className="px-3 py-2 font-mono">{run.target_host || run.target_url}</td>
                      <td className="px-3 py-2">
                        <StatusPill status={run.status} />
                      </td>
                      <td className="px-3 py-2">{run.intensity}</td>
                      <td className="px-3 py-2">
                        {run.candidates_count ?? 0}
                        {run.llm_used ? ` · ${t(`${NS}.llm_used`)}` : ''}
                      </td>
                      <td className="px-3 py-2 font-mono text-[var(--text-muted)]">
                        {run.created_at ? new Date(run.created_at).toLocaleString() : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <div className="relative max-w-md">
          <Search className="absolute start-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-disabled)] pointer-events-none" />
          <input
            type="search"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder={t(`${NS}.search_placeholder`)}
            className="w-full rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] ps-9 pe-3 py-2 text-sm text-[var(--text-primary)]"
          />
        </div>

        <FilterPills
          label={t(`${NS}.filter_label`)}
          pills={STATUS_FILTERS.map((f) => ({
            id: f.id,
            label: t(`${NS}.filter_${f.id}`),
            active: statusFilter === f.id,
            onClick: () => setStatusFilter(f.id),
          }))}
        />

        <WeissmanFindingsPanel
          title={t(`${NS}.candidates_section`)}
          findings={findingRows}
          filteredFindings={filteredFindings}
          counts={counts}
          total={total}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          severityFilter={severityFilter}
          onSeverityChange={setSeverityFilter}
          loading={loading}
          emptyTitle={t(`${NS}.no_candidates`)}
          emptyBody={t(`${NS}.no_candidates_hint`)}
          renderFinding={(row) => (
            <article
              key={row.id}
              data-testid={`discovery-candidate-${row.id}`}
              className="rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] p-3 space-y-2"
            >
              <div className="flex flex-wrap items-start justify-between gap-2">
                <button type="button" className="text-start" onClick={() => setSelectedCandidate(row)}>
                  <h3 className="text-sm font-semibold text-[var(--text-primary)]">{row.title}</h3>
                  <p className="text-[11px] font-mono text-[var(--text-muted)]">
                    {row.target_url} · {row.payload_class} · {row.anomaly_type || '—'}
                  </p>
                </button>
                <StatusPill status={row.status} />
              </div>
              <p className="text-xs text-[var(--text-secondary)]">{row.technical_summary}</p>
              <div className="flex flex-wrap gap-3 text-[11px] font-mono text-[var(--text-muted)]">
                <span>
                  {t(`${NS}.novelty`)}: {pct(row.novelty_score)}
                </span>
                <span>
                  {t(`${NS}.confidence`)}: {pct(row.confidence)}
                </span>
                {row.fp_routed ? <span>{t(`${NS}.fp_routed`)}</span> : null}
                {row.kev_listed ? <span>{t(`${NS}.kev`)}</span> : null}
              </div>
              <div className="flex flex-wrap gap-2">
                {row.status === 'candidate' && (
                  <>
                    <Button
                      variant="unstyled"
                      type="button"
                      data-testid={`discovery-validate-${row.id}`}
                      disabled={busyId === row.id}
                      onClick={() => patchCandidate(row.id, 'validate')}
                      className="rounded-md px-2 py-1 text-[11px] font-bold border border-emerald-500/40 text-emerald-300 hover:bg-emerald-900/20"
                    >
                      {t(`${NS}.validate`)}
                    </Button>
                    <Button
                      variant="unstyled"
                      type="button"
                      data-testid={`discovery-suppress-${row.id}`}
                      disabled={busyId === row.id}
                      onClick={() => patchCandidate(row.id, 'suppress')}
                      className="rounded-md px-2 py-1 text-[11px] font-bold border border-[var(--border-default)]"
                    >
                      {t(`${NS}.suppress`)}
                    </Button>
                  </>
                )}
                {row.status === 'validated' && (
                  <>
                    <Button
                      variant="unstyled"
                      type="button"
                      disabled={busyId === row.id}
                      onClick={() => patchCandidate(row.id, 'remediation')}
                      className="rounded-md px-2 py-1 text-[11px] font-bold border border-[var(--border-default)]"
                    >
                      {t(`${NS}.mark_remediation`)}
                    </Button>
                    <Button
                      variant="unstyled"
                      type="button"
                      data-testid={`discovery-open-disclosure-${row.id}`}
                      disabled={busyId === row.id}
                      onClick={() => openDisclosure(row)}
                      className="rounded-md px-2 py-1 text-[11px] font-bold border border-cyan-500/40 text-cyan-200"
                    >
                      {t(`${NS}.open_disclosure`)}
                    </Button>
                  </>
                )}
                {(row.status === 'customer_remediation' || row.status === 'disclosure_ready') && (
                  <Button
                    variant="unstyled"
                    type="button"
                    disabled={busyId === row.id}
                    onClick={() => openDisclosure(row)}
                    className="rounded-md px-2 py-1 text-[11px] font-bold border border-cyan-500/40 text-cyan-200"
                  >
                    {t(`${NS}.open_disclosure`)}
                  </Button>
                )}
              </div>
            </article>
          )}
        />

        {selectedCandidate && (
          <section className="rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4 space-y-3">
            <h2 className="text-sm font-semibold">{t(`${NS}.detail_title`)}</h2>
            <p className="text-xs whitespace-pre-wrap text-[var(--text-secondary)]">
              {selectedCandidate.evidence?.probe_url || selectedCandidate.technical_summary}
            </p>
            <div className="grid gap-3 md:grid-cols-2">
              <label className="text-[11px] font-mono space-y-1">
                <span>{t(`${NS}.recipient_kind`)}</span>
                <select
                  value={packDraft.recipient_kind}
                  onChange={(e) => setPackDraft((p) => ({ ...p, recipient_kind: e.target.value }))}
                  className="w-full rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] px-2 py-2 text-sm"
                >
                  {RECIPIENT_KINDS.map((id) => (
                    <option key={id} value={id}>
                      {t(`${NS}.recipient_${id}`)}
                    </option>
                  ))}
                </select>
              </label>
              <label className="text-[11px] font-mono space-y-1">
                <span>{t(`${NS}.recipient`)}</span>
                <input
                  value={packDraft.recipient}
                  onChange={(e) => setPackDraft((p) => ({ ...p, recipient: e.target.value }))}
                  placeholder={t(`${NS}.recipient_placeholder`)}
                  className="w-full rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] px-2 py-2 text-sm"
                />
              </label>
              <label className="text-[11px] font-mono space-y-1 md:col-span-2">
                <span>{t(`${NS}.timeline`)}</span>
                <textarea
                  value={packDraft.timeline}
                  onChange={(e) => setPackDraft((p) => ({ ...p, timeline: e.target.value }))}
                  rows={2}
                  className="w-full rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] px-2 py-2 text-sm"
                />
              </label>
              <label className="text-[11px] font-mono space-y-1 md:col-span-2">
                <span>{t(`${NS}.recommended_fix`)}</span>
                <textarea
                  value={packDraft.recommended_fix}
                  onChange={(e) => setPackDraft((p) => ({ ...p, recommended_fix: e.target.value }))}
                  rows={2}
                  className="w-full rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] px-2 py-2 text-sm"
                />
              </label>
            </div>
            <div className="flex flex-wrap gap-4 text-xs">
              <label className="inline-flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={packDraft.redact_payloads}
                  onChange={(e) => setPackDraft((p) => ({ ...p, redact_payloads: e.target.checked }))}
                />
                {t(`${NS}.redact_payloads`)}
              </label>
              <label className="inline-flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={packDraft.redact_internal_hosts}
                  onChange={(e) => setPackDraft((p) => ({ ...p, redact_internal_hosts: e.target.checked }))}
                />
                {t(`${NS}.redact_hosts`)}
              </label>
              <label className="inline-flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={packDraft.redact_customer_ids}
                  onChange={(e) => setPackDraft((p) => ({ ...p, redact_customer_ids: e.target.checked }))}
                />
                {t(`${NS}.redact_customer_ids`)}
              </label>
            </div>
          </section>
        )}

        <section className="space-y-3">
          <h2 className="text-[10px] font-mono uppercase tracking-widest text-cyan-300/80">{t(`${NS}.disclosure_section`)}</h2>
          {filteredPacks.length === 0 ? (
            <EmptyState icon="file" title={t(`${NS}.no_packs`)} description={t(`${NS}.no_packs_hint`)} compact />
          ) : (
            filteredPacks.map((pack) => (
              <article
                key={pack.id}
                data-testid={`discovery-pack-${pack.id}`}
                className="rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] p-3 space-y-2"
              >
                <div className="flex flex-wrap justify-between gap-2">
                  <button type="button" className="text-start" onClick={() => setSelectedPack(pack)}>
                    <h3 className="text-sm font-semibold">{pack.title}</h3>
                    <p className="text-[11px] font-mono text-[var(--text-muted)]">
                      {pack.recipient_kind} · {pack.recipient || '—'}
                    </p>
                  </button>
                  <StatusPill status={pack.status} />
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button variant="unstyled" type="button" onClick={() => exportPack(pack, 'markdown')} className="rounded-md border border-[var(--border-default)] px-2 py-1 text-[11px] font-bold">
                    {t(`${NS}.export_md`)}
                  </Button>
                  <Button variant="unstyled" type="button" onClick={() => exportPack(pack, 'json')} className="rounded-md border border-[var(--border-default)] px-2 py-1 text-[11px] font-bold">
                    {t(`${NS}.export_json`)}
                  </Button>
                  <Button variant="unstyled" type="button" onClick={() => exportPack(pack, 'pdf')} className="rounded-md border border-[var(--border-default)] px-2 py-1 text-[11px] font-bold">
                    {t(`${NS}.export_pdf`)}
                  </Button>
                  {pack.status === 'draft' && (
                    <Button variant="unstyled" type="button" disabled={busyId === pack.id} onClick={() => patchPack(pack.id, 'ready')} className="rounded-md px-2 py-1 text-[11px] font-bold border border-cyan-500/40 text-cyan-200">
                      {t(`${NS}.mark_ready`)}
                    </Button>
                  )}
                  {pack.status === 'ready' && (
                    <Button variant="unstyled" type="button" disabled={busyId === pack.id} onClick={() => patchPack(pack.id, 'submitted')} className="rounded-md px-2 py-1 text-[11px] font-bold border border-cyan-500/40 text-cyan-200">
                      {t(`${NS}.mark_submitted`)}
                    </Button>
                  )}
                  {pack.status === 'submitted' && (
                    <Button variant="unstyled" type="button" disabled={busyId === pack.id} onClick={() => patchPack(pack.id, 'disclosed')} className="rounded-md px-2 py-1 text-[11px] font-bold border border-cyan-500/40 text-cyan-200">
                      {t(`${NS}.mark_disclosed`)}
                    </Button>
                  )}
                </div>
              </article>
            ))
          )}
        </section>

        {selectedPack && events.length > 0 && (
          <section className="rounded-2xl border border-[var(--border-default)] p-4 space-y-2">
            <h2 className="text-sm font-semibold">{t(`${NS}.audit_log`)}</h2>
            <ul className="space-y-1 text-xs text-[var(--text-secondary)] font-mono">
              {events.map((ev) => (
                <li key={ev.id}>
                  {ev.occurred_at ? new Date(ev.occurred_at).toLocaleString() : '—'} · {ev.from_status || '∅'} → {ev.to_status} · {ev.action}
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    </PageShell>
  )
}
