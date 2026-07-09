/**
 * Incident Response Center
 *
 * World-class IR management: active incidents, automated playbooks,
 * real-time timelines, containment / eradication actions, MTTR metrics.
 * Route: /incident-response
 */
import React, { useState, useCallback, useEffect, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import { Download } from 'lucide-react'
import { apiFetch } from '../lib/apiBase'
import EmptyState from '../components/ui/EmptyState'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import { SkeletonWidgetGrid, SkeletonCard } from '../components/ui/Skeleton'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { usePageAutoRefresh } from '../hooks/usePageAutoRefresh'
import { computeSla, slaBand, SLA_BAND_COLOR, slaCountdownLabel } from '../lib/incidentSla'

const NS = 'pages.incidentResponseCenter'

/**
 * Ticking clock for live SLA countdowns. Updates on a coarse interval
 * (minute-granularity display doesn't need per-second churn) and pauses when
 * the tab is hidden to avoid needless re-renders.
 */
function useNow(intervalMs = 30_000) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const tick = () => {
      if (document.visibilityState === 'visible') setNow(Date.now())
    }
    const id = setInterval(tick, intervalMs)
    const onVis = () => { if (document.visibilityState === 'visible') setNow(Date.now()) }
    document.addEventListener('visibilitychange', onVis)
    return () => {
      clearInterval(id)
      document.removeEventListener('visibilitychange', onVis)
    }
  }, [intervalMs])
  return now
}

/** Compact SLA countdown pill, colored by band. */
function SlaBadge({ incident, now, t, showLabel = true }) {
  const sla = computeSla(incident, now)
  if (sla.unknown) return null
  const band = slaBand(sla)
  const color = SLA_BAND_COLOR[band]
  return (
    <span
      className="inline-flex items-center gap-1 text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-wider"
      style={{ color, borderColor: `${color}40`, background: `${color}10` }}
      title={t(`${NS}.sla_tooltip`)}
    >
      {band === 'breached' && !sla.resolved ? '⚠ ' : ''}
      {showLabel ? t(`${NS}.sla_prefix`) + ' ' : ''}
      {slaCountdownLabel(sla, t)}
    </span>
  )
}

// ─── Constants ────────────────────────────────────────────────────────────────

const SEVERITY_COLOR = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22d3ee',
  info: '#6b7280',
}

const PLAYBOOKS = {
  ransomware: {
    labelKey: 'pages.incidentResponseCenter.playbooks.ransomware.label',
    steps: [
      { id: 1, phaseKey: 'detection', actionKey: 'pages.incidentResponseCenter.playbooks.ransomware.step_1', mitre: 'T1486' },
      { id: 2, phaseKey: 'detection', actionKey: 'pages.incidentResponseCenter.playbooks.ransomware.step_2', mitre: 'T1055' },
      { id: 3, phaseKey: 'containment', actionKey: 'pages.incidentResponseCenter.playbooks.ransomware.step_3', mitre: 'T1071' },
      { id: 4, phaseKey: 'containment', actionKey: 'pages.incidentResponseCenter.playbooks.ransomware.step_4', mitre: 'T1021.002' },
      { id: 5, phaseKey: 'eradication', actionKey: 'pages.incidentResponseCenter.playbooks.ransomware.step_5', mitre: 'T1485' },
      { id: 6, phaseKey: 'recovery', actionKey: 'pages.incidentResponseCenter.playbooks.ransomware.step_6', mitre: null },
      { id: 7, phaseKey: 'recovery', actionKey: 'pages.incidentResponseCenter.playbooks.ransomware.step_7', mitre: null },
      { id: 8, phaseKey: 'lessons_learned', actionKey: 'pages.incidentResponseCenter.playbooks.ransomware.step_8', mitre: null },
    ],
  },
  credential_stuffing: {
    labelKey: 'pages.incidentResponseCenter.playbooks.credential_stuffing.label',
    steps: [
      { id: 1, phaseKey: 'detection', actionKey: 'pages.incidentResponseCenter.playbooks.credential_stuffing.step_1', mitre: 'T1110' },
      { id: 2, phaseKey: 'containment', actionKey: 'pages.incidentResponseCenter.playbooks.credential_stuffing.step_2', mitre: 'T1110.004' },
      { id: 3, phaseKey: 'containment', actionKey: 'pages.incidentResponseCenter.playbooks.credential_stuffing.step_3', mitre: null },
      { id: 4, phaseKey: 'eradication', actionKey: 'pages.incidentResponseCenter.playbooks.credential_stuffing.step_4', mitre: null },
      { id: 5, phaseKey: 'eradication', actionKey: 'pages.incidentResponseCenter.playbooks.credential_stuffing.step_5', mitre: null },
      { id: 6, phaseKey: 'recovery', actionKey: 'pages.incidentResponseCenter.playbooks.credential_stuffing.step_6', mitre: null },
      { id: 7, phaseKey: 'lessons_learned', actionKey: 'pages.incidentResponseCenter.playbooks.credential_stuffing.step_7', mitre: null },
    ],
  },
  supply_chain: {
    labelKey: 'pages.incidentResponseCenter.playbooks.supply_chain.label',
    steps: [
      { id: 1, phaseKey: 'detection', actionKey: 'pages.incidentResponseCenter.playbooks.supply_chain.step_1', mitre: 'T1195.001' },
      { id: 2, phaseKey: 'containment', actionKey: 'pages.incidentResponseCenter.playbooks.supply_chain.step_2', mitre: null },
      { id: 3, phaseKey: 'eradication', actionKey: 'pages.incidentResponseCenter.playbooks.supply_chain.step_3', mitre: null },
      { id: 4, phaseKey: 'eradication', actionKey: 'pages.incidentResponseCenter.playbooks.supply_chain.step_4', mitre: 'T1552' },
      { id: 5, phaseKey: 'recovery', actionKey: 'pages.incidentResponseCenter.playbooks.supply_chain.step_5', mitre: null },
      { id: 6, phaseKey: 'lessons_learned', actionKey: 'pages.incidentResponseCenter.playbooks.supply_chain.step_6', mitre: null },
    ],
  },
  zero_day: {
    labelKey: 'pages.incidentResponseCenter.playbooks.zero_day.label',
    steps: [
      { id: 1, phaseKey: 'detection', actionKey: 'pages.incidentResponseCenter.playbooks.zero_day.step_1', mitre: 'T1190' },
      { id: 2, phaseKey: 'containment', actionKey: 'pages.incidentResponseCenter.playbooks.zero_day.step_2', mitre: null },
      { id: 3, phaseKey: 'containment', actionKey: 'pages.incidentResponseCenter.playbooks.zero_day.step_3', mitre: null },
      { id: 4, phaseKey: 'eradication', actionKey: 'pages.incidentResponseCenter.playbooks.zero_day.step_4', mitre: null },
      { id: 5, phaseKey: 'recovery', actionKey: 'pages.incidentResponseCenter.playbooks.zero_day.step_5', mitre: null },
      { id: 6, phaseKey: 'recovery', actionKey: 'pages.incidentResponseCenter.playbooks.zero_day.step_6', mitre: null },
      { id: 7, phaseKey: 'lessons_learned', actionKey: 'pages.incidentResponseCenter.playbooks.zero_day.step_7', mitre: null },
    ],
  },
}

const PHASE_COLOR = {
  detection: '#ef4444',
  containment: '#f97316',
  eradication: '#f59e0b',
  recovery: '#22d3ee',
  lessons_learned: '#8b5cf6',
}

const STATUS_META = {
  active:      { labelKey: 'pages.incidentResponseCenter.status_active',      color: '#ef4444' },
  containment: { labelKey: 'pages.incidentResponseCenter.status_containment', color: '#f97316' },
  eradication: { labelKey: 'pages.incidentResponseCenter.status_eradication', color: '#f59e0b' },
  resolved:    { labelKey: 'pages.incidentResponseCenter.status_resolved',    color: '#22d3ee' },
}

function severityLabel(severity, t) {
  const s = String(severity ?? 'high').toLowerCase()
  return t(`${NS}.severity_${s}`)
}

function durationHuman(created, updated, t) {
  const ms = new Date(updated) - new Date(created)
  const h = Math.floor(ms / 3_600_000)
  const m = Math.floor((ms % 3_600_000) / 60_000)
  if (h > 0) return t(`${NS}.duration_hours_minutes`, { hours: h, minutes: m })
  return t(`${NS}.duration_minutes`, { minutes: m })
}

function exportIncidentsCsv(incidents) {
  const header = ['id', 'title', 'severity', 'status', 'assignee', 'source', 'created', 'updated']
  const rows = incidents.map((inc) => [
    inc.id,
    (inc.title || '').replace(/"/g, '""'),
    inc.severity,
    inc.status,
    (inc.assignee || '').replace(/"/g, '""'),
    inc.source,
    inc.created,
    inc.updated,
  ])
  const csv = [header.join(','), ...rows.map((r) => r.map((c) => `"${c}"`).join(','))].join('\n')
  const blob = new Blob([csv], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `incidents-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

function normalizeIncident(raw, t) {
  return {
    id: raw.id ?? '',
    title: raw.title ?? t(`${NS}.untitled_incident`),
    severity: String(raw.severity ?? 'high').toLowerCase(),
    status: String(raw.status ?? 'active').toLowerCase(),
    assignee: raw.assignee ?? t(`${NS}.default_assignee`),
    created: raw.created ?? new Date().toISOString(),
    updated: raw.updated ?? raw.created ?? new Date().toISOString(),
    source: raw.source ?? '—',
    affectedAssets: Array.isArray(raw.affectedAssets) ? raw.affectedAssets : [],
    mitre: raw.mitre ?? null,
    description: raw.description ?? '',
    playbook: raw.playbook ?? 'credential_stuffing',
    playbookStepsDone: Array.isArray(raw.playbookStepsDone) ? raw.playbookStepsDone : [],
    timeline: Array.isArray(raw.timeline) ? raw.timeline : [],
  }
}

function mergePlaybookSteps(playbookId, doneIds) {
  const pb = PLAYBOOKS[playbookId]
  if (!pb) return []
  const doneSet = new Set(doneIds)
  return pb.steps.map((s) => ({ ...s, done: doneSet.has(s.id) }))
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function MetricCard({ label, value, sub, color, icon }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-xl bg-[var(--bg-2)] backdrop-blur border border-[var(--border-subtle)] p-4 flex flex-col gap-1"
    >
      <div className="flex items-center gap-2">
        {icon && <span className="text-lg">{icon}</span>}
        <span className="text-[10px] font-mono uppercase tracking-widest" style={{ color: `${color}99` }}>{label}</span>
      </div>
      <div className="text-3xl font-bold font-mono" style={{ color }}>{value}</div>
      {sub && <div className="text-[10px] text-[var(--text-disabled)] font-mono">{sub}</div>}
    </motion.div>
  )
}

function IncidentRow({ incident, selected, onSelect, t, now }) {
  const sm = STATUS_META[incident.status] ?? { labelKey: null, color: '#6b7280' }
  const sc = SEVERITY_COLOR[incident.severity] ?? '#6b7280'
  const statusLabel = sm.labelKey ? t(sm.labelKey) : incident.status.toUpperCase()
  return (
    <motion.button
      type="button"
      layout
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      onClick={() => onSelect(incident.id)}
      className="w-full text-left rounded-xl border p-4 transition-all hover:scale-[1.005]"
      style={{
        borderColor: selected ? `${sc}50` : 'rgba(255,255,255,0.07)',
        background: selected ? `${sc}08` : 'rgba(0,0,0,0.3)',
      }}
    >
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap mb-0.5">
            <span className="text-[10px] font-mono text-[var(--text-muted)]">{incident.id}</span>
            <span
              className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest"
              style={{ color: sm.color, borderColor: `${sm.color}40`, background: `${sm.color}10` }}
            >
              {statusLabel}
            </span>
            <span
              className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest"
              style={{ color: sc, borderColor: `${sc}40`, background: `${sc}10` }}
            >
              {severityLabel(incident.severity, t)}
            </span>
            <SlaBadge incident={incident} now={now} t={t} showLabel={false} />
          </div>
          <p className="text-xs font-semibold text-[var(--text-primary)] leading-snug">{incident.title}</p>
        </div>
        <div className="shrink-0 text-right">
          <div className="text-[10px] font-mono text-[var(--text-disabled)]">{incident.source}</div>
          <div className="text-[10px] font-mono text-[var(--text-disabled)]">{durationHuman(incident.created, incident.updated, t)}</div>
        </div>
      </div>
      <div className="flex flex-wrap gap-1">
        {incident.affectedAssets.map((a) => (
          <span key={a} className="text-[9px] font-mono px-1.5 py-0.5 bg-[var(--row-hover-bg)] border border-[var(--border-default)] rounded text-[var(--text-muted)]">
            {a}
          </span>
        ))}
      </div>
    </motion.button>
  )
}

function Timeline({ events }) {
  return (
    <div className="space-y-3">
      {events.map((e, i) => (
        <div key={i} className="flex gap-3">
          <div className="flex flex-col items-center gap-0">
            <span className="w-2 h-2 rounded-full bg-cyan-400/70 shrink-0 mt-0.5" />
            {i < events.length - 1 && <div className="w-px flex-1 bg-[var(--row-hover-bg)] mt-1 min-h-[20px]" />}
          </div>
          <div className="pb-3 min-w-0">
            <div className="flex items-center gap-2 mb-0.5">
              <span className="text-[10px] font-mono text-cyan-400/70">{e.t}</span>
              <span className="text-[9px] font-mono bg-[var(--row-hover-bg)] border border-[var(--border-default)] px-1.5 py-0.5 rounded text-[var(--text-muted)]">{e.actor}</span>
            </div>
            <p className="text-xs text-[var(--text-tertiary)] leading-relaxed">{e.msg}</p>
          </div>
        </div>
      ))}
    </div>
  )
}

function PlaybookSteps({ playbookId, onToggle, steps, t }) {
  const pb = PLAYBOOKS[playbookId]
  if (!pb) return null
  const done = steps.filter((s) => s.done).length
  const pct = Math.round((done / steps.length) * 100)
  const barColor = pct === 100 ? '#22d3ee' : pct > 60 ? '#22d3ee' : pct > 30 ? '#f59e0b' : '#ef4444'
  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{t(pb.labelKey)}</span>
        <span className="text-[10px] font-mono" style={{ color: barColor }}>{done}/{steps.length} ({pct}%)</span>
      </div>
      <div className="h-1.5 rounded-full bg-[var(--row-hover-bg)] mb-4 overflow-hidden">
        <motion.div
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.5 }}
          className="h-full rounded-full"
          style={{ background: barColor }}
        />
      </div>
      <div className="space-y-2">
        {steps.map((step) => {
          const phaseColor = PHASE_COLOR[step.phaseKey] ?? '#6b7280'
          const phaseLabel = t(`pages.incidentResponseCenter.phases.${step.phaseKey}`)
          return (
            <motion.div
              key={step.id}
              layout
              className="flex items-start gap-3 rounded-lg p-2.5 border transition-all cursor-pointer hover:border-[var(--border-strong)]"
              style={{
                borderColor: step.done ? 'rgba(34,211,238,0.2)' : 'rgba(255,255,255,0.07)',
                background: step.done ? 'rgba(34,211,238,0.04)' : 'rgba(0,0,0,0.2)',
              }}
              onClick={() => onToggle && onToggle(step.id)}
            >
              <div
                className="mt-0.5 w-4 h-4 rounded border flex items-center justify-center shrink-0 transition-all"
                style={{
                  borderColor: step.done ? '#22d3ee' : 'rgba(255,255,255,0.2)',
                  background: step.done ? 'rgba(34,211,238,0.15)' : 'transparent',
                }}
              >
                {step.done && <span className="text-[10px] text-cyan-400">✓</span>}
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span
                    className="text-[9px] font-mono px-1 py-0.5 rounded border uppercase tracking-wider"
                    style={{ color: phaseColor, borderColor: `${phaseColor}40`, background: `${phaseColor}10` }}
                  >
                    {phaseLabel}
                  </span>
                  {step.mitre && (
                    <span className="text-[9px] font-mono text-[var(--text-disabled)] bg-[var(--row-hover-bg)] border border-[var(--border-default)] px-1.5 py-0.5 rounded">
                      {step.mitre}
                    </span>
                  )}
                </div>
                <p className="text-xs text-[var(--text-secondary)] mt-0.5" style={{ textDecoration: step.done ? 'line-through' : 'none', opacity: step.done ? 0.4 : 0.85 }}>
                  {t(step.actionKey)}
                </p>
              </div>
            </motion.div>
          )
        })}
      </div>
    </div>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function IncidentResponseCenter() {
  const { t } = useTranslation()
  const [incidents, setIncidents] = useState([])
  const [selectedId, setSelectedId] = useState(null)
  const [tab, setTab] = useState('timeline') // 'timeline' | 'playbook'
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [stepSaving, setStepSaving] = useState(false)
  const now = useNow(30_000)

  const loadIncidents = useCallback(async (opts) => {
    const silent = opts?.silent === true
    if (!silent) setLoading(true)
    setError(null)
    try {
      const r = await apiFetch('/api/soc/incidents')
      if (!r.ok) throw new Error(`Failed to load incidents (${r.status})`)
      const data = await r.json()
      const list = (data?.incidents ?? []).map((raw) => normalizeIncident(raw, t))
      setIncidents(list)
      setSelectedId((prev) => prev ?? list[0]?.id ?? null)
    } catch (e) {
      // A background refresh must not blow away a working view with an error.
      if (!silent) setError(e.message ?? t('pages.incidentResponseCenter.load_failed'))
    } finally {
      if (!silent) setLoading(false)
    }
  }, [t])

  useEffect(() => {
    loadIncidents()
  }, [loadIncidents])

  // Keep the queue live without a full-page skeleton flash.
  usePageAutoRefresh(() => loadIncidents({ silent: true }), 30_000, true)

  const selected = useMemo(() => incidents.find((i) => i.id === selectedId), [incidents, selectedId])

  const selectedSteps = useMemo(() => {
    if (!selected) return []
    return mergePlaybookSteps(selected.playbook, selected.playbookStepsDone)
  }, [selected])

  const handleToggleStep = useCallback(async (incidentId, stepId) => {
    const incident = incidents.find((i) => i.id === incidentId)
    if (!incident) return
    const current = mergePlaybookSteps(incident.playbook, incident.playbookStepsDone)
    const step = current.find((s) => s.id === stepId)
    const nextDone = !(step?.done ?? false)

    setIncidents((prev) => prev.map((inc) => {
      if (inc.id !== incidentId) return inc
      const doneIds = new Set(inc.playbookStepsDone)
      if (nextDone) doneIds.add(stepId)
      else doneIds.delete(stepId)
      return { ...inc, playbookStepsDone: [...doneIds] }
    }))

    setStepSaving(true)
    try {
      const r = await apiFetch(`/api/soc/incidents/${encodeURIComponent(incidentId)}/playbook-steps`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ step_id: stepId, done: nextDone }),
      })
      if (!r.ok) throw new Error(`Failed to save step (${r.status})`)
      const data = await r.json()
      const doneIds = Array.isArray(data?.playbookStepsDone) ? data.playbookStepsDone : null
      if (doneIds) {
        setIncidents((prev) => prev.map((inc) => (
          inc.id === incidentId ? { ...inc, playbookStepsDone: doneIds } : inc
        )))
      }
    } catch (e) {
      setIncidents((prev) => prev.map((inc) => {
        if (inc.id !== incidentId) return inc
        const doneIds = new Set(inc.playbookStepsDone)
        if (nextDone) doneIds.delete(stepId)
        else doneIds.add(stepId)
        return { ...inc, playbookStepsDone: [...doneIds] }
      }))
      setError(e.message ?? t('pages.incidentResponseCenter.save_step_failed'))
    } finally {
      setStepSaving(false)
    }
  }, [incidents, t])

  const metrics = useMemo(() => {
    const active = incidents.filter((i) => i.status === 'active').length
    const crit = incidents.filter((i) => i.severity === 'critical').length
    const resolved = incidents.filter((i) => i.status === 'resolved').length
    const totalMs = incidents.reduce((sum, i) => sum + (new Date(i.updated) - new Date(i.created)), 0)
    const avgH = incidents.length
      ? (totalMs / incidents.length / 3_600_000).toFixed(1)
      : '0.0'
    // Open incidents already past their SLA target — the number an IR lead
    // watches. Recomputed on the SLA clock tick.
    const slaBreaching = incidents.filter(
      (i) => i.status !== 'resolved' && computeSla(i, now).breached,
    ).length
    return { active, crit, resolved, avgH, slaBreaching }
  }, [incidents, now])

  const listFindings = useMemo(() => incidents.map((i) => ({
    id: i.id,
    severity: i.severity || 'medium',
    title: i.title || i.id,
    type: i.status || 'incident',
    description: i.summary || '',
    resource: i.assignee || '',
  })), [incidents])

  const {
    exportCsv,
    filteredFindings,
    searchQuery,
    setSearchQuery,
  } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-incidents',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const visibleIncidents = useMemo(() => {
    if (!searchQuery.trim()) return incidents
    const ids = new Set(filteredFindings.map((f) => f.id))
    return incidents.filter((i) => ids.has(i.id))
  }, [incidents, filteredFindings, searchQuery])

  return (
    <PageShell
      title={t('pages.incidentResponseCenter.title')}
      subtitle={t('pages.incidentResponseCenter.subtitle', { count: incidents.length })}
      badge={t(`${NS}.badge`)}
      badgeColor="#ef4444"
      actions={(
        <ShellScanActions
          onRefresh={loadIncidents}
          onExport={() => exportIncidentsCsv(incidents)}
          refreshLoading={loading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="mb-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>
      </div>

      {loading ? (
        <>
          <SkeletonWidgetGrid count={4} className="mb-8" />
          <div className="grid lg:grid-cols-[360px_1fr] gap-6">
            <SkeletonCard lines={5} />
            <SkeletonCard lines={8} />
          </div>
        </>
      ) : (
        <>
      {/* ── Metrics ──────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-8">
        <MetricCard label={t(`${NS}.active_incidents`)} value={metrics.active} sub={t(`${NS}.active_sub`)} color="#ef4444" icon="🔥" />
        <MetricCard label={t(`${NS}.critical_severity`)} value={metrics.crit} sub={t(`${NS}.critical_sub`)} color="#f97316" icon="⚠️" />
        <MetricCard
          label={t(`${NS}.sla_breaching`)}
          value={metrics.slaBreaching}
          sub={t(`${NS}.sla_breaching_sub`)}
          color={metrics.slaBreaching > 0 ? '#ef4444' : '#4ade80'}
          icon="⏳"
        />
        <MetricCard label={t(`${NS}.avg_mttr`)} value={`${metrics.avgH}h`} sub={t(`${NS}.mttr_sub`)} color="#22d3ee" icon="⏱️" />
        <MetricCard label={t(`${NS}.resolved_7d`)} value={metrics.resolved} sub={t(`${NS}.resolved_sub`)} color="#4ade80" icon="✅" />
      </div>

      {error && (
        <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono mb-6">
          {error}
        </div>
      )}

      {!error && incidents.length === 0 && (
        <EmptyState
          icon="shield"
          title={t(`${NS}.empty_title`)}
          body={t(`${NS}.empty_body`)}
          cta={{ label: t(`${NS}.view_findings`), to: '/findings' }}
        />
      )}

      {!error && incidents.length > 0 && (
      <div className="grid lg:grid-cols-[360px_1fr] gap-6">
        {/* ── Left: Incident List ───────────────────────────────────────── */}
        <div className="space-y-2">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-disabled)]">{t(`${NS}.incident_queue`)}</h2>
            <button
              type="button"
              onClick={() => exportIncidentsCsv(incidents)}
              className="inline-flex items-center gap-1 px-2 py-1 rounded-lg border border-cyan-500/30 text-[10px] font-mono text-cyan-300/80 hover:bg-cyan-500/10"
            >
              <Download className="w-3 h-3" />
              {t(`${NS}.export_csv`)}
            </button>
          </div>
          <WeissmanListToolbar
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            resultCount={visibleIncidents.length}
            totalCount={incidents.length}
          />
          {visibleIncidents.length === 0 ? (
            <div className="text-center py-8 text-slate-500">{t('weissmanFindings.filtered_title')}</div>
          ) : visibleIncidents.map((inc) => (
            <IncidentRow
              key={inc.id}
              incident={inc}
              selected={selectedId === inc.id}
              onSelect={setSelectedId}
              t={t}
              now={now}
            />
          ))}
        </div>

        {/* ── Right: Incident Detail ────────────────────────────────────── */}
        <AnimatePresence mode="wait">
          {selected && (
            <motion.div
              key={selected.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="rounded-2xl bg-[var(--bg-2)] backdrop-blur border border-[var(--border-default)] p-6 space-y-6"
            >
              {/* Header */}
              <div>
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <span className="text-[10px] font-mono text-[var(--text-disabled)]">{selected.id}</span>
                  <span
                    className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest"
                    style={{
                      color: STATUS_META[selected.status]?.color ?? '#6b7280',
                      borderColor: `${STATUS_META[selected.status]?.color ?? '#6b7280'}40`,
                      background: `${STATUS_META[selected.status]?.color ?? '#6b7280'}10`,
                    }}
                  >
                    {STATUS_META[selected.status]
                      ? t(STATUS_META[selected.status].labelKey)
                      : selected.status}
                  </span>
                  <span
                    className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest"
                    style={{
                      color: SEVERITY_COLOR[selected.severity],
                      borderColor: `${SEVERITY_COLOR[selected.severity]}40`,
                      background: `${SEVERITY_COLOR[selected.severity]}10`,
                    }}
                  >
                    {severityLabel(selected.severity, t)}
                  </span>
                  {selected.mitre && (
                    <span className="text-[9px] font-mono text-[var(--text-disabled)] bg-[var(--row-hover-bg)] border border-[var(--border-default)] px-1.5 py-0.5 rounded">
                      {selected.mitre}
                    </span>
                  )}
                </div>
                <h2 className="text-sm font-bold text-white mb-2">{selected.title}</h2>
                <p className="text-xs text-[var(--text-tertiary)] leading-relaxed">{selected.description}</p>
              </div>

              {/* Meta row */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                  { label: t('pages.incidentResponseCenter.assignee'), value: selected.assignee },
                  { label: t('pages.incidentResponseCenter.source'), value: selected.source },
                  { label: t(`${NS}.duration`), value: durationHuman(selected.created, selected.updated, t) },
                ].map(({ label, value }) => (
                  <div key={label} className="rounded-lg bg-[var(--table-surface)] border border-[var(--border-subtle)] p-3">
                    <div className="text-[9px] font-mono uppercase tracking-widest text-[var(--text-disabled)] mb-1">{label}</div>
                    <div className="text-xs font-semibold text-[var(--text-secondary)]">{value}</div>
                  </div>
                ))}
                {(() => {
                  const sla = computeSla(selected, now)
                  const color = SLA_BAND_COLOR[slaBand(sla)]
                  return (
                    <div className="rounded-lg bg-[var(--table-surface)] border border-[var(--border-subtle)] p-3">
                      <div className="text-[9px] font-mono uppercase tracking-widest text-[var(--text-disabled)] mb-1">
                        {t(`${NS}.sla_prefix`)}
                      </div>
                      <div className="text-xs font-semibold" style={{ color }}>
                        {sla.unknown ? '—' : slaCountdownLabel(sla, t)}
                      </div>
                    </div>
                  )
                })()}
              </div>

              {/* Tabs */}
              <div className="flex gap-2 border-b border-[var(--border-default)] pb-2">
                {['timeline', 'playbook'].map((tabKey) => (
                  <button
                    key={tabKey}
                    type="button"
                    onClick={() => setTab(tabKey)}
                    className="text-[11px] font-mono uppercase tracking-widest px-3 py-1.5 rounded-lg transition-all"
                    style={{
                      color: tab === tabKey ? '#22d3ee' : 'rgba(255,255,255,0.3)',
                      background: tab === tabKey ? 'rgba(34,211,238,0.08)' : 'transparent',
                      border: tab === tabKey ? '1px solid rgba(34,211,238,0.2)' : '1px solid transparent',
                    }}
                  >
                    {tabKey === 'timeline' ? t('pages.incidentResponseCenter.tab_timeline') : t('pages.incidentResponseCenter.tab_playbook')}
                  </button>
                ))}
              </div>

              {tab === 'timeline' ? (
                selected.timeline.length > 0 ? (
                  <Timeline events={selected.timeline} />
                ) : (
                  <p className="text-xs text-[var(--text-muted)] font-mono">
                    {t(`${NS}.no_timeline`)}
                  </p>
                )
              ) : (
                <PlaybookSteps
                  playbookId={selected.playbook}
                  steps={selectedSteps}
                  t={t}
                  onToggle={stepSaving ? undefined : (stepId) => handleToggleStep(selected.id, stepId)}
                />
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
      )}
        </>
      )}
    </PageShell>
  )
}
