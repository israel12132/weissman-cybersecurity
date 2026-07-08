/**
 * Phase 3 – Findings Command Center
 *
 * TanStack Table aggregating results from all 119 engines.
 * Columns: Severity, Engine Name, Title, MITRE ATT&CK, Score (CVSS), Status, Time/Date.
 * Filters: Severity, Engine group/name, Status, global text search.
 * Row click: drawer showing raw JSON + technical details + status update.
 * Export: CSV download of all findings.
 */
import React, { useState, useEffect, useMemo, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { ENGINES_BY_ID, ENGINE_GROUP_DEFS, ENGINE_GROUPS } from '../lib/enginesRegistry'
import { apiFetch } from '../lib/apiBase'
import { sanitizeFindingPlainText } from '../lib/sanitizeFinding'
import { useToast } from '../components/ui/Toaster'
import PremiumPageHeader from '../components/ui/PremiumPageHeader'
import FilterPills from '../components/ui/FilterPills'
import EmptyState from '../components/ui/EmptyState'
import DataTable from '../components/ui/DataTable'
import FindingDrawer from '../components/ui/FindingDrawer'
import FindingVerifyButton, { LiveVerdictBadge } from '../components/findings/FindingLiveVerify'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import SeverityBadge, {
  SEVERITY_META,
  getSeverityMeta,
  getSeverityOrder,
} from '../components/ui/SeverityBadge'

// ─── Constants ────────────────────────────────────────────────────────────────

const FINDING_STATUSES = [
  { value: 'OPEN', labelKey: 'findings.status_open', color: '#ef4444' },
  { value: 'ACKNOWLEDGED', labelKey: 'findings.status_acknowledged', color: '#f59e0b' },
  { value: 'IN_PROGRESS', labelKey: 'findings.status_in_progress', color: '#3b82f6' },
  { value: 'FIXED', labelKey: 'findings.status_fixed', color: '#22c55e' },
  { value: 'FALSE_POSITIVE', labelKey: 'findings.status_false_positive', color: '#6b7280' },
]

function getStatusMeta(s, t) {
  const key = (s || '').toUpperCase()
  const found = FINDING_STATUSES.find((x) => x.value === key)
  if (found) return { ...found, label: t(found.labelKey) }
  return { value: s, label: s || '—', color: '#6b7280' }
}

function StatusBadge({ status, t }) {
  const meta = getStatusMeta(status, t)
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider font-mono"
      style={{ color: meta.color, backgroundColor: `${meta.color}20`, border: `1px solid ${meta.color}40` }}
    >
      {meta.label}
    </span>
  )
}

function VerifiedBadge({ verified, t }) {
  if (verified) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold font-mono"
        style={{ color: '#22c55e', backgroundColor: '#22c55e15', border: '1px solid #22c55e40' }}>
        ✓ {t('findings.verified')}
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono"
      style={{ color: '#94a3b8', backgroundColor: '#94a3b810', border: '1px solid #94a3b830' }}>
      {t('findings.potential')}
    </span>
  )
}

const PAGE_SIZES = [25, 50, 100]

function isKevListed(f) {
  return !!(f?.kev_listed || f?.kev || f?.raw?.kev)
}

/** Map source/engine-id string → registry label & group */
function resolveEngine(sourceOrId) {
  if (!sourceOrId) return { label: '—', group: null, mitre: null }
  // Direct ID match
  const byId = ENGINES_BY_ID[sourceOrId]
  if (byId) return { label: byId.label, group: byId.group, mitre: byId.mitre }
  // Fuzzy match on label (case-insensitive)
  const lower = sourceOrId.toLowerCase().replace(/[-_\s]/g, '')
  const found = Object.values(ENGINES_BY_ID).find(
    (e) => e.label.toLowerCase().replace(/[-_\s]/g, '') === lower,
  )
  if (found) return { label: found.label, group: found.group, mitre: found.mitre }
  return { label: sanitizeFindingPlainText(sourceOrId, 64), group: null, mitre: null }
}

function formatDate(val) {
  if (!val) return '—'
  try {
    const d = new Date(val)
    if (isNaN(d.getTime())) return sanitizeFindingPlainText(String(val), 32)
    return d.toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  } catch {
    return '—'
  }
}

// ─── Small UI pieces ──────────────────────────────────────────────────────────

function MitreBadge({ id }) {
  if (!id) return <span className="text-[var(--text-disabled)] font-mono text-[11px]">—</span>
  return (
    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-white/5 border border-[var(--border-default)] text-[var(--text-tertiary)] tracking-wider">
      {id}
    </span>
  )
}

function ComplianceBadges({ compliance }) {
  const list = Array.isArray(compliance) ? compliance : []
  if (list.length === 0) return <span className="text-[var(--text-disabled)] font-mono text-[11px]">—</span>
  return (
    <div className="flex flex-wrap gap-1.5">
      {list.slice(0, 12).map((c, idx) => {
        const raw = typeof c === 'string' ? c : JSON.stringify(c)
        const label = sanitizeFindingPlainText(raw || '—', 48)
        return (
          <span
            key={`${label}-${idx}`}
            className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-white/5 border border-[var(--border-default)] text-[var(--text-tertiary)] tracking-wider"
            title={sanitizeFindingPlainText(raw || '', 256)}
          >
            {label}
          </span>
        )
      })}
      {list.length > 12 ? (
        <span className="text-[10px] font-mono text-[var(--text-muted)] px-1.5 py-0.5">+{list.length - 12}</span>
      ) : null}
    </div>
  )
}

function ScoreBadge({ score }) {
  if (score == null || score === '') return <span className="text-[var(--text-disabled)] font-mono text-[11px]">—</span>
  const n = typeof score === 'number' ? score : parseFloat(score)
  const color = n >= 9 ? '#ef4444' : n >= 7 ? '#f97316' : n >= 4 ? '#f59e0b' : '#22d3ee'
  return (
    <span className="font-mono text-[12px] font-semibold" style={{ color }}>
      {isNaN(n) ? sanitizeFindingPlainText(String(score), 8) : n.toFixed(1)}
    </span>
  )
}

// ─── Column helper ────────────────────────────────────────────────────────────

const columnHelper = createColumnHelper()

function buildColumns(t, onVerifyRow) {
  return [
    columnHelper.accessor('severity', {
      id: 'severity',
      header: t('findings.col_severity'),
      size: 100,
      sortingFn: (a, b) => {
        const ao = getSeverityOrder(a.getValue('severity'))
        const bo = getSeverityOrder(b.getValue('severity'))
        return ao - bo
      },
      cell: ({ getValue }) => <SeverityBadge severity={getValue()} />,
      filterFn: (row, _id, filterValue) =>
        !filterValue || row.original.severity?.toLowerCase() === filterValue,
    }),
    columnHelper.accessor(
      (row) => resolveEngine(row.source || row.engine).label,
      {
        id: 'engine',
        header: t('findings.col_engine'),
        size: 150,
        cell: ({ row, getValue }) => {
          const eng = resolveEngine(row.original.source || row.original.engine)
          const groupDef = eng.group ? ENGINE_GROUPS[eng.group] : null
          return (
            <div className="min-w-0">
              <div className="text-[12px] text-[var(--text-secondary)] truncate">{getValue()}</div>
              {groupDef && (
                <div
                  className="text-[10px] font-mono truncate"
                  style={{ color: `${groupDef.color}90` }}
                >
                  {groupDef.label}
                </div>
              )}
            </div>
          )
        },
        filterFn: (row, _id, filterValue) => {
          if (!filterValue) return true
          const eng = resolveEngine(row.original.source || row.original.engine)
          return (
            eng.group === filterValue ||
            eng.label.toLowerCase().includes(filterValue.toLowerCase())
          )
        },
      },
    ),
    columnHelper.accessor('title', {
      id: 'title',
      header: t('findings.col_title'),
      size: 280,
      cell: ({ getValue }) => (
        <span
          className="text-[12px] text-[var(--text-primary)] line-clamp-2 leading-snug"
          title={sanitizeFindingPlainText(getValue() || '', 512)}
        >
          {sanitizeFindingPlainText(getValue() || t('findings.untitled'), 128)}
        </span>
      ),
    }),
    columnHelper.accessor(
      (row) => row.target || row.raw?.target || null,
      {
        id: 'target',
        header: t('findings.col_target'),
        size: 220,
        enableSorting: false,
        cell: ({ getValue }) => {
          const v = getValue()
          if (!v) return <span className="text-[var(--text-disabled)] font-mono text-[11px]">—</span>
          return (
            <span className="text-[11px] font-mono text-[var(--text-tertiary)] line-clamp-1" title={sanitizeFindingPlainText(String(v), 512)}>
              {sanitizeFindingPlainText(String(v), 96)}
            </span>
          )
        },
      },
    ),
    columnHelper.accessor(
      (row) => {
        const eng = resolveEngine(row.source || row.engine)
        return eng.mitre || row.mitre_attack || row.mitre || row.technique || null
      },
      {
        id: 'mitre',
        header: t('findings.col_mitre'),
        size: 130,
        cell: ({ getValue }) => <MitreBadge id={getValue()} />,
        enableSorting: false,
      },
    ),
    columnHelper.accessor(
      (row) => row.priority_score ?? row.risk_score ?? row.cvss_score ?? null,
      {
        id: 'priority',
        header: t('findings.col_priority'),
        size: 90,
        sortingFn: (a, b) => {
          const av = parseFloat(a.getValue('priority') ?? NaN)
          const bv = parseFloat(b.getValue('priority') ?? NaN)
          if (isNaN(av) && isNaN(bv)) return 0
          if (isNaN(av)) return 1
          if (isNaN(bv)) return -1
          return av - bv
        },
        cell: ({ getValue, row }) => {
          const v = getValue()
          const kev = isKevListed(row.original)
          const epss = row.original.epss_score
          return (
            <div className="flex flex-col gap-0.5">
              <ScoreBadge score={v} />
              {(kev || epss != null) && (
                <span className="text-[9px] font-mono text-[var(--text-muted)]">
                  {kev ? 'KEV' : ''}{kev && epss != null ? ' · ' : ''}{epss != null ? `EPSS ${(epss * 100).toFixed(0)}%` : ''}
                </span>
              )}
            </div>
          )
        },
      },
    ),
    columnHelper.accessor(
      (row) => row.seen_count ?? 1,
      {
        id: 'seen_count',
        header: t('findings.col_seen'),
        size: 70,
        cell: ({ getValue }) => {
          const n = getValue()
          if (!n || n <= 1) return <span className="text-[var(--text-disabled)] font-mono text-[11px]">1×</span>
          return (
            <span className="text-[11px] font-mono text-amber-300/90" title="Recurrence count from dedup engine">
              {n}×
            </span>
          )
        },
      },
    ),
    columnHelper.accessor(
      (row) => row.cvss_score ?? row.score ?? null,
      {
        id: 'score',
        header: t('findings.col_score'),
        size: 100,
        sortingFn: (a, b) => {
          const av = parseFloat(a.getValue('score') ?? NaN)
          const bv = parseFloat(b.getValue('score') ?? NaN)
          // Null/missing scores sort to the end regardless of direction
          if (isNaN(av) && isNaN(bv)) return 0
          if (isNaN(av)) return 1
          if (isNaN(bv)) return -1
          return av - bv
        },
        cell: ({ getValue }) => <ScoreBadge score={getValue()} />,
      },
    ),
    columnHelper.accessor(
      (row) => (Array.isArray(row.compliance) ? row.compliance.length : 0),
      {
        id: 'compliance',
        header: t('findings.col_compliance'),
        size: 110,
        enableSorting: false,
        cell: ({ row, getValue }) => {
          const count = getValue()
          const has = count > 0
          return (
            <span className="text-[11px] font-mono" style={{ color: has ? '#a78bfa' : 'rgba(255,255,255,0.25)' }}>
              {has ? t('findings.compliance_tags', { count }) : '—'}
            </span>
          )
        },
      },
    ),
    columnHelper.accessor('status', {
      id: 'status',
      header: t('findings.col_status'),
      size: 130,
      cell: ({ getValue }) => <StatusBadge status={getValue()} t={t} />,
      filterFn: (row, _id, filterValue) =>
        !filterValue || (row.original.status || '').toUpperCase() === filterValue,
    }),
    columnHelper.display({
      id: 'live_verify',
      header: t('findings.col_live_verify'),
      size: 130,
      enableSorting: false,
      cell: ({ row }) => (
        <div className="flex items-center gap-1.5" onClick={(e) => e.stopPropagation()} onKeyDown={(e) => e.stopPropagation()} role="presentation">
          <LiveVerdictBadge
            verification={row.original.live_verification || row.original.raw?.live_verification}
            verdict={row.original.live_verdict}
            compact
          />
          <FindingVerifyButton compact finding={row.original} onVerified={onVerifyRow} />
        </div>
      ),
    }),
    columnHelper.accessor('verified', {
      id: 'verified',
      header: t('findings.col_verified'),
      size: 100,
      enableSorting: false,
      cell: ({ getValue }) => <VerifiedBadge verified={!!getValue()} t={t} />,
    }),
    columnHelper.accessor(
      (row) => row.discovered_at || row.created_at || null,
      {
        id: 'date',
        header: t('findings.col_date'),
        size: 160,
        cell: ({ getValue }) => (
          <span className="text-[11px] font-mono text-[var(--text-muted)] whitespace-nowrap">
            {formatDate(getValue())}
          </span>
        ),
      },
    ),
  ]
}

// ─── Global filter function ───────────────────────────────────────────────────

function globalFilterFn(row, _columnId, filterValue) {
  if (!filterValue) return true
  const q = filterValue.toLowerCase()
  const { original: f } = row
  const engine = resolveEngine(f.source || f.engine)
  return (
    (f.title || '').toLowerCase().includes(q) ||
    (f.severity || '').toLowerCase().includes(q) ||
    (f.description || '').toLowerCase().includes(q) ||
    String(f.cwe_id || f.cwe || '').toLowerCase().includes(q) ||
    String(f.url || f.affected_url || f.target_url || '').toLowerCase().includes(q) ||
    engine.label.toLowerCase().includes(q) ||
    (engine.mitre || '').toLowerCase().includes(q) ||
    (f.finding_id || '').toLowerCase().includes(q) ||
    (f.status || '').toLowerCase().includes(q)
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function FindingsCommandCenter() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const [rawFindings, setRawFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [region, setRegion] = useState('')
  const [lastUpdated, setLastUpdated] = useState(null)

  const [selectedFinding, setSelectedFinding] = useState(null)

  // Filter state
  const [globalFilter, setGlobalFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [engineFilter, setEngineFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [kevFilter, setKevFilter] = useState(false)
  const [filtersExpanded, setFiltersExpanded] = useState(true)

  // Sorting
  const [sorting, setSorting] = useState([{ id: 'severity', desc: false }])

  // Pagination
  const [pagination, setPagination] = useState({ pageIndex: 0, pageSize: 25 })

  const loadFindings = useCallback(() => {
    setLoading(true)
    setError(null)
    return apiFetch('/api/findings?limit=2000')
      .then((r) => {
        if (!r.ok) throw new Error(`Server returned HTTP ${r.status}`)
        return r.json()
      })
      .then((d) => {
        const list = Array.isArray(d) ? d : Array.isArray(d?.findings) ? d.findings : []
        setRawFindings(list)
        setLastUpdated(new Date())
      })
      .catch((e) => setError(e?.message || t('findings.load_error')))
      .finally(() => setLoading(false))
  }, [t])

  // Load findings and public config
  useEffect(() => {
    loadFindings()
    apiFetch('/api/config/public')
      .then((r) => r.ok ? r.json() : null)
      .then((d) => { if (d?.region) setRegion(d.region) })
      .catch(() => {})
  }, [loadFindings])

  const handleStatusUpdate = useCallback((rawId, newStatus) => {
    if (!rawId) return
    const matchesId = (f) => Number(f.raw_id) === Number(rawId)
    apiFetch(`/api/findings/${rawId}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus }),
    })
      .then((r) => r.json())
      .then((d) => {
        if (d.ok) {
          setRawFindings((prev) =>
            prev.map((f) => (matchesId(f) ? { ...f, status: d.status } : f)),
          )
          setSelectedFinding((prev) =>
            prev && matchesId(prev) ? { ...prev, status: d.status } : prev,
          )
          toast.success(t('findings.toast_status_updated', { status: d.status }))
        } else {
          toast.error(t('findings.toast_status_rejected', { detail: d?.detail || t('findings.unknown_error') }))
        }
      })
      .catch((e) => toast.error(t('findings.toast_status_failed', { detail: e?.message || t('findings.network_error') })))
  }, [toast, t])

  const handleExportCsv = useCallback(() => {
    apiFetch('/api/findings/export/csv')
      .then((r) => {
        if (!r.ok) throw new Error(`Export failed (HTTP ${r.status})`)
        const disposition = r.headers.get('content-disposition') || ''
        const match = disposition.match(/filename="?([^";\s]+)"?/)
        const filename = match?.[1] ?? `Weissman_findings_${new Date().toISOString().slice(0, 10)}.csv`
        return r.blob().then((blob) => ({ blob, filename }))
      })
      .then(({ blob, filename }) => {
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = filename
        a.click()
        URL.revokeObjectURL(url)
        toast.success(t('findings.toast_export_ok', { filename }))
      })
      .catch((e) => toast.error(t('findings.toast_export_failed', { detail: e?.message || t('findings.network_error') })))
  }, [toast, t])

  const handleVerifyComplete = useCallback((rawId, verification) => {
    const patch = (f) => (
      Number(f.raw_id) === Number(rawId) || Number(f.id) === Number(rawId)
        ? {
            ...f,
            live_verification: verification,
            live_verdict: verification?.verdict,
          }
        : f
    )
    setRawFindings((prev) => prev.map(patch))
    setSelectedFinding((prev) => {
      if (!prev) return prev
      if (Number(prev.raw_id) !== Number(rawId) && Number(prev.id) !== Number(rawId)) return prev
      return { ...prev, live_verification: verification, live_verdict: verification?.verdict }
    })
  }, [])

  const columns = useMemo(() => buildColumns(t, handleVerifyComplete), [t, handleVerifyComplete])

  const tableData = useMemo(() => {
    if (!kevFilter) return rawFindings
    return rawFindings.filter(isKevListed)
  }, [rawFindings, kevFilter])

  // Column filters built from controlled state
  const columnFilters = useMemo(() => {
    const f = []
    if (severityFilter) f.push({ id: 'severity', value: severityFilter })
    if (engineFilter) f.push({ id: 'engine', value: engineFilter })
    if (statusFilter) f.push({ id: 'status', value: statusFilter })
    return f
  }, [severityFilter, engineFilter, statusFilter])

  const totalFiltered = useMemo(() => {
    let count = 0
    for (const f of tableData) {
      if (severityFilter && (f.severity || '').toLowerCase() !== severityFilter) continue
      if (statusFilter && (f.status || '').toUpperCase() !== statusFilter) continue
      if (engineFilter) {
        const eng = resolveEngine(f.source || f.engine)
        if (eng.group !== engineFilter && !eng.label.toLowerCase().includes(engineFilter.toLowerCase())) {
          continue
        }
      }
      if (globalFilter && !globalFilterFn({ original: f }, '', globalFilter)) continue
      count += 1
    }
    return count
  }, [tableData, severityFilter, engineFilter, statusFilter, globalFilter])

  const handleRowClick = useCallback((row) => {
    setSelectedFinding(row.original)
  }, [])

  const handleCloseDrawer = useCallback(() => {
    setSelectedFinding(null)
  }, [])

  // Summary counts
  const countsBySeverity = useMemo(() => {
    const c = {}
    tableData.forEach((f) => {
      const s = (f.severity || 'info').toLowerCase()
      c[s] = (c[s] || 0) + 1
    })
    return c
  }, [tableData])

  const kevCount = useMemo(() => tableData.filter(isKevListed).length, [tableData])

  const statusCounts = useMemo(() => {
    const c = {}
    tableData.forEach((f) => {
      const s = (f.status || 'OPEN').toUpperCase()
      c[s] = (c[s] || 0) + 1
    })
    return c
  }, [tableData])

  const selectedRowId = selectedFinding?.raw_id ?? selectedFinding?.id

  const drawerEngineMeta = useMemo(() => {
    if (!selectedFinding) return { headerExtra: null, subtitle: undefined }
    const engine = resolveEngine(selectedFinding.source || selectedFinding.engine)
    const groupDef = engine.group ? ENGINE_GROUPS[engine.group] : null
    const headerExtra = groupDef ? (
      <span
        className="text-[10px] font-mono px-2 py-0.5 rounded border uppercase tracking-wider"
        style={{
          color: groupDef.color,
          borderColor: `${groupDef.color}40`,
          backgroundColor: `${groupDef.color}10`,
        }}
      >
        {groupDef.label}
      </span>
    ) : null
    const subtitle = [
      engine.label,
      engine.mitre || selectedFinding.mitre_attack,
      selectedFinding.finding_id
        ? sanitizeFindingPlainText(selectedFinding.finding_id, 64)
        : null,
    ]
      .filter(Boolean)
      .join(' · ')
    return { headerExtra, subtitle }
  }, [selectedFinding])

  return (
    <div
      className="min-h-[100dvh] text-slate-100"
      style={{
        background: 'radial-gradient(ellipse 120% 80% at 50% 0%, #0f172a 0%, #020617 55%, #000 100%)',
      }}
    >
      <header className="sticky top-0 z-20 border-b border-[var(--border-default)] bg-[var(--bg-3)] backdrop-blur-md">
        <div className="max-w-screen-2xl mx-auto px-4 py-2.5 flex flex-wrap items-center gap-3 text-[11px] font-mono">
          <Link to="/" className="text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors shrink-0">
            ← {t('nav.dashboard')}
          </Link>
          <span className="text-[var(--text-disabled)]">|</span>
          <Link to="/engines" className="text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors shrink-0">
            {t('nav.engine_matrix')}
          </Link>
          {region && (
            <>
              <span className="text-[var(--text-disabled)]">|</span>
              <span
                className="text-[10px] px-2 py-0.5 rounded-full border"
                style={{ color: '#22d3ee', borderColor: '#22d3ee30', backgroundColor: '#22d3ee08' }}
                title="Data residency region"
              >
                🌐 {region}
              </span>
            </>
          )}
        </div>
      </header>

      <main id="main-content" tabIndex={-1} className="max-w-screen-2xl mx-auto px-4 py-6 space-y-5 outline-none">
        <EvidenceNotice>{t('findings.evidence_notice')}</EvidenceNotice>

        <PremiumPageHeader
          title={t('findings.command_center_title')}
          subtitle={t('findings.command_center_subtitle')}
          badge={t('findings.live_badge')}
          badgeColor="#ef4444"
          count={totalFiltered}
          countLabel={t('findings.title')}
          lastUpdated={lastUpdated}
          loading={loading}
          onRefresh={loadFindings}
          onExport={handleExportCsv}
          exportLabel={t('common.export_csv')}
          refreshLabel={t('common.refresh')}
        >
          <button
            type="button"
            onClick={() => setFiltersExpanded((v) => !v)}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-[11px] font-mono border border-[var(--border-default)] bg-white/[0.03] text-[var(--text-tertiary)] hover:text-white hover:border-[var(--border-strong)] transition-all"
          >
            {filtersExpanded ? t('common.hide_filters') : t('common.show_filters')}
          </button>
        </PremiumPageHeader>

        {filtersExpanded && (
          <div className="glass-panel rounded-2xl p-4 sm:p-5 space-y-4">
            <FilterPills
              label={t('findings.filter_severity')}
              pills={Object.entries(SEVERITY_META).map(([key, meta]) => ({
                id: `findings-filter-severity-${key}`,
                label: meta.label,
                count: countsBySeverity[key] || 0,
                active: severityFilter === key,
                color: meta.color,
                onClick: () => {
                  setSeverityFilter(severityFilter === key ? '' : key)
                  setPagination((p) => ({ ...p, pageIndex: 0 }))
                },
              }))}
            />

            <FilterPills
              label={t('findings.filter_status')}
              pills={[
                {
                  id: 'findings-filter-status-all',
                  label: t('findings.all_statuses'),
                  count: tableData.length,
                  active: !statusFilter,
                  color: '#94a3b8',
                  onClick: () => {
                    setStatusFilter('')
                    setPagination((p) => ({ ...p, pageIndex: 0 }))
                  },
                },
                ...FINDING_STATUSES.map((s) => ({
                  id: `findings-filter-status-${s.value}`,
                  label: t(s.labelKey),
                  count: statusCounts[s.value] || 0,
                  active: statusFilter === s.value,
                  color: s.color,
                  onClick: () => {
                    setStatusFilter(statusFilter === s.value ? '' : s.value)
                    setPagination((p) => ({ ...p, pageIndex: 0 }))
                  },
                })),
                {
                  id: 'findings-filter-kev',
                  label: t('findings.filter_kev'),
                  count: kevCount,
                  active: kevFilter,
                  color: '#f59e0b',
                  onClick: () => {
                    setKevFilter((v) => !v)
                    setPagination((p) => ({ ...p, pageIndex: 0 }))
                  },
                },
              ]}
            />

            <div className="flex flex-wrap items-center gap-3 pt-1 border-t border-[var(--border-subtle)]">
              <div className="relative flex-1 min-w-[220px] max-w-md">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-disabled)] text-xs pointer-events-none">
                  ⌕
                </span>
                <input
                  type="text"
                  value={globalFilter}
                  onChange={(e) => {
                    setGlobalFilter(e.target.value)
                    setPagination((p) => ({ ...p, pageIndex: 0 }))
                  }}
                  placeholder={t('findings.search_findings')}
                  className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-xl pl-8 pr-8 py-2.5 text-xs text-[var(--text-secondary)] font-mono placeholder-white/25 focus:outline-none focus:border-cyan-500/40 transition-colors"
                />
                {globalFilter && (
                  <button
                    type="button"
                    onClick={() => setGlobalFilter('')}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--text-disabled)] hover:text-[var(--text-tertiary)] text-xs"
                    aria-label={t('common.close')}
                  >
                    ✕
                  </button>
                )}
              </div>

              <select
                value={engineFilter}
                onChange={(e) => {
                  setEngineFilter(e.target.value)
                  setPagination((p) => ({ ...p, pageIndex: 0 }))
                }}
                className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-xl px-3 py-2.5 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-cyan-500/40 transition-colors"
              >
                <option value="">{t('findings.all_engine_groups')}</option>
                {ENGINE_GROUP_DEFS.map((g) => (
                  <option key={g.id} value={g.id}>{g.label}</option>
                ))}
              </select>

              {(globalFilter || severityFilter || engineFilter || statusFilter || kevFilter) && (
                <button
                  type="button"
                  onClick={() => {
                    setGlobalFilter('')
                    setSeverityFilter('')
                    setEngineFilter('')
                    setStatusFilter('')
                    setKevFilter(false)
                    setPagination((p) => ({ ...p, pageIndex: 0 }))
                  }}
                  className="px-3 py-2.5 rounded-xl text-xs font-mono border border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] transition-colors"
                >
                  {t('common.clear_filters')}
                </button>
              )}
            </div>
          </div>
        )}

        {error && (
          <div className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        {!loading && !error && rawFindings.length === 0 && (
          <EmptyState
            icon="shield"
            title={t('findings.no_findings_yet')}
            body={t('findings.no_findings_body')}
            cta={{ label: t('findings.run_scan_cta'), to: '/clients' }}
            secondary={{ label: t('nav.engine_matrix'), to: '/engines' }}
          />
        )}

        {(tableData.length > 0 || loading) && (
          <DataTable
            id="findings-command-table"
            columns={columns}
            data={tableData}
            loading={loading}
            sorting={sorting}
            onSortingChange={setSorting}
            pagination={pagination}
            onPaginationChange={setPagination}
            columnFilters={columnFilters}
            globalFilter={globalFilter}
            globalFilterFn={globalFilterFn}
            pageSizes={PAGE_SIZES}
            onRowClick={handleRowClick}
            selectedRowId={selectedRowId}
            getRowAccentColor={(row) => getSeverityMeta(row.severity).border ?? getSeverityMeta(row.severity).color}
            emptyFilteredMessage={t('findings.no_filter_match')}
            zebra
          />
        )}
      </main>

      <FindingDrawer
        finding={selectedFinding}
        onClose={handleCloseDrawer}
        onStatusUpdate={handleStatusUpdate}
        onVerifyComplete={handleVerifyComplete}
        statusOptions={FINDING_STATUSES.map(({ value, label }) => ({ value, label }))}
        headerExtra={drawerEngineMeta.headerExtra}
        subtitle={drawerEngineMeta.subtitle}
      />
    </div>
  )
}
