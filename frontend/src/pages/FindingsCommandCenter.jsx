/**
 * Phase 3 – Findings Command Center
 *
 * TanStack Table aggregating results from all 119 engines.
 * Columns: Severity, Engine Name, Title, MITRE ATT&CK, Score (CVSS), Status, Time/Date.
 * Filters: Severity, Engine group/name, Status, global text search.
 * Row click: drawer showing raw JSON + technical details + status update.
 * Export: CSV download of all findings.
 */
import { useState, useEffect, useMemo, useCallback } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { createColumnHelper } from '@tanstack/react-table'
import { ENGINES_BY_ID, ENGINE_GROUP_DEFS, ENGINE_GROUPS } from '../lib/enginesRegistry'
import { apiFetch } from '../utils/apiFetch'
// bulkUpdateFindingStatus expects a raw-Response apiFetch (reads r.ok / r.json()),
// so keep the legacy lib/apiBase client for that helper only.
import { apiFetch as rawApiFetch } from '../lib/apiBase'
import { bulkUpdateFindingStatus } from '../lib/bulkFindingStatus'
import { useSavedViews } from '../hooks/useSavedViews'
import { encodeFindingsFilters, decodeFindingsFilters } from '../lib/findingsUrlState'
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
import Button from '../components/ui/Button'

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

// Registry is static, so precompute a normalized-label → engine index ONCE
// instead of scanning all ~563 engines on every unmatched lookup. Results are
// memoized by raw input — the accessors below run per-row × per-render over a
// 2000-row set, so this must be O(1), not an O(n) find per call.
const _normLabelIndex = (() => {
  const idx = new Map()
  for (const e of Object.values(ENGINES_BY_ID)) {
    const key = String(e.label || '').toLowerCase().replace(/[-_\s]/g, '')
    if (key && !idx.has(key)) idx.set(key, e)
  }
  return idx
})()
const _resolveEngineCache = new Map()

/** Map source/engine-id string → registry label & group (memoized, O(1)). */
function resolveEngine(sourceOrId) {
  if (!sourceOrId) return { label: '—', group: null, mitre: null }
  const cached = _resolveEngineCache.get(sourceOrId)
  if (cached) return cached
  let result
  const byId = ENGINES_BY_ID[sourceOrId]
  if (byId) {
    result = { label: byId.label, group: byId.group, mitre: byId.mitre }
  } else {
    const found = _normLabelIndex.get(sourceOrId.toLowerCase().replace(/[-_\s]/g, ''))
    result = found
      ? { label: found.label, group: found.group, mitre: found.mitre }
      : { label: sanitizeFindingPlainText(sourceOrId, 64), group: null, mitre: null }
  }
  _resolveEngineCache.set(sourceOrId, result)
  return result
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
    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-[var(--row-hover-bg)] border border-[var(--border-default)] text-[var(--text-tertiary)] tracking-wider">
      {id}
    </span>
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
        cell: ({ getValue }) => {
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

  // Filter state — hydrated once from the URL so a shared link opens pre-filtered.
  const [searchParams, setSearchParams] = useSearchParams()
  const initialUrlFilters = useMemo(() => decodeFindingsFilters(searchParams), []) // eslint-disable-line react-hooks/exhaustive-deps
  const [globalFilter, setGlobalFilter] = useState(initialUrlFilters.globalFilter)
  const [severityFilter, setSeverityFilter] = useState(initialUrlFilters.severityFilter)
  const [engineFilter, setEngineFilter] = useState(initialUrlFilters.engineFilter)
  const [statusFilter, setStatusFilter] = useState(initialUrlFilters.statusFilter)
  const [kevFilter, setKevFilter] = useState(initialUrlFilters.kevFilter)
  const [filtersExpanded, setFiltersExpanded] = useState(true)

  // Keep the URL in sync with the active filters (shareable / bookmarkable),
  // preserving any unrelated query params. Replace (no history spam).
  useEffect(() => {
    const FILTER_KEYS = ['q', 'sev', 'status', 'engine', 'kev']
    const encoded = encodeFindingsFilters({ globalFilter, severityFilter, statusFilter, engineFilter, kevFilter })
    // Compare only our own keys so unrelated params (and their order) never
    // trigger a redundant write — avoids a cosmetic replace() on mount.
    const changed = FILTER_KEYS.some((k) => (encoded[k] ?? '') !== (searchParams.get(k) ?? ''))
    if (!changed) return
    const next = new URLSearchParams(searchParams)
    for (const k of FILTER_KEYS) next.delete(k)
    for (const [k, v] of Object.entries(encoded)) next.set(k, v)
    setSearchParams(next, { replace: true })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [globalFilter, severityFilter, statusFilter, engineFilter, kevFilter])

  // Sorting
  const [sorting, setSorting] = useState([{ id: 'severity', desc: false }])

  // Pagination
  const [pagination, setPagination] = useState({ pageIndex: 0, pageSize: 25 })

  // Bulk selection / actions
  const [selectedRows, setSelectedRows] = useState([])
  const [bulkStatus, setBulkStatus] = useState('')
  const [bulkBusy, setBulkBusy] = useState(false)
  const [selectionResetSignal, setSelectionResetSignal] = useState(0)

  // Saved views (named filter/sort snapshots, per-user, localStorage)
  const { views: savedViews, saveView, deleteView } = useSavedViews('weissman_findings_views')
  const [viewName, setViewName] = useState('')

  const loadFindings = useCallback(() => {
    setLoading(true)
    setError(null)
    return apiFetch('/api/findings?limit=2000')
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
      .then((d) => { if (d?.region) setRegion(d.region) })
      .catch(() => {})
  }, [loadFindings])

  const handleStatusUpdate = useCallback((rawId, newStatus) => {
    if (!rawId) return
    const matchesId = (f) => Number(f.raw_id) === Number(rawId)
    apiFetch(`/api/findings/${rawId}/status`, {
      method: 'PATCH',
      body: { status: newStatus },
    })
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

  // Bulk status update — batches the per-finding PATCH /api/findings/:id/status
  // (there is no server bulk endpoint) with concurrency-limited requests, then
  // reports an aggregate result. Local state is patched from each success.
  const applyBulkStatus = useCallback(async () => {
    const status = bulkStatus
    const targets = selectedRows.map((f) => f.raw_id ?? f.id)
    if (!status || targets.filter((id) => id != null).length === 0) return
    setBulkBusy(true)
    const { ok, failed } = await bulkUpdateFindingStatus(targets, status, {
      apiFetch: rawApiFetch,
      onSuccess: (rawId, serverStatus) => {
        // Match on both keys: targets are `raw_id ?? id`, so a finding without a
        // raw_id was PATCHed by its id and must be matched by id here too, else
        // the row shows a stale status despite the server success.
        setRawFindings((prev) => prev.map((f) => (Number(f.raw_id) === Number(rawId) || Number(f.id) === Number(rawId) ? { ...f, status: serverStatus } : f)))
      },
    })
    setBulkBusy(false)
    setSelectionResetSignal((n) => n + 1)
    setSelectedRows([])
    if (failed.length === 0) {
      toast.success(t('findings.bulk_status_ok', { count: ok, status }))
    } else {
      toast.warning(t('findings.bulk_status_partial', { ok, failed: failed.length }))
    }
  }, [bulkStatus, selectedRows, toast, t])

  const handleExportCsv = useCallback(() => {
    apiFetch('/api/findings/export/csv', { raw: true })
      .then((r) => {
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

  // Snapshot / restore the full filter+sort state for saved views.
  const saveCurrentView = useCallback(() => {
    const name = viewName.trim()
    if (!name) return
    saveView(name, { globalFilter, severityFilter, engineFilter, statusFilter, kevFilter, sorting })
    setViewName('')
    toast.success(t('findings.view_saved', { name }))
  }, [viewName, saveView, globalFilter, severityFilter, engineFilter, statusFilter, kevFilter, sorting, toast, t])

  const applyView = useCallback((state) => {
    if (!state) return
    setGlobalFilter(state.globalFilter ?? '')
    setSeverityFilter(state.severityFilter ?? '')
    setEngineFilter(state.engineFilter ?? '')
    setStatusFilter(state.statusFilter ?? '')
    setKevFilter(Boolean(state.kevFilter))
    if (Array.isArray(state.sorting)) setSorting(state.sorting)
    setPagination((p) => ({ ...p, pageIndex: 0 }))
  }, [])

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
      className="min-h-[100dvh] text-[var(--text-secondary)]"
      style={{
        background: 'var(--shell-bg)',
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
          <Button variant="unstyled"
            type="button"
            onClick={() => setFiltersExpanded((v) => !v)}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-[11px] font-mono border border-[var(--border-default)] bg-[var(--row-hover-bg)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:border-[var(--border-strong)] transition-all"
          >
            {filtersExpanded ? t('common.hide_filters') : t('common.show_filters')}
          </Button>
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
                  <Button variant="unstyled"
                    type="button"
                    onClick={() => setGlobalFilter('')}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-[var(--text-disabled)] hover:text-[var(--text-tertiary)] text-xs"
                    aria-label={t('common.close')}
                  >
                    ✕
                  </Button>
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
                <Button variant="unstyled"
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
                </Button>
              )}
            </div>

            {/* Saved views — named filter/sort snapshots (per-user, local). */}
            <div className="flex flex-wrap items-center gap-2 pt-3 mt-1 border-t border-[var(--border-subtle)]">
              <span className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{t('findings.views_label')}</span>
              {savedViews.map((v) => (
                <span key={v.id} className="inline-flex items-center gap-1 rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] pl-2.5 pr-1 py-1 text-[11px] font-mono text-[var(--text-secondary)]">
                  <Button variant="unstyled" type="button" onClick={() => applyView(v.state)} className="hover:text-cyan-300 transition-colors" title={t('findings.view_apply')}>
                    {v.name}
                  </Button>
                  <Button variant="unstyled" type="button" onClick={() => deleteView(v.id)} aria-label={t('findings.view_delete', { name: v.name })} className="w-4 h-4 flex items-center justify-center rounded text-[var(--text-muted)] hover:text-rose-300 transition-colors">×</Button>
                </span>
              ))}
              {savedViews.length === 0 && (
                <span className="text-[11px] font-mono text-[var(--text-disabled)]">{t('findings.views_empty')}</span>
              )}
              <form
                className="inline-flex items-center gap-1.5 ms-auto"
                onSubmit={(e) => { e.preventDefault(); saveCurrentView() }}
              >
                <input
                  type="text"
                  value={viewName}
                  onChange={(e) => setViewName(e.target.value)}
                  placeholder={t('findings.view_name_placeholder')}
                  aria-label={t('findings.view_name_placeholder')}
                  className="w-40 bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-[11px] text-[var(--text-secondary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500/40"
                />
                <Button variant="unstyled"
                  type="submit"
                  disabled={!viewName.trim()}
                  className="rounded-lg border border-cyan-500/30 bg-cyan-500/5 px-2.5 py-1.5 text-[11px] font-mono text-cyan-300 hover:bg-cyan-500/15 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  {t('findings.view_save')}
                </Button>
              </form>
            </div>
          </div>
        )}

        {error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
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

        {selectedRows.length > 0 && (
          <div className="sticky top-2 z-10 flex flex-wrap items-center gap-3 rounded-xl border border-cyan-500/30 bg-[var(--bg-elevated)] px-4 py-2.5 shadow-lg">
            <span className="text-[12px] font-mono text-cyan-300">
              {t('findings.bulk_selected', { count: selectedRows.length })}
            </span>
            <div className="flex items-center gap-2 ms-auto">
              <label className="text-[11px] font-mono text-[var(--text-muted)]">{t('findings.bulk_set_status')}</label>
              <select
                value={bulkStatus}
                onChange={(e) => setBulkStatus(e.target.value)}
                aria-label={t('findings.bulk_set_status')}
                className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1.5 text-[12px] text-[var(--text-secondary)] focus:outline-none focus:border-cyan-500/40"
              >
                <option value="">{t('findings.bulk_choose_status')}</option>
                {FINDING_STATUSES.map((s) => (
                  <option key={s.value} value={s.value}>{t(s.labelKey)}</option>
                ))}
              </select>
              <Button variant="unstyled"
                type="button"
                disabled={!bulkStatus || bulkBusy}
                onClick={applyBulkStatus}
                className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 text-[12px] font-mono text-cyan-200 hover:bg-cyan-500/20 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                {bulkBusy && <span className="w-3 h-3 border-2 border-cyan-400/40 border-t-cyan-400 rounded-full animate-spin" />}
                {t('findings.bulk_apply', { count: selectedRows.length })}
              </Button>
              <Button variant="unstyled"
                type="button"
                onClick={() => { setSelectionResetSignal((n) => n + 1); setSelectedRows([]) }}
                className="rounded-lg border border-[var(--border-default)] px-2.5 py-1.5 text-[12px] font-mono text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors"
              >
                {t('findings.bulk_clear')}
              </Button>
            </div>
          </div>
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
            enableSelection
            onSelectionChange={setSelectedRows}
            selectionResetSignal={selectionResetSignal}
            selectLabel={t('findings.select_row')}
            selectAllLabel={t('findings.select_all')}
            densityToggle
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
        statusOptions={FINDING_STATUSES.map(({ value, labelKey }) => ({ value, label: t(labelKey) }))}
        headerExtra={drawerEngineMeta.headerExtra}
        subtitle={drawerEngineMeta.subtitle}
      />
    </div>
  )
}
