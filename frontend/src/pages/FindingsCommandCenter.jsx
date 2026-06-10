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
import { createColumnHelper } from '@tanstack/react-table'
import { ENGINES_BY_ID, ENGINE_GROUP_DEFS, ENGINE_GROUPS } from '../lib/enginesRegistry'
import { apiFetch } from '../lib/apiBase'
import { sanitizeFindingPlainText } from '../lib/sanitizeFinding'
import { useToast } from '../components/ui/Toaster'
import DataTable from '../components/ui/DataTable'
import EmptyState from '../components/ui/EmptyState'
import FindingDrawer from '../components/ui/FindingDrawer'
import SeverityBadge, {
  SEVERITY_META,
  getSeverityMeta,
  getSeverityOrder,
} from '../components/ui/SeverityBadge'

// ─── Constants ────────────────────────────────────────────────────────────────

const FINDING_STATUSES = [
  { value: 'OPEN',          label: 'Open',          color: '#ef4444' },
  { value: 'ACKNOWLEDGED',  label: 'Acknowledged',  color: '#f59e0b' },
  { value: 'IN_PROGRESS',   label: 'In Progress',   color: '#3b82f6' },
  { value: 'FIXED',         label: 'Fixed',         color: '#22c55e' },
  { value: 'FALSE_POSITIVE',label: 'False Positive',color: '#6b7280' },
]

function getStatusMeta(s) {
  return FINDING_STATUSES.find((x) => x.value === (s || '').toUpperCase()) ??
    { value: s, label: s || '—', color: '#6b7280' }
}

function StatusBadge({ status }) {
  const meta = getStatusMeta(status)
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider font-mono"
      style={{ color: meta.color, backgroundColor: `${meta.color}20`, border: `1px solid ${meta.color}40` }}
    >
      {meta.label}
    </span>
  )
}

function VerifiedBadge({ verified }) {
  if (verified) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold font-mono"
        style={{ color: '#22c55e', backgroundColor: '#22c55e15', border: '1px solid #22c55e40' }}>
        ✓ Verified
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono"
      style={{ color: '#94a3b8', backgroundColor: '#94a3b810', border: '1px solid #94a3b830' }}>
      Potential
    </span>
  )
}

const PAGE_SIZES = [25, 50, 100]

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
  if (!id) return <span className="text-white/25 font-mono text-[11px]">—</span>
  return (
    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-white/5 border border-white/10 text-white/55 tracking-wider">
      {id}
    </span>
  )
}

function ComplianceBadges({ compliance }) {
  const list = Array.isArray(compliance) ? compliance : []
  if (list.length === 0) return <span className="text-white/25 font-mono text-[11px]">—</span>
  return (
    <div className="flex flex-wrap gap-1.5">
      {list.slice(0, 12).map((c, idx) => {
        const raw = typeof c === 'string' ? c : JSON.stringify(c)
        const label = sanitizeFindingPlainText(raw || '—', 48)
        return (
          <span
            key={`${label}-${idx}`}
            className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-white/5 border border-white/10 text-white/55 tracking-wider"
            title={sanitizeFindingPlainText(raw || '', 256)}
          >
            {label}
          </span>
        )
      })}
      {list.length > 12 ? (
        <span className="text-[10px] font-mono text-white/35 px-1.5 py-0.5">+{list.length - 12}</span>
      ) : null}
    </div>
  )
}

function ScoreBadge({ score }) {
  if (score == null || score === '') return <span className="text-white/25 font-mono text-[11px]">—</span>
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

function buildColumns() {
  return [
    columnHelper.accessor('severity', {
      id: 'severity',
      header: 'Severity',
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
        header: 'Engine Name',
        size: 150,
        cell: ({ row, getValue }) => {
          const eng = resolveEngine(row.original.source || row.original.engine)
          const groupDef = eng.group ? ENGINE_GROUPS[eng.group] : null
          return (
            <div className="min-w-0">
              <div className="text-[12px] text-white/80 truncate">{getValue()}</div>
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
      header: 'Title',
      size: 280,
      cell: ({ getValue }) => (
        <span
          className="text-[12px] text-white/85 line-clamp-2 leading-snug"
          title={sanitizeFindingPlainText(getValue() || '', 512)}
        >
          {sanitizeFindingPlainText(getValue() || 'Untitled', 128)}
        </span>
      ),
    }),
    columnHelper.accessor(
      (row) => row.target || row.raw?.target || null,
      {
        id: 'target',
        header: 'Target',
        size: 220,
        enableSorting: false,
        cell: ({ getValue }) => {
          const v = getValue()
          if (!v) return <span className="text-white/25 font-mono text-[11px]">—</span>
          return (
            <span className="text-[11px] font-mono text-white/55 line-clamp-1" title={sanitizeFindingPlainText(String(v), 512)}>
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
        header: 'MITRE ATT&CK',
        size: 130,
        cell: ({ getValue }) => <MitreBadge id={getValue()} />,
        enableSorting: false,
      },
    ),
    columnHelper.accessor(
      (row) => row.cvss_score ?? row.score ?? null,
      {
        id: 'score',
        header: 'Score (CVSS)',
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
        header: 'Compliance',
        size: 110,
        enableSorting: false,
        cell: ({ row, getValue }) => {
          const count = getValue()
          const has = count > 0
          return (
            <span className="text-[11px] font-mono" style={{ color: has ? '#a78bfa' : 'rgba(255,255,255,0.25)' }}>
              {has ? `${count} tag${count === 1 ? '' : 's'}` : '—'}
            </span>
          )
        },
      },
    ),
    columnHelper.accessor('status', {
      id: 'status',
      header: 'Status',
      size: 130,
      cell: ({ getValue }) => <StatusBadge status={getValue()} />,
      filterFn: (row, _id, filterValue) =>
        !filterValue || (row.original.status || '').toUpperCase() === filterValue,
    }),
    columnHelper.accessor('verified', {
      id: 'verified',
      header: 'Verified',
      size: 100,
      enableSorting: false,
      cell: ({ getValue }) => <VerifiedBadge verified={!!getValue()} />,
    }),
    columnHelper.accessor(
      (row) => row.discovered_at || row.created_at || null,
      {
        id: 'date',
        header: 'Time / Date',
        size: 160,
        cell: ({ getValue }) => (
          <span className="text-[11px] font-mono text-white/45 whitespace-nowrap">
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
  const { toast } = useToast()
  const [rawFindings, setRawFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [region, setRegion] = useState('')

  const [selectedFinding, setSelectedFinding] = useState(null)

  // Filter state
  const [globalFilter, setGlobalFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [engineFilter, setEngineFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')

  // Sorting
  const [sorting, setSorting] = useState([{ id: 'severity', desc: false }])

  // Pagination
  const [pagination, setPagination] = useState({ pageIndex: 0, pageSize: 25 })

  // Load findings and public config
  useEffect(() => {
    setLoading(true)
    apiFetch('/api/findings?limit=2000')
      .then((r) => {
        if (!r.ok) throw new Error(`Server returned HTTP ${r.status}`)
        return r.json()
      })
      .then((d) => {
        // Backend was rewritten to return {ok, findings, total, limit, offset}.
        // Tolerate legacy array shape for older deployments.
        const list = Array.isArray(d) ? d : Array.isArray(d?.findings) ? d.findings : []
        setRawFindings(list)
      })
      .catch((e) => setError(e?.message || 'Failed to load findings'))
      .finally(() => setLoading(false))
    apiFetch('/api/config/public')
      .then((r) => r.ok ? r.json() : null)
      .then((d) => { if (d?.region) setRegion(d.region) })
      .catch(() => {})
  }, [])

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
          toast.success(`Status updated → ${d.status}`)
        } else {
          toast.error(`Status update rejected: ${d?.detail || 'unknown error'}`)
        }
      })
      .catch((e) => toast.error(`Status update failed: ${e?.message || 'network error'}`))
  }, [toast])

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
        toast.success(`Downloaded ${filename}`)
      })
      .catch((e) => toast.error(`CSV export failed: ${e?.message || 'network error'}`))
  }, [toast])

  const columns = useMemo(() => buildColumns(), [])

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
    for (const f of rawFindings) {
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
  }, [rawFindings, severityFilter, engineFilter, statusFilter, globalFilter])

  const handleRowClick = useCallback((row) => {
    setSelectedFinding(row.original)
  }, [])

  const handleCloseDrawer = useCallback(() => {
    setSelectedFinding(null)
  }, [])

  // Summary counts
  const countsBySeverity = useMemo(() => {
    const c = {}
    rawFindings.forEach((f) => {
      const s = (f.severity || 'info').toLowerCase()
      c[s] = (c[s] || 0) + 1
    })
    return c
  }, [rawFindings])

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
      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <header className="sticky top-0 z-20 border-b border-white/10 bg-black/50 backdrop-blur-md">
        <div className="max-w-screen-2xl mx-auto px-4 py-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <Link
              to="/"
              className="text-white/40 hover:text-white/70 text-xs font-mono transition-colors shrink-0"
            >
              ← Dashboard
            </Link>
            <span className="text-white/20 text-xs">|</span>
            <Link
              to="/engines"
              className="text-white/40 hover:text-white/70 text-xs font-mono transition-colors shrink-0"
            >
              Engine Matrix
            </Link>
            <span className="text-white/20 text-xs">|</span>
            <span
              className="text-[10px] font-mono px-2 py-0.5 rounded border uppercase tracking-widest shrink-0"
              style={{ color: '#ef4444', borderColor: '#ef444440', backgroundColor: '#ef444410' }}
            >
              Findings
            </span>
            <h1 className="text-sm font-bold text-white truncate">Command Center</h1>
          </div>

          <div className="flex items-center gap-3">
            {loading && (
              <div className="w-3 h-3 border-2 border-[#22d3ee]/40 border-t-[#22d3ee] rounded-full animate-spin" />
            )}
            {region && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded border"
                style={{ color: '#22d3ee', borderColor: '#22d3ee30', backgroundColor: '#22d3ee08' }}
                title="Data residency region">
                🌐 {region}
              </span>
            )}
            <span className="text-[11px] font-mono text-white/35">
              {rawFindings.length} total · {totalFiltered} shown
            </span>
            <button
              id="findings-export-csv-btn"
              type="button"
              onClick={handleExportCsv}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-white/15 text-[11px] font-mono text-white/60 hover:text-white/90 hover:border-white/30 transition-colors"
              title="Export all findings as CSV"
            >
              ↓ Export CSV
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-screen-2xl mx-auto px-4 py-6 space-y-6">
        {/* ── Severity summary bar ──────────────────────────────────────────── */}
        <div className="flex flex-wrap gap-3">
          {Object.entries(SEVERITY_META).map(([key, meta]) => {
            const count = countsBySeverity[key] || 0
            const active = severityFilter === key
            return (
              <button
                id={`findings-filter-severity-${key}`}
                key={key}
                type="button"
                onClick={() => setSeverityFilter(active ? '' : key)}
                className="flex items-center gap-2 px-3 py-2 rounded-xl border transition-all duration-150 hover:scale-[1.03] active:scale-100"
                style={{
                  borderColor: active ? meta.color : `${meta.color}30`,
                  backgroundColor: active ? `${meta.color}15` : 'transparent',
                }}
              >
                <span
                  className="w-2 h-2 rounded-full"
                  style={{ backgroundColor: meta.color, boxShadow: `0 0 6px ${meta.color}70` }}
                />
                <span className="text-[11px] font-mono" style={{ color: meta.color }}>
                  {meta.label}
                </span>
                <span className="text-[10px] font-mono text-white/40">{count}</span>
              </button>
            )
          })}
        </div>

        {/* ── Filter bar ───────────────────────────────────────────────────── */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Global search */}
          <div className="relative flex-1 min-w-[200px] max-w-sm">
            <span className="absolute left-3 top-1/2 -translate-y-1/2 text-white/30 text-xs pointer-events-none">
              ⌕
            </span>
            <input
              type="text"
              value={globalFilter}
              onChange={(e) => {
                setGlobalFilter(e.target.value)
                setPagination((p) => ({ ...p, pageIndex: 0 }))
              }}
              placeholder="Search findings…"
              className="w-full bg-black/50 border border-white/10 rounded-lg pl-8 pr-3 py-2 text-xs text-white/80 font-mono placeholder-white/25 focus:outline-none focus:border-cyan-500/40 transition-colors"
            />
            {globalFilter && (
              <button
                type="button"
                onClick={() => setGlobalFilter('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/60 text-xs"
              >
                ✕
              </button>
            )}
          </div>

          {/* Engine / group filter */}
          <select
            value={engineFilter}
            onChange={(e) => {
              setEngineFilter(e.target.value)
              setPagination((p) => ({ ...p, pageIndex: 0 }))
            }}
            className="bg-black/50 border border-white/10 rounded-lg px-3 py-2 text-xs text-white/70 font-mono focus:outline-none focus:border-cyan-500/40 transition-colors"
          >
            <option value="">All Engine Groups</option>
            {ENGINE_GROUP_DEFS.map((g) => (
              <option key={g.id} value={g.id}>
                {g.label}
              </option>
            ))}
          </select>

          {/* Status filter */}
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value)
              setPagination((p) => ({ ...p, pageIndex: 0 }))
            }}
            className="bg-black/50 border border-white/10 rounded-lg px-3 py-2 text-xs text-white/70 font-mono focus:outline-none focus:border-cyan-500/40 transition-colors"
          >
            <option value="">All Statuses</option>
            {FINDING_STATUSES.map((s) => (
              <option key={s.value} value={s.value}>{s.label}</option>
            ))}
          </select>

          {/* Clear filters */}
          {(globalFilter || severityFilter || engineFilter || statusFilter) && (
            <button
              type="button"
              onClick={() => {
                setGlobalFilter('')
                setSeverityFilter('')
                setEngineFilter('')
                setStatusFilter('')
                setPagination((p) => ({ ...p, pageIndex: 0 }))
              }}
              className="px-3 py-2 rounded-lg text-xs font-mono border border-white/10 text-white/40 hover:text-white/70 hover:border-white/20 transition-colors"
            >
              Clear filters
            </button>
          )}
        </div>

        {/* ── Error ────────────────────────────────────────────────────────── */}
        {error && (
          <div className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        {/* ── Empty state ───────────────────────────────────────────────────── */}
        {!loading && !error && rawFindings.length === 0 && (
          <EmptyState
            icon="shield"
            title="No findings yet"
            body="Run engines from the Engine Matrix to populate findings here."
            secondary={{ label: 'Go to Engine Matrix →', href: '/engines' }}
          />
        )}

        {/* ── Table ────────────────────────────────────────────────────────── */}
        {(rawFindings.length > 0 || loading) && (
          <DataTable
            id="findings-command-table"
            columns={columns}
            data={rawFindings}
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
            getRowAccentColor={(row) => getSeverityMeta(row.severity).border}
            emptyFilteredMessage="No findings match the current filters."
          />
        )}
      </main>
      <FindingDrawer
        finding={selectedFinding}
        onClose={handleCloseDrawer}
        onStatusUpdate={handleStatusUpdate}
        statusOptions={FINDING_STATUSES.map(({ value, label }) => ({ value, label }))}
        headerExtra={drawerEngineMeta.headerExtra}
        subtitle={drawerEngineMeta.subtitle}
      />
    </div>
  )
}
