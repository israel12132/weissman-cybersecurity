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
import { motion, AnimatePresence } from 'framer-motion'
import {
  useReactTable,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  getPaginationRowModel,
  flexRender,
  createColumnHelper,
} from '@tanstack/react-table'
import { ENGINES_BY_ID, ENGINE_GROUP_DEFS, ENGINE_GROUPS } from '../lib/enginesRegistry'
import { apiFetch } from '../lib/apiBase'
import { sanitizeFindingPlainText } from '../lib/sanitizeFinding'

// ─── Constants ────────────────────────────────────────────────────────────────

const SEVERITY_META = {
  critical: { color: '#ef4444', bg: '#ef444420', label: 'Critical', order: 0 },
  high:     { color: '#f97316', bg: '#f9731620', label: 'High',     order: 1 },
  medium:   { color: '#f59e0b', bg: '#f59e0b20', label: 'Medium',   order: 2 },
  low:      { color: '#22d3ee', bg: '#22d3ee20', label: 'Low',      order: 3 },
  info:     { color: '#6b7280', bg: '#6b728020', label: 'Info',     order: 4 },
}

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

const UNKNOWN_SEVERITY_ORDER = 5

const MAX_VISIBLE_PAGES = 7

const PAGE_SIZES = [25, 50, 100]

function getSeverityMeta(s) {
  return SEVERITY_META[(s || '').toLowerCase()] ?? SEVERITY_META.info
}

/** Returns the numeric sort order for a severity string; unknowns sort last. */
function getSeverityOrder(s) {
  const key = (s || '').toLowerCase()
  return SEVERITY_META[key]?.order ?? UNKNOWN_SEVERITY_ORDER
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

function SeverityBadge({ severity }) {
  const meta = getSeverityMeta(severity)
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider font-mono"
      style={{ color: meta.color, backgroundColor: meta.bg, border: `1px solid ${meta.color}40` }}
    >
      {meta.label}
    </span>
  )
}

function MitreBadge({ id }) {
  if (!id) return <span className="text-white/25 font-mono text-[11px]">—</span>
  return (
    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-white/5 border border-white/10 text-white/55 tracking-wider">
      {id}
    </span>
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

function SortIndicator({ sorted }) {
  if (!sorted) return <span className="text-white/20 ml-1">⇅</span>
  return <span className="ml-1">{sorted === 'asc' ? '↑' : '↓'}</span>
}

// ─── Detail Drawer ────────────────────────────────────────────────────────────

function FindingDrawer({ finding, onClose, onStatusUpdate }) {
  const meta = getSeverityMeta(finding?.severity)
  const engine = resolveEngine(finding?.source || finding?.engine)
  const groupDef = engine.group ? ENGINE_GROUPS[engine.group] : null
  const [statusUpdating, setStatusUpdating] = useState(false)

  const handleStatusChange = (e) => {
    const newStatus = e.target.value
    if (!newStatus || newStatus === finding?.status) return
    setStatusUpdating(true)
    onStatusUpdate?.(finding?.raw_id, newStatus)
    setTimeout(() => setStatusUpdating(false), 600)
  }

  const rawJson = useMemo(() => {
    try {
      return JSON.stringify(finding, null, 2)
    } catch {
      return '{}'
    }
  }, [finding])

  return (
    <AnimatePresence>
      {finding && (
        <>
          {/* Backdrop */}
          <motion.div
            key="backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm"
            onClick={onClose}
          />
          {/* Drawer */}
          <motion.aside
            key="drawer"
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 30, stiffness: 280 }}
            className="fixed inset-y-0 right-0 z-50 w-full max-w-xl flex flex-col border-l border-white/10 bg-[#080f1e]/95 backdrop-blur-xl shadow-2xl"
          >
            {/* Drawer header */}
            <div
              className="shrink-0 flex items-start justify-between gap-4 px-5 py-4 border-b border-white/10"
              style={{ borderColor: `${meta.color}30` }}
            >
              <div className="min-w-0 space-y-1.5">
                <div className="flex items-center flex-wrap gap-2">
                  <SeverityBadge severity={finding.severity} />
                  {groupDef && (
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
                  )}
                </div>
                <h2 className="text-sm font-semibold text-white leading-snug">
                  {sanitizeFindingPlainText(finding.title || 'Untitled Finding', 256)}
                </h2>
                <p className="text-[11px] font-mono text-white/40">
                  {engine.label}
                  {engine.mitre && ` · ${engine.mitre}`}
                  {finding.finding_id && ` · ${sanitizeFindingPlainText(finding.finding_id, 64)}`}
                </p>
              </div>
              <button
                id="findings-drawer-close-btn"
                type="button"
                onClick={onClose}
                aria-label="Close findings drawer"
                className="shrink-0 text-white/40 hover:text-white/80 transition-colors text-lg leading-none mt-0.5"
              >
                ✕
              </button>
            </div>

            {/* Scrollable body */}
            <div className="flex-1 overflow-y-auto px-5 py-4 space-y-6">
              {/* Verification + Status Update */}
              <section className="flex flex-wrap items-center gap-3">
                <VerifiedBadge verified={!!finding.verified || !!finding.poc_sealed} />
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-white/35 uppercase tracking-wide">Status:</span>
                  <select
                    id="findings-drawer-status-select"
                    value={finding.status || 'OPEN'}
                    onChange={handleStatusChange}
                    disabled={statusUpdating}
                    className="bg-black/60 border border-white/15 rounded px-2 py-1 text-[11px] font-mono text-white/70 focus:outline-none focus:border-cyan-500/40 transition-colors disabled:opacity-50"
                  >
                    {FINDING_STATUSES.map((s) => (
                      <option key={s.value} value={s.value}>{s.label}</option>
                    ))}
                  </select>
                  {statusUpdating && (
                    <div className="w-3 h-3 border-2 border-[#22d3ee]/40 border-t-[#22d3ee] rounded-full animate-spin" />
                  )}
                </div>
              </section>

              {/* Key fields */}
              <section>
                <h3 className="text-[10px] font-mono text-white/40 uppercase tracking-widest mb-3">
                  Technical Details
                </h3>
                <dl className="space-y-2">
                  {[
                    ['Score (CVSS)', finding.cvss_score ?? finding.score],
                    ['Discovered',  formatDate(finding.discovered_at || finding.created_at)],
                    ['Client ID',   finding.client_id],
                    ['Run ID',      finding.run_id],
                    ['Finding ID',  finding.finding_id],
                  ].map(([label, val]) =>
                    val != null && val !== '' ? (
                      <div key={label} className="flex items-start gap-3">
                        <dt className="shrink-0 w-28 text-[10px] font-mono text-white/35 uppercase tracking-wide pt-0.5">
                          {label}
                        </dt>
                        <dd className="text-[12px] text-white/75 break-all font-mono">
                          {sanitizeFindingPlainText(String(val), 256)}
                        </dd>
                      </div>
                    ) : null,
                  )}
                </dl>
              </section>

              {/* Description */}
              {finding.description && (
                <section>
                  <h3 className="text-[10px] font-mono text-white/40 uppercase tracking-widest mb-2">
                    Description
                  </h3>
                  <p className="text-[12px] text-white/65 leading-relaxed whitespace-pre-wrap">
                    {sanitizeFindingPlainText(finding.description, 4096)}
                  </p>
                </section>
              )}

              {/* Proof */}
              {finding.proof && (
                <section>
                  <h3 className="text-[10px] font-mono text-white/40 uppercase tracking-widest mb-2">
                    Proof / PoC
                  </h3>
                  <pre className="text-[11px] font-mono text-[#4ade80]/80 bg-black/60 border border-white/5 rounded-xl p-3 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                    {sanitizeFindingPlainText(finding.proof, 8192)}
                  </pre>
                </section>
              )}

              {/* Raw JSON */}
              <section>
                <h3 className="text-[10px] font-mono text-white/40 uppercase tracking-widest mb-2">
                  Raw JSON
                </h3>
                <pre className="text-[10px] font-mono text-white/50 bg-black/60 border border-white/5 rounded-xl p-3 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed max-h-96">
                  {rawJson}
                </pre>
              </section>
            </div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
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
      (row) => {
        const eng = resolveEngine(row.source || row.engine)
        return eng.mitre || row.mitre || row.technique || null
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
    engine.label.toLowerCase().includes(q) ||
    (engine.mitre || '').toLowerCase().includes(q) ||
    (f.finding_id || '').toLowerCase().includes(q) ||
    (f.status || '').toLowerCase().includes(q)
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function FindingsCommandCenter() {
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
    apiFetch('/api/findings')
      .then((r) => {
        if (!r.ok) throw new Error(`Server returned HTTP ${r.status}`)
        return r.json()
      })
      .then((d) => setRawFindings(Array.isArray(d) ? d : []))
      .catch((e) => setError(e?.message || 'Failed to load findings'))
      .finally(() => setLoading(false))
    apiFetch('/api/config/public')
      .then((r) => r.ok ? r.json() : null)
      .then((d) => { if (d?.region) setRegion(d.region) })
      .catch(() => {})
  }, [])

  // Status update handler — updates local state + calls API
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
        }
      })
      .catch(() => {})
  }, [])

  // CSV export
  const handleExportCsv = useCallback(() => {
    apiFetch('/api/findings/export/csv')
      .then((r) => {
        if (!r.ok) throw new Error('Export failed')
        // Use filename from Content-Disposition header when available; fallback to dated name
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
      })
      .catch(() => {})
  }, [])

  const columns = useMemo(() => buildColumns(), [])

  // Column filters built from controlled state
  const columnFilters = useMemo(() => {
    const f = []
    if (severityFilter) f.push({ id: 'severity', value: severityFilter })
    if (engineFilter) f.push({ id: 'engine', value: engineFilter })
    if (statusFilter) f.push({ id: 'status', value: statusFilter })
    return f
  }, [severityFilter, engineFilter, statusFilter])

  const table = useReactTable({
    data: rawFindings,
    columns,
    state: {
      globalFilter,
      columnFilters,
      sorting,
      pagination,
    },
    globalFilterFn,
    onSortingChange: setSorting,
    onPaginationChange: setPagination,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    manualFiltering: false,
  })

  const { rows } = table.getRowModel()
  const totalFiltered = table.getFilteredRowModel().rows.length
  const pageCount = table.getPageCount()

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
          <div className="rounded-xl border border-white/10 bg-white/[0.02] px-8 py-16 text-center space-y-3">
            <div className="text-4xl">🛡️</div>
            <p className="text-sm font-semibold text-white/60">No findings yet</p>
            <p className="text-xs text-white/35 font-mono">
              Run engines from the Engine Matrix to populate findings here.
            </p>
            <Link
              to="/engines"
              className="inline-block mt-2 px-4 py-2 rounded-lg border border-cyan-500/30 text-cyan-300/80 text-xs font-mono hover:bg-cyan-950/30 transition-colors"
            >
              Go to Engine Matrix →
            </Link>
          </div>
        )}

        {/* ── Table ────────────────────────────────────────────────────────── */}
        {(rawFindings.length > 0 || loading) && (
          <div className="rounded-2xl border border-white/10 bg-black/30 backdrop-blur-md overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  {table.getHeaderGroups().map((headerGroup) => (
                    <tr key={headerGroup.id} className="border-b border-white/10">
                      {headerGroup.headers.map((header) => (
                        <th
                          key={header.id}
                          style={{ width: header.getSize() }}
                          className="px-4 py-3 text-[10px] font-mono uppercase tracking-widest text-white/40 bg-white/[0.02] select-none whitespace-nowrap"
                        >
                          {header.column.getCanSort() ? (
                            <button
                              type="button"
                              onClick={header.column.getToggleSortingHandler()}
                              className="flex items-center gap-0.5 hover:text-white/70 transition-colors"
                            >
                              {flexRender(header.column.columnDef.header, header.getContext())}
                              <SortIndicator sorted={header.column.getIsSorted()} />
                            </button>
                          ) : (
                            flexRender(header.column.columnDef.header, header.getContext())
                          )}
                        </th>
                      ))}
                    </tr>
                  ))}
                </thead>

                <tbody>
                  {loading && rows.length === 0 && (
                    <tr>
                      <td colSpan={columns.length} className="px-4 py-12 text-center">
                        <div className="flex items-center justify-center gap-2 text-white/40 text-xs font-mono">
                          <div className="w-3 h-3 border-2 border-[#22d3ee]/40 border-t-[#22d3ee] rounded-full animate-spin" />
                          Loading findings…
                        </div>
                      </td>
                    </tr>
                  )}
                  {!loading && rows.length === 0 && rawFindings.length > 0 && (
                    <tr>
                      <td colSpan={columns.length} className="px-4 py-10 text-center text-white/35 text-xs font-mono">
                        No findings match the current filters.
                      </td>
                    </tr>
                  )}
                  {rows.map((row, i) => {
                    const sev = row.original.severity?.toLowerCase() ?? 'info'
                    const meta = getSeverityMeta(sev)
                    return (
                      <motion.tr
                        key={row.id}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ duration: 0.1, delay: Math.min(i * 0.01, 0.3) }}
                        onClick={() => handleRowClick(row)}
                        className="border-b border-white/5 cursor-pointer transition-all duration-100 hover:bg-white/[0.04] group"
                        style={{
                          borderLeftWidth: 2,
                          borderLeftColor: `${meta.color}50`,
                          borderLeftStyle: 'solid',
                        }}
                      >
                        {row.getVisibleCells().map((cell) => (
                          <td key={cell.id} className="px-4 py-3 align-middle">
                            {flexRender(cell.column.columnDef.cell, cell.getContext())}
                          </td>
                        ))}
                      </motion.tr>
                    )
                  })}
                </tbody>
              </table>
            </div>

            {/* ── Pagination ──────────────────────────────────────────────── */}
            <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-t border-white/5 bg-white/[0.01]">
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono text-white/35">Rows:</span>
                <select
                  value={pagination.pageSize}
                  onChange={(e) =>
                    setPagination({ pageIndex: 0, pageSize: Number(e.target.value) })
                  }
                  className="bg-black/50 border border-white/10 rounded px-1.5 py-0.5 text-[11px] font-mono text-white/60 focus:outline-none focus:border-cyan-500/40"
                >
                  {PAGE_SIZES.map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
                <span className="text-[10px] font-mono text-white/30">
                  {totalFiltered === 0
                    ? '0'
                    : `${pagination.pageIndex * pagination.pageSize + 1}–${Math.min(
                        (pagination.pageIndex + 1) * pagination.pageSize,
                        totalFiltered,
                      )}`}{' '}
                  of {totalFiltered}
                </span>
              </div>

              <div className="flex items-center gap-1.5">
                <button
                  id="findings-pagination-first"
                  type="button"
                  onClick={() => table.setPageIndex(0)}
                  disabled={!table.getCanPreviousPage()}
                  className="px-2 py-1 rounded text-[10px] font-mono border border-white/10 text-white/40 hover:text-white/70 hover:border-white/20 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                >
                  «
                </button>
                <button
                  id="findings-pagination-prev"
                  type="button"
                  onClick={() => table.previousPage()}
                  disabled={!table.getCanPreviousPage()}
                  className="px-2 py-1 rounded text-[10px] font-mono border border-white/10 text-white/40 hover:text-white/70 hover:border-white/20 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                >
                  ‹
                </button>

                {/* Page number pills */}
                {Array.from({ length: Math.min(pageCount, MAX_VISIBLE_PAGES) }, (_, i) => {
                  const startPage = Math.max(0, Math.min(pagination.pageIndex - 3, pageCount - MAX_VISIBLE_PAGES))
                  const p = startPage + i
                  if (p >= pageCount) return null
                  const active = p === pagination.pageIndex
                  return (
                    <button
                      id={`findings-pagination-page-${p + 1}`}
                      key={p}
                      type="button"
                      onClick={() => table.setPageIndex(p)}
                      className="px-2.5 py-1 rounded text-[10px] font-mono border transition-colors"
                      style={
                        active
                          ? { borderColor: '#22d3ee50', color: '#22d3ee', backgroundColor: '#22d3ee15' }
                          : { borderColor: 'rgba(255,255,255,0.08)', color: 'rgba(255,255,255,0.35)' }
                      }
                    >
                      {p + 1}
                    </button>
                  )
                })}

                <button
                  id="findings-pagination-next"
                  type="button"
                  onClick={() => table.nextPage()}
                  disabled={!table.getCanNextPage()}
                  className="px-2 py-1 rounded text-[10px] font-mono border border-white/10 text-white/40 hover:text-white/70 hover:border-white/20 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                >
                  ›
                </button>
                <button
                  id="findings-pagination-last"
                  type="button"
                  onClick={() => table.setPageIndex(pageCount - 1)}
                  disabled={!table.getCanNextPage()}
                  className="px-2 py-1 rounded text-[10px] font-mono border border-white/10 text-white/40 hover:text-white/70 hover:border-white/20 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                >
                  »
                </button>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* ── Detail Drawer ──────────────────────────────────────────────────── */}
      <FindingDrawer finding={selectedFinding} onClose={handleCloseDrawer} onStatusUpdate={handleStatusUpdate} />
    </div>
  )
}
