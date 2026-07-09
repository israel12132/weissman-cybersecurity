import React, { useMemo, useState, useRef, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  useReactTable,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  getPaginationRowModel,
  getExpandedRowModel,
  flexRender,
} from '@tanstack/react-table'
import { ChevronDown, ChevronUp, ChevronsUpDown, ChevronRight, Search, Download, Columns3, X } from 'lucide-react'
import EmptyState from './EmptyState'
import { SkeletonTable } from './Skeleton'

const MAX_VISIBLE_PAGES = 7
const DEFAULT_PAGE_SIZES = [25, 50, 100]
const PAGE_SIZE_KEY = 'weissman_table_page_size'

/** Case-insensitive substring match across every cell value of a row. */
function fuzzyGlobalFilter(row, _columnId, value) {
  const needle = String(value ?? '').toLowerCase()
  if (!needle) return true
  return row.getAllCells().some((cell) => {
    const v = cell.getValue()
    return v != null && String(v).toLowerCase().includes(needle)
  })
}

/** Serialize the currently-filtered rows × visible accessor columns to CSV. */
function tableToCsv(table) {
  const cols = table.getVisibleLeafColumns().filter((c) => typeof c.accessorFn === 'function')
  const header = cols.map((c) =>
    typeof c.columnDef.header === 'string' ? c.columnDef.header : c.id,
  )
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const lines = [
    header.map(esc).join(','),
    ...table.getFilteredRowModel().rows.map((r) => cols.map((c) => esc(r.getValue(c.id))).join(',')),
  ]
  return lines.join('\n')
}

function SortIndicator({ sorted }) {
  if (!sorted) {
    return <ChevronsUpDown className="w-3 h-3 ml-1 opacity-30" aria-hidden="true" />
  }
  return sorted === 'asc' ? (
    <ChevronUp className="w-3 h-3 ml-1 text-cyan-400/80" aria-hidden="true" />
  ) : (
    <ChevronDown className="w-3 h-3 ml-1 text-cyan-400/80" aria-hidden="true" />
  )
}

/**
 * Premium TanStack Table wrapper for SOC data grids.
 *
 * Props:
 *  - columns, data — required
 *  - loading — skeleton rows
 *  - emptyState — React node or EmptyState props object
 *  - emptyFilteredMessage — when data exists but filters hide all rows
 *  - zebra — alternate row shading
 *  - stickyHeader — default true
 *  - onRowClick — (row) => void
 *  - getRowAccentColor — (row) => css color for left border
 *  - animateRows — subtle fade-in on rows
 *  - sorting, onSortingChange
 *  - pagination, onPaginationChange
 *  - columnFilters, globalFilter, globalFilterFn
 *  - pageSizes — default [25, 50, 100]
 *  - className, tableClassName
 *  - id — root element id
 *  - renderSubRow — (rowOriginal, row) => node; enables an expander column whose
 *      chevron toggles a full-width detail row. Opt-in: omit → unchanged behavior.
 *  - getRowCanExpand — (row) => boolean; gate which rows show an expander
 *  - expandLabel / collapseLabel — a11y labels for the expander button
 */
export default function DataTable({
  columns,
  data,
  loading = false,
  emptyState,
  emptyFilteredMessage = 'No rows match the current filters.',
  zebra = false,
  stickyHeader = true,
  onRowClick,
  getRowAccentColor,
  selectedRowId,
  getRowId = (row) => row?.raw_id ?? row?.id,
  animateRows = true,
  sorting,
  onSortingChange,
  pagination,
  onPaginationChange,
  columnFilters,
  globalFilter,
  globalFilterFn,
  pageSizes = DEFAULT_PAGE_SIZES,
  className = '',
  tableClassName = '',
  id,
  renderSubRow,
  getRowCanExpand,
  expandLabel = 'Expand row',
  collapseLabel = 'Collapse row',
  // ── Opt-in toolbar (all default off → existing usages unchanged) ──
  searchable = false,
  searchPlaceholder = 'Search…',
  exportable = false,
  exportFilename = 'weissman-export',
  columnToggle = false,
  toolbarTitle,
  // Hide the built-in pagination bar and render every filtered row (the parent
  // owns paging — e.g. server-side limit/offset over a large ledger).
  hidePagination = false,
}) {
  const defaultPageSize = pageSizes?.[0] ?? 25
  // Remember the user's rows-per-page across sessions (only affects uncontrolled
  // pagination; a page passing its own `pagination` prop is untouched).
  const [internalPagination, setInternalPagination] = useState(() => {
    let stored = null
    try {
      stored = Number(localStorage.getItem(PAGE_SIZE_KEY))
    } catch {
      /* storage may be unavailable */
    }
    const pageSize = pageSizes?.includes(stored) ? stored : defaultPageSize
    return { pageIndex: 0, pageSize }
  })
  const persistingSetPagination = React.useCallback((updater) => {
    setInternalPagination((prev) => {
      const next = typeof updater === 'function' ? updater(prev) : updater
      if (next?.pageSize && next.pageSize !== prev.pageSize) {
        try {
          localStorage.setItem(PAGE_SIZE_KEY, String(next.pageSize))
        } catch {
          /* ignore */
        }
      }
      return next
    })
  }, [])
  const effectivePagination = pagination ?? internalPagination
  const effectiveOnPaginationChange = onPaginationChange ?? persistingSetPagination

  // Uncontrolled global filter (only when searchable and not externally driven).
  const [internalGlobalFilter, setInternalGlobalFilter] = useState('')
  const globalFilterControlled = globalFilter !== undefined
  const effectiveGlobalFilter = globalFilterControlled ? globalFilter : internalGlobalFilter
  const [columnVisibility, setColumnVisibility] = useState({})
  const [colMenuOpen, setColMenuOpen] = useState(false)
  const colMenuRef = useRef(null)

  // Close the column-visibility menu on outside click / Escape.
  useEffect(() => {
    if (!colMenuOpen) return undefined
    const onKey = (e) => { if (e.key === 'Escape') setColMenuOpen(false) }
    const onClick = (e) => {
      if (colMenuRef.current && !colMenuRef.current.contains(e.target)) setColMenuOpen(false)
    }
    document.addEventListener('keydown', onKey)
    document.addEventListener('mousedown', onClick)
    return () => {
      document.removeEventListener('keydown', onKey)
      document.removeEventListener('mousedown', onClick)
    }
  }, [colMenuOpen])

  // Expandable sub-rows (opt-in via renderSubRow). Prepend a compact expander
  // column so existing column layouts stay untouched when the feature is off.
  const [expanded, setExpanded] = useState({})
  const expandable = typeof renderSubRow === 'function'
  const tableColumns = useMemo(() => {
    if (!expandable) return columns
    const expanderColumn = {
      id: '__expander',
      header: () => null,
      size: 40,
      enableSorting: false,
      cell: ({ row }) =>
        row.getCanExpand() ? (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation()
              row.getToggleExpandedHandler()()
            }}
            aria-label={row.getIsExpanded() ? collapseLabel : expandLabel}
            aria-expanded={row.getIsExpanded()}
            className="flex h-6 w-6 items-center justify-center rounded text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--row-hover-bg)] transition-colors"
          >
            <ChevronRight
              className={`h-4 w-4 transition-transform ${row.getIsExpanded() ? 'rotate-90 text-cyan-400' : ''}`}
              aria-hidden="true"
            />
          </button>
        ) : null,
    }
    return [expanderColumn, ...columns]
  }, [columns, expandable, collapseLabel, expandLabel])

  const table = useReactTable({
    data: data ?? [],
    columns: tableColumns,
    state: {
      sorting,
      pagination: effectivePagination,
      columnFilters,
      globalFilter: effectiveGlobalFilter,
      columnVisibility,
      expanded,
    },
    onSortingChange,
    onPaginationChange: effectiveOnPaginationChange,
    onGlobalFilterChange: globalFilterControlled ? undefined : setInternalGlobalFilter,
    onColumnVisibilityChange: setColumnVisibility,
    onExpandedChange: setExpanded,
    getRowCanExpand: expandable ? (getRowCanExpand ?? (() => true)) : undefined,
    globalFilterFn: globalFilterFn ?? fuzzyGlobalFilter,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
    ...(hidePagination ? {} : { getPaginationRowModel: getPaginationRowModel() }),
    getExpandedRowModel: getExpandedRowModel(),
    initialState: {
      pagination: { pageIndex: 0, pageSize: defaultPageSize },
    },
  })

  const hasToolbar = searchable || exportable || columnToggle || toolbarTitle

  const handleExport = () => {
    const csv = tableToCsv(table)
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${exportFilename}-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  const { rows } = table.getRowModel()
  const colCount = table.getVisibleLeafColumns().length
  const totalFiltered = table.getFilteredRowModel().rows.length
  const pageCount = table.getPageCount()
  const pageIndex = effectivePagination.pageIndex ?? 0
  const pageSize = effectivePagination.pageSize ?? defaultPageSize

  const emptyNode = useMemo(() => {
    if (emptyState == null) {
      return (
        <EmptyState
          icon="inbox"
          title="No data"
          body="Nothing to display yet."
        />
      )
    }
    if (React.isValidElement(emptyState)) return emptyState
    return <EmptyState {...emptyState} />
  }, [emptyState])

  const showEmpty = !loading && data?.length === 0
  const showFilteredEmpty = !loading && data?.length > 0 && rows.length === 0

  if (showEmpty) {
    return <div className={className}>{emptyNode}</div>
  }

  return (
    <div className="flex flex-col gap-2">
      {hasToolbar && (
        <div className="flex flex-wrap items-center gap-2">
          {toolbarTitle && (
            <span className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)] mr-auto">
              {toolbarTitle}
            </span>
          )}
          {searchable && (
            <div className={`relative ${toolbarTitle ? '' : 'mr-auto'} min-w-[180px]`}>
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-muted)] pointer-events-none" aria-hidden />
              <input
                type="search"
                value={effectiveGlobalFilter ?? ''}
                onChange={(e) =>
                  globalFilterControlled ? undefined : setInternalGlobalFilter(e.target.value)
                }
                placeholder={searchPlaceholder}
                aria-label={searchPlaceholder}
                className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg pl-8 pr-3 py-1.5 text-[12px] text-[var(--text-secondary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500/40"
              />
            </div>
          )}
          {columnToggle && (
            <div className="relative" ref={colMenuRef}>
              <button
                type="button"
                onClick={() => setColMenuOpen((v) => !v)}
                aria-haspopup="menu"
                aria-expanded={colMenuOpen}
                className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-[var(--border-default)] text-[11px] font-mono text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:border-[var(--border-strong)]"
              >
                <Columns3 className="w-3.5 h-3.5" aria-hidden />
                Columns
              </button>
              {colMenuOpen && (
                <div
                  role="menu"
                  className="absolute end-0 mt-1 z-30 min-w-[160px] rounded-lg border border-[var(--border-default)] bg-[var(--bg-elevated)] shadow-2xl p-1.5"
                >
                  <div className="flex items-center justify-between px-1.5 pb-1">
                    <span className="text-[9px] font-mono uppercase tracking-widest text-[var(--text-muted)]">Columns</span>
                    <button type="button" onClick={() => setColMenuOpen(false)} aria-label="Close" className="text-[var(--text-muted)] hover:text-[var(--text-primary)]">
                      <X className="w-3 h-3" aria-hidden />
                    </button>
                  </div>
                  {table.getAllLeafColumns().filter((c) => typeof c.accessorFn === 'function').map((col) => (
                    <label key={col.id} className="flex items-center gap-2 px-1.5 py-1 rounded text-[11px] font-mono text-[var(--text-tertiary)] hover:bg-[var(--row-hover-bg)] cursor-pointer">
                      <input type="checkbox" checked={col.getIsVisible()} onChange={col.getToggleVisibilityHandler()} className="accent-cyan-500" />
                      <span className="truncate">
                        {typeof col.columnDef.header === 'string' ? col.columnDef.header : col.id}
                      </span>
                    </label>
                  ))}
                </div>
              )}
            </div>
          )}
          {exportable && (
            <button
              type="button"
              onClick={handleExport}
              disabled={totalFiltered === 0}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-cyan-500/30 bg-cyan-500/5 text-[11px] font-mono text-cyan-300 hover:bg-cyan-500/15 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <Download className="w-3.5 h-3.5" aria-hidden />
              CSV
            </button>
          )}
        </div>
      )}
      <div
        id={id}
        className={`rounded-2xl border border-[var(--border-default)] bg-[var(--table-surface)] backdrop-blur-md overflow-hidden ${className}`}
      >
      <div className="overflow-x-auto custom-scroll max-h-[70vh]">
        <table
          className={`weissman-data-table w-full text-left border-collapse ${tableClassName}`}
        >
          <thead>
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id} className="border-b border-[var(--border)]">
                {headerGroup.headers.map((header) => {
                  const sorted = header.column.getIsSorted()
                  const ariaSort = header.column.getCanSort()
                    ? sorted === 'asc'
                      ? 'ascending'
                      : sorted === 'desc'
                        ? 'descending'
                        : 'none'
                    : undefined
                  return (
                  <th
                    key={header.id}
                    aria-sort={ariaSort}
                    style={{ width: header.getSize() !== 150 ? header.getSize() : undefined }}
                    className={`px-4 py-3 text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] select-none whitespace-nowrap ${
                      stickyHeader ? '' : 'relative'
                    }`}
                  >
                    {header.column.getCanSort() ? (
                      <button
                        type="button"
                        onClick={header.column.getToggleSortingHandler()}
                        className="inline-flex items-center hover:text-[var(--accent-strong)] transition-colors"
                      >
                        {flexRender(header.column.columnDef.header, header.getContext())}
                        <SortIndicator sorted={header.column.getIsSorted()} />
                      </button>
                    ) : (
                      flexRender(header.column.columnDef.header, header.getContext())
                    )}
                  </th>
                  )
                })}
              </tr>
            ))}
          </thead>

          <tbody>
            {loading && rows.length === 0 && (
              <tr>
                <td colSpan={colCount} className="px-4 py-6">
                  <SkeletonTable rows={8} cols={Math.min(colCount, 6)} />
                </td>
              </tr>
            )}

            {showFilteredEmpty && (
              <tr>
                <td
                  colSpan={colCount}
                  className="px-4 py-10 text-center text-[var(--text-muted)] text-xs font-mono"
                >
                  {emptyFilteredMessage}
                </td>
              </tr>
            )}

            {rows.map((row, i) => {
              const accent = getRowAccentColor?.(row.original)
              const rowId = getRowId(row.original)
              const isSelected =
                selectedRowId != null && rowId != null && String(selectedRowId) === String(rowId)
              const rowClasses = [
                'border-b border-[var(--border-subtle)] transition-colors duration-100',
                onRowClick
                  ? 'cursor-pointer weissman-row-hover focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-cyan-400/60'
                  : 'weissman-row-hover',
                zebra ? 'weissman-row-zebra' : '',
                isSelected ? 'bg-cyan-500/[0.08] ring-1 ring-inset ring-cyan-500/25' : '',
              ]
                .filter(Boolean)
                .join(' ')

              const cells = row.getVisibleCells().map((cell) => (
                <td key={cell.id} className="px-4 py-3 align-middle">
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </td>
              ))

              const style = accent
                ? { borderLeftWidth: 2, borderLeftColor: accent, borderLeftStyle: 'solid' }
                : undefined

              // Make clickable rows keyboard-operable (WCAG 2.1 / Section 508):
              // focusable, activated by Enter/Space, announced as a button.
              const interactiveProps = onRowClick
                ? {
                    onClick: () => onRowClick(row),
                    role: 'button',
                    tabIndex: 0,
                    'aria-selected': isSelected || undefined,
                    onKeyDown: (e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault()
                        onRowClick(row)
                      }
                    },
                  }
                : {}

              const subRow =
                expandable && row.getIsExpanded() ? (
                  <tr key={`${row.id}-detail`} className="bg-[var(--table-surface)]">
                    <td colSpan={colCount} className="px-4 pb-4 pt-0 align-top">
                      {renderSubRow(row.original, row)}
                    </td>
                  </tr>
                ) : null

              const mainRow = animateRows ? (
                <motion.tr
                  key={row.id}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ duration: 0.12, delay: Math.min(i * 0.012, 0.25) }}
                  className={rowClasses}
                  style={style}
                  {...interactiveProps}
                >
                  {cells}
                </motion.tr>
              ) : (
                <tr key={row.id} className={rowClasses} style={style} {...interactiveProps}>
                  {cells}
                </tr>
              )

              if (!subRow) return mainRow
              return (
                <React.Fragment key={row.id}>
                  {mainRow}
                  {subRow}
                </React.Fragment>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination bar */}
      {!hidePagination && (
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-t border-[var(--border-subtle)] bg-[var(--bg-1)]">
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono text-[var(--text-muted)]">Rows:</span>
          <select
            value={pageSize}
            onChange={(e) =>
              effectiveOnPaginationChange({ pageIndex: 0, pageSize: Number(e.target.value) })
            }
              className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded px-1.5 py-0.5 text-[11px] font-mono text-[var(--text-secondary)] focus:outline-none focus:border-cyan-500/40"
            >
              {pageSizes.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <span className="text-[10px] font-mono text-[var(--text-muted)] tabular-nums">
              {totalFiltered === 0
                ? '0'
                : `${pageIndex * pageSize + 1}–${Math.min(
                    (pageIndex + 1) * pageSize,
                    totalFiltered,
                  )}`}{' '}
              of {totalFiltered}
            </span>
          </div>

          <div className="flex items-center gap-1.5">
            <PaginationBtn
              onClick={() => table.setPageIndex(0)}
              disabled={!table.getCanPreviousPage()}
              label="First page"
            >
              «
            </PaginationBtn>
            <PaginationBtn
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
              label="Previous page"
            >
              ‹
            </PaginationBtn>

            {Array.from({ length: Math.min(pageCount, MAX_VISIBLE_PAGES) }, (_, i) => {
              const startPage = Math.max(
                0,
                Math.min(pageIndex - 3, pageCount - MAX_VISIBLE_PAGES),
              )
              const p = startPage + i
              if (p >= pageCount) return null
              const active = p === pageIndex
              return (
                <button
                  key={p}
                  type="button"
                  onClick={() => table.setPageIndex(p)}
                  className="px-2.5 py-1 rounded text-[10px] font-mono border transition-colors tabular-nums"
                  style={
                    active
                      ? {
                          borderColor: 'rgba(34, 211, 238, 0.35)',
                          color: '#22d3ee',
                          backgroundColor: 'rgba(34, 211, 238, 0.1)',
                        }
                      : {
                          borderColor: 'var(--border-default)',
                          color: 'var(--text-muted)',
                        }
                  }
                >
                  {p + 1}
                </button>
              )
            })}

            <PaginationBtn
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
              label="Next page"
            >
              ›
            </PaginationBtn>
            <PaginationBtn
              onClick={() => table.setPageIndex(pageCount - 1)}
              disabled={!table.getCanNextPage()}
              label="Last page"
            >
              »
            </PaginationBtn>
          </div>
        </div>
      )}
      </div>
    </div>
  )
}

function PaginationBtn({ children, onClick, disabled, label }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-label={label}
      className="px-2 py-1 rounded text-[10px] font-mono border border-[var(--border-default)] text-[var(--text-muted)] hover:text-[var(--text-secondary)] hover:border-[var(--border-strong)] disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
    >
      {children}
    </button>
  )
}

export { SortIndicator }
