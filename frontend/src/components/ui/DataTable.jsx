import React, { useMemo } from 'react'
import { motion } from 'framer-motion'
import {
  useReactTable,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  getPaginationRowModel,
  flexRender,
} from '@tanstack/react-table'
import { ChevronDown, ChevronUp, ChevronsUpDown } from 'lucide-react'
import EmptyState from './EmptyState'
import { SkeletonTable } from './Skeleton'

const MAX_VISIBLE_PAGES = 7
const DEFAULT_PAGE_SIZES = [25, 50, 100]

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
}) {
  const table = useReactTable({
    data: data ?? [],
    columns,
    state: {
      sorting,
      pagination,
      columnFilters,
      globalFilter,
    },
    onSortingChange,
    onPaginationChange,
    globalFilterFn,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
  })

  const { rows } = table.getRowModel()
  const totalFiltered = table.getFilteredRowModel().rows.length
  const pageCount = table.getPageCount()
  const pageIndex = pagination?.pageIndex ?? 0
  const pageSize = pagination?.pageSize ?? pageSizes[0]

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
    <div
      id={id}
      className={`rounded-2xl border border-white/10 bg-black/30 backdrop-blur-md overflow-hidden ${className}`}
    >
      <div className="overflow-x-auto custom-scroll max-h-[70vh]">
        <table
          className={`weissman-data-table w-full text-left border-collapse ${tableClassName}`}
        >
          <thead>
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id} className="border-b border-[var(--border)]">
                {headerGroup.headers.map((header) => (
                  <th
                    key={header.id}
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
                ))}
              </tr>
            ))}
          </thead>

          <tbody>
            {loading && rows.length === 0 && (
              <tr>
                <td colSpan={columns.length} className="px-4 py-6">
                  <SkeletonTable rows={8} cols={Math.min(columns.length, 6)} />
                </td>
              </tr>
            )}

            {showFilteredEmpty && (
              <tr>
                <td
                  colSpan={columns.length}
                  className="px-4 py-10 text-center text-[var(--text-muted)] text-xs font-mono"
                >
                  {emptyFilteredMessage}
                </td>
              </tr>
            )}

            {rows.map((row, i) => {
              const accent = getRowAccentColor?.(row.original)
              const rowClasses = [
                'border-b border-white/5 transition-colors duration-100',
                onRowClick ? 'cursor-pointer weissman-row-hover' : 'weissman-row-hover',
                zebra ? 'weissman-row-zebra' : '',
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

              if (animateRows) {
                return (
                  <motion.tr
                    key={row.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ duration: 0.12, delay: Math.min(i * 0.012, 0.25) }}
                    onClick={onRowClick ? () => onRowClick(row) : undefined}
                    className={rowClasses}
                    style={style}
                  >
                    {cells}
                  </motion.tr>
                )
              }

              return (
                <tr
                  key={row.id}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  className={rowClasses}
                  style={style}
                >
                  {cells}
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination bar */}
      {(pagination != null || onPaginationChange) && (
        <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 border-t border-white/5 bg-white/[0.01]">
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono text-white/35">Rows:</span>
            <select
              value={pageSize}
              onChange={(e) =>
                onPaginationChange?.({ pageIndex: 0, pageSize: Number(e.target.value) })
              }
              className="bg-black/50 border border-white/10 rounded px-1.5 py-0.5 text-[11px] font-mono text-white/60 focus:outline-none focus:border-cyan-500/40"
            >
              {pageSizes.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <span className="text-[10px] font-mono text-white/30 tabular-nums">
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
                          borderColor: 'rgba(255,255,255,0.08)',
                          color: 'rgba(255,255,255,0.35)',
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
  )
}

function PaginationBtn({ children, onClick, disabled, label }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-label={label}
      className="px-2 py-1 rounded text-[10px] font-mono border border-white/10 text-white/40 hover:text-white/70 hover:border-white/20 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
    >
      {children}
    </button>
  )
}

export { SortIndicator }
