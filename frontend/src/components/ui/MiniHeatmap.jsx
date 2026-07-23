import { forwardRef, Fragment } from 'react'
import { cn } from '../../lib/cn'

const VARIANT_TEXT = {
  accent: 'text-accent-cyan',
  danger: 'text-severity-critical',
  success: 'text-status-active',
  violet: 'text-accent-violet',
}

const numberFmt = new Intl.NumberFormat('en-US', { maximumFractionDigits: 2 })

/** True when data looks like the flat [{row,col,value}] form. */
function isFlatForm(data) {
  return (
    Array.isArray(data) &&
    data.length > 0 &&
    !Array.isArray(data[0]) &&
    typeof data[0] === 'object' &&
    data[0] !== null
  )
}

/** Coerce a value to a finite number, defaulting to 0. */
function toNum(v) {
  const n = Number(v)
  return Number.isFinite(n) ? n : 0
}

/**
 * Normalize either a 2D array or a flat {row,col,value} list into a dense
 * rows×cols matrix of numbers. Missing cells default to 0. Dimensions are
 * inferred from the data shape when not supplied.
 */
function buildMatrix(data, rowsProp, colsProp) {
  if (!Array.isArray(data) || data.length === 0) {
    const r = Math.max(0, rowsProp ?? 0)
    const c = Math.max(0, colsProp ?? 0)
    const matrix = Array.from({ length: r }, () =>
      Array.from({ length: c }, () => 0),
    )
    return { matrix, rows: r, cols: c }
  }

  if (isFlatForm(data)) {
    let maxRow = -1
    let maxCol = -1
    for (const d of data) {
      const r = toNum(d.row)
      const c = toNum(d.col)
      if (r > maxRow) maxRow = r
      if (c > maxCol) maxCol = c
    }
    const rows = Math.max(0, rowsProp ?? maxRow + 1)
    const cols = Math.max(0, colsProp ?? maxCol + 1)
    const matrix = Array.from({ length: rows }, () =>
      Array.from({ length: cols }, () => 0),
    )
    for (const d of data) {
      const r = toNum(d.row)
      const c = toNum(d.col)
      if (r >= 0 && r < rows && c >= 0 && c < cols) {
        matrix[r][c] = toNum(d.value)
      }
    }
    return { matrix, rows, cols }
  }

  // 2D array form.
  const rows = Math.max(0, rowsProp ?? data.length)
  const cols = Math.max(
    0,
    colsProp ??
      data.reduce((m, row) => Math.max(m, Array.isArray(row) ? row.length : 0), 0),
  )
  const matrix = Array.from({ length: rows }, (_, r) =>
    Array.from({ length: cols }, (_, c) =>
      Array.isArray(data[r]) ? toNum(data[r][c]) : 0,
    ),
  )
  return { matrix, rows, cols }
}

/**
 * MiniHeatmap — compact grid heatmap primitive. Presentational.
 *
 * Renders a rows×cols matrix as color-intensity cells. Accepts a 2D number
 * array or a flat `[{row,col,value}]` list. Cell background intensity scales
 * with `(value-lo)/span` via `color-mix` against the variant's `currentColor`.
 * When `onCellClick` is provided cells become focusable buttons.
 *
 * @param {number[][]|Array<{row:number,col:number,value:number}>} data
 * @param {number} [rows] @param {number} [cols] — inferred from data if omitted
 * @param {string[]} [rowLabels=[]] @param {string[]} [colLabels=[]]
 * @param {number} [min] @param {number} [max] — fix the domain (else derived)
 * @param {'accent'|'danger'|'success'|'violet'} [variant='accent']
 * @param {number} [cellSize=16] @param {number} [gap=2]
 * @param {(row:number,col:number,value:number)=>void} [onCellClick]
 * @param {string} [title='Heatmap'] — accessible name for the whole grid
 */
const MiniHeatmap = forwardRef(function MiniHeatmap(
  {
    data = [],
    rows: rowsProp,
    cols: colsProp,
    rowLabels = [],
    colLabels = [],
    min: minProp,
    max: maxProp,
    variant = 'accent',
    cellSize = 16,
    gap = 2,
    onCellClick,
    title = 'Heatmap',
    className,
    ...props
  },
  ref,
) {
  const { matrix, rows, cols } = buildMatrix(data, rowsProp, colsProp)

  const flat = matrix.flat()
  const matrixMin = flat.length ? Math.min(...flat) : 0
  const matrixMax = flat.length ? Math.max(...flat) : 0
  const lo = minProp ?? matrixMin
  const hi = maxProp ?? matrixMax
  const span = hi - lo || 1

  const colorClass = VARIANT_TEXT[variant] ?? VARIANT_TEXT.accent
  const interactive = typeof onCellClick === 'function'
  const hasRowLabels = Array.isArray(rowLabels) && rowLabels.length > 0
  const hasColLabels = Array.isArray(colLabels) && colLabels.length > 0

  const gridStyle = {
    gridTemplateColumns: `${hasRowLabels ? 'auto ' : ''}repeat(${cols}, ${cellSize}px)`,
    gap: `${gap}px`,
  }

  const renderCell = (r, c, value) => {
    const pct = Math.min(100, Math.max(0, ((value - lo) / span) * 100))
    const rowText = rowLabels[r] ?? r
    const colText = colLabels[c] ?? c
    const label = `${rowText},${colText}: ${numberFmt.format(value)}`
    const cellStyle = {
      width: `${cellSize}px`,
      height: `${cellSize}px`,
      backgroundColor: `color-mix(in srgb, currentColor ${pct}%, transparent)`,
    }

    if (interactive) {
      return (
        <button
          key={`cell-${r}-${c}`}
          type="button"
          onClick={() => onCellClick(r, c, value)}
          title={label}
          aria-label={label}
          className={cn(
            'rounded-sm border border-border-subtle',
            'cursor-pointer transition-colors duration-fast',
            'hover:border-border-strong',
            'focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]',
          )}
          style={cellStyle}
        />
      )
    }

    return (
      <div
        key={`cell-${r}-${c}`}
        title={label}
        aria-label={label}
        className="rounded-sm border border-border-subtle"
        style={cellStyle}
      />
    )
  }

  return (
    <div
      ref={ref}
      role={interactive ? 'group' : 'img'}
      aria-label={title}
      className={cn('inline-block', colorClass, className)}
      {...props}
    >
      <div className="grid" style={gridStyle}>
        {hasColLabels && (
          <>
            {hasRowLabels && <span aria-hidden="true" />}
            {Array.from({ length: cols }, (_, c) => (
              <span
                key={`col-${c}`}
                className="self-end truncate text-center text-[10px] leading-none text-text-muted"
                aria-hidden="true"
              >
                {colLabels[c] ?? ''}
              </span>
            ))}
          </>
        )}

        {matrix.map((row, r) => (
          <Fragment key={`row-${r}`}>
            {hasRowLabels && (
              <span
                className="self-center pe-1 text-end text-[10px] leading-none text-text-muted"
                aria-hidden="true"
              >
                {rowLabels[r] ?? ''}
              </span>
            )}
            {row.map((value, c) => renderCell(r, c, value))}
          </Fragment>
        ))}
      </div>
    </div>
  )
})

MiniHeatmap.displayName = 'MiniHeatmap'

export default MiniHeatmap
export { MiniHeatmap }
