import { forwardRef, useId } from 'react'
import { cn } from '../../lib/cn'

const VARIANT_TEXT = {
  accent: 'text-accent-cyan',
  violet: 'text-accent-violet',
  success: 'text-status-active',
  warning: 'text-severity-medium',
  danger: 'text-severity-critical',
  critical: 'text-severity-critical',
  info: 'text-severity-info',
  muted: 'text-text-muted',
}

/** Coerce a data point (number | {y} | {value}) to a numeric y. */
function toY(d) {
  if (typeof d === 'number') return d
  if (d && typeof d === 'object') return Number(d.y ?? d.value ?? 0)
  return 0
}

/**
 * Dependency-free SVG sparkline. Renders a compact line or filled-area trend
 * from a numeric series — the trend glyph used by KPI tiles, table cells, and
 * activity feeds. Colour is driven by design tokens via `currentColor`.
 *
 * @param {Array<number|{y?:number,value?:number}>} data — the series
 * @param {number} [width=120] @param {number} [height=32]
 * @param {'line'|'area'} [type='area']
 * @param {'accent'|'violet'|'success'|'warning'|'danger'|'critical'|'info'|'muted'} [variant='accent']
 * @param {number} [strokeWidth=1.5]
 * @param {boolean} [showDot=false] — emphasize the last point
 * @param {number} [min] @param {number} [max] — fix the domain (else derived)
 * @param {string} [label] — accessible name (role=img); omit → decorative (aria-hidden)
 */
const Sparkline = forwardRef(function Sparkline(
  {
    data = [],
    width = 120,
    height = 32,
    type = 'area',
    variant = 'accent',
    strokeWidth = 1.5,
    showDot = false,
    min: minProp,
    max: maxProp,
    label,
    className,
    ...props
  },
  ref,
) {
  const gradientId = useId()
  const series = Array.isArray(data) ? data.map(toY).filter((n) => Number.isFinite(n)) : []
  const pad = Math.max(strokeWidth, 1)
  const innerW = Math.max(1, width - pad * 2)
  const innerH = Math.max(1, height - pad * 2)

  const colorClass = VARIANT_TEXT[variant] ?? VARIANT_TEXT.accent
  const a11y = label
    ? { role: 'img', 'aria-label': label }
    : { 'aria-hidden': 'true' }

  // Nothing to draw — render an empty, sized SVG so layout is stable.
  if (series.length === 0) {
    return (
      <svg
        ref={ref}
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        className={cn(colorClass, className)}
        {...a11y}
        {...props}
      />
    )
  }

  const lo = minProp ?? Math.min(...series)
  const hi = maxProp ?? Math.max(...series)
  const span = hi - lo || 1
  const stepX = series.length > 1 ? innerW / (series.length - 1) : 0

  const points = series.map((v, i) => {
    const x = pad + i * stepX
    // Invert: higher value → smaller y (toward the top).
    const y = pad + innerH - ((v - lo) / span) * innerH
    return [x, y]
  })

  const linePath = points.map(([x, y], i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(2)},${y.toFixed(2)}`).join(' ')
  const baseline = pad + innerH
  const areaPath =
    `M${points[0][0].toFixed(2)},${baseline.toFixed(2)} ` +
    points.map(([x, y]) => `L${x.toFixed(2)},${y.toFixed(2)}`).join(' ') +
    ` L${points[points.length - 1][0].toFixed(2)},${baseline.toFixed(2)} Z`

  const last = points[points.length - 1]

  return (
    <svg
      ref={ref}
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      className={cn(colorClass, className)}
      {...a11y}
      {...props}
    >
      {type === 'area' && (
        <>
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="currentColor" stopOpacity="0.28" />
              <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
            </linearGradient>
          </defs>
          <path d={areaPath} fill={`url(#${gradientId})`} stroke="none" />
        </>
      )}
      <path
        d={linePath}
        fill="none"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        strokeLinejoin="round"
        strokeLinecap="round"
        vectorEffect="non-scaling-stroke"
      />
      {showDot && (
        <circle cx={last[0]} cy={last[1]} r={Math.max(strokeWidth * 1.4, 2)} fill="currentColor" />
      )}
    </svg>
  )
})

Sparkline.displayName = 'Sparkline'

export default Sparkline
export { Sparkline }
