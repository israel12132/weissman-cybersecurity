import { ArrowDown, ArrowUp, Minus } from 'lucide-react'

function DeltaDisplay({ delta, trend }) {
  if (delta == null && !trend) return null

  const resolvedTrend =
    trend ??
    (typeof delta === 'number' ? (delta > 0 ? 'up' : delta < 0 ? 'down' : 'neutral') : 'neutral')

  const value = typeof delta === 'object' ? delta?.value : delta
  if (value == null && !trend) return null

  const colors = {
    up: 'text-emerald-400',
    down: 'text-rose-400',
    neutral: 'text-[var(--text-muted)]',
  }
  const Icon = resolvedTrend === 'up' ? ArrowUp : resolvedTrend === 'down' ? ArrowDown : Minus

  return (
    <span
      className={`inline-flex items-center gap-0.5 text-[11px] font-mono font-medium ${colors[resolvedTrend] ?? colors.neutral}`}
    >
      <Icon className="w-3 h-3" strokeWidth={2.5} />
      {value != null && value !== '' ? String(value) : null}
    </span>
  )
}

/**
 * KPI stat card for SOC dashboards.
 *
 * Props:
 *  - label: metric name
 *  - value: primary number or string
 *  - delta: number or { value } — 24h change
 *  - trend: 'up' | 'down' | 'neutral' — overrides delta direction coloring
 *  - hint: secondary caption below value
 *  - sparkline: React node slot (e.g. mini Recharts chart)
 *  - footer: optional bottom line
 *  - onClick: makes card interactive
 *  - className
 */
export default function StatCard({
  label,
  value,
  delta,
  trend,
  hint,
  sparkline,
  footer,
  onClick,
  className = '',
}) {
  const Wrapper = onClick ? 'button' : 'div'
  const wrapperProps = onClick
    ? { type: 'button', onClick, className: 'text-left w-full' }
    : {}

  return (
    <Wrapper
      {...wrapperProps}
      className={`group rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] backdrop-blur-md p-5 transition-colors ${
        onClick ? 'hover:border-[var(--border-strong)] hover:bg-[var(--row-hover-bg)] cursor-pointer' : ''
      } ${className}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">
            {label}
          </div>
          <div className="flex items-baseline gap-2 mt-2 flex-wrap">
            <div className="text-2xl sm:text-3xl font-bold text-[var(--accent-strong)] tabular-nums tracking-tight">
              {value}
            </div>
            <DeltaDisplay delta={delta} trend={trend} />
          </div>
          {hint && (
            <p className="text-[11px] text-[var(--text-tertiary)] mt-1.5 leading-snug">{hint}</p>
          )}
        </div>
        {sparkline && (
          <div className="shrink-0 w-20 h-10 opacity-80 group-hover:opacity-100 transition-opacity">
            {sparkline}
          </div>
        )}
      </div>
      {footer && (
        <div className="mt-3 pt-3 border-t border-[var(--border-subtle)] text-[10px] font-mono text-[var(--text-muted)]">
          {footer}
        </div>
      )}
    </Wrapper>
  )
}
