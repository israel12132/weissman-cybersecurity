
/**
 * Single skeleton bar with shimmer animation.
 */
export function SkeletonBar({ className = '', style, shimmer = true }) {
  return (
    <div
      className={`rounded ${shimmer ? 'skeleton-shimmer' : 'bg-[var(--skeleton-bg)] animate-pulse'} ${className}`}
      style={style}
      aria-hidden="true"
    />
  )
}

/** A predefined loading table of N rows × M columns. */
export function SkeletonTable({ rows = 6, cols = 4, className = '' }) {
  return (
    <div className={`space-y-2.5 ${className}`} aria-busy="true" aria-live="polite">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex gap-3">
          {Array.from({ length: cols }).map((_, c) => (
            <SkeletonBar
              key={c}
              className="h-4"
              style={{ flex: c === 0 ? 2 : 1, opacity: Math.max(0.35, 1 - r * 0.07) }}
            />
          ))}
        </div>
      ))}
    </div>
  )
}

/** A predefined loading card — header line + body rows. */
export function SkeletonCard({ className = '', lines = 4 }) {
  return (
    <div
      className={`rounded-2xl border border-[var(--border-default)] p-5 bg-[var(--bg-2)] ${className}`}
      aria-busy="true"
    >
      <SkeletonBar className="h-5 w-40 mb-4" />
      {Array.from({ length: lines }).map((_, i) => (
        <SkeletonBar
          key={i}
          className="h-3 mb-2"
          style={{ width: `${100 - i * 12}%` }}
        />
      ))}
    </div>
  )
}

/** Skeleton row mimicking a data table row. */
export function SkeletonRow({ cols = 5, className = '' }) {
  return (
    <div className={`flex gap-3 py-2 ${className}`}>
      {Array.from({ length: cols }).map((_, c) => (
        <SkeletonBar key={c} className="h-4 flex-1" style={{ flex: c === 0 ? 0.8 : 1 }} />
      ))}
    </div>
  )
}

/** Grid of executive widget placeholders. */
export function SkeletonWidgetGrid({ count = 4, className = '' }) {
  return (
    <div className={`grid grid-cols-2 lg:grid-cols-4 gap-3 ${className}`} aria-busy="true">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="rounded-2xl border border-[var(--border-subtle)] p-5 bg-[var(--table-surface)]">
          <SkeletonBar className="h-3 w-24 mb-4" />
          <SkeletonBar className="h-8 w-32 mb-2" />
          <SkeletonBar className="h-3 w-full" />
        </div>
      ))}
    </div>
  )
}

/** Client card grid skeleton. */
export function SkeletonCardGrid({ count = 3, className = '' }) {
  return (
    <div className={`grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5 ${className}`} aria-busy="true">
      {Array.from({ length: count }).map((_, i) => (
        <SkeletonCard key={i} lines={3} />
      ))}
    </div>
  )
}

export default SkeletonBar
