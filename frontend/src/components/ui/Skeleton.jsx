import React from 'react'

/**
 * Single skeleton bar. Combine for cards / tables. Accepts standard width / height props.
 */
export function SkeletonBar({ className = '', style }) {
  return (
    <div
      className={`bg-white/5 rounded animate-pulse ${className}`}
      style={style}
      aria-hidden="true"
    />
  )
}

/** A predefined "loading table" of N rows × M columns. */
export function SkeletonTable({ rows = 6, cols = 4, className = '' }) {
  return (
    <div className={`space-y-2 ${className}`} aria-busy="true" aria-live="polite">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex gap-3">
          {Array.from({ length: cols }).map((_, c) => (
            <SkeletonBar
              key={c}
              className="h-4"
              style={{ flex: c === 0 ? 2 : 1, opacity: 1 - r * 0.08 }}
            />
          ))}
        </div>
      ))}
    </div>
  )
}

/** A predefined "loading card" — header line + 4 short rows. */
export function SkeletonCard({ className = '' }) {
  return (
    <div className={`rounded-2xl border border-white/10 p-5 bg-black/30 ${className}`} aria-busy="true">
      <SkeletonBar className="h-5 w-40 mb-4" />
      <SkeletonBar className="h-3 w-full mb-2" />
      <SkeletonBar className="h-3 w-5/6 mb-2" />
      <SkeletonBar className="h-3 w-4/6 mb-2" />
      <SkeletonBar className="h-3 w-3/6" />
    </div>
  )
}
