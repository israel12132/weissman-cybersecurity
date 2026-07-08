import React from 'react'

/**
 * Pill toggle bar for severity, status, KEV-only, etc.
 *
 * pills: [{ id, label, count?, active, color?, onClick }]
 */
export default function FilterPills({ pills = [], className = '', label }) {
  return (
    <div className={`space-y-2 ${className}`}>
      {label && (
        <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{label}</div>
      )}
      <div className="flex flex-wrap gap-2">
        {pills.map((pill) => {
          const color = pill.color || '#22d3ee'
          const active = !!pill.active
          return (
            <button
              key={pill.id}
              id={pill.id}
              type="button"
              onClick={pill.onClick}
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border text-[11px] font-mono transition-all duration-150 hover:scale-[1.02] active:scale-100"
              style={{
                borderColor: active ? `${color}70` : 'rgba(255,255,255,0.1)',
                backgroundColor: active ? `${color}18` : 'rgba(255,255,255,0.02)',
                color: active ? color : 'rgba(255,255,255,0.55)',
                boxShadow: active ? `0 0 20px ${color}15` : 'none',
              }}
            >
              {pill.dot !== false && (
                <span
                  className="w-1.5 h-1.5 rounded-full shrink-0"
                  style={{
                    backgroundColor: active ? color : 'rgba(255,255,255,0.25)',
                    boxShadow: active ? `0 0 8px ${color}80` : 'none',
                  }}
                  aria-hidden="true"
                />
              )}
              <span>{pill.label}</span>
              {pill.count != null && (
                <span
                  className="tabular-nums text-[10px] px-1.5 py-0.5 rounded-full"
                  style={{
                    backgroundColor: active ? `${color}25` : 'rgba(255,255,255,0.06)',
                    color: active ? color : 'rgba(255,255,255,0.35)',
                  }}
                >
                  {pill.count}
                </span>
              )}
            </button>
          )
        })}
      </div>
    </div>
  )
}
