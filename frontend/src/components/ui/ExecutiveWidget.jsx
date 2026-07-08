import React from 'react'

/**
 * Executive dashboard metric widget — subtle border, formatted value slot.
 */
export default function ExecutiveWidget({
  label,
  value,
  hint,
  accent = '#22d3ee',
  className = '',
  footer,
}) {
  return (
    <div
      className={`relative overflow-hidden rounded-2xl border p-5 backdrop-blur-md transition-all hover:border-[var(--border-strong)] ${className}`}
      style={{
        borderColor: `${accent}35`,
        background: `linear-gradient(145deg, ${accent}08 0%, rgba(0,0,0,0.35) 55%, rgba(0,0,0,0.5) 100%)`,
        boxShadow: `inset 0 1px 0 ${accent}15, 0 4px 24px rgba(0,0,0,0.25)`,
      }}
    >
      <div
        className="absolute inset-x-0 top-0 h-px opacity-60"
        style={{ background: `linear-gradient(90deg, transparent, ${accent}60, transparent)` }}
        aria-hidden="true"
      />
      <div
        className="text-[10px] font-mono uppercase tracking-[0.14em] mb-2"
        style={{ color: `${accent}cc` }}
      >
        {label}
      </div>
      <div
        className="text-2xl sm:text-[1.75rem] font-bold tabular-nums tracking-tight text-[var(--text-primary)]"
        style={{ textShadow: `0 0 40px ${accent}25` }}
      >
        {value}
      </div>
      {hint && (
        <div className="text-[10px] font-mono text-[var(--text-muted)] mt-1.5 leading-relaxed">{hint}</div>
      )}
      {footer && (
        <div className="text-[10px] font-mono text-[var(--text-muted)] mt-2 pt-2 border-t border-[var(--border-subtle)]">{footer}</div>
      )}
    </div>
  )
}
