import React from 'react'

/** Unified severity metadata — single source of truth for SOC screens. */
export const SEVERITY_META = {
  critical: {
    color: 'var(--sev-critical)',
    bg: 'var(--sev-critical-bg)',
    border: 'var(--sev-critical-border)',
    label: 'Critical',
    order: 0,
  },
  high: {
    color: 'var(--sev-high)',
    bg: 'var(--sev-high-bg)',
    border: 'var(--sev-high-border)',
    label: 'High',
    order: 1,
  },
  medium: {
    color: 'var(--sev-medium)',
    bg: 'var(--sev-medium-bg)',
    border: 'var(--sev-medium-border)',
    label: 'Medium',
    order: 2,
  },
  low: {
    color: 'var(--sev-low)',
    bg: 'var(--sev-low-bg)',
    border: 'var(--sev-low-border)',
    label: 'Low',
    order: 3,
  },
  info: {
    color: 'var(--sev-info)',
    bg: 'var(--sev-info-bg)',
    border: 'var(--sev-info-border)',
    label: 'Info',
    order: 4,
  },
}

const UNKNOWN_SEVERITY_ORDER = 5

export function getSeverityMeta(severity) {
  const key = (severity || 'info').toLowerCase()
  return SEVERITY_META[key] ?? SEVERITY_META.info
}

export function getSeverityOrder(severity) {
  const key = (severity || '').toLowerCase()
  return SEVERITY_META[key]?.order ?? UNKNOWN_SEVERITY_ORDER
}

/**
 * Unified severity pill used across all SOC screens.
 *
 * Props:
 *  - severity: critical | high | medium | low | info
 *  - size: 'sm' | 'md' (default sm)
 *  - showDot: optional leading indicator dot
 *  - className
 */
export default function SeverityBadge({
  severity,
  size = 'sm',
  showDot = false,
  className = '',
}) {
  const meta = getSeverityMeta(severity)
  const sizeClass =
    size === 'md'
      ? 'px-2.5 py-1 text-[11px]'
      : 'px-2 py-0.5 text-[10px]'

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded font-bold uppercase tracking-wider font-mono border ${sizeClass} ${className}`}
      style={{
        color: meta.color,
        backgroundColor: meta.bg,
        borderColor: meta.border,
      }}
    >
      {showDot && (
        <span
          className="w-1.5 h-1.5 rounded-full shrink-0"
          style={{ backgroundColor: meta.color }}
          aria-hidden="true"
        />
      )}
      {meta.label}
    </span>
  )
}
