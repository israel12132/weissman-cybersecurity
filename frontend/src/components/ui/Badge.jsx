import { cn } from '../../lib/cn'

const SEVERITY_STYLES = {
  critical: 'bg-severity-critical-bg text-severity-critical border-severity-critical-border',
  high: 'bg-severity-high-bg text-severity-high border-severity-high-border',
  medium: 'bg-severity-medium-bg text-severity-medium border-severity-medium-border',
  low: 'bg-severity-low-bg text-severity-low border-severity-low-border',
  info: 'bg-severity-info-bg text-severity-info border-severity-info-border',
}

const STATUS_STYLES = {
  active: 'bg-status-active-bg text-status-active border-status-active/30',
  pending: 'bg-status-pending-bg text-status-pending border-status-pending/30',
  resolved: 'bg-status-resolved-bg text-status-resolved border-status-resolved/30',
  offline: 'bg-status-offline-bg text-status-offline border-status-offline/30',
  error: 'bg-status-error-bg text-status-error border-status-error/30',
  warning: 'bg-severity-medium-bg text-severity-medium border-severity-medium-border',
}

const INTEL_STYLES = {
  kev: 'bg-kev-bg text-kev border-kev-border shadow-kev-glow font-semibold',
  'epss-high': 'bg-epss-high-bg text-epss-high border-epss-high-border',
  'epss-mid': 'bg-epss-mid-bg text-epss-mid border-epss-mid/30',
  'epss-low': 'bg-epss-low-bg text-epss-low border-epss-low/30',
}

const SIZES = {
  sm: 'px-1.5 py-0.5 text-[10px] gap-1 rounded-sm',
  md: 'px-2 py-0.5 text-xs gap-1 rounded-md',
  lg: 'px-2.5 py-1 text-sm gap-1.5 rounded-md',
}

/**
 * Unified badge primitive for severity, status, and intel (KEV/EPSS) labels.
 *
 * @param {'severity'|'status'|'kev'|'epss'} kind
 * @param {string} value — severity level, status name, or epss tier
 * @param {'sm'|'md'|'lg'} size
 * @param {boolean} dot — leading status indicator dot
 * @param {boolean} mono — use JetBrains Mono for data values
 */
export default function Badge({
  kind = 'severity',
  value = 'info',
  size = 'md',
  dot = false,
  mono = false,
  className,
  children,
  ...props
}) {
  const normalized = String(value).toLowerCase()

  let styleClasses = SEVERITY_STYLES.info

  if (kind === 'severity') {
    styleClasses = SEVERITY_STYLES[normalized] ?? SEVERITY_STYLES.info
  } else if (kind === 'status') {
    styleClasses = STATUS_STYLES[normalized] ?? STATUS_STYLES.offline
  } else if (kind === 'kev') {
    styleClasses = INTEL_STYLES.kev
  } else if (kind === 'epss') {
    const epssKey = normalized.startsWith('epss-') ? normalized : `epss-${normalized}`
    styleClasses = INTEL_STYLES[epssKey] ?? INTEL_STYLES['epss-mid']
  }

  const label = children ?? formatLabel(kind, normalized)

  return (
    <span
      className={cn(
        'inline-flex items-center border font-sans font-medium',
        'tracking-wide uppercase',
        'transition-colors duration-fast',
        SIZES[size] ?? SIZES.md,
        styleClasses,
        mono && 'font-mono normal-case tracking-normal',
        className,
      )}
      {...props}
    >
      {dot && (
        <span
          className="size-1.5 shrink-0 rounded-full bg-current opacity-80"
          aria-hidden="true"
        />
      )}
      {label}
    </span>
  )
}

function formatLabel(kind, value) {
  if (kind === 'kev') return 'KEV'
  if (kind === 'epss') {
    if (value.includes('high')) return 'EPSS High'
    if (value.includes('low')) return 'EPSS Low'
    return 'EPSS'
  }
  return value
}

export { Badge, SEVERITY_STYLES, STATUS_STYLES, INTEL_STYLES }
