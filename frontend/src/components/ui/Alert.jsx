import { forwardRef } from 'react'
import { AlertTriangle, CheckCircle2, Info, X, XCircle } from 'lucide-react'
import { cn } from '../../lib/cn'

const VARIANTS = {
  info: {
    Icon: Info,
    classes: 'bg-severity-info-bg text-severity-info border-severity-info-border',
  },
  success: {
    Icon: CheckCircle2,
    classes: 'bg-status-active-bg text-status-active border-status-active/30',
  },
  warning: {
    Icon: AlertTriangle,
    classes: 'bg-severity-medium-bg text-severity-medium border-severity-medium-border',
  },
  danger: {
    Icon: XCircle,
    classes: 'bg-severity-critical-bg text-severity-critical border-severity-critical-border',
  },
  neutral: {
    Icon: Info,
    classes: 'bg-bg-2 text-text-secondary border-border-default',
  },
}

/**
 * Inline status banner for surfacing contextual feedback.
 *
 * @param {'info'|'success'|'warning'|'danger'|'neutral'} variant
 * @param {React.ReactNode} title — optional bold heading line
 * @param {React.ReactNode} icon — override node (pass null to suppress)
 * @param {boolean} dismissible — render a trailing dismiss button
 * @param {() => void} onDismiss — called when the dismiss button is clicked
 * @param {React.ReactNode} action — optional action row below the body
 */
const Alert = forwardRef(function Alert(
  {
    variant = 'info',
    title,
    children,
    icon,
    dismissible = false,
    onDismiss,
    action,
    className,
    ...props
  },
  ref,
) {
  const { Icon, classes } = VARIANTS[variant] ?? VARIANTS.info
  const role = variant === 'danger' || variant === 'warning' ? 'alert' : 'status'

  return (
    <div
      ref={ref}
      role={role}
      className={cn(
        'flex items-start gap-3 rounded-lg border p-3.5 text-sm',
        classes,
        className,
      )}
      {...props}
    >
      {icon !== null && (
        <span
          className="mt-0.5 inline-flex shrink-0 [&>svg]:size-4"
          aria-hidden="true"
        >
          {icon ?? <Icon className="size-4" />}
        </span>
      )}

      <div className="min-w-0 flex-1">
        {title && (
          <div className="text-sm font-medium text-text-primary">{title}</div>
        )}
        {children && (
          <div className={cn('text-sm', title && 'mt-0.5')}>{children}</div>
        )}
        {action && (
          <div className="mt-2.5 flex flex-wrap items-center gap-2">{action}</div>
        )}
      </div>

      {dismissible && (
        <button
          type="button"
          onClick={onDismiss}
          aria-label="Dismiss"
          className={cn(
            '-me-1 -mt-1 inline-flex shrink-0 items-center justify-center rounded-md p-1',
            'text-current opacity-70 transition-all duration-fast ease-out-expo',
            'hover:bg-current/10 hover:opacity-100',
            'focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]',
          )}
        >
          <X className="size-3.5" aria-hidden="true" />
        </button>
      )}
    </div>
  )
})

Alert.displayName = 'Alert'

export default Alert
export { Alert }
