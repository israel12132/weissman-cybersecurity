import { forwardRef } from 'react'
import { cn } from '../../lib/cn'

const DOT_VARIANT = {
  default: 'bg-border-strong',
  success: 'bg-status-active',
  warning: 'bg-severity-medium',
  danger: 'bg-severity-critical',
  info: 'bg-severity-info',
  accent: 'bg-accent-cyan',
}

/**
 * Vertical event timeline. Renders an ordered list of events, each with a
 * status-coloured node on a connecting rail and title / description / timestamp.
 * Used by the finding detail drawer, WarRoom replay, and audit trail.
 *
 * @param {Array<{id?:string|number,title:React.ReactNode,description?:React.ReactNode,
 *   timestamp?:React.ReactNode,icon?:React.ReactNode,variant?:string}>} items
 * @param {boolean} [dense=false] — tighter vertical rhythm
 * @param {string} [emptyMessage='No events']
 */
const Timeline = forwardRef(function Timeline(
  { items = [], dense = false, emptyMessage = 'No events', className, ...props },
  ref,
) {
  if (!Array.isArray(items) || items.length === 0) {
    return (
      <p ref={ref} className={cn('text-xs text-text-muted', className)} {...props}>
        {emptyMessage}
      </p>
    )
  }

  return (
    <ol ref={ref} className={cn('relative', className)} {...props}>
      {items.map((item, i) => {
        const isLast = i === items.length - 1
        const dot = DOT_VARIANT[item.variant] ?? DOT_VARIANT.default
        return (
          <li key={item.id ?? i} className="flex gap-3">
            {/* Rail: node + connecting line (omitted on the last item). */}
            <div className="flex flex-col items-center">
              {item.icon ? (
                <span
                  className={cn(
                    'inline-flex size-5 shrink-0 items-center justify-center rounded-full',
                    'text-text-inverse ring-2 ring-bg-1 [&>svg]:size-3',
                    dot,
                  )}
                  aria-hidden="true"
                >
                  {item.icon}
                </span>
              ) : (
                <span
                  className={cn('mt-1 size-2.5 shrink-0 rounded-full ring-2 ring-bg-1', dot)}
                  aria-hidden="true"
                />
              )}
              {!isLast && <span className="w-px flex-1 bg-border-subtle" aria-hidden="true" />}
            </div>

            {/* Content */}
            <div className={cn('min-w-0 flex-1', dense ? 'pb-3' : 'pb-5')}>
              <div className="flex flex-wrap items-baseline justify-between gap-x-2 gap-y-0.5">
                <span className="text-sm font-medium text-text-primary">{item.title}</span>
                {item.timestamp != null && (
                  <span className="text-[10px] uppercase tracking-wide text-text-muted">
                    {item.timestamp}
                  </span>
                )}
              </div>
              {item.description != null && (
                <p className="mt-0.5 text-xs leading-relaxed text-text-tertiary">
                  {item.description}
                </p>
              )}
            </div>
          </li>
        )
      })}
    </ol>
  )
})

Timeline.displayName = 'Timeline'

export default Timeline
export { Timeline }
