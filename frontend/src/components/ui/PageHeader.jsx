import React from 'react'
import { ChevronRight } from 'lucide-react'
import { cn } from '../../lib/cn'

/**
 * Page-level header with title, subtitle, breadcrumbs slot, and actions slot.
 *
 * @param {string} title
 * @param {string} subtitle
 * @param {React.ReactNode} breadcrumbs — custom breadcrumb trail; overrides `crumbs` prop
 * @param {Array<{label: string, href?: string, onClick?: () => void}>} crumbs — auto-rendered trail
 * @param {React.ReactNode} actions — right-aligned action buttons / controls
 * @param {'default'|'compact'} size
 */
export default function PageHeader({
  title,
  subtitle,
  breadcrumbs,
  crumbs = [],
  actions,
  size = 'default',
  className,
  ...props
}) {
  const isCompact = size === 'compact'

  return (
    <header
      className={cn(
        'flex flex-col gap-3',
        'border-b border-border-subtle',
        isCompact ? 'pb-4 mb-5' : 'pb-6 mb-6',
        className,
      )}
      {...props}
    >
      {(breadcrumbs || crumbs.length > 0) && (
        <nav aria-label="Breadcrumb" className="flex items-center min-w-0">
          {breadcrumbs ?? <BreadcrumbTrail crumbs={crumbs} />}
        </nav>
      )}

      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 flex-1">
          {title && (
            <h1
              className={cn(
                'font-display font-semibold text-text-primary tracking-tight truncate',
                isCompact ? 'text-xl' : 'text-2xl',
              )}
            >
              {title}
            </h1>
          )}
          {subtitle && (
            <p
              className={cn(
                'text-text-tertiary leading-relaxed max-w-2xl',
                isCompact ? 'text-sm mt-1' : 'text-sm mt-1.5',
              )}
            >
              {subtitle}
            </p>
          )}
        </div>

        {actions && (
          <div
            className={cn(
              'flex items-center gap-2 shrink-0',
              'flex-wrap sm:flex-nowrap',
            )}
          >
            {actions}
          </div>
        )}
      </div>
    </header>
  )
}

function BreadcrumbTrail({ crumbs }) {
  return (
    <ol className="flex items-center gap-1 min-w-0 text-xs text-text-muted">
      {crumbs.map((crumb, index) => {
        const isLast = index === crumbs.length - 1
        const key = `${crumb.label}-${index}`

        return (
          <li key={key} className="inline-flex items-center gap-1 min-w-0">
            {index > 0 && (
              <ChevronRight
                className="size-3 shrink-0 text-text-disabled"
                aria-hidden="true"
              />
            )}
            {isLast ? (
              <span
                className="font-medium text-text-secondary truncate"
                aria-current="page"
              >
                {crumb.label}
              </span>
            ) : crumb.href ? (
              <a
                href={crumb.href}
                className={cn(
                  'truncate transition-colors duration-fast',
                  'hover:text-text-accent',
                  'focus-visible:outline-none focus-visible:text-text-accent',
                )}
              >
                {crumb.label}
              </a>
            ) : (
              <button
                type="button"
                onClick={crumb.onClick}
                className={cn(
                  'truncate transition-colors duration-fast',
                  'hover:text-text-accent',
                  'focus-visible:outline-none focus-visible:text-text-accent',
                )}
              >
                {crumb.label}
              </button>
            )}
          </li>
        )
      })}
    </ol>
  )
}

export { PageHeader, BreadcrumbTrail }
