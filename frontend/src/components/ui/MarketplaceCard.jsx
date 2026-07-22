import { forwardRef } from 'react'
import { Check, Download, Star } from 'lucide-react'
import { cn } from '../../lib/cn'
import Button from './Button.jsx'

const compact = new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 })

/**
 * MarketplaceCard — a browse/install card for the Engine Marketplace. Shows the
 * engine's identity, rating, install count, and price, with an install action
 * that flips to an installed state.
 *
 * @param {string} name @param {string} description @param {string} [category]
 * @param {string} [version] @param {number} [rating] (0–5) @param {number} [installs]
 * @param {string} [price] — e.g. "Free", "$49/mo" @param {boolean} [installed=false]
 * @param {React.ReactNode} [icon] @param {()=>void} [onInstall] @param {()=>void} [onOpen]
 */
const MarketplaceCard = forwardRef(function MarketplaceCard(
  {
    name,
    description,
    category,
    version,
    rating,
    installs,
    price = 'Free',
    installed = false,
    icon,
    onInstall,
    onOpen,
    className,
    ...props
  },
  ref,
) {
  const roundedRating = Math.round(Number(rating) || 0)

  return (
    <div
      ref={ref}
      className={cn(
        'flex flex-col gap-3 rounded-xl border border-border-default bg-bg-2 p-4',
        'transition-colors duration-normal hover:border-border-strong',
        className,
      )}
      {...props}
    >
      <div className="flex items-start gap-3">
        <span className="inline-flex size-10 shrink-0 items-center justify-center rounded-lg bg-accent-cyan-muted text-accent-cyan [&>svg]:size-5">
          {icon}
        </span>
        <div className="min-w-0 flex-1">
          {onOpen ? (
            <button
              type="button"
              onClick={onOpen}
              className="text-start focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)] rounded"
            >
              <span className="block truncate font-display text-sm font-semibold text-text-primary hover:text-accent-cyan">
                {name}
              </span>
            </button>
          ) : (
            <span className="block truncate font-display text-sm font-semibold text-text-primary">
              {name}
            </span>
          )}
          <div className="mt-0.5 flex items-center gap-2 text-[10px] uppercase tracking-wide text-text-muted">
            {category && <span>{category}</span>}
            {version && <span className="font-mono normal-case tracking-normal">v{version}</span>}
          </div>
        </div>
      </div>

      <p className="line-clamp-2 text-xs leading-relaxed text-text-tertiary">{description}</p>

      <div className="flex items-center gap-3 text-[11px] text-text-muted">
        {rating != null && (
          <span className="inline-flex items-center gap-0.5" aria-label={`Rating ${roundedRating} of 5`}>
            {Array.from({ length: 5 }, (_, i) => (
              <Star
                key={i}
                className={cn('size-3', i < roundedRating ? 'text-severity-medium' : 'text-border-strong')}
                fill={i < roundedRating ? 'currentColor' : 'none'}
                aria-hidden="true"
              />
            ))}
          </span>
        )}
        {installs != null && (
          <span className="inline-flex items-center gap-1">
            <Download className="size-3" aria-hidden="true" />
            {compact.format(installs)}
          </span>
        )}
      </div>

      <div className="mt-auto flex items-center justify-between gap-2 border-t border-border-subtle pt-3">
        <span className="text-sm font-medium text-text-secondary tabular-nums">{price}</span>
        {installed ? (
          <Button size="sm" variant="secondary" leftIcon={<Check />} disabled>
            Installed
          </Button>
        ) : (
          <Button size="sm" leftIcon={<Download />} onClick={onInstall}>
            Install
          </Button>
        )}
      </div>
    </div>
  )
})

MarketplaceCard.displayName = 'MarketplaceCard'

export default MarketplaceCard
export { MarketplaceCard }
