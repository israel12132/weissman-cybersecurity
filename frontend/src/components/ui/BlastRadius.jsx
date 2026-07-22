import { forwardRef } from 'react'
import { Crosshair } from 'lucide-react'
import { cn } from '../../lib/cn'

const CAPTION = 'text-[10px] font-medium uppercase tracking-widest text-text-muted'

/** Coerce any input to a finite number, defaulting to 0. */
function toNumber(v) {
  const n = Number(v)
  return Number.isFinite(n) ? n : 0
}

/** Build a currency formatter, degrading to a plain decimal on a bad code. */
function makeFormatter(currency) {
  try {
    return new Intl.NumberFormat(undefined, {
      style: 'currency',
      currency,
      maximumFractionDigits: 0,
    })
  } catch {
    return new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 })
  }
}

/**
 * BlastRadius — financial exposure visualization. Renders headline SLE / ALE
 * figures plus a proportional "crown jewels" exposure list. Presentational
 * only: every value is caller-provided and formatted deterministically.
 *
 * @param {number} [sle=0] — Single Loss Expectancy
 * @param {number} [ale=0] — Annualized Loss Expectancy
 * @param {string} [currency='USD'] — ISO 4217 code for Intl currency formatting
 * @param {Array<{name:string,value:number}>} [crownJewels=[]] — mapped assets
 * @param {string} [title='Financial blast radius'] — region accessible name
 */
const BlastRadius = forwardRef(function BlastRadius(
  {
    sle = 0,
    ale = 0,
    currency = 'USD',
    crownJewels = [],
    title = 'Financial blast radius',
    className,
    ...props
  },
  ref,
) {
  const fmt = makeFormatter(currency)
  const jewels = Array.isArray(crownJewels) ? crownJewels : []
  const values = jewels.map((j) => toNumber(j?.value))
  // Guard divide-by-zero so an all-zero (or empty) list never scales by 0.
  const maxValue = Math.max(1, ...values)

  return (
    <section
      ref={ref}
      aria-label={title}
      className={cn(
        'flex flex-col gap-4 rounded-xl border border-border-default bg-bg-2 p-5',
        className,
      )}
      {...props}
    >
      <header className="flex items-center gap-2">
        <Crosshair className="size-4 text-severity-critical" aria-hidden="true" />
        <h3 className="font-display text-sm font-semibold tracking-tight text-text-primary">
          {title}
        </h3>
      </header>

      <dl className="grid grid-cols-2 gap-4">
        <div className="flex flex-col gap-1">
          <dt className={CAPTION}>Single loss (SLE)</dt>
          <dd className="font-display text-2xl font-semibold leading-none tabular-nums text-text-primary">
            {fmt.format(toNumber(sle))}
          </dd>
        </div>
        <div className="flex flex-col gap-1">
          <dt className={CAPTION}>Annualized loss (ALE)</dt>
          <dd className="font-display text-2xl font-semibold leading-none tabular-nums text-severity-critical">
            {fmt.format(toNumber(ale))}
          </dd>
        </div>
      </dl>

      <div className="flex flex-col gap-2 border-t border-border-subtle pt-4">
        <p className={CAPTION}>Crown jewels</p>
        {jewels.length === 0 ? (
          <p className="text-sm text-text-muted">No crown jewels mapped</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {jewels.map((jewel, i) => {
              const value = toNumber(jewel?.value)
              const pct = Math.max(0, Math.min(100, (value / maxValue) * 100))
              return (
                <li
                  key={jewel?.name ?? i}
                  className="grid grid-cols-[minmax(0,1fr)_minmax(0,1.5fr)_auto] items-center gap-3"
                >
                  <span className="truncate text-sm text-text-secondary">
                    {jewel?.name}
                  </span>
                  <span className="h-2 overflow-hidden rounded-full bg-bg-3">
                    <span
                      className="block h-full rounded-full bg-severity-critical/70"
                      style={{ width: `${pct}%` }}
                    />
                  </span>
                  <span className="text-end text-sm tabular-nums text-text-primary">
                    {fmt.format(value)}
                  </span>
                </li>
              )
            })}
          </ul>
        )}
      </div>
    </section>
  )
})

BlastRadius.displayName = 'BlastRadius'

export default BlastRadius
export { BlastRadius }
