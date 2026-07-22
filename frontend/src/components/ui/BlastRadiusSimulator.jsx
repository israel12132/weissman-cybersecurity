import { useId, useMemo, useState } from 'react'
import { cn } from '../../lib/cn'
import BlastRadius from './BlastRadius.jsx'

const LIKELIHOOD = [
  { value: '0.5', label: 'Low' },
  { value: '1', label: 'Expected' },
  { value: '2', label: 'High' },
]

/**
 * BlastRadiusSimulator — interactive what-if financial exposure modelling. Drag
 * the mitigation coverage and pick a likelihood scenario to see SLE/ALE and
 * crown-jewel exposure recompute live, with the annualized savings vs the
 * un-mitigated baseline. Composes the BlastRadius primitive.
 *
 * @param {number} baseSle @param {number} baseAle
 * @param {Array<{name,value}>} [crownJewels] @param {string} [currency='USD']
 */
export default function BlastRadiusSimulator({
  baseSle = 0,
  baseAle = 0,
  crownJewels = [],
  currency = 'USD',
  className,
  ...props
}) {
  const uid = useId()
  const [mitigation, setMitigation] = useState(0)
  const [likelihood, setLikelihood] = useState('1')

  const factor = 1 - mitigation / 100
  const likelihoodFactor = Number(likelihood) || 1

  const { sle, ale, jewels, savings } = useMemo(() => {
    const s = baseSle * factor
    const a = baseAle * factor * likelihoodFactor
    return {
      sle: s,
      ale: a,
      jewels: crownJewels.map((j) => ({ ...j, value: (Number(j.value) || 0) * factor })),
      savings: Math.max(0, baseAle * likelihoodFactor - a),
    }
  }, [baseSle, baseAle, crownJewels, factor, likelihoodFactor])

  const fmt = useMemo(
    () => new Intl.NumberFormat(undefined, { style: 'currency', currency, maximumFractionDigits: 0 }),
    [currency],
  )

  return (
    <div className={cn('flex flex-col gap-4', className)} {...props}>
      <div className="flex flex-col gap-3 rounded-xl border border-border-default bg-bg-2 p-4 sm:flex-row sm:items-end sm:gap-6">
        <label htmlFor={`${uid}-mit`} className="flex-1">
          <span className="mb-1 flex items-center justify-between text-xs text-text-secondary">
            <span>Mitigation coverage</span>
            <span className="tabular-nums text-text-primary">{mitigation}%</span>
          </span>
          <input
            id={`${uid}-mit`}
            type="range"
            min={0}
            max={100}
            step={5}
            value={mitigation}
            onChange={(e) => setMitigation(Number(e.target.value))}
            className="w-full accent-[color:var(--accent-cyan)]"
          />
        </label>
        <label htmlFor={`${uid}-lik`} className="flex flex-col gap-1 text-xs text-text-secondary">
          <span>Threat likelihood</span>
          <select
            id={`${uid}-lik`}
            value={likelihood}
            onChange={(e) => setLikelihood(e.target.value)}
            className="rounded-lg border border-border-default bg-bg-1 px-2.5 py-1.5 text-sm text-text-primary outline-none focus-visible:shadow-[var(--focus-ring)]"
          >
            {LIKELIHOOD.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      <BlastRadius sle={sle} ale={ale} currency={currency} crownJewels={jewels} title="Projected exposure" />

      <div
        className="flex items-center justify-between rounded-xl border border-status-active/30 bg-status-active-bg px-4 py-3"
        aria-live="polite"
      >
        <span className="text-xs uppercase tracking-widest text-text-muted">Annualized savings vs baseline</span>
        <span className="font-display text-lg font-semibold text-status-active tabular-nums" data-testid="savings">
          {fmt.format(savings)}
        </span>
      </div>
    </div>
  )
}

export { BlastRadiusSimulator }
