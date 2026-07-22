import { forwardRef } from 'react'
import { Sparkles, TrendingUp } from 'lucide-react'
import { cn } from '../../lib/cn'
import Skeleton from './Skeleton.jsx'

const LEVEL_TEXT = {
  high: 'text-severity-critical',
  medium: 'text-severity-medium',
  low: 'text-severity-low',
}
const LEVEL_DOT = {
  high: 'bg-severity-critical',
  medium: 'bg-severity-medium',
  low: 'bg-severity-low',
}

function Chip({ caption, level }) {
  const key = String(level || '').toLowerCase()
  return (
    <span className="inline-flex items-center gap-1.5 rounded-lg border border-border-default bg-bg-2 px-2.5 py-1">
      <span className="text-[10px] uppercase tracking-widest text-text-muted">{caption}</span>
      <span className={cn('text-xs font-medium capitalize', LEVEL_TEXT[key] ?? 'text-text-secondary')}>
        {level ?? '—'}
      </span>
    </span>
  )
}

/**
 * RiskExplanation — an LLM-authored explanation of why a finding is risky, in
 * business terms. Presentational (FE-surface): pass the model output as props;
 * wire the generator to your LLM endpoint.
 *
 * @param {React.ReactNode} narrative — the business-risk explanation
 * @param {'high'|'medium'|'low'} [likelihood] @param {'high'|'medium'|'low'} [impact]
 * @param {Array<{label:React.ReactNode,level?:'high'|'medium'|'low'}>} [factors]
 * @param {React.ReactNode} [recommendation] @param {string} [generatedBy='Ask Weissman']
 * @param {boolean} [loading=false]
 */
const RiskExplanation = forwardRef(function RiskExplanation(
  {
    narrative,
    likelihood,
    impact,
    factors = [],
    recommendation,
    generatedBy = 'Ask Weissman',
    loading = false,
    className,
    ...props
  },
  ref,
) {
  return (
    <section
      ref={ref}
      aria-label="AI risk explanation"
      className={cn(
        'flex flex-col gap-3 rounded-xl border border-border-accent-violet bg-bg-2 p-4',
        'shadow-glow-violet',
        className,
      )}
      {...props}
    >
      <div className="flex items-center gap-2">
        <span className="inline-flex size-6 items-center justify-center rounded-md bg-accent-violet-muted text-accent-violet">
          <Sparkles className="size-3.5" aria-hidden="true" />
        </span>
        <h3 className="text-sm font-semibold text-text-primary">Why this matters</h3>
        <span className="ms-auto text-[10px] uppercase tracking-widest text-text-muted">{generatedBy}</span>
      </div>

      {loading ? (
        <div className="space-y-2">
          <Skeleton className="h-3 w-full" />
          <Skeleton className="h-3 w-5/6" />
          <Skeleton className="h-3 w-2/3" />
        </div>
      ) : (
        <>
          {narrative != null && (
            <p className="text-sm leading-relaxed text-text-secondary">{narrative}</p>
          )}

          {(likelihood != null || impact != null) && (
            <div className="flex flex-wrap gap-2">
              {likelihood != null && <Chip caption="Likelihood" level={likelihood} />}
              {impact != null && <Chip caption="Impact" level={impact} />}
            </div>
          )}

          {factors.length > 0 && (
            <ul className="flex flex-col gap-1.5">
              {factors.map((f, i) => (
                <li key={i} className="flex items-center gap-2 text-xs text-text-tertiary">
                  <span
                    className={cn('size-1.5 shrink-0 rounded-full', LEVEL_DOT[String(f.level || '').toLowerCase()] ?? 'bg-border-strong')}
                    aria-hidden="true"
                  />
                  {f.label}
                </li>
              ))}
            </ul>
          )}

          {recommendation != null && (
            <div className="flex items-start gap-2 rounded-lg border border-border-subtle bg-bg-1 p-3">
              <TrendingUp className="mt-0.5 size-4 shrink-0 text-accent-cyan" aria-hidden="true" />
              <p className="text-xs leading-relaxed text-text-secondary">{recommendation}</p>
            </div>
          )}
        </>
      )}
    </section>
  )
})

RiskExplanation.displayName = 'RiskExplanation'

export default RiskExplanation
export { RiskExplanation }
