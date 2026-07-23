import { forwardRef } from 'react'
import { AlertTriangle, Check } from 'lucide-react'
import { cn } from '../../lib/cn'

const STATUS = {
  complete: 'bg-status-active text-text-inverse border-status-active',
  current: 'bg-accent-cyan text-text-inverse border-accent-cyan',
  upcoming: 'bg-bg-3 text-text-muted border-border-default',
  error: 'bg-severity-critical text-text-inverse border-severity-critical',
}

/**
 * Stepper — a numbered progress indicator for linear flows (playbook dry-run,
 * approval workflow, onboarding). Horizontal or vertical.
 *
 * @param {Array<{id?:string|number,label:React.ReactNode,description?:React.ReactNode,
 *   status?:'complete'|'current'|'upcoming'|'error'}>} steps
 * @param {'horizontal'|'vertical'} [orientation='horizontal']
 * @param {(step:object,index:number)=>void} [onStepClick]
 */
const Stepper = forwardRef(function Stepper(
  { steps = [], orientation = 'horizontal', onStepClick, className, ...props },
  ref,
) {
  const vertical = orientation === 'vertical'
  const interactive = typeof onStepClick === 'function'

  return (
    <ol
      ref={ref}
      className={cn('flex', vertical ? 'flex-col' : 'flex-row items-start', className)}
      {...props}
    >
      {steps.map((step, i) => {
        const status = step.status ?? 'upcoming'
        const badge = STATUS[status] ?? STATUS.upcoming
        const isLast = i === steps.length - 1

        const Marker = (
          <span
            className={cn(
              'inline-flex size-7 shrink-0 items-center justify-center rounded-full border text-xs font-semibold tabular-nums',
              'transition-colors duration-normal',
              badge,
            )}
            aria-hidden="true"
          >
            {status === 'complete' ? (
              <Check className="size-4" />
            ) : status === 'error' ? (
              <AlertTriangle className="size-4" />
            ) : (
              i + 1
            )}
          </span>
        )

        const labelBlock = (
          <span className={cn('min-w-0', vertical ? 'pb-4' : 'mt-1.5 block text-center')}>
            <span
              className={cn(
                'block text-xs font-medium',
                status === 'upcoming' ? 'text-text-muted' : 'text-text-primary',
              )}
            >
              {step.label}
            </span>
            {step.description != null && (
              <span className="mt-0.5 block text-[10px] text-text-tertiary">{step.description}</span>
            )}
          </span>
        )

        // Connector line to the next step.
        const connector = !isLast && (
          <span
            className={cn(
              vertical ? 'my-1 ms-3.5 w-px flex-1' : 'mt-3.5 h-px flex-1',
              status === 'complete' ? 'bg-status-active/50' : 'bg-border-default',
            )}
            aria-hidden="true"
          />
        )

        const content = vertical ? (
          <div className="flex gap-3">
            <div className="flex flex-col items-center">
              {Marker}
              {connector}
            </div>
            {labelBlock}
          </div>
        ) : (
          <div className="flex flex-1 flex-col items-center">
            <div className="flex w-full items-center">
              <span className="flex-1" aria-hidden="true" />
              {interactive ? (
                <button
                  type="button"
                  onClick={() => onStepClick(step, i)}
                  aria-current={status === 'current' ? 'step' : undefined}
                  className="rounded-full focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]"
                >
                  {Marker}
                </button>
              ) : (
                Marker
              )}
              {connector}
            </div>
            {labelBlock}
          </div>
        )

        return (
          <li
            key={step.id ?? i}
            aria-current={status === 'current' ? 'step' : undefined}
            className={cn(vertical ? 'flex' : 'flex flex-1', isLast && !vertical && 'flex-none')}
          >
            {vertical && interactive ? (
              <button
                type="button"
                onClick={() => onStepClick(step, i)}
                className="text-start focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)] rounded-lg"
              >
                {content}
              </button>
            ) : (
              content
            )}
          </li>
        )
      })}
    </ol>
  )
})

Stepper.displayName = 'Stepper'

export default Stepper
export { Stepper }
