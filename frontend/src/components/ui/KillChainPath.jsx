import { forwardRef } from 'react'
import { Ban, Check, ChevronRight } from 'lucide-react'
import { cn } from '../../lib/cn'

const STATUS = {
  done: {
    node: 'bg-status-active-bg text-status-active border-status-active/40',
    Icon: Check,
  },
  active: {
    node: 'bg-accent-cyan-muted text-accent-cyan border-accent-cyan/50',
    Icon: null,
  },
  pending: {
    node: 'bg-bg-3 text-text-muted border-border-default',
    Icon: null,
  },
  blocked: {
    node: 'bg-severity-critical-bg text-severity-critical border-severity-critical-border',
    Icon: Ban,
  },
}

/**
 * Horizontal staged attack-path / kill-chain. Renders each stage as a status-
 * coloured node connected by chevrons; stages are clickable when `onStageClick`
 * is supplied. Scrolls horizontally when the chain overflows.
 *
 * @param {Array<{id?:string|number,label:React.ReactNode,status?:'done'|'active'|'pending'|'blocked',detail?:React.ReactNode}>} stages
 * @param {(stage:object,index:number)=>void} [onStageClick]
 * @param {string} [title='Attack path']
 */
const KillChainPath = forwardRef(function KillChainPath(
  { stages = [], onStageClick, title = 'Attack path', emptyMessage = 'No stages', className, ...props },
  ref,
) {
  if (!Array.isArray(stages) || stages.length === 0) {
    return (
      <p ref={ref} className={cn('text-xs text-text-muted', className)} {...props}>
        {emptyMessage}
      </p>
    )
  }

  const interactive = typeof onStageClick === 'function'

  return (
    <ol
      ref={ref}
      role="list"
      aria-label={title}
      className={cn('flex items-center gap-1 overflow-x-auto custom-scroll py-1', className)}
      {...props}
    >
      {stages.map((stage, i) => {
        const status = STATUS[stage.status] ?? STATUS.pending
        const isLast = i === stages.length - 1
        const nodeClass = cn(
          'inline-flex flex-col items-start rounded-lg border px-3 py-1.5 transition-colors duration-normal',
          status.node,
        )
        const label = `${typeof stage.label === 'string' ? stage.label : `Stage ${i + 1}`}: ${stage.status ?? 'pending'}`
        const inner = (
          <>
            <span className="inline-flex items-center gap-1 text-xs font-medium">
              {status.Icon && <status.Icon className="size-3" aria-hidden="true" />}
              {stage.label}
            </span>
            {stage.detail != null && (
              <span className="text-[10px] text-text-muted">{stage.detail}</span>
            )}
          </>
        )
        return (
          <li key={stage.id ?? i} className="flex shrink-0 items-center gap-1">
            {interactive ? (
              <button
                type="button"
                onClick={() => onStageClick(stage, i)}
                aria-label={label}
                aria-current={stage.status === 'active' ? 'step' : undefined}
                className={cn(
                  nodeClass,
                  'text-start focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]',
                  'hover:brightness-110',
                )}
              >
                {inner}
              </button>
            ) : (
              <div
                className={nodeClass}
                aria-label={label}
                aria-current={stage.status === 'active' ? 'step' : undefined}
              >
                {inner}
              </div>
            )}
            {!isLast && (
              <ChevronRight className="size-4 shrink-0 text-text-disabled" aria-hidden="true" />
            )}
          </li>
        )
      })}
    </ol>
  )
})

KillChainPath.displayName = 'KillChainPath'

export default KillChainPath
export { KillChainPath }
