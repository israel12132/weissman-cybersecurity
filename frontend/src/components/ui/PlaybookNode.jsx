import { forwardRef } from 'react'
import { AlertTriangle, Bell, Clock, GitBranch, Loader2, Play, Zap } from 'lucide-react'
import { cn } from '../../lib/cn'

const TYPE = {
  trigger: { accent: 'text-accent-cyan', ring: 'border-accent-cyan/50', Icon: Zap, label: 'Trigger' },
  action: { accent: 'text-accent-violet', ring: 'border-accent-violet/50', Icon: Play, label: 'Action' },
  condition: { accent: 'text-severity-medium', ring: 'border-severity-medium/50', Icon: GitBranch, label: 'Condition' },
  delay: { accent: 'text-text-tertiary', ring: 'border-border-strong', Icon: Clock, label: 'Delay' },
  notify: { accent: 'text-severity-info', ring: 'border-severity-info/50', Icon: Bell, label: 'Notify' },
}

const STATUS_DOT = {
  running: 'text-accent-cyan',
  success: 'text-status-active',
  error: 'text-severity-critical',
}

/**
 * PlaybookNode — a single SOAR playbook node card for the visual builder. Can be
 * placed inside a flow canvas or a static layout. Renders input/output ports
 * (condition nodes expose true/false outputs) and a run status.
 *
 * @param {'trigger'|'action'|'condition'|'delay'|'notify'} [type='action']
 * @param {React.ReactNode} title @param {React.ReactNode} [summary]
 * @param {'idle'|'running'|'success'|'error'} [status='idle']
 * @param {boolean} [selected=false] @param {()=>void} [onClick] @param {React.ReactNode} [icon]
 */
const PlaybookNode = forwardRef(function PlaybookNode(
  { type = 'action', title, summary, status = 'idle', selected = false, onClick, icon, className, ...props },
  ref,
) {
  const meta = TYPE[type] ?? TYPE.action
  const Icon = meta.Icon
  const interactive = typeof onClick === 'function'
  const isCondition = type === 'condition'

  const StatusIcon = status === 'error' ? AlertTriangle : status === 'running' ? Loader2 : null

  const body = (
    <>
      {/* input port */}
      <span
        className="absolute -top-1 start-1/2 size-2 -translate-x-1/2 rounded-full bg-border-strong ring-2 ring-bg-1"
        aria-hidden="true"
      />

      <div className="flex items-center gap-2">
        <span className={cn('inline-flex size-6 items-center justify-center rounded-md bg-bg-3 [&>svg]:size-3.5', meta.accent)}>
          {icon ?? <Icon aria-hidden="true" />}
        </span>
        <span className="text-[10px] uppercase tracking-widest text-text-muted">{meta.label}</span>
        {StatusIcon && (
          <StatusIcon
            className={cn('ms-auto size-3.5', STATUS_DOT[status], status === 'running' && 'animate-spin')}
            aria-hidden="true"
          />
        )}
      </div>

      <div className="mt-1.5 text-sm font-medium text-text-primary">{title}</div>
      {summary != null && <div className="mt-0.5 text-xs text-text-tertiary">{summary}</div>}

      {/* output port(s) */}
      {isCondition ? (
        <>
          <span className="absolute -bottom-1 start-1/3 size-2 -translate-x-1/2 rounded-full bg-status-active ring-2 ring-bg-1" aria-hidden="true" title="true" />
          <span className="absolute -bottom-1 start-2/3 size-2 -translate-x-1/2 rounded-full bg-severity-critical ring-2 ring-bg-1" aria-hidden="true" title="false" />
        </>
      ) : (
        <span className="absolute -bottom-1 start-1/2 size-2 -translate-x-1/2 rounded-full bg-border-strong ring-2 ring-bg-1" aria-hidden="true" />
      )}
    </>
  )

  const classes = cn(
    'relative w-56 rounded-xl border bg-bg-2 p-3 text-start shadow-sm transition-all duration-normal',
    selected ? 'border-accent-cyan shadow-glow-cyan' : meta.ring,
    interactive && 'hover:-translate-y-px hover:shadow-md focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]',
    className,
  )

  if (interactive) {
    return (
      <button ref={ref} type="button" onClick={onClick} aria-pressed={selected} className={classes} {...props}>
        {body}
      </button>
    )
  }
  return (
    <div ref={ref} className={classes} {...props}>
      {body}
    </div>
  )
})

PlaybookNode.displayName = 'PlaybookNode'

export default PlaybookNode
export { PlaybookNode }
