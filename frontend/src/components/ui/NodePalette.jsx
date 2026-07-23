import { AlertTriangle, Bell, Clock, GitBranch, Play, Zap } from 'lucide-react'
import { cn } from '../../lib/cn'

const TYPE_ICON = {
  trigger: Zap,
  action: Play,
  condition: GitBranch,
  delay: Clock,
  notify: Bell,
}

const DEFAULT_TYPES = [
  { type: 'trigger', label: 'Trigger', description: 'Start on an event' },
  { type: 'action', label: 'Action', description: 'Run a task' },
  { type: 'condition', label: 'Condition', description: 'Branch on a test' },
  { type: 'delay', label: 'Delay', description: 'Wait' },
  { type: 'notify', label: 'Notify', description: 'Alert a channel' },
]

/**
 * NodePalette — a palette of playbook node types for the SOAR builder. Each item
 * is click-to-add and HTML5-draggable (drag payload = the node type), so it
 * feeds a flow canvas by drop or click.
 *
 * @param {Array<{type:string,label:string,description?:string}>} [types]
 * @param {(type:string)=>void} [onAdd]
 * @param {boolean} [draggable=true]
 */
export default function NodePalette({ types = DEFAULT_TYPES, onAdd, draggable = true, className, ...props }) {
  return (
    <div
      role="group"
      aria-label="Playbook node palette"
      className={cn('flex flex-col gap-1.5', className)}
      {...props}
    >
      {types.map((t) => {
        const Icon = TYPE_ICON[t.type] ?? AlertTriangle
        return (
          <button
            key={t.type}
            type="button"
            draggable={draggable}
            onDragStart={(e) => {
              e.dataTransfer?.setData('application/weissman-node', t.type)
              if (e.dataTransfer) e.dataTransfer.effectAllowed = 'copy'
            }}
            onClick={() => onAdd?.(t.type)}
            aria-label={`Add ${t.label} node`}
            className={cn(
              'flex items-center gap-2.5 rounded-lg border border-border-default bg-bg-2 px-3 py-2 text-start',
              'cursor-grab transition-colors hover:border-border-strong hover:bg-bg-3',
              'focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]',
            )}
          >
            <span className="inline-flex size-6 shrink-0 items-center justify-center rounded-md bg-bg-3 text-text-tertiary [&>svg]:size-3.5">
              <Icon aria-hidden="true" />
            </span>
            <span className="min-w-0">
              <span className="block text-xs font-medium text-text-primary">{t.label}</span>
              {t.description && <span className="block text-[10px] text-text-muted">{t.description}</span>}
            </span>
          </button>
        )
      })}
    </div>
  )
}

export { NodePalette, DEFAULT_TYPES }
