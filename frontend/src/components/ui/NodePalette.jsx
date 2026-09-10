import { Bell, Clock, GitBranch, Play, Zap } from 'lucide-react'
import { cn } from '../../lib/cn'
import { setNodeDragData } from '../../lib/playbookFlow.js'

const TYPE_ICON = {
  trigger: Zap,
  action: Play,
  condition: GitBranch,
  delay: Clock,
  notify: Bell,
}

const DEFAULT_TYPES = [
  { type: 'trigger', nodeType: 'trigger', label: 'Trigger', description: 'Start on an event' },
  { type: 'action', nodeType: 'action', label: 'Action', description: 'Run a task' },
  { type: 'condition', nodeType: 'condition', label: 'Condition', description: 'Branch on a test' },
  { type: 'delay', nodeType: 'delay', label: 'Delay', description: 'Wait' },
  { type: 'notify', nodeType: 'notify', label: 'Notify', description: 'Alert a channel' },
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
      className={cn('flex max-h-[36rem] flex-col gap-1.5 overflow-y-auto pe-1 custom-scroll', className)}
      {...props}
    >
      {types.map((item) => {
        const Icon = TYPE_ICON[item.nodeType || item.type] ?? Play
        return (
          <button
            key={item.type}
            type="button"
            draggable={draggable}
            onDragStart={(e) => setNodeDragData(e.dataTransfer, item.type)}
            onClick={() => onAdd?.(item.type)}
            aria-label={item.ariaLabel || `Add ${item.label} node`}
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
              <span className="block text-xs font-medium text-text-primary">{item.label}</span>
              {item.description && <span className="block text-[10px] text-text-muted">{item.description}</span>}
            </span>
          </button>
        )
      })}
    </div>
  )
}

export { NodePalette, DEFAULT_TYPES }
