import { ChevronLeft, ChevronRight, GripVertical, X } from 'lucide-react'
import { cn } from '../../lib/cn'

/**
 * DashboardGrid — a personalized widget grid. Widgets carry a column span; in
 * edit mode each can be reordered (keyboard-accessible move buttons — more
 * robust and accessible than HTML5 drag-and-drop) or removed. Controlled: pass
 * `widgets` and handle `onReorder` / `onRemove`.
 *
 * @param {Array<{id:string,title:React.ReactNode,span?:1|2|3,node:React.ReactNode}>} widgets
 * @param {boolean} [editable=false]
 * @param {(widgets:Array)=>void} [onReorder] @param {(id:string)=>void} [onRemove]
 * @param {number} [columns=3]
 */
export default function DashboardGrid({
  widgets = [],
  editable = false,
  onReorder,
  onRemove,
  columns = 3,
  className,
  ...props
}) {
  const move = (index, delta) => {
    const next = [...widgets]
    const target = index + delta
    if (target < 0 || target >= next.length) return
    ;[next[index], next[target]] = [next[target], next[index]]
    onReorder?.(next)
  }

  return (
    <div
      className={cn('grid gap-4', className)}
      style={{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }}
      {...props}
    >
      {widgets.map((w, i) => {
        const span = Math.min(columns, Math.max(1, w.span || 1))
        return (
          <section
            key={w.id}
            aria-label={typeof w.title === 'string' ? w.title : undefined}
            className="flex min-w-0 flex-col rounded-xl border border-border-default bg-bg-2"
            style={{ gridColumn: `span ${span} / span ${span}` }}
          >
            <header className="flex items-center gap-2 border-b border-border-subtle px-3 py-2">
              {editable && (
                <GripVertical className="size-3.5 shrink-0 text-text-disabled" aria-hidden="true" />
              )}
              <h3 className="min-w-0 flex-1 truncate text-xs font-semibold uppercase tracking-widest text-text-muted">
                {w.title}
              </h3>
              {editable && (
                <div className="flex items-center gap-0.5">
                  <button
                    type="button"
                    onClick={() => move(i, -1)}
                    disabled={i === 0}
                    aria-label={`Move ${typeof w.title === 'string' ? w.title : 'widget'} earlier`}
                    className="rounded p-1 text-text-muted hover:text-text-secondary disabled:opacity-30 focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]"
                  >
                    <ChevronLeft className="size-3.5" aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    onClick={() => move(i, 1)}
                    disabled={i === widgets.length - 1}
                    aria-label={`Move ${typeof w.title === 'string' ? w.title : 'widget'} later`}
                    className="rounded p-1 text-text-muted hover:text-text-secondary disabled:opacity-30 focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]"
                  >
                    <ChevronRight className="size-3.5" aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    onClick={() => onRemove?.(w.id)}
                    aria-label={`Remove ${typeof w.title === 'string' ? w.title : 'widget'}`}
                    className="rounded p-1 text-text-muted hover:text-severity-critical focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]"
                  >
                    <X className="size-3.5" aria-hidden="true" />
                  </button>
                </div>
              )}
            </header>
            <div className="min-w-0 p-3">{w.node}</div>
          </section>
        )
      })}
    </div>
  )
}

export { DashboardGrid }
