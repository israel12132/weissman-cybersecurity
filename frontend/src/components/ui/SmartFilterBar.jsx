import { forwardRef, useId, useState } from 'react'
import { BookmarkPlus, Check, X } from 'lucide-react'
import { cn } from '../../lib/cn'

const numberFormat = new Intl.NumberFormat()

/** Format a filter value — numbers are localized, everything else passes through. */
function formatValue(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return numberFormat.format(value)
  return value
}

const FOCUS_RING = 'focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]'

/**
 * Controlled filter + saved-views bar. Purely presentational: it renders the
 * active filter pills, a "clear all" affordance, and the saved-view switcher,
 * and reports every change through callbacks. It owns no filter state and
 * fetches nothing — only the inline "save view" name field is local UI state.
 *
 * @param {Array<{id:string,label:string,value:*}>} [filters] — active filters as pills
 * @param {(id:string)=>void} [onRemove] — remove a single filter pill
 * @param {()=>void} [onClear] — clear every active filter
 * @param {Array<{id:string,name:string}>} [savedViews] — selectable saved views
 * @param {string} [activeViewId] — id of the currently applied saved view
 * @param {(id:string)=>void} [onApplyView] — apply a saved view
 * @param {(name:string)=>void} [onSaveView] — persist the current filters as a named view
 * @param {React.ReactNode} [addSlot] — leading control (e.g. an "add filter" menu)
 */
const SmartFilterBar = forwardRef(function SmartFilterBar(
  {
    filters = [],
    onRemove,
    onClear,
    savedViews = [],
    activeViewId,
    onApplyView,
    onSaveView,
    addSlot,
    className,
    ...props
  },
  ref,
) {
  const inputId = useId()
  const [naming, setNaming] = useState(false)
  const [draftName, setDraftName] = useState('')

  const confirmSave = () => {
    const trimmed = draftName.trim()
    if (!trimmed) return
    onSaveView?.(trimmed)
    setDraftName('')
    setNaming(false)
  }

  const cancelSave = () => {
    setDraftName('')
    setNaming(false)
  }

  const handleKeyDown = (event) => {
    if (event.key === 'Enter') {
      event.preventDefault()
      confirmSave()
    } else if (event.key === 'Escape') {
      event.preventDefault()
      cancelSave()
    }
  }

  return (
    <div
      ref={ref}
      role="group"
      aria-label="Filters"
      className={cn('flex flex-wrap items-center gap-2', className)}
      {...props}
    >
      {addSlot}

      {filters.map(({ id, label, value }) => (
        <span
          key={id}
          className="inline-flex items-center gap-1.5 rounded-full border border-border-default bg-bg-3 ps-2.5 pe-1 py-0.5 text-xs text-text-secondary"
        >
          <span className="inline-flex items-center gap-1">
            <span className="text-text-muted">{label}</span>
            <span aria-hidden="true" className="text-text-muted">
              :
            </span>
            <span className="font-medium text-text-primary tabular-nums">{formatValue(value)}</span>
          </span>
          <button
            type="button"
            onClick={() => onRemove?.(id)}
            aria-label={`Remove ${label} filter`}
            className={cn(
              'inline-flex size-4 shrink-0 items-center justify-center rounded-full',
              'text-text-muted transition-colors duration-fast',
              'hover:bg-bg-4 hover:text-text-primary',
              FOCUS_RING,
            )}
          >
            <X className="size-3" aria-hidden="true" />
          </button>
        </span>
      ))}

      {filters.length > 0 && (
        <button
          type="button"
          onClick={() => onClear?.()}
          className={cn(
            'inline-flex h-7 items-center rounded-md px-2 text-xs font-medium',
            'bg-transparent text-text-tertiary transition-colors duration-fast',
            'hover:bg-bg-2 hover:text-text-primary',
            FOCUS_RING,
          )}
        >
          Clear all
        </button>
      )}

      {savedViews.map(({ id, name }) => {
        const active = id === activeViewId
        return (
          <button
            key={id}
            type="button"
            aria-pressed={active}
            onClick={() => onApplyView?.(id)}
            className={cn(
              'inline-flex h-7 items-center rounded-full border px-3 text-xs font-medium',
              'transition-colors duration-fast',
              active
                ? 'border-accent-cyan/40 bg-accent-cyan/10 text-accent-cyan'
                : 'border-border-default bg-bg-2 text-text-secondary hover:border-border-strong hover:text-text-primary',
              FOCUS_RING,
            )}
          >
            {name}
          </button>
        )
      })}

      {naming ? (
        <span className="inline-flex items-center gap-1">
          <input
            id={inputId}
            type="text"
            value={draftName}
            onChange={(event) => setDraftName(event.target.value)}
            onKeyDown={handleKeyDown}
            aria-label="New view name"
            placeholder="View name"
            className={cn(
              'h-7 w-32 rounded-md border border-border-default bg-bg-1 px-2 text-xs',
              'text-text-primary placeholder:text-text-muted',
              'transition-colors duration-fast',
              'focus-visible:outline-none focus-visible:border-accent-cyan/50 focus-visible:shadow-[var(--focus-ring)]',
            )}
          />
          <button
            type="button"
            onClick={confirmSave}
            aria-label="Confirm view name"
            className={cn(
              'inline-flex size-7 shrink-0 items-center justify-center rounded-md border',
              'border-accent-cyan/40 bg-accent-cyan/10 text-accent-cyan',
              'transition-colors duration-fast hover:bg-accent-cyan/20',
              FOCUS_RING,
            )}
          >
            <Check className="size-3.5" aria-hidden="true" />
          </button>
          <button
            type="button"
            onClick={cancelSave}
            aria-label="Cancel saving view"
            className={cn(
              'inline-flex size-7 shrink-0 items-center justify-center rounded-md',
              'text-text-muted transition-colors duration-fast',
              'hover:bg-bg-2 hover:text-text-primary',
              FOCUS_RING,
            )}
          >
            <X className="size-3.5" aria-hidden="true" />
          </button>
        </span>
      ) : (
        <button
          type="button"
          onClick={() => setNaming(true)}
          className={cn(
            'inline-flex h-7 items-center gap-1.5 rounded-md px-2.5 text-xs font-medium',
            'bg-transparent text-text-tertiary transition-colors duration-fast',
            'hover:bg-bg-2 hover:text-text-primary',
            FOCUS_RING,
          )}
        >
          <BookmarkPlus className="size-3.5" aria-hidden="true" />
          Save view
        </button>
      )}
    </div>
  )
})

SmartFilterBar.displayName = 'SmartFilterBar'

export default SmartFilterBar
export { SmartFilterBar }
