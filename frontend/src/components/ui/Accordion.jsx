import {
  createContext,
  forwardRef,
  useContext,
  useId,
  useState,
} from 'react'
import { ChevronDown } from 'lucide-react'
import { cn } from '../../lib/cn'

const AccordionContext = createContext(null)
const AccordionItemContext = createContext(null)

/**
 * Accordion — compound, keyboard-accessible expand/collapse panels.
 *
 * `type="single"` keeps at most one panel open (`value` is a string); when
 * `collapsible` is true the open panel can be toggled shut. `type="multiple"`
 * lets any number of panels stay open (`value` is a string array). Controlled
 * via `value` + `onValueChange`, otherwise uncontrolled from `defaultValue`.
 *
 * @param {'single'|'multiple'} type
 * @param {string|string[]} value — controlled open-panel state
 * @param {string|string[]} defaultValue — uncontrolled initial open-panel state
 * @param {(value: string|string[]) => void} onValueChange
 * @param {boolean} collapsible — allow the open single panel to close again
 */
const Accordion = forwardRef(function Accordion(
  {
    type = 'single',
    value,
    defaultValue,
    onValueChange,
    collapsible = true,
    className,
    children,
    ...props
  },
  ref,
) {
  const isControlled = value !== undefined
  const [internal, setInternal] = useState(
    defaultValue ?? (type === 'multiple' ? [] : ''),
  )
  const current = isControlled ? value : internal

  const commit = (next) => {
    if (!isControlled) setInternal(next)
    onValueChange?.(next)
  }

  const isItemOpen = (itemValue) =>
    type === 'multiple'
      ? Array.isArray(current) && current.includes(itemValue)
      : current === itemValue

  const toggleItem = (itemValue) => {
    if (type === 'multiple') {
      const arr = Array.isArray(current) ? current : []
      commit(
        arr.includes(itemValue)
          ? arr.filter((v) => v !== itemValue)
          : [...arr, itemValue],
      )
    } else {
      const willClose = current === itemValue
      commit(willClose ? (collapsible ? '' : current) : itemValue)
    }
  }

  return (
    <AccordionContext.Provider value={{ isItemOpen, toggleItem }}>
      <div ref={ref} className={cn('font-sans', className)} {...props}>
        {children}
      </div>
    </AccordionContext.Provider>
  )
})

Accordion.displayName = 'Accordion'

/**
 * A single accordion section. Establishes the trigger/content wiring (ids, open
 * state, disabled) shared with its descendants via context.
 *
 * @param {string} value — unique key identifying this section
 * @param {boolean} disabled — prevent this section from toggling
 */
const AccordionItem = forwardRef(function AccordionItem(
  { value, disabled = false, className, children, ...props },
  ref,
) {
  const ctx = useContext(AccordionContext)
  const uid = useId()
  const open = ctx ? ctx.isItemOpen(value) : false

  return (
    <AccordionItemContext.Provider
      value={{
        value,
        disabled,
        open,
        triggerId: `${uid}-trigger`,
        contentId: `${uid}-content`,
      }}
    >
      <div
        ref={ref}
        data-state={open ? 'open' : 'closed'}
        className={cn(
          'border-b border-border-subtle last:border-b-0',
          className,
        )}
        {...props}
      >
        {children}
      </div>
    </AccordionItemContext.Provider>
  )
})

AccordionItem.displayName = 'AccordionItem'

/**
 * The clickable header button that toggles its section open or closed.
 */
const AccordionTrigger = forwardRef(function AccordionTrigger(
  { className, children, ...props },
  ref,
) {
  const acc = useContext(AccordionContext)
  const item = useContext(AccordionItemContext)
  const open = item?.open ?? false

  return (
    <button
      ref={ref}
      type="button"
      id={item?.triggerId}
      aria-expanded={open}
      aria-controls={item?.contentId}
      disabled={item?.disabled}
      onClick={() => acc?.toggleItem(item?.value)}
      className={cn(
        'flex w-full items-center justify-between gap-3 text-start',
        'px-4 py-3.5 font-medium text-text-primary',
        'transition-colors duration-fast ease-out-expo',
        'hover:bg-bg-2/60',
        'focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]',
        'disabled:opacity-45 disabled:pointer-events-none',
        className,
      )}
      {...props}
    >
      {children}
      <ChevronDown
        aria-hidden="true"
        className={cn(
          'size-4 shrink-0 text-text-muted',
          'transition-transform duration-normal ease-out-expo',
          open && 'rotate-180',
        )}
      />
    </button>
  )
})

AccordionTrigger.displayName = 'AccordionTrigger'

/**
 * The collapsible panel region revealed while its section is open. Hidden from
 * layout and the accessibility tree when its section is closed.
 */
const AccordionContent = forwardRef(function AccordionContent(
  { className, children, ...props },
  ref,
) {
  const item = useContext(AccordionItemContext)
  const open = item?.open ?? false

  return (
    <div
      ref={ref}
      role="region"
      id={item?.contentId}
      aria-labelledby={item?.triggerId}
      hidden={!open}
      className={cn('px-4 pb-4 pt-1 text-sm text-text-secondary', className)}
      {...props}
    >
      {children}
    </div>
  )
})

AccordionContent.displayName = 'AccordionContent'

export default Accordion
export { Accordion, AccordionItem, AccordionTrigger, AccordionContent }
