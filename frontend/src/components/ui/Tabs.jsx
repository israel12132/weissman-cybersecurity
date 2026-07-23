import {
  createContext,
  forwardRef,
  useCallback,
  useContext,
  useEffect,
  useId,
  useRef,
  useState,
} from 'react'
import { cn } from '../../lib/cn'

const TabsContext = createContext(null)

function useTabsContext(component) {
  const ctx = useContext(TabsContext)
  if (!ctx) {
    throw new Error(`<${component}> must be rendered inside <Tabs>.`)
  }
  return ctx
}

function assignRef(ref, node) {
  if (typeof ref === 'function') ref(node)
  else if (ref) ref.current = node
}

function isRtlContext(node) {
  if (node && typeof node.closest === 'function' && node.closest('[dir="rtl"]')) return true
  if (typeof document !== 'undefined' && document.documentElement.getAttribute('dir') === 'rtl') return true
  return false
}

const tabId = (baseId, value) => `${baseId}-tab-${value}`
const panelId = (baseId, value) => `${baseId}-panel-${value}`

/**
 * Compound ARIA tablist with roving tabindex and arrow-key navigation.
 *
 * Controlled via `value` + `onValueChange`, otherwise uncontrolled from
 * `defaultValue`. Compose with `TabList`, `Tab`, and `TabPanel`.
 *
 * @param {string} value — controlled selected tab value
 * @param {string} defaultValue — initial value for uncontrolled use
 * @param {(value: string) => void} onValueChange — fires on selection change
 * @param {'horizontal'|'vertical'} orientation — arrow-key axis + layout
 * @param {'underline'|'pill'} variant — active-tab treatment
 */
const Tabs = forwardRef(function Tabs(
  {
    value,
    defaultValue,
    onValueChange,
    orientation = 'horizontal',
    variant = 'underline',
    className,
    children,
    ...props
  },
  ref,
) {
  const baseId = useId()
  const isControlled = value !== undefined
  const [internal, setInternal] = useState(defaultValue)
  const selected = isControlled ? value : internal
  const [values, setValues] = useState([])

  const setValue = useCallback(
    (next) => {
      if (!isControlled) setInternal(next)
      onValueChange?.(next)
    },
    [isControlled, onValueChange],
  )

  const register = useCallback((v) => {
    setValues((prev) => (prev.includes(v) ? prev : [...prev, v]))
  }, [])

  const unregister = useCallback((v) => {
    setValues((prev) => prev.filter((x) => x !== v))
  }, [])

  const ctx = {
    baseId,
    selected,
    setValue,
    orientation,
    variant,
    register,
    unregister,
    values,
  }

  return (
    <TabsContext.Provider value={ctx}>
      <div
        ref={ref}
        className={cn(
          'flex',
          orientation === 'vertical' ? 'flex-row gap-4' : 'flex-col gap-4',
          className,
        )}
        {...props}
      >
        {children}
      </div>
    </TabsContext.Provider>
  )
})

Tabs.displayName = 'Tabs'

/**
 * Row/column of tabs. Renders `role="tablist"`, wires arrow-key + Home/End
 * navigation with automatic activation, and reflects `aria-orientation`.
 */
const TabList = forwardRef(function TabList({ className, children, ...props }, ref) {
  const { orientation, variant, setValue } = useTabsContext('TabList')
  const innerRef = useRef(null)
  const isVertical = orientation === 'vertical'

  const setRefs = (node) => {
    innerRef.current = node
    assignRef(ref, node)
  }

  const handleKeyDown = (event) => {
    const list = innerRef.current
    if (!list) return

    const rtl = !isVertical && isRtlContext(list)
    const forwardKey = isVertical ? 'ArrowDown' : rtl ? 'ArrowLeft' : 'ArrowRight'
    const backKey = isVertical ? 'ArrowUp' : rtl ? 'ArrowRight' : 'ArrowLeft'

    if (
      event.key !== forwardKey &&
      event.key !== backKey &&
      event.key !== 'Home' &&
      event.key !== 'End'
    ) {
      return
    }

    const tabs = Array.from(list.querySelectorAll('[role="tab"]')).filter(
      (t) => !t.disabled && t.getAttribute('aria-disabled') !== 'true',
    )
    if (tabs.length === 0) return

    const currentIndex = tabs.indexOf(document.activeElement)
    let nextIndex
    if (event.key === 'Home') nextIndex = 0
    else if (event.key === 'End') nextIndex = tabs.length - 1
    else if (event.key === forwardKey) nextIndex = currentIndex < 0 ? 0 : (currentIndex + 1) % tabs.length
    else nextIndex = currentIndex < 0 ? tabs.length - 1 : (currentIndex - 1 + tabs.length) % tabs.length

    event.preventDefault()
    const nextTab = tabs[nextIndex]
    nextTab.focus()
    const nextValue = nextTab.getAttribute('data-value')
    if (nextValue != null) setValue(nextValue)
  }

  return (
    <div
      ref={setRefs}
      role="tablist"
      aria-orientation={orientation}
      onKeyDown={handleKeyDown}
      className={cn(
        'flex',
        isVertical ? 'flex-col items-stretch' : 'flex-row items-center',
        variant === 'pill'
          ? cn('gap-1 rounded-lg bg-bg-2 p-1', isVertical ? 'shrink-0' : 'w-fit')
          : cn(
              'gap-1',
              isVertical
                ? 'border-e border-border-subtle'
                : 'border-b border-border-subtle',
            ),
        className,
      )}
      {...props}
    >
      {children}
    </div>
  )
})

TabList.displayName = 'TabList'

/**
 * A single tab trigger. Renders `role="tab"`, wires `aria-selected` and
 * `aria-controls`, and participates in the roving tabindex.
 *
 * @param {string} value — identity linking this tab to its panel
 * @param {boolean} disabled
 */
const Tab = forwardRef(function Tab(
  { value, disabled = false, className, children, ...props },
  ref,
) {
  const { baseId, selected, setValue, orientation, variant, register, unregister, values } =
    useTabsContext('Tab')
  const isVertical = orientation === 'vertical'
  const isSelected = selected === value

  useEffect(() => {
    register(value)
    return () => unregister(value)
  }, [value, register, unregister])

  // Roving tabindex: the selected tab is tabbable; if nothing valid is selected
  // yet, the first registered tab takes the tab stop.
  const hasSelection = values.includes(selected)
  const tabbable = hasSelection ? isSelected : values[0] === value

  return (
    <button
      ref={ref}
      type="button"
      role="tab"
      id={tabId(baseId, value)}
      data-value={String(value)}
      aria-selected={isSelected}
      aria-controls={panelId(baseId, value)}
      tabIndex={tabbable ? 0 : -1}
      disabled={disabled}
      onClick={() => setValue(value)}
      className={cn(
        'relative inline-flex items-center justify-center gap-2 whitespace-nowrap select-none',
        'font-sans text-sm font-medium',
        'transition-all duration-normal ease-out-expo',
        'focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]',
        'disabled:opacity-40 disabled:pointer-events-none disabled:cursor-not-allowed',
        '[&>svg]:size-4 [&>svg]:shrink-0',
        variant === 'pill'
          ? cn(
              'rounded-md px-3.5 py-1.5',
              isSelected
                ? 'bg-bg-4 text-text-primary shadow-sm'
                : 'text-text-secondary hover:bg-bg-3/60 hover:text-text-primary',
            )
          : cn(
              'px-3.5 py-2.5',
              isVertical
                ? '-me-px border-e-2 rounded-s-md'
                : '-mb-px border-b-2 rounded-t-md',
              isSelected
                ? 'border-accent-cyan text-text-accent'
                : 'border-transparent text-text-secondary hover:border-border-strong hover:text-text-primary',
            ),
        className,
      )}
      {...props}
    >
      {children}
    </button>
  )
})

Tab.displayName = 'Tab'

/**
 * Content region for a tab. Renders `role="tabpanel"`, is `hidden` while its
 * tab is inactive, and is focusable (`tabIndex=0`) so keyboard users land on
 * the content after activating a tab.
 *
 * @param {string} value — identity linking this panel to its tab
 */
const TabPanel = forwardRef(function TabPanel(
  { value, className, children, ...props },
  ref,
) {
  const { baseId, selected } = useTabsContext('TabPanel')
  const isSelected = selected === value

  return (
    <div
      ref={ref}
      role="tabpanel"
      id={panelId(baseId, value)}
      aria-labelledby={tabId(baseId, value)}
      hidden={!isSelected}
      tabIndex={0}
      className={cn(
        'rounded-md text-sm text-text-secondary',
        'focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]',
        isSelected && 'animate-fade-in',
        className,
      )}
      {...props}
    >
      {children}
    </div>
  )
})

TabPanel.displayName = 'TabPanel'

export default Tabs
export { Tabs, TabList, Tab, TabPanel }
