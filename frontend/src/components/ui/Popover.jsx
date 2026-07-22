import { useEffect, useId, useRef, useState } from 'react'
import { cn } from '../../lib/cn'

// Which side of the trigger the panel floats on. Positioned absolutely inside
// the `relative` wrapper using logical inset utilities so it mirrors under RTL.
const SIDE_CLASSES = {
  bottom: 'top-full mt-1',
  top: 'bottom-full mb-1',
  start: 'end-full me-1',
  end: 'start-full ms-1',
}

// Cross-axis alignment. For top/bottom sides this is the horizontal axis; for
// start/end sides it is the vertical axis. `translate-x` is direction-aware, so
// the center case flips via ltr:/rtl: variants.
const ALIGN_HORIZONTAL = {
  start: 'start-0',
  center: 'start-1/2 ltr:-translate-x-1/2 rtl:translate-x-1/2',
  end: 'end-0',
}

const ALIGN_VERTICAL = {
  start: 'top-0',
  center: 'top-1/2 -translate-y-1/2',
  end: 'bottom-0',
}

function getPositionClasses(side, align) {
  const sideClass = SIDE_CLASSES[side] ?? SIDE_CLASSES.bottom
  const isHorizontalSide = side === 'top' || side === 'bottom'
  const alignClass = isHorizontalSide
    ? ALIGN_HORIZONTAL[align] ?? ALIGN_HORIZONTAL.start
    : ALIGN_VERTICAL[align] ?? ALIGN_VERTICAL.start
  return `${sideClass} ${alignClass}`
}

/**
 * Click-triggered floating panel. Toggled by its trigger, dismissed by an
 * outside click or Escape (which returns focus to the trigger). Controlled via
 * `open` + `onOpenChange`, otherwise self-managed from `defaultOpen`.
 *
 * @param {React.ReactNode} trigger — element wrapped in the toggle button
 * @param {React.ReactNode} children — panel content
 * @param {boolean} open — controlled open state
 * @param {boolean} defaultOpen — uncontrolled initial state
 * @param {(open: boolean) => void} onOpenChange — open-state change callback
 * @param {'top'|'bottom'|'start'|'end'} side — side the panel floats on
 * @param {'start'|'center'|'end'} align — cross-axis alignment
 * @param {string} panelClassName — extra classes for the panel
 */
function Popover({
  trigger,
  children,
  open,
  defaultOpen = false,
  onOpenChange,
  side = 'bottom',
  align = 'start',
  className,
  panelClassName,
  ...props
}) {
  const wrapperRef = useRef(null)
  const triggerRef = useRef(null)
  const [internalOpen, setInternalOpen] = useState(defaultOpen)

  const isControlled = open !== undefined
  const isOpen = isControlled ? open : internalOpen

  const uid = useId()
  const triggerId = `${uid}-trigger`
  const panelId = `${uid}-panel`

  const setOpen = (next) => {
    if (!isControlled) setInternalOpen(next)
    onOpenChange?.(next)
  }

  // Outside-click (mousedown) dismissal.
  useEffect(() => {
    if (!isOpen) return undefined
    const onMouseDown = (e) => {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', onMouseDown)
    return () => document.removeEventListener('mousedown', onMouseDown)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen])

  // Escape closes and restores focus to the trigger button.
  useEffect(() => {
    if (!isOpen) return undefined
    const onKeyDown = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        setOpen(false)
        triggerRef.current?.focus()
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen])

  return (
    <div ref={wrapperRef} className={cn('relative inline-flex', className)} {...props}>
      <button
        ref={triggerRef}
        id={triggerId}
        type="button"
        aria-haspopup="dialog"
        aria-expanded={isOpen}
        aria-controls={isOpen ? panelId : undefined}
        onClick={() => setOpen(!isOpen)}
        className={cn(
          'inline-flex items-center rounded-md',
          'transition-colors duration-fast ease-out-expo',
          'focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]',
        )}
      >
        {trigger}
      </button>

      {isOpen && (
        <div
          id={panelId}
          role="dialog"
          aria-labelledby={triggerId}
          className={cn(
            'absolute z-dropdown',
            'bg-bg-elevated border border-border-strong rounded-lg shadow-xl p-3',
            'animate-slide-up',
            getPositionClasses(side, align),
            panelClassName,
          )}
        >
          {children}
        </div>
      )}
    </div>
  )
}

Popover.displayName = 'Popover'

export default Popover
export { Popover }
