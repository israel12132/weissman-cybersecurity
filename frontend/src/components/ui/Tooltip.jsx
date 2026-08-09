import { cloneElement, isValidElement, useEffect, useId, useRef, useState } from 'react'
import { cn } from '../../lib/cn'

const SIDE_STYLES = {
  top: 'bottom-full mb-1 start-1/2 -translate-x-1/2',
  bottom: 'top-full mt-1 start-1/2 -translate-x-1/2',
  start: 'end-full me-1 top-1/2 -translate-y-1/2',
  end: 'start-full ms-1 top-1/2 -translate-y-1/2',
}

/**
 * Tooltip primitive — wraps a single trigger and reveals a describing bubble on
 * hover (after `delay` ms) and immediately on keyboard focus. Hides on
 * mouse-leave, blur, or Escape. The bubble carries role="tooltip" and is wired
 * to the trigger via aria-describedby.
 *
 * @param {React.ReactNode} content — tooltip body (rendered when visible)
 * @param {'top'|'bottom'|'start'|'end'} side — placement relative to the trigger
 * @param {number} delay — hover delay in ms before showing (focus is immediate)
 * @param {React.ReactNode} children — the single trigger element
 */
export default function Tooltip({
  content,
  side = 'top',
  delay = 200,
  className,
  children,
  ...props
}) {
  const [open, setOpen] = useState(false)
  const timerRef = useRef(null)
  const tooltipId = useId()

  const clearTimer = () => {
    if (timerRef.current) {
      clearTimeout(timerRef.current)
      timerRef.current = null
    }
  }

  const show = (immediate) => {
    clearTimer()
    if (immediate || delay <= 0) {
      setOpen(true)
    } else {
      timerRef.current = setTimeout(() => setOpen(true), delay)
    }
  }

  const hide = () => {
    clearTimer()
    setOpen(false)
  }

  // Clear any pending show timer if the trigger unmounts mid-delay.
  useEffect(() => clearTimer, [])

  const hasContent = content != null && content !== ''
  // aria-describedby must land on the element that actually receives focus (the
  // caller's trigger), not this wrapper — otherwise AT never announces the bubble.
  const describedBy = hasContent && open ? tooltipId : undefined
  const trigger = isValidElement(children)
    ? cloneElement(children, { 'aria-describedby': describedBy })
    : children

  return (
    <span className={cn('relative inline-flex', className)} {...props}>
      <span
        className="inline-flex"
        onMouseEnter={() => show(false)}
        onMouseLeave={hide}
        onFocus={() => show(true)}
        onBlur={hide}
        onKeyDown={(e) => {
          if (e.key === 'Escape') hide()
        }}
      >
        {trigger}
      </span>
      {open && hasContent && (
        <span
          role="tooltip"
          id={tooltipId}
          className={cn(
            'absolute z-toast pointer-events-none whitespace-nowrap',
            'bg-bg-elevated border border-border-strong text-text-primary',
            'text-xs rounded-md px-2 py-1 shadow-lg animate-fade-in',
            SIDE_STYLES[side] ?? SIDE_STYLES.top,
          )}
        >
          {content}
        </span>
      )}
    </span>
  )
}

export { Tooltip }
