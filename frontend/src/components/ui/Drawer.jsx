import { useEffect, useId, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { X } from 'lucide-react'
import { cn } from '../../lib/cn'
import useFocusTrap from '../../hooks/useFocusTrap'

// Inline-axis sheets (start/end) are sized by width; block-axis sheets
// (top/bottom) by height.
const INLINE_SIZE = {
  sm: 'w-80',
  md: 'w-[26rem]',
  lg: 'w-[34rem]',
}

const BLOCK_SIZE = {
  sm: 'h-1/3',
  md: 'h-1/2',
  lg: 'h-2/3',
}

// Per-edge geometry. `hidden` is the offscreen transform used before the
// `entered` flag flips; start/end use ltr:/rtl: variants so the sheet always
// slides in from the correct physical edge under RTL.
const SIDES = {
  start: {
    axis: 'inline',
    position: 'top-0 bottom-0 start-0 h-full max-w-full',
    edge: 'border-e rounded-e-2xl',
    hidden: 'ltr:-translate-x-full rtl:translate-x-full',
  },
  end: {
    axis: 'inline',
    position: 'top-0 bottom-0 end-0 h-full max-w-full',
    edge: 'border-s rounded-s-2xl',
    hidden: 'ltr:translate-x-full rtl:-translate-x-full',
  },
  top: {
    axis: 'block',
    position: 'top-0 start-0 end-0 w-full max-h-full',
    edge: 'border-b rounded-b-2xl',
    hidden: '-translate-y-full',
  },
  bottom: {
    axis: 'block',
    position: 'bottom-0 start-0 end-0 w-full max-h-full',
    edge: 'border-t rounded-t-2xl',
    hidden: 'translate-y-full',
  },
}

/**
 * Drawer — an edge-pinned side sheet rendered in a portal.
 *
 * Mirrors the Modal contract (role="dialog" aria-modal, focus trap, Esc-to-close,
 * body scroll-lock, blurred scrim) but slides in from a chosen edge instead of
 * centring. Renders `null` while closed.
 *
 * @param {boolean} open — whether the drawer is mounted/visible
 * @param {() => void} onClose — invoked on Esc, close button, or scrim click
 * @param {'start'|'end'|'top'|'bottom'} side — edge the sheet is pinned to
 * @param {'sm'|'md'|'lg'} size — inline width (start/end) or block height (top/bottom)
 * @param {React.ReactNode} title — heading rendered in the header (labels the dialog)
 * @param {React.ReactNode} description — supporting text under the title
 * @param {React.ReactNode} footer — optional pinned footer content
 * @param {boolean} closeOnOverlay — click the scrim to close (default true)
 * @param {boolean} closeOnEsc — press Escape to close (default true)
 */
function Drawer({
  open,
  onClose,
  side = 'end',
  size = 'md',
  title,
  description,
  children,
  footer,
  closeOnOverlay = true,
  closeOnEsc = true,
  className,
  ...props
}) {
  const panelRef = useRef(null)
  const [entered, setEntered] = useState(false)
  const uid = useId()
  const titleId = `${uid}-title`
  const descId = `${uid}-desc`

  useFocusTrap(panelRef, open)

  // Lock body scroll + wire Esc while open; restore on close/unmount.
  useEffect(() => {
    if (!open) return undefined
    const onKeyDown = (e) => {
      if (e.key === 'Escape' && closeOnEsc) {
        e.preventDefault()
        onClose?.()
      }
    }
    document.addEventListener('keydown', onKeyDown)
    const prevOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      document.body.style.overflow = prevOverflow
    }
  }, [open, closeOnEsc, onClose])

  // Flip `entered` on the next frame so the panel transitions from its offscreen
  // resting position into view.
  useEffect(() => {
    if (!open) {
      setEntered(false)
      return undefined
    }
    const raf = requestAnimationFrame(() => setEntered(true))
    return () => cancelAnimationFrame(raf)
  }, [open])

  if (!open) return null

  const cfg = SIDES[side] ?? SIDES.end
  const sizeClass =
    cfg.axis === 'block'
      ? BLOCK_SIZE[size] ?? BLOCK_SIZE.md
      : INLINE_SIZE[size] ?? INLINE_SIZE.md

  return createPortal(
    <>
      <div
        role="presentation"
        onClick={closeOnOverlay ? () => onClose?.() : undefined}
        className="fixed inset-0 z-modal bg-bg-overlay backdrop-blur-sm animate-fade-in"
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title != null ? titleId : undefined}
        aria-describedby={description != null ? descId : undefined}
        className={cn(
          'fixed z-modal flex flex-col',
          'bg-bg-2 border-border-strong shadow-xl',
          'transition-transform duration-normal ease-out-expo',
          cfg.position,
          cfg.edge,
          sizeClass,
          entered ? 'translate-x-0 translate-y-0' : cfg.hidden,
          className,
        )}
        {...props}
      >
        <div className="flex items-start justify-between gap-4 px-5 py-4 border-b border-border-subtle">
          <div className="min-w-0 flex-1">
            {title != null && (
              <h2
                id={titleId}
                className="font-display text-lg font-semibold text-text-primary tracking-tight"
              >
                {title}
              </h2>
            )}
            {description != null && (
              <p id={descId} className="mt-1 text-sm text-text-tertiary leading-relaxed">
                {description}
              </p>
            )}
          </div>
          <button
            type="button"
            onClick={() => onClose?.()}
            aria-label="Close"
            className={cn(
              'inline-flex size-8 shrink-0 items-center justify-center rounded-md',
              'text-text-muted',
              'transition-colors duration-fast ease-out-expo',
              'hover:bg-bg-3 hover:text-text-primary',
              'focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]',
              '[&>svg]:size-4',
            )}
          >
            <X aria-hidden="true" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-5 py-5 text-text-secondary text-sm">
          {children}
        </div>

        {footer != null && (
          <div className="flex items-center justify-end gap-3 px-5 py-4 border-t border-border-subtle">
            {footer}
          </div>
        )}
      </div>
    </>,
    document.body,
  )
}

Drawer.displayName = 'Drawer'

export default Drawer
export { Drawer }
