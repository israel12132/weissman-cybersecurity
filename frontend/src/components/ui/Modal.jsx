import { useEffect, useId, useRef } from 'react'
import { createPortal } from 'react-dom'
import { X } from 'lucide-react'
import { cn } from '../../lib/cn'
import useFocusTrap from '../../hooks/useFocusTrap'

const SIZES = {
  sm: 'max-w-sm',
  md: 'max-w-md',
  lg: 'max-w-2xl',
  xl: 'max-w-4xl',
  '2xl': 'max-w-6xl',
}

/**
 * Modal — centered dialog rendered in a portal, with focus trap, body scroll
 * lock, ESC-to-close, and overlay-click dismissal. Renders null when closed.
 *
 * @param {boolean} open — controls visibility
 * @param {() => void} onClose — invoked on ESC, overlay click, or close button
 * @param {string} title — heading text (labels the dialog)
 * @param {string} description — optional sub-heading (describes the dialog)
 * @param {'sm'|'md'|'lg'|'xl'|'2xl'} size
 * @param {React.ReactNode} footer — optional footer content (end-aligned row)
 * @param {boolean} closeOnOverlay — close when the scrim is clicked
 * @param {boolean} closeOnEsc — close when Escape is pressed
 * @param {boolean} hideClose — hide the header close (X) button
 */
function Modal({
  open,
  onClose,
  title,
  description,
  size = 'md',
  children,
  footer,
  closeOnOverlay = true,
  closeOnEsc = true,
  hideClose = false,
  className,
  ...props
}) {
  const dialogRef = useRef(null)
  const autoId = useId()
  const titleId = title ? `${autoId}-title` : undefined
  const descId = description ? `${autoId}-desc` : undefined

  useFocusTrap(dialogRef, open)

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

  if (!open) return null

  const hasHeader = Boolean(title) || Boolean(description) || !hideClose

  return createPortal(
    <div
      className={cn(
        'fixed inset-0 z-modal flex items-center justify-center p-4',
        'bg-bg-overlay backdrop-blur-sm animate-fade-in',
      )}
      onMouseDown={(e) => {
        if (closeOnOverlay && e.target === e.currentTarget) onClose?.()
      }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descId}
        className={cn(
          'relative flex w-full flex-col',
          'max-h-[calc(100vh-2rem)]',
          'bg-bg-2 border border-border-strong rounded-2xl shadow-xl',
          'animate-slide-up',
          SIZES[size] ?? SIZES.md,
          className,
        )}
        {...props}
      >
        {hasHeader && (
          <div className="flex items-start justify-between gap-4 p-5 pb-3">
            <div className="flex min-w-0 flex-col gap-1 text-start">
              {title && (
                <h2
                  id={titleId}
                  className="font-display text-lg text-text-primary"
                >
                  {title}
                </h2>
              )}
              {description && (
                <p id={descId} className="text-sm text-text-tertiary">
                  {description}
                </p>
              )}
            </div>
            {!hideClose && (
              <button
                type="button"
                onClick={() => onClose?.()}
                aria-label="Close"
                className={cn(
                  'inline-flex size-8 shrink-0 items-center justify-center',
                  'rounded-lg border border-transparent',
                  'text-text-tertiary transition-colors duration-fast',
                  'hover:bg-bg-3 hover:text-text-primary hover:border-border-subtle',
                  'focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]',
                )}
              >
                <X className="size-4" aria-hidden="true" />
              </button>
            )}
          </div>
        )}

        {children != null && (
          <div className="overflow-y-auto px-5 py-2 text-sm text-text-secondary">
            {children}
          </div>
        )}

        {footer && (
          <div className="flex justify-end gap-2 p-5 pt-3">{footer}</div>
        )}
      </div>
    </div>,
    document.body,
  )
}

Modal.displayName = 'Modal'

/** Layout wrapper for a Modal header (title / description block). */
function ModalHeader({ className, children, ...props }) {
  return (
    <div
      className={cn('flex flex-col gap-1 p-5 pb-3 text-start', className)}
      {...props}
    >
      {children}
    </div>
  )
}

/** Layout wrapper for the scrollable Modal body. */
function ModalBody({ className, children, ...props }) {
  return (
    <div
      className={cn(
        'overflow-y-auto px-5 py-2 text-sm text-text-secondary',
        className,
      )}
      {...props}
    >
      {children}
    </div>
  )
}

/** Layout wrapper for a Modal footer (end-aligned action row). */
function ModalFooter({ className, children, ...props }) {
  return (
    <div
      className={cn('flex justify-end gap-2 p-5 pt-3', className)}
      {...props}
    >
      {children}
    </div>
  )
}

export default Modal
export { Modal, ModalHeader, ModalBody, ModalFooter }
