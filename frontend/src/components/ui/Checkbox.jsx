import { forwardRef, useCallback, useEffect, useId, useRef } from 'react'
import { Check, Minus } from 'lucide-react'
import { cn } from '../../lib/cn'

const SIZES = {
  sm: { box: 'size-4 rounded-sm', icon: 'size-3' },
  md: { box: 'size-5 rounded-md', icon: 'size-3.5' },
}

/**
 * Checkbox primitive — a custom-styled box layered over an sr-only native
 * <input type="checkbox">. Supports checked/unchecked, an indeterminate
 * ("some selected") state, label, hint, and error messaging.
 *
 * `className` merges onto the visual box; `wrapperClassName` onto the root row.
 *
 * @param {string} label — visible, clickable label text
 * @param {string} hint — helper text below the label
 * @param {string} error — validation message (replaces hint, applies error styles)
 * @param {'sm'|'md'} size
 * @param {boolean} indeterminate — renders the dash glyph and active fill
 * @param {boolean} checked — controlled checked state (forwarded to the input)
 * @param {boolean} defaultChecked — uncontrolled initial state
 */
const Checkbox = forwardRef(function Checkbox(
  {
    label,
    hint,
    error,
    size = 'md',
    indeterminate = false,
    disabled,
    checked,
    defaultChecked,
    onChange,
    id: idProp,
    className,
    wrapperClassName,
    ...props
  },
  ref,
) {
  const autoId = useId()
  const id = idProp ?? autoId
  const hasError = Boolean(error)
  const hintId = hint || error ? `${id}-hint` : undefined
  const s = SIZES[size] ?? SIZES.md

  const innerRef = useRef(null)
  const setRefs = useCallback(
    (node) => {
      innerRef.current = node
      if (typeof ref === 'function') ref(node)
      else if (ref) ref.current = node
    },
    [ref],
  )

  // The `indeterminate` state is a DOM property, not an attribute — React does
  // not manage it, so sync it imperatively whenever the prop changes.
  useEffect(() => {
    if (innerRef.current) innerRef.current.indeterminate = Boolean(indeterminate)
  }, [indeterminate])

  return (
    <div className={cn('inline-flex items-start gap-2', wrapperClassName)}>
      <span className="relative inline-flex shrink-0">
        <input
          ref={setRefs}
          id={id}
          type="checkbox"
          className="peer sr-only"
          checked={checked}
          defaultChecked={defaultChecked}
          onChange={onChange}
          disabled={disabled}
          aria-invalid={hasError || undefined}
          aria-describedby={hintId}
          {...props}
        />
        <label
          htmlFor={id}
          className={cn(
            'grid cursor-pointer select-none place-items-center',
            'border border-border-strong bg-bg-1 text-text-inverse',
            'transition-colors duration-fast ease-out-expo',
            '[&>svg]:transition-opacity [&>svg]:duration-fast',
            'peer-hover:border-accent-cyan/50',
            'peer-checked:border-accent-cyan peer-checked:bg-accent-cyan',
            'peer-focus-visible:shadow-[var(--focus-ring)]',
            'peer-disabled:cursor-not-allowed peer-disabled:opacity-45',
            s.box,
            !indeterminate && '[&>svg]:opacity-0 peer-checked:[&>svg]:opacity-100',
            indeterminate && 'border-accent-cyan bg-accent-cyan',
            hasError && 'border-severity-critical-border',
            hasError && 'peer-focus-visible:shadow-[var(--focus-ring-danger)]',
            className,
          )}
        >
          {indeterminate ? (
            <Minus className={s.icon} strokeWidth={3} aria-hidden="true" />
          ) : (
            <Check className={s.icon} strokeWidth={3} aria-hidden="true" />
          )}
        </label>
      </span>

      {(label || hint || error) && (
        <span className="flex flex-col gap-0.5 pt-px">
          {label && (
            <label
              htmlFor={id}
              className={cn(
                'cursor-pointer text-sm text-text-secondary',
                disabled && 'cursor-not-allowed opacity-45',
              )}
            >
              {label}
            </label>
          )}
          {(hint || error) && (
            <p
              id={hintId}
              className={cn(
                'text-xs leading-relaxed',
                hasError ? 'text-severity-critical' : 'text-text-muted',
              )}
            >
              {error ?? hint}
            </p>
          )}
        </span>
      )}
    </div>
  )
})

Checkbox.displayName = 'Checkbox'

export default Checkbox
export { Checkbox }
