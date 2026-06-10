import React, { forwardRef, useId } from 'react'
import { cn } from '../../lib/cn'

const SIZES = {
  sm: 'h-8 px-3 text-sm rounded-md',
  md: 'h-9 px-3.5 text-sm rounded-lg',
  lg: 'h-11 px-4 text-base rounded-lg',
}

/**
 * Text input primitive with label, hint, and error support.
 *
 * @param {'sm'|'md'|'lg'} size
 * @param {string} label
 * @param {string} hint — helper text below input
 * @param {string} error — validation message (replaces hint, applies error styles)
 * @param {React.ReactNode} leftAddon — icon or prefix inside the field
 * @param {React.ReactNode} rightAddon — icon or suffix inside the field
 */
const Input = forwardRef(function Input(
  {
    size = 'md',
    label,
    hint,
    error,
    leftAddon,
    rightAddon,
    className,
    wrapperClassName,
    id: idProp,
    disabled,
    required,
    ...props
  },
  ref,
) {
  const autoId = useId()
  const id = idProp ?? autoId
  const hintId = hint || error ? `${id}-hint` : undefined
  const hasError = Boolean(error)

  const field = (
    <div className={cn('relative flex items-center', wrapperClassName)}>
      {leftAddon && (
        <span
          className={cn(
            'absolute start-3 inline-flex items-center text-text-muted',
            'pointer-events-none [&>svg]:size-4',
            disabled && 'opacity-50',
          )}
          aria-hidden="true"
        >
          {leftAddon}
        </span>
      )}
      <input
        ref={ref}
        id={id}
        disabled={disabled}
        required={required}
        aria-invalid={hasError || undefined}
        aria-describedby={hintId}
        className={cn(
          'w-full font-sans text-text-primary placeholder:text-text-muted',
          'bg-bg-1 border border-border-default',
          'shadow-inner transition-all duration-normal ease-out-expo',
          'hover:border-border-strong hover:bg-bg-2',
          'focus-visible:outline-none focus-visible:border-accent-cyan/50',
          'focus-visible:shadow-[var(--focus-ring)] focus-visible:bg-bg-2',
          'disabled:opacity-45 disabled:cursor-not-allowed disabled:hover:border-border-default',
          hasError && [
            'border-severity-critical-border text-severity-critical',
            'focus-visible:shadow-[var(--focus-ring-danger)]',
            'focus-visible:border-severity-critical/60',
          ],
          leftAddon && 'ps-9',
          rightAddon && 'pe-9',
          SIZES[size] ?? SIZES.md,
          className,
        )}
        {...props}
      />
      {rightAddon && (
        <span
          className={cn(
            'absolute end-3 inline-flex items-center text-text-muted',
            '[&>svg]:size-4',
            disabled && 'opacity-50',
          )}
        >
          {rightAddon}
        </span>
      )}
    </div>
  )

  if (!label && !hint && !error) return field

  return (
    <div className="flex flex-col gap-1.5">
      {label && (
        <label
          htmlFor={id}
          className={cn(
            'text-sm font-medium text-text-secondary',
            disabled && 'opacity-50',
          )}
        >
          {label}
          {required && (
            <span className="text-severity-critical ms-0.5" aria-hidden="true">
              *
            </span>
          )}
        </label>
      )}
      {field}
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
    </div>
  )
})

Input.displayName = 'Input'

export default Input
export { Input }
