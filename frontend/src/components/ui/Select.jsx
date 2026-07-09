import { forwardRef, useId } from 'react'
import { ChevronDown } from 'lucide-react'
import { cn } from '../../lib/cn'

const SIZES = {
  sm: 'h-8 pe-8 ps-3 text-sm rounded-md',
  md: 'h-9 pe-9 ps-3.5 text-sm rounded-lg',
  lg: 'h-11 pe-10 ps-4 text-base rounded-lg',
}

const CHEVRON_SIZES = {
  sm: 'size-3.5 end-2.5',
  md: 'size-4 end-3',
  lg: 'size-4 end-3.5',
}

/**
 * Native select primitive with luxury styling and full accessibility.
 *
 * @param {'sm'|'md'|'lg'} size
 * @param {string} label
 * @param {string} hint
 * @param {string} error
 * @param {Array<{value: string, label: string, disabled?: boolean}>} options
 */
const Select = forwardRef(function Select(
  {
    size = 'md',
    label,
    hint,
    error,
    options = [],
    placeholder,
    className,
    wrapperClassName,
    id: idProp,
    disabled,
    required,
    children,
    ...props
  },
  ref,
) {
  const autoId = useId()
  const id = idProp ?? autoId
  const hintId = hint || error ? `${id}-hint` : undefined
  const hasError = Boolean(error)

  const field = (
    <div className={cn('relative', wrapperClassName)}>
      <select
        ref={ref}
        id={id}
        disabled={disabled}
        required={required}
        aria-invalid={hasError || undefined}
        aria-describedby={hintId}
        className={cn(
          'w-full appearance-none font-sans text-text-primary',
          'bg-bg-1 border border-border-default',
          'shadow-inner transition-all duration-normal ease-out-expo',
          'hover:border-border-strong hover:bg-bg-2',
          'focus-visible:outline-none focus-visible:border-accent-cyan/50',
          'focus-visible:shadow-[var(--focus-ring)] focus-visible:bg-bg-2',
          'disabled:opacity-45 disabled:cursor-not-allowed',
          'cursor-pointer',
          hasError && [
            'border-severity-critical-border',
            'focus-visible:shadow-[var(--focus-ring-danger)]',
          ],
          SIZES[size] ?? SIZES.md,
          className,
        )}
        {...props}
      >
        {placeholder && (
          <option value="" disabled>
            {placeholder}
          </option>
        )}
        {children ??
          options.map((opt) => (
            <option key={opt.value} value={opt.value} disabled={opt.disabled}>
              {opt.label}
            </option>
          ))}
      </select>
      <ChevronDown
        className={cn(
          'pointer-events-none absolute top-1/2 -translate-y-1/2 text-text-muted',
          CHEVRON_SIZES[size] ?? CHEVRON_SIZES.md,
          disabled && 'opacity-50',
        )}
        aria-hidden="true"
      />
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

Select.displayName = 'Select'

export default Select
export { Select }
