import { forwardRef, useId } from 'react'
import { cn } from '../../lib/cn'

const SIZES = {
  sm: {
    track: 'h-5 w-9',
    thumb: 'size-4 top-0.5 start-0.5',
    translate: 'ltr:peer-checked:translate-x-4 rtl:peer-checked:-translate-x-4',
  },
  md: {
    track: 'h-6 w-11',
    thumb: 'size-5 top-0.5 start-0.5',
    translate: 'ltr:peer-checked:translate-x-5 rtl:peer-checked:-translate-x-5',
  },
}

/**
 * Switch — an iOS-style toggle backed by a visually-hidden native
 * `input[type=checkbox]` carrying `role="switch"`. The visible track + thumb are
 * decorative siblings driven by the input's `:checked` / `:focus-visible` /
 * `:disabled` states via Tailwind `peer-*` variants.
 *
 * Works controlled (`checked` + `onChange`) or uncontrolled (`defaultChecked`).
 *
 * @param {React.ReactNode} label — clickable text rendered beside the control
 * @param {'sm'|'md'} size
 * @param {boolean} checked — controlled on/off state (forwarded to the input)
 * @param {boolean} defaultChecked — uncontrolled initial state
 * @param {(event: Event) => void} onChange
 * @param {boolean} disabled
 * @param {'start'|'end'} labelPosition — logical side the label sits on
 */
const Switch = forwardRef(function Switch(
  {
    label,
    size = 'md',
    checked,
    defaultChecked,
    onChange,
    disabled,
    labelPosition = 'end',
    id: idProp,
    className,
    ...props
  },
  ref,
) {
  const autoId = useId()
  const id = idProp ?? autoId
  const sz = SIZES[size] ?? SIZES.md

  const text = label != null && (
    <span
      className={cn(
        'text-sm text-text-secondary select-none',
        disabled && 'opacity-45',
      )}
    >
      {label}
    </span>
  )

  return (
    <label
      className={cn(
        'inline-flex items-center gap-2.5 font-sans',
        disabled ? 'cursor-not-allowed' : 'cursor-pointer',
        className,
      )}
    >
      {labelPosition === 'start' && text}
      <span className="relative inline-flex shrink-0">
        <input
          ref={ref}
          id={id}
          type="checkbox"
          role="switch"
          className="peer sr-only"
          checked={checked}
          defaultChecked={defaultChecked}
          onChange={onChange}
          disabled={disabled}
          {...props}
        />
        <span
          aria-hidden="true"
          className={cn(
            'rounded-full bg-bg-4 border border-border-subtle',
            'transition-colors duration-normal ease-out-expo',
            'peer-hover:border-border-strong/60',
            'peer-checked:bg-accent-cyan peer-checked:border-accent-cyan',
            'peer-focus-visible:outline-none peer-focus-visible:shadow-[var(--focus-ring)]',
            'peer-disabled:opacity-45',
            sz.track,
          )}
        />
        <span
          aria-hidden="true"
          className={cn(
            'pointer-events-none absolute rounded-full bg-text-inverse shadow-sm',
            'transition-transform duration-normal ease-out-expo',
            'peer-disabled:opacity-45',
            sz.thumb,
            sz.translate,
          )}
        />
      </span>
      {labelPosition === 'end' && text}
    </label>
  )
})

Switch.displayName = 'Switch'

export default Switch
export { Switch }
