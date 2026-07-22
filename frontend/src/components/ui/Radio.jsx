import {
  Children,
  cloneElement,
  forwardRef,
  isValidElement,
  useId,
  useState,
} from 'react'
import { cn } from '../../lib/cn'

const SIZES = {
  sm: { box: 'size-4', dot: 'size-1.5', text: 'text-sm' },
  md: { box: 'size-5', dot: 'size-2', text: 'text-sm' },
  lg: { box: 'size-6', dot: 'size-2.5', text: 'text-base' },
}

/**
 * Single radio option — a visually-hidden native `input[type=radio]` behind a
 * styled circle (outer ring + centered cyan dot revealed on check).
 *
 * @param {React.ReactNode} label — text rendered beside the control
 * @param {'sm'|'md'|'lg'} size
 * @param {boolean} disabled
 * @param {string} value — submitted value / group-selection key
 */
const Radio = forwardRef(function Radio(
  {
    label,
    size = 'md',
    disabled,
    value,
    className,
    id: idProp,
    ...props
  },
  ref,
) {
  const autoId = useId()
  const id = idProp ?? autoId
  const sz = SIZES[size] ?? SIZES.md

  return (
    <label
      htmlFor={id}
      className={cn(
        'inline-flex items-center gap-2.5 font-sans select-none',
        disabled ? 'cursor-not-allowed' : 'cursor-pointer',
        className,
      )}
    >
      <span className="relative inline-flex shrink-0 items-center justify-center">
        <input
          ref={ref}
          id={id}
          type="radio"
          value={value}
          disabled={disabled}
          className="peer sr-only"
          {...props}
        />
        <span
          aria-hidden="true"
          className={cn(
            'inline-flex rounded-full bg-bg-1',
            'border border-border-strong',
            'transition-all duration-normal ease-out-expo',
            'peer-hover:border-border-strong/80',
            'peer-checked:border-accent-cyan',
            'peer-focus-visible:outline-none peer-focus-visible:border-accent-cyan/50',
            'peer-focus-visible:shadow-[var(--focus-ring)]',
            'peer-disabled:opacity-45',
            sz.box,
          )}
        />
        <span
          aria-hidden="true"
          className={cn(
            'pointer-events-none absolute inset-0 m-auto rounded-full bg-accent-cyan',
            'scale-0 transition-transform duration-fast ease-out-expo',
            'peer-checked:scale-100',
            'peer-disabled:opacity-45',
            sz.dot,
          )}
        />
      </span>
      {label != null && (
        <span
          className={cn(
            'text-text-secondary',
            sz.text,
            disabled && 'opacity-45',
          )}
        >
          {label}
        </span>
      )}
    </label>
  )
})

Radio.displayName = 'Radio'

/**
 * Grouped radios sharing a `name`, rendered from `options` or `children`.
 * Controlled via `value` + `onChange`, otherwise uncontrolled from
 * `defaultValue`. Exposes `role="radiogroup"` labelled by its rendered label.
 *
 * @param {React.ReactNode} label
 * @param {string} name — shared radio group name (auto-generated if omitted)
 * @param {string} value — controlled selected value
 * @param {string} defaultValue — initial value for uncontrolled use
 * @param {(value: string, event: Event) => void} onChange
 * @param {Array<{value: string, label: React.ReactNode, disabled?: boolean}>} options
 * @param {boolean} disabled — disable every option
 * @param {'vertical'|'horizontal'} orientation
 */
function RadioGroup({
  label,
  name,
  value,
  defaultValue,
  onChange,
  options = [],
  disabled = false,
  orientation = 'vertical',
  className,
  children,
  ...props
}) {
  const autoName = useId()
  const labelId = useId()
  const groupName = name ?? autoName
  const isControlled = value !== undefined
  const [internal, setInternal] = useState(defaultValue)
  const current = isControlled ? value : internal

  const handleChange = (event) => {
    const next = event.target.value
    if (!isControlled) setInternal(next)
    onChange?.(next, event)
  }

  const radios = children != null
    ? Children.map(children, (child) => {
        if (!isValidElement(child)) return child
        return cloneElement(child, {
          name: groupName,
          checked: current === child.props.value,
          onChange: handleChange,
          disabled: disabled || child.props.disabled,
        })
      })
    : options.map((opt) => (
        <Radio
          key={opt.value}
          name={groupName}
          value={opt.value}
          label={opt.label}
          checked={current === opt.value}
          onChange={handleChange}
          disabled={disabled || opt.disabled}
        />
      ))

  return (
    <div
      role="radiogroup"
      aria-orientation={orientation}
      aria-labelledby={label ? labelId : undefined}
      className={cn('flex flex-col gap-2', className)}
      {...props}
    >
      {label != null && (
        <span
          id={labelId}
          className={cn(
            'text-sm font-medium text-text-secondary',
            disabled && 'opacity-50',
          )}
        >
          {label}
        </span>
      )}
      <div
        className={cn(
          'flex',
          orientation === 'horizontal'
            ? 'flex-row flex-wrap items-center gap-x-5 gap-y-2'
            : 'flex-col gap-2.5',
        )}
      >
        {radios}
      </div>
    </div>
  )
}

RadioGroup.displayName = 'RadioGroup'

export default RadioGroup
export { Radio, RadioGroup }
