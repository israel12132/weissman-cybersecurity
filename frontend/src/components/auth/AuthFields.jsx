import React, { useState } from 'react'

/**
 * Floating-label field primitives for the Command Center sign-in surface.
 *
 * Lifted out of Login.jsx so the credential controls stay in one place. There is no second
 * login page and no tenant/workspace picker on this form — email + password (and MFA) only.
 */

/** Border, background, and focus treatment shared by every auth control. */
export const authControlClass = (focused) =>
  `peer w-full rounded-xl border bg-white/[0.03] px-4 pb-3 pt-7 text-sm text-white outline-none transition-all duration-200 placeholder:text-white/25 disabled:cursor-not-allowed disabled:opacity-50 ${
    focused
      ? 'border-cyan-400/50 shadow-[0_0_0_3px_rgba(34,211,238,0.12),0_0_24px_rgba(34,211,238,0.08)]'
      : 'border-white/10 hover:border-white/20'
  }`

/** The label itself: small caps above a filled control, placeholder-sized over an empty one. */
export const authLabelClass = (floated) =>
  `pointer-events-none absolute start-4 z-10 origin-start transition-all duration-200 ${
    floated
      ? 'top-2.5 text-[10px] font-medium uppercase tracking-[0.14em] text-cyan-400/80'
      : 'top-1/2 -translate-y-1/2 text-sm text-white/45'
  }`

export const FloatingInput = React.forwardRef(function FloatingInput(
  {
    id,
    label,
    type = 'text',
    value,
    onChange,
    required,
    autoComplete,
    inputMode,
    placeholder,
    disabled,
    endAdornment,
    className = '',
    inputClassName = '',
    describedBy,
    onFocus,
    onBlur,
  },
  ref,
) {
  const [focused, setFocused] = useState(false)
  const floated = focused || (value != null && String(value).length > 0)

  return (
    <div className={`relative ${className}`}>
      <label htmlFor={id} className={authLabelClass(floated)}>
        {label}
      </label>
      <input
        ref={ref}
        id={id}
        type={type}
        value={value}
        onChange={onChange}
        required={required}
        autoComplete={autoComplete}
        inputMode={inputMode}
        placeholder={floated ? placeholder : undefined}
        disabled={disabled}
        aria-describedby={describedBy}
        onFocus={(e) => {
          setFocused(true)
          onFocus?.(e)
        }}
        onBlur={(e) => {
          setFocused(false)
          onBlur?.(e)
        }}
        className={`${authControlClass(focused)} ${endAdornment ? 'pe-12' : ''} ${inputClassName}`}
      />
      {endAdornment}
    </div>
  )
})
