import { forwardRef } from 'react'
import { cn } from '../../lib/cn'

const VARIANTS = {
  primary: [
    'bg-accent-gradient text-text-inverse font-medium',
    'shadow-sm shadow-glow-cyan/30',
    'border border-accent-cyan/30',
    'hover:brightness-110 hover:shadow-glow-cyan',
    'active:brightness-95 active:scale-[0.98]',
    'disabled:opacity-45 disabled:pointer-events-none disabled:shadow-none',
  ],
  secondary: [
    'bg-bg-2 text-text-primary font-medium',
    'border border-border-default',
    'shadow-xs',
    'hover:bg-bg-3 hover:border-border-strong',
    'active:bg-bg-2 active:scale-[0.98]',
    'disabled:opacity-40 disabled:pointer-events-none',
  ],
  ghost: [
    'bg-transparent text-text-secondary font-medium',
    'border border-transparent',
    'hover:bg-bg-2/60 hover:text-text-primary hover:border-border-subtle',
    'active:bg-bg-2/80',
    'disabled:opacity-35 disabled:pointer-events-none',
  ],
  danger: [
    'bg-severity-critical-bg text-severity-critical font-medium',
    'border border-severity-critical-border',
    'hover:bg-severity-critical/20 hover:border-severity-critical/50',
    'active:scale-[0.98]',
    'disabled:opacity-40 disabled:pointer-events-none',
    'focus-ring-danger',
  ],
  premium: [
    'relative overflow-hidden text-text-primary font-semibold',
    'bg-bg-2 border border-border-accent-violet',
    'shadow-glow-premium',
    'before:absolute before:inset-0 before:bg-accent-gradient-subtle before:opacity-80',
    'after:absolute after:inset-x-0 after:top-0 after:h-px after:bg-accent-gradient',
    'hover:border-accent-violet/50 hover:shadow-glow-violet',
    'active:scale-[0.98]',
    'disabled:opacity-40 disabled:pointer-events-none disabled:shadow-none',
    'focus-ring-violet',
  ],
}

const SIZES = {
  xs: 'h-7 px-2.5 gap-1 text-xs rounded-sm',
  sm: 'h-8 px-3 gap-1.5 text-sm rounded-md',
  md: 'h-9 px-4 gap-2 text-sm rounded-lg',
  lg: 'h-11 px-5 gap-2.5 text-base rounded-lg',
  xl: 'h-12 px-6 gap-3 text-md rounded-xl',
}

function Spinner({ className }) {
  return (
    <svg
      className={cn('animate-spin', className)}
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
      aria-hidden="true"
    >
      <circle
        className="opacity-20"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="3"
      />
      <path
        className="opacity-90"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      />
    </svg>
  )
}

const Button = forwardRef(function Button(
  {
    variant = 'primary',
    size = 'md',
    loading = false,
    fullWidth = false,
    leftIcon,
    rightIcon,
    className,
    children,
    disabled,
    type = 'button',
    ...props
  },
  ref,
) {
  const isDisabled = disabled || loading
  const isPremium = variant === 'premium'

  const content = (
    <>
      {loading && <Spinner className="size-3.5 shrink-0" />}
      {!loading && leftIcon && (
        <span className="inline-flex shrink-0 [&>svg]:size-4">{leftIcon}</span>
      )}
      {children && (
        <span className={isPremium ? undefined : loading ? 'opacity-70' : undefined}>
          {children}
        </span>
      )}
      {!loading && rightIcon && (
        <span className="inline-flex shrink-0 [&>svg]:size-4">{rightIcon}</span>
      )}
    </>
  )

  return (
    <button
      ref={ref}
      type={type}
      disabled={isDisabled}
      aria-busy={loading || undefined}
      className={cn(
        'relative inline-flex items-center justify-center',
        'font-sans tracking-tight',
        'transition-all duration-normal ease-out-expo',
        'focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]',
        VARIANTS[variant] ?? VARIANTS.primary,
        SIZES[size] ?? SIZES.md,
        fullWidth && 'w-full',
        className,
      )}
      {...props}
    >
      {isPremium ? (
        <span className="relative z-10 inline-flex items-center gap-[inherit]">
          {content}
        </span>
      ) : (
        content
      )}
    </button>
  )
})

Button.displayName = 'Button'

export default Button
export { Button }
