import React, { forwardRef } from 'react'
import { cn } from '../../lib/cn'

const VARIANTS = {
  glass: 'glass-panel rounded-xl',
  elevated: 'glass-elevated rounded-xl',
  bordered: [
    'bg-bg-2 rounded-xl',
    'border border-border-default',
    'shadow-sm',
    'hover:border-border-strong transition-colors duration-normal',
  ],
}

/**
 * Surface card primitive with glass, elevated, or bordered treatments.
 *
 * @param {'glass'|'elevated'|'bordered'} variant
 * @param {boolean} padding — applies default inner padding
 * @param {boolean} interactive — subtle hover lift for clickable cards
 */
const Card = forwardRef(function Card(
  {
    variant = 'bordered',
    padding = true,
    interactive = false,
    className,
    children,
    ...props
  },
  ref,
) {
  return (
    <div
      ref={ref}
      className={cn(
        VARIANTS[variant] ?? VARIANTS.bordered,
        padding && 'p-5',
        interactive && [
          'cursor-pointer',
          'transition-all duration-normal ease-out-expo',
          'hover:-translate-y-px hover:shadow-md',
          variant === 'bordered' && 'hover:bg-bg-3',
        ],
        className,
      )}
      {...props}
    >
      {children}
    </div>
  )
})

Card.displayName = 'Card'

function CardHeader({ className, children, ...props }) {
  return (
    <div
      className={cn(
        'flex flex-col gap-1 mb-4',
        'border-b border-border-subtle pb-4',
        className,
      )}
      {...props}
    >
      {children}
    </div>
  )
}

function CardTitle({ className, children, ...props }) {
  return (
    <h3
      className={cn(
        'font-display text-lg font-semibold text-text-primary tracking-tight',
        className,
      )}
      {...props}
    >
      {children}
    </h3>
  )
}

function CardDescription({ className, children, ...props }) {
  return (
    <p
      className={cn('text-sm text-text-tertiary leading-relaxed', className)}
      {...props}
    >
      {children}
    </p>
  )
}

function CardBody({ className, children, ...props }) {
  return (
    <div className={cn('text-text-secondary text-sm', className)} {...props}>
      {children}
    </div>
  )
}

function CardFooter({ className, children, ...props }) {
  return (
    <div
      className={cn(
        'flex items-center gap-3 mt-4 pt-4',
        'border-t border-border-subtle',
        className,
      )}
      {...props}
    >
      {children}
    </div>
  )
}

export default Card
export { Card, CardHeader, CardTitle, CardDescription, CardBody, CardFooter }
