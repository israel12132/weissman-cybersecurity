import type { AnchorHTMLAttributes, ButtonHTMLAttributes, ReactNode } from 'react'
import { useI18n } from '../i18n'
import { track, type AnalyticsPayload } from '../lib/analytics'

type Shared = {
  children: ReactNode
  variant?: 'primary' | 'ghost' | 'text'
  className?: string
  analyticsEvent?: string
  analyticsPayload?: AnalyticsPayload
}

export function ButtonLink({
  children,
  variant = 'primary',
  className = '',
  href = '#',
  analyticsEvent,
  analyticsPayload,
  onClick,
  ...rest
}: Shared & AnchorHTMLAttributes<HTMLAnchorElement>) {
  const { href: loc } = useI18n()
  return (
    <a
      className={`${styles[variant]} group ${className}`}
      href={loc(href)}
      onClick={(e) => {
        if (analyticsEvent) track(analyticsEvent, analyticsPayload)
        onClick?.(e)
      }}
      {...rest}
    >
      <span>{children}</span>
      <span
        aria-hidden
        className="inline-block transition-transform duration-base group-hover:translate-x-0.5 rtl:rotate-180 rtl:group-hover:-translate-x-0.5"
      >
        →
      </span>
    </a>
  )
}

export function Button({
  children,
  variant = 'primary',
  className = '',
  ...rest
}: Shared & ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button className={`${styles[variant]} ${className}`} {...rest}>
      {children}
    </button>
  )
}

const styles: Record<NonNullable<Shared['variant']>, string> = {
  primary:
    'inline-flex min-h-11 items-center justify-center gap-2 rounded-[12px] bg-accent px-5 py-2.5 text-sm font-semibold text-[#041016] shadow-[0_0_0_0_rgba(34,211,238,0)] transition duration-base hover:-translate-y-px hover:shadow-[0_10px_28px_rgba(34,211,238,0.22)]',
  ghost:
    'inline-flex min-h-11 items-center justify-center gap-2 rounded-[12px] border border-[var(--line-strong)] px-5 py-2.5 text-sm font-semibold text-ink transition duration-base hover:border-accent hover:text-accent',
  text: 'inline-flex min-h-11 items-center gap-2 text-sm font-semibold text-accent',
}
