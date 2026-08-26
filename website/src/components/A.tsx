import type { AnchorHTMLAttributes, ReactNode } from 'react'
import { useI18n } from '../i18n'

type Props = AnchorHTMLAttributes<HTMLAnchorElement> & { children: ReactNode; href: string }

/** Localizes in-site hrefs. Pass-through for mailto, API, Command Center, and absolute URLs. */
export function A({ href, children, ...rest }: Props) {
  const { href: loc } = useI18n()
  return (
    <a href={loc(href)} {...rest}>
      {children}
    </a>
  )
}
