import type { ReactNode } from 'react'

/** Isolate emails, URLs, code, and identifiers as LTR inside RTL copy. */
export function Ltr({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <span dir="ltr" className={`ltr-isolate ${className}`}>
      {children}
    </span>
  )
}

/** Render a catalog string, isolating `{email}` (or another token) as LTR. */
export function TextWithLtr({
  template,
  token = 'email',
  value,
}: {
  template: string
  token?: string
  value: string
}) {
  const needle = `{${token}}`
  const parts = template.split(needle)
  if (parts.length === 1) return <>{template}</>
  return (
    <>
      {parts.map((part, i) => (
        <span key={i}>
          {part}
          {i < parts.length - 1 ? <Ltr>{value}</Ltr> : null}
        </span>
      ))}
    </>
  )
}
