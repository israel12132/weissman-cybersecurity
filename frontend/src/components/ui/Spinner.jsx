import { forwardRef } from 'react'
import { cn } from '../../lib/cn'

const SIZES = {
  xs: 'size-3',
  sm: 'size-3.5',
  md: 'size-4',
  lg: 'size-6',
  xl: 'size-8',
}

/**
 * Standalone loading indicator — a spinning cyan ring for pending states.
 * Mirrors the inline spinner in Button.jsx. Announces itself via role="status"
 * with an sr-only label for assistive tech.
 *
 * @param {'xs'|'sm'|'md'|'lg'|'xl'} size
 * @param {string} label — sr-only text describing what is loading
 * @param {string} className — merged onto the spinning svg
 */
const Spinner = forwardRef(function Spinner(
  { size = 'md', label = 'Loading', className, ...props },
  ref,
) {
  return (
    <span ref={ref} role="status" className="inline-flex" {...props}>
      <span className="sr-only">{label}</span>
      <svg
        className={cn('animate-spin', SIZES[size] ?? SIZES.md, 'text-accent-cyan', className)}
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
    </span>
  )
})

Spinner.displayName = 'Spinner'

export default Spinner
export { Spinner }
