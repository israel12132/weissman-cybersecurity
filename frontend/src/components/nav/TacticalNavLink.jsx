import { Link } from 'react-router'
import { onNavIntent } from '../../boot/intentPrefetch'

/**
 * Nav link with predictive micro-chunk prefetch on operator intent (hover/focus).
 */
export default function TacticalNavLink({
  to,
  prefetch = true,
  onMouseEnter,
  onFocus,
  children,
  ...rest
}) {
  const handleIntent = (e) => {
    if (prefetch && to) onNavIntent(to)
    onMouseEnter?.(e)
  }
  const handleFocus = (e) => {
    if (prefetch && to) onNavIntent(to)
    onFocus?.(e)
  }

  return (
    <Link
      to={to}
      onMouseEnter={handleIntent}
      onFocus={handleFocus}
      {...rest}
    >
      {children}
    </Link>
  )
}
