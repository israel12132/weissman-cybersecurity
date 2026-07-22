import { forwardRef } from 'react'
import { cn } from '../../lib/cn'
import Avatar from './Avatar.jsx'

/**
 * PresenceStack — overlapping avatars of the users currently viewing a
 * resource, for collaborative real-time surfaces. Pass the active users; wire
 * the list to your presence channel to make it live.
 *
 * @param {Array<{id?:string|number,name?:string,src?:string,status?:string}>} users
 * @param {number} [max=5] @param {'xs'|'sm'|'md'} [size='sm']
 * @param {boolean} [showLabel=true] — append an "N viewing" caption
 */
const PresenceStack = forwardRef(function PresenceStack(
  { users = [], max = 5, size = 'sm', showLabel = true, className, ...props },
  ref,
) {
  const shown = users.slice(0, max)
  const overflow = Math.max(0, users.length - shown.length)

  const dim = size === 'xs' ? 'size-6 text-[9px]' : size === 'md' ? 'size-9 text-xs' : 'size-7 text-[10px]'

  return (
    <div
      ref={ref}
      className={cn('flex items-center gap-2', className)}
      aria-label={`${users.length} viewing`}
      {...props}
    >
      <div className="flex items-center">
        {shown.map((u, i) => (
          <span key={u.id ?? i} className={cn('rounded-full ring-2 ring-bg-1', i > 0 && '-ms-2')}>
            <Avatar name={u.name} src={u.src} size={size} status={u.status || 'online'} />
          </span>
        ))}
        {overflow > 0 && (
          <span
            className={cn(
              'inline-flex items-center justify-center rounded-full ring-2 ring-bg-1 -ms-2',
              'bg-bg-4 font-medium text-text-secondary tabular-nums',
              dim,
            )}
          >
            +{overflow}
          </span>
        )}
      </div>
      {showLabel && users.length > 0 && (
        <span className="text-xs text-text-muted">{users.length} viewing</span>
      )}
    </div>
  )
})

PresenceStack.displayName = 'PresenceStack'

export default PresenceStack
export { PresenceStack }
