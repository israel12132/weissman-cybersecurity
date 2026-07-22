import { Children, cloneElement, forwardRef, isValidElement, useState } from 'react'
import { User } from 'lucide-react'
import { cn } from '../../lib/cn'

const SIZES = {
  xs: { box: 'size-6 text-[10px]', icon: 'size-3.5', dot: 'size-1.5' },
  sm: { box: 'size-8 text-xs', icon: 'size-4', dot: 'size-2' },
  md: { box: 'size-10 text-sm', icon: 'size-5', dot: 'size-2.5' },
  lg: { box: 'size-12 text-base', icon: 'size-6', dot: 'size-3' },
  xl: { box: 'size-16 text-lg', icon: 'size-8', dot: 'size-3.5' },
}

const STATUS_STYLES = {
  online: 'bg-status-active',
  offline: 'bg-status-offline',
  away: 'bg-status-pending',
  busy: 'bg-status-error',
}

/** Derive up to two uppercased initials from a display name. */
function getInitials(name) {
  if (!name) return ''
  const parts = String(name).trim().split(/\s+/).filter(Boolean)
  if (parts.length === 0) return ''
  return parts
    .slice(0, 2)
    .map((part) => part[0])
    .join('')
    .toUpperCase()
}

/**
 * Avatar primitive — image with graceful initials / icon fallback and an
 * optional presence dot.
 *
 * @param {string} src — image URL; falls back to initials/icon on load error
 * @param {string} alt — image alt text (defaults to name)
 * @param {string} name — display name, source of initials and the a11y label
 * @param {'xs'|'sm'|'md'|'lg'|'xl'} size
 * @param {'online'|'offline'|'away'|'busy'} status — presence indicator dot
 * @param {'circle'|'square'} shape
 */
const Avatar = forwardRef(function Avatar(
  {
    src,
    alt,
    name,
    size = 'md',
    status,
    shape = 'circle',
    className,
    ...props
  },
  ref,
) {
  const [errored, setErrored] = useState(false)
  const sizing = SIZES[size] ?? SIZES.md
  const radius = shape === 'square' ? 'rounded-lg' : 'rounded-full'
  const showImage = Boolean(src) && !errored
  const initials = getInitials(name)

  return (
    <span
      ref={ref}
      className={cn(
        'relative inline-flex shrink-0 items-center justify-center',
        'select-none align-middle font-sans font-medium',
        radius,
        sizing.box,
        className,
      )}
      {...props}
    >
      {showImage ? (
        <img
          src={src}
          alt={alt ?? name ?? ''}
          onError={() => setErrored(true)}
          className={cn('size-full object-cover', radius)}
        />
      ) : (
        <>
          <span
            aria-hidden="true"
            className={cn(
              'flex size-full items-center justify-center',
              'bg-bg-3 text-text-secondary',
              radius,
            )}
          >
            {initials || <User className={sizing.icon} aria-hidden="true" />}
          </span>
          {name && <span className="sr-only">{name}</span>}
        </>
      )}
      {status && (
        <span
          aria-hidden="true"
          className={cn(
            'absolute end-0 bottom-0 rounded-full ring-2 ring-bg-1',
            sizing.dot,
            STATUS_STYLES[status] ?? STATUS_STYLES.offline,
          )}
        />
      )}
    </span>
  )
})

Avatar.displayName = 'Avatar'

/**
 * AvatarGroup — a compact, overlapping stack of avatars with a `+N` overflow
 * chip once the child count exceeds `max`.
 *
 * @param {number} max — maximum avatars shown before collapsing into `+N`
 * @param {'xs'|'sm'|'md'|'lg'|'xl'} size — applied to children lacking their own
 */
function AvatarGroup({ max, size = 'md', className, children, ...props }) {
  const items = Children.toArray(children).filter(Boolean)
  const total = items.length
  const limit = typeof max === 'number' && max > 0 ? Math.min(max, total) : total
  const visible = items.slice(0, limit)
  const overflow = total - visible.length
  const sizing = SIZES[size] ?? SIZES.md

  return (
    <div className={cn('inline-flex items-center', className)} {...props}>
      {visible.map((child, index) => {
        const overlap = cn(index > 0 && '-ms-2', 'ring-2 ring-bg-1')
        if (isValidElement(child)) {
          return cloneElement(child, {
            key: child.key ?? index,
            size: child.props.size ?? size,
            className: cn(child.props.className, overlap),
          })
        }
        return (
          <span key={index} className={overlap}>
            {child}
          </span>
        )
      })}
      {overflow > 0 && (
        <span
          aria-hidden="true"
          className={cn(
            'inline-flex shrink-0 items-center justify-center -ms-2',
            'rounded-full ring-2 ring-bg-1',
            'bg-bg-3 text-text-secondary font-sans font-medium',
            sizing.box,
          )}
        >
          +{overflow}
        </span>
      )}
    </div>
  )
}

AvatarGroup.displayName = 'AvatarGroup'

export default Avatar
export { Avatar, AvatarGroup }
