import { useState } from 'react'
import { Send } from 'lucide-react'
import { cn } from '../../lib/cn'
import Avatar from './Avatar.jsx'

/**
 * CommentThread — a collaborative comment thread for findings / incidents.
 * Presentational: pass the comment list and handle `onSubmit`; wire it to your
 * realtime backend (WebSocket/CRDT) to make it live.
 *
 * @param {Array<{id?:string|number,author?:{name?:string,src?:string},body:React.ReactNode,timestamp?:React.ReactNode}>} comments
 * @param {(text:string)=>void} onSubmit
 * @param {string} [placeholder='Add a comment…'] @param {string} [emptyMessage='No comments yet']
 */
export default function CommentThread({
  comments = [],
  onSubmit,
  placeholder = 'Add a comment…',
  emptyMessage = 'No comments yet',
  className,
  ...props
}) {
  const [value, setValue] = useState('')

  const submit = () => {
    const t = value.trim()
    if (!t) return
    onSubmit?.(t)
    setValue('')
  }

  return (
    <div className={cn('flex flex-col gap-3', className)} {...props}>
      <ol role="log" aria-label="Comments" className="flex flex-col gap-3">
        {comments.length === 0 && <li className="text-xs text-text-muted">{emptyMessage}</li>}
        {comments.map((c, i) => (
          <li key={c.id ?? i} className="flex gap-2.5">
            <Avatar name={c.author?.name} src={c.author?.src} size="sm" className="mt-0.5 shrink-0" />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-baseline gap-x-2">
                <span className="text-xs font-medium text-text-primary">{c.author?.name || 'Unknown'}</span>
                {c.timestamp != null && (
                  <span className="text-[10px] text-text-muted">{c.timestamp}</span>
                )}
              </div>
              <p className="mt-0.5 whitespace-pre-wrap break-words text-sm leading-relaxed text-text-secondary">
                {c.body}
              </p>
            </div>
          </li>
        ))}
      </ol>

      <form
        className="flex items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault()
          submit()
        }}
      >
        <input
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={placeholder}
          aria-label="Add a comment"
          className="flex-1 rounded-lg border border-border-default bg-bg-1 px-3 py-2 text-sm text-text-primary outline-none placeholder:text-text-muted focus-visible:border-accent-cyan/50 focus-visible:shadow-[var(--focus-ring)]"
        />
        <button
          type="submit"
          disabled={!value.trim()}
          aria-label="Post comment"
          className="inline-flex size-9 items-center justify-center rounded-lg bg-accent-cyan text-text-inverse disabled:opacity-40 focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]"
        >
          <Send className="size-4" aria-hidden="true" />
        </button>
      </form>
    </div>
  )
}

export { CommentThread }
