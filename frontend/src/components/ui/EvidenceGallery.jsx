import { useState } from 'react'
import { ChevronLeft, ChevronRight, FileText, ScrollText } from 'lucide-react'
import { cn } from '../../lib/cn'
import Modal from './Modal.jsx'

/**
 * EvidenceGallery — a thumbnail grid of finding evidence with a lightbox built
 * on the Modal primitive. Supports image, log, and generic file items and lets
 * the viewer page through them with Prev/Next.
 *
 * @param {Array<{id?:string|number,src?:string,alt?:string,caption?:string,
 *   kind?:'image'|'log'|'file',content?:string}>} items
 * @param {number} [columns=3] @param {string} [title='Evidence']
 * @param {string} [emptyMessage='No evidence attached']
 */
export default function EvidenceGallery({
  items = [],
  columns = 3,
  title = 'Evidence',
  emptyMessage = 'No evidence attached',
  className,
  ...props
}) {
  const [openIndex, setOpenIndex] = useState(null)

  if (!Array.isArray(items) || items.length === 0) {
    return <p className={cn('text-xs text-text-muted', className)}>{emptyMessage}</p>
  }

  const current = openIndex != null ? items[openIndex] : null
  const go = (delta) =>
    setOpenIndex((i) => {
      if (i == null) return i
      return (i + delta + items.length) % items.length
    })

  const kindIcon = (kind) => (kind === 'log' ? ScrollText : FileText)

  return (
    <div className={cn('w-full', className)} {...props}>
      <div
        className="grid gap-2"
        style={{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }}
      >
        {items.map((item, i) => {
          const Icon = kindIcon(item.kind)
          const label = item.caption || item.alt || `Evidence ${i + 1}`
          return (
            <button
              key={item.id ?? i}
              type="button"
              onClick={() => setOpenIndex(i)}
              aria-label={label}
              className={cn(
                'group relative aspect-video overflow-hidden rounded-lg border border-border-default bg-bg-3',
                'transition-colors hover:border-border-strong',
                'focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]',
              )}
            >
              {item.kind !== 'log' && item.kind !== 'file' && item.src ? (
                <img src={item.src} alt={item.alt || label} className="size-full object-cover" />
              ) : (
                <span className="flex size-full flex-col items-center justify-center gap-1 p-2 text-text-muted">
                  <Icon className="size-5" aria-hidden="true" />
                  <span className="line-clamp-2 text-center text-[10px] text-text-tertiary">
                    {label}
                  </span>
                </span>
              )}
            </button>
          )
        })}
      </div>

      <Modal
        open={openIndex !== null}
        onClose={() => setOpenIndex(null)}
        title={current?.caption || title}
        size="lg"
        footer={
          items.length > 1 ? (
            <div className="flex w-full items-center justify-between">
              <button
                type="button"
                onClick={() => go(-1)}
                aria-label="Previous evidence"
                className="inline-flex items-center gap-1 rounded-lg border border-border-default bg-bg-2 px-3 py-1.5 text-sm text-text-secondary hover:bg-bg-3 focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]"
              >
                <ChevronLeft className="size-4" aria-hidden="true" />
                Prev
              </button>
              <span className="text-xs tabular-nums text-text-muted">
                {openIndex != null ? openIndex + 1 : 0} / {items.length}
              </span>
              <button
                type="button"
                onClick={() => go(1)}
                aria-label="Next evidence"
                className="inline-flex items-center gap-1 rounded-lg border border-border-default bg-bg-2 px-3 py-1.5 text-sm text-text-secondary hover:bg-bg-3 focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]"
              >
                Next
                <ChevronRight className="size-4" aria-hidden="true" />
              </button>
            </div>
          ) : undefined
        }
      >
        {current && (
          <div className="space-y-3">
            {current.kind === 'log' || current.content ? (
              <pre className="max-h-[50vh] overflow-auto rounded-lg border border-border-subtle bg-bg-1 p-3 font-mono text-xs text-text-secondary">
                {current.content || current.caption}
              </pre>
            ) : current.kind === 'file' || !current.src ? (
              <div className="flex flex-col items-center gap-2 py-8 text-text-muted">
                <FileText className="size-8" aria-hidden="true" />
                <span className="text-sm text-text-tertiary">{current.caption || current.alt}</span>
              </div>
            ) : (
              <img
                src={current.src}
                alt={current.alt || current.caption || 'Evidence'}
                className="mx-auto max-h-[60vh] rounded-lg object-contain"
              />
            )}
            {current.caption && current.kind !== 'log' && (
              <p className="text-xs text-text-tertiary">{current.caption}</p>
            )}
          </div>
        )}
      </Modal>
    </div>
  )
}

export { EvidenceGallery }
