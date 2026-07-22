import { forwardRef } from 'react'
import { Download, FileText, ShieldAlert, ShieldCheck } from 'lucide-react'
import { cn } from '../../lib/cn'

function shortHash(hash) {
  const h = String(hash || '')
  if (h.length <= 16) return h
  return `${h.slice(0, 8)}…${h.slice(-6)}`
}

/**
 * EvidenceVault — a tamper-evident evidence ledger. Each artifact shows its
 * content hash, seal time, and a verification state (a green seal when the
 * recomputed hash matches, red when it does not). Presentational: verification
 * happens server-side; pass `verified` per item and handle onVerify/onDownload.
 *
 * @param {Array<{id:string,name:string,hash?:string,sealedAt?:React.ReactNode,
 *   verified?:boolean,size?:React.ReactNode,kind?:string}>} items
 * @param {(id:string)=>void} [onVerify] @param {(id:string)=>void} [onDownload]
 */
const EvidenceVault = forwardRef(function EvidenceVault(
  { items = [], onVerify, onDownload, emptyMessage = 'The vault is empty', className, ...props },
  ref,
) {
  if (!Array.isArray(items) || items.length === 0) {
    return <p ref={ref} className={cn('text-xs text-text-muted', className)}>{emptyMessage}</p>
  }

  return (
    <ul ref={ref} className={cn('flex flex-col gap-2', className)} {...props}>
      {items.map((item) => {
        const tampered = item.verified === false
        const Seal = tampered ? ShieldAlert : ShieldCheck
        return (
          <li
            key={item.id}
            className="flex flex-wrap items-center gap-3 rounded-xl border border-border-default bg-bg-2 p-3"
          >
            <span
              className={cn(
                'inline-flex size-8 shrink-0 items-center justify-center rounded-lg',
                tampered ? 'bg-severity-critical-bg text-severity-critical' : 'bg-status-active-bg text-status-active',
              )}
              aria-hidden="true"
            >
              <Seal className="size-4" />
            </span>

            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1.5">
                <FileText className="size-3.5 shrink-0 text-text-muted" aria-hidden="true" />
                <span className="truncate text-sm font-medium text-text-primary">{item.name}</span>
              </div>
              <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-text-muted">
                {item.hash && (
                  <span className="font-mono" title={item.hash}>
                    sha256:{shortHash(item.hash)}
                  </span>
                )}
                {item.sealedAt != null && <span>sealed {item.sealedAt}</span>}
                {item.size != null && <span className="tabular-nums">{item.size}</span>}
              </div>
            </div>

            <span
              className={cn(
                'rounded-md px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide',
                tampered
                  ? 'bg-severity-critical-bg text-severity-critical'
                  : 'bg-status-active-bg text-status-active',
              )}
            >
              {tampered ? 'Tampered' : 'Verified'}
            </span>

            <div className="flex items-center gap-1">
              {onVerify && (
                <button
                  type="button"
                  onClick={() => onVerify(item.id)}
                  aria-label={`Verify ${item.name}`}
                  className="rounded-lg border border-border-default px-2 py-1 text-[11px] text-text-secondary hover:bg-bg-3 focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]"
                >
                  Verify
                </button>
              )}
              {onDownload && (
                <button
                  type="button"
                  onClick={() => onDownload(item.id)}
                  aria-label={`Download ${item.name}`}
                  className="rounded-lg p-1.5 text-text-muted hover:text-text-secondary focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]"
                >
                  <Download className="size-4" aria-hidden="true" />
                </button>
              )}
            </div>
          </li>
        )
      })}
    </ul>
  )
})

EvidenceVault.displayName = 'EvidenceVault'

export default EvidenceVault
export { EvidenceVault }
