import { Building2, ChevronRight } from 'lucide-react'
import { cn } from '../../lib/cn'

function postureTone(score) {
  const s = Number(score) || 0
  if (s >= 80) return 'text-status-active'
  if (s >= 60) return 'text-severity-medium'
  return 'text-severity-critical'
}

/**
 * PartnerPortal — an MSSP multi-tenant overview. Renders a grid of managed
 * tenants with per-tenant posture, client and open-finding counts, and a status
 * dot; selecting a tenant drills into its workspace.
 *
 * @param {Array<{id:string,name:string,clients?:number,openFindings?:number,
 *   posture?:number,status?:'active'|'pending'|'offline'}>} tenants
 * @param {string} [activeTenantId] @param {(tenant:object)=>void} [onSelectTenant]
 */
export default function PartnerPortal({ tenants = [], activeTenantId, onSelectTenant, emptyMessage = 'No managed tenants', className, ...props }) {
  if (!Array.isArray(tenants) || tenants.length === 0) {
    return <p className={cn('text-xs text-text-muted', className)}>{emptyMessage}</p>
  }

  const STATUS_DOT = {
    active: 'bg-status-active',
    pending: 'bg-status-pending',
    offline: 'bg-status-offline',
  }

  return (
    <div
      className={cn('grid gap-3 sm:grid-cols-2 lg:grid-cols-3', className)}
      role="group"
      aria-label="Managed tenants"
      {...props}
    >
      {tenants.map((t) => {
        const active = t.id === activeTenantId
        return (
          <button
            key={t.id}
            type="button"
            onClick={() => onSelectTenant?.(t)}
            aria-current={active ? 'true' : undefined}
            className={cn(
              'group flex flex-col gap-3 rounded-xl border bg-bg-2 p-4 text-start transition-all duration-normal',
              active ? 'border-accent-cyan shadow-glow-cyan' : 'border-border-default hover:border-border-strong hover:bg-bg-3',
              'focus-visible:outline-none focus-visible:shadow-[var(--focus-ring)]',
            )}
          >
            <div className="flex items-center gap-2.5">
              <span className="inline-flex size-9 shrink-0 items-center justify-center rounded-lg bg-bg-3 text-text-tertiary">
                <Building2 className="size-4" aria-hidden="true" />
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate font-display text-sm font-semibold text-text-primary">{t.name}</span>
                <span className="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-text-muted">
                  <span className={cn('size-1.5 rounded-full', STATUS_DOT[t.status] ?? STATUS_DOT.active)} aria-hidden="true" />
                  {t.status ?? 'active'}
                </span>
              </span>
              <ChevronRight className="size-4 shrink-0 text-text-disabled group-hover:text-text-muted" aria-hidden="true" />
            </div>

            <div className="grid grid-cols-3 gap-2 border-t border-border-subtle pt-3">
              <span className="flex flex-col">
                <span className="text-sm font-semibold text-text-primary tabular-nums">{t.clients ?? 0}</span>
                <span className="text-[10px] uppercase tracking-wide text-text-muted">Clients</span>
              </span>
              <span className="flex flex-col">
                <span className="text-sm font-semibold text-text-primary tabular-nums">{t.openFindings ?? 0}</span>
                <span className="text-[10px] uppercase tracking-wide text-text-muted">Open</span>
              </span>
              <span className="flex flex-col">
                <span className={cn('text-sm font-semibold tabular-nums', postureTone(t.posture))}>
                  {t.posture ?? '—'}
                </span>
                <span className="text-[10px] uppercase tracking-wide text-text-muted">Posture</span>
              </span>
            </div>
          </button>
        )
      })}
    </div>
  )
}

export { PartnerPortal }
