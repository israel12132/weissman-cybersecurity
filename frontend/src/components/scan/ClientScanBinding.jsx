import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { firstClientTarget } from '../../lib/clientTarget'
import { useClientOptional } from '../../context/ClientContext'

/**
 * Client binding for scan enqueue. Scoped/portal users are locked to their
 * assigned customer — never a picker.
 */
export default function ClientScanBinding({
  clients = [],
  selectedClientId,
  onChange,
  locked = false,
  disabled = false,
  selectClassName = 'bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-2 text-sm text-[var(--text-secondary)] font-mono focus:outline-none focus:border-cyan-500/40',
  emptyLabel,
  id = 'scan-client',
}) {
  const { t } = useTranslation()
  const selected = clients.find((c) => String(c.id) === String(selectedClientId))
  const domain = firstClientTarget(selected)

  if (locked) {
    return (
      <div
        data-testid="client-scan-binding-locked"
        className="rounded-lg border border-cyan-500/25 bg-cyan-950/20 px-3 py-2 min-w-0"
      >
        <div className="text-sm font-mono text-[var(--text-primary)] truncate">
          {selected?.name || t('engines.workspace_locked')}
        </div>
        {domain ? (
          <div className="text-[10px] font-mono text-cyan-300/80 truncate mt-0.5">{domain}</div>
        ) : (
          <div className="text-[10px] font-mono text-amber-300/80 mt-0.5">
            {t('engines.no_assigned_domain')}
          </div>
        )}
        <div className="text-[9px] font-mono uppercase tracking-widest text-cyan-400/70 mt-1">
          {t('nav.portal_locked')}
        </div>
      </div>
    )
  }

  return (
    <div className="flex items-center gap-2 min-w-0 flex-wrap" data-testid="client-scan-binding-picker">
      <select
        id={id}
        value={selectedClientId ?? ''}
        onChange={(e) => onChange?.(e.target.value || null)}
        disabled={disabled}
        className={selectClassName}
        aria-label={t('engines.client_label')}
      >
        <option value="">{emptyLabel || t('engines.select_client')}</option>
        {clients.map((c) => (
          <option key={c.id} value={c.id}>{c.name || `Client ${c.id}`}</option>
        ))}
      </select>
      {domain && (
        <span className="text-[10px] font-mono text-[var(--text-muted)] truncate max-w-[220px]">
          {domain}
        </span>
      )}
    </div>
  )
}

/**
 * Drop-in replacement for in-page client `<select>` lists.
 * Portal sessions bind to the assigned client (no picker) and sync that id
 * into the page's local state so Run stays enabled and targets auto-fill.
 */
export function BoundClientScanField({
  clients = [],
  selectedClientId,
  onChange,
  emptyLabel,
  selectClassName,
  id,
  disabled = false,
}) {
  const ctx = useClientOptional()
  const locked = ctx?.clientScopeLocked === true
  const boundId = locked ? (ctx?.selectedClientId ?? selectedClientId) : selectedClientId
  const boundClients = locked && ctx?.clients?.length ? ctx.clients : clients

  useEffect(() => {
    if (!locked || ctx?.selectedClientId == null || !onChange) return
    if (String(selectedClientId) === String(ctx.selectedClientId)) return
    onChange(ctx.selectedClientId)
  }, [locked, ctx?.selectedClientId, selectedClientId, onChange])

  return (
    <ClientScanBinding
      clients={boundClients}
      selectedClientId={boundId}
      onChange={locked ? undefined : onChange}
      locked={locked}
      disabled={disabled}
      emptyLabel={emptyLabel}
      selectClassName={selectClassName}
      id={id}
    />
  )
}
