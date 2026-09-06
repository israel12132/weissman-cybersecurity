import { useTranslation } from 'react-i18next'
import { Lock } from 'lucide-react'
import { useScopedClient } from '../../hooks/useScopedClient'

/**
 * Drop-in replacement for every engine/module client <select>.
 *
 * Scoped / single-customer sessions render a locked identity chip — never a
 * dropdown, never an empty "choose client" placeholder.
 */
export default function ScopedClientControl({
  value,
  onChange,
  clients,
  className = '',
  placeholder,
  id,
  disabled = false,
  name = 'client_id',
  allowEmpty = false,
}) {
  const { t } = useTranslation()
  const scoped = useScopedClient(value, onChange, clients)
  const label = scoped.selectedClient?.name || (scoped.clientId != null ? `#${scoped.clientId}` : null)

  if (scoped.hidePicker) {
    if (!label) {
      return (
        <div
          className={`inline-flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-xs font-mono text-amber-200 ${className}`}
          role="status"
        >
          <Lock className="w-3.5 h-3.5 shrink-0" aria-hidden />
          <span>{t('components.scopedClient.unbound')}</span>
        </div>
      )
    }
    return (
      <div
        className={`inline-flex items-center gap-2 rounded-lg border border-cyan-500/35 bg-cyan-500/10 px-3 py-1.5 text-xs font-mono text-cyan-100 ${className}`}
        title={t('components.scopedClient.locked_hint')}
        role="status"
        aria-label={t('components.scopedClient.bound_aria', { name: label })}
      >
        <Lock className="w-3.5 h-3.5 shrink-0 text-cyan-300" aria-hidden />
        <span className="truncate max-w-[16rem]">{label}</span>
        <span className="text-[9px] uppercase tracking-widest text-cyan-400/70 shrink-0">
          {t('components.scopedClient.locked')}
        </span>
      </div>
    )
  }

  return (
    <select
      id={id}
      name={name}
      disabled={disabled}
      value={scoped.clientId ?? ''}
      onChange={(e) => {
        const raw = e.target.value
        if (!raw) {
          scoped.setClientId(allowEmpty ? null : '')
          return
        }
        const n = Number(raw)
        scoped.setClientId(Number.isFinite(n) && n > 0 ? n : raw)
      }}
      className={
        className
        || 'bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs font-mono text-[var(--text-secondary)]'
      }
      aria-label={placeholder || t('components.scopedClient.select')}
    >
      {allowEmpty || scoped.clients.length === 0 ? (
        <option value="">{placeholder || t('components.scopedClient.select')}</option>
      ) : null}
      {scoped.clients.map((c) => (
        <option key={c.id} value={c.id}>
          {c.name || c.id}
        </option>
      ))}
    </select>
  )
}
