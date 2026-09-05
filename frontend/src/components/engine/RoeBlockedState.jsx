import { ShieldAlert } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router'

export function RoeBlockedBadge({ className = '' }) {
  const { t } = useTranslation()
  return (
    <span
      role="status"
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border border-amber-500/45 bg-amber-950/40 text-amber-200 text-[10px] font-mono uppercase tracking-widest ${className}`}
    >
      <ShieldAlert className="w-3 h-3" aria-hidden />
      {t('roeBlocked.badge')}
    </span>
  )
}

/** Distinct fail-closed panel — not green success, not a fake empty findings list. */
export default function RoeBlockedState({ roe, compact = false, className = '' }) {
  const { t, i18n } = useTranslation()
  const control = roe?.control || 'industrial_ot_enabled'
  const wouldRun = roe?.would_run_if_authorized
  const clientId = roe?.client_id
  const blockedAt = roe?.blocked_at
  let when = null
  if (blockedAt) {
    try {
      when = new Date(blockedAt).toLocaleString(i18n.language)
    } catch {
      when = String(blockedAt)
    }
  }

  return (
    <div
      role="status"
      className={`rounded-xl border border-amber-500/40 bg-amber-950/25 p-3 space-y-2 ${className}`}
    >
      <div className="flex items-start gap-2">
        <ShieldAlert className="w-4 h-4 text-amber-300 shrink-0 mt-0.5" aria-hidden />
        <div className="min-w-0 space-y-1">
          <RoeBlockedBadge />
          <p className="text-[12px] font-semibold text-amber-100">{t('roeBlocked.title')}</p>
          <p className="text-[11px] text-amber-100/80 leading-relaxed">{t('roeBlocked.notEmpty')}</p>
        </div>
      </div>
      <p className="text-[11px] font-mono text-amber-200/90">{t('roeBlocked.control', { control })}</p>
      {wouldRun && (
        <p className="text-[11px] text-[var(--text-secondary)] leading-relaxed">
          {t('roeBlocked.wouldRun', { detail: wouldRun })}
        </p>
      )}
      {!compact && (
        <>
          <p className="text-[11px] text-amber-100/80 leading-relaxed">{t('roeBlocked.whoMustEnable')}</p>
          <div className="rounded-lg border border-amber-500/20 bg-black/20 p-2 space-y-1">
            <p className="text-[10px] font-mono uppercase tracking-widest text-amber-300/80">
              {t('roeBlocked.enableTitle')}
            </p>
            <p className="text-[11px] text-[var(--text-secondary)] leading-relaxed">{t('roeBlocked.enableStepOt')}</p>
            <p className="text-[11px] text-[var(--text-secondary)] leading-relaxed">{t('roeBlocked.enableStepRoe')}</p>
            <p className="text-[11px] text-[var(--text-secondary)] leading-relaxed">{t('roeBlocked.enableStepAuth')}</p>
          </div>
        </>
      )}
      <div className="flex flex-wrap gap-x-3 gap-y-1 text-[10px] font-mono text-amber-200/70">
        {clientId != null && (
          <Link to={`/clients/${clientId}`} className="text-cyan-400 hover:underline">
            {t('roeBlocked.clientId', { id: clientId })}
          </Link>
        )}
        {when && <span>{t('roeBlocked.timestamp', { time: when })}</span>}
        <span>{t('roeBlocked.neverAuto')}</span>
      </div>
    </div>
  )
}
