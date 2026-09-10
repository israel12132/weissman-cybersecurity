import { useTranslation } from 'react-i18next'

/**
 * Operator dual-control fields for destructive SOAR / agent actions.
 * Tokens must match WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET and WEISSMAN_DUAL_APPROVAL_SECRET.
 */
export default function DualControlGate({
  confirm,
  dual,
  reason,
  onConfirmChange,
  onDualChange,
  onReasonChange,
  showReason = false,
  reasonRequired = false,
  remember = true,
  onRememberChange,
  className = '',
}) {
  const { t } = useTranslation()
  return (
    <div className={`rounded-xl border border-amber-500/25 bg-amber-950/20 p-4 space-y-3 ${className}`}>
      <p className="text-[11px] font-mono uppercase tracking-wider text-amber-200/80">
        {t('dual_control.title')}
      </p>
      <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">
        {t('dual_control.hint')}
      </p>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <label className="block">
          <span className="text-[10px] font-mono uppercase text-[var(--text-muted)]">
            {t('dual_control.confirm_label')}
          </span>
          <input
            type="password"
            autoComplete="off"
            value={confirm}
            onChange={(e) => onConfirmChange(e.target.value)}
            placeholder="X-Weissman-Destructive-Confirm"
            className="mt-1 w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-[12px] font-mono text-[var(--text-secondary)] focus:outline-none focus:border-amber-400/50"
          />
        </label>
        <label className="block">
          <span className="text-[10px] font-mono uppercase text-[var(--text-muted)]">
            {t('dual_control.dual_label')}
          </span>
          <input
            type="password"
            autoComplete="off"
            value={dual}
            onChange={(e) => onDualChange(e.target.value)}
            placeholder="X-Weissman-Dual-Approve"
            className="mt-1 w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-[12px] font-mono text-[var(--text-secondary)] focus:outline-none focus:border-amber-400/50"
          />
        </label>
      </div>
      {showReason && (
        <label className="block">
          <span className="text-[10px] font-mono uppercase text-[var(--text-muted)]">
            {reasonRequired ? t('dual_control.reason_required') : t('dual_control.reason_optional')}
          </span>
          <input
            type="text"
            value={reason}
            onChange={(e) => onReasonChange(e.target.value)}
            placeholder={t('dual_control.reason_placeholder')}
            className="mt-1 w-full rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] px-3 py-1.5 text-[12px] text-[var(--text-secondary)] focus:outline-none focus:border-amber-400/50"
          />
        </label>
      )}
      {typeof onRememberChange === 'function' && (
        <label className="flex items-center gap-2 text-[11px] text-[var(--text-tertiary)]">
          <input
            type="checkbox"
            checked={remember}
            onChange={(e) => onRememberChange(e.target.checked)}
          />
          {t('dual_control.remember_session')}
        </label>
      )}
    </div>
  )
}
