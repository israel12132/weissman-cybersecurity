import { useTranslation } from 'react-i18next'

/**
 * Executive-grade page header: title, live count badge, last-updated, primary actions.
 */
export default function PremiumPageHeader({
  title,
  subtitle,
  count,
  countLabel,
  lastUpdated,
  loading = false,
  onRefresh,
  onExport,
  exportLabel,
  refreshLabel,
  badge,
  badgeColor = '#22d3ee',
  children,
  className = '',
}) {
  const { t } = useTranslation()

  const formattedTime = lastUpdated
    ? lastUpdated.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : null

  return (
    <div className={`glass-panel rounded-2xl p-5 sm:p-6 ${className}`}>
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0 space-y-2">
          <div className="flex flex-wrap items-center gap-2.5">
            {badge && (
              <span
                className="inline-flex items-center gap-1.5 text-[10px] font-mono px-2.5 py-1 rounded-full uppercase tracking-widest border"
                style={{
                  color: badgeColor,
                  borderColor: `${badgeColor}45`,
                  backgroundColor: `${badgeColor}12`,
                  boxShadow: `0 0 16px ${badgeColor}18`,
                }}
              >
                <span
                  className="w-1.5 h-1.5 rounded-full animate-pulse"
                  style={{ backgroundColor: badgeColor }}
                  aria-hidden="true"
                />
                {badge}
              </span>
            )}
            {count != null && (
              <span className="inline-flex items-center gap-1.5 text-[11px] font-mono px-2.5 py-1 rounded-full border border-[var(--border-default)] bg-[var(--row-hover-bg)] text-[var(--text-secondary)] tabular-nums">
                <span className="text-[var(--text-muted)]">{countLabel || t('common.count')}</span>
                <span className="font-semibold text-[var(--text-primary)]">{loading ? '—' : count.toLocaleString()}</span>
              </span>
            )}
            {formattedTime && (
              <span className="text-[10px] font-mono text-[var(--text-muted)]">
                {t('common.last_updated')} {formattedTime}
              </span>
            )}
          </div>
          <div>
            <h1 className="text-xl sm:text-2xl font-semibold text-[var(--text-primary)] tracking-tight font-display">
              {title}
            </h1>
            {subtitle && (
              <p className="text-sm text-[var(--text-tertiary)] mt-1 max-w-2xl leading-relaxed">{subtitle}</p>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {onRefresh && (
            <button
              type="button"
              onClick={onRefresh}
              disabled={loading}
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-[11px] font-mono border border-[var(--border-default)] bg-[var(--row-hover-bg)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:border-[var(--border-strong)] hover:bg-[var(--row-hover-bg)] transition-all disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <span className={loading ? 'inline-block animate-spin' : ''} aria-hidden="true">↻</span>
              {refreshLabel || t('common.refresh')}
            </button>
          )}
          {onExport && (
            <button
              type="button"
              onClick={onExport}
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-[11px] font-mono border border-cyan-500/30 bg-cyan-500/10 text-cyan-200/90 hover:bg-cyan-500/18 hover:border-cyan-500/45 transition-all"
            >
              <span aria-hidden="true">↓</span>
              {exportLabel || t('common.export')}
            </button>
          )}
          {children}
        </div>
      </div>
    </div>
  )
}
