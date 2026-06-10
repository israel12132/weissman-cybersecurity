import React from 'react'
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
              <span className="inline-flex items-center gap-1.5 text-[11px] font-mono px-2.5 py-1 rounded-full border border-white/12 bg-white/[0.04] text-white/70 tabular-nums">
                <span className="text-white/40">{countLabel || t('common.count')}</span>
                <span className="font-semibold text-white">{loading ? '—' : count.toLocaleString()}</span>
              </span>
            )}
            {formattedTime && (
              <span className="text-[10px] font-mono text-white/35">
                {t('common.last_updated')} {formattedTime}
              </span>
            )}
          </div>
          <div>
            <h1 className="text-xl sm:text-2xl font-semibold text-white tracking-tight font-display">
              {title}
            </h1>
            {subtitle && (
              <p className="text-sm text-white/50 mt-1 max-w-2xl leading-relaxed">{subtitle}</p>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {onRefresh && (
            <button
              type="button"
              onClick={onRefresh}
              disabled={loading}
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-[11px] font-mono border border-white/12 bg-white/[0.03] text-white/65 hover:text-white hover:border-white/25 hover:bg-white/[0.06] transition-all disabled:opacity-40 disabled:cursor-not-allowed"
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
