import React from 'react'
import { useTranslation } from 'react-i18next'
import { Search } from 'lucide-react'

/**
 * Standard list-page toolbar: search + optional filter slot + last sync.
 */
export default function WeissmanListToolbar({
  searchQuery = '',
  onSearchChange,
  searchPlaceholder,
  lastUpdated,
  children,
  className = '',
  resultCount,
  totalCount,
}) {
  const { t } = useTranslation()

  return (
    <div className={`flex flex-col sm:flex-row sm:items-center gap-3 justify-between ${className}`}>
      <div className="flex flex-wrap items-center gap-3 min-w-0">
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-disabled)]" />
          <input
            type="search"
            value={searchQuery}
            onChange={(e) => onSearchChange?.(e.target.value)}
            placeholder={searchPlaceholder || t('weissmanFindings.search_placeholder')}
            aria-label={searchPlaceholder || t('weissmanFindings.search_placeholder')}
            className="w-full pl-8 pr-3 py-2 rounded-xl bg-[var(--bg-3)] border border-[var(--border-default)] text-[12px] font-mono text-[var(--text-primary)] placeholder-white/25 focus:outline-none focus:border-cyan-500/40 focus:ring-1 focus:ring-cyan-500/15"
          />
        </div>
        {children}
      </div>
      <div className="flex flex-wrap items-center gap-3 text-[10px] font-mono text-[var(--text-muted)] shrink-0">
        {resultCount != null && totalCount != null && (
          <span>{resultCount}/{totalCount}</span>
        )}
        {lastUpdated && (
          <span>{t('weissmanFindings.last_updated', { time: new Date(lastUpdated).toLocaleString() })}</span>
        )}
      </div>
    </div>
  )
}
