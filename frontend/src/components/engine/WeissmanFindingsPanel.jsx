import React from 'react'
import { useTranslation } from 'react-i18next'
import { Search } from 'lucide-react'
import EmptyState from '../ui/EmptyState'
import { SkeletonBar, SkeletonWidgetGrid } from '../ui/Skeleton'

const SEV_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22d3ee',
  info: '#64748b',
}

const SEV_FILTER_OPTIONS = ['all', 'critical', 'high', 'medium', 'low', 'info']

function KpiTiles({ counts, total, accent = '#22d3ee', t }) {
  const sevs = ['critical', 'high', 'medium', 'low', 'info']
  return (
    <div className="flex flex-wrap gap-2">
      <div
        className="px-4 py-2 rounded-xl border text-center min-w-[80px]"
        style={{ borderColor: `${accent}40`, background: `${accent}10` }}
      >
        <p className="text-xl font-bold font-mono" style={{ color: accent }}>{total}</p>
        <p className="text-[9px] font-mono text-white/40 uppercase">{t('weissmanFindings.kpi_total')}</p>
      </div>
      {sevs.filter((s) => counts[s] > 0).map((sev) => (
        <div key={sev} className="px-4 py-2 rounded-xl border border-white/10 bg-black/30 text-center min-w-[72px]">
          <p className="text-xl font-bold font-mono" style={{ color: SEV_COLORS[sev] }}>{counts[sev]}</p>
          <p className="text-[9px] font-mono text-white/40 uppercase">{sev}</p>
        </div>
      ))}
    </div>
  )
}

/**
 * Weissman-standard findings panel: KPI strip, search, severity filter, skeleton, empty states.
 * Pass `renderFinding` for custom row UI; defaults to compact mono row.
 */
export default function WeissmanFindingsPanel({
  findings = [],
  filteredFindings,
  counts,
  total,
  searchQuery,
  onSearchChange,
  severityFilter,
  onSeverityChange,
  loading = false,
  pending = false,
  lastUpdated,
  jobId,
  accent = '#22d3ee',
  title,
  emptyTitle,
  emptyBody,
  emptyReadyTitle,
  emptyReadyBody,
  showEmptyReady = false,
  renderFinding,
  className = '',
}) {
  const { t } = useTranslation()
  const list = filteredFindings ?? findings
  const displayTotal = total ?? findings.length

  if (loading && !findings.length) {
    return (
      <div className={`rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-6 space-y-4 ${className}`}>
        <SkeletonBar className="h-4 w-40" />
        <SkeletonWidgetGrid count={4} />
      </div>
    )
  }

  if (pending) {
    return (
      <div className={`rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-6 space-y-4 ${className}`}>
        <p className="text-[11px] font-mono animate-pulse" style={{ color: accent }}>{t('weissmanFindings.scanning')}</p>
        {jobId && <p className="text-[10px] font-mono text-white/30">{t('weissmanFindings.job')}: {jobId}</p>}
        <SkeletonWidgetGrid count={3} />
      </div>
    )
  }

  const defaultRender = (f, i) => (
    <div key={i} className="rounded-lg border border-white/10 bg-black/30 px-3 py-2 space-y-1">
      <div className="flex items-start gap-2">
        <span className="text-[9px] font-mono uppercase shrink-0" style={{ color: SEV_COLORS[(f.severity || 'info').toLowerCase()] || SEV_COLORS.info }}>
          [{f.severity || 'info'}]
        </span>
        <span className="text-[12px] font-mono text-white/90 min-w-0">{f.title || f.type || 'Finding'}</span>
      </div>
      {f.description && <p className="text-[10px] font-mono text-white/45 leading-relaxed">{f.description}</p>}
    </div>
  )

  return (
    <div className={`rounded-2xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-4 ${className}`}>
      {(counts || displayTotal > 0) && (
        <div className="space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-[10px] font-mono text-white/40 uppercase tracking-widest">
              {title || t('weissmanFindings.title')}
            </p>
            <div className="flex flex-wrap gap-3 text-[10px] font-mono text-white/35">
              {jobId && <span>{t('weissmanFindings.job')}: {jobId}</span>}
              {lastUpdated && (
                <span>{t('weissmanFindings.last_updated', { time: new Date(lastUpdated).toLocaleString() })}</span>
              )}
            </div>
          </div>
          {counts && <KpiTiles counts={counts} total={displayTotal} accent={accent} t={t} />}
        </div>
      )}

      <div className="flex flex-col sm:flex-row sm:items-center gap-3 justify-between">
        <p className="text-xs font-mono text-white/55 uppercase tracking-widest">
          {list.length}/{displayTotal} {t('weissmanFindings.title')}
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-white/30" />
            <input
              type="search"
              value={searchQuery ?? ''}
              onChange={(e) => onSearchChange?.(e.target.value)}
              placeholder={t('weissmanFindings.search_placeholder')}
              className="pl-8 pr-3 py-1.5 rounded-lg bg-black/50 border border-white/10 text-[11px] font-mono text-white/80 placeholder-white/25 focus:outline-none focus:border-cyan-500/40 min-w-[200px]"
            />
          </div>
          <div className="flex gap-1 flex-wrap">
            {SEV_FILTER_OPTIONS.map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => onSeverityChange?.(s)}
                className={`text-[9px] font-mono px-2 py-0.5 rounded border uppercase ${
                  severityFilter === s
                    ? 'border-cyan-500/50 text-cyan-200 bg-cyan-500/10'
                    : 'border-white/10 text-white/40 hover:text-white/60'
                }`}
              >
                {s === 'all' ? t('weissmanFindings.filter_all') : s}
              </button>
            ))}
          </div>
        </div>
      </div>

      {displayTotal === 0 && !showEmptyReady ? (
        <EmptyState
          icon="search"
          title={emptyTitle || t('weissmanFindings.empty_title')}
          body={emptyBody || t('weissmanFindings.empty_body')}
        />
      ) : showEmptyReady && displayTotal === 0 ? (
        <EmptyState
          icon="radar"
          title={emptyReadyTitle || t('weissmanFindings.ready_title')}
          body={emptyReadyBody || t('weissmanFindings.ready_body')}
        />
      ) : list.length === 0 ? (
        <EmptyState
          icon="search-x"
          title={t('weissmanFindings.filtered_title')}
          body={t('weissmanFindings.filtered_body')}
        />
      ) : (
        <div className="space-y-2 max-h-[520px] overflow-auto pr-1">
          {list.map((f, i) => (renderFinding ? renderFinding(f, i) : defaultRender(f, i)))}
        </div>
      )}
    </div>
  )
}
