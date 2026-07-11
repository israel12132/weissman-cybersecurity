import { useState, useEffect, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { TrendingUp, Clock, AlertTriangle, BarChart3 } from 'lucide-react';
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import PageShell from './PageShell';
import ShellScanActions from '../components/engine/ShellScanActions';
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar';
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench';
import EmptyState from '../components/ui/EmptyState';
import { SkeletonWidgetGrid, SkeletonBar } from '../components/ui/Skeleton';
import { apiFetch } from '../lib/apiBase';
import { useVisiblePolling } from '../hooks/useVisiblePolling';

/**
 * RateLimitAnalytics — live request-budget monitoring.
 *
 * Every number is sourced from GET /api/rate-limits/analytics (current usage vs.
 * server-configured caps, usage history, throttling violations, per-endpoint hits).
 * Until the first response lands we render skeletons — we never show placeholder caps.
 */

const RANGES = ['1h', '6h', '24h', '7d'];

function utilColor(pct) {
  if (pct >= 90) return '#f43f5e';
  if (pct >= 70) return '#fbbf24';
  return '#34d399';
}

const CHART_TOOLTIP = {
  backgroundColor: '#0f172a',
  border: '1px solid #334155',
  borderRadius: '8px',
  color: '#e2e8f0',
};

function UsageTile({ label, current, max, color }) {
  const pct = max > 0 ? Math.min((current / max) * 100, 100) : 0;
  const accent = utilColor(pct);
  return (
    <div className="rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] backdrop-blur-md p-5">
      <div className="flex items-center justify-between mb-3">
        <span className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">{label}</span>
        <span
          className="text-[10px] font-mono px-1.5 py-0.5 rounded border"
          style={{ color: accent, borderColor: `${accent}40`, background: `${accent}12` }}
        >
          {pct.toFixed(0)}%
        </span>
      </div>
      <div className="flex items-baseline gap-2">
        <span className="text-3xl font-bold tabular-nums" style={{ color }}>{current}</span>
        <span className="text-sm text-[var(--text-muted)] font-mono">/ {max}</span>
      </div>
      <div className="h-2 bg-[var(--row-hover-bg)] rounded-full overflow-hidden mt-3">
        <div className="h-full rounded-full transition-all duration-300" style={{ width: `${pct}%`, background: accent }} />
      </div>
    </div>
  );
}

export default function RateLimitAnalytics() {
  const { t } = useTranslation();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [timeRange, setTimeRange] = useState('1h');

  const fetchAnalytics = useCallback(async () => {
    setError(null);
    try {
      const response = await apiFetch(`/api/rate-limits/analytics?range=${timeRange}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      setData(await response.json());
    } catch (err) {
      setError(err?.message || 'error');
    } finally {
      setLoading(false);
    }
  }, [timeRange]);

  useEffect(() => {
    setLoading(true);
    fetchAnalytics();
  }, [fetchAnalytics]);

  // Refresh every 30s, skipping ticks while the tab is hidden.
  useVisiblePolling(fetchAnalytics, 30000);

  const TILE_COLORS = { scans: '#22d3ee', logins: '#fbbf24', api: '#34d399' };
  const history = data?.history ?? [];
  const violations = data?.violations ?? [];
  const endpoints = data?.endpoints ?? [];
  const source = data?.source;

  const listFindings = useMemo(() => [
    ...(violations || []).map((v, i) => ({
      id: `violation-${i}`,
      severity: 'high',
      title: v.endpoint || v.key || 'violation',
      type: 'rate_limit_violation',
      description: String(v.count ?? v.hits ?? ''),
    })),
    ...(endpoints || []).map((e, i) => ({
      id: `ep-${i}`,
      severity: 'info',
      title: e.path || e.endpoint || 'endpoint',
      type: 'endpoint_hits',
      description: String(e.hits ?? e.count ?? ''),
    })),
  ], [violations, endpoints])

  const {
    exportCsv,
    filteredFindings,
    searchQuery,
    setSearchQuery,
  } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-rate-limits',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description}`,
  })

  const visibleEndpoints = useMemo(() => {
    if (!searchQuery.trim()) return endpoints
    const ids = new Set(filteredFindings.map((f) => String(f.id)))
    return endpoints.filter((e, i) => ids.has(`ep-${i}`))
  }, [endpoints, filteredFindings, searchQuery])

  const actions = (
    <div className="flex items-center gap-2">
      <div className="flex items-center gap-1 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg p-1">
        {RANGES.map((range) => (
          <button
            key={range}
            type="button"
            onClick={() => setTimeRange(range)}
            className={`px-2.5 py-1 rounded-md text-[11px] font-mono transition-all ${
              timeRange === range
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                : 'text-[var(--text-muted)] hover:text-[var(--text-secondary)]'
            }`}
          >
            {t(`pages.rateLimitAnalytics.range_${range}`)}
          </button>
        ))}
      </div>
      <ShellScanActions
        onRefresh={fetchAnalytics}
        onExport={exportCsv}
        refreshLoading={loading}
        exportDisabled={!filteredFindings.length}
      />
    </div>
  );

  return (
    <PageShell
      title={t('pages.rateLimitAnalytics.title')}
      subtitle={t('pages.rateLimitAnalytics.subtitle')}
      badge={t('pages.rateLimitAnalytics.badge')}
      badgeColor="#22d3ee"
      icon={<BarChart3 />}
      actions={actions}
    >
      <div className="space-y-6">
        {error && (
          <div className="p-4 rounded-xl border border-rose-500/30 bg-rose-900/20 text-rose-200 text-sm flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            {t('pages.rateLimitAnalytics.load_error')}
          </div>
        )}

        {/* Current usage — real caps from server config; skeleton until first load */}
        {!data ? (
          <SkeletonWidgetGrid count={3} />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {Object.entries(data.current ?? {}).map(([key, v]) => (
              <UsageTile
                key={key}
                label={t(`pages.rateLimitAnalytics.${key}_label`, { defaultValue: key })}
                current={v?.current ?? 0}
                max={v?.max ?? 0}
                color={TILE_COLORS[key] ?? '#22d3ee'}
              />
            ))}
          </div>
        )}

        {source && (
          <div className="flex items-center gap-2 text-[10px] font-mono text-[var(--text-muted)]">
            <span
              className={`w-1.5 h-1.5 rounded-full ${source === 'redis' ? 'bg-emerald-400' : 'bg-amber-400'}`}
            />
            {t('pages.rateLimitAnalytics.source_label')}:{' '}
            {t(`pages.rateLimitAnalytics.source_${source}`, { defaultValue: source })}
          </div>
        )}

        {/* Usage over time */}
        <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl p-6">
          <div className="flex items-center gap-2 mb-6">
            <TrendingUp className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-white">{t('pages.rateLimitAnalytics.usage_history')}</h3>
          </div>
          {!data ? (
            <SkeletonBar className="h-[300px] w-full" />
          ) : history.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart accessibilityLayer data={history}>
                <defs>
                  <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorLogins" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorApi" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="time" stroke="#64748b" style={{ fontSize: '12px' }} />
                <YAxis stroke="#64748b" style={{ fontSize: '12px' }} />
                <Tooltip contentStyle={CHART_TOOLTIP} />
                <Legend />
                <Area type="monotone" dataKey="scans" stroke="#06b6d4" fillOpacity={1} fill="url(#colorScans)" name={t('pages.rateLimitAnalytics.scans_label')} />
                <Area type="monotone" dataKey="logins" stroke="#f59e0b" fillOpacity={1} fill="url(#colorLogins)" name={t('pages.rateLimitAnalytics.logins_label')} />
                <Area type="monotone" dataKey="api" stroke="#10b981" fillOpacity={1} fill="url(#colorApi)" name={t('pages.rateLimitAnalytics.api_label')} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <EmptyState
              compact
              icon="search"
              title={t('pages.rateLimitAnalytics.history_empty_title')}
              body={t('pages.rateLimitAnalytics.history_empty_body')}
            />
          )}
        </div>

        {/* Throttling violations */}
        <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl p-6">
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <h3 className="text-sm font-semibold text-white">{t('pages.rateLimitAnalytics.violations_heading')}</h3>
          </div>
          {!data ? (
            <SkeletonBar className="h-24 w-full" />
          ) : violations.length > 0 ? (
            <div className="space-y-2">
              {violations.slice(0, 10).map((violation, index) => (
                <div
                  key={`${violation.endpoint || violation.type}-${index}`}
                  className="flex items-center justify-between p-3 bg-rose-500/5 border border-rose-500/20 rounded-lg"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <Clock className="w-4 h-4 text-rose-400 shrink-0" />
                    <div className="min-w-0">
                      <div className="text-sm text-white truncate">{violation.endpoint || violation.type}</div>
                      <div className="text-xs text-[var(--text-tertiary)] font-mono">{violation.time}</div>
                    </div>
                  </div>
                  <div className="text-xs text-rose-300 font-mono shrink-0">
                    {t('pages.rateLimitAnalytics.attempts', { count: violation.attempts ?? 0 })}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState compact icon="shield" title={t('pages.rateLimitAnalytics.violations_empty_title')} />
          )}
        </div>

        {/* Per-endpoint breakdown */}
        <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl p-6">
          <div className="flex items-center gap-2 mb-4">
            <BarChart3 className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-white">{t('pages.rateLimitAnalytics.endpoints_heading')}</h3>
          </div>
          {!data ? (
            <SkeletonBar className="h-[250px] w-full" />
          ) : endpoints.length > 0 ? (
            <>
            <WeissmanListToolbar
              className="mb-4"
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              resultCount={visibleEndpoints.length}
              totalCount={endpoints.length}
            />
            {visibleEndpoints.length === 0 ? (
              <EmptyState
                compact
                icon="search"
                title={t('weissmanFindings.filtered_title')}
                body={t('weissmanFindings.filtered_body')}
              />
            ) : (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart accessibilityLayer data={visibleEndpoints.slice(0, 10)} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis type="number" stroke="#64748b" style={{ fontSize: '12px' }} />
                <YAxis type="category" dataKey="endpoint" stroke="#64748b" style={{ fontSize: '12px' }} width={150} />
                <Tooltip contentStyle={CHART_TOOLTIP} />
                <Bar dataKey="count" fill="#06b6d4" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
            )}
            </>
          ) : (
            <EmptyState compact icon="search" title={t('pages.rateLimitAnalytics.endpoints_empty_title')} />
          )}
        </div>
      </div>
    </PageShell>
  );
}
