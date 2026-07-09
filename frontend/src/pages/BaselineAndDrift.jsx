import { useState, useEffect, useCallback, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Activity, TrendingUp, AlertTriangle, CheckCircle, Search, Cpu } from 'lucide-react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar,
} from 'recharts';
import PageShell from './PageShell';
import ShellScanActions from '../components/engine/ShellScanActions';
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench';
import EmptyState from '../components/ui/EmptyState';
import { SkeletonWidgetGrid, SkeletonTable } from '../components/ui/Skeleton';
import { api } from '../utils/apiFetch';

const SEV_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22d3ee',
  info: '#64748b',
};

function driftColor(score) {
  if (score > 20) return 'text-red-400';
  if (score > 10) return 'text-yellow-400';
  return 'text-green-400';
}

export default function BaselineAndDrift() {
  const { t } = useTranslation();
  const [baseline, setBaseline] = useState(null);
  const [driftData, setDriftData] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [timeRange, setTimeRange] = useState('7d');
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      setError('');
      const [summaryRes, driftRes, anomaliesRes] = await Promise.all([
        api.get('/api/baseline/summary'),
        api.get(`/api/baseline/drift?range=${timeRange}`),
        api.get(`/api/baseline/anomalies?range=${timeRange}&limit=200`),
      ]);
      const hasBaseline = (summaryRes.total_assets || 0) > 0 || (summaryRes.baseline_rows || 0) > 0;
      setBaseline(hasBaseline ? summaryRes : null);
      setDriftData(driftRes.data || []);
      setAnomalies(anomaliesRes.anomalies || []);
    } catch (err) {
      console.error('Failed to fetch baseline data:', err);
      setError(err?.message || t('pages.baselineAndDrift.load_failed'));
      setBaseline(null);
      setDriftData([]);
      setAnomalies([]);
    } finally {
      setLoading(false);
    }
  }, [timeRange, t]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const filteredAnomalies = useMemo(() => {
    const q = search.trim().toLowerCase();
    return anomalies.filter((a) => {
      const sev = (a.severity || '').toLowerCase();
      if (severityFilter !== 'all' && sev !== severityFilter) return false;
      if (!q) return true;
      const hay = `${a.type || ''} ${a.description || ''} ${a.agent_id || ''}`.toLowerCase();
      return hay.includes(q);
    });
  }, [anomalies, search, severityFilter]);

  const severityCounts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const a of anomalies) {
      const s = (a.severity || 'info').toLowerCase();
      if (c[s] !== undefined) c[s] += 1;
    }
    return c;
  }, [anomalies]);

  const stats = baseline
    ? {
        totalAssets: baseline.total_assets || 0,
        baselineRows: baseline.baseline_rows || 0,
        sampleCount: baseline.sample_count || 0,
        driftScore: baseline.drift_score || 0,
        anomalyCount: anomalies.length,
        lastUpdated: baseline.last_updated,
      }
    : {
        totalAssets: 0, baselineRows: 0, sampleCount: 0, driftScore: 0, anomalyCount: 0, lastUpdated: null,
      };

  const listFindings = useMemo(() => filteredAnomalies.map((a) => ({
    id: a.id,
    severity: a.severity || 'medium',
    title: a.type || 'anomaly',
    type: 'baseline_drift',
    description: a.description || '',
    resource: a.agent_id || '',
  })), [filteredAnomalies])

  const { exportCsv, filteredFindings } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-baseline-anomalies',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  return (
    <PageShell
      title={t('pages.baselineAndDrift.title')}
      subtitle={t('pages.baselineAndDrift.subtitle')}
      badge={t('pages.baselineAndDrift.badge')}
      badgeColor="#a78bfa"
      icon={<Activity />}
      actions={(
        <ShellScanActions
          onRefresh={fetchData}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="space-y-6">
        <div className="rounded-xl border border-violet-500/20 bg-violet-950/20 px-4 py-3 flex items-start gap-3">
          <Cpu className="w-4 h-4 text-violet-400 mt-0.5 shrink-0" />
          <p className="text-xs text-violet-100/70">{t('pages.baselineAndDrift.evidence_notice')}</p>
        </div>

        {error && (
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/30 px-4 py-3 text-sm text-rose-200">
            {error}
          </div>
        )}

        {loading && !baseline && anomalies.length === 0 ? (
          <SkeletonWidgetGrid count={5} />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            <StatCard
              label={t('pages.baselineAndDrift.baseline_assets')}
              value={stats.totalAssets}
              icon={<CheckCircle className="w-4 h-4 text-cyan-400" />}
            />
            <StatCard
              label={t('pages.baselineAndDrift.baseline_rows')}
              value={stats.baselineRows}
              sub={t('pages.baselineAndDrift.samples', { count: stats.sampleCount })}
              icon={<Activity className="w-4 h-4 text-purple-400" />}
            />
            <StatCard
              label={t('pages.baselineAndDrift.drift_score')}
              value={`${Number(stats.driftScore).toFixed(1)}%`}
              valueClass={driftColor(stats.driftScore)}
              icon={<TrendingUp className="w-4 h-4 text-purple-400" />}
            />
            <StatCard
              label={t('pages.baselineAndDrift.anomalies')}
              value={stats.anomalyCount}
              icon={<AlertTriangle className="w-4 h-4 text-red-400" />}
              variant="danger"
            />
            <StatCard
              label={t('pages.baselineAndDrift.last_update')}
              value={stats.lastUpdated ? new Date(stats.lastUpdated).toLocaleDateString() : t('pages.baselineAndDrift.never')}
              small
              icon={<Activity className="w-4 h-4 text-green-400" />}
            />
          </div>
        )}

        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg p-1">
            {['24h', '7d', '30d'].map((range) => (
              <button
                key={range}
                type="button"
                onClick={() => setTimeRange(range)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                  timeRange === range
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                    : 'text-gray-400 hover:text-[var(--text-primary)] hover:bg-[var(--row-hover-bg)]'
                }`}
              >
                {t(`pages.baselineAndDrift.range_${range}`)}
              </button>
            ))}
          </div>
          <Link
            to="/agents"
            className="text-xs font-mono text-cyan-300/80 hover:text-cyan-200 underline"
          >
            {t('pages.baselineAndDrift.open_agents')}
          </Link>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <ChartPanel title={t('pages.baselineAndDrift.drift_over_time')} icon={<TrendingUp className="w-4 h-4 text-cyan-400" />}>
            {driftData.length > 0 ? (
              <ResponsiveContainer width="100%" height={240}>
                <LineChart accessibilityLayer data={driftData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="time" stroke="#64748b" style={{ fontSize: '11px' }} />
                  <YAxis stroke="#64748b" style={{ fontSize: '11px' }} domain={[0, 100]} />
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '8px' }} />
                  <Line type="monotone" dataKey="drift" stroke="#a78bfa" strokeWidth={2} dot={false} name={t('pages.baselineAndDrift.drift_score')} />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <EmptyChart message={t('pages.baselineAndDrift.no_drift_data')} />
            )}
          </ChartPanel>

          <ChartPanel title={t('pages.baselineAndDrift.anomaly_volume')} icon={<AlertTriangle className="w-4 h-4 text-orange-400" />}>
            {driftData.some((d) => d.anomalies > 0) ? (
              <ResponsiveContainer width="100%" height={240}>
                <BarChart accessibilityLayer data={driftData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="time" stroke="#64748b" style={{ fontSize: '11px' }} />
                  <YAxis stroke="#64748b" style={{ fontSize: '11px' }} allowDecimals={false} />
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '8px' }} />
                  <Bar dataKey="anomalies" fill="#f97316" radius={[4, 4, 0, 0]} name={t('pages.baselineAndDrift.anomalies')} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <EmptyChart message={t('pages.baselineAndDrift.no_anomaly_volume')} />
            )}
          </ChartPanel>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-disabled)]" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              aria-label={t('pages.baselineAndDrift.search_placeholder')}
              placeholder={t('pages.baselineAndDrift.search_placeholder')}
              className="w-full pl-10 pr-4 py-2 rounded-xl bg-[var(--bg-2)] border border-[var(--border-default)] text-sm text-white placeholder-white/25 focus:outline-none focus:border-violet-500/40"
            />
          </div>
          <div className="flex items-center gap-1 flex-wrap">
            {['all', 'critical', 'high', 'medium', 'low'].map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => setSeverityFilter(s)}
                className={`px-2.5 py-1 rounded-md text-[10px] font-mono uppercase ${
                  severityFilter === s ? 'bg-violet-500/20 text-violet-300 border border-violet-500/30' : 'text-[var(--text-muted)]'
                }`}
              >
                {s === 'all' ? t('pages.baselineAndDrift.filter_all') : `${s} (${severityCounts[s] || 0})`}
              </button>
            ))}
          </div>
        </div>

        <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl overflow-hidden">
          <div className="p-4 border-b border-[var(--border-default)]">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400" />
              {t('pages.baselineAndDrift.anomalies_heading', { count: filteredAnomalies.length })}
            </h3>
          </div>

          {loading ? (
            <div className="p-6"><SkeletonTable rows={5} cols={4} /></div>
          ) : filteredAnomalies.length === 0 ? (
            <div className="p-8">
              <EmptyState
                icon="shield"
                title={t('pages.baselineAndDrift.no_anomalies_title')}
                body={anomalies.length === 0 ? t('pages.baselineAndDrift.no_anomalies') : t('pages.baselineAndDrift.no_filter_anomalies')}
                cta={!baseline ? { label: t('pages.baselineAndDrift.open_agents'), to: '/agents' } : undefined}
              />
            </div>
          ) : (
            <div className="divide-y divide-[var(--border-subtle)] max-h-[480px] overflow-y-auto">
              {filteredAnomalies.map((anomaly) => {
                const sev = (anomaly.severity || 'medium').toLowerCase();
                const sevColor = SEV_COLORS[sev] || SEV_COLORS.info;
                return (
                  <div key={anomaly.id} className="p-4 hover:bg-[var(--row-hover-bg)] transition-colors">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap mb-2">
                          <span className="text-sm font-semibold text-white font-mono">{anomaly.type || '—'}</span>
                          {anomaly.severity && (
                            <span
                              className="px-2 py-0.5 rounded text-[10px] font-mono uppercase border"
                              style={{ color: sevColor, borderColor: `${sevColor}55`, background: `${sevColor}15` }}
                            >
                              {anomaly.severity}
                            </span>
                          )}
                          <span className="text-[10px] font-mono text-[var(--text-muted)]">
                            {t('pages.baselineAndDrift.score_label', { score: anomaly.score ?? '—' })}
                          </span>
                        </div>
                        {anomaly.description && (
                          <p className="text-xs text-gray-400 mb-2">{anomaly.description}</p>
                        )}
                        <div className="flex flex-wrap gap-3 text-[10px] font-mono text-[var(--text-muted)]">
                          {anomaly.agent_id && (
                            <span>{t('pages.baselineAndDrift.agent_label')}: {anomaly.agent_id}</span>
                          )}
                          {anomaly.observed != null && anomaly.baseline_mean != null && (
                            <span>
                              {t('pages.baselineAndDrift.observed_vs_baseline', {
                                observed: Number(anomaly.observed).toFixed(2),
                                baseline: Number(anomaly.baseline_mean).toFixed(2),
                              })}
                            </span>
                          )}
                          {anomaly.detected_at && (
                            <span>{t('pages.baselineAndDrift.detected_at', { time: new Date(anomaly.detected_at).toLocaleString() })}</span>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {!baseline && !loading && (
          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle className="w-5 h-5 text-yellow-400" />
              <h3 className="text-sm font-semibold text-white">{t('pages.baselineAndDrift.no_baseline_title')}</h3>
            </div>
            <p className="text-sm text-gray-300 mb-3">{t('pages.baselineAndDrift.no_baseline_body')}</p>
            <Link to="/agents" className="inline-flex px-4 py-2 bg-yellow-500/20 text-yellow-200 rounded-lg text-sm font-medium border border-yellow-500/30 hover:bg-yellow-500/30">
              {t('pages.baselineAndDrift.deploy_agents')}
            </Link>
          </div>
        )}
      </div>
    </PageShell>
  );
}

function StatCard({ label, value, sub, icon, valueClass, variant, small }) {
  const bg = variant === 'danger' ? 'bg-red-500/10 border-red-500/30' : 'bg-[var(--bg-2)] border-[var(--border-default)]';
  return (
    <div className={`backdrop-blur-md border rounded-xl p-4 ${bg}`}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm text-gray-400">{label}</span>
        {icon}
      </div>
      <div className={`font-bold text-white ${small ? 'text-sm' : 'text-2xl'} ${valueClass || ''}`}>{value}</div>
      {sub && <div className="text-[10px] text-[var(--text-muted)] mt-1 font-mono">{sub}</div>}
    </div>
  );
}

function ChartPanel({ title, icon, children }) {
  return (
    <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl p-6">
      <div className="flex items-center gap-2 mb-4">
        {icon}
        <h3 className="text-sm font-semibold text-white">{title}</h3>
      </div>
      {children}
    </div>
  );
}

function EmptyChart({ message }) {
  return (
    <div className="h-[240px] flex items-center justify-center text-gray-500 text-sm">
      {message}
    </div>
  );
}
