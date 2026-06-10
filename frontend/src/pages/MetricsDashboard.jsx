import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Activity, AlertTriangle, CheckCircle, Database, Scan, XCircle } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import PageShell from './PageShell';
import { api } from '../utils/apiFetch';

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#06b6d4',
  info: '#64748b',
};

const EMPTY_METRICS = {
  postgres_ok: false,
  active_scans: 0,
  findings_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  jobs: { completed_24h: 0, failed_24h: 0 },
};

export default function MetricsDashboard() {
  const { t } = useTranslation();
  const [metrics, setMetrics] = useState(EMPTY_METRICS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 10000);
    return () => clearInterval(interval);
  }, []);

  const fetchMetrics = async () => {
    try {
      const data = await api.get('/api/metrics/dashboard');
      setMetrics({
        postgres_ok: Boolean(data.postgres_ok),
        active_scans: data.active_scans ?? 0,
        findings_by_severity: {
          critical: data.findings_by_severity?.critical ?? 0,
          high: data.findings_by_severity?.high ?? 0,
          medium: data.findings_by_severity?.medium ?? 0,
          low: data.findings_by_severity?.low ?? 0,
          info: data.findings_by_severity?.info ?? 0,
        },
        jobs: {
          completed_24h: data.jobs?.completed_24h ?? 0,
          failed_24h: data.jobs?.failed_24h ?? 0,
        },
      });
      setError(null);
      setLoading(false);
    } catch (err) {
      console.error('Failed to fetch metrics:', err);
      setError(t('pages.metricsDashboard.load_error'));
      setLoading(false);
    }
  };

  const severityLabel = (severity) => t(`pages.metricsDashboard.severity_${severity}`, {
    defaultValue: severity.charAt(0).toUpperCase() + severity.slice(1),
  });
  const severityChartData = Object.entries(metrics.findings_by_severity).map(([severity, count]) => ({
    severity,
    count,
    label: severityLabel(severity),
  }));

  const totalFindings = severityChartData.reduce((sum, row) => sum + row.count, 0);

  return (
    <PageShell title={t('pages.metricsDashboard.title')} icon={<Activity />}>
      <div className="space-y-6">
        <div className="flex items-center gap-2">
          <Activity className="w-5 h-5 text-cyan-400" />
          <h2 className="text-lg font-semibold text-white">{t('pages.metricsDashboard.live_metrics')}</h2>
          {loading && <span className="text-xs text-gray-500">{t('pages.metricsDashboard.refreshing')}</span>}
        </div>

        {error && (
          <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div
            className={`p-4 rounded-xl border backdrop-blur-md ${
              metrics.postgres_ok
                ? 'text-green-400 bg-green-500/10 border-green-500/30'
                : 'text-red-400 bg-red-500/10 border-red-500/30'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium opacity-90">{t('pages.metricsDashboard.postgres')}</span>
              <Database className="w-4 h-4" />
            </div>
            <div className="flex items-center gap-2 text-2xl font-bold">
              {metrics.postgres_ok ? (
                <>
                  <CheckCircle className="w-6 h-6" />
                  {t('pages.metricsDashboard.connected')}
                </>
              ) : (
                <>
                  <XCircle className="w-6 h-6" />
                  {t('pages.metricsDashboard.unavailable')}
                </>
              )}
            </div>
          </div>

          <div className="p-4 rounded-xl border backdrop-blur-md bg-cyan-500/10 border-cyan-500/30 text-cyan-400">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium opacity-90">{t('pages.metricsDashboard.active_scans')}</span>
              <Scan className="w-4 h-4" />
            </div>
            <div className="text-3xl font-bold">{metrics.active_scans}</div>
          </div>

          <div className="p-4 rounded-xl border backdrop-blur-md bg-green-500/10 border-green-500/30 text-green-400">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium opacity-90">{t('pages.metricsDashboard.jobs_completed_24h')}</span>
              <CheckCircle className="w-4 h-4" />
            </div>
            <div className="text-3xl font-bold">{metrics.jobs.completed_24h}</div>
          </div>

          <div className="p-4 rounded-xl border backdrop-blur-md bg-red-500/10 border-red-500/30 text-red-400">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium opacity-90">{t('pages.metricsDashboard.jobs_failed_24h')}</span>
              <AlertTriangle className="w-4 h-4" />
            </div>
            <div className="text-3xl font-bold">{metrics.jobs.failed_24h}</div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-white">{t('pages.metricsDashboard.findings_by_severity')}</h3>
              <span className="text-xs text-gray-400">{t('pages.metricsDashboard.total_count', { count: totalFindings })}</span>
            </div>
            {totalFindings > 0 ? (
              <ResponsiveContainer width="100%" height={260}>
                <BarChart data={severityChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis dataKey="label" stroke="#64748b" style={{ fontSize: '12px' }} />
                  <YAxis stroke="#64748b" style={{ fontSize: '12px' }} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      border: '1px solid #334155',
                      borderRadius: '8px',
                      color: '#e2e8f0',
                    }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {severityChartData.map((entry) => (
                      <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[260px] flex items-center justify-center text-gray-500">
                {t('pages.metricsDashboard.no_open_findings')}
              </div>
            )}
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
            <h3 className="text-sm font-semibold text-white mb-4">{t('pages.metricsDashboard.severity_breakdown')}</h3>
            <div className="space-y-3">
              {severityChartData.map(({ severity, count, label }) => (
                <div key={severity} className="flex items-center gap-3">
                  <span
                    className="w-2 h-2 rounded-full shrink-0"
                    style={{ backgroundColor: SEVERITY_COLORS[severity] }}
                  />
                  <span className="text-sm text-gray-300 w-20">{label}</span>
                  <div className="flex-1 h-2 bg-black/30 rounded-full overflow-hidden">
                    <div
                      className="h-full transition-all duration-300"
                      style={{
                        width: totalFindings ? `${(count / totalFindings) * 100}%` : '0%',
                        backgroundColor: SEVERITY_COLORS[severity],
                      }}
                    />
                  </div>
                  <span className="text-sm font-mono text-gray-400 w-10 text-right">{count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </PageShell>
  );
}
