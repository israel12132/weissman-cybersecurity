import { useState, useEffect, useCallback, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  Activity, AlertTriangle, CheckCircle, Database, Scan, XCircle, RefreshCw, Shield,
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import PageShell from './PageShell';
import ShellScanActions from '../components/engine/ShellScanActions';
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench';
import EmptyState from '../components/ui/EmptyState';
import { SkeletonBar, SkeletonWidgetGrid } from '../components/ui/Skeleton';
import { apiFetch } from '../lib/apiBase';

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
  const { t, i18n } = useTranslation();
  const [metrics, setMetrics] = useState(EMPTY_METRICS);
  const [execKpis, setExecKpis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);

  const fetchMetrics = useCallback(async (silent = false) => {
    if (!silent) setRefreshing(true);
    try {
      const [metricsRes, kpisRes] = await Promise.all([
        apiFetch('/api/metrics/dashboard'),
        apiFetch('/api/dashboard/exec-kpis'),
      ]);

      if (!metricsRes.ok) throw new Error(`HTTP ${metricsRes.status}`);

      const data = await metricsRes.json();
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

      if (kpisRes.ok) {
        const kpis = await kpisRes.json();
        setExecKpis(kpis);
      }

      setError(null);
      setLastUpdated(new Date());
    } catch (err) {
      setError(t('pages.metricsDashboard.load_error'));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [t]);

  useEffect(() => {
    fetchMetrics();
  }, [fetchMetrics]);

  useEffect(() => {
    if (!autoRefresh) return undefined;
    const interval = setInterval(() => fetchMetrics(true), 10000);
    return () => clearInterval(interval);
  }, [autoRefresh, fetchMetrics]);

  const severityLabel = (severity) => t(`pages.metricsDashboard.severity_${severity}`, {
    defaultValue: severity.charAt(0).toUpperCase() + severity.slice(1),
  });
  const severityChartData = Object.entries(metrics.findings_by_severity).map(([severity, count]) => ({
    severity,
    count,
    label: severityLabel(severity),
  }));

  const totalFindings = severityChartData.reduce((sum, row) => sum + row.count, 0);
  const securityScore = execKpis?.security_score
  const mttrHours = execKpis?.mttr_hours
  const agentsOnline = execKpis?.agents?.online
  const agentsRegistered = execKpis?.agents?.registered
  const jobsRunning = execKpis?.jobs?.running ?? metrics.active_scans

  const listFindings = useMemo(() => Object.entries(metrics.findings_by_severity).map(([severity, count]) => ({
    severity,
    title: severityLabel(severity),
    type: 'finding_count',
    description: String(count),
  })), [metrics.findings_by_severity, i18n.language])

  const { exportCsv, filteredFindings } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-metrics',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description}`,
  })

  return (
    <PageShell
      title={t('pages.metricsDashboard.title')}
      subtitle={t('pages.metricsDashboard.subtitle')}
      icon={<Activity />}
      actions={
        <>
          <label className="flex items-center gap-2 text-[11px] font-mono text-white/55">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="w-3.5 h-3.5 rounded border-white/20 bg-black/40 text-cyan-500"
            />
            {t('pages.metricsDashboard.auto_refresh')}
          </label>
          <ShellScanActions
            onRefresh={() => fetchMetrics()}
            onExport={exportCsv}
            refreshLoading={refreshing}
            exportDisabled={!filteredFindings.length}
          />
        </>
      }
    >
      <div className="space-y-6">
        <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 px-4 py-3 text-[11px] font-mono text-cyan-200/80 leading-relaxed">
          {t('pages.metricsDashboard.evidence_notice')}
        </div>

        {lastUpdated && (
          <p className="text-[11px] font-mono text-white/40">
            {t('pages.metricsDashboard.last_updated', {
              time: lastUpdated.toLocaleTimeString(i18n.language),
            })}
            {refreshing && ` · ${t('pages.metricsDashboard.refreshing')}`}
          </p>
        )}

        {error && (
          <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}

        {loading ? (
          <>
            <SkeletonWidgetGrid count={4} />
            <SkeletonBar className="h-64" />
          </>
        ) : (
          <>
            {execKpis && (
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                {securityScore != null && (
                  <div className="p-4 rounded-xl border border-violet-500/30 bg-violet-500/10">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium text-violet-300">{t('pages.metricsDashboard.security_score')}</span>
                      <Shield className="w-4 h-4 text-violet-400" />
                    </div>
                    <div className="text-3xl font-bold text-violet-200">{securityScore}</div>
                  </div>
                )}
                {mttrHours != null && (
                  <div className="p-4 rounded-xl border border-amber-500/30 bg-amber-500/10">
                    <div className="text-sm font-medium text-amber-300 mb-2">{t('pages.metricsDashboard.mttr_hours')}</div>
                    <div className="text-3xl font-bold text-amber-200">{Number(mttrHours).toFixed(1)}h</div>
                  </div>
                )}
                {agentsRegistered != null && (
                  <div className="p-4 rounded-xl border border-emerald-500/30 bg-emerald-500/10">
                    <div className="text-sm font-medium text-emerald-300 mb-2">{t('pages.metricsDashboard.agents_online')}</div>
                    <div className="text-3xl font-bold text-emerald-200">
                      {agentsOnline ?? 0}
                      <span className="text-lg text-emerald-400/60">/{agentsRegistered}</span>
                    </div>
                  </div>
                )}
                <div className="p-4 rounded-xl border border-blue-500/30 bg-blue-500/10">
                  <div className="text-sm font-medium text-blue-300 mb-2">{t('pages.metricsDashboard.jobs_running')}</div>
                  <div className="text-3xl font-bold text-blue-200">{jobsRunning ?? 0}</div>
                </div>
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
                  <EmptyState
                    icon="📊"
                    title={t('pages.metricsDashboard.no_open_findings')}
                    body={t('pages.metricsDashboard.no_findings_body')}
                    action={(
                      <Link to="/findings" className="text-sm text-cyan-400 hover:underline">
                        {t('pages.metricsDashboard.go_findings')}
                      </Link>
                    )}
                  />
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
                <div className="mt-6 pt-4 border-t border-white/10 flex flex-wrap gap-3">
                  <Link to="/jobs" className="text-[11px] font-mono text-cyan-400 hover:underline">
                    {t('pages.metricsDashboard.link_jobs')} →
                  </Link>
                  <Link to="/findings" className="text-[11px] font-mono text-cyan-400 hover:underline">
                    {t('pages.metricsDashboard.link_findings')} →
                  </Link>
                  <Link to="/agents" className="text-[11px] font-mono text-cyan-400 hover:underline">
                    {t('pages.metricsDashboard.link_agents')} →
                  </Link>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </PageShell>
  );
}
