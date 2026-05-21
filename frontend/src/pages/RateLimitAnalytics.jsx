import { useState, useEffect } from 'react';
import { Activity, TrendingUp, Clock, AlertTriangle, BarChart3, RefreshCw } from 'lucide-react';
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'

/**
 * RateLimitAnalytics - Comprehensive rate limit monitoring and analytics
 *
 * Features:
 * - Historical usage charts
 * - Peak usage times
 * - Violation history
 * - Per-endpoint breakdown
 * - Tenant comparison
 */
// Fallback data when API is unavailable
const FALLBACK_DATA = {
  current: {
    scans: { current: 0, max: 24 },
    logins: { current: 0, max: 8 },
    api: { current: 0, max: 30 },
  },
  history: [],
  violations: [],
  endpoints: [],
}

export default function RateLimitAnalytics() {
  const [data, setData] = useState(FALLBACK_DATA);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [timeRange, setTimeRange] = useState('1h'); // 1h, 6h, 24h, 7d

  useEffect(() => {
    fetchAnalytics();
    const interval = setInterval(fetchAnalytics, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, [timeRange]);

  const fetchAnalytics = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await apiFetch(`/api/rate-limits/analytics?range=${timeRange}`)
      if (response.ok) {
        const analyticsData = await response.json();
        setData(analyticsData);
      } else if (response.status === 404) {
        // API not implemented, use fallback
        setData(FALLBACK_DATA);
      } else {
        throw new Error(`Failed to load analytics (HTTP ${response.status})`)
      }
    } catch (err) {
      setError(err?.message || 'Failed to fetch analytics')
      setData(FALLBACK_DATA);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (current, max) => {
    const percentage = (current / max) * 100;
    if (percentage >= 90) return 'text-red-400 bg-red-500/10 border-red-500/30';
    if (percentage >= 70) return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
    return 'text-green-400 bg-green-500/10 border-green-500/30';
  };

  return (
    <PageShell title="Rate Limit Analytics" icon={<BarChart3 />}>
      <div className="space-y-6">
        {/* Error Banner */}
        {error && (
          <div className="rounded-xl border border-amber-500/30 bg-amber-950/20 px-4 py-3">
            <div className="flex items-center gap-2">
              <span className="text-amber-400 text-sm">⚠️</span>
              <span className="text-xs font-mono text-amber-300/80">{error}</span>
              <span className="text-[10px] text-amber-300/50 ml-auto">Using demo data</span>
            </div>
          </div>
        )}

        {/* Header Controls */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Activity className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-semibold text-white">Usage Analytics</h2>
          </div>
          <div className="flex items-center gap-3">
            {/* Time range selector */}
            <div className="flex items-center gap-2 bg-black/40 backdrop-blur-md border border-white/10 rounded-lg p-1">
              {['1h', '6h', '24h', '7d'].map((range) => (
                <button
                  key={range}
                  onClick={() => setTimeRange(range)}
                  className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                    timeRange === range
                      ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                      : 'text-gray-400 hover:text-white hover:bg-white/5'
                  }`}
                >
                  {range}
                </button>
              ))}
            </div>

            <button
              onClick={fetchAnalytics}
              className="flex items-center gap-2 px-3 py-1.5 bg-black/40 backdrop-blur-md border border-white/10 rounded-lg text-xs font-medium text-gray-300 hover:text-white hover:bg-white/5 transition-colors"
            >
              <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>
        </div>

        {/* Current Status Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {Object.entries(data.current).map(([key, { current, max }]) => {
            const percentage = (current / max) * 100;
            const label = key.charAt(0).toUpperCase() + key.slice(1);

            return (
              <div key={key} className={`p-4 rounded-xl border backdrop-blur-md ${getStatusColor(current, max)}`}>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-sm font-medium opacity-90">{label}</span>
                  <Activity className="w-4 h-4" />
                </div>
                <div className="flex items-end gap-2 mb-2">
                  <span className="text-3xl font-bold">{current}</span>
                  <span className="text-lg opacity-60 mb-1">/ {max}</span>
                </div>
                <div className="h-2 bg-black/20 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-current transition-all duration-300"
                    style={{ width: `${Math.min(percentage, 100)}%` }}
                  />
                </div>
                <div className="mt-2 text-xs opacity-75">
                  {percentage.toFixed(1)}% used
                </div>
              </div>
            );
          })}
        </div>

        {/* Usage History Chart */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-white">Usage Over Time</h3>
            </div>
          </div>

          {data.history && data.history.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={data.history}>
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
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    color: '#e2e8f0',
                  }}
                />
                <Legend />
                <Area
                  type="monotone"
                  dataKey="scans"
                  stroke="#06b6d4"
                  fillOpacity={1}
                  fill="url(#colorScans)"
                  name="Scans"
                />
                <Area
                  type="monotone"
                  dataKey="logins"
                  stroke="#f59e0b"
                  fillOpacity={1}
                  fill="url(#colorLogins)"
                  name="Logins"
                />
                <Area
                  type="monotone"
                  dataKey="api"
                  stroke="#10b981"
                  fillOpacity={1}
                  fill="url(#colorApi)"
                  name="API Calls"
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[300px] flex items-center justify-center text-gray-500">
              No historical data available
            </div>
          )}
        </div>

        {/* Violations History */}
        {data.violations && data.violations.length > 0 && (
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-4">
              <AlertTriangle className="w-4 h-4 text-red-400" />
              <h3 className="text-sm font-semibold text-white">Recent Violations</h3>
            </div>
            <div className="space-y-2">
              {data.violations.slice(0, 10).map((violation, index) => (
                <div
                  key={index}
                  className="flex items-center justify-between p-3 bg-red-500/5 border border-red-500/20 rounded-lg"
                >
                  <div className="flex items-center gap-3">
                    <Clock className="w-4 h-4 text-red-400" />
                    <div>
                      <div className="text-sm text-white">{violation.endpoint || violation.type}</div>
                      <div className="text-xs text-gray-400">{violation.time}</div>
                    </div>
                  </div>
                  <div className="text-xs text-red-400 font-medium">
                    {violation.attempts} attempts
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Top Endpoints */}
        {data.endpoints && data.endpoints.length > 0 && (
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-4">
              <BarChart3 className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-white">Top Endpoints by Usage</h3>
            </div>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={data.endpoints.slice(0, 10)} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis type="number" stroke="#64748b" style={{ fontSize: '12px' }} />
                <YAxis
                  type="category"
                  dataKey="endpoint"
                  stroke="#64748b"
                  style={{ fontSize: '12px' }}
                  width={150}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                    color: '#e2e8f0',
                  }}
                />
                <Bar dataKey="count" fill="#06b6d4" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </PageShell>
  );
}
