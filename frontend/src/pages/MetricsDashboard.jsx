import { useState, useEffect } from 'react';
import { Activity, Cpu, HardDrive, Network, Zap, TrendingUp, AlertTriangle, Server } from 'lucide-react';
import { LineChart, Line, AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import PageShell from '../components/PageShell';
import { api } from '../utils/apiFetch';

/**
 * MetricsDashboard - Real-time system metrics with Prometheus integration
 *
 * Features:
 * - CPU, memory, disk usage
 * - Network I/O statistics
 * - Database performance metrics
 * - Engine execution metrics
 * - Request/response times
 * - Error rates
 * - Queue depths
 * - Cache hit rates
 */
export default function MetricsDashboard() {
  const [metrics, setMetrics] = useState({
    system: {
      cpu: [],
      memory: [],
      disk: [],
      network: [],
    },
    application: {
      requests: [],
      errors: [],
      latency: [],
    },
    database: {
      connections: [],
      queries: [],
      slow_queries: [],
    },
    engines: {
      executions: [],
      failures: [],
      duration: [],
    },
  });
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState('1h'); // 1h, 6h, 24h, 7d

  useEffect(() => {
    fetchMetrics();
    const interval = setInterval(fetchMetrics, 10000); // Refresh every 10s
    return () => clearInterval(interval);
  }, [timeRange]);

  const fetchMetrics = async () => {
    try {
      const data = await api.get(`/api/metrics/dashboard?range=${timeRange}`);
      setMetrics(data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch metrics:', error);
      setLoading(false);
    }
  };

  const currentStats = {
    cpu: metrics.system.cpu[metrics.system.cpu.length - 1]?.value || 0,
    memory: metrics.system.memory[metrics.system.memory.length - 1]?.value || 0,
    disk: metrics.system.disk[metrics.system.disk.length - 1]?.value || 0,
    requests: metrics.application.requests.reduce((sum, m) => sum + (m.value || 0), 0),
    errors: metrics.application.errors.reduce((sum, m) => sum + (m.value || 0), 0),
    latency: metrics.application.latency[metrics.application.latency.length - 1]?.value || 0,
  };

  const getStatusColor = (value, thresholds) => {
    if (value >= thresholds.critical) return 'text-red-400 bg-red-500/10 border-red-500/30';
    if (value >= thresholds.warning) return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
    return 'text-green-400 bg-green-500/10 border-green-500/30';
  };

  return (
    <PageShell title="Real-time Metrics Dashboard" icon={<Activity />}>
      <div className="space-y-6">
        {/* Time Range Selector */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-semibold text-white">System Metrics</h2>
          </div>
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
        </div>

        {/* Current Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className={`p-4 rounded-xl border backdrop-blur-md ${getStatusColor(currentStats.cpu, { critical: 90, warning: 70 })}`}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium opacity-90">CPU Usage</span>
              <Cpu className="w-4 h-4" />
            </div>
            <div className="text-3xl font-bold mb-2">{currentStats.cpu.toFixed(1)}%</div>
            <div className="h-2 bg-black/20 rounded-full overflow-hidden">
              <div
                className="h-full bg-current transition-all duration-300"
                style={{ width: `${Math.min(currentStats.cpu, 100)}%` }}
              />
            </div>
          </div>

          <div className={`p-4 rounded-xl border backdrop-blur-md ${getStatusColor(currentStats.memory, { critical: 90, warning: 75 })}`}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium opacity-90">Memory</span>
              <HardDrive className="w-4 h-4" />
            </div>
            <div className="text-3xl font-bold mb-2">{currentStats.memory.toFixed(1)}%</div>
            <div className="h-2 bg-black/20 rounded-full overflow-hidden">
              <div
                className="h-full bg-current transition-all duration-300"
                style={{ width: `${Math.min(currentStats.memory, 100)}%` }}
              />
            </div>
          </div>

          <div className={`p-4 rounded-xl border backdrop-blur-md ${getStatusColor(currentStats.disk, { critical: 95, warning: 85 })}`}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium opacity-90">Disk Usage</span>
              <Server className="w-4 h-4" />
            </div>
            <div className="text-3xl font-bold mb-2">{currentStats.disk.toFixed(1)}%</div>
            <div className="h-2 bg-black/20 rounded-full overflow-hidden">
              <div
                className="h-full bg-current transition-all duration-300"
                style={{ width: `${Math.min(currentStats.disk, 100)}%` }}
              />
            </div>
          </div>

          <div className="p-4 rounded-xl border backdrop-blur-md bg-cyan-500/10 border-cyan-500/30 text-cyan-400">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium opacity-90">Avg Latency</span>
              <Zap className="w-4 h-4" />
            </div>
            <div className="text-3xl font-bold">{currentStats.latency.toFixed(0)}ms</div>
          </div>
        </div>

        {/* Application Metrics */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Request Rate */}
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-4">
              <TrendingUp className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-white">Request Rate</h3>
            </div>
            {metrics.application.requests.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={metrics.application.requests}>
                  <defs>
                    <linearGradient id="colorRequests" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
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
                  <Area
                    type="monotone"
                    dataKey="value"
                    stroke="#06b6d4"
                    fillOpacity={1}
                    fill="url(#colorRequests)"
                    name="Requests/min"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[200px] flex items-center justify-center text-gray-500">
                No data available
              </div>
            )}
          </div>

          {/* Error Rate */}
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-4">
              <AlertTriangle className="w-4 h-4 text-red-400" />
              <h3 className="text-sm font-semibold text-white">Error Rate</h3>
            </div>
            {metrics.application.errors.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={metrics.application.errors}>
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
                  <Line
                    type="monotone"
                    dataKey="value"
                    stroke="#ef4444"
                    strokeWidth={2}
                    dot={false}
                    name="Errors/min"
                  />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[200px] flex items-center justify-center text-gray-500">
                No data available
              </div>
            )}
          </div>

          {/* Response Time */}
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-4">
              <Zap className="w-4 h-4 text-yellow-400" />
              <h3 className="text-sm font-semibold text-white">Response Time</h3>
            </div>
            {metrics.application.latency.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={metrics.application.latency}>
                  <defs>
                    <linearGradient id="colorLatency" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
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
                  <Area
                    type="monotone"
                    dataKey="value"
                    stroke="#f59e0b"
                    fillOpacity={1}
                    fill="url(#colorLatency)"
                    name="Latency (ms)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[200px] flex items-center justify-center text-gray-500">
                No data available
              </div>
            )}
          </div>

          {/* Database Performance */}
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-4">
              <Server className="w-4 h-4 text-purple-400" />
              <h3 className="text-sm font-semibold text-white">Database Queries</h3>
            </div>
            {metrics.database.queries.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={metrics.database.queries}>
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
                  <Bar dataKey="value" fill="#a855f7" radius={[4, 4, 0, 0]} name="Queries/min" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[200px] flex items-center justify-center text-gray-500">
                No data available
              </div>
            )}
          </div>
        </div>

        {/* Engine Metrics */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-4">
            <Cpu className="w-4 h-4 text-green-400" />
            <h3 className="text-sm font-semibold text-white">Engine Executions</h3>
          </div>
          {metrics.engines.executions.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <LineChart data={metrics.engines.executions}>
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
                <Line
                  type="monotone"
                  dataKey="success"
                  stroke="#10b981"
                  strokeWidth={2}
                  dot={false}
                  name="Successful"
                />
                <Line
                  type="monotone"
                  dataKey="failed"
                  stroke="#ef4444"
                  strokeWidth={2}
                  dot={false}
                  name="Failed"
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[250px] flex items-center justify-center text-gray-500">
              No data available
            </div>
          )}
        </div>

        {/* System Resources */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* CPU History */}
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-4">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-white">CPU History</h3>
            </div>
            {metrics.system.cpu.length > 0 ? (
              <ResponsiveContainer width="100%" height={150}>
                <AreaChart data={metrics.system.cpu}>
                  <defs>
                    <linearGradient id="colorCpu" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <Area
                    type="monotone"
                    dataKey="value"
                    stroke="#06b6d4"
                    fillOpacity={1}
                    fill="url(#colorCpu)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[150px] flex items-center justify-center text-gray-500">
                No data available
              </div>
            )}
          </div>

          {/* Memory History */}
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-4">
              <HardDrive className="w-4 h-4 text-purple-400" />
              <h3 className="text-sm font-semibold text-white">Memory History</h3>
            </div>
            {metrics.system.memory.length > 0 ? (
              <ResponsiveContainer width="100%" height={150}>
                <AreaChart data={metrics.system.memory}>
                  <defs>
                    <linearGradient id="colorMemory" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#a855f7" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#a855f7" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <Area
                    type="monotone"
                    dataKey="value"
                    stroke="#a855f7"
                    fillOpacity={1}
                    fill="url(#colorMemory)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[150px] flex items-center justify-center text-gray-500">
                No data available
              </div>
            )}
          </div>

          {/* Network I/O */}
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-4">
              <Network className="w-4 h-4 text-green-400" />
              <h3 className="text-sm font-semibold text-white">Network I/O</h3>
            </div>
            {metrics.system.network.length > 0 ? (
              <ResponsiveContainer width="100%" height={150}>
                <AreaChart data={metrics.system.network}>
                  <defs>
                    <linearGradient id="colorNetwork" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <Area
                    type="monotone"
                    dataKey="value"
                    stroke="#10b981"
                    fillOpacity={1}
                    fill="url(#colorNetwork)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[150px] flex items-center justify-center text-gray-500">
                No data available
              </div>
            )}
          </div>
        </div>
      </div>
    </PageShell>
  );
}
