import { useState, useEffect } from 'react';
import { Activity, TrendingUp, TrendingDown, AlertTriangle, CheckCircle, BarChart3 } from 'lucide-react';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import PageShell from './PageShell';
import { api } from '../utils/apiFetch';

/**
 * BaselineAndDrift - Security posture baseline and drift detection
 *
 * Features:
 * - Establish security baseline (normal state)
 * - Continuous drift detection
 * - Anomaly scoring
 * - Threshold-based alerting
 * - Historical trend analysis
 * - Baseline snapshots
 * - Configuration drift tracking
 */
export default function BaselineAndDrift() {
  const [baseline, setBaseline] = useState(null);
  const [driftData, setDriftData] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState('7d'); // 24h, 7d, 30d

  useEffect(() => {
    fetchData();
  }, [timeRange]);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [baselineRes, driftRes, anomaliesRes] = await Promise.all([
        api.get('/api/baseline/current'),
        api.get(`/api/baseline/drift?range=${timeRange}`),
        api.get(`/api/baseline/anomalies?range=${timeRange}`),
      ]);
      setBaseline(baselineRes);
      setDriftData(driftRes.data || []);
      setAnomalies(anomaliesRes.anomalies || []);
    } catch (error) {
      console.error('Failed to fetch baseline data:', error);
    } finally {
      setLoading(false);
    }
  };

  const createBaseline = async () => {
    try {
      await api.post('/api/baseline/create');
      alert('Baseline created successfully!');
      fetchData();
    } catch (error) {
      console.error('Failed to create baseline:', error);
    }
  };

  const getDriftColor = (drift) => {
    if (drift > 20) return 'text-red-400';
    if (drift > 10) return 'text-yellow-400';
    return 'text-green-400';
  };

  const stats = baseline
    ? {
        totalAssets: baseline.total_assets || 0,
        driftScore: baseline.drift_score || 0,
        anomalyCount: anomalies.length,
        lastUpdated: baseline.last_updated,
      }
    : { totalAssets: 0, driftScore: 0, anomalyCount: 0, lastUpdated: null };

  return (
    <PageShell title="Baseline & Drift Detection" icon={<Activity />}>
      <div className="space-y-6">
        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Baseline Assets</span>
              <CheckCircle className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{stats.totalAssets}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Drift Score</span>
              <TrendingUp className="w-4 h-4 text-purple-400" />
            </div>
            <div className={`text-2xl font-bold ${getDriftColor(stats.driftScore)}`}>
              {stats.driftScore.toFixed(1)}%
            </div>
          </div>

          <div className="bg-red-500/10 backdrop-blur-md border border-red-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-red-400">Anomalies</span>
              <AlertTriangle className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-red-400">{stats.anomalyCount}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Last Update</span>
              <Activity className="w-4 h-4 text-green-400" />
            </div>
            <div className="text-sm font-bold text-white">
              {stats.lastUpdated ? new Date(stats.lastUpdated).toLocaleDateString() : 'Never'}
            </div>
          </div>
        </div>

        {/* Controls */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 bg-black/40 backdrop-blur-md border border-white/10 rounded-lg p-1">
            {['24h', '7d', '30d'].map((range) => (
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
            onClick={createBaseline}
            className="px-4 py-2 bg-cyan-500 text-white rounded-lg font-medium hover:bg-cyan-600 transition-colors"
          >
            Create New Baseline
          </button>
        </div>

        {/* Drift Chart */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-white">Drift Over Time</h3>
          </div>
          {driftData.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <LineChart data={driftData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="time" stroke="#64748b" style={{ fontSize: '12px' }} />
                <YAxis stroke="#64748b" style={{ fontSize: '12px' }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    border: '1px solid #334155',
                    borderRadius: '8px',
                  }}
                />
                <Line type="monotone" dataKey="drift" stroke="#06b6d4" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[250px] flex items-center justify-center text-gray-500">
              No drift data available
            </div>
          )}
        </div>

        {/* Anomalies */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/10">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400" />
              Detected Anomalies ({anomalies.length})
            </h3>
          </div>

          {loading ? (
            <div className="p-8 text-center text-gray-500">
              <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
              Loading anomalies...
            </div>
          ) : anomalies.length === 0 ? (
            <div className="p-8 text-center text-gray-500">No anomalies detected</div>
          ) : (
            <div className="divide-y divide-white/5 max-h-[400px] overflow-y-auto">
              {anomalies.map((anomaly) => (
                <div key={anomaly.id} className="p-4 hover:bg-white/5 transition-colors">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <AlertTriangle className="w-4 h-4 text-red-400" />
                        <h4 className="text-sm font-semibold text-white">{anomaly.type}</h4>
                        <span className="px-2 py-1 bg-red-500/20 text-red-400 border border-red-500/30 rounded text-xs font-medium">
                          Score: {anomaly.score}
                        </span>
                      </div>
                      <p className="text-xs text-gray-400 mb-2">{anomaly.description}</p>
                      <div className="text-xs text-gray-500">
                        Detected: {new Date(anomaly.detected_at).toLocaleString()}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Info */}
        {!baseline && (
          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle className="w-5 h-5 text-yellow-400" />
              <h3 className="text-sm font-semibold text-white">No Baseline Established</h3>
            </div>
            <p className="text-sm text-gray-300">
              Create a baseline to start tracking drift and detecting anomalies in your security posture.
            </p>
          </div>
        )}
      </div>
    </PageShell>
  );
}
