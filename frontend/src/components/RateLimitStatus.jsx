import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Activity, AlertTriangle, CheckCircle, Clock } from 'lucide-react';
import { apiFetch } from '../lib/apiBase';

const NS = 'components.intelWidgets.rateLimitStatus';

/**
 * RateLimitStatus - Real-time rate limit monitoring component
 *
 * Shows current usage vs limits for:
 * - Scan operations (per minute)
 * - Login attempts (per minute)
 * - API calls (per second)
 *
 * Features:
 * - Color-coded status (green/yellow/red)
 * - Live countdown timer
 * - Usage percentage bars
 * - Auto-refresh every 5 seconds
 */
export default function RateLimitStatus({ compact = false }) {
  const { t } = useTranslation();
  const [limits, setLimits] = useState({
    scans: { current: 0, max: 24, resetIn: 0 },
    logins: { current: 0, max: 8, resetIn: 0 },
    api: { current: 0, max: 30, resetIn: 0 },
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchLimits();
    const interval = setInterval(fetchLimits, 5000); // Refresh every 5s
    return () => clearInterval(interval);
  }, []);

  const fetchLimits = async () => {
    try {
      const response = await apiFetch('/api/rate-limits/status');
      if (response.ok) {
        const data = await response.json();
        const next = data.limits || {};
        setLimits({
          scans: next.scans || limits.scans,
          logins: next.logins || limits.logins,
          api: next.api || limits.api,
        });
      }
    } catch (error) {
      console.warn('Failed to fetch rate limits:', error);
    } finally {
      setLoading(false);
    }
  };

  const getStatus = (current, max) => {
    const percentage = (current / max) * 100;
    if (percentage >= 90) return 'critical';
    if (percentage >= 70) return 'warning';
    return 'healthy';
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'critical': return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'warning': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'healthy': return 'text-green-400 bg-green-500/10 border-green-500/30';
      default: return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'critical': return <AlertTriangle className="w-4 h-4" />;
      case 'warning': return <Clock className="w-4 h-4" />;
      case 'healthy': return <CheckCircle className="w-4 h-4" />;
      default: return <Activity className="w-4 h-4" />;
    }
  };

  const formatResetTime = (seconds) => {
    if (seconds <= 0) return t(`${NS}.resetNow`);
    if (seconds < 60) return `${seconds}s`;
    return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  };

  if (loading && compact) {
    return (
      <div className="flex items-center gap-2 text-xs text-gray-400">
        <Activity className="w-3 h-3 animate-pulse" />
        <span>{t(`${NS}.loading`)}</span>
      </div>
    );
  }

  if (compact) {
    // Compact mode for header/toolbar
    const scanStatus = getStatus(limits.scans.current, limits.scans.max);
    const StatusIcon = getStatusIcon(scanStatus);

    return (
      <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border ${getStatusColor(scanStatus)}`}>
        {StatusIcon}
        <span className="text-xs font-medium">
          {t(`${NS}.scansCompact`, { current: limits.scans.current, max: limits.scans.max })}
        </span>
      </div>
    );
  }

  // Full mode for dedicated display
  return (
    <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <Activity className="w-4 h-4 text-cyan-400" />
          {t(`${NS}.title`)}
        </h3>
        <span className="text-xs text-gray-400">
          {t(`${NS}.updated`, { time: new Date().toLocaleTimeString() })}
        </span>
      </div>

      <div className="space-y-3">
        {Object.entries(limits).map(([key, { current, max, resetIn }]) => {
          const status = getStatus(current, max);
          const percentage = (current / max) * 100;
          const label = t(`${NS}.labels.${key}`, { defaultValue: key });

          return (
            <div key={key} className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  {getStatusIcon(status)}
                  <span className="text-gray-300 font-medium">{label}</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className={`font-mono ${
                    status === 'critical' ? 'text-red-400' :
                    status === 'warning' ? 'text-yellow-400' :
                    'text-green-400'
                  }`}>
                    {current}/{max}
                  </span>
                  <span className="text-gray-500">
                    {t(`${NS}.reset`, { time: formatResetTime(resetIn) })}
                  </span>
                </div>
              </div>

              {/* Progress bar */}
              <div className="h-1.5 bg-gray-800/50 rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all duration-300 ${
                    status === 'critical' ? 'bg-red-500' :
                    status === 'warning' ? 'bg-yellow-500' :
                    'bg-green-500'
                  }`}
                  style={{ width: `${Math.min(percentage, 100)}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>

      {/* Warning message if any limit is near */}
      {Object.values(limits).some(({ current, max }) => (current / max) >= 0.9) && (
        <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
          <p className="text-xs text-red-400">
            <AlertTriangle className="w-3 h-3 inline mr-1" />
            {t(`${NS}.warning`)}
          </p>
        </div>
      )}
    </div>
  );
}
