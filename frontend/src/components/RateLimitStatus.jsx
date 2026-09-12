import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Activity, AlertTriangle, CheckCircle, Clock } from 'lucide-react';
import { apiFetch } from '../utils/apiFetch';
import { useVisiblePolling } from '../hooks/useVisiblePolling';

const NS = 'components.intelWidgets.rateLimitStatus';

function limitBucketOk(bucket) {
  return Boolean(
    bucket
    && Number.isFinite(Number(bucket.current))
    && Number.isFinite(Number(bucket.max))
    && Number(bucket.max) > 0,
  )
}

/**
 * RateLimitStatus - Real-time rate limit monitoring component
 *
 * Shows current usage vs limits for:
 * - Scan operations (per minute)
 * - Login attempts (per minute)
 * - API calls (per second)
 *
 * Features:
 * - Color-coded status (green/yellow/red/unavailable)
 * - Live countdown timer
 * - Usage percentage bars
 * - Visible-tab refresh every 15s (full) / 30s (compact)
 */
export default function RateLimitStatus({ compact = false }) {
  const { t } = useTranslation();
  const [limits, setLimits] = useState(null);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const abortRef = useRef(null);
  const inflightRef = useRef(false);

  const fetchLimits = useCallback(async () => {
    if (inflightRef.current) return;
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    inflightRef.current = true;
    try {
      const data = await apiFetch('/api/rate-limits/status', { signal: ac.signal });
      if (data?.ok === false || data?.unavailable) {
        throw new Error(data.detail || 'unavailable');
      }
      const next = data.limits || {};
      if (!limitBucketOk(next.scans) || !limitBucketOk(next.logins) || !limitBucketOk(next.api)) {
        throw new Error('unavailable');
      }
      setLimits({
        scans: next.scans,
        logins: next.logins,
        api: next.api,
      });
      setUnavailable(false);
    } catch (error) {
      if (error?.name === 'AbortError' || ac.signal.aborted) return;
      setUnavailable(true);
      setLimits(null);
    } finally {
      if (abortRef.current === ac) inflightRef.current = false;
      if (abortRef.current === ac && !ac.signal.aborted) setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLimits();
    return () => abortRef.current?.abort();
  }, [fetchLimits]);
  useVisiblePolling(fetchLimits, compact ? 30000 : 15000);

  const getStatus = (current, max) => {
    if (!max || max <= 0) return 'unknown';
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
      default: return 'text-amber-200 bg-amber-500/10 border-amber-500/30';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'critical': return <AlertTriangle className="w-4 h-4" />;
      case 'warning': return <Clock className="w-4 h-4" />;
      case 'healthy': return <CheckCircle className="w-4 h-4" />;
      default: return <AlertTriangle className="w-4 h-4" />;
    }
  };

  const formatResetTime = (seconds) => {
    if (seconds <= 0) return t(`${NS}.resetNow`);
    if (seconds < 60) return `${seconds}s`;
    return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  };

  if (loading && !limits) {
    return compact ? (
      <div className="flex items-center gap-2 text-xs text-[var(--text-tertiary)]">
        <Activity className="w-3 h-3 animate-pulse" />
        <span>{t(`${NS}.loading`)}</span>
      </div>
    ) : (
      <div className="h-32 rounded-xl border border-white/10 bg-black/40 animate-pulse" />
    );
  }

  if (unavailable) {
    return (
      <p
        className={compact
          ? 'flex items-center gap-2 px-3 py-1.5 rounded-lg border text-amber-200 bg-amber-500/10 border-amber-500/30 text-xs'
          : 'text-sm text-amber-200/90'}
        data-testid="rate-limit-unavailable"
        role="alert"
      >
        {t(`${NS}.unavailable`)}
      </p>
    );
  }

  if (!limits) {
    return compact ? (
      <div className="flex items-center gap-2 text-xs text-[var(--text-tertiary)]">
        <Activity className="w-3 h-3 animate-pulse" />
        <span>{t(`${NS}.loading`)}</span>
      </div>
    ) : (
      <div className="h-32 rounded-xl border border-white/10 bg-black/40 animate-pulse" />
    );
  }

  if (compact) {
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

  return (
    <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <Activity className="w-4 h-4 text-cyan-400" />
          {t(`${NS}.title`)}
        </h3>
        <span className="text-xs text-[var(--text-tertiary)]">
          {t(`${NS}.updated`, { time: new Date().toLocaleTimeString() })}
        </span>
      </div>

      <div className="space-y-3">
        {Object.entries(limits).map(([key, { current, max, resetIn }]) => {
          const status = getStatus(current, max);
          const percentage = max > 0 ? (current / max) * 100 : 0;
          const label = t(`${NS}.labels.${key}`, { defaultValue: key });

          return (
            <div key={key} className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  {getStatusIcon(status)}
                  <span className="text-[var(--text-secondary)] font-medium">{label}</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className={`font-mono ${
                    status === 'critical' ? 'text-red-400' :
                    status === 'warning' ? 'text-yellow-400' :
                    status === 'healthy' ? 'text-green-400' :
                    'text-amber-200'
                  }`}>
                    {current}/{max}
                  </span>
                  <span className="text-[var(--text-muted)]">
                    {t(`${NS}.reset`, { time: formatResetTime(resetIn) })}
                  </span>
                </div>
              </div>

              <div className="h-1.5 bg-[var(--bg-3)]/50 rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all duration-300 ${
                    status === 'critical' ? 'bg-red-500' :
                    status === 'warning' ? 'bg-yellow-500' :
                    status === 'healthy' ? 'bg-green-500' :
                    'bg-amber-400/40'
                  }`}
                  style={{ width: `${Math.min(percentage, 100)}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>

      {!unavailable && Object.values(limits).some(({ current, max }) => max > 0 && (current / max) >= 0.9) && (
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
