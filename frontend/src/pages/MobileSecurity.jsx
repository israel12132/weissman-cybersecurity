import { useState, useEffect, useCallback, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Smartphone, Shield, AlertTriangle, Search, Loader2, ExternalLink } from 'lucide-react';
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useWeissmanEnginePage, applyHistoryFindings } from '../hooks/useWeissmanEnginePage'
import EmptyState from '../components/ui/EmptyState'
import { SkeletonTable } from '../components/ui/Skeleton'
import { apiFetch } from '../lib/apiBase'
import { clientPrimaryTargetUrl } from '../lib/clientTarget'
import { useJobPoll, resolveJobFindings } from '../lib/useJobPoll'

const MOBILE_ENGINE = 'mobile_attack'
const SEVERITY_KEYS = ['critical', 'high', 'medium', 'low', 'info']
const SEV_META = {
  critical: { color: '#f43f5e', rank: 5 },
  high: { color: '#fb923c', rank: 4 },
  medium: { color: '#fbbf24', rank: 3 },
  low: { color: '#38bdf8', rank: 2 },
  info: { color: '#94a3b8', rank: 1 },
}
const normSev = (s) => (SEV_META[String(s || '').toLowerCase()] ? String(s).toLowerCase() : 'info')

function SeverityBadge({ severity, t }) {
  const k = normSev(severity)
  const { color } = SEV_META[k]
  return (
    <span
      className="px-1.5 py-0.5 rounded text-[9px] font-mono uppercase tracking-wider border"
      style={{ color, borderColor: `${color}55`, background: `${color}14` }}
    >
      {t(`pages.mobileSecurity.sev_${k}`)}
    </span>
  )
}

/**
 * MobileSecurity — mobile/app findings from the real GET /api/mobile-security/apps
 * endpoint. Apps are derived from mobile-tagged vulnerabilities; each carries only
 * the fields the backend actually returns (name, package_id, platform,
 * findings_count, max_severity). No upload widget or fabricated app metadata.
 */
export default function MobileSecurity() {
  const { t } = useTranslation();
  const [apps, setApps] = useState([]);
  const [findings, setFindings] = useState([]);
  const [clients, setClients] = useState([]);
  const [selectedClientId, setSelectedClientId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [scanningAppId, setScanningAppId] = useState(null);
  const [pendingJobId, setPendingJobId] = useState(null);
  const [scanError, setScanError] = useState(null);

  const fetchMobileApps = useCallback(async () => {
    setLoading(true);
    try {
      const response = await apiFetch('/api/mobile-security/apps');
      if (response.ok) {
        const data = await response.json();
        setApps(Array.isArray(data.apps) ? data.apps : []);
        setFindings(Array.isArray(data.findings) ? data.findings : []);
      }
    } catch {
      // non-critical: list stays empty and the empty-state explains next steps
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchMobileApps();
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => {
        if (!Array.isArray(d)) return
        setClients(d)
        if (d.length) setSelectedClientId(String(d[0].id))
      })
      .catch(() => setClients([]));
  }, [fetchMobileApps]);

  const platformFindings = useMemo(
    () => findings.filter((f) => filter === 'all' || f.platform === filter),
    [findings, filter],
  );

  const {
    filteredFindings,
    counts,
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    exportCsv,
    refreshFromHistory,
    historyLoading,
    lastUpdated,
    lastJobId,
    setLastUpdated,
    setLastJobId,
  } = useWeissmanEnginePage(MOBILE_ENGINE, platformFindings);

  useEffect(() => {
    refreshFromHistory().then((run) => {
      if (run?.findings?.length) {
        applyHistoryFindings(run, setFindings, { setLastUpdated, setJobId: setLastJobId })
      }
    })
  }, [refreshFromHistory, setLastUpdated, setLastJobId])

  const handleRefresh = useCallback(async () => {
    await fetchMobileApps()
    const run = await refreshFromHistory()
    applyHistoryFindings(run, setFindings, { setLastUpdated, setJobId: setLastJobId })
  }, [fetchMobileApps, refreshFromHistory, setLastUpdated, setLastJobId])

  useJobPoll(pendingJobId, {
    enabled: Boolean(pendingJobId),
    onComplete: async (job) => {
      const resolved = await resolveJobFindings(job, MOBILE_ENGINE, selectedClientId)
      if (resolved.length) {
        setFindings((prev) => {
          const ids = new Set(prev.map((f) => f.id))
          return [...resolved.filter((f) => !ids.has(f.id)), ...prev]
        })
      }
      setLastUpdated(new Date().toISOString())
      if (pendingJobId) setLastJobId(pendingJobId)
      await fetchMobileApps()
      setScanningAppId(null)
      setPendingJobId(null)
    },
  })

  const handleScan = useCallback(async (app) => {
    if (!selectedClientId) {
      setScanError(t('pages.mobileSecurity.select_client_first'))
      return
    }
    const client = clients.find((c) => String(c.id) === String(selectedClientId))
    const target = clientPrimaryTargetUrl(client)
    if (!target) {
      setScanError(t('pages.mobileSecurity.no_client_domain'))
      return
    }
    setScanError(null)
    setScanningAppId(app.id)
    try {
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          engine: MOBILE_ENGINE,
          client_id: Number(selectedClientId),
          target,
          package_id: app.package_id,
          platform: app.platform,
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) {
        setScanError(d.detail || d.error || t('pages.mobileSecurity.scan_failed'))
        setScanningAppId(null)
        return
      }
      const jobId = d.job_id ?? ''
      if (jobId) setPendingJobId(jobId)
      else {
        setScanError(t('pages.mobileSecurity.scan_no_job'))
        setScanningAppId(null)
      }
    } catch (e) {
      setScanError(e?.message ?? t('pages.mobileSecurity.network_error'))
      setScanningAppId(null)
    }
  }, [selectedClientId, clients, t])

  const filteredApps = useMemo(
    () =>
      apps
        .filter((app) => filter === 'all' || app.platform === filter)
        .filter((app) => {
          if (!searchTerm) return true
          const q = searchTerm.toLowerCase()
          return (
            String(app.name || '').toLowerCase().includes(q) ||
            String(app.package_id || '').toLowerCase().includes(q)
          )
        }),
    [apps, filter, searchTerm],
  );

  const sevCounts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const f of findings) c[normSev(f.severity)] += 1
    return c
  }, [findings]);

  const refreshAction = (
    <ShellScanActions
      onRefresh={handleRefresh}
      onExport={exportCsv}
      refreshLoading={historyLoading || loading}
      refreshDisabled={Boolean(pendingJobId)}
      exportDisabled={!filteredFindings.length}
    />
  );

  return (
    <PageShell
      title={t('pages.mobileSecurity.title')}
      subtitle={t('pages.mobileSecurity.subtitle')}
      badge={t('pages.mobileSecurity.badge')}
      badgeColor="#22d3ee"
      icon={<Smartphone />}
      actions={refreshAction}
    >
      <div className="space-y-6">
        {clients.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono text-white/40">{t('pages.mobileSecurity.client_label')}</span>
            <select
              value={selectedClientId ?? ''}
              onChange={(e) => setSelectedClientId(e.target.value || null)}
              className="bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white/80 font-mono focus:outline-none focus:border-cyan-500/40"
            >
              {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </div>
        )}

        {scanError && (
          <div className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            {scanError}
          </div>
        )}

        {/* KPIs — all derived from the real API response */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {[
            { key: 'stat_total_apps', value: apps.length, color: '#22d3ee', Icon: Smartphone },
            { key: 'stat_ios', value: apps.filter((a) => a.platform === 'ios').length, color: '#a78bfa', Icon: Shield },
            { key: 'stat_android', value: apps.filter((a) => a.platform === 'android').length, color: '#34d399', Icon: Shield },
            { key: 'stat_findings', value: findings.length, color: '#fb923c', Icon: AlertTriangle },
          ].map(({ key, value, color, Icon }) => (
            <div key={key} className="rounded-2xl border border-white/10 bg-black/40 backdrop-blur-md p-4">
              <div className="flex items-start justify-between">
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-widest text-white/40">
                    {t(`pages.mobileSecurity.${key}`)}
                  </div>
                  <div className="text-2xl font-bold mt-1 tabular-nums" style={{ color }}>
                    {loading ? '—' : value}
                  </div>
                </div>
                <Icon className="w-4 h-4 shrink-0" style={{ color }} />
              </div>
            </div>
          ))}
        </div>

        {/* Severity distribution from the real findings list */}
        {findings.length > 0 && (
          <div className="flex flex-wrap items-center gap-2">
            {SEVERITY_KEYS.filter((k) => sevCounts[k] > 0).map((k) => (
              <span
                key={k}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-mono border"
                style={{ color: SEV_META[k].color, borderColor: `${SEV_META[k].color}33`, background: `${SEV_META[k].color}0d` }}
              >
                {t(`pages.mobileSecurity.sev_${k}`)}
                <span className="tabular-nums font-semibold">{sevCounts[k]}</span>
              </span>
            ))}
          </div>
        )}

        {/* Search and platform filter */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex-1 min-w-[200px] relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-white/25" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder={t('pages.mobileSecurity.search_placeholder')}
              className="w-full pl-10 pr-4 py-2 bg-black/40 border border-white/10 rounded-lg text-sm text-white placeholder-white/25 focus:outline-none focus:border-cyan-500/40"
            />
          </div>
          <div className="flex items-center gap-1 bg-black/40 border border-white/10 rounded-lg p-1">
            {['all', 'ios', 'android'].map((f) => (
              <button
                key={f}
                type="button"
                onClick={() => setFilter(f)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                  filter === f
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                    : 'text-white/45 hover:text-white/80'
                }`}
              >
                {t(`pages.mobileSecurity.filter_${f}`)}
              </button>
            ))}
          </div>
        </div>

        {/* Apps list */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/10">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Smartphone className="w-4 h-4 text-cyan-400" />
              {t('pages.mobileSecurity.apps_heading')}
            </h3>
          </div>

          {loading ? (
            <div className="p-4"><SkeletonTable rows={4} cols={4} /></div>
          ) : filteredApps.length === 0 ? (
            <div className="p-4">
              <EmptyState
                compact
                icon="search"
                title={t('pages.mobileSecurity.apps_empty_title')}
                body={t('pages.mobileSecurity.apps_empty_body')}
              />
            </div>
          ) : (
            <div className="divide-y divide-white/5">
              {filteredApps.map((app) => (
                <div key={app.id} className="p-4 hover:bg-white/5 transition-colors">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 mb-1.5 flex-wrap">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-medium border ${
                            app.platform === 'ios'
                              ? 'bg-violet-500/15 text-violet-300 border-violet-500/30'
                              : app.platform === 'android'
                                ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                                : 'bg-white/5 text-white/50 border-white/10'
                          }`}
                        >
                          <Smartphone className="w-3 h-3" />
                          {t(`pages.mobileSecurity.platform_${app.platform || 'unknown'}`, { defaultValue: app.platform })}
                        </span>
                        <h4 className="text-sm font-semibold text-white truncate">
                          {app.name || app.package_id || '—'}
                        </h4>
                        {app.max_severity && <SeverityBadge severity={app.max_severity} t={t} />}
                      </div>
                      <div className="flex items-center gap-3 text-xs text-white/40 font-mono flex-wrap">
                        <span className="truncate">{t('pages.mobileSecurity.package_label')} {app.package_id || '—'}</span>
                        <span>•</span>
                        <span>{t('pages.mobileSecurity.findings_count_badge', { count: app.findings_count ?? 0 })}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        type="button"
                        onClick={() => handleScan(app)}
                        disabled={!selectedClientId || (scanningAppId === app.id && Boolean(pendingJobId))}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 rounded-lg text-xs font-medium hover:bg-cyan-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                      >
                        {scanningAppId === app.id && pendingJobId && <Loader2 className="w-3 h-3 animate-spin" />}
                        {scanningAppId === app.id && pendingJobId ? t('pages.mobileSecurity.scanning') : t('pages.mobileSecurity.scan_now')}
                      </button>
                      <Link
                        to={`/findings?q=${encodeURIComponent(app.package_id || app.name || '')}`}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white/5 text-white/60 border border-white/10 rounded-lg text-xs font-medium hover:bg-white/10 hover:text-white/90 transition-colors"
                      >
                        <ExternalLink className="w-3 h-3" />
                        {t('pages.mobileSecurity.view_findings')}
                      </Link>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent mobile findings (real list) */}
        <WeissmanFindingsPanel
          findings={platformFindings}
          filteredFindings={filteredFindings}
          counts={counts}
          total={platformFindings.length}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          severityFilter={severityFilter}
          onSeverityChange={setSeverityFilter}
          pending={Boolean(pendingJobId) && platformFindings.length === 0}
          loading={(loading || historyLoading) && platformFindings.length === 0}
          lastUpdated={lastUpdated}
          jobId={pendingJobId || lastJobId}
          accent="#22d3ee"
          title={t('pages.mobileSecurity.recent_findings_heading')}
          showEmptyReady={!loading && platformFindings.length === 0}
          emptyReadyTitle={t('pages.mobileSecurity.findings_empty_title')}
          renderFinding={(f) => (
            <div key={f.id} className="rounded-lg border border-white/10 bg-black/30 px-3 py-2 flex items-start gap-3">
              <SeverityBadge severity={f.severity} t={t} />
              <div className="min-w-0 flex-1">
                <p className="text-sm text-white/85 truncate">{f.title || '—'}</p>
                <p className="text-[10px] text-white/35 font-mono mt-0.5">
                  {(f.platform || 'unknown')} · {f.status || 'open'}
                </p>
              </div>
            </div>
          )}
        />
      </div>
    </PageShell>
  );
}
