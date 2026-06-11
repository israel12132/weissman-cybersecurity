import { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { Smartphone, Shield, AlertTriangle, Search, Filter } from 'lucide-react';
import PageShell from './PageShell'
import { apiFetch } from '../lib/apiBase'
import { clientPrimaryTargetUrl } from '../lib/clientTarget'
import { useJobPoll, resolveJobFindings } from '../lib/useJobPoll'

const MOBILE_ENGINE = 'mobile_attack'

/**
 * MobileSecurity - Mobile & App Security Analysis Dashboard
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
    try {
      const response = await apiFetch('/api/mobile-security/apps');
      if (response.ok) {
        const data = await response.json();
        setApps(data.apps || []);
        setFindings(data.findings || []);
      }
    } catch (error) {
      console.error('Failed to fetch mobile apps:', error);
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
      .catch(() => {});
  }, [fetchMobileApps]);

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

  const filteredApps = apps
    .filter((app) => filter === 'all' || app.platform === filter)
    .filter((app) =>
      searchTerm
        ? app.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
          app.package_id.toLowerCase().includes(searchTerm.toLowerCase())
        : true
    );

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'high':
        return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'medium':
        return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'low':
        return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30';
      default:
        return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
    }
  };

  return (
    <PageShell title={t('pages.mobileSecurity.title')} icon={<Smartphone />}>
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
          <div className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {scanError}
          </div>
        )}

        {/* Header Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">{t('pages.mobileSecurity.stats_total_apps')}</span>
              <Smartphone className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{apps.length}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">{t('pages.mobileSecurity.stats_ios_apps')}</span>
              <Shield className="w-4 h-4 text-gray-400" />
            </div>
            <div className="text-2xl font-bold text-white">
              {apps.filter((a) => a.platform === 'ios').length}
            </div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">{t('pages.mobileSecurity.stats_android_apps')}</span>
              <Shield className="w-4 h-4 text-green-400" />
            </div>
            <div className="text-2xl font-bold text-white">
              {apps.filter((a) => a.platform === 'android').length}
            </div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">{t('pages.mobileSecurity.stats_vulnerabilities')}</span>
              <AlertTriangle className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-white">{findings.length}</div>
          </div>
        </div>

        {/* Search and Filter */}
        <div className="flex items-center gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder={t('pages.mobileSecurity.search_placeholder')}
              className="w-full pl-10 pr-4 py-2 bg-black/40 backdrop-blur-md border border-white/10 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            />
          </div>

          <div className="flex items-center gap-2 bg-black/40 backdrop-blur-md border border-white/10 rounded-lg p-1">
            {['all', 'ios', 'android'].map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                  filter === f
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                    : 'text-gray-400 hover:text-white hover:bg-white/5'
                }`}
              >
                {f === 'all' ? t('pages.mobileSecurity.filter_all') : f === 'ios' ? t('pages.mobileSecurity.filter_ios') : t('pages.mobileSecurity.filter_android')}
              </button>
            ))}
          </div>
        </div>

        {/* Apps List */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/10">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Filter className="w-4 h-4 text-cyan-400" />
              {t('pages.mobileSecurity.apps_heading')}
            </h3>
          </div>

          {loading ? (
            <div className="p-8 text-center text-gray-500">
              <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
              {t('pages.mobileSecurity.loading')}
            </div>
          ) : filteredApps.length === 0 ? (
            <div className="p-8 text-center text-gray-500">
              {t('pages.mobileSecurity.empty')}
            </div>
          ) : (
            <div className="divide-y divide-white/5">
              {filteredApps.map((app) => (
                <div
                  key={app.id}
                  className="p-4 hover:bg-white/5 transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <div
                          className={`flex items-center gap-2 px-2 py-1 rounded-md text-xs font-medium ${
                            app.platform === 'ios'
                              ? 'bg-gray-500/20 text-gray-300 border border-gray-500/30'
                              : 'bg-green-500/20 text-green-400 border border-green-500/30'
                          }`}
                        >
                          <Smartphone className="w-3 h-3" />
                          {app.platform === 'ios' ? t('pages.mobileSecurity.platform_ios') : t('pages.mobileSecurity.platform_android')}
                        </div>
                        <h4 className="text-sm font-semibold text-white">{app.name}</h4>
                        <span className="text-xs text-gray-500">{app.version}</span>
                      </div>

                      <div className="flex items-center gap-4 text-xs text-gray-400 mb-2">
                        <span>{t('pages.mobileSecurity.package_label')} {app.package_id}</span>
                        <span>•</span>
                        <span>{t('pages.mobileSecurity.size_label', { size: app.size_mb })}</span>
                        <span>•</span>
                        <span>{t('pages.mobileSecurity.last_scanned_label')} {app.last_scan || t('pages.mobileSecurity.last_scanned_never')}</span>
                      </div>

                      {app.findings && app.findings.length > 0 && (
                        <div className="flex items-center gap-2 mt-2">
                          {['critical', 'high', 'medium', 'low'].map((severity) => {
                            const count = app.findings.filter(
                              (f) => f.severity?.toLowerCase() === severity
                            ).length;
                            if (count === 0) return null;
                            return (
                              <div
                                key={severity}
                                className={`px-2 py-1 rounded-md text-xs font-medium ${getSeverityColor(
                                  severity
                                )}`}
                              >
                                {t(`pages.mobileSecurity.severity_count_${severity}`, { count })}
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => handleScan(app)}
                        disabled={!selectedClientId || (scanningAppId === app.id && Boolean(pendingJobId))}
                        className="px-3 py-1.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-medium hover:bg-cyan-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                      >
                        {scanningAppId === app.id && pendingJobId ? t('pages.mobileSecurity.scanning') : t('pages.mobileSecurity.scan_now')}
                      </button>
                      <button className="px-3 py-1.5 bg-white/5 text-gray-300 border border-white/10 rounded-lg text-xs font-medium hover:bg-white/10 transition-colors">
                        {t('pages.mobileSecurity.view_details')}
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Upload New App */}
        <div className="bg-gradient-to-r from-cyan-500/10 to-blue-500/10 backdrop-blur-md border border-cyan-500/30 rounded-xl p-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white mb-1">{t('pages.mobileSecurity.upload_title')}</h3>
              <p className="text-xs text-gray-400">
                {t('pages.mobileSecurity.upload_body')}
              </p>
            </div>
            <button className="px-4 py-2 bg-cyan-500 text-white rounded-lg text-sm font-medium hover:bg-cyan-600 transition-colors">
              {t('pages.mobileSecurity.choose_file')}
            </button>
          </div>
        </div>
      </div>
    </PageShell>
  );
}
