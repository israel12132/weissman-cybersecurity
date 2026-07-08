import { useState, useEffect, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Package, AlertTriangle, Shield, Download, Database } from 'lucide-react';
import PageShell from './PageShell';
import ShellScanActions from '../components/engine/ShellScanActions';
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar';
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench';
import EmptyState from '../components/ui/EmptyState';
import { SkeletonWidgetGrid } from '../components/ui/Skeleton';
import { api } from '../utils/apiFetch';
import { apiFetch } from '../lib/apiBase';
import { useFirstTenantClientId, withClientId } from '../lib/aliasClient';

const FILTER_KEYS = ['all', 'vulnerable', 'high_severity', 'direct', 'transitive'];

function vulnKey(vuln, idx) {
  return vuln?.id ?? vuln?.cve ?? vuln?.title ?? idx;
}

function cveLabel(vuln) {
  const cve = vuln?.cve;
  if (cve && cve !== 'null' && String(cve).trim()) return String(cve);
  return vuln?.title || '—';
}

function cveHref(vuln) {
  const cve = String(vuln?.cve || '').trim();
  if (/^CVE-\d/i.test(cve)) return `https://nvd.nist.gov/vuln/detail/${cve}`;
  return null;
}

export default function SBOMBrowser() {
  const { t } = useTranslation();
  const { clientId, loading: clientLoading } = useFirstTenantClientId();
  const [components, setComponents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('all');
  const [ecosystemFilter, setEcosystemFilter] = useState('all');

  const fetchSBOM = useCallback(async (cid) => {
    try {
      setLoading(true);
      setError('');
      const data = await api.get(withClientId('/api/sbom/components', cid));
      setComponents(Array.isArray(data.components) ? data.components : []);
    } catch (err) {
      console.error('Failed to fetch SBOM:', err);
      setComponents([]);
      setError(err?.message || t('pages.sbomBrowser.load_failed'));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    if (clientLoading) return;
    if (clientId == null) {
      setComponents([]);
      setLoading(false);
      return;
    }
    fetchSBOM(clientId);
  }, [clientId, clientLoading, fetchSBOM]);

  const exportSBOM = async (format) => {
    if (clientId == null) return;
    try {
      const r = await apiFetch(withClientId(`/api/sbom/export?format=${format}`, clientId));
      if (!r.ok) throw new Error(`Export failed (${r.status})`);
      const blob = await r.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `sbom.${format}`;
      link.click();
    } catch (err) {
      console.error('Failed to export SBOM:', err);
      setError(t('pages.sbomBrowser.export_failed'));
    }
  };

  const ecosystems = useMemo(
    () => [...new Set(components.map((c) => c.ecosystem).filter(Boolean))].sort(),
    [components],
  );

  const categoryFilteredComponents = useMemo(() => components
    .filter((comp) => {
      const vulns = comp.vulnerabilities || [];
      if (filter === 'vulnerable') return vulns.length > 0;
      if (filter === 'high_severity') return comp.outdated === true;
      if (filter === 'direct') return comp.type === 'direct';
      if (filter === 'transitive') return comp.type === 'transitive';
      return true;
    })
    .filter((comp) => {
      if (ecosystemFilter === 'all') return true;
      return comp.ecosystem === ecosystemFilter;
    }), [components, filter, ecosystemFilter]);

  const listFindings = useMemo(() => categoryFilteredComponents.map((c) => ({
    id: String(c.id || c.purl || c.name),
    severity: (c.vulnerabilities?.length || 0) > 0 ? 'high' : 'info',
    title: c.name || c.purl,
    type: c.type || 'component',
    description: c.version || '',
    resource: c.ecosystem || '',
  })), [categoryFilteredComponents])

  const {
    exportCsv,
    filteredFindings,
    searchQuery,
    setSearchQuery,
  } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-sbom-components',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const visibleComponents = useMemo(() => {
    if (!searchQuery.trim()) return categoryFilteredComponents
    const ids = new Set(filteredFindings.map((f) => String(f.id)))
    return categoryFilteredComponents.filter((c) => ids.has(String(c.id || c.purl || c.name)))
  }, [categoryFilteredComponents, filteredFindings, searchQuery])

  const stats = useMemo(() => ({
    total: components.length,
    direct: components.filter((c) => c.type === 'direct').length,
    transitive: components.filter((c) => c.type === 'transitive').length,
    vulnerable: components.filter((c) => (c.vulnerabilities || []).length > 0).length,
    highSeverity: components.filter((c) => c.outdated === true).length,
    ecosystems: ecosystems.length,
  }), [components, ecosystems]);

  const riskScore = stats.total > 0
    ? ((stats.vulnerable * 10 + stats.highSeverity * 5) / stats.total).toFixed(1)
    : '0';

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

  const showClientEmpty = !clientLoading && clientId == null;
  const showDataEmpty = !loading && !showClientEmpty && components.length === 0;
  const showFilterEmpty = !loading && !showClientEmpty && components.length > 0 && visibleComponents.length === 0;

  return (
    <PageShell
      title={t('pages.sbomBrowser.title')}
      subtitle={t('pages.sbomBrowser.subtitle')}
      icon={<Package />}
      actions={clientId != null && (
        <ShellScanActions
          onRefresh={() => fetchSBOM(clientId)}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="space-y-6">
        {error && (
          <div className="rounded-xl border border-rose-500/30 bg-rose-950/30 px-4 py-3 text-sm text-rose-200">
            {error}
          </div>
        )}

        {showClientEmpty ? (
          <EmptyState
            icon={<Database className="w-8 h-8 text-[var(--text-disabled)]" />}
            title={t('pages.sbomBrowser.no_client_title')}
            description={t('pages.sbomBrowser.no_client')}
          />
        ) : loading && components.length === 0 ? (
          <SkeletonWidgetGrid count={5} />
        ) : (
          <>
            <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
              <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-gray-400">{t('pages.sbomBrowser.total_components')}</span>
                  <Package className="w-4 h-4 text-cyan-400" />
                </div>
                <div className="text-2xl font-bold text-white">{stats.total}</div>
                <div className="text-xs text-gray-500 mt-1">
                  {t('pages.sbomBrowser.direct_transitive', { direct: stats.direct, transitive: stats.transitive })}
                </div>
              </div>

              <div className="bg-red-500/10 backdrop-blur-md border border-red-500/30 rounded-xl p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-red-400">{t('pages.sbomBrowser.vulnerable')}</span>
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                </div>
                <div className="text-2xl font-bold text-red-400">{stats.vulnerable}</div>
              </div>

              <div className="bg-orange-500/10 backdrop-blur-md border border-orange-500/30 rounded-xl p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-orange-400">{t('pages.sbomBrowser.high_severity')}</span>
                  <AlertTriangle className="w-4 h-4 text-orange-400" />
                </div>
                <div className="text-2xl font-bold text-orange-400">{stats.highSeverity}</div>
                <div className="text-[10px] text-orange-300/60 mt-1">{t('pages.sbomBrowser.high_severity_hint')}</div>
              </div>

              <div className="bg-purple-500/10 backdrop-blur-md border border-purple-500/30 rounded-xl p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-purple-400">{t('pages.sbomBrowser.ecosystems')}</span>
                  <Package className="w-4 h-4 text-purple-400" />
                </div>
                <div className="text-2xl font-bold text-purple-400">{stats.ecosystems}</div>
              </div>

              <div className="bg-cyan-500/10 backdrop-blur-md border border-cyan-500/30 rounded-xl p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-cyan-400">{t('pages.sbomBrowser.risk_score')}</span>
                  <Shield className="w-4 h-4 text-cyan-400" />
                </div>
                <div className="text-2xl font-bold text-cyan-400">{riskScore}</div>
                <div className="text-[10px] text-cyan-300/60 mt-1">{t('pages.sbomBrowser.risk_score_hint')}</div>
              </div>
            </div>

            <WeissmanListToolbar
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              searchPlaceholder={t('pages.sbomBrowser.search_placeholder')}
              resultCount={visibleComponents.length}
              totalCount={categoryFilteredComponents.length}
            >
              <div className="flex items-center gap-2 bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-lg p-1 flex-wrap">
                {FILTER_KEYS.map((f) => (
                  <button
                    key={f}
                    type="button"
                    onClick={() => setFilter(f)}
                    className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                      filter === f
                        ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                        : 'text-gray-400 hover:text-white hover:bg-[var(--row-hover-bg)]'
                    }`}
                  >
                    {t(`pages.sbomBrowser.filter_${f}`)}
                  </button>
                ))}
              </div>
              {ecosystems.length > 0 && (
                <select
                  value={ecosystemFilter}
                  onChange={(e) => setEcosystemFilter(e.target.value)}
                  className="px-3 py-2 bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-lg text-sm text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
                >
                  <option value="all">{t('pages.sbomBrowser.all_ecosystems')}</option>
                  {ecosystems.map((eco) => (
                    <option key={eco} value={eco}>{eco}</option>
                  ))}
                </select>
              )}
            </WeissmanListToolbar>

            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => exportSBOM('spdx')}
                disabled={components.length === 0}
                className="flex items-center gap-2 px-3 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-sm font-medium hover:bg-cyan-500/30 transition-colors disabled:opacity-40"
              >
                <Download className="w-4 h-4" />
                {t('pages.sbomBrowser.export_spdx')}
              </button>
              <button
                type="button"
                onClick={() => exportSBOM('cyclonedx')}
                disabled={components.length === 0}
                className="flex items-center gap-2 px-3 py-2 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded-lg text-sm font-medium hover:bg-purple-500/30 transition-colors disabled:opacity-40"
              >
                <Download className="w-4 h-4" />
                {t('pages.sbomBrowser.export_cyclonedx')}
              </button>
            </div>
          </>
        )}

        {!showClientEmpty && (
          <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl overflow-hidden">
            <div className="p-4 border-b border-[var(--border-default)]">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Package className="w-4 h-4 text-cyan-400" />
                {t('pages.sbomBrowser.components_heading', { count: visibleComponents.length })}
              </h3>
            </div>

            {showDataEmpty ? (
              <EmptyState
                icon={<Package className="w-8 h-8 text-[var(--text-disabled)]" />}
                title={t('pages.sbomBrowser.empty_data_title')}
                description={t('pages.sbomBrowser.empty_data')}
              />
            ) : showFilterEmpty ? (
              <EmptyState
                icon="search"
                title={t('weissmanFindings.filtered_title')}
                description={t('weissmanFindings.filtered_body')}
              />
            ) : (
              <div className="divide-y divide-white/5 max-h-[600px] overflow-y-auto">
                {visibleComponents.map((component) => {
                  const vulns = component.vulnerabilities || [];
                  return (
                    <div
                      key={component.id}
                      className="p-4 hover:bg-[var(--row-hover-bg)] transition-colors"
                    >
                      <div className="flex items-start gap-3">
                        <div className="p-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg shrink-0">
                          <Package className="w-4 h-4" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <h4 className="text-sm font-semibold text-white font-mono">
                              {component.name || component.package_name}
                            </h4>
                            <span className="text-xs text-gray-400 font-mono">
                              v{component.version || component.version_spec || 'unknown'}
                            </span>
                            {component.type && (
                              <span
                                className={`px-2 py-0.5 rounded text-xs font-medium ${
                                  component.type === 'direct'
                                    ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                                    : 'bg-gray-500/20 text-gray-400 border border-gray-500/30'
                                }`}
                              >
                                {t(`pages.sbomBrowser.type_${component.type}`, component.type)}
                              </span>
                            )}
                            {component.outdated && (
                              <span className="px-2 py-0.5 bg-orange-500/20 text-orange-400 border border-orange-500/30 rounded text-xs font-medium">
                                {t('pages.sbomBrowser.high_severity_badge')}
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-3 mt-1 text-xs text-gray-500 flex-wrap">
                            {component.ecosystem && (
                              <span className="px-2 py-0.5 rounded border border-purple-500/20 text-purple-300/80 bg-purple-500/10">
                                {component.ecosystem}
                              </span>
                            )}
                            {component.source && (
                              <span className="font-mono text-[var(--text-muted)]">{component.source}</span>
                            )}
                            {component.created_at && (
                              <span>{t('pages.sbomBrowser.ingested_at', { date: new Date(component.created_at).toLocaleDateString() })}</span>
                            )}
                          </div>

                          {vulns.length > 0 && (
                            <div className="mt-3 p-3 bg-red-500/5 border border-red-500/20 rounded-lg">
                              <div className="flex items-center gap-2 mb-2">
                                <AlertTriangle className="w-4 h-4 text-red-400" />
                                <span className="text-sm font-medium text-red-400">
                                  {t('pages.sbomBrowser.known_vulnerabilities', { count: vulns.length })}
                                </span>
                              </div>
                              <div className="space-y-2">
                                {vulns.slice(0, 3).map((vuln, idx) => {
                                  const href = cveHref(vuln);
                                  return (
                                    <div
                                      key={vulnKey(vuln, idx)}
                                      className="flex items-center justify-between gap-2"
                                    >
                                      <div className="flex items-center gap-2 min-w-0">
                                        <span className="text-xs font-mono text-gray-400 shrink-0">
                                          {cveLabel(vuln)}
                                        </span>
                                        <span
                                          className={`px-2 py-0.5 rounded text-xs font-medium shrink-0 ${getSeverityColor(vuln.severity)}`}
                                        >
                                          {vuln.severity}
                                        </span>
                                        {vuln.title && (
                                          <span className="text-xs text-gray-500 truncate">
                                            {vuln.title}
                                          </span>
                                        )}
                                      </div>
                                      {href && (
                                        <a
                                          href={href}
                                          target="_blank"
                                          rel="noopener noreferrer"
                                          className="text-cyan-400 hover:text-cyan-300 text-xs shrink-0"
                                        >
                                          NVD
                                        </a>
                                      )}
                                    </div>
                                  );
                                })}
                                {vulns.length > 3 && (
                                  <div className="text-xs text-gray-500">
                                    {t('pages.sbomBrowser.more_vulnerabilities', { count: vulns.length - 3 })}
                                  </div>
                                )}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {stats.vulnerable > 0 && !showClientEmpty && (
          <div className="bg-red-500/10 backdrop-blur-md border border-red-500/30 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              <h3 className="text-sm font-semibold text-white">{t('pages.sbomBrowser.alert_title')}</h3>
            </div>
            <p className="text-sm text-gray-300">
              {t('pages.sbomBrowser.alert_body', { count: stats.vulnerable })}
            </p>
          </div>
        )}
      </div>
    </PageShell>
  );
}
