import { useState, useEffect } from 'react';
import { Package, Search, AlertTriangle, Shield, Filter, Download, FileText, ExternalLink } from 'lucide-react';
import PageShell from '../components/PageShell';
import { api } from '../utils/apiFetch';

/**
 * SBOMBrowser - Software Bill of Materials analysis and vulnerability tracking
 *
 * Features:
 * - Component inventory (direct + transitive dependencies)
 * - License compliance checking
 * - Known vulnerability mapping (CVE)
 * - Outdated package detection
 * - Supply chain risk scoring
 * - SBOM export (SPDX, CycloneDX)
 * - Dependency graph visualization
 */
export default function SBOMBrowser() {
  const [components, setComponents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filter, setFilter] = useState('all'); // all, vulnerable, outdated, direct, transitive
  const [licenseFilter, setLicenseFilter] = useState('all');

  useEffect(() => {
    fetchSBOM();
  }, []);

  const fetchSBOM = async () => {
    try {
      setLoading(true);
      const data = await api.get('/api/sbom/components');
      setComponents(data.components || []);
    } catch (error) {
      console.error('Failed to fetch SBOM:', error);
    } finally {
      setLoading(false);
    }
  };

  const exportSBOM = async (format) => {
    try {
      const blob = await api.get(`/api/sbom/export?format=${format}`, {
        responseType: 'blob',
      });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `sbom.${format}`;
      link.click();
    } catch (error) {
      console.error('Failed to export SBOM:', error);
    }
  };

  const filteredComponents = components
    .filter((comp) => {
      // Search filter
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        return (
          comp.name.toLowerCase().includes(term) ||
          comp.version.toLowerCase().includes(term) ||
          comp.license?.toLowerCase().includes(term)
        );
      }
      return true;
    })
    .filter((comp) => {
      // Type filter
      if (filter === 'vulnerable') return comp.vulnerabilities && comp.vulnerabilities.length > 0;
      if (filter === 'outdated') return comp.outdated;
      if (filter === 'direct') return comp.type === 'direct';
      if (filter === 'transitive') return comp.type === 'transitive';
      return true;
    })
    .filter((comp) => {
      // License filter
      if (licenseFilter === 'all') return true;
      return comp.license === licenseFilter;
    });

  const stats = {
    total: components.length,
    direct: components.filter((c) => c.type === 'direct').length,
    transitive: components.filter((c) => c.type === 'transitive').length,
    vulnerable: components.filter((c) => c.vulnerabilities && c.vulnerabilities.length > 0).length,
    outdated: components.filter((c) => c.outdated).length,
    licenses: [...new Set(components.map((c) => c.license).filter(Boolean))],
  };

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

  const getLicenseColor = (license) => {
    const permissive = ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'ISC'];
    const copyleft = ['GPL', 'LGPL', 'AGPL'];

    if (permissive.some((l) => license?.includes(l))) {
      return 'text-green-400 bg-green-500/10 border-green-500/30';
    }
    if (copyleft.some((l) => license?.includes(l))) {
      return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
    }
    return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
  };

  return (
    <PageShell title="SBOM Browser" icon={<Package />}>
      <div className="space-y-6">
        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Total Components</span>
              <Package className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{stats.total}</div>
            <div className="text-xs text-gray-500 mt-1">
              {stats.direct} direct, {stats.transitive} transitive
            </div>
          </div>

          <div className="bg-red-500/10 backdrop-blur-md border border-red-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-red-400">Vulnerable</span>
              <AlertTriangle className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-red-400">{stats.vulnerable}</div>
          </div>

          <div className="bg-yellow-500/10 backdrop-blur-md border border-yellow-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-yellow-400">Outdated</span>
              <Package className="w-4 h-4 text-yellow-400" />
            </div>
            <div className="text-2xl font-bold text-yellow-400">{stats.outdated}</div>
          </div>

          <div className="bg-purple-500/10 backdrop-blur-md border border-purple-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-purple-400">Licenses</span>
              <FileText className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-purple-400">{stats.licenses.length}</div>
          </div>

          <div className="bg-cyan-500/10 backdrop-blur-md border border-cyan-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-cyan-400">Risk Score</span>
              <Shield className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-cyan-400">
              {components.length > 0
                ? (
                    (stats.vulnerable * 10 + stats.outdated * 5) /
                    components.length
                  ).toFixed(1)
                : 0}
            </div>
          </div>
        </div>

        {/* Search and Filters */}
        <div className="flex items-center gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by name, version, or license..."
              className="w-full pl-10 pr-4 py-2 bg-black/40 backdrop-blur-md border border-white/10 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            />
          </div>

          <div className="flex items-center gap-2 bg-black/40 backdrop-blur-md border border-white/10 rounded-lg p-1">
            {['all', 'vulnerable', 'outdated', 'direct', 'transitive'].map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                  filter === f
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                    : 'text-gray-400 hover:text-white hover:bg-white/5'
                }`}
              >
                {f.charAt(0).toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>

          <select
            value={licenseFilter}
            onChange={(e) => setLicenseFilter(e.target.value)}
            className="px-3 py-2 bg-black/40 backdrop-blur-md border border-white/10 rounded-lg text-sm text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          >
            <option value="all">All Licenses</option>
            {stats.licenses.map((license) => (
              <option key={license} value={license}>
                {license}
              </option>
            ))}
          </select>
        </div>

        {/* Export Buttons */}
        <div className="flex justify-end gap-2">
          <button
            onClick={() => exportSBOM('spdx')}
            className="flex items-center gap-2 px-3 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-sm font-medium hover:bg-cyan-500/30 transition-colors"
          >
            <Download className="w-4 h-4" />
            Export SPDX
          </button>
          <button
            onClick={() => exportSBOM('cyclonedx')}
            className="flex items-center gap-2 px-3 py-2 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded-lg text-sm font-medium hover:bg-purple-500/30 transition-colors"
          >
            <Download className="w-4 h-4" />
            Export CycloneDX
          </button>
        </div>

        {/* Components List */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/10">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Package className="w-4 h-4 text-cyan-400" />
              Components ({filteredComponents.length})
            </h3>
          </div>

          {loading ? (
            <div className="p-8 text-center text-gray-500">
              <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
              Loading SBOM...
            </div>
          ) : filteredComponents.length === 0 ? (
            <div className="p-8 text-center text-gray-500">
              No components found matching your filters.
            </div>
          ) : (
            <div className="divide-y divide-white/5 max-h-[600px] overflow-y-auto">
              {filteredComponents.map((component) => (
                <div
                  key={component.id}
                  className="p-4 hover:bg-white/5 transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <div className="p-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg">
                          <Package className="w-4 h-4" />
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <h4 className="text-sm font-semibold text-white font-mono">
                              {component.name}
                            </h4>
                            <span className="text-xs text-gray-400 font-mono">
                              v{component.version}
                            </span>
                            <span
                              className={`px-2 py-1 rounded text-xs font-medium ${
                                component.type === 'direct'
                                  ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                                  : 'bg-gray-500/20 text-gray-400 border border-gray-500/30'
                              }`}
                            >
                              {component.type}
                            </span>
                            {component.outdated && (
                              <span className="px-2 py-1 bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 rounded text-xs font-medium">
                                Outdated
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-3 mt-1 text-xs text-gray-500">
                            {component.license && (
                              <span
                                className={`px-2 py-1 rounded border ${getLicenseColor(
                                  component.license
                                )}`}
                              >
                                {component.license}
                              </span>
                            )}
                            {component.latest_version && component.version !== component.latest_version && (
                              <span>Latest: v{component.latest_version}</span>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* Vulnerabilities */}
                      {component.vulnerabilities && component.vulnerabilities.length > 0 && (
                        <div className="mt-3 p-3 bg-red-500/5 border border-red-500/20 rounded-lg">
                          <div className="flex items-center gap-2 mb-2">
                            <AlertTriangle className="w-4 h-4 text-red-400" />
                            <span className="text-sm font-medium text-red-400">
                              {component.vulnerabilities.length} Known Vulnerabilities
                            </span>
                          </div>
                          <div className="space-y-2">
                            {component.vulnerabilities.slice(0, 3).map((vuln) => (
                              <div
                                key={vuln.cve}
                                className="flex items-center justify-between"
                              >
                                <div className="flex items-center gap-2">
                                  <span className="text-xs font-mono text-gray-400">
                                    {vuln.cve}
                                  </span>
                                  <span
                                    className={`px-2 py-0.5 rounded text-xs font-medium ${getSeverityColor(
                                      vuln.severity
                                    )}`}
                                  >
                                    {vuln.severity}
                                  </span>
                                  <span className="text-xs text-gray-500">
                                    {vuln.description}
                                  </span>
                                </div>
                                <a
                                  href={`https://nvd.nist.gov/vuln/detail/${vuln.cve}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-cyan-400 hover:text-cyan-300"
                                >
                                  <ExternalLink className="w-3 h-3" />
                                </a>
                              </div>
                            ))}
                            {component.vulnerabilities.length > 3 && (
                              <div className="text-xs text-gray-500">
                                +{component.vulnerabilities.length - 3} more vulnerabilities
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      {/* Dependencies */}
                      {component.dependencies && component.dependencies.length > 0 && (
                        <div className="mt-2 text-xs text-gray-500">
                          {component.dependencies.length} dependencies
                        </div>
                      )}
                    </div>

                    <button className="px-3 py-1.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-medium hover:bg-cyan-500/30 transition-colors">
                      View Details
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Supply Chain Warning */}
        {stats.vulnerable > 0 && (
          <div className="bg-red-500/10 backdrop-blur-md border border-red-500/30 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              <h3 className="text-sm font-semibold text-white">Supply Chain Risk Alert</h3>
            </div>
            <p className="text-sm text-gray-300">
              {stats.vulnerable} components have known vulnerabilities. Update these packages to
              reduce supply chain risk.
            </p>
          </div>
        )}
      </div>
    </PageShell>
  );
}
