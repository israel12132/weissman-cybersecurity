import { useState, useEffect } from 'react';
import { Smartphone, Shield, AlertTriangle, CheckCircle, Search, Filter } from 'lucide-react';
import PageShell from '../components/PageShell';

/**
 * MobileSecurity - Mobile & App Security Analysis Dashboard
 *
 * Covers:
 * - iOS/Android vulnerability scanning
 * - Mobile app binary analysis
 * - API security testing
 * - Certificate pinning bypass
 * - Root/Jailbreak detection bypass
 * - Deep link hijacking
 */
export default function MobileSecurity() {
  const [apps, setApps] = useState([]);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all'); // all, ios, android
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    fetchMobileApps();
  }, []);

  const fetchMobileApps = async () => {
    try {
      const response = await fetch('/api/mobile-security/apps', {
        credentials: 'include',
      });
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
  };

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
    <PageShell title="Mobile & App Security" icon={<Smartphone />}>
      <div className="space-y-6">
        {/* Header Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Total Apps</span>
              <Smartphone className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{apps.length}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">iOS Apps</span>
              <Shield className="w-4 h-4 text-gray-400" />
            </div>
            <div className="text-2xl font-bold text-white">
              {apps.filter((a) => a.platform === 'ios').length}
            </div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Android Apps</span>
              <Shield className="w-4 h-4 text-green-400" />
            </div>
            <div className="text-2xl font-bold text-white">
              {apps.filter((a) => a.platform === 'android').length}
            </div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Vulnerabilities</span>
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
              placeholder="Search apps by name or package ID..."
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
                {f === 'all' ? 'All' : f === 'ios' ? 'iOS' : 'Android'}
              </button>
            ))}
          </div>
        </div>

        {/* Apps List */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/10">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Filter className="w-4 h-4 text-cyan-400" />
              Mobile Applications
            </h3>
          </div>

          {loading ? (
            <div className="p-8 text-center text-gray-500">
              <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
              Loading mobile apps...
            </div>
          ) : filteredApps.length === 0 ? (
            <div className="p-8 text-center text-gray-500">
              No mobile apps found. Upload an APK/IPA file to start analysis.
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
                          {app.platform === 'ios' ? 'iOS' : 'Android'}
                        </div>
                        <h4 className="text-sm font-semibold text-white">{app.name}</h4>
                        <span className="text-xs text-gray-500">{app.version}</span>
                      </div>

                      <div className="flex items-center gap-4 text-xs text-gray-400 mb-2">
                        <span>Package: {app.package_id}</span>
                        <span>•</span>
                        <span>Size: {app.size_mb} MB</span>
                        <span>•</span>
                        <span>Last scanned: {app.last_scan || 'Never'}</span>
                      </div>

                      {/* Findings Summary */}
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
                                {count} {severity}
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      <button className="px-3 py-1.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-medium hover:bg-cyan-500/30 transition-colors">
                        Scan Now
                      </button>
                      <button className="px-3 py-1.5 bg-white/5 text-gray-300 border border-white/10 rounded-lg text-xs font-medium hover:bg-white/10 transition-colors">
                        View Details
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
              <h3 className="text-sm font-semibold text-white mb-1">Upload Mobile App</h3>
              <p className="text-xs text-gray-400">
                Upload an APK (Android) or IPA (iOS) file for security analysis
              </p>
            </div>
            <button className="px-4 py-2 bg-cyan-500 text-white rounded-lg text-sm font-medium hover:bg-cyan-600 transition-colors">
              Choose File
            </button>
          </div>
        </div>
      </div>
    </PageShell>
  );
}
