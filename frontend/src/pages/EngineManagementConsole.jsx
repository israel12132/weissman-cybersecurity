import { useState, useEffect } from 'react';
import { Settings, Cpu, Play, Pause, Filter, Search, Clock, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';
import PageShell from './PageShell'
import { api } from '../utils/apiFetch';

/**
 * EngineManagementConsole - Complete control over all 496 engines
 *
 * Features:
 * - Enable/disable individual engines
 * - Configure engine parameters (timeout, concurrency, resources)
 * - Category-based filtering (14 categories)
 * - Bulk operations (enable all, disable all by category)
 * - Real-time status monitoring
 * - Per-engine execution logs
 * - Resource usage metrics
 */
export default function EngineManagementConsole() {
  const [engines, setEngines] = useState([]);
  const [filteredEngines, setFilteredEngines] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all'); // all, enabled, disabled
  const [selectedEngine, setSelectedEngine] = useState(null);
  const [configModal, setConfigModal] = useState(false);

  // Engine categories from enginesRegistry.js
  const categories = [
    'all',
    'web',
    'network',
    'api',
    'auth',
    'crypto',
    'cloud',
    'mobile',
    'iot',
    'containers',
    'supply-chain',
    'ai-ml',
    'blockchain',
    'quantum',
    'misc',
  ];

  useEffect(() => {
    fetchEngines();
  }, []);

  useEffect(() => {
    applyFilters();
  }, [engines, searchTerm, categoryFilter, statusFilter]);

  const fetchEngines = async () => {
    try {
      setLoading(true);
      const data = await api.get('/api/ceo/tenant/engines');
      setEngines(data.engines || []);
    } catch (error) {
      console.error('Failed to fetch engines:', error);
    } finally {
      setLoading(false);
    }
  };

  const applyFilters = () => {
    let filtered = [...engines];

    // Search filter
    if (searchTerm) {
      filtered = filtered.filter(
        (engine) =>
          engine.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
          engine.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
          engine.id.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    // Category filter
    if (categoryFilter !== 'all') {
      filtered = filtered.filter((engine) => engine.category === categoryFilter);
    }

    // Status filter
    if (statusFilter !== 'all') {
      const isEnabled = statusFilter === 'enabled';
      filtered = filtered.filter((engine) => engine.enabled === isEnabled);
    }

    setFilteredEngines(filtered);
  };

  const toggleEngine = async (engineId, currentState) => {
    try {
      await api.patch(`/api/ceo/tenant/engines/${engineId}`, {
        enabled: !currentState,
      });
      // Update local state
      setEngines((prev) =>
        prev.map((e) => (e.id === engineId ? { ...e, enabled: !currentState } : e))
      );
    } catch (error) {
      console.error('Failed to toggle engine:', error);
    }
  };

  const bulkToggleCategory = async (category, enable) => {
    try {
      const engineIds = engines
        .filter((e) => e.category === category)
        .map((e) => e.id);

      await api.patch('/api/ceo/tenant/engines/bulk', {
        engine_ids: engineIds,
        enabled: enable,
      });

      // Update local state
      setEngines((prev) =>
        prev.map((e) =>
          engineIds.includes(e.id) ? { ...e, enabled: enable } : e
        )
      );
    } catch (error) {
      console.error('Failed to bulk toggle:', error);
    }
  };

  const openConfigModal = (engine) => {
    setSelectedEngine(engine);
    setConfigModal(true);
  };

  const saveEngineConfig = async (engineId, config) => {
    try {
      await api.put(`/api/ceo/tenant/engines/${engineId}/config`, config);
      setConfigModal(false);
      fetchEngines(); // Refresh
    } catch (error) {
      console.error('Failed to save config:', error);
    }
  };

  const stats = {
    total: engines.length,
    enabled: engines.filter((e) => e.enabled).length,
    disabled: engines.filter((e) => !e.enabled).length,
    byCategory: categories.slice(1).reduce((acc, cat) => {
      acc[cat] = engines.filter((e) => e.category === cat).length;
      return acc;
    }, {}),
  };

  return (
    <PageShell title="Engine Management Console" icon={<Cpu />}>
      <div className="space-y-6">
        {/* Stats Header */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Total Engines</span>
              <Cpu className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{stats.total}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Enabled</span>
              <CheckCircle className="w-4 h-4 text-green-400" />
            </div>
            <div className="text-2xl font-bold text-green-400">{stats.enabled}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Disabled</span>
              <XCircle className="w-4 h-4 text-gray-400" />
            </div>
            <div className="text-2xl font-bold text-gray-400">{stats.disabled}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Categories</span>
              <Filter className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-white">{categories.length - 1}</div>
          </div>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3">
          {/* Search */}
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search engines by name, ID, or description..."
              className="w-full pl-10 pr-4 py-2 bg-black/40 backdrop-blur-md border border-white/10 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            />
          </div>

          {/* Category Filter */}
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="px-3 py-2 bg-black/40 backdrop-blur-md border border-white/10 rounded-lg text-sm text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          >
            {categories.map((cat) => (
              <option key={cat} value={cat}>
                {cat === 'all' ? 'All Categories' : cat.toUpperCase()}
              </option>
            ))}
          </select>

          {/* Status Filter */}
          <div className="flex items-center gap-2 bg-black/40 backdrop-blur-md border border-white/10 rounded-lg p-1">
            {['all', 'enabled', 'disabled'].map((status) => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                  statusFilter === status
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                    : 'text-gray-400 hover:text-white hover:bg-white/5'
                }`}
              >
                {status === 'all' ? 'All' : status === 'enabled' ? 'Enabled' : 'Disabled'}
              </button>
            ))}
          </div>
        </div>

        {/* Bulk Actions */}
        {categoryFilter !== 'all' && (
          <div className="bg-gradient-to-r from-purple-500/10 to-blue-500/10 backdrop-blur-md border border-purple-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-white mb-1">
                  Bulk Actions for {categoryFilter.toUpperCase()}
                </h3>
                <p className="text-xs text-gray-400">
                  {stats.byCategory[categoryFilter]} engines in this category
                </p>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => bulkToggleCategory(categoryFilter, true)}
                  className="flex items-center gap-2 px-3 py-1.5 bg-green-500/20 text-green-400 border border-green-500/30 rounded-lg text-xs font-medium hover:bg-green-500/30 transition-colors"
                >
                  <Play className="w-3 h-3" />
                  Enable All
                </button>
                <button
                  onClick={() => bulkToggleCategory(categoryFilter, false)}
                  className="flex items-center gap-2 px-3 py-1.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg text-xs font-medium hover:bg-red-500/30 transition-colors"
                >
                  <Pause className="w-3 h-3" />
                  Disable All
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Engines List */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/10">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              {filteredEngines.length} Engines
              {searchTerm || categoryFilter !== 'all' || statusFilter !== 'all'
                ? ' (filtered)'
                : ''}
            </h3>
          </div>

          {loading ? (
            <div className="p-8 text-center text-gray-500">
              <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
              Loading engines...
            </div>
          ) : filteredEngines.length === 0 ? (
            <div className="p-8 text-center text-gray-500">
              No engines found matching your filters.
            </div>
          ) : (
            <div className="divide-y divide-white/5 max-h-[600px] overflow-y-auto">
              {filteredEngines.map((engine) => (
                <div
                  key={engine.id}
                  className="p-4 hover:bg-white/5 transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        {/* Status Toggle */}
                        <button
                          onClick={() => toggleEngine(engine.id, engine.enabled)}
                          className={`p-1.5 rounded-lg border transition-colors ${
                            engine.enabled
                              ? 'bg-green-500/20 text-green-400 border-green-500/30 hover:bg-green-500/30'
                              : 'bg-gray-500/20 text-gray-400 border-gray-500/30 hover:bg-gray-500/30'
                          }`}
                        >
                          {engine.enabled ? (
                            <Play className="w-3 h-3" />
                          ) : (
                            <Pause className="w-3 h-3" />
                          )}
                        </button>

                        {/* Engine Name */}
                        <h4 className="text-sm font-semibold text-white">
                          {engine.name}
                        </h4>

                        {/* Category Badge */}
                        <span className="px-2 py-1 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded-md text-xs font-medium">
                          {engine.category}
                        </span>

                        {/* Status Badge */}
                        <span
                          className={`px-2 py-1 rounded-md text-xs font-medium ${
                            engine.enabled
                              ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                              : 'bg-gray-500/20 text-gray-400 border border-gray-500/30'
                          }`}
                        >
                          {engine.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                      </div>

                      {/* Description */}
                      <p className="text-xs text-gray-400 mb-2">
                        {engine.description || 'No description available'}
                      </p>

                      {/* Engine Details */}
                      <div className="flex items-center gap-4 text-xs text-gray-500">
                        <span>ID: {engine.id}</span>
                        {engine.timeout && (
                          <>
                            <span>•</span>
                            <span className="flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              Timeout: {engine.timeout}s
                            </span>
                          </>
                        )}
                        {engine.concurrency && (
                          <>
                            <span>•</span>
                            <span>Concurrency: {engine.concurrency}</span>
                          </>
                        )}
                        {engine.last_run && (
                          <>
                            <span>•</span>
                            <span>Last run: {engine.last_run}</span>
                          </>
                        )}
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => openConfigModal(engine)}
                        className="px-3 py-1.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-medium hover:bg-cyan-500/30 transition-colors"
                      >
                        <Settings className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Config Modal */}
      {configModal && selectedEngine && (
        <EngineConfigModal
          engine={selectedEngine}
          onClose={() => setConfigModal(false)}
          onSave={(config) => saveEngineConfig(selectedEngine.id, config)}
        />
      )}
    </PageShell>
  );
}

/**
 * Engine Configuration Modal
 */
function EngineConfigModal({ engine, onClose, onSave }) {
  const [config, setConfig] = useState({
    timeout: engine.timeout || 30,
    concurrency: engine.concurrency || 1,
    max_retries: engine.max_retries || 3,
    resource_limit_cpu: engine.resource_limit_cpu || 100,
    resource_limit_memory: engine.resource_limit_memory || 512,
  });

  const handleSave = () => {
    onSave(config);
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-white/10 rounded-xl max-w-lg w-full p-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h3 className="text-lg font-bold text-white">{engine.name}</h3>
            <p className="text-xs text-gray-400">Engine Configuration</p>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors"
          >
            <XCircle className="w-5 h-5" />
          </button>
        </div>

        <div className="space-y-4">
          {/* Timeout */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Timeout (seconds)
            </label>
            <input
              type="number"
              value={config.timeout}
              onChange={(e) =>
                setConfig({ ...config, timeout: parseInt(e.target.value) })
              }
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            />
          </div>

          {/* Concurrency */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Concurrency
            </label>
            <input
              type="number"
              value={config.concurrency}
              onChange={(e) =>
                setConfig({ ...config, concurrency: parseInt(e.target.value) })
              }
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            />
          </div>

          {/* Max Retries */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Max Retries
            </label>
            <input
              type="number"
              value={config.max_retries}
              onChange={(e) =>
                setConfig({ ...config, max_retries: parseInt(e.target.value) })
              }
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            />
          </div>

          {/* CPU Limit */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              CPU Limit (%)
            </label>
            <input
              type="number"
              value={config.resource_limit_cpu}
              onChange={(e) =>
                setConfig({
                  ...config,
                  resource_limit_cpu: parseInt(e.target.value),
                })
              }
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            />
          </div>

          {/* Memory Limit */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Memory Limit (MB)
            </label>
            <input
              type="number"
              value={config.resource_limit_memory}
              onChange={(e) =>
                setConfig({
                  ...config,
                  resource_limit_memory: parseInt(e.target.value),
                })
              }
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            />
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-3 mt-6">
          <button
            onClick={onClose}
            className="flex-1 px-4 py-2 bg-gray-500/20 text-gray-300 border border-gray-500/30 rounded-lg text-sm font-medium hover:bg-gray-500/30 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            className="flex-1 px-4 py-2 bg-cyan-500 text-white rounded-lg text-sm font-medium hover:bg-cyan-600 transition-colors"
          >
            Save Configuration
          </button>
        </div>
      </div>
    </div>
  );
}
