import { useState, useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Settings, Cpu, Play, Pause, Filter, Search, Clock, CheckCircle, XCircle, Download } from 'lucide-react';
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import { SkeletonTable, SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { api } from '../utils/apiFetch';
import { ENGINES_BY_ID } from '../lib/enginesRegistry';

const NS = 'pages.engineManagementConsole';

function exportEnginesCsv(engines) {
  const header = ['id', 'name', 'category', 'enabled', 'description'];
  const rows = engines.map((e) => [
    e.id,
    (e.name || '').replace(/"/g, '""'),
    e.category ?? '',
    e.enabled ? 'yes' : 'no',
    (e.description || '').replace(/"/g, '""'),
  ]);
  const csv = [header.join(','), ...rows.map((r) => r.map((c) => `"${c}"`).join(','))].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `engines-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

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
  const { t } = useTranslation();
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

  const mapSnapshotEngine = (e) => ({
    id: e.id,
    name: e.label || e.id,
    enabled: !!e.tenant_policy_includes,
    category: ENGINES_BY_ID[e.id]?.group || 'misc',
    description: ENGINES_BY_ID[e.id]?.description,
  });

  const applyActiveEngines = (activeEngines) => {
    const activeSet = new Set(activeEngines || []);
    setEngines((prev) => prev.map((e) => ({ ...e, enabled: activeSet.has(e.id) })));
  };

  const fetchEngines = async () => {
    try {
      setLoading(true);
      const data = await api.get('/api/ceo/god-mode/snapshot');
      const core = data?.engine_matrix?.core_engines || [];
      setEngines(core.map(mapSnapshotEngine));
    } catch (error) {
      console.error('Failed to fetch engines:', error);
      try {
        const health = await api.get('/api/health');
        const activeSet = new Set(health.active_engines || []);
        setEngines([...activeSet].map((id) => ({
          id,
          name: ENGINES_BY_ID[id]?.label || id,
          enabled: true,
          category: ENGINES_BY_ID[id]?.group || 'misc',
          description: ENGINES_BY_ID[id]?.description,
        })));
      } catch (fallbackErr) {
        console.error('Failed to fetch active engines:', fallbackErr);
      }
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
      const data = await api.put('/api/ceo/tenant/engines', {
        engine_id: engineId,
        enabled: !currentState,
      });
      if (Array.isArray(data.active_engines)) {
        applyActiveEngines(data.active_engines);
      } else {
        setEngines((prev) =>
          prev.map((e) => (e.id === engineId ? { ...e, enabled: !currentState } : e))
        );
      }
    } catch (error) {
      console.error('Failed to toggle engine:', error);
    }
  };

  const bulkToggleCategory = async (category, enable) => {
    try {
      const engineIds = engines
        .filter((e) => e.category === category)
        .map((e) => e.id);

      let lastActive = null;
      for (const engineId of engineIds) {
        const data = await api.put('/api/ceo/tenant/engines', {
          engine_id: engineId,
          enabled: enable,
        });
        if (Array.isArray(data.active_engines)) {
          lastActive = data.active_engines;
        }
      }

      if (lastActive) {
        applyActiveEngines(lastActive);
      }
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
      await api.put('/api/system/config', {
        extra: {
          [`engine_config_${engineId}`]: config,
        },
      });
      setConfigModal(false);
      fetchEngines();
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

  const isFiltered = searchTerm || categoryFilter !== 'all' || statusFilter !== 'all';

  const listFindings = useMemo(() => filteredEngines.map((e) => ({
    id: e.id,
    severity: e.enabled ? 'info' : 'low',
    title: e.name || e.id,
    type: e.category || 'engine',
    description: e.description || '',
  })), [filteredEngines])

  const { exportCsv, filteredFindings } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-engines',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description}`,
  })

  return (
    <PageShell
      title={t(`${NS}.title`)}
      icon={<Cpu />}
      actions={(
        <ShellScanActions
          onRefresh={fetchEngines}
          onExport={() => exportEnginesCsv(filteredEngines)}
          refreshLoading={loading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        {loading ? (
          <>
            <SkeletonWidgetGrid count={4} />
            <SkeletonTable rows={10} cols={4} />
          </>
        ) : (
        <>
        {/* Stats Header */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">
                {t('pages.engineManagementConsole.total_engines')}
              </span>
              <Cpu className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{stats.total}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">
                {t('pages.engineManagementConsole.enabled')}
              </span>
              <CheckCircle className="w-4 h-4 text-green-400" />
            </div>
            <div className="text-2xl font-bold text-green-400">{stats.enabled}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">
                {t('pages.engineManagementConsole.disabled')}
              </span>
              <XCircle className="w-4 h-4 text-gray-400" />
            </div>
            <div className="text-2xl font-bold text-gray-400">{stats.disabled}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">
                {t('pages.engineManagementConsole.categories')}
              </span>
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
              placeholder={t('pages.engineManagementConsole.search_placeholder')}
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
                {cat === 'all'
                  ? t('pages.engineManagementConsole.all_categories')
                  : cat.toUpperCase()}
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
                {status === 'all'
                  ? t('common.all')
                  : status === 'enabled'
                    ? t('pages.engineManagementConsole.enabled')
                    : t('pages.engineManagementConsole.disabled')}
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
                  {t('pages.engineManagementConsole.bulk_actions', {
                    category: categoryFilter.toUpperCase(),
                  })}
                </h3>
                <p className="text-xs text-gray-400">
                  {t('pages.engineManagementConsole.engines_in_category', {
                    count: stats.byCategory[categoryFilter],
                  })}
                </p>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => bulkToggleCategory(categoryFilter, true)}
                  className="flex items-center gap-2 px-3 py-1.5 bg-green-500/20 text-green-400 border border-green-500/30 rounded-lg text-xs font-medium hover:bg-green-500/30 transition-colors"
                >
                  <Play className="w-3 h-3" />
                  {t('pages.engineManagementConsole.enable_all')}
                </button>
                <button
                  onClick={() => bulkToggleCategory(categoryFilter, false)}
                  className="flex items-center gap-2 px-3 py-1.5 bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg text-xs font-medium hover:bg-red-500/30 transition-colors"
                >
                  <Pause className="w-3 h-3" />
                  {t('pages.engineManagementConsole.disable_all')}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Engines List */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/10 flex items-center justify-between gap-3">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              {t(`${NS}.engines_heading`, {
                count: filteredEngines.length,
              })}
              {isFiltered ? t(`${NS}.filtered`) : ''}
            </h3>
            <button
              type="button"
              onClick={() => exportEnginesCsv(filteredEngines)}
              disabled={filteredEngines.length === 0}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-cyan-500/30 text-xs font-mono text-cyan-300/80 hover:bg-cyan-500/10 disabled:opacity-40"
            >
              <Download className="w-3.5 h-3.5" />
              {t(`${NS}.export_csv`)}
            </button>
          </div>

          {filteredEngines.length === 0 ? (
            <div className="p-8 text-center text-gray-500">
              {t('pages.engineManagementConsole.empty')}
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
                          {engine.enabled
                            ? t('pages.engineManagementConsole.enabled')
                            : t('pages.engineManagementConsole.disabled')}
                        </span>
                      </div>

                      {/* Description */}
                      <p className="text-xs text-gray-400 mb-2">
                        {engine.description || t('pages.engineManagementConsole.no_description')}
                      </p>

                      {/* Engine Details */}
                      <div className="flex items-center gap-4 text-xs text-gray-500">
                        <span>
                          {t('pages.engineManagementConsole.id_detail', { id: engine.id })}
                        </span>
                        {engine.timeout && (
                          <>
                            <span>•</span>
                            <span className="flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {t('pages.engineManagementConsole.timeout_detail', {
                                seconds: engine.timeout,
                              })}
                            </span>
                          </>
                        )}
                        {engine.concurrency && (
                          <>
                            <span>•</span>
                            <span>
                              {t('pages.engineManagementConsole.concurrency_detail', {
                                count: engine.concurrency,
                              })}
                            </span>
                          </>
                        )}
                        {engine.last_run && (
                          <>
                            <span>•</span>
                            <span>
                              {t('pages.engineManagementConsole.last_run_detail', {
                                time: engine.last_run,
                              })}
                            </span>
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
        </>
        )}
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
  const { t } = useTranslation();
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
            <p className="text-xs text-gray-400">
              {t('pages.engineManagementConsole.engine_config')}
            </p>
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
              {t('pages.engineManagementConsole.timeout_label')}
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
              {t('pages.engineManagementConsole.concurrency_label')}
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
              {t('pages.engineManagementConsole.max_retries_label')}
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
              {t('pages.engineManagementConsole.cpu_limit_label')}
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
              {t('pages.engineManagementConsole.memory_limit_label')}
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
            {t('common.cancel')}
          </button>
          <button
            onClick={handleSave}
            className="flex-1 px-4 py-2 bg-cyan-500 text-white rounded-lg text-sm font-medium hover:bg-cyan-600 transition-colors"
          >
            {t('pages.engineManagementConsole.save_configuration')}
          </button>
        </div>
      </div>
    </div>
  );
}
