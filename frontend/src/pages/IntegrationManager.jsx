import { useState, useEffect, useMemo, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { Plug, Check, AlertTriangle, Settings, Plus, Trash2, RefreshCw } from 'lucide-react';
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { api } from '../utils/apiFetch';
import { confirmDialog } from '../utils/confirmDialog'
import { useToast } from '../components/ui/Toaster'

/**
 * IntegrationManager - Third-party integrations hub
 *
 * Supported Integrations:
 * - SIEM: Splunk, QRadar, Sentinel, Chronicle
 * - Ticketing: Jira, ServiceNow, GitHub Issues
 * - Communication: Slack, Teams, Discord, PagerDuty
 * - DevOps: GitHub Actions, GitLab CI, Jenkins
 * - Cloud: AWS Security Hub, Azure Defender, GCP SCC
 *
 * Features:
 * - OAuth/API key authentication
 * - Webhook configuration
 * - Connection test (manual — no background sync)
 * - Connection testing
 * - Event filtering
 */
export default function IntegrationManager() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [integrations, setIntegrations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [testingConnection, setTestingConnection] = useState(null);
  const [addModal, setAddModal] = useState(false);

  const availableIntegrations = [
    { id: 'splunk', name: 'Splunk', category: 'SIEM', icon: '📊', color: 'green' },
    { id: 'qradar', name: 'IBM QRadar', category: 'SIEM', icon: '🔷', color: 'blue' },
    { id: 'sentinel', name: 'Microsoft Sentinel', category: 'SIEM', icon: '🛡️', color: 'cyan' },
    { id: 'jira', name: 'Jira', category: 'Ticketing', icon: '📝', color: 'blue' },
    { id: 'servicenow', name: 'ServiceNow', category: 'Ticketing', icon: '🎫', color: 'green' },
    { id: 'slack', name: 'Slack', category: 'Communication', icon: '💬', color: 'purple' },
    { id: 'teams', name: 'Microsoft Teams', category: 'Communication', icon: '👥', color: 'blue' },
    { id: 'pagerduty', name: 'PagerDuty', category: 'Communication', icon: '🚨', color: 'red' },
    { id: 'github', name: 'GitHub', category: 'DevOps', icon: '🐙', color: 'gray' },
    { id: 'gitlab', name: 'GitLab', category: 'DevOps', icon: '🦊', color: 'orange' },
    { id: 'aws', name: 'AWS Security Hub', category: 'Cloud', icon: '☁️', color: 'orange' },
    { id: 'azure', name: 'Azure Defender', category: 'Cloud', icon: '☁️', color: 'blue' },
  ];

  const fetchIntegrations = useCallback(async () => {
    try {
      setLoading(true);
      const data = await api.get('/api/integrations');
      setIntegrations(data.integrations || []);
    } catch (error) {
      console.error('Failed to fetch integrations:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchIntegrations();
  }, [fetchIntegrations]);

  const integrationFindings = useMemo(() => integrations.map((i) => ({
    title: i.name,
    type: i.category || i.type || 'integration',
    severity: i.status === 'connected' ? 'info' : i.status === 'error' ? 'high' : 'medium',
    description: i.description || i.endpoint || i.config?.endpoint || 'No description',
    remediation: i.status ? `Status: ${i.status}` : '',
    resource: i.id,
    component: i.last_test ? `Last test: ${i.last_test}` : '',
  })), [integrations]);

  const {
    filteredFindings,
    counts,
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    exportCsv,
    total,
  } = useFindingsWorkbench(integrationFindings, { csvPrefix: 'weissman-integrations' });

  const testConnection = async (integrationId) => {
    try {
      setTestingConnection(integrationId);
      const result = await api.post(`/api/integrations/${integrationId}/test`);

      // Update integration status
      setIntegrations((prev) =>
        prev.map((i) =>
          i.id === integrationId
            ? { ...i, status: result.success ? 'connected' : 'error', last_test: new Date().toISOString() }
            : i
        )
      );
    } catch (error) {
      console.error('Connection test failed:', error);
    } finally {
      setTestingConnection(null);
    }
  };

  const deleteIntegration = async (integrationId) => {
    const ok = await confirmDialog({
      title: t('pages.integrationManager.delete_title'),
      message: t('pages.integrationManager.delete_confirm'),
      confirmLabel: t('common.delete'),
      cancelLabel: t('common.cancel'),
      variant: 'danger',
    });
    if (!ok) return;

    try {
      await api.delete(`/api/integrations/${integrationId}`);
      setIntegrations((prev) => prev.filter((i) => i.id !== integrationId));
      toast.success(t('pages.integrationManager.delete_success'));
    } catch (error) {
      console.error('Failed to delete integration:', error);
      toast.error(t('pages.integrationManager.delete_failed'));
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'connected':
        return 'text-green-400 bg-green-500/10 border-green-500/30';
      case 'error':
        return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'pending':
        return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      default:
        return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'connected':
        return <Check className="w-4 h-4" />;
      case 'error':
        return <AlertTriangle className="w-4 h-4" />;
      default:
        return <RefreshCw className="w-4 h-4" />;
    }
  };

  const stats = {
    total: integrations.length,
    connected: integrations.filter((i) => i.status === 'connected').length,
    error: integrations.filter((i) => i.status === 'error').length,
    categories: [...new Set(integrations.map((i) => i.category))].length,
  };

  return (
    <PageShell
      title={t('pages.integrationManager.title')}
      subtitle={t('pages.integrationManager.subtitle')}
      icon={<Plug />}
      actions={(
        <ShellScanActions
          onRefresh={fetchIntegrations}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="space-y-6">
        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Total Integrations</span>
              <Plug className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{stats.total}</div>
          </div>

          <div className="bg-green-500/10 backdrop-blur-md border border-green-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-green-400">Connected</span>
              <Check className="w-4 h-4 text-green-400" />
            </div>
            <div className="text-2xl font-bold text-green-400">{stats.connected}</div>
          </div>

          <div className="bg-red-500/10 backdrop-blur-md border border-red-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-red-400">Errors</span>
              <AlertTriangle className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-red-400">{stats.error}</div>
          </div>

          <div className="bg-purple-500/10 backdrop-blur-md border border-purple-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-purple-400">Categories</span>
              <Settings className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-purple-400">{stats.categories}</div>
          </div>
        </div>

        {/* Add Integration Button */}
        <div className="flex justify-end">
          <button
            onClick={() => setAddModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-500 text-white rounded-lg font-medium hover:bg-cyan-600 transition-colors"
          >
            <Plus className="w-4 h-4" />
            {t('pages.integrationManager.add_integration')}
          </button>
        </div>

        {/* Active Integrations */}
        <WeissmanFindingsPanel
          findings={integrationFindings}
          filteredFindings={filteredFindings}
          counts={counts}
          total={total}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          severityFilter={severityFilter}
          onSeverityChange={setSeverityFilter}
          loading={loading && !integrationFindings.length}
          accent="#22d3ee"
          title="Active Integrations"
          emptyTitle={t('pages.integrationManager.no_integrations_hint')}
          emptyBody={t('pages.integrationManager.no_integrations_hint')}
          renderFinding={(f, i) => {
            const integration = integrations.find((int) => int.id === f.resource) || integrations[i];
            if (!integration) return null;
            return (
              <div
                key={integration.id}
                className="p-4 rounded-lg border border-white/10 bg-black/30 hover:bg-white/5 transition-colors"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-start gap-4 flex-1 min-w-0">
                    <div className="text-3xl shrink-0">{integration.icon || '🔌'}</div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 mb-2 flex-wrap">
                        <h4 className="text-sm font-semibold text-white">{integration.name}</h4>
                        <span className="px-2 py-1 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded text-xs font-medium">
                          {integration.category}
                        </span>
                        <span
                          className={`flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium ${getStatusColor(
                            integration.status
                          )}`}
                        >
                          {getStatusIcon(integration.status)}
                          {integration.status}
                        </span>
                      </div>

                      <p className="text-xs text-gray-400 mb-3">
                        {integration.description || 'No description'}
                      </p>

                      <div className="flex items-center gap-4 text-xs text-gray-500 flex-wrap">
                        {integration.endpoint && (
                          <span className="flex items-center gap-1">
                            Endpoint: <span className="font-mono">{integration.endpoint}</span>
                          </span>
                        )}
                        {integration.config?.endpoint && !integration.endpoint && (
                          <span className="flex items-center gap-1">
                            Endpoint: <span className="font-mono">{integration.config.endpoint}</span>
                          </span>
                        )}
                        <span className="px-2 py-0.5 rounded border border-white/10 bg-white/5 text-gray-400">
                          Manual sync · test connection to verify
                        </span>
                        {integration.last_test && (
                          <>
                            <span>•</span>
                            <span>Last test: {integration.last_test}</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => testConnection(integration.id)}
                      disabled={testingConnection === integration.id}
                      className="flex items-center gap-2 px-3 py-1.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-medium hover:bg-cyan-500/30 transition-colors disabled:opacity-50"
                    >
                      <RefreshCw
                        className={`w-3 h-3 ${
                          testingConnection === integration.id ? 'animate-spin' : ''
                        }`}
                      />
                      Test
                    </button>
                    <button
                      type="button"
                      onClick={() => {}}
                      className="p-2 bg-white/5 border border-white/10 rounded-lg text-gray-400 hover:text-white hover:bg-white/10 transition-colors"
                    >
                      <Settings className="w-4 h-4" />
                    </button>
                    <button
                      type="button"
                      onClick={() => deleteIntegration(integration.id)}
                      className="p-2 bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg hover:bg-red-500/30 transition-colors"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            );
          }}
        />

        {/* Available Integrations */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-white mb-4">Available Integrations</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {availableIntegrations
              .filter((ai) => !integrations.find((i) => i.type === ai.id))
              .map((integration) => (
                <button
                  key={integration.id}
                  onClick={() => setAddModal(integration)}
                  className="flex items-center gap-3 p-3 bg-white/5 border border-white/10 rounded-lg hover:bg-white/10 transition-colors text-left"
                >
                  <span className="text-2xl">{integration.icon}</span>
                  <div>
                    <div className="text-sm font-medium text-white">{integration.name}</div>
                    <div className="text-xs text-gray-400">{integration.category}</div>
                  </div>
                </button>
              ))}
          </div>
        </div>
      </div>

      {/* Add Integration Modal */}
      {addModal && (
        <AddIntegrationModal
          integration={addModal === true ? null : addModal}
          onClose={() => setAddModal(false)}
          onSave={(saved) => {
            if (saved?.integrations) {
              setIntegrations(saved.integrations);
            } else {
              fetchIntegrations();
            }
            setAddModal(false);
          }}
        />
      )}
    </PageShell>
  );
}

/**
 * Add Integration Modal
 */
function AddIntegrationModal({ integration, onClose, onSave }) {
  const { t } = useTranslation();
  const [formData, setFormData] = useState({
    type: integration?.id || '',
    name: integration?.name || '',
    endpoint: '',
    api_key: '',
    webhook_url: '',
  });
  const [saving, setSaving] = useState(false);
  const [saveResult, setSaveResult] = useState(null);

  const handleSave = async () => {
    try {
      setSaving(true);
      setSaveResult(null);
      const payload = {
        id: formData.type,
        name: formData.name,
        category: integration?.category || 'Custom',
        config: {
          endpoint: formData.endpoint,
          api_key: formData.api_key,
          webhook_url: formData.webhook_url,
        },
      };
      const result = await api.post('/api/integrations', payload);
      onSave(result);
    } catch (error) {
      console.error('Failed to add integration:', error);
      setSaveResult({ status: 'error', message: error?.message || 'Failed to add integration.' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-white/10 rounded-xl max-w-lg w-full p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-bold text-white">{t('pages.integrationManager.add_integration_modal')}</h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors"
          >
            ✕
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Integration Type
            </label>
            <input
              type="text"
              value={formData.type}
              disabled
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Name
            </label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              placeholder="Production Splunk"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Endpoint URL
            </label>
            <input
              type="text"
              value={formData.endpoint}
              onChange={(e) => setFormData({ ...formData, endpoint: e.target.value })}
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              placeholder="https://splunk.example.com:8088"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              API Key / Token
            </label>
            <input
              type="password"
              value={formData.api_key}
              onChange={(e) => setFormData({ ...formData, api_key: e.target.value })}
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              placeholder="Enter API key"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Webhook URL (optional)
            </label>
            <input
              type="text"
              value={formData.webhook_url}
              onChange={(e) =>
                setFormData({ ...formData, webhook_url: e.target.value })
              }
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              placeholder="https://your-instance/webhook"
            />
          </div>
        </div>

        {saveResult && (
          <div className={`mt-4 rounded-lg border px-3 py-2 text-xs ${
            saveResult.status === 'error'
              ? 'border-red-500/30 bg-red-500/10 text-red-300'
              : 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300'
          }`}>
            {saveResult.message}
          </div>
        )}

        <div className="flex gap-3 mt-6">
          <button
            onClick={onClose}
            className="flex-1 px-4 py-2 bg-gray-500/20 text-gray-300 border border-gray-500/30 rounded-lg text-sm font-medium hover:bg-gray-500/30 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={saving || !formData.name || !formData.endpoint || !formData.type}
            className="flex-1 px-4 py-2 bg-cyan-500 text-white rounded-lg text-sm font-medium hover:bg-cyan-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {saving ? t('pages.integrationManager.adding') : t('pages.integrationManager.add_integration')}
          </button>
        </div>
      </div>
    </div>
  );
}
