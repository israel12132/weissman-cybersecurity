import { useState, useEffect } from 'react';
import { Plug, Check, AlertTriangle, Settings, Plus, Trash2, RefreshCw } from 'lucide-react';
import PageShell from '../components/PageShell';
import { api } from '../utils/apiFetch';

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
 * - Real-time sync status
 * - Connection testing
 * - Event filtering
 */
export default function IntegrationManager() {
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

  useEffect(() => {
    fetchIntegrations();
  }, []);

  const fetchIntegrations = async () => {
    try {
      setLoading(true);
      const data = await api.get('/api/integrations');
      setIntegrations(data.integrations || []);
    } catch (error) {
      console.error('Failed to fetch integrations:', error);
    } finally {
      setLoading(false);
    }
  };

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
    if (!confirm('Are you sure you want to remove this integration?')) return;

    try {
      await api.delete(`/api/integrations/${integrationId}`);
      setIntegrations((prev) => prev.filter((i) => i.id !== integrationId));
    } catch (error) {
      console.error('Failed to delete integration:', error);
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
    <PageShell title="Integration Manager" icon={<Plug />}>
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
            Add Integration
          </button>
        </div>

        {/* Active Integrations */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/10">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Plug className="w-4 h-4 text-cyan-400" />
              Active Integrations
            </h3>
          </div>

          {loading ? (
            <div className="p-8 text-center text-gray-500">
              <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
              Loading integrations...
            </div>
          ) : integrations.length === 0 ? (
            <div className="p-8 text-center text-gray-500">
              No integrations configured. Click "Add Integration" to get started.
            </div>
          ) : (
            <div className="divide-y divide-white/5">
              {integrations.map((integration) => (
                <div
                  key={integration.id}
                  className="p-4 hover:bg-white/5 transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-4 flex-1">
                      <div className="text-3xl">{integration.icon || '🔌'}</div>
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <h4 className="text-sm font-semibold text-white">
                            {integration.name}
                          </h4>
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

                        <div className="flex items-center gap-4 text-xs text-gray-500">
                          {integration.endpoint && (
                            <span className="flex items-center gap-1">
                              Endpoint: <span className="font-mono">{integration.endpoint}</span>
                            </span>
                          )}
                          {integration.last_sync && (
                            <>
                              <span>•</span>
                              <span>Last sync: {integration.last_sync}</span>
                            </>
                          )}
                          {integration.events_sent !== undefined && (
                            <>
                              <span>•</span>
                              <span>{integration.events_sent} events sent</span>
                            </>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
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
                        onClick={() => {}}
                        className="p-2 bg-white/5 border border-white/10 rounded-lg text-gray-400 hover:text-white hover:bg-white/10 transition-colors"
                      >
                        <Settings className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => deleteIntegration(integration.id)}
                        className="p-2 bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg hover:bg-red-500/30 transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

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
          onSave={() => {
            fetchIntegrations();
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
  const [formData, setFormData] = useState({
    type: integration?.id || '',
    name: integration?.name || '',
    endpoint: '',
    api_key: '',
    webhook_url: '',
  });
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    try {
      setSaving(true);
      await api.post('/api/integrations', formData);
      onSave();
    } catch (error) {
      console.error('Failed to add integration:', error);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-white/10 rounded-xl max-w-lg w-full p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-bold text-white">Add Integration</h3>
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

        <div className="flex gap-3 mt-6">
          <button
            onClick={onClose}
            className="flex-1 px-4 py-2 bg-gray-500/20 text-gray-300 border border-gray-500/30 rounded-lg text-sm font-medium hover:bg-gray-500/30 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={saving || !formData.name || !formData.endpoint}
            className="flex-1 px-4 py-2 bg-cyan-500 text-white rounded-lg text-sm font-medium hover:bg-cyan-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {saving ? 'Adding...' : 'Add Integration'}
          </button>
        </div>
      </div>
    </div>
  );
}
