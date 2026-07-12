import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import useFocusTrap from '../hooks/useFocusTrap';
import { useTranslation } from 'react-i18next';
import { Plug, Check, AlertTriangle, Settings, Plus, Trash2, RefreshCw } from 'lucide-react';
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { api } from '../utils/apiFetch';
import { confirmDialog } from '../utils/confirmDialog'
import { useToast } from '../components/ui/Toaster'
import Button from '../components/ui/Button'

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
  const [dryRunTests, setDryRunTests] = useState(true);
  const [addModal, setAddModal] = useState(false);
  const [configureTarget, setConfigureTarget] = useState(null);

  const availableIntegrations = [
    { id: 'aws_ec2', name: 'AWS EC2 Isolate', category: 'SOAR', icon: '☁️', color: 'orange', fields: ['region', 'forensic_source_cidr'] },
    { id: 'azure_vm', name: 'Azure VM Isolate', category: 'SOAR', icon: '🔷', color: 'blue', fields: ['subscription_id', 'resource_group', 'tenant_id', 'client_id', 'client_secret'] },
    { id: 'crowdstrike_falcon', name: 'CrowdStrike Falcon', category: 'SOAR', icon: '🦅', color: 'red', fields: ['client_id', 'client_secret', 'api_url'] },
    { id: 'github', name: 'GitHub PR', category: 'SOAR', icon: '🐙', color: 'gray', fields: ['token', 'default_repo'] },
    { id: 'pagerduty', name: 'PagerDuty', category: 'SOAR', icon: '🚨', color: 'red', fields: ['routing_key'] },
    { id: 'opsgenie', name: 'OpsGenie', category: 'SOAR', icon: '📟', color: 'blue', fields: ['api_key'] },
    { id: 'slack', name: 'Slack', category: 'SOAR', icon: '💬', color: 'purple', fields: ['webhook_url', 'bot_token', 'channel'] },
    { id: 'servicenow', name: 'ServiceNow', category: 'SOAR', icon: '🎫', color: 'green', fields: ['instance_url', 'username', 'password'] },
    { id: 'splunk', name: 'Splunk', category: 'SIEM', icon: '📊', color: 'green' },
    { id: 'sentinel', name: 'Microsoft Sentinel', category: 'SIEM', icon: '🛡️', color: 'cyan' },
    { id: 'jira', name: 'Jira', category: 'Ticketing', icon: '📝', color: 'blue' },
  ];
  const [vaultEnabled, setVaultEnabled] = useState(false);

  const fetchIntegrations = useCallback(async () => {
    try {
      setLoading(true);
      const data = await api.get('/api/integrations');
      setIntegrations(data.integrations || []);
      setVaultEnabled(Boolean(data.vault_enabled));
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
      const result = await api.post(`/api/integrations/${integrationId}/test`, { dry_run: dryRunTests });

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
        return 'text-[var(--text-tertiary)] bg-[var(--border-strong)]/10 border-[var(--border-strong)]/30';
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
        {vaultEnabled && (
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
            Vault encryption active — integration secrets stored encrypted at rest (AES-256-GCM).
          </div>
        )}
        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-[var(--text-tertiary)]">Total Integrations</span>
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
        <div className="flex justify-end items-center gap-4">
          <label className="flex items-center gap-2 text-xs text-[var(--text-tertiary)] cursor-pointer">
            <input
              type="checkbox"
              checked={dryRunTests}
              onChange={(e) => setDryRunTests(e.target.checked)}
              className="rounded border-[var(--border-strong)]"
            />
            Dry-run SOAR tests (recommended)
          </label>
          <Button variant="unstyled"
            onClick={() => setAddModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-500 text-white rounded-lg font-medium hover:bg-cyan-600 transition-colors"
          >
            <Plus className="w-4 h-4" />
            {t('pages.integrationManager.add_integration')}
          </Button>
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
                className="p-4 rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] hover:bg-[var(--row-hover-bg)] transition-colors"
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

                      <p className="text-xs text-[var(--text-tertiary)] mb-3">
                        {integration.description || 'No description'}
                      </p>

                      <div className="flex items-center gap-4 text-xs text-[var(--text-muted)] flex-wrap">
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
                        <span className="px-2 py-0.5 rounded border border-[var(--border-default)] bg-[var(--row-hover-bg)] text-[var(--text-tertiary)]">
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
                    <Button variant="unstyled"
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
                    </Button>
                    <Button variant="unstyled"
                      type="button"
                      onClick={() => setConfigureTarget(integration)}
                      title={t('pages.integrationManager.configure')}
                      aria-label={t('pages.integrationManager.configure')}
                      className="p-2 bg-[var(--row-hover-bg)] border border-[var(--border-default)] rounded-lg text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:bg-[var(--row-hover-bg)] transition-colors"
                    >
                      <Settings className="w-4 h-4" />
                    </Button>
                    <Button variant="unstyled"
                      type="button"
                      onClick={() => deleteIntegration(integration.id)}
                      className="p-2 bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg hover:bg-red-500/30 transition-colors"
                    >
                      <Trash2 className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              </div>
            );
          }}
        />

        {/* Available Integrations */}
        <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl p-6">
          <h3 className="text-sm font-semibold text-white mb-4">Available Integrations</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {availableIntegrations
              .filter((ai) => !integrations.find((i) => i.id === ai.id || i.type === ai.id))
              .map((integration) => (
                <Button variant="unstyled"
                  key={integration.id}
                  onClick={() => setAddModal(integration)}
                  className="flex items-center gap-3 p-3 bg-[var(--row-hover-bg)] border border-[var(--border-default)] rounded-lg hover:bg-[var(--row-hover-bg)] transition-colors text-left"
                >
                  <span className="text-2xl">{integration.icon}</span>
                  <div>
                    <div className="text-sm font-medium text-white">{integration.name}</div>
                    <div className="text-xs text-[var(--text-tertiary)]">{integration.category}</div>
                  </div>
                </Button>
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

      {/* Configure existing integration modal */}
      {configureTarget && (
        <AddIntegrationModal
          integration={
            availableIntegrations.find(
              (ai) => ai.id === (configureTarget.type || configureTarget.id)
            ) || null
          }
          existing={configureTarget}
          onClose={() => setConfigureTarget(null)}
          onSave={(saved) => {
            if (saved?.integrations) {
              setIntegrations(saved.integrations);
            } else {
              fetchIntegrations();
            }
            setConfigureTarget(null);
            toast.success(t('pages.integrationManager.configure_success'));
          }}
        />
      )}
    </PageShell>
  );
}

/**
 * Add Integration Modal
 */
function AddIntegrationModal({ integration, existing = null, onClose, onSave }) {
  const dialogRef = useRef(null)
  useFocusTrap(dialogRef, true)
  const { t } = useTranslation();
  const isEdit = Boolean(existing);
  // In edit mode, prefer the keys already stored on the integration so the
  // form matches what the backend persisted; fall back to the catalog fields.
  const existingConfigKeys = existing?.config ? Object.keys(existing.config) : [];
  const providerFields =
    (existingConfigKeys.length ? existingConfigKeys : integration?.fields) ||
    ['endpoint', 'api_key', 'webhook_url'];
  const initialConfig = Object.fromEntries(
    providerFields.map((f) => [f, existing?.config?.[f] ?? ''])
  );
  const [formData, setFormData] = useState({
    type: existing?.type || existing?.id || integration?.id || '',
    name: existing?.name || integration?.name || '',
    config: initialConfig,
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
        category: existing?.category || integration?.category || 'Custom',
        config: formData.config,
      };
      const result = await api.post('/api/integrations', payload);
      onSave(result);
    } catch (error) {
      console.error(isEdit ? 'Failed to update integration:' : 'Failed to add integration:', error);
      setSaveResult({
        status: 'error',
        message:
          error?.message ||
          (isEdit
            ? t('pages.integrationManager.configure_failed')
            : 'Failed to add integration.'),
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className="fixed inset-0 bg-[var(--bg-3)] backdrop-blur-sm flex items-center justify-center z-50 p-4"
      onKeyDown={(e) => { if (e.key === 'Escape') onClose() }}
    >
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-label={isEdit ? 'Configure integration' : 'Add integration'} className="bg-[var(--bg-1)] border border-[var(--border-default)] rounded-xl max-w-lg w-full p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-bold text-white">
            {isEdit
              ? t('pages.integrationManager.configure_modal_title', { name: formData.name || formData.type })
              : t('pages.integrationManager.add_integration_modal')}
          </h3>
          <Button variant="unstyled"
            onClick={onClose}
            className="text-[var(--text-tertiary)] hover:text-[var(--text-primary)] transition-colors"
          >
            ✕
          </Button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
              Integration Type
            </label>
            <input
              type="text"
              value={formData.type}
              disabled
              className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
              Name
            </label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              placeholder="Production Splunk"
            />
          </div>

          {providerFields.map((field) => (
            <div key={field}>
              <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2 capitalize">
                {field.replace(/_/g, ' ')}
              </label>
              <input
                type={field.includes('secret') || field.includes('password') || field.includes('token') || field.includes('key') ? 'password' : 'text'}
                value={formData.config[field] || ''}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    config: { ...formData.config, [field]: e.target.value },
                  })
                }
                className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              />
            </div>
          ))}
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
          <Button variant="unstyled"
            onClick={onClose}
            className="flex-1 px-4 py-2 bg-[var(--border-strong)]/20 text-[var(--text-secondary)] border border-[var(--border-strong)]/30 rounded-lg text-sm font-medium hover:bg-[var(--border-strong)]/30 transition-colors"
          >
            Cancel
          </Button>
          <Button variant="unstyled"
            onClick={handleSave}
            disabled={saving || !formData.name || !formData.type}
            className="flex-1 px-4 py-2 bg-cyan-500 text-white rounded-lg text-sm font-medium hover:bg-cyan-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {saving
              ? isEdit
                ? t('pages.integrationManager.saving')
                : t('pages.integrationManager.adding')
              : isEdit
                ? t('pages.integrationManager.save_changes')
                : t('pages.integrationManager.add_integration')}
          </Button>
        </div>
      </div>
    </div>
  );
}
