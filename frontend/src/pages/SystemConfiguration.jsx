import { useState, useEffect } from 'react';
import { Settings, Database, Shield, Zap, Globe, Lock, AlertTriangle, Save, RefreshCw } from 'lucide-react';
import PageShell from '../components/PageShell';
import { api } from '../utils/apiFetch';

/**
 * SystemConfiguration - Complete system settings management
 *
 * Features:
 * - General settings (name, logo, timezone)
 * - Security policies (password, session, MFA)
 * - Scan configuration (default engines, timeout, concurrency)
 * - Integration settings (webhooks, SIEM, notifications)
 * - Data retention policies
 * - Performance tuning
 * - Compliance settings
 */
export default function SystemConfiguration() {
  const [config, setConfig] = useState({
    general: {},
    security: {},
    scanning: {},
    integrations: {},
    retention: {},
    performance: {},
    compliance: {},
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [activeTab, setActiveTab] = useState('general');
  const [unsavedChanges, setUnsavedChanges] = useState(false);

  const tabs = [
    { id: 'general', label: 'General', icon: <Settings /> },
    { id: 'security', label: 'Security', icon: <Shield /> },
    { id: 'scanning', label: 'Scanning', icon: <Zap /> },
    { id: 'integrations', label: 'Integrations', icon: <Globe /> },
    { id: 'retention', label: 'Data Retention', icon: <Database /> },
    { id: 'performance', label: 'Performance', icon: <RefreshCw /> },
    { id: 'compliance', label: 'Compliance', icon: <Lock /> },
  ];

  useEffect(() => {
    fetchConfig();
  }, []);

  const fetchConfig = async () => {
    try {
      setLoading(true);
      const data = await api.get('/api/system/config');
      setConfig(data);
    } catch (error) {
      console.error('Failed to fetch config:', error);
    } finally {
      setLoading(false);
    }
  };

  const saveConfig = async () => {
    try {
      setSaving(true);
      await api.put('/api/system/config', config);
      setUnsavedChanges(false);
    } catch (error) {
      console.error('Failed to save config:', error);
    } finally {
      setSaving(false);
    }
  };

  const updateConfig = (section, key, value) => {
    setConfig((prev) => ({
      ...prev,
      [section]: {
        ...prev[section],
        [key]: value,
      },
    }));
    setUnsavedChanges(true);
  };

  return (
    <PageShell title="System Configuration" icon={<Settings />}>
      <div className="space-y-6">
        {/* Unsaved Changes Warning */}
        {unsavedChanges && (
          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-yellow-400" />
              <div>
                <h3 className="text-sm font-semibold text-yellow-400">Unsaved Changes</h3>
                <p className="text-xs text-gray-400">You have unsaved configuration changes</p>
              </div>
            </div>
            <button
              onClick={saveConfig}
              disabled={saving}
              className="flex items-center gap-2 px-4 py-2 bg-yellow-500 text-black rounded-lg text-sm font-medium hover:bg-yellow-600 transition-colors disabled:opacity-50"
            >
              <Save className="w-4 h-4" />
              {saving ? 'Saving...' : 'Save Changes'}
            </button>
          </div>
        )}

        {/* Tabs */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="flex overflow-x-auto border-b border-white/10">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-6 py-4 text-sm font-medium whitespace-nowrap transition-all ${
                  activeTab === tab.id
                    ? 'text-cyan-400 border-b-2 border-cyan-400 bg-cyan-500/10'
                    : 'text-gray-400 hover:text-white hover:bg-white/5'
                }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </div>

          {/* Tab Content */}
          <div className="p-6">
            {loading ? (
              <div className="text-center py-12 text-gray-500">
                <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
                Loading configuration...
              </div>
            ) : (
              <>
                {activeTab === 'general' && <GeneralSettings config={config.general} onChange={(key, value) => updateConfig('general', key, value)} />}
                {activeTab === 'security' && <SecuritySettings config={config.security} onChange={(key, value) => updateConfig('security', key, value)} />}
                {activeTab === 'scanning' && <ScanningSettings config={config.scanning} onChange={(key, value) => updateConfig('scanning', key, value)} />}
                {activeTab === 'integrations' && <IntegrationsSettings config={config.integrations} onChange={(key, value) => updateConfig('integrations', key, value)} />}
                {activeTab === 'retention' && <RetentionSettings config={config.retention} onChange={(key, value) => updateConfig('retention', key, value)} />}
                {activeTab === 'performance' && <PerformanceSettings config={config.performance} onChange={(key, value) => updateConfig('performance', key, value)} />}
                {activeTab === 'compliance' && <ComplianceSettings config={config.compliance} onChange={(key, value) => updateConfig('compliance', key, value)} />}
              </>
            )}
          </div>
        </div>

        {/* Save Button */}
        <div className="flex justify-end">
          <button
            onClick={saveConfig}
            disabled={!unsavedChanges || saving}
            className="flex items-center gap-2 px-6 py-3 bg-cyan-500 text-white rounded-lg font-medium hover:bg-cyan-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Save className="w-4 h-4" />
            {saving ? 'Saving...' : 'Save All Changes'}
          </button>
        </div>
      </div>
    </PageShell>
  );
}

// General Settings Component
function GeneralSettings({ config, onChange }) {
  return (
    <div className="space-y-6">
      <h3 className="text-lg font-bold text-white mb-4">General Settings</h3>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Organization Name
          </label>
          <input
            type="text"
            value={config.org_name || ''}
            onChange={(e) => onChange('org_name', e.target.value)}
            className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Timezone
          </label>
          <select
            value={config.timezone || 'UTC'}
            onChange={(e) => onChange('timezone', e.target.value)}
            className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          >
            <option value="UTC">UTC</option>
            <option value="America/New_York">Eastern Time</option>
            <option value="America/Los_Angeles">Pacific Time</option>
            <option value="Europe/London">London</option>
            <option value="Asia/Tokyo">Tokyo</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Language
          </label>
          <select
            value={config.language || 'en'}
            onChange={(e) => onChange('language', e.target.value)}
            className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          >
            <option value="en">English</option>
            <option value="he">Hebrew</option>
            <option value="es">Spanish</option>
            <option value="fr">French</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Date Format
          </label>
          <select
            value={config.date_format || 'YYYY-MM-DD'}
            onChange={(e) => onChange('date_format', e.target.value)}
            className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          >
            <option value="YYYY-MM-DD">YYYY-MM-DD</option>
            <option value="MM/DD/YYYY">MM/DD/YYYY</option>
            <option value="DD/MM/YYYY">DD/MM/YYYY</option>
          </select>
        </div>
      </div>
    </div>
  );
}

// Security Settings Component
function SecuritySettings({ config, onChange }) {
  return (
    <div className="space-y-6">
      <h3 className="text-lg font-bold text-white mb-4">Security Policies</h3>

      <div className="space-y-4">
        {/* Password Policy */}
        <div className="bg-white/5 border border-white/10 rounded-lg p-4">
          <h4 className="text-sm font-semibold text-white mb-3">Password Policy</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-gray-400 mb-2">Minimum Length</label>
              <input
                type="number"
                value={config.password_min_length || 12}
                onChange={(e) => onChange('password_min_length', parseInt(e.target.value))}
                className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-2">Max Age (days)</label>
              <input
                type="number"
                value={config.password_max_age || 90}
                onChange={(e) => onChange('password_max_age', parseInt(e.target.value))}
                className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              />
            </div>
          </div>
          <div className="mt-4 space-y-2">
            <label className="flex items-center gap-2 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={config.password_require_uppercase || false}
                onChange={(e) => onChange('password_require_uppercase', e.target.checked)}
                className="rounded"
              />
              Require uppercase letters
            </label>
            <label className="flex items-center gap-2 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={config.password_require_numbers || false}
                onChange={(e) => onChange('password_require_numbers', e.target.checked)}
                className="rounded"
              />
              Require numbers
            </label>
            <label className="flex items-center gap-2 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={config.password_require_special || false}
                onChange={(e) => onChange('password_require_special', e.target.checked)}
                className="rounded"
              />
              Require special characters
            </label>
          </div>
        </div>

        {/* Session Policy */}
        <div className="bg-white/5 border border-white/10 rounded-lg p-4">
          <h4 className="text-sm font-semibold text-white mb-3">Session Management</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-gray-400 mb-2">Session Timeout (minutes)</label>
              <input
                type="number"
                value={config.session_timeout || 60}
                onChange={(e) => onChange('session_timeout', parseInt(e.target.value))}
                className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-2">Max Concurrent Sessions</label>
              <input
                type="number"
                value={config.max_concurrent_sessions || 3}
                onChange={(e) => onChange('max_concurrent_sessions', parseInt(e.target.value))}
                className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              />
            </div>
          </div>
        </div>

        {/* MFA */}
        <div className="bg-white/5 border border-white/10 rounded-lg p-4">
          <h4 className="text-sm font-semibold text-white mb-3">Multi-Factor Authentication</h4>
          <label className="flex items-center gap-2 text-sm text-gray-300">
            <input
              type="checkbox"
              checked={config.mfa_required || false}
              onChange={(e) => onChange('mfa_required', e.target.checked)}
              className="rounded"
            />
            Require MFA for all users
          </label>
        </div>
      </div>
    </div>
  );
}

// Scanning Settings Component
function ScanningSettings({ config, onChange }) {
  return (
    <div className="space-y-6">
      <h3 className="text-lg font-bold text-white mb-4">Scanning Configuration</h3>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Default Scan Timeout (seconds)
          </label>
          <input
            type="number"
            value={config.default_timeout || 300}
            onChange={(e) => onChange('default_timeout', parseInt(e.target.value))}
            className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Max Concurrency
          </label>
          <input
            type="number"
            value={config.max_concurrency || 10}
            onChange={(e) => onChange('max_concurrency', parseInt(e.target.value))}
            className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Auto-Retry Failed Scans
          </label>
          <select
            value={config.auto_retry || 'false'}
            onChange={(e) => onChange('auto_retry', e.target.value === 'true')}
            className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          >
            <option value="true">Enabled</option>
            <option value="false">Disabled</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Max Retries
          </label>
          <input
            type="number"
            value={config.max_retries || 3}
            onChange={(e) => onChange('max_retries', parseInt(e.target.value))}
            className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>
      </div>
    </div>
  );
}

// Integrations Settings Component
function IntegrationsSettings({ config, onChange }) {
  return (
    <div className="space-y-6">
      <h3 className="text-lg font-bold text-white mb-4">Integration Settings</h3>

      <div className="space-y-4">
        {/* Webhook */}
        <div className="bg-white/5 border border-white/10 rounded-lg p-4">
          <h4 className="text-sm font-semibold text-white mb-3">Webhook URL</h4>
          <input
            type="text"
            value={config.webhook_url || ''}
            onChange={(e) => onChange('webhook_url', e.target.value)}
            placeholder="https://example.com/webhook"
            className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>

        {/* SIEM */}
        <div className="bg-white/5 border border-white/10 rounded-lg p-4">
          <h4 className="text-sm font-semibold text-white mb-3">SIEM Integration</h4>
          <div className="space-y-3">
            <select
              value={config.siem_type || 'none'}
              onChange={(e) => onChange('siem_type', e.target.value)}
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            >
              <option value="none">None</option>
              <option value="splunk">Splunk</option>
              <option value="qradar">IBM QRadar</option>
              <option value="sentinel">Microsoft Sentinel</option>
            </select>
            {config.siem_type && config.siem_type !== 'none' && (
              <input
                type="text"
                value={config.siem_endpoint || ''}
                onChange={(e) => onChange('siem_endpoint', e.target.value)}
                placeholder="SIEM endpoint URL"
                className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              />
            )}
          </div>
        </div>

        {/* Email Notifications */}
        <div className="bg-white/5 border border-white/10 rounded-lg p-4">
          <h4 className="text-sm font-semibold text-white mb-3">Email Notifications</h4>
          <div className="space-y-3">
            <input
              type="text"
              value={config.smtp_server || ''}
              onChange={(e) => onChange('smtp_server', e.target.value)}
              placeholder="smtp.example.com"
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            />
            <input
              type="number"
              value={config.smtp_port || 587}
              onChange={(e) => onChange('smtp_port', parseInt(e.target.value))}
              placeholder="587"
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            />
          </div>
        </div>
      </div>
    </div>
  );
}

// Retention Settings Component
function RetentionSettings({ config, onChange }) {
  return (
    <div className="space-y-6">
      <h3 className="text-lg font-bold text-white mb-4">Data Retention Policies</h3>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Scan Results (days)
          </label>
          <input
            type="number"
            value={config.scan_results_retention || 90}
            onChange={(e) => onChange('scan_results_retention', parseInt(e.target.value))}
            className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Audit Logs (days)
          </label>
          <input
            type="number"
            value={config.audit_logs_retention || 365}
            onChange={(e) => onChange('audit_logs_retention', parseInt(e.target.value))}
            className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Findings (days)
          </label>
          <input
            type="number"
            value={config.findings_retention || 180}
            onChange={(e) => onChange('findings_retention', parseInt(e.target.value))}
            className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Metrics (days)
          </label>
          <input
            type="number"
            value={config.metrics_retention || 30}
            onChange={(e) => onChange('metrics_retention', parseInt(e.target.value))}
            className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>
      </div>
    </div>
  );
}

// Performance Settings Component
function PerformanceSettings({ config, onChange }) {
  return (
    <div className="space-y-6">
      <h3 className="text-lg font-bold text-white mb-4">Performance Tuning</h3>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Worker Threads
          </label>
          <input
            type="number"
            value={config.worker_threads || 4}
            onChange={(e) => onChange('worker_threads', parseInt(e.target.value))}
            className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Cache TTL (seconds)
          </label>
          <input
            type="number"
            value={config.cache_ttl || 300}
            onChange={(e) => onChange('cache_ttl', parseInt(e.target.value))}
            className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Max Memory (MB)
          </label>
          <input
            type="number"
            value={config.max_memory || 2048}
            onChange={(e) => onChange('max_memory', parseInt(e.target.value))}
            className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Database Pool Size
          </label>
          <input
            type="number"
            value={config.db_pool_size || 20}
            onChange={(e) => onChange('db_pool_size', parseInt(e.target.value))}
            className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>
      </div>
    </div>
  );
}

// Compliance Settings Component
function ComplianceSettings({ config, onChange }) {
  return (
    <div className="space-y-6">
      <h3 className="text-lg font-bold text-white mb-4">Compliance Frameworks</h3>

      <div className="space-y-3">
        {['CIS', 'PCI-DSS', 'NIST', 'HIPAA', 'SOC2', 'GDPR', 'ISO27001'].map((framework) => (
          <label key={framework} className="flex items-center gap-3 p-3 bg-white/5 border border-white/10 rounded-lg hover:bg-white/10 transition-colors">
            <input
              type="checkbox"
              checked={config[`framework_${framework.toLowerCase()}`] || false}
              onChange={(e) => onChange(`framework_${framework.toLowerCase()}`, e.target.checked)}
              className="rounded"
            />
            <span className="text-sm font-medium text-white">{framework}</span>
          </label>
        ))}
      </div>
    </div>
  );
}
