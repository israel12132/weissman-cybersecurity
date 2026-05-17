import { useState, useEffect } from 'react';
import { Shield, Plus, Trash2, Edit, Play, AlertTriangle, Check } from 'lucide-react';
import PageShell from './PageShell';
import { api } from '../utils/apiFetch';

/**
 * ContainmentRulesBuilder - Network containment and isolation rules
 *
 * Features:
 * - Auto-isolation rules for critical findings
 * - Network segmentation policies
 * - Quarantine workflows
 * - Whitelist/blacklist management
 * - Emergency kill switches
 * - Containment history tracking
 * - Integration with firewall/SDN
 */
export default function ContainmentRulesBuilder() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [createModal, setCreateModal] = useState(false);
  const [editModal, setEditModal] = useState(null);

  useEffect(() => {
    fetchRules();
  }, []);

  const fetchRules = async () => {
    try {
      setLoading(true);
      const data = await api.get('/api/containment/rules');
      setRules(data.rules || []);
    } catch (error) {
      console.error('Failed to fetch containment rules:', error);
    } finally {
      setLoading(false);
    }
  };

  const toggleRule = async (ruleId, currentState) => {
    try {
      await api.patch(`/api/containment/rules/${ruleId}`, {
        enabled: !currentState,
      });
      setRules((prev) =>
        prev.map((r) => (r.id === ruleId ? { ...r, enabled: !currentState } : r))
      );
    } catch (error) {
      console.error('Failed to toggle rule:', error);
    }
  };

  const deleteRule = async (ruleId) => {
    if (!confirm('Are you sure you want to delete this containment rule?')) return;

    try {
      await api.delete(`/api/containment/rules/${ruleId}`);
      setRules((prev) => prev.filter((r) => r.id !== ruleId));
    } catch (error) {
      console.error('Failed to delete rule:', error);
    }
  };

  const getActionColor = (action) => {
    switch (action) {
      case 'isolate':
        return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'quarantine':
        return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'block':
        return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      default:
        return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
    }
  };

  const stats = {
    total: rules.length,
    enabled: rules.filter((r) => r.enabled).length,
    triggered: rules.reduce((sum, r) => sum + (r.triggered_count || 0), 0),
    isolated: rules.filter((r) => r.action === 'isolate' && r.enabled).length,
  };

  return (
    <PageShell title="Containment Rules Builder" icon={<Shield />}>
      <div className="space-y-6">
        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Total Rules</span>
              <Shield className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{stats.total}</div>
          </div>

          <div className="bg-green-500/10 backdrop-blur-md border border-green-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-green-400">Active</span>
              <Play className="w-4 h-4 text-green-400" />
            </div>
            <div className="text-2xl font-bold text-green-400">{stats.enabled}</div>
          </div>

          <div className="bg-red-500/10 backdrop-blur-md border border-red-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-red-400">Auto-Isolate</span>
              <AlertTriangle className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-red-400">{stats.isolated}</div>
          </div>

          <div className="bg-purple-500/10 backdrop-blur-md border border-purple-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-purple-400">Triggered</span>
              <Check className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-purple-400">{stats.triggered}</div>
          </div>
        </div>

        {/* Create Button */}
        <div className="flex justify-end">
          <button
            onClick={() => setCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-500 text-white rounded-lg font-medium hover:bg-cyan-600 transition-colors"
          >
            <Plus className="w-4 h-4" />
            Create Rule
          </button>
        </div>

        {/* Rules List */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/10">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              Containment Rules
            </h3>
          </div>

          {loading ? (
            <div className="p-8 text-center text-gray-500">
              <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
              Loading rules...
            </div>
          ) : rules.length === 0 ? (
            <div className="p-8 text-center text-gray-500">
              No containment rules configured. Click "Create Rule" to get started.
            </div>
          ) : (
            <div className="divide-y divide-white/5">
              {rules.map((rule) => (
                <div
                  key={rule.id}
                  className="p-4 hover:bg-white/5 transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3 flex-1">
                      <button
                        onClick={() => toggleRule(rule.id, rule.enabled)}
                        className={`p-2 rounded-lg border transition-colors ${
                          rule.enabled
                            ? 'bg-green-500/20 text-green-400 border-green-500/30'
                            : 'bg-gray-500/20 text-gray-400 border-gray-500/30'
                        }`}
                      >
                        {rule.enabled ? <Play className="w-4 h-4" /> : <Shield className="w-4 h-4" />}
                      </button>

                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <h4 className="text-sm font-semibold text-white">{rule.name}</h4>
                          <span
                            className={`px-2 py-1 rounded text-xs font-medium border ${getActionColor(
                              rule.action
                            )}`}
                          >
                            {rule.action?.toUpperCase()}
                          </span>
                          {rule.auto_trigger && (
                            <span className="px-2 py-1 bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 rounded text-xs font-medium">
                              AUTO
                            </span>
                          )}
                        </div>

                        <p className="text-xs text-gray-400 mb-3">{rule.description}</p>

                        {/* Conditions */}
                        <div className="flex flex-wrap gap-2 mb-2">
                          {rule.trigger_on?.severity && (
                            <span className="text-xs px-2 py-1 bg-red-500/10 text-red-400 border border-red-500/20 rounded">
                              Severity: {rule.trigger_on.severity}
                            </span>
                          )}
                          {rule.trigger_on?.cve && (
                            <span className="text-xs px-2 py-1 bg-orange-500/10 text-orange-400 border border-orange-500/20 rounded">
                              CVE Match
                            </span>
                          )}
                          {rule.target && (
                            <span className="text-xs px-2 py-1 bg-blue-500/10 text-blue-400 border border-blue-500/20 rounded">
                              Target: {rule.target}
                            </span>
                          )}
                        </div>

                        <div className="flex items-center gap-3 text-xs text-gray-500">
                          {rule.triggered_count !== undefined && (
                            <span>Triggered: {rule.triggered_count} times</span>
                          )}
                          {rule.last_triggered && (
                            <>
                              <span>•</span>
                              <span>Last: {rule.last_triggered}</span>
                            </>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setEditModal(rule)}
                        className="p-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/30 transition-colors"
                      >
                        <Edit className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => deleteRule(rule.id)}
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

        {/* Emergency Kill Switch */}
        <div className="bg-gradient-to-r from-red-500/10 to-orange-500/10 backdrop-blur-md border border-red-500/30 rounded-xl p-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white mb-1 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                Emergency Network Isolation
              </h3>
              <p className="text-xs text-gray-400">
                Immediately isolate all compromised assets from the network
              </p>
            </div>
            <button className="px-4 py-2 bg-red-500 text-white rounded-lg text-sm font-medium hover:bg-red-600 transition-colors">
              Activate Kill Switch
            </button>
          </div>
        </div>
      </div>

      {/* Create/Edit Modal */}
      {(createModal || editModal) && (
        <RuleModal
          rule={editModal}
          onClose={() => {
            setCreateModal(false);
            setEditModal(null);
          }}
          onSave={() => {
            fetchRules();
            setCreateModal(false);
            setEditModal(null);
          }}
        />
      )}
    </PageShell>
  );
}

/**
 * Rule Modal
 */
function RuleModal({ rule, onClose, onSave }) {
  const [formData, setFormData] = useState({
    name: rule?.name || '',
    description: rule?.description || '',
    enabled: rule?.enabled ?? true,
    action: rule?.action || 'isolate',
    auto_trigger: rule?.auto_trigger ?? false,
    trigger_on: rule?.trigger_on || {},
  });
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    try {
      setSaving(true);
      if (rule) {
        await api.put(`/api/containment/rules/${rule.id}`, formData);
      } else {
        await api.post('/api/containment/rules', formData);
      }
      onSave();
    } catch (error) {
      console.error('Failed to save rule:', error);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-white/10 rounded-xl max-w-lg w-full p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-bold text-white">
            {rule ? 'Edit Rule' : 'Create Containment Rule'}
          </h3>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            ✕
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Rule Name</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              placeholder="Auto-isolate critical assets"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Action</label>
            <select
              value={formData.action}
              onChange={(e) => setFormData({ ...formData, action: e.target.value })}
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            >
              <option value="isolate">Isolate (full network cut)</option>
              <option value="quarantine">Quarantine (limited access)</option>
              <option value="block">Block (IP/port specific)</option>
              <option value="alert">Alert Only</option>
            </select>
          </div>

          <div>
            <label className="flex items-center gap-2 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={formData.auto_trigger}
                onChange={(e) => setFormData({ ...formData, auto_trigger: e.target.checked })}
                className="rounded"
              />
              Auto-trigger on condition match
            </label>
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
            disabled={saving || !formData.name}
            className="flex-1 px-4 py-2 bg-cyan-500 text-white rounded-lg text-sm font-medium hover:bg-cyan-600 transition-colors disabled:opacity-50"
          >
            {saving ? 'Saving...' : rule ? 'Save Changes' : 'Create Rule'}
          </button>
        </div>
      </div>
    </div>
  );
}
