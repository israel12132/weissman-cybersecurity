import { useState, useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Bell, Plus, Trash2, Edit, Play, Pause, AlertTriangle } from 'lucide-react';
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { api } from '../utils/apiFetch';
import { confirmDialog } from '../utils/confirmDialog'
import { useToast } from '../components/ui/Toaster'
import Button from '../components/ui/Button'

/**
 * AlertRulesEngine - Custom alert rule creation and management
 *
 * Features:
 * - Condition-based alerting (severity, CVE, engine, asset)
 * - Multiple notification channels (email, Slack, PagerDuty, webhook)
 * - Threshold configuration
 * - Alert deduplication
 * - Alert suppression windows
 * - Rule priority and chaining
 * - Test mode before activation
 */
export default function AlertRulesEngine() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all'); // all, enabled, disabled
  const [createModal, setCreateModal] = useState(false);
  const [editModal, setEditModal] = useState(null);

  useEffect(() => {
    fetchRules();
  }, []);

  const fetchRules = async () => {
    try {
      setLoading(true);
      const data = await api.get('/api/alerts/rules');
      setRules(data.rules || []);
    } catch (error) {
      console.error('Failed to fetch alert rules:', error);
      toast.error(t('pages.alertRulesEngine.load_failed'));
    } finally {
      setLoading(false);
    }
  };

  const toggleRule = async (ruleId, currentState) => {
    try {
      await api.patch(`/api/alerts/rules/${ruleId}`, {
        enabled: !currentState,
      });
      setRules((prev) =>
        prev.map((r) => (r.id === ruleId ? { ...r, enabled: !currentState } : r))
      );
      toast.success(
        currentState
          ? t('pages.alertRulesEngine.rule_disabled')
          : t('pages.alertRulesEngine.rule_enabled')
      );
    } catch (error) {
      console.error('Failed to toggle rule:', error);
      toast.error(t('pages.alertRulesEngine.toggle_failed'));
    }
  };

  const deleteRule = async (ruleId) => {
    const ok = await confirmDialog({
      title: t('pages.alertRulesEngine.delete_title'),
      message: t('pages.alertRulesEngine.delete_confirm'),
      confirmLabel: t('common.delete'),
      cancelLabel: t('common.cancel'),
      variant: 'danger',
    });
    if (!ok) return;

    try {
      await api.delete(`/api/alerts/rules/${ruleId}`);
      setRules((prev) => prev.filter((r) => r.id !== ruleId));
      toast.success(t('pages.alertRulesEngine.delete_success'));
    } catch (error) {
      console.error('Failed to delete rule:', error);
      toast.error(t('pages.alertRulesEngine.delete_failed'));
    }
  };

  const testRule = async (ruleId) => {
    try {
      const result = await api.post(`/api/alerts/rules/${ruleId}/test`);
      if (result.success) {
        toast.success(t('pages.alertRulesEngine.test_success', { count: result.matched }));
      } else {
        toast.warning(t('pages.alertRulesEngine.test_failed'));
      }
    } catch (error) {
      console.error('Failed to test rule:', error);
      toast.error(t('pages.alertRulesEngine.test_error'));
    }
  };

  const filteredRules = rules.filter((rule) => {
    if (filter === 'all') return true;
    return filter === 'enabled' ? rule.enabled : !rule.enabled;
  });

  const stats = {
    total: rules.length,
    enabled: rules.filter((r) => r.enabled).length,
    disabled: rules.filter((r) => !r.enabled).length,
    triggered: rules.reduce((sum, r) => sum + (r.triggered_count || 0), 0),
  };

  const listFindings = useMemo(() => rules.map((r) => ({
    id: r.id,
    severity: r.enabled ? 'medium' : 'info',
    title: r.name || r.id,
    type: r.condition_type || 'alert_rule',
    description: r.description || '',
    resource: r.enabled ? 'enabled' : 'disabled',
  })), [rules])

  const {
    exportCsv,
    filteredFindings,
    searchQuery,
    setSearchQuery,
  } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-alert-rules',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const visibleRules = useMemo(() => {
    if (!searchQuery.trim()) return filteredRules
    const ids = new Set(filteredFindings.map((f) => f.id))
    return filteredRules.filter((r) => ids.has(r.id))
  }, [filteredRules, filteredFindings, searchQuery])

  return (
    <PageShell
      title={t('pages.alertRulesEngine.title')}
      icon={<Bell />}
      actions={(
        <ShellScanActions
          onRefresh={fetchRules}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="space-y-6">
        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-[var(--text-tertiary)]">{t('pages.alertRulesEngine.total_rules')}</span>
              <Bell className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{stats.total}</div>
          </div>

          <div className="bg-green-500/10 backdrop-blur-md border border-green-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-green-400">{t('pages.alertRulesEngine.enabled')}</span>
              <Play className="w-4 h-4 text-green-400" />
            </div>
            <div className="text-2xl font-bold text-green-400">{stats.enabled}</div>
          </div>

          <div className="bg-[var(--border-strong)]/10 backdrop-blur-md border border-[var(--border-strong)]/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-[var(--text-tertiary)]">{t('pages.alertRulesEngine.disabled')}</span>
              <Pause className="w-4 h-4 text-[var(--text-tertiary)]" />
            </div>
            <div className="text-2xl font-bold text-[var(--text-tertiary)]">{stats.disabled}</div>
          </div>

          <div className="bg-purple-500/10 backdrop-blur-md border border-purple-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-purple-400">{t('pages.alertRulesEngine.triggered_24h')}</span>
              <AlertTriangle className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-purple-400">{stats.triggered}</div>
          </div>
        </div>

        {/* Controls */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-lg p-1">
            {['all', 'enabled', 'disabled'].map((f) => (
              <Button variant="unstyled"
                key={f}
                onClick={() => setFilter(f)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                  filter === f
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                    : 'text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:bg-[var(--row-hover-bg)]'
                }`}
              >
                {t(`pages.alertRulesEngine.filter_${f}`)}
              </Button>
            ))}
          </div>

          <Button variant="unstyled"
            onClick={() => setCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-500 text-white rounded-lg font-medium hover:bg-cyan-600 transition-colors"
          >
            <Plus className="w-4 h-4" />
            {t('pages.alertRulesEngine.create_rule')}
          </Button>
        </div>

        {/* Rules List */}
        <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl overflow-hidden">
          <div className="p-4 border-b border-[var(--border-default)] space-y-3">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Bell className="w-4 h-4 text-cyan-400" />
              {t('pages.alertRulesEngine.rules_heading', { count: filteredRules.length })}
            </h3>
            <WeissmanListToolbar
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              resultCount={visibleRules.length}
              totalCount={filteredRules.length}
            />
          </div>

          {loading ? (
            <div className="p-8 text-center text-[var(--text-muted)]">
              <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
              Loading rules...
            </div>
          ) : filteredRules.length === 0 ? (
            <div className="p-8 text-center text-[var(--text-muted)]">
              No alert rules found. Click &quot;Create Rule&quot; to get started.
            </div>
          ) : visibleRules.length === 0 ? (
            <div className="p-8 text-center text-[var(--text-muted)]">{t('weissmanFindings.filtered_title')}</div>
          ) : (
            <div className="divide-y divide-[var(--border-subtle)]">
              {visibleRules.map((rule) => (
                <div
                  key={rule.id}
                  className="p-4 hover:bg-[var(--row-hover-bg)] transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3 flex-1">
                      <Button variant="unstyled"
                        onClick={() => toggleRule(rule.id, rule.enabled)}
                        className={`p-2 rounded-lg border transition-colors ${
                          rule.enabled
                            ? 'bg-green-500/20 text-green-400 border-green-500/30 hover:bg-green-500/30'
                            : 'bg-[var(--border-strong)]/20 text-[var(--text-tertiary)] border-[var(--border-strong)]/30 hover:bg-[var(--border-strong)]/30'
                        }`}
                      >
                        {rule.enabled ? (
                          <Play className="w-4 h-4" />
                        ) : (
                          <Pause className="w-4 h-4" />
                        )}
                      </Button>

                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <h4 className="text-sm font-semibold text-white">{rule.name}</h4>
                          <span
                            className={`px-2 py-1 rounded text-xs font-medium ${
                              rule.enabled
                                ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                                : 'bg-[var(--border-strong)]/20 text-[var(--text-tertiary)] border border-[var(--border-strong)]/30'
                            }`}
                          >
                            {rule.enabled ? 'Active' : 'Inactive'}
                          </span>
                          {rule.priority && (
                            <span className="px-2 py-1 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded text-xs font-medium">
                              Priority: {rule.priority}
                            </span>
                          )}
                        </div>

                        <p className="text-xs text-[var(--text-tertiary)] mb-3">{rule.description}</p>

                        {/* Conditions */}
                        <div className="flex flex-wrap gap-2 mb-3">
                          {rule.conditions?.severity && (
                            <span className="text-xs px-2 py-1 bg-red-500/10 text-red-400 border border-red-500/20 rounded">
                              Severity: {rule.conditions.severity.join(', ')}
                            </span>
                          )}
                          {rule.conditions?.cve_pattern && (
                            <span className="text-xs px-2 py-1 bg-orange-500/10 text-orange-400 border border-orange-500/20 rounded">
                              CVE: {rule.conditions.cve_pattern}
                            </span>
                          )}
                          {rule.conditions?.engines && (
                            <span className="text-xs px-2 py-1 bg-blue-500/10 text-blue-400 border border-blue-500/20 rounded">
                              {rule.conditions.engines.length} engines
                            </span>
                          )}
                        </div>

                        {/* Channels */}
                        <div className="flex items-center gap-3 text-xs text-[var(--text-muted)]">
                          <span>Channels:</span>
                          {rule.channels?.map((channel) => (
                            <span
                              key={channel}
                              className="px-2 py-1 bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 rounded"
                            >
                              {channel}
                            </span>
                          ))}
                          {rule.triggered_count !== undefined && (
                            <>
                              <span>•</span>
                              <span>Triggered: {rule.triggered_count} times</span>
                            </>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <Button variant="unstyled"
                        onClick={() => testRule(rule.id)}
                        className="px-3 py-1.5 bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 rounded-lg text-xs font-medium hover:bg-yellow-500/30 transition-colors"
                      >
                        Test
                      </Button>
                      <Button variant="unstyled"
                        onClick={() => setEditModal(rule)}
                        className="p-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/30 transition-colors"
                      >
                        <Edit className="w-4 h-4" />
                      </Button>
                      <Button variant="unstyled"
                        onClick={() => deleteRule(rule.id)}
                        className="p-2 bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg hover:bg-red-500/30 transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Quick Templates */}
        <div className="bg-gradient-to-r from-purple-500/10 to-blue-500/10 backdrop-blur-md border border-purple-500/30 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-white mb-3">Quick Templates</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <Button variant="unstyled"
              onClick={() =>
                setCreateModal({
                  template: 'critical-findings',
                  name: 'Critical Findings Alert',
                  conditions: { severity: ['critical'] },
                })
              }
              className="p-3 bg-[var(--row-hover-bg)] border border-[var(--border-default)] rounded-lg hover:bg-[var(--row-hover-bg)] transition-colors text-left"
            >
              <div className="text-sm font-medium text-white mb-1">Critical Findings</div>
              <div className="text-xs text-[var(--text-tertiary)]">Alert on all critical severity findings</div>
            </Button>
            <Button variant="unstyled"
              onClick={() =>
                setCreateModal({
                  template: 'new-cve',
                  name: 'New CVE Alert',
                  conditions: { cve_pattern: 'CVE-2024-*' },
                })
              }
              className="p-3 bg-[var(--row-hover-bg)] border border-[var(--border-default)] rounded-lg hover:bg-[var(--row-hover-bg)] transition-colors text-left"
            >
              <div className="text-sm font-medium text-white mb-1">New CVE Detection</div>
              <div className="text-xs text-[var(--text-tertiary)]">Alert on newly published CVEs</div>
            </Button>
            <Button variant="unstyled"
              onClick={() =>
                setCreateModal({
                  template: 'high-volume',
                  name: 'High Volume Alert',
                  conditions: { threshold: 50 },
                })
              }
              className="p-3 bg-[var(--row-hover-bg)] border border-[var(--border-default)] rounded-lg hover:bg-[var(--row-hover-bg)] transition-colors text-left"
            >
              <div className="text-sm font-medium text-white mb-1">High Volume</div>
              <div className="text-xs text-[var(--text-tertiary)]">Alert when findings exceed threshold</div>
            </Button>
          </div>
        </div>
      </div>

      {/* Create/Edit Modal */}
      {(createModal || editModal) && (
        <RuleModal
          rule={editModal}
          template={createModal?.template ? createModal : null}
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
 * Rule Create/Edit Modal
 */
function RuleModal({ rule, template, onClose, onSave }) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [formData, setFormData] = useState({
    name: rule?.name || template?.name || '',
    description: rule?.description || '',
    enabled: rule?.enabled ?? true,
    priority: rule?.priority || 5,
    conditions: rule?.conditions || template?.conditions || {},
    channels: rule?.channels || ['email'],
  });
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    try {
      setSaving(true);
      if (rule) {
        await api.put(`/api/alerts/rules/${rule.id}`, formData);
      } else {
        await api.post('/api/alerts/rules', formData);
      }
      toast.success(
        rule
          ? t('pages.alertRulesEngine.save_updated')
          : t('pages.alertRulesEngine.save_created')
      );
      onSave();
    } catch (error) {
      console.error('Failed to save rule:', error);
      toast.error(t('pages.alertRulesEngine.save_failed'));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-[var(--bg-3)] backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-[var(--bg-1)] border border-[var(--border-default)] rounded-xl max-w-2xl w-full p-6 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-bold text-white">
            {rule ? 'Edit Rule' : 'Create Alert Rule'}
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
            <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">Rule Name</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              placeholder="Critical vulnerabilities alert"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">Description</label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              rows={2}
              className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              placeholder="Alert when critical findings are detected"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">Priority</label>
              <input
                type="number"
                min="1"
                max="10"
                value={formData.priority}
                onChange={(e) =>
                  setFormData({ ...formData, priority: parseInt(e.target.value) })
                }
                className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">Status</label>
              <select
                value={formData.enabled ? 'enabled' : 'disabled'}
                onChange={(e) =>
                  setFormData({ ...formData, enabled: e.target.value === 'enabled' })
                }
                className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              >
                <option value="enabled">Enabled</option>
                <option value="disabled">Disabled</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
              Notification Channels
            </label>
            <div className="space-y-2">
              {['email', 'slack', 'teams', 'pagerduty', 'webhook'].map((channel) => (
                <label key={channel} className="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
                  <input
                    type="checkbox"
                    checked={formData.channels.includes(channel)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setFormData({
                          ...formData,
                          channels: [...formData.channels, channel],
                        });
                      } else {
                        setFormData({
                          ...formData,
                          channels: formData.channels.filter((c) => c !== channel),
                        });
                      }
                    }}
                    className="rounded"
                  />
                  {channel.charAt(0).toUpperCase() + channel.slice(1)}
                </label>
              ))}
            </div>
          </div>
        </div>

        <div className="flex gap-3 mt-6">
          <Button variant="unstyled"
            onClick={onClose}
            className="flex-1 px-4 py-2 bg-[var(--border-strong)]/20 text-[var(--text-secondary)] border border-[var(--border-strong)]/30 rounded-lg text-sm font-medium hover:bg-[var(--border-strong)]/30 transition-colors"
          >
            Cancel
          </Button>
          <Button variant="unstyled"
            onClick={handleSave}
            disabled={saving || !formData.name}
            className="flex-1 px-4 py-2 bg-cyan-500 text-white rounded-lg text-sm font-medium hover:bg-cyan-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {saving ? 'Saving...' : rule ? 'Save Changes' : 'Create Rule'}
          </Button>
        </div>
      </div>
    </div>
  );
}
