import { useState, useEffect, useMemo, useRef } from 'react';
import useFocusTrap from '../hooks/useFocusTrap';
import { useTranslation } from 'react-i18next';
import { Shield, Plus, Trash2, Edit, Play, AlertTriangle, Check } from 'lucide-react';
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { api } from '../utils/apiFetch';
import { confirmDialog } from '../utils/confirmDialog';


import { useFirstTenantClientId, withClientId } from '../lib/aliasClient';
import Button from '../components/ui/Button'

export default function ContainmentRulesBuilder() {
  const { t } = useTranslation();
  const { clientId, loading: clientLoading } = useFirstTenantClientId();
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [createModal, setCreateModal] = useState(false);
  const [editModal, setEditModal] = useState(null);

  useEffect(() => {
    if (clientLoading) return;
    if (clientId == null) {
      setRules([]);
      setLoading(false);
      return;
    }
    fetchRules(clientId);
  }, [clientId, clientLoading]);

  const fetchRules = async (cid) => {
    try {
      setLoading(true);
      const data = await api.get(withClientId('/api/containment/rules', cid));
      setRules(data.rules || []);
    } catch (error) {
      console.error('Failed to fetch containment rules:', error);
    } finally {
      setLoading(false);
    }
  };

  const toggleRule = async (ruleId, currentState) => {
    if (clientId == null) return;
    try {
      await api.patch(withClientId(`/api/containment/rules/${ruleId}`, clientId), {
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
    if (!(await confirmDialog(t('pages.containmentRulesBuilder.delete_confirm')))) return;
    if (clientId == null) return;

    try {
      await api.delete(withClientId(`/api/containment/rules/${ruleId}`, clientId));
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
        return 'text-[var(--text-tertiary)] bg-[var(--border-strong)]/10 border-[var(--border-strong)]/30';
    }
  };

  const stats = {
    total: rules.length,
    enabled: rules.filter((r) => r.enabled).length,
    triggered: rules.reduce((sum, r) => sum + (r.triggered_count || 0), 0),
    isolated: rules.filter((r) => r.action === 'isolate' && r.enabled).length,
  };

  const listFindings = useMemo(() => rules.map((r) => ({
    id: r.id,
    severity: r.enabled ? 'medium' : 'info',
    title: r.name || r.id,
    type: r.action || 'containment',
    description: r.condition || r.description || '',
    resource: r.enabled ? 'enabled' : 'disabled',
  })), [rules])

  const {
    exportCsv,
    filteredFindings,
    searchQuery,
    setSearchQuery,
  } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-containment-rules',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const visibleRules = useMemo(() => {
    if (!searchQuery.trim()) return rules
    const ids = new Set(filteredFindings.map((f) => f.id))
    return rules.filter((r) => ids.has(r.id))
  }, [rules, filteredFindings, searchQuery])

  const reloadRules = () => {
    if (clientId != null) fetchRules(clientId)
  }

  return (
    <PageShell
      title={t('pages.containmentRulesBuilder.title')}
      icon={<Shield />}
      actions={(
        <ShellScanActions
          onRefresh={reloadRules}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-[var(--text-tertiary)]">{t('pages.containmentRulesBuilder.total_rules')}</span>
              <Shield className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{stats.total}</div>
          </div>

          <div className="bg-green-500/10 backdrop-blur-md border border-green-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-green-400">{t('pages.containmentRulesBuilder.active')}</span>
              <Play className="w-4 h-4 text-green-400" />
            </div>
            <div className="text-2xl font-bold text-green-400">{stats.enabled}</div>
          </div>

          <div className="bg-red-500/10 backdrop-blur-md border border-red-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-red-400">{t('pages.containmentRulesBuilder.auto_isolate')}</span>
              <AlertTriangle className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-red-400">{stats.isolated}</div>
          </div>

          <div className="bg-purple-500/10 backdrop-blur-md border border-purple-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-purple-400">{t('pages.containmentRulesBuilder.triggered')}</span>
              <Check className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-purple-400">{stats.triggered}</div>
          </div>
        </div>

        <div className="flex justify-end">
          <Button variant="unstyled"
            onClick={() => setCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-500 text-white rounded-lg font-medium hover:bg-cyan-600 transition-colors"
          >
            <Plus className="w-4 h-4" />
            {t('pages.containmentRulesBuilder.create_rule')}
          </Button>
        </div>

        <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl overflow-hidden">
          <div className="p-4 border-b border-[var(--border-default)] space-y-3">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              {t('pages.containmentRulesBuilder.rules_heading')}
            </h3>
            <WeissmanListToolbar
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              resultCount={visibleRules.length}
              totalCount={rules.length}
            />
          </div>

          {loading ? (
            <div className="p-8 text-center text-[var(--text-muted)]">
              <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
              {t('pages.containmentRulesBuilder.loading')}
            </div>
          ) : rules.length === 0 ? (
            <div className="p-8 text-center text-[var(--text-muted)]">
              {t('pages.containmentRulesBuilder.empty')}
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
                            ? 'bg-green-500/20 text-green-400 border-green-500/30'
                            : 'bg-[var(--border-strong)]/20 text-[var(--text-tertiary)] border-[var(--border-strong)]/30'
                        }`}
                      >
                        {rule.enabled ? <Play className="w-4 h-4" /> : <Shield className="w-4 h-4" />}
                      </Button>

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
                              {t('pages.containmentRulesBuilder.auto_badge')}
                            </span>
                          )}
                        </div>

                        <p className="text-xs text-[var(--text-tertiary)] mb-3">{rule.description}</p>

                        <div className="flex flex-wrap gap-2 mb-2">
                          {rule.trigger_on?.severity && (
                            <span className="text-xs px-2 py-1 bg-red-500/10 text-red-400 border border-red-500/20 rounded">
                              {t('pages.containmentRulesBuilder.severity_trigger', { severity: rule.trigger_on.severity })}
                            </span>
                          )}
                          {rule.trigger_on?.cve && (
                            <span className="text-xs px-2 py-1 bg-orange-500/10 text-orange-400 border border-orange-500/20 rounded">
                              {t('pages.containmentRulesBuilder.cve_match')}
                            </span>
                          )}
                          {rule.target && (
                            <span className="text-xs px-2 py-1 bg-blue-500/10 text-blue-400 border border-blue-500/20 rounded">
                              {t('pages.containmentRulesBuilder.target_label', { target: rule.target })}
                            </span>
                          )}
                        </div>

                        <div className="flex items-center gap-3 text-xs text-[var(--text-muted)]">
                          {rule.triggered_count !== undefined && (
                            <span>{t('pages.containmentRulesBuilder.triggered_times', { count: rule.triggered_count })}</span>
                          )}
                          {rule.last_triggered && (
                            <>
                              <span>•</span>
                              <span>{t('pages.containmentRulesBuilder.last_triggered', { time: rule.last_triggered })}</span>
                            </>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
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

        <div className="bg-gradient-to-r from-red-500/10 to-orange-500/10 backdrop-blur-md border border-red-500/30 rounded-xl p-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white mb-1 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                {t('pages.containmentRulesBuilder.emergency_title')}
              </h3>
              <p className="text-xs text-[var(--text-tertiary)]">
                {t('pages.containmentRulesBuilder.emergency_body')}
              </p>
            </div>
            <Button variant="unstyled" className="px-4 py-2 bg-red-500 text-white rounded-lg text-sm font-medium hover:bg-red-600 transition-colors">
              {t('pages.containmentRulesBuilder.kill_switch')}
            </Button>
          </div>
        </div>
      </div>

      {(createModal || editModal) && (
        <RuleModal
          rule={editModal}
          clientId={clientId}
          onClose={() => {
            setCreateModal(false);
            setEditModal(null);
          }}
          onSave={() => {
            if (clientId != null) fetchRules(clientId);
            setCreateModal(false);
            setEditModal(null);
          }}
        />
      )}
    </PageShell>
  );
}

function RuleModal({ rule, clientId, onClose, onSave }) {
  const dialogRef = useRef(null)
  useFocusTrap(dialogRef, true)
  const { t } = useTranslation();
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
    if (clientId == null) return;
    try {
      setSaving(true);
      if (rule) {
        await api.put(withClientId(`/api/containment/rules/${rule.id}`, clientId), formData);
      } else {
        await api.post(withClientId('/api/containment/rules', clientId), formData);
      }
      onSave();
    } catch (error) {
      console.error('Failed to save rule:', error);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className="fixed inset-0 bg-[var(--bg-3)] backdrop-blur-sm flex items-center justify-center z-50 p-4"
      onKeyDown={(e) => { if (e.key === 'Escape') onClose() }}
    >
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-label={rule ? t('pages.containmentRulesBuilder.edit_rule') : t('pages.containmentRulesBuilder.create_containment_rule')} className="bg-[var(--bg-1)] border border-[var(--border-default)] rounded-xl max-w-lg w-full p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-bold text-white">
            {rule ? t('pages.containmentRulesBuilder.edit_rule') : t('pages.containmentRulesBuilder.create_containment_rule')}
          </h3>
          <Button variant="unstyled" onClick={onClose} className="text-[var(--text-tertiary)] hover:text-[var(--text-primary)]">
            ✕
          </Button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">{t('pages.containmentRulesBuilder.rule_name')}</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              placeholder={t('pages.containmentRulesBuilder.rule_name_placeholder')}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">{t('pages.containmentRulesBuilder.action')}</label>
            <select
              value={formData.action}
              onChange={(e) => setFormData({ ...formData, action: e.target.value })}
              className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            >
              <option value="isolate">{t('pages.containmentRulesBuilder.action_isolate')}</option>
              <option value="quarantine">{t('pages.containmentRulesBuilder.action_quarantine')}</option>
              <option value="block">{t('pages.containmentRulesBuilder.action_block')}</option>
              <option value="alert">{t('pages.containmentRulesBuilder.action_alert')}</option>
            </select>
          </div>

          <div>
            <label className="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
              <input
                type="checkbox"
                checked={formData.auto_trigger}
                onChange={(e) => setFormData({ ...formData, auto_trigger: e.target.checked })}
                className="rounded"
              />
              {t('pages.containmentRulesBuilder.auto_trigger')}
            </label>
          </div>
        </div>

        <div className="flex gap-3 mt-6">
          <Button variant="unstyled"
            onClick={onClose}
            className="flex-1 px-4 py-2 bg-[var(--border-strong)]/20 text-[var(--text-secondary)] border border-[var(--border-strong)]/30 rounded-lg text-sm font-medium hover:bg-[var(--border-strong)]/30 transition-colors"
          >
            {t('common.cancel')}
          </Button>
          <Button variant="unstyled"
            onClick={handleSave}
            disabled={saving || !formData.name}
            className="flex-1 px-4 py-2 bg-cyan-500 text-white rounded-lg text-sm font-medium hover:bg-cyan-600 transition-colors disabled:opacity-50"
          >
            {saving ? t('pages.containmentRulesBuilder.saving') : rule ? t('pages.containmentRulesBuilder.save_changes') : t('pages.containmentRulesBuilder.create_rule')}
          </Button>
        </div>
      </div>
    </div>
  );
}
