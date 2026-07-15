import { useState, useEffect, useMemo, useRef } from 'react';
import useFocusTrap from '../hooks/useFocusTrap';
import { useTranslation } from 'react-i18next';
import { Calendar, Clock, Play, Pause, Plus, Trash2, Edit } from 'lucide-react';
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { api } from '../utils/apiFetch';
import { confirmDialog } from '../utils/confirmDialog'
import EmptyState from '../components/ui/EmptyState'
import { useToast } from '../components/ui/Toaster'
import Button from '../components/ui/Button'

/**
 * ScanScheduler - Automated scan scheduling and management
 *
 * Features:
 * - Cron-based scheduling
 * - Recurring scans (daily, weekly, monthly)
 * - One-time scheduled scans
 * - Engine selection per schedule
 * - Client/asset targeting
 * - Maintenance windows
 * - Scan queue management
 * - Execution history
 */
export default function ScanScheduler() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all'); // all, active, paused
  const [createModal, setCreateModal] = useState(false);
  const [editModal, setEditModal] = useState(null);

  useEffect(() => {
    fetchSchedules();
  }, []);

  const fetchSchedules = async () => {
    try {
      setLoading(true);
      const data = await api.get('/api/scans/schedules');
      setSchedules(data.schedules || []);
    } catch (error) {
      console.error('Failed to fetch schedules:', error);
      setSchedules([]);
    } finally {
      setLoading(false);
    }
  };

  const toggleSchedule = async (scheduleId, currentState) => {
    try {
      await api.patch(`/api/scans/schedules/${scheduleId}`, {
        enabled: !currentState,
      });
      await fetchSchedules();
    } catch (error) {
      console.error('Failed to toggle schedule:', error);
      toast.error(error?.message || t('pages.scanScheduler.toggle_failed'));
    }
  };

  const deleteSchedule = async (scheduleId) => {
    const ok = await confirmDialog({
      title: t('pages.scanScheduler.delete_title'),
      message: t('pages.scanScheduler.delete_confirm'),
      confirmLabel: t('common.delete'),
      cancelLabel: t('common.cancel'),
      variant: 'danger',
    });
    if (!ok) return;

    try {
      await api.delete(`/api/scans/schedules/${scheduleId}`);
      setSchedules((prev) => prev.filter((s) => s.id !== scheduleId));
      toast.success(t('pages.scanScheduler.delete_success'));
    } catch (error) {
      console.error('Failed to delete schedule:', error);
      toast.error(t('pages.scanScheduler.delete_failed'));
    }
  };

  const runNow = async (scheduleId) => {
    try {
      const result = await api.post(`/api/scans/schedules/${scheduleId}/run`);
      toast.success(
        result?.jobs_queued
          ? t('pages.scanScheduler.scan_started', { count: result.jobs_queued })
          : t('pages.scanScheduler.scan_started_ok')
      );
      await fetchSchedules();
    } catch (error) {
      console.error('Failed to start scan:', error);
      toast.error(error?.message || t('pages.scanScheduler.scan_start_failed'));
    }
  };

  const filteredSchedules = schedules.filter((schedule) => {
    if (filter === 'all') return true;
    return filter === 'active' ? schedule.enabled : !schedule.enabled;
  });

  const stats = {
    total: schedules.length,
    active: schedules.filter((s) => s.enabled).length,
    paused: schedules.filter((s) => !s.enabled).length,
    nextRun: schedules
      .filter((s) => s.enabled && s.next_run)
      .sort((a, b) => new Date(a.next_run) - new Date(b.next_run))[0],
  };

  const listFindings = useMemo(() => schedules.map((s) => ({
    id: s.id,
    severity: s.enabled ? 'info' : 'low',
    title: s.name || s.id,
    type: s.engine || s.schedule_type || 'schedule',
    description: s.cron || s.next_run || '',
    resource: String(s.client_id || ''),
  })), [schedules])

  const {
    exportCsv,
    filteredFindings,
    searchQuery,
    setSearchQuery,
  } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-scan-schedules',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const visibleSchedules = useMemo(() => {
    if (!searchQuery.trim()) return filteredSchedules
    const ids = new Set(filteredFindings.map((f) => f.id))
    return filteredSchedules.filter((s) => ids.has(s.id))
  }, [filteredSchedules, filteredFindings, searchQuery])

  return (
    <PageShell
      title={t('pages.scanScheduler.title')}
      icon={<Calendar />}
      actions={(
        <ShellScanActions
          onRefresh={fetchSchedules}
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
              <span className="text-sm text-[var(--text-tertiary)]">{t('pages.scanScheduler.total_schedules')}</span>
              <Calendar className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{stats.total}</div>
          </div>

          <div className="bg-green-500/10 backdrop-blur-md border border-green-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-green-400">{t('pages.scanScheduler.active')}</span>
              <Play className="w-4 h-4 text-green-400" />
            </div>
            <div className="text-2xl font-bold text-green-400">{stats.active}</div>
          </div>

          <div className="bg-[var(--border-default)] backdrop-blur-md border border-[var(--border-strong)] rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-[var(--text-tertiary)]">{t('pages.scanScheduler.paused')}</span>
              <Pause className="w-4 h-4 text-[var(--text-tertiary)]" />
            </div>
            <div className="text-2xl font-bold text-[var(--text-tertiary)]">{stats.paused}</div>
          </div>

          <div className="bg-purple-500/10 backdrop-blur-md border border-purple-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-purple-400">{t('pages.scanScheduler.next_run')}</span>
              <Clock className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-sm font-bold text-purple-400">
              {stats.nextRun ? new Date(stats.nextRun.next_run).toLocaleString() : t('pages.scanScheduler.none')}
            </div>
          </div>
        </div>

        {/* Controls */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-lg p-1">
            {['all', 'active', 'paused'].map((f) => (
              <Button variant="unstyled"
                key={f}
                onClick={() => setFilter(f)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                  filter === f
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                    : 'text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:bg-[var(--row-hover-bg)]'
                }`}
              >
                {t(`pages.scanScheduler.filter_${f}`)}
              </Button>
            ))}
          </div>

          <Button variant="unstyled"
            onClick={() => setCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-500 text-white rounded-lg font-medium hover:bg-cyan-600 transition-colors"
          >
            <Plus className="w-4 h-4" />
            {t('pages.scanScheduler.create_schedule')}
          </Button>
        </div>

        {/* Schedules List */}
        <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl overflow-hidden">
          <div className="p-4 border-b border-[var(--border-default)] space-y-3">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Calendar className="w-4 h-4 text-cyan-400" />
              {t('pages.scanScheduler.schedules_heading', { count: filteredSchedules.length })}
            </h3>
            <WeissmanListToolbar
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              resultCount={visibleSchedules.length}
              totalCount={filteredSchedules.length}
            />
          </div>

          {loading ? (
            <div className="p-8 text-center text-[var(--text-muted)]">
              <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
              Loading schedules...
            </div>
          ) : filteredSchedules.length === 0 ? (
            <div className="p-6">
              <EmptyState
                icon="inbox"
                title={t('pages.scanScheduler.empty_title')}
                body={t('pages.scanScheduler.empty_body')}
              />
            </div>
          ) : visibleSchedules.length === 0 ? (
            <div className="p-6">
              <EmptyState icon="search-x" title={t('weissmanFindings.filtered_title')} compact />
            </div>
          ) : (
            <div className="divide-y divide-[var(--border-subtle)]">
              {visibleSchedules.map((schedule) => (
                <div
                  key={schedule.id}
                  className="p-4 hover:bg-[var(--row-hover-bg)] transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3 flex-1">
                      <Button variant="unstyled"
                        onClick={() => toggleSchedule(schedule.id, schedule.enabled)}
                        className={`p-2 rounded-lg border transition-colors ${
                          schedule.enabled
                            ? 'bg-green-500/20 text-green-400 border-green-500/30 hover:bg-green-500/30'
                            : 'bg-[var(--border-strong)] text-[var(--text-tertiary)] border-[var(--border-strong)] hover:bg-[var(--border-strong)]'
                        }`}
                      >
                        {schedule.enabled ? (
                          <Play className="w-4 h-4" />
                        ) : (
                          <Pause className="w-4 h-4" />
                        )}
                      </Button>

                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <h4 className="text-sm font-semibold text-white">{schedule.name}</h4>
                          <span
                            className={`px-2 py-1 rounded text-xs font-medium ${
                              schedule.enabled
                                ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                                : 'bg-[var(--border-strong)] text-[var(--text-tertiary)] border border-[var(--border-strong)]'
                            }`}
                          >
                            {schedule.enabled ? 'Active' : 'Paused'}
                          </span>
                          {schedule.type && (
                            <span className="px-2 py-1 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded text-xs font-medium">
                              {schedule.type}
                            </span>
                          )}
                        </div>

                        <p className="text-xs text-[var(--text-tertiary)] mb-3">{schedule.description}</p>

                        {/* Schedule Details */}
                        <div className="flex items-center gap-4 text-xs text-[var(--text-muted)] mb-2">
                          <span className="flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {schedule.cron || schedule.frequency}
                          </span>
                          {schedule.target_client && (
                            <>
                              <span>•</span>
                              <span>Client: {schedule.target_client}</span>
                            </>
                          )}
                          {schedule.engines && (
                            <>
                              <span>•</span>
                              <span>{schedule.engines.length} engines</span>
                            </>
                          )}
                        </div>

                        {/* Next/Last Run */}
                        <div className="flex items-center gap-4 text-xs text-[var(--text-muted)]">
                          {schedule.next_run && (
                            <span className="text-cyan-400">
                              Next: {new Date(schedule.next_run).toLocaleString()}
                            </span>
                          )}
                          {schedule.last_run && (
                            <>
                              <span>•</span>
                              <span>Last: {new Date(schedule.last_run).toLocaleString()}</span>
                            </>
                          )}
                          {schedule.run_count !== undefined && (
                            <>
                              <span>•</span>
                              <span>{schedule.run_count} executions</span>
                            </>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <Button variant="unstyled"
                        onClick={() => runNow(schedule.id)}
                        disabled={!schedule.enabled}
                        className="flex items-center gap-2 px-3 py-1.5 bg-green-500/20 text-green-400 border border-green-500/30 rounded-lg text-xs font-medium hover:bg-green-500/30 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        <Play className="w-3 h-3" />
                        Run Now
                      </Button>
                      <Button variant="unstyled"
                        onClick={() => setEditModal(schedule)}
                        className="p-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/30 transition-colors"
                      >
                        <Edit className="w-4 h-4" />
                      </Button>
                      <Button variant="unstyled"
                        onClick={() => deleteSchedule(schedule.id)}
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
        <div className="bg-gradient-to-r from-cyan-500/10 to-blue-500/10 backdrop-blur-md border border-cyan-500/30 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-white mb-3">Quick Templates</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <Button variant="unstyled"
              onClick={() =>
                setCreateModal({
                  template: 'daily',
                  name: 'Daily Full Scan',
                  frequency: 'daily',
                  time: '02:00',
                })
              }
              className="p-3 bg-[var(--row-hover-bg)] border border-[var(--border-default)] rounded-lg hover:bg-[var(--row-hover-bg)] transition-colors text-left"
            >
              <div className="text-sm font-medium text-white mb-1">Daily Scan</div>
              <div className="text-xs text-[var(--text-tertiary)]">Run comprehensive scan every day at 2 AM</div>
            </Button>
            <Button variant="unstyled"
              onClick={() =>
                setCreateModal({
                  template: 'weekly',
                  name: 'Weekly Deep Scan',
                  frequency: 'weekly',
                  day: 'sunday',
                })
              }
              className="p-3 bg-[var(--row-hover-bg)] border border-[var(--border-default)] rounded-lg hover:bg-[var(--row-hover-bg)] transition-colors text-left"
            >
              <div className="text-sm font-medium text-white mb-1">Weekly Scan</div>
              <div className="text-xs text-[var(--text-tertiary)]">Deep scan every Sunday</div>
            </Button>
            <Button variant="unstyled"
              onClick={() =>
                setCreateModal({
                  template: 'custom',
                  name: 'Custom Schedule',
                })
              }
              className="p-3 bg-[var(--row-hover-bg)] border border-[var(--border-default)] rounded-lg hover:bg-[var(--row-hover-bg)] transition-colors text-left"
            >
              <div className="text-sm font-medium text-white mb-1">Custom Cron</div>
              <div className="text-xs text-[var(--text-tertiary)]">Advanced cron expression</div>
            </Button>
          </div>
        </div>
      </div>

      {/* Create/Edit Modal */}
      {(createModal || editModal) && (
        <ScheduleModal
          schedule={editModal}
          template={createModal?.template ? createModal : null}
          onClose={() => {
            setCreateModal(false);
            setEditModal(null);
          }}
          onSave={() => {
            fetchSchedules();
            setCreateModal(false);
            setEditModal(null);
          }}
        />
      )}
    </PageShell>
  );
}

/**
 * Schedule Create/Edit Modal
 */
function ScheduleModal({ schedule, template, onClose, onSave }) {
  const dialogRef = useRef(null)
  useFocusTrap(dialogRef, true)
  const [clients, setClients] = useState([]);
  const [formData, setFormData] = useState({
    name: schedule?.name || template?.name || '',
    description: schedule?.description || '',
    enabled: schedule?.enabled ?? true,
    type: schedule?.type || template?.frequency || 'daily',
    cron: schedule?.cron || '',
    client_id: schedule?.client_id ?? '',
    target_client: schedule?.target_client || '',
    engines: schedule?.engines || [],
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    api
      .get('/api/clients')
      .then((data) => {
        const list = Array.isArray(data) ? data : data?.clients || [];
        setClients(list);
      })
      .catch((err) => console.error('Failed to load clients:', err));
  }, []);

  const handleSave = async () => {
    try {
      setSaving(true);
      setError('');
      const payload = {
        ...formData,
        client_id: formData.client_id ? Number(formData.client_id) : null,
        target_client:
          formData.client_id
            ? clients.find((c) => String(c.id) === String(formData.client_id))?.name || ''
            : '',
      };
      if (schedule) {
        await api.put(`/api/scans/schedules/${schedule.id}`, payload);
      } else {
        await api.post('/api/scans/schedules', payload);
      }
      onSave();
    } catch (err) {
      console.error('Failed to save schedule:', err);
      setError(err?.message || 'Failed to save schedule');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className="fixed inset-0 bg-[var(--bg-3)] backdrop-blur-sm flex items-center justify-center z-50 p-4"
      onKeyDown={(e) => { if (e.key === 'Escape') onClose() }}
    >
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-label={schedule ? 'Edit scan schedule' : 'Create scan schedule'} className="bg-[var(--bg-1)] border border-[var(--border-default)] rounded-xl max-w-2xl w-full p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-bold text-white">
            {schedule ? 'Edit Schedule' : 'Create Scan Schedule'}
          </h3>
          <Button variant="unstyled"
            aria-label="Close"
            onClick={onClose}
            className="text-[var(--text-tertiary)] hover:text-[var(--text-primary)] transition-colors"
          >
            ✕
          </Button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">Schedule Name</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              placeholder="Daily production scan"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">Description</label>
            <input
              type="text"
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              placeholder="Run full security scan daily"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">Frequency</label>
              <select
                value={formData.type}
                onChange={(e) => setFormData({ ...formData, type: e.target.value })}
                className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              >
                <option value="hourly">Hourly</option>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
                <option value="custom">Custom (Cron)</option>
              </select>
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

          {formData.type === 'custom' && (
            <div>
              <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
                Cron Expression
              </label>
              <input
                type="text"
                value={formData.cron}
                onChange={(e) => setFormData({ ...formData, cron: e.target.value })}
                className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white font-mono focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
                placeholder="0 2 * * *"
              />
              <div className="text-xs text-[var(--text-muted)] mt-1">
                Example: 0 2 * * * (runs daily at 2:00 AM)
              </div>
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
              Target Client
            </label>
            <select
              value={formData.client_id}
              onChange={(e) =>
                setFormData({ ...formData, client_id: e.target.value, target_client: '' })
              }
              className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            >
              <option value="">All clients (manual run requires a client)</option>
              {clients.map((client) => (
                <option key={client.id} value={client.id}>
                  {client.name}
                </option>
              ))}
            </select>
          </div>

          {error && (
            <div className="text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2">
              {error}
            </div>
          )}
        </div>

        <div className="flex gap-3 mt-6">
          <Button variant="unstyled"
            onClick={onClose}
            className="flex-1 px-4 py-2 bg-[var(--border-strong)] text-[var(--text-secondary)] border border-[var(--border-strong)] rounded-lg text-sm font-medium hover:bg-[var(--border-strong)] transition-colors"
          >
            Cancel
          </Button>
          <Button variant="unstyled"
            onClick={handleSave}
            disabled={saving || !formData.name}
            className="flex-1 px-4 py-2 bg-cyan-500 text-white rounded-lg text-sm font-medium hover:bg-cyan-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {saving ? 'Saving...' : schedule ? 'Save Changes' : 'Create Schedule'}
          </Button>
        </div>
      </div>
    </div>
  );
}
