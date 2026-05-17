import { useState, useEffect } from 'react';
import { Calendar, Clock, Play, Pause, Plus, Trash2, Edit, RefreshCw } from 'lucide-react';
import PageShell from '../components/PageShell';
import { api } from '../utils/apiFetch';

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
    } finally {
      setLoading(false);
    }
  };

  const toggleSchedule = async (scheduleId, currentState) => {
    try {
      await api.patch(`/api/scans/schedules/${scheduleId}`, {
        enabled: !currentState,
      });
      setSchedules((prev) =>
        prev.map((s) => (s.id === scheduleId ? { ...s, enabled: !currentState } : s))
      );
    } catch (error) {
      console.error('Failed to toggle schedule:', error);
    }
  };

  const deleteSchedule = async (scheduleId) => {
    if (!confirm('Are you sure you want to delete this schedule?')) return;

    try {
      await api.delete(`/api/scans/schedules/${scheduleId}`);
      setSchedules((prev) => prev.filter((s) => s.id !== scheduleId));
    } catch (error) {
      console.error('Failed to delete schedule:', error);
    }
  };

  const runNow = async (scheduleId) => {
    try {
      await api.post(`/api/scans/schedules/${scheduleId}/run`);
      alert('Scan started successfully!');
    } catch (error) {
      console.error('Failed to start scan:', error);
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

  return (
    <PageShell title="Scan Scheduler" icon={<Calendar />}>
      <div className="space-y-6">
        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Total Schedules</span>
              <Calendar className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{stats.total}</div>
          </div>

          <div className="bg-green-500/10 backdrop-blur-md border border-green-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-green-400">Active</span>
              <Play className="w-4 h-4 text-green-400" />
            </div>
            <div className="text-2xl font-bold text-green-400">{stats.active}</div>
          </div>

          <div className="bg-gray-500/10 backdrop-blur-md border border-gray-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Paused</span>
              <Pause className="w-4 h-4 text-gray-400" />
            </div>
            <div className="text-2xl font-bold text-gray-400">{stats.paused}</div>
          </div>

          <div className="bg-purple-500/10 backdrop-blur-md border border-purple-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-purple-400">Next Run</span>
              <Clock className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-sm font-bold text-purple-400">
              {stats.nextRun ? new Date(stats.nextRun.next_run).toLocaleString() : 'None'}
            </div>
          </div>
        </div>

        {/* Controls */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 bg-black/40 backdrop-blur-md border border-white/10 rounded-lg p-1">
            {['all', 'active', 'paused'].map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                  filter === f
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                    : 'text-gray-400 hover:text-white hover:bg-white/5'
                }`}
              >
                {f.charAt(0).toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>

          <button
            onClick={() => setCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-500 text-white rounded-lg font-medium hover:bg-cyan-600 transition-colors"
          >
            <Plus className="w-4 h-4" />
            Create Schedule
          </button>
        </div>

        {/* Schedules List */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/10">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Calendar className="w-4 h-4 text-cyan-400" />
              Scan Schedules ({filteredSchedules.length})
            </h3>
          </div>

          {loading ? (
            <div className="p-8 text-center text-gray-500">
              <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
              Loading schedules...
            </div>
          ) : filteredSchedules.length === 0 ? (
            <div className="p-8 text-center text-gray-500">
              No schedules found. Click "Create Schedule" to get started.
            </div>
          ) : (
            <div className="divide-y divide-white/5">
              {filteredSchedules.map((schedule) => (
                <div
                  key={schedule.id}
                  className="p-4 hover:bg-white/5 transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3 flex-1">
                      <button
                        onClick={() => toggleSchedule(schedule.id, schedule.enabled)}
                        className={`p-2 rounded-lg border transition-colors ${
                          schedule.enabled
                            ? 'bg-green-500/20 text-green-400 border-green-500/30 hover:bg-green-500/30'
                            : 'bg-gray-500/20 text-gray-400 border-gray-500/30 hover:bg-gray-500/30'
                        }`}
                      >
                        {schedule.enabled ? (
                          <Play className="w-4 h-4" />
                        ) : (
                          <Pause className="w-4 h-4" />
                        )}
                      </button>

                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <h4 className="text-sm font-semibold text-white">{schedule.name}</h4>
                          <span
                            className={`px-2 py-1 rounded text-xs font-medium ${
                              schedule.enabled
                                ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                                : 'bg-gray-500/20 text-gray-400 border border-gray-500/30'
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

                        <p className="text-xs text-gray-400 mb-3">{schedule.description}</p>

                        {/* Schedule Details */}
                        <div className="flex items-center gap-4 text-xs text-gray-500 mb-2">
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
                        <div className="flex items-center gap-4 text-xs text-gray-500">
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
                      <button
                        onClick={() => runNow(schedule.id)}
                        disabled={!schedule.enabled}
                        className="flex items-center gap-2 px-3 py-1.5 bg-green-500/20 text-green-400 border border-green-500/30 rounded-lg text-xs font-medium hover:bg-green-500/30 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        <Play className="w-3 h-3" />
                        Run Now
                      </button>
                      <button
                        onClick={() => setEditModal(schedule)}
                        className="p-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/30 transition-colors"
                      >
                        <Edit className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => deleteSchedule(schedule.id)}
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

        {/* Quick Templates */}
        <div className="bg-gradient-to-r from-cyan-500/10 to-blue-500/10 backdrop-blur-md border border-cyan-500/30 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-white mb-3">Quick Templates</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <button
              onClick={() =>
                setCreateModal({
                  template: 'daily',
                  name: 'Daily Full Scan',
                  frequency: 'daily',
                  time: '02:00',
                })
              }
              className="p-3 bg-white/5 border border-white/10 rounded-lg hover:bg-white/10 transition-colors text-left"
            >
              <div className="text-sm font-medium text-white mb-1">Daily Scan</div>
              <div className="text-xs text-gray-400">Run comprehensive scan every day at 2 AM</div>
            </button>
            <button
              onClick={() =>
                setCreateModal({
                  template: 'weekly',
                  name: 'Weekly Deep Scan',
                  frequency: 'weekly',
                  day: 'sunday',
                })
              }
              className="p-3 bg-white/5 border border-white/10 rounded-lg hover:bg-white/10 transition-colors text-left"
            >
              <div className="text-sm font-medium text-white mb-1">Weekly Scan</div>
              <div className="text-xs text-gray-400">Deep scan every Sunday</div>
            </button>
            <button
              onClick={() =>
                setCreateModal({
                  template: 'custom',
                  name: 'Custom Schedule',
                })
              }
              className="p-3 bg-white/5 border border-white/10 rounded-lg hover:bg-white/10 transition-colors text-left"
            >
              <div className="text-sm font-medium text-white mb-1">Custom Cron</div>
              <div className="text-xs text-gray-400">Advanced cron expression</div>
            </button>
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
  const [formData, setFormData] = useState({
    name: schedule?.name || template?.name || '',
    description: schedule?.description || '',
    enabled: schedule?.enabled ?? true,
    type: schedule?.type || template?.frequency || 'daily',
    cron: schedule?.cron || '',
    target_client: schedule?.target_client || '',
    engines: schedule?.engines || [],
  });
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    try {
      setSaving(true);
      if (schedule) {
        await api.put(`/api/scans/schedules/${schedule.id}`, formData);
      } else {
        await api.post('/api/scans/schedules', formData);
      }
      onSave();
    } catch (error) {
      console.error('Failed to save schedule:', error);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-white/10 rounded-xl max-w-2xl w-full p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-bold text-white">
            {schedule ? 'Edit Schedule' : 'Create Scan Schedule'}
          </h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors"
          >
            ✕
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Schedule Name</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              placeholder="Daily production scan"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Description</label>
            <input
              type="text"
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              placeholder="Run full security scan daily"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Frequency</label>
              <select
                value={formData.type}
                onChange={(e) => setFormData({ ...formData, type: e.target.value })}
                className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              >
                <option value="hourly">Hourly</option>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
                <option value="custom">Custom (Cron)</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Status</label>
              <select
                value={formData.enabled ? 'enabled' : 'disabled'}
                onChange={(e) =>
                  setFormData({ ...formData, enabled: e.target.value === 'enabled' })
                }
                className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              >
                <option value="enabled">Enabled</option>
                <option value="disabled">Disabled</option>
              </select>
            </div>
          </div>

          {formData.type === 'custom' && (
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Cron Expression
              </label>
              <input
                type="text"
                value={formData.cron}
                onChange={(e) => setFormData({ ...formData, cron: e.target.value })}
                className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white font-mono focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
                placeholder="0 2 * * *"
              />
              <div className="text-xs text-gray-500 mt-1">
                Example: 0 2 * * * (runs daily at 2:00 AM)
              </div>
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Target Client (optional)
            </label>
            <input
              type="text"
              value={formData.target_client}
              onChange={(e) => setFormData({ ...formData, target_client: e.target.value })}
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              placeholder="Leave empty for all clients"
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
            disabled={saving || !formData.name}
            className="flex-1 px-4 py-2 bg-cyan-500 text-white rounded-lg text-sm font-medium hover:bg-cyan-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {saving ? 'Saving...' : schedule ? 'Save Changes' : 'Create Schedule'}
          </button>
        </div>
      </div>
    </div>
  );
}
