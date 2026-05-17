import { useState, useEffect } from 'react';
import { Users, Shield, Key, AlertTriangle, CheckCircle, Clock } from 'lucide-react';
import PageShell from './PageShell'
import { api } from '../utils/apiFetch';

/**
 * IdentityContextManager - User identity and access context tracking
 *
 * Features:
 * - User behavior profiling
 * - Access pattern analysis
 * - Privilege escalation detection
 * - Session anomaly detection
 * - Identity risk scoring
 * - UEBA (User and Entity Behavior Analytics)
 * - Insider threat detection
 */
export default function IdentityContextManager() {
  const [identities, setIdentities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedIdentity, setSelectedIdentity] = useState(null);

  useEffect(() => {
    fetchIdentities();
  }, []);

  const fetchIdentities = async () => {
    try {
      setLoading(true);
      const data = await api.get('/api/identity/contexts');
      setIdentities(data.identities || []);
    } catch (error) {
      console.error('Failed to fetch identities:', error);
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (risk) => {
    if (risk >= 75) return 'text-red-400 bg-red-500/10 border-red-500/30';
    if (risk >= 50) return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
    if (risk >= 25) return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
    return 'text-green-400 bg-green-500/10 border-green-500/30';
  };

  const stats = {
    total: identities.length,
    highRisk: identities.filter((i) => i.risk_score >= 75).length,
    privileged: identities.filter((i) => i.is_privileged).length,
    anomalies: identities.reduce((sum, i) => sum + (i.anomaly_count || 0), 0),
  };

  return (
    <PageShell title="Identity Context Manager" icon={<Users />}>
      <div className="space-y-6">
        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Total Identities</span>
              <Users className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{stats.total}</div>
          </div>

          <div className="bg-red-500/10 backdrop-blur-md border border-red-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-red-400">High Risk</span>
              <AlertTriangle className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-red-400">{stats.highRisk}</div>
          </div>

          <div className="bg-purple-500/10 backdrop-blur-md border border-purple-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-purple-400">Privileged</span>
              <Key className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-purple-400">{stats.privileged}</div>
          </div>

          <div className="bg-yellow-500/10 backdrop-blur-md border border-yellow-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-yellow-400">Anomalies</span>
              <AlertTriangle className="w-4 h-4 text-yellow-400" />
            </div>
            <div className="text-2xl font-bold text-yellow-400">{stats.anomalies}</div>
          </div>
        </div>

        {/* Identities List */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/10">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Users className="w-4 h-4 text-cyan-400" />
              User Identities ({identities.length})
            </h3>
          </div>

          {loading ? (
            <div className="p-8 text-center text-gray-500">
              <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
              Loading identities...
            </div>
          ) : identities.length === 0 ? (
            <div className="p-8 text-center text-gray-500">No identities found</div>
          ) : (
            <div className="divide-y divide-white/5 max-h-[600px] overflow-y-auto">
              {identities.map((identity) => (
                <div
                  key={identity.id}
                  className="p-4 hover:bg-white/5 transition-colors cursor-pointer"
                  onClick={() => setSelectedIdentity(identity)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3 flex-1">
                      <div className="p-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg">
                        <Users className="w-4 h-4" />
                      </div>

                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <h4 className="text-sm font-semibold text-white">{identity.username}</h4>
                          {identity.is_privileged && (
                            <span className="px-2 py-1 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded text-xs font-medium">
                              PRIVILEGED
                            </span>
                          )}
                          <span
                            className={`px-2 py-1 rounded text-xs font-medium border ${getRiskColor(
                              identity.risk_score
                            )}`}
                          >
                            Risk: {identity.risk_score}
                          </span>
                        </div>

                        <div className="flex items-center gap-4 text-xs text-gray-500">
                          <span>Email: {identity.email}</span>
                          {identity.last_login && (
                            <>
                              <span>•</span>
                              <span className="flex items-center gap-1">
                                <Clock className="w-3 h-3" />
                                Last login: {new Date(identity.last_login).toLocaleString()}
                              </span>
                            </>
                          )}
                          {identity.anomaly_count > 0 && (
                            <>
                              <span>•</span>
                              <span className="text-yellow-400">
                                {identity.anomaly_count} anomalies
                              </span>
                            </>
                          )}
                        </div>

                        {/* Roles */}
                        {identity.roles && identity.roles.length > 0 && (
                          <div className="flex gap-2 mt-2">
                            {identity.roles.map((role) => (
                              <span
                                key={role}
                                className="text-xs px-2 py-1 bg-blue-500/10 text-blue-400 border border-blue-500/20 rounded"
                              >
                                {role}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* High Risk Alert */}
        {stats.highRisk > 0 && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              <h3 className="text-sm font-semibold text-white">High Risk Identities Detected</h3>
            </div>
            <p className="text-sm text-gray-300">
              {stats.highRisk} users have been flagged as high risk. Review their activity immediately.
            </p>
          </div>
        )}
      </div>

      {/* Identity Detail Modal */}
      {selectedIdentity && (
        <IdentityDetailModal
          identity={selectedIdentity}
          onClose={() => setSelectedIdentity(null)}
        />
      )}
    </PageShell>
  );
}

/**
 * Identity Detail Modal
 */
function IdentityDetailModal({ identity, onClose }) {
  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-white/10 rounded-xl max-w-2xl w-full p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-bold text-white">{identity.username}</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-white">
            ✕
          </button>
        </div>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <span className="text-xs text-gray-400">Email</span>
              <div className="text-sm text-white">{identity.email}</div>
            </div>
            <div>
              <span className="text-xs text-gray-400">Risk Score</span>
              <div className="text-sm text-white">{identity.risk_score}</div>
            </div>
            <div>
              <span className="text-xs text-gray-400">Last Login</span>
              <div className="text-sm text-white">
                {identity.last_login ? new Date(identity.last_login).toLocaleString() : 'Never'}
              </div>
            </div>
            <div>
              <span className="text-xs text-gray-400">Anomalies</span>
              <div className="text-sm text-white">{identity.anomaly_count || 0}</div>
            </div>
          </div>

          {/* Recent Activity */}
          {identity.recent_activity && (
            <div>
              <h4 className="text-sm font-semibold text-white mb-2">Recent Activity</h4>
              <div className="space-y-2">
                {identity.recent_activity.map((activity, i) => (
                  <div key={i} className="text-xs text-gray-400 p-2 bg-white/5 rounded">
                    {activity.description} - {new Date(activity.timestamp).toLocaleString()}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="mt-6">
          <button
            onClick={onClose}
            className="w-full px-4 py-2 bg-cyan-500 text-white rounded-lg text-sm font-medium hover:bg-cyan-600 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
