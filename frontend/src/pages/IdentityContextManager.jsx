import { useState, useEffect, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Users, Shield, Key, AlertTriangle, Clock, X, ArrowRight } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar'
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench'
import { api } from '../utils/apiFetch';
import { useFirstTenantClientId, withClientId } from '../lib/aliasClient';

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
  const { t } = useTranslation();
  const { clientId, loading: clientLoading } = useFirstTenantClientId();
  const [identities, setIdentities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedIdentity, setSelectedIdentity] = useState(null);

  useEffect(() => {
    if (clientLoading) return;
    if (clientId == null) {
      setIdentities([]);
      setLoading(false);
      return;
    }
    fetchIdentities(clientId);
  }, [clientId, clientLoading]);

  const fetchIdentities = async (cid) => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.get(withClientId('/api/identity/contexts', cid));
      setIdentities(data.identities || []);
    } catch (err) {
      console.error('Failed to fetch identities:', err);
      setError(t('pages.identityContextManager.load_error'));
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

  const listFindings = useMemo(() => identities.map((i) => ({
    id: i.id,
    severity: i.risk_score >= 75 ? 'critical' : i.risk_score >= 50 ? 'high' : 'info',
    title: i.username || i.email || i.id,
    type: i.is_privileged ? 'privileged' : 'identity',
    description: `Risk ${i.risk_score ?? 0}`,
    resource: String(i.anomaly_count ?? 0),
  })), [identities])

  const {
    exportCsv,
    filteredFindings,
    searchQuery,
    setSearchQuery,
  } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-identities',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  const visibleIdentities = useMemo(() => {
    if (!searchQuery.trim()) return identities
    const ids = new Set(filteredFindings.map((f) => f.id))
    return identities.filter((i) => ids.has(i.id))
  }, [identities, filteredFindings, searchQuery])

  const reloadIdentities = () => {
    if (clientId != null) fetchIdentities(clientId)
  }

  return (
    <PageShell
      title={t('pages.identityContextManager.title')}
      icon={<Users />}
      actions={(
        <ShellScanActions
          onRefresh={reloadIdentities}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="space-y-6">
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-xl border border-cyan-500/30 bg-gradient-to-r from-cyan-950/40 to-violet-950/30 p-5"
        >
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="p-2 rounded-lg bg-cyan-500/20 border border-cyan-500/30">
                <Shield className="w-5 h-5 text-cyan-400" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-white mb-1">
                  {t('pages.identityContextManager.oauth_hub_title')}
                </h3>
                <p className="text-xs text-gray-400 max-w-xl">
                  {t('pages.identityContextManager.oauth_hub_body', { })}
                </p>
              </div>
            </div>
            <Link
              to="/identity-security"
              className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-cyan-500/20 border border-cyan-500/40 text-cyan-200 text-sm font-medium hover:bg-cyan-500/30 transition-colors shrink-0"
            >
              {t('pages.identityContextManager.oauth_hub_cta')}
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </motion.div>

        {/* Error Banner */}
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="rounded-xl border border-amber-500/30 bg-amber-950/20 px-4 py-3"
          >
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
              <div className="flex-1">
                <span className="text-sm font-mono text-amber-300/90">{error}</span>
              </div>
              <button
                onClick={() => clientId != null && fetchIdentities(clientId)}
                className="text-xs text-amber-400 hover:text-amber-300 font-medium transition-colors"
              >
                {t('pages.identityContextManager.retry')}
              </button>
            </div>
          </motion.div>
        )}

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl p-4"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">{t('pages.identityContextManager.total_identities')}</span>
              <Users className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{stats.total}</div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="bg-red-500/10 backdrop-blur-md border border-red-500/30 rounded-xl p-4"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-red-400">{t('pages.identityContextManager.high_risk')}</span>
              <AlertTriangle className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-red-400">{stats.highRisk}</div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="bg-purple-500/10 backdrop-blur-md border border-purple-500/30 rounded-xl p-4"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-purple-400">{t('pages.identityContextManager.privileged')}</span>
              <Key className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-purple-400">{stats.privileged}</div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="bg-yellow-500/10 backdrop-blur-md border border-yellow-500/30 rounded-xl p-4"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-yellow-400">{t('pages.identityContextManager.anomalies')}</span>
              <AlertTriangle className="w-4 h-4 text-yellow-400" />
            </div>
            <div className="text-2xl font-bold text-yellow-400">{stats.anomalies}</div>
          </motion.div>
        </div>

        {/* Identities List */}
        <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl overflow-hidden">
          <div className="p-4 border-b border-[var(--border-default)] space-y-3">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Users className="w-4 h-4 text-cyan-400" />
              {t('pages.identityContextManager.identities_heading', { count: identities.length })}
            </h3>
            <WeissmanListToolbar
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              resultCount={visibleIdentities.length}
              totalCount={identities.length}
            />
          </div>

          {loading ? (
            <div className="p-12 text-center">
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                className="w-10 h-10 border-3 border-cyan-500/30 border-t-cyan-500 rounded-full mx-auto mb-4"
              />
              <p className="text-sm text-gray-400 font-mono">{t('pages.identityContextManager.loading')}</p>
            </div>
          ) : identities.length === 0 ? (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="p-12 text-center"
            >
              <Users className="w-12 h-12 text-gray-600 mx-auto mb-3" />
              <p className="text-sm text-gray-400 mb-2">{t('pages.identityContextManager.empty_title')}</p>
              <p className="text-xs text-gray-500">{t('pages.identityContextManager.empty_body')}</p>
            </motion.div>
          ) : visibleIdentities.length === 0 ? (
            <div className="p-12 text-center text-gray-500">{t('weissmanFindings.filtered_title')}</div>
          ) : (
            <div className="divide-y divide-[var(--border-subtle)] max-h-[70vh] overflow-y-auto">
              {visibleIdentities.map((identity, index) => (
                <motion.div
                  key={identity.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.05, duration: 0.3 }}
                  className="p-4 hover:bg-[var(--row-hover-bg)] transition-all cursor-pointer group"
                  onClick={() => setSelectedIdentity(identity)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => e.key === 'Enter' && setSelectedIdentity(identity)}
                  aria-label={t('pages.identityContextManager.view_details', { username: identity.username })}
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
                              {t('pages.identityContextManager.privileged_badge')}
                            </span>
                          )}
                          <span
                            className={`px-2 py-1 rounded text-xs font-medium border ${getRiskColor(
                              identity.risk_score
                            )}`}
                          >
                            {t('pages.identityContextManager.risk_score', { score: identity.risk_score })}
                          </span>
                        </div>

                        <div className="flex items-center gap-4 text-xs text-gray-500">
                          <span>{t('pages.identityContextManager.email', { email: identity.email })}</span>
                          {identity.last_login && (
                            <>
                              <span>•</span>
                              <span className="flex items-center gap-1">
                                <Clock className="w-3 h-3" />
                                {t('pages.identityContextManager.last_login', {
                                  time: new Date(identity.last_login).toLocaleString(),
                                })}
                              </span>
                            </>
                          )}
                          {identity.anomaly_count > 0 && (
                            <>
                              <span>•</span>
                              <span className="text-yellow-400">
                                {t('pages.identityContextManager.anomaly_count', { count: identity.anomaly_count })}
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
                </motion.div>
              ))}
            </div>
          )}
        </div>

        {/* High Risk Alert */}
        {stats.highRisk > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-red-500/10 border border-red-500/30 rounded-xl p-6"
          >
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              <h3 className="text-sm font-semibold text-white">{t('pages.identityContextManager.high_risk_title')}</h3>
            </div>
            <p className="text-sm text-gray-300">
              {t('pages.identityContextManager.high_risk_body', { count: stats.highRisk })}
            </p>
          </motion.div>
        )}
      </div>

      {/* Identity Detail Modal */}
      <AnimatePresence>
        {selectedIdentity && (
          <IdentityDetailModal
            identity={selectedIdentity}
            onClose={() => setSelectedIdentity(null)}
          />
        )}
      </AnimatePresence>
    </PageShell>
  );
}

/**
 * Identity Detail Modal
 */
function IdentityDetailModal({ identity, onClose }) {
  const { t } = useTranslation();

  // Close on Escape key
  useEffect(() => {
    const handleEsc = (e) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [onClose]);

  return (
    <>
      {/* Backdrop */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        onClick={onClose}
        className="fixed inset-0 bg-[var(--bg-3)] backdrop-blur-sm z-50"
        aria-hidden="true"
      />

      {/* Modal */}
      <div className="fixed inset-0 flex items-center justify-center z-50 p-4 pointer-events-none">
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          transition={{ type: "spring", duration: 0.5 }}
          className="bg-gray-900 border border-[var(--border-default)] rounded-xl max-w-2xl w-full p-6 pointer-events-auto shadow-2xl"
          role="dialog"
          aria-modal="true"
          aria-labelledby="modal-title"
        >
          <div className="flex items-center justify-between mb-6">
            <h3 id="modal-title" className="text-lg font-bold text-white">{identity.username}</h3>
            <button
              onClick={onClose}
              className="p-1 text-gray-400 hover:text-[var(--text-primary)] hover:bg-[var(--row-hover-bg)] rounded-lg transition-all"
              aria-label={t('pages.identityContextManager.close_modal')}
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 }}
              >
                <span className="text-xs text-gray-400 block mb-1">{t('pages.identityContextManager.email_label')}</span>
                <div className="text-sm text-white">{identity.email}</div>
              </motion.div>
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.15 }}
              >
                <span className="text-xs text-gray-400 block mb-1">{t('pages.identityContextManager.risk_score_label')}</span>
                <div className="text-sm font-semibold text-white">{identity.risk_score}</div>
              </motion.div>
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 }}
              >
                <span className="text-xs text-gray-400 block mb-1">{t('pages.identityContextManager.last_login_label')}</span>
                <div className="text-sm text-white">
                  {identity.last_login ? new Date(identity.last_login).toLocaleString() : t('pages.identityContextManager.never')}
                </div>
              </motion.div>
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.25 }}
              >
                <span className="text-xs text-gray-400 block mb-1">{t('pages.identityContextManager.anomalies_label')}</span>
                <div className="text-sm text-white">{identity.anomaly_count || 0}</div>
              </motion.div>
            </div>

            {/* Recent Activity */}
            {identity.recent_activity && identity.recent_activity.length > 0 && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
              >
                <h4 className="text-sm font-semibold text-white mb-3">{t('pages.identityContextManager.recent_activity')}</h4>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {identity.recent_activity.map((activity, i) => (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: 0.35 + i * 0.05 }}
                      className="text-xs text-gray-400 p-3 bg-[var(--row-hover-bg)] rounded-lg border border-[var(--border-subtle)] hover:bg-[var(--row-hover-bg)] transition-colors"
                    >
                      <div className="flex items-center justify-between">
                        <span>{activity.description}</span>
                        <span className="text-gray-500 text-[10px]">
                          {new Date(activity.timestamp).toLocaleString()}
                        </span>
                      </div>
                    </motion.div>
                  ))}
                </div>
              </motion.div>
            )}
          </div>

          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.4 }}
            className="mt-6"
          >
            <button
              onClick={onClose}
              className="w-full px-4 py-2 bg-cyan-500 text-white rounded-lg text-sm font-medium hover:bg-cyan-600 transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:ring-offset-2 focus:ring-offset-gray-900"
            >
              {t('pages.identityContextManager.close')}
            </button>
          </motion.div>
        </motion.div>
      </div>
    </>
  );
}
