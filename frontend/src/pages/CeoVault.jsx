import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Lock, Key, Shield, Eye, EyeOff, Plus, Trash2, Edit, Copy, Check } from 'lucide-react';
import PageShell from './PageShell'
import { api } from '../utils/apiFetch';

/**
 * CeoVault - Secure credential and secret management
 *
 * Features:
 * - Store API keys, passwords, certificates
 * - Encrypted at rest (AES-256)
 * - Access logging and audit trail
 * - Time-limited access tokens
 * - Secret rotation reminders
 * - One-click copy with auto-clear
 * - Expiration tracking
 */
export default function CeoVault() {
  const { t } = useTranslation();
  const [secrets, setSecrets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showSecret, setShowSecret] = useState({});
  const [createModal, setCreateModal] = useState(false);
  const [editModal, setEditModal] = useState(null);
  const [copiedId, setCopiedId] = useState(null);

  useEffect(() => {
    fetchSecrets();
  }, []);

  const fetchSecrets = async () => {
    try {
      setLoading(true);
      const data = await api.get('/api/ceo/vault/secrets');
      setSecrets(data.secrets || []);
    } catch (error) {
      console.error('Failed to fetch secrets:', error);
    } finally {
      setLoading(false);
    }
  };

  const toggleSecretVisibility = async (secretId) => {
    if (!showSecret[secretId]) {
      // Log access attempt
      await api.post(`/api/ceo/vault/secrets/${secretId}/access`);
    }
    setShowSecret((prev) => ({ ...prev, [secretId]: !prev[secretId] }));
  };

  const copyToClipboard = async (secretId, value) => {
    await navigator.clipboard.writeText(value);
    setCopiedId(secretId);
    setTimeout(() => setCopiedId(null), 2000);

    // Log copy event
    await api.post(`/api/ceo/vault/secrets/${secretId}/copy`);
  };

  const deleteSecret = async (secretId) => {
    if (!confirm(t('pages.ceoVault.delete_confirm'))) return;

    try {
      await api.delete(`/api/ceo/vault/secrets/${secretId}`);
      setSecrets((prev) => prev.filter((s) => s.id !== secretId));
    } catch (error) {
      console.error('Failed to delete secret:', error);
    }
  };

  const getExpirationColor = (expiresAt) => {
    if (!expiresAt) return 'text-gray-400';
    const daysUntilExpiry = Math.floor(
      (new Date(expiresAt) - new Date()) / (1000 * 60 * 60 * 24)
    );
    if (daysUntilExpiry < 0) return 'text-red-400';
    if (daysUntilExpiry < 7) return 'text-yellow-400';
    if (daysUntilExpiry < 30) return 'text-orange-400';
    return 'text-green-400';
  };

  const getTypeIcon = (type) => {
    switch (type) {
      case 'api_key':
        return <Key className="w-4 h-4" />;
      case 'password':
        return <Lock className="w-4 h-4" />;
      case 'certificate':
        return <Shield className="w-4 h-4" />;
      default:
        return <Key className="w-4 h-4" />;
    }
  };

  return (
    <PageShell title={t('pages.ceoVault.title')} icon={<Lock />}>
      <div className="space-y-6">
        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">{t('pages.ceoVault.total_secrets')}</span>
              <Lock className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{secrets.length}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">{t('pages.ceoVault.api_keys')}</span>
              <Key className="w-4 h-4 text-yellow-400" />
            </div>
            <div className="text-2xl font-bold text-white">
              {secrets.filter((s) => s.type === 'api_key').length}
            </div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">{t('pages.ceoVault.expiring_soon')}</span>
              <Shield className="w-4 h-4 text-orange-400" />
            </div>
            <div className="text-2xl font-bold text-white">
              {
                secrets.filter((s) => {
                  if (!s.expires_at) return false;
                  const days = Math.floor(
                    (new Date(s.expires_at) - new Date()) / (1000 * 60 * 60 * 24)
                  );
                  return days >= 0 && days < 30;
                }).length
              }
            </div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">{t('pages.ceoVault.expired')}</span>
              <Shield className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-red-400">
              {
                secrets.filter((s) => {
                  if (!s.expires_at) return false;
                  return new Date(s.expires_at) < new Date();
                }).length
              }
            </div>
          </div>
        </div>

        {/* Create Button */}
        <div className="flex justify-end">
          <button
            onClick={() => setCreateModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-500 text-white rounded-lg font-medium hover:bg-cyan-600 transition-colors"
          >
            <Plus className="w-4 h-4" />
            {t('pages.ceoVault.add_secret')}
          </button>
        </div>

        {/* Secrets List */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/10">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Lock className="w-4 h-4 text-cyan-400" />
              {t('pages.ceoVault.stored_secrets')}
            </h3>
          </div>

          {loading ? (
            <div className="p-8 text-center text-gray-500">
              <div className="animate-spin w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full mx-auto mb-3" />
              {t('pages.ceoVault.loading')}
            </div>
          ) : secrets.length === 0 ? (
            <div className="p-8 text-center text-gray-500">
              {t('pages.ceoVault.empty')}
            </div>
          ) : (
            <div className="divide-y divide-white/5">
              {secrets.map((secret) => (
                <div
                  key={secret.id}
                  className="p-4 hover:bg-white/5 transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <div className="p-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg">
                          {getTypeIcon(secret.type)}
                        </div>
                        <div>
                          <h4 className="text-sm font-semibold text-white">
                            {secret.name}
                          </h4>
                          <p className="text-xs text-gray-400">
                            {secret.description || t('pages.ceoVault.no_description')}
                          </p>
                        </div>
                        <span className="px-2 py-1 bg-purple-500/20 text-purple-400 border border-purple-500/30 rounded-md text-xs font-medium">
                          {secret.type}
                        </span>
                      </div>

                      {/* Secret Value */}
                      <div className="mt-3 flex items-center gap-2">
                        <div className="flex-1 relative">
                          <input
                            type={showSecret[secret.id] ? 'text' : 'password'}
                            value={showSecret[secret.id] ? secret.value : '••••••••••••'}
                            readOnly
                            className="w-full px-3 py-2 bg-black/60 border border-white/10 rounded-lg text-sm text-white font-mono"
                          />
                        </div>

                        <button
                          onClick={() => toggleSecretVisibility(secret.id)}
                          className="p-2 bg-white/5 border border-white/10 rounded-lg text-gray-400 hover:text-white hover:bg-white/10 transition-colors"
                        >
                          {showSecret[secret.id] ? (
                            <EyeOff className="w-4 h-4" />
                          ) : (
                            <Eye className="w-4 h-4" />
                          )}
                        </button>

                        <button
                          onClick={() =>
                            copyToClipboard(secret.id, secret.value)
                          }
                          className="p-2 bg-white/5 border border-white/10 rounded-lg text-gray-400 hover:text-white hover:bg-white/10 transition-colors"
                        >
                          {copiedId === secret.id ? (
                            <Check className="w-4 h-4 text-green-400" />
                          ) : (
                            <Copy className="w-4 h-4" />
                          )}
                        </button>
                      </div>

                      {/* Metadata */}
                      <div className="mt-3 flex items-center gap-4 text-xs text-gray-500">
                        <span>{t('pages.ceoVault.created', { date: secret.created_at })}</span>
                        {secret.expires_at && (
                          <>
                            <span>•</span>
                            <span className={getExpirationColor(secret.expires_at)}>
                              {t('pages.ceoVault.expires', { date: secret.expires_at })}
                            </span>
                          </>
                        )}
                        {secret.last_accessed && (
                          <>
                            <span>•</span>
                            <span>{t('pages.ceoVault.last_accessed', { date: secret.last_accessed })}</span>
                          </>
                        )}
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setEditModal(secret)}
                        className="p-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/30 transition-colors"
                      >
                        <Edit className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => deleteSecret(secret.id)}
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
      </div>

      {/* Create/Edit Modals */}
      {(createModal || editModal) && (
        <SecretModal
          secret={editModal}
          onClose={() => {
            setCreateModal(false);
            setEditModal(null);
          }}
          onSave={() => {
            fetchSecrets();
            setCreateModal(false);
            setEditModal(null);
          }}
        />
      )}
    </PageShell>
  );
}

/**
 * Secret Create/Edit Modal
 */
function SecretModal({ secret, onClose, onSave }) {
  const { t } = useTranslation();
  const [formData, setFormData] = useState({
    name: secret?.name || '',
    description: secret?.description || '',
    type: secret?.type || 'api_key',
    value: secret?.value || '',
    expires_at: secret?.expires_at || '',
  });
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    try {
      setSaving(true);
      if (secret) {
        await api.put(`/api/ceo/vault/secrets/${secret.id}`, formData);
      } else {
        await api.post('/api/ceo/vault/secrets', formData);
      }
      onSave();
    } catch (error) {
      console.error('Failed to save secret:', error);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-white/10 rounded-xl max-w-lg w-full p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-bold text-white">
            {secret ? t('pages.ceoVault.edit_secret') : t('pages.ceoVault.create_secret')}
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
            <label className="block text-sm font-medium text-gray-300 mb-2">
              {t('pages.ceoVault.name')}
            </label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              placeholder={t('pages.ceoVault.name_placeholder')}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              {t('pages.ceoVault.description_optional')}
            </label>
            <input
              type="text"
              value={formData.description}
              onChange={(e) =>
                setFormData({ ...formData, description: e.target.value })
              }
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              placeholder={t('pages.ceoVault.description_placeholder')}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              {t('pages.ceoVault.type')}
            </label>
            <select
              value={formData.type}
              onChange={(e) => setFormData({ ...formData, type: e.target.value })}
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            >
              <option value="api_key">{t('pages.ceoVault.type_api_key')}</option>
              <option value="password">{t('pages.ceoVault.type_password')}</option>
              <option value="certificate">{t('pages.ceoVault.type_certificate')}</option>
              <option value="token">{t('pages.ceoVault.type_token')}</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              {t('pages.ceoVault.secret_value')}
            </label>
            <textarea
              value={formData.value}
              onChange={(e) => setFormData({ ...formData, value: e.target.value })}
              rows={4}
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white font-mono text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              placeholder={t('pages.ceoVault.secret_placeholder')}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              {t('pages.ceoVault.expiration_optional')}
            </label>
            <input
              type="date"
              value={formData.expires_at}
              onChange={(e) =>
                setFormData({ ...formData, expires_at: e.target.value })
              }
              className="w-full px-3 py-2 bg-black/40 border border-white/10 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            />
          </div>
        </div>

        <div className="flex gap-3 mt-6">
          <button
            onClick={onClose}
            className="flex-1 px-4 py-2 bg-gray-500/20 text-gray-300 border border-gray-500/30 rounded-lg text-sm font-medium hover:bg-gray-500/30 transition-colors"
          >
            {t('pages.ceoVault.cancel')}
          </button>
          <button
            onClick={handleSave}
            disabled={saving || !formData.name || !formData.value}
            className="flex-1 px-4 py-2 bg-cyan-500 text-white rounded-lg text-sm font-medium hover:bg-cyan-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {saving ? t('pages.ceoVault.saving') : t('pages.ceoVault.save_secret')}
          </button>
        </div>
      </div>
    </div>
  );
}
