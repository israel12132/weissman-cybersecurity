import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Mail, Users, Link, AlertTriangle } from 'lucide-react';
import PageShell from './PageShell';
import { apiFetch } from '../lib/apiBase';

const TEMPLATES = [
  'Password Reset',
  'Invoice',
  'IT Support',
  'HR Notice',
  'Package Delivery',
  'Account Verification',
];

const TEMPLATE_I18N_KEYS = {
  'Password Reset': 'template_password_reset',
  Invoice: 'template_invoice',
  'IT Support': 'template_it_support',
  'HR Notice': 'template_hr_notice',
  'Package Delivery': 'template_package_delivery',
  'Account Verification': 'template_account_verification',
};

/**
 * SocialEngineering - Phishing & Social Engineering Simulator
 *
 * Features:
 * - Email phishing campaigns
 * - SMS phishing (smishing)
 * - Voice phishing (vishing)
 * - QR code phishing
 * - Awareness training
 * - User reporting
 */
export default function SocialEngineering() {
  const { t } = useTranslation();
  const [campaigns, setCampaigns] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [clients, setClients] = useState([]);
  const [createOpen, setCreateOpen] = useState(false);
  const [createTemplate, setCreateTemplate] = useState(TEMPLATES[0]);
  const [createName, setCreateName] = useState('');
  const [createClientId, setCreateClientId] = useState('');
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState('');

  const templateLabel = (template) =>
    t(`pages.socialEngineering.${TEMPLATE_I18N_KEYS[template]}`);

  useEffect(() => {
    fetchSocialEngineering();
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((data) => {
        const list = Array.isArray(data) ? data : data?.clients || [];
        setClients(list);
        if (list.length > 0) {
          setCreateClientId(String(list[0].id));
        }
      })
      .catch(() => {});
  }, []);

  const fetchSocialEngineering = async () => {
    try {
      const response = await apiFetch('/api/soc/social-engineering');
      if (response.ok) {
        const data = await response.json();
        setCampaigns(data.campaigns || []);
        setStats(data.stats || null);
      }
    } catch (error) {
      console.error('Failed to fetch social engineering data:', error);
    } finally {
      setLoading(false);
    }
  };

  const openCreateModal = (template = TEMPLATES[0]) => {
    setCreateTemplate(template);
    setCreateName(
      t('pages.socialEngineering.campaign_name_default', {
        template: templateLabel(template),
      })
    );
    setCreateError('');
    setCreateOpen(true);
  };

  const createCampaign = async () => {
    const name = createName.trim();
    const clientId = Number(createClientId);
    if (!name) {
      setCreateError(t('pages.socialEngineering.name_required'));
      return;
    }
    if (!clientId) {
      setCreateError(t('pages.socialEngineering.select_client'));
      return;
    }
    setCreating(true);
    setCreateError('');
    try {
      const response = await apiFetch('/api/soc/social-engineering/campaigns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name,
          client_id: clientId,
          template: createTemplate,
          campaign_type: 'email_phishing',
        }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        setCreateError(
          data.detail || data.error || t('pages.socialEngineering.create_failed')
        );
        return;
      }
      setCreateOpen(false);
      await fetchSocialEngineering();
    } catch (error) {
      setCreateError(error?.message || t('common.error'));
    } finally {
      setCreating(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'high':
        return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'medium':
        return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'low':
        return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30';
      default:
        return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
    }
  };

  const getStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'open':
        return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'closed':
      case 'resolved':
        return 'text-green-400 bg-green-500/10 border-green-500/30';
      default:
        return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
    }
  };

  const statValue = (key) => {
    if (loading) return '…';
    if (stats && stats[key] != null) return stats[key];
    return '—';
  };

  return (
    <PageShell title={t('pages.socialEngineering.title')} icon={<Users />}>
      <div className="space-y-6">
        {/* Campaign Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">
                {t('pages.socialEngineering.active_campaigns')}
              </span>
              <Mail className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{statValue('active')}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">
                {t('pages.socialEngineering.total_campaigns')}
              </span>
              <Link className="w-4 h-4 text-yellow-400" />
            </div>
            <div className="text-2xl font-bold text-white">{statValue('total_campaigns')}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">
                {t('pages.socialEngineering.critical_findings')}
              </span>
              <AlertTriangle className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-white">{statValue('critical_findings')}</div>
          </div>

          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">
                {t('pages.socialEngineering.assessments_loaded')}
              </span>
              <Users className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-white">
              {loading ? '…' : campaigns.length}
            </div>
          </div>
        </div>

        {/* Create Campaign */}
        <div className="bg-gradient-to-r from-purple-500/10 to-pink-500/10 backdrop-blur-md border border-purple-500/30 rounded-xl p-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white mb-1">
                {t('pages.socialEngineering.create_heading')}
              </h3>
              <p className="text-xs text-gray-400">
                {t('pages.socialEngineering.create_subtitle')}
              </p>
            </div>
            <button
              type="button"
              onClick={() => openCreateModal()}
              className="px-4 py-2 bg-purple-500 text-white rounded-lg text-sm font-medium hover:bg-purple-600 transition-colors"
            >
              {t('pages.socialEngineering.new_campaign')}
            </button>
          </div>
        </div>

        {/* Campaigns from findings */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/10">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Mail className="w-4 h-4 text-purple-400" />
              {t('pages.socialEngineering.assessments_heading')}
            </h3>
          </div>

          {loading ? (
            <div className="p-8 text-center text-gray-500">
              <div className="animate-spin w-8 h-8 border-2 border-purple-500 border-t-transparent rounded-full mx-auto mb-3" />
              {t('pages.socialEngineering.loading')}
            </div>
          ) : campaigns.length === 0 ? (
            <div className="p-8 text-center text-gray-500">
              {t('pages.socialEngineering.empty')}
            </div>
          ) : (
            <div className="divide-y divide-white/5">
              {campaigns.map((campaign) => (
                <div key={campaign.id} className="p-4 hover:bg-white/5 transition-colors">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-2 flex-wrap">
                        <h4 className="text-sm font-semibold text-white">
                          {campaign.name || t('pages.socialEngineering.untitled')}
                        </h4>
                        {campaign.severity && (
                          <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(campaign.severity)}`}>
                            {campaign.severity}
                          </span>
                        )}
                        {campaign.status && (
                          <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(campaign.status)}`}>
                            {campaign.status}
                          </span>
                        )}
                      </div>
                      {campaign.description && (
                        <p className="text-xs text-gray-400 mb-2 line-clamp-2">{campaign.description}</p>
                      )}
                      <div className="flex items-center gap-3 text-xs text-gray-500">
                        <span>
                          {campaign.type?.replace(/_/g, ' ') ||
                            t('pages.socialEngineering.type_fallback')}
                        </span>
                        {campaign.started_at && (
                          <>
                            <span>•</span>
                            <span>{new Date(campaign.started_at).toLocaleDateString()}</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Templates */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-white mb-4">
            {t('pages.socialEngineering.templates_heading')}
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {TEMPLATES.map((template) => (
              <div
                key={template}
                role="button"
                tabIndex={0}
                onClick={() => openCreateModal(template)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') openCreateModal(template);
                }}
                className="p-4 bg-gradient-to-br from-gray-800/50 to-gray-900/50 border border-white/10 rounded-lg hover:border-purple-500/30 transition-colors cursor-pointer"
              >
                <Mail className="w-5 h-5 text-purple-400 mb-2" />
                <h4 className="text-sm font-medium text-white mb-1">{templateLabel(template)}</h4>
                <p className="text-xs text-gray-500">{t('pages.socialEngineering.click_preview')}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {createOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="w-full max-w-md rounded-xl border border-white/10 bg-gray-900 p-6 shadow-xl">
            <h3 className="mb-4 text-lg font-semibold text-white">
              {t('pages.socialEngineering.create_modal_title')}
            </h3>
            <div className="space-y-4">
              <div>
                <label className="mb-1 block text-xs text-gray-400">
                  {t('pages.socialEngineering.campaign_name_label')}
                </label>
                <input
                  type="text"
                  value={createName}
                  onChange={(e) => setCreateName(e.target.value)}
                  className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-gray-400">
                  {t('pages.socialEngineering.template_label')}
                </label>
                <select
                  value={createTemplate}
                  onChange={(e) => setCreateTemplate(e.target.value)}
                  className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
                >
                  {TEMPLATES.map((template) => (
                    <option key={template} value={template}>
                      {templateLabel(template)}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs text-gray-400">{t('common.client')}</label>
                <select
                  value={createClientId}
                  onChange={(e) => setCreateClientId(e.target.value)}
                  className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
                >
                  {clients.length === 0 ? (
                    <option value="">{t('pages.socialEngineering.no_clients')}</option>
                  ) : (
                    clients.map((client) => (
                      <option key={client.id} value={client.id}>
                        {client.name || `${t('common.client')} ${client.id}`}
                      </option>
                    ))
                  )}
                </select>
              </div>
              {createError && <p className="text-sm text-red-400">{createError}</p>}
            </div>
            <div className="mt-6 flex justify-end gap-3">
              <button
                type="button"
                onClick={() => setCreateOpen(false)}
                className="rounded-lg border border-white/10 px-4 py-2 text-sm text-gray-300 hover:bg-white/5"
              >
                {t('common.cancel')}
              </button>
              <button
                type="button"
                onClick={createCampaign}
                disabled={creating || clients.length === 0}
                className="rounded-lg bg-purple-500 px-4 py-2 text-sm font-medium text-white hover:bg-purple-600 disabled:opacity-50"
              >
                {creating
                  ? t('pages.socialEngineering.creating')
                  : t('pages.socialEngineering.create_campaign')}
              </button>
            </div>
          </div>
        </div>
      )}
    </PageShell>
  );
}
