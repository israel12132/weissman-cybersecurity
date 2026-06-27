import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useState, useEffect, useCallback, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  Mail, Users, AlertTriangle, Play, Shield,
} from 'lucide-react';
import PageShell from './PageShell';
import ShellScanActions from '../components/engine/ShellScanActions';
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel';
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench';
import { apiFetch } from '../lib/apiBase';
import { clientPrimaryTargetUrl } from '../lib/clientTarget';
import { useJobPoll } from '../lib/useJobPoll';

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

const ASSESSMENT_ENGINE = 'spear_phishing';

export default function SocialEngineering() {
  const { t } = useTranslation();
  const [campaigns, setCampaigns] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [clients, setClients] = useState([]);
  const [createOpen, setCreateOpen] = useState(false);
  const [createTemplate, setCreateTemplate] = useState(TEMPLATES[0]);
  const [createName, setCreateName] = useState('');
  const [createClientId, setCreateClientId] = useState('');
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState('');
  const [scanClientId, setScanClientId] = useState('');
  const { postScan } = useCommandCenterScan(scanClientId)
  const [scanning, setScanning] = useState(false);
  const [scanJobId, setScanJobId] = useState(null);

  const templateLabel = (template) =>
    t(`pages.socialEngineering.${TEMPLATE_I18N_KEYS[template]}`);

  const fetchSocialEngineering = useCallback(async () => {
    try {
      setLoading(true);
      setError('');
      const response = await apiFetch('/api/soc/social-engineering');
      if (response.ok) {
        const data = await response.json();
        setCampaigns(data.campaigns || []);
        setStats(data.stats || null);
      } else {
        setError(t('pages.socialEngineering.load_failed'));
      }
    } catch (err) {
      setError(err?.message || t('pages.socialEngineering.load_failed'));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    fetchSocialEngineering();
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((data) => {
        const list = Array.isArray(data) ? data : data?.clients || [];
        setClients(list);
        if (list.length > 0) {
          const id = String(list[0].id);
          setCreateClientId(id);
          setScanClientId(id);
        }
      })
      .catch(() => {});
  }, [fetchSocialEngineering]);

  useJobPoll(scanJobId, {
    enabled: Boolean(scanJobId),
    onComplete: () => {
      setScanJobId(null);
      setScanning(false);
      fetchSocialEngineering();
    },
  });

  const runAssessment = async () => {
    const client = clients.find((c) => String(c.id) === String(scanClientId));
    const target = clientPrimaryTargetUrl(client);
    if (!target) {
      setError(t('pages.socialEngineering.missing_target'));
      return;
    }
    setScanning(true);
    setError('');
    try {
      const { ok, data: d } = await postScan({
        engine: ASSESSMENT_ENGINE,
        client_id: Number(scanClientId),
        target,
      });
      if (!ok) throw new Error(d.detail || d.error || t('pages.socialEngineering.scan_failed'));
      if (d.job_id) setScanJobId(String(d.job_id));
      else {
        setScanning(false);
        await fetchSocialEngineering();
      }
    } catch (e) {
      setError(e?.message || t('pages.socialEngineering.scan_failed'));
      setScanning(false);
    }
  };

  const openCreateModal = (template = TEMPLATES[0]) => {
    setCreateTemplate(template);
    setCreateName(
      t('pages.socialEngineering.campaign_name_default', {
        template: templateLabel(template),
      }),
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
        setCreateError(data.detail || data.error || t('pages.socialEngineering.create_failed'));
        return;
      }
      setCreateOpen(false);
      await fetchSocialEngineering();
    } catch (err) {
      setCreateError(err?.message || t('common.error'));
    } finally {
      setCreating(false);
    }
  };

  const campaignFindings = useMemo(() => campaigns.map((c) => ({
    title: c.name || t('pages.socialEngineering.untitled'),
    type: c.type?.replace(/_/g, ' ') || t('pages.socialEngineering.type_fallback'),
    severity: String(c.severity || 'info').toLowerCase(),
    description: c.description || '',
    remediation: c.status ? `Status: ${c.status}` : '',
    resource: c.id,
    component: c.started_at ? new Date(c.started_at).toLocaleDateString() : '',
  })), [campaigns, t]);

  const {
    filteredFindings,
    counts,
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    exportCsv,
    total,
  } = useFindingsWorkbench(campaignFindings, { csvPrefix: 'weissman-social-engineering' });

  const severityDistribution = useMemo(() => {
    const dist = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const c of campaigns) {
      const s = String(c.severity || 'info').toLowerCase();
      if (dist[s] != null) dist[s] += 1;
    }
    return dist;
  }, [campaigns]);

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'high': return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'low': return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30';
      default: return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
    }
  };

  const getStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'open': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'closed':
      case 'resolved': return 'text-green-400 bg-green-500/10 border-green-500/30';
      default: return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
    }
  };

  const statValue = (key) => {
    if (loading) return '…';
    if (stats && stats[key] != null) return stats[key];
    return '—';
  };

  return (
    <PageShell
      title={t('pages.socialEngineering.title')}
      subtitle={t('pages.socialEngineering.subtitle')}
      icon={<Users />}
      actions={(
        <ShellScanActions
          onRefresh={fetchSocialEngineering}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="space-y-6">
        <div className="rounded-xl border border-purple-500/20 bg-purple-950/20 px-4 py-3 text-xs text-purple-100/75 leading-relaxed">
          {t('pages.socialEngineering.data_notice')}
        </div>

        {error && (
          <div className="rounded-xl border border-rose-500/30 bg-rose-950/30 px-4 py-3 text-sm text-rose-200">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">{t('pages.socialEngineering.active_campaigns')}</span>
              <Mail className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-white">{statValue('active')}</div>
          </div>
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">{t('pages.socialEngineering.total_campaigns')}</span>
              <Users className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold text-white">{statValue('total_campaigns')}</div>
          </div>
          <div className="bg-red-500/10 backdrop-blur-md border border-red-500/30 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-red-400">{t('pages.socialEngineering.critical_findings')}</span>
              <AlertTriangle className="w-4 h-4 text-red-400" />
            </div>
            <div className="text-2xl font-bold text-red-400">{statValue('critical_findings')}</div>
          </div>
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">{t('pages.socialEngineering.assessments_loaded')}</span>
              <Shield className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-2xl font-bold text-white">{loading ? '…' : campaigns.length}</div>
          </div>
        </div>

        {campaigns.length > 0 && (
          <div className="rounded-xl border border-white/10 bg-black/40 p-4">
            <div className="text-[10px] font-mono text-white/40 uppercase mb-2">{t('pages.socialEngineering.severity_distribution')}</div>
            <div className="flex h-2 rounded-full overflow-hidden">
              {['critical', 'high', 'medium', 'low', 'info'].map((sev) => {
                const count = severityDistribution[sev] || 0;
                const colors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22d3ee', info: '#6b7280' };
                return count > 0 ? (
                  <div key={sev} style={{ width: `${(count / campaigns.length) * 100}%`, backgroundColor: colors[sev] }} title={`${sev}: ${count}`} />
                ) : null;
              })}
            </div>
          </div>
        )}

        <div className="bg-gradient-to-r from-purple-500/10 to-pink-500/10 backdrop-blur-md border border-purple-500/30 rounded-xl p-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-semibold text-white mb-1">{t('pages.socialEngineering.run_assessment_heading')}</h3>
              <p className="text-xs text-gray-400">{t('pages.socialEngineering.run_assessment_subtitle', { engine: ASSESSMENT_ENGINE })}</p>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <select
                value={scanClientId}
                onChange={(e) => setScanClientId(e.target.value)}
                className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-xs text-white font-mono"
              >
                {clients.map((c) => (
                  <option key={c.id} value={c.id}>{c.name}</option>
                ))}
              </select>
              <button
                type="button"
                onClick={runAssessment}
                disabled={scanning || !scanClientId || Boolean(scanJobId)}
                className="flex items-center gap-2 px-4 py-2 bg-purple-500 text-white rounded-lg text-sm font-medium hover:bg-purple-600 disabled:opacity-50 transition-colors"
              >
                <Play className="w-4 h-4" />
                {scanning || scanJobId ? t('pages.socialEngineering.scanning') : t('pages.socialEngineering.run_assessment')}
              </button>
              <button
                type="button"
                onClick={() => openCreateModal()}
                className="px-4 py-2 border border-purple-500/40 text-purple-200 rounded-lg text-sm font-medium hover:bg-purple-500/10 transition-colors"
              >
                {t('pages.socialEngineering.new_campaign')}
              </button>
            </div>
          </div>
        </div>

        <div className="flex items-center justify-end">
          <Link to="/findings" className="text-xs text-cyan-400 hover:text-cyan-300 font-mono">
            {t('pages.socialEngineering.view_findings')}
          </Link>
        </div>

        <WeissmanFindingsPanel
          findings={campaignFindings}
          filteredFindings={filteredFindings}
          counts={counts}
          total={total}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          severityFilter={severityFilter}
          onSeverityChange={setSeverityFilter}
          loading={loading && !campaignFindings.length}
          accent="#a855f7"
          title={t('pages.socialEngineering.assessments_heading')}
          emptyTitle={t('pages.socialEngineering.empty_title')}
          emptyBody={t('pages.socialEngineering.empty')}
          renderFinding={(f, i) => {
            const statusMatch = f.remediation?.match(/Status:\s*(.+)/i);
            const status = statusMatch?.[1];
            return (
              <div key={i} className="p-4 rounded-lg border border-white/10 bg-black/30 hover:bg-white/5 transition-colors">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-2 flex-wrap">
                      <h4 className="text-sm font-semibold text-white">{f.title}</h4>
                      {f.severity && (
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(f.severity)}`}>
                          {f.severity}
                        </span>
                      )}
                      {status && (
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(status)}`}>
                          {status}
                        </span>
                      )}
                    </div>
                    {f.description && (
                      <p className="text-xs text-gray-400 mb-2 line-clamp-2">{f.description}</p>
                    )}
                    <div className="flex items-center gap-3 text-xs text-gray-500">
                      <span>{f.type}</span>
                      {f.component && (
                        <>
                          <span>•</span>
                          <span>{f.component}</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            );
          }}
        />

        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-white mb-1">{t('pages.socialEngineering.templates_heading')}</h3>
          <p className="text-xs text-white/40 mb-4">{t('pages.socialEngineering.templates_notice')}</p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {TEMPLATES.map((template) => (
              <button
                key={template}
                type="button"
                onClick={() => openCreateModal(template)}
                className="p-4 text-left bg-gradient-to-br from-gray-800/50 to-gray-900/50 border border-white/10 rounded-lg hover:border-purple-500/30 transition-colors"
              >
                <Mail className="w-5 h-5 text-purple-400 mb-2" />
                <h4 className="text-sm font-medium text-white mb-1">{templateLabel(template)}</h4>
                <p className="text-xs text-gray-500">{t('pages.socialEngineering.click_create')}</p>
              </button>
            ))}
          </div>
        </div>
      </div>

      {createOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
          <div className="w-full max-w-md rounded-xl border border-white/10 bg-gray-900 p-6 shadow-xl">
            <h3 className="mb-4 text-lg font-semibold text-white">{t('pages.socialEngineering.create_modal_title')}</h3>
            <div className="space-y-4">
              <div>
                <label className="mb-1 block text-xs text-gray-400">{t('pages.socialEngineering.campaign_name_label')}</label>
                <input type="text" value={createName} onChange={(e) => setCreateName(e.target.value)} className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white" />
              </div>
              <div>
                <label className="mb-1 block text-xs text-gray-400">{t('pages.socialEngineering.template_label')}</label>
                <select value={createTemplate} onChange={(e) => setCreateTemplate(e.target.value)} className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white">
                  {TEMPLATES.map((template) => (
                    <option key={template} value={template}>{templateLabel(template)}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs text-gray-400">{t('common.client')}</label>
                <select value={createClientId} onChange={(e) => setCreateClientId(e.target.value)} className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white">
                  {clients.length === 0 ? (
                    <option value="">{t('pages.socialEngineering.no_clients')}</option>
                  ) : (
                    clients.map((client) => (
                      <option key={client.id} value={client.id}>{client.name || `${t('common.client')} ${client.id}`}</option>
                    ))
                  )}
                </select>
              </div>
              {createError && <p className="text-sm text-red-400">{createError}</p>}
            </div>
            <div className="mt-6 flex justify-end gap-3">
              <button type="button" onClick={() => setCreateOpen(false)} className="rounded-lg border border-white/10 px-4 py-2 text-sm text-gray-300 hover:bg-white/5">{t('common.cancel')}</button>
              <button type="button" onClick={createCampaign} disabled={creating || clients.length === 0} className="rounded-lg bg-purple-500 px-4 py-2 text-sm font-medium text-white hover:bg-purple-600 disabled:opacity-50">
                {creating ? t('pages.socialEngineering.creating') : t('pages.socialEngineering.create_campaign')}
              </button>
            </div>
          </div>
        </div>
      )}
    </PageShell>
  );
}
