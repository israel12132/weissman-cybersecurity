import React, { useState, useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Settings, Database, Shield, Zap, Globe, Lock, AlertTriangle, Save, RefreshCw, CheckCircle2, XCircle } from 'lucide-react';
import PageShell from './PageShell';
import ShellScanActions from '../components/engine/ShellScanActions';
import WeissmanListToolbar from '../components/engine/WeissmanListToolbar';
import EmptyState from '../components/ui/EmptyState';
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench';
import EvidenceNotice from '../components/ui/EvidenceNotice';
import { SkeletonBar } from '../components/ui/Skeleton';
import { api } from '../utils/apiFetch';
import { apiFetch } from '../lib/apiBase';
import Button from '../components/ui/Button'

const NS = 'pages.systemConfiguration';

const TIMEZONE_OPTIONS = [
  { value: 'UTC', labelKey: 'options.timezones.utc' },
  { value: 'America/New_York', labelKey: 'options.timezones.eastern' },
  { value: 'America/Los_Angeles', labelKey: 'options.timezones.pacific' },
  { value: 'Europe/London', labelKey: 'options.timezones.london' },
  { value: 'Asia/Tokyo', labelKey: 'options.timezones.tokyo' },
];

const LANGUAGE_OPTIONS = [
  { value: 'en', labelKey: 'options.languages.en' },
  { value: 'he', labelKey: 'options.languages.he' },
  { value: 'es', labelKey: 'options.languages.es' },
  { value: 'fr', labelKey: 'options.languages.fr' },
];

const DATE_FORMAT_OPTIONS = [
  { value: 'YYYY-MM-DD', labelKey: 'options.dateFormats.iso' },
  { value: 'MM/DD/YYYY', labelKey: 'options.dateFormats.us' },
  { value: 'DD/MM/YYYY', labelKey: 'options.dateFormats.eu' },
];

const SIEM_OPTIONS = [
  { value: 'none', labelKey: 'options.siem.none' },
  { value: 'splunk', labelKey: 'options.siem.splunk' },
  { value: 'qradar', labelKey: 'options.siem.qradar' },
  { value: 'sentinel', labelKey: 'options.siem.sentinel' },
];

const COMPLIANCE_FRAMEWORKS = [
  { configKey: 'framework_cis', labelKey: 'frameworks.cis' },
  { configKey: 'framework_pci-dss', labelKey: 'frameworks.pci_dss' },
  { configKey: 'framework_nist', labelKey: 'frameworks.nist' },
  { configKey: 'framework_hipaa', labelKey: 'frameworks.hipaa' },
  { configKey: 'framework_soc2', labelKey: 'frameworks.soc2' },
  { configKey: 'framework_gdpr', labelKey: 'frameworks.gdpr' },
  { configKey: 'framework_iso27001', labelKey: 'frameworks.iso27001' },
];

function ConfigLoadingSkeleton() {
  return (
    <div className="space-y-6" aria-busy="true" aria-live="polite">
      <SkeletonBar className="h-6 w-48" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="space-y-2">
            <SkeletonBar className="h-4 w-32" />
            <SkeletonBar className="h-10 w-full" />
          </div>
        ))}
      </div>
      <SkeletonBar className="h-24 w-full" />
      <SkeletonBar className="h-3 w-5/6" />
      <SkeletonBar className="h-3 w-4/6" />
    </div>
  );
}

export default function SystemConfiguration() {
  const { t } = useTranslation();
  const [config, setConfig] = useState({
    general: {},
    security: {},
    scanning: {},
    integrations: {},
    retention: {},
    performance: {},
    compliance: {},
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [activeTab, setActiveTab] = useState('general');
  const [unsavedChanges, setUnsavedChanges] = useState(false);
  const [saveMessage, setSaveMessage] = useState(null);

  const tabs = [
    { id: 'general', label: t(`${NS}.tab_general`), icon: <Settings /> },
    { id: 'security', label: t(`${NS}.tab_security`), icon: <Shield /> },
    { id: 'scanning', label: t(`${NS}.tab_scanning`), icon: <Zap /> },
    { id: 'integrations', label: t(`${NS}.tab_integrations`), icon: <Globe /> },
    { id: 'retention', label: t(`${NS}.tab_retention`), icon: <Database /> },
    { id: 'performance', label: t(`${NS}.tab_performance`), icon: <RefreshCw /> },
    { id: 'compliance', label: t(`${NS}.tab_compliance`), icon: <Lock /> },
  ];

  useEffect(() => {
    fetchConfig();
  }, []);

  const fetchConfig = async () => {
    try {
      setLoading(true);
      const data = await api.get('/api/system/config');
      setConfig(data);
    } catch (error) {
      console.error('Failed to fetch config:', error);
    } finally {
      setLoading(false);
    }
  };

  const saveConfig = async () => {
    try {
      setSaving(true);
      setSaveMessage(null);
      await api.put('/api/system/config', config);
      setUnsavedChanges(false);
      setSaveMessage({ type: 'success', text: t(`${NS}.saved`) });
    } catch (error) {
      console.error('Failed to save config:', error);
      setSaveMessage({
        type: 'error',
        text: error?.message || t(`${NS}.save_error`),
      });
    } finally {
      setSaving(false);
    }
  };

  const updateConfig = (section, key, value) => {
    setConfig((prev) => ({
      ...prev,
      [section]: {
        ...prev[section],
        [key]: value,
      },
    }));
    setUnsavedChanges(true);
    setSaveMessage(null);
  };

  const listFindings = useMemo(() => Object.entries(config).flatMap(([section, values]) => {
    if (!values || typeof values !== 'object') return []
    return Object.entries(values).map(([key, val]) => ({
      id: `${section}:${key}`,
      severity: 'info',
      title: key,
      type: section,
      description: String(val ?? ''),
    }))
  }), [config])

  const {
    exportCsv,
    filteredFindings,
    searchQuery,
    setSearchQuery,
  } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-system-config',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description}`,
  })

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      icon={<Settings />}
      actions={(
        <ShellScanActions
          onRefresh={fetchConfig}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        {saveMessage && (
          <div
            className={`rounded-xl border px-4 py-3 text-sm flex items-center justify-between gap-3 ${
              saveMessage.type === 'success'
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                : 'bg-red-500/10 border-red-500/30 text-red-400'
            }`}
            role="alert"
          >
            <div className="flex items-center gap-2">
              {saveMessage.type === 'success' ? (
                <CheckCircle2 className="w-4 h-4 shrink-0" />
              ) : (
                <XCircle className="w-4 h-4 shrink-0" />
              )}
              <span>{saveMessage.text}</span>
            </div>
            <Button variant="unstyled"
              type="button"
              onClick={() => setSaveMessage(null)}
              className="opacity-70 hover:opacity-100 shrink-0"
              aria-label="Dismiss"
            >
              ✕
            </Button>
          </div>
        )}

        {unsavedChanges && (
          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-yellow-400" />
              <div>
                <h3 className="text-sm font-semibold text-yellow-400">{t(`${NS}.unsaved_warning`)}</h3>
                <p className="text-xs text-[var(--text-tertiary)]">{t(`${NS}.unsaved_changes_subtitle`)}</p>
              </div>
            </div>
            <Button variant="unstyled"
              onClick={saveConfig}
              disabled={saving}
              className="flex items-center gap-2 px-4 py-2 bg-yellow-500 text-black rounded-lg text-sm font-medium hover:bg-yellow-600 transition-colors disabled:opacity-50"
            >
              <Save className="w-4 h-4" />
              {saving ? t(`${NS}.saving`) : t(`${NS}.save_changes`)}
            </Button>
          </div>
        )}

        <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl overflow-hidden">
          <div className="flex overflow-x-auto border-b border-[var(--border-default)]">
            {tabs.map((tab) => (
              <Button variant="unstyled"
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-6 py-4 text-sm font-medium whitespace-nowrap transition-all ${
                  activeTab === tab.id
                    ? 'text-cyan-400 border-b-2 border-cyan-400 bg-cyan-500/10'
                    : 'text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:bg-[var(--row-hover-bg)]'
                }`}
              >
                {tab.icon}
                {tab.label}
              </Button>
            ))}
          </div>

          <div className="p-6">
            {loading ? (
              <ConfigLoadingSkeleton />
            ) : (
              <>
                <WeissmanListToolbar
                  className="mb-6"
                  searchQuery={searchQuery}
                  onSearchChange={setSearchQuery}
                  resultCount={searchQuery.trim() ? filteredFindings.length : listFindings.length}
                  totalCount={listFindings.length}
                />
                {searchQuery.trim() ? (
                  filteredFindings.length === 0 ? (
                    <EmptyState
                      icon="search"
                      title={t('weissmanFindings.filtered_title')}
                      body={t('weissmanFindings.filtered_body')}
                      compact
                    />
                  ) : (
                    <div className="space-y-2 max-h-[480px] overflow-y-auto">
                      {filteredFindings.map((item) => (
                        <div key={item.id} className="rounded-lg border border-[var(--border-default)] bg-[var(--row-hover-bg)] px-4 py-3">
                          <div className="text-[10px] font-mono uppercase text-cyan-400/70">{item.type}</div>
                          <div className="text-sm font-medium text-white mt-1">{item.title}</div>
                          <div className="text-xs text-[var(--text-tertiary)] font-mono mt-1 break-all">{item.description}</div>
                        </div>
                      ))}
                    </div>
                  )
                ) : (
              <>
                {activeTab === 'general' && (
                  <GeneralSettings config={config.general} onChange={(key, value) => updateConfig('general', key, value)} />
                )}
                {activeTab === 'security' && (
                  <SecuritySettings config={config.security} onChange={(key, value) => updateConfig('security', key, value)} />
                )}
                {activeTab === 'scanning' && (
                  <ScanningSettings config={config.scanning} onChange={(key, value) => updateConfig('scanning', key, value)} />
                )}
                {activeTab === 'integrations' && (
                  <IntegrationsSettings config={config.integrations} onChange={(key, value) => updateConfig('integrations', key, value)} />
                )}
                {activeTab === 'retention' && (
                  <RetentionSettings config={config.retention} onChange={(key, value) => updateConfig('retention', key, value)} />
                )}
                {activeTab === 'performance' && (
                  <PerformanceSettings config={config.performance} onChange={(key, value) => updateConfig('performance', key, value)} />
                )}
                {activeTab === 'compliance' && (
                  <ComplianceSettings config={config.compliance} onChange={(key, value) => updateConfig('compliance', key, value)} />
                )}
              </>
                )}
              </>
            )}
          </div>
        </div>

        <div className="flex justify-end">
          <Button variant="unstyled"
            onClick={saveConfig}
            disabled={!unsavedChanges || saving}
            className="flex items-center gap-2 px-6 py-3 bg-cyan-500 text-white rounded-lg font-medium hover:bg-cyan-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Save className="w-4 h-4" />
            {saving ? t(`${NS}.saving`) : t(`${NS}.save_all`)}
          </Button>
        </div>
      </div>
    </PageShell>
  );
}

function GeneralSettings({ config, onChange }) {
  const { t } = useTranslation();

  return (
    <div className="space-y-6">
      <h3 className="text-lg font-bold text-white mb-4">{t(`${NS}.sections.general.title`)}</h3>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
            {t(`${NS}.fields.general.org_name`)}
          </label>
          <input
            type="text"
            value={config.org_name || ''}
            onChange={(e) => onChange('org_name', e.target.value)}
            className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
            {t(`${NS}.fields.general.timezone`)}
          </label>
          <select
            value={config.timezone || 'UTC'}
            onChange={(e) => onChange('timezone', e.target.value)}
            className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          >
            {TIMEZONE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {t(`${NS}.${opt.labelKey}`)}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
            {t(`${NS}.fields.general.language`)}
          </label>
          <select
            value={config.language || 'en'}
            onChange={(e) => onChange('language', e.target.value)}
            className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          >
            {LANGUAGE_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {t(`${NS}.${opt.labelKey}`)}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
            {t(`${NS}.fields.general.date_format`)}
          </label>
          <select
            value={config.date_format || 'YYYY-MM-DD'}
            onChange={(e) => onChange('date_format', e.target.value)}
            className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          >
            {DATE_FORMAT_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {t(`${NS}.${opt.labelKey}`)}
              </option>
            ))}
          </select>
        </div>
      </div>
    </div>
  );
}

function SecuritySettings({ config, onChange }) {
  const { t } = useTranslation();

  return (
    <div className="space-y-6">
      <h3 className="text-lg font-bold text-white mb-4">{t(`${NS}.sections.security.title`)}</h3>

      <div className="space-y-4">
        <div className="bg-[var(--row-hover-bg)] border border-[var(--border-default)] rounded-lg p-4">
          <h4 className="text-sm font-semibold text-white mb-3">{t(`${NS}.sections.security.password_policy`)}</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-[var(--text-tertiary)] mb-2">{t(`${NS}.fields.security.password_min_length`)}</label>
              <input
                type="number"
                value={config.password_min_length || 12}
                onChange={(e) => onChange('password_min_length', parseInt(e.target.value, 10))}
                className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              />
            </div>
            <div>
              <label className="block text-sm text-[var(--text-tertiary)] mb-2">{t(`${NS}.fields.security.password_max_age`)}</label>
              <input
                type="number"
                value={config.password_max_age || 90}
                onChange={(e) => onChange('password_max_age', parseInt(e.target.value, 10))}
                className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              />
            </div>
          </div>
          <div className="mt-4 space-y-2">
            <label className="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
              <input
                type="checkbox"
                checked={config.password_require_uppercase || false}
                onChange={(e) => onChange('password_require_uppercase', e.target.checked)}
                className="rounded"
              />
              {t(`${NS}.fields.security.password_require_uppercase`)}
            </label>
            <label className="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
              <input
                type="checkbox"
                checked={config.password_require_numbers || false}
                onChange={(e) => onChange('password_require_numbers', e.target.checked)}
                className="rounded"
              />
              {t(`${NS}.fields.security.password_require_numbers`)}
            </label>
            <label className="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
              <input
                type="checkbox"
                checked={config.password_require_special || false}
                onChange={(e) => onChange('password_require_special', e.target.checked)}
                className="rounded"
              />
              {t(`${NS}.fields.security.password_require_special`)}
            </label>
          </div>
        </div>

        <div className="bg-[var(--row-hover-bg)] border border-[var(--border-default)] rounded-lg p-4">
          <h4 className="text-sm font-semibold text-white mb-3">{t(`${NS}.sections.security.session_management`)}</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-[var(--text-tertiary)] mb-2">{t(`${NS}.fields.security.session_timeout`)}</label>
              <input
                type="number"
                value={config.session_timeout || 60}
                onChange={(e) => onChange('session_timeout', parseInt(e.target.value, 10))}
                className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              />
            </div>
            <div>
              <label className="block text-sm text-[var(--text-tertiary)] mb-2">{t(`${NS}.fields.security.max_concurrent_sessions`)}</label>
              <input
                type="number"
                value={config.max_concurrent_sessions || 3}
                onChange={(e) => onChange('max_concurrent_sessions', parseInt(e.target.value, 10))}
                className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              />
            </div>
          </div>
        </div>

        <div className="bg-[var(--row-hover-bg)] border border-[var(--border-default)] rounded-lg p-4">
          <h4 className="text-sm font-semibold text-white mb-3">{t(`${NS}.sections.security.mfa`)}</h4>
          <label className="flex items-center gap-2 text-sm text-[var(--text-secondary)] mb-3">
            <input
              type="checkbox"
              checked={config.mfa_required || false}
              onChange={(e) => onChange('mfa_required', e.target.checked)}
              className="rounded"
            />
            {t(`${NS}.fields.security.mfa_required`)}
          </label>
          <MfaSelfServicePanel />
        </div>
      </div>
    </div>
  );
}

function MfaSelfServicePanel() {
  const { t } = useTranslation();
  const [status, setStatus] = React.useState(null);
  const [setup, setSetup] = React.useState(null);
  const [code, setCode] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState('');

  const refresh = React.useCallback(async () => {
    try {
      const r = await apiFetch('/api/auth/mfa/status');
      const d = await r.json().catch(() => ({}));
      setStatus(d);
    } catch (e) {
      setErr(e?.message || t(`${NS}.mfa.errors.status_fetch_failed`));
    }
  }, [t]);

  React.useEffect(() => {
    refresh();
  }, [refresh]);

  const startSetup = async () => {
    setBusy(true);
    setErr('');
    try {
      const r = await apiFetch('/api/auth/mfa/setup', { method: 'POST' });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.detail || t(`${NS}.mfa.errors.setup_failed`));
      setSetup(d);
    } catch (e) {
      setErr(e?.message || t(`${NS}.mfa.errors.setup_failed`));
    } finally {
      setBusy(false);
    }
  };

  const enable = async () => {
    setBusy(true);
    setErr('');
    try {
      const r = await apiFetch('/api/auth/mfa/enable', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: code.trim() }),
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.detail || t(`${NS}.mfa.errors.enable_failed`));
      setSetup(null);
      setCode('');
      await refresh();
    } catch (e) {
      setErr(e?.message || t(`${NS}.mfa.errors.enable_failed`));
    } finally {
      setBusy(false);
    }
  };

  const disable = async () => {
    setBusy(true);
    setErr('');
    try {
      const r = await apiFetch('/api/auth/mfa/disable', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: code.trim() }),
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.detail || t(`${NS}.mfa.errors.disable_failed`));
      setCode('');
      await refresh();
    } catch (e) {
      setErr(e?.message || t(`${NS}.mfa.errors.disable_failed`));
    } finally {
      setBusy(false);
    }
  };

  if (!status) {
    return <p className="text-[11px] text-[var(--text-muted)]">{t(`${NS}.mfa.loading_status`)}</p>;
  }

  return (
    <div className="mt-3 space-y-2 border-t border-[var(--border-default)] pt-3">
      <div className="text-[11px] font-mono text-[var(--text-tertiary)]">
        {t(`${NS}.mfa.account_label`)}{' '}
        {status.mfa_enabled ? (
          <span className="text-emerald-400">{t(`${NS}.mfa.status_enabled`)}</span>
        ) : (
          <span className="text-yellow-400">{t(`${NS}.mfa.status_disabled`)}</span>
        )}
        {status.mfa_provisioned && !status.mfa_enabled && (
          <span className="text-cyan-400 ml-2">{t(`${NS}.mfa.provisioning_in_progress`)}</span>
        )}
      </div>
      {err && <div className="text-[11px] text-rose-400">{err}</div>}
      {!status.mfa_enabled && !setup && (
        <Button variant="unstyled"
          type="button"
          disabled={busy}
          onClick={startSetup}
          className="px-3 py-1.5 rounded-lg text-[11px] font-mono border border-cyan-500/40 bg-cyan-500/15 text-cyan-200 hover:bg-cyan-500/25 disabled:opacity-50"
        >
          {busy ? t(`${NS}.mfa.working`) : status.mfa_provisioned ? t(`${NS}.mfa.reprovision`) : t(`${NS}.mfa.setup`)}
        </Button>
      )}
      {setup && (
        <div className="space-y-2">
          <p className="text-[11px] text-[var(--text-tertiary)]">{t(`${NS}.mfa.scan_uri_instructions`)}</p>
          <code className="block break-all text-[10px] font-mono text-cyan-300 bg-[var(--bg-2)] p-2 rounded">
            {setup.otpauth_url}
          </code>
          <div className="flex items-center gap-2">
            <input
              type="text"
              inputMode="numeric"
              maxLength={6}
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
              placeholder={t(`${NS}.mfa.code_placeholder`)}
              className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1 text-sm font-mono w-28"
            />
            <Button variant="unstyled"
              type="button"
              onClick={enable}
              disabled={busy || code.length !== 6}
              className="px-3 py-1.5 rounded-lg text-[11px] font-mono border border-emerald-500/40 bg-emerald-500/15 text-emerald-200 hover:bg-emerald-500/25 disabled:opacity-50"
            >
              {busy ? t(`${NS}.mfa.working`) : t(`${NS}.mfa.enable`)}
            </Button>
          </div>
        </div>
      )}
      {status.mfa_enabled && (
        <div className="flex items-center gap-2 mt-2">
          <input
            type="text"
            inputMode="numeric"
            maxLength={6}
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
            placeholder={t(`${NS}.mfa.code_placeholder`)}
            className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2 py-1 text-sm font-mono w-28"
          />
          <Button variant="unstyled"
            type="button"
            onClick={disable}
            disabled={busy || code.length !== 6}
            className="px-3 py-1.5 rounded-lg text-[11px] font-mono border border-rose-500/40 bg-rose-500/15 text-rose-200 hover:bg-rose-500/25 disabled:opacity-50"
          >
            {busy ? t(`${NS}.mfa.working`) : t(`${NS}.mfa.disable`)}
          </Button>
        </div>
      )}
    </div>
  );
}

function ScanningSettings({ config, onChange }) {
  const { t } = useTranslation();

  return (
    <div className="space-y-6">
      <h3 className="text-lg font-bold text-white mb-4">{t(`${NS}.sections.scanning.title`)}</h3>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
            {t(`${NS}.fields.scanning.default_timeout`)}
          </label>
          <input
            type="number"
            value={config.default_timeout || 300}
            onChange={(e) => onChange('default_timeout', parseInt(e.target.value, 10))}
            className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
            {t(`${NS}.fields.scanning.max_concurrency`)}
          </label>
          <input
            type="number"
            value={config.max_concurrency || 10}
            onChange={(e) => onChange('max_concurrency', parseInt(e.target.value, 10))}
            className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
            {t(`${NS}.fields.scanning.auto_retry`)}
          </label>
          <select
            value={String(config.auto_retry ?? false)}
            onChange={(e) => onChange('auto_retry', e.target.value === 'true')}
            className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          >
            <option value="true">{t(`${NS}.common.enabled`)}</option>
            <option value="false">{t(`${NS}.common.disabled`)}</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
            {t(`${NS}.fields.scanning.max_retries`)}
          </label>
          <input
            type="number"
            value={config.max_retries || 3}
            onChange={(e) => onChange('max_retries', parseInt(e.target.value, 10))}
            className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>
      </div>
    </div>
  );
}

function IntegrationsSettings({ config, onChange }) {
  const { t } = useTranslation();

  return (
    <div className="space-y-6">
      <h3 className="text-lg font-bold text-white mb-4">{t(`${NS}.sections.integrations.title`)}</h3>

      <div className="space-y-4">
        <div className="bg-[var(--row-hover-bg)] border border-[var(--border-default)] rounded-lg p-4">
          <h4 className="text-sm font-semibold text-white mb-3">{t(`${NS}.sections.integrations.webhook`)}</h4>
          <input
            type="text"
            value={config.webhook_url || ''}
            onChange={(e) => onChange('webhook_url', e.target.value)}
            placeholder={t(`${NS}.placeholders.webhook_url`)}
            className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>

        <div className="bg-[var(--row-hover-bg)] border border-[var(--border-default)] rounded-lg p-4">
          <h4 className="text-sm font-semibold text-white mb-3">{t(`${NS}.sections.integrations.siem`)}</h4>
          <div className="space-y-3">
            <select
              value={config.siem_type || 'none'}
              onChange={(e) => onChange('siem_type', e.target.value)}
              className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            >
              {SIEM_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {t(`${NS}.${opt.labelKey}`)}
                </option>
              ))}
            </select>
            {config.siem_type && config.siem_type !== 'none' && (
              <input
                type="text"
                value={config.siem_endpoint || ''}
                onChange={(e) => onChange('siem_endpoint', e.target.value)}
                placeholder={t(`${NS}.placeholders.siem_endpoint`)}
                className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              />
            )}
          </div>
        </div>

        <div className="bg-[var(--row-hover-bg)] border border-[var(--border-default)] rounded-lg p-4">
          <h4 className="text-sm font-semibold text-white mb-3">{t(`${NS}.sections.integrations.email`)}</h4>
          <div className="space-y-3">
            <input
              type="text"
              value={config.smtp_server || ''}
              onChange={(e) => onChange('smtp_server', e.target.value)}
              placeholder={t(`${NS}.placeholders.smtp_server`)}
              className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            />
            <input
              type="number"
              value={config.smtp_port || 587}
              onChange={(e) => onChange('smtp_port', parseInt(e.target.value, 10))}
              placeholder={t(`${NS}.placeholders.smtp_port`)}
              className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            />
          </div>
        </div>
      </div>
    </div>
  );
}

function RetentionSettings({ config, onChange }) {
  const { t } = useTranslation();

  return (
    <div className="space-y-6">
      <h3 className="text-lg font-bold text-white mb-4">{t(`${NS}.sections.retention.title`)}</h3>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
            {t(`${NS}.fields.retention.scan_results`)}
          </label>
          <input
            type="number"
            value={config.scan_results_retention || 90}
            onChange={(e) => onChange('scan_results_retention', parseInt(e.target.value, 10))}
            className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
            {t(`${NS}.fields.retention.audit_logs`)}
          </label>
          <input
            type="number"
            value={config.audit_logs_retention || 365}
            onChange={(e) => onChange('audit_logs_retention', parseInt(e.target.value, 10))}
            className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
            {t(`${NS}.fields.retention.findings`)}
          </label>
          <input
            type="number"
            value={config.findings_retention || 180}
            onChange={(e) => onChange('findings_retention', parseInt(e.target.value, 10))}
            className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
            {t(`${NS}.fields.retention.metrics`)}
          </label>
          <input
            type="number"
            value={config.metrics_retention || 30}
            onChange={(e) => onChange('metrics_retention', parseInt(e.target.value, 10))}
            className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>
      </div>
    </div>
  );
}

function PerformanceSettings({ config, onChange }) {
  const { t } = useTranslation();

  return (
    <div className="space-y-6">
      <h3 className="text-lg font-bold text-white mb-4">{t(`${NS}.sections.performance.title`)}</h3>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
            {t(`${NS}.fields.performance.worker_threads`)}
          </label>
          <input
            type="number"
            value={config.worker_threads || 4}
            onChange={(e) => onChange('worker_threads', parseInt(e.target.value, 10))}
            className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
            {t(`${NS}.fields.performance.cache_ttl`)}
          </label>
          <input
            type="number"
            value={config.cache_ttl || 300}
            onChange={(e) => onChange('cache_ttl', parseInt(e.target.value, 10))}
            className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
            {t(`${NS}.fields.performance.max_memory`)}
          </label>
          <input
            type="number"
            value={config.max_memory || 2048}
            onChange={(e) => onChange('max_memory', parseInt(e.target.value, 10))}
            className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-[var(--text-secondary)] mb-2">
            {t(`${NS}.fields.performance.db_pool_size`)}
          </label>
          <input
            type="number"
            value={config.db_pool_size || 20}
            onChange={(e) => onChange('db_pool_size', parseInt(e.target.value, 10))}
            className="w-full px-3 py-2 bg-[var(--bg-2)] border border-[var(--border-default)] rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          />
        </div>
      </div>
    </div>
  );
}

function ComplianceSettings({ config, onChange }) {
  const { t } = useTranslation();

  return (
    <div className="space-y-6">
      <h3 className="text-lg font-bold text-white mb-4">{t(`${NS}.sections.compliance.title`)}</h3>

      <div className="space-y-3">
        {COMPLIANCE_FRAMEWORKS.map((framework) => (
          <label
            key={framework.configKey}
            className="flex items-center gap-3 p-3 bg-[var(--row-hover-bg)] border border-[var(--border-default)] rounded-lg hover:bg-[var(--row-hover-bg)] transition-colors"
          >
            <input
              type="checkbox"
              checked={config[framework.configKey] || false}
              onChange={(e) => onChange(framework.configKey, e.target.checked)}
              className="rounded"
            />
            <span className="text-sm font-medium text-white">{t(`${NS}.${framework.labelKey}`)}</span>
          </label>
        ))}
      </div>
    </div>
  );
}
