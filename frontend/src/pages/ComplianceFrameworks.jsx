import { useState, useEffect, useCallback, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  Shield, CheckCircle, XCircle, AlertTriangle, FileText, Download, RefreshCw, Search,
} from 'lucide-react';
import PageShell from './PageShell';
import ShellScanActions from '../components/engine/ShellScanActions';
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench';
import EmptyState from '../components/ui/EmptyState';
import { SkeletonWidgetGrid, SkeletonTable } from '../components/ui/Skeleton';
import { api } from '../utils/apiFetch';
import { apiFetch } from '../lib/apiBase';

const FRAMEWORK_ICONS = {
  iso27001: '🔐',
  soc2: '📊',
  nis2: '🇪🇺',
  gdpr: '🇪🇺',
  iec62443: '⚙️',
  pci: '💳',
  'csa-ccm': '☁️',
};

const FILTER_KEYS = ['all', 'compliant', 'non-compliant', 'partial'];

function statusLabel(status, t) {
  switch (status?.toLowerCase()) {
    case 'compliant':
      return t('pages.complianceFrameworks.status_compliant');
    case 'non-compliant':
      return t('pages.complianceFrameworks.status_non_compliant');
    case 'partial':
      return t('pages.complianceFrameworks.status_partial');
    default:
      return status || '—';
  }
}

export default function ComplianceFrameworks() {
  const { t } = useTranslation();
  const [frameworks, setFrameworks] = useState([]);
  const [selectedFramework, setSelectedFramework] = useState(null);
  const [controls, setControls] = useState([]);
  const [loadingFrameworks, setLoadingFrameworks] = useState(true);
  const [loadingControls, setLoadingControls] = useState(false);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [exporting, setExporting] = useState(false);

  const fetchFrameworks = useCallback(async () => {
    try {
      setLoadingFrameworks(true);
      setError('');
      const data = await api.get('/api/compliance/frameworks');
      const list = data.frameworks || [];
      setFrameworks(list);
      if (list.length > 0) {
        setSelectedFramework((prev) => prev ?? list[0]);
      }
    } catch (err) {
      console.error('Failed to fetch frameworks:', err);
      setError(err?.message || t('pages.complianceFrameworks.load_failed'));
      setFrameworks([]);
    } finally {
      setLoadingFrameworks(false);
    }
  }, [t]);

  const fetchControls = useCallback(async (frameworkId) => {
    if (!frameworkId) return;
    try {
      setLoadingControls(true);
      setError('');
      const data = await api.get(`/api/compliance/frameworks/${frameworkId}/controls`);
      setControls(data.controls || []);
    } catch (err) {
      console.error('Failed to fetch controls:', err);
      setControls([]);
      setError(err?.message || t('pages.complianceFrameworks.controls_load_failed'));
    } finally {
      setLoadingControls(false);
    }
  }, [t]);

  useEffect(() => {
    fetchFrameworks();
  }, [fetchFrameworks]);

  useEffect(() => {
    if (selectedFramework?.id) {
      fetchControls(selectedFramework.id);
    }
  }, [selectedFramework, fetchControls]);

  const generateReport = async (frameworkId) => {
    try {
      setExporting(true);
      const r = await apiFetch(`/api/compliance/frameworks/${frameworkId}/report`);
      if (!r.ok) throw new Error(`Report failed (${r.status})`);
      const blob = await r.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${frameworkId}-compliance-report.pdf`;
      link.click();
    } catch (err) {
      console.error('Failed to generate report:', err);
      setError(t('pages.complianceFrameworks.export_failed'));
    } finally {
      setExporting(false);
    }
  };

  const getComplianceColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'compliant':
        return 'text-green-400 bg-green-500/10 border-green-500/30';
      case 'non-compliant':
        return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'partial':
        return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      default:
        return 'text-gray-400 bg-gray-500/10 border-gray-500/30';
    }
  };

  const getComplianceIcon = (status) => {
    switch (status?.toLowerCase()) {
      case 'compliant':
        return <CheckCircle className="w-4 h-4" />;
      case 'non-compliant':
        return <XCircle className="w-4 h-4" />;
      case 'partial':
        return <AlertTriangle className="w-4 h-4" />;
      default:
        return <AlertTriangle className="w-4 h-4" />;
    }
  };

  const filteredControls = useMemo(() => {
    const term = search.trim().toLowerCase();
    return controls.filter((c) => {
      if (filter !== 'all' && c.status !== filter) return false;
      if (!term) return true;
      return (
        String(c.id || '').toLowerCase().includes(term)
        || String(c.title || '').toLowerCase().includes(term)
      );
    });
  }, [controls, filter, search]);

  const stats = useMemo(() => {
    if (!selectedFramework || controls.length === 0) {
      return { total: 0, compliant: 0, nonCompliant: 0, partial: 0, score: 0 };
    }
    const compliant = controls.filter((c) => c.status === 'compliant').length;
    const nonCompliant = controls.filter((c) => c.status === 'non-compliant').length;
    const partial = controls.filter((c) => c.status === 'partial').length;
    return {
      total: controls.length,
      compliant,
      nonCompliant,
      partial,
      score: ((compliant / controls.length) * 100).toFixed(1),
    };
  }, [selectedFramework, controls]);

  const listFindings = useMemo(() => filteredControls.map((c) => ({
    id: c.id,
    severity: c.status === 'non-compliant' ? 'high' : c.status === 'partial' ? 'medium' : 'info',
    title: c.name || c.control_id || c.id,
    type: selectedFramework?.id || 'control',
    description: c.description || statusLabel(c.status, t),
    resource: c.category || '',
  })), [filteredControls, selectedFramework, t])

  const { exportCsv, filteredFindings } = useFindingsWorkbench(listFindings, {
    csvPrefix: 'weissman-compliance-controls',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.resource}`,
  })

  return (
    <PageShell
      title={t('pages.complianceFrameworks.title')}
      subtitle={t('pages.complianceFrameworks.subtitle')}
      icon={<Shield />}
      actions={(
        <ShellScanActions
          onRefresh={fetchFrameworks}
          onExport={exportCsv}
          refreshLoading={loadingFrameworks}
          exportDisabled={!filteredFindings.length}
        />
      )}
    >
      <div className="space-y-6">
        {error && (
          <div className="rounded-xl border border-rose-500/30 bg-rose-950/30 px-4 py-3 text-sm text-rose-200">
            {error}
          </div>
        )}

        <div className="rounded-xl border border-cyan-500/20 bg-cyan-950/20 px-4 py-3 text-xs text-cyan-100/70">
          {t('pages.complianceFrameworks.evidence_notice')}
        </div>

        <div className="flex items-center gap-3 overflow-x-auto pb-2">
          {loadingFrameworks && frameworks.length === 0 ? (
            <div className="text-sm text-gray-500 px-4 py-3">{t('pages.complianceFrameworks.loading')}</div>
          ) : frameworks.length === 0 ? (
            <EmptyState
              title={t('pages.complianceFrameworks.no_frameworks_title')}
              description={t('pages.complianceFrameworks.no_frameworks')}
            />
          ) : (
            frameworks.map((fw) => {
              const isSelected = selectedFramework?.id === fw.id;
              const scoreLabel = isSelected && controls.length > 0
                ? t('pages.complianceFrameworks.framework_score', { score: stats.score })
                : fw.scope;

              return (
                <button
                  key={fw.id}
                  type="button"
                  onClick={() => setSelectedFramework(fw)}
                  className={`flex items-center gap-2 px-4 py-3 rounded-xl border transition-all whitespace-nowrap ${
                    isSelected
                      ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30'
                      : 'bg-[var(--bg-2)] text-gray-400 border-[var(--border-default)] hover:bg-[var(--row-hover-bg)] hover:text-white'
                  }`}
                >
                  <span className="text-xl">{FRAMEWORK_ICONS[fw.id] || '🛡️'}</span>
                  <div className="text-left">
                    <div className="text-sm font-semibold">{fw.name}</div>
                    {scoreLabel && (
                      <div className="text-xs opacity-75 truncate max-w-[180px]">{scoreLabel}</div>
                    )}
                  </div>
                </button>
              );
            })
          )}
        </div>

        {selectedFramework && (
          <>
            {loadingControls && controls.length === 0 ? (
              <SkeletonWidgetGrid count={5} />
            ) : controls.length > 0 && (
              <>
                <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
                  <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-gray-400">{t('pages.complianceFrameworks.total_controls')}</span>
                      <FileText className="w-4 h-4 text-cyan-400" />
                    </div>
                    <div className="text-2xl font-bold text-white">{stats.total}</div>
                  </div>
                  <div className="bg-green-500/10 backdrop-blur-md border border-green-500/30 rounded-xl p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-green-400">{t('pages.complianceFrameworks.status_compliant')}</span>
                      <CheckCircle className="w-4 h-4 text-green-400" />
                    </div>
                    <div className="text-2xl font-bold text-green-400">{stats.compliant}</div>
                  </div>
                  <div className="bg-red-500/10 backdrop-blur-md border border-red-500/30 rounded-xl p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-red-400">{t('pages.complianceFrameworks.status_non_compliant')}</span>
                      <XCircle className="w-4 h-4 text-red-400" />
                    </div>
                    <div className="text-2xl font-bold text-red-400">{stats.nonCompliant}</div>
                  </div>
                  <div className="bg-yellow-500/10 backdrop-blur-md border border-yellow-500/30 rounded-xl p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-yellow-400">{t('pages.complianceFrameworks.status_partial')}</span>
                      <AlertTriangle className="w-4 h-4 text-yellow-400" />
                    </div>
                    <div className="text-2xl font-bold text-yellow-400">{stats.partial}</div>
                  </div>
                  <div className="bg-cyan-500/10 backdrop-blur-md border border-cyan-500/30 rounded-xl p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-cyan-400">{t('pages.complianceFrameworks.score_label')}</span>
                      <Shield className="w-4 h-4 text-cyan-400" />
                    </div>
                    <div className="text-2xl font-bold text-cyan-400">{stats.score}%</div>
                  </div>
                </div>

                {stats.total > 0 && (
                  <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
                    <div className="flex h-3 rounded-full overflow-hidden">
                      <div className="bg-green-500/70" style={{ width: `${(stats.compliant / stats.total) * 100}%` }} />
                      <div className="bg-yellow-500/70" style={{ width: `${(stats.partial / stats.total) * 100}%` }} />
                      <div className="bg-red-500/70" style={{ width: `${(stats.nonCompliant / stats.total) * 100}%` }} />
                    </div>
                    <div className="flex gap-4 mt-2 text-[10px] font-mono text-[var(--text-muted)]">
                      <span>{t('pages.complianceFrameworks.status_compliant')} {stats.compliant}</span>
                      <span>{t('pages.complianceFrameworks.status_partial')} {stats.partial}</span>
                      <span>{t('pages.complianceFrameworks.status_non_compliant')} {stats.nonCompliant}</span>
                    </div>
                  </div>
                )}
              </>
            )}

            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-disabled)]" />
                  <input
                    type="text"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder={t('pages.complianceFrameworks.search_placeholder')}
                    className="pl-10 pr-4 py-2 rounded-lg bg-[var(--bg-2)] border border-[var(--border-default)] text-sm text-white placeholder-white/25 focus:outline-none focus:border-cyan-500/40"
                  />
                </div>
                <div className="flex items-center gap-2 bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-lg p-1">
                  {FILTER_KEYS.map((f) => (
                    <button
                      key={f}
                      type="button"
                      onClick={() => setFilter(f)}
                      className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                        filter === f
                          ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                          : 'text-gray-400 hover:text-white hover:bg-[var(--row-hover-bg)]'
                      }`}
                    >
                      {t(`pages.complianceFrameworks.filter_${f.replace('-', '_')}`)}
                    </button>
                  ))}
                </div>
              </div>

              <button
                type="button"
                onClick={() => generateReport(selectedFramework.id)}
                disabled={exporting || controls.length === 0}
                className="flex items-center gap-2 px-4 py-2 bg-cyan-500 text-white rounded-lg font-medium hover:bg-cyan-600 transition-colors disabled:opacity-40"
              >
                <Download className="w-4 h-4" />
                {exporting ? t('pages.complianceFrameworks.exporting') : t('pages.complianceFrameworks.export_report')}
              </button>
            </div>

            <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl overflow-hidden">
              <div className="p-4 border-b border-[var(--border-default)]">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <FileText className="w-4 h-4 text-cyan-400" />
                  {t('pages.complianceFrameworks.controls_heading')} — {selectedFramework.name}
                  {' '}
                  ({filteredControls.length})
                </h3>
              </div>

              {loadingControls ? (
                <div className="p-6">
                  <SkeletonTable rows={5} cols={3} />
                </div>
              ) : controls.length === 0 ? (
                <EmptyState
                  title={t('pages.complianceFrameworks.no_controls_title')}
                  description={t('pages.complianceFrameworks.no_controls')}
                />
              ) : filteredControls.length === 0 ? (
                <EmptyState
                  title={t('pages.complianceFrameworks.no_filter_results_title')}
                  description={t('pages.complianceFrameworks.no_filter_results')}
                />
              ) : (
                <div className="divide-y divide-[var(--border-subtle)] max-h-[600px] overflow-y-auto">
                  {filteredControls.map((control) => (
                    <div
                      key={control.id}
                      className="p-4 hover:bg-[var(--row-hover-bg)] transition-colors"
                    >
                      <div className="flex items-start gap-3">
                        <span className="text-xs font-mono text-gray-500 bg-[var(--row-hover-bg)] px-2 py-1 rounded shrink-0">
                          {control.id}
                        </span>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-3 flex-wrap">
                            <h4 className="text-sm font-semibold text-white">
                              {control.title}
                            </h4>
                            <span
                              className={`flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium ${getComplianceColor(control.status)}`}
                            >
                              {getComplianceIcon(control.status)}
                              {statusLabel(control.status, t)}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        )}

        {selectedFramework && stats.nonCompliant > 0 && (
          <div className="bg-red-500/10 backdrop-blur-md border border-red-500/30 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-4">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              <h3 className="text-sm font-semibold text-white">{t('pages.complianceFrameworks.gap_title')}</h3>
            </div>
            <p className="text-sm text-gray-300 mb-4">
              {t('pages.complianceFrameworks.gap_body', {
                count: stats.nonCompliant,
                framework: selectedFramework.name,
              })}
            </p>
            <Link
              to="/remediation"
              className="inline-flex px-4 py-2 bg-red-500 text-white rounded-lg text-sm font-medium hover:bg-red-600 transition-colors"
            >
              {t('pages.complianceFrameworks.open_remediation')}
            </Link>
          </div>
        )}
      </div>
    </PageShell>
  );
}
