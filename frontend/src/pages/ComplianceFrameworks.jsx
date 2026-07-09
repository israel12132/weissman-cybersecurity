import { useState, useEffect, useCallback, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { createColumnHelper } from '@tanstack/react-table';
import {
  Shield, CheckCircle, XCircle, AlertTriangle, FileText, Download, RefreshCw, Search, FileCheck, ShieldCheck,
} from 'lucide-react';
import PageShell from './PageShell';
import ShellScanActions from '../components/engine/ShellScanActions';
import DataTable from '../components/ui/DataTable';
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench';
import EmptyState from '../components/ui/EmptyState';
import CopyButton from '../components/ui/CopyButton';
import { SkeletonWidgetGrid, SkeletonTable } from '../components/ui/Skeleton';
import { useClient } from '../context/ClientContext';
import { useToast } from '../components/ui/Toaster';
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
  const { selectedClientId, selectedClient } = useClient();
  const { toast } = useToast();
  const [pack, setPack] = useState(null);
  const [packLoading, setPackLoading] = useState(false);
  const [soarOpenId, setSoarOpenId] = useState(null);
  const [soarDetail, setSoarDetail] = useState(null);
  const [soarLoading, setSoarLoading] = useState(false);
  const [mappings, setMappings] = useState(null);
  const [mappingsOpen, setMappingsOpen] = useState(false);
  const [mappingsLoading, setMappingsLoading] = useState(false);
  const [mappingsSearch, setMappingsSearch] = useState('');
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

  // Auditor evidence pack — a tamper-evident (sha256-stamped) packet aggregating
  // live findings-by-framework, control mappings, SOAR actions, and audit-chain
  // integrity for the selected client. Wired to GET /api/compliance/evidence-pack/:id.
  const generateEvidencePack = useCallback(async () => {
    if (selectedClientId == null) return;
    setPackLoading(true);
    try {
      const fw = selectedFramework?.id ? `?framework=${encodeURIComponent(selectedFramework.id)}` : '';
      const r = await apiFetch(`/api/compliance/evidence-pack/${encodeURIComponent(selectedClientId)}${fw}`);
      const d = await r.json().catch(() => ({}));
      if (!r.ok || d.error) throw new Error(d.error || d.detail || `HTTP ${r.status}`);
      setPack(d);
      toast.success(t('pages.complianceFrameworks.pack_ready'));
    } catch (err) {
      toast.error(err?.message || t('pages.complianceFrameworks.pack_failed'));
    } finally {
      setPackLoading(false);
    }
  }, [selectedClientId, selectedFramework, t, toast]);

  const downloadPack = useCallback(() => {
    if (!pack) return;
    const blob = new Blob([JSON.stringify(pack, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `weissman-evidence-pack-client${pack.client_id}-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }, [pack]);

  // Fresh client selection invalidates a previously-generated pack.
  useEffect(() => {
    setPack(null);
    setSoarOpenId(null);
    setSoarDetail(null);
  }, [selectedClientId]);

  // Expand a SOAR action to its full execution detail (blast radius, evidence,
  // revert runbook). Wired to GET /api/soar/executions/:id (operator+).
  const toggleSoar = useCallback(async (execId) => {
    if (soarOpenId === execId) {
      setSoarOpenId(null);
      setSoarDetail(null);
      return;
    }
    setSoarOpenId(execId);
    setSoarDetail(null);
    setSoarLoading(true);
    try {
      const r = await apiFetch(`/api/soar/executions/${encodeURIComponent(execId)}`);
      const d = await r.json().catch(() => ({}));
      if (r.ok && d.ok !== false) setSoarDetail(d.execution || d);
      else setSoarDetail({ _error: d.detail || `HTTP ${r.status}` });
    } catch (e) {
      setSoarDetail({ _error: e.message });
    } finally {
      setSoarLoading(false);
    }
  }, [soarOpenId]);

  // Control → evidence mapping matrix. Wired to GET /api/compliance/control-mappings.
  const toggleMappings = useCallback(async () => {
    if (mappingsOpen) {
      setMappingsOpen(false);
      return;
    }
    setMappingsOpen(true);
    if (mappings != null) return; // already loaded
    setMappingsLoading(true);
    try {
      const fw = selectedFramework?.id ? `?framework=${encodeURIComponent(selectedFramework.id)}` : '';
      const r = await apiFetch(`/api/compliance/control-mappings${fw}`);
      const d = await r.json().catch(() => ({}));
      let list = Array.isArray(d.mappings) ? d.mappings : [];
      // If the framework filter returned nothing (naming mismatch), fall back to all.
      if (list.length === 0 && fw) {
        const rAll = await apiFetch('/api/compliance/control-mappings');
        const dAll = await rAll.json().catch(() => ({}));
        list = Array.isArray(dAll.mappings) ? dAll.mappings : [];
      }
      setMappings(list);
    } catch {
      setMappings([]);
    } finally {
      setMappingsLoading(false);
    }
  }, [mappingsOpen, mappings, selectedFramework]);

  const filteredMappings = useMemo(() => {
    if (!Array.isArray(mappings)) return [];
    const q = mappingsSearch.trim().toLowerCase();
    if (!q) return mappings;
    return mappings.filter((m) =>
      `${m.framework} ${m.control_id} ${m.control_title} ${m.engine_id} ${m.evidence_type}`.toLowerCase().includes(q),
    );
  }, [mappings, mappingsSearch]);

  const mappingColumns = useMemo(() => {
    const ch = createColumnHelper();
    return [
      ch.accessor('framework', {
        id: 'framework',
        header: t('pages.complianceFrameworks.map_framework'),
        size: 130,
        cell: ({ getValue }) => (
          <span className="font-mono text-[var(--text-muted)] whitespace-nowrap uppercase">{getValue()}</span>
        ),
      }),
      ch.accessor('control_id', {
        id: 'control',
        header: t('pages.complianceFrameworks.map_control'),
        cell: ({ row, getValue }) => (
          <span>
            <span className="font-mono text-cyan-300/85">{getValue()}</span>
            {row.original.control_title && <span className="text-[var(--text-tertiary)]"> · {row.original.control_title}</span>}
          </span>
        ),
      }),
      ch.accessor((m) => m.engine_id || '—', {
        id: 'engine',
        header: t('pages.complianceFrameworks.map_engine'),
        size: 160,
        cell: ({ getValue }) => (
          <span className="font-mono text-violet-300/85 whitespace-nowrap">{getValue()}</span>
        ),
      }),
      ch.accessor((m) => m.evidence_type || '—', {
        id: 'evidence',
        header: t('pages.complianceFrameworks.map_evidence'),
        cell: ({ row, getValue }) => (
          <span className="text-[var(--text-tertiary)] whitespace-nowrap">
            {getValue()}
            {row.original.live_only && (
              <span className="ml-1.5 text-[9px] font-mono px-1 py-0.5 rounded border border-emerald-500/30 bg-emerald-500/10 text-emerald-300 uppercase">
                {t('pages.complianceFrameworks.map_live')}
              </span>
            )}
          </span>
        ),
      }),
    ];
  }, [t]);

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
          <div role="alert" className="rounded-xl border border-rose-500/30 bg-rose-950/30 px-4 py-3 text-sm text-rose-200">
            {error}
          </div>
        )}

        <div className="rounded-xl border border-cyan-500/20 bg-cyan-950/20 px-4 py-3 text-xs text-cyan-100/70">
          {t('pages.complianceFrameworks.evidence_notice')}
        </div>

        {/* Auditor evidence pack — tamper-evident, client-scoped */}
        <div className="rounded-xl border border-violet-500/25 bg-violet-950/15 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex items-start gap-3 min-w-0">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-violet-500/15 text-violet-300 ring-1 ring-violet-500/30">
                <FileCheck className="w-5 h-5" />
              </div>
              <div className="min-w-0">
                <h3 className="text-sm font-semibold text-white">{t('pages.complianceFrameworks.pack_title')}</h3>
                <p className="text-xs text-gray-400 mt-0.5 max-w-xl">{t('pages.complianceFrameworks.pack_subtitle')}</p>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              {pack && (
                <button
                  type="button"
                  onClick={downloadPack}
                  className="flex items-center gap-2 px-3 py-2 rounded-lg border border-violet-500/40 bg-violet-500/10 text-violet-200 text-sm font-medium hover:bg-violet-500/20 transition-colors"
                >
                  <Download className="w-4 h-4" />
                  {t('pages.complianceFrameworks.pack_download')}
                </button>
              )}
              <button
                type="button"
                onClick={generateEvidencePack}
                disabled={packLoading || selectedClientId == null}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-violet-500 text-white text-sm font-medium hover:bg-violet-600 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <RefreshCw className={`w-4 h-4 ${packLoading ? 'animate-spin' : ''}`} />
                {packLoading
                  ? t('pages.complianceFrameworks.pack_generating')
                  : pack
                    ? t('pages.complianceFrameworks.pack_regenerate')
                    : t('pages.complianceFrameworks.pack_generate')}
              </button>
            </div>
          </div>

          {selectedClientId == null ? (
            <div className="mt-3 text-xs font-mono text-amber-300/80">
              {t('pages.complianceFrameworks.pack_pick_client')}
            </div>
          ) : (
            <div className="mt-2 text-xs font-mono text-gray-500">
              {t('pages.complianceFrameworks.pack_scope', {
                client: selectedClient?.name || selectedClient?.domain || `#${selectedClientId}`,
                framework: selectedFramework?.name || t('pages.complianceFrameworks.pack_all_frameworks'),
              })}
            </div>
          )}

          {pack && (
            <div className="mt-4 space-y-4">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="rounded-lg border border-[var(--border-default)] bg-[var(--bg-2)] p-3">
                  <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-1">
                    {t('pages.complianceFrameworks.pack_findings')}
                  </div>
                  <div className="text-xl font-bold text-white tabular-nums">{pack.findings_total ?? 0}</div>
                </div>
                <div className="rounded-lg border border-[var(--border-default)] bg-[var(--bg-2)] p-3">
                  <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-1">
                    {t('pages.complianceFrameworks.pack_soar')}
                  </div>
                  <div className="text-xl font-bold text-cyan-300 tabular-nums">
                    {Array.isArray(pack.soar_executions) ? pack.soar_executions.length : 0}
                  </div>
                </div>
                <div className="rounded-lg border border-[var(--border-default)] bg-[var(--bg-2)] p-3">
                  <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-1">
                    {t('pages.complianceFrameworks.pack_audit_chain')}
                  </div>
                  <div
                    className="text-sm font-bold flex items-center gap-1.5"
                    style={{ color: pack.live_evidence?.audit_log_chain_intact ? '#4ade80' : '#f87171' }}
                  >
                    {pack.live_evidence?.audit_log_chain_intact ? <CheckCircle className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                    {pack.live_evidence?.audit_log_chain_intact
                      ? t('pages.complianceFrameworks.pack_intact')
                      : t('pages.complianceFrameworks.pack_broken')}
                  </div>
                </div>
                <div className="rounded-lg border border-[var(--border-default)] bg-[var(--bg-2)] p-3">
                  <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-1">
                    {t('pages.complianceFrameworks.pack_ready_label')}
                  </div>
                  <div
                    className="text-sm font-bold flex items-center gap-1.5"
                    style={{ color: pack.audit_ready ? '#4ade80' : '#facc15' }}
                  >
                    <ShieldCheck className="w-4 h-4" />
                    {pack.audit_ready ? t('pages.complianceFrameworks.pack_yes') : t('pages.complianceFrameworks.pack_no')}
                  </div>
                </div>
              </div>

              {pack.frameworks && Object.keys(pack.frameworks).length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {Object.entries(pack.frameworks).map(([fw, items]) => (
                    <span
                      key={fw}
                      className="text-[10px] font-mono px-2 py-1 rounded border border-violet-500/25 bg-violet-500/5 text-violet-200/85"
                    >
                      {fw} · {Array.isArray(items) ? items.length : 0}
                    </span>
                  ))}
                </div>
              )}

              {Array.isArray(pack.soar_executions) && pack.soar_executions.length > 0 && (
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-2">
                    {t('pages.complianceFrameworks.soar_heading')}
                  </div>
                  <ul className="space-y-1.5">
                    {pack.soar_executions.map((ex) => {
                      const open = soarOpenId === ex.id;
                      const st = String(ex.status || '').toLowerCase();
                      const stColor = st.includes('success') || st.includes('done') || st.includes('complete')
                        ? '#4ade80'
                        : st.includes('fail') || st.includes('error')
                          ? '#f87171'
                          : '#facc15';
                      return (
                        <li key={ex.id} className="rounded-lg border border-[var(--border-default)] bg-[var(--bg-2)] overflow-hidden">
                          <button
                            type="button"
                            onClick={() => toggleSoar(ex.id)}
                            aria-expanded={open}
                            className="w-full flex items-center gap-3 px-3 py-2 text-left hover:bg-[var(--row-hover-bg)] transition-colors"
                          >
                            <span className="text-[11px] font-mono px-1.5 py-0.5 rounded border border-cyan-500/25 bg-cyan-500/5 text-cyan-300/85 shrink-0">
                              {ex.action_kind || '—'}
                            </span>
                            <span
                              className="text-[9px] font-mono px-1.5 py-0.5 rounded uppercase tracking-wider shrink-0"
                              style={{ color: stColor, background: `${stColor}12` }}
                            >
                              {ex.status || '—'}
                            </span>
                            <span className="text-[11px] text-[var(--text-tertiary)] font-mono truncate flex-1 min-w-0">
                              {ex.target_id || ex.detail || '—'}
                            </span>
                            <span className="text-[10px] font-mono text-[var(--text-muted)] shrink-0 hidden sm:inline">
                              {ex.updated_at ? new Date(ex.updated_at).toLocaleString() : ''}
                            </span>
                          </button>
                          {open && (
                            <div className="px-3 pb-3 pt-1 border-t border-[var(--border-subtle)]">
                              {soarLoading ? (
                                <div className="text-[11px] font-mono text-[var(--text-muted)] py-2">
                                  {t('pages.complianceFrameworks.soar_loading')}
                                </div>
                              ) : soarDetail?._error ? (
                                <div className="text-[11px] font-mono text-rose-300 py-2">{soarDetail._error}</div>
                              ) : soarDetail ? (
                                <div className="space-y-2 pt-2">
                                  {soarDetail.provider && (
                                    <div className="text-[11px] font-mono text-[var(--text-tertiary)]">
                                      {t('pages.complianceFrameworks.soar_provider')}: {soarDetail.provider}
                                    </div>
                                  )}
                                  {soarDetail.result_detail && (
                                    <div className="text-[11px] text-[var(--text-secondary)]">{soarDetail.result_detail}</div>
                                  )}
                                  {soarDetail.blast_radius && Object.keys(soarDetail.blast_radius).length > 0 && (
                                    <div>
                                      <div className="text-[9px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-1">
                                        {t('pages.complianceFrameworks.soar_blast')}
                                      </div>
                                      <pre className="text-[10px] font-mono text-amber-200/80 bg-[var(--bg-3)] rounded-lg p-2 overflow-auto max-h-40 leading-relaxed">
                                        {JSON.stringify(soarDetail.blast_radius, null, 2)}
                                      </pre>
                                    </div>
                                  )}
                                  {soarDetail.revert_runbook?.id && (
                                    <div className="text-[11px] font-mono text-[var(--text-tertiary)]">
                                      {t('pages.complianceFrameworks.soar_revert', {
                                        status: soarDetail.revert_runbook.status || '—',
                                      })}
                                    </div>
                                  )}
                                </div>
                              ) : null}
                            </div>
                          )}
                        </li>
                      );
                    })}
                  </ul>
                </div>
              )}

              {pack.pack_sha256 && (
                <div className="flex items-center gap-2 text-[11px] font-mono text-[var(--text-muted)] flex-wrap">
                  <span className="uppercase tracking-widest">{t('pages.complianceFrameworks.pack_hash')}</span>
                  <code className="text-[var(--text-tertiary)] truncate max-w-[22rem]" title={pack.pack_sha256}>
                    {pack.pack_sha256}
                  </code>
                  <CopyButton value={pack.pack_sha256} />
                  {pack.snapshot_id != null && (
                    <span className="text-[var(--text-disabled)]">
                      · {t('pages.complianceFrameworks.pack_snapshot', { id: pack.snapshot_id })}
                    </span>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Control → evidence mapping matrix (lazy) */}
        <div className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4">
          <button
            type="button"
            onClick={toggleMappings}
            aria-expanded={mappingsOpen}
            className="w-full flex items-center justify-between gap-2 text-left"
          >
            <span className="text-sm font-semibold text-white flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyan-400" />
              {t('pages.complianceFrameworks.mappings_title')}
              {Array.isArray(mappings) && (
                <span className="text-[10px] font-mono text-[var(--text-muted)]">({mappings.length})</span>
              )}
            </span>
            <span className="text-[11px] font-mono text-cyan-400/80">
              {mappingsOpen ? t('pages.complianceFrameworks.mappings_hide') : t('pages.complianceFrameworks.mappings_show')}
            </span>
          </button>
          {mappingsOpen && (
            <div className="mt-3">
              {mappingsLoading ? (
                <SkeletonTable rows={4} cols={4} />
              ) : !Array.isArray(mappings) || mappings.length === 0 ? (
                <div className="text-[12px] font-mono text-[var(--text-muted)] py-3">
                  {t('pages.complianceFrameworks.mappings_empty')}
                </div>
              ) : (
                <>
                  <div className="relative max-w-md mb-3">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-disabled)] pointer-events-none" />
                    <input
                      type="search"
                      value={mappingsSearch}
                      onChange={(e) => setMappingsSearch(e.target.value)}
                      aria-label={t('pages.complianceFrameworks.mappings_search')}
                      placeholder={t('pages.complianceFrameworks.mappings_search')}
                      className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg pl-10 pr-3 py-2 text-sm text-white placeholder-white/25 focus:outline-none focus:border-cyan-500/40"
                    />
                  </div>
                  <DataTable
                    columns={mappingColumns}
                    data={filteredMappings}
                    animateRows={false}
                    getRowId={(m) => m.id}
                    exportable
                    exportFilename="weissman-control-mappings"
                    columnToggle
                    emptyFilteredMessage={t('pages.complianceFrameworks.mappings_empty')}
                    emptyState={{ icon: 'search', title: t('pages.complianceFrameworks.mappings_empty') }}
                  />
                </>
              )}
            </div>
          )}
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
                      : 'bg-[var(--bg-2)] text-gray-400 border-[var(--border-default)] hover:bg-[var(--row-hover-bg)] hover:text-[var(--text-primary)]'
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
                          : 'text-gray-400 hover:text-[var(--text-primary)] hover:bg-[var(--row-hover-bg)]'
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
