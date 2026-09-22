import { useState, useEffect, useMemo, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { Network, Globe, Shield, Activity, AlertTriangle, Search, Download } from 'lucide-react';
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import { apiFetch } from '../utils/apiFetch';
import EvidenceNotice from '../components/ui/EvidenceNotice';
import EmptyState from '../components/ui/EmptyState'
import Button from '../components/ui/Button'
import { downloadCsv } from '../lib/exportFindingsCsv'

/**
 * NetworkProtocols — live protocol-exposure posture served by the SOC
 * aggregator at GET /api/soc/network-protocols. No fabricated stats.
 */

function getStatusColor(status) {
  switch (status) {
    case 'critical': return 'text-[var(--severity-critical)] bg-red-500/10 border-red-500/30';
    case 'warning': return 'text-[var(--severity-medium)] bg-yellow-500/10 border-yellow-500/30';
    case 'secure': return 'text-[var(--severity-low)] bg-green-500/10 border-green-500/30';
    default: return 'text-[var(--text-tertiary)] bg-[var(--border-strong)]/10 border-[var(--border-strong)]/30';
  }
}

export default function NetworkProtocols() {
  const { t } = useTranslation();
  const [clients, setClients] = useState([]);
  const [clientsUnavailable, setClientsUnavailable] = useState(false);
  const [selectedClientId, setSelectedClientId] = useState('');
  const [protocols, setProtocols] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [dataSource, setDataSource] = useState('findings');
  const [protocolSearch, setProtocolSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');

  useEffect(() => {
    apiFetch('/api/clients')
      .then((d) => {
        if (Array.isArray(d)) { setClients(d); setClientsUnavailable(false); }
        else setClientsUnavailable(true);
      })
      .catch(() => { setClientsUnavailable(true); });
  }, []);

  const loadProtocols = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = selectedClientId
        ? await apiFetch(`/api/soc/network-protocols?client_id=${encodeURIComponent(selectedClientId)}`)
        : await apiFetch('/api/soc/network-protocols');
      const list = Array.isArray(data?.protocols) ? data.protocols : [];
      setProtocols(list);
      setDataSource('soc');
    } catch (e) {
      setProtocols([]);
      setError(e.message || 'Failed to load protocol data');
    } finally {
      setLoading(false);
    }
  }, [selectedClientId]);

  useEffect(() => {
    // eslint-disable-next-line no-restricted-syntax -- intentional best-effort swallow
    loadProtocols().catch(() => {});
  }, [loadProtocols]);

  const stats = useMemo(() => ({
    scanned: protocols.length,
    critical: protocols.filter((p) => p.status === 'critical').length,
    warning: protocols.filter((p) => p.status === 'warning').length,
    secure: protocols.filter((p) => p.status === 'secure').length,
  }), [protocols]);

  const filteredProtocols = useMemo(() => {
    const q = protocolSearch.trim().toLowerCase();
    return protocols.filter((p) => {
      if (statusFilter !== 'all' && p.status !== statusFilter) return false;
      if (!q) return true;
      return `${p.name} ${p.status}`.toLowerCase().includes(q);
    });
  }, [protocols, protocolSearch, statusFilter]);

  const statusLabel = useCallback((status) => {
    if (status === 'critical') return t('pages.networkProtocols.status_critical');
    if (status === 'warning') return t('pages.networkProtocols.status_warning');
    if (status === 'secure') return t('pages.networkProtocols.status_secure');
    return status;
  }, [t]);

  const exportCsv = useCallback(() => {
    const header = ['protocol', 'status', 'findings'];
    const rows = filteredProtocols.map((p) => [p.name, p.status, p.findings]);
    downloadCsv(rows, header, 'network-protocols');
  }, [filteredProtocols]);

  return (
    <PageShell
      title={t('pages.networkProtocols.title')}
      icon={<Network />}
      actions={(
        <ShellScanActions
          onRefresh={loadProtocols}
          onExport={error ? undefined : exportCsv}
          refreshLoading={loading}
          exportDisabled={!filteredProtocols.length}
        />
      )}
    >
      <div className="space-y-6">
        <EvidenceNotice>{t('pages.networkProtocols.evidence_notice')}</EvidenceNotice>

        <div className="flex flex-wrap items-center gap-3">
          <span className="text-[11px] font-mono text-[var(--text-muted)]">{t('pages.networkProtocols.client_scope')}</span>
          <select
            value={selectedClientId}
            onChange={(e) => setSelectedClientId(e.target.value)}
            aria-label={t('pages.networkProtocols.client_scope')}
            className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-cyan-500/40"
          >
            <option value="">{t('pages.networkProtocols.all_clients')}</option>
            {clients.map((c) => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>
          <span className="text-[10px] font-mono text-[var(--text-disabled)]">
            {t('pages.networkProtocols.source_label', { source: dataSource === 'soc' ? '/api/soc/network-protocols' : dataSource })}
          </span>
          {clientsUnavailable && (
            <span className="text-[10px] font-mono text-amber-300/80" data-testid="network-protocols-clients-unavailable">
              {t('pages.networkProtocols.clients_unavailable')}
            </span>
          )}
          <Link to="/findings" className="text-xs text-cyan-300 hover:text-cyan-200 ml-auto">{t('pages.networkProtocols.open_findings')}</Link>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[200px] max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--text-disabled)] pointer-events-none" />
            <input
              type="search"
              value={protocolSearch}
              onChange={(e) => setProtocolSearch(e.target.value)}
              aria-label={t('pages.networkProtocols.search_placeholder')}
              placeholder={t('pages.networkProtocols.search_placeholder')}
              className="w-full bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg pl-10 pr-3 py-2 text-sm text-[var(--text-primary)] font-mono placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500/40"
            />
          </div>
          {!error && (
          <Button variant="unstyled"
            type="button"
            onClick={exportCsv}
            disabled={filteredProtocols.length === 0}
            className="inline-flex items-center gap-2 px-3 py-2 rounded-lg border border-emerald-500/30 text-xs font-mono text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-40"
          >
            <Download className="h-3.5 w-3.5" />
            {t('pages.networkProtocols.export_csv')}
          </Button>
          )}
        </div>

        {loading ? (
          <div className="p-6 text-sm text-[var(--text-muted)]">{t('pages.networkProtocols.loading')}</div>
        ) : error ? (
          <div data-testid="network-protocols-unavailable">
            <EmptyState
              icon="network"
              title={t('pages.networkProtocols.unavailable_title')}
              body={t('pages.networkProtocols.unavailable_body')}
            />
          </div>
        ) : (
        <>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[
            { id: 'all', label: t('pages.networkProtocols.protocols_scanned'), value: stats.scanned, Icon: Network, color: '#22d3ee' },
            { id: 'critical', label: t('pages.networkProtocols.critical_issues'), value: stats.critical, Icon: AlertTriangle, color: 'var(--severity-critical)' },
            { id: 'warning', label: t('pages.networkProtocols.warnings'), value: stats.warning, Icon: Activity, color: 'var(--severity-medium)' },
            { id: 'secure', label: t('pages.networkProtocols.secure'), value: stats.secure, Icon: Shield, color: 'var(--severity-low)' },
          ].map(({ id, label, value, Icon, color }) => {
            const active = statusFilter === id;
            return (
              <Button
                variant="unstyled"
                key={id}
                type="button"
                onClick={() => setStatusFilter(id)}
                aria-pressed={active}
                className="bg-[var(--bg-2)] backdrop-blur-md border rounded-xl p-4 text-left transition-all hover:border-[var(--border-strong)]"
                style={{ borderColor: active ? color : 'var(--border-default)', boxShadow: active ? `0 0 0 1px ${color} inset` : 'none' }}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-[var(--text-tertiary)]">{label}</span>
                  <Icon className="w-4 h-4" style={{ color }} />
                </div>
                <div className="text-2xl font-bold text-[var(--text-primary)] tabular-nums">{value}</div>
              </Button>
            );
          })}
        </div>

        <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl overflow-hidden">
          <div className="p-4 border-b border-[var(--border-default)]">
            <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              {t('pages.networkProtocols.heading')}
            </h3>
          </div>

          {protocols.length === 0 ? (
            <div className="p-6 space-y-3 text-sm text-[var(--text-tertiary)]">
              <p>{t('pages.networkProtocols.empty_title')}</p>
              <p className="text-xs text-[var(--text-muted)]">
                {t('pages.networkProtocols.empty_hint')}{' '}
                <Link to="/network" className="text-cyan-300 hover:text-cyan-200">{t('pages.networkProtocols.network_intel_link')}</Link>
                {' '}{t('pages.networkProtocols.empty_suffix')}
              </p>
            </div>
          ) : filteredProtocols.length === 0 ? (
            <div className="p-6 text-sm text-[var(--text-tertiary)] text-center">
              {t('pages.networkProtocols.no_search_results')}
            </div>
          ) : (
            <div className="divide-y divide-[var(--border-subtle)]">
              {filteredProtocols.map((protocol) => (
                <div key={protocol.name} className="p-4 hover:bg-[var(--row-hover-bg)] transition-colors">
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h4 className="text-sm font-semibold text-[var(--text-primary)]">{protocol.name}</h4>
                        <span className={`px-2 py-1 rounded text-xs font-medium border ${getStatusColor(protocol.status)}`}>
                          {statusLabel(protocol.status)}
                        </span>
                      </div>
                      <div className="text-xs text-[var(--text-tertiary)]">
                        {protocol.findings === 1
                          ? t('pages.networkProtocols.findings_one', { count: protocol.findings })
                          : t('pages.networkProtocols.findings_other', { count: protocol.findings })}
                      </div>
                    </div>
                    <Link
                      to="/findings"
                      className="px-3 py-1.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs font-medium hover:bg-cyan-500/30 transition-colors"
                    >
                      {t('pages.networkProtocols.view_findings')}
                    </Link>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
        </>
        )}
      </div>
    </PageShell>
  );
}
