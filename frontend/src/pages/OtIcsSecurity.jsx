import { useCommandCenterScan } from '../hooks/useCommandCenterScan'
import { useHubEngineFocus } from '../hooks/useLaunchEngineScan'
import { useState, useEffect, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Factory, Cpu, AlertTriangle, Activity, Zap, Shield, ShieldAlert,
  ShieldCheck, Network, Fingerprint,
} from 'lucide-react';
import PageShell from './PageShell';
import AgentRequiredGate from '../components/engine/AgentRequiredGate';
import ShellScanActions from '../components/engine/ShellScanActions';
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel';
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench';
import EmptyState from '../components/ui/EmptyState';
import { SkeletonTable } from '../components/ui/Skeleton';
import { apiFetch } from '../utils/apiFetch';
import { clientPrimaryTargetUrl } from '../lib/clientTarget';
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll';
import Button from '../components/ui/Button'

const FINDINGS_ACCENT = '#f97316';

const OT_ENGINES = [
  {
    id: 'scada_ics',
    labelKey: 'pages.otIcsSecurity.engine_scada',
    descKey: 'pages.otIcsSecurity.engine_scada_desc',
  },
  {
    id: 'modbus_attack',
    labelKey: 'pages.otIcsSecurity.engine_modbus',
    descKey: 'pages.otIcsSecurity.engine_modbus_desc',
  },
  {
    id: 'bacnet_attack',
    labelKey: 'pages.otIcsSecurity.engine_bacnet',
    descKey: 'pages.otIcsSecurity.engine_bacnet_desc',
  },
  {
    id: 'opcua_attack',
    labelKey: 'pages.otIcsSecurity.engine_opcua',
    descKey: 'pages.otIcsSecurity.engine_opcua_desc',
  },
];

// Protocol coloring is driven entirely by the backend status (info | warning | critical).
const PROTOCOL_STATUS_META = {
  critical: { color: '#f43f5e', Icon: ShieldAlert },
  warning: { color: '#fbbf24', Icon: ShieldAlert },
  info: { color: '#38bdf8', Icon: ShieldCheck },
};

const DEVICE_TYPE_KEYS = {
  SCADA: 'pages.otIcsSecurity.devices_scada',
  PLC: 'pages.otIcsSecurity.devices_plc',
  HMI: 'pages.otIcsSecurity.devices_hmi',
  RTU: 'pages.otIcsSecurity.devices_rtu',
};

const DEVICE_TYPE_ICONS = { SCADA: Activity, PLC: Cpu, HMI: Factory, RTU: Zap };
const DEVICE_TYPE_COLORS = { SCADA: '#22d3ee', PLC: '#a78bfa', HMI: '#60a5fa', RTU: '#fb923c' };

function StatusBadge({ status, t }) {
  const map = {
    running: { label: t('pages.otIcsSecurity.status_running'), cls: 'text-cyan-400 border-cyan-500/30 bg-cyan-500/10' },
    completed: { label: t('pages.otIcsSecurity.status_done'), cls: 'text-green-400 border-green-500/30 bg-green-500/10' },
    error: { label: t('pages.otIcsSecurity.status_error'), cls: 'text-red-400 border-red-500/30 bg-red-950/30' },
    idle: { label: t('pages.otIcsSecurity.status_idle'), cls: 'text-[var(--text-tertiary)] border-[var(--border-default)] bg-[var(--row-hover-bg)]' },
  };
  const { label, cls } = map[status] ?? map.idle;
  return (
    <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest ${cls}`}>
      {label}
    </span>
  );
}

function OtEngineCard({ engine, clientId, clients, onScanComplete, onFindingsUpdate, showToast, isFocused, onFocus, t }) {
  const { postScan } = useCommandCenterScan(clientId)
  useHubEngineFocus(engine.id, { active: isFocused })
  const [status, setStatus] = useState('idle');
  const [findings, setFindings] = useState([]);
  const [lastRun, setLastRun] = useState(null);
  const [pendingJobId, setPendingJobId] = useState(null);

  useJobPoll(pendingJobId, {
    enabled: Boolean(pendingJobId),
    onComplete: async (job) => {
      const terminal = uiJobStatus(job.status);
      setStatus(terminal);
      setLastRun(new Date().toLocaleTimeString());
      const resolved = await resolveJobFindings(job, engine.id, clientId);
      setFindings(resolved);
      onFindingsUpdate?.(engine.id, resolved);
      setPendingJobId(null);
      if (terminal === 'completed') onScanComplete?.();
    },
  });

  const handleRun = useCallback(async () => {
    if (!clientId) {
      showToast('error', t('pages.otIcsSecurity.select_client_first'));
      return;
    }
    const client = clients.find((c) => String(c.id) === String(clientId));
    const target = clientPrimaryTargetUrl(client);
    if (!target) {
      showToast('error', t('pages.otIcsSecurity.no_client_target'));
      return;
    }
    setStatus('running');
    setFindings([]);
    try {
      const { ok, data: d } = await postScan({ engine: engine.id, client_id: Number(clientId), target });
      if (!ok) {
        setStatus('error');
        showToast('error', d.detail || d.error || t('pages.otIcsSecurity.scan_failed'));
        return;
      }
      const jobId = d.job_id ?? '';
      if (jobId) {
        showToast('info', t('pages.otIcsSecurity.queued', { label: t(engine.labelKey), jobId }));
        setPendingJobId(jobId);
      } else {
        setStatus('error');
      }
    } catch (e) {
      setStatus('error');
      showToast('error', e?.message ?? t('pages.otIcsSecurity.scan_failed'));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clientId, clients, engine, showToast, t]);

  return (
    <AgentRequiredGate engineId={engine.id} className="rounded-xl">
    <div
      className="rounded-xl bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] p-5 space-y-3 hover:border-[var(--border-strong)] transition-all"
      onMouseEnter={onFocus}
      onFocus={onFocus}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h3 className="text-sm font-semibold text-white">{t(engine.labelKey)}</h3>
            <StatusBadge status={status} t={t} />
          </div>
          <span className="text-[9px] font-mono text-[var(--text-disabled)] bg-[var(--row-hover-bg)] px-1.5 py-0.5 rounded border border-[var(--border-default)]">
            {engine.id}
          </span>
        </div>
        <Button variant="unstyled"
          type="button"
          onClick={handleRun}
          disabled={status === 'running' || !clientId}
          className="shrink-0 px-3 py-1.5 rounded-lg text-[11px] font-mono uppercase border border-cyan-500/30 text-cyan-400/70 hover:bg-cyan-500/10 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          {status === 'running' ? '⟳' : t('pages.otIcsSecurity.scan')}
        </Button>
      </div>
      <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">{t(engine.descKey)}</p>
      {lastRun && (
        <p className="text-[10px] font-mono text-[var(--text-disabled)]">
          {t('pages.otIcsSecurity.last_scan', { time: lastRun })}
        </p>
      )}
      {findings.length > 0 && (
        <div className="space-y-2 pt-2 border-t border-[var(--border-subtle)]">
          <p className="text-[10px] font-mono text-[var(--text-muted)]">
            {t('pages.otIcsSecurity.findings_count', { count: findings.length })}
          </p>
          {findings.slice(0, 4).map((f, i) => (
            <div key={f.id ?? i} className="text-[11px] font-mono text-[var(--text-tertiary)] bg-[var(--row-hover-bg)] rounded px-2 py-1">
              <span className={`mr-2 uppercase text-[9px] ${
                f.severity === 'critical' ? 'text-red-400' :
                f.severity === 'high' ? 'text-orange-400' :
                f.severity === 'medium' ? 'text-yellow-400' : 'text-[var(--text-tertiary)]'
              }`}>
                {f.severity ?? 'info'}
              </span>
              {f.title ?? f.type ?? 'Finding'}
            </div>
          ))}
        </div>
      )}
    </div>
    </AgentRequiredGate>
  );
}

function renderOtFinding(f, i) {
  const sev = (f.severity || 'info').toLowerCase();
  const sevColor = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#f59e0b',
    low: '#22d3ee',
    info: '#64748b',
  }[sev] || '#64748b';
  return (
    <div key={f.id ?? f.finding_id ?? i} className="rounded-lg border border-[var(--border-default)] bg-[var(--table-surface)] px-3 py-2 space-y-1">
      <div className="flex items-start gap-2 flex-wrap">
        <span
          className="text-[9px] font-mono uppercase shrink-0 px-1.5 py-0.5 rounded border"
          style={{ color: sevColor, borderColor: `${sevColor}40` }}
        >
          {sev}
        </span>
        {f._engine && (
          <span className="text-[9px] font-mono text-[var(--text-muted)] uppercase">{f._engine}</span>
        )}
        <span className="text-[12px] font-mono text-[var(--text-primary)] min-w-0 flex-1">{f.title ?? f.type ?? 'Finding'}</span>
      </div>
      {f.description && (
        <p className="text-[10px] font-mono text-[var(--text-muted)] leading-relaxed">{f.description}</p>
      )}
    </div>
  );
}

export default function OtIcsSecurity() {
  const { t } = useTranslation();
  const [devices, setDevices] = useState([]);
  const [protocols, setProtocols] = useState([]);
  const [findings, setFindings] = useState([]);
  const [clients, setClients] = useState([]);
  const [selectedClientId, setSelectedClientId] = useState(null);
  const [focusedEngineId, setFocusedEngineId] = useState(OT_ENGINES[0].id);
  const [loading, setLoading] = useState(true);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [lastJobId, setLastJobId] = useState(null);
  const [engineFindingsMap, setEngineFindingsMap] = useState({});
  const [toast, setToast] = useState(null);
  const [fingerprints, setFingerprints] = useState([]);
  const [fpLoading, setFpLoading] = useState(false);

  const fetchOtDevices = useCallback(async () => {
    try {
      const data = await apiFetch('/api/ot-ics/devices');
      setDevices(data.devices || []);
      setProtocols(data.protocols || []);
      setFindings(data.findings || []);
    } catch (error) {
      console.error('Failed to fetch OT devices:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  // Per-client passive fingerprints — deeper forensic detail (vendor hint,
  // confidence, raw protocol bytes) beyond the global device inventory.
  // Wired to GET /api/clients/:id/ot-ics/fingerprints.
  const fetchFingerprints = useCallback(async (cid) => {
    if (cid == null || cid === '') {
      setFingerprints([]);
      return;
    }
    setFpLoading(true);
    try {
      const d = await apiFetch(`/api/clients/${encodeURIComponent(cid)}/ot-ics/fingerprints`);
      setFingerprints(Array.isArray(d.fingerprints) ? d.fingerprints : []);
    } catch {
      setFingerprints([]);
    } finally {
      setFpLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchFingerprints(selectedClientId);
  }, [selectedClientId, fetchFingerprints]);

  const showToast = useCallback((sev, msg) => {
    const id = Date.now();
    setToast({ id, sev, msg });
    setTimeout(() => setToast((cur) => (cur?.id === id ? null : cur)), 5000);
  }, []);

  const handleFindingsUpdate = useCallback((engineId, findings) => {
    setEngineFindingsMap((prev) => ({ ...prev, [engineId]: findings }));
  }, []);

  const aggregatedScanFindings = useMemo(() => {
    const all = [];
    const seen = new Set();
    for (const engine of OT_ENGINES) {
      for (const f of engineFindingsMap[engine.id] || []) {
        const key = f.id ?? f.finding_id ?? `${engine.id}-${f.title}-${f.type}`;
        if (seen.has(key)) continue;
        seen.add(key);
        all.push({ ...f, _engine: engine.id });
      }
    }
    return all;
  }, [engineFindingsMap]);

  const {
    filteredFindings: filteredScanFindings,
    counts: scanCounts,
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    exportCsv,
    total: scanTotal,
  } = useFindingsWorkbench(aggregatedScanFindings, {
    csvPrefix: 'ot-ics-security',
    haystackFn: (f) => `${f.title || ''} ${f.type || ''} ${f.description || ''} ${f._engine || ''} ${f.source || ''}`,
  });

  const handleRefresh = useCallback(async () => {
    setHistoryLoading(true);
    try {
      try {
        const d = await apiFetch('/api/engines/history/scada_ics?limit=1');
        const runs = Array.isArray(d) ? d : Array.isArray(d?.runs) ? d.runs : [];
        const last = runs[0];
        if (last) {
          const historyFindings = Array.isArray(last.findings) ? last.findings : [];
          setEngineFindingsMap((prev) => ({ ...prev, scada_ics: historyFindings }));
          setLastUpdated(last.completed_at || last.updated_at || last.created_at || null);
          setLastJobId(last.job_id ?? last.id ?? null);
        }
      } catch { /* history unavailable — still refresh the device inventory below */ }
      await fetchOtDevices();
    } finally {
      setHistoryLoading(false);
    }
  }, [fetchOtDevices]);

  useEffect(() => {
    handleRefresh();
    apiFetch('/api/clients')
      .then((d) => {
        if (!Array.isArray(d)) return;
        setClients(d);
        if (d.length) setSelectedClientId(String(d[0].id));
      })
      .catch(() => setClients([]));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps -- initial history + inventory load once on mount

  const filteredDevices = selectedClientId
    ? devices.filter((d) => !d.client_id || String(d.client_id) === String(selectedClientId))
    : devices;

  const deviceTypes = useMemo(() => ['SCADA', 'PLC', 'HMI', 'RTU'].map((type) => ({
    type,
    count: filteredDevices.filter((d) => d.type === type.toLowerCase()).length,
    icon: DEVICE_TYPE_ICONS[type],
    color: DEVICE_TYPE_COLORS[type],
    labelKey: DEVICE_TYPE_KEYS[type],
  })), [filteredDevices]);

  const filteredFindings = selectedClientId
    ? findings.filter((f) => !f.client_id || String(f.client_id) === String(selectedClientId))
    : findings;

  // KPI strip — every value derived from the real /api/ot-ics/devices response.
  const kpis = useMemo(() => {
    const sev = (f) => String(f.severity || '').toLowerCase();
    return {
      devices: filteredDevices.length,
      protocols: protocols.length,
      findings: filteredFindings.length,
      severe: filteredFindings.filter((f) => sev(f) === 'critical' || sev(f) === 'high').length,
    };
  }, [filteredDevices, protocols, filteredFindings]);

  return (
    <PageShell
      engineId={focusedEngineId}
      title={t('pages.otIcsSecurity.title')}
      subtitle={t('pages.otIcsSecurity.subtitle')}
      badge={t('pages.otIcsSecurity.badge')}
      badgeColor="#22d3ee"
      icon={<Factory />}
      actions={(
        <ShellScanActions
          onRefresh={handleRefresh}
          onExport={exportCsv}
          refreshLoading={historyLoading || loading}
          exportDisabled={!filteredScanFindings.length}
        />
      )}
    >
      <div className="space-y-6">
        {clients.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono text-[var(--text-muted)]">{t('pages.otIcsSecurity.client_label')}</span>
            <select
              value={selectedClientId ?? ''}
              onChange={(e) => setSelectedClientId(e.target.value || null)}
              className="bg-[var(--scrim)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-cyan-500/40"
            >
              {clients.map((c) => (
                <option key={c.id} value={c.id}>{c.name}</option>
              ))}
            </select>
          </div>
        )}

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {[
            { key: 'kpi_devices', value: kpis.devices, color: '#22d3ee', Icon: Cpu },
            { key: 'kpi_protocols', value: kpis.protocols, color: '#a78bfa', Icon: Network },
            { key: 'kpi_findings', value: kpis.findings, color: '#fb923c', Icon: AlertTriangle },
            { key: 'kpi_severe', value: kpis.severe, color: '#f43f5e', Icon: ShieldAlert },
          ].map(({ key, value, color, Icon }) => (
            <div key={key} className="rounded-2xl border border-[var(--border-default)] bg-[var(--bg-2)] backdrop-blur-md p-4">
              <div className="flex items-start justify-between">
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)]">
                    {t(`pages.otIcsSecurity.${key}`)}
                  </div>
                  <div className="text-2xl font-bold mt-1 tabular-nums" style={{ color }}>
                    {loading ? '—' : value}
                  </div>
                </div>
                <Icon className="w-4 h-4 shrink-0" style={{ color }} />
              </div>
            </div>
          ))}
        </div>

        {toast && (
          <div className={`fixed top-16 right-4 z-50 rounded-xl border px-4 py-3 text-sm font-mono max-w-sm shadow-2xl ${
            toast.sev === 'error'
              ? 'bg-rose-950/90 border-rose-500/40 text-rose-200'
              : 'bg-[var(--bg-1)] border-cyan-500/30 text-cyan-300'
          }`}>
            {toast.msg}
          </div>
        )}

        <div>
          <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            {t('pages.otIcsSecurity.inventory_heading')}
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {deviceTypes.map(({ type, count, icon: Icon, color, labelKey }) => (
              <div key={type} className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-[var(--text-tertiary)]">{t(labelKey)}</span>
                  <Icon className="w-4 h-4" style={{ color }} />
                </div>
                <div className="text-2xl font-bold text-white">{count}</div>
              </div>
            ))}
          </div>
        </div>

        {selectedClientId != null && (fpLoading || fingerprints.length > 0) && (
          <div>
            <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
              <Fingerprint className="w-4 h-4 text-cyan-400" />
              {t('pages.otIcsSecurity.fingerprints_heading')}
              {!fpLoading && (
                <span className="text-[10px] font-mono text-[var(--text-muted)]">({fingerprints.length})</span>
              )}
            </h3>
            <p className="text-[11px] text-[var(--text-muted)] mb-3">{t('pages.otIcsSecurity.fingerprints_hint')}</p>
            {fpLoading ? (
              <SkeletonTable rows={3} cols={4} />
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                {fingerprints.map((fp) => {
                  const conf = Math.max(0, Math.min(1, Number(fp.confidence) || 0));
                  const confPct = Math.round(conf * 100);
                  const confColor = conf >= 0.75 ? '#4ade80' : conf >= 0.4 ? '#facc15' : '#fb923c';
                  return (
                    <div key={fp.id} className="rounded-xl border border-[var(--border-default)] bg-[var(--bg-2)] p-4 space-y-2">
                      <div className="flex items-center justify-between gap-2 flex-wrap">
                        <code className="text-[12px] font-mono text-[var(--text-primary)]">
                          {fp.host || '—'}:{fp.port || 0}
                        </code>
                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-violet-500/30 bg-violet-500/10 text-violet-300/85 uppercase tracking-wider">
                          {fp.protocol || t('pages.otIcsSecurity.fp_unknown_protocol')}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-mono uppercase tracking-widest text-[var(--text-muted)] shrink-0">
                          {t('pages.otIcsSecurity.fp_vendor')}
                        </span>
                        <span className="text-[12px] text-[var(--text-secondary)] truncate">
                          {fp.vendor_hint || t('pages.otIcsSecurity.fp_unknown_vendor')}
                        </span>
                      </div>
                      <div>
                        <div className="flex items-center justify-between text-[10px] font-mono text-[var(--text-muted)] mb-1">
                          <span className="uppercase tracking-widest">{t('pages.otIcsSecurity.fp_confidence')}</span>
                          <span style={{ color: confColor }}>{confPct}%</span>
                        </div>
                        <div className="h-1.5 rounded-full bg-[var(--border-strong)] overflow-hidden">
                          <div className="h-full rounded-full" style={{ width: `${confPct}%`, background: confColor }} />
                        </div>
                      </div>
                      {fp.raw_excerpt_hex && (
                        <code className="ltr-only block text-[10px] font-mono text-[var(--text-tertiary)] bg-[var(--bg-3)] rounded-lg px-2 py-1.5 truncate" title={fp.raw_excerpt_hex}>
                          {fp.raw_excerpt_hex}
                        </code>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        <div>
          <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            {t('pages.otIcsSecurity.engines_heading')}
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {OT_ENGINES.map((engine) => (
              <OtEngineCard
                key={engine.id}
                engine={engine}
                clientId={selectedClientId}
                clients={clients}
                isFocused={focusedEngineId === engine.id}
                onFocus={() => setFocusedEngineId(engine.id)}
                onScanComplete={fetchOtDevices}
                onFindingsUpdate={handleFindingsUpdate}
                showToast={showToast}
                t={t}
              />
            ))}
          </div>
        </div>

        <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl p-6">
          <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <Network className="w-4 h-4 text-cyan-400" />
            {t('pages.otIcsSecurity.protocols_heading')}
          </h3>
          {loading ? (
            <SkeletonTable rows={2} cols={3} />
          ) : protocols.length === 0 ? (
            <EmptyState
              compact
              icon="radar"
              title={t('pages.otIcsSecurity.protocols_empty_title')}
              body={t('pages.otIcsSecurity.protocols_empty_body')}
            />
          ) : (
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              {[...protocols]
                .sort((a, b) => (b.count ?? 0) - (a.count ?? 0))
                .map((p) => {
                  const meta = PROTOCOL_STATUS_META[p.status] ?? PROTOCOL_STATUS_META.info;
                  const Icon = meta.Icon;
                  return (
                    <div
                      key={p.name}
                      className="p-4 rounded-lg border"
                      style={{ borderColor: `${meta.color}33`, background: `${meta.color}0d` }}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm font-medium text-white">{p.name}</span>
                        <Icon className="w-4 h-4" style={{ color: meta.color }} />
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-xs text-[var(--text-tertiary)]">
                          {t('pages.otIcsSecurity.devices_count', { count: p.count ?? 0 })}
                        </span>
                        <span
                          className="text-[9px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border"
                          style={{ color: meta.color, borderColor: `${meta.color}40` }}
                        >
                          {t(`pages.otIcsSecurity.protocol_status_${p.status}`, p.status)}
                        </span>
                      </div>
                    </div>
                  );
                })}
            </div>
          )}
        </div>

        <div className="bg-[var(--bg-2)] backdrop-blur-md border border-[var(--border-default)] rounded-xl overflow-hidden">
          <div className="p-4 border-b border-[var(--border-default)]">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Factory className="w-4 h-4 text-cyan-400" />
              {t('pages.otIcsSecurity.devices_heading')}
            </h3>
          </div>

          {loading ? (
            <div className="p-4">
              <SkeletonTable rows={5} cols={4} />
            </div>
          ) : filteredDevices.length === 0 ? (
            <div className="p-4">
              <EmptyState
                compact
                icon="search"
                title={t('pages.otIcsSecurity.devices_empty_title')}
                body={t('pages.otIcsSecurity.empty_scan_hint')}
              />
            </div>
          ) : (
            <div className="divide-y divide-[var(--border-subtle)]">
              {filteredDevices.map((device) => (
                <div key={device.id} className="p-4 hover:bg-[var(--row-hover-bg)] transition-colors">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <span className="px-2 py-1 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded text-xs font-medium">
                          {(device.type ?? 'unknown').toUpperCase()}
                        </span>
                        <h4 className="text-sm font-semibold text-white">
                          {device.name || device.host || device.ip}
                        </h4>
                        {device.status && (
                          <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${
                            device.status === 'verified'
                              ? 'text-green-400 border-green-500/30'
                              : 'text-yellow-400 border-yellow-500/30'
                          }`}>
                            {device.status}
                          </span>
                        )}
                      </div>
                      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[var(--text-tertiary)]">
                        <span>{t('pages.otIcsSecurity.ip_label')} {device.ip ?? device.host ?? t('pages.otIcsSecurity.unknown')}</span>
                        {device.port > 0 && (
                          <>
                            <span>•</span>
                            <span>{t('pages.otIcsSecurity.port_label')} {device.port}</span>
                          </>
                        )}
                        <span>•</span>
                        <span>{t('pages.otIcsSecurity.vendor')} {device.vendor || t('pages.otIcsSecurity.unknown')}</span>
                        <span>•</span>
                        <span>{t('pages.otIcsSecurity.protocol')} {device.protocol || t('pages.otIcsSecurity.unknown')}</span>
                        {device.confidence != null && (
                          <>
                            <span>•</span>
                            <span>{t('pages.otIcsSecurity.confidence_label')} {(device.confidence * 100).toFixed(0)}%</span>
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

        <WeissmanFindingsPanel
          findings={aggregatedScanFindings}
          filteredFindings={filteredScanFindings}
          counts={scanCounts}
          total={scanTotal}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          severityFilter={severityFilter}
          onSeverityChange={setSeverityFilter}
          loading={historyLoading && !aggregatedScanFindings.length}
          lastUpdated={lastUpdated}
          jobId={lastJobId}
          accent={FINDINGS_ACCENT}
          title={t('pages.otIcsSecurity.scan_findings_title')}
          emptyTitle={t('pages.otIcsSecurity.scan_findings_empty_title')}
          emptyBody={t('pages.otIcsSecurity.scan_findings_empty_body')}
          showEmptyReady
          emptyReadyTitle={t('pages.otIcsSecurity.scan_findings_ready_title')}
          emptyReadyBody={t('pages.otIcsSecurity.scan_findings_ready_body')}
          renderFinding={renderOtFinding}
        />

        <div className="bg-gradient-to-r from-orange-500/10 to-red-500/10 backdrop-blur-md border border-orange-500/30 rounded-xl p-6">
          <div className="flex items-start gap-4">
            <AlertTriangle className="w-5 h-5 text-orange-400 flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="text-sm font-semibold text-white mb-1">{t('pages.otIcsSecurity.notice_title')}</h3>
              <p className="text-xs text-[var(--text-tertiary)] leading-relaxed">{t('pages.otIcsSecurity.notice_body')}</p>
            </div>
          </div>
        </div>
      </div>
    </PageShell>
  );
}
