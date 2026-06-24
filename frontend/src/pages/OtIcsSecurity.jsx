import { useState, useEffect, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Factory, Cpu, AlertTriangle, Activity, Zap, Shield, ShieldAlert,
  ShieldCheck, Network,
} from 'lucide-react';
import PageShell from './PageShell';
import ShellScanActions from '../components/engine/ShellScanActions';
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel';
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench';
import EmptyState from '../components/ui/EmptyState';
import { SkeletonTable } from '../components/ui/Skeleton';
import { apiFetch } from '../lib/apiBase';
import { clientPrimaryTargetUrl } from '../lib/clientTarget';
import { useJobPoll, resolveJobFindings, uiJobStatus } from '../lib/useJobPoll';

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
    idle: { label: t('pages.otIcsSecurity.status_idle'), cls: 'text-gray-400 border-white/10 bg-white/5' },
  };
  const { label, cls } = map[status] ?? map.idle;
  return (
    <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-widest ${cls}`}>
      {label}
    </span>
  );
}

function OtEngineCard({ engine, clientId, clients, onScanComplete, onFindingsUpdate, showToast, t }) {
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
      const r = await apiFetch('/api/command-center/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ engine: engine.id, client_id: Number(clientId), target }),
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) {
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
  }, [clientId, clients, engine, showToast, t]);

  return (
    <div className="rounded-xl bg-black/40 backdrop-blur-md border border-white/10 p-5 space-y-3 hover:border-white/20 transition-all">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h3 className="text-sm font-semibold text-white">{t(engine.labelKey)}</h3>
            <StatusBadge status={status} t={t} />
          </div>
          <span className="text-[9px] font-mono text-white/30 bg-white/5 px-1.5 py-0.5 rounded border border-white/10">
            {engine.id}
          </span>
        </div>
        <button
          type="button"
          onClick={handleRun}
          disabled={status === 'running' || !clientId}
          className="shrink-0 px-3 py-1.5 rounded-lg text-[11px] font-mono uppercase border border-cyan-500/30 text-cyan-400/70 hover:bg-cyan-500/10 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          {status === 'running' ? '⟳' : t('pages.otIcsSecurity.scan')}
        </button>
      </div>
      <p className="text-[11px] text-white/45 leading-relaxed">{t(engine.descKey)}</p>
      {lastRun && (
        <p className="text-[10px] font-mono text-white/25">
          {t('pages.otIcsSecurity.last_scan', { time: lastRun })}
        </p>
      )}
      {findings.length > 0 && (
        <div className="space-y-2 pt-2 border-t border-white/5">
          <p className="text-[10px] font-mono text-white/35">
            {t('pages.otIcsSecurity.findings_count', { count: findings.length })}
          </p>
          {findings.slice(0, 4).map((f, i) => (
            <div key={f.id ?? i} className="text-[11px] font-mono text-white/60 bg-white/5 rounded px-2 py-1">
              <span className={`mr-2 uppercase text-[9px] ${
                f.severity === 'critical' ? 'text-red-400' :
                f.severity === 'high' ? 'text-orange-400' :
                f.severity === 'medium' ? 'text-yellow-400' : 'text-gray-400'
              }`}>
                {f.severity ?? 'info'}
              </span>
              {f.title ?? f.type ?? 'Finding'}
            </div>
          ))}
        </div>
      )}
    </div>
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
    <div key={f.id ?? f.finding_id ?? i} className="rounded-lg border border-white/10 bg-black/30 px-3 py-2 space-y-1">
      <div className="flex items-start gap-2 flex-wrap">
        <span
          className="text-[9px] font-mono uppercase shrink-0 px-1.5 py-0.5 rounded border"
          style={{ color: sevColor, borderColor: `${sevColor}40` }}
        >
          {sev}
        </span>
        {f._engine && (
          <span className="text-[9px] font-mono text-white/35 uppercase">{f._engine}</span>
        )}
        <span className="text-[12px] font-mono text-white/90 min-w-0 flex-1">{f.title ?? f.type ?? 'Finding'}</span>
      </div>
      {f.description && (
        <p className="text-[10px] font-mono text-white/45 leading-relaxed">{f.description}</p>
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
  const [loading, setLoading] = useState(true);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [lastJobId, setLastJobId] = useState(null);
  const [engineFindingsMap, setEngineFindingsMap] = useState({});
  const [toast, setToast] = useState(null);

  const fetchOtDevices = useCallback(async () => {
    try {
      const response = await apiFetch('/api/ot-ics/devices');
      if (response.ok) {
        const data = await response.json();
        setDevices(data.devices || []);
        setProtocols(data.protocols || []);
        setFindings(data.findings || []);
      }
    } catch (error) {
      console.error('Failed to fetch OT devices:', error);
    } finally {
      setLoading(false);
    }
  }, []);

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
      const r = await apiFetch('/api/engines/history/scada_ics?limit=1');
      if (r.ok) {
        const d = await r.json();
        const runs = Array.isArray(d) ? d : Array.isArray(d?.runs) ? d.runs : [];
        const last = runs[0];
        if (last) {
          const historyFindings = Array.isArray(last.findings) ? last.findings : [];
          setEngineFindingsMap((prev) => ({ ...prev, scada_ics: historyFindings }));
          setLastUpdated(last.completed_at || last.updated_at || last.created_at || null);
          setLastJobId(last.job_id ?? last.id ?? null);
        }
      }
      await fetchOtDevices();
    } finally {
      setHistoryLoading(false);
    }
  }, [fetchOtDevices]);

  useEffect(() => {
    handleRefresh();
    apiFetch('/api/clients')
      .then((r) => (r.ok ? r.json() : []))
      .then((d) => {
        if (!Array.isArray(d)) return;
        setClients(d);
        if (d.length) setSelectedClientId(String(d[0].id));
      })
      .catch(() => setClients([]));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps -- initial history + inventory load once on mount

  const deviceTypes = ['SCADA', 'PLC', 'HMI', 'RTU'].map((type) => ({
    type,
    count: devices.filter((d) => d.type === type.toLowerCase()).length,
    icon: DEVICE_TYPE_ICONS[type],
    color: DEVICE_TYPE_COLORS[type],
    labelKey: DEVICE_TYPE_KEYS[type],
  }));

  const filteredDevices = selectedClientId
    ? devices.filter((d) => !d.client_id || String(d.client_id) === String(selectedClientId))
    : devices;

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
            <span className="text-[11px] font-mono text-white/40">{t('pages.otIcsSecurity.client_label')}</span>
            <select
              value={selectedClientId ?? ''}
              onChange={(e) => setSelectedClientId(e.target.value || null)}
              className="bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white/80 font-mono focus:outline-none focus:border-cyan-500/40"
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
            <div key={key} className="rounded-2xl border border-white/10 bg-black/40 backdrop-blur-md p-4">
              <div className="flex items-start justify-between">
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-widest text-white/40">
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
              : 'bg-black/80 border-cyan-500/30 text-cyan-300'
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
              <div key={type} className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm text-gray-400">{t(labelKey)}</span>
                  <Icon className="w-4 h-4" style={{ color }} />
                </div>
                <div className="text-2xl font-bold text-white">{count}</div>
              </div>
            ))}
          </div>
        </div>

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
                onScanComplete={fetchOtDevices}
                onFindingsUpdate={handleFindingsUpdate}
                showToast={showToast}
                t={t}
              />
            ))}
          </div>
        </div>

        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-6">
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
                        <span className="text-xs text-gray-400">
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

        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl overflow-hidden">
          <div className="p-4 border-b border-white/10">
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
            <div className="divide-y divide-white/5">
              {filteredDevices.map((device) => (
                <div key={device.id} className="p-4 hover:bg-white/5 transition-colors">
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
                      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-400">
                        <span>{t('pages.otIcsSecurity.ip_label', { defaultValue: 'IP:' })} {device.ip ?? device.host ?? t('pages.otIcsSecurity.unknown')}</span>
                        {device.port > 0 && (
                          <>
                            <span>•</span>
                            <span>{t('pages.otIcsSecurity.port_label', { defaultValue: 'Port:' })} {device.port}</span>
                          </>
                        )}
                        <span>•</span>
                        <span>{t('pages.otIcsSecurity.vendor')} {device.vendor || t('pages.otIcsSecurity.unknown')}</span>
                        <span>•</span>
                        <span>{t('pages.otIcsSecurity.protocol')} {device.protocol || t('pages.otIcsSecurity.unknown')}</span>
                        {device.confidence != null && (
                          <>
                            <span>•</span>
                            <span>{t('pages.otIcsSecurity.confidence_label', { defaultValue: 'Confidence:' })} {(device.confidence * 100).toFixed(0)}%</span>
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
              <p className="text-xs text-gray-400 leading-relaxed">{t('pages.otIcsSecurity.notice_body')}</p>
            </div>
          </div>
        </div>
      </div>
    </PageShell>
  );
}
