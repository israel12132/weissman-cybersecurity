import { useState, useEffect, useCallback, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Puzzle, GitBranch, ShieldAlert, Network } from 'lucide-react';
import PageShell from './PageShell';
import EmptyState from '../components/ui/EmptyState';
import ShellScanActions from '../components/engine/ShellScanActions';
import WeissmanFindingsPanel from '../components/engine/WeissmanFindingsPanel';
import { useFindingsWorkbench } from '../hooks/useFindingsWorkbench';
import { SkeletonWidgetGrid } from '../components/ui/Skeleton';
import { api } from '../utils/apiFetch';
import { useFirstTenantClientId } from '../lib/aliasClient';
import AttackExposurePanel from './AttackExposurePanel';

const ACCENT = '#22d3ee';

function scoreTone(score) {
  if (score >= 60) return { text: 'text-red-400', ring: 'border-red-500/40', bg: 'bg-red-500/10' };
  if (score >= 30) return { text: 'text-amber-400', ring: 'border-amber-500/40', bg: 'bg-amber-500/10' };
  if (score > 0) return { text: 'text-cyan-400', ring: 'border-cyan-500/40', bg: 'bg-cyan-500/10' };
  return { text: 'text-emerald-400', ring: 'border-emerald-500/30', bg: 'bg-emerald-500/10' };
}

function sevColor(sev) {
  const s = String(sev || '').toLowerCase();
  if (s === 'critical') return 'text-red-400';
  if (s === 'high') return 'text-orange-400';
  if (s === 'medium') return 'text-amber-400';
  return 'text-cyan-400';
}

export default function ThreatAnalysisCenter() {
  const { t } = useTranslation();
  const { clientId, loading: clientLoading } = useFirstTenantClientId();
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [persisting, setPersisting] = useState(false);
  const [error, setError] = useState(null);
  const [persistedNote, setPersistedNote] = useState(null);

  const fetchReport = useCallback(async (cid) => {
    if (cid == null) {
      setReport(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await api.get(`/api/threat-analysis/${cid}`);
      setReport(res || null);
    } catch (e) {
      setError(e?.message || 'Failed to load threat analysis');
      setReport(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (clientLoading) return;
    fetchReport(clientId);
  }, [clientId, clientLoading, fetchReport]);

  const persistIncidents = async () => {
    if (clientId == null) return;
    setPersisting(true);
    setPersistedNote(null);
    try {
      const res = await api.get(`/api/threat-analysis/${clientId}?persist=1`);
      setReport(res || null);
      setPersistedNote(
        t('pages.threatAnalysis.persisted', { n: res?.persisted_incidents ?? 0,
        }),
      );
    } catch (e) {
      setPersistedNote(e?.message || 'Persist failed (operator role required).');
    } finally {
      setPersisting(false);
    }
  };

  const analysis = report?.analysis || {};
  const summary = analysis.summary || {};
  const score = Number(analysis.incident_score || 0);
  const tone = scoreTone(score);
  const chain = analysis.attack_chain;
  const hits = Array.isArray(analysis.correlation_hits) ? analysis.correlation_hits : [];
  const netFindings = Array.isArray(analysis.network_findings) ? analysis.network_findings : [];
  const idFindings = Array.isArray(analysis.identity_findings) ? analysis.identity_findings : [];

  const unifiedFindings = useMemo(() => {
    const list = [];
    hits.forEach((h, idx) => {
      list.push({
        id: `corr-${idx}-${h.rule_name}-${h.target}`,
        severity: h.severity || 'medium',
        title: h.rule_name,
        type: 'correlation',
        description: `${h.target} · span ${h.span_secs}s`,
        target: h.target,
        stages: h.stages || [],
      });
    });
    netFindings.forEach((f, idx) => {
      list.push({
        id: `net-${idx}-${f.kind}-${f.dst}`,
        severity: f.severity || 'medium',
        title: `${f.kind} · ${f.dst}`,
        type: 'network',
        description: f.mitre ? `MITRE ${f.mitre}` : 'NDR detection',
        mitre: f.mitre,
      });
    });
    idFindings.forEach((f, idx) => {
      list.push({
        id: `id-${idx}-${f.kind}-${f.subject}`,
        severity: f.severity || 'medium',
        title: `${f.kind} · ${f.subject}`,
        type: 'identity',
        description: f.mitre ? `MITRE ${f.mitre}` : 'ITDR detection',
        mitre: f.mitre,
      });
    });
    return list;
  }, [hits, netFindings, idFindings]);

  const {
    filteredFindings,
    counts,
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    exportCsv,
    total,
  } = useFindingsWorkbench(unifiedFindings, {
    csvPrefix: 'threat-analysis',
    haystackFn: (f) => `${f.title} ${f.type} ${f.description} ${f.target || ''} ${(f.stages || []).map((s) => s.category).join(' ')} ${f.mitre || ''}`,
  });

  const handleRefresh = useCallback(() => {
    fetchReport(clientId);
  }, [fetchReport, clientId]);

  return (
    <PageShell
      title={t('pages.threatAnalysis.title')}
      icon={<Puzzle />}
      actions={(
        <div className="flex items-center gap-2 flex-wrap">
          <ShellScanActions
            onRefresh={handleRefresh}
            onExport={exportCsv}
            refreshLoading={loading}
            refreshDisabled={clientId == null}
            exportDisabled={!filteredFindings.length}
          />
          <button
            type="button"
            onClick={persistIncidents}
            disabled={persisting || clientId == null}
            className="flex items-center gap-2 px-3 py-2 bg-red-500/15 text-red-300 border border-red-500/30 rounded-lg text-sm font-medium hover:bg-red-500/25 disabled:opacity-40"
          >
            <ShieldAlert className="w-4 h-4" />
            {persisting
              ? t('pages.threatAnalysis.persisting')
              : t('pages.threatAnalysis.persist')}
          </button>
        </div>
      )}
    >
      <div className="space-y-6">
        <p className="text-sm text-gray-400 max-w-2xl">
          {t('pages.threatAnalysis.subtitle', { })}
        </p>

        {/* Live MITRE ATT&CK exposure for the selected client (technique ranking + tactic rollup). */}
        <AttackExposurePanel clientId={clientId} />

        {persistedNote && (
          <div className="text-xs text-emerald-300 bg-emerald-500/10 border border-emerald-500/20 rounded-lg px-3 py-2">
            {persistedNote}
          </div>
        )}

        {loading ? (
          <div className="rounded-2xl bg-black/40 border border-white/10 p-6">
            <SkeletonWidgetGrid count={4} />
          </div>
        ) : clientId == null ? (
          <EmptyState
            icon="shield"
            title={t('pages.threatAnalysis.no_client_title')}
            body={t('pages.threatAnalysis.no_client_body', { })}
          />
        ) : error ? (
          <EmptyState
            icon="alert"
            title={t('pages.threatAnalysis.error_title')}
            body={error}
          />
        ) : (
          <>
            {/* Hero score + summary */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className={`rounded-xl p-5 border ${tone.ring} ${tone.bg}`}>
                <div className="text-xs text-gray-400 mb-1">
                  {t('pages.threatAnalysis.incident_score')}
                </div>
                <div className={`text-4xl font-bold ${tone.text}`}>{score.toFixed(0)}</div>
                <div className="text-[11px] text-gray-500 mt-1">
                  {t('pages.threatAnalysis.findings_analyzed', { n: report?.findings_analyzed ?? 0,
                  })}
                </div>
              </div>
              <SummaryCard
                label={t('pages.threatAnalysis.reached_objective')}
                value={summary.reached_objective ? t('common.yes') : t('common.no')}
                valueClass={summary.reached_objective ? 'text-red-400' : 'text-emerald-400'}
                icon={<GitBranch className="w-4 h-4 text-cyan-400" />}
              />
              <SummaryCard
                label={t('pages.threatAnalysis.correlation_incidents')}
                value={summary.correlation_incidents ?? 0}
                valueClass="text-orange-400"
                icon={<ShieldAlert className="w-4 h-4 text-orange-400" />}
              />
              <SummaryCard
                label={t('pages.threatAnalysis.detections')}
                value={`${summary.network_detections ?? 0} / ${summary.identity_detections ?? 0}`}
                valueClass="text-white"
                icon={<Network className="w-4 h-4 text-purple-400" />}
              />
            </div>

            {/* Attack chain */}
            {chain?.reached_goal && Array.isArray(chain.steps) && chain.steps.length > 0 && (
              <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-5">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
                  <GitBranch className="w-4 h-4 text-red-400" />
                  {t('pages.threatAnalysis.attack_chain')}
                  <span className="text-[11px] text-gray-500 font-normal">
                    {t('pages.threatAnalysis.goal')}: {chain.goal} · cost {chain.total_cost}
                  </span>
                </h3>
                <div className="flex items-center gap-2 flex-wrap">
                  {chain.steps.map((s, i) => (
                    <div key={i} className="flex items-center gap-2">
                      {i > 0 && <span className="text-gray-600">→</span>}
                      <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5">
                        <div className="text-xs font-medium text-white">{s.name}</div>
                        <div className="text-[10px] font-mono text-red-300/80">{s.mitre}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <WeissmanFindingsPanel
              findings={unifiedFindings}
              filteredFindings={filteredFindings}
              counts={counts}
              total={total}
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              severityFilter={severityFilter}
              onSeverityChange={setSeverityFilter}
              accent={ACCENT}
              title={t('pages.threatAnalysis.multi_stage')}
              emptyTitle={t('pages.threatAnalysis.no_incidents', { })}
              emptyBody={t('pages.threatAnalysis.no_incidents', { })}
              renderFinding={(f) => (
                <div key={f.id} className="rounded-lg border border-white/10 bg-white/[0.03] p-3">
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className="text-sm font-medium text-white">{f.title}</span>
                    <span className="flex items-center gap-2">
                      {f.type && (
                        <span className="text-[9px] font-mono uppercase px-1.5 py-0.5 rounded border border-white/10 text-white/40">
                          {f.type}
                        </span>
                      )}
                      <span className={`text-xs font-mono ${sevColor(f.severity)}`}>{f.severity}</span>
                    </span>
                  </div>
                  {f.target && (
                    <div className="text-[11px] text-gray-400 mb-2">
                      {t('pages.threatAnalysis.target')}:{' '}
                      <span className="font-mono text-white/70">{f.target}</span>
                    </div>
                  )}
                  {f.description && (
                    <p className="text-[11px] text-gray-400 mb-2">{f.description}</p>
                  )}
                  {f.stages?.length > 0 && (
                    <div className="flex items-center gap-1.5 flex-wrap">
                      {f.stages.map((st, i) => (
                        <div key={i} className="flex items-center gap-1.5">
                          {i > 0 && <span className="text-gray-600 text-xs">→</span>}
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-orange-500/10 border border-orange-500/30 text-orange-300">
                            {st.category}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            />
          </>
        )}
      </div>
    </PageShell>
  );
}

function SummaryCard({ label, value, valueClass, icon }) {
  return (
    <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-xl p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm text-gray-400">{label}</span>
        {icon}
      </div>
      <div className={`text-2xl font-bold ${valueClass}`}>{value}</div>
    </div>
  );
}
