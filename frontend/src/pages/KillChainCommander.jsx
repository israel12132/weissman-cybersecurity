/**
 * Live Kill-Chain Commander — recon → foothold → identity → privilege → impact
 * composed only from persisted findings/jobs/assets for the bound client.
 *
 * Route: /kill-chain-commander
 * APIs: GET /api/kill-chain-commander  POST /api/kill-chain-commander/compose
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Activity,
  ChevronRight,
  Crosshair,
  Lock,
  ShieldAlert,
  Sparkles,
} from 'lucide-react'
import PageShell from './PageShell'
import ShellScanActions from '../components/engine/ShellScanActions'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import EmptyState from '../components/ui/EmptyState'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import Button from '../components/ui/Button'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import { apiFetch } from '../utils/apiFetch'
import { useClient } from '../context/ClientContext'
import ScopedClientControl from '../components/clients/ScopedClientControl'
import EngineRealityBadge from '../components/EngineRealityBadge'

const NS = 'pages.killChainCommander'

const STAGE_CHROME = {
  recon: { icon: '🔭', color: '#22d3ee' },
  foothold: { icon: '💥', color: '#f97316' },
  identity: { icon: '🪪', color: '#a78bfa' },
  privilege: { icon: '⬆', color: '#f59e0b' },
  impact: { icon: '☠', color: '#ef4444' },
}

function HonestyChip({ on, label, hint }) {
  return (
    <span
      className="font-mono rounded-md border uppercase font-semibold text-[9px] px-1.5 py-0.5 tracking-wider"
      style={
        on
          ? { color: '#34d399', borderColor: 'rgba(52,211,153,0.35)', backgroundColor: 'rgba(52,211,153,0.08)' }
          : { color: '#f87171', borderColor: 'rgba(248,113,113,0.35)', backgroundColor: 'rgba(248,113,113,0.08)' }
      }
      title={hint}
    >
      {label}
    </span>
  )
}

function riskTone(points) {
  const n = Number(points) || 0
  if (n >= 20) return '#ef4444'
  if (n >= 12) return '#f97316'
  if (n >= 6) return '#f59e0b'
  return '#22d3ee'
}

export default function KillChainCommander() {
  const { t } = useTranslation()
  const { selectedClientId, setSelectedClientId, clients } = useClient()
  const [snap, setSnap] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [composing, setComposing] = useState(false)
  const [composeError, setComposeError] = useState('')
  const [openId, setOpenId] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const qs = selectedClientId ? `?client_id=${encodeURIComponent(selectedClientId)}` : ''
      const d = await apiFetch(`/api/kill-chain-commander${qs}`)
      setSnap(d)
    } catch (e) {
      setError(e.message || t(`${NS}.load_failed`))
      setSnap(null)
    } finally {
      setLoading(false)
    }
  }, [selectedClientId, t])

  useEffect(() => {
    load()
  }, [load])

  const stages = Array.isArray(snap?.stages) ? snap.stages : []
  const edges = Array.isArray(snap?.edges) ? snap.edges : []
  const pricing = snap?.pricing || {}
  const honesty = snap?.honesty || {}
  const jobs = Array.isArray(snap?.jobs) ? snap.jobs : []
  const empty = Boolean(snap?.empty_reason)
  const q = search.trim().toLowerCase()

  const filteredStages = useMemo(() => {
    if (!q) return stages
    return stages.map((st) => ({
      ...st,
      findings: (st.findings || []).filter((f) =>
        `${f.title} ${f.source} ${f.finding_id} ${(f.mitre || []).map((m) => m.id).join(' ')} ${f.proof_snippet || ''}`
          .toLowerCase()
          .includes(q),
      ),
    }))
  }, [stages, q])

  const exportCsv = () => {
    const header = [
      'stage', 'id', 'finding_id', 'title', 'severity', 'source', 'confidence',
      'risk_points', 'priced_usd', 'exposure', 'criticality', 'mitre', 'proof',
    ]
    const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`
    const rows = []
    for (const st of stages) {
      for (const f of st.findings || []) {
        rows.push([
          st.stage,
          f.id,
          f.finding_id,
          f.title,
          f.severity,
          f.source,
          f.confidence,
          f.risk_points,
          f.priced_usd,
          f.formula_inputs?.exposure,
          f.formula_inputs?.asset_criticality,
          (f.mitre || []).map((m) => m.id).join('|'),
          f.proof_snippet,
        ].map(esc).join(','))
      }
    }
    const blob = new Blob([[header.join(','), ...rows].join('\n')], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `weissman-kill-chain-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  const compose = async () => {
    setComposing(true)
    setComposeError('')
    try {
      const d = await apiFetch('/api/kill-chain-commander/compose', {
        method: 'POST',
        body: {
          client_id: selectedClientId ? Number(selectedClientId) : null,
        },
      })
      setSnap(d)
    } catch (e) {
      if (e?.response) {
        const body = await e.response.json().catch(() => ({}))
        setComposeError(body.empty_reason || body.detail || body.error || e.message || t(`${NS}.compose_failed`))
      } else {
        setComposeError(e.message || t(`${NS}.compose_failed`))
      }
    } finally {
      setComposing(false)
    }
  }

  const liveFindings = stages.reduce((n, s) => n + (s.finding_count || 0), 0)
  const formula = pricing.formula || {}

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#ef4444"
      icon={<Crosshair />}
      hideEvidence
      actions={(
        <ShellScanActions
          onRefresh={load}
          onExport={exportCsv}
          refreshLoading={loading}
          exportDisabled={!liveFindings}
          exportLabel={t(`${NS}.export_csv`)}
        />
      )}
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        <div className="flex flex-wrap items-center gap-2">
          <EngineRealityBadge kind="real_probe" size="sm" />
          <HonestyChip on={honesty.live_evidence_only !== false} label={t(`${NS}.badge_live`)} hint={t(`${NS}.badge_live_hint`)} />
          <HonestyChip on={honesty.no_fabricated_apt !== false} label={t(`${NS}.badge_no_apt`)} hint={t(`${NS}.badge_no_apt_hint`)} />
          <HonestyChip on={honesty.fail_closed_empty !== false} label={t(`${NS}.badge_fail_closed`)} hint={t(`${NS}.badge_fail_closed_hint`)} />
          <HonestyChip on={Boolean(snap?.client_id)} label={t(`${NS}.badge_bound`)} hint={t(`${NS}.badge_bound_hint`)} />
          <HonestyChip on={honesty.formula_published !== false} label={t(`${NS}.badge_formula`)} hint={formula.expression || ''} />
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <ScopedClientControl
            value={selectedClientId}
            onChange={setSelectedClientId}
            clients={clients}
            placeholder={t(`${NS}.select_client`)}
            className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-3 py-1.5 text-xs font-mono text-[var(--text-secondary)] min-w-[12rem]"
          />
          <label className="relative flex-1 min-w-[12rem]">
            <span className="sr-only">{t(`${NS}.search_placeholder`)}</span>
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={t(`${NS}.search_placeholder`)}
              className="w-full ps-3 pe-3 py-1.5 rounded-lg bg-[var(--bg-3)] border border-[var(--border-default)] text-xs font-mono text-[var(--text-secondary)]"
            />
          </label>
          <Button
            type="button"
            onClick={compose}
            disabled={composing || loading}
            className="inline-flex items-center gap-2"
          >
            <Lock className="w-3.5 h-3.5" />
            {composing ? t(`${NS}.composing`) : t(`${NS}.compose`)}
          </Button>
        </div>
        {composeError && (
          <p className="text-xs text-rose-300 font-mono" role="alert">{composeError}</p>
        )}

        {loading ? (
          <SkeletonWidgetGrid count={4} />
        ) : error ? (
          <EmptyState icon="alert" title={t(`${NS}.load_failed`)} description={error} />
        ) : (
          <>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              <ExecutiveWidget
                label={t(`${NS}.kpi_findings`)}
                value={liveFindings}
                accent="#ef4444"
                hint={t(`${NS}.kpi_findings_hint`, { n: snap?.findings_considered ?? 0 })}
              />
              <ExecutiveWidget
                label={t(`${NS}.kpi_risk`)}
                value={(Number(pricing.total_risk_points) || 0).toFixed(1)}
                accent="#f97316"
                hint={formula.expression || t(`${NS}.formula_short`)}
              />
              <ExecutiveWidget
                label={t(`${NS}.kpi_residual`)}
                value={(Number(pricing.residual_if_top3_fixed) || 0).toFixed(1)}
                accent="#22d3ee"
                hint={t(`${NS}.kpi_residual_hint`, { pct: pricing.residual_reduction_pct ?? 0 })}
              />
              <ExecutiveWidget
                label={t(`${NS}.kpi_scope`)}
                value={snap?.client_name || snap?.primary_domain || t(`${NS}.unbound`)}
                accent="#a78bfa"
                hint={snap?.primary_domain ? t(`${NS}.domain_hint`, { domain: snap.primary_domain }) : t(`${NS}.bound_hint`)}
              />
            </div>

            {empty && (
              <EmptyState
                icon="alert"
                title={t(`${NS}.empty_title`)}
                description={snap.empty_reason}
              />
            )}

            <section className="rounded-2xl border border-rose-500/25 bg-gradient-to-br from-rose-500/[0.06] via-black/40 to-cyan-500/[0.05] p-4 space-y-4">
              <h2 className="text-xs font-mono uppercase tracking-[0.18em] text-rose-300/90 flex items-center gap-2">
                <Activity className="w-3.5 h-3.5" /> {t(`${NS}.chain_title`)}
              </h2>
              <div className="flex flex-col lg:flex-row lg:items-stretch gap-3">
                {filteredStages.map((st, i) => {
                  const chrome = STAGE_CHROME[st.stage] || { icon: '●', color: '#94a3b8' }
                  const lit = (st.findings || []).length > 0
                  return (
                    <div key={st.stage} className="flex-1 min-w-0 flex flex-col lg:flex-row gap-3">
                      {i > 0 && (
                        <div className="hidden lg:flex items-center justify-center shrink-0" aria-hidden>
                          <ChevronRight className="w-4 h-4 text-white/30 rtl:rotate-180" />
                        </div>
                      )}
                      <div
                        className="flex-1 rounded-xl border px-3 py-3 min-h-[9rem]"
                        style={{
                          borderColor: lit ? `${chrome.color}55` : 'rgba(255,255,255,0.06)',
                          background: lit ? `${chrome.color}12` : 'rgba(255,255,255,0.02)',
                        }}
                      >
                        <div className="flex items-center justify-between gap-2 mb-2">
                          <div className="flex items-center gap-2 min-w-0">
                            <span aria-hidden>{chrome.icon}</span>
                            <span className="text-sm font-semibold truncate" style={{ color: chrome.color }}>
                              {t(`${NS}.stages.${st.stage}`, { defaultValue: st.label })}
                            </span>
                          </div>
                          <span className="text-[10px] font-mono tabular-nums" style={{ color: chrome.color }}>
                            {st.findings?.length ?? 0}
                          </span>
                        </div>
                        <div className="text-[9px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-2">
                          {(st.mitre_tactics || []).join(' · ')}
                        </div>
                        <ul className="space-y-1.5 max-h-[18rem] overflow-y-auto">
                          {(st.findings || []).length === 0 ? (
                            <li className="text-[11px] text-[var(--text-muted)]">{t(`${NS}.stage_empty`)}</li>
                          ) : (
                            (st.findings || []).map((f) => (
                              <li key={`${st.stage}-${f.id}`}>
                                <button
                                  type="button"
                                  onClick={() => setOpenId(openId === f.id ? null : f.id)}
                                  className="w-full text-start rounded-lg border border-white/5 bg-black/30 px-2 py-1.5 hover:border-white/20 transition-colors"
                                >
                                  <div className="flex items-center justify-between gap-2">
                                    <span className="text-[12px] text-[var(--text-primary)] truncate">{f.title}</span>
                                    <span
                                      className="text-[10px] font-mono shrink-0 tabular-nums"
                                      style={{ color: riskTone(f.risk_points) }}
                                    >
                                      {Number(f.risk_points).toFixed(1)}
                                    </span>
                                  </div>
                                  <div className="mt-1 flex flex-wrap gap-1">
                                    <span className="text-[8px] font-mono uppercase tracking-widest text-[var(--text-muted)]">
                                      {f.severity} · {Math.round((f.confidence || 0) * 100)}%
                                    </span>
                                    {(f.mitre || []).slice(0, 3).map((m) => (
                                      <span
                                        key={m.id}
                                        className="text-[8px] font-mono px-1 rounded border border-violet-400/30 text-violet-200/90"
                                        title={m.name || m.id}
                                      >
                                        {m.id}
                                      </span>
                                    ))}
                                  </div>
                                  {openId === f.id && (
                                    <div className="mt-2 space-y-1 text-[10px] font-mono text-[var(--text-secondary)]">
                                      <div>{t(`${NS}.cite_id`)} {f.finding_id} · {f.source}</div>
                                      {f.proof_snippet && (
                                        <div className="rounded bg-black/40 border border-white/5 p-2 whitespace-pre-wrap text-[var(--text-primary)]">
                                          {f.proof_snippet}
                                        </div>
                                      )}
                                      <div>
                                        {t(`${NS}.formula_line`, {
                                          sev: f.formula_inputs?.severity_weight,
                                          crit: f.formula_inputs?.asset_criticality,
                                          exp: f.formula_inputs?.exposure_weight,
                                          expLabel: f.formula_inputs?.exposure,
                                        })}
                                      </div>
                                    </div>
                                  )}
                                </button>
                              </li>
                            ))
                          )}
                        </ul>
                      </div>
                    </div>
                  )
                })}
              </div>
              {edges.length > 0 && (
                <ul className="text-[10px] font-mono text-[var(--text-muted)] space-y-1 border-t border-white/5 pt-3">
                  {edges.map((e) => (
                    <li key={`${e.from}-${e.to}`}>
                      {e.from} → {e.to} · {e.reason}
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
              <section className="xl:col-span-7 rounded-2xl border border-amber-500/20 bg-black/30 p-4 space-y-3">
                <h2 className="text-xs font-mono uppercase tracking-[0.18em] text-amber-300/80 flex items-center gap-2">
                  <ShieldAlert className="w-3.5 h-3.5" /> {t(`${NS}.pricing_title`)}
                </h2>
                <p className="text-sm text-[var(--text-primary)] font-mono">
                  {formula.expression || t(`${NS}.formula_short`)}
                </p>
                <dl className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-[11px]">
                  {Object.entries(formula.severity_weights || {}).map(([k, v]) => (
                    <div key={k} className="rounded-lg border border-white/5 px-2 py-1.5">
                      <dt className="text-[9px] uppercase tracking-widest text-[var(--text-muted)]">{k}</dt>
                      <dd className="font-mono text-[var(--text-primary)]">{v}</dd>
                    </div>
                  ))}
                  {Object.entries(formula.exposure || {}).map(([k, v]) => (
                    <div key={k} className="rounded-lg border border-white/5 px-2 py-1.5">
                      <dt className="text-[9px] uppercase tracking-widest text-[var(--text-muted)]">{k}</dt>
                      <dd className="font-mono text-[var(--text-primary)]">×{v}</dd>
                    </div>
                  ))}
                </dl>
                <p className="text-[10px] text-[var(--text-muted)] leading-relaxed">{formula.usd_overlay}</p>
                <p className="text-[10px] text-[var(--text-muted)] leading-relaxed">{formula.residual}</p>
                {(pricing.top3_fixes || []).length > 0 && (
                  <ol className="space-y-2">
                    {(pricing.top3_fixes || []).map((fix, idx) => (
                      <li key={fix.id} className="rounded-xl border border-white/5 px-3 py-2">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[11px] font-mono text-amber-200/80">#{idx + 1} {fix.stage}</span>
                          <span className="text-[11px] font-mono tabular-nums" style={{ color: riskTone(fix.risk_points) }}>
                            −{Number(fix.risk_points).toFixed(1)}
                          </span>
                        </div>
                        <div className="text-sm text-[var(--text-primary)] truncate">{fix.title}</div>
                      </li>
                    ))}
                  </ol>
                )}
              </section>

              <section className="xl:col-span-5 rounded-2xl border border-[var(--border-default)] bg-black/25 p-4 space-y-3">
                <h2 className="text-xs font-mono uppercase tracking-[0.18em] text-[var(--text-muted)] flex items-center gap-2">
                  <Sparkles className="w-3.5 h-3.5 text-cyan-400" /> {t(`${NS}.jobs_title`)}
                </h2>
                {jobs.length === 0 ? (
                  <p className="text-xs text-[var(--text-muted)]">{t(`${NS}.jobs_empty`)}</p>
                ) : (
                  <ul className="space-y-2 max-h-[22rem] overflow-y-auto">
                    {jobs.map((j) => (
                      <li key={j.id} className="rounded-xl border border-white/5 px-3 py-2">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[12px] text-[var(--text-primary)] truncate">{j.kind}</span>
                          <span className="text-[9px] font-mono uppercase tracking-widest text-cyan-300/80">{j.status}</span>
                        </div>
                        <div className="text-[10px] font-mono text-[var(--text-muted)] truncate">
                          {j.engine || '—'} · {j.target || snap?.primary_domain || '—'}
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </section>
            </div>
          </>
        )}
      </div>
    </PageShell>
  )
}
