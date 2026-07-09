/**
 * Executive Overview — one-glance command surface aggregating the platform's
 * live risk signals, each linking to its detail page. Every tile is wired to a
 * real endpoint; nothing is fabricated. Route: /overview
 *
 *   Global:  security posture (grade), ATT&CK coverage, IOC count,
 *            threat-intel feed freshness (KEV/EPSS).
 *   Client:  financial ALE (FAIR) + attack-path count/top-risk.
 */
import React, { useState, useCallback, useEffect, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { LayoutDashboard, ArrowRight, Search } from 'lucide-react'
import PageShell from './PageShell'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useClient } from '../context/ClientContext'
import { apiFetch } from '../lib/apiBase'

const NS = 'pages.executiveOverview'

function fmtUsd(n) {
  const v = Number(n) || 0
  const abs = Math.abs(v)
  if (abs >= 1_000_000) return `$${(v / 1_000_000).toFixed(2)}M`
  if (abs >= 1_000) return `$${(v / 1_000).toFixed(1)}K`
  return `$${v.toLocaleString()}`
}
function gradeColor(grade) {
  return { A: '#4ade80', B: '#84cc16', C: '#facc15', D: '#f97316', F: '#ef4444' }[String(grade || '').toUpperCase()] || '#22d3ee'
}
function scoreColor(s) {
  const n = Number(s) || 0
  if (n >= 90) return '#4ade80'
  if (n >= 75) return '#84cc16'
  if (n >= 60) return '#facc15'
  if (n >= 40) return '#f97316'
  return '#ef4444'
}
function riskColor(r) {
  const n = Number(r) || 0
  if (n >= 8) return '#ef4444'
  if (n >= 6) return '#f97316'
  if (n >= 4) return '#f59e0b'
  return '#22d3ee'
}
function freshnessColor(iso) {
  if (!iso) return '#6b7280'
  const ageH = (Date.now() - new Date(iso).getTime()) / 3_600_000
  if (Number.isNaN(ageH)) return '#6b7280'
  if (ageH <= 24) return '#4ade80'
  if (ageH <= 72) return '#facc15'
  return '#f97316'
}
async function getJson(path) {
  const r = await apiFetch(path)
  const d = await r.json().catch(() => ({}))
  if (!r.ok) throw new Error(d.detail || `HTTP ${r.status}`)
  return d
}

/** A metric tile linking to its detail page. */
function Tile({ to, label, value, sub, accent = '#22d3ee', linkLabel, loading }) {
  return (
    <Link
      to={to}
      className="group relative overflow-hidden rounded-2xl border p-5 backdrop-blur-md transition-all hover:border-[var(--border-strong)] block"
      style={{
        borderColor: `${accent}30`,
        background: `linear-gradient(145deg, ${accent}08 0%, rgba(0,0,0,0.35) 55%, rgba(0,0,0,0.5) 100%)`,
      }}
    >
      <div className="absolute inset-x-0 top-0 h-px opacity-60" style={{ background: `linear-gradient(90deg, transparent, ${accent}60, transparent)` }} aria-hidden />
      <div className="text-[10px] font-mono uppercase tracking-[0.14em] mb-2" style={{ color: `${accent}cc` }}>
        {label}
      </div>
      <div className="text-3xl font-bold tabular-nums tracking-tight text-white">
        {loading ? <span className="text-[var(--text-disabled)]">—</span> : value}
      </div>
      {sub && <div className="text-[11px] font-mono text-[var(--text-muted)] mt-1">{sub}</div>}
      {linkLabel && (
        <div className="mt-3 inline-flex items-center gap-1 text-[10px] font-mono text-[var(--text-muted)] group-hover:text-[var(--text-secondary)] transition-colors">
          {linkLabel}
          <ArrowRight className="w-3 h-3" aria-hidden />
        </div>
      )}
    </Link>
  )
}

export default function ExecutiveOverview() {
  const { t } = useTranslation()
  const { clients, selectedClientId, setSelectedClientId } = useClient()

  const [global, setGlobal] = useState({ loading: true, posture: null, coverage: null, iocs: null, intel: null, ueba: null, crypto: null })
  const [client, setClient] = useState({ loading: false, financial: null, attack: null })
  const [searchQuery, setSearchQuery] = useState('')

  // Live tile filter — narrows the signal wall to matching labels/subtitles.
  const tileMatches = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    return (...parts) => !q || parts.some((p) => String(p || '').toLowerCase().includes(q))
  }, [searchQuery])

  const loadGlobal = useCallback(async () => {
    setGlobal((g) => ({ ...g, loading: true }))
    // Each signal is independent — one failure must not blank the others.
    const [posture, coverage, iocs, intel, ueba, crypto] = await Promise.all([
      getJson('/api/security/posture-score').catch(() => null),
      getJson('/api/attack-coverage').catch(() => null),
      getJson('/api/soc/iocs').catch(() => null),
      getJson('/api/intel/status').catch(() => null),
      getJson('/api/ueba/anomalies?limit=500').catch(() => null),
      getJson('/api/crypto/capabilities').catch(() => null),
    ])
    setGlobal({ loading: false, posture, coverage, iocs, intel, ueba, crypto })
  }, [])

  const loadClient = useCallback(async (cid) => {
    if (cid == null) {
      setClient({ loading: false, financial: null, attack: null })
      return
    }
    setClient((c) => ({ ...c, loading: true }))
    const [financial, attack] = await Promise.all([
      getJson(`/api/financial-risk/${encodeURIComponent(cid)}`).catch(() => null),
      getJson(`/api/attack-paths/${encodeURIComponent(cid)}`).catch(() => null),
    ])
    setClient({ loading: false, financial, attack })
  }, [])

  useEffect(() => {
    loadGlobal()
  }, [loadGlobal])

  useEffect(() => {
    loadClient(selectedClientId)
  }, [selectedClientId, loadClient])

  const posture = global.posture
  const totals = global.coverage?.totals || {}
  const iocCount = Array.isArray(global.iocs?.iocs) ? global.iocs.iocs.length : null
  const kev = global.intel?.kev
  const epss = global.intel?.epss
  const uebaList = Array.isArray(global.ueba?.anomalies) ? global.ueba.anomalies : null
  const uebaCritHigh = uebaList
    ? uebaList.filter((a) => ['critical', 'high'].includes(String(a.severity || '').toLowerCase())).length
    : null
  const pqReady = global.crypto?.post_quantum?.ml_kem_selftest_ok === true

  const fin = client.financial?.snapshot
  const atk = client.attack?.snapshot
  const paths = Array.isArray(atk?.paths) ? atk.paths : []
  const topRisk = paths.length ? Math.max(...paths.map((p) => Number(p.risk) || 0)) : null

  // Which tiles survive the live label/subtitle filter.
  const showPosture = tileMatches(t(`${NS}.posture`), t(`${NS}.posture_sub`))
  const showCoverage = tileMatches(t(`${NS}.coverage`))
  const showIocs = tileMatches(t(`${NS}.iocs`), t(`${NS}.iocs_sub`))
  const showIntel = tileMatches(t(`${NS}.intel`))
  const showUeba = tileMatches(t(`${NS}.ueba`), t(`${NS}.ueba_sub`))
  const showCrypto = tileMatches(t(`${NS}.crypto`), t(`${NS}.crypto_sub`))
  const platformVisible = showPosture || showCoverage || showIocs || showIntel || showUeba || showCrypto
  const showAle = tileMatches(t(`${NS}.ale`))
  const showPaths = tileMatches(t(`${NS}.paths`))
  const showTopRisk = tileMatches(t(`${NS}.top_risk`))
  const clientVisible = showAle || showPaths || showTopRisk

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={t(`${NS}.badge`)}
      badgeColor="#22d3ee"
      icon={<LayoutDashboard className="w-5 h-5" />}
      actions={
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute top-1/2 -translate-y-1/2 left-2.5 w-3.5 h-3.5 text-[var(--text-muted)] pointer-events-none" aria-hidden />
            <input
              type="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder={t(`${NS}.search_placeholder`)}
              aria-label={t(`${NS}.search_placeholder`)}
              className="w-40 sm:w-52 bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg pl-8 pr-2.5 py-1.5 text-xs text-[var(--text-secondary)] font-mono focus:outline-none focus:border-cyan-500/40"
            />
          </div>
          <select
            value={selectedClientId ?? ''}
            onChange={(e) => setSelectedClientId(e.target.value ? Number(e.target.value) : null)}
            className="bg-[var(--bg-3)] border border-[var(--border-default)] rounded-lg px-2.5 py-1.5 text-xs text-[var(--text-secondary)] focus:outline-none focus:border-cyan-500/40"
            aria-label={t(`${NS}.select_client`)}
          >
            <option value="">{t(`${NS}.all_clients`)}</option>
            {clients.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name || c.domain || `#${c.id}`}
              </option>
            ))}
          </select>
          <ShellScanActions onRefresh={() => { loadGlobal(); loadClient(selectedClientId) }} refreshLoading={global.loading} exportDisabled />
        </div>
      }
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        {/* Global posture row */}
        <div>
          <h2 className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-3">{t(`${NS}.platform_heading`)}</h2>
          {global.loading ? (
            <SkeletonWidgetGrid count={6} />
          ) : !platformVisible ? (
            <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-1)] px-4 py-6 text-center text-[12px] font-mono text-[var(--text-muted)]">
              {t(`${NS}.no_matches`)}
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
              {showPosture && (
              <Tile
                to="/security-posture"
                label={t(`${NS}.posture`)}
                value={posture ? <span style={{ color: scoreColor(posture.score) }}>{posture.score}<span className="text-sm text-[var(--text-muted)]"> / 100 </span><span style={{ color: gradeColor(posture.grade) }}>{String(posture.grade || '').toUpperCase()}</span></span> : t(`${NS}.na`)}
                sub={t(`${NS}.posture_sub`)}
                accent={gradeColor(posture?.grade)}
                linkLabel={t(`${NS}.open_posture`)}
              />
              )}
              {showCoverage && (
              <Tile
                to="/attack-coverage"
                label={t(`${NS}.coverage`)}
                value={totals.techniques_covered ?? t(`${NS}.na`)}
                sub={t(`${NS}.coverage_sub`, { tactics: totals.tactics_covered ?? 0 })}
                accent="#f43f5e"
                linkLabel={t(`${NS}.open_coverage`)}
              />
              )}
              {showIocs && (
              <Tile
                to="/iocs"
                label={t(`${NS}.iocs`)}
                value={iocCount ?? t(`${NS}.na`)}
                sub={t(`${NS}.iocs_sub`)}
                accent="#a78bfa"
                linkLabel={t(`${NS}.open_iocs`)}
              />
              )}
              {showIntel && (
              <Tile
                to="/threat-intel"
                label={t(`${NS}.intel`)}
                value={kev ? <span>{kev.rows}<span className="text-sm text-[var(--text-muted)]"> KEV</span></span> : t(`${NS}.na`)}
                sub={
                  <span className="flex flex-col gap-0.5">
                    <span style={{ color: freshnessColor(kev?.last_refresh) }}>
                      {t(`${NS}.kev_fresh`, { time: kev?.last_refresh ? new Date(kev.last_refresh).toLocaleDateString() : '—' })}
                    </span>
                    <span style={{ color: freshnessColor(epss?.last_refresh) }}>
                      {t(`${NS}.epss_fresh`, { rows: epss?.rows ?? 0 })}
                    </span>
                  </span>
                }
                accent="#22d3ee"
                linkLabel={t(`${NS}.open_intel`)}
              />
              )}
              {showUeba && (
              <Tile
                to="/ueba"
                label={t(`${NS}.ueba`)}
                value={uebaList ? (uebaCritHigh > 0 ? <span style={{ color: '#f43f5e' }}>{uebaCritHigh}</span> : uebaList.length) : t(`${NS}.na`)}
                sub={t(`${NS}.ueba_sub`, { total: uebaList ? uebaList.length : 0 })}
                accent="#a78bfa"
                linkLabel={t(`${NS}.open_ueba`)}
              />
              )}
              {showCrypto && (
              <Tile
                to="/crypto-posture"
                label={t(`${NS}.crypto`)}
                value={global.crypto ? <span style={{ color: pqReady ? '#4ade80' : '#facc15' }}>{pqReady ? t(`${NS}.pq_ready`) : t(`${NS}.pq_check`)}</span> : t(`${NS}.na`)}
                sub={t(`${NS}.crypto_sub`)}
                accent={pqReady ? '#4ade80' : '#facc15'}
                linkLabel={t(`${NS}.open_crypto`)}
              />
              )}
            </div>
          )}
        </div>

        {/* Per-client row */}
        <div>
          <h2 className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-3">
            {selectedClientId == null ? t(`${NS}.client_heading_none`) : t(`${NS}.client_heading`)}
          </h2>
          {selectedClientId == null ? (
            <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-1)] px-4 py-6 text-center text-[12px] font-mono text-[var(--text-muted)]">
              {t(`${NS}.pick_client_hint`)}
            </div>
          ) : client.loading ? (
            <SkeletonWidgetGrid count={3} />
          ) : !clientVisible ? (
            <div className="rounded-2xl border border-[var(--border-subtle)] bg-[var(--bg-1)] px-4 py-6 text-center text-[12px] font-mono text-[var(--text-muted)]">
              {t(`${NS}.no_matches`)}
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {showAle && (
              <Tile
                to="/financial-risk"
                label={t(`${NS}.ale`)}
                value={fin ? fmtUsd(fin.ale_annualised_usd) : t(`${NS}.no_snapshot`)}
                sub={fin ? t(`${NS}.ale_sub`, { sle: fmtUsd(fin.sle_worst_usd) }) : t(`${NS}.recompute_hint`)}
                accent="#ef4444"
                linkLabel={t(`${NS}.open_financial`)}
              />
              )}
              {showPaths && (
              <Tile
                to="/attack-paths"
                label={t(`${NS}.paths`)}
                value={atk ? paths.length : t(`${NS}.no_snapshot`)}
                sub={atk ? t(`${NS}.paths_sub`, { entries: atk.entry_count ?? 0, jewels: atk.jewel_count ?? 0 }) : t(`${NS}.recompute_hint`)}
                accent="#f97316"
                linkLabel={t(`${NS}.open_paths`)}
              />
              )}
              {showTopRisk && (
              <Tile
                to="/attack-paths"
                label={t(`${NS}.top_risk`)}
                value={topRisk != null ? <span style={{ color: riskColor(topRisk) }}>{topRisk.toFixed(1)}<span className="text-sm text-[var(--text-muted)]"> / 10</span></span> : t(`${NS}.no_snapshot`)}
                sub={t(`${NS}.top_risk_sub`)}
                accent={riskColor(topRisk)}
                linkLabel={t(`${NS}.open_paths`)}
              />
              )}
            </div>
          )}
        </div>
      </div>
    </PageShell>
  )
}
