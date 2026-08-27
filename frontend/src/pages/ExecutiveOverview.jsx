/**
 * Executive Overview — one-glance command surface aggregating the platform's
 * live risk signals, each linking to its detail page. Every tile is wired to a
 * real endpoint; nothing is fabricated. Route: /overview
 *
 *   Global:  security posture (grade), ATT&CK coverage, IOC count,
 *            threat-intel feed freshness (KEV/EPSS).
 *   Client:  financial ALE (FAIR) + attack-path count/top-risk.
 */
import { useState, useCallback, useEffect, useMemo } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { LayoutDashboard, ArrowRight, Search, AlertTriangle } from 'lucide-react'
import PageShell from './PageShell'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import { SkeletonWidgetGrid } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { useClient } from '../context/ClientContext'
import { apiFetch } from '../utils/apiFetch'
import { fmtUsd, postureGradeColor as gradeColor, postureScoreColor as scoreColor } from '../lib/riskFormat'
import Button from '../components/ui/Button'
import { BoundClientScanField } from '../components/scan/ClientScanBinding'

const NS = 'pages.executiveOverview'

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
  return await apiFetch(path)
}

/** A metric tile linking to its detail page. */
function Tile({ to, label, value, sub, accent = '#22d3ee', linkLabel, loading }) {
  return (
    <Link
      to={to}
      className="group relative overflow-hidden rounded-2xl border p-5 backdrop-blur-md transition-all hover:border-[var(--border-strong)] block"
      style={{
        borderColor: `${accent}30`,
        background: `linear-gradient(145deg, ${accent}12 0%, var(--bg-elevated) 55%, var(--bg-2) 100%)`,
      }}
    >
      <div className="absolute inset-x-0 top-0 h-px opacity-60" style={{ background: `linear-gradient(90deg, transparent, ${accent}60, transparent)` }} aria-hidden />
      <div className="text-[10px] font-mono uppercase tracking-[0.14em] mb-2" style={{ color: `${accent}cc` }}>
        {label}
      </div>
      <div className="text-3xl font-bold tabular-nums tracking-tight text-[var(--text-primary)]">
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

  const [global, setGlobal] = useState({ loading: true, error: false, posture: null, coverage: null, iocs: null, intel: null, ueba: null, crypto: null })
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
    // allSettled distinguishes a rejected probe (outage) from a fulfilled-but-empty
    // one, so a platform-wide failure can be surfaced instead of reading as "no data".
    const results = await Promise.allSettled([
      getJson('/api/security/posture-score'),
      getJson('/api/attack-coverage'),
      getJson('/api/soc/iocs'),
      getJson('/api/intel/status'),
      getJson('/api/ueba/anomalies?limit=500'),
      getJson('/api/crypto/capabilities'),
    ])
    const [posture, coverage, iocs, intel, ueba, crypto] = results.map((r) => (r.status === 'fulfilled' ? r.value : null))
    const error = results.every((r) => r.status === 'rejected')
    setGlobal({ loading: false, error, posture, coverage, iocs, intel, ueba, crypto })
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
          <BoundClientScanField
            clients={clients}
            selectedClientId={selectedClientId ?? ''}
            onChange={(id) => setSelectedClientId(id ? Number(id) : null)}
            emptyLabel={t(`${NS}.all_clients`)}
          />
          <ShellScanActions onRefresh={() => { loadGlobal(); loadClient(selectedClientId) }} refreshLoading={global.loading} exportDisabled />
        </div>
      }
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        {global.error && !global.loading && (
          <div role="alert" className="rounded-2xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200 flex items-center justify-between gap-4">
            <span className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              {t('common.error')}
            </span>
            <Button variant="unstyled" type="button" onClick={loadGlobal} className="text-xs font-medium text-red-100 underline underline-offset-2">
              {t('common.retry')}
            </Button>
          </div>
        )}

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
