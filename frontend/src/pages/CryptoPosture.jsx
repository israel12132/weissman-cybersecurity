/**
 * Cryptographic Posture — session-crypto capabilities + live post-quantum proof.
 *
 * Wired to two live endpoints:
 *   GET /api/crypto/capabilities  → JWT/session algorithm, ML-KEM (FIPS 203)
 *                                   availability, session KEM mode, WASM target.
 *   GET /api/crypto/pqc-selftest  → a real ML-KEM-768 encapsulate/decapsulate
 *                                   round-trip (ciphertext / shared-secret sizes,
 *                                   round_trip_ok) — proof the PQ stack is linked
 *                                   and operational, not a static claim.
 * Route: /crypto-posture
 */
import React, { useState, useCallback, useEffect, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { KeyRound, Search, ShieldCheck, ShieldAlert } from 'lucide-react'
import PageShell from './PageShell'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import ExecutiveWidget from '../components/ui/ExecutiveWidget'
import { SkeletonWidgetGrid, SkeletonCard } from '../components/ui/Skeleton'
import ShellScanActions from '../components/engine/ShellScanActions'
import { apiFetch } from '../lib/apiBase'

const NS = 'pages.cryptoPosture'

async function getJson(path) {
  const r = await apiFetch(path)
  const d = await r.json().catch(() => ({}))
  if (!r.ok) throw new Error(d.detail || d.error || `HTTP ${r.status}`)
  return d
}

export default function CryptoPosture() {
  const { t } = useTranslation()
  const [caps, setCaps] = useState(null)
  const [selftest, setSelftest] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    // Independent probes — one failing must not blank the other.
    const [c, s] = await Promise.all([
      getJson('/api/crypto/capabilities').catch(() => null),
      getJson('/api/crypto/pqc-selftest').catch(() => null),
    ])
    if (!c && !s) setError(t(`${NS}.load_failed`))
    setCaps(c)
    setSelftest(s)
    setLoading(false)
  }, [t])

  useEffect(() => {
    load()
  }, [load])

  const pq = useMemo(() => caps?.post_quantum || {}, [caps])
  const jwt = useMemo(() => caps?.jwt || {}, [caps])
  const wasm = useMemo(() => caps?.fuzz_core_wasm || {}, [caps])
  const pqOperational = selftest?.round_trip_ok === true || pq.ml_kem_selftest_ok === true

  // Flatten capabilities into a searchable control list.
  const controls = useMemo(() => {
    if (!caps) return []
    const rows = [
      {
        id: 'ml-kem-768',
        name: t(`${NS}.ctl_ml_kem`),
        value: pq.nist_standard || 'FIPS 203 (ML-KEM)',
        ok: pq.ml_kem_768_available === true,
      },
      {
        id: 'ml-kem-selftest',
        name: t(`${NS}.ctl_selftest`),
        value: selftest?.round_trip_ok
          ? t(`${NS}.roundtrip_ok`)
          : pq.ml_kem_selftest_ok === true
            ? t(`${NS}.roundtrip_ok`)
            : t(`${NS}.roundtrip_unknown`),
        ok: pqOperational,
      },
      {
        id: 'session-kem-mode',
        name: t(`${NS}.ctl_kem_mode`),
        value: pq.session_kem_mode || '—',
        ok: null,
      },
      {
        id: 'jwt-alg',
        name: t(`${NS}.ctl_jwt_alg`),
        value: jwt.algorithm || '—',
        ok: null,
      },
      {
        id: 'session-cookie',
        name: t(`${NS}.ctl_cookie`),
        value: jwt.cookie || '—',
        ok: null,
      },
      {
        id: 'wasm-target',
        name: t(`${NS}.ctl_wasm`),
        value: wasm.target || '—',
        ok: null,
      },
    ]
    return rows
  }, [caps, selftest, pq, jwt, wasm, pqOperational, t])

  const filteredControls = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return controls
    return controls.filter((c) => `${c.name} ${c.value}`.toLowerCase().includes(q))
  }, [controls, search])

  return (
    <PageShell
      title={t(`${NS}.title`)}
      subtitle={t(`${NS}.subtitle`)}
      badge={pqOperational ? t(`${NS}.badge_pq`) : t(`${NS}.badge`)}
      badgeColor={pqOperational ? '#4ade80' : '#22d3ee'}
      icon={<KeyRound className="w-5 h-5" />}
      actions={<ShellScanActions onRefresh={load} refreshLoading={loading} exportDisabled />}
    >
      <div className="space-y-6">
        <EvidenceNotice>{t(`${NS}.evidence_notice`)}</EvidenceNotice>

        {loading && (
          <>
            <SkeletonWidgetGrid count={4} />
            <SkeletonCard lines={6} />
          </>
        )}

        {error && !loading && (
          <div className="rounded-xl border border-rose-500/30 bg-rose-950/20 px-4 py-3 text-sm text-rose-300 font-mono">
            {error}
          </div>
        )}

        {!loading && (caps || selftest) && (
          <>
            {/* Post-quantum readiness hero */}
            <div
              className="rounded-2xl border p-6 flex flex-col sm:flex-row items-start sm:items-center gap-5"
              style={{
                borderColor: pqOperational ? 'rgba(74,222,128,0.3)' : 'rgba(250,204,21,0.3)',
                background: pqOperational
                  ? 'linear-gradient(145deg, rgba(74,222,128,0.08), rgba(0,0,0,0.4))'
                  : 'linear-gradient(145deg, rgba(250,204,21,0.06), rgba(0,0,0,0.4))',
              }}
            >
              <div
                className="flex h-16 w-16 shrink-0 items-center justify-center rounded-2xl"
                style={{ background: pqOperational ? 'rgba(74,222,128,0.15)' : 'rgba(250,204,21,0.12)' }}
              >
                {pqOperational ? (
                  <ShieldCheck className="w-8 h-8 text-emerald-400" />
                ) : (
                  <ShieldAlert className="w-8 h-8 text-amber-400" />
                )}
              </div>
              <div className="min-w-0 flex-1">
                <div className="text-lg font-bold text-white">
                  {pqOperational ? t(`${NS}.pq_operational`) : t(`${NS}.pq_unverified`)}
                </div>
                <p className="text-[12px] text-[var(--text-tertiary)] mt-1 max-w-2xl leading-relaxed">
                  {pqOperational ? t(`${NS}.pq_operational_body`) : t(`${NS}.pq_unverified_body`)}
                </p>
                {pq.hybrid_rollout && (
                  <p className="text-[11px] font-mono text-[var(--text-muted)] mt-2">{pq.hybrid_rollout}</p>
                )}
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <ExecutiveWidget label={t(`${NS}.kpi_standard`)} value={pq.nist_standard ? 'FIPS 203' : '—'} accent="#4ade80" />
              <ExecutiveWidget
                label={t(`${NS}.kpi_ciphertext`)}
                value={selftest?.ciphertext_bytes != null ? `${selftest.ciphertext_bytes} B` : '—'}
                accent="#22d3ee"
              />
              <ExecutiveWidget
                label={t(`${NS}.kpi_secret`)}
                value={selftest?.shared_secret_bytes != null ? `${selftest.shared_secret_bytes} B` : '—'}
                accent="#a78bfa"
              />
              <ExecutiveWidget label={t(`${NS}.kpi_mode`)} value={pq.session_kem_mode || '—'} accent="#f97316" />
            </div>

            <div>
              <h2 className="text-[11px] font-mono uppercase tracking-widest text-[var(--text-muted)] mb-3">
                {t(`${NS}.controls_heading`)}
              </h2>
              <div className="relative flex-1 min-w-[220px] max-w-md mb-3">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--text-disabled)] pointer-events-none" />
                <input
                  type="search"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder={t(`${NS}.search_placeholder`)}
                  className="w-full bg-[var(--bg-3)] border border-[var(--border-default)] rounded-xl pl-10 pr-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-cyan-500/40"
                />
              </div>
              <ul className="space-y-2">
                {filteredControls.map((c) => (
                  <li
                    key={c.id}
                    className="flex items-center justify-between gap-3 rounded-xl border border-[var(--border-default)] bg-[var(--table-surface)] px-4 py-3"
                  >
                    <div className="min-w-0">
                      <div className="text-[12px] text-[var(--text-secondary)]">{c.name}</div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <code className="text-[11px] font-mono text-[var(--text-tertiary)]">{c.value}</code>
                      {c.ok != null && (
                        <span
                          className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase tracking-wider"
                          style={{
                            color: c.ok ? '#4ade80' : '#f87171',
                            borderColor: c.ok ? 'rgba(74,222,128,0.4)' : 'rgba(239,68,68,0.4)',
                            background: c.ok ? 'rgba(74,222,128,0.1)' : 'rgba(239,68,68,0.1)',
                          }}
                        >
                          {c.ok ? t(`${NS}.ok`) : t(`${NS}.fail`)}
                        </span>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          </>
        )}
      </div>
    </PageShell>
  )
}
