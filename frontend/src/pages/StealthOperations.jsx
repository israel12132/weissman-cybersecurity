import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { FileText, Search } from 'lucide-react'
import { apiFetch } from '../lib/apiBase'
import EvidenceNotice from '../components/ui/EvidenceNotice'
import Button from '../components/ui/Button'
import ShellScanActions from '../components/engine/ShellScanActions'
import { exportRowsCsv, exportRowsPdf, rowMatchesQuery } from '../lib/pageExport'

/** CSV/PDF columns for the live active-host saturation list. Exported for tests. */
export const STEALTH_CSV_HEADER = ['host', 'in_flight', 'capacity']

/** Pure: live active hosts → export rows. Exported for tests. */
export function stealthHostRows(hosts) {
  return (Array.isArray(hosts) ? hosts : []).map((h) => [
    h?.host ?? '',
    h?.in_flight ?? 0,
    h?.capacity ?? 0,
  ])
}

// Live-load tint by saturation ratio.
function loadColor(ratio) {
  if (ratio >= 0.85) return 'bg-rose-500'
  if (ratio >= 0.6) return 'bg-amber-500'
  if (ratio > 0) return 'bg-emerald-500'
  return 'bg-text-muted'
}

function Stat({ label, value, sub }) {
  return (
    <div className="rounded-lg border border-white/10 bg-bg-2 px-3 py-2.5">
      <div className="text-[10px] uppercase tracking-wider text-text-muted">{label}</div>
      <div className="text-xl font-semibold text-white tabular-nums font-mono">{value}</div>
      {sub && <div className="text-[10px] text-text-muted mt-0.5">{sub}</div>}
    </div>
  )
}

// Horizontal saturation bar: in-flight vs capacity.
function LoadBar({ inFlight, capacity }) {
  const cap = Math.max(1, Number(capacity) || 1)
  const cur = Math.max(0, Number(inFlight) || 0)
  const ratio = Math.min(1, cur / cap)
  return (
    <div className="flex items-center gap-2">
      <div className="h-2 flex-1 rounded-full bg-white/10 overflow-hidden">
        <div className={`h-full ${loadColor(ratio)} transition-all`} style={{ width: `${ratio * 100}%` }} />
      </div>
      <span className="text-[11px] font-mono text-text-secondary tabular-nums w-12 text-right">
        {cur}/{cap}
      </span>
    </div>
  )
}

export default function StealthOperations() {
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [live, setLive] = useState(true)
  const [loading, setLoading] = useState(true)
  const [pacing, setPacing] = useState(null) // editable draft, seeded once from status
  const [saving, setSaving] = useState(false)
  const [saveMsg, setSaveMsg] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const timer = useRef(null)

  const load = useCallback(async () => {
    try {
      const r = await apiFetch('/api/stealth/status')
      if (!r.ok) {
        const j = await r.json().catch(() => ({}))
        throw new Error(j.detail || j.error || `HTTP ${r.status}`)
      }
      setData(await r.json())
      setError('')
    } catch (err) {
      setError((err && err.message) || 'request failed')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    if (live) {
      timer.current = setInterval(load, 2000)
      return () => clearInterval(timer.current)
    }
    return undefined
  }, [load, live])

  // Seed the editable pacing draft once (live polling must not clobber edits).
  useEffect(() => {
    if (data && data.config && pacing === null) {
      setPacing({
        jitter_min_ms: data.config.jitter_min_ms,
        jitter_max_ms: data.config.jitter_max_ms,
        min_interval_ms: data.config.min_interval_ms,
      })
    }
  }, [data, pacing])

  const setP = (k) => (ev) => {
    const n = Math.max(0, Math.min(60000, Math.floor(Number(ev.target.value) || 0)))
    setPacing((p) => ({ ...p, [k]: n }))
    setSaveMsg('')
  }

  const savePacing = async () => {
    if (!pacing) return
    setSaving(true)
    setSaveMsg('')
    try {
      const r = await apiFetch('/api/stealth/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(pacing),
      })
      if (!r.ok) {
        const j = await r.json().catch(() => ({}))
        throw new Error(j.detail || j.error || `HTTP ${r.status}`)
      }
      const fresh = await r.json()
      setData(fresh)
      setPacing({
        jitter_min_ms: fresh.config.jitter_min_ms,
        jitter_max_ms: fresh.config.jitter_max_ms,
        min_interval_ms: fresh.config.min_interval_ms,
      })
      setSaveMsg(t('stealthOps.applied'))
    } catch (err) {
      setSaveMsg((err && err.message) || 'save failed')
    } finally {
      setSaving(false)
    }
  }

  const pacingDirty =
    pacing &&
    data &&
    data.config &&
    (pacing.jitter_min_ms !== data.config.jitter_min_ms ||
      pacing.jitter_max_ms !== data.config.jitter_max_ms ||
      pacing.min_interval_ms !== data.config.min_interval_ms)

  const cfg = data && data.config
  const l = data && data.live
  const id = data && data.identity

  // Client-side filter over the already-loaded live active-host list (a bounded, live
  // snapshot — searched in place, no extra round-trip).
  const activeHosts = useMemo(
    () => (Array.isArray(data?.live?.active_hosts) ? data.live.active_hosts : []),
    [data],
  )
  const filteredHosts = useMemo(
    () => activeHosts.filter((h) => rowMatchesQuery(searchQuery, [h?.host])),
    [activeHosts, searchQuery],
  )

  const handleRefresh = useCallback(() => load(), [load])
  const exportCsv = useCallback(
    () => exportRowsCsv(STEALTH_CSV_HEADER, stealthHostRows(filteredHosts), 'weissman-stealth-operations'),
    [filteredHosts],
  )
  const exportPdf = useCallback(
    () =>
      exportRowsPdf('Weissman Stealth Operations', STEALTH_CSV_HEADER, stealthHostRows(filteredHosts), 'weissman-stealth-operations'),
    [filteredHosts],
  )

  return (
    <div className="mx-auto max-w-6xl px-4 py-6 text-text-secondary">
      <header className="mb-5 flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-white flex items-center gap-2">
            <span aria-hidden>🛡️</span> {t('stealthOps.title')}
          </h1>
          <p className="text-sm text-text-tertiary mt-1 max-w-2xl">{t('stealthOps.subtitle')}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="unstyled"
            onClick={() => setLive((v) => !v)}
            className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
              live
                ? 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300'
                : 'border-white/15 bg-bg-2 text-text-tertiary'
            }`}
          >
            <span className={`inline-block w-1.5 h-1.5 rounded-full mr-1.5 ${live ? 'bg-emerald-400 animate-pulse' : 'bg-text-muted'}`} />
            {live ? t('stealthOps.live') : t('stealthOps.paused')}
          </Button>
          <Button
            variant="unstyled"
            onClick={load}
            className="rounded-lg border border-white/15 bg-bg-2 px-3 py-1.5 text-xs font-medium text-text-secondary hover:bg-bg-3"
          >
            {t('stealthOps.refresh')}
          </Button>
          <ShellScanActions
            onRefresh={handleRefresh}
            onExport={exportCsv}
            refreshLoading={loading}
            exportDisabled={!filteredHosts.length}
          />
          <Button
            variant="unstyled"
            type="button"
            onClick={exportPdf}
            disabled={!filteredHosts.length}
            title={t('common.export_pdf', { defaultValue: 'Export PDF' })}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-semibold border border-white/15 text-text-secondary hover:bg-white/10 disabled:opacity-40 transition-colors"
          >
            <FileText className="w-3.5 h-3.5" />
            {t('common.export_pdf', { defaultValue: 'PDF' })}
          </Button>
        </div>
      </header>

      <EvidenceNotice className="mb-4">
        Live snapshot from GET /api/stealth/status — real concurrency, pacing and rotating-identity
        telemetry. Active-host saturation is exported as loaded; no fabricated host activity.
      </EvidenceNotice>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-950/30 px-4 py-3 text-sm text-rose-300 mb-4">
          {error}
        </div>
      )}

      {loading && !data && (
        <div className="rounded-xl border border-dashed border-white/10 bg-bg-2 px-6 py-12 text-center text-sm text-text-muted">
          {t('stealthOps.loading')}
        </div>
      )}

      {data && (
        <>
          {data.disabled && (
            <div className="rounded-lg border border-amber-500/40 bg-amber-950/30 px-4 py-3 text-sm text-amber-300 mb-4">
              {t('stealthOps.disabledWarn')}
            </div>
          )}

          {/* ── Live metrics ── */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
            <Stat
              label={t('stealthOps.globalInFlight')}
              value={`${l.global_in_flight}`}
              sub={t('stealthOps.ofFree', { cap: cfg.global_capacity, free: l.global_free })}
            />
            <Stat label={t('stealthOps.queued')} value={`${l.waiting}`} sub={t('stealthOps.parkedForSlot')} />
            <Stat
              label={t('stealthOps.activeHostsStat')}
              value={`${l.active_hosts.length}`}
              sub={t('stealthOps.tracked', { n: l.tracked_hosts })}
            />
            <Stat
              label={t('stealthOps.admittedTotal')}
              value={l.admitted_total.toLocaleString()}
              sub={t('stealthOps.sinceStart')}
            />
          </div>

          <div className="mb-5">
            <div className="text-[11px] uppercase tracking-wider text-text-muted mb-1">
              {t('stealthOps.globalSaturation')}
            </div>
            <LoadBar inFlight={l.global_in_flight} capacity={cfg.global_capacity} />
          </div>

          <div className="grid gap-5 md:grid-cols-2">
            {/* ── Config ── */}
            <section className="rounded-xl border border-white/10 bg-bg-2 p-4">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-text-tertiary mb-3">
                {t('stealthOps.effectiveConfig')}
              </h2>
              {/* Protection floor — env-only, read-only. */}
              <div className="text-[11px] uppercase tracking-wider text-text-muted mb-1">
                {t('stealthOps.concurrencyCaps')}
              </div>
              <p className="text-xs text-text-muted mb-2">{t('stealthOps.capsNote')}</p>
              <dl className="space-y-2 mb-4">
                {[
                  [t('stealthOps.perTarget'), cfg.per_target, cfg.env_keys.per_target],
                  [t('stealthOps.globalCeiling'), cfg.global_capacity, cfg.env_keys.global],
                ].map(([k, v, env]) => (
                  <div key={k} className="flex items-baseline justify-between gap-3 border-b border-white/5 pb-2 last:border-0">
                    <div className="min-w-0">
                      <div className="text-sm text-text-secondary">{k}</div>
                      <div className="text-[10px] font-mono text-text-muted truncate">{env}</div>
                    </div>
                    <span className="text-lg font-mono font-semibold text-text-secondary tabular-nums shrink-0">
                      {v}
                    </span>
                  </div>
                ))}
              </dl>

              {/* Pacing — live-tunable within the enforced envelope (operator+). */}
              <div className="text-[11px] uppercase tracking-wider text-text-muted mb-1">
                {t('stealthOps.pacingTitle')}
              </div>
              <p className="text-xs text-text-muted mb-3">{t('stealthOps.pacingNote')}</p>
              <div className="space-y-2">
                {pacing &&
                  [
                    [t('stealthOps.jitterMin'), 'jitter_min_ms'],
                    [t('stealthOps.jitterMax'), 'jitter_max_ms'],
                    [t('stealthOps.minInterval'), 'min_interval_ms'],
                  ].map(([k, key]) => (
                    <label key={key} htmlFor={`pacing-${key}`} className="flex items-center justify-between gap-3">
                      <span className="text-sm text-text-secondary">{k}</span>
                      <input
                        id={`pacing-${key}`}
                        type="number"
                        min="0"
                        max="60000"
                        aria-label={k}
                        value={pacing[key]}
                        onChange={setP(key)}
                        className="w-28 rounded-md border border-white/10 bg-bg-1 px-2 py-1 text-right text-sm font-mono text-cyan-300 tabular-nums focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
                      />
                    </label>
                  ))}
              </div>
              <div className="mt-3 flex items-center gap-3">
                <Button
                  variant="unstyled"
                  onClick={savePacing}
                  disabled={!pacingDirty || saving}
                  className="rounded-lg bg-cyan-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  {saving ? t('stealthOps.applying') : t('stealthOps.applyPacing')}
                </Button>
                {saveMsg && (
                  <span
                    className={`text-xs font-mono ${saveMsg.includes('✓') ? 'text-emerald-400' : 'text-rose-400'}`}
                  >
                    {saveMsg}
                  </span>
                )}
              </div>
            </section>

            {/* ── Rotating identity ── */}
            <section className="rounded-xl border border-white/10 bg-bg-2 p-4">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-text-tertiary mb-3">
                {t('stealthOps.rotatingIdentity')}
              </h2>
              <p className="text-xs text-text-muted mb-3">{t('stealthOps.identityNote')}</p>
              <div className="grid grid-cols-3 gap-3 mb-4">
                <Stat label={t('stealthOps.userAgents')} value={id.user_agent_pool} />
                <Stat label={t('stealthOps.acceptLang')} value={id.accept_language_pool} />
                <Stat label={t('stealthOps.platforms')} value={id.platform_pool} />
              </div>
              <div className="rounded-lg border border-white/5 bg-white/[0.02] px-3 py-2">
                <div className="text-[10px] uppercase tracking-wider text-text-muted">
                  {t('stealthOps.identitiesDispensed')}
                </div>
                <div className="text-lg font-mono font-semibold text-white tabular-nums">
                  {id.identities_dispensed.toLocaleString()}
                </div>
              </div>
            </section>
          </div>

          {/* ── Active hosts ── */}
          <section className="rounded-xl border border-white/10 bg-bg-2 p-4 mt-5">
            <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-text-tertiary">
                {t('stealthOps.activeTargets')}
              </h2>
              <div className="flex items-center gap-3">
                <div className="relative">
                  <Search className="w-3 h-3 text-text-muted absolute left-2 top-1/2 -translate-y-1/2 pointer-events-none" />
                  <input
                    type="search"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder={t('common.search', { defaultValue: 'Search host' })}
                    aria-label={t('common.search', { defaultValue: 'Search host' })}
                    className="w-40 pl-6 pr-2 py-1 rounded-md text-[11px] bg-bg-1 border border-white/10 text-text-secondary placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-cyan-500/40"
                  />
                </div>
                <span className="text-xs font-mono text-text-muted">
                  {t('stealthOps.showing', { n: filteredHosts.length })}
                </span>
              </div>
            </div>
            {activeHosts.length === 0 ? (
              <div className="text-sm text-text-muted py-6 text-center">
                {t('stealthOps.noRequests')}
              </div>
            ) : filteredHosts.length === 0 ? (
              <div className="text-sm text-text-muted py-6 text-center">
                {t('stealthOps.noMatch', { defaultValue: 'No active hosts match your search.' })}
              </div>
            ) : (
              <ul className="space-y-2">
                {filteredHosts.map((h) => (
                  <li key={h.host} className="flex items-center gap-3">
                    <span className="text-sm font-mono text-text-secondary truncate w-56 shrink-0" title={h.host}>
                      {h.host}
                    </span>
                    <span className="flex-1">
                      <LoadBar inFlight={h.in_flight} capacity={h.capacity} />
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </>
      )}
    </div>
  )
}
