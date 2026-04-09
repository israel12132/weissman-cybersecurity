import React, { useCallback, useEffect, useState } from 'react'
import { useAuth } from '../../context/AuthContext'
import { apiFetch, formatHttpApiError } from '../../lib/apiBase'
import CeoGenesisPanel from './CeoGenesisPanel'
import CeoWarRoomDock from './CeoWarRoomDock'
import CeoVaccineVault from './CeoVaccineVault'
import CeoSovereignLab from './CeoSovereignLab'
import GodModeDiscoveryStrip from './GodModeDiscoveryStrip'
import GodModeEngineMatrix from './GodModeEngineMatrix'

function formatUptime(sec) {
  const s = Number(sec) || 0
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

function MetricCard({ label, value, sub, accent }) {
  return (
    <div
      className={`rounded-xl border px-4 py-3 bg-black/40 backdrop-blur-sm ${
        accent || 'border-white/10'
      }`}
    >
      <p className="text-[9px] uppercase tracking-[0.2em] text-slate-500 font-mono mb-1">{label}</p>
      <p className="text-lg font-semibold text-white tracking-tight font-mono">{value}</p>
      {sub && <p className="text-[10px] text-slate-500 font-mono mt-1">{sub}</p>}
    </div>
  )
}

export default function CeoIntegratedCommandDeck() {
  const { refreshSession } = useAuth()
  const [tel, setTel] = useState(null)
  const [telErr, setTelErr] = useState('')
  const [god, setGod] = useState(null)
  const [godErr, setGodErr] = useState('')
  const [safeSaving, setSafeSaving] = useState(false)
  const [killSaving, setKillSaving] = useState(false)
  const [intervalSaving, setIntervalSaving] = useState(false)
  const [intervalInput, setIntervalInput] = useState('60')
  const [vaultOpen, setVaultOpen] = useState(false)
  const [sovereignOpen, setSovereignOpen] = useState(false)
  const [engineToggleBusy, setEngineToggleBusy] = useState(null)

  const fetchCeoGet = useCallback(
    async (path) => {
      let r = await apiFetch(path)
      if (r.status === 401) {
        await refreshSession()
        r = await apiFetch(path)
      }
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(formatHttpApiError(r, d.detail))
      return d
    },
    [refreshSession],
  )

  const loadTelemetry = useCallback(async () => {
    setTelErr('')
    try {
      const d = await fetchCeoGet('/api/ceo/telemetry')
      setTel(d)
    } catch (e) {
      setTelErr(e.message || 'telemetry failed')
    }
  }, [fetchCeoGet])

  const loadGodSnapshot = useCallback(async () => {
    setGodErr('')
    try {
      const d = await fetchCeoGet('/api/ceo/god-mode/snapshot')
      setGod(d)
      if (d.scan_interval_secs != null) setIntervalInput(String(d.scan_interval_secs))
    } catch (e) {
      setGodErr(e.message || 'god-mode snapshot failed')
    }
  }, [fetchCeoGet])

  useEffect(() => {
    loadTelemetry()
    loadGodSnapshot()
    const t1 = setInterval(loadTelemetry, 3000)
    const t2 = setInterval(loadGodSnapshot, 4000)
    return () => {
      clearInterval(t1)
      clearInterval(t2)
    }
  }, [loadTelemetry, loadGodSnapshot])

  const globalSafe = !!tel?.global_safe_mode
  const eff = tel?.strategy?.effective || {}
  const genesisKill = !!eff.genesis_kill_switch

  const toggleGlobalSafe = async () => {
    setSafeSaving(true)
    const next = !globalSafe
    try {
      const r = await apiFetch('/api/ceo/global-safe-mode', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ global_safe_mode: next }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(formatHttpApiError(r, d.detail))
      await loadTelemetry()
      await loadGodSnapshot()
    } catch (e) {
      window.alert(e.message || 'Global safe mode update failed')
    }
    setSafeSaving(false)
  }

  const toggleTenantEngine = async (engineId, enabled) => {
    setEngineToggleBusy(engineId)
    try {
      const r = await apiFetch('/api/ceo/tenant/engines', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ engine_id: engineId, enabled }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(formatHttpApiError(r, d.detail))
      await loadGodSnapshot()
    } catch (e) {
      window.alert(e.message || 'Tenant engine toggle failed')
    }
    setEngineToggleBusy(null)
  }

  const toggleGenesisKill = async () => {
    setKillSaving(true)
    const next = !genesisKill
    try {
      const r = await apiFetch('/api/ceo/strategy', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          configs: { genesis_kill_switch: next ? 'true' : 'false' },
        }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(formatHttpApiError(r, d.detail))
      await loadTelemetry()
    } catch (e) {
      window.alert(e.message || 'Genesis kill switch failed')
    }
    setKillSaving(false)
  }

  const saveScanInterval = async () => {
    const n = Math.floor(Number(intervalInput))
    if (!Number.isFinite(n) || n < 10 || n > 86400) {
      window.alert('scan_interval_secs must be between 10 and 86400')
      return
    }
    setIntervalSaving(true)
    try {
      const r = await apiFetch('/api/ceo/god-mode/scan-interval', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_interval_secs: n }),
      })
      const d = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(formatHttpApiError(r, d.detail))
      if (d.scan_interval_secs != null) setIntervalInput(String(d.scan_interval_secs))
      await loadGodSnapshot()
    } catch (e) {
      window.alert(e.message || 'Scan interval update failed')
    }
    setIntervalSaving(false)
  }

  const rssKb = tel?.server_process_rss_kb
  const rssMb = rssKb != null ? (Number(rssKb) / 1024).toFixed(1) : '—'
  const scanFromGod = god?.scanning_active
  const scanFromTel = tel?.scanning_active
  const scanningActive = scanFromGod ?? scanFromTel

  return (
    <div className="space-y-6">
      {/* Hero */}
      <div
        className="rounded-2xl border border-cyan-500/15 bg-gradient-to-br from-slate-950 via-black to-indigo-950/40 p-6 overflow-hidden relative"
        style={{
          boxShadow:
            '0 0 100px rgba(34, 211, 238, 0.07), inset 0 1px 0 rgba(255,255,255,0.06)',
        }}
      >
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.12]"
          style={{
            backgroundImage: `linear-gradient(105deg, transparent 40%, rgba(34,211,238,0.15) 50%, transparent 60%)`,
          }}
        />
        <div className="relative flex flex-wrap items-start justify-between gap-4 mb-6">
          <div>
            <p className="text-[9px] font-mono uppercase tracking-[0.4em] text-cyan-500/90 mb-2">
              Weissman · God mode
            </p>
            <h2 className="text-xl font-bold text-white tracking-tight">Command authority</h2>
            <p className="text-[11px] font-mono text-slate-500 mt-2 max-w-xl leading-relaxed">
              Live cockpit: PostgreSQL <span className="text-slate-400">system_configs</span>,{' '}
              <span className="text-slate-400">weissman_async_jobs</span>, orchestrator telemetry — zero mock
              payloads.
            </p>
          </div>
          {(telErr || godErr) && (
            <div className="text-[10px] font-mono text-red-300 px-3 py-2 rounded-lg border border-red-500/30 bg-red-950/40 max-w-md">
              {telErr && <div>Telemetry: {telErr}</div>}
              {godErr && <div>Snapshot: {godErr}</div>}
            </div>
          )}
        </div>

        <div className="relative grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
          <MetricCard
            label="Server uptime"
            value={tel ? formatUptime(tel.uptime_secs) : '—'}
            accent="border-cyan-500/25"
          />
          <MetricCard
            label="Process RSS"
            value={tel ? `${rssMb} MB` : '—'}
            sub="weissman-server process"
            accent="border-violet-500/25"
          />
          <MetricCard
            label="Worker IDs (tenant)"
            value={tel != null ? String(tel.distinct_worker_ids_on_tenant_jobs ?? 0) : '—'}
            accent="border-emerald-500/25"
          />
          <MetricCard
            label="Jobs (tenant)"
            value={
              tel != null
                ? `${tel.tenant_jobs_running ?? 0} run / ${tel.tenant_jobs_pending ?? 0} pend`
                : '—'
            }
            accent="border-white/10"
          />
          <MetricCard
            label="Queue (global)"
            value={
              tel != null
                ? `${tel.queue_global_running ?? 0} run / ${tel.queue_global_pending ?? 0} pend`
                : '—'
            }
            sub="all tenants"
            accent="border-slate-600/40"
          />
          <MetricCard
            label="Scanning"
            value={scanningActive ? 'ACTIVE' : 'idle'}
            accent={scanningActive ? 'border-orange-500/40' : 'border-white/10'}
          />
        </div>

        {/* Orchestrator + global controls */}
        <div className="relative grid gap-4 lg:grid-cols-12">
          <div className="lg:col-span-4 rounded-xl border border-red-500/35 bg-red-950/25 p-4 backdrop-blur-sm">
            <p className="text-[10px] font-mono uppercase tracking-widest text-red-300/90 mb-2">
              Global safe mode
            </p>
            <p className="text-[10px] text-slate-500 font-mono mb-3 leading-snug">
              DB: <code className="text-slate-400">global_safe_mode</code> — extra jitter + 2.5s between engines.
            </p>
            <button
              type="button"
              disabled={safeSaving || !tel}
              onClick={toggleGlobalSafe}
              className={`w-full py-2.5 rounded-lg text-xs font-bold uppercase tracking-widest border ${
                globalSafe
                  ? 'border-emerald-500/60 bg-emerald-950/50 text-emerald-200'
                  : 'border-red-500/50 bg-red-950/50 text-red-100 hover:bg-red-900/40'
              } disabled:opacity-40`}
            >
              {safeSaving ? '…' : globalSafe ? 'Safe ON — release' : 'Engage safe mode'}
            </button>
          </div>

          <div className="lg:col-span-4 rounded-xl border border-amber-500/30 bg-amber-950/15 p-4 backdrop-blur-sm">
            <p className="text-[10px] font-mono uppercase tracking-widest text-amber-200/90 mb-2">
              Orchestrator interval
            </p>
            <p className="text-[10px] text-slate-500 font-mono mb-2 leading-snug">
              Updates <code className="text-slate-400">scan_interval_secs</code> for tenant{' '}
              <code className="text-amber-600/90">slug=default</code> (server loop).
            </p>
            <div className="flex gap-2 items-center">
              <input
                type="number"
                min={10}
                max={86400}
                value={intervalInput}
                onChange={(e) => setIntervalInput(e.target.value)}
                className="flex-1 min-w-0 font-mono text-sm bg-black/50 border border-amber-500/25 rounded-lg px-3 py-2 text-amber-100"
              />
              <button
                type="button"
                disabled={intervalSaving}
                onClick={saveScanInterval}
                className="shrink-0 px-4 py-2 rounded-lg border border-amber-500/50 bg-amber-950/40 text-amber-100 text-[10px] font-mono uppercase hover:bg-amber-900/40 disabled:opacity-40"
              >
                {intervalSaving ? '…' : 'Apply'}
              </button>
            </div>
          </div>

          <div className="lg:col-span-4 rounded-xl border border-rose-500/40 bg-rose-950/20 p-4 backdrop-blur-sm">
            <p className="text-[10px] font-mono uppercase tracking-widest text-rose-300/90 mb-2">
              Genesis kill switch
            </p>
            <p className="text-[10px] text-slate-500 font-mono mb-3 leading-snug">
              CEO strategy / <code className="text-slate-400">genesis_kill_switch</code> — hibernates Genesis
              workers.
            </p>
            <button
              type="button"
              disabled={killSaving || !tel}
              onClick={toggleGenesisKill}
              className={`w-full py-2.5 rounded-lg text-xs font-bold uppercase tracking-widest border ${
                genesisKill
                  ? 'border-rose-500 bg-rose-950/70 text-rose-100'
                  : 'border-white/20 bg-white/5 text-slate-200 hover:bg-white/10'
              } disabled:opacity-40`}
            >
              {killSaving ? '…' : genesisKill ? 'ARMED — disarm' : 'Arm kill switch'}
            </button>
          </div>
        </div>
      </div>

      <GodModeDiscoveryStrip discovery={god?.discovery} godErr={godErr} />

      <GodModeEngineMatrix
        matrix={god?.engine_matrix}
        scanningActive={!!scanningActive}
        godErr={godErr}
        onTenantEngineToggle={toggleTenantEngine}
        engineToggleBusy={engineToggleBusy}
      />

      <CeoWarRoomDock />

      <div>
        <h3 className="text-[10px] font-mono uppercase tracking-[0.25em] text-emerald-400/90 mb-3">
          HPC routing · Genesis RAM (PUT/POST → /api/ceo/hpc/policy)
        </h3>
        <CeoGenesisPanel />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-cyan-500/15 bg-black/30 overflow-hidden">
          <button
            type="button"
            onClick={() => setVaultOpen((o) => !o)}
            className="w-full px-4 py-3 flex items-center justify-between text-left border-b border-white/10 bg-cyan-950/20 hover:bg-cyan-950/30"
          >
            <span className="text-xs font-mono uppercase tracking-widest text-cyan-200/90">
              Vaccine vault
            </span>
            <span className="text-[10px] text-slate-500 font-mono">{vaultOpen ? '−' : '+'}</span>
          </button>
          {vaultOpen && (
            <div className="p-4 max-h-[min(70vh,520px)] overflow-y-auto">
              <CeoVaccineVault />
            </div>
          )}
        </div>
        <div className="rounded-xl border border-violet-500/15 bg-black/30 overflow-hidden">
          <button
            type="button"
            onClick={() => setSovereignOpen((o) => !o)}
            className="w-full px-4 py-3 flex items-center justify-between text-left border-b border-white/10 bg-violet-950/20 hover:bg-violet-950/30"
          >
            <span className="text-xs font-mono uppercase tracking-widest text-violet-200/90">
              Sovereign lab
            </span>
            <span className="text-[10px] text-slate-500 font-mono">{sovereignOpen ? '−' : '+'}</span>
          </button>
          {sovereignOpen && (
            <div className="p-4 max-h-[min(70vh,520px)] overflow-y-auto">
              <CeoSovereignLab />
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
