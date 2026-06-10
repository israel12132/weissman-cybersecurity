import React, { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { apiFetch } from '../../lib/apiBase'

/**
 * MITRE ATT&CK coverage heatmap — inspired by CrowdStrike Falcon's coverage matrix and
 * AttackIQ's Validation Lab. Each column is one of the 14 ATT&CK enterprise tactics;
 * each cell is a technique observed in our findings. Cell intensity scales with hit
 * count; clicking a cell deep-links to findings filtered by that technique.
 *
 * Data: `/api/dashboard/exec-kpis.mitre_top` already returns the top techniques with
 * tactic + hits. We render the full tactic header even when no techniques have hits
 * — gives the user a sense of *coverage* (Falcon's killer move).
 */

const TACTICS = [
  { id: 'reconnaissance',     label: 'Recon',         icon: '⌕' },
  { id: 'resource_development', label: 'Resources',   icon: '⚙' },
  { id: 'initial_access',     label: 'Init. Access',  icon: '⇲' },
  { id: 'execution',          label: 'Execution',     icon: '▶' },
  { id: 'persistence',        label: 'Persistence',   icon: '⛁' },
  { id: 'privilege_escalation', label: 'Priv. Esc',   icon: '↑' },
  { id: 'defense_evasion',    label: 'Defense Evas.', icon: '◯' },
  { id: 'credential_access',  label: 'Credentials',   icon: '🔑' },
  { id: 'discovery',          label: 'Discovery',     icon: '☉' },
  { id: 'lateral_movement',   label: 'Lateral',       icon: '⇆' },
  { id: 'collection',         label: 'Collection',    icon: '⊞' },
  { id: 'command_and_control', label: 'C2',           icon: '✦' },
  { id: 'exfiltration',       label: 'Exfil',         icon: '⇗' },
  { id: 'impact',             label: 'Impact',        icon: '☢' },
]

function cellColor(hits, max) {
  if (!hits || hits <= 0) return { bg: 'rgba(255,255,255,0.025)', border: 'rgba(255,255,255,0.04)', text: 'rgba(255,255,255,0.25)' }
  const intensity = Math.min(1, hits / Math.max(1, max))
  // gradient red → orange → yellow as intensity grows (defensive-color palette)
  const r = 239
  const g = Math.round(68 + (1 - intensity) * 130)
  const b = Math.round(68 + (1 - intensity) * 50)
  return {
    bg: `rgba(${r},${g},${b},${0.18 + intensity * 0.42})`,
    border: `rgba(${r},${g},${b},0.55)`,
    text: '#f8fafc',
  }
}

export default function MitreCoverageHeatmap({ className = '', maxHeight = 320 }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState(null)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const r = await apiFetch('/api/dashboard/exec-kpis')
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        const d = await r.json()
        if (!cancelled) {
          setData(d)
          setErr(null)
        }
      } catch (e) {
        if (!cancelled) setErr(e?.message || 'fetch failed')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    const t = setInterval(load, 30_000)
    return () => { cancelled = true; clearInterval(t) }
  }, [])

  const { byTactic, max, totalHits, totalTechniques } = useMemo(() => {
    const grouped = {}
    let max = 0
    let totalHits = 0
    const techniques = data?.mitre_top || []
    for (const t of techniques) {
      const tactic = t.tactic || 'unknown'
      if (!grouped[tactic]) grouped[tactic] = []
      grouped[tactic].push({ id: t.id, hits: t.hits })
      if (t.hits > max) max = t.hits
      totalHits += Number(t.hits || 0)
    }
    return { byTactic: grouped, max, totalHits, totalTechniques: techniques.length }
  }, [data])

  if (loading && !data) {
    return (
      <section className={`rounded-2xl border border-white/10 bg-black/35 backdrop-blur-md p-3 ${className}`}>
        <div className="h-44 rounded bg-white/[0.025] animate-pulse" />
      </section>
    )
  }

  return (
    <section
      className={`rounded-2xl border border-white/10 bg-black/35 backdrop-blur-md ${className}`}
      aria-label="MITRE ATT&CK coverage"
    >
      <header className="flex items-center justify-between gap-2 px-3 py-2 border-b border-white/[0.06]">
        <div className="min-w-0">
          <h3 className="text-[11px] font-mono uppercase tracking-[0.18em] text-white/75">
            MITRE ATT&amp;CK · live coverage
          </h3>
          <p className="text-[10px] font-mono text-white/40 mt-0.5">
            {totalTechniques} techniques · {totalHits} active findings
          </p>
        </div>
        <a
          href="https://attack.mitre.org/matrices/enterprise/"
          target="_blank"
          rel="noopener noreferrer"
          className="text-[10px] font-mono text-cyan-300/70 hover:text-cyan-200"
        >
          ATT&amp;CK ↗
        </a>
      </header>

      {err && (
        <p className="px-3 py-2 text-[11px] font-mono text-rose-300">{err}</p>
      )}

      <div className="overflow-x-auto custom-scroll" style={{ maxHeight }}>
        <div className="flex gap-1 p-2 min-w-max">
          {TACTICS.map((tac) => {
            const techniques = byTactic[tac.id] || []
            return (
              <div key={tac.id} className="flex flex-col gap-1 min-w-[88px]">
                <header className="text-center px-1 py-1 bg-white/[0.04] rounded border border-white/[0.06]">
                  <div className="text-[10px] font-mono text-cyan-300/80 leading-tight" aria-hidden="true">
                    {tac.icon}
                  </div>
                  <div className="text-[9px] font-mono uppercase tracking-widest text-white/65 truncate">
                    {tac.label}
                  </div>
                  <div className="text-[9px] font-mono text-white/30 mt-0.5">
                    {techniques.length || 0}
                  </div>
                </header>
                {techniques.length === 0 ? (
                  <div
                    className="text-center text-[9px] font-mono py-3 rounded border border-dashed border-white/[0.06] text-white/25"
                    aria-label={`No findings under ${tac.label}`}
                  >
                    —
                  </div>
                ) : (
                  techniques.map((t) => {
                    const c = cellColor(t.hits, max)
                    return (
                      <Link
                        key={t.id}
                        to={`/findings?mitre=${encodeURIComponent(t.id)}`}
                        className="block px-1.5 py-1 rounded text-[10px] font-mono text-center transition-all hover:scale-[1.04]"
                        style={{
                          background: c.bg,
                          border: `1px solid ${c.border}`,
                          color: c.text,
                        }}
                        title={`${t.id} — ${t.hits} active findings`}
                      >
                        <div className="font-semibold truncate">{t.id}</div>
                        <div className="text-[9px] opacity-80">{t.hits}</div>
                      </Link>
                    )
                  })
                )}
              </div>
            )
          })}
        </div>
      </div>
    </section>
  )
}
