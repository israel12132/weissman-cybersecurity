import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'
import { apiFetch } from '../../utils/apiFetch'

const NS = 'components.cockpitWidgets.mitreCoverageHeatmap'

const TACTICS = [
  { id: 'reconnaissance',     icon: '⌕' },
  { id: 'resource_development', icon: '⚙' },
  { id: 'initial_access',     icon: '⇲' },
  { id: 'execution',          icon: '▶' },
  { id: 'persistence',        icon: '⛁' },
  { id: 'privilege_escalation', icon: '↑' },
  { id: 'defense_evasion',    icon: '◯' },
  { id: 'credential_access',  icon: '🔑' },
  { id: 'discovery',          icon: '☉' },
  { id: 'lateral_movement',   icon: '⇆' },
  { id: 'collection',         icon: '⊞' },
  { id: 'command_and_control', icon: '✦' },
  { id: 'exfiltration',       icon: '⇗' },
  { id: 'impact',             icon: '☢' },
]

function cellColor(hits, max) {
  if (!hits || hits <= 0) return { bg: 'rgba(255,255,255,0.025)', border: 'rgba(255,255,255,0.04)', text: 'rgba(255,255,255,0.25)' }
  const intensity = Math.min(1, hits / Math.max(1, max))
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
  const { t } = useTranslation()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState(null)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const d = await apiFetch('/api/dashboard/exec-kpis')
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
    const timer = setInterval(load, 30_000)
    return () => { cancelled = true; clearInterval(timer) }
  }, [])

  const { byTactic, max, totalHits, totalTechniques } = useMemo(() => {
    const grouped = {}
    let maxHits = 0
    let hits = 0
    const techniques = data?.mitre_top || []
    for (const tac of techniques) {
      const tactic = tac.tactic || 'unknown'
      if (!grouped[tactic]) grouped[tactic] = []
      grouped[tactic].push({ id: tac.id, hits: tac.hits })
      if (tac.hits > maxHits) maxHits = tac.hits
      hits += Number(tac.hits || 0)
    }
    return { byTactic: grouped, max: maxHits, totalHits: hits, totalTechniques: techniques.length }
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
      aria-label={t(`${NS}.ariaLabel`)}
    >
      <header className="flex items-center justify-between gap-2 px-3 py-2 border-b border-white/[0.06]">
        <div className="min-w-0">
          <h3 className="text-[11px] font-mono uppercase tracking-[0.18em] text-white/75">
            {t(`${NS}.title`)}
          </h3>
          <p className="text-[10px] font-mono text-white/40 mt-0.5">
            {t(`${NS}.summary`, { techniques: totalTechniques, hits: totalHits })}
          </p>
        </div>
        <a
          href="https://attack.mitre.org/matrices/enterprise/"
          target="_blank"
          rel="noopener noreferrer"
          className="text-[10px] font-mono text-cyan-300/70 hover:text-cyan-200"
        >
          {t(`${NS}.attackLink`)}
        </a>
      </header>

      {err && (
        <p className="px-3 py-2 text-[11px] font-mono text-rose-300">{err}</p>
      )}

      <div className="overflow-x-auto custom-scroll" style={{ maxHeight }}>
        <div className="flex gap-1 p-2 min-w-max">
          {TACTICS.map((tac) => {
            const techniques = byTactic[tac.id] || []
            const tacticLabel = t(`${NS}.tactics.${tac.id}`)
            return (
              <div key={tac.id} className="flex flex-col gap-1 min-w-[88px]">
                <header className="text-center px-1 py-1 bg-white/[0.04] rounded border border-white/[0.06]">
                  <div className="text-[10px] font-mono text-cyan-300/80 leading-tight" aria-hidden="true">
                    {tac.icon}
                  </div>
                  <div className="text-[9px] font-mono uppercase tracking-widest text-white/65 truncate">
                    {tacticLabel}
                  </div>
                  <div className="text-[9px] font-mono text-white/30 mt-0.5">
                    {techniques.length || 0}
                  </div>
                </header>
                {techniques.length === 0 ? (
                  <div
                    className="text-center text-[9px] font-mono py-3 rounded border border-dashed border-white/[0.06] text-white/25"
                    aria-label={t(`${NS}.noFindings`, { tactic: tacticLabel })}
                  >
                    —
                  </div>
                ) : (
                  techniques.map((tech) => {
                    const c = cellColor(tech.hits, max)
                    return (
                      <Link
                        key={tech.id}
                        to={`/findings?mitre=${encodeURIComponent(tech.id)}`}
                        className="block px-1.5 py-1 rounded text-[10px] font-mono text-center transition-all hover:scale-[1.04]"
                        style={{
                          background: c.bg,
                          border: `1px solid ${c.border}`,
                          color: c.text,
                        }}
                        title={t(`${NS}.techniqueTitle`, { id: tech.id, hits: tech.hits })}
                      >
                        <div className="font-semibold truncate">{tech.id}</div>
                        <div className="text-[9px] opacity-80">{tech.hits}</div>
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
