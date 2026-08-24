import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '../utils/apiFetch'

const NS = 'components.intelWidgets.killChainVisualizer'

// Kill-chain ordering. Tactics absent from GET /api/attack-coverage are not
// rendered, so this list never implies coverage we do not have.
const CHAIN_ORDER = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
]

function orderTactics(tactics) {
  return [...tactics].sort((a, b) => {
    const ai = CHAIN_ORDER.indexOf(a.tactic)
    const bi = CHAIN_ORDER.indexOf(b.tactic)
    return (ai === -1 ? CHAIN_ORDER.length : ai) - (bi === -1 ? CHAIN_ORDER.length : bi)
  })
}

export default function KillChainVisualizer() {
  const { t } = useTranslation()
  const [tactics, setTactics] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    apiFetch('/api/attack-coverage')
      .then((data) => {
        if (cancelled) return
        setTactics(orderTactics(data?.tactics || []))
      })
      .catch((e) => {
        if (!cancelled) setError(e?.message || String(e))
      })
    return () => {
      cancelled = true
    }
  }, [])

  const maxTechniques = tactics?.length
    ? Math.max(...tactics.map((x) => x.technique_count || 0), 1)
    : 1

  // .soc-panel-killchain is a height-constrained flex child (min-height: 0), so the
  // full 14-tactic chain overflows it. Pin the heading and scroll the list rather
  // than clipping the late tactics off the bottom with no affordance.
  return (
    <div className="kill-chain-visualizer flex flex-col h-full min-h-0">
      <div className="shrink-0 text-cyber-cyan font-semibold text-xs tracking-widest mb-3 uppercase">
        {t(`${NS}.title`)}
      </div>

      {error ? (
        <div className="font-mono text-xs text-amber-400/90 border border-amber-500/30 bg-amber-950/20 rounded px-3 py-2">
          {t(`${NS}.error`)}
        </div>
      ) : tactics === null ? (
        <div className="font-mono text-xs text-[var(--text-muted)] px-3 py-2">
          {t(`${NS}.loading`)}
        </div>
      ) : tactics.length === 0 ? (
        <div className="font-mono text-xs text-[var(--text-muted)] px-3 py-2">
          {t(`${NS}.empty`)}
        </div>
      ) : (
        <ul
          className="flex flex-col gap-1.5 flex-1 min-h-0 overflow-y-auto scrollbar-thin pe-1"
          aria-label={t(`${NS}.title`)}
        >
          {tactics.map((entry, i) => {
            const count = entry.technique_count || 0
            const engines = (entry.techniques || []).reduce(
              (sum, tech) => sum + (tech.engine_count || 0),
              0,
            )
            const width = Math.round((count / maxTechniques) * 100)
            return (
              <li
                key={entry.tactic}
                className="step-item relative font-mono text-xs py-1.5 px-3 rounded border border-cyber-cyan/25 bg-cyber-cyan/5 text-cyber-cyan/90 overflow-hidden"
                title={t(`${NS}.tacticTitle`, {
                  tactic: entry.tactic,
                  techniques: count,
                  engines,
                })}
              >
                <span
                  className="absolute inset-y-0 start-0 bg-cyber-cyan/10"
                  style={{ width: `${width}%` }}
                  aria-hidden="true"
                />
                <span className="relative flex items-center gap-2">
                  <span className="tabular-nums text-[var(--text-muted)]">
                    {String(i + 1).padStart(2, '0')}
                  </span>
                  <span className="truncate flex-1">{entry.tactic}</span>
                  <span className="tabular-nums shrink-0">
                    {t(`${NS}.techniqueCount`, { count })}
                  </span>
                </span>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
